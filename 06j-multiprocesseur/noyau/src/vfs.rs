//! Les fichiers, côté noyau : le système de fichiers de démarrage (un
//! tmpfs, ../fichiers), ses pages, et le déballage de l'archive.
//!
//! C'est le rootfs de Linux : au démarrage, avant tout pilote de disque,
//! Linux monte un tmpfs à la racine et y déballe l'initramfs, l'archive
//! cpio que lui a laissée le chargeur (init/initramfs.c,
//! `populate_rootfs`) ; puis il rend la mémoire de l'archive
//! (`free_initrd_mem`). On fait de même :
//!   - chaque entrée de l'archive devient un dossier, un fichier, un lien
//!     symbolique ou un nœud de périphérique, avec ses droits, son
//!     propriétaire et sa date ; les liens physiques (le même numéro
//!     d'inode, plusieurs liens, le contenu dans la dernière entrée) sont
//!     reliés, comme le `maybe_link` de Linux ;
//!   - le contenu d'un fichier est copié dans ses pages, une à une : le
//!     cpio aligne les contenus sur 4 octets, pas sur 4 Kio, une page de
//!     fichier ne peut donc pas être une page de l'archive. Le pic de
//!     mémoire est le double de l'archive, le temps du déballage ;
//!   - puis /dev, que Linux remplit avec son devtmpfs : null, zero, full,
//!     random, urandom, console ;
//!   - enfin l'archive retourne à l'allocateur de pages.
//!
//! Les pages des fichiers viennent de l'allocateur de pages, au-dessus de
//! la réserve du noyau (comme celles des programmes) : un programme qui
//! remplit /tmp ne prive pas le noyau. Le tmpfs a les limites de Linux par
//! défaut : la moitié de la mémoire, et autant d'inodes que la moitié des
//! pages (ENOSPC au-delà).
//!
//! Le système de fichiers est sous un verrou. Règles :
//!   - l'ordre (le tableau complet : l'en-tête de processus.rs) : le verrou
//!     d'un processus, puis celui des fichiers (le dossier de départ d'une
//!     résolution, getcwd), et celui des tables de pages, puis celui des
//!     fichiers (une faute de page dans une projection de fichier, sous la
//!     mémoire du processus, un verrou qui dort : memoire.rs). Sous celui
//!     des fichiers, une vue de /proc (procfs.rs) ne lit un processus que
//!     par les verrous du dernier niveau : la table des processus, celle
//!     des tâches, les descripteurs d'un processus (leur propre verrou,
//!     6j) ; jamais le verrou du processus lui-même (`processus::avec` le
//!     vérifie, par `tenu_ici`). Jusqu'à 6i, elle le prenait : l'ordre
//!     inverse, sans danger sur un seul processeur (un `Verrou` coupe les
//!     interruptions), un interblocage avec deux. Ce qui se fait sous le
//!     verrou d'un processus ne résout jamais de chemin ;
//!   - jamais de copie depuis ou vers un programme sous ce verrou : une
//!     copie peut faire une faute de page.
//! D'autres systèmes de fichiers se montent sur des dossiers du tmpfs
//! (../fichiers/src/montages.rs, 6d) : la résolution des chemins parcourt
//! une `Vue` de tous (`Systeme::avec_vue`), qui traverse les points de
//! montage.

use alloc::vec::Vec;
use core::fmt;

use crate::descripteurs::{Fichier, Ouverts, Tenu};
use crate::memoire::Echec;
use crate::verrou::Verrou;
use crate::faillible::{self, VecFaillible};
use crate::{copie_utilisateur, espace, pages, pile, surveillance, temps};
use fichiers::chemins::{Depart, Dernier, Fin, Suivre, Texte, resoudre};
use fichiers::montages::{Interne, Monte, Objet, Vue};
use fichiers::noyaufs::NoyauFs;
use fichiers::tmpfs::Attributs;
use fichiers::tmpfs::{Cadres, Horodatage, Limites, Numero, RENAME_EXCHANGE, Tmpfs};
use fichiers::{Erreur, Identite, PAGE, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Temps};

/// Les pages des fichiers : des cadres de la mémoire, pris au-dessus de la
/// réserve du noyau, lus et écrits par la projection directe. Et les
/// inodes finis pendant l'opération, que des surveillances d'inotify
/// regardaient (6i) : leur fin est annoncée (surveillance::inode_fini)
/// avant que le verrou des fichiers ne soit rendu, avant que leur numéro
/// ne puisse resservir, et au moment où le dit Linux : une opération qui
/// pose d'abord un autre événement (unlink : IN_ATTRIB, puis la fin, puis
/// IN_DELETE au dossier) l'annonce elle-même entre les deux
/// (`annoncer_les_fins`), sinon la fin de `avec_systeme` s'en charge.
pub struct CadresDuNoyau {
    /// Au plus deux par opération (l'inode effacé ou écrasé, le dossier
    /// d'un fichier qu'on ferme) ; au-delà, annoncés aussitôt.
    finis: [Option<(Numero, bool)>; 4],
}

impl CadresDuNoyau {
    /// Annonce la fin des inodes finis jusqu'ici, dans l'ordre.
    pub fn annoncer_les_fins(&mut self) {
        for f in &mut self.finis {
            if let Some((n, anonyme)) = f.take() {
                crate::surveillance::inode_fini(n, anonyme);
            }
        }
    }
}

impl Cadres for CadresDuNoyau {
    fn allouer(&mut self) -> Option<u64> {
        let cadre = pages::allouer_pour_programme()?;
        // SAFETY: le cadre vient d'être alloué, personne d'autre ne le
        // voit ; il contenait ce qu'y avait laissé son précédent occupant.
        unsafe { core::ptr::write_bytes(espace::virtuelle(cadre) as *mut u8, 0, PAGE as usize) };
        // Une page de fichier : jamais inscriptible dans une projection
        // privée (espace_utilisateur.rs, entree_finale).
        pages::marquer(cadre, pages::FICHIER);
        Some(cadre)
    }

    fn lacher(&mut self, page: u64) {
        pages::lacher(page);
    }

    fn ecrire(&mut self, page: u64, decalage: usize, octets: &[u8]) {
        assert!(decalage + octets.len() <= PAGE as usize);
        // SAFETY: `page` est une page d'un fichier, tenue par le système de
        // fichiers (dont on tient le verrou) ; on reste dans la page.
        unsafe {
            let destination = (espace::virtuelle(page) as *mut u8).add(decalage);
            core::ptr::copy_nonoverlapping(octets.as_ptr(), destination, octets.len());
        }
    }

    fn lire(&self, page: u64, decalage: usize, tampon: &mut [u8]) {
        assert!(decalage + tampon.len() <= PAGE as usize);
        // SAFETY: comme `ecrire`, en lecture.
        unsafe {
            let source = (espace::virtuelle(page) as *const u8).add(decalage);
            core::ptr::copy_nonoverlapping(source, tampon.as_mut_ptr(), tampon.len());
        }
    }

    fn inode_detruit(&mut self, n: Numero, anonyme: bool) {
        if !crate::surveillance::actif() {
            return;
        }
        match self.finis.iter_mut().find(|f| f.is_none()) {
            Some(place) => *place = Some((n, anonyme)),
            None => {
                self.annoncer_les_fins();
                crate::surveillance::inode_fini(n, anonyme);
            }
        }
    }
}

/// Ce que garde le verrou des fichiers : le système de fichiers de la
/// racine, la table des fichiers ouverts (descripteurs.rs), et les systèmes
/// montés, chacun avec son point de montage (un dossier du tmpfs, tenu) :
/// procfs sur /proc (le premier, `PROC`), sysfs sur /sys.
pub struct Systeme {
    pub fs: Tmpfs,
    pub ouverts: Ouverts,
    pub montes: Vec<(Numero, NoyauFs)>,
}

/// La place de procfs dans la table des montages (sysfs est la suivante).
pub const PROC: usize = 0;

/// Un système monté, vu le temps d'un appel (le `Monte` de la `Vue`) : /proc,
/// dont une partie est fabriquée d'après les processus (procfs.rs), ou un
/// système du noyau tout fait (/sys). Option écartée : un `dyn Monte` dans
/// la table des montages ; mais /proc a besoin, pour ce qu'il fabrique,
/// d'autres morceaux du système (la table des fichiers ouverts, le
/// tmpfs, pour fd/), qu'il emprunte le temps de l'appel.
pub enum Montage<'a> {
    Proc(crate::procfs::ProcVue<'a>),
    Fixe(&'a NoyauFs),
}

impl Monte for Montage<'_> {
    fn racine(&self) -> u64 {
        match self {
            Montage::Proc(p) => p.racine(),
            Montage::Fixe(f) => Monte::racine(*f),
        }
    }

    fn peripherique(&self) -> (u32, u32) {
        match self {
            Montage::Proc(p) => p.peripherique(),
            Montage::Fixe(f) => f.peripherique(),
        }
    }

    fn taille_de_bloc(&self) -> u64 {
        match self {
            Montage::Proc(p) => p.taille_de_bloc(),
            Montage::Fixe(f) => f.taille_de_bloc(),
        }
    }

    fn attributs(&self, n: u64) -> Attributs {
        match self {
            Montage::Proc(p) => p.attributs(n),
            Montage::Fixe(f) => f.attributs(n),
        }
    }

    fn chercher(&self, dossier: u64, nom: &[u8]) -> Option<u64> {
        match self {
            Montage::Proc(p) => p.chercher(dossier, nom),
            Montage::Fixe(f) => f.chercher(dossier, nom),
        }
    }

    fn parent(&self, n: u64) -> u64 {
        match self {
            Montage::Proc(p) => p.parent(n),
            Montage::Fixe(f) => f.parent(n),
        }
    }

    fn nom(&self, n: u64) -> Texte<'_> {
        match self {
            Montage::Proc(p) => p.nom(n),
            Montage::Fixe(f) => f.nom(n),
        }
    }

    fn cible<'b>(&'b self, lien: u64, lecteur: &'b [u8], fil: &'b [u8]) -> Texte<'b> {
        match self {
            Montage::Proc(p) => p.cible(lien, lecteur, fil),
            Montage::Fixe(f) => f.cible(lien, lecteur, fil),
        }
    }

    fn saut(&self, lien: u64) -> Option<Objet> {
        match self {
            Montage::Proc(p) => p.saut(lien),
            Montage::Fixe(f) => f.saut(lien),
        }
    }

    fn chemin_du_saut(&self, lien: u64) -> Option<Texte<'_>> {
        match self {
            Montage::Proc(p) => p.chemin_du_saut(lien),
            Montage::Fixe(f) => f.chemin_du_saut(lien),
        }
    }

    fn lire_dossier(&self, dossier: u64, position: u64, entree: &mut dyn FnMut(&[u8], u64, u8, u64) -> bool)
        -> Result<(), Erreur> {
        match self {
            Montage::Proc(p) => p.lire_dossier(dossier, position, entree),
            Montage::Fixe(f) => f.lire_dossier(dossier, position, entree),
        }
    }

    fn contenu(&self, n: u64) -> Option<(u32, u32)> {
        match self {
            Montage::Proc(p) => p.contenu(n),
            Montage::Fixe(f) => f.contenu(n),
        }
    }

    fn refuser(&self, qui: Identite, m: Interne) -> Result<(), Erreur> {
        match self {
            Montage::Proc(p) => p.refuser(qui, m),
            Montage::Fixe(f) => f.refuser(qui, m),
        }
    }
}

impl Systeme {
    /// Le fichier ouvert `f` est tenu une fois de moins ; au dernier, il est
    /// fermé : le tmpfs rend son inode (et ses pages, si plus rien ne le
    /// tient).
    ///
    /// Sa fermeture se voit d'inotify (6i) : IN_CLOSE_WRITE s'il était
    /// ouvert en écriture, IN_CLOSE_NOWRITE sinon (`fsnotify_close`, dans
    /// le `__fput` de Linux), avant la fin de son inode et celle de son
    /// dossier, que son lieu tenait.
    pub fn lacher(&mut self, f: Fichier, cadres: &mut CadresDuNoyau) {
        if let Some(ferme) = self.ouverts.lacher(f) {
            let fermeture = if ferme.ecriture { surveillance::IN_CLOSE_WRITE } else { surveillance::IN_CLOSE_NOWRITE };
            surveillance::du_fichier(&self.fs, &ferme, fermeture);
            // Le dernier fichier ouvert par une entrée effacée : elle meurt.
            if let (Some(l), Some(n)) = (&ferme.lieu, ferme.numero())
                && let Objet::Tmpfs(d) = l.dossier
                && !self.fs.a_l_entree(d, l.cookie, n)
            {
                self.entree_morte(n, d, l.cookie);
            }
            if let Tenu::Tmpfs(ouvert) = ferme.tenu {
                self.fs.fermer(&ouvert, cadres);
            }
            if let Some(Objet::Tmpfs(d)) = ferme.lieu.map(|l| l.dossier) {
                self.fs.lacher(d, cadres);
            }
        }
    }

    /// L'entrée `cookie` du dossier `dossier`, qui désignait l'inode `n`,
    /// a disparu (effacée, écrasée par un renommage), ou le dernier fichier
    /// ouvert par elle vient d'être fermé : si plus aucun fichier ouvert ne
    /// la tient, elle meurt (le `dentry_unlink_inode` de Linux : un dentry
    /// tenu attend sa dernière référence), et si l'inode n'a plus aucun
    /// nom, inotify annonce sa fin maintenant (IN_DELETE_SELF, puis
    /// IN_IGNORED : `if (!inode->i_nlink) fsnotify_inoderemove(inode)`),
    /// même si un fichier ouvert par un AUTRE nom le tient encore. Mesuré
    /// sous Linux 6.18 : un fichier ouvert par f, lié en h, effacé par f
    /// puis par h : la fin à l'effacement de h (personne ne tenait ce
    /// nom-là), rien au close ; ouvert par f et par h, effacé deux fois :
    /// la fin au premier close. Sans lien physique, c'est la fin de l'inode
    /// (`Cadres::inode_detruit`), qui n'aura plus rien à dire. Pas pour un
    /// dossier : il n'a qu'un nom, et le dossier courant d'un processus le
    /// tient aussi (hors de la table des fichiers ouverts) ; sa fin d'inode
    /// est le bon moment.
    pub fn entree_morte(&self, n: Numero, dossier: Numero, cookie: u64) {
        if !surveillance::actif() || !self.fs.existe(n) || self.fs.est_un_dossier(n) {
            return;
        }
        if self.fs.attributs(n).nlink == 0 && !self.ouverts.tient_l_entree(dossier, cookie) {
            surveillance::inode_fini(n, false);
        }
    }

    /// Renomme le dernier composant de `ancien` en celui de `nouveau`
    /// (renameat2 : Tmpfs::renommer), puis ce qu'en voient les fichiers
    /// ouverts et inotify (6i), comme le `d_move` et le `fsnotify_move` de
    /// Linux :
    ///   - les fichiers ouverts par l'entrée déplacée la suivent (leur lieu :
    ///     le nouveau dossier, le nouveau nom) ; avec RENAME_EXCHANGE, ceux de
    ///     l'autre entrée aussi, à l'ancien nom ; ceux d'un fichier écrasé
    ///     gardent le leur (leur entrée a disparu). Leurs noms sont copiés
    ///     d'avance : ENOMEM avant de rien changer ;
    ///   - IN_MOVED_FROM à l'ancien dossier, IN_MOVED_TO au nouveau, avec
    ///     le même cookie, neuf ; IN_ATTRIB à un inode écrasé (un nom de
    ///     moins) ; IN_MOVE_SELF à l'inode déplacé ; avec RENAME_EXCHANGE,
    ///     le déplacement inverse, avec son propre cookie. La fin d'un inode
    ///     écrasé vient ensuite (IN_DELETE_SELF : à la fin de `avec_systeme`,
    ///     ou par `entree_morte` s'il vit par un autre nom).
    /// Rien si les deux noms désignent le même inode.
    pub fn renommer(&mut self, qui: Identite, ancien: &Fin<Numero>, nouveau: &Fin<Numero>, drapeaux: u32,
                    cadres: &mut CadresDuNoyau) -> Result<(), Erreur> {
        let echange = drapeaux & RENAME_EXCHANGE != 0;
        let source = (ancien.dernier == Dernier::Nom).then(|| self.fs.entree(ancien.dossier, &ancien.nom)).flatten();
        let cible = (nouveau.dernier == Dernier::Nom).then(|| self.fs.entree(nouveau.dossier, &nouveau.nom)).flatten();
        let est_dossier = |fs: &Tmpfs, e: Option<(Numero, u64)>| e.is_some_and(|(n, _)| fs.est_un_dossier(n));
        let (dossier_source, dossier_cible) = (est_dossier(&self.fs, source), est_dossier(&self.fs, cible));
        // Les fichiers ouverts qui suivront chaque entrée, et leurs noms.
        let suit = |f: &crate::descripteurs::FichierOuvert, dossier: Numero, e: Option<(Numero, u64)>| {
            e.is_some_and(|(n, c)| f.numero() == Some(n) && f.lieu.as_ref().is_some_and(|l| l.dossier == Objet::Tmpfs(dossier) && l.cookie == c))
        };
        let a_suivre = self.ouverts.tous().filter(|f| suit(f, ancien.dossier, source)).count();
        let b_suivre = if echange { self.ouverts.tous().filter(|f| suit(f, nouveau.dossier, cible)).count() } else { 0 };
        let mut noms_a: Vec<Vec<u8>> = faillible::avec_capacite(a_suivre)?;
        let mut noms_b: Vec<Vec<u8>> = faillible::avec_capacite(b_suivre)?;
        for _ in 0..a_suivre {
            noms_a.ajouter_dans_la_place(faillible::copie(&nouveau.nom)?);
        }
        for _ in 0..b_suivre {
            noms_b.ajouter_dans_la_place(faillible::copie(&ancien.nom)?);
        }
        self.fs.renommer(qui, ancien, nouveau, drapeaux, temps::maintenant(), cadres)?;
        let Some((source, cookie_a)) = source else { return Ok(()) };
        if cible.is_some_and(|(c, _)| c == source) {
            return Ok(());
        }
        // Les entrées après : RENAME_EXCHANGE les garde, en échangeant leurs
        // inodes ; sinon, une entrée neuve au nouveau nom.
        let cookie_nouveau = match (echange, cible) {
            (true, Some((_, c))) => c,
            _ => self.fs.entree(nouveau.dossier, &nouveau.nom).map_or(0, |(_, c)| c),
        };
        let Systeme { fs, ouverts, .. } = self;
        for f in ouverts.tous() {
            let n = f.numero();
            let Some(l) = f.lieu.as_mut() else { continue };
            let (dossier, cookie, nom) = if n == Some(source) && l.dossier == Objet::Tmpfs(ancien.dossier) && l.cookie == cookie_a {
                (nouveau.dossier, cookie_nouveau, noms_a.pop())
            } else if let Some((c, cookie_c)) = cible.filter(|_| echange)
                && n == Some(c)
                && l.dossier == Objet::Tmpfs(nouveau.dossier)
                && l.cookie == cookie_c
            {
                (ancien.dossier, cookie_a, noms_b.pop())
            } else {
                continue;
            };
            fs.prendre(dossier);
            if let Objet::Tmpfs(ancien) = l.dossier {
                fs.lacher(ancien, cadres);
            }
            l.dossier = Objet::Tmpfs(dossier);
            l.cookie = cookie;
            l.nom = nom.expect("un nom par fichier qui suit");
        }
        let cookie = surveillance::cookie();
        surveillance::dans_le_dossier(ancien.dossier, &ancien.nom, surveillance::IN_MOVED_FROM, dossier_source, cookie);
        surveillance::dans_le_dossier(nouveau.dossier, &nouveau.nom, surveillance::IN_MOVED_TO, dossier_source, cookie);
        match cible {
            Some((c, _)) if !echange => surveillance::de_l_inode(c, dossier_cible, surveillance::IN_ATTRIB),
            _ => {}
        }
        surveillance::de_l_inode(source, dossier_source, surveillance::IN_MOVE_SELF);
        if let Some((c, _)) = cible.filter(|_| echange) {
            let cookie = surveillance::cookie();
            surveillance::dans_le_dossier(nouveau.dossier, &nouveau.nom, surveillance::IN_MOVED_FROM, dossier_cible, cookie);
            surveillance::dans_le_dossier(ancien.dossier, &ancien.nom, surveillance::IN_MOVED_TO, dossier_cible, cookie);
            surveillance::de_l_inode(c, dossier_cible, surveillance::IN_MOVE_SELF);
        }
        // L'entrée écrasée meurt (le `dput(new_dentry)` de `do_renameat2`),
        // après les déplacements.
        if let Some((c, cookie_c)) = cible.filter(|_| !echange) {
            self.entree_morte(c, nouveau.dossier, cookie_c);
        }
        Ok(())
    }

    /// Appelle `f` avec la vue de tous les systèmes de fichiers, telle que
    /// la voit le processus `pid`, par la tâche courante (pour /proc/self et
    /// /proc/thread-self ; 0 : le noyau, ou un programme WebAssembly, qui
    /// n'est pas un processus Linux).
    pub fn avec_vue<R>(&self, pid: u32, f: impl FnOnce(&Vue<Montage>) -> R) -> R {
        let mut texte = [0u8; 10];
        let lecteur = decimal(pid, &mut texte);
        // « <pid>/task/<tid> » : 10 + 6 + 10 octets au plus.
        let mut chemin_du_fil = [0u8; 26];
        let mut longueur = 0;
        if pid != 0 {
            let mut tid = [0u8; 10];
            for morceau in [lecteur, b"/task/", decimal(crate::tache::courante().tid(), &mut tid)] {
                chemin_du_fil[longueur..longueur + morceau.len()].copy_from_slice(morceau);
                longueur += morceau.len();
            }
        }
        // Les systèmes montés, vus le temps de l'appel : /proc avec ce qu'il
        // fabrique des processus (procfs.rs), /sys tel qu'il est ; eux deux
        // seuls, montés au démarrage (un système de plus, le disque de 6m,
        // devra prendre place ici).
        let montes: [(Numero, Montage); 2] = core::array::from_fn(|i| {
            let (point, fs) = &self.montes[i];
            (*point, if i == PROC { Montage::Proc(crate::procfs::ProcVue::new(fs, &self.ouverts, &self.fs)) } else { Montage::Fixe(fs) })
        });
        f(&Vue { fs: &self.fs, montes: &montes, lecteur, fil: &chemin_du_fil[..longueur] })
    }

    /// Résout `chemin` depuis `depart`, pour le processus `pid`, à travers
    /// les montages (fichiers::montages).
    pub fn resoudre(&self, pid: u32, depart: &Depart<Objet>, chemin: &[u8], suivre: Suivre) -> Result<Fin<Objet>, Erreur> {
        self.avec_vue(pid, |vue| resoudre(vue, depart, chemin, suivre))
    }

    /// La racine de l'arborescence (celle du tmpfs).
    pub fn racine(&self) -> Objet {
        Objet::Tmpfs(self.fs.racine())
    }
}

/// `n` en décimal, dans `texte` (rien pour 0).
pub fn decimal(mut n: u32, texte: &mut [u8; 10]) -> &[u8] {
    let mut i = texte.len();
    while n > 0 {
        i -= 1;
        texte[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &texte[i..]
}

static RACINE: Verrou<Option<Systeme>> = Verrou::new(None);

/// Ce processeur tient-il le verrou des fichiers ? Pour l'`assert!` d'ordre
/// de processus.rs.
pub fn tenu_ici() -> bool {
    RACINE.tenu_par_ce_processeur()
}

/// Exécute `f` sur le système de fichiers, verrou tenu : court, et sans
/// copie depuis ou vers un programme.
#[track_caller]
pub fn avec<R>(f: impl FnOnce(&mut Tmpfs, &mut CadresDuNoyau) -> R) -> R {
    avec_systeme(|s, cadres| f(&mut s.fs, cadres))
}

/// Comme `avec`, avec aussi la table des fichiers ouverts.
#[track_caller]
pub fn avec_systeme<R>(f: impl FnOnce(&mut Systeme, &mut CadresDuNoyau) -> R) -> R {
    let mut racine = RACINE.verrouiller();
    let mut cadres = CadresDuNoyau { finis: [None; 4] };
    let r = f(racine.as_mut().expect("systeme de fichiers pas encore monte"), &mut cadres);
    cadres.annoncer_les_fins();
    r
}

/// Copie `n` octets de la page `cadre` d'un fichier, que l'appelant tient
/// (pages::prendre), à partir de `decalage`, vers l'adresse `destination`
/// du programme : rend le nombre d'octets copiés (moins à une faute, voir
/// copie_utilisateur).
///
/// Par un pointeur brut, jamais une tranche (`&[u8]`) : une tranche
/// promettrait au compilateur que personne n'écrit la page tant qu'elle
/// existe, et c'est faux depuis 6e : une autre tâche peut écrire le même
/// fichier pendant la copie (une lecture n'attend pas les écritures, comme
/// sous Linux : elle peut en voir une à moitié faite). La copie elle-même
/// est `rep movsb`, qui ne suppose rien de ce qu'elle lit. Option écartée,
/// celle de 6b à 6d : la tranche, juste avec un seul programme à la fois
/// (personne ne pouvait écrire la page pendant la copie).
pub fn copier_vers_programme(cadre: u64, decalage: usize, n: usize, destination: u64) -> usize {
    assert!(decalage + n <= PAGE as usize);
    let source = (espace::virtuelle(cadre) as *const u8).wrapping_add(decalage);
    // SAFETY: le cadre est une page allouée, vue par la projection directe,
    // et tenue par l'appelant : elle ne sera pas rendue pendant la copie ; on
    // reste dans la page (vérifié).
    unsafe { copie_utilisateur::copier_vers_utilisateur_brut(destination, source, n) }
}

/// Copie `n` octets depuis l'adresse `source` du programme dans la page
/// `cadre` d'un fichier, que l'appelant tient, à `decalage` (write) : rend
/// le nombre d'octets copiés. La page est à un fichier, jamais projetée en
/// écriture chez un programme (une projection privée la voit en lecture
/// seule, et MAP_SHARED n'existe pas encore).
/// Par un pointeur brut, comme `copier_vers_programme` : une lecture du même
/// fichier peut la lire en même temps.
pub fn copier_depuis_programme(cadre: u64, decalage: usize, n: usize, source: u64) -> usize {
    assert!(decalage + n <= PAGE as usize);
    let destination = (espace::virtuelle(cadre) as *mut u8).wrapping_add(decalage);
    // SAFETY: comme `copier_vers_programme`, en écriture.
    unsafe { copie_utilisateur::copier_depuis_utilisateur_brut(destination, source, n) }
}

/// Copie `destination.len()` octets de la page `cadre` d'un fichier, que
/// l'appelant tient, à partir de `decalage`, dans un tampon du noyau
/// (sendfile, copy_file_range, 6i). Par `rep movsb`, comme les copies vers
/// un programme : une autre tâche peut écrire la page en même temps.
pub fn copier_page_vers_noyau(cadre: u64, decalage: usize, destination: &mut [u8]) {
    assert!(decalage + destination.len() <= PAGE as usize);
    let source = (espace::virtuelle(cadre) as *const u8).wrapping_add(decalage);
    // SAFETY: le cadre est une page allouée, tenue par l'appelant, vue par
    // la projection directe, et qu'aucune référence Rust ne désigne (un
    // write du même fichier peut l'écrire pendant la copie) ; on reste dans
    // la page (vérifié) ; la destination est un tampon du noyau, désigné
    // seulement par l'emprunt exclusif d'où vient son pointeur.
    unsafe { copie_utilisateur::copier_dans_le_noyau(destination.as_mut_ptr(), source, destination.len()) }
}

/// Copie `source`, octets du noyau, dans la page `cadre` d'un fichier, que
/// l'appelant tient, à `decalage` (sendfile, copy_file_range, 6i).
pub fn copier_noyau_vers_page(cadre: u64, decalage: usize, source: &[u8]) {
    assert!(decalage + source.len() <= PAGE as usize);
    let destination = (espace::virtuelle(cadre) as *mut u8).wrapping_add(decalage);
    // SAFETY: comme `copier_page_vers_noyau`, en écriture : la page n'est
    // désignée par aucune référence Rust (une lecture du même fichier peut
    // la lire pendant la copie : voir `copier_vers_programme`) ; la source
    // est un tampon du noyau, désigné seulement par l'emprunt partagé d'où
    // vient son pointeur.
    unsafe { copie_utilisateur::copier_dans_le_noyau(destination, source.as_ptr(), source.len()) }
}

/// La page numéro `index` du fichier ouvert `f`, pour une faute de page
/// dans une zone qui le projette : créée si c'est un trou (comme le
/// `shmem_fault` de Linux, pour qu'une page privée pas encore copiée soit
/// toujours la page du fichier). Au-delà de la fin du fichier (à la page
/// près) : `HorsDuFichier` (SIGBUS) ; le tmpfs plein : `PlusDePlace`
/// (SIGBUS aussi, comme Linux) ; plus de mémoire : `PlusDeMemoire` (le
/// tueur OOM).
///
/// Le cadre est pris une fois de plus (pages::prendre) pour l'appelant,
/// qui le passe à l'entrée qui le projettera, ou le lâche. Sans cette
/// référence, une troncature du fichier entre ce moment et la pose de
/// l'entrée (la faute ne tient plus que la mémoire en lecture, et peut être
/// préemptée, depuis 6i) rendrait le cadre à l'allocateur, et la faute
/// projetterait une page qui est déjà à quelqu'un d'autre. Linux rend de
/// même la page tenue (`filemap_fault`, `folio_get`).
pub fn page_projetee(f: Fichier, index: u64) -> Result<u64, Echec> {
    avec_systeme(|s, cadres| {
        let n = s.ouverts.fichier(f).inode();
        if index >= s.fs.attributs(n).taille.div_ceil(PAGE) {
            return Err(Echec::HorsDuFichier);
        }
        let cadre = s.fs.page_pour_ecrire(n, index, cadres).map_err(|e| match e {
            Erreur::ENOSPC => Echec::PlusDePlace,
            Erreur::ENOMEM => Echec::PlusDeMemoire,
            _ => Echec::HorsDuFichier,
        })?;
        crate::pages::prendre(cadre);
        Ok(cadre)
    })
}

/// La page numéro `index` du fichier ouvert `f` est-elle toujours `cadre`
/// (le fichier n'a pas été raccourci entre-temps) ? Après qu'une faute a
/// posé l'entrée, sous le verrou des tables : si non, elle la retire et
/// recommence, et c'est la troncature qui l'emporte (SIGBUS au-delà de la
/// fin), comme le contrôle de Linux sous le verrou de la page (`folio->mapping`
/// et `i_size` revus dans `filemap_fault`). Ordre des verrous : celui des
/// tables, puis celui des fichiers.
pub fn page_encore_projetable(f: Fichier, index: u64, cadre: u64) -> bool {
    avec_systeme(|s, _| {
        let n = s.ouverts.fichier(f).inode();
        index < s.fs.attributs(n).taille.div_ceil(PAGE) && s.fs.page(n, index) == Some(cadre)
    })
}

/// Lit le fichier `n` à partir de `position` dans `tampon` (pour le
/// noyau : un programme à exécuter). Rend le nombre d'octets lus, moins que
/// demandé à la fin du fichier.
pub fn lire(n: Numero, position: u64, tampon: &mut [u8]) -> usize {
    avec(|fs, cadres| fs.lire(n, position, tampon, cadres))
}

/// Ce que le déballage a fait, pour l'afficher.
#[derive(Default)]
pub struct Bilan {
    pub dossiers: usize,
    pub fichiers: usize,
    pub liens_symboliques: usize,
    pub liens_physiques: usize,
    /// Les entrées refusées (le noyau a dit pourquoi).
    pub refusees: usize,
}

/// Une date de l'archive (en secondes).
fn date(secondes: u32) -> Horodatage {
    Horodatage::Valeur(Temps { secondes: secondes as i64, nanosecondes: 0 })
}

/// Le chemin absolu d'une entrée de l'archive (« bin/x » : « /bin/x »).
fn absolu(nom: &[u8]) -> Result<Vec<u8>, Erreur> {
    Ok(faillible::concatenation(&[b"/", nom])?)
}

/// Le nom d'une entrée, pour un message (sans accents : tel quel, l'ASCII
/// imprimable seulement).
struct Chemin<'a>(&'a [u8]);

impl fmt::Display for Chemin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", crate::programmes::Nom(self.0))
    }
}

/// Monte le système de fichiers de la racine, y déballe `archive` (si le
/// chargeur en a laissé une), puis crée /dev.
pub fn initialiser(archive: Option<&[u8]>) -> Result<Bilan, Erreur> {
    let total = pages::total() as u64;
    let limites = Limites { inodes: (total / 2).min(u32::MAX as u64) as u32, pages: total / 2 };
    *RACINE.verrouiller() = Some(Systeme { fs: Tmpfs::new(limites, temps::maintenant())?, ouverts: Ouverts::default(), montes: Vec::new() });
    let mut bilan = Bilan::default();
    if let Some(octets) = archive {
        deballer(octets, &mut bilan)?;
    }
    creer_dev()?;
    monter("procfs", b"/proc", crate::procfs::creer)?;
    monter("sysfs", b"/sys", crate::sysfs::creer)?;
    Ok(bilan)
}

/// Monte le système que fabrique `creer` sur le dossier `chemin` du tmpfs,
/// créé s'il n'existe pas (0555, à root, comme /proc et /sys dans une
/// distribution), comme le fait un init (« mount -t proc proc /proc ») :
/// ici, le noyau en tient le rôle. Le dossier est tenu tant que le système
/// y est monté.
fn monter(nom: &str, chemin: &[u8], creer: fn(Temps) -> Result<NoyauFs, Erreur>) -> Result<(), Erreur> {
    let maintenant = temps::maintenant();
    let systeme = creer(maintenant)?;
    avec_systeme(|s, _| {
        s.montes.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
        let racine = s.fs.racine();
        let depart = Depart { racine, dossier: racine, qui: Identite::ROOT, sous: false };
        let fin = resoudre(&s.fs, &depart, chemin, Suivre::Jamais)?;
        let point = match fin.objet {
            Some(n) if s.fs.mode(n) & S_IFMT == S_IFDIR => n,
            Some(_) => return Err(Erreur::ENOTDIR),
            None => s.fs.creer(Identite::ROOT, &fin, S_IFDIR | 0o555, (0, 0), &[], maintenant)?,
        };
        s.fs.prendre(point);
        s.montes.ajouter_dans_la_place((point, systeme));
        Ok(())
    })?;
    afficherln!("[noyau] {} monte sur {}.", nom, Chemin(chemin));
    Ok(())
}

/// Le déballage, entrée par entrée. Une entrée refusée (un dossier parent
/// qui manque, plus de place) est signalée, et la suite continue, comme
/// Linux. L'archive a été vérifiée d'avance, en entier.
fn deballer(octets: &[u8], bilan: &mut Bilan) -> Result<(), Erreur> {
    // Les fichiers déjà vus qui ont des liens physiques : (inode dans
    // l'archive, inode chez nous).
    let mut vus: Vec<(u32, Numero)> = Vec::new();
    for entree in formats::cpio::lire(octets).flatten() {
        if entree.nom.is_empty() || entree.nom == b"." {
            continue;
        }
        let chemin = absolu(entree.nom)?;
        let resultat = deballer_entree(&entree, &chemin, &mut vus, bilan);
        if let Err(e) = resultat {
            afficherln!("[noyau] archive : {} refuse (errno {})", Chemin(&chemin), e.errno());
            bilan.refusees += 1;
        }
    }
    Ok(())
}

fn deballer_entree(entree: &formats::cpio::Entree, chemin: &[u8], vus: &mut Vec<(u32, Numero)>, bilan: &mut Bilan)
    -> Result<(), Erreur> {
    let root = Identite::ROOT;
    let maintenant = temps::maintenant();
    let droits = entree.mode & 0o7777;
    let numero = avec(|fs, cadres| -> Result<Option<Numero>, Erreur> {
        let racine = fs.racine();
        let depart = Depart { racine, dossier: racine, qui: root, sous: false };
        let fin = resoudre(fs, &depart, chemin, Suivre::Jamais)?;
        let genre = entree.mode & S_IFMT;
        // Ce qui est déjà là sous ce nom : un dossier se garde (on lui
        // applique les droits de l'archive), le reste s'efface (le
        // `clean_path` de Linux), sauf un lien physique déjà vu.
        if let Some(existant) = fin.objet {
            let dossier_existant = fs.mode(existant) & S_IFMT == S_IFDIR;
            if genre == S_IFDIR && dossier_existant {
                proprietes(fs, existant, entree, maintenant)?;
                return Ok(None);
            }
            fs.effacer(root, &fin, dossier_existant, maintenant, cadres)?;
        }
        let fin = resoudre(fs, &depart, chemin, Suivre::Jamais)?;
        if genre == S_IFREG
            && entree.liens >= 2
            && let Some(&(_, premier)) = vus.iter().find(|(ino, _)| *ino == entree.inode)
        {
            fs.lier(root, premier, &fin, maintenant)?;
            bilan.liens_physiques += 1;
            return Ok(Some(premier));
        }
        let (mode, cible) = match genre {
            S_IFDIR => (S_IFDIR | droits, &[][..]),
            S_IFREG => (S_IFREG | droits, &[][..]),
            S_IFLNK => (S_IFLNK | droits, entree.contenu),
            S_IFCHR => (S_IFCHR | droits, &[][..]),
            _ => return Err(Erreur::EINVAL),
        };
        let n = fs.creer(root, &fin, mode, entree.rdev, cible, maintenant)?;
        match genre {
            S_IFDIR => bilan.dossiers += 1,
            S_IFREG => bilan.fichiers += 1,
            S_IFLNK => bilan.liens_symboliques += 1,
            _ => {}
        }
        if genre == S_IFREG && entree.liens >= 2 {
            vus.ajouter((entree.inode, n))?;
        }
        Ok(Some(n))
    })?;
    // (Un nom que l'archive répète : le dernier compte, comme pour Linux ;
    // l'ancien a été effacé plus haut.)
    let Some(n) = numero else { return Ok(()) };
    // Le contenu d'un fichier, page à page, en rendant le verrou entre
    // deux : copier des centaines de Mio d'un coup, interruptions coupées,
    // ferait perdre ses tics à l'horloge (et l'heure retarderait).
    if entree.mode & S_IFMT == S_IFREG {
        let mut fait = 0;
        while fait < entree.contenu.len() {
            let morceau = &entree.contenu[fait..(fait + PAGE as usize).min(entree.contenu.len())];
            let ecrits = avec(|fs, cadres| fs.ecrire(n, fait as u64, morceau, maintenant, cadres))?;
            fait += ecrits;
        }
    }
    avec(|fs, _| proprietes(fs, n, entree, maintenant))
}

/// Le propriétaire, les droits et la date de l'archive (dans cet ordre :
/// changer de propriétaire fait tomber les bits setuid et setgid).
fn proprietes(fs: &mut Tmpfs, n: Numero, entree: &formats::cpio::Entree, maintenant: Temps) -> Result<(), Erreur> {
    let root = Identite::ROOT;
    fs.changer_proprietaire(root, n, Some(entree.uid), Some(entree.gid), maintenant)?;
    if entree.mode & S_IFMT != S_IFLNK {
        fs.changer_mode(root, n, entree.mode, maintenant)?;
    }
    fs.changer_temps(root, n, date(entree.date), date(entree.date), maintenant)
}

// Les périphériques de /dev : majeur, mineur (Documentation/admin-guide/
// devices.txt), nom, droits.
pub const NULL: (u32, u32) = (1, 3);
pub const ZERO: (u32, u32) = (1, 5);
pub const FULL: (u32, u32) = (1, 7);
pub const RANDOM: (u32, u32) = (1, 8);
pub const URANDOM: (u32, u32) = (1, 9);
pub const CONSOLE: (u32, u32) = (5, 1);

/// Crée /dev et ses périphériques, comme le devtmpfs de Linux : à root, en
/// 0666, sauf la console, qui est au terminal de l'utilisateur (0620, à
/// lui), comme celle d'une session ouverte (et comme fstat la décrivait
/// déjà, à l'étape 5).
fn creer_dev() -> Result<(), Erreur> {
    let maintenant = temps::maintenant();
    avec(|fs, _| {
        let racine = fs.racine();
        let depart = Depart { racine, dossier: racine, qui: Identite::ROOT, sous: false };
        let fin = resoudre(fs, &depart, b"/dev", Suivre::Jamais)?;
        if fin.objet.is_none() {
            fs.creer(Identite::ROOT, &fin, S_IFDIR | 0o755, (0, 0), &[], maintenant)?;
        }
        let peripheriques: [(&[u8], (u32, u32), u32); 6] = [
            (b"/dev/null", NULL, 0o666),
            (b"/dev/zero", ZERO, 0o666),
            (b"/dev/full", FULL, 0o666),
            (b"/dev/random", RANDOM, 0o666),
            (b"/dev/urandom", URANDOM, 0o666),
            (b"/dev/console", CONSOLE, 0o620),
        ];
        for (chemin, rdev, droits) in peripheriques {
            let fin = resoudre(fs, &depart, chemin, Suivre::Jamais)?;
            if fin.objet.is_some() {
                continue;
            }
            let n = fs.creer(Identite::ROOT, &fin, S_IFCHR | droits, rdev, &[], maintenant)?;
            if rdev == CONSOLE {
                fs.changer_proprietaire(Identite::ROOT, n, Some(pile::UTILISATEUR as u32), Some(pile::GROUPE as u32), maintenant)?;
            }
        }
        Ok(())
    })
}
