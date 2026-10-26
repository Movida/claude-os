//! Les systèmes de fichiers du noyau : procfs (/proc) et sysfs (/sys). Leur
//! arborescence est décrite par le noyau, entrée par entrée (le
//! `proc_dir_entry` de Linux, ou les `kernfs_node` de sysfs), et le
//! contenu de leurs fichiers est fabriqué à la lecture, d'après une
//! « source » que seul le noyau sait remplir (la carte des zones d'un
//! processus, sa mémoire, un réglage). Rien ne s'y crée, ne s'y efface ni ne
//! s'y renomme par les appels système.
//!
//! La bibliothèque tient l'arborescence et répond à la résolution des
//! chemins (le trait `Monte` de montages.rs) ; elle découpe aussi le
//! contenu en lectures (`Sequence`, le `seq_file` de Linux). Le noyau,
//! lui, ajoute et retire les entrées (une entrée par processus dans
//! /proc), et fabrique les contenus.
//!
//! Les deux genres, mesurés sous Linux 6.18, ne diffèrent que par ce
//! qu'ils répondent :
//!   - procfs : la taille des fichiers est 0, la taille de bloc 1024 ; un
//!     nom absent y est une erreur dès la recherche (ENOENT : on ne peut pas
//!     y créer) ; dans le dossier d'un processus, une écriture dans le
//!     dossier est refusée par EPERM, ailleurs par les droits (EACCES) ;
//!   - sysfs : la taille des fichiers est une page (4096), la taille de
//!     bloc aussi ; un nom absent n'y est qu'absent (créer est refusé par
//!     les droits, EACCES, ou par EPERM pour root : rien ne sait y créer).

use crate::montages::{Interne, Monte};
use crate::tmpfs::{Attributs, DT_DIR, DT_LNK, DT_REG, Numero};
use crate::{ECRIRE, EXECUTER, Erreur, Identite, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Temps, permis};
use alloc::vec::Vec;

/// Le genre du système : ce qu'il répond (voir l'en-tête).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Genre {
    Proc,
    Sys,
}

/// La cible d'un lien.
#[derive(Clone, Debug)]
pub enum Cible {
    /// Un texte fixé à la création (/proc/<pid>/exe : le chemin de
    /// l'exécutable).
    Fixe(Vec<u8>),
    /// Le numéro du processus qui lit (/proc/self).
    Lecteur,
}

/// Ce qu'est une entrée.
#[derive(Clone, Debug)]
pub enum Contenu {
    Dossier,
    /// Un fichier, dont le contenu vient de la source `source` du noyau,
    /// avec `argument` (le numéro du processus d'un fichier de
    /// /proc/<pid>).
    Fichier { source: u32, argument: u32 },
    Lien(Cible),
}

#[derive(Clone, Debug)]
struct Entree {
    /// Son numéro d'inode.
    numero: u32,
    nom: Vec<u8>,
    parent: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    contenu: Contenu,
    /// Dans le dossier d'un processus (/proc/<pid>, et lui-même) : une
    /// écriture dans un tel dossier est refusée par EPERM (mesuré), avant
    /// même les droits.
    processus: bool,
    /// Immuable (le S_IMMUTABLE de Linux, que procfs pose sur /proc/<pid>
    /// lui-même, `proc_pid_instantiate`) : ni son propriétaire, ni ses
    /// droits, ni ses dates ne changent, pour personne (EPERM, avant toute
    /// autre vérification, `notify_change` ; mesuré : chown vers son propre
    /// propriétaire rend EPERM pour le dossier, 0 pour maps).
    immuable: bool,
    /// Sa date de création (celle de ses trois dates).
    date: Temps,
    /// Marquée pour `retirer`, le temps d'un balayage.
    retiree: bool,
}

/// Ce que désigne un numéro qui n'est plus dans la table : l'entrée d'un
/// processus terminé, qu'un descripteur ouvert ou un dossier courant
/// désigne encore. Linux garde l'inode (compté) et ses attributs, et les
/// opérations sur le processus disparu échouent (ESRCH, ENOENT) ; nous
/// rendons une entrée vide, à root, sans nom ni contenu : stat répond,
/// readdir rend ENOENT (`lire_dossier`), et un numéro n'est jamais repris
/// (`NoyauFs::prochain`) : il ne peut pas désigner l'entrée d'un autre.
static DISPARUE: Entree = Entree {
    numero: 0,
    nom: Vec::new(),
    parent: RACINE,
    mode: 0,
    uid: 0,
    gid: 0,
    contenu: Contenu::Dossier,
    processus: false,
    immuable: false,
    date: Temps { secondes: 0, nanosecondes: 0 },
    retiree: false,
};

/// Un système de fichiers du noyau.
pub struct NoyauFs {
    genre: Genre,
    peripherique: (u32, u32),
    /// Les entrées, dans l'ordre de leur numéro d'inode (la racine est
    /// l'inode 1, comme sous Linux). Un parent est toujours avant ses
    /// enfants : il existait quand on les a ajoutés, et les numéros
    /// croissent.
    entrees: Vec<Entree>,
    /// Le numéro de la prochaine entrée. Il ne fait que croître : un numéro
    /// gardé par un fichier ouvert (un `Objet::Monte`) ne désigne jamais
    /// l'entrée d'un autre. Options écartées : reprendre la première place
    /// libre (le numéro de /proc/2/maps désignerait, après la fin de 2, le
    /// statm de /proc/3) ; une génération à côté de chaque numéro (il
    /// faudrait l'ajouter à `Objet`, que partagent tous les systèmes). À
    /// quatre milliards d'entrées, `ajouter` rend ENOSPC (Linux, lui,
    /// recycle ses numéros d'inode de procfs, mais il tient l'inode).
    prochain: u32,
}

/// La racine : l'inode 1.
const RACINE: u32 = 1;

impl NoyauFs {
    /// Un système vide : sa racine seule, à root, de mode `mode` (0555 pour
    /// /proc et /sys), créée à `maintenant`.
    pub fn new(genre: Genre, peripherique: (u32, u32), mode: u32, maintenant: Temps) -> Result<NoyauFs, Erreur> {
        let mut entrees = Vec::new();
        entrees.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
        entrees.push(Entree {
            numero: RACINE,
            nom: Vec::new(),
            parent: RACINE,
            mode: S_IFDIR | (mode & 0o7777),
            uid: 0,
            gid: 0,
            contenu: Contenu::Dossier,
            processus: false,
            immuable: false,
            date: maintenant,
            retiree: false,
        });
        Ok(NoyauFs { genre, peripherique, entrees, prochain: RACINE + 1 })
    }

    pub fn racine(&self) -> u32 {
        RACINE
    }

    /// L'entrée de numéro `n`, si elle existe encore.
    fn trouver(&self, n: u32) -> Option<&Entree> {
        self.entrees.binary_search_by_key(&n, |e| e.numero).ok().map(|i| &self.entrees[i])
    }

    /// L'entrée de numéro `n`, ou `DISPARUE`.
    fn entree(&self, n: u32) -> &Entree {
        self.trouver(n).unwrap_or(&DISPARUE)
    }

    /// De la place d'avance pour `n` entrées de plus (ENOMEM) : une table qui
    /// ne grandit pas plus tard.
    pub fn reserver(&mut self, n: usize) -> Result<(), Erreur> {
        self.entrees.try_reserve(n).map_err(|_| Erreur::ENOMEM)
    }

    /// Ajoute `nom` dans le dossier `parent` : un dossier, un fichier ou un
    /// lien (`contenu`), de droits `droits`, à (`uid`, `gid`), daté de
    /// `maintenant`. `processus` : l'entrée appartient au dossier d'un
    /// processus (voir `Entree::processus`) ; un dossier de processus mis
    /// à la racine est le dossier du processus lui-même, immuable. Rend son
    /// numéro ; ENOENT si le parent n'existe pas, ENOTDIR s'il n'est pas un
    /// dossier, EEXIST si le nom est déjà pris, ENOMEM, ENOSPC.
    pub fn ajouter(&mut self, parent: u32, nom: &[u8], droits: u32, (uid, gid): (u32, u32), contenu: Contenu,
                   processus: bool, maintenant: Temps) -> Result<u32, Erreur> {
        let p = self.trouver(parent).ok_or(Erreur::ENOENT)?;
        if p.mode & S_IFMT != S_IFDIR {
            return Err(Erreur::ENOTDIR);
        }
        if self.chercher(parent, nom).is_some() {
            return Err(Erreur::EEXIST);
        }
        let genre = match contenu {
            Contenu::Dossier => S_IFDIR,
            Contenu::Fichier { .. } => S_IFREG,
            Contenu::Lien(_) => S_IFLNK,
        };
        let numero = self.prochain;
        let prochain = numero.checked_add(1).ok_or(Erreur::ENOSPC)?;
        let mut copie = Vec::new();
        copie.try_reserve_exact(nom.len()).map_err(|_| Erreur::ENOMEM)?;
        copie.extend_from_slice(nom);
        self.entrees.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
        let immuable = processus && parent == RACINE && genre == S_IFDIR;
        self.entrees.push(Entree {
            numero,
            nom: copie,
            parent,
            mode: genre | (droits & 0o7777),
            uid,
            gid,
            contenu,
            processus,
            immuable,
            date: maintenant,
            retiree: false,
        });
        self.prochain = prochain;
        Ok(numero)
    }

    /// Retire l'entrée `n` et tout ce qu'elle contient (le dossier d'un
    /// processus qui se termine), sans allouer : retirer ne doit pas
    /// pouvoir échouer. Un parent étant toujours avant ses enfants, un seul
    /// passage dans l'ordre marque tout le sous-arbre (le parent d'une
    /// entrée a déjà été vu), puis `retain` balaie. La racine ne se retire
    /// pas.
    pub fn retirer(&mut self, n: u32) {
        if n == RACINE {
            return;
        }
        for i in 0..self.entrees.len() {
            let parent = self.entrees[i].parent;
            let retiree = self.entrees[i].numero == n
                || self.entrees[..i].binary_search_by_key(&parent, |e| e.numero).is_ok_and(|j| self.entrees[j].retiree);
            self.entrees[i].retiree = retiree;
        }
        self.entrees.retain(|e| !e.retiree);
    }

    /// Les sous-dossiers d'un dossier (pour son nombre de liens).
    fn sous_dossiers(&self, dossier: u32) -> u32 {
        self.entrees.iter().filter(|e| e.parent == dossier && e.numero != dossier && e.mode & S_IFMT == S_IFDIR).count() as u32
    }

    /// L'entrée est-elle /proc/sys ou dans /proc/sys (un réglage, le
    /// `proc_sys` de Linux, qui a ses propres règles) ?
    fn dans_proc_sys(&self, mut n: u32) -> bool {
        if self.genre != Genre::Proc {
            return false;
        }
        // Borné par la profondeur : un parent est toujours un numéro plus
        // petit, et la racine est son propre parent.
        loop {
            let e = self.entree(n);
            if e.parent == RACINE {
                return n != RACINE && e.nom == b"sys";
            }
            if e.parent >= n {
                return false;
            }
            n = e.parent;
        }
    }
}

impl Monte for NoyauFs {
    fn racine(&self) -> u32 {
        RACINE
    }

    fn peripherique(&self) -> (u32, u32) {
        self.peripherique
    }

    fn taille_de_bloc(&self) -> u64 {
        match self.genre {
            Genre::Proc => 1024,
            Genre::Sys => 4096,
        }
    }

    /// Un dossier a deux liens (son nom, et son « . »), plus un par
    /// sous-dossier (leur « .. »), sauf ceux de /proc/sys, qui en annoncent
    /// un seul (mesuré, comme ceux de btrfs : « nombre inconnu ») ; le
    /// reste, un. Les fichiers et les liens de procfs annoncent une taille
    /// nulle (leur contenu n'existe qu'à la lecture), comme les liens de
    /// sysfs ; ses fichiers, une page (mesuré). Une entrée disparue : mode
    /// et liens nuls.
    fn attributs(&self, n: u32) -> Attributs {
        let e = self.entree(n);
        let dossier = e.mode & S_IFMT == S_IFDIR;
        let taille = match (&e.contenu, self.genre) {
            (Contenu::Fichier { .. }, Genre::Sys) => 4096,
            _ => 0,
        };
        let nlink = match () {
            _ if self.trouver(n).is_none() => 0,
            _ if dossier && self.dans_proc_sys(n) => 1,
            _ if dossier => 2 + self.sous_dossiers(n),
            _ => 1,
        };
        Attributs {
            numero: Numero(n),
            mode: e.mode,
            nlink,
            uid: e.uid,
            gid: e.gid,
            rdev: (0, 0),
            taille,
            blocs: 0,
            atime: e.date,
            mtime: e.date,
            ctime: e.date,
        }
    }

    fn chercher(&self, dossier: u32, nom: &[u8]) -> Option<u32> {
        self.entrees.iter().find(|e| e.parent == dossier && e.numero != dossier && e.nom == nom).map(|e| e.numero)
    }

    fn parent(&self, n: u32) -> u32 {
        self.entree(n).parent
    }

    fn nom(&self, n: u32) -> &[u8] {
        &self.entree(n).nom
    }

    fn cible<'a>(&'a self, lien: u32, lecteur: &'a [u8]) -> &'a [u8] {
        match &self.entree(lien).contenu {
            Contenu::Lien(Cible::Fixe(c)) => c,
            Contenu::Lien(Cible::Lecteur) => lecteur,
            _ => &[],
        }
    }

    /// « . » (position 0), « .. » (1), puis les entrées dans l'ordre de leur
    /// numéro : l'entrée `i` est à la position i + 2, et sa suivante à
    /// i + 3. Une position reste juste quand une entrée disparaît. Un
    /// dossier disparu : ENOENT, comme Linux pour le dossier d'un processus
    /// terminé.
    fn lire_dossier(&self, dossier: u32, position: u64, entree: &mut dyn FnMut(&[u8], u64, u8, u64) -> bool)
        -> Result<(), Erreur> {
        let d = self.trouver(dossier).ok_or(Erreur::ENOENT)?;
        if d.mode & S_IFMT != S_IFDIR {
            return Err(Erreur::ENOTDIR);
        }
        if position == 0 && !entree(b".", dossier as u64, DT_DIR, 1) {
            return Ok(());
        }
        if position <= 1 && !entree(b"..", d.parent as u64, DT_DIR, 2) {
            return Ok(());
        }
        let depuis = position.max(2) - 2;
        for e in self.entrees.iter().filter(|e| e.numero as u64 >= depuis) {
            if e.parent != dossier || e.numero == dossier {
                continue;
            }
            let genre = match e.contenu {
                Contenu::Dossier => DT_DIR,
                Contenu::Fichier { .. } => DT_REG,
                Contenu::Lien(_) => DT_LNK,
            };
            if !entree(&e.nom, e.numero as u64, genre, e.numero as u64 + 3) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn contenu(&self, n: u32) -> Option<(u32, u32)> {
        match self.trouver(n)?.contenu {
            Contenu::Fichier { source, argument } => Some((source, argument)),
            _ => None,
        }
    }

    /// Ce que répond le système (mesuré sous Linux 6.18, pour un
    /// utilisateur ordinaire ; root passe les droits, puis rien ne sait le
    /// faire : EPERM, l'erreur d'une opération absente) :
    ///   - créer : procfs, ENOENT (sa recherche d'un nom absent échoue) ;
    ///     sysfs, le droit d'écrire dans le dossier (EACCES), puis EPERM, ou
    ///     EACCES pour open (`lookup_open`, lu dans les sources : un dossier
    ///     sans opération `create`) ;
    ///   - effacer, renommer, lier dans le système : dans le dossier d'un
    ///     processus, EPERM ; ailleurs, le droit d'écrire (EACCES), puis
    ///     EPERM ; renommer vers un nom absent de procfs : ENOENT ;
    ///   - changer les droits : EPERM ;
    ///   - changer le propriétaire : du dossier d'un processus (immuable),
    ///     ou dans /proc/sys (`proc_sys_setattr`), EPERM dès qu'un
    ///     identifiant est donné ; ailleurs, sans rien changer (le même
    ///     utilisateur, son propre groupe, ou -1), le propriétaire le peut
    ///     (0), sinon EPERM ; root : 0. Sans effet ici (Linux garde le
    ///     changement en mémoire tant que l'inode y reste) ;
    ///   - les dates : du dossier d'un processus, EPERM ; à maintenant, il
    ///     faut pouvoir écrire, ou être le propriétaire (EACCES) ; d'autres
    ///     dates, être le propriétaire (EPERM) ; sans effet ici ;
    ///   - truncate (d'un fichier ordinaire : `Vue::refus` a vu le reste) :
    ///     le droit d'écrire (EACCES), puis 0 (procfs ignore la taille,
    ///     `proc_setattr`).
    /// Écarts pour root, écrits ici faute de pouvoir les mesurer sans
    /// écrire dans /proc (nos programmes ne sont jamais root) : Linux le
    /// laisse changer les droits de la racine de /proc (`simple_setattr`)
    /// et d'un nœud de sysfs (`kernfs_iop_setattr`) ; nous rendons EPERM.
    fn refuser(&self, qui: Identite, m: Interne) -> Result<(), Erreur> {
        let droits = |n: u32, masque: u32| {
            let e = self.entree(n);
            permis(e.mode, e.uid, e.gid, qui, masque)
        };
        let proprietaire = |n: u32| qui.root() || qui.uid == self.entree(n).uid;
        // Écrire dans le dossier `d` : refusé dans un dossier de processus
        // (EPERM), sinon par les droits.
        let ecrire_dans = |d: u32| -> Erreur {
            if self.entree(d).processus {
                Erreur::EPERM
            } else if !droits(d, ECRIRE | EXECUTER) {
                Erreur::EACCES
            } else {
                Erreur::EPERM
            }
        };
        match m {
            Interne::Creer { dossier, ouvrir } => Err(match self.genre {
                Genre::Proc => Erreur::ENOENT,
                Genre::Sys if !droits(dossier, ECRIRE | EXECUTER) || ouvrir => Erreur::EACCES,
                Genre::Sys => Erreur::EPERM,
            }),
            Interne::Effacer { dossier, .. } => Err(ecrire_dans(dossier)),
            Interne::Renommer { ancien, nouveau } => Err(match (self.genre, nouveau) {
                (Genre::Proc, None) => Erreur::ENOENT,
                _ => ecrire_dans(self.entree(ancien).parent),
            }),
            Interne::Lier { .. } | Interne::ChangerMode { .. } => Err(Erreur::EPERM),
            Interne::ChangerProprietaire { objet, uid, gid } => {
                let e = self.entree(objet);
                let change = uid.is_some() || gid.is_some();
                if change && (e.immuable || self.dans_proc_sys(objet)) {
                    return Err(Erreur::EPERM);
                }
                let uid_permis = uid.is_none_or(|u| proprietaire(objet) && u == e.uid);
                let gid_permis = gid.is_none_or(|g| proprietaire(objet) && (g == e.gid || g == qui.gid));
                if qui.root() || (uid_permis && gid_permis) { Ok(()) } else { Err(Erreur::EPERM) }
            }
            Interne::ChangerTemps { objet, maintenant } => {
                if self.entree(objet).immuable {
                    Err(Erreur::EPERM)
                } else if proprietaire(objet) || (maintenant && droits(objet, ECRIRE)) {
                    Ok(())
                } else if maintenant {
                    Err(Erreur::EACCES)
                } else {
                    Err(Erreur::EPERM)
                }
            }
            Interne::Tronquer { objet } => if droits(objet, ECRIRE) { Ok(()) } else { Err(Erreur::EACCES) },
        }
    }
}

/// La lecture d'un contenu fait d'enregistrements (le `seq_file` de
/// Linux, fs/seq_file.c) : une ligne par zone pour /proc/self/maps, un seul
/// pour statm. Le contenu n'existe pas d'avance : il est fabriqué
/// enregistrement par enregistrement, à mesure qu'on le lit, par un
/// « producteur » que donne le noyau. Comme `seq_read_iter` :
///   - une lecture remplit un tampon d'une page (doublé tant que le
///     premier enregistrement n'y tient pas, et gardé ainsi ; un tampon
///     plein a toujours un octet libre, comme chez Linux) avec des
///     enregistrements ENTIERS, tant qu'elle en demande plus, et rend ce
///     qu'il en faut ; le reste du tampon attend la lecture suivante, qui
///     le rend d'abord. Une lecture ne coupe donc une ligne que si elle
///     demande moins qu'une ligne, et une grande lecture rend au plus une
///     page de lignes entières (mesuré : 4092, 4067, 4016, puis 201
///     octets pour 200 zones), ce que supposent des lecteurs de maps ;
///   - une lecture à la position 0 repart du début ; à une autre position
///     que celle où l'on s'est arrêté, elle refabrique depuis le début
///     jusqu'à elle (`traverse`) ;
///   - une lecture de 0 octet ne fait rien.
/// La mémoire reste bornée (le tampon), quelle que soit la taille du tout,
/// et le contenu est celui du moment.
#[derive(Clone, Debug, Default)]
pub struct Sequence {
    /// La position du prochain octet à rendre.
    position: u64,
    /// Où reprendre la fabrication : le curseur que le producteur a rendu
    /// avec le dernier enregistrement mis dans le tampon (pour maps,
    /// l'adresse de fin de la dernière zone ; 0 au début).
    curseur: u64,
    /// Le tampon, et ce qui en a déjà été rendu.
    tampon: Vec<u8>,
    rendu: usize,
    /// La taille du tampon : 0 pour une page.
    taille: usize,
    /// Le producteur n'a plus rien.
    fini: bool,
}

/// Ce que rend un producteur : l'enregistrement qui suit le curseur, et le
/// curseur suivant ; None à la fin.
pub type Enregistrement = Option<(Vec<u8>, u64)>;

/// La taille d'une page, celle du premier tampon.
const PAGE: usize = 4096;

impl Sequence {
    /// Les octets [position, position + longueur[ du contenu (moins à la
    /// fin, ou moins que demandé : voir plus haut), fabriqués par
    /// `producteur(curseur)`. ENOMEM s'il manque de mémoire : la lecture
    /// suivante refabrique depuis le début jusqu'à sa position, rien n'est
    /// perdu.
    pub fn lire(&mut self, position: u64, longueur: usize, mut producteur: impl FnMut(u64) -> Result<Enregistrement, Erreur>)
        -> Result<Vec<u8>, Erreur> {
        if longueur == 0 {
            return Ok(Vec::new());
        }
        let r = self.lire_sans_garde(position, longueur, &mut producteur);
        if r.is_err() {
            *self = Sequence::default();
        }
        r
    }

    /// Le prochain enregistrement non vide après le curseur, et son curseur
    /// suivant. Un producteur dont le curseur n'avance pas est poussé d'un
    /// cran (la garde de `seq_read_iter`, « buggy .next function ») : rien
    /// ne boucle sans fin.
    fn suivant(&self, producteur: &mut impl FnMut(u64) -> Result<Enregistrement, Erreur>) -> Result<Enregistrement, Erreur> {
        let mut curseur = self.curseur;
        loop {
            match producteur(curseur)? {
                None => return Ok(None),
                Some((e, suivant)) => {
                    let suivant = if suivant > curseur { suivant } else { curseur.saturating_add(1) };
                    if !e.is_empty() {
                        return Ok(Some((e, suivant)));
                    }
                    if suivant == curseur {
                        return Ok(None);
                    }
                    curseur = suivant;
                }
            }
        }
    }

    fn lire_sans_garde(&mut self, position: u64, longueur: usize, producteur: &mut impl FnMut(u64) -> Result<Enregistrement, Erreur>)
        -> Result<Vec<u8>, Erreur> {
        if position == 0 || position != self.position {
            let taille = self.taille;
            *self = Sequence { taille, ..Sequence::default() };
            self.traverser(position, producteur)?;
        }
        let mut sortie = Vec::new();
        // Ce qui reste du tampon, d'abord.
        let reste = &self.tampon[self.rendu..];
        if !reste.is_empty() {
            let n = reste.len().min(longueur);
            sortie.try_reserve_exact(n).map_err(|_| Erreur::ENOMEM)?;
            sortie.extend_from_slice(&reste[..n]);
            self.rendu += n;
            self.position += n as u64;
            if self.rendu < self.tampon.len() || sortie.len() == longueur {
                return Ok(sortie);
            }
        }
        if self.fini {
            return Ok(sortie);
        }
        // Un tampon neuf : un premier enregistrement, entier.
        let Some((premier, suivant)) = self.suivant(producteur)? else {
            self.fini = true;
            return Ok(sortie);
        };
        // Un enregistrement tient s'il laisse au moins un octet libre (le
        // `seq_has_overflowed` de Linux) : une page en tient 4095.
        if self.taille == 0 {
            self.taille = PAGE;
        }
        while premier.len() >= self.taille {
            self.taille *= 2;
        }
        self.tampon = premier;
        self.rendu = 0;
        self.curseur = suivant;
        // Puis d'autres, entiers, tant que la lecture en demande plus et
        // qu'ils tiennent ; celui qui ne tient pas sera refabriqué par la
        // lecture suivante (le curseur ne bouge pas).
        while self.tampon.len() < longueur - sortie.len() {
            let Some((e, suivant)) = self.suivant(producteur)? else {
                self.fini = true;
                break;
            };
            if self.tampon.len() + e.len() >= self.taille {
                break;
            }
            self.tampon.try_reserve(e.len()).map_err(|_| Erreur::ENOMEM)?;
            self.tampon.extend_from_slice(&e);
            self.curseur = suivant;
        }
        let n = self.tampon.len().min(longueur - sortie.len());
        sortie.try_reserve_exact(n).map_err(|_| Erreur::ENOMEM)?;
        sortie.extend_from_slice(&self.tampon[..n]);
        self.rendu = n;
        self.position += n as u64;
        Ok(sortie)
    }

    /// Refabrique depuis le début jusqu'à `position` (le `traverse` de
    /// Linux) : les enregistrements entièrement avant elle sont jetés,
    /// celui qui la contient reste dans le tampon, rendu jusqu'à elle.
    /// Au-delà de la fin : rien à rendre.
    fn traverser(&mut self, position: u64, producteur: &mut impl FnMut(u64) -> Result<Enregistrement, Erreur>)
        -> Result<(), Erreur> {
        let mut debut = 0u64;
        while debut < position {
            let Some((e, suivant)) = self.suivant(producteur)? else {
                self.fini = true;
                break;
            };
            self.curseur = suivant;
            let fin = debut + e.len() as u64;
            if fin > position {
                self.rendu = (position - debut) as usize;
                self.tampon = e;
                break;
            }
            debut = fin;
        }
        self.position = position;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const DAVID: Identite = Identite { uid: 1000, gid: 1000 };

    /// Un /proc en miniature : self (lien vers le lecteur), sys/vm/valeur,
    /// et le dossier du processus 2, à David, avec maps et exe.
    fn proc_() -> NoyauFs {
        let t = Temps::default();
        let mut p = NoyauFs::new(Genre::Proc, (0, 21), 0o555, t).unwrap();
        p.ajouter(RACINE, b"self", 0o777, (0, 0), Contenu::Lien(Cible::Lecteur), false, t).unwrap();
        let sys = p.ajouter(RACINE, b"sys", 0o555, (0, 0), Contenu::Dossier, false, t).unwrap();
        let vm = p.ajouter(sys, b"vm", 0o555, (0, 0), Contenu::Dossier, false, t).unwrap();
        p.ajouter(vm, b"valeur", 0o644, (0, 0), Contenu::Fichier { source: 3, argument: 0 }, false, t).unwrap();
        let pid = p.ajouter(RACINE, b"2", 0o555, (1000, 1000), Contenu::Dossier, true, t).unwrap();
        p.ajouter(pid, b"maps", 0o444, (1000, 1000), Contenu::Fichier { source: 1, argument: 2 }, true, t).unwrap();
        p.ajouter(pid, b"exe", 0o777, (1000, 1000), Contenu::Lien(Cible::Fixe(b"/bin/x".to_vec())), true, t).unwrap();
        p
    }

    #[test]
    fn arborescence() {
        let mut p = proc_();
        assert_eq!(p.attributs(RACINE).numero, Numero(1));
        let deux = p.chercher(RACINE, b"2").unwrap();
        let maps = p.chercher(deux, b"maps").unwrap();
        assert_eq!(p.contenu(maps), Some((1, 2)));
        assert_eq!(p.attributs(maps).taille, 0);
        assert_eq!(p.attributs(maps).mode, S_IFREG | 0o444);
        assert_eq!(p.attributs(maps).uid, 1000);
        // La racine : deux liens, plus un par sous-dossier (sys, 2).
        assert_eq!(p.attributs(RACINE).nlink, 4);
        assert_eq!(p.parent(maps), deux);
        assert_eq!(p.nom(maps), b"maps");
        let soi = p.chercher(RACINE, b"self").unwrap();
        assert_eq!(p.cible(soi, b"42"), b"42");
        let exe = p.chercher(deux, b"exe").unwrap();
        assert_eq!(p.cible(exe, b"42"), b"/bin/x");
        assert_eq!(p.ajouter(deux, b"maps", 0o444, (0, 0), Contenu::Dossier, true, Temps::default()), Err(Erreur::EEXIST));
        // Les entrées, dans l'ordre, avec des positions qui restent justes
        // quand une entrée disparaît.
        let mut vus = vec![];
        p.lire_dossier(RACINE, 0, &mut |nom, _, _, suivante| {
            vus.push((nom.to_vec(), suivante));
            true
        })
        .unwrap();
        assert_eq!(vus.iter().map(|(n, _)| n.as_slice()).collect::<Vec<_>>(), [&b"."[..], b"..", b"self", b"sys", b"2"]);
        let apres_sys = vus[3].1;
        let mut suite = vec![];
        p.lire_dossier(RACINE, apres_sys, &mut |nom, _, _, _| {
            suite.push(nom.to_vec());
            true
        })
        .unwrap();
        assert_eq!(suite, [b"2".to_vec()]);
        // Le processus se termine : son dossier et ce qu'il contient s'en
        // vont.
        p.retirer(deux);
        assert_eq!(p.chercher(RACINE, b"2"), None);
        assert_eq!(p.attributs(RACINE).nlink, 3);
        // Un système de sysfs : des fichiers d'une page.
        let mut s = NoyauFs::new(Genre::Sys, (0, 22), 0o555, Temps::default()).unwrap();
        let f = s.ajouter(RACINE, b"online", 0o444, (0, 0), Contenu::Fichier { source: 9, argument: 0 }, false, Temps::default()).unwrap();
        assert_eq!(s.attributs(f).taille, 4096);
        assert_eq!(s.taille_de_bloc(), 4096);
        assert_eq!(p.taille_de_bloc(), 1024);
    }

    #[test]
    fn refus() {
        let p = proc_();
        let deux = p.chercher(RACINE, b"2").unwrap();
        let maps = p.chercher(deux, b"maps").unwrap();
        let sys = p.chercher(RACINE, b"sys").unwrap();
        let vm = p.chercher(sys, b"vm").unwrap();
        let valeur = p.chercher(vm, b"valeur").unwrap();
        // Le tableau mesuré sous Linux 6.18, pour /proc/self/maps.
        assert_eq!(p.refuser(DAVID, Interne::Creer { dossier: deux, ouvrir: false }), Err(Erreur::ENOENT));
        assert_eq!(p.refuser(DAVID, Interne::Effacer { dossier: deux, objet: maps, rmdir: false }), Err(Erreur::EPERM));
        assert_eq!(p.refuser(DAVID, Interne::Effacer { dossier: RACINE, objet: sys, rmdir: true }), Err(Erreur::EACCES));
        assert_eq!(p.refuser(DAVID, Interne::Renommer { ancien: maps, nouveau: None }), Err(Erreur::ENOENT));
        assert_eq!(p.refuser(DAVID, Interne::ChangerMode { objet: maps }), Err(Erreur::EPERM));
        assert_eq!(p.refuser(DAVID, Interne::ChangerProprietaire { objet: maps, uid: Some(1000), gid: Some(1000) }), Ok(()));
        assert_eq!(p.refuser(DAVID, Interne::ChangerProprietaire { objet: maps, uid: None, gid: None }), Ok(()));
        assert_eq!(p.refuser(DAVID, Interne::ChangerProprietaire { objet: maps, uid: Some(0), gid: Some(0) }), Err(Erreur::EPERM));
        assert_eq!(p.refuser(DAVID, Interne::ChangerTemps { objet: maps, maintenant: true }), Ok(()));
        assert_eq!(p.refuser(DAVID, Interne::ChangerTemps { objet: maps, maintenant: false }), Ok(()));
        assert_eq!(p.refuser(DAVID, Interne::ChangerTemps { objet: valeur, maintenant: true }), Err(Erreur::EACCES));
        assert_eq!(p.refuser(DAVID, Interne::ChangerTemps { objet: valeur, maintenant: false }), Err(Erreur::EPERM));
        assert_eq!(p.refuser(DAVID, Interne::Tronquer { objet: maps }), Err(Erreur::EACCES));
        // sysfs : créer est refusé par les droits, puis par EPERM.
        let s = NoyauFs::new(Genre::Sys, (0, 22), 0o755, Temps::default()).unwrap();
        assert_eq!(s.refuser(DAVID, Interne::Creer { dossier: RACINE, ouvrir: false }), Err(Erreur::EACCES));
        assert_eq!(s.refuser(Identite::ROOT, Interne::Creer { dossier: RACINE, ouvrir: false }), Err(Erreur::EPERM));
        // open(O_CREAT), pour root : EACCES (`lookup_open`).
        assert_eq!(s.refuser(Identite::ROOT, Interne::Creer { dossier: RACINE, ouvrir: true }), Err(Erreur::EACCES));
        // Changer le propriétaire : root le peut ; le propriétaire peut
        // donner le fichier à son propre groupe, pas à un autre.
        assert_eq!(p.refuser(Identite::ROOT, Interne::ChangerProprietaire { objet: maps, uid: Some(0), gid: Some(0) }), Ok(()));
        let mut q = proc_();
        let t = Temps::default();
        let a_lui = q.ajouter(RACINE, b"a-lui", 0o666, (1000, 0), Contenu::Fichier { source: 5, argument: 0 }, false, t).unwrap();
        let a_root = q.ajouter(RACINE, b"a-root", 0o666, (0, 0), Contenu::Fichier { source: 5, argument: 0 }, false, t).unwrap();
        assert_eq!(q.refuser(DAVID, Interne::ChangerProprietaire { objet: a_lui, uid: None, gid: Some(1000) }), Ok(()));
        assert_eq!(q.refuser(DAVID, Interne::ChangerProprietaire { objet: a_lui, uid: None, gid: Some(5) }), Err(Erreur::EPERM));
        // Qui peut écrire sans être le propriétaire : les dates à
        // maintenant, pas d'autres.
        assert_eq!(q.refuser(DAVID, Interne::ChangerTemps { objet: a_root, maintenant: true }), Ok(()));
        assert_eq!(q.refuser(DAVID, Interne::ChangerTemps { objet: a_root, maintenant: false }), Err(Erreur::EPERM));
        // Le dossier d'un processus est immuable : EPERM dès qu'un
        // identifiant est donné, même le sien, et pour ses dates ; pour
        // root aussi. Rien à changer (-1, -1) : 0.
        for qui in [DAVID, Identite::ROOT] {
            assert_eq!(p.refuser(qui, Interne::ChangerProprietaire { objet: deux, uid: Some(1000), gid: None }), Err(Erreur::EPERM));
            assert_eq!(p.refuser(qui, Interne::ChangerProprietaire { objet: deux, uid: None, gid: Some(1000) }), Err(Erreur::EPERM));
            assert_eq!(p.refuser(qui, Interne::ChangerTemps { objet: deux, maintenant: true }), Err(Erreur::EPERM));
            assert_eq!(p.refuser(qui, Interne::ChangerTemps { objet: deux, maintenant: false }), Err(Erreur::EPERM));
        }
        assert_eq!(p.refuser(DAVID, Interne::ChangerProprietaire { objet: deux, uid: None, gid: None }), Ok(()));
        // /proc/sys : pas de changement de propriétaire, pour root non plus.
        assert_eq!(p.refuser(Identite::ROOT, Interne::ChangerProprietaire { objet: valeur, uid: Some(0), gid: None }), Err(Erreur::EPERM));
        assert_eq!(p.refuser(Identite::ROOT, Interne::ChangerProprietaire { objet: valeur, uid: None, gid: None }), Ok(()));
    }

    #[test]
    fn numeros_et_disparitions() {
        let mut p = proc_();
        let t = Temps::default();
        let deux = p.chercher(RACINE, b"2").unwrap();
        let maps = p.chercher(deux, b"maps").unwrap();
        let exe = p.chercher(deux, b"exe").unwrap();
        let sys = p.chercher(RACINE, b"sys").unwrap();
        let vm = p.chercher(sys, b"vm").unwrap();
        let avant = p.entrees.len();
        // « . » et « .. » : leurs inodes, et la position suivante ; une
        // lecture reprise à la position 1 commence par « .. ».
        let mut vus = vec![];
        p.lire_dossier(deux, 0, &mut |nom, n, _, suivante| {
            vus.push((nom.to_vec(), n, suivante));
            vus.len() < 2
        })
        .unwrap();
        assert_eq!(vus, [(b".".to_vec(), deux as u64, 1), (b"..".to_vec(), RACINE as u64, 2)]);
        let mut premier = None;
        p.lire_dossier(deux, 1, &mut |nom, _, _, _| {
            premier = Some(nom.to_vec());
            false
        })
        .unwrap();
        assert_eq!(premier, Some(b"..".to_vec()));
        assert_eq!(p.lire_dossier(maps, 0, &mut |_, _, _, _| true), Err(Erreur::ENOTDIR));
        // Un lien annonce une taille nulle ; les dossiers de /proc/sys, un
        // seul lien.
        assert_eq!(p.attributs(exe).taille, 0);
        assert_eq!((p.attributs(sys).nlink, p.attributs(vm).nlink), (1, 1));
        // Un parent qui n'existe pas, ou qui n'est pas un dossier.
        assert_eq!(p.ajouter(77, b"x", 0o444, (0, 0), Contenu::Dossier, false, t), Err(Erreur::ENOENT));
        assert_eq!(p.ajouter(maps, b"x", 0o444, (0, 0), Contenu::Dossier, false, t), Err(Erreur::ENOTDIR));
        // Retirer le dossier d'un processus emporte tout ce qu'il contient,
        // et la table revient à sa taille.
        p.retirer(deux);
        assert_eq!(p.entrees.len(), avant - 3);
        for n in [deux, maps, exe] {
            assert_eq!(p.attributs(n).nlink, 0);
            assert_eq!(p.contenu(n), None);
        }
        assert_eq!(p.lire_dossier(deux, 0, &mut |_, _, _, _| true), Err(Erreur::ENOENT));
        // Un numéro n'est jamais repris : celui de l'ancien maps ne désigne
        // pas le statm du processus suivant.
        let trois = p.ajouter(RACINE, b"3", 0o555, (1000, 1000), Contenu::Dossier, true, t).unwrap();
        let statm = p.ajouter(trois, b"statm", 0o444, (1000, 1000), Contenu::Fichier { source: 2, argument: 3 }, true, t).unwrap();
        assert!(trois > exe && statm > trois);
        assert_eq!(p.contenu(maps), None);
        assert_eq!(p.contenu(statm), Some((2, 3)));
        // La racine ne se retire pas.
        p.retirer(RACINE);
        assert_eq!(p.attributs(RACINE).nlink, 4);
    }

    /// Un producteur de trois enregistrements, « a\n », « bbb\n », « cc\n »,
    /// dont le curseur est l'indice du suivant, et qui compte ses appels.
    fn trois(appels: &mut u32) -> impl FnMut(u64) -> Result<Enregistrement, Erreur> + '_ {
        move |curseur| {
            *appels += 1;
            Ok([&b"a\n"[..], b"bbb\n", b"cc\n"].get(curseur as usize).map(|e| (e.to_vec(), curseur + 1)))
        }
    }

    #[test]
    fn lectures_morcelees() {
        let tout = b"a\nbbb\ncc\n";
        // D'un seul trait.
        let mut n = 0;
        assert_eq!(Sequence::default().lire(0, 100, trois(&mut n)).unwrap(), tout);
        // Par morceaux de 1, 2, 3, 7 octets : le même texte.
        for taille in [1usize, 2, 3, 7] {
            let mut s = Sequence::default();
            let mut lu = vec![];
            loop {
                let mut n = 0;
                let m = s.lire(lu.len() as u64, taille, trois(&mut n)).unwrap();
                if m.is_empty() {
                    break;
                }
                lu.extend_from_slice(&m);
            }
            assert_eq!(lu, tout, "morceaux de {taille}");
        }
        // Une lecture ailleurs (pread en arrière) repart du début et
        // refabrique jusqu'à elle.
        let mut s = Sequence::default();
        let mut n = 0;
        assert_eq!(s.lire(0, 5, trois(&mut n)).unwrap(), b"a\nbbb"[..5]);
        let mut n = 0;
        assert_eq!(s.lire(1, 3, trois(&mut n)).unwrap(), b"\nbb");
        assert_eq!(n, 2);
        // Au-delà de la fin : rien ; une lecture de 0 octet : rien, sans
        // rien fabriquer (à toute position).
        let mut n = 0;
        assert_eq!(s.lire(50, 3, trois(&mut n)).unwrap(), b"");
        let mut s = Sequence::default();
        let mut n = 0;
        assert_eq!(s.lire(0, 0, trois(&mut n)).unwrap(), b"");
        assert_eq!(n, 0);
        // Lu jusqu'au bout, puis relu depuis 0 : tout, à nouveau.
        let mut s = Sequence::default();
        let mut n = 0;
        assert_eq!(s.lire(0, 100, trois(&mut n)).unwrap(), tout);
        assert_eq!(s.lire(9, 100, trois(&mut n)).unwrap(), b"");
        assert_eq!(s.lire(0, 100, trois(&mut n)).unwrap(), tout);
    }

    /// Des lignes de 81 octets : `nombre` en tout, et un compteur d'appels.
    fn lignes(nombre: u64) -> impl FnMut(u64) -> Result<Enregistrement, Erreur> {
        move |curseur| {
            Ok((curseur < nombre).then(|| {
                let mut l = alloc::format!("{:080}", curseur).into_bytes();
                l.push(b'\n');
                (l, curseur + 1)
            }))
        }
    }

    #[test]
    fn lectures_d_une_page() {
        // Une grande lecture rend des lignes entières, au plus une page
        // moins un octet (50 lignes de 81 octets : 4050) ; à la suite, tout
        // le texte.
        let mut s = Sequence::default();
        let mut lu = vec![];
        loop {
            let m = s.lire(lu.len() as u64, 1 << 17, lignes(200)).unwrap();
            if m.is_empty() {
                break;
            }
            assert!(m.len() < 4096 && m.len() % 81 == 0, "{}", m.len());
            lu.extend_from_slice(&m);
        }
        assert_eq!(lu.len(), 200 * 81);
        // Une petite lecture coupe la ligne ; la suivante rend d'abord ce
        // qui en reste.
        let mut s = Sequence::default();
        assert_eq!(s.lire(0, 10, lignes(3)).unwrap().len(), 10);
        assert_eq!(s.lire(10, 1000, lignes(3)).unwrap().len(), 3 * 81 - 10);
        // Un enregistrement plus grand qu'une page : rendu entier, dans un
        // tampon doublé.
        let mut grand = |curseur: u64| Ok((curseur == 0).then(|| (vec![b'x'; 5000], 1)));
        let mut s = Sequence::default();
        assert_eq!(s.lire(0, 1 << 17, &mut grand).unwrap().len(), 5000);
        assert_eq!(s.lire(5000, 1 << 17, &mut grand).unwrap().len(), 0);
        // Un producteur dont le curseur n'avance pas : poussé d'un cran,
        // rien ne boucle.
        let mut s = Sequence::default();
        let m = s.lire(0, 100, |c| Ok((c < 3).then(|| (b"z\n".to_vec(), 0)))).unwrap();
        assert_eq!(m, b"z\nz\nz\n");
        // Un manque de mémoire au milieu : la relecture rend les mêmes
        // octets.
        let mut s = Sequence::default();
        let debut = s.lire(0, 100, lignes(3)).unwrap();
        let mut panne = |c: u64| if c == 1 { Err(Erreur::ENOMEM) } else { lignes(3)(c) };
        assert_eq!(s.lire(1, 100, &mut panne), Err(Erreur::ENOMEM));
        assert_eq!(s.lire(1, 99, lignes(3)).unwrap(), debut[1..]);
    }
}
