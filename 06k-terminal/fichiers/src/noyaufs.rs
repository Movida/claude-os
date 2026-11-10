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
//! contenu en lectures (`Sequence`, le `seq_file` de Linux), et dit ce que
//! ces systèmes répondent à une modification (`refus`). Le noyau, lui,
//! fabrique les contenus ; pour /proc, il fabrique aussi à la demande les
//! dossiers des processus, d'après leur table (procfs.rs), et ne met ici
//! que la partie fixe.
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

use crate::chemins::Texte;
use crate::montages::{Interne, Monte};
use crate::tmpfs::{Attributs, DT_DIR, DT_LNK, DT_REG};
use crate::{ECRIRE, EXECUTER, Erreur, Identite, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Temps, permis};
use alloc::vec::Vec;
use faillible::VecFaillible;

/// Le genre du système : ce qu'il répond (voir l'en-tête).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Genre {
    Proc,
    Sys,
}

/// La cible d'un lien : elle dépend de qui le lit (les liens d'un
/// processus, /proc/<pid>/exe et fd/, sont fabriqués par le noyau,
/// procfs.rs).
#[derive(Clone, Debug)]
pub enum Cible {
    /// Le numéro du processus qui lit (/proc/self).
    Lecteur,
    /// Le fil qui lit, « <pid>/task/<tid> » (/proc/thread-self).
    LecteurFil,
}

/// Ce qu'est une entrée.
#[derive(Clone, Debug)]
pub enum Contenu {
    Dossier,
    /// Un fichier, dont le contenu vient de la source `source` du noyau,
    /// avec `argument`.
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
    /// Sa date de création (celle de ses trois dates).
    date: Temps,
}

/// Ce que désigne un numéro qui n'est pas dans la table (rien ne s'en
/// retire : seul un numéro faux le peut) : une entrée vide, à root, sans
/// nom ni contenu, plutôt qu'une panique ; readdir y rend ENOENT
/// (`lire_dossier`).
static ABSENTE: Entree = Entree {
    numero: 0,
    nom: Vec::new(),
    parent: RACINE,
    mode: 0,
    uid: 0,
    gid: 0,
    contenu: Contenu::Dossier,
    date: Temps { secondes: 0, nanosecondes: 0 },
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
    /// Le numéro de la prochaine entrée (ENOSPC au-delà de 32 bits).
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
        entrees.ajouter_dans_la_place(Entree {
            numero: RACINE,
            nom: Vec::new(),
            parent: RACINE,
            mode: S_IFDIR | (mode & 0o7777),
            uid: 0,
            gid: 0,
            contenu: Contenu::Dossier,
            date: maintenant,
        });
        Ok(NoyauFs { genre, peripherique, entrees, prochain: RACINE + 1 })
    }

    pub fn racine(&self) -> u64 {
        RACINE as u64
    }

    /// L'entrée de numéro `n`, si elle existe encore.
    fn trouver(&self, n: u32) -> Option<&Entree> {
        self.entrees.binary_search_by_key(&n, |e| e.numero).ok().map(|i| &self.entrees[i])
    }

    /// L'entrée de numéro `n`, ou `ABSENTE`.
    fn entree(&self, n: u32) -> &Entree {
        self.trouver(n).unwrap_or(&ABSENTE)
    }

    /// Ajoute `nom` dans le dossier `parent` : un dossier, un fichier ou un
    /// lien (`contenu`), de droits `droits`, à (`uid`, `gid`), daté de
    /// `maintenant`. Rend son numéro ; ENOENT si le parent n'existe pas,
    /// ENOTDIR s'il n'est pas un dossier, EEXIST si le nom est déjà pris,
    /// ENOMEM, ENOSPC.
    pub fn ajouter(&mut self, parent: u64, nom: &[u8], droits: u32, (uid, gid): (u32, u32), contenu: Contenu,
                   maintenant: Temps) -> Result<u64, Erreur> {
        let parent = entree32(parent);
        let p = self.trouver(parent).ok_or(Erreur::ENOENT)?;
        if p.mode & S_IFMT != S_IFDIR {
            return Err(Erreur::ENOTDIR);
        }
        if self.chercher_ici(parent, nom).is_some() {
            return Err(Erreur::EEXIST);
        }
        let genre = match contenu {
            Contenu::Dossier => S_IFDIR,
            Contenu::Fichier { .. } => S_IFREG,
            Contenu::Lien(_) => S_IFLNK,
        };
        let numero = self.prochain;
        let prochain = numero.checked_add(1).ok_or(Erreur::ENOSPC)?;
        let copie = faillible::copie(nom)?;
        self.entrees.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
        self.entrees.ajouter_dans_la_place(Entree {
            numero,
            nom: copie,
            parent,
            mode: genre | (droits & 0o7777),
            uid,
            gid,
            contenu,
            date: maintenant,
        });
        self.prochain = prochain;
        Ok(numero as u64)
    }

    /// Ce que désigne `nom` dans `dossier`.
    fn chercher_ici(&self, dossier: u32, nom: &[u8]) -> Option<u32> {
        self.entrees.iter().find(|e| e.parent == dossier && e.numero != dossier && e.nom == nom).map(|e| e.numero)
    }

    /// Ce qu'il faut savoir de l'entrée `n` pour la modifier (`refus`) :
    /// pour /proc, dont le noyau fabrique le reste (procfs.rs). Rien d'ici
    /// n'est dans le dossier d'un processus, ni immuable.
    pub fn proprietes(&self, n: u64) -> Proprietes {
        let n = entree32(n);
        let e = self.entree(n);
        Proprietes {
            mode: e.mode,
            uid: e.uid,
            gid: e.gid,
            parent: e.parent as u64,
            processus: false,
            immuable: false,
            dans_proc_sys: self.dans_proc_sys(n),
        }
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

/// Un numéro d'inode de la `Vue` (64 bits), en numéro d'entrée : au-delà
/// de 32 bits, aucune entrée (0 n'en est jamais une).
fn entree32(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(0)
}

impl Monte for NoyauFs {
    fn racine(&self) -> u64 {
        RACINE as u64
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
    /// sysfs ; ses fichiers, une page (mesuré). Un numéro absent : mode et
    /// liens nuls.
    fn attributs(&self, n: u64) -> Attributs {
        let n = entree32(n);
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
            numero: n as u64,
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

    fn chercher(&self, dossier: u64, nom: &[u8]) -> Option<u64> {
        self.chercher_ici(entree32(dossier), nom).map(u64::from)
    }

    fn parent(&self, n: u64) -> u64 {
        self.entree(entree32(n)).parent as u64
    }

    fn nom(&self, n: u64) -> Texte<'_> {
        Texte::Emprunte(&self.entree(entree32(n)).nom)
    }

    fn cible<'a>(&'a self, lien: u64, lecteur: &'a [u8], fil: &'a [u8]) -> Texte<'a> {
        Texte::Emprunte(match &self.entree(entree32(lien)).contenu {
            Contenu::Lien(Cible::Lecteur) => lecteur,
            Contenu::Lien(Cible::LecteurFil) => fil,
            _ => &[],
        })
    }

    /// « . » (position 0), « .. » (1), puis les entrées dans l'ordre de leur
    /// numéro : l'entrée `i` est à la position i + 2, et sa suivante à
    /// i + 3. Un numéro absent : ENOENT.
    fn lire_dossier(&self, dossier: u64, position: u64, entree: &mut dyn FnMut(&[u8], u64, u8, u64) -> bool)
        -> Result<(), Erreur> {
        let dossier = entree32(dossier);
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

    fn contenu(&self, n: u64) -> Option<(u32, u32)> {
        match self.trouver(entree32(n))?.contenu {
            Contenu::Fichier { source, argument } => Some((source, argument)),
            _ => None,
        }
    }

    /// Les règles communes des systèmes du noyau (`refus`).
    fn refuser(&self, qui: Identite, m: Interne) -> Result<(), Erreur> {
        refus(self.genre, qui, m, |n| self.proprietes(n))
    }
}

/// Ce qu'il faut savoir d'une entrée d'un système du noyau pour répondre à
/// une modification (`refus`) : celle d'un `NoyauFs`, ou une entrée de
/// /proc fabriquée à la demande (le noyau, procfs.rs).
#[derive(Clone, Copy, Debug)]
pub struct Proprietes {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub parent: u64,
    /// Un dossier où une écriture est refusée par EPERM avant même les
    /// droits (mesuré) : celui d'un processus, d'un fil, et fd/ (procfs.rs).
    pub processus: bool,
    /// Immuable (le S_IMMUTABLE de Linux, que procfs pose sur /proc/<pid>
    /// et task/<tid>, `proc_pid_instantiate`, `proc_task_instantiate`) :
    /// ni son propriétaire, ni ses droits, ni ses dates ne changent, pour
    /// personne (EPERM, avant toute autre vérification, `notify_change` ;
    /// mesuré : chown vers son propre propriétaire rend EPERM pour le
    /// dossier, 0 pour maps).
    pub immuable: bool,
    /// /proc/sys ou dedans.
    pub dans_proc_sys: bool,
}

/// Ce que répond un système du noyau de genre `genre` à la modification `m`
/// (mesuré sous Linux 6.18, pour un utilisateur ordinaire ; root passe les
/// droits, puis rien ne sait le faire : EPERM, l'erreur d'une opération
/// absente), d'après les propriétés de ses entrées :
///   - créer : procfs, ENOENT (sa recherche d'un nom absent échoue) ;
///     sysfs, le droit d'écrire dans le dossier (EACCES), puis EPERM, ou
///     EACCES pour open (`lookup_open`, lu dans les sources : un dossier
///     sans opération `create`) ;
///   - effacer, renommer, lier dans le système : dans le dossier d'un
///     processus, d'un fil ou fd/, EPERM ; ailleurs, le droit d'écrire
///     (EACCES), puis EPERM ; renommer vers un nom absent de procfs :
///     ENOENT ;
///   - changer les droits : EPERM ;
///   - changer le propriétaire : d'une entrée immuable (le dossier d'un
///     processus, d'un fil), ou dans /proc/sys (`proc_sys_setattr`),
///     EPERM dès qu'un identifiant est donné ; ailleurs, sans rien changer
///     (le même utilisateur, son propre groupe, ou -1), le propriétaire le
///     peut (0), sinon EPERM ; root : 0. Sans effet ici (Linux garde le
///     changement en mémoire tant que l'inode y reste) ;
///   - les dates : d'une entrée immuable, EPERM ; à maintenant, il
///     faut pouvoir écrire, ou être le propriétaire (EACCES) ; d'autres
///     dates, être le propriétaire (EPERM) ; sans effet ici ;
///   - truncate (d'un fichier ordinaire : `Vue::refus` a vu le reste) :
///     le droit d'écrire (EACCES), puis 0 (procfs ignore la taille,
///     `proc_setattr`).
/// Écarts pour root, écrits ici faute de pouvoir les mesurer sans
/// écrire dans /proc (nos programmes ne sont jamais root) : Linux le
/// laisse changer les droits de la racine de /proc (`simple_setattr`)
/// et d'un nœud de sysfs (`kernfs_iop_setattr`) ; nous rendons EPERM.
pub fn refus(genre: Genre, qui: Identite, m: Interne, proprietes: impl Fn(u64) -> Proprietes) -> Result<(), Erreur> {
    let droits = |n: u64, masque: u32| {
        let e = proprietes(n);
        permis(e.mode, e.uid, e.gid, qui, masque)
    };
    let proprietaire = |n: u64| qui.root() || qui.uid == proprietes(n).uid;
    // Écrire dans le dossier `d` : refusé dans un dossier de processus
    // (EPERM), sinon par les droits.
    let ecrire_dans = |d: u64| -> Erreur {
        if proprietes(d).processus {
            Erreur::EPERM
        } else if !droits(d, ECRIRE | EXECUTER) {
            Erreur::EACCES
        } else {
            Erreur::EPERM
        }
    };
    match m {
        Interne::Creer { dossier, ouvrir } => Err(match genre {
            Genre::Proc => Erreur::ENOENT,
            Genre::Sys if !droits(dossier, ECRIRE | EXECUTER) || ouvrir => Erreur::EACCES,
            Genre::Sys => Erreur::EPERM,
        }),
        Interne::Effacer { dossier, .. } => Err(ecrire_dans(dossier)),
        Interne::Renommer { ancien, nouveau } => Err(match (genre, nouveau) {
            (Genre::Proc, None) => Erreur::ENOENT,
            _ => ecrire_dans(proprietes(ancien).parent),
        }),
        Interne::Lier { .. } | Interne::ChangerMode { .. } => Err(Erreur::EPERM),
        Interne::ChangerProprietaire { objet, uid, gid } => {
            let e = proprietes(objet);
            let change = uid.is_some() || gid.is_some();
            if change && (e.immuable || e.dans_proc_sys) {
                return Err(Erreur::EPERM);
            }
            let uid_permis = uid.is_none_or(|u| proprietaire(objet) && u == e.uid);
            let gid_permis = gid.is_none_or(|g| proprietaire(objet) && (g == e.gid || g == qui.gid));
            if qui.root() || (uid_permis && gid_permis) { Ok(()) } else { Err(Erreur::EPERM) }
        }
        Interne::ChangerTemps { objet, maintenant } => {
            if proprietes(objet).immuable {
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
            sortie.ajouter_tranche(&reste[..n])?;
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
            self.tampon.ajouter_tranche(&e)?;
            self.curseur = suivant;
        }
        let n = self.tampon.len().min(longueur - sortie.len());
        sortie.try_reserve_exact(n).map_err(|_| Erreur::ENOMEM)?;
        sortie.ajouter_tranche(&self.tampon[..n])?;
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
    /// et un dossier à David, avec un fichier.
    fn proc_() -> NoyauFs {
        let t = Temps::default();
        let mut p = NoyauFs::new(Genre::Proc, (0, 21), 0o555, t).unwrap();
        p.ajouter(RACINE as u64, b"self", 0o777, (0, 0), Contenu::Lien(Cible::Lecteur), t).unwrap();
        let sys = p.ajouter(RACINE as u64, b"sys", 0o555, (0, 0), Contenu::Dossier, t).unwrap();
        let vm = p.ajouter(sys, b"vm", 0o555, (0, 0), Contenu::Dossier, t).unwrap();
        p.ajouter(vm, b"valeur", 0o644, (0, 0), Contenu::Fichier { source: 3, argument: 0 }, t).unwrap();
        let d = p.ajouter(RACINE as u64, b"d", 0o555, (1000, 1000), Contenu::Dossier, t).unwrap();
        p.ajouter(d, b"f", 0o444, (1000, 1000), Contenu::Fichier { source: 1, argument: 2 }, t).unwrap();
        p
    }

    #[test]
    fn arborescence() {
        let mut p = proc_();
        assert_eq!(p.attributs(u64::from(RACINE as u64)).numero, 1);
        let d = p.chercher(RACINE as u64, b"d").unwrap();
        let f = p.chercher(u64::from(d), b"f").unwrap();
        assert_eq!(p.contenu(u64::from(f)), Some((1, 2)));
        assert_eq!(p.attributs(u64::from(f)).taille, 0);
        assert_eq!(p.attributs(u64::from(f)).mode, S_IFREG | 0o444);
        assert_eq!(p.attributs(u64::from(f)).uid, 1000);
        // La racine : deux liens, plus un par sous-dossier (sys, d).
        assert_eq!(p.attributs(RACINE as u64).nlink, 4);
        assert_eq!(p.parent(u64::from(f)), d);
        assert_eq!(p.nom(u64::from(f)), b"f");
        let soi = p.chercher(RACINE as u64, b"self").unwrap();
        assert_eq!(p.cible(u64::from(soi), b"42", b"42/task/7"), b"42");
        let fil = p.ajouter(RACINE as u64, b"thread-self", 0o777, (0, 0), Contenu::Lien(Cible::LecteurFil), Temps::default()).unwrap();
        assert_eq!(p.cible(u64::from(fil), b"42", b"42/task/7"), b"42/task/7");
        assert_eq!(p.ajouter(d, b"f", 0o444, (0, 0), Contenu::Dossier, Temps::default()), Err(Erreur::EEXIST));
        // Les entrées, dans l'ordre de leurs numéros, et la position qui
        // suit chacune.
        let mut vus = vec![];
        p.lire_dossier(RACINE as u64, 0, &mut |nom, _, _, suivante| {
            vus.push((nom.to_vec(), suivante));
            true
        })
        .unwrap();
        assert_eq!(vus.iter().map(|(n, _)| n.as_slice()).collect::<Vec<_>>(), [&b"."[..], b"..", b"self", b"sys", b"d", b"thread-self"]);
        let apres_d = vus[4].1;
        let mut suite = vec![];
        p.lire_dossier(RACINE as u64, apres_d, &mut |nom, _, _, _| {
            suite.push(nom.to_vec());
            true
        })
        .unwrap();
        assert_eq!(suite, [b"thread-self".to_vec()]);
        // Un système de sysfs : des fichiers d'une page.
        let mut s = NoyauFs::new(Genre::Sys, (0, 22), 0o555, Temps::default()).unwrap();
        let f = s.ajouter(RACINE as u64, b"online", 0o444, (0, 0), Contenu::Fichier { source: 9, argument: 0 }, Temps::default()).unwrap();
        assert_eq!(s.attributs(u64::from(f)).taille, 4096);
        assert_eq!(s.taille_de_bloc(), 4096);
        assert_eq!(p.taille_de_bloc(), 1024);
    }

    #[test]
    fn refus() {
        let p = proc_();
        let d = p.chercher(RACINE as u64, b"d").unwrap();
        let f = p.chercher(u64::from(d), b"f").unwrap();
        let sys = p.chercher(RACINE as u64, b"sys").unwrap();
        let vm = p.chercher(u64::from(sys), b"vm").unwrap();
        let valeur = p.chercher(u64::from(vm), b"valeur").unwrap();
        // Le tableau mesuré sous Linux 6.18, pour /proc/self/maps, que
        // fabrique le noyau (procfs.rs) : ses propriétés, et celles de son
        // dossier, celui d'un processus (immuable, une écriture y est
        // refusée avant les droits).
        const PID: u64 = 100;
        const MAPS: u64 = 101;
        let fabriquees = |n: u64| match n {
            PID => Proprietes { mode: S_IFDIR | 0o555, uid: 1000, gid: 1000, parent: RACINE as u64, processus: true, immuable: true, dans_proc_sys: false },
            MAPS => Proprietes { mode: S_IFREG | 0o444, uid: 1000, gid: 1000, parent: PID, processus: true, immuable: false, dans_proc_sys: false },
            n => p.proprietes(n),
        };
        let r = |qui, m| super::refus(Genre::Proc, qui, m, &fabriquees);
        assert_eq!(r(DAVID, Interne::Creer { dossier: PID, ouvrir: false }), Err(Erreur::ENOENT));
        assert_eq!(r(DAVID, Interne::Effacer { dossier: PID, objet: MAPS, rmdir: false }), Err(Erreur::EPERM));
        assert_eq!(r(DAVID, Interne::Effacer { dossier: RACINE as u64, objet: sys, rmdir: true }), Err(Erreur::EACCES));
        assert_eq!(r(DAVID, Interne::Renommer { ancien: MAPS, nouveau: None }), Err(Erreur::ENOENT));
        assert_eq!(r(DAVID, Interne::ChangerMode { objet: MAPS }), Err(Erreur::EPERM));
        assert_eq!(r(DAVID, Interne::ChangerProprietaire { objet: MAPS, uid: Some(1000), gid: Some(1000) }), Ok(()));
        assert_eq!(r(DAVID, Interne::ChangerProprietaire { objet: MAPS, uid: None, gid: None }), Ok(()));
        assert_eq!(r(DAVID, Interne::ChangerProprietaire { objet: MAPS, uid: Some(0), gid: Some(0) }), Err(Erreur::EPERM));
        assert_eq!(r(DAVID, Interne::ChangerTemps { objet: MAPS, maintenant: true }), Ok(()));
        assert_eq!(r(DAVID, Interne::ChangerTemps { objet: MAPS, maintenant: false }), Ok(()));
        assert_eq!(r(DAVID, Interne::Tronquer { objet: MAPS }), Err(Erreur::EACCES));
        assert_eq!(r(Identite::ROOT, Interne::ChangerProprietaire { objet: MAPS, uid: Some(0), gid: Some(0) }), Ok(()));
        // Une entrée immuable : EPERM dès qu'un identifiant est donné, même
        // le sien, et pour ses dates ; pour root aussi. Rien à changer
        // (-1, -1) : 0.
        for qui in [DAVID, Identite::ROOT] {
            assert_eq!(r(qui, Interne::ChangerProprietaire { objet: PID, uid: Some(1000), gid: None }), Err(Erreur::EPERM));
            assert_eq!(r(qui, Interne::ChangerProprietaire { objet: PID, uid: None, gid: Some(1000) }), Err(Erreur::EPERM));
            assert_eq!(r(qui, Interne::ChangerTemps { objet: PID, maintenant: true }), Err(Erreur::EPERM));
            assert_eq!(r(qui, Interne::ChangerTemps { objet: PID, maintenant: false }), Err(Erreur::EPERM));
        }
        assert_eq!(r(DAVID, Interne::ChangerProprietaire { objet: PID, uid: None, gid: None }), Ok(()));
        // La partie fixe : ni dossier de processus ni immuable ; un dossier
        // à David mais 0555 refuse d'effacer par les droits.
        assert_eq!(p.refuser(DAVID, Interne::Effacer { dossier: d, objet: f, rmdir: false }), Err(Erreur::EACCES));
        assert_eq!(p.refuser(DAVID, Interne::ChangerTemps { objet: valeur, maintenant: true }), Err(Erreur::EACCES));
        assert_eq!(p.refuser(DAVID, Interne::ChangerTemps { objet: valeur, maintenant: false }), Err(Erreur::EPERM));
        // sysfs : créer est refusé par les droits, puis par EPERM.
        let s = NoyauFs::new(Genre::Sys, (0, 22), 0o755, Temps::default()).unwrap();
        assert_eq!(s.refuser(DAVID, Interne::Creer { dossier: RACINE as u64, ouvrir: false }), Err(Erreur::EACCES));
        assert_eq!(s.refuser(Identite::ROOT, Interne::Creer { dossier: RACINE as u64, ouvrir: false }), Err(Erreur::EPERM));
        // open(O_CREAT), pour root : EACCES (`lookup_open`).
        assert_eq!(s.refuser(Identite::ROOT, Interne::Creer { dossier: RACINE as u64, ouvrir: true }), Err(Erreur::EACCES));
        // Changer le propriétaire : le propriétaire peut donner le fichier
        // à son propre groupe, pas à un autre.
        let mut q = proc_();
        let t = Temps::default();
        let a_lui = q.ajouter(RACINE as u64, b"a-lui", 0o666, (1000, 0), Contenu::Fichier { source: 5, argument: 0 }, t).unwrap();
        let a_root = q.ajouter(RACINE as u64, b"a-root", 0o666, (0, 0), Contenu::Fichier { source: 5, argument: 0 }, t).unwrap();
        assert_eq!(q.refuser(DAVID, Interne::ChangerProprietaire { objet: a_lui, uid: None, gid: Some(1000) }), Ok(()));
        assert_eq!(q.refuser(DAVID, Interne::ChangerProprietaire { objet: a_lui, uid: None, gid: Some(5) }), Err(Erreur::EPERM));
        // Qui peut écrire sans être le propriétaire : les dates à
        // maintenant, pas d'autres.
        assert_eq!(q.refuser(DAVID, Interne::ChangerTemps { objet: a_root, maintenant: true }), Ok(()));
        assert_eq!(q.refuser(DAVID, Interne::ChangerTemps { objet: a_root, maintenant: false }), Err(Erreur::EPERM));
        // /proc/sys : pas de changement de propriétaire, pour root non plus.
        assert_eq!(p.refuser(Identite::ROOT, Interne::ChangerProprietaire { objet: valeur, uid: Some(0), gid: None }), Err(Erreur::EPERM));
        assert_eq!(p.refuser(Identite::ROOT, Interne::ChangerProprietaire { objet: valeur, uid: None, gid: None }), Ok(()));
    }

    #[test]
    fn numeros() {
        let p = proc_();
        let t = Temps::default();
        let d = p.chercher(RACINE as u64, b"d").unwrap();
        let f = p.chercher(u64::from(d), b"f").unwrap();
        let soi = p.chercher(RACINE as u64, b"self").unwrap();
        let sys = p.chercher(RACINE as u64, b"sys").unwrap();
        let vm = p.chercher(u64::from(sys), b"vm").unwrap();
        // « . » et « .. » : leurs inodes, et la position suivante ; une
        // lecture reprise à la position 1 commence par « .. ».
        let mut vus = vec![];
        p.lire_dossier(u64::from(d), 0, &mut |nom, n, _, suivante| {
            vus.push((nom.to_vec(), n, suivante));
            vus.len() < 2
        })
        .unwrap();
        assert_eq!(vus, [(b".".to_vec(), d as u64, 1), (b"..".to_vec(), RACINE as u64, 2)]);
        let mut premier = None;
        p.lire_dossier(u64::from(d), 1, &mut |nom, _, _, _| {
            premier = Some(nom.to_vec());
            false
        })
        .unwrap();
        assert_eq!(premier, Some(b"..".to_vec()));
        assert_eq!(p.lire_dossier(u64::from(f), 0, &mut |_, _, _, _| true), Err(Erreur::ENOTDIR));
        // Un lien annonce une taille nulle ; les dossiers de /proc/sys, un
        // seul lien.
        assert_eq!(p.attributs(u64::from(soi)).taille, 0);
        assert_eq!((p.attributs(u64::from(sys)).nlink, p.attributs(u64::from(vm)).nlink), (1, 1));
        // Un parent qui n'existe pas, ou qui n'est pas un dossier.
        let mut q = proc_();
        assert_eq!(q.ajouter(77, b"x", 0o444, (0, 0), Contenu::Dossier, t), Err(Erreur::ENOENT));
        assert_eq!(q.ajouter(f, b"x", 0o444, (0, 0), Contenu::Dossier, t), Err(Erreur::ENOTDIR));
        // Un numéro absent (au-delà de 32 bits, ou jamais donné) : une
        // entrée vide, rien à lister.
        for n in [77, 1 << 40] {
            assert_eq!(p.attributs(n).nlink, 0);
            assert_eq!(p.contenu(n), None);
            assert_eq!(p.lire_dossier(n, 0, &mut |_, _, _, _| true), Err(Erreur::ENOENT));
        }
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
