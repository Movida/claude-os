//! Les appels système des fichiers : ouvrir, lire, écrire, se déplacer,
//! décrire (stat), dupliquer, fermer. Ce que la glibc et ld-linux demandent
//! (mesuré par strace sur l'hôte, voir le plan de 6b), avec les
//! vérifications et les codes d'erreur de Linux, dans son ordre.
//!
//! Chaque appel suit le même chemin :
//!   1. copier ce que donne le programme (un chemin, un tableau d'iovec)
//!      dans un tampon du noyau, sans rien tenir ;
//!   2. sous le verrou du processus, trouver le descripteur, et TENIR son
//!      fichier ouvert (une référence) ; sous celui des fichiers (vfs.rs),
//!      l'inode, la page ;
//!   3. rendre les verrous, puis seulement copier entre la page et le
//!      programme : une copie peut faire une faute de page, qui prend la
//!      mémoire du processus (un verrou qui dort, depuis 6i), et celui des
//!      fichiers pour une page projetée d'un fichier (memoire.rs). La page est
//!      tenue (pages::prendre) pendant la copie : elle ne peut pas
//!      disparaître sous elle, comme dans le `filemap_read` de Linux.
//!
//! Pourquoi tenir : depuis 6e, une autre tâche peut s'exécuter entre deux
//! sections (la préemption), et un autre fil du même programme (clone,
//! fil.rs), qui partage ses descripteurs et son dossier courant. Ce qu'un appel
//! trouve sous un verrou et dont il se sert sous un autre doit donc être
//! tenu entre les deux : sinon un `close`, un `chdir` ou un `rmdir` de
//! l'autre fil le fait disparaître (le noyau s'arrête sur un fichier ouvert
//! ou un inode qui n'existe plus), ou pire, son numéro sert à un autre (un
//! `mmap` projetterait un fichier dont on n'a pas vérifié le droit de
//! lecture). Comme Linux :
//!   - le fichier d'un descripteur est tenu le temps de l'appel
//!     (`FichierTenu`, le `fdget` et le `fdput` de Linux) ;
//!   - un numéro de descripteur neuf est réservé dans la section qui le
//!     choisit, puis le fichier y est installé (`NumeroReserve` : le
//!     `get_unused_fd_flags` puis le `fd_install` de Linux) ;
//!   - la racine et le dossier d'où part un chemin sont tenus le temps de
//!     la résolution (`DepartTenu`, le `get_fs_pwd`), puis l'objet trouvé
//!     le temps de s'en servir (`ObjetTenu`, le `path_get`) ;
//!   - la position d'un fichier ne change que sous son verrou, l'écriture
//!     d'un fichier et sa troncature que sous celui de son inode
//!     (`verrous` : le `f_pos_lock` de `fdget_pos`, et l'`inode_lock`).
//! Option écartée : faire tout l'appel sous le verrou du processus, celui
//! des fichiers pris dedans (l'ordre le permet). Une copie depuis ou vers
//! le programme ne peut pas s'y faire (elle peut fauter, et servir la
//! faute prend la mémoire du processus, qu'on ne prend pas sous un verrou
//! court), et un fil qui résout un long chemin arrêterait tous les autres.

use alloc::vec::Vec;

use crate::copie_utilisateur::{
    ErreurChaine, chaine_depuis_utilisateur, copier_depuis_utilisateur, copier_depuis_utilisateur_partiel,
    copier_vers_utilisateur, copier_vers_utilisateur_partiel, dans_les_bornes,
};
use crate::descripteurs::{Descripteur, Fichier, FichierOuvert, Lecture, Prive, Refus, Sorte, Tenu};
use crate::faillible::{self, VecFaillible};
use crate::processus::Processus;
use crate::vfs::{self, CadresDuNoyau, Systeme};
use crate::{aleatoire, console, evenements, pages, processus, procfs, signaux, surveillance, tache, temps};
use fichiers::chemins::{Arbre, Depart, Dernier, Fin, PATH_MAX, Suivre};
use fichiers::montages::{Creation, Modification, Objet, Vue, dans_le_tmpfs, en_tmpfs};
use crate::vfs::Montage;
use fichiers::tmpfs::{Attributs, Numero, Ouverture, limite_ecriture, suivre_pour};
use fichiers::{Erreur, Identite, PAGE, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, permis};
use crate::attente::{GardeMutex, Mutex};
use crate::pages::Page;
use crate::tube::Poseur;
use crate::surveillance::{IN_ACCESS, IN_ATTRIB, IN_CREATE, IN_DELETE, IN_MODIFY, IN_OPEN};

// Les numéros d'erreur de Linux qui ne viennent pas du tmpfs.
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EBUSY: i64 = 16;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const EFBIG: i64 = 27;
/// Une écriture au-delà de RLIMIT_FSIZE (`generic_write_check_limits`).
const SIGXFSZ: u64 = 25;
const ENOTTY: i64 = 25;
const ENOSPC: i64 = 28;
const EXDEV: i64 = 18;
const EOVERFLOW: i64 = 75;
const ESPIPE: i64 = 29;
const ENAMETOOLONG: i64 = 36;
const EOPNOTSUPP: i64 = 95;

fn errno(e: Erreur) -> i64 {
    -e.errno()
}

// Les drapeaux d'open (include/uapi/asm-generic/fcntl.h, en octal).
const O_ACCMODE: u64 = 0o3;
const O_RDONLY: u64 = 0o0;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NOCTTY: u64 = 0o400;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;
const O_NONBLOCK: u64 = 0o4000;
const O_ASYNC: u64 = 0o20000;
const O_LARGEFILE: u64 = 0o100000;
const O_DIRECT: u64 = 0o40000;
const O_DIRECTORY: u64 = 0o200000;
const O_NOFOLLOW: u64 = 0o400000;
const O_CLOEXEC: u64 = 0o2000000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20000000;

// Les appels *at.
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EACCESS: u64 = 0x200;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
/// Les choix de synchronisation de statx, sans objet en mémoire.
const AT_STATX_SYNC_TYPE: u64 = 0x6000;

/// Le plus d'octets qu'un read ou un write transfère d'un coup : celui de
/// Linux (MAX_RW_COUNT, 2 Gio moins une page) ; au-delà, une partie,
/// comme le permet POSIX.
pub const RW_MAX: u64 = 0x7fff_f000;
/// Le plus d'octets écrits d'un coup sur la console : un vrai port série à
/// 115 200 bauds en met déjà 90 ms à 1024 octets (comme fd_write de WASI).
const CONSOLE_MAX: usize = 1024;

/// Une page de zéros, à copier vers un programme (un trou de fichier,
/// /dev/zero).
static ZEROS: [u8; PAGE as usize] = [0; PAGE as usize];

/// Le chemin à l'adresse `adresse` du programme (au plus PATH_MAX octets,
/// zéro compris).
fn chemin(adresse: u64) -> Result<Vec<u8>, i64> {
    chaine_depuis_utilisateur(adresse, PATH_MAX).map_err(|e| match e {
        ErreurChaine::Faute => -EFAULT,
        ErreurChaine::TropLongue => -ENAMETOOLONG,
        ErreurChaine::PlusDeMemoire => -ENOMEM,
    })
}

/// Un fichier ouvert tenu le temps d'un appel système (le `struct fd` que
/// rend le `fdget` de Linux) : une référence prise sous le verrou du
/// processus, dans la section même qui a trouvé le descripteur, et rendue à
/// la fin de la garde (le `fdput`). Un `close` du descripteur par un autre
/// fil pendant l'appel ne lâche que la référence du descripteur : le
/// fichier reste, et son numéro (`Fichier`) ne peut pas servir à un autre ;
/// s'il était le dernier à le tenir, c'est la fin de l'appel qui le ferme,
/// comme sous Linux. Avec ce qu'il faut savoir du fichier : ce qui ne
/// change pas tant qu'il est ouvert (sa sorte, son objet, son mode
/// d'ouverture), et ses drapeaux et le FD_CLOEXEC du descripteur au début
/// de l'appel. Option écartée : l'économie de Linux, qui ne prend pas de
/// référence quand la table des descripteurs n'est pas partagée (personne
/// ne peut alors fermer le descripteur) ; ici, la référence ne coûte qu'un
/// compteur, sous le verrou qu'il faut prendre de toute façon pour lire le
/// fichier ouvert.
pub struct FichierTenu {
    fichier: Fichier,
    pub sorte: Sorte,
    /// Son objet du noyau, s'il en a un (un eventfd).
    pub prive: Prive,
    pub objet: Objet,
    pub lecture: bool,
    pub ecriture: bool,
    pub drapeaux: u32,
    pub fermer_a_l_exec: bool,
}

impl FichierTenu {
    pub fn fichier(&self) -> Fichier {
        self.fichier
    }

    /// L'inode du tmpfs d'un fichier dont la sorte ne vient que de lui (un
    /// fichier ordinaire : voir `FichierOuvert::inode`).
    fn numero(&self) -> Numero {
        self.objet.tmpfs().expect("une sorte du tmpfs sur un objet d'un systeme monte")
    }

    /// Sa position : à lire sous son verrou (`verrous`) pour s'en servir.
    fn position(&self) -> u64 {
        vfs::avec_systeme(|s, _| s.ouverts.fichier(self.fichier).position)
    }

    /// Sous son verrou de position, lui aussi.
    fn changer_position(&self, position: u64) {
        vfs::avec_systeme(|s, _| s.ouverts.fichier(self.fichier).position = position);
    }

    /// Le même fichier, tenu une fois de plus (le `get_file` de Linux) : une
    /// entrée de `poll` le garde ainsi tant qu'elle est inscrite dans sa file
    /// (sondage.rs), même s'il est fermé entre-temps.
    pub fn dupliquer(&self) -> FichierTenu {
        vfs::avec_systeme(|s, _| s.ouverts.prendre(self.fichier));
        FichierTenu {
            fichier: self.fichier,
            sorte: self.sorte,
            prive: self.prive.clone(),
            objet: self.objet,
            lecture: self.lecture,
            ecriture: self.ecriture,
            drapeaux: self.drapeaux,
            fermer_a_l_exec: self.fermer_a_l_exec,
        }
    }

    /// L'eventfd d'un fichier de sorte EventFd.
    pub fn eventfd(&self) -> &evenements::EventFd {
        match &self.prive {
            Prive::EventFd(e) => e,
            _ => unreachable!("un eventfd sans compteur"),
        }
    }

    /// Le tube d'un bout de tube.
    pub fn tube(&self) -> &crate::tube::Tube {
        match &self.prive {
            Prive::Tube(t) => t,
            _ => unreachable!("un tube sans objet"),
        }
    }

    /// La socket d'un fichier de sorte Socket.
    /// Son fichier ouvert.
    pub fn fichier_ouvert(&self) -> Fichier {
        self.fichier
    }

    pub fn socket(&self) -> &crate::partage::Arc<crate::reseau::socket::Socket> {
        match &self.prive {
            Prive::Socket(s) => s,
            _ => unreachable!("une socket sans objet"),
        }
    }

    /// L'instance d'inotify d'un fichier de sorte Inotify ; None pour une
    /// autre sorte.
    pub fn inotify(&self) -> Option<&crate::partage::Arc<surveillance::Groupe>> {
        match &self.prive {
            Prive::Inotify(g) => Some(g),
            _ => None,
        }
    }

    /// L'epoll d'un fichier de sorte Epoll.
    pub fn epoll(&self) -> &crate::epoll::Epoll {
        match &self.prive {
            Prive::Epoll(e) => e,
            _ => unreachable!("un epoll sans objet"),
        }
    }

}

impl Drop for FichierTenu {
    /// La fin de l'appel : la référence rendue, et le fichier fermé si
    /// c'était la dernière. Jamais sous le verrou des fichiers ni sous celui
    /// du processus (on prend le premier).
    fn drop(&mut self) {
        vfs::avec_systeme(|s, cadres| s.lacher(self.fichier, cadres));
    }
}

/// Tient le fichier du descripteur `fd` du processus en cours (EBADF s'il
/// n'est pas ouvert).
pub fn tenir(fd: u64) -> Result<FichierTenu, i64> {
    vfs::avec_systeme(|s, _| {
        // Le verrou des descripteurs, pris sous celui des fichiers (l'ordre
        // de processus.rs) : un close d'un autre fil retire le descripteur
        // sous le premier, puis lâche son fichier sous le second ; il
        // attend donc que nous l'ayons tenu, ou nous ne le trouvons plus.
        let d = processus::descripteurs(|d| d.get(fd))?;
        let mut o = tenir_ouvert(s, d.fichier);
        o.fermer_a_l_exec = d.fermer_a_l_exec;
        Some(o)
    })
    .ok_or(-EBADF)
}

/// Tient le fichier ouvert `f`, sous le verrou des fichiers : un élément
/// d'epoll le désigne ainsi, sans descripteur (epoll.rs).
pub fn tenir_ouvert(s: &mut Systeme, f: Fichier) -> FichierTenu {
    s.ouverts.prendre(f);
    let o = s.ouverts.fichier(f);
    FichierTenu {
        fichier: f,
        sorte: o.sorte,
        prive: o.prive.clone(),
        objet: o.objet(),
        lecture: o.lecture,
        ecriture: o.ecriture,
        drapeaux: o.drapeaux,
        fermer_a_l_exec: false,
    }
}

/// Les verrous de position des fichiers ouverts (le `f_pos_lock` de
/// Linux) : 64 verrous qui dorment, celui d'un fichier ouvert choisi par son
/// numéro, comme les verrous d'écriture (`verrou_d_ecriture`). Un verrou
/// dans chaque fichier ouvert serait celui de Linux, mais la table des
/// fichiers ouverts est un vecteur qui se déplace quand il grandit, et un
/// verrou qui dort ne doit pas bouger tant qu'on l'attend.
static VERROUS_DE_POSITION: [Mutex<()>; 64] = [const { Mutex::new(()) }; 64];

/// Les verrous d'un appel qui se sert d'un fichier ouvert, rendus à la fin
/// de la garde (celui de l'inode d'abord).
struct Verrous {
    _ecriture: Option<GardeMutex<'static, ()>>,
    _position: Option<GardeMutex<'static, ()>>,
}

/// Les verrous qu'il faut à un appel sur `f`, pris dans l'ordre de Linux,
/// la position puis l'inode :
///   - celui de sa position, si l'appel s'en sert (`a_la_position` : read,
///     write, readv, writev, lseek, getdents64 ; pas pread) et que le
///     fichier en a une (un fichier ordinaire ou un dossier : le
///     FMODE_ATOMIC_POS de Linux). Deux fils qui lisent à la suite le même
///     fichier ouvert lisent chacun sa part, sans octet lu deux fois ni
///     sauté, comme le demande POSIX (Linux le garantit depuis 3.14) ;
///   - pour un fichier du noyau (/proc, /sys), celui de sa position pour
///     tout appel, pread compris : il garde aussi l'état de sa séquence,
///     qui sort du fichier ouvert pendant la lecture (le `m->lock` du
///     seq_file de Linux, procfs::lire) ;
///   - celui de l'inode, pour écrire dans un fichier ordinaire
///     (`verrou_d_ecriture`) : tenu sur tous les morceaux d'un writev,
///     deux writev en O_APPEND ne s'entremêlent pas.
fn verrous(f: &FichierTenu, a_la_position: bool, ecriture: bool) -> Verrous {
    let position = match f.sorte {
        Sorte::Fichier | Sorte::Dossier => a_la_position,
        Sorte::Noyau { .. } => true,
        _ => false,
    };
    Verrous {
        _position: position.then(|| VERROUS_DE_POSITION[f.fichier.numero() as usize % 64].verrouiller()),
        _ecriture: (ecriture && f.sorte == Sorte::Fichier).then(|| verrou_d_ecriture(f.numero())),
    }
}

/// Un objet de l'arborescence tenu le temps d'un appel (le `path_get` de
/// Linux) : un inode du tmpfs, par une référence, pour qu'un `unlink` ou un
/// `rmdir` d'une autre tâche ne le fasse pas disparaître (ni servir son
/// numéro à un autre) pendant qu'on s'en sert. Un objet d'un système du
/// noyau n'a rien à tenir : ses objets sont au noyau, et un processus
/// disparu se voit à la lecture (ESRCH).
pub struct ObjetTenu(Objet);

impl ObjetTenu {
    /// Tient `o`, sous le verrou des fichiers.
    fn tenir(s: &mut Systeme, o: Objet) -> ObjetTenu {
        if let Some(n) = o.tmpfs() {
            s.fs.prendre(n);
        }
        ObjetTenu(o)
    }

    pub fn objet(&self) -> Objet {
        self.0
    }
}

impl Drop for ObjetTenu {
    /// La référence rendue : l'inode disparaît s'il n'a plus de nom ni
    /// d'autre référence. Jamais sous un verrou.
    fn drop(&mut self) {
        if let Some(n) = self.0.tmpfs() {
            vfs::avec(|fs, cadres| fs.lacher(n, cadres));
        }
    }
}

/// D'où part la résolution d'un chemin, tenu jusqu'à sa fin : la racine et
/// le dossier de départ, et qui résout (ses droits, et son numéro de
/// processus pour /proc/self).
struct DepartTenu {
    racine: ObjetTenu,
    dossier: ObjetTenu,
    qui: Identite,
    pid: u32,
}

impl DepartTenu {
    fn depart(&self) -> Depart<Objet> {
        Depart { racine: self.racine.objet(), dossier: self.dossier.objet(), qui: self.qui, sous: false }
    }
}

/// Sous le verrou du processus `p` et celui des fichiers : le dossier
/// courant (AT_FDCWD, ou `courant`), ou l'objet du fichier du descripteur
/// `dirfd` (EBADF), tenu.
fn tenir_dossier(p: &Processus, s: &mut Systeme, dirfd: u64, courant: bool) -> Result<ObjetTenu, i64> {
    let o = if courant || dirfd as i32 == AT_FDCWD {
        p.dossier
    } else {
        // Celui des descripteurs, sous les deux (l'ordre de processus.rs).
        let d = processus::descripteurs(|d| d.get(dirfd)).ok_or(-EBADF)?;
        s.ouverts.fichier(d.fichier).objet()
    };
    Ok(ObjetTenu::tenir(s, o))
}

/// D'où part la résolution de `chemin`, pour un appel *at : le dossier
/// courant (AT_FDCWD) ou celui du descripteur `dirfd` (qui doit en être un
/// : ENOTDIR, à la résolution). Un chemin absolu ignore `dirfd`, même
/// invalide, comme Linux. Tout est pris dans une seule section du
/// processus : un `chdir` ou un `close` d'un autre fil passe avant ou
/// après, jamais entre la lecture du dossier et sa référence.
fn depart(dirfd: u64, chemin: &[u8]) -> Result<DepartTenu, i64> {
    let absolu = chemin.first() == Some(&b'/');
    processus::avec(|p| {
        vfs::avec_systeme(|s, _| {
            let dossier = tenir_dossier(p, s, dirfd, absolu)?;
            Ok(DepartTenu { racine: ObjetTenu::tenir(s, p.racine), dossier, qui: p.identite, pid: p.pid })
        })
    })
}

/// Résout `chemin` (non vide) depuis `dirfd`, sous le verrou des fichiers,
/// à travers les montages, et appelle `f` avec le résultat.
fn avec_fin<R>(dirfd: u64, chemin: &[u8], suivre: Suivre,
               f: impl FnOnce(&mut Systeme, &mut CadresDuNoyau, Fin<Objet>, Depart<Objet>, u32) -> Result<R, i64>)
    -> Result<R, i64> {
    let tenu = depart(dirfd, chemin)?;
    let (depart, pid) = (tenu.depart(), tenu.pid);
    vfs::avec_systeme(|s, cadres| {
        let fin = s.resoudre(pid, &depart, chemin, suivre).map_err(errno)?;
        f(s, cadres, fin, depart, pid)
    })
}

/// Le refus d'une modification qui touche un système monté
/// (fichiers::montages::Vue::refus), vue par le processus `pid`.
fn refus(s: &Systeme, pid: u32, qui: Identite, m: Modification) -> i64 {
    match s.avec_vue(pid, |vue| vue.refus(qui, m)) {
        // Permise, et sans effet (les dates d'un fichier de /proc).
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

/// Le chemin canonique de ce que désigne `fin` (pour le fichier ouvert,
/// `FichierOuvert::chemin`), vide s'il ne peut pas être calculé.
fn canonique(s: &Systeme, pid: u32, fin: &Fin<Objet>) -> Vec<u8> {
    s.avec_vue(pid, |vue| {
        // Un lien magique en dernier (/proc/<pid>/fd/N, /proc/<pid>/exe) :
        // ce qu'il désigne garde le chemin du fichier (Linux rouvre le même
        // `struct path`), même effacé ou sans nom ; jamais un chemin
        // calculé d'après l'objet, qui n'existe que pour un dossier.
        if fin.dernier == Dernier::Nom
            && let Some(objet) = fin.objet
            && let Some(lien) = vue.chercher(fin.dossier, &fin.nom)
            && vue.saut(lien) == Some(objet)
            && let Some(chemin) = vue.chemin_du_saut(lien)
        {
            return Ok(faillible::copie(&chemin)?);
        }
        vue.chemin_de(fin)
    })
    .unwrap_or_default()
}

/// Le fichier ouvert que désigne `fin`, si son dernier composant est un lien
/// magique (/proc/<pid>/fd/N) : Linux rouvre alors son `struct path`.
fn saut(s: &Systeme, pid: u32, fin: &Fin<Objet>) -> Option<Fichier> {
    if fin.dernier != Dernier::Nom {
        return None;
    }
    let objet = fin.objet?;
    s.avec_vue(pid, |vue| {
        let lien = vue.chercher(fin.dossier, &fin.nom)?;
        if vue.saut(lien) != Some(objet) {
            return None;
        }
        procfs::fichier_du_saut(lien)
    })
}

/// Le lieu de ce que désigne `fin` (pour inotify : surveillance::Lieu),
/// préparé : le dernier composant et son dossier ; pour « . », « .. » et la
/// racine, le dossier dans son parent ; au bout d'un lien magique, le lieu
/// du fichier ouvert qu'il désigne. Dans un système monté aussi, sauf pour
/// sa racine (un point de montage). ENOMEM s'il n'y a pas la place du nom.
pub fn preparer_lieu(s: &Systeme, pid: u32, fin: &Fin<Objet>) -> Result<Option<surveillance::LieuPrepare>, i64> {
    if let Some(f) = saut(s, pid, fin) {
        return match s.ouverts.voir(f).and_then(|o| o.lieu.as_ref()) {
            Some(l) => surveillance::LieuPrepare::copie(l).map(Some).map_err(|_| -ENOMEM),
            None => Ok(None),
        };
    }
    let r = match (fin.dernier, fin.dossier, fin.objet) {
        (Dernier::Nom, d @ Objet::Tmpfs(_), None | Some(Objet::Tmpfs(_))) | (Dernier::Nom, d @ Objet::Monte(..), Some(Objet::Monte(..))) => {
            surveillance::LieuPrepare::entree(d, &fin.nom).map(Some)
        }
        (Dernier::Point | Dernier::PointPoint | Dernier::Racine, _, Some(Objet::Tmpfs(n))) => {
            surveillance::LieuPrepare::du_dossier(&s.fs, n)
        }
        (Dernier::Point | Dernier::PointPoint | Dernier::Racine, _, Some(o @ Objet::Monte(..))) => {
            s.avec_vue(pid, |vue| surveillance::LieuPrepare::du_dossier_monte(vue, o))
        }
        _ => Ok(None),
    };
    r.map_err(|_| -ENOMEM)
}

/// Un chemin tenu le temps d'un appel (le `struct path` que Linux garde de
/// la résolution jusqu'à la fin de l'appel) : un fichier ouvert O_PATH, qui
/// ne dit rien à inotify, mais dont le lieu suit un renommage (vfs.rs) :
/// l'événement de l'appel (chmod, truncate...) va au dossier et au nom que
/// l'objet a à ce moment-là, comme chez Linux. Lâché à la fin de la garde.
pub struct CheminTenu {
    fichier: Fichier,
    objet: Objet,
}

impl CheminTenu {
    pub fn objet(&self) -> Objet {
        self.objet
    }

    pub fn fichier(&self) -> Fichier {
        self.fichier
    }
}

impl Drop for CheminTenu {
    /// Jamais sous un verrou.
    fn drop(&mut self) {
        vfs::avec_systeme(|s, cadres| s.lacher(self.fichier, cadres));
    }
}

/// Un fichier ouvert O_PATH neuf pour `objet`, avec son lieu (`CheminTenu`).
fn chemin_ouvert(s: &mut Systeme, objet: Objet, lieu: Option<surveillance::LieuPrepare>, cadres: &mut CadresDuNoyau)
    -> Result<CheminTenu, i64> {
    let tenu = match objet {
        Objet::Tmpfs(n) => {
            s.fs.prendre(n);
            Tenu::Tmpfs(fichiers::tmpfs::Ouvert { numero: n, cree: false, tronquer: false, ecrivain: false })
        }
        o => Tenu::Noyau(o),
    };
    let f = FichierOuvert::new(Sorte::Chemin, tenu, false, false, O_PATH as u32, b"");
    match s.ouverts.ajouter(f) {
        Ok(fichier) => {
            if let Some(l) = lieu {
                s.ouverts.fichier(fichier).lieu = l.achever(&mut s.fs, objet);
            }
            Ok(CheminTenu { fichier, objet })
        }
        Err(f) => {
            if let Tenu::Tmpfs(o) = f.tenu {
                s.fs.fermer(&o, cadres);
            }
            Err(-ENOMEM)
        }
    }
}

/// Comme `objet`, tenu par un `CheminTenu`. Un chemin vide (AT_EMPTY_PATH)
/// : le fichier ouvert du descripteur lui-même, tenu une fois de plus, ou
/// le dossier courant.
fn tenir_chemin(dirfd: u64, chemin: &[u8], suivre: bool, vide_permis: bool) -> Result<CheminTenu, i64> {
    if chemin.is_empty() {
        if !vide_permis {
            return Err(errno(Erreur::ENOENT));
        }
        return processus::avec(|p| {
            vfs::avec_systeme(|s, cadres| {
                if dirfd as i32 != AT_FDCWD {
                    let fichier = processus::descripteurs(|d| d.get(dirfd)).ok_or(-EBADF)?.fichier;
                    s.ouverts.prendre(fichier);
                    return Ok(CheminTenu { fichier, objet: s.ouverts.fichier(fichier).objet() });
                }
                let lieu = match p.dossier {
                    Objet::Tmpfs(n) => surveillance::LieuPrepare::du_dossier(&s.fs, n),
                    o => s.avec_vue(p.pid, |vue| surveillance::LieuPrepare::du_dossier_monte(vue, o)),
                }
                .map_err(|_| -ENOMEM)?;
                chemin_ouvert(s, p.dossier, lieu, cadres)
            })
        });
    }
    let tenu = depart(dirfd, chemin)?;
    vfs::avec_systeme(|s, cadres| {
        let fin = s.resoudre(tenu.pid, &tenu.depart(), chemin, if suivre { Suivre::Toujours } else { Suivre::AvecBarre })
            .map_err(errno)?;
        let objet = fin.objet.ok_or(errno(Erreur::ENOENT))?;
        if fin.barre && !s.avec_vue(tenu.pid, |vue| fichiers::montages::est_dossier(vue, objet)) {
            return Err(errno(Erreur::ENOTDIR));
        }
        let lieu = preparer_lieu(s, tenu.pid, &fin)?;
        chemin_ouvert(s, objet, lieu, cadres)
    })
}

/// Ce que surveille inotify_add_watch (surveillance.rs) : l'objet de
/// `adresse`, tenu (le lien final suivi si `suivre`), s'il est un dossier,
/// et si l'appelant a le droit de le lire (`path_permission(MAY_READ)`).
pub fn objet_pour_surveiller(adresse: u64, suivre: bool) -> Result<(ObjetTenu, bool, bool), i64> {
    const LIRE: u32 = 4;
    let chemin = chemin(adresse)?;
    let o = objet(AT_FDCWD as u64, &chemin, suivre, false)?;
    let qui = processus::avec(|p| p.identite);
    let a = attributs(o.objet());
    Ok((o, a.mode & S_IFMT == S_IFDIR, permis(a.mode, a.uid, a.gid, qui, LIRE)))
}

/// L'objet désigné par `chemin` depuis `dirfd`, qui doit exister (stat,
/// access...), tenu. Avec AT_EMPTY_PATH, un chemin vide désigne `dirfd`
/// lui-même.
fn objet(dirfd: u64, chemin: &[u8], suivre: bool, vide_permis: bool) -> Result<ObjetTenu, i64> {
    if chemin.is_empty() {
        if !vide_permis {
            return Err(errno(Erreur::ENOENT));
        }
        return processus::avec(|p| vfs::avec_systeme(|s, _| tenir_dossier(p, s, dirfd, false)));
    }
    let tenu = depart(dirfd, chemin)?;
    vfs::avec_systeme(|s, _| {
        let o = s.avec_vue(tenu.pid, |vue| fichiers::chemins::trouver(vue, &tenu.depart(), chemin, suivre)).map_err(errno)?;
        Ok(ObjetTenu::tenir(s, o))
    })
}

/// Ce que dit `stat` de l'objet `o`, dans la vue (le processus en cours,
/// ou le noyau).
pub fn attributs(o: Objet) -> Attributs {
    vfs::avec_systeme(|s, _| s.avec_vue(0, |vue| vue.attributs(o)))
}

/// La sorte d'un fichier qu'on ouvre, d'après son inode : ses opérations.
/// Un périphérique sans pilote : ENXIO, comme Linux.
fn sorte(mode: u32, rdev: (u32, u32)) -> Result<Sorte, i64> {
    Ok(match mode & S_IFMT {
        S_IFREG => Sorte::Fichier,
        S_IFDIR => Sorte::Dossier,
        // L'inode d'un tube, rouvert par /proc/<pid>/fd (le `fifo_open` de
        // Linux) : son tube (tube::rouvrir).
        S_IFIFO => Sorte::Tube,
        // Une socket ne se rouvre pas par son inode (`sock_no_open` : ENXIO,
        // mesuré) ; O_PATH, oui (il ne passe pas par ici).
        S_IFSOCK => return Err(errno(Erreur::ENXIO)),
        S_IFCHR => match rdev {
            vfs::NULL => Sorte::Null,
            vfs::ZERO => Sorte::Zero,
            vfs::FULL => Sorte::Plein,
            vfs::RANDOM => Sorte::Aleatoire { random: true },
            vfs::URANDOM => Sorte::Aleatoire { random: false },
            vfs::CONSOLE => Sorte::Console,
            _ => return Err(errno(Erreur::ENXIO)),
        },
        // Un lien (O_PATH | O_NOFOLLOW) : rien d'autre à faire qu'O_PATH.
        _ => Sorte::Chemin,
    })
}

/// Ouvre `chemin` pour le noyau lui-même, en root : la console des
/// programmes (le `console_on_rootfs` de Linux). Rend le fichier ouvert.
pub fn ouvrir_pour_le_noyau(chemin: &[u8], lecture: bool, ecriture: bool) -> Result<Fichier, Erreur> {
    ouvrir_pour(fichiers::Identite::ROOT, chemin, lecture, ecriture, false)
}

/// Ouvre `chemin`, absolu, depuis la racine, comme le ferait `qui` : avec
/// ses droits (traverser chaque dossier, lire ou écrire l'objet). Pour le
/// noyau, avant qu'un programme existe : les dossiers pré-ouverts d'un
/// programme WebAssembly (`dossier` : il doit en être un, ENOTDIR sinon).
pub fn ouvrir_pour(qui: fichiers::Identite, chemin: &[u8], lecture: bool, ecriture: bool, dossier: bool)
    -> Result<Fichier, Erreur> {
    ouvrir_depuis(qui, None, chemin, lecture, ecriture, dossier)
}

/// Ouvre en lecture `chemin` pour une redirection de /etc/demarrage (6i),
/// en root, un chemin relatif partant de `dossier`, le dossier courant du
/// lanceur (après `cd`).
pub fn ouvrir_pour_le_lanceur(dossier: Objet, chemin: &[u8]) -> Result<Fichier, Erreur> {
    ouvrir_depuis(fichiers::Identite::ROOT, Some(dossier), chemin, true, false, false)
}

/// Le dossier `chemin` (absolu), pour le `cd` de /etc/demarrage (6i) :
/// trouvé en root, en suivant les liens, un dossier (ENOTDIR sinon), tenu
/// s'il est du tmpfs (le lanceur le lâchera).
pub fn dossier_pour_le_lanceur(chemin: &[u8]) -> Result<Objet, Erreur> {
    vfs::avec_systeme(|s, _| {
        let racine = s.racine();
        let depart = Depart { racine, dossier: racine, qui: fichiers::Identite::ROOT, sous: false };
        let o = s.resoudre(0, &depart, chemin, Suivre::Toujours)?.objet.ok_or(Erreur::ENOENT)?;
        if !s.avec_vue(0, |vue| fichiers::montages::est_dossier(vue, o)) {
            return Err(Erreur::ENOTDIR);
        }
        if let Some(n) = o.tmpfs() {
            s.fs.prendre(n);
        }
        Ok(o)
    })
}

/// `ouvrir_pour`, un chemin relatif partant de `depuis` (la racine sinon).
fn ouvrir_depuis(qui: fichiers::Identite, depuis: Option<Objet>, chemin: &[u8], lecture: bool, ecriture: bool, dossier: bool)
    -> Result<Fichier, Erreur> {
    vfs::avec_systeme(|s, cadres| {
        let racine = s.racine();
        let depart = Depart { racine, dossier: depuis.unwrap_or(racine), qui, sous: false };
        let fin = s.resoudre(0, &depart, chemin, Suivre::Toujours)?;
        let o = Ouverture { lecture, ecriture, dossier, ..Ouverture::default() };
        let drapeaux = O_LARGEFILE
            | if ecriture && lecture { 2 } else if ecriture { O_WRONLY } else { O_RDONLY }
            | if dossier { O_DIRECTORY } else { 0 };
        let complet = canonique(s, 0, &fin);
        let lieu = preparer_lieu(s, 0, &fin).map_err(|_| Erreur::ENOMEM)?;
        let fin = match en_tmpfs(fin) {
            Ok(fin) => fin,
            Err(fin) => {
                let objet = fin.objet.ok_or(Erreur::ENOENT)?;
                let f = s.avec_vue(0, |vue| ouvrir_monte(vue, qui, objet, &o, drapeaux as u32, chemin))?;
                let fichier = s.ouverts.ajouter(f.avec_chemin(complet)).map_err(|_| Erreur::ENOMEM)?;
                surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_OPEN);
                return Ok(fichier);
            }
        };
        let ouvert = s.fs.ouvrir(qui, &fin, &o, temps::maintenant())?;
        let a = s.fs.attributs(ouvert.numero);
        let Ok(sorte) = sorte(a.mode, a.rdev) else {
            s.fs.fermer(&ouvert, cadres);
            return Err(Erreur::ENXIO);
        };
        let fichier = s.ouverts
            .ajouter(FichierOuvert::new(sorte, Tenu::Tmpfs(ouvert), lecture, ecriture, drapeaux as u32, chemin).avec_chemin(complet))
            .map_err(|f| {
                if let Tenu::Tmpfs(ouvert) = f.tenu {
                    s.fs.fermer(&ouvert, cadres);
                }
                Erreur::ENOMEM
            })?;
        s.ouverts.fichier(fichier).lieu = lieu.and_then(|l| l.achever(&mut s.fs, Objet::Tmpfs(ouvert.numero)));
        surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_OPEN);
        Ok(fichier)
    })
}

/// Le fichier ouvert d'un objet d'un système monté qu'on ouvre (`o` :
/// comment ; `drapeaux` : ceux que gardera F_GETFL ; `chemin` : tel que
/// donné), avec les vérifications de `do_open` et `may_open` de Linux,
/// dans leur ordre (mesuré sous Linux 6.18 sur /proc) : O_PATH, rien à
/// vérifier (O_CREAT et O_EXCL ont été retirés) ; avec O_CREAT, sur ce qui
/// existe : O_EXCL, EEXIST, puis un dossier, EISDIR ; O_DIRECTORY sur ce
/// qui n'est pas un dossier, ENOTDIR ; un lien (O_NOFOLLOW l'a laissé au
/// bout du chemin), ELOOP ; un dossier ouvert pour écrire, ou avec
/// O_TRUNC, EISDIR ; puis les droits demandés, EACCES, O_TRUNC demandant
/// celui d'écrire (`build_open_flags`). Un fichier d'un système du noyau a une source (son
/// contenu est fabriqué à la lecture, procfs.rs) ; seul `comm` s'écrit (un
/// réglage de /proc/sys, en 0644 à root : EACCES pour root aussi, nos
/// programmes ne le sont jamais).
pub fn ouvrir_monte(vue: &Vue<Montage>, qui: Identite, objet: Objet, o: &Ouverture, drapeaux: u32, chemin: &[u8])
    -> Result<FichierOuvert, Erreur> {
    let ouvrir = |sorte| FichierOuvert::new(sorte, Tenu::Noyau(objet), o.lecture, o.ecriture, drapeaux, chemin);
    if o.chemin_seul {
        return Ok(ouvrir(Sorte::Chemin));
    }
    let a = vue.attributs(objet);
    let dossier = a.mode & S_IFMT == S_IFDIR;
    if o.creer && o.exclusif {
        return Err(Erreur::EEXIST);
    }
    if o.creer && dossier {
        return Err(Erreur::EISDIR);
    }
    if o.dossier && !dossier {
        return Err(Erreur::ENOTDIR);
    }
    if a.mode & S_IFMT == S_IFLNK {
        return Err(Erreur::ELOOP);
    }
    let ecrire = o.ecriture || o.tronquer;
    if dossier && ecrire {
        return Err(Erreur::EISDIR);
    }
    let masque = if o.lecture { fichiers::LIRE } else { 0 } | if ecrire { fichiers::ECRIRE } else { 0 };
    if !permis(a.mode, a.uid, a.gid, qui, masque) {
        return Err(Erreur::EACCES);
    }
    if dossier {
        return Ok(ouvrir(Sorte::Dossier));
    }
    let Some((source, argument)) = vue.contenu(objet) else { return Err(Erreur::ENXIO) };
    if o.ecriture && !procfs::ecrivable(source) {
        return Err(Erreur::EACCES);
    }
    let mut f = ouvrir(Sorte::Noyau { lecture: procfs::lecture(source) });
    f.donnees = procfs::donnees(source, argument);
    Ok(f)
}

/// Le fichier que désigne `chemin`, absolu, depuis la racine, résolu comme
/// `execve` le ferait pour `qui` (liens suivis, droit de traverser chaque
/// dossier, ENOTDIR pour une barre finale après autre chose qu'un
/// dossier), et son chemin canonique (vide s'il ne peut pas être calculé).
/// L'inode est tenu une fois : à lâcher après usage. Seul un fichier du
/// tmpfs peut être un programme : ce qu'on trouve dans un système monté
/// n'est pas exécutable (EACCES, comme `do_open_execat` pour un fichier
/// sans le droit x). Et le chemin, tenu jusqu'à l'ouverture
/// (`ouvrir_inode`) : son lieu, pour inotify.
pub fn trouver_pour(qui: fichiers::Identite, chemin: &[u8]) -> Result<(Numero, Vec<u8>, CheminTenu), Erreur> {
    vfs::avec_systeme(|s, cadres| {
        let racine = s.racine();
        let depart = Depart { racine, dossier: racine, qui, sous: false };
        let fin = s.resoudre(0, &depart, chemin, Suivre::Toujours)?;
        let o = fin.objet.ok_or(Erreur::ENOENT)?;
        if fin.barre && !s.avec_vue(0, |vue| fichiers::montages::est_dossier(vue, o)) {
            return Err(Erreur::ENOTDIR);
        }
        let n = o.tmpfs().ok_or(Erreur::EACCES)?;
        let complet = canonique(s, 0, &fin);
        let lieu = preparer_lieu(s, 0, &fin).map_err(|_| Erreur::ENOMEM)?;
        let tenu = chemin_ouvert(s, o, lieu, cadres).map_err(|_| Erreur::ENOMEM)?;
        s.fs.prendre(n);
        Ok((n, complet, tenu))
    })
}

/// openat(dossier, chemin, drapeaux, droits). Dans l'ordre de Linux
/// (`do_sys_openat2`) :
///   - les drapeaux (`build_open_flags`) : O_PATH ne garde que
///     O_DIRECTORY, O_NOFOLLOW et O_CLOEXEC, et n'ouvre ni en lecture ni en
///     écriture ; O_CREAT avec O_DIRECTORY : EINVAL ; O_TMPFILE (un fichier
///     sans nom) : pas pris en charge, EOPNOTSUPP avec un message ;
///   - le chemin, copié (EFAULT, ENAMETOOLONG ; vide : ENOENT, comme
///     `getname`) ;
///   - le numéro de descripteur, réservé : plus de numéro libre, EMFILE,
///     avant de résoudre le chemin (open("absent/x") rend EMFILE, mesuré) ;
///   - le chemin résolu (le dernier composant suivi, sauf O_NOFOLLOW ou
///     O_EXCL, et pas devant une barre finale avec O_CREAT), puis ouvert
///     par le tmpfs, qui fait les vérifications de `do_open` (voir
///     `Tmpfs::ouvrir`) ; les droits du fichier créé passent par l'umask ;
///   - O_TRUNC ramène le fichier à zéro ;
///   - un périphérique sans pilote : ENXIO.
/// Les drapeaux inconnus sont ignorés, comme le fait open (pas openat2).
/// O_ACCMODE à 3 (ni lecture seule, ni écriture seule, ni les deux) est
/// traité comme O_RDWR (Linux vérifie les deux droits, mais n'ouvre ni en
/// lecture ni en écriture : un usage des pilotes, pour leurs ioctl).
pub fn openat(dirfd: u64, adresse: u64, drapeaux: u64, mode: u64) -> i64 {
    match ouvrir(dirfd, adresse, drapeaux, mode) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
}

fn ouvrir(dirfd: u64, adresse: u64, drapeaux: u64, mode: u64) -> Result<u64, i64> {
    let chemin_seul = drapeaux & O_PATH != 0;
    let drapeaux = if chemin_seul { drapeaux & (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) } else { drapeaux };
    if drapeaux & (O_CREAT | O_DIRECTORY) == O_CREAT | O_DIRECTORY {
        return Err(-EINVAL);
    }
    if drapeaux & O_TMPFILE != 0 {
        afficherln!("[noyau] open : O_TMPFILE pas pris en charge");
        return Err(-EOPNOTSUPP);
    }
    let chemin = chemin(adresse)?;
    if chemin.is_empty() {
        return Err(errno(Erreur::ENOENT));
    }
    let fd = reserver()?;
    let acces = drapeaux & O_ACCMODE;
    let umask = processus::avec(|p| p.umask);
    let o = Ouverture {
        lecture: !chemin_seul && acces != O_WRONLY,
        ecriture: !chemin_seul && acces != O_RDONLY,
        creer: drapeaux & O_CREAT != 0,
        mode: (mode as u32 & 0o7777) & !umask,
        exclusif: drapeaux & O_EXCL != 0,
        tronquer: drapeaux & O_TRUNC != 0,
        dossier: drapeaux & O_DIRECTORY != 0,
        chemin_seul,
    };
    let maintenant = temps::maintenant();
    // Ce que rendra F_GETFL : les drapeaux d'état, O_LARGEFILE toujours (un
    // noyau 64 bits l'impose), sauf pour O_PATH, dont Linux ne garde que les
    // drapeaux d'O_PATH ; pas ceux qui ne servent qu'à open.
    let largefile = if chemin_seul { 0 } else { O_LARGEFILE };
    let gardes = (drapeaux & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC)) | largefile;
    let fichier = avec_fin(dirfd, &chemin, suivre_pour(&o, drapeaux & O_NOFOLLOW != 0), |s, cadres, fin, depart, pid| {
        let complet = canonique(s, pid, &fin);
        // Le lieu du fichier (inotify), préparé d'abord : une fois le
        // fichier créé ou ouvert, plus rien ne doit échouer.
        let lieu = preparer_lieu(s, pid, &fin)?;
        let fin = match en_tmpfs(fin) {
            Ok(fin) => fin,
            Err(fin) => {
                // Dans un système monté : créer y est refusé, le reste est
                // ouvert comme le dit sa sorte. O_CREAT et une barre finale :
                // EISDIR, avant même de chercher le nom, comme
                // `open_last_lookups` (mesuré : open("/proc/self/x/",
                // O_CREAT) rend EISDIR, pas ENOENT).
                if o.creer && fin.barre {
                    return Err(errno(Erreur::EISDIR));
                }
                let Some(objet) = fin.objet else {
                    let e = if o.creer { refus(s, pid, depart.qui, Modification::Creer(&fin, Creation::Ouvrir)) } else { 0 };
                    return Err(if e == 0 { errno(Erreur::ENOENT) } else { e });
                };
                let f = s.avec_vue(pid, |vue| ouvrir_monte(vue, depart.qui, objet, &o, gardes as u32, &chemin)).map_err(errno)?;
                let fichier = s.ouverts.ajouter(f.avec_chemin(complet)).map_err(|_| -ENOMEM)?;
                s.ouverts.fichier(fichier).lieu = lieu.and_then(|l| l.achever(&mut s.fs, objet));
                surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_OPEN);
                return Ok((fichier, None));
            }
        };
        let ouvert = s.fs.ouvrir(depart.qui, &fin, &o, maintenant).map_err(errno)?;
        let a = s.fs.attributs(ouvert.numero);
        let sorte = match if chemin_seul { Ok(Sorte::Chemin) } else { sorte(a.mode, a.rdev) } {
            Ok(sorte) => sorte,
            Err(e) => {
                s.fs.fermer(&ouvert, cadres);
                return Err(e);
            }
        };
        let mut f = FichierOuvert::new(sorte, Tenu::Tmpfs(ouvert), o.lecture, o.ecriture, gardes as u32, &chemin).avec_chemin(complet);
        if sorte == Sorte::Tube {
            match crate::tube::rouvrir(ouvert.numero, o.lecture, o.ecriture) {
                Some((tube, nom)) => {
                    f.prive = Prive::Tube(tube);
                    f.chemin = nom;
                }
                None => {
                    s.fs.fermer(&ouvert, cadres);
                    return Err(errno(Erreur::ENXIO));
                }
            }
        }
        let fichier = s.ouverts.ajouter(f)
            .map_err(|f| {
                crate::tube::fichier_jamais_ouvert(&f);
                if let Tenu::Tmpfs(ouvert) = f.tenu {
                    s.fs.fermer(&ouvert, cadres);
                }
                -ENOMEM
            })?;
        // Ce qu'en voit inotify : la création (au dossier), puis
        // l'ouverture (`fsnotify_create`, puis `fsnotify_open`).
        s.ouverts.fichier(fichier).lieu = lieu.and_then(|l| l.achever(&mut s.fs, Objet::Tmpfs(ouvert.numero)));
        if ouvert.cree {
            surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_CREATE, false, 0);
        }
        surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_OPEN);
        Ok((fichier, Some(ouvert)))
    })?;
    let (fichier, ouvert) = fichier;
    // O_TRUNC, hors du verrou des fichiers : il faut d'abord retirer les
    // pages des projections, sous la mémoire du processus, en lecture
    // (`tronquer`). Le
    // fichier est ouvert : vider ne peut plus échouer (une taille nulle
    // n'est jamais trop grande).
    if let Some(ouvert) = ouvert
        && ouvert.tronquer
    {
        tronquer(ouvert.numero, 0, fichier);
    }
    Ok(fd.installer(fichier, drapeaux & O_CLOEXEC != 0))
}

/// open(chemin, drapeaux, droits) : openat depuis le dossier courant. Bun
/// s'en sert encore (/proc/sys/vm/overcommit_memory, dans la trace de
/// `claude --version`).
pub fn open(adresse: u64, drapeaux: u64, mode: u64) -> i64 {
    openat(AT_FDCWD as u64, adresse, drapeaux, mode)
}

/// creat(chemin, droits) : open avec O_CREAT | O_WRONLY | O_TRUNC.
pub fn creat(adresse: u64, mode: u64) -> i64 {
    open(adresse, O_CREAT | O_WRONLY | O_TRUNC, mode)
}

/// Ferme le descripteur `fd` du processus : son fichier est tenu une fois
/// de moins.
fn fermer_descripteur(fd: u64) -> Result<(), i64> {
    let d = processus::descripteurs(|d| d.retirer(fd)).ok_or(-EBADF)?;
    vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
    Ok(())
}

/// Ce fichier a-t-il de quoi retenir O_ASYNC (un `fasync`) ?
fn a_une_liste(o: &FichierTenu) -> bool {
    matches!(o.sorte, Sorte::Socket | Sorte::Tube | Sorte::Inotify)
}

/// `f_op->fasync`, et le drapeau qu'il pose : la socket (`sock_fasync`) ou les bouts du tube
/// (`pipe_fasync`) inscrivent le fichier sous le descripteur `fd`, ou le retirent. Sans liste : rien.
fn basculer_async(o: &FichierTenu, fd: u64, oui: bool) -> Result<(), i64> {
    if !a_une_liste(o) {
        return Ok(());
    }
    let (lecture, ecriture) = vfs::avec_systeme(|s, _| {
        let f = s.ouverts.fichier(o.fichier);
        (f.lecture, f.ecriture)
    });
    let listes = match o.sorte {
        Sorte::Tube => [lecture.then(|| &o.tube().async_lecteurs), ecriture.then(|| &o.tube().async_ecrivains)],
        // Une instance d'inotify (`fsnotify_fasync`) : SIGIO à chaque
        // événement ajouté.
        Sorte::Inotify => [o.inotify().map(|g| &g.async_lecteurs), None],
        _ => [Some(o.socket().liste_async()), None],
    };
    if oui {
        let p = crate::asynchrone::du_fichier(o.fichier)?;
        for (k, l) in listes.iter().enumerate() {
            if let Some(l) = l
                && let Err(e) = l.inscrire(o.fichier, fd as i32, &p)
            {
                if let Some(Some(a)) = listes.get(..k).and_then(|a| a.first()) {
                    a.retirer(o.fichier);
                }
                return Err(e);
            }
        }
    } else {
        for l in listes.into_iter().flatten() {
            l.retirer(o.fichier);
        }
    }
    vfs::avec_systeme(|s, _| {
        let f = s.ouverts.fichier(o.fichier);
        f.drapeaux = if oui { f.drapeaux | O_ASYNC as u32 } else { f.drapeaux & !(O_ASYNC as u32) };
    });
    Ok(())
}

/// Un numéro de descripteur réservé pour un fichier qu'on ouvre (le
/// `get_unused_fd_flags` de Linux, voir descripteurs::Descripteurs) : rendu
/// à la fin de la garde si l'ouverture échoue (le `put_unused_fd`), sauf
/// une fois le fichier installé (`installer`, le `fd_install`). Une garde,
/// comme les plus récentes de Linux (`CLASS(get_unused_fd, ...)`,
/// include/linux/file.h) : aucun chemin d'erreur ne peut l'oublier.
pub struct NumeroReserve(u64);

impl NumeroReserve {
    /// Installe `fichier` (tenu une fois, pour le descripteur) au numéro
    /// réservé, et rend ce numéro.
    fn installer(self, fichier: Fichier, fermer_a_l_exec: bool) -> u64 {
        let fd = self.0;
        core::mem::forget(self);
        processus::descripteurs(|d| d.installer(fd, Descripteur { fichier, fermer_a_l_exec }));
        fd
    }
}

impl Drop for NumeroReserve {
    fn drop(&mut self) {
        processus::descripteurs(|d| d.liberer(self.0));
    }
}

/// Réserve le plus petit numéro libre du processus en cours (EMFILE,
/// ENOMEM).
pub fn reserver() -> Result<NumeroReserve, i64> {
    processus::descripteurs(|d| d.reserver(0)).map(NumeroReserve).map_err(errno_table)
}

/// Le numéro d'erreur d'un refus de la table des descripteurs.
fn errno_table(r: Refus) -> i64 {
    match r {
        Refus::PlusDeNumero => -EMFILE,
        Refus::PlusDeMemoire => -ENOMEM,
        Refus::Reserve => -EBUSY,
    }
}

/// Un fichier arrive d'une autre socket (`receive_fd`) : un descripteur de plus, le plus petit
/// libre, que `ecrire` donne au programme avant qu'il n'existe (faux : EFAULT, rien ne reste).
pub fn recevoir_fichier(o: &FichierTenu, fermer_a_l_exec: bool, ecrire: impl FnOnce(u64) -> bool) -> Result<u64, i64> {
    let fd = reserver()?;
    if !ecrire(fd.0) {
        return Err(-EFAULT);
    }
    vfs::avec_systeme(|s, _| s.ouverts.prendre(o.fichier));
    Ok(fd.installer(o.fichier, fermer_a_l_exec))
}

/// Range un fichier ouvert neuf (eventfd, epoll : sans chemin) au plus petit
/// numéro libre, avec FD_CLOEXEC si demandé : rend le numéro, EMFILE s'il
/// n'y en a plus, ENOMEM si une table ne peut pas grandir (rien ne reste).
pub fn installer_fichier(f: FichierOuvert, fermer_a_l_exec: bool) -> i64 {
    installer_fichier_puis(f, fermer_a_l_exec, |_| {})
}

/// Range deux fichiers ouverts neufs (les deux bouts d'un tube) aux deux plus
/// petits numéros libres, avec FD_CLOEXEC si demandé, comme `do_pipe2` : les
/// deux numéros réservés (EMFILE), les fichiers rangés (ENOMEM), puis
/// `ecrire` reçoit les numéros pour les donner au programme ; s'il échoue
/// (EFAULT), rien ne reste. Rend 0.
pub fn installer_paire(a: FichierOuvert, b: FichierOuvert, fermer_a_l_exec: bool, ecrire: impl FnOnce([u64; 2]) -> bool) -> i64 {
    let fermer = |f: FichierOuvert| vfs::avec_systeme(|s, cadres| {
        if let Tenu::Tmpfs(o) = f.tenu {
            s.fs.fermer(&o, cadres);
        }
        crate::tube::fichier_jamais_ouvert(&f);
    });
    let (fa, fb) = match (reserver(), reserver()) {
        (Ok(x), Ok(y)) => (x, y),
        (Err(e), _) | (_, Err(e)) => {
            fermer(a);
            fermer(b);
            return e;
        }
    };
    let x = match vfs::avec_systeme(|s, _| s.ouverts.ajouter(a)) {
        Ok(x) => x,
        Err(a) => {
            fermer(a);
            fermer(b);
            return -ENOMEM;
        }
    };
    let y = match vfs::avec_systeme(|s, _| s.ouverts.ajouter(b)) {
        Ok(y) => y,
        Err(b) => {
            fermer(b);
            vfs::avec_systeme(|s, cadres| s.lacher(x, cadres));
            return -ENOMEM;
        }
    };
    if !ecrire([fa.0, fb.0]) {
        vfs::avec_systeme(|s, cadres| {
            s.lacher(x, cadres);
            s.lacher(y, cadres);
        });
        return -EFAULT;
    }
    fa.installer(x, fermer_a_l_exec);
    fb.installer(y, fermer_a_l_exec);
    0
}

/// installer_fichier, en appelant `range` avec le fichier ouvert dès qu'il
/// est dans la table, avant que son descripteur n'existe (personne ne peut
/// encore s'en servir) : un epoll y apprend sa case.
pub fn installer_fichier_puis(f: FichierOuvert, fermer_a_l_exec: bool, range: impl FnOnce(Fichier)) -> i64 {
    let fd = match reserver() {
        Ok(fd) => fd,
        Err(e) => {
            rendre_fichier(f);
            return e;
        }
    };
    match installer_reserve_puis(fd, f, fermer_a_l_exec, range) {
        Ok(fd) => fd as i64,
        Err(f) => {
            rendre_fichier(f);
            -ENOMEM
        }
    }
}

/// Range le fichier ouvert neuf `f` dans la table, puis l'installe au
/// numéro réservé `fd` (le `fd_install`), en appelant `range` entre les deux
/// (voir `installer_fichier_puis`) : le numéro ; sans place dans la table
/// (ENOMEM), le fichier est rendu à l'appelant, et le numéro libéré.
pub fn installer_reserve_puis(fd: NumeroReserve, f: FichierOuvert, fermer_a_l_exec: bool, range: impl FnOnce(Fichier))
    -> Result<u64, FichierOuvert> {
    let fichier = vfs::avec_systeme(|s, _| s.ouverts.ajouter(f))?;
    range(fichier);
    Ok(fd.installer(fichier, fermer_a_l_exec))
}

/// Un fichier ouvert neuf qui n'entrera pas dans la table : il rend son
/// inode s'il en tient un du tmpfs (celui d'une socket, 6g). Son objet du
/// noyau, lui, est à l'appelant (une socket se ferme comme à son dernier
/// `close`).
pub fn rendre_fichier(f: FichierOuvert) {
    if let Tenu::Tmpfs(o) = f.tenu {
        vfs::avec(|fs, cadres| fs.fermer(&o, cadres));
    }
}

/// close(fd).
pub fn close(fd: u64) -> i64 {
    match fermer_descripteur(fd) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// close_range(premier, dernier, drapeaux) : ferme (ou marque « fermer à
/// l'exec », CLOSE_RANGE_CLOEXEC) les descripteurs de [premier, dernier].
/// Premier après dernier, ou un drapeau inconnu : EINVAL.
/// CLOSE_RANGE_UNSHARE (ne plus partager la table avec les autres fils,
/// puis fermer dans sa copie : ce que fait un programme avant execve) : sans
/// objet pour un processus d'un seul fil ; avec plusieurs, la table est au
/// processus (processus.rs), un fil ne peut pas en avoir une à lui : EINVAL,
/// avec un message (un écart, jusqu'à execve, 6l).
pub fn close_range(premier: u64, dernier: u64, drapeaux: u64) -> i64 {
    const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
    let (premier, dernier) = (premier as u32 as u64, dernier as u32 as u64);
    if drapeaux & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || premier > dernier {
        return -EINVAL;
    }
    if drapeaux & CLOSE_RANGE_UNSHARE != 0 && processus::avec(|p| p.fils.len() > 1) {
        afficherln!("[noyau] close_range : CLOSE_RANGE_UNSHARE avec plusieurs fils pas pris en charge");
        return -EINVAL;
    }
    let ouverts: Vec<u64> = match processus::descripteurs(|d| {
        let mut v = faillible::avec_capacite(d.ouverts(premier, dernier).count()).ok()?;
        v.ajouter_tout(d.ouverts(premier, dernier)).ok()?;
        Some(v)
    }) {
        Some(v) => v,
        None => return -ENOMEM,
    };
    for fd in ouverts {
        if drapeaux & CLOSE_RANGE_CLOEXEC != 0 {
            processus::descripteurs(|t| t.get_mut(fd).map(|d| d.fermer_a_l_exec = true));
        } else {
            let _ = fermer_descripteur(fd);
        }
    }
    0
}

/// Lit le fichier `n` du tmpfs, à partir de `position`, vers l'adresse
/// `tampon` du programme : au plus `longueur` octets, jusqu'à la fin du
/// fichier. Page par page : sous le verrou des fichiers, la page est
/// trouvée et prise ; hors du verrou, copiée ; puis lâchée. Un trou se lit
/// comme des zéros. Une faute dans le tampon arrête la lecture, au milieu
/// d'une page s'il le faut : ce qui a été copié jusque-là, ou EFAULT si
/// rien.
fn lire_pages(n: Numero, position: u64, tampon: u64, longueur: u64) -> Result<u64, i64> {
    let mut lus = 0;
    while lus < longueur {
        let ici = position + lus;
        let (page, reste) = vfs::avec(|fs, _| {
            let taille = fs.attributs(n).taille;
            let page = fs.page(n, ici / PAGE);
            if let Some(p) = page {
                pages::prendre(p);
            }
            (page, taille.saturating_sub(ici))
        });
        let decalage = (ici % PAGE) as usize;
        let morceau = (longueur - lus).min(PAGE - decalage as u64).min(reste) as usize;
        if morceau == 0 {
            if let Some(p) = page {
                pages::lacher(p);
            }
            break;
        }
        let copies = match page {
            Some(p) => vfs::copier_vers_programme(p, decalage, morceau, tampon + lus),
            None => copier_vers_utilisateur_partiel(tampon + lus, &ZEROS[..morceau]),
        };
        if let Some(p) = page {
            pages::lacher(p);
        }
        lus += copies as u64;
        if copies < morceau {
            if lus == 0 {
                return Err(-EFAULT);
            }
            break;
        }
    }
    vfs::avec(|fs, _| fs.acceder(n, temps::maintenant()));
    Ok(lus)
}

/// Écrit dans le fichier `n`, à `position`, `longueur` octets de l'adresse
/// `tampon` du programme, page par page comme `lire_pages` : la page est
/// trouvée (ou créée) et prise sous le verrou, remplie hors du verrou, et
/// la taille du fichier suit chaque morceau écrit. Plus de place après des
/// octets écrits : leur nombre ; avant : ENOSPC. Une faute dans le tampon,
/// même au milieu d'une page : les octets copiés jusque-là sont écrits et
/// comptés (le fichier les a : les taire mentirait), EFAULT si aucun ; les
/// pages créées pour rien sont rendues (Tmpfs::rogner).
fn ecrire_pages(n: Numero, position: u64, tampon: u64, longueur: u64) -> Result<u64, i64> {
    let longueur = limites_d_ecriture(position, longueur as usize)? as u64;
    let mut ecrits = 0;
    let mut faute = false;
    while ecrits < longueur {
        let ici = position + ecrits;
        let page = vfs::avec(|fs, cadres| {
            let p = fs.page_pour_ecrire(n, ici / PAGE, cadres)?;
            pages::prendre(p);
            Ok(p)
        });
        let page = match page {
            Ok(p) => p,
            Err(e) if ecrits == 0 => return Err(errno(e)),
            Err(_) => break,
        };
        let decalage = (ici % PAGE) as usize;
        let morceau = (longueur - ecrits).min(PAGE - decalage as u64) as usize;
        let copies = vfs::copier_depuis_programme(page, decalage, morceau, tampon + ecrits);
        pages::lacher(page);
        ecrits += copies as u64;
        if copies > 0 {
            vfs::avec(|fs, _| fs.ecrit(n, position + ecrits, temps::maintenant()));
        }
        if copies < morceau {
            faute = true;
            break;
        }
    }
    if faute {
        vfs::avec(|fs, cadres| fs.rogner(n, cadres));
        if ecrits == 0 {
            return Err(-EFAULT);
        }
    }
    Ok(ecrits)
}

/// Une écriture du fichier `n`, tenu par le fichier ouvert `par`, par la
/// tâche courante : ses bits setuid et setgid tombent s'il le faut
/// (Tmpfs::retirer_les_privileges ; une tâche du noyau est root), ce
/// qu'inotify voit (IN_ATTRIB, celui du `notify_change` de
/// `file_remove_privs`). Une troncature fait de même dans `tronquer`, d'un
/// seul événement avec son IN_MODIFY.
fn retirer_les_privileges(n: Numero, par: Fichier) {
    let qui = processus::essayer_avec(|p| p.identite).unwrap_or(Identite::ROOT);
    vfs::avec_systeme(|s, _| {
        if s.fs.retirer_les_privileges(qui, n, temps::maintenant()) {
            surveillance::changement(&s.fs, s.ouverts.fichier(par), IN_ATTRIB);
        }
    });
}

/// Des octets aléatoires vers le programme (`get_random_bytes_user`) :
/// un tirage, dont la clé est remplacée par 32 octets neufs avant la
/// première copie (une copie peut fauter et dormir : la clé d'avant
/// l'effacement rapide ne doit pas attendre avec elle) ; ces 32 octets,
/// pour une demande de 32 octets au plus, directement ; au-delà, des
/// blocs de 64 octets, un signal regardé à chaque page copiée (il fait
/// rendre ce qui l'est). Une faute : ce qui a été copié, ou EFAULT si
/// rien.
pub fn alea_vers_programme(tampon: u64, longueur: u64) -> Result<u64, i64> {
    alea_vers(longueur, |decalage, octets| copier_vers_utilisateur_partiel(tampon + decalage, octets))
}

/// Ce que fait `alea_vers_programme`, vers `copier` (le décalage, les
/// octets ; rend ce qui a été copié, moins à une faute) : la mémoire d'un
/// programme, ou un tampon du noyau (sendfile, 6i : le même
/// `get_random_bytes_user`, par `copy_splice_read`).
fn alea_vers(longueur: u64, mut copier: impl FnMut(u64, &[u8]) -> usize) -> Result<u64, i64> {
    if longueur == 0 {
        return Ok(0);
    }
    let mut premiers = [0u8; 32];
    let mut tirage = aleatoire::commencer(&mut premiers);
    // La clé de l'état, écrasée tout de suite par ces 32 octets
    // (`get_random_bytes_user`) : la copie peut dormir, la clé d'avant
    // l'effacement rapide ne doit pas attendre avec elle.
    tirage.changer_de_cle(&premiers);
    if longueur <= 32 {
        let n = longueur as usize;
        let copies = copier(0, &premiers[..n]);
        crypto::effacer(&mut premiers);
        return if copies == 0 { Err(-EFAULT) } else { Ok(copies as u64) };
    }
    crypto::effacer(&mut premiers);
    let mut fait = 0u64;
    let mut bloc = [0u8; 64];
    let r = loop {
        tirage.suite(&mut bloc);
        let n = (longueur - fait).min(64) as usize;
        let copies = copier(fait, &bloc[..n]);
        fait += copies as u64;
        if fait == longueur || copies < n {
            break if fait == 0 { Err(-EFAULT) } else { Ok(fait) };
        }
        if fait % PAGE == 0 && tache::signal_en_attente() {
            break Ok(fait);
        }
    };
    crypto::effacer(&mut bloc);
    r
}

/// Des zéros vers le programme, à `tampon` (`read_zero`) : par pages,
/// copiées de la page de zéros du noyau, un signal regardé après chacune
/// (il fait rendre ce qui l'est : un read d'un Gio de /dev/zero ne fait
/// pas attendre un SIGINT). Une faute : ce qui a été copié, ou EFAULT si
/// rien.
fn zeros_vers_programme(tampon: u64, longueur: u64) -> Result<u64, i64> {
    let mut fait = 0;
    while fait < longueur {
        let n = (longueur - fait).min(PAGE) as usize;
        let copies = vfs::copier_vers_programme(crate::espace_utilisateur::page_de_zeros(), 0, n, tampon + fait);
        fait += copies as u64;
        if copies < n {
            return if fait == 0 { Err(-EFAULT) } else { Ok(fait) };
        }
        if tache::signal_en_attente() {
            break;
        }
    }
    Ok(fait)
}

/// Les vérifications de `vfs_read` et `vfs_write` avant tout transfert,
/// dans leur ordre, après celle du mode d'ouverture (EBADF) :
///   - toute la plage du tampon dans les adresses des programmes (EFAULT,
///     l'access_ok de Linux) : un `read(fd, tampon, 1 << 62)` ne doit pas
///     écrire jusqu'à la première page absente, par-dessus ce qui suit le
///     tampon ;
///   - la position, plus la longueur, sous la plus grande taille de fichier
///     (EINVAL, `rw_verify_area`), avant de plafonner la longueur.
/// Rend la longueur plafonnée à RW_MAX.
fn verifier_transfert(tampon: u64, longueur: u64, position: u64) -> Result<u64, i64> {
    if !dans_les_bornes(tampon, longueur) {
        return Err(-EFAULT);
    }
    if position.saturating_add(longueur) > i64::MAX as u64 {
        return Err(-EINVAL);
    }
    Ok(longueur.min(RW_MAX))
}

/// Lire, selon la sorte du fichier, `longueur` octets à `position` (ou à
/// la position du fichier, `None`, qui avance d'autant : l'appelant tient
/// son verrou, voir `verrous`).
fn lire_ouvert(o: &FichierTenu, position: Option<u64>, tampon: u64, longueur: u64) -> Result<u64, i64> {
    // Un eventfd, un epoll, un tube ou une socket n'a pas de position :
    // pread rend ESPIPE avant tout (FMODE_PREAD n'est pas mis) ; un epoll ne
    // se lit pas (pas d'opération read : EINVAL, avant de regarder le
    // tampon).
    match o.sorte {
        Sorte::EventFd | Sorte::Epoll | Sorte::Tube | Sorte::Socket | Sorte::Inotify if position.is_some() => return Err(-ESPIPE),
        Sorte::Epoll => return Err(-EINVAL),
        _ => {}
    }
    if !o.lecture {
        return Err(-EBADF);
    }
    let ici = position.unwrap_or_else(|| o.position());
    let longueur = verifier_transfert(tampon, longueur, ici)?;
    match o.sorte {
        Sorte::Fichier => {
            let lus = lire_pages(o.numero(), ici, tampon, longueur)?;
            if position.is_none() {
                o.changer_position(ici + lus);
            }
            Ok(lus)
        }
        Sorte::Dossier => Err(errno(Erreur::EISDIR)),
        Sorte::Console if position.is_some() => Err(-ESPIPE),
        // La console n'est pas encore un terminal (6k) : rien à lire.
        Sorte::Null | Sorte::Console => Ok(0),
        Sorte::Zero | Sorte::Plein => zeros_vers_programme(tampon, longueur),
        // /dev/random attend que le générateur soit prêt (EAGAIN en
        // O_NONBLOCK) ; /dev/urandom n'attend pas, mais lance la gigue
        // (`random_read_iter`, `urandom_read_iter`).
        Sorte::Aleatoire { random: true } => {
            if !aleatoire::pret() {
                if o.drapeaux as u64 & O_NONBLOCK != 0 {
                    return Err(-EAGAIN);
                }
                aleatoire::attendre_pret()?;
            }
            alea_vers_programme(tampon, longueur)
        }
        Sorte::Aleatoire { random: false } => {
            aleatoire::essayer_la_gigue();
            alea_vers_programme(tampon, longueur)
        }
        Sorte::Chemin => Err(-EBADF),
        Sorte::EventFd => evenements::lire(o.eventfd(), o.drapeaux as u64 & O_NONBLOCK != 0, tampon, longueur),
        Sorte::Inotify => surveillance::lire(o.inotify().expect("une instance"), o.drapeaux as u64 & O_NONBLOCK != 0, tampon, longueur),
        Sorte::Tube => en_resultat(o.tube().lire(&[(tampon, longueur)], o.drapeaux as u64 & O_NONBLOCK != 0)),
        Sorte::Socket => en_resultat(crate::appels_reseau::lire(o, &[(tampon, longueur)])),
        Sorte::Epoll => Err(-EINVAL),
        Sorte::Noyau { .. } => {
            let contenu = procfs::lire(o.fichier(), ici, longueur)?;
            let copies = copier_vers_utilisateur_partiel(tampon, &contenu) as u64;
            if copies == 0 && !contenu.is_empty() {
                return Err(-EFAULT);
            }
            if position.is_none() {
                o.changer_position(ici + copies);
            }
            Ok(copies)
        }
    }
}

/// Les verrous d'écriture des fichiers : un verrou qui dort (attente.rs)
/// par inode, comme l'`inode_lock` de Linux. Plutôt qu'un verrou dans
/// chaque inode (la bibliothèque des fichiers n'a pas de verrou qui dort),
/// 64 verrous, celui d'un inode choisi par son numéro : deux écritures du
/// même fichier se suivent toujours, deux de fichiers différents ne
/// s'attendent que s'ils tombent sur le même (comme les seaux des futex).
static VERROUS_D_ECRITURE: [Mutex<()>; 64] = [const { Mutex::new(()) }; 64];

/// Le verrou d'écriture de l'inode `n`, tenu jusqu'à la fin de la garde.
pub fn verrou_d_ecriture(n: Numero) -> GardeMutex<'static, ()> {
    VERROUS_D_ECRITURE[n.0 as usize % 64].verrouiller()
}

/// Écrire, selon la sorte du fichier, comme `lire_ouvert`. L'appelant tient
/// le verrou d'écriture de l'inode d'un fichier ordinaire (`verrous`), de
/// la lecture de la fin jusqu'à la nouvelle position : deux programmes qui
/// ajoutent au même fichier ne s'écrasent pas (l'`inode_lock` de Linux,
/// pendant tout `generic_file_write_iter`).
fn ecrire_ouvert(o: &FichierTenu, position: Option<u64>, tampon: u64, longueur: u64) -> Result<u64, i64> {
    // Comme pour lire : ESPIPE, puis EINVAL pour un epoll.
    match o.sorte {
        Sorte::EventFd | Sorte::Epoll | Sorte::Tube | Sorte::Socket | Sorte::Inotify if position.is_some() => return Err(-ESPIPE),
        Sorte::Epoll => return Err(-EINVAL),
        _ => {}
    }
    if !o.ecriture {
        return Err(-EBADF);
    }
    let ici = position.unwrap_or_else(|| o.position());
    let longueur = verifier_transfert(tampon, longueur, ici)?;
    match o.sorte {
        Sorte::Fichier => {
            // O_APPEND : toujours à la fin, même pour pwrite (une
            // bizarrerie de Linux, que décrit sa page de manuel).
            let fin = vfs::avec(|fs, _| fs.attributs(o.numero()).taille);
            let ici = if o.drapeaux as u64 & O_APPEND != 0 { fin } else { ici };
            // La limite (EFBIG), puis les bits setuid et setgid, avant
            // d'écrire (`generic_write_checks`, puis `file_remove_privs`).
            limites_d_ecriture(ici, longueur as usize)?;
            if longueur > 0 {
                retirer_les_privileges(o.numero(), o.fichier);
            }
            let ecrits = ecrire_pages(o.numero(), ici, tampon, longueur)?;
            if position.is_none() {
                o.changer_position(ici + ecrits);
            }
            Ok(ecrits)
        }
        Sorte::Console if position.is_some() => Err(-ESPIPE),
        Sorte::Console => {
            // Les octets du programme passent par un tampon du noyau :
            // copiés d'abord, sans rien tenir (une copie peut fauter), puis
            // écrits sur la console (qui prend son verrou).
            // Tout ou rien, comme un terminal de Linux (`iterate_tty_write`
            // copie chaque morceau en entier avant de l'écrire) : une faute
            // dans le tampon, même après des octets valides, EFAULT.
            let mut copie = [0u8; CONSOLE_MAX];
            let n = (longueur as usize).min(CONSOLE_MAX);
            if copier_depuis_utilisateur(&mut copie[..n], tampon).is_err() {
                return Err(-EFAULT);
            }
            console::ecrire_octets(&copie[..n]);
            Ok(n as u64)
        }
        // Dans le vide, sans même lire le tampon (comme le write_null de
        // Linux).
        Sorte::Null | Sorte::Zero => Ok(longueur),
        // Mêlé au réservoir du générateur, sans crédit (`write_pool_user`) :
        // par morceaux de 64 octets copiés d'abord ; une faute : ce qui a
        // été versé, ou EFAULT si rien.
        Sorte::Aleatoire { .. } => {
            let mut fait = 0u64;
            let mut morceau = [0u8; 64];
            while fait < longueur {
                let n = (longueur - fait).min(64) as usize;
                let copies = copier_depuis_utilisateur_partiel(&mut morceau[..n], tampon + fait);
                aleatoire::melanger(&morceau[..copies]);
                fait += copies as u64;
                if copies < n {
                    break;
                }
                if fait % PAGE == 0 && tache::signal_en_attente() {
                    break;
                }
            }
            crypto::effacer(&mut morceau);
            if fait == 0 && longueur > 0 { Err(-EFAULT) } else { Ok(fait) }
        }
        Sorte::Plein => Err(-ENOSPC),
        // Une instance d'inotify ne s'ouvre qu'en lecture.
        Sorte::Dossier | Sorte::Chemin | Sorte::Inotify => Err(-EBADF),
        Sorte::EventFd => evenements::ecrire(o.eventfd(), o.drapeaux as u64 & O_NONBLOCK != 0, tampon, longueur),
        Sorte::Tube => en_resultat(o.tube().ecrire(&[(tampon, longueur)], o.drapeaux as u64 & O_NONBLOCK != 0,
                                               o.drapeaux as u64 & O_DIRECT != 0)),
        Sorte::Socket => en_resultat(crate::appels_reseau::ecrire(o, &[(tampon, longueur)])),
        Sorte::Epoll => Err(-EINVAL),
        // Un fichier du noyau qui s'écrit (procfs::ecrivable : comm) :
        // seuls ses 15 premiers octets comptent, copiés d'abord, sans rien
        // tenir ; la position ne sert pas (`comm_write`).
        Sorte::Noyau { .. } => {
            let (source, argument) = procfs::source(o.fichier());
            let mut copie = [0u8; 15];
            let n = (longueur as usize).min(copie.len());
            if copier_depuis_utilisateur(&mut copie[..n], tampon).is_err() {
                return Err(-EFAULT);
            }
            procfs::ecrire(source, argument, &copie[..n], longueur)
        }
    }
}

/// Un résultat d'appel (négatif : une erreur) en Result.
fn en_resultat(r: i64) -> Result<u64, i64> {
    if r < 0 { Err(r) } else { Ok(r as u64) }
}

fn resultat(r: Result<u64, i64>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// read(fd, tampon, longueur).
pub fn read(fd: u64, tampon: u64, longueur: u64) -> i64 {
    resultat(tenir(fd).and_then(|o| {
        let _verrous = verrous(&o, true, false);
        annoncer(&o, IN_ACCESS, lire_ouvert(&o, None, tampon, longueur))
    }))
}

/// Ce qu'inotify voit d'un transfert : IN_ACCESS pour une lecture,
/// IN_MODIFY pour une écriture, si au moins un octet est passé
/// (`fsnotify_access`, `fsnotify_modify` de `vfs_read`, `vfs_write`) ; sur
/// toute sorte de fichier (un tube, une socket, /dev/null : mesuré).
/// readv et writev ont leur règle (`vecteur`).
fn annoncer(o: &FichierTenu, masque: u32, r: Result<u64, i64>) -> Result<u64, i64> {
    if r.is_ok_and(|n| n > 0) {
        surveillance::apres_l_appel(o, masque);
    }
    r
}

/// write(fd, tampon, longueur).
pub fn write(fd: u64, tampon: u64, longueur: u64) -> i64 {
    resultat(tenir(fd).and_then(|o| {
        let _verrous = verrous(&o, true, true);
        annoncer(&o, IN_MODIFY, ecrire_ouvert(&o, None, tampon, longueur))
    }))
}

/// pread64(fd, tampon, longueur, position) : sans bouger la position.
/// Position négative : EINVAL, avant même de regarder le descripteur
/// (`ksys_pread64`) ; un fichier sans position (la console) : ESPIPE.
pub fn pread64(fd: u64, tampon: u64, longueur: u64, position: u64) -> i64 {
    if (position as i64) < 0 {
        return -EINVAL;
    }
    resultat(tenir(fd).and_then(|o| {
        let _verrous = verrous(&o, false, false);
        annoncer(&o, IN_ACCESS, lire_ouvert(&o, Some(position), tampon, longueur))
    }))
}

/// pwrite64(fd, tampon, longueur, position).
pub fn pwrite64(fd: u64, tampon: u64, longueur: u64, position: u64) -> i64 {
    if (position as i64) < 0 {
        return -EINVAL;
    }
    resultat(tenir(fd).and_then(|o| {
        let _verrous = verrous(&o, false, true);
        annoncer(&o, IN_MODIFY, ecrire_ouvert(&o, Some(position), tampon, longueur))
    }))
}

/// Les morceaux d'un readv ou d'un writev : le tableau de `struct iovec`
/// (adresse, longueur) du programme, copié en entier dans un bloc du tas
/// (16 Kio pour 1024 morceaux : pas sur la pile du noyau), et vérifié en
/// entier avant de rien transférer, comme `import_iovec` de Linux : plus
/// de 1024 morceaux (IOV_MAX), ou une longueur négative en ssize_t :
/// EINVAL ; puis un morceau hors des adresses des programmes (même vide) :
/// EFAULT. Les longueurs sont ensuite raccourcies pour que leur total ne
/// dépasse pas RW_MAX : au-delà, le transfert est partiel, comme pour un
/// read. (Un point de « Reste à faire » de l'étape 5 : writev écrivait les
/// premiers morceaux avant de découvrir une erreur dans un suivant.)
pub fn morceaux(adresse: u64, nombre: u64) -> Result<Vec<(u64, u64)>, i64> {
    if nombre > 1024 {
        return Err(-EINVAL);
    }
    let mut octets = faillible::remplie(nombre as usize * 16, 0).map_err(|_| -ENOMEM)?;
    copier_depuis_utilisateur(&mut octets, adresse).map_err(|_| -EFAULT)?;
    let mut v = faillible::avec_capacite(nombre as usize).map_err(|_| -ENOMEM)?;
    for c in octets.chunks_exact(16) {
        let base = u64::from_le_bytes(c[..8].try_into().unwrap_or([0; 8]));
        let longueur = u64::from_le_bytes(c[8..].try_into().unwrap_or([0; 8]));
        if (longueur as i64) < 0 {
            return Err(-EINVAL);
        }
        v.ajouter_dans_la_place((base, longueur));
    }
    let mut total = 0;
    for (base, longueur) in v.iter_mut() {
        if !dans_les_bornes(*base, *longueur) {
            return Err(-EFAULT);
        }
        *longueur = (*longueur).min(RW_MAX - total);
        total += *longueur;
    }
    Ok(v)
}

/// readv et writev : morceau par morceau, jusqu'au premier qui n'est pas
/// fait en entier (une fin de fichier, une faute) ; le total transféré,
/// ou l'erreur du premier morceau si rien ne l'a été.
fn vecteur(fd: u64, adresse: u64, nombre: u64, ecrire: bool) -> i64 {
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let r = vecteur_tenu(&o, adresse, nombre, ecrire);
    // Ce qu'en voit inotify : writev comme write (au moins un octet) ;
    // readv, même 0 octet, une fin de fichier ou des morceaux vides
    // (`vfs_readv` : `if (ret >= 0) fsnotify_access(file)`, mesuré).
    if if ecrire { r > 0 } else { r >= 0 } {
        surveillance::apres_l_appel(&o, if ecrire { IN_MODIFY } else { IN_ACCESS });
    }
    r
}

/// readv ou writev de `o`.
fn vecteur_tenu(o: &FichierTenu, adresse: u64, nombre: u64, ecrire: bool) -> i64 {
    if (ecrire && !o.ecriture) || (!ecrire && !o.lecture) {
        return -EBADF;
    }
    let morceaux = match morceaux(adresse, nombre) {
        Ok(m) => m,
        Err(e) => return e,
    };
    // Un tube se lit et s'écrit d'un coup, sur tous les morceaux (le
    // `read_iter` et le `write_iter` de Linux : un writev de PIPE_BUF octets
    // en plusieurs morceaux reste atomique).
    if o.sorte == Sorte::Tube {
        let non_bloquant = o.drapeaux as u64 & O_NONBLOCK != 0;
        return if ecrire {
            o.tube().ecrire(&morceaux, non_bloquant, o.drapeaux as u64 & O_DIRECT != 0)
        } else {
            o.tube().lire(&morceaux, non_bloquant)
        };
    }
    // Une socket aussi : un seul datagramme, de tous les morceaux, ou dans
    // tous les morceaux (le `sock_read_iter` et le `sock_write_iter`).
    if o.sorte == Sorte::Socket {
        return if ecrire { crate::appels_reseau::ecrire(o, &morceaux) } else { crate::appels_reseau::lire(o, &morceaux) };
    }
    // Une instance d'inotify : morceau par morceau (surveillance.rs).
    if o.sorte == Sorte::Inotify {
        return resultat(surveillance::lire_morceaux(o.inotify().expect("une instance"), o.drapeaux as u64 & O_NONBLOCK != 0, &morceaux));
    }
    // Un eventfd se lit d'un coup, sur tous les morceaux (evenements.rs).
    if !ecrire && o.sorte == Sorte::EventFd {
        return match evenements::lire_morceaux(o.eventfd(), o.drapeaux as u64 & O_NONBLOCK != 0, &morceaux) {
            Ok(n) => n as i64,
            Err(e) => e,
        };
    }
    // Les verrous tenus sur tous les morceaux : chacun part de la position
    // où s'est arrêté le précédent, sans qu'un autre fil s'intercale.
    let _verrous = verrous(o, true, ecrire);
    // Un fichier ordinaire s'écrit en un seul `write_iter` chez Linux
    // (`do_iter_readv_writev`) : ses limites (`generic_write_checks`) se
    // vérifient une fois, sur le total, à la position de départ (la fin pour
    // O_APPEND). SIGXFSZ seulement si elle est déjà à RLIMIT_FSIZE ; sinon,
    // les morceaux sont coupés au total permis, et aucun ne part de la
    // limite (morceau par morceau, le suivant enverrait SIGXFSZ, qui tue).
    let mut permis = u64::MAX;
    if ecrire && o.sorte == Sorte::Fichier {
        let total = morceaux.iter().fold(0u64, |t, m| t.saturating_add(m.1));
        let depart = if o.drapeaux as u64 & O_APPEND != 0 { vfs::avec(|fs, _| fs.attributs(o.numero()).taille) } else { o.position() };
        permis = match limites_d_ecriture(depart, total.min(isize::MAX as u64) as usize) {
            Ok(n) => n as u64,
            Err(e) => return e,
        };
    }
    let mut total = 0u64;
    for (base, longueur) in morceaux {
        let longueur = longueur.min(permis - total);
        if longueur == 0 {
            if total == permis {
                break;
            }
            continue;
        }
        let r = if ecrire { ecrire_ouvert(o, None, base, longueur) } else { lire_ouvert(o, None, base, longueur) };
        match r {
            Ok(n) => {
                total += n;
                if n < longueur {
                    break;
                }
            }
            Err(e) if total == 0 => return e,
            Err(_) => break,
        }
    }
    total as i64
}

/// readv(fd, morceaux, nombre).
pub fn readv(fd: u64, adresse: u64, nombre: u64) -> i64 {
    vecteur(fd, adresse, nombre, false)
}

/// writev(fd, morceaux, nombre) : la glibc s'en sert pour ses messages
/// d'erreur fatale, et pour vider ses tampons d'un coup.
pub fn writev(fd: u64, adresse: u64, nombre: u64) -> i64 {
    vecteur(fd, adresse, nombre, true)
}

/// lseek(fd, décalage, d'où) : SEEK_SET, SEEK_CUR, SEEK_END, et pour un
/// fichier SEEK_DATA et SEEK_HOLE (Tmpfs::chercher : tmpfs connaît ses
/// trous). Une position négative : EINVAL. Un dossier : SEEK_SET et
/// SEEK_CUR seulement, sa position est celle de `lire_dossier` (EINVAL
/// sinon, mesuré) ; la console : ESPIPE ; /dev/null et ses voisins : 0,
/// comme Linux. Un `depuis` au-delà de SEEK_HOLE : EINVAL pour tous, avant
/// de demander au fichier (`ksys_lseek`).
pub fn lseek(fd: u64, decalage: u64, depuis: u64) -> i64 {
    const SEEK_SET: u64 = 0;
    const SEEK_CUR: u64 = 1;
    const SEEK_END: u64 = 2;
    const SEEK_DATA: u64 = 3;
    const SEEK_HOLE: u64 = 4;
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let depuis = depuis as u32 as u64;
    if depuis > SEEK_HOLE {
        return -EINVAL;
    }
    let decalage = decalage as i64;
    let _verrous = verrous(&o, true, false);
    let position = o.position();
    let nouvelle = match (o.sorte, depuis) {
        (Sorte::Chemin, _) => return -EBADF,
        (Sorte::Console | Sorte::Tube | Sorte::Socket, _) => return -ESPIPE,
        (Sorte::Null | Sorte::Zero | Sorte::Plein | Sorte::Aleatoire { .. }, _) => return 0,
        // Ni position ni taille : `noop_llseek`, qui rend la position, nulle.
        (Sorte::EventFd | Sorte::Epoll | Sorte::Inotify, _) => return position as i64,
        (Sorte::Noyau { lecture }, _) => match procfs::deplacer(lecture, position, decalage, depuis) {
            p if p >= 0 => Some(p),
            e => return e,
        },
        (_, SEEK_SET) => Some(decalage),
        (_, SEEK_CUR) => (position as i64).checked_add(decalage),
        (Sorte::Fichier, SEEK_END) => {
            let taille = vfs::avec(|fs, _| fs.attributs(o.numero()).taille) as i64;
            taille.checked_add(decalage)
        }
        (Sorte::Fichier, SEEK_DATA | SEEK_HOLE) => {
            if decalage < 0 {
                return errno(Erreur::ENXIO);
            }
            match vfs::avec(|fs, _| fs.chercher(o.numero(), decalage as u64, depuis == SEEK_DATA)) {
                Ok(p) => Some(p as i64),
                Err(e) => return errno(e),
            }
        }
        _ => return -EINVAL,
    };
    match nouvelle {
        Some(p) if p >= 0 => {
            o.changer_position(p as u64);
            p
        }
        _ => -EINVAL,
    }
}

/// Le fichier du descripteur `fd` qu'un mmap projette, tenu jusqu'à ce que
/// la zone tienne le sien : sinon un `close` et un `open` d'un autre fil
/// entre les deux donneraient son numéro à un autre fichier, que la zone
/// projetterait sans qu'on ait vérifié son droit de lecture. Un
/// descripteur invalide ou O_PATH : EBADF (le `fget` de Linux ne rend pas
/// les fichiers O_PATH).
pub fn pour_projeter(fd: u64) -> Result<FichierTenu, i64> {
    let o = tenir(fd)?;
    if o.sorte == Sorte::Chemin {
        return Err(-EBADF);
    }
    Ok(o)
}

/// Le périphérique de l'objet (`st_dev`) et sa taille de bloc
/// (`st_blksize`) : ceux de son système de fichiers.
pub fn systeme_de(o: Objet) -> ((u32, u32), u64) {
    vfs::avec_systeme(|s, _| s.avec_vue(0, |vue| vue.peripherique(o))).unwrap_or((DEV_RACINE, TAILLE_DE_BLOC))
}

/// La « struct stat » de Linux sur x86_64 (144 octets), d'après les
/// attributs d'un inode et son système de fichiers. Celui de la racine est
/// le périphérique 0:20 (un numéro anonyme, comme ceux que Linux donne aux
/// tmpfs).
fn stat_linux(a: &Attributs, (dev, taille_de_bloc): ((u32, u32), u64)) -> [u8; 144] {
    let mut s = [0u8; 144];
    let mut mettre = |position: usize, valeur: u64, taille: usize| {
        s[position..position + taille].copy_from_slice(&valeur.to_le_bytes()[..taille]);
    };
    mettre(0, encoder_peripherique(dev), 8); // st_dev
    mettre(8, a.numero, 8); // st_ino
    mettre(16, a.nlink as u64, 8); // st_nlink
    mettre(24, a.mode as u64, 4); // st_mode
    mettre(28, a.uid as u64, 4); // st_uid
    mettre(32, a.gid as u64, 4); // st_gid
    mettre(40, encoder_peripherique(a.rdev), 8); // st_rdev
    mettre(48, a.taille, 8); // st_size
    mettre(56, taille_de_bloc, 8); // st_blksize
    mettre(64, a.blocs, 8); // st_blocks
    for (position, t) in [(72, a.atime), (88, a.mtime), (104, a.ctime)] {
        mettre(position, t.secondes as u64, 8);
        mettre(position + 8, t.nanosecondes as u64, 8);
    }
    s
}

/// Le périphérique du système de fichiers de la racine.
pub const DEV_RACINE: (u32, u32) = (0, 20);

/// Majeur et mineur dans un st_dev (le `new_encode_dev` de Linux : le
/// mineur sur 20 bits, coupé autour du majeur, pour rester compatible avec
/// les vieux numéros sur 16 bits).
pub fn encoder_peripherique((majeur, mineur): (u32, u32)) -> u64 {
    ((mineur & 0xff) | (majeur << 8) | ((mineur & !0xff) << 12)) as u64
}

/// La taille de bloc « préférée » pour les entrées-sorties (st_blksize)
/// du tmpfs : une page, périphériques compris (/dev/null, /dev/console :
/// 4096 sous Linux ; seuls les pseudo-terminaux de /dev/pts disent 1024).
/// La glibc en tire la taille du tampon de stdout. Un système monté a la
/// sienne (fichiers::montages::Monte::taille_de_bloc).
const TAILLE_DE_BLOC: u64 = PAGE;

fn ecrire_stat(o: Objet, adresse: u64) -> i64 {
    let s = stat_linux(&attributs(o), systeme_de(o));
    match copier_vers_utilisateur(adresse, &s) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// fstat(fd, stat). Un descripteur O_PATH convient.
pub fn fstat(fd: u64, adresse: u64) -> i64 {
    match tenir(fd) {
        Ok(o) => ecrire_stat(o.objet, adresse),
        Err(e) => e,
    }
}

/// Le chemin d'un appel de la famille de stat : avec AT_EMPTY_PATH, un
/// pointeur nul vaut un chemin vide (le descripteur lui-même), comme depuis
/// Linux 6.11 (`getname_maybe_null` : fstat sans copier de chemin).
fn chemin_de_stat(adresse: u64, drapeaux: u64) -> Result<Vec<u8>, i64> {
    if adresse == 0 && drapeaux & AT_EMPTY_PATH != 0 { Ok(Vec::new()) } else { chemin(adresse) }
}

/// newfstatat(dossier, chemin, stat, drapeaux) : stat et lstat de la glibc.
/// Drapeaux : AT_SYMLINK_NOFOLLOW (lstat), AT_EMPTY_PATH (le descripteur
/// lui-même), AT_NO_AUTOMOUNT (sans objet) ; les autres : EINVAL.
pub fn newfstatat(dirfd: u64, adresse: u64, stat: u64, drapeaux: u64) -> i64 {
    if drapeaux & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT) != 0 {
        return -EINVAL;
    }
    let chemin = match chemin_de_stat(adresse, drapeaux) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(o) => ecrire_stat(o.objet(), stat),
        Err(e) => e,
    }
}

/// stat(chemin, stat) et lstat : les anciens appels.
pub fn stat(adresse: u64, stat: u64, suivre: bool) -> i64 {
    newfstatat(AT_FDCWD as u64, adresse, stat, if suivre { 0 } else { AT_SYMLINK_NOFOLLOW })
}

/// statx(dossier, chemin, drapeaux, masque, statx) : stat, en plus riche
/// et extensible ; Rust (std) l'essaie d'abord. La « struct statx » : 256
/// octets. On remplit les champs de base (STATX_BASIC_STATS), quel que soit
/// le masque demandé (permis : le masque rendu dit ce qui est rempli). Un
/// bit réservé du masque (STATX__RESERVED) ou un drapeau inconnu : EINVAL.
pub fn statx(dirfd: u64, adresse: u64, drapeaux: u64, masque: u64, statx: u64) -> i64 {
    const STATX_BASIC_STATS: u32 = 0x7ff;
    const STATX_RESERVE: u64 = 0x8000_0000;
    if masque & STATX_RESERVE != 0
        || drapeaux & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE) != 0
        || drapeaux & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE
    {
        return -EINVAL;
    }
    let chemin = match chemin_de_stat(adresse, drapeaux) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let o = match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let a = attributs(o.objet());
    let (dev, taille_de_bloc) = systeme_de(o.objet());
    let mut s = [0u8; 256];
    let mut mettre = |position: usize, valeur: u64, taille: usize| {
        s[position..position + taille].copy_from_slice(&valeur.to_le_bytes()[..taille]);
    };
    mettre(0, STATX_BASIC_STATS as u64, 4); // stx_mask
    mettre(4, taille_de_bloc, 4); // stx_blksize
    mettre(16, a.nlink as u64, 4);
    mettre(20, a.uid as u64, 4);
    mettre(24, a.gid as u64, 4);
    mettre(28, a.mode as u64, 2);
    mettre(32, a.numero, 8);
    mettre(40, a.taille, 8);
    mettre(48, a.blocs, 8);
    // atime, btime (absente), ctime, mtime : secondes sur 64 bits,
    // nanosecondes sur 32.
    for (position, t) in [(64, a.atime), (96, a.ctime), (112, a.mtime)] {
        mettre(position, t.secondes as u64, 8);
        mettre(position + 8, t.nanosecondes as u64, 4);
    }
    mettre(128, a.rdev.0 as u64, 4);
    mettre(132, a.rdev.1 as u64, 4);
    mettre(136, dev.0 as u64, 4);
    mettre(140, dev.1 as u64, 4);
    match copier_vers_utilisateur(statx, &s) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// faccessat2(dossier, chemin, droits, drapeaux) : le programme a-t-il les
/// droits `droits` (R_OK, W_OK, X_OK ; F_OK = 0 : seulement l'existence) ?
/// Un droit inconnu, un drapeau inconnu : EINVAL. AT_EACCESS (l'identité
/// effective plutôt que réelle) ne change rien : elles sont les mêmes.
pub fn faccessat2(dirfd: u64, adresse: u64, droits: u64, drapeaux: u64) -> i64 {
    if droits & !7 != 0 || drapeaux & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let o = match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let qui = processus::avec(|p| p.identite);
    let a = attributs(o.objet());
    if permis(a.mode, a.uid, a.gid, qui, droits as u32) { 0 } else { errno(Erreur::EACCES) }
}

/// access(chemin, droits), faccessat(dossier, chemin, droits).
pub fn access(adresse: u64, droits: u64) -> i64 {
    faccessat2(AT_FDCWD as u64, adresse, droits, 0)
}

/// Un second descripteur pour le fichier tenu `f`, au plus petit numéro
/// libre à partir de `minimum` (dup, F_DUPFD) : réservé, le fichier tenu
/// une fois de plus et installé, dans une seule section de la table des
/// descripteurs, sous le verrou des fichiers (l'ordre de processus.rs),
/// comme le `f_dupfd` de Linux sous le verrou de sa table. EMFILE, ENOMEM.
fn dupliquer(f: &FichierTenu, minimum: u64, fermer_a_l_exec: bool) -> i64 {
    let r = vfs::avec_systeme(|s, _| {
        processus::descripteurs(|d| {
            let fd = d.reserver(minimum)?;
            s.ouverts.prendre(f.fichier);
            d.installer(fd, Descripteur { fichier: f.fichier, fermer_a_l_exec });
            Ok(fd)
        })
    });
    match r {
        Ok(fd) => fd as i64,
        Err(refus) => errno_table(refus),
    }
}

/// Installe un second descripteur pour le fichier du descripteur `ancien`,
/// au numéro `nouveau` : le fichier est tenu une fois de plus. Si `nouveau`
/// était ouvert, il est remplacé d'un coup, puis son fichier lâché (le
/// `do_dup2` de Linux) : pas d'instant où le numéro est libre, et si la
/// table ne peut pas grandir (ENOMEM), l'ancien reste ouvert. Tout est
/// fait sous le verrou des descripteurs (et celui des fichiers, pour tenir
/// le fichier une fois de plus), avec les numéros comme Linux (pas un
/// fichier tenu) : dans l'ordre de `ksys_dup3`, un `nouveau` au-delà de la
/// limite, EBADF ; un `ancien` fermé, EBADF ; la table qui ne grandit pas,
/// ENOMEM ; un `nouveau` réservé par un appel en cours d'un autre fil,
/// EBUSY. Le fichier remplacé est lâché hors des deux verrous (le fermer
/// peut rendre des pages).
fn installer_copie(ancien: u64, nouveau: u64, fermer_a_l_exec: bool) -> i64 {
    let r = vfs::avec_systeme(|s, _| {
        processus::descripteurs(|t| {
            if nouveau >= t.limite.0 {
                return Err(-EBADF);
            }
            let d = t.get(ancien).ok_or(-EBADF)?;
            let remplace = t.remplacer(nouveau, Descripteur { fichier: d.fichier, fermer_a_l_exec }).map_err(errno_table)?;
            s.ouverts.prendre(d.fichier);
            Ok(remplace)
        })
    });
    match r {
        Ok(remplace) => {
            if let Some(ancien) = remplace {
                vfs::avec_systeme(|s, cadres| s.lacher(ancien.fichier, cadres));
            }
            nouveau as i64
        }
        Err(e) => e,
    }
}

/// dup(fd) : le plus petit numéro libre.
pub fn dup(fd: u64) -> i64 {
    match tenir(fd) {
        Ok(f) => dupliquer(&f, 0, false),
        Err(e) => e,
    }
}

/// dup3(ancien, nouveau, drapeaux) : au numéro `nouveau`, à la place de ce
/// qui y était ouvert. Un numéro au-delà de la limite : EBADF ; le même des
/// deux côtés : EINVAL (dup2, lui, rend le numéro) ; un drapeau autre
/// qu'O_CLOEXEC : EINVAL.
pub fn dup3(ancien: u64, nouveau: u64, drapeaux: u64) -> i64 {
    if drapeaux & !O_CLOEXEC != 0 {
        return -EINVAL;
    }
    let (ancien, nouveau) = (ancien as u32 as u64, nouveau as u32 as u64);
    if ancien == nouveau {
        return -EINVAL;
    }
    installer_copie(ancien, nouveau, drapeaux & O_CLOEXEC != 0)
}

/// dup2(ancien, nouveau).
pub fn dup2(ancien: u64, nouveau: u64) -> i64 {
    if ancien as u32 == nouveau as u32 {
        return match processus::descripteurs(|d| d.get(ancien)) {
            Some(_) => nouveau as u32 as i64,
            None => -EBADF,
        };
    }
    dup3(ancien, nouveau, 0)
}

/// fcntl(fd, commande, argument). Les commandes :
///   - F_DUPFD, F_DUPFD_CLOEXEC : dup, au plus petit numéro libre à partir
///     de `argument` ; un argument au-delà de la limite : EINVAL ; plus de
///     numéro libre au-dessus : EMFILE ;
///   - F_GETFD, F_SETFD : le drapeau FD_CLOEXEC ;
///   - F_GETOWN, F_SETOWN et leurs versions _EX, F_GETOWNER_UIDS, F_GETSIG, F_SETSIG : le
///     propriétaire du fichier (asynchrone.rs) ;
///   - F_GETFL : le mode d'ouverture et les drapeaux d'état ; F_SETFL :
///     seuls O_APPEND, O_NONBLOCK, O_ASYNC (asynchrone.rs, sur ce qui a une liste) (et O_DIRECT, O_NOATIME, sans
///     effet ici) changent, le reste est ignoré, comme Linux ;
///   - F_GETLK, F_SETLK, F_SETLKW et leurs versions « OFD » : les verrous
///     de fichiers (`verrou_posix`). Ils ne sont pas encore tenus : poser
///     réussit toujours, et F_GETLK répond « rien ne bloque » (l_type =
///     F_UNLCK), une fois la demande vérifiée ;
///   - F_GETPIPE_SZ, F_SETPIPE_SZ : la capacité d'un tube (tube.rs) ; d'un
///     autre fichier : EBADF (mesuré) ;
///   - le reste : EINVAL.
/// Sur un descripteur O_PATH, seules F_DUPFD*, F_GETFD, F_SETFD et F_GETFL
/// sont permises (EBADF sinon).
pub fn fcntl(fd: u64, commande: u64, argument: u64) -> i64 {
    use crate::asynchrone;
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;
    const F_OFD_GETLK: u64 = 36;
    const F_OFD_SETLK: u64 = 37;
    const F_OFD_SETLKW: u64 = 38;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_SETPIPE_SZ: u64 = 1031;
    const F_GETPIPE_SZ: u64 = 1032;
    const FD_CLOEXEC: u64 = 1;
    const F_SETOWN: u64 = 8;
    const F_GETOWN: u64 = 9;
    const F_SETSIG: u64 = 10;
    const F_GETSIG: u64 = 11;
    const F_SETOWN_EX: u64 = 15;
    const F_GETOWN_EX: u64 = 16;
    const F_GETOWNER_UIDS: u64 = 17;
    const CHANGEABLES: u64 = O_APPEND | O_NONBLOCK | 0o40000 | 0o1000000;
    let d = match tenir(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if d.sorte == Sorte::Chemin && !matches!(commande, F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL) {
        return -EBADF;
    }
    match commande {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let (minimum, limite) = (argument as u32 as u64, processus::descripteurs(|d| d.limite.0));
            if minimum >= limite {
                return -EINVAL;
            }
            dupliquer(&d, minimum, commande == F_DUPFD_CLOEXEC)
        }
        F_GETFD => d.fermer_a_l_exec as i64,
        F_SETFD => {
            processus::descripteurs(|t| t.get_mut(fd).map(|d| d.fermer_a_l_exec = argument & FD_CLOEXEC != 0));
            0
        }
        F_GETFL => d.drapeaux as i64,
        F_SETFL => {
            // O_ASYNC (`setfl`) : ce n'est pas un drapeau comme un autre : il inscrit le fichier (une
            // faute de mémoire, et rien n'a changé), et sans inscription possible, il ne reste pas.
            let voulu = argument & O_ASYNC != 0;
            if voulu != (d.drapeaux as u64 & O_ASYNC != 0)
                && let Err(e) = basculer_async(&d, fd, voulu)
            {
                return e;
            }
            vfs::avec_systeme(|s, _| {
                let f = s.ouverts.fichier(d.fichier);
                f.drapeaux = ((f.drapeaux as u64 & !CHANGEABLES) | (argument & CHANGEABLES)) as u32;
            });
            0
        }
        F_GETOWN => asynchrone::f_getown(d.fichier),
        F_SETOWN => asynchrone::f_setown(d.fichier, argument as u32 as i32),
        F_GETOWN_EX => asynchrone::f_getown_ex(d.fichier, argument),
        F_SETOWN_EX => asynchrone::f_setown_ex(d.fichier, argument),
        F_GETOWNER_UIDS => asynchrone::f_getowner_uids(d.fichier, argument),
        F_GETSIG => asynchrone::f_getsig(d.fichier),
        F_SETSIG => asynchrone::f_setsig(d.fichier, argument as u32 as i32),
        F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => {
            verrou_posix(fd, argument, false, matches!(commande, F_OFD_SETLK | F_OFD_SETLKW))
        }
        F_GETLK | F_OFD_GETLK => verrou_posix(fd, argument, true, commande == F_OFD_GETLK),
        // La capacité d'un tube (`pipe_fcntl`) ; un autre fichier : EBADF.
        F_SETPIPE_SZ | F_GETPIPE_SZ if d.sorte != Sorte::Tube => -EBADF,
        F_GETPIPE_SZ => d.tube().capacite(),
        F_SETPIPE_SZ => d.tube().changer_capacite(argument, processus::avec(|p| p.identite.root())),
        _ => -EINVAL,
    }
}

/// Un verrou de fichier (F_SETLK, F_GETLK...) : la `struct flock` du
/// programme (32 octets : l_type et l_whence sur 16 bits, l_start et l_len
/// sur 64, l_pid sur 32), vérifiée comme `fcntl_setlk` et `fcntl_getlk` de
/// Linux, dans leur ordre :
///   - copiée (EFAULT) ;
///   - l_type : F_RDLCK, F_WRLCK, ou pour poser F_UNLCK (EINVAL sinon ;
///     F_GETLK le vérifie en premier, F_SETLK après la plage) ;
///   - la plage : l_whence (SEEK_SET, SEEK_CUR, SEEK_END : EINVAL sinon),
///     un début négatif (EINVAL), une fin au-delà de la plus grande
///     position (EOVERFLOW) ; une longueur négative compte vers l'arrière ;
///   - poser un verrou de lecture sur un descripteur qui ne lit pas, ou
///     d'écriture sur un qui n'écrit pas : EBADF ;
///   - pour la version OFD, l_pid doit valoir 0 (EINVAL).
/// Puis : poser réussit, F_GETLK répond F_UNLCK (le reste de la structure
/// inchangé, comme Linux). Un écart, depuis que deux programmes peuvent
/// tourner en même temps (`&`, 6e) : deux verrous d'écriture sur le même
/// fichier ne s'excluent pas ; les vrais verrous viendront avec le premier
/// programme qui en aura besoin (noté dans « Reste à faire »).
fn verrou_posix(fd: u64, adresse: u64, demander: bool, ofd: bool) -> i64 {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    const EOVERFLOW: i64 = 75;
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let mut flock = [0u8; 32];
    if copier_depuis_utilisateur(&mut flock, adresse).is_err() {
        return -EFAULT;
    }
    let mot = |i: usize| i16::from_le_bytes([flock[i], flock[i + 1]]);
    let long = |i: usize| i64::from_le_bytes(flock[i..i + 8].try_into().unwrap_or([0; 8]));
    let (genre, depuis, debut, longueur) = (mot(0), mot(2), long(8), long(16));
    let pid = i32::from_le_bytes(flock[24..28].try_into().unwrap_or([0; 4]));
    let genre_permis = matches!(genre, F_RDLCK | F_WRLCK) || (genre == F_UNLCK && !demander);
    if demander && !genre_permis {
        return -EINVAL;
    }
    let base = match depuis {
        0 => 0,
        1 => o.position() as i64,
        2 if o.sorte == Sorte::Fichier => vfs::avec(|fs, _| fs.attributs(o.numero()).taille) as i64,
        2 => 0,
        _ => return -EINVAL,
    };
    let Some(debut) = base.checked_add(debut).filter(|&d| d >= 0) else {
        return -EINVAL;
    };
    if longueur > 0 && longueur - 1 > i64::MAX - debut {
        return -EOVERFLOW;
    }
    if longueur < 0 && debut.checked_add(longueur).is_none_or(|d| d < 0) {
        return -EINVAL;
    }
    if !genre_permis {
        return -EINVAL;
    }
    if !demander && ((genre == F_RDLCK && !o.lecture) || (genre == F_WRLCK && !o.ecriture)) {
        return -EBADF;
    }
    if ofd && pid != 0 {
        return -EINVAL;
    }
    if demander && copier_vers_utilisateur(adresse, &F_UNLCK.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    0
}

/// flock(fd, opération) : un verrou sur tout le fichier. Toujours accordé,
/// comme ceux de fcntl (voir `verrou_posix`, le même écart). Une opération
/// inconnue : EINVAL ; un descripteur O_PATH : EBADF.
pub fn flock(fd: u64, operation: u64) -> i64 {
    const LOCK_SH: u64 = 1;
    const LOCK_EX: u64 = 2;
    const LOCK_NB: u64 = 4;
    const LOCK_UN: u64 = 8;
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if o.sorte == Sorte::Chemin {
        return -EBADF;
    }
    match operation & !LOCK_NB {
        LOCK_SH | LOCK_EX | LOCK_UN => 0,
        _ => -EINVAL,
    }
}

/// ioctl(fd, requête, argument) : les requêtes que Linux traite pour tous
/// les fichiers (`do_vfs_ioctl`) :
///   - FIOCLEX, FIONCLEX : le drapeau « fermer à l'exec » ;
///   - FIONBIO : O_NONBLOCK, d'après l'entier à `argument` ;
///   - FIONREAD, pour un inode de fichier ordinaire (S_IFREG) : de la
///     position à la taille, en `int` (négatif si la position est au-delà :
///     Linux ne borne pas). Les fichiers de /proc et de /sys en sont : ce
///     qu'en dit stat, 0 ou une page, moins la position (mesuré : -3 après
///     avoir lu 3 octets de maps). Pour le reste, c'est au pilote d'y
///     répondre : ENOTTY pour les nôtres (un terminal le fera, 6k), sauf
///     ceux qui ont leurs propres requêtes ;
///   - un epoll répond lui-même à toute autre requête : EINVAL
///     (`ep_eventpoll_ioctl`, mesuré), et /dev/random et /dev/urandom
///     aussi, après les leurs (`ioctl_aleatoire`) ;
///   - les requêtes des terminaux (TCGETS, la question d'isatty, et les
///     autres) : ENOTTY, la console n'en est pas encore un (6k). La glibc
///     met alors la sortie standard dans un tampon complet, vidé à la
///     sortie.
pub fn ioctl(fd: u64, requete: u64, argument: u64) -> i64 {
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    const FIONBIO: u64 = 0x5421;
    const FIOASYNC: u64 = 0x5452;
    const FIONREAD: u64 = 0x541b;
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if o.sorte == Sorte::Chemin {
        return -EBADF;
    }
    match requete as u32 as u64 {
        FIOCLEX | FIONCLEX => {
            processus::descripteurs(|t| t.get_mut(fd).map(|d| d.fermer_a_l_exec = requete as u32 as u64 == FIOCLEX));
            0
        }
        FIONBIO => {
            let mut valeur = [0u8; 4];
            if copier_depuis_utilisateur(&mut valeur, argument).is_err() {
                return -EFAULT;
            }
            vfs::avec_systeme(|s, _| {
                let f = s.ouverts.fichier(o.fichier);
                f.drapeaux = if i32::from_le_bytes(valeur) != 0 {
                    f.drapeaux | O_NONBLOCK as u32
                } else {
                    f.drapeaux & !(O_NONBLOCK as u32)
                };
            });
            0
        }
        // `ioctl_fioasync` : un fichier sans liste : ENOTTY, si cela change quelque chose.
        FIOASYNC => {
            let mut valeur = [0u8; 4];
            if copier_depuis_utilisateur(&mut valeur, argument).is_err() {
                return -EFAULT;
            }
            let voulu = i32::from_le_bytes(valeur) != 0;
            if voulu == (o.drapeaux as u64 & O_ASYNC != 0) {
                return 0;
            }
            if !a_une_liste(&o) {
                return -ENOTTY;
            }
            match basculer_async(&o, fd, voulu) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        FIONREAD if attributs(o.objet).mode & S_IFMT == S_IFREG => {
            let taille = attributs(o.objet).taille;
            let reste = (taille as i64).wrapping_sub(o.position() as i64) as i32;
            match copier_vers_utilisateur(argument, &reste.to_le_bytes()) {
                Ok(()) => 0,
                Err(_) => -EFAULT,
            }
        }
        // Les octets présents dans un tube (`pipe_ioctl`).
        FIONREAD if o.sorte == Sorte::Tube => match copier_vers_utilisateur(argument, &o.tube().octets_presents().to_le_bytes()) {
            Ok(()) => 0,
            Err(_) => -EFAULT,
        },
        _ if o.sorte == Sorte::Epoll => -EINVAL,
        _ if o.sorte == Sorte::Socket => crate::appels_reseau::ioctl(&o, requete as u32 as u64, argument),
        _ if o.sorte == Sorte::Inotify => surveillance::ioctl(o.inotify().expect("une instance"), requete as u32 as u64, argument),
        _ if matches!(o.sorte, Sorte::Aleatoire { .. }) => ioctl_aleatoire(requete as u32 as u64, argument),
        _ => -ENOTTY,
    }
}

/// Les requêtes du pilote de /dev/random et /dev/urandom (`random_ioctl`,
/// drivers/char/random.c), une fois passées celles de tous les fichiers :
///   - RNDGETENTCNT : les bits crédités au réservoir (`input_pool.init_bits`),
///     de 0 à 256 ; 256 une fois prêt (le compte ne bouge plus, mesuré) ;
///   - les requêtes qui changent le générateur (ajouter de l'entropie, la
///     remettre à zéro, le réensemencer) : réservées à root (EPERM, avant
///     de rien lire), ce que nos programmes ne sont pas ;
///   - toute autre, FIONREAD et les requêtes des terminaux comprises :
///     EINVAL (mesuré ; pas ENOTTY comme les autres périphériques).
fn ioctl_aleatoire(requete: u64, argument: u64) -> i64 {
    const RNDGETENTCNT: u64 = 0x8004_5200;
    const RNDADDTOENTCNT: u64 = 0x4004_5201;
    const RNDADDENTROPY: u64 = 0x4008_5203;
    const RNDZAPENTCNT: u64 = 0x5204;
    const RNDCLEARPOOL: u64 = 0x5206;
    const RNDRESEEDCRNG: u64 = 0x5207;
    match requete {
        RNDGETENTCNT => {
            let compte = crate::aleatoire::bits() as i32;
            match copier_vers_utilisateur(argument, &compte.to_le_bytes()) {
                Ok(()) => 0,
                Err(_) => -EFAULT,
            }
        }
        RNDADDTOENTCNT | RNDADDENTROPY | RNDZAPENTCNT | RNDCLEARPOOL | RNDRESEEDCRNG => errno(Erreur::EPERM),
        _ => -EINVAL,
    }
}

/// unlinkat(dossier, chemin, drapeaux) : unlink, ou rmdir avec
/// AT_REMOVEDIR (un autre drapeau : EINVAL). Les vérifications sont celles
/// du tmpfs (`Tmpfs::effacer`). Un fichier encore ouvert ou projeté vit
/// jusqu'à sa dernière référence.
pub fn unlinkat(dirfd: u64, adresse: u64, drapeaux: u64) -> i64 {
    if drapeaux & !AT_REMOVEDIR != 0 {
        return -EINVAL;
    }
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if chemin.is_empty() {
        return errno(Erreur::ENOENT);
    }
    let maintenant = temps::maintenant();
    let rmdir = drapeaux & AT_REMOVEDIR != 0;
    let r = avec_fin(dirfd, &chemin, Suivre::Jamais, |s, cadres, fin, depart, pid| match en_tmpfs(fin) {
        Ok(fin) => {
            let victime = fin.objet.filter(|_| fin.dernier == Dernier::Nom);
            let dossier = victime.is_some_and(|v| s.fs.est_un_dossier(v));
            let entree = victime.and_then(|_| s.fs.entree(fin.dossier, &fin.nom));
            s.fs.effacer(depart.qui, &fin, rmdir, maintenant, cadres).map_err(errno)?;
            // Ce qu'en voit inotify, dans l'ordre de `vfs_unlink` et
            // `vfs_rmdir` : le nombre de liens du fichier (pas d'un dossier) ;
            // la fin de l'inode, s'il n'est plus tenu, ou s'il n'a plus de
            // nom et que personne ne tenait celui-ci (IN_DELETE_SELF :
            // `Systeme::entree_morte`) ; l'entrée effacée, au dossier.
            if let Some(v) = victime
                && !rmdir
            {
                surveillance::de_l_inode(v, false, IN_ATTRIB);
            }
            cadres.annoncer_les_fins();
            if let Some((v, cookie)) = entree {
                s.entree_morte(v, fin.dossier, cookie);
            }
            surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_DELETE, dossier, 0);
            Ok(())
        }
        Err(fin) => Err(refus(s, pid, depart.qui, Modification::Effacer(&fin, rmdir))),
    });
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// unlink(chemin).
pub fn unlink(adresse: u64) -> i64 {
    unlinkat(AT_FDCWD as u64, adresse, 0)
}

/// rmdir(chemin).
pub fn rmdir(adresse: u64) -> i64 {
    unlinkat(AT_FDCWD as u64, adresse, AT_REMOVEDIR)
}

/// Ouvre en lecture l'inode `n` (de chemin `chemin`, tel que donné, et
/// `complet`, canonique, et de sorte `sorte`), pour le noyau : le programme
/// à exécuter, que ses zones projetteront (le `bprm->file` de Linux), ou
/// son interpréteur. Rend le fichier ouvert, tenu une fois. Son lieu est
/// celui de `trouve` (trouver_pour). Comme l'`execve` de Linux, inotify
/// voit son ouverture (IN_OPEN), puis sa lecture, quand le lanceur la dit
/// (`annoncer_la_lecture` : IN_ACCESS), et, quand ses zones le lâcheront à
/// la fin du programme, sa fermeture (IN_CLOSE_NOWRITE ; mesuré).
pub fn ouvrir_inode(n: Numero, chemin: &[u8], complet: Vec<u8>, sorte: Sorte, trouve: &CheminTenu) -> Result<Fichier, Erreur> {
    vfs::avec_systeme(|s, cadres| {
        let lieu = match s.ouverts.voir(trouve.fichier).and_then(|f| f.lieu.as_ref()) {
            Some(l) => Some(surveillance::LieuPrepare::copie(l).map_err(|_| Erreur::ENOMEM)?),
            None => None,
        };
        s.fs.prendre(n);
        let ouvert = fichiers::tmpfs::Ouvert { numero: n, cree: false, tronquer: false, ecrivain: false };
        let fichier = FichierOuvert::new(sorte, Tenu::Tmpfs(ouvert), true, false, (O_RDONLY | O_LARGEFILE) as u32, chemin)
            .avec_chemin(complet);
        let fichier = s.ouverts.ajouter(fichier).map_err(|_| {
            s.fs.fermer(&ouvert, cadres);
            Erreur::ENOMEM
        })?;
        s.ouverts.fichier(fichier).lieu = lieu.and_then(|l| l.achever(&mut s.fs, Objet::Tmpfs(n)));
        surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_OPEN);
        Ok(fichier)
    })
}

/// Le noyau lit le fichier ouvert `fichier` (le programme ou
/// l'interpréteur que lance le lanceur : le `kernel_read` de
/// `prepare_binprm` et de `load_elf_binary`) : IN_ACCESS.
pub fn annoncer_la_lecture(fichier: Fichier) {
    vfs::avec_systeme(|s, _| surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_ACCESS));
}

/// Les descripteurs d'un programme qui commence : la console, ouverte en
/// lecture et écriture au numéro 0, puis dupliquée en 1 et 2 (le
/// `console_on_rootfs` de Linux, dont héritent tous les processus).
/// Sur ENOMEM, rien ne reste installé : l'appelant jette `descripteurs`
/// sans les fermer.
pub fn ouvrir_console(descripteurs: &mut crate::descripteurs::Descripteurs) -> Result<(), Erreur> {
    let console = ouvrir_pour_le_noyau(b"/dev/console", true, true)?;
    for fd in 0..3 {
        if fd > 0 {
            vfs::avec_systeme(|s, _| s.ouverts.prendre(console));
        }
        if descripteurs.remplacer(fd, Descripteur { fichier: console, fermer_a_l_exec: false }).is_err() {
            vfs::avec_systeme(|s, cadres| {
                s.lacher(console, cadres);
                for installe in 0..fd {
                    if let Some(d) = descripteurs.retirer(installe) {
                        s.lacher(d.fichier, cadres);
                    }
                }
            });
            return Err(Erreur::ENOMEM);
        }
    }
    Ok(())
}

/// Installe le fichier ouvert `f` (tenu par l'appelant, qui le garde) au
/// numéro `fd` de `descripteurs`, sans FD_CLOEXEC, à la place de ce qui y
/// était : une redirection de /etc/demarrage (6i, programmes.rs).
pub fn installer_pour_le_noyau(descripteurs: &mut crate::descripteurs::Descripteurs, fd: u64, f: Fichier)
    -> Result<(), Erreur> {
    vfs::avec_systeme(|s, _| s.ouverts.prendre(f));
    match descripteurs.remplacer(fd, Descripteur { fichier: f, fermer_a_l_exec: false }) {
        Ok(ancien) => {
            if let Some(d) = ancien {
                vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
            }
            Ok(())
        }
        Err(_) => {
            vfs::avec_systeme(|s, cadres| s.lacher(f, cadres));
            Err(Erreur::ENOMEM)
        }
    }
}

/// L'entrée standard d'un programme lancé par `&` : /dev/null, ouvert en
/// lecture au numéro 0, à la place de la console (POSIX, pour un `sh` sans
/// contrôle des tâches : « asynchronous lists »).
pub fn entree_sur_null(descripteurs: &mut crate::descripteurs::Descripteurs) -> Result<(), Erreur> {
    let null = ouvrir_pour_le_noyau(b"/dev/null", true, false)?;
    match descripteurs.remplacer(0, Descripteur { fichier: null, fermer_a_l_exec: false }) {
        Ok(ancien) => {
            if let Some(d) = ancien {
                vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
            }
            Ok(())
        }
        Err(_) => {
            vfs::avec_systeme(|s, cadres| s.lacher(null, cadres));
            Err(Erreur::ENOMEM)
        }
    }
}

// ----- Les sockets nommées (AF_UNIX, 6h) -----

/// Crée l'inode d'une socket nommée au chemin `chemin` (le `vfs_mknod` de
/// `unix_bind_bsd`) : S_IFSOCK, 0777 moins l'umask (mesuré : 0755 sous
/// l'umask 022). Le nom pris : EADDRINUSE (Linux traduit EEXIST, mesuré :
/// un fichier ordinaire aussi) ; sinon les refus de toute création
/// (ENOENT, EACCES, ENOTDIR...). L'inode est tenu : la socket le garde
/// jusqu'à sa fermeture (`lacher_noeud`), pour qu'un inode neuf qui
/// reprendrait son numéro ne soit jamais pris pour elle.
pub fn creer_noeud_socket(chemin: &[u8]) -> Result<u32, i64> {
    const EADDRINUSE: i64 = 98;
    const EACCES: i64 = 13;
    let umask = processus::avec(|p| p.umask);
    avec_fin(AT_FDCWD as u64, chemin, Suivre::Jamais, |s, _, fin, depart, pid| match en_tmpfs(fin) {
        Ok(fin) => {
            let n = s.fs.creer(depart.qui, &fin, S_IFSOCK | (0o777 & !umask), (0, 0), &[], temps::maintenant())
                .map_err(|e| if e == Erreur::EEXIST { -EADDRINUSE } else { errno(e) })?;
            s.fs.prendre(n);
            // `vfs_mknod` : `fsnotify_create`.
            surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_CREATE, false, 0);
            Ok(n.0)
        }
        Err(fin) => match refus(s, pid, depart.qui, Modification::Creer(&fin, Creation::Autre)) {
            0 => Err(-EACCES),
            e => Err(e),
        },
    })
}

/// L'inode de la socket nommée au chemin `chemin`, pour `connect` et
/// `sendto` (`unix_find_bsd`) : le chemin suivi jusqu'au bout (ENOENT...),
/// le droit d'y écrire (EACCES), une socket (sinon ECONNREFUSED, mesuré).
pub fn trouver_noeud_socket(chemin: &[u8]) -> Result<u32, i64> {
    const ENOENT: i64 = 2;
    const ECONNREFUSED: i64 = 111;
    avec_fin(AT_FDCWD as u64, chemin, Suivre::Toujours, |s, _, fin, depart, _| {
        let objet = fin.objet.ok_or(-ENOENT)?;
        let Some(n) = objet.tmpfs() else { return Err(-ECONNREFUSED) };
        s.fs.acces(depart.qui, n, fichiers::ECRIRE).map_err(errno)?;
        if s.fs.mode(n) & S_IFMT != S_IFSOCK {
            return Err(-ECONNREFUSED);
        }
        Ok(n.0)
    })
}

/// Rend l'inode d'une socket nommée (à sa fermeture) : effacé, il
/// disparaît.
pub fn lacher_noeud(n: u32) {
    vfs::avec(|fs, cadres| fs.lacher(Numero(n), cadres));
}

// ----- L'arborescence -----

const ERANGE: i64 = 34;

/// mkdirat(dossier, chemin, droits) : les droits passent par l'umask (et
/// le bit sticky est gardé, comme Linux). Les vérifications sont celles du
/// tmpfs (`Tmpfs::creer`).
pub fn mkdirat(dirfd: u64, adresse: u64, mode: u64) -> i64 {
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let umask = processus::avec(|p| p.umask);
    let droits = (mode as u32 & 0o1777) & !umask;
    let r = avec_fin(dirfd, &chemin, Suivre::Jamais, |s, _, fin, depart, pid| match en_tmpfs(fin) {
        Ok(fin) => {
            let n = s.fs.creer(depart.qui, &fin, S_IFDIR | droits, (0, 0), &[], temps::maintenant()).map_err(errno)?;
            surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_CREATE, true, 0);
            Ok(n)
        }
        Err(fin) => Err(refus(s, pid, depart.qui, Modification::Creer(&fin, Creation::Dossier))),
    });
    match r {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// mkdir(chemin, droits).
pub fn mkdir(adresse: u64, mode: u64) -> i64 {
    mkdirat(AT_FDCWD as u64, adresse, mode)
}

/// symlinkat(cible, dossier, chemin) : un lien symbolique de contenu
/// `cible` (une chaîne quelconque, qui n'a pas à exister ; vide : ENOENT,
/// avant même de résoudre le chemin, comme le `getname` de Linux).
pub fn symlinkat(cible: u64, dirfd: u64, adresse: u64) -> i64 {
    let (cible, chemin) = match (chemin(cible), chemin(adresse)) {
        (Ok(c), Ok(p)) => (c, p),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if cible.is_empty() {
        return errno(Erreur::ENOENT);
    }
    let r = avec_fin(dirfd, &chemin, Suivre::Jamais, |s, _, fin, depart, pid| match en_tmpfs(fin) {
        Ok(fin) => {
            let n = s.fs.creer(depart.qui, &fin, S_IFLNK | 0o777, (0, 0), &cible, temps::maintenant()).map_err(errno)?;
            surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_CREATE, false, 0);
            Ok(n)
        }
        Err(fin) => Err(refus(s, pid, depart.qui, Modification::Creer(&fin, Creation::Autre))),
    });
    match r {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// symlink(cible, chemin).
pub fn symlink(cible: u64, adresse: u64) -> i64 {
    symlinkat(cible, AT_FDCWD as u64, adresse)
}

/// readlinkat(dossier, chemin, tampon, taille) : le contenu du lien, sans
/// zéro final, coupé à `taille` octets. Une taille nulle ou négative, ou
/// ce qui n'est pas un lien : EINVAL. Un chemin vide désigne le
/// descripteur (ouvert avec O_PATH | O_NOFOLLOW sur le lien) ; s'il n'est
/// pas un lien : ENOENT, comme `do_readlinkat` (le chemin vide ne désigne
/// alors rien qu'on puisse lire).
pub fn readlinkat(dirfd: u64, adresse: u64, tampon: u64, taille: u64) -> i64 {
    if (taille as i32) <= 0 {
        return -EINVAL;
    }
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let tenu = match objet(dirfd, &chemin, false, true) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let o = tenu.objet();
    let vide = chemin.is_empty();
    let pid = processus::avec(|p| p.pid);
    let contenu = vfs::avec_systeme(|s, _| -> Result<Vec<u8>, i64> {
        let pas_un_lien = || if vide { errno(Erreur::ENOENT) } else { errno(Erreur::EINVAL) };
        let mut copie = Vec::new();
        s.avec_vue(pid, |vue| {
            if vue.mode(o) & S_IFMT != S_IFLNK {
                return Err(pas_un_lien());
            }
            // Un lien sans texte n'est qu'un lien de /proc dont l'objet est
            // parti (le processus) ou faute de mémoire : ENOENT, l'erreur
            // de `proc_pid_readlink`, jamais 0 (un lien du tmpfs n'est
            // jamais vide : symlink de "" rend ENOENT).
            let cible = vue.cible(o);
            if cible.is_empty() {
                return Err(errno(Erreur::ENOENT));
            }
            copie = faillible::copie(&cible).map_err(|_| -ENOMEM)?;
            Ok(())
        })?;
        if let Some(n) = o.tmpfs() {
            s.fs.acceder(n, temps::maintenant());
        }
        Ok(copie)
    });
    match contenu {
        Ok(c) => {
            let n = c.len().min(taille as u32 as usize);
            match copier_vers_utilisateur(tampon, &c[..n]) {
                Ok(()) => n as i64,
                Err(_) => -EFAULT,
            }
        }
        Err(e) => e,
    }
}

/// readlink(chemin, tampon, taille).
pub fn readlink(adresse: u64, tampon: u64, taille: u64) -> i64 {
    readlinkat(AT_FDCWD as u64, adresse, tampon, taille)
}

/// linkat(ancien dossier, ancien chemin, nouveau dossier, nouveau chemin,
/// drapeaux) : un nom de plus. L'ancien chemin n'est suivi qu'avec
/// AT_SYMLINK_FOLLOW (sinon on lie le lien lui-même, comme Linux).
/// AT_EMPTY_PATH (donner un nom au fichier d'un descripteur) : depuis Linux
/// 6.10, permis si le fichier a été ouvert sous la même identité que celle
/// qui le lie (sinon, sans CAP_DAC_READ_SEARCH : ENOENT) ; avec un seul
/// utilisateur et sans setuid, c'est toujours le cas. Un autre drapeau :
/// EINVAL.
pub fn linkat(ancien_dossier: u64, ancien: u64, nouveau_dossier: u64, nouveau: u64, drapeaux: u64) -> i64 {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    if drapeaux & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let (ancien, nouveau) = match (chemin(ancien), chemin(nouveau)) {
        (Ok(a), Ok(n)) => (a, n),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let source = match objet(ancien_dossier, &ancien, drapeaux & AT_SYMLINK_FOLLOW != 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let r = avec_fin(nouveau_dossier, &nouveau, Suivre::Jamais, |s, _, fin, depart, pid| {
        let source = source.objet();
        match (source.tmpfs(), dans_le_tmpfs(&fin)) {
            (Some(source), true) => match en_tmpfs(fin) {
                // Ce qu'en voit inotify (`fsnotify_link`) : le nombre de
                // liens de l'inode, puis l'entrée créée.
                Ok(fin) => {
                    s.fs.lier(depart.qui, source, &fin, temps::maintenant()).map_err(errno)?;
                    surveillance::de_l_inode(source, false, IN_ATTRIB);
                    surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_CREATE, false, 0);
                    Ok(())
                }
                Err(_) => Err(-EINVAL),
            },
            _ => Err(refus(s, pid, depart.qui, Modification::Lier(source, &fin))),
        }
    });
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// link(ancien, nouveau).
pub fn link(ancien: u64, nouveau: u64) -> i64 {
    linkat(AT_FDCWD as u64, ancien, AT_FDCWD as u64, nouveau, 0)
}

/// renameat2(ancien dossier, ancien chemin, nouveau dossier, nouveau
/// chemin, drapeaux) : avec RENAME_NOREPLACE et RENAME_EXCHANGE. Les deux
/// chemins sont résolus sous le même verrou ; les vérifications sont
/// celles du tmpfs (`Tmpfs::renommer`), les drapeaux d'abord, avant même
/// les chemins (`do_renameat2`). `claude` réécrit ainsi ~/.claude.json :
/// écrit à côté, puis renommé par-dessus.
pub fn renameat2(ancien_dossier: u64, ancien: u64, nouveau_dossier: u64, nouveau: u64, drapeaux: u64) -> i64 {
    if let Err(e) = fichiers::tmpfs::verifier_renommage(drapeaux as u32) {
        return errno(e);
    }
    let (ancien, nouveau) = match (chemin(ancien), chemin(nouveau)) {
        (Ok(a), Ok(n)) => (a, n),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let (tenu_ancien, tenu_nouveau) = match (depart(ancien_dossier, &ancien), depart(nouveau_dossier, &nouveau)) {
        (Ok(a), Ok(n)) => (a, n),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let (depart_ancien, depart_nouveau, pid) = (tenu_ancien.depart(), tenu_nouveau.depart(), tenu_ancien.pid);
    let r = vfs::avec_systeme(|s, cadres| {
        let fa = s.resoudre(pid, &depart_ancien, &ancien, Suivre::Jamais).map_err(errno)?;
        let fn_ = s.resoudre(pid, &depart_nouveau, &nouveau, Suivre::Jamais).map_err(errno)?;
        if !dans_le_tmpfs(&fa) || !dans_le_tmpfs(&fn_) {
            return Err(refus(s, pid, depart_ancien.qui, Modification::Renommer(&fa, &fn_, drapeaux as u32)));
        }
        let (Ok(fa), Ok(fn_)) = (en_tmpfs(fa), en_tmpfs(fn_)) else { return Err(-EINVAL) };
        s.renommer(depart_ancien.qui, &fa, &fn_, drapeaux as u32, cadres).map_err(errno)
    });
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// rename(ancien, nouveau), renameat(...).
pub fn rename(ancien: u64, nouveau: u64) -> i64 {
    renameat2(AT_FDCWD as u64, ancien, AT_FDCWD as u64, nouveau, 0)
}

/// getdents64(fd, tampon, taille) : les entrées d'un dossier, à partir de
/// sa position, au format `struct linux_dirent64` : le numéro d'inode, la
/// position de l'entrée suivante, la taille de l'entrée, son type, et son
/// nom terminé par un zéro, le tout arrondi à 8 octets. Autant d'entrées
/// qu'il en tient ; 0 à la fin du dossier. Pas un dossier : ENOTDIR ; un
/// tampon trop petit pour la première entrée : EINVAL. Les entrées sont
/// préparées dans un bloc du tas (64 Kio au plus par appel), puis copiées.
pub fn getdents64(fd: u64, tampon: u64, taille: u64) -> i64 {
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if o.sorte == Sorte::Chemin {
        return -EBADF;
    }
    if o.sorte != Sorte::Dossier {
        return errno(Erreur::ENOTDIR);
    }
    let taille = (taille as u32 as usize).min(64 << 10);
    // Le bloc mis à zéro d'avance (le zéro final de chaque nom et le
    // bourrage y sont déjà) : la lecture du dossier, sous le verrou des
    // fichiers, n'alloue rien ; `ecrit` en compte les octets remplis.
    let Ok(mut entrees) = faillible::remplie(taille, 0u8) else { return -ENOMEM };
    let mut ecrit = 0;
    let _verrous = verrous(&o, true, false);
    let debut = o.position();
    let mut position = debut;
    let lu = vfs::avec_systeme(|s, _| {
        let r = s.avec_vue(0, |vue| vue.lire_dossier(o.objet, debut, |nom, n, genre, suivante| {
            let longueur = (8 + 8 + 2 + 1 + nom.len() + 1).next_multiple_of(8);
            if ecrit + longueur > taille {
                return false;
            }
            let e = &mut entrees[ecrit..ecrit + longueur];
            e[..8].copy_from_slice(&n.to_le_bytes());
            e[8..16].copy_from_slice(&suivante.to_le_bytes());
            e[16..18].copy_from_slice(&(longueur as u16).to_le_bytes());
            e[18] = genre;
            e[19..19 + nom.len()].copy_from_slice(nom);
            ecrit += longueur;
            position = suivante;
            true
        }));
        if let Some(n) = o.objet.tmpfs() {
            s.fs.acceder(n, temps::maintenant());
        }
        // Lu, même vide ou trop petit (`iterate_dir` : son
        // fsnotify_access suit la lecture, quoi qu'elle ait rendu ; pas un
        // dossier effacé, ENOENT avant).
        if r.is_ok() {
            surveillance::du_fichier(&s.fs, s.ouverts.fichier(o.fichier), IN_ACCESS);
        }
        r
    });
    if let Err(e) = lu {
        return errno(e);
    }
    if ecrit == 0 {
        // Fin du dossier, ou la première entrée ne tient pas : on les
        // distingue en regardant s'il restait une entrée à lire.
        let reste = vfs::avec_systeme(|s, _| {
            let mut une = false;
            let _ = s.avec_vue(0, |vue| vue.lire_dossier(o.objet, debut, |_, _, _, _| {
                une = true;
                false
            }));
            une
        });
        return if reste { -EINVAL } else { 0 };
    }
    if copier_vers_utilisateur(tampon, &entrees[..ecrit]).is_err() {
        return -EFAULT;
    }
    o.changer_position(position);
    ecrit as i64
}

/// getcwd(tampon, taille) : le chemin du dossier courant, avec son zéro
/// final ; rend sa longueur, zéro compris. Trop petit : ERANGE ; un dossier
/// courant effacé : ENOENT.
pub fn getcwd(tampon: u64, taille: u64) -> i64 {
    // Tenu le temps de calculer son chemin : un `chdir` d'un autre fil, puis
    // un `rmdir`, ne le font pas disparaître sous nous (le `get_fs_pwd` de
    // Linux).
    let dossier = processus::avec(|p| vfs::avec_systeme(|s, _| ObjetTenu::tenir(s, p.dossier)));
    let mut chemin = match vfs::avec_systeme(|s, _| s.avec_vue(0, |vue| vue.chemin(dossier.objet()))) {
        Ok(c) => c,
        Err(e) => return errno(e),
    };
    if chemin.ajouter(0).is_err() {
        return -ENOMEM;
    }
    if (taille as usize) < chemin.len() {
        return -ERANGE;
    }
    match copier_vers_utilisateur(tampon, &chemin) {
        Ok(()) => chemin.len() as i64,
        Err(_) => -EFAULT,
    }
}

/// Le dossier `o` (que l'appelant tient) devient le dossier courant : un
/// dossier (ENOTDIR) qu'on a le droit de traverser (EACCES), comme
/// `set_fs_pwd` après la vérification de chdir. Il peut être dans un
/// système monté (« cd /proc ») ; un inode du tmpfs est tenu une fois de
/// plus, pour le processus.
fn changer_de_dossier(o: Objet) -> i64 {
    let qui = processus::avec(|p| p.identite);
    let a = attributs(o);
    if a.mode & S_IFMT != S_IFDIR {
        return errno(Erreur::ENOTDIR);
    }
    if !permis(a.mode, a.uid, a.gid, qui, fichiers::EXECUTER) {
        return errno(Erreur::EACCES);
    }
    if let Some(n) = o.tmpfs() {
        vfs::avec(|fs, _| fs.prendre(n));
    }
    let ancien = processus::avec(|p| core::mem::replace(&mut p.dossier, o));
    if let Some(n) = ancien.tmpfs() {
        vfs::avec(|fs, cadres| fs.lacher(n, cadres));
    }
    0
}

/// chdir(chemin).
pub fn chdir(adresse: u64) -> i64 {
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match objet(AT_FDCWD as u64, &chemin, true, false) {
        Ok(o) => changer_de_dossier(o.objet()),
        Err(e) => e,
    }
}

/// fchdir(fd).
pub fn fchdir(fd: u64) -> i64 {
    match tenir(fd) {
        Ok(o) => changer_de_dossier(o.objet),
        Err(e) => e,
    }
}

/// Ramène le fichier `n` (tenu par l'appelant) à `taille` octets, sous le
/// verrou d'écriture de son inode (l'`inode_lock` du `do_truncate` de
/// Linux) : une écriture en cours ne rallonge pas le fichier derrière nous.
///
/// Les pages qui disparaissent sont retirées des projections du processus,
/// copies privées comprises (mesuré sous Linux : une page copiée puis le
/// fichier raccourci et rallongé se relit à zéro), comme
/// `truncate_pagecache` : un accès au-delà de la nouvelle fin fera SIGBUS.
/// Deux fois, comme Linux : avant que le tmpfs lâche ses pages, et après,
/// car un autre fil qui fait une faute entre les deux trouve encore
/// l'ancienne taille, et projette la page (la seconde fois, la nouvelle
/// taille est en place : une faute suivante rend SIGBUS). Il faudrait le
/// faire dans chaque processus qui projette le fichier (la carte inverse
/// `i_mmap` de Linux) ; seul le processus en cours l'est. Un autre programme qui
/// projette le même fichier (`&`, 6e) garde ses pages (elles sont tenues :
/// la mémoire reste sûre) et y lit l'ancien contenu au lieu d'un SIGBUS :
/// un écart, noté dans « Reste à faire ».
fn tronquer(n: Numero, taille: u64, par: Fichier) -> i64 {
    // Agrandir au-delà de RLIMIT_FSIZE : SIGXFSZ et EFBIG (`inode_newsize_ok`) ;
    // raccourcir est toujours permis.
    let limite = processus::essayer_avec(|p| p.courante(processus::RLIMIT_FSIZE)).unwrap_or(u64::MAX);
    if taille > limite && taille > vfs::avec(|fs, _| fs.attributs(n).taille) {
        signaux::au_fil_courant(SIGXFSZ);
        return -EFBIG;
    }
    let _ecriture = verrou_d_ecriture(n);
    retirer_projections(n, taille.div_ceil(PAGE));
    let qui = processus::essayer_avec(|p| p.identite).unwrap_or(Identite::ROOT);
    // IN_MODIFY, au dossier et au nom qu'a l'objet à ce moment
    // (`fsnotify_change` d'ATTR_SIZE), par le fichier qui le tient ; avec
    // IN_ATTRIB, d'un seul événement, si les bits setuid et setgid tombent
    // (ATTR_MODE, dans le même `notify_change` : `do_truncate`, mesuré).
    let r = vfs::avec_systeme(|s, cadres| {
        let maintenant = temps::maintenant();
        s.fs.tronquer(n, taille, maintenant, cadres)?;
        let attrib = if s.fs.retirer_les_privileges(qui, n, maintenant) { IN_ATTRIB } else { 0 };
        surveillance::changement(&s.fs, s.ouverts.fichier(par), IN_MODIFY | attrib);
        Ok(())
    });
    retirer_projections(n, taille.div_ceil(PAGE));
    match r {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

/// Retire des projections du processus en cours les pages du fichier `n`
/// de numéro `premiere` ou plus (le `unmap_mapping_range` de Linux, copies
/// comprises). Les zones restent : un accès y refera une faute. La mémoire
/// tenue en lecture (Linux ne prend pas même le `mmap_lock` : il passe par
/// la carte inverse du fichier, `i_mmap`), les tables sous leur verrou,
/// tranche par tranche (EspaceUtilisateur::retirer_par_tranches) ; le
/// verrou des fichiers est rendu avant celui des tables (memoire.rs, l'ordre
/// des deux). Sans processus (une tâche du noyau), rien à faire.
fn retirer_projections(n: Numero, premiere: u64) {
    if tache::courante().processus().is_none() {
        return;
    }
    processus::memoire_lue(|m| {
        for z in m.zones.zones() {
            let Some(projection) = z.fichier else { continue };
            let numero = vfs::avec_systeme(|s, _| s.ouverts.fichier(Fichier::de(projection.fichier)).numero());
            let fin = projection.page + z.taille() / PAGE;
            if numero != Some(n) || fin <= premiere {
                continue;
            }
            let debut = z.debut + premiere.saturating_sub(projection.page) * PAGE;
            // Sans les tables (la zone reste), et sans réserve : le lot vide
            // à chaque tranche, une troncature retire peu de pages.
            crate::espace_utilisateur::EspaceUtilisateur::retirer_par_tranches(&m.espace, debut, z.fin, false, 0);
        }
    });
}

/// truncate(chemin, taille) : une taille négative : EINVAL ; les
/// vérifications de `vfs_truncate` (Tmpfs::verifier_tronquer).
pub fn truncate(adresse: u64, taille: u64) -> i64 {
    if (taille as i64) < 0 {
        return -EINVAL;
    }
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (qui, pid) = processus::avec(|p| (p.identite, p.pid));
    let tenu = match tenir_chemin(AT_FDCWD as u64, &chemin, true, false) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let n = match tenu.objet() {
        Objet::Tmpfs(n) => n,
        o => return vfs::avec_systeme(|s, _| refus(s, pid, qui, Modification::Tronquer(o))),
    };
    if let Err(e) = vfs::avec(|fs, _| fs.verifier_tronquer(qui, n)) {
        return errno(e);
    }
    tronquer(n, taille, tenu.fichier())
}

/// ftruncate(fd, taille) : une taille négative, EINVAL avant même le
/// descripteur (`do_sys_ftruncate`) ; O_PATH : EBADF ; un fichier ordinaire
/// ouvert en écriture, sinon EINVAL (mesuré : un descripteur en lecture
/// seule, un dossier).
pub fn ftruncate(fd: u64, taille: u64) -> i64 {
    if (taille as i64) < 0 {
        return -EINVAL;
    }
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if o.sorte == Sorte::Chemin {
        return -EBADF;
    }
    if o.sorte != Sorte::Fichier || !o.ecriture {
        return -EINVAL;
    }
    tronquer(o.numero(), taille, o.fichier)
}

/// fsync(fd) et fdatasync(fd) : tout est déjà en mémoire, rien à écrire
/// sur un disque (il viendra en 6m). Le descripteur doit exister (EBADF),
/// et ne pas être O_PATH. Puis, comme `vfs_fsync_range`, le fichier doit
/// avoir une opération fsync, sinon EINVAL. Mesuré sous Linux 6.18 : les
/// fichiers et dossiers du tmpfs en ont une (`noop_fsync`), et les
/// attributs de /sys ; pas les périphériques de /dev, ni un terminal, ni
/// un eventfd ou un epoll, ni les fichiers et dossiers de /proc, ni les
/// dossiers de /sys.
pub fn fsync(fd: u64) -> i64 {
    match tenir(fd) {
        Ok(o) => match o.sorte {
            Sorte::Chemin => -EBADF,
            Sorte::Fichier | Sorte::Noyau { lecture: Lecture::Attribut } => 0,
            Sorte::Dossier if o.objet.tmpfs().is_some() => 0,
            _ => -EINVAL,
        },
        Err(e) => e,
    }
}

/// syncfs(fd) : le système de fichiers du fichier écrit sur son disque.
/// Aucun n'en a (6m) : 0, pour tout descripteur qui n'est pas O_PATH
/// (EBADF), quelle que soit la sorte du fichier (mesuré).
pub fn syncfs(fd: u64) -> i64 {
    match tenir(fd) {
        Ok(o) if o.sorte != Sorte::Chemin => 0,
        Ok(_) => -EBADF,
        Err(e) => e,
    }
}

/// Combien des `longueur` octets à écrire à `position` d'un fichier peuvent
/// l'être (`generic_write_check_limits`) : rien à écrire, rien à vérifier ;
/// puis RLIMIT_FSIZE du programme, à partir de laquelle SIGXFSZ (au fil
/// courant) et EFBIG, et en deçà de laquelle l'écriture est coupée à elle ;
/// puis la plus grande taille de fichier (`limite_ecriture`). Pour tous les
/// chemins qui écrivent dans un fichier : write et ses voisins, et ce que le
/// noyau y écrit pour le programme (sendfile, copy_file_range). Sans
/// processus (une tâche du noyau) : pas de RLIMIT_FSIZE.
fn limites_d_ecriture(position: u64, longueur: usize) -> Result<usize, i64> {
    if longueur == 0 {
        return Ok(0);
    }
    let longueur = limite_du_programme(position, longueur as u64)? as usize;
    limite_ecriture(position, longueur).map_err(errno)
}

/// RLIMIT_FSIZE du programme (la première moitié de
/// `generic_write_check_limits`) : à partir d'elle, SIGXFSZ (au fil
/// courant) et EFBIG ; en deçà, `longueur` coupée à elle. Sans processus
/// (une tâche du noyau) : pas de limite.
fn limite_du_programme(position: u64, longueur: u64) -> Result<u64, i64> {
    let limite = processus::essayer_avec(|p| p.courante(processus::RLIMIT_FSIZE)).unwrap_or(u64::MAX);
    if limite == u64::MAX {
        return Ok(longueur);
    }
    if position >= limite {
        signaux::au_fil_courant(SIGXFSZ);
        return Err(-EFBIG);
    }
    Ok(longueur.min(limite - position))
}

/// umask(masque) : le nouveau masque (ses 9 bits de droits), rend
/// l'ancien.
pub fn umask(masque: u64) -> i64 {
    processus::avec(|p| core::mem::replace(&mut p.umask, masque as u32 & 0o777)) as i64
}

/// Change les droits de `o` (chmod et ses voisins) : Tmpfs::changer_mode,
/// ou le refus d'un système monté.
/// Les droits de `o`, tenu par le fichier ouvert `par` : IN_ATTRIB s'ils
/// ont changé (`fsnotify_change` d'ATTR_MODE), au lieu du fichier.
fn changer_mode(o: Objet, par: Fichier, mode: u64) -> i64 {
    let (qui, pid) = processus::avec(|p| (p.identite, p.pid));
    vfs::avec_systeme(|s, _| {
        let r = match o.tmpfs() {
            Some(n) => s.fs.changer_mode(qui, n, mode as u32, temps::maintenant()).map_or_else(errno, |()| 0),
            None => refus(s, pid, qui, Modification::ChangerMode(o)),
        };
        if r == 0 {
            surveillance::changement(&s.fs, s.ouverts.fichier(par), IN_ATTRIB);
        }
        r
    })
}

/// fchmodat2(dossier, chemin, droits, drapeaux) : AT_SYMLINK_NOFOLLOW
/// (changer les droits d'un lien, qui n'en a pas sous Linux : EOPNOTSUPP)
/// et AT_EMPTY_PATH ; un autre drapeau : EINVAL. fchmodat, chmod, fchmod :
/// sans drapeaux.
pub fn fchmodat2(dirfd: u64, adresse: u64, mode: u64, drapeaux: u64) -> i64 {
    if drapeaux & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let o = match tenir_chemin(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if attributs(o.objet()).mode & S_IFMT == S_IFLNK {
        return -EOPNOTSUPP;
    }
    changer_mode(o.objet(), o.fichier(), mode)
}

/// chmod(chemin, droits).
pub fn chmod(adresse: u64, mode: u64) -> i64 {
    fchmodat2(AT_FDCWD as u64, adresse, mode, 0)
}

/// fchmod(fd, droits).
pub fn fchmod(fd: u64, mode: u64) -> i64 {
    match tenir(fd) {
        Ok(o) if o.sorte != Sorte::Chemin => changer_mode(o.objet, o.fichier, mode),
        Ok(_) => -EBADF,
        Err(e) => e,
    }
}

/// Un uid ou un gid de chown : -1 (en 32 bits) veut dire « sans
/// changement ».
fn identifiant(valeur: u64) -> Option<u32> {
    (valeur as u32 != u32::MAX).then_some(valeur as u32)
}

/// Le propriétaire de `o`, tenu par le fichier ouvert `par` : IN_ATTRIB si
/// l'uid ou le gid est donné, même inchangé (`fsnotify_change` d'ATTR_UID
/// ou ATTR_GID), ou si le mode a changé (-1 et -1 d'un fichier setuid : le
/// bit tombe, ATTR_MODE ; sinon, rien : mesuré).
fn changer_proprietaire(o: Objet, par: Fichier, uid: u64, gid: u64) -> i64 {
    let (qui, pid) = processus::avec(|p| (p.identite, p.pid));
    let (uid, gid) = (identifiant(uid), identifiant(gid));
    vfs::avec_systeme(|s, _| {
        // Le mode, qui peut changer même avec -1 et -1 : les bits setuid et
        // setgid tombent (ATTR_KILL_SUID, dont `notify_change` fait un
        // ATTR_MODE).
        let mode = o.tmpfs().map(|n| s.fs.attributs(n).mode);
        let r = match o.tmpfs() {
            Some(n) => s.fs.changer_proprietaire(qui, n, uid, gid, temps::maintenant()).map_or_else(errno, |()| 0),
            None => refus(s, pid, qui, Modification::ChangerProprietaire(o, uid, gid)),
        };
        let mode_change = o.tmpfs().is_some_and(|n| Some(s.fs.attributs(n).mode) != mode);
        if r == 0 && (uid.is_some() || gid.is_some() || mode_change) {
            surveillance::changement(&s.fs, s.ouverts.fichier(par), IN_ATTRIB);
        }
        r
    })
}

/// fchownat(dossier, chemin, uid, gid, drapeaux) : Tmpfs::changer_proprietaire
/// (seul root change le propriétaire). chown suit un lien, lchown non.
pub fn fchownat(dirfd: u64, adresse: u64, uid: u64, gid: u64, drapeaux: u64) -> i64 {
    if drapeaux & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return -EINVAL;
    }
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match tenir_chemin(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(o) => changer_proprietaire(o.objet(), o.fichier(), uid, gid),
        Err(e) => e,
    }
}

/// fchown(fd, uid, gid).
pub fn fchown(fd: u64, uid: u64, gid: u64) -> i64 {
    match tenir(fd) {
        Ok(o) if o.sorte != Sorte::Chemin => changer_proprietaire(o.objet, o.fichier, uid, gid),
        Ok(_) => -EBADF,
        Err(e) => e,
    }
}

/// utimensat(dossier, chemin, dates, drapeaux) : les dates d'accès et de
/// modification (deux `struct timespec`). Pas de dates : les deux à
/// maintenant ; un tv_nsec de UTIME_NOW : maintenant, de UTIME_OMIT : sans
/// changement. Un chemin nul (pas vide : nul) désigne le descripteur
/// lui-même (futimens). Dans l'ordre de `sys_utimensat` et `do_utimes` :
///   - les dates copiées (EFAULT) ; les deux à UTIME_OMIT : rien à faire,
///     succès, sans même regarder le chemin ;
///   - un chemin nul : pas de drapeaux (EINVAL), un descripteur ouvert
///     autrement qu'O_PATH (EBADF) ; avec AT_FDCWD, c'est un chemin, que
///     l'adresse nulle rend EFAULT ;
///   - sinon : les drapeaux (EINVAL), puis le chemin ;
///   - un tv_nsec au-delà d'une seconde (ni NOW ni OMIT) : EINVAL, une fois
///     l'objet trouvé ;
///   - les droits : Tmpfs::changer_temps.
pub fn utimensat(dirfd: u64, adresse: u64, dates: u64, drapeaux: u64) -> i64 {
    use fichiers::Temps;
    use fichiers::tmpfs::Horodatage;
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;
    let mut lues = [(0i64, UTIME_NOW); 2];
    if dates != 0 {
        let mut octets = [0u8; 32];
        if copier_depuis_utilisateur(&mut octets, dates).is_err() {
            return -EFAULT;
        }
        let mot = |i: usize| i64::from_le_bytes(octets[i..i + 8].try_into().unwrap_or([0; 8]));
        lues = [(mot(0), mot(8)), (mot(16), mot(24))];
        if lues[0].1 == UTIME_OMIT && lues[1].1 == UTIME_OMIT {
            return 0;
        }
    }
    let tenu = if adresse == 0 && dirfd as i32 != AT_FDCWD {
        if drapeaux != 0 {
            return -EINVAL;
        }
        match tenir(dirfd) {
            Ok(o) if o.sorte != Sorte::Chemin => Tenue::Fichier(o),
            Ok(_) => return -EBADF,
            Err(e) => return e,
        }
    } else {
        if drapeaux & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return -EINVAL;
        }
        let chemin = match chemin(adresse) {
            Ok(c) => c,
            Err(e) => return e,
        };
        match tenir_chemin(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
            Ok(o) => Tenue::Chemin(o),
            Err(e) => return e,
        }
    };
    let (o, par) = match &tenu {
        Tenue::Fichier(f) => (f.objet, f.fichier),
        Tenue::Chemin(c) => (c.objet(), c.fichier()),
    };
    let horodatage = |(secondes, nano): (i64, i64)| match nano {
        UTIME_NOW => Some(Horodatage::Maintenant),
        UTIME_OMIT => Some(Horodatage::Garder),
        0..=999_999_999 => Some(Horodatage::Valeur(Temps { secondes, nanosecondes: nano as u32 })),
        _ => None,
    };
    let (Some(acces), Some(modification)) = (horodatage(lues[0]), horodatage(lues[1])) else {
        return -EINVAL;
    };
    let (qui, pid) = processus::avec(|p| (p.identite, p.pid));
    // Ce qu'en voit inotify (`fsnotify_change`) : les deux dates, IN_ATTRIB ;
    // l'accès seul, IN_ACCESS ; la modification seule, IN_MODIFY.
    let masque = match (acces, modification) {
        (Horodatage::Garder, _) => IN_MODIFY,
        (_, Horodatage::Garder) => IN_ACCESS,
        _ => IN_ATTRIB,
    };
    vfs::avec_systeme(|s, _| {
        let r = match o.tmpfs() {
            Some(n) => s.fs.changer_temps(qui, n, acces, modification, temps::maintenant()).map_or_else(errno, |()| 0),
            None => {
                let maintenant = matches!((acces, modification), (Horodatage::Maintenant, Horodatage::Maintenant));
                refus(s, pid, qui, Modification::ChangerTemps(o, maintenant))
            }
        };
        if r == 0 {
            surveillance::changement(&s.fs, s.ouverts.fichier(par), masque);
        }
        r
    })
}

/// Ce que tient utimensat : le fichier du descripteur (futimens), ou un
/// chemin.
enum Tenue {
    Fichier(FichierTenu),
    Chemin(CheminTenu),
}

// ----- Les transferts du noyau : fadvise64, copy_file_range, sendfile (6i) -----
//
// Trois appels que `claude -p` faisait déjà, et dont il se passait (ENOSYS) :
// Bun copie un fichier par copy_file_range, puis sendfile s'il manque, puis
// read et write ; et conseille sa lecture par fadvise64. Les deux premiers
// font passer les octets d'un fichier à l'autre sans les montrer au
// programme : par un tampon du noyau d'une page, lu par `lire_pour_le_noyau`
// et écrit par `ecrire_pour_le_noyau`, page après page. Linux le fait par
// un tube interne (`do_splice_direct`), dont les pages vont d'un fichier à
// l'autre sans copie ; le tampon fait une copie de plus (une page, une
// microseconde), et sert aussi bien un fichier, un tube, une socket ou un
// périphérique en sortie. Les vérifications et les codes d'erreur sont
// ceux de Linux 6.18 (fs/read_write.c, fs/splice.c, mm/fadvise.c), dans
// leur ordre, mesurés par linux/copies.c (sur l'hôte aussi) et par la
// relecture du plan de 6i.

/// fadvise64(fd, position, longueur, conseil) : un conseil sur la façon
/// dont le programme lira le fichier (le `generic_fadvise` de Linux). Sur
/// tmpfs, Linux n'en fait rien (pas de lecture anticipée sans disque : la
/// branche `noop_backing_dev_info`), et nous non plus ; restent ses refus :
/// un descripteur fermé, ou O_PATH : EBADF ; un tube : ESPIPE (avant tout le
/// reste) ; une longueur négative, ou un conseil inconnu (au-delà de
/// POSIX_FADV_NOREUSE, 5) : EINVAL. Une position négative est permise. Le
/// reste (une socket, un eventfd, /proc...) : 0, comme Linux.
pub fn fadvise64(fd: u64, _position: u64, longueur: u64, conseil: u64) -> i64 {
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    match o.sorte {
        Sorte::Chemin => -EBADF,
        Sorte::Tube => -ESPIPE,
        _ if (longueur as i64) < 0 || conseil as u32 > 5 => -EINVAL,
        _ => 0,
    }
}

// Les transferts dans le noyau (6i) : sendfile et copy_file_range.
//
// Linux les fait passer par un TUBE : les pages lues de l'entrée y sont
// posées (le `splice_read` de l'entrée), puis données à la sortie (son
// `splice_write`). Vers un tube, c'est celui de la sortie, et une seule
// lecture ; vers autre chose, un tube interne à la tâche, par rondes
// (`splice_direct_to_actor`). Ce qu'un programme en voit est écrit ici
// sorte par sorte, mesuré sous Linux 6.18 (les sondes de la relecture de
// 6i, que `linux/copies.c` reprend, sur l'hôte et chez nous).

/// Une position donnée a un sens (FMODE_PREAD ; sinon ESPIPE) : pas pour un
/// tube, une socket, la console (`nonseekable_open`), un eventfd, un epoll,
/// une instance d'inotify.
fn a_des_positions(o: &FichierTenu) -> bool {
    !matches!(o.sorte, Sorte::Tube | Sorte::Socket | Sorte::Console | Sorte::EventFd | Sorte::Epoll | Sorte::Inotify)
}

/// Le fichier se positionne (FMODE_LSEEK, que `splice_direct_to_actor`
/// demande à l'entrée d'un transfert qui ne va pas vers un tube, même de 0
/// octet) : tout ce qui a un llseek, `noop_llseek` compris (un eventfd, un
/// epoll, inotify : mesuré) ; pas un tube, une socket, la console.
fn se_positionne(o: &FichierTenu) -> bool {
    !matches!(o.sorte, Sorte::Tube | Sorte::Socket | Sorte::Console)
}

/// L'entrée a un `splice_read` : un fichier ordinaire (ses pages),
/// /dev/zero, /dev/full, /dev/random, /dev/urandom, la console, une valeur
/// de /proc/sys, un attribut de /sys (`copy_splice_read` : une lecture),
/// une socket. Pas un dossier, /dev/null, un tube, un eventfd, un epoll,
/// inotify, ni les séquences de /proc (maps, statm, comm, /proc/net :
/// `seq_read`, sans `read_iter`).
fn lisible_par_le_noyau(o: &FichierTenu) -> bool {
    matches!(o.sorte, Sorte::Fichier | Sorte::Zero | Sorte::Plein | Sorte::Aleatoire { .. } | Sorte::Console | Sorte::Socket
        | Sorte::Noyau { lecture: Lecture::Valeur | Lecture::Attribut })
}

/// La sortie a un `splice_write` : un fichier ordinaire, /dev/null et
/// /dev/zero (`splice_write_null`), /dev/random et /dev/urandom, la
/// console, un tube, une socket. Pas /dev/full (mesuré : EINVAL, pas
/// ENOSPC), un eventfd, un epoll, ni comm, le seul fichier de /proc qui
/// s'écrive chez nous (`.write` seulement).
fn ecrivable_par_le_noyau(o: &FichierTenu) -> bool {
    matches!(o.sorte, Sorte::Fichier | Sorte::Null | Sorte::Zero | Sorte::Aleatoire { .. } | Sorte::Console | Sorte::Tube | Sorte::Socket)
}

/// La plus grande position du système du fichier (son `s_maxbytes`) :
/// 2^31 - 1 pour /proc et /sys (MAX_NON_LFS, qu'ils ne changent pas :
/// mesuré, EOVERFLOW à la position 0x7fffffff), la plus grande taille de
/// fichier pour le reste (tmpfs, et les systèmes sans nom des tubes, des
/// sockets, des eventfd).
fn position_max(o: &FichierTenu) -> u64 {
    match o.sorte {
        Sorte::Noyau { .. } => 0x7fff_ffff,
        _ => fichiers::tmpfs::TAILLE_MAX,
    }
}

/// La position de l'entrée avance de ce qui en est lu : un fichier
/// ordinaire, une valeur de /proc/sys, un attribut de /sys ; pas /dev/zero,
/// /dev/full, /dev/random, /dev/urandom (`read_iter_zero` et
/// `get_random_bytes_user` ne la touchent pas : mesuré, une position donnée
/// revient telle quelle).
fn avance_en_lisant(o: &FichierTenu) -> bool {
    matches!(o.sorte, Sorte::Fichier | Sorte::Noyau { .. })
}

/// Lit `o` (`lisible_par_le_noyau`) à `position` dans `tampon`, du noyau,
/// comme read : un fichier ordinaire, page par page (un trou se lit en
/// zéros) ; /dev/zero et /dev/full, des zéros, un signal regardé après
/// chaque page (`read_iter_zero` : il fait rendre ce qui l'est) ;
/// /dev/random, qui attend d'être prêt (EAGAIN en O_NONBLOCK), et
/// /dev/urandom, de l'aléa (`get_random_bytes_user`) ; une valeur de
/// /proc/sys, un attribut de /sys, comme read ; la console, rien (elle
/// n'est pas encore un terminal, 6k) ; une socket, une réception. Rend ce
/// qui est lu, 0 à la fin.
fn lire_pour_le_noyau(o: &FichierTenu, position: u64, tampon: &mut [u8]) -> Result<usize, i64> {
    match o.sorte {
        Sorte::Fichier => Ok(lire_pages_noyau(o.numero(), position, tampon)),
        Sorte::Zero | Sorte::Plein => {
            let mut fait = 0;
            for morceau in tampon.chunks_mut(PAGE as usize) {
                morceau.fill(0);
                fait += morceau.len();
                if tache::signal_en_attente() {
                    break;
                }
            }
            Ok(fait)
        }
        Sorte::Aleatoire { random } => {
            if random && !aleatoire::pret() {
                if o.drapeaux as u64 & O_NONBLOCK != 0 {
                    return Err(-EAGAIN);
                }
                aleatoire::attendre_pret()?;
            } else if !random {
                aleatoire::essayer_la_gigue();
            }
            let longueur = tampon.len() as u64;
            let copier = |decalage: u64, octets: &[u8]| {
                tampon[decalage as usize..decalage as usize + octets.len()].copy_from_slice(octets);
                octets.len()
            };
            alea_vers(longueur, copier).map(|n| n as usize)
        }
        Sorte::Noyau { .. } => {
            let contenu = procfs::lire(o.fichier(), position, tampon.len() as u64)?;
            tampon[..contenu.len()].copy_from_slice(&contenu);
            Ok(contenu.len())
        }
        Sorte::Console => Ok(0),
        Sorte::Socket => crate::appels_reseau::lire_noyau(o, tampon),
        _ => Err(-EINVAL),
    }
}

/// Lit le fichier `n` à `position` dans `tampon`, page par page comme
/// `lire_pages` : un trou se lit en zéros, la fin du fichier arrête. Rend ce
/// qui est lu.
fn lire_pages_noyau(n: Numero, position: u64, tampon: &mut [u8]) -> usize {
    let mut lus = 0;
    while lus < tampon.len() {
        let ici = position + lus as u64;
        let (page, reste) = vfs::avec(|fs, _| {
            let page = fs.page(n, ici / PAGE);
            if let Some(p) = page {
                pages::prendre(p);
            }
            (page, fs.attributs(n).taille.saturating_sub(ici))
        });
        let decalage = (ici % PAGE) as usize;
        let morceau = (tampon.len() - lus).min(PAGE as usize - decalage).min(reste as usize);
        if morceau == 0 {
            if let Some(p) = page {
                pages::lacher(p);
            }
            break;
        }
        match page {
            Some(p) => {
                vfs::copier_page_vers_noyau(p, decalage, &mut tampon[lus..lus + morceau]);
                pages::lacher(p);
            }
            None => tampon[lus..lus + morceau].fill(0),
        }
        lus += morceau;
    }
    vfs::avec(|fs, _| fs.acceder(n, temps::maintenant()));
    lus
}

/// Écrit `octets`, du noyau, dans `o` (`ecrivable_par_le_noyau`, pas un
/// tube : voir `Tube::episser`), à `position` pour un fichier ordinaire,
/// comme write (une ronde du `splice_write` de Linux) : un fichier
/// ordinaire, page par page ; /dev/null et /dev/zero, dans le vide ;
/// /dev/random et /dev/urandom, mêlé au générateur, sans crédit, par blocs
/// de 64 octets, un signal regardé à chaque page (`write_pool_user` : il
/// fait rendre ce qui l'est) ; la console ; une socket, par envois
/// jusqu'à ce que tout soit parti (`splice_to_socket`, qui regarde les
/// signaux avant chacun : ERESTARTSYS si rien n'est parti), avec MSG_MORE
/// si `plus_a_venir`. Rend ce qui est écrit.
fn ecrire_pour_le_noyau(o: &FichierTenu, position: u64, octets: &[u8], plus_a_venir: bool) -> Result<usize, i64> {
    match o.sorte {
        // Chaque ronde est un write (`vfs_iter_write`) : la limite, puis les
        // bits setuid et setgid (voir `ecrire_ouvert`).
        Sorte::Fichier => {
            limites_d_ecriture(position, octets.len())?;
            if !octets.is_empty() {
                retirer_les_privileges(o.numero(), o.fichier);
            }
            ecrire_pages_noyau(o.numero(), position, octets)
        }
        Sorte::Null | Sorte::Zero => Ok(octets.len()),
        Sorte::Aleatoire { .. } => {
            let mut fait = 0;
            for bloc in octets.chunks(64) {
                aleatoire::melanger(bloc);
                fait += bloc.len();
                if fait < octets.len() && fait % PAGE as usize == 0 && tache::signal_en_attente() {
                    break;
                }
            }
            Ok(fait)
        }
        Sorte::Console => {
            console::ecrire_octets(octets);
            Ok(octets.len())
        }
        Sorte::Socket => {
            let mut fait = 0;
            while fait < octets.len() {
                if tache::signal_en_attente() {
                    return if fait > 0 { Ok(fait) } else { Err(-crate::reprise::ERESTARTSYS) };
                }
                match crate::appels_reseau::ecrire_noyau(o, &octets[fait..], plus_a_venir) {
                    r if r > 0 => fait += r as usize,
                    r if fait > 0 || r == 0 => break,
                    r => return Err(r),
                }
            }
            Ok(fait)
        }
        _ => Err(-EINVAL),
    }
}

/// Écrit `octets`, du noyau, dans le fichier `n` à `position`, page par
/// page comme `ecrire_pages` (la taille suit chaque morceau ; plus de place
/// après des octets écrits : leur nombre, avant : ENOSPC ; au-delà de la
/// plus grande taille de fichier : EFBIG).
fn ecrire_pages_noyau(n: Numero, position: u64, octets: &[u8]) -> Result<usize, i64> {
    let longueur = limites_d_ecriture(position, octets.len())?;
    let mut ecrits = 0;
    while ecrits < longueur {
        let ici = position + ecrits as u64;
        let page = vfs::avec(|fs, cadres| {
            let p = fs.page_pour_ecrire(n, ici / PAGE, cadres)?;
            pages::prendre(p);
            Ok(p)
        });
        let page = match page {
            Ok(p) => p,
            Err(e) if ecrits == 0 => return Err(errno(e)),
            Err(_) => break,
        };
        let decalage = (ici % PAGE) as usize;
        let morceau = (longueur - ecrits).min(PAGE as usize - decalage);
        vfs::copier_noyau_vers_page(page, decalage, &octets[ecrits..ecrits + morceau]);
        pages::lacher(page);
        ecrits += morceau;
        vfs::avec(|fs, _| fs.ecrit(n, position + ecrits as u64, temps::maintenant()));
    }
    Ok(ecrits)
}

/// Transfère au plus `longueur` octets de `entree`, lus à `*position` (qui
/// avance de ce qui est écrit, si `avance_en_lisant`), vers `sortie`, à
/// `vers` pour un fichier ordinaire, ni l'une ni l'autre un tube : le
/// `splice_direct_to_actor` de Linux, par le tube interne de la tâche
/// (`tube::cases_du_tube_interne`, ENOMEM), en rondes. Chaque ronde lit ce
/// que tiennent ses cases : autant de morceaux de pages d'un fichier
/// ordinaire (le premier s'arrête à la fin de sa page), autant de pages du
/// reste (une seule lecture, `copy_splice_read`) ; puis l'écrit, MSG_MORE
/// pour une socket s'il reste à lire après elle. Jusqu'à la fin de
/// l'entrée, une sortie qui ne prend plus tout, ou une erreur : avant tout
/// octet, elle (une entrée sans `splice_read`, une sortie sans
/// `splice_write` : EINVAL) ; après, ce qui est fait. Aucun signal n'arrête
/// la boucle, comme chez Linux : seules les lectures et écritures qui le
/// regardent (/dev/zero, /dev/random, une socket). Le tampon d'une ronde
/// est effacé sur tous les chemins : il a pu recevoir des pages d'un
/// fichier, ou de l'aléa. Le verrou d'écriture de la sortie est tenu tout
/// du long (celui d'un write), jamais celui de l'entrée : deux inodes
/// peuvent tomber dans le même des 64 verrous (`verrou_d_ecriture`), et la
/// tâche s'y attendrait elle-même.
fn transferer(entree: &FichierTenu, position: &mut u64, sortie: &FichierTenu, vers: u64, longueur: u64) -> Result<u64, i64> {
    let cases = crate::tube::cases_du_tube_interne()?;
    if longueur == 0 {
        return Ok(0);
    }
    let ronde = (cases as u64 * PAGE).min(longueur) as usize;
    let Ok(mut tampon) = faillible::remplie(ronde, 0u8) else { return Err(-ENOMEM) };
    let _ecriture = (sortie.sorte == Sorte::Fichier).then(|| verrou_d_ecriture(sortie.numero()));
    let pages_du_fichier = entree.sorte == Sorte::Fichier && entree.drapeaux as u64 & O_DIRECT == 0;
    let mut fait = 0u64;
    let r = loop {
        if fait >= longueur {
            break Ok(());
        }
        let reste = longueur - fait;
        let decalage = if pages_du_fichier { *position % PAGE } else { 0 };
        let n = reste.min(cases as u64 * PAGE - decalage) as usize;
        let lus = if lisible_par_le_noyau(entree) { lire_pour_le_noyau(entree, *position, &mut tampon[..n]) } else { Err(-EINVAL) };
        let lus = match lus {
            Ok(0) => break Ok(()),
            Ok(l) => l,
            Err(e) if fait == 0 => break Err(e),
            Err(_) => break Ok(()),
        };
        let ecrits = if ecrivable_par_le_noyau(sortie) {
            ecrire_pour_le_noyau(sortie, vers + fait, &tampon[..lus], (lus as u64) < reste)
        } else {
            Err(-EINVAL)
        };
        let ecrits = match ecrits {
            Ok(e) => e,
            Err(e) if fait == 0 => break Err(e),
            Err(_) => break Ok(()),
        };
        fait += ecrits as u64;
        if avance_en_lisant(entree) {
            *position += ecrits as u64;
        }
        if ecrits < lus {
            break Ok(());
        }
    };
    crypto::effacer(&mut tampon);
    r.map(|()| fait)
}

/// Pose dans un tube, par `p`, au plus `longueur` octets de `entree` lus à
/// `*position` (qui avance, si `avance_en_lisant`) : le `splice_read` de
/// l'entrée (`do_splice_read` : sans lui, EINVAL). Un fichier ordinaire :
/// ses pages elles-mêmes, une case par morceau de page, la page de zéros
/// pour un trou, jusqu'à sa fin (`shmem_file_splice_read`) ; sauf en
/// O_DIRECT, une copie (`copy_splice_read`), comme pour tout ce qui n'est
/// pas un flux. Un flux (AF_UNIX, TCP) : ce qu'il reçoit, une case par
/// morceau, coupé à la page (Linux coupe aux pages de la mémoire de ses
/// paquets, qu'un programme ne peut pas prévoir) ; non bloquant si la
/// socket l'est, ou pour AF_UNIX la sortie (`tube_non_bloquant`). Rend ce
/// qui est posé.
fn poser_dans_le_tube(entree: &FichierTenu, position: &mut u64, tube_non_bloquant: bool, p: &mut Poseur, longueur: usize) -> Result<usize, i64> {
    if !lisible_par_le_noyau(entree) {
        return Err(-EINVAL);
    }
    if entree.sorte == Sorte::Fichier && entree.drapeaux as u64 & O_DIRECT == 0 {
        return Ok(poser_les_pages(entree.numero(), position, p, longueur));
    }
    if entree.sorte == Sorte::Socket && crate::appels_reseau::s_episse(entree) {
        let poser = |_decalage: usize, octets: &[u8]| {
            if octets.is_empty() {
                return Ok(0);
            }
            let mut pris = 0;
            while pris < octets.len() && p.libres() > 0 {
                let Some(page) = Page::pour_programme() else { break };
                let n = (octets.len() - pris).min(PAGE as usize);
                p.poser_copie(page, n, |d| d.copy_from_slice(&octets[pris..pris + n]));
                pris += n;
            }
            if pris == 0 && p.libres() > 0 { Err(-ENOMEM) } else { Ok(pris) }
        };
        return crate::appels_reseau::episser(entree, longueur, tube_non_bloquant, poser);
    }
    // `copy_splice_read` : les pages d'abord, avant de rien lire (une
    // socket garde son datagramme si la mémoire manque), une lecture,
    // puis les pages remplies posées, les autres rendues.
    let n = longueur.div_ceil(PAGE as usize).min(p.libres());
    let longueur = longueur.min(n * PAGE as usize);
    let mut neuves: Vec<Page> = Vec::new();
    if neuves.try_reserve_exact(n).is_err() {
        return Err(-ENOMEM);
    }
    for _ in 0..n {
        let Some(page) = Page::pour_programme() else { return Err(-ENOMEM) };
        neuves.ajouter_dans_la_place(page);
    }
    let Ok(mut tampon) = faillible::remplie(longueur, 0u8) else { return Err(-ENOMEM) };
    let r = lire_pour_le_noyau(entree, *position, &mut tampon);
    if let Ok(lus) = r {
        for (morceau, page) in tampon[..lus].chunks(PAGE as usize).zip(neuves.drain(..)) {
            p.poser_copie(page, morceau.len(), |d| d.copy_from_slice(morceau));
        }
        if avance_en_lisant(entree) {
            *position += lus as u64;
        }
    }
    crypto::effacer(&mut tampon);
    r
}

/// Les pages du fichier `n` posées dans un tube, à partir de `*position`
/// (`shmem_file_splice_read`) : une case par morceau de page, jusqu'à
/// `longueur` octets, la fin du fichier ou des cases ; un trou, la page de
/// zéros. Rend ce qui est posé.
fn poser_les_pages(n: Numero, position: &mut u64, p: &mut Poseur, mut longueur: usize) -> usize {
    let mut fait = 0;
    while longueur > 0 && p.libres() > 0 {
        let ici = *position;
        let (page, taille) = vfs::avec(|fs, _| (fs.page(n, ici / PAGE).map(pages::Tenue::prendre), fs.attributs(n).taille));
        if ici >= taille {
            break;
        }
        let decalage = (ici % PAGE) as usize;
        let morceau = (longueur as u64).min(taille - ici).min(PAGE - decalage as u64) as usize;
        match page {
            Some(page) => p.poser_page(page, decalage, morceau),
            None => p.poser_zeros(decalage, morceau),
        }
        longueur -= morceau;
        fait += morceau;
        *position += morceau as u64;
    }
    vfs::avec(|fs, _| fs.acceder(n, temps::maintenant()));
    fait
}

/// La position de l'entrée ou de la sortie : celle que donne le programme à
/// l'adresse `adresse` (un loff_t), ou celle du fichier (0 : pas
/// d'adresse).
fn position_donnee(o: &FichierTenu, adresse: u64) -> Result<u64, i64> {
    if adresse == 0 {
        return Ok(o.position());
    }
    let mut p = [0u8; 8];
    copier_depuis_utilisateur(&mut p, adresse).map_err(|_| -EFAULT)?;
    Ok(u64::from_le_bytes(p))
}

/// copy_file_range(entrée, &position, sortie, &position, longueur,
/// drapeaux) : copie d'un fichier ordinaire à un autre, dans le noyau.
/// L'ordre de Linux 6.18 (`SYSCALL_DEFINE6(copy_file_range)`, puis
/// `vfs_copy_file_range`, `generic_copy_file_checks`), mesuré :
///   - les deux descripteurs (EBADF ; O_PATH aussi) ;
///   - les positions données lues (EFAULT), sinon celles des fichiers ;
///   - des drapeaux : EINVAL ;
///   - un dossier : EISDIR ; autre chose qu'un fichier ordinaire (un tube,
///     une socket, /dev/null) : EINVAL ; l'entrée pas en lecture, la sortie
///     pas en écriture ou en O_APPEND : EBADF ;
///   - deux systèmes de fichiers différents (un fichier de /proc) : EXDEV ;
///   - une position plus la longueur qui fait le tour, comptées sans signe :
///     EOVERFLOW (une position négative ne le fait que plus près de 0 que
///     la longueur) ;
///   - la longueur ramenée à la fin de l'entrée ;
///   - la position de la sortie, avec son signe, à la plus grande taille
///     de fichier ou au-delà : EFBIG, même pour 0 octet ; la longueur
///     ramenée à elle (`generic_write_check_limits`) ;
///   - les deux plages qui se chevauchent dans le même fichier : EINVAL ;
///   - `rw_verify_area`, pour l'entrée puis la sortie : une position
///     négative, ou plus la longueur au-delà de la plus grande : EINVAL ;
///   - rien à copier : 0 ; sinon au plus MAX_RW_COUNT, par `transferer`,
///     puis les positions avancées d'autant (rendues au programme, EFAULT
///     si on ne peut pas).
pub fn copy_file_range(fd_entree: u64, adresse_entree: u64, fd_sortie: u64, adresse_sortie: u64, longueur: u64, drapeaux: u64) -> i64 {
    let (entree, sortie) = match (tenir(fd_entree), tenir(fd_sortie)) {
        (Ok(e), Ok(s)) => (e, s),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if entree.sorte == Sorte::Chemin || sortie.sorte == Sorte::Chemin {
        return -EBADF;
    }
    let (depuis, vers) = match (position_donnee(&entree, adresse_entree), position_donnee(&sortie, adresse_sortie)) {
        (Ok(d), Ok(v)) => (d, v),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if drapeaux as u32 != 0 {
        return -EINVAL;
    }
    // `generic_file_rw_checks` : un fichier de /proc est ordinaire pour
    // Linux (S_IFREG), d'un autre système : il ira jusqu'à EXDEV.
    let ordinaire = |o: &FichierTenu| matches!(o.sorte, Sorte::Fichier | Sorte::Noyau { .. });
    if entree.sorte == Sorte::Dossier || sortie.sorte == Sorte::Dossier {
        return errno(Erreur::EISDIR);
    }
    if !ordinaire(&entree) || !ordinaire(&sortie) {
        return -EINVAL;
    }
    if !entree.lecture || !sortie.ecriture || sortie.drapeaux as u64 & O_APPEND != 0 {
        return -EBADF;
    }
    if entree.sorte != Sorte::Fichier || sortie.sorte != Sorte::Fichier {
        return -EXDEV;
    }
    if depuis.checked_add(longueur).is_none() || vers.checked_add(longueur).is_none() {
        return -EOVERFLOW;
    }
    let taille = vfs::avec(|fs, _| fs.attributs(entree.numero()).taille);
    let longueur = if depuis as i64 >= taille as i64 { 0 } else { longueur.min(taille.wrapping_sub(depuis)) };
    // RLIMIT_FSIZE, d'avance (`generic_copy_file_checks` appelle
    // `generic_write_check_limits`, même pour 0 octet) : à la limite, SIGXFSZ
    // et EFBIG ; en deçà, la copie coupée à elle, et aucune ronde de
    // `transferer` ne part de la limite (sendfile, lui, n'a pas cette coupe :
    // sa ronde suivante envoie SIGXFSZ, comme chez Linux).
    let longueur = match limite_du_programme(vers, longueur) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let max = fichiers::tmpfs::TAILLE_MAX;
    if vers as i64 >= max as i64 {
        return errno(Erreur::EFBIG);
    }
    let longueur = longueur.min(max.wrapping_sub(vers));
    if entree.numero() == sortie.numero() && vers + longueur > depuis && vers < depuis + longueur {
        return -EINVAL;
    }
    let hors = |p: u64| (p as i64) < 0 || (p as i64).checked_add(longueur as i64).is_none() || (longueur as i64) < 0;
    if hors(depuis) || hors(vers) {
        return -EINVAL;
    }
    if longueur == 0 {
        return 0;
    }
    let mut ici = depuis;
    let fait = match transferer(&entree, &mut ici, &sortie, vers, longueur.min(RW_MAX)) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if fait == 0 {
        return 0;
    }
    surveillance::apres_l_appel(&entree, IN_ACCESS);
    surveillance::apres_l_appel(&sortie, IN_MODIFY);
    let mut r = fait as i64;
    for (o, adresse, position) in [(&entree, adresse_entree, depuis + fait), (&sortie, adresse_sortie, vers + fait)] {
        if adresse == 0 {
            o.changer_position(position);
        } else if copier_vers_utilisateur(adresse, &position.to_le_bytes()).is_err() {
            r = -EFAULT;
        }
    }
    r
}

/// sendfile(sortie, entrée, &position, longueur) : envoie des octets d'un
/// fichier vers un autre, dans le noyau. L'ordre de Linux 6.18
/// (`SYSCALL_DEFINE4(sendfile64)`, puis `do_sendfile`), mesuré :
///   - la position donnée lue (EFAULT), avant même les descripteurs ;
///   - l'entrée : EBADF (aussi pas ouverte en lecture) ; une position
///     donnée, et un fichier qui n'en a pas (`a_des_positions`) : ESPIPE ;
///   - `rw_verify_area` : une longueur ou une position négative, ou leur
///     somme au-delà de la plus grande : EINVAL ; la longueur ramenée à
///     MAX_RW_COUNT ;
///   - la sortie : EBADF (aussi pas ouverte en écriture) ;
///   - la plus grande position des deux systèmes (`position_max`) : la
///     longueur ramenée à elle, et une position déjà à elle : EOVERFLOW
///     (pas pour 0 octet) ;
///   - vers un tube (`Tube::episser`) : sa place d'abord (sans lecteur :
///     SIGPIPE et EPIPE ; plein et non bloquant : EAGAIN), puis 0 octet :
///     0, puis une entrée sans `splice_read` : EINVAL ; une seule lecture,
///     au plus ce que tiennent ses cases libres (`poser_dans_le_tube`) ;
///   - vers autre chose : la position de la sortie plus la longueur
///     au-delà de la plus grande (`rw_verify_area`), O_APPEND, une entrée
///     qui ne se positionne pas (même pour 0 octet) : EINVAL ; puis les
///     rondes de `transferer` ;
///   - la position donnée rendue au programme, même après une erreur
///     (EFAULT, qui l'emporte alors) ; sans elle, celle de l'entrée avance
///     (si `avance_en_lisant`) ; celle d'une sortie ordinaire aussi.
pub fn sendfile(fd_sortie: u64, fd_entree: u64, adresse_position: u64, longueur: u64) -> i64 {
    let mut donnee = None;
    if adresse_position != 0 {
        let mut p = [0u8; 8];
        if copier_depuis_utilisateur(&mut p, adresse_position).is_err() {
            return -EFAULT;
        }
        donnee = Some(u64::from_le_bytes(p));
    }
    let mut position = donnee.unwrap_or(0);
    let r = envoyer_le_fichier(fd_sortie, fd_entree, donnee.is_some(), &mut position, longueur);
    if donnee.is_some() && copier_vers_utilisateur(adresse_position, &position.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    r
}

/// `do_sendfile` : `position` est celle que le programme a donnée
/// (`donnee`), qui avance de ce qui est envoyé ; sans elle, celle de
/// l'entrée.
fn envoyer_le_fichier(fd_sortie: u64, fd_entree: u64, donnee: bool, position: &mut u64, longueur: u64) -> i64 {
    let entree = match tenir(fd_entree) {
        Ok(o) if o.lecture => o,
        Ok(_) => return -EBADF,
        Err(e) => return e,
    };
    if donnee && !a_des_positions(&entree) {
        return -ESPIPE;
    }
    let depuis = if donnee { *position } else { entree.position() };
    if (longueur as i64) < 0 || (depuis as i64) < 0 || (depuis as i64).checked_add(longueur as i64).is_none() {
        return -EINVAL;
    }
    let mut longueur = longueur.min(RW_MAX);
    let sortie = match tenir(fd_sortie) {
        Ok(o) if o.ecriture => o,
        Ok(_) => return -EBADF,
        Err(e) => return e,
    };
    let max = position_max(&entree).min(position_max(&sortie));
    if depuis + longueur > max {
        if depuis >= max {
            return -EOVERFLOW;
        }
        longueur = max - depuis;
    }
    let mut ici = depuis;
    let vers = sortie.position();
    let fait = if sortie.sorte == Sorte::Tube {
        let non_bloquant = sortie.drapeaux as u64 & O_NONBLOCK != 0;
        let r = sortie.tube().episser(non_bloquant, longueur as usize, |p, longueur| {
            poser_dans_le_tube(&entree, &mut ici, non_bloquant, p, longueur)
        });
        if r < 0 {
            return r;
        }
        r as u64
    } else {
        if (vers as i64) < 0 || (vers as i64).checked_add(longueur as i64).is_none() {
            return -EINVAL;
        }
        if sortie.drapeaux as u64 & O_APPEND != 0 || !se_positionne(&entree) {
            return -EINVAL;
        }
        match transferer(&entree, &mut ici, &sortie, vers, longueur) {
            Ok(f) => f,
            Err(e) => return e,
        }
    };
    if fait > 0 {
        // Ce qu'en voit inotify : la lecture de l'entrée, puis l'écriture
        // de la sortie ; puis les positions, la sortie d'abord (le même
        // fichier des deux côtés : celle de l'entrée l'emporte).
        surveillance::apres_l_appel(&entree, IN_ACCESS);
        surveillance::apres_l_appel(&sortie, IN_MODIFY);
        if sortie.sorte == Sorte::Fichier {
            sortie.changer_position(vers + fait);
        }
        if donnee {
            *position = ici;
        } else {
            entree.changer_position(ici);
        }
    }
    fait as i64
}
