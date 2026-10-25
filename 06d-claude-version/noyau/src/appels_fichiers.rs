//! Les appels système des fichiers : ouvrir, lire, écrire, se déplacer,
//! décrire (stat), dupliquer, fermer. Ce que la glibc et ld-linux demandent
//! (mesuré par strace sur l'hôte, voir le plan de 6b), avec les
//! vérifications et les codes d'erreur de Linux, dans son ordre.
//!
//! Chaque appel suit le même chemin :
//!   1. copier ce que donne le programme (un chemin, un tableau d'iovec)
//!      dans un tampon du noyau, sans rien tenir ;
//!   2. sous le verrou du processus, trouver le descripteur ; sous celui
//!      des fichiers (vfs.rs), le fichier ouvert, l'inode, la page ;
//!   3. rendre les verrous, puis seulement copier entre la page et le
//!      programme : une copie peut faire une faute de page, qui prend le
//!      verrou du processus, et celui des fichiers pour une page projetée
//!      d'un fichier (memoire.rs). La page est
//!      tenue (pages::prendre) pendant la copie : elle ne peut pas
//!      disparaître sous elle, comme dans le `filemap_read` de Linux.
//! Un seul fil par programme : personne ne peut fermer un descripteur
//! pendant qu'un appel s'en sert. Avec les fils (6e), il faudra le tenir le
//! temps de l'appel (le `fdget` de Linux).

use alloc::vec::Vec;

use crate::copie_utilisateur::{
    ErreurChaine, chaine_depuis_utilisateur, copier_depuis_utilisateur, copier_depuis_utilisateur_partiel,
    copier_vers_utilisateur, copier_vers_utilisateur_partiel, dans_les_bornes,
};
use crate::descripteurs::{Descripteur, Fichier, FichierOuvert, Sorte};
use crate::vfs::{self, CadresDuNoyau, Systeme};
use crate::{aleatoire, console, pages, processus, temps};
use fichiers::chemins::{Depart, Fin, PATH_MAX, Suivre, resoudre};
use fichiers::tmpfs::{Attributs, Numero, Ouverture, limite_ecriture, suivre_pour};
use fichiers::{Erreur, PAGE, S_IFCHR, S_IFDIR, S_IFMT, S_IFREG};

// Les numéros d'erreur de Linux qui ne viennent pas du tmpfs.
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTTY: i64 = 25;
const ENOSPC: i64 = 28;
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
const O_LARGEFILE: u64 = 0o100000;
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
const RW_MAX: u64 = 0x7fff_f000;
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

/// Le descripteur `fd` du processus en cours, s'il est ouvert (EBADF).
fn descripteur(fd: u64) -> Result<Descripteur, i64> {
    processus::avec(|p| p.descripteurs.get(fd)).ok_or(-EBADF)
}

/// D'où part la résolution d'un chemin relatif, pour un appel *at :
/// le dossier courant (AT_FDCWD) ou celui du descripteur `dirfd` (qui doit
/// en être un : ENOTDIR). Un chemin absolu ignore `dirfd`, même invalide,
/// comme Linux.
fn depart(dirfd: u64, chemin: &[u8]) -> Result<Depart<Numero>, i64> {
    let (racine, courant, qui) = processus::avec(|p| (p.racine, p.dossier, p.identite));
    let dossier = if chemin.first() == Some(&b'/') || dirfd as i32 == AT_FDCWD {
        courant
    } else {
        let d = descripteur(dirfd)?;
        vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).ouvert.numero)
    };
    Ok(Depart { racine, dossier, qui, sous: false })
}

/// Résout `chemin` (non vide) depuis `dirfd`, sous le verrou des fichiers,
/// et appelle `f` avec le résultat.
fn avec_fin<R>(dirfd: u64, chemin: &[u8], suivre: Suivre,
               f: impl FnOnce(&mut Systeme, &mut CadresDuNoyau, Fin<Numero>, Depart<Numero>) -> Result<R, i64>) -> Result<R, i64> {
    let depart = depart(dirfd, chemin)?;
    vfs::avec_systeme(|s, cadres| {
        let fin = resoudre(&s.fs, &depart, chemin, suivre).map_err(errno)?;
        f(s, cadres, fin, depart)
    })
}

/// L'objet désigné par `chemin` depuis `dirfd`, qui doit exister (stat,
/// access...). Avec AT_EMPTY_PATH, un chemin vide désigne `dirfd`
/// lui-même.
fn objet(dirfd: u64, chemin: &[u8], suivre: bool, vide_permis: bool) -> Result<Numero, i64> {
    if chemin.is_empty() {
        if !vide_permis {
            return Err(errno(Erreur::ENOENT));
        }
        if dirfd as i32 == AT_FDCWD {
            return Ok(processus::avec(|p| p.dossier));
        }
        let d = descripteur(dirfd)?;
        return Ok(vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).ouvert.numero));
    }
    let depart = depart(dirfd, chemin)?;
    vfs::avec(|fs, _| fichiers::chemins::trouver(fs, &depart, chemin, suivre)).map_err(errno)
}

/// La sorte d'un fichier qu'on ouvre, d'après son inode : ses opérations.
/// Un périphérique sans pilote : ENXIO, comme Linux.
fn sorte(mode: u32, rdev: (u32, u32)) -> Result<Sorte, i64> {
    Ok(match mode & S_IFMT {
        S_IFREG => Sorte::Fichier,
        S_IFDIR => Sorte::Dossier,
        S_IFCHR => match rdev {
            vfs::NULL => Sorte::Null,
            vfs::ZERO => Sorte::Zero,
            vfs::FULL => Sorte::Plein,
            vfs::RANDOM | vfs::URANDOM => Sorte::Aleatoire,
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
    vfs::avec_systeme(|s, cadres| {
        let racine = s.fs.racine();
        let depart = Depart { racine, dossier: racine, qui, sous: false };
        let fin = resoudre(&s.fs, &depart, chemin, Suivre::Toujours)?;
        let o = Ouverture { lecture, ecriture, dossier, ..Ouverture::default() };
        let ouvert = s.fs.ouvrir(qui, &fin, &o, temps::maintenant())?;
        let a = s.fs.attributs(ouvert.numero);
        let Ok(sorte) = sorte(a.mode, a.rdev) else {
            s.fs.fermer(&ouvert, cadres);
            return Err(Erreur::ENXIO);
        };
        let drapeaux = O_LARGEFILE
            | if ecriture && lecture { 2 } else if ecriture { O_WRONLY } else { O_RDONLY }
            | if dossier { O_DIRECTORY } else { 0 };
        s.ouverts.ajouter(FichierOuvert::new(sorte, ouvert, lecture, ecriture, drapeaux as u32, chemin)).map_err(|f| {
            s.fs.fermer(&f.ouvert, cadres);
            Erreur::ENOMEM
        })
    })
}

/// Le fichier que désigne `chemin`, absolu, depuis la racine, résolu comme
/// `execve` le ferait pour `qui` (liens suivis, droit de traverser chaque
/// dossier, ENOTDIR pour une barre finale après autre chose qu'un
/// dossier). L'inode est tenu une fois : à lâcher après usage.
pub fn trouver_pour(qui: fichiers::Identite, chemin: &[u8]) -> Result<Numero, Erreur> {
    vfs::avec(|fs, _| {
        let racine = fs.racine();
        let depart = Depart { racine, dossier: racine, qui, sous: false };
        let n = fichiers::chemins::trouver(fs, &depart, chemin, true)?;
        fs.prendre(n);
        Ok(n)
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
///   - le numéro de descripteur : plus de numéro libre, EMFILE, avant de
///     résoudre le chemin (open("absent/x") rend EMFILE, mesuré) ;
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
    let fd = processus::avec(|p| p.descripteurs.libre(0)).ok_or(-EMFILE)?;
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
    let fichier = avec_fin(dirfd, &chemin, suivre_pour(&o, drapeaux & O_NOFOLLOW != 0), |s, cadres, fin, depart| {
        let ouvert = s.fs.ouvrir(depart.qui, &fin, &o, maintenant).map_err(errno)?;
        let a = s.fs.attributs(ouvert.numero);
        let sorte = match if chemin_seul { Ok(Sorte::Chemin) } else { sorte(a.mode, a.rdev) } {
            Ok(sorte) => sorte,
            Err(e) => {
                s.fs.fermer(&ouvert, cadres);
                return Err(e);
            }
        };
        // Ce que rendra F_GETFL : les drapeaux d'état, O_LARGEFILE toujours
        // (un noyau 64 bits l'impose), sauf pour O_PATH, dont Linux ne garde
        // que les drapeaux d'O_PATH ; pas ceux qui ne servent qu'à open.
        let largefile = if chemin_seul { 0 } else { O_LARGEFILE };
        let gardes = (drapeaux & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC)) | largefile;
        let fichier = s.ouverts.ajouter(FichierOuvert::new(sorte, ouvert, o.lecture, o.ecriture, gardes as u32, &chemin))
            .map_err(|f| {
                s.fs.fermer(&f.ouvert, cadres);
                -ENOMEM
            })?;
        Ok((fichier, ouvert))
    })?;
    let (fichier, ouvert) = fichier;
    // O_TRUNC, hors du verrou des fichiers : il faut d'abord retirer les
    // pages des projections, sous celui du processus (`tronquer`). Le
    // fichier est ouvert : vider ne peut plus échouer (une taille nulle
    // n'est jamais trop grande).
    if ouvert.tronquer {
        tronquer(ouvert.numero, 0);
    }
    let d = Descripteur { fichier, fermer_a_l_exec: drapeaux & O_CLOEXEC != 0 };
    if processus::avec(|p| p.descripteurs.installer(fd, d)).is_err() {
        vfs::avec_systeme(|s, cadres| s.lacher(fichier, cadres));
        return Err(-ENOMEM);
    }
    Ok(fd)
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
    let d = processus::avec(|p| p.descripteurs.retirer(fd)).ok_or(-EBADF)?;
    vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
    Ok(())
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
/// CLOSE_RANGE_UNSHARE (ne plus partager la table, après un clone) : sans
/// objet avec un seul fil.
pub fn close_range(premier: u64, dernier: u64, drapeaux: u64) -> i64 {
    const CLOSE_RANGE_UNSHARE: u64 = 1 << 1;
    const CLOSE_RANGE_CLOEXEC: u64 = 1 << 2;
    let (premier, dernier) = (premier as u32 as u64, dernier as u32 as u64);
    if drapeaux & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || premier > dernier {
        return -EINVAL;
    }
    let ouverts: Vec<u64> = match processus::avec(|p| {
        let mut v = Vec::new();
        v.try_reserve(p.descripteurs.ouverts(premier, dernier).count()).ok()?;
        v.extend(p.descripteurs.ouverts(premier, dernier));
        Some(v)
    }) {
        Some(v) => v,
        None => return -ENOMEM,
    };
    for fd in ouverts {
        if drapeaux & CLOSE_RANGE_CLOEXEC != 0 {
            processus::avec(|p| p.descripteurs.get_mut(fd).map(|d| d.fermer_a_l_exec = true));
        } else {
            let _ = fermer_descripteur(fd);
        }
    }
    0
}

/// Ce qu'un appel de lecture ou d'écriture doit savoir du fichier ouvert.
#[derive(Clone, Copy)]
struct Ouvert {
    fichier: Fichier,
    sorte: Sorte,
    numero: Numero,
    lecture: bool,
    ecriture: bool,
    drapeaux: u32,
    position: u64,
}

fn ouvert(fd: u64) -> Result<Ouvert, i64> {
    let d = descripteur(fd)?;
    Ok(vfs::avec_systeme(|s, _| {
        let f = s.ouverts.fichier(d.fichier);
        Ouvert {
            fichier: d.fichier,
            sorte: f.sorte,
            numero: f.ouvert.numero,
            lecture: f.lecture,
            ecriture: f.ecriture,
            drapeaux: f.drapeaux,
            position: f.position,
        }
    }))
}

fn changer_position(f: Fichier, position: u64) {
    vfs::avec_systeme(|s, _| s.ouverts.fichier(f).position = position);
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
        let source = match page {
            Some(p) => &vfs::octets(p)[decalage..decalage + morceau],
            None => &ZEROS[..morceau],
        };
        let copies = copier_vers_utilisateur_partiel(tampon + lus, source);
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
    let longueur = limite_ecriture(position, longueur as usize).map_err(errno)? as u64;
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
        let copies = copier_depuis_utilisateur_partiel(&mut vfs::octets_mut(page)[decalage..decalage + morceau], tampon + ecrits);
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

/// Remplit `longueur` octets du programme à `tampon` avec `remplir`, par
/// morceaux de 256 octets (des zéros, de l'aléa). Une faute : ce qui a été
/// copié, ou EFAULT si rien.
fn produire(tampon: u64, longueur: u64, mut remplir: impl FnMut(&mut [u8])) -> Result<u64, i64> {
    let mut fait = 0;
    let mut morceau = [0u8; 256];
    while fait < longueur {
        let n = (longueur - fait).min(morceau.len() as u64) as usize;
        remplir(&mut morceau[..n]);
        let copies = copier_vers_utilisateur_partiel(tampon + fait, &morceau[..n]);
        fait += copies as u64;
        if copies < n {
            return if fait == 0 { Err(-EFAULT) } else { Ok(fait) };
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
/// la position du fichier, `None`).
fn lire_ouvert(o: &Ouvert, position: Option<u64>, tampon: u64, longueur: u64) -> Result<u64, i64> {
    if !o.lecture {
        return Err(-EBADF);
    }
    let longueur = verifier_transfert(tampon, longueur, position.unwrap_or(o.position))?;
    match o.sorte {
        Sorte::Fichier => {
            let lus = lire_pages(o.numero, position.unwrap_or(o.position), tampon, longueur)?;
            if position.is_none() {
                changer_position(o.fichier, o.position + lus);
            }
            Ok(lus)
        }
        Sorte::Dossier => Err(errno(Erreur::EISDIR)),
        Sorte::Console if position.is_some() => Err(-ESPIPE),
        // La console n'est pas encore un terminal (6j) : rien à lire.
        Sorte::Null | Sorte::Console => Ok(0),
        Sorte::Zero | Sorte::Plein => produire(tampon, longueur, |m| m.fill(0)),
        Sorte::Aleatoire => produire(tampon, longueur, aleatoire::remplir),
        Sorte::Chemin => Err(-EBADF),
    }
}

/// Écrire, selon la sorte du fichier.
fn ecrire_ouvert(o: &Ouvert, position: Option<u64>, tampon: u64, longueur: u64) -> Result<u64, i64> {
    if !o.ecriture {
        return Err(-EBADF);
    }
    let longueur = verifier_transfert(tampon, longueur, position.unwrap_or(o.position))?;
    match o.sorte {
        Sorte::Fichier => {
            // O_APPEND : toujours à la fin, même pour pwrite (une
            // bizarrerie de Linux, que décrit sa page de manuel).
            let fin = vfs::avec(|fs, _| fs.attributs(o.numero).taille);
            let ici = if o.drapeaux as u64 & O_APPEND != 0 { fin } else { position.unwrap_or(o.position) };
            let ecrits = ecrire_pages(o.numero, ici, tampon, longueur)?;
            if position.is_none() {
                changer_position(o.fichier, ici + ecrits);
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
        // Linux). L'aléa écrit dans /dev/random ne nourrit rien : notre
        // générateur n'a pas encore de réserve à brasser (6h).
        Sorte::Null | Sorte::Zero | Sorte::Aleatoire => Ok(longueur),
        Sorte::Plein => Err(-ENOSPC),
        Sorte::Dossier | Sorte::Chemin => Err(-EBADF),
    }
}

fn resultat(r: Result<u64, i64>) -> i64 {
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// read(fd, tampon, longueur).
pub fn read(fd: u64, tampon: u64, longueur: u64) -> i64 {
    resultat(ouvert(fd).and_then(|o| lire_ouvert(&o, None, tampon, longueur)))
}

/// write(fd, tampon, longueur).
pub fn write(fd: u64, tampon: u64, longueur: u64) -> i64 {
    resultat(ouvert(fd).and_then(|o| ecrire_ouvert(&o, None, tampon, longueur)))
}

/// pread64(fd, tampon, longueur, position) : sans bouger la position.
/// Position négative : EINVAL, avant même de regarder le descripteur
/// (`ksys_pread64`) ; un fichier sans position (la console) : ESPIPE.
pub fn pread64(fd: u64, tampon: u64, longueur: u64, position: u64) -> i64 {
    if (position as i64) < 0 {
        return -EINVAL;
    }
    resultat(ouvert(fd).and_then(|o| lire_ouvert(&o, Some(position), tampon, longueur)))
}

/// pwrite64(fd, tampon, longueur, position).
pub fn pwrite64(fd: u64, tampon: u64, longueur: u64, position: u64) -> i64 {
    if (position as i64) < 0 {
        return -EINVAL;
    }
    resultat(ouvert(fd).and_then(|o| ecrire_ouvert(&o, Some(position), tampon, longueur)))
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
fn morceaux(adresse: u64, nombre: u64) -> Result<Vec<(u64, u64)>, i64> {
    if nombre > 1024 {
        return Err(-EINVAL);
    }
    let mut octets = Vec::new();
    octets.try_reserve_exact(nombre as usize * 16).map_err(|_| -ENOMEM)?;
    octets.resize(nombre as usize * 16, 0);
    copier_depuis_utilisateur(&mut octets, adresse).map_err(|_| -EFAULT)?;
    let mut v = Vec::new();
    v.try_reserve_exact(nombre as usize).map_err(|_| -ENOMEM)?;
    for c in octets.chunks_exact(16) {
        let base = u64::from_le_bytes(c[..8].try_into().unwrap_or([0; 8]));
        let longueur = u64::from_le_bytes(c[8..].try_into().unwrap_or([0; 8]));
        if (longueur as i64) < 0 {
            return Err(-EINVAL);
        }
        v.push((base, longueur));
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
    let o = match ouvert(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if (ecrire && !o.ecriture) || (!ecrire && !o.lecture) {
        return -EBADF;
    }
    let morceaux = match morceaux(adresse, nombre) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let mut total = 0u64;
    for (base, longueur) in morceaux {
        if longueur == 0 {
            continue;
        }
        // La position a pu bouger avec le morceau précédent.
        let o = match ouvert(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let r = if ecrire { ecrire_ouvert(&o, None, base, longueur) } else { lire_ouvert(&o, None, base, longueur) };
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
    let o = match ouvert(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let depuis = depuis as u32 as u64;
    if depuis > SEEK_HOLE {
        return -EINVAL;
    }
    let decalage = decalage as i64;
    let nouvelle = match (o.sorte, depuis) {
        (Sorte::Chemin, _) => return -EBADF,
        (Sorte::Console, _) => return -ESPIPE,
        (Sorte::Null | Sorte::Zero | Sorte::Plein | Sorte::Aleatoire, _) => return 0,
        (_, SEEK_SET) => Some(decalage),
        (_, SEEK_CUR) => (o.position as i64).checked_add(decalage),
        (Sorte::Fichier, SEEK_END) => {
            let taille = vfs::avec(|fs, _| fs.attributs(o.numero).taille) as i64;
            taille.checked_add(decalage)
        }
        (Sorte::Fichier, SEEK_DATA | SEEK_HOLE) => {
            if decalage < 0 {
                return errno(Erreur::ENXIO);
            }
            match vfs::avec(|fs, _| fs.chercher(o.numero, decalage as u64, depuis == SEEK_DATA)) {
                Ok(p) => Some(p as i64),
                Err(e) => return errno(e),
            }
        }
        _ => return -EINVAL,
    };
    match nouvelle {
        Some(p) if p >= 0 => {
            changer_position(o.fichier, p as u64);
            p
        }
        _ => -EINVAL,
    }
}

/// Ce que mmap doit savoir du fichier du descripteur `fd` : le fichier
/// ouvert, sa sorte, et s'il a été ouvert en lecture et en écriture. Un
/// descripteur invalide ou O_PATH : EBADF (le `fget` de Linux ne rend pas
/// les fichiers O_PATH).
pub struct PourProjeter {
    pub fichier: Fichier,
    pub sorte: Sorte,
    pub lecture: bool,
    pub ecriture: bool,
}

pub fn pour_projeter(fd: u64) -> Result<PourProjeter, i64> {
    let o = ouvert(fd)?;
    if o.sorte == Sorte::Chemin {
        return Err(-EBADF);
    }
    Ok(PourProjeter { fichier: o.fichier, sorte: o.sorte, lecture: o.lecture, ecriture: o.ecriture })
}

/// La « struct stat » de Linux sur x86_64 (144 octets), d'après les
/// attributs d'un inode. Le système de fichiers de la racine est le
/// périphérique 0:20 (un numéro anonyme, comme ceux que Linux donne aux
/// tmpfs).
fn stat_linux(a: &Attributs) -> [u8; 144] {
    let mut s = [0u8; 144];
    let mut mettre = |position: usize, valeur: u64, taille: usize| {
        s[position..position + taille].copy_from_slice(&valeur.to_le_bytes()[..taille]);
    };
    mettre(0, encoder_peripherique(DEV_RACINE), 8); // st_dev
    mettre(8, a.numero.0 as u64, 8); // st_ino
    mettre(16, a.nlink as u64, 8); // st_nlink
    mettre(24, a.mode as u64, 4); // st_mode
    mettre(28, a.uid as u64, 4); // st_uid
    mettre(32, a.gid as u64, 4); // st_gid
    mettre(40, encoder_peripherique(a.rdev), 8); // st_rdev
    mettre(48, a.taille, 8); // st_size
    mettre(56, TAILLE_DE_BLOC, 8); // st_blksize
    mettre(64, a.blocs, 8); // st_blocks
    for (position, t) in [(72, a.atime), (88, a.mtime), (104, a.ctime)] {
        mettre(position, t.secondes as u64, 8);
        mettre(position + 8, t.nanosecondes as u64, 8);
    }
    s
}

/// Le périphérique du système de fichiers de la racine.
const DEV_RACINE: (u32, u32) = (0, 20);

/// Majeur et mineur dans un st_dev (le `new_encode_dev` de Linux : le
/// mineur sur 20 bits, coupé autour du majeur, pour rester compatible avec
/// les vieux numéros sur 16 bits).
fn encoder_peripherique((majeur, mineur): (u32, u32)) -> u64 {
    ((mineur & 0xff) | (majeur << 8) | ((mineur & !0xff) << 12)) as u64
}

/// La taille de bloc « préférée » pour les entrées-sorties (st_blksize) :
/// une page, pour tout ce qu'on a, périphériques compris (/dev/null,
/// /dev/console : 4096 sous Linux ; seuls les pseudo-terminaux de /dev/pts
/// disent 1024). La glibc en tire la taille du tampon de stdout.
const TAILLE_DE_BLOC: u64 = PAGE;

fn ecrire_stat(n: Numero, adresse: u64) -> i64 {
    let s = stat_linux(&vfs::avec(|fs, _| fs.attributs(n)));
    match copier_vers_utilisateur(adresse, &s) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// fstat(fd, stat). Un descripteur O_PATH convient.
pub fn fstat(fd: u64, adresse: u64) -> i64 {
    match descripteur(fd) {
        Ok(d) => ecrire_stat(vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).ouvert.numero), adresse),
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
        Ok(n) => ecrire_stat(n, stat),
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
    let n = match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let a = vfs::avec(|fs, _| fs.attributs(n));
    let mut s = [0u8; 256];
    let mut mettre = |position: usize, valeur: u64, taille: usize| {
        s[position..position + taille].copy_from_slice(&valeur.to_le_bytes()[..taille]);
    };
    mettre(0, STATX_BASIC_STATS as u64, 4); // stx_mask
    mettre(4, TAILLE_DE_BLOC, 4); // stx_blksize
    mettre(16, a.nlink as u64, 4);
    mettre(20, a.uid as u64, 4);
    mettre(24, a.gid as u64, 4);
    mettre(28, a.mode as u64, 2);
    mettre(32, a.numero.0 as u64, 8);
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
    mettre(136, DEV_RACINE.0 as u64, 4);
    mettre(140, DEV_RACINE.1 as u64, 4);
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
    let n = match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let qui = processus::avec(|p| p.identite);
    match vfs::avec(|fs, _| fs.acces(qui, n, droits as u32)) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

/// access(chemin, droits), faccessat(dossier, chemin, droits).
pub fn access(adresse: u64, droits: u64) -> i64 {
    faccessat2(AT_FDCWD as u64, adresse, droits, 0)
}

/// Installe un second descripteur pour le fichier de `d`, au numéro `fd`
/// : le fichier est tenu une fois de plus. Si `fd` était ouvert, il est
/// remplacé d'un coup, puis son fichier lâché (le `do_dup2` de Linux) : pas
/// d'instant où le numéro est libre, et si la table ne peut pas grandir
/// (ENOMEM), l'ancien reste ouvert.
fn installer_copie(d: Descripteur, fd: u64, fermer_a_l_exec: bool) -> i64 {
    vfs::avec_systeme(|s, _| s.ouverts.prendre(d.fichier));
    let copie = Descripteur { fichier: d.fichier, fermer_a_l_exec };
    match processus::avec(|p| p.descripteurs.remplacer(fd, copie)) {
        Ok(ancien) => {
            if let Some(ancien) = ancien {
                vfs::avec_systeme(|s, cadres| s.lacher(ancien.fichier, cadres));
            }
            fd as i64
        }
        Err(()) => {
            vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
            -ENOMEM
        }
    }
}

/// dup(fd) : le plus petit numéro libre.
pub fn dup(fd: u64) -> i64 {
    let d = match descripteur(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    match processus::avec(|p| p.descripteurs.libre(0)) {
        Some(nouveau) => installer_copie(d, nouveau, false),
        None => -EMFILE,
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
    let d = match descripteur(ancien) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if nouveau >= processus::avec(|p| p.descripteurs.limite.0) {
        return -EBADF;
    }
    installer_copie(d, nouveau, drapeaux & O_CLOEXEC != 0)
}

/// dup2(ancien, nouveau).
pub fn dup2(ancien: u64, nouveau: u64) -> i64 {
    if ancien as u32 == nouveau as u32 {
        return match descripteur(ancien) {
            Ok(_) => nouveau as u32 as i64,
            Err(e) => e,
        };
    }
    dup3(ancien, nouveau, 0)
}

/// fcntl(fd, commande, argument). Les commandes :
///   - F_DUPFD, F_DUPFD_CLOEXEC : dup, au plus petit numéro libre à partir
///     de `argument` ; un argument au-delà de la limite : EINVAL ; plus de
///     numéro libre au-dessus : EMFILE ;
///   - F_GETFD, F_SETFD : le drapeau FD_CLOEXEC ;
///   - F_GETFL : le mode d'ouverture et les drapeaux d'état ; F_SETFL :
///     seuls O_APPEND et O_NONBLOCK (et O_ASYNC, O_DIRECT, O_NOATIME, sans
///     effet ici) changent, le reste est ignoré, comme Linux ;
///   - F_GETLK, F_SETLK, F_SETLKW et leurs versions « OFD » : les verrous
///     de fichiers (`verrou_posix`). Avec un seul processus, personne ne
///     peut gêner : poser réussit toujours, et F_GETLK répond « rien ne
///     bloque » (l_type = F_UNLCK), une fois la demande vérifiée ;
///   - le reste : EINVAL.
/// Sur un descripteur O_PATH, seules F_DUPFD*, F_GETFD, F_SETFD et F_GETFL
/// sont permises (EBADF sinon).
pub fn fcntl(fd: u64, commande: u64, argument: u64) -> i64 {
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
    const FD_CLOEXEC: u64 = 1;
    const CHANGEABLES: u64 = O_APPEND | O_NONBLOCK | 0o20000 | 0o40000 | 0o1000000;
    let d = match descripteur(fd) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let chemin_seul = vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).sorte == Sorte::Chemin);
    if chemin_seul && !matches!(commande, F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL) {
        return -EBADF;
    }
    match commande {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let (minimum, limite) = (argument as u32 as u64, processus::avec(|p| p.descripteurs.limite.0));
            if minimum >= limite {
                return -EINVAL;
            }
            match processus::avec(|p| p.descripteurs.libre(minimum)) {
                Some(nouveau) => installer_copie(d, nouveau, commande == F_DUPFD_CLOEXEC),
                None => -EMFILE,
            }
        }
        F_GETFD => d.fermer_a_l_exec as i64,
        F_SETFD => {
            processus::avec(|p| p.descripteurs.get_mut(fd).map(|d| d.fermer_a_l_exec = argument & FD_CLOEXEC != 0));
            0
        }
        F_GETFL => vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).drapeaux) as i64,
        F_SETFL => {
            vfs::avec_systeme(|s, _| {
                let f = s.ouverts.fichier(d.fichier);
                f.drapeaux = ((f.drapeaux as u64 & !CHANGEABLES) | (argument & CHANGEABLES)) as u32;
            });
            0
        }
        F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => {
            verrou_posix(fd, argument, false, matches!(commande, F_OFD_SETLK | F_OFD_SETLKW))
        }
        F_GETLK | F_OFD_GETLK => verrou_posix(fd, argument, true, commande == F_OFD_GETLK),
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
/// Puis, sans autre processus pour gêner : poser réussit, F_GETLK répond
/// F_UNLCK (le reste de la structure inchangé, comme Linux).
fn verrou_posix(fd: u64, adresse: u64, demander: bool, ofd: bool) -> i64 {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    const EOVERFLOW: i64 = 75;
    let o = match ouvert(fd) {
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
        1 => o.position as i64,
        2 if o.sorte == Sorte::Fichier => vfs::avec(|fs, _| fs.attributs(o.numero).taille) as i64,
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

/// flock(fd, opération) : un verrou sur tout le fichier. Avec un seul
/// processus, il est toujours accordé. Une opération inconnue : EINVAL ; un
/// descripteur O_PATH : EBADF.
pub fn flock(fd: u64, operation: u64) -> i64 {
    const LOCK_SH: u64 = 1;
    const LOCK_EX: u64 = 2;
    const LOCK_NB: u64 = 4;
    const LOCK_UN: u64 = 8;
    let o = match ouvert(fd) {
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
///   - FIONREAD, pour un fichier ordinaire seulement : de la position à la
///     fin, en `int` (négatif si la position est au-delà : Linux ne borne
///     pas) ; pour le reste, c'est au pilote d'y répondre, et aucun des
///     nôtres ne le fait : ENOTTY (un terminal le fera, 6j) ;
///   - les requêtes des terminaux (TCGETS, la question d'isatty, et les
///     autres) : ENOTTY, la console n'en est pas encore un (6j). La glibc
///     met alors la sortie standard dans un tampon complet, vidé à la
///     sortie.
pub fn ioctl(fd: u64, requete: u64, argument: u64) -> i64 {
    const FIONCLEX: u64 = 0x5450;
    const FIOCLEX: u64 = 0x5451;
    const FIONBIO: u64 = 0x5421;
    const FIONREAD: u64 = 0x541b;
    let o = match ouvert(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if o.sorte == Sorte::Chemin {
        return -EBADF;
    }
    match requete as u32 as u64 {
        FIOCLEX | FIONCLEX => {
            processus::avec(|p| p.descripteurs.get_mut(fd).map(|d| d.fermer_a_l_exec = requete as u32 as u64 == FIOCLEX));
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
        FIONREAD if o.sorte == Sorte::Fichier => {
            let taille = vfs::avec(|fs, _| fs.attributs(o.numero).taille);
            let reste = (taille as i64).wrapping_sub(o.position as i64) as i32;
            match copier_vers_utilisateur(argument, &reste.to_le_bytes()) {
                Ok(()) => 0,
                Err(_) => -EFAULT,
            }
        }
        _ => -ENOTTY,
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
    let r = avec_fin(dirfd, &chemin, Suivre::Jamais, |s, cadres, fin, depart| {
        s.fs.effacer(depart.qui, &fin, drapeaux & AT_REMOVEDIR != 0, maintenant, cadres).map_err(errno)
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

/// Ouvre en lecture l'inode `n` (de chemin `chemin`, et de sorte `sorte`),
/// pour le noyau : le programme à exécuter, que ses zones projetteront (le
/// `bprm->file` de Linux), ou le dossier pré-ouvert d'un programme WASI.
/// Rend le fichier ouvert, tenu une fois.
pub fn ouvrir_inode(n: Numero, chemin: &[u8], sorte: Sorte) -> Result<Fichier, Erreur> {
    vfs::avec_systeme(|s, cadres| {
        s.fs.prendre(n);
        let ouvert = fichiers::tmpfs::Ouvert { numero: n, cree: false, tronquer: false, ecrivain: false };
        let fichier = FichierOuvert::new(sorte, ouvert, true, false, (O_RDONLY | O_LARGEFILE) as u32, chemin);
        s.ouverts.ajouter(fichier).map_err(|f| {
            s.fs.fermer(&f.ouvert, cadres);
            Erreur::ENOMEM
        })
    })
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
        if descripteurs.installer(fd, Descripteur { fichier: console, fermer_a_l_exec: false }).is_err() {
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
    let r = avec_fin(dirfd, &chemin, Suivre::Jamais, |s, _, fin, depart| {
        s.fs.creer(depart.qui, &fin, S_IFDIR | droits, (0, 0), &[], temps::maintenant()).map_err(errno)
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
    let r = avec_fin(dirfd, &chemin, Suivre::Jamais, |s, _, fin, depart| {
        s.fs.creer(depart.qui, &fin, fichiers::S_IFLNK | 0o777, (0, 0), &cible, temps::maintenant()).map_err(errno)
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
    let n = match objet(dirfd, &chemin, false, true) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let vide = chemin.is_empty();
    let contenu = vfs::avec(|fs, _| -> Result<Vec<u8>, i64> {
        let cible = fs.lire_lien(n).map_err(|e| if vide { errno(Erreur::ENOENT) } else { errno(e) })?;
        let mut copie = Vec::new();
        copie.try_reserve_exact(cible.len()).map_err(|_| -ENOMEM)?;
        copie.extend_from_slice(cible);
        fs.acceder(n, temps::maintenant());
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
    let r = avec_fin(nouveau_dossier, &nouveau, Suivre::Jamais, |s, _, fin, depart| {
        s.fs.lier(depart.qui, source, &fin, temps::maintenant()).map_err(errno)
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
    let (depart_ancien, depart_nouveau) = match (depart(ancien_dossier, &ancien), depart(nouveau_dossier, &nouveau)) {
        (Ok(a), Ok(n)) => (a, n),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let r = vfs::avec_systeme(|s, cadres| {
        let fa = resoudre(&s.fs, &depart_ancien, &ancien, Suivre::Jamais)?;
        let fn_ = resoudre(&s.fs, &depart_nouveau, &nouveau, Suivre::Jamais)?;
        s.fs.renommer(depart_ancien.qui, &fa, &fn_, drapeaux as u32, temps::maintenant(), cadres)
    });
    match r {
        Ok(()) => 0,
        Err(e) => errno(e),
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
    let o = match ouvert(fd) {
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
    let mut entrees = Vec::new();
    if entrees.try_reserve_exact(taille).is_err() {
        return -ENOMEM;
    }
    let mut position = o.position;
    let lu = vfs::avec(|fs, _| {
        let r = fs.lire_dossier(o.numero, o.position, |nom, n, genre, suivante| {
            let longueur = (8 + 8 + 2 + 1 + nom.len() + 1).next_multiple_of(8);
            if entrees.len() + longueur > taille {
                return false;
            }
            entrees.extend_from_slice(&(n.0 as u64).to_le_bytes());
            entrees.extend_from_slice(&suivante.to_le_bytes());
            entrees.extend_from_slice(&(longueur as u16).to_le_bytes());
            entrees.push(genre);
            entrees.extend_from_slice(nom);
            entrees.resize(entrees.len() + longueur - (19 + nom.len()), 0);
            position = suivante;
            true
        });
        fs.acceder(o.numero, temps::maintenant());
        r
    });
    if let Err(e) = lu {
        return errno(e);
    }
    if entrees.is_empty() {
        // Fin du dossier, ou la première entrée ne tient pas : on les
        // distingue en regardant s'il restait une entrée à lire.
        let reste = vfs::avec(|fs, _| {
            let mut une = false;
            let _ = fs.lire_dossier(o.numero, o.position, |_, _, _, _| {
                une = true;
                false
            });
            une
        });
        return if reste { -EINVAL } else { 0 };
    }
    if copier_vers_utilisateur(tampon, &entrees).is_err() {
        return -EFAULT;
    }
    changer_position(o.fichier, position);
    entrees.len() as i64
}

/// getcwd(tampon, taille) : le chemin du dossier courant, avec son zéro
/// final ; rend sa longueur, zéro compris. Trop petit : ERANGE ; un dossier
/// courant effacé : ENOENT.
pub fn getcwd(tampon: u64, taille: u64) -> i64 {
    let dossier = processus::avec(|p| p.dossier);
    let mut chemin = match vfs::avec(|fs, _| fs.chemin(dossier)) {
        Ok(c) => c,
        Err(e) => return errno(e),
    };
    if chemin.try_reserve_exact(1).is_err() {
        return -ENOMEM;
    }
    chemin.push(0);
    if (taille as usize) < chemin.len() {
        return -ERANGE;
    }
    match copier_vers_utilisateur(tampon, &chemin) {
        Ok(()) => chemin.len() as i64,
        Err(_) => -EFAULT,
    }
}

/// Le dossier `n` devient le dossier courant : un dossier (ENOTDIR) qu'on
/// a le droit de traverser (EACCES), comme `set_fs_pwd` après la
/// vérification de chdir.
fn changer_de_dossier(n: Numero) -> i64 {
    let qui = processus::avec(|p| p.identite);
    let r = vfs::avec(|fs, _| {
        if fs.mode(n) & S_IFMT != S_IFDIR {
            return Err(Erreur::ENOTDIR);
        }
        fs.acces(qui, n, fichiers::EXECUTER)?;
        fs.prendre(n);
        Ok(())
    });
    if let Err(e) = r {
        return errno(e);
    }
    let ancien = processus::avec(|p| core::mem::replace(&mut p.dossier, n));
    vfs::avec(|fs, cadres| fs.lacher(ancien, cadres));
    0
}

/// chdir(chemin).
pub fn chdir(adresse: u64) -> i64 {
    let chemin = match chemin(adresse) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match objet(AT_FDCWD as u64, &chemin, true, false) {
        Ok(n) => changer_de_dossier(n),
        Err(e) => e,
    }
}

/// fchdir(fd).
pub fn fchdir(fd: u64) -> i64 {
    match ouvert(fd) {
        Ok(o) => changer_de_dossier(o.numero),
        Err(e) => e,
    }
}

/// Ramène le fichier `n` à `taille` octets.
///
/// Les pages qui disparaissent sont d'abord retirées des projections du
/// processus, copies privées comprises (mesuré sous Linux : une page
/// copiée puis le fichier raccourci et rallongé se relit à zéro), comme
/// `truncate_pagecache` : un accès au-delà de la nouvelle fin fera SIGBUS.
/// Le tmpfs ne lâche ses pages qu'ensuite. Il faudrait le faire dans
/// chaque processus qui projette le fichier (la carte inverse `i_mmap` de
/// Linux) : avec un seul processus à la fois, c'est le processus en cours
/// (à généraliser avec l'ordonnanceur, 6e).
fn tronquer(n: Numero, taille: u64) -> i64 {
    retirer_projections(n, taille.div_ceil(PAGE));
    match vfs::avec(|fs, cadres| fs.tronquer(n, taille, temps::maintenant(), cadres)) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}

/// Retire des projections du processus en cours les pages du fichier `n`
/// de numéro `premiere` ou plus (le `unmap_mapping_range` de Linux, copies
/// comprises). Les zones restent : un accès y refera une faute.
fn retirer_projections(n: Numero, premiere: u64) {
    processus::essayer_avec(|p| {
        let m = &mut p.memoire;
        let mut i = 0;
        while let Some(z) = m.zones.zones().get(i).copied() {
            i += 1;
            let Some(projection) = z.fichier else { continue };
            let numero = vfs::avec_systeme(|s, _| s.ouverts.fichier(Fichier::de(projection.fichier)).ouvert.numero);
            let fin = projection.page + z.taille() / PAGE;
            if numero != n || fin <= premiere {
                continue;
            }
            let debut = z.debut + premiere.saturating_sub(projection.page) * PAGE;
            m.espace.retirer_plage(debut, z.fin, false);
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
    let n = match objet(AT_FDCWD as u64, &chemin, true, false) {
        Ok(n) => n,
        Err(e) => return e,
    };
    let qui = processus::avec(|p| p.identite);
    if let Err(e) = vfs::avec(|fs, _| fs.verifier_tronquer(qui, n)) {
        return errno(e);
    }
    tronquer(n, taille)
}

/// ftruncate(fd, taille) : une taille négative, EINVAL avant même le
/// descripteur (`do_sys_ftruncate`) ; O_PATH : EBADF ; un fichier ordinaire
/// ouvert en écriture, sinon EINVAL (mesuré : un descripteur en lecture
/// seule, un dossier).
pub fn ftruncate(fd: u64, taille: u64) -> i64 {
    if (taille as i64) < 0 {
        return -EINVAL;
    }
    let o = match ouvert(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if o.sorte == Sorte::Chemin {
        return -EBADF;
    }
    if o.sorte != Sorte::Fichier || !o.ecriture {
        return -EINVAL;
    }
    tronquer(o.numero, taille)
}

/// fsync(fd) et fdatasync(fd) : tout est déjà en mémoire, rien à écrire
/// sur un disque (il viendra en 6l). Le descripteur doit exister (EBADF),
/// et ne pas être O_PATH. Puis, comme `vfs_fsync_range`, le fichier doit
/// avoir une opération fsync, sinon EINVAL. Mesuré sous Linux 6.18 : les
/// fichiers et dossiers du tmpfs en ont une (`noop_fsync`) ; pas les
/// périphériques de /dev, ni un terminal.
pub fn fsync(fd: u64) -> i64 {
    match ouvert(fd) {
        Ok(o) => match o.sorte {
            Sorte::Chemin => -EBADF,
            Sorte::Fichier | Sorte::Dossier => 0,
            _ => -EINVAL,
        },
        Err(e) => e,
    }
}

/// syncfs(fd) : le système de fichiers du fichier écrit sur son disque.
/// Aucun n'en a (6l) : 0, pour tout descripteur qui n'est pas O_PATH
/// (EBADF), quelle que soit la sorte du fichier (mesuré).
pub fn syncfs(fd: u64) -> i64 {
    match ouvert(fd) {
        Ok(o) if o.sorte != Sorte::Chemin => 0,
        Ok(_) => -EBADF,
        Err(e) => e,
    }
}

/// umask(masque) : le nouveau masque (ses 9 bits de droits), rend
/// l'ancien.
pub fn umask(masque: u64) -> i64 {
    processus::avec(|p| core::mem::replace(&mut p.umask, masque as u32 & 0o777)) as i64
}

/// Change les droits de `n` (chmod et ses voisins) : Tmpfs::changer_mode.
fn changer_mode(n: Numero, mode: u64) -> i64 {
    let qui = processus::avec(|p| p.identite);
    match vfs::avec(|fs, _| fs.changer_mode(qui, n, mode as u32, temps::maintenant())) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
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
    let n = match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if vfs::avec(|fs, _| fs.mode(n) & S_IFMT) == fichiers::S_IFLNK {
        return -EOPNOTSUPP;
    }
    changer_mode(n, mode)
}

/// chmod(chemin, droits).
pub fn chmod(adresse: u64, mode: u64) -> i64 {
    fchmodat2(AT_FDCWD as u64, adresse, mode, 0)
}

/// fchmod(fd, droits).
pub fn fchmod(fd: u64, mode: u64) -> i64 {
    match ouvert(fd) {
        Ok(o) if o.sorte != Sorte::Chemin => changer_mode(o.numero, mode),
        Ok(_) => -EBADF,
        Err(e) => e,
    }
}

/// Un uid ou un gid de chown : -1 (en 32 bits) veut dire « sans
/// changement ».
fn identifiant(valeur: u64) -> Option<u32> {
    (valeur as u32 != u32::MAX).then_some(valeur as u32)
}

fn changer_proprietaire(n: Numero, uid: u64, gid: u64) -> i64 {
    let qui = processus::avec(|p| p.identite);
    match vfs::avec(|fs, _| fs.changer_proprietaire(qui, n, identifiant(uid), identifiant(gid), temps::maintenant())) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
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
    match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
        Ok(n) => changer_proprietaire(n, uid, gid),
        Err(e) => e,
    }
}

/// fchown(fd, uid, gid).
pub fn fchown(fd: u64, uid: u64, gid: u64) -> i64 {
    match ouvert(fd) {
        Ok(o) if o.sorte != Sorte::Chemin => changer_proprietaire(o.numero, uid, gid),
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
    let n = if adresse == 0 && dirfd as i32 != AT_FDCWD {
        if drapeaux != 0 {
            return -EINVAL;
        }
        match ouvert(dirfd) {
            Ok(o) if o.sorte != Sorte::Chemin => o.numero,
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
        match objet(dirfd, &chemin, drapeaux & AT_SYMLINK_NOFOLLOW == 0, drapeaux & AT_EMPTY_PATH != 0) {
            Ok(n) => n,
            Err(e) => return e,
        }
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
    let qui = processus::avec(|p| p.identite);
    match vfs::avec(|fs, _| fs.changer_temps(qui, n, acces, modification, temps::maintenant())) {
        Ok(()) => 0,
        Err(e) => errno(e),
    }
}
