//! Les appels système de Linux : ce que le noyau offre aux programmes
//! Linux (la « couche de compatibilité », voir CLAUDE.md).
//!
//! Un programme demande un service par son NUMÉRO, celui de Linux sur
//! x86_64 (arch/x86/entry/syscalls/syscall_64.tbl), avec jusqu'à six
//! arguments, et reçoit un nombre : le résultat, ou une erreur, codée
//! comme -errno (-14 pour EFAULT, par exemple). La glibc le transforme en
//! -1 et range le code dans errno.
//!
//! Ce qu'il faut à un programme C compilé avec `gcc -static` (la glibc
//! 2.39 d'Ubuntu 24.04), mesuré par strace sur la machine hôte, dans
//! l'ordre : brk, arch_prctl(ARCH_SET_FS), set_tid_address,
//! set_robust_list, rseq, prlimit64(RLIMIT_STACK), readlinkat
//! ("/proc/self/exe"), getrandom, brk, mprotect (RELRO), fstat(1), write,
//! exit_group. Plus writev (les messages d'erreur fatale de la glibc),
//! ioctl(TCGETS) (isatty), et exit ; et, pour la mémoire de `claude`
//! (6a), mmap, munmap et madvise (de la mémoire anonyme), sysinfo ; et
//! l'heure (6b) : clock_gettime, clock_getres, gettimeofday, time ; et les
//! fichiers (6b), dans appels_fichiers.rs.
//!
//! Le reste rend -ENOSYS (« appel non implémenté »), comme Linux pour un
//! numéro qu'il ne connaît pas, et le noyau le signale. `make trace`
//! construit un noyau qui affiche chaque appel à la façon de strace, pour
//! comparer avec strace sur l'hôte.
//!
//! Les numéros de fichier sont des `unsigned int` pour Linux : on n'en
//! regarde que les 32 bits bas, comme lui.

use core::fmt;

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::espace_utilisateur::ADRESSE_MAX;
use crate::interruptions::Cadre;
use crate::memoire::{self, Acces, ECART_GARDE, Echec, ZoneDuCode, engagement_possible};
use zones::{Drapeaux, Droits, Nature, Projection, Zone};
use crate::appels_fichiers as f;
use crate::{aleatoire, cpu, horloge, pages, processus, tache, temps};

// Les numéros d'erreur de Linux (include/uapi/asm-generic/errno-base.h).
const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const ENODEV: i64 = 19;
const EOVERFLOW: i64 = 75;

// Les numéros des appels.
const FSYNC: u64 = 74;
const FDATASYNC: u64 = 75;
const TRUNCATE: u64 = 76;
const FTRUNCATE: u64 = 77;
const GETCWD: u64 = 79;
const CHDIR: u64 = 80;
const FCHDIR: u64 = 81;
const RENAME: u64 = 82;
const MKDIR: u64 = 83;
const LINK: u64 = 86;
const SYMLINK: u64 = 88;
const READLINK: u64 = 89;
const CHMOD: u64 = 90;
const FCHMOD: u64 = 91;
const CHOWN: u64 = 92;
const FCHOWN: u64 = 93;
const LCHOWN: u64 = 94;
const UMASK: u64 = 95;
const SYNC: u64 = 162;
const GETDENTS64: u64 = 217;
const MKDIRAT: u64 = 258;
const FCHOWNAT: u64 = 260;
const RENAMEAT: u64 = 264;
const LINKAT: u64 = 265;
const SYMLINKAT: u64 = 266;
const FCHMODAT: u64 = 268;
const UTIMENSAT: u64 = 280;
const SYNCFS: u64 = 306;
const RENAMEAT2: u64 = 316;
const FCHMODAT2: u64 = 452;
const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const CLOSE: u64 = 3;
const STAT: u64 = 4;
const FSTAT: u64 = 5;
const LSTAT: u64 = 6;
const LSEEK: u64 = 8;
const MMAP: u64 = 9;
const MPROTECT: u64 = 10;
const MUNMAP: u64 = 11;
const MADVISE: u64 = 28;
const BRK: u64 = 12;
const IOCTL: u64 = 16;
const PREAD64: u64 = 17;
const PWRITE64: u64 = 18;
const READV: u64 = 19;
const WRITEV: u64 = 20;
const ACCESS: u64 = 21;
const DUP: u64 = 32;
const DUP2: u64 = 33;
const GETPID: u64 = 39;
const EXIT: u64 = 60;
const FCNTL: u64 = 72;
const FLOCK: u64 = 73;
const RMDIR: u64 = 84;
const CREAT: u64 = 85;
const UNLINK: u64 = 87;
const GETTIMEOFDAY: u64 = 96;
const SYSINFO: u64 = 99;
const GETUID: u64 = 102;
const GETGID: u64 = 104;
const GETEUID: u64 = 107;
const GETEGID: u64 = 108;
const GETPPID: u64 = 110;
const GETTID: u64 = 186;
const ARCH_PRCTL: u64 = 158;
const TIME: u64 = 201;
const SET_TID_ADDRESS: u64 = 218;
const CLOCK_GETTIME: u64 = 228;
const CLOCK_GETRES: u64 = 229;
const EXIT_GROUP: u64 = 231;
const OPENAT: u64 = 257;
const NEWFSTATAT: u64 = 262;
const UNLINKAT: u64 = 263;
const READLINKAT: u64 = 267;
const FACCESSAT: u64 = 269;
const DUP3: u64 = 292;
const STATX: u64 = 332;
const CLOSE_RANGE: u64 = 436;
const FACCESSAT2: u64 = 439;
const SET_ROBUST_LIST: u64 = 273;
const PRLIMIT64: u64 = 302;
const GETRANDOM: u64 = 318;
const RSEQ: u64 = 334;

const PAGE: u64 = 4096;


/// Le numéro de processus et de fil du programme : 1, le premier (et le
/// seul) processus. (set_tid_address rend le numéro du fil appelant.)
const PID: i64 = 1;

/// Exécute l'appel système `numero` : un résultat, ou -errno.
pub fn appel(numero: u64, a: [u64; 6]) -> i64 {
    let resultat = match numero {
        READ => f::read(a[0], a[1], a[2]),
        WRITE => f::write(a[0], a[1], a[2]),
        OPEN => f::open(a[0], a[1], a[2]),
        OPENAT => f::openat(a[0], a[1], a[2], a[3]),
        CREAT => f::creat(a[0], a[1]),
        CLOSE => f::close(a[0]),
        CLOSE_RANGE => f::close_range(a[0], a[1], a[2]),
        STAT => f::stat(a[0], a[1], true),
        LSTAT => f::stat(a[0], a[1], false),
        FSTAT => f::fstat(a[0], a[1]),
        NEWFSTATAT => f::newfstatat(a[0], a[1], a[2], a[3]),
        STATX => f::statx(a[0], a[1], a[2], a[3], a[4]),
        LSEEK => f::lseek(a[0], a[1], a[2]),
        PREAD64 => f::pread64(a[0], a[1], a[2], a[3]),
        PWRITE64 => f::pwrite64(a[0], a[1], a[2], a[3]),
        READV => f::readv(a[0], a[1], a[2]),
        WRITEV => f::writev(a[0], a[1], a[2]),
        ACCESS => f::access(a[0], a[1]),
        FACCESSAT => f::faccessat2(a[0], a[1], a[2], 0),
        FACCESSAT2 => f::faccessat2(a[0], a[1], a[2], a[3]),
        DUP => f::dup(a[0]),
        DUP2 => f::dup2(a[0], a[1]),
        DUP3 => f::dup3(a[0], a[1], a[2]),
        FCNTL => f::fcntl(a[0], a[1], a[2]),
        FLOCK => f::flock(a[0], a[1]),
        IOCTL => f::ioctl(a[0], a[1], a[2]),
        UNLINK => f::unlink(a[0]),
        UNLINKAT => f::unlinkat(a[0], a[1], a[2]),
        RMDIR => f::rmdir(a[0]),
        BRK => brk(a[0]),
        MMAP => mmap(a[0], a[1], a[2], a[3], a[4], a[5]),
        MUNMAP => munmap(a[0], a[1]),
        MPROTECT => mprotect(a[0], a[1], a[2]),
        MADVISE => madvise(a[0], a[1], a[2]),
        ARCH_PRCTL => arch_prctl(a[0], a[1]),
        // L'adresse où effacer le numéro du fil quand il se termine (pour
        // pthread_join) : sans fils, rien à faire ; on rend le numéro du fil.
        SET_TID_ADDRESS => PID,
        // La liste des verrous « robustes » du fil (relâchés s'il meurt en
        // les tenant) : sans fils, rien à faire. La taille de la tête de
        // liste est fixée par l'ABI (24 octets) ; Linux refuse les autres.
        SET_ROBUST_LIST => if a[1] == 24 { 0 } else { -EINVAL },
        // Les « séquences redémarrables » : une optimisation des compteurs
        // par processeur. La glibc s'en passe si le noyau ne l'a pas.
        RSEQ => -ENOSYS,
        PRLIMIT64 => prlimit64(a[0], a[1], a[2], a[3]),
        // La glibc lit le lien /proc/self/exe pour connaître son propre
        // chemin (dl_get_origin) : /proc viendra en 6d, ENOENT d'ici là.
        READLINKAT => f::readlinkat(a[0], a[1], a[2], a[3]),
        READLINK => f::readlink(a[0], a[1], a[2]),
        MKDIR => f::mkdir(a[0], a[1]),
        MKDIRAT => f::mkdirat(a[0], a[1], a[2]),
        SYMLINK => f::symlink(a[0], a[1]),
        SYMLINKAT => f::symlinkat(a[0], a[1], a[2]),
        LINK => f::link(a[0], a[1]),
        LINKAT => f::linkat(a[0], a[1], a[2], a[3], a[4]),
        RENAME => f::rename(a[0], a[1]),
        RENAMEAT => f::renameat2(a[0], a[1], a[2], a[3], 0),
        RENAMEAT2 => f::renameat2(a[0], a[1], a[2], a[3], a[4]),
        GETDENTS64 => f::getdents64(a[0], a[1], a[2]),
        GETCWD => f::getcwd(a[0], a[1]),
        CHDIR => f::chdir(a[0]),
        FCHDIR => f::fchdir(a[0]),
        TRUNCATE => f::truncate(a[0], a[1]),
        FTRUNCATE => f::ftruncate(a[0], a[1]),
        FSYNC | FDATASYNC | SYNCFS => f::fsync(a[0]),
        SYNC => 0,
        UMASK => f::umask(a[0]),
        CHMOD => f::chmod(a[0], a[1]),
        FCHMOD => f::fchmod(a[0], a[1]),
        FCHMODAT => f::fchmodat2(a[0], a[1], a[2], 0),
        FCHMODAT2 => f::fchmodat2(a[0], a[1], a[2], a[3]),
        CHOWN => f::fchownat(-100i64 as u64, a[0], a[1], a[2], 0),
        LCHOWN => f::fchownat(-100i64 as u64, a[0], a[1], a[2], 0x100),
        FCHOWN => f::fchown(a[0], a[1], a[2]),
        FCHOWNAT => f::fchownat(a[0], a[1], a[2], a[3], a[4]),
        UTIMENSAT => f::utimensat(a[0], a[1], a[2], a[3]),
        GETRANDOM => getrandom(a[0], a[1], a[2]),
        SYSINFO => sysinfo(a[0]),
        // Qui est le programme : le processus 1, le seul (son parent, le
        // noyau, n'a pas de numéro : 0, comme le parent de l'init de
        // Linux), un seul fil, l'utilisateur et le groupe 1000.
        GETPID | GETTID => PID,
        GETPPID => 0,
        GETUID | GETEUID => processus::avec(|p| p.identite.uid) as i64,
        GETGID | GETEGID => processus::avec(|p| p.identite.gid) as i64,
        CLOCK_GETTIME => clock_gettime(a[0], a[1]),
        CLOCK_GETRES => clock_getres(a[0], a[1]),
        GETTIMEOFDAY => gettimeofday(a[0], a[1]),
        TIME => time(a[0]),
        // Le code de sortie tient sur 8 bits : Linux ne garde que l'octet
        // bas (exit(256) rend 0, exit(-1) rend 255), ce que verra le futur
        // wait ; les codes 128 + N restent ceux des signaux.
        EXIT | EXIT_GROUP => {
            tracer(numero, a, None);
            tache::terminer((a[0] & 0xff) as i32)
        }
        _ => {
            afficherln!("[noyau] appel systeme inconnu : {}", numero);
            -ENOSYS
        }
    };
    tracer(numero, a, Some(resultat));
    resultat
}

/// Avec la fonctionnalité `trace` (make trace) : affiche l'appel, ses
/// arguments et son résultat, comme strace. (`None` : l'appel ne revient
/// pas.)
fn tracer(numero: u64, a: [u64; 6], resultat: Option<i64>) {
    if !cfg!(feature = "trace") {
        return;
    }
    let (nom, n) = match numero {
        READ => ("read", 3),
        WRITE => ("write", 3),
        OPEN => ("open", 3),
        OPENAT => ("openat", 4),
        CREAT => ("creat", 2),
        CLOSE => ("close", 1),
        CLOSE_RANGE => ("close_range", 3),
        STAT => ("stat", 2),
        LSTAT => ("lstat", 2),
        FSTAT => ("fstat", 2),
        NEWFSTATAT => ("newfstatat", 4),
        STATX => ("statx", 5),
        LSEEK => ("lseek", 3),
        PREAD64 => ("pread64", 4),
        PWRITE64 => ("pwrite64", 4),
        READV => ("readv", 3),
        WRITEV => ("writev", 3),
        ACCESS => ("access", 2),
        FACCESSAT => ("faccessat", 3),
        FACCESSAT2 => ("faccessat2", 4),
        DUP => ("dup", 1),
        DUP2 => ("dup2", 2),
        DUP3 => ("dup3", 3),
        FCNTL => ("fcntl", 3),
        FLOCK => ("flock", 2),
        IOCTL => ("ioctl", 3),
        UNLINK => ("unlink", 1),
        UNLINKAT => ("unlinkat", 3),
        RMDIR => ("rmdir", 1),
        BRK => ("brk", 1),
        MMAP => ("mmap", 6),
        MUNMAP => ("munmap", 2),
        MPROTECT => ("mprotect", 3),
        MADVISE => ("madvise", 3),
        ARCH_PRCTL => ("arch_prctl", 2),
        SET_TID_ADDRESS => ("set_tid_address", 1),
        SET_ROBUST_LIST => ("set_robust_list", 2),
        RSEQ => ("rseq", 4),
        PRLIMIT64 => ("prlimit64", 4),
        READLINKAT => ("readlinkat", 4),
        READLINK => ("readlink", 3),
        MKDIR => ("mkdir", 2),
        MKDIRAT => ("mkdirat", 3),
        SYMLINK => ("symlink", 2),
        SYMLINKAT => ("symlinkat", 3),
        LINK => ("link", 2),
        LINKAT => ("linkat", 5),
        RENAME => ("rename", 2),
        RENAMEAT => ("renameat", 4),
        RENAMEAT2 => ("renameat2", 5),
        GETDENTS64 => ("getdents64", 3),
        GETCWD => ("getcwd", 2),
        CHDIR => ("chdir", 1),
        FCHDIR => ("fchdir", 1),
        TRUNCATE => ("truncate", 2),
        FTRUNCATE => ("ftruncate", 2),
        FSYNC => ("fsync", 1),
        FDATASYNC => ("fdatasync", 1),
        SYNCFS => ("syncfs", 1),
        SYNC => ("sync", 0),
        UMASK => ("umask", 1),
        CHMOD => ("chmod", 2),
        FCHMOD => ("fchmod", 2),
        FCHMODAT => ("fchmodat", 3),
        FCHMODAT2 => ("fchmodat2", 4),
        CHOWN => ("chown", 3),
        LCHOWN => ("lchown", 3),
        FCHOWN => ("fchown", 3),
        FCHOWNAT => ("fchownat", 5),
        UTIMENSAT => ("utimensat", 4),
        GETRANDOM => ("getrandom", 3),
        SYSINFO => ("sysinfo", 1),
        GETPID => ("getpid", 0),
        GETTID => ("gettid", 0),
        GETPPID => ("getppid", 0),
        GETUID => ("getuid", 0),
        GETEUID => ("geteuid", 0),
        GETGID => ("getgid", 0),
        GETEGID => ("getegid", 0),
        CLOCK_GETTIME => ("clock_gettime", 2),
        CLOCK_GETRES => ("clock_getres", 2),
        GETTIMEOFDAY => ("gettimeofday", 2),
        TIME => ("time", 1),
        EXIT => ("exit", 1),
        EXIT_GROUP => ("exit_group", 1),
        _ => ("?", 6),
    };
    afficher!("[trace] {}(", nom);
    for (i, x) in a[..n].iter().enumerate() {
        afficher!("{}{:#x}", if i > 0 { ", " } else { "" }, x);
    }
    match resultat {
        None => afficherln!(") = ?"),
        Some(r) if r < 0 => afficherln!(") = -1 (errno {})", -r),
        Some(r) => afficherln!(") = {:#x}", r),
    }
}

/// brk(adresse) : déplace la fin du tas, à l'octet près : la zone du tas
/// (memoire.rs) grandit ou recule. Rend la nouvelle fin, ou l'ancienne en
/// cas d'échec (c'est ainsi que Linux signale l'erreur ; brk(0) demande
/// donc la fin actuelle). Le tas ne peut ni reculer sous son début, ni
/// s'approcher à moins d'une page de la zone suivante (de plus l'écart de
/// garde si c'est la pile, comme Linux). Une extension plus grande que
/// toute la mémoire est refusée (memoire::engagement_possible) ; le reste
/// est promis, et ses pages ne viennent qu'à la faute.
///
/// Rien n'est mis à zéro d'avance : agrandir le tas ne coûte que la zone.
/// Le reculer rend les pages que le programme avait touchées, verrou du
/// processus tenu, donc interruptions coupées : une page rendue prend une
/// centaine de nanosecondes. Avec l'ordonnanceur, ce verrou deviendra un
/// verrou qui dort (le mmap_lock de Linux).
fn brk(demande: u64) -> i64 {
    processus::avec(|p| {
        let m = &mut p.memoire;
        let actuelle = m.fin_tas as i64;
        if demande < m.debut_tas || demande >= ADRESSE_MAX {
            return actuelle;
        }
        let (pages_avant, pages_apres) = (m.fin_tas.next_multiple_of(PAGE), demande.next_multiple_of(PAGE));
        if pages_apres > pages_avant {
            let zone = Zone {
                debut: pages_avant,
                fin: pages_apres,
                droits: Droits { lecture: true, ecriture: true, execution: false },
                nature: Nature::Tas,
                drapeaux: Drapeaux::default(),
                fichier: None,
            };
            // La zone se fond dans celle du tas.
            if !engagement_possible(pages_apres - pages_avant)
                || !m.zones.libre(pages_avant, pages_apres + PAGE, ECART_GARDE)
                || m.zones.inserer(zone, &mut memoire::references).is_err()
            {
                return actuelle;
            }
        } else if pages_apres < pages_avant && m.retirer(pages_apres, pages_avant).is_err() {
            return actuelle;
        }
        m.fin_tas = demande;
        demande as i64
    })
}

/// Les droits demandés par `prot` (mmap, mprotect).
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;

fn droits_de(prot: u64) -> Droits {
    Droits { lecture: prot & PROT_READ != 0, ecriture: prot & PROT_WRITE != 0, execution: prot & PROT_EXEC != 0 }
}

/// mmap(adresse, longueur, droits, drapeaux, fichier, décalage) : une
/// nouvelle zone, de mémoire anonyme ou d'un fichier projeté en privé (6b).
/// Ses pages ne viennent qu'à la faute (memoire.rs) ; celles d'un fichier
/// sont ses pages à lui, en lecture seule, copiées à la première écriture
/// (espace_utilisateur.rs). Les codes d'erreur sont ceux de Linux, vérifiés
/// par linux/memoire.c et linux/fichiers.c, qui tournent aussi sur l'hôte :
///   - décalage non aligné : EINVAL ; pas de MAP_ANONYMOUS, et un
///     descripteur qui n'en est pas un (ou O_PATH) : EBADF ; longueur nulle,
///     ni MAP_PRIVATE ni MAP_SHARED : EINVAL ; trop grand : ENOMEM ; la page
///     du fichier plus la longueur au-delà de la plus grande taille de
///     fichier : EOVERFLOW ;
///   - MAP_FIXED : l'adresse telle quelle, ce qui y était est retiré
///     (tout ou rien). Hors des adresses : ENOMEM ; non alignée : EINVAL ;
///     sous 64 Kio : EPERM. MAP_FIXED_NOREPLACE : de même, mais EEXIST si
///     quelque chose y est déjà ;
///   - un fichier : il faut l'avoir ouvert en lecture (EACCES), et que sa
///     sorte se projette : un fichier ordinaire ; /dev/zero en privé donne
///     de la mémoire anonyme, comme Linux ; un dossier, /dev/null, la
///     console : ENODEV. Un décalage au-delà de la fin du fichier est
///     permis : l'accès fera SIGBUS ;
///   - sinon, une adresse suggérée est suivie si la place est libre,
///     ignorée sinon (Memoire::chercher_place) ; plus de place : ENOMEM ;
///   - une zone privée inscriptible sans MAP_NORESERVE plus grande que
///     toute la mémoire : ENOMEM (le surengagement, memoire.rs) ; trop de
///     zones : ENOMEM ;
///   - MAP_POPULATE : les pages sont mises en place d'avance, au mieux (un
///     échec est ignoré, comme dans Linux : la faute le redira) ;
///   - MAP_STACK, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_LOCKED, MAP_NONBLOCK
///     et les drapeaux inconnus : sans effet, comme Linux (sans mémoire
///     d'échange, toute page est de fait « verrouillée » ; Linux ignore
///     les drapeaux qu'il ne connaît pas, sauf avec MAP_SHARED_VALIDATE).
///     Les droits inconnus aussi : mmap, au contraire de mprotect, ne les
///     vérifie pas ;
///   - MAP_SHARED (après ses vérifications de droits : écrire demande un
///     descripteur ouvert en écriture, EACCES), MAP_GROWSDOWN, MAP_HUGETLB,
///     MAP_32BIT, MAP_SYNC : refusés (EINVAL), avec un message du noyau qui
///     le dit ; `claude` ne s'en sert pas, fork (6k) en aura besoin.
fn mmap(adresse: u64, longueur: u64, prot: u64, drapeaux: u64, fd: u64, decalage: u64) -> i64 {
    const MAP_SHARED: u64 = 0x01;
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_TYPE: u64 = 0x0f;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    const MAP_32BIT: u64 = 0x40;
    const MAP_GROWSDOWN: u64 = 0x100;
    const MAP_NORESERVE: u64 = 0x4000;
    const MAP_POPULATE: u64 = 0x8000;
    const MAP_HUGETLB: u64 = 0x4_0000;
    const MAP_SYNC: u64 = 0x8_0000;
    const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
    use crate::descripteurs::Sorte;
    use crate::espace_utilisateur::ADRESSE_MIN;

    if decalage % PAGE != 0 {
        return -EINVAL;
    }
    // Le fichier projeté, s'il y en a un (fget, avant même la longueur).
    let fichier = if drapeaux & MAP_ANONYMOUS == 0 {
        match f::pour_projeter(fd) {
            Ok(p) => Some(p),
            Err(e) => return e,
        }
    } else {
        None
    };
    if longueur == 0 {
        return -EINVAL;
    }
    let partagee = match drapeaux & MAP_TYPE {
        MAP_PRIVATE => false,
        MAP_SHARED | 0x03 => true,
        _ => return -EINVAL,
    };
    for (bit, nom) in [(MAP_GROWSDOWN, "MAP_GROWSDOWN"), (MAP_HUGETLB, "MAP_HUGETLB"), (MAP_32BIT, "MAP_32BIT"), (MAP_SYNC, "MAP_SYNC")] {
        if drapeaux & bit != 0 {
            afficherln!("[noyau] mmap : {} pas pris en charge", nom);
            return -EINVAL;
        }
    }
    let Some(taille) = longueur.checked_next_multiple_of(PAGE).filter(|&t| t <= ADRESSE_MAX - ADRESSE_MIN) else {
        return -ENOMEM;
    };
    let page = decalage / PAGE;
    // La fin de la projection sous la plus grande taille de fichier, 2^63 - 1
    // octets (`file_mmap_ok`) : sa dernière page est au plus la page
    // 2^51 - 1, la fin (exclue) au plus INDEX_MAX = 2^51.
    if fichier.is_some() && page.checked_add(taille / PAGE).is_none_or(|fin| fin >= fichiers::index::INDEX_MAX) {
        return -EOVERFLOW;
    }
    let fixe = drapeaux & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    if fixe {
        if adresse > ADRESSE_MAX - taille {
            return -ENOMEM;
        }
        if adresse % PAGE != 0 {
            return -EINVAL;
        }
        if adresse < ADRESSE_MIN {
            return -EPERM;
        }
    }
    let droits = droits_de(prot);
    // Ce que projette la zone : le fichier (sa page de début), ou rien
    // (/dev/zero en privé est de la mémoire anonyme).
    let projection = match fichier {
        None => None,
        Some(p) => {
            if partagee && droits.ecriture && !p.ecriture {
                return -EACCES;
            }
            if !p.lecture {
                return -EACCES;
            }
            match p.sorte {
                Sorte::Fichier if partagee => None,
                Sorte::Fichier => Some(Projection { fichier: p.fichier.numero(), page }),
                Sorte::Zero => None,
                _ => return -ENODEV,
            }
        }
    };
    if partagee {
        afficherln!("[noyau] mmap : MAP_SHARED pas encore pris en charge");
        return -EINVAL;
    }
    let sans_reserve = drapeaux & MAP_NORESERVE != 0;
    if droits.ecriture && !sans_reserve && !engagement_possible(taille) {
        return -ENOMEM;
    }
    let resultat = processus::avec(|p| {
        let m = &mut p.memoire;
        let debut = if fixe {
            if drapeaux & MAP_FIXED_NOREPLACE != 0 && !m.zones.libre(adresse, adresse + taille, 0) {
                return Err(-EEXIST);
            }
            adresse
        } else {
            m.chercher_place(taille, adresse).ok_or(-ENOMEM)?
        };
        let drapeaux = Drapeaux { sans_reserve, ..Drapeaux::default() };
        let zone = Zone { debut, fin: debut + taille, droits, nature: Nature::Anonyme, drapeaux, fichier: projection };
        m.ajouter(zone, fixe).map_err(|_| -ENOMEM)?;
        Ok(debut)
    });
    let debut = match resultat {
        Ok(debut) => debut,
        Err(erreur) => return erreur,
    };
    if drapeaux & MAP_POPULATE != 0 {
        // Au mieux : un échec (plus de mémoire) est ignoré.
        let _ = peupler(debut, debut + taille, droits.ecriture);
    }
    debut as i64
}

/// Met en place d'avance les pages de [debut, fin[, comme si le programme
/// les avait touchées (en écriture si `ecriture`) : MAP_POPULATE,
/// MADV_POPULATE_*. Une page à la fois, en rendant le verrou du processus
/// entre deux : mettre en place des Mio, interruptions coupées, ferait
/// perdre ses tics à l'horloge. S'arrête au premier échec, et dit lequel.
/// Seulement dans des zones : peupler n'étend pas la pile.
fn peupler(debut: u64, fin: u64, ecriture: bool) -> Result<(), Echec> {
    let acces = if ecriture { Acces::Ecriture } else { Acces::Lecture };
    for page in (debut..fin).step_by(PAGE as usize) {
        processus::avec(|p| {
            p.memoire.zones.trouver(page).ok_or(Echec::SansZone)?;
            p.memoire.servir(page, acces)
        })?;
    }
    Ok(())
}

/// munmap(adresse, longueur) : retire les zones de la plage, et leurs
/// pages. Comme Linux : adresse non alignée, longueur nulle, ou plage qui
/// sort des adresses des programmes : EINVAL ; une plage où il n'y a rien
/// n'est pas une erreur ; couper une zone en deux quand la carte est
/// pleine : ENOMEM. Les pages touchées sont rendues verrou du processus
/// tenu, donc interruptions coupées : une centaine de nanosecondes par
/// page, des tics d'horloge perdus pour un munmap de centaines de Mio
/// touchés (le mmap_lock qui dort, avec l'ordonnanceur, y remédiera).
fn munmap(adresse: u64, longueur: u64) -> i64 {
    if adresse % PAGE != 0 || longueur == 0 {
        return -EINVAL;
    }
    let Some(fin) = longueur.checked_next_multiple_of(PAGE).and_then(|l| adresse.checked_add(l)) else {
        return -EINVAL;
    };
    if fin > ADRESSE_MAX {
        return -EINVAL;
    }
    match processus::avec(|p| p.memoire.retirer(adresse, fin)) {
        Ok(()) => 0,
        Err(_) => -ENOMEM,
    }
}

/// mprotect(adresse, longueur, droits) : change les droits d'une plage de
/// zones (memoire.rs), et ceux des pages qui y sont projetées. La glibc
/// statique s'en sert pour remettre en lecture seule, une fois ses
/// adresses corrigées, ses tables sensibles (RELRO : la GOT,
/// .init_array...) ; JavaScriptCore, pour ouvrir et fermer sa mémoire
/// réservée, et ses pages de code compilé. W+X est permis, comme sous
/// Linux (voir EspaceUtilisateur::proteger_plage).
///
/// Les vérifications et les codes d'erreur de Linux, dans son ordre
/// (do_mprotect_pkey, vérifiés par linux/memoire.c) : PROT_GROWSDOWN et
/// PROT_GROWSUP ensemble, ou une adresse non alignée : EINVAL ; une
/// longueur nulle : 0, quels que soient les droits ; une plage qui
/// déborde : ENOMEM ; un droit inconnu : EINVAL. Puis :
///   - PROT_GROWSDOWN : le changement part du début de la première zone de
///     la plage, qui doit grandir vers le bas (la pile), sinon EINVAL ;
///   - PROT_GROWSUP : aucune zone ne grandit vers le haut sur x86 :
///     EINVAL ;
///   - un trou dans la plage : ENOMEM, et rien ne change. (Linux change
///     les zones d'avant le trou, puis rend ENOMEM ; POSIX ne dit rien de
///     l'état après une erreur, aucun programme ne compte sur l'état
///     partiel, et tout ou rien est plus simple à garantir) ;
///   - rendre inscriptible une zone privée qui ne l'était pas, sans
///     MAP_NORESERVE, et plus grande que toute la mémoire : ENOMEM (le
///     surengagement, comme pour mmap).
fn mprotect(adresse: u64, longueur: u64, prot: u64) -> i64 {
    // Sans effet sur x86 : Linux l'accepte et l'ignore.
    const PROT_SEM: u64 = 8;
    const PROT_GROWSDOWN: u64 = 0x0100_0000;
    const PROT_GROWSUP: u64 = 0x0200_0000;
    let grandit = prot & (PROT_GROWSDOWN | PROT_GROWSUP);
    let prot = prot & !grandit;
    if grandit == PROT_GROWSDOWN | PROT_GROWSUP || adresse % PAGE != 0 {
        return -EINVAL;
    }
    if longueur == 0 {
        return 0;
    }
    let Some(fin) = longueur.checked_next_multiple_of(PAGE).and_then(|l| adresse.checked_add(l)) else {
        return -ENOMEM;
    };
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM) != 0 {
        return -EINVAL;
    }
    if fin > ADRESSE_MAX {
        return -ENOMEM;
    }
    processus::avec(|p| {
        let m = &mut p.memoire;
        // La première zone de la plage.
        let Some(&premiere) = m.zones.suivante(adresse).filter(|z| z.debut < fin) else {
            return -ENOMEM;
        };
        let debut = match grandit {
            PROT_GROWSDOWN if !premiere.drapeaux.vers_le_bas => return -EINVAL,
            PROT_GROWSDOWN => premiere.debut,
            _ if premiere.debut > adresse => return -ENOMEM,
            PROT_GROWSUP => return -EINVAL,
            _ => adresse,
        };
        match m.proteger(debut, fin, droits_de(prot)) {
            Ok(()) => 0,
            Err(_) => -ENOMEM,
        }
    })
}

/// madvise(adresse, longueur, conseil) : ce que le programme dit de sa
/// mémoire. JavaScriptCore en fait des centaines au démarrage de `claude`
/// (MADV_DONTNEED surtout : il rend des pages, et les reprendra). Les
/// vérifications de Linux, dans son ordre (do_madvise, vérifiées par
/// linux/memoire.c) : conseil inconnu, adresse non alignée, plage qui
/// déborde : EINVAL ; longueur nulle : 0. Puis le conseil s'applique à
/// chaque partie projetée de la plage, et s'il y a des trous, l'appel rend
/// ENOMEM à la fin (après avoir traité le reste).
///
/// Les conseils :
///   - MADV_DONTNEED, MADV_DONTNEED_LOCKED : les pages sont retirées. Dans
///     une zone anonyme, elles se reliront à zéro ; dans une projection de
///     fichier, le programme relira le FICHIER (ses copies privées sont
///     perdues) : c'est ce que fait Bun, qui rend ainsi 54 Mo de sa propre
///     section `.bun` (la trace de `claude --version`). Sans effet, encore,
///     sur un segment du programme que le chargeur a copié sans fichier
///     derrière (chargeur_elf.rs) : y mettre des zéros casserait le
///     programme en silence ;
///   - MADV_FREE : de même (il permet de garder le contenu ou de le
///     perdre), mais seulement sur de la mémoire anonyme : EINVAL sur un
///     fichier ou un segment du programme, comme Linux, avant de rien
///     changer ;
///   - MADV_WILLNEED, NORMAL, RANDOM, SEQUENTIAL, COLD, PAGEOUT, DONTDUMP,
///     DODUMP : des indications pour la mémoire d'échange, la lecture
///     anticipée ou les fichiers « core », que nous n'avons pas : acceptés,
///     sans effet. HUGEPAGE et NOHUGEPAGE aussi : comme un Linux dont les
///     grandes pages transparentes sont réglées sur « never » ;
///   - MADV_POPULATE_READ, MADV_POPULATE_WRITE : les fautes servies
///     d'avance. Une zone qui ne permet pas l'accès : EINVAL ; plus de
///     mémoire : ENOMEM ;
///   - MADV_DONTFORK, DOFORK, WIPEONFORK, KEEPONFORK : des drapeaux de
///     zone, pour le futur fork (6k) ; ils coupent les zones, comme
///     mprotect. WIPEONFORK n'a de sens que pour la mémoire anonyme :
///     EINVAL sur un segment du programme ;
///   - MADV_MERGEABLE, UNMERGEABLE : EINVAL, comme un Linux sans KSM (la
///     fusion des pages identiques) ;
///   - MADV_HWPOISON, SOFT_OFFLINE (simuler une panne de mémoire) : EPERM,
///     réservés à root ;
///   - les autres (MADV_REMOVE, COLLAPSE, GUARD_INSTALL...) : EINVAL.
fn madvise(adresse: u64, longueur: u64, conseil: u64) -> i64 {
    const NORMAL: u64 = 0;
    const RANDOM: u64 = 1;
    const SEQUENTIAL: u64 = 2;
    const WILLNEED: u64 = 3;
    const DONTNEED: u64 = 4;
    const FREE: u64 = 8;
    const DONTFORK: u64 = 10;
    const DOFORK: u64 = 11;
    const HUGEPAGE: u64 = 14;
    const NOHUGEPAGE: u64 = 15;
    const DONTDUMP: u64 = 16;
    const DODUMP: u64 = 17;
    const WIPEONFORK: u64 = 18;
    const KEEPONFORK: u64 = 19;
    const COLD: u64 = 20;
    const PAGEOUT: u64 = 21;
    const POPULATE_READ: u64 = 22;
    const POPULATE_WRITE: u64 = 23;
    const DONTNEED_LOCKED: u64 = 24;
    const HWPOISON: u64 = 100;
    const SOFT_OFFLINE: u64 = 101;
    let connu = matches!(conseil,
        NORMAL | RANDOM | SEQUENTIAL | WILLNEED | DONTNEED | FREE | DONTFORK | DOFORK | HUGEPAGE | NOHUGEPAGE
        | DONTDUMP | DODUMP | WIPEONFORK | KEEPONFORK | COLD | PAGEOUT | POPULATE_READ | POPULATE_WRITE
        | DONTNEED_LOCKED | HWPOISON | SOFT_OFFLINE);
    if !connu || adresse % PAGE != 0 {
        return -EINVAL;
    }
    let Some(fin) = longueur.checked_next_multiple_of(PAGE).and_then(|l| adresse.checked_add(l)) else {
        return -EINVAL;
    };
    if fin == adresse {
        return 0;
    }
    if matches!(conseil, HWPOISON | SOFT_OFFLINE) {
        return -EPERM;
    }
    // Au-delà des adresses des programmes, il n'y a aucune zone.
    let (debut, fin_zones) = (adresse.min(ADRESSE_MAX), fin.min(ADRESSE_MAX));
    let couverte = fin <= ADRESSE_MAX && processus::avec(|p| p.memoire.zones.couverte(debut, fin_zones));
    let resultat = match conseil {
        DONTNEED | FREE | DONTNEED_LOCKED => processus::avec(|p| {
            let m = &mut p.memoire;
            if conseil == FREE && m.zones.morceaux(debut, fin_zones).any(|z| z.fichier.is_some() || z.nature == Nature::Programme) {
                return Err(-EINVAL);
            }
            m.oublier(debut, fin_zones);
            Ok(())
        }),
        POPULATE_READ | POPULATE_WRITE => match peupler(debut, fin_zones, conseil == POPULATE_WRITE) {
            Err(Echec::AccesInterdit) => Err(-EINVAL),
            // Une page au-delà de la fin du fichier, ou un trou que le tmpfs
            // n'a plus la place de remplir : la faute ferait SIGBUS, madvise
            // rend EFAULT (`faultin_page`, VM_FAULT_SIGBUS).
            Err(Echec::HorsDuFichier | Echec::PlusDePlace) => Err(-EFAULT),
            Err(_) => Err(-ENOMEM),
            Ok(()) => Ok(()),
        },
        DONTFORK | DOFORK | WIPEONFORK | KEEPONFORK => processus::avec(|p| {
            let m = &mut p.memoire;
            if conseil == WIPEONFORK && m.zones.morceaux(debut, fin_zones).any(|z| z.fichier.is_some() || z.nature == Nature::Programme) {
                return Err(-EINVAL);
            }
            m.zones
                .changer(debut, fin_zones, |z| match conseil {
                    DONTFORK => z.drapeaux.ne_pas_dupliquer = true,
                    DOFORK => z.drapeaux.ne_pas_dupliquer = false,
                    WIPEONFORK => z.drapeaux.effacer_au_fork = true,
                    _ => z.drapeaux.effacer_au_fork = false,
                }, &mut memoire::references)
                .map_err(|_| -ENOMEM)
        }),
        // Les indications sans effet.
        _ => Ok(()),
    };
    match resultat {
        Err(erreur) => erreur,
        Ok(()) if !couverte => -ENOMEM,
        Ok(()) => 0,
    }
}

/// arch_prctl(code, adresse) : la base de FS (ARCH_SET_FS, ARCH_GET_FS),
/// où la glibc range ses variables propres au fil (TLS).
fn arch_prctl(code: u64, adresse: u64) -> i64 {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    match code {
        // Une adresse des programmes seulement : une adresse non canonique
        // ferait fauter wrmsr dans le noyau. Linux rend EPERM au-delà.
        ARCH_SET_FS if adresse < ADRESSE_MAX => {
            cpu::ecrire_base_fs(adresse);
            0
        }
        ARCH_SET_FS => -EPERM,
        ARCH_GET_FS => match copier_vers_utilisateur(adresse, &cpu::lire_base_fs().to_le_bytes()) {
            Ok(()) => 0,
            Err(_) => -EFAULT,
        },
        _ => -EINVAL,
    }
}

/// prlimit64(processus, ressource, nouvelle, ancienne) : les limites du
/// processus (processus::LIMITES_PAR_DEFAUT). Dans l'ordre de `do_prlimit`
/// : la nouvelle lue ; courante au-delà de la dure : EINVAL ; plus de
/// descripteurs que Linux n'en permet (nr_open, 2^20) : EPERM ; la dure
/// relevée sans être root (CAP_SYS_RESOURCE) : EPERM. Baisser, ou relever
/// la courante sous la dure, est permis pour toutes. Puis l'ancienne,
/// telle qu'elle était avant le changement. Bun relève RLIMIT_NOFILE au
/// démarrage ; d'autres programmes baissent RLIMIT_CORE.
fn prlimit64(pid: u64, ressource: u64, nouvelle: u64, ancienne: u64) -> i64 {
    if pid != 0 && pid != PID as u64 {
        return -ESRCH;
    }
    if ressource >= processus::LIMITES as u64 {
        return -EINVAL;
    }
    let ressource = ressource as usize;
    let mut regle = None;
    if nouvelle != 0 {
        let mut octets = [0u8; 16];
        if copier_depuis_utilisateur(&mut octets, nouvelle).is_err() {
            return -EFAULT;
        }
        let (c, m) = (u64::from_le_bytes(octets[..8].try_into().unwrap_or([0; 8])),
                      u64::from_le_bytes(octets[8..].try_into().unwrap_or([0; 8])));
        if c > m {
            return -EINVAL;
        }
        if ressource == processus::RLIMIT_NOFILE && m > 1 << 20 {
            return -EPERM;
        }
        regle = Some((c, m));
    }
    let avant = processus::avec(|p| {
        let avant = p.limite(ressource);
        if let Some(limite) = regle {
            if limite.1 > avant.1 && !p.identite.root() {
                return Err(-EPERM);
            }
            p.changer_limite(ressource, limite);
        }
        Ok(avant)
    });
    let (courante, maximale) = match avant {
        Ok(a) => a,
        Err(e) => return e,
    };
    if ancienne != 0 {
        let mut octets = [0u8; 16];
        octets[..8].copy_from_slice(&u64::to_le_bytes(courante));
        octets[8..].copy_from_slice(&u64::to_le_bytes(maximale));
        if copier_vers_utilisateur(ancienne, &octets).is_err() {
            return -EFAULT;
        }
    }
    0
}

/// getrandom(tampon, nombre, options) : des octets aléatoires, de la même
/// source qu'AT_RANDOM (aleatoire.rs). Au plus 256 octets d'une fois, la
/// taille que Linux garantit sans interruption ; au-delà, une partie
/// (permis : le programme redemande).
fn getrandom(tampon: u64, nombre: u64, options: u64) -> i64 {
    const GRND_NONBLOCK: u64 = 1;
    const GRND_RANDOM: u64 = 2;
    const GRND_INSECURE: u64 = 4;
    // GRND_INSECURE (« même si le générateur n'est pas prêt ») et
    // GRND_RANDOM (« de la meilleure source ») se contredisent : Linux
    // refuse les deux ensemble.
    if options & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || options & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return -EINVAL;
    }
    let mut octets = [0u8; 256];
    let n = (nombre as usize).min(octets.len());
    aleatoire::remplir(&mut octets[..n]);
    match copier_vers_utilisateur(tampon, &octets[..n]) {
        Ok(()) => n as i64,
        Err(_) => -EFAULT,
    }
}

/// sysinfo(info) : la mémoire de la machine, et le temps depuis le
/// démarrage. `claude` (JavaScriptCore) et la glibc s'en servent pour se
/// dimensionner (la taille du tas du ramasse-miettes, par exemple). La
/// « struct sysinfo » de Linux sur x86_64 : 112 octets, les tailles en
/// unités de mem_unit (1 : en octets). Pas de mémoire d'échange, ni de
/// mémoire « haute » (une notion des machines 32 bits), ni de charge
/// mesurée.
fn sysinfo(info: u64) -> i64 {
    let mut s = [0u8; 112];
    let mut mettre = |position: usize, valeur: u64, taille: usize| {
        s[position..position + taille].copy_from_slice(&valeur.to_le_bytes()[..taille]);
    };
    mettre(0, horloge::tics() / horloge::HZ as u64, 8); // uptime, en secondes
    mettre(32, pages::total() as u64 * PAGE, 8); // totalram
    mettre(40, pages::libres() as u64 * PAGE, 8); // freeram
    mettre(80, 1, 2); // procs : un seul processus
    mettre(104, 1, 4); // mem_unit
    match copier_vers_utilisateur(info, &s) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// Écrit un `struct timespec` (secondes, nanosecondes : deux entiers de 64
/// bits) à l'adresse `adresse` du programme.
fn ecrire_timespec(adresse: u64, t: fichiers::Temps) -> Result<(), ()> {
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&t.secondes.to_le_bytes());
    octets[8..].copy_from_slice(&(t.nanosecondes as i64).to_le_bytes());
    copier_vers_utilisateur(adresse, &octets).map_err(|_| ())
}

/// clock_gettime(horloge, temps) : l'heure d'une des horloges de Linux
/// (temps.rs). Une horloge inconnue : EINVAL. Sous Linux, la glibc passe
/// d'ordinaire par le vDSO, une page du noyau projetée chez le programme
/// qui lit l'heure sans appel système ; sans vDSO (6m), elle fait l'appel.
fn clock_gettime(horloge: u64, adresse: u64) -> i64 {
    let Some(t) = temps::horloge(horloge) else { return -EINVAL };
    match ecrire_timespec(adresse, t) {
        Ok(()) => 0,
        Err(()) => -EFAULT,
    }
}

/// clock_getres(horloge, resolution) : la finesse de l'horloge, la durée
/// d'un tic d'horloge pour toutes (Linux rend une nanoseconde pour ses
/// horloges fines, la durée d'un tic pour les _COARSE). Le résultat peut
/// ne pas être demandé (adresse nulle).
fn clock_getres(horloge: u64, adresse: u64) -> i64 {
    if temps::horloge(horloge).is_none() {
        return -EINVAL;
    }
    if adresse == 0 {
        return 0;
    }
    match ecrire_timespec(adresse, temps::resolution()) {
        Ok(()) => 0,
        Err(()) => -EFAULT,
    }
}

/// gettimeofday(temps, fuseau) : la date, en secondes et microsecondes.
/// Le fuseau (une notion abandonnée, que Linux garde à zéro par défaut) est
/// rendu à zéro s'il est demandé.
fn gettimeofday(adresse: u64, fuseau: u64) -> i64 {
    if adresse != 0 {
        let t = temps::maintenant();
        let mut octets = [0u8; 16];
        octets[..8].copy_from_slice(&t.secondes.to_le_bytes());
        octets[8..].copy_from_slice(&(t.nanosecondes as i64 / 1000).to_le_bytes());
        if copier_vers_utilisateur(adresse, &octets).is_err() {
            return -EFAULT;
        }
    }
    if fuseau != 0 && copier_vers_utilisateur(fuseau, &[0u8; 8]).is_err() {
        return -EFAULT;
    }
    0
}

/// time(adresse) : la date en secondes, rendue, et écrite à `adresse` si
/// elle n'est pas nulle.
fn time(adresse: u64) -> i64 {
    let secondes = temps::maintenant().secondes;
    if adresse != 0 && copier_vers_utilisateur(adresse, &secondes.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    secondes
}

/// Un signal de Linux (include/uapi/asm-generic/signal.h), par lequel un
/// programme fautif est arrêté. Un programme arrêté par le signal N se
/// termine avec le code de sortie 128 + N, comme le rapporte un shell
/// (139 pour SIGSEGV).
#[derive(Clone, Copy)]
pub struct Signal {
    pub numero: u8,
    pub nom: &'static str,
}

pub const SIGILL: Signal = Signal { numero: 4, nom: "SIGILL" };
pub const SIGTRAP: Signal = Signal { numero: 5, nom: "SIGTRAP" };
pub const SIGBUS: Signal = Signal { numero: 7, nom: "SIGBUS" };
pub const SIGFPE: Signal = Signal { numero: 8, nom: "SIGFPE" };
pub const SIGKILL: Signal = Signal { numero: 9, nom: "SIGKILL" };
pub const SIGSEGV: Signal = Signal { numero: 11, nom: "SIGSEGV" };
pub const SIGXCPU: Signal = Signal { numero: 24, nom: "SIGXCPU" };

/// Ce qui est arrivé, pour le message : celui que Linux écrit dans son
/// journal pour un programme tué par une exception
/// (show_signal_msg, do_trap), en ajoutant le vecteur.
pub struct Raison {
    vecteur: usize,
    rip: u64,
    rsp: u64,
    code: u64,
    cr2: u64,
    /// Pour une faute de page : pourquoi elle n'a pas été servie.
    cause: Option<Echec>,
    /// La zone où était RIP, s'il y en a une.
    zone: Option<ZoneDuCode>,
}

impl fmt::Display for Raison {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Raison { vecteur, rip, rsp, code, cr2, cause, zone } = *self;
        match vecteur {
            // Le code d'erreur d'une faute de page : bit 0 page présente
            // (sinon absente), bit 1 écriture, bit 2 venue de l'anneau 3,
            // bit 4 lecture d'instruction (NX).
            14 if matches!(cause, Some(Echec::HorsDuFichier | Echec::PlusDePlace)) => {
                write!(f, "bus error at {cr2:#x} ip {rip:#x} sp {rsp:#x} error {code:x}")?
            }
            14 => write!(f, "segfault at {cr2:#x} ip {rip:#x} sp {rsp:#x} error {code:x}")?,
            // `int n` vers une entrée de l'IDT interdite aux programmes : le
            // code d'erreur désigne l'entrée (n x 8, plus 2 pour « IDT »).
            // int 0x80, c'est l'ABI 32 bits de Linux.
            13 if code == 0x80 << 3 | 2 => write!(f, "int 0x80 : ABI 32 bits non prise en charge, ip {rip:#x}")?,
            13 => write!(f, "general protection fault ip {rip:#x} sp {rsp:#x} error {code:x}")?,
            0 => write!(f, "trap divide error ip {rip:#x} sp {rsp:#x}")?,
            1 => write!(f, "trap debug (int1 ou pas-a-pas) ip {rip:#x} sp {rsp:#x}")?,
            3 => write!(f, "trap int3 ip {rip:#x} sp {rsp:#x}")?,
            6 => write!(f, "trap invalid opcode ip {rip:#x} sp {rsp:#x}")?,
            _ => write!(f, "exception {vecteur} ip {rip:#x} sp {rsp:#x} error {code:x}")?,
        }
        if let Some(cause) = cause {
            write!(f, " ({})", cause.texte())?;
        }
        // Comme Linux : « ... error 6 in a.out[401000+1000] ».
        if let Some(zone) = zone {
            write!(f, " dans {zone}")?;
        }
        Ok(())
    }
}

/// Le signal qu'envoie Linux pour l'exception `vecteur` venue d'un
/// programme (arch/x86/kernel/traps.c), et de quoi l'expliquer. `cr2` :
/// l'adresse fautive d'une faute de page, et `cause` pourquoi elle n'a
/// pas été servie ; `zone` : celle où était RIP.
pub fn signal_de_l_exception(vecteur: usize, cadre: &Cadre, cr2: u64, cause: Option<Echec>, zone: Option<ZoneDuCode>)
    -> (Signal, Raison) {
    let signal = match vecteur {
        // Une projection de fichier au-delà de sa fin, ou un trou qu'un
        // système de fichiers plein ne peut pas remplir : SIGBUS (BUS_ADRERR),
        // comme Linux.
        14 if matches!(cause, Some(Echec::HorsDuFichier | Echec::PlusDePlace)) => SIGBUS,
        0 | 16 | 19 => SIGFPE, // division, x87, SIMD
        1 | 3 => SIGTRAP,      // débogage, int3
        6 => SIGILL,           // instruction invalide
        7 => SIGILL,           // SSE sans le contexte prêt (sous-étape 9)
        17 => SIGBUS,          // alignement
        _ => SIGSEGV,          // pages, protection générale, segments
    };
    (signal, Raison { vecteur, rip: cadre.rip, rsp: cadre.rsp, code: cadre.code_erreur, cr2, cause, zone })
}
