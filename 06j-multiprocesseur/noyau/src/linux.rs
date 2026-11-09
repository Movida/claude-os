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
//! fichiers (6b), dans appels_fichiers.rs ; et les signaux (6d), dans
//! signaux.rs : rt_sigaction, rt_sigprocmask, rt_sigpending, sigaltstack,
//! kill, tkill, tgkill ; et ce que `claude --version` demande encore (6d) :
//! futex (futex.rs), uname, sched_getaffinity, sched_yield, prctl ;
//! eventfd et epoll (evenements.rs) ; et les fils (6e) : clone et clone3
//! (fil.rs), gettid, exit (un fil) et exit_group (le groupe) ; et les
//! sockets (6g), dans appels_reseau.rs.
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
use crate::{aleatoire, appels_reseau, cpu, evenements, futex, pages, processus, signaux, tache, temps};

// Les numéros d'erreur de Linux (include/uapi/asm-generic/errno-base.h).
const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const EOPNOTSUPP: i64 = 95;
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
// Les transferts dans le noyau (6i).
const SENDFILE: u64 = 40;
const FADVISE64: u64 = 221;
const COPY_FILE_RANGE: u64 = 326;
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
const GETRUSAGE: u64 = 98;
const GETUID: u64 = 102;
const GETGID: u64 = 104;
const GETEUID: u64 = 107;
const GETEGID: u64 = 108;
const GETPPID: u64 = 110;
const GETPGRP: u64 = 111;
const GETPGID: u64 = 121;
const GETSID: u64 = 124;
const GETTID: u64 = 186;
const ARCH_PRCTL: u64 = 158;
const TIME: u64 = 201;
const SET_TID_ADDRESS: u64 = 218;
const CLOCK_GETTIME: u64 = 228;
const CLOCK_GETRES: u64 = 229;
const NANOSLEEP: u64 = 35;
const CLOCK_NANOSLEEP: u64 = 230;
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
const SCHED_YIELD: u64 = 24;
const EPOLL_CREATE: u64 = 213;
const EPOLL_WAIT: u64 = 232;
const EPOLL_CTL: u64 = 233;
// Les sockets (6g : appels_reseau.rs).
const SOCKET: u64 = 41;
const CONNECT: u64 = 42;
const ACCEPT: u64 = 43;
const SENDTO: u64 = 44;
const RECVFROM: u64 = 45;
const SENDMSG: u64 = 46;
const RECVMSG: u64 = 47;
const SHUTDOWN: u64 = 48;
const BIND: u64 = 49;
const LISTEN: u64 = 50;
const GETSOCKNAME: u64 = 51;
const GETPEERNAME: u64 = 52;
const SOCKETPAIR: u64 = 53;
const SETSOCKOPT: u64 = 54;
const GETSOCKOPT: u64 = 55;
const ACCEPT4: u64 = 288;
const RECVMMSG: u64 = 299;
const SENDMMSG: u64 = 307;
const EPOLL_PWAIT: u64 = 281;
const EVENTFD: u64 = 284;
const PIPE: u64 = 22;
const PIPE2: u64 = 293;
const EVENTFD2: u64 = 290;
// inotify (6i, surveillance.rs).
const INOTIFY_INIT: u64 = 253;
const INOTIFY_ADD_WATCH: u64 = 254;
const INOTIFY_RM_WATCH: u64 = 255;
const INOTIFY_INIT1: u64 = 294;
const EPOLL_CREATE1: u64 = 291;
const EPOLL_PWAIT2: u64 = 441;
const POLL: u64 = 7;
const PPOLL: u64 = 271;
const SELECT: u64 = 23;
const PSELECT6: u64 = 270;
const UNAME: u64 = 63;
const PRCTL: u64 = 157;
const FUTEX: u64 = 202;
const SCHED_SETAFFINITY: u64 = 203;
const SCHED_GETAFFINITY: u64 = 204;
const GETCPU: u64 = 309;
const RT_SIGACTION: u64 = 13;
const RT_SIGPROCMASK: u64 = 14;
const KILL: u64 = 62;
const RT_SIGPENDING: u64 = 127;
const SIGALTSTACK: u64 = 131;
const RT_SIGRETURN: u64 = 15;
const RT_SIGSUSPEND: u64 = 130;
const PAUSE: u64 = 34;
const RESTART_SYSCALL: u64 = 219;
const TKILL: u64 = 200;
const TGKILL: u64 = 234;
const RT_SIGTIMEDWAIT: u64 = 128;
const RT_SIGQUEUEINFO: u64 = 129;
const RT_TGSIGQUEUEINFO: u64 = 297;
const GETRANDOM: u64 = 318;
const RSEQ: u64 = 334;
const CLONE: u64 = 56;
const CLONE3: u64 = 435;

const PAGE: u64 = 4096;


/// Le numéro du processus en cours (processus::numero_neuf).
fn pid() -> i64 {
    processus::avec(|p| p.pid) as i64
}

/// Le numéro du fil en cours : celui du processus pour son fil principal.
fn tid() -> i64 {
    tache::courante().tid() as i64
}

/// getpgid, getsid : 0, soi ; un processus, ou le fil d'un processus (`find_task_by_vpid`) : le
/// sien ; sinon ESRCH.
fn groupe_de(qui: i32) -> i64 {
    const ESRCH: i64 = 3;
    if qui == 0 {
        return pid();
    }
    if qui < 0 {
        return -ESRCH;
    }
    let qui = qui as u32;
    if processus::existe(qui) {
        return qui as i64;
    }
    tache::processus_du_fil(qui).map_or(-ESRCH, |p| p as i64)
}

/// Exécute l'appel système `numero` : un résultat, ou -errno. `cadre` :
/// les registres du programme à l'appel (clone les copie pour le fil neuf).
pub fn appel(numero: u64, a: [u64; 6], cadre: &mut Cadre) -> i64 {
    let resultat = match numero {
        CLONE => crate::fil::clone(a[0], a[1], a[2], a[3], a[4], cadre),
        CLONE3 => crate::fil::clone3(a[0], a[1], cadre),
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
        SENDFILE => f::sendfile(a[0], a[1], a[2], a[3]),
        COPY_FILE_RANGE => f::copy_file_range(a[0], a[1], a[2], a[3], a[4], a[5]),
        FADVISE64 => f::fadvise64(a[0], a[1], a[2], a[3]),
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
        // pthread_join, tache.rs) ; rend le numéro du fil.
        SET_TID_ADDRESS => tache::effacer_tid_a(a[0]) as i64,
        // La liste des verrous « robustes » du fil (rendus s'il meurt en
        // les tenant, futex.rs). La taille de la tête de liste est fixée
        // par l'ABI (24 octets) ; Linux refuse les autres.
        SET_ROBUST_LIST => {
            if a[1] != 24 {
                -EINVAL
            } else {
                tache::liste_robuste(a[0]);
                0
            }
        }
        // Les « séquences redémarrables » : une optimisation des compteurs
        // par processeur. La glibc s'en passe si le noyau ne l'a pas.
        RSEQ => -ENOSYS,
        PRLIMIT64 => prlimit64(a[0], a[1], a[2], a[3]),
        FUTEX => futex::futex(a[0], a[1], a[2], a[3], a[4], a[5]),
        EVENTFD => evenements::eventfd(a[0]),
        PIPE => crate::tube::pipe(a[0]),
        PIPE2 => crate::tube::pipe2(a[0], a[1]),
        EVENTFD2 => evenements::eventfd2(a[0], a[1]),
        INOTIFY_INIT => crate::surveillance::inotify_init(),
        INOTIFY_INIT1 => crate::surveillance::inotify_init1(a[0]),
        INOTIFY_ADD_WATCH => crate::surveillance::inotify_add_watch(a[0], a[1], a[2]),
        INOTIFY_RM_WATCH => crate::surveillance::inotify_rm_watch(a[0], a[1]),
        EPOLL_CREATE => crate::epoll::epoll_create(a[0]),
        EPOLL_CREATE1 => crate::epoll::epoll_create1(a[0]),
        EPOLL_CTL => crate::epoll::epoll_ctl(a[0], a[1], a[2], a[3]),
        SOCKET => appels_reseau::socket(a[0], a[1], a[2]),
        SOCKETPAIR => appels_reseau::socketpair(a[0], a[1], a[2], a[3]),
        BIND => appels_reseau::bind(a[0], a[1], a[2]),
        CONNECT => appels_reseau::connect(a[0], a[1], a[2]),
        LISTEN => appels_reseau::listen(a[0], a[1]),
        ACCEPT => appels_reseau::accept4(a[0], a[1], a[2], 0),
        ACCEPT4 => appels_reseau::accept4(a[0], a[1], a[2], a[3]),
        GETSOCKNAME => appels_reseau::getsockname(a[0], a[1], a[2]),
        GETPEERNAME => appels_reseau::getpeername(a[0], a[1], a[2]),
        SENDTO => appels_reseau::sendto(a[0], a[1], a[2], a[3], a[4], a[5]),
        RECVFROM => appels_reseau::recvfrom(a[0], a[1], a[2], a[3], a[4], a[5]),
        SENDMSG => appels_reseau::sendmsg(a[0], a[1], a[2]),
        RECVMSG => appels_reseau::recvmsg(a[0], a[1], a[2]),
        SENDMMSG => appels_reseau::sendmmsg(a[0], a[1], a[2], a[3]),
        RECVMMSG => appels_reseau::recvmmsg(a[0], a[1], a[2], a[3], a[4]),
        SHUTDOWN => appels_reseau::shutdown(a[0], a[1]),
        SETSOCKOPT => appels_reseau::setsockopt(a[0], a[1], a[2], a[3], a[4]),
        GETSOCKOPT => appels_reseau::getsockopt(a[0], a[1], a[2], a[3], a[4]),
        EPOLL_WAIT => crate::epoll::epoll_wait(a[0], a[1], a[2], a[3]),
        EPOLL_PWAIT => crate::epoll::epoll_pwait(a[0], a[1], a[2], a[3], a[4], a[5]),
        EPOLL_PWAIT2 => crate::epoll::epoll_pwait2(a[0], a[1], a[2], a[3], a[4], a[5]),
        POLL => crate::sondage::poll(a[0], a[1], a[2]),
        PPOLL => crate::sondage::ppoll(a[0], a[1], a[2], a[3], a[4]),
        SELECT => crate::sondage::select(a[0], a[1], a[2], a[3], a[4]),
        PSELECT6 => crate::sondage::pselect6(a[0], a[1], a[2], a[3], a[4], a[5]),
        UNAME => uname(a[0]),
        SCHED_SETAFFINITY => sched_setaffinity(a[0], a[1], a[2]),
        SCHED_GETAFFINITY => sched_getaffinity(a[0], a[1], a[2]),
        GETCPU => getcpu(a[0], a[1]),
        // Céder le processeur (ordonnanceur.rs).
        SCHED_YIELD => {
            crate::ordonnanceur::ceder();
            0
        }
        PRCTL => prctl(a[0], a[1]),
        RT_SIGACTION => signaux::rt_sigaction(a[0], a[1], a[2], a[3]),
        RT_SIGPROCMASK => signaux::rt_sigprocmask(a[0], a[1], a[2], a[3]),
        RT_SIGPENDING => signaux::rt_sigpending(a[0], a[1]),
        SIGALTSTACK => signaux::sigaltstack(a[0], a[1], cadre.rsp),
        RT_SIGRETURN => crate::cadre_signal::rt_sigreturn(cadre),
        RT_SIGSUSPEND => signaux::rt_sigsuspend(a[0], a[1]),
        PAUSE => signaux::pause(),
        RESTART_SYSCALL => crate::reprise::restart_syscall(),
        KILL => signaux::kill(a[0], a[1]),
        TKILL => signaux::tkill(a[0], a[1]),
        TGKILL => signaux::tgkill(a[0], a[1], a[2]),
        RT_SIGTIMEDWAIT => signaux::rt_sigtimedwait(a[0], a[1], a[2], a[3]),
        RT_SIGQUEUEINFO => signaux::rt_sigqueueinfo(a[0], a[1], a[2]),
        RT_TGSIGQUEUEINFO => signaux::rt_tgsigqueueinfo(a[0], a[1], a[2], a[3]),
        // La glibc lit le lien /proc/self/exe pour connaître son propre
        // chemin (dl_get_origin) : /proc y répond (procfs.rs).
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
        FSYNC | FDATASYNC => f::fsync(a[0]),
        SYNCFS => f::syncfs(a[0]),
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
        GETRUSAGE => crate::rusage::getrusage(a[0], a[1]),
        // Qui est le programme : son numéro, et celui du fil ; son parent, le
        // noyau qui tient le rôle d'init (1) ; l'utilisateur et le groupe
        // 1000.
        GETPID => pid(),
        GETTID => tid(),
        GETPPID => 1,
        // Chaque programme mène son propre groupe et sa session (processus.rs), jusqu'au shell de 6l.
        GETPGRP => crate::processus::avec(|p| p.pid) as i64,
        GETPGID | GETSID => groupe_de(a[0] as u32 as i32),
        GETUID | GETEUID => processus::avec(|p| p.identite.uid) as i64,
        GETGID | GETEGID => processus::avec(|p| p.identite.gid) as i64,
        CLOCK_GETTIME => clock_gettime(a[0], a[1]),
        CLOCK_GETRES => clock_getres(a[0], a[1]),
        NANOSLEEP => clock_nanosleep(temps::CLOCK_MONOTONIC, 0, a[0], a[1]),
        CLOCK_NANOSLEEP => clock_nanosleep(a[0], a[1], a[2], a[3]),
        GETTIMEOFDAY => gettimeofday(a[0], a[1]),
        TIME => time(a[0]),
        // Le code de sortie tient sur 8 bits : Linux ne garde que l'octet
        // bas (exit(256) rend 0, exit(-1) rend 255), ce que verra le futur
        // wait ; les codes 128 + N restent ceux des signaux.
        // La fin elle-même vient au retour vers l'anneau 3 (tache.rs) : celle
        // du fil (exit), ou de tout le groupe (exit_group, ce qu'appelle
        // l'exit de la glibc).
        EXIT => {
            tracer(numero, a, None);
            tache::prevoir_sortie((a[0] & 0xff) as i32);
            return 0;
        }
        EXIT_GROUP => {
            tracer(numero, a, None);
            tache::prevoir_sortie_du_groupe((a[0] & 0xff) as i32);
            return 0;
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
        SENDFILE => ("sendfile", 4),
        COPY_FILE_RANGE => ("copy_file_range", 6),
        FADVISE64 => ("fadvise64", 4),
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
        CLONE => ("clone", 5),
        CLONE3 => ("clone3", 2),
        SET_TID_ADDRESS => ("set_tid_address", 1),
        SET_ROBUST_LIST => ("set_robust_list", 2),
        RSEQ => ("rseq", 4),
        PRLIMIT64 => ("prlimit64", 4),
        FUTEX => ("futex", 6),
        EVENTFD => ("eventfd", 1),
        PIPE => ("pipe", 1),
        PIPE2 => ("pipe2", 2),
        EVENTFD2 => ("eventfd2", 2),
        INOTIFY_INIT => ("inotify_init", 0),
        INOTIFY_INIT1 => ("inotify_init1", 1),
        INOTIFY_ADD_WATCH => ("inotify_add_watch", 3),
        INOTIFY_RM_WATCH => ("inotify_rm_watch", 2),
        EPOLL_CREATE => ("epoll_create", 1),
        EPOLL_CREATE1 => ("epoll_create1", 1),
        EPOLL_CTL => ("epoll_ctl", 4),
        SOCKET => ("socket", 3),
        SOCKETPAIR => ("socketpair", 4),
        BIND => ("bind", 3),
        CONNECT => ("connect", 3),
        LISTEN => ("listen", 2),
        ACCEPT => ("accept", 3),
        ACCEPT4 => ("accept4", 4),
        GETSOCKNAME => ("getsockname", 3),
        GETPEERNAME => ("getpeername", 3),
        SENDTO => ("sendto", 6),
        RECVFROM => ("recvfrom", 6),
        SENDMSG => ("sendmsg", 3),
        RECVMSG => ("recvmsg", 3),
        SENDMMSG => ("sendmmsg", 4),
        RECVMMSG => ("recvmmsg", 5),
        SHUTDOWN => ("shutdown", 2),
        SETSOCKOPT => ("setsockopt", 5),
        GETSOCKOPT => ("getsockopt", 5),
        EPOLL_WAIT => ("epoll_wait", 4),
        EPOLL_PWAIT => ("epoll_pwait", 6),
        EPOLL_PWAIT2 => ("epoll_pwait2", 6),
        POLL => ("poll", 3),
        PPOLL => ("ppoll", 5),
        SELECT => ("select", 5),
        PSELECT6 => ("pselect6", 6),
        UNAME => ("uname", 1),
        SCHED_SETAFFINITY => ("sched_setaffinity", 3),
        SCHED_GETAFFINITY => ("sched_getaffinity", 3),
        GETCPU => ("getcpu", 3),
        SCHED_YIELD => ("sched_yield", 0),
        PRCTL => ("prctl", 5),
        RT_SIGACTION => ("rt_sigaction", 4),
        RT_SIGPROCMASK => ("rt_sigprocmask", 4),
        RT_SIGPENDING => ("rt_sigpending", 2),
        SIGALTSTACK => ("sigaltstack", 2),
        RT_SIGRETURN => ("rt_sigreturn", 0),
        RT_SIGSUSPEND => ("rt_sigsuspend", 2),
        PAUSE => ("pause", 0),
        RESTART_SYSCALL => ("restart_syscall", 0),
        KILL => ("kill", 2),
        TKILL => ("tkill", 2),
        TGKILL => ("tgkill", 3),
        RT_SIGTIMEDWAIT => ("rt_sigtimedwait", 4),
        RT_SIGQUEUEINFO => ("rt_sigqueueinfo", 3),
        RT_TGSIGQUEUEINFO => ("rt_tgsigqueueinfo", 4),
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
        GETRUSAGE => ("getrusage", 2),
        GETPID => ("getpid", 0),
        GETTID => ("gettid", 0),
        GETPPID => ("getppid", 0),
        GETPGRP => ("getpgrp", 0),
        GETPGID => ("getpgid", 1),
        GETSID => ("getsid", 1),
        GETUID => ("getuid", 0),
        GETEUID => ("geteuid", 0),
        GETGID => ("getgid", 0),
        GETEGID => ("getegid", 0),
        CLOCK_GETTIME => ("clock_gettime", 2),
        CLOCK_GETRES => ("clock_getres", 2),
        NANOSLEEP => ("nanosleep", 2),
        CLOCK_NANOSLEEP => ("clock_nanosleep", 4),
        GETTIMEOFDAY => ("gettimeofday", 2),
        TIME => ("time", 1),
        EXIT => ("exit", 1),
        EXIT_GROUP => ("exit_group", 1),
        _ => ("?", 6),
    };
    // Une ligne en UN message : avec plusieurs processeurs (6j), deux
    // appels tracés en même temps mêlaient leurs morceaux (un `afficher!`
    // par argument) ; un message entier passe sous le verrou des écritures.
    struct Arguments<'a>(&'a [u64]);
    impl core::fmt::Display for Arguments<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            for (i, x) in self.0.iter().enumerate() {
                write!(f, "{}{:#x}", if i > 0 { ", " } else { "" }, x)?;
            }
            Ok(())
        }
    }
    struct Resultat(Option<i64>);
    impl core::fmt::Display for Resultat {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self.0 {
                None => write!(f, "?"),
                Some(r) if r < 0 => write!(f, "-1 (errno {})", -r),
                Some(r) => write!(f, "{:#x}", r),
            }
        }
    }
    afficherln!("[trace] {}({}) = {}", nom, Arguments(&a[..n]), Resultat(resultat));
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
/// Le reculer rend les pages que le programme avait touchées, mémoire du
/// processus tenue en écriture (6i : un verrou qui dort, le mmap_lock de
/// Linux), interruptions actives.
fn brk(demande: u64) -> i64 {
    processus::memoire_ecrite(|m| {
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
///     le dit ; `claude` ne s'en sert pas, fork (6l) en aura besoin.
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
    // Le fichier projeté, s'il y en a un (fget, avant même la longueur),
    // tenu jusqu'à la fin de l'appel : la zone prend sa propre référence.
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
    let projection = match &fichier {
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
                Sorte::Fichier => Some(Projection { fichier: p.fichier().numero(), page }),
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
    let resultat = processus::memoire_ecrite(|m| {
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
/// MADV_POPULATE_*. Une page à la fois, mémoire tenue en lecture (comme
/// une faute), rendue entre deux : un munmap d'un autre fil n'attend pas
/// des Mio. S'arrête au premier échec, et dit lequel. Seulement dans des
/// zones : peupler n'étend pas la pile (Memoire::servir).
fn peupler(debut: u64, fin: u64, ecriture: bool) -> Result<(), Echec> {
    let acces = if ecriture { Acces::Ecriture } else { Acces::Lecture };
    for page in (debut..fin).step_by(PAGE as usize) {
        processus::memoire_lue(|m| m.servir(page, acces))?;
    }
    Ok(())
}

/// munmap(adresse, longueur) : retire les zones de la plage, et leurs
/// pages. Comme Linux : adresse non alignée, longueur nulle, ou plage qui
/// sort des adresses des programmes : EINVAL ; une plage où il n'y a rien
/// n'est pas une erreur ; couper une zone en deux quand la carte est
/// pleine : ENOMEM. En deux temps, comme Linux (`do_vmi_align_munmap`) :
/// les zones retirées mémoire du processus tenue en ÉCRITURE (un verrou qui
/// dort, depuis 6i), puis le verrou RÉTROGRADÉ en lecture pour rendre les
/// pages et les tables (6j, `mmap_write_downgrade`) : les fautes des autres
/// fils, ailleurs dans la mémoire, continuent pendant ce temps ; dans la
/// plage, il n'y a plus de zone, une faute y fait SIGSEGV comme après.
/// Interruptions actives : un munmap de centaines de Mio ne fait pas perdre
/// ses tics à l'horloge (memoire.rs, `rendre_pages`).
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
    match processus::memoire_ecrite_puis_lue(|m| m.retirer_zones(adresse, fin), |m, ()| m.rendre_pages(adresse, fin)) {
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
    processus::memoire_ecrite(|m| {
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
///     fichier (les segments du programme compris, chargeur_elf.rs), le
///     programme relira le FICHIER (ses copies privées sont perdues) :
///     c'est ce que fait Bun, qui rend ainsi 54 Mo de sa propre section
///     `.bun` (la trace de `claude --version`) ;
///   - MADV_FREE : de même (il permet de garder le contenu ou de le
///     perdre), mais seulement sur de la mémoire anonyme : EINVAL sur un
///     fichier, comme Linux, avant de rien changer ;
///   - MADV_WILLNEED, NORMAL, RANDOM, SEQUENTIAL, COLD, PAGEOUT, DONTDUMP,
///     DODUMP : des indications pour la mémoire d'échange, la lecture
///     anticipée ou les fichiers « core », que nous n'avons pas : acceptés,
///     sans effet. HUGEPAGE et NOHUGEPAGE aussi : comme un Linux dont les
///     grandes pages transparentes sont réglées sur « never » ;
///   - MADV_POPULATE_READ, MADV_POPULATE_WRITE : les fautes servies
///     d'avance. Une zone qui ne permet pas l'accès : EINVAL ; plus de
///     mémoire : ENOMEM ;
///   - MADV_DONTFORK, DOFORK, WIPEONFORK, KEEPONFORK : des drapeaux de
///     zone, pour le futur fork (6l) ; ils coupent les zones, comme
///     mprotect. WIPEONFORK n'a de sens que pour la mémoire anonyme :
///     EINVAL sur un fichier ;
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
    let couverte = fin <= ADRESSE_MAX && processus::memoire_lue(|m| m.zones.couverte(debut, fin_zones));
    let resultat = match conseil {
        // Mémoire tenue en LECTURE, comme Linux (6j, Memoire::oublier) : les
        // pages sont rendues interruptions actives, et les fautes des autres
        // fils continuent.
        DONTNEED | FREE | DONTNEED_LOCKED => processus::memoire_lue(|m| {
            if conseil == FREE && m.zones.morceaux(debut, fin_zones).any(|z| z.fichier.is_some()) {
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
        DONTFORK | DOFORK | WIPEONFORK | KEEPONFORK => processus::memoire_ecrite(|m| {
            if conseil == WIPEONFORK && m.zones.morceaux(debut, fin_zones).any(|z| z.fichier.is_some()) {
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
/// processus (processus::limites_par_defaut). Dans l'ordre de `do_prlimit`
/// : la nouvelle lue ; courante au-delà de la dure : EINVAL ; plus de
/// descripteurs que Linux n'en permet (nr_open, 2^20) : EPERM ; la dure
/// relevée sans être root (CAP_SYS_RESOURCE) : EPERM. Baisser, ou relever
/// la courante sous la dure, est permis pour toutes. Puis l'ancienne,
/// telle qu'elle était avant le changement. Bun relève RLIMIT_NOFILE au
/// démarrage ; d'autres programmes baissent RLIMIT_CORE.
fn prlimit64(pid: u64, ressource: u64, nouvelle: u64, ancienne: u64) -> i64 {
    if pid != 0 && pid != self::pid() as u64 {
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
    let (courante, maximale) = match processus::regler_limite(ressource, regle) {
        Ok(a) => a,
        Err(()) => return -EPERM,
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

/// uname(tampon) : qui est le système, en six chaînes de 65 octets (la
/// `struct new_utsname`). On annonce la version de Linux dont on imite le
/// comportement (6.18, celle des sondes de chaque sous-étape), suivie de
/// qui l'a construit, comme le fait WSL (« 6.18.33.2-microsoft-standard-
/// WSL2 », mesuré) : les programmes testent `sysname` et lisent `release`
/// pour choisir des fonctions. Le nom de la machine et le domaine :
/// « (none) », ceux de Linux tant que personne n'a appelé `sethostname`
/// (UTS_NODENAME) ; notre lanceur, qui tient le rôle d'init, n'a aucune
/// raison de le faire.
fn uname(tampon: u64) -> i64 {
    const CHAMPS: [&[u8]; 6] = [b"Linux", b"(none)", b"6.18.0-claude-os", b"#1", b"x86_64", b"(none)"];
    let mut u = [0u8; 6 * 65];
    for (i, champ) in CHAMPS.iter().enumerate() {
        u[i * 65..i * 65 + champ.len()].copy_from_slice(champ);
    }
    match copier_vers_utilisateur(tampon, &u) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// Le masque des processeurs du noyau, en octets (le `cpumask_size` de
/// Linux) : un `unsigned long` suffit jusqu'à 64 processeurs.
const MASQUE_PROCESSEURS: u64 = 8;

/// sched_getaffinity(pid, longueur, masque) : sur quels processeurs le fil
/// `pid` (0 : le courant) peut tourner : son masque (sched_setaffinity, ou
/// celui de son créateur), restreint aux processeurs en service, ce que
/// rend Linux (`cpumask_and(mask, &p->cpus_mask, cpu_active_mask)`). Dans
/// l'ordre de Linux : la longueur d'abord (au moins le masque du noyau, et
/// un multiple de 8 : EINVAL, avant même de chercher le processus), puis le
/// fil (tout fil vivant, ou tout processus qui existe, zombie compris ;
/// sinon ESRCH) ; on écrit au plus le masque du noyau, et on rend sa taille
/// (mesuré : 8 sur une machine de 12 processeurs, autant que pour un).
fn sched_getaffinity(pid: u64, longueur: u64, masque: u64) -> i64 {
    let longueur = longueur as u32 as u64;
    if longueur < MASQUE_PROCESSEURS || longueur % 8 != 0 {
        return -EINVAL;
    }
    let Some(affinite) = affinite_du(pid) else { return -ESRCH };
    let rendu = affinite & crate::processeur::masque_en_service();
    match copier_vers_utilisateur(masque, &rendu.to_le_bytes()) {
        Ok(()) => MASQUE_PROCESSEURS as i64,
        Err(_) => -EFAULT,
    }
}

/// L'affinité du fil `pid` (0 : le courant) : celle de sa tâche s'il vit ;
/// tous les processeurs pour un processus qui existe sans ce fil (un
/// zombie : Linux garde la tâche de son fil principal et son masque ; nous
/// rendons celui d'un fil neuf) ; None s'il n'y a ni l'un ni l'autre
/// (ESRCH).
fn affinite_du(pid: u64) -> Option<u64> {
    let pid = pid as u32 as i32;
    if pid == 0 {
        return Some(tache::courante().affinite());
    }
    if pid < 0 {
        return None;
    }
    tache::affinite_du_fil(pid as u32).or_else(|| processus::existe(pid as u32).then_some(u64::MAX))
}

/// sched_setaffinity(pid, longueur, masque) : sur quels processeurs le fil
/// `pid` (0 : le courant) pourra tourner. Dans l'ordre de Linux
/// (`get_user_cpu_mask`, puis `sched_setaffinity`) : le masque lu sur
/// `longueur` octets (EFAULT), au plus ceux du masque du noyau (le reste
/// n'est pas lu), les octets manquants valant zéro (pas d'EINVAL sur la
/// longueur, contrairement à sched_getaffinity) ; puis le fil (tout fil
/// vivant, ou tout processus qui existe ; sinon ESRCH) ; un masque sans
/// aucun processeur en service : EINVAL (`__set_cpus_allowed_ptr`) ; le
/// masque posé TEL QUEL, bits des processeurs absents compris (Linux garde
/// `cpus_mask` tel que demandé ; sched_getaffinity le restreint). Un
/// processus sans ce fil (un zombie) : 0, rien à poser (Linux pose le
/// masque de sa tâche morte). Gardé dès ce commit ; honoré par le placement
/// des tâches avec la file des prêtes par processeur (6j).
fn sched_setaffinity(pid: u64, longueur: u64, masque: u64) -> i64 {
    let longueur = (longueur as u32 as u64).min(MASQUE_PROCESSEURS) as usize;
    let mut octets = [0u8; 8];
    if longueur > 0 && copier_depuis_utilisateur(&mut octets[..longueur], masque).is_err() {
        return -EFAULT;
    }
    let nouveau = u64::from_le_bytes(octets);
    let pid = pid as u32 as i32;
    let tid = match pid {
        0 => tache::courante().tid(),
        1.. => pid as u32,
        _ => return -ESRCH,
    };
    if tache::affinite_du_fil(tid).is_none() && !processus::existe(tid) {
        return -ESRCH;
    }
    if nouveau & crate::processeur::masque_en_service() == 0 {
        return -EINVAL;
    }
    tache::poser_affinite_du_fil(tid, nouveau);
    0
}

/// getcpu(processeur, nœud, inutilisé) : le processeur où le fil s'exécute,
/// et son nœud NUMA (toujours 0 : une seule mémoire). Chaque adresse est
/// écrite si elle n'est pas nulle (EFAULT si elle est invalide) ; le
/// troisième argument, un cache d'une ancienne glibc, est ignoré, comme
/// chez Linux. La glibc s'en sert pour `sched_getcpu`, faute de `rseq`
/// (ENOSYS chez nous) ou du vDSO (6n). La valeur peut être périmée dès
/// qu'elle est lue : le fil peut changer de processeur juste après, ce que
/// Linux dit aussi dans sa page de manuel.
fn getcpu(processeur: u64, noeud: u64) -> i64 {
    if processeur != 0 && copier_vers_utilisateur(processeur, &crate::processeur::numero().to_le_bytes()).is_err() {
        return -EFAULT;
    }
    if noeud != 0 && copier_vers_utilisateur(noeud, &0u32.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    0
}

/// prctl(option, argument, ...) : des réglages du processus. Ceux que
/// demandent nos programmes :
///   - PR_SET_NAME, PR_GET_NAME : le nom du programme, 15 octets au plus
///     (le `comm` de Linux), celui que portent les messages du noyau ;
///   - PR_SET_VMA (nommer une zone, « JSJITCode » pour Bun) : EINVAL, comme
///     un Linux construit sans CONFIG_ANON_VMA_NAME (celui de la trace de
///     claude --version, qui continue sans) ; il faudrait un nom par zone
///     dans zones/, comparé à chaque fusion : utile au débogage, pas à
///     claude.
/// Le reste : EINVAL, comme Linux pour une option qu'il ne connaît pas, et
/// un message.
fn prctl(option: u64, argument: u64) -> i64 {
    const PR_SET_NAME: u64 = 15;
    const PR_GET_NAME: u64 = 16;
    const PR_SET_VMA: u64 = 0x5356_4d41;
    match option as u32 as u64 {
        PR_SET_NAME => {
            // strncpy_from_user de 15 octets au plus, jusqu'au premier zéro.
            let mut nom = [0u8; 15];
            let lus = crate::copie_utilisateur::copier_depuis_utilisateur_partiel(&mut nom, argument);
            let nom = &nom[..lus];
            let fin = nom.iter().position(|&o| o == 0);
            if fin.is_none() && lus < 15 {
                return -EFAULT;
            }
            tache::renommer(crate::programmes::NomCourt::de(&nom[..fin.unwrap_or(lus)]));
            0
        }
        PR_GET_NAME => {
            let mut nom = [0u8; 16];
            let n = tache::nom();
            nom[..n.octets().len()].copy_from_slice(n.octets());
            match copier_vers_utilisateur(argument, &nom) {
                Ok(()) => 0,
                Err(_) => -EFAULT,
            }
        }
        PR_SET_VMA => -EINVAL,
        o => {
            afficherln!("[noyau] prctl : option {:#x} pas prise en charge", o);
            -EINVAL
        }
    }
}

/// getrandom(tampon, nombre, options), dans l'ordre de Linux (le
/// `getrandom` de drivers/char/random.c) : des options inconnues, ou
/// GRND_INSECURE (« même si le générateur n'est pas prêt ») avec
/// GRND_RANDOM (« de la meilleure source »), qui se contredisent : EINVAL ;
/// le générateur pas prêt (et pas GRND_INSECURE) : EAGAIN avec
/// GRND_NONBLOCK, sinon attendre (aleatoire::attendre_pret, interruptible) ;
/// puis les octets (`alea_vers_programme`), au plus MAX_RW_COUNT, ce
/// qu'a copié une faute ou un signal. GRND_RANDOM ne change rien depuis
/// Linux 5.6 (plus de réservoir « bloquant » à part).
fn getrandom(tampon: u64, nombre: u64, options: u64) -> i64 {
    const GRND_NONBLOCK: u64 = 1;
    const GRND_RANDOM: u64 = 2;
    const GRND_INSECURE: u64 = 4;
    const EAGAIN: i64 = 11;
    let options = options as u32 as u64;
    if options & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || options & (GRND_RANDOM | GRND_INSECURE) == GRND_RANDOM | GRND_INSECURE
    {
        return -EINVAL;
    }
    if !aleatoire::pret() && options & GRND_INSECURE == 0 {
        if options & GRND_NONBLOCK != 0 {
            return -EAGAIN;
        }
        if let Err(e) = aleatoire::attendre_pret() {
            return e;
        }
    }
    // import_ubuf : la plage dans les adresses des programmes, plafonnée.
    let nombre = nombre.min(crate::appels_fichiers::RW_MAX);
    if !crate::copie_utilisateur::dans_les_bornes(tampon, nombre) {
        return -EFAULT;
    }
    match crate::appels_fichiers::alea_vers_programme(tampon, nombre) {
        Ok(n) => n as i64,
        Err(e) => e,
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
    mettre(0, temps::monotone().secondes as u64, 8); // uptime, en secondes
    mettre(32, pages::total() as u64 * PAGE, 8); // totalram
    mettre(40, pages::libres() as u64 * PAGE, 8); // freeram
    mettre(80, tache::nombre().min(u16::MAX as usize) as u64, 2); // procs : les tâches (nr_threads)
    mettre(104, 1, 4); // mem_unit
    match copier_vers_utilisateur(info, &s) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// clock_nanosleep(horloge, drapeaux, durée, reste) et nanosleep(durée,
/// reste) (sur CLOCK_MONOTONIC, comme Linux) : dormir une durée, ou
/// jusqu'à une échéance absolue (TIMER_ABSTIME), dans l'ordre de Linux
/// (kernel/time/posix-timers.c), mesuré sur 6.18 :
///   1. l'horloge : REALTIME, MONOTONIC, BOOTTIME, TAI et
///      PROCESS_CPUTIME_ID dorment ; THREAD_CPUTIME_ID, MONOTONIC_RAW et
///      les _COARSE n'ont pas d'attente (EOPNOTSUPP) ; une inconnue, EINVAL
///      (les numéros négatifs, horloges de calcul d'un autre processus ou
///      d'un fil, que Linux accepte : EINVAL chez nous, un écart) ;
///   2. la durée lue (EFAULT), puis vérifiée (EINVAL : secondes négatives,
///      nanosecondes hors de [0, 10^9[) ;
///   3. les horloges des alarmes (REALTIME_ALARM, BOOTTIME_ALARM) : un
///      drapeau inconnu, EINVAL ; sinon il faudrait pouvoir réveiller la
///      machine (CAP_WAKE_ALARM) : EPERM. Pour les autres, les drapeaux
///      autres que TIMER_ABSTIME sont ignorés ;
///   4. dormir, interruptible (`sommeil`) ; une échéance atteinte, même
///      avec un signal en attente : 0 (le sommeil a réussi, le signal sera
///      livré au retour : `do_nanosleep`, `do_cpu_nanosleep`). Un signal
///      avant l'échéance : pour une durée relative, le
///      temps qui restait est écrit à `reste` (s'il est demandé), et
///      l'appel rend ERESTART_RESTARTBLOCK (EINTR si un gestionnaire est
///      appelé ; sans, il est repris par restart_syscall, jusqu'à la même
///      échéance : le délai ne recommence pas) ; pour une échéance absolue,
///      rien n'est écrit, et ERESTARTNOHAND (refait tel quel sans
///      gestionnaire : `hrtimer_nanosleep`, reprise.rs).
/// L'attente se fait au tic qui suit l'échéance, jamais avant (attente.rs).
/// Sur CLOCK_PROCESS_CPUTIME_ID, on attend que le temps de calcul du
/// processus atteigne l'échéance : un programme d'un seul fil qui dort ne
/// calcule plus, il attend pour toujours (mesuré sous Linux).
fn clock_nanosleep(horloge: u64, drapeaux: u64, duree: u64, reste: u64) -> i64 {
    const TIMER_ABSTIME: u64 = 1;
    const CLOCK_REALTIME_ALARM: u64 = 8;
    const CLOCK_BOOTTIME_ALARM: u64 = 9;
    use temps::{CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW, CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME,
                CLOCK_REALTIME_COARSE, CLOCK_TAI, CLOCK_THREAD_CPUTIME_ID};
    let alarme = matches!(horloge, CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM);
    match horloge {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME | CLOCK_TAI | CLOCK_PROCESS_CPUTIME_ID => {}
        _ if alarme => {}
        CLOCK_THREAD_CPUTIME_ID | CLOCK_MONOTONIC_RAW | CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => return -EOPNOTSUPP,
        _ => return -EINVAL,
    }
    let mut o = [0u8; 16];
    if copier_depuis_utilisateur(&mut o, duree).is_err() {
        return -EFAULT;
    }
    let secondes = i64::from_le_bytes(o[..8].try_into().unwrap_or([0; 8]));
    let nanosecondes = i64::from_le_bytes(o[8..].try_into().unwrap_or([0; 8]));
    if secondes < 0 || !(0..1_000_000_000).contains(&nanosecondes) {
        return -EINVAL;
    }
    if alarme {
        return if drapeaux & !TIMER_ABSTIME != 0 { -EINVAL } else { -EPERM };
    }
    let demande = (secondes as u128 * 1_000_000_000 + nanosecondes as u128).min(u64::MAX as u128) as u64;
    let absolue = drapeaux & TIMER_ABSTIME != 0;
    let calcul = horloge == CLOCK_PROCESS_CPUTIME_ID;
    let cible = if calcul {
        if absolue { demande } else { tache::temps_du_processus().saturating_add(demande) }
    } else {
        // L'échéance en temps monotone : les horloges de dates (REALTIME,
        // TAI) ne diffèrent du temps monotone que d'un écart fixe (la date
        // ne se règle pas encore).
        let mono = temps::ns_monotone();
        if !absolue {
            mono.saturating_add(demande)
        } else if matches!(horloge, CLOCK_REALTIME | CLOCK_TAI) {
            let reel = temps::maintenant();
            let reel = reel.secondes as i128 * 1_000_000_000 + reel.nanosecondes as i128;
            (demande as i128 - reel + mono as i128).clamp(0, u64::MAX as i128) as u64
        } else {
            demande
        }
    };
    sommeil(calcul, cible, if absolue { None } else { Some(reste) })
}

/// Dort jusqu'à `cible` (temps monotone, ou temps de calcul du processus si
/// `calcul`), interruptible. Un signal : pour un sommeil relatif (`reste`
/// donné), le temps qui restait écrit (si l'adresse n'est pas nulle), et la
/// reprise gardée pour restart_syscall : ERESTART_RESTARTBLOCK ; pour une
/// échéance absolue, ERESTARTNOHAND.
fn sommeil(calcul: bool, cible: u64, reste: Option<u64>) -> i64 {
    let interruptions = cpu::couper_interruptions();
    let (reveil, restant) = if calcul {
        let compte = tache::courante().processus().cloned().expect("appel systeme sans processus");
        let r = crate::attente::dormir_calcul(compte, cible);
        (r, cible.saturating_sub(tache::temps_du_processus()))
    } else {
        let t = tache::courante();
        let r = loop {
            // Rien d'autre que l'échéance ou un signal ne la réveille : un
            // réveil sans raison se rendort. « Je vais dormir » à chaque
            // tour (attente.rs) : sans file, seuls le tic et les signaux
            // la réveillent, mais `dormir` l'exige.
            t.preparer_sommeil(crate::attente::Sommeil::Interruptible);
            match crate::attente::dormir(Some(cible), crate::attente::Sommeil::Interruptible) {
                tache::Reveil::Reveillee => continue,
                r => break r,
            }
        };
        t.reveille();
        (r, cible.saturating_sub(temps::ns_monotone()))
    };
    if interruptions {
        cpu::activer_interruptions();
    }
    // L'échéance atteinte : le sommeil a réussi, même réveillé par un signal
    // (`dormir` regarde les signaux avant l'échéance, servie au tic qui la
    // suit : un signal peut tomber entre les deux, ou attendre déjà à
    // l'entrée d'un sommeil nul).
    if reveil != tache::Reveil::Signal || restant == 0 {
        return 0;
    }
    let Some(reste) = reste else { return -crate::reprise::ERESTARTNOHAND };
    if reste != 0 {
        let t = fichiers::Temps { secondes: (restant / 1_000_000_000) as i64, nanosecondes: (restant % 1_000_000_000) as u32 };
        if ecrire_timespec(reste, t).is_err() {
            return -EFAULT;
        }
    }
    crate::reprise::garder(crate::reprise::Reprise::Sommeil { calcul, cible, reste });
    -crate::reprise::ERESTART_RESTARTBLOCK
}

/// La reprise d'un sommeil relatif par restart_syscall (reprise.rs) :
/// jusqu'à la même échéance (le `hrtimer_nanosleep_restart` de Linux).
pub fn reprendre_sommeil(calcul: bool, cible: u64, reste: u64) -> i64 {
    sommeil(calcul, cible, Some(reste))
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
/// qui lit l'heure sans appel système ; sans vDSO (6n), elle fait l'appel.
fn clock_gettime(horloge: u64, adresse: u64) -> i64 {
    let Some(t) = temps::horloge(horloge) else { return -EINVAL };
    match ecrire_timespec(adresse, t) {
        Ok(()) => 0,
        Err(()) => -EFAULT,
    }
}

/// clock_getres(horloge, resolution) : la finesse de l'horloge (Linux rend
/// une nanoseconde pour ses horloges fines, la durée d'un tic pour les
/// _COARSE ; voir temps::resolution). Le résultat peut ne pas être
/// demandé (adresse nulle).
fn clock_getres(horloge: u64, adresse: u64) -> i64 {
    if temps::horloge(horloge).is_none() {
        return -EINVAL;
    }
    if adresse == 0 {
        return 0;
    }
    match ecrire_timespec(adresse, temps::resolution(horloge)) {
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
    pub vecteur: usize,
    rip: u64,
    rsp: u64,
    pub code: u64,
    pub cr2: u64,
    /// Pour une faute de page : pourquoi elle n'a pas été servie.
    cause: Option<Echec>,
    /// La zone où était RIP, s'il y en a une.
    zone: Option<ZoneDuCode>,
    /// Le si_code et le si_addr du siginfo (le `force_sig_fault` de Linux).
    pub si_code: i32,
    pub si_addr: u64,
}

impl Raison {
    /// Le siginfo de cette exception, pour le signal `signal`.
    pub fn info(&self, signal: Signal) -> crate::signaux::Info {
        crate::signaux::Info::faute(signal.numero as u64, self.si_code, self.si_addr)
    }
}

impl fmt::Display for Raison {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Raison { vecteur, rip, rsp, code, cr2, cause, zone, .. } = *self;
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

/// Les si_code des fautes (include/uapi/asm-generic/siginfo.h).
const SEGV_MAPERR: i32 = 1;
const SEGV_ACCERR: i32 = 2;
const BUS_ADRALN: i32 = 1;
const BUS_ADRERR: i32 = 2;
const ILL_ILLOPN: i32 = 2;
const FPE_INTDIV: i32 = 1;
const TRAP_BRKPT: i32 = 1;
const TRAP_TRACE: i32 = 2;
const SI_KERNEL: i32 = 0x80;

/// Le signal qu'envoie Linux pour l'exception `vecteur` venue d'un
/// programme (arch/x86/kernel/traps.c, et arch/x86/mm/fault.c pour la faute
/// de page), et de quoi l'expliquer : le message, et le siginfo que reçoit
/// un gestionnaire (si_code, si_addr ; mesurés sous Linux 6.18). `cr2` :
/// l'adresse fautive d'une faute de page, et `cause` pourquoi elle n'a
/// pas été servie ; `zone` : celle où était RIP ; `dr6` : pour #DB, le
/// registre de débogage qui dit pourquoi (0 sinon).
pub fn signal_de_l_exception(vecteur: usize, cadre: &Cadre, cr2: u64, cause: Option<Echec>, zone: Option<ZoneDuCode>,
                             dr6: u64) -> (Signal, Raison) {
    let rip = cadre.rip;
    let (signal, si_code, si_addr) = match vecteur {
        // Une projection de fichier au-delà de sa fin, ou un trou qu'un
        // système de fichiers plein ne peut pas remplir : SIGBUS, comme Linux.
        14 if matches!(cause, Some(Echec::HorsDuFichier | Echec::PlusDePlace)) => (SIGBUS, BUS_ADRERR, cr2),
        // Pas de zone (ou une adresse du noyau) : SEGV_MAPERR ; une zone qui
        // ne permet pas l'accès : SEGV_ACCERR.
        14 if cause == Some(Echec::AccesInterdit) => (SIGSEGV, SEGV_ACCERR, cr2),
        14 => (SIGSEGV, SEGV_MAPERR, cr2),
        0 => (SIGFPE, FPE_INTDIV, rip),
        // x87 et SIMD : la raison, d'après l'état du processeur (le
        // `math_error` de Linux).
        16 | 19 => (SIGFPE, code_fpu(vecteur), rip),
        // #DB : le pas-à-pas (DR6.BS) ou `icebp` ; si_addr, l'instruction
        // suivante (`exc_debug_user`, `get_si_code`).
        1 => (SIGTRAP, if dr6 & 1 << 14 != 0 { TRAP_TRACE } else { TRAP_BRKPT }, rip),
        3 => (SIGTRAP, SI_KERNEL, 0),
        6 => (SIGILL, ILL_ILLOPN, rip),
        // SSE sans le contexte prêt (étape 5, sous-étape 9) : ne doit pas
        // arriver.
        7 => (SIGILL, SI_KERNEL, 0),
        // Segment absent, faute de pile : SIGBUS (`exc_segment_not_present`,
        // `exc_stack_segment`) ; l'alignement : SIGBUS BUS_ADRALN, sans
        // adresse.
        11 | 12 => (SIGBUS, SI_KERNEL, 0),
        17 => (SIGBUS, BUS_ADRALN, 0),
        // Protection générale, et le reste : SIGSEGV, du noyau, sans adresse.
        _ => (SIGSEGV, SI_KERNEL, 0),
    };
    (signal, Raison { vecteur, rip, rsp: cadre.rsp, code: cadre.code_erreur, cr2, cause, zone, si_code, si_addr })
}

/// Le si_code d'une exception x87 (#MF, 16) ou SIMD (#XM, 19), d'après
/// l'état du programme, encore dans les registres (le `fpu__exception_code`
/// de Linux) : les exceptions signalées et non masquées (x87 : le mot
/// d'état et le mot de contrôle ; SIMD : MXCSR), dans l'ordre de Linux.
fn code_fpu(vecteur: usize) -> i32 {
    match crate::sse::exceptions_en_attente(vecteur) {
        e if e & 0x001 != 0 => 7, // FPE_FLTINV
        e if e & 0x004 != 0 => 3, // FPE_FLTDIV
        e if e & 0x008 != 0 => 4, // FPE_FLTOVF
        e if e & 0x012 != 0 => 5, // FPE_FLTUND
        e if e & 0x020 != 0 => 6, // FPE_FLTRES
        // Linux n'envoie alors rien (une exception fantôme) ; nous envoyons
        // SIGFPE sans raison : l'instruction referait la même faute.
        _ => 0,
    }
}
