//! Les fils d'un processus : ce qui est à chacun d'eux, et pas au processus
//! qu'ils partagent.
//!
//! Un processus Linux est un GROUPE DE FILS (le « thread group ») qui
//! partagent tout ce qui fait le programme : sa mémoire, ses descripteurs,
//! son dossier courant, son identité, ses limites, l'action de chaque
//! signal, les signaux envoyés au processus. Chaque fil a, lui, ce qui fait
//! une exécution : son numéro (le tid ; celui du fil principal est le pid),
//! son nom (le `comm`), ses registres, sa pile noyau, son état x87/SSE et
//! sa base de FS, son temps de calcul (tout cela dans sa tâche, tache.rs),
//! et, ici, ce qui touche aux signaux : son masque, les signaux envoyés à
//! lui seul (tkill, une faute), sa pile de secours.
//!
//! Le partage, ligne par ligne (le tableau de la section 4 du plan de 6e) :
//!
//! | Au processus (partagé par ses fils)      | Au fil                       |
//! |------------------------------------------|------------------------------|
//! | pid, mémoire, descripteurs, dossiers,    | tid, nom, état, pile noyau,  |
//! | umask, identité, limites                 | registres, x87/SSE, base FS  |
//! | actions des signaux, signaux envoyés au  | masque, signaux envoyés au   |
//! | processus, fin de groupe et son code     | fil, pile de secours, signal |
//! |                                          | forcé d'une faute            |
//! | temps de calcul de tous ses fils         | temps de calcul              |
//!
//! Les `Fil` d'un processus sont rangés DANS le processus (`Processus::fils`),
//! sous son verrou : c'est le `siglock` de Linux, un seul verrou pour les
//! actions, les signaux du processus, et le masque et les signaux de chacun
//! de ses fils (envoyer un signal au processus, c'est choisir un fil qui ne
//! le bloque pas : il faut voir les deux ensemble). La liste sert aussi de
//! liste des fils du groupe (le `thread_head` de Linux), pour réveiller,
//! arrêter (exit_group) ou montrer (/proc/<pid>/task) chacun d'eux.
//! Options écartées :
//!   - l'état des signaux du fil dans sa tâche, sous un verrou à elle : deux
//!     verrous à prendre dans le bon ordre pour chaque signal, sans rien
//!     gagner (un fil ne change son masque qu'en appel système, où il prend
//!     de toute façon celui du processus) ;
//!   - le même dans sa tâche, mais protégé par le verrou du processus
//!     (exactement Linux) : en Rust, une cellule que garde le verrou d'un
//!     autre objet demande du code `unsafe` à chaque accès, et un noyau qui
//!     le réserve au matériel ne le veut pas.
//!
//! Un fil naît de clone ou de clone3 (plus bas), et finit par exit, par la
//! fin de son groupe, ou avec son processus (tache.rs).

use alloc::sync::{Arc, Weak};

use crate::copie_utilisateur::{copier_depuis_utilisateur, dans_les_bornes};
use crate::espace_utilisateur::ADRESSE_MAX;
use crate::interruptions::Cadre;
use crate::processus;
use crate::signaux::SignauxDuFil;
use crate::tache::{self, NouveauFil, Tache};

const PAGE: u64 = 4096;

/// Un fil d'un processus, vu du processus.
pub struct Fil {
    /// Son numéro (le tid) : celui de sa tâche.
    pub tid: u32,
    /// Sa tâche, pour la réveiller (un signal) : un lien faible, pour que le
    /// processus et ses tâches ne se tiennent pas l'un l'autre (une tâche
    /// tient son processus). Il ne sert que tant que le fil est dans la
    /// liste : sa tâche l'en retire en mourant.
    pub tache: Weak<Tache>,
    /// Son masque, ses signaux, sa pile de secours (signaux.rs).
    pub signaux: SignauxDuFil,
}

impl Fil {
    /// Le fil de la tâche `t`, sans signal bloqué ni en attente ni pile de
    /// secours (comme le fil principal d'un programme qui commence).
    pub fn de(t: &Arc<Tache>) -> Fil {
        Fil { tid: t.tid(), tache: Arc::downgrade(t), signaux: SignauxDuFil::default() }
    }
}

/// Exécute `f` sur le fil courant, sous le verrou de son processus (il y en
/// a toujours un pendant un appel système d'un programme Linux) : court, et
/// sans copie vers ou depuis le programme, comme `processus::avec`.
pub fn avec<R>(f: impl FnOnce(&mut Fil) -> R) -> R {
    let tid = tache::courante().tid();
    processus::avec(|p| f(p.fil(tid).expect("appel systeme d'un fil qui a quitte son processus")))
}

// ----- clone et clone3 -----

// Les drapeaux de clone (include/uapi/linux/sched.h).
const CSIGNAL: u64 = 0xff;
const CLONE_NEWTIME: u64 = 0x80;
const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_PTRACE: u64 = 0x2000;
const CLONE_PARENT: u64 = 0x8000;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_NEWNS: u64 = 0x20000;
const CLONE_SYSVSEM: u64 = 0x40000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_DETACHED: u64 = 0x400000;
const CLONE_UNTRACED: u64 = 0x800000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;
const CLONE_NEWCGROUP: u64 = 0x2000000;
const CLONE_NEWUTS: u64 = 0x4000000;
const CLONE_NEWIPC: u64 = 0x8000000;
const CLONE_NEWUSER: u64 = 0x10000000;
const CLONE_NEWPID: u64 = 0x20000000;
const CLONE_NEWNET: u64 = 0x40000000;
const CLONE_IO: u64 = 0x80000000;
/// Ceux de clone3 seulement.
const CLONE_CLEAR_SIGHAND: u64 = 1 << 32;
const CLONE_INTO_CGROUP: u64 = 1 << 33;
/// Les nouveaux espaces de noms.
const CLONE_NEW: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID
    | CLONE_NEWNET | CLONE_NEWTIME;
/// Ce qu'un fil (un `pthread_create`) demande toujours : la même mémoire,
/// les mêmes actions des signaux, le même groupe, les mêmes dossiers, les
/// mêmes descripteurs.
const UN_FIL: u64 = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD | CLONE_FS | CLONE_FILES;
/// Ce qui ne change rien ici : les sémaphores System V (nous n'en avons
/// pas), le traçage (pas de ptrace), la priorité d'entrées-sorties.
const SANS_EFFET: u64 = CLONE_SYSVSEM | CLONE_PTRACE | CLONE_UNTRACED | CLONE_IO | CLONE_PARENT | CLONE_DETACHED;

const EPERM: i64 = 1;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const E2BIG: i64 = 7;

/// Ce que demande un clone ou un clone3 (le `kernel_clone_args` de Linux).
struct Demande {
    drapeaux: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    /// Le haut de la pile du fil (0 : celle du créateur).
    pile: u64,
    tls: u64,
}

/// clone(drapeaux, pile, parent_tid, child_tid, tls), dans l'ordre des
/// arguments de x86_64. Seuls les 32 bits bas des drapeaux comptent
/// (mesuré : `clone(SIGCHLD | 0xffffffff00000000)` crée l'enfant) ; l'octet
/// bas est le signal de fin (CSIGNAL) ; CLONE_PIDFD rendrait son
/// descripteur à `parent_tid` (pas encore : ENOSYS, voir `cloner`).
/// `cadre` : celui de l'appel du créateur.
pub fn clone(drapeaux: u64, pile: u64, parent_tid: u64, child_tid: u64, tls: u64, cadre: &Cadre) -> i64 {
    let bas = drapeaux & 0xffff_ffff;
    // Le signal de fin (l'octet bas) ne sert qu'à un processus neuf (6k) :
    // celui d'un fil est ignoré, comme chez Linux.
    let d = Demande { drapeaux: bas & !CSIGNAL, pidfd: parent_tid, child_tid, parent_tid, pile, tls };
    cloner(d, cadre)
}

/// La taille de la `struct clone_args` dans ses trois versions (VER0 à
/// VER2) : 8 champs, puis set_tid et sa taille, puis cgroup.
const CLONE_ARGS_VER0: u64 = 64;
const CLONE_ARGS_VER2: u64 = 88;

/// clone3(arguments, taille), dans l'ordre de `kernel/fork.c` (Linux 6.18,
/// lu) :
///   1. la taille : plus d'une page, E2BIG ; moins que la première version
///      (64 octets), EINVAL ; au-delà de ce que nous connaissons (88
///      octets), que des zéros (E2BIG : la règle de `copy_struct_from_user`,
///      pour qu'un programme plus récent sache qu'un champ n'est pas
///      compris), puis la structure copiée (EFAULT) ;
///   2. `set_tid` (choisir son numéro, dans des espaces de noms) : au plus
///      32, l'adresse et la taille ensemble ; le signal de fin, un vrai
///      signal sur l'octet bas ; CLONE_INTO_CGROUP avec la version 2
///      (EINVAL) ;
///   3. `clone3_args_valid` (EINVAL) : pas de drapeau inconnu, ni
///      CLONE_DETACHED ni les bits du signal (libérés dans clone3, sauf
///      CLONE_NEWTIME) ; pas CLONE_CLEAR_SIGHAND avec CLONE_SIGHAND ; pas
///      de signal de fin pour un fil (CLONE_THREAD) ou CLONE_PARENT ; la
///      pile et sa taille données ensemble, la pile dans les adresses des
///      programmes (son haut : pile + taille) ;
///   4. puis comme clone (`kernel_clone`).
/// glibc essaie clone3 d'abord, puis clone s'il rend ENOSYS : le filtre
/// seccomp de Docker le fait (mesuré dans le devcontainer).
pub fn clone3(adresse: u64, taille: u64, cadre: &Cadre) -> i64 {
    if taille > PAGE {
        return -E2BIG;
    }
    if taille < CLONE_ARGS_VER0 {
        return -EINVAL;
    }
    // Au-delà de ce que nous connaissons d'abord (E2BIG, ou EFAULT), par
    // morceaux : pas une page entière sur la pile du noyau ; puis ce que
    // nous connaissons (88 octets au plus, des zéros derrière une version
    // plus courte). L'ordre de `copy_struct_from_user`.
    let mut lu = CLONE_ARGS_VER2;
    while lu < taille {
        let mut morceau = [0u8; 64];
        let n = (taille - lu).min(64) as usize;
        if copier_depuis_utilisateur(&mut morceau[..n], adresse + lu).is_err() {
            return -EFAULT;
        }
        if morceau[..n].iter().any(|&o| o != 0) {
            return -E2BIG;
        }
        lu += n as u64;
    }
    let mut octets = [0u8; CLONE_ARGS_VER2 as usize];
    let connue = taille.min(CLONE_ARGS_VER2) as usize;
    if copier_depuis_utilisateur(&mut octets[..connue], adresse).is_err() {
        return -EFAULT;
    }
    let champ = |i: usize| u64::from_le_bytes(octets[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
    let (drapeaux, pidfd, child_tid, parent_tid, exit_signal) = (champ(0), champ(1), champ(2), champ(3), champ(4));
    let (pile, taille_pile, tls, set_tid, set_tid_taille, cgroup) = (champ(5), champ(6), champ(7), champ(8), champ(9), champ(10));
    if set_tid_taille > 32 || (set_tid == 0) != (set_tid_taille == 0) {
        return -EINVAL;
    }
    if exit_signal & !CSIGNAL != 0 || exit_signal > crate::signaux::NSIG {
        return -EINVAL;
    }
    if drapeaux & CLONE_INTO_CGROUP != 0 && (cgroup > i32::MAX as u64 || taille < CLONE_ARGS_VER2) {
        return -EINVAL;
    }
    let connus = 0xffff_ffff | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP;
    if drapeaux & !connus != 0
        || drapeaux & (CLONE_DETACHED | (CSIGNAL & !CLONE_NEWTIME)) != 0
        || drapeaux & (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND) == CLONE_SIGHAND | CLONE_CLEAR_SIGHAND
        || (drapeaux & (CLONE_THREAD | CLONE_PARENT) != 0 && exit_signal != 0)
    {
        return -EINVAL;
    }
    let haut = match (pile, taille_pile) {
        (0, 0) => 0,
        (0, _) | (_, 0) => return -EINVAL,
        (p, t) if !dans_les_bornes(p, t) => return -EINVAL,
        (p, t) => p + t,
    };
    if set_tid != 0 || drapeaux & (CLONE_INTO_CGROUP | CLONE_CLEAR_SIGHAND) != 0 {
        afficherln!("[noyau] clone3 : set_tid, CLONE_INTO_CGROUP et CLONE_CLEAR_SIGHAND pas pris en charge");
        return -ENOSYS;
    }
    cloner(Demande { drapeaux, pidfd, child_tid, parent_tid, pile: haut, tls }, cadre)
}

/// La suite commune de clone et clone3 : `kernel_clone`, puis les
/// vérifications de `copy_process`, dans leur ordre (EINVAL) : CLONE_PIDFD
/// avec CLONE_PARENT_SETTID à la même adresse, ou avec CLONE_DETACHED ; CLONE_NEWNS
/// ou CLONE_NEWUSER avec CLONE_FS ; un fil (CLONE_THREAD) sans les actions
/// des signaux (CLONE_SIGHAND), qui elles-mêmes demandent la mémoire
/// (CLONE_VM) ; un fil dans un nouvel espace de noms d'utilisateurs ou de
/// processus. Puis ce que nous savons faire : un FIL du processus, ce que
/// fait `pthread_create`. Un nouvel espace de noms : EPERM, ce que reçoit
/// tout programme qui n'est pas root (sauf pour CLONE_NEWUSER, que Linux
/// lui permet : un écart). Un nouveau processus (fork, vfork, posix_spawn)
/// viendra en 6k : ENOSYS, avec un message. Puis la base de FS de
/// CLONE_SETTLS, vérifiée tard comme le `set_new_tls` de Linux (EPERM hors
/// des adresses des programmes), et le fil (tache::lancer_fil).
fn cloner(d: Demande, cadre: &Cadre) -> i64 {
    let f = d.drapeaux;
    if f & CLONE_PIDFD != 0 && f & CLONE_PARENT_SETTID != 0 && d.pidfd == d.parent_tid {
        return -EINVAL;
    }
    // (clone3 a déjà refusé CLONE_DETACHED ; clone le garde, sauf avec
    // CLONE_PIDFD, dont il garde le bit pour plus tard.)
    if f & CLONE_PIDFD != 0 && f & CLONE_DETACHED != 0 {
        return -EINVAL;
    }
    if f & CLONE_FS != 0 && f & (CLONE_NEWNS | CLONE_NEWUSER) != 0 {
        return -EINVAL;
    }
    if (f & CLONE_THREAD != 0 && f & CLONE_SIGHAND == 0) || (f & CLONE_SIGHAND != 0 && f & CLONE_VM == 0) {
        return -EINVAL;
    }
    if f & CLONE_THREAD != 0 && f & (CLONE_NEWUSER | CLONE_NEWPID) != 0 {
        return -EINVAL;
    }
    if f & CLONE_NEW != 0 {
        return -EPERM;
    }
    let geres = UN_FIL | SANS_EFFET | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    if f & UN_FIL != UN_FIL || f & !geres != 0 {
        afficherln!("[noyau] clone : seulement des fils (pthread_create) ; un processus neuf (fork, vfork) viendra en 6k");
        return -ENOSYS;
    }
    let tls = if f & CLONE_SETTLS != 0 {
        if d.tls >= ADRESSE_MAX {
            return -EPERM;
        }
        Some(d.tls)
    } else {
        None
    };
    // Le cadre du fil : celui de l'appel de son créateur, qui revient de
    // clone avec 0, sur la pile donnée (ou la même : un fil sans pile à lui
    // écraserait celle de son créateur, c'est son affaire, comme chez
    // Linux).
    let mut depart = *cadre;
    depart.rax = 0;
    if d.pile != 0 {
        depart.rsp = d.pile;
    }
    let n = NouveauFil {
        cadre: depart,
        tls,
        ecrire_tid: if f & CLONE_CHILD_SETTID != 0 { d.child_tid } else { 0 },
        effacer_tid: if f & CLONE_CHILD_CLEARTID != 0 { d.child_tid } else { 0 },
        parent_tid: if f & CLONE_PARENT_SETTID != 0 { d.parent_tid } else { 0 },
    };
    match tache::lancer_fil(n) {
        Ok(tid) => tid as i64,
        Err(e) => e,
    }
}
