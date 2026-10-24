//! Les appels système de Linux : ce que le noyau offre aux programmes
//! Linux (la « couche de compatibilité », voir CLAUDE.md).
//!
//! Un programme demande un service par son NUMÉRO, celui de Linux sur
//! x86_64 (arch/x86/entry/syscalls/syscall_64.tbl), avec jusqu'à six
//! arguments, et reçoit un nombre : le résultat, ou une erreur, codée
//! comme -errno (-14 pour EFAULT, par exemple). La glibc le transforme en
//! -1 et range le code dans errno.
//!
//! Pour l'instant, de quoi écrire et s'arrêter :
//!   - write (1) : sur la sortie standard ou d'erreur, la console ;
//!   - exit (60) et exit_group (231) : terminer. (exit ne termine que le
//!     fil d'exécution, exit_group tout le programme ; avec un seul fil,
//!     c'est pareil.)
//! Le reste rend -ENOSYS (« appel non implémenté »), comme Linux pour un
//! numéro qu'il ne connaît pas, et le noyau le signale.

use core::fmt;

use crate::copie_utilisateur::copier_depuis_utilisateur;
use crate::interruptions::Cadre;
use crate::{console, tache};

// Les numéros d'erreur de Linux (include/uapi/asm-generic/errno-base.h).
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const ENOSYS: i64 = 38;

const WRITE: u64 = 1;
const EXIT: u64 = 60;
const EXIT_GROUP: u64 = 231;

/// Le plus d'octets qu'un write écrit d'une fois : au-delà, il en écrit une
/// partie et le dit (le nombre écrit), ce que POSIX permet ; la glibc
/// recommence avec la suite. Comme pour fd_write de WASI (wasi.rs) : sur
/// un vrai port série, 1024 octets prennent déjà 90 ms, et le noyau ne doit
/// pas rester longtemps dans un seul appel.
const ECRITURE_MAX: usize = 1024;

/// Exécute l'appel système `numero` : un résultat, ou -errno.
pub fn appel(numero: u64, a: [u64; 6]) -> i64 {
    match numero {
        WRITE => write(a[0], a[1], a[2]),
        // Le code de sortie tient sur 8 bits : Linux ne garde que l'octet
        // bas (exit(256) rend 0, exit(-1) rend 255), ce que verra le futur
        // wait ; les codes 128 + N restent ceux des signaux.
        EXIT | EXIT_GROUP => tache::terminer((a[0] & 0xff) as i32),
        _ => {
            afficherln!("[noyau] appel systeme inconnu : {}", numero);
            -ENOSYS
        }
    }
}

/// write(fichier, tampon, nombre).
fn write(fichier: u64, tampon: u64, nombre: u64) -> i64 {
    if fichier != 1 && fichier != 2 {
        return -EBADF;
    }
    // Les octets du programme passent par un tampon du noyau : on copie sa
    // mémoire d'abord, sans rien tenir (une copie peut fauter), puis on
    // écrit sur la console (qui, elle, prend son verrou).
    let mut copie = [0u8; ECRITURE_MAX];
    let n = (nombre as usize).min(ECRITURE_MAX);
    if copier_depuis_utilisateur(&mut copie[..n], tampon).is_err() {
        return -EFAULT;
    }
    console::ecrire_octets(&copie[..n]);
    n as i64
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
}

impl fmt::Display for Raison {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Raison { vecteur, rip, rsp, code, cr2 } = *self;
        match vecteur {
            // Le code d'erreur d'une faute de page : bit 0 page présente
            // (sinon absente), bit 1 écriture, bit 2 venue de l'anneau 3,
            // bit 4 lecture d'instruction (NX).
            14 => write!(f, "segfault at {cr2:#x} ip {rip:#x} sp {rsp:#x} error {code:x}"),
            // `int n` vers une entrée de l'IDT interdite aux programmes : le
            // code d'erreur désigne l'entrée (n x 8, plus 2 pour « IDT »).
            // int 0x80, c'est l'ABI 32 bits de Linux.
            13 if code == 0x80 << 3 | 2 => {
                write!(f, "int 0x80 : ABI 32 bits non prise en charge, ip {rip:#x}")
            }
            13 => write!(f, "general protection fault ip {rip:#x} sp {rsp:#x} error {code:x}"),
            0 => write!(f, "trap divide error ip {rip:#x} sp {rsp:#x}"),
            1 => write!(f, "trap debug (int1 ou pas-a-pas) ip {rip:#x} sp {rsp:#x}"),
            3 => write!(f, "trap int3 ip {rip:#x} sp {rsp:#x}"),
            6 => write!(f, "trap invalid opcode ip {rip:#x} sp {rsp:#x}"),
            _ => write!(f, "exception {vecteur} ip {rip:#x} sp {rsp:#x} error {code:x}"),
        }
    }
}

/// Le signal qu'envoie Linux pour l'exception `vecteur` venue d'un
/// programme (arch/x86/kernel/traps.c), et de quoi l'expliquer. `cr2` :
/// l'adresse fautive d'une faute de page.
pub fn signal_de_l_exception(vecteur: usize, cadre: &Cadre, cr2: u64) -> (Signal, Raison) {
    let signal = match vecteur {
        0 | 16 | 19 => SIGFPE, // division, x87, SIMD
        1 | 3 => SIGTRAP,      // débogage, int3
        6 => SIGILL,           // instruction invalide
        7 => SIGILL,           // SSE sans le contexte prêt (sous-étape 9)
        17 => SIGBUS,          // alignement
        _ => SIGSEGV,          // pages, protection générale, segments
    };
    (signal, Raison { vecteur, rip: cadre.rip, rsp: cadre.rsp, code: cadre.code_erreur, cr2 })
}
