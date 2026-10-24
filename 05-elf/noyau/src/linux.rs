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

use crate::espace_utilisateur;
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
    // Les octets du programme passent par un tampon du noyau : on lit sa
    // mémoire d'abord, sans rien tenir, puis on écrit sur la console (qui,
    // elle, prend son verrou).
    let mut copie = [0u8; ECRITURE_MAX];
    let n = (nombre as usize).min(ECRITURE_MAX);
    if espace_utilisateur::lire_courant(tampon, &mut copie[..n]).is_err() {
        return -EFAULT;
    }
    console::ecrire_octets(&copie[..n]);
    n as i64
}
