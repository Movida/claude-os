//! Les futex (« fast userspace mutex ») : le noyau de tous les verrous de
//! la glibc et de Bun. Un verrou libre se prend sans appel système (une
//! instruction atomique sur un entier du programme) ; seul celui qui doit
//! attendre appelle `futex(FUTEX_WAIT)`, et celui qui rend le verrou
//! réveille les attentes par `futex(FUTEX_WAKE)`. Le noyau ne connaît que
//! l'adresse de l'entier, et la file de ceux qui y attendent.
//!
//! En 6d, un seul fil : personne ne peut attendre pendant qu'un autre
//! s'exécute. Tout se réduit donc exactement (le tableau mesuré sur Linux
//! 6.18 est dans le plan de 6d) :
//!   - WAKE, WAKE_BITSET, REQUEUE, CMP_REQUEUE, WAKE_OP : il n'y a personne
//!     à réveiller ni à déplacer, 0 ; avec les vérifications de Linux
//!     (alignement, adresse, valeur comparée de CMP_REQUEUE), et WAKE_OP
//!     fait bien son opération sur la seconde adresse ;
//!   - WAIT, WAIT_BITSET : si l'entier ne vaut pas `val`, EAGAIN (le verrou
//!     a changé entre le moment où le programme l'a lu et l'appel) ; sinon,
//!     avec un délai, le noyau dort jusqu'à lui, puis ETIMEDOUT ; sans
//!     délai, rien ne pourrait jamais réveiller le programme (aucun autre
//!     fil, aucun signal livré avant 6f) : Linux le laisserait bloqué pour
//!     toujours, nous l'arrêtons et le disons (un écart voulu) ;
//!   - les futex à héritage de priorité (LOCK_PI...) : ENOSYS jusqu'en 6e.
//! `claude --version` ne fait que des FUTEX_WAKE_PRIVATE (37 dans la
//! trace). Le vrai futex, avec ses files d'attente par adresse, vient avec
//! les fils, en 6e.
//!
//! Le délai attendu ne compte pas dans le temps de calcul (RLIMIT_CPU) :
//! le programme dort, comme sous Linux.

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::espace_utilisateur::ADRESSE_MAX;
use crate::{linux, tache, temps};

const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EAGAIN: i64 = 11;
const ENOSYS: i64 = 38;
const ETIMEDOUT: i64 = 110;

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_REQUEUE: u32 = 3;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_WAKE_OP: u32 = 5;
const FUTEX_LOCK_PI: u32 = 6;
const FUTEX_UNLOCK_PI: u32 = 7;
const FUTEX_TRYLOCK_PI: u32 = 8;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
const FUTEX_CMP_REQUEUE_PI: u32 = 12;
const FUTEX_LOCK_PI2: u32 = 13;
/// Le futex n'est vu que par ce processus (les verrous de la glibc) : le
/// noyau n'a pas à savoir quelle page il désigne.
const FUTEX_PRIVATE_FLAG: u32 = 128;
/// Le délai absolu de WAIT_BITSET est sur CLOCK_REALTIME (sinon
/// CLOCK_MONOTONIC).
const FUTEX_CLOCK_REALTIME: u32 = 256;
/// Tous les bits : « n'importe quelle attente » (WAIT et WAKE simples).
const BITSET_TOUS: u32 = u32::MAX;

/// futex(adresse, opération, val, délai ou val2, adresse2, val3), dans
/// l'ordre de Linux (`sys_futex`, puis `do_futex`, kernel/futex/) :
///   1. pour une opération qui attend, le délai est lu (EFAULT) et vérifié
///      (EINVAL), avant tout le reste, même avant la valeur ;
///   2. FUTEX_CLOCK_REALTIME n'est permis qu'avec WAIT_BITSET (et les
///      opérations PI) : ENOSYS sinon ;
///   3. l'opération.
pub fn futex(adresse: u64, operation: u64, val: u64, delai: u64, adresse2: u64, val3: u64) -> i64 {
    let operation = operation as u32;
    let commande = operation & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let partage = operation & FUTEX_PRIVATE_FLAG == 0;
    let (val, val3) = (val as u32, val3 as u32);
    let attend = matches!(commande, FUTEX_WAIT | FUTEX_LOCK_PI | FUTEX_LOCK_PI2 | FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI);
    let mut echeance = None;
    if attend && delai != 0 {
        let mut o = [0u8; 16];
        if copier_depuis_utilisateur(&mut o, delai).is_err() {
            return -EFAULT;
        }
        let secondes = i64::from_le_bytes(o[..8].try_into().unwrap_or([0; 8]));
        let nanosecondes = i64::from_le_bytes(o[8..].try_into().unwrap_or([0; 8]));
        if secondes < 0 || !(0..1_000_000_000).contains(&nanosecondes) {
            return -EINVAL;
        }
        let duree = secondes as i128 * 1_000_000_000 + nanosecondes as i128;
        // FUTEX_WAIT : un délai relatif ; WAIT_BITSET : une échéance
        // absolue, sur l'horloge que dit FUTEX_CLOCK_REALTIME.
        echeance = Some(match commande {
            FUTEX_WAIT => Echeance::Monotone(monotone() + duree),
            _ if operation & FUTEX_CLOCK_REALTIME != 0 => Echeance::Reelle(duree),
            _ => Echeance::Monotone(duree),
        });
    }
    if operation & FUTEX_CLOCK_REALTIME != 0 && !matches!(commande, FUTEX_WAIT_BITSET | FUTEX_WAIT_REQUEUE_PI | FUTEX_LOCK_PI2) {
        return -ENOSYS;
    }
    match commande {
        FUTEX_WAIT => attendre(adresse, partage, val, echeance, BITSET_TOUS),
        FUTEX_WAIT_BITSET => attendre(adresse, partage, val, echeance, val3),
        FUTEX_WAKE => reveiller(adresse, partage, BITSET_TOUS),
        FUTEX_WAKE_BITSET => reveiller(adresse, partage, val3),
        FUTEX_REQUEUE => deplacer(adresse, partage, val, delai, adresse2, None),
        FUTEX_CMP_REQUEUE => deplacer(adresse, partage, val, delai, adresse2, Some(val3)),
        FUTEX_WAKE_OP => operer(adresse, partage, adresse2, val3),
        FUTEX_LOCK_PI | FUTEX_UNLOCK_PI | FUTEX_TRYLOCK_PI | FUTEX_WAIT_REQUEUE_PI | FUTEX_CMP_REQUEUE_PI | FUTEX_LOCK_PI2 => {
            afficherln!("[noyau] futex : operation {} (heritage de priorite) pas encore prise en charge (6e)", commande);
            -ENOSYS
        }
        _ => -ENOSYS,
    }
}

/// Quand une attente doit finir, en nanosecondes.
#[derive(Clone, Copy)]
enum Echeance {
    /// Sur CLOCK_MONOTONIC (depuis le démarrage).
    Monotone(i128),
    /// Sur CLOCK_REALTIME (depuis 1970).
    Reelle(i128),
}

impl Echeance {
    fn passee(self) -> bool {
        match self {
            Echeance::Monotone(n) => monotone() >= n,
            Echeance::Reelle(n) => {
                let t = temps::maintenant();
                t.secondes as i128 * 1_000_000_000 + t.nanosecondes as i128 >= n
            }
        }
    }
}

fn monotone() -> i128 {
    let t = temps::monotone();
    t.secondes as i128 * 1_000_000_000 + t.nanosecondes as i128
}

/// La « clé » du futex, comme `get_futex_key` : l'adresse alignée sur 4
/// (EINVAL), dans la moitié basse (EFAULT, `access_ok`) ; pour un futex
/// partagé, Linux cherche aussi la page qu'elle désigne (EFAULT si rien
/// n'y est projeté) : on la lit. Un futex privé n'est jamais lu ici
/// (mesuré : un WAKE privé à l'adresse 0 rend 0).
fn cle(adresse: u64, partage: bool) -> Result<(), i64> {
    if adresse % 4 != 0 {
        return Err(-EINVAL);
    }
    if adresse.checked_add(4).is_none_or(|fin| fin > ADRESSE_MAX) {
        return Err(-EFAULT);
    }
    if partage {
        lire(adresse)?;
    }
    Ok(())
}

fn lire(adresse: u64) -> Result<u32, i64> {
    let mut o = [0u8; 4];
    copier_depuis_utilisateur(&mut o, adresse).map_err(|_| -EFAULT)?;
    Ok(u32::from_le_bytes(o))
}

/// FUTEX_WAIT et FUTEX_WAIT_BITSET (`futex_wait`).
fn attendre(adresse: u64, partage: bool, val: u32, echeance: Option<Echeance>, bitset: u32) -> i64 {
    if bitset == 0 {
        return -EINVAL;
    }
    if let Err(e) = cle(adresse, partage) {
        return e;
    }
    match lire(adresse) {
        Err(e) => return e,
        Ok(v) if v != val => return -EAGAIN,
        Ok(_) => {}
    }
    let Some(echeance) = echeance else {
        // Le verrou ne peut pas être rendu : le programme le tenait-il
        // lui-même, ou en attendait-il un qu'aucun autre fil ne rendra ?
        tache::arreter(linux::SIGKILL, "attente sans fin d'un futex : un seul fil, rien ne peut la terminer");
    };
    // Dormir jusqu'à l'échéance : au premier tic qui la dépasse, jamais
    // avant (les tics d'une milliseconde arrondissent au-dessus).
    tache::dormir_jusqu_a(|| echeance.passee());
    -ETIMEDOUT
}

/// FUTEX_WAKE et FUTEX_WAKE_BITSET (`futex_wake`) : personne à réveiller.
fn reveiller(adresse: u64, partage: bool, bitset: u32) -> i64 {
    if bitset == 0 {
        return -EINVAL;
    }
    match cle(adresse, partage) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// FUTEX_REQUEUE et FUTEX_CMP_REQUEUE (`futex_requeue`) : réveiller `val`
/// attentes de la première adresse, et déplacer les suivantes, jusqu'à
/// `val2` (passé à la place du délai), vers la seconde. Personne
/// n'attend : 0, une fois les deux clés vérifiées, et pour CMP_REQUEUE la
/// valeur de la première comparée à `val3` (EAGAIN).
fn deplacer(adresse: u64, partage: bool, val: u32, val2: u64, adresse2: u64, attendue: Option<u32>) -> i64 {
    if (val as i32) < 0 || (val2 as u32 as i32) < 0 {
        return -EINVAL;
    }
    if let Err(e) = cle(adresse, partage).and_then(|_| cle(adresse2, partage)) {
        return e;
    }
    if let Some(attendue) = attendue {
        match lire(adresse) {
            Err(e) => return e,
            Ok(v) if v != attendue => return -EAGAIN,
            Ok(_) => {}
        }
    }
    0
}

/// FUTEX_WAKE_OP (`futex_wake_op`) : changer l'entier de la seconde adresse
/// par une opération, et réveiller sur l'une, puis sur l'autre selon
/// l'ancienne valeur. Personne à réveiller : reste l'opération, codée dans
/// `codee` (`futex_atomic_op_inuser`) :
///   bits 28-31 : l'opération (SET, ADD, OR, ANDN, XOR ; plus 8 : son
///                argument est un décalage, 1 << arg) ;
///   bits 24-27 : la comparaison (EQ, NE, LT, LE, GT, GE) ;
///   bits 12-23 : l'argument, sur 12 bits signés ; bits 0-11 : la valeur
///                comparée, de même.
/// Une opération inconnue : ENOSYS, sans rien écrire. Une comparaison
/// inconnue : ENOSYS aussi, mais APRÈS l'opération, comme Linux, qui ne la
/// regarde qu'une fois l'entier changé (mesuré : 7 + 3 donne 10, et -38).
/// Un seul fil : lire puis écrire suffit à rendre l'opération indivisible.
fn operer(adresse: u64, partage: bool, adresse2: u64, codee: u32) -> i64 {
    if let Err(e) = cle(adresse, partage).and_then(|_| cle(adresse2, partage)) {
        return e;
    }
    let mut op = codee >> 28;
    let cmp = (codee >> 24) & 0xf;
    let signe12 = |x: u32| ((x << 20) as i32) >> 20;
    let mut argument = signe12((codee >> 12) & 0xfff);
    if op & 8 != 0 {
        op &= 7;
        // Linux garde les 5 bits bas d'un décalage hors de [0, 31].
        argument = 1 << (argument & 31);
    }
    if op > 4 {
        return -ENOSYS;
    }
    let ancienne = match lire(adresse2) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let a = argument as u32;
    let nouvelle = match op {
        0 => a,
        1 => ancienne.wrapping_add(a),
        2 => ancienne | a,
        3 => ancienne & !a,
        _ => ancienne ^ a,
    };
    if copier_vers_utilisateur(adresse2, &nouvelle.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    if cmp > 5 {
        return -ENOSYS;
    }
    0
}
