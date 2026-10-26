//! Les futex (« fast userspace mutex ») : le noyau de tous les verrous de
//! la glibc et de Bun. Un verrou libre se prend sans appel système (une
//! instruction atomique sur un entier du programme) ; seul celui qui doit
//! attendre appelle `futex(FUTEX_WAIT)`, et celui qui rend le verrou
//! réveille les attentes par `futex(FUTEX_WAKE)`. Le noyau ne connaît que
//! l'adresse de l'entier, et la file de ceux qui y attendent.
//!
//! Comme Linux (kernel/futex/) : 256 SEAUX (les `futex_hash_bucket`),
//! chacun une file d'attente sous son verrou ; une attente est rangée dans
//! le seau de sa CLÉ, hachée. La clé : le processus (son espace
//! d'adressage), l'adresse, et si le futex est partagé. Linux, pour un
//! futex partagé d'une page de fichier projetée en commun (MAP_SHARED),
//! prend l'inode et la position dans le fichier, pour que deux processus
//! se rencontrent ; sans MAP_SHARED ni fork (6k), un futex partagé ne peut
//! être vu que par son processus, et la clé de Linux pour une page anonyme
//! est la nôtre (`get_futex_key`). Une attente privée et une partagée à la
//! même adresse ne se rencontrent jamais (mesuré : la clé dit « partagé »).
//!
//! WAIT sans réveil perdu : l'entier est relu SOUS le verrou du seau, puis
//! l'attente inscrite, puis la tâche dort ; un WAKE prend le même verrou
//! pour retirer l'attente de la file et réveiller la tâche. Qu'une attente
//! ait été réveillée par un WAKE se décide par là : retirée de la file par
//! le réveilleur, elle rend 0, même si son échéance ou un signal sont
//! arrivés aussi ; encore dans la file, elle s'en retire elle-même et rend
//! ETIMEDOUT ou EINTR (`futex_unqueue`). Sinon, un WAKE compté (et rendu à
//! qui réveille) serait perdu : une condition de la glibc ne se réveillerait
//! plus. Relire l'entier sous un verrou demande une lecture qui ne SERT
//! PAS une faute de page (servir prend le verrou du processus, et attendra
//! le disque en 6l) : en cas de faute, on rend le verrou, on fait venir la
//! page par une lecture ordinaire, et on recommence (`futex_wait_setup`).
//!
//! Les futex à héritage de priorité (LOCK_PI...) : ENOSYS, avec un
//! message. Ni `claude` (mesuré sur `--help`) ni la glibc par défaut ne
//! s'en servent, et l'héritage de priorité n'a de sens qu'avec des
//! priorités temps réel, que nous n'avons pas.
//!
//! Le délai attendu ne compte pas dans le temps de calcul (RLIMIT_CPU) :
//! le programme dort, comme sous Linux.

use crate::attente::{self, FileAttente, Sommeil};
use crate::copie_utilisateur::{self, copier_depuis_utilisateur};
use crate::espace_utilisateur::ADRESSE_MAX;
use crate::memoire::Acces;
use crate::tache::Reveil;
use crate::verrou::Verrou;
use crate::{cpu, processus, tache, temps};

const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EAGAIN: i64 = 11;
const ENOSYS: i64 = 38;
const ETIMEDOUT: i64 = 110;
const EINTR: i64 = 4;

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
        FUTEX_WAKE => reveiller(adresse, partage, val, BITSET_TOUS),
        FUTEX_WAKE_BITSET => reveiller(adresse, partage, val, val3),
        FUTEX_REQUEUE => deplacer(adresse, partage, val, delai, adresse2, None),
        FUTEX_CMP_REQUEUE => deplacer(adresse, partage, val, delai, adresse2, Some(val3)),
        FUTEX_WAKE_OP => operer(adresse, partage, val, delai, adresse2, val3),
        FUTEX_LOCK_PI | FUTEX_UNLOCK_PI | FUTEX_TRYLOCK_PI | FUTEX_WAIT_REQUEUE_PI | FUTEX_CMP_REQUEUE_PI | FUTEX_LOCK_PI2 => {
            afficherln!("[noyau] futex : operation {} (heritage de priorite) non prise en charge", commande);
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
    /// L'échéance, en temps monotone (ns). Une échéance sur CLOCK_REALTIME
    /// est traduite d'après l'écart entre les deux horloges, qui ne change
    /// pas : la date ne se règle pas encore (pas de clock_settime).
    fn en_monotone(self) -> u64 {
        let n = match self {
            Echeance::Monotone(n) => n,
            Echeance::Reelle(n) => {
                let t = temps::maintenant();
                n - (t.secondes as i128 * 1_000_000_000 + t.nanosecondes as i128) + monotone()
            }
        };
        n.clamp(0, u64::MAX as i128) as u64
    }
}

fn monotone() -> i128 {
    let t = temps::monotone();
    t.secondes as i128 * 1_000_000_000 + t.nanosecondes as i128
}

/// La clé d'un futex (voir l'en-tête).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cle {
    pid: u32,
    adresse: u64,
    partage: bool,
}

/// Ce que la tâche qui attend un futex en dit (dans sa tâche, sous le
/// verrou du seau où elle attend) : sa clé, et son masque de bits.
#[derive(Clone, Copy)]
pub struct Attente {
    cle: Cle,
    bitset: u32,
}

/// Un seau : la file des tâches qui attendent un futex dont la clé y mène.
struct Seau {
    file: FileAttente,
}

const SEAUX: usize = 256;
static TABLE: [Verrou<Seau>; SEAUX] = [const { Verrou::new(Seau { file: FileAttente::new() }) }; SEAUX];

/// Le seau de la clé : un mélange de ses champs (le multiplicateur de
/// Fibonacci, comme le `hash_long` de Linux), ses 8 bits hauts.
fn seau(c: &Cle) -> usize {
    let x = (c.adresse >> 2) ^ (c.pid as u64) << 40 ^ c.partage as u64;
    (x.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as usize
}

/// La clé du futex à `adresse`, comme `get_futex_key` : l'adresse alignée
/// sur 4 (EINVAL), dans la moitié basse (EFAULT, `access_ok`). Pour un
/// futex partagé, Linux cherche aussi la page, POUR L'ÉCRIRE (EFAULT si
/// elle ne peut pas l'être : mesuré, une page anonyme en lecture seule,
/// même après mprotect ; la page de zéros, elle, se copie) : on la sert
/// comme une faute en écriture. Un futex privé n'est jamais touché ici
/// (mesuré : un WAKE privé à l'adresse 0 rend 0).
fn cle(adresse: u64, partage: bool) -> Result<Cle, i64> {
    if adresse % 4 != 0 {
        return Err(-EINVAL);
    }
    if adresse.checked_add(4).is_none_or(|fin| fin > ADRESSE_MAX) {
        return Err(-EFAULT);
    }
    if partage && processus::avec(|p| p.memoire.servir(adresse, Acces::Ecriture)).is_err() {
        return Err(-EFAULT);
    }
    Ok(Cle { pid: processus::avec(|p| p.pid), adresse, partage })
}

fn lire(adresse: u64) -> Result<u32, i64> {
    let mut o = [0u8; 4];
    copier_depuis_utilisateur(&mut o, adresse).map_err(|_| -EFAULT)?;
    Ok(u32::from_le_bytes(o))
}

/// Lit l'entier sans servir de faute de page (sous le verrou d'un seau) :
/// None si la page n'est pas là.
fn lire_sans_faute(adresse: u64) -> Option<u32> {
    let mut o = [0u8; 4];
    tache::sans_faute_servie(|| copier_depuis_utilisateur(&mut o, adresse)).ok()?;
    Some(u32::from_le_bytes(o))
}

/// FUTEX_WAIT et FUTEX_WAIT_BITSET (`futex_wait`).
fn attendre(adresse: u64, partage: bool, val: u32, echeance: Option<Echeance>, bitset: u32) -> i64 {
    if bitset == 0 {
        return -EINVAL;
    }
    let c = match cle(adresse, partage) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let echeance = echeance.map(Echeance::en_monotone);
    let interruptions = cpu::couper_interruptions();
    let r = loop {
        let mut s = TABLE[seau(&c)].verrouiller();
        match lire_sans_faute(adresse) {
            None => {
                // La page n'est pas là : la faire venir, verrou rendu, et
                // recommencer.
                drop(s);
                cpu::activer_interruptions();
                let lue = lire(adresse);
                cpu::couper_interruptions();
                if let Err(e) = lire_ok(lue) {
                    break e;
                }
                continue;
            }
            Some(v) if v != val => break -EAGAIN,
            Some(_) => {}
        }
        tache::courante().futex().set(Some(Attente { cle: c, bitset }));
        s.file.inscrire();
        drop(s);
        let reveil = attente::dormir(echeance, Sommeil::Interruptible);
        // Réveillée : par un WAKE (elle n'est plus dans la file), ou par son
        // échéance ou un signal (elle y est encore). Un REQUEUE a pu la
        // déplacer dans le seau d'une autre clé : sa clé le dit.
        let t = tache::courante();
        let ou = t.futex().get().map_or(c, |a| a.cle);
        let mut s = TABLE[seau(&ou)].verrouiller();
        let encore = s.file.contient(t);
        s.file.retirer(t);
        drop(s);
        t.futex().set(None);
        if !encore {
            break 0;
        }
        match reveil {
            Reveil::Echeance => break -ETIMEDOUT,
            Reveil::Signal => break -EINTR,
            // Réveillée sans être retirée (personne ne le fait) : se rendort.
            Reveil::Reveillee => continue,
        }
    };
    if interruptions {
        cpu::activer_interruptions();
    }
    r
}

fn lire_ok(r: Result<u32, i64>) -> Result<(), i64> {
    r.map(|_| ())
}

/// Réveille au plus `n` attentes de la clé `c` dont le masque croise
/// `bitset`, dans le seau `s` (verrou tenu) ; rend leur nombre.
fn reveiller_dans(s: &mut Seau, c: &Cle, bitset: u32, n: u32) -> u32 {
    let mut faits = 0;
    while faits < n {
        let Some(t) = s.file.retirer_si(|t| t.futex().get().is_some_and(|a| a.cle == *c && a.bitset & bitset != 0)) else { break };
        tache::reveiller(t, Reveil::Reveillee);
        faits += 1;
    }
    faits
}

/// FUTEX_WAKE et FUTEX_WAKE_BITSET (`futex_wake`) : réveille jusqu'à `val`
/// attentes (au moins une : 0 et les nombres négatifs en réveillent une,
/// mesuré), rend leur nombre.
fn reveiller(adresse: u64, partage: bool, val: u32, bitset: u32) -> i64 {
    if bitset == 0 {
        return -EINVAL;
    }
    let c = match cle(adresse, partage) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let n = if (val as i32) <= 0 { 1 } else { val };
    reveiller_dans(&mut TABLE[seau(&c)].verrouiller(), &c, bitset, n) as i64
}

/// Réveille au plus `n` attentes du futex PARTAGÉ à `adresse` du processus
/// en cours (la fin d'un fil : CLONE_CHILD_CLEARTID et la liste robuste,
/// fils.rs), sans les vérifications d'un appel.
#[allow(dead_code)]
pub fn reveiller_partage(adresse: u64, n: u32) {
    let c = Cle { pid: processus::avec(|p| p.pid), adresse, partage: true };
    reveiller_dans(&mut TABLE[seau(&c)].verrouiller(), &c, BITSET_TOUS, n);
}

/// Les verrous des seaux `a` et `b`, dans l'ordre des numéros (un seul si
/// c'est le même) : deux appels qui prendraient les mêmes seaux dans
/// l'ordre inverse se bloqueraient l'un l'autre avec plusieurs
/// processeurs.
fn deux_seaux(a: usize, b: usize, f: impl FnOnce(&mut Seau, Option<&mut Seau>) -> i64) -> i64 {
    if a == b {
        return f(&mut TABLE[a].verrouiller(), None);
    }
    let (premier, second) = (a.min(b), a.max(b));
    let mut p = TABLE[premier].verrouiller();
    let mut s = TABLE[second].verrouiller();
    if a < b { f(&mut p, Some(&mut s)) } else { f(&mut s, Some(&mut p)) }
}

/// FUTEX_REQUEUE et FUTEX_CMP_REQUEUE (`futex_requeue`) : réveiller `val`
/// attentes de la première clé, et déplacer les suivantes, jusqu'à `val2`
/// (passé à la place du délai), vers la seconde. Pour CMP_REQUEUE, la
/// valeur de la première est d'abord comparée à `attendue` (EAGAIN), sous
/// les verrous. Rend le nombre d'attentes réveillées plus déplacées.
fn deplacer(adresse: u64, partage: bool, val: u32, val2: u64, adresse2: u64, attendue: Option<u32>) -> i64 {
    if (val as i32) < 0 || (val2 as u32 as i32) < 0 {
        return -EINVAL;
    }
    let (c1, c2) = match cle(adresse, partage).and_then(|a| cle(adresse2, partage).map(|b| (a, b))) {
        Ok(c) => c,
        Err(e) => return e,
    };
    loop {
        let mut faute = false;
        let r = deux_seaux(seau(&c1), seau(&c2), |s1, mut s2| {
            if let Some(attendue) = attendue {
                match lire_sans_faute(adresse) {
                    None => {
                        faute = true;
                        return 0;
                    }
                    Some(v) if v != attendue => return -EAGAIN,
                    Some(_) => {}
                }
            }
            let reveillees = reveiller_dans(s1, &c1, BITSET_TOUS, val);
            // Vers la même clé : rien ne bouge, mais Linux compte celles
            // qu'il aurait déplacées (un seul parcours de la file). Les
            // retirer et les remettre à la fin, comme pour une autre clé,
            // les ferait retrouver sans fin : `val2` tours, interruptions
            // coupées (2^31 : des minutes de machine figée).
            if c1 == c2 {
                let restantes = s1.file.compter(|t| t.futex().get().is_some_and(|a| a.cle == c1));
                return (reveillees as u64 + (restantes as u64).min(val2)) as i64;
            }
            let mut deplacees = 0;
            while deplacees < val2 as u32 {
                let Some(t) = s1.file.retirer_si(|t| t.futex().get().is_some_and(|a| a.cle == c1)) else { break };
                let bitset = t.futex().get().map_or(BITSET_TOUS, |a| a.bitset);
                t.futex().set(Some(Attente { cle: c2, bitset }));
                // Dans la file du seau de la seconde clé (le même, ou l'autre).
                match s2.as_deref_mut() {
                    Some(s2) => s2.file.inscrire_tache(t),
                    None => s1.file.inscrire_tache(t),
                }
                deplacees += 1;
            }
            (reveillees + deplacees) as i64
        });
        if !faute {
            return r;
        }
        if let Err(e) = lire(adresse) {
            return e;
        }
    }
}

/// FUTEX_WAKE_OP (`futex_wake_op`) : changer l'entier de la seconde adresse
/// par une opération, et réveiller sur l'une, puis sur l'autre selon
/// l'ancienne valeur. L'opération, codée dans `codee`
/// (`futex_atomic_op_inuser`) :
///   bits 28-31 : l'opération (SET, ADD, OR, ANDN, XOR ; plus 8 : son
///                argument est un décalage, 1 << arg) ;
///   bits 24-27 : la comparaison (EQ, NE, LT, LE, GT, GE) ;
///   bits 12-23 : l'argument, sur 12 bits signés ; bits 0-11 : la valeur
///                comparée, de même.
/// Une opération inconnue : ENOSYS, sans rien écrire. Une comparaison
/// inconnue : ENOSYS aussi, mais APRÈS l'opération, comme Linux, qui ne la
/// regarde qu'une fois l'entier changé (mesuré : 7 + 3 donne 10, et -38).
/// L'opération est indivisible (`lock cmpxchg`, recommencé si l'entier a
/// changé entre la lecture et l'écriture), sous les verrous des deux
/// seaux ; une faute rend les verrous, fait venir la page, et recommence.
/// Rend le nombre d'attentes réveillées sur les deux clés.
fn operer(adresse: u64, partage: bool, val: u32, val2: u64, adresse2: u64, codee: u32) -> i64 {
    let (c1, c2) = match cle(adresse, partage).and_then(|a| cle(adresse2, partage).map(|b| (a, b))) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut op = codee >> 28;
    let cmp = (codee >> 24) & 0xf;
    let signe12 = |x: u32| ((x << 20) as i32) >> 20;
    let mut argument = signe12((codee >> 12) & 0xfff);
    let comparee = signe12(codee & 0xfff);
    if op & 8 != 0 {
        op &= 7;
        // Linux garde les 5 bits bas d'un décalage hors de [0, 31].
        argument = 1 << (argument & 31);
    }
    if op > 4 {
        return -ENOSYS;
    }
    let a = argument as u32;
    loop {
        let mut faute = false;
        let r = deux_seaux(seau(&c1), seau(&c2), |s1, s2| {
            let ancienne = loop {
                let Some(ancienne) = lire_sans_faute(adresse2) else {
                    faute = true;
                    return 0;
                };
                let nouvelle = match op {
                    0 => a,
                    1 => ancienne.wrapping_add(a),
                    2 => ancienne | a,
                    3 => ancienne & !a,
                    _ => ancienne ^ a,
                };
                match tache::sans_faute_servie(|| copie_utilisateur::cmpxchg_u32(adresse2, ancienne, nouvelle)) {
                    Err(_) => {
                        faute = true;
                        return 0;
                    }
                    Ok(trouvee) if trouvee == ancienne => break ancienne as i32,
                    // Changé entre-temps (un autre processeur, un jour) :
                    // recommencer.
                    Ok(_) => continue,
                }
            };
            if cmp > 5 {
                return -ENOSYS;
            }
            // Au moins une attente de chaque côté, comme FUTEX_WAKE (la
            // boucle de `futex_wake_op` compte comme celle de `futex_wake`).
            let au_moins_une = |n: u32| if (n as i32) <= 0 { 1 } else { n };
            let mut n = reveiller_dans(s1, &c1, BITSET_TOUS, au_moins_une(val));
            let vrai = match cmp {
                0 => ancienne == comparee,
                1 => ancienne != comparee,
                2 => ancienne < comparee,
                3 => ancienne <= comparee,
                4 => ancienne > comparee,
                _ => ancienne >= comparee,
            };
            if vrai {
                let s2 = match s2 {
                    Some(s2) => s2,
                    None => s1,
                };
                n += reveiller_dans(s2, &c2, BITSET_TOUS, au_moins_une(val2 as u32));
            }
            n as i64
        });
        if !faute {
            return r;
        }
        // La page à écrire : la faire venir en écriture (un futex partagé
        // l'a déjà fait), verrous rendus.
        if processus::avec(|p| p.memoire.servir(adresse2, Acces::Ecriture)).is_err() {
            return -EFAULT;
        }
    }
}
