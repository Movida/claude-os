//! L'heure : la date et l'heure du jour (pour les horodatages des
//! fichiers, et l'horloge CLOCK_REALTIME des programmes), et les horloges
//! de Linux (clock_gettime).
//!
//! La date vient de l'horloge CMOS, le MC146818 du PC d'IBM (1984) : une
//! petite horloge à pile, qui compte même machine éteinte, derrière les
//! ports 0x70 (le numéro du registre) et 0x71 (sa valeur). On la lit une
//! seule fois, au démarrage, comme Linux (`read_persistent_clock64`, puis
//! `mc146818_get_time`) ; ensuite, l'heure avance avec les tics de
//! l'horloge du noyau (horloge.rs). L'horloge CMOS ne donne que des
//! secondes, et sa lecture est lente (plusieurs microsecondes par
//! registre) : on ne la relit pas.
//!
//! Les pièges de sa lecture, que Linux connaît tous :
//!   - pendant qu'elle avance d'une seconde (environ 2 ms par seconde, le
//!     bit UIP du registre A le dit), ses registres sont incohérents : on
//!     lit quand UIP est à 0, et on le relit après (voir `lire_date`) ;
//!   - elle peut manquer (une machine sans horloge compatible, un port qui
//!     ne répond rien : UIP paraît toujours levé), ou dire n'importe quoi
//!     (une pile vide) : on attend au plus 10 ms, on vérifie la date lue,
//!     et sinon on démarre au 1er janvier 1970, comme Linux quand il n'a
//!     pas d'horloge ;
//!   - les valeurs sont en décimal codé binaire (0x59 pour 59) ou en
//!     binaire, et l'heure sur 12 heures (bit 7 : l'après-midi) ou 24,
//!     selon le registre B ;
//!   - l'année n'a que deux chiffres. Le siècle est dans un registre que
//!     désigne la table ACPI FADT (acpi.rs), quand elle est de révision 3
//!     au moins : on le lit avec le reste, et l'année est celle de Linux
//!     (`mc146818_get_time`) : les deux chiffres, plus (siècle - 19) × 100
//!     si le siècle dépasse 19, puis, si l'on n'arrive qu'à 69 ou moins
//!     après 1900, cent ans de plus (une année avant 70 est dans les
//!     années 2000). La machine `pc` de QEMU n'a qu'une FADT de révision
//!     1 : la règle seule ;
//!   - le bit 7 du port 0x70 coupe les interruptions non masquables (NMI)
//!     : on le laisse à 0 ;
//!   - le choix d'un registre puis sa lecture forment une paire qu'il ne
//!     faut pas couper : sous un verrou (le `rtc_lock` de Linux).
//! L'horloge CMOS donne l'heure UTC, comme le veut Linux (QEMU fait de
//! même par défaut) ; le fuseau horaire est l'affaire des programmes
//! (/etc/localtime).
//!
//! Les horloges des programmes, comptées depuis le démarrage, à la
//! nanoseconde (le TSC) ou au tic (voir plus bas) :
//!   - CLOCK_REALTIME : la date, celle de l'horloge CMOS plus le temps
//!     écoulé depuis ;
//!   - CLOCK_MONOTONIC et CLOCK_BOOTTIME : le temps depuis le démarrage (pas
//!     de mise en veille, elles sont donc égales) ; MONOTONIC_RAW aussi ;
//!   - CLOCK_TAI : le temps atomique, égal à REALTIME tant que personne ne
//!     règle l'écart (comme Linux, où il vaut 0 au démarrage) ;
//!   - leurs versions _COARSE, « grossières » mais plus rapides sous Linux :
//!     l'heure du dernier tic (ici, la fine arrondie au tic : jamais en
//!     avance sur elle), de la finesse d'un tic ;
//!   - CLOCK_PROCESS_CPUTIME_ID et CLOCK_THREAD_CPUTIME_ID : le temps de
//!     calcul du programme, compté tic par tic quand il s'exécute (en
//!     anneau 3 ou dans le noyau pour lui : utime + stime, comme Linux),
//!     celui de sa limite RLIMIT_CPU (tache.rs). Avec un seul fil, les deux
//!     sont égaux.
//! Le temps vient du TSC, étalonné (tsc.rs), à la nanoseconde, quand il
//! est fiable : clock_getres rend alors 1 ns pour les horloges fines,
//! comme Linux. Sinon, il est compté en tics, avec la durée exacte d'un
//! tic (horloge.rs, le `tick_nsec` de Linux) : un tic du PIT ne dure pas
//! exactement une milliseconde (1 193 182 Hz divisés par 1193, soit
//! 999 847,6 ns), et le compter pour une milliseconde ferait dériver
//! l'heure de 13 secondes par jour.

use crate::verrou::Verrou;
use crate::{horloge, port, tache};
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use fichiers::Temps;

const CMOS_INDEX: u16 = 0x70;
const CMOS_DONNEE: u16 = 0x71;

// Les registres de l'horloge CMOS.
const SECONDES: u8 = 0x00;
const MINUTES: u8 = 0x02;
const HEURES: u8 = 0x04;
const JOUR: u8 = 0x07;
const MOIS: u8 = 0x08;
const ANNEE: u8 = 0x09;
const ETAT_A: u8 = 0x0a;
const ETAT_B: u8 = 0x0b;
/// Registre A : une mise à jour est en cours.
const UIP: u8 = 0x80;
/// Registre B : les valeurs sont en binaire (sinon en BCD).
const BINAIRE: u8 = 0x04;
/// Registre B : l'heure est sur 24 heures (sinon 12, et le bit 7 dit PM).
const H24: u8 = 0x02;

/// Le couple index et donnée ne se coupe pas.
static CMOS: Verrou<()> = Verrou::new(());

/// La date au démarrage (secondes depuis 1970, UTC), et l'instant où on
/// l'a lue (en nanosecondes du temps monotone).
static DATE_LUE: AtomicI64 = AtomicI64::new(0);
static INSTANT_DE_LECTURE: AtomicU64 = AtomicU64::new(0);

/// Le temps depuis le démarrage, en nanosecondes : le TSC s'il est fiable,
/// les tics sinon.
pub fn ns_monotone() -> u64 {
    crate::tsc::nanosecondes().unwrap_or_else(|| horloge::nanosecondes(horloge::tics()))
}

/// La durée d'un tic, arrondie à la nanoseconde au-dessus.
fn duree_tic() -> u64 {
    horloge::nanosecondes(1_000_000).div_ceil(1_000_000)
}

/// La finesse de l'horloge `horloge` (clock_getres) : 1 ns pour les
/// horloges fines et le temps de calcul (compté au TSC, ordonnanceur.rs)
/// quand le TSC sert, la durée d'un tic sinon, et pour les _COARSE.
pub fn resolution(h: u64) -> Temps {
    let fine = !matches!(h, CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE);
    let ns = if fine && crate::tsc::khz().is_some() { 1 } else { duree_tic() };
    Temps { secondes: 0, nanosecondes: ns as u32 }
}

fn lire_registre(r: u8) -> u8 {
    // SAFETY : les ports de l'horloge CMOS ; le bit 7 de l'index à 0 laisse
    // les NMI actifs. Sous le verrou CMOS, que tient l'appelant.
    unsafe {
        port::ecrire(CMOS_INDEX, r);
        port::lire(CMOS_DONNEE)
    }
}

/// Les six registres de la date et le registre B, lus hors d'une mise à
/// jour, comme `mc146818_avoid_UIP` de Linux : UIP passe à 1 au moins
/// 244 µs avant que la mise à jour ne commence, donc une lecture faite
/// juste après l'avoir vu à 0 est cohérente ; UIP est relu après, et si une
/// mise à jour a commencé quand même, on recommence. Tant qu'UIP est levé,
/// on réessaie, le verrou rendu entre deux essais (les interruptions
/// passent : l'horloge du noyau compte, et rien n'est perdu), pendant 10 ms
/// au plus ; une vraie horloge ne garde UIP qu'environ 2 ms. Rien après
/// 10 ms : pas d'horloge, ou une horloge en panne. (Appelée interruptions
/// actives, une fois l'horloge du noyau en marche ; un plafond d'essais
/// arrête aussi la boucle si elle ne comptait pas.)
fn lire_date(siecle: Option<u8>) -> Option<([u8; 6], u8, Option<u8>)> {
    let limite = horloge::tics() + 10 * horloge::HZ as u64 / 1000;
    for _ in 0..1_000_000 {
        {
            let _cmos = CMOS.verrouiller();
            if lire_registre(ETAT_A) & UIP == 0 {
                let date = [SECONDES, MINUTES, HEURES, JOUR, MOIS, ANNEE].map(lire_registre);
                let s = siecle.map(lire_registre);
                let b = lire_registre(ETAT_B);
                if lire_registre(ETAT_A) & UIP == 0 {
                    return Some((date, b, s));
                }
            }
        }
        if horloge::tics() > limite {
            break;
        }
        core::hint::spin_loop();
    }
    None
}

/// Le nombre de jours du 1er janvier 1970 au jour donné (le calendrier
/// grégorien, l'algorithme de `mktime64` dans Linux, dit « de Gauss » : on
/// fait commencer l'année en mars pour que février, le mois irrégulier,
/// vienne en dernier).
fn jours_depuis_1970(annee: i64, mois: i64, jour: i64) -> i64 {
    let (a, m) = if mois <= 2 { (annee - 1, mois + 9) } else { (annee, mois - 3) };
    a * 365 + a / 4 - a / 100 + a / 400 + (m * 306 + 5) / 10 + jour - 1 - 719_468
}

/// Lit l'horloge CMOS : la date au démarrage. Rend (année, mois, jour,
/// heure, minute, seconde) pour l'afficher ; rien si elle ne répond pas,
/// ou donne une date impossible : la date part alors de 1970 (0).
pub fn initialiser() -> Option<(i64, i64, i64, i64, i64, i64)> {
    // Un registre du siècle au-delà des 128 de l'horloge CMOS : une table
    // fausse, on s'en passe (le bit 7 de l'index coupe les NMI).
    let lue = lire_date(crate::acpi::registre_du_siecle().filter(|&r| r < 0x80));
    INSTANT_DE_LECTURE.store(ns_monotone(), Ordering::Relaxed);
    let (brut, b, siecle) = lue?;
    let valeur = |v: u8| if b & BINAIRE != 0 { v as i64 } else { (v >> 4) as i64 * 10 + (v & 0x0f) as i64 };
    let [s, mi, h, j, mo, a] = brut;
    let heure = if b & H24 != 0 {
        valeur(h)
    } else {
        // Sur 12 heures : 12 h est minuit (AM) ou midi (PM).
        valeur(h & 0x7f) % 12 + if h & 0x80 != 0 { 12 } else { 0 }
    };
    let mut depuis_1900 = valeur(a);
    if let Some(s) = siecle.map(valeur).filter(|&s| s > 19) {
        depuis_1900 += (s - 19) * 100;
    }
    if depuis_1900 <= 69 {
        depuis_1900 += 100;
    }
    let annee = 1900 + depuis_1900;
    let (mois, jour, minute, seconde) = (valeur(mo), valeur(j), valeur(mi), valeur(s));
    if !(1..=12).contains(&mois) || !(1..=31).contains(&jour) || heure >= 24 || minute >= 60 || seconde >= 60 {
        return None;
    }
    let date = jours_depuis_1970(annee, mois, jour) * 86_400 + heure * 3600 + minute * 60 + seconde;
    DATE_LUE.store(date, Ordering::Relaxed);
    Some((annee, mois, jour, heure, minute, seconde))
}

fn depuis_nanosecondes(ns: u64) -> Temps {
    Temps { secondes: (ns / 1_000_000_000) as i64, nanosecondes: (ns % 1_000_000_000) as u32 }
}

/// Le temps depuis le démarrage (CLOCK_MONOTONIC).
pub fn monotone() -> Temps {
    depuis_nanosecondes(ns_monotone())
}

/// La date et l'heure (CLOCK_REALTIME), en temps UTC.
pub fn maintenant() -> Temps {
    date(ns_monotone())
}

/// La date à l'instant `ns` du temps monotone.
fn date(ns: u64) -> Temps {
    let ecoule = depuis_nanosecondes(ns.saturating_sub(INSTANT_DE_LECTURE.load(Ordering::Relaxed)));
    Temps { secondes: DATE_LUE.load(Ordering::Relaxed) + ecoule.secondes, ..ecoule }
}

/// L'instant `ns`, arrondi au tic en dessous (les horloges _COARSE).
fn grossier(ns: u64) -> u64 {
    ns - ns % duree_tic()
}

/// Le temps de calcul de la tâche en cours.
pub fn temps_du_programme() -> Temps {
    depuis_nanosecondes(tache::temps_de_calcul())
}

// Les horloges de Linux (include/uapi/linux/time.h).
pub const CLOCK_REALTIME: u64 = 0;
pub const CLOCK_MONOTONIC: u64 = 1;
pub const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
pub const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
pub const CLOCK_MONOTONIC_RAW: u64 = 4;
pub const CLOCK_REALTIME_COARSE: u64 = 5;
pub const CLOCK_MONOTONIC_COARSE: u64 = 6;
pub const CLOCK_BOOTTIME: u64 = 7;
pub const CLOCK_TAI: u64 = 11;

/// L'horloge `horloge` de Linux, si on la connaît. Les horloges des alarmes
/// (CLOCK_*_ALARM, qui réveillent une machine en veille) et celles d'un
/// autre processus (les numéros négatifs de clock_getcpuclockid) : non.
pub fn horloge(horloge: u64) -> Option<Temps> {
    match horloge {
        CLOCK_REALTIME | CLOCK_TAI => Some(maintenant()),
        CLOCK_REALTIME_COARSE => Some(date(grossier(ns_monotone()))),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => Some(monotone()),
        CLOCK_MONOTONIC_COARSE => Some(depuis_nanosecondes(grossier(ns_monotone()))),
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => Some(temps_du_programme()),
        _ => None,
    }
}
