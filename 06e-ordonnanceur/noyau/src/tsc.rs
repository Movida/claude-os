//! Le TSC (Time Stamp Counter) : le compteur de cycles du processeur,
//! l'horloge fine du noyau.
//!
//! RDTSC rend en une instruction un compteur de 64 bits qui avance depuis
//! la mise sous tension. Sur les processeurs récents, il avance à une
//! fréquence CONSTANTE, quelle que soit la vitesse du cœur (les économies
//! d'énergie la changent sans cesse) : c'est alors la meilleure horloge du
//! PC, à la nanoseconde près, et c'est celle de Linux. Il faut deux
//! choses avant de s'en servir :
//!   - savoir s'il est constant. Le processeur le dit (CPUID 0x80000007,
//!     bit 8 d'EDX, « invariant TSC ») ; certains processeurs Intel l'ont
//!     constant sans le dire, et Linux les reconnaît à leur modèle
//!     (cpu/intel.c, 6.18) : le Core de Yonah à Ivy Bridge (famille 6,
//!     modèles 0x0E à 0x3A, Nehalem compris) et le Pentium 4 de Prescott à
//!     Cedar Mill (famille 15, modèles 3 à 6). Chez AMD, le bit seul.
//!     Sinon, le temps reste compté en tics du PIT, comme aux étapes 3 à 6d.
//!     (Sous QEMU sans KVM, aucun processeur n'a le bit : Nehalem passe
//!     par son modèle, qemu64 et max, des AMD, n'ont pas de TSC fiable :
//!     les deux chemins sont donc vérifiés.)
//!   - connaître sa fréquence : on la MESURE contre le canal 2 du PIT, dont
//!     le quartz est connu (1 193 182 Hz), comme `pit_calibrate_tsc` de
//!     Linux : on arme le canal pour 10 ms, on lit le TSC au départ et
//!     quand le canal a fini. Cinq essais. Un essai est rejeté si le PIT a
//!     été lu moins de 1000 fois pendant ces 10 ms (un PIT qui ne répond
//!     pas, ou une machine trop lente pour la mesure). On prend la MÉDIANE
//!     des essais, et il en faut au moins trois à 0,5 % d'elle, sinon le
//!     TSC n'est pas utilisé : un vol de temps (une interruption de gestion
//!     du système, l'hôte qui fait tourner QEMU) au bord d'un essai le
//!     fausse, et l'écarte.
//!     Deux écarts avec Linux, mesurés sous QEMU sans KVM : Linux rejette
//!     aussi un essai dont un tour de boucle a duré plus de 10 fois le plus
//!     court ; sous QEMU, c'est le cas de TOUS les essais (le plus long
//!     tour dure de 200 à 6000 fois le plus court : l'émulateur s'arrête à
//!     chaque accès au port, et l'hôte l'interrompt), qui s'accordent
//!     pourtant à 0,3 % près. Et Linux garde le plus petit essai ; mais un
//!     retard au bord d'un essai (juste après l'armement du canal, ou juste
//!     avant de voir sa fin) le raccourcit : le plus petit serait celui-là.
//! Linux affine ensuite la fréquence une seconde plus tard, contre le
//! HPET ou le timer d'ACPI, dont nous n'avons pas les pilotes : nos dix
//! millisecondes, sur un PIT lu à la microseconde, donnent la fréquence à
//! un dix-millième près (moins de 9 secondes par jour).
//!
//! La conversion en nanosecondes ne fait pas de division à chaque lecture :
//! ns = (cycles × mult) >> 32, avec mult = 10^6 × 2^32 / fréquence en kHz
//! (le `mult` et le `shift` des clocksources de Linux) ; le produit est
//! calculé sur 128 bits, il ne déborde jamais.

use crate::port;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// La fréquence mesurée, en kHz ; 0 : pas de TSC fiable.
static KHZ: AtomicU64 = AtomicU64::new(0);
/// Le facteur de conversion en nanosecondes (voir l'en-tête).
static MULT: AtomicU64 = AtomicU64::new(0);
/// Le TSC à l'instant pris pour origine du temps du noyau.
static ORIGINE: AtomicU64 = AtomicU64::new(0);

/// Lit le TSC. LFENCE avant RDTSC : sinon le processeur peut exécuter la
/// lecture en avance, avant les instructions qui la précèdent, et deux
/// lectures de suite pourraient sembler reculer (le `rdtsc_ordered` de
/// Linux, qui choisit LFENCE sur Intel comme sur AMD).
pub fn lire() -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY : LFENCE et RDTSC ne font que lire ; RDTSC est permis en
    // anneau 0 quel que soit CR4.TSD.
    unsafe { asm!("lfence", "rdtsc", out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}

/// Le TSC est-il constant, d'après le processeur (voir l'en-tête) ?
fn constant() -> bool {
    use core::arch::x86_64::__cpuid;
    if __cpuid(0x8000_0000).eax >= 0x8000_0007 && __cpuid(0x8000_0007).edx & 1 << 8 != 0 {
        return true;
    }
    let f = __cpuid(0);
    if (f.ebx, f.edx, f.ecx) != (0x756e_6547, 0x4965_6e69, 0x6c65_746e) {
        return false; // pas « GenuineIntel »
    }
    let s = __cpuid(1).eax;
    let famille = (s >> 8 & 0xF) + if s >> 8 & 0xF == 0xF { s >> 20 & 0xFF } else { 0 };
    let modele = (s >> 4 & 0xF) | if matches!(s >> 8 & 0xF, 6 | 0xF) { (s >> 16 & 0xF) << 4 } else { 0 };
    (famille == 6 && (0x0E..=0x3A).contains(&modele)) || (famille == 15 && (3..=6).contains(&modele))
}

/// Les ports du PIT et de sa porte (le port 0x61 du PC/AT : bit 0, la
/// porte du canal 2 ; bit 1, le haut-parleur ; bit 5, la sortie du canal 2).
const PIT_CANAL2: u16 = 0x42;
const PIT_COMMANDE: u16 = 0x43;
const PORTE: u16 = 0x61;

/// Un essai de mesure : le nombre de cycles du TSC pendant `ms`
/// millisecondes du canal 2 du PIT, ou None si l'essai est rejeté.
fn essai(ms: u64) -> Option<u64> {
    let decompte = (crate::horloge::FREQUENCE_PIT as u64 * ms / 1000) as u16;
    // Le canal compte dès que le second octet du décompte est écrit :
    // l'instant du départ est pris au milieu de deux lectures du TSC qui
    // encadrent cette écriture, et celui de la fin, entre la dernière
    // lecture qui précède la sortie montée et celle qui la suit.
    // SAFETY : la porte du canal 2, sans le haut-parleur ; le canal 2 en
    // mode 0 (« compte à rebours, puis la sortie monte »), comptage
    // binaire, décompte en deux octets. Le canal 2 ne sert qu'ici.
    let avant = unsafe {
        port::ecrire(PORTE, (port::lire(PORTE) & !0x02) | 0x01);
        port::ecrire(PIT_COMMANDE, 0xB0);
        port::ecrire(PIT_CANAL2, decompte as u8);
        let avant = lire();
        port::ecrire(PIT_CANAL2, (decompte >> 8) as u8);
        avant
    };
    let apres = lire();
    let mut fin = apres;
    let mut lectures = 0u32;
    // SAFETY : lire la porte ne change rien.
    while unsafe { port::lire(PORTE) } & 0x20 == 0 {
        fin = lire();
        lectures += 1;
    }
    let vue = lire();
    if lectures < 1000 {
        return None;
    }
    Some((fin / 2 + vue / 2) - (avant / 2 + apres / 2))
}

/// Ce que l'étalonnage a donné, pour l'afficher.
pub enum Bilan {
    /// La fréquence, en kHz, et le nombre d'essais à 0,5 % de la médiane.
    Fiable { khz: u64, essais: u32 },
    /// Le processeur ne dit pas son TSC constant.
    NonConstant,
    /// Les essais ont été rejetés, ou ne s'accordent pas.
    Mesure,
}

/// Mesure la fréquence du TSC, s'il est constant. Interruptions coupées
/// (les essais ne doivent pas être interrompus), avant que le PIT serve
/// d'horloge.
pub fn etalonner() -> Bilan {
    if !constant() {
        return Bilan::NonConstant;
    }
    let interruptions = crate::cpu::couper_interruptions();
    // Un premier essai pour rien : le premier passage dans ce code est
    // plus lent (sous QEMU, l'émulateur le traduit alors), et fausserait
    // son départ (mesuré : un essai sur deux trop court de 0,5 %).
    let _ = essai(1);
    let (mut retenus, mut n) = ([0u64; 5], 0);
    for _ in 0..5 {
        if let Some(cycles) = essai(10) {
            // Des cycles en 10 ms aux kHz : / 10.
            retenus[n] = cycles / 10;
            n += 1;
        }
    }
    if interruptions {
        crate::cpu::activer_interruptions();
    }
    let retenus = &mut retenus[..n];
    retenus.sort_unstable();
    // La médiane, et au moins trois essais à 0,5 % d'elle.
    let khz = retenus.get(n / 2).copied().unwrap_or(0);
    let proches = retenus.iter().filter(|&&k| k.abs_diff(khz) * 200 <= khz).count();
    if khz == 0 || proches < 3 {
        return Bilan::Mesure;
    }
    MULT.store(((1_000_000u128 << 32) / khz as u128) as u64, Ordering::Relaxed);
    ORIGINE.store(lire(), Ordering::Relaxed);
    KHZ.store(khz, Ordering::Relaxed);
    Bilan::Fiable { khz, essais: proches as u32 }
}

/// La fréquence du TSC en kHz, s'il sert d'horloge.
pub fn khz() -> Option<u64> {
    Some(KHZ.load(Ordering::Relaxed)).filter(|&k| k != 0)
}

/// Des cycles du TSC en nanosecondes.
pub fn en_nanosecondes(cycles: u64) -> u64 {
    ((cycles as u128 * MULT.load(Ordering::Relaxed) as u128) >> 32) as u64
}

/// Les nanosecondes depuis l'origine (l'étalonnage), si le TSC sert
/// d'horloge.
pub fn nanosecondes() -> Option<u64> {
    khz()?;
    Some(en_nanosecondes(lire().wrapping_sub(ORIGINE.load(Ordering::Relaxed))))
}
