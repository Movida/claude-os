//! L'horloge du noyau : le « tic », une interruption périodique, qui
//! compte le temps et rendra la main à l'ordonnanceur.
//!
//! Deux sources, choisies au démarrage :
//!   - le TIMER DE L'APIC local (apic.rs), dès que l'APIC est en service :
//!     celle de Linux. Chaque processeur a le sien, il ne passe ni par
//!     l'IO-APIC ni par le bus ISA : c'est ce qui donnera un tic à chaque
//!     processeur (6j). Sa fréquence (celle du bus de l'APIC, divisée par
//!     16) dépend de la machine : on la MESURE, contre le TSC pendant 10 ms
//!     s'il est fiable (tsc.rs), sinon contre le canal 2 du PIT pendant
//!     50 ms (ce que fait `calibrate_APIC_clock` de Linux contre son
//!     horloge globale) ; puis on le règle en mode périodique pour une
//!     interruption par milliseconde. Le PIT est alors arrêté. Jusqu'à 6i,
//!     le timer de l'APIC n'était pris qu'avec un TSC fiable, et le PIT
//!     gardé sinon ; or l'IRQ 0 du PIT ne va qu'au premier processeur, et
//!     `make tests-qemu` lance l'archive de test sous `-cpu qemu64`, dont
//!     le TSC n'est pas déclaré constant : des secondaires sans tic ne
//!     préempteraient jamais un fil qui calcule ;
//!   - sinon le PIT 8253/8254 (Programmable Interval Timer) des étapes 3 à
//!     6d, qui reçoit un quartz à 1 193 182 Hz (un tiers de la fréquence
//!     des télévisions NTSC : le quartz le moins cher en 1981 !). Son canal
//!     0, câblé sur l'IRQ 0, compte à rebours depuis un « diviseur », puis
//!     recommence. Sans APIC (une machine sans tables ACPI : un seul
//!     processeur), il reste l'horloge.
//!
//! Chaque processeur règle le timer de son APIC (6j : le même décompte que
//! le premier, `demarrer_tic_secondaire` ; les APIC partagent le bus) :
//! son tic fait tourner sa propre file des prêtes (ordonnanceur.rs). Le
//! TEMPS, lui, n'est compté qu'une fois, par le processeur 0 (`tic`, les
//! minuteries d'attente.rs : le `tick_do_timer_cpu` de Linux) : les tics
//! des autres ne comptent pas (interruptions.rs).
//!
//! Fréquence : 1000 Hz, un tic par milliseconde, comme le CONFIG_HZ=1000
//! des noyaux Linux de bureau. Plus de tics = plus de réactivité (un
//! programme attend au plus 1 ms son tour), au prix de 1000 petites
//! interruptions par seconde, négligeable aujourd'hui.
//!
//! Option écartée pour l'instant : le mode « sans tic » (tickless, NO_HZ)
//! de Linux, qui programme le timer au coup par coup (en un coup, ou à
//! une échéance du TSC, « TSC-deadline ») pour laisser dormir un
//! processeur inoccupé et réveiller une attente à la microseconde (les
//! hrtimers) : une optimisation d'énergie et de précision, à envisager
//! plus tard ; TSC-deadline n'est de toute façon pas imité par QEMU sans
//! KVM (mesuré).

use crate::cpu;
use crate::port;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const IRQ: u8 = 0;

/// Fréquence du quartz du PIT, en Hz.
pub const FREQUENCE_PIT: u32 = 1_193_182;
/// Fréquence voulue des tics.
pub const HZ: u32 = 1000;
/// 1 193 182 / 1000 = 1193 (arrondi) : en réalité 1000,15 Hz, une dérive
/// d'environ 13 secondes par jour. Sans importance pour mesurer des
/// durées courtes ; temps.rs compte avec la durée exacte d'un tic.
pub const DIVISEUR: u16 = ((FREQUENCE_PIT + HZ / 2) / HZ) as u16;

/// La durée exacte d'un tic, en fraction de seconde : NUMERATEUR /
/// DENOMINATEUR (le PIT : DIVISEUR / FREQUENCE_PIT ; le timer de l'APIC :
/// son décompte / sa fréquence mesurée).
static NUMERATEUR: AtomicU64 = AtomicU64::new(DIVISEUR as u64);
static DENOMINATEUR: AtomicU64 = AtomicU64::new(FREQUENCE_PIT as u64);
/// Le décompte du timer de l'APIC pour un tic, une fois mesuré (0 : le
/// PIT fait l'horloge, pas de timer d'APIC) : ce que règle chaque
/// processeur secondaire.
static DECOMPTE_APIC: AtomicU32 = AtomicU32::new(0);

/// La durée de `tics` tics, en nanosecondes.
pub fn nanosecondes(tics: u64) -> u64 {
    (tics as u128 * NUMERATEUR.load(Ordering::Relaxed) as u128 * 1_000_000_000
        / DENOMINATEUR.load(Ordering::Relaxed) as u128) as u64
}

const PIT_CANAL0: u16 = 0x40;
const PIT_COMMANDE: u16 = 0x43;

/// Le compteur de tics depuis le démarrage. Atomique plutôt que sous
/// Verrou : il n'y a qu'un seul écrivain (le gestionnaire d'IRQ 0), et la
/// lecture d'un u64 aligné est indivisible en x86_64. En 64 bits, il ne
/// débordera pas avant 584 millions d'années.
static TICS: AtomicU64 = AtomicU64::new(0);

/// La source du tic, pour l'afficher.
pub enum Source {
    /// Le timer de l'APIC : sa fréquence mesurée (en Hz, après le
    /// diviseur), et contre quoi (« TSC » ou « PIT »).
    Apic { hz: u64, etalon: &'static str },
    Pit,
}

/// Mesure la fréquence du timer de l'APIC, après son diviseur (en Hz), et
/// dit contre quoi : le TSC pendant 10 ms s'il est fiable, sinon le canal 2
/// du PIT pendant 50 ms. Un accès aux registres de l'APIC prend du temps
/// (sous QEMU, des dizaines de microsecondes : l'émulateur s'arrête à
/// chaque fois) : contre le TSC, l'instant où le timer démarre, et celui où
/// on lit son compteur, sont pris au milieu de deux lectures du TSC qui
/// encadrent l'accès (sinon, la mesure surestimait sa fréquence de 0,7 %) ;
/// contre le PIT, qu'on ne lit pas aussi finement, c'est la durée de la
/// mesure, 50 ms, qui rend ces dizaines de microsecondes négligeables (un
/// millième). None : le PIT n'a pas répondu (alors il ne ferait pas
/// d'horloge non plus ; on le garde quand même, comme avant).
fn etalonner_apic() -> Option<(u64, &'static str)> {
    if let Some(khz) = crate::tsc::khz() {
        let t0 = crate::tsc::lire();
        crate::apic::armer_etalonnage();
        let t1 = crate::tsc::lire();
        let fin = t1 + khz * 10;
        while crate::tsc::lire() < fin {
            core::hint::spin_loop();
        }
        let t2 = crate::tsc::lire();
        let decomptes = crate::apic::decomptes_etalonnage();
        let t3 = crate::tsc::lire();
        let ns = crate::tsc::en_nanosecondes((t2 / 2 + t3 / 2) - (t0 / 2 + t1 / 2)).max(1);
        return Some(((decomptes as u128 * 1_000_000_000 / ns as u128) as u64, "TSC"));
    }
    crate::apic::armer_etalonnage();
    if !crate::tsc::attendre_canal2(50) {
        return None;
    }
    Some((crate::apic::decomptes_etalonnage() * 1000 / 50, "PIT"))
}

/// Démarre le tic : le timer de l'APIC si `apic` (l'APIC est en service),
/// le PIT sinon. Interruptions coupées.
pub fn initialiser(apic: bool) -> Source {
    if apic && let Some((hz, etalon)) = etalonner_apic() {
        let decompte = (hz / HZ as u64).max(1);
        NUMERATEUR.store(decompte, Ordering::Relaxed);
        DENOMINATEUR.store(hz, Ordering::Relaxed);
        DECOMPTE_APIC.store(decompte as u32, Ordering::Relaxed);
        crate::apic::demarrer_timer(decompte as u32);
        // Le PIT arrêté, comme le `pit_shutdown` de Linux : le canal 0 en
        // mode 0 (un seul compte à rebours, sans recharge), décompte nul.
        // Son IRQ n'a jamais été démasquée.
        // SAFETY: registres documentés du PIT.
        unsafe {
            port::ecrire(PIT_COMMANDE, 0x30);
            port::ecrire(PIT_CANAL0, 0);
            port::ecrire(PIT_CANAL0, 0);
        }
        return Source::Apic { hz, etalon };
    }
    // SAFETY: registres documentés du PIT (commande, puis canal 0).
    unsafe {
        // Octet de commande 0x34 = 00 11 010 0 :
        //   00  : canal 0,
        //   11  : on enverra le diviseur octet bas puis octet haut,
        //   010 : mode 2, « générateur de fréquence », une impulsion à
        //         chaque passage par zéro, puis rechargement automatique
        //         (le mode périodique de Linux, i8253.c) ;
        //   0   : comptage binaire (et pas en décimal codé binaire).
        port::ecrire(PIT_COMMANDE, 0x34);
        port::ecrire(PIT_CANAL0, DIVISEUR as u8);
        port::ecrire(PIT_CANAL0, (DIVISEUR >> 8) as u8);
    }
    crate::irq::demasquer(IRQ);
    Source::Pit
}

/// Démarre le timer de l'APIC d'un processeur secondaire, avec le décompte
/// mesuré sur le premier (le `setup_secondary_APIC_clock` de Linux) : sur
/// ce processeur, interruptions coupées (smp.rs). Rien sans APIC (une
/// machine sans ACPI n'a qu'un processeur).
pub fn demarrer_tic_secondaire() {
    let decompte = DECOMPTE_APIC.load(Ordering::Relaxed);
    if decompte != 0 {
        crate::apic::demarrer_timer(decompte);
    }
}

/// Appelée à chaque tic du processeur 0, interruptions coupées.
pub fn tic() {
    // Relaxed : un simple compteur, rien d'autre à rendre visible avec lui.
    TICS.fetch_add(1, Ordering::Relaxed);
}

/// Nombre de tics depuis l'initialisation de l'horloge.
pub fn tics() -> u64 {
    TICS.load(Ordering::Relaxed)
}

/// Attend au moins `us` microsecondes, sans dormir : par le TSC s'il est
/// fiable, sinon par les tics, dont la finesse est la milliseconde
/// (l'attente dure alors jusqu'à une milliseconde de plus : les délais du
/// réveil des processeurs secondaires, smp.rs, sont des minimums). Les
/// interruptions doivent être actives si l'heure vient des tics.
pub fn attendre_us(us: u64) {
    let debut = crate::temps::ns_monotone();
    while crate::temps::ns_monotone().wrapping_sub(debut) < us * 1000 {
        core::hint::spin_loop();
    }
}

/// Endort le processeur jusqu'à ce que `ms` millisecondes soient passées.
/// `hlt` arrête le CPU jusqu'à la prochaine interruption : entre deux tics,
/// il ne consomme presque rien (au lieu de tourner dans une boucle vide).
pub fn attendre_ms(ms: u64) {
    let fin = tics() + ms * HZ as u64 / 1000;
    loop {
        // Vérifier interruptions coupées, puis dormir : voir pourquoi dans
        // cpu::attendre_interruption.
        cpu::couper_interruptions();
        if tics() >= fin {
            cpu::activer_interruptions();
            return;
        }
        cpu::attendre_interruption();
    }
}
