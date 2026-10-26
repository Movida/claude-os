//! L'horloge du noyau : le « tic », une interruption périodique, qui
//! compte le temps et rendra la main à l'ordonnanceur.
//!
//! Deux sources, choisies au démarrage :
//!   - le TIMER DE L'APIC local (apic.rs), quand l'APIC est en service et
//!     que le TSC est fiable (tsc.rs) : celle de Linux. Chaque processeur a
//!     le sien (il en faudra un par cœur avec le multiprocesseur), il ne
//!     passe ni par l'IO-APIC ni par le bus ISA. Sa fréquence (celle du bus
//!     de l'APIC, divisée par 16) dépend de la machine : on la MESURE
//!     contre le TSC pendant 10 ms, puis on le règle en mode périodique pour
//!     une interruption par milliseconde. Le PIT est alors arrêté ;
//!   - sinon le PIT 8253/8254 (Programmable Interval Timer) des étapes 3 à
//!     6d, qui reçoit un quartz à 1 193 182 Hz (un tiers de la fréquence
//!     des télévisions NTSC : le quartz le moins cher en 1981 !). Son canal
//!     0, câblé sur l'IRQ 0, compte à rebours depuis un « diviseur », puis
//!     recommence. Sans TSC fiable, la période exacte du PIT est notre
//!     seule mesure du temps (Linux prendrait le HPET, que nous n'avons
//!     pas) : il reste l'horloge.
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
use core::sync::atomic::{AtomicU64, Ordering};

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
    /// Le timer de l'APIC, et sa fréquence mesurée (en Hz, après le
    /// diviseur).
    Apic(u64),
    Pit,
}

/// Démarre le tic : le timer de l'APIC si `apic` (l'APIC est en service)
/// et si le TSC est fiable, le PIT sinon. Interruptions coupées.
pub fn initialiser(apic: bool) -> Source {
    if apic && crate::tsc::khz().is_some() {
        // Les décomptes du timer pendant environ 10 ms, mesurées au TSC. Un
        // accès aux registres de l'APIC prend du temps (sous QEMU, des
        // dizaines de microsecondes : l'émulateur s'arrête à chaque fois) :
        // l'instant où le timer démarre, et celui où on lit son compteur,
        // sont pris au milieu de deux lectures du TSC qui encadrent
        // l'accès. Sinon, la mesure surestimait sa fréquence de 0,7 %.
        let t0 = crate::tsc::lire();
        crate::apic::armer_etalonnage();
        let t1 = crate::tsc::lire();
        let fin = t1 + crate::tsc::khz().unwrap_or(0) * 10;
        while crate::tsc::lire() < fin {
            core::hint::spin_loop();
        }
        let t2 = crate::tsc::lire();
        let decomptes = crate::apic::decomptes_etalonnage();
        let t3 = crate::tsc::lire();
        let ns = crate::tsc::en_nanosecondes((t2 / 2 + t3 / 2) - (t0 / 2 + t1 / 2)).max(1);
        let hz = (decomptes as u128 * 1_000_000_000 / ns as u128) as u64;
        let decompte = (hz / HZ as u64).max(1);
        NUMERATEUR.store(decompte, Ordering::Relaxed);
        DENOMINATEUR.store(hz, Ordering::Relaxed);
        crate::apic::demarrer_timer(decompte as u32);
        // Le PIT arrêté, comme le `pit_shutdown` de Linux : le canal 0 en
        // mode 0 (un seul compte à rebours, sans recharge), décompte nul.
        // Son IRQ n'a jamais été démasquée.
        // SAFETY : registres documentés du PIT.
        unsafe {
            port::ecrire(PIT_COMMANDE, 0x30);
            port::ecrire(PIT_CANAL0, 0);
            port::ecrire(PIT_CANAL0, 0);
        }
        return Source::Apic(hz);
    }
    // SAFETY : registres documentés du PIT (commande, puis canal 0).
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

/// Appelée à chaque tic, interruptions coupées.
pub fn tic() {
    // Relaxed : un simple compteur, rien d'autre à rendre visible avec lui.
    TICS.fetch_add(1, Ordering::Relaxed);
}

/// Nombre de tics depuis l'initialisation de l'horloge.
pub fn tics() -> u64 {
    TICS.load(Ordering::Relaxed)
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
