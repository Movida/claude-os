//! L'horloge du noyau : le PIT 8253/8254 (Programmable Interval Timer).
//!
//! Le PIT reçoit un quartz à 1 193 182 Hz (un tiers de la fréquence des
//! télévisions NTSC : c'était le quartz le moins cher en 1981 !). Chacun de
//! ses trois canaux compte à rebours à partir d'une valeur qu'on lui donne,
//! le « diviseur ». Le canal 0 est câblé sur l'IRQ 0 : à chaque passage par
//! zéro, il déclenche une interruption, puis recommence. Le noyau compte
//! ces « tics » : c'est son horloge, qui servira plus tard à partager le
//! processeur entre les programmes (l'ordonnanceur reprend la main à
//! chaque tic).
//!
//! Fréquence : 1000 Hz, un tic par milliseconde, comme le CONFIG_HZ=1000
//! des noyaux Linux de bureau. Plus de tics = plus de réactivité (un
//! programme attend au plus 1 ms son tour), au prix de 1000 petites
//! interruptions par seconde, négligeable aujourd'hui. Les serveurs
//! choisissent souvent 100 ou 250 Hz.
//!
//! Options écartées pour l'instant :
//!   - le timer de l'APIC local : un par processeur, nécessaire avec
//!     plusieurs cœurs, mais sa fréquence varie d'une machine à l'autre et
//!     doit être mesurée... avec le PIT. On y viendra avec l'APIC ;
//!   - le HPET et le compteur TSC du processeur : plus précis, mais il faut
//!     les trouver ou les étalonner (tables ACPI, PIT encore). Linux les
//!     utilise pour l'heure fine et garde un « tic » à côté ;
//!   - le mode « sans tic » (tickless, NO_HZ) de Linux, qui programme
//!     l'horloge au coup par coup pour laisser dormir un CPU inoccupé :
//!     une optimisation d'énergie, à envisager bien plus tard.

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

const PIT_CANAL0: u16 = 0x40;
const PIT_COMMANDE: u16 = 0x43;

/// Le compteur de tics depuis le démarrage. Atomique plutôt que sous
/// Verrou : il n'y a qu'un seul écrivain (le gestionnaire d'IRQ 0), et la
/// lecture d'un u64 aligné est indivisible en x86_64. En 64 bits, il ne
/// débordera pas avant 584 millions d'années.
static TICS: AtomicU64 = AtomicU64::new(0);

pub fn initialiser() {
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
}

/// Appelée à chaque IRQ 0, interruptions coupées.
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
