//! Des octets aléatoires, pour les programmes : les 16 octets d'AT_RANDOM
//! (la glibc en tire la valeur qui protège ses piles contre les
//! débordements, et celle qui brouille ses pointeurs de fonctions), et
//! l'appel système getrandom.
//!
//! La source : l'instruction RDRAND, le générateur matériel des processeurs
//! depuis 2012 (Intel Ivy Bridge, AMD 2015), quand il existe (CPUID feuille
//! 1, bit 30 d'ECX). Sinon, le compteur de cycles du processeur (RDTSC),
//! brassé : ses bits bas varient d'un démarrage à l'autre, mais un
//! attaquant qui connaît la machine peut les deviner. Ce n'est PAS un
//! générateur cryptographique, et le noyau ne prétend pas le contraire.
//!
//! Un vrai générateur (celui de Linux, drivers/char/random.c) accumule de
//! l'aléa de plusieurs sources (instants des interruptions, RDRAND, RDSEED,
//! le chargeur) dans un état brassé par une fonction cryptographique
//! (BLAKE2s, puis ChaCha20). Étape 6, avec TLS, qui en aura besoin.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// RDRAND peut échouer (CF = 0) quand le générateur est momentanément
/// vide : Intel conseille de réessayer, dix fois au plus.
const ESSAIS_RDRAND: usize = 10;

fn a_rdrand() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & 1 << 30 != 0
}

fn rdrand() -> Option<u64> {
    for _ in 0..ESSAIS_RDRAND {
        let (valeur, ok): (u64, u8);
        // SAFETY : RDRAND existe (a_rdrand), et ne fait que rendre un nombre.
        unsafe { asm!("rdrand {v}", "setc {ok}", v = out(reg) valeur, ok = out(reg_byte) ok, options(nomem, nostack)) };
        if ok != 0 {
            return Some(valeur);
        }
    }
    None
}

/// Le repli : le compteur de cycles, brassé par SplitMix64 (un mélange
/// simple et rapide de Steele, Lea et Flood, 2014) avec un compteur qui
/// avance à chaque appel, pour que deux appels rapprochés diffèrent.
fn tsc_brasse() -> u64 {
    static COMPTEUR: AtomicU64 = AtomicU64::new(0);
    let (bas, haut): (u32, u32);
    // SAFETY : RDTSC ne fait que lire le compteur de cycles.
    unsafe { asm!("rdtsc", out("eax") bas, out("edx") haut, options(nomem, nostack)) };
    let mut x = ((haut as u64) << 32 | bas as u64)
        .wrapping_add(COMPTEUR.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed));
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Remplit `octets` d'aléa.
pub fn remplir(octets: &mut [u8]) {
    let materiel = a_rdrand();
    for morceau in octets.chunks_mut(8) {
        let x = if materiel { rdrand().unwrap_or_else(tsc_brasse) } else { tsc_brasse() };
        morceau.copy_from_slice(&x.to_le_bytes()[..morceau.len()]);
    }
}

/// La source qu'utilise `remplir`, pour l'affichage.
pub fn source() -> &'static str {
    if cryptographique() { "RDRAND" } else { "TSC (non cryptographique)" }
}

/// La source est-elle cryptographique (RDRAND) ?
pub fn cryptographique() -> bool {
    a_rdrand()
}
