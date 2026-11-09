//! Ports d'entrée-sortie x86 : le second espace d'adresses du processeur.
//!
//! Les vieux périphériques du PC (port série, clavier, horloge, contrôleur
//! d'interruptions) ne sont pas dans la mémoire mais derrière des « ports »
//! numérotés de 0 à 0xFFFF, qu'on lit avec `in` et qu'on écrit avec `out`.
//! Le compilateur ne connaît pas ces instructions : on les écrit en
//! assembleur dans le code Rust (`asm!`).
//!
//! Ces fonctions sont `unsafe` : écrire sur le mauvais port peut faire
//! n'importe quoi (le port 0x92 peut redémarrer la machine !). C'est à
//! l'appelant de garantir que le port et la valeur ont un sens.

use core::arch::asm;

/// Écrit un octet sur un port.
pub unsafe fn ecrire(port: u16, valeur: u8) {
    // SAFETY: le port et la valeur, garantis par l'appelant (voir
    // l'en-tête). nomem : ne touche pas la mémoire ; nostack : pas la pile ;
    // preserves_flags : ne modifie pas les drapeaux. Ces promesses laissent
    // le compilateur optimiser le code autour.
    // SAFETY: comme `ecrire`.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") valeur,
             options(nomem, nostack, preserves_flags));
    }
}

/// Lit un octet sur un port.
pub unsafe fn lire(port: u16) -> u8 {
    let valeur: u8;
    // SAFETY: comme `ecrire`.
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") valeur,
             options(nomem, nostack, preserves_flags));
    }
    valeur
}

/// Écrit un mot de 16 bits sur un port.
pub unsafe fn ecrire16(port: u16, valeur: u16) {
    // SAFETY: comme `ecrire`.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") valeur,
             options(nomem, nostack, preserves_flags));
    }
}

/// Lit un mot de 16 bits sur un port.
pub unsafe fn lire16(port: u16) -> u16 {
    let valeur: u16;
    // SAFETY: comme `ecrire`.
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") valeur,
             options(nomem, nostack, preserves_flags));
    }
    valeur
}

/// Écrit un mot de 32 bits sur un port.
pub unsafe fn ecrire32(port: u16, valeur: u32) {
    // SAFETY: comme `ecrire`.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") valeur,
             options(nomem, nostack, preserves_flags));
    }
}

/// Lit un mot de 32 bits sur un port.
pub unsafe fn lire32(port: u16) -> u32 {
    let valeur: u32;
    // SAFETY: comme `ecrire`.
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") valeur,
             options(nomem, nostack, preserves_flags));
    }
    valeur
}
