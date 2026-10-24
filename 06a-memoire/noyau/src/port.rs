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
    // nomem : ne touche pas la mémoire ; nostack : pas la pile ;
    // preserves_flags : ne modifie pas les drapeaux. Ces promesses laissent
    // le compilateur optimiser le code autour.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") valeur,
             options(nomem, nostack, preserves_flags));
    }
}

/// Lit un octet sur un port.
pub unsafe fn lire(port: u16) -> u8 {
    let valeur: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") valeur,
             options(nomem, nostack, preserves_flags));
    }
    valeur
}
