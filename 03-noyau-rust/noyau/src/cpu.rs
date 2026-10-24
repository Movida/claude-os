//! Les instructions du processeur qui gouvernent les interruptions.
//!
//! Le bit IF (Interrupt Flag, n° 9 du registre RFLAGS) dit si le CPU
//! accepte les interruptions matérielles : `sti` le met à 1, `cli` à 0.
//! Les exceptions (division par zéro, faute de page...) ne dépendent pas de
//! lui : elles arrivent toujours.
//!
//! Aucune de ces fonctions ne porte l'option `nomem` : sans elle, le
//! compilateur suppose que l'instruction lit et écrit la mémoire, et n'a
//! pas le droit de déplacer un accès mémoire de part et d'autre. Elles
//! servent ainsi de « barrière », comme le "memory" des macros de Linux
//! (local_irq_save...) : un accès à une donnée protégée ne doit pas glisser
//! hors de la zone où les interruptions sont coupées.

use core::arch::asm;

/// Coupe les interruptions et dit si elles étaient actives, pour pouvoir
/// rétablir exactement l'état d'avant (local_irq_save de Linux). On ne lit
/// RFLAGS qu'en l'empilant (pushfq).
pub fn couper_interruptions() -> bool {
    let rflags: u64;
    // SAFETY : pushfq/pop lisent RFLAGS ; cli ne fait que masquer les
    // interruptions.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) rflags) };
    rflags & (1 << 9) != 0
}

pub fn activer_interruptions() {
    // SAFETY : l'IDT est en place (interruptions::initialiser) avant tout
    // appel ; une interruption trouvera son gestionnaire.
    unsafe { asm!("sti", options(nostack)) };
}

/// Arrête le processeur pour de bon : interruptions coupées, puis `hlt`.
/// La boucle reprend l'arrêt si une interruption non masquable (NMI) le
/// réveille.
pub fn arreter() -> ! {
    loop {
        // SAFETY : cli et hlt n'ont pas d'autre effet que d'arrêter le
        // processeur, ce qu'on veut ici.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}
