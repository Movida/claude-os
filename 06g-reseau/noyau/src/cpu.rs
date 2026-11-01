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

/// Les interruptions sont-elles actives (IF) ?
pub fn interruptions_actives() -> bool {
    let rflags: u64;
    // SAFETY : pushfq/pop ne font que lire RFLAGS.
    unsafe { asm!("pushfq", "pop {}", out(reg) rflags) };
    rflags & (1 << 9) != 0
}

pub fn activer_interruptions() {
    // SAFETY : l'IDT est en place (interruptions::initialiser) avant tout
    // appel ; une interruption trouvera son gestionnaire.
    unsafe { asm!("sti", options(nostack)) };
}

/// Active les interruptions et endort le CPU jusqu'à la prochaine.
///
/// `sti` et `hlt` sont collés exprès : `sti` ne prend effet qu'APRÈS
/// l'instruction qui le suit. Une interruption ne peut donc pas tomber
/// entre les deux. Sans cette garantie, ce code serait faux :
///     cli ; if rien_a_faire { sti ; <IRQ ici, qui crée du travail> ; hlt }
/// le CPU dormirait alors avec du travail en attente. L'appelant coupe les
/// interruptions, vérifie s'il a quelque chose à faire, et sinon appelle
/// cette fonction : c'est la boucle d'attente de Linux (safe_halt).
pub fn attendre_interruption() {
    // SAFETY : comme activer_interruptions ; hlt ne fait qu'attendre.
    unsafe { asm!("sti", "hlt", options(nostack)) };
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

/// Le MSR de la base du segment FS : en 64 bits, le seul usage qui reste
/// de FS est d'y ranger une adresse de base, que le programme fixe par
/// arch_prctl. La glibc y met son bloc de « variables propres au fil
/// d'exécution » (TLS : errno, entre autres), lu par `mov rax, fs:[...]`.
const FS_BASE: u32 = 0xC000_0100;

/// Fixe la base de FS du programme en cours.
pub fn ecrire_base_fs(base: u64) {
    // SAFETY : le MSR existe sur tout processeur 64 bits ; le noyau ne se
    // sert pas de FS. L'appelant vérifie que `base` est une adresse
    // canonique (sinon wrmsr fait une faute de protection générale).
    unsafe {
        asm!("wrmsr", in("ecx") FS_BASE, in("eax") base as u32, in("edx") (base >> 32) as u32,
             options(nostack, preserves_flags));
    }
}

/// La base de FS du programme en cours.
pub fn lire_base_fs() -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY : lecture d'un MSR qui existe, sans effet.
    unsafe { asm!("rdmsr", in("ecx") FS_BASE, out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}
