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
    // SAFETY: pushfq/pop lisent RFLAGS ; cli ne fait que masquer les
    // interruptions.
    unsafe { asm!("pushfq", "pop {}", "cli", out(reg) rflags) };
    rflags & (1 << 9) != 0
}

/// Les interruptions sont-elles actives (IF) ?
pub fn interruptions_actives() -> bool {
    let rflags: u64;
    // SAFETY: pushfq/pop ne font que lire RFLAGS.
    unsafe { asm!("pushfq", "pop {}", out(reg) rflags) };
    rflags & (1 << 9) != 0
}

pub fn activer_interruptions() {
    // SAFETY: l'IDT est en place (interruptions::initialiser) avant tout
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
    // SAFETY: comme activer_interruptions ; hlt ne fait qu'attendre.
    unsafe { asm!("sti", "hlt", options(nostack)) };
}

/// Arrête le processeur pour de bon : interruptions coupées, puis `hlt`.
/// La boucle reprend l'arrêt si une interruption non masquable (NMI) le
/// réveille.
pub fn arreter() -> ! {
    loop {
        // SAFETY: cli et hlt n'ont pas d'autre effet que d'arrêter le
        // processeur, ce qu'on veut ici.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Les registres de contrôle CR0 et CR4, pour les comparer d'un processeur
/// à l'autre (smp.rs) et les donner aux secondaires (trampoline.rs).
pub fn lire_cr0() -> u64 {
    let v: u64;
    // SAFETY: lecture d'un registre de contrôle, sans effet.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

pub fn lire_cr4() -> u64 {
    let v: u64;
    // SAFETY: comme `lire_cr0`.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Lit un registre spécifique du modèle (MSR).
///
/// # Safety
/// `msr` doit exister sur ce processeur (sinon, faute de protection
/// générale).
pub unsafe fn lire_msr(msr: u32) -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY: garanti par l'appelant.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}

/// Écrit un registre spécifique du modèle (MSR).
///
/// # Safety
/// `msr` doit exister, et `valeur` y avoir un sens.
pub unsafe fn ecrire_msr(msr: u32, valeur: u64) {
    // SAFETY: garanti par l'appelant.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") valeur as u32, in("edx") (valeur >> 32) as u32,
             options(nostack, preserves_flags));
    }
}

/// Le MSR EFER (Extended Feature Enable Register) : le mode long (LME,
/// LMA), le bit NX (NXE), `syscall` (SCE).
pub const EFER: u32 = 0xC000_0080;

pub fn lire_efer() -> u64 {
    // SAFETY: EFER existe sur tout processeur 64 bits.
    unsafe { lire_msr(EFER) }
}

/// Le MSR de la base du segment FS : en 64 bits, le seul usage qui reste
/// de FS est d'y ranger une adresse de base, que le programme fixe par
/// arch_prctl. La glibc y met son bloc de « variables propres au fil
/// d'exécution » (TLS : errno, entre autres), lu par `mov rax, fs:[...]`.
const FS_BASE: u32 = 0xC000_0100;

/// Le processeur a-t-il le défaut de SYSRET des AMD (et des Hygon, leurs
/// cousins) : `sysretq` y charge le sélecteur de SS sans en refaire les
/// attributs (le `X86_BUG_SYSRET_SS_ATTRS` de Linux, posé d'après le
/// fabricant, `init_amd`). En mode long, une interruption venue de l'anneau 3
/// laisse un SS nul ; si la tâche qui revient ensuite au programme par
/// `sysretq` hérite de ce SS (une bascule entre les deux), le programme
/// repart avec un SS inutilisable. Lu une fois (CPUID 0, le nom du
/// fabricant), puis gardé.
pub fn bogue_sysret_ss() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering::Relaxed};
    static CONNU: AtomicU8 = AtomicU8::new(0);
    match CONNU.load(Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let c = core::arch::x86_64::__cpuid(0);
            let mut nom = [0u8; 12];
            nom[..4].copy_from_slice(&c.ebx.to_le_bytes());
            nom[4..8].copy_from_slice(&c.edx.to_le_bytes());
            nom[8..].copy_from_slice(&c.ecx.to_le_bytes());
            let amd = &nom == b"AuthenticAMD" || &nom == b"HygonGenuine";
            CONNU.store(if amd { 2 } else { 1 }, Relaxed);
            amd
        }
    }
}

/// Le contournement de Linux pour ce défaut (`__switch_to`) : à chaque
/// bascule, si SS n'est pas celui des données du noyau, le recharger ; la
/// tâche qui reviendra au programme par `sysretq` part alors d'un SS valide.
pub fn ss_du_noyau() {
    let ss: u16;
    // SAFETY: lire SS n'a aucun effet ; y charger le sélecteur des données
    // du noyau (présent, écrivable, DPL 0, dans la GDT du processeur) est ce
    // que fait toute entrée dans le noyau, et ne change rien à la pile.
    unsafe {
        asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        if ss != crate::gdt::DONNEES_NOYAU {
            asm!("mov ss, {0:x}", in(reg) crate::gdt::DONNEES_NOYAU, options(nostack, preserves_flags));
        }
    }
    if ss != crate::gdt::DONNEES_NOYAU {
        SS_RECHARGES.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

/// Les bascules où SS n'était pas celui du noyau (le plus souvent nul,
/// après une interruption venue de l'anneau 3), et a été rechargé : la
/// preuve que le contournement sert (make tests-qemu, sous -cpu EPYC).
static SS_RECHARGES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Le nombre de ces rechargements.
pub fn ss_recharges() -> u64 {
    SS_RECHARGES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Le nombre de bits d'une adresse physique (MAXPHYADDR) : CPUID
/// 0x80000008, comme `get_cpu_address_sizes` de Linux ; 36 si le
/// processeur n'a pas cette feuille (la valeur de Linux pour x86_64).
pub fn bits_physiques() -> u32 {
    if core::arch::x86_64::__cpuid(0x8000_0000).eax < 0x8000_0008 {
        return 36;
    }
    core::arch::x86_64::__cpuid(0x8000_0008).eax & 0xFF
}

/// Fixe la base de FS du programme en cours.
pub fn ecrire_base_fs(base: u64) {
    // SAFETY: le MSR existe sur tout processeur 64 bits ; le noyau ne se
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
    // SAFETY: lecture d'un MSR qui existe, sans effet.
    unsafe { asm!("rdmsr", in("ecx") FS_BASE, out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}
