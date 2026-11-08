//! La zone propre à chaque processeur, trouvée par le segment GS.
//!
//! Jusqu'à 6i, le noyau tournait sur un seul processeur, et une dizaine de
//! variables globales décrivaient en fait LE processeur, pas le système :
//! la tâche qui s'exécute, la TSS (la pile que prend le processeur à la
//! prochaine interruption venue de l'anneau 3), le nombre de verrous
//! tenus, « dans une interruption », la tâche morte à rendre après la
//! bascule. Avec plusieurs processeurs, chacun a les siennes. Il faut les
//! trouver vite, et sans registre : la première instruction de l'entrée de
//! `syscall` lit la pile noyau dans la TSS alors que RSP vaut encore ce que
//! le programme y a mis, et que tous les registres sont au programme.
//!
//! La solution de Linux (`DEFINE_PER_CPU`, `this_cpu_read`, le
//! `pcpu_hot`), et la nôtre : un SEGMENT. En 64 bits, les segments ne
//! servent plus à rien, sauf FS et GS, dont la base s'ajoute encore à
//! l'adresse : `mov rax, gs:[8]` lit le mot à base_de_GS + 8. La base de GS
//! du noyau désigne la zone du processeur ; la lire tient en une
//! instruction, sans registre libre. Comme le programme a droit à sa propre
//! base de GS (l'ABI le permet, même si la glibc n'en a pas besoin en 64
//! bits), le processeur en garde DEUX, dans les MSR GS_BASE (l'active) et
//! KERNEL_GS_BASE (l'autre), et l'instruction `swapgs` les échange : à
//! l'entrée dans le noyau, et juste avant d'en sortir (appel_systeme.rs,
//! interruptions.rs). Options écartées :
//!   - une table indexée par le numéro d'APIC du processeur : il faut le
//!     lire dans les registres de l'APIC (un accès mémoire sans cache, des
//!     centaines de cycles) ou par CPUID (qui vide le pipeline), et il faut
//!     un registre pour le faire, qu'on n'a pas à l'entrée de `syscall` ;
//!   - `rdpid` ou `rdtscp`, qui rendent un numéro de processeur rangé par
//!     le noyau dans un MSR : il faut encore un registre, puis une table ;
//!   - les instructions FSGSBASE (`wrgsbase`, Ivy Bridge et plus), que
//!     Linux préfère aux MSR quand il les a : notre Nehalem ne les a pas.
//!
//! Le numéro du processeur est le PREMIER champ de la zone (`gs:[0]`), et
//! la zone est l'élément de ce numéro du tableau ZONES_PROCESSEURS : le
//! noyau retrouve sa zone par ce numéro, sans pointeur sur elle-même (Rust
//! ne sait pas écrire, dans l'initialisation d'une variable statique, un
//! pointeur vers elle-même). Linux range plutôt le décalage de la zone
//! (`this_cpu_off`) ; une multiplication par la taille de la zone revient
//! au même.
//!
//! LA RÈGLE D'ACCÈS. Une donnée du processeur ne se lit et ne s'écrit
//! qu'interruptions coupées (ou, dès 6j, préemption coupée) : sinon, entre
//! la lecture de « ma zone » et son usage, le tic peut préempter la tâche,
//! et une autre file des prêtes la reprendre sur un AUTRE processeur ; on
//! écrirait alors dans la zone d'un processeur qui n'est plus le sien.
//! C'est le `debug_smp_processor_id` de Linux. `courant` le vérifie par un
//! `assert!` (le noyau est construit en --release, où `debug_assert!` ne
//! vérifie rien). Deux exceptions, écrites : la tâche courante (quel que
//! soit le processeur, c'est toujours « soi-même » : `tache::courante`), et
//! les compteurs du contexte courant lus interruptions actives (les
//! verrous tenus, « dans une interruption » : s'ils ne sont pas nuls,
//! c'est NOUS qui les tenons, et nous ne pouvons pas être déplacés ; s'ils
//! sont nuls, ils le restent tant que nous ne prenons rien). Ces lectures
//! passent par `courant_sans_verification`, qui dit pourquoi à chaque
//! appel.
//!
//! Les champs sont des atomiques ou des `UnsafeCell`, jamais un `&mut
//! Processeur` : une interruption imbriquée sur le même processeur en
//! ferait deux. Ce que la zone contient grandit avec 6j : la file des
//! prêtes du processeur (ordonnanceur.rs), le compte de préemption, les
//! statistiques des verrous.

use crate::cpu;
use crate::gdt::TssAlignee;
use crate::tache::Tache;
use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32};

/// Le nombre maximal de processeurs : la taille du masque de
/// `sched_getaffinity` (un `unsigned long`, 64 bits). Linux va bien
/// au-delà, avec des masques plus longs ; aucune machine de QEMU qui nous
/// serve n'approche de ce nombre.
pub const MAX: usize = 64;

/// La zone d'un processeur.
#[repr(C)]
pub struct Processeur {
    /// Son numéro (0 pour le processeur de démarrage) : l'index de sa zone
    /// dans ZONES_PROCESSEURS. À l'octet 0 : c'est lui que lit `gs:[0]`.
    pub numero: u32,
    /// Le numéro de son APIC local (apic.rs), 0 tant qu'il n'est pas lu.
    pub apic: AtomicU8,
    /// Le nombre de verrous tenus sur ce processeur (verrou.rs, la part
    /// « verrous » du `preempt_count` de Linux).
    pub tenus: AtomicU32,
    /// Le nombre d'interruptions matérielles en cours de traitement
    /// (interruptions.rs, la part HARDIRQ du `preempt_count`).
    pub dans_une_interruption: AtomicU32,
    /// La tâche qui s'exécute sur ce processeur (le `current` de Linux).
    pub courante: AtomicPtr<Tache>,
    /// Sa tâche inactive, celle qui prend le processeur quand aucune autre
    /// n'est prête (tache.rs).
    pub inactive: AtomicPtr<Tache>,
    /// La tâche qui vient de mourir sur ce processeur, à rendre à la fin de
    /// la bascule qui suit (tache.rs).
    pub a_rendre: AtomicPtr<Tache>,
    /// Sa TSS, lue par le processeur à chaque entrée depuis l'anneau 3, et
    /// par l'entrée de `syscall` (gs:[tss + 4] et gs:[tss + 20] :
    /// appel_systeme.rs), d'où `#[repr(C)]` et un décalage connu
    /// (`offset_of!`). Écrite interruptions coupées, par ce processeur seul.
    pub tss: UnsafeCell<TssAlignee>,
    /// Sa GDT (gdt.rs) : la même que celle des autres processeurs, sauf le
    /// descripteur de la TSS, qui porte l'adresse de la sienne.
    pub gdt: UnsafeCell<[u64; 10]>,
}

// SAFETY: chaque champ est atomique, ou dans un UnsafeCell que seul son
// processeur écrit : la TSS et la GDT interruptions coupées (gdt.rs), le
// compte de préemption par une seule instruction gs-relative,
// interruptions actives ou non (indivisible pour une interruption de ce
// processeur, et aucun autre n'y touche).
unsafe impl Sync for Processeur {}

impl Processeur {
    const fn new(numero: u32) -> Processeur {
        Processeur {
            numero,
            apic: AtomicU8::new(0),
            tenus: AtomicU32::new(0),
            dans_une_interruption: AtomicU32::new(0),
            courante: AtomicPtr::new(core::ptr::null_mut()),
            inactive: AtomicPtr::new(core::ptr::null_mut()),
            a_rendre: AtomicPtr::new(core::ptr::null_mut()),
            tss: UnsafeCell::new(TssAlignee::vide()),
            gdt: UnsafeCell::new([0; 10]),
        }
    }
}

/// Les zones, une par numéro.
#[repr(transparent)]
pub struct Zones([Processeur; MAX]);

const fn zones() -> Zones {
    let mut z = [const { Processeur::new(0) }; MAX];
    let mut i = 0;
    while i < MAX {
        z[i].numero = i as u32;
        i += 1;
    }
    Zones(z)
}

/// Les zones de tous les processeurs. Un nom fixe (no_mangle) : le
/// démarrage (main.rs, `_start`) met la base de GS sur la première avant
/// la première ligne de Rust, puisque le premier `Verrou` (celui de la
/// console) compte déjà ses verrous tenus dans la zone.
#[unsafe(no_mangle)]
pub static ZONES_PROCESSEURS: Zones = zones();

/// Le numéro du processeur qui exécute ceci : `gs:[0]`.
fn numero_brut() -> u32 {
    let n: u32;
    // SAFETY: la base de GS du noyau désigne une zone (posée par `_start`
    // pour le premier processeur, et par le trampoline pour un secondaire
    // (trampoline.rs, `trampoline_64`, avant sa première instruction
    // Rust) : avant tout code qui vient ici), dont le premier champ est le
    // numéro.
    unsafe { asm!("mov {:e}, gs:[0]", out(reg) n, options(nostack, readonly, preserves_flags)) };
    n
}

/// La zone de ce processeur. Interruptions coupées (voir l'en-tête).
#[track_caller]
pub fn courant() -> &'static Processeur {
    assert!(!cpu::interruptions_actives(), "zone du processeur lue interruptions actives");
    &ZONES_PROCESSEURS.0[numero_brut() as usize]
}

/// La zone de ce processeur, sans vérifier les interruptions : seulement
/// pour les champs qu'une tâche peut lire interruptions actives sans
/// risque (voir l'en-tête : la tâche courante, les compteurs du contexte
/// courant). `pourquoi` le dit, pour qui relit l'appel.
pub fn courant_sans_verification(pourquoi: &'static str) -> &'static Processeur {
    let _ = pourquoi;
    &ZONES_PROCESSEURS.0[numero_brut() as usize]
}

/// Le numéro de ce processeur : une valeur qui peut être périmée dès
/// qu'on la lit (interruptions actives, la tâche peut être déplacée), ce
/// que `getcpu` et `sched_getcpu` acceptent (Linux le dit aussi).
pub fn numero() -> u32 {
    numero_brut()
}

/// La zone du processeur `n`.
pub fn zone(n: usize) -> &'static Processeur {
    &ZONES_PROCESSEURS.0[n]
}

/// Le MSR de la base de GS du noyau (celle qui est active dans le noyau).
const GS_BASE: u32 = 0xC000_0101;

/// Fait de la zone `p` celle de ce processeur : GS_BASE y pointe. Au
/// démarrage de chaque processeur, et après tout rechargement du sélecteur
/// GS (`mov gs, ...` remet la base à celle du descripteur, zéro : gdt.rs).
/// Interruptions coupées.
pub fn charger_base_gs(p: &'static Processeur) {
    let base = p as *const Processeur as u64;
    // SAFETY: GS_BASE existe sur tout processeur 64 bits ; `p` est une zone
    // statique, une adresse canonique du noyau.
    unsafe {
        asm!("wrmsr", in("ecx") GS_BASE, in("eax") base as u32, in("edx") (base >> 32) as u32,
             options(nostack, preserves_flags));
    }
}
