//! L'APIC local : le contrôleur d'interruptions de chaque processeur.
//!
//! Depuis le Pentium (1993), chaque processeur x86 a son « APIC local »
//! (Advanced Programmable Interrupt Controller) : c'est lui qui reçoit
//! les interruptions et les présente au cœur, par priorité (les quatre
//! bits hauts du vecteur), et qui les acquitte (EOI). Il a aussi son propre
//! temporisateur (le timer de l'APIC, tsc.rs et horloge.rs), et il sait
//! envoyer des interruptions aux autres processeurs (pour le
//! multiprocesseur). Les périphériques ne lui parlent pas directement :
//! leurs lignes arrivent sur un IO-APIC (ioapic.rs), qui envoie un message
//! à l'APIC local choisi.
//!
//! Ses registres sont en mémoire, une page de 4 Kio à l'adresse que donne
//! la MADT (0xFEE00000 sur tous les PC), chaque registre sur 32 bits tous
//! les 16 octets : on la projette sans cache (vmalloc::ioremap), pour que
//! chaque accès atteigne vraiment l'APIC. C'est le mode « xAPIC ».
//! Options écartées :
//!   - le mode x2APIC (les registres en MSR, des numéros d'APIC sur 32
//!     bits, nécessaire au-delà de 255 processeurs) : QEMU 8.2 ne l'imite
//!     pas sans KVM (mesuré), on ne pourrait pas le vérifier. Un
//!     micrologiciel qui a laissé l'APIC en x2APIC (bit 10 de
//!     IA32_APIC_BASE) : on le dit, et on reste sur le 8259 ;
//!   - garder le 8259 (étapes 3 à 6d) : il n'a que 15 lignes, une seule
//!     priorité fixe par ligne, il ne sait parler qu'à un processeur, et
//!     ne sait rien des interruptions des cartes PCI modernes (MSI, 6g).
//!
//! Chaque processeur a le sien : la page des registres est la même adresse
//! pour tous (chacun y voit le sien), projetée une fois
//! (`initialiser_machine`, sur le premier processeur) ; chaque processeur
//! met le sien en service (`initialiser_processeur` : le premier au
//! démarrage, chaque secondaire à son départ, smp.rs). Les périphériques
//! (l'IO-APIC, les MSI-X des cartes) visent explicitement l'APIC du
//! PREMIER processeur (`id_du_premier`), pas « l'APIC de ce processeur » :
//! la répartition des interruptions entre processeurs n'est pas de 6j.
//!
//! L'initialisation d'un APIC suit `setup_local_APIC` de Linux :
//!   - SVR (Spurious-interrupt Vector Register) : le bit 8 allume l'APIC,
//!     et le vecteur des interruptions « fantômes » (0xFF, comme Linux) :
//!     celles que l'APIC a commencé à présenter puis retirées, qui n'ont
//!     pas d'EOI ;
//!   - TPR (Task Priority Register) à 0 : toutes les priorités passent ;
//!   - les entrées locales (LVT) : LINT0, où arrivait le 8259 en mode
//!     « ExtINT », masquée (les IRQ passent désormais par l'IO-APIC) ;
//!     LINT1 en NMI, d'après la MADT (sous QEMU : tous les processeurs,
//!     LINT1), sur le premier processeur seulement : sur les secondaires,
//!     LINT0 et LINT1 restent masquées, comme chez Linux (« Only the BSP
//!     sees the LINT1 NMI signal by default ») ; le timer, le compteur de
//!     performance et le capteur thermique masqués ; les erreurs de l'APIC
//!     sur le vecteur 0xFE ;
//!   - ESR (Error Status Register) effacé (il s'écrit avant de se lire) ;
//!   - un EOI, pour le cas où une interruption serait restée en service.

use crate::acpi;
use crate::vmalloc;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// Les vecteurs de l'APIC, ceux de Linux (arch/x86/include/asm/irq_vectors.h).
/// Le timer (LOCAL_TIMER_VECTOR), les erreurs, les fantômes.
pub const VECTEUR_TIMER: u8 = 0xEC;
pub const VECTEUR_ERREUR: u8 = 0xFE;
pub const VECTEUR_FANTOME: u8 = 0xFF;

// Les registres, par leur position dans la page.
const ID: usize = 0x20;
const VERSION: usize = 0x30;
const TPR: usize = 0x80;
const EOI: usize = 0xB0;
const SVR: usize = 0xF0;
const ESR: usize = 0x280;
const ICR_BAS: usize = 0x300;
const ICR_HAUT: usize = 0x310;
const LVT_TIMER: usize = 0x320;
const LVT_THERMIQUE: usize = 0x330;
const LVT_PERFORMANCE: usize = 0x340;
const LVT_LINT0: usize = 0x350;
const LVT_LINT1: usize = 0x360;
const LVT_ERREUR: usize = 0x370;
const TIMER_INITIAL: usize = 0x380;
const TIMER_COURANT: usize = 0x390;
const TIMER_DIVISEUR: usize = 0x3E0;

/// Dans une entrée LVT : masquée.
pub const MASQUEE: u32 = 1 << 16;
/// Le mode de livraison NMI (100b, bits 8 à 10).
const MODE_NMI: u32 = 0b100 << 8;
/// Le mode de livraison ExtINT (0b111) : le vecteur vient du 8259.
const MODE_EXTINT: u32 = 0b111 << 8;
/// Dans une entrée LVT : actif bas (bit 13).
const ACTIF_BAS: u32 = 1 << 13;
/// SVR : l'APIC est en service.
const ALLUME: u32 = 1 << 8;

/// Dans l'ICR (Interrupt Command Register, deux registres : le bas porte le
/// message, le haut la destination, bits 24 à 31) : le mode de livraison
/// INIT (101b) et STARTUP (110b, bits 8 à 10) ; « posé » (bit 14, le
/// niveau de l'INIT : 1 pose, 0 lève) ; « en niveau » (bit 15) ; « envoi
/// en cours » (bit 12, à attendre avant le message suivant).
const ICR_INIT: u32 = 0b101 << 8;
const ICR_DEMARRAGE: u32 = 0b110 << 8;
const ICR_POSE: u32 = 1 << 14;
const ICR_NIVEAU: u32 = 1 << 15;
const ICR_EN_COURS: u32 = 1 << 12;

/// Le MSR de l'adresse de l'APIC : bit 11, l'APIC est en service ; bit 10,
/// en mode x2APIC ; bits 12 et plus, l'adresse physique de ses registres.
const IA32_APIC_BASE: u32 = 0x1B;
const APIC_EN: u64 = 1 << 11;
const APIC_EXTD: u64 = 1 << 10;

/// Le numéro de l'APIC du PREMIER processeur, celui que visent les messages
/// MSI (msix.rs) et les entrées de l'IO-APIC : la destination des
/// périphériques, pas « l'APIC de ce processeur » (chaque processeur a le
/// sien dans sa zone, processeur.rs, 6j). Une constante du démarrage.
static ID_APIC: AtomicU8 = AtomicU8::new(0);

/// L'adresse virtuelle des registres (la projection, gardée pour
/// toujours : l'APIC sert jusqu'à l'arrêt de la machine). 0 : pas d'APIC
/// en service.
static REGISTRES: AtomicU64 = AtomicU64::new(0);

fn lire(registre: usize) -> u32 {
    let base = REGISTRES.load(Ordering::Relaxed);
    debug_assert!(base != 0);
    // SAFETY: la page des registres est projetée sans cache
    // (initialiser) ; un accès de 32 bits aligné, ce qu'exige l'APIC.
    unsafe { ((base + registre as u64) as *const u32).read_volatile() }
}

fn ecrire(registre: usize, valeur: u32) {
    let base = REGISTRES.load(Ordering::Relaxed);
    debug_assert!(base != 0);
    // SAFETY: comme `lire`.
    unsafe { ((base + registre as u64) as *mut u32).write_volatile(valeur) }
}

/// Pourquoi l'APIC n'est pas en service.
pub enum Refus {
    /// Le processeur n'en a pas (CPUID.1:EDX, bit 9).
    Absent,
    /// Le micrologiciel l'a laissé éteint (IA32_APIC_BASE, bit 11).
    Eteint,
    /// Le micrologiciel l'a laissé en mode x2APIC.
    X2apic,
    /// Plus de place pour projeter ses registres.
    Projection,
}

// Affiché par le noyau : sans accents.
impl core::fmt::Display for Refus {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(match self {
            Refus::Absent => "le processeur n'a pas d'APIC",
            Refus::Eteint => "l'APIC est eteint par le micrologiciel",
            Refus::X2apic => "l'APIC est en mode x2APIC (non pris en charge)",
            Refus::Projection => "ses registres n'ont pas pu etre projetes",
        })
    }
}

/// Ce que l'initialisation a trouvé, pour l'afficher.
pub struct Bilan {
    pub id: u8,
    pub adresse: u64,
    pub version: u8,
}

fn lire_msr(msr: u32) -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY: IA32_APIC_BASE existe dès que CPUID dit qu'il y a un APIC.
    unsafe { core::arch::asm!("rdmsr", in("ecx") msr, out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}

/// Ce qui vaut pour la machine : projette la page des registres, lit le
/// numéro et la version de l'APIC du premier processeur, puis met son APIC
/// en service (`initialiser_processeur`). D'après la MADT (`madt` : son
/// adresse, ses NMI). Sur le premier processeur, interruptions coupées.
pub fn initialiser_machine(madt: &acpi::ConfigurationMadt) -> Result<Bilan, Refus> {
    if core::arch::x86_64::__cpuid(1).edx & 1 << 9 == 0 {
        return Err(Refus::Absent);
    }
    let base = lire_msr(IA32_APIC_BASE);
    if base & APIC_EN == 0 {
        return Err(Refus::Eteint);
    }
    if base & APIC_EXTD != 0 {
        return Err(Refus::X2apic);
    }
    // L'adresse de la MADT (Linux la préfère aussi à celle du MSR, qui la
    // vaut toujours sur un PC).
    let adresse = madt.apic_local;
    let projection = vmalloc::ioremap(adresse, 4096).ok_or(Refus::Projection)?;
    REGISTRES.store(projection.adresse(), Ordering::Relaxed);
    // Projetés pour toujours : la projection n'est jamais rendue.
    core::mem::forget(projection);

    let id = id_local();
    ID_APIC.store(id, Ordering::Relaxed);
    let version = lire(VERSION) as u8;
    initialiser_processeur(madt, true);
    Ok(Bilan { id, adresse, version })
}

/// Met en service l'APIC local du processeur qui exécute ceci (le
/// `setup_local_APIC` de Linux, voir l'en-tête) : le premier au démarrage
/// (`premier` : son NMI d'après la MADT), chaque secondaire à son départ
/// (smp.rs : LINT0 et LINT1 masquées). Interruptions coupées.
pub fn initialiser_processeur(madt: &acpi::ConfigurationMadt, premier: bool) {
    let id = id_local();
    // Le nombre d'entrées LVT moins un, bits 16 à 23 : le capteur thermique
    // et le compteur de performance n'existent que si l'APIC les a (5 et 4
    // entrées au moins, sur la cinquième et la sixième).
    let entrees = (lire(VERSION) >> 16 & 0xFF) + 1;
    ecrire(TPR, 0);
    ecrire(SVR, ALLUME | VECTEUR_FANTOME as u32);
    ecrire(LVT_TIMER, MASQUEE);
    if entrees >= 5 {
        ecrire(LVT_PERFORMANCE, MASQUEE);
    }
    if entrees >= 6 {
        ecrire(LVT_THERMIQUE, MASQUEE);
    }
    ecrire(LVT_LINT0, MASQUEE);
    if premier {
        // Le NMI : sur l'entrée que dit la MADT, pour ce processeur ou pour
        // tous (0xFF) ; sans entrée, LINT1, la règle des PC (Linux fait de
        // même). Polarité et déclenchement : ceux de la MADT, sinon ceux du
        // bus (front montant, actif haut) ; un NMI est toujours par front.
        let nmi = madt.nmi.iter().find(|&&(p, _, _)| p == 0xFF || madt.processeurs.iter().any(|&(n, a)| n == p && a == id));
        let (lint, drapeaux) = nmi.map_or((1, 0), |&(_, d, l)| (l, d));
        let polarite = if drapeaux & 3 == 3 { ACTIF_BAS } else { 0 };
        let entree_nmi = MODE_NMI | polarite;
        if lint == 0 {
            ecrire(LVT_LINT0, entree_nmi);
            ecrire(LVT_LINT1, MASQUEE);
        } else {
            ecrire(LVT_LINT1, entree_nmi);
        }
    } else {
        ecrire(LVT_LINT1, MASQUEE);
    }
    ecrire(LVT_ERREUR, VECTEUR_ERREUR as u32);
    // ESR : une écriture fige les erreurs en cours dans le registre, la
    // seconde efface ce qui a été figé (Linux en fait deux aussi).
    ecrire(ESR, 0);
    ecrire(ESR, 0);
    fin_interruption();
}

/// Le repli sur le 8259 avec l'APIC local déjà en service (pas d'IO-APIC
/// utilisable, découvert après lui) : le 8259 arrive sur LINT0, qu'on
/// avait masquée. Elle passe en ExtINT, le « fil virtuel » des PC : le
/// processeur demande alors le vecteur au 8259, comme sans APIC (ce que
/// fait Linux, `APIC_DM_EXTINT` sur LVT0). Sauf si le NMI est sur LINT0
/// (la MADT le dit) : le 8259 n'a alors pas de chemin, comme sous Linux.
pub fn fil_virtuel() {
    if lire(LVT_LINT0) & (0b111 << 8) != MODE_NMI {
        ecrire(LVT_LINT0, MODE_EXTINT);
    }
}

/// La fin d'une interruption : l'APIC peut en présenter une autre de même
/// priorité ou de priorité plus basse. Pour une interruption en niveau
/// venue d'un IO-APIC, l'APIC prévient aussi l'IO-APIC (EOI diffusé).
pub fn fin_interruption() {
    ecrire(EOI, 0);
}

/// Une erreur signalée par l'APIC (vecteur 0xFE) : ce que dit ESR (un
/// message illégal, un vecteur reçu invalide...). Rien à corriger : on la
/// dit, comme Linux (« APIC error on CPU0 »).
pub fn erreur() {
    ecrire(ESR, 0);
    let esr = lire(ESR);
    afficherln!("[noyau] erreur de l'APIC local (ESR {:#x})", esr);
    fin_interruption();
}

/// Le diviseur du timer : 16 (0b0011 dans le registre), celui de Linux
/// (APIC_DIVISOR) : un décompte de 32 bits dure ainsi des secondes même
/// sur un bus rapide, et une milliseconde en compte encore des dizaines
/// de milliers.
const DIVISEUR_16: u32 = 0b0011;
/// Dans l'entrée LVT du timer : périodique (bit 17), sinon en un coup.
const PERIODIQUE: u32 = 1 << 17;

/// Fait décompter le timer depuis 2^32 - 1, masqué : le début d'un
/// étalonnage (horloge.rs).
pub fn armer_etalonnage() {
    ecrire(TIMER_DIVISEUR, DIVISEUR_16);
    ecrire(LVT_TIMER, MASQUEE | VECTEUR_TIMER as u32);
    ecrire(TIMER_INITIAL, u32::MAX);
}

/// Le nombre de décomptes depuis `armer_etalonnage`.
pub fn decomptes_etalonnage() -> u64 {
    (u32::MAX - lire(TIMER_COURANT)) as u64
}

/// Démarre le timer en mode périodique : une interruption (vecteur 0xEC)
/// tous les `decompte` décomptes.
pub fn demarrer_timer(decompte: u32) {
    ecrire(TIMER_DIVISEUR, DIVISEUR_16);
    ecrire(LVT_TIMER, PERIODIQUE | VECTEUR_TIMER as u32);
    ecrire(TIMER_INITIAL, decompte);
}

/// Le numéro de l'APIC du PREMIER processeur : la destination des
/// périphériques (ioapic.rs, msix.rs), voir l'en-tête.
pub fn id_du_premier() -> u8 {
    ID_APIC.load(Ordering::Relaxed)
}

/// Le numéro de l'APIC du processeur qui exécute ceci, lu dans ses
/// registres (bits 24 à 31 du registre ID, en xAPIC).
pub fn id_local() -> u8 {
    (lire(ID) >> 24) as u8
}

/// Envoie le message `bas` de l'ICR à l'APIC `destination` : le haut
/// d'abord (la destination), puis le bas, dont l'écriture déclenche
/// l'envoi.
fn envoyer(destination: u8, bas: u32) {
    ecrire(ICR_HAUT, (destination as u32) << 24);
    ecrire(ICR_BAS, bas);
}

/// Attend que l'APIC ait fini d'envoyer le message précédent (le bit « en
/// cours » de l'ICR retombe) : au plus 100 ms, par pas de 100 µs (le
/// `safe_apic_wait_icr_idle` de Linux). Faux si le message n'est jamais
/// parti. Interruptions actives (l'attente passe par l'horloge).
pub fn attendre_envoi() -> bool {
    for _ in 0..1000 {
        if lire(ICR_BAS) & ICR_EN_COURS == 0 {
            return true;
        }
        crate::horloge::attendre_us(100);
    }
    false
}

/// Envoie le message `bas` à `destination`, interruptions coupées le temps
/// d'attendre que l'ICR soit libre et de l'écrire (ses deux moitiés) : un
/// gestionnaire d'interruption qui enverrait une IPI entre les deux
/// écritures (un réveil fait du tic, qui reprogramme un autre processeur)
/// changerait la destination sous nous, et le message partirait ailleurs
/// (le `local_irq_save` du `native_apic_icr_write` de Linux). Pour tout ce
/// qui s'envoie : les IPI, le NMI, l'INIT et les SIPI du démarrage (la
/// relecture de 6j : ces derniers s'écrivaient interruptions actives).
fn envoyer_protege(destination: u8, bas: u32) {
    let interruptions = crate::cpu::couper_interruptions();
    attendre_envoi();
    envoyer(destination, bas);
    if interruptions {
        crate::cpu::activer_interruptions();
    }
}

/// Pose l'INIT sur l'APIC `destination` (en niveau) : le processeur revient
/// à son état de mise sous tension, et attend un SIPI (smp.rs).
pub fn envoyer_init(destination: u8) {
    envoyer_protege(destination, ICR_INIT | ICR_NIVEAU | ICR_POSE);
}

/// Lève l'INIT (le `APIC_INT_LEVELTRIG | APIC_DM_INIT` de
/// `send_init_sequence`), 10 ms après l'avoir posé.
pub fn lever_init(destination: u8) {
    envoyer_protege(destination, ICR_INIT | ICR_NIVEAU);
}

/// Envoie un SIPI à l'APIC `destination` : le processeur commence à
/// exécuter la page `page` de la mémoire basse (adresse page × 4 Kio, en
/// mode réel : CS = page × 0x100, IP = 0).
pub fn envoyer_demarrage(destination: u8, page: u8) {
    envoyer_protege(destination, ICR_DEMARRAGE | page as u32);
}

/// Les erreurs que l'APIC a notées depuis la dernière lecture (ESR, sans
/// ses bits réservés : 0xEF, comme Linux), après les avoir figées ; 0 :
/// aucune. Pour savoir si un SIPI a été accepté.
pub fn erreurs() -> u32 {
    ecrire(ESR, 0);
    lire(ESR) & 0xEF
}

/// Envoie l'interruption `vecteur` à ce processeur lui-même (une IPI
/// « à soi », le raccourci 01 de l'ICR, en livraison fixe) : elle arrive
/// comme celle d'un périphérique, dès que les interruptions sont permises.
pub fn ipi_a_soi(vecteur: u8) {
    const A_SOI: u32 = 0b01 << 18;
    ecrire(ICR_HAUT, 0);
    ecrire(ICR_BAS, A_SOI | vecteur as u32);
}
