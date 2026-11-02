//! Les interruptions des périphériques : quel contrôleur les livre, et
//! sur quels vecteurs.
//!
//! Deux possibilités, choisies une fois au démarrage, comme le fait Linux
//! (`apic_intr_mode_select`) :
//!   - l'APIC local et l'IO-APIC (apic.rs, ioapic.rs), quand la MADT les
//!     décrit et que l'APIC est utilisable : les IRQ ISA n arrivent sur le
//!     vecteur 0x30 + n, et chaque fin d'interruption s'écrit à l'APIC
//!     local. Le 8259, initialisé d'abord, est alors entièrement masqué
//!     (sinon il pourrait encore livrer ses interruptions fantômes) ;
//!   - sinon le 8259 (pic.rs), comme aux étapes 3 à 6d : sans tables ACPI
//!     (`-machine acpi=off`), sans APIC, ou avec un APIC laissé en mode
//!     x2APIC par le micrologiciel. Vecteurs 0x20 à 0x2F.
//! Les pilotes (l'horloge, le clavier) ne voient que les numéros d'IRQ ISA
//! (`demasquer`) ; `gerer` les retrouve d'après le vecteur, et fait ce que
//! demande chaque contrôleur (les fantômes du 8259, l'EOI de l'APIC).

use crate::verrou::Verrou;
use crate::{apic, ioapic, pic};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// L'APIC est-il en service ?
static APIC: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// Les vecteurs donnés à la demande (6g)
// ---------------------------------------------------------------------------
//
// Une interruption MSI ou MSI-X n'arrive sur aucune ligne : le périphérique
// écrit un message à l'APIC local, qui porte directement le VECTEUR (6g,
// msix.rs). Chaque file d'une carte réseau en veut un. Les vecteurs fixes
// (0x30 + n pour l'ISA, 0xEC pour le timer, 0xFE et 0xFF) ne suffisent
// plus : ceux qui restent se donnent à la demande, et chaque vecteur donné
// a son gestionnaire. C'est la `irq_matrix` de Linux (kernel/irq/matrix.c),
// pour un seul processeur : une carte des vecteurs libres, le premier libre
// donné (comme `irq_matrix_alloc`) ; et la table `vector_irq` qui dit, pour
// chaque vecteur, à qui il est.
// UNIPROCESSEUR : une carte des vecteurs pour tout le noyau ; avec
// plusieurs processeurs, une par processeur, et chaque interruption dirigée
// vers l'un d'eux (son affinité).
//
// Le gestionnaire d'un vecteur est une fonction et son argument (l'adresse
// de l'objet du pilote), lus sans verrou dans l'interruption : deux
// atomiques, la fonction écrite en dernier (et effacée en premier) ; le
// pilote ne démasque son interruption qu'une fois `allouer` revenu, et
// `liberer` ne se fait qu'interruption masquée. Option écartée : une
// fermeture Rust (`Box<dyn Fn>`), qu'il faudrait allouer, et lire sous un
// verrou dans l'interruption.

/// Les vecteurs donnés à la demande : de 0x40 (après ceux de l'ISA) à 0xEB
/// (avant le timer). Linux commence à 0x20 (FIRST_EXTERNAL_VECTOR), mais ses
/// IRQ ISA y sont elles aussi données à la demande.
pub const PREMIER_DYNAMIQUE: u8 = 0x40;
pub const DERNIER_DYNAMIQUE: u8 = 0xEB;

/// La carte des vecteurs pris (un bit par vecteur).
static PRIS: Verrou<[u64; 4]> = Verrou::new([0; 4]);

/// Le gestionnaire de chaque vecteur : la fonction (0 : aucune), et son
/// argument.
struct Gestionnaire {
    fonction: AtomicUsize,
    argument: AtomicUsize,
}

static GESTIONNAIRES: [Gestionnaire; 256] =
    [const { Gestionnaire { fonction: AtomicUsize::new(0), argument: AtomicUsize::new(0) } }; 256];

/// Donne un vecteur libre, dont l'interruption appellera `fonction(argument)`
/// (interruptions coupées, avant l'EOI). None : plus aucun libre, ou pas
/// d'APIC (sans lui, les messages MSI n'arrivent nulle part).
pub fn allouer(fonction: fn(usize), argument: usize) -> Option<u8> {
    if !APIC.load(Ordering::Relaxed) {
        return None;
    }
    let mut pris = PRIS.verrouiller();
    let v = (PREMIER_DYNAMIQUE..=DERNIER_DYNAMIQUE).find(|&v| pris[v as usize / 64] & 1 << (v % 64) == 0)?;
    pris[v as usize / 64] |= 1 << (v % 64);
    let g = &GESTIONNAIRES[v as usize];
    g.argument.store(argument, Ordering::Relaxed);
    g.fonction.store(fonction as usize, Ordering::Release);
    Some(v)
}

/// Rend le vecteur `v` : son interruption doit déjà être masquée à la
/// source.
pub fn liberer(v: u8) {
    let mut pris = PRIS.verrouiller();
    GESTIONNAIRES[v as usize].fonction.store(0, Ordering::Release);
    pris[v as usize / 64] &= !(1 << (v % 64));
}

/// Le nombre de vecteurs encore libres.
pub fn libres() -> usize {
    let pris = PRIS.verrouiller();
    (PREMIER_DYNAMIQUE..=DERNIER_DYNAMIQUE).filter(|&v| pris[v as usize / 64] & 1 << (v % 64) == 0).count()
}

/// Le gestionnaire du vecteur `v`, s'il en a un.
fn gestionnaire(v: u8) -> Option<(fn(usize), usize)> {
    let g = &GESTIONNAIRES[v as usize];
    let f = g.fonction.load(Ordering::Acquire);
    // SAFETY : une valeur non nulle n'a été écrite que par `allouer`, à
    // partir d'un `fn(usize)`.
    (f != 0).then(|| (unsafe { core::mem::transmute::<usize, fn(usize)>(f) }, g.argument.load(Ordering::Relaxed)))
}

/// Le vecteur `v` est-il celui d'un périphérique (le clavier, le port
/// série, une MSI-X), dont l'instant d'arrivée nourrit le générateur
/// aléatoire ? Pas l'horloge (ni le timer de l'APIC, ni l'IRQ 0 du PIT) :
/// Linux ne la compte pas, elle est périodique.
pub fn est_un_peripherique(v: u8) -> bool {
    let isa = |irq: u8| irq != crate::horloge::IRQ;
    if APIC.load(Ordering::Relaxed) {
        if (ioapic::VECTEUR_ISA..ioapic::VECTEUR_ISA + ioapic::NB_ISA).contains(&v) {
            return isa(v - ioapic::VECTEUR_ISA);
        }
        return gestionnaire(v).is_some();
    }
    (pic::VECTEUR_BASE..pic::VECTEUR_BASE + pic::NB_IRQ).contains(&v) && isa(v - pic::VECTEUR_BASE)
}

/// Ce que l'initialisation a choisi, pour l'afficher.
pub enum Bilan {
    Apic { apic: apic::Bilan, ioapic: ioapic::Bilan },
    /// Le 8259, et pourquoi.
    Pic(&'static str),
    /// Le 8259, parce que l'APIC a été refusé.
    PicSansApic(apic::Refus),
}

/// Choisit et prépare le contrôleur d'interruptions, toutes les IRQ
/// masquées. Avant `sti`.
pub fn initialiser() -> Bilan {
    // Le 8259 d'abord, dans tous les cas : remappé sur 0x20 à 0x2F, tout
    // masqué. S'il reste en service, c'est fait ; sinon, ses fantômes
    // tombent sur des vecteurs connus.
    pic::initialiser();
    let Some(r) = crate::acpi::avec(|c| {
        let Some(madt) = &c.madt else { return Bilan::Pic("pas de MADT") };
        let a = match apic::initialiser(madt) {
            Ok(a) => a,
            Err(e) => return Bilan::PicSansApic(e),
        };
        match ioapic::initialiser(madt, a.id) {
            Some(i) => Bilan::Apic { apic: a, ioapic: i },
            None => {
                // L'APIC est déjà en service, LINT0 masquée : le 8259 n'y
                // passerait plus.
                apic::fil_virtuel();
                Bilan::Pic("pas d'IO-APIC utilisable")
            }
        }
    }) else {
        return Bilan::Pic("pas de tables ACPI");
    };
    if let Bilan::Apic { .. } = r {
        pic::masquer_tout();
        APIC.store(true, Ordering::Relaxed);
    }
    r
}

/// L'APIC est-il en service (sinon, le 8259) ?
pub fn apic() -> bool {
    APIC.load(Ordering::Relaxed)
}

/// Le vecteur de l'IRQ ISA `irq`.
pub fn vecteur(irq: u8) -> u8 {
    if APIC.load(Ordering::Relaxed) { ioapic::VECTEUR_ISA + irq } else { pic::VECTEUR_BASE + irq }
}

/// Laisse passer l'IRQ ISA `irq` : son pilote est prêt.
pub fn demasquer(irq: u8) {
    if APIC.load(Ordering::Relaxed) {
        ioapic::demasquer(irq);
    } else {
        pic::demasquer(irq);
    }
}

/// D'où vient une interruption matérielle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Une IRQ du bus ISA (par le 8259 ou l'IO-APIC).
    Isa(u8),
    /// Le timer de l'APIC local.
    TimerApic,
}

/// Une interruption matérielle, de vecteur `vecteur` (32 à 255), arrivée.
/// `traiter(source)` fait le travail de son pilote ; puis la fin
/// d'interruption, en dernier (avant, le contrôleur pourrait renvoyer la
/// même IRQ pendant qu'on la traite encore).
pub fn gerer(vecteur: u8, traiter: impl FnOnce(Source)) {
    let base_pic = pic::VECTEUR_BASE;
    match vecteur {
        v if (base_pic..base_pic + pic::NB_IRQ).contains(&v) => {
            let irq = v - base_pic;
            // Un fantôme du 8259 (même masqué, il peut en livrer) : pas
            // d'EOI, sauf la cascade (pic.rs).
            if pic::est_fantome(irq) {
                return;
            }
            if !APIC.load(Ordering::Relaxed) {
                traiter(Source::Isa(irq));
            }
            pic::fin_interruption(irq);
        }
        v if APIC.load(Ordering::Relaxed) && (ioapic::VECTEUR_ISA..ioapic::VECTEUR_ISA + ioapic::NB_ISA).contains(&v) => {
            traiter(Source::Isa(v - ioapic::VECTEUR_ISA));
            apic::fin_interruption();
        }
        apic::VECTEUR_TIMER if APIC.load(Ordering::Relaxed) => {
            traiter(Source::TimerApic);
            apic::fin_interruption();
        }
        // Un fantôme de l'APIC : il n'est pas « en service », pas d'EOI
        // (manuel d'Intel, vol. 3A, 11.9).
        apic::VECTEUR_FANTOME if APIC.load(Ordering::Relaxed) => {}
        apic::VECTEUR_ERREUR if APIC.load(Ordering::Relaxed) => apic::erreur(),
        // Un vecteur donné à la demande (une MSI-X) : son gestionnaire,
        // puis l'EOI.
        v if APIC.load(Ordering::Relaxed) && gestionnaire(v).is_some() => {
            if let Some((f, argument)) = gestionnaire(v) {
                f(argument);
            }
            apic::fin_interruption();
        }
        v => {
            // Un vecteur que personne n'a demandé : on le dit, et on
            // l'acquitte s'il vient de l'APIC (Linux : « spurious or
            // unexpected interrupt »).
            afficherln!("[noyau] interruption inattendue, vecteur {:#x}", v);
            if APIC.load(Ordering::Relaxed) {
                apic::fin_interruption();
            }
        }
    }
}
