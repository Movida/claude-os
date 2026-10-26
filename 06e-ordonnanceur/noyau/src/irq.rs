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

use crate::{apic, ioapic, pic};
use core::sync::atomic::{AtomicBool, Ordering};

/// L'APIC est-il en service ?
static APIC: AtomicBool = AtomicBool::new(false);

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

/// Une interruption matérielle, de vecteur `vecteur` (32 à 255), arrivée.
/// `traiter(irq)` fait le travail du pilote de l'IRQ ISA ; puis la fin
/// d'interruption, en dernier (avant, le contrôleur pourrait renvoyer la
/// même IRQ pendant qu'on la traite encore).
pub fn gerer(vecteur: u8, traiter: impl FnOnce(u8)) {
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
                traiter(irq);
            }
            pic::fin_interruption(irq);
        }
        v if APIC.load(Ordering::Relaxed) && (ioapic::VECTEUR_ISA..ioapic::VECTEUR_ISA + ioapic::NB_ISA).contains(&v) => {
            traiter(v - ioapic::VECTEUR_ISA);
            apic::fin_interruption();
        }
        // Un fantôme de l'APIC : il n'est pas « en service », pas d'EOI
        // (manuel d'Intel, vol. 3A, 11.9).
        apic::VECTEUR_FANTOME if APIC.load(Ordering::Relaxed) => {}
        apic::VECTEUR_ERREUR if APIC.load(Ordering::Relaxed) => apic::erreur(),
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
