//! Les tables ACPI de la machine : les trouver, les projeter, les lire
//! (par ../formats/src/acpi.rs, qui vérifie chaque octet), et garder ce
//! qu'elles disent des processeurs et des contrôleurs d'interruptions
//! (la MADT, pour apic.rs et ioapic.rs) et de l'horloge CMOS (la FADT,
//! pour temps.rs).
//!
//! La RSDP se cherche comme Linux le fait sur un PC sans UEFI
//! (`acpi_find_root_pointer`) : dans le premier Kio de l'EBDA (la zone de
//! données étendue du BIOS, dont le segment est au mot 0x40E de la mémoire
//! basse), puis dans la zone du BIOS, de 0xE0000 à 0xFFFFF. Les deux sont
//! dans le premier Mio, que la projection directe couvre. Les tables
//! elles-mêmes sont ailleurs (QEMU : tout en haut de la mémoire, dans une
//! étendue que la carte E820 dit réservée) : chacune est projetée le temps
//! de la lire (vmalloc::memremap), d'abord son en-tête pour connaître sa
//! longueur, puis toute la table.
//!
//! Sans RSDP (`-machine acpi=off`, ou une très vieille machine), ou avec
//! des tables refusées, il n'y a pas de configuration : le noyau garde le
//! 8259 et le PIT (voir apic.rs). Linux lit aussi, en ce cas, l'ancienne
//! table MP d'Intel ; pas nous (aucune machine de QEMU n'en a besoin).

use crate::espace;
use crate::verrou::Verrou;
use crate::vmalloc;
use alloc::vec::Vec;
use formats::acpi::{self, Entree, Madt};

/// Ce que disent les tables.
pub struct Configuration {
    /// La révision de la RSDP et le fabricant.
    pub revision: u8,
    pub oem: [u8; 6],
    /// Les signatures des tables qu'elle liste, dans l'ordre (pour
    /// l'affichage), et si la liste vient d'une XSDT.
    pub signatures: Vec<[u8; 4]>,
    pub xsdt: bool,
    /// De la MADT, s'il y en a une valide.
    pub madt: Option<ConfigurationMadt>,
    /// Le registre du siècle de l'horloge CMOS (FADT).
    pub siecle: Option<u8>,
}

/// Ce que dit la MADT.
pub struct ConfigurationMadt {
    /// L'adresse physique des registres de l'APIC local.
    pub apic_local: u64,
    /// La machine a aussi les deux 8259 (PCAT_COMPAT).
    pub pcat: bool,
    /// Les processeurs activés : (numéro ACPI, numéro de l'APIC).
    pub processeurs: Vec<(u8, u8)>,
    /// Les IO-APIC : (numéro, adresse physique, premier GSI).
    pub ioapics: Vec<(u8, u64, u32)>,
    /// Les remplacements des IRQ ISA : (IRQ, GSI, drapeaux).
    pub remplacements: Vec<(u8, u32, u16)>,
    /// Les NMI des APIC locaux : (processeur, 0xFF pour tous ; drapeaux ;
    /// entrée LINT).
    pub nmi: Vec<(u8, u16, u8)>,
}

static CONFIGURATION: Verrou<Option<Configuration>> = Verrou::new(None);

/// La plus longue table qu'on accepte de projeter : bien plus que la MADT
/// ou la FADT (quelques centaines d'octets) ; une longueur absurde (une
/// mémoire abîmée) ne fera pas projeter des Gio.
const TABLE_MAX: usize = 1 << 20;

/// Pourquoi il n'y a pas de configuration.
pub enum Absence {
    /// Pas de RSDP dans la mémoire du BIOS.
    SansRsdp,
    /// La RSDT ou la XSDT illisible : son adresse, et l'erreur.
    Racine(u64, acpi::Erreur),
}

/// Les octets de la mémoire basse [debut, debut + longueur[, par la
/// projection directe.
fn memoire_basse(debut: u64, longueur: usize) -> &'static [u8] {
    assert!(debut + longueur as u64 <= 1 << 20);
    // SAFETY : le premier Mio est projeté en entier par la projection
    // directe (pagination.rs) et n'est donné à aucun allocateur (cadres.rs) :
    // personne ne l'écrit pendant qu'on le lit (le BIOS n'y touche plus).
    unsafe { core::slice::from_raw_parts(espace::virtuelle(debut) as *const u8, longueur) }
}

/// Cherche la RSDP : (son adresse physique, ce qu'elle dit).
fn chercher_rsdp() -> Option<(u64, acpi::Rsdp)> {
    // Le segment de l'EBDA, au mot 0x40E ; Linux ne le prend qu'entre
    // 0x400 et 0xA0000 (au-delà commence la mémoire vidéo).
    let segment = u16::from_le_bytes([memoire_basse(0x40E, 2)[0], memoire_basse(0x40E, 2)[1]]);
    let ebda = (segment as u64) << 4;
    let mut zones = Vec::new();
    if ebda > 0x400 && ebda + 1024 <= 0xA0000 {
        zones.push((ebda, 1024));
    }
    zones.push((0xE0000, 0x20000));
    zones.into_iter().find_map(|(debut, longueur)| {
        let zone = memoire_basse(debut, longueur);
        let i = acpi::chercher_rsdp(zone)?;
        Some((debut + i as u64, acpi::lire_rsdp(&zone[i..]).ok()?))
    })
}

/// Projette la table d'adresse physique `adresse`, la vérifie, et appelle
/// `f` sur elle ; la projection est rendue ensuite.
fn avec_table<R>(adresse: u64, f: impl FnOnce(&acpi::Table) -> R) -> Result<R, acpi::Erreur> {
    let longueur = {
        let entete = vmalloc::memremap(adresse, acpi::TAILLE_ENTETE as u64).ok_or(acpi::Erreur::Tronquee)?;
        // SAFETY : la projection couvre l'en-tête, en lecture seule ; ce
        // sont des tables du micrologiciel, que personne n'écrit.
        let octets = unsafe { core::slice::from_raw_parts(entete.adresse() as *const u8, acpi::TAILLE_ENTETE) };
        acpi::longueur(octets)?
    };
    if longueur > TABLE_MAX {
        return Err(acpi::Erreur::Longueur);
    }
    let table = vmalloc::memremap(adresse, longueur as u64).ok_or(acpi::Erreur::Tronquee)?;
    // SAFETY : comme ci-dessus, pour toute la table.
    let octets = unsafe { core::slice::from_raw_parts(table.adresse() as *const u8, longueur) };
    Ok(f(&acpi::lire_table(octets)?))
}

/// Lit la MADT.
fn lire_madt(t: &acpi::Table) -> Option<ConfigurationMadt> {
    let m = Madt::lire(t).ok()?;
    let mut c = ConfigurationMadt {
        apic_local: m.apic_local as u64,
        pcat: m.drapeaux & acpi::PCAT_COMPAT != 0,
        processeurs: Vec::new(),
        ioapics: Vec::new(),
        remplacements: Vec::new(),
        nmi: Vec::new(),
    };
    for e in m.entrees() {
        // Une entrée illisible : on garde ce qui la précède, comme Linux
        // (`acpi_parse_entries_array` s'arrête à la première fausse).
        let Ok(e) = e else { break };
        match e {
            // Activé, ou activable plus tard : on ne compte que les premiers
            // (un seul processeur servi de toute façon).
            Entree::Processeur { processeur, apic, drapeaux } if drapeaux & 1 != 0 => c.processeurs.push((processeur, apic)),
            Entree::IoApic { numero, adresse, gsi_base } => c.ioapics.push((numero, adresse as u64, gsi_base)),
            // Seul le bus 0, ISA, existe.
            Entree::Remplacement { bus: 0, source, gsi, drapeaux } => c.remplacements.push((source, gsi, drapeaux)),
            Entree::NmiApic { processeur, drapeaux, lint } => c.nmi.push((processeur, drapeaux, lint)),
            Entree::AdresseApic(a) => c.apic_local = a,
            _ => {}
        }
    }
    Some(c)
}

/// Trouve et lit les tables, une fois, au démarrage (après vmalloc).
pub fn initialiser() -> Result<(), Absence> {
    let (_, rsdp) = chercher_rsdp().ok_or(Absence::SansRsdp)?;
    // La XSDT si la RSDP en donne une (ACPI 2.0), la RSDT sinon : l'ordre
    // de Linux (`acpi_tb_parse_root_table`).
    let (racine, larges, signature) = match rsdp.xsdt {
        Some(x) => (x, true, b"XSDT"),
        None => (rsdp.rsdt as u64, false, b"RSDT"),
    };
    let adresses: Vec<u64> = avec_table(racine, |t| {
        if &t.signature == signature { Some(acpi::adresses(t, larges).collect()) } else { None }
    })
    .and_then(|a| a.ok_or(acpi::Erreur::Signature))
    .map_err(|e| Absence::Racine(racine, e))?;
    let mut c = Configuration { revision: rsdp.revision, oem: rsdp.oem, signatures: Vec::new(), xsdt: larges, madt: None, siecle: None };
    for a in adresses {
        // Une table illisible est sautée : les autres peuvent servir.
        let _ = avec_table(a, |t| {
            c.signatures.push(t.signature);
            match &t.signature {
                // La première de chaque, comme Linux.
                b"APIC" if c.madt.is_none() => c.madt = lire_madt(t),
                b"FACP" if c.siecle.is_none() => c.siecle = acpi::registre_du_siecle(t),
                _ => {}
            }
        });
    }
    *CONFIGURATION.verrouiller() = Some(c);
    Ok(())
}

/// Exécute `f` sur la configuration lue, s'il y en a une.
pub fn avec<R>(f: impl FnOnce(&Configuration) -> R) -> Option<R> {
    CONFIGURATION.verrouiller().as_ref().map(f)
}

/// Le registre du siècle de l'horloge CMOS, s'il y en a un.
pub fn registre_du_siecle() -> Option<u8> {
    avec(|c| c.siecle).flatten()
}

/// Affiche ce que disent les tables (au démarrage).
pub fn afficher() {
    avec(|c| {
        // Le fabricant est complété d'espaces (« BOCHS »).
        let oem = &c.oem[..c.oem.iter().rposition(|&o| o != b' ' && o != 0).map_or(0, |i| i + 1)];
        afficher!("[noyau] ACPI : RSDP v{} ({}), {} :", c.revision, crate::programmes::Nom(oem), if c.xsdt { "XSDT" } else { "RSDT" });
        for s in &c.signatures {
            afficher!(" {}", crate::programmes::Nom(s));
        }
        afficherln!(".");
        let Some(m) = &c.madt else {
            return afficherln!("[noyau] ACPI : pas de MADT lisible.");
        };
        afficher!("[noyau] ACPI : {} processeur{}, APIC local a {:#x}", m.processeurs.len(),
                  if m.processeurs.len() > 1 { "s" } else { "" }, m.apic_local);
        for &(n, a, gsi) in &m.ioapics {
            afficher!(", IO-APIC {} a {:#x} (GSI a partir de {})", n, a, gsi);
        }
        afficherln!("{}.", if m.pcat { ", 8259 present" } else { "" });
        afficher!("[noyau] ACPI : IRQ ISA remplacees :");
        for &(irq, gsi, d) in &m.remplacements {
            let niveau = if d >> 2 & 3 == 3 { " en niveau" } else { "" };
            let bas = if d & 3 == 3 { " actif bas" } else { "" };
            afficher!(" {} -> GSI {}{}{} ;", irq, gsi, niveau, bas);
        }
        match m.nmi.first() {
            Some(&(_, _, lint)) => afficherln!(" NMI sur LINT{}.", lint),
            None => afficherln!(" pas de NMI."),
        }
    });
}
