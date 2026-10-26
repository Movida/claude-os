//! Les tables ACPI : ce que le micrologiciel dit de la machine.
//!
//! ACPI (Advanced Configuration and Power Interface, 1996) remplace les
//! anciennes tables du BIOS (la table MP d'Intel pour les processeurs et
//! les contrôleurs d'interruptions). Le micrologiciel laisse en mémoire un
//! arbre de tables, chacune avec une signature de quatre lettres :
//!   - la RSDP (« RSD PTR ») : le point de départ, à chercher dans la
//!     mémoire du BIOS (ou donné par UEFI) ; elle désigne la RSDT (des
//!     adresses de 32 bits) ou, depuis ACPI 2.0, la XSDT (64 bits) ;
//!   - la RSDT ou la XSDT : la liste des adresses des autres tables ;
//!   - la MADT (« APIC ») : les processeurs et leurs APIC locaux, les
//!     IO-APIC, et comment les IRQ de l'ancien bus ISA arrivent sur les
//!     entrées des IO-APIC (6e) ;
//!   - la FADT (« FACP ») : les registres de la gestion de l'énergie, et le
//!     registre du siècle dans l'horloge CMOS (6e) ;
//!   - et d'autres, que nous ne lisons pas encore : HPET (un temporisateur),
//!     MCFG (la configuration PCI en mémoire, 6g), la DSDT (du code AML, à
//!     interpréter, pour éteindre la machine, entre autres).
//! Chaque table commence par un en-tête commun de 36 octets (signature,
//! longueur totale, révision, somme de contrôle, fabricant...) ; la somme
//! de tous ses octets doit valoir 0 modulo 256.
//!
//! Comme le reste de la bibliothèque, ces octets viennent de l'extérieur
//! et ne sont crus qu'une fois vérifiés : une table tronquée, de mauvaise
//! somme, ou dont une entrée déborde, est refusée, jamais devinée (Linux
//! refuse de même une table de mauvaise somme, `acpi_tb_verify_checksum`).
//! La lecture ne suppose rien de la mémoire : c'est le noyau qui projette
//! chaque table (memremap) et donne ses octets.
//!
//! Mesuré sous QEMU 8.2 (machines `pc` et `q35`) : une RSDP de révision 0
//! (ACPI 1.0), une RSDT seule, pas de XSDT ; les tests le vérifient sur les
//! vraies tables de QEMU, et la XSDT sur des tables faites à la main.

use core::fmt;

/// Pourquoi une table est refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Moins d'octets que ce que dit la table (ou que son en-tête).
    Tronquee,
    /// La signature n'est pas celle attendue.
    Signature,
    /// La somme des octets ne vaut pas 0.
    Somme,
    /// Une longueur impossible : une table plus courte que son en-tête, une
    /// entrée de la MADT de moins de 2 octets ou qui dépasse la table, ou
    /// trop courte pour son type.
    Longueur,
}

// Affichés par le noyau : sans accents.
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Erreur::Tronquee => "table tronquee",
            Erreur::Signature => "mauvaise signature",
            Erreur::Somme => "mauvaise somme de controle",
            Erreur::Longueur => "longueur impossible",
        })
    }
}

fn u16_a(o: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(o.get(i..i + 2)?.try_into().ok()?))
}

fn u32_a(o: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(o.get(i..i + 4)?.try_into().ok()?))
}

fn u64_a(o: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(o.get(i..i + 8)?.try_into().ok()?))
}

/// La somme de contrôle d'ACPI : la somme des octets, modulo 256, doit
/// être nulle.
fn somme_nulle(o: &[u8]) -> bool {
    o.iter().fold(0u8, |s, &b| s.wrapping_add(b)) == 0
}

/// La RSDP, lue et vérifiée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rsdp {
    /// 0 pour ACPI 1.0 (20 octets) ; 2 et plus depuis ACPI 2.0 (36 octets,
    /// avec la XSDT).
    pub revision: u8,
    /// Le fabricant (« BOCHS » sous QEMU, SeaBIOS venant de Bochs).
    pub oem: [u8; 6],
    /// L'adresse physique de la RSDT.
    pub rsdt: u32,
    /// L'adresse physique de la XSDT, depuis ACPI 2.0 (et si elle n'est pas
    /// nulle).
    pub xsdt: Option<u64>,
}

/// La signature de la RSDP, au début de ses 20 premiers octets.
pub const SIGNATURE_RSDP: &[u8; 8] = b"RSD PTR ";
/// La taille de la RSDP d'ACPI 1.0, et celle d'ACPI 2.0.
pub const TAILLE_RSDP_1: usize = 20;
pub const TAILLE_RSDP_2: usize = 36;

/// Lit la RSDP au début de `o` (20 octets au moins, 36 pour une révision
/// 2 et plus). Comme Linux (`acpi_tb_validate_rsdp`) : la signature, la
/// somme des 20 premiers octets, puis, depuis la révision 2, celle de toute
/// la structure (sa longueur est dans le champ de l'octet 20, au moins 36).
pub fn lire_rsdp(o: &[u8]) -> Result<Rsdp, Erreur> {
    let debut = o.get(..TAILLE_RSDP_1).ok_or(Erreur::Tronquee)?;
    if &debut[..8] != SIGNATURE_RSDP {
        return Err(Erreur::Signature);
    }
    if !somme_nulle(debut) {
        return Err(Erreur::Somme);
    }
    let revision = debut[15];
    let mut oem = [0u8; 6];
    oem.copy_from_slice(&debut[9..15]);
    let rsdt = u32_a(debut, 16).ok_or(Erreur::Tronquee)?;
    let mut xsdt = None;
    if revision >= 2 {
        let longueur = u32_a(o, 20).ok_or(Erreur::Tronquee)? as usize;
        if longueur < TAILLE_RSDP_2 {
            return Err(Erreur::Longueur);
        }
        let tout = o.get(..longueur).ok_or(Erreur::Tronquee)?;
        if !somme_nulle(tout) {
            return Err(Erreur::Somme);
        }
        xsdt = u64_a(tout, 24).filter(|&a| a != 0);
    }
    Ok(Rsdp { revision, oem, rsdt, xsdt })
}

/// La première RSDP valide de `zone`, là où ACPI dit de la chercher : à
/// une position multiple de 16 (`acpi_tb_scan_memory_for_rsdp`) ; sa
/// position dans la zone.
pub fn chercher_rsdp(zone: &[u8]) -> Option<usize> {
    (0..zone.len()).step_by(16).find(|&i| lire_rsdp(&zone[i..]).is_ok())
}

/// La taille de l'en-tête commun des tables.
pub const TAILLE_ENTETE: usize = 36;

/// La longueur totale d'une table, d'après son en-tête (ses 8 premiers
/// octets suffisent), pour savoir combien en projeter.
pub fn longueur(entete: &[u8]) -> Result<usize, Erreur> {
    let l = u32_a(entete, 4).ok_or(Erreur::Tronquee)? as usize;
    if l < TAILLE_ENTETE { Err(Erreur::Longueur) } else { Ok(l) }
}

/// Une table vérifiée : sa signature, sa révision, et son contenu après
/// l'en-tête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table<'a> {
    pub signature: [u8; 4],
    pub revision: u8,
    /// Les octets après l'en-tête, jusqu'à la longueur de la table.
    pub corps: &'a [u8],
}

/// Vérifie la table au début de `o` : sa longueur (au moins l'en-tête, et
/// pas plus que les octets donnés), sa somme. Les octets au-delà de sa
/// longueur sont ignorés.
pub fn lire_table(o: &[u8]) -> Result<Table<'_>, Erreur> {
    let l = longueur(o)?;
    let tout = o.get(..l).ok_or(Erreur::Tronquee)?;
    if !somme_nulle(tout) {
        return Err(Erreur::Somme);
    }
    let mut signature = [0u8; 4];
    signature.copy_from_slice(&tout[..4]);
    Ok(Table { signature, revision: tout[8], corps: &tout[TAILLE_ENTETE..] })
}

/// Comme `lire_table`, en exigeant la signature `signature`.
pub fn lire_table_signee<'a>(o: &'a [u8], signature: &[u8; 4]) -> Result<Table<'a>, Erreur> {
    if o.get(..4).ok_or(Erreur::Tronquee)? != signature {
        return Err(Erreur::Signature);
    }
    lire_table(o)
}

/// Les adresses des tables que liste une RSDT (`larges` = false, 4 octets
/// par adresse) ou une XSDT (`larges` = true, 8 octets). Des octets en
/// trop à la fin (moins d'une adresse) sont ignorés, comme Linux.
pub fn adresses<'a>(racine: &Table<'a>, larges: bool) -> impl Iterator<Item = u64> + 'a {
    let taille = if larges { 8 } else { 4 };
    racine.corps.chunks_exact(taille).map(move |c| if larges { u64_a(c, 0).unwrap_or(0) } else { u32_a(c, 0).unwrap_or(0) as u64 })
}

/// La MADT (signature « APIC ») : l'adresse des APIC locaux, ses drapeaux,
/// et ses entrées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Madt<'a> {
    /// L'adresse physique des registres de l'APIC local de chaque
    /// processeur (chacun voit le sien à la même adresse).
    pub apic_local: u32,
    /// Bit 0, PCAT_COMPAT : la machine a aussi les deux 8259 du PC/AT, à
    /// masquer avant de se servir des IO-APIC.
    pub drapeaux: u32,
    entrees: &'a [u8],
}

pub const PCAT_COMPAT: u32 = 1;

/// Une entrée de la MADT. Les types qu'on ne lit pas sont rendus avec leur
/// numéro (`Autre`), pour qu'on puisse les compter ou les afficher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entree {
    /// Type 0 : un processeur et son APIC local. Drapeaux : bit 0, activé ;
    /// bit 1, peut être activé plus tard (« online capable »).
    Processeur { processeur: u8, apic: u8, drapeaux: u32 },
    /// Type 1 : un IO-APIC, son numéro, l'adresse de ses registres, et le
    /// premier numéro global d'interruption (GSI) de ses entrées.
    IoApic { numero: u8, adresse: u32, gsi_base: u32 },
    /// Type 2 : une IRQ du bus ISA qui n'arrive pas sur le GSI de même
    /// numéro, ou pas avec la polarité et le déclenchement d'ISA (front
    /// montant, actif haut). Drapeaux : bits 0-1, la polarité (0 : celle
    /// du bus, 1 : active haute, 3 : active basse) ; bits 2-3, le
    /// déclenchement (0 : celui du bus, 1 : par front, 3 : par niveau).
    Remplacement { bus: u8, source: u8, gsi: u32, drapeaux: u16 },
    /// Type 4 : l'entrée LINT (0 ou 1) d'un APIC local sur laquelle arrive
    /// le NMI ; `processeur` 0xFF : tous les processeurs. Drapeaux comme
    /// pour un remplacement.
    NmiApic { processeur: u8, drapeaux: u16, lint: u8 },
    /// Type 5 : l'adresse de l'APIC local sur 64 bits, qui remplace celle
    /// de l'en-tête.
    AdresseApic(u64),
    /// Un autre type (x2APIC, GIC d'ARM...) : son numéro.
    Autre(u8),
}

impl<'a> Madt<'a> {
    /// Lit la MADT dans une table vérifiée (signature « APIC »).
    pub fn lire(table: &Table<'a>) -> Result<Madt<'a>, Erreur> {
        if &table.signature != b"APIC" {
            return Err(Erreur::Signature);
        }
        let apic_local = u32_a(table.corps, 0).ok_or(Erreur::Tronquee)?;
        let drapeaux = u32_a(table.corps, 4).ok_or(Erreur::Tronquee)?;
        Ok(Madt { apic_local, drapeaux, entrees: &table.corps[8..] })
    }

    /// Les entrées, dans l'ordre de la table. Une entrée de longueur
    /// impossible (moins de 2 octets, au-delà de la table, ou plus courte
    /// que son type) arrête la lecture, avec une erreur : on ne sait plus
    /// où commence la suivante.
    pub fn entrees(&self) -> Entrees<'a> {
        Entrees { reste: self.entrees, fini: false }
    }
}

/// Les entrées de la MADT (voir `Madt::entrees`).
pub struct Entrees<'a> {
    reste: &'a [u8],
    fini: bool,
}

impl Iterator for Entrees<'_> {
    type Item = Result<Entree, Erreur>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fini || self.reste.is_empty() {
            return None;
        }
        let (genre, l) = match self.reste {
            [g, l, ..] => (*g, *l as usize),
            _ => (0, 0),
        };
        // La longueur minimale de chaque type (spécification ACPI 6.5,
        // 5.2.12) ; un type inconnu doit au moins avoir ses 2 octets.
        let minimum = match genre {
            0 => 8,
            1 => 12,
            2 => 10,
            4 => 6,
            5 => 12,
            _ => 2,
        };
        if l < minimum || l > self.reste.len() {
            self.fini = true;
            return Some(Err(Erreur::Longueur));
        }
        let e = &self.reste[..l];
        self.reste = &self.reste[l..];
        // Les champs sont dans l'entrée : sa longueur a été vérifiée.
        let entree = match genre {
            0 => Entree::Processeur { processeur: e[2], apic: e[3], drapeaux: u32_a(e, 4).unwrap_or(0) },
            1 => Entree::IoApic { numero: e[2], adresse: u32_a(e, 4).unwrap_or(0), gsi_base: u32_a(e, 8).unwrap_or(0) },
            2 => Entree::Remplacement { bus: e[2], source: e[3], gsi: u32_a(e, 4).unwrap_or(0), drapeaux: u16_a(e, 8).unwrap_or(0) },
            4 => Entree::NmiApic { processeur: e[2], drapeaux: u16_a(e, 3).unwrap_or(0), lint: e[5] },
            5 => Entree::AdresseApic(u64_a(e, 4).unwrap_or(0)),
            g => Entree::Autre(g),
        };
        Some(Ok(entree))
    }
}

/// Le registre du siècle de l'horloge CMOS, d'après la FADT (signature
/// « FACP ») : son numéro est l'octet 108 de la table. Comme Linux
/// (`mc146818_get_time`), seulement pour une FADT de révision 3 au moins
/// (FADT2_REVISION_ID, ACPI 2.0) : avant, le champ existait, mais les
/// micrologiciels n'y mettaient pas toujours une valeur sûre. 0, ou une
/// FADT trop courte : pas de registre du siècle. (QEMU, machine `pc` : une
/// FADT de révision 1, qui nomme le registre 0x32 ; Linux ne s'en sert
/// pas, nous non plus.)
pub fn registre_du_siecle(fadt: &Table) -> Option<u8> {
    if &fadt.signature != b"FACP" || fadt.revision < 3 {
        return None;
    }
    fadt.corps.get(108 - TAILLE_ENTETE).copied().filter(|&r| r != 0)
}
