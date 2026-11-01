//! L'espace de configuration PCI : ce que chaque fonction d'un périphérique
//! dit d'elle-même.
//!
//! Le bus PCI (1992) relie les périphériques au processeur. Chaque
//! périphérique a jusqu'à 8 FONCTIONS (une carte à deux ports réseau peut
//! en avoir deux), et chaque fonction un ESPACE DE CONFIGURATION de 256
//! octets (4 Kio en PCI Express), qu'on lit et écrit par des registres à
//! part (noyau/src/pci.rs). Ses 64 premiers octets ont une forme fixe, l'EN-TÊTE :
//!   - qui est la fonction : le fabricant (0x8086 Intel, 0x1af4 Red Hat pour
//!     virtio) et le modèle, sa classe (0x02 réseau, 0x01 stockage, 0x06
//!     pont...) ;
//!   - où sont ses registres : jusqu'à six BAR (« Base Address Registers »),
//!     chacun une fenêtre de ports d'E/S ou de mémoire, que le
//!     micrologiciel a placée et que le système peut déplacer ;
//!   - pour un PONT (en-tête de type 1), les bus qu'il dessert derrière lui ;
//!   - le début d'une liste chaînée de CAPACITÉS : des structures
//!     facultatives, chacune avec son numéro (0x11 MSI-X, 0x09 propre au
//!     fabricant, que virtio utilise pour dire où sont ses registres).
//!
//! Comme le reste de la bibliothèque, ces octets ne sont crus qu'une fois
//! vérifiés : un périphérique peut être bogué, ou hostile (une carte
//! branchée par Thunderbolt). Une liste de capacités qui boucle s'arrête au
//! bout de 48 maillons (le `PCI_FIND_CAP_TTL` de Linux) ; un pointeur dans
//! l'en-tête ou hors des 256 octets l'arrête aussi ; une structure qui
//! déborde est refusée. Ce module ne fait que DÉCODER : lire et écrire
//! l'espace (et mesurer une BAR, ce qui demande d'y écrire) est le travail
//! du noyau.
//!
//! Testé sur l'hôte avec les espaces de configuration des fonctions de
//! QEMU 8.2 (machine `pc`), capturés par son moniteur (tests/pci/capturer.sh),
//! et avec des espaces abîmés à la main.

use core::fmt;

/// La taille de l'espace de configuration de PCI (sans l'espace étendu de
/// PCI Express, de 256 à 4096, que l'accès par ports ne voit pas).
pub const TAILLE_ESPACE: usize = 256;
/// La taille de l'en-tête commun ; les capacités sont après lui.
pub const TAILLE_ENTETE: usize = 0x40;
/// Le nombre de BAR d'une fonction ordinaire (type 0) ; un pont (type 1)
/// n'en a que 2.
pub const NB_BAR: usize = 6;

// Les champs de l'en-tête (include/uapi/linux/pci_regs.h).
pub const VENDEUR: usize = 0x00;
pub const COMMANDE: usize = 0x04;
pub const ETAT: usize = 0x06;
pub const BAR0: usize = 0x10;
pub const CAPACITES: usize = 0x34;

/// Les bits du registre de commande.
pub const COMMANDE_ES: u16 = 1 << 0;
pub const COMMANDE_MEMOIRE: u16 = 1 << 1;
/// La fonction peut lire et écrire la mémoire elle-même (DMA) : sans lui,
/// une carte réseau ne peut ni prendre ses tampons ni y poser des trames.
pub const COMMANDE_MAITRE: u16 = 1 << 2;
/// Coupe le fil d'interruption partagé (INTx) : avec MSI-X, il ne doit
/// plus rien lever.
pub const COMMANDE_SANS_INTX: u16 = 1 << 10;
/// Bit du registre d'état : la fonction a une liste de capacités.
pub const ETAT_CAPACITES: u16 = 1 << 4;

/// Les numéros de capacités que lit le noyau.
pub const CAPACITE_FABRICANT: u8 = 0x09;
pub const CAPACITE_MSIX: u8 = 0x11;

/// Le nombre maximal de maillons suivis dans une liste de capacités
/// (`PCI_FIND_CAP_TTL` de Linux : 48 capacités de 4 octets au moins ne
/// tiennent pas plus dans les 192 octets qui suivent l'en-tête).
pub const MAILLONS_MAX: usize = 48;

/// Pourquoi un espace ou une structure est refusé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Moins de 256 octets.
    Tronque,
    /// Pas de fonction à cette adresse (le fabricant lu vaut 0xFFFF : un
    /// bus PCI rend des 1 quand personne ne répond).
    Absente,
    /// Un type d'en-tête que nous ne connaissons pas (2 : pont CardBus).
    TypeInconnu(u8),
    /// Une capacité dont la structure dépasse l'espace, ou plus courte que
    /// ce que dit son type.
    Capacite,
    /// Une BAR 64 bits en dernière position (sa moitié haute serait hors
    /// des BAR).
    Bar,
}

// Affichés par le noyau : sans accents.
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::Tronque => f.write_str("espace de configuration tronque"),
            Erreur::Absente => f.write_str("pas de fonction"),
            Erreur::TypeInconnu(t) => write!(f, "type d'en-tete {t} inconnu"),
            Erreur::Capacite => f.write_str("capacite qui deborde"),
            Erreur::Bar => f.write_str("BAR 64 bits sans moitie haute"),
        }
    }
}

fn u16_a(o: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(o.get(i..i + 2)?.try_into().ok()?))
}

fn u32_a(o: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(o.get(i..i + 4)?.try_into().ok()?))
}

/// La sorte d'une fonction, d'après le type de son en-tête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Genre {
    /// Type 0 : une fonction ordinaire, ses six BAR, son sous-système.
    Ordinaire { sous_vendeur: u16, sous_systeme: u16 },
    /// Type 1 : un pont vers un autre bus, ses deux BAR, et les numéros
    /// des bus derrière lui : `secondaire` celui qu'il dessert directement,
    /// `subordonne` le plus grand de ceux qu'on atteint à travers lui.
    Pont { primaire: u8, secondaire: u8, subordonne: u8 },
}

/// L'en-tête d'une fonction, lu et vérifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entete {
    pub vendeur: u16,
    pub peripherique: u16,
    pub commande: u16,
    pub etat: u16,
    pub revision: u8,
    /// La classe, la sous-classe et l'interface de programmation
    /// (0x02_00_00 : contrôleur Ethernet).
    pub classe: u32,
    /// Bit 7 du type d'en-tête, sur la fonction 0 : les fonctions 1 à 7
    /// peuvent exister.
    pub multifonction: bool,
    pub genre: Genre,
    /// La broche d'interruption INTx (0 : aucune, 1 à 4 : INTA à INTD), et
    /// la ligne que le micrologiciel y a notée.
    pub broche: u8,
    pub ligne: u8,
    /// Le premier maillon de la liste des capacités, s'il y en a une.
    capacites: Option<u8>,
}

/// Lit l'en-tête de l'espace `o` (256 octets).
pub fn lire_entete(o: &[u8]) -> Result<Entete, Erreur> {
    let o = o.get(..TAILLE_ESPACE).ok_or(Erreur::Tronque)?;
    let vendeur = u16_a(o, VENDEUR).ok_or(Erreur::Tronque)?;
    if vendeur == 0xFFFF {
        return Err(Erreur::Absente);
    }
    let etat = u16_a(o, ETAT).ok_or(Erreur::Tronque)?;
    let type_entete = o[0x0E];
    let genre = match type_entete & 0x7F {
        0 => Genre::Ordinaire {
            sous_vendeur: u16_a(o, 0x2C).ok_or(Erreur::Tronque)?,
            sous_systeme: u16_a(o, 0x2E).ok_or(Erreur::Tronque)?,
        },
        1 => Genre::Pont { primaire: o[0x18], secondaire: o[0x19], subordonne: o[0x1A] },
        t => return Err(Erreur::TypeInconnu(t)),
    };
    Ok(Entete {
        vendeur,
        peripherique: u16_a(o, 0x02).ok_or(Erreur::Tronque)?,
        commande: u16_a(o, COMMANDE).ok_or(Erreur::Tronque)?,
        etat,
        revision: o[0x08],
        classe: u32_a(o, 0x08).ok_or(Erreur::Tronque)? >> 8,
        multifonction: type_entete & 0x80 != 0,
        genre,
        broche: o[0x3D],
        ligne: o[0x3C],
        capacites: (etat & ETAT_CAPACITES != 0).then_some(o[CAPACITES]),
    })
}

impl Entete {
    /// Le nombre de BAR que l'en-tête peut avoir.
    pub fn nb_bar(&self) -> usize {
        match self.genre {
            Genre::Ordinaire { .. } => NB_BAR,
            Genre::Pont { .. } => 2,
        }
    }

    /// Les capacités de l'espace `o` (celui dont on a lu l'en-tête) : des
    /// paires (position, numéro), dans l'ordre de la liste.
    pub fn capacites<'a>(&self, o: &'a [u8]) -> Capacites<'a> {
        Capacites { o, suivante: self.capacites, restants: MAILLONS_MAX }
    }
}

/// Le parcours d'une liste de capacités, comme `__pci_find_next_cap_ttl` :
/// un pointeur est arrondi à 4 (ses deux bits bas sont réservés) ; il
/// s'arrête sur un pointeur dans l'en-tête (moins de 0x40 : 0 finit la
/// liste), sur le numéro 0xFF (un espace qui ne répond plus), ou au bout de
/// 48 maillons.
pub struct Capacites<'a> {
    o: &'a [u8],
    suivante: Option<u8>,
    restants: usize,
}

impl Iterator for Capacites<'_> {
    type Item = (usize, u8);

    fn next(&mut self) -> Option<(usize, u8)> {
        let p = self.suivante.take()? as usize & !3;
        if p < TAILLE_ENTETE || self.restants == 0 {
            return None;
        }
        self.restants -= 1;
        let numero = *self.o.get(p)?;
        if numero == 0xFF {
            return None;
        }
        self.suivante = self.o.get(p + 1).copied();
        Some((p, numero))
    }
}

/// Ce que dit une BAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bar {
    /// Aucune fenêtre : la BAR n'est pas implémentée (la mesure rend 0),
    /// ou c'est la moitié haute d'une BAR 64 bits.
    Aucune,
    /// Des ports d'E/S.
    Es { port: u32, taille: u32 },
    /// De la mémoire (des registres projetés : MMIO). `prefetchable` : la
    /// lire n'a pas d'effet de bord, elle peut être lue d'avance ou
    /// combinée ; `bits64` : la BAR occupe aussi la suivante.
    Memoire { adresse: u64, taille: u64, bits64: bool, prefetchable: bool },
}

/// Les bits bas d'une BAR (include/uapi/linux/pci_regs.h).
const BAR_ES: u32 = 1 << 0;
const BAR_TYPE: u32 = 3 << 1;
const BAR_64: u32 = 2 << 1;
const BAR_PREFETCHABLE: u32 = 1 << 3;

/// Une BAR 64 bits occupe-t-elle aussi la suivante ? (D'après sa valeur
/// seule, avant toute mesure.)
pub fn bar_64(valeur: u32) -> bool {
    valeur & BAR_ES == 0 && valeur & BAR_TYPE == BAR_64
}

/// Décode une BAR, d'après sa valeur et sa MESURE : ce qu'on y relit après
/// y avoir écrit des 1 partout (les bits d'adresse que la fonction ne
/// décode pas restent à 0, ce qui donne la taille de la fenêtre : la
/// méthode de `__pci_read_base`). Pour une BAR 64 bits, `haute` porte la
/// valeur et la mesure de la BAR suivante.
///
/// Comme Linux : pour des ports d'E/S, seuls les 16 bits bas comptent
/// (`IO_SPACE_LIMIT` sur x86 : 65 536 ports), et une mesure nulle, ou
/// qui n'a aucun bit d'adresse, veut dire « pas de BAR ». Une valeur ou une
/// mesure (de la moitié basse) où tous les bits sont à 1 est la réponse d'un
/// bus où personne ne répond (une fonction retirée, endormie) : « pas de
/// BAR » aussi (`PCI_POSSIBLE_ERROR`, que Linux écarte de même). La moitié
/// haute d'une BAR 64 bits, elle, se mesure tout à 1 dès que la fenêtre
/// tient sous 4 Gio.
pub fn decoder_bar(valeur: u32, mesure: u32, haute: Option<(u32, u32)>) -> Bar {
    if valeur == u32::MAX || mesure == u32::MAX {
        return Bar::Aucune;
    }
    if valeur & BAR_ES != 0 {
        let masque = mesure & 0xFFFC;
        if masque == 0 {
            return Bar::Aucune;
        }
        // La taille : le plus petit bit d'adresse que décode la fonction.
        return Bar::Es { port: valeur & 0xFFFC, taille: masque & masque.wrapping_neg() };
    }
    let bits64 = valeur & BAR_TYPE == BAR_64;
    let (valeur_haute, mesure_haute) = if bits64 { haute.unwrap_or((0, 0)) } else { (0, 0) };
    // Les bits d'adresse que décode la fonction ; une BAR 32 bits ne
    // décode rien au-delà de 4 Gio.
    let masque = (mesure_haute as u64) << 32 | (mesure & !0xF) as u64;
    if masque == 0 {
        return Bar::Aucune;
    }
    Bar::Memoire {
        adresse: (valeur_haute as u64) << 32 | (valeur & !0xF) as u64,
        taille: masque & masque.wrapping_neg(),
        bits64,
        prefetchable: valeur & BAR_PREFETCHABLE != 0,
    }
}

/// La capacité MSI-X : où sont la table des messages et le tableau des
/// interruptions en attente (le PBA), et combien d'entrées.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsiX {
    /// La position de la capacité dans l'espace (son registre de contrôle
    /// est à +2).
    pub position: usize,
    /// Le nombre d'entrées de la table (1 à 2048).
    pub entrees: u16,
    /// La table : sa BAR et son décalage dans la BAR (aligné sur 8).
    pub bar_table: u8,
    pub decalage_table: u32,
    pub bar_pba: u8,
    pub decalage_pba: u32,
}

/// Le registre de contrôle de MSI-X : la taille de la table moins 1 (bits
/// 0 à 10), toutes les entrées masquées d'un coup (« function mask », bit
/// 14), MSI-X activé (bit 15).
pub const MSIX_CONTROLE: usize = 2;
pub const MSIX_TAILLE: u16 = 0x7FF;
pub const MSIX_MASQUE_TOUT: u16 = 1 << 14;
pub const MSIX_ACTIF: u16 = 1 << 15;

/// Lit la capacité MSI-X à la position `p` de l'espace `o`.
pub fn lire_msix(o: &[u8], p: usize) -> Result<MsiX, Erreur> {
    if p + 12 > TAILLE_ESPACE || o.get(p) != Some(&CAPACITE_MSIX) {
        return Err(Erreur::Capacite);
    }
    let controle = u16_a(o, p + MSIX_CONTROLE).ok_or(Erreur::Capacite)?;
    let table = u32_a(o, p + 4).ok_or(Erreur::Capacite)?;
    let pba = u32_a(o, p + 8).ok_or(Erreur::Capacite)?;
    Ok(MsiX {
        position: p,
        entrees: (controle & MSIX_TAILLE) + 1,
        bar_table: (table & 7) as u8,
        decalage_table: table & !7,
        bar_pba: (pba & 7) as u8,
        decalage_pba: pba & !7,
    })
}

/// Les sortes de structures que virtio décrit par une capacité du fabricant
/// (spécification de virtio 1.2, 4.1.4 ; `VIRTIO_PCI_CAP_*` de Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureVirtio {
    /// La configuration commune : fonctionnalités, état, files.
    Commune,
    /// Où écrire pour prévenir la carte qu'une file a du nouveau ; le
    /// multiplicateur donne l'écart entre les files.
    Notification { multiplicateur: u32 },
    /// Le registre d'état des interruptions INTx (inutile avec MSI-X).
    Isr,
    /// La configuration propre au périphérique (l'adresse MAC d'une carte
    /// réseau...).
    Peripherique,
    /// Une fenêtre pour atteindre les autres par l'espace de configuration
    /// lui-même (pour les micrologiciels qui ne projettent pas les BAR).
    AccesPci,
    /// Une autre (mémoire partagée, propre au fabricant) : son numéro.
    Autre(u8),
}

/// Une capacité de virtio : quelle structure, dans quelle BAR, où et sur
/// quelle longueur (le `struct virtio_pci_cap` de la spécification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapaciteVirtio {
    pub structure: StructureVirtio,
    pub bar: u8,
    pub decalage: u32,
    pub longueur: u32,
}

/// La taille du `struct virtio_pci_cap`, et celle de la capacité de
/// notification qui le suit de son multiplicateur.
const TAILLE_CAP_VIRTIO: usize = 16;
const TAILLE_CAP_NOTIFICATION: usize = 20;

/// Lit une capacité de virtio à la position `p` de l'espace `o` (une
/// capacité du fabricant, numéro 0x09). Sa longueur (`cap_len`, l'octet 2)
/// doit couvrir la structure de son type, et tenir dans l'espace.
pub fn lire_virtio(o: &[u8], p: usize) -> Result<CapaciteVirtio, Erreur> {
    if o.get(p) != Some(&CAPACITE_FABRICANT) {
        return Err(Erreur::Capacite);
    }
    let longueur_cap = *o.get(p + 2).ok_or(Erreur::Capacite)? as usize;
    let genre = *o.get(p + 3).ok_or(Erreur::Capacite)?;
    let minimum = if genre == 2 { TAILLE_CAP_NOTIFICATION } else { TAILLE_CAP_VIRTIO };
    if longueur_cap < minimum || p + longueur_cap > TAILLE_ESPACE {
        return Err(Erreur::Capacite);
    }
    let structure = match genre {
        1 => StructureVirtio::Commune,
        2 => StructureVirtio::Notification { multiplicateur: u32_a(o, p + 16).ok_or(Erreur::Capacite)? },
        3 => StructureVirtio::Isr,
        4 => StructureVirtio::Peripherique,
        5 => StructureVirtio::AccesPci,
        g => StructureVirtio::Autre(g),
    };
    Ok(CapaciteVirtio {
        structure,
        bar: o[p + 4],
        decalage: u32_a(o, p + 8).ok_or(Erreur::Capacite)?,
        longueur: u32_a(o, p + 12).ok_or(Erreur::Capacite)?,
    })
}
