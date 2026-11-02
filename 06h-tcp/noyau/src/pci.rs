//! Le bus PCI : trouver les périphériques, lire et écrire leur espace de
//! configuration.
//!
//! Chaque fonction PCI a un espace de configuration de 256 octets (décodé
//! par formats::pci). Sur un PC, le processeur l'atteint par deux ports, le
//! « mécanisme de configuration n° 1 » de la spécification PCI : on écrit
//! sur le port 0xCF8 l'ADRESSE de ce qu'on veut lire (bit 31 : « accès de
//! configuration », puis le bus, le périphérique, la fonction et la
//! position du mot de 32 bits), puis on lit ou écrit la DONNÉE sur le port
//! 0xCFC (à 0xCFC + 1 à 3 pour un octet ou un mot de 16 bits qui n'est pas
//! au début du mot). Deux accès pour une lecture : sous un verrou, sinon une
//! interruption qui lirait aussi l'espace pourrait changer l'adresse entre
//! les deux (le `pci_config_lock` de Linux, arch/x86/pci/direct.c).
//!
//! Options écartées :
//!   - ECAM (« Enhanced Configuration Access Mechanism », PCI Express) :
//!     tout l'espace de chaque fonction projeté en mémoire, à l'adresse que
//!     donne la table MCFG de l'ACPI, et ses 4 Kio au lieu de 256. C'est ce
//!     que préfère Linux quand il existe ; mais la machine `pc` de QEMU
//!     (l'i440FX, du PCI d'avant PCI Express) n'en a pas, et virtio n'a
//!     besoin que des 256 premiers octets. ECAM viendra avec le vrai
//!     matériel (« Reste à faire ») ;
//!   - le mécanisme n° 2 (ports 0xCF8 et 0xCFA, des années 1990), abandonné
//!     par la spécification PCI 2.1 ; Linux ne le garde que pour de vieilles
//!     machines.
//!
//! LE PARCOURS. Les fonctions sont trouvées en essayant chaque adresse (un
//! bus PCI rend 0xFFFF quand personne ne répond) : sur le bus 0, chacun des
//! 32 périphériques, la fonction 0 d'abord, les fonctions 1 à 7 seulement
//! si la 0 se dit multifonction (sinon, certains vieux périphériques
//! répondent à toutes les fonctions, et apparaîtraient huit fois). Un PONT
//! (en-tête de type 1) mène à un autre bus, son « secondaire », qu'on
//! parcourt à son tour : c'est `pci_scan_child_bus` de Linux, en profondeur
//! d'abord. Les numéros de bus et les BAR restent ceux que le micrologiciel
//! (SeaBIOS) a attribués, comme le fait Linux sur PC : les refaire n'aurait
//! de sens que s'ils étaient faux, ou pour brancher à chaud. Un écart : une
//! machine peut avoir d'autres ponts hôtes que le premier, chacun avec son
//! bus racine, qu'aucun pont PCI ne dessert (un serveur à plusieurs
//! complexes racines ; l'expandeur `pxb` de QEMU) : nous ne les voyons pas.
//! Linux les trouve par l'ACPI (le `_CRS` de chaque pont hôte, de l'AML que
//! nous ne lisons pas encore), ou, sans ACPI, en essayant chaque bus pas
//! encore vu (`pcibios_fixup_peer_bridges`) : « Reste à faire », avec
//! l'accès ECAM.
//!
//! LA MESURE DES BAR. Pour connaître la taille d'une fenêtre, on écrit des 1
//! dans sa BAR et on relit : la fonction ne garde à 1 que les bits d'adresse
//! qu'elle décode (formats::pci::decoder_bar). Pendant la mesure, la BAR ne
//! désigne plus la bonne adresse : on coupe d'abord le décodage de la
//! fonction (les bits mémoire et E/S de COMMANDE), comme `__pci_read_base`,
//! et on remet tout après. Au démarrage, avant tout pilote : personne ne se
//! sert encore de ces fenêtres (sauf la mémoire vidéo, que coupe aussi le
//! bit mémoire de la carte VGA : on n'affiche rien pendant la mesure).

use crate::faillible::VecFaillible;
use crate::port;
use crate::verrou::{Garde, Verrou};
use alloc::vec::Vec;
use formats::pci::{self, Bar, Entete, Genre};

/// Les deux ports du mécanisme n° 1.
const ADRESSE: u16 = 0xCF8;
const DONNEE: u16 = 0xCFC;

/// Le verrou des accès à l'espace de configuration : l'adresse, puis la
/// donnée, sans qu'un autre accès s'intercale.
static ACCES: Verrou<()> = Verrou::new(());

/// L'adresse d'une fonction sur le bus : bus (0 à 255), périphérique (0 à
/// 31), fonction (0 à 7). Affichée « 00:03.0 », comme lspci.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adresse {
    pub bus: u8,
    pub periph: u8,
    pub fonction: u8,
}

impl core::fmt::Display for Adresse {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:02x}:{:02x}.{}", self.bus, self.periph, self.fonction)
    }
}

impl Adresse {
    /// Le mot à écrire sur le port d'adresse pour le mot de 32 bits qui
    /// contient la position `position`.
    fn mot(self, position: usize) -> u32 {
        1 << 31 | (self.bus as u32) << 16 | (self.periph as u32) << 11 | (self.fonction as u32) << 8
            | (position as u32 & 0xFC)
    }

    /// Lit le mot de 16 bits à `position` de l'espace (un accès, sous le
    /// verrou).
    pub fn lire16(self, position: usize) -> u16 {
        configuration().lire16(self, position)
    }

    /// Écrit le mot de 16 bits à `position` de l'espace.
    pub fn ecrire16(self, position: usize, valeur: u16) {
        configuration().ecrire16(self, position, valeur)
    }

    /// La fonction devient « maître du bus » : elle peut lire et écrire la
    /// mémoire elle-même (DMA), et envoyer ses MSI, qui sont des écritures
    /// (le `pci_set_master` de Linux). Le décodage de sa mémoire aussi, au
    /// cas où le micrologiciel l'aurait laissé coupé (`pci_enable_device`).
    pub fn activer_maitrise(self) {
        self.changer_commande(pci::COMMANDE_MAITRE | pci::COMMANDE_MEMOIRE, 0);
    }

    /// Change le registre de commande : les bits `poser` mis, puis les bits
    /// `effacer` ôtés, d'un seul tenant sous le verrou (en 16 bits : l'état,
    /// à côté, n'est pas touché).
    pub fn changer_commande(self, poser: u16, effacer: u16) {
        let c = configuration();
        let commande = c.lire16(self, pci::COMMANDE);
        c.ecrire16(self, pci::COMMANDE, (commande | poser) & !effacer);
    }
}

/// L'espace de configuration, son verrou tenu : une suite d'accès qu'aucun
/// autre ne coupe (la mesure des BAR d'une fonction se fait d'un seul
/// tenant). Chaque accès a la largeur du registre, comme les `pci_conf1_*`
/// de Linux : 16 bits pour COMMANDE, à côté de l'ÉTAT, dont les bits
/// d'erreur s'effacent quand on y écrit 1 (une lecture-écriture de 32 bits
/// les effacerait au passage).
pub struct Configuration<'a> {
    _garde: Garde<'a, ()>,
}

/// Prend l'espace de configuration (son verrou coupe les interruptions :
/// pour quelques accès, jamais pour attendre).
pub fn configuration() -> Configuration<'static> {
    Configuration { _garde: ACCES.verrouiller() }
}

impl Configuration<'_> {
    /// Lit le mot de 32 bits à `position` (multiple de 4) de l'espace de `a`.
    pub fn lire32(&self, a: Adresse, position: usize) -> u32 {
        // SAFETY : les deux ports du mécanisme n° 1, toujours présents sur
        // un PC ; lire l'espace de configuration n'a pas d'effet de bord.
        unsafe {
            port::ecrire32(ADRESSE, a.mot(position));
            port::lire32(DONNEE)
        }
    }

    /// Lit le mot de 16 bits à `position` (paire) : sur le port de donnée
    /// plus la position dans le mot.
    pub fn lire16(&self, a: Adresse, position: usize) -> u16 {
        // SAFETY : comme lire32.
        unsafe {
            port::ecrire32(ADRESSE, a.mot(position));
            port::lire16(DONNEE + (position as u16 & 2))
        }
    }

    /// Écrit le mot de 32 bits à `position` (multiple de 4).
    pub fn ecrire32(&self, a: Adresse, position: usize, valeur: u32) {
        // SAFETY : l'appelant écrit un registre dont il connaît l'effet
        // (une BAR à mesurer, puis remise).
        unsafe {
            port::ecrire32(ADRESSE, a.mot(position));
            port::ecrire32(DONNEE, valeur);
        }
    }

    /// Écrit le mot de 16 bits à `position` (paire), sans toucher aux deux
    /// autres octets du mot de 32 bits.
    pub fn ecrire16(&self, a: Adresse, position: usize, valeur: u16) {
        // SAFETY : comme ecrire32.
        unsafe {
            port::ecrire32(ADRESSE, a.mot(position));
            port::ecrire16(DONNEE + (position as u16 & 2), valeur);
        }
    }

    /// Les 256 octets de l'espace de `a`, lus mot par mot.
    fn lire_espace(&self, a: Adresse) -> [u8; pci::TAILLE_ESPACE] {
        let mut o = [0u8; pci::TAILLE_ESPACE];
        for (i, mot) in o.chunks_exact_mut(4).enumerate() {
            mot.copy_from_slice(&self.lire32(a, i * 4).to_le_bytes());
        }
        o
    }
}

/// Une fonction trouvée sur le bus : son adresse, son en-tête, ses BAR
/// mesurées, et une copie de son espace tel qu'au démarrage (pour en lire
/// les capacités).
pub struct Fonction {
    pub adresse: Adresse,
    pub entete: Entete,
    pub bars: [Bar; pci::NB_BAR],
    pub espace: [u8; pci::TAILLE_ESPACE],
}

impl Fonction {
    /// Les capacités de la fonction : (position, numéro).
    pub fn capacites(&self) -> pci::Capacites<'_> {
        self.entete.capacites(&self.espace)
    }
}

/// Les fonctions trouvées au démarrage (au plus 256 : un bus et ses 32
/// périphériques à 8 fonctions ; sur QEMU, une dizaine). Faites une fois,
/// avant les pilotes, et jamais changées ensuite (pas de branchement à
/// chaud) : gardées pour toujours dans le tas (`Vec::leak`), chacun les lit
/// sans verrou une fois la tranche obtenue. Un pilote peut alors allouer,
/// projeter des registres, dormir, en tenant sa fonction.
static FONCTIONS: Verrou<&'static [Fonction]> = Verrou::new(&[]);

/// Le nombre maximal de fonctions gardées.
const FONCTIONS_MAX: usize = 256;

/// Mesure les BAR de la fonction `a`, son décodage coupé le temps de la
/// mesure, sous le verrou de `c` du début à la fin : rien ne s'affiche
/// pendant ce temps (« No printks while decoding is disabled! », dit
/// `__pci_read_base` : couper la carte VGA coupe aussi son écran). Sauf pour
/// un pont hôte, dont Linux ne coupe jamais le décodage (le `mmio_always_on`
/// qu'un « quirk » pose sur toute sa classe : « may cause problems on host
/// bridge ») : c'est lui qui mène le processeur à la mémoire vive. Et
/// COMMANDE n'est réécrite que si elle avait un décodage à couper.
fn mesurer_bars(c: &Configuration, a: Adresse, entete: &Entete, espace: &[u8]) -> [Bar; pci::NB_BAR] {
    let valeur = |p: usize| u32::from_le_bytes([espace[p], espace[p + 1], espace[p + 2], espace[p + 3]]);
    let mesurer = |p: usize| {
        c.ecrire32(a, p, !0);
        let m = c.lire32(a, p);
        c.ecrire32(a, p, valeur(p));
        m
    };
    let mut bars = [Bar::Aucune; pci::NB_BAR];
    let commande = c.lire16(a, pci::COMMANDE);
    let decodage = commande & (pci::COMMANDE_ES | pci::COMMANDE_MEMOIRE);
    let couper = decodage != 0 && entete.classe >> 8 != CLASSE_PONT_HOTE;
    if couper {
        c.ecrire16(a, pci::COMMANDE, commande & !decodage);
    }
    let mut i = 0;
    while i < entete.nb_bar() {
        let p = pci::BAR0 + 4 * i;
        let v = valeur(p);
        let mesure = mesurer(p);
        if pci::bar_64(v) {
            // Une BAR 64 bits occupe aussi la suivante ; en dernière
            // position, elle n'a pas de moitié haute : on l'ignore (Linux la
            // dit « invalide »).
            if i + 1 < entete.nb_bar() {
                bars[i] = pci::decoder_bar(v, mesure, Some((valeur(p + 4), mesurer(p + 4))));
            }
            i += 2;
        } else {
            bars[i] = pci::decoder_bar(v, mesure, None);
            i += 1;
        }
    }
    if couper {
        c.ecrire16(a, pci::COMMANDE, commande);
    }
    bars
}

/// La classe d'un pont hôte (PCI_CLASS_BRIDGE_HOST : classe 06, sous-classe
/// 00).
const CLASSE_PONT_HOTE: u32 = 0x0600;

/// Parcourt le bus `bus`, puis les bus derrière ses ponts : tout le bus
/// d'abord, ensuite chaque pont dans l'ordre (comme `pci_scan_child_bus`).
/// `vus` : les bus déjà parcourus (un pont mal configuré qui ramène à un
/// bus déjà vu ne fait pas boucler).
fn parcourir(bus: u8, vus: &mut [bool; 256], trouvees: &mut Vec<Fonction>) {
    if core::mem::replace(&mut vus[bus as usize], true) {
        return;
    }
    let mut ponts = [0u8; 32 * 8];
    let mut nb_ponts = 0;
    for periph in 0..32 {
        for fonction in 0..8 {
            let a = Adresse { bus, periph, fonction };
            let c = configuration();
            if c.lire16(a, pci::VENDEUR) == 0xFFFF {
                // Pas de fonction 0 : pas de périphérique (ses autres
                // fonctions ne sont pas cherchées).
                if fonction == 0 {
                    break;
                }
                continue;
            }
            let espace = c.lire_espace(a);
            let Ok(entete) = pci::lire_entete(&espace) else { continue };
            let bars = mesurer_bars(&c, a, &entete, &espace);
            drop(c);
            // Un pont vers un bus plus grand que le sien (celui que lui a
            // donné le micrologiciel) ; un pont vers un bus plus petit ou
            // égal est faux, on ne le suit pas.
            if let Genre::Pont { secondaire, .. } = entete.genre {
                if secondaire > bus {
                    ponts[nb_ponts] = secondaire;
                    nb_ponts += 1;
                }
            }
            let multifonction = entete.multifonction;
            if trouvees.len() < FONCTIONS_MAX {
                let _ = trouvees.ajouter(Fonction { adresse: a, entete, bars, espace });
            }
            if fonction == 0 && !multifonction {
                break;
            }
        }
    }
    for &s in &ponts[..nb_ponts] {
        parcourir(s, vus, trouvees);
    }
}

/// Parcourt le bus, et garde ce qu'il trouve. Une fois, au démarrage, avant
/// les pilotes.
pub fn initialiser() -> usize {
    let mut trouvees = Vec::new();
    let mut vus = [false; 256];
    parcourir(0, &mut vus, &mut trouvees);
    let n = trouvees.len();
    *FONCTIONS.verrouiller() = trouvees.leak();
    n
}

/// Les fonctions trouvées au démarrage.
pub fn fonctions() -> &'static [Fonction] {
    *FONCTIONS.verrouiller()
}

/// Le nom d'une classe, pour le journal (sans accents).
fn nom_de_classe(classe: u32) -> &'static str {
    match classe >> 8 {
        0x0100 => "SCSI",
        0x0101 => "IDE",
        0x0106 => "SATA",
        0x0108 => "NVMe",
        0x0200 => "Ethernet",
        0x0300 => "VGA",
        0x0600 => "pont hote",
        0x0601 => "pont ISA",
        0x0604 => "pont PCI",
        0x0680 => "pont",
        0x0C03 => "USB",
        _ => match classe >> 16 {
            0x01 => "stockage",
            0x02 => "reseau",
            0x03 => "affichage",
            0x06 => "pont",
            _ => "autre",
        },
    }
}

/// Une taille, pour le journal : en octets sous 1 Kio, en Kio sinon.
struct Taille(u64);

impl core::fmt::Display for Taille {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if self.0 < 1024 { write!(f, "{} octets", self.0) } else { write!(f, "{} Kio", self.0 >> 10) }
    }
}

/// Affiche les fonctions trouvées, une ligne chacune : identifiants,
/// classe, fenêtres, et MSI-X s'il y en a.
pub fn afficher() {
    for fonction in fonctions() {
        let e = &fonction.entete;
        afficher!("[pci] {} {:04x}:{:04x} {}", fonction.adresse, e.vendeur, e.peripherique, nom_de_classe(e.classe));
        if let Genre::Pont { secondaire, subordonne, .. } = e.genre {
            afficher!(", bus {}-{}", secondaire, subordonne);
        }
        for (i, b) in fonction.bars.iter().enumerate() {
            match *b {
                Bar::Aucune => {}
                Bar::Es { port, taille } => afficher!(", BAR{} ports {:#x} ({})", i, port, taille),
                Bar::Memoire { adresse, taille, bits64, prefetchable } => {
                    afficher!(", BAR{} {:#x} ({}{}{})", i, adresse, Taille(taille),
                              if bits64 { ", 64 bits" } else { "" }, if prefetchable { ", prefetchable" } else { "" })
                }
            }
        }
        let msix = fonction.capacites().find(|&(_, n)| n == pci::CAPACITE_MSIX)
            .and_then(|(p, _)| pci::lire_msix(&fonction.espace, p).ok());
        if let Some(m) = msix {
            afficher!(", MSI-X ({} entrees)", m.entrees);
        }
        afficherln!(".");
    }
}
