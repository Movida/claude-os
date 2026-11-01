//! virtio : des périphériques faits pour les machines virtuelles.
//!
//! Imiter une vraie carte réseau (l'e1000 d'Intel, que QEMU propose aussi)
//! oblige l'hyperviseur à reproduire chacun de ses registres, et le système
//! à en avoir le pilote ; virtio (Rusty Russell, 2007 ; norme OASIS depuis
//! 2016, version 1.2 en 2022) est une interface pensée pour la virtualisation,
//! la même pour toutes les sortes de périphériques (réseau, disque, console,
//! entropie...) : des FILES partagées en mémoire (virtqueue.rs) où le
//! pilote dépose des tampons et où le périphérique les rend remplis, un
//! jeu de FONCTIONNALITÉS que les deux côtés négocient, et une petite zone
//! de configuration propre au périphérique (l'adresse MAC d'une carte
//! réseau). Linux, FreeBSD, Windows (pilotes de Red Hat) en ont les
//! pilotes ; QEMU, KVM, Firecracker, les nuages en offrent les
//! périphériques.
//!
//! Ce module est le TRANSPORT PCI MODERNE (spécification 1.2, section
//! 4.1) : la carte est une fonction PCI de fabricant 0x1af4, et des
//! capacités du fabricant (formats::pci::lire_virtio) disent dans quelle BAR
//! sont ses quatre structures : la configuration COMMUNE (fonctionnalités,
//! état, files), la zone de NOTIFICATION (où l'on écrit pour dire « une file
//! a du nouveau »), le registre ISR (seulement pour INTx), et la
//! configuration du PÉRIPHÉRIQUE. Le pilote d'une sorte de périphérique
//! (reseau/virtio_net.rs) s'en sert ; le disque (virtio-blk, 6l) s'en
//! servira de même.
//!
//! Options écartées :
//!   - l'interface « legacy » de virtio 0.9 (des ports d'E/S dans la BAR 0,
//!     que QEMU offre encore : la carte est « transitionnelle ») : dépréciée
//!     par virtio 1.0, sans fonctionnalités au-delà du bit 31, avec un
//!     format d'octets qui dépend de la machine, et un MSI-X greffé après
//!     coup (deux registres qui décalent la zone du périphérique selon
//!     qu'il est activé) ;
//!   - le transport MMIO de virtio (une page de registres à une adresse
//!     fixe, sans PCI) : celui des petites machines virtuelles ARM et de
//!     Firecracker ; un PC a PCI.
//!
//! La poignée de main (spécification 3.1.1, `virtio_dev_probe` et
//! `virtio_pci_modern` de Linux) : remise à zéro (écrire 0 dans l'état,
//! puis attendre de relire 0), ACKNOWLEDGE (« je t'ai vu »), DRIVER (« je
//! sais te piloter »), lire les fonctionnalités offertes, écrire celles
//! qu'on accepte, FEATURES_OK, puis RELIRE l'état : la carte enlève
//! FEATURES_OK si elle refuse notre choix. Puis les files, les vecteurs
//! d'interruption, et DRIVER_OK : la carte travaille. À la moindre erreur,
//! FAILED, et la carte reste éteinte.
//!
//! Tous les accès aux registres sont volatils et de la largeur du champ
//! (la spécification, 4.1.3.1 : un champ de 16 bits ne se lit pas en 32) ;
//! les champs de 64 bits (les adresses des files) s'écrivent en deux mots
//! de 32 bits, le bas d'abord, ce que la spécification permet.

use crate::msix::{self, MsiX};
use crate::pci::Fonction;
use crate::vmalloc::{self, Projection};
use formats::pci::{self, Bar, StructureVirtio};

/// Le fabricant des périphériques virtio (Red Hat, Qumranet à l'origine).
pub const FABRICANT: u16 = 0x1af4;
/// Les modèles : transitionnels (0x1000 + sorte de l'ancienne
/// numérotation), modernes (0x1040 + numéro de sorte). Une carte réseau :
/// 0x1000 ou 0x1041 (sorte 1).
pub const RESEAU_TRANSITIONNEL: u16 = 0x1000;
pub const MODERNE: u16 = 0x1040;
pub const SORTE_RESEAU: u16 = 1;

// La configuration commune (`struct virtio_pci_common_cfg`).
const FONCTIONNALITE_CHOIX: u64 = 0x00;
const FONCTIONNALITE: u64 = 0x04;
const PILOTE_CHOIX: u64 = 0x08;
const PILOTE: u64 = 0x0C;
const VECTEUR_CONFIGURATION: u64 = 0x10;
const NB_FILES: u64 = 0x12;
const ETAT: u64 = 0x14;
const GENERATION: u64 = 0x15;
/// La taille minimale de la configuration commune (jusqu'à
/// `queue_device` compris).
const TAILLE_COMMUNE: u32 = 0x38;

// Les bits de l'état.
pub const ETAT_ACKNOWLEDGE: u8 = 1;
pub const ETAT_DRIVER: u8 = 2;
pub const ETAT_DRIVER_OK: u8 = 4;
pub const ETAT_FEATURES_OK: u8 = 8;
/// Le pilote abandonne la carte. (0x40, DEVICE_NEEDS_RESET, est la carte
/// qui demande à être remise à zéro : pas encore suivi.)
pub const ETAT_FAILED: u8 = 0x80;

/// Les fonctionnalités communes à toutes les sortes (virtio_config.h,
/// virtio_ring.h) : des numéros de bits sur 64.
pub const F_EVENT_IDX: u32 = 29;
pub const F_VERSION_1: u32 = 32;

/// Un vecteur MSI-X refusé par la carte (relu après l'avoir écrit).
const SANS_VECTEUR: u16 = 0xFFFF;

/// Pourquoi une carte virtio n'est pas mise en service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Il manque une des structures (commune, notification, périphérique),
    /// ou elle sort de sa BAR.
    Structure,
    /// Plus de place pour projeter les registres.
    Projection,
    /// La carte n'offre pas VERSION_1 (une carte d'avant 1.0), ou refuse
    /// nos fonctionnalités (FEATURES_OK effacé).
    Fonctionnalites,
    /// La carte ne revient pas à zéro.
    RemiseAZero,
    /// MSI-X absent ou inutilisable.
    MsiX(msix::Refus),
    /// La carte refuse un vecteur MSI-X.
    Vecteur,
}

// Affiché par le noyau : sans accents.
impl core::fmt::Display for Refus {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Refus::Structure => f.write_str("structures de virtio introuvables"),
            Refus::Projection => f.write_str("registres impossibles a projeter"),
            Refus::Fonctionnalites => f.write_str("fonctionnalites refusees"),
            Refus::RemiseAZero => f.write_str("la carte ne revient pas a zero"),
            Refus::MsiX(r) => write!(f, "{r}"),
            Refus::Vecteur => f.write_str("vecteur MSI-X refuse par la carte"),
        }
    }
}

/// Une structure de virtio projetée : son adresse virtuelle et sa longueur.
struct Fenetre {
    _projection: Projection,
    adresse: u64,
    longueur: u32,
}

/// Projette la structure `c` de la fonction `f` (dans sa BAR de mémoire),
/// d'au moins `minimum` octets.
fn projeter(f: &Fonction, c: &pci::CapaciteVirtio, minimum: u32) -> Result<Fenetre, Refus> {
    let Some(Bar::Memoire { adresse, taille, .. }) = f.bars.get(c.bar as usize).copied() else {
        return Err(Refus::Structure);
    };
    if c.longueur < minimum || c.decalage as u64 + c.longueur as u64 > taille {
        return Err(Refus::Structure);
    }
    let p = vmalloc::ioremap(adresse + c.decalage as u64, c.longueur as u64).ok_or(Refus::Projection)?;
    let a = p.adresse();
    Ok(Fenetre { _projection: p, adresse: a, longueur: c.longueur })
}

/// Une carte virtio en cours de mise en service, puis en service.
pub struct Virtio {
    commune: Fenetre,
    peripherique: Fenetre,
    pub msix: MsiX,
    /// Les fonctionnalités négociées.
    fonctionnalites: u64,
}

macro_rules! acces {
    ($lire:ident, $ecrire:ident, $t:ty) => {
        fn $lire(f: &Fenetre, position: u64) -> $t {
            debug_assert!(position + size_of::<$t>() as u64 <= f.longueur as u64);
            // SAFETY : la fenêtre est projetée sans cache sur toute sa
            // longueur, la position y est (les appelants passent des
            // positions de la spécification, vérifiées contre la longueur à
            // la projection) ; un accès aligné de la largeur du champ.
            unsafe { ((f.adresse + position) as *const $t).read_volatile() }
        }
        fn $ecrire(f: &Fenetre, position: u64, valeur: $t) {
            debug_assert!(position + size_of::<$t>() as u64 <= f.longueur as u64);
            // SAFETY : comme la lecture.
            unsafe { ((f.adresse + position) as *mut $t).write_volatile(valeur) }
        }
    };
}
acces!(lire8, ecrire8, u8);
acces!(lire16, ecrire16, u16);
acces!(lire32, ecrire32, u32);

impl Virtio {
    /// Trouve les structures de `f`, remet la carte à zéro, et la reconnaît
    /// (ACKNOWLEDGE, DRIVER). MSI-X est mis en service, toutes ses entrées
    /// masquées.
    pub fn ouvrir(f: &Fonction) -> Result<Virtio, Refus> {
        let mut commune = None;
        let mut notification = None;
        let mut peripherique = None;
        for (p, n) in f.capacites() {
            if n != pci::CAPACITE_FABRICANT {
                continue;
            }
            let Ok(c) = pci::lire_virtio(&f.espace, p) else { continue };
            // La première de chaque sorte, dans une BAR qui existe (la
            // spécification, 4.1.4 : le pilote utilise la première qu'il
            // sait utiliser ; Linux, `virtio_pci_find_capability`).
            if !matches!(f.bars.get(c.bar as usize), Some(Bar::Memoire { .. })) {
                continue;
            }
            match c.structure {
                StructureVirtio::Commune if commune.is_none() => commune = Some(c),
                StructureVirtio::Notification { .. } if notification.is_none() => notification = Some(c),
                StructureVirtio::Peripherique if peripherique.is_none() => peripherique = Some(c),
                _ => {}
            }
        }
        // La zone de notification ne sert qu'aux files ; mais une carte
        // sans elle n'est pas une carte virtio 1.x.
        let (Some(c), Some(_), Some(d)) = (commune, notification, peripherique) else {
            return Err(Refus::Structure);
        };
        // La carte lit et écrit la mémoire elle-même (ses files), et ses
        // MSI-X sont des écritures en mémoire : la maîtrise du bus d'abord,
        // comme le `pci_set_master` de `virtio_pci_probe`. SeaBIOS la laisse
        // éteinte (COMMANDE = 0x103, mesuré) ; sans elle, QEMU ne lit pas les
        // files, n'envoie aucune MSI-X, et une écriture de COMMANDE qui ne
        // l'a pas retire DRIVER_OK à la carte.
        f.adresse.activer_maitrise();
        let commune = projeter(f, &c, TAILLE_COMMUNE)?;
        let peripherique = projeter(f, &d, 0)?;
        let msix = MsiX::activer(f).map_err(Refus::MsiX)?;
        let v = Virtio { commune, peripherique, msix, fonctionnalites: 0 };
        v.remettre_a_zero()?;
        v.poser_etat(ETAT_ACKNOWLEDGE);
        v.poser_etat(ETAT_DRIVER);
        Ok(v)
    }

    /// Remet la carte à zéro : elle oublie ses files et ses fonctionnalités,
    /// et ne touche plus à la mémoire une fois l'état relu à 0 (la
    /// spécification, 4.1.4.3.2 : attendre de relire 0).
    fn remettre_a_zero(&self) -> Result<(), Refus> {
        ecrire8(&self.commune, ETAT, 0);
        let debut = crate::horloge::tics();
        while lire8(&self.commune, ETAT) != 0 {
            if crate::horloge::tics() - debut > 1000 {
                return Err(Refus::RemiseAZero);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    pub fn etat(&self) -> u8 {
        lire8(&self.commune, ETAT)
    }

    fn poser_etat(&self, bits: u8) {
        ecrire8(&self.commune, ETAT, self.etat() | bits);
    }

    /// Les fonctionnalités offertes par la carte (64 bits, lues par mots de
    /// 32 : `device_feature_select` choisit le mot).
    pub fn offertes(&self) -> u64 {
        let mut f = 0u64;
        for mot in 0..2u32 {
            ecrire32(&self.commune, FONCTIONNALITE_CHOIX, mot);
            f |= (lire32(&self.commune, FONCTIONNALITE) as u64) << (32 * mot);
        }
        f
    }

    /// Accepte, parmi les fonctionnalités offertes, celles de `voulues`
    /// (VERSION_1 doit en être, et être offerte), puis FEATURES_OK, relu.
    /// Rend celles qui sont négociées.
    pub fn negocier(&mut self, voulues: u64) -> Result<u64, Refus> {
        let offertes = self.offertes();
        let choisies = offertes & voulues;
        // VERSION_1 : le transport moderne. VIRTIO_F_ACCESS_PLATFORM (bit
        // 33), si la carte l'exige, demanderait de passer par une IOMMU : on
        // ne l'accepte pas, et une carte qui l'exige refusera FEATURES_OK.
        if choisies & 1 << F_VERSION_1 == 0 {
            return Err(self.echouer(Refus::Fonctionnalites));
        }
        for mot in 0..2u32 {
            ecrire32(&self.commune, PILOTE_CHOIX, mot);
            ecrire32(&self.commune, PILOTE, (choisies >> (32 * mot)) as u32);
        }
        self.poser_etat(ETAT_FEATURES_OK);
        if self.etat() & ETAT_FEATURES_OK == 0 {
            return Err(self.echouer(Refus::Fonctionnalites));
        }
        self.fonctionnalites = choisies;
        Ok(choisies)
    }

    /// Les fonctionnalités négociées.
    pub fn a(&self, bit: u32) -> bool {
        self.fonctionnalites & 1 << bit != 0
    }

    /// FAILED : la carte sait que le pilote abandonne.
    pub fn echouer(&self, r: Refus) -> Refus {
        self.poser_etat(ETAT_FAILED);
        r
    }

    /// DRIVER_OK : la carte travaille.
    pub fn demarrer(&self) {
        self.poser_etat(ETAT_DRIVER_OK);
    }

    /// Fait arriver les interruptions de configuration (un changement dans
    /// la zone du périphérique : le lien d'une carte réseau) par l'entrée
    /// MSI-X `entree`, qui doit déjà être programmée.
    pub fn vecteur_de_configuration(&self, entree: u16) -> Result<(), Refus> {
        ecrire16(&self.commune, VECTEUR_CONFIGURATION, entree);
        if lire16(&self.commune, VECTEUR_CONFIGURATION) == SANS_VECTEUR {
            return Err(Refus::Vecteur);
        }
        Ok(())
    }

    /// Le nombre de files de la carte.
    pub fn nb_files(&self) -> u16 {
        lire16(&self.commune, NB_FILES)
    }

    /// Lit la zone du périphérique avec `lire`, d'une seule « génération »
    /// : si la carte la change pendant la lecture (le compteur
    /// `config_generation` bouge), on relit (la spécification, 4.1.4.3.1 ;
    /// le `virtio_cread_bytes` de Linux).
    pub fn configuration<T>(&self, mut lire: impl FnMut(&LecteurConfiguration) -> T) -> T {
        loop {
            let avant = lire8(&self.commune, GENERATION);
            let r = lire(&LecteurConfiguration { fenetre: &self.peripherique });
            if lire8(&self.commune, GENERATION) == avant {
                return r;
            }
        }
    }
}

/// La lecture de la zone propre au périphérique, champ par champ.
pub struct LecteurConfiguration<'a> {
    fenetre: &'a Fenetre,
}

impl LecteurConfiguration<'_> {
    pub fn octet(&self, position: u64) -> Option<u8> {
        (position < self.fenetre.longueur as u64).then(|| lire8(self.fenetre, position))
    }

    pub fn mot16(&self, position: u64) -> Option<u16> {
        (position + 2 <= self.fenetre.longueur as u64).then(|| lire16(self.fenetre, position))
    }
}

impl Drop for Virtio {
    /// Une carte rendue est remise à zéro : elle ne touchera plus à la
    /// mémoire (ses files peuvent alors être rendues).
    fn drop(&mut self) {
        let _ = self.remettre_a_zero();
    }
}
