//! La carte de la mémoire physique, obtenue du BIOS par le chargeur (E820).
//!
//! La mémoire vive d'un PC n'est pas d'un seul tenant. Sur une machine de
//! 128 Mio, QEMU annonce par exemple :
//!     0x00000000-0x0009FBFF  libre      (les 640 Kio « conventionnels »)
//!     0x0009FC00-0x0009FFFF  reservee   (données du BIOS)
//!     0x000F0000-0x000FFFFF  reservee   (le BIOS lui-même)
//!     0x00100000-0x07FDFFFF  libre      (tout le reste, à partir de 1 Mio)
//!     0x07FE0000-0x07FFFFFF  reservee   (tables ACPI)
//!     0xFFFC0000-0xFFFFFFFF  reservee   (copie du BIOS en mémoire flash)
//!     0xFD00000000-...       reservee   (trou propre aux processeurs AMD)
//! Entre 0xA0000 et 0xF0000 : la mémoire vidéo et les ROM des cartes, qui
//! n'apparaissent même pas. Utiliser une adresse hors des zones « libres »,
//! c'est écrire dans le BIOS, l'ACPI ou un périphérique.
//!
//! Le chargeur a rangé la carte en mémoire basse (0x4000) et nous a donné
//! son adresse. On la recopie ici dès le début : la mémoire du chargeur
//! n'est pas à nous, et le noyau ne doit dépendre de rien qui y reste.

use crate::verrou::Verrou;

/// Le format écrit par le chargeur (voir CARTE dans ../boot.asm).
#[repr(C)]
struct CarteChargeur {
    signature: [u8; 4],
    nombre: u32,
    zones: [Zone; MAX_ZONES],
}

/// Une zone de la carte. Le format est celui de l'appel E820 lui-même.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Zone {
    pub base: u64,
    pub taille: u64,
    pub genre: u32,
    _inutilise: u32,
}

/// Le seul type de zone qu'on a le droit d'utiliser librement.
pub const LIBRE: u32 = 1;

const MAX_ZONES: usize = 128;

impl Zone {
    pub fn fin(&self) -> u64 {
        // saturating_add : une zone mal décrite par le BIOS (base + taille
        // au-delà de 2^64) ne doit pas faire déborder le calcul.
        self.base.saturating_add(self.taille)
    }

    fn nom_du_genre(&self) -> &'static str {
        match self.genre {
            LIBRE => "libre",
            2 => "reservee",
            // Tables ACPI : décrivent la machine. Récupérables une fois
            // lues ; on les laisse tranquilles pour l'instant.
            3 => "ACPI (recuperable)",
            // ACPI NVS : le firmware y garde son état, même en veille.
            4 => "ACPI NVS",
            5 => "defectueuse",
            _ => "inconnue",
        }
    }
}

pub struct Carte {
    zones: [Zone; MAX_ZONES],
    nombre: usize,
}

impl Carte {
    pub fn zones(&self) -> &[Zone] {
        &self.zones[..self.nombre]
    }
}

static CARTE: Verrou<Carte> = Verrou::new(Carte {
    zones: [Zone { base: 0, taille: 0, genre: 0, _inutilise: 0 }; MAX_ZONES],
    nombre: 0,
});

/// Recopie la carte laissée par le chargeur à l'adresse `adresse`.
///
/// # Safety
/// `adresse` doit être celle que le chargeur a passée au noyau dans rdi,
/// et la mémoire basse ne doit pas encore avoir été réutilisée.
pub unsafe fn recopier(adresse: u64) -> Result<(), &'static str> {
    // SAFETY : garanti par l'appelant ; la mémoire basse est projetée.
    let source = unsafe { &*(adresse as *const CarteChargeur) };
    if &source.signature != b"E820" {
        return Err("signature absente : ce n'est pas notre chargeur");
    }
    let nombre = (source.nombre as usize).min(MAX_ZONES);
    let mut carte = CARTE.verrouiller();
    // On écarte les zones vides : certains BIOS en rendent.
    for zone in source.zones[..nombre].iter().filter(|z| z.taille > 0) {
        let n = carte.nombre;
        carte.zones[n] = *zone;
        carte.nombre += 1;
    }
    Ok(())
}

/// Donne accès à la carte (en lecture) le temps d'un calcul.
pub fn lire<R>(f: impl FnOnce(&Carte) -> R) -> R {
    f(&CARTE.verrouiller())
}

/// Affiche la carte, à la façon des lignes « BIOS-e820 » de Linux au
/// démarrage (dmesg).
pub fn afficher() {
    lire(|carte| {
        afficherln!("[noyau] Carte de la memoire (E820), {} zones :", carte.nombre);
        for zone in carte.zones() {
            afficherln!("        {:#014x}-{:#014x}  {}",
                        zone.base, zone.fin() - 1, zone.nom_du_genre());
        }
    });
}
