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
//! Le chargeur l'a rangée dans les informations de démarrage, que
//! demarrage.rs recopie dès le début, en nous passant les zones.

use crate::verrou::Verrou;

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

/// Le plus de zones que le chargeur transmet (CARTE_MAX dans ../boot.asm).
pub const MAX_ZONES: usize = 128;

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

/// Garde les zones de la carte transmise par le chargeur.
pub fn installer(zones: &[Zone]) {
    let mut carte = CARTE.verrouiller();
    // On écarte les zones vides : certains BIOS en rendent.
    for zone in zones.iter().filter(|z| z.taille > 0).take(MAX_ZONES) {
        let n = carte.nombre;
        carte.zones[n] = *zone;
        carte.nombre += 1;
    }
}

/// Appelle `f(debut, fin)` pour chaque étendue de mémoire libre, dans
/// l'ordre des adresses : les zones libres qui se chevauchent ou se
/// touchent ne font qu'une (le BIOS ne promet pas de zones disjointes,
/// Linux les fusionne aussi, dans e820__update_table).
pub fn etendues_libres(mut f: impl FnMut(u64, u64)) {
    lire(|carte| {
        let mut libres = [(0u64, 0u64); MAX_ZONES];
        let mut n = 0;
        for z in carte.zones().iter().filter(|z| z.genre == LIBRE) {
            libres[n] = (z.base, z.fin());
            n += 1;
        }
        libres[..n].sort_unstable();
        let mut courante: Option<(u64, u64)> = None;
        for &(debut, fin) in &libres[..n] {
            courante = match courante {
                Some((d, f_)) if debut <= f_ => Some((d, f_.max(fin))),
                Some((d, f_)) => {
                    f(d, f_);
                    Some((debut, fin))
                }
                None => Some((debut, fin)),
            };
        }
        if let Some((d, f_)) = courante {
            f(d, f_);
        }
    });
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
