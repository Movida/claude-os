//! L'allocateur de démarrage : distribue la mémoire physique par pages de
//! 4 Kio, le temps que le noyau construise sa pagination.
//!
//! Un « cadre » (frame) est une page de mémoire PHYSIQUE : 4096 octets
//! alignés sur 4096, la taille de page de base du processeur. Les tables de
//! pages du noyau (pagination.rs) en ont besoin avant que toute la mémoire
//! soit projetée ; une fois la pagination en place, cet allocateur cède
//! tous ses cadres libres à l'allocateur de pages (pages.rs), et ne sert
//! plus. C'est le rôle de memblock dans Linux : memblock_free_all donne la
//! mémoire au buddy à la fin du démarrage.
//!
//! La méthode : une carte de bits (bitmap), un bit par cadre, 1 = occupé,
//! 0 = libre. 1 Gio de mémoire = 262 144 cadres = 32 Kio de bits.
//!   - Allouer : chercher un bit à 0, le mettre à 1. On lit 64 bits à la
//!     fois (un mot entier à !0 = 64 cadres occupés, on passe), et on
//!     reprend la recherche là où la précédente s'est arrêtée.
//!   - Libérer : remettre le bit à 0.
//! C'est l'allocateur de démarrage qu'a utilisé Linux pendant vingt ans
//! (bootmem, remplacé par memblock en 2018).
//!
//! Options écartées :
//!   - la pile (ou liste) de cadres libres : allouer et libérer en temps
//!     constant, mais impossible de trouver plusieurs cadres CONTIGUS, dont
//!     les pilotes auront besoin (les files virtio de l'étape 6) ; et la
//!     liste vit dans les cadres libres eux-mêmes, qu'il faut pouvoir lire ;
//!   - l'allocateur « buddy » de Linux (page_alloc.c), dès le départ :
//!     rapide et efficace contre l'émiettement, mais il a besoin d'une
//!     description de chaque cadre et de voir toute la mémoire, donc d'une
//!     pagination complète du noyau. Il prend la suite (pages.rs), construit
//!     à partir de cette carte de bits.
//!
//! Où ranger la carte de bits ? Sa taille dépend de la mémoire de la
//! machine : on ne peut pas la réserver d'avance dans le noyau. On la place
//! dans la première place libre assez grande, après le noyau et hors de
//! l'archive de programmes, puis on marque ses propres cadres comme
//! occupés.

use crate::carte_memoire::{self, LIBRE};
use crate::demarrage::Etendue;
use crate::verrou::Verrou;

pub const TAILLE_CADRE: u64 = 4096;

/// Les tables de démarrage (main.rs) ne projettent que le premier Gio : la
/// carte de bits doit y être, pour qu'on puisse l'écrire dès maintenant.
/// Les cadres, eux, sont comptés dans toute la mémoire ; ceux du dessus ne
/// servent qu'une fois la projection directe complète (pagination.rs).
const LIMITE_DEMARRAGE: u64 = 1 << 30;

/// La mémoire sous 1 Mio reste réservée : vecteurs d'interruption du mode
/// réel, données du BIOS, mémoire vidéo, nos propres tables du chargeur.
/// Linux fait de même (il réserve le premier Mio sur x86 depuis 2021) : des
/// BIOS y écrivent encore après le démarrage.
const DEBUT_UTILISABLE: u64 = 0x10_0000;

struct Cadres {
    /// Un bit par cadre, du cadre 0 au cadre nombre - 1.
    bits: &'static mut [u64],
    /// L'adresse physique de la carte de bits elle-même.
    adresse_bits: u64,
    nombre: usize,
    /// Les cadres ont-ils été cédés à l'allocateur de pages ?
    cede: bool,
    libres: usize,
    /// Mot de `bits` où reprendre la recherche (« next fit »).
    prochain: usize,
}

static CADRES: Verrou<Cadres> =
    Verrou::new(Cadres { bits: &mut [], adresse_bits: 0, nombre: 0, cede: false, libres: 0, prochain: 0 });

fn arrondir_haut(x: u64) -> u64 {
    x.div_ceil(TAILLE_CADRE) * TAILLE_CADRE
}

fn arrondir_bas(x: u64) -> u64 {
    x / TAILLE_CADRE * TAILLE_CADRE
}

impl Cadres {
    fn est_occupe(&self, cadre: usize) -> bool {
        self.bits[cadre / 64] & 1 << (cadre % 64) != 0
    }

    fn marquer(&mut self, cadre: usize, occupe: bool) {
        if self.est_occupe(cadre) == occupe {
            return;
        }
        if occupe {
            self.bits[cadre / 64] |= 1 << (cadre % 64);
            self.libres -= 1;
        } else {
            self.bits[cadre / 64] &= !(1 << (cadre % 64));
            self.libres += 1;
        }
    }

    /// Marque tous les cadres de [debut, fin[, adresses physiques.
    /// Pour libérer, on ne prend que les cadres ENTIÈREMENT dans la zone ;
    /// pour réserver, tous ceux qui la touchent, même d'un octet.
    fn marquer_zone(&mut self, debut: u64, fin: u64, occupe: bool) {
        // D'abord ramener la zone à la mémoire gérée : arrondir une adresse
        // proche de 2^64 déborderait (et en version optimisée, Rust ne
        // vérifie pas les débordements : le résultat serait faux en silence).
        let limite = self.nombre as u64 * TAILLE_CADRE;
        let (debut, fin) = (debut.min(limite), fin.min(limite));
        let (debut, fin) = if occupe {
            (arrondir_bas(debut), arrondir_haut(fin))
        } else {
            (arrondir_haut(debut), arrondir_bas(fin))
        };
        let premier = (debut / TAILLE_CADRE) as usize;
        let dernier = (fin / TAILLE_CADRE) as usize;
        for cadre in premier..dernier {
            self.marquer(cadre, occupe);
        }
    }
}

/// Ce que l'initialisation a trouvé, pour l'afficher.
pub struct Bilan {
    pub libres: usize,
    pub adresse_bits: u64,
    pub taille_bits: u64,
}

/// Construit la carte de bits à partir de la carte de la mémoire.
/// `fin_noyau` : première adresse après le noyau (code, données, pile) ;
/// `archive` : l'archive de programmes déposée par le chargeur, réservée
/// elle aussi (comme l'initramfs de Linux, que memblock réserve).
pub fn initialiser(fin_noyau: u64, archive: Option<Etendue>) -> Result<Bilan, &'static str> {
    carte_memoire::lire(|carte| {
        let zones = carte.zones();
        let libres = || zones.iter().filter(|z| z.genre == LIBRE);

        // 1. Jusqu'où va la mémoire libre ?
        let fin_memoire = libres().map(|z| z.fin()).max().ok_or("aucune zone libre")?;
        let nombre = (fin_memoire / TAILLE_CADRE) as usize;
        let taille_bits = arrondir_haut(nombre.div_ceil(64) as u64 * 8);

        // 2. Une place pour la carte de bits : dans une zone libre, après le
        //    début utilisable, sans toucher une zone réservée (des zones
        //    peuvent se chevaucher, le BIOS ne promet rien), ni le noyau, ni
        //    l'archive. Les débuts possibles : le début d'une zone libre, ou
        //    la fin d'une étendue occupée ; on prend le plus bas qui
        //    convient.
        let occupees = [
            Etendue { debut: DEBUT_UTILISABLE, fin: fin_noyau },
            archive.unwrap_or(Etendue { debut: 0, fin: 0 }),
        ];
        let convient = |debut: u64| {
            let fin = debut + taille_bits;
            fin <= LIMITE_DEMARRAGE
                && libres().any(|z| z.base <= debut && fin <= z.fin())
                && zones.iter().all(|r| r.genre == LIBRE || r.fin() <= debut || r.base >= fin)
                && occupees.iter().all(|o| o.fin <= debut || o.debut >= fin)
        };
        let adresse_bits = libres()
            .map(|z| z.base)
            .chain(occupees.iter().map(|o| o.fin))
            // Borner avant d'arrondir : une adresse proche de 2^64
            // déborderait en silence.
            .filter(|&d| d < LIMITE_DEMARRAGE)
            .map(|d| arrondir_haut(d.max(DEBUT_UTILISABLE)))
            .filter(|&d| convient(d))
            .min()
            .ok_or("pas de place pour la carte de bits")?;

        // SAFETY : cette plage est de la mémoire libre d'après le BIOS,
        // sous la limite projetée, hors du noyau, et n'appartient qu'à nous
        // à partir de maintenant (on la marque occupée juste après). On la
        // voit par la projection directe.
        let bits = unsafe {
            let debut = crate::espace::virtuelle(adresse_bits) as *mut u64;
            core::slice::from_raw_parts_mut(debut, (taille_bits / 8) as usize)
        };

        // 3. Tout occupé d'abord, puis on libère les zones libres, puis on
        //    réoccupe tout ce qui est réservé : si deux zones se recouvrent,
        //    la réservée l'emporte (prudence, comme Linux).
        bits.fill(!0);
        let mut cadres = CADRES.verrouiller();
        *cadres = Cadres { bits, adresse_bits, nombre, cede: false, libres: 0, prochain: 0 };
        for z in libres() {
            cadres.marquer_zone(z.base, z.fin(), false);
        }
        for z in zones.iter().filter(|z| z.genre != LIBRE) {
            cadres.marquer_zone(z.base, z.fin(), true);
        }
        cadres.marquer_zone(0, DEBUT_UTILISABLE, true);
        cadres.marquer_zone(DEBUT_UTILISABLE, fin_noyau, true);
        if let Some(a) = archive {
            cadres.marquer_zone(a.debut, a.fin, true);
        }
        cadres.marquer_zone(adresse_bits, adresse_bits + taille_bits, true);

        Ok(Bilan { libres: cadres.libres, adresse_bits, taille_bits })
    })
}

/// Donne un cadre libre : son adresse physique, alignée sur 4 Kio.
/// Son contenu est quelconque (ce qu'y a laissé le précédent occupant).
pub fn allouer() -> Option<u64> {
    let mut cadres = CADRES.verrouiller();
    assert!(!cadres.cede, "allocateur de demarrage deja cede");
    let nb_mots = cadres.bits.len();
    for i in 0..nb_mots {
        let mot = (cadres.prochain + i) % nb_mots;
        let bits = cadres.bits[mot];
        if bits != !0 {
            // trailing_ones : nombre de 1 en partant du bit 0, donc la
            // position du premier 0 (une instruction : tzcnt sur !bits).
            let cadre = mot * 64 + bits.trailing_ones() as usize;
            if cadre >= cadres.nombre {
                continue; // Les bits du dernier mot, au-delà de la mémoire.
            }
            cadres.marquer(cadre, true);
            cadres.prochain = mot;
            return Some(cadre as u64 * TAILLE_CADRE);
        }
    }
    None
}

/// Rend un cadre. Rendre un cadre mal aligné, ou déjà libre, est une
/// erreur de programmation grave (deux propriétaires pour une même page) :
/// on s'arrête tout de suite, plutôt que de laisser la mémoire se corrompre
/// en silence (Linux affiche alors « Bad page state »).
pub fn liberer(adresse: u64) {
    let mut cadres = CADRES.verrouiller();
    assert!(!cadres.cede, "allocateur de demarrage deja cede");
    assert!(adresse % TAILLE_CADRE == 0, "cadre mal aligne : {:#x}", adresse);
    let cadre = (adresse / TAILLE_CADRE) as usize;
    assert!(cadre < cadres.nombre && cadres.est_occupe(cadre), "cadre deja libre : {:#x}", adresse);
    cadres.marquer(cadre, false);
}

pub fn libres() -> usize {
    CADRES.verrouiller().libres
}

/// L'allocateur a-t-il déjà cédé ses cadres à l'allocateur de pages ?
pub fn est_cede() -> bool {
    CADRES.verrouiller().cede
}

/// Le nombre de cadres de la mémoire, libres ou non.
pub fn nombre() -> usize {
    CADRES.verrouiller().nombre
}

/// Donne `n` cadres CONTIGUS : l'adresse physique du premier. Le premier
/// qui convient, en partant du bas (« first fit ») : ce n'est appelé que
/// quelques fois, au démarrage.
pub fn allouer_contigus(n: usize) -> Option<u64> {
    let mut cadres = CADRES.verrouiller();
    assert!(!cadres.cede, "allocateur de demarrage deja cede");
    let mut debut = 0;
    for cadre in 0..cadres.nombre {
        if cadres.est_occupe(cadre) {
            debut = cadre + 1;
        } else if cadre + 1 - debut == n {
            for c in debut..=cadre {
                cadres.marquer(c, true);
            }
            return Some(debut as u64 * TAILLE_CADRE);
        }
    }
    None
}

/// Cède tous les cadres libres à l'allocateur de pages : appelle
/// `ceder_zone(debut, fin)` (adresses physiques) pour chaque suite de
/// cadres libres, puis pour la carte de bits elle-même, qui ne servira
/// plus. Après, allouer et libérer ici est une erreur.
pub fn ceder(mut ceder_zone: impl FnMut(u64, u64)) {
    let mut cadres = CADRES.verrouiller();
    assert!(!cadres.cede, "allocateur de demarrage deja cede");
    let mut debut = None;
    for cadre in 0..=cadres.nombre {
        let libre = cadre < cadres.nombre && !cadres.est_occupe(cadre);
        match (libre, debut) {
            (true, None) => debut = Some(cadre),
            (false, Some(d)) => {
                ceder_zone(d as u64 * TAILLE_CADRE, cadre as u64 * TAILLE_CADRE);
                debut = None;
            }
            _ => {}
        }
    }
    cadres.cede = true;
    cadres.libres = 0;
    let taille = (cadres.bits.len() * 8) as u64;
    cadres.bits = &mut [];
    ceder_zone(cadres.adresse_bits, cadres.adresse_bits + taille);
}
