//! L'allocateur de cadres : distribue la mémoire physique par pages de 4 Kio.
//!
//! Un « cadre » (frame) est une page de mémoire PHYSIQUE : 4096 octets
//! alignés sur 4096, la taille de page de base du processeur. Tout ce que
//! le noyau construira ensuite en a besoin : de nouvelles tables de pages,
//! la mémoire de chaque programme, les tampons des pilotes. Cet allocateur
//! est le seul à savoir quels cadres sont libres.
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
//!   - l'allocateur « buddy » de Linux (page_alloc.c) : des blocs de 2^n
//!     cadres, qu'on coupe en deux « copains » ou qu'on recolle. Rapide et
//!     efficace contre l'émiettement, c'est la cible à terme ; mais il a
//!     besoin d'une description de chaque cadre (la « struct page ») et de
//!     voir toute la mémoire, donc d'une pagination complète du noyau. On
//!     le construira alors, à partir de cette carte de bits, comme Linux
//!     construit le sien à partir de memblock.
//!
//! Où ranger la carte de bits ? Sa taille dépend de la mémoire de la
//! machine : on ne peut pas la réserver d'avance dans le noyau. On la place
//! dans la première zone libre assez grande, après le noyau, puis on marque
//! ses propres cadres comme occupés.

use crate::carte_memoire::{self, LIBRE};
use crate::verrou::Verrou;

pub const TAILLE_CADRE: u64 = 4096;

/// Les tables de démarrage (main.rs) ne projettent que le premier Gio : au
/// delà, le noyau ne peut rien lire ni écrire. On ne distribue donc que les
/// cadres situés en dessous, pour l'instant ; la mémoire au-dessus sera
/// prise en compte quand la projection directe couvrira toute la mémoire.
const LIMITE_PROJETEE: u64 = 1 << 30;

/// La mémoire sous 1 Mio reste réservée : vecteurs d'interruption du mode
/// réel, données du BIOS, mémoire vidéo, nos propres tables du chargeur.
/// Linux fait de même (il réserve le premier Mio sur x86 depuis 2021) : des
/// BIOS y écrivent encore après le démarrage.
const DEBUT_UTILISABLE: u64 = 0x10_0000;

struct Cadres {
    /// Un bit par cadre, du cadre 0 au cadre nombre - 1.
    bits: &'static mut [u64],
    nombre: usize,
    libres: usize,
    /// Mot de `bits` où reprendre la recherche (« next fit »).
    prochain: usize,
}

static CADRES: Verrou<Cadres> = Verrou::new(Cadres { bits: &mut [], nombre: 0, libres: 0, prochain: 0 });

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
    pub au_dela: u64,
    pub adresse_bits: u64,
    pub taille_bits: u64,
}

/// Construit la carte de bits à partir de la carte de la mémoire.
/// `fin_noyau` : première adresse après le noyau (code, données, pile).
pub fn initialiser(fin_noyau: u64) -> Result<Bilan, &'static str> {
    carte_memoire::lire(|carte| {
        let zones = carte.zones();
        let libres = || zones.iter().filter(|z| z.genre == LIBRE);

        // 1. Jusqu'où va la mémoire libre qu'on peut atteindre ?
        let fin_memoire = libres().map(|z| z.fin()).max().ok_or("aucune zone libre")?;
        let au_dela: u64 = libres()
            .map(|z| z.fin().saturating_sub(z.base.max(LIMITE_PROJETEE)))
            .sum();
        let fin_memoire = fin_memoire.min(LIMITE_PROJETEE);
        let nombre = (fin_memoire / TAILLE_CADRE) as usize;
        let taille_bits = arrondir_haut(nombre.div_ceil(64) as u64 * 8);

        // 2. Une place pour la carte de bits : dans une zone libre, après le
        //    noyau, sans toucher une zone réservée (des zones peuvent se
        //    chevaucher, le BIOS ne promet rien).
        let plancher = arrondir_haut(fin_noyau.max(DEBUT_UTILISABLE));
        let adresse_bits = libres()
            .filter(|z| z.base < fin_memoire)
            .map(|z| (arrondir_haut(z.base.max(plancher)), z.fin().min(fin_memoire)))
            .find(|&(debut, fin)| {
                debut + taille_bits <= fin
                    && zones.iter().all(|r| r.genre == LIBRE || r.fin() <= debut || r.base >= debut + taille_bits)
            })
            .map(|(debut, _)| debut)
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
        *cadres = Cadres { bits, nombre, libres: 0, prochain: 0 };
        for z in libres() {
            cadres.marquer_zone(z.base, z.fin(), false);
        }
        for z in zones.iter().filter(|z| z.genre != LIBRE) {
            cadres.marquer_zone(z.base, z.fin(), true);
        }
        cadres.marquer_zone(0, DEBUT_UTILISABLE, true);
        cadres.marquer_zone(DEBUT_UTILISABLE, fin_noyau, true);
        cadres.marquer_zone(adresse_bits, adresse_bits + taille_bits, true);

        Ok(Bilan { libres: cadres.libres, au_dela, adresse_bits, taille_bits })
    })
}

/// Donne un cadre libre : son adresse physique, alignée sur 4 Kio.
/// Son contenu est quelconque (ce qu'y a laissé le précédent occupant).
pub fn allouer() -> Option<u64> {
    let mut cadres = CADRES.verrouiller();
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
    assert!(adresse % TAILLE_CADRE == 0, "cadre mal aligne : {:#x}", adresse);
    let cadre = (adresse / TAILLE_CADRE) as usize;
    assert!(cadre < cadres.nombre && cadres.est_occupe(cadre), "cadre deja libre : {:#x}", adresse);
    cadres.marquer(cadre, false);
}

pub fn libres() -> usize {
    CADRES.verrouiller().libres
}
