//! L'allocateur de pages : le « buddy » de Linux (mm/page_alloc.c).
//!
//! Il distribue la mémoire physique par BLOCS de 2^ordre pages de 4 Kio
//! contiguës, d'ordre 0 (une page) à ORDRE_MAX (1024 pages, 4 Mio), chaque
//! bloc aligné sur sa taille. Pour chaque ordre, une liste des blocs libres.
//!
//!   - Allouer un bloc d'ordre k : en prendre un dans la liste de l'ordre
//!     k ; si elle est vide, couper en deux un bloc de l'ordre k + 1 (ou
//!     plus haut, de proche en proche) : on garde une moitié, l'autre va
//!     dans la liste de l'ordre inférieur.
//!   - Libérer un bloc d'ordre k : son « copain » (buddy) est l'autre
//!     moitié du bloc d'ordre k + 1 qui les contient tous les deux ; son
//!     adresse ne diffère que d'un bit (bloc XOR taille). S'il est libre, et
//!     du même ordre, on les recolle en un bloc d'ordre k + 1, et on
//!     recommence un ordre plus haut.
//! Les deux opérations prennent au plus ORDRE_MAX étapes. Et la mémoire se
//! recolle d'elle-même en grands blocs à mesure qu'on la rend : c'est ce qui
//! permet, longtemps après le démarrage, de trouver encore plusieurs pages
//! contiguës (les files des pilotes virtio, à l'étape 6), ce qu'une simple
//! liste de pages libres ne sait pas faire.
//!
//! Ce qu'il faut savoir de chaque cadre : est-il le début d'un bloc libre,
//! ou d'un bloc alloué, et de quel ordre ? Linux le range dans la « struct
//! page » (64 octets par cadre, qui décrivent aussi bien d'autres choses) ;
//! il nous suffit d'un octet par cadre, la table `etats`. Savoir où
//! commencent les blocs alloués permet de refuser une libération fausse
//! (un bloc déjà libre, ou rendu avec un autre ordre que le sien). Les listes, elles, sont rangées dans
//! les blocs libres eux-mêmes (les deux premiers mots de chacun : le
//! suivant et le précédent) : un bloc libre ne contient rien d'utile, et
//! la projection directe permet de l'écrire.

use crate::verrou::Verrou;
use crate::{cadres, espace};

/// Le plus grand ordre : des blocs de 2^10 pages (4 Mio), comme Linux
/// (MAX_PAGE_ORDER).
pub const ORDRE_MAX: u32 = 10;

const PAGE: u64 = 4096;

/// Dans `etats` : le cadre n'est le début d'aucun bloc (il est réservé, ou
/// au milieu d'un bloc). Le début d'un bloc libre vaut son ordre ; celui
/// d'un bloc alloué, ALLOUE | son ordre.
const AUCUN: u8 = 0xFF;
const ALLOUE: u8 = 0x80;

struct Pages {
    /// Pour chaque cadre, ce qui y commence (voir AUCUN).
    etats: &'static mut [u8],
    /// Le premier bloc libre de chaque ordre (adresse physique), 0 si la
    /// liste est vide. Le cadre 0 n'est jamais libre (le premier Mio est
    /// réservé) : 0 ne désigne aucun bloc.
    listes: [u64; ORDRE_MAX as usize + 1],
    /// Pages libres, au total.
    libres: usize,
}

static PAGES: Verrou<Pages> = Verrou::new(Pages { etats: &mut [], listes: [0; ORDRE_MAX as usize + 1], libres: 0 });

/// Les liens d'un bloc libre dans sa liste, rangés au début du bloc.
#[repr(C)]
struct Liens {
    suivant: u64,
    precedent: u64,
}

/// Les liens du bloc libre d'adresse physique `bloc`.
///
/// # Safety
/// `bloc` doit être un bloc libre de l'allocateur : personne d'autre ne s'en
/// sert, et la projection directe le couvre.
unsafe fn liens(bloc: u64) -> &'static mut Liens {
    // SAFETY : garanti par l'appelant.
    unsafe { &mut *(espace::virtuelle(bloc) as *mut Liens) }
}

impl Pages {
    fn inserer(&mut self, bloc: u64, ordre: u32) {
        let tete = self.listes[ordre as usize];
        // SAFETY : `bloc` devient un bloc libre ; `tete` en est un.
        unsafe {
            *liens(bloc) = Liens { suivant: tete, precedent: 0 };
            if tete != 0 {
                liens(tete).precedent = bloc;
            }
        }
        self.listes[ordre as usize] = bloc;
        self.etats[(bloc / PAGE) as usize] = ordre as u8;
    }

    fn retirer(&mut self, bloc: u64, ordre: u32) {
        // SAFETY : `bloc` est un bloc libre de la liste `ordre`, ses voisins
        // aussi.
        unsafe {
            let Liens { suivant, precedent } = *liens(bloc);
            if precedent == 0 {
                self.listes[ordre as usize] = suivant;
            } else {
                liens(precedent).suivant = suivant;
            }
            if suivant != 0 {
                liens(suivant).precedent = precedent;
            }
        }
        self.etats[(bloc / PAGE) as usize] = AUCUN;
    }

    fn allouer(&mut self, ordre: u32) -> Option<u64> {
        let k = (ordre..=ORDRE_MAX).find(|&k| self.listes[k as usize] != 0)?;
        let bloc = self.listes[k as usize];
        self.retirer(bloc, k);
        // Couper : la moitié haute de chaque niveau retourne dans sa liste.
        for j in (ordre..k).rev() {
            self.inserer(bloc + (PAGE << j), j);
        }
        self.etats[(bloc / PAGE) as usize] = ALLOUE | ordre as u8;
        self.libres -= 1 << ordre;
        Some(bloc)
    }

    fn liberer(&mut self, mut bloc: u64, mut ordre: u32) {
        self.etats[(bloc / PAGE) as usize] = AUCUN;
        self.libres += 1 << ordre;
        while ordre < ORDRE_MAX {
            let copain = bloc ^ (PAGE << ordre);
            let i = (copain / PAGE) as usize;
            if i >= self.etats.len() || self.etats[i] != ordre as u8 {
                break;
            }
            self.retirer(copain, ordre);
            bloc = bloc.min(copain);
            ordre += 1;
        }
        self.inserer(bloc, ordre);
    }

    /// Ajoute la zone libre [debut, fin[ en blocs aussi grands que leur
    /// alignement et la zone le permettent (comme __free_pages_memory dans
    /// Linux) : plus rapide que de libérer page par page.
    fn ajouter_zone(&mut self, debut: u64, fin: u64) {
        let (mut cadre, fin) = (debut / PAGE, fin / PAGE);
        while cadre < fin {
            let ordre = ORDRE_MAX.min(cadre.trailing_zeros()).min((fin - cadre).ilog2());
            self.inserer(cadre * PAGE, ordre);
            self.libres += 1 << ordre;
            cadre += 1 << ordre;
        }
    }
}

/// Ce que l'initialisation a fait, pour l'afficher.
pub struct Bilan {
    pub libres: usize,
    pub taille_etats: usize,
}

/// Construit l'allocateur à partir de l'allocateur de démarrage, qui lui
/// cède tous ses cadres libres. La pagination doit être en place : toute la
/// mémoire doit être projetée.
pub fn initialiser() -> Bilan {
    let nombre = cadres::nombre();
    let taille_etats = nombre.next_multiple_of(PAGE as usize);
    let adresse = cadres::allouer_contigus(taille_etats / PAGE as usize).expect("pas de place pour l'etat des pages");
    // SAFETY : ces cadres viennent d'être alloués, d'un seul tenant, et la
    // projection directe couvre toute la mémoire.
    let etats = unsafe { core::slice::from_raw_parts_mut(espace::virtuelle(adresse) as *mut u8, nombre) };
    etats.fill(AUCUN);
    let mut pages = PAGES.verrouiller();
    *pages = Pages { etats, listes: [0; ORDRE_MAX as usize + 1], libres: 0 };
    cadres::ceder(|debut, fin| pages.ajouter_zone(debut, fin));
    Bilan { libres: pages.libres, taille_etats }
}

/// Donne un bloc de 2^ordre pages contiguës, aligné sur sa taille :
/// l'adresse physique de sa première page. Son contenu est quelconque.
pub fn allouer(ordre: u32) -> Option<u64> {
    assert!(ordre <= ORDRE_MAX, "ordre {ordre} trop grand");
    PAGES.verrouiller().allouer(ordre)
}

/// Rend un bloc, avec l'ordre qu'il avait à l'allocation. Rendre ce qui
/// n'est pas un bloc alloué de cet ordre (déjà libre, rendu deux fois, avec
/// un autre ordre, ou jamais donné par cet allocateur) est une erreur grave
/// (deux propriétaires pour une même mémoire) : on s'arrête tout de suite.
pub fn liberer(bloc: u64, ordre: u32) {
    let mut pages = PAGES.verrouiller();
    let i = (bloc / PAGE) as usize;
    let attendu = ALLOUE | ordre as u8;
    assert!(
        ordre <= ORDRE_MAX && bloc % PAGE == 0 && pages.etats.get(i) == Some(&attendu),
        "pas un bloc alloue d'ordre {ordre} : {bloc:#x}"
    );
    pages.liberer(bloc, ordre);
}

/// Le nombre de pages libres.
pub fn libres() -> usize {
    PAGES.verrouiller().libres
}
