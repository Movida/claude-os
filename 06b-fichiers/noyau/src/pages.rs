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
//! Ce qu'il faut savoir de chaque cadre tient dans son DESCRIPTEUR, une
//! table de 8 octets par cadre (le `mem_map` de Linux, un tableau de
//! « struct page ») :
//!   - est-il le début d'un bloc libre, ou d'un bloc alloué, et de quel
//!     ordre ? Savoir où commencent les blocs alloués permet de refuser une
//!     libération fausse (un bloc déjà libre, ou rendu avec un autre ordre
//!     que le sien) ;
//!   - combien de fois est-il PRIS (son compteur de références, le
//!     `_refcount` de Linux) ? Une page d'un fichier (6b) est tenue par le
//!     fichier, par chaque projection qui la montre à un programme, et par
//!     une lecture en cours qui la copie : elle n'est rendue qu'au dernier
//!     qui la lâche (`prendre`, `lacher`). Un bloc alloué l'est une fois ;
//!   - des drapeaux : la page appartient-elle à un fichier ? Une page d'un
//!     fichier ne doit JAMAIS devenir inscriptible dans la projection
//!     privée d'un programme : il écrirait dans le fichier ;
//!   - pour une page du tas du noyau, le nombre de ses objets occupés.
//! Options écartées :
//!   - la `struct page` entière de Linux : 64 octets par cadre (1,6 % de la
//!     mémoire), parce qu'elle sert à tout (listes du cache, carte inverse,
//!     compteur des projections à part, verrou...). La nôtre en fait 8 (0,2
//!     %) ; elle grandira avec ce qui en aura besoin ;
//!   - une table à part pour les compteurs, et les drapeaux dans les bits
//!     libres des entrées de pages : les drapeaux disent ce qu'est le cadre,
//!     pas ce qu'est une de ses projections ; et trois tables par cadre
//!     coûteraient trois accès au lieu d'un.
//! Les listes, elles, sont rangées dans les blocs libres eux-mêmes (les
//! deux premiers mots de chacun : le suivant et le précédent) : un bloc
//! libre ne contient rien d'utile, et la projection directe permet de
//! l'écrire.

use crate::verrou::Verrou;
use crate::{cadres, espace};

/// Le plus grand ordre : des blocs de 2^10 pages (4 Mio), comme Linux
/// (MAX_PAGE_ORDER).
pub const ORDRE_MAX: u32 = 10;

const PAGE: u64 = 4096;

/// Dans `Descripteur::etat` : le cadre n'est le début d'aucun bloc (il est
/// réservé, ou au milieu d'un bloc). Le début d'un bloc libre vaut son
/// ordre ; celui d'un bloc alloué, ALLOUE | son ordre.
const AUCUN: u8 = 0xFF;
const ALLOUE: u8 = 0x80;

/// Le descripteur d'un cadre (la « struct page » de Linux, en 8 octets).
#[derive(Clone, Copy)]
#[repr(C)]
struct Descripteur {
    /// Ce qui commence à ce cadre (voir AUCUN).
    etat: u8,
    /// Ce qu'est le cadre : une page d'un fichier, par exemple (6b).
    drapeaux: u8,
    /// Pour une page du tas : ses objets occupés (tas.rs).
    objets: u16,
    /// Combien de fois le bloc qui commence ici est pris (0 s'il est libre).
    references: u32,
}

const VIERGE: Descripteur = Descripteur { etat: AUCUN, drapeaux: 0, objets: 0, references: 0 };

struct Pages {
    /// Le descripteur de chaque cadre.
    cadres: &'static mut [Descripteur],
    /// Le premier bloc libre de chaque ordre (adresse physique), 0 si la
    /// liste est vide. Le cadre 0 n'est jamais libre (le premier Mio est
    /// réservé) : 0 ne désigne aucun bloc.
    listes: [u64; ORDRE_MAX as usize + 1],
    /// Pages libres, au total.
    libres: usize,
    /// Pages confiées à l'allocateur au démarrage : toute la mémoire dont
    /// il dispose (le totalram_pages de Linux).
    total: usize,
    /// La réserve du noyau, en pages (voir `allouer_pour_programme`).
    reserve: usize,
}

static PAGES: Verrou<Pages> =
    Verrou::new(Pages { cadres: &mut [], listes: [0; ORDRE_MAX as usize + 1], libres: 0, total: 0, reserve: 0 });

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
        self.cadres[(bloc / PAGE) as usize] = Descripteur { etat: ordre as u8, ..VIERGE };
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
        self.cadres[(bloc / PAGE) as usize].etat = AUCUN;
    }

    fn allouer(&mut self, ordre: u32) -> Option<u64> {
        let k = (ordre..=ORDRE_MAX).find(|&k| self.listes[k as usize] != 0)?;
        let bloc = self.listes[k as usize];
        self.retirer(bloc, k);
        // Couper : la moitié haute de chaque niveau retourne dans sa liste.
        for j in (ordre..k).rev() {
            self.inserer(bloc + (PAGE << j), j);
        }
        self.cadres[(bloc / PAGE) as usize] = Descripteur { etat: ALLOUE | ordre as u8, references: 1, ..VIERGE };
        self.libres -= 1 << ordre;
        Some(bloc)
    }

    fn liberer(&mut self, mut bloc: u64, mut ordre: u32) {
        self.cadres[(bloc / PAGE) as usize] = VIERGE;
        self.libres += 1 << ordre;
        while ordre < ORDRE_MAX {
            let copain = bloc ^ (PAGE << ordre);
            let i = (copain / PAGE) as usize;
            if i >= self.cadres.len() || self.cadres[i].etat != ordre as u8 {
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
    /// La place des descripteurs des cadres, en octets.
    pub taille_descripteurs: usize,
    /// La réserve du noyau, en pages.
    pub reserve: usize,
}

/// La réserve du noyau pour `total` pages de mémoire : le min_free_kbytes
/// de Linux (mm/page_alloc.c), √(16 × la mémoire en Kio), entre 128 Kio et
/// 256 Mio. Environ 1,4 Mio pour 128 Mio, 5,7 Mio pour 2 Gio : elle croît
/// moins vite que la mémoire, parce que ce dont le noyau a besoin en
/// urgence (des tables, des tampons) croît moins vite aussi.
fn reserve_pour(total: usize) -> usize {
    let kio = (total as u64 * (PAGE >> 10)).saturating_mul(16).isqrt().clamp(128, 256 << 10);
    (kio / (PAGE >> 10)) as usize
}

/// Construit l'allocateur à partir de l'allocateur de démarrage, qui lui
/// cède tous ses cadres libres. La pagination doit être en place : toute la
/// mémoire doit être projetée.
pub fn initialiser() -> Bilan {
    let nombre = cadres::nombre();
    let taille = (nombre * size_of::<Descripteur>()).next_multiple_of(PAGE as usize);
    let adresse = cadres::allouer_contigus(taille / PAGE as usize).expect("pas de place pour les descripteurs des cadres");
    // SAFETY : ces cadres viennent d'être alloués, d'un seul tenant, et la
    // projection directe couvre toute la mémoire ; l'adresse est alignée
    // sur la page, donc sur un descripteur.
    let descripteurs = unsafe { core::slice::from_raw_parts_mut(espace::virtuelle(adresse) as *mut Descripteur, nombre) };
    descripteurs.fill(VIERGE);
    let mut pages = PAGES.verrouiller();
    *pages = Pages { cadres: descripteurs, listes: [0; ORDRE_MAX as usize + 1], libres: 0, total: 0, reserve: 0 };
    cadres::ceder(|debut, fin| pages.ajouter_zone(debut, fin));
    (pages.total, pages.reserve) = (pages.libres, reserve_pour(pages.libres));
    Bilan { libres: pages.libres, taille_descripteurs: taille, reserve: pages.reserve }
}

/// Donne un bloc de 2^ordre pages contiguës, aligné sur sa taille :
/// l'adresse physique de sa première page, pris une fois. Son contenu est
/// quelconque.
pub fn allouer(ordre: u32) -> Option<u64> {
    assert!(ordre <= ORDRE_MAX, "ordre {ordre} trop grand");
    PAGES.verrouiller().allouer(ordre)
}

/// Donne une page pour un programme (une page à la faute, une table de son
/// espace) : seulement s'il reste plus que la réserve du noyau. Le noyau,
/// lui (`allouer`), peut y puiser : c'est ce qui lui permet de finir ce
/// qu'il a commencé (rendre la mémoire d'un programme tué, par exemple)
/// quand un programme a tout pris. C'est la ligne de flottaison « min »
/// de Linux, sous laquelle seules les allocations du noyau qui ne peuvent
/// pas attendre descendent. Sans réserve, un programme qui touche toute sa
/// mémoire laisserait le noyau sans une page.
pub fn allouer_pour_programme() -> Option<u64> {
    let mut pages = PAGES.verrouiller();
    if pages.libres <= pages.reserve {
        return None;
    }
    pages.allouer(0)
}

/// Toute la mémoire de l'allocateur, en pages.
pub fn total() -> usize {
    PAGES.verrouiller().total
}

/// Le descripteur du bloc alloué d'ordre `ordre` qui commence à `bloc`.
/// Ce qui n'en est pas un (déjà libre, rendu deux fois, avec un autre
/// ordre, ou jamais donné par cet allocateur) est une erreur grave (deux
/// propriétaires pour une même mémoire) : on s'arrête tout de suite.
fn bloc_alloue(pages: &mut Pages, bloc: u64, ordre: u32) -> &mut Descripteur {
    let i = (bloc / PAGE) as usize;
    match pages.cadres.get_mut(i) {
        Some(d) if ordre <= ORDRE_MAX && bloc % PAGE == 0 && d.etat == ALLOUE | ordre as u8 => d,
        _ => panic!("pas un bloc alloue d'ordre {ordre} : {bloc:#x}"),
    }
}

/// Rend un bloc, avec l'ordre qu'il avait à l'allocation. Il ne doit être
/// pris qu'une fois : un bloc encore tenu ailleurs se rend par `lacher`.
pub fn liberer(bloc: u64, ordre: u32) {
    let mut pages = PAGES.verrouiller();
    let references = bloc_alloue(&mut pages, bloc, ordre).references;
    assert!(references == 1, "bloc {bloc:#x} rendu alors qu'il est pris {references} fois");
    pages.liberer(bloc, ordre);
}

/// Le cadre `cadre` (une page allouée) est pris une fois de plus : une
/// projection de plus, une lecture en cours.
pub fn prendre(cadre: u64) {
    let mut pages = PAGES.verrouiller();
    let d = bloc_alloue(&mut pages, cadre, 0);
    d.references = d.references.checked_add(1).expect("compteur de references d'un cadre plein");
}

/// Le cadre `cadre` est pris une fois de moins ; il est rendu au dernier.
/// Rend vrai s'il l'a été.
pub fn lacher(cadre: u64) -> bool {
    let mut pages = PAGES.verrouiller();
    let d = bloc_alloue(&mut pages, cadre, 0);
    d.references -= 1;
    if d.references > 0 {
        return false;
    }
    pages.liberer(cadre, 0);
    true
}

/// Un objet de plus (`plus`) ou de moins occupé dans la page du tas
/// `cadre` (tas.rs) : rend le nouveau compte.
pub fn compter_objets(cadre: u64, plus: bool) -> u16 {
    let mut pages = PAGES.verrouiller();
    let d = bloc_alloue(&mut pages, cadre, 0);
    d.objets = if plus { d.objets + 1 } else { d.objets - 1 };
    d.objets
}

/// Combien de fois le cadre `cadre` (une page allouée) est pris.
pub fn references(cadre: u64) -> u32 {
    bloc_alloue(&mut PAGES.verrouiller(), cadre, 0).references
}


/// Le nombre de pages libres.
pub fn libres() -> usize {
    PAGES.verrouiller().libres
}
