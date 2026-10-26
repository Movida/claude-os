//! Les adresses du noyau à la demande : une région de la moitié haute où
//! le noyau projette, quand il en a besoin, des pages qui ne sont pas
//! d'un seul tenant en mémoire physique (le vmalloc de Linux).
//!
//! Jusqu'ici, le noyau ne voyait que deux choses : son image, et la
//! projection directe de la mémoire vive (espace.rs). Il lui faut
//! maintenant :
//!   - des PILES pour ses tâches (une par fil, 6e), chacune sous une page
//!     de garde NON PROJETÉE : une pile qui déborde y fait une faute au lieu
//!     d'écraser en silence ce qui est en dessous. Dans la projection
//!     directe, c'est impossible : chaque adresse y désigne un cadre, la
//!     page sous une pile est la mémoire de quelqu'un d'autre. Ici, une
//!     garde ne coûte qu'une adresse (le VMAP_STACK de Linux, par défaut
//!     depuis 4.9). Option écartée : des blocs de 16 Kio du buddy, dans la
//!     projection directe, sans garde (le Linux d'avant 4.9) ;
//!   - les REGISTRES des périphériques (l'APIC, 6e), qui ne sont pas de la
//!     mémoire vive : projetés sans cache (`ioremap`), pour que chaque
//!     lecture et chaque écriture atteigne vraiment le périphérique ;
//!   - les TABLES du micrologiciel (ACPI, 6e), dans une étendue que la
//!     carte E820 dit « réservée » : projetées avec cache, en lecture
//!     seule (`memremap`).
//!
//! La région commence à l'adresse de Linux (VMALLOC_START sur x86_64 à
//! quatre niveaux, 0xffffc90000000000) et tient dans UNE entrée de la PML4
//! (512 Gio). Sa PDPT est créée au démarrage, avant le premier espace
//! d'adressage : chaque programme recopie la moitié haute de la PML4 du
//! noyau (espace_utilisateur.rs) et partage donc cette PDPT ; tout ce
//! qu'on projette ensuite dans la région, il le voit aussitôt. Sans
//! cela, une entrée de PML4 créée après la naissance d'un programme lui
//! manquerait (le `preallocate_vmalloc_pages` de Linux, « Reste à faire »
//! de 6c et 6d).
//!
//! Deux parties, plutôt qu'un seul allocateur de plages comme Linux :
//!   - la zone des PILES, en cases de taille fixe (une page de garde, puis
//!     16 Kio de pile, le THREAD_SIZE de Linux), autant que le noyau
//!     permettra de fils (`max_threads`, la règle de Linux, voir plus
//!     bas). Ses tables sont toutes créées au démarrage : une pile prise et
//!     rendue pendant un programme ne laisse aucune table derrière elle (le
//!     contrôle « memoire rendue » des programmes le verrait), et la
//!     création d'un fil n'a jamais à en allouer ;
//!   - la zone des PROJECTIONS (ioremap, memremap), des plages de taille
//!     quelconque, chacune suivie d'une page de garde, prises dans une
//!     liste triée de plages libres (la première qui convient : le
//!     vmap_area de Linux, sans son arbre). Elles servent au démarrage,
//!     quelques-unes ; une liste suffit.
//! Les cases de taille fixe rendent la recherche d'une pile immédiate, et
//! disent sans calcul à quelle pile appartient une garde touchée.

use crate::pagination::{self, ECRITURE, SANS_CACHE};
use crate::pages;
use crate::verrou::Verrou;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

const PAGE: u64 = 4096;

/// Le début de la région, et sa taille : l'entrée 402 de la PML4.
pub const DEBUT: u64 = 0xffff_c900_0000_0000;
const TAILLE: u64 = 512 << 30;

/// La taille d'une pile de tâche : 16 Kio (le THREAD_SIZE de Linux sur
/// x86_64). Mesuré sur 6d : la pile du lanceur, qui décode, valide et
/// exécute aussi les programmes WebAssembly, ne descend que de 8 Kio, et
/// celle d'un programme (appels système, fautes, interruptions) de 3 Kio.
pub const TAILLE_PILE: u64 = 16 << 10;
/// Une case de la zone des piles : la garde, puis la pile.
const CASE: u64 = PAGE + TAILLE_PILE;

/// Le nombre de piles, fixé au démarrage (voir `max_threads`).
static PILES: AtomicUsize = AtomicUsize::new(0);

/// Le nombre maximal de fils, la règle de Linux (`set_max_threads`,
/// kernel/fork.c) : que les piles noyau de tous les fils ne prennent pas
/// plus d'un huitième de la mémoire, soit mémoire / (8 × 16 Kio) ; au
/// moins 20 (MIN_THREADS). 1024 pour 128 Mio, 16 384 pour 2 Gio.
pub fn max_threads() -> usize {
    PILES.load(Ordering::Relaxed)
}

/// La zone des projections commence après celle des piles, à 1 Gio
/// près, et va jusqu'à la fin de la région.
fn debut_projections(piles: usize) -> u64 {
    (DEBUT + piles as u64 * CASE).next_multiple_of(1 << 30)
}

struct Region {
    /// Les numéros des cases de pile libres (une pile, à prendre).
    piles_libres: Vec<u32>,
    /// Les plages libres de la zone des projections, triées, sans
    /// chevauchement : (début, fin).
    plages: Vec<(u64, u64)>,
}

static REGION: Verrou<Region> = Verrou::new(Region { piles_libres: Vec::new(), plages: Vec::new() });

/// Ce que l'initialisation a fait, pour l'afficher.
pub struct Bilan {
    pub piles: usize,
    /// Les tables créées d'avance, en octets.
    pub tables: u64,
}

/// Crée la région : sa PDPT, les tables de toute la zone des piles, les
/// listes. Après l'allocateur de pages, avant le premier espace
/// d'adressage d'un programme. Au démarrage, sans mémoire pour ces
/// tables, rien ne peut marcher : on s'arrête.
pub fn initialiser() -> Bilan {
    let piles = (pages::total() / 32).max(20);
    let pml4 = pagination::pml4_noyau();
    let avant = pages::libres();
    // Une table de dernier niveau (PT) couvre 2 Mio : en préparer une
    // adresse tous les 2 Mio crée toutes les tables de la zone ; la
    // première adresse de la région crée aussi la PDPT.
    let fin_piles = DEBUT + piles as u64 * CASE;
    for v in (DEBUT..fin_piles).step_by(2 << 20).chain([fin_piles - 1]) {
        pagination::preparer(pml4, v).expect("plus de memoire pour les tables de vmalloc");
    }
    let tables = (avant - pages::libres()) as u64 * PAGE;
    let mut r = REGION.verrouiller();
    // Les numéros dans l'ordre inverse : `pop` donne d'abord la case 0.
    r.piles_libres.try_reserve_exact(piles).expect("plus de memoire pour la liste des piles");
    r.piles_libres.extend((0..piles as u32).rev());
    r.plages.try_reserve_exact(16).expect("plus de memoire pour la liste des plages");
    r.plages.push((debut_projections(piles), DEBUT + TAILLE));
    PILES.store(piles, Ordering::Relaxed);
    Bilan { piles, tables }
}

/// Une pile de tâche : ses 16 Kio projetés, sous leur page de garde. Rendue
/// par `Drop` (ses pages rendues au buddy, ses traductions oubliées).
pub struct Pile {
    case: u32,
}

impl Pile {
    /// Une pile neuve, ou None : plus de case (le maximum de fils), ou
    /// plus de mémoire pour ses pages (rien ne reste alors).
    pub fn allouer() -> Option<Pile> {
        let case = REGION.verrouiller().piles_libres.pop()?;
        let pile = Pile { case };
        let pml4 = pagination::pml4_noyau();
        for v in (pile.bas()..pile.haut()).step_by(PAGE as usize) {
            // Une page qui manque : `pile` est lâchée, Drop rend celles déjà
            // projetées et la case.
            let cadre = pages::allouer(0)?;
            // Les tables existent (initialiser) : rien à allouer ici.
            pagination::projeter(pml4, v, cadre, ECRITURE | pagination::non_executable())
                .expect("table de la zone des piles absente");
        }
        Some(pile)
    }

    /// La première adresse de la pile (juste au-dessus de sa garde).
    pub fn bas(&self) -> u64 {
        DEBUT + self.case as u64 * CASE + PAGE
    }

    /// Le sommet de la pile : sa première adresse après elle (une pile x86
    /// descend).
    pub fn haut(&self) -> u64 {
        self.bas() + TAILLE_PILE
    }
}

impl Drop for Pile {
    fn drop(&mut self) {
        let pml4 = pagination::pml4_noyau();
        for v in (self.bas()..self.haut()).step_by(PAGE as usize) {
            if let Some(cadre) = pagination::retirer(pml4, v) {
                // Oublier la traduction AVANT de rendre le cadre : sinon une
                // écriture par une traduction restée en cache irait dans un
                // cadre déjà donné à quelqu'un d'autre. Les autres espaces
                // n'ont pas de traduction de cette page en cache : chaque
                // changement de CR3 vide le cache (pas de pages globales).
                pagination::invalider(v);
                pages::liberer(cadre, 0);
            }
        }
        REGION.verrouiller().piles_libres.push(self.case);
    }
}

/// Si `adresse` est dans la garde d'une pile de tâche : le message d'un
/// débordement (voir pagination::garde_touchee).
pub fn garde_touchee(adresse: u64) -> bool {
    let piles = max_threads() as u64;
    adresse >= DEBUT && adresse < DEBUT + piles * CASE && (adresse - DEBUT) % CASE < PAGE
}

/// Comment projeter une plage de la zone des projections.
#[derive(Clone, Copy)]
enum Genre {
    /// Des registres : inscriptibles, sans cache.
    Registres,
    /// Des tables du micrologiciel : en lecture seule, avec cache.
    Tables,
}

/// Une plage projetée de la zone des projections, rendue par `Drop`.
pub struct Projection {
    debut: u64,
    /// Les pages réservées pour elle (la garde, après, n'en est pas), et
    /// celles déjà projetées : une projection interrompue par une table qui
    /// manque n'en a projeté qu'une partie.
    reservees: u64,
    projetees: u64,
    /// L'adresse que demandait l'appelant (dans la première page).
    adresse: u64,
}

impl Projection {
    /// L'adresse virtuelle de la première adresse physique demandée.
    pub fn adresse(&self) -> u64 {
        self.adresse
    }
}

/// Projette [physique, physique + longueur[ dans la zone des projections,
/// des pages entières qui la couvrent. None : plus de place, ou plus de
/// mémoire pour une table (rien ne reste alors).
fn projeter(physique: u64, longueur: u64, genre: Genre) -> Option<Projection> {
    let premiere = physique / PAGE * PAGE;
    let fin = physique.checked_add(longueur.max(1))?.next_multiple_of(PAGE);
    let pages = (fin - premiere) / PAGE;
    let debut = {
        let mut r = REGION.verrouiller();
        // La place des pages, plus une page de garde après elles.
        let taille = (pages + 1) * PAGE;
        let i = r.plages.iter().position(|&(d, f)| f - d >= taille)?;
        let debut = r.plages[i].0;
        r.plages[i].0 += taille;
        if r.plages[i].0 == r.plages[i].1 {
            r.plages.remove(i);
        }
        debut
    };
    let mut p = Projection { debut, reservees: pages, projetees: 0, adresse: debut + physique % PAGE };
    let droits = match genre {
        Genre::Registres => ECRITURE | SANS_CACHE | pagination::non_executable(),
        Genre::Tables => pagination::non_executable(),
    };
    let pml4 = pagination::pml4_noyau();
    for i in 0..pages {
        // Une table qui manque : `p` est lâchée, Drop retire ce qui est déjà
        // projeté et rend la plage.
        pagination::projeter(pml4, debut + i * PAGE, premiere + i * PAGE, droits)?;
        p.projetees += 1;
    }
    Some(p)
}

/// Projette des registres de périphérique, sans cache (le `ioremap` de
/// Linux).
pub fn ioremap(physique: u64, longueur: u64) -> Option<Projection> {
    projeter(physique, longueur, Genre::Registres)
}

/// Projette des tables du micrologiciel, en lecture seule, avec cache (le
/// `memremap(MEMREMAP_WB)` de Linux). Seulement hors de la mémoire vive
/// donnée aux allocateurs : une étendue réservée, ou ACPI, de la carte
/// E820 (QEMU met ses tables dans une étendue « réservée », mesuré), ou
/// le premier Mio. Projeter une page de la mémoire vive deux fois, avec
/// des types de cache différents, aurait un comportement indéfini (manuel
/// d'Intel, vol. 3A, 11.12.4) ; et ce serait lire la mémoire de quelqu'un.
pub fn memremap(physique: u64, longueur: u64) -> Option<Projection> {
    let fin = physique.checked_add(longueur)?;
    let mut libre = false;
    crate::carte_memoire::etendues_libres(|d, f| libre |= physique < f && d < fin && d >= 1 << 20);
    if libre {
        return None;
    }
    projeter(physique, longueur, Genre::Tables)
}

impl Drop for Projection {
    fn drop(&mut self) {
        let pml4 = pagination::pml4_noyau();
        for i in 0..self.projetees {
            // Les pages projetées ne sont pas à nous : rien à rendre au buddy.
            let _ = pagination::retirer(pml4, self.debut + i * PAGE);
            pagination::invalider(self.debut + i * PAGE);
        }
        // La plage et sa garde reviennent à la liste, recollées à leurs
        // voisines.
        let (debut, fin) = (self.debut, self.debut + (self.reservees + 1) * PAGE);
        let mut r = REGION.verrouiller();
        let i = r.plages.partition_point(|&(d, _)| d < debut);
        let colle_avant = i > 0 && r.plages[i - 1].1 == debut;
        let colle_apres = i < r.plages.len() && r.plages[i].0 == fin;
        match (colle_avant, colle_apres) {
            (true, true) => {
                r.plages[i - 1].1 = r.plages[i].1;
                r.plages.remove(i);
            }
            (true, false) => r.plages[i - 1].1 = fin,
            (false, true) => r.plages[i].0 = debut,
            // La liste a toujours de la place : elle a été réservée pour 16
            // plages, et le noyau en garde bien moins à la fois. Sinon, la
            // plage est perdue (des adresses seulement), pas la mémoire.
            (false, false) => {
                if r.plages.try_reserve(1).is_ok() {
                    r.plages.insert(i, (debut, fin));
                }
            }
        }
    }
}
