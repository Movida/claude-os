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
//!     seule (`memremap`) ;
//!   - les GRANDS BLOCS du tas (les soldes d'avant 6k) : au-delà de 4 Mio,
//!     le plus grand bloc d'un seul tenant de l'allocateur de pages, des
//!     pages éparses projetées d'un seul tenant (le `vmalloc` de Linux) ;
//!     et en secours, quand la mémoire est trop morcelée pour donner un
//!     bloc de plusieurs pages (le `kvmalloc` de Linux, voir tas.rs).
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
//!   - la zone des PROJECTIONS (ioremap, memremap) et des grands blocs du
//!     tas, des plages de taille quelconque, chacune suivie d'une page de
//!     garde, prises dans une liste triée de plages libres (la première
//!     qui convient : le vmap_area de Linux, sans son arbre). Les
//!     projections servent au démarrage, quelques-unes ; les grands blocs
//!     sont des mémoires de programmes WebAssembly, quelques-uns à la
//!     fois : une liste suffit (Linux, qui en tient des milliers, a deux
//!     arbres : les plages par adresse, et les libres par taille).
//! Les cases de taille fixe rendent la recherche d'une pile immédiate, et
//! disent sans calcul à quelle pile appartient une garde touchée.

use crate::pagination::{self, ECRITURE, SANS_CACHE};
use crate::faillible::VecFaillible;
use crate::{cpu, espace, pages};
use crate::verrou::Verrou;
use alloc::vec::Vec;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
/// moins 20 (MIN_THREADS). 1024 pour 128 Mio, 16 384 pour 2 Gio ; moins
/// les piles que les processeurs ont prises pour toujours, qu'aucun fil
/// n'aura : celles de l'IST des secondaires (`garder_pour_ist`, quatre
/// chacun), et la pile d'interruption de chacun (`garder_pour_interruptions`).
pub fn max_threads() -> usize {
    let gardees = IST.iter().chain(&INTERRUPTIONS).filter(|c| c.load(Ordering::Relaxed) != 0).count();
    PILES.load(Ordering::Relaxed) - gardees
}

/// Les piles de tâche prises pour toujours par les piles de l'IST des
/// processeurs secondaires (smp.rs) : par processeur et par rôle, le numéro
/// de la case plus un (0 : aucune). Pour nommer un débordement
/// (`garde_touchee` : « la pile IST (NMI) du processeur 2 », pas « la pile
/// noyau d'une tache »), et pour les retrancher de `max_threads`.
static IST: [AtomicU64; 4 * crate::processeur::MAX] = [const { AtomicU64::new(0) }; 4 * crate::processeur::MAX];
/// Les quatre rôles, dans l'ordre des piles de l'IST (gdt.rs).
const ROLES_IST: [&str; 4] = ["double faute", "NMI", "debogage", "verification machine"];
/// De même, la pile d'interruption de chaque processeur (interruptions.rs) :
/// le numéro de sa case plus un.
static INTERRUPTIONS: [AtomicU64; crate::processeur::MAX] = [const { AtomicU64::new(0) }; crate::processeur::MAX];

/// Donne la pile `p` pour toujours au processeur `processeur`, pour ses
/// interruptions ; rend son sommet.
pub fn garder_pour_interruptions(p: Pile, processeur: usize) -> u64 {
    INTERRUPTIONS[processeur].store(p.case as u64 + 1, Ordering::Relaxed);
    let haut = p.haut();
    core::mem::forget(p);
    haut
}

/// Donne la pile `p` pour toujours à la pile de l'IST de rôle `role` (0 à
/// 3) du processeur `processeur` ; rend son sommet. Jamais rendue : un
/// processeur en service ne s'arrête pas.
pub fn garder_pour_ist(p: Pile, processeur: usize, role: usize) -> u64 {
    IST[processeur * 4 + role].store(p.case as u64 + 1, Ordering::Relaxed);
    let haut = p.haut();
    core::mem::forget(p);
    haut
}

/// Ce que garde une page de garde de la zone des piles : la pile d'une
/// tâche, une pile de l'IST d'un processeur secondaire, ou la pile
/// d'interruption d'un processeur.
pub enum GardePile {
    Tache,
    Ist { processeur: usize, role: &'static str },
    Interruptions { processeur: usize },
}

impl core::fmt::Display for GardePile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GardePile::Tache => write!(f, "la pile noyau d'une tache"),
            GardePile::Ist { processeur, role } => write!(f, "la pile IST ({}) du processeur {}", role, processeur),
            GardePile::Interruptions { processeur } => write!(f, "la pile d'interruption du processeur {}", processeur),
        }
    }
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
    let tables = TABLES_NOYAU.verrouiller();
    for v in (DEBUT..fin_piles).step_by(2 << 20).chain([fin_piles - 1]) {
        pagination::preparer(pml4, v).expect("plus de memoire pour les tables de vmalloc");
    }
    drop(tables);
    let tables = (avant - pages::libres()) as u64 * PAGE;
    let mut r = REGION.verrouiller();
    // Les numéros dans l'ordre inverse : `pop` donne d'abord la case 0. La
    // liste a la place de toutes les piles : une pile rendue y retrouve
    // toujours la sienne.
    r.piles_libres.try_reserve_exact(piles).expect("plus de memoire pour la liste des piles");
    r.piles_libres.ajouter_tout((0..piles as u32).rev()).expect("plus de memoire pour la liste des piles");
    r.plages.try_reserve_exact(16).expect("plus de memoire pour la liste des plages");
    r.plages.ajouter_dans_la_place((debut_projections(piles), DEBUT + TAILLE));
    PILES.store(piles, Ordering::Relaxed);
    Bilan { piles, tables }
}

/// Une pile de tâche : ses 16 Kio projetés, sous leur page de garde. Rendue
/// par `Drop` (ses pages rendues au buddy, ses traductions oubliées).
pub struct Pile {
    case: u32,
}

/// Les piles rendues gardées projetées, prêtes à resservir (le cache de
/// `NR_CACHED_STACKS` piles par processeur de Linux, `kernel/fork.c`) :
/// une pile reprise pour un fil neuf garde ses adresses et ses cadres, rien
/// à projeter, et surtout rien à faire oublier aux autres processeurs (6j :
/// retirer une pile de la région demande une interruption entre
/// processeurs). Deux par processeur ; au-delà, la pile est vraiment rendue
/// (`Drop`). « Memoire rendue » (programmes.rs) vide le cache avant de
/// compter : ces cadres ne sont pas libres.
static CACHE_PILES: Verrou<Vec<Pile>> = Verrou::new(Vec::new());
const PILES_EN_CACHE_PAR_PROCESSEUR: usize = 2;

/// Le verrou des tables de pages du noyau (le `init_mm.page_table_lock` de
/// Linux, 6j) : deux processeurs qui projettent ou retirent des pages de la
/// région en même temps (une pile allouée par un clone, une autre rendue par
/// le rendeur, des registres projetés) écrivent dans les mêmes tables ;
/// chacun sa propre entrée, mais la création d'une table qui manque
/// (pagination::suivante) écrit l'entrée du niveau au-dessus, et deux
/// créateurs en perdraient une. Pris le temps d'écrire les entrées, jamais
/// pendant le vidage des TLB (qui attend les autres processeurs : smp.rs).
static TABLES_NOYAU: Verrou<()> = Verrou::new(());

/// Range la pile `p`, rendue par le rendeur (tache.rs) : dans le cache
/// s'il a de la place, sinon vraiment rendue.
pub fn ranger_pile(p: Pile) {
    let rendue = {
        let mut cache = CACHE_PILES.verrouiller();
        if cache.len() < PILES_EN_CACHE_PAR_PROCESSEUR * crate::processeur::nombre() { cache.ajouter_ou_rendre(p).err() } else { Some(p) }
    };
    // Vraiment rendue HORS du verrou du cache (le cache plein, ou sans place
    // pour elle) : rendre une pile vide les TLB des autres processeurs, ce
    // qui attend leurs réponses, interdit sous un Verrou (smp.rs).
    // `ajouter` l'aurait lâchée sous le verrou si la place avait manqué
    // (la relecture de 6j).
    drop(rendue);
}

/// Vide le cache des piles : chacune est vraiment rendue. Avant de compter
/// la mémoire rendue d'un programme.
pub fn vider_le_cache_des_piles() {
    loop {
        let Some(p) = CACHE_PILES.verrouiller().pop() else { return };
        drop(p);
    }
}

impl Pile {
    /// Une pile neuve, ou None : plus de case (le maximum de fils), ou
    /// plus de mémoire pour ses pages (rien ne reste alors). Une pile du
    /// cache d'abord (voir CACHE_PILES) : déjà projetée.
    pub fn allouer() -> Option<Pile> {
        if let Some(p) = CACHE_PILES.verrouiller().pop() {
            return Some(p);
        }
        let case = REGION.verrouiller().piles_libres.pop()?;
        let pile = Pile { case };
        let pml4 = pagination::pml4_noyau();
        let tables = TABLES_NOYAU.verrouiller();
        for v in (pile.bas()..pile.haut()).step_by(PAGE as usize) {
            // Une page qui manque : `pile` est lâchée, Drop rend celles déjà
            // projetées et la case.
            let cadre = pages::allouer(0)?;
            // Les tables existent (initialiser) : rien à allouer ici.
            pagination::projeter(pml4, v, cadre, ECRITURE | pagination::non_executable())
                .expect("table de la zone des piles absente");
        }
        drop(tables);
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
        // Oublier les traductions AVANT de rendre les cadres : sinon une
        // écriture par une traduction restée en cache irait dans un cadre
        // déjà donné à quelqu'un d'autre. Sur TOUS les processeurs
        // (smp::vider_tlb_noyau) : un autre a pu exécuter cette tâche, et
        // garder une traduction de sa pile (les adresses du noyau sont les
        // mêmes dans tous les espaces). Le rendeur (tache.rs) rend les piles
        // interruptions actives, sans verrou : il peut attendre les autres.
        const PAGES: usize = (TAILLE_PILE / PAGE) as usize;
        let (mut adresses, mut cadres) = ([0u64; PAGES], [0u64; PAGES]);
        let mut n = 0;
        let tables = TABLES_NOYAU.verrouiller();
        for v in (self.bas()..self.haut()).step_by(PAGE as usize) {
            if let Some(cadre) = pagination::retirer(pml4, v) {
                adresses[n] = v;
                cadres[n] = cadre;
                n += 1;
            }
        }
        drop(tables);
        crate::smp::vider_tlb_noyau(&adresses[..n]);
        for &c in &cadres[..n] {
            pages::liberer(c, 0);
        }
        REGION.verrouiller().piles_libres.ajouter_dans_la_place(self.case);
    }
}

/// Si `adresse` est dans la garde d'une pile de la zone : laquelle (pour le
/// message d'un débordement, voir pagination::garde_touchee).
pub fn garde_touchee(adresse: u64) -> Option<GardePile> {
    let piles = PILES.load(Ordering::Relaxed) as u64;
    if !(adresse >= DEBUT && adresse < DEBUT + piles * CASE && (adresse - DEBUT) % CASE < PAGE) {
        return None;
    }
    let case = (adresse - DEBUT) / CASE + 1;
    let ist = IST.iter().position(|c| c.load(Ordering::Relaxed) == case);
    let interruptions = INTERRUPTIONS.iter().position(|c| c.load(Ordering::Relaxed) == case);
    Some(match (ist, interruptions) {
        (Some(i), _) => GardePile::Ist { processeur: i / 4, role: ROLES_IST[i % 4] },
        (None, Some(processeur)) => GardePile::Interruptions { processeur },
        (None, None) => GardePile::Tache,
    })
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
    // Une adresse que le processeur ne sait pas former (au-delà de
    // MAXPHYADDR : une table de l'ACPI abîmée, une BAR mal lue) : refusée,
    // comme le `phys_addr_valid` de `__ioremap_caller` (Linux le dit, et
    // rend NULL). La projeter ferait poser des bits réservés dans une
    // entrée de table : une faute à la première lecture.
    if physique >> cpu::bits_physiques() != 0 {
        afficherln!("[noyau] projection refusee : {:#x} est au-dela des {} bits d'adresse physique.", physique, cpu::bits_physiques());
        return None;
    }
    let premiere = physique / PAGE * PAGE;
    let fin = physique.checked_add(longueur.max(1))?.next_multiple_of(PAGE);
    let pages = (fin - premiere) / PAGE;
    // La place des pages, plus une page de garde après elles.
    let debut = prendre_plage(pages + 1)?;
    let mut p = Projection { debut, reservees: pages, projetees: 0, adresse: debut + physique % PAGE };
    let droits = match genre {
        Genre::Registres => ECRITURE | SANS_CACHE | pagination::non_executable(),
        Genre::Tables => pagination::non_executable(),
    };
    let pml4 = pagination::pml4_noyau();
    let tables = TABLES_NOYAU.verrouiller();
    for i in 0..pages {
        // Une table qui manque : `p` est lâchée, Drop retire ce qui est déjà
        // projeté et rend la plage.
        projeter_en_comptant(pml4, debut + i * PAGE, premiere + i * PAGE, droits)?;
        p.projetees += 1;
    }
    drop(tables);
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
        let tables = TABLES_NOYAU.verrouiller();
        for i in 0..self.projetees {
            // Les pages projetées ne sont pas à nous : rien à rendre au buddy.
            let _ = pagination::retirer(pml4, self.debut + i * PAGE);
        }
        drop(tables);
        // Les traductions oubliées par tous les processeurs (voir
        // Pile::drop) : page par page jusqu'à 33, tout le TLB au-delà.
        let mut adresses = [0u64; 33];
        let n = (self.projetees as usize).min(adresses.len());
        for (i, a) in adresses[..n].iter_mut().enumerate() {
            *a = self.debut + i as u64 * PAGE;
        }
        if self.projetees as usize > n {
            crate::smp::vider_tlb(None, None, &[], true);
        } else {
            crate::smp::vider_tlb_noyau(&adresses[..n]);
        }
        // La plage et sa garde reviennent à la liste.
        rendre_plage(self.debut, self.debut + (self.reservees + 1) * PAGE);
    }
}

/// Prend `pages` pages d'adresses (la garde comprise) dans la zone des
/// projections : au début de la première plage libre assez grande (la
/// première qui convient). None : plus de place. N'alloue rien : appelable
/// de partout, comme le tas qui s'en sert.
fn prendre_plage(pages: u64) -> Option<u64> {
    let taille = pages.checked_mul(PAGE)?;
    let mut r = REGION.verrouiller();
    let i = r.plages.iter().position(|&(d, f)| f - d >= taille)?;
    let debut = r.plages[i].0;
    r.plages[i].0 += taille;
    if r.plages[i].0 == r.plages[i].1 {
        r.plages.remove(i);
    }
    Some(debut)
}

/// Rend la plage [debut, fin[ à la liste, recollée à ses voisines. Hors de
/// tout verrou court (la liste peut devoir grandir) : par le rendeur, ou
/// une projection rendue. La liste grandit HORS de son verrou, puis
/// l'échange, comme Linux prépare d'avance le nœud d'une plage
/// (`preload_this_cpu_lock`, mm/vmalloc.c) : la nouvelle liste pourrait
/// elle-même être un grand bloc (`prendre_plage`, qui prend REGION). Sans
/// mémoire pour elle, la plage est perdue : des adresses seulement (la
/// zone en a des centaines de Gio), pas de la mémoire ; et on le dit.
fn rendre_plage(debut: u64, fin: u64) {
    loop {
        let capacite = {
            let mut r = REGION.verrouiller();
            let i = r.plages.partition_point(|&(d, _)| d < debut);
            let colle_avant = i > 0 && r.plages[i - 1].1 == debut;
            let colle_apres = i < r.plages.len() && r.plages[i].0 == fin;
            match (colle_avant, colle_apres) {
                (true, true) => {
                    r.plages[i - 1].1 = r.plages[i].1;
                    r.plages.remove(i);
                    return;
                }
                (true, false) => {
                    r.plages[i - 1].1 = fin;
                    return;
                }
                (false, true) => {
                    r.plages[i].0 = debut;
                    return;
                }
                (false, false) if r.plages.len() < r.plages.capacity() => {
                    r.plages.inserer_dans_la_place(i, (debut, fin));
                    return;
                }
                (false, false) => r.plages.capacity(),
            }
        };
        let Ok(mut neuve) = crate::faillible::avec_capacite::<(u64, u64)>(capacite * 2) else {
            afficherln!("[noyau] vmalloc : plus de memoire pour la liste des plages, {} Kio d'adresses perdus.", (fin - debut) >> 10);
            return;
        };
        // Échangée si personne ne l'a fait grandir entre-temps ; l'ancienne
        // (ou la neuve, inutile) rendue hors du verrou.
        let a_rendre = {
            let mut r = REGION.verrouiller();
            if r.plages.capacity() == capacite {
                for &p in r.plages.iter() {
                    neuve.ajouter_dans_la_place(p);
                }
                core::mem::swap(&mut r.plages, &mut neuve);
            }
            neuve
        };
        drop(a_rendre);
    }
}

// ---------------------------------------------------------------------
// Les grands blocs du tas : vmalloc et vfree (les soldes d'avant 6k).
//
// Jusque-là, un bloc du tas ne dépassait pas 4 Mio (pages::ORDRE_MAX) : un
// programme WebAssembly ne pouvait avoir ni plus de 4 Mio de mémoire, ni un
// module plus gros. Au-delà, le tas (tas.rs) demande ici des pages
// éparses, projetées d'un seul tenant dans la zone des projections, chaque
// bloc suivi d'une page de garde (un débordement y fait faute, au lieu
// d'écrire chez le voisin).
//
// Prendre un bloc ne demande rien aux autres processeurs : des adresses
// qui n'étaient pas projetées n'ont de traduction dans aucun TLB. Le
// rendre, si : chacun peut garder la traduction d'une de ses pages. Linux
// rend les pages AUSSITÔT, sans vider les TLB (`vfree` : seul le réemploi
// des ADRESSES attend un vidage groupé) : il compte sur ce que plus aucun
// code n'y accède, et une traduction restée mène alors à un cadre donné à
// un autre. Nous gardons les cadres jusqu'au vidage, comme nos piles : une
// traduction restée ne mène jamais qu'au bloc d'avant, un écart plus
// strict, au prix de la mémoire du bloc gardée jusqu'au passage du rendeur
// (une milliseconde). Or le tas rend ses blocs de partout, sous un verrou
// court, interruptions coupées, où l'on ne peut pas attendre les autres
// processeurs (smp.rs). Un bloc rendu est donc DIFFÉRÉ, comme par le
// `vfree_atomic` de Linux (qui, lui, diffère tout) : une note,
// écrite dans son premier cadre (le bloc ne sert plus à personne), va dans
// une liste sans verrou, que le rendeur (tache.rs) vide, interruptions
// actives : les pages de tous les blocs de la liste rendues absentes, un
// seul vidage des TLB de tous les processeurs pour tous (Linux rassemble
// de même les siens, `__purge_vmap_area_lazy`), puis leurs cadres et leurs
// adresses rendus. Le tas ne réveille pas le rendeur lui-même : un réveil
// prend les verrous de l'ordonnanceur, qu'un `dealloc` peut tenir ; le tic
// suivant du processeur 0 s'en charge (une milliseconde au plus). Option
// écartée : vider les TLB depuis le tas ; deux processeurs qui rendraient
// chacun un bloc, interruptions coupées, attendraient chacun la réponse de
// l'autre, pour toujours.
//
// Les cadres d'un bloc ne sont notés nulle part ailleurs que dans ses
// entrées de table : chaque entrée est d'abord rendue absente en gardant
// l'adresse de son cadre (pagination::suspendre), relue après le vidage.
// Linux tient un tableau des cadres de chaque bloc (`vm_struct->pages`),
// qu'il faudrait ici allouer... dans le tas qu'on est en train de servir.
//
// Les tables créées pour la zone restent, comme chez Linux : un bloc pris
// plus tard aux mêmes adresses les retrouve. Elles sont comptées
// (`tables_gardees`), et « memoire rendue » (programmes.rs) les compte
// avec les pages libres.

/// Les tables de la zone des projections créées depuis le démarrage, en
/// pages (voir plus haut).
static TABLES_GARDEES: AtomicUsize = AtomicUsize::new(0);

pub fn tables_gardees() -> usize {
    TABLES_GARDEES.load(Ordering::Relaxed)
}

/// Projette la page `virtuelle` de la zone des projections sur `physique`,
/// en comptant les tables créées (TABLES_GARDEES). Sous TABLES_NOYAU :
/// personne d'autre n'en crée pendant ce temps.
fn projeter_en_comptant(pml4: u64, virtuelle: u64, physique: u64, droits: u64) -> Option<()> {
    let manquantes = pagination::tables_manquantes(pml4, virtuelle);
    let r = pagination::projeter(pml4, virtuelle, physique, droits);
    let creees = manquantes - pagination::tables_manquantes(pml4, virtuelle);
    TABLES_GARDEES.fetch_add(creees as usize, Ordering::Relaxed);
    r
}

/// La note d'un bloc différé, écrite dans son premier cadre (vu par la
/// projection directe) : la liste des blocs à rendre passe par elles.
#[derive(Clone, Copy)]
#[repr(C)]
struct Note {
    /// La note suivante (son adresse dans la projection directe), 0 à la
    /// fin.
    suivante: u64,
    debut: u64,
    /// Les pages d'adresses réservées (sans la garde), et celles projetées :
    /// un bloc dont la projection a échoué en chemin n'en a projeté qu'une
    /// partie.
    reservees: u64,
    projetees: u64,
    /// Le cadre de la note : rendu à part s'il n'a pas été projeté.
    cadre: u64,
}

/// Les notes des blocs à rendre (l'adresse de la première, 0 : aucune) :
/// une pile sans verrou, où l'on ne fait qu'empiler, et que le rendeur
/// prend tout entière (`swap`). Sans retrait d'un seul élément, pas de
/// problème ABA.
static A_RENDRE: AtomicU64 = AtomicU64::new(0);
/// Les blocs différés pas encore tout à fait rendus (dans la liste, ou en
/// train de l'être) : « memoire rendue » attend qu'il soit nul.
static EN_ATTENTE: AtomicUsize = AtomicUsize::new(0);

/// Vrai si des blocs attendent le rendeur (le tic du processeur 0 le
/// réveille alors, tache.rs).
pub fn a_rendre() -> bool {
    A_RENDRE.load(Ordering::Relaxed) != 0
}

/// Les blocs différés pas encore rendus.
pub fn en_attente() -> usize {
    EN_ATTENTE.load(Ordering::Acquire)
}

/// Empile la note `note` (dans son cadre, `note.cadre`).
fn differer(note: Note) {
    EN_ATTENTE.fetch_add(1, Ordering::Relaxed);
    let adresse = espace::virtuelle(note.cadre);
    let mut tete = A_RENDRE.load(Ordering::Relaxed);
    loop {
        // SAFETY: le cadre de la note est à nous : le premier d'un bloc que
        // personne n'utilise plus (ou jamais projeté), vu par la projection
        // directe, aligné sur sa page.
        unsafe { (adresse as *mut Note).write(Note { suivante: tete, ..note }) };
        // Release : la note écrite avant que le rendeur la voie.
        match A_RENDRE.compare_exchange_weak(tete, adresse, Ordering::Release, Ordering::Relaxed) {
            Ok(_) => return,
            Err(t) => tete = t,
        }
    }
}

/// La note d'adresse `adresse` (une copie).
fn lire_note(adresse: u64) -> Note {
    // SAFETY: une note écrite par `differer`, dans un cadre que seul le
    // rendeur rendra, après l'avoir lue.
    unsafe { (adresse as *const Note).read() }
}

/// Un grand bloc du tas : `taille` octets en pages éparses, projetées d'un
/// seul tenant, suivies d'une page de garde (le `vmalloc` de Linux). Aligné
/// sur une page : un alignement plus grand est refusé (personne ne le
/// demande ; un bloc du buddy, aligné sur sa taille, le donne jusqu'à
/// 4 Mio). Null : plus de mémoire, ou plus d'adresses ; rien ne reste alors
/// (les pages déjà projetées passent par le rendeur, comme un bloc
/// rendu). Appelable de partout, comme le tas : rien n'y attend.
pub fn allouer(taille: usize, alignement: usize) -> *mut u8 {
    if alignement > PAGE as usize || taille == 0 {
        return null_mut();
    }
    let pages = (taille as u64).div_ceil(PAGE);
    // Plus que la mémoire : refusé d'emblée, comme Linux (`totalram_pages`,
    // `__vmalloc_node_range`) ; et plus que ce qui est libre aussi : le
    // prendre cadre par cadre jusqu'à l'échec viderait toute la mémoire,
    // réserve du noyau comprise, jusqu'au passage du rendeur (Linux rend
    // aussitôt ce qu'il avait pris ; nous, au vidage).
    if pages > pages::total() as u64 || pages > pages::libres() as u64 {
        return null_mut();
    }
    // Le premier cadre avant les adresses : s'il manque, rien n'est pris.
    // Il porte la note du bloc si la projection échoue en chemin.
    let Some(premier) = pages::allouer(0) else { return null_mut() };
    let Some(debut) = prendre_plage(pages + 1) else {
        pages::liberer(premier, 0);
        return null_mut();
    };
    let pml4 = pagination::pml4_noyau();
    let droits = ECRITURE | pagination::non_executable();
    let mut projetees = 0;
    while projetees < pages {
        let cadre = match projetees {
            0 => premier,
            _ => match pages::allouer(0) {
                Some(c) => c,
                None => break,
            },
        };
        // Le verrou des tables page par page : tenu pour toute une
        // projection de plusieurs Mio, il couperait les interruptions des
        // millisecondes.
        let tables = TABLES_NOYAU.verrouiller();
        let projetee = projeter_en_comptant(pml4, debut + projetees * PAGE, cadre, droits).is_some();
        drop(tables);
        if !projetee {
            // Une table qui manque : ce cadre n'a jamais été projeté, rendu
            // tout de suite (sauf le premier, qui porte la note).
            if projetees > 0 {
                pages::liberer(cadre, 0);
            }
            break;
        }
        projetees += 1;
    }
    if projetees < pages {
        differer(Note { suivante: 0, debut, reservees: pages, projetees, cadre: premier });
        return null_mut();
    }
    debut as *mut u8
}

/// Vrai si `adresse` est dans la région : pour le tas, un grand bloc (il
/// ne reçoit jamais d'autres adresses de la région).
pub fn contient(adresse: u64) -> bool {
    (DEBUT..DEBUT + TAILLE).contains(&adresse)
}

/// Rend le grand bloc `debut`, de `taille` octets : différé (voir plus
/// haut). Appelable de partout, comme le tas.
///
/// # Safety
/// Le bloc vient d'`allouer`, avec cette taille, et ne sert plus.
pub unsafe fn rendre(debut: u64, taille: usize) {
    let pages = (taille as u64).div_ceil(PAGE);
    let tables = TABLES_NOYAU.verrouiller();
    let premier = pagination::traduire(pagination::pml4_noyau(), debut);
    drop(tables);
    let premier = premier.expect("grand bloc du tas sans sa premiere page");
    differer(Note { suivante: 0, debut, reservees: pages, projetees: pages, cadre: premier });
}

/// Rend les grands blocs différés : leurs pages absentes, un seul vidage
/// des TLB de tous les processeurs, puis leurs cadres et leurs adresses.
/// Par le rendeur (tache.rs) ; au démarrage, par son test. Interruptions
/// actives et aucun verrou court tenu, si d'autres processeurs sont en
/// service (le vidage les attend). Vrai si un bloc a été rendu.
pub fn purger() -> bool {
    // Acquire : les notes écrites avant d'être empilées.
    let premiere = A_RENDRE.swap(0, Ordering::Acquire);
    if premiere == 0 {
        return false;
    }
    let pml4 = pagination::pml4_noyau();
    // 1. Chaque page absente, l'adresse de son cadre gardée dans son entrée.
    let mut n = premiere;
    while n != 0 {
        let note = lire_note(n);
        for i in 0..note.projetees {
            let tables = TABLES_NOYAU.verrouiller();
            pagination::suspendre(pml4, note.debut + i * PAGE);
            drop(tables);
        }
        n = note.suivante;
    }
    // 2. Un seul vidage, de tout le TLB (Linux aussi, au-delà de 33 pages).
    crate::smp::vider_tlb(None, None, &[], true);
    // 3. Les cadres, relus dans les entrées, puis les adresses.
    let mut n = premiere;
    while n != 0 {
        // Une copie : son cadre est rendu avec les autres.
        let note = lire_note(n);
        for i in 0..note.projetees {
            let tables = TABLES_NOYAU.verrouiller();
            let cadre = pagination::oublier_suspendue(pml4, note.debut + i * PAGE);
            drop(tables);
            pages::liberer(cadre.expect("page d'un grand bloc rendu sans cadre"), 0);
        }
        if note.projetees == 0 {
            pages::liberer(note.cadre, 0);
        }
        rendre_plage(note.debut, note.debut + (note.reservees + 1) * PAGE);
        EN_ATTENTE.fetch_sub(1, Ordering::Release);
        n = note.suivante;
    }
    true
}
