//! Le tas du noyau : les allocations de toutes tailles, celles de `Box`,
//! `Vec` et `String` (la bibliothèque `alloc` de Rust appelle notre
//! allocateur pour chacune).
//!
//! L'allocateur de pages ne donne que des blocs de 4 Kio ou plus ; la
//! plupart des allocations sont bien plus petites. Comme SLUB, l'allocateur
//! de Linux (mm/slub.c), on range les petites par CLASSES de taille :
//! 16, 32, 64... jusqu'à 2048 octets. Chaque classe découpe des pages en
//! objets de sa taille, et garde la liste de ses objets libres, chaînés à
//! travers eux-mêmes (un objet libre contient l'adresse du suivant et du
//! précédent). Allouer : prendre le premier de la liste (et, si elle est
//! vide, découper une nouvelle page). Libérer : le remettre en tête. Les
//! deux en temps constant, sans chercher. Au-delà de 2048 octets,
//! l'allocation prend directement un bloc de pages.
//!
//! Une page VIDE retourne à l'allocateur de pages (6b) : le descripteur de
//! chaque cadre (pages.rs) compte les objets occupés de la page, comme le
//! `inuse` du slab de Linux. Quand le dernier est rendu, tous les objets de
//! la page sont dans la liste de la classe ; la liste est doublement
//! chaînée, on les en retire donc chacun en temps constant (on connaît
//! leurs adresses : la page découpée à la taille de la classe), et la page
//! est rendue. Sans cela, la mémoire prise un jour par une classe ne
//! revenait jamais : un programme qui crée cent fichiers puis les efface
//! (des noms de quelques octets, des entrées de dossier) laissait derrière
//! lui des pages qui ne servaient plus, et la vérification « memoire
//! rendue » de chaque programme ne pouvait plus rien dire.
//!
//! Ce qui est plus simple que dans SLUB :
//!   - aucune description par objet : Rust donne la taille de l'objet à la
//!     libération (le `Layout`), d'où l'on retrouve sa classe. Linux, dont
//!     kfree ne connaît que l'adresse, doit la chercher dans la struct page ;
//!   - une seule liste d'objets libres par classe, au lieu d'une par page :
//!     SLUB sert les objets page par page, pour qu'ils restent groupés (et
//!     que les pages se vident plus souvent) ; ici une page ne se vide que
//!     si tous ses objets sont rendus, dans n'importe quel ordre ;
//!   - aucune page vide gardée en réserve : SLUB en garde quelques-unes par
//!     classe (`min_partial`), pour ne pas rendre puis reprendre sans cesse
//!     une page au buddy. Rendre tout de suite coûte de redécouper une page
//!     de temps en temps, et garde exact le compte de la mémoire ;
//!   - un seul verrou : SLUB a des listes par processeur (les `cpu_slab`),
//!     pour ne pas se disputer le verrou. Mesuré en 6j, sur quatre
//!     processeurs, pendant `claude -p` (`make verrous-claude-p`) : le
//!     verrou du tas n'est pas parmi les seize endroits les plus attendus
//!     (moins de cinq attentes par lancement, quand le verrou des tables de
//!     pages en compte 700). Un cache par processeur devant lui quand une
//!     mesure le demandera.
//!
//! Les GRANDS BLOCS (les soldes d'avant 6k) : l'allocateur de pages ne
//! donne pas plus de 4 Mio d'un seul tenant (pages::ORDRE_MAX). Au-delà, le
//! tas prend des pages éparses, projetées d'un seul tenant dans la région
//! des adresses à la demande (vmalloc.rs) ; jusque-là, l'allocation
//! échouait (memory.grow d'un programme WebAssembly rendait -1 à 4 Mio). Et
//! de même en secours, quand l'allocateur de pages n'a plus de bloc d'un
//! seul tenant de la taille voulue (la mémoire morcelée), comme le
//! `kvmalloc` de Linux : un bloc de pages d'abord (plus rapide à prendre et
//! à rendre, sans vidage des TLB), des pages éparses s'il manque. Linux
//! laisse ce choix à chaque appelant (kmalloc ou kvmalloc), parce que
//! certains donnent leur mémoire à un périphérique (le DMA), qui la veut
//! d'un seul tenant en mémoire physique ; ici, aucune mémoire du tas ne va
//! à un périphérique (les tampons de virtio sont des pages, virtio_net.rs),
//! tout le tas peut donc s'en servir. Rien en secours pour une seule page :
//! s'il n'y en a plus une, il n'y en a pas plusieurs éparses non plus. Un
//! bloc est rendu à vmalloc.rs ou à l'allocateur de pages selon son
//! adresse (Linux : `kvfree`, par `is_vmalloc_addr`).

use crate::verrou::Verrou;
use crate::{espace, pages, vmalloc};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

const PLUS_PETITE: usize = 16;
const CLASSES: usize = 8;
/// 16 << 7 = 2048 octets.
const PLUS_GRANDE: usize = PLUS_PETITE << (CLASSES - 1);
const PAGE: usize = 4096;

struct Tas {
    /// Pour chaque classe, le premier objet libre (adresse virtuelle), 0
    /// si la liste est vide.
    libres: [usize; CLASSES],
}

/// Les liens d'un objet libre dans la liste de sa classe, rangés au début de
/// l'objet (16 octets : la plus petite classe).
#[repr(C)]
struct Liens {
    suivant: usize,
    precedent: usize,
}

/// Les liens de l'objet libre `objet`.
///
/// # Safety
/// `objet` doit être un objet libre du tas (personne d'autre ne s'en sert),
/// d'au moins 16 octets, aligné sur 8.
unsafe fn liens(objet: usize) -> &'static mut Liens {
    // SAFETY: garanti par l'appelant.
    unsafe { &mut *(objet as *mut Liens) }
}

/// La page (adresse physique) qui contient l'objet `objet`.
fn page_de(objet: usize) -> u64 {
    espace::physique((objet & !(PAGE - 1)) as u64)
}

static TAS: Verrou<Tas> = Verrou::new(Tas { libres: [0; CLASSES] });

/// L'allocateur de Rust, branché sur notre tas.
struct Allocateur;

#[global_allocator]
static ALLOCATEUR: Allocateur = Allocateur;

/// La classe d'une allocation, ou None si elle prend directement des
/// pages. Une classe est une puissance de deux qui divise 4096 : ses objets,
/// découpés dans une page alignée sur 4096, sont alignés sur leur taille.
/// On choisit donc la classe sur la taille ET l'alignement demandés.
fn classe(layout: Layout) -> Option<usize> {
    let taille = layout.size().max(layout.align()).max(PLUS_PETITE);
    (taille <= PLUS_GRANDE).then(|| (taille.next_power_of_two() / PLUS_PETITE).trailing_zeros() as usize)
}

/// L'ordre du bloc de pages d'une grande allocation (aligné sur sa taille,
/// donc sur tout alignement plus petit).
fn ordre(layout: Layout) -> u32 {
    let pages = layout.size().max(layout.align()).div_ceil(PAGE);
    pages.next_power_of_two().trailing_zeros()
}

impl Tas {
    fn allouer(&mut self, c: usize) -> *mut u8 {
        if self.libres[c] == 0 && !self.decouper(c) {
            return null_mut();
        }
        let objet = self.libres[c];
        // SAFETY: `objet` est le premier objet libre de la classe.
        unsafe { self.retirer(c, objet) };
        pages::compter_objets(page_de(objet), true);
        objet as *mut u8
    }

    /// # Safety
    /// `objet` doit avoir été alloué dans la classe `c`, et n'être plus
    /// utilisé.
    unsafe fn liberer(&mut self, c: usize, objet: *mut u8) {
        let objet = objet as usize;
        // SAFETY: garanti par l'appelant.
        unsafe { self.inserer(c, objet) };
        let page = page_de(objet);
        if pages::compter_objets(page, false) == 0 {
            // La page est vide : tous ses objets sont dans la liste. On les
            // en retire, et la page retourne à l'allocateur de pages.
            let debut = objet & !(PAGE - 1);
            for o in (debut..debut + PAGE).step_by(PLUS_PETITE << c) {
                // SAFETY: un objet de la page vide, donc libre.
                unsafe { self.retirer(c, o) };
            }
            pages::liberer(page, 0);
        }
    }

    /// Met `objet` en tête de la liste de la classe `c`.
    ///
    /// # Safety
    /// `objet` doit être un objet de la classe `c` que personne n'utilise,
    /// hors de la liste.
    unsafe fn inserer(&mut self, c: usize, objet: usize) {
        let tete = self.libres[c];
        // SAFETY: `objet` est libre (l'appelant), `tete` aussi.
        unsafe {
            *liens(objet) = Liens { suivant: tete, precedent: 0 };
            if tete != 0 {
                liens(tete).precedent = objet;
            }
        }
        self.libres[c] = objet;
    }

    /// Retire `objet` de la liste de la classe `c`.
    ///
    /// # Safety
    /// `objet` doit être dans cette liste.
    unsafe fn retirer(&mut self, c: usize, objet: usize) {
        // SAFETY: `objet` et ses voisins sont des objets libres de la liste.
        unsafe {
            let Liens { suivant, precedent } = *liens(objet);
            if precedent == 0 {
                self.libres[c] = suivant;
            } else {
                liens(precedent).suivant = suivant;
            }
            if suivant != 0 {
                liens(suivant).precedent = precedent;
            }
        }
    }

    /// Découpe une nouvelle page en objets libres de la classe `c`. Aucun
    /// n'est encore occupé.
    fn decouper(&mut self, c: usize) -> bool {
        let Some(page) = pages::allouer(0) else { return false };
        let debut = espace::virtuelle(page) as usize;
        // À l'envers, pour que la liste les donne ensuite dans l'ordre.
        for objet in (debut..debut + PAGE).step_by(PLUS_PETITE << c).rev() {
            // SAFETY: la page vient d'être allouée, ses objets sont à nous.
            unsafe { self.inserer(c, objet) };
        }
        true
    }
}

// SAFETY: les blocs rendus sont à nous jusqu'à leur libération, alignés
// comme demandé (voir `classe`, `ordre`, et vmalloc::allouer, qui refuse
// plus d'une page d'alignement), et les verrous empêchent deux allocations
// de se croiser, même depuis une interruption.
unsafe impl GlobalAlloc for Allocateur {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(c) = classe(layout) else {
            let ordre = ordre(layout);
            if ordre <= pages::ORDRE_MAX
                && let Some(p) = pages::allouer(ordre)
            {
                return espace::virtuelle(p) as *mut u8;
            }
            // Plus de 4 Mio, ou plus de bloc de cet ordre (voir l'en-tête).
            return if ordre == 0 { null_mut() } else { vmalloc::allouer(layout.size(), layout.align()) };
        };
        TAS.verrouiller().allouer(c)
    }

    unsafe fn dealloc(&self, objet: *mut u8, layout: Layout) {
        if vmalloc::contient(objet as u64) {
            // SAFETY: un grand bloc, de vmalloc::allouer avec cette taille
            // (contrat de GlobalAlloc), que l'appelant n'utilise plus.
            return unsafe { vmalloc::rendre(objet as u64, layout.size()) };
        }
        match classe(layout) {
            // SAFETY: `objet` vient de `alloc` avec ce `layout` (contrat de
            // GlobalAlloc), donc de cette classe.
            Some(c) => unsafe { TAS.verrouiller().liberer(c, objet) },
            None => pages::liberer(espace::physique(objet as u64), ordre(layout)),
        }
    }
}
