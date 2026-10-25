//! Le tas du noyau : les allocations de toutes tailles, celles de `Box`,
//! `Vec` et `String` (la bibliothèque `alloc` de Rust appelle notre
//! allocateur pour chacune).
//!
//! L'allocateur de pages ne donne que des blocs de 4 Kio ou plus ; la
//! plupart des allocations sont bien plus petites. Comme SLUB, l'allocateur
//! de Linux (mm/slub.c), on range les petites par CLASSES de taille :
//! 16, 32, 64... jusqu'à 2048 octets. Chaque classe découpe des pages en
//! objets de sa taille, et garde la liste de ses objets libres, chaînés à
//! travers eux-mêmes (un objet libre contient l'adresse du suivant).
//! Allouer : prendre le premier de la liste (et, si elle est vide, découper
//! une nouvelle page). Libérer : le remettre en tête. Les deux en temps
//! constant, sans chercher. Au-delà de 2048 octets, l'allocation prend
//! directement un bloc de pages.
//!
//! Ce qui est plus simple que dans SLUB :
//!   - aucune description par objet ni par page : Rust donne la taille de
//!     l'objet à la libération (le `Layout`), d'où l'on retrouve sa classe.
//!     Linux, dont kfree ne connaît que l'adresse, doit la chercher dans la
//!     struct page ;
//!   - une page découpée pour une classe y reste, même vide : SLUB compte
//!     les objets de chaque page pour rendre les pages vides à l'allocateur
//!     de pages ;
//!   - une seule liste, sous un seul verrou : SLUB en a une par processeur,
//!     pour ne pas se disputer le verrou (on n'a qu'un processeur).
//!
//! Un seul bloc ne dépasse pas 4 Mio (pages::ORDRE_MAX) : au-delà, une
//! allocation échoue. `try_reserve` le dit proprement (memory.grow d'un
//! programme WebAssembly rend alors -1) ; une allocation ordinaire, elle,
//! fait paniquer le noyau. Pour aller plus loin, il faudra projeter des
//! pages éparses d'un seul tenant dans l'espace virtuel (vmalloc dans
//! Linux).

use crate::verrou::Verrou;
use crate::{espace, pages};
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
        // SAFETY : `objet` est un objet libre de la classe, qui contient
        // l'adresse du suivant.
        self.libres[c] = unsafe { *(objet as *const usize) };
        objet as *mut u8
    }

    /// # Safety
    /// `objet` doit avoir été alloué dans la classe `c`, et n'être plus
    /// utilisé.
    unsafe fn liberer(&mut self, c: usize, objet: *mut u8) {
        // SAFETY : garanti par l'appelant ; l'objet fait au moins 16
        // octets, assez pour l'adresse du suivant.
        unsafe { *(objet as *mut usize) = self.libres[c] };
        self.libres[c] = objet as usize;
    }

    /// Découpe une nouvelle page en objets libres de la classe `c`.
    fn decouper(&mut self, c: usize) -> bool {
        let Some(page) = pages::allouer(0) else { return false };
        let debut = espace::virtuelle(page) as usize;
        // À l'envers, pour que la liste les donne ensuite dans l'ordre.
        for objet in (debut..debut + PAGE).step_by(PLUS_PETITE << c).rev() {
            // SAFETY : la page vient d'être allouée, ses objets sont à nous.
            unsafe { self.liberer(c, objet as *mut u8) };
        }
        true
    }
}

// SAFETY : les blocs rendus sont à nous jusqu'à leur libération, alignés
// comme demandé (voir `classe` et `ordre`), et le verrou empêche deux
// allocations de se croiser, même depuis une interruption.
unsafe impl GlobalAlloc for Allocateur {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match classe(layout) {
            Some(c) => TAS.verrouiller().allouer(c),
            None if ordre(layout) > pages::ORDRE_MAX => null_mut(),
            None => pages::allouer(ordre(layout)).map_or(null_mut(), |p| espace::virtuelle(p) as *mut u8),
        }
    }

    unsafe fn dealloc(&self, objet: *mut u8, layout: Layout) {
        match classe(layout) {
            // SAFETY : `objet` vient de `alloc` avec ce `layout` (contrat de
            // GlobalAlloc), donc de cette classe.
            Some(c) => unsafe { TAS.verrouiller().liberer(c, objet) },
            None => pages::liberer(espace::physique(objet as u64), ordre(layout)),
        }
    }
}
