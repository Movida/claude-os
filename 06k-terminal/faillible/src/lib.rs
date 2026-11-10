//! Les allocations qui peuvent échouer : celles du noyau, toutes, et
//! celles de ses bibliothèques (les soldes d'avant 6k : jusque-là, ce
//! module était dans le noyau, et les bibliothèques allouaient comme un
//! programme ordinaire, alors qu'un client du dehors ou un programme peut
//! les faire allouer dans le noyau). Une bibliothèque à part, sans rien
//! d'autre que `alloc`, que le noyau et chacune d'elles utilisent ; son seul
//! `unsafe` (`boite_vide`) est permis ici, et nulle part ailleurs dans les
//! bibliothèques.
//!
//! Les collections de Rust (`Vec`, `Box`, `String`) supposent qu'une
//! allocation réussit toujours : `push`, `Box::new` ou `format!`, quand
//! le tas ne peut plus rien donner, appellent `handle_alloc_error`, qui
//! dans un noyau sans bibliothèque standard fait paniquer. Pour un
//! programme ordinaire, c'est raisonnable (Linux tuera de toute façon le
//! processus). Pour un noyau, c'est la machine entière qui s'arrête, et la
//! cause peut venir d'un programme qui demande trop, ou, depuis TCP (6h),
//! d'un client du dehors qui ouvre des connexions. Linux, en C, vérifie
//! chaque `kmalloc` ; Rust pour Linux a retiré toutes les allocations qui
//! paniquent. Ici de même : chaque allocation du noyau rend un `Result`,
//! et l'appelant décide (ENOMEM pour un appel système, un paquet jeté
//! pour le réseau, une panique au démarrage, quand la machine est neuve
//! et qu'un échec dit qu'elle ne peut pas servir). `cargo clippy` le fait
//! respecter : `clippy.toml` refuse les méthodes qui paniquent, et ce
//! module en donne les équivalents (choix de conception).
//!
//! Ce qui est retenu : de petites fonctions au-dessus de ce que Rust
//! stable sait déjà faire sans paniquer, `Vec::try_reserve` (qui rend une
//! erreur au lieu de paniquer) et `alloc::alloc::alloc` (qui rend un
//! pointeur nul) ; `Arc`, lui, est le nôtre (partage.rs), Rust stable
//! n'en ayant pas de faillible. Options écartées :
//!   - compiler `alloc` avec `no_global_oom_handling`, ce qui retire
//!     carrément les méthodes qui paniquent (ce que faisait Rust pour
//!     Linux au début) : il faut recompiler `alloc` (`-Z build-std`),
//!     donc un compilateur de développement (nightly), contraire au
//!     compilateur figé de `rust-toolchain.toml` ;
//!   - `Box::try_new`, `Arc::try_new`, `Vec::push_within_capacity` :
//!     instables (`allocator_api`), refusés par notre compilateur (1.99.1,
//!     essayé) ;
//!   - faire que les petites allocations n'échouent jamais, comme le
//!     « trop petit pour échouer » de Linux : un `kmalloc` de moins de
//!     huit pages attend que le noyau récupère de la mémoire (vider des
//!     caches, écrire des pages sur le disque, tuer un processus). Nous
//!     n'avons rien à récupérer (ni disque, ni cache qu'on puisse vider) ;
//!     et même Linux vérifie chaque retour, l'attente pouvant échouer ;
//!   - une revue à la main, sans outil : elle se relâcherait au premier
//!     oubli.
//!
//! Ce que `clippy.toml` ne peut pas voir : `clone()` d'un `Vec` ou d'une
//! structure qui en contient (le même nom que celui, sans allocation, de
//! `Arc::clone`) ; le noyau n'en fait aucun, et une relecture doit y
//! veiller.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::alloc::{Layout, alloc};
use alloc::boxed::Box;
use alloc::collections::{TryReserveError, VecDeque};
use alloc::vec::Vec;
use core::mem::{MaybeUninit, size_of};

/// Le tas n'a pas pu donner la mémoire demandée.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlusDeMemoire;

impl From<TryReserveError> for PlusDeMemoire {
    fn from(_: TryReserveError) -> Self {
        PlusDeMemoire
    }
}

/// `Box::new(valeur)`, sans paniquer. `valeur` est lâchée si le tas est
/// plein : pour la garder (et la rendre à son propriétaire), allouer
/// d'abord la place avec `boite_vide`.
pub fn boite<T>(valeur: T) -> Result<Box<T>, PlusDeMemoire> {
    Ok(Box::write(boite_vide()?, valeur))
}

/// La place d'une valeur dans le tas, pas encore écrite (`Box::new_uninit`),
/// sans paniquer : on alloue avant de construire, et un échec laisse
/// intactes les ressources qui auraient dû y entrer (`Box::write` y range
/// ensuite la valeur, sans pouvoir échouer).
#[allow(unsafe_code)]
pub fn boite_vide<T>() -> Result<Box<MaybeUninit<T>>, PlusDeMemoire> {
    let layout = Layout::new::<MaybeUninit<T>>();
    if size_of::<T>() == 0 {
        // Un type sans taille ne prend rien au tas : new_uninit ne peut pas
        // échouer (il ne demande rien à l'allocateur).
        #[allow(clippy::disallowed_methods)]
        return Ok(Box::new_uninit());
    }
    // SAFETY: la taille n'est pas nulle (le seul cas interdit à alloc).
    let p = unsafe { alloc(layout) } as *mut MaybeUninit<T>;
    if p.is_null() {
        return Err(PlusDeMemoire);
    }
    // SAFETY: `p` vient d'être alloué par l'allocateur global avec le
    // Layout de son type : la documentation de Box le permet (« memory
    // layout », alloc::boxed). Un MaybeUninit n'a pas besoin d'être écrit.
    Ok(unsafe { Box::from_raw(p) })
}

/// Une copie de `tranche` dans un `Vec` neuf, à sa taille exacte
/// (`to_vec`), sans paniquer.
pub fn copie<T: Clone>(tranche: &[T]) -> Result<Vec<T>, PlusDeMemoire> {
    let mut v = Vec::new();
    v.try_reserve_exact(tranche.len())?;
    v.ajouter_tranche(tranche)?;
    Ok(v)
}

/// `n` copies de `valeur` dans un `Vec` neuf, à sa taille exacte
/// (`vec![valeur; n]`), sans paniquer.
pub fn remplie<T: Clone>(n: usize, valeur: T) -> Result<Vec<T>, PlusDeMemoire> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)?;
    v.redimensionner(n, valeur)?;
    Ok(v)
}

/// Les morceaux mis bout à bout dans un `Vec` neuf, à sa taille exacte
/// (un nom comme « pipe:[12] »), sans paniquer.
pub fn concatenation<T: Clone>(morceaux: &[&[T]]) -> Result<Vec<T>, PlusDeMemoire> {
    let mut v = Vec::new();
    v.try_reserve_exact(morceaux.iter().map(|m| m.len()).sum())?;
    for m in morceaux {
        v.ajouter_tranche(m)?;
    }
    Ok(v)
}

/// Une copie de `tranche` dans une `Box<[T]>` (`Box::from`), sans
/// paniquer.
pub fn boite_de_tranche<T: Clone>(tranche: &[T]) -> Result<Box<[T]>, PlusDeMemoire> {
    // La copie est à sa taille exacte : into_boxed_slice n'a rien à
    // réallouer (il ne le fait que pour rendre une place en trop).
    #[allow(clippy::disallowed_methods)]
    Ok(copie(tranche)?.into_boxed_slice())
}

/// Un `Vec` vide qui a déjà la place de `n` éléments
/// (`Vec::with_capacity`), sans paniquer.
pub fn avec_capacite<T>(n: usize) -> Result<Vec<T>, PlusDeMemoire> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)?;
    Ok(v)
}

/// Les méthodes de `Vec` qui allouent, sans paniquer. Chacune réserve
/// d'abord la place (`try_reserve`, qui grandit comme `push` : en
/// doublant), puis appelle la méthode de Rust, qui ne peut alors plus
/// allouer. Après un `try_reserve_exact` du bon nombre, elles n'allouent
/// rien (la place est déjà là) : la réservation exacte reste le moyen de
/// ne prendre que ce qu'il faut.
pub trait VecFaillible<T> {
    /// `push`.
    fn ajouter(&mut self, valeur: T) -> Result<(), PlusDeMemoire>;
    /// `push`, mais la valeur est rendue si le tas est plein, au lieu
    /// d'être lâchée (pour la rendre à qui la possède).
    fn ajouter_ou_rendre(&mut self, valeur: T) -> Result<(), T>;
    /// `extend_from_slice`.
    fn ajouter_tranche(&mut self, tranche: &[T]) -> Result<(), PlusDeMemoire>
    where
        T: Clone;
    /// `extend` : tous les éléments d'un itérateur. En cas d'échec, ceux
    /// qui ont déjà été ajoutés le restent.
    fn ajouter_tout(&mut self, elements: impl IntoIterator<Item = T>) -> Result<(), PlusDeMemoire>;
    /// `insert`.
    fn inserer(&mut self, indice: usize, valeur: T) -> Result<(), PlusDeMemoire>;
    /// `resize` : rallonge avec des copies de `valeur`, ou raccourcit.
    fn redimensionner(&mut self, longueur: usize, valeur: T) -> Result<(), PlusDeMemoire>
    where
        T: Clone;
    /// `push` dans la place déjà réservée, sans jamais allouer : pour
    /// ce qui ne doit plus échouer (la place prise avant de rien changer),
    /// ou un contexte où le tas est interdit (l'ordonnanceur, la file de
    /// `lo`), la place prise au démarrage. Une place qui manque est une
    /// erreur de programmation, pas un manque de mémoire : panique, comme
    /// un indice hors des bornes. (Rust a `push_within_capacity`, instable,
    /// qui rend la valeur.)
    #[track_caller]
    fn ajouter_dans_la_place(&mut self, valeur: T);
}

// Les méthodes de Vec appelées ici ne peuvent plus allouer : la place est
// réservée juste avant (d'où l'exception à clippy.toml, le seul endroit
// du noyau qui en ait besoin, avec le test du tas au démarrage).
#[allow(clippy::disallowed_methods)]
impl<T> VecFaillible<T> for Vec<T> {
    fn ajouter(&mut self, valeur: T) -> Result<(), PlusDeMemoire> {
        self.try_reserve(1)?;
        self.push(valeur);
        Ok(())
    }

    fn ajouter_ou_rendre(&mut self, valeur: T) -> Result<(), T> {
        if self.try_reserve(1).is_err() {
            return Err(valeur);
        }
        self.push(valeur);
        Ok(())
    }

    fn ajouter_tranche(&mut self, tranche: &[T]) -> Result<(), PlusDeMemoire>
    where
        T: Clone,
    {
        self.try_reserve(tranche.len())?;
        self.extend_from_slice(tranche);
        Ok(())
    }

    fn ajouter_tout(&mut self, elements: impl IntoIterator<Item = T>) -> Result<(), PlusDeMemoire> {
        let elements = elements.into_iter();
        // La borne basse de l'itérateur d'un coup (une seule allocation pour
        // un itérateur de taille connue), puis un à un.
        self.try_reserve(elements.size_hint().0)?;
        for e in elements {
            self.ajouter(e)?;
        }
        Ok(())
    }

    fn inserer(&mut self, indice: usize, valeur: T) -> Result<(), PlusDeMemoire> {
        self.try_reserve(1)?;
        self.insert(indice, valeur);
        Ok(())
    }

    fn redimensionner(&mut self, longueur: usize, valeur: T) -> Result<(), PlusDeMemoire>
    where
        T: Clone,
    {
        self.try_reserve(longueur.saturating_sub(self.len()))?;
        self.resize(longueur, valeur);
        Ok(())
    }

    fn ajouter_dans_la_place(&mut self, valeur: T) {
        assert!(self.len() < self.capacity(), "Vec sans la place reservee");
        self.push(valeur);
    }
}

/// Les méthodes de `VecDeque` qui allouent, sans paniquer (comme
/// `VecFaillible`).
pub trait FileFaillible<T> {
    /// `push_back`.
    fn ajouter_derriere(&mut self, valeur: T) -> Result<(), PlusDeMemoire>;
    /// `push_back` dans la place déjà réservée (voir
    /// `VecFaillible::ajouter_dans_la_place`).
    #[track_caller]
    fn ajouter_derriere_dans_la_place(&mut self, valeur: T);
    /// `push_front` dans la place déjà réservée.
    #[track_caller]
    fn ajouter_devant_dans_la_place(&mut self, valeur: T);
    /// `insert` à la place `i` dans la place déjà réservée.
    #[track_caller]
    fn inserer_dans_la_place(&mut self, i: usize, valeur: T);
    /// `append` (tous les éléments de `autre`, au bout) dans la place déjà
    /// réservée.
    #[track_caller]
    fn deplacer_dans_la_place(&mut self, autre: &mut VecDeque<T>);
}

// Voir VecFaillible : la place est réservée juste avant.
#[allow(clippy::disallowed_methods)]
impl<T> FileFaillible<T> for VecDeque<T> {
    fn ajouter_derriere(&mut self, valeur: T) -> Result<(), PlusDeMemoire> {
        self.try_reserve(1)?;
        self.push_back(valeur);
        Ok(())
    }

    fn ajouter_derriere_dans_la_place(&mut self, valeur: T) {
        assert!(self.len() < self.capacity(), "VecDeque sans la place reservee");
        self.push_back(valeur);
    }

    fn ajouter_devant_dans_la_place(&mut self, valeur: T) {
        assert!(self.len() < self.capacity(), "VecDeque sans la place reservee");
        self.push_front(valeur);
    }

    fn inserer_dans_la_place(&mut self, i: usize, valeur: T) {
        assert!(self.len() < self.capacity(), "VecDeque sans la place reservee");
        self.insert(i, valeur);
    }

    fn deplacer_dans_la_place(&mut self, autre: &mut VecDeque<T>) {
        assert!(self.len() + autre.len() <= self.capacity(), "VecDeque sans la place reservee");
        self.append(autre);
    }
}
