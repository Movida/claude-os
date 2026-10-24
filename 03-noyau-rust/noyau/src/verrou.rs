//! Un verrou à attente active (« spinlock »), écrit à la main.
//!
//! Pourquoi un verrou dans un noyau qui n'a qu'un seul fil d'exécution ?
//! Parce que Rust refuse, à juste titre, une variable globale modifiable
//! sans protection : dès qu'il y aura des interruptions (sous-étape 3) ou
//! plusieurs processeurs, deux morceaux de code pourront y écrire en même
//! temps. Le verrou garantit qu'un seul à la fois y accède.
//!
//! Principe : un booléen atomique. `verrouiller` essaie de le faire passer
//! de false à true en une seule instruction indivisible (compare_exchange,
//! `lock cmpxchg` en x86) ; tant que quelqu'un d'autre le tient, on boucle.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Verrou<T> {
    pris: AtomicBool,
    donnee: UnsafeCell<T>,
}

// SAFETY : l'accès à `donnee` ne se fait qu'à travers une Garde, et le
// booléen atomique garantit qu'il n'existe qu'une Garde à la fois.
unsafe impl<T: Send> Sync for Verrou<T> {}

impl<T> Verrou<T> {
    pub const fn new(donnee: T) -> Self {
        Verrou { pris: AtomicBool::new(false), donnee: UnsafeCell::new(donnee) }
    }

    pub fn verrouiller(&self) -> Garde<'_, T> {
        // Acquire / Release : les écritures faites sous le verrou sont
        // visibles par le prochain qui le prend (ordre mémoire).
        while self
            .pris
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop(); // Instruction `pause` : boucle économe.
        }
        Garde { verrou: self }
    }

    /// Libère le verrou de force, même si quelqu'un le tient.
    ///
    /// # Safety
    /// Seulement quand le détenteur ne reprendra jamais la main : en cas de
    /// panique, juste avant d'arrêter le processeur (voir console.rs).
    pub unsafe fn forcer_liberation(&self) {
        self.pris.store(false, Ordering::Release);
    }
}

/// Tant qu'elle existe, on tient le verrou ; il se libère tout seul quand
/// elle disparaît (Drop), même en sortie anticipée : impossible de l'oublier.
pub struct Garde<'a, T> {
    verrou: &'a Verrou<T>,
}

impl<T> Deref for Garde<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY : la Garde prouve qu'on tient le verrou.
        unsafe { &*self.verrou.donnee.get() }
    }
}

impl<T> DerefMut for Garde<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY : idem, et &mut self garantit l'exclusivité locale.
        unsafe { &mut *self.verrou.donnee.get() }
    }
}

impl<T> Drop for Garde<'_, T> {
    fn drop(&mut self) {
        self.verrou.pris.store(false, Ordering::Release);
    }
}
