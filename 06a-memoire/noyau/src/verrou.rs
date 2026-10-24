//! Un verrou à attente active (« spinlock »), écrit à la main.
//!
//! Pourquoi un verrou dans un noyau qui n'a qu'un seul fil d'exécution ?
//! Parce que Rust refuse, à juste titre, une variable globale modifiable
//! sans protection : dès qu'il y a des interruptions matérielles
//! (horloge, clavier) ou plusieurs processeurs, deux morceaux de code
//! peuvent y écrire en même temps. Le verrou garantit qu'un seul à la fois y accède.
//!
//! Principe : un booléen atomique. `verrouiller` le fait passer de false à
//! true en une seule instruction indivisible (compare_exchange, `lock
//! cmpxchg` en x86). Avec plusieurs processeurs, on bouclerait tant que
//! quelqu'un d'autre le tient ; sur un seul, ce serait attendre pour
//! toujours (voir `verrouiller`).
//!
//! Piège des interruptions : si le noyau tient le verrou de la console et
//! qu'une interruption d'horloge arrive, et que son gestionnaire veut
//! afficher, il attend un verrou que personne ne rendra jamais (le code qui
//! le tient est justement celui qui a été interrompu) : blocage définitif.
//! D'où la règle de Linux pour les données partagées avec un gestionnaire
//! d'interruption, spin_lock_irqsave : on coupe les interruptions AVANT de
//! prendre le verrou, et on remet leur état d'origine APRÈS l'avoir rendu.
//! Options écartées :
//!   - deux sortes de verrous (avec et sans coupure), comme spin_lock et
//!     spin_lock_irqsave : plus rapide, mais un mauvais choix ne se voit
//!     qu'au premier blocage, des semaines plus tard. Le coût de cli/sti
//!     est négligeable pour nous ; on pourra spécialiser plus tard ;
//!   - couper les interruptions sans mémoriser leur état, puis toujours les
//!     réactiver : faux si le verrou est pris dans un gestionnaire (elles
//!     doivent y rester coupées) ou pendant le démarrage.

use crate::cpu;
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

    /// Prend le verrou. Sur un seul processeur, un verrou déjà pris ne sera
    /// JAMAIS rendu : son détenteur a coupé les interruptions, rien n'a pu
    /// l'interrompre pour venir ici, sauf une exception (une faute de page
    /// sous le verrou, par exemple) ou un NMI, qui ne lui rendront pas la
    /// main avant d'avoir fini. Boucler serait un interblocage silencieux :
    /// on le dit par une panique, avec l'endroit de l'appel
    /// (#[track_caller]). La panique peut toujours afficher : elle force
    /// d'abord le verrou de la console (console::preparer_panique). Avec
    /// plusieurs processeurs, un verrou pris par un autre cœur se libère :
    /// il faudra de nouveau attendre (la boucle des spinlocks).
    #[track_caller]
    pub fn verrouiller(&self) -> Garde<'_, T> {
        let interruptions_actives = cpu::couper_interruptions();
        // Acquire / Release : les écritures faites sous le verrou sont
        // visibles par le prochain qui le prend (ordre mémoire).
        if self.pris.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            panic!("verrou deja pris : interblocage");
        }
        Garde { verrou: self, interruptions_actives }
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
    interruptions_actives: bool,
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
        // Dans cet ordre : rendre le verrou, puis seulement laisser revenir
        // les interruptions, sinon une interruption pourrait encore le
        // trouver pris.
        if self.interruptions_actives {
            cpu::activer_interruptions();
        }
    }
}
