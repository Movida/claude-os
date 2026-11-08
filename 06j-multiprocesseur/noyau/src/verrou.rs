//! Un verrou à attente active (« spinlock »), écrit à la main.
//!
//! Pourquoi un verrou sur un seul processeur ? Parce que Rust refuse, à
//! juste titre, une variable globale modifiable sans protection : dès
//! qu'il y a des interruptions matérielles (horloge, clavier), des tâches
//! qui se passent le processeur (6e), ou plusieurs processeurs, deux
//! morceaux de code peuvent y écrire en même temps. Le verrou garantit qu'un seul à la fois y accède.
//!
//! Principe : un booléen atomique. `verrouiller` le fait passer de false à
//! true en une seule instruction indivisible (compare_exchange, `lock
//! cmpxchg` en x86). Avec plusieurs processeurs, on bouclerait tant que
//! quelqu'un d'autre le tient ; sur un seul, ce serait attendre pour
//! toujours (voir `verrouiller`).
//!
//! Le marqueur UNIPROCESSEUR : chaque endroit du noyau qui suppose un seul
//! processeur le dit par une ligne qui commence par ce mot, avec ce qu'il
//! faudra changer ; `grep -rn UNIPROCESSEUR` en donne la liste, pour le
//! jour du multiprocesseur. Ici, la première : couper les interruptions
//! suffit à exclure tout autre code.
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
//!
//! Combien de temps un verrou garde-t-il les interruptions coupées ? Avec
//! la fonctionnalité `verrous` (make verrous), le noyau le mesure pour
//! chaque endroit qui en prend un (`statistiques`, plus bas) : le
//! `lock_stat` de Linux, pour la part qui nous importe.

use crate::{cpu, processeur};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// Le nombre de verrous tenus sur le processeur (le `preempt_count` de
/// Linux, pour la part des verrous) : l'ordonnanceur refuse de céder le
/// processeur s'il n'est pas nul (ordonnanceur.rs). Un compteur pour le
/// processeur, pas pour la tâche : un verrou coupe les interruptions, la
/// tâche qui le tient ne peut pas être remplacée avant de l'avoir rendu.
/// Dans la zone du processeur (processeur.rs), depuis 6j. Lu interruptions
/// actives : s'il n'est pas nul, c'est nous qui tenons ces verrous, et nous
/// ne pouvons pas être déplacés sur un autre processeur ; s'il est nul, il
/// le reste tant que nous ne prenons rien (l'exception écrite dans
/// processeur.rs).
pub fn tenus() -> u32 {
    processeur::courant_sans_verification("les verrous tenus par le contexte courant").tenus.load(Ordering::Relaxed)
}

pub struct Verrou<T> {
    pris: AtomicBool,
    donnee: UnsafeCell<T>,
}

// SAFETY: l'accès à `donnee` ne se fait qu'à travers une Garde, et le
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
    /// d'abord le verrou de la console (console::preparer_panique).
    /// UNIPROCESSEUR : avec plusieurs processeurs, un verrou pris par un
    /// autre cœur se libère : il faudra de nouveau attendre (la boucle des
    /// spinlocks), et distinguer les sortes de verrous de Linux (spin_lock,
    /// spin_lock_irqsave, mutex), un seul ne suffisant plus.
    #[track_caller]
    pub fn verrouiller(&self) -> Garde<'_, T> {
        let interruptions_actives = cpu::couper_interruptions();
        // Acquire / Release : les écritures faites sous le verrou sont
        // visibles par le prochain qui le prend (ordre mémoire).
        if self.pris.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            panic!("verrou deja pris : interblocage");
        }
        // Interruptions coupées : la zone est bien celle de ce processeur.
        processeur::courant().tenus.fetch_add(1, Ordering::Relaxed);
        Garde {
            verrou: self,
            interruptions_actives,
            #[cfg(feature = "verrous")]
            debut: statistiques::Debut::maintenant(),
        }
    }

    /// La donnée, sans prendre le verrou : `&mut self` prouve que personne
    /// d'autre ne peut l'avoir (le `get_mut` des verrous de la bibliothèque
    /// standard). Les interruptions restent comme elles sont : celui qui
    /// tient la mémoire d'un processus en écriture touche ainsi ses tables
    /// de pages sans les couper (memoire.rs).
    pub fn get_mut(&mut self) -> &mut T {
        self.donnee.get_mut()
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
    /// Quand et où les interruptions ont été coupées (make verrous).
    #[cfg(feature = "verrous")]
    debut: statistiques::Debut,
}

impl<T> Deref for Garde<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: la Garde prouve qu'on tient le verrou.
        unsafe { &*self.verrou.donnee.get() }
    }
}

impl<T> DerefMut for Garde<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, et &mut self garantit l'exclusivité locale.
        unsafe { &mut *self.verrou.donnee.get() }
    }
}

impl<T> Drop for Garde<'_, T> {
    fn drop(&mut self) {
        // Encore interruptions coupées (elles ne reviennent qu'en dessous).
        processeur::courant().tenus.fetch_sub(1, Ordering::Relaxed);
        self.verrou.pris.store(false, Ordering::Release);
        // Dans cet ordre : rendre le verrou, puis seulement laisser revenir
        // les interruptions, sinon une interruption pourrait encore le
        // trouver pris.
        if self.interruptions_actives {
            // Le premier verrou de la série, celui qui a coupé les
            // interruptions : il les remet, on compte depuis lui. Ceux
            // qu'on a pris en le tenant sont dans son temps.
            #[cfg(feature = "verrous")]
            statistiques::noter(&self.debut);
            cpu::activer_interruptions();
        }
    }
}

/// Les statistiques des verrous (la fonctionnalité `verrous`, make
/// verrous) : pour chaque endroit du noyau qui prend un `Verrou` alors que
/// les interruptions étaient actives (le premier d'une série : il les
/// coupe, et les remet en le rendant), le plus long temps qu'il les a
/// gardées coupées, combien de fois au-delà d'une milliseconde, et combien
/// de prises. Le lanceur les affiche après chaque programme
/// (programmes.rs), et les remet à zéro.
///
/// Pourquoi ce temps-là : tant que les interruptions sont coupées, le tic
/// d'horloge attend (une échéance de TCP, un réveil, la préemption), et
/// les suivants sont perdus : l'APIC ne garde qu'une interruption en
/// attente par vecteur. C'est ce que le verrou de la mémoire qui dort (6i)
/// devait faire baisser, et ce qu'il faudra regarder en 6j (plusieurs
/// processeurs : la contention) et en 6k (la console).
///
/// L'endroit : celui de l'appel à `verrouiller`, ou à la fonction qui le
/// prend pour son appelant (`processus::avec`, `vfs::avec_systeme`...,
/// marquées `#[track_caller]`) : sinon, tout le processus serait « dans
/// processus.rs ».
///
/// C'est le `lock_stat` de Linux (CONFIG_LOCK_STAT, /proc/lock_stat, sa
/// colonne holdtime-max), et son traceur `irqsoff` pour la part qui coupe
/// les interruptions ; mesuré au TSC (`tsc::lire`, quelques dizaines de
/// cycles). Sans la fonctionnalité, rien n'est mesuré ni gardé : la garde
/// n'a pas même le champ.
///
/// Options écartées : un seuil d'ECHEC au démarrage (sous QEMU sans
/// accélération, ce temps dépend de la machine hôte, de 10 à 30 fois celui
/// d'un vrai processeur, et la console, qui attend le port série octet par
/// octet, dépasse tout jusqu'en 6k) ; mesurer aussi les interruptions
/// coupées hors des verrous (les gestionnaires d'interruption, `dormir`) :
/// il faudrait instrumenter chaque `cli` et l'entrée de chaque vecteur,
/// pour des sections courtes, que le code borne déjà.
#[cfg(feature = "verrous")]
pub mod statistiques {
    use core::panic::Location;
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

    /// Quand et où une série de verrous a commencé.
    pub struct Debut {
        tsc: u64,
        lieu: &'static Location<'static>,
    }

    impl Debut {
        /// Maintenant, à l'endroit de l'appel (à travers les fonctions
        /// `#[track_caller]` qui ont mené jusqu'ici).
        #[track_caller]
        pub fn maintenant() -> Debut {
            Debut { tsc: crate::tsc::lire(), lieu: Location::caller() }
        }
    }

    /// Un endroit du noyau et ce qu'on a mesuré de lui. Tout en atomiques :
    /// une place se prend sans verrou (on mesure les verrous), et les
    /// compteurs s'écrivent depuis n'importe quelle tâche ou interruption.
    struct Endroit {
        lieu: AtomicPtr<Location<'static>>,
        max: AtomicU64,
        longues: AtomicU32,
        prises: AtomicU64,
    }

    impl Endroit {
        const fn new() -> Endroit {
            Endroit {
                lieu: AtomicPtr::new(core::ptr::null_mut()),
                max: AtomicU64::new(0),
                longues: AtomicU32::new(0),
                prises: AtomicU64::new(0),
            }
        }
    }

    /// Les endroits mesurés depuis la dernière remise à zéro. Une table
    /// fixe, pas un tableau qui grandit : mesurer ne doit rien allouer (on
    /// est sous un verrou, peut-être celui du tas). 256 places : le
    /// démarrage complet de 6h en prend un peu plus de 120.
    const PLACES: usize = 256;
    static TABLE: [Endroit; PLACES] = [const { Endroit::new() }; PLACES];
    /// Les mesures perdues faute de place (dites à l'affichage).
    static PERDUES: AtomicU64 = AtomicU64::new(0);
    /// Pendant l'affichage, on ne mesure pas : les lignes du tableau
    /// passeraient sinon dans celles du programme suivant.
    /// UNIPROCESSEUR : la remise à zéro suppose que personne ne mesure
    /// pendant l'affichage ; avec plusieurs processeurs, une table par
    /// processeur (comme les compteurs de lock_stat), réunies à
    /// l'affichage.
    static SUSPENDUES: AtomicBool = AtomicBool::new(false);

    /// Note la fin d'une série commencée à `debut`. Interruptions encore
    /// coupées.
    pub fn noter(debut: &Debut) {
        if SUSPENDUES.load(Ordering::Relaxed) {
            return;
        }
        let duree = crate::tsc::lire().wrapping_sub(debut.tsc);
        let cle = debut.lieu as *const Location<'static> as *mut Location<'static>;
        // La place de l'endroit, ou la première libre (prise d'un seul
        // compare_exchange : jamais deux places pour un même endroit).
        for e in &TABLE {
            let lieu = e.lieu.load(Ordering::Relaxed);
            let a_nous = lieu == cle
                || (lieu.is_null() && e.lieu.compare_exchange(lieu, cle, Ordering::Relaxed, Ordering::Relaxed)
                    .map_or_else(|autre| autre == cle, |_| true));
            if a_nous {
                e.max.fetch_max(duree, Ordering::Relaxed);
                e.prises.fetch_add(1, Ordering::Relaxed);
                if crate::tsc::en_nanosecondes(duree) > 1_000_000 {
                    e.longues.fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
        }
        PERDUES.fetch_add(1, Ordering::Relaxed);
    }

    /// Affiche les `n` endroits qui ont gardé les interruptions coupées le
    /// plus longtemps depuis la dernière fois (pour `quoi` : un programme,
    /// le démarrage), puis remet tout à zéro.
    pub fn afficher(quoi: impl core::fmt::Display) {
        const N: usize = 8;
        SUSPENDUES.store(true, Ordering::Relaxed);
        // Les N plus longs, par sélection (sans allouer ni trier la table).
        let mut choisis: [Option<usize>; N] = [None; N];
        for rang in 0..N {
            let meilleur = (0..PLACES)
                .filter(|&i| !TABLE[i].lieu.load(Ordering::Relaxed).is_null() && !choisis.contains(&Some(i)))
                .max_by_key(|&i| TABLE[i].max.load(Ordering::Relaxed));
            choisis[rang] = meilleur;
        }
        afficherln!("[verrous] {} : les interruptions coupees le plus longtemps, par endroit :", quoi);
        for i in choisis.into_iter().flatten() {
            let e = &TABLE[i];
            // SAFETY: on ne range dans `lieu` que des `&'static Location`
            // (`noter`), jamais libérées ; non nul : filtré plus haut.
            let lieu = unsafe { &*e.lieu.load(Ordering::Relaxed) };
            afficherln!("[verrous]   {}:{} : {} us au plus, {} fois plus d'1 ms, {} prises", lieu.file(), lieu.line(),
                        crate::tsc::en_nanosecondes(e.max.load(Ordering::Relaxed)) / 1000,
                        e.longues.load(Ordering::Relaxed), e.prises.load(Ordering::Relaxed));
        }
        let perdues = PERDUES.swap(0, Ordering::Relaxed);
        if perdues > 0 {
            afficherln!("[verrous]   ({} mesures perdues : plus de {} endroits)", perdues, PLACES);
        }
        for e in &TABLE {
            e.max.store(0, Ordering::Relaxed);
            e.longues.store(0, Ordering::Relaxed);
            e.prises.store(0, Ordering::Relaxed);
            e.lieu.store(core::ptr::null_mut(), Ordering::Relaxed);
        }
        SUSPENDUES.store(false, Ordering::Relaxed);
    }
}
