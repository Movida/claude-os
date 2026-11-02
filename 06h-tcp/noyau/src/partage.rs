//! `Arc` : une valeur partagée, comptée, dont la création peut échouer.
//!
//! Le même type que `alloc::sync::Arc` (un compteur de références
//! « fortes », qui gardent la valeur en vie, et de références « faibles »,
//! `Weak`, qui gardent seulement la mémoire), avec les mêmes noms de
//! méthodes, sauf une différence : `Arc::new` rend un `Result` au lieu de
//! paniquer quand le tas est plein (voir faillible.rs). Rust stable n'a
//! pas d'`Arc` faillible (`Arc::try_new` est instable), et on ne peut pas
//! en fabriquer un par-dessus celui de `alloc` : la disposition de sa
//! mémoire (le bloc qui porte les deux compteurs puis la valeur) est un
//! détail interne, qu'un `Arc::from_raw` sur un bloc à nous violerait.
//! Rust pour Linux a fait le même choix (`kernel::sync::Arc`, dont `new`
//! prend des drapeaux d'allocation et rend un `Result`), pour la même
//! raison (choix de conception).
//!
//! Ce qui est plus simple que dans `alloc` : pas de valeur de taille
//! variable (`Arc<[T]>`, `Arc<dyn Trait>` : le noyau n'en a pas, et la
//! conversion d'un `Arc<T>` en `Arc<dyn Trait>` demande `CoerceUnsized`,
//! instable) ; pas de `get_mut` ni de `make_mut` (ils demandent de
//! savoir qu'on est le seul à tenir la valeur, ce que `alloc` vérifie
//! en bloquant un instant le compteur faible). Le reste suit la mise en
//! œuvre de `alloc` et ses ordres mémoire, expliqués à chaque endroit.
//!
//! La bibliothèque `wasm` garde l'`Arc` de `alloc` (son `ModuleValide`) :
//! ses allocations sont une dette à part, notée dans « Reste à faire ».

use crate::faillible::PlusDeMemoire;
use alloc::alloc::{Layout, alloc, dealloc};
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, offset_of};
use core::ops::Deref;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicUsize, Ordering, fence};

/// Le bloc alloué : les deux compteurs, puis la valeur. `repr(C)` : la
/// valeur est à une place connue (`offset_of!`), ce que demande
/// `from_raw`, qui ne reçoit que son adresse.
#[repr(C)]
struct Bloc<T> {
    /// Les références fortes (`Arc`).
    forts: AtomicUsize,
    /// Les références faibles (`Weak`), plus une pour toutes les fortes
    /// ensemble : le bloc est rendu quand ce compte tombe à zéro, c'est-à-
    /// dire après la dernière faible ET la dernière forte (l'astuce de
    /// `alloc` : la dernière forte rend sa faible collective en lâchant la
    /// valeur, et le bloc n'est jamais rendu deux fois).
    faibles: AtomicUsize,
    donnee: T,
}

/// Au-delà, un compteur serait près de déborder : une fuite (des
/// `mem::forget` en boucle), comme le dit `alloc`, qui s'arrête là.
const MAX: usize = isize::MAX as usize;

/// Une référence forte : la valeur vit tant qu'il en reste une.
pub struct Arc<T> {
    bloc: NonNull<Bloc<T>>,
    // L'Arc possède (une part de) la valeur : pour le compilateur, le
    // lâcher peut lâcher un T (l'analyse de `drop`, comme dans `alloc`).
    _possede: PhantomData<Bloc<T>>,
}

/// Une référence faible : elle ne garde que la mémoire, et `upgrade` rend
/// un `Arc` tant que la valeur vit encore.
pub struct Weak<T> {
    bloc: NonNull<Bloc<T>>,
}

// SAFETY: comme `alloc::sync::Arc` : partager ou envoyer un Arc à une
// autre tâche donne à celle-ci un `&T` (il faut T: Sync) et peut lui faire
// lâcher le T, la dernière référence partie (il faut T: Send). Les
// compteurs sont atomiques.
unsafe impl<T: Send + Sync> Send for Arc<T> {}
// SAFETY: voir ci-dessus.
unsafe impl<T: Send + Sync> Sync for Arc<T> {}
// SAFETY: un Weak devient un Arc par `upgrade` : mêmes conditions.
unsafe impl<T: Send + Sync> Send for Weak<T> {}
// SAFETY: voir ci-dessus.
unsafe impl<T: Send + Sync> Sync for Weak<T> {}

/// Un bloc neuf, compteurs écrits, valeur pas encore là.
fn allouer<T>(forts: usize) -> Result<NonNull<Bloc<T>>, PlusDeMemoire> {
    // Les deux compteurs font au moins 16 octets : jamais une taille nulle.
    // SAFETY: la taille du Layout n'est pas nulle.
    let p = unsafe { alloc(Layout::new::<Bloc<T>>()) } as *mut Bloc<T>;
    let bloc = NonNull::new(p).ok_or(PlusDeMemoire)?;
    // SAFETY: le bloc vient d'être alloué avec le Layout de Bloc<T> : on
    // y écrit les compteurs, champ par champ (la valeur n'y est pas encore,
    // on ne forme donc pas de référence au bloc entier).
    unsafe {
        (&raw mut (*p).forts).write(AtomicUsize::new(forts));
        (&raw mut (*p).faibles).write(AtomicUsize::new(1));
    }
    Ok(bloc)
}

/// La place d'un Arc, allouée mais pas encore remplie : on alloue avant
/// de construire la valeur, et un échec laisse intact ce qui devait y
/// entrer (une fille d'écoute garde sa place dans la file, à `accept`).
/// Le `UniqueArc::new_uninit` de Rust pour Linux, `boite_vide` pour Box.
pub struct ArcVide<T> {
    bloc: NonNull<Bloc<T>>,
}

impl<T> ArcVide<T> {
    pub fn new() -> Result<ArcVide<T>, PlusDeMemoire> {
        Ok(ArcVide { bloc: allouer::<T>(1)? })
    }

    /// Range la valeur : l'Arc est fait, sans plus rien allouer.
    pub fn remplir(self, donnee: T) -> Arc<T> {
        let bloc = self.bloc;
        // Le bloc passe à l'Arc : ArcVide ne le rend pas.
        core::mem::forget(self);
        // SAFETY: le bloc est neuf, sa valeur pas encore écrite.
        unsafe { (&raw mut (*bloc.as_ptr()).donnee).write(donnee) };
        Arc { bloc, _possede: PhantomData }
    }
}

impl<T> Drop for ArcVide<T> {
    /// Une place jamais remplie : rendue telle quelle.
    fn drop(&mut self) {
        // SAFETY: le bloc a été alloué avec ce Layout, et n'a ni valeur ni
        // référence.
        unsafe { dealloc(self.bloc.as_ptr() as *mut u8, Layout::new::<Bloc<T>>()) };
    }
}

impl<T> Arc<T> {
    /// Partage `donnee`, ou PlusDeMemoire si le tas ne peut pas donner le
    /// bloc (`donnee` est alors lâchée ; pour la garder, `ArcVide`).
    pub fn new(donnee: T) -> Result<Arc<T>, PlusDeMemoire> {
        Ok(ArcVide::new()?.remplir(donnee))
    }

    /// Partage la valeur que construit `f`, à qui l'on donne déjà une
    /// référence faible vers elle-même (pour une valeur qui doit se
    /// retrouver : une entrée d'epoll). Avant que `f` ait fini, cette
    /// référence ne peut pas encore devenir un Arc (`upgrade` rend None :
    /// le compte fort est à zéro). Le bloc est alloué d'abord : si le tas
    /// est plein, `f` n'est pas appelée.
    pub fn new_cyclic(f: impl FnOnce(&Weak<T>) -> T) -> Result<Arc<T>, PlusDeMemoire> {
        let bloc = allouer::<T>(0)?;
        // La faible de `f` est la faible collective des fortes à venir :
        // on ne la lâche pas (ManuallyDrop), elle leur revient.
        let faible = ManuallyDrop::new(Weak { bloc });
        let donnee = f(&faible);
        // SAFETY: la valeur n'était pas encore écrite, et personne ne la
        // lit avant que le compte fort passe à 1.
        unsafe { (&raw mut (*bloc.as_ptr()).donnee).write(donnee) };
        // Release : qui verra le compte à 1 par `upgrade` (Acquire) verra
        // aussi la valeur écrite.
        faible.forts().store(1, Ordering::Release);
        Ok(Arc { bloc, _possede: PhantomData })
    }

    /// Les compteurs, à travers n'importe quelle référence au bloc.
    fn bloc(&self) -> &Bloc<T> {
        // SAFETY: tant qu'un Arc existe, le bloc et sa valeur aussi.
        unsafe { self.bloc.as_ref() }
    }

    /// L'adresse de la valeur, sans rien changer aux compteurs.
    pub fn as_ptr(this: &Arc<T>) -> *const T {
        // Pas de référence intermédiaire : l'adresse du champ directement.
        // SAFETY: le bloc est valide tant que `this` existe.
        unsafe { &raw const (*this.bloc.as_ptr()).donnee }
    }

    /// Rend l'Arc sous forme d'adresse de la valeur, sans lâcher sa
    /// référence : `from_raw` la reprendra.
    pub fn into_raw(this: Arc<T>) -> *const T {
        let p = Arc::as_ptr(&this);
        core::mem::forget(this);
        p
    }

    /// Reprend une référence rendue par `into_raw`.
    ///
    /// # Safety
    /// `p` doit venir de `Arc::<T>::into_raw`, et chaque `into_raw` n'est
    /// repris qu'une fois.
    pub unsafe fn from_raw(p: *const T) -> Arc<T> {
        // La valeur est à `offset_of!` du début du bloc (repr(C)).
        // SAFETY: garanti par l'appelant, `p` est dans un bloc vivant.
        let bloc = unsafe { (p as *const u8).sub(offset_of!(Bloc<T>, donnee)) } as *mut Bloc<T>;
        // SAFETY: non nul, puisque dans un bloc alloué.
        Arc { bloc: unsafe { NonNull::new_unchecked(bloc) }, _possede: PhantomData }
    }

    /// Ajoute une référence forte à la valeur d'adresse `p`, sans en faire
    /// un Arc (pour une file d'attente qui garde des adresses).
    ///
    /// # Safety
    /// `p` doit venir de `Arc::<T>::into_raw`, et sa référence ne pas
    /// encore avoir été reprise.
    pub unsafe fn increment_strong_count(p: *const T) {
        // SAFETY: garanti par l'appelant ; ManuallyDrop : la référence de
        // `p` n'est pas lâchée, seul le clone en ajoute une.
        let a = ManuallyDrop::new(unsafe { Arc::from_raw(p) });
        let _ = ManuallyDrop::new(Arc::clone(&a));
    }

    /// Les deux Arc partagent-ils la même valeur ?
    pub fn ptr_eq(a: &Arc<T>, b: &Arc<T>) -> bool {
        a.bloc == b.bloc
    }

    /// Une référence faible vers la valeur.
    pub fn downgrade(this: &Arc<T>) -> Weak<T> {
        // Relaxed : comme `clone`, on tient déjà une référence, le bloc ne
        // peut pas disparaître pendant ce temps.
        let ancien = this.bloc().faibles.fetch_add(1, Ordering::Relaxed);
        assert!(ancien < MAX, "Arc : compte faible deborde");
        Weak { bloc: this.bloc }
    }
}

impl<T> Clone for Arc<T> {
    fn clone(&self) -> Arc<T> {
        // Relaxed : la nouvelle référence vient d'une qu'on tient déjà ;
        // il n'y a rien à rendre visible à qui que ce soit (`alloc` fait
        // de même, la synchronisation se fait au lâcher).
        let ancien = self.bloc().forts.fetch_add(1, Ordering::Relaxed);
        assert!(ancien < MAX, "Arc : compte fort deborde");
        Arc { bloc: self.bloc, _possede: PhantomData }
    }
}

impl<T> Deref for Arc<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.bloc().donnee
    }
}

impl<T> Drop for Arc<T> {
    fn drop(&mut self) {
        // Release : nos accès à la valeur passent avant ce qui suit le
        // dernier lâcher. Seul le dernier continue.
        if self.bloc().forts.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        // Acquire : le dernier voit tout ce que les autres ont fait de la
        // valeur avant de lâcher la leur (la paire Release / Acquire, comme
        // `alloc`).
        fence(Ordering::Acquire);
        // SAFETY: plus aucune référence forte : personne ne lit la valeur,
        // et `upgrade` ne peut plus réussir (le compte est à zéro).
        unsafe { ptr::drop_in_place(&raw mut (*self.bloc.as_ptr()).donnee) };
        // La faible collective des fortes : le bloc part avec la dernière.
        drop(Weak { bloc: self.bloc });
    }
}

impl<T> Weak<T> {
    /// Les compteurs. Un Weak garde le bloc, pas forcément la valeur
    /// (déjà lâchée, ou pas encore écrite par `new_cyclic`) : on ne forme
    /// donc jamais de référence au bloc entier, seulement à ses compteurs
    /// (comme `alloc`).
    fn forts(&self) -> &AtomicUsize {
        // SAFETY: le bloc est vivant tant que ce Weak existe.
        unsafe { &(*self.bloc.as_ptr()).forts }
    }

    fn faibles(&self) -> &AtomicUsize {
        // SAFETY: voir `forts`.
        unsafe { &(*self.bloc.as_ptr()).faibles }
    }

    /// L'adresse de la valeur (qui peut ne plus vivre : à comparer, pas à
    /// lire).
    pub fn as_ptr(&self) -> *const T {
        // SAFETY: le bloc est vivant ; on ne forme qu'une adresse.
        unsafe { &raw const (*self.bloc.as_ptr()).donnee }
    }

    /// Le nombre de références fortes : 0 quand la valeur ne vit plus (ou
    /// pendant son `drop`, la dernière déjà lâchée).
    pub fn strong_count(&self) -> usize {
        self.forts().load(Ordering::Relaxed)
    }

    /// Un Arc vers la valeur, si elle vit encore.
    pub fn upgrade(&self) -> Option<Arc<T>> {
        let forts = self.forts();
        let mut n = forts.load(Ordering::Relaxed);
        loop {
            if n == 0 {
                return None;
            }
            assert!(n < MAX, "Arc : compte fort deborde");
            // Acquire en cas de succès : voir la valeur écrite par
            // `new_cyclic` avant son Release. Un échec ne promet rien.
            match forts.compare_exchange_weak(n, n + 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return Some(Arc { bloc: self.bloc, _possede: PhantomData }),
                Err(vu) => n = vu,
            }
        }
    }
}

impl<T> Clone for Weak<T> {
    fn clone(&self) -> Weak<T> {
        let ancien = self.faibles().fetch_add(1, Ordering::Relaxed);
        assert!(ancien < MAX, "Arc : compte faible deborde");
        Weak { bloc: self.bloc }
    }
}

impl<T> Drop for Weak<T> {
    fn drop(&mut self) {
        // Release puis Acquire : le même raisonnement que pour les fortes ;
        // le dernier rend le bloc, la valeur déjà lâchée.
        if self.faibles().fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            // SAFETY: plus aucune référence, d'aucune sorte ; le bloc a été
            // alloué avec ce Layout (allouer).
            unsafe { dealloc(self.bloc.as_ptr() as *mut u8, Layout::new::<Bloc<T>>()) };
        }
    }
}
