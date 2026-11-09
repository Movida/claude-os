//! Dormir et se réveiller : les files d'attente, les minuteries, les
//! verrous qui dorment (le `Mutex`, et depuis 6i le `VerrouLE`, en lecture
//! et en écriture).
//!
//! Une tâche qui attend quelque chose (un caractère du clavier, un verrou
//! tenu par une autre, une échéance) quitte la file des prêtes de
//! l'ordonnanceur et ne prend plus le processeur ; celle qui rend la chose
//! disponible la réveille. C'est le couple `prepare_to_wait` /
//! `wake_up` de Linux, et la difficulté est toujours la même : ne pas
//! PERDRE de réveil. Si la tâche vérifie « rien à lire », puis qu'un
//! caractère arrive et qu'on la réveille AVANT qu'elle se soit endormie,
//! elle s'endort ensuite pour toujours. La règle, celle de Linux
//! (`___wait_event`, `prepare_to_wait_event`), depuis 6j :
//!   1. couper les interruptions ;
//!   2. poser « je vais dormir » (`Tache::preparer_sommeil`, le
//!      `set_current_state` de Linux : un `xchg`, une barrière complète),
//!      au début de CHAQUE tour ;
//!   3. s'inscrire dans la file de l'objet attendu ;
//!   4. vérifier la condition ; vraie : fini (se retirer de la file) ;
//!   5. pour un sommeil interruptible, vérifier les signaux ;
//!   6. dormir (`dormir`), qui cède le processeur : la tâche ne quitte la
//!      file des prêtes que si son état dit ENCORE « dort » (ordonnanceur.rs) ;
//!   7. réveillée, se retirer de la file si elle y est encore (réveillée
//!      par une échéance ou un signal), et recommencer au 2.
//! Pourquoi l'état avant la condition : celui qui réveille pose d'abord la
//! condition, puis lit notre état (`tache::reveiller`, un compare_exchange
//! précédé d'une barrière complète). Ou bien il voit « dort » et nous
//! réveille (nous ne quitterons pas la file des prêtes) ; ou bien nous
//! voyons sa condition. Sur deux processeurs, c'est le motif de Dekker
//! (processeur.rs) : sans les deux barrières, chacun pourrait voir l'ancien
//! état de l'autre, et le réveil se perdre. La condition n'a donc plus
//! besoin d'être vérifiée sous le verrou de qui réveille : c'est ce qui
//! rend le `wait_event` de Linux juste pour des conditions sans verrou.
//! `attendre_que`, plus bas, fait les sept pas pour la plupart des
//! attentes ; les autres (les verrous qui dorment, `poll`, les futex, les
//! sommeils à échéance) suivent la même règle, écrite chez chacune.
//! Jusqu'à 6i, les interruptions coupées de 1 à 6 tenaient lieu de tout
//! cela : personne ne pouvait s'exécuter entre la vérification et le
//! sommeil, ni le gestionnaire qui réveillerait, ni une autre tâche ; six
//! endroits vérifiaient leur condition avant de s'inscrire, et une dizaine
//! de sommeils sans file comptaient sur `dormir` pour remettre l'état.
//!
//! Une file d'attente ne demande aucune allocation : c'est une liste
//! chaînée d'ENTRÉES posées par ceux qui attendent (les `wait_queue_entry`
//! de Linux). Chaque tâche a la sienne, dans sa `Tache` (elle n'attend
//! qu'une chose à la fois) : s'inscrire ne peut donc pas échouer, et une
//! file d'un objet qui dure (le clavier, la console) ne garde aucune mémoire
//! après son dernier attendant (le contrôle « memoire rendue » des
//! programmes le verrait). Une entrée peut aussi être un RAPPEL : une
//! fonction que le réveil appelle au lieu de réveiller une tâche, et qui
//! laisse l'entrée inscrite. C'est ainsi que `poll` attend plusieurs
//! fichiers à la fois (une entrée dans la file de chacun, qui réveille la
//! même tâche), et qu'un epoll apprendra qu'un de ses fichiers est prêt.
//!
//! Un réveil porte une CLÉ, les événements qui viennent d'arriver (POLLIN
//! quand un eventfd reçoit une écriture, POLLOUT quand il est lu ; 0 :
//! « n'importe quoi ») : un rappel l'ignore s'il attend autre chose (une
//! tâche, elle, est toujours réveillée). Une entrée peut être EXCLUSIVE
//! (WQ_FLAG_EXCLUSIVE) : `reveiller(cle, n)`
//! réveille toutes les entrées ordinaires, mais s'arrête dès que `n`
//! exclusives ont réveillé quelqu'un (le `__wake_up_common` de Linux). Pour
//! un verrou qui dort, ou les lecteurs d'un tube, réveiller tous
//! ceux qui attendent quand un seul pourra passer serait les faire courir
//! pour rien (le « troupeau tonitruant »). Les ordinaires sont rangées en
//! tête, les exclusives en queue (dans l'ordre d'arrivée), comme chez
//! Linux : toutes les ordinaires sont réveillées avant la première
//! exclusive. Une tâche déjà réveillée (par son échéance, un signal) ne
//! compte pas : le réveil passe à l'exclusive suivante, au lieu d'être
//! perdu.
//!
//! La file a son propre verrou (le spinlock du `wait_queue_head` de
//! Linux), pris APRÈS celui de l'objet attendu s'il est tenu. Option
//! écartée, celle de 6e : la file sous le verrou de son objet. Mais `poll`
//! et epoll laissent des entrées dans la file d'un fichier pendant qu'ils
//! attendent, et doivent les retirer sans rien savoir de lui (un eventfd,
//! un tube, le clavier...), ni de son verrou. Un rappel est appelé sous le
//! verrou de la file : il ne doit pas y toucher (le verrou est pris :
//! panique), mais peut prendre d'autres verrous (celui de son epoll, la
//! file des prêtes).
//!
//! Les minuteries (les échéances des attentes) : une liste triée par
//! échéance, réservée au démarrage pour autant de tâches qu'il peut y en
//! avoir (une échéance au plus par tâche), regardée à chaque tic ; une
//! minuterie annulée (la tâche réveillée avant) en est retirée aussitôt.
//! Linux a une roue de minuteries pour les tics et un arbre pour les
//! hrtimers ; nos attentes se comptent en dizaines, la liste suffit.

use crate::cpu;
use crate::faillible::{FileFaillible, VecFaillible};
use crate::ordonnanceur;
use crate::partage::Arc;
use crate::processeur;
use crate::processus::Entree;
use crate::tache::{self, Reveil, Tache};
use crate::verrou::Verrou;
use alloc::vec::Vec;
use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomPinned;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

/// Ce que fait le réveil d'une entrée qui n'est pas une tâche : l'entrée
/// d'un `poll` (sondage.rs), l'élément d'un epoll (epoll.rs).
pub trait Rappel {
    /// La file de l'entrée est réveillée, avec la clé `cle` (les événements
    /// arrivés, 0 : n'importe lesquels). Rend vrai si une tâche a été
    /// réveillée par lui : pour une entrée exclusive, le réveil compte.
    /// Appelé sous le verrou de la file, interruptions coupées.
    fn rappel(&self, cle: u32) -> bool;
}

/// Une entrée d'une file d'attente (la `wait_queue_entry` de Linux).
///
/// Une entrée inscrite ne doit ni bouger ni disparaître : la file la
/// désigne par son adresse. Celle d'une tâche est dans sa `Tache`, qui ne
/// quitte jamais son Arc, et la file tient cet Arc tant qu'elle y est ;
/// celle d'un rappel est épinglée (`Pin`, et `PhantomPinned` pour que Rust
/// refuse de la déplacer une fois épinglée). Et la détruire encore inscrite
/// arrête le noyau (`Drop`), avant que la file ne désigne une mémoire
/// rendue. Option écartée : des entrées dans un `Vec` de la file (pas de
/// pointeurs) ; mais inscrire allouerait (et pourrait échouer), et une
/// tâche ne pourrait pas attendre sans mémoire.
pub struct EntreeAttente {
    /// La suivante dans la file (sous le verrou de la file).
    suivante: Cell<*const EntreeAttente>,
    /// Réveillée parmi les exclusives (voir l'en-tête).
    exclusive: Cell<bool>,
    /// Dans une file en ce moment : une entrée n'est que dans une à la fois.
    inscrite: Cell<bool>,
    /// Ce que celui qui s'inscrit laisse pour celui qui réveille : la sorte
    /// d'attente d'un `VerrouLE`, en lecture ou en écriture (le `type` d'un
    /// `rwsem_waiter` de Linux). 0 pour les autres.
    marque: Cell<u32>,
    genre: Cell<Genre>,
    _epinglee: PhantomPinned,
}

/// Ce que désigne une entrée.
#[derive(Clone, Copy)]
enum Genre {
    /// Une tâche qui dort : le pointeur d'un Arc que tient la file tant
    /// qu'elle y est. Son réveil la retire de la file (le
    /// `autoremove_wake_function` de Linux).
    Tache(*const Tache),
    /// Un rappel, qui laisse l'entrée inscrite.
    Rappel(*const dyn Rappel),
}

// SAFETY: une entrée n'est lue et écrite que par qui l'inscrit, avant de
// l'inscrire et après l'avoir retirée, et sous le verrou de sa file entre
// les deux.
unsafe impl Sync for EntreeAttente {}
// SAFETY: voir ci-dessus.
unsafe impl Send for EntreeAttente {}

impl EntreeAttente {
    /// Une entrée de tâche (celle de chaque `Tache`), pas encore inscrite.
    pub const fn new() -> EntreeAttente {
        EntreeAttente {
            suivante: Cell::new(core::ptr::null()),
            exclusive: Cell::new(false),
            inscrite: Cell::new(false),
            marque: Cell::new(0),
            genre: Cell::new(Genre::Tache(core::ptr::null())),
            _epinglee: PhantomPinned,
        }
    }

    /// Fait de l'entrée celle d'un rappel : `qui` sera appelé à chaque
    /// réveil de la file où elle sera inscrite ; exclusive ou non, comme
    /// `inscrire_exclusive` et `inscrire`.
    ///
    /// # Safety
    /// `qui` doit rester valable tant que l'entrée est inscrite (en
    /// pratique : `qui` contient l'entrée, et n'est rendu qu'après l'avoir
    /// retirée).
    pub unsafe fn preparer_rappel(&self, qui: *const dyn Rappel, exclusive: bool) {
        assert!(!self.inscrite.get(), "entree d'attente preparee pendant qu'elle est inscrite");
        self.genre.set(Genre::Rappel(qui));
        self.exclusive.set(exclusive);
    }
}

impl Drop for EntreeAttente {
    fn drop(&mut self) {
        assert!(!self.inscrite.get(), "entree d'attente detruite encore inscrite");
    }
}

/// Une file d'attente : les entrées de ceux qui attendent un même objet (le
/// `wait_queue_head` de Linux), avec son verrou.
pub struct FileAttente {
    liste: Verrou<Liste>,
}

struct Liste {
    tete: *const EntreeAttente,
    queue: *const EntreeAttente,
}

// SAFETY: la liste n'est touchée que sous son verrou, et ses entrées
// restent à leur place tant qu'elles y sont (dans leur tâche, ou épinglées).
unsafe impl Send for Liste {}

impl Drop for FileAttente {
    /// Une file détruite avec des entrées arrêterait le noyau plus tard,
    /// sans dire pourquoi (une entrée de rappel qui s'en retire,
    /// `EntreeRappel::retirer`, écrirait dans une mémoire rendue) : on
    /// l'arrête tout de suite, en le disant. C'est ce qui rend
    /// `EntreeRappel::inscrire` sûr (voir là).
    fn drop(&mut self) {
        assert!(self.liste.get_mut().tete.is_null(), "file d'attente detruite avec des entrees");
    }
}

impl Liste {
    /// Inscrit `e` : en tête si elle est ordinaire, en queue si elle est
    /// exclusive.
    fn placer(&mut self, e: &EntreeAttente) {
        if !e.exclusive.get() {
            return self.placer_en_tete(e);
        }
        assert!(!e.inscrite.get(), "entree d'attente inscrite deux fois");
        e.inscrite.set(true);
        let p: *const EntreeAttente = e;
        e.suivante.set(core::ptr::null());
        // SAFETY: les entrées de la liste sont valables (dans leur tâche tenue, ou épinglées).
        match unsafe { self.queue.as_ref() } {
            Some(q) => q.suivante.set(p),
            None => self.tete = p,
        }
        self.queue = p;
    }

    /// Inscrit `e` en tête, même exclusive.
    fn placer_en_tete(&mut self, e: &EntreeAttente) {
        assert!(!e.inscrite.get(), "entree d'attente inscrite deux fois");
        e.inscrite.set(true);
        let p: *const EntreeAttente = e;
        e.suivante.set(self.tete);
        if self.tete.is_null() {
            self.queue = p;
        }
        self.tete = p;
    }

    /// Délie `e`, qui suit `precedente` (nulle : `e` est en tête).
    fn delier(&mut self, precedente: *const EntreeAttente, e: &EntreeAttente) {
        let suivante = e.suivante.get();
        // SAFETY: comme `placer`.
        match unsafe { precedente.as_ref() } {
            Some(pr) => pr.suivante.set(suivante),
            None => self.tete = suivante,
        }
        if core::ptr::eq(self.queue, e) {
            self.queue = precedente;
        }
        e.suivante.set(core::ptr::null());
        e.inscrite.set(false);
    }

    /// Cherche la première entrée pour qui `choisir` est vrai : (sa
    /// précédente, elle), en pointeurs (une entrée inscrite ne bouge pas :
    /// on la désigne sans retenir la liste empruntée).
    fn chercher(&self, mut choisir: impl FnMut(&EntreeAttente) -> bool) -> Option<(*const EntreeAttente, *const EntreeAttente)> {
        let mut precedente: *const EntreeAttente = core::ptr::null();
        let mut p = self.tete;
        // SAFETY: comme `placer`.
        while let Some(e) = unsafe { p.as_ref() } {
            if choisir(e) {
                return Some((precedente, p));
            }
            precedente = p;
            p = e.suivante.get();
        }
        None
    }
}

/// La tâche d'une entrée, si c'en est une.
fn tache_de(e: &EntreeAttente) -> Option<*const Tache> {
    match e.genre.get() {
        Genre::Tache(t) => Some(t),
        Genre::Rappel(_) => None,
    }
}

impl FileAttente {
    pub const fn new() -> FileAttente {
        FileAttente { liste: Verrou::new(Liste { tete: core::ptr::null(), queue: core::ptr::null() }) }
    }

    /// Inscrit la tâche courante, en tête (le `add_wait_queue` de Linux).
    /// Elle doit ensuite dormir (`dormir`), puis s'en retirer (`retirer`).
    pub fn inscrire(&self) {
        self.inscrire_tache_en(tache::courante_arc(), false);
    }

    /// Inscrit la tâche courante, exclusive, en queue (le
    /// `add_wait_queue_exclusive` de Linux) : réveillée seule, dans l'ordre
    /// d'arrivée.
    pub fn inscrire_exclusive(&self) {
        self.inscrire_tache_en(tache::courante_arc(), true);
    }

    /// Inscrit la tâche courante, exclusive, en TÊTE (le
    /// `__add_wait_queue_exclusive` de Linux, pour `epoll_wait`) : de
    /// plusieurs fils qui attendent le même epoll, le dernier arrivé est
    /// réveillé le premier (le plus chaud dans les caches).
    pub fn inscrire_exclusive_en_tete(&self) {
        let p = Arc::into_raw(tache::courante_arc());
        // SAFETY: comme `inscrire_tache_en`.
        let e = unsafe { (*p).entree_attente() };
        let mut l = self.liste.verrouiller();
        e.genre.set(Genre::Tache(p));
        e.exclusive.set(true);
        e.marque.set(0);
        l.placer_en_tete(e);
    }

    /// Quelqu'un attend-il (le `waitqueue_active` de Linux) ?
    pub fn active(&self) -> bool {
        !self.liste.verrouiller().tete.is_null()
    }

    /// Inscrit la tâche `t` (une autre que la courante : un futex déplacé
    /// d'une file à l'autre par FUTEX_REQUEUE), exclusive, en queue ; la
    /// file prend l'Arc.
    pub fn inscrire_tache(&self, t: Arc<Tache>) {
        self.inscrire_tache_en(t, true);
    }

    fn inscrire_tache_en(&self, t: Arc<Tache>, exclusive: bool) {
        self.inscrire_tache_marquee(t, exclusive, 0);
    }

    fn inscrire_tache_marquee(&self, t: Arc<Tache>, exclusive: bool, marque: u32) {
        // Un Arc de plus, tenu par la file : la tâche vit tant qu'elle y est.
        let p = Arc::into_raw(t);
        // SAFETY: `p` vient d'être tenu ; une tâche n'attend qu'une chose à
        // la fois, son entrée est donc libre (`placer` le vérifie).
        let e = unsafe { (*p).entree_attente() };
        let mut l = self.liste.verrouiller();
        e.genre.set(Genre::Tache(p));
        e.exclusive.set(exclusive);
        e.marque.set(marque);
        l.placer(e);
    }

    /// Inscrit la tâche courante, exclusive, en queue, avec la marque
    /// `marque` (voir `EntreeAttente`) : un `VerrouLE`.
    pub fn inscrire_marquee(&self, marque: u32) {
        self.inscrire_tache_marquee(tache::courante_arc(), true, marque);
    }

    /// La marque de la tâche en tête de la file, s'il y en a une.
    pub fn marque_en_tete(&self) -> Option<u32> {
        let l = self.liste.verrouiller();
        // SAFETY: comme `Liste::placer`.
        unsafe { l.tete.as_ref() }.map(|e| e.marque.get())
    }

    /// Retire de la file la première tâche de marque `marque`, et la rend
    /// (avec l'Arc que tenait la file), sans la réveiller.
    pub fn retirer_marquee(&self, marque: u32) -> Option<Arc<Tache>> {
        let mut l = self.liste.verrouiller();
        let (precedente, e) = l.chercher(|e| tache_de(e).is_some() && e.marque.get() == marque)?;
        // SAFETY: l'entrée trouvée est inscrite, sous le verrou de la file.
        Some(Self::sortir_tache(&mut l, precedente, unsafe { &*e }))
    }

    /// Le nombre d'entrées de la file (tâches et rappels).
    pub fn longueur(&self) -> usize {
        let l = self.liste.verrouiller();
        let mut n = 0;
        l.chercher(|_| {
            n += 1;
            false
        });
        n
    }

    /// Inscrit l'entrée d'un rappel (`EntreeAttente::preparer_rappel`) : en
    /// tête, ou en queue si elle est exclusive. Épinglée : elle ne bougera
    /// pas avant d'en être retirée (`enlever`).
    pub fn ajouter(&self, e: Pin<&EntreeAttente>) {
        assert!(tache_de(&e).is_none(), "une entree de tache ajoutee comme un rappel");
        self.liste.verrouiller().placer(&e);
    }

    /// Retire l'entrée d'un rappel, si elle est dans la file.
    pub fn enlever(&self, e: &EntreeAttente) {
        let mut l = self.liste.verrouiller();
        if let Some((precedente, _)) = l.chercher(|x| core::ptr::eq(x, e)) {
            l.delier(precedente, e);
        }
    }

    /// Délie l'entrée de tâche `e` et rend l'Arc que tenait la file.
    fn sortir_tache(l: &mut Liste, precedente: *const EntreeAttente, e: &EntreeAttente) -> Arc<Tache> {
        let t = tache_de(e).expect("une entree de rappel sortie comme une tache");
        l.delier(precedente, e);
        // SAFETY: l'Arc pris par `inscrire_tache_en`, tenu par la file
        // jusqu'ici, passe à l'appelant.
        unsafe { Arc::from_raw(t) }
    }

    /// `t` est-elle dans la file ?
    pub fn contient(&self, t: &Tache) -> bool {
        self.liste.verrouiller().chercher(|e| core::ptr::eq(e, t.entree_attente())).is_some()
    }

    /// Le nombre de tâches de la file pour qui `choisir` est vrai.
    pub fn compter(&self, mut choisir: impl FnMut(&Tache) -> bool) -> usize {
        let l = self.liste.verrouiller();
        let mut n = 0;
        l.chercher(|e| {
            // SAFETY: la tâche d'une entrée inscrite est tenue par la file.
            n += tache_de(e).is_some_and(|t| choisir(unsafe { &*t })) as usize;
            false
        });
        n
    }

    /// Retire de la file la première tâche pour qui `choisir` est vrai, et
    /// la rend (avec l'Arc que tenait la file).
    pub fn retirer_si(&self, mut choisir: impl FnMut(&Tache) -> bool) -> Option<Arc<Tache>> {
        let mut l = self.liste.verrouiller();
        // SAFETY: comme `compter` ; l'entrée trouvée est inscrite.
        let (precedente, e) = l.chercher(|e| tache_de(e).is_some_and(|t| choisir(unsafe { &*t })))?;
        // SAFETY: l'entrée trouvée est inscrite, sous le verrou de la file.
        Some(Self::sortir_tache(&mut l, precedente, unsafe { &*e }))
    }

    /// Retire de la file la première tâche, et la rend (avec l'Arc que
    /// tenait la file), sans la réveiller : un `Mutex` la lui remet.
    pub fn retirer_premiere(&self) -> Option<Arc<Tache>> {
        self.retirer_si(|_| true)
    }

    /// Retire `t` de la file, si elle y est (réveillée par autre chose
    /// qu'un réveil de la file : une échéance, un signal).
    pub fn retirer(&self, t: &Tache) {
        let mut l = self.liste.verrouiller();
        if !t.entree_attente().inscrite.get() {
            return;
        }
        if let Some((precedente, _)) = l.chercher(|e| core::ptr::eq(e, t.entree_attente())) {
            drop(Self::sortir_tache(&mut l, precedente, t.entree_attente()));
        }
    }

    /// Réveille la file avec la clé `cle` : toutes les entrées ordinaires,
    /// et des exclusives jusqu'à ce que `exclusives` d'entre elles aient
    /// réveillé quelqu'un (0 : toutes). Une tâche réveillée quitte la file ;
    /// une tâche déjà réveillée y reste, et ne compte pas. Un rappel reste,
    /// et dit s'il a réveillé quelqu'un.
    pub fn reveiller(&self, cle: u32, exclusives: usize) {
        // Une barrière complète avant de lire quoi que ce soit : les rappels
        // (poll, epoll) lisent ici ce que leur tâche a écrit avant de
        // s'inscrire ou de réarmer (le masque d'un élément d'epoll), et qui
        // réveille vient d'écrire la condition : le motif de Dekker des deux
        // côtés (attente.rs, l'en-tête ; le `smp_mb__after_spinlock` de
        // Linux sur le verrou de sa `wait_queue_head`).
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        let mut l = self.liste.verrouiller();
        let mut reste = exclusives;
        let mut precedente: *const EntreeAttente = core::ptr::null();
        let mut p = l.tete;
        // SAFETY: comme `Liste::placer`.
        while let Some(e) = unsafe { p.as_ref() } {
            let suivante = e.suivante.get();
            let reveille = match e.genre.get() {
                Genre::Tache(t) => {
                    // SAFETY: l'Arc de la file tient la tâche ; on en
                    // prend un pour le réveil.
                    let a = unsafe {
                        Arc::increment_strong_count(t);
                        Arc::from_raw(t)
                    };
                    let reveillee = tache::reveiller(a, Reveil::Reveillee);
                    if reveillee {
                        drop(Self::sortir_tache(&mut l, precedente, e));
                    }
                    reveillee
                }
                // SAFETY: `qui` reste valable tant que l'entrée est
                // inscrite (`preparer_rappel`).
                Genre::Rappel(qui) => unsafe { (*qui).rappel(cle) },
            };
            if e.inscrite.get() {
                precedente = p;
            }
            if reveille && e.exclusive.get() && exclusives != 0 {
                reste -= 1;
                if reste == 0 {
                    break;
                }
            }
            p = suivante;
        }
    }

    /// Réveille toutes les entrées ordinaires et la première exclusive
    /// (le `wake_up` de Linux).
    pub fn reveiller_une(&self) {
        self.reveiller(0, 1);
    }

    /// Réveille toutes les entrées (le `wake_up_all` de Linux).
    pub fn reveiller_toutes(&self) {
        self.reveiller(0, 0);
    }
}

/// Comment dormir.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sommeil {
    /// Seul un réveil de la file finit l'attente (un verrou qui dort).
    Ininterruptible,
    /// Un signal la finit aussi (TASK_INTERRUPTIBLE) : l'appel système
    /// rendra EINTR, ou sera refait (reprise.rs).
    Interruptible,
}

/// La tâche courante dort, jusqu'à un réveil, l'instant `echeance` (temps
/// monotone, en ns) s'il y en a un, ou un signal si elle dort
/// interruptible. Interruptions coupées, aucun verrou tenu, « je vais
/// dormir » déjà posé pour ce tour (`preparer_sommeil`, voir l'en-tête ;
/// sinon, panique : la tâche ne quitterait jamais la file des prêtes, et
/// tournerait), et la tâche inscrite dans la file de ce qu'elle attend s'il
/// y en a une ; revient interruptions coupées, avec la raison du réveil.
/// Un signal en attente, ou une échéance déjà passée : la raison est posée
/// sans dormir (sauf si quelqu'un a réveillé entre-temps : sa raison
/// reste). Pour qu'un verrou ne soit pas tenu pendant le sommeil,
/// ordonnancer le vérifie.
pub fn dormir(echeance: Option<u64>, sommeil: Sommeil) -> Reveil {
    let t = tache::courante();
    assert!(!t.sommeil_non_prepare(), "dormir sans avoir pose \"je vais dormir\"");
    if sommeil == Sommeil::Interruptible && tache::signal_en_attente() {
        t.ne_dort_pas(Reveil::Signal);
        return t.raison_du_reveil();
    }
    if let Some(e) = echeance {
        if e <= crate::temps::ns_monotone() {
            t.ne_dort_pas(Reveil::Echeance);
            return t.raison_du_reveil();
        }
        armer(e);
    }
    ordonnanceur::ordonnancer(ordonnanceur::Bascule::Sommeil);
    if echeance.is_some() {
        annuler(t);
    }
    t.raison_du_reveil()
}

/// Comment s'inscrire dans la file d'attente, pour `attendre_que`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Inscription {
    /// Réveillée par tout réveil de la file (`inscrire`).
    Ordinaire,
    /// Une seule à la fois, dans l'ordre d'arrivée (`inscrire_exclusive`).
    Exclusive,
}

/// Attend que `condition` soit vraie, inscrite dans `file`, au plus
/// jusqu'à `echeance` (temps monotone), ou jusqu'à un signal si `sommeil`
/// est interruptible : les sept pas de l'en-tête (le `___wait_event` de
/// Linux), interruptions coupées pendant l'attente (rétablies au retour
/// comme elles étaient). `condition` peut prendre des verrous courts (pas
/// dormir). Rend Reveillee si la condition est devenue vraie (même si c'est
/// l'échéance ou un signal qui a réveillé : la condition est revue une
/// dernière fois, ce qui arrive en même temps se lit), Echeance ou Signal
/// sinon. La tâche ressort de la file et de son état d'attente.
pub fn attendre_que(file: &FileAttente, inscription: Inscription, sommeil: Sommeil, echeance: Option<u64>,
                    mut condition: impl FnMut() -> bool) -> Reveil {
    let interruptions = cpu::couper_interruptions();
    let t = tache::courante();
    let r = loop {
        t.preparer_sommeil(sommeil);
        match inscription {
            Inscription::Ordinaire => file.inscrire(),
            Inscription::Exclusive => file.inscrire_exclusive(),
        }
        if condition() {
            file.retirer(t);
            break Reveil::Reveillee;
        }
        let r = dormir(echeance, sommeil);
        file.retirer(t);
        if r != Reveil::Reveillee {
            break if condition() { Reveil::Reveillee } else { r };
        }
    };
    t.reveille();
    if interruptions {
        cpu::activer_interruptions();
    }
    r
}

/// Les échéances des tâches qui dorment, triées.
static MINUTERIES: Verrou<Vec<(u64, Arc<Tache>)>> = Verrou::new(Vec::new());
/// Les attentes du temps de calcul (clock_nanosleep sur
/// CLOCK_PROCESS_CPUTIME_ID) : le temps de calcul à atteindre, le processus
/// dont le temps compte (tous ses fils), la tâche qui dort.
static ATTENTES_CALCUL: Verrou<Vec<(u64, Arc<Entree>, Arc<Tache>)>> = Verrou::new(Vec::new());

/// Réserve les minuteries pour `max` tâches : elles ne grandissent jamais
/// pendant un programme. Au démarrage.
pub fn initialiser(max: usize) {
    MINUTERIES.verrouiller().try_reserve_exact(max).expect("plus de memoire pour les minuteries");
    ATTENTES_CALCUL.verrouiller().try_reserve_exact(max).expect("plus de memoire pour les minuteries");
}

/// Arme une minuterie pour la tâche courante, à `echeance`.
fn armer(echeance: u64) {
    let mut m = MINUTERIES.verrouiller();
    let i = m.partition_point(|&(e, _)| e <= echeance);
    // La place est réservée pour une échéance par tâche (`initialiser`).
    m.inserer(i, (echeance, tache::courante_arc())).expect("minuteries sans leur place");
}

/// Retire la minuterie de `t`, si elle y est encore.
fn annuler(t: &Tache) {
    let mut m = MINUTERIES.verrouiller();
    if let Some(i) = m.iter().position(|(_, x)| core::ptr::eq(Arc::as_ptr(x), t)) {
        m.remove(i);
    }
}

/// La tâche courante dort jusqu'à ce que le temps de calcul du processus
/// `compte` atteigne `cible` (le calcul de ses autres fils), ou un signal.
/// Interruptions coupées.
pub fn dormir_calcul(compte: Arc<Entree>, cible: u64) -> Reveil {
    let t = tache::courante();
    // « Je vais dormir » avant tout (l'en-tête), inscrite ensuite : le tic
    // qui verra la cible atteinte nous réveillera, ou nous la verrons.
    t.preparer_sommeil(Sommeil::Interruptible);
    // La place est réservée pour une attente par tâche (`initialiser`).
    ATTENTES_CALCUL.verrouiller().ajouter_dans_la_place((cible, compte.clone(), tache::courante_arc()));
    if tache::signal_en_attente() {
        t.ne_dort_pas(Reveil::Signal);
    } else if compte.temps_de_calcul() >= cible {
        t.ne_dort_pas(Reveil::Echeance);
    } else {
        ordonnanceur::ordonnancer(ordonnanceur::Bascule::Sommeil);
    }
    {
        let mut a = ATTENTES_CALCUL.verrouiller();
        if let Some(i) = a.iter().position(|(_, _, x)| core::ptr::eq(Arc::as_ptr(x), t)) {
            a.remove(i);
        }
    }
    let r = t.raison_du_reveil();
    t.reveille();
    r
}

/// Le tic d'horloge, interruptions coupées : les échéances passées
/// réveillent leurs tâches.
pub fn tic() {
    let maintenant = crate::temps::ns_monotone();
    let mut m = MINUTERIES.verrouiller();
    while m.first().is_some_and(|&(e, _)| e <= maintenant) {
        let (_, t) = m.remove(0);
        tache::reveiller(t, Reveil::Echeance);
    }
    drop(m);
    let mut a = ATTENTES_CALCUL.verrouiller();
    let mut i = 0;
    while i < a.len() {
        if a[i].1.temps_de_calcul() >= a[i].0 {
            let (_, _, t) = a.swap_remove(i);
            tache::reveiller(t, Reveil::Echeance);
        } else {
            i += 1;
        }
    }
}

/// Le détecteur d'interblocage, appelé par la tâche inactive du processeur
/// 0 quand aucune tâche n'est prête nulle part et que tous les autres
/// processeurs dorment (ordonnanceur.rs, `machine_inactive` : une tâche
/// en cours ailleurs pourrait réveiller qui dort), interruptions coupées.
/// Si aucune minuterie d'un
/// programme n'est armée, plus rien ne peut réveiller les programmes qui
/// dorment : ni une
/// échéance, ni une autre tâche (aucune ne s'exécute), ni un périphérique
/// (le clavier ne réveille que sa tâche du noyau, jusqu'au terminal de
/// 6k). Linux les laisserait endormis pour toujours ; sans terminal,
/// personne ne pourrait les interrompre (pas de ^C) : chacun est arrêté
/// par SIGKILL, en le disant. Un écart voulu, qui généralise celui de 6d
/// (une attente de futex sans délai dans un programme d'un seul fil). Les
/// tâches du noyau (init qui attend un programme, le clavier) ne sont pas
/// concernées. Seules comptent les minuteries des programmes : celles des
/// tâches du noyau (6g : les voisins du réseau, que la tâche du réseau fait
/// vieillir pendant des dizaines de secondes) ne réveillent pas un programme
/// ; sans cela, un programme bloqué pour toujours attendrait la prochaine
/// échéance de la tâche du réseau pour être arrêté. Celles d'un programme
/// WebAssembly comptent (6h) : il tourne dans une tâche du noyau, mais il
/// peut, à son échéance, écrire à un programme Linux par une socket (un
/// serveur qui répond après un poll_oneoff). Une réponse du réseau
/// le peut aussi : tant qu'une socket liée a quelqu'un dans sa file
/// d'attente (un `recv`, un `poll`, un epoll qui la surveille) et qu'une
/// carte a son lien, un datagramme peut encore venir du dehors, et le
/// détecteur ne tue personne (6g : un ping attendu sans délai). Par `lo`,
/// seulement si une connexion TCP a un minuteur armé (6h : une
/// retransmission, un ACK retardé, une sonde peuvent encore faire bouger
/// l'autre côté) ; sinon, seul un programme qui s'exécute peut s'y envoyer
/// quelque chose.
/// Il épargne ainsi plus qu'il ne faudrait : un élément d'epoll reste
/// inscrit dans la file de sa socket même quand personne n'attend l'epoll,
/// et un programme bloqué pour toujours ailleurs (un futex, `pause`) n'est
/// alors pas arrêté. C'est ce que fait Linux, qui n'arrête jamais
/// personne ; ne compter que les éléments dont l'epoll a quelqu'un dans sa
/// file serait plus juste, à voir quand la boucle de Bun aura des sockets
/// (6h). Rend vrai s'il a arrêté quelqu'un.
pub fn detecter_interblocage() -> bool {
    // D'abord, un programme qui attend la mémoire de son processus (6i) :
    // celui qui la tient ne dort jamais en la tenant (processus.rs), il
    // serait donc prêt. Plus rien de prêt et quelqu'un qui l'attend : le
    // verrou est perdu (une erreur du noyau), et rien ne le rendra. On
    // s'arrête en le disant, plutôt que de laisser le programme figé sans un
    // mot (le `hung_task` de Linux, qui le dit au bout de 120 s).
    let mut attend = None;
    tache::pour_chaque(|t| {
        if t.est_programme() && t.tient_sa_memoire() {
            attend = Some(t.nom());
        }
    });
    if let Some(nom) = attend {
        panic!("interblocage : {} attend la memoire de son processus, et plus rien ne peut la rendre", nom);
    }
    if MINUTERIES.verrouiller().iter().any(|(_, t)| t.est_programme() || t.est_webassembly()) || !ATTENTES_CALCUL.verrouiller().is_empty() {
        return false;
    }
    if crate::reseau::attentes() > 0 && (crate::reseau::interface::une_carte_a_son_lien() || crate::reseau::minuteur_tcp_arme()) {
        return false;
    }
    let mut bloquees: Vec<Arc<Tache>> = Vec::new();
    // Un instantané : un réveil réussi pendant le parcours (par un autre
    // processeur, 6j) le périmerait ; on recommence alors.
    let reveils = tache::reveils();
    tache::pour_chaque(|t| {
        if t.est_programme() && t.dort_interruptible_maintenant() {
            let _ = bloquees.ajouter(t.clone());
        }
    });
    if tache::reveils() != reveils {
        return false;
    }
    let mut trouve = false;
    for t in bloquees {
        // Le réveil par le compare_exchange de son état, le verrou de sa fin
        // tenu (`forcer_apres`) : s'il réussit, elle dormait encore
        // interruptible, et c'est nous qui la tuons, la fin écrite avant
        // qu'elle puisse la regarder ; s'il échoue, quelqu'un l'a réveillée
        // entre-temps, et rien ne lui est prévu (jusqu'à 6i, la fin était
        // prévue avant le réveil, et une tâche réveillée normalement entre
        // les deux mourait quand même).
        if t.forcer_apres(crate::linux::SIGKILL, "plus rien ne peut le reveiller (interblocage)", || tache::reveiller(t.clone(), Reveil::Signal)) {
            trouve = true;
        }
    }
    trouve
}

/// Ce qui porte une file d'attente qu'un `Relais` peut écouter.
pub trait PorteFile {
    fn file_ecoutee(&self) -> &FileAttente;
}

/// Un relais (le `peer_wake` de la `unix_sock` de Linux, et
/// `unix_dgram_peer_wake_relay`) : une entrée de rappel qu'un objet inscrit
/// dans la file d'un AUTRE objet ; réveillée, elle réveille une file de son
/// propre objet (sa « cible »). Ainsi une socket AF_UNIX DGRAM qui attend
/// dans `poll` que la file pleine de son pair se vide est réveillée quand le
/// pair lit, sans que le pair la connaisse.
///
/// Épinglé dans sa boîte (`nouveau` le rend ainsi) : la file le désigne par
/// son adresse. Inscrit dans une seule file à la fois ; l'objet de cette
/// file est tenu (son Arc) tant qu'il y est : il ne peut pas disparaître
/// sous lui. La cible aussi est tenue, par un Arc (la file de l'objet qui
/// contient le relais vit dans un Arc, reseau/socket.rs) : jusqu'à la
/// relecture de 6j, un pointeur brut, que l'appelant devait promettre
/// valable ; tenue, elle ne peut pas être rendue sous le rappel, et
/// `inscrire` est sûr au sens de Rust. Retiré à sa destruction. La file
/// écoutée ne doit contenir QUE des relais (la `peer_wait` de Linux, à
/// part de la file de l'objet) : un relais qui réveillerait une file où
/// d'autres relais sont inscrits pourrait boucler.
pub struct Relais<T: PorteFile + 'static> {
    entree: EntreeAttente,
    cible: UnsafeCell<Option<Arc<FileAttente>>>,
    chez: Verrou<Option<Arc<T>>>,
}

// SAFETY: `entree` et `cible` ne sont touchées que par `inscrire` et
// `retirer` (sous le verrou `chez`, avant d'entrer dans la file écoutée ou
// après en être sorti) et par le rappel (sous le verrou de la file écoutée,
// où le relais n'est inscrit qu'entre les deux) : jamais deux à la fois.
unsafe impl<T: PorteFile + Send + Sync> Sync for Relais<T> {}
// SAFETY: voir ci-dessus.
unsafe impl<T: PorteFile + Send + Sync> Send for Relais<T> {}

impl<T: PorteFile + 'static> Relais<T> {
    /// Un relais neuf, pas inscrit, dans sa boîte ; None : plus de mémoire.
    pub fn nouveau() -> Option<Pin<alloc::boxed::Box<Relais<T>>>> {
        let r = Relais { entree: EntreeAttente::new(), cible: UnsafeCell::new(None), chez: Verrou::new(None) };
        crate::faillible::boite(r).ok().map(alloc::boxed::Box::into_pin)
    }

    /// Inscrit le relais dans la file de `chez`, pour réveiller `cible`
    /// (une file de l'objet qui contient le relais, tenue tant qu'il y est
    /// inscrit). Déjà inscrit chez lui : rien ; ailleurs : retiré d'abord.
    pub fn inscrire(self: Pin<&Self>, chez: &Arc<T>, cible: &Arc<FileAttente>) {
        let ancien = {
            let mut c = self.chez.verrouiller();
            if c.as_ref().is_some_and(|a| Arc::ptr_eq(a, chez)) {
                return;
            }
            let ancien = c.take();
            if let Some(a) = &ancien {
                a.file_ecoutee().enlever(&self.entree);
            }
            // SAFETY: sous `chez`, hors de toute file (voir `Sync`).
            unsafe { *self.cible.get() = Some(cible.clone()) };
            let qui: *const dyn Rappel = &*self;
            // SAFETY: le relais est épinglé (il ne bougera pas), et il se
            // retire de la file avant d'être détruit (`Drop`).
            unsafe { self.entree.preparer_rappel(qui, false) };
            // SAFETY: le relais est épinglé (`self: Pin<&Self>`).
            chez.file_ecoutee().ajouter(unsafe { Pin::new_unchecked(&self.entree) });
            *c = Some(chez.clone());
            ancien
        };
        // L'ancien objet rendu hors du verrou (son dernier Arc pourrait le
        // détruire).
        drop(ancien);
    }

    /// Retire le relais de la file où il est inscrit, s'il l'est.
    pub fn retirer(&self) {
        let (ancien, cible) = {
            let mut c = self.chez.verrouiller();
            let ancien = c.take();
            if let Some(a) = &ancien {
                a.file_ecoutee().enlever(&self.entree);
            }
            // SAFETY: sous `chez`, sorti de la file (voir `Sync`).
            let cible = unsafe { (*self.cible.get()).take() };
            (ancien, cible)
        };
        // Rendus hors du verrou (le dernier Arc de l'un ou de l'autre
        // pourrait le détruire).
        drop(ancien);
        drop(cible);
    }
}

impl<T: PorteFile + 'static> Rappel for Relais<T> {
    /// La file écoutée est réveillée : la cible l'est à son tour, avec la
    /// même clé.
    fn rappel(&self, cle: u32) -> bool {
        // SAFETY: sous le verrou de la file écoutée, où le relais est inscrit
        // (voir `Sync`) : `cible` a été posée avant, et ne bouge plus.
        if let Some(c) = unsafe { (*self.cible.get()).as_ref() } {
            c.reveiller(cle, 0);
        }
        false
    }
}

impl<T: PorteFile + 'static> Drop for Relais<T> {
    fn drop(&mut self) {
        self.retirer();
    }
}

/// Une entrée de rappel SÛRE (6j) : elle porte son rappel `R` et sait dans
/// quelle file elle est ; `inscrire` l'y met, `retirer` ou sa disparition
/// (`Drop`) l'en sort. Dans sa boîte, épinglée (`nouveau`) : la file la
/// désigne par son adresse. Sûre au sens de Rust : aucun usage, même
/// maladroit, ne peut en faire un comportement indéfini.
///   - `R: 'static` : ce que `R` désigne vit au moins autant qu'elle, même
///     oubliée (`mem::forget` d'une boîte épinglée ne rend jamais sa
///     mémoire : l'entrée reste dans la file, valable, une fuite et rien
///     de plus) ; `R` ne porte que des Arc ou des Weak (epoll.rs ;
///     sondage.rs met son `Attente` dans un Arc). Un emprunt plus court
///     aurait pu pendre après un `forget` (la relecture de 6j).
///   - la file vit tant que l'entrée y est : le possesseur tient son
///     fichier (sondage.rs, dans `R`) ou retire ses entrées avant qu'il ne
///     se ferme (epoll.rs) ; et une file détruite avec des entrées arrête
///     le noyau (`FileAttente::drop`) au lieu de laisser une entrée désigner
///     une mémoire rendue.
/// Ainsi epoll.rs et sondage.rs n'ont plus d'`unsafe` (jusqu'à 6j, ils
/// inscrivaient leurs entrées par des pointeurs bruts) : ce qu'il faut
/// vérifier est ici, en un seul endroit. Option écartée : des entrées
/// rangées par blocs de seize dans leur possesseur (le `poll_table_page` de
/// Linux, ce que faisait sondage.rs) : il faudrait projeter l'épinglage du
/// bloc sur chacune de ses entrées (ce que fait la crate `pin-project`), et
/// une boîte par entrée est plus simple à relire ; par blocs si une mesure
/// le demande (`claude` sonde par epoll, dont les éléments durent).
pub struct EntreeRappel<R: Rappel + 'static> {
    entree: EntreeAttente,
    /// La file où elle est inscrite (nulle : aucune). Un atomique : epoll
    /// retire les entrées d'un élément depuis la fermeture de son fichier,
    /// une autre tâche que celle qui les inscrit.
    file: AtomicPtr<FileAttente>,
    rappel: R,
}

impl<R: Rappel + 'static> EntreeRappel<R> {
    /// Une entrée neuve, pas inscrite, dans sa boîte ; None : plus de
    /// mémoire.
    pub fn nouveau(rappel: R) -> Option<Pin<alloc::boxed::Box<EntreeRappel<R>>>> {
        let e = EntreeRappel { entree: EntreeAttente::new(), file: AtomicPtr::new(core::ptr::null_mut()), rappel };
        crate::faillible::boite(e).ok().map(alloc::boxed::Box::into_pin)
    }

    /// L'inscrit dans `file`, exclusive ou non (voir `FileAttente`) ; déjà
    /// inscrite ailleurs : retirée d'abord.
    pub fn inscrire(self: Pin<&Self>, file: &FileAttente, exclusive: bool) {
        self.retirer();
        let qui: *const (dyn Rappel + 'static) = &self.rappel;
        // SAFETY: le rappel est dans l'entrée, épinglée (elle ne bougera
        // pas), qui se retire de sa file avant de disparaître (`Drop`), ou
        // n'en disparaît jamais si elle est oubliée ; et `R: 'static` : la
        // file ne désignera jamais un rappel mort.
        unsafe { self.entree.preparer_rappel(qui, exclusive) };
        self.file.store(core::ptr::from_ref(file).cast_mut(), Ordering::Relaxed);
        // SAFETY: l'entrée est un champ d'une valeur épinglée (`self`), que
        // rien ne déplace.
        file.ajouter(unsafe { Pin::new_unchecked(&self.entree) });
    }

    /// La retire de sa file, si elle y est.
    pub fn retirer(&self) {
        let file = self.file.swap(core::ptr::null_mut(), Ordering::Relaxed);
        // SAFETY: la file est celle d'un fichier que le possesseur tient
        // tant que l'entrée y est (voir le type) : elle existe encore.
        if let Some(f) = unsafe { file.as_ref() } {
            f.enlever(&self.entree);
        }
    }
}

impl<R: Rappel + 'static> Drop for EntreeRappel<R> {
    fn drop(&mut self) {
        self.retirer();
    }
}

/// TOURNER D'ABORD (6j) : une tâche qui trouve un verrou qui dort (un
/// Mutex, ou un VerrouLE qu'elle demande en écriture) pris par une tâche
/// qui S'EXÉCUTE EN CE MOMENT sur un autre processeur tourne,
/// interruptions actives et préemption coupée, tant que ce détenteur
/// s'exécute (`sur_processeur`) et tient encore le verrou, que personne
/// n'attend dans la file et que son propre processeur n'a pas besoin de
/// céder, et 25 µs au plus (`TOUR_AU_PLUS_NS`, mesuré) : le verrou sera
/// rendu dans quelques microsecondes, s'endormir et
/// être réveillé coûterait deux bascules (le `mutex_spin_on_owner` et le
/// `rwsem_spin_on_owner` de Linux, le cœur de son « optimistic spinning »).
/// Sans le vol de Linux : dès que quelqu'un attend, ou que le détenteur
/// dort, on se range, et le verrou est REMIS à qui attend, dans l'ordre
/// (pas de famine, donc pas de drapeau HANDOFF). Interruptions actives,
/// jamais coupées : le détenteur, qui vide des TLB vers ce processeur
/// (smp.rs), attendrait sinon notre réponse pour toujours. Le détenteur
/// est connu de deux façons : un Arc sous le verrou de l'état (il peut
/// rendre le verrou et mourir pendant qu'on le regarde : l'Arc le garde,
/// comme le `rcu_read_lock` autour de l'`owner` chez Linux), et son
/// adresse dans un atomique, lisible sans verrou, pour voir sans le
/// prendre qu'il a changé (rendu, ou remis à un autre). Options écartées :
/// tourner interruptions coupées (voir plus haut) ; tourner un temps fixe
/// (on ne sait pas si le détenteur avance) ; la file MCS de Linux
/// (`osq_lock`), qui n'en laisse tourner qu'un par verrou : nos tâches
/// prêtes se comptent sur les doigts.
static PRISES_EN_TOURNANT: AtomicU64 = AtomicU64::new(0);
static SOMMEILS: AtomicU64 = AtomicU64::new(0);

/// Combien de fois un verrou qui dort a été pris en tournant, et combien
/// de fois une tâche s'est endormie dessus, depuis la dernière lecture
/// (`make verrous`, et le test du démarrage).
pub fn compteurs_des_verrous_qui_dorment() -> (u64, u64) {
    (PRISES_EN_TOURNANT.swap(0, Ordering::Relaxed), SOMMEILS.swap(0, Ordering::Relaxed))
}

/// Pour `make verrous` : ces compteurs, pour `quoi` (le démarrage, un
/// programme).
#[cfg(feature = "verrous")]
pub fn afficher_compteurs(quoi: impl core::fmt::Display) {
    let (tours, sommeils) = compteurs_des_verrous_qui_dorment();
    crate::afficherln!("[verrous] {} : verrous qui dorment pris en tournant {} fois, en dormant {} fois.", quoi, tours, sommeils);
}

/// Peut-on tourner ici (« tourner d'abord ») ? Jamais interruptions
/// coupées, ni sur un seul processeur (le détenteur ne s'y exécute pas).
fn peut_tourner() -> bool {
    cpu::interruptions_actives() && processeur::nombre() > 1
}

/// Combien de temps on tourne au plus : 25 µs, le plafond de l'heuristique
/// de Linux pour tourner sur des lecteurs (`rwsem_rspin_threshold`). Sur
/// un détenteur, Linux ne se borne pas : il s'en remet à `need_resched` et
/// à `vcpu_is_preempted` (l'hyperviseur lui dit si le processeur virtuel
/// du détenteur est suspendu), que QEMU sans KVM ne fournit pas. Écart
/// mesuré : sans borne, les programmes de `make tests-qemu` mettaient
/// 27,5 s au lieu de 23,5 s sous QEMU (des sections critiques longues : une
/// ligne écrite sur le port série, la copie d'une lecture de fichier,
/// pendant lesquelles un processeur tournait au lieu d'exécuter une autre
/// tâche prête) ; bornée à 20 µs ou à 100 µs, 23,5 s, comme sans tourner
/// du tout. Le tour ne doit payer que les sections courtes, les seules où
/// il gagne ses deux bascules. Sans TSC fiable, l'heure est au tic : la
/// borne devient le prochain tic, 1 ms au plus (le `sched_clock` de Linux
/// sur un TSC instable suit de même les jiffies).
const TOUR_AU_PLUS_NS: u64 = 25_000;

/// Tourne tant que `d`, vu tenir le verrou, le tient encore (`qui` le dit
/// toujours), s'exécute sur un autre processeur, que personne n'attend,
/// que ce processeur n'a pas à céder et que `TOUR_AU_PLUS_NS` n'est pas
/// écoulé (l'horloge lue tous les 16 tours, le `!(++loop & 0xf)` de Linux).
/// Vrai si le détenteur a changé (le verrou est peut-être libre : à revoir
/// sous le verrou de l'état), faux s'il faut se ranger. Préemption coupée
/// par l'appelant. Relaxed partout : des indications, la décision se prend
/// sous le verrou de l'état.
fn tourner_sur(d: &Tache, qui: &AtomicPtr<Tache>, attendants: &AtomicU32) -> bool {
    let debut = crate::temps::ns_monotone();
    let mut tours = 0u32;
    loop {
        if !core::ptr::eq(qui.load(Ordering::Relaxed), d) {
            return true;
        }
        if !d.est_sur_processeur() || attendants.load(Ordering::Relaxed) != 0 || processeur::besoin_de_ceder() {
            return false;
        }
        tours = tours.wrapping_add(1);
        if tours & 0xf == 0 && crate::temps::ns_monotone().wrapping_sub(debut) > TOUR_AU_PLUS_NS {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Dort jusqu'à ce que celui qui rend le verrou nous le REMETTE en nous
/// sortant de la file (`dans_la_file` le lit sous le verrou de l'état) :
/// tant qu'on y est, on ne l'a pas. Un sommeil ininterruptible n'a pas
/// d'autre réveil ; revérifier ne coûte rien. « Je vais dormir » reposé à
/// chaque tour : un réveil resté d'un tour précédent ferait sinon revenir
/// `dormir` aussitôt, sans fin. Interruptions coupées par l'appelant.
fn dormir_jusqu_a_la_remise(t: &Tache, dans_la_file: impl Fn() -> bool) {
    SOMMEILS.fetch_add(1, Ordering::Relaxed);
    loop {
        dormir(None, Sommeil::Ininterruptible);
        if !dans_la_file() {
            break;
        }
        t.preparer_sommeil(Sommeil::Ininterruptible);
        if !dans_la_file() {
            break;
        }
    }
    t.reveille();
}

/// On va peut-être dormir : jamais sous un verrou court, ni dans un
/// gestionnaire d'interruption (le `might_sleep` de Linux). `ordonnancer`
/// refuserait le premier aussi, mais plus loin, sans dire qui ; ici, la
/// panique nomme l'appelant.
#[track_caller]
fn on_va_peut_etre_dormir() {
    let tenus = crate::verrou::tenus();
    assert!(tenus == 0, "verrou qui dort pris sous {} verrou(s) court(s)", tenus);
    assert!(!crate::interruptions::dans_une_interruption(), "verrou qui dort pris dans un gestionnaire d'interruption");
    // Ni entre « je vais dormir » et `dormir` : prendre un verrou qui dort
    // remet l'état « en cours », et le sommeil prévu serait perdu (le « do
    // not call blocking ops when !TASK_RUNNING » du `__might_sleep` de
    // Linux ; trouvé en 6j dans `poll`).
    assert!(tache::courante().sommeil_non_prepare(), "verrou qui dort pris entre \"je vais dormir\" et dormir");
}

/// Un verrou qui DORT (le `mutex` de Linux) : une tâche qui le trouve pris
/// tourne d'abord si le détenteur s'exécute ailleurs (voir plus haut), puis
/// s'endort, et celui qui le rend le REMET à la première qui attend (6j ;
/// jusque-là il le marquait libre et la réveillait, et un nouveau venu
/// pouvait passer devant elle). Pour ce qui peut durer (écrire une ligne
/// sur le port série), et jamais dans un gestionnaire d'interruption, ni
/// sous un Verrou (on ne dort pas en tenant un verrou qui coupe les
/// interruptions). Il ne coupe pas les interruptions : la tâche qui le
/// tient peut être préemptée.
pub struct Mutex<T> {
    etat: Verrou<EtatMutex>,
    /// Qui le tient (nul : libre), lisible sans le verrou de l'état par qui
    /// tourne (« tourner d'abord ») ; écrit sous lui, où `detenteur` tient
    /// l'Arc de la même tâche.
    qui: AtomicPtr<Tache>,
    /// Combien attendent dans la file : qui tourne se range dès qu'il y en
    /// a un. Écrit sous le verrou de l'état.
    attendants: AtomicU32,
    donnee: UnsafeCell<T>,
}

struct EtatMutex {
    file: FileAttente,
    /// Qui le tient : l'Arc qui le garde en vie pour qui tourne dessus.
    detenteur: Option<Arc<Tache>>,
}

// SAFETY: la donnée n'est touchée qu'à travers une GardeMutex, et le
// détenteur, posé sous le verrou de l'état, garantit qu'il n'en existe
// qu'une à la fois.
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(donnee: T) -> Mutex<T> {
        Mutex {
            etat: Verrou::new(EtatMutex { file: FileAttente::new(), detenteur: None }),
            qui: AtomicPtr::new(core::ptr::null_mut()),
            attendants: AtomicU32::new(0),
            donnee: UnsafeCell::new(donnee),
        }
    }

    /// Prend le verrou : en tournant, puis en dormant, tant qu'il est pris.
    #[track_caller]
    pub fn verrouiller(&self) -> GardeMutex<'_, T> {
        on_va_peut_etre_dormir();
        let t = tache::courante();
        if self.tourner(t) {
            return GardeMutex { mutex: self };
        }
        let interruptions = cpu::couper_interruptions();
        // « Je vais dormir » avant de regarder (l'en-tête).
        t.preparer_sommeil(Sommeil::Ininterruptible);
        {
            let mut e = self.etat.verrouiller();
            if self.qui.load(Ordering::Relaxed).is_null() {
                self.donner(&mut e, tache::courante_arc());
                drop(e);
                t.reveille();
                if interruptions {
                    cpu::activer_interruptions();
                }
                return GardeMutex { mutex: self };
            }
            // Exclusive, en queue : celui qui le rend le remet à la première
            // arrivée.
            e.file.inscrire_exclusive();
            self.attendants.fetch_add(1, Ordering::Relaxed);
        }
        dormir_jusqu_a_la_remise(t, || self.etat.verrouiller().file.contient(t));
        if interruptions {
            cpu::activer_interruptions();
        }
        GardeMutex { mutex: self }
    }

    /// Le donne à `a`, sous le verrou de l'état.
    fn donner(&self, e: &mut EtatMutex, a: Arc<Tache>) {
        self.qui.store(Arc::as_ptr(&a).cast_mut(), Ordering::Relaxed);
        e.detenteur = Some(a);
    }

    /// Tourne tant que le détenteur s'exécute ailleurs (« tourner
    /// d'abord »), et prend le verrou s'il est rendu pendant ce temps : vrai
    /// alors. Faux s'il faut se ranger.
    fn tourner(&self, moi: &Tache) -> bool {
        if !peut_tourner() {
            return false;
        }
        processeur::sans_preemption(|| {
            let mut a_tourne = false;
            loop {
                let detenteur = {
                    let mut e = self.etat.verrouiller();
                    // Quelqu'un attend : derrière lui (remis, jamais pris).
                    if self.attendants.load(Ordering::Relaxed) != 0 {
                        return false;
                    }
                    if self.qui.load(Ordering::Relaxed).is_null() {
                        self.donner(&mut e, tache::courante_arc());
                        if a_tourne {
                            PRISES_EN_TOURNANT.fetch_add(1, Ordering::Relaxed);
                        }
                        return true;
                    }
                    e.detenteur.clone()
                };
                // Pris : il a un détenteur (`donner`). Nous-mêmes : un Mutex
                // ne se reprend pas, l'interblocage se verra en dormant,
                // nommé par le détecteur.
                let Some(d) = detenteur else { return false };
                if core::ptr::eq(Arc::as_ptr(&d), moi) || !tourner_sur(&d, &self.qui, &self.attendants) {
                    return false;
                }
                a_tourne = true;
            }
        })
    }

    /// Prend le verrou s'il est libre, sans dormir (le `mutex_trylock` de
    /// Linux) : possible sous un Verrou.
    pub fn essayer(&self) -> Option<GardeMutex<'_, T>> {
        let mut e = self.etat.verrouiller();
        if !self.qui.load(Ordering::Relaxed).is_null() {
            return None;
        }
        self.donner(&mut e, tache::courante_arc());
        Some(GardeMutex { mutex: self })
    }
}

/// Tant qu'elle existe, on tient le Mutex.
pub struct GardeMutex<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Deref for GardeMutex<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: la garde prouve qu'on tient le Mutex.
        unsafe { &*self.mutex.donnee.get() }
    }
}

impl<T> DerefMut for GardeMutex<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, et &mut self garantit l'exclusivité locale.
        unsafe { &mut *self.mutex.donnee.get() }
    }
}

impl<T> Drop for GardeMutex<'_, T> {
    fn drop(&mut self) {
        let m = self.mutex;
        let mut e = m.etat.verrouiller();
        // Remis à la première qui attend, s'il y en a une : sortie de la
        // file (la preuve qu'elle l'a reçu, comme au `VerrouLE`),
        // détentrice, réveillée. Libre sinon.
        match e.file.retirer_premiere() {
            Some(t) => {
                m.attendants.fetch_sub(1, Ordering::Relaxed);
                m.donner(&mut e, t.clone());
                tache::reveiller(t, Reveil::Reveillee);
            }
            None => {
                e.detenteur = None;
                m.qui.store(core::ptr::null_mut(), Ordering::Relaxed);
            }
        }
    }
}

/// Un verrou qui dort, en LECTURE ou en ÉCRITURE (le `rw_semaphore` de
/// Linux) : plusieurs lecteurs à la fois, ou un seul écrivain. Pour ce que
/// beaucoup lisent et peu changent, longtemps parfois : la mémoire d'un
/// processus (son `mmap_lock`, processus.rs), que lisent toutes les fautes
/// de page de ses fils, et que changent mmap, munmap, mprotect.
///
/// Comme le `Mutex`, il ne coupe pas les interruptions (celui qui le tient
/// peut être préempté, ou fauter), ne se prend jamais sous un `Verrou` ni
/// dans un gestionnaire d'interruption, et une tâche qui le trouve pris
/// s'endort. Ce qui change, c'est qui passe, et dans quel ordre :
///   - une seule file, dans l'ordre d'arrivée, chaque entrée marquée
///     LECTEUR ou ECRIVAIN ;
///   - qui arrive alors que quelqu'un attend se range dans la file, même un
///     lecteur quand des lecteurs tiennent le verrou : sinon un flot de
///     lecteurs (les fautes de page de plusieurs fils) ferait attendre un
///     écrivain (un munmap) sans fin ;
///   - à la libération, si la première qui attend est un écrivain, elle
///     reçoit le verrou ; si c'est un lecteur, TOUS les lecteurs de la file
///     le reçoivent ensemble (256 au plus, MAX_READERS_WAKEUP), où qu'ils
///     soient, les écrivains gardant leur place (la « phase » des lecteurs
///     du « phase-fair » de Linux) ;
///   - le verrou est REMIS à qui est réveillé, déjà compté : il n'a pas à
///     le reprendre. Être sorti de la file, sous le verrou de l'état, est
///     la preuve qu'on l'a reçu (le `waiter.task` remis à NULL de Linux) ;
///     l'attente est ininterruptible, aucun autre réveil ne la finit ;
///   - `retrograder` (le `downgrade_write`) : l'écrivain devient lecteur
///     sans rendre le verrou, et si un lecteur est en tête de la file, tous
///     les lecteurs de la file entrent avec lui (la faute de page qui a dû
///     étendre la pile, en écriture, finit en lecture).
///
/// C'est la politique de Linux 6.18 (`kernel/locking/rwsem.c`) pour les
/// lecteurs. Pour les écrivains, un écart : Linux réveille l'écrivain en
/// tête sans lui remettre le verrou, et le laisse se le faire voler (par un
/// autre écrivain, ou un lecteur qui arrive alors qu'il est libre) jusqu'à
/// ce qu'il ait attendu 4 ms (RWSEM_WAIT_TIMEOUT : le drapeau HANDOFF le lui
/// réserve alors). Le vol évite, sur plusieurs processeurs, d'attendre que
/// la tâche réveillée soit choisie : celle qui tourne déjà continue. Chez
/// nous, qui arrive tourne AVANT de se ranger (« tourner d'abord », avant
/// le `Mutex`), tant que l'écrivain qui tient le verrou s'exécute : c'est
/// là que Linux gagne l'essentiel. Une fois dans la file, la remise
/// stricte coûte une bascule à chaque libération disputée entre écrivains
/// (un « convoi »), et ne laisse jamais attendre personne plus que son
/// rang. Écrit pour le relire simplement, et sans ce drapeau.
///
/// Options écartées :
///   - réveiller et laisser retenter (ce que faisait le `Mutex` d'ici
///     jusqu'à 6j, pour le premier de sa file) : les lecteurs se
///     bousculeraient ;
///   - la priorité aux écrivains (un lecteur n'entre jamais tant qu'un
///     écrivain attend, même derrière des lecteurs) : ce sont alors les
///     lecteurs qui peuvent attendre sans fin ;
///   - un verrou à attente active en lecture et écriture (le `rwlock_t` de
///     Linux) : il coupe les interruptions, c'est justement ce qu'on quitte ;
///   - un sommeil « tuable » (`mmap_read_lock_killable`, TASK_KILLABLE),
///     qu'un signal mortel interrompt : chez Linux, celui qui tient la
///     mémoire d'un processus peut attendre le disque (une faute de page
///     d'un fichier), et le tueur OOM doit pouvoir arrêter ceux qui
///     attendent derrière lui ; chez nous, celui qui la tient n'attend
///     jamais rien d'autre (pas de disque avant 6m, et une allocation qui
///     manque échoue au lieu d'attendre) : l'attente est toujours courte.
///     Avec le disque (6m).
/// Un ÉCRIVAIN qui le trouve tenu par un écrivain qui s'exécute ailleurs
/// tourne d'abord (« tourner d'abord », avant le `Mutex` : le
/// `rwsem_optimistic_spin` de Linux, sans le vol). Un LECTEUR ne tourne
/// pas, il se range : Linux l'a retiré en 5.11 (« locking/rwsem: Remove
/// reader optimistic spinning » : le tour des lecteurs les favorisait aux
/// dépens des écrivains, et ralentissait des programmes), et notre mesure
/// le confirme : avec des lecteurs qui tournent, les programmes de test de
/// `make tests-qemu` (dont `fautes`, quatre fils qui fautent face à deux
/// qui changent la carte) mettaient 27,5 s au lieu de 24 s sous QEMU.
/// L'écrivain ne tourne pas non plus sur des lecteurs (Linux, si : 10 à
/// 25 µs, une heuristique) : ils ne sont pas notés.
pub struct VerrouLE<T> {
    etat: Verrou<EtatLE>,
    /// L'écrivain qui le tient (nul : aucun), lisible sans le verrou de
    /// l'état par qui tourne ; écrit sous lui, où `detenteur` tient son
    /// Arc. Les lecteurs qui le tiennent ne sont pas notés : nombreux,
    /// peut-être endormis, on ne tourne pas sur eux (Linux non plus, hors
    /// un essai borné).
    ecrivain_qui: AtomicPtr<Tache>,
    /// Combien attendent dans la file (écrit sous le verrou de l'état).
    attendants: AtomicU32,
    donnee: UnsafeCell<T>,
}

struct EtatLE {
    /// Les lecteurs qui le tiennent.
    lecteurs: u32,
    /// L'écrivain qui le tient : l'Arc qui le garde en vie pour qui tourne
    /// dessus.
    detenteur: Option<Arc<Tache>>,
    /// Ceux qui attendent, dans l'ordre d'arrivée, marqués LECTEUR ou
    /// ECRIVAIN.
    file: FileAttente,
}

/// Les marques des entrées de la file d'un `VerrouLE`.
const LECTEUR: u32 = 1;
const ECRIVAIN: u32 = 2;
/// Les lecteurs qui reçoivent le verrou à une même libération, au plus
/// (le MAX_READERS_WAKEUP de Linux) : un réveil reste borné.
const LECTEURS_PAR_REVEIL: u32 = 256;

// SAFETY: la donnée n'est touchée qu'à travers une garde : partagée (&T)
// entre des lecteurs, qui peuvent être sur des tâches différentes (d'où
// T: Sync), ou à un seul écrivain (&mut T, d'où T: Send) ; l'état compte
// les gardes sous son verrou.
unsafe impl<T: Send + Sync> Sync for VerrouLE<T> {}

impl EtatLE {
    /// Peut-on le prendre tout de suite, pour `sorte` ? Libre pour elle, et
    /// personne qui attende (on ne passe pas devant la file).
    fn libre_pour(&self, sorte: u32) -> bool {
        let libre = self.detenteur.is_none() && (sorte == LECTEUR || self.lecteurs == 0);
        libre && !self.file.active()
    }
}

impl<T> VerrouLE<T> {
    pub const fn new(donnee: T) -> VerrouLE<T> {
        VerrouLE {
            etat: Verrou::new(EtatLE { lecteurs: 0, detenteur: None, file: FileAttente::new() }),
            ecrivain_qui: AtomicPtr::new(core::ptr::null_mut()),
            attendants: AtomicU32::new(0),
            donnee: UnsafeCell::new(donnee),
        }
    }

    /// Le donne pour `sorte` à la tâche `a`, sous le verrou de l'état.
    fn accorder(&self, e: &mut EtatLE, sorte: u32, a: Arc<Tache>) {
        if sorte == LECTEUR {
            e.lecteurs += 1;
        } else {
            self.ecrivain_qui.store(Arc::as_ptr(&a).cast_mut(), Ordering::Relaxed);
            e.detenteur = Some(a);
        }
    }

    /// L'écrivain le lâche (il le rend, ou devient lecteur).
    fn lacher_ecriture(&self, e: &mut EtatLE) {
        e.detenteur = None;
        self.ecrivain_qui.store(core::ptr::null_mut(), Ordering::Relaxed);
    }

    /// Sort de la file la première tâche de marque `marque`, qui va
    /// recevoir le verrou.
    fn sortir(&self, e: &mut EtatLE, marque: u32) -> Option<Arc<Tache>> {
        let t = e.file.retirer_marquee(marque)?;
        self.attendants.fetch_sub(1, Ordering::Relaxed);
        Some(t)
    }

    /// Les lecteurs qui attendent reçoivent le verrou, tous ensemble (256
    /// au plus), où qu'ils soient dans la file : comptés d'abord, réveillés
    /// ensuite (ils ne s'exécuteront qu'après nous, interruptions coupées).
    fn remettre_aux_lecteurs(&self, e: &mut EtatLE) {
        for _ in 0..LECTEURS_PAR_REVEIL {
            let Some(t) = self.sortir(e, LECTEUR) else { break };
            e.lecteurs += 1;
            tache::reveiller(t, Reveil::Reveillee);
        }
    }

    /// Le verrou vient d'être rendu par le dernier qui le tenait : il passe
    /// à la file (le `rwsem_mark_wake` de Linux, RWSEM_WAKE_ANY).
    fn passer_la_main(&self, e: &mut EtatLE) {
        match e.file.marque_en_tete() {
            Some(ECRIVAIN) => {
                if let Some(t) = self.sortir(e, ECRIVAIN) {
                    self.accorder(e, ECRIVAIN, t.clone());
                    tache::reveiller(t, Reveil::Reveillee);
                }
            }
            Some(_) => self.remettre_aux_lecteurs(e),
            None => {}
        }
    }

    /// Pour un écrivain : tourne tant que l'écrivain qui le tient
    /// s'exécute ailleurs (« tourner d'abord »), et le prend s'il devient
    /// libre pendant ce temps : vrai alors. Faux s'il faut se ranger (dont :
    /// des lecteurs le tiennent, on ne tourne pas sur eux).
    fn tourner(&self, sorte: u32, moi: &Tache) -> bool {
        if !peut_tourner() {
            return false;
        }
        processeur::sans_preemption(|| {
            let mut a_tourne = false;
            loop {
                let detenteur = {
                    let mut e = self.etat.verrouiller();
                    if e.libre_pour(sorte) {
                        self.accorder(&mut e, sorte, tache::courante_arc());
                        if a_tourne {
                            PRISES_EN_TOURNANT.fetch_add(1, Ordering::Relaxed);
                        }
                        return true;
                    }
                    if self.attendants.load(Ordering::Relaxed) != 0 {
                        return false;
                    }
                    e.detenteur.clone()
                };
                let Some(d) = detenteur else { return false };
                if core::ptr::eq(Arc::as_ptr(&d), moi) || !tourner_sur(&d, &self.ecrivain_qui, &self.attendants) {
                    return false;
                }
                a_tourne = true;
            }
        })
    }

    /// Le prend en lecture, en dormant tant qu'il le faut.
    #[track_caller]
    pub fn lire(&self) -> GardeLecture<'_, T> {
        self.prendre(LECTEUR);
        GardeLecture { verrou: self }
    }

    /// Le prend en écriture, en dormant tant qu'il le faut.
    #[track_caller]
    pub fn ecrire(&self) -> GardeEcriture<'_, T> {
        self.prendre(ECRIVAIN);
        GardeEcriture { verrou: self }
    }

    /// Le prend en lecture s'il est libre pour elle, sans dormir (le
    /// `down_read_trylock` de Linux) : possible sous un `Verrou`.
    pub fn essayer_lire(&self) -> Option<GardeLecture<'_, T>> {
        // `then`, pas `then_some` : la garde ne doit exister que si le
        // verrou est pris (la détruire le rendrait).
        self.essayer(LECTEUR).then(|| GardeLecture { verrou: self })
    }

    /// Le prend en écriture s'il est libre, sans dormir.
    pub fn essayer_ecrire(&self) -> Option<GardeEcriture<'_, T>> {
        self.essayer(ECRIVAIN).then(|| GardeEcriture { verrou: self })
    }

    /// Le nombre de tâches qui attendent (pour les tests).
    pub fn en_attente(&self) -> usize {
        self.etat.verrouiller().file.longueur()
    }

    fn essayer(&self, sorte: u32) -> bool {
        let mut e = self.etat.verrouiller();
        let libre = e.libre_pour(sorte);
        if libre {
            self.accorder(&mut e, sorte, tache::courante_arc());
        }
        libre
    }

    /// Le prend pour `sorte`, en dormant tant qu'il le faut.
    #[track_caller]
    fn prendre(&self, sorte: u32) {
        on_va_peut_etre_dormir();
        let t = tache::courante();
        if sorte == ECRIVAIN && self.tourner(sorte, t) {
            return;
        }
        let interruptions = cpu::couper_interruptions();
        // « Je vais dormir » avant de regarder (l'en-tête).
        t.preparer_sommeil(Sommeil::Ininterruptible);
        {
            let mut e = self.etat.verrouiller();
            if e.libre_pour(sorte) {
                self.accorder(&mut e, sorte, tache::courante_arc());
                drop(e);
                t.reveille();
                if interruptions {
                    cpu::activer_interruptions();
                }
                return;
            }
            e.file.inscrire_marquee(sorte);
            self.attendants.fetch_add(1, Ordering::Relaxed);
        }
        // Celui qui le rend nous le remet en nous retirant de la file
        // (`passer_la_main`).
        dormir_jusqu_a_la_remise(t, || self.etat.verrouiller().file.contient(t));
        if interruptions {
            cpu::activer_interruptions();
        }
    }

    /// Un lecteur le rend.
    fn rendre_lecture(&self) {
        let mut e = self.etat.verrouiller();
        e.lecteurs -= 1;
        if e.lecteurs == 0 {
            self.passer_la_main(&mut e);
        }
    }

    /// L'écrivain le rend.
    fn rendre_ecriture(&self) {
        let mut e = self.etat.verrouiller();
        self.lacher_ecriture(&mut e);
        self.passer_la_main(&mut e);
    }
}

/// Tant qu'elle existe, on tient le `VerrouLE` en lecture.
pub struct GardeLecture<'a, T> {
    verrou: &'a VerrouLE<T>,
}

impl<T> Deref for GardeLecture<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: la garde prouve qu'on le tient en lecture : personne ne
        // l'a en écriture.
        unsafe { &*self.verrou.donnee.get() }
    }
}

impl<T> Drop for GardeLecture<'_, T> {
    fn drop(&mut self) {
        self.verrou.rendre_lecture();
    }
}

/// Tant qu'elle existe, on tient le `VerrouLE` en écriture.
pub struct GardeEcriture<'a, T> {
    verrou: &'a VerrouLE<T>,
}

impl<'a, T> GardeEcriture<'a, T> {
    /// L'écrivain devient lecteur, sans rendre le verrou entre les deux (le
    /// `downgrade_write` de Linux) : les lecteurs en tête de la file entrent
    /// avec lui ; un écrivain en tête, lui, attend la fin de tous.
    pub fn retrograder(self) -> GardeLecture<'a, T> {
        let verrou = self.verrou;
        // Le verrou n'est pas rendu : la garde d'écriture disparaît sans
        // son Drop, la garde de lecture prend sa place.
        core::mem::forget(self);
        let mut e = verrou.etat.verrouiller();
        verrou.lacher_ecriture(&mut e);
        e.lecteurs += 1;
        if e.file.marque_en_tete() == Some(LECTEUR) {
            verrou.remettre_aux_lecteurs(&mut e);
        }
        GardeLecture { verrou }
    }
}

impl<T> Deref for GardeEcriture<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: la garde prouve qu'on le tient en écriture, seul.
        unsafe { &*self.verrou.donnee.get() }
    }
}

impl<T> DerefMut for GardeEcriture<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, et &mut self garantit l'exclusivité locale.
        unsafe { &mut *self.verrou.donnee.get() }
    }
}

impl<T> Drop for GardeEcriture<'_, T> {
    fn drop(&mut self) {
        self.verrou.rendre_ecriture();
    }
}

/// Ce que doit savoir faire la donnée d'une `Possession` : traiter un
/// élément mis de côté pendant qu'un appel la possédait (un segment reçu),
/// et un minuteur échu pendant ce temps ; puis recopier son premier étage.
pub trait Possede {
    /// Le premier étage : ce qui se lit sous le verrou court, même quand
    /// un autre possède (l'état, ce qui est lisible... : `poll`).
    type Court;
    /// Ce que la réception met de côté (un segment).
    type Element;
    /// Traite `e` : par la réception sous le verrou court quand personne ne
    /// possède, ou par le possesseur qui rend la possession, SANS le verrou
    /// court.
    fn traiter(&mut self, e: Self::Element);
    /// Fait le travail d'un minuteur échu (de même).
    fn minuteur(&mut self);
    /// Recopie le premier étage, sous le verrou court ; rend les
    /// événements à réveiller dans la file de la possession (0 : rien).
    fn publier(&self, court: &mut Self::Court) -> u32;
    /// Le sens inverse : ce que `poll`, qui ne possède pas, a laissé au
    /// premier étage pour la donnée (SOCK_NOSPACE), pris juste avant de traiter
    /// ce qui arrive.
    fn descendre(&mut self, court: &mut Self::Court);
}

struct Court<U, B> {
    possede: bool,
    premier: U,
    /// La file `backlog` de Linux, et sa taille (en unités de l'appelant).
    file: alloc::collections::VecDeque<B>,
    taille: usize,
    /// Un minuteur est tombé pendant qu'on possédait (le
    /// `TCP_*_TIMER_DEFERRED` de Linux) : un drapeau, jamais perdu.
    minuteur: bool,
}

/// La possession d'une socket (le `lock_sock` de Linux, et sa file
/// `backlog`), pour TCP.
///
/// Deux étages, comme 6g pour UDP. Le PREMIER (`Court`) se lit et s'écrit
/// sous un verrou court (`Verrou`, interruptions coupées), par tous : la
/// réception, `poll`, epoll. Le SECOND (`T`, la connexion entière) n'est
/// touché que par qui POSSÈDE la socket (un appel du programme, qui peut y
/// dormir, s'y faire interrompre, fauter dans une copie), ou par la
/// réception quand personne ne possède, sous le verrou court. Ce qui
/// arrive pendant une possession va dans la FILE (le `backlog`) : la
/// possession rendue la vide (le `release_sock`), jusqu'à la trouver vide
/// (ce qu'elle émet par `lo` peut y remettre quelque chose). C'est
/// obligatoire ici : par `lo`, la réponse de l'autre côté revient dans
/// l'appel même qui possède la socket, qui ne peut ni l'attendre ni la
/// traiter au milieu de son propre travail.
///
/// Option écartée : le `Mutex` de 6g. La tâche du réseau dormirait sur un
/// appel du programme, et la réponse revenue par `lo` dans l'appel qui
/// tient le Mutex s'interbloquerait.
pub struct Possession<T: Possede> {
    court: Verrou<Court<T::Court, T::Element>>,
    donnee: UnsafeCell<T>,
    /// Ceux qui attendent la possession (exclusifs : une seule passe).
    attente: FileAttente,
    /// Ceux qui attendent la socket elle-même (lecteurs, écrivains, poll,
    /// epoll : le `sk_wq`), réveillés de ce que rendent `traiter` et
    /// `minuteur`.
    pub(crate) file: FileAttente,
    /// Ceux qui veulent un signal (`socket_wq`, avec `file`) : la réception les atteint d'ici.
    pub(crate) asynchrone: crate::asynchrone::ListeAsync,
}

// SAFETY: la donnée n'est touchée que par le possesseur (au plus un, par
// `possede`), ou sous le verrou court quand personne ne possède.
unsafe impl<T: Possede + Send> Sync for Possession<T> where T::Court: Send, T::Element: Send {}
// SAFETY: voir ci-dessus.
unsafe impl<T: Possede + Send> Send for Possession<T> where T::Court: Send, T::Element: Send {}

impl<T: Possede> Possession<T> {
    pub fn new(donnee: T, premier: T::Court) -> Possession<T> {
        Possession {
            court: Verrou::new(Court { possede: false, premier, file: alloc::collections::VecDeque::new(), taille: 0, minuteur: false }),
            donnee: UnsafeCell::new(donnee),
            attente: FileAttente::new(),
            file: FileAttente::new(),
            asynchrone: crate::asynchrone::ListeAsync::new(),
        }
    }

    /// Prend la possession (le `lock_sock`), en dormant tant qu'un autre
    /// l'a (ininterruptible : comme Linux, un `lock_sock` ne s'interrompt
    /// pas ; la possession est toujours courte).
    pub fn posseder(&self) -> Garde<'_, T> {
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        loop {
            // « Je vais dormir » avant de regarder (l'en-tête).
            t.preparer_sommeil(Sommeil::Ininterruptible);
            {
                let mut c = self.court.verrouiller();
                if !c.possede {
                    c.possede = true;
                    break;
                }
                self.attente.inscrire_exclusive();
            }
            dormir(None, Sommeil::Ininterruptible);
            self.attente.retirer(t);
        }
        t.reveille();
        if interruptions {
            cpu::activer_interruptions();
        }
        Garde { p: self }
    }

    /// Lit le premier étage, sous le verrou court (pour `poll`).
    pub fn court<R>(&self, f: impl FnOnce(&mut T::Court) -> R) -> R {
        f(&mut self.court.verrouiller().premier)
    }

    /// Ce que la réception a pour la donnée : traité tout de suite sous le
    /// verrou court si personne ne possède ; sinon mis dans la file (taille
    /// `taille`, refusé au-delà de `limite` : jeté, comme `sk_add_backlog`).
    /// Rend faux si l'élément est jeté.
    pub fn du_reseau(&self, e: T::Element, taille: usize, limite: usize) -> bool {
        let mut c = self.court.verrouiller();
        if c.possede {
            if c.taille + taille > limite || c.file.ajouter_derriere(e).is_err() {
                return false;
            }
            c.taille += taille;
            return true;
        }
        // SAFETY: personne ne possède, et le verrou court est tenu : nul
        // autre ne touche la donnée.
        let d = unsafe { &mut *self.donnee.get() };
        d.descendre(&mut c.premier);
        d.traiter(e);
        let m = d.publier(&mut c.premier);
        drop(c);
        self.reveiller(m);
        true
    }

    /// Réveille la file de la socket pour les événements `m` ; puis les signaux d'entrée-sortie
    /// (les bits A_* : ceux à qui parle `sk_wake_async`, après `wake_up`, comme Linux).
    fn reveiller(&self, m: u32) {
        let poll = m & !crate::asynchrone::A_TOUS;
        if poll != 0 {
            self.file.reveiller(poll, 0);
        }
        if m != poll {
            self.asynchrone.evenements(m);
        }
    }

    /// Un minuteur échu : son travail tout de suite si personne ne
    /// possède, sinon un drapeau que la possession rendue verra.
    pub fn minuteur_du_reseau(&self) {
        let mut c = self.court.verrouiller();
        if c.possede {
            c.minuteur = true;
            return;
        }
        // SAFETY: comme `du_reseau`.
        let d = unsafe { &mut *self.donnee.get() };
        d.minuteur();
        let m = d.publier(&mut c.premier);
        drop(c);
        self.reveiller(m);
    }

    /// Rend la possession (le `release_sock`) : la file prise sous le
    /// verrou court, puis vidée et les minuteurs différés faits SANS lui, en
    /// possédant encore, comme le `__release_sock` de Linux ; jusqu'à ne
    /// plus rien trouver ; puis la possession rendue, et le suivant
    /// réveillé. Sans le verrou court parce que ce traitement émet : par
    /// `lo`, la réponse de l'autre côté peut revenir aussitôt à cette
    /// socket, et doit trouver le verrou libre (elle va dans la file, que
    /// le tour suivant reprend) ; sous le verrou, ce serait une panique
    /// (« verrou deja pris »).
    fn rendre(&self) {
        let mut m = 0;
        loop {
            let (mut file, minuteur) = {
                let mut c = self.court.verrouiller();
                if c.file.is_empty() && !c.minuteur {
                    c.possede = false;
                    c.taille = 0;
                    break;
                }
                c.taille = 0;
                // SAFETY: nous possédons : nul autre ne touche la donnée.
                unsafe { &mut *self.donnee.get() }.descendre(&mut c.premier);
                (core::mem::take(&mut c.file), core::mem::take(&mut c.minuteur))
            };
            // SAFETY: nous possédons : nul autre ne touche la donnée (la
            // réception, qui voit `possede`, met ce qui arrive dans la file).
            let d = unsafe { &mut *self.donnee.get() };
            while let Some(e) = file.pop_front() {
                d.traiter(e);
            }
            if minuteur {
                d.minuteur();
            }
            let mut c = self.court.verrouiller();
            m |= d.publier(&mut c.premier);
            // La place de la file revient, si rien n'y est arrivé entre-temps.
            if c.file.is_empty() {
                c.file = file;
            }
        }
        self.reveiller(m);
        self.attente.reveiller_une();
    }
}

/// Tant qu'elle existe, on possède.
pub struct Garde<'a, T: Possede> {
    p: &'a Possession<T>,
}

impl<'a, T: Possede> Garde<'a, T> {
    /// La donnée.
    pub fn donnee(&mut self) -> &mut T {
        // SAFETY: la garde prouve qu'on possède ; `&mut self` garantit
        // l'exclusivité locale.
        unsafe { &mut *self.p.donnee.get() }
    }

    /// La donnée et le premier étage ensemble, sous le verrou court.
    pub fn avec_court<R>(&mut self, f: impl FnOnce(&mut T, &mut T::Court) -> R) -> R {
        let mut c = self.p.court.verrouiller();
        // SAFETY: on possède.
        f(unsafe { &mut *self.p.donnee.get() }, &mut c.premier)
    }

    /// Recopie le premier étage par `f` (qui rend les événements à
    /// réveiller), puis réveille.
    pub fn publier(&mut self, f: impl FnOnce(&mut T, &mut T::Court) -> u32) {
        let m = self.avec_court(f);
        self.p.reveiller(m);
    }

    /// Attend que `pret` soit vrai du premier étage, au plus jusqu'à
    /// `echeance`, en rendant la possession pendant l'attente (sinon ce
    /// qui finirait l'attente resterait dans la file) : la possession
    /// rendue (ce qui vide la file, et peut tout changer), puis,
    /// interruptions coupées, la condition vérifiée sous le verrou court,
    /// l'inscription dans `file`, le sommeil ; réveillée, la possession
    /// reprise. La possession est rendue AVANT de s'inscrire (Linux,
    /// `sk_wait_event`, s'inscrit d'abord puis rend) : le vidage de la file
    /// qu'elle fait peut tout changer, et la condition est revue après ;
    /// avec « je vais dormir » posé avant elle (l'en-tête), l'ordre
    /// n'importe plus pour les réveils. Rend la raison du réveil (Reveillee
    /// si la condition est vraie).
    pub fn attendre(&mut self, file: &FileAttente, sommeil: Sommeil, echeance: Option<u64>,
                    mut pret: impl FnMut(&T::Court) -> bool) -> Reveil {
        self.p.rendre();
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        let r = loop {
            t.preparer_sommeil(sommeil);
            {
                let c = self.p.court.verrouiller();
                if pret(&c.premier) {
                    break Reveil::Reveillee;
                }
                if sommeil == Sommeil::Interruptible && tache::signal_en_attente() {
                    break Reveil::Signal;
                }
                if echeance.is_some_and(|e| e <= crate::temps::ns_monotone()) {
                    break Reveil::Echeance;
                }
                file.inscrire();
            }
            let r = dormir(echeance, sommeil);
            file.retirer(&t);
            if r != Reveil::Reveillee {
                let c = self.p.court.verrouiller();
                break if pret(&c.premier) { Reveil::Reveillee } else { r };
            }
        };
        t.reveille();
        if interruptions {
            cpu::activer_interruptions();
        }
        // La possession reprise (le Garde reste valable).
        let g = self.p.posseder();
        core::mem::forget(g);
        r
    }
}

impl<T: Possede> Drop for Garde<'_, T> {
    fn drop(&mut self) {
        self.p.rendre();
    }
}
