//! Dormir et se réveiller : les files d'attente, les minuteries, le
//! verrou qui dort.
//!
//! Une tâche qui attend quelque chose (un caractère du clavier, un verrou
//! tenu par une autre, une échéance) quitte la file des prêtes de
//! l'ordonnanceur et ne prend plus le processeur ; celle qui rend la chose
//! disponible la réveille. C'est le couple `prepare_to_wait` /
//! `wake_up` de Linux, et la difficulté est toujours la même : ne pas
//! PERDRE de réveil. Si la tâche vérifie « rien à lire », puis qu'un
//! caractère arrive et qu'on la réveille AVANT qu'elle se soit endormie,
//! elle s'endort ensuite pour toujours. La règle, ici :
//!   1. couper les interruptions ;
//!   2. sous le verrou de l'objet attendu, vérifier la condition, et sinon
//!      s'inscrire dans sa file ;
//!   3. rendre le verrou, les interruptions restant coupées ;
//!   4. dormir (`dormir`), qui quitte la file des prêtes et cède le
//!      processeur ;
//!   5. réveillée, se retirer de la file si elle y est encore (réveillée
//!      par une échéance ou un signal), et revérifier.
//! UNIPROCESSEUR : les interruptions coupées de 1 à 4 tiennent lieu de
//! verrou : personne ne peut s'exécuter entre la vérification et le
//! sommeil, ni le gestionnaire qui réveillerait, ni une autre tâche. Avec
//! plusieurs processeurs, le verrou de la file (et l'état de la tâche,
//! changé avant de vérifier, comme `set_current_state` chez Linux).
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
use crate::processus::Entree;
use crate::tache::{self, Reveil, Tache};
use crate::verrou::Verrou;
use alloc::vec::Vec;
use core::cell::{Cell, UnsafeCell};
use core::marker::PhantomPinned;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;

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

// SAFETY : une entrée n'est lue et écrite que par qui l'inscrit, avant de
// l'inscrire et après l'avoir retirée, et sous le verrou de sa file entre
// les deux.
unsafe impl Sync for EntreeAttente {}
unsafe impl Send for EntreeAttente {}

impl EntreeAttente {
    /// Une entrée de tâche (celle de chaque `Tache`), pas encore inscrite.
    pub const fn new() -> EntreeAttente {
        EntreeAttente {
            suivante: Cell::new(core::ptr::null()),
            exclusive: Cell::new(false),
            inscrite: Cell::new(false),
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

// SAFETY : la liste n'est touchée que sous son verrou, et ses entrées
// restent à leur place tant qu'elles y sont (dans leur tâche, ou épinglées).
unsafe impl Send for Liste {}

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
        // SAFETY : les entrées de la liste sont valables (dans leur tâche tenue, ou épinglées).
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
        // SAFETY : comme `placer`.
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
        // SAFETY : comme `placer`.
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
        // SAFETY : comme `inscrire_tache_en`.
        let e = unsafe { (*p).entree_attente() };
        let mut l = self.liste.verrouiller();
        e.genre.set(Genre::Tache(p));
        e.exclusive.set(true);
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
        // Un Arc de plus, tenu par la file : la tâche vit tant qu'elle y est.
        let p = Arc::into_raw(t);
        // SAFETY : `p` vient d'être tenu ; une tâche n'attend qu'une chose à
        // la fois, son entrée est donc libre (`placer` le vérifie).
        let e = unsafe { (*p).entree_attente() };
        let mut l = self.liste.verrouiller();
        e.genre.set(Genre::Tache(p));
        e.exclusive.set(exclusive);
        l.placer(e);
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
        // SAFETY : l'Arc pris par `inscrire_tache_en`, tenu par la file
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
            // SAFETY : la tâche d'une entrée inscrite est tenue par la file.
            n += tache_de(e).is_some_and(|t| choisir(unsafe { &*t })) as usize;
            false
        });
        n
    }

    /// Retire de la file la première tâche pour qui `choisir` est vrai, et
    /// la rend (avec l'Arc que tenait la file).
    pub fn retirer_si(&self, mut choisir: impl FnMut(&Tache) -> bool) -> Option<Arc<Tache>> {
        let mut l = self.liste.verrouiller();
        // SAFETY : comme `compter` ; l'entrée trouvée est inscrite.
        let (precedente, e) = l.chercher(|e| tache_de(e).is_some_and(|t| choisir(unsafe { &*t })))?;
        Some(Self::sortir_tache(&mut l, precedente, unsafe { &*e }))
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
        let mut l = self.liste.verrouiller();
        let mut reste = exclusives;
        let mut precedente: *const EntreeAttente = core::ptr::null();
        let mut p = l.tete;
        // SAFETY : comme `Liste::placer`.
        while let Some(e) = unsafe { p.as_ref() } {
            let suivante = e.suivante.get();
            let reveille = match e.genre.get() {
                Genre::Tache(t) => {
                    // SAFETY : l'Arc de la file tient la tâche ; on en
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
                // SAFETY : `qui` reste valable tant que l'entrée est
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
/// interruptible. Interruptions coupées, aucun verrou tenu, et la tâche
/// déjà inscrite dans la file de ce qu'elle attend (voir l'en-tête) ;
/// revient interruptions coupées. Pour qu'un verrou ne soit pas tenu
/// pendant le sommeil, ordonnancer le vérifie.
pub fn dormir(echeance: Option<u64>, sommeil: Sommeil) -> Reveil {
    let t = tache::courante();
    t.preparer_sommeil();
    if sommeil == Sommeil::Interruptible && tache::signal_en_attente() {
        return Reveil::Signal;
    }
    if let Some(e) = echeance {
        if e <= crate::temps::ns_monotone() {
            return Reveil::Echeance;
        }
        armer(e);
    }
    t.dort_interruptible(sommeil == Sommeil::Interruptible);
    ordonnanceur::retirer_courante();
    ordonnanceur::ordonnancer();
    if echeance.is_some() {
        annuler(t);
    }
    t.dort_interruptible(false);
    t.raison_du_reveil()
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
    t.preparer_sommeil();
    if tache::signal_en_attente() {
        return Reveil::Signal;
    }
    if compte.temps_de_calcul() >= cible {
        return Reveil::Echeance;
    }
    // La place est réservée pour une attente par tâche (`initialiser`).
    ATTENTES_CALCUL.verrouiller().ajouter_dans_la_place((cible, compte, tache::courante_arc()));
    t.dort_interruptible(true);
    ordonnanceur::retirer_courante();
    ordonnanceur::ordonnancer();
    {
        let mut a = ATTENTES_CALCUL.verrouiller();
        if let Some(i) = a.iter().position(|(_, _, x)| core::ptr::eq(Arc::as_ptr(x), t)) {
            a.remove(i);
        }
    }
    t.dort_interruptible(false);
    t.raison_du_reveil()
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

/// Le détecteur d'interblocage, appelé par la tâche inactive quand aucune
/// tâche n'est prête, interruptions coupées. Si aucune minuterie d'un
/// programme n'est armée, plus rien ne peut réveiller les programmes qui
/// dorment : ni une
/// échéance, ni une autre tâche (aucune ne s'exécute), ni un périphérique
/// (le clavier ne réveille que sa tâche du noyau, jusqu'au terminal de
/// 6j). Linux les laisserait endormis pour toujours ; sans terminal,
/// personne ne pourrait les interrompre (pas de ^C) : chacun est arrêté
/// par SIGKILL, en le disant. Un écart voulu, qui généralise celui de 6d
/// (une attente de futex sans délai dans un programme d'un seul fil). Les
/// tâches du noyau (init qui attend un programme, le clavier) ne sont pas
/// concernées. Seules comptent les minuteries des programmes : celles des
/// tâches du noyau (6g : les voisins du réseau, que la tâche du réseau fait
/// vieillir pendant des dizaines de secondes) ne réveillent pas un programme
/// ; sans cela, un programme bloqué pour toujours attendrait la prochaine
/// échéance de la tâche du réseau pour être arrêté. Une réponse du réseau
/// le peut aussi : tant qu'une socket liée a quelqu'un dans sa file
/// d'attente (un `recv`, un `poll`, un epoll qui la surveille) et qu'une
/// carte a son lien, un datagramme peut encore venir du dehors, et le
/// détecteur ne tue personne (6g : un ping attendu sans délai). Par `lo`,
/// non : seul un programme qui s'exécute peut s'y envoyer quelque chose.
/// Il épargne ainsi plus qu'il ne faudrait : un élément d'epoll reste
/// inscrit dans la file de sa socket même quand personne n'attend l'epoll,
/// et un programme bloqué pour toujours ailleurs (un futex, `pause`) n'est
/// alors pas arrêté. C'est ce que fait Linux, qui n'arrête jamais
/// personne ; ne compter que les éléments dont l'epoll a quelqu'un dans sa
/// file serait plus juste, à voir quand la boucle de Bun aura des sockets
/// (6h). Rend vrai s'il a arrêté quelqu'un.
pub fn detecter_interblocage() -> bool {
    if MINUTERIES.verrouiller().iter().any(|(_, t)| t.est_programme()) || !ATTENTES_CALCUL.verrouiller().is_empty() {
        return false;
    }
    if crate::reseau::attentes() > 0 && crate::reseau::interface::une_carte_a_son_lien() {
        return false;
    }
    let mut bloquees: Vec<Arc<Tache>> = Vec::new();
    tache::pour_chaque(|t| {
        if t.est_programme() && t.dort_interruptible_maintenant() {
            let _ = bloquees.ajouter(t.clone());
        }
    });
    let trouve = !bloquees.is_empty();
    for t in bloquees {
        t.forcer(crate::linux::SIGKILL, "plus rien ne peut le reveiller (interblocage)");
        tache::reveiller(t, Reveil::Signal);
    }
    trouve
}

/// Un verrou qui DORT (le `mutex` de Linux) : une tâche qui le trouve pris
/// s'endort au lieu de boucler, et celui qui le rend réveille la première
/// qui attend. Pour ce qui peut durer (écrire une ligne sur le port série),
/// et jamais dans un gestionnaire d'interruption, ni sous un Verrou (on ne
/// dort pas en tenant un verrou qui coupe les interruptions). Il ne coupe
/// pas les interruptions : la tâche qui le tient peut être préemptée.
pub struct Mutex<T> {
    etat: Verrou<EtatMutex>,
    donnee: UnsafeCell<T>,
}

struct EtatMutex {
    pris: bool,
    file: FileAttente,
}

// SAFETY : la donnée n'est touchée qu'à travers une GardeMutex, et `pris`
// garantit qu'il n'en existe qu'une à la fois.
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(donnee: T) -> Mutex<T> {
        Mutex { etat: Verrou::new(EtatMutex { pris: false, file: FileAttente::new() }), donnee: UnsafeCell::new(donnee) }
    }

    /// Prend le verrou, en dormant tant qu'il est pris.
    pub fn verrouiller(&self) -> GardeMutex<'_, T> {
        loop {
            let interruptions = cpu::couper_interruptions();
            {
                let mut e = self.etat.verrouiller();
                if !e.pris {
                    e.pris = true;
                    drop(e);
                    if interruptions {
                        cpu::activer_interruptions();
                    }
                    return GardeMutex { mutex: self };
                }
                // Exclusive : celui qui le rend n'en réveille qu'une, la
                // première arrivée.
                e.file.inscrire_exclusive();
            }
            dormir(None, Sommeil::Ininterruptible);
            self.etat.verrouiller().file.retirer(tache::courante());
            if interruptions {
                cpu::activer_interruptions();
            }
        }
    }
}

impl<T> Mutex<T> {
    /// Prend le verrou s'il est libre, sans dormir (le `mutex_trylock` de
    /// Linux) : possible sous un Verrou.
    pub fn essayer(&self) -> Option<GardeMutex<'_, T>> {
        let mut e = self.etat.verrouiller();
        if e.pris {
            return None;
        }
        e.pris = true;
        Some(GardeMutex { mutex: self })
    }

    /// La donnée, sans prendre le verrou, quand on la tient seul (`&mut
    /// self` : personne d'autre ne peut la prendre ; le `get_mut` de Rust) :
    /// dans un `Drop`, sous un Verrou.
    pub fn seul(&mut self) -> &mut T {
        self.donnee.get_mut()
    }
}

/// Tant qu'elle existe, on tient le Mutex.
pub struct GardeMutex<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Deref for GardeMutex<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY : la garde prouve qu'on tient le Mutex.
        unsafe { &*self.mutex.donnee.get() }
    }
}

impl<T> DerefMut for GardeMutex<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY : idem, et &mut self garantit l'exclusivité locale.
        unsafe { &mut *self.mutex.donnee.get() }
    }
}

impl<T> Drop for GardeMutex<'_, T> {
    fn drop(&mut self) {
        let mut e = self.mutex.etat.verrouiller();
        e.pris = false;
        e.file.reveiller_une();
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
}

// SAFETY : la donnée n'est touchée que par le possesseur (au plus un, par
// `possede`), ou sous le verrou court quand personne ne possède.
unsafe impl<T: Possede + Send> Sync for Possession<T> where T::Court: Send, T::Element: Send {}
unsafe impl<T: Possede + Send> Send for Possession<T> where T::Court: Send, T::Element: Send {}

impl<T: Possede> Possession<T> {
    pub fn new(donnee: T, premier: T::Court) -> Possession<T> {
        Possession {
            court: Verrou::new(Court { possede: false, premier, file: alloc::collections::VecDeque::new(), taille: 0, minuteur: false }),
            donnee: UnsafeCell::new(donnee),
            attente: FileAttente::new(),
            file: FileAttente::new(),
        }
    }

    /// Prend la possession (le `lock_sock`), en dormant tant qu'un autre
    /// l'a (ininterruptible : comme Linux, un `lock_sock` ne s'interrompt
    /// pas ; la possession est toujours courte).
    pub fn posseder(&self) -> Garde<'_, T> {
        let interruptions = cpu::couper_interruptions();
        loop {
            {
                let mut c = self.court.verrouiller();
                if !c.possede {
                    c.possede = true;
                    break;
                }
                self.attente.inscrire_exclusive();
            }
            dormir(None, Sommeil::Ininterruptible);
            self.attente.retirer(tache::courante());
        }
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
        // SAFETY : personne ne possède, et le verrou court est tenu : nul
        // autre ne touche la donnée.
        let d = unsafe { &mut *self.donnee.get() };
        d.traiter(e);
        let m = d.publier(&mut c.premier);
        drop(c);
        self.reveiller(m);
        true
    }

    /// Réveille la file de la socket pour les événements `m`.
    fn reveiller(&self, m: u32) {
        if m != 0 {
            self.file.reveiller(m, 0);
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
        // SAFETY : comme `du_reseau`.
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
                (core::mem::take(&mut c.file), core::mem::take(&mut c.minuteur))
            };
            // SAFETY : nous possédons : nul autre ne touche la donnée (la
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
        // SAFETY : la garde prouve qu'on possède ; `&mut self` garantit
        // l'exclusivité locale.
        unsafe { &mut *self.p.donnee.get() }
    }

    /// La donnée et le premier étage ensemble, sous le verrou court.
    pub fn avec_court<R>(&mut self, f: impl FnOnce(&mut T, &mut T::Court) -> R) -> R {
        let mut c = self.p.court.verrouiller();
        // SAFETY : on possède.
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
    /// reprise. L'ordre de Linux (`sk_wait_event` : s'inscrire, rendre,
    /// dormir) perdrait le réveil ici : `dormir` efface un réveil venu
    /// avant lui, et `reveiller` retire la tâche de la file. Rend la
    /// raison du réveil (Reveillee si la condition est vraie).
    pub fn attendre(&mut self, file: &FileAttente, sommeil: Sommeil, echeance: Option<u64>,
                    mut pret: impl FnMut(&T::Court) -> bool) -> Reveil {
        self.p.rendre();
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        let r = loop {
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
