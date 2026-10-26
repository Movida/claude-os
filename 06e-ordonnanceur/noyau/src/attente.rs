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
//! Sur un seul processeur, les interruptions coupées de 1 à 4 tiennent lieu
//! de verrou : personne ne peut s'exécuter entre la vérification et le
//! sommeil, ni le gestionnaire qui réveillerait, ni une autre tâche.
//!
//! Une file d'attente ne demande aucune allocation : c'est une liste
//! chaînée PAR les tâches elles-mêmes (chaque tâche a un champ « suivante
//! dans la file où j'attends » : une tâche n'attend qu'une chose à la
//! fois), comme les `wait_queue_entry` de Linux, posées sur la pile de qui
//! attend. S'inscrire ne peut donc pas échouer, et une file d'un objet qui
//! dure (le clavier, la console) ne garde aucune mémoire après son dernier
//! attendant (le contrôle « memoire rendue » des programmes le verrait).
//!
//! Les minuteries (les échéances des attentes) : une liste triée par
//! échéance, réservée au démarrage pour autant de tâches qu'il peut y en
//! avoir (une échéance au plus par tâche), regardée à chaque tic ; une
//! minuterie annulée (la tâche réveillée avant) en est retirée aussitôt.
//! Linux a une roue de minuteries pour les tics et un arbre pour les
//! hrtimers ; nos attentes se comptent en dizaines, la liste suffit.

use crate::cpu;
use crate::ordonnanceur;
use crate::tache::{self, Reveil, Tache};
use crate::verrou::Verrou;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};

/// Une file d'attente : les tâches qui attendent un même objet, dans
/// l'ordre où elles se sont inscrites. Toujours sous le verrou de l'objet.
pub struct FileAttente {
    tete: *const Tache,
    queue: *const Tache,
}

// SAFETY : une file n'est lue et écrite que sous le verrou de son objet
// (elle n'est jamais ailleurs que dans un Verrou).
unsafe impl Send for FileAttente {}

impl FileAttente {
    pub const fn new() -> FileAttente {
        FileAttente { tete: core::ptr::null(), queue: core::ptr::null() }
    }

    /// Inscrit la tâche courante à la fin de la file. Elle doit ensuite
    /// dormir (`dormir`), puis s'en retirer (`retirer`).
    pub fn inscrire(&mut self) {
        // Un Arc de plus, tenu par la file : la tâche vit tant qu'elle y est.
        let t = Arc::into_raw(tache::courante_arc());
        // SAFETY : `t` vient d'être tenu ; une tâche n'est que dans une file
        // à la fois (elle n'attend qu'une chose), son lien est donc libre.
        unsafe {
            (*t).lien_attente().set(core::ptr::null());
            if let Some(q) = self.queue.as_ref() {
                q.lien_attente().set(t);
            } else {
                self.tete = t;
            }
        }
        self.queue = t;
    }

    /// Retire `t` de la file, si elle y est (réveillée par autre chose
    /// qu'un réveil de la file : une échéance, un signal).
    pub fn retirer(&mut self, t: &Tache) {
        let mut precedente: *const Tache = core::ptr::null();
        let mut p = self.tete;
        while !p.is_null() {
            // SAFETY : les tâches de la file sont tenues par elle (inscrire).
            let suivante = unsafe { (*p).lien_attente().get() };
            if core::ptr::eq(p, t) {
                // SAFETY : comme ci-dessus.
                unsafe {
                    match precedente.as_ref() {
                        Some(pr) => pr.lien_attente().set(suivante),
                        None => self.tete = suivante,
                    }
                    if core::ptr::eq(self.queue, p) {
                        self.queue = precedente;
                    }
                    // L'Arc que tenait la file.
                    drop(Arc::from_raw(p));
                }
                return;
            }
            precedente = p;
            p = suivante;
        }
    }

    /// Retire la première tâche de la file : None si elle est vide.
    fn sortir(&mut self) -> Option<Arc<Tache>> {
        if self.tete.is_null() {
            return None;
        }
        let p = self.tete;
        // SAFETY : la tête est tenue par la file ; son Arc passe à
        // l'appelant.
        unsafe {
            self.tete = (*p).lien_attente().get();
            if self.tete.is_null() {
                self.queue = core::ptr::null();
            }
            Some(Arc::from_raw(p))
        }
    }

    /// Réveille la première tâche de la file ; false : elle était vide.
    pub fn reveiller_une(&mut self) -> bool {
        match self.sortir() {
            Some(t) => {
                tache::reveiller(t, Reveil::Reveillee);
                true
            }
            None => false,
        }
    }

    /// Réveille toutes les tâches de la file ; rend leur nombre.
    pub fn reveiller_toutes(&mut self) -> usize {
        let mut n = 0;
        while self.reveiller_une() {
            n += 1;
        }
        n
    }
}

/// Comment dormir.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sommeil {
    /// Seul un réveil de la file finit l'attente (un verrou qui dort).
    Ininterruptible,
    /// Un signal la finit aussi (TASK_INTERRUPTIBLE) : l'appel système
    /// rendra EINTR.
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
/// CLOCK_PROCESS_CPUTIME_ID) : le temps de calcul à atteindre, la tâche
/// dont le temps compte, celle qui dort.
static ATTENTES_CALCUL: Verrou<Vec<(u64, Arc<Tache>, Arc<Tache>)>> = Verrou::new(Vec::new());

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
    // La place est réservée pour une échéance par tâche.
    m.insert(i, (echeance, tache::courante_arc()));
}

/// Retire la minuterie de `t`, si elle y est encore.
fn annuler(t: &Tache) {
    let mut m = MINUTERIES.verrouiller();
    if let Some(i) = m.iter().position(|(_, x)| core::ptr::eq(Arc::as_ptr(x), t)) {
        m.remove(i);
    }
}

/// La tâche courante dort jusqu'à ce que le temps de calcul de `compte`
/// atteigne `cible`, ou un signal. Interruptions coupées.
pub fn dormir_calcul(compte: Arc<Tache>, cible: u64) -> Reveil {
    let t = tache::courante();
    t.preparer_sommeil();
    if tache::signal_en_attente() {
        return Reveil::Signal;
    }
    if compte.temps_de_calcul() >= cible {
        return Reveil::Echeance;
    }
    ATTENTES_CALCUL.verrouiller().push((cible, compte, tache::courante_arc()));
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
                e.file.inscrire();
            }
            dormir(None, Sommeil::Ininterruptible);
            self.etat.verrouiller().file.retirer(tache::courante());
            if interruptions {
                cpu::activer_interruptions();
            }
        }
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
