//! L'ordonnanceur : qui a le processeur, et pour combien de temps.
//!
//! Choix de conception : EEVDF (« Earliest Eligible Virtual Deadline
//! First », Stoica et Abdel-Wahab, 1995), l'ordonnanceur de Linux depuis
//! 6.6, qui a remplacé CFS. Chaque tâche prête a :
//!   - un TEMPS VIRTUEL : son temps de calcul, divisé par son poids (celui
//!     de son `nice` : 1024 pour nice 0, la table `sched_prio_to_weight` de
//!     Linux, chaque cran valant environ 10 % de processeur). Une tâche qui
//!     a calculé moins que sa part a un temps virtuel plus petit ;
//!   - une ÉCHÉANCE VIRTUELLE : son temps virtuel plus une tranche (0,70 ms
//!     de calcul, `sysctl_sched_base_slice` sur un processeur, dans le temps
//!     virtuel de son poids).
//! Est ÉLIGIBLE une tâche qui n'a pas pris plus que sa part : son temps
//! virtuel est au plus la moyenne de ceux de toutes les tâches prêtes,
//! pondérée par leurs poids. Parmi les éligibles passe celle dont
//! l'échéance est la plus proche. Une tâche qui a fini sa tranche (son
//! temps virtuel atteint son échéance) en reçoit une nouvelle, plus loin,
//! et cède le processeur. Tant que tout le monde est à nice 0 (nous n'avons
//! pas encore `setpriority`), cela revient à un tourniquet équitable ; mais
//! une tâche qui dort souvent (un éditeur, une boucle d'événements) garde
//! en se réveillant l'avance qu'elle avait (son « lag », borné), et passe
//! avant celles qui calculent sans arrêt.
//!
//! Option écartée : le tourniquet seul (chacun son tour, une tranche
//! chacun), sans cette équité. L'arbre rouge-noir de Linux devient un `Vec`
//! parcouru : quelques tâches prêtes à la fois (13 fils mesurés pour
//! `claude` à son écran d'accueil), comme le `Vec` de la carte des zones
//! (6a). Ce que nous ne faisons pas de l'EEVDF de 6.12 et plus : le
//! « DELAY_DEQUEUE » (une tâche qui s'endort en retard reste comptée dans
//! la moyenne jusqu'à rattraper ce retard) ; nous suivons celui de 6.6, où
//! le retard est gardé dans la tâche et retrouvé au réveil. Comme 6.6 :
//! RUN_TO_PARITY (une tâche qui vient de recevoir le processeur le garde
//! jusqu'au bout de sa tranche, tant qu'elle reste éligible : un réveil ne
//! l'interrompt pas au milieu), et une file vide garde son temps virtuel
//! (le `min_vruntime` de Linux) : il ne repart pas de 0, et le retard d'une
//! tâche ne s'applique que s'il y a des tâches à qui le comparer.
//!
//! LA PRÉEMPTION (choix de conception) : le tic d'horloge lève « besoin de
//! céder » quand la tâche courante a fini sa tranche ; la bascule se fait
//! au retour vers l'anneau 3, ET à la fin d'une interruption qui a
//! interrompu le noyau, si les interruptions y étaient actives (le
//! `PREEMPT` de Linux) et que la préemption n'est pas coupée
//! (processeur.rs, le compte de préemption, 6j). Un programme WebAssembly
//! s'exécute dans l'interpréteur du noyau : sans préemption du noyau, il
//! ne céderait jamais le processeur. Tous les verrous courts coupent les
//! interruptions (verrou.rs) : « les interruptions étaient actives »
//! garantit qu'aucun n'était tenu. La règle, vérifiée : ne jamais céder le
//! processeur verrou tenu ni préemption coupée (`ordonnancer` panique,
//! comme le « scheduling while atomic » de Linux). Écart avec Linux : il
//! préempte aussi en rendant un verrou ; chez nous, un réveil fait dans le
//! noyau ne prend effet qu'au retour vers l'anneau 3 ou au tic suivant
//! (6j le reprend).
//!
//! DORMIR OU ÊTRE PRÉEMPTÉE (6j) : `ordonnancer` dit pourquoi on l'appelle
//! (`Bascule`). Pour un SOMMEIL, la tâche courante quitte la file des
//! prêtes, mais seulement si son état dit encore « dort » (tache.rs,
//! `quitte_la_file`) : si quelqu'un l'a réveillée entre « je vais dormir »
//! et ici, elle reste prête, et son `dormir` revient tout de suite ; un
//! réveil ne se perd pas. Pour une PRÉEMPTION, elle ne quitte JAMAIS la
//! file, quel que soit son état : une tâche neuve, ou une tâche préemptée
//! entre « je vais dormir » et son sommeil, serait sinon perdue. C'est le
//! `!preempt && prev_state` du `__schedule` de Linux (SM_PREEMPT).

use crate::faillible::VecFaillible;
use crate::partage::Arc;
use crate::tache::{self, Reveil, Tache};
use crate::verrou::{self, Verrou};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// La tranche de base, en nanosecondes de calcul (Linux 6.18, un
/// processeur : 0,70 ms).
pub const TRANCHE: u64 = 700_000;
/// Le poids de nice 0.
const POIDS_NICE_0: u64 = 1024;

/// Une tâche prête (ou courante), et ce que l'ordonnanceur sait d'elle.
struct Entite {
    tache: Arc<Tache>,
    /// Temps virtuel et échéance virtuelle, en nanosecondes de temps
    /// virtuel.
    vruntime: u64,
    echeance: u64,
    poids: u64,
    /// Elle a reçu le processeur depuis sa dernière nouvelle tranche :
    /// protégée d'une préemption par un réveil jusqu'à la fin de cette
    /// tranche (RUN_TO_PARITY ; Linux le marque `vlag == deadline`).
    protegee: bool,
}

struct File {
    entites: Vec<Entite>,
    /// L'instant (temps monotone, en ns) où le temps de calcul de la tâche
    /// courante a été compté pour la dernière fois.
    depuis: u64,
    /// La moyenne des temps virtuels quand la file s'est vidée : celle d'une
    /// file vide (le `min_vruntime` de Linux, qui ne recule jamais).
    zero: u64,
}

// UNIPROCESSEUR : une seule file des prêtes ; une par processeur avec
// plusieurs (la `rq` de Linux), et l'équilibrage des charges entre elles.
static FILE: Verrou<File> = Verrou::new(File { entites: Vec::new(), depuis: 0, zero: 0 });
/// La tâche courante a fini sa tranche, ou une tâche réveillée devrait
/// passer avant elle (le TIF_NEED_RESCHED de Linux).
static BESOIN_DE_CEDER: AtomicBool = AtomicBool::new(false);
/// Le nombre de bascules, pour les tests.
static BASCULES: AtomicU64 = AtomicU64::new(0);

/// La tranche en temps virtuel, pour le poids `poids`.
fn tranche_virtuelle(poids: u64) -> u64 {
    TRANCHE * POIDS_NICE_0 / poids
}

impl File {
    /// La moyenne pondérée des temps virtuels (l'`avg_vruntime` de Linux),
    /// calculée sur 128 bits ; celle gardée quand la file s'est vidée, sans
    /// tâche.
    fn moyenne(&self) -> u64 {
        let (somme, poids) = self.entites.iter().fold((0u128, 0u128), |(s, p), e| (s + e.vruntime as u128 * e.poids as u128, p + e.poids as u128));
        if poids == 0 { self.zero } else { (somme / poids) as u64 }
    }

    fn position(&self, t: &Tache) -> Option<usize> {
        self.entites.iter().position(|e| core::ptr::eq(Arc::as_ptr(&e.tache), t))
    }

    /// Compte le temps de calcul de la tâche courante depuis la dernière
    /// fois (l'`update_curr` de Linux) : dans sa tâche (son temps de
    /// calcul), et dans son temps virtuel si elle est dans la file. Rend
    /// vrai si elle a fini sa tranche (et en a reçu une nouvelle).
    fn compter_courante(&mut self) -> bool {
        let maintenant = crate::temps::ns_monotone();
        let delta = maintenant.saturating_sub(self.depuis);
        self.depuis = maintenant;
        let courante = tache::courante();
        courante.compter_calcul(delta);
        let Some(i) = self.position(courante) else { return false };
        let e = &mut self.entites[i];
        e.vruntime += delta * POIDS_NICE_0 / e.poids;
        if e.vruntime >= e.echeance {
            e.echeance = e.vruntime + tranche_virtuelle(e.poids);
            e.protegee = false;
            return true;
        }
        false
    }

    /// La tâche qui doit avoir le processeur : la courante si elle est
    /// protégée et éligible (RUN_TO_PARITY) ; sinon, parmi les éligibles,
    /// celle dont l'échéance est la plus proche (`pick_eevdf`) ; None si la
    /// file est vide (la tâche inactive).
    fn choisir(&self) -> Option<&Entite> {
        let moyenne = self.moyenne();
        if let Some(i) = self.position(tache::courante())
            && self.entites[i].protegee
            && self.entites[i].vruntime <= moyenne
        {
            return Some(&self.entites[i]);
        }
        self.entites
            .iter()
            .filter(|e| e.vruntime <= moyenne)
            .min_by_key(|e| e.echeance)
            // Il y a toujours une éligible (la plus petite est sous la
            // moyenne) ; sinon, par prudence, la plus petite.
            .or_else(|| self.entites.iter().min_by_key(|e| e.vruntime))
    }

    /// Ajoute `t` à la file (`place_entity`, puis `enqueue_entity`) : son
    /// temps virtuel est la moyenne moins le retard qu'elle avait en
    /// quittant la file (0 pour une neuve), retard grossi comme le fait
    /// Linux pour que l'ajouter ne déplace pas la moyenne, et seulement s'il
    /// y a d'autres tâches (PLACE_LAG, avec `nr_running`) ; une neuve
    /// reçoit une demi-tranche (PLACE_DEADLINE_INITIAL), pour passer vite
    /// sans prendre la place des autres.
    fn ajouter(&mut self, t: Arc<Tache>, neuve: bool) {
        let poids = POIDS_NICE_0;
        let charge: u64 = self.entites.iter().map(|e| e.poids).sum();
        let lag = if charge > 0 { (t.lag() as i128 * (charge + poids) as i128 / charge as i128) as i64 } else { 0 };
        let vruntime = (self.moyenne() as i64).saturating_sub(lag).max(0) as u64;
        let tranche = if neuve { tranche_virtuelle(poids) / 2 } else { tranche_virtuelle(poids) };
        // Les deux invariants que le réveil sous verrou garantit (voir
        // `reveiller`) : jamais deux fois en file, jamais une morte.
        assert!(!t.est_en_file(), "tache deja dans la file des pretes");
        assert!(!t.est_morte(), "tache morte remise dans une file des pretes");
        // La place est réservée au démarrage (`initialiser`) : la file ne
        // grandit pas pendant un programme, et l'ordonnanceur n'appelle
        // jamais le tas (il tourne aussi dans les interruptions).
        t.poser_en_file(true, 0);
        self.entites.ajouter_dans_la_place(Entite { tache: t, vruntime, echeance: vruntime + tranche, poids, protegee: false });
    }

    /// Retire `t` de la file, en gardant son retard (`update_entity_lag`) :
    /// la moyenne moins son temps virtuel, borné à plus ou moins deux
    /// tranches ou un tic (le plus grand), dans son temps virtuel.
    fn retirer(&mut self, t: &Tache) {
        let Some(i) = self.position(t) else { return };
        let moyenne = self.moyenne();
        let e = self.entites.swap_remove(i);
        e.tache.poser_en_file(false, 0);
        if self.entites.is_empty() {
            self.zero = moyenne;
        }
        let limite = (2 * TRANCHE).max(crate::horloge::nanosecondes(1)) * POIDS_NICE_0 / e.poids;
        let lag = (moyenne as i64 - e.vruntime as i64).clamp(-(limite as i64), limite as i64);
        e.tache.garder_lag(lag);
    }
}

/// Réserve la file pour `max` tâches prêtes (le nombre maximal de fils) :
/// elle ne grandira jamais pendant un programme. Au démarrage.
pub fn initialiser(max: usize) {
    let mut f = FILE.verrouiller();
    f.entites.try_reserve_exact(max).expect("plus de memoire pour la file des taches pretes");
    f.depuis = crate::temps::ns_monotone();
}

/// Réveille `t` (tache.rs, `reveiller`) : son état passe de « dort » à
/// `pourquoi` SOUS le verrou de la file, dans la même section critique que
/// la lecture de `en_file` (le `pi_lock` de Linux, tenu de
/// `ttwu_state_match` à `ttwu_queue` ; chez nous le verrou de la file
/// suffit : `ordonnancer` lit l'état et retire la tâche sous ce même
/// verrou). Un compare_exchange gagné avec `en_file` faux dit alors que la
/// tâche s'est retirée pour CE sommeil et ne s'exécutera plus d'elle-même :
/// personne d'autre ne peut la remettre en file, et un second réveilleur
/// trouve un état qui ne dort plus. Rend faux si elle ne dormait pas, ou
/// pas d'un sommeil que `pourquoi` réveille.
pub fn reveiller(t: Arc<Tache>, pourquoi: Reveil) -> bool {
    let f = FILE.verrouiller();
    if !t.passer_a_reveillee(pourquoi) {
        return false;
    }
    // Le `ttwu_runnable` de Linux : elle n'avait pas fini de s'endormir
    // (son état, réveillé, l'y garde), ou elle est préemptée : rien à
    // ajouter ; elle doit peut-être passer avant la courante.
    if t.est_en_file() {
        ceder_si_une_autre_passe(&f);
        return true;
    }
    drop(f);
    // Sortie de la file pour ce sommeil ; elle peut n'avoir pas FINI de
    // quitter le processeur (`sur_processeur`, entre sa sortie de la file
    // et la fin de bascule de la tâche suivante) : on attend, sans le
    // verrou de la file (la fin de bascule n'a besoin de rien de nous,
    // quelques centaines de cycles), puis on la met dans la file.
    while t.est_sur_processeur() {
        core::hint::spin_loop();
    }
    let mut f = FILE.verrouiller();
    f.compter_courante();
    f.ajouter(t, false);
    ceder_si_une_autre_passe(&f);
    true
}

/// Une tâche neuve (clone, un programme lancé) devient prête. Elle n'est
/// dans la file ni sur un processeur : rien à vérifier.
pub fn rendre_prete(t: Arc<Tache>) {
    let mut f = FILE.verrouiller();
    f.compter_courante();
    f.ajouter(t, true);
    ceder_si_une_autre_passe(&f);
}

/// Si une autre tâche que la courante devrait avoir le processeur
/// (éligible, et d'échéance plus proche, la courante n'étant pas protégée :
/// `check_preempt_wakeup_fair`), la courante cédera au prochain point de
/// préemption.
fn ceder_si_une_autre_passe(f: &File) {
    let courante = tache::courante();
    let choisie = f.choisir().map(|e| Arc::as_ptr(&e.tache));
    if choisie.is_some_and(|c| !core::ptr::eq(c, courante)) {
        BESOIN_DE_CEDER.store(true, Ordering::Relaxed);
    }
}

/// Le tic d'horloge, interruptions coupées : le temps de la courante est
/// compté ; si elle a fini sa tranche et qu'une autre attend, elle cédera.
pub fn tic() {
    let mut f = FILE.verrouiller();
    if f.compter_courante() && f.entites.len() > 1 {
        BESOIN_DE_CEDER.store(true, Ordering::Relaxed);
    }
    // La tâche inactive, quand une tâche est prête (réveillée hors d'une
    // interruption), cède aussitôt.
    if f.position(tache::courante()).is_none() && !f.entites.is_empty() {
        BESOIN_DE_CEDER.store(true, Ordering::Relaxed);
    }
}

/// Une autre tâche que la courante est-elle prête ?
pub fn autres_pretes() -> bool {
    let f = FILE.verrouiller();
    f.entites.iter().any(|e| !core::ptr::eq(Arc::as_ptr(&e.tache), tache::courante()))
}

/// Faut-il céder le processeur ?
pub fn besoin_de_ceder() -> bool {
    BESOIN_DE_CEDER.load(Ordering::Relaxed)
}

/// Pourquoi on appelle `ordonnancer` (voir l'en-tête).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Bascule {
    /// La tâche courante veut dormir (ou est morte) : elle quitte la file
    /// si son état dit encore « dort ».
    Sommeil,
    /// Elle est préemptée (le tic, un réveil qui passe avant elle,
    /// sched_yield) : elle reste dans la file.
    Preemption,
}

/// Donne le processeur à la tâche que choisit l'EEVDF (la tâche inactive
/// si la file est vide), et revient quand la courante le retrouve (jamais,
/// si elle est morte). Jamais verrou tenu : une tâche qui céderait le
/// processeur en tenant un verrou (qui coupe les interruptions) bloquerait
/// tout le monde.
pub fn ordonnancer(bascule: Bascule) {
    let tenus = verrou::tenus();
    assert!(tenus == 0, "ordonnancer avec {} verrou(s) tenu(s)", tenus);
    // Ni préemption coupée, ni dans une interruption (le « scheduling while
    // atomic » de Linux) : le compte de préemption est ainsi toujours nul
    // quand on bascule, et n'a rien à sauver par tâche (processeur.rs).
    assert!(crate::processeur::preemptible(), "ordonnancer preemption coupee ou dans une interruption");
    let interruptions = crate::cpu::couper_interruptions();
    BESOIN_DE_CEDER.store(false, Ordering::Relaxed);
    let suivante = {
        let mut f = FILE.verrouiller();
        f.compter_courante();
        // Un sommeil : la courante quitte la file, sauf si un réveil l'a
        // déjà changée d'avis (voir l'en-tête) ; une préemption : jamais.
        if bascule == Bascule::Sommeil && tache::courante().quitte_la_file() {
            f.retirer(tache::courante());
        }
        // Un pointeur, pas un Arc : la file garde la tâche choisie tant
        // qu'elle est prête ou courante, et un Arc emporté par une tâche qui
        // ne reprendra jamais la main (une morte) ne serait jamais rendu.
        let choisie = f.choisir().map(|e| Arc::as_ptr(&e.tache));
        // Celle qui reçoit le processeur le garde jusqu'au bout de sa
        // tranche (RUN_TO_PARITY, le `set_next_entity` de Linux) ; et elle
        // s'exécute (`sur_processeur`, le `prepare_task`), dit SOUS le verrou
        // de la file, avant de basculer : un autre processeur qui la
        // tirerait de la file entre les deux la verrait en cours.
        if let Some(i) = choisie.and_then(|c| f.entites.iter().position(|e| core::ptr::eq(Arc::as_ptr(&e.tache), c))) {
            f.entites[i].protegee = true;
            f.entites[i].tache.prend_le_processeur();
        } else {
            // SAFETY: l'inactive de ce processeur vit pour toujours.
            unsafe { &*tache::inactive() }.prend_le_processeur();
        }
        // Une bascule volontaire si la courante a quitté la file (elle
        // s'endort, ou elle meurt), forcée sinon (getrusage : `__schedule`).
        let volontaire = f.position(tache::courante()).is_none();
        (choisie, volontaire)
    };
    let (suivante, volontaire) = suivante;
    let suivante = suivante.unwrap_or_else(tache::inactive);
    if !core::ptr::eq(suivante, tache::courante()) {
        BASCULES.fetch_add(1, Ordering::Relaxed);
        tache::courante().usage().compter_bascule(volontaire);
        // SAFETY: `suivante` est dans la file (ou l'inactive, qui ne meurt
        // pas) : elle vit au moins jusqu'à ce qu'elle quitte la file, ce
        // qu'elle seule peut faire, en s'exécutant.
        tache::basculer_vers(unsafe { &*suivante });
    }
    if interruptions {
        crate::cpu::activer_interruptions();
    }
}

/// Préempte la tâche courante si elle doit céder : à la fin d'une
/// interruption qui a interrompu le noyau, interruptions actives (voir
/// l'en-tête), et préemption permise (processeur.rs : une tâche qui
/// attend la réponse d'autres processeurs, ou qui tourne sur un verrou qui
/// dort, garde son processeur).
pub fn preempter() {
    if besoin_de_ceder() && !crate::processeur::preemption_coupee() {
        ordonnancer(Bascule::Preemption);
    }
}

/// sched_yield : la tâche courante cède le processeur ; comme Linux
/// (`yield_task_fair`), son échéance recule d'une tranche, pour qu'elle
/// passe après les autres éligibles.
pub fn ceder() {
    {
        let mut f = FILE.verrouiller();
        f.compter_courante();
        let courante = tache::courante();
        if let Some(i) = f.position(courante) {
            let e = &mut f.entites[i];
            e.echeance += tranche_virtuelle(e.poids);
            e.protegee = false;
        }
    }
    ordonnancer(Bascule::Preemption);
}

/// Le nombre de bascules depuis le démarrage.
pub fn bascules() -> u64 {
    BASCULES.load(Ordering::Relaxed)
}
