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
//! `PREEMPT` de Linux). Un programme WebAssembly s'exécute dans
//! l'interpréteur du noyau : sans préemption du noyau, il ne céderait
//! jamais le processeur. Sur un seul processeur, avec des verrous qui
//! coupent tous les interruptions, « les interruptions étaient actives »
//! garantit qu'aucun verrou n'était tenu. La règle qui reste, vérifiée :
//! ne jamais céder le processeur verrou tenu (`ordonnancer` panique,
//! comme le « scheduling while atomic » de Linux). Écart avec Linux : il
//! préempte aussi en rendant un verrou ; chez nous, un réveil fait dans le
//! noyau ne prend effet qu'au retour vers l'anneau 3 ou au tic suivant.

use crate::tache::{self, Tache};
use crate::verrou::{self, Verrou};
use alloc::sync::Arc;
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
        // La place est réservée au démarrage (`initialiser`) : la file ne
        // grandit pas pendant un programme.
        self.entites.push(Entite { tache: t, vruntime, echeance: vruntime + tranche, poids, protegee: false });
    }

    /// Retire `t` de la file, en gardant son retard (`update_entity_lag`) :
    /// la moyenne moins son temps virtuel, borné à plus ou moins deux
    /// tranches ou un tic (le plus grand), dans son temps virtuel.
    fn retirer(&mut self, t: &Tache) {
        let Some(i) = self.position(t) else { return };
        let moyenne = self.moyenne();
        let e = self.entites.swap_remove(i);
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

/// Une tâche neuve, ou réveillée, devient prête. Si elle devrait passer
/// avant la courante (éligible, et d'échéance plus proche, la courante
/// n'étant pas protégée : `check_preempt_wakeup_fair`), la courante cédera
/// le processeur au prochain point de préemption.
pub fn rendre_prete(t: Arc<Tache>, neuve: bool) {
    let mut f = FILE.verrouiller();
    if f.position(&t).is_some() {
        return;
    }
    f.compter_courante();
    f.ajouter(t, neuve);
    let courante = tache::courante();
    let choisie = f.choisir().map(|e| Arc::as_ptr(&e.tache));
    if choisie.is_some_and(|c| !core::ptr::eq(c, courante)) {
        BESOIN_DE_CEDER.store(true, Ordering::Relaxed);
    }
}

/// La tâche courante quitte la file : elle s'endort, ou elle est morte. Il
/// faudra ensuite `ordonnancer`.
pub fn retirer_courante() {
    let mut f = FILE.verrouiller();
    f.compter_courante();
    let courante = tache::courante();
    f.retirer(courante);
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

/// Donne le processeur à la tâche que choisit l'EEVDF (la tâche inactive
/// si la file est vide), et revient quand la courante le retrouve (jamais,
/// si elle est morte). Jamais verrou tenu : une tâche qui céderait le
/// processeur en tenant un verrou (qui coupe les interruptions) bloquerait
/// tout le monde.
pub fn ordonnancer() {
    let tenus = verrou::tenus();
    assert!(tenus == 0, "ordonnancer avec {} verrou(s) tenu(s)", tenus);
    let interruptions = crate::cpu::couper_interruptions();
    BESOIN_DE_CEDER.store(false, Ordering::Relaxed);
    let suivante = {
        let mut f = FILE.verrouiller();
        f.compter_courante();
        // Un pointeur, pas un Arc : la file garde la tâche choisie tant
        // qu'elle est prête ou courante, et un Arc emporté par une tâche qui
        // ne reprendra jamais la main (une morte) ne serait jamais rendu.
        let choisie = f.choisir().map(|e| Arc::as_ptr(&e.tache));
        // Celle qui reçoit le processeur le garde jusqu'au bout de sa
        // tranche (RUN_TO_PARITY, le `set_next_entity` de Linux).
        if let Some(i) = choisie.and_then(|c| f.entites.iter().position(|e| core::ptr::eq(Arc::as_ptr(&e.tache), c))) {
            f.entites[i].protegee = true;
        }
        choisie
    };
    let suivante = suivante.unwrap_or_else(tache::inactive);
    if !core::ptr::eq(suivante, tache::courante()) {
        BASCULES.fetch_add(1, Ordering::Relaxed);
        // SAFETY : `suivante` est dans la file (ou l'inactive, qui ne meurt
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
/// l'en-tête).
pub fn preempter() {
    if besoin_de_ceder() {
        ordonnancer();
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
    ordonnancer();
}

/// Le nombre de bascules depuis le démarrage.
pub fn bascules() -> u64 {
    BASCULES.load(Ordering::Relaxed)
}
