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
//! comme le « scheduling while atomic » de Linux). Et, comme Linux (le
//! `preempt_enable` de `spin_unlock`), en RENDANT le dernier `Verrou` tenu
//! ou en rétablissant la préemption (verrou.rs, processeur.rs) : une tâche
//! réveillée sous un verrou, qui devrait passer avant la courante, prend le
//! processeur dès qu'il est rendu, au lieu d'attendre le tic suivant ou le
//! retour vers l'anneau 3 (ce qu'elle faisait jusqu'à 6j).
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
//!
//! UNE FILE PAR PROCESSEUR (6j, la `rq` de Linux) : chaque processeur a sa
//! file (`FILES`), sous son propre verrou, et n'ordonnance que dans la
//! sienne ; l'EEVDF ne change pas dans chacune, mais ce qu'il appelle « la
//! courante » est la tâche courante DU PROCESSEUR DE LA FILE (`zone.courante`),
//! pas celle de qui tient le verrou (un réveil met une tâche dans la file
//! d'un autre). La place est réservée au démarrage pour le maximum de fils
//! dans chacune : la file ne grandit jamais pendant un programme, et
//! l'ordonnanceur n'alloue jamais (16 384 entrées de 48 octets, 768 Kio par
//! processeur avec 2 Gio : la règle vaut ce prix).
//!
//! OÙ VA UNE TÂCHE (le `select_task_rq_fair` de Linux, réduit à ce qui
//! compte sans topologie : nos processeurs virtuels n'ont ni caches
//! partagés ni hyperthreads que QEMU décrive) :
//!   - réveillée : son dernier processeur s'il est inactif (ses caches ont
//!     peut-être encore ses données, le `prev_cpu`) ; sinon un processeur
//!     inactif (`select_idle_cpu`) ; sinon le moins chargé (le moins
//!     d'entités) parmi ceux que son masque permet ;
//!   - neuve (clone, un programme lancé) : le moins chargé (`find_idlest_cpu`) ;
//!   - un processeur qui n'a plus rien TIRE une tâche prête d'une autre file
//!     (`tirer`, le `newidle_balance`) : pas une qui s'exécute
//!     (`sur_processeur`), pas une qu'il n'a pas le droit d'exécuter ; les
//!     deux files prises dans l'ordre des numéros, et tout revérifié sous
//!     les verrous (le RETRY_TASK de Linux) ;
//!   - au tic, toutes les 4 ms (le `balance_interval` d'une petite machine
//!     chez Linux), un processeur tire de la file la plus chargée si
//!     l'écart est d'au moins deux (le `rebalance_domains`, sans ses
//!     domaines).
//! Une tâche déplacée garde son retard (`retirer` le calcule, `ajouter` la
//! place par rapport à la moyenne de la file d'arrivée) : le
//! `migrate_task_rq_fair` puis `place_entity` de Linux. La charge de chaque
//! file (`charge`, le `nr_running`) se lit sans son verrou : une
//! indication, pour choisir ; la décision se vérifie ensuite sous les
//! verrous. Deux files à la fois (tirer) : par numéro croissant
//! (`double_rq_lock`), jamais l'inverse.
//!
//! RÉVEILLER L'AUTRE : une tâche mise dans la file d'un processeur inactif,
//! ou qui devrait passer avant la courante de ce processeur (la règle de
//! `rendre_prete`, appliquée à SA courante) : son « besoin de céder »
//! (processeur.rs) et l'IPI de reprogrammation (smp.rs, le `resched_curr`),
//! qui le sort de `hlt` ou qu'il voit à la sortie de l'interruption.
//!
//! L'AFFINITÉ (sched_setaffinity, tache.rs) : un processeur ne choisit, ne
//! tire ni ne reçoit que des tâches qu'il a le droit d'exécuter (un masque
//! qui ne permet plus aucun processeur en service vaut « tous » : il a été
//! posé quand ils étaient là). Une tâche dont le masque change
//! (`affinite_changee`) : prête dans une file dont le processeur n'est plus
//! permis, elle en est déplacée aussitôt ; en cours sur un processeur qui
//! ne l'est plus, elle n'est pas déplacée pendant qu'elle s'exécute (la
//! destination pourrait la choisir avant que la source ait fini de
//! basculer) : elle cède le processeur (« besoin de céder »), et c'est lui
//! qui la pousse vers un processeur permis dès qu'elle l'a quitté
//! (`pousser_si_interdite`, à la fin de sa bascule ; Linux le fait par sa
//! tâche d'arrêt, `migration_cpu_stop`, que nous n'avons pas) ; endormie,
//! son réveil la placera (`choisir_processeur`). Et l'équilibrage du tic
//! tire d'abord une tâche que sa file ne peut pas exécuter (`interdites`),
//! quelle que soit la charge : le filet, si l'un des deux premiers chemins
//! la manquait (la relecture de 6j : jusque-là, seule une file vide la
//! tirait, et des processeurs permis qui calculaient la laissaient attendre
//! sans fin).
//!
//! LE DÉTECTEUR D'INTERBLOCAGE (attente.rs) ne tourne que sur le processeur
//! 0, quand tous les autres sont inactifs et toutes les files vides
//! (`machine_inactive`) : un programme qui dort et que seule une tâche en
//! cours sur un autre processeur peut réveiller n'est pas un interblocage.
//!
//! Options écartées : l'équilibrage complet de Linux (`fair.c`, 13 000
//! lignes : les domaines, les groupes, les charges moyennes PELT, les
//! marges) : il sert des machines NUMA à centaines de cœurs ; les règles
//! ci-dessus sont celles qu'il applique sur un portable. Le vol de travail
//! sans équilibrage périodique : une tâche qui calcule sans dormir
//! resterait sur un processeur surchargé tant qu'aucun autre ne se vide.

use crate::faillible::VecFaillible;
use crate::partage::Arc;
use crate::processeur;
use crate::tache::{self, Reveil, Tache};
use crate::verrou::{self, Verrou};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

/// La tranche de base, en nanosecondes de calcul (Linux 6.18, un
/// processeur : 0,70 ms).
pub const TRANCHE: u64 = 700_000;
/// Le poids de nice 0.
const POIDS_NICE_0: u64 = 1024;
/// Les tics entre deux équilibrages d'un processeur.
const TICS_EQUILIBRAGE: u64 = 4;

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

/// La file des prêtes d'un processeur (voir l'en-tête).
struct File {
    /// Le processeur dont c'est la file.
    numero: usize,
    entites: Vec<Entite>,
    /// L'instant (temps monotone, en ns) où le temps de calcul de la tâche
    /// courante a été compté pour la dernière fois.
    depuis: u64,
    /// La moyenne des temps virtuels quand la file s'est vidée : celle d'une
    /// file vide (le `min_vruntime` de Linux, qui ne recule jamais).
    zero: u64,
    /// La tâche courante du processeur de cette file : celle que
    /// `ordonnancer` a choisie, écrite SOUS ce verrou au moment du choix
    /// (une tâche de la file, ou l'inactive ; nulle avant la première
    /// bascule). Lue sous ce verrou, par ce processeur ou par un autre qui
    /// tire (`compter_courante`) : une tâche ne quitte la file, et ne
    /// meurt, que par `ordonnancer` sur son processeur, sous ce même
    /// verrou, qui écrit alors sa remplaçante ; tant qu'on tient le verrou,
    /// elle vit. (La relecture de 6j : jusque-là, on lisait `courante` de
    /// la zone du processeur, publiée hors de ce verrou par la bascule, et
    /// un autre processeur pouvait la lire morte et rendue.)
    courante: AtomicPtr<Tache>,
}

/// La file d'un processeur, et sa charge (le nombre d'entités), lisible sans
/// le verrou (le `nr_running` de Linux : pour choisir, une indication) ;
/// et combien de ses entités son processeur n'a pas le droit d'exécuter
/// (leur masque a changé : voir l'en-tête, l'affinité), pour l'équilibrage.
struct FileProcesseur {
    file: Verrou<File>,
    charge: AtomicUsize,
    interdites: AtomicUsize,
}

static FILES: [FileProcesseur; processeur::MAX] = {
    let mut f = [const {
        FileProcesseur {
            file: Verrou::new(File { numero: 0, entites: Vec::new(), depuis: 0, zero: 0, courante: AtomicPtr::new(core::ptr::null_mut()) }),
            charge: AtomicUsize::new(0),
            interdites: AtomicUsize::new(0),
        }
    }; processeur::MAX];
    // Le numéro de chaque file : un champ écrit en place (une valeur
    // entière ne détruit rien, ce qu'un `static` exige).
    let mut i = 0;
    while i < processeur::MAX {
        f[i].file.get_mut().numero = i;
        i += 1;
    }
    f
};

/// Le nombre de bascules, pour les tests.
static BASCULES: AtomicU64 = AtomicU64::new(0);

/// La tranche en temps virtuel, pour le poids `poids`.
fn tranche_virtuelle(poids: u64) -> u64 {
    TRANCHE * POIDS_NICE_0 / poids
}

/// La tâche `t` a-t-elle le droit de s'exécuter sur le processeur `n` ? Un
/// masque qui ne permet plus aucun processeur en service vaut « tous » (il
/// a été posé quand ils étaient là : la même règle que `choisir_processeur`,
/// sinon la tâche ne serait plus jamais choisie).
fn permise(t: &Tache, n: usize) -> bool {
    let m = t.affinite();
    m >> n & 1 != 0 || m & processeur::masque_en_service() == 0
}

impl File {
    /// La tâche courante du processeur de cette file (voir le champ) : sous
    /// le verrou.
    fn courante(&self) -> *const Tache {
        self.courante.load(Ordering::Relaxed)
    }

    /// Recompte ce que ce processeur n'a pas le droit d'exécuter dans sa
    /// file (voir `FileProcesseur::interdites`), sous le verrou : à chaque
    /// entrée, sortie, et changement de masque d'une tâche de la file.
    fn recompter_interdites(&self) {
        FILES[self.numero].interdites.store(self.entites.iter().filter(|e| !permise(&e.tache, self.numero)).count(), Ordering::Relaxed);
    }

    /// La moyenne pondérée des temps virtuels (l'`avg_vruntime` de Linux),
    /// calculée sur 128 bits ; celle gardée quand la file s'est vidée, sans
    /// tâche.
    fn moyenne(&self) -> u64 {
        let (somme, poids) = self.entites.iter().fold((0u128, 0u128), |(s, p), e| (s + e.vruntime as u128 * e.poids as u128, p + e.poids as u128));
        if poids == 0 { self.zero } else { (somme / poids) as u64 }
    }

    fn position(&self, t: *const Tache) -> Option<usize> {
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
        let courante = self.courante();
        if courante.is_null() {
            return false;
        }
        // SAFETY: écrite sous ce verrou par `ordonnancer` (une tâche de la
        // file, ou l'inactive, qui ne meurt pas), et une tâche ne quitte la
        // file ni ne meurt que par `ordonnancer` sur son processeur, sous
        // ce même verrou : tant qu'on le tient, elle vit (voir le champ).
        unsafe { &*courante }.compter_calcul(delta);
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
    /// protégée et éligible (RUN_TO_PARITY) ; sinon, parmi les éligibles
    /// que ce processeur a le droit d'exécuter, celle dont l'échéance est la
    /// plus proche (`pick_eevdf`) ; None si la file n'en a aucune (la tâche
    /// inactive).
    fn choisir(&self) -> Option<&Entite> {
        let moyenne = self.moyenne();
        let n = self.numero;
        if let Some(i) = self.position(self.courante())
            && self.entites[i].protegee
            && self.entites[i].vruntime <= moyenne
            && permise(&self.entites[i].tache, n)
        {
            return Some(&self.entites[i]);
        }
        let permises = || self.entites.iter().filter(|e| permise(&e.tache, n));
        permises()
            .filter(|e| e.vruntime <= moyenne)
            .min_by_key(|e| e.echeance)
            // Il y a toujours une éligible (la plus petite est sous la
            // moyenne) ; sinon, par prudence, la plus petite.
            .or_else(|| permises().min_by_key(|e| e.vruntime))
    }

    /// La courante de ce processeur devrait-elle céder la place (une autre
    /// est choisie : `check_preempt_wakeup_fair`) ? Pour la tâche inactive,
    /// dès qu'une tâche permise est là.
    fn doit_ceder(&self) -> bool {
        self.choisir().is_some_and(|e| !core::ptr::eq(Arc::as_ptr(&e.tache), self.courante()))
    }

    /// Une autre tâche que la courante, que ce processeur peut exécuter,
    /// est-elle là ?
    fn une_autre_permise(&self) -> bool {
        let courante = self.courante();
        self.entites.iter().any(|e| permise(&e.tache, self.numero) && !core::ptr::eq(Arc::as_ptr(&e.tache), courante))
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
        assert!(!t.est_en_file(), "tache deja dans une file des pretes");
        assert!(!t.est_morte(), "tache morte remise dans une file des pretes");
        // La place est réservée au démarrage (`initialiser`) : la file ne
        // grandit pas pendant un programme, et l'ordonnanceur n'appelle
        // jamais le tas (il tourne aussi dans les interruptions).
        t.poser_en_file(true, self.numero as u32);
        self.entites.ajouter_dans_la_place(Entite { tache: t, vruntime, echeance: vruntime + tranche, poids, protegee: false });
        FILES[self.numero].charge.store(self.entites.len(), Ordering::Relaxed);
        self.recompter_interdites();
    }

    /// Retire l'entité `i` de la file, en gardant le retard de sa tâche
    /// (`update_entity_lag`) : la moyenne moins son temps virtuel, borné à
    /// plus ou moins deux tranches ou un tic (le plus grand), dans son temps
    /// virtuel. Rend la tâche.
    fn retirer_entite(&mut self, i: usize) -> Arc<Tache> {
        let moyenne = self.moyenne();
        let e = self.entites.swap_remove(i);
        e.tache.poser_en_file(false, 0);
        FILES[self.numero].charge.store(self.entites.len(), Ordering::Relaxed);
        self.recompter_interdites();
        if self.entites.is_empty() {
            self.zero = moyenne;
        }
        let limite = (2 * TRANCHE).max(crate::horloge::nanosecondes(1)) * POIDS_NICE_0 / e.poids;
        let lag = (moyenne as i64 - e.vruntime as i64).clamp(-(limite as i64), limite as i64);
        e.tache.garder_lag(lag);
        e.tache
    }

    /// Retire `t` de la file, si elle y est.
    fn retirer(&mut self, t: *const Tache) {
        if let Some(i) = self.position(t) {
            self.retirer_entite(i);
        }
    }

    /// Une tâche que le processeur `pour` pourrait tirer de cette file : prête
    /// (pas en train de s'exécuter, ni de finir de quitter son processeur),
    /// qu'il a le droit d'exécuter ; d'abord une que CE processeur n'a plus
    /// le droit d'exécuter (voir l'en-tête : l'affinité).
    fn a_tirer(&self, pour: usize) -> Option<usize> {
        let tirable = |e: &Entite| !e.tache.est_sur_processeur() && permise(&e.tache, pour);
        self.entites.iter().position(|e| tirable(e) && !permise(&e.tache, self.numero)).or_else(|| self.entites.iter().position(tirable))
    }
}

/// Réserve la file du processeur 0 pour `max` tâches prêtes (le nombre
/// maximal de fils) : elle ne grandira jamais pendant un programme. Au
/// démarrage.
pub fn initialiser(max: usize) {
    assert!(initialiser_file(0, max), "plus de memoire pour la file des taches pretes");
}

/// Réserve la file du processeur `n` (un secondaire, avant son départ :
/// smp.rs). Faux sans mémoire : le processeur reste de côté.
pub fn initialiser_file(n: usize, max: usize) -> bool {
    let mut f = FILES[n].file.verrouiller();
    if f.entites.try_reserve_exact(max).is_err() {
        return false;
    }
    f.depuis = crate::temps::ns_monotone();
    true
}

/// Le processeur `p` doit regarder s'il cède : son « besoin de céder »
/// (Release : ce qui a été mis dans sa file avant), et l'IPI de
/// reprogrammation s'il n'est pas celui qui exécute ceci (elle le sort de
/// `hlt`, ou il la voit à la sortie de l'interruption).
fn faire_ceder(p: usize, moi: usize) {
    processeur::zone(p).besoin_de_ceder.store(1, Ordering::Release);
    if p != moi {
        crate::smp::reprogrammer(p);
    }
}

/// Le processeur où mettre la tâche `t` (voir l'en-tête : « où va une
/// tâche »), parmi ceux en service que son masque permet (tous, si son
/// masque n'en permet plus aucun : il a été posé quand ils étaient là).
fn choisir_processeur(t: &Tache, neuve: bool) -> usize {
    let en_service = processeur::masque_en_service();
    let permis = match t.affinite() & en_service {
        0 => en_service,
        m => m,
    };
    let candidats = || (0..processeur::MAX).filter(move |&n| permis >> n & 1 != 0);
    let inactif = |n: usize| processeur::zone(n).inactif.load(Ordering::Relaxed);
    if !neuve {
        let dernier = t.processeur() as usize;
        if permis >> dernier & 1 != 0 && inactif(dernier) {
            return dernier;
        }
        if let Some(n) = candidats().find(|&n| inactif(n)) {
            return n;
        }
    }
    candidats().min_by_key(|&n| FILES[n].charge.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Réveille `t` (tache.rs, `reveiller`) : son état passe de « dort » à
/// `pourquoi` SOUS le verrou de sa dernière file, dans la même section
/// critique que la lecture de `en_file` (le `pi_lock` de Linux, tenu de
/// `ttwu_state_match` à `ttwu_queue` ; chez nous le verrou de la file
/// suffit : `ordonnancer` lit l'état et retire la tâche sous ce même
/// verrou). Un compare_exchange gagné avec `en_file` faux dit alors que la
/// tâche s'est retirée pour CE sommeil et ne s'exécutera plus d'elle-même :
/// personne d'autre ne peut la remettre en file, et un second réveilleur
/// trouve un état qui ne dort plus. Préemption coupée du début à la fin
/// (le `guard(preempt)` de `try_to_wake_up` : « moi » ne change pas de
/// sens). Rend faux si elle ne dormait pas, ou pas d'un sommeil que
/// `pourquoi` réveille.
pub fn reveiller(t: Arc<Tache>, pourquoi: Reveil) -> bool {
    processeur::sans_preemption(|| {
        let moi = processeur::courant().numero as usize;
        loop {
            let p = t.processeur() as usize;
            let f = FILES[p].file.verrouiller();
            // Déplacée entre la lecture de son processeur et le verrou
            // (tirée par un autre) : on recommence avec le bon.
            if t.processeur() as usize != p {
                continue;
            }
            if !t.passer_a_reveillee(pourquoi) {
                return false;
            }
            // Le `ttwu_runnable` de Linux : elle n'avait pas fini de
            // s'endormir (son état, réveillé, l'y garde), ou elle est
            // préemptée : rien à ajouter ; elle doit peut-être passer avant
            // la courante de ce processeur.
            if t.est_en_file() {
                if f.doit_ceder() {
                    faire_ceder(p, moi);
                }
                return true;
            }
            drop(f);
            // Sortie de sa file pour ce sommeil ; elle peut n'avoir pas FINI
            // de quitter son processeur (`sur_processeur`, entre sa sortie
            // de la file et la fin de bascule de la tâche suivante) : on
            // attend, sans verrou (la fin de bascule n'a besoin de rien de
            // nous, quelques centaines de cycles), puis on la place.
            while t.est_sur_processeur() {
                core::hint::spin_loop();
            }
            placer(t, false, moi);
            return true;
        }
    })
}

/// Une tâche neuve (clone, un programme lancé) devient prête : dans la file
/// du processeur le moins chargé (`choisir_processeur`). Elle n'est dans
/// aucune file : rien à vérifier, aucun verrou à prendre d'abord.
pub fn rendre_prete(t: Arc<Tache>) {
    processeur::sans_preemption(|| placer(t, true, processeur::courant().numero as usize));
}

/// Met `t` dans la file du processeur que `choisir_processeur` désigne (le
/// `ttwu_queue` de Linux). Si elle devrait passer avant la courante de ce
/// processeur (éligible, et d'échéance plus proche, la courante n'étant pas
/// protégée : `check_preempt_wakeup_fair`), ce processeur cédera au
/// prochain point de préemption (`faire_ceder`). Préemption coupée par
/// l'appelant, qui dit son numéro (`moi`).
fn placer(t: Arc<Tache>, neuve: bool, moi: usize) {
    let p = choisir_processeur(&t, neuve);
    let mut f = FILES[p].file.verrouiller();
    f.compter_courante();
    f.ajouter(t, neuve);
    if f.doit_ceder() {
        faire_ceder(p, moi);
    }
}

/// Le tic d'horloge de ce processeur, interruptions coupées : le temps de
/// sa courante est compté ; si elle a fini sa tranche et qu'une autre
/// attend (ou si c'est l'inactive et qu'une tâche est là), elle cédera.
/// Toutes les TICS_EQUILIBRAGE : l'équilibrage (voir l'en-tête).
pub fn tic() {
    let zone = processeur::courant();
    let moi = zone.numero as usize;
    {
        let mut f = FILES[moi].file.verrouiller();
        let fini = f.compter_courante();
        let inactive = f.position(f.courante()).is_none();
        if (fini || inactive) && f.une_autre_permise() {
            zone.besoin_de_ceder.store(1, Ordering::Relaxed);
        }
    }
    if crate::horloge::tics() % TICS_EQUILIBRAGE == moi as u64 % TICS_EQUILIBRAGE {
        equilibrer(moi);
    }
}

/// Une autre tâche que la courante, que ce processeur peut exécuter,
/// est-elle prête dans sa file ? Interruptions coupées.
pub fn autres_pretes() -> bool {
    let moi = processeur::courant().numero as usize;
    FILES[moi].file.verrouiller().une_autre_permise()
}

/// Faut-il céder le processeur ?
pub fn besoin_de_ceder() -> bool {
    processeur::besoin_de_ceder()
}

/// Tire une tâche de la file `source` vers la file du processeur `moi`,
/// s'il y en a une à tirer (`File::a_tirer`) : les deux verrous dans l'ordre
/// des numéros, et tout revérifié sous eux. Vrai si une tâche a été
/// déplacée. Interruptions coupées (les deux verrous le font).
fn tirer_de(source: usize, moi: usize) -> bool {
    if source == moi {
        return false;
    }
    let (premier, second) = (source.min(moi), source.max(moi));
    let mut a = FILES[premier].file.verrouiller();
    let mut b = FILES[second].file.verrouiller();
    // Des emprunts, pas les gardes elles-mêmes : `a` et `b` sont rendues
    // dans l'ordre inverse de leur prise (la seconde d'abord), quel que soit
    // le sens ; déplacer les gardes dans un couple les aurait rendues dans
    // l'ordre du couple, et la première prise, celle qui a coupé les
    // interruptions, les aurait remises pendant que la seconde est encore
    // tenue (latent ici : les appelants les coupent déjà).
    let (de, vers) = if source == premier { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
    let Some(i) = de.a_tirer(moi) else { return false };
    let t = de.retirer_entite(i);
    vers.compter_courante();
    vers.ajouter(t, false);
    true
}

/// Les processeurs en service autres que `moi`, du plus chargé au moins
/// chargé (la charge lue sans verrou : une indication).
fn par_charge_decroissante(moi: usize) -> impl Iterator<Item = usize> {
    let en_service = processeur::masque_en_service();
    let mut ordre = [0usize; processeur::MAX];
    let mut n = 0;
    for p in (0..processeur::MAX).filter(|&p| p != moi && en_service >> p & 1 != 0) {
        // Une insertion triée : au plus 63 processeurs.
        let charge = FILES[p].charge.load(Ordering::Relaxed);
        let mut i = n;
        while i > 0 && FILES[ordre[i - 1]].charge.load(Ordering::Relaxed) < charge {
            ordre[i] = ordre[i - 1];
            i -= 1;
        }
        ordre[i] = p;
        n += 1;
    }
    ordre.into_iter().take(n)
}

/// Un processeur qui n'a plus rien tire une tâche prête de la file la plus
/// chargée qui en ait une à donner (le `newidle_balance` de Linux). Vrai
/// si une tâche est arrivée dans sa file. Interruptions coupées.
fn tirer(moi: usize) -> bool {
    par_charge_decroissante(moi).any(|source| FILES[source].charge.load(Ordering::Relaxed) > 0 && tirer_de(source, moi))
}

/// L'équilibrage du tic (voir l'en-tête) : d'abord une tâche qu'une file ne
/// peut plus exécuter (son masque a changé pendant qu'elle y était), tirée
/// quelle que soit la charge ; sinon, si la file la plus chargée a au moins
/// deux entités de plus que la nôtre, on lui en tire une.
fn equilibrer(moi: usize) {
    if let Some(source) = par_charge_decroissante(moi).find(|&s| FILES[s].interdites.load(Ordering::Relaxed) > 0)
        && tirer_de(source, moi)
    {
        return;
    }
    let ma_charge = FILES[moi].charge.load(Ordering::Relaxed);
    if let Some(source) = par_charge_decroissante(moi).next()
        && FILES[source].charge.load(Ordering::Relaxed) >= ma_charge + 2
    {
        tirer_de(source, moi);
    }
}

/// Tous les autres processeurs dorment (leur boucle d'inactivité, dans
/// `hlt`) et toutes les files sont vides : plus rien ne s'exécute nulle
/// part, et rien ne peut mettre une tâche dans une file sinon ce
/// processeur (les périphériques n'interrompent que le processeur 0, et
/// un tic sur un processeur inactif ne fait rien). Pour le détecteur
/// d'interblocage (attente.rs), sur le processeur 0, interruptions coupées.
fn machine_inactive() -> bool {
    let en_service = processeur::masque_en_service();
    (0..processeur::MAX).filter(|&p| en_service >> p & 1 != 0).all(|p| {
        (p == 0 || processeur::zone(p).inactif.load(Ordering::Acquire)) && FILES[p].charge.load(Ordering::Relaxed) == 0
    })
}

/// La boucle de la tâche inactive de ce processeur (le code du démarrage
/// pour le premier, main.rs ; `depart_secondaire` pour les autres, smp.rs) :
/// elle prend le processeur quand aucune autre tâche n'est prête, tire du
/// travail d'une autre file s'il y en a, et arrête le processeur (`sti ;
/// hlt`) jusqu'à la prochaine interruption. Sur le processeur 0, elle
/// regarde aussi si des programmes ne sont pas bloqués pour toujours
/// (attente::detecter_interblocage), quand toute la machine est inactive.
/// Une interruption qui rend une tâche prête la préempte aussitôt ; on
/// vérifie quand même la file interruptions coupées avant de dormir (voir
/// cpu::attendre_interruption).
pub fn boucle_inactive() -> ! {
    loop {
        crate::cpu::couper_interruptions();
        let zone = processeur::courant();
        let moi = zone.numero as usize;
        if autres_pretes() || tirer(moi) || (moi == 0 && machine_inactive() && crate::attente::detecter_interblocage()) {
            crate::cpu::activer_interruptions();
            ordonnancer(Bascule::Preemption);
        } else {
            // « Inactif » : Release après avoir vu la file vide ; qui lit
            // « inactif » (le choix d'un processeur, `machine_inactive`)
            // sait qu'il n'y avait rien ici.
            zone.inactif.store(true, Ordering::Release);
            crate::cpu::attendre_interruption();
            zone.inactif.store(false, Ordering::Relaxed);
        }
    }
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

/// Donne le processeur à la tâche que choisit l'EEVDF dans la file de ce
/// processeur (la tâche inactive si elle n'en a aucune), et revient quand
/// la courante le retrouve (jamais, si elle est morte). Jamais verrou tenu :
/// une tâche qui céderait le processeur en tenant un verrou (qui coupe les
/// interruptions) bloquerait tout le monde.
pub fn ordonnancer(bascule: Bascule) {
    let tenus = verrou::tenus();
    assert!(tenus == 0, "ordonnancer avec {} verrou(s) tenu(s)", tenus);
    // Ni préemption coupée, ni dans une interruption (le « scheduling while
    // atomic » de Linux) : le compte de préemption est ainsi toujours nul
    // quand on bascule, et n'a rien à sauver par tâche (processeur.rs).
    assert!(processeur::preemptible(), "ordonnancer preemption coupee ou dans une interruption");
    let interruptions = crate::cpu::couper_interruptions();
    let zone = processeur::courant();
    zone.besoin_de_ceder.store(0, Ordering::Relaxed);
    let courante = tache::courante();
    let suivante = {
        let mut f = FILES[zone.numero as usize].file.verrouiller();
        f.compter_courante();
        // Un sommeil : la courante quitte la file, sauf si un réveil l'a
        // déjà changée d'avis (voir l'en-tête) ; une préemption : jamais.
        if bascule == Bascule::Sommeil && courante.quitte_la_file() {
            f.retirer(courante);
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
        if let Some(i) = choisie.and_then(|c| f.position(c)) {
            f.entites[i].protegee = true;
            f.entites[i].tache.prend_le_processeur();
        } else {
            // SAFETY: l'inactive de ce processeur vit pour toujours.
            unsafe { &*tache::inactive() }.prend_le_processeur();
        }
        // La courante de la file, sous son verrou (voir `File::courante`).
        f.courante.store(choisie.unwrap_or_else(tache::inactive).cast_mut(), Ordering::Relaxed);
        // La courante de la file, sous son verrou (voir `File::courante`).
        f.courante.store(choisie.unwrap_or_else(tache::inactive).cast_mut(), Ordering::Relaxed);
        // Une bascule volontaire si la courante a quitté la file (elle
        // s'endort, ou elle meurt), forcée sinon (getrusage : `__schedule`).
        let volontaire = f.position(courante).is_none();
        (choisie, volontaire)
    };
    let (suivante, volontaire) = suivante;
    let suivante = suivante.unwrap_or_else(tache::inactive);
    if !core::ptr::eq(suivante, courante) {
        // L'inactive qui cède (préemptée depuis `hlt` par une interruption
        // qui a réveillé une tâche) : le processeur n'est plus inactif, et
        // `choisir_processeur` ne doit plus le préférer (la relecture de
        // 6j : le drapeau restait posé jusqu'à son prochain tour de boucle).
        if core::ptr::eq(courante, tache::inactive()) {
            zone.inactif.store(false, Ordering::Relaxed);
        }
        BASCULES.fetch_add(1, Ordering::Relaxed);
        courante.usage().compter_bascule(volontaire);
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
    if besoin_de_ceder() && !processeur::preemption_coupee() {
        ordonnancer(Bascule::Preemption);
    }
}

/// sched_yield : la tâche courante cède le processeur ; comme Linux
/// (`yield_task_fair`), son échéance recule d'une tranche, pour qu'elle
/// passe après les autres éligibles.
pub fn ceder() {
    {
        let interruptions = crate::cpu::couper_interruptions();
        let mut f = FILES[processeur::courant().numero as usize].file.verrouiller();
        f.compter_courante();
        let courante = tache::courante();
        if let Some(i) = f.position(courante) {
            let e = &mut f.entites[i];
            e.echeance += tranche_virtuelle(e.poids);
            e.protegee = false;
        }
        drop(f);
        if interruptions {
            crate::cpu::activer_interruptions();
        }
    }
    ordonnancer(Bascule::Preemption);
}

/// Le masque de la tâche `t` vient de changer (sched_setaffinity, tache.rs ;
/// voir l'en-tête : l'affinité), sous le verrou de sa file : prête dans une
/// file dont le processeur n'est plus permis, elle est déplacée tout de
/// suite ; en cours, ce processeur la fait céder, et la poussera en
/// finissant la bascule (`pousser_si_interdite`) ; endormie, son réveil
/// choisira. Préemption coupée du début à la fin (« moi » ne change pas).
pub fn affinite_changee(t: &Tache) {
    processeur::sans_preemption(|| {
        let moi = processeur::courant().numero as usize;
        loop {
            let p = t.processeur() as usize;
            let mut f = FILES[p].file.verrouiller();
            // Déplacée entre la lecture de son processeur et le verrou.
            if t.processeur() as usize != p {
                continue;
            }
            f.recompter_interdites();
            if permise(t, p) {
                return;
            }
            if t.est_sur_processeur() {
                drop(f);
                faire_ceder(p, moi);
                return;
            }
            let Some(i) = f.position(t) else { return };
            let e = f.retirer_entite(i);
            drop(f);
            placer(e, false, moi);
            return;
        }
    });
}

/// La tâche `t` vient de quitter ce processeur (la fin de sa bascule,
/// tache.rs) : restée dans sa file (préemptée) alors que son masque n'y
/// permet plus son exécution (`affinite_changee` l'a fait céder), elle est
/// poussée maintenant vers un processeur permis (voir l'en-tête : Linux le
/// fait par sa tâche d'arrêt, `migration_cpu_stop`). Les deux verrous dans
/// l'ordre des numéros, tout revérifié sous eux. Interruptions coupées.
pub fn pousser_si_interdite(t: &Tache) {
    let source = processeur::courant().numero as usize;
    if !t.est_en_file() || permise(t, source) {
        return;
    }
    let dest = choisir_processeur(t, false);
    if dest == source {
        return;
    }
    let (premier, second) = (source.min(dest), source.max(dest));
    let mut a = FILES[premier].file.verrouiller();
    let mut b = FILES[second].file.verrouiller();
    let (de, vers) = if source == premier { (&mut *a, &mut *b) } else { (&mut *b, &mut *a) };
    let Some(i) = de.position(t) else { return };
    if de.entites[i].tache.est_sur_processeur() || permise(t, source) {
        return;
    }
    let e = de.retirer_entite(i);
    vers.compter_courante();
    vers.ajouter(e, false);
    if vers.doit_ceder() {
        faire_ceder(dest, source);
    }
}

/// Le nombre de bascules depuis le démarrage.
pub fn bascules() -> u64 {
    BASCULES.load(Ordering::Relaxed)
}
