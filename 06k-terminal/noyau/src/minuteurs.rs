//! Les minuteurs du noyau : une échéance qui déclenche quelque chose à son
//! heure, sans tâche qui dorme pour elle (le `hrtimer` de Linux). Le
//! premier client est timerfd (timerfd.rs) : un fichier qui devient lisible
//! à l'échéance ; viendront ITIMER_REAL (SIGALRM) et timer_create.
//!
//! Jusqu'ici, seule une tâche qui dort pouvait attendre une échéance (les
//! minuteries d'attente.rs : une par tâche, réservée au démarrage). Un
//! timerfd armé, lui, n'a personne qui dorme : il doit compter son
//! échéance même si personne ne le lit encore, et réveiller ceux qui le
//! sondent (poll, epoll). D'où un objet à part, le `Minuteur`, rangé dans
//! une table des échéances que le tic du processeur 0 parcourt
//! (attente::tic), comme les minuteries des tâches.
//!
//! LA TABLE : un `Vec` trié par échéance DÉCROISSANTE, la plus proche à la
//! fin (le tic la prend par `pop`, sans rien déplacer). Insérer coûte un
//! déplacement de la fin du tableau. Options écartées :
//!   - l'arbre rouge-noir de Linux (la `timerqueue` des hrtimer) : en
//!     O(log n), mais des centaines de lignes de rééquilibrage pour gagner
//!     sur des milliers de minuteurs armés ; nos programmes en arment
//!     quelques-uns ;
//!   - la roue des minuteurs (roue/, celle du réseau, le `timer_list` de
//!     Linux) : faite pour des délais qu'on annule presque toujours avant
//!     l'échéance (une retransmission TCP), au prix d'une échéance arrondie
//!     à sa case ; un timerfd doit tomber à son tic, pas à sa case.
//!
//! AUCUNE ALLOCATION À L'ARMEMENT : armer peut se faire dans le tic (un
//! minuteur périodique), ou sous des verrous. La place de chaque minuteur
//! dans la table est donc RÉSERVÉE à sa création (`Minuteur::nouveau`, qui
//! peut échouer : ENOMEM), et rendue à sa fin : la capacité du tableau
//! couvre toujours tous les minuteurs qui existent, donc tous ceux qui
//! peuvent être armés à la fois. La réserve grandit (et rapetisse) hors du
//! verrou de la table : le nouveau tableau est alloué d'abord, puis les
//! entrées y passent sous le verrou, sans allocation ; l'ancien est rendu
//! après. Quand plus aucun minuteur n'existe, le tableau est rendu tout
//! entier : la mémoire d'un programme qui a fini est toute revenue
//! (« memoire rendue »).
//!
//! DEUX VERROUS, et un ordre : celui du minuteur (son `Etat`), puis celui
//! de la table. Armer et désarmer se font sous le premier, et prennent le
//! second pour ranger l'échéance. Le tic, lui, ne tient jamais les deux :
//! il sort les échéances passées de la table, la rend, puis prend chaque
//! minuteur (le `__run_hrtimer` de Linux, qui rend le verrou de sa base
//! pendant le rappel). Une échéance sortie par le tic peut alors avoir été
//! réarmée ou désarmée entre-temps, sur un autre processeur : chaque
//! armement a sa GÉNÉRATION, et une échéance d'une génération passée est
//! ignorée. C'est notre `hrtimer_cancel`, sans attendre la fin d'un rappel
//! en cours : le rappel périmé ne fait rien. Ce qu'il fait à l'échéance
//! (réveiller une file) se fait hors des deux verrous : le réveil prend
//! celui de la file, puis ceux des epoll qui y sont inscrits, qu'on
//! n'imbrique pas sous celui du minuteur.
//!
//! L'échéance est servie au tic qui la suit (1 ms, horloge.rs), jamais
//! avant, comme les sommeils ; le compte des échéances d'un minuteur
//! périodique, lui, est exact (`avancer` le calcule sur l'heure, comme
//! `hrtimer_forward`).
//!
//! LES ÉCHÉANCES SONT SIGNÉES, en temps monotone, comme le `ktime_t` de
//! Linux : une échéance absolue de la date (REALTIME) d'avant le démarrage
//! est négative. Linux la garde dans la base REALTIME de son hrtimer, et un
//! périodique compte ses périodes depuis elle : la ramener à 0 (le
//! démarrage) fausserait ce compte et la phase des suivantes. La table,
//! elle, la range à 0 : elle est due tout de suite.
//!
//! LA BASE de chaque armement : Linux range un hrtimer dans la base de son
//! horloge, à son armement (`hrtimer_setup`), sauf un REALTIME relatif,
//! qui va dans la base MONOTONIC (« POSIX magic » : un délai ne suit pas
//! les réglages de la date) ; TAI, lui, reste dans la sienne. Ce qui en
//! dépend : son KTIME_MAX, qui borne une échéance relative et la dernière
//! période ajoutée (`ktime_add_safe`, dans la base) ; mesuré, un REALTIME
//! relatif de LONG_MAX secondes laisse KTIME_MAX moins le temps monotone,
//! un absolu, KTIME_MAX moins la date. Chaque armement garde donc l'écart
//! de sa base au temps monotone (`decalage` : 0, ou celui de la date).

use alloc::vec::Vec;

use crate::attente::FileAttente;
use crate::faillible::VecFaillible;
use crate::partage::Arc;
use crate::sondage::POLLIN;
use crate::temps::KTIME_MAX;
use crate::verrou::{Garde, Verrou};

/// Ce que fait un minuteur à son échéance, hors de ses verrous.
pub enum Quoi {
    /// Un timerfd : réveiller sa file (ceux qui le lisent, le sondent, les
    /// epoll qui le surveillent), avec POLLIN.
    Fichier(FileAttente),
}

/// L'état d'un minuteur, sous son verrou. Les champs `intervalle`,
/// `echus` et `echu` sont ceux de son propriétaire (pour un timerfd : le
/// `tintv`, les `ticks` et `expired` de la `timerfd_ctx` de Linux, sous le
/// même verrou que son hrtimer, le `wqh.lock`).
pub struct Etat {
    /// L'échéance programmée, en temps monotone (ns), signée (l'en-tête),
    /// gardée une fois passée (le `expires` d'un hrtimer : le temps restant
    /// d'un minuteur échu est nul, pas inconnu) ; 0 s'il n'a jamais été
    /// armé.
    echeance: i64,
    /// L'écart de la base de son armement au temps monotone (0, ou celui de
    /// la date : `temps::decalage_de_la_date`).
    decalage: i64,
    /// Armé, l'échéance pas encore servie (`hrtimer_is_queued`).
    en_file: bool,
    /// Le numéro de l'armement en cours (voir l'en-tête).
    generation: u64,
    /// La période d'un minuteur périodique (ns) ; 0 : une seule fois.
    pub intervalle: u64,
    /// Les échéances servies et pas encore prises.
    pub echus: u64,
    /// Servi depuis le dernier armement : un périodique est à réarmer.
    pub echu: bool,
}

struct Coeur {
    etat: Verrou<Etat>,
    quoi: Quoi,
}

/// Un minuteur, à son propriétaire (un timerfd...). La table en garde
/// une référence tant qu'il est armé ; le propriétaire qui le lâche le
/// désarme et rend sa place (`Drop`).
pub struct Minuteur(Arc<Coeur>);

/// La table des échéances : les minuteurs armés, par échéance
/// décroissante (échéance, génération, minuteur), et le nombre de
/// minuteurs qui existent, à qui la place est réservée.
struct Table {
    armes: Vec<(u64, u64, Arc<Coeur>)>,
    reserves: usize,
}

static TABLE: Verrou<Table> = Verrou::new(Table { armes: Vec::new(), reserves: 0 });

/// La capacité voulue pour `reserves` minuteurs : de la marge (le double),
/// pour ne pas réallouer à chaque création ; rien s'il n'y en a plus.
fn capacite_voulue(reserves: usize) -> usize {
    if reserves == 0 { 0 } else { (reserves * 2).max(8) }
}

/// Ajuste la place réservée de `ecart` minuteurs (+1 à une création, -1 à
/// une fin), et le tableau à la réserve : agrandi s'il manque de place,
/// rendu ou réduit quand il en a plus de quatre fois trop. Faux si la place
/// manque et que la mémoire ne suffit pas (rien n'est alors réservé).
fn ajuster(ecart: isize) -> bool {
    loop {
        let voulue = {
            let mut t = TABLE.verrouiller();
            let reserves = t.reserves.saturating_add_signed(ecart);
            let capacite = t.armes.capacity();
            if reserves <= capacite && capacite <= capacite_voulue(reserves).saturating_mul(4) {
                t.reserves = reserves;
                return true;
            }
            capacite_voulue(reserves)
        };
        // Le nouveau tableau, hors du verrou. La réserve a pu changer
        // entre-temps : sa taille est revue sous le verrou.
        let mut neuf: Vec<(u64, u64, Arc<Coeur>)> = Vec::new();
        if voulue != 0 && neuf.try_reserve_exact(voulue).is_err() {
            if ecart > 0 {
                return false;
            }
            // Une réduction ratée ne gêne pas : l'ancien tableau reste.
            let mut t = TABLE.verrouiller();
            t.reserves = t.reserves.saturating_add_signed(ecart);
            return true;
        }
        let ancien = {
            let mut t = TABLE.verrouiller();
            let reserves = t.reserves.saturating_add_signed(ecart);
            if neuf.capacity() < reserves.max(t.armes.len()) {
                // Trop petit : la réserve a grandi entre-temps. Un autre tour.
                continue;
            }
            // Sans allocation : la place y est.
            for entree in t.armes.drain(..) {
                neuf.ajouter_dans_la_place(entree);
            }
            t.reserves = reserves;
            core::mem::replace(&mut t.armes, neuf)
        };
        // L'ancien tableau, vide, rendu hors du verrou.
        drop(ancien);
        return true;
    }
}

impl Minuteur {
    /// Un minuteur neuf, désarmé, qui fera `quoi` à ses échéances, sa place
    /// réservée dans la table. None : plus de mémoire.
    pub fn nouveau(quoi: Quoi) -> Option<Minuteur> {
        let etat = Etat { echeance: 0, decalage: 0, en_file: false, generation: 0, intervalle: 0, echus: 0, echu: false };
        let coeur = Arc::new(Coeur { etat: Verrou::new(etat), quoi }).ok()?;
        if !ajuster(1) {
            return None;
        }
        Some(Minuteur(coeur))
    }

    /// Ce qu'il fait à ses échéances (pour un timerfd : sa file).
    pub fn quoi(&self) -> &Quoi {
        &self.0.quoi
    }

    /// Son état, sous son verrou, pour l'armer, le désarmer, le lire.
    pub fn verrouiller(&self) -> GardeMinuteur<'_> {
        GardeMinuteur { coeur: &self.0, etat: self.0.etat.verrouiller() }
    }
}

impl Drop for Minuteur {
    /// Le propriétaire le lâche (un timerfd fermé) : désarmé, sa place
    /// rendue. Une échéance déjà sortie par le tic, et pas encore servie,
    /// garde le cœur en vie jusqu'à son rappel, qui la verra périmée.
    fn drop(&mut self) {
        self.verrouiller().desarmer();
        ajuster(-1);
    }
}

/// Le verrou d'un minuteur, tenu.
pub struct GardeMinuteur<'a> {
    coeur: &'a Arc<Coeur>,
    etat: Garde<'a, Etat>,
}

impl core::ops::Deref for GardeMinuteur<'_> {
    type Target = Etat;
    fn deref(&self) -> &Etat {
        &self.etat
    }
}

impl core::ops::DerefMut for GardeMinuteur<'_> {
    fn deref_mut(&mut self) -> &mut Etat {
        &mut self.etat
    }
}

impl Etat {
    /// Le KTIME_MAX de sa base, en temps monotone.
    fn plafond(&self) -> i64 {
        (KTIME_MAX as i64).saturating_sub(self.decalage)
    }

    /// Prend la base d'écart `decalage` (l'en-tête), et rend l'échéance
    /// `duree` après `maintenant` (temps monotone), au plus le KTIME_MAX de
    /// la base (le `ktime_add_safe` d'`hrtimer_start` en mode relatif).
    pub fn echeance_relative(&mut self, maintenant: u64, duree: u64, decalage: i64) -> i64 {
        self.decalage = decalage;
        (maintenant as i64).saturating_add_unsigned(duree).min(self.plafond())
    }

    /// Prend la base d'écart `decalage`, et rend l'échéance absolue
    /// `valeur` de cette base (au plus KTIME_MAX : `temps::duree`), en temps
    /// monotone.
    pub fn echeance_absolue(&mut self, valeur: u64, decalage: i64) -> i64 {
        self.decalage = decalage;
        (valeur.min(KTIME_MAX) as i64).saturating_sub(decalage)
    }
}

/// Avance l'échéance `echeance` d'autant de périodes `intervalle` qu'il faut
/// pour dépasser `maintenant` : la nouvelle échéance et le nombre de
/// périodes (le `hrtimer_forward` de Linux, ligne à ligne), ou l'échéance
/// telle quelle et 0 si elle n'est pas passée. Une période plus courte que
/// la nanoseconde (la résolution des hrtimer) compte pour une nanoseconde.
/// En entiers de 128 bits : l'écart entre une échéance négative et
/// `maintenant` dépasse un i64.
fn avancer(echeance: i128, maintenant: i128, intervalle: u64) -> (i128, u64) {
    if maintenant < echeance {
        return (echeance, 0);
    }
    let delta = maintenant - echeance;
    let intervalle = intervalle.max(1) as i128;
    let mut periodes = 1;
    let mut nouvelle = echeance;
    if delta >= intervalle {
        periodes = delta / intervalle;
        nouvelle += intervalle * periodes;
        if nouvelle > maintenant {
            return (nouvelle, periodes as u64);
        }
        // Un multiple exact : une période de plus.
        periodes += 1;
    }
    (nouvelle + intervalle, periodes.min(u64::MAX as i128) as u64)
}

impl GardeMinuteur<'_> {
    /// Le retire de la table s'il y est (une échéance sortie par le tic n'y
    /// est plus : sa génération la périmera).
    fn sortir(&mut self) {
        if self.etat.en_file {
            let mut t = TABLE.verrouiller();
            let generation = self.etat.generation;
            if let Some(i) = t.armes.iter().position(|(_, g, c)| *g == generation && Arc::ptr_eq(c, self.coeur)) {
                t.armes.remove(i);
            }
            self.etat.en_file = false;
        }
        self.etat.generation = self.etat.generation.wrapping_add(1);
    }

    /// L'arme pour `echeance` (temps monotone, ns, signée), à la place d'un
    /// armement en cours (`hrtimer_start`). Une échéance déjà passée est
    /// servie au tic suivant : une négative est rangée à 0.
    pub fn armer(&mut self, echeance: i64) {
        self.sortir();
        self.etat.echeance = echeance;
        self.etat.en_file = true;
        let generation = self.etat.generation;
        let echeance = echeance.max(0) as u64;
        let mut t = TABLE.verrouiller();
        let i = t.armes.partition_point(|&(e, _, _)| e > echeance);
        // Après les échéances plus lointaines, avant les égales : les égales
        // sont servies dans l'ordre de leur armement. La place est réservée
        // (`Minuteur::nouveau`).
        t.armes.inserer_dans_la_place(i, (echeance, generation, self.coeur.clone()));
    }

    /// Le réarme pour son échéance, telle que `avancer` l'a mise
    /// (`hrtimer_restart`).
    pub fn rearmer(&mut self) {
        let e = self.etat.echeance;
        self.armer(e);
    }

    /// Le désarme (`hrtimer_cancel`) ; son échéance reste ce qu'elle était.
    pub fn desarmer(&mut self) {
        self.sortir();
    }

    /// Le désarme et oublie son échéance (un minuteur qu'on remet à zéro :
    /// `hrtimer_setup` efface tout le hrtimer).
    pub fn effacer(&mut self) {
        self.sortir();
        self.etat.echeance = 0;
    }

    /// Le temps qui reste jusqu'à son échéance (ns), nul si elle est passée
    /// ou s'il n'a jamais été armé (`hrtimer_expires_remaining`, ramené à
    /// zéro comme `timerfd_get_remaining`).
    pub fn restant(&self, maintenant: u64) -> u64 {
        (self.etat.echeance as i128 - maintenant as i128).max(0) as u64
    }

    /// Avance son échéance d'autant de périodes qu'il faut pour dépasser
    /// `maintenant`, et rend leur nombre (`avancer`, plus haut) : 0 si
    /// l'échéance n'est pas passée, ou s'il est encore armé. La dernière
    /// période s'ajoute au plus jusqu'au KTIME_MAX de sa base
    /// (`hrtimer_add_expires`, par `ktime_add_safe`).
    pub fn avancer(&mut self, maintenant: u64, intervalle: u64) -> u64 {
        if self.etat.en_file {
            return 0;
        }
        let (echeance, periodes) = avancer(self.etat.echeance as i128, maintenant as i128, intervalle);
        self.etat.echeance = echeance.min(self.etat.plafond() as i128) as i64;
        periodes
    }
}

/// Le tic du processeur 0, interruptions coupées : les échéances passées
/// sont servies, une à une, chacune hors du verrou de la table (voir
/// l'en-tête).
pub fn tic(maintenant: u64) {
    loop {
        let (generation, coeur) = {
            let mut t = TABLE.verrouiller();
            match t.armes.last() {
                Some(&(e, _, _)) if e <= maintenant => {}
                _ => return,
            }
            let Some((_, g, c)) = t.armes.pop() else { return };
            (g, c)
        };
        {
            let mut e = coeur.etat.verrouiller();
            if !e.en_file || e.generation != generation {
                continue;
            }
            e.en_file = false;
            e.echu = true;
            e.echus = e.echus.saturating_add(1);
        }
        match &coeur.quoi {
            // Comme le `wake_up_locked_poll` de `timerfd_triggered` : tous les
            // ordinaires, une exclusive (un epoll en EPOLLEXCLUSIVE).
            Quoi::Fichier(file) => file.reveiller(POLLIN, 1),
        }
        // Le cœur d'un minuteur que son propriétaire a lâché entre-temps
        // est rendu ici (le dernier Arc), hors de tout verrou.
        drop(coeur);
    }
}

/// Un minuteur est-il armé ? (Le détecteur d'interblocage, attente.rs :
/// une échéance peut encore réveiller un programme. Seuls les programmes
/// ont des minuteurs.)
pub fn un_arme() -> bool {
    !TABLE.verrouiller().armes.is_empty()
}
