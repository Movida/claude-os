//! Les minuteurs POSIX : timer_create, timer_settime, timer_gettime,
//! timer_getoverrun et timer_delete (le kernel/time/posix-timers.c de
//! Linux, et la part de posix-cpu-timers.c qui sert les horloges de
//! calcul). Un processus en crée autant qu'il veut, chacun sur une
//! horloge, et chacun prévient à son échéance par un signal de son choix
//! (SIGEV_SIGNAL : au processus ; SIGEV_THREAD_ID : à l'un de ses fils, ce
//! dont la glibc fait SIGEV_THREAD, un fil qu'elle crée et qui attend le
//! signal 32), ou pas du tout (SIGEV_NONE : on le lit par timer_gettime).
//! Ils sont au processus, communs à ses fils (la `signal_struct` de Linux),
//! sous son verrou : Linux a un verrou par minuteur (`it_lock`) ; ces
//! appels sont rares, et le verrou du processus est déjà celui des signaux
//! qu'ils envoient (le `siglock`), qu'il faut de toute façon prendre.
//!
//! LE SIGINFO EST PRÉALLOUÉ, comme chez Linux (la `sigq` de la `k_itimer`) :
//! compté dans la limite RLIMIT_SIGPENDING dès timer_create (EAGAIN au-delà),
//! toute la vie du minuteur, il n'est jamais refusé à l'envoi, et sa place
//! est réservée dans la file des signaux qu'il vise (signaux.rs, `places`) :
//! l'envoi, dans le tic, n'alloue rien. Il n'est en file qu'une fois : une
//! échéance qui le trouve encore en attente ne fait rien de plus, et
//! timer_getoverrun dira combien d'échéances se sont fondues en lui (le
//! « dépassement », `it_overrun`, borné à INT_MAX : DELAYTIMER_MAX).
//!
//! RÉARMÉ AU RETRAIT DE SON SIGNAL : un minuteur périodique n'est pas
//! réarmé à l'échéance, mais quand son signal est pris (signaux.rs,
//! `prendre_parmi` appelle `signal_pris`, le `posixtimer_deliver_signal`
//! de Linux) : il repart alors à la première période qui suit l'heure, et
//! les périodes sautées vont dans le dépassement, que le siginfo livré
//! porte (si_overrun). Un signal bloqué arrête donc le minuteur jusqu'à ce
//! qu'il soit pris, sans rien perdre du compte. Option écartée : le
//! réarmer dans le tic, comme un timerfd ; il faudrait compter les
//! dépassements pendant qu'il attend, et le minuteur tournerait pour un
//! signal que personne ne prend.
//!
//! DEUX SÉQUENCES (`seq_signal`, `seq_file` : les `it_signal_seq` et
//! `it_sigqueue_seq` de Linux). Chaque timer_settime, et timer_delete,
//! avance la première ; l'envoi recopie la première dans la seconde. Un
//! signal pris alors qu'elles diffèrent vient d'un armement passé : il est
//! jeté, sans réarmer (sigpending le montrait, sigtimedwait ne le rend
//! pas : mesuré). Le siginfo en file reste donc où il est, et c'est le
//! retrait qui trie.
//!
//! IGNORÉ, UN PÉRIODIQUE EST MIS DE CÔTÉ (la « ignored list » de Linux,
//! depuis 6.13) : un signal ignoré est jeté à l'envoi, et un minuteur
//! réarmé au retrait ne repartirait jamais. Son minuteur est alors marqué
//! `ignore` ; quand un gestionnaire remplace SIG_IGN (rt_sigaction), son
//! signal est remis en file (`designorer`), et le retrait le réarmera. Un
//! signal de minuteur périodique en attente qu'une action SIG_IGN efface est
//! mis de côté de même (`retire_de_la_file`). Un minuteur qui ne sonne
//! qu'une fois perd son signal ignoré, comme tout signal.
//!
//! LES HORLOGES : REALTIME et TAI (la date), MONOTONIC et BOOTTIME (le temps
//! depuis le démarrage, qui est aussi le temps écoulé : notre machine ne se
//! met pas en veille) servent un minuteur du noyau (minuteurs.rs, en temps
//! monotone ; une échéance absolue de la date y est convertie à
//! l'armement, la date ne sautant jamais : pas de clock_settime). Les
//! horloges de calcul, PROCESS_CPUTIME_ID et THREAD_CPUTIME_ID (le temps de
//! calcul exact, en nanosecondes : celui de clock_gettime), sont regardées
//! au retour vers l'anneau 3 qui suit un tic (`verifier_calcul`, à côté des
//! alarmes de calcul d'alarmes.rs) : le temps de calcul ne passe une
//! échéance que pendant que le programme calcule. Les horloges de calcul
//! encodées (temps.rs, `genre` : celles que passe la glibc pour ces deux
//! noms, -6 et -2, et celles de clock_getcpuclockid et
//! pthread_getcpuclockid) aussi, SCHED, PROF ou VIRT, celles du processus
//! et de ses fils ; une qui ne vise personne rend EINVAL, son numéro déjà
//! écrit (`posix_cpu_timer_create`). Un écart : celle d'un AUTRE processus
//! est refusée de même ; Linux range ce minuteur chez le processus visé,
//! que regardent ses propres tics, quand les nôtres ne sont regardés que
//! par les retours de leur processus. Les horloges des alarmes
//! (CLOCK_*_ALARM) demandent CAP_WAKE_ALARM : EPERM ; MONOTONIC_RAW, les
//! COARSE et les horloges des descripteurs n'ont pas de minuteurs :
//! EOPNOTSUPP.
//!
//! Tout ce qui est décrit ici a été mesuré sous Linux 6.18.33 (le
//! programme de test : linux/minuteurs.c).

use alloc::vec::Vec;

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::faillible::VecFaillible;
use crate::minuteurs::{self, Minuteur, Quoi};
use crate::processus::{self, Processus};
use crate::signaux::{self, Destinataire, Info};
use crate::tache;
use crate::temps::{self, DeCalcul, Genre, Mesure};

const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EOPNOTSUPP: i64 = 95;

const SIGALRM: u64 = 14;

/// Les façons de prévenir (`sigev_notify`).
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;

/// timer_settime : une échéance absolue (sinon relative).
const TIMER_ABSTIME: u64 = 1;

/// Le plus grand numéro de minuteur, et le plus grand dépassement rendu
/// (INT_MAX, DELAYTIMER_MAX).
const INT_MAX: u32 = i32::MAX as u32;

/// L'horloge d'un minuteur.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Horloge {
    /// MONOTONIC, BOOTTIME : le temps monotone.
    Monotone,
    /// REALTIME : la date (une échéance absolue est convertie).
    Date,
    /// TAI : la même chez nous (l'écart de TAI vaut 0, comme chez Linux au
    /// démarrage), mais une échéance relative y reste dans sa base.
    Tai,
    /// Une horloge de calcul : celle du processus (None) ou de l'un de ses
    /// fils, et ce qu'elle compte.
    Calcul(Option<u32>, Mesure),
}

/// Où en est un minuteur (l'`it_status` de Linux).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Statut {
    Desarme,
    Arme,
    /// Échu, périodique : réarmé quand son signal sera pris.
    ReArmerAuRetrait,
}

/// Un minuteur POSIX (la `k_itimer` de Linux).
struct MinuteurPosix {
    /// Son numéro (le `timer_t` du programme).
    id: i32,
    /// Faux tant que timer_create n'a pas fini (le bit 0 de l'`it_signal`
    /// de Linux) : le numéro est pris, mais aucun appel ne le trouve.
    valide: bool,
    horloge: Horloge,
    /// SIGEV_NONE : jamais de signal.
    aucun_signal: bool,
    /// À qui va son signal (SIGEV_THREAD_ID : un fil).
    destinataire: Destinataire,
    /// Son siginfo préalloué : SI_TIMER, si_tid (son numéro), si_value.
    info: Info,
    /// Il tient une place dans le compte RLIMIT_SIGPENDING (rendue à sa
    /// fin), sauf s'il l'a passée à son siginfo resté en file (`detruire`).
    compte: bool,
    /// Le minuteur du noyau d'une horloge du temps ; None pour une horloge
    /// de calcul.
    minuteur: Option<Minuteur>,
    /// L'échéance d'une horloge de calcul (ns de calcul) ; 0 : aucune.
    echeance_calcul: u64,
    /// La période (ns) ; 0 : une seule fois.
    intervalle: u64,
    statut: Statut,
    /// Les échéances fondues dans le signal à venir, moins une (`it_overrun`,
    /// qui part de -1), et celles du dernier signal livré (`it_overrun_last`).
    depassement: i64,
    dernier_depassement: i64,
    /// Voir l'en-tête.
    seq_signal: u64,
    seq_file: u64,
    /// Son siginfo est dans une file de signaux.
    en_file: bool,
    /// Mis de côté : son signal périodique était ignoré (l'en-tête).
    ignore: bool,
    /// Le dernier envoi venait d'une échéance périodique (`it_sig_periodic`).
    periodique_a_l_envoi: bool,
}

impl Drop for MinuteurPosix {
    /// Sa place dans le compte des siginfo est rendue (son minuteur du noyau,
    /// désarmé, rend la sienne).
    fn drop(&mut self) {
        if self.compte {
            signaux::rendre_prealloue();
        }
    }
}

/// Les minuteurs POSIX d'un processus, par numéro croissant (le
/// `posix_timers` de la `signal_struct`), et le prochain numéro à donner
/// (`next_posix_timer_id`).
pub struct Minuteurs {
    liste: Vec<MinuteurPosix>,
    prochain: u32,
}

impl Minuteurs {
    pub const fn new() -> Minuteurs {
        Minuteurs { liste: Vec::new(), prochain: 0 }
    }

    /// L'indice du minuteur valide de numéro `id` (un int pour Linux).
    fn indice(&self, id: u64) -> Option<usize> {
        let id = id as u32 as i32;
        let i = self.liste.binary_search_by_key(&id, |m| m.id).ok()?;
        self.liste[i].valide.then_some(i)
    }
}

/// Un numéro libre : le suivant, ramené dans [0, INT_MAX], jamais celui
/// d'un minuteur qui existe (`posix_timer_add`). Linux fait autant d'essais
/// qu'il y a de numéros (INT_MAX + 1) ; il y a moins de minuteurs que de
/// numéros, le premier tour en trouve un.
fn numero_libre(m: &mut Minuteurs) -> Option<(i32, usize)> {
    for _ in 0..=INT_MAX {
        let id = (m.prochain & INT_MAX) as i32;
        m.prochain = m.prochain.wrapping_add(1);
        if let Err(i) = m.liste.binary_search_by_key(&id, |t| t.id) {
            return Some((id, i));
        }
    }
    None
}

/// Le temps que lit l'horloge `h` (None : le fil n'existe plus).
fn echantillon(p: &mut Processus, h: Horloge) -> Option<u64> {
    match h {
        Horloge::Calcul(None, m) => Some(temps::mesurer(m, tache::temps_du_processus(), tache::tics_du_processus())),
        Horloge::Calcul(Some(tid), m) if tid == tache::courante().tid() => {
            let t = tache::courante();
            Some(temps::mesurer(m, t.calcul(), t.usage().tics()))
        }
        Horloge::Calcul(Some(tid), m) => p.fil(tid)?.tache.upgrade().map(|t| temps::mesurer(m, t.calcul(), t.usage().tics())),
        _ => Some(temps::ns_monotone()),
    }
}

/// L'envoi du signal d'un minuteur échu, sous le verrou du processus (le
/// `posixtimer_send_sigqueue` de Linux), dans son ordre : le destinataire
/// (un fil qui a fini : rien), la séquence recopiée, puis le signal
/// ignoré (jeté ; un périodique mis de côté), déjà en file (rien de plus :
/// le dépassement compte), ou mis en file, son fil prévenu.
fn envoyer(p: &mut Processus, i: usize) {
    let m = &mut p.minuteurs.liste[i];
    let (dest, info) = (m.destinataire, m.info);
    if let Destinataire::Fil(tid) = dest {
        if p.fil(tid).is_none() {
            return;
        }
    }
    let m = &mut p.minuteurs.liste[i];
    m.seq_file = m.seq_signal;
    m.periodique_a_l_envoi = m.statut == Statut::ReArmerAuRetrait;
    let pret = signaux::preparer(p, info.signal(), dest);
    let m = &mut p.minuteurs.liste[i];
    if !pret {
        // Ignoré. Déjà en file (bloqué quand il est devenu ignoré, puis
        // débloqué sans avoir encore été pris) : il y reste. Sinon, un
        // périodique est mis de côté, un unique perdu.
        if !m.en_file {
            m.ignore = m.periodique_a_l_envoi;
        }
        return;
    }
    if m.en_file {
        return;
    }
    // Mis de côté puis bloqué, sans que rien ne lève l'ignorance : il
    // revient en file, comme un signal ordinaire.
    m.ignore = false;
    m.en_file = true;
    signaux::reveiller(signaux::mettre_en_file_prealloue(p, dest, info));
}

/// Une échéance passée (`posix_timer_queue_signal`) : un périodique sera
/// réarmé au retrait de son signal.
fn echu(p: &mut Processus, i: usize) {
    let m = &mut p.minuteurs.liste[i];
    m.statut = if m.intervalle != 0 { Statut::ReArmerAuRetrait } else { Statut::Desarme };
    envoyer(p, i);
}

/// L'échéance du minuteur `id` du processus `pid`, dans le tic
/// (minuteurs.rs), hors de tout verrou : `servir` (sous le verrou du
/// processus, puis celui du minuteur) dit si l'armement sorti de la table
/// est toujours le sien. Un minuteur détruit entre-temps a été désarmé :
/// `servir` le voit.
pub fn sonner(pid: u32, id: i32, servir: impl FnOnce() -> bool) {
    processus::avec_pid(pid, |p| {
        if !servir() {
            return;
        }
        if let Some(i) = p.minuteurs.indice(id as u32 as u64) {
            echu(p, i);
        }
    });
}

/// Une échéance d'horloge de calcul passée (`cpu_timer_fire`) : un unique
/// oublie son échéance.
fn calcul_echu(p: &mut Processus, i: usize) {
    p.minuteurs.liste[i].statut = Statut::Desarme;
    echu(p, i);
    let m = &mut p.minuteurs.liste[i];
    if m.intervalle == 0 {
        m.echeance_calcul = 0;
    }
}

/// Les minuteurs des horloges de calcul, au retour vers l'anneau 3 du fil
/// `tid` qui suit un tic (tache.rs, `decider`), sous le verrou du processus :
/// `processus` et `fil` sont les temps de calcul du processus et du fil,
/// exacts et en tics (programme, noyau). Seuls les minuteurs du fil
/// lui-même : le temps d'un autre n'avance que quand il calcule, et ce sont
/// ses propres retours qui le regardent (le `check_thread_timers` de Linux,
/// puis `check_process_timers`).
pub fn verifier_calcul(p: &mut Processus, tid: u32, processus: (u64, (u64, u64)), fil: (u64, (u64, u64))) {
    for i in 0..p.minuteurs.liste.len() {
        let m = &p.minuteurs.liste[i];
        let t = match m.horloge {
            Horloge::Calcul(None, mesure) => temps::mesurer(mesure, processus.0, processus.1),
            Horloge::Calcul(Some(f), mesure) if f == tid => temps::mesurer(mesure, fil.0, fil.1),
            _ => continue,
        };
        if m.valide && m.statut == Statut::Arme && m.echeance_calcul != 0 && t >= m.echeance_calcul {
            calcul_echu(p, i);
        }
    }
}

/// Le siginfo préalloué du minuteur `id` vient d'être pris parmi les
/// signaux du fil ou du processus, sous son verrou (signaux.rs : le
/// `posixtimer_deliver_signal` de Linux) : faux s'il est périmé (un
/// armement passé, un minuteur détruit), il est alors jeté ; sinon, un
/// périodique repart, et le siginfo porte ses dépassements.
pub fn signal_pris(p: &mut Processus, id: i32, info: &mut Info) -> bool {
    let Some(i) = p.minuteurs.indice(id as u32 as u64) else { return false };
    let m = &mut p.minuteurs.liste[i];
    m.en_file = false;
    if m.seq_signal != m.seq_file {
        return false;
    }
    if m.intervalle == 0 || m.statut != Statut::ReArmerAuRetrait {
        return true;
    }
    let iv = m.intervalle;
    let horloge = m.horloge;
    match horloge {
        Horloge::Calcul(..) => {
            // `posix_cpu_timer_rearm` : rien si le fil a fini.
            let Some(t) = echantillon(p, horloge) else { return true };
            let m = &mut p.minuteurs.liste[i];
            let (echeance, n) = minuteurs::avancer_echeance_calcul(m.echeance_calcul, t, iv);
            m.echeance_calcul = echeance;
            m.depassement = m.depassement.saturating_add(n as i64);
        }
        _ => {
            // `common_hrtimer_rearm`.
            if let Some(minuteur) = &m.minuteur {
                let mut g = minuteur.verrouiller();
                let n = g.avancer(temps::ns_monotone(), iv);
                g.rearmer();
                m.depassement = m.depassement.saturating_add(n as i64);
            }
        }
    }
    let m = &mut p.minuteurs.liste[i];
    m.statut = Statut::Arme;
    m.dernier_depassement = m.depassement;
    m.depassement = -1;
    m.seq_signal = m.seq_signal.wrapping_add(1);
    info.poser_depassement(depassement_rendu(m.dernier_depassement));
    true
}

/// Le siginfo préalloué du minuteur `id` quitte sa file sans être pris (une
/// action SIG_IGN l'efface, signaux.rs : le `posixtimer_sig_ignore` de
/// Linux) : un périodique est mis de côté.
pub fn retire_de_la_file(m: &mut Minuteurs, id: i32) {
    if let Some(i) = m.indice(id as u32 as u64) {
        let t = &mut m.liste[i];
        t.en_file = false;
        t.ignore = t.periodique_a_l_envoi;
    }
}

/// Un gestionnaire remplace SIG_IGN pour `sig` (rt_sigaction) : les
/// minuteurs mis de côté pour lui remettent leur signal en file (le
/// `posixtimer_sig_unignore` de Linux), sans le réarmer (le retrait le
/// fera, s'il n'est pas périmé). Celui d'un fil qui a fini est oublié.
pub fn designorer(p: &mut Processus, sig: u64) {
    for i in 0..p.minuteurs.liste.len() {
        let m = &mut p.minuteurs.liste[i];
        if !m.ignore || m.info.signal() != sig {
            continue;
        }
        m.ignore = false;
        if m.en_file {
            continue;
        }
        let (dest, info) = (m.destinataire, m.info);
        if let Destinataire::Fil(tid) = dest {
            if p.fil(tid).is_none() {
                continue;
            }
        }
        p.minuteurs.liste[i].en_file = true;
        signaux::reveiller(signaux::mettre_en_file_prealloue(p, dest, info));
    }
}

/// Le dépassement, tel que le rendent timer_getoverrun et si_overrun : au
/// plus INT_MAX (`timer_overrun_to_int`).
fn depassement_rendu(d: i64) -> i32 {
    d.min(INT_MAX as i64) as i32
}

/// Ce que vaut le minuteur `i` : sa période et le temps qui reste (ns). Un
/// périodique échu (son signal pas encore pris), ou sans signal, est
/// d'abord avancé après l'heure, ses périodes sautées comptées
/// (`common_timer_get`, `posix_cpu_timer_get`). Un minuteur à signal échu
/// rend 1 ns : son signal n'est pas encore pris.
fn valeur(p: &mut Processus, i: usize) -> (u64, u64) {
    let m = &p.minuteurs.liste[i];
    let (iv, horloge, aucun) = (m.intervalle, m.horloge, m.aucun_signal);
    let reste = |echeance: i128, maintenant: i128| match echeance - maintenant {
        r if r > 0 => r as u64,
        _ => if aucun { 0 } else { 1 },
    };
    match horloge {
        Horloge::Calcul(..) => {
            // Rien, période comprise, sans échéance ou sans fil.
            if m.echeance_calcul == 0 {
                return (0, 0);
            }
            let Some(t) = echantillon(p, horloge) else { return (0, 0) };
            let m = &mut p.minuteurs.liste[i];
            let mut echeance = m.echeance_calcul;
            if iv != 0 && m.statut != Statut::Arme {
                let n;
                (echeance, n) = minuteurs::avancer_echeance_calcul(echeance, t, iv);
                m.echeance_calcul = echeance;
                m.depassement = m.depassement.saturating_add(n as i64);
            }
            (iv, reste(echeance as i128, t as i128))
        }
        _ => {
            if iv == 0 && m.statut == Statut::Desarme && !aucun {
                return (0, 0);
            }
            let m = &mut p.minuteurs.liste[i];
            let Some(minuteur) = &m.minuteur else { return (iv, 0) };
            let mut g = minuteur.verrouiller();
            let maintenant = temps::ns_monotone();
            if iv != 0 && m.statut != Statut::Arme {
                let n = g.avancer(maintenant, iv);
                m.depassement = m.depassement.saturating_add(n as i64);
            }
            (iv, reste(g.echeance() as i128, maintenant as i128))
        }
    }
}

/// Arme le minuteur `i` (`common_timer_set`, `posix_cpu_timer_set`), sous
/// le verrou du processus : désarmé, ses dépassements remis à zéro, puis
/// armé pour `valeur` (0 : il reste désarmé, sa période oubliée). Rend sa
/// valeur d'avant (le temps qui restait), si `ancienne` ; ESRCH si son
/// horloge est celle d'un fil qui a fini.
fn regler(p: &mut Processus, i: usize, absolu: bool, intervalle: u64, valeur_: u64, ancienne: bool) -> Result<u64, i64> {
    // L'armement en cours ne doit plus rien livrer (`do_timer_settime`),
    // même si le réglage échoue ensuite.
    let m = &mut p.minuteurs.liste[i];
    m.seq_signal = m.seq_signal.wrapping_add(1);
    let horloge = m.horloge;
    let t = echantillon(p, horloge).ok_or(-ESRCH)?;
    let m = &mut p.minuteurs.liste[i];
    let aucun = m.aucun_signal;
    let avant;
    let mut tout_de_suite = false;
    if let Horloge::Calcul(..) = horloge {
        // Désarmé avant de lire l'ancienne valeur, comme Linux.
        let echeance_avant = m.echeance_calcul;
        m.statut = Statut::Desarme;
        avant = if ancienne && echeance_avant != 0 { valeur(p, i).1 } else { 0 };
        let m = &mut p.minuteurs.liste[i];
        let echeance = if valeur_ != 0 && !absolu { valeur_.saturating_add(t) } else { valeur_ };
        m.echeance_calcul = echeance;
        if !aucun && echeance != 0 {
            if t < echeance {
                m.statut = Statut::Arme;
            } else {
                // Déjà passée : le signal part tout de suite, même si le
                // programme ne calcule plus.
                tout_de_suite = true;
            }
        }
    } else {
        avant = if ancienne { valeur(p, i).1 } else { 0 };
        let m = &mut p.minuteurs.liste[i];
        m.statut = Statut::Desarme;
        if let Some(minuteur) = &m.minuteur {
            let mut g = minuteur.verrouiller();
            g.desarmer();
            if valeur_ != 0 {
                // La base de l'armement (minuteurs.rs) : la date pour TAI, et
                // pour REALTIME absolu ; le temps monotone sinon.
                let date = horloge == Horloge::Tai || (horloge == Horloge::Date && absolu);
                let decalage = if date { temps::decalage_de_la_date() } else { 0 };
                let echeance = if !absolu { g.echeance_relative(t, valeur_, decalage) } else { g.echeance_absolue(valeur_, decalage) };
                if aucun {
                    // Jamais dans la table : son échéance seulement, qu'on lit.
                    g.poser(echeance);
                } else {
                    g.armer(echeance);
                }
            }
        }
        if valeur_ != 0 && !aucun {
            m.statut = Statut::Arme;
        }
    }
    // `posix_timer_set_common`.
    let m = &mut p.minuteurs.liste[i];
    m.intervalle = if valeur_ != 0 { intervalle } else { 0 };
    m.dernier_depassement = 0;
    m.depassement = -1;
    if tout_de_suite {
        calcul_echu(p, i);
    }
    Ok(avant)
}

/// timer_create(horloge, sigevent, numéro), dans l'ordre de Linux
/// (`do_timer_create`) : le sigevent lu (EFAULT), l'horloge (EINVAL,
/// EOPNOTSUPP), le minuteur alloué et son siginfo compté (EAGAIN), son
/// numéro pris, puis le sigevent vérifié (EINVAL), le numéro écrit
/// (EFAULT), et l'horloge des alarmes refusée (EPERM). Un échec après le
/// numéro le consomme : le suivant aura le numéro d'après (mesuré).
pub fn timer_create(horloge: u64, sigevent: u64, numero: u64) -> i64 {
    let mut ev = None;
    if sigevent != 0 {
        let mut o = [0u8; 64];
        if copier_depuis_utilisateur(&mut o, sigevent).is_err() {
            return -EFAULT;
        }
        let int = |k: usize| i32::from_le_bytes([o[k], o[k + 1], o[k + 2], o[k + 3]]);
        let valeur = u64::from_le_bytes(o[0..8].try_into().unwrap_or([0; 8]));
        ev = Some((valeur, int(8), int(12), int(16)));
    }
    // Un clockid_t est un int (`temps::genre`). Les erreurs de l'horloge que
    // Linux ne voit qu'après le numéro écrit (`kc->timer_create`) : celles
    // des alarmes (EPERM), et une horloge de calcul qui ne vise personne
    // (EINVAL).
    let (h, erreur_apres) = match temps::genre(horloge) {
        Genre::Nommee(temps::CLOCK_REALTIME) => (Horloge::Date, 0),
        Genre::Nommee(temps::CLOCK_TAI) => (Horloge::Tai, 0),
        Genre::Nommee(temps::CLOCK_MONOTONIC | temps::CLOCK_BOOTTIME) => (Horloge::Monotone, 0),
        Genre::Nommee(temps::CLOCK_PROCESS_CPUTIME_ID) => horloge_de_calcul(Some(DeCalcul::PROCESSUS)),
        Genre::Nommee(temps::CLOCK_THREAD_CPUTIME_ID) => horloge_de_calcul(Some(DeCalcul { fil: true, ..DeCalcul::PROCESSUS })),
        Genre::Nommee(temps::CLOCK_MONOTONIC_RAW | temps::CLOCK_REALTIME_COARSE | temps::CLOCK_MONOTONIC_COARSE) => return -EOPNOTSUPP,
        Genre::Nommee(8) => (Horloge::Date, -EPERM),
        Genre::Nommee(9) => (Horloge::Monotone, -EPERM),
        Genre::Nommee(_) => return -EINVAL,
        Genre::Calcul(c) => horloge_de_calcul(c),
        Genre::Descripteur => return -EOPNOTSUPP,
    };
    let r = processus::avec(|p| creer(p, h, ev));
    let id = match r {
        Ok(id) => id,
        Err(e) => return e,
    };
    let erreur = if copier_vers_utilisateur(numero, &id.to_le_bytes()).is_err() { -EFAULT } else { erreur_apres };
    // Valide, ou retiré : rendu hors du verrou (son minuteur du noyau rend
    // sa place, son siginfo la sienne).
    let retire = processus::avec(|p| {
        let m = &mut p.minuteurs;
        let Ok(i) = m.liste.binary_search_by_key(&id, |t| t.id) else { return None };
        if erreur == 0 {
            m.liste[i].valide = true;
            return None;
        }
        let t = m.liste.remove(i);
        signaux::rendre_place(p, t.destinataire);
        Some(t)
    });
    drop(retire);
    if erreur != 0 { erreur } else { 0 }
}

/// Le minuteur d'une horloge de calcul `c` (None : une mesure inconnue),
/// cherchée comme le fait `posix_cpu_timer_create` (`pid_for_clock`) : un
/// fil du processus, ou le processus lui-même ; et l'erreur à rendre après
/// le numéro écrit : EINVAL quand elle ne vise personne, ou un autre
/// processus (un écart : voir l'en-tête).
fn horloge_de_calcul(c: Option<DeCalcul>) -> (Horloge, i64) {
    let refus = (Horloge::Calcul(None, Mesure::Sched), -EINVAL);
    let Some(c) = c else { return refus };
    match processus::cible_d_horloge(c, false) {
        Some(processus::Cible::Fil(t)) => (Horloge::Calcul(Some(t.tid()), c.mesure), 0),
        Some(processus::Cible::Processus(e)) if tache::courante().processus().is_some_and(|p| p.pid() == e.pid()) => {
            (Horloge::Calcul(None, c.mesure), 0)
        }
        _ => refus,
    }
}

/// La part de timer_create sous le verrou du processus : le minuteur
/// alloué, son numéro pris, son sigevent vérifié (`good_sigevent`), rangé
/// pas encore valide. Rend son numéro.
fn creer(p: &mut Processus, h: Horloge, ev: Option<(u64, i32, i32, i32)>) -> Result<i32, i64> {
    // L'allocation (`alloc_posix_timer`) : le siginfo préalloué compté,
    // le minuteur du noyau, la place dans la liste.
    if !signaux::compter_prealloue(p.limite(processus::RLIMIT_SIGPENDING).0) {
        return Err(-EAGAIN);
    }
    let pid = p.pid;
    let mut t = MinuteurPosix {
        id: 0,
        valide: false,
        horloge: h,
        aucun_signal: false,
        destinataire: Destinataire::Processus,
        info: Info::de_minuteur(SIGALRM, 0, 0),
        compte: true,
        minuteur: None,
        echeance_calcul: 0,
        intervalle: 0,
        statut: Statut::Desarme,
        depassement: -1,
        dernier_depassement: 0,
        seq_signal: 0,
        seq_file: 0,
        en_file: false,
        ignore: false,
        periodique_a_l_envoi: false,
    };
    if p.minuteurs.liste.try_reserve(1).is_err() {
        return Err(-EAGAIN);
    }
    let Some((id, i)) = numero_libre(&mut p.minuteurs) else { return Err(-EAGAIN) };
    t.id = id;
    if !matches!(h, Horloge::Calcul(..)) {
        t.minuteur = Some(Minuteur::nouveau(Quoi::Posix(pid, id)).ok_or(-EAGAIN)?);
    }
    // Sans sigevent : SIGALRM au processus, si_value = le numéro.
    let (valeur, sig, notification, fil) = ev.unwrap_or((id as u32 as u64, SIGALRM as i32, SIGEV_SIGNAL, 0));
    let signal_valide = (1..=signaux::NSIG as i32).contains(&sig);
    match notification {
        SIGEV_SIGNAL | SIGEV_THREAD if signal_valide => {}
        SIGEV_THREAD_ID if signal_valide && fil > 0 && p.fil(fil as u32).is_some() => {
            t.destinataire = Destinataire::Fil(fil as u32);
        }
        SIGEV_NONE => t.aucun_signal = true,
        _ => return Err(-EINVAL),
    }
    t.info = Info::de_minuteur(sig as u32 as u64, id, valeur);
    // La place de son siginfo dans la file qu'il vise : l'envoi n'alloue
    // rien. (Linux l'a dans la `k_itimer`, allouée d'abord : ici, sous un
    // manque de mémoire, le numéro est déjà pris.)
    if !signaux::reserver_place(p, t.destinataire) {
        return Err(-EAGAIN);
    }
    p.minuteurs.liste.inserer_dans_la_place(i, t);
    Ok(id)
}

/// timer_settime(numéro, drapeaux, nouvelle, ancienne), dans l'ordre de
/// Linux : la nouvelle valeur présente (EINVAL), lue (EFAULT), valide
/// (EINVAL), puis le numéro (EINVAL) ; le minuteur réglé, puis l'ancienne
/// valeur écrite (EFAULT : il est pourtant réglé). Seul TIMER_ABSTIME
/// compte parmi les drapeaux, les autres sont ignorés.
pub fn timer_settime(id: u64, drapeaux: u64, nouvelle: u64, ancienne: u64) -> i64 {
    if nouvelle == 0 {
        return -EINVAL;
    }
    let mut o = [0u8; 32];
    if copier_depuis_utilisateur(&mut o, nouvelle).is_err() {
        return -EFAULT;
    }
    let Some((intervalle, valeur_)) = temps::lire_itimerspec(&o) else { return -EINVAL };
    let absolu = drapeaux as u32 as u64 & TIMER_ABSTIME != 0;
    let r = processus::avec(|p| {
        let i = p.minuteurs.indice(id).ok_or(-EINVAL)?;
        let ancien_intervalle = p.minuteurs.liste[i].intervalle;
        regler(p, i, absolu, intervalle, valeur_, ancienne != 0).map(|v| (ancien_intervalle, v))
    });
    match r {
        Ok((iv, v)) if ancienne != 0 => match temps::ecrire_itimerspec(ancienne, iv, v) {
            Ok(()) => 0,
            Err(e) => e,
        },
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// timer_gettime(numéro, valeur) : le numéro (EINVAL), puis sa valeur
/// écrite (EFAULT).
pub fn timer_gettime(id: u64, adresse: u64) -> i64 {
    let r = processus::avec(|p| p.minuteurs.indice(id).map(|i| valeur(p, i)));
    let Some((iv, v)) = r else { return -EINVAL };
    match temps::ecrire_itimerspec(adresse, iv, v) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// timer_getoverrun(numéro) : les dépassements du dernier signal livré.
pub fn timer_getoverrun(id: u64) -> i64 {
    processus::avec(|p| p.minuteurs.indice(id).map(|i| depassement_rendu(p.minuteurs.liste[i].dernier_depassement)))
        .map_or(-EINVAL, |d| d as i64)
}

/// timer_delete(numéro) : le minuteur retiré (`posix_timer_delete`). Son
/// siginfo encore en file y reste, périmé (le retrait le jettera) : il
/// emporte avec lui la place du minuteur dans le compte RLIMIT_SIGPENDING,
/// qu'il rendra en quittant sa file (la référence que Linux garde au
/// minuteur jusque-là).
pub fn timer_delete(id: u64) -> i64 {
    let retire = processus::avec(|p| {
        let i = p.minuteurs.indice(id)?;
        let mut t = p.minuteurs.liste.remove(i);
        if t.en_file && signaux::orpheliner(p, t.destinataire, t.id) {
            t.compte = false;
        }
        signaux::rendre_place(p, t.destinataire);
        Some(t)
    });
    match retire {
        // Désarmé et rendu hors du verrou.
        Some(t) => {
            drop(t);
            0
        }
        None => -EINVAL,
    }
}
