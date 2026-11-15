//! Les alarmes d'un processus : setitimer, getitimer et alarm (le
//! kernel/time/itimer.c de Linux, et la part de posix-cpu-timers.c qui
//! sert ses alarmes de temps de calcul). Trois par processus, communes à
//! ses fils (Linux les range dans la `signal_struct`, à côté des signaux) :
//!   - ITIMER_REAL, en temps monotone : SIGALRM à l'échéance. Un minuteur du
//!     noyau (minuteurs.rs), le `real_timer` de Linux ;
//!   - ITIMER_VIRTUAL, en temps de calcul passé dans le programme
//!     (anneau 3) : SIGVTALRM ;
//!   - ITIMER_PROF, en temps de calcul, programme et noyau : SIGPROF (le
//!     profilage à l'ancienne : gprof échantillonne ainsi).
//! alarm(s) est ITIMER_REAL en secondes, sans période.
//!
//! LE MINUTEUR D'ITIMER_REAL EST RÉSERVÉ À LA CRÉATION DU PROCESSUS
//! (`Alarmes::nouvelles`), comme le `real_timer` de Linux, logé dans la
//! `signal_struct` allouée au fork : setitimer ne peut pas échouer faute de
//! mémoire (Linux ne rend jamais ENOMEM). Option écartée : le créer au
//! premier setitimer, ce qui épargnerait une place de la table des
//! échéances aux programmes qui n'en armeront jamais, au prix d'une erreur
//! que Linux ne connaît pas.
//!
//! ITIMER_REAL PÉRIODIQUE : réarmé non pas à l'échéance, mais quand SIGALRM
//! est pris parmi les signaux du processus (`sigalrm_pris`, que signaux.rs
//! appelle : le `posixtimer_rearm_itimer` du `dequeue_signal` de Linux). Un
//! SIGALRM bloqué arrête donc l'alarme jusqu'à ce qu'il soit pris (getitimer
//! rend alors une valeur nulle, sa période gardée), puis elle repart à la
//! première période qui suit l'heure (`avancer`, le `hrtimer_forward` de
//! Linux), sans rattraper les autres : un signal ordinaire n'est en attente
//! qu'une fois, elles se seraient fondues en un. Un SIGALRM ignoré est jeté
//! à l'envoi, jamais pris : l'alarme s'arrête après sa première échéance
//! (mesuré sous Linux). Option écartée : la réarmer dans le tic, comme un
//! timerfd périodique ; elle sonnerait encore pour un signal jeté ou déjà
//! en attente, et getitimer ne montrerait plus l'arrêt que Linux montre.
//!
//! L'ÉCHÉANCE D'ITIMER_REAL EST SERVIE SOUS LE VERROU DU PROCESSUS
//! (`sonner`) : le tic prend le verrou du processus, puis celui du minuteur
//! (l'ordre de minuteurs.rs), vérifie que l'armement est toujours celui qu'il
//! sert, et envoie SIGALRM. setitimer et getitimer, qui prennent aussi ces
//! deux verrous dans cet ordre, voient l'échéance servie et son signal
//! envoyé, ou ni l'un ni l'autre : un setitimer qui désarme ne laisse
//! jamais arriver un SIGALRM de l'armement d'avant (Linux attend la fin d'un
//! `it_real_fn` en cours : `hrtimer_cancel_wait_running`).
//!
//! LES ALARMES DE TEMPS DE CALCUL se comptent en tics, comme chez Linux (la
//! `thread_group_cputimer` : le tic ajoute une période d'horloge au temps du
//! programme ou du noyau du fil qu'il interrompt, `account_group_user_time`
//! et `account_group_system_time`) : processus.rs compte les tics de chaque
//! processus (`Entree::compter_tic`). Elles sont vérifiées au retour vers
//! l'anneau 3 qui suit un tic compté, juste avant RLIMIT_CPU (l'ordre de
//! `check_process_timers`) : Linux le fait dans le tic, et le signal serait
//! livré à ce retour de toute façon (tache.rs, `decider`). Une échéance
//! passée envoie son signal et repart d'UNE période (`check_cpu_itimer` :
//! pas de rattrapage). Armée, une alarme de calcul reçoit un tic de plus
//! (`set_cpu_itimer`) : le tic qui suit compte une période entière, même
//! si le programme n'en a calculé qu'une partie ; le tic de plus garantit
//! au moins la valeur demandée. Option écartée : le temps de calcul exact,
//! en nanosecondes (`Entree::temps_de_calcul`, celui de
//! CLOCK_PROCESS_CPUTIME_ID) ; il ne sépare pas le programme du noyau
//! (ITIMER_VIRTUAL), et Linux échantillonne ces deux alarmes par tics.

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::minuteurs::{Minuteur, Quoi};
use crate::partage::Arc;
use crate::processus::{self, Processus};
use crate::signaux::{self, Destinataire, Info};
use crate::tache::{self, Tache};
use crate::temps::{self, Mesure, TIC_NS};

const EINVAL: i64 = 22;
const EFAULT: i64 = 14;

pub const SIGALRM: u64 = 14;
const SIGVTALRM: u64 = 26;
const SIGPROF: u64 = 27;

const NS_PAR_S: u64 = 1_000_000_000;

/// Les indices des alarmes de calcul : ceux de Linux (CPUCLOCK_PROF,
/// CPUCLOCK_VIRT).
const PROF: usize = 0;
const VIRT: usize = 1;

/// Le premier argument de setitimer et getitimer (`which`).
#[derive(Clone, Copy)]
enum Genre {
    Reel,
    /// ITIMER_VIRTUAL ou ITIMER_PROF : l'indice de son alarme de calcul.
    Calcul(usize),
}

/// ITIMER_REAL (0), ITIMER_VIRTUAL (1), ITIMER_PROF (2) ; un int pour
/// Linux.
fn genre(quel: u64) -> Option<Genre> {
    match quel as u32 as i32 {
        0 => Some(Genre::Reel),
        1 => Some(Genre::Calcul(VIRT)),
        2 => Some(Genre::Calcul(PROF)),
        _ => None,
    }
}

/// Une alarme de temps de calcul (la `cpu_itimer` de Linux).
#[derive(Clone, Copy, Default)]
struct DeCalcul {
    /// L'échéance, en temps de calcul du processus (ns) ; 0 : désarmée.
    echeance: u64,
    /// La période (ns) ; 0 : une seule fois. Gardée même désarmée : Linux
    /// la range telle que setitimer la donne, même avec une valeur nulle,
    /// et getitimer la rend (mesuré).
    periode: u64,
}

/// Les alarmes d'un processus (le `real_timer`, `it_real_incr` et `it[]`
/// de la `signal_struct` de Linux), sous le verrou du processus.
pub struct Alarmes {
    /// ITIMER_REAL : SIGALRM au processus à l'échéance.
    reel: Minuteur,
    /// Sa période (ns) ; 0 : une seule fois. Effacée quand la valeur est
    /// nulle (`do_setitimer`), à la différence des alarmes de calcul.
    periode_reelle: u64,
    /// ITIMER_PROF et ITIMER_VIRTUAL.
    calcul: [DeCalcul; 2],
}

impl Alarmes {
    /// Les alarmes, désarmées, du processus `pid` qui naît. None : plus de
    /// mémoire pour son minuteur (le processus n'est pas créé).
    pub fn nouvelles(pid: u32) -> Option<Alarmes> {
        Some(Alarmes { reel: Minuteur::nouveau(Quoi::Alarme(pid))?, periode_reelle: 0, calcul: [DeCalcul::default(); 2] })
    }
}

/// L'échéance d'ITIMER_REAL du processus `pid`, dans le tic (minuteurs.rs),
/// hors de tout verrou. `servir` prend le verrou du minuteur, et dit si
/// l'armement sorti de la table est toujours le sien (puis le marque
/// servi) : sous le verrou du processus (l'en-tête). Puis SIGALRM au
/// processus, de la part du noyau (le `it_real_fn` de Linux : SEND_SIG_PRIV,
/// au groupe), sans réarmer (l'en-tête). Un processus qui finit n'est plus
/// dans la table, ou n'a plus de `Processus` : rien, son minuteur est
/// désarmé avec lui.
pub fn sonner(pid: u32, servir: impl FnOnce() -> bool) {
    let a_reveiller = processus::avec_pid(pid, |p| {
        if !servir() {
            return None;
        }
        signaux::envoyer(p, SIGALRM, Destinataire::Processus, Info::du_noyau(SIGALRM), true).ok().flatten()
    });
    signaux::reveiller(a_reveiller.flatten());
}

/// SIGALRM vient d'être pris parmi les signaux du processus (signaux.rs,
/// `prendre_parmi`), sous son verrou : une alarme périodique échue repart, à
/// la première période qui suit l'heure (l'en-tête). Rien si elle est
/// encore armée (ce SIGALRM venait d'un kill) ou sans période.
pub fn sigalrm_pris(a: &mut Alarmes) {
    if a.periode_reelle == 0 {
        return;
    }
    let mut m = a.reel.verrouiller();
    if m.arme() {
        return;
    }
    m.avancer(temps::ns_monotone(), a.periode_reelle);
    m.rearmer();
}

/// Les alarmes de calcul du processus, au retour vers l'anneau 3 qui suit
/// un tic compté (tache.rs, `decider`), sous son verrou : `tics` est son
/// temps de calcul en tics (programme, noyau). ITIMER_PROF puis
/// ITIMER_VIRTUAL, comme `check_process_timers`. Rend les fils à réveiller
/// (hors du verrou) : ceux qui prendront SIGPROF et SIGVTALRM.
pub fn verifier_calcul(p: &mut Processus, tics: (u64, u64)) -> [Option<Arc<Tache>>; 2] {
    let echantillons = echantillons(tics);
    let mut a_reveiller = [None, None];
    for (i, sig) in [(PROF, SIGPROF), (VIRT, SIGVTALRM)] {
        let it = &mut p.alarmes.calcul[i];
        if it.echeance == 0 || echantillons[i] < it.echeance {
            continue;
        }
        it.echeance = if it.periode != 0 { it.echeance.saturating_add(it.periode) } else { 0 };
        a_reveiller[i] = signaux::envoyer(p, sig, Destinataire::Processus, Info::du_noyau(sig), true).ok().flatten();
    }
    a_reveiller
}

/// Le temps de calcul du processus, en ns, pour chaque alarme de calcul
/// (les `samples` de Linux : PROF, programme et noyau ; VIRT, programme) :
/// celui de ses horloges de calcul PROF et VIRT (temps.rs).
fn echantillons(tics: (u64, u64)) -> [u64; 2] {
    [temps::mesurer(Mesure::Prof, 0, tics), temps::mesurer(Mesure::Virt, 0, tics)]
}

/// La période et la valeur d'une alarme (ns) : le temps qui reste.
/// ITIMER_REAL (`itimer_get_remtime`) : nul désarmée ou échue ; armée,
/// au moins une microseconde (l'échéance est servie au tic qui la suit :
/// passée, elle est encore armée, et Linux rend alors 1 µs). Une alarme de
/// calcul (`get_cpu_itimer`) : une période d'horloge si elle est dépassée
/// sans avoir encore été vue.
fn lire(p: &mut Processus, quel: Genre, maintenant: u64, tics: (u64, u64)) -> (u64, u64) {
    match quel {
        Genre::Reel => {
            let m = p.alarmes.reel.verrouiller();
            let reste = match m.restant(maintenant) {
                _ if !m.arme() => 0,
                0 => 1000,
                r => r,
            };
            (p.alarmes.periode_reelle, reste)
        }
        Genre::Calcul(i) => {
            let it = p.alarmes.calcul[i];
            let t = echantillons(tics)[i];
            let reste = match it.echeance {
                0 => 0,
                e if e < t => TIC_NS,
                e => e - t,
            };
            (it.periode, reste)
        }
    }
}

/// Arme l'alarme `quel` pour `valeur` (relative, ns ; 0 : la désarmer),
/// avec `periode`, et rend ce qu'elle était (période, valeur) : le
/// `do_setitimer` de Linux.
fn regler(p: &mut Processus, quel: Genre, periode: u64, valeur: u64, maintenant: u64, tics: (u64, u64)) -> (u64, u64) {
    match quel {
        Genre::Reel => {
            let avant = lire(p, quel, maintenant, tics);
            let a = &mut p.alarmes;
            let mut m = a.reel.verrouiller();
            m.desarmer();
            if valeur != 0 {
                a.periode_reelle = periode;
                let e = m.echeance_relative(maintenant, valeur, 0);
                m.armer(e);
            } else {
                a.periode_reelle = 0;
            }
            avant
        }
        Genre::Calcul(i) => {
            // `set_cpu_itimer` et `set_process_cpu_timer`, à la lettre :
            // l'ancienne échéance rendue relative (une période d'horloge si
            // elle est atteinte : `<=`, quand getitimer dit `<`), la nouvelle
            // rendue absolue, un tic de plus (l'en-tête).
            let t = echantillons(tics)[i];
            let it = &mut p.alarmes.calcul[i];
            let (mut ancienne, mut nouvelle) = (it.echeance, valeur);
            if ancienne != 0 {
                ancienne = if ancienne <= t { TIC_NS } else { ancienne - t };
            }
            if nouvelle != 0 {
                nouvelle = nouvelle.saturating_add(TIC_NS).saturating_add(t);
            }
            let avant = (it.periode, ancienne);
            *it = DeCalcul { echeance: nouvelle, periode };
            avant
        }
    }
}

/// Un `struct timeval` (secondes, microsecondes) en nanosecondes : None
/// s'il est invalide (`timeval_valid` : secondes négatives, microsecondes
/// hors de [0, 10^6[) ; au-delà de KTIME_MAX, KTIME_MAX (`temps::duree`).
fn lire_timeval(o: &[u8; 16]) -> Option<u64> {
    let mot = |i: usize| i64::from_le_bytes(o[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
    let (s, us) = (mot(0), mot(1));
    if !(0..1_000_000).contains(&us) {
        return None;
    }
    temps::duree(s, us * 1000)
}

/// Écrit un `struct itimerval` (la période, puis la valeur, chacune en
/// `timeval`) : les microsecondes tronquées, comme `put_itimerval`. Linux
/// passe chaque durée par un s64 (`ns_to_timespec64`) : une alarme de
/// calcul armée au-delà de KTIME_MAX s'y lit négative ; la division
/// euclidienne fait de même.
fn ecrire_itimerval(adresse: u64, periode: u64, valeur: u64) -> Result<(), i64> {
    let mut o = [0u8; 32];
    for (i, ns) in [periode, valeur].into_iter().enumerate() {
        let ns = ns as i64;
        let (s, us) = (ns.div_euclid(NS_PAR_S as i64), ns.rem_euclid(NS_PAR_S as i64) / 1000);
        o[i * 16..i * 16 + 8].copy_from_slice(&s.to_le_bytes());
        o[i * 16 + 8..i * 16 + 16].copy_from_slice(&us.to_le_bytes());
    }
    copier_vers_utilisateur(adresse, &o).map_err(|_| -EFAULT)
}

/// getitimer(genre, valeur) : le genre (EINVAL), puis l'alarme écrite
/// (EFAULT).
pub fn getitimer(quel: u64, valeur: u64) -> i64 {
    let Some(quel) = genre(quel) else { return -EINVAL };
    let tics = tache::tics_du_processus();
    let (periode, reste) = processus::avec(|p| lire(p, quel, temps::ns_monotone(), tics));
    match ecrire_itimerval(valeur, periode, reste) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// setitimer(genre, nouvelle, ancienne), dans l'ordre de Linux : la
/// nouvelle valeur lue (EFAULT) et vérifiée (EINVAL), puis le genre
/// (EINVAL), l'alarme réglée, et l'ancienne écrite (EFAULT : l'alarme est
/// pourtant réglée). Une nouvelle valeur absente (NULL) désarme, comme une
/// valeur nulle : Linux l'accepte encore, en le notant une fois dans son
/// journal (« Misfeature support will be removed »).
pub fn setitimer(quel: u64, nouvelle: u64, ancienne: u64) -> i64 {
    let (mut periode, mut valeur) = (0, 0);
    if nouvelle != 0 {
        let mut o = [0u8; 32];
        if copier_depuis_utilisateur(&mut o, nouvelle).is_err() {
            return -EFAULT;
        }
        let moitie = |i: usize| o[i * 16..i * 16 + 16].try_into().ok().and_then(lire_timeval);
        match (moitie(0), moitie(1)) {
            (Some(p), Some(v)) => (periode, valeur) = (p, v),
            _ => return -EINVAL,
        }
    }
    let Some(quel) = genre(quel) else { return -EINVAL };
    let tics = tache::tics_du_processus();
    let (periode, reste) = processus::avec(|p| regler(p, quel, periode, valeur, temps::ns_monotone(), tics));
    if ancienne != 0 {
        if let Err(e) = ecrire_itimerval(ancienne, periode, reste) {
            return e;
        }
    }
    0
}

/// alarm(secondes) : ITIMER_REAL pour `secondes` (un unsigned int), sans
/// période ; 0 la désarme. Rend les secondes qui restaient à la précédente,
/// arrondies à la plus proche, et au moins 1 s'il en restait (« We can't
/// return 0 if we have an alarm pending », `alarm_setitimer`).
pub fn alarm(secondes: u64) -> i64 {
    let valeur = (secondes as u32 as u64) * NS_PAR_S;
    let tics = tache::tics_du_processus();
    let (_, reste) = processus::avec(|p| regler(p, Genre::Reel, 0, valeur, temps::ns_monotone(), tics));
    let (mut s, ns) = (reste / NS_PAR_S, reste % NS_PAR_S);
    if s == 0 && ns != 0 || ns >= NS_PAR_S / 2 {
        s += 1;
    }
    s as u32 as i64
}
