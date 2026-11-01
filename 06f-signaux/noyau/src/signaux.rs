//! Les signaux : ce qu'un programme a demandé de faire de chacun, ce qu'il
//! bloque, ce qui l'attend, et sa pile de secours.
//!
//! Un signal est un événement pour un processus : une faute (SIGSEGV), un
//! ordre (SIGTERM), une limite atteinte (SIGXCPU), un signal qu'il s'envoie
//! (`abort` passe par SIGABRT). Pour chacun, le programme choisit l'ACTION
//! (`rt_sigaction`) : l'action par défaut (SIG_DFL), l'ignorer (SIG_IGN),
//! ou un GESTIONNAIRE, une fonction à lui que le noyau appelle sur un cadre
//! de signal posé sur sa pile (ou sur sa pile de secours, `sigaltstack`).
//! Il peut aussi en BLOQUER (`rt_sigprocmask`) : un signal bloqué attend
//! (« en attente », `rt_sigpending`) qu'on le débloque.
//!
//! En 6d, tout cela est enregistré et rendu exactement comme Linux le fait
//! (mesuré sur Linux 6.18) : Bun en règle quatorze dès son démarrage,
//! avec une pile de secours. Et ce qui ne demande pas d'appeler un
//! gestionnaire est appliqué : SIG_IGN, l'action par défaut (terminer,
//! ignorer, arrêter), l'attente d'un signal bloqué, pour les signaux
//! qu'envoient les programmes (`kill`, `tkill`, `tgkill` : à eux-mêmes, et
//! depuis 6e à un autre processus ou à un autre fil) et pour SIGXCPU. Depuis
//! 6f, un gestionnaire est appelé : sur un cadre de signal posé sur la pile
//! du programme, ou sur sa pile de secours, d'où il revient par
//! `rt_sigreturn` (cadre_signal.rs).
//!
//! Comme Linux, les actions sont au processus (la `sighand_struct`, que
//! partagent ses fils : `Signaux`), le masque et la pile de secours au fil
//! (`SignauxDuFil`, dans le `Fil` du processus, fil.rs). Les signaux en
//! attente sont de deux sortes, comme chez Linux : ceux envoyés au fil
//! (`tkill`, `tgkill`, une faute : `pending`, au fil) et ceux envoyés au
//! processus (`kill`, SIGXCPU : `shared_pending`, au processus, que prendra
//! le premier de ses fils qui ne le bloque pas). Ceux du fil passent
//! d'abord. Tout est sous le verrou du processus (le `siglock` de Linux).
//!
//! Depuis 6f, chaque sorte est une FILE (`EnAttente`, le `sigpending` de
//! Linux) : l'ensemble des signaux en attente, et le siginfo de chaque
//! envoi (`Info` : qui l'a envoyé, pourquoi), que reçoit le gestionnaire
//! (SA_SIGINFO) ou `rt_sigtimedwait`. Un signal ordinaire (1 à 31) n'y est
//! qu'une fois : envoyé de nouveau avant d'être livré, il est jeté (le
//! `legacy_queue` de Linux) ; un signal temps réel (32 à 64) y est autant
//! de fois qu'envoyé, chaque fois avec son siginfo, et livré dans l'ordre.
//! Le nombre de siginfo en file est borné par RLIMIT_SIGPENDING, compté
//! pour l'utilisateur sur tous ses processus (`EN_FILE`), comme les
//! `ucounts` de Linux.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::fil;
use crate::linux::Signal;
use crate::processus::{self, Processus};
use crate::tache::{self, Tache};

const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const EINTR: i64 = 4;
const E2BIG: i64 = 7;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

/// Les signaux vont de 1 à 64 (_NSIG).
pub const NSIG: u64 = 64;

const SIGQUIT: u64 = 3;
const SIGILL: u64 = 4;
const SIGTRAP: u64 = 5;
const SIGABRT: u64 = 6;
const SIGBUS: u64 = 7;
const SIGFPE: u64 = 8;
const SIGKILL: u64 = 9;
const SIGSEGV: u64 = 11;
const SIGCHLD: u64 = 17;
const SIGCONT: u64 = 18;
const SIGSTOP: u64 = 19;
const SIGTSTP: u64 = 20;
const SIGTTIN: u64 = 21;
const SIGTTOU: u64 = 22;
const SIGURG: u64 = 23;
const SIGXCPU: u64 = 24;
const SIGXFSZ: u64 = 25;
const SIGWINCH: u64 = 28;
const SIGSYS: u64 = 31;

/// Le premier signal temps réel (SIGRTMIN du noyau ; la glibc garde les
/// deux premiers pour elle).
const SIGRTMIN: u64 = 32;

/// Le bit du signal `sig` dans un ensemble (sigset_t : le bit sig - 1).
const fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
}

/// Les valeurs de `si_code` : qui a envoyé le signal. Positives, une raison
/// propre au signal (une faute : SEGV_MAPERR...) ; SI_USER, `kill` ;
/// SI_KERNEL, le noyau ; négatives, un envoi « temps réel » d'un programme.
pub const SI_USER: i32 = 0;
pub const SI_KERNEL: i32 = 0x80;
pub const SI_TKILL: i32 = -6;
/// Les plus petits si_code dont Linux connaît la disposition (plus bas,
/// sauf SI_ASYNCNL, un siginfo venu d'un programme doit être nul au-delà de
/// ce que garde le noyau : `known_siginfo_layout`).
const SI_DETHREAD: i32 = -7;
const SI_ASYNCNL: i32 = -60;

/// Le siginfo d'un signal, tel que le garde le noyau : le `kernel_siginfo`
/// de Linux, 48 octets (si_signo, si_errno, si_code, puis 32 octets propres
/// à la sorte d'envoi). Le programme en reçoit 128, nuls au-delà (le
/// `siginfo_t` du programme garde de la place pour plus tard).
#[derive(Clone, Copy)]
pub struct Info([u8; 48]);

impl Info {
    /// Un siginfo de `sig`, avec son si_code, le reste à zéro.
    fn nouveau(sig: u64, code: i32) -> Info {
        let mut o = [0u8; 48];
        o[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
        o[8..12].copy_from_slice(&code.to_le_bytes());
        Info(o)
    }

    /// Envoyé par un programme (kill, tkill, tgkill : SI_USER, SI_TKILL),
    /// le numéro du processus et l'utilisateur de qui l'envoie (les champs
    /// `_kill` : si_pid, si_uid).
    pub fn par(sig: u64, code: i32, pid: u32, uid: u32) -> Info {
        let mut i = Info::nouveau(sig, code);
        i.0[16..20].copy_from_slice(&pid.to_le_bytes());
        i.0[20..24].copy_from_slice(&uid.to_le_bytes());
        i
    }

    /// Envoyé par le noyau lui-même (SIGXCPU : le SEND_SIG_PRIV de Linux).
    pub fn du_noyau(sig: u64) -> Info {
        Info::nouveau(sig, SI_KERNEL)
    }

    /// Celui d'un signal en attente dont le siginfo n'a pas pu être gardé
    /// (la limite, ou plus de mémoire) : SI_USER, sans qui ni pourquoi
    /// (`collect_signal`).
    fn perdu(sig: u64) -> Info {
        Info::nouveau(sig, SI_USER)
    }

    pub fn signal(&self) -> u64 {
        i32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as u32 as u64
    }

    pub fn code(&self) -> i32 {
        i32::from_le_bytes([self.0[8], self.0[9], self.0[10], self.0[11]])
    }

    /// Les 128 octets du `siginfo_t` du programme.
    pub fn octets(&self) -> [u8; 128] {
        let mut o = [0u8; 128];
        o[..48].copy_from_slice(&self.0);
        o
    }
}

/// Le nombre de siginfo en file pour l'utilisateur, sur tous ses processus
/// (l'UCOUNT_RLIMIT_SIGPENDING de Linux) : un seul utilisateur, 1000, pour
/// tous les programmes, donc un seul compteur ; avec plusieurs, un par
/// utilisateur.
static EN_FILE: AtomicU64 = AtomicU64::new(0);

/// Le nombre de siginfo en file (programmes.rs le vérifie, quand plus aucun
/// programme ne tourne).
pub fn en_file() -> u64 {
    EN_FILE.load(Ordering::Relaxed)
}

/// Les signaux en attente d'une sorte (ceux d'un fil, ou ceux d'un
/// processus) : leur ensemble, et la file de leurs siginfo, dans l'ordre des
/// envois (le `sigpending` de Linux). Un signal peut être dans l'ensemble
/// sans siginfo (le sien n'a pas pu être gardé) ; il n'a jamais de siginfo
/// sans être dans l'ensemble. Une `VecDeque` : le siginfo pris est le
/// premier de son signal, presque toujours vers le début de la file (Linux,
/// une liste chaînée, le cherche aussi depuis le début) ; un `Vec` déplacerait
/// toute la file à chaque retrait, et elle peut compter des milliers
/// d'entrées (RLIMIT_SIGPENDING).
#[derive(Default)]
pub struct EnAttente {
    ensemble: u64,
    file: VecDeque<Info>,
}

impl EnAttente {
    /// Range un siginfo (déjà compté dans EN_FILE) : faux s'il n'y a pas la
    /// place (plus de mémoire), le compte est alors rendu.
    fn garder(&mut self, info: Info) -> bool {
        if self.file.try_reserve(1).is_err() {
            EN_FILE.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        self.file.push_back(info);
        true
    }

    /// Retire les signaux de `ensemble`, et leurs siginfo (le
    /// `flush_sigqueue_mask` de Linux).
    fn retirer(&mut self, ensemble: u64) {
        self.ensemble &= !ensemble;
        let avant = self.file.len();
        self.file.retain(|i| bit(i.signal()) & ensemble == 0);
        EN_FILE.fetch_sub((avant - self.file.len()) as u64, Ordering::Relaxed);
    }

    /// Prend le signal `sig`, en attente : son premier siginfo ; le signal
    /// reste en attente s'il en a d'autres (un temps réel envoyé plusieurs
    /// fois), sinon il quitte l'ensemble (le `collect_signal` de Linux).
    fn prendre(&mut self, sig: u64) -> Info {
        let mut indices = self.file.iter().enumerate().filter(|(_, i)| i.signal() == sig).map(|(n, _)| n);
        let premier = indices.next();
        if indices.next().is_none() {
            self.ensemble &= !bit(sig);
        }
        match premier.and_then(|n| self.file.remove(n)) {
            Some(i) => {
                EN_FILE.fetch_sub(1, Ordering::Relaxed);
                i
            }
            None => Info::perdu(sig),
        }
    }

    /// Le prochain signal de `prets` (des signaux en attente ici) à prendre :
    /// les synchrones d'abord, puis le plus petit (le `next_signal` de
    /// Linux).
    fn suivant(prets: u64) -> u64 {
        let choix = if prets & SYNCHRONES != 0 { prets & SYNCHRONES } else { prets };
        choix.trailing_zeros() as u64 + 1
    }
}

impl Drop for EnAttente {
    /// Les siginfo d'un fil qui finit, ou d'un processus, sont rendus au
    /// compte de l'utilisateur.
    fn drop(&mut self) {
        EN_FILE.fetch_sub(self.file.len() as u64, Ordering::Relaxed);
    }
}

/// Ni SIGKILL ni SIGSTOP ne se bloquent, ne s'ignorent ni ne s'attrapent :
/// Linux les retire en silence d'un masque (sigdelsetmask).
const IMBLOQUABLES: u64 = bit(SIGKILL) | bit(SIGSTOP);

/// Les signaux « synchrones », dus à ce que fait le programme lui-même :
/// Linux les livre avant les autres (SYNCHRONOUS_MASK, kernel/signal.c).
const SYNCHRONES: u64 = bit(SIGSEGV) | bit(SIGBUS) | bit(SIGILL) | bit(SIGTRAP) | bit(SIGFPE) | bit(SIGSYS);

/// Le gestionnaire « action par défaut », et « ignorer ».
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// Les drapeaux d'une action que Linux connaît (UAPI_SA_FLAGS de
/// kernel/signal.c, avec SA_RESTORER de x86) : SA_NOCLDSTOP, SA_NOCLDWAIT,
/// SA_SIGINFO, SA_EXPOSE_TAGBITS, SA_RESTORER, SA_ONSTACK, SA_RESTART,
/// SA_NODEFER, SA_RESETHAND. Les autres sont effacés en silence : c'est ce
/// qui permet à un programme de savoir si le noyau connaît un drapeau (il
/// le pose, relit l'action, et regarde s'il y est encore : SA_UNSUPPORTED,
/// 0x400, n'est là que pour cela). Bun en pose d'inconnus
/// (0xffffffff00000000, dans la trace de claude --version) : les refuser
/// par EINVAL l'arrêterait dès son démarrage.
const DRAPEAUX_CONNUS: u64 = 0x1 | 0x2 | 0x4 | 0x800 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x4000_0000 | 0x8000_0000;

/// Une action : la `struct sigaction` du noyau pour x86_64 (32 octets, dans
/// cet ordre : celle de `rt_sigaction`, pas celle de la glibc).
#[derive(Clone, Copy, Default)]
pub struct Action {
    pub gestionnaire: u64,
    pub drapeaux: u64,
    /// Où revient un gestionnaire (le `__restore_rt` de la glibc, qui
    /// appelle rt_sigreturn) : l'adresse de retour de son cadre.
    pub restaurateur: u64,
    /// Les signaux bloqués pendant le gestionnaire.
    pub masque: u64,
}

impl Action {
    fn lire(octets: &[u8; 32]) -> Action {
        let mot = |i: usize| u64::from_le_bytes(octets[i..i + 8].try_into().unwrap_or([0; 8]));
        Action { gestionnaire: mot(0), drapeaux: mot(8), restaurateur: mot(16), masque: mot(24) }
    }

    fn octets(&self) -> [u8; 32] {
        let mut o = [0u8; 32];
        o[0..8].copy_from_slice(&self.gestionnaire.to_le_bytes());
        o[8..16].copy_from_slice(&self.drapeaux.to_le_bytes());
        o[16..24].copy_from_slice(&self.restaurateur.to_le_bytes());
        o[24..32].copy_from_slice(&self.masque.to_le_bytes());
        o
    }
}

/// La pile de secours (`sigaltstack`) : là où un gestionnaire marqué
/// SA_ONSTACK s'exécute, pour qu'un débordement de la pile ordinaire
/// puisse encore être signalé. Ses valeurs telles que le programme les a
/// posées, comme Linux (sas_ss_sp, sas_ss_size, sas_ss_flags).
#[derive(Clone, Copy, Default)]
pub struct PileDeSecours {
    pub adresse: u64,
    pub taille: u64,
    pub drapeaux: u32,
}

impl PileDeSecours {
    /// `sp` est-il dessus (`__on_sig_stack` : la pile descend, son sommet en
    /// fait partie, pas son pied) ?
    pub fn contient(&self, sp: u64) -> bool {
        sp > self.adresse && sp - self.adresse <= self.taille
    }

    /// S'exécute-t-on dessus (`on_sig_stack`) ? Jamais avec SS_AUTODISARM :
    /// elle est désarmée pendant le gestionnaire, un programme n'y est donc
    /// pas, sauf à l'avoir posée en étant déjà dessus ; et un RSP abîmé tout
    /// près de son sommet n'empêche pas de livrer le signal.
    pub fn dessus(&self, sp: u64) -> bool {
        self.drapeaux & SS_AUTODISARM == 0 && self.contient(sp)
    }

    /// Ce que dit `sigaltstack` (`sas_ss_flags`) : SS_DISABLE sans pile,
    /// SS_ONSTACK dessus, 0 sinon.
    pub fn etat(&self, sp: u64) -> u32 {
        if self.taille == 0 {
            SS_DISABLE
        } else if self.dessus(sp) {
            SS_ONSTACK
        } else {
            0
        }
    }
}

const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
/// Le seul drapeau à côté du mode : rendre la pile de secours le temps
/// d'un gestionnaire.
pub const SS_AUTODISARM: u32 = 1 << 31;
/// La plus petite pile de secours (MINSIGSTKSZ de x86).
const MINSIGSTKSZ: u64 = 2048;

/// Les signaux d'un processus, partagés par ses fils : l'action de chaque
/// signal, et ceux envoyés au processus.
pub struct Signaux {
    /// L'action de chaque signal (l'indice : le signal moins 1).
    actions: [Action; NSIG as usize],
    /// Ceux qui attendent d'être livrés, envoyés au processus (le
    /// `shared_pending` de Linux).
    attente: EnAttente,
}

/// Les signaux d'un fil : son masque, ceux envoyés à lui seul (le `pending`
/// de Linux), sa pile de secours. Ceux d'un fil neuf : rien de bloqué, rien
/// en attente, pas de pile de secours (le fil principal d'un programme qui
/// commence, comme après `execve` depuis un parent qui n'avait rien
/// bloqué ; un fil créé par clone héritera du masque de son créateur).
#[derive(Default)]
pub struct SignauxDuFil {
    /// Les signaux bloqués.
    bloques: u64,
    /// Le vrai masque pendant rt_sigtimedwait, qui débloque ce qu'il attend
    /// (le `real_blocked` de Linux) ; 0 hors de lui. Un signal qu'il bloque
    /// n'est jamais jeté à l'envoi, même ignoré (`ignore`) : l'attente le
    /// prendrait.
    bloques_reels: u64,
    attente: EnAttente,
    pile: PileDeSecours,
}

impl SignauxDuFil {
    /// Ceux d'un fil neuf créé par ce fil (clone) : son masque, rien en
    /// attente, pas de pile de secours (`copy_process` l'efface pour un fil
    /// qui partage la mémoire sans vfork).
    pub fn herite(&self) -> SignauxDuFil {
        SignauxDuFil { bloques: self.bloques, bloques_reels: 0, attente: EnAttente::default(), pile: PileDeSecours::default() }
    }
}

/// À qui un signal est envoyé : à un fil, ou au processus (le `PIDTYPE_PID`
/// et le `PIDTYPE_TGID` de `send_signal_locked`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Destinataire {
    Fil(u32),
    Processus,
}

impl Signaux {
    /// Ceux d'un programme neuf : toutes les actions par défaut, rien en
    /// attente.
    pub fn new() -> Signaux {
        Signaux { actions: [Action::default(); NSIG as usize], attente: EnAttente::default() }
    }

    fn action(&self, sig: u64) -> &Action {
        &self.actions[(sig - 1) as usize]
    }
}

/// Efface les signaux de `ensemble` qui attendaient le processus ou l'un de
/// ses fils (le `flush_sigqueue_mask` de Linux, sur le processus puis sur
/// chaque fil).
fn effacer(p: &mut Processus, ensemble: u64) {
    p.signaux.attente.retirer(ensemble);
    for f in p.fils.iter_mut() {
        f.signaux.attente.retirer(ensemble);
    }
}

/// Les signaux en attente pour le fil `tid`, des deux sortes (ce que rend
/// `rt_sigpending` avant de garder les bloqués), et son masque.
fn attente_et_masque(p: &mut Processus, tid: u32) -> (u64, u64) {
    let processus = p.signaux.attente.ensemble;
    match p.fil(tid) {
        Some(f) => (f.signaux.attente.ensemble | processus, f.signaux.bloques),
        None => (processus, 0),
    }
}

/// Le signal serait-il jeté dès son envoi au processus `p` (`sig_ignored`) ?
/// Seulement si son action l'ignore, et que le fil visé ne le bloque pas
/// (l'action pourrait changer d'ici son déblocage), ni ne l'attend dans
/// rt_sigtimedwait (son vrai masque le bloque) : le fil lui-même pour un
/// signal envoyé à un fil, le fil principal pour un signal envoyé au
/// processus (Linux regarde celui que désigne le numéro, le principal pour
/// un pid).
fn ignore(p: &mut Processus, sig: u64, a: Destinataire) -> bool {
    let vise = match a {
        Destinataire::Fil(tid) => tid,
        Destinataire::Processus => p.pid,
    };
    let bloque = p.fil(vise).is_some_and(|f| (f.signaux.bloques | f.signaux.bloques_reels) & bit(sig) != 0);
    !bloque && ignore_par(p.signaux.action(sig).gestionnaire, sig)
}

/// Un gestionnaire serait-il appelé pour une faute (SIGSEGV...) du fil
/// `tid` ? Il faut qu'il y en ait un, et que le fil ne bloque pas le signal :
/// une faute ignorée ou bloquée remet l'action par défaut et tue le
/// programme (`force_sig_info_to_task`).
pub fn gestionnaire_pour_faute(p: &mut Processus, tid: u32, sig: u64) -> bool {
    let g = p.signaux.action(sig).gestionnaire;
    let bloque = p.fil(tid).is_some_and(|f| f.signaux.bloques & bit(sig) != 0);
    g != SIG_DFL && g != SIG_IGN && !bloque
}

/// L'action `gestionnaire` ignore-t-elle `sig` ? SIG_IGN, ou SIG_DFL pour un
/// signal que l'action par défaut ignore (`sig_handler_ignored`).
fn ignore_par(gestionnaire: u64, sig: u64) -> bool {
    gestionnaire == SIG_IGN || gestionnaire == SIG_DFL && matches!(par_defaut(sig), ParDefaut::Ignorer)
}

/// Ce que fait un signal laissé à son action par défaut : la table de Linux
/// (sig_kernel_ignore, sig_kernel_stop, sig_kernel_coredump,
/// include/linux/signal.h). Les signaux temps réel terminent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParDefaut {
    Terminer,
    /// Terminer, avec une image mémoire (« core ») : RLIMIT_CORE est nul,
    /// comme Linux par défaut, aucune n'est écrite.
    ImageMemoire,
    Ignorer,
    /// Arrêter (suspendre) le programme, jusqu'à SIGCONT.
    Arreter,
}

pub fn par_defaut(sig: u64) -> ParDefaut {
    match sig {
        SIGCHLD | SIGURG | SIGWINCH | SIGCONT => ParDefaut::Ignorer,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => ParDefaut::Arreter,
        SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGXCPU | SIGXFSZ | SIGSYS => ParDefaut::ImageMemoire,
        _ => ParDefaut::Terminer,
    }
}

/// Comment un signal livré arrête le programme : pour le message.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fin {
    /// Son action par défaut le termine.
    ParDefaut,
    /// Son action par défaut l'arrête (SIGSTOP) : sans contrôle des tâches
    /// (6k), personne ne pourrait lui envoyer SIGCONT. Il est terminé.
    Suspendu,
}

/// Ce que fait le prochain signal livré (`a_livrer`).
pub enum Livraison {
    /// Appeler son gestionnaire, avec l'action telle qu'elle était quand il a
    /// été pris (SA_RESETHAND l'a peut-être remise à SIG_DFL depuis).
    Gestionnaire { sig: u64, info: Info, action: Action },
    /// L'arrêter.
    Arret { sig: u64, fin: Fin },
}

/// Envoie `sig` (1 à 64), avec son siginfo `info`, au fil `tid` du
/// processus ou au processus : jeté s'il l'ignore, en attente sinon, livré
/// au retour vers l'anneau 3 (`a_livrer`). C'est le `__send_signal_locked`
/// de Linux, dans son ordre :
///   1. `prepare_signal` : un signal qui relance (SIGCONT) efface les
///      signaux d'arrêt en attente, des deux sortes, et l'inverse ; un
///      signal ignoré est jeté ;
///   2. un signal ordinaire déjà en attente (de cette sorte) : jeté, l'envoi
///      réussit (`legacy_queue`) ;
///   3. son siginfo en file, compté pour l'utilisateur ; au-delà de
///      RLIMIT_SIGPENDING (celle du destinataire), seulement s'il « passe
///      quand même » : un signal ordinaire envoyé par le noyau
///      (`speciale`) ou par kill, tkill, une faute (si_code ≥ 0). Sinon,
///      pour un temps réel venu d'un programme autrement que par kill
///      (sigqueue : SI_QUEUE), EAGAIN et rien n'est envoyé ; pour les
///      autres, le signal part sans son siginfo (Linux : « silent loss of
///      information »). SIGKILL n'en garde pas (il tue, sans gestionnaire) ;
///   4. le signal en attente, et le fil qui le prendra (`complete_signal`).
/// Rend le fil à réveiller, s'il y en a un (son appel en cours, s'il dort
/// interruptible, rendra EINTR) : à faire hors du verrou du processus
/// (`reveiller`).
pub fn envoyer(p: &mut Processus, sig: u64, a: Destinataire, info: Info, speciale: bool)
    -> Result<Option<Arc<Tache>>, i64> {
    if sig == SIGCONT {
        effacer(p, bit(SIGSTOP) | bit(SIGTSTP) | bit(SIGTTIN) | bit(SIGTTOU));
    } else if matches!(par_defaut(sig), ParDefaut::Arreter) {
        effacer(p, bit(SIGCONT));
    }
    if ignore(p, sig, a) {
        return Ok(None);
    }
    let limite = p.limite(processus::RLIMIT_SIGPENDING).0;
    let attente = match a {
        Destinataire::Fil(tid) => match p.fil(tid) {
            Some(f) => &mut f.signaux.attente,
            None => return Ok(None),
        },
        Destinataire::Processus => &mut p.signaux.attente,
    };
    if sig < SIGRTMIN && attente.ensemble & bit(sig) != 0 {
        return Ok(None);
    }
    if sig != SIGKILL {
        let passe_quand_meme = sig < SIGRTMIN && (speciale || info.code() >= 0);
        let compte = EN_FILE.fetch_add(1, Ordering::Relaxed) + 1;
        let garde = if !passe_quand_meme && compte > limite {
            EN_FILE.fetch_sub(1, Ordering::Relaxed);
            false
        } else {
            attente.garder(info)
        };
        if !garde && !speciale && sig >= SIGRTMIN && info.code() != SI_USER {
            return Err(-EAGAIN);
        }
    }
    attente.ensemble |= bit(sig);
    Ok(match a {
        Destinataire::Fil(tid) => {
            let f = p.fil(tid).expect("le fil vient d'etre trouve");
            (f.signaux.bloques & bit(sig) == 0).then(|| f.tache.upgrade()).flatten()
        }
        Destinataire::Processus => choisir_fil(p, sig),
    })
}

/// Le fil qui prendra un signal envoyé au processus (le `complete_signal` de
/// Linux) : le principal s'il le veut, sinon le premier qui le veut ; le
/// veut un fil qui ne le bloque pas et dont la fin n'est pas prévue (le
/// `wants_signal` de Linux, qui écarte les fils PF_EXITING) ; aucun s'ils
/// le bloquent tous (il attendra qu'un fil le débloque, et le verra en
/// revenant de rt_sigprocmask).
fn choisir_fil(p: &Processus, sig: u64) -> Option<Arc<Tache>> {
    let veut = |f: &fil::Fil| {
        (f.signaux.bloques & bit(sig) == 0).then(|| f.tache.upgrade()).flatten().filter(|t| !t.fin_prevue())
    };
    p.fils.iter().find(|f| f.tid == p.pid).and_then(veut).or_else(|| p.fils.iter().find_map(veut))
}

/// Les signaux de `ensemble`, envoyés au processus et en attente, que le
/// fil qui devait les prendre ne prendra pas (il vient de les bloquer, ou
/// il finit) : chacun est confié à un autre fil qui le veut, réveillé (le
/// `retarget_shared_pending` de Linux). Sous le verrou du processus, comme
/// chez Linux sous le `siglock`.
pub fn reconfier(p: &Processus, ensemble: u64) {
    let mut reste = ensemble & p.signaux.attente.ensemble;
    while reste != 0 {
        let sig = reste.trailing_zeros() as u64 + 1;
        reste &= !bit(sig);
        reveiller(choisir_fil(p, sig));
    }
}

/// Réveille le fil `t`, à qui un signal vient d'être envoyé, s'il dort
/// interruptible (le `signal_wake_up` de Linux).
pub fn reveiller(t: Option<Arc<Tache>>) {
    if let Some(t) = t {
        tache::reveiller_par_signal(t);
    }
}

/// Un signal attend-il le fil `tid`, qu'il ne bloque pas ? (Une attente
/// interruptible finit alors : attente.rs.) Un signal ignoré n'est jamais
/// en attente : il est jeté à l'envoi (`envoyer`), ou en devenant ignoré.
pub fn en_attente_non_bloque(p: &mut Processus, tid: u32) -> bool {
    let (attente, masque) = attente_et_masque(p, tid);
    attente & !masque != 0
}

/// Le prochain signal à livrer, s'il y en a un qui arrête le programme :
/// appelée au retour vers l'anneau 3, comme le `get_signal` de Linux. Les
/// signaux en attente et non bloqués sont pris un par un, comme le fait
/// `dequeue_signal` : ceux du fil d'abord, puis ceux du processus (mesuré :
/// SIGHUP envoyé au processus puis SIGTERM au fil, tous deux bloqués puis
/// débloqués, c'est SIGTERM qui le tue) ; dans chaque sorte, les synchrones
/// d'abord, puis du plus petit au plus grand. Un signal ignoré, ou dont
/// l'action par défaut est d'ignorer, est jeté ; SIGTSTP, SIGTTIN et
/// SIGTTOU sont jetés aussi, comme Linux le fait pour un groupe de
/// processus orphelin, ce qu'est le nôtre (son parent, le noyau qui joue
/// le rôle d'init, n'est pas dans sa session).
pub fn a_livrer(p: &mut Processus, tid: u32) -> Option<Livraison> {
    loop {
        let (sig, info) = prendre_parmi(p, tid, !0)?;
        let action = *p.signaux.action(sig);
        if action.gestionnaire == SIG_IGN {
            continue;
        }
        if action.gestionnaire != SIG_DFL {
            // SA_RESETHAND (SA_ONESHOT) : le gestionnaire ne sert qu'une
            // fois ; ses drapeaux restent (mesuré).
            if action.drapeaux & SA_RESETHAND != 0 {
                p.signaux.actions[(sig - 1) as usize].gestionnaire = SIG_DFL;
            }
            return Some(Livraison::Gestionnaire { sig, info, action });
        }
        let fin = match par_defaut(sig) {
            ParDefaut::Ignorer => continue,
            ParDefaut::Arreter if sig != SIGSTOP => continue,
            ParDefaut::Arreter => Fin::Suspendu,
            ParDefaut::Terminer | ParDefaut::ImageMemoire => Fin::ParDefaut,
        };
        return Some(Livraison::Arret { sig, fin });
    }
}

/// Les drapeaux d'une action dont se sert la livraison (cadre_signal.rs).
pub const SA_SIGINFO: u64 = 0x4;
pub const SA_RESTORER: u64 = 0x0400_0000;
pub const SA_ONSTACK: u64 = 0x0800_0000;
pub const SA_NODEFER: u64 = 0x4000_0000;
pub const SA_RESETHAND: u64 = 0x8000_0000;

/// Le masque du fil `tid`, et sa pile de secours (pour poser un cadre de
/// signal).
pub fn masque_et_pile(p: &mut Processus, tid: u32) -> (u64, PileDeSecours) {
    p.fil(tid).map_or((0, PileDeSecours::default()), |f| (f.signaux.bloques, f.signaux.pile))
}

/// Un gestionnaire de `sig` vient d'être posé pour le fil `tid` (le
/// `signal_delivered` de Linux) : pendant qu'il s'exécute, le fil bloque en
/// plus le masque de l'action, et `sig` lui-même sauf SA_NODEFER ; une pile
/// de secours SS_AUTODISARM est désarmée (rt_sigreturn la rétablira, d'après
/// le cadre).
pub fn apres_livraison(p: &mut Processus, tid: u32, sig: u64, action: &Action) {
    let mut bloques = action.masque;
    if action.drapeaux & SA_NODEFER == 0 {
        bloques |= bit(sig);
    }
    if let Some(f) = p.fil(tid) {
        f.signaux.bloques |= bloques & !IMBLOQUABLES;
        if f.signaux.pile.drapeaux & SS_AUTODISARM != 0 {
            f.signaux.pile = PileDeSecours { adresse: 0, taille: 0, drapeaux: SS_DISABLE };
        }
    }
    reconfier(p, bloques);
}

/// Le masque du fil `tid` devient `masque`, sans SIGKILL ni SIGSTOP (le
/// `set_current_blocked` de Linux : rt_sigreturn) ; les signaux du processus
/// qu'il vient de bloquer vont à un autre fil.
pub fn poser_masque(p: &mut Processus, tid: u32, masque: u64) {
    let masque = masque & !IMBLOQUABLES;
    let Some(f) = p.fil(tid) else { return };
    let nouveaux = masque & !f.signaux.bloques;
    f.signaux.bloques = masque;
    reconfier(p, nouveaux);
}

/// Force `sig` vers le fil `tid` (le `force_sig_info_to_task` de Linux) :
/// bloqué ou ignoré, il est débloqué et remis à son action par défaut, pour
/// qu'il soit livré, et tue ; `mortel` (HANDLER_SIG_DFL, celui de
/// `force_fatal_sig` : un cadre de SIGSEGV impossible à poser) le remet à
/// l'action par défaut même s'il avait un gestionnaire. Rend le fil à
/// réveiller.
pub fn forcer_au_fil(p: &mut Processus, tid: u32, sig: u64, info: Info, mortel: bool) -> Option<Arc<Tache>> {
    let Some(f) = p.fil(tid) else { return None };
    let bloque = f.signaux.bloques & bit(sig) != 0;
    if bloque {
        f.signaux.bloques &= !bit(sig);
    }
    let action = &mut p.signaux.actions[(sig - 1) as usize];
    if bloque || mortel || action.gestionnaire == SIG_IGN {
        action.gestionnaire = SIG_DFL;
    }
    envoyer(p, sig, Destinataire::Fil(tid), info, true).ok().flatten()
}

/// Prend, pour le fil `tid`, un signal en attente de `voulus` qu'il ne bloque
/// pas, ou de `voulus` seulement si `voulus` n'est pas tout (rt_sigtimedwait
/// prend aussi les bloqués) : ceux du fil d'abord, puis ceux du processus ;
/// dans chaque sorte, `EnAttente::suivant` (le `dequeue_signal` de Linux).
fn prendre_parmi(p: &mut Processus, tid: u32, voulus: u64) -> Option<(u64, Info)> {
    let s = &mut p.signaux;
    let f = &mut p.fils.iter_mut().find(|f| f.tid == tid)?.signaux;
    let permis = if voulus == !0 { !f.bloques } else { voulus };
    let attente = match (f.attente.ensemble & permis, s.attente.ensemble & permis) {
        (0, 0) => return None,
        (0, _) => &mut s.attente,
        _ => &mut f.attente,
    };
    let sig = EnAttente::suivant(attente.ensemble & permis);
    Some((sig, attente.prendre(sig)))
}

/// rt_sigaction(signal, action, ancienne, taille du masque). Dans l'ordre
/// de Linux : la taille du masque (8, sinon EINVAL), la nouvelle action lue
/// (EFAULT), le signal (1 à 64, et ni SIGKILL ni SIGSTOP s'il y a une
/// nouvelle action : EINVAL), puis l'ancienne écrite. Les drapeaux
/// inconnus sont effacés, SIGKILL et SIGSTOP retirés du masque, dans les
/// deux sens. Une action qui ignore désormais le signal efface ce qui en
/// attendait (POSIX, et Linux).
pub fn rt_sigaction(sig: u64, nouvelle: u64, ancienne: u64, taille: u64) -> i64 {
    if taille != 8 {
        return -EINVAL;
    }
    let mut lue = None;
    if nouvelle != 0 {
        let mut octets = [0u8; 32];
        if copier_depuis_utilisateur(&mut octets, nouvelle).is_err() {
            return -EFAULT;
        }
        let mut a = Action::lire(&octets);
        a.drapeaux &= DRAPEAUX_CONNUS;
        a.masque &= !IMBLOQUABLES;
        lue = Some(a);
    }
    // Un int pour Linux : un signal « négatif » est aussi hors de [1, 64].
    let sig = sig as u32 as u64;
    if sig < 1 || sig > NSIG || lue.is_some() && bit(sig) & IMBLOQUABLES != 0 {
        return -EINVAL;
    }
    let mut avant = processus::avec(|p| {
        let avant = *p.signaux.action(sig);
        if let Some(a) = lue {
            p.signaux.actions[(sig - 1) as usize] = a;
            if ignore_par(a.gestionnaire, sig) {
                effacer(p, bit(sig));
            }
        }
        avant
    });
    if ancienne != 0 {
        avant.drapeaux &= DRAPEAUX_CONNUS;
        if copier_vers_utilisateur(ancienne, &avant.octets()).is_err() {
            return -EFAULT;
        }
    }
    0
}

const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

/// rt_sigprocmask(comment, ensemble, ancien, taille du masque). Comme Linux :
/// la taille (8, sinon EINVAL) ; l'ancien masque gardé ; s'il y a un
/// nouvel ensemble, il est lu (EFAULT), sans SIGKILL ni SIGSTOP, puis
/// `comment` est vérifié (EINVAL : seulement quand il y a un ensemble,
/// mesuré) ; l'ancien écrit. Un signal en attente débloqué sera livré au
/// retour vers l'anneau 3. Un signal du processus en attente que ce fil
/// vient de bloquer est confié à un autre fil qui ne le bloque pas, réveillé
/// (le `retarget_shared_pending` de Linux) : sinon il attendrait que ce fil
/// le débloque, pendant qu'un autre aurait pu le prendre.
pub fn rt_sigprocmask(comment: u64, ensemble: u64, ancien: u64, taille: u64) -> i64 {
    if taille != 8 {
        return -EINVAL;
    }
    let mut lu = None;
    if ensemble != 0 {
        let mut octets = [0u8; 8];
        if copier_depuis_utilisateur(&mut octets, ensemble).is_err() {
            return -EFAULT;
        }
        lu = Some(u64::from_le_bytes(octets) & !IMBLOQUABLES);
    }
    let tid = tache::courante().tid();
    let r = processus::avec(|p| {
        let f = &mut p.fil(tid).expect("appel systeme d'un fil qui a quitte son processus").signaux;
        let avant = f.bloques;
        if let Some(e) = lu {
            f.bloques = match comment as u32 as u64 {
                SIG_BLOCK => avant | e,
                SIG_UNBLOCK => avant & !e,
                SIG_SETMASK => e,
                _ => return Err(-EINVAL),
            };
        }
        let bloques = f.bloques & !avant;
        reconfier(p, bloques);
        Ok(avant)
    });
    let avant = match r {
        Ok(avant) => avant,
        Err(e) => return e,
    };
    if ancien != 0 && copier_vers_utilisateur(ancien, &avant.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    0
}

/// rt_sigpending(ensemble, taille) : les signaux en attente ET bloqués (un
/// signal en attente non bloqué est livré avant que le programme ne
/// reprenne). Une taille de 8 au plus, dont on écrit les octets (mesuré : 0
/// et 4 réussissent, 16 rend EINVAL).
pub fn rt_sigpending(ensemble: u64, taille: u64) -> i64 {
    if taille > 8 {
        return -EINVAL;
    }
    let tid = tache::courante().tid();
    let attente = processus::avec(|p| {
        let (attente, masque) = attente_et_masque(p, tid);
        attente & masque
    });
    if copier_vers_utilisateur(ensemble, &attente.to_le_bytes()[..taille as usize]).is_err() {
        return -EFAULT;
    }
    0
}

/// Pose la pile de secours `n` du fil (`do_sigaltstack`, voir `sigaltstack`).
fn changer_pile(s: &mut SignauxDuFil, mut n: PileDeSecours, sp: u64) -> Result<(), i64> {
    let avant = s.pile;
    if avant.dessus(sp) {
        return Err(-EPERM);
    }
    let mode = n.drapeaux & !SS_AUTODISARM;
    if mode != 0 && mode != SS_ONSTACK && mode != SS_DISABLE {
        return Err(-EINVAL);
    }
    if n.adresse == avant.adresse && n.taille == avant.taille && n.drapeaux == avant.drapeaux {
        return Ok(());
    }
    if mode == SS_DISABLE {
        n.adresse = 0;
        n.taille = 0;
    } else if n.taille < MINSIGSTKSZ {
        return Err(-ENOMEM);
    }
    s.pile = n;
    Ok(())
}

/// rt_sigreturn rétablit la pile de secours que dit le cadre
/// (`restore_altstack`) : comme sigaltstack, avec le RSP du programme à
/// l'appel ; ses erreurs sont ignorées (seule une faute de copie compte, et
/// elle a déjà eu lieu en lisant le cadre).
pub fn retablir_pile(p: &mut Processus, tid: u32, n: PileDeSecours, sp: u64) {
    if let Some(f) = p.fil(tid) {
        let _ = changer_pile(&mut f.signaux, n, sp);
    }
}

/// sigaltstack(nouvelle, ancienne), dans l'ordre de `do_sigaltstack` :
///   - l'ancienne : adresse et taille posées, et dans les drapeaux
///     SS_DISABLE si la taille est nulle (la valeur initiale : {NULL,
///     SS_DISABLE, 0}), SS_ONSTACK si l'on s'exécute dessus, plus
///     SS_AUTODISARM s'il avait été demandé ;
///   - la nouvelle : son mode (0, SS_ONSTACK ou SS_DISABLE, sinon EINVAL,
///     SS_AUTODISARM à côté) ; identique à celle posée (adresse, taille et
///     drapeaux tels quels), rien à faire, sans autre vérification : un
///     programme neuf peut redonner {NULL, 0, 0}, ce qu'il a, bien que sa
///     taille soit sous MINSIGSTKSZ (mesuré : 0) ; SS_DISABLE remet adresse
///     et taille à 0 ; sinon une taille d'au moins MINSIGSTKSZ (ENOMEM).
///     L'adresse n'a pas à être alignée (Linux l'accepte).
/// Changer de pile de secours pendant qu'on s'exécute dessus (`sp`, le RSP
/// du programme à l'appel, dans la pile, sans SS_AUTODISARM) : EPERM, avant
/// même de regarder le mode ; l'ancienne dit alors SS_ONSTACK.
pub fn sigaltstack(nouvelle: u64, ancienne: u64, sp: u64) -> i64 {
    // stack_t : ss_sp (8 octets), ss_flags (un int, puis 4 de bourrage),
    // ss_size (8).
    let mut lue = None;
    if nouvelle != 0 {
        let mut o = [0u8; 24];
        if copier_depuis_utilisateur(&mut o, nouvelle).is_err() {
            return -EFAULT;
        }
        let mot = |i: usize| u64::from_le_bytes(o[i..i + 8].try_into().unwrap_or([0; 8]));
        let drapeaux = u32::from_le_bytes(o[8..12].try_into().unwrap_or([0; 4]));
        lue = Some(PileDeSecours { adresse: mot(0), taille: mot(16), drapeaux });
    }
    let avant = fil::avec(|f| {
        let avant = f.signaux.pile;
        if let Some(n) = lue {
            changer_pile(&mut f.signaux, n, sp)?;
        }
        Ok(avant)
    });
    let avant = match avant {
        Ok(a) => a,
        Err(e) => return e,
    };
    if ancienne != 0 {
        let drapeaux = avant.etat(sp) | avant.drapeaux & SS_AUTODISARM;
        let mut o = [0u8; 24];
        o[0..8].copy_from_slice(&avant.adresse.to_le_bytes());
        o[8..12].copy_from_slice(&drapeaux.to_le_bytes());
        o[16..24].copy_from_slice(&avant.taille.to_le_bytes());
        if copier_vers_utilisateur(ancienne, &o).is_err() {
            return -EFAULT;
        }
    }
    0
}

/// Le signal `sig` envoyé au processus `pid` (ou à l'un de ses fils, `a`),
/// après les vérifications de Linux (`check_kill_permission`) : un
/// processus qui existe (vivant ou zombie : ESRCH sinon, et avant le reste),
/// un signal valide (0 à 64, EINVAL), 0 n'envoyant rien (il demande
/// seulement « ce processus existe-t-il ? »). Un seul utilisateur : la
/// permission est toujours accordée. Un zombie ne reçoit plus rien (0, comme
/// Linux). Le fil qui le prendra, s'il ne le bloque pas, est réveillé s'il
/// dort interruptible (le `signal_wake_up` de Linux) : son appel rend
/// EINTR, et le signal est livré à son retour vers l'anneau 3.
fn envoyer_a(pid: u32, sig: u64, a: Destinataire, info: Info) -> i64 {
    if !processus::existe(pid) {
        return -ESRCH;
    }
    if sig > NSIG {
        return -EINVAL;
    }
    if sig == 0 {
        return 0;
    }
    match processus::avec_pid(pid, |p| envoyer(p, sig, a, info, false)) {
        Some(Err(e)) => e,
        Some(Ok(t)) => {
            reveiller(t);
            0
        }
        None => 0,
    }
}

/// Le siginfo d'un envoi par un programme (kill : SI_USER, tkill et tgkill :
/// SI_TKILL), de la part du processus courant.
fn info_de_soi(sig: u64, code: i32) -> Info {
    let (pid, uid) = processus::avec(|p| (p.pid, p.identite.uid));
    Info::par(sig, code, pid, uid)
}

/// kill(pid, signal), comme `kill_something_info` : pid > 0, un processus,
/// ou le processus du fil de ce numéro (ESRCH si aucun n'existe) ; 0, notre groupe de processus ; -1, tous les
/// processus sauf l'init et soi-même (0 si au moins un l'a reçu, ESRCH
/// s'il n'y en a aucun) ; < -1, le groupe -pid. Chaque programme mène son
/// propre groupe (son numéro est celui du processus), comme une commande
/// lancée par un shell. ESRCH passe avant EINVAL, comme chez Linux (on
/// cherche d'abord à qui envoyer).
pub fn kill(pid: u64, sig: u64) -> i64 {
    let pid = pid as u32 as i32;
    let soi = processus::avec(|p| p.pid);
    let sig = sig as u32 as u64;
    let info = info_de_soi(sig, SI_USER);
    match pid {
        0 => envoyer_a(soi, sig, Destinataire::Processus, info),
        -1 => {
            let mut autres = alloc::vec::Vec::new();
            processus::pour_chaque_pid(|p| {
                if p != soi && autres.try_reserve(1).is_ok() {
                    autres.push(p);
                }
            });
            let mut r = -ESRCH;
            for p in autres {
                let e = envoyer_a(p, sig, Destinataire::Processus, info);
                if e == 0 || r == -ESRCH {
                    r = e;
                }
            }
            r
        }
        i32::MIN => -ESRCH,
        // Un numéro de fil (pas celui d'un processus) : son processus, comme
        // Linux (`kill_proc_info` trouve la tâche du fil, puis envoie à son
        // groupe).
        p if p > 0 && !processus::existe(p as u32) => match tache::processus_du_fil(p as u32) {
            Some(pid) => envoyer_a(pid, sig, Destinataire::Processus, info),
            None => -ESRCH,
        },
        p => envoyer_a(p.unsigned_abs(), sig, Destinataire::Processus, info),
    }
}

/// tkill(fil, signal) : un fil précis, de n'importe quel processus. Un
/// numéro nul ou négatif : EINVAL.
pub fn tkill(tid: u64, sig: u64) -> i64 {
    let tid = tid as u32 as i32;
    if tid <= 0 {
        return -EINVAL;
    }
    au_fil(None, tid, sig, info_de_soi(sig as u32 as u64, SI_TKILL))
}

/// tgkill(processus, fil, signal) : le fil `tid` du processus `tgid`, ce
/// qu'appellent `raise` et `abort` de la glibc. Un numéro nul ou négatif :
/// EINVAL.
pub fn tgkill(tgid: u64, tid: u64, sig: u64) -> i64 {
    let (tgid, tid) = (tgid as u32 as i32, tid as u32 as i32);
    if tid <= 0 || tgid <= 0 {
        return -EINVAL;
    }
    au_fil(Some(tgid), tid, sig, info_de_soi(sig as u32 as u64, SI_TKILL))
}

/// Le `do_send_specific` de Linux : le fil `tid`, s'il existe et qu'il est
/// bien du processus `tgid` (quand il est donné), sinon ESRCH. Son
/// processus : celui de sa tâche, si elle vit ; sinon, pour un fil principal
/// (dont le numéro est celui du processus), le processus lui-même, zombie
/// ou dont d'autres fils vivent encore (Linux garde la tâche du fil
/// principal jusqu'à la fin du groupe) : le signal ne va alors à personne.
fn au_fil(tgid: Option<i32>, tid: i32, sig: u64, info: Info) -> i64 {
    let tid = tid as u32;
    let pid = tache::processus_du_fil(tid).unwrap_or(tid);
    if tgid.is_some_and(|t| t as u32 != pid) {
        return -ESRCH;
    }
    envoyer_a(pid, sig as u32 as u64, Destinataire::Fil(tid), info)
}

/// Lit le siginfo qu'un programme veut envoyer (`__copy_siginfo_from_user`) :
/// les 48 octets que garde le noyau (EFAULT), si_signo remplacé par `sig` ;
/// pour un si_code dont le noyau ne connaît pas la disposition, le reste
/// des 128 octets doit être nul (E2BIG : le noyau ne le garderait pas, et
/// le destinataire ne recevrait pas ce qui a été envoyé ;
/// `known_siginfo_layout`).
fn lire_info(sig: u64, adresse: u64) -> Result<Info, i64> {
    let mut o = [0u8; 128];
    copier_depuis_utilisateur(&mut o[..48], adresse).map_err(|_| -EFAULT)?;
    let mut i = Info([0; 48]);
    i.0.copy_from_slice(&o[..48]);
    i.0[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
    let code = i.code();
    // Les si_code propres à un signal (une faute, SIGCHLD, SIGPOLL, SIGSYS),
    // jusqu'à leur nombre (NSIGILL... de Linux) ; pour les autres, ceux de
    // SIGPOLL (NSIGPOLL).
    let limite = match sig {
        4 => 11,  // SIGILL
        8 => 15,  // SIGFPE
        11 => 10, // SIGSEGV
        7 => 5,   // SIGBUS
        5 => 6,   // SIGTRAP
        17 => 6,  // SIGCHLD
        29 => 6,  // SIGPOLL
        31 => 2,  // SIGSYS (SYS_SECCOMP, SYS_USER_DISPATCH)
        _ => 6,
    };
    let connue = code == SI_KERNEL || (code > SI_USER && code <= limite) || code >= SI_DETHREAD && code <= SI_USER
        || code == SI_ASYNCNL;
    if !connue {
        copier_depuis_utilisateur(&mut o[48..], adresse + 48).map_err(|_| -EFAULT)?;
        if o[48..].iter().any(|&x| x != 0) {
            return Err(-E2BIG);
        }
    }
    Ok(i)
}

/// rt_sigqueueinfo(pid, signal, siginfo) : un signal au processus `pid`,
/// avec le siginfo du programme (sigqueue de la glibc : SI_QUEUE et une
/// valeur). Dans l'ordre de Linux : le siginfo lu ; puis personne, pas même
/// root, ne se fait passer pour le noyau ou pour kill et tkill (si_code ≥ 0
/// ou SI_TKILL) envers un autre que soi (EPERM, avant de chercher `pid`) :
/// « soi », c'est le numéro du FIL appelant (`task_pid_vnr(current)`) ; un
/// fil secondaire qui vise son propre processus est refusé (mesuré) ; puis
/// l'envoi, comme kill d'un pid positif (ESRCH, EINVAL).
pub fn rt_sigqueueinfo(pid: u64, sig: u64, uinfo: u64) -> i64 {
    let (pid, sig) = (pid as u32 as i32, sig as u32 as u64);
    let info = match lire_info(sig, uinfo) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let soi = tache::courante().tid() as i32;
    if (info.code() >= 0 || info.code() == SI_TKILL) && pid != soi {
        return -EPERM;
    }
    if pid <= 0 {
        return -ESRCH;
    }
    match pid {
        p if !processus::existe(p as u32) => match tache::processus_du_fil(p as u32) {
            Some(pid) => envoyer_a(pid, sig, Destinataire::Processus, info),
            None => -ESRCH,
        },
        p => envoyer_a(p as u32, sig, Destinataire::Processus, info),
    }
}

/// rt_tgsigqueueinfo(tgid, tid, signal, siginfo) : de même, vers le fil
/// `tid` du processus `tgid` (les numéros nuls ou négatifs : EINVAL, avant
/// le reste ; puis l'EPERM de rt_sigqueueinfo, vis-à-vis du fil).
pub fn rt_tgsigqueueinfo(tgid: u64, tid: u64, sig: u64, uinfo: u64) -> i64 {
    let (tgid, tid, sig) = (tgid as u32 as i32, tid as u32 as i32, sig as u32 as u64);
    let info = match lire_info(sig, uinfo) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if tid <= 0 || tgid <= 0 {
        return -EINVAL;
    }
    let soi = tache::courante().tid() as i32;
    if (info.code() >= 0 || info.code() == SI_TKILL) && tid != soi {
        return -EPERM;
    }
    au_fil(Some(tgid), tid, sig, info)
}

/// rt_sigtimedwait(ensemble, siginfo, délai, taille du masque) : attend un
/// signal de `ensemble` et le prend, sans appeler de gestionnaire
/// (sigwaitinfo, sigtimedwait de la glibc). Dans l'ordre de Linux
/// (`do_sigtimedwait`) : la taille (8, sinon EINVAL), l'ensemble lu
/// (EFAULT), le délai lu (EFAULT) puis vérifié (EINVAL) ; un signal de
/// l'ensemble déjà en attente est pris tout de suite, bloqué ou non ; sinon,
/// avec un délai non nul (ou sans délai : sans fin), le fil attend, ses
/// signaux de l'ensemble débloqués le temps de l'attente (pour qu'un signal
/// envoyé au processus puisse le choisir), puis son masque d'avant revient,
/// et il reprend ce qui est arrivé. Rend le signal, et son siginfo (EFAULT
/// s'il ne peut pas être écrit : le signal est pris quand même) ; EAGAIN au
/// bout du délai ; EINTR si un autre signal, non bloqué, l'a réveillé (il
/// sera livré au retour). SIGKILL et SIGSTOP ne s'attendent pas.
pub fn rt_sigtimedwait(uthese: u64, uinfo: u64, delai: u64, taille: u64) -> i64 {
    if taille != 8 {
        return -EINVAL;
    }
    let mut o = [0u8; 8];
    if copier_depuis_utilisateur(&mut o, uthese).is_err() {
        return -EFAULT;
    }
    let ensemble = u64::from_le_bytes(o) & !IMBLOQUABLES;
    let mut attendre = None;
    if delai != 0 {
        let mut t = [0u8; 16];
        if copier_depuis_utilisateur(&mut t, delai).is_err() {
            return -EFAULT;
        }
        let (s, ns) = (i64::from_le_bytes(t[..8].try_into().unwrap_or([0; 8])), i64::from_le_bytes(t[8..].try_into().unwrap_or([0; 8])));
        if s < 0 || !(0..1_000_000_000).contains(&ns) {
            return -EINVAL;
        }
        attendre = Some((s as u64).saturating_mul(1_000_000_000).saturating_add(ns as u64));
    }
    let tid = tache::courante().tid();
    let interruptions = crate::cpu::couper_interruptions();
    let mut pris = processus::avec(|p| prendre_parmi(p, tid, ensemble));
    let mut r = -EAGAIN;
    if pris.is_none() && attendre != Some(0) {
        let echeance = attendre.map(|ns| crate::temps::ns_monotone().saturating_add(ns));
        let avant = processus::avec(|p| {
            let f = &mut p.fil(tid).expect("appel systeme d'un fil qui a quitte son processus").signaux;
            let avant = f.bloques;
            f.bloques_reels = avant;
            f.bloques &= !ensemble;
            avant
        });
        let reveil = crate::attente::dormir(echeance, crate::attente::Sommeil::Interruptible);
        pris = processus::avec(|p| {
            let f = &mut p.fil(tid).expect("appel systeme d'un fil qui a quitte son processus").signaux;
            let rebloques = avant & !f.bloques;
            f.bloques = avant;
            f.bloques_reels = 0;
            reconfier(p, rebloques);
            prendre_parmi(p, tid, ensemble)
        });
        if reveil != tache::Reveil::Echeance {
            r = -EINTR;
        }
    }
    if interruptions {
        crate::cpu::activer_interruptions();
    }
    let Some((sig, info)) = pris else { return r };
    if uinfo != 0 && copier_vers_utilisateur(uinfo, &info.octets()).is_err() {
        return -EFAULT;
    }
    sig as i64
}

/// Le signal `sig` (1 à 64), avec son nom pour les messages. Les signaux
/// temps réel sont nommés à partir du SIGRTMIN du noyau (32 ; celui de la
/// glibc est 34, elle se garde les deux premiers).
pub fn signal(sig: u64) -> Signal {
    const NOMS: [&str; 65] = [
        "?", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL",
        "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT",
        "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF",
        "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
        "SIGRTMIN", "SIGRTMIN+1", "SIGRTMIN+2", "SIGRTMIN+3", "SIGRTMIN+4", "SIGRTMIN+5", "SIGRTMIN+6", "SIGRTMIN+7",
        "SIGRTMIN+8", "SIGRTMIN+9", "SIGRTMIN+10", "SIGRTMIN+11", "SIGRTMIN+12", "SIGRTMIN+13", "SIGRTMIN+14", "SIGRTMIN+15",
        "SIGRTMIN+16", "SIGRTMIN+17", "SIGRTMIN+18", "SIGRTMIN+19", "SIGRTMIN+20", "SIGRTMIN+21", "SIGRTMIN+22", "SIGRTMIN+23",
        "SIGRTMIN+24", "SIGRTMIN+25", "SIGRTMIN+26", "SIGRTMIN+27", "SIGRTMIN+28", "SIGRTMIN+29", "SIGRTMIN+30", "SIGRTMIN+31",
        "SIGRTMIN+32",
    ];
    Signal { numero: sig as u8, nom: NOMS.get(sig as usize).copied().unwrap_or("?") }
}
