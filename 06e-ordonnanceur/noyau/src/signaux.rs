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
//! ignorer, arrêter), l'attente d'un signal bloqué, pour les signaux qu'un
//! programme s'envoie (`kill`, `tkill`, `tgkill`) et pour SIGXCPU. Appeler
//! un gestionnaire (le cadre de signal, `rt_sigreturn`, SA_RESTART) vient
//! en 6f : d'ici là, un signal qui devrait l'appeler arrête le programme,
//! et le message le dit. Une faute d'un programme qui a un gestionnaire
//! l'arrête aussi (sous Linux, celui de Bun afficherait son rapport de
//! plantage).
//!
//! Comme Linux, les actions sont au processus (la `sighand_struct`, que
//! partageront ses fils en 6e), le masque et la pile de secours au fil. Les
//! signaux en attente sont de deux sortes, comme chez Linux : ceux envoyés
//! au fil (`tkill`, `tgkill`, une faute : `pending`) et ceux envoyés au
//! processus (`kill`, SIGXCPU : `shared_pending`, que n'importe lequel de
//! ses fils prendra en 6e). Ceux du fil passent d'abord. Chaque sorte est
//! un ensemble : un signal temps réel (32 à 64) envoyé deux fois ne compte
//! qu'une fois jusqu'en 6f, où ils feront une file, comme chez Linux.

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::linux::Signal;
use crate::processus::{self, Processus};

const ESRCH: i64 = 3;
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

/// Le bit du signal `sig` dans un ensemble (sigset_t : le bit sig - 1).
const fn bit(sig: u64) -> u64 {
    1 << (sig - 1)
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
    /// appelle rt_sigreturn) : ne servira qu'en 6f.
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
/// SA_ONSTACK s'exécutera (6f), pour qu'un débordement de la pile ordinaire
/// puisse encore être signalé. Ses valeurs telles que le programme les a
/// posées, comme Linux (sas_ss_sp, sas_ss_size, sas_ss_flags).
#[derive(Clone, Copy, Default)]
struct PileDeSecours {
    adresse: u64,
    taille: u64,
    drapeaux: u32,
}

const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
/// Le seul drapeau à côté du mode : rendre la pile de secours le temps
/// d'un gestionnaire (6f).
const SS_AUTODISARM: u32 = 1 << 31;
/// La plus petite pile de secours (MINSIGSTKSZ de x86).
const MINSIGSTKSZ: u64 = 2048;

/// Les signaux d'un processus.
#[derive(Clone)]
pub struct Signaux {
    /// L'action de chaque signal (l'indice : le signal moins 1).
    actions: [Action; NSIG as usize],
    /// Les signaux bloqués (le masque du fil).
    bloques: u64,
    /// Ceux qui attendent d'être livrés : envoyés au fil, et envoyés au
    /// processus. Ils sont dans la même structure tant qu'il n'y a qu'un
    /// fil ; en 6e, le second ira avec les actions, partagé par les fils.
    attente_fil: u64,
    attente_processus: u64,
    pile: PileDeSecours,
}

/// À qui un signal est envoyé : au fil, ou au processus (le `PIDTYPE_PID`
/// et le `PIDTYPE_TGID` de `send_signal_locked`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Destinataire {
    Fil,
    Processus,
}

impl Signaux {
    /// Ceux d'un programme neuf : toutes les actions par défaut, rien de
    /// bloqué, rien en attente, pas de pile de secours (comme après
    /// `execve`, depuis un parent qui n'avait rien changé).
    pub fn new() -> Signaux {
        Signaux {
            actions: [Action::default(); NSIG as usize],
            bloques: 0,
            attente_fil: 0,
            attente_processus: 0,
            pile: PileDeSecours::default(),
        }
    }

    /// Efface les signaux de `ensemble` qui attendaient, des deux sortes.
    fn effacer(&mut self, ensemble: u64) {
        self.attente_fil &= !ensemble;
        self.attente_processus &= !ensemble;
    }

    /// Les signaux en attente, des deux sortes (ce que rend `rt_sigpending`
    /// avant de garder les bloqués).
    fn en_attente(&self) -> u64 {
        self.attente_fil | self.attente_processus
    }

    fn action(&self, sig: u64) -> &Action {
        &self.actions[(sig - 1) as usize]
    }

    /// Le signal serait-il jeté dès son envoi ? Seulement s'il n'est pas
    /// bloqué (l'action pourrait changer d'ici son déblocage) et que son
    /// action l'ignore (`sig_ignored`).
    fn ignore(&self, sig: u64) -> bool {
        self.bloques & bit(sig) == 0 && ignore_par(self.action(sig).gestionnaire, sig)
    }

    /// Un gestionnaire serait-il appelé pour une faute (SIGSEGV...) ? Il
    /// faut qu'il y en ait un, et que le signal ne soit pas bloqué : une
    /// faute ignorée ou bloquée remet l'action par défaut et tue le
    /// programme (`force_sig_info_to_task`).
    pub fn gestionnaire_pour_faute(&self, sig: u64) -> bool {
        let g = self.action(sig).gestionnaire;
        g != SIG_DFL && g != SIG_IGN && self.bloques & bit(sig) == 0
    }
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
    /// Un gestionnaire devrait être appelé : 6f.
    Gestionnaire,
}

/// Envoie `sig` (1 à 64) au fil ou au processus : jeté s'il l'ignore, en
/// attente sinon, livré au retour vers l'anneau 3 (`a_livrer`). C'est le
/// `send_signal_locked` de Linux, avec son `prepare_signal` : un signal qui
/// relance (SIGCONT) efface les signaux d'arrêt en attente, des deux
/// sortes, et l'inverse.
pub fn envoyer(p: &mut Processus, sig: u64, a: Destinataire) {
    let s = &mut p.signaux;
    if sig == SIGCONT {
        s.effacer(bit(SIGSTOP) | bit(SIGTSTP) | bit(SIGTTIN) | bit(SIGTTOU));
    } else if matches!(par_defaut(sig), ParDefaut::Arreter) {
        s.effacer(bit(SIGCONT));
    }
    if !s.ignore(sig) {
        match a {
            Destinataire::Fil => s.attente_fil |= bit(sig),
            Destinataire::Processus => s.attente_processus |= bit(sig),
        }
    }
}

/// Un signal attend-il, que le programme ne bloque pas ? (Une attente
/// interruptible finit alors : attente.rs.) Un signal ignoré n'est jamais
/// en attente : il est jeté à l'envoi (`envoyer`), ou en devenant ignoré.
pub fn en_attente_non_bloque(p: &mut Processus) -> bool {
    p.signaux.en_attente() & !p.signaux.bloques != 0
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
pub fn a_livrer(p: &mut Processus) -> Option<(u64, Fin)> {
    let s = &mut p.signaux;
    loop {
        let (attente, prets) = match (s.attente_fil & !s.bloques, s.attente_processus & !s.bloques) {
            (0, 0) => return None,
            (0, prets) => (&mut s.attente_processus, prets),
            (prets, _) => (&mut s.attente_fil, prets),
        };
        let choix = if prets & SYNCHRONES != 0 { prets & SYNCHRONES } else { prets };
        let sig = choix.trailing_zeros() as u64 + 1;
        *attente &= !bit(sig);
        let gestionnaire = s.action(sig).gestionnaire;
        if gestionnaire == SIG_IGN {
            continue;
        }
        if gestionnaire != SIG_DFL {
            return Some((sig, Fin::Gestionnaire));
        }
        match par_defaut(sig) {
            ParDefaut::Ignorer => continue,
            ParDefaut::Arreter if sig != SIGSTOP => continue,
            ParDefaut::Arreter => return Some((sig, Fin::Suspendu)),
            ParDefaut::Terminer | ParDefaut::ImageMemoire => return Some((sig, Fin::ParDefaut)),
        }
    }
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
        let s = &mut p.signaux;
        let avant = *s.action(sig);
        if let Some(a) = lue {
            s.actions[(sig - 1) as usize] = a;
            if ignore_par(a.gestionnaire, sig) {
                s.effacer(bit(sig));
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
/// retour vers l'anneau 3.
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
    let avant = processus::avec(|p| {
        let s = &mut p.signaux;
        let avant = s.bloques;
        if let Some(e) = lu {
            s.bloques = match comment as u32 as u64 {
                SIG_BLOCK => avant | e,
                SIG_UNBLOCK => avant & !e,
                SIG_SETMASK => e,
                _ => return Err(-EINVAL),
            };
        }
        Ok(avant)
    });
    let avant = match avant {
        Ok(a) => a,
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
    let attente = processus::avec(|p| p.signaux.en_attente() & p.signaux.bloques);
    if copier_vers_utilisateur(ensemble, &attente.to_le_bytes()[..taille as usize]).is_err() {
        return -EFAULT;
    }
    0
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
/// Changer de pile de secours pendant qu'on s'exécute dessus rend EPERM
/// chez Linux ; seul un gestionnaire s'y exécute, et aucun n'est appelé
/// avant 6f : le programme n'y est jamais (écart écrit, il faudrait sinon
/// comparer son RSP à la pile).
pub fn sigaltstack(nouvelle: u64, ancienne: u64) -> i64 {
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
    let avant = processus::avec(|p| {
        let s = &mut p.signaux;
        let avant = s.pile;
        if let Some(mut n) = lue {
            let mode = n.drapeaux & !SS_AUTODISARM;
            if mode != 0 && mode != SS_ONSTACK && mode != SS_DISABLE {
                return Err(-EINVAL);
            }
            if n.adresse == avant.adresse && n.taille == avant.taille && n.drapeaux == avant.drapeaux {
                return Ok(avant);
            }
            if mode == SS_DISABLE {
                n.adresse = 0;
                n.taille = 0;
            } else if n.taille < MINSIGSTKSZ {
                return Err(-ENOMEM);
            }
            s.pile = n;
        }
        Ok(avant)
    });
    let avant = match avant {
        Ok(a) => a,
        Err(e) => return e,
    };
    if ancienne != 0 {
        let drapeaux = if avant.taille == 0 { SS_DISABLE } else { 0 } | avant.drapeaux & SS_AUTODISARM;
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

/// Le signal `sig` envoyé à soi-même (au fil ou au processus), après les
/// vérifications de Linux (`check_kill_permission`) : un signal valide (0 à
/// 64, EINVAL), 0 n'envoyant rien (il demande seulement « ce processus
/// existe-t-il ? »). Un seul utilisateur : la permission est toujours
/// accordée.
fn envoyer_a_soi(sig: u64, a: Destinataire) -> i64 {
    if sig > NSIG {
        return -EINVAL;
    }
    if sig != 0 {
        processus::avec(|p| envoyer(p, sig, a));
    }
    0
}

/// kill(pid, signal), comme `kill_something_info` : pid > 0, un processus
/// (le nôtre, sinon ESRCH) ; 0, notre groupe de processus ; -1, tous les
/// processus sauf l'init et soi-même (il n'y en a aucun : ESRCH) ; < -1, le
/// groupe -pid. Chaque programme mène son propre groupe (son numéro est
/// celui du processus), comme une commande lancée par un shell. ESRCH
/// passe avant EINVAL, comme chez Linux (on cherche d'abord à qui
/// envoyer).
pub fn kill(pid: u64, sig: u64) -> i64 {
    let pid = pid as u32 as i32;
    let soi = processus::avec(|p| p.pid) as i32;
    let sig = sig as u32 as u64;
    match pid {
        0 => envoyer_a_soi(sig, Destinataire::Processus),
        -1 | i32::MIN => -ESRCH,
        p if p == soi || p == -soi => envoyer_a_soi(sig, Destinataire::Processus),
        _ => -ESRCH,
    }
}

/// tkill(fil, signal) : un fil précis (le nôtre : un seul fil, dont le
/// numéro est celui du processus). Un numéro nul ou négatif : EINVAL.
pub fn tkill(tid: u64, sig: u64) -> i64 {
    let tid = tid as u32 as i32;
    if tid <= 0 {
        return -EINVAL;
    }
    au_fil(None, tid, sig)
}

/// tgkill(processus, fil, signal) : le fil `tid` du processus `tgid`, ce
/// qu'appellent `raise` et `abort` de la glibc. Un numéro nul ou négatif :
/// EINVAL.
pub fn tgkill(tgid: u64, tid: u64, sig: u64) -> i64 {
    let (tgid, tid) = (tgid as u32 as i32, tid as u32 as i32);
    if tid <= 0 || tgid <= 0 {
        return -EINVAL;
    }
    au_fil(Some(tgid), tid, sig)
}

/// Le `do_send_specific` de Linux : le fil `tid`, s'il existe et qu'il est
/// bien du processus `tgid` (quand il est donné), sinon ESRCH.
fn au_fil(tgid: Option<i32>, tid: i32, sig: u64) -> i64 {
    let soi = processus::avec(|p| p.pid) as i32;
    if tid != soi || tgid.is_some_and(|t| t != soi) {
        return -ESRCH;
    }
    envoyer_a_soi(sig as u32 as u64, Destinataire::Fil)
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
