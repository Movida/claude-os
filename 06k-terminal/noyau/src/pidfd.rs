//! Les pidfd : un processus, ou un fil, désigné par un descripteur de
//! fichier (Linux 5.3 à 6.9 ; fs/pidfs.c, kernel/pid.c, kernel/signal.c).
//! Un numéro de processus ne désigne plus le même processus une fois
//! celui-ci recueilli, dès que Linux le réutilise : qui envoie un signal par
//! un numéro risque de tuer un inconnu. Le pidfd tient le processus lui-même
//! (sa `struct pid` chez Linux) : il le désigne jusqu'au bout, et dit quand
//! il finit (poll : POLLIN), sans SIGCHLD ni wait. Node (libuv) et systemd
//! s'en servent ; chez Linux, une socket AF_UNIX donne aussi celui de son
//! pair (SO_PEERPIDFD).
//!
//! Ce qu'en fait un programme, mesuré sous Linux 6.18 (la sonde c11 du lot
//! 6 des soldes, puis `linux/pidfd.c`, sur l'hôte et chez nous) :
//!   - pidfd_open(pid, drapeaux) : un pidfd du processus `pid` (vivant ou
//!     zombie), ou, avec PIDFD_THREAD, du fil `pid` ; toujours FD_CLOEXEC ;
//!   - poll : POLLIN|POLLRDNORM quand le processus est fini (un zombie), et
//!     POLLHUP de plus quand il n'a plus de tâche (recueilli ; un fil, dès
//!     sa mort) ;
//!   - pidfd_send_signal : un signal par lui ;
//!   - pidfd_getfd : une copie d'un descripteur du processus, sous le
//!     contrôle d'accès de ptrace et de Yama ;
//!   - ioctl PIDFD_GET_INFO : qui il est, et son statut de sortie ;
//!   - clone3 et clone avec CLONE_PIDFD : le pidfd d'un fil neuf (fil.rs).
//! Le fichier n'a ni read ni write (EINVAL), ni position (lseek : ESPIPE ;
//! pread : EINVAL, il garde FMODE_PREAD), ni fsync (EINVAL) ; ftruncate et
//! fchmod : EOPNOTSUPP (`anon_inode_setattr`). Son inode est celui de
//! pidfs (fichiers::montages, `Objet::Pidfs`), un par numéro, daté de sa
//! création (`INODES`).
//!
//! Chez nous, un pidfd tient l'`Entree` du processus (processus.rs), qui
//! joue la `struct pid` d'un groupe : gardée au-delà du recueil, elle dit
//! s'il vit, s'il est zombie ou recueilli, et son statut ; et, pour un fil
//! qui n'est pas le principal, sa tâche (tache.rs), qui garde le sien. On y
//! attend dans une file de l'`Entree` (le `wait_pidfd` de Linux, une par
//! `struct pid`), une seule pour tout le processus : réveillée à la fin de
//! chacun de ses fils, quand il devient zombie, et quand il est recueilli ;
//! un pidfd de fil réveillé pour la fin d'un autre revoit son état et se
//! rendort. Option écartée : une file par fil, dans sa tâche ; elle
//! n'épargne qu'un réveil par fil qui finit, quand quelqu'un attend un
//! pidfd de ce processus.
//!
//! L'envoi d'un signal, lui, ne passe que par des NUMÉROS (signaux.rs,
//! comme kill et tgkill) : les nôtres ne sont jamais réutilisés
//! (processus.rs, `numero_neuf`), un numéro désigne donc toujours la même
//! tâche, ou plus rien. Écarté : des envois par l'`Entree` et la tâche,
//! une seconde façon de trouver le destinataire, à tenir d'accord avec la
//! première.
//!
//! Le contrôle d'accès de pidfd_getfd est celui de ptrace (kernel/ptrace.c,
//! `__ptrace_may_access`, en PTRACE_MODE_ATTACH_REALCREDS), puis celui de
//! Yama (security/yama/yama_lsm.c), dans le réglage d'Ubuntu, qui est celui
//! du Linux de référence : ptrace_scope à 1, « relationnel ». Un processus
//! n'accède qu'à lui-même, à ses descendants (aucun avant fork, 6l : tous
//! nos programmes sont enfants de l'init), et à qui l'a nommé par
//! prctl(PR_SET_PTRACER) ; root, à tous. Écartés : ptrace_scope à 0 (le
//! défaut de Linux sans Ubuntu ; nos tests sur l'hôte diraient autre
//! chose que chez nous), et Yama absent (la même chose).

use alloc::vec::Vec;

use crate::appels_fichiers::{FichierTenu, Prepare, preparer_fichier, recevoir_fichier, reserver, tenir, tenir_du_processus};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::faillible::VecFaillible;
use crate::partage::Arc;
use crate::processus::{self, Entree};
use crate::signaux::{self, Destinataire, SI_TKILL, SI_USER};
use crate::sondage::{POLLHUP, POLLIN, POLLRDNORM, Table};
use crate::tache::{self, Tache};
use crate::verrou::Verrou;
use fichiers::Temps;
use fichiers::montages::Objet;

const EPERM: i64 = 1;
const ESRCH: i64 = 3;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const ENOENT: i64 = 2;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const EOPNOTSUPP: i64 = 95;

const O_RDWR: u32 = 2;
/// PIDFD_NONBLOCK et PIDFD_THREAD : les valeurs d'O_NONBLOCK et d'O_EXCL,
/// gardées telles quelles dans les drapeaux du fichier (F_GETFL montre
/// PIDFD_THREAD : 0x82, mesuré).
const PIDFD_NONBLOCK: u32 = 0o4000;
const PIDFD_THREAD: u32 = 0o200;
/// Les drapeaux de pidfd_send_signal : la portée du signal, à la place de
/// celle du pidfd.
const PIDFD_SIGNAL_THREAD: u32 = 1;
const PIDFD_SIGNAL_THREAD_GROUP: u32 = 2;
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 4;
/// Les pseudo-descripteurs de pidfd_send_signal (include/uapi/linux/pidfd.h) :
/// le fil appelant, son processus. Ceux de -10001 : pas -20000 (mesuré).
const PIDFD_SELF_THREAD: i32 = -10000;
const PIDFD_SELF_THREAD_GROUP: i32 = -10001;

/// Les requêtes d'ioctl de pidfs : PIDFD_GET_INFO (_IOWR(0xFF, 11, struct
/// pidfd_info), extensible : sa taille dans la requête), les espaces de noms
/// (_IO(0xFF, 1) à _IO(0xFF, 10)), FS_IOC_GETVERSION (_IOR('v', 1, long)).
const PIDFS_MAGIE: u32 = 0xff;
const NR_GET_INFO: u32 = 11;
const FS_IOC_GETVERSION: u32 = 0x8008_7601;
/// Les tailles de la `struct pidfd_info` : la première (VER0), et la nôtre
/// (VER1, avec le masque de l'image mémoire).
const INFO_VER0: usize = 64;
const INFO_VER1: usize = 72;
/// Ce que dit son masque (PIDFD_INFO_*). CGROUPID (4), Linux le donne
/// toujours ; nous n'avons pas de cgroups (comme /proc/<pid>/cgroup, absent).
const INFO_PID: u64 = 1;
const INFO_CREDS: u64 = 2;
const INFO_EXIT: u64 = 8;
const INFO_COREDUMP: u64 = 0x10;
/// L'image mémoire qu'aurait le processus : faite à son nom
/// (SUID_DUMP_USER), seul cas chez nous (ni setuid, ni PR_SET_DUMPABLE).
const PIDFD_COREDUMP_USER: u32 = 4;

/// prctl(PR_SET_PTRACER, pid) : qui peut le tracer (Yama) ; -1 : tout le
/// monde (PR_SET_PTRACER_ANY), 0 : personne de plus.
pub const PR_SET_PTRACER: u64 = 0x5961_6d61;

/// Un pidfd (la `struct pid` que tient le fichier, `file->private_data`
/// chez Linux) : le processus, et, pour un fil qui n'est pas le principal,
/// sa tâche. Né avec son fichier, parti avec lui : il tient l'inode de son
/// numéro (`INODES`).
pub struct PidFd {
    entree: Arc<Entree>,
    fil: Option<Arc<Tache>>,
}

impl PidFd {
    /// Un pidfd neuf, qui prend l'inode de son numéro (ENOMEM).
    fn new(entree: Arc<Entree>, fil: Option<Arc<Tache>>) -> Result<Arc<PidFd>, i64> {
        let numero = fil.as_ref().map_or(entree.pid(), |t| t.tid());
        prendre_inode(numero)?;
        // Sans place pour l'Arc, `Arc::new` lâche l'objet : son Drop rend
        // l'inode pris (le rendre ici aussi le rendrait deux fois, et un
        // autre pidfd ouvert du même numéro perdrait le sien).
        Arc::new(PidFd { entree, fil }).map_err(|_| -ENOMEM)
    }

    /// Son numéro : celui du fil, ou du processus (l'inode de pidfs, et
    /// « soi » pour pidfd_send_signal).
    fn numero(&self) -> u32 {
        self.fil.as_ref().map_or(self.entree.pid(), |t| t.tid())
    }

    /// La tâche qu'il désigne, s'il y en a encore une (le `pid_task(pid,
    /// PIDTYPE_PID)` de Linux) : le fil, jusqu'à sa mort (Linux recueille
    /// aussitôt un fil qui n'est pas le principal) ; pour un processus, son
    /// fil principal, jusqu'au recueil, même parti avant les autres ou
    /// zombie (Linux le garde : `delay_group_leader`).
    fn tache(&self) -> Option<Arc<Tache>> {
        match &self.fil {
            Some(t) => (!t.est_morte()).then(|| t.clone()),
            None => self.entree.principal(),
        }
    }

    /// Le statut de sortie, s'il est connu (le `pidfs_exit_info` de Linux,
    /// posé par `pidfs_exit` quand la tâche est recueillie) : celui du fil,
    /// à sa mort ; celui du processus (le statut de `wait`), au recueil.
    fn statut(&self) -> Option<i32> {
        match &self.fil {
            Some(t) => t.est_morte().then(|| t.code_sortie()),
            None => self.entree.est_recueilli().then(|| self.entree.code()),
        }
    }

    /// Le sondage (`pidfd_poll`) : inscrit dans la file des pidfd du
    /// processus, puis, sans tâche : POLLIN|POLLRDNORM|POLLHUP (0x51,
    /// mesuré) ; un processus zombie, POLLIN|POLLRDNORM (0x41) ; sinon rien,
    /// pas même quand son fil principal est parti avant les autres.
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        table.attendre(self.entree.file_pidfd(), tenu);
        let parti = match &self.fil {
            Some(t) => t.est_morte(),
            None => self.entree.est_recueilli(),
        };
        if parti {
            POLLIN | POLLRDNORM | POLLHUP
        } else if self.fil.is_none() && self.entree.est_zombie() {
            POLLIN | POLLRDNORM
        } else {
            0
        }
    }
}

impl Drop for PidFd {
    fn drop(&mut self) {
        rendre_inode(self.numero());
    }
}

/// Un inode de pidfs ouvert : son numéro, combien de fichiers le tiennent (ses
/// pidfd, et les O_PATH ouverts par /proc/<pid>/fd/N d'un pidfd), sa
/// date de création (ses atime, mtime et ctime : `simple_inode_init_ts`).
struct Inode {
    numero: u32,
    ouverts: u32,
    date: Temps,
}

/// Les inodes de pidfs ouverts (chez Linux, chaque `struct pid` garde le
/// sien, `pid->stashed`, tant qu'un fichier tient son dentry). Un inode naît
/// avec le premier pidfd de son numéro et part avec le dernier fichier qui le
/// tient : rouvert ensuite, il a une date neuve (mesuré). Un O_PATH ouvert par
/// /proc/<pid>/fd/N d'un pidfd (permis sans droit de lecture) le tient aussi,
/// comme chez Linux : sa date reste, même ses pidfd fermés, et un pidfd_open
/// suivant la retrouve (mesuré ; `tenir_inode`, que la table des fichiers
/// ouverts appelle, descripteurs.rs). Une table du noyau, et non un champ de
/// l'`Entree` ou de la tâche : un tel fichier ne connaît que l'objet (son
/// numéro), et le processus peut être recueilli.
/// Le dernier verrou de l'ordre : rien ne se prend sous lui.
static INODES: Verrou<Vec<Inode>> = Verrou::new(Vec::new());

/// Un fichier de plus sur l'inode `numero`, créé s'il n'existait pas (ENOMEM
/// si la table ne peut pas grandir).
fn prendre_inode(numero: u32) -> Result<(), i64> {
    let date = crate::temps::maintenant();
    let mut inodes = INODES.verrouiller();
    if let Some(i) = inodes.iter_mut().find(|i| i.numero == numero) {
        i.ouverts += 1;
        return Ok(());
    }
    inodes.ajouter(Inode { numero, ouverts: 1, date }).map_err(|_| -ENOMEM)
}

/// Un fichier ouvert O_PATH (pas un pidfd) sur l'inode `numero` de pidfs : il
/// le tient comme un pidfd (ENOMEM). Sous le verrou des fichiers (INODES vient
/// après lui).
pub fn tenir_inode(numero: u32) -> Result<(), i64> {
    prendre_inode(numero)
}

/// Le dernier fermé de ces fichiers O_PATH : il rend l'inode.
pub fn lacher_inode(numero: u32) {
    rendre_inode(numero);
}

/// Un fichier de moins sur l'inode `numero` : parti avec le dernier.
fn rendre_inode(numero: u32) {
    let mut inodes = INODES.verrouiller();
    if let Some(k) = inodes.iter().position(|i| i.numero == numero) {
        inodes[k].ouverts -= 1;
        if inodes[k].ouverts == 0 {
            inodes.swap_remove(k);
        }
    }
}

/// La date de l'inode de pidfs `numero` (appels_fichiers::attributs) : il
/// existe tant qu'un pidfd le tient, seul moyen d'en demander les
/// attributs ; zéro sinon.
pub fn date(numero: u32) -> Temps {
    INODES.verrouiller().iter().find(|i| i.numero == numero).map_or(Temps { secondes: 0, nanosecondes: 0 }, |i| i.date)
}

/// Un pidfd neuf, pas encore installé (`pidfd_prepare`) : le numéro réservé
/// d'abord (EMFILE), puis son fichier (`pidfs_alloc_file`, ENOMEM) : O_RDWR,
/// et les drapeaux demandés (PIDFD_NONBLOCK, PIDFD_THREAD) ;
/// « anon_inode:[pidfd] » dans /proc/<pid>/fd. Toujours FD_CLOEXEC, à
/// l'installation.
fn preparer(entree: Arc<Entree>, fil: Option<Arc<Tache>>, drapeaux: u32) -> Result<Prepare, i64> {
    let numero = reserver()?;
    let p = PidFd::new(entree, fil)?;
    let mut f = FichierOuvert::new(Sorte::PidFd, Tenu::Noyau(Objet::Pidfs(p.numero())), true, true, O_RDWR | drapeaux,
                                   b"anon_inode:[pidfd]");
    f.chemin = crate::evenements::nom_anonyme(b"anon_inode:[pidfd]");
    f.prive = Prive::PidFd(p);
    preparer_fichier(numero, f)
}

/// Le pidfd du processus `entree`, que tiennent des droits AF_UNIX
/// (SO_PEERPIDFD, SCM_PIDFD : reseau/unix.rs, `Droits`), prêt à installer :
/// `pidfd_prepare` avec PIDFD_STALE, sans ESRCH ni ENOENT. Le processus peut
/// être un zombie, ou recueilli : Linux le sait inscrit dans pidfs depuis la
/// connexion ou l'envoi (`pidfs_register_pid`), et son pidfd en dit le statut
/// (POLLHUP, PIDFD_INFO_EXIT ; mesuré) ; chez nous, l'entrée le garde.
pub fn preparer_pour(entree: Arc<Entree>) -> Result<Prepare, i64> {
    preparer(entree, None, 0)
}

/// pidfd_open(pid, drapeaux), dans l'ordre de Linux : des drapeaux hors de
/// PIDFD_NONBLOCK et PIDFD_THREAD (O_CLOEXEC aussi) : EINVAL ; un numéro nul
/// ou négatif : EINVAL ; puis (`pidfd_prepare`) un processus de la table qui
/// a sa tâche, vivant ou zombie, même parti son fil principal : son pidfd (le même avec
/// PIDFD_THREAD : celui de son fil principal) ; un fil vivant qui n'est pas
/// le principal : son pidfd avec PIDFD_THREAD, ENOENT sans ; rien (un
/// processus recueilli, un fil mort) : ESRCH. Toujours FD_CLOEXEC.
pub fn pidfd_open(pid: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32;
    if drapeaux & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 {
        return -EINVAL;
    }
    let pid = pid as u32 as i32;
    if pid <= 0 {
        return -EINVAL;
    }
    let pid = pid as u32;
    let (entree, fil) = if let Some(e) = processus::entree(pid) {
        // Pas encore de tâche (son lancement n'a pas attaché son fil
        // principal) : ESRCH, le `pid_has_task(pid, PIDTYPE_PID)` de
        // `pidfd_prepare` (chez Linux, un processus n'est trouvable qu'avec
        // sa tâche). Il en a une ensuite jusqu'au recueil. Écarté : l'accepter :
        // le pidfd garderait l'entrée, et un lancement qui échoue alors la
        // lâcherait pleine à la fermeture du pidfd, sous le verrou des fichiers,
        // que son Drop reprend (sa mémoire, ses descripteurs).
        if e.principal().is_none() {
            return -ESRCH;
        }
        (e, None)
    } else if let Some(t) = tache::trouver(pid)
        && let Some(e) = t.processus().cloned()
    {
        if drapeaux & PIDFD_THREAD == 0 {
            return -ENOENT;
        }
        (e, Some(t))
    } else {
        return -ESRCH;
    };
    match preparer(entree, fil, drapeaux) {
        Ok(p) => p.installer(true) as i64,
        Err(e) => e,
    }
}

/// Le pidfd d'un fil neuf (CLONE_PIDFD, tache::lancer_fil) : celui de
/// `pidfd_prepare` avec PIDFD_THREAD (depuis Linux 6.9, un fil a un pidfd de
/// fil), le numéro réservé, le fichier rangé, et le numéro écrit à `adresse`
/// (un int ; EFAULT) ; installé seulement quand le fil a rejoint son
/// processus (`Prepare::installer`, le `fd_install` de la fin de
/// `copy_process`), défait sinon (le Drop de `Prepare`).
pub fn pour_fil_neuf(entree: &Arc<Entree>, fil: &Arc<Tache>, adresse: u64) -> Result<Prepare, i64> {
    let p = preparer(entree.clone(), Some(fil.clone()), PIDFD_THREAD)?;
    if copier_vers_utilisateur(adresse, &(p.numero() as i32).to_le_bytes()).is_err() {
        return Err(-EFAULT);
    }
    Ok(p)
}

/// Ce que vise pidfd_send_signal (la `struct pid` et le `pid_type` de
/// Linux) : un numéro, et la portée du signal.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Portee {
    /// La tâche de ce numéro seule (PIDTYPE_PID).
    Fil,
    /// Son processus (PIDTYPE_TGID).
    Processus,
    /// Le groupe de processus de ce numéro (PIDTYPE_PGID).
    Groupe,
}

/// pidfd_send_signal(pidfd, signal, siginfo, drapeaux), dans l'ordre de
/// Linux (kernel/signal.c) :
///   1. des drapeaux hors des trois portées, ou plus d'une : EINVAL ;
///   2. ce que désigne `pidfd` : PIDFD_SELF_THREAD, le fil appelant ;
///      PIDFD_SELF_THREAD_GROUP, son processus ; sinon un descripteur
///      (fermé : EBADF) : un pidfd (sa portée : le fil avec PIDFD_THREAD,
///      le processus sinon), ou un dossier /proc/<n> ouvert (le
///      `tgid_pidfd_to_pid` de Linux : le processus) ; autre chose : EBADF ;
///   3. un drapeau remplace la portée ;
///   4. avec un siginfo : copié (EFAULT, E2BIG), son si_signo doit être le
///      signal (EINVAL) ; puis, comme rt_sigqueueinfo, se faire passer pour
///      kill ou tkill (si_code ≥ 0, ou SI_TKILL) n'est permis qu'envers
///      soi-même, au sens du FIL appelant, et au plus pour son processus
///      (EPERM). Sans siginfo : celui de kill (SI_USER) pour un processus ou
///      un groupe, de tkill (SI_TKILL) pour un fil ;
///   5. l'envoi : personne sous ce numéro (un processus recueilli, un fil
///      mort, un groupe que personne ne mène) : ESRCH, avant un signal
///      invalide (EINVAL) ; 0 vérifie seulement ; un zombie, ou un fil
///      principal parti, ne reçoit rien (0).
pub fn pidfd_send_signal(pidfd: u64, sig: u64, info: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32;
    let portees = PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP | PIDFD_SIGNAL_PROCESS_GROUP;
    if drapeaux & !portees != 0 || drapeaux.count_ones() > 1 {
        return -EINVAL;
    }
    let (numero, portee) = match pidfd as u32 as i32 {
        PIDFD_SELF_THREAD => (tache::courante().tid(), Portee::Fil),
        PIDFD_SELF_THREAD_GROUP => (processus::avec(|p| p.pid), Portee::Processus),
        fd => {
            let o = match tenir(fd as u32 as u64) {
                Ok(o) => o,
                Err(e) => return e,
            };
            match (o.sorte, &o.prive) {
                (Sorte::PidFd, Prive::PidFd(p)) => (p.numero(), if o.drapeaux & PIDFD_THREAD != 0 { Portee::Fil } else { Portee::Processus }),
                (Sorte::Dossier, _) if let Some(n) = crate::procfs::numero_du_dossier(o.objet) => (n, Portee::Processus),
                _ => return -EBADF,
            }
        }
    };
    let portee = match drapeaux {
        PIDFD_SIGNAL_THREAD => Portee::Fil,
        PIDFD_SIGNAL_THREAD_GROUP => Portee::Processus,
        PIDFD_SIGNAL_PROCESS_GROUP => Portee::Groupe,
        _ => portee,
    };
    let sig = sig as u32 as u64;
    let info = if info != 0 {
        let i = match signaux::lire_info(None, info) {
            Ok(i) => i,
            Err(e) => return e,
        };
        if i.signal() != sig {
            return -EINVAL;
        }
        if (tache::courante().tid() != numero || portee > Portee::Processus) && (i.code() >= 0 || i.code() == SI_TKILL) {
            return -EPERM;
        }
        i
    } else {
        signaux::info_de_soi(sig, if portee == Portee::Fil { SI_TKILL } else { SI_USER })
    };
    match portee {
        // La tâche de ce numéro : un fil (son processus le trouve), ou un
        // fil principal, même parti (signaux::au_fil).
        Portee::Fil => signaux::au_fil(None, numero as i32, sig, info),
        // Le processus de la tâche de ce numéro, comme kill d'un numéro
        // positif.
        Portee::Processus => {
            let pid = if processus::existe(numero) { Some(numero) } else { tache::processus_du_fil(numero) };
            match pid {
                Some(pid) => signaux::envoyer_a(pid, sig, Destinataire::Processus, info),
                None => -ESRCH,
            }
        }
        // Chaque processus mène son propre groupe (processus.rs) : le groupe
        // de ce numéro est ce processus, s'il est dans la table ; le numéro
        // d'un fil ne nomme aucun groupe.
        Portee::Groupe if processus::existe(numero) => signaux::envoyer_a(numero, sig, Destinataire::Processus, info),
        Portee::Groupe => -ESRCH,
    }
}

/// pidfd_getfd(pidfd, fd, drapeaux), dans l'ordre de Linux (kernel/pid.c) :
/// des drapeaux : EINVAL ; `pidfd` fermé, ou pas un pidfd (un dossier de
/// /proc non plus, ni PIDFD_SELF_*) : EBADF ; plus de tâche : ESRCH ; pas le
/// droit d'y accéder (`acces_permis`) : EPERM ; la tâche qui finit (ses
/// descripteurs rendus, ou sur le point de l'être : PF_EXITING) : ESRCH ;
/// `fd` qui n'est pas ouvert chez elle : EBADF. Puis une copie du
/// descripteur, au plus petit numéro libre, avec FD_CLOEXEC (`receive_fd`,
/// comme un fichier reçu par SCM_RIGHTS) : le même fichier ouvert (sa
/// position partagée), un descripteur O_PATH compris.
/// Linux ne voit la tâche finir que si sa table est déjà rendue (`files`
/// nul) ; nous dès PF_EXITING, posé au début de sa sortie : la même course,
/// un peu plus tôt, et rien d'observable autrement.
pub fn pidfd_getfd(pidfd: u64, fd: u64, drapeaux: u64) -> i64 {
    if drapeaux as u32 != 0 {
        return -EINVAL;
    }
    let o = match tenir(pidfd as u32 as u64) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let p = match (o.sorte, &o.prive) {
        (Sorte::PidFd, Prive::PidFd(p)) => p.clone(),
        _ => return -EBADF,
    };
    let Some(t) = p.tache() else { return -ESRCH };
    if !acces_permis(&p.entree) {
        return -EPERM;
    }
    if t.drapeaux() & tache::PF_EXITING != 0 {
        return -ESRCH;
    }
    let fd = fd as u32 as i32;
    if fd < 0 {
        return -EBADF;
    }
    let Some(f) = tenir_du_processus(p.entree.pid(), fd as u64) else { return -EBADF };
    match recevoir_fichier(&f, true, |_| true) {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// Le fil courant peut-il accéder au processus `cible` comme ptrace le
/// voudrait pour s'y attacher (`ptrace_may_access(PTRACE_MODE_ATTACH_REALCREDS)`)
/// ? Son propre processus, toujours ; root, toujours (CAP_SYS_PTRACE, que
/// Yama respecte aussi) ; sinon, le même utilisateur et le même groupe
/// (réels, effectifs, sauvés : un seul de chaque chez nous), un processus
/// qui peut laisser une image de sa mémoire (toujours : ni setuid, ni
/// PR_SET_DUMPABLE), puis Yama à 1 (`yama_permet`).
fn acces_permis(cible: &Entree) -> bool {
    let (pid, qui) = processus::avec(|p| (p.pid, p.identite));
    if pid == cible.pid() || qui.root() {
        return true;
    }
    let lui = cible.identite();
    lui.uid == qui.uid && lui.gid == qui.gid && yama_permet(pid, cible.pid())
}

/// Ce qu'a déclaré prctl(PR_SET_PTRACER) : le processus qui l'a appelé (son
/// fil principal, comme Linux), et qui peut le tracer (None : tout le
/// monde, PR_SET_PTRACER_ANY ; sinon le numéro d'une tâche, processus ou
/// fil). Une relation par processus.
struct Relation {
    cible: u32,
    traceur: Option<u32>,
}

/// Les relations de Yama (son `ptracer_relations`). Un des derniers verrous
/// de l'ordre, comme `INODES` : on y lit des numéros, rien d'autre ne se
/// prend sous lui.
static RELATIONS: Verrou<Vec<Relation>> = Verrou::new(Vec::new());

/// Yama, dans le réglage relationnel (`yama_ptrace_access_check`, à 1) :
/// `traceur` accède à `cible` si elle descend de lui (jamais chez nous avant
/// fork : tous les programmes sont enfants de l'init), ou si elle l'a permis
/// par PR_SET_PTRACER (`ptracer_exception_found`) : à tous, ou à une tâche
/// dont le processus est `traceur` ou l'un de ses ancêtres (l'init, 1).
fn yama_permet(traceur: u32, cible: u32) -> bool {
    let relation = RELATIONS.verrouiller().iter().find(|r| r.cible == cible).map(|r| r.traceur);
    match relation {
        None => false,
        Some(None) => true,
        Some(Some(t)) => t == 1 || processus_de(t) == Some(traceur),
    }
}

/// Le processus de la tâche `n` : lui-même s'il en est un (vivant, zombie),
/// sinon celui du fil vivant de ce numéro.
fn processus_de(n: u32) -> Option<u32> {
    if processus::existe(n) { Some(n) } else { tache::processus_du_fil(n) }
}

/// prctl(PR_SET_PTRACER, pid) (`yama_task_prctl`) : pour le processus
/// appelant, quel que soit le fil (Linux prend son fil principal), 0 retire
/// la permission, -1 (PR_SET_PTRACER_ANY, ou -1 en int) la donne à tous ;
/// sinon le numéro d'une tâche qui existe (processus vivant ou zombie, fil
/// vivant, l'init) la reçoit, au lieu de celle d'avant (un numéro inconnu :
/// EINVAL). Une place qui manque : ENOMEM, et l'ancienne permission reste.
pub fn pr_set_ptracer(argument: u64) -> i64 {
    let moi = processus::avec(|p| p.pid);
    let traceur = match argument {
        0 => {
            RELATIONS.verrouiller().retain(|r| r.cible != moi);
            return 0;
        }
        a if a == u64::MAX || a as u32 as i32 == -1 => None,
        // Un pid_t : les 32 bits bas.
        a => match a as u32 as i32 {
            n if n == 1 || (n > 1 && processus_de(n as u32).is_some()) => Some(n as u32),
            _ => return -EINVAL,
        },
    };
    let mut relations = RELATIONS.verrouiller();
    if let Some(r) = relations.iter_mut().find(|r| r.cible == moi) {
        r.traceur = traceur;
        return 0;
    }
    match relations.ajouter(Relation { cible: moi, traceur }) {
        Ok(()) => 0,
        Err(_) => -ENOMEM,
    }
}

/// Une tâche disparaît (le `yama_task_free` de Linux) : les relations qui
/// la nomment partent avec elle. Pour un fil qui n'est pas le principal, à
/// sa fin ; pour un processus, à son recueil (Linux garde la tâche du fil
/// principal jusque-là), comme cible ou comme traceur.
pub fn oublier(n: u32) {
    RELATIONS.verrouiller().retain(|r| r.cible != n && r.traceur != Some(n));
}

/// Les requêtes d'ioctl d'un pidfd (`pidfd_ioctl`), une fois passées celles
/// de tous les fichiers (FIOCLEX, FIONBIO...) : une requête inconnue
/// (`pidfs_ioctl_valid`) : ENOTTY ; FS_IOC_GETVERSION : la génération de
/// l'inode, 0 (adresse nulle : EINVAL) ; PIDFD_GET_INFO, de 64 octets au
/// moins, en lecture et écriture : `info` ; un espace de noms : plus de
/// tâche, ESRCH ; un argument, EINVAL ; puis Linux rend un descripteur de
/// cet espace (nsfs), que nous n'avons pas (aucun espace de noms) :
/// EOPNOTSUPP, un écart.
pub fn ioctl(o: &FichierTenu, requete: u64, argument: u64) -> i64 {
    let requete = requete as u32;
    let Prive::PidFd(p) = &o.prive else { return -ENOTTY };
    let (sens, taille, genre, nr) = (requete >> 30, (requete >> 16) & 0x3fff, (requete >> 8) & 0xff, requete & 0xff);
    if requete == FS_IOC_GETVERSION {
        if argument == 0 {
            return -EINVAL;
        }
        return match copier_vers_utilisateur(argument, &0u32.to_le_bytes()) {
            Ok(()) => 0,
            Err(_) => -EFAULT,
        };
    }
    if genre == PIDFS_MAGIE && nr == NR_GET_INFO && sens == 3 && taille as usize >= INFO_VER0 {
        return p.info(argument, taille as usize);
    }
    if requete >> 8 == PIDFS_MAGIE && (1..=10).contains(&nr) {
        if p.tache().is_none() {
            return -ESRCH;
        }
        return if argument != 0 { -EINVAL } else { -EOPNOTSUPP };
    }
    -ENOTTY
}

impl PidFd {
    /// PIDFD_GET_INFO (`pidfd_info`) : la `struct pidfd_info` de `taille`
    /// octets à `adresse` (nulle : EINVAL), dont le programme a posé le masque
    /// de ce qu'il demande (lu : EFAULT). Le statut de sortie (EXIT) et le
    /// masque de l'image mémoire (COREDUMP) seulement demandés, et le
    /// statut seulement connu (`statut`). Puis, s'il reste une tâche : qui
    /// elle est (PID : son numéro, celui du processus, le parent, l'init :
    /// 1) et à qui (CREDS), toujours ; et, l'image demandée, celle qu'aurait
    /// sa mémoire (PIDFD_COREDUMP_USER ; rien si elle n'en a plus). Sans
    /// tâche, seul le statut : demandé, il est rendu (tout le reste à 0) ;
    /// sinon ESRCH. Écrits : les `taille` premiers octets de nos 72 (VER1),
    /// et des zéros au-delà (`copy_struct_to_user` ; EFAULT).
    fn info(&self, adresse: u64, taille: usize) -> i64 {
        if adresse == 0 {
            return -EINVAL;
        }
        let mut o = [0u8; 8];
        if copier_depuis_utilisateur(&mut o, adresse).is_err() {
            return -EFAULT;
        }
        let demande = u64::from_le_bytes(o);
        let mut k = [0u8; INFO_VER1];
        let mut masque = 0u64;
        let mut mettre = |position: usize, valeur: u32| k[position..position + 4].copy_from_slice(&valeur.to_le_bytes());
        if demande & INFO_EXIT != 0
            && let Some(statut) = self.statut()
        {
            masque |= INFO_EXIT;
            mettre(60, statut as u32);
        }
        if demande & INFO_COREDUMP != 0 {
            masque |= INFO_COREDUMP;
        }
        match self.tache() {
            None if demande & INFO_EXIT == 0 => return -ESRCH,
            None => {}
            Some(t) => {
                if demande & INFO_COREDUMP != 0 && t.a_sa_memoire() {
                    mettre(64, PIDFD_COREDUMP_USER);
                }
                let qui = self.entree.identite();
                for position in [28, 36, 44, 52] {
                    mettre(position, qui.uid);
                }
                for position in [32, 40, 48, 56] {
                    mettre(position, qui.gid);
                }
                masque |= INFO_CREDS;
                mettre(24, 1);
                mettre(20, self.entree.pid());
                mettre(16, self.numero());
                masque |= INFO_PID;
            }
        }
        k[..8].copy_from_slice(&masque.to_le_bytes());
        if taille > INFO_VER1 {
            let zeros = [0u8; 256];
            let mut fait = INFO_VER1;
            while fait < taille {
                let n = (taille - fait).min(zeros.len());
                if copier_vers_utilisateur(adresse + fait as u64, &zeros[..n]).is_err() {
                    return -EFAULT;
                }
                fait += n;
            }
        }
        match copier_vers_utilisateur(adresse, &k[..taille.min(INFO_VER1)]) {
            Ok(()) => 0,
            Err(_) => -EFAULT,
        }
    }
}
