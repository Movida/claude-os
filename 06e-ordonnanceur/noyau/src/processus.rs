//! Les processus : ce que les appels système d'un programme Linux doivent
//! pouvoir modifier (sa mémoire : zones, tables de pages, tas ; ses
//! descripteurs de fichiers ; son dossier courant). C'est une toute petite
//! partie de la task_struct de Linux.
//!
//! Chaque processus est une `Entree` de la TABLE DES PROCESSUS, tenue par
//! sa tâche (tache.rs) : `avec` donne celui de la tâche courante,
//! `avec_pid` celui d'un numéro (kill, /proc, sched_getaffinity). Quand sa
//! tâche meurt, elle rend elle-même la mémoire et les descripteurs du
//! processus (le `exit_mm` et le `exit_files` de Linux) ; il reste un
//! ZOMBIE : son numéro et son code de sortie, jusqu'à ce qu'init le
//! recueille (programmes.rs) et le retire de la table. La table est
//! réservée au démarrage pour autant de processus que de tâches : elle ne
//! grandit jamais pendant un programme.
//!
//! Règle : jamais de copie depuis ou vers la mémoire du programme sous le
//! verrou d'un processus (une copie peut fauter, et plus tard attendre le
//! disque). On y lit ou change l'état, on rend le verrou, puis on copie.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use crate::descripteurs::{Descripteurs, LIMITE_DESCRIPTEURS};
use crate::memoire::Memoire;
use crate::signaux::Signaux;
use crate::verrou::Verrou;
use crate::vfs;
use fichiers::Identite;
use fichiers::montages::Objet;

pub struct Processus {
    /// Son numéro (pid), qui est aussi celui de son seul fil et de son
    /// groupe de processus (voir `numero_neuf`).
    pub pid: u32,
    /// Sa mémoire (la mm_struct de Linux, voir memoire.rs).
    pub memoire: Memoire,
    /// Ses descripteurs de fichiers (la files_struct, descripteurs.rs).
    pub descripteurs: Descripteurs,
    /// Son dossier courant, d'où partent les chemins relatifs ; et sa
    /// racine (chroot), d'où partent les chemins absolus. Des objets de la
    /// vue de tous les systèmes de fichiers (un dossier courant peut être
    /// dans /proc) ; un inode du tmpfs est tenu.
    pub dossier: Objet,
    pub racine: Objet,
    /// Son masque de création (umask) : les droits à retirer de tout
    /// fichier qu'il crée. 022 par défaut, comme Linux.
    pub umask: u32,
    /// Qui il est, pour les droits des fichiers.
    pub identite: Identite,
    /// Ses limites de ressources (getrlimit, prlimit64), sauf celle des
    /// descripteurs, que garde leur table (`Descripteurs::limite`).
    pub limites: [(u64, u64); LIMITES],
    /// Ses signaux : actions, masque, signaux en attente, pile de secours
    /// (signaux.rs).
    pub signaux: Signaux,
}

/// Le numéro du prochain programme lancé.
static PROCHAIN: AtomicU32 = AtomicU32::new(2);

/// Un numéro de processus neuf : 2, puis 3, 4... Le 1 est celui de l'init,
/// dont le noyau tient le rôle tant qu'il n'y a pas de `/init` (6k) : il
/// lance chaque ligne de /etc/demarrage, comme un init lance ses
/// services, et `getppid` rend 1. Option écartée : donner le 1 à chaque
/// programme (ce que faisaient les étapes 5 à 6c). Sous Linux, le pid 1
/// est à part : il ne reçoit pas les signaux à action par défaut qu'il
/// s'envoie (SIGNAL_UNKILLABLE, `raise(SIGTERM)` n'y fait rien), et des
/// programmes le traitent autrement (Node et Bun, dans un conteneur). Le
/// processus mène aussi son propre groupe et sa session, comme une
/// commande lancée par un shell. Pas de recyclage des numéros avant
/// pid_max (4 194 304 sous Linux) : des milliers de programmes par
/// démarrage au plus, il ne sera jamais atteint.
pub fn numero_neuf() -> u32 {
    PROCHAIN.fetch_add(1, Ordering::Relaxed)
}

/// Le nombre de limites de ressources de Linux (RLIM_NLIMITS).
pub const LIMITES: usize = 16;
pub const RLIMIT_CPU: usize = 0;
pub const RLIMIT_STACK: usize = 3;
pub const RLIMIT_NOFILE: usize = 7;
/// RLIM_INFINITY.
pub const INFINI: u64 = u64::MAX;

/// Les limites d'un processus neuf : celles que Linux donne au premier
/// (INIT_RLIMITS), (courante, dure). 8 Mio de pile (la glibc la lit pour
/// la pile de ses fils ; elle grandit bien jusque-là, memoire.rs,
/// PILE_MAX), pas de fichier « core », 8 Mio de mémoire verrouillable, 800
/// Kio de files de messages, 1024 descripteurs (4096 au plus), infini pour
/// le reste. NPROC et SIGPENDING : Linux les tire de la mémoire (la moitié
/// de max_threads) ; sans fils ni signaux (6e, 6f), infini.
///
/// Seules celles des descripteurs et du temps de calcul (RLIMIT_CPU, infini
/// par défaut comme chez Linux : voir tache::verifier_au_retour) sont
/// appliquées ; les autres sont rendues telles qu'on les a posées, comme le
/// demandent les programmes qui les baissent par prudence (pas de « core »,
/// une pile plus petite). Les appliquer viendra avec ce qu'elles limitent.
pub const LIMITES_PAR_DEFAUT: [(u64, u64); LIMITES] = {
    let mut l = [(INFINI, INFINI); LIMITES];
    l[RLIMIT_STACK] = (8 << 20, INFINI);
    l[4] = (0, INFINI); // RLIMIT_CORE
    l[RLIMIT_NOFILE] = LIMITE_DESCRIPTEURS;
    l[8] = (8 << 20, 8 << 20); // RLIMIT_MEMLOCK
    l[12] = (819_200, 819_200); // RLIMIT_MSGQUEUE
    l[13] = (0, 0); // RLIMIT_NICE
    l[14] = (0, 0); // RLIMIT_RTPRIO
    l
};

impl Processus {
    /// La limite `ressource` (sous LIMITES).
    pub fn limite(&self, ressource: usize) -> (u64, u64) {
        if ressource == RLIMIT_NOFILE { self.descripteurs.limite } else { self.limites[ressource] }
    }

    pub fn changer_limite(&mut self, ressource: usize, limite: (u64, u64)) {
        if ressource == RLIMIT_NOFILE {
            self.descripteurs.limite = limite;
        } else {
            self.limites[ressource] = limite;
        }
    }
}

impl Drop for Processus {
    /// La fin d'un processus : ses descripteurs fermés, son dossier courant
    /// et sa racine lâchés. Sa mémoire, elle, se rend d'elle-même (memoire.rs).
    fn drop(&mut self) {
        loop {
            let Some(fd) = self.descripteurs.ouverts(0, u64::MAX).next() else { break };
            if let Some(d) = self.descripteurs.retirer(fd) {
                vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
            }
        }
        vfs::avec(|fs, cadres| {
            for o in [self.dossier, self.racine] {
                if let Some(n) = o.tmpfs() {
                    fs.lacher(n, cadres);
                }
            }
        });
    }
}

/// Un processus de la table : son numéro, ce qu'il a tant qu'il vit
/// (None une fois sa tâche morte : un zombie), et son code de sortie.
pub struct Entree {
    pid: u32,
    processus: Verrou<Option<Processus>>,
    code: AtomicI32,
}

impl Entree {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// La fin de sa tâche : son code, puis sa mémoire et ses descripteurs
    /// rendus (dans la tâche qui meurt, interruptions actives : rendre des
    /// centaines de Mio prend du temps). Il reste le zombie.
    pub fn terminer(&self, code: i32) {
        self.code.store(code, Ordering::Relaxed);
        let fini = self.processus.verrouiller().take();
        drop(fini);
    }

    pub fn code(&self) -> i32 {
        self.code.load(Ordering::Relaxed)
    }
}

static TABLE: Verrou<Vec<Arc<Entree>>> = Verrou::new(Vec::new());

/// Réserve la table pour `max` processus. Au démarrage.
pub fn initialiser(max: usize) {
    TABLE.verrouiller().try_reserve_exact(max).expect("plus de memoire pour la table des processus");
}

/// Range un processus neuf dans la table ; None si elle est pleine (pas
/// plus de processus que de tâches).
pub fn ajouter(processus: Processus) -> Option<Arc<Entree>> {
    let mut table = TABLE.verrouiller();
    if table.len() == table.capacity() {
        return None;
    }
    let e = Arc::new(Entree { pid: processus.pid, processus: Verrou::new(Some(processus)), code: AtomicI32::new(0) });
    table.push(e.clone());
    Some(e)
}

/// Retire de la table le zombie `pid`, recueilli (programmes.rs) : son
/// code de sortie.
pub fn recueillir(pid: u32) -> Option<i32> {
    let mut table = TABLE.verrouiller();
    let i = table.iter().position(|e| e.pid == pid)?;
    Some(table.swap_remove(i).code())
}

/// Exécute `f` sur le processus de la tâche courante (il y en a toujours
/// un pendant un appel système), verrou tenu : `f` doit être court, et ne
/// pas toucher à la mémoire du programme par ses adresses.
pub fn avec<R>(f: impl FnOnce(&mut Processus) -> R) -> R {
    essayer_avec(f).expect("appel systeme sans processus en cours")
}

/// Comme `avec`, si la tâche courante a un processus vivant : une faute de
/// page du noyau peut arriver sans lui (le test du démarrage, dans
/// main.rs, une tâche du noyau).
pub fn essayer_avec<R>(f: impl FnOnce(&mut Processus) -> R) -> Option<R> {
    if !crate::tache::en_service() {
        return None;
    }
    let e = crate::tache::courante().processus()?;
    let mut p = e.processus.verrouiller();
    p.as_mut().map(f)
}

/// Exécute `f` sur le processus `pid`, s'il est dans la table et vivant
/// (pas un zombie). None sinon.
pub fn avec_pid<R>(pid: u32, f: impl FnOnce(&mut Processus) -> R) -> Option<R> {
    let e = TABLE.verrouiller().iter().find(|e| e.pid == pid)?.clone();
    let mut p = e.processus.verrouiller();
    p.as_mut().map(f)
}

/// Appelle `f` sur le numéro de chaque processus de la table.
pub fn pour_chaque_pid(mut f: impl FnMut(u32)) {
    for e in TABLE.verrouiller().iter() {
        f(e.pid);
    }
}

/// Le processus `pid` est-il dans la table (vivant ou zombie) ?
pub fn existe(pid: u32) -> bool {
    TABLE.verrouiller().iter().any(|e| e.pid == pid)
}
