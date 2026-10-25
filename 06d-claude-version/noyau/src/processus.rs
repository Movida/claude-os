//! Le processus en cours : ce que les appels système d'un programme Linux
//! doivent pouvoir modifier (sa mémoire : zones, tables de pages, tas ; ses
//! descripteurs de fichiers ; son dossier courant). C'est une toute petite
//! partie de la task_struct de Linux.
//!
//! Le noyau le range ici le temps de l'exécution (tache::executer), et le
//! reprend ensuite pour le détruire. Un seul processus à la fois : un
//! Verrou<Option<...>> ; l'ordonnanceur de l'étape 6 en fera une liste.
//!
//! Règle : jamais de copie depuis ou vers la mémoire du programme sous ce
//! verrou (une copie peut fauter, et plus tard attendre le disque). On y
//! lit ou change l'état, on rend le verrou, puis on copie.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::descripteurs::{Descripteurs, LIMITE_DESCRIPTEURS};
use crate::memoire::Memoire;
use crate::signaux::Signaux;
use crate::verrou::Verrou;
use crate::vfs;
use fichiers::Identite;
use fichiers::tmpfs::Numero;

pub struct Processus {
    /// Son numéro (pid), qui est aussi celui de son seul fil et de son
    /// groupe de processus (voir `numero_neuf`).
    pub pid: u32,
    /// Sa mémoire (la mm_struct de Linux, voir memoire.rs).
    pub memoire: Memoire,
    /// Ses descripteurs de fichiers (la files_struct, descripteurs.rs).
    pub descripteurs: Descripteurs,
    /// Son dossier courant (l'inode est tenu), d'où partent les chemins
    /// relatifs ; et sa racine (chroot), d'où partent les chemins absolus.
    pub dossier: Numero,
    pub racine: Numero,
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
/// pid_max (4 194 304 sous Linux) : avec un programme à la fois, il ne
/// sera jamais atteint.
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
            fs.lacher(self.dossier, cadres);
            fs.lacher(self.racine, cadres);
        });
    }
}

static COURANT: Verrou<Option<Processus>> = Verrou::new(None);

/// Le processus devient le processus en cours.
pub fn installer(processus: Processus) {
    *COURANT.verrouiller() = Some(processus);
}

/// Reprend le processus en cours (pour le détruire).
pub fn retirer() -> Option<Processus> {
    COURANT.verrouiller().take()
}

/// Exécute `f` sur le processus en cours (il y en a toujours un pendant un
/// appel système), verrou tenu : `f` doit être court, et ne pas toucher à
/// la mémoire du programme par ses adresses.
pub fn avec<R>(f: impl FnOnce(&mut Processus) -> R) -> R {
    let mut courant = COURANT.verrouiller();
    f(courant.as_mut().expect("appel systeme sans processus en cours"))
}

/// Comme `avec`, s'il y a un processus en cours : une faute de page du
/// noyau peut arriver sans lui (le test du démarrage, dans main.rs).
pub fn essayer_avec<R>(f: impl FnOnce(&mut Processus) -> R) -> Option<R> {
    COURANT.verrouiller().as_mut().map(f)
}
