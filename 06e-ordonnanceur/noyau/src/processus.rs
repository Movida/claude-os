//! Les processus : ce que partagent les fils d'un programme Linux, et que
//! leurs appels système doivent pouvoir modifier (sa mémoire : zones,
//! tables de pages, tas ; ses descripteurs de fichiers ; son dossier
//! courant ; l'action de ses signaux). Le `signal_struct`, le `mm_struct`,
//! le `files_struct` et le `fs_struct` de Linux, en une structure ; ce qui
//! est à chaque fil est dans sa tâche (tache.rs) et dans son `Fil` (fil.rs).
//!
//! Chaque processus est une `Entree` de la TABLE DES PROCESSUS, tenue par
//! chacun de ses fils (leurs tâches) et par la table : `avec` donne celui
//! de la tâche courante, `avec_pid` celui d'un numéro (kill, /proc,
//! sched_getaffinity). Quand son dernier fil meurt, il rend lui-même la
//! mémoire et les descripteurs du processus (le `exit_mm` et le
//! `exit_files` de Linux, au dernier qui les tient) ; il reste un ZOMBIE :
//! son numéro et son code de sortie, jusqu'à ce qu'init le recueille
//! (programmes.rs) et le retire de la table. La table est réservée au
//! démarrage pour autant de processus que de tâches : elle ne grandit
//! jamais pendant un programme.
//!
//! Règle : jamais de copie depuis ou vers la mémoire du programme sous le
//! verrou d'un processus (une copie peut fauter, et plus tard attendre le
//! disque). On y lit ou change l'état, on rend le verrou, puis on copie.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use crate::descripteurs::{Descripteurs, LIMITE_DESCRIPTEURS};
use crate::fil::Fil;
use crate::programmes::NomCourt;
use crate::tache::Tache;
use crate::memoire::Memoire;
use crate::signaux::Signaux;
use crate::verrou::Verrou;
use crate::vfs;
use fichiers::Identite;
use fichiers::montages::Objet;

pub struct Processus {
    /// Son numéro (pid), qui est aussi celui de son fil principal et de son
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
    /// Ses signaux : les actions, et ceux envoyés au processus (signaux.rs).
    pub signaux: Signaux,
    /// Ses fils vivants, le principal d'abord (fil.rs).
    pub fils: Vec<Fil>,
    /// La fin du groupe, si elle a commencé (exit_group, un signal mortel) :
    /// son code, que prendra le processus (le SIGNAL_GROUP_EXIT et le
    /// `group_exit_code` de Linux). La première l'emporte.
    pub fin_de_groupe: Option<i32>,
}

/// Le numéro du prochain programme lancé.
static PROCHAIN: AtomicU32 = AtomicU32::new(2);

/// Un numéro neuf, de processus ou de fil (le même compteur, comme les pid
/// et les tid de Linux) : 2, puis 3, 4... Le 1 est celui de l'init,
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
pub const RLIMIT_NPROC: usize = 6;
pub const RLIMIT_NOFILE: usize = 7;
/// RLIM_INFINITY.
pub const INFINI: u64 = u64::MAX;

/// Les limites d'un processus neuf : celles que Linux donne au premier
/// (INIT_RLIMITS), (courante, dure). 8 Mio de pile (la glibc la lit pour
/// la pile de ses fils ; elle grandit bien jusque-là, memoire.rs,
/// PILE_MAX), pas de fichier « core », 8 Mio de mémoire verrouillable, 800
/// Kio de files de messages, 1024 descripteurs (4096 au plus), infini pour
/// le reste. NPROC et SIGPENDING : Linux les tire de la mémoire (la moitié
/// de max_threads) ; infini ici, max_threads borne déjà les fils (6e), et
/// les signaux n'ont pas encore de file (6f).
///
/// Seules celles des descripteurs, du temps de calcul (RLIMIT_CPU, infini
/// par défaut comme chez Linux : voir tache::verifier_au_retour) et du
/// nombre de tâches (RLIMIT_NPROC, tache::lancer_fil) sont appliquées ;
/// les autres sont rendues telles qu'on les a posées, comme le demandent
/// les programmes qui les baissent par prudence (pas de « core », une pile
/// plus petite). Les appliquer viendra avec ce qu'elles limitent.
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
    /// Le fil `tid` du processus, s'il y est encore.
    pub fn fil(&mut self, tid: u32) -> Option<&mut Fil> {
        self.fils.iter_mut().find(|f| f.tid == tid)
    }

    /// La fin du groupe commence (exit_group, une faute, un signal mortel),
    /// demandée par le fil `appelant`, avec ce code, si elle n'a pas déjà
    /// commencé (le `do_group_exit` de Linux) : les autres fils sont
    /// arrêtés (le `zap_other_threads`). Rend le code du groupe : le premier
    /// l'emporte.
    pub fn finir_le_groupe(&mut self, code: i32, appelant: u32) -> i32 {
        if let Some(c) = self.fin_de_groupe {
            return c;
        }
        self.fin_de_groupe = Some(code);
        for f in &self.fils {
            if f.tid != appelant
                && let Some(t) = f.tache.upgrade()
            {
                crate::tache::arreter_avec_le_groupe(t, code);
            }
        }
        code
    }

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
/// (None une fois son dernier fil mort), son code de sortie, et ce qui doit
/// se lire sans son verrou.
pub struct Entree {
    pid: u32,
    processus: Verrou<Option<Processus>>,
    code: AtomicI32,
    /// Son temps de calcul, en nanosecondes : celui de tous ses fils,
    /// vivants et morts, compté avec celui de chaque fil (tache.rs), sans
    /// verrou (le gestionnaire d'horloge le compte). Pour
    /// CLOCK_PROCESS_CPUTIME_ID et RLIMIT_CPU. Le `thread_group_cputimer`
    /// de Linux ; option écartée, sa façon ordinaire : additionner les fils
    /// vivants à chaque lecture, plus le temps des morts (le
    /// `sum_sched_runtime`), un parcours de plus à chaque tic qui vérifie une
    /// attente de temps de calcul.
    calcul: AtomicU64,
    /// Ses fils pas encore tout à fait finis : ceux de la liste, et ceux
    /// qui l'ont quittée mais dont la pile n'est pas encore rendue (la fin
    /// de bascule qui suit leur mort, tache.rs). Le processus n'est un
    /// zombie qu'à zéro : un fil préempté entre sa sortie de la liste et sa
    /// dernière bascule (pendant que le dernier fil, lui, rend tout) garde
    /// sinon sa pile et sa tâche quand init le recueille, et « memoire
    /// rendue » compte trop tôt (vu : -6 pages, rendues au programme
    /// suivant).
    vivants: AtomicU32,
    /// Plus aucun fil, et tout est rendu : un zombie. Posé à la fin de
    /// bascule qui rend la pile du dernier fil : celui qui le recueille voit
    /// toute la mémoire rendue.
    zombie: AtomicBool,
    /// Qui attend sa fin (init, le lanceur : programmes.rs), réveillé quand
    /// il devient un zombie (le `do_notify_parent` de Linux).
    parent: Verrou<Option<Arc<Tache>>>,
    /// Le nom de son fil principal, qui se lit encore après la fin de ce fil
    /// (/proc/<pid>/comm ; Linux garde la tâche du fil principal).
    nom: Verrou<NomCourt>,
}

impl Entree {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// La fin du fil `tid` (sa tâche meurt, en lui laissant `code`) : il
    /// quitte le processus. Le dernier fil emporte le processus : son code de
    /// sortie (celui de la fin du groupe s'il y en a une, sinon le sien,
    /// mesuré sous Linux), puis sa mémoire et ses descripteurs rendus (dans
    /// la tâche qui meurt, interruptions actives : rendre des centaines de
    /// Mio prend du temps). Le processus devient un zombie plus tard, quand
    /// la pile de son dernier fil est rendue (`fil_disparu`).
    pub fn fil_termine(&self, tid: u32, code: i32) {
        let fini = {
            let mut garde = self.processus.verrouiller();
            let Some(p) = garde.as_mut() else { return };
            p.fils.retain(|f| f.tid != tid);
            if !p.fils.is_empty() {
                // Les signaux du processus qui l'attendaient vont à un
                // autre fil (`exit_signals` de Linux).
                crate::signaux::reconfier(p, u64::MAX);
                return;
            }
            self.code.store(p.fin_de_groupe.unwrap_or(code), Ordering::Relaxed);
            garde.take()
        };
        drop(fini);
    }

    /// Un fil du processus a tout à fait fini : sa pile vient d'être rendue
    /// (la fin de bascule qui suit sa mort, interruptions coupées). Au
    /// dernier, le processus est un zombie, et son parent, qui attend
    /// peut-être, est réveillé.
    pub fn fil_disparu(&self) {
        if self.vivants.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.zombie.store(true, Ordering::Relaxed);
            if let Some(parent) = self.parent.verrouiller().take() {
                crate::tache::reveiller(parent, crate::tache::Reveil::Reveillee);
            }
        }
    }

    /// Le nom de son fil principal a changé.
    pub fn renommer(&self, nom: NomCourt) {
        *self.nom.verrouiller() = nom;
    }

    /// Est-il un zombie (tous ses fils morts, tout rendu) ?
    pub fn est_zombie(&self) -> bool {
        self.zombie.load(Ordering::Relaxed)
    }

    pub fn code(&self) -> i32 {
        self.code.load(Ordering::Relaxed)
    }

    /// Le fil principal, de la tâche `t`, rejoint son processus neuf : Err
    /// si la liste ne peut pas grandir.
    pub fn attacher(&self, t: &Arc<Tache>) -> Result<(), ()> {
        let mut garde = self.processus.verrouiller();
        let p = garde.as_mut().ok_or(())?;
        p.fils.try_reserve(1).map_err(|_| ())?;
        p.fils.push(Fil::de(t));
        self.vivants.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Le fil neuf de la tâche `t`, créé par le fil `createur` (clone),
    /// rejoint le processus, avec le masque de signaux de son créateur ;
    /// sous le verrou du processus, sauf si la fin du groupe a commencé ou
    /// celle du créateur est prévue (un SIGKILL en attente : le
    /// `fatal_signal_pending` de `copy_process`) : Interrompu.
    pub fn attacher_fil(&self, t: &Arc<Tache>, createur: &Tache) -> Result<(), RefusFil> {
        let mut garde = self.processus.verrouiller();
        let p = garde.as_mut().ok_or(RefusFil::Interrompu)?;
        if p.fin_de_groupe.is_some() || createur.fin_prevue() {
            return Err(RefusFil::Interrompu);
        }
        let masque = p.fil(createur.tid()).map(|f| f.signaux.herite()).unwrap_or_default();
        p.fils.try_reserve(1).map_err(|_| RefusFil::PlusDeMemoire)?;
        let mut fil = Fil::de(t);
        fil.signaux = masque;
        p.fils.push(fil);
        self.vivants.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Le processus a-t-il d'autres fils vivants que `tid` ?
    pub fn a_d_autres_fils(&self, tid: u32) -> bool {
        self.processus.verrouiller().as_ref().is_some_and(|p| p.fils.iter().any(|f| f.tid != tid))
    }

    /// Ajoute `ns` nanosecondes au temps de calcul du processus.
    pub fn compter_calcul(&self, ns: u64) {
        self.calcul.fetch_add(ns, Ordering::Relaxed);
    }

    /// Son temps de calcul, en nanosecondes (tous ses fils).
    pub fn temps_de_calcul(&self) -> u64 {
        self.calcul.load(Ordering::Relaxed)
    }
}

/// Pourquoi un fil ne peut pas rejoindre son processus (clone).
pub enum RefusFil {
    /// La fin du groupe, ou celle du créateur, a commencé (EINTR).
    Interrompu,
    /// Plus de mémoire pour la liste des fils (ENOMEM).
    PlusDeMemoire,
}

static TABLE: Verrou<Vec<Arc<Entree>>> = Verrou::new(Vec::new());

/// Réserve la table pour `max` processus. Au démarrage.
pub fn initialiser(max: usize) {
    TABLE.verrouiller().try_reserve_exact(max).expect("plus de memoire pour la table des processus");
}

/// Range un processus neuf dans la table, sans fil encore (son fil
/// principal le rejoint à sa création, tache::lancer_programme), avec la
/// tâche courante pour parent ; None si elle est pleine (pas plus de
/// processus que de tâches).
pub fn ajouter(processus: Processus, nom: NomCourt) -> Option<Arc<Entree>> {
    let mut table = TABLE.verrouiller();
    if table.len() == table.capacity() {
        return None;
    }
    let e = Arc::new(Entree {
        pid: processus.pid,
        processus: Verrou::new(Some(processus)),
        code: AtomicI32::new(0),
        calcul: AtomicU64::new(0),
        vivants: AtomicU32::new(0),
        zombie: AtomicBool::new(false),
        parent: Verrou::new(Some(crate::tache::courante_arc())),
        nom: Verrou::new(nom),
    });
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

/// Le nom du fil principal du processus `pid`, s'il est dans la table
/// (vivant ou zombie).
pub fn nom_du_principal(pid: u32) -> Option<NomCourt> {
    TABLE.verrouiller().iter().find(|e| e.pid == pid).map(|e| *e.nom.verrouiller())
}

/// Le processus `pid` est-il dans la table (vivant ou zombie) ?
pub fn existe(pid: u32) -> bool {
    TABLE.verrouiller().iter().any(|e| e.pid == pid)
}
