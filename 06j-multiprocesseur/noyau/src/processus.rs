//! Les processus : ce que partagent les fils d'un programme Linux, et que
//! leurs appels système doivent pouvoir modifier (sa mémoire : zones,
//! tables de pages, tas ; ses descripteurs de fichiers ; son dossier
//! courant ; l'action de ses signaux). Le `signal_struct`, le `mm_struct`,
//! le `files_struct` et le `fs_struct` de Linux, en une `Entree` (la
//! mémoire sous son propre verrou, voir plus bas) ; ce qui est à chaque fil
//! est dans sa tâche (tache.rs) et dans son `Fil` (fil.rs).
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
//!
//! La MÉMOIRE du processus est à part (6i), sous un verrou qui dort, en
//! lecture et en écriture : le `mmap_lock` de Linux (`memoire_lue`,
//! `memoire_ecrite`, `servir_faute`). Avant, elle était sous le verrou du
//! processus, qui coupe les interruptions : un munmap ou un madvise de
//! centaines de Mio rendait ses pages d'un trait, les tics d'horloge se
//! perdaient, et les fautes de page de tous les fils se suivaient une à
//! une. Le reste (descripteurs, signaux, dossier courant, fils) ne tient
//! son verrou que le temps de lire ou changer un champ : il reste un
//! verrou court, comme les `siglock` et `fs->lock` de Linux. Les
//! DESCRIPTEURS (6j) ont le leur, dans l'`Entree`, le dernier de l'ordre :
//! le `file_lock` de la `files_struct` de Linux.
//!
//! L'ORDRE DES VERROUS, total depuis 6j (deux processeurs qui prennent deux
//! verrous dans deux ordres s'attendent l'un l'autre pour toujours ; un
//! seul processeur ne le pouvait pas : le premier verrou coupait les
//! interruptions, et l'autre ordre n'avait pas lieu entre-temps) :
//!   1. ceux qui dorment, jamais sous un verrou court : les verrous d'un
//!      fichier, sa position et son écriture (appels_fichiers.rs), puis la
//!      mémoire du processus (write copie sous le premier, et sa copie peut
//!      fauter, ce qui prend la mémoire) ;
//!   2. le verrou du PROCESSUS (`avec`, `avec_pid`) ;
//!   3. celui des tables de pages (memoire.rs) ;
//!   4. celui des FICHIERS (vfs.rs) : le dossier de départ d'une résolution
//!      et getcwd le prennent sous le processus, une faute dans une
//!      projection de fichier sous les tables ;
//!   5. la table des processus (TABLE), celle des tâches (tache::TOUTES) et
//!      le verrou des DESCRIPTEURS d'un processus : pris seuls ou sous les
//!      précédents, jamais l'un sous l'autre.
//! La vue de /proc, sous celui des fichiers, lisait jusqu'à 6i les
//! descripteurs d'un processus (fd/) et ses fils (task/) sous le verrou du
//! processus : l'autre ordre. Elle les lit maintenant par les verrous du
//! niveau 5 seuls (`descripteurs_du_pid`, `pour_chaque_fil`), comme Linux,
//! dont `fget_task` lit la table d'un autre processus sans son verrou (par
//! RCU) et dont /proc parcourt les fils par la liste des tâches ; `avec` et
//! `avec_pid` refusent d'être appelés sous celui des fichiers (un
//! `assert!`). La règle des copies vaut aussi pour la mémoire : une copie
//! qui faute sous elle la redemanderait (voir faute_de_page.rs).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use crate::descripteurs::{Descripteurs, LIMITE_DESCRIPTEURS};
use crate::attente::VerrouLE;
use crate::faillible::{self, VecFaillible};
use crate::fil::Fil;
use crate::memoire::{Acces, Echec, Memoire};
use crate::partage::Arc;
use crate::programmes::NomCourt;
use crate::tache::Tache;
use crate::signaux::Signaux;
use crate::verrou::Verrou;
use crate::vfs;
use fichiers::Identite;
use fichiers::montages::Objet;
use fichiers::tmpfs::Numero;

pub struct Processus {
    /// Son numéro (pid), qui est aussi celui de son fil principal et de son
    /// groupe de processus (voir `numero_neuf`).
    pub pid: u32,
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
    /// descripteurs, que garde leur table (`Descripteurs::limite`, sous le
    /// verrou des descripteurs : `regler_limite`).
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
/// dont le noyau tient le rôle tant qu'il n'y a pas de `/init` (6l) : il
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
pub const RLIMIT_SIGPENDING: usize = 11;
/// RLIM_INFINITY.
pub const INFINI: u64 = u64::MAX;

/// Les limites d'un processus neuf : celles que Linux donne au premier
/// (INIT_RLIMITS), (courante, dure). 8 Mio de pile (la glibc la lit pour
/// la pile de ses fils ; elle grandit bien jusque-là, memoire.rs,
/// PILE_MAX), pas de fichier « core », 8 Mio de mémoire verrouillable, 800
/// Kio de files de messages, 1024 descripteurs (4096 au plus), infini pour
/// le reste. SIGPENDING : comme Linux, la moitié de max_threads, pour la
/// courante et la dure (`fork_init`), depuis que les signaux ont une file
/// (6f) ; NPROC aussi chez Linux, infini ici : max_threads borne déjà les
/// fils (6e).
///
/// Seules celles des descripteurs, du temps de calcul (RLIMIT_CPU, infini
/// par défaut comme chez Linux : voir tache::verifier_au_retour), du
/// nombre de tâches (RLIMIT_NPROC, tache::lancer_fil) et des signaux en
/// file (RLIMIT_SIGPENDING, signaux.rs) sont appliquées ; les autres sont
/// rendues telles qu'on les a posées, comme le demandent les programmes qui
/// les baissent par prudence (pas de « core », une pile plus petite). Les
/// appliquer viendra avec ce qu'elles limitent.
pub fn limites_par_defaut() -> [(u64, u64); LIMITES] {
    let mut l = [(INFINI, INFINI); LIMITES];
    l[RLIMIT_STACK] = (8 << 20, INFINI);
    l[4] = (0, INFINI); // RLIMIT_CORE
    l[RLIMIT_NOFILE] = LIMITE_DESCRIPTEURS;
    l[8] = (8 << 20, 8 << 20); // RLIMIT_MEMLOCK
    let signaux = (crate::vmalloc::max_threads() / 2) as u64;
    l[RLIMIT_SIGPENDING] = (signaux, signaux);
    l[12] = (819_200, 819_200); // RLIMIT_MSGQUEUE
    l[13] = (0, 0); // RLIMIT_NICE
    l[14] = (0, 0); // RLIMIT_RTPRIO
    l
}

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

    /// La limite `ressource` (sous LIMITES), sauf celle des descripteurs,
    /// qui vit avec leur table sous leur verrou (`regler_limite` les sert
    /// toutes).
    pub fn limite(&self, ressource: usize) -> (u64, u64) {
        assert!(ressource != RLIMIT_NOFILE, "la limite des descripteurs est avec leur table");
        self.limites[ressource]
    }

    pub fn changer_limite(&mut self, ressource: usize, limite: (u64, u64)) {
        assert!(ressource != RLIMIT_NOFILE, "la limite des descripteurs est avec leur table");
        self.limites[ressource] = limite;
    }
}

impl Drop for Processus {
    /// La fin d'un processus : son dossier courant et sa racine lâchés (le
    /// `exit_fs` de Linux). Sa mémoire et ses descripteurs, à part, se
    /// rendent d'eux-mêmes juste avant (`fil_termine`).
    fn drop(&mut self) {
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
    /// Ses descripteurs de fichiers (la `files_struct` de Linux,
    /// descripteurs.rs), sous leur propre verrou (le `file_lock`), le
    /// dernier de l'ordre (voir l'en-tête) : un appel qui tient un fichier
    /// par son numéro le prend sous celui des fichiers
    /// (appels_fichiers::tenir), et la vue de /proc lit fd/ par lui, sans
    /// le verrou du processus. Vide une fois le dernier fil mort
    /// (`fil_termine`) : un zombie n'a plus de descripteur, comme chez
    /// Linux.
    descripteurs: Verrou<Descripteurs>,
    /// Sa mémoire (la mm_struct de Linux, memoire.rs), sous son verrou qui
    /// dort, en lecture et en écriture (le `mmap_lock`, voir l'en-tête).
    /// None une fois son dernier fil mort, comme `processus`.
    memoire: VerrouLE<Option<Memoire>>,
    /// Les processeurs qui ont chargé l'espace de sa mémoire (le
    /// `mm_cpumask` de Linux), partagé avec elle (espace_utilisateur.rs) :
    /// ici, lisible sans le verrou qui dort, pour la bascule (tache.rs,
    /// `charger_espace`), qui met et retire le bit de son processeur.
    processeurs: Arc<crate::espace_utilisateur::MasqueProcesseurs>,
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
    /// Ce que ses fils morts ont consommé, pour getrusage (rusage.rs).
    usage: crate::rusage::DuProcessus,
    /// Ce qu'en montre /proc sans le verrou du processus (procfs.rs) : à
    /// qui il est (le propriétaire de /proc/<pid>, même zombie), quand il a
    /// été lancé (les dates de ses entrées), son exécutable
    /// (/proc/<pid>/exe) : le chemin canonique et l'inode, que le lanceur
    /// tient jusqu'au recueil.
    identite: Identite,
    lance: fichiers::Temps,
    exe: Verrou<(Vec<u8>, Option<Numero>)>,
}

impl Entree {
    /// Les processeurs qui ont chargé son espace (voir le champ).
    pub fn processeurs(&self) -> &crate::espace_utilisateur::MasqueProcesseurs {
        &self.processeurs
    }

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
        // La mémoire d'abord, puis les descripteurs, puis le dossier courant
        // et la racine (`fini`), comme Linux (`exit_mm`, `exit_files`,
        // `exit_fs`), chacun rendu hors de tout verrou : interruptions
        // actives. Prendre la mémoire en écriture attend un lecteur de
        // /proc/<pid>/maps qui la lirait encore. La table des descripteurs
        // est sortie de son verrou (une table vide reste, pour un lecteur de
        // /proc/<pid>/fd), puis fermée (`Descripteurs::drop`), ce qui prend
        // celui des fichiers une fois par descripteur.
        // UNIPROCESSEUR : Linux ne prend pas le mmap_lock pour la défaire
        // (`exit_mmap`, quand plus personne ne la tient : `mmput`) ; sur un
        // seul processeur, l'écriture ne fait attendre personne de plus. En
        // 6j.
        let memoire = self.memoire.ecrire().take();
        drop(memoire);
        let descripteurs = core::mem::take(&mut *self.descripteurs.verrouiller());
        drop(descripteurs);
        drop(fini);
    }

    /// Un fil du processus a tout à fait fini : sa pile vient d'être rendue
    /// (la fin de bascule qui suit sa mort, interruptions coupées). Au
    /// dernier, le processus est un zombie, et son parent, qui attend
    /// peut-être, est réveillé.
    pub fn fil_disparu(&self) {
        // Le motif de notre Arc (partage.rs) : chaque fil qui disparaît
        // publie ce qu'il a fait (sa pile rendue) par un Release, et le
        // dernier, qui voit 1, acquiert tout cela par une barrière Acquire
        // avant de poser « zombie » : « zombie » publie alors les piles de
        // TOUS les fils, pas du seul dernier (« memoire rendue » le compte).
        if self.vivants.fetch_sub(1, Ordering::Release) == 1 {
            core::sync::atomic::fence(Ordering::Acquire);
            // Release : le code de sortie et tout le reste sont écrits
            // avant ; le réveil qui suit porte la barrière complète du motif
            // de Dekker (tache::reveiller), et `est_zombie` lit en SeqCst.
            self.zombie.store(true, Ordering::Release);
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
        // SeqCst (un `mov` sur x86) : une condition de sommeil du lanceur,
        // lue sans verrou après « je vais dormir » (voir `Tache::est_morte`).
        self.zombie.load(Ordering::SeqCst)
    }

    pub fn code(&self) -> i32 {
        self.code.load(Ordering::Relaxed)
    }

    /// Le fil principal, de la tâche `t`, rejoint son processus neuf : Err
    /// si la liste ne peut pas grandir.
    pub fn attacher(&self, t: &Arc<Tache>) -> Result<(), ()> {
        let mut garde = self.processus.verrouiller();
        let p = garde.as_mut().ok_or(())?;
        p.fils.ajouter(Fil::de(t)).map_err(|_| ())?;
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
        let mut fil = Fil::de(t);
        fil.signaux = masque;
        p.fils.ajouter(fil).map_err(|_| RefusFil::PlusDeMemoire)?;
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

    /// Ce que ses fils morts ont consommé (getrusage).
    pub fn usage(&self) -> &crate::rusage::DuProcessus {
        &self.usage
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

/// Range un processus neuf dans la table, avec ses descripteurs, sans fil
/// encore (son fil principal le rejoint à sa création,
/// tache::lancer_programme), avec la tâche courante pour parent ; None si
/// elle est pleine (pas plus de processus que de tâches), ou le tas. Un
/// processus refusé est rendu (ses descripteurs fermés, son dossier lâché :
/// le verrou des fichiers) une fois la table rendue : `e` est déclaré avant
/// `table`, donc détruit après.
pub fn ajouter(processus: Processus, descripteurs: Descripteurs, mut memoire: Memoire, nom: NomCourt) -> Option<Arc<Entree>> {
    let identite = processus.identite;
    let processeurs = memoire.processeurs();
    let e = Arc::new(Entree {
        pid: processus.pid,
        processus: Verrou::new(Some(processus)),
        descripteurs: Verrou::new(descripteurs),
        memoire: VerrouLE::new(Some(memoire)),
        processeurs,
        code: AtomicI32::new(0),
        calcul: AtomicU64::new(0),
        vivants: AtomicU32::new(0),
        zombie: AtomicBool::new(false),
        parent: Verrou::new(Some(crate::tache::courante_arc())),
        nom: Verrou::new(nom),
        usage: crate::rusage::DuProcessus::new(),
        identite,
        lance: crate::temps::maintenant(),
        exe: Verrou::new((Vec::new(), None)),
    }).ok()?;
    let mut table = TABLE.verrouiller();
    if table.len() == table.capacity() {
        return None;
    }
    table.ajouter_dans_la_place(e.clone());
    Some(e)
}

/// L'exécutable du processus `pid` (/proc/<pid>/exe) : son chemin
/// canonique, son inode.
pub fn poser_exe(pid: u32, chemin: Vec<u8>, inode: Numero) {
    if let Some(e) = entree(pid) {
        *e.exe.verrouiller() = (chemin, Some(inode));
    }
}

/// L'entrée du processus `pid` (vivant ou zombie).
fn entree(pid: u32) -> Option<Arc<Entree>> {
    TABLE.verrouiller().iter().find(|e| e.pid == pid).cloned()
}

/// Ce que /proc montre d'un processus : son identité, quand il a été lancé,
/// s'il est un zombie.
pub fn vu_de_proc(pid: u32) -> Option<(Identite, fichiers::Temps, bool)> {
    TABLE.verrouiller().iter().find(|e| e.pid == pid).map(|e| (e.identite, e.lance, e.est_zombie()))
}

/// Le nombre de processus de la table, vivants et zombies (ceux que liste
/// /proc).
pub fn nombre() -> u32 {
    TABLE.verrouiller().len() as u32
}

/// L'inode de son exécutable ; None pour un zombie, qui n'a plus de
/// mémoire (Linux le trouve par elle, `get_task_exe_file` : ENOENT).
pub fn exe(pid: u32) -> Option<Numero> {
    let e = entree(pid).filter(|e| !e.est_zombie())?;
    let exe = e.exe.verrouiller();
    exe.1
}

/// Une copie du chemin de son exécutable (vide sans mémoire) ; None pour
/// un zombie.
pub fn chemin_exe(pid: u32) -> Option<Vec<u8>> {
    let e = entree(pid).filter(|e| !e.est_zombie())?;
    let exe = e.exe.verrouiller();
    Some(faillible::copie(&exe.0).unwrap_or_default())
}

/// Le plus petit numéro de processus de la table (vivant ou zombie) à partir
/// de `depuis` : pour lister /proc dans l'ordre (la table ne l'est pas).
pub fn pid_suivant(depuis: u32) -> Option<u32> {
    TABLE.verrouiller().iter().map(|e| e.pid).filter(|&p| p >= depuis).min()
}

/// Les fils vivants du processus `pid`, dans un ordre quelconque, pour
/// /proc/<pid>/task (procfs.rs les trie). Par la table des tâches, sans le
/// verrou du processus : la vue de /proc appelle sous celui des fichiers
/// (l'ordre de l'en-tête), et Linux aussi parcourt les fils d'un processus
/// par ses tâches (`next_tid`, sous RCU). Un fil y reste un instant de plus
/// que dans la liste du processus (de `fil_termine` à la fin de
/// `tache::terminer`), ce que linux/proc attend.
pub fn pour_chaque_fil(pid: u32, mut f: impl FnMut(u32)) {
    crate::tache::pour_chaque(|t| {
        if t.processus().is_some_and(|e| e.pid == pid) {
            f(t.tid());
        }
    });
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
/// pas toucher à la mémoire du programme par ses adresses. Jamais sous le
/// verrou des fichiers (l'ordre de l'en-tête).
#[track_caller]
pub fn avec<R>(f: impl FnOnce(&mut Processus) -> R) -> R {
    essayer_avec(f).expect("appel systeme sans processus en cours")
}

/// Comme `avec`, si la tâche courante a un processus vivant : une faute de
/// page du noyau peut arriver sans lui (le test du démarrage, dans
/// main.rs, une tâche du noyau).
#[track_caller]
pub fn essayer_avec<R>(f: impl FnOnce(&mut Processus) -> R) -> Option<R> {
    if !crate::tache::en_service() {
        return None;
    }
    let e = crate::tache::courante().processus()?;
    assert!(!vfs::tenu_ici(), "verrou d'un processus pris sous celui des fichiers");
    let mut p = e.processus.verrouiller();
    p.as_mut().map(f)
}

/// Exécute `f` sur le processus `pid`, s'il est dans la table et vivant
/// (pas un zombie). None sinon. Jamais sous le verrou des fichiers.
#[track_caller]
pub fn avec_pid<R>(pid: u32, f: impl FnOnce(&mut Processus) -> R) -> Option<R> {
    let e = entree(pid)?;
    assert!(!vfs::tenu_ici(), "verrou d'un processus pris sous celui des fichiers");
    let mut p = e.processus.verrouiller();
    p.as_mut().map(f)
}

/// Exécute `f` sur la table des descripteurs du processus de la tâche
/// courante, verrou tenu : court. Le dernier verrou de l'ordre : il se
/// prend sous celui du processus (le dossier de départ d'un appel *at)
/// comme sous celui des fichiers (appels_fichiers::tenir), jamais
/// l'inverse.
#[track_caller]
pub fn descripteurs<R>(f: impl FnOnce(&mut Descripteurs) -> R) -> R {
    let e = crate::tache::courante().processus().expect("appel systeme sans processus en cours");
    let mut d = e.descripteurs.verrouiller();
    f(&mut d)
}

/// Comme `descripteurs`, pour le processus `pid` (/proc/<pid>/fd, sous le
/// verrou des fichiers) : None s'il n'est pas dans la table ; la table
/// d'un zombie est vide.
pub fn descripteurs_du_pid<R>(pid: u32, f: impl FnOnce(&mut Descripteurs) -> R) -> Option<R> {
    let e = entree(pid)?;
    let mut d = e.descripteurs.verrouiller();
    Some(f(&mut d))
}

/// prlimit64 : la limite `ressource` du processus courant, qui devient
/// `regle` si elle est donnée ; rend l'ancienne, ou Err si la dure serait
/// relevée sans être root (CAP_SYS_RESOURCE). Celle des descripteurs
/// (RLIMIT_NOFILE) vit avec leur table, sous le verrou des descripteurs,
/// que `reserver` tient déjà quand il la lit ; les autres sous celui du
/// processus. (Linux la lit sans verrou, `rlimit`, un READ_ONCE.)
pub fn regler_limite(ressource: usize, regle: Option<(u64, u64)>) -> Result<(u64, u64), ()> {
    let root = avec(|p| p.identite.root());
    let changer = |limite: &mut (u64, u64)| {
        let avant = *limite;
        if let Some(l) = regle {
            if l.1 > avant.1 && !root {
                return Err(());
            }
            *limite = l;
        }
        Ok(avant)
    };
    if ressource == RLIMIT_NOFILE {
        descripteurs(|d| changer(&mut d.limite))
    } else {
        avec(|p| changer(&mut p.limites[ressource]))
    }
}

/// La garde de la mémoire de son processus que tient (ou attend) la tâche
/// courante : elle le note dans sa tâche (`Tache::tient_sa_memoire`), pour
/// qu'une copie faite dessous soit reconnue (copie_utilisateur.rs) au lieu
/// de s'endormir pour toujours derrière elle-même ; pour refuser de la
/// reprendre (pas de prise récursive : derrière un écrivain qui attend, un
/// second `lire` de la même tâche attendrait sans fin, phase-fair oblige) ;
/// et pour que le détecteur d'interblocage voie un programme qui l'attend
/// alors que plus rien n'est prêt (attente.rs).
struct Tenue;

impl Tenue {
    #[track_caller]
    fn prendre() -> Tenue {
        let t = crate::tache::courante();
        assert!(!t.tient_sa_memoire(), "memoire du processus reprise par la tache qui la tient");
        t.tenir_sa_memoire(true);
        Tenue
    }
}

impl Drop for Tenue {
    fn drop(&mut self) {
        crate::tache::courante().tenir_sa_memoire(false);
    }
}

/// La mémoire du processus de la tâche courante, tenue en LECTURE le temps
/// de `f` (le `mmap_read_lock` de Linux) : les fautes de page, /proc, ce
/// qui lit les zones. Peut dormir (jamais sous un verrou court), ne coupe
/// pas les interruptions ; `f` ne copie rien depuis ou vers le programme.
#[track_caller]
pub fn memoire_lue<R>(f: impl FnOnce(&Memoire) -> R) -> R {
    let e = crate::tache::courante().processus().expect("memoire d'un processus sans processus").clone();
    let _tenue = Tenue::prendre();
    let m = e.memoire.lire();
    f(m.as_ref().expect("memoire d'un processus mort"))
}

/// La mémoire du processus de la tâche courante, tenue en ÉCRITURE le
/// temps de `f` (le `mmap_write_lock`) : mmap, munmap, mprotect, brk,
/// madvise. Mêmes règles que `memoire_lue`.
#[track_caller]
pub fn memoire_ecrite<R>(f: impl FnOnce(&mut Memoire) -> R) -> R {
    let e = crate::tache::courante().processus().expect("memoire d'un processus sans processus").clone();
    let _tenue = Tenue::prendre();
    let mut m = e.memoire.ecrire();
    f(m.as_mut().expect("memoire d'un processus mort"))
}

/// La mémoire du processus `pid` (vivant), en lecture le temps de `f` :
/// /proc/<pid>/maps et statm. None pour un zombie ou un inconnu.
#[track_caller]
pub fn memoire_du_pid<R>(pid: u32, f: impl FnOnce(&Memoire) -> R) -> Option<R> {
    let e = TABLE.verrouiller().iter().find(|e| e.pid == pid)?.clone();
    let _tenue = Tenue::prendre();
    let m = e.memoire.lire();
    m.as_ref().map(f)
}

/// Sert une faute de page à `adresse` pour la tâche courante : le
/// `lock_mm_and_find_vma` de Linux 6.18, puis `handle_mm_fault`. La mémoire
/// en lecture ; si l'adresse n'est dans aucune zone mais juste sous la
/// pile, il faut l'étendre, ce qui change la carte : la lecture est rendue,
/// l'écriture prise, la pile étendue (tout est revérifié : un autre fil a
/// pu changer la carte entre les deux), puis l'écriture RÉTROGRADÉE en
/// lecture pour servir la page. Linux faisait autrefois grandir la pile en
/// lecture, sous un verrou à part ; deux fautes à la fois pouvaient alors
/// corrompre la carte (StackRot, CVE-2023-3269, corrigée ainsi dans 6.5).
/// Sans processus (une tâche du noyau) : None.
pub fn servir_faute(adresse: u64, acces: Acces) -> Option<Result<(), Echec>> {
    let e = crate::tache::courante().processus()?.clone();
    let _tenue = Tenue::prendre();
    let lu = e.memoire.lire();
    let m = lu.as_ref()?;
    if m.zones.trouver(adresse).is_some() || !m.pile_au_dessus(adresse) {
        return Some(m.servir(adresse, acces));
    }
    drop(lu);
    let mut ecrit = e.memoire.ecrire();
    if !ecrit.as_mut()?.etendre_pile(adresse) {
        return Some(Err(Echec::SansZone));
    }
    let lu = ecrit.retrograder();
    Some(lu.as_ref()?.servir(adresse, acces))
}

/// Le fichier ouvert du descripteur `fd` du processus `pid`
/// (/proc/<pid>/fd, sous le verrou des fichiers : par celui des
/// descripteurs seul, jamais celui du processus).
pub fn descripteur(pid: u32, fd: u64) -> Option<crate::descripteurs::Fichier> {
    descripteurs_du_pid(pid, |d| d.get(fd).map(|d| d.fichier)).flatten()
}

/// Le plus petit descripteur ouvert du processus `pid` à partir de `depuis`.
pub fn descripteur_suivant(pid: u32, depuis: u64) -> Option<u64> {
    descripteurs_du_pid(pid, |d| d.ouverts(depuis, u64::MAX).next()).flatten()
}

/// Le nombre de descripteurs ouverts du processus `pid`.
pub fn nombre_de_descripteurs(pid: u32) -> u64 {
    descripteurs_du_pid(pid, |d| d.ouverts(0, u64::MAX).count() as u64).unwrap_or(0)
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
