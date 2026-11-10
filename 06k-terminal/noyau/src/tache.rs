//! Les tâches : le noyau, et les programmes qu'il exécute.
//!
//! Un programme ne s'exécute pas « dans » une fonction du noyau qui
//! l'appellerait : c'est une TÂCHE à part, avec sa propre pile noyau (celle
//! que prend le processeur quand le programme entre dans le noyau, par un
//! appel système ou une interruption) et son propre état des registres.
//! Le noyau a aussi les siennes : la tâche inactive (le `noyau_main` du
//! démarrage, sur la pile du démarrage), init (le lanceur de
//! /etc/demarrage, programmes.rs), une par programme WebAssembly
//! (l'interpréteur tourne dans sa tâche). Chaque tâche, sauf l'inactive, a
//! sa pile de 16 Kio dans la région vmalloc, sous une page de garde
//! (vmalloc.rs). On passe le processeur d'une tâche à l'autre en BASCULANT
//! (`basculer_vers`, le `__switch_to` de Linux), interruptions coupées :
//!   1. ce que les registres généraux ne disent pas, mais que le programme
//!      a pu changer : l'état x87, SSE et AVX (XSAVE, ou FXSAVE : sse.rs),
//!      les sélecteurs de
//!      segments et la base de FS (arch_prctl), sauvés pour l'ancienne
//!      tâche si c'est un programme, et rétablis pour la nouvelle ; le
//!      noyau, lui, ne s'en sert jamais (il est compilé sans SSE) ;
//!   2. l'espace d'adressage (CR3), s'il change : toute tâche du noyau
//!      tourne sur la PML4 du noyau, sans garder celle du programme
//!      précédent (pas de « lazy TLB », qui demanderait de compter qui se
//!      sert encore d'un espace) ;
//!   3. la pile que prendra le processeur à la prochaine entrée depuis
//!      l'anneau 3 (TSS.rsp0) : le sommet de celle de la nouvelle tâche ;
//!   4. l'échange des piles (`basculer`, le __switch_to_asm de Linux) :
//!      empiler les registres que l'ABI dit « préservés par l'appelé »
//!      (rbx, rbp, r12 à r15 : l'appelant de `basculer` a déjà sauvé les
//!      autres s'il en avait besoin), ranger RSP dans le contexte de
//!      l'ancienne, prendre celui de la nouvelle, dépiler ses registres,
//!      et `ret` : on revient là où la nouvelle avait elle-même basculé ;
//!   5. la FIN DE BASCULE, dans la nouvelle tâche : si l'ancienne est
//!      morte, la confier au rendeur (`fin_de_bascule`), avec la référence
//!      qu'elle gardait sur elle-même pour cela ; il rendra sa pile
//!      interruptions actives (une tâche ne peut pas rendre la pile sur
//!      laquelle elle s'exécute ; jusqu'à 6i, c'est la suivante qui la
//!      rendait, ici même : le `finish_task_switch` de Linux).
//! Tout l'état d'une tâche suspendue tient donc dans sa pile, et son
//! contexte n'est que l'adresse de son sommet.
//!
//! Une tâche neuve n'a jamais basculé : on lui prépare une pile qui y
//! ressemble (six registres, puis l'adresse de son premier départ), qui
//! commence par la fin de bascule, comme le `schedule_tail` de Linux. Pour
//! un programme, au-dessus, le cadre complet d'un retour vers l'anneau 3
//! (le pt_regs, comme pour fork dans Linux) : `premier_depart` passe par
//! le retour ordinaire des interruptions (iretq), et le programme démarre
//! à son point d'entrée, tous registres à zéro, sur sa pile. Pour une
//! tâche du noyau, `depart_noyau` appelle sa fonction, rangée dans r12.
//!
//! Les tâches prêtes se partagent le processeur (ordonnanceur.rs) ; une
//! tâche qui en a créé d'autres (init, qui lance les programmes) dort
//! jusqu'à ce que l'une d'elles finisse (`attendre`, `dormir_tant_que`),
//! ou, pour un programme Linux, jusqu'à ce que son processus en ait fini
//! avec son dernier fil (processus::Entree::est_zombie).
//!
//! Une tâche de programme Linux est un FIL de son processus : ce qui est à
//! chacun (son numéro, son nom, ses registres, son temps de calcul, sa fin
//! prévue) est ici ; ce que partagent les fils, dans le processus
//! (processus.rs) ; leurs signaux, dans le `Fil` de chacun (fil.rs).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::attente::EntreeAttente;
use crate::faillible::{self, VecFaillible};
use crate::interruptions::Cadre;
use crate::linux::{self, Signal};
use crate::partage::Arc;
use crate::programmes::NomCourt;
use crate::verrou::Verrou;
use crate::vmalloc::Pile;
use crate::{cpu, gdt, ordonnanceur, pagination, processeur, processus, signaux};

global_asm!(
    r#"
    .section .text
    /* basculer(ancien : *mut u64 (rdi), nouveau : *const u64 (rsi),
       tache_ancienne : *const Tache (rdx)) -> *const Tache (rax) : la tâche
       qu'on quitte est rendue à celle qui reprend (dans rax, que rien ne
       touche entre les deux), pour sa fin de bascule : c'est le `prev` que
       `__switch_to_asm` passe à `schedule_tail` chez Linux. */
    .global basculer
basculer:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, [rsi]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    mov rax, rdx
    ret

    /* Le premier départ d'un fil de programme : la fin de bascule, puis la
       base de GS du programme à 0 (le MSR KERNEL_GS_BASE : dans le noyau,
       c'est l'inactive, que swapgs rendra active au retour vers l'anneau
       3 ; GS_BASE, l'active, est la zone du processeur, processeur.rs : on
       n'y touche pas), pour qu'un programme ne trouve rien d'un précédent
       (les sélecteurs, la base de FS et l'état x87/SSE, eux, sont ceux de
       sa tâche, rétablis par basculer_vers ; un programme ne peut pas
       changer la base de GS, arch_prctl la refuse). Puis `debut_de_fil`,
       la sortie ordinaire vers l'anneau 3 (le `ret_from_fork` de Linux),
       et le retour d'interruption : iretq vers le cadre préparé par
       executer() ou par clone. */
    .global premier_depart
premier_depart:
    mov rdi, rax
    call fin_de_bascule
    xor eax, eax
    xor edx, edx
    mov ecx, 0xC0000102
    wrmsr
    call debut_de_fil
    jmp retour_interruption

    /* Le premier départ d'une tâche du noyau : la fin de bascule, puis sa
       fonction, dont l'adresse est dans r12 (rétabli par basculer). Elle
       ne revient pas. Interruptions actives : une tâche du noyau s'exécute
       comme un appel système (et comme sous Linux, après schedule_tail).
       Donc jamais avant que les interruptions soient prêtes (main.rs) :
       le 8259 du BIOS enverrait l'horloge sur le vecteur de la double
       faute. */
    .global depart_noyau
depart_noyau:
    mov rdi, rax
    call fin_de_bascule
    sti
    mov rdi, r12
    call tache_noyau
    ud2

    /* L'état x87 et SSE d'un programme qui démarre, au format de fxsave
       (512 octets, alignés sur 16) : mot de contrôle x87 0x037F (toutes
       les exceptions masquées, double précision étendue, arrondi au plus
       près : l'état de `fninit`), MXCSR 0x1F80 (la valeur de l'ABI), et
       tout le reste à zéro : registres ST0-ST7 (alias MM0-MM7), XMM0-XMM15,
       mot d'état, étiquettes (voir sse.rs). */
    .section .rodata
    .balign 16
    .global etat_fpu_initial
etat_fpu_initial:
    .word 0x037F
    .skip 22
    .long 0x1F80
    .skip 512 - 28
    "#
);

unsafe extern "C" {
    // La tâche quittée passe et revient en pointeur opaque : `Tache` n'a pas
    // de disposition C, l'assembleur ne fait que la transporter.
    fn basculer(ancien: *mut u64, nouveau: *const u64, tache_ancienne: *const core::ffi::c_void) -> *const core::ffi::c_void;
    fn premier_depart();
    fn depart_noyau();
    static etat_fpu_initial: EtatFpu;
}

/// L'état x87 et SSE initial d'un programme, au format de FXSAVE.
#[repr(C, align(16))]
pub struct EtatFpu([u8; 512]);

/// Ce que le noyau sait d'une tâche.
pub struct Tache {
    /// Son numéro de fil (le tid), pour un programme Linux : celui de son
    /// processus pour le fil principal. 0 pour une tâche du noyau (les
    /// programmes ne la voient pas).
    tid: u32,
    /// La tâche inactive d'un processeur (celle qui prend le processeur
    /// quand aucune autre n'est prête) : elle n'entre jamais dans une file
    /// des prêtes ni dans la table des tâches, et n'attend personne.
    inactive: bool,
    /// Son nom, pour les messages : celui du programme (le `comm` de
    /// Linux), ou celui de la tâche du noyau.
    nom: Verrou<NomCourt>,
    /// Le RSP rangé par `basculer` quand elle ne s'exécute pas. Lu et écrit
    /// seulement par `basculer_vers`, interruptions coupées, sur un seul
    /// processeur.
    contexte: UnsafeCell<u64>,
    /// Sa pile noyau, rendue par la fin de bascule qui suit sa mort (la
    /// tâche inactive n'en a pas : elle garde la pile du démarrage).
    pile: Verrou<Option<Pile>>,
    /// Le sommet de sa pile (pour TSS.rsp0).
    haut: u64,
    /// L'espace d'adressage où elle s'exécute (la PML4, pour CR3) : celui
    /// du noyau pour une tâche du noyau, et pour un programme qui meurt
    /// (avant de rendre le sien, `terminer`).
    espace: AtomicU64,
    /// Son processus, pour un programme Linux (processus.rs), qu'elle tient :
    /// il vit tant qu'il a un fil, puis en zombie.
    processus: Option<Arc<crate::processus::Entree>>,
    /// Pour un programme : son état x87/SSE, ses sélecteurs (DS, ES, FS,
    /// GS) et sa base de FS, quand il ne s'exécute pas.
    programme: Option<UnsafeCell<EtatProgramme>>,
    /// Elle s'est terminée : sa pile est à rendre. Un état publié
    /// (Release dans `terminer`, lu SeqCst par `est_morte` : voir là).
    morte: AtomicBool,
    /// Elle s'exécute sur un processeur, ou n'a pas fini de le quitter (le
    /// `on_cpu` de Linux) : posé SOUS le verrou de la file des prêtes par
    /// `ordonnancer`, pour la tâche qu'il choisit, AVANT de basculer ; remis
    /// à faux par la tâche suivante, première chose de sa fin de bascule
    /// (`fin_de_bascule`, le `finish_task`), en Release. Qui veut mettre
    /// cette tâche dans une file (un réveil) ou l'en tirer (un autre
    /// processeur, 6j) attend qu'il soit faux : elle est encore sur une pile
    /// qu'un autre processeur exécute.
    sur_processeur: AtomicBool,
    /// Elle est dans une file des prêtes (le `on_rq`) : écrit sous le verrou
    /// de cette file (`File::ajouter`, `retirer`), lu sous lui.
    en_file: AtomicBool,
    /// Le processeur dont la file la tient, ou la tenait en dernier (le
    /// `task_cpu`) : écrit sous le verrou de cette file.
    processeur: AtomicU32,
    /// Les processeurs où elle a le droit de s'exécuter (le `cpus_mask` de
    /// Linux), un bit par numéro : tous (u64::MAX) pour une tâche née du
    /// noyau, ceux de son créateur pour un fil (sched_setaffinity, linux.rs,
    /// les pose tels quels, bits des processeurs absents compris ; avec les
    /// processeurs en service, c'est le masque que rend sched_getaffinity).
    /// Lu pour sa valeur seule (Relaxed) ; honoré par le placement des
    /// tâches (6j, la file des prêtes par processeur).
    affinite: AtomicU64,
    /// Une tâche du noyau qui exécute un programme WebAssembly (6h) : ses
    /// minuteries comptent pour le détecteur d'interblocage comme celles
    /// d'un programme Linux (attente.rs).
    webassembly: AtomicBool,
    /// Pour un fil créé avec CLONE_CHILD_SETTID : l'adresse où il écrit son
    /// numéro à son premier départ (le `set_child_tid` de Linux), 0 sinon.
    ecrire_tid: AtomicU64,
    /// L'adresse où effacer son numéro à sa fin, puis réveiller qui y attend
    /// (CLONE_CHILD_CLEARTID, set_tid_address : le `clear_child_tid` de
    /// Linux, ce qu'attend `pthread_join`), 0 sinon.
    effacer_tid: AtomicU64,
    /// La tête de sa liste de verrous robustes (set_robust_list), 0 sinon
    /// (futex.rs).
    liste_robuste: AtomicU64,
    /// Son code de sortie, posé par `terminer`.
    code_sortie: AtomicI32,
    /// Les cases de son tube interne, celui de sendfile et copy_file_range
    /// vers autre chose qu'un tube (le `splice_pipe` de Linux, 6i : voir
    /// `tube::cases_du_tube_interne`), 0 tant qu'elle n'en a pas eu besoin.
    pub tube_interne: AtomicU32,
    /// Son temps de calcul, en nanosecondes : compté par l'ordonnanceur à
    /// chaque tic et à chaque bascule, d'après le temps monotone (le TSC
    /// quand il est fiable : le `sum_exec_runtime` de Linux), en anneau 3
    /// ou dans le noyau pour elle. Atomique : le gestionnaire d'horloge le
    /// compte sans prendre de verrou ; un compteur, lu pour sa valeur seule
    /// (Relaxed).
    calcul: AtomicU64,
    /// Son retard (positif) ou son avance (négative) sur la moyenne des
    /// temps virtuels quand elle a quitté la file des prêtes (ordonnanceur.rs),
    /// retrouvé à son réveil.
    lag: AtomicI64,
    /// Pour une tâche du noyau, celle qui l'a créée, réveillée par
    /// `terminer` (elle attend sa fin, ou celle de l'une de ses tâches :
    /// `attendre`, `dormir_tant_que`) ; None pour l'inactive. Un fil de
    /// programme n'en a pas : c'est la fin de son processus qui réveille son
    /// parent (processus::Entree::fil_disparu).
    attendant: Verrou<Option<Arc<Tache>>>,
    /// Son entrée de file d'attente, celle qu'elle inscrit dans la file de ce
    /// qu'elle attend (attente.rs) : une tâche n'attend qu'une chose à la
    /// fois. Dans la tâche, elle ne bouge jamais (une tâche ne quitte pas son
    /// Arc).
    entree_attente: EntreeAttente,
    /// Son état, UN SEUL mot (le `__state` de Linux ; les valeurs : le
    /// module `etat`) : « en cours », « va dormir » (interruptible ou non),
    /// la raison de son réveil, ou « morte ». C'est le mot que se partagent
    /// celle qui s'endort et celui qui la réveille (attente.rs) : posé en
    /// SeqCst par la tâche AVANT qu'elle vérifie ce qu'elle attend, changé
    /// par un compare_exchange de qui la réveille. Jusqu'à 6i, deux mots
    /// (`reveil` et `interruptible`), dont le second était posé après le
    /// test des signaux : un signal envoyé entre les deux pouvait être perdu
    /// sur deux processeurs.
    etat: AtomicU8,
    /// Le futex qu'elle attend (futex.rs) : écrit par elle, et par un
    /// FUTEX_REQUEUE d'un autre fil (sous le verrou du seau où elle attend),
    /// lu par elle sans ce verrou : d'où un verrou court à lui.
    futex: Verrou<Option<crate::futex::Attente>>,
    /// Elle tient la mémoire de son processus, en lecture ou en écriture
    /// (processus::memoire_lue, memoire_ecrite, servir_faute) : une faute
    /// d'une copie du noyau ne peut pas la redemander (faute_de_page.rs).
    tient_sa_memoire: AtomicBool,
    /// Une faute de page du noyau, dans une copie depuis ou vers son
    /// programme, ne doit pas être servie : la copie échoue (la lecture
    /// d'un futex sous le verrou de son seau, futex.rs ; le
    /// `pagefault_disable` de Linux).
    sans_faute: AtomicBool,
    /// Un tic a été compté depuis la dernière vérification de RLIMIT_CPU.
    temps_a_verifier: AtomicBool,
    /// À tuer, faute de mémoire, dès son retour vers l'anneau 3 : une page
    /// lui a manqué pendant une copie du noyau (un appel système qui écrit
    /// dans sa mémoire). L'appel ne peut pas s'arrêter au milieu de ce
    /// qu'il fait : il rend EFAULT, et le programme est tué au retour
    /// (Linux lui envoie de même un SIGKILL, délivré au retour).
    a_tuer: AtomicBool,
    /// Sa fin prévue (voir `Fin`).
    fin: Verrou<Option<Fin>>,
    /// Ce qu'elle a consommé, pour getrusage (rusage.rs) : ses tics en
    /// anneau 3 et dans le noyau, ses fautes de page, ses bascules.
    usage: crate::rusage::Compteurs,
    /// Le dernier partage de son temps entre anneau 3 et noyau rendu par
    /// getrusage(RUSAGE_THREAD).
    precedent: crate::rusage::Precedent,
    /// Sa dernière exception qui a donné un signal : le vecteur, le code
    /// d'erreur, et l'adresse d'une faute de page (le `trap_nr`, l'`error_code`
    /// et le `cr2` du `thread_struct` de Linux). Le cadre de signal les
    /// montre (sigcontext : trapno, err, cr2), même pour un signal envoyé
    /// par kill : ce sont ceux de la dernière exception, pas du signal
    /// (mesuré).
    exception: [AtomicU64; 3],
    /// Ce que reprendra `restart_syscall` (le `restart_block` de Linux,
    /// reprise.rs).
    reprise: Verrou<Option<crate::reprise::Reprise>>,
    /// La profondeur du « contexte réseau » où elle est (reseau/contexte.rs :
    /// le `local_bh_disable` de Linux, mais par tâche).
    pub contexte_reseau: AtomicU32,
    /// Les sockets dont elle a fait le dernier `close`, à fermer à la
    /// sortie de son appel (la liste chaînée par les sockets elles-mêmes :
    /// le `task_work` de Linux ; reseau/socket.rs).
    pub fermetures: Verrou<Option<Arc<crate::reseau::socket::Socket>>>,
    /// Les tubes dont elle a fermé un bout, à signaler (tube::fichier_ferme), au même moment.
    pub tubes_fermes: Verrou<Option<Arc<crate::tube::Tube>>>,
    /// Les instances d'inotify où elle a posé un événement, à signaler à
    /// leurs inscrits O_ASYNC (surveillance::Groupe::deposer), au même
    /// moment.
    pub instances_a_signaler: Verrou<Option<Arc<crate::surveillance::Groupe>>>,
    /// Les trames qu'elle a émises par `lo` et pas encore reçues (6j,
    /// reseau/boucle.rs : une file par tâche émettrice, le `backlog` par
    /// processeur de Linux), et les copies des diffusions qu'elle a
    /// envoyées par une carte ; faite à sa première émission.
    pub file_lo: Verrou<Option<alloc::collections::VecDeque<crate::reseau::boucle::Trame>>>,
}

/// Ce qu'un programme a de plus qu'une tâche du noyau.
struct EtatProgramme {
    fpu: crate::sse::ZoneFpu,
    selecteurs: [u16; 4],
    base_fs: u64,
}

impl EtatProgramme {
    /// Celui d'un programme qui commence : l'état x87/SSE initial, des
    /// sélecteurs et une base de FS nuls. None : plus de mémoire.
    fn initial() -> Option<EtatProgramme> {
        // SAFETY: l'image de l'état initial, une constante.
        let fpu = crate::sse::ZoneFpu::neuve(unsafe { &etat_fpu_initial.0 })?;
        Some(EtatProgramme { fpu, selecteurs: [0; 4], base_fs: 0 })
    }

    /// Celui d'un fil neuf : une copie de celui de la tâche courante, son
    /// créateur (son état x87/SSE, ses sélecteurs), avec la base de FS
    /// `base_fs` (CLONE_SETTLS), ou la sienne (le `copy_thread` de Linux).
    fn herite(base_fs: Option<u64>) -> Option<EtatProgramme> {
        let fpu = crate::sse::ZoneFpu::du_processeur()?;
        let mut selecteurs = [0u16; 4];
        // SAFETY: lire les sélecteurs de segments ne change rien ; ceux
        // de l'anneau 3, que le noyau ne touche pas.
        unsafe {
            asm!("mov {0:x}, ds", "mov {1:x}, es", "mov {2:x}, fs", "mov {3:x}, gs",
                 out(reg) selecteurs[0], out(reg) selecteurs[1], out(reg) selecteurs[2], out(reg) selecteurs[3],
                 options(nomem, nostack, preserves_flags));
        }
        Some(EtatProgramme { fpu, selecteurs, base_fs: base_fs.unwrap_or_else(cpu::lire_base_fs) })
    }
}

// SAFETY: les champs dans des UnsafeCell (`contexte`, `programme`) ne sont
// lus et écrits que par `basculer_vers`, interruptions coupées, sur le
// processeur de la tâche (et, avant son premier départ, par qui la
// prépare : `preparer`, quand personne d'autre ne la connaît), et une
// tâche ne s'exécute que sur un processeur à la fois (`sur_processeur`, le
// `on_cpu` de Linux : posé sous le verrou de la file des prêtes pour celle
// qu'on choisit, retiré quand sa bascule est finie) ; `entree_attente`,
// que sous le verrou de la file d'attente où elle est inscrite ; le reste
// est atomique ou sous Verrou.
unsafe impl Sync for Tache {}
// SAFETY: voir ci-dessus.
unsafe impl Send for Tache {}

/// Ce qui a manqué pour créer une tâche.
pub enum Manque {
    /// Une pile du noyau : il n'y en a qu'autant que le maximum de fils
    /// (`max_threads`), comme le `threads-max` de Linux (EAGAIN).
    Pile,
    /// La mémoire de la tâche elle-même (ENOMEM, le `dup_task_struct` de
    /// Linux).
    Memoire,
}

impl Tache {
    /// Une tâche, sans encore de premier départ, ni de place dans la table
    /// des tâches (`demarrer`) : jetée avant, elle rend sa pile. Ou ce qui
    /// manque : une pile (le maximum de fils), ou la mémoire de la tâche. Une
    /// tâche du noyau attend sa créatrice (`attendant`), un fil de programme
    /// a le numéro `tid` et l'état `programme`.
    fn creer(nom: NomCourt, espace: u64, programme: Option<EtatProgramme>, processus: Option<Arc<crate::processus::Entree>>,
             tid: u32) -> Result<Arc<Tache>, Manque> {
        let pile = Pile::allouer().ok_or(Manque::Pile)?;
        marquer_pile(&pile);
        let haut = pile.haut();
        let programme = programme.map(UnsafeCell::new);
        let noyau = processus.is_none();
        // (La tâche inactive n'attend personne : elle ne doit jamais
        // quitter son rôle pour entrer dans la file des prêtes.)
        let attendant = (noyau && en_service() && !courante().inactive).then(courante_arc);
        // Les processeurs permis : ceux de son créateur (le `copy_process`
        // de Linux copie le `cpus_mask`) ; tous, pour les premières tâches
        // du démarrage.
        let affinite = if en_service() { courante().affinite() } else { u64::MAX };
        Arc::new(Tache::brute(tid, false, nom, Some(pile), haut, espace, processus, programme, attendant, false, affinite))
            .map_err(|_| Manque::Memoire)
    }

    /// Une tâche, champ par champ : ce que partagent l'inactive d'un
    /// processeur (`initialiser`, `inactive_secondaire`) et une tâche
    /// créée (`creer`). `sur_processeur` : vrai pour une inactive, qui
    /// s'exécute déjà (c'est le code qui la crée, ou le processeur qui
    /// démarre dessus).
    fn brute(tid: u32, inactive: bool, nom: NomCourt, pile: Option<Pile>, haut: u64, espace: u64,
             processus: Option<Arc<crate::processus::Entree>>, programme: Option<UnsafeCell<EtatProgramme>>,
             attendant: Option<Arc<Tache>>, sur_processeur: bool, affinite: u64) -> Tache {
        Tache {
            tid,
            inactive,
            nom: Verrou::new(nom),
            contexte: UnsafeCell::new(0),
            pile: Verrou::new(pile),
            haut,
            espace: AtomicU64::new(espace),
            processus,
            programme,
            morte: AtomicBool::new(false),
            sur_processeur: AtomicBool::new(sur_processeur),
            en_file: AtomicBool::new(false),
            processeur: AtomicU32::new(0),
            affinite: AtomicU64::new(affinite),
            webassembly: AtomicBool::new(false),
            ecrire_tid: AtomicU64::new(0),
            effacer_tid: AtomicU64::new(0),
            liste_robuste: AtomicU64::new(0),
            code_sortie: AtomicI32::new(0),
            tube_interne: AtomicU32::new(0),
            calcul: AtomicU64::new(0),
            lag: AtomicI64::new(0),
            attendant: Verrou::new(attendant),
            entree_attente: EntreeAttente::new(),
            etat: AtomicU8::new(etat::EN_COURS),
            futex: Verrou::new(None),
            tient_sa_memoire: AtomicBool::new(false),
            sans_faute: AtomicBool::new(false),
            temps_a_verifier: AtomicBool::new(false),
            a_tuer: AtomicBool::new(false),
            fin: Verrou::new(None),
            usage: crate::rusage::Compteurs::default(),
            precedent: crate::rusage::Precedent::new(),
            exception: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            reprise: Verrou::new(None),
            contexte_reseau: AtomicU32::new(0),
            fermetures: Verrou::new(None),
            tubes_fermes: Verrou::new(None),
            instances_a_signaler: Verrou::new(None),
            file_lo: Verrou::new(None),
        }
    }

    /// Le sommet de sa pile noyau (pour le trampoline d'un processeur
    /// secondaire, smp.rs : la pile de sa tâche inactive).
    pub fn sommet_de_pile(&self) -> u64 {
        self.haut
    }

    /// Les processeurs où elle a le droit de s'exécuter (voir `affinite`).
    pub fn affinite(&self) -> u64 {
        self.affinite.load(Ordering::Relaxed)
    }

    pub fn poser_affinite(&self, masque: u64) {
        self.affinite.store(masque, Ordering::Relaxed);
    }

    /// Son numéro de fil (0 : une tâche du noyau).
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Sa fin est-elle prévue (exit, une faute, SIGKILL, la fin de son
    /// groupe) ? Un clone en cours rend alors EINTR (fil.rs).
    pub fn fin_prevue(&self) -> bool {
        self.fin.verrouiller().is_some()
    }

    /// Prépare la pile pour un premier départ : six registres pour
    /// `basculer` (r12 : `r12`), l'adresse de `depart`, et, pour un
    /// programme, le cadre de son retour vers l'anneau 3 au-dessus.
    fn preparer(&self, depart: unsafe extern "C" fn(), r12: u64, cadre: Option<Cadre>) {
        let mut sommet = self.haut;
        // SAFETY: la pile vient d'être allouée pour cette tâche, qui n'a
        // jamais tourné : personne d'autre ne s'en sert. On y écrit, de haut
        // en bas, le cadre éventuel, l'adresse du départ, et les registres
        // que dépilera `basculer` (r15, r14, r13, r12, rbx, rbp, dans
        // l'ordre de la pile).
        unsafe {
            if let Some(c) = cadre {
                sommet -= size_of::<Cadre>() as u64;
                (sommet as *mut Cadre).write(c);
            }
            sommet -= 8;
            (sommet as *mut u64).write(depart as *const () as u64);
            sommet -= 6 * 8;
            core::ptr::write_bytes(sommet as *mut u64, 0, 6);
            ((sommet + 3 * 8) as *mut u64).write(r12);
            *self.contexte.get() = sommet;
        }
    }

    pub fn nom(&self) -> NomCourt {
        *self.nom.verrouiller()
    }

    /// Ajoute `ns` nanosecondes à son temps de calcul (ordonnanceur.rs), et
    /// à celui de son processus ; un programme verra sa limite de temps de
    /// calcul vérifiée à son retour vers l'anneau 3.
    pub fn compter_calcul(&self, ns: u64) {
        if ns == 0 {
            return;
        }
        self.calcul.fetch_add(ns, Ordering::Relaxed);
        if let Some(p) = &self.processus {
            p.compter_calcul(ns);
        }
        if self.programme.is_some() {
            self.temps_a_verifier.store(true, Ordering::Relaxed);
        }
    }

    /// Son entrée de file d'attente (attente.rs).
    pub fn entree_attente(&self) -> &EntreeAttente {
        &self.entree_attente
    }

    /// Est-elle morte ?
    pub fn est_morte(&self) -> bool {
        // SeqCst (un simple `mov` sur x86) : c'est une condition de
        // sommeil lue sans verrou, après « je vais dormir » (attente.rs) ;
        // `terminer` l'écrit en Release (son code de sortie est écrit
        // avant), puis réveille derrière une barrière complète : le motif
        // de Dekker, que le modèle de Rust ne ferme qu'avec une lecture
        // SeqCst de ce côté-ci.
        self.morte.load(Ordering::SeqCst)
    }

    /// Son processus, pour un programme Linux.
    pub fn processus(&self) -> Option<&Arc<crate::processus::Entree>> {
        self.processus.as_ref()
    }

    /// S'exécute-t-elle sur un processeur, ou n'a-t-elle pas fini de le
    /// quitter (voir `sur_processeur`) ? Acquire : la paire du Release de
    /// `fin_de_bascule`, qui dit que sa pile et ses registres sont rangés.
    pub fn est_sur_processeur(&self) -> bool {
        self.sur_processeur.load(Ordering::Acquire)
    }

    /// `ordonnancer` la choisit (sous le verrou de la file) : elle va
    /// s'exécuter.
    pub fn prend_le_processeur(&self) {
        self.sur_processeur.store(true, Ordering::Relaxed);
    }

    /// Est-elle dans une file des prêtes (sous le verrou de cette file) ?
    pub fn est_en_file(&self) -> bool {
        self.en_file.load(Ordering::Relaxed)
    }

    /// Entre dans la file des prêtes du processeur `p`, ou en sort (sous le
    /// verrou de cette file : ordonnanceur.rs).
    pub fn poser_en_file(&self, oui: bool, p: u32) {
        self.en_file.store(oui, Ordering::Relaxed);
        if oui {
            self.processeur.store(p, Ordering::Relaxed);
        }
    }

    /// Le processeur dont la file la tient, ou la tenait en dernier (voir
    /// `processeur`) : là où elle s'exécute, si elle s'exécute.
    pub fn processeur(&self) -> u32 {
        self.processeur.load(Ordering::Relaxed)
    }



    /// Est-ce un programme (et pas une tâche du noyau) ?
    pub fn est_programme(&self) -> bool {
        self.programme.is_some()
    }

    /// La tâche courante exécute désormais un programme WebAssembly
    /// (programmes.rs).
    pub fn marquer_webassembly(&self) {
        self.webassembly.store(true, Ordering::Relaxed);
    }

    /// Exécute-t-elle un programme WebAssembly ?
    pub fn est_webassembly(&self) -> bool {
        self.webassembly.load(Ordering::Relaxed)
    }

    /// Dort-elle (ou va-t-elle dormir), interruptible ?
    pub fn dort_interruptible_maintenant(&self) -> bool {
        self.etat.load(Ordering::Relaxed) == etat::DORT_INTERRUPTIBLE
    }

    /// Prévoit sa fin par `signal`, avec ce message (voir `forcer`).
    pub fn forcer(&self, signal: Signal, raison: impl fmt::Display) {
        Self::forcer_sous(&mut self.fin.verrouiller(), signal, raison);
    }

    /// Comme `forcer`, mais seulement si `reveil` (le compare_exchange d'un
    /// réveil, `reveiller`) réussit, le verrou de la fin tenu pendant le
    /// réveil : la tâche réveillée, si elle regarde sa fin avant que nous
    /// l'ayons écrite, attend ce verrou (le détecteur d'interblocage,
    /// attente.rs : jusqu'à la relecture de 6j, le réveil précédait
    /// l'écriture, et la tâche pouvait voir « réveillée par un signal » sans
    /// signal, un EINTR sans raison). Rend ce que `reveil` a rendu.
    pub fn forcer_apres(&self, signal: Signal, raison: impl fmt::Display, reveil: impl FnOnce() -> bool) -> bool {
        let mut fin = self.fin.verrouiller();
        if !reveil() {
            return false;
        }
        Self::forcer_sous(&mut fin, signal, raison);
        true
    }

    fn forcer_sous(fin: &mut Option<Fin>, signal: Signal, raison: impl fmt::Display) {
        let remplacer = match &*fin {
            None => true,
            Some(Fin::Signal(s, _)) => signal.numero == linux::SIGKILL.numero && s.numero != linux::SIGKILL.numero,
            Some(Fin::Sortie(_)) => false,
        };
        if remplacer {
            *fin = Some(Fin::Signal(signal, Message::de(raison)));
        }
    }

    /// Le futex qu'elle attend (futex.rs).
    pub fn futex(&self) -> &Verrou<Option<crate::futex::Attente>> {
        &self.futex
    }

    /// Tient-elle la mémoire de son processus ?
    pub fn tient_sa_memoire(&self) -> bool {
        self.tient_sa_memoire.load(Ordering::Relaxed)
    }

    /// Elle prend, ou rend, la mémoire de son processus.
    pub fn tenir_sa_memoire(&self, oui: bool) {
        self.tient_sa_memoire.store(oui, Ordering::Relaxed);
    }

    /// Faut-il servir une faute de page du noyau dans une copie pour elle ?
    pub fn faute_servie(&self) -> bool {
        !self.sans_faute.load(Ordering::Relaxed)
    }

    /// « Je vais dormir » (le `set_current_state` de Linux) : à poser AVANT
    /// de vérifier ce qu'on attend, au début de CHAQUE tour d'une boucle
    /// d'attente (attente.rs). Un `swap` SeqCst, c'est-à-dire un `xchg`,
    /// une barrière complète : la vérification qui suit ne peut pas être
    /// faite avant que l'état soit visible de qui réveille. C'est le motif
    /// de Dekker (processeur.rs) : celui qui réveille pose la condition,
    /// puis lit notre état ; nous posons notre état, puis lisons la
    /// condition ; l'un des deux voit l'autre.
    pub fn preparer_sommeil(&self, sommeil: crate::attente::Sommeil) {
        let e = if sommeil == crate::attente::Sommeil::Interruptible { etat::DORT_INTERRUPTIBLE } else { etat::DORT };
        self.etat.swap(e, Ordering::SeqCst);
    }

    /// Fin d'une attente : « en cours » (le `__set_current_state(TASK_RUNNING)`
    /// de `finish_wait`). Une raison de réveil restée ferait croire, au
    /// prochain `dormir`, que l'état a été posé.
    pub fn reveille(&self) {
        self.etat.store(etat::EN_COURS, Ordering::Relaxed);
    }

    /// Le compare_exchange du réveil (ordonnanceur.rs, `reveiller`, SOUS le
    /// verrou de la file de la tâche, celui sous lequel `ordonnancer` lit
    /// son état pour la retirer) : « dort » devient `pourquoi`. SeqCst : la
    /// paire de `preparer_sommeil` (le motif de Dekker, voir là), et ce que
    /// celui qui réveille a écrit avant (la condition) est visible de la
    /// tâche réveillée. Faux si elle ne dormait pas, ou plus.
    pub fn passer_a_reveillee(&self, pourquoi: Reveil) -> bool {
        loop {
            let e = self.etat.load(Ordering::Relaxed);
            if !reveillable(e, pourquoi) {
                return false;
            }
            if self.etat.compare_exchange(e, pourquoi as u8, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                REVEILS.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
    }

    /// Va-t-elle dormir (son état est « dort »), ou est-elle morte : la
    /// tâche courante quitte alors la file des prêtes quand elle cède le
    /// processeur pour dormir (ordonnanceur.rs). Une raison de réveil
    /// posée entre-temps l'y garde.
    pub fn quitte_la_file(&self) -> bool {
        matches!(self.etat.load(Ordering::Relaxed), etat::DORT | etat::DORT_INTERRUPTIBLE | etat::MORTE)
    }

    /// Son état vaut-il encore « en cours », c'est-à-dire que personne n'a
    /// posé « je vais dormir » pour ce tour : `dormir` le refuse.
    pub fn sommeil_non_prepare(&self) -> bool {
        self.etat.load(Ordering::Relaxed) == etat::EN_COURS
    }

    /// Pose la raison `pourquoi` si elle allait dormir, interruptible ou
    /// non, sans la réveiller : pour qui vient de constater, dans sa propre
    /// tâche, qu'il ne dormira pas (une échéance déjà passée, un signal en
    /// attente : attente.rs). Si quelqu'un l'a déjà réveillée, sa raison
    /// reste.
    pub fn ne_dort_pas(&self, pourquoi: Reveil) {
        for dort in [etat::DORT, etat::DORT_INTERRUPTIBLE] {
            if self.etat.compare_exchange(dort, pourquoi as u8, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                return;
            }
        }
    }

    /// Pourquoi elle a été réveillée (par une file, si personne ne l'a dit :
    /// un réveil sans raison se revérifie de toute façon).
    pub fn raison_du_reveil(&self) -> Reveil {
        match self.etat.load(Ordering::Relaxed) {
            etat::ECHEANCE => Reveil::Echeance,
            etat::SIGNAL => Reveil::Signal,
            _ => Reveil::Reveillee,
        }
    }

    /// Son retard en quittant la file des prêtes (ordonnanceur.rs).
    pub fn lag(&self) -> i64 {
        self.lag.load(Ordering::Relaxed)
    }

    pub fn garder_lag(&self, lag: i64) {
        self.lag.store(lag, Ordering::Relaxed);
    }

    /// Ce qu'elle a consommé (getrusage).
    pub fn usage(&self) -> &crate::rusage::Compteurs {
        &self.usage
    }

    /// Le dernier partage de son temps rendu par getrusage.
    pub fn precedent(&self) -> &crate::rusage::Precedent {
        &self.precedent
    }

    /// Garde ce que reprendra `restart_syscall` (None : rien, rt_sigreturn).
    pub fn garder_reprise(&self, r: Option<crate::reprise::Reprise>) {
        *self.reprise.verrouiller() = r;
    }

    /// Prend ce que reprendra `restart_syscall`.
    pub fn prendre_reprise(&self) -> Option<crate::reprise::Reprise> {
        self.reprise.verrouiller().take()
    }

    /// Sa dernière exception : (vecteur, code d'erreur, adresse fautive).
    pub fn derniere_exception(&self) -> (u64, u64, u64) {
        (self.exception[0].load(Ordering::Relaxed), self.exception[1].load(Ordering::Relaxed),
         self.exception[2].load(Ordering::Relaxed))
    }

    /// Le cadre de son retour vers l'anneau 3, en haut de sa pile noyau :
    /// celui qu'empilent l'entrée de `syscall` et une interruption venue du
    /// programme (22 valeurs sous le sommet ; une exception à pile IST le
    /// recopie là, interruptions.rs), et que prépare le premier départ d'un
    /// fil.
    pub fn cadre_du_programme(&self) -> *mut Cadre {
        (self.haut - size_of::<Cadre>() as u64) as *mut Cadre
    }
}

// La tâche courante (le `current` de Linux), la tâche inactive et la tâche
// à rendre sont PAR PROCESSEUR, dans sa zone (processeur.rs : `courante`,
// `inactive`, `a_rendre`), lue par GS. La tâche à rendre : celle qui vient
// de mourir sur ce processeur, et qu'il faut rendre à la fin de la bascule
// qui suit (sa pile, puis la référence qu'elle avait laissée pour
// elle-même) : un Arc mis de côté par `terminer`. Sans lui, la file des
// prêtes, qui la lâche quand elle meurt, pouvait tenir la dernière
// référence : la tâche aurait rendu sa pile en s'exécutant dessus.

/// Toutes les tâches vivantes, sauf les inactives (pour le détecteur
/// d'interblocage, attente.rs ; pour trouver un fil par son numéro :
/// tkill, /proc, sched_getaffinity ; RLIMIT_NPROC, sysinfo). Réservée au
/// démarrage pour autant de tâches que de piles : elle ne grandit jamais
/// pendant un programme.
static TOUTES: Verrou<Vec<Arc<Tache>>> = Verrou::new(Vec::new());

/// Fait du code en cours (noyau_main, sur la pile du démarrage) la tâche
/// inactive du premier processeur. Avant toute autre tâche, interruptions
/// coupées.
pub fn initialiser() {
    // L'inactive s'exécute : c'est le code qui est en train de la créer ;
    // sans pile à elle (celle du démarrage, haut = 0 : la TSS n'en a pas
    // besoin, rien ne vient de l'anneau 3 vers elle).
    let pile_demarrage = Tache::brute(0, true, NomCourt::de(b"inactive"), None, 0, pagination::pml4_noyau(), None, None, None, true, u64::MAX);
    let t = Arc::into_raw(Arc::new(pile_demarrage).expect("plus de memoire pour la tache du demarrage")) as *mut Tache;
    let p = processeur::courant();
    p.inactive.store(t, Ordering::Relaxed);
    p.courante.store(t, Ordering::Relaxed);
    TOUTES.verrouiller().try_reserve_exact(crate::vmalloc::max_threads()).expect("plus de memoire pour la table des taches");
    MORTES.verrouiller().try_reserve_exact(crate::vmalloc::max_threads()).expect("plus de memoire pour la liste des taches mortes");
}

/// La tâche inactive du processeur secondaire `numero` (smp.rs) : comme
/// celle du premier (`initialiser`), mais avec sa propre pile, de vmalloc
/// sous sa page de garde (le premier garde la pile du démarrage) ; le
/// processeur l'exécute dès sa première instruction Rust (sa pile, sa
/// tâche courante), et pour toujours. Ni dans la table des tâches ni dans
/// une file. None : plus de pile, ou plus de mémoire.
pub fn inactive_secondaire(numero: usize) -> Option<Arc<Tache>> {
    let pile = Pile::allouer()?;
    marquer_pile(&pile);
    let haut = pile.haut();
    // « inactive-N » (N < 64 : deux chiffres au plus).
    let mut nom = *b"inactive-00";
    let longueur = if numero < 10 {
        nom[9] = b'0' + numero as u8;
        10
    } else {
        nom[9] = b'0' + (numero / 10) as u8;
        nom[10] = b'0' + (numero % 10) as u8;
        11
    };
    let nom = NomCourt::de(&nom[..longueur]);
    Arc::new(Tache::brute(0, true, nom, Some(pile), haut, pagination::pml4_noyau(), None, None, None, true, u64::MAX)).ok()
}

/// Appelle `f` sur chaque tâche vivante (sauf les inactives), table tenue :
/// `f` doit être court.
pub fn pour_chaque(mut f: impl FnMut(&Arc<Tache>)) {
    for t in TOUTES.verrouiller().iter() {
        f(t);
    }
}

/// L'affinité du fil `tid` (sched_getaffinity), s'il vit.
pub fn affinite_du_fil(tid: u32) -> Option<u64> {
    let mut a = None;
    pour_chaque(|t| {
        if t.tid == tid {
            a = Some(t.affinite());
        }
    });
    a
}

/// Pose l'affinité du fil `tid` (sched_setaffinity) : faux s'il ne vit
/// pas. S'il s'exécute sur un processeur que le masque ne permet plus, ce
/// processeur le fait céder (ordonnanceur.rs : le premier processeur permis
/// qui n'a rien à faire le tirera).
pub fn poser_affinite_du_fil(tid: u32, masque: u64) -> bool {
    let mut trouve = None;
    pour_chaque(|t| {
        if t.tid == tid {
            t.poser_affinite(masque);
            trouve = Some(t.clone());
        }
    });
    match trouve {
        Some(t) => {
            ordonnanceur::affinite_changee(&t);
            true
        }
        None => false,
    }
}

/// Exécute `f` sans qu'une faute de page dans une copie de la tâche
/// courante soit servie (voir `sans_faute`).
pub fn sans_faute_servie<R>(f: impl FnOnce() -> R) -> R {
    let t = courante();
    t.sans_faute.store(true, Ordering::Relaxed);
    let r = f();
    t.sans_faute.store(false, Ordering::Relaxed);
    r
}

/// Les tâches existent-elles (après `initialiser`) ?
pub fn en_service() -> bool {
    !processeur::courante_brute().is_null()
}

/// La tâche courante. Lisible interruptions actives : sur quelque
/// processeur qu'une préemption nous déplace, la tâche courante y est
/// toujours nous (l'exception écrite dans processeur.rs).
pub fn courante() -> &'static Tache {
    // SAFETY: la tâche courante du processeur est toujours une tâche
    // vivante : elle ne peut pas être rendue pendant qu'elle s'exécute (sa
    // structure vit tant qu'un Arc la tient : celui de qui l'a créée, et
    // la tâche inactive pour toujours). Lue en une instruction
    // (processeur.rs) : c'est ce qui la rend juste interruptions actives.
    unsafe { &*processeur::courante_brute() }
}

/// Les valeurs de l'état d'une tâche (`Tache::etat`, le `__state` de
/// Linux). Les deux premières sont « elle dort, ou va dormir » ; les
/// raisons de réveil valent celles de `Reveil`.
pub mod etat {
    /// Seul un réveil de sa file la réveille (TASK_UNINTERRUPTIBLE).
    pub const DORT: u8 = 0;
    /// Un signal la réveille aussi (TASK_INTERRUPTIBLE).
    pub const DORT_INTERRUPTIBLE: u8 = 1;
    /// Elle s'exécute, ou est prête, sans raison de réveil à lire (l'état
    /// d'une tâche neuve, et celui que rend `reveille`) : TASK_RUNNING.
    pub const EN_COURS: u8 = 2;
    /// Réveillée par sa file (`Reveil::Reveillee`).
    pub const REVEILLEE: u8 = 3;
    /// Réveillée par son échéance (`Reveil::Echeance`).
    pub const ECHEANCE: u8 = 4;
    /// Réveillée par un signal (`Reveil::Signal`).
    pub const SIGNAL: u8 = 5;
    /// Morte : plus aucun réveil ne la touche (TASK_DEAD).
    pub const MORTE: u8 = 6;
}

/// Pourquoi une tâche qui dormait a été réveillée (attente.rs). Les
/// valeurs sont celles de `etat`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reveil {
    /// Par la file où elle attendait : ce qu'elle attendait est peut-être
    /// là (elle revérifie).
    Reveillee = etat::REVEILLEE as isize,
    /// Son échéance est passée.
    Echeance = etat::ECHEANCE as isize,
    /// Un signal (elle dormait interruptible) : l'appel rendra EINTR, ou
    /// sera refait (reprise.rs).
    Signal = etat::SIGNAL as isize,
}

/// Le nombre de réveils réussis depuis le démarrage : l'instantané du
/// détecteur d'interblocage (attente.rs), qui recommence si un réveil a eu
/// lieu pendant qu'il regardait.
static REVEILS: AtomicU64 = AtomicU64::new(0);

/// Le nombre de réveils réussis depuis le démarrage.
pub fn reveils() -> u64 {
    REVEILS.load(Ordering::Relaxed)
}

/// Réveille `t`, qui dort ou va dormir, pour la raison `pourquoi` : elle
/// redevient prête. C'est le `try_to_wake_up` de Linux : un
/// compare_exchange de son état, de « dort » vers la raison ; un signal
/// (`Reveil::Signal`) ne réveille qu'un sommeil INTERRUPTIBLE (le
/// `ttwu_state_match`). Perdu : quelqu'un l'a réveillée avant (sa raison
/// reste, elle n'est mise qu'une fois dans la file des prêtes), ou elle ne
/// dormait pas : rend faux, et un réveil exclusif qui n'a réveillé personne
/// passe à la suivante (attente.rs). Gagné : rend vrai, et la tâche est
/// prête ; si elle n'avait pas encore fini de s'endormir (elle est encore
/// dans la file des prêtes), elle n'en sortira plus (ordonnanceur.rs ne
/// retire qu'une tâche dont l'état dit encore « dort »).
pub fn reveiller(t: Arc<Tache>, pourquoi: Reveil) -> bool {
    // Une barrière complète AVANT de lire l'état (le `smp_mb__after_spinlock`
    // de `try_to_wake_up`) : qui réveille vient d'écrire la condition (le
    // plus souvent par une écriture ordinaire, ou en rendant un Verrou,
    // une écriture Release), et sur x86 une lecture peut passer devant une
    // écriture qui attend encore dans le tampon : sans la barrière, on
    // pourrait lire « en cours » (l'ancien état) pendant que la tâche, qui
    // a posé « dort » puis lu la condition, ne voit pas encore notre
    // écriture : le réveil serait perdu. Un compare_exchange qui échoue
    // n'est qu'une lecture, il ne l'ordonne pas.
    core::sync::atomic::fence(Ordering::SeqCst);
    // Un premier regard sans verrou : la plupart des réveils qui ne peuvent
    // rien (un réveil exclusif qui passe à la suivante, une tâche déjà
    // réveillée) s'arrêtent ici. Le changement d'état lui-même se fait
    // SOUS le verrou de la file de la tâche (ordonnanceur.rs, `reveiller`) :
    // fait avant, hors verrou, il laissait la tâche libre de continuer, de
    // se rendormir ailleurs ou de mourir pendant que le réveilleur n'avait
    // pas fini, et celui-ci la remettait en file (trouvé par la relecture
    // de 6j).
    if !reveillable(t.etat.load(Ordering::Relaxed), pourquoi) {
        return false;
    }
    ordonnanceur::reveiller(t, pourquoi)
}

/// `pourquoi` réveille-t-il une tâche dans l'état `e` ? Un signal ne
/// réveille qu'un sommeil interruptible.
fn reveillable(e: u8, pourquoi: Reveil) -> bool {
    e == etat::DORT_INTERRUPTIBLE || (e == etat::DORT && pourquoi != Reveil::Signal)
}

/// Un signal vient d'être mis en attente pour le fil `t`, qui ne le bloque
/// pas : s'il dort interruptible, il est réveillé (le `signal_wake_up` de
/// Linux). Le compare_exchange décide seul : plus de lecture à part d'un
/// drapeau « interruptible », qui pouvait être lu avant d'être posé. S'il
/// s'exécute sur un autre processeur, celui-ci reçoit l'IPI de
/// reprogrammation (le `kick_process` de Linux) : le fil entre dans le
/// noyau et voit le signal à son retour (`verifier_au_retour`), au lieu
/// d'attendre son prochain tic ou appel système.
pub fn reveiller_par_signal(t: Arc<Tache>) {
    if !reveiller(t.clone(), Reveil::Signal) {
        secouer(&t);
    }
}

/// Fait entrer dans le noyau le fil `t` s'il s'exécute sur un autre
/// processeur (voir `reveiller_par_signal`). Préemption coupée le temps de
/// comparer : « un autre » ne doit pas changer de sens.
fn secouer(t: &Tache) {
    processeur::sans_preemption(|| {
        let p = t.processeur() as usize;
        if t.est_sur_processeur() && p != processeur::courant().numero as usize {
            crate::smp::reprogrammer(p);
        }
    });
}

/// Un signal attend la tâche courante, qui doit finir son attente
/// interruptible : sa fin prévue (SIGKILL forcé, exit_group d'un autre
/// fil), le tueur OOM, ou un signal en attente qu'elle ne bloque pas.
pub fn signal_en_attente() -> bool {
    let t = courante();
    t.fin.verrouiller().is_some()
        || t.a_tuer.load(Ordering::Relaxed)
        || (t.programme.is_some() && processus::essayer_avec(|p| signaux::en_attente_non_bloque(p, t.tid)) == Some(true))
}

/// Le numéro du processus du fil `tid`, s'il vit encore.
pub fn processus_du_fil(tid: u32) -> Option<u32> {
    let mut pid = None;
    pour_chaque(|t| {
        if t.tid == tid {
            pid = t.processus.as_ref().map(|p| p.pid());
        }
    });
    pid
}

/// Un Arc de la tâche courante (pour la mettre dans une file).
pub fn courante_arc() -> Arc<Tache> {
    let p: *const Tache = courante();
    // SAFETY: toute tâche vient d'un Arc (Arc::new, ou Arc::into_raw pour
    // l'inactive), toujours tenu tant qu'elle s'exécute (voir `courante`) :
    // en prendre un de plus est permis.
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

/// La tâche inactive de ce processeur. Interruptions coupées (c'est une
/// donnée du processeur : processeur.rs).
pub fn inactive() -> *const Tache {
    processeur::courant().inactive.load(Ordering::Relaxed)
}

/// Passe le processeur de la tâche courante à `nouvelle` (voir l'en-tête),
/// pour l'ordonnanceur. Revient quand une autre tâche rend la main à la
/// courante. Interruptions coupées pendant la bascule ; leur état est
/// rétabli au retour.
pub fn basculer_vers(nouvelle: &Tache) {
    let interruptions = cpu::couper_interruptions();
    let ancienne = courante();
    // AMD : un SS valide pour le `sysretq` de la tâche suivante (cpu.rs,
    // `bogue_sysret_ss`).
    if cpu::bogue_sysret_ss() {
        cpu::ss_du_noyau();
    }
    // SAFETY: interruptions coupées, et une tâche ne s'exécute que sur un
    // processeur à la fois (`sur_processeur`, voir `unsafe impl Sync for
    // Tache`) : personne d'autre ne touche à l'état des deux tâches
    // (l'ancienne est encore la nôtre, la nouvelle a été choisie sous le
    // verrou de notre file). Les registres et MSR
    // écrits sont ceux du programme de la nouvelle tâche (le noyau n'en
    // dépend pas) ; son espace a la moitié haute du noyau, on continue de
    // s'exécuter après avoir changé CR3 ; sa pile noyau est la sienne.
    unsafe {
        if let Some(p) = &ancienne.programme {
            let p = &mut *p.get();
            p.fpu.sauver();
            asm!("mov {0:x}, ds", "mov {1:x}, es", "mov {2:x}, fs", "mov {3:x}, gs",
                 out(reg) p.selecteurs[0], out(reg) p.selecteurs[1], out(reg) p.selecteurs[2], out(reg) p.selecteurs[3],
                 options(nomem, nostack, preserves_flags));
            p.base_fs = cpu::lire_base_fs();
        }
        if let Some(p) = &nouvelle.programme {
            let p = &*p.get();
            p.fpu.retablir();
            // Le sélecteur avant la base : charger FS remet sa base à celle
            // du descripteur (comme Linux, `load_seg_legacy`). GS entre
            // deux swapgs (le `native_load_gs_index` de Linux) : dans le
            // noyau, la base ACTIVE de GS est la zone du processeur
            // (processeur.rs) ; `mov gs` la remettrait à zéro. On rend
            // d'abord active la base du programme, on charge le sélecteur
            // (qui remet CETTE base-là à zéro, ce que le programme attend :
            // arch_prctl refuse ARCH_SET_GS), et on rééchange. Entre les
            // deux, seuls un NMI, un #DB ou un #MC peuvent tomber
            // (interruptions coupées) : ils retrouvent la zone par le MSR
            // (interruptions.rs, le chemin paranoïaque). Et `mov gs` ne
            // peut pas fauter : le sélecteur est celui que GS portait à la
            // bascule précédente (lu ci-dessus par `mov {:x}, gs`), que le
            // processeur avait donc accepté, et rt_sigreturn n'y touche pas
            // (cadre_signal.rs : Linux non plus en 64 bits) ; une faute ici
            // arriverait avec la base du programme active (le `.Lgs_change`
            // de Linux, que nous n'avons pas à traiter).
            asm!("mov ds, {0:x}", "mov es, {1:x}", "mov fs, {2:x}", "swapgs", "mov gs, {3:x}", "swapgs",
                 in(reg) p.selecteurs[0], in(reg) p.selecteurs[1], in(reg) p.selecteurs[2], in(reg) p.selecteurs[3],
                 options(nostack, preserves_flags));
            cpu::ecrire_base_fs(p.base_fs);
        }
        let espace = nouvelle.espace.load(Ordering::Relaxed);
        if pagination::courante() != espace {
            charger_espace(nouvelle, espace);
        }
        if nouvelle.haut != 0 {
            gdt::definir_pile_noyau(nouvelle.haut);
        }
        processeur::courant().courante.store(nouvelle as *const Tache as *mut Tache, Ordering::Relaxed);
        let precedente = basculer(ancienne.contexte.get(), nouvelle.contexte.get(), ancienne as *const Tache as *const core::ffi::c_void);
        fin_de_bascule(precedente);
    }
    if interruptions {
        cpu::activer_interruptions();
    }
}

/// Charge la PML4 `espace` de la tâche `nouvelle` sur ce processeur, en
/// tenant à jour les masques des processeurs des espaces (le `mm_cpumask`
/// de Linux, espace_utilisateur.rs) : le bit de ce processeur mis dans le
/// masque de l'espace qu'on charge AVANT de charger sa PML4, et retiré de
/// celui de l'espace qu'on quitte APRÈS (un `fetch_or`, une instruction
/// `lock` : la barrière complète du motif de Dekker avec le vidage des TLB à
/// distance, qui lit le masque après avoir écrit ses tables). Interruptions
/// coupées.
///
/// # Safety
/// `espace` est la PML4 du noyau, ou celle du processus de `nouvelle`
/// (une tâche de programme), complète.
unsafe fn charger_espace(nouvelle: &Tache, espace: u64) {
    let zone = processeur::courant();
    let bit = 1u64 << zone.numero;
    let ancien = zone.espace_charge.swap(core::ptr::null_mut(), Ordering::Relaxed);
    if espace != pagination::pml4_noyau() {
        let masque = nouvelle.processus.as_ref().expect("un espace de programme sans processus").processeurs();
        masque.processeurs.fetch_or(bit, Ordering::SeqCst);
        zone.espace_charge.store(masque as *const _ as *mut _, Ordering::Relaxed);
    }
    // SAFETY: garanti par l'appelant.
    unsafe { pagination::activer(espace) };
    if !ancien.is_null() {
        // Le bit de l'espace qu'on quitte, retiré APRÈS avoir chargé l'autre
        // CR3 : « fini de parcourir ses tables » est alors vrai (jusqu'à la
        // relecture de 6j, il était retiré avant, pendant que ce processeur
        // pouvait encore, en spéculation, parcourir ces tables ; Linux
        // d'avant la TLB paresseuse le retirait avant aussi). Une demande
        // de vidage qui lit le masque entre les deux nous envoie une IPI de
        // trop, que `vider_a_distance` ignore (ce n'est plus la PML4
        // chargée).
        // SAFETY: le masque est tenu par l'entrée du processus de la tâche
        // qu'on quitte, vivante (voir processeur.rs, `espace_charge`).
        // Release : fini de parcourir ses tables.
        unsafe { (*ancien).processeurs.fetch_and(!bit, Ordering::Release) };
    }
}

/// La tâche courante quitte l'espace de son programme pour celui du noyau
/// (`terminer`) : le bit de ce processeur retiré du masque, la PML4 du
/// noyau chargée. Interruptions coupées.
fn quitter_espace() {
    let zone = processeur::courant();
    let ancien = zone.espace_charge.swap(core::ptr::null_mut(), Ordering::Relaxed);
    // SAFETY: la PML4 du noyau est complète.
    unsafe { pagination::activer(pagination::pml4_noyau()) };
    if !ancien.is_null() {
        // Après CR3, comme dans `charger_espace`.
        // SAFETY: comme dans `charger_espace` : la tâche courante tient son
        // processus.
        unsafe { (*ancien).processeurs.fetch_and(!(1u64 << zone.numero), Ordering::Release) };
    }
}

/// Ce que porte une pile neuve : là où ce motif reste, elle n'est jamais descendue (le
/// `stack_not_used` de CONFIG_DEBUG_STACK_USAGE, chez nous toujours là : 16 Kio à écrire à
/// la naissance d'un fil, contre une page de garde qui ne dit rien de la marge qui restait
/// jusqu'au jour où un chemin de plus la franchit). Écarté : une limite vérifiée à chaque
/// appel système, qui ne voit rien de ce qui descend et remonte entre deux.
const MOTIF_PILE: u64 = 0x5A5A_5A5A_5A5A_5A5A;

/// La pile qui est descendue le plus bas, parmi celles des tâches finies,
/// et le nom de sa tâche (pour savoir quel chemin creuser quand la marge
/// manque, 6j).
static PILE_LA_PLUS_PROFONDE: AtomicUsize = AtomicUsize::new(0);
static NOM_LA_PLUS_PROFONDE: Verrou<Option<NomCourt>> = Verrou::new(None);

fn marquer_pile(p: &Pile) {
    // SAFETY: la pile vient d'être allouée, projetée tout entière, et à personne d'autre.
    unsafe { core::slice::from_raw_parts_mut(p.bas() as *mut u64, ((p.haut() - p.bas()) / 8) as usize) }.fill(MOTIF_PILE);
}

/// Combien d'octets la pile `p` a servi, au plus.
fn profondeur(p: &Pile) -> usize {
    let mut v = p.bas();
    // SAFETY: la pile est projetée tout entière ; sa partie basse n'est écrite que par
    // sa tâche, finie ou qui nous exécute, et un mot lu à part n'a pas à être cohérent.
    while v < p.haut() && unsafe { (v as *const u64).read_volatile() } == MOTIF_PILE {
        v += 8;
    }
    (p.haut() - v) as usize
}

/// La pile la plus profonde, parmi les tâches finies et la courante. Une tâche encore en
/// vie n'est pas lue : son chemin (la tâche du réseau) est plus court que celui d'un appel
/// système, qui passe aussi par le réseau.
pub fn plus_grande_profondeur() -> (usize, Option<NomCourt>) {
    let ici = courante().pile.verrouiller().as_ref().map_or(0, profondeur);
    let (finie, nom) = (PILE_LA_PLUS_PROFONDE.load(Ordering::Relaxed), *NOM_LA_PLUS_PROFONDE.verrouiller());
    if ici > finie { (ici, Some(courante().nom())) } else { (finie, nom) }
}

/// La fin d'une bascule, dans la tâche qui reprend (ou démarre), avec la
/// tâche qu'on vient de quitter (`precedente`, rendue par `basculer`).
/// Interruptions coupées. Dans l'ordre du `finish_task_switch` de Linux :
///   1. la précédente a fini de quitter le processeur : ses registres et sa
///      pile sont rangés, un autre processeur peut la reprendre (`finish_task`,
///      `on_cpu = 0` en Release). EN PREMIER : qui l'attend (un réveil, un
///      processeur qui tire) tourne pendant ce temps ;
///   2. si elle est morte, elle est confiée au RENDEUR (une tâche du
///      noyau, `rendeur`), qui rendra sa pile interruptions actives : la
///      rendre demande de faire oublier ses traductions à tous les
///      processeurs (6j, une interruption entre processeurs), ce qui ne se
///      fait pas interruptions coupées. Jusqu'à 6i, la pile était rendue
///      ici même. Linux de même : `put_task_stack` passe par un cache de
///      piles par processeur ou par un `vfree` différé.
#[unsafe(no_mangle)]
extern "C" fn fin_de_bascule(precedente: *const core::ffi::c_void) {
    let precedente = precedente as *const Tache;
    // SAFETY: la précédente vit : une tâche ne quitte son Arc que rendue par
    // le rendeur, bien après cette fin de bascule.
    let precedente = unsafe { &*precedente };
    precedente.sur_processeur.store(false, Ordering::Release);
    // Son masque ne permet plus ce processeur (sched_setaffinity pendant
    // qu'elle s'exécutait) : poussée vers un processeur permis maintenant
    // qu'elle l'a quitté (ordonnanceur.rs, l'affinité).
    ordonnanceur::pousser_si_interdite(precedente);
    let morte = processeur::courant().a_rendre.swap(core::ptr::null_mut(), Ordering::Relaxed);
    if !morte.is_null() {
        // SAFETY: `morte` vient d'Arc::into_raw dans `terminer`, rendu une
        // seule fois, ici ; elle ne s'exécute plus.
        let t = unsafe { Arc::from_raw(morte) };
        A_RENDRE_AU_RENDEUR.fetch_add(1, Ordering::Release);
        // La place est réservée (`initialiser`) : autant de mortes au plus
        // que de piles.
        MORTES.verrouiller().ajouter_dans_la_place(t);
        RENDEUR_ATTENTE.reveiller_toutes();
    }
}

/// Les tâches mortes dont le rendeur doit rendre la pile, et leur compte
/// (celles de la liste, et celle qu'il est en train de rendre) : « memoire
/// rendue » (programmes.rs) attend qu'il soit nul.
static MORTES: Verrou<Vec<Arc<Tache>>> = Verrou::new(Vec::new());
static A_RENDRE_AU_RENDEUR: AtomicUsize = AtomicUsize::new(0);
/// Le rendeur y attend du travail ; qui attend que tout soit rendu attend
/// dans la seconde.
static RENDEUR_ATTENTE: crate::attente::FileAttente = crate::attente::FileAttente::new();
static RENDU_ATTENTE: crate::attente::FileAttente = crate::attente::FileAttente::new();

/// Le rendeur : une tâche du noyau qui rend les piles des tâches mortes,
/// interruptions actives, puis dit au processus de chacune qu'un fil a
/// tout à fait disparu (`fil_disparu`, qui fait du processus un zombie au
/// dernier). Une pile rendue va d'abord dans un cache (vmalloc.rs) : reprise
/// pour un fil neuf, aux mêmes adresses et sur les mêmes cadres, elle ne
/// demande rien à personne. Il rend aussi les grands blocs du tas
/// (vmalloc.rs, `purger`), pour la même raison : les rendre demande un
/// vidage des TLB de tous les processeurs.
fn rendeur() {
    loop {
        crate::attente::attendre_que(&RENDEUR_ATTENTE, crate::attente::Inscription::Ordinaire, crate::attente::Sommeil::Ininterruptible, None,
                                     || !MORTES.verrouiller().is_empty() || crate::vmalloc::a_rendre());
        if crate::vmalloc::purger() {
            RENDU_ATTENTE.reveiller_toutes();
        }
        loop {
            // La garde de MORTES rendue à la fin de cette ligne : dans un
            // `while let`, un temporaire du motif vivrait tout le corps, et
            // rendre une pile (ce qui demande aux autres processeurs
            // d'oublier ses traductions, vmalloc.rs) se ferait verrou tenu,
            // interruptions coupées.
            let morte = MORTES.verrouiller().pop();
            let Some(t) = morte else { break };
            // De même pour la garde de sa pile (un `if let` la garderait
            // tout le corps).
            let pile = t.pile.verrouiller().take();
            if let Some(p) = pile {
                let profondeur = profondeur(&p);
                if PILE_LA_PLUS_PROFONDE.fetch_max(profondeur, Ordering::Relaxed) < profondeur {
                    let nom = t.nom();
                    *NOM_LA_PLUS_PROFONDE.verrouiller() = Some(nom);
                }
                crate::vmalloc::ranger_pile(p);
            }
            // Un fil de programme : sa tâche rendue (si rien d'autre ne la
            // tient), son processus est peut-être fini.
            let processus = t.processus.clone();
            drop(t);
            if let Some(p) = processus {
                p.fil_disparu();
            }
            A_RENDRE_AU_RENDEUR.fetch_sub(1, Ordering::Release);
            RENDU_ATTENTE.reveiller_toutes();
        }
    }
}

/// Lance le rendeur, au démarrage, dès que les tâches existent.
pub fn lancer_rendeur() {
    if lancer_noyau(NomCourt::de(b"rendeur"), rendeur).is_none() {
        panic!("pas de pile pour le rendeur");
    }
}

/// Attend que le rendeur ait rendu toutes les tâches mortes et tous les
/// grands blocs du tas : avant de compter la mémoire rendue
/// (programmes.rs), et de vider le cache des piles (vmalloc.rs).
pub fn attendre_le_rendeur() {
    crate::attente::attendre_que(&RENDU_ATTENTE, crate::attente::Inscription::Ordinaire, crate::attente::Sommeil::Ininterruptible, None,
                                 || A_RENDRE_AU_RENDEUR.load(Ordering::SeqCst) == 0 && crate::vmalloc::en_attente() == 0);
}

/// Attend la fin de la tâche `t` : la tâche courante dort jusqu'à ce que
/// `terminer` la réveille. Sans réveil perdu : « je vais dormir » est posé
/// avant de regarder si elle est morte, et `terminer` pose « morte » avant
/// de réveiller (voir `dormir_tant_que`).
pub fn attendre(t: &Tache) -> i32 {
    dormir_tant_que(|| !t.est_morte());
    t.code_sortie.load(Ordering::Relaxed)
}

/// La tâche courante dort tant que `encore` le dit, réveillée par la fin
/// de l'une des tâches qu'elle a créées (le `wait` d'un parent : init qui
/// recueille ses enfants, programmes.rs). Sans file d'attente : la fin
/// réveille directement (`terminer`, par `attendant`). Sans réveil perdu,
/// par l'état (attente.rs) : « je vais dormir » est posé (une barrière
/// complète) AVANT de vérifier `encore` ; `terminer` écrit « morte » puis
/// tente le réveil ; ou bien nous voyons « morte », ou bien le réveil nous
/// trouve « dort » et nous ne quittons pas la file des prêtes.
pub fn dormir_tant_que(encore: impl Fn() -> bool) {
    let interruptions = cpu::couper_interruptions();
    let t = courante();
    loop {
        t.preparer_sommeil(crate::attente::Sommeil::Ininterruptible);
        if !encore() {
            break;
        }
        ordonnanceur::ordonnancer(ordonnanceur::Bascule::Sommeil);
    }
    t.reveille();
    if interruptions {
        cpu::activer_interruptions();
    }
}

/// Le RFLAGS d'un programme qui démarre : IF (interruptions acceptées) et
/// le bit 1, toujours à 1. IOPL = 0 : pas de `in`, `out`, `cli`, `sti`.
const RFLAGS_INITIAL: u64 = 1 << 9 | 1 << 1;

/// Range la tâche `t` dans la table des tâches, et la rend prête.
fn demarrer(t: &Arc<Tache>) {
    // La place est réservée : il n'y a jamais plus de tâches que de piles.
    TOUTES.verrouiller().ajouter_dans_la_place(t.clone());
    ordonnanceur::rendre_prete(t.clone());
}

/// Lance le fil principal d'un programme, prêt aussitôt : `processus` son
/// processus (dont il porte le numéro), `pml4` son espace d'adressage,
/// `entree` son point d'entrée, `pile` le sommet de sa pile. None : pas de
/// pile noyau pour sa tâche, ou plus de mémoire pour la liste des fils.
pub fn lancer_programme(nom: NomCourt, processus: Arc<crate::processus::Entree>, pml4: u64, entree: u64, pile: u64)
    -> Option<Arc<Tache>> {
    let tid = processus.pid();
    let t = Tache::creer(nom, pml4, Some(EtatProgramme::initial()?), Some(processus.clone()), tid).ok()?;
    processus.attacher(&t).ok()?;
    t.preparer(premier_depart, 0, Some(Cadre {
        r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
        rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0,
        vecteur: 0,
        code_erreur: 0,
        rip: entree,
        cs: gdt::CODE_UTILISATEUR as u64,
        rflags: RFLAGS_INITIAL,
        rsp: pile,
        ss: gdt::DONNEES_UTILISATEUR as u64,
    }));
    demarrer(&t);
    Some(t)
}

/// Ce qu'il faut pour lancer un fil neuf du processus courant (clone,
/// fil.rs) : son cadre de départ (une copie de celui de l'appel de son
/// créateur, déjà ajustée), sa base de FS (CLONE_SETTLS, sinon celle du
/// créateur), et les adresses de CLONE_CHILD_SETTID, CLONE_CHILD_CLEARTID et
/// CLONE_PARENT_SETTID (0 : sans).
pub struct NouveauFil {
    pub cadre: Cadre,
    pub tls: Option<u64>,
    pub ecrire_tid: u64,
    pub effacer_tid: u64,
    pub parent_tid: u64,
}

/// Lance un fil neuf du processus de la tâche courante, dans l'ordre du
/// `copy_process` puis du `kernel_clone` de Linux : la copie de l'état du
/// créateur (ENOMEM), une pile noyau (EAGAIN : le maximum de fils,
/// max_threads) et la tâche (ENOMEM), sa place dans le processus, sous son verrou, à condition
/// que le créateur ne soit pas en train de finir (EINTR, tout est défait :
/// « Let kill terminate clone/fork in the middle ») ; puis son numéro écrit
/// à CLONE_PARENT_SETTID AVANT qu'il soit prêt (un fil qui finirait aussitôt
/// effacerait sinon son numéro avant que son créateur ne l'écrive, et
/// `pthread_join` attendrait pour toujours ; une faute est ignorée, comme
/// chez Linux) ; enfin il est prêt. Rend son numéro.
pub fn lancer_fil(n: NouveauFil) -> Result<u32, i64> {
    const ENOMEM: i64 = 12;
    const EAGAIN: i64 = 11;
    const EINTR: i64 = 4;
    let createur = courante();
    let processus = createur.processus.clone().expect("clone sans processus");
    let etat = EtatProgramme::herite(n.tls).ok_or(-ENOMEM)?;
    // RLIMIT_NPROC : les tâches de l'utilisateur, fils compris (tous nos
    // programmes sont au même) ; infinie par défaut.
    let (limite, _) = processus::avec(|p| p.limite(processus::RLIMIT_NPROC));
    if limite != processus::INFINI {
        let mut n = 0u64;
        pour_chaque(|t| n += t.processus.is_some() as u64);
        if n >= limite {
            return Err(-EAGAIN);
        }
    }
    let tid = processus::numero_neuf();
    let espace = createur.espace.load(Ordering::Relaxed);
    let t = Tache::creer(createur.nom(), espace, Some(etat), Some(processus.clone()), tid).map_err(|m| match m {
        Manque::Pile => -EAGAIN,
        Manque::Memoire => -ENOMEM,
    })?;
    t.ecrire_tid.store(n.ecrire_tid, Ordering::Relaxed);
    t.effacer_tid.store(n.effacer_tid, Ordering::Relaxed);
    t.preparer(premier_depart, 0, Some(n.cadre));
    processus.attacher_fil(&t, createur).map_err(|r| match r {
        processus::RefusFil::Interrompu => -EINTR,
        processus::RefusFil::PlusDeMemoire => -ENOMEM,
    })?;
    if n.parent_tid != 0 {
        let _ = crate::copie_utilisateur::copier_vers_utilisateur(n.parent_tid, &tid.to_le_bytes());
    }
    demarrer(&t);
    Ok(tid)
}

/// Le premier départ d'un fil de programme, avant l'anneau 3 (le
/// `schedule_tail` et le `ret_from_fork` de Linux), interruptions coupées :
/// son numéro écrit à CLONE_CHILD_SETTID, par lui-même (une faute est
/// ignorée), puis la sortie ordinaire vers l'anneau 3 : un fil créé pendant
/// que son groupe commençait à finir s'arrête là, sans exécuter une
/// instruction du programme. Revient interruptions coupées.
#[unsafe(no_mangle)]
extern "C" fn debut_de_fil() {
    let t = courante();
    let adresse = t.ecrire_tid.swap(0, Ordering::Relaxed);
    if adresse != 0 {
        cpu::activer_interruptions();
        let _ = crate::copie_utilisateur::copier_vers_utilisateur(adresse, &t.tid.to_le_bytes());
    }
    // SAFETY: le cadre du premier départ, préparé en haut de sa pile
    // (`preparer`) ; rien d'autre ne s'en sert.
    verifier_au_retour(unsafe { &mut *t.cadre_du_programme() });
}

/// set_tid_address(adresse) : l'adresse où effacer le numéro du fil courant
/// à sa fin (le `clear_child_tid` de Linux). Rend son numéro.
pub fn effacer_tid_a(adresse: u64) -> u32 {
    let t = courante();
    t.effacer_tid.store(adresse, Ordering::Relaxed);
    t.tid
}

/// set_robust_list(tête) : la liste des verrous robustes du fil courant.
pub fn liste_robuste(tete: u64) {
    courante().liste_robuste.store(tete, Ordering::Relaxed);
}

/// La fin d'un fil, côté programme, avant qu'il ne quitte son processus
/// (le `mm_release` de Linux) : ses verrous robustes rendus (futex.rs), puis
/// son numéro effacé à CLONE_CHILD_CLEARTID et un réveil partagé à cette
/// adresse, ce qu'attend `pthread_join` ; seulement s'il reste d'autres fils
/// pour le voir (Linux regarde `mm_users`). Plus aucun accès à la mémoire du
/// programme ensuite : `pthread_join` peut déjà avoir rendu la pile du fil.
fn liberer_le_fil(t: &Tache, p: &crate::processus::Entree) {
    let tete = t.liste_robuste.swap(0, Ordering::Relaxed);
    if tete != 0 {
        crate::futex::rendre_liste_robuste(tete, t.tid);
    }
    let adresse = t.effacer_tid.swap(0, Ordering::Relaxed);
    if adresse != 0 && p.a_d_autres_fils(t.tid) {
        let _ = crate::copie_utilisateur::copier_vers_utilisateur(adresse, &0u32.to_le_bytes());
        crate::futex::reveiller_partage(adresse, 1);
    }
}

/// Arrête le fil `t` avec son groupe (exit_group, une faute, un signal
/// mortel d'un autre fil : le `zap_other_threads` de Linux, qui lui envoie
/// SIGKILL) : il finira sans un mot, avec le code du groupe, à son retour
/// vers l'anneau 3, réveillé s'il dort interruptible (son appel rend
/// EINTR). Sous le verrou de son processus.
pub fn arreter_avec_le_groupe(t: Arc<Tache>, code: i32) {
    *t.fin.verrouiller() = Some(Fin::Sortie(code));
    // Réveillé s'il dort interruptible : le compare_exchange de son état
    // décide (un fil qui n'a pas encore posé « je vais dormir » verra sa
    // fin prévue en la vérifiant, après l'avoir posé : attente.rs) ; s'il
    // s'exécute ailleurs, l'IPI (`secouer`).
    if !reveiller(t.clone(), Reveil::Signal) {
        secouer(&t);
    }
}

/// Le nombre de tâches (sysinfo : `procs`, le `nr_threads` de Linux), les
/// inactives comptées, une par processeur en service.
pub fn nombre() -> usize {
    TOUTES.verrouiller().len() + processeur::nombre()
}

/// La fonction d'une tâche du noyau.
type FonctionNoyau = Box<dyn FnOnce() + Send>;

/// Lance `f` dans une tâche du noyau nommée `nom`, prête aussitôt ; None :
/// pas de pile pour la tâche, ou plus de mémoire.
pub fn lancer_noyau(nom: NomCourt, f: impl FnOnce() + Send + 'static) -> Option<Arc<Tache>> {
    // Un pointeur simple vers la fermeture, pour r12 : une boîte de boîte.
    let f: FonctionNoyau = faillible::boite(f).ok()?;
    let f: Box<FonctionNoyau> = faillible::boite(f).ok()?;
    let t = Tache::creer(nom, pagination::pml4_noyau(), None, None, 0).ok()?;
    t.preparer(depart_noyau, Box::into_raw(f) as u64, None);
    demarrer(&t);
    Some(t)
}

/// Le corps d'une tâche du noyau (depart_noyau) : sa fonction, puis sa fin.
#[unsafe(no_mangle)]
extern "C" fn tache_noyau(f: *mut FonctionNoyau) -> ! {
    // SAFETY: `f` vient de Box::into_raw dans `executer_noyau`, rendu une
    // seule fois, ici.
    let f = unsafe { Box::from_raw(f) };
    f();
    terminer(0)
}

/// Termine la tâche courante : elle est morte, réveille qui attend sa fin,
/// quitte la file des prêtes et cède le processeur pour toujours ; la
/// tâche suivante rendra sa pile (fin de bascule). Appelée en haut de sa
/// pile (retour vers l'anneau 3, ou fin de sa fonction) : rien de ce que
/// tiennent les cadres en dessous n'est perdu. Un fil de programme quitte
/// son processus ; le processus devient un zombie quand la pile de son
/// dernier fil est rendue (fin_de_bascule), ce qui réveille son parent.
pub fn terminer(code: i32) -> ! {
    let t = courante();
    t.code_sortie.store(code, Ordering::Relaxed);
    if let Some(p) = &t.processus {
        liberer_le_fil(t, p);
        // La tâche passe ensuite sur l'espace du noyau, interruptions
        // coupées : si elle est préemptée pendant qu'elle rend celui du
        // programme (long, et préemptible), la bascule qui la reprendra
        // chargera la PML4 du noyau, jamais des tables qu'on détruit.
        let interruptions = cpu::couper_interruptions();
        t.espace.store(pagination::pml4_noyau(), Ordering::Relaxed);
        quitter_espace();
        if interruptions {
            cpu::activer_interruptions();
        }
        p.usage().garder(&t.usage);
        p.fil_termine(t.tid, code);
    }
    // Ce que la tâche a différé : pour un programme, les fichiers que son
    // dernier fil vient de fermer (fil_termine), leurs sockets, maintenant
    // (la fermeture différée, socket.rs) ; pour toute tâche, les SIGIO
    // d'inotify qu'elle a prévus (une tâche du noyau qui ouvre un fichier).
    crate::reseau::socket::fermer_les_differees();
    // Son tube interne n'est plus compté à l'utilisateur (`do_exit` :
    // `free_pipe_info(tsk->splice_pipe)`).
    crate::tube::rendre_le_tube_interne(t.tube_interne.swap(0, Ordering::Relaxed));
    cpu::couper_interruptions();
    // Morte : son état d'abord (plus aucun réveil ne la touche, et
    // l'ordonnanceur la retirera de la file), puis `morte`, en Release : qui
    // le lit (`attendre`, `est_morte`, en Acquire) voit tout ce qu'elle a
    // écrit avant, son code de sortie compris.
    t.etat.store(etat::MORTE, Ordering::Relaxed);
    t.morte.store(true, Ordering::Release);
    // Une référence à elle-même, pour la fin de bascule qui rendra sa pile,
    // sur ce processeur.
    processeur::courant().a_rendre.store(Arc::into_raw(courante_arc()) as *mut Tache, Ordering::Relaxed);
    {
        let mut toutes = TOUTES.verrouiller();
        if let Some(i) = toutes.iter().position(|x| core::ptr::eq(Arc::as_ptr(x), t)) {
            toutes.swap_remove(i);
        }
    }
    // Sa créatrice, qui attend peut-être sa fin, ou celle de l'une de ses
    // tâches.
    if let Some(attendant) = t.attendant.verrouiller().take() {
        reveiller(attendant, Reveil::Reveillee);
    }
    ordonnanceur::ordonnancer(ordonnanceur::Bascule::Sommeil);
    unreachable!("une tache morte a repris la main");
}

/// Arrête le programme en cours par le signal `signal` (une exception, sa
/// limite de temps de calcul, un signal envoyé par lui ou par un autre),
/// en disant pourquoi : le message de Linux dans son journal, puis le code de sortie
/// 128 + signal, pour tout le groupe (un signal mortel arrête le processus,
/// le `do_group_exit` de `get_signal`). Seulement au retour vers l'anneau 3
/// (`verifier_au_retour`).
fn mourir(signal: Signal, raison: impl fmt::Display) -> ! {
    afficherln!("[noyau] {} : {} ({})", courante().nom(), raison, signal.nom);
    let code = 128 + signal.numero as i32;
    let tid = courante().tid;
    let code = processus::essayer_avec(|p| p.finir_le_groupe(code, tid)).unwrap_or(code);
    terminer(code)
}

/// Un message du noyau gardé pour plus tard : celui d'une faute, dit quand
/// le programme meurt, au retour vers l'anneau 3. 256 octets au plus (un
/// message plus long est coupé), dans la structure même : le garder ne
/// demande aucune allocation, qui pourrait manquer au moment d'une faute.
pub struct Message {
    octets: [u8; 256],
    longueur: usize,
}

impl Message {
    fn de(raison: impl fmt::Display) -> Message {
        let mut m = Message { octets: [0; 256], longueur: 0 };
        let _ = fmt::write(&mut m, format_args!("{}", raison));
        m
    }
}

impl fmt::Write for Message {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.octets.len() - self.longueur);
        self.octets[self.longueur..self.longueur + n].copy_from_slice(&s.as_bytes()[..n]);
        self.longueur += n;
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Les messages du noyau sont en ASCII : coupés n'importe où, ils
        // restent du texte.
        f.write_str(core::str::from_utf8(&self.octets[..self.longueur]).unwrap_or("?"))
    }
}

/// Comment le programme doit finir, à son retour vers l'anneau 3.
enum Fin {
    /// exit ou exit_group, avec son code.
    Sortie(i32),
    /// Un signal qu'il ne peut ni bloquer ni ignorer (une faute, SIGKILL),
    /// et ce qu'il faudra dire.
    Signal(Signal, Message),
}

/// exit : le fil finira au retour vers l'anneau 3, avec ce code. Elle
/// l'emporte sur tout ce qui pouvait l'attendre (sous Linux, `do_exit` part
/// aussitôt, sans regarder les signaux). Le processus finit avec son
/// dernier fil.
pub fn prevoir_sortie(code: i32) {
    *courante().fin.verrouiller() = Some(Fin::Sortie(code));
}

/// exit_group : la fin de tout le groupe, avec ce code (sauf si elle avait
/// déjà commencé : son code l'emporte, comme le `do_group_exit` de Linux),
/// puis celle du fil, au retour vers l'anneau 3.
pub fn prevoir_sortie_du_groupe(code: i32) {
    let tid = courante().tid;
    let code = processus::avec(|p| p.finir_le_groupe(code, tid));
    prevoir_sortie(code);
}

/// Le programme sera arrêté par `signal` au retour vers l'anneau 3 (une
/// faute, plus rien ne peut le réveiller...), avec ce message. La
/// première raison l'emporte, sauf SIGKILL, qui remplace tout signal
/// prévu avant lui (pas une sortie) : c'est lui qui tuera.
pub fn forcer(signal: Signal, raison: impl fmt::Display) {
    courante().forcer(signal, raison);
}

/// Arrête le programme en cours faute de mémoire (SIGKILL, le tueur OOM de
/// Linux), en disant ce qu'il occupait. La mémoire du processus, lue pour
/// le message, est rendue avant d'arrêter : `terminer` ne revient pas, et
/// une mémoire emportée dans une tâche abandonnée ne serait jamais rendue
/// (le dernier fil l'attendrait pour toujours, dans `fil_termine`).
fn arreter_plus_de_memoire() -> ! {
    let (virtuelle, en_place, fichiers, tables) = processus::memoire_lue(|m| {
        let c = m.compteurs();
        (m.taille_virtuelle(), c.pages() as u64 * 4096, c.pages_fichier() as u64 * 4096, c.tables() as u64 * 4096)
    });
    // Le message de Linux : « Out of memory: Killed process 1234 (a.out)
    // total-vm:...kB, anon-rss:...kB, file-rss:...kB, ... pgtables:...kB ».
    mourir(
        linux::SIGKILL,
        format_args!("plus de memoire : tue, memoire virtuelle {} Kio, en place {} Kio, fichiers {} Kio, tables {} Kio",
                     virtuelle >> 10, en_place >> 10, fichiers >> 10, tables >> 10),
    )
}

/// Le nom de la tâche courante (PR_GET_NAME).
pub fn nom() -> NomCourt {
    courante().nom()
}

/// Change le nom de la tâche courante (PR_SET_NAME) : celui des messages
/// du noyau, comme le `comm` de Linux, que montre aussi son tueur OOM.
pub fn renommer(nom: NomCourt) {
    renommer_tache(courante(), nom);
}

/// Change le nom de `t` ; celui d'un fil principal est aussi gardé par son
/// processus (/proc/<pid>/comm, après la fin de ce fil).
fn renommer_tache(t: &Tache, nom: NomCourt) {
    *t.nom.verrouiller() = nom;
    if let Some(p) = &t.processus
        && p.pid() == t.tid
    {
        p.renommer(nom);
    }
}

/// Le nom du fil `tid`, s'il vit.
pub fn nom_du_fil(tid: u32) -> Option<NomCourt> {
    let mut nom = None;
    pour_chaque(|t| {
        if t.tid == tid && tid != 0 {
            nom = Some(t.nom());
        }
    });
    nom
}

/// Pourquoi un fil ne peut pas être renommé par /proc/<pid>/task/<tid>/comm.
pub enum RefusNom {
    /// Il n'existe plus (ESRCH).
    Absent,
    /// Il est d'un autre processus que celui qui écrit (EINVAL).
    AutreProcessus,
}

/// Renomme le fil `tid`, du processus de la tâche courante (l'écriture de
/// /proc/.../comm : `pthread_setname_np` pour un autre fil que soi).
pub fn renommer_fil(tid: u32, nom: NomCourt) -> Result<(), RefusNom> {
    let mut cible = None;
    pour_chaque(|t| {
        if t.tid == tid && tid != 0 {
            cible = Some(t.clone());
        }
    });
    let t = cible.ok_or(RefusNom::Absent)?;
    let meme = match (&t.processus, &courante().processus) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    };
    if !meme {
        return Err(RefusNom::AutreProcessus);
    }
    renommer_tache(&t, nom);
    Ok(())
}

/// Appelée à chaque tic d'horloge, interruptions coupées, avec l'endroit où
/// il a trouvé la tâche courante (`programme` : en anneau 3, sinon dans le
/// noyau ; pour getrusage, rusage.rs) : l'ordonnanceur compte son temps de
/// calcul, et lui fait céder le processeur si elle a fini sa tranche ; les
/// échéances passées réveillent leurs tâches.
pub fn tic(programme: bool) {
    let t = courante();
    if t.processus.is_some() {
        t.usage.compter_tic(programme);
    }
    ordonnanceur::tic();
    // Les échéances : par le processeur 0 seul, qui compte le temps
    // (horloge.rs). Et des grands blocs du tas rendus qui attendent le
    // rendeur : le tas ne peut pas le réveiller lui-même (vmalloc.rs).
    if processeur::courant().numero == 0 {
        crate::attente::tic();
        if crate::vmalloc::a_rendre() {
            RENDEUR_ATTENTE.reveiller_toutes();
        }
    }
}

/// Le temps de calcul de la tâche courante, en nanosecondes
/// (CLOCK_THREAD_CPUTIME_ID, temps.rs).
pub fn temps_de_calcul() -> u64 {
    courante().calcul.load(Ordering::Relaxed)
}

/// Celui de son processus, tous ses fils (CLOCK_PROCESS_CPUTIME_ID) ; pour
/// une tâche du noyau (un programme WebAssembly), le sien.
pub fn temps_du_processus() -> u64 {
    let t = courante();
    t.processus.as_ref().map_or_else(|| t.calcul.load(Ordering::Relaxed), |p| p.temps_de_calcul())
}

/// La tâche courante sera tuée faute de mémoire à son retour vers
/// l'anneau 3 (voir `a_tuer`).
pub fn tuer_au_retour() {
    courante().a_tuer.store(true, Ordering::Relaxed);
}

/// La sortie vers l'anneau 3 : à la fin d'un appel système, et d'une
/// interruption ou d'une exception venue du programme. C'est là, et
/// seulement là, que le programme meurt, comme sous Linux
/// (`exit_to_user_mode_loop`) : le noyau n'a alors plus rien en cours pour
/// lui, en haut de sa pile noyau, et ne tient aucun verrou. Une faute, un
/// exit, le tueur OOM ne font que PRÉVOIR la fin (`forcer`,
/// `prevoir_sortie`, `tuer_au_retour`), puis l'appel ou le gestionnaire
/// se termine normalement : rien de ce qu'il tenait n'est abandonné.
///
/// Dans l'ordre :
///   0. céder le processeur, si la tâche a fini sa tranche ;
///   1. une fin prévue : exit (son code), ou un signal forcé (son message) ;
///   2. tué faute de mémoire pendant une copie du noyau ;
///   3. RLIMIT_CPU, dans l'ordre de Linux (voir plus bas) ;
///   4. les signaux en attente et non bloqués (le `get_signal` de Linux) :
///      ceux qu'envoient les programmes (kill, tkill, tgkill), et SIGXCPU.
///      Un signal qui a un gestionnaire : son cadre est posé (cadre_signal.rs),
///      `cadre` (le cadre de retour vers l'anneau 3) mène désormais au
///      gestionnaire, et l'on recommence : un second signal non bloqué pose
///      son cadre par-dessus, son gestionnaire passera le premier (comme
///      Linux, mesuré : SIGUSR1, SIGUSR2 et SIGWINCH en attente, leurs
///      gestionnaires s'exécutent dans l'ordre SIGWINCH, SIGUSR2, SIGUSR1).
///      Un cadre impossible à poser : SIGSEGV forcé (`force_sigsegv`).
/// La décision est prise interruptions coupées, et la fonction revient
/// interruptions coupées quand il n'y a rien à faire : sur CE processeur,
/// rien ne peut plus arriver entre la dernière vérification et le retour
/// (sysretq ou iretq rétablissent les interruptions du programme) ; un
/// signal envoyé par une interruption tombée avant est vu. Un signal envoyé
/// par un AUTRE processeur juste après la vérification fait suivre une IPI
/// de reprogrammation (`reveiller_par_signal`), qui attend derrière les
/// interruptions coupées et fait rentrer le fil dans le noyau dès son
/// retour (le `kick_process` de Linux). Linux boucle ainsi jusqu'à ce qu'il
/// n'y ait plus rien à faire :
/// céder le processeur si l'ordonnanceur le demande, puis tout revérifier.
///
/// La limite de temps de calcul est RLIMIT_CPU, en secondes, celle de
/// Linux. Comme lui, elle n'est vérifiée qu'après un tic compté (Linux le
/// fait dans le tic, nous au retour qui suit, où le signal serait livré de
/// toute façon) : un programme qui pose une limite de 0 s ne reçoit SIGXCPU
/// qu'au tic suivant, et un getrlimit fait juste après relit 0 (mesuré),
/// pas la limite déjà relevée. Dans l'ordre de `check_process_timers`
/// (kernel/time/posix-cpu-timers.c) :
///   - rien à vérifier si la limite courante est infinie (le défaut) ;
///   - la limite dure d'abord : atteinte, SIGKILL ;
///   - puis la courante : atteinte, SIGXCPU, et Linux la relève d'une
///     seconde (`rlim_cur = soft + 1`, ce que montre ensuite getrlimit,
///     mesuré) : un programme qui ignore SIGXCPU en reçoit un autre la
///     seconde suivante, jusqu'à la limite dure. Une courante égale à la
///     dure tue donc directement par SIGKILL (mesuré : 137, pas 152).
/// SIGXCPU est un signal comme un autre (signaux.rs) : ignoré, il est jeté ;
/// bloqué, il attend ; laissé à son action par défaut, il arrête le
/// programme. SIGKILL, lui, ne se bloque ni ne s'ignore.
///
/// Options écartées :
///   - le budget fixe d'une seconde des étapes 5 à 6c : il n'existe pas
///     sous Linux, et il arrêterait claude ;
///   - une limite écrite dans /etc/demarrage (un `--cpu=`, comme `--dir=`) :
///     une seconde entorse à la syntaxe de sh, pour une chose que Linux ne
///     fait pas à l'exec ; un programme qui veut une limite la pose
///     (setrlimit), et le shell de 6l aura `ulimit -t`.
pub fn verifier_au_retour(cadre: &mut Cadre) {
    let arret = loop {
        cpu::couper_interruptions();
        // Céder le processeur d'abord, s'il le faut : on revient ici quand
        // la tâche le retrouve, et tout est revérifié.
        if ordonnanceur::besoin_de_ceder() {
            ordonnanceur::ordonnancer(ordonnanceur::Bascule::Preemption);
            continue;
        }
        match decider() {
            Some(Arret::Gestionnaire { sig, info, action, masque, pile }) => {
                // Le cadre s'écrit dans la mémoire du programme :
                // interruptions actives, aucun verrou tenu. D'abord, l'appel
                // interrompu rendra EINTR, ou sera refait après le
                // gestionnaire (reprise.rs).
                cpu::activer_interruptions();
                crate::reprise::avant_gestionnaire(cadre, action.drapeaux & signaux::SA_RESTART != 0);
                livrer(cadre, sig, &info, &action, masque, pile);
            }
            // Rien à livrer sous le masque d'attente : comme Linux
            // (`arch_do_signal_or_restart`), l'appel interrompu est d'abord
            // repris, puis le masque d'avant rendu, et l'on regarde
            // encore. Un signal qu'il bloquait de moins est alors livré
            // par-dessus l'appel refait (rax est redevenu son numéro, rien
            // à convertir) : sigsuspend attend de nouveau après le
            // gestionnaire au lieu de rendre EINTR.
            Some(Arret::RendreMasque) => {
                crate::reprise::sans_gestionnaire(cadre);
                processus::avec(|p| signaux::rendre_masque_sauve(p, courante().tid));
            }
            Some(arret) => break arret,
            None => {
                // Plus rien à livrer : un appel interrompu sans qu'un
                // gestionnaire soit appelé est refait.
                crate::reprise::sans_gestionnaire(cadre);
                return;
            }
        }
    };
    // Le verrou du processus est rendu, les interruptions reviennent :
    // mourir prend du temps (rendre la mémoire).
    cpu::activer_interruptions();
    match arret {
        Arret::Sortie(code) => terminer(code),
        Arret::Force(signal, message) => mourir(signal, message),
        Arret::PlusDeMemoire => arreter_plus_de_memoire(),
        Arret::LimiteDure(secondes) => {
            mourir(linux::SIGKILL, format_args!("limite dure de temps de calcul atteinte (RLIMIT_CPU {} s)", secondes))
        }
        Arret::Limite(secondes) => {
            mourir(linux::SIGXCPU, format_args!("limite de temps de calcul atteinte (RLIMIT_CPU {} s)", secondes))
        }
        Arret::Signal(sig, signaux::Fin::ParDefaut) => mourir(signaux::signal(sig), "arrete par un signal"),
        Arret::Signal(sig, signaux::Fin::Suspendu) => mourir(
            signaux::signal(sig),
            "suspendu par un signal ; sans controle des taches (6l), personne ne pourrait le relancer : termine",
        ),
        Arret::Gestionnaire { .. } | Arret::RendreMasque => unreachable!("un gestionnaire, un masque : dans la boucle"),
    }
}

/// Appelle le gestionnaire de `sig` : son cadre posé, le masque et la pile
/// de secours du fil changés (`signal_delivered`). Un cadre impossible :
/// SIGSEGV forcé, livré au tour suivant de la boucle (`force_sigsegv` de
/// Linux) : à son gestionnaire s'il en a un, sinon il tue ; un cadre de
/// SIGSEGV impossible tue directement.
fn livrer(cadre: &mut Cadre, sig: u64, info: &signaux::Info, action: &signaux::Action, masque: u64, pile: signaux::PileDeSecours) {
    let tid = courante().tid;
    match crate::cadre_signal::poser_cadre(cadre, sig, info, action, masque, pile) {
        Ok(()) => processus::avec(|p| signaux::apres_livraison(p, tid, sig, action)),
        Err(_) => {
            let segv = linux::SIGSEGV.numero as u64;
            let t = processus::avec(|p| signaux::forcer_au_fil(p, tid, segv, signaux::Info::du_noyau(segv), sig == segv));
            if t.as_ref().is_some_and(|t| !core::ptr::eq(Arc::as_ptr(t), courante())) {
                signaux::reveiller(t);
            }
        }
    }
}

/// Ce que la sortie vers l'anneau 3 doit faire (voir `verifier_au_retour`),
/// décidé interruptions coupées.
fn decider() -> Option<Arret> {
    let t = courante();
    match t.fin.verrouiller().take() {
        Some(Fin::Sortie(code)) => return Some(Arret::Sortie(code)),
        Some(Fin::Signal(signal, message)) => return Some(Arret::Force(signal, message)),
        None => {}
    }
    if t.a_tuer.load(Ordering::Relaxed) {
        return Some(Arret::PlusDeMemoire);
    }
    // Le temps de calcul du processus : RLIMIT_CPU compte tous ses fils.
    let calcul = t.processus.as_ref().map_or(0, |p| p.temps_de_calcul());
    let verifier_temps = t.temps_a_verifier.swap(false, Ordering::Relaxed);
    let mut a_reveiller = None;
    let arret = processus::essayer_avec(|p| {
        let (courante, dure) = p.limite(processus::RLIMIT_CPU);
        let atteinte = |secondes: u64| calcul as u128 >= secondes as u128 * 1_000_000_000;
        let mut xcpu = None;
        if verifier_temps && courante != processus::INFINI {
            if dure != processus::INFINI && atteinte(dure) {
                return Some(Arret::LimiteDure(dure));
            }
            if atteinte(courante) {
                // Ici courante < dure (égales, la dure l'aurait emporté) :
                // relevée, elle ne la dépasse pas.
                p.changer_limite(processus::RLIMIT_CPU, (courante + 1, dure));
                // Au processus, comme Linux (`check_process_timers`) : un
                // autre fil le prendra peut-être, s'il ne le bloque pas et
                // que celui-ci le bloque.
                let sig = linux::SIGXCPU.numero as u64;
                // Du noyau (SI_KERNEL) : il passe toujours, même au-delà de
                // RLIMIT_SIGPENDING.
                a_reveiller = signaux::envoyer(p, sig, signaux::Destinataire::Processus, signaux::Info::du_noyau(sig), true)
                    .ok()
                    .flatten();
                xcpu = Some(courante);
            }
        }
        // Plus rien à livrer, mais un masque sauvé (rt_sigsuspend) : la
        // boucle reprend l'appel, puis le rend.
        let Some(livraison) = signaux::a_livrer(p, t.tid) else {
            return signaux::a_un_masque_sauve(p, t.tid).then_some(Arret::RendreMasque);
        };
        Some(match livraison {
            signaux::Livraison::Gestionnaire { sig, info, action } => {
                let (masque, pile) = signaux::masque_et_pile(p, t.tid);
                Arret::Gestionnaire { sig, info, action, masque, pile }
            }
            signaux::Livraison::Arret { sig, fin: signaux::Fin::ParDefaut }
                if xcpu.is_some() && sig == linux::SIGXCPU.numero as u64 => Arret::Limite(xcpu.unwrap_or(0)),
            signaux::Livraison::Arret { sig, fin } => Arret::Signal(sig, fin),
        })
    })
    .flatten();
    if a_reveiller.as_ref().is_some_and(|a| !core::ptr::eq(Arc::as_ptr(a), t)) {
        signaux::reveiller(a_reveiller);
    }
    arret
}

/// Pourquoi `verifier_au_retour` arrête le programme.
enum Arret {
    /// exit, exit_group.
    Sortie(i32),
    /// Un signal forcé, et son message.
    Force(Signal, Message),
    /// Le tueur OOM.
    PlusDeMemoire,
    /// RLIMIT_CPU : la limite dure (SIGKILL), ou la courante (SIGXCPU,
    /// laissé à son action par défaut), en secondes.
    LimiteDure(u64),
    Limite(u64),
    /// Un signal livré, qui l'arrête.
    Signal(u64, signaux::Fin),
    /// Un signal livré à son gestionnaire (cela n'arrête rien : la boucle
    /// pose son cadre et recommence), avec le masque et la pile de secours
    /// du fil à ce moment.
    Gestionnaire { sig: u64, info: signaux::Info, action: signaux::Action, masque: u64, pile: signaux::PileDeSecours },
    /// Rien à livrer, mais un masque sauvé à rendre (cela n'arrête rien non
    /// plus : la boucle reprend l'appel interrompu, rend le masque, et
    /// recommence).
    RendreMasque,
}

/// Une exception du programme en cours (une faute de page, une
/// instruction invalide...) : `signal`, et `raison`, le message de Linux et
/// le siginfo. Le fil garde la trace de l'exception (son vecteur, son code
/// d'erreur, l'adresse d'une faute de page : le sigcontext les montrera).
/// S'il a un gestionnaire pour ce signal, et ne le bloque pas, le signal lui
/// est envoyé, forcé, avec son siginfo : le gestionnaire sera appelé au
/// retour vers l'anneau 3 (`force_sig_fault`), sans message, comme sous
/// Linux. Sinon le programme sera arrêté au retour, même s'il ignore ou
/// bloque son signal (`force_sig_info_to_task`), et le message le dit.
pub fn forcer_par_faute(signal: Signal, raison: linux::Raison) {
    let t = courante();
    // Le code d'erreur d'une faute de page : avec « venue de l'anneau 3 »,
    // et « protection » pour une adresse du noyau (Linux ne dit pas au
    // programme si la page du noyau existe : `set_signal_archinfo`).
    let (code, cr2) = if raison.vecteur == 14 {
        let protection = if raison.cr2 >= crate::espace_utilisateur::ADRESSE_MAX { 1 } else { 0 };
        (raison.code | 4 | protection, raison.cr2)
    } else {
        (raison.code, t.exception[2].load(Ordering::Relaxed))
    };
    t.exception[0].store(raison.vecteur as u64, Ordering::Relaxed);
    t.exception[1].store(code, Ordering::Relaxed);
    t.exception[2].store(cr2, Ordering::Relaxed);
    let tid = t.tid;
    let sig = signal.numero as u64;
    let livree = processus::essayer_avec(|p| {
        let gestionnaire = signaux::gestionnaire_pour_faute(p, tid, sig);
        if gestionnaire {
            // C'est la tâche courante : rien à réveiller.
            let _ = signaux::forcer_au_fil(p, tid, sig, raison.info(signal), false);
        }
        gestionnaire
    }) == Some(true);
    if !livree {
        forcer(signal, raison)
    }
}
