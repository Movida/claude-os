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
//!      morte, rendre sa pile, et la référence qu'elle gardait sur
//!      elle-même pour cela (une tâche ne peut pas rendre la pile sur
//!      laquelle elle s'exécute : c'est la suivante qui le fait, le
//!      `finish_task_switch` de Linux).
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
use core::cell::{Cell, UnsafeCell};
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use crate::attente::EntreeAttente;
use crate::faillible::{self, VecFaillible};
use crate::interruptions::Cadre;
use crate::linux::{self, Signal};
use crate::partage::Arc;
use crate::programmes::NomCourt;
use crate::verrou::Verrou;
use crate::vmalloc::Pile;
use crate::{cpu, gdt, ordonnanceur, pagination, processus, signaux};

global_asm!(
    r#"
    .section .text
    /* basculer(ancien : *mut u64 (rdi), nouveau : *const u64 (rsi)) */
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
    ret

    /* Le premier départ d'un fil de programme : la fin de bascule, puis les
       bases de GS à 0 (MSR GS_BASE et KERNEL_GS_BASE), pour qu'un programme
       ne trouve rien d'un précédent (les sélecteurs, la base de FS et l'état
       x87/SSE, eux, sont ceux de sa tâche, rétablis par basculer_vers ; un
       programme ne peut pas changer la base de GS, arch_prctl la refuse).
       Puis `debut_de_fil`, la sortie ordinaire vers l'anneau 3 (le
       `ret_from_fork` de Linux), et le retour d'interruption : iretq vers
       le cadre préparé par executer() ou par clone. */
    .global premier_depart
premier_depart:
    call fin_de_bascule
    xor eax, eax
    xor edx, edx
    mov ecx, 0xC0000101
    wrmsr
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
    fn basculer(ancien: *mut u64, nouveau: *const u64);
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
    /// Elle s'est terminée : sa pile est à rendre.
    morte: AtomicBool,
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
    /// Son temps de calcul, en nanosecondes : compté par l'ordonnanceur à
    /// chaque tic et à chaque bascule, d'après le temps monotone (le TSC
    /// quand il est fiable : le `sum_exec_runtime` de Linux), en anneau 3
    /// ou dans le noyau pour elle. Atomique : le gestionnaire d'horloge le
    /// compte sans prendre de verrou.
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
    /// Pourquoi elle a été réveillée (`Reveil`, en u8) : le premier qui la
    /// réveille l'écrit ; 0 tant que personne ne l'a fait.
    reveil: AtomicU8,
    /// Elle dort, et un signal peut la réveiller (TASK_INTERRUPTIBLE).
    interruptible: AtomicBool,
    /// Le futex qu'elle attend (futex.rs), sous le verrou de son seau.
    futex: Cell<Option<crate::futex::Attente>>,
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
// lus et écrits que par `basculer_vers`, interruptions coupées, sur notre
// seul processeur (UNIPROCESSEUR : avec plusieurs, une tâche ne tourne que
// sur un à la fois, ce que la bascule devra garantir, le `on_cpu` de
// Linux) ; `entree_attente`, que sous le verrou de la file d'attente
// où elle est inscrite ; le reste est atomique ou sous Verrou.
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
        let t = Arc::new(Tache {
            tid,
            nom: Verrou::new(nom),
            contexte: UnsafeCell::new(0),
            pile: Verrou::new(Some(pile)),
            haut,
            espace: AtomicU64::new(espace),
            processus,
            programme,
            morte: AtomicBool::new(false),
            webassembly: AtomicBool::new(false),
            ecrire_tid: AtomicU64::new(0),
            effacer_tid: AtomicU64::new(0),
            liste_robuste: AtomicU64::new(0),
            code_sortie: AtomicI32::new(0),
            calcul: AtomicU64::new(0),
            lag: AtomicI64::new(0),
            // (La tâche inactive n'attend personne : elle ne doit jamais
            // quitter son rôle pour entrer dans la file des prêtes.)
            attendant: Verrou::new((noyau && en_service() && !core::ptr::eq(courante(), inactive())).then(courante_arc)),
            entree_attente: EntreeAttente::new(),
            reveil: AtomicU8::new(0),
            interruptible: AtomicBool::new(false),
            futex: Cell::new(None),
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
        })
        .map_err(|_| Manque::Memoire)?;
        Ok(t)
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
        self.morte.load(Ordering::Relaxed)
    }

    /// Son processus, pour un programme Linux.
    pub fn processus(&self) -> Option<&Arc<crate::processus::Entree>> {
        self.processus.as_ref()
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

    /// Dort-elle, interruptible ?
    pub fn dort_interruptible_maintenant(&self) -> bool {
        self.interruptible.load(Ordering::Relaxed)
    }

    /// Prévoit sa fin par `signal`, avec ce message (voir `forcer`).
    pub fn forcer(&self, signal: Signal, raison: impl fmt::Display) {
        let mut fin = self.fin.verrouiller();
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
    pub fn futex(&self) -> &Cell<Option<crate::futex::Attente>> {
        &self.futex
    }

    /// Faut-il servir une faute de page du noyau dans une copie pour elle ?
    pub fn faute_servie(&self) -> bool {
        !self.sans_faute.load(Ordering::Relaxed)
    }

    /// Avant de s'endormir : personne ne l'a encore réveillée.
    pub fn preparer_sommeil(&self) {
        self.reveil.store(0, Ordering::Relaxed);
    }

    /// Elle dort, et un signal peut la réveiller (ou plus).
    pub fn dort_interruptible(&self, oui: bool) {
        self.interruptible.store(oui, Ordering::Relaxed);
    }

    /// Pourquoi elle a été réveillée (par une file, si personne ne l'a dit :
    /// un réveil sans raison se revérifie de toute façon).
    pub fn raison_du_reveil(&self) -> Reveil {
        match self.reveil.load(Ordering::Relaxed) {
            2 => Reveil::Echeance,
            3 => Reveil::Signal,
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

/// La tâche courante.
/// UNIPROCESSEUR : une seule tâche courante, comme la tâche inactive et
/// celle à rendre ci-dessous ; avec plusieurs processeurs, une par
/// processeur, dans sa zone propre (le `current` de Linux, lu par GS).
static COURANTE: AtomicPtr<Tache> = AtomicPtr::new(core::ptr::null_mut());
/// Toutes les tâches vivantes, sauf l'inactive (pour le détecteur
/// d'interblocage, attente.rs ; pour trouver un fil par son numéro :
/// tkill, /proc, sched_getaffinity ; RLIMIT_NPROC, sysinfo). Réservée au
/// démarrage pour autant de tâches que de piles : elle ne grandit jamais
/// pendant un programme.
static TOUTES: Verrou<Vec<Arc<Tache>>> = Verrou::new(Vec::new());
/// La tâche qui vient de mourir, et qu'il faut rendre à la fin de la
/// bascule qui suit (sa pile, puis la référence qu'elle avait laissée
/// pour elle-même) : un Arc mis de côté par `terminer`. Sans lui, la file
/// des prêtes, qui la lâche quand elle meurt, pouvait tenir la dernière
/// référence : la tâche aurait rendu sa pile en s'exécutant dessus.
static A_RENDRE: AtomicPtr<Tache> = AtomicPtr::new(core::ptr::null_mut());
/// La tâche inactive, gardée pour toujours (elle ne meurt pas).
static INACTIVE: AtomicPtr<Tache> = AtomicPtr::new(core::ptr::null_mut());

/// Fait du code en cours (noyau_main, sur la pile du démarrage) la tâche
/// inactive. Avant toute autre tâche.
pub fn initialiser() {
    let pile_demarrage = Tache {
        tid: 0,
        nom: Verrou::new(NomCourt::de(b"inactive")),
        contexte: UnsafeCell::new(0),
        pile: Verrou::new(None),
        haut: 0,
        espace: AtomicU64::new(pagination::pml4_noyau()),
        processus: None,
        programme: None,
        morte: AtomicBool::new(false),
        webassembly: AtomicBool::new(false),
        ecrire_tid: AtomicU64::new(0),
        effacer_tid: AtomicU64::new(0),
        liste_robuste: AtomicU64::new(0),
        code_sortie: AtomicI32::new(0),
        calcul: AtomicU64::new(0),
        lag: AtomicI64::new(0),
        attendant: Verrou::new(None),
        entree_attente: EntreeAttente::new(),
        reveil: AtomicU8::new(0),
        interruptible: AtomicBool::new(false),
        futex: Cell::new(None),
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
    };
    let t = Arc::into_raw(Arc::new(pile_demarrage).expect("plus de memoire pour la tache du demarrage")) as *mut Tache;
    INACTIVE.store(t, Ordering::Relaxed);
    COURANTE.store(t, Ordering::Relaxed);
    TOUTES.verrouiller().try_reserve_exact(crate::vmalloc::max_threads()).expect("plus de memoire pour la table des taches");
}

/// Appelle `f` sur chaque tâche vivante (sauf l'inactive), table tenue :
/// `f` doit être court.
pub fn pour_chaque(mut f: impl FnMut(&Arc<Tache>)) {
    for t in TOUTES.verrouiller().iter() {
        f(t);
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
    !COURANTE.load(Ordering::Relaxed).is_null()
}

/// La tâche courante.
pub fn courante() -> &'static Tache {
    // SAFETY: COURANTE désigne toujours une tâche vivante : la tâche
    // courante ne peut pas être rendue pendant qu'elle s'exécute (sa
    // structure vit tant qu'un Arc la tient : celui de qui l'a créée, et
    // la tâche inactive pour toujours).
    unsafe { &*COURANTE.load(Ordering::Relaxed) }
}

/// Pourquoi une tâche qui dormait a été réveillée (attente.rs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reveil {
    /// Par la file où elle attendait : ce qu'elle attendait est peut-être
    /// là (elle revérifie).
    Reveillee = 1,
    /// Son échéance est passée.
    Echeance = 2,
    /// Un signal (elle dormait interruptible) : l'appel rendra EINTR, ou
    /// sera refait (reprise.rs).
    Signal = 3,
}

/// Réveille `t`, qui dort, pour la raison `pourquoi` : elle redevient
/// prête. Si quelqu'un l'a déjà réveillée, la première raison reste (et
/// elle n'est mise qu'une fois dans la file des prêtes). Rend vrai si c'est
/// ce réveil-ci qui compte (le `try_to_wake_up` de Linux, qui rend faux pour
/// une tâche déjà réveillée) : un réveil exclusif qui n'a réveillé personne
/// passe à la suivante (attente.rs).
pub fn reveiller(t: Arc<Tache>, pourquoi: Reveil) -> bool {
    if t.reveil.compare_exchange(0, pourquoi as u8, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        ordonnanceur::rendre_prete(t, false);
        return true;
    }
    false
}

/// Un signal vient d'être mis en attente pour le fil `t`, qui ne le bloque
/// pas : s'il dort interruptible, il est réveillé (le `signal_wake_up` de
/// Linux).
pub fn reveiller_par_signal(t: Arc<Tache>) {
    if t.interruptible.load(Ordering::Relaxed) {
        reveiller(t, Reveil::Signal);
    }
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
    let p = COURANTE.load(Ordering::Relaxed);
    // SAFETY: toute tâche vient d'un Arc (Arc::new, ou Arc::into_raw pour
    // l'inactive), toujours tenu tant qu'elle s'exécute (voir `courante`) :
    // en prendre un de plus est permis.
    unsafe {
        Arc::increment_strong_count(p);
        Arc::from_raw(p)
    }
}

/// La tâche inactive.
pub fn inactive() -> *const Tache {
    INACTIVE.load(Ordering::Relaxed)
}

/// Passe le processeur de la tâche courante à `nouvelle` (voir l'en-tête),
/// pour l'ordonnanceur. Revient quand une autre tâche rend la main à la
/// courante. Interruptions coupées pendant la bascule ; leur état est
/// rétabli au retour.
pub fn basculer_vers(nouvelle: &Tache) {
    let interruptions = cpu::couper_interruptions();
    let ancienne = courante();
    // SAFETY: interruptions coupées, sur notre seul processeur : personne
    // d'autre ne touche à l'état des deux tâches (UNIPROCESSEUR, voir
    // `unsafe impl Sync for Tache`). Les registres et MSR
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
            // du descripteur (comme Linux, `load_seg_legacy`).
            asm!("mov ds, {0:x}", "mov es, {1:x}", "mov fs, {2:x}", "mov gs, {3:x}",
                 in(reg) p.selecteurs[0], in(reg) p.selecteurs[1], in(reg) p.selecteurs[2], in(reg) p.selecteurs[3],
                 options(nostack, preserves_flags));
            cpu::ecrire_base_fs(p.base_fs);
        }
        let espace = nouvelle.espace.load(Ordering::Relaxed);
        if pagination::courante() != espace {
            pagination::activer(espace);
        }
        if nouvelle.haut != 0 {
            gdt::definir_pile_noyau(nouvelle.haut);
        }
        COURANTE.store(nouvelle as *const Tache as *mut Tache, Ordering::Relaxed);
        basculer(ancienne.contexte.get(), nouvelle.contexte.get());
    }
    fin_de_bascule();
    if interruptions {
        cpu::activer_interruptions();
    }
}

/// Ce que porte une pile neuve : là où ce motif reste, elle n'est jamais descendue (le
/// `stack_not_used` de CONFIG_DEBUG_STACK_USAGE, chez nous toujours là : 16 Kio à écrire à
/// la naissance d'un fil, contre une page de garde qui ne dit rien de la marge qui restait
/// jusqu'au jour où un chemin de plus la franchit). Écarté : une limite vérifiée à chaque
/// appel système, qui ne voit rien de ce qui descend et remonte entre deux.
const MOTIF_PILE: u64 = 0x5A5A_5A5A_5A5A_5A5A;

/// La pile qui est descendue le plus bas, parmi celles des tâches finies.
static PILE_LA_PLUS_PROFONDE: AtomicUsize = AtomicUsize::new(0);

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
pub fn plus_grande_profondeur() -> usize {
    let ici = courante().pile.verrouiller().as_ref().map_or(0, profondeur);
    PILE_LA_PLUS_PROFONDE.load(Ordering::Relaxed).max(ici)
}

/// La fin d'une bascule, dans la tâche qui reprend (ou démarre) : si la
/// précédente est morte, sa pile est rendue ici, puisqu'on n'est plus
/// dessus, puis la référence qu'elle avait gardée pour elle-même (le
/// `put_task_stack` et le `put_task_struct` de `finish_task_switch`).
/// Interruptions coupées.
#[unsafe(no_mangle)]
extern "C" fn fin_de_bascule() {
    let morte = A_RENDRE.swap(core::ptr::null_mut(), Ordering::Relaxed);
    if !morte.is_null() {
        // SAFETY: `morte` vient d'Arc::into_raw dans `terminer`, rendu une
        // seule fois, ici ; elle ne s'exécute plus.
        let t = unsafe { Arc::from_raw(morte) };
        if let Some(p) = t.pile.verrouiller().take() {
            PILE_LA_PLUS_PROFONDE.fetch_max(profondeur(&p), Ordering::Relaxed);
        }
        // Un fil de programme : sa tâche rendue (si rien d'autre ne la
        // tient), son processus est peut-être fini.
        let processus = t.processus.clone();
        drop(t);
        if let Some(p) = processus {
            p.fil_disparu();
        }
    }
}

/// Attend la fin de la tâche `t` : la tâche courante dort jusqu'à ce que
/// `terminer` la réveille. Sans réveil perdu : la fin est vérifiée, et
/// l'attente inscrite, interruptions coupées, comme la fin elle-même.
/// UNIPROCESSEUR : rien ne peut se glisser entre les deux ; avec plusieurs
/// processeurs, la fin et l'inscription sous un même verrou.
pub fn attendre(t: &Tache) -> i32 {
    dormir_tant_que(|| !t.est_morte());
    t.code_sortie.load(Ordering::Relaxed)
}

/// La tâche courante dort tant que `encore` le dit, réveillée par la fin
/// de l'une des tâches qu'elle a créées (le `wait` d'un parent : init qui
/// recueille ses enfants, programmes.rs). Sans réveil perdu : `encore` est
/// vérifié interruptions coupées, comme la fin elle-même.
pub fn dormir_tant_que(encore: impl Fn() -> bool) {
    let interruptions = cpu::couper_interruptions();
    while encore() {
        courante().preparer_sommeil();
        ordonnanceur::retirer_courante();
        ordonnanceur::ordonnancer();
    }
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
    ordonnanceur::rendre_prete(t.clone(), true);
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
    if t.interruptible.load(Ordering::Relaxed) {
        reveiller(t, Reveil::Signal);
    }
}

/// Le nombre de tâches (sysinfo : `procs`, le `nr_threads` de Linux).
pub fn nombre() -> usize {
    TOUTES.verrouiller().len() + 1
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
        // SAFETY: la PML4 du noyau est complète.
        unsafe { pagination::activer(pagination::pml4_noyau()) };
        if interruptions {
            cpu::activer_interruptions();
        }
        p.usage().garder(&t.usage);
        p.fil_termine(t.tid, code);
        // Le dernier fil ferme les fichiers du processus (fil_termine) :
        // leurs sockets, maintenant (la fermeture différée, socket.rs).
        crate::reseau::socket::fermer_les_differees();
    }
    cpu::couper_interruptions();
    t.morte.store(true, Ordering::Relaxed);
    // Une référence à elle-même, pour la fin de bascule qui rendra sa pile.
    A_RENDRE.store(Arc::into_raw(courante_arc()) as *mut Tache, Ordering::Relaxed);
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
    ordonnanceur::retirer_courante();
    ordonnanceur::ordonnancer();
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
/// Linux), en disant ce qu'il occupait. Le verrou du processus est rendu
/// avant d'arrêter : `terminer` ne revient pas, et un verrou emporté dans
/// une tâche abandonnée ne serait jamais rendu.
fn arreter_plus_de_memoire() -> ! {
    let (virtuelle, en_place, fichiers, tables) = processus::avec(|p| {
        let e = &p.memoire.espace;
        (p.memoire.taille_virtuelle(), e.pages() as u64 * 4096, e.pages_fichier() as u64 * 4096, e.tables() as u64 * 4096)
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
    crate::attente::tic();
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
/// interruptions coupées quand il n'y a rien à faire : rien ne peut plus
/// arriver entre la dernière vérification et le retour (sysretq ou iretq
/// rétablissent les interruptions du programme) ; un signal envoyé par une
/// interruption tombée avant est vu, un autre après attend l'entrée
/// suivante. Linux boucle ainsi jusqu'à ce qu'il n'y ait plus rien à faire :
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
            ordonnanceur::ordonnancer();
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
