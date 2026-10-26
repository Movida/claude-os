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
//!      a pu changer : l'état x87 et SSE (FXSAVE), les sélecteurs de
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
//! jusqu'à ce que l'une d'elles finisse (`attendre`, `dormir_tant_que`).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::cell::{Cell, UnsafeCell};
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicPtr, AtomicU64, AtomicU8, Ordering};

use crate::interruptions::Cadre;
use crate::linux::{self, Signal};
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

    /* Le premier départ d'un programme : la fin de bascule, puis les bases
       de GS à 0 (MSR GS_BASE et KERNEL_GS_BASE), pour qu'un programme ne
       trouve rien d'un précédent (les sélecteurs, la base de FS et l'état
       x87/SSE, eux, sont ceux de sa tâche, rétablis par basculer_vers).
       Puis le retour d'interruption : iretq vers le cadre préparé par
       executer(). */
    .global premier_depart
premier_depart:
    call fin_de_bascule
    xor eax, eax
    xor edx, edx
    mov ecx, 0xC0000101
    wrmsr
    mov ecx, 0xC0000102
    wrmsr
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

/// L'état x87 et SSE d'un programme, au format de FXSAVE.
#[repr(C, align(16))]
#[derive(Clone)]
pub struct EtatFpu([u8; 512]);

/// Ce que le noyau sait d'une tâche.
pub struct Tache {
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
    /// Son processus, pour un programme Linux (processus.rs).
    processus: Option<Arc<crate::processus::Entree>>,
    /// Pour un programme : son état x87/SSE, ses sélecteurs (DS, ES, FS,
    /// GS) et sa base de FS, quand il ne s'exécute pas.
    programme: Option<UnsafeCell<EtatProgramme>>,
    /// Elle s'est terminée : sa pile est à rendre.
    morte: AtomicBool,
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
    /// La tâche qui l'a créée, réveillée par `terminer` (elle attend sa fin,
    /// ou celle de l'une de ses tâches : `attendre`, `dormir_tant_que`) ;
    /// None pour l'inactive.
    attendant: Verrou<Option<Arc<Tache>>>,
    /// Le lien vers la tâche suivante de la file d'attente où elle attend
    /// (attente.rs), sous le verrou de cette file.
    lien_attente: Cell<*const Tache>,
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
}

/// Ce qu'un programme a de plus qu'une tâche du noyau.
struct EtatProgramme {
    fpu: EtatFpu,
    selecteurs: [u16; 4],
    base_fs: u64,
}

// SAFETY : les champs dans des UnsafeCell (`contexte`, `programme`) ne sont
// lus et écrits que par `basculer_vers`, interruptions coupées, sur notre
// seul processeur ; `lien_attente`, que sous le verrou de la file d'attente
// où elle est ; le reste est atomique ou sous Verrou.
unsafe impl Sync for Tache {}
unsafe impl Send for Tache {}

impl Tache {
    /// Une tâche, sans encore de premier départ. None : plus de mémoire,
    /// ou plus de place pour une pile (le maximum de fils).
    fn creer(nom: NomCourt, espace: u64, programme: bool, processus: Option<Arc<crate::processus::Entree>>) -> Option<Arc<Tache>> {
        let pile = Pile::allouer()?;
        let haut = pile.haut();
        let programme = if programme {
            // SAFETY : l'image de l'état initial, une constante.
            let fpu = unsafe { etat_fpu_initial.clone() };
            Some(UnsafeCell::new(EtatProgramme { fpu, selecteurs: [0; 4], base_fs: 0 }))
        } else {
            None
        };
        let t = Arc::new(Tache {
            nom: Verrou::new(nom),
            contexte: UnsafeCell::new(0),
            pile: Verrou::new(Some(pile)),
            haut,
            espace: AtomicU64::new(espace),
            processus,
            programme,
            morte: AtomicBool::new(false),
            code_sortie: AtomicI32::new(0),
            calcul: AtomicU64::new(0),
            lag: AtomicI64::new(0),
            // (La tâche inactive n'attend personne : elle ne doit jamais
            // quitter son rôle pour entrer dans la file des prêtes.)
            attendant: Verrou::new((en_service() && !core::ptr::eq(courante(), inactive())).then(courante_arc)),
            lien_attente: Cell::new(core::ptr::null()),
            reveil: AtomicU8::new(0),
            interruptible: AtomicBool::new(false),
            futex: Cell::new(None),
            sans_faute: AtomicBool::new(false),
            temps_a_verifier: AtomicBool::new(false),
            a_tuer: AtomicBool::new(false),
            fin: Verrou::new(None),
        });
        // La place est réservée : il n'y a jamais plus de tâches que de piles.
        TOUTES.verrouiller().push(t.clone());
        Some(t)
    }

    /// Prépare la pile pour un premier départ : six registres pour
    /// `basculer` (r12 : `r12`), l'adresse de `depart`, et, pour un
    /// programme, le cadre de son retour vers l'anneau 3 au-dessus.
    fn preparer(&self, depart: unsafe extern "C" fn(), r12: u64, cadre: Option<Cadre>) {
        let mut sommet = self.haut;
        // SAFETY : la pile vient d'être allouée pour cette tâche, qui n'a
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

    /// Ajoute `ns` nanosecondes à son temps de calcul (ordonnanceur.rs) ; un
    /// programme verra sa limite de temps de calcul vérifiée à son retour
    /// vers l'anneau 3.
    pub fn compter_calcul(&self, ns: u64) {
        if ns == 0 {
            return;
        }
        self.calcul.fetch_add(ns, Ordering::Relaxed);
        if self.programme.is_some() {
            self.temps_a_verifier.store(true, Ordering::Relaxed);
        }
    }

    /// Son temps de calcul, en nanosecondes.
    pub fn temps_de_calcul(&self) -> u64 {
        self.calcul.load(Ordering::Relaxed)
    }

    /// Le lien de file d'attente (attente.rs).
    pub fn lien_attente(&self) -> &Cell<*const Tache> {
        &self.lien_attente
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
}

/// La tâche courante.
static COURANTE: AtomicPtr<Tache> = AtomicPtr::new(core::ptr::null_mut());
/// Toutes les tâches vivantes, sauf l'inactive (pour le détecteur
/// d'interblocage, attente.rs ; bientôt /proc et les signaux). Réservée au
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
        nom: Verrou::new(NomCourt::de(b"inactive")),
        contexte: UnsafeCell::new(0),
        pile: Verrou::new(None),
        haut: 0,
        espace: AtomicU64::new(pagination::pml4_noyau()),
        processus: None,
        programme: None,
        morte: AtomicBool::new(false),
        code_sortie: AtomicI32::new(0),
        calcul: AtomicU64::new(0),
        lag: AtomicI64::new(0),
        attendant: Verrou::new(None),
        lien_attente: Cell::new(core::ptr::null()),
        reveil: AtomicU8::new(0),
        interruptible: AtomicBool::new(false),
        futex: Cell::new(None),
        sans_faute: AtomicBool::new(false),
        temps_a_verifier: AtomicBool::new(false),
        a_tuer: AtomicBool::new(false),
        fin: Verrou::new(None),
    };
    let t = Arc::into_raw(Arc::new(pile_demarrage)) as *mut Tache;
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
    // SAFETY : COURANTE désigne toujours une tâche vivante : la tâche
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
    /// Un signal (elle dormait interruptible) : l'appel rendra EINTR.
    Signal = 3,
}

/// Réveille `t`, qui dort, pour la raison `pourquoi` : elle redevient
/// prête. Si quelqu'un l'a déjà réveillée, la première raison reste (et
/// elle n'est mise qu'une fois dans la file des prêtes).
pub fn reveiller(t: Arc<Tache>, pourquoi: Reveil) {
    if t.reveil.compare_exchange(0, pourquoi as u8, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        ordonnanceur::rendre_prete(t, false);
    }
}

/// Un signal vient d'être mis en attente pour le processus `pid` : sa
/// tâche, si elle dort interruptible, est réveillée (le `signal_wake_up`
/// de Linux).
pub fn reveiller_par_signal(pid: u32) {
    let mut cible = None;
    pour_chaque(|t| {
        if t.processus.as_ref().is_some_and(|p| p.pid() == pid) && t.interruptible.load(Ordering::Relaxed) {
            cible = Some(t.clone());
        }
    });
    if let Some(t) = cible {
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
        || (t.programme.is_some() && processus::essayer_avec(|p| signaux::en_attente_non_bloque(p)) == Some(true))
}

/// Un Arc de la tâche courante (pour la mettre dans une file).
pub fn courante_arc() -> Arc<Tache> {
    let p = COURANTE.load(Ordering::Relaxed);
    // SAFETY : toute tâche vient d'un Arc (Arc::new, ou Arc::into_raw pour
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
    // SAFETY : interruptions coupées, sur notre seul processeur : personne
    // d'autre ne touche à l'état des deux tâches. Les registres et MSR
    // écrits sont ceux du programme de la nouvelle tâche (le noyau n'en
    // dépend pas) ; son espace a la moitié haute du noyau, on continue de
    // s'exécuter après avoir changé CR3 ; sa pile noyau est la sienne.
    unsafe {
        if let Some(p) = &ancienne.programme {
            let p = &mut *p.get();
            asm!("fxsave64 [{}]", in(reg) &mut p.fpu, options(nostack));
            asm!("mov {0:x}, ds", "mov {1:x}, es", "mov {2:x}, fs", "mov {3:x}, gs",
                 out(reg) p.selecteurs[0], out(reg) p.selecteurs[1], out(reg) p.selecteurs[2], out(reg) p.selecteurs[3],
                 options(nomem, nostack, preserves_flags));
            p.base_fs = cpu::lire_base_fs();
        }
        if let Some(p) = &nouvelle.programme {
            let p = &*p.get();
            asm!("fxrstor64 [{}]", in(reg) &p.fpu, options(nostack));
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

/// La fin d'une bascule, dans la tâche qui reprend (ou démarre) : si la
/// précédente est morte, sa pile est rendue ici, puisqu'on n'est plus
/// dessus, puis la référence qu'elle avait gardée pour elle-même (le
/// `put_task_stack` et le `put_task_struct` de `finish_task_switch`).
/// Interruptions coupées.
#[unsafe(no_mangle)]
extern "C" fn fin_de_bascule() {
    let morte = A_RENDRE.swap(core::ptr::null_mut(), Ordering::Relaxed);
    if !morte.is_null() {
        // SAFETY : `morte` vient d'Arc::into_raw dans `terminer`, rendu une
        // seule fois, ici ; elle ne s'exécute plus.
        let t = unsafe { Arc::from_raw(morte) };
        drop(t.pile.verrouiller().take());
    }
}

/// Attend la fin de la tâche `t` : la tâche courante dort jusqu'à ce que
/// `terminer` la réveille. Sans réveil perdu : la fin est vérifiée, et
/// l'attente inscrite, interruptions coupées, comme la fin elle-même ; sur
/// un seul processeur, rien ne peut se glisser entre les deux.
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

/// Lance un programme, prêt aussitôt : `processus` son processus, `pml4`
/// son espace d'adressage, `entree` son point d'entrée, `pile` le sommet
/// de sa pile. None : pas de pile noyau pour sa tâche.
pub fn lancer_programme(nom: NomCourt, processus: Arc<crate::processus::Entree>, pml4: u64, entree: u64, pile: u64)
    -> Option<Arc<Tache>> {
    let t = Tache::creer(nom, pml4, true, Some(processus))?;
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
    ordonnanceur::rendre_prete(t.clone(), true);
    Some(t)
}

/// La fonction d'une tâche du noyau.
type FonctionNoyau = Box<dyn FnOnce() + Send>;

/// Lance `f` dans une tâche du noyau nommée `nom`, prête aussitôt ; None :
/// pas de pile pour la tâche.
pub fn lancer_noyau(nom: NomCourt, f: impl FnOnce() + Send + 'static) -> Option<Arc<Tache>> {
    let t = Tache::creer(nom, pagination::pml4_noyau(), false, None)?;
    // Un pointeur simple vers la fermeture, pour r12 : une boîte de boîte.
    let f: Box<FonctionNoyau> = Box::new(Box::new(f));
    t.preparer(depart_noyau, Box::into_raw(f) as u64, None);
    ordonnanceur::rendre_prete(t.clone(), true);
    Some(t)
}

/// Le corps d'une tâche du noyau (depart_noyau) : sa fonction, puis sa fin.
#[unsafe(no_mangle)]
extern "C" fn tache_noyau(f: *mut FonctionNoyau) -> ! {
    // SAFETY : `f` vient de Box::into_raw dans `executer_noyau`, rendu une
    // seule fois, ici.
    let f = unsafe { Box::from_raw(f) };
    f();
    terminer(0)
}

/// Termine la tâche courante : elle est morte, réveille qui attend sa fin,
/// quitte la file des prêtes et cède le processeur pour toujours ; la
/// tâche suivante rendra sa pile (fin de bascule). Appelée en haut de sa
/// pile (retour vers l'anneau 3, ou fin de sa fonction) : rien de ce que
/// tiennent les cadres en dessous n'est perdu.
pub fn terminer(code: i32) -> ! {
    let t = courante();
    t.code_sortie.store(code, Ordering::Relaxed);
    if let Some(p) = &t.processus {
        // La tâche passe d'abord sur l'espace du noyau, interruptions
        // coupées : si elle est préemptée pendant qu'elle rend celui du
        // programme (long, et préemptible), la bascule qui la reprendra
        // chargera la PML4 du noyau, jamais des tables qu'on détruit.
        let interruptions = cpu::couper_interruptions();
        t.espace.store(pagination::pml4_noyau(), Ordering::Relaxed);
        // SAFETY : la PML4 du noyau est complète.
        unsafe { pagination::activer(pagination::pml4_noyau()) };
        if interruptions {
            cpu::activer_interruptions();
        }
        p.terminer(code);
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
/// limite de temps de calcul, un signal qu'il s'est envoyé), en disant
/// pourquoi : le message de Linux dans son journal, puis le code de sortie
/// 128 + signal. Seulement au retour vers l'anneau 3 (`verifier_au_retour`).
fn mourir(signal: Signal, raison: impl fmt::Display) -> ! {
    afficherln!("[noyau] {} : {} ({})", courante().nom(), raison, signal.nom);
    terminer(128 + signal.numero as i32)
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

/// exit et exit_group : le programme finira au retour vers l'anneau 3,
/// avec ce code. Elle l'emporte sur tout ce qui pouvait l'attendre (sous
/// Linux, `do_exit` part aussitôt, sans regarder les signaux).
pub fn prevoir_sortie(code: i32) {
    *courante().fin.verrouiller() = Some(Fin::Sortie(code));
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
    *courante().nom.verrouiller() = nom;
}

/// Appelée à chaque tic d'horloge, interruptions coupées : l'ordonnanceur
/// compte le temps de calcul de la tâche courante, et lui fait céder le
/// processeur si elle a fini sa tranche ; les échéances passées réveillent
/// leurs tâches.
pub fn tic() {
    ordonnanceur::tic();
    crate::attente::tic();
}

/// Le temps de calcul de la tâche courante, en nanosecondes
/// (CLOCK_PROCESS_CPUTIME_ID, temps.rs).
pub fn temps_de_calcul() -> u64 {
    courante().calcul.load(Ordering::Relaxed)
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
///      ceux que le programme s'est envoyés, et SIGXCPU.
/// La décision est prise interruptions coupées, et la fonction revient
/// interruptions coupées quand il n'y a rien à faire : rien ne peut plus
/// arriver entre la dernière vérification et le retour (sysretq ou iretq
/// rétablissent les interruptions du programme) ; un signal envoyé par une
/// interruption tombée avant est vu, un autre après attend l'entrée
/// suivante. Linux boucle ainsi jusqu'à ce qu'il n'y ait plus rien à faire :
/// céder le processeur si l'ordonnanceur le demande, puis tout revérifier
/// (6f y ajoutera les gestionnaires de signaux).
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
///     (setrlimit), et le shell de 6k aura `ulimit -t`.
pub fn verifier_au_retour() {
    let arret = loop {
        cpu::couper_interruptions();
        // Céder le processeur d'abord, s'il le faut : on revient ici quand
        // la tâche le retrouve, et tout est revérifié.
        if ordonnanceur::besoin_de_ceder() {
            ordonnanceur::ordonnancer();
            continue;
        }
        match decider() {
            Some(arret) => break arret,
            None => return,
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
            "suspendu par un signal ; sans controle des taches (6k), personne ne pourrait le relancer : termine",
        ),
        Arret::Signal(sig, signaux::Fin::Gestionnaire) => mourir(signaux::signal(sig), GESTIONNAIRE_EN_6F),
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
    let calcul = t.calcul.load(Ordering::Relaxed);
    let verifier_temps = t.temps_a_verifier.swap(false, Ordering::Relaxed);
    processus::essayer_avec(|p| {
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
                // Au processus, comme Linux (`check_process_timers`).
                signaux::envoyer(p, linux::SIGXCPU.numero as u64, signaux::Destinataire::Processus);
                xcpu = Some(courante);
            }
        }
        signaux::a_livrer(p).map(|(sig, comment)| match (comment, xcpu) {
            (signaux::Fin::ParDefaut, Some(secondes)) if sig == linux::SIGXCPU.numero as u64 => Arret::Limite(secondes),
            _ => Arret::Signal(sig, comment),
        })
    })
    .flatten()
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
    /// Un signal livré.
    Signal(u64, signaux::Fin),
}

/// Le message d'un signal qui devrait appeler un gestionnaire.
const GESTIONNAIRE_EN_6F: &str = "gestionnaire enregistre, pas encore appele (livraison des signaux en 6f)";

/// Une exception du programme en cours (une faute de page, une
/// instruction invalide...) : `signal` et le message de Linux, `raison`.
/// Il sera arrêté au retour vers l'anneau 3. S'il a un gestionnaire pour
/// ce signal, et ne le bloque pas, Linux l'appellerait : le message le dit.
/// Sinon, comme Linux, une faute tue le programme même s'il ignore ou
/// bloque son signal (`force_sig_info_to_task`).
pub fn forcer_par_faute(signal: Signal, raison: impl fmt::Display) {
    let gestionnaire = processus::essayer_avec(|p| p.signaux.gestionnaire_pour_faute(signal.numero as u64)) == Some(true);
    if gestionnaire {
        forcer(signal, format_args!("{} ; {}", raison, GESTIONNAIRE_EN_6F))
    } else {
        forcer(signal, raison)
    }
}
