//! Les tâches : le noyau, et le programme qu'il exécute.
//!
//! Un programme ne s'exécute pas « dans » une fonction du noyau qui
//! l'appellerait : c'est une TÂCHE à part, avec sa propre pile noyau (celle
//! que prend le processeur quand le programme entre dans le noyau, par un
//! appel système ou une interruption) et son propre état des registres. Le
//! noyau lui passe le processeur en BASCULANT de sa tâche à celle du
//! programme ; le programme le rend en basculant dans l'autre sens, quand
//! il se termine. C'est la primitive de l'ordonnanceur de l'étape 6, qui
//! basculera de programme en programme à chaque tic d'horloge.
//!
//! Basculer (`basculer`, le __switch_to_asm de Linux) :
//!   1. empiler les registres que l'ABI dit « préservés par l'appelé »
//!      (rbx, rbp, r12 à r15 : les autres, l'appelant de `basculer` les a
//!      déjà sauvés s'il en avait besoin) ;
//!   2. ranger RSP dans le contexte de l'ancienne tâche ;
//!   3. prendre le RSP du contexte de la nouvelle ;
//!   4. dépiler ses registres, et `ret` : on revient là où la nouvelle tâche
//!      avait elle-même appelé `basculer`.
//! Tout l'état d'une tâche suspendue tient donc dans sa pile, et son
//! contexte n'est que l'adresse de son sommet.
//!
//! Une tâche neuve n'a jamais appelé `basculer` : on lui prépare une pile
//! qui y ressemble (six registres à zéro, puis l'adresse de
//! `premier_depart`), et, au-dessus, le cadre complet d'un retour vers
//! l'anneau 3 (le pt_regs du programme, comme pour fork dans Linux).
//! `premier_depart` remet à zéro les segments et leurs bases, puis passe par
//! le retour ordinaire des interruptions (iretq) : le programme démarre à
//! son point d'entrée, tous registres à zéro, sur sa pile.
//!
//! Ce qui reste à faire avec l'ordonnanceur (étape 6) : une pile noyau par
//! tâche (aujourd'hui une seule, dans linker.ld : un programme à la fois),
//! et la sauvegarde, à chaque bascule, de ce que les registres ne disent
//! pas : base de FS (arch_prctl), état SSE (XSAVE).

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use crate::interruptions::Cadre;
use crate::linux::{self, Signal};
use crate::programmes::NomCourt;
use crate::verrou::Verrou;
use crate::{cpu, gdt, pagination, processus, signaux, temps};

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

    /* Le premier départ d'un programme. Les sélecteurs de données à 0 (en
       64 bits, un programme n'en a pas besoin) ; les bases de FS et de GS
       à 0 (MSR FS_BASE, GS_BASE et KERNEL_GS_BASE), pour qu'un programme
       ne trouve rien d'un précédent : il fixera sa base de FS lui-même
       (arch_prctl). Le x87 et SSE à leur état initial, tous registres de
       données à zéro (voir sse.rs). Puis le retour d'interruption : iretq vers le cadre préparé
       par executer(). */
    .global premier_depart
premier_depart:
    xor eax, eax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    xor edx, edx
    mov ecx, 0xC0000100
    wrmsr
    mov ecx, 0xC0000101
    wrmsr
    mov ecx, 0xC0000102
    wrmsr
    fxrstor [rip + etat_fpu_initial]
    jmp retour_interruption

    /* L'état x87 et SSE d'un programme qui démarre, au format de fxsave
       (512 octets, alignés sur 16) : mot de contrôle x87 0x037F (toutes
       les exceptions masquées, double précision étendue, arrondi au plus
       près : l'état de `fninit`), MXCSR 0x1F80 (la valeur de l'ABI), et
       tout le reste à zéro : registres ST0-ST7 (alias MM0-MM7), XMM0-XMM15,
       mot d'état, étiquettes. */
    .section .rodata
    .balign 16
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
    // La pile noyau du programme (linker.ld).
    static __pile_programme_haut: u8;
}

/// Les contextes des deux tâches : le RSP de chacune, quand elle ne
/// s'exécute pas.
struct Contextes {
    noyau: u64,
    programme: u64,
}

/// Lus et écrits par `basculer`, interruptions coupées, sur un seul
/// processeur : pas de Verrou (on ne peut pas tenir un verrou à travers
/// une bascule, le code qui le rendrait ne s'exécuterait pas avant le
/// retour).
struct ContextesPartages(UnsafeCell<Contextes>);
// SAFETY : voir plus haut.
unsafe impl Sync for ContextesPartages {}
static CONTEXTES: ContextesPartages = ContextesPartages(UnsafeCell::new(Contextes { noyau: 0, programme: 0 }));

/// Le code de sortie du dernier programme, posé par `terminer`.
static CODE_SORTIE: AtomicI32 = AtomicI32::new(0);

/// Un programme s'exécute-t-il ? (Sa tâche existe : en anneau 3, ou dans le
/// noyau pour lui.)
static EN_COURS: AtomicBool = AtomicBool::new(false);
/// Son nom, pour les messages.
static NOM: Verrou<NomCourt> = Verrou::new(NomCourt::VIDE);
/// Ses tics de calcul : un de plus à chaque tic d'horloge qui le trouve en
/// train de s'exécuter, en anneau 3 ou dans le noyau pour lui (`tic`). C'est
/// le `account_process_tick` de Linux, qui compte lui aussi le temps tic par
/// tic. Atomique plutôt que dans le processus : le gestionnaire d'horloge
/// le compte, interruptions coupées, sans prendre de verrou.
static CALCUL: AtomicU64 = AtomicU64::new(0);
/// Le programme est à tuer, faute de mémoire, dès qu'il retourne vers
/// l'anneau 3 : une page lui a manqué pendant une copie du noyau (un appel
/// système qui écrit dans sa mémoire). L'appel ne peut pas s'arrêter au
/// milieu de ce qu'il fait : il rend EFAULT, et le programme est tué au
/// retour (Linux lui envoie de même un SIGKILL, délivré au retour).
static A_TUER: AtomicBool = AtomicBool::new(false);

/// Le RFLAGS d'un programme qui démarre : IF (interruptions acceptées) et
/// le bit 1, toujours à 1. IOPL = 0 : pas de `in`, `out`, `cli`, `sti`.
const RFLAGS_INITIAL: u64 = 1 << 9 | 1 << 1;

/// Exécute un programme : `pml4` son espace d'adressage, `entree` son point
/// d'entrée, `pile` le sommet de sa pile. Revient quand il se termine, avec
/// son code de sortie.
pub fn executer(nom: NomCourt, pml4: u64, entree: u64, pile: u64) -> i32 {
    *NOM.verrouiller() = nom;
    let haut = &raw const __pile_programme_haut as u64;
    let cadre = (haut - size_of::<Cadre>() as u64) as *mut Cadre;
    let retour = cadre as u64 - 8;
    let depart = retour - 6 * 8;
    // SAFETY : la pile noyau du programme est à nous (linker.ld), et
    // aucun programme ne s'exécute : personne ne s'en sert. On y écrit, de
    // haut en bas, le cadre du retour vers l'anneau 3, l'adresse de
    // premier_depart, et six registres à zéro pour `basculer`.
    unsafe {
        cadre.write(Cadre {
            r15: 0, r14: 0, r13: 0, r12: 0, r11: 0, r10: 0, r9: 0, r8: 0,
            rbp: 0, rdi: 0, rsi: 0, rdx: 0, rcx: 0, rbx: 0, rax: 0,
            vecteur: 0,
            code_erreur: 0,
            rip: entree,
            cs: gdt::CODE_UTILISATEUR as u64,
            rflags: RFLAGS_INITIAL,
            rsp: pile,
            ss: gdt::DONNEES_UTILISATEUR as u64,
        });
        (retour as *mut u64).write(premier_depart as *const () as u64);
        core::ptr::write_bytes(depart as *mut u64, 0, 6);
        (*CONTEXTES.0.get()).programme = depart;
    }
    let interruptions = cpu::couper_interruptions();
    CALCUL.store(0, Ordering::Relaxed);
    A_TUER.store(false, Ordering::Relaxed);
    *FIN.verrouiller() = None;
    EN_COURS.store(true, Ordering::Relaxed);
    // SAFETY : interruptions coupées ; la pile noyau du programme sera
    // prise à sa prochaine entrée dans le noyau ; son espace a la moitié
    // haute du noyau (on continue de s'exécuter après avoir changé CR3).
    // `basculer` revient quand le programme se termine (`terminer`).
    unsafe {
        gdt::definir_pile_noyau(haut);
        pagination::activer(pml4);
        let contextes = CONTEXTES.0.get();
        basculer(&raw mut (*contextes).noyau, &raw const (*contextes).programme);
        // De retour : on quitte l'espace du programme, qui va être détruit.
        pagination::activer(pagination::pml4_noyau());
    }
    EN_COURS.store(false, Ordering::Relaxed);
    if interruptions {
        cpu::activer_interruptions();
    }
    CODE_SORTIE.load(Ordering::Relaxed)
}

/// Termine le programme en cours (exit) : rend le processeur à la tâche du
/// noyau, qui reprend dans `executer`. Appelée depuis un appel système, sur
/// la pile noyau du programme, qui est abandonnée telle quelle.
pub fn terminer(code: i32) -> ! {
    CODE_SORTIE.store(code, Ordering::Relaxed);
    cpu::couper_interruptions();
    // SAFETY : interruptions coupées ; le contexte du noyau a été rangé par
    // `executer`, qui attend dans `basculer`. Le contexte du programme est
    // écrit, mais ne servira plus.
    unsafe {
        let contextes = CONTEXTES.0.get();
        basculer(&raw mut (*contextes).programme, &raw const (*contextes).noyau);
    }
    unreachable!("un programme termine a repris la main");
}

/// Arrête le programme en cours par le signal `signal` (une exception, sa
/// limite de temps de calcul, un signal qu'il s'est envoyé), en disant
/// pourquoi : le message de Linux dans son journal, puis le code de sortie
/// 128 + signal. Seulement au retour vers l'anneau 3 (`verifier_au_retour`).
fn mourir(signal: Signal, raison: impl fmt::Display) -> ! {
    let nom = *NOM.verrouiller();
    afficherln!("[noyau] {} : {} ({})", nom, raison, signal.nom);
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

/// La fin prévue du programme en cours, s'il y en a une.
static FIN: Verrou<Option<Fin>> = Verrou::new(None);

/// exit et exit_group : le programme finira au retour vers l'anneau 3,
/// avec ce code. Elle l'emporte sur tout ce qui pouvait l'attendre (sous
/// Linux, `do_exit` part aussitôt, sans regarder les signaux).
pub fn prevoir_sortie(code: i32) {
    *FIN.verrouiller() = Some(Fin::Sortie(code));
}

/// Le programme sera arrêté par `signal` au retour vers l'anneau 3 (une
/// faute, plus rien ne peut le réveiller...), avec ce message. La
/// première raison l'emporte, sauf SIGKILL, qui remplace tout signal
/// prévu avant lui (pas une sortie) : c'est lui qui tuera.
pub fn forcer(signal: Signal, raison: impl fmt::Display) {
    let mut fin = FIN.verrouiller();
    let remplacer = match &*fin {
        None => true,
        Some(Fin::Signal(s, _)) => signal.numero == linux::SIGKILL.numero && s.numero != linux::SIGKILL.numero,
        Some(Fin::Sortie(_)) => false,
    };
    if remplacer {
        *fin = Some(Fin::Signal(signal, Message::de(raison)));
    }
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

/// Le nom du programme en cours (PR_GET_NAME).
pub fn nom() -> NomCourt {
    *NOM.verrouiller()
}

/// Change le nom du programme en cours (PR_SET_NAME) : celui des messages
/// du noyau, comme le `comm` de Linux, que montre aussi son tueur OOM.
pub fn renommer(nom: NomCourt) {
    *NOM.verrouiller() = nom;
}

/// Le programme en cours dort-il (un futex qui attend son délai) ? Ce
/// temps-là n'est pas du calcul.
static DORT: AtomicBool = AtomicBool::new(false);

/// Un tic a été compté depuis la dernière vérification de RLIMIT_CPU.
static TEMPS_A_VERIFIER: AtomicBool = AtomicBool::new(false);

/// Appelée à chaque tic d'horloge, interruptions coupées : le programme en
/// cours, s'il y en a un et qu'il ne dort pas, a calculé un tic de plus, et
/// sa limite de temps de calcul sera vérifiée à son retour vers l'anneau 3.
pub fn tic() {
    if EN_COURS.load(Ordering::Relaxed) && !DORT.load(Ordering::Relaxed) {
        CALCUL.fetch_add(1, Ordering::Relaxed);
        TEMPS_A_VERIFIER.store(true, Ordering::Relaxed);
    }
}

/// Le programme en cours dort, dans un appel système, jusqu'à ce que
/// `fini` le dise (vérifié à chaque interruption) : `sti ; hlt` entre deux,
/// et ce temps ne compte pas dans son temps de calcul. Sans ordonnanceur
/// (6e), le processeur n'a rien d'autre à faire : il attend.
pub fn dormir_jusqu_a(fini: impl Fn() -> bool) {
    DORT.store(true, Ordering::Relaxed);
    loop {
        // Vérifier interruptions coupées, puis dormir : voir pourquoi dans
        // cpu::attendre_interruption.
        cpu::couper_interruptions();
        if fini() {
            break;
        }
        cpu::attendre_interruption();
    }
    DORT.store(false, Ordering::Relaxed);
    // Un appel système s'exécute interruptions actives.
    cpu::activer_interruptions();
}

/// Le temps de calcul du programme en cours, en tics
/// (CLOCK_PROCESS_CPUTIME_ID, temps.rs). 0 sans programme.
pub fn tics_du_programme() -> u64 {
    if !EN_COURS.load(Ordering::Relaxed) {
        return 0;
    }
    CALCUL.load(Ordering::Relaxed)
}

/// Le programme en cours sera tué faute de mémoire à son retour vers
/// l'anneau 3 (voir A_TUER).
pub fn tuer_au_retour() {
    A_TUER.store(true, Ordering::Relaxed);
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
/// suivante. Linux boucle ainsi jusqu'à ce qu'il n'y ait plus rien à faire ;
/// toutes nos décisions arrêtent le programme, la boucle n'a encore qu'un
/// tour (6e ajoutera « céder le processeur », 6f les gestionnaires).
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
    if !EN_COURS.load(Ordering::Relaxed) {
        return;
    }
    cpu::couper_interruptions();
    let Some(arret) = decider() else { return };
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
    match FIN.verrouiller().take() {
        Some(Fin::Sortie(code)) => return Some(Arret::Sortie(code)),
        Some(Fin::Signal(signal, message)) => return Some(Arret::Force(signal, message)),
        None => {}
    }
    if A_TUER.load(Ordering::Relaxed) {
        return Some(Arret::PlusDeMemoire);
    }
    let calcul = temps::nanosecondes(CALCUL.load(Ordering::Relaxed));
    let verifier_temps = TEMPS_A_VERIFIER.swap(false, Ordering::Relaxed);
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
