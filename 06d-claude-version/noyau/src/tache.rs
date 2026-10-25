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
use crate::{cpu, gdt, pagination, processus, temps};

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

/// Arrête le programme en cours par le signal `signal` (une exception, son
/// temps épuisé), en disant pourquoi : le message de Linux dans son
/// journal, puis le code de sortie 128 + signal.
pub fn arreter(signal: Signal, raison: impl fmt::Display) -> ! {
    let nom = *NOM.verrouiller();
    afficherln!("[noyau] {} : {} ({})", nom, raison, signal.nom);
    terminer(128 + signal.numero as i32)
}

/// Arrête le programme en cours faute de mémoire (SIGKILL, le tueur OOM de
/// Linux), en disant ce qu'il occupait. Le verrou du processus est rendu
/// avant d'arrêter : `terminer` ne revient pas, et un verrou emporté dans
/// une tâche abandonnée ne serait jamais rendu.
pub fn arreter_plus_de_memoire() -> ! {
    let (virtuelle, en_place, fichiers, tables) = processus::avec(|p| {
        let e = &p.memoire.espace;
        (p.memoire.taille_virtuelle(), e.pages() as u64 * 4096, e.pages_fichier() as u64 * 4096, e.tables() as u64 * 4096)
    });
    // Le message de Linux : « Out of memory: Killed process 1234 (a.out)
    // total-vm:...kB, anon-rss:...kB, file-rss:...kB, ... pgtables:...kB ».
    arreter(
        linux::SIGKILL,
        format_args!("plus de memoire : tue, memoire virtuelle {} Kio, en place {} Kio, fichiers {} Kio, tables {} Kio",
                     virtuelle >> 10, en_place >> 10, fichiers >> 10, tables >> 10),
    )
}

/// Un tic a été compté depuis la dernière vérification de RLIMIT_CPU.
static TEMPS_A_VERIFIER: AtomicBool = AtomicBool::new(false);

/// Appelée à chaque tic d'horloge, interruptions coupées : le programme en
/// cours, s'il y en a un, a calculé un tic de plus, et sa limite de temps
/// de calcul sera vérifiée à son retour vers l'anneau 3.
pub fn tic() {
    if EN_COURS.load(Ordering::Relaxed) {
        CALCUL.fetch_add(1, Ordering::Relaxed);
        TEMPS_A_VERIFIER.store(true, Ordering::Relaxed);
    }
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

/// Arrête le programme en cours s'il doit être tué faute de mémoire, ou
/// s'il a atteint sa limite de temps de calcul. Appelée au retour vers
/// l'anneau 3 (après une interruption, à la fin d'un appel système) : le
/// noyau n'a alors plus rien en cours pour lui, et ne tient aucun verrou.
///
/// La limite est RLIMIT_CPU, en secondes, celle de Linux. Comme lui, elle
/// n'est vérifiée qu'après un tic compté (Linux le fait dans le tic, nous
/// au retour qui suit, où le signal serait livré de toute façon) : un
/// programme qui pose une limite de 0 s ne reçoit SIGXCPU qu'au tic
/// suivant, et un getrlimit fait juste après relit 0 (mesuré), pas la
/// limite déjà relevée. Dans l'ordre de `check_process_timers`
/// (kernel/time/posix-cpu-timers.c) :
///   - rien à vérifier si la limite courante est infinie (le défaut) ;
///   - la limite dure d'abord : atteinte, SIGKILL ;
///   - puis la courante : atteinte, SIGXCPU, et Linux la relève d'une
///     seconde (`rlim_cur = soft + 1`, ce que montre ensuite getrlimit,
///     mesuré) : un programme qui ignore SIGXCPU en reçoit un autre la
///     seconde suivante, jusqu'à la limite dure. Une courante égale à la
///     dure tue donc directement par SIGKILL (mesuré : 137, pas 152).
/// L'action de SIGXCPU par défaut est d'arrêter le programme (avec image
/// mémoire) : c'est ce qui se passe aujourd'hui, en attendant que les
/// programmes puissent régler leurs signaux.
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
    if A_TUER.load(Ordering::Relaxed) {
        arreter_plus_de_memoire();
    }
    let calcul = temps::nanosecondes(CALCUL.load(Ordering::Relaxed));
    let verifier_temps = TEMPS_A_VERIFIER.swap(false, Ordering::Relaxed);
    let atteinte = processus::essayer_avec(|p| {
        let (courante, dure) = p.limite(processus::RLIMIT_CPU);
        if !verifier_temps || courante == processus::INFINI {
            return None;
        }
        let atteinte = |secondes: u64| calcul as u128 >= secondes as u128 * 1_000_000_000;
        if dure != processus::INFINI && atteinte(dure) {
            return Some((linux::SIGKILL, "limite dure", dure));
        }
        if atteinte(courante) {
            // Ici courante < dure (égales, la dure l'aurait emporté) :
            // relevée, elle ne la dépasse pas.
            p.changer_limite(processus::RLIMIT_CPU, (courante + 1, dure));
            return Some((linux::SIGXCPU, "limite", courante));
        }
        None
    }).flatten();
    // Le verrou du processus est rendu : `arreter` ne revient pas.
    if let Some((signal, quelle, secondes)) = atteinte {
        arreter(signal, format_args!("{} de temps de calcul atteinte (RLIMIT_CPU {} s)", quelle, secondes));
    }
}
