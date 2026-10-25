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
use crate::programmes::Nom;
use crate::verrou::Verrou;
use crate::{cpu, gdt, horloge, pagination, processus};

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
static NOM: Verrou<&'static [u8]> = Verrou::new(&[]);
/// Le tic d'horloge de son départ.
static DEPART: AtomicU64 = AtomicU64::new(0);
/// Le programme est à tuer, faute de mémoire, dès qu'il retourne vers
/// l'anneau 3 : une page lui a manqué pendant une copie du noyau (un appel
/// système qui écrit dans sa mémoire). L'appel ne peut pas s'arrêter au
/// milieu de ce qu'il fait : il rend EFAULT, et le programme est tué au
/// retour (Linux lui envoie de même un SIGKILL, délivré au retour).
static A_TUER: AtomicBool = AtomicBool::new(false);

/// Le temps qu'un programme peut prendre : 1 s, en tics d'horloge (1 ms).
/// C'est l'équivalent, pour les programmes Linux, du carburant des
/// programmes WebAssembly, et de la limite RLIMIT_CPU de Linux : un
/// programme qui boucle sans fin ne garde pas la machine. Le temps compté
/// est le temps écoulé depuis son départ : avec un seul programme à la
/// fois, c'est son temps de calcul, appels système compris.
const BUDGET_TICS: u64 = horloge::HZ as u64;

/// Le RFLAGS d'un programme qui démarre : IF (interruptions acceptées) et
/// le bit 1, toujours à 1. IOPL = 0 : pas de `in`, `out`, `cli`, `sti`.
const RFLAGS_INITIAL: u64 = 1 << 9 | 1 << 1;

/// Exécute un programme : `pml4` son espace d'adressage, `entree` son point
/// d'entrée, `pile` le sommet de sa pile. Revient quand il se termine, avec
/// son code de sortie.
pub fn executer(nom: &'static [u8], pml4: u64, entree: u64, pile: u64) -> i32 {
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
    DEPART.store(horloge::tics(), Ordering::Relaxed);
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
    afficherln!("[noyau] {} : {} ({})", Nom(nom), raison, signal.nom);
    terminer(128 + signal.numero as i32)
}

/// Arrête le programme en cours faute de mémoire (SIGKILL, le tueur OOM de
/// Linux), en disant ce qu'il occupait. Le verrou du processus est rendu
/// avant d'arrêter : `terminer` ne revient pas, et un verrou emporté dans
/// une tâche abandonnée ne serait jamais rendu.
pub fn arreter_plus_de_memoire() -> ! {
    let (virtuelle, en_place, tables) = processus::avec(|p| {
        let e = &p.memoire.espace;
        (p.memoire.taille_virtuelle(), e.pages() as u64 * 4096, e.tables() as u64 * 4096)
    });
    // Le message de Linux : « Out of memory: Killed process 1234 (a.out)
    // total-vm:...kB, anon-rss:...kB, ... pgtables:...kB ».
    arreter(
        linux::SIGKILL,
        format_args!("plus de memoire : tue, memoire virtuelle {} Kio, en place {} Kio, tables {} Kio",
                     virtuelle >> 10, en_place >> 10, tables >> 10),
    )
}

/// Les tics d'horloge passés depuis le départ du programme en cours : son
/// temps de calcul (CLOCK_PROCESS_CPUTIME_ID, temps.rs). 0 sans
/// programme.
pub fn tics_du_programme() -> u64 {
    if !EN_COURS.load(Ordering::Relaxed) {
        return 0;
    }
    horloge::tics() - DEPART.load(Ordering::Relaxed)
}

/// Le programme en cours sera tué faute de mémoire à son retour vers
/// l'anneau 3 (voir A_TUER).
pub fn tuer_au_retour() {
    A_TUER.store(true, Ordering::Relaxed);
}

/// Arrête le programme en cours s'il doit être tué faute de mémoire, ou
/// s'il a dépassé son temps. Appelée au retour vers l'anneau 3 (après une
/// interruption, à la fin d'un appel système) : le noyau n'a alors plus
/// rien en cours pour lui.
pub fn verifier_budget() {
    if !EN_COURS.load(Ordering::Relaxed) {
        return;
    }
    if A_TUER.load(Ordering::Relaxed) {
        arreter_plus_de_memoire();
    }
    if horloge::tics() - DEPART.load(Ordering::Relaxed) > BUDGET_TICS {
        arreter(linux::SIGXCPU, format_args!("temps de calcul depasse ({} ms)", BUDGET_TICS));
    }
}
