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
use core::mem::size_of;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::interruptions::Cadre;
use crate::{cpu, gdt, pagination};

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
       (arch_prctl). Puis le retour d'interruption : iretq vers le cadre
       préparé par executer(). */
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
    jmp retour_interruption
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

/// Le RFLAGS d'un programme qui démarre : IF (interruptions acceptées) et
/// le bit 1, toujours à 1. IOPL = 0 : pas de `in`, `out`, `cli`, `sti`.
const RFLAGS_INITIAL: u64 = 1 << 9 | 1 << 1;

/// Exécute un programme : `pml4` son espace d'adressage, `entree` son point
/// d'entrée, `pile` le sommet de sa pile. Revient quand il se termine, avec
/// son code de sortie.
pub fn executer(pml4: u64, entree: u64, pile: u64) -> i32 {
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
