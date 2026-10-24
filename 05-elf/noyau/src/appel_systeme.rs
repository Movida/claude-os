//! L'entrée dans le noyau par l'instruction `syscall` : comment un
//! programme Linux (anneau 3) appelle le noyau.
//!
//! Un programme ne peut pas appeler une fonction du noyau : ses pages ne
//! portent pas le bit UTILISATEUR, et l'anneau 3 n'a pas le droit d'y
//! sauter. Il exécute `syscall`, qui en une instruction :
//!   - range RIP dans RCX et RFLAGS dans R11 (pour le retour) ;
//!   - efface dans RFLAGS les bits du masque FMASK (dont IF : les
//!     interruptions sont coupées en entrant) ;
//!   - charge CS et SS avec les sélecteurs du noyau (calculés à partir de
//!     STAR, voir gdt.rs), donc passe en anneau 0 ;
//!   - saute à l'adresse rangée dans LSTAR : `entree_syscall`, plus bas.
//! Il ne change PAS de pile : RSP vaut toujours ce que le programme y a
//! mis, peut-être n'importe quoi. Les premières instructions de l'entrée
//! doivent donc passer sur une pile du noyau sans rien empiler avant. (Les
//! NMI, #DB et #MC, qui peuvent tomber entre `syscall` et ce changement de
//! pile, ont leur propre pile IST : voir gdt.rs.)
//!
//! `sysretq` fait l'inverse : RIP = RCX, RFLAGS = R11, CS et SS du
//! programme, anneau 3. Il ne change pas de pile non plus : on remet le RSP
//! du programme juste avant, interruptions coupées.
//!
//! Options écartées :
//!   - `int 0x80` : l'ABI 32 bits de Linux (numéros d'appels différents,
//!     arguments dans ebx, ecx, edx...), pour les programmes 32 bits. Une
//!     interruption logicielle coûte aussi plus cher qu'un `syscall`. Un
//!     programme qui l'essaie est arrêté (l'entrée 0x80 de l'IDT est
//!     absente) ;
//!   - `sysenter` : l'instruction d'Intel pour la même chose, absente du
//!     mode 64 bits sur les processeurs AMD. `syscall` existe partout en
//!     64 bits. SYSENTER_CS vaut 0 : un `sysenter` fait une faute de
//!     protection générale, et le programme est arrêté.
//!
//! Pas de `swapgs` : Linux s'en sert pour trouver, par GS, la zone propre à
//! chaque processeur (la pile noyau courante, entre autres). Avec un seul
//! processeur, une seule TSS, adressée par RIP, suffit ; le noyau ne touche
//! jamais à GS (la cible x86_64-unknown-none n'a ni variables par fil
//! d'exécution ni protection de pile, qui s'en serviraient). `swapgs` est
//! la source de failles la plus fournie de l'entrée de Linux
//! (CVE-2014-9322, CVE-2019-1125) : on l'ajoutera avec le multiprocesseur,
//! pas avant.

use core::arch::{asm, global_asm};
use core::mem::offset_of;

use crate::gdt;
use crate::interruptions::Cadre;
use crate::linux;

/// Le « vecteur » qu'on range dans le cadre d'un appel système, pour le
/// distinguer d'une interruption (0 à 255) : aucun vrai vecteur ne le vaut.
pub const VECTEUR_SYSCALL: u64 = 256;

// Les registres spécifiques (MSR) de `syscall`.
const EFER: u32 = 0xC000_0080;
const STAR: u32 = 0xC000_0081;
const LSTAR: u32 = 0xC000_0082;
const CSTAR: u32 = 0xC000_0083;
const FMASK: u32 = 0xC000_0084;
const SYSENTER_CS: u32 = 0x174;
/// EFER.SCE (System Call Extensions) : sans lui, `syscall` est une
/// instruction invalide.
const EFER_SCE: u64 = 1 << 0;

/// Les bits de RFLAGS que `syscall` efface en entrant, ceux de Linux
/// (syscall_init) :
///   - IF : pas d'interruption tant qu'on est sur la pile du programme ;
///   - TF : pas de pas-à-pas dans le noyau ;
///   - DF : le sens des copies (`rep movsb`) attendu par le compilateur ;
///   - AC : l'alignement contrôlé, et surtout, avec SMAP, la permission de
///     toucher la mémoire du programme (sous-étape 7) ;
///   - NT et IOPL : des restes du 32 bits, qu'un programme pourrait
///     armer pour tromper un `iret` ou un `in`/`out` ;
///   - RF, ID, et les drapeaux arithmétiques (CF, PF, AF, ZF, SF, OF) :
///     le noyau part d'un état connu.
const MASQUE_RFLAGS: u64 = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 6 | 1 << 7 // CF PF AF ZF SF
    | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 // TF IF DF OF
    | 3 << 12 | 1 << 14 | 1 << 16 | 1 << 18 | 1 << 21; // IOPL NT RF AC ID

// L'entrée et la sortie, en assembleur : le même cadre que les
// interruptions (interruptions.rs), comme le pt_regs de Linux, pour que
// la sortie, l'arrêt d'un programme fautif ou un futur ordonnanceur
// traitent tous les cas de la même façon.
global_asm!(
    r#"
    .section .text
    .global entree_syscall
    .align 16
entree_syscall:
    /* Ranger le RSP du programme dans TSS.rsp[2], prendre la pile noyau
       du programme dans TSS.rsp[0] : sans rien empiler avant. */
    mov [rip + TSS_PROCESSEUR + 20], rsp
    mov rsp, [rip + TSS_PROCESSEUR + 4]
    /* Le cadre qu'aurait empilé une interruption venue de l'anneau 3 :
       SS, RSP, RFLAGS, CS, RIP... */
    push {donnees_utilisateur}
    push qword ptr [rip + TSS_PROCESSEUR + 20]
    push r11
    push {code_utilisateur}
    push rcx
    /* ... le « code d'erreur » : le numéro de l'appel (orig_ax de Linux),
       puis le « vecteur »... */
    push rax
    push {vecteur}
    /* ... et tous les registres, comme interruption_commune. */
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    /* Les interruptions reviennent : on est sur une pile du noyau, et un
       appel système peut durer (une écriture de 1024 octets sur un vrai
       port série prend 90 ms : l'horloge ne doit pas perdre ses tics).
       22 valeurs de 8 octets sous un sommet aligné sur 16 : la pile est
       alignée pour l'appel. */
    sti
    mov rdi, rsp
    call gerer_appel_systeme

    /* Le retour. Interruptions coupées jusqu'à sysretq : une interruption
       entre le retour à la pile du programme et sysretq s'empilerait sur
       elle. */
    cli
    /* sysretq seulement dans le cas ordinaire ; sinon iretq, plus lent
       mais qui ne suppose rien (comme Linux, entry_SYSCALL_64) :
       - RIP doit être dans la moitié basse. Sur un processeur Intel,
         sysretq vers une adresse NON CANONIQUE fait sa faute de protection
         générale en anneau 0, avec la pile du programme (CVE-2012-0217) :
         une faille pour qui sait choisir RSP. La dernière page de la
         moitié basse n'est jamais projetable (espace_utilisateur.rs) : un
         `syscall` ne peut donc pas revenir là ; mais le RIP du cadre
         pourra être changé par le noyau (exec, signaux), d'où la
         vérification ici, au dernier moment ;
       - ni TF (pas-à-pas) ni RF dans RFLAGS : sysretq les rétablirait
         d'une façon qui diffère d'un processeur à l'autre ;
       - CS et SS ceux d'un programme 64 bits. */
    mov rcx, [rsp + {rip}]
    mov r11, rcx
    shr r11, 47
    jnz retour_interruption
    mov r11, [rsp + {rflags}]
    test r11, (1 << 8) | (1 << 16)
    jnz retour_interruption
    cmp qword ptr [rsp + {cs}], {code_utilisateur}
    jne retour_interruption
    cmp qword ptr [rsp + {ss}], {donnees_utilisateur}
    jne retour_interruption
    /* Tous les registres, sauf RCX et R11 qui valent déjà RIP et RFLAGS,
       ce que sysretq attend (et ce que l'ABI de Linux annonce : syscall
       écrase rcx et r11). */
    pop r15
    pop r14
    pop r13
    pop r12
    add rsp, 8
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    add rsp, 8
    pop rbx
    pop rax
    /* RSP pointe sur le vecteur ; le RSP du programme est 5 cases plus
       haut (vecteur, code, rip, cs, rflags). */
    mov rsp, [rsp + 40]
    sysretq

    /* L'entrée des `syscall` venus du mode compatibilité (programmes
       32 bits) : impossible, le code 32 bits utilisateur de la GDT est
       nul. Si cela arrivait quand même, on rend -ENOSYS sans rien toucher,
       comme le ignore_sysret de Linux : pas une instruction ne doit
       s'exécuter sur la pile du programme. */
    .global entree_syscall_compat
    .align 16
entree_syscall_compat:
    mov eax, -38
    sysret
    "#,
    donnees_utilisateur = const gdt::DONNEES_UTILISATEUR,
    code_utilisateur = const gdt::CODE_UTILISATEUR,
    vecteur = const VECTEUR_SYSCALL,
    rip = const offset_of!(Cadre, rip),
    rflags = const offset_of!(Cadre, rflags),
    cs = const offset_of!(Cadre, cs),
    ss = const offset_of!(Cadre, ss),
);

/// Écrit un registre spécifique (MSR).
///
/// # Safety
/// `msr` doit exister, et `valeur` y avoir un sens.
unsafe fn ecrire_msr(msr: u32, valeur: u64) {
    // SAFETY : garanti par l'appelant.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") valeur as u32, in("edx") (valeur >> 32) as u32,
             options(nostack, preserves_flags));
    }
}

/// Lit un registre spécifique (MSR).
///
/// # Safety
/// `msr` doit exister.
unsafe fn lire_msr(msr: u32) -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY : garanti par l'appelant.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}

/// Prépare `syscall` : les sélecteurs, l'adresse d'entrée, le masque.
pub fn initialiser() {
    unsafe extern "C" {
        fn entree_syscall();
        fn entree_syscall_compat();
    }
    let star = (gdt::BASE_UTILISATEUR as u64) << 48 | (gdt::CODE_NOYAU as u64) << 32;
    // SAFETY : ces MSR existent sur tout processeur 64 bits (`syscall` fait
    // partie du mode long) ; les valeurs suivent la GDT (gdt.rs) et les
    // entrées ci-dessus.
    unsafe {
        ecrire_msr(STAR, star);
        ecrire_msr(LSTAR, entree_syscall as *const () as u64);
        ecrire_msr(CSTAR, entree_syscall_compat as *const () as u64);
        ecrire_msr(FMASK, MASQUE_RFLAGS);
        ecrire_msr(SYSENTER_CS, 0);
        ecrire_msr(EFER, lire_msr(EFER) | EFER_SCE);
    }
}

/// Appelée par l'entrée de `syscall`, interruptions actives, avec le cadre
/// du programme : son numéro d'appel dans rax, ses arguments dans rdi,
/// rsi, rdx, r10, r8 et r9 (r10 et non rcx comme pour une fonction :
/// `syscall` écrase rcx). Le résultat va dans rax : une valeur, ou -errno.
#[unsafe(no_mangle)]
extern "C" fn gerer_appel_systeme(cadre: &mut Cadre) {
    let arguments = [cadre.rdi, cadre.rsi, cadre.rdx, cadre.r10, cadre.r8, cadre.r9];
    cadre.rax = linux::appel(cadre.rax, arguments) as u64;
}
