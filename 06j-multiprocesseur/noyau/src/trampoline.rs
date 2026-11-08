//! Le trampoline des processeurs secondaires : le code qu'exécute un
//! processeur qui vient de recevoir un SIPI, du mode réel 16 bits jusqu'à
//! la première fonction Rust du noyau (smp.rs, `depart_secondaire`).
//!
//! Un processeur secondaire démarre comme la machine en 1981 : en mode
//! réel, 16 bits, sans pagination, à l'adresse que lui donne le SIPI
//! (le vecteur du SIPI est le numéro d'une page de la mémoire basse : le
//! processeur commence à CS = vecteur × 0x100, IP = 0 ; seules les pages
//! sous 1 Mio sont possibles). Il refait donc en quelques dizaines
//! d'instructions ce que notre chargeur a fait pour le premier processeur
//! en deux étapes (../02-mode-protege, ../02-mode-long) : le mode protégé,
//! puis le mode long, puis le saut dans le noyau en haut de la mémoire.
//! C'est le `trampoline_64.S` de Linux (arch/x86/realmode/rm/), au plus
//! court.
//!
//! Où : la page 0x8000, recopiée là au démarrage (`installer`) depuis
//! l'image du noyau (le code ci-dessous, assemblé avec le noyau). Sous
//! 1 Mio, dans une zone que le premier Mio ne donne à aucun allocateur
//! (cadres.rs : la mémoire sous 1 Mio reste réservée), là où vivait le
//! second étage du chargeur, fini depuis longtemps (boot.asm : 0x7E00 et
//! la suite ; les informations de démarrage, à 0x4000, sont recopiées dès
//! `noyau_main`). Linux prend lui aussi une page libre sous 1 Mio
//! (`reserve_real_mode`). La PML4 du trampoline (voir plus bas) occupe la
//! page suivante, 0x9000 : CR3 s'écrit en 32 bits dans le mode protégé,
//! elle doit donc être sous 4 Gio, et une page du premier Mio l'est à
//! coup sûr, quand un cadre de l'allocateur pourrait ne pas l'être.
//!
//! Les adresses : le code 16 bits travaille en adresses relatives à son
//! segment (DS = CS = 0x0800, la page), et les modes 32 et 64 bits en
//! adresses absolues, toutes des CONSTANTES : la page est fixe (`CODE`),
//! et la disposition de ses données aussi (les `DEC_*` ci-dessous, que
//! l'assembleur reçoit en opérandes `const`, et que `.org` fait respecter
//! au code). Pas de table de relocalisation comme celle de Linux
//! (`real_mode_relocs`, qui lui permet de mettre le trampoline dans
//! n'importe quelle page) : une page fixe suffit à nos machines.
//!
//! Dans l'ordre :
//!   1. (16 bits) `cli` ; DS, ES, SS = CS ; une IDT NULLE (`lidt`, comme
//!      Linux : une exception ou un NMI pendant le trampoline fait une
//!      triple faute nette, qui redémarre la machine, plutôt que d'exécuter
//!      n'importe quoi à l'adresse qu'indiquerait la table du BIOS) ; la
//!      GDT du trampoline (trois descripteurs : code 32 bits, données, code
//!      64 bits) ; CR0.PE ; le saut lointain en 32 bits ;
//!   2. (32 bits) les segments de données ; CR4, puis CR3 = la PML4 du
//!      trampoline, puis EFER, puis CR0, chacun avec la VALEUR FINALE du
//!      premier processeur (écrites dans l'en-tête par `installer` : PAE,
//!      OSFXSR, OSXMMEXCPT, OSXSAVE, SMEP, SMAP, UMIP ; LME, NXE, SCE ; PE,
//!      MP, NE, WP, AM, PG), ce que fait Linux avec `tr_cr4`, `tr_efer` et
//!      `CR0_STATE` : écrire CR0.PG avec EFER.LME active le mode long ;
//!      le saut lointain en 64 bits ;
//!   3. (64 bits) la vérification que ce processeur est bien celui qu'on
//!      attend (son numéro d'APIC par CPUID, comparé à l'en-tête : un
//!      processeur en retard, que le premier a abandonné, et dont l'en-tête
//!      a été réécrit pour le suivant, s'arrête là, `cli ; hlt`, sans
//!      toucher à une pile ni à une zone qui ne sont plus les siennes) ; la
//!      pile ; GS_BASE sur la zone du processeur (processeur.rs) ; et
//!      seulement alors l'appel de `depart_secondaire(numéro)` (la première
//!      fonction Rust : son prologue empile), une adresse HAUTE du noyau,
//!      encore sous la PML4 du trampoline : c'est `depart_secondaire` qui
//!      charge celle du noyau, sa première action, une fois le code exécuté
//!      en haut (le `jmpq *tr_start` de Linux vers `secondary_startup_64`,
//!      qui charge `init_top_pgt` là-bas).
//!
//! La PML4 DU TRAMPOLINE : la façon de Linux (`setup_real_mode`) : une
//! page dont la moitié haute est celle de la PML4 définitive du noyau (son
//! image, la projection directe, la région vmalloc où est la pile du
//! secondaire) et dont l'entrée 0 est la PDPT à l'identique du démarrage
//! (`demarrage_pdpt_identite` et sa PD, main.rs : elles restent dans la
//! .bss pour cela). Pourquoi : les instructions qui suivent « pagination
//! active », jusqu'au saut en haut, sont encore lues à une adresse basse,
//! celle du trampoline, que la PML4 du noyau ne projette plus
//! (pagination.rs : plus rien à l'identique ; la charger ici ferait une
//! faute de page sur l'instruction suivante, sans IDT : une triple faute,
//! vue) ; et les tables de `_start` seules ne projettent pas vmalloc :
//! toucher la pile avant d'avoir une IDT ferait de même une triple faute,
//! qui redémarre toute la machine sans un mot.

use crate::{cpu, espace, pagination, sse};
use core::arch::global_asm;

/// La page du trampoline (le vecteur du SIPI : 0x8000 >> 12 = 8).
pub const CODE: u64 = 0x8000;
/// La page de la PML4 du trampoline.
const PML4: u64 = 0x9000;

// La disposition de la page : le code à partir de 0, les données à partir
// de 0x100 (`.org`, ci-dessous). Les décalages des données, que
// l'assembleur reçoit en `const` : un seul endroit les définit.
/// La GDT du trampoline : nul, code 32 bits (0x08), données (0x10), code
/// 64 bits (0x18).
const DEC_GDT: u64 = 0x100;
/// Ce que lit `lgdt` : la taille moins un, l'adresse.
const DEC_GDT_DESC: u64 = 0x120;
/// Ce que lit `lidt` : une IDT nulle.
const DEC_IDT_DESC: u64 = 0x128;
/// L'EN-TÊTE, écrit par le premier processeur : les registres de contrôle
/// (u32 : CR4, CR0 ; u64 : EFER), la PML4 du trampoline (u64), puis ce
/// qui est propre au processeur qu'on démarre : le sommet de sa pile, sa
/// zone (la base de GS), l'adresse de `depart_secondaire`, son numéro et
/// le numéro de son APIC (u32) ; et si XD_DISABLE est à effacer (u32).
const DEC_CR4: u64 = 0x130;
const DEC_CR0: u64 = 0x134;
const DEC_EFER: u64 = 0x138;
const DEC_PML4_TRAMPOLINE: u64 = 0x140;
const DEC_PILE: u64 = 0x148;
const DEC_GS: u64 = 0x150;
const DEC_DEPART: u64 = 0x158;
const DEC_NUMERO: u64 = 0x160;
const DEC_APIC: u64 = 0x164;
/// Le premier processeur a dû effacer XD_DISABLE (pagination.rs) : le
/// secondaire le fait aussi, avant d'écrire EFER.
const DEC_XD: u64 = 0x168;
/// La taille de la page utile (ce que `installer` recopie).
const TAILLE: u64 = 0x170;

global_asm!(
    r#"
    .section .rodata.trampoline, "a"
    .balign 16
    .global trampoline_debut
    .global trampoline_fin
trampoline_debut:
    .code16
    cli
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov si, {idt_desc}
    lidt [si]
    mov si, {gdt_desc}
    lgdt [si]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    /* Le saut lointain vers le code 32 bits, encode a la main (opcode EA,
       avec le prefixe 66 d'une adresse de 32 bits ; Linux fait de meme,
       LJMPW_RM) : l'assembleur ne sait pas ecrire un saut lointain vers
       une adresse absolue calculee. */
    .byte 0x66, 0xEA
    .long {code} + (trampoline_32 - trampoline_debut)
    .word 0x08

    .code32
trampoline_32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, dword ptr [{code} + {cr4}]
    mov cr4, eax
    mov eax, dword ptr [{code} + {pml4_trampoline}]
    mov cr3, eax
    /* XD_DISABLE (IA32_MISC_ENABLE, bit 34) : si le premier processeur a
       du l'effacer pour voir le bit NX (pagination.rs : un BIOS Intel
       « Execute Disable off »), chaque secondaire l'a aussi, et le wrmsr
       d'EFER.NXE qui suit ferait une faute de protection generale (NX pas
       enumere), donc une triple faute : le processeur ne repondrait jamais.
       On l'efface de meme (le verify_cpu de Linux, que secondary_startup_64
       rappelle pour chaque processeur). Seulement si l'en-tete le dit : ce
       MSR n'existe pas chez AMD. */
    cmp dword ptr [{code} + {xd}], 0
    je 2f
    mov ecx, 0x1A0
    rdmsr
    btr edx, 2
    wrmsr
2:
    mov ecx, 0xC0000080
    mov eax, dword ptr [{code} + {efer}]
    mov edx, dword ptr [{code} + {efer} + 4]
    wrmsr
    mov eax, dword ptr [{code} + {cr0}]
    mov cr0, eax
    .byte 0xEA
    .long {code} + (trampoline_64 - trampoline_debut)
    .word 0x18

    .code64
trampoline_64:
    /* Le processeur attendu ? Son numero d'APIC, CPUID.1:EBX[31:24]. */
    mov eax, 1
    cpuid
    shr ebx, 24
    cmp ebx, dword ptr [{code} + {apic}]
    jne 1f
    mov rsp, qword ptr [{code} + {pile}]
    mov rax, qword ptr [{code} + {gs}]
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0xC0000101
    wrmsr
    mov edi, dword ptr [{code} + {numero}]
    mov rax, qword ptr [{code} + {depart}]
    call rax
1:  cli
    hlt
    jmp 1b

    .org {gdt}
    .quad 0
    .quad 0x00CF9B000000FFFF
    .quad 0x00CF93000000FFFF
    .quad 0x00AF9B000000FFFF
    .org {gdt_desc}
    .word 31
    .long {code} + {gdt}
    .org {idt_desc}
    .word 0
    .long 0
    .org {cr4}
    .skip {taille} - {cr4}
trampoline_fin:
    "#,
    code = const CODE,
    gdt = const DEC_GDT,
    gdt_desc = const DEC_GDT_DESC,
    idt_desc = const DEC_IDT_DESC,
    cr4 = const DEC_CR4,
    cr0 = const DEC_CR0,
    efer = const DEC_EFER,
    pml4_trampoline = const DEC_PML4_TRAMPOLINE,
    pile = const DEC_PILE,
    gs = const DEC_GS,
    depart = const DEC_DEPART,
    numero = const DEC_NUMERO,
    apic = const DEC_APIC,
    xd = const DEC_XD,
    taille = const TAILLE,
);

unsafe extern "C" {
    static trampoline_debut: u8;
    static trampoline_fin: u8;
    // La PDPT à l'identique du démarrage (main.rs, `_start`), et sa PD :
    // le premier Gio en pages de 2 Mio, exécutable ; la moitié basse de la
    // PML4 du trampoline.
    static demarrage_pdpt_identite: u8;
}

/// EFER.LMA (bit 10) : « le mode long est actif », que le processeur pose
/// lui-même ; l'écrire fait une faute de protection générale sur certains
/// AMD (Linux le retire aussi de `tr_efer`).
const EFER_LMA: u64 = 1 << 10;

/// Écrit un mot de l'en-tête (ou une PML4) dans la page, par la
/// projection directe.
fn ecrire_u32(decalage: u64, valeur: u32) {
    // SAFETY: une adresse du premier Mio, projetée inscriptible dans la
    // projection directe (pagination.rs), dans la page du trampoline, que
    // rien d'autre n'emploie ; alignée sur 4.
    unsafe { (espace::virtuelle(CODE + decalage) as *mut u32).write_volatile(valeur) };
}

fn ecrire_u64(decalage: u64, valeur: u64) {
    // SAFETY: comme `ecrire_u32` ; alignée sur 8.
    unsafe { (espace::virtuelle(CODE + decalage) as *mut u64).write_volatile(valeur) };
}

/// Recopie le trampoline dans sa page, construit sa PML4, et écrit dans
/// son en-tête ce qui vaut pour tous les secondaires : les registres de
/// contrôle du premier processeur (ceux qui exécutent ceci, donc leur
/// valeur finale : après pagination.rs, copie_utilisateur.rs et sse.rs), sa
/// PML4, l'adresse de `depart`. Une fois, avant le premier SIPI.
pub fn installer(depart: extern "C" fn(u32) -> !) {
    let debut = &raw const trampoline_debut as u64;
    let taille = (&raw const trampoline_fin as u64) - debut;
    assert!(taille == TAILLE, "trampoline : {} octets au lieu de {}", taille, TAILLE);
    // SAFETY: la source est l'image du noyau (lisible), la destination la
    // page du trampoline dans la projection directe (inscriptible), que
    // rien d'autre n'emploie ; les deux font TAILLE octets.
    unsafe { core::ptr::copy_nonoverlapping(debut as *const u8, espace::virtuelle(CODE) as *mut u8, TAILLE as usize) };

    // La PML4 du trampoline : l'entrée 0 à l'identique, la moitié haute du
    // noyau.
    let pml4_noyau = pagination::pml4_noyau();
    let identite = espace::physique_du_noyau(&raw const demarrage_pdpt_identite as u64);
    // SAFETY: la PML4 du noyau est une de nos tables, projetée.
    let noyau = unsafe { pagination::lire_table(pml4_noyau) };
    for i in 0..512u64 {
        let entree = match i {
            0 => identite | pagination::PRESENTE | pagination::ECRITURE,
            256.. => noyau[i as usize],
            _ => 0,
        };
        ecrire_u64(PML4 - CODE + i * 8, entree);
    }

    ecrire_u32(DEC_CR4, cpu::lire_cr4() as u32);
    ecrire_u32(DEC_CR0, cpu::lire_cr0() as u32);
    ecrire_u64(DEC_EFER, cpu::lire_efer() & !EFER_LMA);
    ecrire_u64(DEC_PML4_TRAMPOLINE, PML4);
    ecrire_u64(DEC_DEPART, depart as usize as u64);
    ecrire_u32(DEC_XD, pagination::xd_efface() as u32);
}

/// Les registres de contrôle que les secondaires doivent avoir, pour les
/// comparer aux leurs (smp.rs) : CR0, CR4, EFER (sans LMA), XCR0. Ceux du
/// processeur qui exécute ceci.
pub fn registres_de_reference() -> [u64; 4] {
    [cpu::lire_cr0(), cpu::lire_cr4(), cpu::lire_efer() & !EFER_LMA, sse::xcr0()]
}

/// Écrit dans l'en-tête ce qui est propre au processeur qu'on va
/// démarrer : son numéro, le numéro d'APIC attendu, le sommet de sa pile,
/// sa zone. Avant son SIPI ; après la poignée de main du précédent, qui a
/// fini de lire l'en-tête (ou a été abandonné : il vérifie le numéro
/// d'APIC avant de rien toucher).
pub fn preparer_processeur(numero: u32, apic: u8, pile: u64, zone: u64) {
    ecrire_u32(DEC_NUMERO, numero);
    ecrire_u32(DEC_APIC, apic as u32);
    ecrire_u64(DEC_PILE, pile);
    ecrire_u64(DEC_GS, zone);
}
