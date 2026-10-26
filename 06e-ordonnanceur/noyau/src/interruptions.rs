//! Les interruptions et les exceptions : l'IDT (Interrupt Descriptor Table).
//!
//! Quand le processeur rencontre un problème (division par zéro, accès à
//! une page absente...) ou qu'un périphérique le réclame, il interrompt ce
//! qu'il faisait et saute à une adresse lue dans l'IDT : une table de 256
//! entrées, une par numéro (« vecteur »). Les vecteurs 0 à 31 sont réservés
//! aux exceptions du processeur. Sans IDT, une exception devient une double
//! faute, puis une triple faute : le CPU redémarre, sans un mot.
//!
//! Le chemin d'une interruption chez nous :
//!   1. Le CPU empile SS, RSP, RFLAGS, CS, RIP (et, pour certaines
//!      exceptions, un code d'erreur), puis saute au « talon » du vecteur.
//!   2. Le talon (assembleur, plus bas) empile un code d'erreur nul s'il
//!      n'y en a pas, puis le numéro du vecteur : la pile a ainsi toujours
//!      la même forme.
//!   3. Le code commun sauvegarde tous les registres et appelle la fonction
//!      Rust `gerer_interruption` avec un pointeur vers tout ça (un Cadre).
//!   4. Au retour, il restaure les registres et exécute `iretq`, qui
//!      dépile RIP, CS, RFLAGS, RSP, SS : le code interrompu reprend.
//!
//! C'est la même organisation que Linux (arch/x86/entry/entry_64.S). On
//! n'utilise pas l'ABI `extern "x86-interrupt"` de Rust : elle n'existe que
//! dans la version expérimentale (nightly) du compilateur, et elle cache ce
//! qui se passe.

use crate::{clavier, faute_de_page, gdt, horloge, irq, linux, processus, tache};
use crate::verrou::Verrou;
use core::arch::{asm, global_asm};
use core::mem::size_of;

/// Une entrée de l'IDT : 16 octets, l'adresse du gestionnaire éclatée en
/// trois morceaux (encore un héritage des formats 16 puis 32 bits).
#[derive(Clone, Copy)]
#[repr(C)]
struct Entree {
    adresse_bas: u16,
    selecteur: u16,
    /// Bits 0-2 : numéro de pile IST (0 = pile courante).
    ist: u8,
    /// Bit 7 : présent ; bits 5-6 : niveau de privilège requis pour
    /// déclencher le vecteur par `int n` ; bits 0-3 : type (0xE = porte
    /// d'interruption : le CPU coupe les interruptions en entrant).
    attributs: u8,
    adresse_milieu: u16,
    adresse_haut: u32,
    _reserve: u32,
}

impl Entree {
    const ABSENTE: Entree = Entree {
        adresse_bas: 0, selecteur: 0, ist: 0, attributs: 0,
        adresse_milieu: 0, adresse_haut: 0, _reserve: 0,
    };

    /// `dpl` : le niveau de privilège le plus faible qui peut déclencher le
    /// vecteur par `int n` (0 : le noyau seul ; 3 : les programmes aussi).
    /// Il ne compte pas pour les exceptions levées par le processeur ni
    /// pour les interruptions matérielles.
    fn new(gestionnaire: u64, ist: u8, dpl: u8) -> Entree {
        Entree {
            adresse_bas: gestionnaire as u16,
            selecteur: gdt::CODE_NOYAU,
            ist,
            // Porte d'interruption plutôt que « porte de trappe » (0xF) :
            // les interruptions sont coupées pendant le gestionnaire, ce
            // qui évite d'être interrompu avant d'avoir tout sauvegardé.
            attributs: 0x8E | dpl << 5,
            adresse_milieu: (gestionnaire >> 16) as u16,
            adresse_haut: (gestionnaire >> 32) as u32,
            _reserve: 0,
        }
    }
}

static IDT: Verrou<[Entree; 256]> = Verrou::new([Entree::ABSENTE; 256]);

/// Nombre de vecteurs pour lesquels on a écrit un talon : tous, comme
/// Linux (`irq_entries_start`). Les 32 exceptions, puis les interruptions
/// des périphériques et de l'APIC (irq.rs) : le 8259 sur 0x20 à 0x2F, les
/// IRQ ISA de l'IO-APIC sur 0x30 à 0x3F, les vecteurs propres à l'APIC tout
/// en haut ; un vecteur que personne n'a demandé est dit, et acquitté.
/// Leur niveau de privilège est 0 : un `int n` d'un programme (int 0x80
/// compris) fait une faute de protection générale.
const NB_TALONS: usize = 256;

// Les talons, générés par une macro de l'assembleur pour chaque vecteur.
// Les exceptions 8, 10-14, 17, 21, 29 et 30 empilent déjà un code
// d'erreur ; pour les autres, on en empile un nul.
//
// Chaque talon commence par `clac` (si le processeur a SMAP) : le
// processeur ne remet PAS le drapeau AC à zéro en entrant dans une
// interruption, et AC = 1 en anneau 0 suspend SMAP. Une interruption qui
// tombe pendant une copie vers un programme (stac ... clac, voir
// copie_utilisateur.rs), ou un programme qui a lui-même mis AC à 1 avant
// d'être interrompu, laisserait sinon tout le gestionnaire sans SMAP.
// iretq rétablit AC tel qu'il était. C'est l'ASM_CLAC en tête des
// idtentry de Linux. (L'entrée de `syscall`, elle, efface AC par son
// masque FMASK.) Le test d'un octet ne touche que les drapeaux, que le
// processeur a déjà sauvés dans le cadre.
global_asm!(
    r#"
    .macro TALON num
    .align 16
talon_\num:
    cmp byte ptr [rip + SMAP_ACTIF], 0
    je 1f
    clac
1:
    .if \num == 8 || (\num >= 10 && \num <= 14) || \num == 17 || \num == 21 || \num == 29 || \num == 30
    .else
        push 0
    .endif
    push \num
    jmp interruption_commune
    .endm

    .macro ADRESSE num
        .quad talon_\num
    .endm

    .section .text
    .altmacro
    .set i, 0
    .rept 256
        TALON %i
        .set i, i + 1
    .endr

interruption_commune:
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
    /* Le CPU a aligné la pile sur 16 octets avant d'empiler son cadre ;
       5 + 2 + 15 = 22 valeurs de 8 octets : elle l'est toujours, comme
       l'exige l'ABI avant un call. */
    mov rdi, rsp
    cld
    call gerer_interruption
    /* Le retour par iretq, partagé : la sortie d'un appel système qui ne
       peut pas prendre sysretq, et le premier départ d'un programme
       (tache.rs), y sautent aussi, RSP sur un cadre complet. */
    .global retour_interruption
retour_interruption:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16         /* Retire le numéro et le code d'erreur. */
    iretq

    /* La table des adresses des talons, lue par initialiser(). */
    .section .rodata
    .align 8
    .global adresses_talons
adresses_talons:
    .set i, 0
    .rept 256
        ADRESSE %i
        .set i, i + 1
    .endr
    .noaltmacro
    "#
);

/// Ce que le code commun a empilé, dans l'ordre inverse des push.
#[repr(C)]
#[derive(Debug)]
pub struct Cadre {
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub rbp: u64, pub rdi: u64, pub rsi: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    pub vecteur: u64,
    pub code_erreur: u64,
    // Empilé par le processeur :
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const NOMS: [&str; 32] = [
    "division par zero", "debogage", "NMI", "point d'arret (int3)",
    "debordement (into)", "hors limites (bound)", "instruction invalide",
    "coprocesseur absent", "double faute", "(reserve)", "TSS invalide",
    "segment absent", "faute de pile", "protection generale",
    "faute de page", "(reserve)", "erreur x87", "alignement",
    "verification machine", "erreur SIMD", "virtualisation",
    "protection de controle", "(reserve)", "(reserve)", "(reserve)",
    "(reserve)", "(reserve)", "(reserve)", "injection hyperviseur",
    "communication VMM", "securite", "(reserve)",
];

pub fn initialiser() {
    unsafe extern "C" {
        static adresses_talons: [u64; NB_TALONS];
    }
    let mut idt = IDT.verrouiller();
    for vecteur in 0..NB_TALONS {
        // SAFETY : tableau constant défini dans le global_asm! ci-dessus.
        let adresse = unsafe { adresses_talons[vecteur] };
        // La double faute bascule sur la pile de secours. Le scénario visé
        // est le débordement de la pile du noyau : sous la pile, une page
        // de garde NON PROJETÉE fait faute de page ; le CPU ne peut pas
        // empiler le cadre de cette faute sur la pile pleine, d'où une
        // double faute, que seule une autre pile permet de traiter.
        // La page de garde est en place (pagination.rs), et `make
        // tests-qemu` vérifie le scénario à chaque fois. La pile de secours
        // sert aussi pour toute autre cause de double faute.
        // NMI, #DB et #MC ont aussi chacun la leur : ils peuvent tomber
        // juste après `syscall`, avant que l'entrée ait quitté la pile du
        // programme (voir gdt.rs et appel_systeme.rs).
        let ist = match vecteur {
            1 => gdt::IST_DEBOGAGE,
            2 => gdt::IST_NMI,
            8 => gdt::IST_DOUBLE_FAUTE,
            18 => gdt::IST_VERIFICATION_MACHINE,
            _ => 0,
        };
        // int3 est permis aux programmes, comme sous Linux : un débogueur y
        // pose ses points d'arrêt (le programme reçoit SIGTRAP). Tous les
        // autres `int n` d'un programme font une faute de protection
        // générale, dont int 0x80 (voir gerer_interruption).
        let dpl = if vecteur == 3 { 3 } else { 0 };
        idt[vecteur] = Entree::new(adresse, ist, dpl);
    }

    #[repr(C, packed)]
    struct Descripteur {
        limite: u16,
        base: u64,
    }
    let descripteur = Descripteur {
        limite: (size_of::<[Entree; 256]>() - 1) as u16,
        base: idt.as_ptr() as u64,
    };
    // SAFETY : l'IDT est statique et chaque entrée présente pointe vers un
    // talon valide.
    unsafe { asm!("lidt [{}]", in(reg) &descripteur, options(nostack)) };
}

/// Appelée par le code commun pour chaque interruption.
///
/// Pour TOUS les vecteurs, ce qui compte d'abord est le privilège du code
/// interrompu (les deux bits bas de CS dans le cadre) :
///   - venue d'un programme (anneau 3), une exception est SA faute : il est
///     arrêté, avec le signal que lui enverrait Linux, et le noyau
///     continue. Même pour une exception qui n'est jamais une erreur dans
///     le noyau (int3) : un `int3`, un `icebp` ou un `int 0x80` d'un
///     programme ne doivent pas arrêter le noyau ;
///   - venue du noyau, c'est une erreur du noyau : on s'arrête (sauf int3,
///     le test du démarrage) ;
///   - le NMI, la double faute et la vérification machine ne sont la faute
///     de personne en particulier (une panne matérielle, ou le noyau dans
///     un état incohérent) : on s'arrête, d'où qu'ils viennent.
/// Linux fait ce même tri (user_mode(regs) dans arch/x86/kernel/traps.c).
#[unsafe(no_mangle)]
extern "C" fn gerer_interruption(cadre: &mut Cadre) {
    let vecteur = cadre.vecteur as usize;
    let depuis_programme = cadre.cs & 3 == 3;
    if vecteur >= 32 {
        irq::gerer(vecteur as u8, |irq| match irq {
            horloge::IRQ => {
                horloge::tic();
                tache::tic();
            }
            clavier::IRQ => clavier::interruption(),
            _ => {}
        });
        // Le programme interrompu a-t-il atteint sa limite de temps de
        // calcul ? Seulement s'il était en anneau 3 : interrompu au milieu
        // d'un appel système, il sera arrêté à la fin de l'appel
        // (appel_systeme.rs), quand le noyau aura fini ce qu'il faisait
        // pour lui.
        if depuis_programme {
            tache::verifier_au_retour();
        }
        return;
    }
    match vecteur {
        2 | 8 | 18 => exception_fatale(cadre),
        // La faute de page, d'où qu'elle vienne : le plus souvent servie
        // (la pagination à la demande), sinon le programme est arrêté, ou
        // la copie du noyau rend EFAULT (faute_de_page.rs).
        14 => faute_de_page::gerer(cadre),
        _ if depuis_programme => {
            // Le verrou du processus est rendu avant d'arrêter le
            // programme (tache::arreter ne revient pas).
            let zone = processus::essayer_avec(|p| p.memoire.zone_du_code(cadre.rip)).flatten();
            let (signal, raison) = linux::signal_de_l_exception(vecteur, cadre, 0, None, zone);
            tache::arreter_par_faute(signal, raison);
        }
        // int3 n'est pas une erreur : un débogueur s'en sert pour poser des
        // points d'arrêt. RIP désigne déjà l'instruction suivante : on
        // revient simplement.
        3 => afficherln!("[noyau] Exception 3 ({}) a RIP={:#x}, on continue.",
                         NOMS[3], cadre.rip),
        _ => exception_fatale(cadre),
    }
}

/// L'adresse de la dernière faute de page (CR2).
pub fn lire_cr2() -> u64 {
    let cr2: u64;
    // SAFETY : lecture d'un registre de contrôle, sans effet.
    unsafe { asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    cr2
}

/// Une exception dont le noyau ne se relève pas : on dit tout ce qu'on
/// sait, puis on s'arrête.
pub fn exception_fatale(cadre: &Cadre) -> ! {
    let vecteur = cadre.vecteur as usize;
    // On ne reviendra pas : libérer la console, au cas où l'exception
    // serait survenue au milieu d'un affichage.
    crate::console::preparer_panique();
    afficherln!("[noyau] EXCEPTION {} ({}), code d'erreur {:#x}",
                vecteur, NOMS.get(vecteur).unwrap_or(&"?"), cadre.code_erreur);
    afficherln!("        RIP={:#x} RSP={:#x} RFLAGS={:#x} CS={:#x}", cadre.rip, cadre.rsp, cadre.rflags, cadre.cs);
    if vecteur == 14 || vecteur == 8 {
        // Pour une faute de page, CR2 contient l'adresse fautive. Une double
        // faute née d'une faute de page la laisse aussi : c'est le cas d'une
        // pile qui déborde (la faute de page ne peut pas être empilée sur la
        // pile qui vient de fauter).
        let cr2 = lire_cr2();
        afficherln!("        adresse fautive (CR2) = {:#x}", cr2);
        if let Some(pile) = crate::pagination::garde_touchee(cr2) {
            afficherln!("        debordement de {} : la page de garde a ete touchee", pile);
        }
    }
    panic!("exception {} non geree", vecteur);
}
