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

use crate::{clavier, faute_de_page, gdt, horloge, irq, linux, ordonnanceur, processus, tache};
use crate::verrou::Verrou;
use core::arch::{asm, global_asm};
use core::mem::size_of;
use core::sync::atomic::Ordering;

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
    cld
    /* LA BASE DE GS (6j, voir appel_systeme.rs et processeur.rs). Le
       noyau trouve la zone de son processeur par GS ; à l'entrée, il faut
       que ce soit SA base qui soit active, pas celle du programme. Trois
       cas, ceux de l'`error_entry` et du `paranoid_entry` de Linux ; EBX
       dira à la sortie s'il faut rééchanger (il est préservé par l'appel
       de gerer_interruption : l'ABI le dit « callee-saved »), et vaut 0
       sauf dans le troisième cas.
       1. Venue de l'anneau 3 (CS & 3 == 3) : la base du programme est
          active, `swapgs`, puis `lfence` (la spéculation, CVE-2019-1125).
          À la sortie, retour_interruption rééchangera d'après le CS.
       2. Venue de l'anneau 0, sur l'`iretq` qui rendait la main à un
          programme (le « bad iret » de Linux : une faute de segment absent
          (11), de pile (12) ou de protection générale (13), parce que le
          cadre que dépilait iretq venait du programme, après rt_sigreturn :
          un CS ou un SS invalide, un RIP non canonique). On venait de
          faire `swapgs` pour le programme : sa base est active, `swapgs`
          d'abord (le `.Lerror_bad_iret`). Puis c'est sa faute à lui : on
          fait comme si l'exception venait de lui (`reparer_iret`, qui
          recopie son cadre en haut de la pile de la tâche), et la suite
          ordinaire la voit venue de l'anneau 3 : un signal, jamais un arrêt
          du noyau. RAX est déjà rangé dans le cadre. Le CS du cadre que
          dépilait iretq, au RSP fautif, le confirme : vers l'anneau 3 ;
          vers l'anneau 0 (un cadre du noyau abîmé, une erreur du noyau), la
          base active est celle du noyau, et l'exception est fatale comme
          toute autre venue du noyau (Linux suppose l'anneau 3, nous
          vérifions, pour que l'arrêt soit propre). Le CS du cadre que
          dépilait iretq, au RSP fautif, le confirme : vers l'anneau 3 ;
          vers l'anneau 0 (un cadre du noyau abîmé, une erreur du noyau), la
          base active est celle du noyau, et l'exception est fatale comme
          toute autre venue du noyau (Linux suppose l'anneau 3, nous
          vérifions, pour que l'arrêt soit propre).
       3. Venue de l'anneau 0, sur un vecteur à pile IST (le NMI, #DB, #MC,
          la double faute) : il a pu tomber entre `syscall` et son `swapgs`,
          ou entre le `swapgs` du retour et `sysretq`, quand le noyau a la
          base du PROGRAMME. On ne peut pas le savoir par CS : on lit le
          MSR GS_BASE et on regarde son signe (le `paranoid_entry` de
          Linux) : une adresse du noyau est négative (la moitié haute) ; une
          base du programme ne l'est jamais (arch_prctl refuse ARCH_SET_GS,
          elle vaut 0). Positive : `swapgs`, et EBX = 1 pour le `swapgs`
          inverse à la sortie. Un #DB venu de l'anneau 3 (icebp) n'est pas
          dans ce cas : il prend le chemin 1, et la copie de son cadre sur
          la pile de la tâche, plus bas (chez Linux aussi, idtentry_mce_db :
          le paranoïaque n'est que pour l'anneau 0) ; lui faire les deux
          rendrait la main au programme avec la base du noyau.
       Toute autre interruption venue de l'anneau 0 trouve la base du noyau
       active : pas de `swapgs`, mais un `lfence` quand même (le label 9,
       plus bas : le FENCE_SWAPGS_KERNEL_ENTRY de Linux). */
    xor ebx, ebx
    test byte ptr [rsp + {cs}], 3
    jz 6f
    swapgs
    lfence
    jmp 3f
6:
    mov rax, [rsp + {vecteur}]
    cmp rax, 11
    jb 7f
    cmp rax, 13
    ja 7f
    lea rcx, [rip + iret_retour]
    cmp [rsp + {rip}], rcx
    jne 7f
    mov rcx, [rsp + {rsp}]
    test byte ptr [rcx + 8], 3
    jz 9f
    swapgs
    lfence
    mov rdi, rsp
    call reparer_iret
    mov rsp, rax
    jmp 3f
7:
    cmp rax, 1
    je 8f
    cmp rax, 2
    je 8f
    cmp rax, 8
    je 8f
    cmp rax, 18
    jne 9f
8:
    mov ecx, 0xC0000101
    rdmsr
    test edx, edx
    js 9f
    swapgs
    lfence
    mov ebx, 1
    jmp 3f
9:
    /* La base du noyau etait active, pas de swapgs : lfence quand meme (le
       FENCE_SWAPGS_KERNEL_ENTRY de Linux). La faille a deux faces : le
       processeur peut, en speculation, SAUTER le swapgs qu'il fallait (d'ou
       le lfence apres chacun, ci-dessus), ou en EXECUTER un qu'il ne
       fallait pas, sur la branche mal predite, et lire gs:[...] avec la
       base du programme : d'ou celui-ci. */
    lfence
3:
    /* Un #DB venu d'un programme arrive sur sa pile de l'IST (gdt.rs), qui
       ne doit servir que le temps de l'entrée : le programme va mourir de
       ce SIGTRAP au retour, et la prochaine exception du même vecteur,
       dans une autre tâche, réécrirait cette pile. Comme Linux
       (`sync_regs`, entry_64.S), on recopie tout le cadre (22 valeurs) en
       haut de la pile noyau de la tâche (TSS.rsp[0], dans la zone du
       processeur), libre puisque la tâche était dans l'anneau 3, et on
       continue de là. Le NMI, la double faute et #MC arrêtent le noyau :
       ils restent sur leur pile. */
    cmp qword ptr [rsp + {vecteur}], 1
    jne 2f
    test byte ptr [rsp + {cs}], 3
    jz 2f
    mov rsi, rsp
    mov rdi, gs:[{tss} + 4]
    sub rdi, 22 * 8
    mov rdx, rdi
    mov ecx, 22
    rep movsq
    mov rsp, rdx
2:
    /* Le CPU a aligné la pile sur 16 octets avant d'empiler son cadre ;
       5 + 2 + 15 = 22 valeurs de 8 octets : elle l'est toujours, comme
       l'exige l'ABI avant un call (et le sommet de la pile de la tâche est
       aligné aussi). */
    mov rdi, rsp
    call gerer_interruption
    /* La sortie du chemin 3 : la base du programme rendue, puisqu'on
       l'avait trouvée active (le `paranoid_exit` de Linux). CS est de
       l'anneau 0 dans ce cas : retour_interruption n'y touchera plus.
       Exécutée seulement pour un NMI ignoré (console.rs : celui qui frappe
       le processeur qui panique) : un #DB de l'anneau 0, une double faute,
       un #MC arrêtent le noyau sans revenir ici. */
    test ebx, ebx
    jz retour_interruption
    swapgs
    /* Le retour par iretq, partagé : la sortie d'un appel système qui ne
       peut pas prendre sysretq, et le premier départ d'un programme
       (tache.rs), y sautent aussi, RSP sur un cadre complet. Vers l'anneau
       3, la base de GS du programme d'abord : interruptions coupées ici
       (verifier_au_retour revient ainsi, et l'entrée de syscall a fait
       cli), seul un NMI peut tomber entre ce swapgs et iretq, et il
       retrouve la zone par le MSR (chemin 3). */
    .global retour_interruption
retour_interruption:
    test byte ptr [rsp + {cs}], 3
    jz 5f
    swapgs
5:
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
    .global iret_retour
iret_retour:
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
    "#,
    vecteur = const core::mem::offset_of!(Cadre, vecteur),
    cs = const core::mem::offset_of!(Cadre, cs),
    rip = const core::mem::offset_of!(Cadre, rip),
    rsp = const core::mem::offset_of!(Cadre, rsp),
    tss = const core::mem::offset_of!(crate::processeur::Processeur, tss),
);

/// Le cadre d'une faute de l'`iretq` de `retour_interruption` (voir plus
/// haut), devenu celui d'une exception venue du programme, comme le
/// `fixup_bad_iret` de Linux : les registres généraux du cadre de la faute,
/// déjà ceux du programme (`retour_interruption` venait de les dépiler) ; son
/// vecteur et son code d'erreur ; et RIP, CS, RFLAGS, RSP, SS, ceux que
/// dépilait `iretq`, à l'adresse du RSP de la faute. Le tout est recopié en
/// haut de la pile noyau de la tâche, là où est toujours le cadre d'un
/// programme. Les trois zones se recouvrent (le cadre que dépilait iretq, en
/// haut ; celui de la faute, juste dessous ; la destination, qui couvre les
/// deux) : on lit tout dans une copie locale, plus bas sur la pile, avant
/// d'écrire. Rend l'adresse du nouveau cadre ; si `iretq` ramenait au
/// noyau (CS de niveau 0 : une erreur du noyau), le cadre de la faute tel
/// quel, et la suite s'arrête (`exception_fatale`).
#[unsafe(no_mangle)]
extern "C" fn reparer_iret(faute: *mut Cadre) -> *mut Cadre {
    // SAFETY: `faute` est le cadre que vient d'empiler interruption_commune ;
    // son RSP désigne les cinq mots que dépilait iretq, sur la même pile.
    let (mut nouveau, cible) = unsafe {
        let f = *faute;
        let iret = f.rsp as *const u64;
        let cible = [iret.read(), iret.add(1).read(), iret.add(2).read(), iret.add(3).read(), iret.add(4).read()];
        (f, cible)
    };
    if cible[1] & 3 != 3 {
        return faute;
    }
    nouveau.rip = cible[0];
    nouveau.cs = cible[1];
    nouveau.rflags = cible[2];
    nouveau.rsp = cible[3];
    nouveau.ss = cible[4];
    let destination = tache::courante().cadre_du_programme();
    // SAFETY: le haut de la pile noyau de la tâche courante ; tout ce qu'il y
    // avait est dans `nouveau` et `cible`, des copies.
    unsafe { destination.write(nouveau) };
    destination
}

/// Ce que le code commun a empilé, dans l'ordre inverse des push.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
        // SAFETY: tableau constant défini dans le global_asm! ci-dessus.
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
    drop(idt);
    charger_idt();
}

/// Charge l'IDT, commune à tous les processeurs, dans celui qui exécute
/// ceci : le premier au démarrage (`initialiser`), chaque secondaire à son
/// départ (smp.rs). Interruptions coupées.
pub fn charger_idt() {
    let idt = IDT.verrouiller();
    #[repr(C, packed)]
    struct Descripteur {
        limite: u16,
        base: u64,
    }
    let descripteur = Descripteur {
        limite: (size_of::<[Entree; 256]>() - 1) as u16,
        base: idt.as_ptr() as u64,
    };
    // SAFETY: l'IDT est statique et chaque entrée présente pointe vers un
    // talon valide.
    unsafe { asm!("lidt [{}]", in(reg) &descripteur, options(nostack)) };
}

/// Le nombre d'interruptions matérielles en cours de traitement (la part
/// HARDIRQ du `preempt_count` de Linux, que lit `in_hardirq()`) : un
/// gestionnaire d'interruption ne s'exécute pour aucune tâche, il ne doit
/// jamais dormir. Les verrous qui dorment le vérifient (attente.rs, le
/// `might_sleep` de Linux) ; les interruptions coupées ne le disent pas,
/// puisqu'on dort aussi interruptions coupées (attente.rs). Les exceptions
/// (une faute de page) ne comptent pas : elles s'exécutent pour la tâche
/// interrompue, qui peut dormir. Un compteur par processeur, dans sa zone
/// (processeur.rs), écrit interruptions coupées par le gestionnaire.
///
/// Une interruption matérielle est-elle en cours de traitement ? Lu
/// interruptions actives aussi (les verrous qui dorment, avant de
/// s'endormir) : s'il n'est pas nul, c'est que NOUS sommes dans un
/// gestionnaire, qui ne peut pas être déplacé ; s'il est nul, il le reste
/// pour nous (l'exception écrite dans processeur.rs).
pub fn dans_une_interruption() -> bool {
    crate::processeur::interruptions_en_cours() != 0
}

/// Appelée par le code commun pour chaque interruption.
///
/// Pour TOUS les vecteurs, ce qui compte d'abord est le privilège du code
/// interrompu (les deux bits bas de CS dans le cadre) :
///   - venue d'un programme (anneau 3), une exception est SA faute : il
///     sera arrêté, avec le signal que lui enverrait Linux, et le noyau
///     continue. Même pour une exception qui n'est jamais une erreur dans
///     le noyau (int3) : un `int3`, un `icebp` ou un `int 0x80` d'un
///     programme ne doivent pas arrêter le noyau ;
///   - venue du noyau, c'est une erreur du noyau : on s'arrête (sauf int3,
///     le test du démarrage) ;
///   - le NMI, la double faute et la vérification machine ne sont la faute
///     de personne en particulier (une panne matérielle, ou le noyau dans
///     un état incohérent) : on s'arrête, d'où qu'ils viennent.
/// Linux fait ce même tri (user_mode(regs) dans arch/x86/kernel/traps.c).
///
/// Le programme ne meurt pas ici, mais à la sortie vers l'anneau 3, à la
/// fin de cette fonction (tache::verifier_au_retour) : le gestionnaire
/// prévoit sa fin, et se termine normalement.
#[unsafe(no_mangle)]
extern "C" fn gerer_interruption(cadre: &mut Cadre) {
    let vecteur = cadre.vecteur as usize;
    let depuis_programme = cadre.cs & 3 == 3;
    // Pour #DB, DR6 dit pourquoi : lu et remis à son état de repos EN
    // PREMIER, avant tout ce qui peut céder le processeur (Linux le lit en
    // entrant dans `exc_debug`, `debug_read_clear_dr6`). Jusqu'en 6j, il
    // était lu plus bas, après le retour des interruptions et la lecture de
    // la mémoire du processus, un verrou qui dort : la tâche pouvait avoir
    // été déplacée entre-temps, et lire le DR6 d'un AUTRE processeur (ou
    // celui d'une autre tâche, dont le #DB serait passé là entre-temps : le
    // si_code du SIGTRAP était faux). Un reste de 6f, que le
    // multiprocesseur rend probable.
    let dr6 = if vecteur == 1 { lire_et_effacer_dr6() } else { 0 };
    match vecteur {
        32.. => {
            // Interruptions coupées (la porte d'interruption) : la zone est
            // celle de ce processeur.
            let dans_une_interruption = &crate::processeur::courant().dans_une_interruption;
            dans_une_interruption.fetch_add(1, Ordering::Relaxed);
            irq::gerer(vecteur as u8, |source| match source {
                irq::Source::TimerApic | irq::Source::Isa(horloge::IRQ) => {
                    // Le temps n'est compté que par le processeur 0 (le
                    // `tick_do_timer_cpu` de Linux) ; chaque processeur
                    // fait tourner sa file des prêtes (tache::tic).
                    if crate::processeur::courant().numero == 0 {
                        horloge::tic();
                    }
                    tache::tic(depuis_programme);
                }
                irq::Source::Isa(clavier::IRQ) => clavier::interruption(),
                irq::Source::Isa(_) => {}
                irq::Source::Fonction => crate::smp::recevoir_appel(),
                // Rien à faire : la sortie de l'interruption regarde si la
                // tâche courante doit céder (plus bas), et un processeur
                // endormi dans `hlt` est réveillé par l'interruption même.
                irq::Source::Reprogrammation => {}
                irq::Source::Arret => crate::smp::s_arreter(),
            });
            // L'instant d'une interruption de périphérique, pour le
            // générateur aléatoire (le `add_interrupt_randomness` que
            // Linux appelle de `handle_irq_event_percpu`).
            if irq::est_un_peripherique(vecteur as u8) {
                crate::aleatoire::ajouter_interruption(vecteur as u64, cadre.rip);
            }
            // Avant la préemption éventuelle (plus bas) : la tâche suivante
            // ne doit pas hériter du compte (Linux : `irq_exit`, avant
            // `preempt_schedule_irq`).
            dans_une_interruption.fetch_sub(1, Ordering::Relaxed);
        }
        // Un NMI pendant qu'un autre processeur panique : il nous
        // l'envoie parce que nous ne répondions pas à son IPI d'arrêt
        // (interruptions coupées) ; on s'arrête sans rien dire (smp.rs).
        2 if crate::smp::arret_demande() => {
            // Sauf si c'est NOUS qui paniquons (le NMI du moniteur de QEMU
            // va à tous les processeurs, le nôtre compris) : on l'ignore,
            // et le message continue ; la sortie du chemin paranoïaque
            // rend la base de GS qu'il avait trouvée.
            if !crate::console::je_panique() {
                crate::smp::s_arreter();
            }
        }
        2 | 8 | 18 => exception_fatale(cadre),
        // La faute de page, d'où qu'elle vienne : le plus souvent servie
        // (la pagination à la demande), sinon le programme sera arrêté, ou
        // la copie du noyau rend EFAULT (faute_de_page.rs).
        14 => faute_de_page::gerer(cadre),
        _ if depuis_programme => {
            // Pour le message, la zone du code fautif : lue dans la mémoire
            // du processus, un verrou qui dort. Les interruptions reviennent
            // d'abord (le `cond_local_irq_enable` des pièges de Linux) : on
            // vient du programme, rien n'est tenu.
            crate::cpu::activer_interruptions();
            let zone = processus::memoire_lue(|m| m.zone_du_code(cadre.rip));
            let (signal, raison) = linux::signal_de_l_exception(vecteur, cadre, 0, None, zone, dr6);
            tache::forcer_par_faute(signal, raison);
        }
        // Une faute de protection générale du noyau sur une instruction de
        // la table d'exceptions (copie_utilisateur.rs) : XRSTOR d'un état
        // x87/SSE venu d'un programme (rt_sigreturn, sse.rs), que le
        // processeur refuse. On reprend à son adresse de reprise, qui rend
        // une erreur (le `fixup_exception` de `do_general_protection`).
        13 if crate::copie_utilisateur::reprise(cadre.rip).is_some() => {
            cadre.rip = crate::copie_utilisateur::reprise(cadre.rip).unwrap_or(cadre.rip);
        }
        // int3 n'est pas une erreur : un débogueur s'en sert pour poser des
        // points d'arrêt. RIP désigne déjà l'instruction suivante : on
        // revient simplement.
        3 => afficherln!("[noyau] Exception 3 ({}) a RIP={:#x}, on continue.",
                         NOMS[3], cadre.rip),
        _ => exception_fatale(cadre),
    }
    // Interrompu au milieu d'un appel système (dans le noyau), le programme
    // verra sa fin, ses signaux, sa limite de temps de calcul à la fin de
    // l'appel (appel_systeme.rs), quand le noyau aura fini ce qu'il faisait
    // pour lui. Mais le noyau, lui, peut céder le processeur ici, si
    // l'interruption l'a trouvé interruptions actives, donc sans verrou
    // (ordonnanceur.rs) : après l'EOI, déjà envoyé par irq::gerer. Jamais
    // après une exception à pile IST : les interruptions des périphériques
    // n'en ont pas.
    if depuis_programme {
        tache::verifier_au_retour(cadre);
    } else if vecteur >= 32 && cadre.rflags & 1 << 9 != 0 {
        ordonnanceur::preempter();
    }
}

/// DR6, le registre qui dit d'où vient un #DB, puis remis à sa valeur de
/// repos (DR6_RESERVED : les bits réservés à 1, les autres à 0) : sinon ses
/// bits resteraient pour le #DB suivant.
fn lire_et_effacer_dr6() -> u64 {
    let dr6: u64;
    // SAFETY: lire et écrire DR6 en anneau 0 ne touche que ce registre.
    unsafe {
        asm!("mov {}, dr6", out(reg) dr6, options(nomem, nostack));
        asm!("mov dr6, {}", in(reg) 0xFFFF_0FF0u64, options(nomem, nostack));
    }
    dr6
}

/// L'adresse de la dernière faute de page (CR2).
pub fn lire_cr2() -> u64 {
    let cr2: u64;
    // SAFETY: lecture d'un registre de contrôle, sans effet.
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
