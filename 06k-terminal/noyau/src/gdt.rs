//! La GDT du noyau, et la TSS de chaque processeur.
//!
//! Le chargeur avait sa propre GDT, rangée dans SA mémoire (vers 0x7E00).
//! Le noyau ne doit dépendre de rien de ce qui reste du chargeur : il
//! installe la sienne. En 64 bits, elle ne sert plus qu'à trois choses :
//!
//!   - dire au CPU qu'on exécute du code 64 bits, en mode noyau (sélecteur
//!     de code), avec un segment de données valide ;
//!   - fournir les segments des PROGRAMMES (anneau 3) : un sélecteur de
//!     code et un de données de niveau de privilège 3, que le processeur
//!     charge en passant dans un programme (sysretq, iretq) ;
//!   - désigner la TSS (Task State Segment). Son nom vient du 386, mais en
//!     64 bits elle ne sert plus qu'à ranger des adresses de PILES : celles
//!     que le CPU prend quand une interruption arrive (voir Tss).
//!
//! L'ORDRE des descripteurs est imposé par les instructions `syscall` et
//! `sysretq` : elles ne lisent pas la GDT pour choisir leurs sélecteurs,
//! elles les calculent à partir du registre STAR (voir appel_systeme.rs).
//!   - `syscall` prend CS = STAR[47:32] et SS = ce sélecteur + 8 : il faut
//!     le code noyau, puis les données noyau, l'un après l'autre ;
//!   - `sysretq` prend CS = STAR[63:48] + 16 et SS = STAR[63:48] + 8 (avec
//!     le niveau 3) : il faut, à partir d'une base, un emplacement (le code
//!     32 bits utilisateur, pour `sysretl`), les données utilisateur, puis
//!     le code 64 bits utilisateur.
//! D'où la disposition de Linux (arch/x86/include/asm/segment.h), entrée
//! pour entrée :
//!     0x00  nul
//!     0x08  code noyau 32 bits          : laissé NUL
//!     0x10  code noyau 64 bits          (STAR[47:32])
//!     0x18  données noyau
//!     0x20  code utilisateur 32 bits    (STAR[63:48]) : laissé NUL
//!     0x28  données utilisateur         -> sélecteur 0x2B (niveau 3)
//!     0x30  code utilisateur 64 bits    -> sélecteur 0x33
//!     0x38  libre
//!     0x40  TSS (deux entrées)
//! Choix de conception : les MÊMES sélecteurs que Linux, et pas seulement
//! le même ordre. Les programmes les voient : dans CS et SS bien sûr, et
//! dans le contexte que reçoit un gestionnaire de signal (le sigcontext,
//! cadre_signal.rs), que lisent des programmes faits pour Linux (un JIT
//! qui regarde CS pour savoir s'il interrompt du code 64 bits, un
//! débogueur). Option écartée : la disposition serrée des étapes 5 à 6e
//! (code noyau en 0x08, programmes en 0x23 et 0x2B), qui économisait une
//! entrée mais donnait aux programmes d'autres sélecteurs que Linux. Les
//! deux codes 32 bits restent nuls : pas de « mode compatibilité » pour
//! exécuter des programmes 32 bits ; un programme qui y sauterait (`ljmp`
//! vers 0x23) ferait une faute de protection générale, et `sysretl` n'est
//! jamais employé.
//!
//! Depuis 6j, chaque processeur a SA TSS et SA GDT, dans sa zone
//! (processeur.rs) : les sept premiers descripteurs sont les mêmes partout,
//! mais le descripteur de la TSS porte l'adresse de celle du processeur, et
//! `ltr` ne la charge que pour lui. C'est le `gdt_page` et le `cpu_tss_rw`
//! par processeur de Linux. Option écartée : une seule GDT dont on
//! réécrirait le descripteur de TSS avant chaque `ltr` : les processeurs
//! démarrent l'un après l'autre, ce serait possible, mais `ltr` marque la
//! TSS « occupée » dans son descripteur, et une TSS occupée ne se recharge
//! pas sans l'effacer : une entrée par processeur est plus simple à relire.

use core::arch::asm;
use core::mem::size_of;

use crate::processeur::{self, Processeur};

pub const CODE_NOYAU: u16 = 0x10;
pub const DONNEES_NOYAU: u16 = 0x18;
/// La base des sélecteurs de `sysretq` (STAR[63:48]).
pub const BASE_UTILISATEUR: u16 = 0x20;
/// Les sélecteurs des programmes : index dans la GDT, plus le niveau de
/// privilège demandé (RPL) 3, dans les deux bits bas.
pub const DONNEES_UTILISATEUR: u16 = 0x28 | 3;
pub const CODE_UTILISATEUR: u16 = 0x30 | 3;
const SELECTEUR_TSS: u16 = 0x40;

/// Les piles de l'IST (Interrupt Stack Table), de 1 à 7 ; 0 = « pas
/// d'IST ». Pour certaines exceptions, le processeur change TOUJOURS de
/// pile, quelle que soit la pile courante, parce qu'elles peuvent tomber à
/// un instant où celle-ci n'est pas sûre :
///   - la double faute : souvent née d'une pile du noyau qui déborde
///     (voir interruptions.rs) ;
///   - le NMI, le débogage (#DB) et la vérification machine (#MC) : ils
///     peuvent arriver juste après `syscall`, quand le processeur est en
///     anneau 0 mais que RSP vaut encore ce que le PROGRAMME y a mis (voir
///     appel_systeme.rs) ; sans IST, le processeur empilerait son cadre à
///     cette adresse, choisie par le programme. Le NMI et #MC ne se
///     masquent pas par `cli`. #DB, lui, ne tombe pas là pour un simple
///     pas-à-pas : `syscall` efface TF, et le processeur ne lève le #DB
///     d'un TF armé qu'après être revenu au programme (le test pas-a-pas
///     le vérifie). Mais un point d'arrêt matériel (les registres DR0-DR7,
///     que posera un débogueur) sur une donnée lue par `mov ss` juste
///     avant `syscall` lève son #DB à la première instruction du noyau :
///     la faille CVE-2018-8897, contre laquelle Linux a aussi mis #DB sur
///     une pile IST. Ce #DB-là, venu de l'anneau 0, arrête chez nous le
///     noyau (interruptions.rs : toute exception du noyau est fatale) là
///     où Linux le sert ; aucun programme ne peut poser de point d'arrêt
///     matériel (pas de ptrace, DR0 à DR7 jamais écrits) : le cas est
///     latent, à reprendre avec un débogueur.
/// C'est la liste de Linux (arch/x86/include/asm/page_64_types.h : DF,
/// NMI, DB, MCE). Depuis 6j, ces piles sont PAR PROCESSEUR : deux NMI en
/// même temps sur deux processeurs ne peuvent pas partager une pile
/// (Linux : les `exception_stacks` de la `cpu_entry_area` de chacun).
pub const IST_DOUBLE_FAUTE: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_DEBOGAGE: u8 = 3;
pub const IST_VERIFICATION_MACHINE: u8 = 4;

/// La TSS 64 bits, au format imposé par le processeur. `packed` : les champs
/// de 8 octets n'y sont pas alignés (rsp0 commence à l'octet 4), et Rust
/// ne doit pas ajouter de rembourrage.
#[repr(C, packed)]
pub struct Tss {
    _reserve1: u32,
    /// Les piles à prendre en entrant dans l'anneau 0, 1 ou 2 depuis un
    /// anneau moins privilégié. Seule rsp[0] sert au processeur : c'est la
    /// pile noyau du programme en cours, prise à chaque interruption venue
    /// de l'anneau 3. rsp[2] ne sert pas au processeur (pas d'anneau 2) :
    /// comme Linux, l'entrée de `syscall` y range le RSP du programme, le
    /// temps de changer de pile (voir appel_systeme.rs).
    rsp: [u64; 3],
    _reserve2: u64,
    /// Les 7 piles de l'IST.
    ist: [u64; 7],
    _reserve3: u64,
    _reserve4: u16,
    /// Position de la table des droits sur les ports : au-delà de la TSS,
    /// donc « aucune » : un programme n'a accès à aucun port (`in` et `out`
    /// font une faute de protection générale en anneau 3, IOPL valant 0).
    iomap: u16,
}

/// La TSS d'un processeur, alignée sur 128 octets : ses 104 octets ne
/// chevauchent ainsi jamais deux pages, ce que demande le manuel d'Intel
/// (vol. 3A, 8.2.1 : le processeur la lit en une fois). Dans la zone du
/// processeur (processeur.rs), à un décalage connu de l'assembleur de
/// l'entrée de `syscall` : rsp[0] à l'octet 4 de la TSS, rsp[2] à l'octet
/// 20. Le noyau ne l'écrit que toujours interruptions coupées, sur son seul
/// processeur : rsp[0] à chaque bascule (tache.rs), rsp[2] à chaque entrée
/// de `syscall` (FMASK a coupé les interruptions).
#[repr(C, align(128))]
pub struct TssAlignee(Tss);

impl TssAlignee {
    pub const fn vide() -> TssAlignee {
        TssAlignee(Tss {
            _reserve1: 0,
            rsp: [0; 3],
            _reserve2: 0,
            ist: [0; 7],
            _reserve3: 0,
            _reserve4: 0,
            iomap: size_of::<Tss>() as u16,
        })
    }
}

/// Les sommets des quatre piles de l'IST d'un processeur, dans l'ordre des
/// numéros (double faute, NMI, débogage, vérification machine).
pub struct PilesIst(pub [u64; 4]);

unsafe extern "C" {
    // Les sommets des piles de l'IST du premier processeur, chacune
    // précédée d'une page de garde, réservées par le script d'édition de
    // liens (linker.ld). Celles des autres processeurs viennent de vmalloc
    // (6j, les processeurs secondaires).
    static __pile_secours_haut: u8;
    static __pile_nmi_haut: u8;
    static __pile_debogage_haut: u8;
    static __pile_mc_haut: u8;
}

/// Les piles de l'IST du premier processeur, celles de la .bss.
pub fn piles_ist_du_premier() -> PilesIst {
    // Adresse de chaque pile : son sommet, car une pile x86 descend.
    PilesIst([
        &raw const __pile_secours_haut as u64,
        &raw const __pile_nmi_haut as u64,
        &raw const __pile_debogage_haut as u64,
        &raw const __pile_mc_haut as u64,
    ])
}

/// Même format que les descripteurs écrits à la main à l'étape 2a (voir
/// 02-mode-protege/boot.asm), en une seule valeur de 64 bits :
const NULLE: u64 = 0;
/// Code noyau 64 bits : accès 0x9B (présent, DPL 0, code, lisible, accédé),
/// flags 0xA (G=1, L=1, DB=0). Base et limite ignorées en 64 bits.
const CODE_64: u64 = 0x00AF_9B00_0000_FFFF;
/// Données noyau : accès 0x93 (présent, DPL 0, données, inscriptible).
const DONNEES: u64 = 0x00CF_9300_0000_FFFF;
/// Les mêmes pour les programmes : DPL 3 (bits 5 et 6 de l'octet d'accès,
/// 0x9B -> 0xFB, 0x93 -> 0xF3).
const CODE_64_UTILISATEUR: u64 = 0x00AF_FB00_0000_FFFF;
const DONNEES_UTILISATEUR_DESC: u64 = 0x00CF_F300_0000_FFFF;

/// Met en place la GDT et la TSS du processeur `p`, celui qui exécute
/// ceci, avec les piles de l'IST `piles` ; puis recharge les segments et
/// la base de GS. Au démarrage de chaque processeur, interruptions
/// coupées, avant toute interruption.
pub fn initialiser(p: &'static Processeur, piles: PilesIst) {
    let tss = p.tss.get();
    let base_tss = tss as u64;
    // SAFETY: le démarrage de ce processeur, interruptions coupées :
    // personne d'autre ne touche à sa TSS ni à sa GDT (processeur.rs).
    unsafe {
        let tss = &mut (*tss).0;
        tss.ist[(IST_DOUBLE_FAUTE - 1) as usize] = piles.0[0];
        tss.ist[(IST_NMI - 1) as usize] = piles.0[1];
        tss.ist[(IST_DEBOGAGE - 1) as usize] = piles.0[2];
        tss.ist[(IST_VERIFICATION_MACHINE - 1) as usize] = piles.0[3];
    }

    // Descripteur de TSS (16 octets) : base éclatée comme dans un
    // descripteur de segment, type 0x89 = présent, « TSS 64 bits libre ».
    let limite = (size_of::<Tss>() - 1) as u64;
    let tss_bas = (limite & 0xFFFF)
        | (base_tss & 0xFF_FFFF) << 16
        | 0x89 << 40
        | (limite >> 16 & 0xF) << 48
        | (base_tss >> 24 & 0xFF) << 56;
    let tss_haut = base_tss >> 32;

    // SAFETY: comme ci-dessus, la GDT de ce processeur, au démarrage.
    let gdt = unsafe { &mut *p.gdt.get() };
    *gdt = [NULLE, NULLE, CODE_64, DONNEES, NULLE, DONNEES_UTILISATEUR_DESC, CODE_64_UTILISATEUR, NULLE, tss_bas, tss_haut];

    // Ce que lit lgdt : taille - 1, puis adresse.
    #[repr(C, packed)]
    struct Descripteur {
        limite: u16,
        base: u64,
    }
    let descripteur = Descripteur {
        limite: (size_of::<[u64; 10]>() - 1) as u16,
        base: gdt.as_ptr() as u64,
    };

    // SAFETY: la GDT est dans une zone statique (elle vivra aussi longtemps
    // que le noyau) et ses sélecteurs correspondent à ce qu'on charge
    // ensuite.
    unsafe {
        asm!(
            "lgdt [{desc}]",
            // Recharger CS : impossible avec mov. On empile le nouveau
            // sélecteur et l'adresse de retour, puis « retour lointain »
            // (retfq) les dépile dans CS et RIP : un saut lointain déguisé.
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {donnees:x}",
            "mov es, {donnees:x}",
            "mov ss, {donnees:x}",
            "mov fs, {donnees:x}",
            "mov gs, {donnees:x}",
            // Le CPU charge la TSS et la marque « occupée » dans la GDT
            // (d'où une GDT en mémoire inscriptible).
            "ltr {tss:x}",
            desc = in(reg) &descripteur,
            code = in(reg) CODE_NOYAU as u64,
            tmp = out(reg) _,
            donnees = in(reg) DONNEES_NOYAU as u64,
            tss = in(reg) SELECTEUR_TSS as u64,
        );
    }
    // `mov gs, ...` vient de remettre la base de GS à celle du descripteur
    // de données, zéro : la zone du processeur serait perdue. On la repose
    // (ce que fait `switch_gdt_and_percpu_base` chez Linux).
    processeur::charger_base_gs(p);
}

/// La pile noyau que prendra ce processeur à la prochaine entrée depuis
/// l'anneau 3 : celle du programme qu'on va lancer (son sommet).
///
/// # Safety
/// Interruptions coupées (une interruption venue de l'anneau 3 lit ce
/// champ, et la zone du processeur se lit interruptions coupées), et
/// `sommet` doit être le sommet d'une pile du noyau réservée à ce
/// programme.
pub unsafe fn definir_pile_noyau(sommet: u64) {
    let tss = processeur::courant().tss.get();
    // SAFETY: garanti par l'appelant ; écriture d'un champ non aligné
    // d'une structure packed, par un pointeur brut.
    unsafe { (&raw mut (*tss).0.rsp[0]).write_unaligned(sommet) };
}
