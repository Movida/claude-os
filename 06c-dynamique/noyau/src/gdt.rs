//! La GDT du noyau, et sa TSS.
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
//! D'où :
//!     0x00  nul
//!     0x08  code noyau 64 bits          (STAR[47:32])
//!     0x10  données noyau
//!     0x18  code utilisateur 32 bits    (STAR[63:48]) : laissé NUL
//!     0x20  données utilisateur         -> sélecteur 0x23 (niveau 3)
//!     0x28  code utilisateur 64 bits    -> sélecteur 0x2B
//!     0x30  TSS (deux entrées)
//! Linux a la même disposition, décalée d'une entrée (il garde un code
//! noyau 32 bits en 0x08). Le code utilisateur 32 bits reste nul : pas de
//! « mode compatibilité » pour exécuter des programmes 32 bits. Un
//! programme qui y sauterait (`ljmp` vers 0x1B) ferait une faute de
//! protection générale, et `sysretl` n'est jamais employé.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::mem::size_of;

use crate::verrou::Verrou;

pub const CODE_NOYAU: u16 = 0x08;
pub const DONNEES_NOYAU: u16 = 0x10;
/// La base des sélecteurs de `sysretq` (STAR[63:48]).
pub const BASE_UTILISATEUR: u16 = 0x18;
/// Les sélecteurs des programmes : index dans la GDT, plus le niveau de
/// privilège demandé (RPL) 3, dans les deux bits bas.
pub const DONNEES_UTILISATEUR: u16 = 0x20 | 3;
pub const CODE_UTILISATEUR: u16 = 0x28 | 3;
const SELECTEUR_TSS: u16 = 0x30;

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
///     une pile IST.
/// C'est la liste de Linux (arch/x86/include/asm/page_64_types.h : DF,
/// NMI, DB, MCE).
pub const IST_DOUBLE_FAUTE: u8 = 1;
pub const IST_NMI: u8 = 2;
pub const IST_DEBOGAGE: u8 = 3;
pub const IST_VERIFICATION_MACHINE: u8 = 4;

/// La TSS 64 bits, au format imposé par le processeur. `packed` : les champs
/// de 8 octets n'y sont pas alignés (rsp0 commence à l'octet 4), et Rust
/// ne doit pas ajouter de rembourrage.
#[repr(C, packed)]
struct Tss {
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

/// La TSS du processeur, lue et écrite aussi par l'assembleur de l'entrée
/// de `syscall` (par son nom, TSS_PROCESSEUR, et la position de ses champs :
/// rsp[0] à l'octet 4, rsp[2] à l'octet 20). D'où un nom fixe
/// (no_mangle), et pas de Verrou autour : le processeur et l'entrée de
/// `syscall` y accèdent sans passer par lui. Le noyau ne l'écrit que
/// toujours interruptions coupées, sur son seul processeur : rsp[0] en
/// démarrant un programme, rsp[2] à chaque entrée de `syscall` (FMASK a
/// coupé les interruptions). Avec plusieurs processeurs, il y en aura une
/// par processeur, comme cpu_tss_rw dans Linux.
#[repr(transparent)]
pub struct TssPartagee(UnsafeCell<Tss>);

// SAFETY : voir plus haut ; un seul processeur, accès interruptions
// coupées.
unsafe impl Sync for TssPartagee {}

#[unsafe(no_mangle)]
static TSS_PROCESSEUR: TssPartagee = TssPartagee(UnsafeCell::new(Tss {
    _reserve1: 0,
    rsp: [0; 3],
    _reserve2: 0,
    ist: [0; 7],
    _reserve3: 0,
    _reserve4: 0,
    iomap: size_of::<Tss>() as u16,
}));

unsafe extern "C" {
    // Les sommets des piles de l'IST, chacune précédée d'une page de garde,
    // réservées par le script d'édition de liens (linker.ld).
    static __pile_secours_haut: u8;
    static __pile_nmi_haut: u8;
    static __pile_debogage_haut: u8;
    static __pile_mc_haut: u8;
}

/// 8 entrées de 8 octets : les 6 descripteurs de segment (dont le code
/// 32 bits nul), puis la TSS qui en occupe deux (son adresse est sur
/// 64 bits).
static GDT: Verrou<[u64; 8]> = Verrou::new([0; 8]);

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

pub fn initialiser() {
    let base_tss = TSS_PROCESSEUR.0.get() as u64;
    // SAFETY : au démarrage, interruptions coupées, personne d'autre ne
    // touche à la TSS.
    unsafe {
        let tss = &mut *TSS_PROCESSEUR.0.get();
        // Adresse de chaque pile : son sommet, car une pile x86 descend.
        tss.ist[(IST_DOUBLE_FAUTE - 1) as usize] = &raw const __pile_secours_haut as u64;
        tss.ist[(IST_NMI - 1) as usize] = &raw const __pile_nmi_haut as u64;
        tss.ist[(IST_DEBOGAGE - 1) as usize] = &raw const __pile_debogage_haut as u64;
        tss.ist[(IST_VERIFICATION_MACHINE - 1) as usize] = &raw const __pile_mc_haut as u64;
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

    let mut gdt = GDT.verrouiller();
    *gdt = [NULLE, CODE_64, DONNEES, NULLE, DONNEES_UTILISATEUR_DESC, CODE_64_UTILISATEUR, tss_bas, tss_haut];

    // Ce que lit lgdt : taille - 1, puis adresse.
    #[repr(C, packed)]
    struct Descripteur {
        limite: u16,
        base: u64,
    }
    let descripteur = Descripteur {
        limite: (size_of::<[u64; 8]>() - 1) as u16,
        base: gdt.as_ptr() as u64,
    };

    // SAFETY : la GDT est statique (elle vivra aussi longtemps que le
    // noyau) et ses sélecteurs correspondent à ce qu'on charge ensuite.
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
}

/// La pile noyau que prendra le processeur à la prochaine entrée depuis
/// l'anneau 3 : celle du programme qu'on va lancer (son sommet).
///
/// # Safety
/// Interruptions coupées (une interruption venue de l'anneau 3 lit ce
/// champ), et `sommet` doit être le sommet d'une pile du noyau réservée
/// à ce programme.
pub unsafe fn definir_pile_noyau(sommet: u64) {
    // SAFETY : garanti par l'appelant ; écriture d'un champ non aligné
    // d'une structure packed, par un pointeur brut.
    unsafe { (&raw mut (*TSS_PROCESSEUR.0.get()).rsp[0]).write_unaligned(sommet) };
}
