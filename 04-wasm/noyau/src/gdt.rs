//! La GDT du noyau, et sa TSS.
//!
//! Le chargeur avait sa propre GDT, rangée dans SA mémoire (vers 0x7E00).
//! Le noyau ne doit dépendre de rien de ce qui reste du chargeur : il
//! installe la sienne. En 64 bits, elle ne sert plus qu'à deux choses :
//!
//!   - dire au CPU qu'on exécute du code 64 bits, en mode noyau (sélecteur
//!     de code), avec un segment de données valide ;
//!   - désigner la TSS (Task State Segment). Son nom vient du 386, mais en
//!     64 bits elle ne sert plus qu'à ranger des adresses de PILES : celles
//!     que le CPU prend quand une interruption arrive. On s'en sert pour
//!     l'IST (Interrupt Stack Table) : une pile de secours pour la double
//!     faute, comme Linux. Elle ne protégera du débordement de la pile du
//!     noyau qu'avec une page de garde, pas encore en place (voir
//!     interruptions.rs).

use crate::verrou::Verrou;
use core::arch::asm;
use core::mem::size_of;

pub const CODE_NOYAU: u16 = 0x08;
pub const DONNEES_NOYAU: u16 = 0x10;
const SELECTEUR_TSS: u16 = 0x18;

/// Numéro de la pile de secours dans l'IST (1 à 7 ; 0 = « pas d'IST »).
pub const IST_DOUBLE_FAUTE: u8 = 1;

/// La TSS 64 bits, au format imposé par le processeur. `packed` : les champs
/// de 8 octets n'y sont pas alignés (rsp0 commence à l'octet 4), et Rust
/// ne doit pas ajouter de rembourrage.
#[repr(C, packed)]
struct Tss {
    _reserve1: u32,
    /// Piles à prendre en passant du mode utilisateur au noyau (étape 6).
    rsp: [u64; 3],
    _reserve2: u64,
    /// Les 7 piles de l'IST.
    ist: [u64; 7],
    _reserve3: u64,
    _reserve4: u16,
    /// Position de la table des droits sur les ports : au-delà de la TSS,
    /// donc « aucune » (un programme utilisateur n'aura aucun port).
    iomap: u16,
}

/// La pile de secours : 16 Kio, alignée sur 16 octets comme l'exige l'ABI.
#[repr(C, align(16))]
struct Pile([u8; 16 * 1024]);
static PILE_DOUBLE_FAUTE: Verrou<Pile> = Verrou::new(Pile([0; 16 * 1024]));

static TSS: Verrou<Tss> = Verrou::new(Tss {
    _reserve1: 0,
    rsp: [0; 3],
    _reserve2: 0,
    ist: [0; 7],
    _reserve3: 0,
    _reserve4: 0,
    iomap: size_of::<Tss>() as u16,
});

/// 5 entrées de 8 octets : nulle, code, données, puis la TSS qui en
/// occupe deux (son adresse est sur 64 bits).
static GDT: Verrou<[u64; 5]> = Verrou::new([0; 5]);

/// Même format que les descripteurs écrits à la main à l'étape 2a (voir
/// 02-mode-protege/boot.asm), en une seule valeur de 64 bits :
const NULLE: u64 = 0;
/// Code noyau 64 bits : accès 0x9B (présent, DPL 0, code, lisible, accédé),
/// flags 0xA (G=1, L=1, DB=0). Base et limite ignorées en 64 bits.
const CODE_64: u64 = 0x00AF_9B00_0000_FFFF;
/// Données noyau : accès 0x93 (présent, DPL 0, données, inscriptible).
const DONNEES: u64 = 0x00CF_9300_0000_FFFF;

pub fn initialiser() {
    // Adresse de la pile de secours : son sommet, car une pile x86 descend.
    let sommet = {
        let pile = PILE_DOUBLE_FAUTE.verrouiller();
        &raw const pile.0 as u64 + size_of::<Pile>() as u64
    };
    let base_tss = {
        let mut tss = TSS.verrouiller();
        tss.ist[(IST_DOUBLE_FAUTE - 1) as usize] = sommet;
        &raw const *tss as u64
    };

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
    *gdt = [NULLE, CODE_64, DONNEES, tss_bas, tss_haut];

    // Ce que lit lgdt : taille - 1, puis adresse.
    #[repr(C, packed)]
    struct Descripteur {
        limite: u16,
        base: u64,
    }
    let descripteur = Descripteur {
        limite: (size_of::<[u64; 5]>() - 1) as u16,
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
