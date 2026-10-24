//! La pagination du noyau : ses tables de pages définitives.
//!
//! Les tables de démarrage (main.rs, _start) projettent le premier Gio en
//! pages de 2 Mio, toutes inscriptibles et exécutables, et trois fois. On
//! les remplace par un arbre construit page par page :
//!
//!   - l'image du noyau, en pages de 4 Kio, avec pour chaque sorte de
//!     contenu ses seuls droits nécessaires (« W^X » : jamais à la fois
//!     inscriptible et exécutable) :
//!         code (.text)            lecture, exécution
//!         constantes (.rodata)    lecture seule
//!         données, pile (.data, .bss)  lecture, écriture
//!     sauf les pages de garde, sous la pile du noyau et sous sa pile de
//!     secours (gdt.rs), laissées sans projection : un débordement de la
//!     pile y fait faute de page. (Leurs cadres physiques, 4 Kio chacun,
//!     sont perdus : Linux, avec VMAP_STACK, place les piles dans une zone
//!     virtuelle à part, où les gardes ne coûtent que des adresses.)
//!     Une erreur du noyau qui écrirait dans son code, ou un attaquant qui
//!     y glisserait des octets à exécuter, déclenche une faute de page au
//!     lieu de réussir en silence. Linux fait de même (CONFIG_STRICT_KERNEL_RWX).
//!   - la projection directe de toute la mémoire VIVE (espace.rs), jamais
//!     exécutable : les zones libres de la carte E820, et le premier Mio
//!     (mémoire vidéo, données du BIOS). Rien d'autre : les trous de la
//!     carte sont des registres de périphériques (APIC, mémoire flash du
//!     BIOS...), qu'une page « write-back » laisserait le processeur lire
//!     par anticipation et mettre en cache ; et une grande page qui
//!     couvrirait plusieurs types de mémoire (MTRR) aurait un comportement
//!     indéfini (manuel d'Intel, vol. 3A). Linux ne projette que la RAM
//!     depuis 2008 (commit 66520ebc2df3) ; les registres des périphériques
//!     seront projetés à la demande, sans cache (ioremap). Des pages de
//!     2 Mio là où c'est possible, de 4 Kio aux bords des zones et sous
//!     2 Mio. Le code et les constantes du noyau y apparaissent une
//!     seconde fois : cet alias est en lecture seule, sinon on pourrait
//!     écrire du code par la projection directe puis l'exécuter par
//!     l'adresse du noyau (l'attaque « ret2dir »).
//!   - plus rien à l'identique : une adresse basse (un pointeur nul, par
//!     exemple) fait faute de page. La moitié basse est aux programmes :
//!     chacun y a ses propres tables (espace_utilisateur.rs), construites
//!     avec les mêmes fonctions.
//!
//! Un rappel du format (voir ../02-mode-long/boot.asm) : quatre niveaux de
//! tables de 512 entrées de 8 octets (PML4, PDPT, PD, PT), chacune un cadre
//! de 4 Kio. Les bits 47 à 39 de l'adresse choisissent l'entrée de la PML4,
//! et ainsi de suite ; une entrée de PD avec le bit « grande page » désigne
//! directement 2 Mio. Les droits se combinent à travers les niveaux (une
//! page n'est inscriptible que si TOUTES les entrées traversées le
//! permettent) : les entrées des tables intermédiaires donnent tout, et
//! seule l'entrée finale restreint.
//!
//! Le bit U/S (« utilisateur ») suit la même règle : un programme (anneau
//! 3) ne touche une page que si TOUTES les entrées traversées portent ce
//! bit. On le pose donc à tous les niveaux de la moitié basse, et jamais
//! dans la moitié haute : même une erreur dans une entrée finale du noyau
//! ne la rendrait pas visible aux programmes, puisque son entrée de PML4
//! ne le porte pas.

use crate::{cadres, carte_memoire, espace, pages};
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const PRESENTE: u64 = 1 << 0;
pub const ECRITURE: u64 = 1 << 1;
/// Accessible à l'anneau 3 (bit U/S).
pub const UTILISATEUR: u64 = 1 << 2;
/// Dans une PD : l'entrée désigne une page de 2 Mio, pas une PT.
const GRANDE: u64 = 1 << 7;
/// Défense d'exécuter (bit NX). Le processeur ne le reconnaît qu'une fois
/// EFER.NXE activé ; avant, c'est un bit réservé. Les tout premiers
/// processeurs 64 bits d'Intel ne l'ont pas : voir `a_le_bit_nx`.
const NON_EXECUTABLE: u64 = 1 << 63;
/// Les bits d'une entrée qui donnent l'adresse physique du niveau suivant.
pub const ADRESSE: u64 = 0x000F_FFFF_FFFF_F000;

const PAGE: u64 = 4096;

/// La première adresse de la moitié haute : les entrées 256 à 511 de la
/// PML4. Tout ce qui est en dessous est aux programmes.
pub const MOITIE_HAUTE: u64 = 0xffff_8000_0000_0000;

/// L'adresse physique de la PML4 du noyau, une fois en place.
static PML4_NOYAU: AtomicU64 = AtomicU64::new(0);
/// Le bit NX est-il en service (EFER.NXE) ?
static NX: AtomicBool = AtomicBool::new(false);
const PAGE_2MIO: u64 = 2 << 20;

/// Une table de pages : 512 entrées, un cadre.
type Table = [u64; 512];

/// Les tables de démarrage ne projettent que le premier Gio : les nouvelles
/// tables doivent y être, pour qu'on puisse les écrire avant de s'en servir.
const LIMITE_DEMARRAGE: u64 = 1 << 30;

unsafe extern "C" {
    // Les bornes des sections du noyau (linker.ld), adresses virtuelles.
    static __texte_debut: u8;
    static __lecture_seule_debut: u8;
    static __donnees_debut: u8;
    static __garde: u8;
    static __garde_secours: u8;
    static __bss_fin: u8;
}

/// L'adresse fait-elle partie de la page de garde, sous la pile du noyau ?
pub fn dans_la_garde(adresse: u64) -> bool {
    let garde = &raw const __garde as u64;
    (garde..garde + PAGE).contains(&adresse)
}

/// La table de pages d'adresse physique `physique`, vue par la projection
/// directe.
///
/// # Safety
/// `physique` doit être une table de pages qui n'appartient qu'à nous, et
/// projetée.
unsafe fn table(physique: u64) -> &'static mut Table {
    // SAFETY : garanti par l'appelant.
    unsafe { &mut *(espace::virtuelle(physique) as *mut Table) }
}

/// Un cadre pour une nouvelle table, mis à zéro (512 entrées absentes), ou
/// None s'il n'y a plus de mémoire.
///
/// Avant que l'allocateur de pages existe, les tables viennent de
/// l'allocateur de démarrage ; ensuite, de l'allocateur de pages. Comme
/// alloc_low_pages dans Linux, qui passe de memblock au buddy une fois
/// celui-ci prêt (after_bootmem).
fn nouvelle_table() -> Option<u64> {
    let cadre = if cadres::est_cede() {
        pages::allouer(0)?
    } else {
        let cadre = cadres::allouer()?;
        // Tant que les tables de démarrage sont en place, seul le premier
        // Gio est projeté. L'allocateur donne d'abord les cadres les plus
        // bas, juste après le noyau : bien sous la limite. Si ce n'était pas
        // le cas, on ne pourrait pas l'écrire : mieux vaut le dire que
        // fauter plus loin.
        assert!(cadre < LIMITE_DEMARRAGE, "table de pages au-dela du 1er Gio : {cadre:#x}");
        cadre
    };
    // SAFETY : le cadre vient d'être alloué, et la projection directe le
    // couvre (voir plus haut).
    let t = unsafe { table(cadre) };
    t.fill(0);
    Some(cadre)
}

/// L'entrée `index` de la table `parent` désigne la table du niveau
/// suivant : on la crée si elle est absente (avec les droits `droits` en
/// plus de « présente, inscriptible »), et on rend son adresse. None : plus
/// de mémoire pour une nouvelle table.
fn suivante(parent: u64, index: usize, droits: u64) -> Option<u64> {
    // SAFETY : `parent` est une de nos tables, créée par nouvelle_table.
    let entree = &mut unsafe { table(parent) }[index];
    if *entree & PRESENTE == 0 {
        *entree = nouvelle_table()? | PRESENTE | ECRITURE | droits;
    }
    assert!(*entree & GRANDE == 0, "une grande page est deja projetee ici");
    Some(*entree & ADRESSE)
}

pub fn index(virtuelle: u64, niveau: u32) -> usize {
    (virtuelle >> (12 + 9 * niveau) & 511) as usize
}

/// L'entrée finale (dans une PT) de la page de 4 Kio `virtuelle`, en créant
/// les tables intermédiaires qui manquent. Dans la moitié basse, elles
/// reçoivent le bit UTILISATEUR. None : plus de mémoire pour une table.
pub fn entree(pml4: u64, virtuelle: u64) -> Option<&'static mut u64> {
    let u = if virtuelle < MOITIE_HAUTE { UTILISATEUR } else { 0 };
    let pdpt = suivante(pml4, index(virtuelle, 3), u)?;
    let pd = suivante(pdpt, index(virtuelle, 2), u)?;
    let pt = suivante(pd, index(virtuelle, 1), u)?;
    // SAFETY : `pt` est une de nos tables.
    Some(&mut unsafe { table(pt) }[index(virtuelle, 0)])
}

/// Projette la page de 4 Kio `virtuelle` sur le cadre `physique`. Dans la
/// moitié basse, la page reçoit aussi le bit UTILISATEUR.
pub fn projeter(pml4: u64, virtuelle: u64, physique: u64, droits: u64) -> Option<()> {
    let u = if virtuelle < MOITIE_HAUTE { UTILISATEUR } else { 0 };
    *entree(pml4, virtuelle)? = physique | PRESENTE | droits | u;
    Some(())
}

/// Les droits « non exécutable » : le bit NX s'il est en service, rien
/// sinon (sans lui, une page présente est toujours exécutable).
pub fn non_executable() -> u64 {
    if NX.load(Ordering::Relaxed) { NON_EXECUTABLE } else { 0 }
}

/// L'adresse physique de la PML4 du noyau.
pub fn pml4_noyau() -> u64 {
    PML4_NOYAU.load(Ordering::Relaxed)
}

/// La table de pages d'adresse physique `physique`, en lecture seule
/// (pour la parcourir sans la modifier).
///
/// # Safety
/// Comme `table` : une de nos tables, projetée.
pub unsafe fn lire_table(physique: u64) -> &'static Table {
    // SAFETY : garanti par l'appelant.
    unsafe { table(physique) }
}

/// Fait de `pml4` l'espace d'adressage courant (CR3). Écrire CR3 vide
/// aussi le cache des traductions (TLB) de tout ce qui n'est pas global :
/// rien de l'espace précédent ne sert plus.
///
/// # Safety
/// `pml4` doit être une PML4 complète, dont la moitié haute est celle du
/// noyau (sinon, l'instruction suivante est introuvable).
pub unsafe fn activer(pml4: u64) {
    // SAFETY : garanti par l'appelant.
    unsafe { asm!("mov cr3, {}", in(reg) pml4, options(nostack)) };
}

/// La PML4 courante (CR3, sans ses bits de contrôle).
pub fn courante() -> u64 {
    let cr3: u64;
    // SAFETY : lecture d'un registre de contrôle, sans effet.
    unsafe { asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
    cr3 & ADRESSE
}

/// Projette la page de 2 Mio `virtuelle` sur `physique` (tous deux alignés
/// sur 2 Mio), dans la moitié haute (le noyau seul s'en sert).
fn projeter_2mio(pml4: u64, virtuelle: u64, physique: u64, droits: u64) {
    let pdpt = suivante(pml4, index(virtuelle, 3), 0).expect(PLUS_DE_TABLES);
    let pd = suivante(pdpt, index(virtuelle, 2), 0).expect(PLUS_DE_TABLES);
    // SAFETY : `pd` est une de nos tables.
    let pd = unsafe { table(pd) };
    pd[index(virtuelle, 1)] = physique | PRESENTE | GRANDE | droits;
}

/// Le processeur connaît-il le bit NX ? CPUID, feuille 0x80000001, bit 20
/// d'EDX (le chargeur a déjà lu cette feuille pour le mode long). Sans lui,
/// écrire EFER.NXE fait une faute de protection générale ; Linux se passe
/// alors de NX, et le dit (« NX (Execute Disable) protection: not
/// present »). On fait de même : les données restent exécutables, le reste
/// des protections tient.
///
/// Un BIOS peut pourtant le cacher sur un processeur Intel (l'option
/// « Execute Disable » du BIOS, le bit 34 du registre IA32_MISC_ENABLE) :
/// Linux efface ce bit et redemande (verify_cpu.S). On fait de même.
fn a_le_bit_nx() -> bool {
    // cpuid existe sur tout processeur 64 bits : Rust le tient pour sûr.
    let nx = || core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 20) != 0;
    if nx() {
        return true;
    }
    // « GenuineIntel », dans ebx, edx, ecx de la feuille 0.
    let fabricant = core::arch::x86_64::__cpuid(0);
    if (fabricant.ebx, fabricant.edx, fabricant.ecx) != (0x756e_6547, 0x4965_6e69, 0x6c65_746e) {
        return false;
    }
    // SAFETY : IA32_MISC_ENABLE (0x1A0) existe sur tout processeur Intel 64
    // bits ; effacer le bit 34 ne fait que rendre NX visible.
    unsafe {
        asm!(
            "mov ecx, 0x1A0",
            "rdmsr",
            "and edx, ~(1 << 2)",
            "wrmsr",
            out("rax") _, out("rcx") _, out("rdx") _,
            options(nostack),
        );
    }
    nx()
}

/// Ce que l'initialisation a fait, pour l'afficher.
pub struct Bilan {
    /// Le bit NX est-il en service ?
    pub nx: bool,
    pub pages_noyau: u64,
    pub projection_directe: u64,
}

/// Projette dans la projection directe les pages de [debut, fin[ (alignées
/// sur 4 Kio) : des pages de 2 Mio là où elles tiennent entières, de 4 Kio
/// ailleurs. `droits` : ceux de chaque page de 4 Kio.
fn projeter_etendue(pml4: u64, debut: u64, fin: u64, droits_2mio: u64, droits: impl Fn(u64) -> u64) -> u64 {
    let mut p = debut;
    while p < fin {
        if p >= PAGE_2MIO && p % PAGE_2MIO == 0 && p + PAGE_2MIO <= fin {
            projeter_2mio(pml4, espace::virtuelle(p), p, droits_2mio);
            p += PAGE_2MIO;
        } else {
            projeter(pml4, espace::virtuelle(p), p, droits(p)).expect(PLUS_DE_TABLES);
            p += PAGE;
        }
    }
    fin - debut
}

/// Au démarrage, sans mémoire pour les tables du noyau, rien ne peut
/// marcher : on s'arrête (les programmes, eux, reçoivent une erreur).
const PLUS_DE_TABLES: &str = "plus de memoire pour les tables de pages";

/// Construit les tables définitives et s'en sert.
pub fn initialiser() -> Bilan {
    // Les adresses des symboles, sans jamais lire ce qu'ils désignent.
    let texte = &raw const __texte_debut as u64;
    let lecture_seule = &raw const __lecture_seule_debut as u64;
    let donnees = &raw const __donnees_debut as u64;
    let fin = &raw const __bss_fin as u64;
    let fin = fin.next_multiple_of(PAGE);
    let pml4 = nouvelle_table().expect(PLUS_DE_TABLES);
    let nx = a_le_bit_nx();
    NX.store(nx, Ordering::Relaxed);
    let non_executable = if nx { NON_EXECUTABLE } else { 0 };

    // 1. L'image du noyau, sauf les pages de garde (sous la pile du noyau
    // et sous la pile de secours de la double faute).
    let garde_secours = &raw const __garde_secours as u64;
    let mut gardes = 0;
    for v in (texte..fin).step_by(PAGE as usize) {
        if dans_la_garde(v) || v == garde_secours {
            gardes += 1;
            continue;
        }
        let droits = if v < lecture_seule {
            0 // code : ni écriture, ni NX
        } else if v < donnees {
            non_executable
        } else {
            ECRITURE | non_executable
        };
        projeter(pml4, v, espace::physique_du_noyau(v), droits).expect(PLUS_DE_TABLES);
    }

    // 2. La projection directe : le premier Mio, puis chaque étendue libre
    // (arrondie vers l'intérieur : un morceau de page n'est pas à nous).
    // L'alias du code et des constantes du noyau, sous 2 Mio, en pages de
    // 4 Kio en lecture seule.
    let (debut_lecture, fin_lecture) = (espace::physique_du_noyau(texte), espace::physique_du_noyau(donnees));
    let droits = |p: u64| {
        let ecriture = if (debut_lecture..fin_lecture).contains(&p) { 0 } else { ECRITURE };
        ecriture | non_executable
    };
    let premier_mio = 1 << 20;
    let mut projetes = projeter_etendue(pml4, 0, premier_mio, ECRITURE | non_executable, droits);
    carte_memoire::etendues_libres(|debut, fin| {
        let (debut, fin) = (debut.max(premier_mio).next_multiple_of(PAGE), fin / PAGE * PAGE);
        if debut < fin {
            projetes += projeter_etendue(pml4, debut, fin, ECRITURE | non_executable, droits);
        }
    });

    // 3. On active les protections, puis les nouvelles tables.
    //   - EFER.NXE (bit 11 du registre spécifique 0xC0000080), si le
    //     processeur a le bit NX : sans lui, ce bit de nos entrées serait un
    //     bit réservé, et chaque accès à une page qui le porte ferait faute.
    //   - CR0.WP (bit 16) : sans lui, le noyau (anneau 0) pourrait écrire
    //     même dans une page en lecture seule ; la protection ne vaudrait
    //     que pour les programmes.
    //   - CR3 : l'adresse physique de la nouvelle PML4. L'écrire vide aussi
    //     le cache des traductions (TLB) : plus rien de l'ancien arbre ne
    //     sert.
    // SAFETY : les nouvelles tables projettent tout ce dont le noyau se sert
    // (son image, la mémoire par la projection directe), aux mêmes adresses
    // virtuelles qu'avant ; l'exécution continue donc sans heurt.
    unsafe {
        if nx {
            asm!(
                "mov ecx, 0xC0000080",
                "rdmsr",
                "or eax, 1 << 11",
                "wrmsr",
                out("rax") _, out("rcx") _, out("rdx") _,
                options(nostack),
            );
        }
        asm!(
            "mov rax, cr0",
            "or rax, 1 << 16",
            "mov cr0, rax",
            "mov cr3, {pml4}",
            pml4 = in(reg) pml4,
            out("rax") _,
            options(nostack),
        );
    }
    PML4_NOYAU.store(pml4, Ordering::Relaxed);
    Bilan { nx, pages_noyau: (fin - texte) / PAGE - gardes, projection_directe: projetes }
}
