//! L'espace d'adressage d'un programme : sa moitié basse à lui, la moitié
//! haute au noyau.
//!
//! Chaque programme a sa propre PML4 (la racine de ses tables de pages) :
//!   - les entrées 0 à 255 (la moitié basse, 128 Tio) sont à lui, vides au
//!     départ ; on y projette ses pages, chacune un cadre neuf, dans les
//!     zones que lui permet sa carte (memoire.rs) ;
//!   - les entrées 256 à 511 (la moitié haute) sont une COPIE de celles du
//!     noyau : elles désignent les mêmes tables, donc le noyau est visible
//!     au même endroit dans tous les espaces. Un appel système ou une
//!     interruption n'a pas à changer de tables pour trouver le code du
//!     noyau. Ces entrées ne portent pas le bit UTILISATEUR (voir
//!     pagination.rs) : le programme ne peut ni les lire ni les écrire.
//!
//! La copie suppose que les entrées hautes de la PML4 du noyau ne changent
//! plus après le démarrage : vrai aujourd'hui (son image et la projection
//! directe sont construites une fois pour toutes). Quand le noyau projettera
//! des zones à la demande (vmalloc), il faudra créer d'avance toutes ses
//! tables de second niveau, comme Linux (preallocate_vmalloc_pages), pour
//! que les copies restent justes.
//!
//! Options écartées :
//!   - un seul espace pour tous les programmes (comme les premiers Unix sur
//!     des machines sans pagination) : plus d'isolation entre eux ;
//!   - une moitié haute sans le noyau (KPTI, la parade de Linux contre
//!     Meltdown, 2018) : à chaque entrée dans le noyau, il faut changer de
//!     CR3, et sans PCID chaque changement vide le TLB. En 6n, avec PCID
//!     (Meltdown touche les Intel d'avant 2018).
//!
//! Adresses permises : de 64 Kio à la dernière page de la moitié basse,
//! exclue, comme Linux :
//!   - sous 64 Kio (vm.mmap_min_addr) : rien, pour qu'un pointeur nul
//!     déréférencé par le NOYAU (un champ d'une structure à l'adresse 0 +
//!     décalage) fasse toujours faute, au lieu de lire ce qu'un programme
//!     aurait mis à l'adresse 0 ;
//!   - la dernière page (0x7fff_ffff_f000, TASK_SIZE_MAX) : un `syscall`
//!     dans ses tout derniers octets reviendrait à 0x8000_0000_0000, une
//!     adresse non canonique, et `sysretq` ferait alors une faute en
//!     anneau 0 sur les processeurs Intel (CVE-2012-0217). Interdire la
//!     page supprime le cas.
//!
//! LE VIDAGE DES TLB ENTRE PROCESSEURS (6j, le « TLB shootdown »). Deux fils
//! d'un même programme sur deux processeurs : A fait `munmap` d'une page
//! que B vient de lire ; le TLB du processeur de B garde la traduction, et
//! B lit encore l'ancienne page, qui est peut-être déjà à quelqu'un
//! d'autre. Le `invlpg` de A ne vide que son propre TLB. D'où :
//!   - LE MASQUE DES PROCESSEURS de l'espace (`MasqueProcesseurs`, le
//!     `mm_cpumask` de Linux), partagé avec l'entrée du processus
//!     (processus.rs) : un processeur y met son bit AVANT de charger la
//!     PML4 de l'espace (tache.rs, `charger_espace`, un `fetch_or` : une
//!     instruction `lock`, une barrière complète), et le retire quand il
//!     la quitte, pour une autre ou pour celle du noyau. Il peut le retirer
//!     parce que nous n'avons pas de TLB paresseuse (6e) : changer de CR3
//!     vide tout ce qui n'est pas global, et rien des programmes ne l'est
//!     avant 6n. C'est la façon de Linux d'avant 6.x ; Linux 6.18 laisse le
//!     bit et le retire paresseusement quand une demande le trouve sur un
//!     autre espace. « L'espace est actif », décidé jusqu'à 6i par le CR3
//!     de CE processeur, est remplacé par le masque : rien à invalider
//!     seulement s'il est vide ;
//!   - LA BARRIÈRE : l'émetteur écrit les entrées des tables, puis lit le
//!     masque ; le receveur met son bit, puis charge CR3 et parcourt les
//!     tables. C'est le motif de Dekker (verrou.rs) : sans barrière
//!     complète, l'émetteur peut lire un masque sans le bit pendant que le
//!     receveur lit l'ancienne entrée, et la page périmée est relue sans
//!     bruit. Un `fence(SeqCst)` avant de lire le masque (smp::vider_tlb)
//!     est la paire du `fetch_or` du receveur ; chez Linux, c'est
//!     `inc_mm_tlb_gen` qui porte cette barrière (« callers are required to
//!     order their read of mm_cpumask after their writes to the paging
//!     structures ») ;
//!   - LA DEMANDE (smp::vider_tlb) : l'espace (la PML4), une plage de pages
//!     ou « tout » (au-delà de 33 pages, recharger CR3 plutôt qu'enchaîner
//!     les `invlpg` : PLAFOND_INVLPG) ; préemption coupée, le vidage local
//!     si ce processeur a l'espace, `smp::appeler` sur le masque sans soi,
//!     l'attente des réponses. Le receveur vérifie que c'est bien cette
//!     PML4 qu'il a chargée (sinon il ignore : le `f->mm != loaded_mm` de
//!     `flush_tlb_func`, pour le processeur qui a retiré son bit après la
//!     lecture du masque) ;
//!   - LA RÈGLE : jamais sous un verrou court. Attendre une réponse
//!     interruptions coupées, c'est le blocage mutuel de smp.rs. Le lot qui
//!     rend les pages (`Lot`, notre `mmu_gather`) porte toutes les
//!     invalidations ; `retirer_plage` REMPLIT le lot de l'appelant au lieu
//!     de le vider, et l'appelant le vide une fois la garde du verrou des
//!     tables lâchée (`retirer_par_tranches` : munmap, madvise et la
//!     troncature, qui ne tiennent la mémoire qu'en lecture ; la pose d'une
//!     page de fichier qui recommence, memoire.rs) ; qui tient la mémoire
//!     en écriture (mprotect, la dernière tâche qui rend l'espace) n'a pas
//!     ce verrou et vide quand il veut. Le lot vide les TLB partout, PUIS rend les cadres
//!     (une page rendue avant que tous l'aient oubliée pourrait être relue
//!     par l'autre fil une fois donnée à quelqu'un d'autre) ;
//!   - LA COPIE À L'ÉCRITURE, dans l'ordre de Linux (`wp_page_copy`).
//!     Remplacer une entrée (la page de zéros ou une page partagée, lue par
//!     un fil, écrite par un autre) ne se fait pas en posant la nouvelle
//!     entrée puis en vidant l'ancienne traduction : dans cette fenêtre, un
//!     fil C écrit dans la page neuve pendant qu'un fil B lit encore la
//!     page de zéros par sa traduction périmée, et B peut voir une écriture
//!     de C faite après, dans une autre page, sans voir celle-ci (« that
//!     left a window where the new PTE could be loaded into some TLBs while
//!     the old PTE remains in others »). Linux efface l'entrée et vide
//!     D'ABORD, sous le verrou des tables, parce que son verrou ne coupe pas
//!     les interruptions ; le nôtre les coupe. Donc : l'entrée est remplacée
//!     par une marque EN_REMPLACEMENT (une entrée absente avec un bit
//!     logiciel, comme les « migration entries » de Linux), le verrou des
//!     tables rendu, l'ancienne traduction vidée partout (`Servi::Remplacement`,
//!     memoire.rs), le verrou repris, et la nouvelle entrée posée si la
//!     marque y est encore (`remplacer`) ; une faute concurrente d'un autre
//!     fil qui trouve la marque recommence (`Servi::ARefaire`, le mécanisme
//!     de 6i). L'ancienne page n'est lâchée qu'après le vidage.
//!   Les adresses du noyau (la pile d'un fil mort, une projection rendue :
//!   vmalloc.rs) sont oubliées par TOUS les processeurs (smp::vider_tlb_noyau,
//!   le `flush_tlb_kernel_range` de Linux). Options écartées : la TLB
//!   paresseuse de Linux (un fil du noyau garde le CR3 du processus
//!   précédent, au prix du filtrage des IPI par `is_lazy` : à revoir en 6n
//!   avec PCID, quand changer de CR3 ne videra plus le TLB) ; la génération
//!   `tlb_gen` (éviter de vider deux fois pour deux demandes concurrentes :
//!   nos programmes ont peu de fils ; sa barrière, elle, est gardée).
//!
//! Toute allocation faite pour un programme est faillible : sans mémoire,
//! il reçoit une erreur (ENOMEM), ou il est tué à la faute (le tueur OOM,
//! memoire.rs) ; le noyau ne panique jamais. Pages et tables d'un
//! programme sont prises au-dessus de la réserve du noyau
//! (pages::allouer_pour_programme), et comptées. Sa carte des zones, elle,
//! vient du tas du noyau, qui peut puiser dans la réserve : 3 Mio au plus
//! pour 65 530 zones, 5 Mio le temps de l'agrandir, l'ancienne et la
//! nouvelle ensemble (zones/src/lib.rs, `agrandir`) (Linux, lui, prend ses
//! vm_area_struct au-dessus du seuil ; à faire avec les allocations
//! faillibles du noyau).

use crate::faillible::VecFaillible;
use crate::partage::Arc;
use crate::{espace, pages, pagination, smp};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use pagination::{ADRESSE, PRESENTE};
use zones::Droits;

const PAGE: u64 = 4096;

/// Une page du programme rendue inaccessible (mprotect avec PROT_NONE) :
/// le processeur ne sait pas dire « présente mais interdite » ; on retire
/// le bit PRESENTE, et on garde le cadre dans l'entrée, marquée de ce bit
/// que le processeur laisse au système (le bit 9 : « disponible »). C'est
/// l'équivalent du _PAGE_PROTNONE de Linux, qui prend, lui, le bit 8 (le
/// bit « global », que le processeur ignore aussi quand la page n'est pas
/// présente) : on le garde libre pour les pages globales du noyau. Un
/// accès fait alors une faute de page.
const SANS_ACCES: u64 = 1 << 9;

/// Une page en cours de remplacement par la copie à l'écriture (voir
/// l'en-tête) : l'entrée est absente, garde l'ancien cadre (qu'elle tient
/// toujours), et porte ce bit, le second que le processeur laisse au
/// système (le bit 10). Une faute qui la trouve recommence ; `retirer_plage`
/// la retire comme une page (le cadre est alors lâché par lui, et le
/// remplacement qui revient ne trouve plus sa marque : il recommence).
const EN_REMPLACEMENT: u64 = 1 << 10;

/// Le jeton d'une marque de remplacement : dans les bits qu'une entrée
/// absente laisse libres (1 à 8, et 52 à 62 ; ni le 9, SANS_ACCES, ni le
/// 10, ni le 63), 19 bits qui changent à chaque marque, si bien que deux
/// marques posées sur la même page ne sont jamais égales et que `remplacer`
/// reconnaît la sienne en comparant l'entrée entière. Sans lui, une marque
/// retirée (madvise, la troncature, mémoire tenue en lecture) puis reposée
/// par un autre fil était prise pour la sienne (un ABA, trouvé par la
/// relecture de 6j) : la page du premier était posée pendant le vidage du
/// second. Linux n'a pas ce cas : `wp_page_copy` garde le verrou de la
/// table du `pte_same` au `set_pte_at`.
static JETONS: AtomicU32 = AtomicU32::new(1);

fn jeton_de_marque() -> u64 {
    let j = u64::from(JETONS.fetch_add(1, Ordering::Relaxed));
    ((j & 0xFF) << 1) | ((j >> 8) & 0x7FF) << 52
}

/// Les processeurs qui ont chargé la PML4 d'un espace, un bit par numéro
/// (le `mm_cpumask` de Linux, voir l'en-tête) : partagé entre l'espace
/// (qui le lit pour vider les TLB) et l'entrée du processus (processus.rs :
/// la bascule l'écrit, tache.rs, sans le verrou qui dort de la mémoire).
/// Avec lui, le nombre de retraits de pages en cours dans l'espace.
pub struct MasqueProcesseurs {
    pub processeurs: AtomicU64,
    /// Les retraits de pages en cours, mémoire tenue en lecture (madvise,
    /// la troncature, le second temps de munmap : `retirer_par_tranches`),
    /// le `tlb_flush_pending` de Linux. Deux retraits de la même plage en
    /// même temps : le second ne trouve que des entrées déjà effacées, son
    /// lot est vide, et il rendrait la main pendant que le lot du premier,
    /// qui porte les traductions à vider, attend encore : un autre
    /// processeur garderait la traduction après le retour de l'appel. Le
    /// dernier vidage d'un retrait vide donc TOUT le TLB des processeurs
    /// de l'espace dès qu'un autre retrait est en cours (le
    /// `mm_tlb_flush_nested` de `tlb_finish_mmu`, le correctif de 2017
    /// « mm: fix MADV_[FREE|DONTNEED] TLB flush miss problem »). SeqCst :
    /// l'incrément du premier précède ses effacements (sous le verrou des
    /// tables), que le second voit avant de lire le compte.
    pub retraits: AtomicU32,
}

/// Ce que l'espace a en place, en pages, lisible SANS AUCUN VERROU (les
/// `rss_stat` de Linux, 6j) : les cadres anonymes à lui (MM_ANONPAGES), les
/// pages de fichiers projetées (MM_FILEPAGES ; les deux font le RSS, que
/// /proc/self/statm dit à part, 6d), les tables de pages de sa moitié
/// basse, PML4 comprise (`pgtables_bytes` : elles aussi sont de la mémoire
/// prise pour lui, 8 Gio touchés page à page en demandent 16 Mio), et le
/// plus grand RSS qu'il ait eu (`hiwater_rss`, le ru_maxrss de getrusage ;
/// Linux le met à jour juste avant que le RSS baisse, ici à chaque page
/// posée, ce qui revient au même pour un maximum, sans oublier un chemin qui
/// retire des pages). Écrits par qui pose ou retire des pages : sous le
/// verrou des tables, la mémoire du processus tenue en lecture (une faute,
/// une page de fichier posée, un lot qui retire des pages : munmap,
/// madvise, la troncature) ou en écriture (mprotect, la dernière tâche qui
/// rend l'espace) ; lus par qui ne tient pas ce verrou (statm, getrusage,
/// le tueur OOM, le message de fin d'un programme), la mémoire tenue en
/// lecture ou pas du tout : Relaxed, une lecture à la fois, des indications
/// (Linux somme de même des compteurs par processeur sans verrou). Partagé
/// par l'espace et l'entrée du processus (processus.rs), comme
/// `MasqueProcesseurs`.
pub struct Compteurs {
    pages: AtomicUsize,
    pages_fichier: AtomicUsize,
    tables: AtomicUsize,
    pic: AtomicUsize,
}

impl Compteurs {
    /// Le nombre de cadres projetés à lui (la mémoire « résidente »
    /// anonyme).
    pub fn pages(&self) -> usize {
        self.pages.load(Ordering::Relaxed)
    }

    /// Le nombre de pages de fichiers projetées.
    pub fn pages_fichier(&self) -> usize {
        self.pages_fichier.load(Ordering::Relaxed)
    }

    /// Le RSS : les deux.
    pub fn resident(&self) -> usize {
        self.pages() + self.pages_fichier()
    }

    /// Le nombre de tables de pages de sa moitié basse.
    pub fn tables(&self) -> usize {
        self.tables.load(Ordering::Relaxed)
    }

    /// Le plus grand RSS qu'il ait eu, en pages.
    pub fn pic(&self) -> usize {
        self.pic.load(Ordering::Relaxed)
    }

    /// Le RSS vient de grandir : le plus grand suit.
    fn suivre_pic(&self) {
        self.pic.fetch_max(self.resident(), Ordering::Relaxed);
    }
}

/// La page de zéros : une page du noyau, toujours nulle, que reçoit en
/// lecture seule toute page d'un programme LUE avant d'avoir été écrite
/// (la ZERO_PAGE de Linux). Une seule pour tous les programmes et toutes
/// les adresses : une zone lue sans être écrite (un tableau qu'on parcourt
/// avant de le remplir, une réservation qu'on sonde) ne coûte aucune
/// mémoire. La première écriture fait une faute (la page est en lecture
/// seule), et le noyau donne alors une page neuve à la place : la COPIE À
/// L'ÉCRITURE, le mécanisme qui servira aussi aux fichiers projetés en
/// privé (6b) et à fork (6l).
///
/// Elle est dans les constantes du noyau (.rodata) : la pagination W^X la
/// projette en lecture seule pour le noyau aussi, y compris par la
/// projection directe ; personne ne peut l'écrire, même par erreur. Elle ne
/// vient pas de l'allocateur de pages : on ne la lui rend jamais (le
/// parcours qui rend les cadres la reconnaît et la saute).
///
/// Options écartées : une page neuve, mise à zéro, à chaque faute de
/// lecture (plus simple, sans copie à l'écriture, mais chaque page lue
/// coûte 4 Kio pour rien) ; une page de zéros par programme (rien à
/// gagner : elle n'est jamais écrite).
#[repr(C, align(4096))]
struct PageDeZeros([u8; 4096]);

#[unsafe(link_section = ".rodata.page_de_zeros")]
static PAGE_DE_ZEROS: PageDeZeros = PageDeZeros([0; 4096]);

/// L'adresse physique de la page de zéros.
pub fn page_de_zeros() -> u64 {
    espace::physique_du_noyau(&raw const PAGE_DE_ZEROS as u64)
}

/// Une entrée finale qui désigne un cadre du programme : accessible,
/// interdite (PROT_NONE), ou en cours de remplacement ; dans les trois cas,
/// elle tient son cadre.
fn occupee(entree: u64) -> bool {
    entree & (PRESENTE | SANS_ACCES | EN_REMPLACEMENT) != 0
}

/// Le cadre est-il partagé : une page d'un fichier, ou une page tenue
/// ailleurs aussi (plus tard, par un fork) ? Il ne doit alors jamais être
/// écrit par une projection privée : la première écriture le copie.
fn partage(cadre: u64) -> bool {
    pages::drapeaux(cadre) & pages::FICHIER != 0 || pages::references(cadre) > 1
}

/// L'entrée finale qui donne au programme le cadre `cadre` avec les
/// droits `droits` (ceux de sa zone). La page de zéros et les pages
/// partagées (celles des fichiers, voir `partage`) ne sont jamais
/// inscriptibles : la prochaine écriture passera par la copie. C'est vrai
/// aussi pour mprotect, qui refait les entrées par ici.
pub fn entree_finale(cadre: u64, droits: Droits) -> u64 {
    let protegee = cadre == page_de_zeros() || (droits.ecriture && partage(cadre));
    let droits = if protegee { Droits { ecriture: false, ..droits } } else { droits };
    if !droits.accessible() {
        return cadre | SANS_ACCES;
    }
    let mut bits = cadre | PRESENTE | pagination::UTILISATEUR;
    if droits.ecriture {
        bits |= pagination::ECRITURE;
    }
    if !droits.execution {
        bits |= pagination::non_executable();
    }
    bits
}

/// La plus basse adresse projetable (vm.mmap_min_addr de Linux).
pub const ADRESSE_MIN: u64 = 0x1_0000;
/// La fin des adresses projetables, exclue (TASK_SIZE_MAX de Linux).
pub const ADRESSE_MAX: u64 = 0x7fff_ffff_f000;

/// Ce qu'a fait `EspaceUtilisateur::servir`.
pub enum Servi {
    /// L'entrée est en place : l'instruction peut reprendre.
    Fait,
    /// Il faut une page neuve : la préparer (`cadre_neuf`) et recommencer.
    PageNeuve,
    /// L'entrée d'une zone de fichier a disparu, ou un autre fil remplace
    /// cette page : recommencer par le fichier.
    ARefaire,
    /// La copie à l'écriture (voir l'en-tête) : l'entrée porte sa marque
    /// (rendue ici, jeton compris), le lot porte l'ancienne traduction à
    /// vider partout. À l'appelant de rendre le verrou des tables, de vider
    /// le lot, puis d'appeler `remplacer` avec la marque, préemption coupée
    /// d'un bout à l'autre (une faute d'un autre fil qui trouve la marque
    /// recommence tant qu'elle est là).
    Remplacement(Lot, u64),
}

/// Pourquoi une projection est refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Hors de [ADRESSE_MIN, ADRESSE_MAX[, ou pas alignée sur une page.
    AdresseInterdite,
    /// Une page y est déjà projetée.
    DejaProjetee,
    /// Plus de mémoire pour la page ou pour une table (ENOMEM).
    PlusDeMemoire,
    /// Rien n'est projeté à cette adresse.
    NonProjetee,
}

// Affiché par le noyau : sans accents.
impl core::fmt::Display for Erreur {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(match self {
            Erreur::AdresseInterdite => "adresse interdite",
            Erreur::DejaProjetee => "page deja projetee",
            Erreur::PlusDeMemoire => "plus de memoire",
            Erreur::NonProjetee => "page non projetee",
        })
    }
}

/// La page `adresse` (alignée) est-elle de celles qu'un programme peut
/// avoir ?
pub fn adresse_permise(adresse: u64) -> bool {
    adresse % PAGE == 0 && (ADRESSE_MIN..ADRESSE_MAX).contains(&adresse)
}

/// Un cadre neuf, mis à zéro, pour une page d'un programme ou une table de
/// son espace : pris au-dessus de la réserve du noyau
/// (pages::allouer_pour_programme). Une faute le prépare AVANT de prendre
/// le verrou des tables (memoire.rs) : mettre 4 Kio à zéro n'a pas à se
/// faire interruptions coupées (le `do_anonymous_page` de Linux alloue de
/// même avant `pte_offset_map_lock`) ; s'il ne sert pas, `rendre_cadre`.
pub fn cadre_neuf() -> Option<u64> {
    let cadre = pages::allouer_pour_programme()?;
    // SAFETY: le cadre vient d'être alloué, personne d'autre ne le voit.
    // Il contenait ce qu'y avait laissé son précédent occupant (le noyau,
    // un autre programme) : le donner tel quel ferait fuir ces données.
    unsafe { core::ptr::write_bytes(espace::virtuelle(cadre) as *mut u8, 0, PAGE as usize) };
    Some(cadre)
}

/// Rend un cadre préparé par `cadre_neuf` qui n'a pas servi.
pub fn rendre_cadre(cadre: u64) {
    pages::lacher(cadre);
}

/// L'espace d'adressage d'un programme. Le détruire (le laisser sortir de
/// portée) rend toutes ses pages et toutes ses tables.
///
/// Depuis 6i, il est sous son propre verrou court dans la mémoire du
/// processus (`Memoire::espace`, le `page_table_lock` de Linux) : plusieurs
/// fautes de page, qui ne tiennent la mémoire qu'en lecture, peuvent être
/// en cours à la fois (préemptées, et en 6j sur plusieurs processeurs), et
/// poser chacune ses entrées. Celui qui tient la mémoire en écriture
/// (munmap, mprotect...) y accède sans ce verrou (`Verrou::get_mut`) :
/// personne d'autre ne peut l'avoir.
pub struct EspaceUtilisateur {
    /// L'adresse physique de sa PML4.
    pml4: u64,
    /// Ses pages en place, ses tables, son pic (voir `Compteurs`) : écrits
    /// ici, sous le verrou des tables ; lus partout sans lui.
    compteurs: Arc<Compteurs>,
    /// Les processeurs qui ont chargé sa PML4 (voir l'en-tête).
    processeurs: Arc<MasqueProcesseurs>,
}

impl EspaceUtilisateur {
    /// Un espace neuf : moitié basse vide, moitié haute du noyau.
    pub fn creer() -> Result<EspaceUtilisateur, Erreur> {
        let processeurs = Arc::new(MasqueProcesseurs { processeurs: AtomicU64::new(0), retraits: AtomicU32::new(0) }).map_err(|_| Erreur::PlusDeMemoire)?;
        // Une table déjà : la PML4.
        let compteurs = Compteurs { pages: AtomicUsize::new(0), pages_fichier: AtomicUsize::new(0), tables: AtomicUsize::new(1), pic: AtomicUsize::new(0) };
        let compteurs = Arc::new(compteurs).map_err(|_| Erreur::PlusDeMemoire)?;
        let pml4 = pages::allouer_pour_programme().ok_or(Erreur::PlusDeMemoire)?;
        // SAFETY: `pml4` vient d'être alloué, il est à nous ; la PML4 du
        // noyau est une table en place, qu'on ne fait que lire.
        unsafe {
            let nouvelle = &mut *(espace::virtuelle(pml4) as *mut [u64; 512]);
            let noyau = pagination::lire_table(pagination::pml4_noyau());
            nouvelle[..256].fill(0);
            nouvelle[256..].copy_from_slice(&noyau[256..]);
        }
        Ok(EspaceUtilisateur { pml4, compteurs, processeurs })
    }

    /// L'adresse physique de la PML4, pour CR3.
    pub fn pml4(&self) -> u64 {
        self.pml4
    }

    /// Les processeurs qui ont chargé sa PML4 (voir l'en-tête), à partager
    /// avec l'entrée du processus.
    pub fn processeurs(&self) -> &Arc<MasqueProcesseurs> {
        &self.processeurs
    }

    /// Ses compteurs (voir `Compteurs`), à partager avec l'entrée du
    /// processus.
    pub fn compteurs(&self) -> &Arc<Compteurs> {
        &self.compteurs
    }

    /// Une page de moins, à lui ou à un fichier selon `cadre`.
    fn decompter(&self, cadre: u64) {
        if pages::drapeaux(cadre) & pages::FICHIER != 0 {
            self.compteurs.pages_fichier.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.compteurs.pages.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// L'entrée finale (dans une PT) de la page `adresse` (permise), en
    /// créant les tables intermédiaires qui manquent, prises au-dessus de la
    /// réserve du noyau et comptées. Toutes reçoivent le bit UTILISATEUR
    /// (voir pagination.rs).
    fn entree(&mut self, adresse: u64) -> Result<&'static mut u64, Erreur> {
        let mut table = self.pml4;
        for niveau in (1..4).rev() {
            // SAFETY: `table` est une table de cet espace (la PML4, ou une
            // table que désigne une entrée présente), que nous possédons.
            let e = unsafe { &mut pagination::table_modifiable(table)[pagination::index(adresse, niveau)] };
            if *e & PRESENTE == 0 {
                // Une table neuve : 512 entrées absentes.
                let nouvelle = cadre_neuf().ok_or(Erreur::PlusDeMemoire)?;
                self.compteurs.tables.fetch_add(1, Ordering::Relaxed);
                pagination::poser(e, nouvelle | PRESENTE | pagination::ECRITURE | pagination::UTILISATEUR);
            }
            table = *e & ADRESSE;
        }
        // SAFETY: `table` est maintenant une PT de cet espace.
        Ok(unsafe { &mut pagination::table_modifiable(table)[pagination::index(adresse, 0)] })
    }

    /// Sert une faute de page à `page` (alignée), dans une zone qui permet
    /// l'accès, avec les droits `droits` de la zone ; `ecriture` : la faute
    /// vient d'une écriture. Le contrôle des droits est fait par
    /// l'appelant (memoire.rs) : ici, on met en place ce qu'il faut pour
    /// que l'instruction, reprise, réussisse.
    ///   - Rien n'est projeté : une lecture reçoit la page de zéros (en
    ///     lecture seule), une écriture une page neuve à zéro (le
    ///     do_anonymous_page de Linux). Le processeur ne garde pas en cache
    ///     les entrées absentes : rien à invalider.
    ///   - La page de zéros, ou une page partagée (celle d'un fichier, voir
    ///     `partage`), et une écriture : une page neuve à sa place, copie de
    ///     l'ancienne (la copie à l'écriture, do_wp_page). L'ancienne
    ///     traduction peut être dans le TLB de plusieurs processeurs : la
    ///     copie est faite, l'entrée marquée EN_REMPLACEMENT, et le reste
    ///     (vider partout, poser la nouvelle entrée, lâcher l'ancienne page)
    ///     revient à l'appelant, hors du verrou des tables
    ///     (`Servi::Remplacement`, puis `remplacer` ; voir l'en-tête).
    ///   - Une page à lui : l'entrée est refaite d'après les droits de la
    ///     zone. C'est le cas d'une page restée en lecture seule dans une
    ///     zone inscriptible (do_wp_page la « réutilise » : personne d'autre
    ///     ne la voit), ou d'une faute « fantôme », quand l'entrée permet
    ///     déjà l'accès mais que le TLB gardait une traduction plus ancienne
    ///     (manuel d'Intel, vol. 3A, 4.10.4.3). invlpg, ici seulement, et on
    ///     reprend : des droits sont AJOUTÉS, un autre processeur qui garde
    ///     l'ancienne traduction fautera et la refera lui-même (Linux :
    ///     `ptep_set_access_flags`, un vidage local). Une page partagée lue
    ///     reste en lecture seule (entree_finale).
    ///   - Une marque EN_REMPLACEMENT : un autre fil remplace cette page en
    ///     ce moment (il vide les TLB) : `Servi::ARefaire`, on recommence.
    ///
    /// La page d'un fichier qui n'est pas encore là est posée avant, par
    /// `poser_fichier` (memoire.rs) : `servir` ne sait rien des fichiers,
    /// sauf qu'une entrée vide dans une zone de fichier (`fichier`) ne se
    /// remplit pas ici (ni page de zéros, ni page neuve) : elle a disparu
    /// depuis que la page du fichier y a été posée (un `ftruncate`, qui ne
    /// prend la mémoire qu'en lecture, comme la faute), et c'est le fichier
    /// qui doit dire ce qu'il y a là (`Servi::ARefaire` ; SIGBUS s'il a été
    /// raccourci). C'est le `pte_same` de Linux : la décision prise hors du
    /// verrou des tables est revérifiée sous lui.
    ///
    /// Une écriture qui demande une page neuve prend `neuve`, un cadre mis à
    /// zéro que l'appelant a préparé hors du verrou des tables (`cadre_neuf`)
    /// et qu'on laisse à None ; sinon il reste là, et l'appelant le rend.
    /// Sans lui : `Servi::PageNeuve`, rien n'est fait, et l'appelant en
    /// prépare un puis recommence. Une page n'est donc préparée que si la
    /// faute en demande une (une faute sur une page déjà à lui, celle d'un
    /// futex partagé ou de MADV_POPULATE_WRITE, n'alloue rien, comme chez
    /// Linux).
    pub fn servir(&mut self, page: u64, droits: Droits, ecriture: bool, fichier: bool, neuve: &mut Option<u64>)
        -> Result<Servi, Erreur> {
        if !adresse_permise(page) {
            return Err(Erreur::AdresseInterdite);
        }
        let entree = self.entree(page)?;
        if *entree & EN_REMPLACEMENT != 0 {
            return Ok(Servi::ARefaire);
        }
        let cadre = *entree & ADRESSE;
        let zeros = page_de_zeros();
        let present = occupee(*entree);
        if !present && fichier {
            return Ok(Servi::ARefaire);
        }
        let a_copier = present && cadre != zeros && partage(cadre);
        if !present {
            let neuve = if !ecriture {
                zeros
            } else if let Some(c) = neuve.take() {
                self.compter_cadre();
                c
            } else {
                return Ok(Servi::PageNeuve);
            };
            pagination::poser(entree, entree_finale(neuve, droits));
        } else if ecriture && (cadre == zeros || a_copier) {
            // La copie à l'écriture : la page neuve reste à l'appelant
            // jusqu'à `remplacer` ; ici la copie, puis la marque. L'ancienne
            // page est en lecture seule pour tous par les tables ; une page
            // de fichier, elle, peut encore être écrite par `write` (un
            // autre processus) pendant la copie, qui prend alors l'un ou
            // l'autre état : comme chez Linux, dont `wp_page_copy` copie
            // hors du verrou puis revérifie l'entrée (copier hors du verrou
            // demanderait de tenir le cadre le temps de la copie : un écart
            // écrit, HISTORIQUE.md). Le lot (400 octets, un clone d'Arc)
            // n'est construit que sur ce chemin, pas à chaque faute.
            let Some(neuve) = *neuve else { return Ok(Servi::PageNeuve) };
            let mut lot = Lot::new(self);
            if a_copier {
                // SAFETY: `neuve` vient d'être allouée, à nous ; `cadre` est
                // tenu par cette entrée (il ne sera lâché qu'après) : deux
                // pages distinctes, entières, dans la projection directe.
                unsafe {
                    core::ptr::copy_nonoverlapping(espace::virtuelle(cadre) as *const u8,
                                                   espace::virtuelle(neuve) as *mut u8, PAGE as usize);
                }
            }
            let marque = cadre | EN_REMPLACEMENT | jeton_de_marque();
            *entree = marque;
            lot.invalider(page);
            return Ok(Servi::Remplacement(lot, marque));
        } else {
            pagination::poser(entree, entree_finale(cadre, droits));
            self.invalider(page);
        }
        Ok(Servi::Fait)
    }

    /// La fin d'une copie à l'écriture (voir `servir`), le lot vidé, le
    /// verrou des tables repris : si NOTRE marque est encore là (l'entrée
    /// entière, jeton compris), la page `neuve` prend la place de
    /// l'ancienne, qui est lâchée (plus aucune traduction ne mène à elle
    /// par cette entrée) ; sinon l'entrée a changé entre-temps (une
    /// troncature ou un madvise l'ont retirée, un autre fil a posé la
    /// sienne) : `Servi::ARefaire`, et `neuve` reste à l'appelant.
    pub fn remplacer(&mut self, page: u64, droits: Droits, neuve: &mut Option<u64>, marque: u64) -> Result<Servi, Erreur> {
        let entree = self.entree(page)?;
        if *entree != marque {
            return Ok(Servi::ARefaire);
        }
        let ancien = *entree & ADRESSE;
        let c = neuve.take().expect("remplacement sans page neuve");
        pagination::poser(entree, entree_finale(c, droits));
        // L'ancienne décomptée AVANT de compter la neuve : sinon le pic
        // (`suivre_pic`) voyait une page de trop le temps de l'échange (un
        // reste de 6i, où la copie faisait de même).
        if ancien != page_de_zeros() {
            self.decompter(ancien);
        }
        self.compter_cadre();
        if ancien != page_de_zeros() {
            pages::lacher(ancien);
        }
        Ok(Servi::Fait)
    }

    /// Une entrée occupe-t-elle la page `page` (présente, ou rendue
    /// inaccessible par PROT_NONE) ?
    pub fn occupee(&self, page: u64) -> bool {
        if !adresse_permise(page) {
            return false;
        }
        let mut table = self.pml4;
        for niveau in (1..4).rev() {
            // SAFETY: `table` est une de nos tables.
            let e = unsafe { pagination::lire_table(table) }[pagination::index(page, niveau)];
            if e & PRESENTE == 0 {
                return false;
            }
            table = e & ADRESSE;
        }
        // SAFETY: une PT de cet espace.
        occupee(unsafe { pagination::lire_table(table) }[pagination::index(page, 0)])
    }

    /// Pose à `page` (où il n'y a rien) la page `cadre` d'un fichier, avec
    /// les droits de la zone, sans jamais celui d'écrire (entree_finale).
    /// L'entrée garde la référence que l'appelant a prise sur le cadre
    /// (vfs::page_projetee, sous le verrou des fichiers : sans elle, le
    /// fichier raccourci entre les deux l'aurait rendu) ; en cas d'échec,
    /// elle reste à l'appelant. Le processeur ne garde pas en cache les
    /// entrées absentes : rien à invalider.
    pub fn poser_fichier(&mut self, page: u64, cadre: u64, droits: Droits) -> Result<(), Erreur> {
        if !adresse_permise(page) {
            return Err(Erreur::AdresseInterdite);
        }
        let entree = self.entree(page)?;
        if occupee(*entree) {
            return Err(Erreur::DejaProjetee);
        }
        pagination::poser(entree, entree_finale(cadre, droits));
        self.compteurs.pages_fichier.fetch_add(1, Ordering::Relaxed);
        self.compteurs.suivre_pic();
        Ok(())
    }

    /// La traduction de `page` ne doit plus servir SUR CE PROCESSEUR : pour
    /// une entrée à laquelle on ajoute des droits (`servir`), ce qui ne
    /// demande rien aux autres processeurs (voir là). L'espace est celui
    /// du processeur : une faute est toujours servie sur celui qui l'a
    /// faite, dans son espace.
    fn invalider(&self, page: u64) {
        if pagination::courante() == self.pml4 {
            pagination::invalider(page);
        }
    }

    /// Projette à `adresse` (une page) un cadre neuf, mis à zéro, avec les
    /// droits `droits`. Rend l'adresse physique du cadre, pour le remplir
    /// par la projection directe. (Pour le test du démarrage, main.rs ; un
    /// programme, lui, reçoit ses pages à la faute : `servir`.)
    ///
    /// Si l'espace est actif, la nouvelle page sert tout de suite : le
    /// processeur ne garde pas en cache les entrées absentes (manuel
    /// d'Intel, vol. 3A, 4.10.4.3), rien à invalider.
    pub fn projeter_neuve(&mut self, adresse: u64, droits: Droits) -> Result<u64, Erreur> {
        if !adresse_permise(adresse) {
            return Err(Erreur::AdresseInterdite);
        }
        let entree = self.entree(adresse)?;
        if occupee(*entree) {
            return Err(Erreur::DejaProjetee);
        }
        let cadre = self.prendre_cadre()?;
        pagination::poser(entree, entree_finale(cadre, droits));
        Ok(cadre)
    }

    /// Un cadre neuf pour une page de l'espace, compté.
    fn prendre_cadre(&mut self) -> Result<u64, Erreur> {
        let cadre = cadre_neuf().ok_or(Erreur::PlusDeMemoire)?;
        self.compter_cadre();
        Ok(cadre)
    }

    /// Une page à lui de plus.
    fn compter_cadre(&mut self) {
        self.compteurs.pages.fetch_add(1, Ordering::Relaxed);
        self.compteurs.suivre_pic();
    }

    /// Retire les pages de [debut, fin[ (alignés), comme `retirer_plage`,
    /// par tranches de 64 pages, en prenant le verrou des tables pour
    /// chacune, et en vidant le lot, sans lui, dès qu'il n'a plus la place
    /// d'une tranche : pour qui ne tient la mémoire qu'en LECTURE (munmap et
    /// madvise depuis 6j, la troncature d'un fichier, appels_fichiers.rs)
    /// comme pour qui la tient en écriture. Les interruptions ne restent
    /// coupées que le temps de 64 entrées, quelle que soit la plage (le
    /// `zap_pte_range` de Linux, qui prend le verrou de chaque table de
    /// pages tour à tour, et le rend pour vider son lot quand il est
    /// plein), et le vidage des TLB des autres processeurs, qui attend
    /// leurs réponses, ne se fait jamais sous le verrou (voir l'en-tête).
    /// Avec `rendre_tables`, les tables devenues vides sont rendues aussi.
    /// `reserve` : combien de cadres garder avant de vider (un munmap de
    /// 2 Gio viderait sinon les TLB de tous les processeurs tous les 64
    /// cadres : memoire::GRAND_LOT pour lui) ; sans mémoire pour cela, le
    /// lot vide tous les huit cadres, ceux qu'il a en place.
    pub fn retirer_par_tranches(espace: &crate::verrou::Verrou<EspaceUtilisateur>, debut: u64, fin: u64, rendre_tables: bool, reserve: usize) {
        const TRANCHE: u64 = PAGE * CADRES_DU_LOT as u64;
        let mut lot = Lot::new(&espace.verrouiller());
        // Jamais plus que de pages à retirer : un munmap d'une page ne
        // réserve pas 32 Kio du tas.
        lot.reserver(reserve.min(((fin - debut) / PAGE) as usize));
        // Un retrait de plus en cours (voir `MasqueProcesseurs::retraits`).
        lot.masque.retraits.fetch_add(1, Ordering::SeqCst);
        let mut a = debut;
        while a < fin {
            // Jamais plus de pages sous le verrou que le lot n'en peut
            // recevoir, leurs tables comprises ; vidé d'abord s'il est près
            // du bord (il retrouve alors au moins ses cadres en place).
            if lot.place() < CADRES_EN_PLACE + TABLES_PAR_TRANCHE {
                lot.vider();
            }
            let pages = (lot.place() - TABLES_PAR_TRANCHE).min(CADRES_DU_LOT) as u64;
            let b = ((a / TRANCHE + 1) * TRANCHE).min(fin).min(a + pages * PAGE);
            espace.verrouiller().retirer_plage(a, b, rendre_tables, &mut lot);
            a = b;
        }
        // Le dernier vidage : un autre retrait en cours a peut-être effacé
        // avant nous des entrées de la plage, dont les traductions sont
        // dans son lot, pas vidé : on vide tout, même un lot vide.
        if lot.masque.retraits.load(Ordering::SeqCst) > 1 {
            lot.tout = true;
        }
        lot.vider();
        lot.masque.retraits.fetch_sub(1, Ordering::SeqCst);
    }

    /// Retire les pages de [debut, fin[ (alignés) et rend leurs cadres :
    /// munmap, brk qui recule. Les adresses où rien n'est projeté ne
    /// coûtent rien (voir `parcourir`). Avec `rendre_tables`, une table
    /// devenue vide est rendue aussi (le free_pgtables de Linux) : sans
    /// cela, un programme qui réserve et rend sans cesse des Gio de mémoire
    /// (le ramasse-miettes de `claude`) laisserait derrière lui des tables
    /// vides par milliers. On le sait en regardant ses 512 entrées : plus
    /// simple que les bornes de la zone précédente et de la suivante qu'en
    /// tire Linux, et toujours juste (une entrée occupée n'existe que dans
    /// une zone). MADV_DONTNEED, lui, garde les tables : la zone reste, ses
    /// pages reviendront. Les traductions à vider et les cadres à rendre
    /// vont dans `lot`, celui de l'appelant, qui le vide quand il ne tient
    /// plus le verrou des tables (voir l'en-tête) ; un lot plein se vide de
    /// lui-même en chemin, ce qui demande qu'aucun verrou ne soit tenu : qui
    /// tient le verrou des tables ne retire qu'une tranche de 64 pages
    /// (`retirer_par_tranches`).
    pub fn retirer_plage(&mut self, debut: u64, fin: u64, rendre_tables: bool, lot: &mut Lot) {
        assert!(lot.pml4 == self.pml4, "un lot d'un autre espace");
        let (mut pages, mut pages_fichier, mut tables) = (0, 0, 0);
        let zeros = page_de_zeros();
        parcourir(self.pml4, debut, fin, &mut |visite| match visite {
            Visite::Page(adresse, entree) => {
                let cadre = *entree & ADRESSE;
                *entree = 0;
                lot.invalider(adresse);
                // La page de zéros reste au noyau ; une page de fichier reste
                // aussi au fichier (lâchée, pas rendue : pages.rs).
                if cadre != zeros {
                    if pages::drapeaux(cadre) & pages::FICHIER != 0 {
                        pages_fichier += 1;
                    } else {
                        pages += 1;
                    }
                    lot.rendre(cadre);
                }
            }
            Visite::Table(entree) => {
                let table = *entree & ADRESSE;
                // SAFETY: une table de cet espace, que nous possédons.
                if rendre_tables && unsafe { pagination::lire_table(table) }.iter().all(|&e| e == 0) {
                    *entree = 0;
                    lot.rendre_table(table);
                    tables += 1;
                }
            }
        });
        self.compteurs.pages.fetch_sub(pages, Ordering::Relaxed);
        self.compteurs.pages_fichier.fetch_sub(pages_fichier, Ordering::Relaxed);
        self.compteurs.tables.fetch_sub(tables, Ordering::Relaxed);
    }

    /// Donne les droits `droits` à toutes les pages projetées de [debut,
    /// fin[ (mprotect). Le processeur ne sait pas interdire la lecture
    /// d'une page présente : écrire ou exécuter permet aussi de lire, et
    /// sans aucun droit, la page est retirée du processeur (SANS_ACCES).
    /// W+X est permis, comme sous Linux : le compilateur à la volée (JIT)
    /// de JavaScriptCore, le moteur de Claude Code, écrit puis exécute son
    /// code dans les mêmes pages.
    pub fn proteger_plage(&mut self, debut: u64, fin: u64, droits: Droits) {
        // Un lot sans cadre : il se vide en sortant (l'appelant tient la
        // mémoire en écriture, sans verrou court : il peut attendre les
        // autres processeurs).
        let mut lot = Lot::new(self);
        parcourir(self.pml4, debut, fin, &mut |visite| {
            if let Visite::Page(adresse, entree) = visite {
                pagination::poser(entree, entree_finale(*entree & ADRESSE, droits));
                // Des droits retirés : l'ancienne traduction ne doit plus
                // servir. Des droits ajoutés : le processeur relirait
                // l'entrée de lui-même après une faute (manuel d'Intel,
                // vol. 3A, 4.10.4.3), mais tout invalider est plus simple à
                // relire.
                lot.invalider(adresse);
            }
        });
    }

    /// Écrit `octets` à partir de l'adresse `adresse` de l'espace, page par
    /// page, par la projection directe de leurs cadres : l'espace n'a pas
    /// besoin d'être actif, et les droits des pages ne comptent pas (on
    /// remplit ainsi le code d'un programme, en lecture seule pour lui).
    /// Toutes les pages doivent être projetées ; sinon rien n'est écrit.
    /// Aucune ne doit être partagée (la page d'un fichier) : on écrirait
    /// dans le fichier. Memoire::ecrire les fait d'abord copier (servir en
    /// écriture) ; une page partagée ici est une erreur du noyau.
    pub fn ecrire(&mut self, adresse: u64, octets: &[u8]) -> Result<(), Erreur> {
        let fin = adresse.checked_add(octets.len() as u64).ok_or(Erreur::AdresseInterdite)?;
        // D'abord vérifier, puis écrire : tout ou rien.
        let mut page = adresse / PAGE * PAGE;
        while page < fin {
            let (cadre, _) = self.traduire(page).ok_or(Erreur::NonProjetee)?;
            assert!(cadre != page_de_zeros() && !partage(cadre), "le noyau ecrirait dans une page partagee a {page:#x}");
            page += PAGE;
        }
        let mut fait = 0;
        while fait < octets.len() {
            let a = adresse + fait as u64;
            let decalage = (a % PAGE) as usize;
            let n = (PAGE as usize - decalage).min(octets.len() - fait);
            let (cadre, _) = self.traduire(a / PAGE * PAGE).ok_or(Erreur::NonProjetee)?;
            // SAFETY: `cadre` est une page de cet espace (traduire l'a
            // trouvée dans ses tables), que nous possédons ; on y écrit
            // `n` octets à partir de `decalage`, sans sortir de la page.
            unsafe {
                let destination = (espace::virtuelle(cadre) as *mut u8).add(decalage);
                core::ptr::copy_nonoverlapping(octets[fait..].as_ptr(), destination, n);
            }
            fait += n;
        }
        Ok(())
    }

    /// Lit `octets.len()` octets à partir de l'adresse `adresse` de
    /// l'espace, comme `ecrire` dans l'autre sens.
    pub fn lire(&self, adresse: u64, octets: &mut [u8]) -> Result<(), Erreur> {
        adresse.checked_add(octets.len() as u64).ok_or(Erreur::AdresseInterdite)?;
        let mut fait = 0;
        while fait < octets.len() {
            let a = adresse + fait as u64;
            let decalage = (a % PAGE) as usize;
            let n = (PAGE as usize - decalage).min(octets.len() - fait);
            let (cadre, _) = self.traduire(a / PAGE * PAGE).ok_or(Erreur::NonProjetee)?;
            // SAFETY: comme dans `ecrire`, en lecture.
            unsafe {
                let source = (espace::virtuelle(cadre) as *const u8).add(decalage);
                core::ptr::copy_nonoverlapping(source, octets[fait..].as_mut_ptr(), n);
            }
            fait += n;
        }
        Ok(())
    }

    /// Le cadre projeté à `adresse` (une page) et les bits de son entrée,
    /// s'il y en a un.
    pub fn traduire(&self, adresse: u64) -> Option<(u64, u64)> {
        // Seulement dans les adresses des programmes : plus haut, ce sont
        // les tables du NOYAU, avec leurs grandes pages de 2 Mio, qu'on
        // prendrait pour des tables de 4 Kio.
        if !adresse_permise(adresse) {
            return None;
        }
        let mut table = self.pml4;
        for niveau in (0..4).rev() {
            // SAFETY: `table` est une de nos tables (la PML4, puis celles
            // que désignent ses entrées présentes).
            let e = unsafe { pagination::lire_table(table) }[pagination::index(adresse, niveau)];
            if e & PRESENTE == 0 {
                return None;
            }
            if niveau == 0 {
                return Some((e & ADRESSE, e & !ADRESSE));
            }
            table = e & ADRESSE;
        }
        None
    }
}

/// Appelle `f` pour chaque entrée finale occupée de [debut, fin[ (alignés,
/// dans la moitié basse), avec l'adresse de sa page, en descendant l'arbre
/// des tables de `pml4` et en SAUTANT toute table absente : le coût suit
/// les pages réellement projetées, pas la taille de la plage. Une boucle
/// page par page ferait 524 288 descentes de quatre niveaux pour un munmap
/// de 2 Gio (`claude` en fait), seize millions pour 64 Gio : des secondes
/// dans QEMU. C'est le parcours de zap_page_range et de change_protection
/// dans Linux.
fn parcourir(pml4: u64, debut: u64, fin: u64, f: &mut impl FnMut(Visite)) {
    parcourir_table(pml4, 3, debut, fin, f);
}

/// Ce que `parcourir` montre à sa fonction.
enum Visite<'a> {
    /// Une entrée finale occupée, et l'adresse de sa page.
    Page(u64, &'a mut u64),
    /// L'entrée d'une table de niveau supérieur, une fois parcourue la
    /// table qu'elle désigne (pour la rendre si elle est devenue vide).
    Table(&'a mut u64),
}

/// Le parcours dans la table `table` de niveau `niveau` (3 : la PML4),
/// restreint à [debut, fin[.
fn parcourir_table(table: u64, niveau: u32, debut: u64, fin: u64, f: &mut impl FnMut(Visite)) {
    // Ce que couvre une entrée de ce niveau : 4 Kio, 2 Mio, 1 Gio, 512 Gio.
    // Les adresses restent sous 2^47 : pas de débordement.
    let couverture = PAGE << (9 * niveau);
    let mut adresse = debut;
    while adresse < fin {
        let suivante = (adresse / couverture + 1) * couverture;
        // SAFETY: `table` est une table de cet espace (la PML4, ou une
        // table que désigne une entrée présente), que nous possédons ;
        // l'espace n'est changé que sous son verrou (`Memoire::espace`),
        // ou par qui tient la mémoire du processus en écriture, ou par sa
        // dernière tâche, qui l'a retirée du processus pour la rendre : tous
        // passent par &mut EspaceUtilisateur, personne ne la change en même
        // temps. Sauf les MMU des autres processeurs qui ont cet espace
        // chargé : elles posent les bits A et D (5 et 6) des entrées qu'elles
        // parcourent, une écriture concurrente bénigne (nous ne lisons ces
        // bits nulle part ; à reprendre pour MAP_SHARED, 6m, où le bit D
        // dira quelle page réécrire, en le lisant par un échange atomique).
        let entree = unsafe { &mut pagination::table_modifiable(table)[pagination::index(adresse, niveau)] };
        if niveau == 0 {
            if occupee(*entree) {
                f(Visite::Page(adresse, entree));
            }
        } else if *entree & PRESENTE != 0 {
            parcourir_table(*entree & ADRESSE, niveau - 1, adresse, suivante.min(fin), f);
            f(Visite::Table(entree));
        }
        adresse = suivante;
    }
}

/// Le plus de pages invalidées une à une (invlpg) avant de préférer vider
/// tout le TLB (recharger CR3) : le tlb_single_page_flush_ceiling de
/// Linux. Au-delà, chaque invlpg coûte plus que de recharger ensuite les
/// traductions dont on a vraiment besoin.
const PLAFOND_INVLPG: usize = 33;

/// Le plus de pages qu'une tranche de `retirer_par_tranches` retire sous le
/// verrou des tables (les interruptions restent coupées le temps de 64
/// entrées, quelle que soit la plage), et ce que le lot garde de cadres
/// quand on lui a réservé de la place.
const CADRES_DU_LOT: usize = 64;
/// Les cadres qu'un lot garde EN PLACE, sans rien demander au tas : sous le
/// verrou des tables, il ne peut ni se vider (vider attend les autres
/// processeurs) ni échouer (sans mémoire, il faudrait pourtant rendre la
/// page) ; une tranche ne dépasse donc jamais ce que le lot peut recevoir.
/// Huit, comme les pages de la `mmu_gather` de Linux elle-même (ses lots de
/// 509, `mmu_gather_batch`, viennent du tas quand il peut) : la pile du
/// noyau porte le lot, et avec 64 cadres en place sa plus grande profondeur
/// passait de 10,4 à 13,3 Kio sur 16 (mesuré au démarrage) ; avec huit,
/// 10,8 Kio.
const CADRES_EN_PLACE: usize = 8;
/// Les tables qu'une tranche peut rendre en plus de ses pages : la sienne
/// (une tranche tient dans une table de dernier niveau), et ses deux
/// parentes si elles se vident (la PML4, jamais).
const TABLES_PAR_TRANCHE: usize = 3;

/// Ce qu'un parcours des tables laisse à faire : des traductions à retirer
/// des TLB (de tous les processeurs qui ont l'espace : voir l'en-tête),
/// puis des cadres à rendre (le mmu_gather de Linux). L'ordre compte : un
/// cadre rendu alors qu'une traduction vers lui reste dans un TLB pourrait
/// encore être écrit par le programme, alors qu'il appartient déjà à
/// quelqu'un d'autre. Le lot vide donc toujours les TLB AVANT de rendre
/// ses cadres, et se vide de lui-même en disparaissant (Drop). Vider
/// attend les autres processeurs : jamais un verrou court tenu (smp.rs le
/// vérifie).
pub struct Lot {
    /// L'espace parcouru : sa PML4 (ce que les receveurs comparent à leur
    /// CR3) et ses processeurs.
    pml4: u64,
    masque: Arc<MasqueProcesseurs>,
    pages: [u64; PLAFOND_INVLPG],
    nombre_pages: usize,
    /// Plus de PLAFOND_INVLPG pages : on videra tout le TLB.
    tout: bool,
    /// Les cadres à lâcher : quelques-uns en place (CADRES_EN_PLACE, plus
    /// les tables d'une tranche), et au-delà ce que `reserver` a obtenu du
    /// tas.
    locaux: [u64; CADRES_EN_PLACE + TABLES_PAR_TRANCHE],
    nombre_locaux: usize,
    cadres: Vec<u64>,
}

impl Lot {
    pub fn new(espace: &EspaceUtilisateur) -> Lot {
        Lot {
            pml4: espace.pml4,
            masque: espace.processeurs.clone(),
            pages: [0; PLAFOND_INVLPG],
            nombre_pages: 0,
            tout: false,
            locaux: [0; CADRES_EN_PLACE + TABLES_PAR_TRANCHE],
            nombre_locaux: 0,
            cadres: Vec::new(),
        }
    }

    /// Fait de la place pour `n` cadres de plus : moins de vidages pour une
    /// grande plage. Sans mémoire, le lot garde sa taille (il videra plus
    /// souvent).
    pub fn reserver(&mut self, n: usize) {
        let _ = self.cadres.try_reserve(n);
    }

    /// Combien de cadres il peut encore recevoir sans se vider.
    pub fn place(&self) -> usize {
        self.locaux.len() - self.nombre_locaux + (self.cadres.capacity() - self.cadres.len())
    }

    /// La traduction de la page `adresse` ne doit plus servir.
    fn invalider(&mut self, adresse: u64) {
        if self.nombre_pages < PLAFOND_INVLPG {
            self.pages[self.nombre_pages] = adresse;
            self.nombre_pages += 1;
        } else {
            self.tout = true;
        }
    }

    /// Le cadre `cadre` est à lâcher, une fois les TLB vidés (il ne sera
    /// rendu que si personne d'autre ne le tient, pages.rs). Toute page qui
    /// le désignait doit déjà avoir été passée à `invalider`. En place
    /// d'abord, puis dans ce que `reserver` a obtenu ; un lot plein se vide,
    /// ce qui ne peut pas arriver sous le verrou des tables (qui le tient
    /// mesure ses tranches à `place`), et le cadre prend la première place.
    fn rendre(&mut self, cadre: u64) {
        if self.nombre_locaux < self.locaux.len() {
            self.locaux[self.nombre_locaux] = cadre;
            self.nombre_locaux += 1;
        } else if self.cadres.len() < self.cadres.capacity() {
            self.cadres.ajouter_dans_la_place(cadre);
        } else {
            self.vider();
            self.locaux[0] = cadre;
            self.nombre_locaux = 1;
        }
    }

    /// La table `table` est à rendre ; l'entrée qui la désignait est déjà
    /// effacée. Le processeur garde en cache, en plus des traductions, des
    /// entrées des tables de niveau supérieur (les « paging-structure
    /// caches », manuel d'Intel, vol. 3A, 4.10.3) : une entrée périmée le
    /// ferait encore descendre dans cette table, devenue la page de
    /// quelqu'un d'autre. On videra donc tout le TLB (recharger CR3 vide
    /// aussi ces caches) avant de la rendre. (Un invlpg les viderait aussi
    /// tous, 4.10.4.1 ; le rechargement est plus simple à relire, et rendre
    /// une table est rare.) Dans cet ordre : `rendre` peut vider le lot
    /// s'il est plein, ce qui remet `tout` à faux.
    fn rendre_table(&mut self, table: u64) {
        self.rendre(table);
        self.tout = true;
    }

    /// Vide les TLB de ce qu'on a noté, sur tous les processeurs qui ont
    /// l'espace (smp::vider_tlb), puis lâche les cadres. Aucun verrou court
    /// tenu, interruptions actives.
    #[track_caller]
    pub fn vider(&mut self) {
        if self.tout || self.nombre_pages > 0 {
            smp::vider_tlb(Some(self.pml4), Some(&self.masque.processeurs), &self.pages[..self.nombre_pages], self.tout);
        }
        (self.nombre_pages, self.tout) = (0, false);
        for &c in &self.locaux[..self.nombre_locaux] {
            pages::lacher(c);
        }
        self.nombre_locaux = 0;
        for c in self.cadres.drain(..) {
            pages::lacher(c);
        }
    }
}

impl Drop for Lot {
    fn drop(&mut self) {
        self.vider();
    }
}

/// Rend les cadres de la moitié basse sous la table `table` de niveau
/// `niveau` (3 = PML4 : seulement ses 256 premières entrées), puis les
/// tables elles-mêmes, sauf la racine.
fn rendre(table: u64, niveau: u32) {
    let entrees = if niveau == 3 { 256 } else { 512 };
    for i in 0..entrees {
        // SAFETY: `table` est une table de l'espace, plus utilisée par
        // personne (voir Drop).
        let e = unsafe { pagination::lire_table(table) }[i];
        if !(e & PRESENTE != 0 || niveau == 0 && occupee(e)) {
            continue;
        }
        let dessous = e & ADRESSE;
        if niveau > 0 {
            rendre(dessous, niveau - 1);
        } else if dessous == page_de_zeros() {
            // La page de zéros est au noyau : on la saute.
            continue;
        }
        // Un cadre de page (niveau 0) : lâché, il peut être tenu ailleurs
        // (une page de fichier, pages.rs). Une table (au-dessus) n'est qu'à
        // cet espace : rendue.
        if niveau == 0 {
            pages::lacher(dessous);
        } else {
            pages::liberer(dessous, 0);
        }
    }
}

impl Drop for EspaceUtilisateur {
    fn drop(&mut self) {
        // D'abord quitter l'espace s'il est actif (le test du démarrage,
        // main.rs, qui le charge sans passer par une tâche) : on ne rend
        // pas des tables dont le processeur se sert encore. La PML4 du
        // noyau a la même moitié haute : l'exécution continue sans heurt.
        if pagination::courante() == self.pml4 {
            // SAFETY: la PML4 du noyau est complète.
            unsafe { pagination::activer(pagination::pml4_noyau()) };
        }
        // Plus aucun processeur n'a cette PML4 : chaque fil du processus l'a
        // quittée en mourant (tache.rs). Sinon, rendre ses tables serait
        // rendre des pages qu'un processeur traverse encore.
        assert!(self.processeurs.processeurs.load(core::sync::atomic::Ordering::Acquire) == 0,
                "espace detruit alors que des processeurs l'ont encore charge");
        rendre(self.pml4, 3);
        pages::liberer(self.pml4, 0);
    }
}
