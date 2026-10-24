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
//!     CR3, et sans PCID chaque changement vide le TLB. En 6m, avec PCID
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
//! Toute allocation faite pour un programme est faillible : sans mémoire,
//! il reçoit une erreur (ENOMEM), le noyau ne panique jamais.

use crate::{espace, pages, pagination};
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

/// La page de zéros : une page du noyau, toujours nulle, que reçoit en
/// lecture seule toute page d'un programme LUE avant d'avoir été écrite
/// (la ZERO_PAGE de Linux). Une seule pour tous les programmes et toutes
/// les adresses : une zone lue sans être écrite (un tableau qu'on parcourt
/// avant de le remplir, une réservation qu'on sonde) ne coûte aucune
/// mémoire. La première écriture fait une faute (la page est en lecture
/// seule), et le noyau donne alors une page neuve à la place : la COPIE À
/// L'ÉCRITURE, le mécanisme qui servira aussi aux fichiers projetés en
/// privé (6b) et à fork (6k).
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

/// Une entrée finale qui désigne un cadre du programme, accessible ou non.
fn occupee(entree: u64) -> bool {
    entree & (PRESENTE | SANS_ACCES) != 0
}

/// L'entrée finale qui donne au programme le cadre `cadre` avec les
/// droits `droits` (ceux de sa zone). La page de zéros n'est jamais
/// inscriptible : la prochaine écriture passera par la copie.
pub fn entree_finale(cadre: u64, droits: Droits) -> u64 {
    let droits = if cadre == page_de_zeros() { Droits { ecriture: false, ..droits } } else { droits };
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

/// Le budget de mémoire d'un programme : au plus 256 Mio de pages (le
/// RLIMIT_DATA et le RLIMIT_AS de Linux, réunis ; illimités par défaut sous
/// Linux, mais notre noyau n'a pas de mémoire virtuelle à prêter), et au
/// plus la moitié des pages libres à son lancement : sur une machine de
/// 128 Mio, 256 Mio ne borneraient rien. Au-delà, brk échoue et le
/// programme reçoit ENOMEM : il ne peut pas prendre toute la mémoire de la
/// machine. Comme le budget des programmes WebAssembly
/// (wasm::Magasin::avec_budget). Les tables de pages, elles, ne sont pas
/// comptées (quelques centaines au plus aujourd'hui, Linux les compte à
/// part) : à revoir avec mmap.
pub const BUDGET_PAGES: usize = (256 << 20) / PAGE as usize;

/// La plus basse adresse projetable (vm.mmap_min_addr de Linux).
pub const ADRESSE_MIN: u64 = 0x1_0000;
/// La fin des adresses projetables, exclue (TASK_SIZE_MAX de Linux).
pub const ADRESSE_MAX: u64 = 0x7fff_ffff_f000;

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

/// Un cadre neuf, mis à zéro, pour une page d'un programme.
fn cadre_neuf() -> Option<u64> {
    let cadre = pages::allouer(0)?;
    // SAFETY : le cadre vient d'être alloué, personne d'autre ne le voit.
    // Il contenait ce qu'y avait laissé son précédent occupant (le noyau,
    // un autre programme) : le donner tel quel ferait fuir ces données.
    unsafe { core::ptr::write_bytes(espace::virtuelle(cadre) as *mut u8, 0, PAGE as usize) };
    Some(cadre)
}

/// L'espace d'adressage d'un programme. Le détruire (le laisser sortir de
/// portée) rend toutes ses pages et toutes ses tables.
pub struct EspaceUtilisateur {
    /// L'adresse physique de sa PML4.
    pml4: u64,
    /// Le nombre de cadres projetés, à lui (sans compter les tables, ni la
    /// page de zéros).
    pages: usize,
    /// Le plus de pages qu'il peut avoir (voir BUDGET_PAGES).
    budget: usize,
}

impl EspaceUtilisateur {
    /// Un espace neuf : moitié basse vide, moitié haute du noyau.
    pub fn creer() -> Result<EspaceUtilisateur, Erreur> {
        let pml4 = pages::allouer(0).ok_or(Erreur::PlusDeMemoire)?;
        // SAFETY : `pml4` vient d'être alloué, il est à nous ; la PML4 du
        // noyau est une table en place, qu'on ne fait que lire.
        unsafe {
            let nouvelle = &mut *(espace::virtuelle(pml4) as *mut [u64; 512]);
            let noyau = pagination::lire_table(pagination::pml4_noyau());
            nouvelle[..256].fill(0);
            nouvelle[256..].copy_from_slice(&noyau[256..]);
        }
        let budget = BUDGET_PAGES.min(pages::libres() / 2);
        Ok(EspaceUtilisateur { pml4, pages: 0, budget })
    }

    /// L'adresse physique de la PML4, pour CR3.
    pub fn pml4(&self) -> u64 {
        self.pml4
    }

    /// Le nombre de cadres projetés (la mémoire « résidente »).
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Le plus de cadres qu'il peut avoir (voir BUDGET_PAGES).
    pub fn budget(&self) -> usize {
        self.budget
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
    ///   - La page de zéros, et une écriture : une page neuve à sa place (la
    ///     copie à l'écriture, do_wp_page). L'ancienne traduction peut être
    ///     dans le TLB : invlpg.
    ///   - Une page à lui : l'entrée est refaite d'après les droits de la
    ///     zone. C'est le cas d'une page restée en lecture seule dans une
    ///     zone inscriptible (do_wp_page la « réutilise » : personne d'autre
    ///     ne la voit), ou d'une faute « fantôme », quand l'entrée permet
    ///     déjà l'accès mais que le TLB gardait une traduction plus ancienne
    ///     (manuel d'Intel, vol. 3A, 4.10.4.3). invlpg, et on reprend.
    ///
    /// Le cadre neuf est mis à zéro ici, interruptions coupées (on tient le
    /// verrou du processus) : 4 Kio, une microseconde. (Linux rouvre les
    /// interruptions pendant une faute, parce qu'elle peut attendre un
    /// disque ; ce sera le cas avec le disque de 6l.)
    pub fn servir(&mut self, page: u64, droits: Droits, ecriture: bool) -> Result<(), Erreur> {
        if !adresse_permise(page) {
            return Err(Erreur::AdresseInterdite);
        }
        let entree = pagination::entree(self.pml4, page).ok_or(Erreur::PlusDeMemoire)?;
        let cadre = *entree & ADRESSE;
        let zeros = page_de_zeros();
        if !occupee(*entree) || (cadre == zeros && ecriture) {
            let neuve = if ecriture { self.prendre_cadre()? } else { zeros };
            let remplacee = occupee(*entree);
            *entree = entree_finale(neuve, droits);
            if remplacee {
                self.invalider(page);
            }
        } else {
            *entree = entree_finale(cadre, droits);
            self.invalider(page);
        }
        Ok(())
    }

    /// La traduction de `page` ne doit plus servir, si cet espace est actif.
    fn invalider(&self, page: u64) {
        if self.actif() {
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
        let entree = pagination::entree(self.pml4, adresse).ok_or(Erreur::PlusDeMemoire)?;
        if occupee(*entree) {
            return Err(Erreur::DejaProjetee);
        }
        let cadre = self.prendre_cadre()?;
        *entree = entree_finale(cadre, droits);
        Ok(cadre)
    }

    /// Un cadre neuf pour l'espace, dans son budget, compté.
    fn prendre_cadre(&mut self) -> Result<u64, Erreur> {
        if self.pages >= self.budget {
            return Err(Erreur::PlusDeMemoire);
        }
        let cadre = cadre_neuf().ok_or(Erreur::PlusDeMemoire)?;
        self.pages += 1;
        Ok(cadre)
    }

    /// Cet espace est-il celui du processeur (CR3) ? Sinon, il n'y a rien
    /// à invalider : le changement de CR3 qui l'activera vide le TLB.
    fn actif(&self) -> bool {
        pagination::courante() == self.pml4
    }

    /// Retire les pages de [debut, fin[ (alignés) et rend leurs cadres :
    /// brk qui recule. Les adresses où rien n'est projeté ne coûtent rien
    /// (voir `parcourir`).
    pub fn retirer_plage(&mut self, debut: u64, fin: u64) {
        let mut lot = Lot::new(self.actif());
        let mut retirees = 0;
        let zeros = page_de_zeros();
        parcourir(self.pml4, debut, fin, &mut |adresse, entree| {
            let cadre = *entree & ADRESSE;
            *entree = 0;
            lot.invalider(adresse);
            // La page de zéros reste au noyau.
            if cadre != zeros {
                lot.rendre(cadre);
                retirees += 1;
            }
        });
        // Le lot se vide en sortant : le TLB d'abord, les cadres ensuite.
        drop(lot);
        self.pages -= retirees;
    }

    /// Donne les droits `droits` à toutes les pages projetées de [debut,
    /// fin[ (mprotect). Le processeur ne sait pas interdire la lecture
    /// d'une page présente : écrire ou exécuter permet aussi de lire, et
    /// sans aucun droit, la page est retirée du processeur (SANS_ACCES).
    /// W+X est permis, comme sous Linux : le compilateur à la volée (JIT)
    /// de JavaScriptCore, le moteur de Claude Code, écrit puis exécute son
    /// code dans les mêmes pages.
    pub fn proteger_plage(&mut self, debut: u64, fin: u64, droits: Droits) {
        let mut lot = Lot::new(self.actif());
        parcourir(self.pml4, debut, fin, &mut |adresse, entree| {
            *entree = entree_finale(*entree & ADRESSE, droits);
            // Des droits retirés : l'ancienne traduction ne doit plus
            // servir. Des droits ajoutés : le processeur relirait l'entrée
            // de lui-même après une faute (manuel d'Intel, vol. 3A,
            // 4.10.4.3), mais tout invalider est plus simple à relire.
            lot.invalider(adresse);
        });
    }

    /// Écrit `octets` à partir de l'adresse `adresse` de l'espace, page par
    /// page, par la projection directe de leurs cadres : l'espace n'a pas
    /// besoin d'être actif, et les droits des pages ne comptent pas (on
    /// remplit ainsi le code d'un programme, en lecture seule pour lui).
    /// Toutes les pages doivent être projetées ; sinon rien n'est écrit.
    pub fn ecrire(&mut self, adresse: u64, octets: &[u8]) -> Result<(), Erreur> {
        let fin = adresse.checked_add(octets.len() as u64).ok_or(Erreur::AdresseInterdite)?;
        // D'abord vérifier, puis écrire : tout ou rien.
        let mut page = adresse / PAGE * PAGE;
        while page < fin {
            self.traduire(page).ok_or(Erreur::NonProjetee)?;
            page += PAGE;
        }
        let mut fait = 0;
        while fait < octets.len() {
            let a = adresse + fait as u64;
            let decalage = (a % PAGE) as usize;
            let n = (PAGE as usize - decalage).min(octets.len() - fait);
            let (cadre, _) = self.traduire(a / PAGE * PAGE).ok_or(Erreur::NonProjetee)?;
            // SAFETY : `cadre` est une page de cet espace (traduire l'a
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
            // SAFETY : comme dans `ecrire`, en lecture.
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
            // SAFETY : `table` est une de nos tables (la PML4, puis celles
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
fn parcourir(pml4: u64, debut: u64, fin: u64, f: &mut impl FnMut(u64, &mut u64)) {
    parcourir_table(pml4, 3, debut, fin, f);
}

/// Le parcours dans la table `table` de niveau `niveau` (3 : la PML4),
/// restreint à [debut, fin[.
fn parcourir_table(table: u64, niveau: u32, debut: u64, fin: u64, f: &mut impl FnMut(u64, &mut u64)) {
    // Ce que couvre une entrée de ce niveau : 4 Kio, 2 Mio, 1 Gio, 512 Gio.
    // Les adresses restent sous 2^47 : pas de débordement.
    let couverture = PAGE << (9 * niveau);
    let mut adresse = debut;
    while adresse < fin {
        let suivante = (adresse / couverture + 1) * couverture;
        // SAFETY : `table` est une table de cet espace (la PML4, ou une
        // table que désigne une entrée présente), que nous possédons ; un
        // seul processeur, un seul programme : personne ne la change en
        // même temps.
        let entree = unsafe { &mut pagination::table_modifiable(table)[pagination::index(adresse, niveau)] };
        if niveau == 0 {
            if occupee(*entree) {
                f(adresse, entree);
            }
        } else if *entree & PRESENTE != 0 {
            parcourir_table(*entree & ADRESSE, niveau - 1, adresse, suivante.min(fin), f);
        }
        adresse = suivante;
    }
}

/// Le plus de pages invalidées une à une (invlpg) avant de préférer vider
/// tout le TLB (recharger CR3) : le tlb_single_page_flush_ceiling de
/// Linux. Au-delà, chaque invlpg coûte plus que de recharger ensuite les
/// traductions dont on a vraiment besoin.
const PLAFOND_INVLPG: usize = 33;

/// Ce qu'un parcours des tables laisse à faire : des traductions à retirer
/// du TLB, puis des cadres à rendre (le mmu_gather de Linux). L'ordre
/// compte : un cadre rendu alors qu'une traduction vers lui reste dans le
/// TLB pourrait encore être écrit par le programme, alors qu'il appartient
/// déjà à quelqu'un d'autre. Le lot vide donc toujours le TLB AVANT de
/// rendre ses cadres, et se vide de lui-même en disparaissant (Drop).
struct Lot {
    /// L'espace parcouru est-il actif ? Sinon, rien à invalider.
    actif: bool,
    pages: [u64; PLAFOND_INVLPG],
    nombre_pages: usize,
    /// Plus de PLAFOND_INVLPG pages : on videra tout le TLB.
    tout: bool,
    cadres: [u64; 64],
    nombre_cadres: usize,
}

impl Lot {
    fn new(actif: bool) -> Lot {
        Lot { actif, pages: [0; PLAFOND_INVLPG], nombre_pages: 0, tout: false, cadres: [0; 64], nombre_cadres: 0 }
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

    /// Le cadre `cadre` est à rendre, une fois le TLB vidé. Toute page qui
    /// le désignait doit déjà avoir été passée à `invalider`.
    fn rendre(&mut self, cadre: u64) {
        if self.nombre_cadres == self.cadres.len() {
            self.vider();
        }
        self.cadres[self.nombre_cadres] = cadre;
        self.nombre_cadres += 1;
    }

    /// Vide le TLB de ce qu'on a noté, puis rend les cadres.
    fn vider(&mut self) {
        if self.actif {
            if self.tout {
                pagination::vider_tlb();
            } else {
                self.pages[..self.nombre_pages].iter().for_each(|&p| pagination::invalider(p));
            }
        }
        (self.nombre_pages, self.tout) = (0, false);
        self.cadres[..self.nombre_cadres].iter().for_each(|&c| pages::liberer(c, 0));
        self.nombre_cadres = 0;
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
        // SAFETY : `table` est une table de l'espace, plus utilisée par
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
        // Un cadre de page (niveau 0) ou une table (au-dessus) : tous des
        // blocs d'une page, pris au buddy. (Le jour où des pages seront
        // partagées entre programmes, il faudra un compteur de références,
        // comme le _refcount de la struct page de Linux.)
        pages::liberer(dessous, 0);
    }
}

impl Drop for EspaceUtilisateur {
    fn drop(&mut self) {
        // D'abord quitter l'espace s'il est actif : on ne rend pas des
        // tables dont le processeur se sert encore. La PML4 du noyau a la
        // même moitié haute : l'exécution continue sans heurt.
        if pagination::courante() == self.pml4 {
            // SAFETY : la PML4 du noyau est complète.
            unsafe { pagination::activer(pagination::pml4_noyau()) };
        }
        rendre(self.pml4, 3);
        pages::liberer(self.pml4, 0);
    }
}
