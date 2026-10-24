//! L'espace d'adressage d'un programme : sa moitié basse à lui, la moitié
//! haute au noyau.
//!
//! Chaque programme a sa propre PML4 (la racine de ses tables de pages) :
//!   - les entrées 0 à 255 (la moitié basse, 128 Tio) sont à lui, vides au
//!     départ ; on y projette ses pages une à une, chacune un cadre neuf ;
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
//!     CR3, et sans PCID chaque changement vide le TLB. À l'étape 6, quand
//!     on saura sur quels processeurs on tourne.
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

const PAGE: u64 = 4096;

/// Une page du programme rendue inaccessible (mprotect avec PROT_NONE) :
/// le processeur ne sait pas dire « présente mais interdite » ; on retire
/// le bit PRESENTE, et on garde le cadre dans l'entrée, marquée de ce bit
/// que le processeur laisse au système (le bit 9 : « disponible »). C'est
/// le _PAGE_PROTNONE de Linux. Un accès fait alors une faute de page.
const SANS_ACCES: u64 = 1 << 9;

/// Une entrée finale qui désigne un cadre du programme, accessible ou non.
fn occupee(entree: u64) -> bool {
    entree & (PRESENTE | SANS_ACCES) != 0
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

/// Un cadre neuf, mis à zéro, pas encore projeté. On le prépare À PART,
/// sans tenir aucun verrou et donc interruptions permises : mettre à zéro
/// beaucoup de pages, verrou tenu, ferait perdre leurs tics à l'horloge
/// (voir brk, dans linux.rs). S'il n'est finalement pas projeté, il
/// retourne à l'allocateur tout seul (Drop).
pub struct CadreNeuf(u64);

impl CadreNeuf {
    pub fn allouer() -> Option<CadreNeuf> {
        let cadre = pages::allouer(0)?;
        // SAFETY : le cadre vient d'être alloué, personne d'autre ne le voit.
        // Il contenait ce qu'y avait laissé son précédent occupant (le noyau,
        // un autre programme) : le donner tel quel ferait fuir ces données.
        unsafe { core::ptr::write_bytes(espace::virtuelle(cadre) as *mut u8, 0, PAGE as usize) };
        Some(CadreNeuf(cadre))
    }
}

impl Drop for CadreNeuf {
    fn drop(&mut self) {
        pages::liberer(self.0, 0);
    }
}

/// L'espace d'adressage d'un programme. Le détruire (le laisser sortir de
/// portée) rend toutes ses pages et toutes ses tables.
pub struct EspaceUtilisateur {
    /// L'adresse physique de sa PML4.
    pml4: u64,
    /// Le nombre de pages projetées (sans compter les tables).
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

    /// Projette à `adresse` (une page) un cadre neuf, mis à zéro, avec les
    /// droits `droits` (pagination::ECRITURE, pagination::non_executable()).
    /// Rend l'adresse physique du cadre, pour le remplir par la projection
    /// directe.
    pub fn projeter_neuve(&mut self, adresse: u64, droits: u64) -> Result<u64, Erreur> {
        let cadre = CadreNeuf::allouer().ok_or(Erreur::PlusDeMemoire)?;
        self.projeter(adresse, cadre, droits)
    }

    /// Projette à `adresse` (une page) le cadre `cadre`, préparé à l'avance
    /// (voir CadreNeuf), avec les droits `droits`. Rend son adresse
    /// physique. En cas d'erreur, le cadre retourne à l'allocateur.
    ///
    /// Si l'espace est actif, la nouvelle page sert tout de suite : le
    /// processeur ne garde pas en cache les entrées absentes (manuel
    /// d'Intel, vol. 3A, 4.10.4.3), rien à invalider.
    pub fn projeter(&mut self, adresse: u64, cadre: CadreNeuf, droits: u64) -> Result<u64, Erreur> {
        if !adresse_permise(adresse) {
            return Err(Erreur::AdresseInterdite);
        }
        if self.pages >= self.budget {
            return Err(Erreur::PlusDeMemoire);
        }
        let entree = pagination::entree(self.pml4, adresse).ok_or(Erreur::PlusDeMemoire)?;
        if occupee(*entree) {
            return Err(Erreur::DejaProjetee);
        }
        // Le cadre appartient désormais à l'espace : il ne doit plus
        // retourner seul à l'allocateur.
        let physique = cadre.0;
        core::mem::forget(cadre);
        self.pages += 1;
        *entree = physique | PRESENTE | droits | pagination::UTILISATEUR;
        Ok(physique)
    }

    /// L'entrée finale de la page `adresse` si elle désigne un cadre du
    /// programme (accessible ou non), sans créer de table.
    fn entree_occupee(&mut self, adresse: u64) -> Option<&'static mut u64> {
        let mut table = self.pml4;
        for niveau in (1..4).rev() {
            // SAFETY : `table` est une table de cet espace.
            let e = unsafe { pagination::lire_table(table) }[pagination::index(adresse, niveau)];
            if e & PRESENTE == 0 {
                return None;
            }
            table = e & ADRESSE;
        }
        // SAFETY : `table` est une PT de cet espace, que nous possédons ;
        // l'entrée y est modifiée sous notre seul contrôle (un processeur,
        // un programme).
        let entree = unsafe { &mut pagination::table_modifiable(table)[pagination::index(adresse, 0)] };
        occupee(*entree).then_some(entree)
    }

    /// Le cache des traductions (TLB) ne doit plus servir l'ancienne entrée
    /// de `adresse`, si cet espace est actif. (Inactif : le changement de
    /// CR3 qui l'activera vide le TLB.)
    fn invalider(&self, adresse: u64) {
        if pagination::courante() == self.pml4 {
            pagination::invalider(adresse);
        }
    }

    /// Retire la page `adresse` (brk qui recule) et rend son cadre. Rien à
    /// faire si elle n'est pas projetée.
    pub fn retirer(&mut self, adresse: u64) {
        let Some(entree) = self.entree_occupee(adresse) else { return };
        let cadre = *entree & ADRESSE;
        *entree = 0;
        // Invalider AVANT de rendre le cadre : sinon le programme pourrait
        // encore l'écrire, par une traduction gardée en cache, alors qu'il
        // appartient déjà à quelqu'un d'autre.
        self.invalider(adresse);
        pages::liberer(cadre, 0);
        self.pages -= 1;
    }

    /// Change les droits de toutes les pages de [debut, fin[ (mprotect) :
    /// `lecture`, `ecriture`, `execution`. Toutes doivent être projetées,
    /// sinon rien n'est changé (Linux rend alors ENOMEM). Le processeur ne
    /// sait pas interdire la lecture d'une page présente : écrire ou
    /// exécuter permet aussi de lire, et sans aucun droit, la page est
    /// retirée du processeur (SANS_ACCES). W+X est permis, comme sous
    /// Linux : le compilateur à la volée (JIT) de JavaScriptCore, le moteur
    /// de Claude Code, écrit puis exécute son code dans les mêmes pages.
    pub fn proteger(&mut self, debut: u64, fin: u64, lecture: bool, ecriture: bool, execution: bool)
        -> Result<(), Erreur> {
        let pages = (debut..fin).step_by(PAGE as usize);
        if pages.clone().any(|p| self.entree_occupee(p).is_none()) {
            return Err(Erreur::NonProjetee);
        }
        let mut droits = 0;
        if ecriture {
            droits |= pagination::ECRITURE;
        }
        if !execution {
            droits |= pagination::non_executable();
        }
        let accessible = lecture || ecriture || execution;
        for page in pages {
            if let Some(entree) = self.entree_occupee(page) {
                let cadre = *entree & ADRESSE;
                *entree = if accessible {
                    cadre | PRESENTE | pagination::UTILISATEUR | droits
                } else {
                    cadre | SANS_ACCES
                };
                self.invalider(page);
            }
        }
        Ok(())
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
