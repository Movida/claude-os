//! MSI-X : les interruptions d'un périphérique PCI, par messages.
//!
//! Le PCI d'origine donnait à chaque carte un FIL d'interruption (INTx),
//! partagé entre plusieurs cartes et routé par la carte mère vers une
//! entrée de l'IO-APIC. Pour savoir quelle entrée, sur un vrai PC, il faut
//! lire la table `_PRT` de l'ACPI, écrite en AML : un interpréteur entier.
//! MSI (« Message Signaled Interrupts », PCI 2.2), puis MSI-X (PCI 3.0),
//! s'en passent : pour interrompre, la carte ÉCRIT un mot de 32 bits à une
//! adresse que le système lui a donnée. Sur x86, une écriture dans la
//! fenêtre 0xFEE0_0000 n'atteint pas la mémoire : c'est un message pour
//! l'APIC local d'un processeur, qui porte le vecteur à livrer (manuel
//! d'Intel, vol. 3A, 11.11). Plus de fil partagé, plus de table à
//! interpréter, et un vecteur par source : une carte réseau en donne un à
//! chaque file.
//!
//! MSI-X range ses messages dans une TABLE, dans l'une de ses BAR (la
//! capacité MSI-X dit laquelle, et à quel décalage) : 16 octets par entrée,
//! l'adresse (64 bits), la donnée (32 bits), et un mot de contrôle dont le
//! bit 0 masque l'entrée. On la projette sans cache (vmalloc::ioremap), et
//! chaque champ s'écrit en mots de 32 bits alignés (la spécification n'y
//! admet que des accès alignés de 32 ou 64 bits ; Linux, comme nous, n'en
//! fait que de 32).
//!
//! L'ordre : MSI-X activé avec TOUTE la fonction masquée (le bit
//! « function mask » du registre de contrôle), chaque entrée masquée, le
//! fil INTx coupé, puis le masque de la fonction levé ; ensuite le pilote
//! programme ses entrées une à une, chacune masquée pendant qu'on l'écrit,
//! et démasquée une fois son message écrit en entier : la carte ne doit
//! jamais envoyer un message à moitié écrit. Linux (`msix_capability_init`,
//! drivers/pci/msi/msi.c) programme d'abord toutes les entrées, puis coupe
//! INTx, masque tout de nouveau (pour une carte NVMe de Marvell qui
//! l'oubliait) et lève enfin le masque de la fonction : équivalent, puisque
//! rien ne part d'une entrée masquée.
//!
//! Le message (manuel d'Intel, 11.11.1 et 11.11.2) : l'adresse
//! 0xFEE0_0000 | (numéro de l'APIC visé << 12), en mode physique (bit 2 à
//! 0) et sans « redirection hint » (bit 3 à 0 : ce processeur-là, pas le
//! moins occupé) ; la donnée = le vecteur, livraison fixe (bits 8 à 10 à
//! 0), par front (bit 15 à 0). Option écartée : MSI simple (une capacité,
//! jusqu'à 32 vecteurs consécutifs et alignés, masquables seulement si la
//! carte le veut bien) : virtio-pci ne connaît que MSI-X, comme la plupart
//! des cartes d'aujourd'hui.

use crate::pci::{Adresse, Fonction};
use crate::vmalloc::{self, Projection};
use crate::{apic, irq};
use formats::pci::{self, Bar};

/// Les champs d'une entrée de la table (16 octets).
const ENTREE: u64 = 16;
const ADRESSE_BASSE: u64 = 0;
const ADRESSE_HAUTE: u64 = 4;
const DONNEE: u64 = 8;
const CONTROLE: u64 = 12;
/// Dans le mot de contrôle : l'entrée est masquée.
const MASQUE: u32 = 1;

/// La fenêtre des messages pour les APIC locaux.
const FENETRE_APIC: u32 = 0xFEE0_0000;

/// Pourquoi MSI-X n'est pas utilisable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// La fonction n'a pas de capacité MSI-X.
    Absente,
    /// Pas d'APIC local (le repli sur le 8259) : un message n'arriverait
    /// nulle part.
    SansApic,
    /// La table n'est pas dans une BAR de mémoire, ou en sort.
    Table,
    /// Plus de place pour projeter la table.
    Projection,
}

// Affiché par le noyau : sans accents.
impl core::fmt::Display for Refus {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(match self {
            Refus::Absente => "pas de MSI-X",
            Refus::SansApic => "pas d'APIC local : pas de MSI-X",
            Refus::Table => "table MSI-X hors de sa BAR",
            Refus::Projection => "table MSI-X impossible a projeter",
        })
    }
}

/// MSI-X en service sur une fonction : sa table projetée. Rendu par `Drop`
/// (chaque entrée masquée, MSI-X coupé, la projection rendue).
pub struct MsiX {
    fonction: Adresse,
    position: usize,
    table: Projection,
    entrees: u16,
}

impl MsiX {
    /// Met MSI-X en service sur `f`, toutes ses entrées masquées et le
    /// masque de la fonction levé : chaque entrée attend son message.
    pub fn activer(f: &Fonction) -> Result<MsiX, Refus> {
        if !irq::apic() {
            return Err(Refus::SansApic);
        }
        let (position, _) = f.capacites().find(|&(_, n)| n == pci::CAPACITE_MSIX).ok_or(Refus::Absente)?;
        let m = pci::lire_msix(&f.espace, position).map_err(|_| Refus::Absente)?;
        let taille = m.entrees as u64 * ENTREE;
        let Some(Bar::Memoire { adresse, taille: fenetre, .. }) = f.bars.get(m.bar_table as usize).copied() else {
            return Err(Refus::Table);
        };
        if m.decalage_table as u64 + taille > fenetre {
            return Err(Refus::Table);
        }
        let table = vmalloc::ioremap(adresse + m.decalage_table as u64, taille).ok_or(Refus::Projection)?;
        let a = f.adresse;
        let controle = position + pci::MSIX_CONTROLE;
        // 1. Activé, la fonction entière masquée.
        let c = a.lire16(controle);
        a.ecrire16(controle, c | pci::MSIX_ACTIF | pci::MSIX_MASQUE_TOUT);
        let msix = MsiX { fonction: a, position, table, entrees: m.entrees };
        // 2. Chaque entrée masquée ; 3. le fil INTx coupé.
        for e in 0..m.entrees {
            msix.ecrire(e, CONTROLE, MASQUE);
        }
        a.changer_commande(pci::COMMANDE_SANS_INTX, 0);
        // 4. Le masque de la fonction levé : seules les entrées démasquées
        // pourront envoyer un message.
        a.ecrire16(controle, (c | pci::MSIX_ACTIF) & !pci::MSIX_MASQUE_TOUT);
        Ok(msix)
    }

    /// Le nombre d'entrées de la table.
    pub fn entrees(&self) -> u16 {
        self.entrees
    }

    fn ecrire(&self, entree: u16, champ: u64, valeur: u32) {
        let adresse = self.table.adresse() + entree as u64 * ENTREE + champ;
        // SAFETY : la table est projetée sans cache sur `entrees` entrées
        // (activer), l'entrée en fait partie (les appelants le vérifient) ;
        // un mot de 32 bits aligné, ce qu'exige MSI-X.
        unsafe { (adresse as *mut u32).write_volatile(valeur) }
    }

    fn lire(&self, entree: u16, champ: u64) -> u32 {
        let adresse = self.table.adresse() + entree as u64 * ENTREE + champ;
        // SAFETY : comme `ecrire`.
        unsafe { (adresse as *const u32).read_volatile() }
    }

    /// Fait envoyer à l'entrée `entree` le vecteur `vecteur`, à l'APIC de ce
    /// processeur, puis la démasque. false : pas d'entrée de ce numéro.
    pub fn programmer(&self, entree: u16, vecteur: u8) -> bool {
        if entree >= self.entrees {
            return false;
        }
        self.ecrire(entree, CONTROLE, MASQUE);
        self.ecrire(entree, ADRESSE_BASSE, FENETRE_APIC | (apic::id() as u32) << 12);
        self.ecrire(entree, ADRESSE_HAUTE, 0);
        self.ecrire(entree, DONNEE, vecteur as u32);
        // Relire avant de démasquer : les écritures dans la table, non
        // cachées, sont alors arrivées à la carte (une écriture PCI peut
        // être « postée », retenue en chemin ; une lecture la force).
        let _ = self.lire(entree, DONNEE);
        self.ecrire(entree, CONTROLE, 0);
        true
    }

    /// Le message de l'entrée `entree`, tel que relu dans la table :
    /// (adresse, donnée, masquée).
    pub fn message(&self, entree: u16) -> Option<(u64, u32, bool)> {
        (entree < self.entrees).then(|| {
            let adresse = (self.lire(entree, ADRESSE_HAUTE) as u64) << 32 | self.lire(entree, ADRESSE_BASSE) as u64;
            (adresse, self.lire(entree, DONNEE), self.lire(entree, CONTROLE) & MASQUE != 0)
        })
    }
}

impl Drop for MsiX {
    fn drop(&mut self) {
        for e in 0..self.entrees {
            self.ecrire(e, CONTROLE, MASQUE);
        }
        let controle = self.position + pci::MSIX_CONTROLE;
        let c = self.fonction.lire16(controle);
        self.fonction.ecrire16(controle, c & !pci::MSIX_ACTIF);
    }
}
