//! L'IO-APIC : là où arrivent les lignes d'interruption des périphériques.
//!
//! Chaque entrée de l'IO-APIC (24 sous QEMU) reçoit une ligne : celles de
//! l'ancien bus ISA (l'horloge PIT, le clavier, les ports série...), puis
//! celles des cartes PCI. Pour chacune, une « entrée de redirection » de 64
//! bits dit à quel vecteur, et à quel APIC local, envoyer un message quand
//! la ligne s'active ; et si la ligne est active haute ou basse, par front
//! ou par niveau. Les entrées de tous les IO-APIC sont numérotées d'un
//! seul tenant, les GSI (Global System Interrupts) : la MADT donne le
//! premier GSI de chaque IO-APIC.
//!
//! Les IRQ du bus ISA arrivent en principe sur le GSI de même numéro, par
//! front montant, actives hautes ; la MADT dit les exceptions (les
//! « remplacements ») : chez QEMU comme sur la plupart des PC, l'horloge
//! (IRQ 0) arrive sur le GSI 2, et les IRQ 5, 9, 10 et 11 (des cartes PCI
//! dans la machine `pc`) sont en niveau.
//!
//! Les registres : deux mots de 32 bits en mémoire, IOREGSEL (le numéro du
//! registre voulu) et IOWIN (sa valeur), à l'adresse que dit la MADT
//! (0xFEC00000), projetés sans cache. Le registre 1 donne la version et le
//! nombre d'entrées ; l'entrée n occupe les registres 0x10 + 2n (bits 0 à
//! 31) et 0x11 + 2n (bits 32 à 63). Choisir un registre puis le lire forme
//! une paire qu'il ne faut pas couper : sous un verrou (l'`ioapic_lock`
//! de Linux).
//!
//! Les vecteurs, ceux de Linux pour les IRQ ISA (ISA_IRQ_VECTOR) : 0x30 +
//! IRQ. Comme pour le 8259, chaque entrée reste masquée jusqu'à ce que son
//! pilote la démasque, quand il est prêt.

use crate::acpi;
use crate::verrou::Verrou;
use crate::vmalloc;
use alloc::vec::Vec;

/// Le vecteur de l'IRQ ISA 0 ; l'IRQ n arrive sur 0x30 + n.
pub const VECTEUR_ISA: u8 = 0x30;
/// Le nombre d'IRQ du bus ISA.
pub const NB_ISA: u8 = 16;

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
const VERSION: u32 = 0x01;
const REDIRECTION: u32 = 0x10;

/// Dans une entrée de redirection : masquée (bit 16), en niveau (bit 15),
/// active basse (bit 13). Mode de livraison « fixe » (000) et destination
/// physique (bit 11 à 0) : un seul APIC, désigné par son numéro (bits 56
/// à 63).
const MASQUEE: u64 = 1 << 16;
const NIVEAU: u64 = 1 << 15;
const ACTIVE_BASSE: u64 = 1 << 13;

/// Un IO-APIC en service : l'adresse virtuelle de ses registres, son premier
/// GSI, son nombre d'entrées.
struct IoApic {
    registres: u64,
    gsi_base: u32,
    entrees: u32,
}

impl IoApic {
    fn lire(&self, registre: u32) -> u32 {
        // SAFETY : les registres sont projetés sans cache (initialiser) ;
        // l'appelant tient le verrou des IO-APIC : la paire IOREGSEL,
        // IOWIN ne peut pas être coupée.
        unsafe {
            ((self.registres + IOREGSEL) as *mut u32).write_volatile(registre);
            ((self.registres + IOWIN) as *const u32).read_volatile()
        }
    }

    fn ecrire(&self, registre: u32, valeur: u32) {
        // SAFETY : comme `lire`.
        unsafe {
            ((self.registres + IOREGSEL) as *mut u32).write_volatile(registre);
            ((self.registres + IOWIN) as *mut u32).write_volatile(valeur);
        }
    }

    /// Écrit l'entrée `n` : la moitié haute (la destination) d'abord, la
    /// basse (le vecteur, le masque) ensuite, pour qu'une entrée démasquée
    /// n'ait jamais une destination à moitié écrite.
    fn ecrire_entree(&self, n: u32, entree: u64) {
        self.ecrire(REDIRECTION + 2 * n + 1, (entree >> 32) as u32);
        self.ecrire(REDIRECTION + 2 * n, entree as u32);
    }
}

/// Les IO-APIC, et l'entrée de redirection de chaque IRQ ISA (sans le
/// masque) : son IO-APIC, son entrée, sa valeur.
struct Etat {
    ioapics: Vec<IoApic>,
    isa: [Option<(usize, u32, u64)>; NB_ISA as usize],
}

static ETAT: Verrou<Etat> = Verrou::new(Etat { ioapics: Vec::new(), isa: [None; NB_ISA as usize] });

/// Ce que l'initialisation a fait, pour l'afficher : pour chaque IO-APIC,
/// son numéro, son adresse, son premier GSI, son nombre d'entrées.
pub struct Bilan {
    pub ioapics: Vec<(u8, u64, u32, u32)>,
}

/// Met les IO-APIC de la MADT en service : chaque entrée masquée, puis
/// chaque IRQ ISA préparée sur son GSI (encore masquée), destinée à
/// l'APIC local `apic`. None : pas d'IO-APIC, ou ses registres
/// impossibles à projeter.
pub fn initialiser(madt: &acpi::ConfigurationMadt, apic: u8) -> Option<Bilan> {
    let mut etat = ETAT.verrouiller();
    let mut bilan = Bilan { ioapics: Vec::new() };
    for &(numero, adresse, gsi_base) in &madt.ioapics {
        let projection = vmalloc::ioremap(adresse, 0x20)?;
        let mut i = IoApic { registres: projection.adresse(), gsi_base, entrees: 0 };
        // Projetés pour toujours, comme l'APIC local.
        core::mem::forget(projection);
        i.entrees = (i.lire(VERSION) >> 16 & 0xFF) + 1;
        for n in 0..i.entrees {
            i.ecrire_entree(n, MASQUEE);
        }
        bilan.ioapics.push((numero, adresse, gsi_base, i.entrees));
        etat.ioapics.try_reserve(1).ok()?;
        etat.ioapics.push(i);
    }
    if etat.ioapics.is_empty() {
        return None;
    }
    for irq in 0..NB_ISA {
        // Le remplacement de la MADT, sinon le GSI de même numéro, avec la
        // polarité et le déclenchement du bus ISA (0 : « ceux du bus »).
        let (gsi, drapeaux) = madt.remplacements.iter().find(|&&(s, _, _)| s == irq).map_or((irq as u32, 0), |&(_, g, d)| (g, d));
        let basse = drapeaux & 3 == 3;
        let niveau = drapeaux >> 2 & 3 == 3;
        let entree = (VECTEUR_ISA + irq) as u64
            | if niveau { NIVEAU } else { 0 }
            | if basse { ACTIVE_BASSE } else { 0 }
            | (apic as u64) << 56;
        let Some(k) = etat.ioapics.iter().position(|i| gsi >= i.gsi_base && gsi < i.gsi_base + i.entrees) else { continue };
        let n = gsi - etat.ioapics[k].gsi_base;
        etat.ioapics[k].ecrire_entree(n, entree | MASQUEE);
        etat.isa[irq as usize] = Some((k, n, entree));
    }
    Some(bilan)
}

/// Laisse passer l'IRQ ISA `irq` (son pilote est prêt). false : elle
/// n'arrive sur aucune entrée.
pub fn demasquer(irq: u8) -> bool {
    let etat = ETAT.verrouiller();
    let Some(&Some((k, n, entree))) = etat.isa.get(irq as usize) else { return false };
    etat.ioapics[k].ecrire_entree(n, entree);
    true
}

/// Le GSI sur lequel arrive l'IRQ ISA `irq`, pour l'afficher.
pub fn gsi(irq: u8) -> Option<u32> {
    let etat = ETAT.verrouiller();
    let &(k, n, _) = etat.isa.get(irq as usize)?.as_ref()?;
    Some(etat.ioapics[k].gsi_base + n)
}
