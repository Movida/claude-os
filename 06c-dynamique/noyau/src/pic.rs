//! Le contrôleur d'interruptions 8259 (PIC, Programmable Interrupt Controller).
//!
//! Les périphériques ne parlent pas directement au processeur : chacun tire
//! sur une « ligne d'interruption » (IRQ) reliée à ce contrôleur, qui choisit
//! la plus prioritaire et la transmet au CPU avec un numéro de vecteur. Un
//! PC en a deux, montés en cascade depuis l'IBM AT (1984) :
//!   - le maître (ports 0x20-0x21) reçoit les IRQ 0 à 7 ;
//!   - l'esclave (ports 0xA0-0xA1) reçoit les IRQ 8 à 15, et sa sortie est
//!     branchée sur l'entrée 2 du maître.
//!
//! IRQ utiles pour nous : 0 = horloge (PIT), 1 = clavier, 4 = COM1.
//!
//! Le problème à régler en premier : au démarrage, le BIOS envoie les IRQ
//! 0-7 sur les vecteurs 8 à 15... qui sont aussi ceux des exceptions du
//! processeur (8 = double faute !). On ne distinguerait plus un tic
//! d'horloge d'une vraie erreur. On « remappe » donc les deux contrôleurs
//! sur les vecteurs 32 à 47, juste après les 32 réservés au processeur
//! (le même choix que Linux, qui commence ses IRQ à 0x20).
//!
//! Option écartée pour l'instant : l'APIC (local APIC + I/O APIC), qui
//! remplace le 8259 sur tous les PC depuis les années 2000 et qu'utilise
//! Linux. Il faut le trouver dans les tables ACPI (MADT), et il ne sert
//! vraiment qu'avec plusieurs processeurs. Le 8259 existe toujours, émulé
//! par le chipset et par QEMU : c'est le bon premier pas, et Linux lui-même
//! le programme puis le masque entièrement quand il passe à l'APIC.

use crate::port;

const MAITRE_COMMANDE: u16 = 0x20;
const MAITRE_DONNEES: u16 = 0x21;
const ESCLAVE_COMMANDE: u16 = 0xA0;
const ESCLAVE_DONNEES: u16 = 0xA1;

/// Premier vecteur des IRQ : IRQ n -> vecteur 32 + n.
pub const VECTEUR_BASE: u8 = 32;
/// Nombre de lignes d'IRQ (deux contrôleurs de 8).
pub const NB_IRQ: u8 = 16;

/// L'esclave arrive sur cette entrée du maître.
const IRQ_CASCADE: u8 = 2;

/// Commande « fin d'interruption » (EOI, End Of Interrupt).
const EOI: u8 = 0x20;
/// Commande « lis-moi le registre ISR » (OCW3).
const LIRE_ISR: u8 = 0x0B;

/// Une petite pause : écrire sur le port 0x80 (le port des codes de
/// diagnostic POST du BIOS, sans effet) prend environ 1 µs. Le vrai 8259
/// d'origine avait besoin de ce délai entre deux commandes. Linux fait de
/// même (outb_p, « p » comme pause).
fn pause() {
    // SAFETY : le port 0x80 n'est relié à rien qui compte.
    unsafe { port::ecrire(0x80, 0) };
}

/// Initialise les deux contrôleurs, et masque toutes les IRQ : chaque
/// pilote démasque la sienne quand il est prêt (sinon une interruption
/// pourrait arriver avant que son gestionnaire sache quoi en faire).
pub fn initialiser() {
    // La séquence d'initialisation est imposée par la fiche technique :
    // ICW1 sur le port de commande, puis ICW2, ICW3, ICW4 sur le port de
    // données (ICW = Initialization Command Word).
    // SAFETY : ports documentés des deux 8259, séquence de la fiche
    // technique d'Intel ; les IRQ restent masquées pendant ce temps.
    unsafe {
        // ICW1 : 0x11 = « initialisation, il y aura un ICW4, mode cascade ».
        port::ecrire(MAITRE_COMMANDE, 0x11);
        pause();
        port::ecrire(ESCLAVE_COMMANDE, 0x11);
        pause();
        // ICW2 : le premier vecteur de chaque contrôleur.
        port::ecrire(MAITRE_DONNEES, VECTEUR_BASE);
        pause();
        port::ecrire(ESCLAVE_DONNEES, VECTEUR_BASE + 8);
        pause();
        // ICW3 : le câblage de la cascade. Au maître, un masque de bits
        // (« un esclave sur l'entrée 2 ») ; à l'esclave, un numéro (« tu
        // es sur l'entrée 2 »).
        port::ecrire(MAITRE_DONNEES, 1 << IRQ_CASCADE);
        pause();
        port::ecrire(ESCLAVE_DONNEES, IRQ_CASCADE);
        pause();
        // ICW4 : 0x01 = mode 8086 (et pas le mode 8080 de 1976 !). Pas de
        // « fin d'interruption automatique » : on enverra nous-mêmes l'EOI,
        // après avoir traité l'interruption.
        port::ecrire(MAITRE_DONNEES, 0x01);
        pause();
        port::ecrire(ESCLAVE_DONNEES, 0x01);
        pause();

        // Masques (OCW1) : un bit à 1 = IRQ ignorée. Tout est masqué, sauf
        // la cascade : sans elle, aucune IRQ de l'esclave ne passerait.
        port::ecrire(MAITRE_DONNEES, !(1 << IRQ_CASCADE));
        port::ecrire(ESCLAVE_DONNEES, 0xFF);
    }
}

/// Port de données (masque) du contrôleur qui gère cette IRQ, et numéro de
/// sa ligne sur ce contrôleur.
fn controleur(irq: u8) -> (u16, u8) {
    if irq < 8 { (MAITRE_DONNEES, irq) } else { (ESCLAVE_DONNEES, irq - 8) }
}

/// Laisse passer une IRQ.
pub fn demasquer(irq: u8) {
    let (port_masque, ligne) = controleur(irq);
    // SAFETY : lecture-modification-écriture du masque, qui ne touche que
    // le bit de cette ligne.
    unsafe {
        let masque = port::lire(port_masque);
        port::ecrire(port_masque, masque & !(1 << ligne));
    }
}

/// Lit le registre ISR (In-Service Register) des deux contrôleurs : les
/// IRQ transmises au CPU et pas encore acquittées par un EOI.
fn en_service() -> u16 {
    // SAFETY : OCW3 ne fait que choisir le registre que rendra la
    // prochaine lecture du port de commande.
    unsafe {
        port::ecrire(MAITRE_COMMANDE, LIRE_ISR);
        port::ecrire(ESCLAVE_COMMANDE, LIRE_ISR);
        (port::lire(ESCLAVE_COMMANDE) as u16) << 8 | port::lire(MAITRE_COMMANDE) as u16
    }
}

/// Les IRQ 7 et 15 peuvent être « fantômes » (spurious) : un parasite sur
/// une ligne, retombé avant que le 8259 ait pu dire laquelle. Il envoie
/// alors la plus basse priorité de chaque contrôleur, 7 ou 15, sans
/// marquer de bit dans l'ISR. Rien à traiter, et surtout pas d'EOI au
/// contrôleur concerné : il acquitterait une AUTRE interruption en cours.
/// Exception : un fantôme de l'esclave est passé par l'entrée 2 du maître,
/// qui, lui, l'a bien comptée et attend son EOI. (Linux : i8259.c,
/// « spurious 8259A interrupt ».)
pub fn est_fantome(irq: u8) -> bool {
    match irq {
        7 if en_service() & (1 << 7) == 0 => true,
        15 if en_service() & (1 << 15) == 0 => {
            // SAFETY : EOI au maître seul, pour la cascade (voir plus haut).
            unsafe { port::ecrire(MAITRE_COMMANDE, EOI) };
            true
        }
        _ => false,
    }
}

/// Signale la fin du traitement d'une IRQ. Tant qu'il ne l'a pas reçue, le
/// contrôleur ne transmet plus cette IRQ, ni aucune de priorité plus basse.
/// Une IRQ de l'esclave doit être acquittée aux deux : à l'esclave, et au
/// maître qui l'a relayée par la cascade.
pub fn fin_interruption(irq: u8) {
    // SAFETY : commande EOI non spécifique, sur les ports de commande.
    unsafe {
        if irq >= 8 {
            port::ecrire(ESCLAVE_COMMANDE, EOI);
        }
        port::ecrire(MAITRE_COMMANDE, EOI);
    }
}
