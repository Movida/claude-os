//! Pilote du port série COM1 (UART 16550), la même puce qu'en assembleur
//! aux étapes précédentes. Tout ce que le noyau affiche part aussi ici :
//! c'est ce que lit `verifier.sh`.

use crate::port;
use core::fmt;

const COM1: u16 = 0x3F8;

/// Programme l'UART : 115200 bauds, 8 bits, sans parité, 1 bit de stop.
pub fn initialiser() {
    // SAFETY : ce sont les registres documentés du 16550 de COM1, dans
    // l'ordre prévu par sa fiche technique.
    unsafe {
        port::ecrire(COM1 + 1, 0x00); // IER : aucune interruption de l'UART.
        port::ecrire(COM1 + 3, 0x80); // LCR.DLAB : accès au diviseur.
        port::ecrire(COM1, 0x01);     // Diviseur = 1 -> 115200 bauds...
        port::ecrire(COM1 + 1, 0x00); // ... octet haut du diviseur.
        port::ecrire(COM1 + 3, 0x03); // LCR : 8N1, DLAB à 0.
        port::ecrire(COM1 + 2, 0xC7); // FCR : FIFO activée et vidée.
        port::ecrire(COM1 + 4, 0x03); // MCR : DTR + RTS.
    }
}

/// Envoie un octet, en attendant que le registre d'émission soit libre.
pub fn ecrire_octet(octet: u8) {
    // SAFETY : lecture du registre d'état (LSR) puis écriture du registre
    // de données de COM1, sans effet sur le reste de la machine.
    unsafe {
        while port::lire(COM1 + 5) & 0x20 == 0 {}
        port::ecrire(COM1, octet);
    }
}

/// Le port série comme destination de `write!` : c'est ce qui permet
/// d'utiliser le formatage de Rust (`{}`, `{:x}`...) sans bibliothèque
/// standard, `core::fmt` suffit.
pub struct Serie;

impl fmt::Write for Serie {
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        for octet in texte.bytes() {
            // Un terminal attend « retour chariot » puis « saut de ligne ».
            // Les caractères non ASCII partent en UTF-8, tels quels : un
            // terminal moderne les affiche correctement.
            match octet {
                b'\n' => {
                    ecrire_octet(b'\r');
                    ecrire_octet(b'\n');
                }
                // Retour arrière : le terminal recule seulement ; pour
                // effacer, on recule, on écrit une espace, on recule.
                0x08 => {
                    ecrire_octet(0x08);
                    ecrire_octet(b' ');
                    ecrire_octet(0x08);
                }
                _ => ecrire_octet(octet),
            }
        }
        Ok(())
    }
}
