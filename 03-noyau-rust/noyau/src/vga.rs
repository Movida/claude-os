//! L'écran en mode texte VGA : 25 lignes de 80 cases à l'adresse 0xB8000.
//! Chaque case fait 2 octets : le caractère (page de code 437), puis la
//! couleur (4 bits de fond, 4 bits de texte).

use core::fmt;
use core::ptr;

const LARGEUR: usize = 80;
const HAUTEUR: usize = 25;
const MEMOIRE_VIDEO: *mut u16 = 0xB8000 as *mut u16;

/// Vert clair sur fond noir, comme les messages du chargeur.
const COULEUR: u16 = 0x0A;

pub struct Ecran {
    ligne: usize,
    colonne: usize,
}

impl Ecran {
    pub const fn new() -> Self {
        Ecran { ligne: 0, colonne: 0 }
    }

    /// Écrit une case. write_volatile : sans lui, le compilateur, qui ne
    /// voit jamais personne relire cette mémoire, pourrait supprimer
    /// l'écriture. « Volatile » lui dit que la mémoire a un effet ailleurs
    /// (ici, la carte vidéo).
    fn case(&mut self, ligne: usize, colonne: usize, valeur: u16) {
        // SAFETY : ligne < HAUTEUR et colonne < LARGEUR, donc on reste dans
        // les 4000 octets de la mémoire vidéo, projetée par le chargeur.
        unsafe {
            ptr::write_volatile(MEMOIRE_VIDEO.add(ligne * LARGEUR + colonne), valeur);
        }
    }

    fn lire_case(&self, ligne: usize, colonne: usize) -> u16 {
        // SAFETY : mêmes bornes que case().
        unsafe { ptr::read_volatile(MEMOIRE_VIDEO.add(ligne * LARGEUR + colonne)) }
    }

    pub fn effacer(&mut self) {
        for ligne in 0..HAUTEUR {
            self.effacer_ligne(ligne);
        }
        self.ligne = 0;
        self.colonne = 0;
    }

    fn effacer_ligne(&mut self, ligne: usize) {
        for colonne in 0..LARGEUR {
            self.case(ligne, colonne, COULEUR << 8 | b' ' as u16);
        }
    }

    fn nouvelle_ligne(&mut self) {
        self.colonne = 0;
        if self.ligne + 1 < HAUTEUR {
            self.ligne += 1;
            return;
        }
        // Écran plein : tout remonte d'une ligne, la dernière est vidée.
        for ligne in 1..HAUTEUR {
            for colonne in 0..LARGEUR {
                let valeur = self.lire_case(ligne, colonne);
                self.case(ligne - 1, colonne, valeur);
            }
        }
        self.effacer_ligne(HAUTEUR - 1);
    }

    pub fn ecrire_octet(&mut self, octet: u8) {
        match octet {
            b'\n' => self.nouvelle_ligne(),
            octet => {
                if self.colonne == LARGEUR {
                    self.nouvelle_ligne();
                }
                self.case(self.ligne, self.colonne, COULEUR << 8 | octet as u16);
                self.colonne += 1;
            }
        }
    }
}

impl fmt::Write for Ecran {
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        for octet in texte.bytes() {
            // Hors ASCII imprimable, la police du BIOS afficherait un
            // caractère de la page 437 sans rapport : on met un carré.
            match octet {
                b'\n' | 0x20..=0x7E => self.ecrire_octet(octet),
                _ => self.ecrire_octet(0xFE),
            }
        }
        Ok(())
    }
}
