//! L'écran en mode texte VGA : 25 lignes de 80 cases à l'adresse 0xB8000.
//! Chaque case fait 2 octets : le caractère (page de code 437), puis la
//! couleur (4 bits de fond, 4 bits de texte).

use crate::port;
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
            // Retour arrière : on recule et on efface la case. On ne remonte
            // pas à la ligne précédente : un terminal ne le fait pas non plus.
            0x08 => {
                if self.colonne > 0 {
                    self.colonne -= 1;
                    self.case(self.ligne, self.colonne, COULEUR << 8 | b' ' as u16);
                }
            }
            // Tabulation : jusqu'à la prochaine colonne multiple de 8.
            b'\t' => {
                self.ecrire_octet(b' ');
                while self.colonne % 8 != 0 {
                    self.ecrire_octet(b' ');
                }
            }
            octet => {
                if self.colonne == LARGEUR {
                    self.nouvelle_ligne();
                }
                self.case(self.ligne, self.colonne, COULEUR << 8 | octet as u16);
                self.colonne += 1;
            }
        }
    }

    /// Place le curseur clignotant (dessiné par la carte, pas par nous)
    /// sur la prochaine case à écrire. Il se règle par deux registres du
    /// contrôleur CRT de la carte VGA, derrière les ports 0x3D4 (numéro du
    /// registre) et 0x3D5 (sa valeur) : 0x0E et 0x0F, octets haut et bas de
    /// la position, comptée en cases depuis le coin haut gauche.
    fn placer_curseur(&self) {
        let position = (self.ligne * LARGEUR + self.colonne.min(LARGEUR - 1)) as u16;
        // SAFETY : registres documentés du contrôleur CRT ; ils ne règlent
        // que la position du curseur.
        unsafe {
            port::ecrire(0x3D4, 0x0F);
            port::ecrire(0x3D5, position as u8);
            port::ecrire(0x3D4, 0x0E);
            port::ecrire(0x3D5, (position >> 8) as u8);
        }
    }
}

/// Le caractère de la page de code 437 (la police gravée dans la carte
/// VGA) qui correspond à un caractère Unicode. Rust manipule du texte en
/// UTF-8, la carte des octets de 0 à 255 : il faut traduire. On ne garde
/// que ce qu'un clavier français peut taper ; le reste devient un carré.
fn cp437(c: char) -> u8 {
    match c {
        '\n' | '\t' | '\u{8}' | ' '..='~' => c as u8,
        'ç' => 0x87, 'é' => 0x82, 'â' => 0x83, 'à' => 0x85, 'ê' => 0x88,
        'ë' => 0x89, 'è' => 0x8A, 'ï' => 0x8B, 'î' => 0x8C, 'ô' => 0x93,
        'û' => 0x96, 'ù' => 0x97, '£' => 0x9C, '§' => 0x15, 'µ' => 0xE6,
        '°' => 0xF8, '²' => 0xFD,
        _ => 0xFE,
    }
}

impl fmt::Write for Ecran {
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        for c in texte.chars() {
            self.ecrire_octet(cp437(c));
        }
        self.placer_curseur();
        Ok(())
    }
}
