//! Les paquets : une trame et ses en-têtes, dans un tampon du noyau (le
//! `sk_buff` de Linux).
//!
//! Un paquet traverse les étages de la pile sans être recopié : à
//! l'émission, chaque étage AJOUTE son en-tête devant (UDP, puis IP, puis
//! Ethernet), dans une MARGE laissée libre en tête du tampon (le
//! `skb_reserve` de Linux) ; à la réception, chaque étage RETIRE le sien
//! (le `skb_pull`) et passe le reste au suivant. Le tampon, et ses bornes
//! (début et fin des données).
//!
//! Tout ce qui le fabrique peut échouer sans paniquer : une trame reçue du
//! dehors, une rafale qui épuise la mémoire, ne doivent jamais arrêter le
//! noyau (`try_reserve`). Les bornes sont vérifiées à chaque ajout et à
//! chaque retrait : un en-tête plus long que ce qui reste est une erreur,
//! jamais une lecture hors du tampon.

use alloc::vec::Vec;

/// La marge laissée devant les données d'un paquet à émettre : de quoi
/// ajouter les en-têtes d'UDP (8 octets), d'IPv4 (20 à 60) et d'Ethernet
/// (14) sans recopier.
pub const MARGE: usize = 96;

pub struct Paquet {
    tampon: Vec<u8>,
    debut: usize,
    fin: usize,
}

impl Paquet {
    /// Un paquet vide, avec la marge pour ses en-têtes et la place pour
    /// `longueur` octets de données. None : plus de mémoire.
    pub fn vide(longueur: usize) -> Option<Paquet> {
        let mut tampon = Vec::new();
        tampon.try_reserve_exact(MARGE + longueur).ok()?;
        tampon.resize(MARGE + longueur, 0);
        Some(Paquet { tampon, debut: MARGE, fin: MARGE })
    }

    /// Une copie de la trame `octets` (reçue), sans marge.
    pub fn copie(octets: &[u8]) -> Option<Paquet> {
        let mut tampon = Vec::new();
        tampon.try_reserve_exact(octets.len()).ok()?;
        tampon.extend_from_slice(octets);
        Some(Paquet { tampon, debut: 0, fin: octets.len() })
    }

    /// Les données.
    pub fn donnees(&self) -> &[u8] {
        &self.tampon[self.debut..self.fin]
    }

    pub fn donnees_mut(&mut self) -> &mut [u8] {
        &mut self.tampon[self.debut..self.fin]
    }

    pub fn longueur(&self) -> usize {
        self.fin - self.debut
    }

    /// Ajoute `n` octets à la fin des données (le `skb_put`) : la place
    /// réservée à la création. None : il n'y en a plus.
    pub fn ajouter_fin(&mut self, n: usize) -> Option<&mut [u8]> {
        let fin = self.fin.checked_add(n).filter(|&f| f <= self.tampon.len())?;
        let debut = core::mem::replace(&mut self.fin, fin);
        Some(&mut self.tampon[debut..fin])
    }

    /// Ajoute un en-tête de `n` octets devant les données (le `skb_push`),
    /// dans la marge. None : la marge est épuisée.
    pub fn ajouter_entete(&mut self, n: usize) -> Option<&mut [u8]> {
        self.debut = self.debut.checked_sub(n)?;
        Some(&mut self.tampon[self.debut..self.debut + n])
    }

    /// Retire les `n` premiers octets des données (le `skb_pull`), et les
    /// rend. None : il y en a moins.
    pub fn retirer_entete(&mut self, n: usize) -> Option<&[u8]> {
        if n > self.longueur() {
            return None;
        }
        let debut = self.debut;
        self.debut += n;
        Some(&self.tampon[debut..debut + n])
    }
}
