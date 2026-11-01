//! L'en-tête d'une trame Ethernet (IEEE 802.3, « Ethernet II ») : 14 octets,
//! l'adresse MAC de destination, celle de la source, et la sorte de ce qui
//! suit (l'EtherType : 0x0800 pour IPv4, 0x0806 pour ARP). La carte ajoute
//! et retire elle-même le préambule et le code de contrôle (CRC) : ils
//! n'existent pas pour nous.

use super::{Erreur, mot16};

/// La taille de l'en-tête.
pub const ENTETE: usize = 14;
/// Les sortes de ce que porte une trame.
pub const IPV4: u16 = 0x0800;
pub const ARP: u16 = 0x0806;
/// La plus petite trame (sans le CRC) : une plus courte est complétée par
/// des zéros (le « bourrage »), à retirer d'après la longueur d'IP.
pub const TRAME_MIN: usize = 60;
/// L'adresse de diffusion : toutes les cartes du réseau.
pub const DIFFUSION: [u8; 6] = [0xff; 6];

/// Un en-tête Ethernet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ethernet {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub genre: u16,
}

impl Ethernet {
    /// La destination est-elle un groupe (bit 0 du premier octet : la
    /// diffusion, la multidiffusion) ?
    pub fn vers_un_groupe(&self) -> bool {
        self.destination[0] & 1 != 0
    }
}

/// Lit l'en-tête au début de `o`, et rend ce qui le suit.
pub fn lire(o: &[u8]) -> Result<(Ethernet, &[u8]), Erreur> {
    let e = o.get(..ENTETE).ok_or(Erreur::Tronque)?;
    let mut destination = [0u8; 6];
    let mut source = [0u8; 6];
    destination.copy_from_slice(&e[..6]);
    source.copy_from_slice(&e[6..12]);
    let genre = mot16(e, 12).ok_or(Erreur::Tronque)?;
    Ok((Ethernet { destination, source, genre }, &o[ENTETE..]))
}

/// Écrit l'en-tête `e` dans les 14 premiers octets de `o`.
pub fn ecrire(o: &mut [u8; ENTETE], e: &Ethernet) {
    o[..6].copy_from_slice(&e.destination);
    o[6..12].copy_from_slice(&e.source);
    o[12..].copy_from_slice(&e.genre.to_be_bytes());
}
