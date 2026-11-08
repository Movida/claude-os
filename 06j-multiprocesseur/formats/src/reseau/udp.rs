//! L'en-tête d'UDP (RFC 768) : 8 octets, les ports de la source et de la
//! destination, la longueur (en-tête compris), et une somme de contrôle qui
//! couvre aussi un « pseudo-en-tête » d'IPv4 (les deux adresses, le
//! protocole, la longueur) : un datagramme arrivé à la mauvaise adresse est
//! refusé lui aussi. En IPv4, une somme nulle veut dire « pas de somme ».

use super::{Erreur, mot16, plier, somme};

/// La taille de l'en-tête.
pub const ENTETE: usize = 8;
/// La plus grande charge d'un datagramme UDP sur IPv4 : 65 535 moins
/// l'en-tête d'IPv4 (20) et celui d'UDP (8).
pub const CHARGE_MAX: usize = 65_507;

/// Un en-tête UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp {
    pub source: u16,
    pub destination: u16,
}

/// La somme du pseudo-en-tête d'IPv4.
fn pseudo(source: [u8; 4], destination: [u8; 4], longueur: u16) -> u32 {
    let mut p = [0u8; 12];
    p[..4].copy_from_slice(&source);
    p[4..8].copy_from_slice(&destination);
    p[9] = super::ipv4::UDP;
    p[10..].copy_from_slice(&longueur.to_be_bytes());
    somme(&p, 0)
}

/// Lit le datagramme `o` (la charge d'un paquet IPv4 de `source` vers
/// `destination`), et rend sa charge. Dans l'ordre d'`__udp4_lib_rcv` :
/// l'en-tête présent, une longueur qui tient dans le paquet et couvre
/// l'en-tête (le reste du paquet est ôté), puis la somme, si elle n'est pas
/// nulle.
pub fn lire(o: &[u8], source: [u8; 4], destination: [u8; 4]) -> Result<(Udp, &[u8]), Erreur> {
    let e = o.get(..ENTETE).ok_or(Erreur::Tronque)?;
    let longueur = mot16(e, 4).ok_or(Erreur::Tronque)? as usize;
    if longueur > o.len() || longueur < ENTETE {
        return Err(Erreur::Tronque);
    }
    let d = &o[..longueur];
    if mot16(e, 6) != Some(0) && plier(somme(d, pseudo(source, destination, longueur as u16))) != 0 {
        return Err(Erreur::Somme);
    }
    let u = Udp { source: mot16(e, 0).ok_or(Erreur::Tronque)?, destination: mot16(e, 2).ok_or(Erreur::Tronque)? };
    Ok((u, &d[ENTETE..]))
}

/// Écrit l'en-tête d'UDP au début de `o` (l'en-tête puis la charge, déjà
/// en place), avec sa somme. `o` fait au plus 65 535 octets (l'appelant l'a
/// vérifié).
pub fn ecrire(o: &mut [u8], u: &Udp, source: [u8; 4], destination: [u8; 4]) {
    let longueur = o.len() as u16;
    o[0..2].copy_from_slice(&u.source.to_be_bytes());
    o[2..4].copy_from_slice(&u.destination.to_be_bytes());
    o[4..6].copy_from_slice(&longueur.to_be_bytes());
    o[6..8].fill(0);
    // Une somme qui vaut 0 s'écrit 0xFFFF (le même nombre en complément à
    // un) : 0 voudrait dire « pas de somme ».
    let s = match plier(somme(o, pseudo(source, destination, longueur))) {
        0 => 0xFFFF,
        s => s,
    };
    o[6..8].copy_from_slice(&s.to_be_bytes());
}
