//! Les en-têtes des trames du réseau (6g) : Ethernet, ARP, IPv4, UDP, et
//! les messages de DHCP.
//!
//! Une trame reçue vient du dehors : n'importe qui sur le réseau peut
//! l'avoir fabriquée pour faire lire le noyau hors du tampon, ou le faire
//! boucler. Chaque longueur lue dans un en-tête est donc bornée par ce qui a
//! été reçu, avant de s'en servir, ici, sans `unsafe`, et testé sur l'hôte
//! avec de vraies trames de QEMU et des milliers de mutations. Les mêmes
//! fonctions écrivent les en-têtes à émettre, et leurs sommes de contrôle.
//!
//! Les nombres des en-têtes sont en gros-boutiste (l'« ordre du réseau ») :
//! le premier octet est le plus fort. Une adresse IPv4 est gardée comme ses
//! quatre octets, dans cet ordre ([10, 0, 2, 15] pour 10.0.2.15).

pub mod arp;
pub mod dhcp;
pub mod ethernet;
pub mod ipv4;
pub mod udp;

use core::fmt;

/// Pourquoi un en-tête est refusé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Moins d'octets que l'en-tête, ou que ce que dit son champ de
    /// longueur.
    Tronque,
    /// Une version, une longueur d'en-tête, une valeur impossible.
    Invalide,
    /// La somme de contrôle est fausse.
    Somme,
}

// Affichés par le noyau : sans accents.
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Erreur::Tronque => "trame tronquee",
            Erreur::Invalide => "en-tete invalide",
            Erreur::Somme => "mauvaise somme de controle",
        })
    }
}

/// Un mot de 16 bits gros-boutiste à la position `i`.
pub(crate) fn mot16(o: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(o.get(i..i + 2)?.try_into().ok()?))
}

/// Un mot de 32 bits gros-boutiste à la position `i`.
pub(crate) fn mot32(o: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(o.get(i..i + 4)?.try_into().ok()?))
}

/// Quatre octets à la position `i` (une adresse IPv4).
pub(crate) fn adresse(o: &[u8], i: usize) -> Option<[u8; 4]> {
    o.get(i..i + 4)?.try_into().ok()
}

/// La somme de l'Internet (RFC 1071), pas encore pliée : chaque mot de 16
/// bits ajouté à `depart` (un octet seul à la fin compte comme l'octet fort
/// d'un mot). Plusieurs morceaux s'additionnent (le pseudo-en-tête d'UDP,
/// puis l'en-tête, puis les données), tant que chacun sauf le dernier est
/// de longueur paire.
pub fn somme(o: &[u8], depart: u32) -> u32 {
    let mut s = depart as u64;
    let mut mots = o.chunks_exact(2);
    for m in &mut mots {
        s += u16::from_be_bytes([m[0], m[1]]) as u64;
    }
    if let [dernier] = mots.remainder() {
        s += (*dernier as u64) << 8;
    }
    // Replier les retenues dans 32 bits (u64 : aucun débordement possible
    // avant 2^48 octets).
    while s > 0xFFFF_FFFF {
        s = (s & 0xFFFF_FFFF) + (s >> 32);
    }
    s as u32
}

/// La somme de contrôle finale : la somme repliée sur 16 bits, en
/// complément à un (le `csum_fold` de Linux). Un en-tête juste a une somme
/// (somme de contrôle comprise) qui se plie en 0.
pub fn plier(s: u32) -> u16 {
    let mut s = s;
    while s > 0xFFFF {
        s = (s & 0xFFFF) + (s >> 16);
    }
    !(s as u16)
}

/// Une adresse IPv4 à afficher, comme `ip addr` : 10.0.2.15.
pub struct Ipv4Affichee(pub [u8; 4]);

impl fmt::Display for Ipv4Affichee {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let a = self.0;
        write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3])
    }
}
