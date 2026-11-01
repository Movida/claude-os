//! Les messages d'ARP (RFC 826) pour IPv4 sur Ethernet : 28 octets après
//! l'en-tête Ethernet. Le type de matériel (1 : Ethernet), le protocole
//! (0x0800 : IPv4), la longueur de leurs adresses (6 et 4), l'opération
//! (1 : requête, « qui a cette adresse ? » ; 2 : réponse, « c'est moi »),
//! puis l'émetteur (son adresse matérielle, son adresse IPv4) et la cible.

use super::{Erreur, adresse, mot16};

/// La taille d'un message.
pub const TAILLE: usize = 28;
pub const REQUETE: u16 = 1;
pub const REPONSE: u16 = 2;

/// Un message ARP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub operation: u16,
    pub mac_emetteur: [u8; 6],
    pub ip_emetteur: [u8; 4],
    pub mac_cible: [u8; 6],
    pub ip_cible: [u8; 4],
}

/// Lit le message au début de `o` (la charge d'une trame Ethernet de sorte
/// ARP). Comme `arp_process` : seulement Ethernet (le type de matériel 1,
/// ou 6, IEEE 802, qu'une interface Ethernet de Linux accepte aussi) et
/// IPv4, avec leurs longueurs d'adresses ; une autre opération est rendue
/// telle quelle (l'appelant l'ignore).
pub fn lire(o: &[u8]) -> Result<Arp, Erreur> {
    let m = o.get(..TAILLE).ok_or(Erreur::Tronque)?;
    if !matches!(mot16(m, 0), Some(1 | 6)) || mot16(m, 2) != Some(0x0800) || m[4] != 6 || m[5] != 4 {
        return Err(Erreur::Invalide);
    }
    let mac = |i: usize| -> [u8; 6] { let mut a = [0u8; 6]; a.copy_from_slice(&m[i..i + 6]); a };
    Ok(Arp {
        operation: mot16(m, 6).ok_or(Erreur::Tronque)?,
        mac_emetteur: mac(8),
        ip_emetteur: adresse(m, 14).ok_or(Erreur::Tronque)?,
        mac_cible: mac(18),
        ip_cible: adresse(m, 24).ok_or(Erreur::Tronque)?,
    })
}

/// Écrit le message `a` dans les 28 premiers octets de `o`.
pub fn ecrire(o: &mut [u8; TAILLE], a: &Arp) {
    o[..8].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 0]);
    o[6..8].copy_from_slice(&a.operation.to_be_bytes());
    o[8..14].copy_from_slice(&a.mac_emetteur);
    o[14..18].copy_from_slice(&a.ip_emetteur);
    o[18..24].copy_from_slice(&a.mac_cible);
    o[24..28].copy_from_slice(&a.ip_cible);
}
