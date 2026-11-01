//! L'en-tête d'IPv4 (RFC 791) : 20 octets, plus des options (jusqu'à 40) :
//! la version (4), la longueur de l'en-tête en mots de 32 bits (IHL), le
//! type de service, la longueur totale du paquet, l'identifiant et les
//! drapeaux de fragmentation, la durée de vie (TTL), le protocole de ce qui
//! suit (1 ICMP, 6 TCP, 17 UDP), la somme de contrôle de l'en-tête, et les
//! adresses de la source et de la destination.

use super::{Erreur, adresse, mot16, plier, somme};

/// La taille de l'en-tête sans options (le seul que nous écrivons).
pub const ENTETE: usize = 20;
/// Les protocoles.
pub const ICMP: u8 = 1;
pub const UDP: u8 = 17;
/// L'adresse de diffusion limitée : tout le réseau local.
pub const DIFFUSION: [u8; 4] = [255; 4];
/// L'adresse « pas encore d'adresse » (la source d'un DHCP DISCOVER).
pub const AUCUNE: [u8; 4] = [0; 4];

/// Les bits de drapeaux du mot de fragmentation.
const NE_PAS_FRAGMENTER: u16 = 0x4000;
const FRAGMENTS_SUIVANTS: u16 = 0x2000;
const DECALAGE: u16 = 0x1FFF;

/// Un en-tête IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4 {
    pub tos: u8,
    /// La longueur de tout le paquet, en-tête compris.
    pub longueur: u16,
    pub identifiant: u16,
    /// DF : le paquet ne doit pas être fragmenté en chemin.
    pub ne_pas_fragmenter: bool,
    /// MF : d'autres fragments suivent.
    pub fragments_suivants: bool,
    /// La place du fragment dans le paquet d'origine, en unités de 8 octets.
    pub decalage: u16,
    pub ttl: u8,
    pub protocole: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    /// La longueur de l'en-tête, options comprises.
    pub longueur_entete: usize,
}

impl Ipv4 {
    /// Est-ce un fragment (un morceau d'un paquet plus grand) ?
    pub fn est_un_fragment(&self) -> bool {
        self.fragments_suivants || self.decalage != 0
    }
}

/// Lit l'en-tête au début de `o`, et rend sa charge (de la fin de l'en-tête
/// à la longueur totale : le bourrage d'Ethernet au-delà est ôté). Les
/// vérifications dans l'ordre d'`ip_rcv_core` : 20 octets au moins, la
/// version 4 et une longueur d'en-tête d'au moins 5 mots, l'en-tête entier
/// présent, sa somme, puis une longueur totale qui tient dans ce qui a été
/// reçu et couvre l'en-tête.
pub fn lire(o: &[u8]) -> Result<(Ipv4, &[u8]), Erreur> {
    let debut = o.get(..ENTETE).ok_or(Erreur::Tronque)?;
    let ihl = (debut[0] & 0x0F) as usize;
    if debut[0] >> 4 != 4 || ihl < 5 {
        return Err(Erreur::Invalide);
    }
    let longueur_entete = ihl * 4;
    let entete = o.get(..longueur_entete).ok_or(Erreur::Tronque)?;
    if plier(somme(entete, 0)) != 0 {
        return Err(Erreur::Somme);
    }
    let longueur = mot16(entete, 2).ok_or(Erreur::Tronque)?;
    if (longueur as usize) > o.len() {
        return Err(Erreur::Tronque);
    }
    if (longueur as usize) < longueur_entete {
        return Err(Erreur::Invalide);
    }
    let fragment = mot16(entete, 6).ok_or(Erreur::Tronque)?;
    let h = Ipv4 {
        tos: entete[1],
        longueur,
        identifiant: mot16(entete, 4).ok_or(Erreur::Tronque)?,
        ne_pas_fragmenter: fragment & NE_PAS_FRAGMENTER != 0,
        fragments_suivants: fragment & FRAGMENTS_SUIVANTS != 0,
        decalage: fragment & DECALAGE,
        ttl: entete[8],
        protocole: entete[9],
        source: adresse(entete, 12).ok_or(Erreur::Tronque)?,
        destination: adresse(entete, 16).ok_or(Erreur::Tronque)?,
        longueur_entete,
    };
    Ok((h, &o[longueur_entete..longueur as usize]))
}

/// Écrit l'en-tête `h` (sans options : `longueur_entete` est ignoré) dans
/// les 20 premiers octets de `o`, sa somme comprise.
pub fn ecrire(o: &mut [u8; ENTETE], h: &Ipv4) {
    o[0] = 0x45;
    o[1] = h.tos;
    o[2..4].copy_from_slice(&h.longueur.to_be_bytes());
    o[4..6].copy_from_slice(&h.identifiant.to_be_bytes());
    let fragment = (h.decalage & DECALAGE)
        | if h.ne_pas_fragmenter { NE_PAS_FRAGMENTER } else { 0 }
        | if h.fragments_suivants { FRAGMENTS_SUIVANTS } else { 0 };
    o[6..8].copy_from_slice(&fragment.to_be_bytes());
    o[8] = h.ttl;
    o[9] = h.protocole;
    o[10..12].fill(0);
    o[12..16].copy_from_slice(&h.source);
    o[16..20].copy_from_slice(&h.destination);
    let s = plier(somme(o, 0));
    o[10..12].copy_from_slice(&s.to_be_bytes());
}

/// Une adresse de multidiffusion (224.0.0.0/4, la « classe D »).
pub fn multidiffusion(a: [u8; 4]) -> bool {
    a[0] & 0xF0 == 0xE0
}

/// Une adresse de la boucle locale (127.0.0.0/8).
pub fn boucle(a: [u8; 4]) -> bool {
    a[0] == 127
}

/// Le masque d'un préfixe de `bits` bits (24 : 255.255.255.0).
pub fn masque(bits: u8) -> [u8; 4] {
    let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits.min(32) as u32) };
    m.to_be_bytes()
}

/// La longueur du préfixe d'un masque (255.255.255.0 : 24), s'il est fait
/// de 1 puis de 0.
pub fn prefixe(masque: [u8; 4]) -> Option<u8> {
    let m = u32::from_be_bytes(masque);
    let bits = m.leading_ones();
    (m.checked_shl(bits).unwrap_or(0) == 0).then_some(bits as u8)
}

/// `a` est-elle dans le réseau `reseau`/`bits` ?
pub fn dans(a: [u8; 4], reseau: [u8; 4], bits: u8) -> bool {
    let m = u32::from_be_bytes(masque(bits));
    u32::from_be_bytes(a) & m == u32::from_be_bytes(reseau) & m
}
