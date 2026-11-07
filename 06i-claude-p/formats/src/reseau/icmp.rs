//! Les messages d'ICMP (RFC 792) : ce que se disent les machines d'IPv4 sur
//! le réseau lui-même. Un en-tête de 8 octets : le genre du message, son
//! code, une somme de contrôle qui couvre tout le message, et 4 octets dont
//! le sens dépend du genre (l'identifiant et le numéro d'un écho, la MTU
//! d'une « fragmentation nécessaire », l'octet fautif d'un « problème de
//! paramètre »). Puis les données : celles de l'écho, ou, pour une erreur,
//! le début du paquet qui l'a provoquée (son en-tête IPv4 et au moins 8
//! octets de ce qu'il portait : de quoi retrouver la socket qui l'a envoyé).

use super::{Erreur, adresse, mot16, plier, somme};

/// La taille de l'en-tête.
pub const ENTETE: usize = 8;

// Les genres de messages, et ceux qui sont des erreurs (`icmp_pointers` :
// on ne répond jamais à une erreur par une erreur).
pub const ECHO_REPONSE: u8 = 0;
pub const INJOIGNABLE: u8 = 3;
pub const ETOUFFEMENT: u8 = 4;
pub const REDIRECTION: u8 = 5;
pub const ECHO: u8 = 8;
pub const TEMPS_DEPASSE: u8 = 11;
pub const PARAMETRE: u8 = 12;
pub const HORODATAGE: u8 = 13;
pub const HORODATAGE_REPONSE: u8 = 14;
pub const ADRESSE: u8 = 17;
pub const ADRESSE_REPONSE: u8 = 18;
/// Le plus grand genre connu (NR_ICMP_TYPES).
pub const GENRE_MAX: u8 = 18;

// Les codes d'INJOIGNABLE.
pub const RESEAU: u8 = 0;
pub const HOTE: u8 = 1;
pub const PROTOCOLE: u8 = 2;
pub const PORT: u8 = 3;
pub const FRAGMENTATION: u8 = 4;
/// Le plus grand code d'INJOIGNABLE (NR_ICMP_UNREACH).
pub const INJOIGNABLE_MAX: u8 = 15;

/// Ce genre est-il une erreur (le `error` d'`icmp_pointers`) ? Tous le
/// sont, sauf l'écho et sa réponse, et les genres 13 à 18 (horodatage,
/// information, masque d'adresse, et leurs réponses) : Linux compte aussi
/// pour des erreurs les genres 1, 2, 6 et 7 (jamais attribués), 9 et 10
/// (annonce et sollicitation de routeur), à qui il ne répond donc jamais
/// par une erreur. Un genre inconnu en est une : « think about it », dit
/// Linux.
pub fn est_erreur(genre: u8) -> bool {
    !matches!(genre, ECHO_REPONSE | ECHO | HORODATAGE..=ADRESSE_REPONSE)
}

/// Un en-tête ICMP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp {
    pub genre: u8,
    pub code: u8,
    /// Les 4 octets qui dépendent du genre, tels quels.
    pub reste: [u8; 4],
}

impl Icmp {
    /// L'identifiant et le numéro d'un écho (ou de sa réponse).
    pub fn echo(&self) -> (u16, u16) {
        (u16::from_be_bytes([self.reste[0], self.reste[1]]), u16::from_be_bytes([self.reste[2], self.reste[3]]))
    }
}

/// Le reste d'un écho : son identifiant et son numéro.
pub fn reste_echo(identifiant: u16, numero: u16) -> [u8; 4] {
    let (i, n) = (identifiant.to_be_bytes(), numero.to_be_bytes());
    [i[0], i[1], n[0], n[1]]
}

/// Lit le message `o` (la charge d'un paquet IPv4), et rend ses données.
/// Dans l'ordre d'`icmp_rcv` : la somme d'abord (sur tout le message),
/// puis l'en-tête entier.
pub fn lire(o: &[u8]) -> Result<(Icmp, &[u8]), Erreur> {
    if plier(somme(o, 0)) != 0 {
        return Err(Erreur::Somme);
    }
    let e = o.get(..ENTETE).ok_or(Erreur::Tronque)?;
    let i = Icmp { genre: e[0], code: e[1], reste: [e[4], e[5], e[6], e[7]] };
    Ok((i, &o[ENTETE..]))
}

/// Écrit l'en-tête `i` au début de `o` (l'en-tête puis les données, déjà
/// en place), avec la somme de tout le message.
pub fn ecrire(o: &mut [u8], i: &Icmp) {
    o[0] = i.genre;
    o[1] = i.code;
    o[2..4].fill(0);
    o[4..8].copy_from_slice(&i.reste);
    let s = plier(somme(o, 0));
    o[2..4].copy_from_slice(&s.to_be_bytes());
}

/// Ce que dit d'elle-même la copie d'un paquet que porte une erreur : son
/// protocole, ses adresses, et où commence ce qu'il portait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interne {
    pub protocole: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    /// La longueur de son en-tête (options comprises).
    pub longueur_entete: usize,
}

/// Lit le début du paquet d'origine que portent les données `o` d'une
/// erreur, comme `icmp_unreach` : un en-tête IPv4 d'au moins 20 octets,
/// une longueur d'en-tête d'au moins 5 mots, puis l'en-tête entier et 8
/// octets de ce qu'il portait (les ports d'UDP, l'identifiant d'un écho).
/// Rien d'autre n'est vérifié : la copie est coupée (sa longueur totale ne
/// tient pas), et sa somme n'importe pas.
pub fn interne(o: &[u8]) -> Option<Interne> {
    let e = o.get(..super::ipv4::ENTETE)?;
    let longueur_entete = (e[0] & 0x0F) as usize * 4;
    if longueur_entete < super::ipv4::ENTETE || o.len() < longueur_entete + 8 {
        return None;
    }
    Some(Interne { protocole: e[9], source: adresse(e, 12)?, destination: adresse(e, 16)?, longueur_entete })
}

/// Les ports (source, destination) de l'en-tête UDP qui suit l'en-tête
/// d'origine `i` dans `o`.
pub fn ports(o: &[u8], i: &Interne) -> Option<(u16, u16)> {
    Some((mot16(o, i.longueur_entete)?, mot16(o, i.longueur_entete + 2)?))
}
