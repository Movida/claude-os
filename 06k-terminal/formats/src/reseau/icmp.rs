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
/// L'écho étendu (PROBE, RFC 8335 : « cette interface est-elle là ? ») et sa
/// réponse, au-delà de la table des genres connus.
pub const ECHO_ETENDU: u8 = 42;
pub const ECHO_ETENDU_REPONSE: u8 = 43;

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

/// Les extensions d'une erreur ICMP (RFC 4884) : un message d'erreur peut
/// porter, après la copie du paquet d'origine, des objets qui en disent
/// plus (l'interface d'arrivée d'un routeur, RFC 5837 ; une étiquette MPLS,
/// RFC 4950). L'octet 5 de l'en-tête dit alors la longueur de la copie, en
/// mots de 32 bits ; elle est complétée de zéros jusqu'à 128 octets au
/// moins, pour qu'un ancien programme qui ne connaît pas les extensions ne
/// les prenne pas pour la fin de son datagramme.
///
/// Avec IP_RECVERR_RFC4884, Linux dit dans le `ee_data` de l'erreur où
/// elles commencent dans ce que lit le programme, et si leur structure
/// tient : le programme les lit lui-même (Linux ne les interprète pas).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extensions {
    /// Leur position dans ce que lit le programme (la copie, moins les
    /// en-têtes d'origine qu'il ne voit pas).
    pub debut: u16,
    /// Leur structure est fausse (SO_EE_RFC4884_FLAG_INVALID) : une somme
    /// qui ne tombe pas juste, un objet coupé ou trop court.
    pub invalide: bool,
}

impl Extensions {
    /// Le `ee_data` de la `sock_extended_err`, lu par le programme comme un
    /// entier : c'est l'union `ee_rfc4884` (un u16 `len`, puis un octet
    /// `flags` et un octet réservé), petit-boutiste sur x86-64.
    pub fn ee_data(&self) -> u32 {
        self.debut as u32 | (self.invalide as u32) << 16
    }
}

/// Les extensions du message d'erreur `message` (le message ICMP entier,
/// en-tête compris, jusqu'à la fin du paquet), quand le programme lira ce
/// qui suit les `entetes` premiers octets de la copie d'origine (son
/// en-tête IPv4, plus celui d'UDP qu'il ne voit pas ; IPv4 seul pour un
/// écho, dont le programme lit l'en-tête ICMP d'origine). C'est
/// `ipv4_icmp_error_rfc4884` puis `ip_icmp_error_rfc4884` de Linux 6.18
/// (ip_sockglue.c, icmp.c) :
///
/// - seuls « destination injoignable », « temps dépassé » et « problème de
///   paramètre » en ont (la RFC 4884 les définit pour eux trois) ;
/// - une copie de moins de 128 octets (le minimum de la RFC), ou plus
///   courte que les en-têtes ôtés, n'a pas d'extensions : un message
///   d'avant la RFC a 0 à l'octet 5 (un champ « inutilisé ») ;
/// - leur en-tête (4 octets) doit tenir dans ce que lit le programme ;
/// - leur structure n'est vérifiée qu'en version 2 (la seule définie) :
///   une autre version les dit valides sans les lire, comme Linux.
///
/// Rien n'est rendu (None) quand il n'y en a pas : le `ee_data` reste nul.
/// Les erreurs mesurées sous Linux (une socket brute qui s'envoie les
/// messages par lo : formats/tests/reseau.rs, `icmp_rfc4884`) : leur somme,
/// un objet de moins de 4 octets, un objet qui dépasse la fin, et 1 à 3
/// octets après le dernier objet.
pub fn extensions_rfc4884(message: &[u8], entetes: usize) -> Option<Extensions> {
    if !matches!(*message.first()?, INJOIGNABLE | TEMPS_DEPASSE | PARAMETRE) {
        return None;
    }
    let longueur = *message.get(5)? as usize * 4;
    if longueur < 128 || longueur < entetes {
        return None;
    }
    let debut = longueur - entetes;
    let charge = message.get(ENTETE + entetes..)?;
    let extensions = charge.get(debut..).filter(|e| e.len() >= 4)?;
    // `debut` est d'au plus 255 × 4 octets : il tient dans un u16.
    Some(Extensions { debut: debut as u16, invalide: !extensions_valides(extensions) })
}

/// La structure des extensions `e` (au moins leur en-tête de 4 octets :
/// une version de 4 bits, 12 bits réservés, une somme sur 16 bits) tient-elle
/// (`ip_icmp_error_rfc4884_validate`) ? En version 2 : la somme de toutes
/// les extensions doit tomber juste, sauf si elle est nulle (« pas de
/// somme », permis par la RFC 4884, section 7) ; puis chaque objet a un
/// en-tête de 4 octets (sa longueur, en-tête compris, sur 16 bits, puis sa
/// classe et son genre), une longueur d'au moins 4, et finit dans le
/// message.
fn extensions_valides(e: &[u8]) -> bool {
    if e[0] >> 4 != 2 {
        return true;
    }
    if mot16(e, 2) != Some(0) && plier(somme(e, 0)) != 0 {
        return false;
    }
    let mut position = 4;
    while position < e.len() {
        // Un en-tête d'objet coupé : `skb_header_pointer` ne le trouve pas.
        let Some(longueur) = e.get(position..position + 4).and_then(|o| mot16(o, 0)) else {
            return false;
        };
        if longueur < 4 {
            return false;
        }
        position += longueur as usize;
        if position > e.len() {
            return false;
        }
    }
    true
}
