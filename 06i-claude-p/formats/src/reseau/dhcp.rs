//! Les messages de DHCP (RFC 2131 et 2132), portés par UDP (le client sur
//! le port 68, le serveur sur le port 67).
//!
//! Un message de DHCP est un message de BOOTP (1985) : une partie fixe de
//! 236 octets (l'opération, requête ou réponse ; l'identifiant de
//! transaction que choisit le client ; l'adresse proposée, « your IP » ;
//! l'adresse matérielle du client...), le « cookie magique » 99.130.83.99,
//! puis des OPTIONS : un code, une longueur, la valeur (53 : la sorte du
//! message ; 1 : le masque du réseau ; 3 : les passerelles ; 6 : les
//! serveurs DNS ; 51 : la durée du bail...). Le code 0 bourre, 255 finit.
//! Comme Linux (`ipconfig.c`), le client envoie des messages de 576 octets
//! avec leurs en-têtes (le plus petit datagramme qu'un serveur doive
//! accepter) : 236 de partie fixe, et 312 d'options.

use super::{Erreur, adresse, mot32};

/// Les ports.
pub const PORT_SERVEUR: u16 = 67;
pub const PORT_CLIENT: u16 = 68;
/// La partie fixe, le cookie, et la place des options d'un message que
/// nous écrivons.
pub const FIXE: usize = 236;
const COOKIE: [u8; 4] = [99, 130, 83, 99];
pub const OPTIONS: usize = 312;
/// La taille d'un message que nous écrivons.
pub const TAILLE: usize = FIXE + OPTIONS;

/// Les opérations de BOOTP.
const REQUETE: u8 = 1;
const REPONSE: u8 = 2;

/// Les sortes de messages (option 53).
pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;

/// Les options lues.
pub const MASQUE: u8 = 1;
pub const PASSERELLES: u8 = 3;
pub const DNS: u8 = 6;
pub const DOMAINE: u8 = 15;
pub const MTU: u8 = 26;
pub const ADRESSE_DEMANDEE: u8 = 50;
pub const BAIL: u8 = 51;
pub const SORTE: u8 = 53;
pub const SERVEUR: u8 = 54;
pub const PARAMETRES: u8 = 55;
const BOURRAGE: u8 = 0;
const FIN: u8 = 255;

/// Un message reçu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub reponse: bool,
    pub xid: u32,
    /// L'adresse proposée au client (« your IP »).
    pub adresse: [u8; 4],
    /// Le serveur suivant de l'amorçage (« siaddr », celui de TFTP), et le
    /// relais par lequel la réponse est passée (« giaddr »).
    pub serveur_suivant: [u8; 4],
    pub relais: [u8; 4],
    /// L'adresse matérielle du client (les 6 premiers octets de `chaddr`
    /// pour Ethernet).
    pub client: [u8; 6],
    options: &'a [u8],
}

/// Lit le message au début de `o` (la charge d'un datagramme UDP).
pub fn lire(o: &[u8]) -> Result<Message<'_>, Erreur> {
    let fixe = o.get(..FIXE + 4).ok_or(Erreur::Tronque)?;
    if fixe[FIXE..] != COOKIE || !(fixe[0] == REQUETE || fixe[0] == REPONSE) {
        return Err(Erreur::Invalide);
    }
    let mut client = [0u8; 6];
    client.copy_from_slice(&fixe[28..34]);
    Ok(Message {
        reponse: fixe[0] == REPONSE,
        xid: mot32(fixe, 4).ok_or(Erreur::Tronque)?,
        adresse: adresse(fixe, 16).ok_or(Erreur::Tronque)?,
        serveur_suivant: adresse(fixe, 20).ok_or(Erreur::Tronque)?,
        relais: adresse(fixe, 24).ok_or(Erreur::Tronque)?,
        client,
        options: &o[FIXE + 4..],
    })
}

impl<'a> Message<'a> {
    /// Les options, dans l'ordre : (code, valeur). Le parcours s'arrête à
    /// l'option FIN, ou sur une option qui déborde.
    pub fn options(&self) -> impl Iterator<Item = (u8, &'a [u8])> + 'a {
        let mut reste = self.options;
        core::iter::from_fn(move || loop {
            let (&code, suite) = reste.split_first()?;
            match code {
                BOURRAGE => reste = suite,
                FIN => return None,
                _ => {
                    let (&n, suite) = suite.split_first()?;
                    let Some(valeur) = suite.get(..n as usize) else {
                        reste = &[];
                        return None;
                    };
                    reste = &suite[n as usize..];
                    return Some((code, valeur));
                }
            }
        })
    }

    /// La valeur de la première option `code`.
    pub fn option(&self, code: u8) -> Option<&'a [u8]> {
        self.options().find(|&(c, _)| c == code).map(|(_, v)| v)
    }

    /// La sorte du message (option 53).
    pub fn sorte(&self) -> Option<u8> {
        self.option(SORTE).and_then(|v| v.first().copied())
    }

    /// La première adresse de l'option `code` (4 octets au moins).
    pub fn adresse_option(&self, code: u8) -> Option<[u8; 4]> {
        self.option(code).and_then(|v| v.get(..4)?.try_into().ok())
    }
}

/// Écrit dans `o` (TAILLE octets) une requête du client : `sorte`
/// (DISCOVER ou REQUEST), d'identifiant `xid`, `secondes` après le début de
/// l'échange, de l'adresse matérielle `mac` ; pour un REQUEST, l'adresse
/// demandée (50) et le serveur choisi (54). Les paramètres demandés (55) :
/// ceux que lit notre client. Le drapeau BROADCAST n'est pas posé (comme
/// `ipconfig.c`) : le serveur peut répondre en diffusion ou à l'adresse
/// offerte.
pub fn ecrire_requete(o: &mut [u8; TAILLE], sorte: u8, xid: u32, secondes: u16, mac: [u8; 6],
                      demandee: Option<[u8; 4]>, serveur: Option<[u8; 4]>) {
    o.fill(0);
    o[0] = REQUETE;
    // Ethernet : type de matériel 1, adresses de 6 octets.
    o[1] = 1;
    o[2] = 6;
    o[4..8].copy_from_slice(&xid.to_be_bytes());
    o[8..10].copy_from_slice(&secondes.to_be_bytes());
    o[28..34].copy_from_slice(&mac);
    let mut options = [0u8; OPTIONS];
    options[..4].copy_from_slice(&COOKIE);
    let mut i = 4;
    let mut ajouter = |code: u8, valeur: &[u8]| {
        options[i] = code;
        options[i + 1] = valeur.len() as u8;
        options[i + 2..i + 2 + valeur.len()].copy_from_slice(valeur);
        i += 2 + valeur.len();
    };
    ajouter(SORTE, &[sorte]);
    if let Some(a) = demandee {
        ajouter(ADRESSE_DEMANDEE, &a);
    }
    if let Some(s) = serveur {
        ajouter(SERVEUR, &s);
    }
    ajouter(PARAMETRES, &[MASQUE, PASSERELLES, DNS, DOMAINE, MTU]);
    options[i] = FIN;
    o[FIXE..].copy_from_slice(&options);
}
