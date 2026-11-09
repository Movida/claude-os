//! Le client DHCP du démarrage, comme celui de Linux (net/ipv4/ipconfig.c,
//! le paramètre `ip=dhcp`) : une machine à états qui dit quoi envoyer, et
//! quand abandonner.
//!
//! L'échange (RFC 2131) : le client, qui n'a pas encore d'adresse, diffuse
//! un DISCOVER ; un serveur répond par une OFFER (une adresse, et la
//! configuration du réseau) ; le client la demande par un REQUEST (en
//! nommant le serveur choisi), et le serveur la confirme par un ACK. Comme
//! `ipconfig.c` : la première offre est prise (les autres ignorées tant
//! qu'elle est en cours), le REQUEST part aussitôt ; un NAK fait tout
//! oublier, et le prochain envoi redevient un DISCOVER ; une réponse n'est
//! prise que si elle porte notre identifiant de transaction et notre
//! adresse matérielle.
//!
//! Les délais de Linux : un premier délai de 2 s plus un hasard d'au plus
//! 1 s (tiré une fois), multiplié par 7/4 à chaque nouvel envoi, jusqu'à
//! 30 s. Linux fait six envois avant d'abandonner ; nous trois (2 + 3,5 +
//! 6,1 s environ, entre 11,6 et 17,4 s avec le hasard) : le démarrage
//! attend la fin du DHCP, et les programmes de test avec lui. Linux ne
//! renouvelle pas le bail (la machine démarre, et garde son adresse) :
//! nous non plus.
//!
//! Le bail, comme `ic_bootp_recv` et `ic_defaults` : sans masque, celui de
//! la classe de l'adresse (A, B, C ; /32 en classe E ; une adresse de
//! multidiffusion, la classe D, est refusée : « Unable to guess
//! netmask ») ; sans passerelle, le relais (giaddr) s'il y en a un ; une
//! passerelle hors du réseau reçu est refusée, et toute la configuration
//! avec (`ic_setup_routes`) ; sans DNS, le serveur de l'amorçage (siaddr),
//! que Linux montre aussi comme « bootserver ». Un écart : nous gardons les
//! valeurs de l'ACK (ce que demande la RFC 2131), Linux celles de l'offre,
//! l'ACK ne remplissant que ce qui manquait ; un serveur honnête donne les
//! mêmes.
//!
//! Rien ici ne lit l'horloge : l'heure est donnée en nanosecondes, depuis
//! n'importe quelle origine (le noyau donne son horloge monotone).

use formats::reseau::dhcp::{self, Message};
use formats::reseau::ipv4;

/// Les délais (en nanosecondes).
pub const DELAI_BASE: u64 = 2_000_000_000;
pub const HASARD_MAX: u64 = 1_000_000_000;
pub const DELAI_MAX: u64 = 30_000_000_000;
/// Le nombre d'envois à vide avant d'abandonner.
pub const ESSAIS: u32 = 3;
/// Le nombre maximal de serveurs DNS gardés (CONF_NAMESERVERS_MAX).
pub const SERVEURS_DNS: usize = 3;
/// La longueur maximale du nom de domaine gardé.
pub const DOMAINE_MAX: usize = 64;

/// La configuration reçue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bail {
    pub adresse: [u8; 4],
    pub prefixe: u8,
    pub passerelle: Option<[u8; 4]>,
    pub dns: [Option<[u8; 4]>; SERVEURS_DNS],
    /// Le serveur DHCP qui l'a donné (option 54), et le serveur de
    /// l'amorçage (siaddr : le « bootserver » de /proc/net/pnp).
    pub serveur: [u8; 4],
    pub amorce: [u8; 4],
    /// La durée du bail, en secondes (option 51).
    pub duree: Option<u32>,
    pub mtu: Option<u16>,
    domaine: [u8; DOMAINE_MAX],
    longueur_domaine: usize,
}

impl Bail {
    /// Le nom de domaine (option 15), s'il y en a un.
    pub fn domaine(&self) -> Option<&[u8]> {
        (self.longueur_domaine > 0).then(|| &self.domaine[..self.longueur_domaine])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etat {
    /// Le DISCOVER est parti, on attend une offre.
    Decouverte,
    /// Une offre est prise : le REQUEST est parti, on attend l'ACK.
    Demande { offre: [u8; 4], serveur: [u8; 4] },
    /// Configuré, ou abandonné.
    Fini,
}

/// Ce que doit faire le noyau après un message ou une échéance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evenement {
    /// Rien de neuf.
    Rien,
    /// Envoyer le message du moment (`message`).
    Envoyer,
    /// L'adresse est obtenue.
    Configure(Bail),
    /// Un bail inutilisable : pas d'adresse (Linux abandonne de même).
    Refuse(Refus),
    /// Pas de réponse : l'interface reste sans adresse.
    Abandon,
}

/// Pourquoi un bail est refusé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Sans masque, une adresse de multidiffusion n'a pas de classe.
    Masque,
    /// La passerelle n'est pas sur le réseau reçu.
    Passerelle,
}

/// Le client de l'interface d'adresse matérielle `mac`.
pub struct Client {
    mac: [u8; 6],
    xid: u32,
    etat: Etat,
    debut: u64,
    delai: u64,
    echeance: u64,
    envois: u32,
}

impl Client {
    /// Un client qui commence maintenant : son premier message (un
    /// DISCOVER) est à envoyer tout de suite. `xid` et `hasard` viennent du
    /// générateur du noyau.
    pub fn new(mac: [u8; 6], xid: u32, hasard: u64, maintenant: u64) -> Client {
        let delai = DELAI_BASE + hasard % HASARD_MAX;
        Client { mac, xid, etat: Etat::Decouverte, debut: maintenant, delai, echeance: maintenant + delai, envois: 1 }
    }

    /// Le message à envoyer maintenant (un DISCOVER, ou un REQUEST pour
    /// l'offre prise), dans `o` (la charge du datagramme UDP).
    pub fn message(&self, maintenant: u64, o: &mut [u8; dhcp::TAILLE]) {
        let secondes = ((maintenant.saturating_sub(self.debut)) / 1_000_000_000).min(u16::MAX as u64) as u16;
        match self.etat {
            Etat::Demande { offre, serveur } => {
                dhcp::ecrire_requete(o, dhcp::REQUEST, self.xid, secondes, self.mac, Some(offre), Some(serveur))
            }
            _ => dhcp::ecrire_requete(o, dhcp::DISCOVER, self.xid, secondes, self.mac, None, None),
        }
    }

    /// L'échéance (le prochain envoi, ou l'abandon) ; None : fini.
    pub fn echeance(&self) -> Option<u64> {
        (self.etat != Etat::Fini).then_some(self.echeance)
    }

    /// Le temps passe : à l'échéance, envoyer de nouveau (le délai
    /// allongé), ou abandonner après `ESSAIS` envois sans réponse.
    pub fn temps(&mut self, maintenant: u64) -> Evenement {
        if self.etat == Etat::Fini || maintenant < self.echeance {
            return Evenement::Rien;
        }
        if self.envois >= ESSAIS {
            self.etat = Etat::Fini;
            return Evenement::Abandon;
        }
        self.envois += 1;
        self.delai = (self.delai * 7 / 4).min(DELAI_MAX);
        self.echeance = maintenant + self.delai;
        Evenement::Envoyer
    }

    /// Un datagramme est arrivé sur le port 68 (sa charge : un message de
    /// DHCP, peut-être).
    pub fn recu(&mut self, charge: &[u8], maintenant: u64) -> Evenement {
        let Ok(m) = dhcp::lire(charge) else { return Evenement::Rien };
        if !m.reponse || m.xid != self.xid || m.client != self.mac {
            return Evenement::Rien;
        }
        match (self.etat, m.sorte()) {
            (Etat::Decouverte, Some(dhcp::OFFER)) => {
                let Some(serveur) = m.adresse_option(dhcp::SERVEUR) else { return Evenement::Rien };
                self.etat = Etat::Demande { offre: m.adresse, serveur };
                // Le REQUEST part aussitôt, et attend le délai en cours.
                self.echeance = maintenant + self.delai;
                Evenement::Envoyer
            }
            (Etat::Demande { offre, serveur }, Some(dhcp::ACK)) if m.adresse == offre => {
                self.etat = Etat::Fini;
                match bail(&m, serveur) {
                    Ok(b) => Evenement::Configure(b),
                    Err(r) => Evenement::Refuse(r),
                }
            }
            (Etat::Demande { .. }, Some(dhcp::NAK)) => {
                // Tout oublier : le prochain envoi est un DISCOVER.
                self.etat = Etat::Decouverte;
                Evenement::Rien
            }
            _ => Evenement::Rien,
        }
    }
}

/// Le masque d'une adresse sans option de masque : celui de sa classe
/// (`ic_defaults`) : A, B, C, et /32 en classe E ; None pour la classe D.
fn prefixe_de_classe(a: [u8; 4]) -> Option<u8> {
    match a[0] {
        0..=127 => Some(8),
        128..=191 => Some(16),
        192..=223 => Some(24),
        224..=239 => None,
        _ => Some(32),
    }
}

/// La configuration que donne l'ACK `m` (voir l'en-tête).
fn bail(m: &Message, serveur: [u8; 4]) -> Result<Bail, Refus> {
    let prefixe = match m.adresse_option(dhcp::MASQUE).and_then(ipv4::prefixe) {
        Some(p) => p,
        None => prefixe_de_classe(m.adresse).ok_or(Refus::Masque)?,
    };
    let passerelle = m.adresse_option(dhcp::PASSERELLES).or((m.relais != ipv4::AUCUNE).then_some(m.relais));
    if let Some(p) = passerelle {
        if !ipv4::dans(p, m.adresse, prefixe) {
            return Err(Refus::Passerelle);
        }
    }
    let mut dns = [None; SERVEURS_DNS];
    if let Some(v) = m.option(dhcp::DNS) {
        for (place, a) in dns.iter_mut().zip(v.chunks_exact(4)) {
            *place = a.try_into().ok();
        }
    } else {
        dns[0] = Some(m.serveur_suivant);
    }
    let mut domaine = [0u8; DOMAINE_MAX];
    let mut longueur_domaine = 0;
    if let Some(d) = m.option(dhcp::DOMAINE) {
        longueur_domaine = d.len().min(DOMAINE_MAX);
        domaine[..longueur_domaine].copy_from_slice(&d[..longueur_domaine]);
    }
    Ok(Bail {
        adresse: m.adresse,
        prefixe,
        passerelle,
        dns,
        serveur,
        amorce: m.serveur_suivant,
        duree: m.option(dhcp::BAIL).and_then(|v| Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))),
        mtu: m.option(dhcp::MTU).and_then(|v| Some(u16::from_be_bytes(v.get(..2)?.try_into().ok()?))),
        domaine,
        longueur_domaine,
    })
}
