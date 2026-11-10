//! ICMP dans le noyau (net/ipv4/icmp.c) : répondre à l'écho, dire une
//! erreur à qui a envoyé un paquet qu'on ne peut pas livrer, et rendre aux
//! sockets les erreurs que le réseau nous dit.
//!
//! LA RÉCEPTION, dans l'ordre d'`icmp_rcv` : la somme, l'en-tête ; rien
//! de ce qui arrive en diffusion (Linux n'y accepte que l'écho et
//! l'horodatage, qu'il ignore par défaut, `icmp_echo_ignore_broadcasts` :
//! sinon une seule trame ferait répondre tout un réseau, l'attaque
//! « smurf »). Puis selon le genre : l'écho reçoit sa réponse ;
//! l'horodatage aussi (les millisecondes depuis minuit, temps universel) ;
//! la réponse à l'écho va à la socket de ping de son identifiant (ping.rs) ;
//! une erreur (injoignable, étouffement, redirection, temps dépassé,
//! problème de paramètre) va au protocole du paquet d'origine qu'elle
//! porte (UDP, ou ICMP pour un écho : ping.rs), qui retrouve la socket qui
//! l'avait envoyé, comme `icmp_unreach`. Le reste est ignoré.
//!
//! L'ENVOI D'UNE ERREUR, comme `__icmp_send` : jamais pour une trame reçue
//! en diffusion, un paquet en diffusion, un fragment autre que le premier,
//! ni pour une erreur ICMP (« a mess would result », dit Linux). Puis la
//! limite globale de Linux pour les erreurs (`icmp_msgs_per_sec` 1000 par
//! seconde, `icmp_msgs_burst` 50 d'un coup, les genres de `icmp_ratemask` :
//! injoignable sauf la fragmentation nécessaire, étouffement, temps
//! dépassé, problème de paramètre ; un crédit consommé de 0 à 2 au hasard,
//! pour qu'on ne devine pas ce qu'envoient les autres), sauf pour un paquet
//! arrivé par `lo`. Puis, si la limite globale s'appliquait, la limite par
//! destination (`icmpv4_xrlim_allow` : six d'un coup, puis une par seconde,
//! inet::pairs), sauf sur un chemin qui part par `lo` ; c'est seulement
//! quand elle aussi permet le message que le crédit global est consommé :
//! une machine qu'on fait taire ne prend rien aux autres. Le message part
//! de l'adresse visée si elle était à nous, sinon de celle de la route ; il
//! porte autant du paquet d'origine que tient en 576 octets (la RFC 1812).
//!
//! Les réponses (écho, horodatage) partent de l'adresse visée, sans DF,
//! comme toute émission de la socket ICMP de Linux (IP_PMTUDISC_DONT).
//! Linux les fait passer par les mêmes limites (`icmp_reply`), mais leurs
//! genres ne sont pas dans `icmp_ratemask` : aucune ne s'y applique.

use super::interface::Interface;
use super::ipv4::{self, Envoi};
use super::paquet::Paquet;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicU64, Ordering};
use formats::reseau::icmp::{self, Icmp, Interne};
use formats::reseau::ipv4 as format_ipv4;
use inet::pairs::Pairs;

/// Le crédit de la limite globale (`icmp_global_credit`) et l'instant où
/// il a été rempli (`icmp_global_stamp`, en millisecondes : notre tic).
struct Credit {
    credit: i32,
    remplie: u64,
}

static CREDIT: Verrou<Credit> = Verrou::new(Credit { credit: 0, remplie: 0 });

/// Les machines à qui l'on a envoyé une erreur, et leur seau (inet::pairs ;
/// le `net->ipv4.peers` de Linux).
static PAIRS: Verrou<Pairs> = Verrou::new(Pairs::new());

/// `icmp_msgs_per_sec` et `icmp_msgs_burst`.
const PAR_SECONDE: u64 = 1000;
const RAFALE: i32 = 50;

/// Les messages jetés : somme fausse ou tronqués ; refusés par la limite
/// globale (`ICMP_MIB_RATELIMITGLOBAL`), par celle d'une machine
/// (`ICMP_MIB_RATELIMITHOST`).
static FAUX: AtomicU64 = AtomicU64::new(0);
static LIMITES_GLOBALES: AtomicU64 = AtomicU64::new(0);
static LIMITES_PAR_MACHINE: AtomicU64 = AtomicU64::new(0);

fn ms() -> u64 {
    crate::temps::ns_monotone() / 1_000_000
}

/// Une erreur de ce genre est-elle soumise à la limite (`icmpv4_mask_allow`
/// et `icmp_ratemask`, 0x1818) ? La fragmentation nécessaire ne l'est
/// jamais (la découverte de la MTU d'un chemin en dépend).
fn limitee(genre: u8, code: u8) -> bool {
    if genre > icmp::GENRE_MAX || (genre == icmp::INJOIGNABLE && code == icmp::FRAGMENTATION) {
        return false;
    }
    matches!(genre, icmp::INJOIGNABLE | icmp::ETOUFFEMENT | icmp::TEMPS_DEPASSE | icmp::PARAMETRE)
}

/// La limite globale permet-elle un message de plus (`icmp_global_allow`) ?
/// Un crédit positif : oui. Sinon, s'il s'est passé au moins 20 ms (HZ/50)
/// depuis le dernier remplissage, le crédit gagne un message par
/// milliseconde écoulée (au plus une seconde), sans dépasser la rafale.
/// Rien n'est consommé ici : seulement quand la limite par destination
/// permet aussi le message (`consommer`).
fn permis() -> bool {
    let mut c = CREDIT.verrouiller();
    if c.credit <= 0 {
        let maintenant = ms();
        let ecoule = maintenant.saturating_sub(c.remplie).min(1000);
        if ecoule < 1000 / 50 {
            return false;
        }
        let gain = (PAR_SECONDE * ecoule / 1000) as i32;
        c.remplie = maintenant;
        c.credit = (c.credit + gain).min(RAFALE);
    }
    true
}

/// Le message part : il consomme de 0 à 2 crédits, tirés au hasard
/// (`icmp_global_consume`), pour qu'on ne devine pas ce qu'envoient les
/// autres ; le crédit peut devenir négatif.
fn consommer() {
    CREDIT.verrouiller().credit -= crate::aleatoire::u32_sous(3) as i32;
}

/// Les millisecondes depuis minuit, temps universel (`inet_current_timestamp`).
fn horodatage() -> u32 {
    let t = crate::temps::maintenant();
    ((t.secondes.rem_euclid(86_400) as u64) * 1000 + t.nanosecondes as u64 / 1_000_000) as u32
}

/// Un message ICMP reçu par `i` (`p` : le message, sans l'en-tête d'IPv4,
/// dont voici les champs `h`), dans la tâche du réseau. `diffusion` : sa
/// destination est une diffusion.
pub fn recevoir(i: &'static Interface, h: &format_ipv4::Ipv4, diffusion: bool, p: Paquet) {
    let Ok((m, donnees)) = icmp::lire(p.donnees()) else {
        FAUX.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if m.genre > icmp::GENRE_MAX {
        return;
    }
    // En diffusion, Linux n'accepte que l'écho, l'horodatage et les
    // demandes de masque (qu'il ignore ensuite) ; et il ignore les deux
    // premiers (`icmp_echo_ignore_broadcasts`) : rien ne passe.
    if diffusion {
        return;
    }
    match m.genre {
        icmp::ECHO => {
            let reponse = Icmp { genre: icmp::ECHO_REPONSE, ..m };
            repondre(h, &reponse, &[donnees]);
        }
        icmp::HORODATAGE => {
            // L'heure d'origine (copiée de la demande), de réception et
            // d'émission ; une demande de moins de 4 octets est jetée.
            let Some(origine) = donnees.get(..4) else { return };
            let t = horodatage().to_be_bytes();
            let reponse = Icmp { genre: icmp::HORODATAGE_REPONSE, code: 0, ..m };
            repondre(h, &reponse, &[origine, &t, &t]);
        }
        icmp::ECHO_REPONSE => super::ping::recevoir(i.index, h.source, h.destination, p),
        icmp::INJOIGNABLE | icmp::ETOUFFEMENT | icmp::REDIRECTION | icmp::TEMPS_DEPASSE | icmp::PARAMETRE => {
            erreur_recue(i, h, &m, donnees)
        }
        _ => {}
    }
}

/// Ce qu'une erreur reçue dit au protocole du paquet qui l'a provoquée.
pub struct ErreurRecue<'a> {
    pub genre: u8,
    pub code: u8,
    /// La MTU d'une fragmentation nécessaire, l'octet fautif d'un problème
    /// de paramètre, la passerelle qu'annonce une redirection (le `info` de
    /// Linux : `icmp_unreach`, `icmp_redirect`).
    pub info: u32,
    /// L'en-tête du paquet d'origine, et sa copie entière (en-tête compris).
    pub interne: Interne,
    pub origine: &'a [u8],
    /// Qui a dit l'erreur (la source du message ICMP), où et par quelle
    /// interface il est arrivé.
    pub emetteur: [u8; 4],
    pub destination: [u8; 4],
    pub interface: u32,
}

/// Une erreur reçue (`icmp_unreach`) : le paquet d'origine lisible (un
/// en-tête d'au moins 5 mots, puis 8 octets) ; un code d'injoignable connu
/// (au plus 15) ; un « temps dépassé » du réassemblage ignoré ; puis le
/// protocole d'origine.
fn erreur_recue(i: &'static Interface, h: &format_ipv4::Ipv4, m: &Icmp, donnees: &[u8]) {
    let Some(interne) = icmp::interne(donnees) else { return };
    let info = match m.genre {
        icmp::INJOIGNABLE if m.code > icmp::INJOIGNABLE_MAX => return,
        icmp::INJOIGNABLE if m.code == icmp::FRAGMENTATION => u16::from_be_bytes([m.reste[2], m.reste[3]]) as u32,
        icmp::PARAMETRE => m.reste[0] as u32,
        icmp::REDIRECTION => u32::from_be_bytes(m.reste),
        icmp::TEMPS_DEPASSE if m.code == 1 => return,
        _ => 0,
    };
    let e = ErreurRecue {
        genre: m.genre, code: m.code, info, interne, origine: donnees, emetteur: h.source, destination: h.destination,
        interface: i.index,
    };
    match interne.protocole {
        format_ipv4::UDP => super::udp::erreur(&e),
        format_ipv4::TCP => super::tcp::erreur(&e),
        format_ipv4::ICMP => super::ping::erreur(&e),
        _ => {}
    }
}

/// Répond au message reçu `h` par le message `reponse`, dont les données
/// sont les morceaux `morceaux` (`icmp_reply`) : de l'adresse visée, vers
/// l'émetteur, avec son TOS.
fn repondre(h: &format_ipv4::Ipv4, reponse: &Icmp, morceaux: &[&[u8]]) {
    let longueur: usize = morceaux.iter().map(|m| m.len()).sum();
    let Ok((chemin, destination)) = ipv4::router(h.source, None) else { return };
    let Some(mut p) = Paquet::vide(icmp::ENTETE + longueur) else { return };
    let Some(o) = p.ajouter_fin(icmp::ENTETE + longueur) else { return };
    let mut k = icmp::ENTETE;
    for m in morceaux {
        o[k..k + m.len()].copy_from_slice(m);
        k += m.len();
    }
    icmp::ecrire(o, reponse);
    let envoi = Envoi {
        source: h.destination, destination, protocole: format_ipv4::ICMP, ttl: 64, tos: h.tos,
        identifiant: ipv4::identifiant(destination, h.destination, format_ipv4::ICMP), ne_pas_fragmenter: false, mtu: ipv4::mtu_vers(&chemin, destination), confirmer: false,
    };
    ipv4::emettre(chemin, &envoi, p);
}

/// Envoie une erreur ICMP (`genre`, `code`, `info` : ses 4 octets) pour le
/// paquet `origine` (son en-tête IPv4 compris), comme `__icmp_send` (voir
/// l'en-tête du module). `par_lo` : il est arrivé par `lo` (ou en partait)
/// ; `pour_nous` : il nous était destiné (sa destination devient la source
/// de l'erreur) ; `trame_diffusee` : sa trame Ethernet allait à tous.
/// `origine` peut être plus court que ne le dit son en-tête : un datagramme
/// UDP coupé à sa longueur UDP (`__udp4_lib_rcv` le coupe aussi), dont
/// seul l'en-tête IPv4 est relu.
pub fn envoyer_erreur(genre: u8, code: u8, info: u32, origine: &[u8], par_lo: bool, pour_nous: bool, trame_diffusee: bool) {
    let Ok(h) = format_ipv4::lire_entete(origine) else { return };
    if trame_diffusee || h.decalage != 0 {
        return;
    }
    let Ok((chemin_origine, _)) = ipv4::router(h.destination, None) else { return };
    if matches!(chemin_origine, inet::routes::Chemin::Diffusion { .. }) || format_ipv4::multidiffusion(h.destination) {
        return;
    }
    if icmp::est_erreur(genre) && h.protocole == format_ipv4::ICMP {
        match origine.get(h.longueur_entete) {
            Some(&g) if !icmp::est_erreur(g) => {}
            _ => return,
        }
    }
    // La limite globale (`icmpv4_global_allow`), sauf pour un paquet arrivé
    // par lo ; `limiter` : elle s'appliquait, et la limite par destination
    // s'appliquera aussi (l'`apply_ratelimit` de Linux).
    let limiter = !par_lo && limitee(genre, code);
    if limiter && !permis() {
        LIMITES_GLOBALES.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Ok((chemin, destination)) = ipv4::router(h.source, None) else { return };
    // La limite par destination (`icmpv4_xrlim_allow`), sauf sur un chemin
    // qui part par lo ; permis, le message consomme le crédit global.
    if limiter {
        if !ipv4::par_lo(&chemin) && !PAIRS.verrouiller().permettre(destination, crate::temps::ns_monotone()) {
            LIMITES_PAR_MACHINE.fetch_add(1, Ordering::Relaxed);
            return;
        }
        consommer();
    }
    let source = if pour_nous { h.destination } else { ipv4::source(&chemin) };
    // Autant du paquet d'origine que tient en 576 octets ; au moins un
    // en-tête IPv4, sinon le message n'aurait pas de sens.
    let place = (ipv4::mtu_vers(&chemin, destination) as usize).min(576).saturating_sub(format_ipv4::ENTETE + icmp::ENTETE);
    if place <= format_ipv4::ENTETE {
        return;
    }
    let n = origine.len().min(place);
    let Some(mut p) = Paquet::vide(icmp::ENTETE + n) else { return };
    let Some(o) = p.ajouter_fin(icmp::ENTETE + n) else { return };
    o[icmp::ENTETE..].copy_from_slice(&origine[..n]);
    icmp::ecrire(o, &Icmp { genre, code, reste: info.to_be_bytes() });
    // Le TOS d'origine (ses bits de type de service) et la priorité de
    // « contrôle de l'Internet » (`IPTOS_PREC_INTERNETCONTROL`).
    let envoi = Envoi {
        source, destination, protocole: format_ipv4::ICMP, ttl: 64, tos: (h.tos & 0x1E) | 0xC0,
        identifiant: ipv4::identifiant(destination, source, format_ipv4::ICMP), ne_pas_fragmenter: false, mtu: ipv4::mtu_vers(&chemin, destination), confirmer: false,
    };
    ipv4::emettre(chemin, &envoi, p);
}
