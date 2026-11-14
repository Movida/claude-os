//! ICMP dans le noyau (net/ipv4/icmp.c) : répondre à l'écho, dire une
//! erreur à qui a envoyé un paquet qu'on ne peut pas livrer, et rendre aux
//! sockets les erreurs que le réseau nous dit.
//!
//! LA RÉCEPTION, dans l'ordre d'`icmp_rcv` : la somme, l'en-tête ; l'écho
//! étendu (PROBE) ignoré, comme Linux par défaut
//! (`icmp_echo_enable_probe` à 0) ; rien de ce qui arrive en diffusion
//! (Linux n'y accepte que l'écho et l'horodatage, qu'il ignore par défaut,
//! `icmp_echo_ignore_broadcasts` : sinon une seule trame ferait répondre
//! tout un réseau, l'attaque « smurf » ; et les demandes de masque, qu'il
//! ignore ensuite). Puis selon le genre : la réponse à l'écho, étendu ou
//! non, va à la socket de ping de son identifiant (ping.rs) ; un genre
//! inconnu est jeté ; l'écho reçoit sa réponse ;
//! l'horodatage aussi (les millisecondes depuis minuit, temps universel) ;
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
//!
//! LES COMPTEURS (/proc/net/snmp, snmp.rs) : chaque message reçu (InMsgs),
//! puis son genre (IcmpMsg) une fois l'en-tête lu ; une somme fausse
//! (InCsumErrors), et tout message refusé (InErrors : trop court, en
//! diffusion, d'un genre inconnu, une erreur qui ne cite pas un en-tête
//! lisible, un horodatage trop court) ; chaque message envoyé, par son
//! genre (OutMsgs et IcmpMsg, quand son paquet est fait : `icmp_out_count`),
//! ou qu'on n'a pas pu faire (OutErrors) ; les erreurs que retient une
//! limite (OutRateLimitGlobal, OutRateLimitHost).

use super::interface::Interface;
use super::ipv4::{self, Envoi};
use super::paquet::Paquet;
use super::snmp::MIB;
use crate::verrou::Verrou;
use formats::reseau::Erreur;
use formats::reseau::icmp::{self, Icmp, Interne};
use formats::reseau::ipv4 as format_ipv4;
use inet::pairs::Pairs;
use inet::snmp::{Icmp as Compteur, Ip};

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

/// Les millisecondes depuis minuit, temps universel (`inet_current_timestamp`) :
/// la réponse à l'horodatage, et l'option d'horodatage d'IP (ipv4.rs).
pub fn horodatage() -> u32 {
    let t = crate::temps::maintenant();
    ((t.secondes.rem_euclid(86_400) as u64) * 1000 + t.nanosecondes as u64 / 1_000_000) as u32
}

/// Un message ICMP reçu par `i` (`p` : le message, sans l'en-tête d'IPv4,
/// dont voici les champs `h`), dans la tâche du réseau. `diffusion` : sa
/// destination est une diffusion.
pub fn recevoir(i: &'static Interface, h: &format_ipv4::Ipv4, entete: &ipv4::EnteteRecu, diffusion: bool, p: Paquet) {
    MIB.icmp(Compteur::InMsgs);
    let (m, donnees) = match icmp::lire(p.donnees()) {
        Ok(x) => x,
        Err(e) => {
            if e == Erreur::Somme {
                MIB.icmp(Compteur::InCsumErrors);
            }
            return refuse();
        }
    };
    MIB.icmp_entree(m.genre);
    if m.genre == icmp::ECHO_ETENDU {
        return;
    }
    // En diffusion, Linux n'accepte que l'écho, l'horodatage et les
    // demandes de masque ; et il ignore les deux premiers
    // (`icmp_echo_ignore_broadcasts`), qui sont refusés : rien ne passe.
    if diffusion {
        if !matches!(m.genre, icmp::ADRESSE | icmp::ADRESSE_REPONSE) {
            refuse();
        }
        return;
    }
    if matches!(m.genre, icmp::ECHO_REPONSE | icmp::ECHO_ETENDU_REPONSE) {
        return super::ping::recevoir(i.index, h.source, h.destination, entete, p);
    }
    if m.genre > icmp::GENRE_MAX {
        return refuse();
    }
    match m.genre {
        icmp::ECHO => {
            let reponse = Icmp { genre: icmp::ECHO_REPONSE, ..m };
            repondre(h, entete, &reponse, &[donnees]);
        }
        icmp::HORODATAGE => {
            // L'heure d'origine (copiée de la demande), de réception et
            // d'émission ; une demande de moins de 4 octets est jetée.
            let Some(origine) = donnees.get(..4) else { return refuse() };
            let t = horodatage().to_be_bytes();
            let reponse = Icmp { genre: icmp::HORODATAGE_REPONSE, code: 0, ..m };
            repondre(h, entete, &reponse, &[origine, &t, &t]);
        }
        icmp::INJOIGNABLE | icmp::ETOUFFEMENT | icmp::REDIRECTION | icmp::TEMPS_DEPASSE | icmp::PARAMETRE => {
            erreur_recue(i, h, entete, &m, donnees, p.donnees())
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
    /// interface il est arrivé, ce que la réception a gardé de son en-tête
    /// IP, et le message ICMP entier (sa somme, IP_CHECKSUM).
    pub emetteur: [u8; 4],
    pub destination: [u8; 4],
    pub interface: u32,
    pub entete: &'a ipv4::EnteteRecu,
    pub message: &'a [u8],
}

/// Un message reçu refusé (InErrors).
fn refuse() {
    MIB.icmp(Compteur::InErrors);
}

/// Une erreur reçue (`icmp_unreach`, `icmp_redirect`) : un en-tête d'origine
/// (20 octets, et au moins 5 mots, sauf pour une redirection, que Linux ne
/// regarde pas) ; un code d'injoignable connu (au plus 15) ; un « temps
/// dépassé » du réassemblage ignoré ; le paquet d'origine lisible (son
/// en-tête, puis 8 octets : `icmp_socket_deliver`) ; puis son protocole.
fn erreur_recue(i: &'static Interface, h: &format_ipv4::Ipv4, ip: &ipv4::EnteteRecu, m: &Icmp, donnees: &[u8], message: &[u8]) {
    let entete = donnees.first().map_or(0, |o| (o & 0x0F) as usize * 4);
    if donnees.len() < format_ipv4::ENTETE || (m.genre != icmp::REDIRECTION && entete < format_ipv4::ENTETE) {
        return refuse();
    }
    let info = match m.genre {
        icmp::INJOIGNABLE if m.code > icmp::INJOIGNABLE_MAX => return,
        icmp::INJOIGNABLE if m.code == icmp::FRAGMENTATION => u16::from_be_bytes([m.reste[2], m.reste[3]]) as u32,
        icmp::PARAMETRE => m.reste[0] as u32,
        icmp::REDIRECTION => u32::from_be_bytes(m.reste),
        icmp::TEMPS_DEPASSE if m.code == 1 => return,
        _ => 0,
    };
    let Some(interne) = icmp::interne(donnees) else {
        // Moins que l'en-tête cité et 8 octets : refusée. Une redirection qui
        // cite un en-tête de moins de 5 mots, Linux la passe au protocole cité,
        // qui lit ses « ports » dans l'en-tête lui-même et n'y trouve aucune
        // socket : UDP et TCP le comptent (`__udp4_lib_err`, `tcp_v4_err` :
        // InErrors), ping et les autres non.
        if donnees.len() < entete + 8 || matches!(donnees.get(9), Some(&format_ipv4::UDP | &format_ipv4::TCP)) {
            refuse();
        }
        return;
    };
    let e = ErreurRecue {
        genre: m.genre, code: m.code, info, interne, origine: donnees, emetteur: h.source, destination: h.destination,
        interface: i.index, entete: ip, message,
    };
    match interne.protocole {
        format_ipv4::UDP => super::udp::erreur(&e),
        format_ipv4::TCP => super::tcp::erreur(&e),
        format_ipv4::ICMP => super::ping::erreur(&e),
        _ => {}
    }
}

/// Répond au message reçu `h` (ce que la réception en a gardé : `entete`)
/// par le message `reponse`, dont les données sont les morceaux `morceaux`
/// (`icmp_reply`) : de l'adresse visée, vers l'émetteur, avec son TOS et
/// l'écho de ses options (`ip_options_echo` : s'il est impossible, pas de
/// réponse) ; avec une route source, vers sa première étape.
fn repondre(h: &format_ipv4::Ipv4, entete: &ipv4::EnteteRecu, reponse: &Icmp, morceaux: &[&[u8]]) {
    let Ok(options) = format_ipv4::options_echo(entete.options(), &entete.compilees, h.source, &ipv4::unicast) else { return };
    let vers = if options.places.route_source != 0 { options.premier_saut } else { h.source };
    let longueur: usize = morceaux.iter().map(|m| m.len()).sum();
    let Ok((chemin, destination)) = ipv4::router(vers, None) else { return };
    let Some(mut p) = Paquet::vide(icmp::ENTETE + longueur) else { return pas_de_paquet() };
    let Some(o) = p.ajouter_fin(icmp::ENTETE + longueur) else { return pas_de_paquet() };
    let mut k = icmp::ENTETE;
    for m in morceaux {
        o[k..k + m.len()].copy_from_slice(m);
        k += m.len();
    }
    icmp::ecrire(o, reponse);
    let envoi = Envoi {
        source: h.destination, destination, protocole: format_ipv4::ICMP, ttl: ipv4::TTL_DEFAUT, tos: h.tos,
        identifiant: ipv4::identifiant(destination, h.destination, format_ipv4::ICMP), ne_pas_fragmenter: false, mtu: ipv4::mtu_vers(&chemin, destination), confirmer: false,
        options, destination_finale: h.source,
    };
    MIB.icmp_sortie(reponse.genre);
    ipv4::emettre(chemin, &envoi, p);
}

/// Un message qu'on ne peut pas faire, faute de mémoire (`icmp_push_reply` :
/// OutErrors ; et OutDiscards d'IP, `__ip_append_data`).
fn pas_de_paquet() {
    MIB.icmp(Compteur::OutErrors);
    MIB.ip(Ip::OutDiscards);
}

/// Envoie une erreur ICMP (`genre`, `code`, `info` : ses 4 octets) pour le
/// paquet `origine` (son en-tête IPv4 compris), comme `__icmp_send` (voir
/// l'en-tête du module). `options` : ce qu'on sait de ses options
/// (vérifiées à son arrivée, ou celles de son envoi) ; l'erreur en fait
/// l'écho (`__ip_options_echo` : s'il est impossible, elle se tait), et va à
/// la première étape d'une route source. `par_lo` : il est arrivé par `lo` (ou en partait)
/// ; `pour_nous` : il nous était destiné (sa destination devient la source
/// de l'erreur) ; `trame_diffusee` : sa trame Ethernet allait à tous.
/// `origine` peut être plus court que ne le dit son en-tête : un datagramme
/// UDP coupé à sa longueur UDP (`__udp4_lib_rcv` le coupe aussi), dont
/// seul l'en-tête IPv4 est relu.
#[allow(clippy::too_many_arguments)]
pub fn envoyer_erreur(genre: u8, code: u8, info: u32, origine: &[u8], options: &format_ipv4::Options, par_lo: bool, pour_nous: bool,
                      trame_diffusee: bool) {
    let Ok(h) = format_ipv4::lire_cite(origine) else { return };
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
        MIB.icmp(Compteur::OutRateLimitGlobal);
        return;
    }
    let cite = origine.get(format_ipv4::ENTETE..h.longueur_entete).unwrap_or(&[]);
    let Ok(echo) = format_ipv4::options_echo(cite, options, h.source, &ipv4::unicast) else { return };
    let vers = if echo.places.route_source != 0 { echo.premier_saut } else { h.source };
    let Ok((chemin, destination)) = ipv4::router(vers, None) else { return };
    // La limite par destination (`icmpv4_xrlim_allow`), sauf sur un chemin
    // qui part par lo ; permis, le message consomme le crédit global.
    if limiter {
        if !ipv4::par_lo(&chemin) && !PAIRS.verrouiller().permettre(destination, crate::temps::ns_monotone()) {
            MIB.icmp(Compteur::OutRateLimitHost);
            return;
        }
        consommer();
    }
    let source = if pour_nous { h.destination } else { ipv4::source(&chemin) };
    // Autant du paquet d'origine que tient en 576 octets, avec nos options ;
    // au moins un en-tête IPv4, sinon le message n'aurait pas de sens.
    let place = (ipv4::mtu_vers(&chemin, destination) as usize).min(576)
        .saturating_sub(format_ipv4::ENTETE + echo.longueur as usize + icmp::ENTETE);
    if place <= format_ipv4::ENTETE {
        return;
    }
    let n = origine.len().min(place);
    let Some(mut p) = Paquet::vide(icmp::ENTETE + n) else { return pas_de_paquet() };
    let Some(o) = p.ajouter_fin(icmp::ENTETE + n) else { return pas_de_paquet() };
    o[icmp::ENTETE..].copy_from_slice(&origine[..n]);
    icmp::ecrire(o, &Icmp { genre, code, reste: info.to_be_bytes() });
    // Le TOS d'origine (ses bits de type de service) et la priorité de
    // « contrôle de l'Internet » (`IPTOS_PREC_INTERNETCONTROL`).
    let envoi = Envoi {
        source, destination, protocole: format_ipv4::ICMP, ttl: ipv4::TTL_DEFAUT, tos: (h.tos & 0x1E) | 0xC0,
        identifiant: ipv4::identifiant(destination, source, format_ipv4::ICMP), ne_pas_fragmenter: false, mtu: ipv4::mtu_vers(&chemin, destination), confirmer: false,
        options: echo, destination_finale: h.source,
    };
    MIB.icmp_sortie(genre);
    ipv4::emettre(chemin, &envoi, p);
}
