//! Ce qu'ont en commun les sockets de datagrammes d'IPv4 (af_inet.c et
//! datagram.c de Linux) : bind, connect, sa fin (AF_UNSPEC), le port
//! éphémère d'un envoi, getsockname et getpeername. Chaque appel dans
//! l'ordre de vérification de Linux ; la table où une socket prend son
//! port est celle de son protocole (`table`). Ce que fait chaque protocole
//! d'un envoi et d'une arrivée est dans le sien (udp.rs).

use super::ipv4;
use super::socket::{self, AF_INET, AF_UNSPEC, Inet, Socket};
use alloc::sync::Arc;
use formats::reseau::ipv4 as format_ipv4;
use inet::ports;
use inet::routes::Chemin;

const EAGAIN: i64 = 11;
const EACCES: i64 = 13;
const EINVAL: i64 = 22;
const EAFNOSUPPORT: i64 = 97;
const EADDRNOTAVAIL: i64 = 99;

/// La table du protocole de la socket : y inscrire une socket à un port (0
/// : éphémère), récrire son lien, l'en retirer, lui dire que SO_REUSEADDR
/// ou SO_REUSEPORT a changé. Sous le `Mutex` de la socket.
pub mod table {
    use super::super::socket::{Inet, Protocole, Socket};
    use super::super::udp;
    use alloc::sync::Arc;

    pub fn inscrire(s: &Arc<Socket>, inet: &mut Inet, port: u16) -> Result<(), i64> {
        match s.protocole {
            Protocole::Udp => udp::inscrire(s, inet, port),
        }
    }

    pub fn changer(s: &Socket, inet: &Inet) {
        match s.protocole {
            Protocole::Udp => udp::changer(s, inet),
        }
    }

    pub fn retirer(s: &Socket) {
        match s.protocole {
            Protocole::Udp => udp::liberer(s),
        }
    }

    pub fn reutilisation_changee(s: &Socket, inet: &Inet) {
        match s.protocole {
            Protocole::Udp => udp::reutilisation_changee(s, inet),
        }
    }
}

/// bind(adresse) : la `sockaddr_in` copiée du programme, dans l'ordre
/// d'`inet_bind` et d'`__inet_bind` : moins de 16 octets : EINVAL ; une
/// autre famille qu'AF_INET : EAFNOSUPPORT (AF_UNSPEC accepté avec
/// 0.0.0.0, une compatibilité de Linux) ; une adresse qui n'est pas à nous
/// (ni 0.0.0.0, ni une diffusion, ni une multidiffusion) : EADDRNOTAVAIL ;
/// un port de moins de 1024 sans être root : EACCES ; déjà liée : EINVAL ;
/// le port pris : EADDRINUSE.
pub fn lier(s: &Arc<Socket>, o: &[u8]) -> Result<(), i64> {
    let Some(a) = socket::lire_adresse(o) else { return Err(-EINVAL) };
    if a.famille != AF_INET && !(a.famille == AF_UNSPEC && a.adresse == format_ipv4::AUCUNE) {
        return Err(-EAFNOSUPPORT);
    }
    let a_nous = a.adresse == format_ipv4::AUCUNE || a.adresse == format_ipv4::DIFFUSION || format_ipv4::multidiffusion(a.adresse)
        || ipv4::avec_table(|t| t.est_a_nous(a.adresse) || matches!(t.chercher(a.adresse), Some(Chemin::Diffusion { .. })))
            .unwrap_or(false);
    if !a_nous {
        return Err(-EADDRNOTAVAIL);
    }
    if a.port != 0 && a.port < ports::PRIVILEGIE && s.uid != 0 {
        return Err(-EACCES);
    }
    let mut inet = s.appels.verrouiller();
    if inet.lie {
        return Err(-EINVAL);
    }
    inet.adresse = a.adresse;
    if let Err(e) = table::inscrire(s, &mut inet, a.port) {
        inet.adresse = format_ipv4::AUCUNE;
        return Err(e);
    }
    inet.port_choisi = a.port != 0;
    inet.adresse_choisie = a.adresse != format_ipv4::AUCUNE;
    Ok(())
}

/// Un port éphémère si la socket n'en a pas (l'`inet_autobind` : EAGAIN
/// s'il n'y en a plus). Sous le `Mutex`.
pub fn lier_au_besoin(s: &Arc<Socket>, inet: &mut Inet) -> Result<(), i64> {
    if inet.lie {
        return Ok(());
    }
    table::inscrire(s, inet, 0).map_err(|_| -EAGAIN)
}

/// L'adresse source d'un envoi : celle de `bind` si elle en est une à
/// nous (pas une diffusion ni une multidiffusion : Linux laisse alors la
/// route choisir, `inet_saddr` à 0), sinon celle de la route.
pub fn source_liee(inet: &Inet) -> Option<[u8; 4]> {
    let a = inet.adresse;
    (a != format_ipv4::AUCUNE && a != format_ipv4::DIFFUSION && !format_ipv4::multidiffusion(a)).then_some(a)
}

/// connect(adresse), dans l'ordre d'`inet_dgram_connect` puis
/// d'`__ip4_datagram_connect` : moins de 2 octets : EINVAL ; AF_UNSPEC :
/// la fin de la connexion (`deconnecter`) ; un port éphémère s'il le faut
/// (AVANT de regarder le reste de l'adresse : EAGAIN) ; moins de 16
/// octets : EINVAL ; une autre famille : EAFNOSUPPORT ; la route
/// (`router` : ENETUNREACH, EINVAL, EACCES). Puis l'adresse source de la
/// route devient l'adresse locale si `bind` n'en avait pas choisi ;
/// l'identifiant IP de la socket est tiré (l'`inet_id`, `get_random_u16`).
pub fn connecter(s: &Arc<Socket>, o: &[u8]) -> Result<(), i64> {
    let Some(famille) = socket::famille(o) else { return Err(-EINVAL) };
    if famille == AF_UNSPEC {
        deconnecter(s);
        return Ok(());
    }
    let mut inet = s.appels.verrouiller();
    lier_au_besoin(s, &mut inet)?;
    let Some(a) = socket::lire_adresse(o) else { return Err(-EINVAL) };
    if a.famille != AF_INET {
        return Err(-EAFNOSUPPORT);
    }
    let Trajet { destination: adresse, source, .. } = router(&inet, a.adresse, &Controle::default(), 0)?;
    if !inet.adresse_choisie {
        inet.adresse = source;
    }
    inet.source = source;
    inet.distante = adresse;
    inet.port_distant = a.port;
    inet.connecte = true;
    let mut h = [0u8; 2];
    crate::aleatoire::remplir(&mut h);
    inet.identifiant = u16::from_le_bytes(h);
    table::changer(s, &inet);
    Ok(())
}

/// La fin de la connexion (connect AF_UNSPEC, `__udp_disconnect`) : plus
/// de destination ; l'adresse locale oubliée si `bind` ne l'avait pas
/// choisie, et le port rendu s'il était éphémère (mesuré : getsockname
/// rend ensuite 0.0.0.0:0).
pub fn deconnecter(s: &Arc<Socket>) {
    let mut inet = s.appels.verrouiller();
    inet.connecte = false;
    inet.distante = format_ipv4::AUCUNE;
    inet.port_distant = 0;
    inet.source = format_ipv4::AUCUNE;
    if !inet.adresse_choisie {
        inet.adresse = format_ipv4::AUCUNE;
    }
    if !inet.port_choisi && inet.lie {
        table::retirer(s);
        inet.lie = false;
        inet.port = 0;
    } else {
        table::changer(s, &inet);
    }
}

/// L'adresse locale et le port (getsockname : `inet_getname`).
pub fn nom(s: &Socket) -> ([u8; 4], u16) {
    let inet = s.appels.verrouiller();
    (inet.adresse, inet.port)
}

/// L'adresse distante (getpeername) ; None : pas connectée (ENOTCONN).
pub fn pair(s: &Socket) -> Option<([u8; 4], u16)> {
    let inet = s.appels.verrouiller();
    inet.connecte.then_some((inet.distante, inet.port_distant))
}

/// La MTU du chemin d'une socket connectée (IP_MTU) ; None : pas
/// connectée (ENOTCONN).
pub fn mtu(s: &Socket) -> Option<u32> {
    let inet = s.appels.verrouiller();
    if !inet.connecte {
        return None;
    }
    ipv4::router(inet.distante, None).ok().map(|(c, _)| ipv4::mtu(&c))
}

/// Ce que précisent les messages de contrôle d'un envoi (`ip_cmsg_send`) :
/// IP_TTL, IP_TOS, et l'adresse source et l'interface d'IP_PKTINFO.
#[derive(Clone, Copy, Default)]
pub struct Controle {
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    pub source: Option<[u8; 4]>,
    pub interface: Option<u32>,
}

/// Ce que donne la route d'un envoi ou d'une connexion.
pub struct Trajet {
    pub chemin: Chemin,
    /// La destination de l'en-tête (0.0.0.0 remplacée), et la source.
    pub destination: [u8; 4],
    pub source: [u8; 4],
}

/// La route d'un envoi ou d'une connexion vers `destination`, dans l'ordre
/// d'`ip_route_output_flow` : une source demandée (IP_PKTINFO, celle de
/// `bind`) qui n'est pas à nous : EINVAL ; l'interface d'IP_PKTINFO qui
/// n'existe pas : ENODEV (Linux la prend aussi pour sortie : un écart, nos
/// routes ne passent que par une interface) ; 0.0.0.0, la source demandée
/// ou 127.0.0.1 (`ipv4::router`) ; pas de route : ENETUNREACH ; avec
/// SO_DONTROUTE ou MSG_DONTROUTE, seulement une machine d'un réseau
/// directement branché (RTO_ONLINK : ENETUNREACH par une passerelle) ; une
/// source de la boucle (127.0.0.0/8) qui sortirait par une carte : EINVAL
/// (`__mkroute_output` : l'autre bout la jetterait comme un martien) ; une
/// diffusion sans SO_BROADCAST : EACCES.
pub fn router(inet: &Inet, destination: [u8; 4], c: &Controle, drapeaux: u64) -> Result<Trajet, i64> {
    const MSG_DONTROUTE: u64 = 4;
    const ENODEV: i64 = 19;
    const ENETUNREACH: i64 = 101;
    let demandee = c.source.filter(|&a| a != format_ipv4::AUCUNE).or_else(|| source_liee(inet));
    if demandee.is_some_and(|a| !ipv4::avec_table(|t| t.est_a_nous(a)).unwrap_or(false)) {
        return Err(-EINVAL);
    }
    if c.interface.is_some_and(|k| k != 0 && super::interface::par_index(k).is_none()) {
        return Err(-ENODEV);
    }
    let (chemin, destination) = ipv4::router(destination, demandee)?;
    if (inet.options.dontroute || drapeaux & MSG_DONTROUTE != 0)
        && matches!(chemin, Chemin::Unicast { prochain, .. } if prochain != destination) {
        return Err(-ENETUNREACH);
    }
    let source = demandee.unwrap_or_else(|| ipv4::source(&chemin));
    if format_ipv4::boucle(source) && !ipv4::par_lo(&chemin) {
        return Err(-EINVAL);
    }
    if matches!(chemin, Chemin::Diffusion { .. }) && !inet.options.broadcast {
        return Err(-EACCES);
    }
    Ok(Trajet { chemin, destination, source })
}
