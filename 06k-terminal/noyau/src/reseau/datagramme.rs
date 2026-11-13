//! Ce qu'ont en commun les sockets de datagrammes d'IPv4 (af_inet.c et
//! datagram.c de Linux) : bind, connect, sa fin (AF_UNSPEC), le port
//! éphémère d'un envoi, getsockname et getpeername. Chaque appel dans
//! l'ordre de vérification de Linux ; la table où une socket prend son
//! port est celle de son protocole (`table`). Ce que fait chaque protocole
//! d'un envoi et d'une arrivée est dans le sien (udp.rs, ping.rs).
//! Deux compteurs d'IP (/proc/net/snmp) sont communs à leurs envois : pas de
//! route (OutNoRoutes, `router` : l'ENETUNREACH d'`udp_sendmsg`, de
//! `ping_v4_sendmsg` et d'`__ip4_datagram_connect`), et un paquet qu'on ne
//! peut pas faire (OutDiscards, `jete` : le `error:` d'`__ip_append_data`).

use super::ipv4;
use super::paquet::{self, Paquet};
use super::snmp::MIB;
use super::socket::{self, AF_INET, AF_UNSPEC, Inet, Protocole, Socket};
use crate::attente::{self, Sommeil};
use crate::sondage::{POLLOUT, POLLWRBAND, POLLWRNORM};
use crate::tache::Reveil;
use crate::partage::Arc;
use core::sync::atomic::Ordering;
use formats::reseau::ipv4 as format_ipv4;
use inet::ports;
use inet::routes::Chemin;
use inet::snmp::Ip;

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
    use super::super::{ping, udp};
    use crate::partage::Arc;

    pub fn inscrire(s: &Arc<Socket>, inet: &mut Inet, port: u16) -> Result<(), i64> {
        match s.protocole {
            Protocole::Udp => udp::inscrire(s, inet, port),
            Protocole::Ping => ping::inscrire(s, inet, port),
            // TCP a sa propre table (tcp.rs) ; AF_UNIX, ses noms (unix.rs).
            Protocole::Tcp | Protocole::Unix => Ok(()),
        }
    }

    pub fn changer(s: &Socket, inet: &Inet) {
        match s.protocole {
            Protocole::Udp => udp::changer(s, inet),
            Protocole::Ping => ping::changer(s, inet),
            Protocole::Tcp | Protocole::Unix => {}
        }
    }

    pub fn retirer(s: &Socket) {
        match s.protocole {
            Protocole::Udp => udp::liberer(s),
            Protocole::Ping => ping::liberer(s),
            Protocole::Tcp | Protocole::Unix => {}
        }
    }

    pub fn reutilisation_changee(s: &Socket, inet: &Inet) {
        match s.protocole {
            Protocole::Udp => udp::reutilisation_changee(s, inet),
            Protocole::Ping => ping::reutilisation_changee(s, inet),
            Protocole::Tcp => super::super::tcp::reutilisation_changee(s, inet),
            Protocole::Unix => {}
        }
    }
}

/// L'adresse `a` est-elle une diffusion ou une multidiffusion (le
/// RTN_BROADCAST et le RTN_MULTICAST d'`inet_addr_type` : la limitée,
/// celle d'un réseau d'une interface, une de multidiffusion) ?
pub fn diffusion(a: [u8; 4]) -> bool {
    a == format_ipv4::DIFFUSION
        || format_ipv4::multidiffusion(a)
        || ipv4::avec_table(|t| matches!(t.chercher(a), Some(Chemin::Diffusion { .. }))).unwrap_or(false)
}

/// L'adresse `a` peut-elle être celle d'un `bind` (`inet_addr_valid_or_nonlocal`) :
/// 0.0.0.0, une adresse à nous, une diffusion ou une multidiffusion, ou
/// toute adresse avec IP_FREEBIND ou IP_TRANSPARENT (`nonlocale`) ? Une
/// socket de ping (`ping_check_bind_addr`) refuse les diffusions et les
/// multidiffusions, même avec IP_FREEBIND. Partagée avec TCP, qui suit
/// `__inet_bind` comme UDP.
pub fn adresse_de_bind(a: [u8; 4], nonlocale: bool, ping: bool) -> bool {
    if a == format_ipv4::AUCUNE {
        return true;
    }
    let locale = ipv4::avec_table(|t| t.est_a_nous(a)).unwrap_or(false);
    if ping {
        return !diffusion(a) && (locale || nonlocale);
    }
    locale || nonlocale || diffusion(a)
}

/// bind(adresse) : la `sockaddr_in` copiée du programme, dans l'ordre
/// d'`inet_bind` et d'`__inet_bind` : moins de 16 octets : EINVAL ; une
/// autre famille qu'AF_INET : EAFNOSUPPORT (AF_UNSPEC accepté avec
/// 0.0.0.0, une compatibilité de Linux) ; une adresse qui ne peut pas
/// l'être (`adresse_de_bind`) : EADDRNOTAVAIL ; un port de moins de 1024
/// sans être root : EACCES (pour UDP) ; déjà liée : EINVAL ; le port pris :
/// EADDRINUSE. Une socket de ping suit le même ordre
/// (`ping_check_bind_addr`, puis `ping_bind`), son port étant
/// l'identifiant de ses échos. Avec IP_BIND_ADDRESS_NO_PORT, le port 0
/// n'en prend pas (UDP seulement : `ping_bind` l'ignore) : la socket garde
/// son adresse, sans port, et peut être liée de nouveau (le refus de Linux
/// regarde `inet_num`) ; son port viendra au premier envoi ou au `connect`
/// (`lier_au_besoin`), avec cette adresse.
pub fn lier(s: &Arc<Socket>, o: &[u8]) -> Result<(), i64> {
    let Some(a) = socket::lire_adresse(o) else { return Err(-EINVAL) };
    if a.famille != AF_INET && !(a.famille == AF_UNSPEC && a.adresse == format_ipv4::AUCUNE) {
        return Err(-EAFNOSUPPORT);
    }
    let op = s.appels.verrouiller().options;
    if !adresse_de_bind(a.adresse, op.freebind || op.transparent, s.protocole == Protocole::Ping) {
        return Err(-EADDRNOTAVAIL);
    }
    // Un port privilégié pour UDP ; une socket de ping n'a que des
    // identifiants (`ping_bind` ne regarde pas).
    if s.protocole == Protocole::Udp && a.port != 0 && a.port < ports::PRIVILEGIE && s.uid != 0 {
        return Err(-EACCES);
    }
    let mut inet = s.appels.verrouiller();
    if inet.lie {
        return Err(-EINVAL);
    }
    inet.adresse = a.adresse;
    let sans_port = a.port == 0 && s.protocole == Protocole::Udp && inet.options.bind_no_port;
    if !sans_port && let Err(e) = table::inscrire(s, &mut inet, a.port) {
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
    s.connectee.store(true, Ordering::Relaxed);
    inet.identifiant = crate::aleatoire::u32() as u16;
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
    s.connectee.store(false, Ordering::Relaxed);
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
    ipv4::router(inet.distante, None).ok().map(|(c, d)| ipv4::mtu_vers(&c, d))
}

/// Ce que précisent les messages de contrôle d'un envoi (`ip_cmsg_send`) :
/// IP_TTL, IP_TOS, et l'adresse source et l'interface d'IP_PKTINFO.
#[derive(Clone, Copy, Default)]
pub struct Controle {
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    pub source: Option<[u8; 4]>,
    pub interface: Option<u32>,
    /// SCM_RIGHTS ou SCM_CREDENTIALS (qu'UDP ignore, et qu'AF_UNIX refuse
    /// jusqu'à 6l).
    pub droits: bool,
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
/// `bind`) de multidiffusion ou de diffusion limitée : EINVAL ; une autre
/// qui n'est pas à nous (liée par IP_FREEBIND, ou d'IP_PKTINFO) :
/// ENETUNREACH (`ip_route_output_key_hash_rcu`, mesuré : 0.1.2.3 aussi,
/// `ipv4_is_zeronet` ne regarde plus que 0.0.0.0), sauf avec
/// IP_TRANSPARENT (FLOWI_FLAG_ANYSRC), mais pas vers une diffusion ou une
/// multidiffusion sans interface demandée ; l'interface d'IP_PKTINFO qui
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
    let demandee = c.source.filter(|&a| a != format_ipv4::AUCUNE).or_else(|| source_liee(inet));
    if let Some(a) = demandee {
        if format_ipv4::multidiffusion(a) || a == format_ipv4::DIFFUSION {
            return Err(-EINVAL);
        }
        let vers_diffusion = c.interface.unwrap_or(0) == 0
            && (format_ipv4::multidiffusion(destination) || destination == format_ipv4::DIFFUSION);
        if !ipv4::avec_table(|t| t.est_a_nous(a)).unwrap_or(false) && (!inet.options.transparent || vers_diffusion) {
            return Err(sans_route());
        }
    }
    if c.interface.is_some_and(|k| k != 0 && super::interface::par_index(k).is_none()) {
        return Err(-ENODEV);
    }
    let (chemin, destination) = ipv4::router(destination, demandee).map_err(|_| sans_route())?;
    if (inet.options.dontroute || drapeaux & MSG_DONTROUTE != 0)
        && matches!(chemin, Chemin::Unicast { prochain, .. } if prochain != destination) {
        return Err(sans_route());
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

/// Ce que fixe un envoi quand il commence (le `flowi4` et l'`inet_cork` de
/// Linux, `ip_setup_cork`) : la route, les adresses, la MTU où le découper
/// (`cork->fragsize`), et ce que ses messages de contrôle demandent pour
/// l'en-tête IPv4 (`cork->ttl`, `cork->tos` : sinon, ceux de la socket
/// quand il part). Le bouchon d'UDP le garde d'un envoi à l'autre.
#[derive(Clone, Copy)]
pub struct Depart {
    pub chemin: Chemin,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub mtu: u32,
    ttl: Option<u8>,
    tos: Option<u8>,
    /// MSG_CONFIRM, au premier envoi : la machine voisine est là (arp.rs).
    confirmer: bool,
}

impl Depart {
    /// Le paquet de `charge` octets (après l'en-tête IPv4) part-il avec DF
    /// (`__ip_make_skb`) ? Avec IP_PMTUDISC_DO et PROBE, et WANT s'il n'a
    /// pas à être découpé.
    pub fn ne_pas_fragmenter(&self, pmtudisc: u8, charge: usize) -> bool {
        matches!(pmtudisc, 2 | 3)
            || (charge + format_ipv4::ENTETE <= ipv4::mtu_vers(&self.chemin, self.destination) as usize
                && ipv4::ne_pas_fragmenter(pmtudisc, self.destination))
    }

    /// L'en-tête IPv4 d'un paquet de `charge` octets, au moment où il part
    /// (`__ip_make_skb`, sous le `Mutex`) : DF (`ne_pas_fragmenter`, avec
    /// IP_MTU_DISCOVER d'alors) ; l'identifiant comme `ip_select_ident_segs`
    /// : celui de la socket si elle est connectée (même pour un autre
    /// destinataire), qui avance d'un paquet parti (pas d'un envoi refusé en
    /// route) ; 0 avec DO et PROBE (un paquet que rien ne fragmentera, pas
    /// même nous : `ignore_df` faux) ; sinon `ipv4::identifiant` ; le TTL et
    /// le TOS des messages de contrôle du premier envoi, sinon ceux de la
    /// socket d'alors.
    pub fn envoi(&self, inet: &mut Inet, charge: usize, protocole: u8) -> ipv4::Envoi {
        let pmtudisc = inet.options.pmtudisc;
        let identifiant = if inet.connecte {
            inet.identifiant = inet.identifiant.wrapping_add(1);
            inet.identifiant
        } else if matches!(pmtudisc, 2 | 3) {
            0
        } else {
            ipv4::identifiant(self.destination, self.source, protocole)
        };
        ipv4::Envoi {
            source: self.source, destination: self.destination, protocole,
            ttl: self.ttl.or(inet.options.ttl).unwrap_or(ipv4::TTL_DEFAUT), tos: self.tos.unwrap_or(inet.options.tos),
            identifiant, ne_pas_fragmenter: self.ne_pas_fragmenter(pmtudisc, charge), mtu: self.mtu, confirmer: self.confirmer,
        }
    }

    /// Ce qu'on a le droit d'envoyer, l'en-tête IPv4 compris : 65 535
    /// octets si la fragmentation est permise (IP_PMTUDISC_DONT, WANT,
    /// OMIT : `ip_sk_ignore_df`), sinon la MTU (celle du chemin pour DO ;
    /// celle de la carte pour PROBE et INTERFACE, qui ne veulent pas de la
    /// découverte) : le `maxnonfragsize` d'`__ip_append_data`.
    pub fn permis(&self, pmtudisc: u8) -> usize {
        if pmtudisc < 2 || pmtudisc == 5 { 0xFFFF } else { self.mtu as usize }
    }
}

/// Trop gros pour `d` (`permis`) : EMSGSIZE, et avec IP_RECVERR une erreur
/// « locale » en file (`ip_local_error` : la destination, le port de la
/// connexion, la MTU).
pub fn trop_gros(s: &Socket, inet: &Inet, d: &Depart) -> i64 {
    const EMSGSIZE: i64 = 90;
    if inet.options.recverr
        && let Some(e) = socket::ErreurEnFile::locale(EMSGSIZE as i32, d.mtu, d.destination, inet.port_distant)
    {
        s.mettre_en_file(e);
    }
    -EMSGSIZE
}

/// MSG_PROBE : chercher la route, sans rien envoyer (tracepath s'en sert
/// pour sonder la MTU d'un chemin).
pub const MSG_PROBE: u64 = 0x10;

/// Le début d'un envoi, une fois sa destination connue (`ip_make_skb`,
/// `__ip_append_data`, `sock_alloc_send_pskb`), commun à UDP et ping, sous
/// le `Mutex` : la route et ses refus (`router`) ; `charge` octets
/// (l'en-tête du protocole compris) plus l'en-tête IPv4 au-delà de ce qu'on
/// a le droit d'envoyer (`Depart::permis`) : `trop_gros` ; l'erreur en
/// attente (lue et effacée : un ECONNREFUSED revenu après l'envoi précédent
/// sort ici) ; l'écriture arrêtée : EPIPE, sans SIGPIPE (le signal est
/// l'affaire de TCP). Avec MSG_PROBE, rien après la route : Linux ne fait
/// aucun paquet (`ip_make_skb` rend NULL, `ip_append_data` 0, avant
/// `__ip_append_data`), donc ni la taille, ni l'erreur en attente, ni
/// l'arrêt ne comptent ; l'envoi rend sa longueur sans rien envoyer.
pub fn preparer(s: &Socket, inet: &mut Inet, destination: [u8; 4], charge: usize, drapeaux: u64, c: &Controle) -> Result<Depart, i64> {
    const MSG_CONFIRM: u64 = 0x800;
    const EPIPE: i64 = 32;
    let Trajet { chemin, destination, source } = router(inet, destination, c, drapeaux)?;
    let pmtudisc = inet.options.pmtudisc;
    let d = Depart {
        chemin, source, destination, mtu: ipv4::mtu_d_envoi(pmtudisc, &chemin, destination),
        ttl: c.ttl, tos: c.tos, confirmer: drapeaux & MSG_CONFIRM != 0,
    };
    if drapeaux & MSG_PROBE != 0 {
        return Ok(d);
    }
    if charge + format_ipv4::ENTETE > d.permis(pmtudisc) {
        return Err(trop_gros(s, inet, &d));
    }
    // (Chez Linux, ces deux refus viennent de l'attente de la place, dans
    // `__ip_append_data` : des paquets jetés.)
    let erreur = s.prendre_erreur();
    if erreur != 0 {
        return Err(jete(-(erreur as i64)));
    }
    if s.reception.verrouiller().arret & socket::ARRET_ECRITURE != 0 {
        return Err(jete(-EPIPE));
    }
    Ok(d)
}

/// Le paquet d'un envoi de `charge` octets vers `d` (sans l'en-tête IPv4 ;
/// `remplir` y copie ceux du programme), commun à UDP et ping : la place
/// dans SO_SNDBUF (`attendre_place`), les morceaux au-delà de son double
/// (`morceaux_permis`), le paquet (ENOBUFS) attaché à la socket, la copie
/// (EFAULT). Chaque refus jette le paquet (OutDiscards).
pub fn faire_paquet(s: &Socket, d: &Depart, charge: usize, pmtudisc: u8, non_bloquant: bool, delai: Option<u64>,
                    remplir: impl FnOnce(&mut [u8]) -> Result<(), i64>) -> Result<Paquet, i64> {
    const ENOBUFS: i64 = 105;
    attendre_place(s, non_bloquant, delai)?;
    morceaux_permis(s, charge, d, pmtudisc)?;
    let Some(mut p) = Paquet::vide(charge) else { return Err(jete(-ENOBUFS)) };
    attacher(s, &mut p);
    let Some(segment) = p.ajouter_fin(charge) else { return Err(jete(-ENOBUFS)) };
    remplir(segment).map_err(jete)?;
    Ok(p)
}

// --- SO_SNDBUF (les soldes d'avant 6k) ---

/// Attend qu'un envoi de la socket `s` ait de la place, dans l'ordre de
/// `sock_alloc_send_pskb` : une erreur en attente, prise et rendue ;
/// l'écriture arrêtée : EPIPE ; moins que SO_SNDBUF en route : la place ;
/// MSG_DONTWAIT (ou O_NONBLOCK) : EAGAIN ; sinon attendre, au plus jusqu'à
/// l'échéance de SO_SNDTIMEO (puis EAGAIN), un signal : ERESTARTSYS, ou
/// EINTR avec un délai (`sock_intr_errno`), et revoir tout cela. Le
/// `Mutex` de la socket n'est pas tenu (Linux ne prend pas son verrou pour
/// un envoi sans bouchon) : un autre fil peut l'utiliser pendant l'attente.
/// Chaque erreur jette le paquet (OutDiscards).
pub fn attendre_place(s: &Socket, non_bloquant: bool, delai: Option<u64>) -> Result<(), i64> {
    attendre_la_place(s, non_bloquant, delai).map_err(jete)
}

fn attendre_la_place(s: &Socket, non_bloquant: bool, delai: Option<u64>) -> Result<(), i64> {
    const EPIPE: i64 = 32;
    const EINTR: i64 = 4;
    let Some(r) = &s.envois else { return Ok(()) };
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    let arretee = || s.reception.verrouiller().arret & socket::ARRET_ECRITURE != 0;
    loop {
        let erreur = s.prendre_erreur();
        if erreur != 0 {
            return Err(-(erreur as i64));
        }
        if arretee() {
            return Err(-EPIPE);
        }
        if r.place() {
            return Ok(());
        }
        // SOCKWQ_ASYNC_NOSPACE et SOCK_NOSPACE : la place revue derrière
        // chaque drapeau (asynchrone.rs, paquet.rs) ; et SOCK_NOSPACE tel que
        // le lit `udp_sendmsg`, qui ne s'efface pas (`place_manquee`).
        s.asynchrone.marquer_sans_place(|| !r.place());
        r.marquer_sans_place(|| !r.place());
        s.place_manquee.store(true, Ordering::Relaxed);
        if non_bloquant {
            return Err(-EAGAIN);
        }
        // Qui attend dans l'appel n'a pas de SIGIO à la place rendue :
        // SOCKWQ_ASYNC_NOSPACE effacé avant d'attendre (`sock_wait_for_wmem`).
        s.asynchrone.oublier_sans_place();
        let pret = || r.place() || arretee() || s.reception.verrouiller().erreur != 0;
        match attente::attendre_que(&s.attente, attente::Inscription::Ordinaire, Sommeil::Interruptible, echeance, pret) {
            Reveil::Reveillee => {}
            Reveil::Echeance => return Err(-EAGAIN),
            Reveil::Signal => return Err(if delai.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
        }
    }
}

/// Un datagramme de `charge` octets (après l'en-tête IPv4) qui sera
/// découpé en morceaux pour la MTU `mtu` (`format_ipv4::nombre_de_fragments`) :
/// le premier prend sa place par `attendre_place` (`sock_alloc_send_skb`) ;
/// chacun des suivants, avant d'être fait, ne doit pas mener ce qui est en
/// route, les morceaux d'avant de cet envoi compris (pleins, comptés à leur
/// taille vraie), au-delà du double de SO_SNDBUF (le `wmem_alloc_delta <= 2
/// * sk_sndbuf` de `__ip_append_data`) : ENOBUFS. Le plus exigeant est le
/// dernier. Sans découpage, ou avec DF (le paquet ne partira pas), rien à
/// compter.
fn morceaux_permis(s: &Socket, charge: usize, d: &Depart, pmtudisc: u8) -> Result<(), i64> {
    const ENOBUFS: i64 = 105;
    let Some(r) = &s.envois else { return Ok(()) };
    if charge + format_ipv4::ENTETE <= d.mtu as usize || d.ne_pas_fragmenter(pmtudisc, charge) {
        return Ok(());
    }
    let plein = (d.mtu as usize - format_ipv4::ENTETE) & !7;
    let morceaux = format_ipv4::nombre_de_fragments(charge, d.mtu as usize, format_ipv4::ENTETE);
    let taille = (morceaux - 1) * (paquet::MARGE + plein + paquet::SURCOUT);
    if r.octets() + taille > 2 * r.limite() {
        return Err(jete(-ENOBUFS));
    }
    Ok(())
}

/// Pas de route : ENETUNREACH, compté (OutNoRoutes).
pub(super) fn sans_route() -> i64 {
    const ENETUNREACH: i64 = 101;
    MIB.ip(Ip::OutNoRoutes);
    -ENETUNREACH
}

/// Le paquet d'un envoi ne peut pas être fait (la place, la mémoire, la copie : le
/// `error:` d'`__ip_append_data`) : l'erreur `e`, et un paquet jeté (OutDiscards).
pub fn jete(e: i64) -> i64 {
    MIB.ip(Ip::OutDiscards);
    e
}

/// Le paquet `p` d'une socket de datagrammes compte dans son SO_SNDBUF
/// jusqu'à ce que la carte l'ait fini (`skb_set_owner_w`).
pub fn attacher(s: &Socket, p: &mut Paquet) {
    if let Some(r) = &s.envois {
        p.attacher(r, 0);
    }
}

/// La place rendue d'une socket de datagrammes, dans la tâche du réseau
/// (rappelée par `Proprietaire::rendre`, paquet.rs ; la socket de numéro
/// `n`, si elle est encore liée) : `sock_def_write_space`, s'il y a encore
/// de quoi progresser, réveille qui attend (POLLOUT), et SIGIO pour qui a
/// vu la place manquer. Vrai si c'était une socket de datagrammes.
pub fn place_rendue(n: u64) -> bool {
    let Some(s) = super::udp::par_numero(n).or_else(|| super::ping::par_numero(n)) else { return false };
    reveiller_les_ecrivains(&s);
    true
}

/// `sk_write_space` : aussi quand SO_SNDBUF grandit (setsockopt).
pub fn reveiller_les_ecrivains(s: &Socket) {
    let Some(r) = &s.envois else { return };
    r.rappelee();
    if r.ecriture_possible() {
        s.attente.reveiller(POLLOUT | POLLWRNORM | POLLWRBAND, 0);
        s.asynchrone.place();
    }
}
