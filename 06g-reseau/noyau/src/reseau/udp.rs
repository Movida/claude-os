//! UDP (RFC 768 ; net/ipv4/udp.c) : des datagrammes, sans connexion ni
//! garantie, chacun avec ses ports.
//!
//! Les règles des ports (qui peut prendre lequel, à qui va un datagramme)
//! sont dans inet::ports, testées sur l'hôte ; la table vit ici, sous un
//! `Verrou`, faite au démarrage. Chaque appel suit l'ordre de vérification
//! de Linux (mesuré, ou lu dans udp.c) ; ce qui est commun aux sockets de
//! datagrammes (bind, connect, le port éphémère) est dans datagramme.rs, et
//! à toutes les sockets (recevoir, attendre, l'erreur en attente, l'arrêt)
//! dans socket.rs.
//!
//! Ce qui manque, écrit : la fragmentation (un datagramme plus grand que la
//! MTU du chemin rend EMSGSIZE, comme Linux avec IP_PMTUDISC_DO ; avec
//! IP_PMTUDISC_WANT, le réglage par défaut, Linux le fragmenterait) ;
//! SO_SNDBUF ne fait jamais attendre (un datagramme part tout de suite vers
//! la carte, ou sa petite file) ; MSG_MORE et UDP_CORK ; la multidiffusion.

use super::datagramme::{self, Controle};
use super::ipv4::{self, Envoi};
use super::paquet::Paquet;
use super::socket::{self, AF_INET, AF_UNSPEC, ARRET_ECRITURE, Datagramme, Inet, Socket};
use crate::aleatoire;
use crate::verrou::Verrou;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use formats::reseau::{ipv4 as format_ipv4, udp};
use inet::ports::{Lien, Refus, Table};

const EINVAL: i64 = 22;
const EPIPE: i64 = 32;
const EDESTADDRREQ: i64 = 89;
const EMSGSIZE: i64 = 90;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;
const EAFNOSUPPORT: i64 = 97;
const ENOBUFS: i64 = 105;

/// La table des ports ; faite au démarrage.
static PORTS: Verrou<Option<Table<Arc<Socket>>>> = Verrou::new(None);

/// Les datagrammes jetés à l'arrivée (les `UdpInErrors`, `RcvbufErrors`,
/// `NoPorts` de Linux, pas encore montrés).
static FAUX: AtomicU64 = AtomicU64::new(0);
static FILE_PLEINE: AtomicU64 = AtomicU64::new(0);
static SANS_SOCKET: AtomicU64 = AtomicU64::new(0);

pub fn initialiser() {
    *PORTS.verrouiller() = Table::new();
}

fn hasard() -> u32 {
    let mut h = [0u8; 4];
    aleatoire::remplir(&mut h);
    u32::from_le_bytes(h)
}

/// Retire la socket `s` de la table des ports (son dernier close).
pub fn liberer(s: &Socket) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.retirer(s.numero);
    }
}

/// Le lien de `inet` pour la table des ports.
fn lien(s: &Socket, inet: &Inet, port: u16) -> Lien {
    Lien {
        adresse: inet.adresse, port, distante: inet.distante, port_distant: inet.port_distant,
        reuseaddr: inet.options.reuseaddr, reuseport: inet.options.reuseport, uid: s.uid,
    }
}

/// Inscrit `s` dans la table, au port `port` (0 : éphémère). Sous le `Mutex`.
pub fn inscrire(s: &Arc<Socket>, inet: &mut Inet, port: u16) -> Result<(), i64> {
    let mut g = PORTS.verrouiller();
    let Some(t) = g.as_mut() else { return Err(-ENOBUFS) };
    let l = lien(s, inet, port);
    match t.lier(s.numero, l, s.clone(), hasard()) {
        Ok(p) => {
            inet.port = p;
            inet.lie = true;
            Ok(())
        }
        Err(Refus::Pris) => Err(-EADDRINUSE),
        Err(Refus::Plein) => Err(-ENOBUFS),
    }
}

/// Récrit le lien de `s` dans la table (connect, ou sa fin).
pub fn changer(s: &Socket, inet: &Inet) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.changer(s.numero, inet.distante, inet.port_distant, inet.adresse);
    }
}

/// SO_REUSEADDR ou SO_REUSEPORT a changé : la table le saura au prochain
/// conflit. Sous le `Mutex`.
pub fn reutilisation_changee(s: &Socket, inet: &Inet) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.reutiliser(s.numero, inet.options.reuseaddr, inet.options.reuseport);
    }
}

/// Envoie `longueur` octets, que `remplir` copie du programme dans le
/// paquet, à la destination `nom` (la `sockaddr` de sendto ou de sendmsg ;
/// None : celle de la connexion), dans l'ordre d'`inet_sendmsg` et
/// d'`udp_sendmsg` :
///   - un port éphémère s'il le faut, avant tout (EAGAIN) ;
///   - plus de 65 535 octets : EMSGSIZE ; MSG_OOB : EOPNOTSUPP ; MSG_MORE
///     (le « bouchon » d'UDP, qui réunit plusieurs envois en un
///     datagramme) : EOPNOTSUPP, un écart : plutôt que d'envoyer en deux
///     datagrammes ce qui n'en fait qu'un ;
///   - la destination : moins de 16 octets, ou le port 0 : EINVAL ; une
///     autre famille qu'AF_INET ou AF_UNSPEC : EAFNOSUPPORT ; aucune, et
///     pas connectée : EDESTADDRREQ ;
///   - les messages de contrôle (`controle`, lus par l'appel : leur erreur
///     sort ici, EINVAL) ;
///   - la route (ENETUNREACH) ; une diffusion sans SO_BROADCAST : EACCES ;
///     l'adresse source (IP_PKTINFO, celle de `bind`, celle de la route ;
///     une qui n'est pas à nous : EINVAL) ;
///   - plus grand que la MTU du chemin : EMSGSIZE (l'en-tête du module) ;
///   - l'écriture arrêtée (`shutdown`) : EPIPE, sans SIGPIPE (le
///     `sock_alloc_send_pskb` de Linux, pour qui le signal est l'affaire de
///     TCP) ;
///   - le paquet (ENOBUFS), la copie (EFAULT), et il part.
///
/// Rend la longueur envoyée.
pub fn envoyer(s: &Arc<Socket>, nom: Option<&[u8]>, longueur: usize, drapeaux: u64, controle: Result<Controle, i64>,
               remplir: impl FnOnce(&mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    const MSG_CONFIRM: u64 = 0x800;
    const MSG_MORE: u64 = 0x8000;
    let mut inet = s.appels.verrouiller();
    datagramme::lier_au_besoin(s, &mut inet)?;
    if longueur > 0xFFFF {
        return Err(-EMSGSIZE);
    }
    if drapeaux & (MSG_OOB | MSG_MORE) != 0 {
        return Err(-EOPNOTSUPP);
    }
    let (adresse, port) = match nom {
        Some(o) => {
            let Some(a) = socket::lire_adresse(o) else { return Err(-EINVAL) };
            if a.famille != AF_INET && a.famille != AF_UNSPEC {
                return Err(-EAFNOSUPPORT);
            }
            if a.port == 0 {
                return Err(-EINVAL);
            }
            (a.adresse, a.port)
        }
        None if inet.connecte => (inet.distante, inet.port_distant),
        None => return Err(-EDESTADDRREQ),
    };
    let c = controle?;
    let datagramme::Trajet { chemin, destination: adresse, source } = datagramme::router(&inet, adresse, &c, drapeaux)?;
    if longueur + udp::ENTETE + format_ipv4::ENTETE > ipv4::mtu(&chemin) as usize {
        return Err(-EMSGSIZE);
    }
    if s.reception.verrouiller().arret & ARRET_ECRITURE != 0 {
        return Err(-EPIPE);
    }
    // DF avec IP_PMTUDISC_WANT, DO et PROBE (`__ip_make_skb`) ;
    // l'identifiant comme `ip_select_ident_segs` : celui de la socket si
    // elle est connectée (même pour un autre destinataire) ; 0 avec DO et
    // PROBE (un paquet que rien ne fragmentera, pas même nous :
    // `ignore_df` faux) ; sinon `ipv4::identifiant`.
    let ne_pas_fragmenter = matches!(inet.options.pmtudisc, 1..=3);
    let identifiant = if inet.connecte {
        inet.identifiant = inet.identifiant.wrapping_add(1);
        inet.identifiant
    } else if matches!(inet.options.pmtudisc, 2 | 3) {
        0
    } else {
        ipv4::identifiant()
    };
    let envoi = Envoi {
        source, destination: adresse, protocole: format_ipv4::UDP, ttl: c.ttl.or(inet.options.ttl).unwrap_or(64),
        tos: c.tos.unwrap_or(inet.options.tos), identifiant, ne_pas_fragmenter,
        confirmer: drapeaux & MSG_CONFIRM != 0,
    };
    let u = udp::Udp { source: inet.port, destination: port };
    drop(inet);
    let Some(mut p) = Paquet::vide(udp::ENTETE + longueur) else { return Err(-ENOBUFS) };
    let Some(segment) = p.ajouter_fin(udp::ENTETE + longueur) else { return Err(-ENOBUFS) };
    remplir(&mut segment[udp::ENTETE..])?;
    udp::ecrire(segment, &u, source, adresse);
    ipv4::emettre(chemin, &envoi, p);
    Ok(longueur)
}

/// Un datagramme UDP (`p` : le segment, en-tête compris, sans l'en-tête
/// d'IPv4) reçu par l'interface `interface`, pour `destination`, de
/// `source`, dans la tâche du réseau : `__udp4_lib_rcv`, la somme
/// vérifiée, puis la socket qui le reçoit ; une diffusion à chacune de
/// celles du port. Rend vrai si une socket l'a pris (sinon, ICMP « port
/// injoignable » : le commit suivant).
pub fn recevoir(interface: u32, source: [u8; 4], destination: [u8; 4], diffusion: bool, mut p: Paquet) -> bool {
    let Ok((u, charge)) = udp::lire(p.donnees(), source, destination) else {
        FAUX.fetch_add(1, Ordering::Relaxed);
        return true;
    };
    let longueur = charge.len();
    let _ = p.retirer_entete(udp::ENTETE);
    p.couper(longueur);
    if diffusion {
        // Une copie pour chacune, déposée sous le verrou de la table (son
        // ordre permet de prendre ensuite celui de la file d'une socket).
        if let Some(t) = PORTS.verrouiller().as_ref() {
            t.pour_chaque_diffusion(source, u.source, destination, u.destination, |s| {
                if let Some(copie) = Paquet::copie(p.donnees()) {
                    deposer(s, copie, source, u.source, destination, interface);
                }
            });
        }
        return true;
    }
    let s = PORTS.verrouiller().as_ref().and_then(|t| t.trouver(source, u.source, destination, u.destination));
    match s {
        Some(s) => {
            deposer(&s, p, source, u.source, destination, interface);
            true
        }
        None => {
            SANS_SOCKET.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

fn deposer(s: &Socket, p: Paquet, source: [u8; 4], port: u16, destination: [u8; 4], interface: u32) {
    let taille = p.taille_vraie();
    let d = Datagramme { paquet: p, source, port, destination, interface, taille };
    if !s.deposer(d) {
        FILE_PLEINE.fetch_add(1, Ordering::Relaxed);
    }
}

/// Le nombre de sockets dont quelqu'un attend une lecture (le détecteur
/// d'interblocage : attente.rs).
pub fn attentes() -> usize {
    let mut n = 0;
    if let Some(t) = PORTS.verrouiller().as_ref() {
        t.pour_chaque(|s| n += s.attente.active() as usize);
    }
    n
}
