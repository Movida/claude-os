//! Les sockets : ce qu'ont en commun toutes les sortes (la `struct socket`
//! et la `struct sock` de Linux, net/socket.c et net/core/sock.c).
//!
//! Choix de conception. Deux étages, comme Linux : la SOCKET, objet du
//! noyau derrière un fichier ouvert de sorte `Socket` (son `Prive`, comme
//! l'eventfd et le tube de 6f), avec ce qu'ont toutes les sortes : sa file
//! de réception, son erreur en attente (`sk_err`), ses drapeaux d'arrêt
//! (`shutdown`), ses options, sa file d'attente pour poll et epoll ; et son
//! PROTOCOLE (UDP, udp.rs), qui fait le reste. Un `enum` des protocoles
//! plutôt qu'une table de fonctions (les `proto_ops` de Linux) : une
//! poignée, et chaque `match` dit en un endroit ce que fait chacun ; TCP et
//! AF_UNIX y ajouteront une ligne (6h). Écarté : un objet par protocole
//! sans couche commune (chaque appel refaisait les vérifications communes,
//! et read, write, poll ne sauraient pas à qui parler).
//!
//! LES DEUX VERROUS DE LINUX :
//!   - un `Verrou` pour ce que touche la tâche du réseau quand un datagramme
//!     arrive (la file de réception et sa taille, l'erreur, l'arrêt) : le
//!     spinlock de `sk_receive_queue`. Il se prend après celui de la table
//!     des ports, jamais l'inverse ;
//!   - un `Mutex`, le `lock_sock` : ce que font les appels du programme
//!     (lier, connecter, envoyer, prendre un datagramme et le copier), que
//!     la tâche du réseau ne prend jamais. Un `recvmsg` attend sans aucun
//!     des deux (dans la file d'attente de la socket), puis prend le
//!     `Mutex` pour retirer ou lire (MSG_PEEK) le premier datagramme et le
//!     copier : deux fils qui lisent la même socket ne se marchent pas
//!     dessus, et un MSG_PEEK ne voit pas son datagramme disparaître
//!     pendant sa copie.
//!
//! La socket vit tant qu'on la tient : son fichier ouvert, un appel en
//! cours, la table des ports. Son DERNIER `close` (le fichier ouvert rendu,
//! `fichier_ferme`) l'accroche à la tâche, et la sortie de l'appel la
//! retire de la table des ports (6h : la fermeture différée de Linux,
//! `fermer_les_differees`) : elle ne reçoit plus rien, et ce qui restait
//! dans sa file est rendu avec elle. Un `recv` qui
//! dort dans un autre fil n'est pas réveillé (Linux non plus, mesuré) : il
//! tient la socket (le `fdget` de 6e) jusqu'à ce qu'un datagramme arrive.

use super::ipv4::EnteteRecu;
use super::paquet::Paquet;
use super::snmp::MIB;
use crate::appels_fichiers::FichierTenu;
use crate::attente::{self, FileAttente, Mutex, Sommeil};
use crate::descripteurs::{FichierOuvert, Prive};
use crate::partage::Arc;
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM, Table};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::faillible::{self, FileFaillible};
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU32, AtomicU64, Ordering};
use inet::snmp::Udp;

/// POLLRDHUP : l'autre côté a fermé (ou la lecture est arrêtée).
pub const POLLRDHUP: u32 = 0x2000;

// Les familles (include/linux/socket.h).
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
/// Le nombre de familles que connaît Linux (NPROTO = AF_MAX) : au-delà,
/// EAFNOSUPPORT sans chercher.
pub const NPROTO: u64 = 46;
// Les sortes.
pub const SOCK_DGRAM: u64 = 2;
pub const SOCK_RAW: u64 = 3;
pub const SOCK_MAX: u64 = 11;
/// Les drapeaux que `socket` accepte avec la sorte.
pub const SOCK_NONBLOCK: u64 = 0o4000;
pub const SOCK_CLOEXEC: u64 = 0o2000000;
// Les protocoles d'IPv4.
pub const IPPROTO_IP: u64 = 0;
pub const IPPROTO_ICMP: u64 = 1;
pub const IPPROTO_UDP: u64 = 17;
pub const IPPROTO_MAX: u64 = 263;

/// Les drapeaux d'arrêt (`sk_shutdown`).
pub const ARRET_LECTURE: u8 = 1;
pub const ARRET_ECRITURE: u8 = 2;

/// Les tailles des files, celles de Linux 6.18 (`sysctl_rmem_max` dans
/// net/core/sock.c, et mesurées) : la valeur par défaut (`rmem_default`,
/// `wmem_default`), le plafond d'une demande (`rmem_max`, `wmem_max` : 4 Mio,
/// qu'un SO_RCVBUF ou un SO_SNDBUF double ensuite), puis le minimum
/// (SOCK_MIN_RCVBUF, SOCK_MIN_SNDBUF : 2048 et deux fois 2048, plus la taille
/// d'un sk_buff).
pub const TAMPON_DEFAUT: u32 = 212_992;
pub const TAMPON_MAX: u32 = 4 << 20;
pub const RCVBUF_MIN: u32 = 2304;
pub const SNDBUF_MIN: u32 = 4608;

/// La taille d'une `sockaddr_in` (famille, port, adresse, 8 octets nuls).
pub const SOCKADDR_IN: usize = 16;

/// Une adresse d'IPv4 lue d'une `sockaddr_in` : sa famille (vérifiée par
/// l'appel, chacun à sa façon), son adresse et son port.
#[derive(Clone, Copy)]
pub struct AdresseInet {
    pub famille: u16,
    pub adresse: [u8; 4],
    pub port: u16,
}

/// Lit une `sockaddr_in` (la famille dans l'ordre de la machine, le port
/// et l'adresse dans celui du réseau). None : moins de 16 octets.
pub fn lire_adresse(o: &[u8]) -> Option<AdresseInet> {
    let o = o.get(..SOCKADDR_IN)?;
    Some(AdresseInet {
        famille: u16::from_le_bytes([o[0], o[1]]),
        port: u16::from_be_bytes([o[2], o[3]]),
        adresse: [o[4], o[5], o[6], o[7]],
    })
}

/// La famille seule d'une adresse (`sa_family`). None : moins de 2 octets.
pub fn famille(o: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes([*o.first()?, *o.get(1)?]))
}

/// Écrit une `sockaddr_in`.
pub fn sockaddr_in(adresse: [u8; 4], port: u16) -> [u8; SOCKADDR_IN] {
    let mut o = [0u8; SOCKADDR_IN];
    o[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    o[2..4].copy_from_slice(&port.to_be_bytes());
    o[4..8].copy_from_slice(&adresse);
    o
}

const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;

/// Le numéro de la prochaine socket (pour la table des ports).
static NUMEROS: AtomicU64 = AtomicU64::new(1);

/// Les sortes de sockets qui existent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocole {
    Udp,
    /// Les sockets de ping (ping.rs) : SOCK_DGRAM et IPPROTO_ICMP.
    Ping,
    /// TCP (tcp.rs, 6h) : SOCK_STREAM.
    Tcp,
    /// AF_UNIX (unix.rs, 6h) : les trois sortes.
    Unix,
}

/// La règle qui accepte un datagramme en file.
#[derive(Clone, Copy)]
pub enum Admission {
    /// Celle d'UDP (`__udp_enqueue_schedule_skb`) : une file vide accepte
    /// toujours ; sinon la taille vraie du datagramme doit tenir dans
    /// SO_RCVBUF.
    Udp,
    /// Celle des autres (`__sock_queue_rcv_skb`) : accepté tant que la file
    /// n'a pas atteint SO_RCVBUF, quelle que soit sa taille.
    Ordinaire,
}

/// Pourquoi un datagramme n'entre pas en file (les RcvbufErrors et
/// MemErrors d'UDP : `__udp_queue_rcv_skb`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rejet {
    /// SO_RCVBUF est plein (l'ENOMEM d'`__udp_enqueue_schedule_skb`).
    Pleine,
    /// Plus de mémoire pour la file (la mémoire du protocole qui manque, son
    /// ENOBUFS).
    Memoire,
}

// D'où vient une erreur de la file d'erreurs (SO_EE_ORIGIN_*).
pub const ORIGINE_LOCALE: u8 = 1;
pub const ORIGINE_ICMP: u8 = 2;

/// Une erreur dans la file d'erreurs (la `sk_error_queue` de Linux, avec
/// IP_RECVERR), lue par MSG_ERRQUEUE : sa `sock_extended_err` (l'errno,
/// l'origine, le genre et le code du message ICMP, son `info`), la
/// destination du paquet qui l'a causée (le `msg_name` rendu), qui l'a dite
/// (SO_EE_OFFENDER : la source du message ICMP), où ce message est arrivé
/// (IP_PKTINFO), ce que la réception a gardé de son en-tête et sa somme
/// (les autres messages de contrôle IP), et ce que lira le programme : ce
/// que le message portait de la charge d'origine (rien pour une erreur
/// locale).
pub struct ErreurEnFile {
    pub errno: i32,
    pub origine: u8,
    pub genre: u8,
    pub code: u8,
    pub info: u32,
    /// Le `ee_data` : où commencent les extensions du message (RFC 4884),
    /// si la socket avait IP_RECVERR_RFC4884 quand il est arrivé ; 0 sinon.
    pub ee_data: u32,
    pub adresse: [u8; 4],
    pub port: u16,
    pub emetteur: [u8; 4],
    pub interface: u32,
    pub arrivee: [u8; 4],
    pub entete: EnteteRecu,
    /// La somme de tout le message ICMP (IP_CHECKSUM : `icmp_rcv` l'a
    /// calculée en le vérifiant, CHECKSUM_COMPLETE).
    pub somme: u32,
    pub donnees: Paquet,
    /// Sa taille vraie (elle compte dans SO_RCVBUF, avec les datagrammes).
    pub taille: usize,
}

/// La somme d'un datagramme que rendra IP_CHECKSUM (le `skb->csum` de
/// Linux, quand il est CHECKSUM_COMPLETE) : voir udp.rs, `recevoir`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Somme {
    /// Jamais calculée en entier.
    Aucune,
    /// Calculée (la valeur de `formats::reseau::somme_linux`).
    Calculee(u32),
    /// À calculer, sur les données, par la lecture qui coupe le datagramme
    /// ou le regarde (MSG_PEEK) ; elle reste ensuite (`udp_recvmsg`,
    /// `__udp_lib_checksum_complete`).
    ALaLecture,
}

/// Un datagramme reçu, en file : sa charge (les données du paquet), qui
/// l'a envoyé, à quelle adresse et par quelle interface il est arrivé (pour
/// IP_PKTINFO), ce que la réception a gardé de son en-tête IP, les deux
/// octets 2 et 3 de son en-tête de transport (IP_ORIGDSTADDR : le port de
/// destination d'UDP, la somme d'un message ICMP), sa somme, et sa taille
/// vraie (ce qu'il compte dans SO_RCVBUF).
pub struct Datagramme {
    /// Un datagramme vide déjà vu par MSG_PEEK (`skb->peeked`) : SO_PEEK_OFF passe au suivant.
    pub regarde: bool,
    pub paquet: Paquet,
    pub source: [u8; 4],
    pub port: u16,
    pub destination: [u8; 4],
    /// L'interface et l'adresse locale que rendra IP_PKTINFO (le
    /// `PKTINFO_SKB_CB` de Linux) : ce qu'a préparé l'arrivée d'un datagramme
    /// UDP pour une socket qui avait IP_PKTINFO, sinon 0 et 0.0.0.0 (udp.rs) ;
    /// pour une réponse de ping, rien de préparé : l'interface qui l'a reçue
    /// et 0.0.0.0 (ping.rs).
    pub pktinfo: (u32, [u8; 4]),
    pub entete: EnteteRecu,
    pub port_destination: u16,
    pub somme: Somme,
    pub taille: usize,
}

impl ErreurEnFile {
    /// Une erreur « locale » (`ip_local_error`) : vue par l'envoi lui-même,
    /// sans message ICMP ni données. None : plus de mémoire.
    pub fn locale(errno: i32, info: u32, adresse: [u8; 4], port: u16) -> Option<ErreurEnFile> {
        let donnees = Paquet::vide(0)?;
        Some(ErreurEnFile {
            errno, origine: ORIGINE_LOCALE, genre: 0, code: 0, info, ee_data: 0, adresse, port, emetteur: [0; 4], interface: 0,
            arrivee: [0; 4], entete: EnteteRecu::AUCUN, somme: 0, taille: donnees.taille_vraie(), donnees,
        })
    }

    /// Ce que diront ses messages de contrôle IP : pour une erreur venue
    /// d'ICMP seulement (`ipv4_datagram_support_cmsg`). Les « ports »
    /// d'IP_ORIGDSTADDR sont les octets 2 et 3 de ce que lira le programme :
    /// Linux fait de sa charge l'en-tête de transport de l'erreur
    /// (`ip_icmp_error`), et n'en dit rien si elle a moins de 4 octets
    /// (mesuré : UDP « abc », aucun ; un écho, sa somme).
    pub fn controle(&self) -> Option<ControleIp> {
        if self.origine != ORIGINE_ICMP {
            return None;
        }
        let port = self.donnees.donnees().get(..4).map(|o| u16::from_be_bytes([o[2], o[3]]));
        Some(ControleIp { entete: self.entete, source: self.emetteur, port, somme: Some(self.somme) })
    }
}

/// Ce que disent les messages de contrôle IP d'une réception, après
/// IP_PKTINFO (`ip_cmsg_recv_offset`) : l'en-tête reçu et sa source (que
/// retire l'écho d'une route source), les octets 2 et 3 de l'en-tête de
/// transport (None : il n'y en a pas quatre), et la somme (None : pas de
/// somme complète), déjà réduite de ce que SO_PEEK_OFF a passé.
#[derive(Clone, Copy)]
pub struct ControleIp {
    pub entete: EnteteRecu,
    pub source: [u8; 4],
    pub port: Option<u16>,
    pub somme: Option<u32>,
}

/// Ce que touche la tâche du réseau (sous le `Verrou`).
pub struct Reception {
    pub file: VecDeque<Datagramme>,
    /// La file d'erreurs (IP_RECVERR).
    pub erreurs: VecDeque<ErreurEnFile>,
    /// La taille vraie de ce qui est en file, dans les deux files
    /// (`sk_rmem_alloc`).
    pub octets: usize,
    /// L'erreur en attente (`sk_err`, un errno positif ; 0 : aucune).
    pub erreur: i32,
    /// ARRET_LECTURE, ARRET_ECRITURE.
    pub arret: u8,
}

/// Les options d'une socket que lisent ses appels (sous le `Mutex`).
#[derive(Clone, Copy)]
pub struct Options {
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub broadcast: bool,
    pub keepalive: bool,
    /// SO_DEBUG (root seul) et SO_OOBINLINE : gardés et relus, sans effet
    /// sur UDP ; SO_NO_CHECK : UDP envoie sans somme (udp.rs, `emettre`) ;
    /// SO_DONTROUTE : seulement les machines d'un réseau directement
    /// branché (datagramme::router).
    pub debug: bool,
    pub dontroute: bool,
    pub oobinline: bool,
    pub no_check: bool,
    pub priority: u32,
    pub linger: (bool, u32),
    pub rcvlowat: u32,
    /// Les délais de réception et d'émission (SO_RCVTIMEO, SO_SNDTIMEO), en
    /// nanosecondes, déjà arrondis au tic ; None : sans délai.
    pub rcvtimeo: Option<u64>,
    pub sndtimeo: Option<u64>,
    pub tos: u8,
    /// IP_TTL : None, celui du système (64).
    pub ttl: Option<u8>,
    pub pktinfo: bool,
    /// IP_UNICAST_IF : l'interface des envois sans IP_PKTINFO, sauf vers une
    /// multidiffusion (le `uc_index` de Linux ; datagramme::router) ; 0 :
    /// aucune. TCP le garde sans s'en servir (`tcp_v4_connect` ne le lit pas).
    pub unicast_if: u32,
    /// SO_BINDTODEVICE et SO_BINDTOIFINDEX : l'interface à laquelle la socket
    /// est liée (`sk_bound_dev_if`, son index) ; 0 : aucune. Les tables de
    /// ports en gardent la copie, lue à chaque recherche et à chaque conflit
    /// (`datagramme::table::interface_changee`) ; c'est l'interface des envois
    /// d'UDP et de ping quand IP_PKTINFO n'en donne pas (`interface_demandee`),
    /// la seule de TCP (sa copie, `OptionsTcp::interface`). AF_UNIX la garde
    /// sans s'en servir, comme Linux.
    pub interface: u32,
    pub recverr: bool,
    /// IP_MTU_DISCOVER (IP_PMTUDISC_WANT, 1, par défaut).
    pub pmtudisc: u8,
    /// UDP_CORK : tout envoi bouche la socket (udp.rs, `Bouchon`).
    pub udp_cork: bool,
    /// Les drapeaux de SOL_IP qui demandent un message de contrôle à la
    /// réception (IP_RECVTTL, IP_RECVTOS, IP_RECVOPTS, IP_RETOPTS,
    /// IP_PASSSEC, IP_RECVORIGDSTADDR, IP_CHECKSUM, IP_RECVFRAGSIZE), et
    /// IP_RECVERR_RFC4884 (les extensions d'une erreur ICMP en file).
    pub recvttl: bool,
    pub recvtos: bool,
    pub recvopts: bool,
    pub retopts: bool,
    pub passsec: bool,
    pub origdstaddr: bool,
    pub checksum: bool,
    pub recvfragsize: bool,
    pub rfc4884: bool,
    /// IP_FREEBIND et IP_TRANSPARENT : `bind` d'une adresse qui n'est pas à
    /// nous (`inet_can_nonlocal_bind`) ; IP_TRANSPARENT envoie aussi depuis
    /// elle (FLOWI_FLAG_ANYSRC).
    pub freebind: bool,
    pub transparent: bool,
    /// IP_BIND_ADDRESS_NO_PORT : `bind(adresse, 0)` ne prend pas de port ;
    /// il viendra au premier envoi ou au `connect`.
    pub bind_no_port: bool,
    /// IP_MINTTL (TCP) : un segment reçu de TTL plus petit est jeté.
    pub minttl: u8,
    /// IP_LOCAL_PORT_RANGE, tel que donné (inet::ports::plage).
    pub local_port_range: u32,
    /// Le TTL des paquets de multidiffusion (`mc_ttl`, 1), l'index de leur
    /// interface (`mc_index`, 0), et le TOS reçu (`rcv_tos`) : une fille de
    /// TCP prend les trois du dernier segment de sa poignée de main
    /// (`tcp_v4_syn_recv_sock`), que rend IP_PKTOPTIONS.
    pub mc_ttl: u8,
    pub mc_index: u32,
    pub rcv_tos: u8,
    /// IP_MULTICAST_IF : l'adresse demandée avec l'interface (`mc_addr`), la
    /// source d'un envoi vers un groupe qui n'en a pas d'autre ; et
    /// IP_MULTICAST_LOOP (`MC_LOOP`, 1) : un envoi vers un groupe de la
    /// machine lui en rend une copie.
    pub mc_addr: [u8; 4],
    pub mc_loop: bool,
    /// IP_OPTIONS : les options de chaque envoi (`inet_opt`), vérifiées pour
    /// l'envoi (formats, `options_a_envoyer`).
    pub ip_options: formats::reseau::ipv4::OptionsSortantes,
}

impl Options {
    const DEFAUT: Options = Options {
        reuseaddr: false, reuseport: false, broadcast: false, keepalive: false, debug: false, dontroute: false,
        oobinline: false, no_check: false, priority: 0, linger: (false, 0), rcvlowat: 1,
        rcvtimeo: None, sndtimeo: None, tos: 0, ttl: None, pktinfo: false, unicast_if: 0, interface: 0, recverr: false, pmtudisc: 1,
        udp_cork: false, recvttl: false, recvtos: false, recvopts: false, retopts: false, passsec: false,
        origdstaddr: false, checksum: false, recvfragsize: false, rfc4884: false, freebind: false, transparent: false,
        bind_no_port: false, minttl: 0, local_port_range: 0, mc_ttl: 1, mc_index: 0, rcv_tos: 0, mc_addr: [0; 4], mc_loop: true,
        ip_options: formats::reseau::ipv4::OptionsSortantes::AUCUNE,
    };
}

/// Où est la socket (l'`inet_sock` de Linux), et ses options : sous le
/// `Mutex`.
pub struct Inet {
    /// A-t-elle un port (dans la table des ports) ?
    pub lie: bool,
    pub adresse: [u8; 4],
    pub port: u16,
    /// Le port a-t-il été choisi par `bind` (SOCK_BINDPORT_LOCK : gardé à
    /// la déconnexion), l'adresse aussi (SOCK_BINDADDR_LOCK) ?
    pub port_choisi: bool,
    pub adresse_choisie: bool,
    pub connecte: bool,
    pub distante: [u8; 4],
    pub port_distant: u16,
    /// L'adresse source de la connexion (pour getsockname).
    pub source: [u8; 4],
    /// La route qu'a gardée `connect` (le `sk_dst_cache` de Linux), dite par
    /// l'interface qu'elle demandait (0 : aucune) : la destination et la
    /// source sont à côté, et les routes ne changent plus après le
    /// démarrage. Un envoi d'UDP sur la connexion la reprend
    /// (datagramme::preparer), IP_MTU la lit. None : pas de route gardée.
    pub route_gardee: Option<u32>,
    /// L'identifiant IP des paquets d'une socket connectée (l'`inet_id`).
    pub identifiant: u16,
    pub options: Options,
    /// Le datagramme d'UDP qui s'assemble (MSG_MORE, UDP_CORK).
    pub bouchon: Option<super::udp::Bouchon>,
}

pub struct Socket {
    pub numero: u64,
    pub protocole: Protocole,
    /// La sorte et le protocole demandés (SO_TYPE, SO_PROTOCOL).
    pub sorte: u16,
    pub proto: u16,
    /// L'utilisateur qui l'a créée (SO_REUSEPORT ; un port privilégié).
    pub uid: u32,
    /// Qui attend : `recv`, `poll`, epoll (le `sk_wq`). Dans un Arc : le
    /// relais d'une socket AF_UNIX (unix.rs, attente.rs) la tient comme
    /// cible tant qu'il est inscrit chez son pair.
    pub attente: Arc<FileAttente>,
    pub reception: Verrou<Reception>,
    pub appels: Mutex<Inet>,
    /// SO_RCVBUF et SO_SNDBUF (lus par la tâche du réseau sans le Mutex).
    pub rcvbuf: AtomicU32,
    pub sndbuf: AtomicU32,
    /// Ce que la tâche du réseau doit savoir d'une socket quand une erreur
    /// ICMP arrive, sans prendre le `Mutex` : est-elle connectée (le
    /// `sk_state` de Linux) ? a-t-elle IP_RECVERR (un bit atomique de
    /// Linux aussi) ? et IP_MTU_DISCOVER (lu par READ_ONCE chez Linux) ?
    /// Écrits sous le `Mutex`, avec leurs copies d'`Inet`.
    pub connectee: AtomicBool,
    pub recverr: AtomicBool,
    pub pmtudisc: AtomicU8,
    /// IP_RECVERR_RFC4884, lu par la tâche du réseau quand elle met une
    /// erreur ICMP en file (un bit atomique de Linux, `inet_test_bit`, lu à
    /// ce moment-là : le poser ensuite ne change pas les erreurs déjà en
    /// file). UDP et ping seulement : TCP n'a pas de file d'erreurs
    /// (`tcp_v4_err` n'appelle pas `ip_icmp_error`).
    pub rfc4884: AtomicBool,
    /// IP_PKTINFO, lu par la tâche du réseau à l'arrivée d'un datagramme UDP,
    /// qu'il fait préparer (`ipv4_pktinfo_prepare`, un bit de Linux lu à ce
    /// moment-là : posé ensuite, il ne vaut que pour les suivants, mesuré).
    pub pktinfo: AtomicBool,
    /// IP_MULTICAST_ALL (`MC_ALL`, 1), lu par la tâche du réseau à la
    /// livraison d'un datagramme pour un groupe : sans adhésion à ce groupe,
    /// la socket le reçoit-elle (multidiffusion.rs, `permet`) ?
    pub mc_all: AtomicBool,
    /// Ses adhésions à des groupes (inet::multidiffusion), sous leur verrou :
    /// la livraison les lit sans le `Mutex`, qui dort. Une fille de TCP n'en
    /// hérite pas.
    pub adhesions: Verrou<inet::multidiffusion::Adhesions>,
    /// Un envoi a manqué de place dans SO_SNDBUF (le bit SOCK_NOSPACE de
    /// Linux, tel que le voit une socket de datagrammes : posé par
    /// `sock_alloc_send_pskb`, jamais effacé, `sock_def_write_space` ne le
    /// touche pas) : toute erreur d'un envoi UDP compte alors un
    /// SndbufErrors (udp.rs).
    pub place_manquee: AtomicBool,
    /// Ceux qui veulent un signal (O_ASYNC) et le propriétaire de son fichier ; pour TCP, ils sont
    /// avec sa possession : voir `liste_async`.
    pub asynchrone: crate::asynchrone::ListeAsync,
    /// Le numéro de son inode (/proc/net/tcp le montre), posé quand son
    /// fichier est fait ; 0 avant (une fille d'une écoute pas encore
    /// acceptée n'en a pas, chez Linux non plus).
    pub inode: AtomicU32,
    /// SO_PEEK_OFF (`sk_peek_off`) : où MSG_PEEK reprend, en octets depuis le début de ce qui est à
    /// lire ; négatif : il ne s'en sert pas, et regarde toujours la tête (-1, le défaut).
    pub peek_off: AtomicI32,
    /// La suivante des sockets qu'une tâche a à fermer (sa liste
    /// `Tache::fermetures`, voir `fichier_ferme`).
    suivante: Verrou<Option<Arc<Socket>>>,
    /// Le flux d'une socket TCP (tcp.rs) : sa possession et sa connexion.
    pub flux: Option<alloc::boxed::Box<crate::attente::Possession<super::tcp::Partie>>>,
    /// La partie d'une socket AF_UNIX (unix.rs).
    pub unix: Option<alloc::boxed::Box<super::unix::Unix>>,
    /// Ce qu'une socket de datagrammes (UDP, ping) a encore en route, compté dans
    /// SO_SNDBUF (le `sk_wmem_alloc`, paquet.rs ; les soldes d'avant 6k : jusque-là, un
    /// envoi n'attendait jamais). TCP a la sienne, dans son flux.
    pub envois: Option<Arc<super::paquet::Retenue>>,
}

impl Socket {
    /// Une socket neuve, sans port ; None : plus de mémoire (pour sa file
    /// d'attente).
    pub fn new(protocole: Protocole, sorte: u16, proto: u16, uid: u32) -> Option<Socket> {
        let numero = NUMEROS.fetch_add(1, Ordering::Relaxed);
        let attente = Arc::new(FileAttente::new()).ok()?;
        let envois = match protocole {
            Protocole::Udp | Protocole::Ping => {
                Some(Arc::new(super::paquet::Retenue::pour_datagrammes(numero, TAMPON_DEFAUT as usize, attente.clone())).ok()?)
            }
            Protocole::Tcp | Protocole::Unix => None,
        };
        Some(Socket {
            numero,
            protocole, sorte, proto, uid,
            attente,
            reception: Verrou::new(Reception { file: VecDeque::new(), erreurs: VecDeque::new(), octets: 0, erreur: 0, arret: 0 }),
            appels: Mutex::new(Inet {
                lie: false, adresse: [0; 4], port: 0, port_choisi: false, adresse_choisie: false, connecte: false,
                distante: [0; 4], port_distant: 0, source: [0; 4], route_gardee: None, identifiant: 0, options: Options::DEFAUT,
                bouchon: None,
            }),
            rcvbuf: AtomicU32::new(TAMPON_DEFAUT),
            sndbuf: AtomicU32::new(TAMPON_DEFAUT),
            connectee: AtomicBool::new(false),
            recverr: AtomicBool::new(false),
            place_manquee: AtomicBool::new(false),
            pmtudisc: AtomicU8::new(Options::DEFAUT.pmtudisc),
            rfc4884: AtomicBool::new(false),
            pktinfo: AtomicBool::new(false),
            mc_all: AtomicBool::new(true),
            adhesions: Verrou::new(inet::multidiffusion::Adhesions::new()),
            asynchrone: crate::asynchrone::ListeAsync::new(),
            inode: AtomicU32::new(0),
            peek_off: AtomicI32::new(-1),
            suivante: Verrou::new(None),
            flux: None,
            unix: None,
            envois,
        })
    }

    /// La liste O_ASYNC de la socket : celle qui suit la réception (`socket_wq`).
    pub fn liste_async(&self) -> &crate::asynchrone::ListeAsync {
        match &self.flux {
            Some(f) => &f.asynchrone,
            None => &self.asynchrone,
        }
    }

    /// Une socket AF_UNIX de sorte `sorte`. None : plus de mémoire.
    pub fn unix(mut self, sorte: super::unix::Sorte) -> Option<Socket> {
        self.unix = Some(faillible::boite(super::unix::Unix::new(sorte)?).ok()?);
        Some(self)
    }

    /// Où MSG_PEEK commence (`max(sk_peek_offset(sk, flags), 0)`).
    pub fn decalage_de_peek(&self) -> usize {
        self.peek_off.load(Ordering::Relaxed).max(0) as usize
    }

    /// `n` octets regardés (`sk_peek_offset_fwd`).
    pub fn peek_avance(&self, n: usize) {
        let o = self.peek_off.load(Ordering::Relaxed);
        if o >= 0 {
            self.peek_off.store(o.saturating_add(n.min(i32::MAX as usize) as i32), Ordering::Relaxed);
        }
    }

    /// `n` octets retirés (`sk_peek_offset_bwd`) : la place de MSG_PEEK, comptée depuis le début de ce
    /// qui est à lire, recule d'autant.
    pub fn peek_recule(&self, n: usize) {
        let o = self.peek_off.load(Ordering::Relaxed);
        if o >= 0 {
            self.peek_off.store(o.saturating_sub(n.min(i32::MAX as usize) as i32).max(0), Ordering::Relaxed);
        }
    }

    /// Une socket TCP : son flux, et ses tampons de départ (`tcp_rmem[1]`,
    /// `tcp_wmem[1]`). None : plus de mémoire pour le flux.
    pub fn tcp(mut self) -> Option<Socket> {
        self.flux = Some(faillible::boite(super::tcp::nouvelle(self.numero)?).ok()?);
        self.rcvbuf.store(super::tcp::RCVBUF_DEFAUT, Ordering::Relaxed);
        self.sndbuf.store(super::tcp::SNDBUF_DEFAUT, Ordering::Relaxed);
        Some(self)
    }

    /// La même, avec un flux déjà fait (la fille d'une écoute, à
    /// `accept`).
    pub fn avec_flux(mut self, f: alloc::boxed::Box<crate::attente::Possession<super::tcp::Partie>>) -> Socket {
        self.flux = Some(f);
        self.rcvbuf.store(super::tcp::RCVBUF_DEFAUT, Ordering::Relaxed);
        self.sndbuf.store(super::tcp::SNDBUF_DEFAUT, Ordering::Relaxed);
        self
    }

    /// La même, avec le numéro `n` (celui de la fille, déjà dans la table).
    pub fn avec_numero(mut self, n: u64) -> Socket {
        self.numero = n;
        self
    }

    /// Dépose un datagramme reçu (dans la tâche du réseau), si la règle
    /// `admission` le permet ; puis ceux qui attendent sont réveillés (le
    /// `sock_def_readable`). Err : jeté, la file pleine (SO_RCVBUF), ou
    /// plus de mémoire pour elle.
    pub fn deposer(&self, d: Datagramme, admission: Admission) -> Result<(), Rejet> {
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        {
            let mut r = self.reception.verrouiller();
            let refuse = match admission {
                Admission::Udp => r.octets > 0 && r.octets + d.taille > rcvbuf,
                Admission::Ordinaire => r.octets >= rcvbuf,
            };
            if refuse {
                return Err(Rejet::Pleine);
            }
            let taille = d.taille;
            if r.file.ajouter_derriere(d).is_err() {
                return Err(Rejet::Memoire);
            }
            r.octets += taille;
        }
        self.attente.reveiller(POLLIN | POLLRDNORM, 1);
        self.asynchrone.lecture(crate::asynchrone::Raison::Entree);
        Ok(())
    }

    /// Pose l'erreur `errno` (`sk_err`) et réveille (le `sk_error_report`).
    pub fn signaler_erreur(&self, errno: i32) {
        self.reception.verrouiller().erreur = errno;
        self.attente.reveiller(POLLERR, 1);
        self.asynchrone.evenement(crate::asynchrone::Raison::Erreur);
    }

    /// Met l'erreur `e` dans la file d'erreurs, s'il y a la place
    /// (`sock_queue_err_skb` : elle compte avec les datagrammes, et doit
    /// laisser de la place sous SO_RCVBUF), et réveille. false : jetée.
    pub fn mettre_en_file(&self, e: ErreurEnFile) -> bool {
        // (`sock_queue_err_skb` : `sk_error_report`.)
        let raison = crate::asynchrone::Raison::Erreur;
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        {
            let mut r = self.reception.verrouiller();
            let taille = e.taille;
            if r.octets + taille >= rcvbuf || r.erreurs.ajouter_derriere(e).is_err() {
                return false;
            }
            r.octets += taille;
        }
        self.attente.reveiller(POLLERR, 1);
        self.asynchrone.evenement(raison);
        true
    }

    /// Prend la première erreur de la file (`sock_dequeue_err_skb`) : l'erreur
    /// en attente devient celle de la suivante si elle vient d'ICMP, ou 0 si
    /// celle-ci en venait et qu'il n'en reste pas d'ICMP ; une erreur locale
    /// n'y touche pas. S'il en reste, ceux qui attendent sont réveillés.
    pub fn prendre_en_file(&self) -> Option<ErreurEnFile> {
        let (e, reste) = {
            let mut r = self.reception.verrouiller();
            let e = r.erreurs.pop_front()?;
            r.octets = r.octets.saturating_sub(e.taille);
            let suivante_icmp = r.erreurs.front().filter(|s| s.origine == ORIGINE_ICMP).map(|s| s.errno);
            if let Some(errno) = suivante_icmp {
                r.erreur = errno;
            } else if e.origine == ORIGINE_ICMP {
                r.erreur = 0;
            }
            (e, !r.erreurs.is_empty())
        };
        if reste {
            self.attente.reveiller(POLLERR, 1);
            self.asynchrone.evenement(crate::asynchrone::Raison::Erreur);
        }
        Some(e)
    }

    /// Vide la file d'erreurs (IP_RECVERR remis à 0).
    pub fn vider_erreurs(&self) {
        let mut r = self.reception.verrouiller();
        let rendus: usize = r.erreurs.iter().map(|e| e.taille).sum();
        r.octets = r.octets.saturating_sub(rendus);
        r.erreurs.clear();
    }

    /// Prend l'erreur en attente (le `sock_error` : lue et effacée).
    pub fn prendre_erreur(&self) -> i32 {
        core::mem::take(&mut self.reception.verrouiller().erreur)
    }

    /// Ce qu'on peut faire de la socket sans attendre (le `datagram_poll`
    /// de Linux) : une erreur en attente ou en file (POLLERR), l'arrêt de la lecture (POLLRDHUP,
    /// et POLLIN : un recv rendra 0), les deux arrêts (POLLHUP), un
    /// datagramme en file (POLLIN), et l'écriture si moins de la moitié de
    /// SO_SNDBUF est en route (`sock_writeable` ; sinon, la place a manqué :
    /// SOCKWQ_ASYNC_NOSPACE, pour SIGIO).
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        if let Some(f) = &self.flux {
            table.attendre(&f.file, tenu);
            return super::tcp::sonder(self);
        }
        if self.unix.is_some() {
            table.attendre(&self.attente, tenu);
            return super::unix::sonder(self);
        }
        table.attendre(&self.attente, tenu);
        let ecriture = match &self.envois {
            Some(e) if !e.ecriture_possible() => {
                self.asynchrone.marquer_sans_place(|| !e.ecriture_possible());
                e.marquer_sans_place(|| !e.ecriture_possible());
                0
            }
            _ => POLLOUT | POLLWRNORM | POLLWRBAND,
        };
        let r = self.reception.verrouiller();
        let mut m = ecriture;
        if r.erreur != 0 || !r.erreurs.is_empty() {
            m |= POLLERR;
        }
        if r.arret & ARRET_LECTURE != 0 {
            m |= POLLRDHUP | POLLIN | POLLRDNORM;
        }
        if r.arret == ARRET_LECTURE | ARRET_ECRITURE {
            m |= POLLHUP;
        }
        if !r.file.is_empty() {
            m |= POLLIN | POLLRDNORM;
        }
        m
    }

    /// Attend qu'il y ait de quoi lire : un datagramme, une erreur, ou
    /// l'arrêt de la lecture (le `__skb_wait_for_more_packets`). Ok : il y
    /// en a. EAGAIN : l'échéance `echeance` (celle de SO_RCVTIMEO, en temps
    /// monotone) passée ; un signal : ERESTARTSYS
    /// sans délai, EINTR avec (le `sock_intr_errno` de Linux : un appel qui
    /// a un délai n'est pas refait). L'attente est exclusive : un datagramme
    /// arrivé ne réveille qu'un des fils qui attendent (le
    /// `prepare_to_wait_exclusive` de Linux), pas tous pour un seul.
    pub fn attendre_lecture(&self, echeance: Option<u64>, deja: usize) -> Result<(), i64> {
        const EINTR: i64 = 4;
        let pret = || {
            let r = self.reception.verrouiller();
            r.file.len() > deja || r.erreur != 0 || r.arret & ARRET_LECTURE != 0
        };
        if pret() {
            return Ok(());
        }
        // Les sept pas d'attente.rs (`attendre_que`) : la condition est
        // revue une dernière fois après l'échéance ou le signal (un
        // datagramme arrivé en même temps se lit).
        match attente::attendre_que(&self.attente, attente::Inscription::Exclusive, Sommeil::Interruptible, echeance, pret) {
            Reveil::Reveillee => Ok(()),
            Reveil::Echeance => Err(-EAGAIN),
            Reveil::Signal => Err(if echeance.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
        }
    }

    /// Arrête la lecture, l'écriture, ou les deux (les drapeaux de
    /// `shutdown`), et réveille tout le monde : un recv bloqué rend 0.
    pub fn arreter(&self, arret: u8) {
        self.reception.verrouiller().arret |= arret;
        self.attente.reveiller(0, 0);
    }

    /// La longueur du premier datagramme en file (FIONREAD, SIOCINQ : pas le
    /// total, mesuré), 0 sans datagramme.
    pub fn premier(&self) -> usize {
        self.reception.verrouiller().file.front().map_or(0, |d| d.paquet.longueur())
    }
}

/// Ce que rend une réception : la longueur copiée (ou, avec MSG_TRUNC, la
/// vraie), l'émetteur, l'adresse d'arrivée et son interface, si le
/// datagramme a été coupé, et ses messages de contrôle IP (None : il n'en a
/// pas) ; `vide` : aucun datagramme (la lecture arrêtée), donc pas
/// d'émetteur à dire.
pub struct Recu {
    pub vide: bool,
    pub longueur: usize,
    pub source: [u8; 4],
    pub port: u16,
    pub destination: [u8; 4],
    /// L'interface et l'adresse locale d'IP_PKTINFO (`Datagramme::pktinfo`).
    pub pktinfo: (u32, [u8; 4]),
    pub coupe: bool,
    pub ip: Option<ControleIp>,
}

impl Recu {
    /// Rien de reçu, ou un flux : ni émetteur, ni messages de contrôle IP.
    pub fn sans_emetteur(longueur: usize, coupe: bool) -> Recu {
        Recu { vide: true, longueur, source: [0; 4], port: 0, destination: [0; 4], pktinfo: (0, [0; 4]), coupe, ip: None }
    }
}

/// Prend (ou lit, MSG_PEEK) le premier datagramme et le copie par `copier`
/// (au plus ce qu'elle peut prendre : elle rend combien elle a copié, ou
/// EFAULT), dans l'ordre d'`__skb_recv_udp` : l'erreur en attente d'abord
/// (lue et effacée), même s'il y a des datagrammes ; puis le premier
/// datagramme ; rien : EAGAIN sans attendre (MSG_DONTWAIT, le fichier en
/// O_NONBLOCK) ; une lecture arrêtée : 0 ; sinon attendre, au plus
/// SO_RCVTIMEO. Le datagramme est retiré sous le `Mutex`, puis copié sans
/// le `Verrou` (une copie peut fauter, et dormir pour servir une faute de
/// page). Un datagramme plus long que ce qui est copié est coupé, et le
/// reste perdu (MSG_TRUNC le dit dans `msg_flags`, ou fait rendre la vraie
/// longueur, pour UDP).
///
/// MSG_PEEK laisse le datagramme en file : Linux le copie depuis la file,
/// le paquet tenu par un compteur de références (`skb_get`). Le nôtre est
/// copié d'abord dans un tampon du noyau, sous le `Verrou`, puis de là au
/// programme : une copie de plus (un écart, pour MSG_PEEK seulement), et
/// pas de paquet partagé entre la file et l'appel.
pub fn prendre(s: &Socket, place: usize, drapeaux: u64, non_bloquant: bool, mut copier: impl FnMut(&[u8]) -> Result<usize, i64>)
               -> Result<Recu, i64> {
    // MSG_TRUNC fait rendre la vraie longueur à UDP (`udp_recvmsg`), pas à
    // ping (`ping_recvmsg` rend ce qu'il a copié).
    let vraie = s.protocole == Protocole::Udp;
    const MSG_PEEK: u64 = 2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    let delai = s.appels.verrouiller().options.rcvtimeo;
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    // SO_RCVTIMEO négatif : 0, une réception qui n'attend pas (Linux).
    let non_bloquant = non_bloquant || drapeaux & MSG_DONTWAIT != 0 || delai == Some(0);
    // Les datagrammes que le décalage de MSG_PEEK a déjà passés : il en faut un de plus.
    let mut deja;
    loop {
        let erreur = s.prendre_erreur();
        if erreur != 0 {
            return Err(-(erreur as i64));
        }
        {
            let _appel = s.appels.verrouiller();
            let mut r = s.reception.verrouiller();
            // MSG_PEEK et SO_PEEK_OFF (`__skb_try_recv_from_queue`) : le datagramme où tombe le
            // décalage, et la place dedans ; un datagramme vide compte une fois, regardé.
            let regarder = drapeaux & MSG_PEEK != 0;
            let decalage = if regarder { s.peek_off.load(Ordering::Relaxed) } else { -1 };
            let mut reste = decalage.max(0) as usize;
            let k = r.file.iter().position(|d| {
                let n = d.paquet.longueur();
                if decalage >= 0 && reste >= n && (reste > 0 || d.regarde) {
                    reste -= n;
                    return false;
                }
                true
            });
            deja = if k.is_none() { r.file.len() } else { 0 };
            if let Some(k) = k {
                let premier = &mut r.file[k];
                let (source, port, destination, pktinfo) = (premier.source, premier.port, premier.destination, premier.pktinfo);
                let total = premier.paquet.longueur();
                let dispo = total - reste;
                // La somme d'UDP qui attend une lecture qui coupe ou qui regarde
                // (`a_sommer`) se calcule hors du `Verrou` (jusqu'à 64 Kio,
                // interruptions coupées sinon : la tâche du réseau attendrait),
                // sur la copie de MSG_PEEK ou sur le datagramme pris (voir
                // `somme_lue`).
                let etat = premier.somme;
                let a_sommer = etat == Somme::ALaLecture && (regarder || place < total);
                let mut ip = ControleIp { entete: premier.entete, source: premier.source, port: Some(premier.port_destination), somme: None };
                let copie = if regarder {
                    premier.regarde |= total == 0;
                    // Tout le datagramme si sa somme est à faire ou à couper au
                    // décalage (elle porte sur lui entier) ; sinon depuis le
                    // décalage.
                    let debut = if etat != Somme::Aucune && (a_sommer || reste > 0) { 0 } else { reste };
                    let v = faillible::copie(&premier.paquet.donnees()[debut..]).map_err(|_| -ENOMEM)?;
                    drop(r);
                    let brute = somme_lue(etat, a_sommer, &v);
                    // Gardée dans la file : le `Mutex` tenu, personne d'autre
                    // ne prend de datagramme (la tâche du réseau ne fait
                    // qu'ajouter derrière), le k-ième est toujours celui-là.
                    if a_sommer
                        && let Some(b) = brute
                        && let Some(d) = s.reception.verrouiller().file.get_mut(k)
                    {
                        d.somme = Somme::Calculee(b);
                    }
                    ip.somme = brute.map(|b| sans_le_decalage(s, b, &v, reste));
                    copier(&v[reste - debut..])?
                } else {
                    let d = r.file.pop_front().expect("le premier datagramme");
                    r.octets = r.octets.saturating_sub(d.taille);
                    drop(r);
                    ip.somme = somme_lue(etat, a_sommer, d.paquet.donnees());
                    let copie = copier(d.paquet.donnees());
                    // `udp_recvmsg` : un datagramme retiré est lu (InDatagrams), ou perdu
                    // dans une copie qui faute (InErrors) ; MSG_PEEK ne compte rien.
                    if s.protocole == Protocole::Udp {
                        MIB.udp(if copie.is_ok() { Udp::InDatagrams } else { Udp::InErrors });
                    }
                    copie?
                };
                // `udp_recvmsg` : plus de place qu'il n'en reste à copier : rien de coupé, même si
                // le décalage en a passé ; sinon, moins de place que le datagramme : coupé.
                let coupe = place <= dispo && place < total;
                let longueur = if vraie && drapeaux & MSG_TRUNC != 0 { total } else { copie };
                if regarder {
                    s.peek_avance(longueur);
                } else {
                    s.peek_recule(longueur);
                }
                return Ok(Recu { vide: false, longueur, source, port, destination, pktinfo, coupe, ip: Some(ip) });
            }
        }
        // Rien en file : EAGAIN sans attendre, même après l'arrêt de la
        // lecture (Linux ne regarde l'arrêt qu'en attendant) ; sinon une
        // lecture arrêtée rend 0, et on attend.
        if non_bloquant {
            return Err(-EAGAIN);
        }
        if s.reception.verrouiller().arret & ARRET_LECTURE != 0 {
            return Ok(Recu::sans_emetteur(0, false));
        }
        s.attendre_lecture(echeance, deja)?;
    }
}

/// La somme d'un datagramme lu (`etat`), pour IP_CHECKSUM, sur ses `donnees` entières :
/// celle qui attend une lecture qui coupe ou qui regarde (`a_sommer`) est calculée là
/// (`udp_recvmsg` : `copied < ulen || peeking`) ; Linux la calcule pour vérifier le
/// datagramme avant de le copier, que ce soit demandé ou non, et la garde : un
/// IP_CHECKSUM posé ensuite la verra (`prendre` la range dans la file).
fn somme_lue(etat: Somme, a_sommer: bool, donnees: &[u8]) -> Option<u32> {
    match etat {
        Somme::Aucune => None,
        Somme::Calculee(v) => Some(v),
        Somme::ALaLecture if a_sommer => Some(formats::reseau::somme_linux(donnees)),
        Somme::ALaLecture => None,
    }
}

/// La somme `v` d'un datagramme regardé avec un décalage (SO_PEEK_OFF) : Linux en ôte
/// celle des octets passés (`ip_cmsg_recv_checksum`, `csum_sub`) ; ping n'en a pas
/// (`ip_cmsg_recv` : 0).
fn sans_le_decalage(s: &Socket, v: u32, donnees: &[u8], decalage: usize) -> u32 {
    use formats::reseau::{somme_linux, somme_linux_moins};
    if decalage != 0 && s.protocole == Protocole::Udp {
        somme_linux_moins(v, somme_linux(donnees.get(..decalage).unwrap_or(&[])))
    } else {
        v
    }
}

/// Le dernier `close` d'un fichier ouvert : s'il tenait une socket, elle
/// est accrochée à la tâche courante, et sera fermée à la sortie de son
/// appel (`fermer_les_differees`). Le `__fput` de Linux, remis par
/// `task_work_add` au retour vers l'anneau 3 : le dernier `close` se fait
/// sous le verrou des fichiers (vfs.rs), où l'on ne peut ni dormir ni
/// prendre la possession d'une socket, ce que demandera la fermeture d'une
/// socket TCP (envoyer FIN, attendre SO_LINGER) ; une socket UDP s'en
/// passerait, mais toutes suivent le même chemin, comme chez Linux. Sans
/// allocation : la liste est chaînée par les sockets elles-mêmes.
pub fn fichier_ferme(ferme: &FichierOuvert, fichier: crate::descripteurs::Fichier) {
    if let Prive::Socket(s) = &ferme.prive {
        s.liste_async().fichier_ferme(fichier);
        let t = tache::courante();
        let mut tete = t.fermetures.verrouiller();
        *s.suivante.verrouiller() = tete.take();
        *tete = Some(s.clone());
    }
}

/// Ferme les sockets dont la tâche courante a fait le dernier `close` (le
/// `task_work_run`) : à la sortie de chaque appel système et de chaque
/// appel WASI, et à la fin de la tâche. Sans verrou tenu. Une socket
/// quitte alors sa table des ports (le `sock_close`, puis
/// `udp_lib_unhash`) : elle ne reçoit plus rien, et ce qui restait dans sa
/// file est rendu avec elle.
pub fn fermer_les_differees() {
    crate::tube::signaler_les_fermes();
    crate::surveillance::signaler_les_instances();
    let t = tache::courante();
    loop {
        let s = {
            let mut tete = t.fermetures.verrouiller();
            let Some(s) = tete.take() else { return };
            *tete = s.suivante.verrouiller().take();
            s
        };
        fermer(&s);
    }
}

/// Ferme la socket `s` (le `sock_close`) : à son dernier `close`, ou quand
/// elle n'a jamais eu de fichier (un `sock_accept` de WASI qui échoue après
/// avoir pris la connexion, wasi.rs). Sans verrou tenu.
pub fn fermer(s: &Arc<Socket>) {
    // D'abord ses adhésions (`inet_release` : `ip_mc_drop_socket`).
    if s.protocole != Protocole::Unix {
        super::multidiffusion::fermer(s);
    }
    match s.protocole {
        Protocole::Tcp => super::tcp::fermer(s),
        Protocole::Unix => super::unix::fermer(s),
        Protocole::Udp => super::udp::fermer(s),
        Protocole::Ping => super::datagramme::table::retirer(s),
    }
}

/// Un numéro de socket neuf (la fille d'une écoute en prend un).
pub fn nouveau_numero() -> u64 {
    NUMEROS.fetch_add(1, Ordering::Relaxed)
}
