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
use super::paquet::{Contexte, Paquet};
use super::snmp::MIB;
use crate::appels_fichiers::FichierTenu;
use crate::attente::{self, FileAttente, Mutex, Sommeil};
use crate::descripteurs::{FichierOuvert, Prive};
use crate::partage::Arc;
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDNORM, POLLWRBAND, POLLWRNORM, Table};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::faillible::{self, FileFaillible};
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU8, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};
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

/// La mémoire des options d'une socket (`optmem_max`, net.core) : ce que
/// `sock_kmalloc` et `sock_omalloc` lui laissent prendre en tout (ses
/// adhésions, ses avis de MSG_ZEROCOPY, ses messages de contrôle d'un
/// envoi le temps de les lire).
pub const OPTMEM_MAX: usize = 131_072;

// D'où vient une erreur de la file d'erreurs (SO_EE_ORIGIN_*).
pub const ORIGINE_LOCALE: u8 = 1;
pub const ORIGINE_ICMP: u8 = 2;
/// Un horodatage d'émission (horodatage.rs).
pub const ORIGINE_HORODATAGE: u8 = 4;
/// L'avis d'envois de MSG_ZEROCOPY (zerocopie.rs).
pub const ORIGINE_ZEROCOPIE: u8 = 5;

/// Une erreur dans la file d'erreurs (la `sk_error_queue` de Linux, avec
/// IP_RECVERR ; ou l'entrée d'un horodatage d'émission, avec
/// SO_TIMESTAMPING, voir horodatage.rs pour ce que disent alors ses champs),
/// lue par MSG_ERRQUEUE : sa `sock_extended_err` (l'errno,
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
    /// L'heure d'arrivée du message ICMP (paquet::Contexte) ; 0 pour une
    /// erreur locale, que Linux fait sans heure (`ip_local_error`) : la
    /// lecture lui donne la sienne (SO_TIMESTAMP, `__sock_recv_timestamp`).
    pub horodatage: u64,
    pub donnees: Paquet,
    /// Sa taille vraie (elle compte dans SO_RCVBUF, avec les datagrammes).
    pub taille: usize,
    /// Ses octets sont les statistiques de TCP d'OPT_STATS (`opt_stats` de la
    /// `sock_exterr_skb`) : la lecture les redit en SCM_TIMESTAMPING_OPT_STATS.
    pub stats: bool,
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
    /// Les pertes de la socket quand il est arrivé, si elle avait alors
    /// SO_RXQ_OVFL (`dropcount` : `sock_skb_set_dropcount`, et pour UDP le
    /// même compte avant chaque lot, `__udp_enqueue_schedule_skb`) ; 0 sinon.
    pub pertes: u32,
}

impl ErreurEnFile {
    /// Une erreur « locale » (`ip_local_error`) : vue par l'envoi lui-même,
    /// sans message ICMP ni données. None : plus de mémoire.
    pub fn locale(errno: i32, info: u32, adresse: [u8; 4], port: u16) -> Option<ErreurEnFile> {
        let donnees = Paquet::vide(0)?;
        Some(ErreurEnFile {
            errno, origine: ORIGINE_LOCALE, genre: 0, code: 0, info, ee_data: 0, adresse, port, emetteur: [0; 4], interface: 0,
            arrivee: [0; 4], entete: EnteteRecu::AUCUN, somme: 0, horodatage: 0, taille: donnees.taille_vraie(), donnees, stats: false,
        })
    }

    /// L'avis de MSG_ZEROCOPY des envois `premier` à `premier + nombre - 1`
    /// (`__msg_zerocopy_callback`) : errno 0, ee_info et ee_data ces deux
    /// numéros, et toujours SO_EE_CODE_ZEROCOPY_COPIED (zerocopie.rs) ;
    /// ni adresse, ni octets, ni place dans SO_RCVBUF (Linux le met en file
    /// sans `sock_queue_err_skb` : il compte dans la mémoire des options).
    pub fn avis(premier: u32, nombre: u32) -> ErreurEnFile {
        const COPIE: u8 = 1;
        ErreurEnFile {
            errno: 0, origine: ORIGINE_ZEROCOPIE, genre: 0, code: COPIE, info: premier, ee_data: premier.wrapping_add(nombre - 1),
            adresse: [0; 4], port: 0, emetteur: [0; 4], interface: 0, arrivee: [0; 4], entete: EnteteRecu::AUCUN, somme: 0,
            horodatage: 0, donnees: Paquet::rien(), taille: 0, stats: false,
        }
    }

    /// L'avis `self`, la queue de la file, prolonge-t-il ses numéros des
    /// `nombre` qui commencent à `premier` (`skb_zerocopy_notify_extend` :
    /// ils le suivent, et l'intervalle tient sur 32 bits) ? Alors c'est fait.
    fn prolonger(&mut self, premier: u32, nombre: u32) -> bool {
        let longueur = self.ee_data.wrapping_sub(self.info) as u64 + 1 + nombre as u64;
        if longueur >= 1 << 32 || premier != self.ee_data.wrapping_add(1) {
            return false;
        }
        self.ee_data = self.ee_data.wrapping_add(nombre);
        true
    }

    /// Ce que diront ses messages de contrôle IP, pour une socket de
    /// drapeaux SO_TIMESTAMPING `tsflags` (`ipv4_datagram_support_cmsg`) :
    /// une erreur venue d'ICMP, toujours ; un horodatage d'émission, avec
    /// OPT_CMSG et s'il a une interface (pas avec OPT_TSONLY : il n'a pas de
    /// paquet), ceux du paquet parti ; une erreur locale, jamais. Les « ports »
    /// d'IP_ORIGDSTADDR sont les octets 2 et 3 de l'en-tête de transport : pour
    /// une erreur, de ce que lira le programme (Linux fait de sa charge
    /// l'en-tête de transport de l'erreur, `ip_icmp_error`, et n'en dit rien si
    /// elle a moins de 4 octets : mesuré, UDP « abc », aucun ; un écho, sa
    /// somme) ; pour un horodatage, du paquet, après ses en-têtes Ethernet et
    /// IP. La somme : celle d'un message ICMP reçu (IP_CHECKSUM) ; un paquet
    /// qui part n'en a pas de complète (CHECKSUM_PARTIAL).
    pub fn controle(&self, tsflags: u32) -> Option<ControleIp> {
        let (port, somme) = match self.origine {
            ORIGINE_ICMP => (self.donnees.donnees().get(..4).map(|o| u16::from_be_bytes([o[2], o[3]])), Some(self.somme)),
            ORIGINE_HORODATAGE if tsflags & SOF_OPT_CMSG != 0 && self.interface != 0 => {
                let ip = self.donnees.donnees().get(formats::reseau::ethernet::ENTETE..).unwrap_or(&[]);
                let entete = ip.first().map_or(0, |o| (o & 0xf) as usize * 4);
                (ip.get(entete..entete + 4).map(|o| u16::from_be_bytes([o[2], o[3]])), None)
            }
            _ => return None,
        };
        Some(ControleIp { entete: self.entete, source: self.emetteur, port, somme })
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
    /// Les avis de MSG_ZEROCOPY faits et pas encore livrés (zerocopie.rs) :
    /// la file d'erreurs leur garde chacun une place, pour qu'aucun ne se
    /// perde faute de mémoire (Linux a fait d'avance le `sk_buff` de l'avis).
    pub avis_en_vol: usize,
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
    /// SO_MARK (`sk_mark`) : la marque de ses envois (paquet::Contexte).
    pub mark: u32,
    /// SO_LINGER : en marche, et le délai en tics (`sk_lingertime`, en
    /// jiffies) : LINGER_INFINI pour un délai qui ne finit pas.
    pub linger: (bool, u64),
    /// Les tampons fixés par le programme (`sk_userlocks`, ses deux bits
    /// que SO_BUF_LOCK lit et écrit) : VERROU_SNDBUF, posé par SO_SNDBUF,
    /// et VERROU_RCVBUF, par SO_RCVBUF. TCP ne fait plus grandir de
    /// lui-même un tampon fixé (tcp.rs, `tampons_changes`).
    pub verrous_tampons: u8,
    /// L'attente active à la réception (CONFIG_NET_RX_BUSY_POLL) :
    /// SO_BUSY_POLL (`sk_ll_usec`), SO_PREFER_BUSY_POLL et
    /// SO_BUSY_POLL_BUDGET, gardés et relus. Ils règlent combien de temps
    /// un `recv` interroge la file NAPI de la carte avant de dormir ; nos
    /// cartes réveillent toujours par interruption, et une attente active
    /// ne changerait que le temps, jamais ce que lit le programme.
    pub busy_poll: u32,
    pub prefer_busy_poll: bool,
    pub busy_poll_budget: u16,
    /// SO_WIFI_STATUS (l'avis d'acquittement d'une trame Wi-Fi) et
    /// SO_NOFCS (une trame sans somme de contrôle Ethernet, pour les
    /// sockets de paquets) : gardés et relus ; seul un pilote Wi-Fi, ou
    /// une carte qui sait le faire, s'en sert, et nous n'en avons pas.
    pub wifi_status: bool,
    pub nofcs: bool,
    /// SO_TXTIME (`SOCK_TXTIME`, `sk_clockid`, ses deux drapeaux) : posé,
    /// il ne se retire plus ; il permet SCM_TXTIME à l'envoi, l'heure de
    /// départ voulue d'un paquet. Seuls les ordonnanceurs de file etf et fq
    /// la lisent ; sans eux (lo, et nos cartes : une file simple), le
    /// paquet part tout de suite, comme chez nous.
    pub txtime: bool,
    pub txtime_horloge: u8,
    pub txtime_drapeaux: u8,
    /// SO_TXREHASH de TCP (`sk_txrehash`) : 1, un RTO change le hachage du
    /// flux (TCP_INFO le compte, `tcpi_rehash`) ; 0, jamais.
    pub txrehash: u8,
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

/// Le HZ de Linux, la résolution des délais des sockets : 1 000 tics par
/// seconde, ceux de notre horloge (6e), et de la machine du Linux de
/// référence (CONFIG_HZ=1000 ; 250 sous WSL). Il se voit : un SO_LINGER
/// infini se relit `LINGER_INFINI / HZ`, tronqué à 32 bits.
pub const HZ: u64 = 1_000;

/// SO_LINGER d'un délai qui ne finit pas : MAX_SCHEDULE_TIMEOUT (LONG_MAX
/// jiffies), ce que Linux garde pour un délai négatif ou trop grand.
pub const LINGER_INFINI: u64 = i64::MAX as u64;

/// Les deux bits de `sk_userlocks` que SO_BUF_LOCK expose
/// (SOCK_SNDBUF_LOCK, SOCK_RCVBUF_LOCK) ; les verrous de `bind`
/// (SOCK_BINDADDR_LOCK, SOCK_BINDPORT_LOCK) vivent avec les adresses.
pub const VERROU_SNDBUF: u8 = 1;
pub const VERROU_RCVBUF: u8 = 2;

/// Les drapeaux de réception de `Socket::drapeaux`, ceux du `sk_flags` de
/// Linux : SO_TIMESTAMP, SO_TIMESTAMPNS et leurs formes _NEW posent
/// RCVTSTAMP, RCVTSTAMPNS (les nanosecondes) et TSTAMP_NEW (la forme
/// _NEW, dite par le type du message de contrôle : les deux ont 16 octets
/// sur x86_64) ; TIMESTAMP (SOCK_TIMESTAMP) : une lecture garde l'heure de
/// son datagramme pour SIOCGSTAMP, posé par SIOCGSTAMP lui-même et par
/// toute forme de SO_TIMESTAMP, et jamais retiré (`sock_enable_timestamp`) ;
/// RXQ_OVFL, RCVMARK, RCVPRIORITY : leurs options ; INQ : SO_INQ d'AF_UNIX
/// (le `recvmsg_inq` de son `unix_sock`) ; SELECT_ERR_QUEUE
/// (SOCK_SELECT_ERR_QUEUE) : poll rend POLLPRI avec POLLERR, voir `sonder`.
pub const RCVTSTAMP: u16 = 1;
pub const RCVTSTAMPNS: u16 = 2;
pub const TSTAMP_NEW: u16 = 4;
pub const TIMESTAMP: u16 = 8;
pub const RXQ_OVFL: u16 = 16;
pub const RCVMARK: u16 = 32;
pub const RCVPRIORITY: u16 = 64;
pub const INQ: u16 = 128;
pub const SELECT_ERR_QUEUE: u16 = 256;
/// La socket compte dans la clé des horodatages (`HORODATAGES`).
pub const CLE_HORODATAGE: u16 = 512;
/// SO_ZEROCOPY (SOCK_ZEROCOPY) : MSG_ZEROCOPY y vaut quelque chose
/// (zerocopie.rs) ; TCP et UDP seulement.
pub const ZEROCOPIE: u16 = 1024;
/// SO_LOCK_FILTER (SOCK_FILTER_LOCKED) : son filtre ne se change plus, ni ne
/// s'enlève (filtre.rs), et le verrou ne s'ouvre plus.
pub const FILTRE_VERROUILLE: u16 = 2048;

/// Les drapeaux de SO_TIMESTAMPING que la réception regarde (`sk_tsflags`,
/// include/uapi/linux/net_tstamp.h) : RX_SOFTWARE fait prendre l'heure
/// d'arrivée (il allume la clé), SOFTWARE la dit (SCM_TIMESTAMPING), et
/// OPT_RX_FILTER ne la dit que si la socket l'a fait prendre ;
/// RAW_HARDWARE dirait celle d'une carte, qu'aucune des nôtres ne donne.
pub const SOF_RX_SOFTWARE: u32 = 1 << 3;
pub const SOF_SOFTWARE: u32 = 1 << 4;
pub const SOF_RAW_HARDWARE: u32 = 1 << 6;
pub const SOF_OPT_RX_FILTER: u32 = 1 << 17;

/// Ceux de l'émission (horodatage.rs) : les points demandés, TX_SOFTWARE (le
/// pilote prend la trame), TX_SCHED (l'interface), TX_ACK (TCP : l'autre côté
/// a acquitté), et TX_HARDWARE, TX_COMPLETION, que rien ne dit chez nous ;
/// ensemble, TX_RECORD_MASK, les seuls qu'un message de contrôle d'envoi
/// peut changer. Et la forme des entrées : OPT_ID (une clé par envoi),
/// OPT_CMSG (les messages de contrôle IP du paquet), OPT_TSONLY (sans ses
/// octets).
pub const SOF_TX_HARDWARE: u32 = 1 << 0;
pub const SOF_TX_SOFTWARE: u32 = 1 << 1;
pub const SOF_OPT_ID: u32 = 1 << 7;
pub const SOF_TX_SCHED: u32 = 1 << 8;
pub const SOF_TX_ACK: u32 = 1 << 9;
pub const SOF_OPT_CMSG: u32 = 1 << 10;
pub const SOF_OPT_TSONLY: u32 = 1 << 11;
pub const SOF_OPT_STATS: u32 = 1 << 12;
pub const SOF_TX_COMPLETION: u32 = 1 << 18;
pub const SOF_TX_RECORD_MASK: u32 = SOF_TX_HARDWARE | SOF_TX_SOFTWARE | SOF_TX_SCHED | SOF_TX_ACK | SOF_TX_COMPLETION;

/// La clé des horodatages (le `netstamp_needed_key` de Linux) : combien de
/// sockets d'Internet veulent l'heure d'arrivée des paquets, par
/// SOCK_TIMESTAMP (toute SO_TIMESTAMP, SIOCGSTAMP) ou par
/// SOF_TIMESTAMPING_RX_SOFTWARE (`sock_enable_timestamp`) ; AF_UNIX ne
/// compte pas (`sock_needs_netstamp` : ses messages prennent l'heure à
/// l'envoi, pour qui la veut). Chacune compte une fois, de la première
/// demande à sa fermeture ou à la fin de la dernière (SOCK_TIMESTAMP ne
/// s'enlève pas ; RX_SOFTWARE, si).
///
/// Choix de conception : l'heure n'est prise à l'entrée de la pile que si
/// la clé est allumée (`heure_d_arrivee`), comme Linux : SCM_TIMESTAMPING
/// dit l'heure d'un paquet « s'il en a une » (SOF_TIMESTAMPING_SOFTWARE
/// sans RX_SOFTWARE : l'heure qu'une autre socket a fait prendre, la
/// documentation le dit, et OPT_RX_FILTER existe pour l'écarter) ; une
/// heure toujours prise la dirait toujours. Un datagramme arrivé avant la
/// clé n'en a donc pas : SO_TIMESTAMP le lit à l'heure de sa lecture
/// (`__sock_recv_timestamp`, `false_tstamp`), TCP n'en dit rien (mesuré).
/// Sans la course de Linux : sa clé statique s'allume en différé (une
/// tâche de fond, `netstamp_work`), et le premier paquet qui suit
/// SO_TIMESTAMP peut arriver sans heure (vu sur l'hôte) ; la nôtre est un
/// compteur, allumé avant le retour de l'appel. Écartés : l'heure toujours
/// prise (le choix d'avant), qui ne distingue pas ces cas ; une clé par
/// socket, qui ne saurait pas que la pile en prend pour une autre.
static HORODATAGES: AtomicUsize = AtomicUsize::new(0);

/// La part de la clé des horodatages que compte une fille d'une écoute de TCP, de sa
/// naissance à son `accept` : `sk_clone_lock` copie l'écoute, et compte la copie
/// (`net_enable_timestamp`) si l'écoute comptait ; la fille vit ensuite sans programme
/// jusqu'à l'`accept`. Sa socket la reprend alors (`Socket::heriter`), et sa fermeture la
/// rendra ; une fille qui meurt avant (un RST, son écoute fermée) la rend ici. Sans cela,
/// la clé resterait allumée pour une socket qui n'est plus, ou la fermeture de la socket
/// ôterait une part qu'elle n'avait pas mise.
pub struct PartDeCle(bool);

impl PartDeCle {
    pub const AUCUNE: PartDeCle = PartDeCle(false);

    /// Celle d'une copie de drapeaux `drapeaux` : une part si l'original comptait.
    pub fn de(drapeaux: u16) -> PartDeCle {
        let compte = drapeaux & CLE_HORODATAGE != 0;
        if compte {
            HORODATAGES.fetch_add(1, Ordering::Relaxed);
        }
        PartDeCle(compte)
    }
}

impl Drop for PartDeCle {
    fn drop(&mut self) {
        if self.0 {
            HORODATAGES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// L'heure d'arrivée d'un paquet qui entre dans la pile : celle de la date si
/// la clé est allumée, 0 sinon (`net_timestamp_check`, `__net_timestamp`).
pub fn heure_d_arrivee() -> u64 {
    if HORODATAGES.load(Ordering::Relaxed) > 0 { crate::temps::ns_calendrier() } else { 0 }
}

/// `sk_stamp` avant toute lecture (SK_DEFAULT_STAMP : -1 s).
pub const HORODATAGE_AUCUN: i64 = -1_000_000_000;

/// Le programme qui appelle a-t-il les droits d'administrer le réseau
/// (CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE : chez nous, root les
/// a tous, et lui seul) ? Ceux de QUI APPELLE (`sockopt_ns_capable`,
/// `ns_capable` dans `inet_bind`), pas de qui a créé la socket : une
/// socket passée à un autre processus (SCM_RIGHTS), ou gardée après un
/// changement d'identité, suit les droits de son nouvel utilisateur.
/// `Socket::uid`, lui, reste celui du créateur (`sk_uid`), que comparent
/// SO_REUSEPORT et /proc/net.
pub fn appelant_privilegie() -> bool {
    crate::processus::avec(|p| p.identite).root()
}

/// Le compteur des SO_COOKIE (`sock_cookie`), le dernier donné.
static COOKIES: AtomicU64 = AtomicU64::new(0);

impl Socket {
    /// Le drapeau de réception `d` est-il posé (`sock_flag`) ?
    pub fn drapeau(&self, d: u16) -> bool {
        self.drapeaux.load(Ordering::Relaxed) & d != 0
    }

    /// Pose ou retire les drapeaux `d` (`sock_valbool_flag`).
    pub fn poser_drapeau(&self, d: u16, oui: bool) {
        if oui {
            self.drapeaux.fetch_or(d, Ordering::Relaxed);
        } else {
            self.drapeaux.fetch_and(!d, Ordering::Relaxed);
        }
    }

    /// Met à jour sa part de la clé des horodatages après un changement de
    /// SOCK_TIMESTAMP ou de `tsflags` (`sock_enable_timestamp`,
    /// `sock_disable_timestamp`). Sous le verrou de ses appels, comme Linux
    /// sous celui de la socket : deux changements à la fois ne la comptent
    /// pas de travers (le dernier à le prendre voit les deux).
    pub fn revoir_cle(&self) {
        let _appels = self.appels.verrouiller();
        let veut = self.unix.is_none()
            && (self.drapeau(TIMESTAMP) || self.tsflags.load(Ordering::Relaxed) & SOF_RX_SOFTWARE != 0);
        if veut != self.drapeau(CLE_HORODATAGE) {
            self.poser_drapeau(CLE_HORODATAGE, veut);
            if veut {
                HORODATAGES.fetch_add(1, Ordering::Relaxed);
            } else {
                HORODATAGES.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Ce que SO_SELECT_ERR_QUEUE ajoute à POLLERR : POLLPRI, que `select`
    /// range dans ses exceptions (POLLEX_SET), pour attendre les erreurs sans
    /// être réveillé par les données. Pour les datagrammes d'Internet (UDP,
    /// ping), et les datagrammes et paquets d'AF_UNIX (`datagram_poll`,
    /// `unix_dgram_poll`) ; ni TCP
    /// (`tcp_poll`), ni un flux AF_UNIX (`unix_poll`), qui l'acceptent sans
    /// effet (mesuré, sonde c6).
    ///
    /// Le réveil n'en dit rien : une erreur réveille avec la clé POLLERR seule
    /// (`sock_def_error_report`, depuis que « skbuff: Fix not waking
    /// applications when errors are enqueued », 2018, a remplacé le
    /// `sk_data_ready` qui réveillait avec POLLPRI). Un `select` qui n'attend
    /// que les exceptions n'écoute pas POLLERR : il ne se réveille pas, et ne
    /// voit l'erreur qu'à son échéance, à son dernier tour (mesuré sous Linux ;
    /// poll et epoll, qui écoutent toujours POLLERR, se réveillent). Notre
    /// `select` filtre les réveils par la même clé (sondage.rs, `table.cle`),
    /// et fait de même.
    pub fn erreur_prioritaire(&self) -> u32 {
        if self.drapeau(SELECT_ERR_QUEUE) { POLLPRI } else { 0 }
    }

    /// La socket d'une fille d'une écoute de TCP, à son `accept`, prend ce que `sk_clone_lock`
    /// a copié de l'écoute à sa naissance (tcp.rs, `Heritage`) : ses drapeaux de réception
    /// (SO_TIMESTAMP, SO_RXQ_OVFL..., et SO_ZEROCOPY), SO_TIMESTAMPING et le compteur de ses
    /// clés ; et la part de la clé des horodatages que la fille compte depuis (`part`), que sa
    /// fermeture rendra (son drapeau CLE_HORODATAGE). Le compteur de MSG_ZEROCOPY reste à 0
    /// (`sk_clone_lock` : `sk_zckey`), même quand l'écoute a été une connexion qui en a envoyé.
    pub fn heriter(&self, drapeaux: u16, tsflags: u32, cle_emission: u32, part: &mut PartDeCle) {
        self.drapeaux.store(drapeaux, Ordering::Relaxed);
        self.tsflags.store(tsflags, Ordering::Relaxed);
        self.cle_emission.store(cle_emission, Ordering::Relaxed);
        part.0 = false;
    }

    /// Un paquet arrive pour elle sur ce processeur (`sk_incoming_cpu_update`).
    pub fn arrivee_ici(&self) {
        self.processeur.store(crate::processeur::numero() as i32, Ordering::Relaxed);
    }

    /// SO_COOKIE (`sock_gen_cookie`) : celui de la socket, donné au premier
    /// besoin ; deux appels concurrents gardent le même (le premier
    /// `compare_exchange` gagne, comme le `atomic64_cmpxchg` de Linux).
    pub fn cookie(&self) -> u64 {
        let c = self.cookie.load(Ordering::Relaxed);
        if c != 0 {
            return c;
        }
        let neuf = COOKIES.fetch_add(1, Ordering::Relaxed) + 1;
        match self.cookie.compare_exchange(0, neuf, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => neuf,
            Err(autre) => autre,
        }
    }
}

impl Options {
    pub const DEFAUT: Options = Options {
        reuseaddr: false, reuseport: false, broadcast: false, keepalive: false, debug: false, dontroute: false,
        oobinline: false, no_check: false, priority: 0, mark: 0, linger: (false, 0), verrous_tampons: 0,
        busy_poll: 0, prefer_busy_poll: false, busy_poll_budget: 0, wifi_status: false, nofcs: false,
        txtime: false, txtime_horloge: 0, txtime_drapeaux: 0, txrehash: 1, rcvlowat: 1,
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
    /// L'utilisateur qui l'a créée (`sk_uid` : SO_REUSEPORT, /proc/net) ;
    /// pas ses droits (`appelant_privilegie`).
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
    /// Ce qui a été jeté en arrivant pour elle (`sk_drops` : SO_MEMINFO, et
    /// SO_RXQ_OVFL) : un datagramme que sa file ne prend pas (`deposer` :
    /// `__udp_enqueue_schedule_skb`, `__sock_queue_rcv_skb`), la copie ratée
    /// d'une diffusion, une somme fausse (udp.rs), un segment que la file
    /// `backlog` de TCP ne prend pas (`tcp_add_backlog`), ce que jette une
    /// écoute (`tcp_listendrop`, `tcp_drop_reason`). Un `atomic_t` chez Linux :
    /// il fait le tour.
    pub pertes: AtomicU32,
    /// Ses drapeaux de réception (les bits du `sk_flags` de Linux qui les
    /// tiennent, atomiques comme eux : la tâche du réseau et l'envoi
    /// d'AF_UNIX les lisent sans le `Mutex`) : voir `RCVTSTAMP` et la suite.
    pub drapeaux: AtomicU16,
    /// SO_TIMESTAMPING (`sk_tsflags`) : ses drapeaux SOF_TIMESTAMPING_*, tels
    /// que posés (voir `SOF_SOFTWARE` et la suite).
    pub tsflags: AtomicU32,
    /// Le compteur des clés d'OPT_ID (`sk_tskey`), remis à zéro quand OPT_ID
    /// se pose : la clé du prochain datagramme horodaté
    /// (`horodatage::demander_datagramme`) ; pour TCP, le numéro de séquence
    /// d'où partent les clés.
    pub cle_emission: AtomicU32,
    /// Le numéro du prochain envoi de MSG_ZEROCOPY (`sk_zckey`, zerocopie.rs).
    pub cle_zerocopie: AtomicU32,
    /// Ce que tiennent ses avis de MSG_ZEROCOPY, faits et pas encore lus,
    /// dans la mémoire de ses options (leur part de `sk_omem_alloc`,
    /// zerocopie.rs).
    pub memoire_avis: AtomicUsize,
    /// L'heure du dernier datagramme lu (`sk_stamp`), que rend SIOCGSTAMP
    /// (appels_reseau.rs, `heure_du_dernier` ; la lecture l'écrit :
    /// `heure_lue`, `controle_udp`) : HORODATAGE_AUCUN tant que rien n'a été
    /// lu ; 0 : une lecture sans heure à garder, SIOCGSTAMP prendra la sienne.
    pub horodatage: AtomicI64,
    /// SO_INCOMING_CPU (`sk_incoming_cpu`) : le processeur qui a reçu son
    /// dernier paquet (une socket UDP connectée, une connexion TCP), ou
    /// celui que le programme a posé ; -1 au départ. Une recherche de
    /// socket préfère, à note égale, celle de ce processeur.
    pub processeur: AtomicI32,
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
    /// SO_COOKIE (`sk_cookie`) : un nombre propre à la socket, jamais 0,
    /// jamais réutilisé, donné au premier qui le demande (0 : pas encore).
    pub cookie: AtomicU64,
    /// SO_MAX_PACING_RATE (`sk_max_pacing_rate`) : le plafond du débit de ses envois,
    /// en octets par seconde, l'infini au départ (`sock_init_data`). Seul TCP s'en sert,
    /// par son rythme interne (inet, tcp/rythme.rs) ; les autres le gardent pour le
    /// relire : sans la file `fq`, que nous n'avons pas, rien ne rythme un datagramme.
    pub rythme_max: AtomicU64,
    /// Le hachage du flux d'une socket de datagrammes (UDP, ping), son `sk_txhash` : tiré à
    /// chaque `connect` réussi (`ip4_datagram_connect` : `sk_set_txhash`), gardé après la
    /// déconnexion, et porté par chacun de ses datagrammes, même envoyé par `sendto` à un
    /// autre (`skb_set_hash_from_sk`, paquet.rs ; tout mesuré, sonde c10g du lot 6 des
    /// soldes) ; 0 : jamais connectée, ses datagrammes n'en ont pas. Une connexion TCP a le
    /// sien (inet, `Tcb::hachage`) ; AF_UNIX n'en a jamais.
    pub hachage: AtomicU32,
    /// Son filtre (SO_ATTACH_FILTER, filtre.rs). Linux le lit sous RCU à chaque paquet ;
    /// ici, sous un verrou court, le temps d'en prendre une référence (l'`Arc`) : le
    /// programme tourne hors de lui, et un nouveau filtre peut se poser pendant ce temps.
    pub filtre: Verrou<Option<Arc<super::filtre::Filtre>>>,
    /// La suivante des sockets qu'une tâche a à fermer (sa liste
    /// `Tache::fermetures`, voir `fichier_ferme`).
    suivante: Verrou<Option<Arc<Socket>>>,
    /// Le flux d'une socket TCP (tcp.rs) : sa possession et sa connexion.
    pub flux: Option<alloc::boxed::Box<crate::attente::Possession<super::tcp::Partie>>>,
    /// Pour TCP, ce que sa file d'erreurs partage avec sa connexion (le
    /// `sk_rmem_alloc`, tcp.rs) : qu'elle tienne avec ce que la connexion a
    /// reçu sous SO_RCVBUF, et que la connexion la compte.
    pub compte_tcp: Option<Arc<super::tcp::CompteReception>>,
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
            reception: Verrou::new(Reception { file: VecDeque::new(), erreurs: VecDeque::new(), octets: 0, erreur: 0, arret: 0, avis_en_vol: 0 }),
            appels: Mutex::new(Inet {
                lie: false, adresse: [0; 4], port: 0, port_choisi: false, adresse_choisie: false, connecte: false,
                distante: [0; 4], port_distant: 0, source: [0; 4], route_gardee: None, identifiant: 0,
                // Une socket de ping naît avec SO_REUSEADDR (INET_PROTOSW_REUSE,
                // `inet_create`, mesuré) : deux pings du même identifiant se
                // partagent ses réponses tant qu'aucune ne l'a retiré (idents.rs).
                options: Options { reuseaddr: protocole == Protocole::Ping, ..Options::DEFAUT },
                bouchon: None,
            }),
            rcvbuf: AtomicU32::new(TAMPON_DEFAUT),
            sndbuf: AtomicU32::new(TAMPON_DEFAUT),
            pertes: AtomicU32::new(0),
            drapeaux: AtomicU16::new(0),
            tsflags: AtomicU32::new(0),
            cle_emission: AtomicU32::new(0),
            cle_zerocopie: AtomicU32::new(0),
            memoire_avis: AtomicUsize::new(0),
            horodatage: AtomicI64::new(HORODATAGE_AUCUN),
            processeur: AtomicI32::new(-1),
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
            cookie: AtomicU64::new(0),
            rythme_max: AtomicU64::new(u64::MAX),
            hachage: AtomicU32::new(0),
            filtre: Verrou::new(None),
            suivante: Verrou::new(None),
            flux: None,
            compte_tcp: None,
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
        let (flux, compte) = super::tcp::nouvelle(self.numero)?;
        self.flux = Some(faillible::boite(flux).ok()?);
        self.compte_tcp = Some(compte);
        self.rcvbuf.store(super::tcp::RCVBUF_DEFAUT, Ordering::Relaxed);
        self.sndbuf.store(super::tcp::SNDBUF_DEFAUT, Ordering::Relaxed);
        Some(self)
    }

    /// La même, avec un flux déjà fait (la fille d'une écoute, à
    /// `accept`).
    pub fn avec_flux(mut self, f: alloc::boxed::Box<crate::attente::Possession<super::tcp::Partie>>, compte: Arc<super::tcp::CompteReception>) -> Socket {
        self.flux = Some(f);
        self.compte_tcp = Some(compte);
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
    pub fn deposer(&self, mut d: Datagramme, admission: Admission) -> Result<(), Rejet> {
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        // Les pertes d'avant lui, si la socket veut les savoir (SO_RXQ_OVFL).
        d.pertes = if self.drapeau(RXQ_OVFL) { self.pertes.load(Ordering::Relaxed) } else { 0 };
        {
            let mut r = self.reception.verrouiller();
            let refuse = match admission {
                Admission::Udp => r.octets > 0 && r.octets + d.taille > rcvbuf,
                Admission::Ordinaire => r.octets >= rcvbuf,
            };
            if refuse {
                self.pertes.fetch_add(1, Ordering::Relaxed);
                return Err(Rejet::Pleine);
            }
            let taille = d.taille;
            if r.file.ajouter_derriere(d).is_err() {
                self.pertes.fetch_add(1, Ordering::Relaxed);
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
    /// (`sock_queue_err_skb` : elle compte avec les datagrammes, ou avec ce
    /// que la connexion de TCP a reçu, et doit laisser de la place sous
    /// SO_RCVBUF), et réveille. false : jetée. Elle laisse derrière elle la
    /// place des avis de MSG_ZEROCOPY en vol (`Reception::avis_en_vol`).
    pub fn mettre_en_file(&self, e: ErreurEnFile) -> bool {
        // (`sock_queue_err_skb` : `sk_error_report`.)
        let raison = crate::asynchrone::Raison::Erreur;
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        {
            let mut r = self.reception.verrouiller();
            let taille = e.taille;
            let admise = match &self.compte_tcp {
                Some(c) => c.admet(r.octets, taille, rcvbuf),
                None => r.octets + taille < rcvbuf,
            };
            let place = r.avis_en_vol + 1;
            if !admise || r.erreurs.try_reserve(place).is_err() {
                return false;
            }
            r.erreurs.ajouter_derriere_dans_la_place(e);
            r.octets += taille;
            self.compter_erreurs(r.octets);
        }
        self.file_de_sondage().reveiller(POLLERR, 1);
        self.liste_async().evenement(raison);
        true
    }

    /// Met en file l'avis de MSG_ZEROCOPY des envois `premier` à `premier +
    /// nombre - 1` (zerocopie.rs, `livrer`) : fondu dans l'avis en queue de
    /// file s'il le prolonge, sinon une entrée neuve, à la place que son
    /// `preparer` a gardée ; puis le réveil, même fondu (`sk_error_report`).
    /// Vrai : une entrée neuve (sa mémoire reste comptée jusqu'à sa lecture).
    pub fn mettre_avis_en_file(&self, premier: u32, nombre: u32) -> bool {
        let neuve = {
            let mut r = self.reception.verrouiller();
            r.avis_en_vol = r.avis_en_vol.saturating_sub(1);
            if r.erreurs.back_mut().is_some_and(|q| q.origine == ORIGINE_ZEROCOPIE && q.prolonger(premier, nombre)) {
                false
            } else if r.erreurs.len() < r.erreurs.capacity() || r.erreurs.try_reserve(1).is_ok() {
                r.erreurs.ajouter_derriere_dans_la_place(ErreurEnFile::avis(premier, nombre));
                true
            } else {
                // La place gardée manque (rien ne la reprend pourtant) : perdu.
                false
            }
        };
        self.file_de_sondage().reveiller(POLLERR, 1);
        self.liste_async().evenement(crate::asynchrone::Raison::Erreur);
        neuve
    }

    /// La mémoire de ses options (`sk_omem_alloc`, SO_MEMINFO) : ses
    /// adhésions à des groupes et leurs listes de sources, ses avis de
    /// MSG_ZEROCOPY, et son filtre.
    pub fn memoire_des_options(&self) -> usize {
        let adhesions = if self.protocole == Protocole::Unix { 0 } else { self.adhesions.verrouiller().memoire() };
        adhesions + self.memoire_hors_adhesions()
    }

    /// La mémoire de ses options, ses adhésions à part : ses avis de MSG_ZEROCOPY et son
    /// filtre (ce qui borne les adhésions, multidiffusion.rs).
    pub fn memoire_hors_adhesions(&self) -> usize {
        let filtre = self.filtre.verrouiller().as_ref().map_or(0, |f| f.taille());
        self.memoire_avis.load(Ordering::Relaxed) + filtre
    }

    /// La file où attendent `poll` et epoll : celle du flux pour TCP (où
    /// attendent aussi ses lectures et ses écritures), sinon `attente`.
    fn file_de_sondage(&self) -> &crate::attente::FileAttente {
        match &self.flux {
            Some(f) => f.file(),
            None => &self.attente,
        }
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
            self.compter_erreurs(r.octets);
            if e.origine == ORIGINE_ZEROCOPIE {
                super::zerocopie::lu(self);
            }
            let suivante_icmp = r.erreurs.front().filter(|s| s.origine == ORIGINE_ICMP).map(|s| s.errno);
            if let Some(errno) = suivante_icmp {
                r.erreur = errno;
            } else if e.origine == ORIGINE_ICMP {
                r.erreur = 0;
            }
            (e, !r.erreurs.is_empty())
        };
        if reste {
            self.file_de_sondage().reveiller(POLLERR, 1);
            self.liste_async().evenement(crate::asynchrone::Raison::Erreur);
        }
        Some(e)
    }

    /// Vide la file d'erreurs (IP_RECVERR remis à 0, `skb_errqueue_purge`),
    /// sauf les horodatages d'émission et les avis de MSG_ZEROCOPY : ils ne
    /// viennent pas d'IP_RECVERR
    /// (mesuré : l'entrée SND reste, l'erreur ICMP part, et l'erreur en
    /// attente aussi, SO_ERROR la rend encore).
    pub fn vider_erreurs(&self) {
        let mut r = self.reception.verrouiller();
        let gardee = |e: &ErreurEnFile| e.origine == ORIGINE_HORODATAGE || e.origine == ORIGINE_ZEROCOPIE;
        let rendus: usize = r.erreurs.iter().filter(|e| !gardee(e)).map(|e| e.taille).sum();
        r.octets = r.octets.saturating_sub(rendus);
        r.erreurs.retain(gardee);
        self.compter_erreurs(r.octets);
    }

    /// Ce que garde maintenant la file d'erreurs, `octets`, pour la
    /// connexion de TCP (`CompteReception`) ; sous le verrou de la
    /// réception, qui ordonne ces écritures.
    fn compter_erreurs(&self, octets: usize) {
        if let Some(c) = &self.compte_tcp {
            c.poser_erreurs(octets);
        }
    }

    /// Prend l'erreur en attente (le `sock_error` : lue et effacée).
    pub fn prendre_erreur(&self) -> i32 {
        core::mem::take(&mut self.reception.verrouiller().erreur)
    }

    /// Ce qu'on peut faire de la socket sans attendre (le `datagram_poll`
    /// de Linux) : une erreur en attente ou en file (POLLERR ; et POLLPRI
    /// avec SO_SELECT_ERR_QUEUE), l'arrêt de la lecture (POLLRDHUP,
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
            m |= POLLERR | self.erreur_prioritaire();
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
    /// Pas d'émetteur à rendre : rien de reçu (la lecture arrêtée), un flux,
    /// ou l'entrée d'un horodatage d'émission.
    pub vide: bool,
    pub longueur: usize,
    pub source: [u8; 4],
    pub port: u16,
    pub destination: [u8; 4],
    /// L'interface et l'adresse locale d'IP_PKTINFO (`Datagramme::pktinfo`).
    pub pktinfo: (u32, [u8; 4]),
    pub coupe: bool,
    pub ip: Option<ControleIp>,
    /// Ce que disent les messages de contrôle de SOL_SOCKET : l'heure
    /// d'arrivée, la marque et la priorité (paquet::Contexte ; une heure 0 :
    /// aucune, la lecture prendra la sienne), les pertes d'avant lui
    /// (`Datagramme::pertes`).
    pub contexte: Contexte,
    pub pertes: u32,
}

impl Recu {
    /// Rien de reçu, ou un flux : ni émetteur, ni messages de contrôle IP.
    pub fn sans_emetteur(longueur: usize, coupe: bool) -> Recu {
        Recu {
            vide: true, longueur, source: [0; 4], port: 0, destination: [0; 4], pktinfo: (0, [0; 4]), coupe, ip: None,
            contexte: Contexte::default(), pertes: 0,
        }
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
                let (contexte, pertes) = (premier.paquet.contexte(), premier.pertes);
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
                return Ok(Recu { vide: false, longueur, source, port, destination, pktinfo, coupe, ip: Some(ip), contexte, pertes });
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
        Protocole::Ping => super::ping::fermer(s),
    }
}

/// Un numéro de socket neuf (la fille d'une écoute en prend un).
pub fn nouveau_numero() -> u64 {
    NUMEROS.fetch_add(1, Ordering::Relaxed)
}

/// Une socket fermée ne compte plus dans la clé des horodatages
/// (`sk_destruct` : `sock_disable_timestamp`).
impl Drop for Socket {
    fn drop(&mut self) {
        if self.drapeau(CLE_HORODATAGE) {
            HORODATAGES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
