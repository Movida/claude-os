//! TCP dans le noyau (6h) : les sockets de flux d'IPv4. Les règles d'une
//! connexion sont dans inet::tcp (la machine à états, testée sur l'hôte),
//! celles des ports dans inet::ports_tcp ; ici, ce qui les relie aux
//! programmes et au réseau : la socket et sa possession (attente.rs), la
//! table des ports, les écoutes et leurs filles, TIME_WAIT, l'émission des
//! segments, les attentes et les copies.
//!
//! LA SOCKET. Une socket TCP est une `Socket` de 6g (son fichier, ses
//! options de SOL_SOCKET et SOL_IP sous son `Mutex`, SO_RCVBUF et
//! SO_SNDBUF), plus un FLUX : une `Possession<Partie>`. La partie possédée
//! tient ce que font les appels (l'adresse, le port, la connexion entière
//! ou l'écoute) ; son premier étage (`Premier`), ce que lisent `poll` et
//! epoll même quand un appel possède la socket.
//!
//! L'ÉCOUTE et ses FILLES (plan de 6h, section 4) : un SYN reçu par une
//! écoute crée une fille (SYN_RECEIVED, une `Tcb` neuve), qui reste une
//! valeur dans la file de l'écoute jusqu'à `accept`, comme la
//! `request_sock` de Linux avant le troisième ACK (Linux, lui, en fait une
//! socket entière dès la poignée de main finie). Choix gardé : la socket
//! (son Arc, son inode, sa partie possédée) ne naît que dans l'appel
//! système qui la donne au programme, où sa mémoire peut manquer sans rien
//! perdre (la fille reste en file) ; un client du dehors ne fait allouer
//! au noyau que la petite valeur de la fille, sous la borne de la file. Le
//! prix : une fille établie n'est pas une socket, et ce qui la concerne
//! (poll de l'écoute, accept, un RST, une erreur ICMP) passe par l'écoute
//! (`Fille::prete`, `ranger_filles`). La table des ports la désigne par
//! « l'écoute, et sa fille de tel numéro » ; `accept4`, dans l'appel
//! système, la sort de la file et lui fait sa socket. La file : au plus
//! `backlog + 1` filles en tout, un SYN jeté quand les filles prêtes
//! dépassent `backlog` (`sk_acceptq_is_full`, mesuré).
//!
//! LA FIN. Le dernier `close` (différé, socket.rs) envoie FIN, ou RST s'il
//! reste des données non lues (RFC 2525, mesuré) ; la socket devient
//! ORPHELINE : la table des ports la garde vivante jusqu'à la fin de la
//! connexion. Une connexion qui arrive en TIME_WAIT (orpheline ou non),
//! ou orpheline en FIN_WAIT_2, devient une petite entrée de TIME_WAIT
//! (`TempsAttente`), et la socket est rendue, comme `tcp_time_wait`.
//!
//! LES MINUTEURS (commit 6 : la retransmission, l'ACK retardé, la sonde de
//! fenêtre) sont tenus par la connexion (inet::tcp, `echeance` et
//! `minuteur`) ; la socket inscrit la prochaine échéance de sa connexion,
//! ou de ses filles pour une écoute, dans les échéances du
//! réseau (tache.rs, sous le numéro de la socket), et la tâche du réseau
//! la réveille à l'heure (`minuteur_du_reseau` : tout de suite, ou par un
//! drapeau que verra la possession rendue). Une entrée de TIME_WAIT prend
//! un numéro neuf, pour sa place dans la table et pour son échéance.
//!
//! LES VERROUS, dans l'ordre de Linux : la possession d'une socket, son
//! verrou court, puis la table des ports (au plus profond). Ce qui se fait
//! sous le verrou court se fait dans le contexte réseau (contexte.rs) :
//! ce qui part par `lo` y est déposé, livré à la fin.

use super::contexte;
use super::ipv4;
use super::paquet::{Paquet, Retenue};
use super::snmp::MIB;
use super::socket::{self, Protocole, Socket};
use crate::attente::{FileAttente, Possede, Possession, Sommeil};
use crate::faillible::{self, FileFaillible, VecFaillible};
use crate::partage::{Arc, ArcVide};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDNORM, POLLWRNORM};
use crate::tache::Reveil;
use crate::verrou::Verrou;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use formats::reseau::ipv4 as fipv4;
use formats::reseau::Erreur;
use formats::reseau::tcp::{self as ftcp, Tcp};
use inet::ports_tcp::{self, Destinataire, Lien, Sorte};
use inet::routes::Portee;
use inet::snmp::{Icmp as CompteurIcmp, Ip as CompteurIp, Tcp as Compteur};
use inet::tcp::{self as itcp, Charge, Compte, Etat, Tcb};

const EINVAL: i64 = 22;
const EAGAIN: i64 = 11;
const EINTR: i64 = 4;
const EPIPE: i64 = 32;
const EACCES: i64 = 13;
const EADDRINUSE: i64 = 98;
const EADDRNOTAVAIL: i64 = 99;
const ENFILE: i64 = 23;
const EAFNOSUPPORT: i64 = 97;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const EALREADY: i64 = 114;
const EINPROGRESS: i64 = 115;
const ENOBUFS: i64 = 105;
const ECONNABORTED: i64 = 103;

/// SOCK_STREAM, et le protocole d'IPv4.
pub const SOCK_STREAM: u64 = 1;
/// Un drapeau du noyau pour `recevoir_programme` (ceux d'un programme
/// tiennent dans 32 bits) : sendfile d'une socket vers un tube
/// (`tcp_splice_read`, 6i), qui rend dès qu'il a quelque chose, sans
/// regarder SO_RCVLOWAT.
pub const MSG_EPISSER: u64 = 1 << 32;
pub const IPPROTO_TCP: u64 = 6;

/// Les tailles de départ des tampons d'une socket TCP (`tcp_rmem[1]`,
/// `tcp_wmem[1]`, mesurées : 131 072 et 16 384) ; leurs plafonds dépendent de
/// la mémoire de la machine (`RECEPTION_MAX`, `ENVOI_MAX`).
pub const RCVBUF_DEFAUT: u32 = 131_072;
pub const SNDBUF_DEFAUT: u32 = 16_384;
/// La plus longue file d'écoute (`somaxconn`).
pub const SOMAXCONN: usize = 4096;
/// Le temps en TIME_WAIT (TCP_TIMEWAIT_LEN, 60 s), et celui d'une orpheline
/// en FIN_WAIT_2 sans TCP_LINGER2 (`tcp_fin_timeout`, 60 s aussi).
pub const TEMPS_ATTENTE: u64 = 60_000_000_000;
/// Le nombre d'entrées de la table des ports et de TIME_WAIT
/// (`tcp_max_tw_buckets`, en plus petit).
const MAX_PORTS: usize = 1024 + MAX_TW;
pub const MAX_TW: usize = 4096;

/// Une charge reçue : le paquet, réduit à sa charge TCP.
impl Charge for Paquet {
    fn octets(&self) -> &[u8] {
        self.donnees()
    }
    fn avancer(&mut self, n: usize) {
        let n = n.min(self.longueur());
        let _ = self.retirer_entete(n);
    }
    fn taille_vraie(&self) -> usize {
        Paquet::taille_vraie(self)
    }
    fn neuve(n: usize) -> Option<Paquet> {
        Paquet::vide(n)
    }
    fn completer(&mut self, o: &[u8]) {
        if let Some(d) = self.ajouter_fin(o.len()) {
            d.copy_from_slice(o);
        }
    }
}

/// À qui va un segment, dans la table des ports.
#[derive(Clone)]
pub enum Cible {
    Socket(Arc<Socket>),
    /// La fille `numero` de l'écoute.
    Fille(Arc<Socket>, u64),
}

/// Une entrée de TIME_WAIT : ses règles (inet::tcp::attente), et ce que le
/// noyau en garde.
#[derive(Clone, Copy)]
struct TempsAttente {
    /// Son numéro à elle, dans la table et la liste des échéances (pas
    /// celui de la socket : voir `ports_tcp::Table::temps_attente`).
    numero: u64,
    locale: [u8; 4],
    distante: [u8; 4],
    regles: itcp::attente::Attente,
    /// Le TOS de la socket quand elle y est entrée (`tw_tos`) : celui de ses
    /// ACK.
    tos: u8,
    /// La liaison de la socket à une interface (`tw_bound_dev_if`) : celle de
    /// ses ACK et de ses RST (sa table la garde aussi) ; et son IP_TRANSPARENT
    /// (`tw_transparent` : leur source peut ne pas être à nous).
    interface: u32,
    transparent: bool,
    /// Son échéance (/proc/net/tcp la montre).
    echeance: u64,
}

static TABLE: Verrou<Option<ports_tcp::Table<Cible>>> = Verrou::new(None);

/// La mémoire de TCP de toute la machine (le `tcp_memory_allocated` de
/// Linux), en octets : ce que gardent les connexions, en réception (taille
/// vraie) et en attente d'acquittement. Chaque socket y compte la sienne
/// après chaque événement (`Partie::compter`), et la rend en disparaissant.
/// Sans elle, chaque socket est bornée seule, mais pas leur somme : un
/// programme ordinaire, ouvrant des connexions qu'il ne lit pas, ferait
/// garder toute la mémoire de la machine au noyau.
static MEMOIRE: AtomicUsize = AtomicUsize::new(0);
/// Ses seuils (`tcp_mem`), posés au démarrage : 4,7 %, 6,25 % et 9,4 % de la
/// mémoire.
static SEUILS: [AtomicUsize; 3] = [AtomicUsize::new(usize::MAX), AtomicUsize::new(usize::MAX), AtomicUsize::new(usize::MAX)];
/// La pression (`tcp_memory_pressure`) : entrée au-delà du deuxième seuil, sortie
/// seulement sous le premier (une hystérésis : la mémoire qui hésite autour d'un
/// seuil ne ferait pas battre les fenêtres de toutes les connexions).
static PRESSION: AtomicBool = AtomicBool::new(false);
/// Les sockets TCP vivantes (`tcp_sockets_allocated`), pour la juste part de chacune.
static SOCKETS: AtomicUsize = AtomicUsize::new(0);
/// Les plafonds des tampons d'une connexion que la machine permet
/// (`tcp_rmem[2]`, `tcp_wmem[2]`), posés au démarrage. L'échelle de fenêtre
/// que proposent les connexions dépend du premier (et de `rmem_max`,
/// `itcp::echelle`) ; SO_SNDBUF grandit jusqu'au second.
static RECEPTION_MAX: AtomicUsize = AtomicUsize::new(RCVBUF_DEFAUT as usize);
static ENVOI_MAX: AtomicUsize = AtomicUsize::new(itcp::SNDBUF_MAX);

/// `tcp_mem`, en octets.
pub fn seuils_memoire() -> [usize; 3] {
    [SEUILS[0].load(Ordering::Relaxed), SEUILS[1].load(Ordering::Relaxed), SEUILS[2].load(Ordering::Relaxed)]
}

/// `tcp_rmem[1]` et `tcp_rmem[2]`.
pub fn reception_reglee() -> (u32, usize) {
    (RCVBUF_DEFAUT, RECEPTION_MAX.load(Ordering::Relaxed))
}

/// `tcp_wmem[1]` et `tcp_wmem[2]`.
pub fn envoi_regle() -> (u32, usize) {
    (SNDBUF_DEFAUT, ENVOI_MAX.load(Ordering::Relaxed))
}

/// La plus grande place de réception possible, pour l'échelle de fenêtre
/// (`tcp_select_initial_window` : `tcp_rmem[2]`, au moins `rmem_max`).
fn reception_max() -> usize {
    RECEPTION_MAX.load(Ordering::Relaxed).max(socket::TAMPON_MAX as usize)
}

/// Où en est la mémoire de TCP de toute la machine (`__sk_mem_raise_allocated`,
/// `__sk_mem_reduce_allocated`).
fn niveau_memoire() -> itcp::Memoire {
    let m = MEMOIRE.load(Ordering::Relaxed);
    if m <= SEUILS[0].load(Ordering::Relaxed) {
        PRESSION.store(false, Ordering::Relaxed);
    } else if m > SEUILS[1].load(Ordering::Relaxed) {
        PRESSION.store(true, Ordering::Relaxed);
    }
    if m > SEUILS[2].load(Ordering::Relaxed) {
        itcp::Memoire::Limite
    } else if PRESSION.load(Ordering::Relaxed) {
        itcp::Memoire::Pression
    } else if m > SEUILS[0].load(Ordering::Relaxed) {
        itcp::Memoire::Souple
    } else {
        itcp::Memoire::Libre
    }
}

/// Le niveau pour une socket qui garde `m` octets : sous pression, celle qui a
/// plus que sa juste part de la limite se fait refuser ce qui dépasse le minimum
/// (`__sk_mem_raise_allocated`, « Try to be fair among all the sockets »). `sk_mem_pages`
/// compte en pages.
fn niveau_pour(niveau: itcp::Memoire, m: usize) -> itcp::Memoire {
    let part = SOCKETS.load(Ordering::Relaxed).saturating_mul(m.div_ceil(4096) * 4096);
    if niveau == itcp::Memoire::Pression && SEUILS[2].load(Ordering::Relaxed) <= part { itcp::Memoire::Excedent } else { niveau }
}

static TW: Verrou<Vec<TempsAttente>> = Verrou::new(Vec::new());
/// Les sockets orphelines (fermées par le programme, connexion pas finie) :
/// le repos du réseau les attend.
static ORPHELINES: AtomicUsize = AtomicUsize::new(0);
/// Les sockets qui ont une échéance inscrite (le détecteur
/// d'interblocage : un minuteur peut encore réveiller un programme).
static MINUTEURS: AtomicUsize = AtomicUsize::new(0);

/// Fait la table des ports et celle des TIME_WAIT. Au démarrage.
pub fn initialiser() {
    // Tout d'après les pages LIBRES à cet instant (`nr_free_buffer_pages`),
    // pas toute la mémoire : l'image et le noyau n'en font pas partie.
    let libres = crate::pages::libres();
    // Les seuils de `tcp_mem` (`tcp_init_mem`) : un seizième de ces pages,
    // au moins 128 ; 3/4 de cela, cela, puis le double du premier.
    let limite = (libres / 16).max(128);
    SEUILS[0].store(limite / 4 * 3 * 4096, Ordering::Relaxed);
    SEUILS[1].store(limite * 4096, Ordering::Relaxed);
    SEUILS[2].store(limite / 4 * 3 * 2 * 4096, Ordering::Relaxed);
    // `tcp_rmem[2]` et `tcp_wmem[2]` (`tcp_init`) : un 128e de ces pages, au
    // plus 32 Mio et 4 Mio, au moins 128 Kio et 64 Kio. Sur la machine de
    // l'étape (2 Gio) : 12 à 15 Mio selon l'image, une échelle de 8.
    let par_socket = libres * 4096 / 128;
    RECEPTION_MAX.store(par_socket.min(32 << 20).max(131_072), Ordering::Relaxed);
    ENVOI_MAX.store(par_socket.min(itcp::SNDBUF_MAX).max(64 << 10), Ordering::Relaxed);
    *TABLE.verrouiller() = ports_tcp::Table::new(MAX_PORTS, crate::aleatoire::u32);
    let mut tw = TW.verrouiller();
    if TABLE.verrouiller().is_none() || tw.try_reserve_exact(MAX_TW).is_err() {
        afficherln!("[reseau] plus de memoire pour les tables de TCP.");
    }
}

/// Les orphelines en vie (le repos du réseau).
pub fn orphelines() -> usize {
    ORPHELINES.load(Ordering::Relaxed)
}

/// Les sockets dont un minuteur est armé (le détecteur d'interblocage).
pub fn minuteurs_armes() -> usize {
    MINUTEURS.load(Ordering::Relaxed)
}

/// L'heure, pour les connexions (en nanosecondes).
fn maintenant() -> u64 {
    crate::temps::ns_monotone()
}

/// L'adresse locale et distante, le port local et distant d'une socket.
#[derive(Clone, Copy, Default)]
pub struct Adresses {
    pub lie: bool,
    /// L'adresse de `bind`, gardée à la fin d'une connexion
    /// (SOCK_BINDADDR_LOCK) ; avec IP_BIND_ADDRESS_NO_PORT, elle peut être
    /// là sans port (`lie` faux).
    pub adresse_choisie: bool,
    pub adresse: [u8; 4],
    pub port: u16,
    pub port_choisi: bool,
    pub distante: [u8; 4],
    pub port_distant: u16,
    /// L'adresse source de la connexion.
    pub source: [u8; 4],
}

/// Une fille d'une écoute, avant `accept`.
pub struct Fille {
    numero: u64,
    tcb: Box<Tcb<Paquet>>,
    locale: [u8; 4],
    distante: [u8; 4],
    identifiant: u16,
    /// Sa poignée de main a abouti : elle est dans la file d'acceptation
    /// (`inet_csk_reqsk_queue_add`), et y reste jusqu'à `accept`, quoi
    /// qu'elle devienne : CLOSE_WAIT (le client a envoyé sa requête et son
    /// FIN avant l'accept : HTTP/1.0, une sonde de santé), ou fermée par un
    /// RST (accept la rend, sa première lecture dit ECONNRESET).
    etablie: bool,
    /// Le TTL, le TOS et l'interface du segment qui a fini sa poignée de
    /// main (`tcp_v4_syn_recv_sock` : `mc_ttl`, `rcv_tos`, `mc_index`), que
    /// sa socket gardera (IP_PKTOPTIONS, IP_MULTICAST_TTL).
    arrivee: (u8, u8, u32),
    /// Ses options IP : l'écho de celles de son SYN (`tcp_v4_save_options`),
    /// celles de son SYN-ACK et de ses segments, que sa socket gardera.
    options: fipv4::OptionsSortantes,
    /// La liaison de son écoute à une interface quand son SYN est arrivé (l'`ir_iif`
    /// de sa demande, `inet_request_bound_dev_if`) : l'interface de ses segments,
    /// et celle de sa socket (`inet_csk_clone_lock` : `sk_bound_dev_if`), même si
    /// l'écoute en change ensuite. De même IP_TRANSPARENT de l'écoute (le
    /// `no_srccheck` de sa demande).
    interface: u32,
    transparent: bool,
}

impl Fille {
    /// Ce que ses segments mettent dans leur en-tête IPv4, d'après `ecoute`
    /// (celui de son écoute) : ses options, sa liaison.
    fn ip(&self, ecoute: Ip) -> Ip {
        Ip { options: self.options, oif: self.interface, transparent: self.transparent, ..ecoute }
    }

    /// Émet ce qu'elle a à envoyer (`emettre_tcb`), avec `ecoute` (voir `ip`).
    fn emettre(&mut self, ecoute: Ip, recu: Option<&ipv4::EnteteRecu>) {
        let ip = self.ip(ecoute);
        emettre_tcb(&mut self.tcb, self.locale, self.distante, &mut self.identifiant, ip, recu, None);
    }

    /// Prête pour `accept` (`inet_csk_listen_poll` : la file d'acceptation
    /// n'est pas vide), la seule définition, pour poll, accept, l'admission
    /// d'un SYN et /proc/net/tcp.
    fn prete(&self) -> bool {
        self.etablie
    }
}

/// Après un événement des filles d'une écoute : celles dont la poignée de
/// main vient d'aboutir entrent dans la file d'acceptation ; une fille
/// fermée quitte la table (elle ne reçoit plus rien), et la file si sa
/// poignée de main n'avait pas abouti (un SYN-ACK resté sans réponse, un
/// RST, une erreur ICMP : `inet_csk_reqsk_queue_drop`).
fn ranger_filles(filles: &mut VecDeque<Fille>) {
    for f in filles.iter_mut() {
        f.etablie |= matches!(f.tcb.etat(), Etat::Etablie | Etat::AttenteFermeture);
        if f.tcb.etat() == Etat::Fermee
            && let Some(t) = TABLE.verrouiller().as_mut()
        {
            t.retirer(f.numero);
        }
    }
    filles.retain(|f| f.tcb.etat() != Etat::Fermee || f.etablie);
}

/// Ce que `connect`, `listen` et `shutdown` savent de la connexion (le `sock->state` de Linux,
/// `socket_state`), à côté de l'état de TCP (`Tcb::etat`, le `sk_state`).
///
/// Choix de conception : deux états, comme Linux. Celui de TCP change seul, au gré des
/// segments et des minuteurs ; celui-ci, seulement dans un appel système : il dit ce que le
/// programme a vu. Une connexion refusée est TCP_CLOSE, que le programme ait déjà eu
/// l'échec par `connect` ou pas encore : seul ce second état les distingue (pas vu :
/// `listen` refuse, EINVAL ; vu, la socket est redevenue neuve). Écartés : tout tirer de
/// l'état de TCP (ces deux cas-là s'y confondent) ; les deux booléens d'avant (« établie
/// un jour », « connect non bloquant en cours »), qui ne savaient dire ni un `connect`
/// bloquant interrompu par un signal (encore en cours : le suivant rend 0 quand elle est
/// établie), ni SS_DISCONNECTING.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtatSocket {
    /// SS_UNCONNECTED : neuve, une écoute, ou défaite (AF_UNSPEC, `shutdown` en SYN_SENT, un
    /// `connect` qui a vu l'échec).
    NonConnectee,
    /// SS_CONNECTING : un `connect` l'a lancée, et aucun ne l'a encore vue aboutir ou échouer.
    EnConnexion,
    /// SS_CONNECTED : un `connect` l'a vue établie (ou `shutdown`, pendant qu'elle était en
    /// cours), ou c'est une fille rendue par `accept`.
    Connectee,
    /// SS_DISCONNECTING : `shutdown` pendant qu'elle était en cours sans être établie
    /// (SYN_RECEIVED, ou déjà fermée) : `connect` et `listen` refusent (EINVAL) jusqu'à
    /// AF_UNSPEC.
    EnDeconnexion,
}

/// Ce qu'est la socket.
pub enum Mode {
    Neuve,
    Ecoute { backlog: usize, filles: VecDeque<Fille> },
    /// Dans le tas, comme la `tcp_sock` de Linux (`sk_prot_alloc`) : plus d'un Kio qui ne doit
    /// ni passer par la pile de 16 Kio de qui la manipule, ni grossir chaque `Partie`.
    Connexion(Box<Tcb<Paquet>>),
}

/// La partie possédée.
pub struct Partie {
    pub numero: u64,
    pub mode: Mode,
    pub adresses: Adresses,
    /// L'identifiant IP des paquets de la connexion (`inet_id`).
    identifiant: u16,
    /// Fermée par le programme.
    orpheline: bool,
    /// L'entrée de la table n'est plus à elle (rendue, ou en TIME_WAIT).
    hors_table: bool,
    /// Les options de SOL_TCP.
    pub options: OptionsTcp,
    /// Ce qu'en savent `connect`, `listen` et `shutdown` (`sock->state`).
    pub etat_socket: EtatSocket,
    /// Les déconnexions (`sk_disconnects`) : AF_UNSPEC, et un `connect` qui voit l'échec ;
    /// un `connect` bloquant qui en voit passer une pendant qu'il dort rend EPIPE.
    deconnexions: u32,
    /// L'échéance inscrite dans la liste du réseau pour cette socket.
    echeance_armee: Option<u64>,
    /// La mémoire que la socket a comptée dans celle de TCP (`MEMOIRE`).
    memoire_comptee: usize,
    /// L'erreur d'une socket redevenue neuve (`sk_err`, après `tcp_disconnect`) : plus de connexion
    /// pour la tenir, mais SO_ERROR, `poll` et la lecture la disent encore.
    erreur_seule: i32,
    /// Ce que la carte a encore d'elle (`sk_wmem_alloc`, TSQ).
    retenue: Arc<Retenue>,
    /// La route de la connexion a été oubliée (`sk_dst_reset`, par SO_BINDTODEVICE,
    /// SO_DONTROUTE ou un IP_TOS qui change) et pas encore retrouvée : IP_MTU dit
    /// ENOTCONN jusqu'au prochain segment qui en trouve une (`ip_queue_xmit` la
    /// regarde : mesuré).
    route_oubliee: bool,
}

/// Les options de SOL_TCP.
#[derive(Clone, Copy)]
pub struct OptionsTcp {
    pub nodelay: bool,
    pub cork: bool,
    pub keepidle: u32,
    pub keepintvl: u32,
    pub keepcnt: u32,
    pub syncnt: u32,
    pub linger2: i32,
    pub maxseg: u16,
    pub quickack: bool,
    pub defer_accept: u32,
    pub user_timeout: u32,
    /// Les copies de SO_KEEPALIVE et SO_OOBINLINE (gardées sous le Mutex
    /// de la socket, que la réception ne peut pas prendre : une fille les
    /// hérite de son écoute dans la tâche du réseau), et SO_SNDBUF et
    /// SO_RCVBUF fixés par le programme (`SOCK_SNDBUF_LOCK`,
    /// `SOCK_RCVBUF_LOCK`).
    pub keepalive: bool,
    pub oobinline: bool,
    pub sndbuf_fixe: bool,
    pub rcvbuf_fixe: bool,
    /// Les copies de SO_RCVLOWAT (le seuil de poll et de recv), d'IP_TTL et
    /// d'IP_TOS (ceux de chaque segment émis), pour la même raison.
    pub rcvlowat: u32,
    pub ttl: u8,
    pub tos: u8,
    /// La copie d'IP_MTU_DISCOVER (DF, et la MTU à suivre), pour la même raison.
    pub pmtudisc: u8,
    /// La copie d'IP_MINTTL, pour la même raison : un segment reçu, ou une
    /// erreur ICMP, de TTL plus petit est jeté.
    pub minttl: u8,
    /// La copie d'IP_OPTIONS, pour la même raison : les options de chaque segment.
    pub ip_options: fipv4::OptionsSortantes,
    /// La copie de SO_BINDTODEVICE, pour la même raison : l'interface de la
    /// route de chaque segment (`sk_bound_dev_if`, la seule de TCP :
    /// IP_UNICAST_IF ne compte pas).
    pub interface: u32,
    /// La copie d'IP_TRANSPARENT : ses segments peuvent partir d'une adresse
    /// qui n'est pas à nous (FLOWI_FLAG_ANYSRC, `inet_sk_flowi_flags`).
    pub transparent: bool,
    /// La copie de SO_DONTROUTE : chaque route de la socket est de portée
    /// « lien » (`ip_sock_rt_scope`) ; une fille en hérite (`sk_clone`).
    pub dontroute: bool,
    /// TCP_WINDOW_CLAMP (0 : rien), d'une socket pas encore connectée, et d'une
    /// écoute : ses filles en héritent (`tcp_openreq_init_rwin`).
    pub window_clamp: u32,
    /// TCP_CONGESTION : le contrôle de la socket, et de ses filles
    /// (`tcp_ca_openreq_child`).
    pub controle: itcp::Controle,
    /// Ce que la socket garde d'une connexion (TCP_MAXSEG, TCP_INFO, SIOCOUTQ le
    /// montrent hors connexion, et la suivante en reprend une part) : rien pour une
    /// socket neuve, puis ce que lui laisse chaque connexion.
    pub hors_connexion: itcp::Restes,
}

impl OptionsTcp {
    /// `syncnt` à 0 : celui du système (TCP_SYNCNT se lit alors 6), comme
    /// le `icsk_syn_retries` de Linux ; une fille en hérite pour ses
    /// SYN-ACK (5 par défaut).
    pub const DEFAUT: OptionsTcp = OptionsTcp {
        nodelay: false, cork: false, keepidle: 7200, keepintvl: 75, keepcnt: 9, syncnt: 0, linger2: 60, maxseg: 0,
        quickack: true, defer_accept: 0, user_timeout: 0, keepalive: false, oobinline: false, sndbuf_fixe: false,
        rcvbuf_fixe: false, rcvlowat: 1, ttl: ipv4::TTL_DEFAUT, tos: 0, pmtudisc: 1, minttl: 0, ip_options: fipv4::OptionsSortantes::AUCUNE, window_clamp: 0,
        controle: itcp::Controle::DEFAUT, interface: 0, transparent: false, dontroute: false,
        hors_connexion: itcp::Restes::NEUF,
    };

    /// Ce que la connexion en retient (TCP_USER_TIMEOUT est en ms, les
    /// délais du keepalive en secondes).
    pub fn reglages(&self, orpheline: bool) -> itcp::Reglages {
        const S: u64 = 1_000_000_000;
        itcp::Reglages {
            syn_essais: self.syncnt, delai_utilisateur: self.user_timeout as u64 * 1_000_000, orpheline,
            nodelay: self.nodelay, cork: self.cork, keepalive: self.keepalive, keepidle: self.keepidle as u64 * S,
            keepintvl: self.keepintvl as u64 * S, keepcnt: self.keepcnt, oobinline: self.oobinline, defer_accept: self.defer_accept,
        }
    }
}

/// Le premier étage, lu par `poll` sous le verrou court.
#[derive(Clone, Copy)]
pub struct Premier {
    pub etat: Option<Etat>,
    pub ecoute: bool,
    pub lisibles: usize,
    /// Tout ce qui est reçu et pas lu (`rcv_nxt - copied_seq`), l'octet urgent compris ; et RCV.NXT.
    pub en_file: usize,
    pub rcv_nxt: u32,
    pub fin_recue: bool,
    pub erreur: i32,
    pub place: usize,
    pub sndbuf: usize,
    /// SO_RCVBUF (la borne de la file `backlog`).
    pub rcvbuf: usize,
    /// Les filles établies, prêtes pour `accept`, et la longueur de la file d'écoute.
    pub pretes: usize,
    pub file: usize,
    /// Un octet urgent à lire (POLLPRI).
    pub urgent: bool,
    pub arret: u8,
    /// SO_RCVLOWAT, et une fenêtre de réception presque fermée (moins d'un
    /// segment : POLLIN quand même, sans quoi un seuil plus grand que la
    /// place ne serait jamais atteint, `tcp_epollin_ready`).
    pub rcvlowat: usize,
    pub fenetre_basse: bool,
    /// `poll` a trouvé le tampon d'envoi trop plein (SOCK_NOSPACE) : à dire à la
    /// connexion (`Possede::descendre`), qu'il ne peut pas toucher.
    pub sans_place: bool,
    /// Combien de pointeurs urgents neufs vus (`tcp_check_urg` : `sk_send_sigurg`).
    pub urgents: u32,
}

/// Ce qui arrive à une socket depuis le réseau : un segment, ou une
/// erreur ICMP pour un de ses paquets.
pub enum Arrivee {
    Segment(Segment),
    /// L'errno (`icmp_err_convert`), le réseau ou la machine injoignables
    /// (RFC 6069), le numéro de séquence du segment d'origine (vérifié
    /// contre ce qui est en vol), la fille visée ; IP_RECVERR de la socket ;
    /// le TTL de l'en-tête recopié dans le message (IP_MINTTL).
    Erreur { errno: i32, injoignable: bool, seq: u32, fille: Option<u64>, recverr: bool, abandon: bool, ttl: u8 },
    /// « Fragmentation nécessaire » : la MTU qu'elle dit, et de même le numéro, la fille, le TTL.
    Mtu { info: u32, seq: u32, fille: Option<u64>, ttl: u8 },
}

/// Un segment reçu, pour une socket (ou la fille d'une écoute).
pub struct Segment {
    entete: Tcp,
    charge: Paquet,
    source: [u8; 4],
    destination: [u8; 4],
    /// Ce que la réception a gardé de son en-tête IPv4 (le TTL, le TOS, les
    /// options : leur écho, pour lui répondre), l'interface d'arrivée.
    ip: ipv4::EnteteRecu,
    interface: u32,
    /// Sa destination est une diffusion, dans une trame pour nous seuls (le
    /// RTCF_BROADCAST de sa route) : une écoute de 0.0.0.0 la voit, mais n'en
    /// fait jamais de fille.
    diffusion: bool,
    fille: Option<u64>,
    /// Un SYN qui reprend le quadruplet d'une entrée de TIME_WAIT : le
    /// numéro initial de la fille, plus loin que tout ce que l'ancienne
    /// connexion a envoyé (RFC 1122 4.2.2.13, `tw_isn`).
    isn: Option<u32>,
}

/// La taille vraie de ce qui arrive, pour la borne de la file `backlog`.
fn taille(a: &Arrivee) -> usize {
    match a {
        Arrivee::Segment(s) => s.charge.taille_vraie(),
        Arrivee::Erreur { .. } | Arrivee::Mtu { .. } => 64,
    }
}

impl Partie {
    /// Le premier étage d'après la partie ; `sndbuf` : SO_SNDBUF d'une
    /// socket sans connexion (une connexion a le sien, qui grandit).
    fn premier(&self, arret: u8, sndbuf: usize, rcvbuf: usize) -> Premier {
        let (etat, lisibles, fin_recue, erreur, place, sndbuf, rcvbuf, urgent, fenetre_basse) = match &self.mode {
            Mode::Connexion(t) => (Some(t.etat()), t.lisibles_dans_le_flux(), t.fin_recue(), t.erreur(), t.place(), t.sndbuf, t.rcvbuf, t.urgent_a_lire(),
                                   t.fenetre_presque_fermee()),
            _ => (None, 0, false, self.erreur_seule, sndbuf, sndbuf, rcvbuf, false, false),
        };
        let (ecoute, pretes, file) = match &self.mode {
            Mode::Ecoute { filles, backlog } => (true, filles.iter().filter(|f| f.prete()).count(), *backlog),
            _ => (false, 0, 0),
        };
        Premier {
            etat, ecoute, lisibles, fin_recue, erreur, place, sndbuf, rcvbuf, pretes, file, urgent, arret, rcvlowat: self.options.rcvlowat as usize,
            fenetre_basse, sans_place: false,
            en_file: if let Mode::Connexion(t) = &self.mode { t.lisibles() } else { 0 },
            rcv_nxt: if let Mode::Connexion(t) = &self.mode { t.numeros().2 } else { 0 },
            urgents: if let Mode::Connexion(t) = &self.mode { t.urgents_annonces() } else { 0 },
        }
    }

    /// Recopie le premier étage, et rend les événements qui ont changé
    /// (pour réveiller).
    fn rafraichir(&self, court: &mut Premier) -> u32 {
        let mut neuf = self.premier(court.arret, court.sndbuf, court.rcvbuf);
        neuf.sans_place = court.sans_place;
        let mut m = 0;
        if neuf.lisibles > court.lisibles || neuf.fin_recue != court.fin_recue || neuf.pretes > court.pretes {
            m |= POLLIN | POLLRDNORM;
        }
        if neuf.place > court.place {
            m |= POLLOUT | POLLWRNORM;
        }
        if neuf.etat != court.etat || neuf.erreur != court.erreur {
            m |= POLLIN | POLLOUT | POLLERR | POLLHUP;
        }
        if neuf.urgent && !court.urgent {
            m |= POLLPRI;
        }
        m |= Partie::evenements_asynchrones(court, &neuf);
        *court = neuf;
        m
    }

    /// Ce qu'il y a à dire à ceux qui veulent un signal (`sk_wake_async`), d'après ce qui a changé : ce
    /// que `sk_data_ready` et `tcp_fin` (la lecture), `tcp_rcv_synsent_state_process` (établie),
    /// `sk_error_report`, `sk_stream_write_space` (la place, au tiers de SO_SNDBUF) et `tcp_check_urg`.
    fn evenements_asynchrones(avant: &Premier, neuf: &Premier) -> u32 {
        use crate::asynchrone::{A_COUPURE, A_ERREUR, A_ETABLIE, A_FIN, A_LECTURE, A_OCTET_URGENT, A_PLACE, A_URGENT};
        let mut m = 0;
        // `tcp_data_ready` : à chaque avancée, si `tcp_epollin_ready` (tout ce qui est reçu compte,
        // l'octet urgent compris) ou si le FIN est là. Le FIN seul y passe donc aussi, en plus de
        // ce que dit `tcp_fin`.
        let assez = neuf.en_file >= neuf.rcvlowat || neuf.fenetre_basse || neuf.fin_recue;
        if (neuf.rcv_nxt != avant.rcv_nxt && assez) || neuf.pretes > avant.pretes {
            m |= A_LECTURE;
        }
        if neuf.fin_recue && !avant.fin_recue {
            // Pas de POLL_HUP pour une fermeture à moitié (`tcp_fin`).
            let fini = neuf.arret == socket::ARRET_LECTURE | socket::ARRET_ECRITURE || neuf.etat == Some(Etat::Fermee);
            m |= if fini { A_COUPURE } else { A_FIN };
        }
        let en_syn = |e: Option<Etat>| matches!(e, Some(Etat::SynEnvoye | Etat::SynRecu));
        if en_syn(avant.etat) && !en_syn(neuf.etat) && neuf.etat != Some(Etat::Fermee) {
            m |= A_ETABLIE;
        }
        if neuf.erreur != 0 && neuf.erreur != avant.erreur {
            m |= A_ERREUR;
        }
        if neuf.place > avant.place && neuf.place >= neuf.sndbuf / 3 && neuf.arret & socket::ARRET_ECRITURE == 0 {
            m |= A_PLACE;
        }
        if neuf.urgents != avant.urgents {
            m |= A_URGENT;
        }
        if neuf.urgent && !avant.urgent {
            m |= A_OCTET_URGENT;
        }
        m
    }

    /// Émet ce que la connexion a à envoyer.
    fn emettre(&mut self) {
        self.emettre_apres(None);
    }

    /// Le même, juste après avoir reçu un segment de l'en-tête IPv4 `recu`,
    /// auquel peut répondre la connexion (un RST).
    fn emettre_apres(&mut self, recu: Option<&ipv4::EnteteRecu>) {
        let Mode::Connexion(t) = &mut self.mode else { return };
        if emettre_tcb(t, self.adresses.source, self.adresses.distante, &mut self.identifiant, Ip::de(&self.options), recu, Some(&self.retenue)) {
            self.route_oubliee = false;
        }
    }

    /// Après un événement : ce que devient la connexion (`apres_l_etat`),
    /// puis sa mémoire comptée dans celle de TCP, et le niveau de celle-ci
    /// dit à la connexion (et aux filles d'une écoute) pour la suite.
    fn apres(&mut self) {
        self.apres_l_etat();
        self.compter();
    }

    /// La mémoire de la socket, comptée dans `MEMOIRE` (la différence avec
    /// ce qu'elle y avait déjà).
    fn compter(&mut self) {
        let niveau = niveau_memoire();
        let m = match &mut self.mode {
            Mode::Connexion(t) => {
                t.memoire = niveau_pour(niveau, t.memoire());
                t.memoire()
            }
            Mode::Ecoute { filles, .. } => filles
                .iter_mut()
                .map(|f| {
                    f.tcb.memoire = niveau_pour(niveau, f.tcb.memoire());
                    f.tcb.memoire()
                })
                .sum(),
            Mode::Neuve => 0,
        };
        if m > self.memoire_comptee {
            MEMOIRE.fetch_add(m - self.memoire_comptee, Ordering::Relaxed);
        } else {
            MEMOIRE.fetch_sub(self.memoire_comptee - m, Ordering::Relaxed);
        }
        self.memoire_comptee = m;
    }

    /// Ce qu'une connexion devient après un événement : TIME_WAIT (ou
    /// orpheline en FIN_WAIT_2) : une entrée de TIME_WAIT, la socket n'a
    /// plus d'entrée dans la table ; fermée et orpheline : l'entrée rendue.
    /// (Fermée, le programme la tenant encore : l'entrée reste, son
    /// quadruplet pris, jusqu'au `close`, ou jusqu'à ce qu'elle redevienne
    /// neuve, `redevenir_neuve`.)
    fn apres_l_etat(&mut self) {
        let Mode::Connexion(t) = &self.mode else {
            self.armer();
            return;
        };
        if self.hors_table {
            return;
        }
        let etat = t.etat();
        let fin_orpheline = self.orpheline && etat == Etat::FinAttente2;
        if fin_orpheline && self.options.linger2 < 0 {
            // TCP_LINGER2 négatif : une orpheline n'attend pas en
            // FIN_WAIT_2, elle coupe la connexion (RST, `tcp_close` et
            // `tcp_rcv_state_process`, TCPAbortOnLinger).
            if let Mode::Connexion(t) = &mut self.mode {
                t.avorter();
            }
            self.emettre();
            if let Some(t) = TABLE.verrouiller().as_mut() {
                t.retirer(self.numero);
            }
            self.desarmer();
            self.quitter_la_table();
            return;
        }
        if etat == Etat::TempsAttente || fin_orpheline {
            // Une orpheline en FIN_WAIT_2 attend TCP_LINGER2 (60 s par
            // défaut, `tcp_fin_timeout`), au moins 3,5 RTO (`tcp_fin_time`) ;
            // TIME_WAIT, 60 s.
            let duree = if fin_orpheline {
                let linger2 = if self.options.linger2 > 0 { self.options.linger2 as u64 * 1_000_000_000 } else { TEMPS_ATTENTE };
                let rto = t.congestion().2;
                linger2.max(4 * rto - rto / 2)
            } else {
                TEMPS_ATTENTE
            };
            let echeance = crate::temps::ns_monotone() + duree;
            let numero = socket::nouveau_numero();
            let e = TempsAttente {
                numero, locale: self.adresses.source, distante: self.adresses.distante, regles: t.en_attente(fin_orpheline), tos: self.options.tos,
                interface: self.options.interface, transparent: self.options.transparent, echeance,
            };
            // L'entrée de TIME_WAIT prend un numéro neuf, et l'échéance
            // qui va avec ; la socket n'a plus d'entrée dans la table.
            self.desarmer();
            let mut tw = TW.verrouiller();
            // La place prise au démarrage : MAX_TW entrées, ou aucune si le
            // tas n'avait pas pu la donner (`initialiser`).
            if tw.len() < tw.capacity() {
                tw.ajouter_dans_la_place(e);
                drop(tw);
                if let Some(t) = TABLE.verrouiller().as_mut() {
                    t.temps_attente(self.numero, numero);
                }
                super::tache::armer(numero, Some(echeance));
            } else {
                drop(tw);
                // Pleine : pas de TIME_WAIT, comme Linux au-delà de
                // `tcp_max_tw_buckets`.
                if let Some(t) = TABLE.verrouiller().as_mut() {
                    t.retirer(self.numero);
                }
            }
            self.quitter_la_table();
        } else if etat == Etat::Fermee && self.orpheline {
            if let Some(t) = TABLE.verrouiller().as_mut() {
                t.retirer(self.numero);
            }
            self.desarmer();
            self.quitter_la_table();
        } else if etat == Etat::Fermee {
            // Finie, mais le programme tient le descripteur (`tcp_done`, `tcp_set_state`) : elle ne
            // garde pas son quadruplet : un SYN du même client irait à une connexion morte. Son port
            // reste s'il vient de `bind` ; sinon, il est rendu (`inet_put_port`).
            if let Some(t) = TABLE.verrouiller().as_mut() {
                if self.adresses.port_choisi {
                    t.redevenir_liee(self.numero, self.adresses.source);
                } else {
                    t.retirer(self.numero);
                    self.quitter_la_table();
                }
            }
            if self.hors_table {
                self.desarmer();
            } else {
                self.armer();
            }
        } else {
            self.armer();
        }
    }

    /// Inscrit la prochaine échéance de la connexion (ou de ses filles)
    /// dans la liste du réseau, si elle a changé.
    fn armer(&mut self) {
        if self.hors_table {
            return;
        }
        let e = match &self.mode {
            Mode::Connexion(t) => t.echeance(),
            Mode::Ecoute { filles, .. } => filles.iter().filter_map(|f| f.tcb.echeance()).min(),
            Mode::Neuve => None,
        };
        // Une fin d'émission a rappelé la socket, sans passer par ici : son échéance à
        // elle (tout de suite) tient jusqu'à ce qu'elle tombe.
        let e = if self.retenue.a_pousser() { Some(0) } else { e };
        if e == self.echeance_armee {
            return;
        }
        // La seule à ne pas attendre le tic de la roue : la compression des SACK, moins d'une
        // milliseconde (`compressed_ack_timer`, un hrtimer).
        let fine = match &self.mode {
            Mode::Connexion(t) => t.echeance_fine(),
            Mode::Ecoute { filles, .. } => filles.iter().filter_map(|f| f.tcb.echeance_fine()).min(),
            Mode::Neuve => None,
        };
        match (self.echeance_armee, e) {
            (None, Some(_)) => {
                MINUTEURS.fetch_add(1, Ordering::Relaxed);
            }
            (Some(_), None) => {
                MINUTEURS.fetch_sub(1, Ordering::Relaxed);
            }
            _ => {}
        }
        self.echeance_armee = e;
        match e {
            Some(t) if t == 0 || fine == e => {
                super::tache::armer_precis(self.numero, t);
            }
            _ => {
                super::tache::armer(self.numero, e);
            }
        }
    }

    /// La socket n'a plus d'échéance : retirée de la liste.
    fn desarmer(&mut self) {
        if self.echeance_armee.is_some() {
            super::tache::armer(self.numero, None);
            self.oublier_echeance();
        }
    }

    /// L'échéance n'est plus dans la liste (tombée, ou reprise par une
    /// entrée de TIME_WAIT) : la socket l'oublie.
    fn oublier_echeance(&mut self) {
        if self.echeance_armee.take().is_some() {
            MINUTEURS.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// La socket redevient neuve (TCP_CLOSE), et peut se connecter à nouveau
    /// ou écouter : après un `connect` qui n'a pas abouti (refusé, abandonné),
    /// ou `connect(AF_UNSPEC)` (`oublier_la_connexion`, qui efface aussi ce
    /// qu'efface `tcp_disconnect`). Son entrée de la table est rendue ; un
    /// port choisi par `bind` est gardé (SOCK_BINDPORT_LOCK), lié de nouveau
    /// à son adresse.
    fn redevenir_neuve(&mut self, s: &Arc<Socket>) {
        // Ce que les tampons sont devenus reste (`tcp_disconnect` n'y touche pas), et ce
        // que la connexion laisse du MSS.
        if let Mode::Connexion(t) = &self.mode {
            s.rcvbuf.store(t.rcvbuf.min(i32::MAX as usize) as u32, Ordering::Relaxed);
            s.sndbuf.store(t.sndbuf.min(i32::MAX as usize) as u32, Ordering::Relaxed);
            self.options.hors_connexion = t.restes();
        }
        let a = self.adresses;
        let dans_la_table = !self.hors_table;
        if dans_la_table
            && let Some(t) = TABLE.verrouiller().as_mut()
        {
            // Le port de `bind` n'a jamais été rendu (une fille d'une écoute à port nommé : l'écoute
            // le tient aussi, ce qui ne se heurte pas).
            if a.port_choisi {
                t.redevenir_liee(self.numero, a.adresse);
            } else {
                t.retirer(self.numero);
            }
        }
        self.desarmer();
        self.mode = Mode::Neuve;
        self.hors_table = false;
        self.etat_socket = EtatSocket::NonConnectee;
        // L'adresse de `bind` reste (SOCK_BINDADDR_LOCK), avec ou sans son port. Un port qui
        // n'était pas de `bind` est rendu, mais getsockname le montre encore (`inet_sport`, que
        // `inet_put_port` ne remet pas à 0 : mesuré), sans que la socket le tienne (`lie` faux :
        // IP_PROTOCOL dit 0, et `bind`, `listen` ou `connect` en prendra un).
        let adresse = if a.adresse_choisie { a.adresse } else { [0; 4] };
        self.adresses = Adresses { adresse, adresse_choisie: a.adresse_choisie, port: a.port, ..Adresses::default() };
        if a.port_choisi && dans_la_table {
            self.adresses = Adresses { lie: true, adresse: a.adresse, port: a.port, port_choisi: true, ..self.adresses };
        } else if a.port_choisi {
            let op = s.appels.verrouiller().options;
            let lien = Lien {
                sorte: Sorte::Liee, adresse: a.adresse, port: a.port, distante: [0; 4], port_distant: 0, reuseaddr: op.reuseaddr,
                reuseport: op.reuseport, uid: s.uid, par_connect: false, plage: op.local_port_range, interface: op.interface,
            };
            let lie = TABLE.verrouiller().as_mut().map(|t| t.lier(self.numero, lien, Cible::Socket(s.clone()), crate::aleatoire::u32()));
            if let Some(Ok(port)) = lie {
                self.adresses = Adresses { lie: true, adresse: a.adresse, port, port_choisi: true, ..self.adresses };
            }
        }
        // Ce qu'elle tenait est rendu : `tcp_mem` n'a plus à le compter.
        self.compter();
    }

    /// `tcp_disconnect`, depuis `connect(AF_UNSPEC)` et `shutdown` : plus rien de la connexion ou de
    /// l'écoute ; un RST s'il en faut un, et l'erreur que verra le programme.
    fn deconnecter(&mut self, s: &Arc<Socket>) {
        let _contexte = contexte::entrer();
        let ip = Ip::de(&self.options);
        match &mut self.mode {
            Mode::Connexion(t) => {
                let (rst, erreur) = t.deconnexion();
                if erreur {
                    self.erreur_seule = inet::tcp::ECONNRESET;
                } else {
                    self.erreur_seule = t.prendre_erreur();
                }
                if rst {
                    t.avorter_sur_donnees();
                    self.emettre();
                }
            }
            Mode::Ecoute { filles, .. } => arreter_les_filles(filles, ip),
            Mode::Neuve => {}
        }
        self.oublier_la_connexion(s);
    }

    /// `tcp_disconnect` : la socket redevient neuve, et oublie `rx_opt` (TCP_MAXSEG :
    /// mesuré, la connexion suivante annonce le MSS de sa route) ; ce qu'elle garde de la
    /// connexion devient ce qu'en laisse `tcp_disconnect` (`Restes::deconnecte`), une fois
    /// de plus si elle n'en avait déjà plus (AF_UNSPEC sur une socket neuve, ou défaite par un
    /// autre fil : la suite des numéros saute encore, comme chez Linux). Ce que fait aussi
    /// `connect`, quand il voit qu'une connexion n'a pas abouti (`__inet_stream_connect`,
    /// `sock_error`).
    fn oublier_la_connexion(&mut self, s: &Arc<Socket>) {
        self.redevenir_neuve(s);
        self.options.maxseg = 0;
        self.options.hors_connexion = self.options.hors_connexion.deconnecte(maintenant());
    }

    /// Un `connect` voit que la connexion n'a pas abouti (`sock_error`) : la socket est
    /// défaite (`tcp_disconnect`, une déconnexion de plus), SS_UNCONNECTED.
    fn voir_l_echec(&mut self, s: &Arc<Socket>) {
        self.oublier_la_connexion(s);
        self.deconnexions = self.deconnexions.wrapping_add(1);
    }

    /// La socket ne tient plus d'entrée dans la table : une connexion finie,
    /// ou passée à TIME_WAIT. Un port qui n'était pas de `bind` est rendu
    /// (`tcp_set_state`, TCP_CLOSE : `inet_put_port` sans SOCK_BINDPORT_LOCK) :
    /// IP_PROTOCOL dit 0 (`lie` faux), getsockname le montre encore (mesuré,
    /// coupée par un RST comme en TIME_WAIT) ; un port de `bind` se dit
    /// encore tenu (en TIME_WAIT, l'entrée de la table le tient pour elle).
    fn quitter_la_table(&mut self) {
        self.hors_table = true;
        if !self.adresses.port_choisi {
            self.adresses.lie = false;
        }
        if self.orpheline {
            ORPHELINES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for Partie {
    /// Une socket rendue : elle ne compte plus pour le détecteur (son
    /// échéance, si elle en avait encore une, tombera sur une socket
    /// absente, sans effet), et rend sa mémoire à celle de TCP.
    fn drop(&mut self) {
        self.oublier_echeance();
        MEMOIRE.fetch_sub(self.memoire_comptee, Ordering::Relaxed);
        SOCKETS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Ce qu'une connexion met dans l'en-tête IPv4 de ses segments : IP_TTL,
/// IP_TOS et IP_OPTIONS de sa socket (ses copies, dans les options) ; une
/// fille, l'écho des options de son SYN. Et ce que demande leur route :
/// l'interface (`oif` : la liaison, SO_BINDTODEVICE ; 0 : aucune), et une
/// source qui peut ne pas être à nous (`transparent` : IP_TRANSPARENT,
/// FLOWI_FLAG_ANYSRC ; sinon, une source qui n'est pas à nous n'a pas de
/// route, `ip_route_output_key_hash_rcu` : un segment pour une adresse
/// d'ailleurs, livré ici par lo, ne reçoit aucune réponse).
#[derive(Clone, Copy)]
struct Ip {
    ttl: u8,
    tos: u8,
    pmtudisc: u8,
    options: fipv4::OptionsSortantes,
    oif: u32,
    transparent: bool,
    /// La portée de ses routes (« lien » avec SO_DONTROUTE).
    portee: Portee,
}

impl Ip {
    /// Celui d'une réponse sans socket (un RST, l'ACK d'une fille ou d'une
    /// entrée de TIME_WAIT : `ip_send_unicast_reply`, par la socket de
    /// contrôle de TCP, `ipv4_tcp_sk`) au segment reçu `recu`, venu de
    /// `source` : le TTL du système, 64 (celui de la socket de contrôle,
    /// pas l'IP_TTL de la connexion), DF (`IP_PMTUDISC_DO`, `tcp_sk_init`),
    /// le TOS `tos`, et l'écho des options du segment ; sa route par `oif`
    /// (l'`arg.bound_dev_if` d'`ip_send_unicast_reply` : la liaison de la
    /// socket qui répond, celle de son écoute pour une fille, celle d'une
    /// entrée de TIME_WAIT ; 0 sans socket, et pour l'ACK d'une demande,
    /// `tcp_v4_reqsk_send_ack`), une source qui n'est pas à nous permise si
    /// cette socket est `transparent` (IP_REPLY_ARG_NOSRCCHECK). None : l'écho
    /// est impossible, et Linux ne répond pas.
    fn reponse(recu: &ipv4::EnteteRecu, source: [u8; 4], tos: u8, oif: u32, transparent: bool) -> Option<Ip> {
        let options = fipv4::options_echo(recu.options(), &recu.compilees, source, &ipv4::unicast).ok()?;
        Some(Ip { ttl: ipv4::TTL_DEFAUT, tos, pmtudisc: 2, options, oif, transparent, portee: Portee::Univers })
    }

    fn de(o: &OptionsTcp) -> Ip {
        Ip {
            ttl: o.ttl, tos: o.tos, pmtudisc: o.pmtudisc, options: o.ip_options, oif: o.interface, transparent: o.transparent,
            portee: if o.dontroute { Portee::Lien } else { Portee::Univers },
        }
    }

    /// Où vont les paquets pour `distante` : d'abord à la première étape d'une
    /// route source (`faddr`).
    fn vers(&self, distante: [u8; 4]) -> [u8; 4] {
        if self.options.places.route_source != 0 { self.options.premier_saut } else { distante }
    }
}

/// Émet les segments de la connexion `t`, de `source` à `distante`, avec ce
/// que dit `ip` de leur en-tête IPv4 et de leur route ; `recu` : l'en-tête du
/// segment qu'elle vient de recevoir, s'il y en a un, dont ses réponses
/// prennent le leur. Leur route est cherchée une fois, avant (la même pour
/// tous : `__sk_dst_check`, puis `ip_route_output_ports`) ; sa MTU vérifie
/// le MSS, et le Tcb sait ce qui ne partira pas (`emettre_route`). Rend vrai
/// si un de ses segments (pas une réponse) a trouvé sa route.
fn emettre_tcb(t: &mut Tcb<Paquet>, source: [u8; 4], distante: [u8; 4], identifiant: &mut u16, ip: Ip, recu: Option<&ipv4::EnteteRecu>,
               retenue: Option<&Arc<Retenue>>) -> bool {
    if let Some(r) = retenue {
        t.poser_en_file(r.octets(), r.rendu());
    }
    let route = route_de_segment(&ip, source, distante, false);
    if let Some((c, d)) = route {
        t.verifier_mtu(ipv4::mtu_vers(&c, d));
    }
    let mut a_envoyer: Vec<itcp::Sortant> = Vec::new();
    let mut route_trouvee = false;
    t.emettre_route(maintenant(), route.is_some(), |s| {
        // Sans place, le segment ne part pas : la retransmission y pourvoira, et personne ne doit
        // le croire encore dans la carte. Il compte comme un paquet que Linux n'a pas pu faire.
        let (numero, compte) = (s.numero, s.compte);
        if a_envoyer.ajouter(s).is_err() {
            compte.compter(&MIB, true, false);
            if let Some(r) = retenue
                && numero != 0
            {
                r.envoi_perdu(numero);
            }
        }
    });
    for s in a_envoyer {
        // La réponse à un segment refusé (le RST d'une connexion ou d'une
        // fille, l'ACK d'une fille à un segment hors de sa fenêtre) part comme
        // celle d'un segment sans connexion, pas avec ce qu'a demandé la socket
        // (`tcp_v4_send_reset`, `tcp_v4_reqsk_send_ack`, puis
        // `ip_send_unicast_reply`) : le TOS du segment sans ses bits ECN,
        // l'écho de ses options, rien si l'écho est impossible. Une réponse
        // naît d'un segment reçu, et part juste après lui : `recu` est là.
        // Un RST part par la liaison de la socket (celle de l'écoute pour une
        // fille) ; l'ACK d'une fille en SYN_RECEIVED, sans (`tcp_v4_reqsk_send_ack`).
        let ip = match (s.compte, recu) {
            (Compte::Reponse { rst }, Some(r)) => match Ip::reponse(r, distante, r.tos & !ipv4::ECN, if rst { ip.oif } else { 0 }, ip.transparent) {
                Some(ip) => ip,
                None => {
                    s.compte.compter(&MIB, false, false);
                    continue;
                }
            },
            _ => ip,
        };
        // Un ACK pur, un RST ne tiennent pas la socket (`skb_is_tcp_pure_ack`).
        let suivi = retenue.filter(|_| s.numero != 0).map(|r| (r, s.numero));
        let reponse = matches!(s.compte, Compte::Reponse { .. });
        let sa_route = if reponse { route_de_segment(&ip, source, distante, true) } else { route };
        let routee = envoyer_segment(&s.entete, s.compte, source, distante, identifiant, ip, sa_route, s.longueur, suivi, |o| t.copier_envoi(s.debut, o));
        route_trouvee |= routee && !reponse;
    }
    if t.prendre_etrangle()
        && let Some(r) = retenue
    {
        r.etrangler();
    }
    route_trouvee
}

/// La route d'un segment de `source` à `distante`, avec ce que dit `ip` : par
/// `ip.oif` (sa liaison), d'une source à nous sauf `ip.transparent`, vers la
/// première étape d'une route source. Une route source stricte dont la
/// première étape n'est pas une voisine : pas de route pour un segment d'une
/// socket (`__ip_queue_xmit`, `inet_csk_route_req`) ; une réponse sans socket
/// (`reponse`) part quand même (`ip_send_unicast_reply` ne la regarde pas).
fn route_de_segment(ip: &Ip, source: [u8; 4], distante: [u8; 4], reponse: bool) -> Option<(inet::routes::Chemin, [u8; 4])> {
    ipv4::router_depuis(ip.vers(distante), source, ip.oif, ip.transparent, ip.portee).ok().filter(|(c, d)| {
        !ip.options.places.stricte || reponse || !matches!(c, inet::routes::Chemin::Unicast { prochain, .. } if *prochain != *d)
    })
}

/// Écrit et émet un segment : l'en-tête `h`, `longueur` octets de charge
/// remplis par `remplir`, de `source` à `distante`, avec ce que dit `ip`
/// de l'en-tête IPv4, par `route` (`route_de_segment` ; None : il n'en a
/// pas). La somme n'est pas calculée par `lo` (comme Linux) ; elle prend la
/// vraie destination (`tcp_v4_send_check` : `inet_daddr`), et l'en-tête IPv4
/// va à la première étape d'une route source. Un segment qui ne part pas
/// (plus de mémoire, pas de route) est perdu, comme sur un câble. Il compte
/// dans /proc/net/snmp ce que dit `compte`. Rend vrai s'il a une route.
fn envoyer_segment(h: &Tcp, compte: Compte, source: [u8; 4], distante: [u8; 4], identifiant: &mut u16, ip: Ip,
                   route: Option<(inet::routes::Chemin, [u8; 4])>, longueur: usize, suivi: Option<(&Arc<Retenue>, u64)>,
                   remplir: impl FnOnce(&mut [u8])) -> bool {
    let n = ftcp::longueur_entete(&h.options);
    let paquet = Paquet::vide(n + longueur);
    let routee = route.is_some();
    compte.compter(&MIB, routee, paquet.is_some());
    let (Some((chemin, destination)), Some(mut p)) = (route, paquet) else {
        // Il ne partira pas : personne ne le rendra.
        if let Some((r, numero)) = suivi {
            r.envoi_perdu(numero);
        }
        return routee;
    };
    let Some(o) = p.ajouter_fin(n + longueur) else { return routee };
    remplir(&mut o[n..]);
    let finale = if ip.options.places.route_source != 0 { distante } else { destination };
    ftcp::ecrire(o, h, source, finale, !ipv4::par_lo(&chemin));
    if let Some((r, numero)) = suivi {
        p.attacher(r, numero);
    }
    *identifiant = identifiant.wrapping_add(1);
    let envoi = ipv4::Envoi {
        source, destination, protocole: fipv4::TCP, ttl: ip.ttl, tos: ip.tos, identifiant: *identifiant,
        ne_pas_fragmenter: ipv4::ne_pas_fragmenter(ip.pmtudisc, destination), mtu: ipv4::mtu_d_envoi(ip.pmtudisc, &chemin, destination), confirmer: false,
        options: ip.options, destination_finale: finale,
    };
    ipv4::emettre(chemin, &envoi, p);
    true
}

/// Répond à un segment sans connexion (RST), de `locale` à `distante`, avec
/// le TOS du segment (`recu`) sans ses bits ECN (`tcp_v4_send_reset`) et
/// l'écho de ses options, par l'interface `oif` (la liaison de la socket qui
/// le refuse, une écoute ou une entrée de TIME_WAIT ; 0 sans socket : « When
/// socket is gone, all binding information is lost », dit Linux), de
/// `locale` à nous sauf pour une socket `transparent`. Impossible : rien ne
/// part, mais le RST compte (`tcp_v4_send_reset` compte après
/// `ip_send_unicast_reply`, qui s'est tue).
fn repondre_rst(h: &Tcp, longueur_charge: usize, locale: [u8; 4], distante: [u8; 4], recu: &ipv4::EnteteRecu, oif: u32, transparent: bool) {
    if let Some(r) = itcp::reponse_sans_connexion(h, longueur_charge) {
        let Some(ip) = Ip::reponse(recu, distante, recu.tos & !ipv4::ECN, oif, transparent) else {
            return Compte::Reponse { rst: true }.compter(&MIB, false, false);
        };
        let mut id = crate::aleatoire::u32() as u16;
        let route = route_de_segment(&ip, locale, distante, true);
        envoyer_segment(&r, Compte::Reponse { rst: true }, locale, distante, &mut id, ip, route, 0, None, |_| {});
    }
}

impl Possede for Partie {
    type Court = Premier;
    type Element = Arrivee;

    fn traiter(&mut self, a: Arrivee) {
        // Le garde ici, à part du reste : `lo` se vide quand il tombe, et ce vidage reçoit à
        // son tour, sur la même pile : autant que le cadre de ce qui suit n'y soit plus.
        let _contexte = contexte::entrer();
        self.traiter_arrivee(a);
    }

    fn publier(&self, court: &mut Premier) -> u32 {
        self.rafraichir(court)
    }

    fn descendre(&mut self, court: &mut Premier) {
        if core::mem::take(&mut court.sans_place) && let Mode::Connexion(t) = &mut self.mode {
            t.marquer_sans_place();
        }
    }

    /// L'échéance de la socket est tombée (elle n'est plus dans la liste) :
    /// la connexion, ou chaque fille d'une écoute, fait ce qui est échu ;
    /// une fille dont les SYN-ACK sont restés sans réponse s'en va.
    fn minuteur(&mut self) {
        let _contexte = contexte::entrer();
        self.oublier_echeance();
        let maintenant = maintenant();
        let ip = Ip::de(&self.options);
        let (defer, syncnt) = (self.options.defer_accept, self.options.syncnt);
        let pousse = self.retenue.pousse();
        match &mut self.mode {
            Mode::Connexion(t) => {
                t.minuteur(maintenant);
                if pousse {
                    t.fin_d_emission();
                }
            }
            Mode::Ecoute { filles, backlog } => {
                let embryons = filles.iter().filter(|f| f.tcb.etat() == Etat::SynRecu);
                let qlen = embryons.clone().count() as u32;
                let jeunes = embryons.filter(|f| f.tcb.fille_jeune()).count() as u32;
                let essais = itcp::essais_de_filles(syncnt, qlen, jeunes, *backlog as u32);
                for f in filles.iter_mut() {
                    f.tcb.reglages.defer_accept = defer;
                    f.tcb.reglages.syn_essais = syncnt;
                    f.tcb.reduire_essais(essais);
                    f.tcb.minuteur(maintenant);
                    f.emettre(ip, None);
                }
                ranger_filles(filles);
            }
            Mode::Neuve => {}
        }
        self.emettre();
        self.apres();
    }
}

impl Partie {
    /// Ce qui vient d'arriver du réseau.
    #[inline(never)]
    fn traiter_arrivee(&mut self, a: Arrivee) {
        let s = match a {
            Arrivee::Segment(s) => s,
            Arrivee::Erreur { errno, injoignable, seq, fille, recverr, abandon, ttl } => {
                if !self.ttl_trop_petit(ttl, fille) {
                    self.erreur_icmp(errno, injoignable, seq, fille, recverr, abandon);
                }
                self.emettre();
                self.apres();
                return;
            }
            Arrivee::Mtu { info, seq, fille, ttl } => {
                if !self.ttl_trop_petit(ttl, fille) {
                    self.mtu_reduite(info, seq, fille);
                }
                self.emettre();
                self.apres();
                return;
            }
        };
        // IP_MINTTL (`tcp_v4_rcv`, après la recherche) : une connexion, une
        // fille établie (une socket chez Linux), une écoute (ses SYN) ; pas
        // une fille en SYN_RECEIVED (une `request_sock`, servie avant).
        if self.ttl_trop_petit(s.ip.ttl, s.fille) {
            return;
        }
        let recu = s.ip;
        match &mut self.mode {
            Mode::Connexion(t) => {
                t.recevoir(&s.entete, s.charge, maintenant());
            }
            Mode::Ecoute { .. } => self.traiter_ecoute(s),
            Mode::Neuve => {
                // Plus rien n'écoute ici (un `listen` défait par un
                // `connect` qui a échoué...) : RST, par sa liaison.
                repondre_rst(&s.entete, s.charge.longueur(), s.destination, s.source, &s.ip, self.options.interface, self.options.transparent);
            }
        }
        self.emettre_apres(Some(&recu));
        self.apres();
    }

    /// IP_MINTTL (RFC 5082, GTSM) : un segment ou une erreur ICMP de TTL
    /// `ttl` est-il jeté ? Oui sous le minimum, pour la socket et pour une
    /// fille établie (elle l'a hérité), pas pour une fille dont la poignée
    /// de main n'a pas abouti (`tcp_v4_rcv` et `tcp_v4_err` servent une
    /// `request_sock` avant de regarder). L'erreur ICMP compare le TTL de
    /// l'en-tête recopié, comme `tcp_v4_err` (son `iph`). Linux compte
    /// TCPMinTTLDrop, que nous n'avons pas (pas de /proc/net/netstat).
    fn ttl_trop_petit(&self, ttl: u8, fille: Option<u64>) -> bool {
        if ttl >= self.options.minttl {
            return false;
        }
        match (&self.mode, fille) {
            // Une fille partie entre-temps : le segment ira à l'écoute, qui regarde.
            (Mode::Ecoute { filles, .. }, Some(n)) => filles.iter().find(|f| f.numero == n).is_none_or(|f| f.tcb.etat() != Etat::SynRecu),
            // Plus rien n'écoute : Linux ne la trouverait pas, et répondrait
            // RST quel que soit le TTL.
            (Mode::Neuve, _) => false,
            _ => true,
        }
    }

    /// « Fragmentation nécessaire » (`tcp_v4_err`, TCP_MTU_REDUCED_DEFERRED) : ignorée si
    /// le segment d'origine n'est pas en vol (la route non plus ne change pas : mesuré) ;
    /// sinon la route la retient, et la connexion suit. Ni une écoute, ni une fille en
    /// SYN_RECEIVED (`tcp_req_err` : ses SYN-ACK sont toujours petits).
    fn mtu_reduite(&mut self, info: u32, seq: u32, fille: Option<u64>) {
        let pmtudisc = self.options.pmtudisc;
        // La portée de la socket : celle de l'écoute pour une fille pas encore
        // acceptée (elle en a hérité SO_DONTROUTE).
        let portee = Ip::de(&self.options).portee;
        let (t, distante, oif) = match (&mut self.mode, fille) {
            (Mode::Connexion(t), None) => (t, self.adresses.distante, self.options.interface),
            (Mode::Ecoute { filles, .. }, Some(n)) => {
                let Some(f) = filles.iter_mut().find(|f| f.numero == n && f.tcb.etat() != Etat::SynRecu) else { return };
                (&mut f.tcb, f.distante, f.interface)
            }
            _ => return,
        };
        let (una, nxt, _) = t.numeros();
        if itcp::avant(seq, una) || itcp::apres(seq, nxt) {
            return;
        }
        ipv4::apprendre_mtu(distante, info);
        let Ok((c, d)) = ipv4::router(distante, None, oif, portee) else { return };
        // (`ip_sk_accept_pmtu`, et IP_PMTUDISC_DONT.)
        let suivre = !matches!(pmtudisc, 0 | 4 | 5);
        t.mtu_reduite(info, ipv4::mtu_vers(&c, d), ipv4::ne_pas_fragmenter(pmtudisc, d), suivre);
    }

    /// Une erreur ICMP (`tcp_v4_err`) : ignorée si le segment d'origine
    /// n'est pas en vol (entre SND.UNA et SND.NXT : un ICMP forgé ne peut
    /// pas couper une connexion sans connaître ses numéros) ; sinon la
    /// connexion décide, inet::tcp::erreur_icmp. Une fille en SYN_RECEIVED
    /// (`tcp_req_err`) : retirée seulement pour son SYN-ACK (le numéro
    /// exact) et une erreur d'`abandon` (réseau ou hôte injoignable, TTL
    /// dépassé, paramètre), sans rien dire ; une autre erreur (un « port
    /// injoignable » forgé) ne la touche pas.
    fn erreur_icmp(&mut self, errno: i32, injoignable: bool, seq: u32, fille: Option<u64>, recverr: bool, abandon: bool) {
        let en_vol = |t: &Tcb<Paquet>| {
            let (una, nxt, _) = t.numeros();
            !itcp::avant(seq, una) && !itcp::apres(seq, nxt)
        };
        match (&mut self.mode, fille) {
            (Mode::Connexion(t), None) if en_vol(t) => {
                t.erreur_icmp(errno, seq, injoignable, recverr, maintenant());
            }
            (Mode::Ecoute { filles, .. }, Some(n)) => {
                let Some(f) = filles.iter_mut().find(|f| f.numero == n) else { return };
                if f.tcb.etat() == Etat::SynRecu {
                    if abandon && seq == f.tcb.numeros().0 {
                        if let Some(t) = TABLE.verrouiller().as_mut() {
                            t.retirer(n);
                        }
                        filles.retain(|f| f.numero != n);
                    }
                } else if en_vol(&f.tcb) {
                    // Une fille établie, en attente d'accept : une connexion
                    // comme une autre (chez Linux, déjà une socket).
                    f.tcb.erreur_icmp(errno, seq, injoignable, recverr, maintenant());
                    ranger_filles(filles);
                }
            }
            _ => {}
        }
    }

    /// Un segment pour une écoute : un SYN (une fille neuve), ou un
    /// segment d'une fille.
    #[inline(never)]
    fn traiter_ecoute(&mut self, mut s: Segment) {
        let ip = Ip::de(&self.options);
        let defer = self.options.defer_accept;
        let numero_ecoute = self.numero;
        let Mode::Ecoute { backlog, filles } = &mut self.mode else { return };
        if let Some(n) = s.fille {
            if let Some(f) = filles.iter_mut().find(|f| f.numero == n) {
                f.tcb.reglages.defer_accept = defer;
                let en_poignee = f.tcb.etat() == Etat::SynRecu;
                f.tcb.recevoir(&s.entete, s.charge, maintenant());
                if en_poignee && f.tcb.etat() != Etat::SynRecu {
                    f.arrivee = (s.ip.ttl, s.ip.tos, s.interface);
                }
                f.emettre(ip, Some(&s.ip));
                ranger_filles(filles);
                return;
            }
            // La fille n'est plus là depuis que le segment l'a trouvée dans
            // la table. Acceptée entre-temps : la table désigne sa socket,
            // une autre, à qui il va. Retirée (un RST, ses SYN-ACK restés
            // sans réponse) : il est traité ici, comme un segment de
            // l'écoute, jamais relivré par la table, qui le rendrait à
            // l'écoute elle-même, dont nous pouvons tenir le verrou court
            // (`du_reseau`).
            let objet = TABLE.verrouiller().as_ref().and_then(|t| t.objet(n));
            if let Some(Cible::Socket(sock)) = objet {
                vers_socket(&sock, Arrivee::Segment(Segment { fille: None, ..s }));
                return;
            }
            s.fille = None;
        }
        let h = s.entete;
        if h.drapeaux & ftcp::RST != 0 {
            return;
        }
        if h.drapeaux & ftcp::ACK != 0 {
            // Un ACK pour une fille qu'on n'a plus : RST (`tcp_rcv_state_process`, TCP_LISTEN),
            // par la liaison de l'écoute.
            repondre_rst(&h, s.charge.longueur(), s.destination, s.source, &s.ip, ip.oif, ip.transparent);
            return;
        }
        // Ni un SYN, ni un SYN|FIN : rien, pas même un RST : ce que distinguent les balayages FIN et
        // NULL (`TCP_FLAGS`). Un SYN vers une diffusion : rien non plus (`tcp_v4_conn_request`,
        // ListenDrops). (Un ACK vers elle a tenté plus haut son RST : il compte, mais n'a pas de
        // route, sauf de la diffusion d'un réseau pour une écoute IP_TRANSPARENT.)
        if h.drapeaux & ftcp::SYN == 0 || h.drapeaux & ftcp::FIN != 0 || s.diffusion {
            return;
        }
        // Un SYN : jeté si la file d'acceptation est pleine, ou s'il y a
        // déjà backlog + 1 filles (`tcp_conn_request`).
        let pretes = filles.iter().filter(|f| f.prete()).count();
        if pretes > *backlog || filles.len() > *backlog || filles.try_reserve(1).is_err() {
            return;
        }
        let Ok(place) = faillible::boite_vide() else { return };
        let numero = socket::nouveau_numero();
        let iss = s.isn.unwrap_or_else(|| numero_initial(s.destination, s.source, h.destination, h.source));
        // L'écho des options du SYN (`tcp_v4_save_options` : impossible, aucune) :
        // celles du SYN-ACK et de la fille, qui leur laisse leur place dans son MSS
        // (`tcp_v4_syn_recv_sock`) ; avec une route source, la route va à sa
        // première étape (`inet_csk_route_req`).
        let options = fipv4::options_echo(s.ip.options(), &s.ip.compilees, s.source, &ipv4::unicast)
            .unwrap_or(fipv4::OptionsSortantes::AUCUNE);
        let ip_fille = Ip { options, ..ip };
        // La route du SYN-ACK d'abord (`tcp_conn_request` : `route_req`,
        // `inet_csk_route_req`) : celle de ses segments, par la liaison de
        // l'écoute, de l'adresse visée, sa route source stricte comprise ;
        // sans elle, pas de demande, le SYN est jeté (OutNoRoutes ; et
        // ListenDrops, un compteur que nous n'avons pas). Ainsi une adresse
        // d'ailleurs, livrée ici par lo, n'a pas de fille, sauf pour une
        // écoute IP_TRANSPARENT.
        if route_de_segment(&ip_fille, s.destination, s.source, false).is_none() {
            MIB.ip(CompteurIp::OutNoRoutes);
            return;
        }
        let vers = ip_fille.vers(s.source);
        let mss = mss_vers(vers, ip.oif, ip.portee);
        let Some(moi) = par_numero(self.numero) else { return };
        // Une fille hérite des tampons de son écoute, et de SO_SNDBUF fixé
        // (`sk_clone_lock` : `sk_sndbuf`, `sk_rcvbuf`, `sk_userlocks`) :
        // c'est ainsi qu'un serveur règle ses connexions, et la fenêtre que
        // la fille annonce (son échelle est choisie ici, au SYN).
        let rcvbuf = moi.rcvbuf.load(Ordering::Relaxed) as usize;
        let echelle = itcp::echelle(rcvbuf, self.options.rcvbuf_fixe, reception_max(), self.options.window_clamp);
        let mut tcb = tcb_de_syn(place, &h, iss, mss, rcvbuf, moi.sndbuf.load(Ordering::Relaxed) as usize, echelle);
        tcb.poser_mss_utilisateur(self.options.maxseg);
        tcb.poser_options_ip(options.longueur);
        tcb.window_clamp = self.options.window_clamp;
        tcb.rcvbuf_fixe = self.options.rcvbuf_fixe;
        tcb.rcvbuf_max = RECEPTION_MAX.load(Ordering::Relaxed);
        tcb.rcvlowat = self.options.rcvlowat;
        // Pas de programme encore : `accept` la lui donnera.
        tcb.attachee = false;
        tcb.decalage_horodatages(decalage_horodatages(s.destination, s.source));
        tcb.reglages = self.options.reglages(false);
        tcb.sndbuf_fixe = self.options.sndbuf_fixe;
        tcb.sndbuf_max = ENVOI_MAX.load(Ordering::Relaxed);
        tcb.memoire = niveau_memoire();
        tcb.poser_controle(self.options.controle);
        tcb.sans_file = sans_carte(vers, ip.oif, ip.portee);
        // Elle hérite de ce que l'écoute permet (`sk_clone_lock`) : un serveur SO_REUSEADDR doit
        // pouvoir redémarrer tant que vivent ses connexions, et jusqu'en TIME_WAIT (`tw_reuse`) ;
        // et de sa liaison à une interface.
        let ajoutee = TABLE.verrouiller().as_mut().is_some_and(|t| {
            let (reuseaddr, reuseport, uid, plage) =
                t.lien(numero_ecoute).map_or((false, false, 0, 0), |l| (l.reuseaddr, l.reuseport, l.uid, l.plage));
            let lien = Lien {
                sorte: Sorte::Connectee, adresse: s.destination, port: h.destination, distante: s.source, port_distant: h.source,
                reuseaddr, reuseport, uid, par_connect: false, plage, interface: ip.oif,
            };
            t.ajouter_fille(numero, lien, Cible::Fille(moi, numero)).is_ok()
        });
        if !ajoutee {
            return;
        }
        let mut f = Fille {
            numero, tcb, locale: s.destination, distante: s.source, identifiant: crate::aleatoire::u32() as u16, etablie: false,
            arrivee: (0, 0, 0), options, interface: ip.oif, transparent: ip.transparent,
        };
        f.emettre(ip, None);
        // La place est prise plus haut, avant tout changement.
        filles.ajouter_derriere_dans_la_place(f);
    }
}

/// Écrit dans sa place du tas le bloc d'une fille, à part : `Tcb::depuis_syn` le rend par
/// valeur, plus d'un Kio qui resterait sur la pile de qui l'appelle, tant qu'il dure.
#[inline(never)]
fn tcb_de_syn(place: Box<MaybeUninit<Tcb<Paquet>>>, h: &Tcp, iss: u32, mss: u16, rcvbuf: usize, sndbuf: usize, echelle: u8) -> Box<Tcb<Paquet>> {
    Box::write(place, Tcb::depuis_syn(&MIB, h, iss, mss, rcvbuf, sndbuf, echelle))
}

/// De même pour `connect`, qui dort ensuite sur sa pile, jusqu'à la fin de la poignée de main.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn tcb_de_connect(place: Box<MaybeUninit<Tcb<Paquet>>>, port: u16, port_distant: u16, iss: u32, mss: u16, rcvbuf: usize, sndbuf: usize, echelle: u8) -> Box<Tcb<Paquet>> {
    Box::write(place, Tcb::connecter(&MIB, port, port_distant, iss, mss, rcvbuf, sndbuf, echelle))
}

/// Le numéro de séquence initial d'une connexion (`secure_tcp_seq`, RFC
/// 6528) : SipHash du quadruplet sous une clé secrète, plus l'horloge du
/// calendrier en unités de 64 ns (`seq_scale` : elle fait le tour des 32
/// bits en 274 s, et deux connexions successives du même quadruplet ne se
/// recouvrent pas). Le calendrier plutôt que le temps depuis le démarrage :
/// c'est celle de Linux, et elle ne repart pas de zéro avec la machine.
pub fn numero_initial(locale: [u8; 4], distante: [u8; 4], port: u16, port_distant: u16) -> u32 {
    let cle = cle_secrete();
    let h = crypto::siphash::siphash_3u32(u32::from_ne_bytes(locale), u32::from_ne_bytes(distante),
                                          (port as u32) << 16 | port_distant as u32, &cle);
    (h as u32).wrapping_add((crate::temps::ns_calendrier() >> 6) as u32)
}

/// Le décalage des horodatages entre deux adresses (`secure_tcp_ts_off`) :
/// SipHash du couple sous une clé secrète, la même pour toutes les connexions
/// de ce couple, une autre que celle des numéros de séquence (`ts_secret`) :
/// PAWS suppose une seule horloge par machine distante, et notre heure de
/// démarrage reste cachée.
fn decalage_horodatages(locale: [u8; 4], distante: [u8; 4]) -> u32 {
    static CLE: Verrou<Option<crypto::siphash::Cle>> = Verrou::new(None);
    let cle = *CLE.verrouiller();
    let cle = cle.unwrap_or_else(|| {
        let c = [crate::aleatoire::u64(), crate::aleatoire::u64()];
        *CLE.verrouiller().get_or_insert(c)
    });
    crypto::siphash::siphash_2u32(u32::from_ne_bytes(locale), u32::from_ne_bytes(distante), &cle) as u32
}

/// La clé secrète des numéros de séquence et des ports (`net_secret`),
/// tirée au premier usage.
fn cle_secrete() -> crypto::siphash::Cle {
    static CLE: Verrou<Option<crypto::siphash::Cle>> = Verrou::new(None);
    if let Some(c) = *CLE.verrouiller() {
        return c;
    }
    let c = [crate::aleatoire::u64(), crate::aleatoire::u64()];
    *CLE.verrouiller().get_or_insert(c)
}

/// Vers cette adresse, un paquet n'attend-il dans aucune carte (`lo`) ?
/// (Par l'interface `oif`, la liaison de la socket, et de la portée de ses
/// routes, comme ses segments.)
fn sans_carte(distante: [u8; 4], oif: u32, portee: Portee) -> bool {
    ipv4::router(distante, None, oif, portee).is_ok_and(|(c, _)| ipv4::par_lo(&c))
}

/// Le MSS qu'on annonce pour parler à `distante` : la MTU du chemin moins
/// 40 (les en-têtes d'IPv4 et de TCP).
fn mss_vers(distante: [u8; 4], oif: u32, portee: Portee) -> u16 {
    // (`ipv4_default_advmss` : d'après la MTU du chemin, ce qu'on en a appris compris, et au
    // moins `ip_rt_min_advmss`.)
    match ipv4::router(distante, None, oif, portee) {
        Ok((c, d)) => (ipv4::mtu_vers(&c, d).saturating_sub(40)).clamp(256, 65_495) as u16,
        Err(_) => itcp::MSS_DEFAUT,
    }
}

/// Livre un segment à sa cible, d'après la table.
fn livrer(s: Segment) {
    let h = s.entete;
    let cible = TABLE.verrouiller().as_ref().and_then(|t| t.trouver(s.source, h.source, s.destination, h.destination, s.interface));
    match cible {
        Some(Destinataire::Connexion(Cible::Socket(sock))) | Some(Destinataire::Ecoute(Cible::Socket(sock))) => {
            vers_socket(&sock, Arrivee::Segment(Segment { fille: None, ..s }));
        }
        Some(Destinataire::Connexion(Cible::Fille(ecoute, n))) | Some(Destinataire::Ecoute(Cible::Fille(ecoute, n))) => {
            vers_socket(&ecoute, Arrivee::Segment(Segment { fille: Some(n), ..s }));
        }
        Some(Destinataire::TempsAttente(n)) => temps_attente(n, s),
        // Sans socket, un RST seulement pour une de nos adresses
        // (`tcp_v4_send_reset` : la route du segment reçu doit être
        // RTN_LOCAL) : pas pour une diffusion, ni pour une adresse d'ailleurs
        // que lo nous a livrée (le SYN d'une socket liée à lo vers 192.0.2.1),
        // sans rien compter.
        None if ipv4::est_a_nous(s.destination) => {
            repondre_rst(&h, s.charge.longueur(), s.destination, s.source, &s.ip, 0, false);
        }
        None => {}
    }
}

/// Donne le segment à la socket : traité tout de suite, ou mis dans sa
/// file `backlog` si un appel la possède (bornée comme `tcp_add_backlog` :
/// deux fois SO_RCVBUF, plus la moitié de SO_SNDBUF, plus 64 Kio).
fn vers_socket(sock: &Arc<Socket>, a: Arrivee) {
    let Some(flux) = sock.flux.as_ref() else { return };
    let limite = flux.court(|c| 2 * c.rcvbuf + c.sndbuf / 2 + 65_536);
    let t = taille(&a);
    flux.du_reseau(a, t, limite);
}

/// Une erreur ICMP pour un segment TCP que nous avons envoyé (`tcp_v4_err`) :
/// la connexion trouvée par l'en-tête recopié dans le message (ses ports,
/// son numéro de séquence), puis la règle d'`icmp_err_convert`. Une entrée
/// de TIME_WAIT, une écoute : rien.
pub fn erreur(e: &super::icmp::ErreurRecue) {
    let i = &e.interne;
    let Some((port_source, port_destination)) = formats::reseau::icmp::ports(e.origine, i) else { return };
    let tcp = e.origine.get(i.longueur_entete..).unwrap_or(&[]);
    let Some(seq) = tcp.get(4..8).map(|o| u32::from_be_bytes([o[0], o[1], o[2], o[3]])) else { return };
    // (Ses 20 premiers octets au moins sont là : `icmp::ports` les a lus.)
    let ttl = e.origine.get(8).copied().unwrap_or(0);
    // (Cherchée par l'interface de la route du message, `inet_iif` de `tcp_v4_err`.)
    let cible = TABLE.verrouiller().as_ref().and_then(|t| t.trouver(i.destination, port_destination, i.source, port_source, e.iif));
    let (sock, fille) = match cible {
        Some(Destinataire::Connexion(Cible::Socket(s))) => (s, None),
        Some(Destinataire::Connexion(Cible::Fille(ecoute, n))) => (ecoute, Some(n)),
        // Une entrée de TIME_WAIT l'ignore. Sans connexion (une écoute ne compte pas :
        // `__inet_lookup_established` ne les cherche pas), une erreur pour rien.
        Some(Destinataire::TempsAttente(_)) => return,
        Some(Destinataire::Ecoute(_)) | None => {
            MIB.icmp(CompteurIcmp::InErrors);
            return;
        }
    };
    use formats::reseau::icmp;
    // « Fragmentation nécessaire » : la MTU du chemin, qui réduit le MSS
    // (`tcp_v4_mtu_reduced`), jamais une erreur, même avec IP_RECVERR (mesuré).
    if e.genre == icmp::INJOIGNABLE && e.code == icmp::FRAGMENTATION {
        let _contexte = contexte::entrer();
        vers_socket(&sock, Arrivee::Mtu { info: e.info, seq, fille, ttl });
        return;
    }
    let Some((errno, _)) = super::udp::convertir(e.genre, e.code, true) else { return };
    let injoignable = e.genre == icmp::INJOIGNABLE && (e.code == icmp::RESEAU || e.code == icmp::HOTE);
    // Ce qui retire une fille (l'`abort` de `tcp_req_err`).
    let abandon = injoignable || e.genre == icmp::TEMPS_DEPASSE || e.genre == icmp::PARAMETRE;
    let recverr = sock.recverr.load(Ordering::Relaxed);
    let _contexte = contexte::entrer();
    vers_socket(&sock, Arrivee::Erreur { errno, injoignable, seq, fille, recverr, abandon, ttl });
}

/// Un segment pour une entrée de TIME_WAIT : ses règles disent quoi faire
/// (inet::tcp::attente). Un SYN qui reprend le quadruplet va à l'écoute,
/// s'il y en a une ; sinon, l'entrée lui répond par un ACK.
fn temps_attente(n: u64, s: Segment) {
    let maintenant = crate::temps::ns_monotone();
    let h = s.entete;
    let (issue, e) = {
        let mut tw = TW.verrouiller();
        let Some(e) = tw.iter_mut().find(|e| e.numero == n) else { return };
        let issue = e.regles.recevoir(&h, s.charge.longueur() as u32, maintenant);
        if issue.prolonger {
            e.echeance = maintenant + TEMPS_ATTENTE;
        }
        (issue, *e)
    };
    if let Some(isn) = issue.reprendre {
        if TABLE.verrouiller().as_ref().and_then(|t| t.ecoute(s.destination, h.destination, s.interface)).is_some() {
            effacer_temps_attente(n);
            livrer(Segment { isn: Some(isn), ..s });
        } else {
            envoyer_ack_tw(&e, &s.ip, false);
        }
        return;
    }
    if issue.prolonger {
        super::tache::armer(n, Some(e.echeance));
    }
    if issue.effacer {
        effacer_temps_attente(n);
    }
    if issue.rst {
        repondre_rst(&h, s.charge.longueur(), s.destination, s.source, &s.ip, e.interface, e.transparent);
    }
    if issue.ack {
        envoyer_ack_tw(&e, &s.ip, issue.hors_fenetre);
    }
}

/// L'ACK d'une entrée de TIME_WAIT (`tcp_v4_timewait_ack`), en réponse au
/// segment reçu `recu` : avec l'écho de ses options ; impossible, rien ne
/// part, mais il compte (comme un RST). Son TOS est celui de la socket,
/// gardé par l'entrée (`tw_tos`), sans les bits ECN s'il répond à un
/// segment `hors_fenetre` (`TCP_TW_ACK_OOW`).
fn envoyer_ack_tw(e: &TempsAttente, recu: &ipv4::EnteteRecu, hors_fenetre: bool) {
    let r = e.regles.entete_ack(crate::temps::ns_monotone());
    let tos = if hors_fenetre { e.tos & !ipv4::ECN } else { e.tos };
    let Some(ip) = Ip::reponse(recu, e.distante, tos, e.interface, e.transparent) else {
        return Compte::Reponse { rst: false }.compter(&MIB, false, false);
    };
    let mut id = crate::aleatoire::u32() as u16;
    let route = route_de_segment(&ip, e.locale, e.distante, true);
    envoyer_segment(&r, Compte::Reponse { rst: false }, e.locale, e.distante, &mut id, ip, route, 0, None, |_| {});
}

fn effacer_temps_attente(n: u64) {
    TW.verrouiller().retain(|e| e.numero != n);
    if let Some(t) = TABLE.verrouiller().as_mut() {
        t.retirer(n);
    }
    super::tache::armer(n, None);
}

/// Une échéance du réseau pour l'objet `n` : une entrée de TIME_WAIT
/// échue (effacée), ou le minuteur d'une socket.
pub fn echeance(n: u64) -> bool {
    if TW.verrouiller().iter().any(|e| e.numero == n) {
        effacer_temps_attente(n);
        return true;
    }
    if let Some(s) = par_numero(n)
        && let Some(f) = s.flux.as_ref()
    {
        f.minuteur_du_reseau();
        return true;
    }
    false
}

/// La socket de numéro `n`, d'après la table des ports.
fn par_numero(n: u64) -> Option<Arc<Socket>> {
    match TABLE.verrouiller().as_ref()?.objet(n)? {
        Cible::Socket(s) => Some(s),
        Cible::Fille(..) => None,
    }
}

/// Un segment TCP reçu par `interface` (`p` : le segment, en-tête
/// compris ; `recu` : ce que la réception a gardé de son en-tête IPv4), par
/// la route de `iif` (`inet_iif` : par lo, celle de notre adresse visée),
/// de `source` pour `destination`, dans la tâche du réseau ou un
/// vidage de `lo` (`tcp_v4_rcv`) : l'en-tête et la somme (pas pour `lo`),
/// puis la socket. Un segment faux est jeté sans rien dire ; il compte
/// dans InSegs comme les autres (« même mauvais », `tcp_v4_rcv`), et dans
/// InErrs s'il a un en-tête faux (`bad_packet`) ou une somme fausse (avec
/// InCsumErrors) ; pas s'il est trop court pour son en-tête (`discard_it`).
/// `diffusion` : sa destination est une diffusion.
pub fn recevoir(ip: &fipv4::Ipv4, recu: &ipv4::EnteteRecu, i: &super::interface::Interface, iif: u32, diffusion: bool, mut p: Paquet) {
    MIB.tcp(Compteur::InSegs);
    let (source, destination, par_lo) = (ip.source, ip.destination, i.boucle());
    let (h, charge) = match ftcp::lire(p.donnees(), source, destination, !par_lo) {
        Ok(x) => x,
        Err(e) => {
            if e == Erreur::Somme {
                MIB.tcp(Compteur::InCsumErrors);
            }
            if e != Erreur::Tronque {
                MIB.tcp(Compteur::InErrs);
            }
            return;
        }
    };
    let entete = p.longueur() - charge.len();
    let _ = p.retirer_entete(entete);
    let _contexte = contexte::entrer();
    livrer(Segment { entete: h, charge: p, source, destination, ip: *recu, interface: iif, diffusion, fille: None, isn: None });
}

// --- Les appels ---

/// Une socket TCP neuve (`tcp_v4_init_sock`) : SO_RCVBUF et SO_SNDBUF de
/// TCP, son flux.
pub fn nouvelle(numero: u64) -> Option<Possession<Partie>> {
    let retenue = Arc::new(Retenue::new(numero)).ok()?;
    SOCKETS.fetch_add(1, Ordering::Relaxed);
    let partie = Partie {
        numero, mode: Mode::Neuve, adresses: Adresses::default(), identifiant: 0, orpheline: false, hors_table: false,
        options: OptionsTcp::DEFAUT, etat_socket: EtatSocket::NonConnectee, deconnexions: 0, echeance_armee: None, memoire_comptee: 0, erreur_seule: 0, retenue,
        route_oubliee: false,
    };
    let premier = partie.premier(0, SNDBUF_DEFAUT as usize, RCVBUF_DEFAUT as usize);
    Some(Possession::new(partie, premier))
}

fn flux(s: &Socket) -> &Possession<Partie> {
    s.flux.as_ref().expect("une socket TCP a son flux")
}

/// Lit une adresse d'IPv4 pour `bind` et `connect` : au moins 16 octets
/// (EINVAL), la famille AF_INET (bind : EAFNOSUPPORT ; AF_UNSPEC permis
/// avec 0.0.0.0, comme `__inet_bind`).
fn adresse(o: &[u8]) -> Result<socket::AdresseInet, i64> {
    socket::lire_adresse(o).ok_or(-EINVAL)
}

/// bind (`__inet_bind`, `inet_csk_get_port`) : l'adresse comme UDP
/// (`datagramme::adresse_de_bind` : à nous, une diffusion ou une
/// multidiffusion, que `connect` remplacera par celle de sa route, ou toute
/// adresse avec IP_FREEBIND ou IP_TRANSPARENT) ; avec
/// IP_BIND_ADDRESS_NO_PORT, le port 0 n'en prend pas : il viendra à
/// `listen` ou à `connect`, et un second `bind` reste permis. L'adresse est
/// vérifiée avant de prendre la socket, comme Linux (elle prend la table
/// des routes) ; la liaison à une interface et SO_REUSEADDR sont lus et
/// inscrits dans la table sous le `Mutex` des appels, qui les change
/// (`lier_a_une_interface`, `reutilisation_changee`) : un SO_BINDTODEVICE
/// qui passe pendant le `bind` est vu par la table, avant ou après lui
/// (`__inet_bind` tient la socket, `lock_sock`, et `inet_csk_get_port` lit
/// `sk_bound_dev_if` et `sk_reuse` sous elle). L'ordre est celui de
/// `lier_a_une_interface` : la possession, le `Mutex`, la table.
pub fn lier(s: &Arc<Socket>, o: &[u8]) -> Result<(), i64> {
    let a = adresse(o)?;
    if a.famille != socket::AF_INET && !(a.famille == socket::AF_UNSPEC && a.adresse == [0; 4]) {
        return Err(-EAFNOSUPPORT);
    }
    let libre = {
        let op = &s.appels.verrouiller().options;
        op.freebind || op.transparent
    };
    if !super::datagramme::adresse_de_bind(a.adresse, libre, false) {
        return Err(-EADDRNOTAVAIL);
    }
    if a.port != 0 && a.port < ports_tcp::PRIVILEGIE && s.uid != 0 {
        return Err(-EACCES);
    }
    let mut g = flux(s).posseder();
    let p = g.donnee();
    if p.adresses.lie || !matches!(p.mode, Mode::Neuve) {
        return Err(-EINVAL);
    }
    let appels = s.appels.verrouiller();
    let op = &appels.options;
    if a.port == 0 && op.bind_no_port {
        p.adresses = Adresses { adresse: a.adresse, adresse_choisie: a.adresse != [0; 4], ..p.adresses };
        return Ok(());
    }
    let lien = Lien {
        sorte: Sorte::Liee, adresse: a.adresse, port: a.port, distante: [0; 4], port_distant: 0, reuseaddr: op.reuseaddr,
        reuseport: op.reuseport, uid: s.uid, par_connect: false, plage: op.local_port_range, interface: op.interface,
    };
    let port = match TABLE.verrouiller().as_mut() {
        Some(t) => t.lier(p.numero, lien, Cible::Socket(s.clone()), crate::aleatoire::u32()),
        None => return Err(-ENOBUFS),
    };
    let port = port.map_err(|e| match e {
        ports_tcp::Refus::Pris => -EADDRINUSE,
        ports_tcp::Refus::Plein => -ENOBUFS,
    })?;
    p.adresses = Adresses { lie: true, adresse: a.adresse, adresse_choisie: a.adresse != [0; 4], port, port_choisi: a.port != 0, ..p.adresses };
    p.hors_table = false;
    Ok(())
}

/// listen (`inet_listen`) : une socket neuve (liée, ou un port éphémère),
/// ou qui écoute déjà (le backlog change) ; une socket connectée, ou dont un `connect`
/// n'a pas encore vu la fin (SS_CONNECTING, même refusée) : EINVAL.
pub fn ecouter(s: &Arc<Socket>, backlog: i32) -> Result<(), i64> {
    // Comparé sans signe : un négatif, le plus grand permis (`__sys_listen_socket`).
    let backlog = (backlog as u32 as usize).min(SOMAXCONN);
    let mut g = flux(s).posseder();
    let p = g.donnee();
    if p.etat_socket != EtatSocket::NonConnectee {
        return Err(-EINVAL);
    }
    match &mut p.mode {
        Mode::Ecoute { backlog: b, .. } => {
            *b = backlog;
            g.publier(|p, c| p.rafraichir(c));
            return Ok(());
        }
        // Ni CLOSE ni LISTEN (`__inet_listen_sk`) ; une connexion est toujours vue d'un
        // `connect` (SS_CONNECTING ou après), refusée plus haut.
        Mode::Connexion(_) => return Err(-EINVAL),
        Mode::Neuve => {}
    }
    let p = g.donnee();
    if !p.adresses.lie {
        // L'adresse d'un `bind` sans port (IP_BIND_ADDRESS_NO_PORT), s'il y en a eu un.
        let op = s.appels.verrouiller().options;
        let lien = Lien {
            sorte: Sorte::Liee, adresse: p.adresses.adresse, port: 0, distante: [0; 4], port_distant: 0, reuseaddr: op.reuseaddr,
            reuseport: op.reuseport, uid: s.uid, par_connect: false, plage: op.local_port_range, interface: op.interface,
        };
        let port = TABLE.verrouiller().as_mut().map(|t| t.lier(p.numero, lien, Cible::Socket(s.clone()), crate::aleatoire::u32()));
        match port {
            Some(Ok(port)) => p.adresses = Adresses { lie: true, port, ..p.adresses },
            _ => return Err(-EADDRINUSE),
        }
    }
    p.hors_table = false;
    if TABLE.verrouiller().as_mut().is_none_or(|t| t.ecouter(p.numero).is_err()) {
        return Err(-EADDRINUSE);
    }
    p.mode = Mode::Ecoute { backlog, filles: VecDeque::new() };
    // `inet_csk_listen_start` efface l'état des ACK : TCP_QUICKACK à 0 ne survit pas à `listen`.
    p.options.quickack = true;
    g.publier(|p, c| p.rafraichir(c));
    Ok(())
}

/// connect (`inet_stream_connect`, `tcp_v4_connect`).
pub fn connecter(s: &Arc<Socket>, o: &[u8], non_bloquant: bool) -> Result<(), i64> {
    if o.len() >= 2 && socket::famille(o) == Some(socket::AF_UNSPEC) {
        // Déconnecter (`tcp_disconnect`), une connexion ou une écoute ; un `connect` bloquant
        // qui dort sur elle le verra (`sk_disconnects`).
        let mut g = flux(s).posseder();
        let p = g.donnee();
        p.deconnecter(s);
        p.deconnexions = p.deconnexions.wrapping_add(1);
        g.avec_court(|_, c| c.arret = 0);
        g.publier(|p, c| p.rafraichir(c));
        // Un `accept` en attente n'a pas d'état qui change à voir (`sk_error_report`).
        flux(s).file().reveiller_toutes();
        return Ok(());
    }
    let a = adresse(o)?;
    if a.famille != socket::AF_INET {
        return Err(-EAFNOSUPPORT);
    }
    let delai = s.appels.verrouiller().options.sndtimeo;
    let mut g = flux(s).posseder();
    let mut deja = false;
    {
        let p = g.donnee();
        // Selon ce que les `connect` d'avant ont vu (`__inet_stream_connect`) : défaite par
        // `shutdown` pendant qu'elle était en cours : EINVAL ; vue établie : EISCONN, même
        // fermée depuis (l'erreur reste en attente, mesuré) ; une écoute : EISCONN.
        match p.etat_socket {
            EtatSocket::EnDeconnexion => return Err(-EINVAL),
            EtatSocket::Connectee => return Err(-EISCONN),
            EtatSocket::NonConnectee | EtatSocket::EnConnexion => {}
        }
        match &mut p.mode {
            Mode::Ecoute { .. } => return Err(-EISCONN),
            Mode::Connexion(t) => {
                // En cours (SS_CONNECTING) : EALREADY (non bloquant), ou attendre encore
                // (bloquant, refait après un signal) ; établie depuis : 0, une fois (mesuré) ;
                // fermée sans qu'un `connect` l'ait vu (refusée, abandonnée, ou coupée après
                // l'établissement) : son erreur, ou ECONNABORTED si elle a déjà été lue
                // (`sock_error`) ; la socket redevient neuve, et c'est le `connect` suivant
                // qui repart.
                match t.etat() {
                    Etat::SynEnvoye | Etat::SynRecu => {
                        if non_bloquant {
                            return Err(-EALREADY);
                        }
                        // Bloquant : attendre encore (la suite), EALREADY
                        // si le délai passe (`inet_stream_connect`).
                        deja = true;
                    }
                    Etat::Fermee => {
                        let e = t.prendre_erreur();
                        p.voir_l_echec(s);
                        g.publier(|p, c| p.rafraichir(c));
                        return Err(if e != 0 { -(e as i64) } else { -ECONNABORTED });
                    }
                    _ => {
                        p.etat_socket = EtatSocket::Connectee;
                        return Ok(());
                    }
                }
            }
            Mode::Neuve => {
                // La route, la source, le port. La source : l'adresse de
                // `bind` (même sans port), sauf une diffusion ou une
                // multidiffusion (`inet_saddr` à 0 : celle de la route) ;
                // une qui n'est pas à nous (IP_FREEBIND) : ENETUNREACH, sauf
                // avec IP_TRANSPARENT (`ip_route_connect`, comme UDP).
                // Une route source (`tcp_v4_connect`) : une vraie destination
                // (EINVAL pour 0.0.0.0), gardée telle quelle ; la route va à sa
                // première étape.
                let ip = Ip::de(&p.options);
                let srr = ip.options.places.route_source != 0;
                if srr && a.adresse == fipv4::AUCUNE {
                    return Err(-EINVAL);
                }
                let op = s.appels.verrouiller().options;
                let liee = Some(p.adresses.adresse).filter(|&x| x != [0; 4] && !super::datagramme::diffusion(x));
                if let Some(x) = liee
                    && !op.transparent
                    && !ipv4::avec_table(|t| t.est_a_nous(x)).unwrap_or(false)
                {
                    return Err(super::datagramme::sans_route());
                }
                // Par la liaison (`tcp_v4_connect` : `sk_bound_dev_if`, seule ;
                // IP_UNICAST_IF ne compte pas) : une interface qui n'existe pas
                // (SO_BINDTOIFINDEX ne le vérifie pas) : ENODEV.
                const ENETUNREACH: i64 = 101;
                let (chemin, routee) = ipv4::router(ip.vers(a.adresse), liee, ip.oif, ip.portee)
                    .map_err(|e| if e == -ENETUNREACH { super::datagramme::sans_route() } else { e })?;
                let destination = if srr { a.adresse } else { routee };
                let source = liee.unwrap_or_else(|| chemin.source());
                if fipv4::boucle(source) && !ipv4::par_lo(&chemin) {
                    return Err(-EINVAL);
                }
                let lien = Lien {
                    sorte: Sorte::Liee, adresse: source, port: 0, distante: [0; 4], port_distant: 0, reuseaddr: op.reuseaddr,
                    reuseport: op.reuseport, uid: s.uid, par_connect: false, plage: op.local_port_range, interface: op.interface,
                };
                let place = faillible::boite_vide().map_err(|_| -ENOBUFS)?;
                let cle = cle_secrete();
                let decalage = crypto::siphash::siphash_4u32(u32::from_ne_bytes(source), u32::from_ne_bytes(destination), a.port as u32,
                                                             (crate::temps::ns_monotone() / 10_000_000_000) as u32, &cle);
                // Une entrée de TIME_WAIT du quadruplet peut être reprise
                // (`tcp_twsk_unique`) : ses règles le disent ; la neuve part de
                // son numéro et de ses horodatages.
                let boucle = fipv4::boucle(source) || fipv4::boucle(destination);
                let heure = maintenant();
                let mut reprise = None;
                let port = TABLE.verrouiller().as_mut().map(|t| {
                    t.connecter(p.numero, source, destination, a.port, lien, Cible::Socket(s.clone()), decalage, crate::aleatoire::u32(), |n, lie| {
                        let r = TW.verrouiller().iter().find(|e| e.numero == n).and_then(|e| e.regles.reprise(lie, boucle, heure));
                        if r.is_some() {
                            reprise = r.map(|(isn, ts)| (n, isn, ts));
                        }
                        r.is_some()
                    })
                });
                let port = match port {
                    Some(Ok(port)) => port,
                    Some(Err(ports_tcp::Refus::Plein)) | None => return Err(-ENOBUFS),
                    Some(Err(_)) => return Err(-EADDRNOTAVAIL),
                };
                p.adresses = Adresses { lie: true, port, distante: destination, port_distant: a.port, source, ..p.adresses };
                p.hors_table = false;
                // Le numéro du SYN : celui que donne une connexion en TIME_WAIT reprise
                // (`tcp_twsk_unique`), sinon celui que la socket garde d'une connexion
                // passée, sinon un neuf (`tcp_v4_connect` : seulement si `write_seq` vaut 0).
                let iss = reprise.map_or_else(
                    || p.options.hors_connexion.numero_de_depart().unwrap_or_else(|| numero_initial(source, destination, port, a.port)),
                    |(_, isn, _)| isn,
                );
                if let Some((n, _, _)) = reprise {
                    TW.verrouiller().retain(|e| e.numero != n);
                    super::tache::armer(n, None);
                }
                let rcvbuf = s.rcvbuf.load(Ordering::Relaxed) as usize;
                let echelle = itcp::echelle(rcvbuf, p.options.rcvbuf_fixe, reception_max(), p.options.window_clamp);
                let mut t = tcb_de_connect(place, port, a.port, iss, mss_vers(ip.vers(destination), ip.oif, ip.portee), rcvbuf,
                                           s.sndbuf.load(Ordering::Relaxed) as usize, echelle);
                // Ce que la socket garde de ses connexions passées (rien pour une neuve).
                t.reprendre(&p.options.hors_connexion);
                t.mss_utilisateur = p.options.maxseg;
                t.poser_options_ip(ip.options.longueur);
                t.window_clamp = p.options.window_clamp;
                t.rcvbuf_fixe = p.options.rcvbuf_fixe;
                t.rcvbuf_max = RECEPTION_MAX.load(Ordering::Relaxed);
                t.rcvlowat = p.options.rcvlowat;
                t.reglages = p.options.reglages(false);
                t.sndbuf_fixe = p.options.sndbuf_fixe;
                t.sndbuf_max = ENVOI_MAX.load(Ordering::Relaxed);
                t.memoire = niveau_memoire();
                t.poser_controle(p.options.controle);
                t.sans_file = sans_carte(ip.vers(destination), ip.oif, ip.portee);
                // TCP_QUICKACK à 0 (`inet_csk_enter_pingpong_mode`), posé avant.
                if !p.options.quickack {
                    t.quickack(false);
                }
                t.proposer_horodatages(decalage_horodatages(source, destination));
                t.proposer_sack();
                if let Some((_, _, ts)) = reprise {
                    t.reprendre_horodatages(ts);
                }
                p.mode = Mode::Connexion(t);
                p.identifiant = crate::aleatoire::u32() as u16;
                p.etat_socket = EtatSocket::EnConnexion;
                // Une connexion neuve repart sans erreur (`tcp_connect_init`).
                p.erreur_seule = 0;
                let _contexte = contexte::entrer();
                p.emettre();
                p.apres();
                drop(_contexte);
                g.publier(|p, c| p.rafraichir(c));
                if non_bloquant {
                    return Err(-EINPROGRESS);
                }
            }
        }
    }
    // Attendre l'établissement ou l'erreur.
    let deconnexions = g.donnee().deconnexions;
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    let r = g.attendre(flux(s).file(), Sommeil::Interruptible, echeance, |c| !matches!(c.etat, Some(Etat::SynEnvoye | Etat::SynRecu)));
    let p = g.donnee();
    match r {
        Reveil::Reveillee => {}
        Reveil::Echeance => return Err(if deja { -EALREADY } else { -EINPROGRESS }),
        Reveil::Signal => return Err(if delai.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
    }
    // Défaite par AF_UNSPEC d'un autre fil pendant qu'on dormait : EPIPE, et son erreur
    // (ECONNRESET) reste en attente (mesuré).
    if p.deconnexions != deconnexions {
        return Err(-EPIPE);
    }
    match &mut p.mode {
        // Défaite par `shutdown` d'un autre fil (en SYN_SENT : `tcp_disconnect`) : son erreur.
        Mode::Neuve => {
            let e = core::mem::take(&mut p.erreur_seule);
            p.voir_l_echec(s);
            g.publier(|p, c| p.rafraichir(c));
            Err(if e != 0 { -(e as i64) } else { -ECONNABORTED })
        }
        // Un connect bloquant qui échoue remet la socket à neuf
        // (`tcp_disconnect`) : elle peut se reconnecter, et poll ne dit
        // plus que POLLOUT | POLLHUP. Son erreur déjà lue par un autre fil : ECONNABORTED.
        Mode::Connexion(t) if t.etat() == Etat::Fermee => {
            let e = t.prendre_erreur();
            p.voir_l_echec(s);
            g.publier(|p, c| p.rafraichir(c));
            Err(if e != 0 { -(e as i64) } else { -ECONNABORTED })
        }
        // Établie. Ou, défaite puis mise à l'écoute par d'autres fils avant que celui-ci ne
        // reprenne la main : ni fermée ni en cours, Linux la dit connectée aussi, et rend 0.
        Mode::Connexion(_) | Mode::Ecoute { .. } => {
            p.etat_socket = EtatSocket::Connectee;
            Ok(())
        }
    }
}

impl Possession<Partie> {
    /// La file d'attente de la socket (lecteurs, écrivains, poll).
    pub fn file(&self) -> &FileAttente {
        &self.file
    }
}

/// accept4 (`inet_accept`) : la première fille établie, devenue une
/// socket ; rien : EAGAIN (non bloquant), ou attendre. Rend la socket
/// neuve et l'adresse du pair.
pub fn accepter(s: &Arc<Socket>, non_bloquant: bool) -> Result<(Arc<Socket>, [u8; 4], u16), i64> {
    // Les options de l'écoute, que la socket neuve hérite (`sk_clone_lock`
    // recopie la socket entière : SO_LINGER, SO_RCVTIMEO, SO_SNDTIMEO,
    // SO_KEEPALIVE, SO_OOBINLINE, IP_TTL...), lues une fois, avant d'attendre.
    let options = s.appels.verrouiller().options;
    let delai = options.rcvtimeo;
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    let mut g = flux(s).posseder();
    loop {
        let p = g.donnee();
        let Mode::Ecoute { filles, .. } = &mut p.mode else { return Err(-EINVAL) };
        if let Some(i) = filles.iter().position(|f| f.prete()) {
            // La place de la socket neuve d'abord : sans mémoire, la fille
            // reste dans la file, pour un prochain accept (ENFILE, comme le
            // `sock_alloc` de `do_accept`).
            let (Ok(place_flux), Ok(place_socket), Ok(retenue), Some(enfant)) =
                (faillible::boite_vide(), ArcVide::new(), Arc::new(Retenue::new(filles[i].numero)), Socket::new(Protocole::Tcp, SOCK_STREAM as u16, IPPROTO_TCP as u16, s.uid))
            else { return Err(-ENFILE) };
            let f = filles.remove(i).expect("la fille");
            let (port, distante, port_distant, locale) = (f.tcb.port_local, f.distante, f.tcb.port_distant, f.locale);
            let (mc_ttl, rcv_tos, mc_index) = f.arrivee;
            let (numero, ip_options, interface) = (f.numero, f.options, f.interface);
            let enfant = enfant.avec_numero(numero);
            // Une fille fermée avant l'accept (un RST) a déjà quitté la
            // table : sa lecture dira son erreur.
            let hors_table = f.tcb.etat() == Etat::Fermee;
            let mut tcb = f.tcb;
            tcb.attachee = true;
            SOCKETS.fetch_add(1, Ordering::Relaxed);
            let partie = Partie {
                numero, mode: Mode::Connexion(tcb),
                // Comme ses verrous de `bind` (`sk_userlocks`, recopié) : déconnectée, elle redevient
                // ce qu'était son écoute, liée à son port si `bind` l'a nommé.
                adresses: Adresses { lie: true, port, distante, port_distant, source: locale, ..p.adresses },
                identifiant: f.identifiant, orpheline: false, hors_table,
                // Tout, sauf ce qui est propre à une écoute (`inet_csk_clone_lock`,
                // `inet_csk_delack_init`) : la fille n'attend pas de données pour naître deux fois.
                options: OptionsTcp { defer_accept: 0, quickack: true, ip_options, interface, ..p.options },
                etat_socket: EtatSocket::Connectee, deconnexions: 0, echeance_armee: None, memoire_comptee: 0, erreur_seule: 0, retenue,
                route_oubliee: false,
            };
            let premier = partie.premier(0, SNDBUF_DEFAUT as usize, RCVBUF_DEFAUT as usize);
            let flux = alloc::boxed::Box::write(place_flux, Possession::new(partie, premier));
            let enfant = place_socket.remplir(enfant.avec_flux(flux));
            enfant.rcvbuf.store(s.rcvbuf.load(Ordering::Relaxed), Ordering::Relaxed);
            enfant.sndbuf.store(s.sndbuf.load(Ordering::Relaxed), Ordering::Relaxed);
            enfant.recverr.store(options.recverr, Ordering::Relaxed);
            enfant.pmtudisc.store(options.pmtudisc, Ordering::Relaxed);
            enfant.peek_off.store(s.peek_off.load(Ordering::Relaxed), Ordering::Relaxed);
            enfant.appels.verrouiller().options = socket::Options { mc_ttl, rcv_tos, mc_index, ip_options, interface, ..options };
            if let Some(t) = TABLE.verrouiller().as_mut() {
                t.changer_objet(numero, Cible::Socket(enfant.clone()));
            }
            // Ses minuteurs et sa mémoire : à sa socket maintenant, sous son
            // numéro ; ceux de l'écoute, recalculés sans elle.
            p.compter();
            if let Some(f) = enfant.flux.as_ref() {
                let mut g = f.posseder();
                g.donnee().armer();
                g.donnee().compter();
            }
            p.armer();
            g.publier(|p, c| p.rafraichir(c));
            return Ok((enfant, distante, port_distant));
        }
        if non_bloquant {
            return Err(-EAGAIN);
        }
        match g.attendre(flux(s).file(), Sommeil::Interruptible, echeance, |c| c.pretes > 0 || !c.ecoute) {
            Reveil::Reveillee => {}
            Reveil::Echeance => return Err(-EAGAIN),
            Reveil::Signal => return Err(if delai.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
        }
    }
}

/// L'adresse locale (getsockname : celle où la socket reçoit, et son port,
/// ou le dernier qu'elle a eu, `inet_sport`) et distante (getpeername ;
/// None : pas connectée).
pub fn nom(s: &Socket) -> ([u8; 4], u16) {
    let mut g = flux(s).posseder();
    let a = g.donnee().adresses;
    (if matches!(g.donnee().mode, Mode::Connexion(_)) { a.source } else { a.adresse }, a.port)
}

/// L'adresse où la socket reçoit (`inet_rcv_saddr` : sa source si elle
/// est connectée, l'adresse de `bind` sinon) et son port (`inet_num` : 0
/// sans port), pour IP_PKTOPTIONS et IP_PROTOCOL.
pub fn nom_lie(s: &Socket) -> ([u8; 4], u16) {
    let mut g = flux(s).posseder();
    let a = g.donnee().adresses;
    (if matches!(g.donnee().mode, Mode::Connexion(_)) { a.source } else { a.adresse }, if a.lie { a.port } else { 0 })
}

/// Le pair d'une connexion (getpeername, `inet_getname`) : ENOTCONN (None)
/// en TCP_CLOSE et TCP_SYN_SENT ; une connexion en TIME_WAIT, Linux l'a
/// déjà rendue à TCP_CLOSE pour sa socket (`tcp_time_wait`, `tcp_done`).
pub fn pair(s: &Socket) -> Option<([u8; 4], u16)> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    match &p.mode {
        Mode::Connexion(t) if !matches!(t.etat(), Etat::Fermee | Etat::SynEnvoye | Etat::TempsAttente) => {
            Some((p.adresses.distante, p.adresses.port_distant))
        }
        _ => None,
    }
}

/// Envoie `longueur` octets remplis par `remplir` (`tcp_sendmsg`) :
/// attendre la place (sauf MSG_DONTWAIT : EAGAIN si rien n'a pu être
/// écrit), SO_SNDTIMEO ; pas connectée : EPIPE (mesuré : une socket neuve
/// ou une écoute) ou ENOTCONN pendant la poignée de main d'un non
/// bloquant... ; l'écriture arrêtée : EPIPE (et SIGPIPE, sauf
/// MSG_NOSIGNAL : l'appelant). MSG_OOB : le dernier octet écrit est
/// urgent (`tcp_mark_urg`) ; MSG_MORE : le dernier segment, incomplet,
/// attend la suite (sauf quand l'envoi attend la place : ce qui est écrit
/// part). Rend ce qui a été écrit.
pub fn envoyer(s: &Arc<Socket>, longueur: usize, drapeaux: u64, mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_MORE: u64 = 0x8000;
    let non_bloquant = drapeaux & MSG_DONTWAIT != 0;
    let delai = s.appels.verrouiller().options.sndtimeo;
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    let mut g = flux(s).posseder();
    let mut fait = 0;
    {
        let p = g.donnee();
        let retenue = p.retenue.octets();
        if let Mode::Connexion(t) = &mut p.mode {
            t.verifier_app_limite(retenue);
        }
    }
    loop {
        let arret = g.avec_court(|_, c| c.arret);
        let p = g.donnee();
        let Mode::Connexion(t) = &mut p.mode else {
            // Une socket neuve, l'erreur de sa déconnexion d'abord.
            let e = core::mem::take(&mut p.erreur_seule);
            g.publier(|p, c| p.rafraichir(c));
            return Err(if e != 0 { -(e as i64) } else { -EPIPE });
        };
        // Des octets déjà pris : rendus ; l'erreur attend l'appel suivant (`do_error`).
        if t.erreur() != 0 {
            if fait > 0 {
                return Ok(fait);
            }
            let e = t.prendre_erreur();
            g.publier(|p, c| p.rafraichir(c));
            return Err(-(e as i64));
        }
        if arret & socket::ARRET_ECRITURE != 0 || !matches!(t.etat(), Etat::Etablie | Etat::AttenteFermeture | Etat::SynEnvoye | Etat::SynRecu) {
            return if fait > 0 { Ok(fait) } else { Err(-EPIPE) };
        }
        let poignee = matches!(t.etat(), Etat::SynEnvoye | Etat::SynRecu);
        if !poignee {
            let mut decalage = fait;
            let ecrit = t.ecrire(longueur - fait, |o| {
                remplir(decalage, o)?;
                decalage += o.len();
                Ok::<(), i64>(())
            });
            // Une copie qui faute après des octets déjà écrits : ceux-là
            // (`tcp_sendmsg_locked`).
            let n = match ecrit {
                Ok(n) => n,
                Err(_) if fait > 0 => return Ok(fait),
                Err(e) => return Err(e),
            };
            fait += n;
            if drapeaux & MSG_OOB != 0 && n > 0 {
                t.marquer_urgent();
            }
            t.plus_a_venir = drapeaux & MSG_MORE != 0 && fait == longueur;
            let _contexte = contexte::entrer();
            p.emettre();
            p.apres();
            drop(_contexte);
            g.publier(|p, c| p.rafraichir(c));
            if fait == longueur {
                return Ok(fait);
            }
        }
        // (`sk_stream_wait_memory` : SOCKWQ_ASYNC_NOSPACE.) La place est
        // revue derrière le drapeau, sous le verrou court de la socket.
        flux(s).asynchrone.marquer_sans_place(|| g.avec_court(|_, c| c.place == 0));
        if non_bloquant {
            return if fait > 0 { Ok(fait) } else { Err(-EAGAIN) };
        }
        // Pendant la poignée de main, attendre qu'elle aboutisse
        // (`sk_stream_wait_connect`) ; ensuite, la place. À la limite de la
        // mémoire de TCP, la place peut revenir sans que la socket le sache
        // (d'autres rendent la leur) : un nouveau regard toutes les 200 ms
        // au plus, comme le `vm_wait` de `sk_stream_wait_memory`.
        let limite = niveau_memoire() == itcp::Memoire::Limite;
        let regard = limite.then(|| crate::temps::ns_monotone() + 200_000_000);
        if poignee {
            if let Mode::Connexion(t) = &mut g.donnee().mode {
                t.ecrivains_en_attente += 1;
            }
        }
        let echeance_ici = match (echeance, regard) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let r = g.attendre(flux(s).file(), Sommeil::Interruptible, echeance_ici, |c| {
            let vivante = matches!(c.etat, Some(Etat::Etablie | Etat::AttenteFermeture | Etat::SynEnvoye | Etat::SynRecu));
            let fin_poignee = !matches!(c.etat, Some(Etat::SynEnvoye | Etat::SynRecu));
            c.erreur != 0 || !vivante || if poignee { fin_poignee } else { c.place > 0 }
        });
        if poignee {
            if let Mode::Connexion(t) = &mut g.donnee().mode {
                t.ecrivains_en_attente = t.ecrivains_en_attente.saturating_sub(1);
            }
        }
        match r {
            Reveil::Reveillee => {}
            // Le regard de la mémoire, avant l'échéance du programme.
            Reveil::Echeance if regard.is_some() && echeance.is_none_or(|e| crate::temps::ns_monotone() < e) => {
                let _contexte = contexte::entrer();
                g.donnee().compter();
            }
            _ if fait > 0 => return Ok(fait),
            Reveil::Echeance => return Err(-EAGAIN),
            Reveil::Signal => return Err(if delai.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
        }
    }
}

/// Reçoit au plus `longueur` octets par `copier` (`tcp_recvmsg`) : ce qui
/// est en file ; rien : 0 si l'autre a fermé, l'erreur en attente,
/// EAGAIN sans attendre, sinon attendre (SO_RCVTIMEO) ; MSG_PEEK laisse
/// les octets ; MSG_WAITALL attend tout ; MSG_TRUNC les jette. Pas
/// connectée : ENOTCONN.
pub fn recevoir_programme(s: &Arc<Socket>, longueur: usize, drapeaux: u64, non_bloquant: bool,
                          mut copier: impl FnMut(usize, &[u8]) -> Result<usize, i64>) -> Result<usize, i64> {
    const MSG_PEEK: u64 = 2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_WAITALL: u64 = 0x100;
    let (delai, rcvlowat) = {
        let i = s.appels.verrouiller();
        (i.options.rcvtimeo, i.options.rcvlowat as usize)
    };
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    let non_bloquant = non_bloquant || drapeaux & MSG_DONTWAIT != 0 || delai == Some(0);
    let peek = drapeaux & MSG_PEEK != 0;
    // Combien rendre avant de revenir (`sock_rcvlowat`) : tout avec
    // MSG_WAITALL, sinon SO_RCVLOWAT (1 par défaut), jamais plus que la
    // place ; pour sendfile, un octet.
    let cible = if drapeaux & MSG_WAITALL != 0 {
        longueur
    } else if drapeaux & MSG_EPISSER != 0 {
        1
    } else {
        rcvlowat.min(longueur)
    };
    let mut g = flux(s).posseder();
    let mut fait = 0;
    // MSG_PEEK : où l'on regarde, depuis le début de ce qui est à lire (`peek_seq`) : SO_PEEK_OFF,
    // puis ce qu'on a déjà vu ; et la lecture à laquelle cela se rapporte.
    let decalage_de_depart = if peek { s.decalage_de_peek() } else { 0 };
    let mut debut = decalage_de_depart;
    let mut lu_au_depart = None;
    loop {
        let arret = g.avec_court(|_, c| c.arret);
        let p = g.donnee();
        let Mode::Connexion(t) = &mut p.mode else {
            // Une socket neuve, l'erreur de sa déconnexion d'abord.
            let e = core::mem::take(&mut p.erreur_seule);
            g.publier(|p, c| p.rafraichir(c));
            return Err(if e != 0 { -(e as i64) } else { -ENOTCONN });
        };
        // Un autre lecteur a retiré des octets pendant qu'on attendait (« Application bug, race in
        // MSG_PEEK ») : on repart de là où il en est.
        if peek {
            let lu = t.numero_lu();
            if lu_au_depart.is_some_and(|l| l != lu) {
                debut = decalage_de_depart;
            }
            lu_au_depart = Some(lu);
        }
        // À la marque urgente (`tcp_recvmsg_locked`), une lecture s'arrête : ce qu'elle a déjà suffit,
        // même MSG_WAITALL ; et rien encore : un signal passe d'abord, sans doute SIGURG, pour que
        // le programme lise l'octet urgent avant de continuer.
        if t.a_la_marque_depuis(debut) {
            if fait > 0 {
                return Ok(fait);
            }
            if crate::tache::signal_en_attente() {
                return Err(if non_bloquant {
                    -EAGAIN
                } else if delai.is_some() {
                    -EINTR
                } else {
                    -crate::reprise::ERESTARTSYS
                });
            }
        }
        // L'octet urgent seul en tête, hors du flux : MSG_PEEK n'a rien à
        // voir ; une lecture le passe (et l'oublie : `urg_data` effacé, un
        // recv(MSG_OOB) suivant rend EINVAL, comme Linux), puis regarde ce
        // qui suit, ou attend.
        let a_lire = if peek { t.lisibles_depuis(debut) } else { t.lisibles() };
        if a_lire > 0 {
            let lu = if drapeaux & MSG_TRUNC != 0 && peek {
                // Rien n'est retiré, rien n'est copié : on compte (`tcp_recvmsg_locked`).
                t.lire_depuis(&mut debut, longueur - fait, true, |o| Ok::<usize, i64>(o.len()))
            } else if drapeaux & MSG_TRUNC != 0 {
                Ok(t.jeter(longueur - fait))
            } else {
                let mut decalage = fait;
                t.lire_depuis(&mut debut, longueur - fait, peek, |o| {
                    let n = copier(decalage, o)?;
                    decalage += n;
                    Ok::<usize, i64>(n)
                })
            };
            // Une copie qui faute : ce qui a déjà été pris est rendu
            // (`tcp_recvmsg_locked`) ; l'erreur, seulement si rien ne l'a
            // été.
            let (n, faute) = match lu {
                Ok(n) => (n, None),
                Err(e) => (0, Some(e)),
            };
            fait += n;
            if peek {
                s.peek_avance(n);
            } else {
                s.peek_recule(n);
                t.lecture_finie();
            }
            let _contexte = contexte::entrer();
            t.lu(n, maintenant());
            p.emettre();
            p.apres();
            drop(_contexte);
            g.publier(|p, c| p.rafraichir(c));
            match faute {
                Some(e) if fait == 0 => return Err(e),
                Some(_) => return Ok(fait),
                None => {}
            }
            if fait == longueur || fait >= cible.max(1) {
                return Ok(fait);
            }
            continue;
        }
        if fait >= cible.max(1) {
            return Ok(fait);
        }
        let p = g.donnee();
        let Mode::Connexion(t) = &mut p.mode else { return Ok(fait) };
        // Rien de copié : le FIN d'abord (SOCK_DONE), puis l'erreur : un RST après le FIN laisse
        // lire la fin (`tcp_recvmsg_locked`), SO_ERROR dira l'erreur. Des octets copiés : ils sont
        // rendus, l'erreur attend l'appel suivant.
        if t.erreur() != 0 && !t.fin_recue() {
            if fait > 0 {
                return Ok(fait);
            }
            let e = t.prendre_erreur();
            g.publier(|p, c| p.rafraichir(c));
            return Err(-(e as i64));
        }
        if t.fin_recue() || arret & socket::ARRET_LECTURE != 0 || t.etat() == Etat::Fermee {
            if !peek {
                t.lecture_finie();
            }
            return Ok(fait);
        }
        if matches!(t.etat(), Etat::SynEnvoye | Etat::SynRecu) && non_bloquant {
            return Err(-EAGAIN);
        }
        if non_bloquant {
            return if fait > 0 { Ok(fait) } else { Err(-EAGAIN) };
        }
        // Ce qui arrive de neuf, plus ce qui est déjà là (que MSG_PEEK a déjà vu).
        let vu = t.lisibles_dans_le_flux();
        flux(s).asynchrone.attendre_donnees(true);
        let r = g.attendre(flux(s).file(), Sommeil::Interruptible, echeance, |c| {
            c.lisibles > vu || c.fin_recue || c.erreur != 0 || c.arret & socket::ARRET_LECTURE != 0 || c.etat == Some(Etat::Fermee)
        });
        flux(s).asynchrone.attendre_donnees(false);
        match r {
            // Une place de 0 : un seul tour, attente comprise (le `while (len > 0)` de
            // `tcp_recvmsg_locked`), et 0 quoi qu'il en sorte, même si le délai est passé (mesuré).
            Reveil::Reveillee | Reveil::Echeance if longueur == 0 => return Ok(0),
            Reveil::Reveillee => {}
            _ if fait > 0 => return Ok(fait),
            Reveil::Echeance => return Err(-EAGAIN),
            Reveil::Signal => return Err(if delai.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
        }
    }
}

/// recv(MSG_OOB) (`tcp_recv_urg`) : l'octet urgent, rendu par `copier`
/// (Some(0) : MSG_TRUNC ou une place nulle, l'octet pris sans être copié ;
/// None : il ne viendra plus, 0 octet) ; MSG_PEEK le laisse. Une écoute :
/// ENOTCONN ; sans octet urgent : EINVAL ; pas encore arrivé : EAGAIN.
pub fn recevoir_urgent(s: &Arc<Socket>, drapeaux: u64, place: usize, copier: impl FnOnce(u8) -> Result<(), i64>) -> Result<Option<usize>, i64> {
    const MSG_PEEK: u64 = 2;
    const MSG_TRUNC: u64 = 0x20;
    const EINVAL_: i64 = 22;
    let mut g = flux(s).posseder();
    let arret = g.avec_court(|_, c| c.arret);
    let p = g.donnee();
    let t = match &mut p.mode {
        Mode::Ecoute { .. } => return Err(-ENOTCONN),
        Mode::Neuve => return Err(-EINVAL_),
        Mode::Connexion(t) => t,
    };
    let r = match t.lire_urgent(drapeaux & MSG_PEEK != 0) {
        Ok(Some(o)) if place > 0 && drapeaux & MSG_TRUNC == 0 => copier(o).map(|()| Some(1)),
        Ok(Some(_)) => Ok(Some(0)),
        Ok(None) => Ok(None),
        // Pas encore là, et la lecture est fermée : il ne viendra plus (`tcp_recv_urg`).
        Err(inet::tcp::EAGAIN) if arret & socket::ARRET_LECTURE != 0 => Ok(None),
        Err(e) => Err(-(e as i64)),
    };
    g.publier(|p, c| p.rafraichir(c));
    r
}

/// shutdown (`inet_shutdown`, `tcp_shutdown`) : les drapeaux posés ;
/// SHUT_WR d'une connexion envoie FIN. Pas connectée : ENOTCONN, mais les
/// drapeaux posés (mesuré). Une écoute : SHUT_RD la défait, SHUT_WR ne fait rien ; en
/// SYN_SENT, la connexion est défaite (`tcp_disconnect`), et ce n'est pas une erreur.
pub fn arreter(s: &Arc<Socket>, arret: u8) -> Result<(), i64> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    let (ecoute, etat) = match &p.mode {
        Mode::Ecoute { .. } => (true, None),
        Mode::Connexion(t) => (false, Some(t.etat())),
        Mode::Neuve => (false, None),
    };
    let en_syn = etat == Some(Etat::SynEnvoye);
    // Une connexion en cours aux yeux de `connect` : établie, elle le devient pour lui
    // (SS_CONNECTED) ; sinon, défaite pour lui (SS_DISCONNECTING, sauf en SYN_SENT, défaite
    // plus bas), il refusera (EINVAL) jusqu'à AF_UNSPEC (`inet_shutdown`, mesuré). Une
    // connexion en TIME_WAIT est TCP_CLOSE pour la socket (`pair`).
    if p.etat_socket == EtatSocket::EnConnexion {
        p.etat_socket = if matches!(etat, Some(Etat::SynEnvoye | Etat::SynRecu | Etat::Fermee | Etat::TempsAttente)) {
            EtatSocket::EnDeconnexion
        } else {
            EtatSocket::Connectee
        };
    }
    if en_syn || (ecoute && arret & socket::ARRET_LECTURE != 0) {
        g.donnee().deconnecter(s);
        g.avec_court(|_, c| c.arret = 0);
        g.publier(|p, c| p.rafraichir(c));
        flux(s).file().reveiller_toutes();
        return Ok(());
    }
    if ecoute {
        return Ok(());
    }
    // TCP_CLOSE, TIME_WAIT compris (`pair`) : l'arrêt est noté, mais ENOTCONN.
    let connectee = matches!(&g.donnee().mode, Mode::Connexion(t) if !matches!(t.etat(), Etat::Fermee | Etat::TempsAttente));
    g.avec_court(|_, c| c.arret |= arret);
    if arret & socket::ARRET_LECTURE != 0
        && let Mode::Connexion(t) = &mut g.donnee().mode
    {
        t.fermer_lecture();
    }
    if arret & socket::ARRET_ECRITURE != 0 {
        let p = g.donnee();
        if let Mode::Connexion(t) = &mut p.mode {
            t.fermer_envoi();
            let _contexte = contexte::entrer();
            p.emettre();
            p.apres();
        }
    }
    g.publier(|p, c| p.rafraichir(c));
    flux(s).file().reveiller(0, 0);
    if connectee { Ok(()) } else { Err(-ENOTCONN) }
}

/// Le dernier `close`, différé (socket.rs) : une écoute réinitialise ses
/// filles ; une connexion envoie FIN, ou RST s'il reste des données non
/// lues ou SO_LINGER 0 ; la socket devient orpheline, et la table la garde
/// jusqu'à la fin de la connexion.
pub fn fermer(s: &Arc<Socket>) {
    let linger = s.appels.verrouiller().options.linger;
    let mut g = flux(s).posseder();
    // Une connexion : RST s'il reste des données non lues (RFC 2525,
    // mesuré) ou avec SO_LINGER 0 ; sinon FIN, et avec SO_LINGER d'un délai,
    // attendre au plus ce délai que le FIN soit acquitté
    // (`sk_stream_wait_close`), avant d'en faire une orpheline.
    let mut attendre = false;
    {
        let p = g.donnee();
        if let Mode::Connexion(t) = &mut p.mode {
            if t.lisibles() > 0 {
                t.avorter_sur_donnees();
            } else if linger.0 && linger.1 == 0 {
                t.avorter();
            } else {
                t.fermer_envoi();
                attendre = linger.0;
            }
            let _contexte = contexte::entrer();
            p.emettre();
            p.apres();
        }
    }
    if attendre {
        g.publier(|p, c| p.rafraichir(c));
        let echeance = maintenant().saturating_add(linger.1 as u64 * 1_000_000_000);
        let _ = g.attendre(flux(s).file(), Sommeil::Interruptible, Some(echeance), |c| {
            !matches!(c.etat, Some(Etat::FinAttente1 | Etat::Fermeture | Etat::DernierAck))
        });
    }
    let p = g.donnee();
    let _contexte = contexte::entrer();
    let ip = Ip::de(&p.options);
    match &mut p.mode {
        Mode::Neuve => {
            if p.adresses.lie && let Some(t) = TABLE.verrouiller().as_mut() {
                t.retirer(p.numero);
            }
            p.desarmer();
            p.hors_table = true;
        }
        Mode::Ecoute { filles, .. } => {
            arreter_les_filles(filles, ip);
            if let Some(t) = TABLE.verrouiller().as_mut() {
                t.retirer(p.numero);
            }
            p.desarmer();
            p.hors_table = true;
        }
        Mode::Connexion(t) => {
            // Orpheline : personne n'attend plus la fin, elle abandonnera
            // plus tôt (`tcp_orphan_retries`), et plus personne ne lira.
            t.reglages.orpheline = true;
            t.attachee = false;
            t.fermer_lecture();
            if !p.hors_table {
                p.orpheline = true;
                ORPHELINES.fetch_add(1, Ordering::Relaxed);
            }
            p.emettre();
            p.apres();
            if t_ferme(p) && !p.hors_table {
                if let Some(tb) = TABLE.verrouiller().as_mut() {
                    tb.retirer(p.numero);
                }
                p.desarmer();
                p.quitter_la_table();
            }
        }
    }
    drop(_contexte);
    g.publier(|p, c| p.rafraichir(c));
}

/// Les filles d'une écoute qui s'arrête (`inet_csk_listen_stop`) : coupées, rendues.
/// Celles de la file d'accept reçoivent un RST (`inet_child_forget`, `tcp_disconnect`) ;
/// pas une fille encore en SYN_RECEIVED : chez Linux, une demande, qui s'en va sans
/// rien dire à son prochain minuteur (`reqsk_timer_handler`) ; l'ACK qui arrivera
/// trouvera le RST d'un port fermé.
fn arreter_les_filles(filles: &mut VecDeque<Fille>, ip: Ip) {
    for f in filles.iter_mut() {
        if f.tcb.etat() != Etat::SynRecu {
            f.tcb.avorter();
            f.emettre(ip, None);
        }
        if let Some(t) = TABLE.verrouiller().as_mut() {
            t.retirer(f.numero);
        }
    }
    filles.clear();
}

fn t_ferme(p: &Partie) -> bool {
    matches!(&p.mode, Mode::Connexion(t) if t.etat() == Etat::Fermee)
}

/// Ce qu'on peut faire de la socket sans attendre (`tcp_poll`).
pub fn sonder(s: &Socket) -> u32 {
    flux(s).court(|c| {
        let m = masque(c);
        // Pas écrivable : la connexion devra le savoir (`tcp_poll`, SOCK_NOSPACE), et O_ASYNC aussi.
        if m & POLLOUT == 0 && !c.ecoute && !matches!(c.etat, Some(Etat::SynEnvoye | Etat::SynRecu)) {
            c.sans_place = true;
            // Sous le verrou court, que prend aussi qui rend de la place : la
            // revue derrière le drapeau trouve le même masque.
            flux(s).asynchrone.marquer_sans_place(|| masque(c) & POLLOUT == 0);
        }
        m
    })
}

/// Le masque de `tcp_poll`, d'après le premier étage.
fn masque(c: &Premier) -> u32 {
    use socket::{ARRET_ECRITURE, ARRET_LECTURE, POLLRDHUP};
    if c.ecoute {
        return if c.pretes > 0 { POLLIN | POLLRDNORM } else { 0 };
    }
    let mut m = 0;
    // TIME_WAIT est, pour le programme, une socket fermée (Linux : la
    // connexion passée à sa petite structure, la socket en TCP_CLOSE).
    let fermee = matches!(c.etat, None | Some(Etat::Fermee | Etat::TempsAttente));
    let arret_total = c.arret == ARRET_LECTURE | ARRET_ECRITURE;
    // POLLHUP : les deux sens arrêtés, ou la socket fermée (une neuve
    // compte : mesuré, POLLOUT | POLLHUP).
    if arret_total || fermee {
        m |= POLLHUP;
    }
    // Une connexion morte (un RST, un refus, un abandon) a ses deux sens
    // arrêtés (`tcp_done` : SHUTDOWN_MASK) ; un connect BLOQUANT qui échoue
    // la remet neuve (`tcp_disconnect`), sans eux.
    if c.arret & ARRET_LECTURE != 0 || c.fin_recue || c.etat == Some(Etat::Fermee) {
        m |= POLLIN | POLLRDNORM | POLLRDHUP;
    }
    if !matches!(c.etat, Some(Etat::SynEnvoye | Etat::SynRecu)) {
        // SO_RCVLOWAT (`tcp_epollin_ready`) : assez d'octets, ou une
        // fenêtre presque fermée.
        if c.lisibles > 0 && (c.lisibles >= c.rcvlowat || c.fenetre_basse) {
            m |= POLLIN | POLLRDNORM;
        }
        if c.arret & ARRET_ECRITURE == 0 {
            // Un tiers de SO_SNDBUF libre (`__sk_stream_is_writeable`).
            if fermee || c.place >= c.sndbuf / 3 {
                m |= POLLOUT | POLLWRNORM;
            }
        } else {
            m |= POLLOUT | POLLWRNORM;
        }
    }
    if c.urgent {
        m |= POLLPRI;
    }
    if c.erreur != 0 {
        m |= POLLERR;
    }
    m
}

/// SO_ERROR : l'erreur en attente, lue et effacée.
pub fn prendre_erreur(s: &Socket) -> i32 {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    let e = match &mut p.mode {
        Mode::Connexion(t) => t.prendre_erreur_so(),
        _ => core::mem::take(&mut p.erreur_seule),
    };
    g.publier(|p, c| p.rafraichir(c));
    e
}

/// Les octets à lire (FIONREAD), ceux pas encore acquittés et pas
/// encore envoyés (SIOCOUTQ, SIOCOUTQNSD), et la lecture à la marque
/// urgente (SIOCATMARK). Une écoute : EINVAL.
pub fn files(s: &Socket) -> Result<(usize, usize, usize, bool), i64> {
    let mut g = flux(s).posseder();
    match &g.donnee().mode {
        Mode::Connexion(t) => Ok((t.lisibles_fionread(), t.non_acquittes(), t.non_envoyes(), t.a_la_marque())),
        Mode::Ecoute { .. } => Err(-EINVAL),
        // Ce que la socket garde des numéros d'une connexion passée (0 pour une neuve).
        Mode::Neuve => {
            let r = &g.donnee().options.hors_connexion;
            Ok((0, r.non_acquittes() as usize, r.non_envoyes() as usize, false))
        }
    }
}

/// Lit ou change les options de SOL_TCP sous la possession ; puis ce que
/// le changement fait partir (TCP_NODELAY, TCP_CORK retiré), et les
/// minuteurs (le keepalive).
pub fn avec_options<R>(s: &Socket, f: impl FnOnce(&mut OptionsTcp, Option<&mut Tcb<Paquet>>) -> R) -> R {
    avec_options_et_route(s, false, f)
}

/// Le même ; avec `oublier_la_route`, la route gardée de la connexion est
/// oubliée sous la même possession (`sk_dst_reset` : SO_DONTROUTE posé ou
/// retiré, un IP_TOS qui change) : IP_MTU dit ENOTCONN jusqu'au segment
/// suivant qui en trouve une (mesuré).
pub fn avec_options_et_route<R>(s: &Socket, oublier_la_route: bool, f: impl FnOnce(&mut OptionsTcp, Option<&mut Tcb<Paquet>>) -> R) -> R {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    p.route_oubliee |= oublier_la_route;
    let tcb = match &mut p.mode {
        Mode::Connexion(t) => Some(&mut **t),
        _ => None,
    };
    let r = f(&mut p.options, tcb);
    let _contexte = contexte::entrer();
    p.emettre();
    p.apres();
    drop(_contexte);
    g.publier(|p, c| p.rafraichir(c));
    r
}

/// La fin d'un sendfile vers la socket (`tcp_splice_eof`) : ce que la
/// dernière ronde, envoyée avec MSG_MORE, a gardé part selon les règles
/// ordinaires (Nagle, TCP_CORK : le `tcp_push` d'un envoi sans MSG_MORE),
/// par le chemin d'un changement d'options qui ne change rien.
pub fn fin_d_episse(s: &Socket) {
    avec_options(s, |_, t| {
        if let Some(t) = t {
            t.plus_a_venir = false;
        }
    });
}

/// SO_KEEPALIVE, SO_OOBINLINE ou SO_DONTROUTE a changé : la socket en garde
/// la copie, et la connexion en tient compte (le keepalive armé ou arrêté ;
/// la route oubliée pour SO_DONTROUTE, `oublier_la_route`).
pub fn options_socket_changees(s: &Socket, keepalive: bool, oobinline: bool, dontroute: bool, oublier_la_route: bool) {
    avec_options_et_route(s, oublier_la_route, |op, t| {
        op.keepalive = keepalive;
        op.oobinline = oobinline;
        op.dontroute = dontroute;
        if let Some(t) = t {
            t.regler(op.reglages(t.reglages.orpheline), maintenant());
        }
    });
}

/// SO_SNDBUF de la connexion, qui grandit (`tcp_sndbuf_expand`) ; sans
/// connexion, celui de la socket.
pub fn sndbuf(s: &Socket) -> u32 {
    let mut g = flux(s).posseder();
    match &g.donnee().mode {
        Mode::Connexion(t) => t.sndbuf.min(i32::MAX as usize) as u32,
        _ => s.sndbuf.load(Ordering::Relaxed),
    }
}

/// Pour l'auto-test : la source et le port, SND.UNA et SND.NXT d'une connexion.
pub fn numeros_de(s: &Socket) -> Option<([u8; 4], u16, u32, u32)> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    let Mode::Connexion(t) = &p.mode else { return None };
    let (una, nxt, _) = t.numeros();
    Some((p.adresses.source, p.adresses.port, una, nxt))
}

/// Pour l'auto-test : TCP_MAXSEG et `tcpi_pmtu`.
pub fn mss_et_pmtu(s: &Socket) -> Option<(u16, u32)> {
    avec_options(s, |_, t| t.map(|t| (t.mss(), t.info(maintenant()).pmtu)))
}

/// Pour l'auto-test : `tcpi_advmss`.
pub fn advmss_de(s: &Socket) -> Option<u32> {
    avec_options(s, |_, t| t.map(|t| t.info(maintenant()).advmss))
}

/// IP_MTU d'une connexion (`dst_mtu`), par sa liaison ; None : pas de
/// connexion, ou sa route oubliée (ENOTCONN : `sk_dst_get` nul).
pub fn mtu_du_chemin(s: &Socket) -> Option<u32> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    if !matches!(p.mode, Mode::Connexion(_)) || p.route_oubliee {
        return None;
    }
    ipv4::router(p.adresses.distante, None, p.options.interface, Ip::de(&p.options).portee).ok().map(|(c, d)| ipv4::mtu_vers(&c, d))
}

/// SO_RCVBUF, qui grandit de même (reception.rs).
pub fn rcvbuf(s: &Socket) -> u32 {
    let mut g = flux(s).posseder();
    match &g.donnee().mode {
        Mode::Connexion(t) => t.rcvbuf.min(i32::MAX as usize) as u32,
        _ => s.rcvbuf.load(Ordering::Relaxed),
    }
}

/// `tcp_set_rcvlowat` (SO_RCVLOWAT) : borné par la moitié de SO_RCVBUF fixé, sinon de
/// `tcp_rmem[2]` ; et SO_RCVBUF grandit pour le tenir, sauf s'il est fixé. Rend le seuil.
pub fn poser_rcvlowat(s: &Socket, v: u32) -> u32 {
    avec_options(s, |op, t| {
        let lu = match t {
            Some(t) => t.poser_rcvlowat(v),
            None => {
                let plafond = if op.rcvbuf_fixe { s.rcvbuf.load(Ordering::Relaxed) >> 1 } else { RECEPTION_MAX.load(Ordering::Relaxed) as u32 >> 1 };
                let val = v.min(plafond);
                // Le rapport de départ : 50 % (`tcp_space_from_win`).
                if !op.rcvbuf_fixe && val.saturating_mul(2) > s.rcvbuf.load(Ordering::Relaxed) {
                    s.rcvbuf.store(val.saturating_mul(2), Ordering::Relaxed);
                }
                val.max(1)
            }
        };
        op.rcvlowat = lu;
        lu
    })
}

/// Une ligne de /proc/net/tcp, complétée à 149 colonnes (le `seq_setwidth`
/// de Linux), dans un tampon de la pile (une allocation ne doit pas pouvoir
/// faire paniquer le noyau).
struct LigneProc {
    octets: [u8; 160],
    longueur: usize,
}

impl core::fmt::Write for LigneProc {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(149 - self.longueur);
        self.octets[self.longueur..self.longueur + n].copy_from_slice(&s.as_bytes()[..n]);
        self.longueur += n;
        Ok(())
    }
}

/// Une adresse comme la montre /proc/net : le mot gros-boutiste lu comme
/// un nombre de la machine.
fn hexa(a: [u8; 4]) -> u32 {
    u32::from_le_bytes(a)
}

/// Des nanosecondes en `clock_t` (USER_HZ, 100 par seconde).
fn clock_t(ns: u64) -> u64 {
    ns / 10_000_000
}

/// La ligne `n` de /proc/net/tcp (`tcp4_seq_show`) : l'en-tête, puis les
/// écoutes, les connexions (les filles d'une écoute comprises) et les
/// TIME_WAIT, dans l'ordre de la table des ports, aux trois formats de
/// Linux (`get_tcp4_sock`, `get_openreq4`, `get_timewait4_sock`). Les
/// adresses de noyau (`%pK`) sont des zéros, ce que voit un programme sans
/// CAP_SYSLOG. false : il n'y en a plus.
pub fn ligne_proc(n: u64, sortie: &mut dyn core::fmt::Write) -> Result<bool, core::fmt::Error> {
    use core::fmt::Write;
    let mut l = LigneProc { octets: [b' '; 160], longueur: 0 };
    if n == 0 {
        l.write_str("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode")?;
    } else {
        // L'entrée, prise sous le verrou de la table ; ce qu'on en montre,
        // après (sa possession peut faire dormir).
        let mut vue = None;
        let mut i = 0;
        if let Some(table) = TABLE.verrouiller().as_ref() {
            table.pour_chaque(|numero, lien, objet| {
                if vue.is_none() && matches!(lien.sorte, Sorte::Ecoute | Sorte::Connectee | Sorte::TempsAttente) {
                    i += 1;
                    if i == n {
                        vue = Some((numero, *lien, objet.cloned()));
                    }
                }
            });
        }
        let Some((numero, lien, objet)) = vue else { return Ok(false) };
        write!(l, "{:4}: {:08X}:{:04X} {:08X}:{:04X} ", n - 1, hexa(lien.adresse), lien.port, hexa(lien.distante), lien.port_distant)?;
        let maintenant = maintenant();
        match (lien.sorte, objet) {
            (Sorte::TempsAttente, _) => {
                let e = TW.verrouiller().iter().find(|e| e.numero == numero).copied();
                let (etat, reste) = e.map_or((6, 0), |e| (if e.regles.fin_attente2 { 5 } else { 6 }, e.echeance.saturating_sub(maintenant)));
                write!(l, "{:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x}", etat, 0, 0, 3, clock_t(reste), 0, 0, 0, 0, 1, 0)?;
            }
            (_, Some(Cible::Socket(s))) => {
                let mut g = flux(&s).posseder();
                let inode = s.inode.load(Ordering::Relaxed);
                match &g.donnee().mode {
                    Mode::Ecoute { filles, .. } => {
                        let pretes = filles.iter().filter(|f| f.prete()).count();
                        write!(l, "{:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x} {} {} {} {} {}",
                               10, 0, pretes, 0, 0, 0, s.uid, 0, inode, 1, 0, clock_t(itcp::RTO_INITIAL), 0, 0, itcp::CWND_INITIALE, 0)?;
                    }
                    Mode::Connexion(t) => ligne_connexion(&mut l, t, maintenant, s.uid, inode)?,
                    Mode::Neuve => write!(l, "{:02X}", 7)?,
                }
            }
            (_, Some(Cible::Fille(ecoute, num))) => {
                let mut g = flux(&ecoute).posseder();
                if let Mode::Ecoute { filles, .. } = &g.donnee().mode
                    && let Some(f) = filles.iter().find(|f| f.numero == num)
                {
                    if f.tcb.etat() == Etat::SynRecu {
                        let i = f.tcb.info(maintenant);
                        write!(l, "{:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x}", 3, 0, 0, 1,
                               clock_t(i.t_retrans.unwrap_or(0)), i.retransmissions, ecoute.uid, 0, 0, 0, 0)?;
                    } else {
                        ligne_connexion(&mut l, &f.tcb, maintenant, ecoute.uid, 0)?;
                    }
                }
            }
            _ => {}
        }
    }
    while l.longueur < 149 {
        l.longueur += 1;
    }
    sortie.write_str(core::str::from_utf8(&l.octets[..l.longueur]).unwrap_or(""))?;
    sortie.write_char('\n')?;
    Ok(true)
}

/// La fin d'une ligne de /proc/net/tcp pour une connexion
/// (`get_tcp4_sock`) : l'état, les files, le minuteur (1 : la
/// retransmission, 4 : la sonde, 2 : le keepalive), les retransmissions,
/// l'utilisateur, les sondes, l'inode, le RTO et l'ATO, les ACK rapides et
/// le ping-pong, la fenêtre de congestion et le seuil (-1 au démarrage
/// lent du début).
fn ligne_connexion(l: &mut LigneProc, t: &Tcb<Paquet>, maintenant: u64, uid: u32, inode: u32) -> core::fmt::Result {
    use core::fmt::Write;
    let i = t.info(maintenant);
    let (minuteur, quand) = match (i.t_retrans, i.t_keepalive) {
        (Some(q), _) => (if i.sonde { 4 } else { 1 }, q),
        (None, Some(q)) => (2, q),
        _ => (0, 0),
    };
    let ssthresh = if i.demarrage_lent { -1 } else { i.ssthresh as i64 };
    write!(l, "{:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} {:8} {} {} {:016x} {} {} {} {} {}",
           i.etat, t.a_acquitter(), t.en_reception(), minuteur, clock_t(quand), i.retransmissions, uid, i.sondes, inode, 1, 0,
           clock_t(i.rto as u64 * 1000), clock_t(i.ato as u64 * 1000), i.ack_rapides << 1 | u32::from(i.pingpong), i.cwnd, ssthresh)
}

/// La socket écoute-t-elle (SO_ACCEPTCONN) ?
pub fn ecoute(s: &Socket) -> bool {
    flux(s).court(|c| c.ecoute)
}

/// Une écoute : ses filles prêtes, et la longueur de sa file (TCP_INFO).
pub fn file_d_ecoute(s: &Socket) -> (u32, u32) {
    flux(s).court(|c| (c.pretes as u32, c.file as u32))
}

/// Quelqu'un attend-il sur une socket TCP (le détecteur d'interblocage) ?
pub fn attentes() -> usize {
    let mut n = 0;
    if let Some(t) = TABLE.verrouiller().as_ref() {
        t.pour_chaque(|_, _, o| {
            if let Some(Cible::Socket(s)) = o
                && let Some(f) = s.flux.as_ref()
            {
                n += f.file().active() as usize;
            }
        });
    }
    n
}

/// SO_BINDTODEVICE ou SO_BINDTOIFINDEX (`sock_bindtoindex_locked`), sous la
/// possession de la socket (le `lock_sock` de Linux), puis son `Mutex` : `poser`
/// vérifie et pose la liaison dans ses options. Puis la table l'apprend (Linux
/// la lit sur la socket à chaque recherche et à chaque conflit, son écoute ou
/// sa connexion comprises), ses segments suivants partent par elle (sa copie),
/// et sa route est oubliée (`sk_dst_reset`).
pub fn lier_a_une_interface(s: &Socket, poser: impl FnOnce(&mut socket::Inet) -> Result<u32, i64>) -> Result<(), i64> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    let k = poser(&mut s.appels.verrouiller())?;
    if let Some(t) = TABLE.verrouiller().as_mut() {
        t.changer_interface(p.numero, k);
    }
    p.options.interface = k;
    p.route_oubliee = true;
    Ok(())
}

/// SO_REUSEADDR ou SO_REUSEPORT a changé : la table le lit au moment des
/// conflits.
pub fn reutilisation_changee(s: &Socket, inet: &socket::Inet) {
    if let Some(t) = TABLE.verrouiller().as_mut() {
        t.reutiliser(s.numero, inet.options.reuseaddr, inet.options.reuseport);
    }
}

/// SO_RCVBUF ou SO_SNDBUF a changé : la connexion en tient compte ; un
/// SO_SNDBUF donné par le programme ne grandit plus de lui-même
/// (`SOCK_SNDBUF_LOCK`), un SO_RCVBUF donné borne l'échelle de fenêtre de
/// la connexion à venir (`SOCK_RCVBUF_LOCK`).
pub fn tampons_changes(s: &Socket, sndbuf_fixe: bool, rcvbuf_fixe: bool) {
    let (r, e) = (s.rcvbuf.load(Ordering::Relaxed) as usize, s.sndbuf.load(Ordering::Relaxed) as usize);
    avec_options(s, |op, t| {
        op.sndbuf_fixe |= sndbuf_fixe;
        op.rcvbuf_fixe |= rcvbuf_fixe;
        if let Some(t) = t {
            // Seulement celui qui a changé : l'autre a pu grandir depuis.
            if rcvbuf_fixe {
                t.rcvbuf = r;
                t.rcvbuf_fixe = true;
            }
            if sndbuf_fixe {
                t.sndbuf = e;
                t.sndbuf_fixe = true;
            }
        }
    });
}
