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
//! ou de ses filles pour une écoute, dans la liste des échéances du
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
use super::socket::{self, Protocole, Socket};
use crate::attente::{FileAttente, Possede, Possession, Sommeil};
use crate::faillible::{self, FileFaillible, VecFaillible};
use crate::partage::{Arc, ArcVide};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use crate::tache::Reveil;
use crate::verrou::Verrou;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use formats::reseau::ipv4 as fipv4;
use formats::reseau::tcp::{self as ftcp, Tcp};
use inet::ports_tcp::{self, Destinataire, Lien, Sorte};
use inet::tcp::{self as itcp, Charge, Etat, Tcb};

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
    tcb: Tcb<Paquet>,
    locale: [u8; 4],
    distante: [u8; 4],
    identifiant: u16,
    /// Sa poignée de main a abouti : elle est dans la file d'acceptation
    /// (`inet_csk_reqsk_queue_add`), et y reste jusqu'à `accept`, quoi
    /// qu'elle devienne : CLOSE_WAIT (le client a envoyé sa requête et son
    /// FIN avant l'accept : HTTP/1.0, une sonde de santé), ou fermée par un
    /// RST (accept la rend, sa première lecture dit ECONNRESET).
    etablie: bool,
}

impl Fille {
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

/// Ce qu'est la socket.
pub enum Mode {
    Neuve,
    Ecoute { backlog: usize, filles: VecDeque<Fille> },
    Connexion(Tcb<Paquet>),
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
    /// La connexion a été établie un jour (un second `connect` rend
    /// EISCONN, pas EALREADY).
    pub etablie_un_jour: bool,
    /// Un `connect` non bloquant est en cours.
    pub connexion_en_cours: bool,
    /// L'échéance inscrite dans la liste du réseau pour cette socket.
    echeance_armee: Option<u64>,
    /// La mémoire que la socket a comptée dans celle de TCP (`MEMOIRE`).
    memoire_comptee: usize,
    /// L'erreur d'une socket redevenue neuve (`sk_err`, après `tcp_disconnect`) : plus de connexion
    /// pour la tenir, mais SO_ERROR, `poll` et la lecture la disent encore.
    erreur_seule: i32,
    /// Ce que la carte a encore d'elle (`sk_wmem_alloc`, TSQ).
    retenue: Arc<Retenue>,
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
    /// TCP_WINDOW_CLAMP (0 : rien), d'une socket pas encore connectée, et d'une
    /// écoute : ses filles en héritent (`tcp_openreq_init_rwin`).
    pub window_clamp: u32,
    /// TCP_CONGESTION : le contrôle de la socket, et de ses filles
    /// (`tcp_ca_openreq_child`).
    pub controle: itcp::Controle,
}

impl OptionsTcp {
    /// `syncnt` à 0 : celui du système (TCP_SYNCNT se lit alors 6), comme
    /// le `icsk_syn_retries` de Linux ; une fille en hérite pour ses
    /// SYN-ACK (5 par défaut).
    pub const DEFAUT: OptionsTcp = OptionsTcp {
        nodelay: false, cork: false, keepidle: 7200, keepintvl: 75, keepcnt: 9, syncnt: 0, linger2: 60, maxseg: 0,
        quickack: true, defer_accept: 0, user_timeout: 0, keepalive: false, oobinline: false, sndbuf_fixe: false,
        rcvbuf_fixe: false, rcvlowat: 1, ttl: 64, tos: 0, pmtudisc: 1, window_clamp: 0, controle: itcp::Controle::DEFAUT,
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
}

/// Ce qui arrive à une socket depuis le réseau : un segment, ou une
/// erreur ICMP pour un de ses paquets.
pub enum Arrivee {
    Segment(Segment),
    /// L'errno (`icmp_err_convert`), le réseau ou la machine injoignables
    /// (RFC 6069), le numéro de séquence du segment d'origine (vérifié
    /// contre ce qui est en vol), la fille visée ; IP_RECVERR de la socket.
    Erreur { errno: i32, injoignable: bool, seq: u32, fille: Option<u64>, recverr: bool, abandon: bool },
    /// « Fragmentation nécessaire » : la MTU qu'elle dit, et de même le numéro et la fille.
    Mtu { info: u32, seq: u32, fille: Option<u64> },
}

/// Un segment reçu, pour une socket (ou la fille d'une écoute).
pub struct Segment {
    entete: Tcp,
    charge: Paquet,
    source: [u8; 4],
    destination: [u8; 4],
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
        *court = neuf;
        m
    }

    /// Émet ce que la connexion a à envoyer.
    fn emettre(&mut self) {
        let Mode::Connexion(t) = &mut self.mode else { return };
        emettre_tcb(t, self.adresses.source, self.adresses.distante, &mut self.identifiant, Ip::de(&self.options), Some(&self.retenue));
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
            let e = TempsAttente { numero, locale: self.adresses.source, distante: self.adresses.distante, regles: t.en_attente(fin_orpheline), echeance };
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
        super::tache::armer(self.numero, e);
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

    /// La socket redevient neuve (`tcp_disconnect` : TCP_CLOSE), et peut se
    /// connecter à nouveau ou écouter : après un `connect` qui n'a pas
    /// abouti (refusé, abandonné), ou `connect(AF_UNSPEC)`. Son entrée de la
    /// table est rendue ; un port choisi par `bind` est gardé
    /// (SOCK_BINDPORT_LOCK), lié de nouveau à son adresse.
    fn redevenir_neuve(&mut self, s: &Arc<Socket>) {
        // Ce que les tampons sont devenus reste (`tcp_disconnect` n'y touche pas).
        if let Mode::Connexion(t) = &self.mode {
            s.rcvbuf.store(t.rcvbuf.min(i32::MAX as usize) as u32, Ordering::Relaxed);
            s.sndbuf.store(t.sndbuf.min(i32::MAX as usize) as u32, Ordering::Relaxed);
        }
        if !self.hors_table
            && let Some(t) = TABLE.verrouiller().as_mut()
        {
            t.retirer(self.numero);
        }
        self.desarmer();
        self.mode = Mode::Neuve;
        self.hors_table = false;
        self.etablie_un_jour = false;
        self.connexion_en_cours = false;
        let a = self.adresses;
        self.adresses = Adresses::default();
        if a.port_choisi {
            let (reuseaddr, reuseport) = partage(s);
            let lien = Lien {
                sorte: Sorte::Liee, adresse: a.adresse, port: a.port, distante: [0; 4], port_distant: 0, reuseaddr, reuseport, uid: s.uid,
                par_connect: false,
            };
            let lie = TABLE.verrouiller().as_mut().map(|t| t.lier(self.numero, lien, Cible::Socket(s.clone()), crate::aleatoire::u32()));
            if let Some(Ok(port)) = lie {
                self.adresses = Adresses { lie: true, adresse: a.adresse, port, port_choisi: true, ..Adresses::default() };
            }
        }
    }

    /// La socket ne tient plus d'entrée dans la table.
    fn quitter_la_table(&mut self) {
        self.hors_table = true;
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

/// Émet les segments de la connexion `t`, de `source` à `distante`.
/// Ce qu'une connexion met dans l'en-tête IPv4 de ses segments : IP_TTL et
/// IP_TOS de sa socket (ses copies, dans les options).
#[derive(Clone, Copy)]
struct Ip {
    ttl: u8,
    tos: u8,
    pmtudisc: u8,
}

impl Ip {
    /// Celui d'un segment sans socket (un RST, l'ACK d'une entrée de
    /// TIME_WAIT) : le TTL du système, 64.
    const SYSTEME: Ip = Ip { ttl: 64, tos: 0, pmtudisc: 2 };

    fn de(o: &OptionsTcp) -> Ip {
        Ip { ttl: o.ttl, tos: o.tos, pmtudisc: o.pmtudisc }
    }
}

fn emettre_tcb(t: &mut Tcb<Paquet>, source: [u8; 4], distante: [u8; 4], identifiant: &mut u16, ip: Ip, retenue: Option<&Arc<Retenue>>) {
    if let Some(r) = retenue {
        t.poser_en_file(r.octets(), r.rendu());
    }
    if let Ok((c, d)) = ipv4::router(distante, Some(source)) {
        t.verifier_mtu(ipv4::mtu_vers(&c, d));
    }
    let mut a_envoyer: Vec<itcp::Sortant> = Vec::new();
    t.emettre(maintenant(), |s| {
        // Sans place, le segment ne part pas : la retransmission y pourvoira.
        let _ = a_envoyer.ajouter(s);
    });
    for s in a_envoyer {
        // Un ACK pur, un RST ne tiennent pas la socket (`skb_is_tcp_pure_ack`).
        let suivi = retenue.filter(|_| s.numero != 0).map(|r| (r, s.numero));
        envoyer_segment(&s.entete, source, distante, identifiant, ip, s.longueur, suivi, |o| t.copier_envoi(s.debut, o));
    }
    if t.prendre_etrangle()
        && let Some(r) = retenue
    {
        r.etrangler();
    }
}

/// Écrit et émet un segment : l'en-tête `h`, `longueur` octets de charge
/// remplis par `remplir`, de `source` à `distante` (DF, TTL 64 : IPv4 de
/// 6g). La somme n'est pas calculée par `lo` (comme Linux). Un segment
/// qui ne part pas (plus de mémoire, pas de route) est perdu, comme sur
/// un câble.
fn envoyer_segment(h: &Tcp, source: [u8; 4], distante: [u8; 4], identifiant: &mut u16, ip: Ip, longueur: usize, suivi: Option<(&Arc<Retenue>, u64)>,
                   remplir: impl FnOnce(&mut [u8])) {
    let n = ftcp::longueur_entete(&h.options);
    let prets = ipv4::router(distante, Some(source)).ok().zip(Paquet::vide(n + longueur));
    let Some(((chemin, destination), mut p)) = prets else {
        // Il ne partira pas : personne ne le rendra.
        if let Some((r, numero)) = suivi {
            r.envoi_perdu(numero);
        }
        return;
    };
    let Some(o) = p.ajouter_fin(n + longueur) else { return };
    remplir(&mut o[n..]);
    ftcp::ecrire(o, h, source, destination, !ipv4::par_lo(&chemin));
    if let Some((r, numero)) = suivi {
        p.attacher(r, numero);
    }
    *identifiant = identifiant.wrapping_add(1);
    let envoi = ipv4::Envoi {
        source, destination, protocole: fipv4::TCP, ttl: ip.ttl, tos: ip.tos, identifiant: *identifiant,
        ne_pas_fragmenter: ipv4::ne_pas_fragmenter(ip.pmtudisc, destination), mtu: ipv4::mtu_d_envoi(ip.pmtudisc, &chemin, destination), confirmer: false,
    };
    ipv4::emettre(chemin, &envoi, p);
}

/// Répond à un segment sans connexion (RST), de `locale` à `distante`.
fn repondre_rst(h: &Tcp, longueur_charge: usize, locale: [u8; 4], distante: [u8; 4]) {
    if let Some(r) = itcp::reponse_sans_connexion(h, longueur_charge) {
        let mut id = crate::aleatoire::u32() as u16;
        envoyer_segment(&r, locale, distante, &mut id, Ip::SYSTEME, 0, None, |_| {});
    }
}

impl Possede for Partie {
    type Court = Premier;
    type Element = Arrivee;

    fn traiter(&mut self, a: Arrivee) {
        let _contexte = contexte::entrer();
        let s = match a {
            Arrivee::Segment(s) => s,
            Arrivee::Erreur { errno, injoignable, seq, fille, recverr, abandon } => {
                self.erreur_icmp(errno, injoignable, seq, fille, recverr, abandon);
                self.emettre();
                self.apres();
                return;
            }
            Arrivee::Mtu { info, seq, fille } => {
                self.mtu_reduite(info, seq, fille);
                self.emettre();
                self.apres();
                return;
            }
        };
        match &mut self.mode {
            Mode::Connexion(t) => {
                t.recevoir(&s.entete, s.charge, maintenant());
            }
            Mode::Ecoute { .. } => self.traiter_ecoute(s),
            Mode::Neuve => {
                // Plus rien n'écoute ici (un `listen` défait par un
                // `connect` qui a échoué...) : RST.
                repondre_rst(&s.entete, s.charge.longueur(), s.destination, s.source);
            }
        }
        self.emettre();
        self.apres();
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
                    emettre_tcb(&mut f.tcb, f.locale, f.distante, &mut f.identifiant, ip, None);
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
    /// « Fragmentation nécessaire » (`tcp_v4_err`, TCP_MTU_REDUCED_DEFERRED) : ignorée si
    /// le segment d'origine n'est pas en vol (la route non plus ne change pas : mesuré) ;
    /// sinon la route la retient, et la connexion suit. Ni une écoute, ni une fille en
    /// SYN_RECEIVED (`tcp_req_err` : ses SYN-ACK sont toujours petits).
    fn mtu_reduite(&mut self, info: u32, seq: u32, fille: Option<u64>) {
        let pmtudisc = self.options.pmtudisc;
        let (t, distante) = match (&mut self.mode, fille) {
            (Mode::Connexion(t), None) => (t, self.adresses.distante),
            (Mode::Ecoute { filles, .. }, Some(n)) => {
                let Some(f) = filles.iter_mut().find(|f| f.numero == n && f.tcb.etat() != Etat::SynRecu) else { return };
                (&mut f.tcb, f.distante)
            }
            _ => return,
        };
        let (una, nxt, _) = t.numeros();
        if itcp::avant(seq, una) || itcp::apres(seq, nxt) {
            return;
        }
        ipv4::apprendre_mtu(distante, info);
        let Ok((c, d)) = ipv4::router(distante, None) else { return };
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
    fn traiter_ecoute(&mut self, mut s: Segment) {
        let ip = Ip::de(&self.options);
        let defer = self.options.defer_accept;
        let Mode::Ecoute { backlog, filles } = &mut self.mode else { return };
        if let Some(n) = s.fille {
            if let Some(f) = filles.iter_mut().find(|f| f.numero == n) {
                f.tcb.reglages.defer_accept = defer;
                f.tcb.recevoir(&s.entete, s.charge, maintenant());
                emettre_tcb(&mut f.tcb, f.locale, f.distante, &mut f.identifiant, ip, None);
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
        if h.drapeaux & ftcp::ACK != 0 || h.drapeaux & ftcp::SYN == 0 {
            // Un ACK pour une fille qu'on n'a plus : RST (`tcp_v4_rcv`).
            repondre_rst(&h, s.charge.longueur(), s.destination, s.source);
            return;
        }
        // Un SYN : jeté si la file d'acceptation est pleine, ou s'il y a
        // déjà backlog + 1 filles (`tcp_conn_request`).
        let pretes = filles.iter().filter(|f| f.prete()).count();
        if pretes > *backlog || filles.len() > *backlog || filles.try_reserve(1).is_err() {
            return;
        }
        let numero = socket::nouveau_numero();
        let iss = s.isn.unwrap_or_else(|| numero_initial(s.destination, s.source, h.destination, h.source));
        let mss = mss_vers(s.source);
        let Some(moi) = par_numero(self.numero) else { return };
        // Une fille hérite des tampons de son écoute, et de SO_SNDBUF fixé
        // (`sk_clone_lock` : `sk_sndbuf`, `sk_rcvbuf`, `sk_userlocks`) :
        // c'est ainsi qu'un serveur règle ses connexions, et la fenêtre que
        // la fille annonce (son échelle est choisie ici, au SYN).
        let rcvbuf = moi.rcvbuf.load(Ordering::Relaxed) as usize;
        let echelle = itcp::echelle(rcvbuf, self.options.rcvbuf_fixe, reception_max(), self.options.window_clamp);
        let mut tcb = Tcb::depuis_syn(&h, iss, mss, rcvbuf, moi.sndbuf.load(Ordering::Relaxed) as usize, echelle);
        tcb.poser_mss_utilisateur(self.options.maxseg);
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
        tcb.sans_file = sans_carte(s.source);
        let lien = Lien {
            sorte: Sorte::Connectee, adresse: s.destination, port: h.destination, distante: s.source, port_distant: h.source,
            reuseaddr: false, reuseport: false, uid: 0, par_connect: false,
        };
        let ajoutee = TABLE.verrouiller().as_mut().is_some_and(|t| t.ajouter_fille(numero, lien, Cible::Fille(moi, numero)).is_ok());
        if !ajoutee {
            return;
        }
        let mut f = Fille {
            numero, tcb, locale: s.destination, distante: s.source, identifiant: crate::aleatoire::u32() as u16, etablie: false,
        };
        emettre_tcb(&mut f.tcb, f.locale, f.distante, &mut f.identifiant, ip, None);
        // La place est prise plus haut, avant tout changement.
        filles.ajouter_derriere_dans_la_place(f);
    }
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

/// Le MSS qu'on annonce pour parler à `distante` : la MTU du chemin moins
/// 40 (les en-têtes d'IPv4 et de TCP).
/// Vers cette adresse, un paquet n'attend-il dans aucune carte (`lo`) ?
fn sans_carte(distante: [u8; 4]) -> bool {
    ipv4::router(distante, None).is_ok_and(|(c, _)| ipv4::par_lo(&c))
}

fn mss_vers(distante: [u8; 4]) -> u16 {
    // (`ipv4_default_advmss` : d'après la MTU du chemin, ce qu'on en a appris compris, et au
    // moins `ip_rt_min_advmss`.)
    match ipv4::router(distante, None) {
        Ok((c, d)) => (ipv4::mtu_vers(&c, d).saturating_sub(40)).clamp(256, 65_495) as u16,
        Err(_) => itcp::MSS_DEFAUT,
    }
}

/// Livre un segment à sa cible, d'après la table.
fn livrer(s: Segment) {
    let h = s.entete;
    let cible = TABLE.verrouiller().as_ref().and_then(|t| t.trouver(s.source, h.source, s.destination, h.destination));
    match cible {
        Some(Destinataire::Connexion(Cible::Socket(sock))) | Some(Destinataire::Ecoute(Cible::Socket(sock))) => {
            vers_socket(&sock, Arrivee::Segment(Segment { fille: None, ..s }));
        }
        Some(Destinataire::Connexion(Cible::Fille(ecoute, n))) | Some(Destinataire::Ecoute(Cible::Fille(ecoute, n))) => {
            vers_socket(&ecoute, Arrivee::Segment(Segment { fille: Some(n), ..s }));
        }
        Some(Destinataire::TempsAttente(n)) => temps_attente(n, s),
        None => repondre_rst(&h, s.charge.longueur(), s.destination, s.source),
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
    let cible = TABLE.verrouiller().as_ref().and_then(|t| t.trouver(i.destination, port_destination, i.source, port_source));
    let (sock, fille) = match cible {
        Some(Destinataire::Connexion(Cible::Socket(s))) => (s, None),
        Some(Destinataire::Connexion(Cible::Fille(ecoute, n))) => (ecoute, Some(n)),
        _ => return,
    };
    use formats::reseau::icmp;
    // « Fragmentation nécessaire » : la MTU du chemin, qui réduit le MSS
    // (`tcp_v4_mtu_reduced`), jamais une erreur, même avec IP_RECVERR (mesuré).
    if e.genre == icmp::INJOIGNABLE && e.code == icmp::FRAGMENTATION {
        let _contexte = contexte::entrer();
        vers_socket(&sock, Arrivee::Mtu { info: e.info, seq, fille });
        return;
    }
    let Some((errno, _)) = super::udp::convertir(e.genre, e.code, true) else { return };
    let injoignable = e.genre == icmp::INJOIGNABLE && (e.code == icmp::RESEAU || e.code == icmp::HOTE);
    // Ce qui retire une fille (l'`abort` de `tcp_req_err`).
    let abandon = injoignable || e.genre == icmp::TEMPS_DEPASSE || e.genre == icmp::PARAMETRE;
    let recverr = sock.recverr.load(Ordering::Relaxed);
    let _contexte = contexte::entrer();
    vers_socket(&sock, Arrivee::Erreur { errno, injoignable, seq, fille, recverr, abandon });
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
        if TABLE.verrouiller().as_ref().and_then(|t| t.ecoute(s.destination, h.destination)).is_some() {
            effacer_temps_attente(n);
            livrer(Segment { isn: Some(isn), ..s });
        } else {
            envoyer_ack_tw(&e);
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
        repondre_rst(&h, s.charge.longueur(), s.destination, s.source);
    }
    if issue.ack {
        envoyer_ack_tw(&e);
    }
}

/// L'ACK d'une entrée de TIME_WAIT (`tcp_v4_timewait_ack`).
fn envoyer_ack_tw(e: &TempsAttente) {
    let r = e.regles.entete_ack(crate::temps::ns_monotone());
    let mut id = crate::aleatoire::u32() as u16;
    envoyer_segment(&r, e.locale, e.distante, &mut id, Ip::SYSTEME, 0, None, |_| {});
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
/// compris), de `source` pour `destination`, dans la tâche du réseau ou un
/// vidage de `lo` (`tcp_v4_rcv`) : l'en-tête et la somme (pas pour `lo`),
/// puis la socket. Un segment faux est jeté sans rien dire.
pub fn recevoir(source: [u8; 4], destination: [u8; 4], par_lo: bool, mut p: Paquet) {
    let Ok((h, charge)) = ftcp::lire(p.donnees(), source, destination, !par_lo) else { return };
    let entete = p.longueur() - charge.len();
    let _ = p.retirer_entete(entete);
    let _contexte = contexte::entrer();
    livrer(Segment { entete: h, charge: p, source, destination, fille: None, isn: None });
}

// --- Les appels ---

/// Une socket TCP neuve (`tcp_v4_init_sock`) : SO_RCVBUF et SO_SNDBUF de
/// TCP, son flux.
pub fn nouvelle(numero: u64) -> Option<Possession<Partie>> {
    let retenue = Arc::new(Retenue::new(numero)).ok()?;
    SOCKETS.fetch_add(1, Ordering::Relaxed);
    let partie = Partie {
        numero, mode: Mode::Neuve, adresses: Adresses::default(), identifiant: 0, orpheline: false, hors_table: false,
        options: OptionsTcp::DEFAUT, etablie_un_jour: false, connexion_en_cours: false, echeance_armee: None, memoire_comptee: 0, erreur_seule: 0, retenue,
    };
    let premier = partie.premier(0, SNDBUF_DEFAUT as usize, RCVBUF_DEFAUT as usize);
    Some(Possession::new(partie, premier))
}

fn flux(s: &Socket) -> &Possession<Partie> {
    s.flux.as_ref().expect("une socket TCP a son flux")
}

/// Les options de partage de la socket (sous son Mutex de 6g).
fn partage(s: &Socket) -> (bool, bool) {
    let i = s.appels.verrouiller();
    (i.options.reuseaddr, i.options.reuseport)
}

/// Lit une adresse d'IPv4 pour `bind` et `connect` : au moins 16 octets
/// (EINVAL), la famille AF_INET (bind : EAFNOSUPPORT ; AF_UNSPEC permis
/// avec 0.0.0.0, comme `__inet_bind`).
fn adresse(o: &[u8]) -> Result<socket::AdresseInet, i64> {
    socket::lire_adresse(o).ok_or(-EINVAL)
}

/// bind (`__inet_bind`, `inet_csk_get_port`).
pub fn lier(s: &Arc<Socket>, o: &[u8]) -> Result<(), i64> {
    let a = adresse(o)?;
    if a.famille != socket::AF_INET && !(a.famille == socket::AF_UNSPEC && a.adresse == [0; 4]) {
        return Err(-EAFNOSUPPORT);
    }
    if a.adresse != [0; 4] && !ipv4::avec_table(|t| t.est_a_nous(a.adresse)).unwrap_or(false) && !fipv4::boucle(a.adresse) {
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
    let (reuseaddr, reuseport) = partage(s);
    let lien = Lien {
        sorte: Sorte::Liee, adresse: a.adresse, port: a.port, distante: [0; 4], port_distant: 0, reuseaddr, reuseport,
        uid: s.uid, par_connect: false,
    };
    let port = match TABLE.verrouiller().as_mut() {
        Some(t) => t.lier(p.numero, lien, Cible::Socket(s.clone()), crate::aleatoire::u32()),
        None => return Err(-ENOBUFS),
    };
    let port = port.map_err(|e| match e {
        ports_tcp::Refus::Pris => -EADDRINUSE,
        ports_tcp::Refus::Plein => -ENOBUFS,
    })?;
    p.adresses = Adresses { lie: true, adresse: a.adresse, port, port_choisi: a.port != 0, ..p.adresses };
    p.hors_table = false;
    Ok(())
}

/// listen (`inet_listen`) : une socket neuve (liée, ou un port éphémère),
/// ou qui écoute déjà (le backlog change) ; une socket connectée : EINVAL.
pub fn ecouter(s: &Arc<Socket>, backlog: i32) -> Result<(), i64> {
    let backlog = (backlog.max(0) as usize).min(SOMAXCONN);
    let mut g = flux(s).posseder();
    let p = g.donnee();
    match &mut p.mode {
        Mode::Ecoute { backlog: b, .. } => {
            *b = backlog;
            return Ok(());
        }
        // Une connexion qui n'a jamais abouti : la socket est neuve pour
        // Linux (TCP_CLOSE), elle peut écouter.
        Mode::Connexion(t) if t.etat() == Etat::Fermee && !p.etablie_un_jour => {
            p.redevenir_neuve(s);
        }
        Mode::Connexion(_) => return Err(-EINVAL),
        Mode::Neuve => {}
    }
    let p = g.donnee();
    if !p.adresses.lie {
        let (reuseaddr, reuseport) = partage(s);
        let lien = Lien { sorte: Sorte::Liee, adresse: [0; 4], port: 0, distante: [0; 4], port_distant: 0, reuseaddr, reuseport, uid: s.uid, par_connect: false };
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
    g.publier(|p, c| p.rafraichir(c));
    Ok(())
}

/// connect (`inet_stream_connect`, `tcp_v4_connect`).
pub fn connecter(s: &Arc<Socket>, o: &[u8], non_bloquant: bool) -> Result<(), i64> {
    if o.len() >= 2 && socket::famille(o) == Some(socket::AF_UNSPEC) {
        // Déconnecter : RST, et la socket redevient neuve (`tcp_disconnect`).
        let mut g = flux(s).posseder();
        let p = g.donnee();
        if let Mode::Connexion(t) = &mut p.mode {
            t.avorter();
            p.emettre();
            p.redevenir_neuve(s);
        }
        g.publier(|p, c| p.rafraichir(c));
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
        // Une connexion qui n'a jamais abouti (refusée, abandonnée) : son
        // erreur, une fois, si personne ne l'a lue ; puis la socket
        // redevient neuve, et ce `connect` repart (`inet_stream_connect` :
        // TCP_CLOSE), même si une écoute est apparue entre-temps.
        if let Mode::Connexion(t) = &mut p.mode
            && t.etat() == Etat::Fermee
            && !p.etablie_un_jour
        {
            let e = t.prendre_erreur();
            p.redevenir_neuve(s);
            if e != 0 {
                g.publier(|p, c| p.rafraichir(c));
                return Err(-(e as i64));
            }
        }
        let p = g.donnee();
        match &p.mode {
            Mode::Ecoute { .. } => return Err(-EISCONN),
            Mode::Connexion(t) => {
                // Le `connect` d'une connexion en cours : EALREADY (non
                // bloquant), ou attendre encore (bloquant, refait après un
                // signal) ; établie : EISCONN ; fermée sur une erreur :
                // l'erreur, une fois.
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
                        // Établie un jour, puis fermée : son erreur, une
                        // fois, puis EISCONN.
                        let e = if let Mode::Connexion(t) = &mut p.mode { t.prendre_erreur() } else { 0 };
                        if e != 0 {
                            return Err(-(e as i64));
                        }
                        return Err(-EISCONN);
                    }
                    _ => {
                        if p.connexion_en_cours {
                            // Le premier `connect` qui suit l'établissement
                            // d'un `connect` non bloquant rend 0 (mesuré).
                            p.connexion_en_cours = false;
                            return Ok(());
                        }
                        return Err(-EISCONN);
                    }
                }
            }
            Mode::Neuve => {
                // La route, la source, le port.
                let (chemin, destination) = ipv4::router(a.adresse, p.adresses.lie.then_some(p.adresses.adresse).filter(|&x| x != [0; 4]))?;
                let source = if p.adresses.lie && p.adresses.adresse != [0; 4] { p.adresses.adresse } else { ipv4::source(&chemin) };
                if fipv4::boucle(source) && !ipv4::par_lo(&chemin) {
                    return Err(-EINVAL);
                }
                let (reuseaddr, reuseport) = partage(s);
                let lien = Lien { sorte: Sorte::Liee, adresse: source, port: 0, distante: [0; 4], port_distant: 0, reuseaddr, reuseport, uid: s.uid, par_connect: false };
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
                p.adresses = Adresses { lie: true, adresse: p.adresses.adresse, port, port_choisi: p.adresses.port_choisi, distante: destination, port_distant: a.port, source };
                p.hors_table = false;
                let iss = reprise.map_or_else(|| numero_initial(source, destination, port, a.port), |(_, isn, _)| isn);
                if let Some((n, _, _)) = reprise {
                    TW.verrouiller().retain(|e| e.numero != n);
                    super::tache::armer(n, None);
                }
                let rcvbuf = s.rcvbuf.load(Ordering::Relaxed) as usize;
                let echelle = itcp::echelle(rcvbuf, p.options.rcvbuf_fixe, reception_max(), p.options.window_clamp);
                let mut t = Tcb::connecter(port, a.port, iss, mss_vers(destination), rcvbuf, s.sndbuf.load(Ordering::Relaxed) as usize,
                                           echelle);
                t.mss_utilisateur = p.options.maxseg;
                t.window_clamp = p.options.window_clamp;
                t.rcvbuf_fixe = p.options.rcvbuf_fixe;
                t.rcvbuf_max = RECEPTION_MAX.load(Ordering::Relaxed);
                t.rcvlowat = p.options.rcvlowat;
                t.reglages = p.options.reglages(false);
                t.sndbuf_fixe = p.options.sndbuf_fixe;
                t.sndbuf_max = ENVOI_MAX.load(Ordering::Relaxed);
                t.memoire = niveau_memoire();
                t.poser_controle(p.options.controle);
                t.sans_file = sans_carte(destination);
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
                p.connexion_en_cours = non_bloquant;
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
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    let r = g.attendre(flux(s).file(), Sommeil::Interruptible, echeance, |c| !matches!(c.etat, Some(Etat::SynEnvoye | Etat::SynRecu)));
    let p = g.donnee();
    match r {
        Reveil::Reveillee => {}
        Reveil::Echeance => return Err(if deja { -EALREADY } else { -EINPROGRESS }),
        Reveil::Signal => return Err(if delai.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS }),
    }
    let Mode::Connexion(t) = &mut p.mode else { return Err(-ECONNABORTED) };
    if t.etat() == Etat::Fermee {
        // Un connect bloquant qui échoue remet la socket à neuf
        // (`tcp_disconnect`) : elle peut se reconnecter, et poll ne dit
        // plus que POLLOUT | POLLHUP.
        let e = t.prendre_erreur();
        p.redevenir_neuve(s);
        g.publier(|p, c| p.rafraichir(c));
        return Err(-(if e != 0 { e } else { itcp::ECONNREFUSED }) as i64);
    }
    p.etablie_un_jour = true;
    p.connexion_en_cours = false;
    Ok(())
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
    // SO_KEEPALIVE, SO_OOBINLINE, IP_TTL...), lues avant la possession
    // (l'ordre de nos verrous : le Mutex de la socket d'abord).
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
            let (Ok(place_flux), Ok(place_socket), Ok(retenue)) = (faillible::boite_vide(), ArcVide::new(), Arc::new(Retenue::new(filles[i].numero))) else { return Err(-ENFILE) };
            let f = filles.remove(i).expect("la fille");
            let (port, distante, port_distant, locale) = (f.tcb.port_local, f.distante, f.tcb.port_distant, f.locale);
            let numero = f.numero;
            let enfant = Socket::new(Protocole::Tcp, SOCK_STREAM as u16, IPPROTO_TCP as u16, s.uid);
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
                adresses: Adresses { lie: true, adresse: p.adresses.adresse, port, port_choisi: p.adresses.port_choisi, distante, port_distant, source: locale },
                identifiant: f.identifiant, orpheline: false, hors_table,
                // Tout, sauf ce qui est propre à une écoute (`inet_csk_clone_lock`,
                // `inet_csk_delack_init`) : la fille n'attend pas de données pour naître deux fois.
                options: OptionsTcp { defer_accept: 0, quickack: true, ..p.options },
                etablie_un_jour: true,
                connexion_en_cours: false, echeance_armee: None, memoire_comptee: 0, erreur_seule: 0, retenue,
            };
            let premier = partie.premier(0, SNDBUF_DEFAUT as usize, RCVBUF_DEFAUT as usize);
            let flux = alloc::boxed::Box::write(place_flux, Possession::new(partie, premier));
            let enfant = place_socket.remplir(enfant.avec_flux(flux));
            enfant.rcvbuf.store(s.rcvbuf.load(Ordering::Relaxed), Ordering::Relaxed);
            enfant.sndbuf.store(s.sndbuf.load(Ordering::Relaxed), Ordering::Relaxed);
            enfant.recverr.store(options.recverr, Ordering::Relaxed);
            enfant.pmtudisc.store(options.pmtudisc, Ordering::Relaxed);
            enfant.appels.verrouiller().options = options;
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

/// L'adresse locale (getsockname) et distante (getpeername ; None : pas
/// connectée).
pub fn nom(s: &Socket) -> ([u8; 4], u16) {
    let mut g = flux(s).posseder();
    let a = g.donnee().adresses;
    (if matches!(g.donnee().mode, Mode::Connexion(_)) { a.source } else { a.adresse }, a.port)
}

pub fn pair(s: &Socket) -> Option<([u8; 4], u16)> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    match &p.mode {
        Mode::Connexion(t) if !matches!(t.etat(), Etat::Fermee | Etat::SynEnvoye) || p.etablie_un_jour && t.etat() != Etat::Fermee => {
            Some((p.adresses.distante, p.adresses.port_distant))
        }
        Mode::Connexion(t) if t.etat() == Etat::SynEnvoye => None,
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
    loop {
        let arret = g.avec_court(|_, c| c.arret);
        let p = g.donnee();
        let Mode::Connexion(t) = &mut p.mode else { return Err(-EPIPE) };
        let e = t.prendre_erreur();
        if e != 0 {
            g.publier(|p, c| p.rafraichir(c));
            return if fait > 0 { Ok(fait) } else { Err(-(e as i64)) };
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
    // place.
    let cible = if drapeaux & MSG_WAITALL != 0 { longueur } else { rcvlowat.min(longueur) };
    let mut g = flux(s).posseder();
    let mut fait = 0;
    loop {
        let arret = g.avec_court(|_, c| c.arret);
        let p = g.donnee();
        let Mode::Connexion(t) = &mut p.mode else { return Err(-ENOTCONN) };
        // L'octet urgent seul en tête, hors du flux : MSG_PEEK n'a rien à
        // voir ; une lecture le passe (et l'oublie : `urg_data` effacé, un
        // recv(MSG_OOB) suivant rend EINVAL, comme Linux), puis regarde ce
        // qui suit, ou attend.
        let a_lire = if peek { t.lisibles_dans_le_flux() } else { t.lisibles() };
        if a_lire > 0 {
            let lu = if drapeaux & MSG_TRUNC != 0 {
                Ok(t.jeter(longueur - fait))
            } else {
                let mut decalage = fait;
                t.lire(longueur - fait, peek, |o| {
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
            if fait == longueur || fait >= cible.max(1) || peek {
                return Ok(fait);
            }
            continue;
        }
        if fait >= cible.max(1) {
            return Ok(fait);
        }
        let e = t.prendre_erreur();
        if e != 0 {
            g.publier(|p, c| p.rafraichir(c));
            return if fait > 0 { Ok(fait) } else { Err(-(e as i64)) };
        }
        if t.fin_recue() || arret & socket::ARRET_LECTURE != 0 || t.etat() == Etat::Fermee {
            return Ok(fait);
        }
        if matches!(t.etat(), Etat::SynEnvoye | Etat::SynRecu) && non_bloquant {
            return Err(-EAGAIN);
        }
        if non_bloquant {
            return if fait > 0 { Ok(fait) } else { Err(-EAGAIN) };
        }
        let r = g.attendre(flux(s).file(), Sommeil::Interruptible, echeance, |c| {
            c.lisibles > 0 || c.fin_recue || c.erreur != 0 || c.arret & socket::ARRET_LECTURE != 0 || c.etat == Some(Etat::Fermee)
        });
        match r {
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
        Err(e) => Err(-(e as i64)),
    };
    g.publier(|p, c| p.rafraichir(c));
    r
}

/// shutdown (`inet_shutdown`, `tcp_shutdown`) : les drapeaux posés ;
/// SHUT_WR d'une connexion envoie FIN. Pas connectée : ENOTCONN, mais les
/// drapeaux posés (mesuré) ; une écoute : SHUT_RD la défait.
pub fn arreter(s: &Arc<Socket>, arret: u8) -> Result<(), i64> {
    let mut g = flux(s).posseder();
    let connectee = matches!(&g.donnee().mode, Mode::Connexion(t) if !matches!(t.etat(), Etat::Fermee | Etat::SynEnvoye));
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
            if t.lisibles() > 0 || (linger.0 && linger.1 == 0) {
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
            for f in filles.iter_mut() {
                f.tcb.avorter();
                emettre_tcb(&mut f.tcb, f.locale, f.distante, &mut f.identifiant, ip, None);
                if let Some(t) = TABLE.verrouiller().as_mut() {
                    t.retirer(f.numero);
                }
            }
            filles.clear();
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

fn t_ferme(p: &Partie) -> bool {
    matches!(&p.mode, Mode::Connexion(t) if t.etat() == Etat::Fermee)
}

/// Ce qu'on peut faire de la socket sans attendre (`tcp_poll`).
pub fn sonder(s: &Socket) -> u32 {
    flux(s).court(|c| {
        let m = masque(c);
        // Pas écrivable : la connexion devra le savoir (`tcp_poll`, SOCK_NOSPACE).
        if m & POLLOUT == 0 && !c.ecoute && !matches!(c.etat, Some(Etat::SynEnvoye | Etat::SynRecu)) {
            c.sans_place = true;
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
                m |= POLLOUT | POLLWRNORM | POLLWRBAND;
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
    let e = match &mut g.donnee().mode {
        Mode::Connexion(t) => t.prendre_erreur(),
        _ => 0,
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
        Mode::Neuve => Ok((0, 0, 0, false)),
    }
}

/// Lit ou change les options de SOL_TCP sous la possession ; puis ce que
/// le changement fait partir (TCP_NODELAY, TCP_CORK retiré), et les
/// minuteurs (le keepalive).
pub fn avec_options<R>(s: &Socket, f: impl FnOnce(&mut OptionsTcp, Option<&mut Tcb<Paquet>>) -> R) -> R {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    let tcb = match &mut p.mode {
        Mode::Connexion(t) => Some(t),
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

/// SO_KEEPALIVE ou SO_OOBINLINE a changé : la socket en garde la copie, et
/// la connexion en tient compte (le keepalive armé ou arrêté).
pub fn options_socket_changees(s: &Socket, keepalive: bool, oobinline: bool) {
    avec_options(s, |op, t| {
        op.keepalive = keepalive;
        op.oobinline = oobinline;
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

/// IP_MTU d'une connexion (`dst_mtu`) ; None : pas de connexion (ENOTCONN).
pub fn mtu_du_chemin(s: &Socket) -> Option<u32> {
    let mut g = flux(s).posseder();
    let p = g.donnee();
    if !matches!(p.mode, Mode::Connexion(_)) {
        return None;
    }
    ipv4::router(p.adresses.distante, None).ok().map(|(c, d)| ipv4::mtu_vers(&c, d))
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
           i.etat, t.non_acquittes(), t.lisibles(), minuteur, clock_t(quand), i.retransmissions, uid, i.sondes, inode, 1, 0,
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
