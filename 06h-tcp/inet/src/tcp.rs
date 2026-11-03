//! Une connexion TCP (RFC 9293), sans le matériel : la machine à états et
//! ses variables (le `tcp_sock` de Linux, net/ipv4/tcp*.c), testée sur
//! l'hôte. Le noyau (noyau/src/reseau/tcp.rs) garde les sockets, leurs
//! verrous, les tables, les échéances, les attentes des programmes et les
//! copies ; ici, les RÈGLES : ce que fait chaque segment reçu dans chaque
//! état, ce qu'il faut envoyer, quand, ce que voit le programme.
//!
//! TCP en deux mots. Chaque octet envoyé a un numéro de séquence (sur 32
//! bits, qui reviennent à zéro : toutes les comparaisons se font modulo
//! 2³², `avant`). Chaque côté choisit son premier numéro (l'ISN, tiré par
//! le noyau : RFC 6528) et l'annonce dans son SYN ; l'autre l'acquitte
//! (ACK = le prochain octet attendu). La poignée de main : SYN, SYN-ACK,
//! ACK. Chacun dit aussi combien il peut encore recevoir (la FENÊTRE) :
//! l'émetteur n'envoie jamais au-delà. La fin : chaque sens se ferme par un
//! FIN (qui compte pour un octet), acquitté ; le côté qui ferme le premier
//! attend ensuite deux fois la durée de vie d'un segment (TIME_WAIT, 60 s
//! chez Linux), pour qu'un vieux segment de la connexion ne soit pas pris
//! pour un segment d'une suivante. RST coupe tout, tout de suite.
//!
//! LES ÉTATS (RFC 9293, 3.3.2) : SYN_SENT (un `connect`), SYN_RECEIVED (un
//! SYN reçu par une écoute ; la fille d'une écoute, plan de 6h), ESTABLISHED,
//! puis la fermeture : FIN_WAIT_1 et FIN_WAIT_2 (nous avons fermé),
//! CLOSE_WAIT (l'autre a fermé), CLOSING (les deux à la fois), LAST_ACK
//! (l'autre avait fermé, puis nous), TIME_WAIT, et CLOSED. L'écoute
//! (LISTEN) n'est pas une connexion : c'est le noyau qui la tient, et qui
//! crée une `Tcb` par SYN reçu.
//!
//! LA FIABILITÉ (6h, commit 6). Un réseau perd, duplique, retarde et
//! réordonne ; TCP le cache au programme :
//!   - la RETRANSMISSION : ce qui n'est pas acquitté au bout du RTO est
//!     renvoyé (rtt.rs : le RTO suit le temps d'aller-retour mesuré ;
//!     Karn : jamais de mesure sur un segment retransmis), le RTO double à
//!     chaque échec, et la connexion abandonne comme Linux 6.18
//!     (`tcp_write_timeout` : le SYN, ses quatre premières retransmissions
//!     sans doublement, TCP_SYNCNT ; puis le « temps modélisé » de
//!     `tcp_retries2`, 924,6 s ; une orpheline plus tôt ; TCP_USER_TIMEOUT) ;
//!   - la CONGESTION (congestion.rs) : Reno, la retransmission rapide au
//!     troisième ACK dupliqué, la reprise NewReno et PRR ;
//!   - la FILE HORS D'ORDRE (hors_ordre.rs) : ce qui arrive après un trou
//!     est gardé, et l'ACK dupliqué part aussitôt ;
//!   - les ACK RETARDÉS (`tcp_send_delayed_ack`) : un ACK attend jusqu'à
//!     40 à 200 ms (l'`ato`, qui suit l'écart entre les arrivées) une
//!     réponse à laquelle s'accrocher, sauf au début d'une connexion (le
//!     mode « quickack »), au deuxième segment plein, ou devant un trou ;
//!   - la SONDE de fenêtre nulle (`tcp_probe_timer`) : quand l'autre n'a
//!     plus de place, on lui demande régulièrement s'il en a refait (sinon
//!     un ACK perdu qui la rouvrait bloquerait les deux côtés pour
//!     toujours).
//!
//! LE DÉBIT ET LES OPTIONS (commit 7) :
//!   - l'ÉCHELLE DE FENÊTRE (RFC 7323) : la fenêtre de 16 bits décalée,
//!     proposée dans le SYN, pour annoncer plus de 64 Kio (sur `lo`) ;
//!   - NAGLE (RFC 896, avec la règle de Minshall de Linux) : un petit
//!     segment attend tant qu'un autre petit segment n'est pas acquitté,
//!     sauf TCP_NODELAY ; TCP_CORK et MSG_MORE retiennent tout segment
//!     incomplet, que pousse au plus tard la sonde (un RTO : 200 ms et
//!     plus) ;
//!   - le KEEPALIVE (SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL,
//!     TCP_KEEPCNT) : une connexion muette est sondée, et coupée si l'autre
//!     ne répond plus ;
//!   - l'OCTET URGENT (MSG_OOB) : un octet marqué par le pointeur urgent,
//!     lu à part (sauf SO_OOBINLINE), comme Linux ;
//!   - l'agrandissement de SO_SNDBUF (`tcp_sndbuf_expand`), et ce que
//!     rendent TCP_INFO et /proc/net/tcp (`Info`).
//!
//! LES TAMPONS : les données à envoyer, des blocs de 64 Kio au plus (la
//! `size_goal` de Linux), remplis par `ecrire`, découpés au MSS par
//! `emettre`, rendus quand ils sont acquittés ; les données reçues, les
//! charges des segments telles quelles (`P`, le paquet du noyau : aucune
//! copie de plus), lues par `lire`. Tout est alloué faillible : un manque
//! de mémoire jette le segment reçu (il reviendra), ou rend moins à
//! `ecrire`, jamais une panique.
//!
//! LA RETRANSMISSION, À LA FAÇON DE BSD : SND.NXT revient à SND.UNA après
//! un RTO, et `emettre` renvoie de là ce qui avait déjà été envoyé ;
//! SND.MAX garde le plus loin qu'on soit allé (un ACK peut couvrir jusque
//! là). Linux garde SND.NXT et renvoie depuis sa file de retransmission
//! les paquets qu'il a marqués perdus ; sans SACK, il les marque tous
//! après un RTO : c'est le même renvoi, que nos octets n'ont pas besoin de
//! liste pour faire.
//!
//! L'heure et le hasard sont des arguments (l'ISN est tiré par le noyau,
//! l'heure est en nanosecondes) ; les segments à envoyer sont rendus par
//! `emettre` ; les copies vers et depuis le programme passent par des
//! fonctions données. `echeance` dit quand appeler `minuteur`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use formats::reseau::tcp::{self, Tcp};

mod congestion;
mod hors_ordre;
mod rtt;

use congestion::{Congestion, Phase, REORDONNANCEMENT};
use hors_ordre::HorsOrdre;
use rtt::Rtt;

pub use congestion::CWND_INITIALE;
pub use rtt::{RTO_INITIAL, RTO_MAX, RTO_MIN, RTO_REPLI, temps_modele};

/// La plus grande taille d'un bloc du tampon d'émission.
pub const BLOC: usize = 65_536;
/// Le MSS par défaut, quand l'autre n'en dit rien (RFC 9293 : 536).
pub const MSS_DEFAUT: u16 = 536;
/// Le plus petit MSS (TCP_MIN_MSS de Linux, que TCP_MAXSEG ne peut pas
/// descendre plus bas).
pub const MSS_MIN: u16 = 88;
/// Le plus petit MSS d'envoi, quoi que propose l'autre (`tcp_min_snd_mss`,
/// la correction de CVE-2019-11479 : sans plancher, un pair qui annonce un
/// MSS de 1 fait découper tout ce qu'on envoie en segments d'un octet).
pub const MSS_ENVOI_MIN: u16 = 48;
/// Où en est la mémoire de TCP de toute la machine (`tcp_mem`), que le
/// noyau dit à chaque connexion avant de la faire travailler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Memoire {
    /// Sous le premier seuil (`tcp_mem[0]`) : rien ne change.
    Libre,
    /// Au-delà : SO_SNDBUF ne grandit plus de lui-même
    /// (`tcp_should_expand_sndbuf`).
    Pression,
    /// Au-delà du dernier (`tcp_mem[2]`) : plus rien de neuf n'est gardé,
    /// sauf pour qu'une connexion avance (`__sk_mem_raise_allocated` qui
    /// échoue) : un envoi n'écrit que dans un tampon vide, une réception ne
    /// garde un segment dans l'ordre que si sa file est vide
    /// (`sk_forced_mem_schedule`), et la file hors d'ordre ne prend plus
    /// rien (`tcp_data_queue_ofo`) ; l'autre retransmettra.
    Limite,
}

/// L'intervalle entre deux ACK « hors fenêtre » ou « de défi » d'une
/// connexion (`tcp_invalid_ratelimit` : 500 ms) : deux pairs dont les
/// numéros ne se correspondent plus ne s'échangent pas d'ACK sans fin.
pub const LIMITE_ACK_INVALIDE: u64 = 500_000_000;
/// La plus grande fenêtre sans échelle.
pub const FENETRE_MAX: u32 = 65_535;
/// La plus grande échelle de fenêtre (`TCP_MAX_WSCALE`, RFC 7323 2.3) :
/// celle d'un pair qui en propose plus est ramenée à 14, comme Linux.
pub const ECHELLE_MAX: u8 = 14;

/// L'échelle que nous proposons (`tcp_select_initial_window`) : de quoi
/// annoncer en 16 bits la plus grande place de réception que la connexion
/// pourra avoir, ilog2(place) - 15, entre 0 et 14. Cette place : la moitié
/// de SO_RCVBUF (`tcp_full_space`) s'il a été fixé par le programme
/// (`SOCK_RCVBUF_LOCK` : la fenêtre ne la dépassera jamais) ; sinon la plus
/// grande que la machine permet, `reception_max` (`tcp_rmem[2]` et
/// `rmem_max`), que le noyau calcule d'après sa mémoire, comme `tcp_init`.
/// Linux 6.18 propose ainsi 10 sur une machine de 12 Gio, et 7 avec
/// SO_RCVBUF fixé à 8 Mio (mesuré sur l'hôte).
pub fn echelle(rcvbuf: usize, rcvbuf_fixe: bool, reception_max: usize) -> u8 {
    let pleine = rcvbuf / 2;
    let place = if rcvbuf_fixe { pleine } else { pleine.max(reception_max).min(65_535 << ECHELLE_MAX) };
    (place.max(1).ilog2() as i64 - 15).clamp(0, ECHELLE_MAX as i64) as u8
}
/// Le plafond de SO_SNDBUF agrandi (`tcp_wmem[2]`, 4 Mio).
pub const SNDBUF_MAX: usize = 4 << 20;

/// Les retransmissions d'un SYN avant d'abandonner (`tcp_syn_retries`, la
/// valeur de TCP_SYNCNT quand le programme n'en a pas donné), et d'un
/// SYN-ACK (`tcp_synack_retries`).
pub const SYN_ESSAIS: u32 = 6;
pub const SYNACK_ESSAIS: u32 = 5;
/// Les premières retransmissions d'un SYN qui ne doublent pas le RTO
/// (`tcp_syn_linear_timeouts`, Linux 6.x : un SYN perdu se rattrape en 1 s,
/// pas en 1, 2, 4... s).
const SYN_LINEAIRES: u32 = 4;
/// Les retransmissions de données avant d'abandonner (`tcp_retries2`),
/// comptées en temps modélisé (rtt.rs).
pub const RETRIES2: u32 = 15;
/// Celles d'une orpheline : `tcp_orphan_retries` vaut 0, qui veut dire 8
/// tant que la connexion semble vivante (son RTO sous le maximum).
const ORPHELINE_ESSAIS: u32 = 8;

/// Les ACK retardés : le plus petit délai (TCP_ATO_MIN, TCP_DELACK_MIN),
/// le plus grand (TCP_DELACK_MAX), celui d'une connexion qui ne fait que
/// recevoir (HZ/2), et le nombre d'ACK immédiats au début d'une connexion
/// (TCP_MAX_QUICKACKS).
const ATO_MIN: u64 = 40_000_000;
const DELACK_MAX: u64 = 200_000_000;
const ATO_RECEPTION: u64 = 500_000_000;
const ACK_RAPIDES_MAX: u32 = 16;

// Les errno que voit le programme.
pub const EAGAIN: i32 = 11;
pub const EINVAL: i32 = 22;
pub const ECONNREFUSED: i32 = 111;
pub const ECONNRESET: i32 = 104;
pub const EPIPE: i32 = 32;
pub const ETIMEDOUT: i32 = 110;

/// `a` est-il avant `b`, modulo 2³² (le `before` de Linux) ?
pub fn avant(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a` est-il après `b` ?
pub fn apres(a: u32, b: u32) -> bool {
    avant(b, a)
}

/// Les états d'une connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    SynEnvoye,
    SynRecu,
    Etablie,
    FinAttente1,
    FinAttente2,
    AttenteFermeture,
    Fermeture,
    DernierAck,
    TempsAttente,
    Fermee,
}

impl Etat {
    /// Le numéro de l'état chez Linux (`TCP_ESTABLISHED`... : /proc/net/tcp,
    /// TCP_INFO).
    pub fn linux(self) -> u8 {
        match self {
            Etat::Etablie => 1,
            Etat::SynEnvoye => 2,
            Etat::SynRecu => 3,
            Etat::FinAttente1 => 4,
            Etat::FinAttente2 => 5,
            Etat::TempsAttente => 6,
            Etat::Fermee => 7,
            Etat::AttenteFermeture => 8,
            Etat::DernierAck => 9,
            Etat::Fermeture => 11,
        }
    }

    /// La connexion est-elle « synchronisée » (après la poignée de main) ?
    fn synchronise(self) -> bool {
        !matches!(self, Etat::SynEnvoye | Etat::SynRecu | Etat::Fermee)
    }

    /// Reçoit-on encore des données dans cet état ?
    fn recoit(self) -> bool {
        matches!(self, Etat::Etablie | Etat::FinAttente1 | Etat::FinAttente2)
    }
}

/// Une charge reçue, gardée telle quelle dans la file de réception : le
/// paquet du noyau, réduit à sa charge TCP.
pub trait Charge {
    /// Les octets (ce qui reste à lire).
    fn octets(&self) -> &[u8];
    /// Retire `n` octets du début (lus, ou déjà reçus).
    fn avancer(&mut self, n: usize);
    /// Ce qu'elle occupe en mémoire (la taille vraie, que compte
    /// SO_RCVBUF).
    fn taille_vraie(&self) -> usize;
}

/// Un segment à envoyer : son en-tête, et sa charge, désignée dans le
/// tampon d'émission (le noyau la copie par `copier_envoi`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sortant {
    pub entete: Tcp,
    /// Le décalage de la charge depuis le début du tampon d'émission, et sa
    /// longueur.
    pub debut: usize,
    pub longueur: usize,
}

/// Ce qu'un événement a changé, pour réveiller qui attend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effets {
    /// Des octets (ou la fin de l'autre sens, ou une erreur) à lire.
    pub lisible: bool,
    /// De la place s'est libérée dans le tampon d'émission.
    pub place: bool,
    /// L'état a changé (établie, fermée...).
    pub etat: bool,
    /// Il y a quelque chose à envoyer (`emettre`).
    pub a_emettre: bool,
}

impl Effets {
    pub fn ou(&mut self, autre: Effets) {
        self.lisible |= autre.lisible;
        self.place |= autre.place;
        self.etat |= autre.etat;
        self.a_emettre |= autre.a_emettre;
    }
}

/// Ce que le programme (ou le noyau) règle d'une connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reglages {
    /// TCP_SYNCNT : les retransmissions du SYN (ou du SYN-ACK d'une fille)
    /// avant d'abandonner ; 0 : celles du système (SYN_ESSAIS,
    /// SYNACK_ESSAIS).
    pub syn_essais: u32,
    /// TCP_USER_TIMEOUT, en nanosecondes : le plus long que des données
    /// puissent rester sans acquittement avant d'abandonner (0 : la règle
    /// de `tcp_retries2`).
    pub delai_utilisateur: u64,
    /// Le programme a fermé la socket (le `SOCK_DEAD` de Linux) : personne
    /// n'attend plus la fin de cette connexion, qui abandonne plus tôt.
    pub orpheline: bool,
    /// TCP_NODELAY (pas de Nagle) et TCP_CORK (aucun segment incomplet).
    pub nodelay: bool,
    pub cork: bool,
    /// SO_KEEPALIVE, et TCP_KEEPIDLE, TCP_KEEPINTVL (en nanosecondes),
    /// TCP_KEEPCNT.
    pub keepalive: bool,
    pub keepidle: u64,
    pub keepintvl: u64,
    pub keepcnt: u32,
    /// SO_OOBINLINE : l'octet urgent reste dans le flux.
    pub oobinline: bool,
}

impl Reglages {
    /// Ceux de Linux : keepalive après 2 h de silence, une sonde toutes les
    /// 75 s, 9 sans réponse (TCP_KEEPALIVE_TIME, _INTVL, _PROBES).
    pub const DEFAUT: Reglages = Reglages {
        syn_essais: 0, delai_utilisateur: 0, orpheline: false, nodelay: false, cork: false, keepalive: false,
        keepidle: 7200 * 1_000_000_000, keepintvl: 75 * 1_000_000_000, keepcnt: 9, oobinline: false,
    };
}

/// L'octet urgent reçu (le `urg_data` de Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Urgent {
    Aucun,
    /// Le pointeur est arrivé, pas encore l'octet (TCP_URG_NOTYET).
    Attendu,
    /// L'octet est là, à lire par MSG_OOB (TCP_URG_VALID).
    Valide(u8),
    /// Il a été lu par MSG_OOB (TCP_URG_READ) ; sa place dans le flux reste
    /// marquée jusqu'à ce que la lecture la passe.
    Lu,
}

/// Ce que rendent TCP_INFO et /proc/net/tcp (les champs de `struct
/// tcp_info` que nous tenons ; les durées en microsecondes, les heures en
/// millisecondes depuis l'événement).
#[derive(Debug, Clone, Copy, Default)]
pub struct Info {
    pub etat: u8,
    /// La phase de la congestion (`TCP_CA_Open` 0, `Disorder` 1,
    /// `Recovery` 3, `Loss` 4).
    pub phase: u8,
    pub retransmissions: u8,
    pub sondes: u8,
    pub recul: u8,
    /// TCPI_OPT_WSCALE (4) si l'échelle de fenêtre est en service.
    pub options: u8,
    pub echelle_envoi: u8,
    pub echelle_reception: u8,
    pub rto: u32,
    pub ato: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    /// Les segments en vol, et ceux qui ont été retransmis.
    pub non_acquittes: u32,
    pub retransmis: u32,
    pub dernier_envoi: u32,
    pub dernier_recu: u32,
    pub dernier_ack: u32,
    pub rtt: u32,
    pub rttvar: u32,
    pub ssthresh: u32,
    pub cwnd: u32,
    pub advmss: u32,
    pub reordonnancement: u32,
    pub total_retrans: u32,
    /// Les échéances, pour /proc/net/tcp : la retransmission (ou la sonde,
    /// `sonde`) et le keepalive, en ns depuis l'appel (None : aucune) ;
    /// les ACK rapides qui restent, et le ping-pong.
    pub t_retrans: Option<u64>,
    pub sonde: bool,
    pub t_keepalive: Option<u64>,
    pub ack_rapides: u32,
    pub pingpong: bool,
    pub demarrage_lent: bool,
}

/// Les ACK retardés (le `icsk_ack` de Linux).
#[derive(Debug, Clone, Copy)]
struct Ack {
    /// Un ACK est dû (ICSK_ACK_SCHED) : il partira avec le prochain
    /// segment, ou à l'échéance `t`, ou tout de suite si `verifier_ack`
    /// le décide.
    programme: bool,
    /// Le prochain ACK dû part sans délai, une fois (ICSK_ACK_NOW : un trou
    /// de la file hors d'ordre vient d'être comblé, RFC 5681 4.2).
    urgent: bool,
    /// Le délai d'un ACK retardé (`ato`) : il suit l'écart entre les
    /// arrivées de données. 0 : rien n'est encore arrivé.
    ato: u64,
    /// Les ACK encore à envoyer sans délai (le mode « quickack ») : au
    /// début d'une connexion, l'émetteur en démarrage lent attend chaque
    /// ACK pour grandir.
    rapides: u32,
    /// Le mode « ping-pong » : nous répondons vite à ce qui arrive (une
    /// conversation) ; l'ACK attend alors la réponse pour partir avec elle.
    pingpong: u8,
    /// La taille des segments de l'autre, estimée (`rcv_mss`).
    rcv_mss: u32,
    /// RCV.NXT au dernier ACK envoyé (`rcv_wup`), et la fenêtre qu'il
    /// annonçait (`rcv_wnd`) : le bord droit, lui, avance à chaque arrivée.
    rcv_wup: u32,
    fenetre: u32,
    /// L'heure de la dernière arrivée de données (`lrcvtime`).
    lrcvtime: u64,
    /// L'échéance de l'ACK retardé.
    t: Option<u64>,
}

impl Ack {
    const fn new() -> Ack {
        Ack { programme: false, urgent: false, ato: 0, rapides: 0, pingpong: 0, rcv_mss: MSS_DEFAUT as u32, rcv_wup: 0, fenetre: 0, lrcvtime: 0,
              t: None }
    }

    /// Le mode « quickack », hors ping-pong (`tcp_in_quickack_mode`).
    fn rapide(&self) -> bool {
        self.rapides > 0 && self.pingpong == 0
    }
}

/// Une connexion.
pub struct Tcb<P: Charge> {
    etat: Etat,
    /// Les ports et adresses : du noyau, recopiés dans chaque en-tête.
    pub port_local: u16,
    pub port_distant: u16,
    /// La fille d'une écoute (le `request_sock` de Linux) : ses SYN-ACK
    /// suivent `tcp_synack_retries`.
    fille: bool,
    // L'émission (RFC 9293, 3.3.1).
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Le plus loin qu'on ait envoyé (SND.NXT recule après un RTO).
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    /// La plus grande fenêtre que l'autre ait annoncée (`max_window`).
    max_fenetre: u32,
    /// L'échelle de fenêtre (RFC 7323) : de combien de bits décaler la
    /// fenêtre que l'autre annonce, et celle que nous annonçons. En service
    /// (`wscale_ok`) seulement si les deux SYN la portent (slirp ne la
    /// propose pas) ; une échelle de 0 est une échelle en service.
    echelle_envoi: u8,
    echelle_reception: u8,
    echelle_ok: bool,
    /// La fin du dernier petit segment envoyé (`snd_sml`, pour Nagle).
    snd_sml: u32,
    /// Le pointeur urgent à envoyer (`snd_up`) : le numéro qui suit
    /// l'octet urgent ; égal à SND.UNA hors du « mode urgent ».
    snd_up: u32,
    /// Notre SYN a été acquitté.
    syn_acquitte: bool,
    // La réception.
    irs: u32,
    rcv_nxt: u32,
    /// Le bord droit de la fenêtre annoncée (rcv_nxt + fenêtre), qui ne
    /// recule jamais (RFC 9293, 3.8.6.2.2).
    rcv_bord: u32,
    /// Une fenêtre a déjà été annoncée (le bord droit a un sens).
    bord_pose: bool,
    /// Le MSS qu'on envoie : celui de l'autre, borné par le nôtre.
    mss: u16,
    /// Le MSS qu'on annonce (la MTU de notre chemin moins 40).
    mss_local: u16,
    /// TCP_MAXSEG demandé (0 : rien).
    pub mss_utilisateur: u16,
    // Le tampon d'émission : les octets non acquittés et ceux qui restent
    // à envoyer, par blocs ; le premier bloc commence à `decalage_envoi`,
    // et son premier octet porte le numéro `seq_envoi`.
    envoi: VecDeque<Vec<u8>>,
    decalage_envoi: usize,
    octets_envoi: usize,
    seq_envoi: u32,
    /// Le programme ne veut plus écrire : un FIN suit les données (son
    /// numéro : `fin_seq`).
    fin_voulue: bool,
    // La réception.
    reception: VecDeque<P>,
    octets_reception: usize,
    taille_vraie_reception: usize,
    hors_ordre: HorsOrdre<P>,
    /// Le numéro du FIN de l'autre, arrivé après un trou.
    fin_hors_ordre: Option<u32>,
    /// Le numéro du prochain octet que lira le programme (`copied_seq`).
    rcv_lu: u32,
    /// L'octet urgent reçu, et son numéro (`urg_seq`).
    urgent: Urgent,
    urg_seq: u32,
    /// L'autre a fermé son sens (FIN reçu et accepté).
    fin_recue: bool,
    /// Les tailles des tampons (SO_RCVBUF, SO_SNDBUF, déjà doublées), et
    /// SO_SNDBUF fixé par le programme (`SOCK_SNDBUF_LOCK` : il ne grandit
    /// plus de lui-même).
    pub rcvbuf: usize,
    pub sndbuf: usize,
    pub sndbuf_fixe: bool,
    /// L'erreur à rendre au programme (`sk_err`), et l'erreur « douce »
    /// d'un ICMP (`sk_err_soft`), que rendra un abandon.
    erreur: i32,
    erreur_douce: i32,
    /// Plus personne ne lira (le `RCV_SHUTDOWN` de Linux : `close`, ou
    /// shutdown(SHUT_RD)) : en FIN_WAIT, des données neuves coupent la
    /// connexion (RFC 1122, 4.2.2.13).
    lecture_fermee: bool,
    /// L'heure du dernier ACK hors fenêtre ou de défi (`last_oow_ack_time`).
    dernier_ack_invalide: Option<u64>,
    /// La mémoire de TCP de toute la machine, posée par le noyau.
    pub memoire: Memoire,
    // Ce qui doit partir au prochain `emettre`.
    syn_du: bool,
    rst_du: Option<(u32, u32, u8)>,
    /// Un ACK, tout de suite.
    ack_maintenant: bool,
    /// Le premier segment non acquitté, à retransmettre (la retransmission
    /// rapide, et NewReno).
    retransmettre_tete: bool,
    /// Une sonde de fenêtre, ou de keepalive.
    sonde_due: bool,
    /// Pousser ce qui attend, une fois, malgré Nagle et TCP_CORK (le
    /// `TCP_NAGLE_PUSH` de Linux : TCP_NODELAY posé, TCP_CORK retiré).
    pousser: bool,
    /// MSG_MORE : le prochain `emettre` garde un segment incomplet (le
    /// `send` qui l'a écrit annonce une suite).
    pub plus_a_venir: bool,
    pub reglages: Reglages,
    // Le temps.
    rtt: Rtt,
    /// Le RTO courant, doublé à chaque échec (`icsk_rto`), et le nombre de
    /// doublements depuis la dernière mesure (`icsk_backoff`, qui règle
    /// aussi les sondes).
    rto: u64,
    recul: u32,
    /// Les RTO de suite sans progrès (`icsk_retransmits`), tous ceux de la
    /// connexion (`total_rto`), et toutes ses retransmissions
    /// (`total_retrans`).
    retransmissions: u32,
    total_rto: u32,
    total_retrans: u32,
    /// Depuis quand on retransmet (`retrans_stamp`) : l'heure où le
    /// minuteur de la première retransmission avait été armé.
    retrans_debut: Option<u64>,
    /// Le segment chronométré (un à la fois, RFC 6298) : la fin de sa
    /// séquence et l'heure de son envoi.
    chrono: Option<(u32, u64)>,
    /// L'échéance de la retransmission, et l'heure où elle a été armée.
    t_retrans: Option<u64>,
    t_retrans_pose: u64,
    /// L'échéance de la sonde de fenêtre, les sondes sans réponse
    /// (`icsk_probes_out`), et depuis quand on sonde (`icsk_probes_tstamp`).
    t_sonde: Option<u64>,
    sondes: u32,
    sondes_debut: Option<u64>,
    /// L'échéance du keepalive.
    t_keepalive: Option<u64>,
    ack: Ack,
    cc: Congestion,
    /// L'heure du dernier envoi de données (`lsndtime`), et du dernier
    /// ACK reçu (`rcv_tstamp`).
    dernier_envoi: u64,
    dernier_recu: u64,
}

impl<P: Charge> Tcb<P> {
    fn vide(port_local: u16, port_distant: u16, iss: u32, mss_local: u16, rcvbuf: usize, sndbuf: usize) -> Tcb<P> {
        Tcb {
            etat: Etat::Fermee,
            port_local,
            port_distant,
            fille: false,
            iss,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            snd_wnd: 0,
            snd_wl1: 0,
            max_fenetre: 0,
            echelle_envoi: 0,
            echelle_reception: 0,
            echelle_ok: false,
            snd_sml: iss,
            // Hors du mode urgent : SND.UNA une fois le SYN acquitté.
            snd_up: iss.wrapping_add(1),
            syn_acquitte: false,
            irs: 0,
            rcv_nxt: 0,
            rcv_bord: 0,
            bord_pose: false,
            mss: MSS_DEFAUT,
            mss_local,
            mss_utilisateur: 0,
            envoi: VecDeque::new(),
            decalage_envoi: 0,
            octets_envoi: 0,
            seq_envoi: iss.wrapping_add(1),
            fin_voulue: false,
            reception: VecDeque::new(),
            octets_reception: 0,
            taille_vraie_reception: 0,
            hors_ordre: HorsOrdre::new(),
            fin_hors_ordre: None,
            rcv_lu: 0,
            urgent: Urgent::Aucun,
            urg_seq: 0,
            fin_recue: false,
            rcvbuf,
            sndbuf,
            sndbuf_fixe: false,
            erreur: 0,
            erreur_douce: 0,
            lecture_fermee: false,
            dernier_ack_invalide: None,
            memoire: Memoire::Libre,
            syn_du: false,
            rst_du: None,
            ack_maintenant: false,
            retransmettre_tete: false,
            sonde_due: false,
            pousser: false,
            plus_a_venir: false,
            reglages: Reglages::DEFAUT,
            rtt: Rtt::new(),
            rto: RTO_INITIAL,
            recul: 0,
            retransmissions: 0,
            total_rto: 0,
            total_retrans: 0,
            retrans_debut: None,
            chrono: None,
            t_retrans: None,
            t_retrans_pose: 0,
            t_sonde: None,
            sondes: 0,
            sondes_debut: None,
            t_keepalive: None,
            ack: Ack::new(),
            cc: Congestion::new(),
            dernier_envoi: 0,
            dernier_recu: 0,
        }
    }

    /// Une connexion qui s'ouvre (`connect`) : SYN_SENT, le SYN à envoyer ;
    /// `echelle`, l'échelle à proposer (`echelle`).
    pub fn connecter(port_local: u16, port_distant: u16, iss: u32, mss_local: u16, rcvbuf: usize, sndbuf: usize, echelle: u8)
        -> Tcb<P> {
        let mut t = Tcb::vide(port_local, port_distant, iss, mss_local, rcvbuf, sndbuf);
        t.etat = Etat::SynEnvoye;
        t.syn_du = true;
        // L'échelle est proposée, même 0 (comme Linux) ; elle ne vaudra que
        // si l'autre la propose aussi.
        t.echelle_reception = echelle.min(ECHELLE_MAX);
        t.echelle_ok = true;
        t
    }

    /// La fille d'une écoute, pour le SYN `syn` reçu : SYN_RECEIVED, le
    /// SYN-ACK à envoyer ; `echelle`, la nôtre, si l'autre a proposé la
    /// sienne.
    pub fn depuis_syn(syn: &Tcp, iss: u32, mss_local: u16, rcvbuf: usize, sndbuf: usize, echelle: u8) -> Tcb<P> {
        let mut t = Tcb::vide(syn.destination, syn.source, iss, mss_local, rcvbuf, sndbuf);
        t.etat = Etat::SynRecu;
        t.fille = true;
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.rcv_lu = t.rcv_nxt;
        t.echelle_reception = echelle.min(ECHELLE_MAX);
        t.accepter_echelle(syn.options.echelle);
        t.snd_wnd = syn.fenetre as u32;
        t.max_fenetre = t.snd_wnd;
        t.snd_wl1 = syn.seq;
        t.mss = t.mss_effectif(syn.options.mss);
        t.annoncer();
        t.syn_du = true;
        t
    }

    pub fn etat(&self) -> Etat {
        self.etat
    }

    /// Le SYN de l'autre dit son échelle, ou rien : sans elle des deux
    /// côtés, aucune (RFC 7323 2.2) ; plus de 14, 14 (`tcp_parse_options`).
    fn accepter_echelle(&mut self, echelle: Option<u8>) {
        match echelle {
            Some(e) => {
                self.echelle_envoi = e.min(ECHELLE_MAX);
                self.echelle_ok = true;
            }
            None => {
                self.echelle_envoi = 0;
                self.echelle_reception = 0;
                self.echelle_ok = false;
            }
        }
    }

    /// SND.UNA, le plus loin envoyé (SND.MAX) et RCV.NXT (/proc/net/tcp,
    /// TIME_WAIT, les erreurs ICMP, les tests).
    pub fn numeros(&self) -> (u32, u32, u32) {
        (self.snd_una, self.snd_max, self.rcv_nxt)
    }

    /// La fenêtre de congestion et le seuil, en segments ; le RTO courant
    /// (TCP_INFO, les tests).
    pub fn congestion(&self) -> (u32, u32, u64) {
        (self.cc.cwnd, self.cc.ssthresh, self.rto)
    }

    /// Le MSS d'envoi pour ce que l'autre propose : son offre (536 s'il ne
    /// dit rien, ou dit 0 : `tcp_parse_options` l'ignore), bornée par le
    /// nôtre et par TCP_MAXSEG, et jamais sous MSS_ENVOI_MIN
    /// (`__tcp_mtu_to_mss`).
    fn mss_effectif(&self, offre: Option<u16>) -> u16 {
        let mut m = offre.filter(|&o| o != 0).unwrap_or(MSS_DEFAUT).min(self.mss_local);
        if self.mss_utilisateur != 0 {
            m = m.min(self.mss_utilisateur);
        }
        m.max(MSS_ENVOI_MIN)
    }

    /// Ce que rend TCP_MAXSEG : le MSS d'envoi une fois la connexion
    /// établie ; avant, ce qu'a demandé le programme, ou 536 (mesuré).
    pub fn mss(&self) -> u16 {
        if self.etat.synchronise() {
            self.mss
        } else if self.mss_utilisateur != 0 {
            self.mss_utilisateur
        } else {
            MSS_DEFAUT
        }
    }

    /// La taille des segments qu'on envoie : le MSS, sauf face à un
    /// récepteur minuscule, la moitié de la plus grande fenêtre qu'il ait
    /// annoncée (`tcp_bound_to_half_wnd`) : sinon un segment plein ne
    /// tiendrait jamais dans sa fenêtre, et rien ne partirait.
    fn mss_courant(&self) -> u32 {
        let mss = self.mss as u32;
        let coupure = if self.max_fenetre > MSS_DEFAUT as u32 { self.max_fenetre / 2 } else { self.max_fenetre };
        if coupure > 0 && mss > coupure { coupure.max(48) } else { mss }
    }

    // --- La réception, vue du programme ---

    /// Les octets en file de réception, l'octet urgent compris.
    pub fn lisibles(&self) -> usize {
        self.octets_reception
    }

    /// Ce que dit FIONREAD (`tcp_inq`) : rien pendant la poignée de main ;
    /// avec un octet urgent hors du flux encore devant, les octets jusqu'à
    /// lui (la lecture s'y arrête) ; sinon tout.
    pub fn lisibles_fionread(&self) -> usize {
        if matches!(self.etat, Etat::SynEnvoye | Etat::SynRecu) {
            return 0;
        }
        let devant = self.urg_seq.wrapping_sub(self.rcv_lu) as usize;
        if self.urgent != Urgent::Aucun && !self.reglages.oobinline && devant < self.octets_reception {
            devant
        } else {
            self.octets_reception
        }
    }

    /// La mémoire que garde la réception, en taille vraie : la file de
    /// lecture et la file hors d'ordre (bornées ensemble à deux fois
    /// SO_RCVBUF, voir `recevoir_donnees`).
    pub fn memoire_reception(&self) -> usize {
        self.taille_vraie_reception + self.hors_ordre.taille_vraie
    }

    /// Plus personne ne lira (`close` d'une orpheline, shutdown(SHUT_RD)).
    pub fn fermer_lecture(&mut self) {
        self.lecture_fermee = true;
    }

    /// Ceux qu'une lecture peut rendre, pour `poll` : l'octet urgent en
    /// tête, hors du flux, ne compte pas (`tcp_stream_is_readable`).
    pub fn lisibles_dans_le_flux(&self) -> usize {
        self.octets_reception - usize::from(self.a_la_marque() && !self.reglages.oobinline)
    }

    /// La lecture est-elle à la marque urgente (SIOCATMARK) ?
    pub fn a_la_marque(&self) -> bool {
        self.urgent != Urgent::Aucun && self.urg_seq == self.rcv_lu && self.octets_reception > 0
    }

    /// Un octet urgent attend-il d'être lu par MSG_OOB (POLLPRI) ?
    pub fn urgent_a_lire(&self) -> bool {
        matches!(self.urgent, Urgent::Valide(_))
    }

    /// recv(MSG_OOB) (`tcp_recv_urg`) : l'octet urgent (Some), ou rien
    /// s'il ne viendra plus (None : la fin) ; EINVAL sans octet urgent, déjà
    /// lu, ou avec SO_OOBINLINE ; EAGAIN s'il n'est pas encore arrivé.
    /// `garder` : MSG_PEEK.
    pub fn lire_urgent(&mut self, garder: bool) -> Result<Option<u8>, i32> {
        if self.reglages.oobinline || matches!(self.urgent, Urgent::Aucun | Urgent::Lu) {
            return Err(EINVAL);
        }
        if let Urgent::Valide(o) = self.urgent {
            if !garder {
                self.urgent = Urgent::Lu;
            }
            return Ok(Some(o));
        }
        if self.etat == Etat::Fermee || self.fin_recue {
            return Ok(None);
        }
        Err(EAGAIN)
    }

    /// L'autre a-t-il fermé son sens (une lecture rendra 0 après les
    /// données) ?
    pub fn fin_recue(&self) -> bool {
        self.fin_recue
    }

    /// L'erreur en attente (0 : aucune), sans l'effacer.
    pub fn erreur(&self) -> i32 {
        self.erreur
    }

    /// Prend l'erreur en attente (SO_ERROR, ou ce que rend un appel).
    pub fn prendre_erreur(&mut self) -> i32 {
        core::mem::take(&mut self.erreur)
    }

    /// L'erreur douce (d'un ICMP), que rendra un abandon.
    pub fn erreur_douce(&self) -> i32 {
        self.erreur_douce
    }

    /// Copie jusqu'à `n` octets reçus par `copier` (qui rend combien elle a
    /// copié d'un morceau, ou une erreur) ; `garder` : MSG_PEEK, rien n'est
    /// retiré. Rend le nombre d'octets copiés (moins si `copier` en prend
    /// moins). L'appelant appelle ensuite `lu` (la fenêtre).
    ///
    /// La marque urgente (`tcp_recvmsg`) : une lecture s'arrête devant elle
    /// (SIOCATMARK le dira) ; à la marque, l'octet urgent est sauté, sauf
    /// SO_OOBINLINE (MSG_OOB le lit à part).
    pub fn lire<E>(&mut self, n: usize, garder: bool, mut copier: impl FnMut(&[u8]) -> Result<usize, E>) -> Result<usize, E> {
        let mut n = n;
        let mut saut = 0;
        if self.urgent != Urgent::Aucun {
            let devant = self.urg_seq.wrapping_sub(self.rcv_lu) as usize;
            if devant == 0 && self.octets_reception > 0 {
                saut = usize::from(!self.reglages.oobinline);
            } else if devant < self.octets_reception {
                n = n.min(devant);
            }
        }
        let mut fait = 0;
        let mut i = 0;
        // Le décalage dans le premier morceau regardé (MSG_PEEK saute
        // l'octet urgent sans le retirer).
        let mut decalage = 0;
        if saut > 0 {
            if garder {
                decalage = 1;
            } else {
                self.retirer_tete(1);
            }
        }
        while fait < n && i < self.reception.len() {
            let morceau = &self.reception[i].octets()[decalage.min(self.reception[i].octets().len())..];
            decalage = 0;
            let m = morceau.len().min(n - fait);
            // Une copie qui échoue après des octets déjà pris rend ce qui a
            // été lu ; l'erreur, seulement si rien ne l'a été
            // (`tcp_recvmsg_locked`) : sans cela, ces octets seraient perdus.
            let c = match copier(&morceau[..m]) {
                Ok(c) => c,
                Err(_) if fait > 0 => break,
                Err(e) => return Err(e),
            };
            fait += c;
            if garder {
                if c < m {
                    break;
                }
                i += 1;
                continue;
            }
            self.retirer_tete(c);
            if c < m {
                break;
            }
        }
        if !garder && self.urgent != Urgent::Aucun && apres(self.rcv_lu, self.urg_seq) {
            // La marque est passée.
            self.urgent = Urgent::Aucun;
        }
        Ok(fait)
    }

    /// Retire `n` octets lus du début de la file de réception.
    fn retirer_tete(&mut self, mut n: usize) {
        while n > 0 {
            let Some(p) = self.reception.front_mut() else { break };
            let m = n.min(p.octets().len());
            p.avancer(m);
            n -= m;
            self.octets_reception -= m;
            self.rcv_lu = self.rcv_lu.wrapping_add(m as u32);
            if p.octets().is_empty()
                && let Some(p) = self.reception.pop_front()
            {
                self.taille_vraie_reception = self.taille_vraie_reception.saturating_sub(p.taille_vraie());
            }
        }
    }

    /// Jette jusqu'à `n` octets reçus (MSG_TRUNC de TCP) ; rend combien.
    pub fn jeter(&mut self, n: usize) -> usize {
        self.lire::<()>(n, false, |m| Ok(m.len())).unwrap_or(0)
    }

    /// La place libre de la réception, en taille vraie (la file hors
    /// d'ordre compte, comme chez Linux).
    fn libre(&self) -> usize {
        self.rcvbuf.saturating_sub(self.taille_vraie_reception + self.hors_ordre.taille_vraie)
    }

    /// La plus grande fenêtre qu'on puisse annoncer (`window_clamp`) : sans
    /// échelle, 65 535.
    fn fenetre_max(&self) -> u32 {
        ((self.rcvbuf / 2) as u32).min(FENETRE_MAX << self.echelle_reception)
    }

    /// La fenêtre que permet la place libre : la moitié (le `scaling_ratio`
    /// de Linux à sa valeur de départ, 50 % : une charge reçue occupe à peu
    /// près le double de ses octets en mémoire), au plus `fenetre_max` ;
    /// moins d'un MSS : 0 (le récepteur n'annonce pas de petite fenêtre, RFC
    /// 9293 3.8.6.2.2, le SWS).
    fn fenetre_possible(&self) -> u32 {
        let f = ((self.libre() / 2) as u32).min(FENETRE_MAX << self.echelle_reception);
        if f < self.mss_local as u32 && f < (self.rcvbuf / 4) as u32 { 0 } else { f }
    }

    /// Pose le bord droit annoncé, sans jamais le reculer ; avec l'échelle,
    /// la fenêtre arrondie au multiple supérieur de son unité (sinon le
    /// décalage la tronquerait, et le bord reculerait : le `ALIGN` de
    /// `tcp_select_window`).
    fn annoncer(&mut self) {
        let bord = self.rcv_nxt.wrapping_add(self.fenetre_possible());
        if !self.bord_pose || apres(bord, self.rcv_bord) {
            self.rcv_bord = bord;
            self.bord_pose = true;
        }
        if avant(self.rcv_bord, self.rcv_nxt) {
            self.rcv_bord = self.rcv_nxt;
        }
        let e = self.echelle_reception;
        let w = self.rcv_bord.wrapping_sub(self.rcv_nxt);
        self.rcv_bord = self.rcv_nxt.wrapping_add(w.div_ceil(1 << e) << e);
    }

    /// La fenêtre à annoncer dans un segment (hors SYN), décalée de notre
    /// échelle.
    fn fenetre(&self) -> u16 {
        (self.rcv_bord.wrapping_sub(self.rcv_nxt) >> self.echelle_reception).min(FENETRE_MAX) as u16
    }

    /// Le programme a lu (`tcp_cleanup_rbuf`) : un ACK part tout de suite
    /// si un ACK dû attend plus d'un segment plein (`verifier_ack` l'avait
    /// retardé parce que la fenêtre n'avançait pas), ou si la fenêtre
    /// qu'on pourrait annoncer a au moins doublé depuis la dernière
    /// annonce (sans cela, un émetteur bloqué par une fenêtre nulle
    /// attendrait sa prochaine sonde).
    pub fn lu(&mut self) -> Effets {
        if !self.etat.synchronise() && self.etat != Etat::SynRecu {
            return Effets::default();
        }
        let mut tout_de_suite = self.ack.programme && self.rcv_nxt.wrapping_sub(self.ack.rcv_wup) > self.ack.rcv_mss;
        if !tout_de_suite && !self.fin_recue {
            let annoncee = self.rcv_bord.wrapping_sub(self.rcv_nxt);
            let possible = self.fenetre_possible();
            if 2 * annoncee <= self.fenetre_max() && possible > 0 && possible >= 2 * annoncee {
                self.annoncer();
                tout_de_suite = true;
            }
        }
        let mut e = Effets::default();
        if tout_de_suite {
            self.ack_maintenant = true;
            e.a_emettre = true;
        }
        e
    }

    // --- L'émission, vue du programme ---

    /// La place libre du tampon d'émission, en octets.
    pub fn place(&self) -> usize {
        if self.memoire == Memoire::Limite && self.octets_envoi > 0 {
            return 0;
        }
        self.sndbuf.saturating_sub(self.octets_envoi)
    }

    /// La mémoire que garde la connexion, en octets : la réception (en
    /// taille vraie) et ce qui attend d'être acquitté (le compte de
    /// `tcp_mem`).
    pub fn memoire(&self) -> usize {
        self.memoire_reception() + self.octets_envoi
    }

    /// Les octets pas encore acquittés (SIOCOUTQ), et pas encore envoyés
    /// (SIOCOUTQNSD).
    pub fn non_acquittes(&self) -> usize {
        self.octets_envoi
    }

    pub fn non_envoyes(&self) -> usize {
        self.octets_envoi.saturating_sub(self.envoyes())
    }

    /// Les octets du tampon déjà envoyés au moins une fois (de son début à
    /// SND.MAX, sans le FIN).
    fn envoyes(&self) -> usize {
        if apres(self.snd_max, self.seq_envoi) {
            (self.snd_max.wrapping_sub(self.seq_envoi) as usize).min(self.octets_envoi)
        } else {
            0
        }
    }

    /// Le numéro de notre FIN, s'il est voulu : juste après les données.
    fn fin_seq(&self) -> Option<u32> {
        self.fin_voulue.then(|| self.seq_envoi.wrapping_add(self.octets_envoi as u32))
    }

    /// Ajoute jusqu'à `n` octets au tampon d'émission, remplis par
    /// `remplir` (qui copie depuis le programme), dans la limite de la
    /// place ; rend combien. Moins si la mémoire manque (0 : rien n'a pu
    /// être ajouté). Le programme ne doit plus écrire après `fermer_envoi`.
    pub fn ecrire<E>(&mut self, n: usize, mut remplir: impl FnMut(&mut [u8]) -> Result<(), E>) -> Result<usize, E> {
        let n = n.min(self.place());
        let mut fait = 0;
        while fait < n {
            let dernier_plein = self.envoi.back().is_none_or(|b| b.len() >= BLOC);
            if dernier_plein {
                let mut b = Vec::new();
                if b.try_reserve_exact((n - fait).min(BLOC)).is_err() {
                    break;
                }
                if self.envoi.try_reserve(1).is_err() {
                    break;
                }
                self.envoi.push_back(b);
            }
            let b = self.envoi.back_mut().expect("un bloc");
            let m = (BLOC - b.len()).min(n - fait);
            if b.try_reserve(m).is_err() {
                break;
            }
            let debut = b.len();
            b.resize(debut + m, 0);
            if let Err(e) = remplir(&mut b[debut..]) {
                b.truncate(debut);
                if b.is_empty() {
                    self.envoi.pop_back();
                }
                return if fait == 0 { Err(e) } else { Ok(fait) };
            }
            fait += m;
            self.octets_envoi += m;
        }
        Ok(fait)
    }

    /// Copie dans `o` les octets du tampon d'émission à partir du décalage
    /// `debut` (celui d'un `Sortant`).
    pub fn copier_envoi(&self, mut debut: usize, o: &mut [u8]) {
        debut += self.decalage_envoi;
        let mut fait = 0;
        for b in &self.envoi {
            if debut >= b.len() {
                debut -= b.len();
                continue;
            }
            let m = (b.len() - debut).min(o.len() - fait);
            o[fait..fait + m].copy_from_slice(&b[debut..debut + m]);
            fait += m;
            debut = 0;
            if fait == o.len() {
                break;
            }
        }
    }

    /// Retire `n` octets acquittés du début du tampon d'émission.
    fn acquitter_octets(&mut self, mut n: usize) {
        n = n.min(self.octets_envoi);
        self.octets_envoi -= n;
        self.seq_envoi = self.seq_envoi.wrapping_add(n as u32);
        while n > 0 {
            let Some(b) = self.envoi.front() else { break };
            let reste = b.len() - self.decalage_envoi;
            if n >= reste {
                n -= reste;
                self.envoi.pop_front();
                self.decalage_envoi = 0;
            } else {
                self.decalage_envoi += n;
                n = 0;
            }
        }
    }

    /// Le programme ne veut plus écrire (`shutdown(SHUT_WR)`, ou `close`) :
    /// un FIN partira après les données (`tcp_shutdown`, `tcp_close_state`).
    pub fn fermer_envoi(&mut self) -> Effets {
        let mut e = Effets::default();
        match self.etat {
            Etat::Etablie | Etat::SynRecu => self.passer(Etat::FinAttente1, &mut e),
            Etat::AttenteFermeture => self.passer(Etat::DernierAck, &mut e),
            Etat::SynEnvoye => {
                // Rien n'est parti que le SYN : la connexion se ferme
                // (`tcp_close` : CLOSE depuis SYN_SENT).
                self.passer(Etat::Fermee, &mut e);
                return e;
            }
            _ => return e,
        }
        self.fin_voulue = true;
        e.a_emettre = true;
        e
    }

    /// Un ACK hors fenêtre ou de défi doit-il attendre (le précédent date de
    /// moins de 500 ms) ? Sinon, l'heure de celui-ci est retenue
    /// (`__tcp_oow_rate_limited`).
    fn ack_invalide_limite(&mut self, maintenant: u64) -> bool {
        if let Some(d) = self.dernier_ack_invalide
            && maintenant.saturating_sub(d) < LIMITE_ACK_INVALIDE
        {
            return true;
        }
        self.dernier_ack_invalide = Some(maintenant);
        false
    }

    /// Coupe la connexion (SO_LINGER 0, `close` avec des données non lues,
    /// `connect(AF_UNSPEC)`) : un RST, si la connexion était synchronisée,
    /// puis fermée (`tcp_disconnect`, `tcp_send_active_reset`). Son numéro
    /// est le plus loin qu'on soit allé, celui qu'attend l'autre (le
    /// `tcp_acceptable_seq` de Linux).
    pub fn avorter(&mut self) -> Effets {
        let mut e = Effets::default();
        if matches!(self.etat, Etat::Etablie | Etat::AttenteFermeture | Etat::FinAttente1 | Etat::FinAttente2 | Etat::SynRecu) {
            self.rst_du = Some((self.snd_max, self.rcv_nxt, tcp::RST | tcp::ACK));
            e.a_emettre = true;
        }
        self.passer(Etat::Fermee, &mut e);
        e
    }

    fn passer(&mut self, etat: Etat, e: &mut Effets) {
        if self.etat != etat {
            self.etat = etat;
            e.etat = true;
            e.lisible = true;
            e.place = true;
        }
        if matches!(etat, Etat::Fermee | Etat::TempsAttente) {
            // Plus rien à retransmettre, à sonder ni à acquitter plus tard :
            // TIME_WAIT réacquitte ce qui revient, tout de suite.
            self.t_retrans = None;
            self.t_sonde = None;
            self.t_keepalive = None;
            self.ack.t = None;
            self.hors_ordre.vider();
            self.fin_hors_ordre = None;
        }
    }

    /// Une erreur qui ferme la connexion (`tcp_done_with_error`) : ce qui
    /// restait à envoyer est jeté (`tcp_write_queue_purge`) ; ce qui a été
    /// reçu se lit encore (mesuré).
    fn finir(&mut self, erreur: i32, e: &mut Effets) {
        self.erreur = erreur;
        self.envoi.clear();
        self.decalage_envoi = 0;
        self.octets_envoi = 0;
        self.passer(Etat::Fermee, e);
        e.lisible = true;
        e.place = true;
    }

    // --- Les segments reçus ---

    /// La fenêtre de réception annoncée (`tw_rcv_wnd` d'une entrée de
    /// TIME_WAIT).
    pub fn fenetre_annoncee(&self) -> u32 {
        self.rcv_wnd()
    }

    /// Ce qui reste de la fenêtre annoncée tient-il en un segment de
    /// l'autre (`tcp_receive_window(tp) <= icsk_ack.rcv_mss`) ? Alors poll
    /// dit POLLIN même sous SO_RCVLOWAT : l'autre ne peut plus rien envoyer
    /// avant qu'on lise.
    pub fn fenetre_presque_fermee(&self) -> bool {
        self.rcv_wnd() <= self.ack.rcv_mss
    }

    /// La fenêtre de réception, pour l'acceptabilité.
    fn rcv_wnd(&self) -> u32 {
        self.rcv_bord.wrapping_sub(self.rcv_nxt)
    }

    /// Un segment est-il acceptable (RFC 9293, 3.10.7.4, le tableau des
    /// quatre cas) ?
    fn acceptable(&self, seq: u32, longueur: u32) -> bool {
        let wnd = self.rcv_wnd();
        let dans = |s: u32| !avant(s, self.rcv_nxt) && avant(s, self.rcv_nxt.wrapping_add(wnd));
        match (longueur, wnd) {
            (0, 0) => seq == self.rcv_nxt,
            (0, _) => dans(seq),
            (_, 0) => false,
            _ => dans(seq) || dans(seq.wrapping_add(longueur - 1)),
        }
    }

    /// Reçoit le segment `t`, de charge `charge` (vide pour un segment sans
    /// données), à l'heure `maintenant`, dans l'ordre de la RFC 9293
    /// (3.10.7) et de `tcp_rcv_state_process`.
    pub fn recevoir(&mut self, t: &Tcp, charge: P, maintenant: u64) -> Effets {
        let mut e = Effets::default();
        let longueur_charge = charge.octets().len() as u32;
        let syn = t.drapeaux & tcp::SYN != 0;
        let fin = t.drapeaux & tcp::FIN != 0;
        let rst = t.drapeaux & tcp::RST != 0;
        let ack = t.drapeaux & tcp::ACK != 0;
        match self.etat {
            Etat::Fermee => {
                // Une connexion fermée n'a plus de table : le noyau répond
                // lui-même (RST).
                return e;
            }
            Etat::SynEnvoye => {
                // 3.10.7.3 : d'abord l'ACK.
                if ack && (!apres(t.ack, self.iss) || apres(t.ack, self.snd_max)) {
                    if !rst {
                        self.rst_du = Some((t.ack, 0, tcp::RST));
                        e.a_emettre = true;
                    }
                    return e;
                }
                if rst {
                    // Un RST qui acquitte notre SYN : refusé.
                    if ack {
                        self.finir(ECONNREFUSED, &mut e);
                    }
                    return e;
                }
                if !syn {
                    return e;
                }
                self.irs = t.seq;
                self.rcv_nxt = t.seq.wrapping_add(1);
                self.rcv_lu = self.rcv_nxt;
                self.mss = self.mss_effectif(t.options.mss);
                self.accepter_echelle(t.options.echelle);
                self.bord_pose = false;
                self.annoncer();
                self.dernier_recu = maintenant;
                if ack {
                    self.snd_una = t.ack;
                    self.syn_acquitte = true;
                    if apres(self.snd_una, self.snd_nxt) {
                        self.snd_nxt = self.snd_una;
                    }
                    self.snd_wnd = t.fenetre as u32;
                    self.max_fenetre = self.snd_wnd;
                    self.snd_wl1 = t.seq;
                    self.mesurer(t.ack, maintenant);
                    self.retransmissions = 0;
                    self.retrans_debut = None;
                    self.t_retrans = None;
                    self.passer(Etat::Etablie, &mut e);
                    self.etablir(maintenant);
                    // L'ACK de la poignée de main part tout de suite.
                    self.ack_maintenant = true;
                    e.a_emettre = true;
                    e.place = true;
                } else {
                    // L'ouverture simultanée : SYN_RECEIVED, et notre SYN
                    // repart avec un ACK.
                    self.passer(Etat::SynRecu, &mut e);
                    self.syn_du = true;
                    e.a_emettre = true;
                }
                // Des données dans le SYN-ACK : Linux les garde ; ici
                // (rare), elles seront redemandées par l'ACK.
                return e;
            }
            _ => {}
        }
        // TIME_WAIT : un FIN retransmis est réacquitté ; un RST l'efface
        // (`tcp_timewait_state_process`, rfc1337 à 0).
        // L'ouverture simultanée : en SYN_RECEIVED, le SYN-ACK de l'autre,
        // qui acquitte notre SYN, vaut un ACK (son SYN déjà reçu est
        // ignoré : le `goto pass` de `tcp_validate_incoming`).
        let mut syn = syn;
        let mut seq = t.seq;
        if self.etat == Etat::SynRecu && syn && ack && t.seq.wrapping_add(1) == self.rcv_nxt && t.ack == self.snd_max {
            syn = false;
            seq = self.rcv_nxt;
        }
        // 1. Le numéro de séquence. Hors de la fenêtre : un ACK, tout de
        // suite (`tcp_send_dupack`) ; des données déjà reçues disent que
        // notre ACK s'est perdu : le mode « quickack ».
        // Un ACK hors fenêtre ou de défi part au plus toutes les 500 ms, sauf
        // pour un segment qui porte des données (sans SYN) : lui ne fait pas
        // partie d'une boucle d'ACK (`tcp_oow_rate_limited`).
        let longueur = longueur_charge + u32::from(syn) + u32::from(fin);
        if !self.acceptable(seq, longueur) {
            if !rst {
                if longueur_charge > 0 && avant(seq, self.rcv_nxt) {
                    self.entrer_mode_rapide();
                }
                if (longueur > 0 && !syn) || !self.ack_invalide_limite(maintenant) {
                    self.ack_maintenant = true;
                    e.a_emettre = true;
                }
            }
            return e;
        }
        // 2. RST (RFC 5961 : exactement au bord gauche ; sinon, dans la
        // fenêtre, un ACK « de défi », limité comme ci-dessus).
        if rst {
            if t.seq != self.rcv_nxt {
                if !self.ack_invalide_limite(maintenant) {
                    self.ack_maintenant = true;
                    e.a_emettre = true;
                }
                return e;
            }
            let erreur = match self.etat {
                Etat::SynRecu | Etat::Fermeture | Etat::DernierAck | Etat::TempsAttente => 0,
                Etat::AttenteFermeture => EPIPE,
                _ => ECONNRESET,
            };
            if self.etat == Etat::SynRecu {
                // La fille d'une écoute : elle disparaît, sans erreur
                // (l'écoute ne l'avait pas encore donnée).
                self.passer(Etat::Fermee, &mut e);
            } else {
                self.finir(erreur, &mut e);
                if erreur == 0 {
                    self.erreur = 0;
                }
            }
            return e;
        }
        // 4. SYN dans une connexion synchronisée : un ACK de défi (RFC 5961,
        // 4.2) ; en SYN_RECEIVED, un SYN retransmis : notre SYN-ACK repart
        // (et ne se mesure plus : Karn).
        if syn {
            if self.etat == Etat::SynRecu && t.seq.wrapping_add(1) == self.rcv_nxt {
                self.syn_du = true;
                self.chrono = None;
                e.a_emettre = true;
            } else if !self.ack_invalide_limite(maintenant) {
                self.ack_maintenant = true;
                e.a_emettre = true;
            }
            return e;
        }
        // 5. ACK.
        if !ack {
            return e;
        }
        let etablissement = self.etat == Etat::SynRecu;
        if etablissement {
            if apres(t.ack, self.snd_una) && !apres(t.ack, self.snd_max) {
                self.passer(Etat::Etablie, &mut e);
                // Un SYN-ACK qui n'était pas encore parti (l'ouverture
                // simultanée) : notre SYN est acquitté, un ACK suffit.
                if core::mem::take(&mut self.syn_du) {
                    self.ack_maintenant = true;
                    e.a_emettre = true;
                }
            } else {
                self.rst_du = Some((t.ack, 0, tcp::RST));
                e.a_emettre = true;
                return e;
            }
        }
        if !self.traiter_ack(t, longueur_charge > 0 || fin, maintenant, &mut e) {
            return e;
        }
        if etablissement {
            self.etablir(maintenant);
        }
        if self.etat == Etat::Fermee {
            return e;
        }
        // 6. URG (`tcp_urg`) : un pointeur urgent neuf, puis l'octet qu'il
        // désigne, quand il arrive (dans ce segment, ou un suivant).
        if t.drapeaux & tcp::URG != 0 && self.etat.recoit() {
            self.pointeur_urgent(t.urgent, seq);
        }
        if self.urgent == Urgent::Attendu
            && let Some(&o) = charge.octets().get(self.urg_seq.wrapping_sub(seq) as usize)
        {
            self.urgent = Urgent::Valide(o);
            e.lisible = true;
        }
        // 7. Le texte. Pour une lecture fermée, en FIN_WAIT, des données
        // neuves coupent la connexion : RST, comme BSD et Linux (« RFC 793
        // says to queue data in these states, RFC 1122 says we MUST send a
        // reset », `tcp_rcv_state_process`) ; l'autre apprend que ce qu'il
        // envoie ne sera jamais lu.
        if self.lecture_fermee
            && matches!(self.etat, Etat::FinAttente1 | Etat::FinAttente2)
            && longueur_charge > 0
            && apres(seq.wrapping_add(longueur_charge), self.rcv_nxt)
        {
            self.rst_du = Some((t.ack, 0, tcp::RST));
            self.finir(ECONNRESET, &mut e);
            e.a_emettre = true;
            return e;
        }
        if longueur_charge > 0 && self.etat.recoit() {
            self.recevoir_donnees(seq, charge, maintenant, &mut e);
        }
        // 8. FIN, s'il arrive à son tour ; après un trou, il attend que le
        // trou se comble.
        if fin && self.etat.recoit() {
            let position = seq.wrapping_add(longueur_charge);
            if position == self.rcv_nxt {
                self.recevoir_fin(&mut e);
            } else if apres(position, self.rcv_nxt) {
                self.fin_hors_ordre = Some(position);
                self.ack_maintenant = true;
            }
        }
        if self.fin_hors_ordre == Some(self.rcv_nxt) && self.etat.recoit() {
            self.fin_hors_ordre = None;
            self.recevoir_fin(&mut e);
        }
        self.verifier_ack(maintenant);
        if self.ack_maintenant {
            e.a_emettre = true;
        }
        self.annoncer();
        e
    }

    /// L'ACK d'un segment acceptable (`tcp_ack`) : la fenêtre de l'autre,
    /// ce qui est acquitté, la mesure du RTT, le minuteur de
    /// retransmission, la congestion. Rend faux si le segment doit s'arrêter
    /// là. `porte` : le segment porte des données ou un FIN (ce n'est pas
    /// un ACK dupliqué).
    fn traiter_ack(&mut self, t: &Tcp, porte: bool, maintenant: u64, e: &mut Effets) -> bool {
        if apres(t.ack, self.snd_max) {
            // Il acquitte ce qui n'a jamais été envoyé : ACK, et rien
            // d'autre (RFC 9293).
            self.ack_maintenant = true;
            e.a_emettre = true;
            return false;
        }
        let una_avant = self.snd_una;
        if avant(t.ack, una_avant) {
            // Un vieil ACK (dépassé par un autre) : rien à en tirer.
            return true;
        }
        let rien_en_vol = self.snd_max == una_avant;
        let avance = apres(t.ack, una_avant);
        // La fenêtre de l'autre (`tcp_may_update_window`) : d'un segment
        // plus récent que celui qui l'a donnée la dernière fois ; décalée
        // de son échelle (jamais dans un SYN : ce segment n'en est pas un).
        let fenetre = (t.fenetre as u32) << self.echelle_envoi;
        let maj_fenetre = avance || apres(t.seq, self.snd_wl1) || (t.seq == self.snd_wl1 && (fenetre > self.snd_wnd || fenetre == 0));
        if maj_fenetre {
            if self.snd_wnd == 0 && fenetre != 0 {
                e.a_emettre = true;
            }
            self.snd_wnd = fenetre;
            self.snd_wl1 = t.seq;
            self.max_fenetre = self.max_fenetre.max(fenetre);
        }
        let acquittes = t.ack.wrapping_sub(una_avant);
        if avance {
            self.acquitter_jusqu_a(t.ack, e);
            // Le mode urgent finit quand l'octet urgent est acquitté.
            if !avant(self.snd_up, una_avant) && !apres(self.snd_up, t.ack) {
                self.snd_up = t.ack;
            }
            self.retransmissions = 0;
            self.retrans_debut = None;
            self.mesurer(t.ack, maintenant);
            // Le minuteur repart de maintenant (RFC 6298 5.3), ou s'arrête.
            if self.snd_max == self.snd_una {
                self.t_retrans = None;
            } else {
                self.armer_rto(maintenant);
            }
            e.place = true;
            e.a_emettre = true;
        }
        // Quelque chose est revenu : l'erreur douce d'un ICMP ne vaut plus,
        // les sondes ont une réponse.
        self.erreur_douce = 0;
        self.sondes = 0;
        self.dernier_recu = maintenant;
        if rien_en_vol {
            self.ack_de_sonde(maintenant);
            return true;
        }
        let dupack = !avance && !porte && !maj_fenetre;
        self.controler_congestion(avance, acquittes, dupack);
        // De la place libérée, et la fenêtre de congestion n'est pas pleine :
        // SO_SNDBUF suit (`tcp_new_space`).
        if avance && self.paquets_en_vol() < self.cc.cwnd {
            self.agrandir_sndbuf();
        }
        true
    }

    /// SO_SNDBUF agrandi pour deux fenêtres de congestion de segments
    /// pleins, chacun compté avec sa place dans la mémoire du noyau, comme
    /// Linux (`tcp_sndbuf_expand` : le MSS plus 640 octets d'en-têtes et de
    /// structures, arrondi à la puissance de deux, plus 256 ; au moins 10
    /// segments ; au plus `tcp_wmem[2]`, 4 Mio). Sur `lo` (MSS 65 495) : 2 626 560
    /// (mesuré chez Linux). Rien si le programme a fixé SO_SNDBUF.
    fn agrandir_sndbuf(&mut self) {
        if self.sndbuf_fixe || self.memoire != Memoire::Libre {
            return;
        }
        let par_segment = (self.mss as usize + 640).next_power_of_two() + 256;
        let segments = (self.cc.cwnd.max(CWND_INITIALE).max(REORDONNANCEMENT + 1)) as usize;
        let voulu = (2 * segments * par_segment).min(SNDBUF_MAX);
        if self.sndbuf < voulu {
            self.sndbuf = voulu;
        }
    }

    /// SND.UNA avance jusqu'à `ack` : le SYN, les octets, le FIN acquittés.
    fn acquitter_jusqu_a(&mut self, ack: u32, e: &mut Effets) {
        let mut n = ack.wrapping_sub(self.snd_una) as usize;
        if !self.syn_acquitte {
            // Le SYN compte pour un, pas dans le tampon.
            self.syn_acquitte = true;
            n -= 1;
        }
        let fin_acquitte = self.fin_seq().is_some_and(|f| apres(ack, f));
        if fin_acquitte {
            n = n.saturating_sub(1);
        }
        self.acquitter_octets(n);
        self.snd_una = ack;
        if apres(ack, self.snd_nxt) {
            // Après un RTO, un ACK de ce qui était parti avant.
            self.snd_nxt = ack;
        }
        if fin_acquitte {
            match self.etat {
                Etat::FinAttente1 => self.passer(Etat::FinAttente2, e),
                Etat::Fermeture => self.passer(Etat::TempsAttente, e),
                Etat::DernierAck => self.passer(Etat::Fermee, e),
                _ => {}
            }
        }
    }

    /// Le segment chronométré est-il acquitté ? Alors une mesure du RTT
    /// (`tcp_ack_update_rtt`), et le RTO repart de l'estimateur, sans recul
    /// (RFC 6298 5.7 : seulement sur une vraie mesure).
    fn mesurer(&mut self, ack: u32, maintenant: u64) {
        if let Some((fin, envoi)) = self.chrono
            && !avant(ack, fin)
        {
            self.chrono = None;
            self.rtt.echantillon(maintenant.saturating_sub(envoi), self.snd_una, self.snd_nxt);
            self.rto = self.rtt.rto();
            self.recul = 0;
        }
    }

    /// La poignée de main est finie (`tcp_init_transfer`) : sans mesure du
    /// RTT (le SYN retransmis), le RTO de 3 s ; la fenêtre de congestion de
    /// départ, d'un segment seulement si le SYN a dû être renvoyé plus
    /// d'une fois.
    fn etablir(&mut self, maintenant: u64) {
        if self.rtt.mesure() {
            self.rto = self.rtt.rto();
        } else {
            self.rtt.repli();
            self.rto = RTO_REPLI;
        }
        self.cc.cwnd = if self.total_retrans > 1 { 1 } else { CWND_INITIALE };
        // La perte du SYN est réparée ; le seuil, lui, garde sa moitié
        // (Linux aussi).
        if self.cc.phase == Phase::Perte {
            self.cc.phase = Phase::Ouverte;
        }
        self.dernier_envoi = maintenant;
        // `tcp_initialize_rcv_mss` : au plus 536 avant d'avoir vu un segment.
        let rcv_wnd = self.rcv_wnd();
        self.ack.rcv_mss = (self.mss_local as u32)
            .min(self.mss as u32)
            .min(rcv_wnd / 2)
            .min(MSS_DEFAUT as u32)
            .max(MSS_MIN as u32);
        self.ack.rcv_wup = self.rcv_nxt;
        self.ack.fenetre = rcv_wnd;
        // `tcp_init_buffer_space` ; et le keepalive, s'il est demandé.
        self.agrandir_sndbuf();
        if self.reglages.keepalive {
            self.t_keepalive = Some(maintenant + self.reglages.keepidle);
        }
    }

    /// Change les réglages (setsockopt) : TCP_NODELAY posé ou TCP_CORK
    /// retiré poussent ce qui attend (`__tcp_sock_set_nodelay`,
    /// `__tcp_sock_set_cork`) ; SO_KEEPALIVE arme ou arrête le keepalive
    /// (`tcp_set_keepalive`), TCP_KEEPIDLE le recale sur le dernier
    /// segment reçu (`tcp_sock_set_keepidle_locked`).
    pub fn regler(&mut self, r: Reglages, maintenant: u64) -> Effets {
        let ancien = core::mem::replace(&mut self.reglages, r);
        let mut e = Effets::default();
        if (r.nodelay && !ancien.nodelay) || (ancien.cork && !r.cork) {
            self.pousser = true;
            e.a_emettre = true;
        }
        let vivante = !matches!(self.etat, Etat::Fermee | Etat::SynEnvoye | Etat::SynRecu | Etat::TempsAttente);
        if !r.keepalive || !vivante {
            self.t_keepalive = None;
        } else if !ancien.keepalive {
            self.t_keepalive = Some(maintenant + r.keepidle);
        } else if r.keepidle != ancien.keepidle {
            let ecoule = maintenant.saturating_sub(self.ack.lrcvtime.max(self.dernier_recu));
            self.t_keepalive = Some(maintenant + r.keepidle.saturating_sub(ecoule));
        }
        e
    }

    /// TCP_QUICKACK (`__tcp_sock_set_quickack`) : 1 quitte le ping-pong et
    /// envoie tout de suite un ACK dû ; 0 entre en ping-pong.
    pub fn quickack(&mut self, oui: bool) -> Effets {
        let mut e = Effets::default();
        if oui {
            self.ack.pingpong = 0;
            if self.ack.programme {
                self.ack_maintenant = true;
                e.a_emettre = true;
            }
        } else {
            self.ack.pingpong = self.ack.pingpong.max(1);
        }
        e
    }

    /// send(MSG_OOB) (`tcp_mark_urg`) : le dernier octet écrit est urgent ;
    /// le pointeur urgent le suit.
    pub fn marquer_urgent(&mut self) {
        self.snd_up = self.seq_envoi.wrapping_add(self.octets_envoi as u32);
    }

    /// Le mode urgent : un octet urgent pas encore acquitté
    /// (`tcp_urg_mode`).
    fn mode_urgent(&self) -> bool {
        self.snd_up != self.snd_una
    }

    /// Ce que rendent TCP_INFO et /proc/net/tcp (`tcp_get_info`).
    pub fn info(&self, maintenant: u64) -> Info {
        let us = |ns: u64| (ns / 1000).min(u32::MAX as u64) as u32;
        let ms = |depuis: u64| (maintenant.saturating_sub(depuis) / 1_000_000).min(u32::MAX as u64) as u32;
        let echelle = self.etat.synchronise() && self.echelle_ok;
        Info {
            etat: self.etat.linux(),
            phase: match self.cc.phase {
                Phase::Ouverte => 0,
                Phase::Desordre => 1,
                Phase::Reprise => 3,
                Phase::Perte => 4,
            },
            retransmissions: self.retransmissions.min(255) as u8,
            sondes: self.sondes.min(255) as u8,
            recul: self.recul.min(255) as u8,
            options: if echelle { 4 } else { 0 },
            echelle_envoi: if echelle { self.echelle_envoi } else { 0 },
            echelle_reception: if echelle { self.echelle_reception } else { 0 },
            rto: us(self.rto),
            ato: us(self.ack.ato),
            snd_mss: self.mss_courant(),
            rcv_mss: self.ack.rcv_mss,
            non_acquittes: self.paquets_sortis(),
            retransmis: u32::from(self.retransmettre_tete || avant(self.snd_nxt, self.snd_max)),
            dernier_envoi: ms(self.dernier_envoi),
            dernier_recu: ms(self.ack.lrcvtime),
            dernier_ack: ms(self.dernier_recu),
            rtt: us(self.rtt.srtt()),
            rttvar: us(self.rtt.ecart()),
            ssthresh: self.cc.ssthresh,
            cwnd: self.cc.cwnd,
            advmss: self.mss_local as u32,
            reordonnancement: REORDONNANCEMENT,
            total_retrans: self.total_retrans,
            t_retrans: self.t_retrans.or(self.t_sonde).map(|t| t.saturating_sub(maintenant)),
            sonde: self.t_retrans.is_none() && self.t_sonde.is_some(),
            t_keepalive: self.t_keepalive.map(|t| t.saturating_sub(maintenant)),
            ack_rapides: self.ack.rapides,
            pingpong: self.ack.pingpong > 0,
            demarrage_lent: self.cc.ssthresh >= congestion::SSTHRESH_INFINI,
        }
    }

    /// Les segments en vol, estimés : les octets de SND.UNA à SND.NXT
    /// divisés par le MSS (exact pour des segments pleins ; Nagle ne laisse
    /// pas plus d'un petit segment en vol).
    fn paquets_sortis(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una).div_ceil(self.mss.max(1) as u32)
    }

    /// Ceux qui sont encore dans le réseau (`tcp_packets_in_flight`) : sans
    /// ceux que les ACK dupliqués disent arrivés, ni la tête perdue tant
    /// qu'elle n'est pas renvoyée.
    fn paquets_en_vol(&self) -> u32 {
        let sortis = self.paquets_sortis();
        let arrives = self.cc.dupacks.min(sortis.saturating_sub(1));
        (sortis - arrives).saturating_sub(u32::from(self.retransmettre_tete))
    }

    /// Un ACK dupliqué de plus, au plus un de moins que les segments en vol
    /// (`tcp_limit_reno_sacked` : il en manque au moins un).
    fn ajouter_dupack(&mut self) {
        self.cc.dupacks = (self.cc.dupacks + 1).min(self.paquets_sortis().saturating_sub(1));
    }

    /// La congestion après un ACK (`tcp_fastretrans_alert`, `tcp_cong_control`,
    /// pour Reno) : `acquittes` octets de plus acquittés, ou un ACK
    /// dupliqué.
    fn controler_congestion(&mut self, avance: bool, acquittes: u32, dupack: bool) {
        let segments = acquittes.div_ceil(self.mss.max(1) as u32);
        let couvert = self.cc.point.is_some_and(|p| !avant(self.snd_una, p));
        match self.cc.phase {
            Phase::Perte => {
                if avance && couvert {
                    self.cc.phase = Phase::Ouverte;
                    self.cc.dupacks = 0;
                }
                if avance {
                    self.cc.croitre(segments);
                }
            }
            Phase::Reprise => {
                if avance && couvert {
                    self.cc.finir_reprise();
                } else if avance {
                    // Un ACK partiel : la perte suivante est là (NewReno),
                    // renvoyée aussitôt ; les ACK dupliqués comptés pour ce
                    // que celui-ci couvre ne comptent plus.
                    let livres = segments.saturating_sub(self.cc.dupacks).max(1);
                    self.cc.dupacks -= self.cc.dupacks.min(segments - 1);
                    self.retransmettre_tete = true;
                    let en_vol = self.paquets_en_vol();
                    self.cc.prr(livres, 1, true, en_vol);
                } else if dupack {
                    self.ajouter_dupack();
                    let en_vol = self.paquets_en_vol();
                    self.cc.prr(1, 0, false, en_vol);
                }
            }
            Phase::Ouverte | Phase::Desordre => {
                if dupack {
                    self.ajouter_dupack();
                    if self.cc.dupacks >= REORDONNANCEMENT && self.cc.entrer_reprise(self.snd_una, self.snd_max) {
                        // La retransmission rapide.
                        self.retransmettre_tete = true;
                        self.chrono = None;
                        let en_vol = self.paquets_en_vol();
                        self.cc.prr(1, 1, false, en_vol);
                    } else if self.cc.dupacks > 0 {
                        self.cc.phase = Phase::Desordre;
                    }
                } else if avance {
                    // Ce qui avance couvre les ACK dupliqués : un seul
                    // segment manquait, les autres étaient arrivés.
                    self.cc.dupacks -= self.cc.dupacks.min(segments - 1);
                    if self.cc.dupacks == 0 {
                        self.cc.phase = Phase::Ouverte;
                    }
                    self.cc.croitre(segments);
                }
            }
        }
    }

    /// Un pointeur urgent reçu (`tcp_check_urg`) : à la façon de BSD, que
    /// suit Linux (`tcp_stdurg` à 0), il désigne l'octet qui PRÉCÈDE
    /// SEG.SEQ + pointeur. Ignoré s'il est déjà lu, déjà reçu, ou pas plus
    /// loin que celui qu'on a ; un ancien octet urgent en tête de lecture,
    /// hors du flux, est retiré.
    fn pointeur_urgent(&mut self, pointeur: u16, seq: u32) {
        let p = seq.wrapping_add((pointeur as u32).saturating_sub(1));
        if apres(self.rcv_lu, p) || avant(p, self.rcv_nxt) {
            return;
        }
        if self.urgent != Urgent::Aucun && !apres(p, self.urg_seq) {
            return;
        }
        if self.urgent != Urgent::Aucun && self.urg_seq == self.rcv_lu && !self.reglages.oobinline && self.octets_reception > 0 {
            self.retirer_tete(1);
        }
        self.urgent = Urgent::Attendu;
        self.urg_seq = p;
    }

    /// Des données dans un segment acceptable (`tcp_data_queue`).
    fn recevoir_donnees(&mut self, seq: u32, mut charge: P, maintenant: u64, e: &mut Effets) {
        let n = charge.octets().len() as u32;
        if !apres(seq.wrapping_add(n), self.rcv_nxt) {
            // Déjà reçues : l'autre n'a pas eu notre ACK. Un ACK tout de
            // suite, et le mode « quickack ».
            self.entrer_mode_rapide();
            self.ack_maintenant = true;
            return;
        }
        if apres(seq, self.rcv_nxt) {
            // Un trou devant : la file hors d'ordre ; l'ACK dupliqué part
            // tout de suite (il dit le trou à l'émetteur).
            // La même borne que dans l'ordre (plus bas) ; au-delà, jeté ; et
            // rien au-delà de la limite de toute la machine.
            if self.memoire != Memoire::Limite && self.taille_vraie_reception + self.hors_ordre.taille_vraie + charge.taille_vraie() <= 2 * self.rcvbuf {
                self.hors_ordre.ranger(seq, charge);
            }
            self.ack.programme = true;
            self.ack_maintenant = true;
            return;
        }
        // Dans l'ordre (le début peut être déjà reçu).
        charge.avancer(self.rcv_nxt.wrapping_sub(seq) as usize);
        let longueur = charge.octets().len() as u32;
        // La fenêtre annoncée est une promesse : ce qui y tient est gardé,
        // même si sa taille vraie dépasse un peu SO_RCVBUF (de petits
        // segments occupent plus que prévu : Linux les recopie alors en
        // gros blocs, le « collapse » de `tcp_prune_queue`, que nous
        // n'avons pas). Au-delà du double de SO_RCVBUF, la mémoire prime :
        // d'abord la file hors d'ordre, par la fin
        // (`tcp_prune_ofo_queue`), puis le segment lui-même.
        while self.taille_vraie_reception + self.hors_ordre.taille_vraie + charge.taille_vraie() > 2 * self.rcvbuf {
            if !self.hors_ordre.jeter_la_derniere() {
                self.ack_maintenant = true;
                return;
            }
        }
        // Au-delà de la limite de toute la machine : gardé seulement si la
        // file de lecture est vide (la connexion doit pouvoir avancer), la
        // file hors d'ordre rendue d'abord (`tcp_prune_ofo_queue`).
        if self.memoire == Memoire::Limite && !self.reception.is_empty() {
            while self.hors_ordre.jeter_la_derniere() {}
            self.ack_maintenant = true;
            return;
        }
        if !self.ajouter_recu(charge) {
            self.ack_maintenant = true;
            return;
        }
        self.donnees_recues(longueur, maintenant);
        e.lisible = true;
        if !self.hors_ordre.vide() {
            while let Some(p) = self.hors_ordre.suivante(self.rcv_nxt) {
                if !self.ajouter_recu(p) {
                    break;
                }
            }
            // Le trou est comblé : un ACK sans attendre (RFC 5681 4.2).
            if self.hors_ordre.vide() {
                self.ack.urgent = true;
            }
        }
    }

    /// Ajoute une charge qui commence à RCV.NXT à la file de réception ;
    /// faux si la mémoire manque (elle est jetée).
    fn ajouter_recu(&mut self, charge: P) -> bool {
        let n = charge.octets().len();
        if n == 0 {
            return true;
        }
        if self.reception.try_reserve(1).is_err() {
            return false;
        }
        self.taille_vraie_reception += charge.taille_vraie();
        self.octets_reception += n;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
        self.reception.push_back(charge);
        true
    }

    /// Le FIN de l'autre, à son tour (`tcp_fin`).
    fn recevoir_fin(&mut self, e: &mut Effets) {
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.fin_recue = true;
        self.ack.programme = true;
        e.lisible = true;
        match self.etat {
            Etat::Etablie => {
                // CLOSE_WAIT : l'ACK attend un peu (le ping-pong), le temps
                // que le programme ferme à son tour et que notre FIN
                // l'emporte.
                self.passer(Etat::AttenteFermeture, e);
                self.ack.pingpong = self.ack.pingpong.max(1);
            }
            Etat::FinAttente1 => {
                // Notre FIN acquitté avec : TIME_WAIT ; sinon CLOSING.
                let n = if self.fin_seq().is_some_and(|f| apres(self.snd_una, f)) { Etat::TempsAttente } else { Etat::Fermeture };
                self.passer(n, e);
                self.ack_maintenant = true;
            }
            Etat::FinAttente2 => {
                self.passer(Etat::TempsAttente, e);
                self.ack_maintenant = true;
            }
            _ => {}
        }
        // Ce qui serait hors d'ordre après le FIN ne viendra jamais : jeté.
        self.hors_ordre.vider();
    }

    // --- Les ACK retardés ---

    /// Des données sont arrivées (`tcp_event_data_recv`, avec
    /// `tcp_measure_rcv_mss`) : l'`ato` suit l'écart entre les arrivées.
    fn donnees_recues(&mut self, longueur: u32, maintenant: u64) {
        self.ack.programme = true;
        if longueur >= self.ack.rcv_mss {
            self.ack.rcv_mss = longueur.min(self.mss_local as u32);
        }
        if self.ack.ato == 0 {
            // Les premières données : le mode « quickack ».
            self.ajouter_ack_rapides();
            self.ack.ato = ATO_MIN;
        } else {
            let m = maintenant.saturating_sub(self.ack.lrcvtime);
            if m <= ATO_MIN / 2 {
                self.ack.ato = (self.ack.ato >> 1) + ATO_MIN / 2;
            } else if m < self.ack.ato {
                self.ack.ato = ((self.ack.ato >> 1) + m).min(self.rto);
            } else if m > self.rto {
                // Un long silence : l'émetteur repart en démarrage lent.
                self.ajouter_ack_rapides();
            }
        }
        self.ack.lrcvtime = maintenant;
    }

    /// Des ACK immédiats en plus (`tcp_incr_quickack`) : de quoi couvrir
    /// la moitié de la fenêtre annoncée, au moins 2, au plus 16.
    fn ajouter_ack_rapides(&mut self) {
        let mut n = self.rcv_wnd() / (2 * self.ack.rcv_mss.max(1));
        if n == 0 {
            n = 2;
        }
        self.ack.rapides = self.ack.rapides.max(n.min(ACK_RAPIDES_MAX));
    }

    /// Le mode « quickack » (`tcp_enter_quickack_mode`) : notre ACK a dû
    /// se perdre.
    fn entrer_mode_rapide(&mut self) {
        self.ajouter_ack_rapides();
        self.ack.pingpong = 0;
        self.ack.ato = ATO_MIN;
    }

    /// Un ACK est dû : maintenant, ou plus tard (`__tcp_ack_snd_check`) ?
    /// Maintenant si plus d'un segment plein attend son ACK et que la
    /// fenêtre avance (l'émetteur grandit par ACK : un pour deux segments,
    /// RFC 5681 4.2), au début d'une connexion (« quickack »), après un
    /// trou comblé, ou tant que la file hors d'ordre a quelque chose (les
    /// ACK dupliqués qui déclenchent la retransmission rapide).
    fn verifier_ack(&mut self, maintenant: u64) {
        if !self.ack.programme || self.ack_maintenant {
            return;
        }
        let recus = self.rcv_nxt.wrapping_sub(self.ack.rcv_wup);
        // La fenêtre qu'on annoncerait maintenant ne recule pas sur la
        // dernière annoncée (`__tcp_select_window(sk) >= tp->rcv_wnd`).
        let fenetre_avance = self.fenetre_possible() >= self.ack.fenetre;
        if (recus > self.ack.rcv_mss && fenetre_avance) || self.ack.rapide() || self.ack.urgent || !self.hors_ordre.vide() {
            self.ack_maintenant = true;
        } else {
            self.retarder_ack(maintenant);
        }
    }

    /// Arme l'ACK retardé (`tcp_send_delayed_ack`) : l'`ato`, au plus
    /// 200 ms (500 ms pour un récepteur pur hors ping-pong, mais pas plus
    /// que le RTT mesuré) ; une échéance déjà plus proche est gardée, et
    /// une échéance presque échue fait partir l'ACK tout de suite.
    fn retarder_ack(&mut self, maintenant: u64) {
        let mut ato = self.ack.ato;
        if ato > ATO_MIN {
            let mut max_ato = if self.ack.pingpong > 0 { DELACK_MAX } else { ATO_RECEPTION };
            if self.rtt.mesure() {
                max_ato = max_ato.min(self.rtt.srtt().max(ATO_MIN));
            }
            ato = ato.min(max_ato);
        }
        ato = ato.min(DELACK_MAX);
        let mut echeance = maintenant + ato;
        if let Some(t) = self.ack.t {
            if t <= maintenant + (ato >> 2) {
                self.ack_maintenant = true;
                return;
            }
            echeance = echeance.min(t);
        }
        self.ack.t = Some(echeance);
    }

    /// Un segment qui porte notre ACK est parti (`tcp_event_ack_sent`) :
    /// plus rien n'est dû, un ACK rapide de moins.
    fn ack_envoye(&mut self) {
        if self.ack.programme && self.ack.rapides > 0 {
            self.ack.rapides -= 1;
            if self.ack.rapides == 0 {
                self.ack.ato = ATO_MIN;
            }
        }
        self.ack.programme = false;
        self.ack.urgent = false;
        self.ack.t = None;
        self.ack_maintenant = false;
        self.ack.rcv_wup = self.rcv_nxt;
        self.ack.fenetre = self.rcv_wnd();
    }

    // --- Les erreurs du réseau ---

    /// Une erreur ICMP pour cette connexion (`tcp_v4_err`) : `erreur` est
    /// l'errno que dit `icmp_err_convert`, `seq` le numéro du segment qui
    /// l'a provoquée. Avant la fin de la poignée de main, toute erreur
    /// ferme la connexion (un `connect` la rend aussitôt : la machine est
    /// injoignable, inutile d'attendre) ; ensuite, elle n'est que « douce »
    /// (rendue si la connexion abandonne), sauf avec IP_RECVERR
    /// (`recverr`), où elle est rendue tout de suite. Un réseau ou une
    /// machine injoignables (`injoignable`) pendant des retransmissions :
    /// le recul du RTO est défait d'un cran (RFC 6069, `tcp_ld_RTO_revert`) :
    /// le lien est coupé, pas encombré, et la connexion repartira dès son
    /// retour.
    pub fn erreur_icmp(&mut self, erreur: i32, seq: u32, injoignable: bool, recverr: bool, maintenant: u64) -> Effets {
        let mut e = Effets::default();
        match self.etat {
            Etat::SynEnvoye | Etat::SynRecu => self.finir(erreur, &mut e),
            Etat::Fermee | Etat::TempsAttente => {}
            _ => {
                if injoignable {
                    self.defaire_recul(seq, maintenant, &mut e);
                }
                // (Défaire le recul a pu faire abandonner la connexion.)
                if self.etat != Etat::Fermee {
                    if recverr {
                        self.erreur = erreur;
                        e.lisible = true;
                        e.place = true;
                    } else {
                        self.erreur_douce = erreur;
                    }
                }
            }
        }
        e
    }

    /// `tcp_ld_RTO_revert` : un cran de recul de moins, et l'échéance
    /// recalculée depuis le dernier envoi ; déjà passée : la retransmission
    /// tout de suite.
    fn defaire_recul(&mut self, seq: u32, maintenant: u64, e: &mut Effets) {
        if seq != self.snd_una || self.retransmissions == 0 || self.recul == 0 {
            return;
        }
        self.recul -= 1;
        let base = if self.rtt.mesure() { self.rtt.rto() } else { RTO_INITIAL };
        self.rto = reculer(base, self.recul);
        let ecoule = maintenant.saturating_sub(self.t_retrans_pose);
        if self.rto > ecoule {
            self.t_retrans = Some(self.t_retrans_pose + self.rto);
        } else {
            self.t_retrans = None;
            self.minuteur_retrans(maintenant, e);
        }
    }

    // --- Les minuteurs ---

    /// La prochaine échéance de la connexion (None : aucune).
    pub fn echeance(&self) -> Option<u64> {
        [self.t_retrans, self.t_sonde, self.t_keepalive, self.ack.t].into_iter().flatten().min()
    }

    /// Fait ce qui est échu à l'heure `maintenant` : l'ACK retardé, la
    /// retransmission, la sonde de fenêtre.
    pub fn minuteur(&mut self, maintenant: u64) -> Effets {
        let mut e = Effets::default();
        if self.ack.t.is_some_and(|t| t <= maintenant) {
            self.ack.t = None;
            self.minuteur_ack(&mut e);
        }
        if self.t_retrans.is_some_and(|t| t <= maintenant) {
            self.t_retrans = None;
            self.minuteur_retrans(maintenant, &mut e);
        }
        if self.t_sonde.is_some_and(|t| t <= maintenant) {
            self.t_sonde = None;
            self.minuteur_sonde(maintenant, &mut e);
        }
        if self.t_keepalive.is_some_and(|t| t <= maintenant) {
            self.t_keepalive = None;
            self.minuteur_keepalive(maintenant, &mut e);
        }
        e
    }

    /// Le keepalive est échu (`tcp_keepalive_timer`) : une connexion qui a
    /// quelque chose en vol ou à envoyer est vivante sans lui ; sinon, après
    /// TCP_KEEPIDLE de silence, une sonde (un segment d'un numéro déjà
    /// acquitté, que l'autre ne peut qu'acquitter) toutes les
    /// TCP_KEEPINTVL ; TCP_KEEPCNT sans réponse (ou TCP_USER_TIMEOUT
    /// passé), la connexion est coupée : RST, et ETIMEDOUT.
    fn minuteur_keepalive(&mut self, maintenant: u64, e: &mut Effets) {
        let r = self.reglages;
        if !r.keepalive || matches!(self.etat, Etat::Fermee | Etat::SynEnvoye | Etat::TempsAttente) {
            return;
        }
        if self.snd_max != self.snd_una || self.prochain_segment().is_some() {
            self.t_keepalive = Some(maintenant + r.keepidle);
            return;
        }
        let ecoule = maintenant.saturating_sub(self.ack.lrcvtime.max(self.dernier_recu));
        if ecoule < r.keepidle {
            self.t_keepalive = Some(maintenant + (r.keepidle - ecoule));
            return;
        }
        let u = r.delai_utilisateur;
        if (u != 0 && ecoule >= u && self.sondes > 0) || (u == 0 && self.sondes >= r.keepcnt) {
            self.rst_du = Some((self.snd_max, self.rcv_nxt, tcp::RST | tcp::ACK));
            self.abandonner(e);
            e.a_emettre = true;
            return;
        }
        self.sonde_due = true;
        self.sondes += 1;
        self.t_keepalive = Some(maintenant + r.keepintvl);
        e.a_emettre = true;
    }

    /// L'ACK retardé est échu (`tcp_delack_timer_handler`) : il part ; et
    /// puisqu'aucune réponse ne l'a emporté, le délai était trop court
    /// (l'`ato` double), ou le ping-pong a cessé (l'`ato` revient au
    /// minimum).
    fn minuteur_ack(&mut self, e: &mut Effets) {
        if !self.ack.programme || matches!(self.etat, Etat::Fermee) {
            return;
        }
        if self.ack.pingpong == 0 {
            self.ack.ato = (self.ack.ato << 1).min(self.rto);
        } else {
            self.ack.pingpong = 0;
            self.ack.ato = ATO_MIN;
        }
        self.ack_maintenant = true;
        e.a_emettre = true;
    }

    /// Arme la retransmission à `maintenant` + RTO.
    fn armer_rto(&mut self, maintenant: u64) {
        self.t_retrans = Some(maintenant + self.rto);
        self.t_retrans_pose = maintenant;
    }

    /// Le RTO est échu (`tcp_retransmit_timer`) : abandonner
    /// (`tcp_write_timeout`), ou renvoyer depuis SND.UNA (le SYN, le
    /// SYN-ACK, ou les données et le FIN), la fenêtre de congestion à un
    /// segment, et doubler le RTO (sauf pour les quatre premières
    /// retransmissions d'un SYN).
    fn minuteur_retrans(&mut self, maintenant: u64, e: &mut Effets) {
        let syn = matches!(self.etat, Etat::SynEnvoye | Etat::SynRecu);
        if self.etat == Etat::Fermee || (!syn && self.snd_max == self.snd_una) {
            return;
        }
        if !syn && self.snd_wnd == 0 && !self.reglages.orpheline {
            // L'autre a refermé sa fenêtre sur des données déjà en vol :
            // nos retransmissions deviennent des sondes, qui n'abandonnent
            // pas tant qu'il répond (Linux : « Receiver dastardly shrinks
            // window »). Une orpheline, elle, abandonne comme d'habitude.
            let debut = self.retrans_debut.unwrap_or(self.t_retrans_pose);
            if self.fenetre_nulle_echue(maintenant, maintenant.saturating_sub(debut)) {
                self.abandonner(e);
                return;
            }
            self.retrans_debut.get_or_insert(self.t_retrans_pose);
            self.perte();
        } else {
            if self.temps_ecoule(maintenant) {
                self.abandonner(e);
                return;
            }
            self.retrans_debut.get_or_insert(self.t_retrans_pose);
            self.perte();
            self.retransmissions += 1;
            self.total_rto += 1;
        }
        self.total_retrans += 1;
        if !(self.etat == Etat::SynEnvoye && self.total_rto <= SYN_LINEAIRES) {
            self.recul += 1;
            self.rto = (self.rto * 2).min(RTO_MAX);
        }
        let d = self.borne_utilisateur(maintenant, self.rto);
        self.t_retrans = Some(maintenant + d);
        self.t_retrans_pose = maintenant;
        e.a_emettre = true;
    }

    /// Ce qui est en vol est réputé perdu (`tcp_enter_loss`) : renvoyé
    /// depuis SND.UNA (le SYN ou le SYN-ACK dans la poignée de main), sans
    /// mesure du RTT (Karn).
    fn perte(&mut self) {
        self.cc.entrer_perte(self.snd_una, self.snd_max, self.retransmissions);
        self.chrono = None;
        self.retransmettre_tete = false;
        match self.etat {
            Etat::SynEnvoye | Etat::SynRecu => self.syn_du = true,
            _ => self.snd_nxt = self.snd_una,
        }
    }

    /// Faut-il abandonner (`tcp_write_timeout`) ? Dans la poignée de main,
    /// au compte : TCP_SYNCNT (6 par défaut, 5 pour le SYN-ACK d'une
    /// fille), plus les quatre retransmissions linéaires d'un SYN ; et pour
    /// tous, au temps modélisé (rtt.rs) de ce compte depuis la première
    /// retransmission, ou au délai de TCP_USER_TIMEOUT.
    fn temps_ecoule(&self, maintenant: u64) -> bool {
        let (limite, base, expire) = match self.etat {
            Etat::SynEnvoye | Etat::SynRecu => {
                let essais = match self.reglages.syn_essais {
                    0 if self.fille => SYNACK_ESSAIS,
                    0 => SYN_ESSAIS,
                    n => n,
                };
                let max = essais + if self.etat == Etat::SynEnvoye { SYN_LINEAIRES } else { 0 };
                (essais, RTO_INITIAL, self.retransmissions >= max)
            }
            _ => {
                let essais = if self.reglages.orpheline { self.essais_orpheline(self.rto < RTO_MAX) } else { RETRIES2 };
                (essais, RTO_MIN, false)
            }
        };
        expire || self.retransmissions_echues(maintenant, limite, base)
    }

    /// Les retransmissions d'une orpheline (`tcp_orphan_retries`) : 8 tant
    /// qu'elle semble vivante, aucune ensuite.
    fn essais_orpheline(&self, vivante: bool) -> u32 {
        if vivante { ORPHELINE_ESSAIS } else { 0 }
    }

    /// `retransmits_timed_out` : retransmet-on depuis plus longtemps que
    /// le temps modélisé de `limite` retransmissions (ou TCP_USER_TIMEOUT) ?
    fn retransmissions_echues(&self, maintenant: u64, limite: u32, base: u64) -> bool {
        if self.retransmissions == 0 {
            return false;
        }
        let Some(debut) = self.retrans_debut else { return false };
        let delai = if self.reglages.delai_utilisateur != 0 { self.reglages.delai_utilisateur } else { temps_modele(limite, base) };
        maintenant.saturating_sub(debut) >= delai
    }

    /// `tcp_rtx_probe0_timed_out` : face à une fenêtre nulle, abandonner
    /// seulement si l'autre se tait depuis plus de deux RTO_MAX (ou le délai
    /// de TCP_USER_TIMEOUT), et qu'on retransmet depuis aussi longtemps.
    fn fenetre_nulle_echue(&self, maintenant: u64, depuis: u64) -> bool {
        let mut limite = 2 * RTO_MAX;
        let u = self.reglages.delai_utilisateur;
        if u != 0 {
            if depuis > u {
                return true;
            }
            limite = limite.min(u);
        }
        maintenant.saturating_sub(self.dernier_recu) > limite && depuis > limite
    }

    /// Le prochain RTO, borné par ce qui reste de TCP_USER_TIMEOUT
    /// (`tcp_clamp_rto_to_user_timeout`) : passé, tout de suite.
    fn borne_utilisateur(&self, maintenant: u64, rto: u64) -> u64 {
        let u = self.reglages.delai_utilisateur;
        let Some(debut) = self.retrans_debut else { return rto };
        if u == 0 {
            return rto;
        }
        let ecoule = maintenant.saturating_sub(debut);
        if ecoule >= u { 1 } else { rto.min(u - ecoule) }
    }

    /// Abandonner (`tcp_write_err`) : l'erreur douce d'un ICMP s'il y en a
    /// une (elle dit pourquoi), sinon ETIMEDOUT. Sans RST : l'autre ne
    /// répond plus.
    fn abandonner(&mut self, e: &mut Effets) {
        let erreur = if self.erreur_douce != 0 { self.erreur_douce } else { ETIMEDOUT };
        self.finir(erreur, e);
    }

    /// La longueur, en numéros de séquence, du prochain segment neuf (ses
    /// données et son FIN) ; None : rien à envoyer.
    fn prochain_segment(&self) -> Option<u32> {
        let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
        let reste = self.octets_envoi.saturating_sub(debut);
        let fin = self.fin_seq().is_some_and(|f| !apres(self.snd_nxt, f));
        let n = reste.min(self.mss_courant() as usize);
        let avec_fin = fin && n == reste;
        (n > 0 || avec_fin).then_some(n as u32 + u32::from(avec_fin))
    }

    /// Le délai de la prochaine sonde (`tcp_probe0_when`) : le RTO (au
    /// moins 200 ms), doublé à chaque sonde, au plus RTO_MAX.
    fn delai_sonde(&self) -> u64 {
        reculer(self.rto.max(RTO_MIN), self.recul)
    }

    /// Un ACK quand rien n'est en vol (`tcp_ack_probe`) : la fenêtre
    /// laisse-t-elle passer le prochain segment ? Les sondes s'arrêtent ;
    /// sinon, la suivante est réarmée.
    fn ack_de_sonde(&mut self, maintenant: u64) {
        let Some(longueur) = self.prochain_segment() else { return };
        if !apres(self.snd_nxt.wrapping_add(longueur), self.snd_una.wrapping_add(self.snd_wnd)) {
            self.recul = 0;
            self.sondes_debut = None;
            self.t_sonde = None;
        } else {
            self.t_sonde = Some(maintenant + self.delai_sonde());
        }
    }

    /// La sonde est échue (`tcp_probe_timer`) : une de plus, ou abandonner
    /// (15 sans réponse, `tcp_retries2` ; une orpheline plus tôt ;
    /// TCP_USER_TIMEOUT). Tant que l'autre répond, on sonde pour toujours
    /// (RFC 1122 4.2.2.17).
    fn minuteur_sonde(&mut self, maintenant: u64, e: &mut Effets) {
        if self.snd_nxt != self.snd_una || self.prochain_segment().is_none() || !self.etat.synchronise() {
            self.sondes = 0;
            self.sondes_debut = None;
            return;
        }
        match self.sondes_debut {
            None => self.sondes_debut = Some(maintenant),
            Some(d) => {
                let u = self.reglages.delai_utilisateur;
                if u != 0 && maintenant.saturating_sub(d) >= u {
                    self.abandonner(e);
                    return;
                }
            }
        }
        let mut max = RETRIES2;
        if self.reglages.orpheline {
            let vivante = reculer(self.rto, self.recul) < RTO_MAX;
            max = self.essais_orpheline(vivante);
            if !vivante && self.recul >= max {
                self.abandonner(e);
                return;
            }
        }
        if self.sondes >= max {
            self.abandonner(e);
            return;
        }
        self.sonde_due = true;
        self.sondes += 1;
        if self.recul < RETRIES2 {
            self.recul += 1;
        }
        self.t_sonde = Some(maintenant + self.delai_sonde());
        e.a_emettre = true;
    }

    // --- Ce qu'il faut envoyer ---

    /// L'en-tête d'un segment de cette connexion.
    fn entete(&self, seq: u32, drapeaux: u8) -> Tcp {
        let mut h = Tcp {
            source: self.port_local,
            destination: self.port_distant,
            seq,
            ack: if drapeaux & tcp::ACK != 0 { self.rcv_nxt } else { 0 },
            drapeaux,
            fenetre: if drapeaux & tcp::SYN != 0 { self.fenetre_possible().min(FENETRE_MAX) as u16 } else { self.fenetre() },
            urgent: 0,
            options: tcp::Options::default(),
        };
        // Le pointeur urgent, dans tout segment qui précède l'octet urgent
        // (`__tcp_transmit_skb`) ; trop loin pour 16 bits, 0xFFFF, tant
        // que le segment reste en deçà.
        if drapeaux & (tcp::SYN | tcp::RST) == 0 && self.mode_urgent() && avant(seq, self.snd_up) {
            if avant(self.snd_up, seq.wrapping_add(0x10000)) {
                h.urgent = self.snd_up.wrapping_sub(seq) as u16;
                h.drapeaux |= tcp::URG;
            } else if apres(seq.wrapping_add(0xFFFF), self.snd_max) {
                h.urgent = 0xFFFF;
                h.drapeaux |= tcp::URG;
            }
        }
        h
    }

    /// Ce que la fenêtre de l'autre laisse d'un segment renvoyé, qui
    /// commence à `seq`, de `n` octets de données sur les `reste` qui
    /// suivent (`__tcp_retransmit_skb`) : coupé à la place qu'elle laisse ;
    /// une fenêtre fermée n'arrête pas la tête (SND.UNA), qui part entière
    /// et sert de sonde (sinon une fenêtre réduite à rien sur des données
    /// en vol bloquerait tout). Rend la longueur et si le FIN peut suivre ;
    /// None : rien ne peut partir.
    fn couper_retransmission(&self, seq: u32, n: usize, reste: usize) -> Option<(usize, bool)> {
        let mut place = self.snd_una.wrapping_add(self.snd_wnd).wrapping_sub(seq) as i32 as i64;
        if place <= 0 {
            if seq != self.snd_una {
                return None;
            }
            place = self.mss_courant() as i64;
        }
        let n = n.min(place as usize);
        Some((n, n == reste && (n as i64) < place))
    }

    /// Envoie un segment de `n` octets à partir de SND.NXT (et le FIN si
    /// `avec_fin`) : neuf, ou renvoyé après un RTO.
    fn envoyer_donnees(&mut self, n: usize, avec_fin: bool, maintenant: u64, sortir: &mut impl FnMut(Sortant)) {
        let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
        let reste = self.octets_envoi.saturating_sub(debut);
        let mut drapeaux = tcp::ACK;
        // PSH : la fin de ce que le programme a écrit.
        if n > 0 && n == reste {
            drapeaux |= tcp::PSH;
        }
        if avec_fin {
            drapeaux |= tcp::FIN;
        }
        sortir(Sortant { entete: self.entete(self.snd_nxt, drapeaux), debut, longueur: n });
        let fin_segment = self.snd_nxt.wrapping_add(n as u32 + u32::from(avec_fin));
        if n < self.mss_courant() as usize {
            // Un petit segment (`tcp_minshall_update`).
            self.snd_sml = fin_segment;
        }
        if self.snd_nxt == self.snd_max {
            if self.chrono.is_none() {
                self.chrono = Some((fin_segment, maintenant));
            }
        } else {
            self.total_retrans += 1;
        }
        self.snd_nxt = fin_segment;
        if apres(fin_segment, self.snd_max) {
            self.snd_max = fin_segment;
        }
        if self.t_retrans.is_none() {
            self.armer_rto(maintenant);
        }
        self.t_sonde = None;
        if self.cc.phase == Phase::Reprise {
            self.cc.prr_sortis += 1;
        }
        // `tcp_event_data_sent` : une réponse rapide à ce qui vient
        // d'arriver, c'est une conversation (le ping-pong).
        self.dernier_envoi = maintenant;
        if maintenant.saturating_sub(self.ack.lrcvtime) < self.ack.ato {
            self.ack.pingpong = self.ack.pingpong.saturating_add(1);
        }
        self.ack_envoye();
    }

    /// Rend, par `sortir`, les segments à envoyer maintenant : un RST, le
    /// SYN ou le SYN-ACK, une sonde, la retransmission rapide de la tête,
    /// les données que permettent la fenêtre de l'autre et celle de
    /// congestion (neuves, ou renvoyées depuis SND.NXT après un RTO), le
    /// FIN, et l'ACK s'il en faut un tout de suite et qu'aucun segment ne
    /// l'a porté.
    pub fn emettre(&mut self, maintenant: u64, mut sortir: impl FnMut(Sortant)) {
        if let Some((seq, ack, drapeaux)) = self.rst_du.take() {
            let mut h = self.entete(seq, drapeaux);
            h.ack = ack;
            h.fenetre = 0;
            sortir(Sortant { entete: h, debut: 0, longueur: 0 });
            if self.etat == Etat::Fermee {
                return;
            }
        }
        if self.etat == Etat::Fermee {
            return;
        }
        self.annoncer();
        if self.syn_du {
            self.syn_du = false;
            let drapeaux = if self.etat == Etat::SynRecu { tcp::SYN | tcp::ACK } else { tcp::SYN };
            let mut h = self.entete(self.iss, drapeaux);
            h.options.mss = Some(self.mss_local);
            // L'échelle : proposée dans notre SYN ; rendue dans le SYN-ACK
            // seulement si l'autre l'a proposée (RFC 7323 1.3).
            if self.echelle_ok {
                h.options.echelle = Some(self.echelle_reception);
            }
            sortir(Sortant { entete: h, debut: 0, longueur: 0 });
            self.snd_nxt = self.iss.wrapping_add(1);
            self.snd_max = self.snd_nxt;
            // Le premier SYN est chronométré ; pas ceux qui le répètent.
            if self.retransmissions == 0 && self.total_retrans == 0 {
                self.chrono = Some((self.snd_nxt, maintenant));
            }
            if self.t_retrans.is_none() {
                self.armer_rto(maintenant);
            }
            if drapeaux & tcp::ACK != 0 {
                self.ack_envoye();
            }
            return;
        }
        if !self.etat.synchronise() {
            // En SYN_RECEIVED, un ACK peut partir (l'ouverture simultanée,
            // un segment inacceptable) ; en SYN_SENT, on ne sait encore rien
            // à acquitter.
            if self.etat == Etat::SynRecu && self.ack_maintenant {
                sortir(Sortant { entete: self.entete(self.snd_max, tcp::ACK), debut: 0, longueur: 0 });
                self.ack_envoye();
            }
            return;
        }
        // La sonde de fenêtre (`tcp_write_wakeup`) : ce qui tient dans une
        // fenêtre trop petite pour un segment entier ; une fenêtre nulle :
        // un segment sans données, d'un numéro déjà acquitté, que l'autre
        // ne peut qu'acquitter en redisant sa fenêtre.
        if core::mem::take(&mut self.sonde_due) {
            let bord = self.snd_una.wrapping_add(self.snd_wnd);
            let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
            let reste = self.octets_envoi.saturating_sub(debut);
            let fenetre = bord.wrapping_sub(self.snd_nxt);
            if self.prochain_segment().is_some() && avant(self.snd_nxt, bord) {
                let n = reste.min(self.mss_courant() as usize).min(fenetre as usize);
                let avec_fin = self.fin_seq().is_some_and(|f| !apres(self.snd_nxt, f)) && n == reste && (n as u32) < fenetre;
                self.envoyer_donnees(n, avec_fin, maintenant, &mut sortir);
            } else {
                sortir(Sortant { entete: self.entete(self.snd_una.wrapping_sub(1), tcp::ACK), debut: 0, longueur: 0 });
                self.ack_envoye();
            }
        }
        // La retransmission rapide (et NewReno) : la tête seule, sans
        // toucher à SND.NXT.
        if core::mem::take(&mut self.retransmettre_tete) && self.snd_max != self.snd_una {
            let envoyes = self.envoyes();
            let n = envoyes.min(self.mss_courant() as usize);
            let (n, avec_fin) = self.couper_retransmission(self.snd_una, n, envoyes).unwrap_or((n, false));
            let avec_fin = avec_fin && self.fin_seq().is_some_and(|f| apres(self.snd_max, f));
            let mut drapeaux = tcp::ACK;
            if avec_fin {
                drapeaux |= tcp::FIN;
            }
            let debut = self.snd_una.wrapping_sub(self.seq_envoi) as usize;
            sortir(Sortant { entete: self.entete(self.snd_una, drapeaux), debut, longueur: n });
            self.chrono = None;
            self.total_retrans += 1;
            if self.cc.phase == Phase::Reprise {
                self.cc.prr_sortis += 1;
            }
            self.ack_envoye();
        }
        // Les données, et le FIN, tant que la fenêtre de congestion a de la
        // place : un segment neuf entier dans la fenêtre de l'autre
        // (`tcp_snd_wnd_test` : on attend plutôt que de le couper) ; un
        // segment renvoyé après un RTO, coupé à ce qu'elle laisse
        // (`__tcp_retransmit_skb`).
        let mut limite_cwnd = false;
        let mut bloque_fenetre = false;
        let mut retenu = false;
        loop {
            let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
            let reste = self.octets_envoi.saturating_sub(debut);
            let fin_ici = self.fin_seq().is_some_and(|f| !apres(self.snd_nxt, f));
            if reste == 0 && !fin_ici {
                break;
            }
            let mut n = reste.min(self.mss_courant() as usize);
            let mut avec_fin = fin_ici && n == reste;
            if avant(self.snd_nxt, self.snd_max) {
                match self.couper_retransmission(self.snd_nxt, n, reste) {
                    Some((m, fin)) => {
                        n = m;
                        avec_fin = fin && fin_ici;
                    }
                    None => {
                        bloque_fenetre = true;
                        break;
                    }
                }
            } else if apres(self.snd_nxt.wrapping_add(n as u32 + u32::from(avec_fin)), self.snd_una.wrapping_add(self.snd_wnd)) {
                bloque_fenetre = true;
                break;
            }
            if self.paquets_en_vol() >= self.cc.cwnd {
                limite_cwnd = true;
                break;
            }
            // Nagle (`tcp_nagle_test`) : le dernier segment, incomplet,
            // attend ; TCP_CORK et MSG_MORE le retiennent toujours ; sinon,
            // tant qu'un petit segment déjà envoyé n'est pas acquitté (la
            // règle de Minshall : de gros segments en vol ne retiennent
            // pas le petit qui suit), sauf TCP_NODELAY. Ni le FIN, ni le
            // mode urgent, ni une poussée n'attendent.
            let partiel = n < self.mss_courant() as usize && n == reste;
            if partiel && !avec_fin && !avant(self.snd_nxt, self.snd_max) && !self.pousser && !self.mode_urgent() {
                let bouchon = self.reglages.cork || self.plus_a_venir;
                let petit_en_vol = apres(self.snd_sml, self.snd_una) && !apres(self.snd_sml, self.snd_max);
                let nagle = !self.reglages.nodelay && self.snd_max != self.snd_una && petit_en_vol;
                if bouchon || nagle {
                    retenu = true;
                    break;
                }
            }
            if self.snd_nxt == self.snd_una && self.snd_nxt == self.snd_max {
                // Rien en vol : après un long silence, la cwnd ne vaut plus.
                let silence = maintenant.saturating_sub(self.dernier_envoi);
                if silence > self.rto {
                    self.cc.redemarrer(silence, self.rto);
                }
            }
            self.envoyer_donnees(n, avec_fin, maintenant, &mut sortir);
            if avec_fin {
                break;
            }
        }
        self.pousser = false;
        self.plus_a_venir = false;
        let sortis = self.paquets_sortis();
        self.cc.valider(limite_cwnd, sortis, self.snd_una, self.snd_nxt);
        // Rien en vol, et des données qui attendent (la fenêtre de l'autre ne
        // les laisse pas passer, ou TCP_CORK les retient) : la sonde
        // (`tcp_check_probe_timer`), qui les poussera au plus tard.
        if (bloque_fenetre || retenu) && self.snd_max == self.snd_una && self.t_retrans.is_none() && self.t_sonde.is_none() {
            self.t_sonde = Some(maintenant + self.rto.max(RTO_MIN));
        }
        if self.ack_maintenant {
            sortir(Sortant { entete: self.entete(self.snd_max, tcp::ACK), debut: 0, longueur: 0 });
            self.ack_envoye();
        }
    }
}

/// `base` doublé `recul` fois, au plus RTO_MAX (`inet_csk_rto_backoff`).
fn reculer(base: u64, recul: u32) -> u64 {
    if recul >= 20 { RTO_MAX } else { (base << recul).min(RTO_MAX) }
}

/// La réponse à un segment qui n'a pas de connexion (`tcp_v4_send_reset`,
/// RFC 9293 3.10.7.1) : rien pour un RST ; sinon un RST, dont le numéro
/// est l'ACK du segment s'il en avait un, ou 0 avec un ACK de tout ce qu'il
/// portait.
pub fn reponse_sans_connexion(t: &Tcp, longueur_charge: usize) -> Option<Tcp> {
    if t.drapeaux & tcp::RST != 0 {
        return None;
    }
    let mut r = Tcp { source: t.destination, destination: t.source, ..Tcp::default() };
    if t.drapeaux & tcp::ACK != 0 {
        r.seq = t.ack;
        r.drapeaux = tcp::RST;
    } else {
        let n = longueur_charge as u32 + u32::from(t.drapeaux & tcp::SYN != 0) + u32::from(t.drapeaux & tcp::FIN != 0);
        r.ack = t.seq.wrapping_add(n);
        r.drapeaux = tcp::RST | tcp::ACK;
    }
    Some(r)
}
