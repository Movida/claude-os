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
//!   - la FILE DE RETRANSMISSION et la reprise (retrans.rs), le modèle de
//!     Linux : chaque segment envoyé a son entrée, marquée perdue ou renvoyée ;
//!   - la CONGESTION (congestion.rs, cubic.rs) : CUBIC, ou Reno ; la retransmission
//!     rapide au troisième ACK dupliqué, la reprise NewReno et PRR ;
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
//!   - les HORODATAGES (RFC 7323) : chaque segment porte notre heure, en ms,
//!     et renvoie la dernière heure reçue de l'autre. Ils protègent des
//!     numéros de séquence qui reviennent (PAWS : un segment plus vieux que
//!     le dernier vu est refusé) et mesurent le RTT d'un segment renvoyé, là
//!     où Karn l'interdirait. slirp ne les propose pas ;
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
//! L'heure et le hasard sont des arguments (l'ISN est tiré par le noyau,
//! l'heure est en nanosecondes) ; les segments à envoyer sont rendus par
//! `emettre` ; les copies vers et depuis le programme passent par des
//! fonctions données. `echeance` dit quand appeler `minuteur`.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use formats::reseau::tcp::{self, Tcp};

pub mod attente;
mod carte;
mod congestion;
mod cubic;
mod hors_ordre;
mod minmax;
mod reception;
mod retrans;
mod rtt;
mod sack;

use attente::Attente;
use congestion::{Congestion, Phase, TCP_REORDERING};
use hors_ordre::HorsOrdre;
use minmax::MinMax;
use reception::{EspaceLu, RATIO_DEFAUT};
use retrans::{Envoye, EtatSack, Rexmit, ResultatAck, FLAG_CA_ALERT, FLAG_DATA, FLAG_DSACKING_ACK, FLAG_NO_CHALLENGE_ACK, FLAG_NOT_DUP, FLAG_SET_XMIT_TIMER, FLAG_SND_UNA_ADVANCED, FLAG_SYN_ACKED, FLAG_WIN_UPDATE};
use rtt::Rtt;
use sack::Rack;

pub use congestion::{CWND_INITIALE, Controle, PACING_MAX};
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
/// noyau dit à chaque connexion avant de la faire travailler
/// (`__sk_mem_raise_allocated`, `sk_memory_allocated`, `tcp_memory_pressure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Memoire {
    /// Sous le premier seuil (`tcp_mem[0]`) : rien ne change.
    Libre,
    /// Au-delà : SO_SNDBUF et SO_RCVBUF ne grandissent plus d'eux-mêmes
    /// (`tcp_should_expand_sndbuf`, `tcp_clamp_window`).
    Souple,
    /// Passé le second (`tcp_mem[1]`), et jusqu'à redescendre sous le premier : la
    /// pression (`tcp_memory_pressure`) : la fenêtre se resserre.
    Pression,
    /// Sous pression, et cette socket a plus que sa juste part (la limite divisée
    /// par le nombre de sockets) : plus rien de neuf au-delà du minimum
    /// (`tcp_rmem[0]`, `tcp_wmem[0]`).
    Excedent,
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
/// La place de l'option des horodatages dans chaque segment
/// (TCPOLEN_TSTAMP_ALIGNED).
const TS_ALIGNE: u16 = 12;
/// La plus grande échelle de fenêtre (`TCP_MAX_WSCALE`, RFC 7323 2.3) :
/// celle d'un pair qui en propose plus est ramenée à 14, comme Linux.
pub const ECHELLE_MAX: u8 = 14;

/// L'échelle que nous proposons (`tcp_select_initial_window`) : de quoi
/// annoncer en 16 bits la plus grande place de réception que la connexion
/// pourra avoir, ilog2(place) - 15, entre 0 et 14. Cette place : la moitié
/// de SO_RCVBUF (`tcp_full_space`) s'il a été fixé par le programme
/// (`SOCK_RCVBUF_LOCK` : la fenêtre ne la dépassera jamais) ; sinon la plus
/// grande que la machine permet, `reception_max` (`tcp_rmem[2]` et
/// `rmem_max`), que le noyau calcule d'après sa mémoire, comme `tcp_init` ;
/// au plus TCP_WINDOW_CLAMP (`clamp`, 0 : rien). Linux 6.18 propose ainsi 10
/// sur une machine de 12 Gio, et 7 avec SO_RCVBUF fixé à 8 Mio (mesuré sur
/// l'hôte).
pub fn echelle(rcvbuf: usize, rcvbuf_fixe: bool, reception_max: usize, clamp: u32) -> u8 {
    let pleine = rcvbuf / 2;
    let mut plafond = if clamp == 0 { 65_535 << ECHELLE_MAX } else { clamp as usize };
    if rcvbuf_fixe && (clamp == 0 || plafond > pleine) {
        plafond = pleine;
    }
    let place = pleine.max(reception_max).min(plafond);
    (place.max(1).ilog2() as i64 - 15).clamp(0, ECHELLE_MAX as i64) as u8
}

/// ICSK_ACK_PUSHED, et PUSHED2 : un segment, puis un deuxième, qui ne remplit pas
/// le MSS est arrivé : l'autre a sans doute fini d'écrire, et attend peut-être un ACK.
const ACK_POUSSE: u8 = 1;
const ACK_POUSSE2: u8 = 2;

/// Le plafond de SO_SNDBUF agrandi sur une machine assez grande
/// (`tcp_wmem[2]`, 4 Mio ; moins sur une petite : `Tcb::sndbuf_max`).
pub const SNDBUF_MAX: usize = 4 << 20;
/// De même pour SO_RCVBUF (`tcp_rmem[2]`, 32 Mio ; `Tcb::rcvbuf_max`).
pub const RCVBUF_MAX: usize = 32 << 20;
/// La mémoire garantie à une socket au-delà de sa juste part (`tcp_wmem[0]`).
const WMEM0: usize = 4096;

/// Le plus grand degré de réordonnancement qu'on estime (`tcp_max_reordering`).
const TCP_MAX_REORDERING: u32 = 300;

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
/// La compression des ACK dupliqués (`tcp_comp_sack_nr`, `tcp_comp_sack_delay_ns`).
const COMP_SACK_MAX: u32 = 44;
const COMP_SACK_DELAI: u64 = 1_000_000;

// Les errno que voit le programme.
pub const EAGAIN: i32 = 11;
pub const EINVAL: i32 = 22;
pub const EMSGSIZE: i32 = 90;
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

/// Combien de SYN-ACK pour les filles d'une écoute, de TCP_SYNCNT `syncnt`, avec `qlen` filles
/// sans ACK dont `jeunes` n'ont encore vu aucune échéance (`reqsk_timer_handler`). « Essentially,
/// we reserve half of room for young embrions; and abort old ones without pity, if old ones are
/// about to clog our table. » : passé la moitié de la file, chaque moitié de plus d'anciennes
/// retire un essai, jusqu'à 2.
pub fn essais_de_filles(syncnt: u32, qlen: u32, jeunes: u32, backlog: u32) -> u32 {
    let mut max = if syncnt != 0 { syncnt } else { SYNACK_ESSAIS };
    if qlen << 1 > backlog.max(8) {
        let mut jeunes = jeunes << 1;
        while max > 2 && qlen >= jeunes {
            max -= 1;
            jeunes <<= 1;
        }
    }
    max
}

/// Un segment de `seq` à `fin_seq` tombe-t-il dans la fenêtre [`debut`, `fin`]
/// (`tcp_in_window`) ? Ce que regardent une fille et une entrée de TIME_WAIT ;
/// une connexion a sa règle (`Tcb::acceptable`).
pub fn dans_la_fenetre(seq: u32, fin_seq: u32, debut: u32, fin: u32) -> bool {
    seq == debut || (apres(fin_seq, debut) && avant(seq, fin)) || (seq == fin && seq == fin_seq)
}

/// Ce qu'une connexion, ou une entrée de TIME_WAIT, retient des horodatages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Horodatages {
    /// Le dernier TSval reçu et accepté (`ts_recent`), que nos segments
    /// renvoient ; 0 : aucun encore (`tcp_paws_check` n'en juge rien).
    pub recent: u32,
    /// L'heure de sa réception (`ts_recent_stamp`, ici en ns) : passé
    /// PAWS_ENVELOPPE, il ne vaut plus rien.
    pub instant: u64,
    /// Notre décalage (`tsoffset`) : ajouté à notre horloge, tiré par couple
    /// d'adresses. Il cache notre heure de démarrage, et lie les connexions
    /// entre les mêmes machines par une même horloge, ce que PAWS demande.
    pub decalage: u32,
}

impl Horodatages {
    /// Notre TSval à l'heure `maintenant`.
    pub fn valeur(&self, maintenant: u64) -> u32 {
        horloge_ts(maintenant).wrapping_add(self.decalage)
    }

    /// Retient TSval `val`, reçu à l'heure `maintenant` (`tcp_store_ts_recent`).
    pub fn retenir(&mut self, val: u32, maintenant: u64) {
        self.recent = val;
        self.instant = maintenant;
    }
}

/// Notre horloge des horodatages : des ms (`tcp_clock_ts`, sans l'option de
/// route `usec_ts`, que rien ne pose).
fn horloge_ts(maintenant: u64) -> u32 {
    (maintenant / 1_000_000) as u32
}

/// La fenêtre de PAWS dans une connexion (TCP_PAWS_WINDOW) : un TSval d'une
/// unité en arrière passe encore.
const PAWS_FENETRE: i32 = 1;
/// Passé ce temps, un `ts_recent` ne vaut plus (TCP_PAWS_WRAP, 2147 s : ce
/// qu'il faut à une horloge d'1 MHz, la plus rapide permise, pour faire le tour
/// de la moitié des 32 bits).
const PAWS_ENVELOPPE: u64 = 2147 * 1_000_000_000;
/// Passé ce temps, un RST d'un TSval trop vieux est cru, dans TIME_WAIT et une
/// fille (TCP_PAWS_MSL) : l'autre a pu redémarrer, son horloge avec lui.
const PAWS_MSL: u64 = 60 * 1_000_000_000;

/// `tcp_paws_check` : TSval `val` est-il acceptable, à `fenetre` près ? Oui
/// aussi si `ts_recent` a passé son temps, ou s'il est nul (« some OSes send
/// SYN and SYNACK messages with tsval=0 »).
pub(crate) fn paws_controle(ts: &Horodatages, val: u32, fenetre: i32, maintenant: u64) -> bool {
    (ts.recent.wrapping_sub(val) as i32) <= fenetre || maintenant.saturating_sub(ts.instant) >= PAWS_ENVELOPPE || ts.recent == 0
}

/// `tcp_paws_reject`, pour une entrée de TIME_WAIT et une fille : fenêtre 0, et
/// un RST relâché après 60 s. Dans une connexion, un RST passe toujours
/// (`tcp_validate_incoming`), et la fenêtre vaut 1.
pub(crate) fn paws_rejet(ts: &Horodatages, val: u32, rst: bool, maintenant: u64) -> bool {
    !paws_controle(ts, val, 0, maintenant) && !(rst && maintenant.saturating_sub(ts.instant) >= PAWS_MSL)
}

/// `seq` est-il entre `s1` et `s2`, modulo 2³² (le `between` de Linux) ?
fn entre(seq: u32, s1: u32, s2: u32) -> bool {
    s2.wrapping_sub(s1) >= seq.wrapping_sub(s1)
}

/// Ce que garde le minuteur de transmission d'une connexion (`icsk_pending`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Minuteur {
    /// La retransmission (ICSK_TIME_RETRANS).
    Retransmission,
    /// La sonde de fenêtre nulle (ICSK_TIME_PROBE0).
    Sonde,
    /// La fenêtre de réordonnancement de RACK (ICSK_TIME_REO_TIMEOUT).
    Reordonnancement,
    /// La sonde de fin de rafale (ICSK_TIME_LOSS_PROBE).
    SondeDePerte,
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

/// Ce que dit `ack_desordonne` d'un segment qui a échoué PAWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Desordonne {
    Accepte,
    Refuse,
    VieilAck,
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
    /// Une charge neuve, pour `n` octets à recopier (`tcp_collapse`) ; None : plus de
    /// mémoire.
    fn neuve(n: usize) -> Option<Self> where Self: Sized;
    /// Ajoute ces octets à sa fin : la place a été prise par `neuve`.
    fn completer(&mut self, o: &[u8]);
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
    /// Le numéro de cet envoi, pour suivre ce paquet dans la file de la carte
    /// (`Tcb::poser_en_file`) ; 0 : il ne tient pas la socket (un ACK pur, un RST).
    pub numero: u64,
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
    /// TCP_DEFER_ACCEPT, en périodes de SYN-ACK (`rskq_defer_accept`).
    pub defer_accept: u32,
}

impl Reglages {
    /// Ceux de Linux : keepalive après 2 h de silence, une sonde toutes les
    /// 75 s, 9 sans réponse (TCP_KEEPALIVE_TIME, _INTVL, _PROBES).
    pub const DEFAUT: Reglages = Reglages {
        syn_essais: 0, delai_utilisateur: 0, orpheline: false, nodelay: false, cork: false, keepalive: false,
        keepidle: 7200 * 1_000_000_000, keepintvl: 75 * 1_000_000_000, keepcnt: 9, oobinline: false, defer_accept: 0,
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
    /// TCPI_OPT_TIMESTAMPS (1), TCPI_OPT_SACK (2) et TCPI_OPT_WSCALE (4), si en
    /// service.
    pub options: u8,
    pub echelle_envoi: u8,
    pub echelle_reception: u8,
    pub rto: u32,
    pub ato: u32,
    pub snd_mss: u32,
    pub rcv_mss: u32,
    /// Les segments en file (`packets_out`), ceux réputés arrivés hors d'ordre
    /// (`sacked_out`), réputés perdus (`lost_out`), renvoyés et encore en vol
    /// (`retrans_out`).
    pub non_acquittes: u32,
    pub sackes: u32,
    pub perdus: u32,
    pub retransmis: u32,
    pub dernier_envoi: u32,
    pub dernier_recu: u32,
    pub dernier_ack: u32,
    pub rtt: u32,
    pub rttvar: u32,
    pub ssthresh: u32,
    pub cwnd: u32,
    pub advmss: u32,
    /// La MTU du chemin (`tcpi_pmtu`).
    pub pmtu: u32,
    /// Ce qui borne la fenêtre annoncée (`tcpi_rcv_ssthresh`), et le plus que le
    /// programme ait lu en un RTT (`tcpi_rcv_space`).
    pub rcv_ssthresh: u32,
    pub rcv_space: u32,
    pub reordonnancement: u32,
    pub total_retrans: u32,
    /// Le RTT vu du récepteur (`tcpi_rcv_rtt`).
    pub rcv_rtt: u32,
    /// Le plus petit RTT récent (`tcpi_min_rtt`), les octets acquittés, les
    /// segments livrés, les doublons dits par D-SACK, les réordonnancements vus,
    /// les fenêtres, et les RTO.
    pub min_rtt: u32,
    pub octets_acquittes: u64,
    pub livres: u32,
    pub dsack_doublons: u32,
    pub reord_seen: u32,
    pub snd_wnd: u32,
    pub rcv_wnd: u32,
    pub total_rto: u32,
    /// Le débit calculé (`tcpi_pacing_rate`), en octets par seconde.
    pub pacing: u64,
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

impl Info {
    /// Ce que dit TCP_INFO d'une socket sans connexion (TCP_CLOSE) : les valeurs de
    /// départ de `tcp_init_sock` (mesuré ; pas les heures, que Linux y compte depuis
    /// l'origine de ses jiffies, et qui ne disent rien).
    pub fn sans_connexion() -> Info {
        Info {
            etat: 7,
            rto: (RTO_INITIAL / 1000) as u32,
            snd_mss: MSS_DEFAUT as u32,
            rttvar: (RTO_INITIAL / 4 / 1000) as u32,
            ssthresh: congestion::SSTHRESH_INFINI,
            cwnd: CWND_INITIALE,
            reordonnancement: TCP_REORDERING,
            min_rtt: u32::MAX,
            pacing: PACING_MAX,
            ..Info::default()
        }
    }

    /// Et d'une écoute (`tcp_get_info`, mesuré) : presque rien ; les filles prêtes
    /// et la longueur de sa file à la place de `tcpi_unacked` et `tcpi_sacked`.
    pub fn ecoute(pretes: u32, file: u32) -> Info {
        Info { etat: 10, non_acquittes: pretes, sackes: file, cwnd: CWND_INITIALE, reordonnancement: TCP_REORDERING, pacing: PACING_MAX, ..Info::default() }
    }
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
    /// La taille des segments de l'autre, estimée (`rcv_mss`), et celle du dernier
    /// segment plus petit (`last_seg_size`).
    rcv_mss: u32,
    dernier_segment: u32,
    /// ACK_POUSSE et ACK_POUSSE2 (ICSK_ACK_PUSHED, PUSHED2).
    pousse: u8,
    /// Un segment vient d'être jeté, faute de mémoire : le prochain ACK annonce une
    /// fenêtre nulle (ICSK_ACK_NOMEM).
    sans_memoire: bool,
    /// L'heure de la dernière arrivée de données (`lrcvtime`).
    lrcvtime: u64,
    /// L'échéance de l'ACK retardé.
    t: Option<u64>,
}

impl Ack {
    const fn new() -> Ack {
        Ack { programme: false, urgent: false, ato: 0, rapides: 0, pingpong: 0, rcv_mss: MSS_DEFAUT as u32, dernier_segment: 0, pousse: 0, sans_memoire: false, lrcvtime: 0, t: None }
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
    /// Une fille : son dernier ACK est arrivé, sans données, et attend sa fin de
    /// TCP_DEFER_ACCEPT (`inet_rsk(req)->acked`). Et la limite de ses SYN-ACK sous la
    /// charge (`reqsk_timer_handler`, posée par le noyau, qui voit toute la file).
    ack_differe: bool,
    essais_reduits: u32,
    /// Les programmes qui attendent dans `send` que la poignée de main finisse
    /// (`sk_write_pending`) : pas d'ACK seul, leurs données le porteront.
    pub ecrivains_en_attente: u32,
    // La réception.
    irs: u32,
    rcv_nxt: u32,
    /// La dernière fenêtre annoncée (`rcv_wnd`), et RCV.NXT à ce moment (`rcv_wup`) :
    /// son bord droit, rcv_wup + rcv_wnd, ne recule jamais (RFC 9293, 3.8.6.2.2).
    rcv_wnd: u32,
    rcv_wup: u32,
    /// `rcv_wnd` a été choisie (le premier SYN ou SYN-ACK : `tcp_select_initial_window`).
    fenetre_posee: bool,
    /// Ce qui borne la fenêtre (reception.rs) : `rcv_ssthresh`, `window_clamp`, et le
    /// rapport octets de données sur mémoire, sur 256 (`scaling_ratio`).
    rcv_ssthresh: u32,
    pub window_clamp: u32,
    ratio: u8,
    /// Le plus que le programme ait lu en un RTT (`rcvq_space`).
    espace: EspaceLu,
    /// Le MSS d'envoi (`mss_cache`) : celui de l'autre, borné par le nôtre et
    /// par TCP_MAXSEG, moins la place des options de tout segment
    /// (`tcp_sync_mss`).
    mss: u16,
    /// L'offre de l'autre, dans son SYN.
    mss_offre: Option<u16>,
    /// La plus grande charge que permet notre route (sa MTU moins 40).
    mss_route: u16,
    /// La charge qu'on dit pouvoir recevoir (`advmss`) : `mss_route` au départ,
    /// borné par TCP_MAXSEG à la première émission du SYN, et moins 12 quand les horodatages
    /// entrent en service.
    mss_local: u16,
    /// TCP_MAXSEG demandé (0 : rien).
    pub mss_utilisateur: u16,
    /// Les horodatages : proposés (avant le SYN de l'autre), ou en service
    /// (`tstamp_ok`). Ceux du segment en cours (`saw_tstamp`, `rcv_tsval`,
    /// `rcv_tsecr`, notre décalage retiré), l'heure de l'événement en cours
    /// (`tcp_mstamp`), et pour une fille, les TSval du premier et du dernier
    /// SYN-ACK (`snt_tsval_first`, `snt_tsval_last`).
    ts: Option<Horodatages>,
    ts_recu: Option<(u32, u32)>,
    heure: u64,
    ts_synack: Option<(u32, u32)>,
    /// La mesure du RTT par le récepteur (`rcv_rtt_est`) : RTT × 8, le numéro
    /// et l'heure de la fenêtre chronométrée ; et le dernier TSecr regardé
    /// (`rcv_rtt_last_tsecr`).
    rcv_rtt8: u64,
    rcv_rtt_seq: u32,
    rcv_rtt_debut: u64,
    rcv_rtt_tsecr: u32,
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
    // Ce que la carte a encore de cette connexion (`sk_wmem_alloc`, TSQ : carte.rs).
    /// Les octets (en taille vraie) qu'elle garde, et jusqu'à quel envoi elle a fini
    /// (`Tcb::poser_en_file`) ; le numéro du dernier envoi.
    en_file: usize,
    rendu: u64,
    envois: u64,
    /// Rien n'attend jamais dans une carte (`lo` : `skb_orphan` à l'émission).
    pub sans_file: bool,
    /// Il faudra pousser à la fin d'émission (TSQ_THROTTLED) ; et un `send` vient
    /// d'écrire : `tcp_push`, où l'autocork se décide.
    etrangle: bool,
    ecrit: bool,
    /// Le programme a voulu écrire plus que la place (`SOCK_NOSPACE`) : il attend,
    /// et sa limite est le tampon d'envoi, pas ce qu'il a à dire. Et un segment
    /// est arrivé depuis le dernier regard (`tcp_data_snd_check`).
    sans_place: bool,
    place_a_voir: bool,
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
    /// s'ils sont fixés par le programme (`SOCK_RCVBUF_LOCK`, `SOCK_SNDBUF_LOCK` :
    /// ils ne grandissent plus d'eux-mêmes), et leurs plafonds sur cette machine
    /// (`tcp_rmem[2]`, `tcp_wmem[2]`).
    pub rcvbuf: usize,
    pub sndbuf: usize,
    pub rcvbuf_fixe: bool,
    pub sndbuf_fixe: bool,
    pub rcvbuf_max: usize,
    pub sndbuf_max: usize,
    /// SO_RCVLOWAT (`sk_rcvlowat`), et si un programme tient cette connexion
    /// (`sk_socket` : ni une fille pas encore acceptée, ni une orpheline).
    pub rcvlowat: u32,
    pub attachee: bool,
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
    /// Un RST : son numéro, son ACK, ses drapeaux ; et s'il coupe la connexion
    /// (`tcp_send_active_reset`, avec nos options), plutôt qu'il ne répond à un
    /// segment refusé (`tcp_v4_send_reset`, sans).
    rst_du: Option<(u32, u32, u8)>,
    rst_actif: bool,
    /// Un ACK, tout de suite.
    ack_maintenant: bool,
    /// Ce qu'il faut renvoyer après un ACK, la tête de la file après un RTO, et
    /// la sonde de fin de rafale.
    rexmit: Rexmit,
    rto_du: bool,
    tlp_du: bool,
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
    /// L'heure du premier renvoi de l'épisode (`retrans_stamp`, 0 : aucun) ;
    /// pour le SYN, celle de son premier envoi. Les abandons comptent de là.
    retrans_stamp: u64,
    /// L'heure d'envoi du SYN ou du SYN-ACK tant qu'il n'a pas été renvoyé
    /// (Karn) : la première mesure du RTT.
    syn_envoi: Option<u64>,
    /// Le minuteur de transmission (`icsk_retransmit_timer`) : son échéance et
    /// ce qu'il garde.
    t_xmit: Option<u64>,
    t_sorte: Minuteur,
    /// Les sondes sans réponse (`icsk_probes_out`), et depuis quand on sonde
    /// (`icsk_probes_tstamp`).
    sondes: u32,
    sondes_debut: Option<u64>,
    /// L'échéance du keepalive.
    t_keepalive: Option<u64>,
    ack: Ack,
    cc: Congestion,
    // La file de retransmission (retrans.rs).
    file: VecDeque<Envoye>,
    /// `sacked_out`, `lost_out`, `retrans_out`.
    sacked_out: u32,
    lost_out: u32,
    retrans_out: u32,
    /// Le numéro de la première entrée à regarder pour un renvoi
    /// (`retransmit_skb_hint`) : la file peut être longue.
    indice_renvoi: Option<u32>,
    /// Le point de reprise (`high_seq`) : le plus loin qu'on avait envoyé au
    /// début de la reprise ou de la perte.
    high_seq: u32,
    /// Le seuil et la cwnd d'avant la réduction (`prior_ssthresh`,
    /// `prior_cwnd`), et ce que PRR a reçu et envoyé depuis (`prr_delivered`,
    /// `prr_out`).
    prior_ssthresh: u32,
    prior_cwnd: u32,
    prr_livres: u32,
    prr_sortis: u32,
    /// Le début de l'épisode qu'on pourrait annuler (`undo_marker`), les
    /// renvois pas encore démentis (`undo_retrans`), et F-RTO en cours (`frto`).
    undo_marker: Option<u32>,
    undo_retrans: i32,
    frto: bool,
    /// Les segments livrés et perdus depuis le début (`delivered`, `lost`) : leur
    /// différence, sur un ACK, règle la cwnd.
    livres: u32,
    perdus: u32,
    /// Le degré de réordonnancement estimé (`reordering`), et le nombre de fois
    /// qu'on en a vu (`reord_seen`).
    reordering: u32,
    reord_seen: u32,
    /// Tous les octets acquittés (`bytes_acked`).
    octets_acquittes: u64,
    // SACK et RACK (sack.rs).
    /// SACK : proposé (avant le SYN de l'autre), ou en service (`sack_ok`).
    sack_ok: bool,
    /// Ce qu'on dit à l'autre : les blocs (`selective_acks`), un doublon
    /// (`duplicate_sack`).
    blocs: [(u32, u32); tcp::BLOCS_MAX],
    nb_blocs: u8,
    dsack: Option<(u32, u32)>,
    /// La compression des ACK dupliqués (`compressed_ack`,
    /// `compressed_ack_rcv_nxt`, `dup_ack_counter`, et son minuteur).
    ack_comprimes: u32,
    comprime_rcv_nxt: u32,
    ack_dupliques: u32,
    t_comprime: Option<u64>,
    /// Ce qu'on sait de l'autre : le plus haut SACKé, les doublons qu'il a dits
    /// (`dsack_dups`), et s'il a oublié des SACK (`is_sack_reneg`).
    fack: u32,
    dsack_doublons: u32,
    sack_renie: bool,
    rack: Rack,
    min_rtt: MinMax,
    /// La sonde de fin de rafale en cours : SND.NXT à son envoi (`tlp_high_seq`),
    /// et si c'était un renvoi (`tlp_retrans`).
    tlp_high_seq: Option<u32>,
    tlp_renvoi: bool,
    /// La file par heure d'envoi (`tsorted_sent_queue`), nettoyée à la lecture,
    /// et l'heure d'envoi du dernier segment acquitté (`first_tx_mstamp`).
    tri: VecDeque<(u32, u64)>,
    tx_acquitte: u64,
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
            ack_differe: false,
            essais_reduits: u32::MAX,
            ecrivains_en_attente: 0,
            irs: 0,
            rcv_nxt: 0,
            rcv_wnd: 0,
            rcv_wup: 0,
            fenetre_posee: false,
            rcv_ssthresh: 0,
            window_clamp: 0,
            ratio: RATIO_DEFAUT,
            espace: EspaceLu { octets: 0, seq: 0, temps: 0 },
            mss: MSS_DEFAUT,
            mss_offre: None,
            mss_route: mss_local,
            mss_local,
            mss_utilisateur: 0,
            ts: None,
            ts_recu: None,
            heure: 0,
            ts_synack: None,
            rcv_rtt8: 0,
            rcv_rtt_seq: 0,
            rcv_rtt_debut: 0,
            rcv_rtt_tsecr: 0,
            envoi: VecDeque::new(),
            decalage_envoi: 0,
            octets_envoi: 0,
            seq_envoi: iss.wrapping_add(1),
            fin_voulue: false,
            en_file: 0,
            rendu: u64::MAX,
            envois: 0,
            sans_file: true,
            etrangle: false,
            ecrit: false,
            sans_place: false,
            place_a_voir: false,
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
            rcvbuf_fixe: false,
            sndbuf_fixe: false,
            rcvbuf_max: RCVBUF_MAX,
            sndbuf_max: SNDBUF_MAX,
            rcvlowat: 1,
            attachee: true,
            erreur: 0,
            erreur_douce: 0,
            lecture_fermee: false,
            dernier_ack_invalide: None,
            memoire: Memoire::Libre,
            syn_du: false,
            rst_du: None,
            rst_actif: false,
            ack_maintenant: false,
            rexmit: Rexmit::Rien,
            rto_du: false,
            tlp_du: false,
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
            retrans_stamp: 0,
            syn_envoi: None,
            t_xmit: None,
            t_sorte: Minuteur::Retransmission,
            sondes: 0,
            sondes_debut: None,
            t_keepalive: None,
            ack: Ack::new(),
            cc: Congestion::new(),
            file: VecDeque::new(),
            sacked_out: 0,
            lost_out: 0,
            retrans_out: 0,
            indice_renvoi: None,
            high_seq: iss,
            prior_ssthresh: 0,
            prior_cwnd: 0,
            prr_livres: 0,
            prr_sortis: 0,
            undo_marker: None,
            undo_retrans: -1,
            frto: false,
            livres: 0,
            perdus: 0,
            reordering: TCP_REORDERING,
            reord_seen: 0,
            octets_acquittes: 0,
            sack_ok: false,
            blocs: [(0, 0); tcp::BLOCS_MAX],
            nb_blocs: 0,
            dsack: None,
            ack_comprimes: 0,
            comprime_rcv_nxt: 0,
            ack_dupliques: 0,
            t_comprime: None,
            fack: iss,
            dsack_doublons: 0,
            sack_renie: false,
            rack: Rack::new(),
            min_rtt: MinMax::new(),
            tlp_high_seq: None,
            tlp_renvoi: false,
            tri: VecDeque::new(),
            tx_acquitte: 0,
            dernier_envoi: 0,
            dernier_recu: 0,
        }
    }

    /// Propose les horodatages dans le SYN de `connect` (`tcp_timestamps`) :
    /// `decalage`, notre décalage (`secure_tcp_ts_off`). Sans cet appel, la
    /// connexion n'en propose pas.
    pub fn proposer_horodatages(&mut self, decalage: u32) {
        self.ts = Some(Horodatages { recent: 0, instant: 0, decalage });
    }

    /// Le `connect` reprend le quadruplet d'une entrée de TIME_WAIT
    /// (`tcp_twsk_unique`) : la neuve garde son dernier TSval reçu, à quoi
    /// PAWS comparera ce que l'autre enverra.
    pub fn reprendre_horodatages(&mut self, ts: Horodatages) {
        if let Some(n) = self.ts.as_mut() {
            n.recent = ts.recent;
            n.instant = ts.instant;
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
    /// sienne. Les horodatages, s'il les a proposés ; le noyau pose notre
    /// décalage par `decalage_horodatages`, avant d'émettre.
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
        t.ts = syn.options.horodatage.map(|(val, _)| Horodatages { recent: val, instant: 0, decalage: 0 });
        t.sack_ok = syn.options.sack_permis;
        t.mss_offre = syn.options.mss;
        t.synchroniser_mss();
        t.rcv_wup = t.rcv_nxt;
        t.syn_du = true;
        t
    }

    /// Le décalage de nos horodatages, pour une fille (`tcp_v4_init_ts_off`).
    pub fn decalage_horodatages(&mut self, decalage: u32) {
        if let Some(t) = self.ts.as_mut() {
            t.decalage = decalage;
        }
    }

    /// TCP_MAXSEG d'une fille, hérité de son écoute : il borne son MSS d'envoi.
    pub fn poser_mss_utilisateur(&mut self, mss: u16) {
        self.mss_utilisateur = mss;
        self.synchroniser_mss();
    }

    pub fn etat(&self) -> Etat {
        self.etat
    }

    /// Le contrôle de congestion d'une connexion qui naît (`tcp_assign_congestion_control`,
    /// `tcp_ca_openreq_child`).
    pub fn poser_controle(&mut self, c: Controle) {
        self.cc.choisir(c, false, self.snd_nxt, self.heure);
    }

    /// Le contrôle en service (TCP_CONGESTION).
    pub fn controle(&self) -> Controle {
        self.cc.controle()
    }

    /// TCP_CONGESTION sur une connexion en route (`tcp_reinit_congestion_control`).
    pub fn choisir_controle(&mut self, c: Controle, maintenant: u64) {
        if c != self.cc.controle() {
            self.prior_ssthresh = 0;
            self.cc.choisir(c, self.etat != Etat::Fermee, self.snd_nxt, maintenant);
        }
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
                if self.window_clamp != 0 {
                    self.window_clamp = self.window_clamp.min(FENETRE_MAX);
                }
            }
        }
    }

    /// SND.UNA, SND.NXT et RCV.NXT (/proc/net/tcp, TIME_WAIT, les erreurs
    /// ICMP, les tests).
    pub fn numeros(&self) -> (u32, u32, u32) {
        (self.snd_una, self.snd_nxt, self.rcv_nxt)
    }

    /// La fenêtre de congestion et le seuil, en segments ; le RTO courant
    /// (TCP_INFO, les tests).
    pub fn congestion(&self) -> (u32, u32, u64) {
        (self.cc.cwnd, self.cc.ssthresh, self.rto)
    }

    /// La MTU du chemin a changé (`tcp_sync_mss`) : le MSS suit, dans les deux sens
    /// (`tcp_current_mss` : une exception qui expire le fait remonter).
    pub fn verifier_mtu(&mut self, mtu: u32) {
        if self.mss_route as u32 + 40 != mtu {
            self.mss_route = mtu.saturating_sub(40).min(u16::MAX as u32) as u16;
            self.synchroniser_mss();
        }
    }

    /// `tcp_v4_mtu_reduced` : ICMP dit `info`, et la route dit maintenant `mtu`.
    /// Plus bas que ce que dit la route (sous le plancher), et DF : une erreur douce, que
    /// rendra un abandon. Plus bas que ce qu'on suppose (`suivre` : ni IP_PMTUDISC_DONT, ni
    /// INTERFACE, ni OMIT) : le MSS baisse, et ce qui est en vol et trop gros est perdu :
    /// renvoyé tout de suite, découpé (`tcp_simple_retransmit`).
    pub fn mtu_reduite(&mut self, info: u32, mtu: u32, ne_pas_fragmenter: bool, suivre: bool) -> Effets {
        let mut e = Effets::default();
        if self.etat == Etat::Fermee {
            return e;
        }
        if info < mtu && ne_pas_fragmenter {
            self.erreur_douce = EMSGSIZE;
        }
        if suivre && self.mss_route as u32 + 40 > mtu {
            self.verifier_mtu(mtu);
            self.renvoyer_trop_longs();
            e.a_emettre = true;
        }
        e
    }

    /// Le MSS d'envoi (`tcp_sync_mss`, `__tcp_mtu_to_mss`) : l'offre de l'autre
    /// (536 s'il ne dit rien, ou dit 0 : `tcp_parse_options` l'ignore), bornée
    /// par notre route et par TCP_MAXSEG, jamais sous MSS_ENVOI_MIN, moins la
    /// place des horodatages (`tcp_mtu_to_mss` : ils sont dans chaque segment,
    /// et l'offre de l'autre compte les options).
    fn synchroniser_mss(&mut self) {
        let mut m = self.mss_offre.filter(|&o| o != 0).unwrap_or(MSS_DEFAUT).min(self.mss_route);
        if self.mss_utilisateur != 0 {
            m = m.min(self.mss_utilisateur);
        }
        self.mss = m.max(MSS_ENVOI_MIN) - if self.ts.is_some() { TS_ALIGNE } else { 0 };
    }

    /// Ce que rend TCP_MAXSEG : le MSS d'envoi une fois la connexion
    /// établie (`mss_cache`, borné à la moitié de la plus grande fenêtre de
    /// l'autre) ; avant, ce qu'a demandé le programme, ou 536 (mesuré).
    pub fn mss(&self) -> u16 {
        if self.etat.synchronise() {
            self.mss_borne() as u16
        } else if self.mss_utilisateur != 0 {
            self.mss_utilisateur
        } else {
            MSS_DEFAUT
        }
    }

    /// Le MSS, sauf face à un récepteur minuscule : la moitié de la plus grande
    /// fenêtre qu'il ait annoncée (`tcp_bound_to_half_wnd`, au moins 68 octets
    /// d'IP moins les en-têtes de TCP) : sinon un segment plein ne tiendrait
    /// jamais dans sa fenêtre, et rien ne partirait.
    fn mss_borne(&self) -> u32 {
        let mss = self.mss as u32;
        let coupure = if self.max_fenetre > MSS_DEFAUT as u32 { self.max_fenetre / 2 } else { self.max_fenetre };
        let plancher = 48 - if self.ts.is_some() { TS_ALIGNE as u32 } else { 0 };
        if coupure > 0 && mss > coupure { coupure.max(plancher) } else { mss }
    }

    /// La taille des segments qu'on envoie (`tcp_current_mss`) : les blocs SACK
    /// du prochain segment prennent leur place.
    fn mss_courant(&self) -> u32 {
        self.mss_borne().saturating_sub(self.place_des_blocs()).max(1)
    }

    /// La charge qu'annonce notre SYN (`tcp_advertise_mss`, `tcp_mss_clamp`).
    fn mss_annonce(&self) -> u16 {
        if self.mss_utilisateur != 0 { self.mss_local.min(self.mss_utilisateur) } else { self.mss_local }
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

    /// Le programme a lu `copie` octets (`tcp_rcv_space_adjust`, `tcp_cleanup_rbuf`) :
    /// SO_RCVBUF suit ce débit ; et un ACK part tout de suite si un ACK dû attend
    /// plus d'un segment plein (`verifier_ack` l'avait retardé parce que la fenêtre
    /// n'avançait pas), si cette lecture a vidé la file après un petit segment (l'autre
    /// attend peut-être cet ACK pour continuer, hors d'une conversation), ou si la
    /// fenêtre qu'on pourrait annoncer a au moins doublé depuis la dernière annonce
    /// (sans cela, un émetteur bloqué par une fenêtre nulle attendrait sa prochaine
    /// sonde).
    pub fn lu(&mut self, copie: usize, maintenant: u64) -> Effets {
        self.ajuster_espace(maintenant);
        if !self.etat.synchronise() && self.etat != Etat::SynRecu {
            return Effets::default();
        }
        let mut tout_de_suite = false;
        if self.ack.programme {
            let pousse = self.ack.pousse & ACK_POUSSE2 != 0 || (self.ack.pousse & ACK_POUSSE != 0 && self.ack.pingpong == 0);
            tout_de_suite = self.rcv_nxt.wrapping_sub(self.rcv_wup) > self.ack.rcv_mss || (copie > 0 && pousse && self.memoire_reception() == 0);
        }
        if copie > 0 && !tout_de_suite && !self.fin_recue && !self.lecture_fermee {
            let annoncee = self.fenetre_restante();
            if 2 * annoncee as u64 <= self.window_clamp as u64 {
                let neuve = self.choisir_fenetre();
                tout_de_suite = neuve != 0 && neuve as u64 >= 2 * annoncee as u64;
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
        // (`sk_wmem_schedule` qui échoue, sauf pour un tampon vide : `sk_forced_mem_schedule`.)
        if (self.memoire == Memoire::Limite && self.octets_envoi > 0) || (self.memoire == Memoire::Excedent && self.octets_envoi >= WMEM0) {
            return 0;
        }
        self.sndbuf.saturating_sub(self.octets_envoi)
    }

    /// `poll` a trouvé le tampon d'envoi trop plein (`tcp_poll`, SOCK_NOSPACE).
    pub fn marquer_sans_place(&mut self) {
        self.sans_place = true;
    }

    /// `tcp_check_space`, après chaque segment neuf envoyé et chaque segment reçu :
    /// pour un programme qui attend de la place, SO_SNDBUF suit la cwnd
    /// (`tcp_new_space`), si elle n'est pas pleine ; et il n'attend plus quand un
    /// tiers du tampon est libre (`sk_stream_write_space`).
    fn verifier_place(&mut self, maintenant: u64) {
        if !self.sans_place {
            return;
        }
        if !self.sndbuf_fixe && self.memoire == Memoire::Libre && self.paquets_en_vol() < self.cc.cwnd {
            self.agrandir_sndbuf();
            self.cc.poser_instant(maintenant);
        }
        if self.place() >= self.sndbuf / 3 {
            self.sans_place = false;
        }
    }

    /// La mémoire que garde la connexion, en octets : la réception (en
    /// taille vraie) et ce qui attend d'être acquitté (le compte de
    /// `tcp_mem`).
    pub fn memoire(&self) -> usize {
        self.memoire_reception() + self.octets_envoi
    }

    /// Le numéro qui suit tout ce que le programme a écrit, FIN compris
    /// (`write_seq`).
    fn write_seq(&self) -> u32 {
        self.seq_envoi.wrapping_add(self.octets_envoi as u32).wrapping_add(u32::from(self.fin_voulue))
    }

    /// Les octets pas encore acquittés (SIOCOUTQ) et pas encore envoyés
    /// (SIOCOUTQNSD), FIN compris, comme `tcp_ioctl`, rien pendant la poignée
    /// de main.
    pub fn non_acquittes(&self) -> usize {
        if !self.syn_acquitte { 0 } else { self.write_seq().wrapping_sub(self.snd_una) as usize }
    }

    pub fn non_envoyes(&self) -> usize {
        if !self.syn_acquitte { 0 } else { self.write_seq().wrapping_sub(self.snd_nxt) as usize }
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
        if n > self.place() {
            self.sans_place = true;
        }
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
            self.ecrit = true;
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
    /// puis fermée (`tcp_disconnect`, `tcp_send_active_reset`).
    pub fn avorter(&mut self) -> Effets {
        let mut e = Effets::default();
        if matches!(self.etat, Etat::Etablie | Etat::AttenteFermeture | Etat::FinAttente1 | Etat::FinAttente2 | Etat::SynRecu) {
            self.rst_du = Some((self.seq_acceptable(), self.rcv_nxt, tcp::RST | tcp::ACK));
            self.rst_actif = true;
            e.a_emettre = true;
        }
        self.passer(Etat::Fermee, &mut e);
        e
    }

    /// `close` avec des données non lues (`tcp_close`) : un RST, quel que soit l'état : ni
    /// LAST_ACK ni CLOSING n'y échappent, à la différence de `tcp_disconnect`.
    pub fn avorter_sur_donnees(&mut self) -> Effets {
        let mut e = Effets::default();
        if self.etat != Etat::Fermee {
            self.rst_du = Some((self.seq_acceptable(), self.rcv_nxt, tcp::RST | tcp::ACK));
            self.rst_actif = true;
            e.a_emettre = true;
        }
        self.passer(Etat::Fermee, &mut e);
        e
    }

    /// L'état au moment de `tcp_disconnect` : faut-il un RST, et une erreur en attente
    /// (`tcp_need_reset`, ce qui reste à envoyer en CLOSING et LAST_ACK) ? Et sans RST, une erreur
    /// (`TCP_SYN_SENT`).
    pub fn deconnexion(&self) -> (bool, bool) {
        let rst = matches!(self.etat, Etat::Etablie | Etat::AttenteFermeture | Etat::FinAttente1 | Etat::FinAttente2 | Etat::SynRecu)
            || (matches!(self.etat, Etat::Fermeture | Etat::DernierAck) && self.snd_nxt != self.write_seq());
        (rst, rst || self.etat == Etat::SynEnvoye)
    }

    /// Le numéro d'un segment sans données, ACK ou RST (`tcp_acceptable_seq`) :
    /// SND.NXT, sauf si l'autre a réduit sa fenêtre en deçà (de plus que
    /// l'arrondi de son échelle) : alors son bord droit.
    fn seq_acceptable(&self) -> u32 {
        let bord = self.snd_una.wrapping_add(self.snd_wnd);
        if !avant(bord, self.snd_nxt) || (self.echelle_ok && self.snd_nxt.wrapping_sub(bord) < (1 << self.echelle_reception)) {
            self.snd_nxt
        } else {
            bord
        }
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
            self.t_xmit = None;
            self.t_keepalive = None;
            self.ack.t = None;
            self.t_comprime = None;
            self.hors_ordre.vider();
            self.fin_hors_ordre = None;
            self.nb_blocs = 0;
            self.dsack = None;
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
        self.file.clear();
        self.sacked_out = 0;
        self.lost_out = 0;
        self.retrans_out = 0;
        self.indice_renvoi = None;
        self.tri.clear();
        self.passer(Etat::Fermee, e);
        e.lisible = true;
        e.place = true;
    }

    // --- Les segments reçus ---

    /// La fenêtre de réception annoncée.
    pub fn fenetre_annoncee(&self) -> u32 {
        self.fenetre_restante()
    }

    /// L'entrée de TIME_WAIT de cette connexion (`tcp_time_wait`) ;
    /// `fin_attente2` : une orpheline qui attend encore le FIN de l'autre.
    pub fn en_attente(&self, fin_attente2: bool) -> Attente {
        Attente::new(self.port_local, self.port_distant, self.snd_nxt, self.rcv_nxt, self.fenetre_restante(), self.echelle_reception, fin_attente2, self.ts, self.heure)
    }

    /// Ce qui reste de la fenêtre annoncée tient-il en un segment de
    /// l'autre (`tcp_receive_window(tp) <= icsk_ack.rcv_mss`), ou la mémoire
    /// presse-t-elle (`tcp_rmem_pressure`) ? Alors poll dit POLLIN même sous
    /// SO_RCVLOWAT : l'autre ne peut plus rien envoyer avant qu'on lise.
    pub fn fenetre_presque_fermee(&self) -> bool {
        self.fenetre_restante() <= self.ack.rcv_mss || self.reception_pressee()
    }

    /// Un segment de `seq` à `fin_seq` est-il acceptable (`tcp_sequence`) ?
    /// Le bord gauche est `rcv_wup`, pas RCV.NXT (l'autre n'a pas encore vu
    /// l'ACK de ce que nous avons reçu depuis : un RST ou un ACK qu'il envoie
    /// peut porter ce numéro-là). Linux ne suit pas le tableau de la RFC 9293
    /// (3.10.7.4) pour le bord droit : un segment à cheval passe, mais
    /// seulement si la file de réception est vide (sinon, un récepteur lent
    /// verrait grandir sa mémoire au-delà de ce qu'il a annoncé).
    fn acceptable(&self, seq: u32, fin_seq: u32) -> bool {
        if avant(fin_seq, self.rcv_wup) {
            return false;
        }
        let bord = self.rcv_nxt.wrapping_add(self.fenetre_restante());
        !apres(fin_seq, bord) || (!apres(seq, bord) && self.reception.is_empty())
    }

    /// Un RST au numéro RCV.NXT - 1 vaut aussi après le FIN de l'autre
    /// (`tcp_reset_check`) : certains systèmes coupent ainsi une connexion,
    /// un FIN puis un RST du même numéro.
    fn rst_apres_fin(&self, seq: u32) -> bool {
        seq == self.rcv_nxt.wrapping_sub(1) && matches!(self.etat, Etat::AttenteFermeture | Etat::DernierAck | Etat::Fermeture)
    }

    /// Un RST accepté (`tcp_reset`) : l'erreur que voit le programme, comme
    /// BSD. La connexion se ferme ; ce qui avait été reçu se lit encore.
    fn reinitialiser(&mut self, e: &mut Effets) {
        let erreur = if self.etat == Etat::AttenteFermeture { EPIPE } else { ECONNRESET };
        self.finir(erreur, e);
    }

    /// Un segment pour une fille encore en SYN_RECEIVED (`tcp_check_req`,
    /// dans son ordre, qui n'est pas celui d'une connexion). Rend vrai si la
    /// poignée de main est finie : ce segment la fait entrer dans ESTABLISHED
    /// et continue comme tout segment.
    fn verifier_fille(&mut self, t: &Tcp, longueur_charge: u32, maintenant: u64, e: &mut Effets) -> bool {
        let drapeaux = t.drapeaux & (tcp::RST | tcp::SYN | tcp::ACK);
        let (syn, fin) = (t.drapeaux & tcp::SYN != 0, t.drapeaux & tcp::FIN != 0);
        let fin_seq = t.seq.wrapping_add(longueur_charge + u32::from(syn) + u32::from(fin));
        // Les horodatages : PAWS, et un TSecr qui n'est aucun de ceux de nos
        // SYN-ACK (nouveau en 6.18, `tsecr_reject`). La fille n'a pas retenu
        // l'heure de son `ts_recent` : Linux l'estime, à l'heure de son prochain
        // SYN-ACK en arrière (`reqsk_timeout`).
        let (mut rejet_paws, mut rejet_tsecr) = (false, false);
        if let (Some(ts), Some((val, ecr))) = (self.ts, t.options.horodatage) {
            if ecr != 0
                && let Some((premier, dernier)) = self.ts_synack
            {
                rejet_tsecr = !entre(ecr, premier, dernier);
            }
            let estime = Horodatages { instant: maintenant.saturating_sub(self.rto), ..ts };
            rejet_paws = paws_rejet(&estime, val, drapeaux & tcp::RST != 0, maintenant);
        }
        // Le SYN répété, seul : notre SYN-ACK a dû se perdre. Il repart, le
        // minuteur repart aussi (« comme une retransmission rapide »), sauf
        // limite des réponses à ce qui n'a rien à faire ici.
        if t.seq == self.irs && drapeaux == tcp::SYN && !rejet_paws {
            if !self.ack_invalide_limite(maintenant) {
                self.syn_du = true;
                self.syn_envoi = None;
                self.total_retrans += 1;
                self.armer_rto(maintenant);
                e.a_emettre = true;
            }
            return false;
        }
        // Un ACK qui n'acquitte pas notre SYN : pour Linux, le segment repart
        // vers l'écoute, qui répond RST (sauf à un RST) ; la fille reste.
        if drapeaux & tcp::ACK != 0 && t.ack != self.iss.wrapping_add(1) {
            if drapeaux & tcp::RST == 0 {
                self.rst_du = Some((t.ack, 0, tcp::RST));
                e.a_emettre = true;
            }
            return false;
        }
        // Hors de la fenêtre, ou rejeté : un ACK (limité, sauf s'il porte des
        // données).
        if rejet_paws || rejet_tsecr || !dans_la_fenetre(t.seq, fin_seq, self.rcv_nxt, self.rcv_nxt.wrapping_add(self.rcv_wnd.min(FENETRE_MAX))) {
            if drapeaux & tcp::RST == 0 && ((fin_seq != t.seq && !syn) || !self.ack_invalide_limite(maintenant)) {
                self.ack_maintenant = true;
                e.a_emettre = true;
            }
            return false;
        }
        // Le SYN d'origine dans un segment de la fenêtre (un SYN-ACK) ne
        // compte plus ; un autre SYN, ou un RST, défait la fille : RST
        // (pas à un RST), sans rien dire à personne.
        let sans_syn = if t.seq == self.irs { drapeaux & !tcp::SYN } else { drapeaux };
        if sans_syn & (tcp::RST | tcp::SYN) != 0 {
            if sans_syn & tcp::RST == 0 {
                self.rst_du = Some(if drapeaux & tcp::ACK != 0 { (t.ack, 0, tcp::RST) } else { (0, fin_seq, tcp::RST | tcp::ACK) });
                e.a_emettre = true;
            }
            self.passer(Etat::Fermee, e);
            return false;
        }
        if sans_syn & tcp::ACK == 0 {
            return false;
        }
        // TCP_DEFER_ACCEPT : un ACK sans rien avec lui ne fait pas naître la connexion : un
        // serveur qui écrit le premier n'a pas à être réveillé pour rien. Passée la période,
        // le prochain ACK la fait naître.
        if self.retransmissions < self.reglages.defer_accept && fin_seq == self.irs.wrapping_add(1) {
            self.ack_differe = true;
            return false;
        }
        // La connexion naît (`tcp_create_openreq_child`).
        if let Some(ts) = self.ts.as_mut() {
            ts.instant = maintenant;
        }
        true
    }

    /// Un segment refusé reçoit un ACK (`tcp_send_dupack`), limité s'il ne
    /// porte pas de données (`tcp_oow_rate_limited`) ; des données déjà reçues
    /// disent que notre ACK s'est perdu : le mode « quickack ».
    fn repondre_doublon(&mut self, seq: u32, longueur: u32, syn: bool, maintenant: u64, e: &mut Effets) {
        if longueur > 0 && !syn && avant(seq, self.rcv_nxt) {
            self.entrer_mode_rapide();
            let fin = seq.wrapping_add(longueur);
            self.poser_doublon(seq, if apres(fin, self.rcv_nxt) { self.rcv_nxt } else { fin });
        }
        if (longueur > 0 && !syn) || !self.ack_invalide_limite(maintenant) {
            self.ack_maintenant = true;
            e.a_emettre = true;
        }
    }

    /// `tcp_disordered_ack_check` : un segment qui échoue PAWS passe quand même
    /// si c'est un ACK pur, au bord gauche, dupliqué, qui ne change pas la
    /// fenêtre, et dont TSval n'a reculé que de moins d'un RTO (`tcp_tsval_replay`,
    /// en unités de 1/1200 s, l'horloge la plus rapide que Linux suppose à
    /// l'autre) : l'ACK d'un segment et celui du suivant se croisent souvent.
    /// Rend aussi vrai pour un ACK pur plus vieux que le bord gauche, jeté sans
    /// réponse par l'appelant (`PAWS_OLD_ACK`).
    fn ack_desordonne(&self, t: &Tcp, val: u32, fin_seq: u32) -> Desordonne {
        if t.drapeaux & tcp::ACK == 0 || t.seq != fin_seq {
            return Desordonne::Refuse;
        }
        if t.seq != self.rcv_nxt {
            return if avant(t.seq, self.rcv_nxt) { Desordonne::VieilAck } else { Desordonne::Refuse };
        }
        if t.ack != self.snd_una || self.fenetre_a_jour(t) {
            return Desordonne::Refuse;
        }
        let rejeu = (self.rto / 1_000 * 1200 / 1_000_000) as i64;
        match self.ts {
            Some(ts) if (ts.recent.wrapping_sub(val) as i32 as i64) <= rejeu => Desordonne::Accepte,
            _ => Desordonne::Refuse,
        }
    }

    /// Reçoit le segment `t`, de charge `charge` (vide pour un segment sans
    /// données), à l'heure `maintenant`, dans l'ordre de la RFC 9293
    /// (3.10.7) et de `tcp_rcv_state_process`.
    pub fn recevoir(&mut self, t: &Tcp, charge: P, maintenant: u64) -> Effets {
        let mut e = Effets::default();
        self.heure = maintenant;
        self.place_a_voir = true;
        // Les horodatages du segment, seulement s'ils sont en service (ou
        // proposés, pour le SYN de l'autre), notre décalage retiré de TSecr.
        self.ts_recu = self.ts.and(t.options.horodatage).map(|(val, ecr)| (val, if ecr != 0 { ecr.wrapping_sub(self.ts.map_or(0, |x| x.decalage)) } else { 0 }));
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
                if ack && (!apres(t.ack, self.iss) || apres(t.ack, self.snd_nxt)) {
                    if !rst {
                        self.rst_du = Some((t.ack, 0, tcp::RST));
                        e.a_emettre = true;
                    }
                    return e;
                }
                // Un SYN-ACK dont TSecr n'est pas entre notre premier SYN et
                // maintenant : RST (`PAWSACTIVEREJECTED`).
                if ack
                    && let Some((_, ecr)) = self.ts_recu
                    && ecr != 0
                    && !entre(ecr, horloge_ts(self.retrans_stamp), horloge_ts(maintenant))
                {
                    // (`reset_and_undo` passe par `tcp_v4_send_reset` : pas de RST pour un RST.)
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
                self.rcv_wup = self.rcv_nxt;
                self.mss_offre = t.options.mss;
                self.accepter_echelle(t.options.echelle);
                self.sack_ok &= t.options.sack_permis;
                // Les horodatages n'entrent en service que si l'autre les porte
                // aussi.
                match self.ts_recu {
                    Some((val, _)) => {
                        if let Some(ts) = self.ts.as_mut() {
                            ts.retenir(val, maintenant);
                        }
                    }
                    None => self.ts = None,
                }
                self.synchroniser_mss();
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
                    self.syn_renvoye_pour_rien();
                    self.mesurer_syn(maintenant);
                    self.maj_pacing(self.mss_borne());
                    self.retransmissions = 0;
                    self.retrans_stamp = 0;
                    self.t_xmit = None;
                    self.passer(Etat::Etablie, &mut e);
                    self.etablir(maintenant);
                    // L'ACK de la poignée de main part tout de suite ; sauf si
                    // des données vont le porter (`tcp_rcv_synsent_state_process` : un
                    // programme qui attend d'écrire, TCP_DEFER_ACCEPT, TCP_QUICKACK à 0) :
                    // il attend alors au plus 200 ms.
                    if self.ecrivains_en_attente > 0 || self.reglages.defer_accept != 0 || self.ack.pingpong > 0 {
                        self.ack.programme = true;
                        self.entrer_mode_rapide();
                        self.ack.t = Some(maintenant + DELACK_MAX);
                    } else {
                        self.ack_maintenant = true;
                    }
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
        // La fille d'une écoute a ses propres règles jusqu'au troisième ACK.
        if self.etat == Etat::SynRecu && self.fille && !self.verifier_fille(t, longueur_charge, maintenant, &mut e) {
            return e;
        }
        // L'ouverture simultanée, et la fille : en SYN_RECEIVED, le SYN-ACK
        // de l'autre, qui acquitte notre SYN, vaut un ACK (son SYN déjà reçu
        // est ignoré : le `goto pass` de `tcp_validate_incoming`).
        let mut syn = syn;
        let mut seq = t.seq;
        if self.etat == Etat::SynRecu && syn && ack && t.seq.wrapping_add(1) == self.rcv_nxt && t.ack == self.snd_nxt {
            syn = false;
            seq = self.rcv_nxt;
        }
        let longueur = longueur_charge + u32::from(syn) + u32::from(fin);
        let fin_seq = seq.wrapping_add(longueur);
        // PAWS, avant tout (`tcp_validate_incoming`) : un segment dont TSval est
        // plus vieux que le dernier vu vient d'une autre époque de ces numéros.
        // Un RST passe toujours ici : c'est sa propre règle qui le jugera. Un
        // SYN reçoit l'ACK de défi ; un vieil ACK pur, rien (ils sont fréquents,
        // et sans danger) ; le reste, un ACK limité.
        if let (Some(ts), Some((val, _))) = (self.ts, self.ts_recu)
            && !paws_controle(&ts, val, PAWS_FENETRE, maintenant)
            && !rst
        {
            match self.ack_desordonne(t, val, fin_seq) {
                Desordonne::Accepte => {}
                Desordonne::VieilAck => return e,
                Desordonne::Refuse => {
                    self.repondre_doublon(seq, longueur, syn, maintenant, &mut e);
                    return e;
                }
            }
        }
        // 1. Le numéro de séquence. Hors de la fenêtre : un ACK, tout de
        // suite (`tcp_send_dupack`).
        if !self.acceptable(seq, fin_seq) {
            if rst {
                if self.rst_apres_fin(t.seq) {
                    self.reinitialiser(&mut e);
                }
            } else {
                self.repondre_doublon(seq, longueur, syn, maintenant, &mut e);
            }
            return e;
        }
        // 2. RST (RFC 5961 : exactement au bord gauche ; sinon, dans la
        // fenêtre, un ACK « de défi », limité comme ci-dessus).
        if rst {
            // Le bord du bloc SACK le plus à droite vaut aussi (`tcp_validate_incoming`).
            let bord_sack = self.blocs[..self.nb_blocs as usize].iter().map(|b| b.1).reduce(|a, b| if apres(b, a) { b } else { a });
            if t.seq == self.rcv_nxt || self.rst_apres_fin(t.seq) || bord_sack == Some(t.seq) {
                self.reinitialiser(&mut e);
            } else if !self.ack_invalide_limite(maintenant) {
                self.ack_maintenant = true;
                e.a_emettre = true;
            }
            return e;
        }
        // 4. SYN dans une connexion synchronisée : un ACK de défi (RFC 5961,
        // 4.2).
        if syn {
            if !self.ack_invalide_limite(maintenant) {
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
            if apres(t.ack, self.snd_una) && !apres(t.ack, self.snd_nxt) {
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
        // `FLAG_NO_CHALLENGE_ACK` : hors d'ESTABLISHED, c'est la suite qui répond
        // à un ACK rejeté (`tcp_rcv_state_process`, « accept old ack during
        // closing »).
        let hors_etablie = self.etat != Etat::Etablie;
        let drapeaux = if hors_etablie { FLAG_NO_CHALLENGE_ACK } else { 0 } | if longueur > 0 { FLAG_DATA } else { 0 };
        if self.traiter_ack(t, drapeaux, maintenant, &mut e) == ResultatAck::Rejete {
            if hors_etablie && !self.ack_invalide_limite(maintenant) {
                self.ack_maintenant = true;
                e.a_emettre = true;
            }
            return e;
        }
        if etablissement {
            self.syn_renvoye_pour_rien();
            self.mesurer_syn(maintenant);
            self.etablir(maintenant);
            self.maj_pacing(self.mss_borne());
        }
        self.apres_notre_fin(&mut e);
        if self.etat == Etat::Fermee {
            return e;
        }
        self.rtt_reception_ts(fin_seq.wrapping_sub(seq), maintenant);
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
        // 7. Le texte (`tcp_rcv_state_process`). Après le FIN de l'autre, ce
        // qui vient de plus loin est ignoré ; un doublon reçoit son ACK, comme
        // dans les états qui reçoivent encore. Pour une lecture fermée, en
        // FIN_WAIT, des données neuves coupent la connexion : RST, comme BSD
        // et Linux (« RFC 793 says to queue data in these states, RFC 1122
        // says we MUST send a reset ») ; l'autre apprend que ce qu'il envoie
        // ne sera jamais lu.
        let recoit = self.etat.recoit() || avant(seq, self.rcv_nxt);
        if recoit && self.etat != Etat::Etablie && (self.lecture_fermee || self.fin_recue) && longueur > 0 && apres(seq.wrapping_add(longueur_charge), self.rcv_nxt) {
            self.rst_du = Some((t.ack, 0, tcp::RST));
            self.reinitialiser(&mut e);
            e.a_emettre = true;
            return e;
        }
        if recoit {
            self.recevoir_texte(t, seq, charge, fin, maintenant, &mut e);
        }
        if self.fin_hors_ordre == Some(self.rcv_nxt) && self.etat.recoit() {
            self.fin_hors_ordre = None;
            self.recevoir_fin(&mut e);
        }
        self.verifier_ack(maintenant);
        if self.ack_maintenant {
            e.a_emettre = true;
        }
        e
    }

    /// L'ACK d'un segment acceptable (`tcp_ack`, dans son ordre) : la fenêtre
    /// de l'autre, ce qui est acquitté, les blocs SACK, la mesure du RTT, le
    /// minuteur de retransmission, l'état de la reprise, la congestion. `flag` :
    /// les FLAG_ que connaît déjà l'appelant.
    fn traiter_ack(&mut self, t: &Tcp, mut flag: u32, maintenant: u64, e: &mut Effets) -> ResultatAck {
        let una_avant = self.snd_una;
        let packets_avant = self.file.len();
        let (livres_avant, perdus_avant) = (self.livres, self.perdus);
        let a_des_blocs = self.sack_ok && t.options.nb_blocs > 0;
        let mut etat = EtatSack::default();
        if avant(t.ack, una_avant) {
            // RFC 5961 5.2 : un ACK plus vieux que ce qu'on a jamais pu avoir
            // envoyé dans la fenêtre : une injection à l'aveugle.
            let max_fenetre = (self.max_fenetre as u64).min(self.octets_acquittes) as u32;
            if avant(t.ack, una_avant.wrapping_sub(max_fenetre)) {
                if flag & FLAG_NO_CHALLENGE_ACK == 0 && !self.ack_invalide_limite(maintenant) {
                    self.ack_maintenant = true;
                    e.a_emettre = true;
                }
                return ResultatAck::Rejete;
            }
            // Ses blocs valent encore.
            if a_des_blocs {
                flag |= self.marquer_blocs(t, una_avant, &mut etat, maintenant);
                self.alerte(una_avant, 0, &mut flag, maintenant);
                if self.rexmit != Rexmit::Rien {
                    e.a_emettre = true;
                }
            }
            return ResultatAck::Vieux;
        }
        // Il acquitte ce qui n'a jamais été envoyé : le segment est jeté, sans
        // réponse (RFC 793 3.9 le veut, ici ; RFC 9293 dit d'envoyer un ACK).
        if apres(t.ack, self.snd_nxt) {
            return ResultatAck::Rejete;
        }
        if apres(t.ack, una_avant) {
            flag |= FLAG_SND_UNA_ADVANCED;
            self.retransmissions = 0;
        }
        let fack_avant = if self.sack_ok { self.plus_haut_sack() } else { una_avant };
        self.remplacer_ts_recent(t.seq, maintenant);
        flag |= self.maj_fenetre(t, e);
        // SND.UNA, et les octets acquittés rendus.
        if flag & FLAG_SND_UNA_ADVANCED != 0 {
            self.acquitter_jusqu_a(t.ack);
            // Le mode urgent finit quand l'octet urgent est acquitté.
            if !avant(self.snd_up, una_avant) && !apres(self.snd_up, t.ack) {
                self.snd_up = t.ack;
            }
            e.place = true;
            e.a_emettre = true;
        }
        if a_des_blocs {
            flag |= self.marquer_blocs(t, una_avant, &mut etat, maintenant);
            self.livres += etat.livres;
        }
        // Quelque chose est revenu : l'erreur douce d'un ICMP ne vaut plus,
        // les sondes ont une réponse.
        self.erreur_douce = 0;
        self.sondes = 0;
        self.dernier_recu = maintenant;
        if packets_avant == 0 {
            // Un D-SACK sans rien en vol peut encore annuler une réduction.
            if flag & FLAG_DSACKING_ACK != 0 {
                self.alerte(una_avant, 0, &mut flag, maintenant);
            }
            self.ack_de_sonde(maintenant);
            self.traiter_ack_de_sonde(t.ack, flag);
            return ResultatAck::Traite;
        }
        flag |= self.nettoyer_file(fack_avant, una_avant, &mut etat, maintenant);
        self.rack_maj_fenetre(etat.prior_livres);
        self.traiter_ack_de_sonde(t.ack, flag);
        // `tcp_ack_is_dubious`.
        if flag & FLAG_NOT_DUP == 0 || flag & FLAG_CA_ALERT != 0 || self.cc.phase != Phase::Ouverte {
            let dupack = u32::from(flag & (FLAG_SND_UNA_ADVANCED | FLAG_NOT_DUP | FLAG_DSACKING_ACK) == 0);
            self.alerte(una_avant, dupack, &mut flag, maintenant);
        }
        // `tcp_set_xmit_timer` : la sonde de fin de rafale, sinon le RTO.
        if flag & FLAG_SET_XMIT_TIMER != 0 && !self.programmer_sonde_de_perte(true, maintenant) {
            self.rearmer_rto(maintenant);
        }
        self.controler_congestion(self.livres.wrapping_sub(livres_avant), self.perdus.wrapping_sub(perdus_avant), flag, maintenant);
        if self.rexmit != Rexmit::Rien {
            e.a_emettre = true;
        }
        ResultatAck::Traite
    }

    /// La fenêtre de l'autre (`tcp_ack_update_window`,
    /// `tcp_may_update_window`) : d'un segment plus récent que celui qui l'a
    /// donnée la dernière fois ; décalée de son échelle (jamais dans un SYN : ce
    /// segment n'en est pas un).
    fn maj_fenetre(&mut self, t: &Tcp, e: &mut Effets) -> u32 {
        if !self.fenetre_a_jour(t) {
            return 0;
        }
        let fenetre = (t.fenetre as u32) << self.echelle_envoi;
        self.snd_wl1 = t.seq;
        if self.snd_wnd != fenetre {
            if self.snd_wnd == 0 {
                e.a_emettre = true;
            }
            self.snd_wnd = fenetre;
            self.max_fenetre = self.max_fenetre.max(fenetre);
        }
        FLAG_WIN_UPDATE
    }

    /// `tcp_may_update_window`.
    fn fenetre_a_jour(&self, t: &Tcp) -> bool {
        let fenetre = (t.fenetre as u32) << self.echelle_envoi;
        apres(t.ack, self.snd_una) || apres(t.seq, self.snd_wl1) || (t.seq == self.snd_wl1 && (fenetre > self.snd_wnd || fenetre == 0))
    }

    /// `tcp_replace_ts_recent` : TSval d'un segment qui ne vient pas d'au-delà
    /// du bord (RFC 7323 4.3 : le plus ancien segment acquitté par notre
    /// prochain ACK) et qui passe PAWS strictement devient celui qu'on renvoie.
    /// Seulement une fois le segment jugé bon : un TSval faux dans un segment
    /// abîmé bloquerait la connexion.
    fn remplacer_ts_recent(&mut self, seq: u32, maintenant: u64) {
        if let (Some(ts), Some((val, _))) = (self.ts.as_mut(), self.ts_recu)
            && !apres(seq, self.rcv_wup)
            && paws_controle(ts, val, 0, maintenant)
        {
            ts.retenir(val, maintenant);
        }
    }

    /// SO_SNDBUF agrandi pour deux fenêtres de congestion de segments
    /// pleins, chacun compté avec sa place dans la mémoire du noyau, comme
    /// Linux (`tcp_sndbuf_expand` : le MSS plus 640 octets d'en-têtes et de
    /// structures, arrondi à la puissance de deux, plus 256 ; au moins 10
    /// segments ; au plus `tcp_wmem[2]`). Sur `lo` (MSS 65 495) : 2 626 560
    /// (mesuré chez Linux). Rien si le programme a fixé SO_SNDBUF.
    fn agrandir_sndbuf(&mut self) {
        if self.sndbuf_fixe {
            return;
        }
        // `max(mss_clamp, mss_cache)`, le premier sans la place des options.
        let clamp = self.mss_offre.filter(|&o| o != 0).unwrap_or(MSS_DEFAUT).min(if self.mss_utilisateur != 0 { self.mss_utilisateur } else { u16::MAX });
        let par_segment = (clamp.max(self.mss) as usize + 640).next_power_of_two() + 256;
        let segments = (self.cc.cwnd.max(CWND_INITIALE).max(self.reordering + 1)) as usize;
        let voulu = (2 * segments * par_segment).min(self.sndbuf_max);
        if self.sndbuf < voulu {
            self.sndbuf = voulu;
        }
    }

    /// SND.UNA avance jusqu'à `ack` : le SYN, les octets, le FIN acquittés
    /// (`tcp_snd_una_update`).
    fn acquitter_jusqu_a(&mut self, ack: u32) {
        let mut n = ack.wrapping_sub(self.snd_una) as usize;
        self.octets_acquittes += n as u64;
        if !self.syn_acquitte {
            // Le SYN compte pour un, pas dans le tampon.
            self.syn_acquitte = true;
            n -= 1;
        }
        if self.fin_seq().is_some_and(|f| apres(ack, f)) {
            n = n.saturating_sub(1);
        }
        self.acquitter_octets(n);
        self.snd_una = ack;
    }

    /// Notre FIN acquitté : ce que devient la connexion
    /// (`tcp_rcv_state_process`, une fois `tcp_ack` fini).
    fn apres_notre_fin(&mut self, e: &mut Effets) {
        if self.fin_voulue && self.snd_una == self.write_seq() {
            match self.etat {
                Etat::FinAttente1 => self.passer(Etat::FinAttente2, e),
                Etat::Fermeture => self.passer(Etat::TempsAttente, e),
                Etat::DernierAck => self.passer(Etat::Fermee, e),
                _ => {}
            }
        }
    }

    /// Le SYN ou le SYN-ACK est acquitté : une première mesure du RTT, s'il n'a
    /// pas été renvoyé (Karn : `tcp_clean_rtx_queue`, `tcp_synack_rtt_meas`) ;
    /// renvoyé : par TSecr, s'il y en a un.
    fn mesurer_syn(&mut self, maintenant: u64) {
        let mesure = self.syn_envoi.take().map(|envoi| maintenant.saturating_sub(envoi));
        self.mettre_a_jour_rtt(FLAG_SYN_ACKED, mesure, None, mesure, maintenant);
    }

    /// Le RTT que donne TSecr, en ns (`tcp_rtt_tsopt_us`), l'horloge comptant en
    /// ms : `min` si l'écart est nul (1 ms pour l'estimateur ; 0 pour le
    /// récepteur, qui jette alors la mesure).
    fn rtt_par_tsecr(&self, maintenant: u64, min: u32) -> Option<u64> {
        let (_, ecr) = self.ts_recu.filter(|&(_, e)| e != 0)?;
        let delta = horloge_ts(maintenant).wrapping_sub(ecr);
        if delta >= i32::MAX as u32 / 1000 {
            return None;
        }
        Some(if delta == 0 { min } else { delta } as u64 * 1_000_000)
    }

    /// Une mesure du RTT par le récepteur (`tcp_rcv_rtt_update`) : le minimum
    /// sans horodatages (`depend_fenetre` : la mesure par fenêtre grossit toute
    /// seule avec un programme lent) ; avec, une moyenne, si le programme suit.
    fn rtt_reception(&mut self, m: u64, depend_fenetre: bool) {
        let m8 = m << 3;
        if self.rcv_rtt8 == 0 || m8 < self.rcv_rtt8 {
            self.rcv_rtt8 = m8;
        } else if !depend_fenetre && self.rcv_nxt == self.rcv_lu {
            self.rcv_rtt8 = self.rcv_rtt8 - (self.rcv_rtt8 >> 3) + m;
        }
    }

    /// Le RTT du récepteur par une fenêtre de données reçue
    /// (`tcp_rcv_rtt_measure`).
    fn rtt_reception_fenetre(&mut self, maintenant: u64) {
        if self.rcv_rtt_debut != 0 {
            if avant(self.rcv_nxt, self.rcv_rtt_seq) {
                return;
            }
            self.rtt_reception(maintenant.saturating_sub(self.rcv_rtt_debut).max(1), true);
        }
        self.rcv_rtt_seq = self.rcv_nxt.wrapping_add(self.rcv_wnd);
        self.rcv_rtt_debut = maintenant;
    }

    /// Le RTT du récepteur par TSecr (`tcp_rcv_rtt_measure_ts`) : un seul par
    /// valeur, et d'un segment plein (l'autre n'envoie un petit segment que
    /// quand il n'a plus rien, et le TSecr dirait son silence).
    fn rtt_reception_ts(&mut self, longueur: u32, maintenant: u64) {
        let Some((_, ecr)) = self.ts_recu else { return };
        if ecr == self.rcv_rtt_tsecr {
            return;
        }
        self.rcv_rtt_tsecr = ecr;
        if longueur >= self.ack.rcv_mss
            && let Some(m) = self.rtt_par_tsecr(maintenant, 0)
            && m > 0
        {
            self.rtt_reception(m, false);
        }
    }

    /// La poignée de main est finie (`tcp_init_transfer`) : sans mesure du
    /// RTT (le SYN retransmis), le RTO de 3 s ; la fenêtre de congestion de
    /// départ, d'un segment seulement si le SYN a dû être renvoyé plus
    /// d'une fois, et pas pour rien.
    fn etablir(&mut self, maintenant: u64) {
        if self.rtt.mesure() {
            self.rto = self.rtt.rto();
        } else {
            self.rtt.repli();
            self.rto = RTO_REPLI;
        }
        // Les horodatages retirent leur place de ce qu'on dit pouvoir recevoir.
        if self.ts.is_some() {
            self.mss_local -= TS_ALIGNE;
        }
        self.cc.cwnd = if self.total_retrans > 1 && self.undo_marker.is_some() { 1 } else { CWND_INITIALE };
        // La perte du SYN est réparée ; le seuil, lui, garde sa réduction
        // (Linux aussi).
        if self.cc.phase == Phase::Perte {
            self.changer_phase(Phase::Ouverte);
        }
        self.cc.etablir(self.snd_nxt, maintenant);
        self.dernier_envoi = maintenant;
        // `tcp_initialize_rcv_mss` : au plus 536 avant d'avoir vu un segment.
        self.ack.rcv_mss = (self.mss_local as u32)
            .min(self.mss_borne())
            .min(self.rcv_wnd / 2)
            .min(MSS_DEFAUT as u32)
            .max(MSS_MIN as u32);
        // `tcp_init_buffer_space` ; et le keepalive, s'il est demandé.
        self.agrandir_sndbuf();
        self.espace_initial(maintenant);
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
                Phase::Reduction => 2,
                Phase::Reprise => 3,
                Phase::Perte => 4,
            },
            retransmissions: self.retransmissions.min(255) as u8,
            sondes: self.sondes.min(255) as u8,
            recul: self.recul.min(255) as u8,
            options: if echelle { 4 } else { 0 } | u8::from(self.etat.synchronise() && self.ts.is_some()) | if self.etat.synchronise() && self.sack_ok { 2 } else { 0 },
            echelle_envoi: if echelle { self.echelle_envoi } else { 0 },
            echelle_reception: if echelle { self.echelle_reception } else { 0 },
            rto: us(self.rto),
            ato: us(self.ack.ato),
            snd_mss: self.mss_borne(),
            rcv_mss: self.ack.rcv_mss,
            non_acquittes: self.file.len() as u32,
            sackes: self.sacked_out,
            perdus: self.lost_out,
            retransmis: self.retrans_out,
            dernier_envoi: ms(self.dernier_envoi),
            dernier_recu: ms(self.ack.lrcvtime),
            dernier_ack: ms(self.dernier_recu),
            rtt: us(self.rtt.srtt()),
            rttvar: us(self.rtt.ecart()),
            ssthresh: self.cc.ssthresh,
            cwnd: self.cc.cwnd,
            advmss: self.mss_local as u32,
            pmtu: self.mss_route as u32 + 40,
            reordonnancement: self.reordering,
            total_retrans: self.total_retrans,
            rcv_rtt: us(self.rcv_rtt8 >> 3),
            min_rtt: if self.min_rtt.valeur() == u64::MAX { u32::MAX } else { us(self.min_rtt.valeur()) },
            octets_acquittes: self.octets_acquittes,
            livres: self.livres,
            dsack_doublons: self.dsack_doublons,
            reord_seen: self.reord_seen,
            snd_wnd: self.snd_wnd,
            rcv_wnd: self.rcv_wnd,
            rcv_ssthresh: self.rcv_ssthresh,
            rcv_space: self.espace.octets,
            total_rto: self.total_rto,
            pacing: self.cc.pacing,
            t_retrans: self.t_xmit.map(|t| t.saturating_sub(maintenant)),
            sonde: self.t_sorte == Minuteur::Sonde,
            t_keepalive: self.t_keepalive.map(|t| t.saturating_sub(maintenant)),
            ack_rapides: self.ack.rapides,
            pingpong: self.ack.pingpong > 0,
            demarrage_lent: self.cc.ssthresh >= congestion::SSTHRESH_INFINI,
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

    /// Le texte d'un segment acceptable, ses données et son FIN
    /// (`tcp_data_queue`).
    fn recevoir_texte(&mut self, t: &Tcp, seq: u32, mut charge: P, fin: bool, maintenant: u64, e: &mut Effets) {
        let n = charge.octets().len() as u32;
        let fin_seq = seq.wrapping_add(n + u32::from(fin));
        if fin_seq == seq {
            return;
        }
        self.dsack = None;
        let wnd = self.fenetre_restante();
        if seq == self.rcv_nxt {
            // Dans l'ordre. Une fenêtre fermée ne laisse passer qu'un FIN
            // seul (« Some stacks are known to send bare FIN packets in a
            // loop even if we send RWIN 0 »).
            if wnd == 0 && !(n == 0 && fin) {
                self.hors_fenetre();
                return;
            }
        } else if !apres(fin_seq, self.rcv_nxt) {
            // Déjà reçu : l'autre n'a pas eu notre ACK.
            self.poser_doublon(seq, fin_seq);
            self.hors_fenetre();
            return;
        } else if !avant(seq, self.rcv_nxt.wrapping_add(wnd)) {
            // Au-delà de la fenêtre : une sonde, par exemple.
            self.hors_fenetre();
            return;
        } else if avant(seq, self.rcv_nxt) {
            // Le début déjà reçu ; fenêtre fermée, la suite n'entre pas.
            self.poser_doublon(seq, self.rcv_nxt);
            if wnd == 0 {
                self.hors_fenetre();
                return;
            }
            charge.avancer(self.rcv_nxt.wrapping_sub(seq) as usize);
        } else {
            self.recevoir_hors_ordre(t, seq, charge, fin, fin_seq);
            return;
        }
        let vraie = charge.taille_vraie();
        // La mémoire (reception.rs) : malgré tout ce qu'on sait faire, pas de place :
        // une fenêtre nulle, tout de suite ; le segment n'est gardé que s'il ne reste
        // rien à lire, ou qu'il ne porte rien : la connexion doit pouvoir avancer.
        if !self.reserver_reception(seq, n as usize) {
            self.ack.sans_memoire = true;
            self.ack.urgent = true;
            self.ack.programme = true;
            e.lisible = true;
            if !self.reception.is_empty() && n > 0 {
                return;
            }
        }
        if !charge.octets().is_empty() {
            if !self.ajouter_recu(charge) {
                self.ack_maintenant = true;
                return;
            }
            self.donnees_recues(t, n, vraie, maintenant);
            e.lisible = true;
        }
        if fin {
            self.recevoir_fin(e);
        }
        if !self.hors_ordre.vide() {
            let haut = self.rcv_nxt;
            let mut doublon = self.dsack;
            while let Some(p) = self.hors_ordre.suivante(self.rcv_nxt, haut, &mut doublon) {
                if !self.ajouter_recu(p) {
                    break;
                }
            }
            if self.sack_ok {
                self.dsack = doublon;
            }
            // Le trou est comblé : un ACK sans attendre (RFC 5681 4.2).
            if self.hors_ordre.vide() {
                self.ack.urgent = true;
            }
        }
        if self.nb_blocs > 0 {
            self.retirer_blocs();
        }
    }

    /// Un trou devant (`tcp_data_queue_ofo`) : la file hors d'ordre (le FIN attend
    /// que le trou se comble) ; l'ACK dupliqué le dit à l'émetteur (`verifier_ack`).
    /// La fenêtre ne grandit que pour un pair SACK : à un autre, il faut les ACK
    /// dupliqués, que la fenêtre qui bouge empêcherait de compter.
    fn recevoir_hors_ordre(&mut self, t: &Tcp, seq: u32, charge: P, fin: bool, fin_seq: u32) {
        let n = charge.octets().len() as u32;
        if !self.reserver_reception(seq, n as usize) {
            return;
        }
        let vraie = charge.taille_vraie();
        self.mesurer_rcv_mss(n, vraie, t);
        self.ack.programme = true;
        let premier = self.hors_ordre.vide();
        // Plus de mémoire : jeté, et surtout pas annoncé : l'émetteur le croirait arrivé.
        let Ok(doublon) = self.hors_ordre.ranger(seq, charge) else { return };
        if self.sack_ok {
            if premier {
                self.blocs[0] = (seq, fin_seq);
                self.nb_blocs = 1;
            } else {
                if let Some((d, f)) = doublon {
                    self.poser_doublon(d, f);
                }
                self.nouveau_bloc(seq, fin_seq);
            }
            self.agrandir_fenetre(n, vraie);
        }
        if self.attachee {
            self.rcvbuf_suit(self.espace.octets);
        }
        if fin {
            self.fin_hors_ordre = Some(fin_seq.wrapping_sub(1));
        }
    }

    /// Un segment qui n'a pas sa place, ou qui revient : un ACK tout de suite
    /// et le mode « quickack » (le `out_of_window` de `tcp_data_queue`).
    fn hors_fenetre(&mut self) {
        self.entrer_mode_rapide();
        self.ack.programme = true;
        self.ack_maintenant = true;
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
        self.nb_blocs = 0;
    }

    // --- Les ACK retardés ---

    /// Des données sont arrivées (`tcp_event_data_recv`, avec
    /// `tcp_measure_rcv_mss`) : l'`ato` suit l'écart entre les arrivées ;
    /// et la fenêtre peut grandir, pour tout segment qui n'est pas minuscule.
    fn donnees_recues(&mut self, t: &Tcp, longueur: u32, vraie: usize, maintenant: u64) {
        self.ack.programme = true;
        self.mesurer_rcv_mss(longueur, vraie, t);
        self.rtt_reception_fenetre(maintenant);
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
        if longueur >= 128 {
            self.agrandir_fenetre(longueur, vraie);
        }
    }

    /// Des ACK immédiats en plus (`tcp_incr_quickack`) : de quoi couvrir
    /// la moitié de la fenêtre annoncée, au moins 2, au plus 16.
    fn ajouter_ack_rapides(&mut self) {
        let mut n = self.rcv_wnd / (2 * self.ack.rcv_mss.max(1));
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
    /// RFC 5681 4.2), au début d'une connexion (« quickack »), ou après un
    /// trou comblé. Tant que la file hors d'ordre a quelque chose : sans SACK,
    /// chaque ACK dupliqué part (l'émetteur les compte) ; avec SACK, les trois
    /// premiers pour un même RCV.NXT, puis ils sont comprimés : un seul, après 5 %
    /// du RTT (au plus 1 ms), ou le 44e (`tcp_comp_sack_*`) : sur un long chemin à
    /// grande fenêtre, un ACK par segment hors d'ordre charge le réseau pour
    /// rien, les blocs redisant la même chose.
    fn verifier_ack(&mut self, maintenant: u64) {
        if !self.ack.programme || self.ack_maintenant {
            return;
        }
        let recus = self.rcv_nxt.wrapping_sub(self.rcv_wup);
        // Pas assez à lire pour SO_RCVLOWAT : l'autre doit continuer ; sinon, seulement
        // si le bord droit avance : la fenêtre qu'on annoncerait maintenant ne recule
        // pas sur la dernière (la lecture enverra l'ACK, sinon).
        let plein = recus > self.ack.rcv_mss && (self.rcv_nxt.wrapping_sub(self.rcv_lu) < self.rcvlowat || self.choisir_fenetre() >= self.rcv_wnd);
        if plein || self.ack.rapide() || self.ack.urgent {
            self.ack_maintenant = true;
            return;
        }
        // (Un FIN après le trou compte : chez Linux, il est dans la file.)
        if self.hors_ordre.vide() && self.fin_hors_ordre.is_none() {
            self.retarder_ack(maintenant);
            return;
        }
        if !self.sack_ok || self.ack_comprimes >= COMP_SACK_MAX {
            self.ack_maintenant = true;
            return;
        }
        if self.comprime_rcv_nxt != self.rcv_nxt {
            self.comprime_rcv_nxt = self.rcv_nxt;
            self.ack_dupliques = 0;
        }
        if self.ack_dupliques < TCP_REORDERING {
            self.ack_dupliques += 1;
            self.ack_maintenant = true;
            return;
        }
        self.ack_comprimes += 1;
        if self.t_comprime.is_none() {
            let srtt8 = self.rtt.srtt() << 3;
            let rtt8 = if srtt8 != 0 && srtt8 < self.rcv_rtt8 { srtt8 } else { self.rcv_rtt8 };
            self.t_comprime = Some(maintenant + COMP_SACK_DELAI.min(rtt8 / 8 / 20));
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
        self.ack.sans_memoire = false;
        self.ack.pousse = 0;
        self.ack.t = None;
        self.ack_maintenant = false;
        self.ack_comprimes = 0;
        self.t_comprime = None;
        self.dsack = None;
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
        self.heure = maintenant;
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

    // --- Les minuteurs ---

    /// La prochaine échéance de la connexion (None : aucune).
    pub fn echeance(&self) -> Option<u64> {
        [self.t_xmit, self.t_keepalive, self.ack.t, self.t_comprime].into_iter().flatten().min()
    }

    /// Fait ce qui est échu à l'heure `maintenant` : l'ACK retardé, la
    /// retransmission, la sonde de fenêtre.
    pub fn minuteur(&mut self, maintenant: u64) -> Effets {
        let mut e = Effets::default();
        self.heure = maintenant;
        if self.ack.t.is_some_and(|t| t <= maintenant) {
            self.ack.t = None;
            self.minuteur_ack(&mut e);
        }
        if self.t_comprime.is_some_and(|t| t <= maintenant) {
            self.t_comprime = None;
            if self.ack_comprimes > 0 {
                self.ack_comprimes -= 1;
                self.ack_maintenant = true;
                e.a_emettre = true;
            }
        }
        if self.t_xmit.is_some_and(|t| t <= maintenant) {
            self.t_xmit = None;
            match self.t_sorte {
                Minuteur::Retransmission => self.minuteur_retrans(maintenant, &mut e),
                Minuteur::Sonde => self.minuteur_sonde(maintenant, &mut e),
                Minuteur::Reordonnancement => self.minuteur_reordonnancement(maintenant, &mut e),
                Minuteur::SondeDePerte => {
                    self.tlp_du = true;
                    e.a_emettre = true;
                }
            }
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
        if !self.file.is_empty() || self.prochain_segment().is_some() {
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
            self.rst_du = Some((self.seq_acceptable(), self.rcv_nxt, tcp::RST | tcp::ACK));
            self.rst_actif = true;
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

    /// Combien de SYN-ACK pour une fille, TCP_SYNCNT, ou `tcp_synack_retries`.
    pub fn essais_de_fille(&self) -> u32 {
        if self.reglages.syn_essais != 0 { self.reglages.syn_essais } else { SYNACK_ESSAIS }
    }

    /// La limite que lui donne son écoute (`essais_de_filles`).
    pub fn reduire_essais(&mut self, n: u32) {
        self.essais_reduits = n;
    }

    /// Une fille encore jeune : aucun SYN-ACK n'a échu (`req->num_timeout == 0`) ?
    pub fn fille_jeune(&self) -> bool {
        self.retransmissions == 0
    }

    /// Le minuteur d'une fille (`reqsk_timer_handler`, `syn_ack_recalc`) : chez Linux, une
    /// simple demande, ni RTO ni congestion : le seuil reste infini, et la fenêtre de départ
    /// se décide à la naissance. Elle abandonne au bout de ses essais, en silence : personne
    /// ne la connaît. Avec TCP_DEFER_ACCEPT, une fois son ACK reçu, les SYN-ACK ne repartent
    /// plus avant la dernière période, qui donne une dernière chance à l'autre : un ACK
    /// redit la fera naître ; elle ne meurt qu'une fois cette période passée.
    pub(super) fn minuteur_fille(&mut self, maintenant: u64, e: &mut Effets) {
        let max = self.essais_de_fille().min(self.essais_reduits);
        let (n, defer) = (self.retransmissions, self.reglages.defer_accept);
        let (expire, renvoi) = if defer == 0 {
            (n >= max, true)
        } else {
            (n >= max && (!self.ack_differe || n >= defer), !self.ack_differe || n + 1 >= defer)
        };
        if expire {
            self.abandonner(e);
            return;
        }
        if renvoi {
            self.syn_du = true;
            self.total_retrans += 1;
            self.syn_envoi = None;
            e.a_emettre = true;
        }
        self.retransmissions += 1;
        self.total_rto += 1;
        self.undo_marker = Some(self.snd_una);
        self.recul += 1;
        self.rto = (self.rto * 2).min(RTO_MAX);
        self.armer_xmit(Minuteur::Retransmission, self.rto, maintenant);
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
        let delai = if self.reglages.delai_utilisateur != 0 { self.reglages.delai_utilisateur } else { temps_modele(limite, base) };
        maintenant.saturating_sub(self.retrans_stamp) >= delai
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
        if u == 0 {
            return rto;
        }
        let ecoule = maintenant.saturating_sub(self.retrans_stamp);
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
            if self.t_sorte == Minuteur::Sonde {
                self.t_xmit = None;
            }
        } else {
            let d = self.borne_sonde(maintenant, self.delai_sonde());
            self.armer_xmit(Minuteur::Sonde, d, maintenant);
        }
    }

    /// Le prochain délai de sonde, borné par ce qui reste de TCP_USER_TIMEOUT
    /// (`tcp_clamp_probe0_to_user_timeout`).
    fn borne_sonde(&self, maintenant: u64, delai: u64) -> u64 {
        let u = self.reglages.delai_utilisateur;
        let Some(debut) = self.sondes_debut else { return delai };
        if u == 0 {
            return delai;
        }
        let ecoule = maintenant.saturating_sub(debut);
        // Au moins deux tics (TCP_TIMEOUT_MIN) ; passé le délai, Linux déborde en non signé, et
        // reste au délai de la sonde : c'est `minuteur_sonde` qui abandonnera.
        if ecoule >= u { delai } else { delai.min((u - ecoule).max(2 * sack::JIFFY)) }
    }

    /// La sonde est échue (`tcp_probe_timer`) : une de plus, ou abandonner
    /// (15 sans réponse, `tcp_retries2` ; une orpheline plus tôt ;
    /// TCP_USER_TIMEOUT). Tant que l'autre répond, on sonde pour toujours
    /// (RFC 1122 4.2.2.17).
    fn minuteur_sonde(&mut self, maintenant: u64, e: &mut Effets) {
        if !self.file.is_empty() || self.prochain_segment().is_none() || !self.etat.synchronise() {
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
        let d = self.borne_sonde(maintenant, self.delai_sonde());
        self.armer_xmit(Minuteur::Sonde, d, maintenant);
        e.a_emettre = true;
    }

    // --- Ce qu'il faut envoyer ---

    /// L'en-tête d'un segment de cette connexion ; sa fenêtre, comme `__tcp_transmit_skb` :
    /// celle du SYN, jamais décalée ; sinon choisie à l'instant (`tcp_select_window`).
    pub(super) fn entete(&mut self, seq: u32, drapeaux: u8) -> Tcp {
        let fenetre = if drapeaux & tcp::SYN != 0 { self.rcv_wnd.min(FENETRE_MAX) as u16 } else { self.fenetre_a_annoncer() };
        self.entete_avec(seq, drapeaux, fenetre)
    }

    fn entete_avec(&self, seq: u32, drapeaux: u8, fenetre: u16) -> Tcp {
        let mut h = Tcp {
            source: self.port_local,
            destination: self.port_distant,
            seq,
            ack: if drapeaux & tcp::ACK != 0 { self.rcv_nxt } else { 0 },
            drapeaux,
            fenetre,
            urgent: 0,
            options: tcp::Options { horodatage: self.ts.map(|ts| (ts.valeur(self.heure), ts.recent)), ..tcp::Options::default() },
        };
        if drapeaux & tcp::SYN == 0 {
            let (blocs, n) = self.blocs_a_envoyer();
            h.options.blocs = blocs;
            h.options.nb_blocs = n;
        }
        // Le pointeur urgent, dans tout segment qui précède l'octet urgent
        // (`__tcp_transmit_skb`) ; trop loin pour 16 bits, 0xFFFF, tant
        // que le segment reste en deçà.
        if drapeaux & (tcp::SYN | tcp::RST) == 0 && self.mode_urgent() && avant(seq, self.snd_up) {
            if avant(self.snd_up, seq.wrapping_add(0x10000)) {
                h.urgent = self.snd_up.wrapping_sub(seq) as u16;
                h.drapeaux |= tcp::URG;
            } else if apres(seq.wrapping_add(0xFFFF), self.snd_nxt) {
                h.urgent = 0xFFFF;
                h.drapeaux |= tcp::URG;
            }
        }
        h
    }

    /// Un segment de données vient de partir, neuf ou renvoyé
    /// (`tcp_event_data_sent`) : une réponse rapide à ce qui vient d'arriver,
    /// c'est une conversation (le ping-pong).
    fn segment_de_donnees_parti(&mut self, maintenant: u64) {
        if self.paquets_en_vol() == 0 {
            self.cc.depart(self.dernier_envoi, maintenant);
        }
        self.dernier_envoi = maintenant;
        if maintenant.saturating_sub(self.ack.lrcvtime) < self.ack.ato {
            self.ack.pingpong = self.ack.pingpong.saturating_add(1);
        }
    }

    /// Envoie un segment neuf de `n` octets à partir de SND.NXT, et le FIN si
    /// `avec_fin` ; son entrée va dans la file (`tcp_event_new_data_sent`). Faux
    /// si la place manque dans la file : rien n'est parti, on réessaiera.
    fn envoyer_donnees(&mut self, n: usize, avec_fin: bool, maintenant: u64, sortir: &mut impl FnMut(Sortant)) -> bool {
        if self.file.try_reserve(1).is_err() {
            return false;
        }
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
        let h = self.entete(self.snd_nxt, drapeaux);
        let numero = self.compter_envoi(n);
        sortir(Sortant { entete: h, debut, longueur: n, numero });
        let fin_segment = self.snd_nxt.wrapping_add(n as u32 + u32::from(avec_fin));
        if n < self.mss_courant() as usize {
            // Un petit segment (`tcp_minshall_update`).
            self.snd_sml = fin_segment;
        }
        // L'ACK d'abord, puis la donnée (`__tcp_transmit_skb`) : sortir du mode rapide remet `ato` au
        // plus bas, ce que lit le test du ping-pong. Avant que le segment ne compte comme en vol ; un
        // FIN seul n'est pas une donnée.
        self.ack_envoye();
        if n > 0 {
            self.segment_de_donnees_parti(maintenant);
        }
        // Une sonde de fin de rafale armée laisse la place au RTO (`tcp_event_new_data_sent`).
        let rearmer = self.file.is_empty() || (self.t_xmit.is_some() && self.t_sorte == Minuteur::SondeDePerte);
        self.file.push_back(Envoye::neuf(self.snd_nxt, fin_segment, maintenant, drapeaux, self.livres, numero));
        self.tri_ajouter(self.snd_nxt, maintenant);
        self.snd_nxt = fin_segment;
        if rearmer {
            self.rearmer_rto(maintenant);
        }
        self.ack_envoye();
        self.verifier_place(maintenant);
        true
    }

    /// Rend, par `sortir`, les segments à envoyer maintenant : un RST, le
    /// SYN ou le SYN-ACK, une sonde, la tête après un RTO, ce qui est marqué
    /// perdu, les données neuves que permettent la fenêtre de l'autre et celle
    /// de congestion, le FIN, et l'ACK s'il en faut un tout de suite et
    /// qu'aucun segment ne l'a porté.
    pub fn emettre(&mut self, maintenant: u64, mut sortir: impl FnMut(Sortant)) {
        self.heure = maintenant;
        if let Some((seq, ack, drapeaux)) = self.rst_du.take() {
            // Un RST qui coupe la connexion est un segment comme un autre
            // (`tcp_send_active_reset`) ; celui qui répond à un segment refusé n'a
            // ni fenêtre ni options (`tcp_v4_send_reset`).
            let mut h = if core::mem::take(&mut self.rst_actif) {
                self.entete(seq, drapeaux)
            } else {
                Tcp { options: tcp::Options::default(), ..self.entete_avec(seq, drapeaux, 0) }
            };
            h.ack = ack;
            sortir(Sortant { entete: h, debut: 0, longueur: 0, numero: 0 });
            if self.etat == Etat::Fermee {
                return;
            }
        }
        if self.etat == Etat::Fermee {
            return;
        }
        if self.syn_du {
            self.syn_du = false;
            let drapeaux = if self.etat == Etat::SynRecu { tcp::SYN | tcp::ACK } else { tcp::SYN };
            if !core::mem::replace(&mut self.fenetre_posee, true) {
                // TCP_MAXSEG borne ce qu'on annonce, et tout ce qui en découle (`tcp_mss_clamp`).
                self.mss_local = self.mss_annonce();
                // `tcp_openreq_init_rwin` : les options de la fille comptent ;
                // `tcp_connect_init` : pas encore, sauf reprise d'un TIME_WAIT.
                let options = if self.fille { self.ts.is_some() } else { self.ts.is_some_and(|t| t.instant != 0) };
                self.fenetre_initiale((self.mss_annonce() as u32).saturating_sub(if options { TS_ALIGNE as u32 } else { 0 }));
            }
            let mut h = self.entete(self.iss, drapeaux);
            h.options.mss = Some(self.mss_annonce());
            h.options.sack_permis = self.sack_ok;
            // Le TSval de nos SYN-ACK (`tcp_synack_options`) : jamais nul le
            // premier, et l'intervalle d'une réponse valide.
            if let Some((val, ecr)) = h.options.horodatage
                && self.fille
            {
                let val = if self.ts_synack.is_none() && val == 0 { u32::MAX } else { val };
                h.options.horodatage = Some((val, ecr));
                self.ts_synack = Some((self.ts_synack.map_or(val, |(premier, _)| premier), val));
            }
            // L'échelle : proposée dans notre SYN ; rendue dans le SYN-ACK
            // seulement si l'autre l'a proposée (RFC 7323 1.3).
            if self.echelle_ok {
                h.options.echelle = Some(self.echelle_reception);
            }
            sortir(Sortant { entete: h, debut: 0, longueur: 0, numero: 0 });
            self.snd_nxt = self.iss.wrapping_add(1);
            // Le premier SYN est chronométré ; pas ceux qui le répètent.
            if self.retransmissions == 0 && self.total_retrans == 0 {
                self.syn_envoi = Some(maintenant);
                self.retrans_stamp = maintenant;
            }
            if self.t_xmit.is_none() {
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
                let h = self.entete(self.seq_acceptable(), tcp::ACK);
                sortir(Sortant { entete: h, debut: 0, longueur: 0, numero: 0 });
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
                let h = self.entete(self.snd_una.wrapping_sub(1), tcp::ACK);
                sortir(Sortant { entete: h, debut: 0, longueur: 0, numero: 0 });
                self.ack_envoye();
            }
        }
        // La tête, après un RTO ; ce qui est marqué perdu, après un ACK
        // (`tcp_xmit_recovery`).
        if core::mem::take(&mut self.rto_du) {
            self.renvoyer_tete(maintenant, &mut sortir);
        }
        match core::mem::replace(&mut self.rexmit, Rexmit::Rien) {
            Rexmit::Rien => {}
            Rexmit::Perdus => self.renvoyer_perdus(maintenant, &mut sortir),
            Rexmit::Neuf => {
                // F-RTO (`tcp_xmit_recovery`) : du neuf ; s'il n'a pas pu partir,
                // la reprise ordinaire.
                self.pousser = true;
                self.envoyer_neuf(maintenant, &mut sortir);
                if !apres(self.snd_nxt, self.high_seq) {
                    self.frto = false;
                    self.renvoyer_perdus(maintenant, &mut sortir);
                }
            }
        }
        if core::mem::take(&mut self.tlp_du) {
            self.envoyer_sonde_de_perte(maintenant, &mut sortir);
        }
        self.envoyer_neuf(maintenant, &mut sortir);
        if self.ack_maintenant {
            let h = self.entete(self.seq_acceptable(), tcp::ACK);
            sortir(Sortant { entete: h, debut: 0, longueur: 0, numero: 0 });
            self.ack_envoye();
        }
        if core::mem::take(&mut self.place_a_voir) {
            self.verifier_place(maintenant);
        }
    }

    /// Les données neuves, et le FIN (`tcp_write_xmit`), tant que la fenêtre
    /// de congestion a de la place : un segment entier dans la fenêtre de
    /// l'autre (`tcp_snd_wnd_test` : on attend plutôt que de le couper) ; sauf ce
    /// que l'autocork retient (carte.rs), et tant que la carte n'en garde pas trop.
    fn envoyer_neuf(&mut self, maintenant: u64, sortir: &mut impl FnMut(Sortant)) {
        let retenu = self.autocork();
        let mut sortis = 0;
        loop {
            let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
            let reste = self.octets_envoi.saturating_sub(debut);
            let fin_ici = self.fin_seq().is_some_and(|f| !apres(self.snd_nxt, f));
            if reste == 0 && !fin_ici {
                break;
            }
            if retenu > 0 && reste <= retenu {
                break;
            }
            if self.paquets_en_vol() >= self.cc.cwnd {
                break;
            }
            let n = reste.min(self.mss_courant() as usize);
            let avec_fin = fin_ici && n == reste;
            if apres(self.snd_nxt.wrapping_add(n as u32 + u32::from(avec_fin)), self.snd_una.wrapping_add(self.snd_wnd)) {
                break;
            }
            // Nagle (`tcp_nagle_test`) : le dernier segment, incomplet,
            // attend ; TCP_CORK et MSG_MORE le retiennent toujours ; sinon,
            // tant qu'un petit segment déjà envoyé n'est pas acquitté (la
            // règle de Minshall : de gros segments en vol ne retiennent
            // pas le petit qui suit), sauf TCP_NODELAY. Ni le FIN, ni le
            // mode urgent, ni une poussée n'attendent.
            let partiel = n < self.mss_courant() as usize && n == reste;
            if partiel && !avec_fin && !self.pousser && !self.mode_urgent() {
                let bouchon = self.reglages.cork || self.plus_a_venir;
                let petit_en_vol = apres(self.snd_sml, self.snd_una) && !apres(self.snd_sml, self.snd_nxt);
                let nagle = !self.reglages.nodelay && !self.file.is_empty() && petit_en_vol;
                if bouchon || nagle {
                    break;
                }
            }
            if self.file.is_empty() && n > 0 {
                // Rien en vol : après un long silence, la cwnd ne vaut plus.
                let silence = maintenant.saturating_sub(self.dernier_envoi);
                if silence > self.rto {
                    self.cc.redemarrer(silence, self.rto, maintenant);
                }
            }
            if self.carte_trop_pleine(n, 0) {
                break;
            }
            if !self.envoyer_donnees(n, avec_fin, maintenant, sortir) {
                break;
            }
            sortis += 1;
            if avec_fin {
                break;
            }
        }
        self.pousser = false;
        self.plus_a_venir = false;
        let limitee = self.paquets_en_vol() >= self.cc.cwnd;
        if sortis > 0 || limitee {
            let relachable = self.cc.phase == Phase::Ouverte && !self.reglages.orpheline && !self.sans_place;
            self.cc.valider(limitee, self.file.len() as u32, self.snd_una, self.snd_nxt, self.rto, relachable, maintenant);
        }
        if sortis > 0 {
            // Une sonde par fin de rafale.
            self.programmer_sonde_de_perte(false, maintenant);
        }
        // Rien en vol, et des données qui attendent (la fenêtre de l'autre ne
        // les laisse pas passer, ou TCP_CORK les retient) : la sonde
        // (`tcp_check_probe_timer`), qui les poussera au plus tard.
        if self.file.is_empty() && self.prochain_segment().is_some() && self.t_xmit.is_none() {
            self.armer_xmit(Minuteur::Sonde, self.rto.max(RTO_MIN), maintenant);
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
