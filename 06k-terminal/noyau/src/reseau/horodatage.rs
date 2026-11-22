//! Les horodatages d'émission (SO_TIMESTAMPING, les soldes d'avant 6k) : une
//! socket demande l'heure à laquelle ses paquets passent certains points de
//! la pile, et la lit dans sa file d'erreurs (MSG_ERRQUEUE), une entrée
//! d'origine SO_EE_ORIGIN_TIMESTAMPING par point passé (`__skb_tstamp_tx`,
//! net/core/skbuff.c).
//!
//! LES POINTS, ceux de Linux : SCHED à l'entrée de l'émission par une
//! interface, avant toute file (`__dev_queue_xmit` : interface.rs) ; SND quand
//! le pilote prend la trame (`skb_tx_timestamp` : lo juste avant de la
//! renvoyer, boucle.rs ; virtio-net quand il la pose dans l'anneau) ; ACK
//! quand l'autre côté a acquitté le dernier octet d'un envoi de TCP. Ce que
//! dit l'entrée : le point (ee_info : SND 0, SCHED 1, ACK 2), la clé de
//! l'envoi avec OPT_ID (ee_data), l'heure (SCM_TIMESTAMPING, à la lecture), et
//! la trame entière telle qu'elle part, en-tête Ethernet compris (le
//! `skb_clone` de Linux, ici une copie), ou rien avec OPT_TSONLY.
//!
//! LA DEMANDE voyage avec le paquet (`Demande`, le `tx_flags` et le `tskey` du
//! `skb_shared_info`), avec un lien FAIBLE vers sa socket : un paquet encore
//! dans la carte ne fait pas durer une socket fermée (la `Retenue` de
//! paquet.rs a la même raison), et l'entrée d'une socket partie n'a nulle part
//! où aller (Linux la range dans la file d'une socket morte, qui la jette avec
//! elle : personne ne la lit). Seul le premier morceau d'un datagramme
//! fragmenté la porte (`__ip_append_data`) ; la copie d'une diffusion rendue
//! à la machine n'en a pas (le `skb_clone` d'`ip_mc_output` n'a pas de
//! socket).
//!
//! TCP (`tcp_tx_timestamp`) : un envoi demande pour son DERNIER octet, que
//! la connexion garde (tcp.rs, `DemandeTx`) ; chaque segment qui porte cet
//! octet, à chaque envoi, reçoit la `Demande` de SCHED et SND, avec le numéro
//! de cet octet pour clé ; l'ACK qui le passe fait l'entrée ACK
//! (`acquitte`), une seule fois.
//!
//! LA MÉMOIRE : une entrée compte dans la réception de sa socket (SO_RCVBUF,
//! SO_MEMINFO) la taille vraie de son `sk_buff` chez Linux : la copie d'un
//! datagramme, celle du paquet (`Paquet::taille_vraie`, son `skb_clone`) ;
//! une entrée sans octets (OPT_TSONLY), un `sk_buff` vide
//! (`paquet::TAILLE_VIDE`) ; celle d'un segment de TCP, la tête vide et ses
//! octets de données (les `sk_buff` de TCP gardent leurs octets dans des
//! pages ; mesuré : 960 + n pour SCHED, SND et ACK). Pour TCP, la file
//! d'erreurs compte avec ce que la connexion a reçu, sous le même SO_RCVBUF
//! (`tcp::CompteReception`).
//!
//! L'ENTRÉE est faite au point même : l'heure, la copie, et ce que disent à
//! cet instant les drapeaux de la socket (OPT_TSONLY, OPT_ID), comme Linux.
//! Mais elle n'entre dans la file d'erreurs que plus tard : SCHED et SND
//! arrivent sous le verrou des voisins (arp.rs) ou sous celui de la carte,
//! où l'on ne prend aucun verrou de socket, et une entrée en file réveille
//! ceux qui attendent, puis SIGIO, qui prend les verrous des processus
//! (asynchrone.rs). Elle passe donc par la file de `lo` de la tâche
//! (boucle.rs), vidée à la sortie du contexte réseau (contexte.rs, le
//! `local_bh_enable`) : l'interface et les voisins y entrent avant leurs
//! verrous, et en sortent après. L'entrée est ainsi en file avant que
//! l'envoi ne rende la main, comme chez Linux, où un `recvmsg(MSG_ERRQUEUE)`
//! juste après un `send` par lo trouve déjà SCHED et SND. Écartés : la mettre
//! en file au point même (sous ces verrous) ; la confier à la tâche du réseau
//! (elle arriverait quand l'ordonnanceur la choisit : un programme qui lit
//! tout de suite ne la trouverait pas).

use super::ipv4::EnteteRecu;
use super::paquet::{Paquet, TAILLE_VIDE};
use alloc::boxed::Box;
use super::socket::{self, ErreurEnFile, Protocole, Socket};
use crate::partage::{Arc, Weak};
use core::sync::atomic::Ordering;
use formats::reseau::ethernet;

/// Les points où une demande veut une entrée (`Demande::points`) : SCHED
/// (SKBTX_SCHED_TSTAMP), et le passage au pilote (SKBTX_SW_TSTAMP).
pub const SCHED: u8 = 1;
pub const PILOTE: u8 = 2;

/// Ce que dit ee_info (`enum scm_tstamp`, include/uapi/linux/errqueue.h).
pub const SCM_TSTAMP_SND: u32 = 0;
pub const SCM_TSTAMP_SCHED: u32 = 1;
pub const SCM_TSTAMP_ACK: u32 = 2;

/// L'errno d'une entrée d'horodatage (ENOMSG : ce n'est pas une erreur).
const ENOMSG: i32 = 42;

/// Ce qu'un paquet demande d'horodater (le `tx_flags` et le `tskey` de son
/// `skb_shared_info`) : à quels points (`SCHED`, `PILOTE`), pour quelle
/// socket, et sa clé : celle d'OPT_ID pour un datagramme, et pour TCP le
/// numéro de séquence de son dernier octet, que l'entrée rend relatif.
pub struct Demande {
    socket: Weak<Socket>,
    points: u8,
    cle: u32,
}

/// Une entrée faite, pour la file d'erreurs de sa socket : ce qu'attend la
/// file de `lo` de la tâche (boucle.rs, `Trame`), dans une boîte (elle est
/// grande, et la file a la place de mille trames d'avance).
pub struct Entree {
    socket: Arc<Socket>,
    erreur: ErreurEnFile,
}

/// Le paquet `p` d'un datagramme (UDP, ping) de la socket `s`, qui vient
/// d'être fait (`__ip_append_data`) : `tx`, les drapeaux d'émission de cet
/// envoi (ceux de la socket, ou ceux du message de contrôle SO_TIMESTAMPING :
/// `datagramme::Depart`), `ts_opt_id`, la clé de SCM_TS_OPT_ID. Toute
/// demande d'émission (TX_SOFTWARE, TX_SCHED, et aussi TX_HARDWARE et
/// TX_COMPLETION, que rien ne dit chez nous : aucune carte ne donne d'heure,
/// et seuls quelques pilotes de Linux disent la fin d'un envoi), avec OPT_ID
/// posé à cet instant, prend une clé : celle du message de contrôle, sinon
/// la suivante du compteur de la socket (`sk_tskey`), qui avance d'un envoi
/// fait (Linux la prend avant de faire le paquet, et la rend s'il échoue :
/// la même suite). TX_ACK ne vaut que pour TCP.
pub fn demander_datagramme(s: &Arc<Socket>, p: &mut Paquet, tx: u32, ts_opt_id: Option<u32>) {
    if tx & (socket::SOF_TX_HARDWARE | socket::SOF_TX_SOFTWARE | socket::SOF_TX_SCHED | socket::SOF_TX_COMPLETION) == 0 {
        return;
    }
    let cle = if s.tsflags.load(Ordering::Relaxed) & socket::SOF_OPT_ID != 0 {
        ts_opt_id.unwrap_or_else(|| s.cle_emission.fetch_add(1, Ordering::Relaxed))
    } else {
        0
    };
    demander(s, p, tx, cle);
}

/// Pose sur `p` la demande des drapeaux d'émission `tx` pour la socket `s`,
/// de clé `cle`, s'il y a un point à dire (`__sock_tx_timestamp`) ; plus de
/// mémoire : rien ne sera dit de ce paquet.
pub fn demander(s: &Arc<Socket>, p: &mut Paquet, tx: u32, cle: u32) {
    if let Some(d) = demande(&Arc::downgrade(s), tx, cle) {
        p.poser_demande(d);
    }
}

/// La demande des drapeaux d'émission `tx` pour la socket `socket`, de clé
/// `cle`, dans le tas (voir `Paquet`) ; None : aucun point à dire (TX_ACK
/// seul ne regarde que l'ACK, que TCP fait lui-même ; TX_HARDWARE et
/// TX_COMPLETION, rien chez nous), ou plus de mémoire (rien ne sera dit de
/// ce paquet).
pub fn demande(socket: &Weak<Socket>, tx: u32, cle: u32) -> Option<Box<Demande>> {
    let points = if tx & socket::SOF_TX_SCHED != 0 { SCHED } else { 0 } | if tx & socket::SOF_TX_SOFTWARE != 0 { PILOTE } else { 0 };
    if points == 0 {
        return None;
    }
    crate::faillible::boite(Demande { socket: socket.clone(), points, cle }).ok()
}

/// Le paquet `p` passe le point `point` (`SCHED` ou `PILOTE`) de l'interface
/// d'index `interface` : s'il le demandait, son entrée est faite (`entree`) et
/// déposée dans la file de `lo` de la tâche. Dans le contexte réseau (voir
/// l'en-tête) : la file sera vidée en le quittant.
pub fn passer(p: &Paquet, point: u8, interface: u32) {
    let Some(d) = p.demande() else { return };
    if d.points & point == 0 {
        return;
    }
    let Some(s) = d.socket.upgrade() else { return };
    let info = if point == SCHED { SCM_TSTAMP_SCHED } else { SCM_TSTAMP_SND };
    if let Some(erreur) = entree(&s, p.donnees(), p.taille_vraie(), info, d.cle, interface) {
        deposer(s, erreur);
    }
}

/// Dépose l'entrée `erreur` de la socket `s` dans la file de `lo` de la
/// tâche, vidée à la sortie du contexte réseau (voir l'en-tête) ; plus de
/// mémoire : elle est perdue (le `skb_clone` qui échoue). À part, comme
/// `entree`.
#[inline(never)]
fn deposer(s: Arc<Socket>, erreur: ErreurEnFile) {
    if let Ok(e) = crate::faillible::boite(Entree { socket: s, erreur }) {
        super::boucle::deposer_entree(e);
    }
}

/// L'ACK de TCP a passé l'octet `cle` (son numéro de séquence) d'une demande
/// TX_ACK de la socket `s` (`tcp_ack_tstamp`) : son entrée SCM_TSTAMP_ACK,
/// déposée comme les autres (voir l'en-tête ; TCP est dans le contexte
/// réseau quand il reçoit). Ce qu'elle porte, `octets` : les DONNÉES du
/// segment acquitté, sans en-tête, tout le segment (Linux copie le `sk_buff`
/// de sa file de retransmission, que n'a jamais touché IP : mesuré, 10 octets
/// pour un envoi de 10, et 6 pour un envoi de 4 avec la demande et un de 2
/// sans, dans le même segment), copiées avant que l'ACK ne les retire (tcp.rs) ; None avec
/// OPT_TSONLY, ou quand la copie a manqué de mémoire (rien alors, comme le
/// `skb_clone` qui échoue). Aucune interface : ce `sk_buff` n'est jamais
/// passé par une carte (`skb->dev` nul), d'où ni IP_PKTINFO ni
/// SO_EE_OFFENDER avec OPT_CMSG (`ipv4_datagram_support_cmsg`).
pub fn acquitte(s: Arc<Socket>, octets: Option<Paquet>, cle: u32) {
    let tsonly = s.tsflags.load(Ordering::Relaxed) & socket::SOF_OPT_TSONLY != 0;
    let (donnees, taille) = match (tsonly, octets) {
        (true, _) => (Paquet::copie(&[]), TAILLE_VIDE),
        (false, o) => {
            let n = o.as_ref().map_or(0, Paquet::longueur);
            (o, TAILLE_VIDE + n)
        }
    };
    if let Some(donnees) = donnees {
        let erreur = faire(&s, donnees, &[], taille, SCM_TSTAMP_ACK, cle, 0);
        deposer(s, erreur);
    }
}

/// L'entrée du point `info` pour la socket `s` (`__skb_tstamp_tx`, puis
/// `__skb_complete_tx_timestamp`), avec les drapeaux qu'elle a maintenant :
/// avec OPT_TSONLY, aucun octet et aucune interface (le paquet vide
/// d'`alloc_skb(0)`, sans `dev`) ; sinon une copie de `trame` (le paquet tel
/// qu'il part, en-tête Ethernet devant), qui compte dans SO_RCVBUF la taille
/// vraie du paquet, `taille` (celle d'un `skb_clone` : la même ; pour TCP,
/// la tête vide et ses octets de données : voir l'en-tête), et
/// l'interface `interface` (son `dev`). Avec OPT_ID, la clé (relative au compteur de la socket pour TCP :
/// le numéro de son octet depuis qu'elle a posé OPT_ID). L'heure : celle de
/// la date, maintenant (`__net_timestamp`). Ce que diront, avec OPT_CMSG, ses
/// messages de contrôle IP (`ipv4_datagram_support_cmsg`) : l'en-tête du
/// paquet (son TTL, son TOS ; jamais d'options : Linux efface le `cb` du
/// paquet, où elles étaient notées), sa source (SO_EE_OFFENDER, et
/// l'adresse locale d'IP_PKTINFO) et sa destination. None : plus de
/// mémoire (le `skb_clone` qui échoue : rien). À part de `passer`, que
/// traverse chaque paquet émis, au fond du réseau : son cadre n'a pas à
/// garder la place de ce travail quand le paquet ne demande rien.
#[inline(never)]
pub fn entree(s: &Socket, trame: &[u8], taille: usize, info: u32, cle: u32, interface: u32) -> Option<ErreurEnFile> {
    let tsonly = s.tsflags.load(Ordering::Relaxed) & socket::SOF_OPT_TSONLY != 0;
    let donnees = Paquet::copie(if tsonly { &[] } else { trame })?;
    let ip = if tsonly { &[][..] } else { trame.get(ethernet::ENTETE..).unwrap_or(&[]) };
    let taille = match () {
        _ if tsonly => TAILLE_VIDE,
        _ if s.protocole == Protocole::Tcp => TAILLE_VIDE + charge_tcp(ip),
        _ => taille,
    };
    Some(faire(s, donnees, ip, taille, info, cle, if tsonly { 0 } else { interface }))
}

/// Les octets de données du segment de TCP dont `ip` est le paquet IPv4
/// (son en-tête et celui de TCP ôtés).
fn charge_tcp(ip: &[u8]) -> usize {
    let ihl = ip.first().map_or(0, |o| usize::from(o & 0xf) * 4);
    let doff = ip.get(ihl + 12).map_or(0, |o| usize::from(o >> 4) * 4);
    ip.len().saturating_sub(ihl + doff)
}

/// L'entrée elle-même : ses octets `donnees`, qui comptent `taille` dans
/// SO_RCVBUF ; `ip`, l'en-tête IPv4 du paquet (vide : il n'en a pas) ;
/// l'interface `interface` (0 : aucune).
fn faire(s: &Socket, donnees: Paquet, ip: &[u8], taille: usize, info: u32, cle: u32, interface: u32) -> ErreurEnFile {
    let ts = s.tsflags.load(Ordering::Relaxed);
    let adresse = |i: usize| ip.get(i..i + 4).map_or([0; 4], |o| [o[0], o[1], o[2], o[3]]);
    let entete = EnteteRecu { tos: ip.get(1).copied().unwrap_or(0), ttl: ip.get(8).copied().unwrap_or(0), ..EnteteRecu::AUCUN };
    let ee_data = match ts & socket::SOF_OPT_ID {
        0 => 0,
        _ if s.protocole == Protocole::Tcp => cle.wrapping_sub(s.cle_emission.load(Ordering::Relaxed)),
        _ => cle,
    };
    ErreurEnFile {
        errno: ENOMSG, origine: socket::ORIGINE_HORODATAGE, genre: 0, code: 0, info, ee_data, adresse: [0; 4], port: 0,
        emetteur: adresse(12), interface, arrivee: adresse(16), entete, somme: 0, horodatage: crate::temps::ns_calendrier(), taille,
        donnees,
    }
}

/// Met l'entrée `e` dans la file d'erreurs de sa socket (`sock_queue_err_skb` :
/// sous SO_RCVBUF, sinon jetée), à la sortie du contexte réseau (boucle.rs).
pub fn livrer(e: alloc::boxed::Box<Entree>) {
    let Entree { socket, erreur } = *e;
    socket.mettre_en_file(erreur);
}
