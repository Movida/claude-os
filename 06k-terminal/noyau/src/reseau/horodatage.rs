//! Les horodatages d'émission (SO_TIMESTAMPING, les soldes d'avant 6k) : une
//! socket demande l'heure à laquelle ses paquets passent certains points de
//! la pile, et la lit dans sa file d'erreurs (MSG_ERRQUEUE), une entrée
//! d'origine SO_EE_ORIGIN_TIMESTAMPING par point passé (`__skb_tstamp_tx`,
//! net/core/skbuff.c).
//!
//! LES POINTS, ceux de Linux pour un datagramme : SCHED à l'entrée de
//! l'émission par une interface, avant toute file (`__dev_queue_xmit` :
//! interface.rs) ; SND quand le pilote prend la trame (`skb_tx_timestamp` : lo
//! juste avant de la renvoyer, boucle.rs ; virtio-net quand il la pose dans
//! l'anneau). Ce que dit l'entrée : le point (ee_info : SND 0, SCHED 1), la clé
//! de l'envoi avec OPT_ID (ee_data), l'heure (SCM_TIMESTAMPING, à la lecture), et
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
use super::socket::{self, ErreurEnFile, Socket};
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

/// L'errno d'une entrée d'horodatage (ENOMSG : ce n'est pas une erreur).
const ENOMSG: i32 = 42;

/// Ce qu'un paquet demande d'horodater (le `tx_flags` et le `tskey` de son
/// `skb_shared_info`) : à quels points (`SCHED`, `PILOTE`), pour quelle
/// socket, et sa clé : celle d'OPT_ID.
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
/// de clé `cle`, s'il y a un point à dire (`__sock_tx_timestamp`), dans le
/// tas (voir `Paquet`) ; plus de mémoire : rien ne sera dit de ce paquet.
pub fn demander(s: &Arc<Socket>, p: &mut Paquet, tx: u32, cle: u32) {
    let points = if tx & socket::SOF_TX_SCHED != 0 { SCHED } else { 0 } | if tx & socket::SOF_TX_SOFTWARE != 0 { PILOTE } else { 0 };
    if points != 0
        && let Ok(d) = crate::faillible::boite(Demande { socket: Arc::downgrade(s), points, cle })
    {
        p.poser_demande(d);
    }
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

/// L'entrée du point `info` pour la socket `s` (`__skb_tstamp_tx`, puis
/// `__skb_complete_tx_timestamp`), avec les drapeaux qu'elle a maintenant :
/// avec OPT_TSONLY, aucun octet et aucune interface (le paquet vide
/// d'`alloc_skb(0)`, sans `dev`) ; sinon une copie de `trame` (le paquet tel
/// qu'il part, en-tête Ethernet devant), qui compte dans SO_RCVBUF la taille
/// vraie du paquet, `taille` (celle d'un `skb_clone` : la même), et
/// l'interface `interface` (son `dev`). Avec OPT_ID, la clé. L'heure : celle de
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
    let ts = s.tsflags.load(Ordering::Relaxed);
    let tsonly = ts & socket::SOF_OPT_TSONLY != 0;
    let donnees = Paquet::copie(if tsonly { &[] } else { trame })?;
    let ip = if tsonly { &[][..] } else { trame.get(ethernet::ENTETE..).unwrap_or(&[]) };
    let adresse = |i: usize| ip.get(i..i + 4).map_or([0; 4], |o| [o[0], o[1], o[2], o[3]]);
    let entete = EnteteRecu { tos: ip.get(1).copied().unwrap_or(0), ttl: ip.get(8).copied().unwrap_or(0), ..EnteteRecu::AUCUN };
    let ee_data = if ts & socket::SOF_OPT_ID != 0 { cle } else { 0 };
    Some(ErreurEnFile {
        errno: ENOMSG, origine: socket::ORIGINE_HORODATAGE, genre: 0, code: 0, info, ee_data, adresse: [0; 4], port: 0,
        emetteur: adresse(12), interface: if tsonly { 0 } else { interface }, arrivee: adresse(16), entete, somme: 0,
        horodatage: crate::temps::ns_calendrier(), taille: if tsonly { TAILLE_VIDE } else { taille }, donnees,
    })
}

/// Met l'entrée `e` dans la file d'erreurs de sa socket (`sock_queue_err_skb` :
/// sous SO_RCVBUF, sinon jetée), à la sortie du contexte réseau (boucle.rs).
pub fn livrer(e: alloc::boxed::Box<Entree>) {
    let Entree { socket, erreur } = *e;
    socket.mettre_en_file(erreur);
}
