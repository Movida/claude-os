//! Le réseau (6g) : les cartes, les interfaces, les paquets, la tâche du
//! noyau qui fait le travail des cartes, et la pile au-dessus.
//!
//! Comme dans Linux, une carte réseau ne fait presque rien dans son
//! interruption : elle dit qu'il y a du travail, et une tâche du noyau le
//! fait plus tard, interruptions permises (tache.rs). Les pilotes : la carte
//! virtio-net (virtio_net.rs). Ce que voit la pile d'une carte : son
//! interface (interface.rs) ; ce qui circule : des paquets (paquet.rs).
//! Les étages : Ethernet (ethernet.rs), ARP (arp.rs), IPv4 (ipv4.rs), ICMP
//! (icmp.rs), UDP (udp.rs), les sockets de ping (ping.rs) ; les sockets, ce qu'en voient les programmes (socket.rs, ce
//! qu'ont en commun celles de datagrammes : datagramme.rs, et leurs appels
//! système : ../appels_reseau.rs) ; l'interface de boucle,
//! `lo` (boucle.rs) ; la configuration au démarrage par DHCP (dhcp.rs) ;
//! ce qu'en montre /proc/net (proc.rs). Les règles (les routes, le client
//! DHCP, les voisins, les ports) sont dans la bibliothèque inet, testée
//! sur l'hôte ; les en-têtes, dans formats::reseau.

pub mod arp;
pub mod boucle;
pub mod datagramme;
pub mod dhcp;
pub mod ethernet;
pub mod icmp;
pub mod interface;
pub mod ipv4;
pub mod paquet;
pub mod ping;
pub mod proc;
pub mod socket;
pub mod tache;
pub mod udp;
pub mod virtio_net;

use interface::Interface;
use paquet::Paquet;

/// Une trame reçue par l'interface `i`, dans la tâche du réseau.
pub fn recevoir(i: &'static Interface, p: Paquet) {
    ethernet::recevoir(i, p);
}

/// Trouve les cartes réseau et met en service celles qu'on sait piloter,
/// puis lance la tâche du réseau. Au démarrage, une fois les tâches et les
/// interruptions en service.
pub fn demarrer() {
    ipv4::initialiser();
    arp::initialiser();
    udp::initialiser();
    ping::initialiser();
    boucle::ajouter();
    virtio_net::sonder();
    tache::lancer();
}

/// Le nombre de sockets liées dont quelqu'un attend une lecture (le
/// détecteur d'interblocage, attente.rs).
pub fn attentes() -> usize {
    udp::attentes() + ping::attentes()
}

/// Le réseau est-il au repos : plus rien dans une file du noyau (celle de
/// `lo`, la petite file d'émission d'une carte, la file d'un voisin qui se
/// cherche), ni de travail en attente ou en cours de la tâche du réseau ?
/// Le lanceur l'attend avant de mesurer la mémoire rendue par un
/// programme : un paquet qu'il a envoyé peut encore être en route, et tenir
/// de la mémoire, quand il finit.
pub fn au_repos() -> bool {
    boucle::au_repos() && virtio_net::au_repos() && !arp::en_attente() && tache::au_repos()
}

/// Configure le réseau par DHCP, et attend la fin : dans le lanceur, avant
/// /etc/demarrage.
pub fn configurer() {
    dhcp::configurer();
}
