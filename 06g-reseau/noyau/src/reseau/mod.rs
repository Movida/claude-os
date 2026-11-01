//! Le réseau (6g) : les cartes, les interfaces, les paquets, la tâche du
//! noyau qui fait le travail des cartes, et la pile au-dessus.
//!
//! Comme dans Linux, une carte réseau ne fait presque rien dans son
//! interruption : elle dit qu'il y a du travail, et une tâche du noyau le
//! fait plus tard, interruptions permises (tache.rs). Les pilotes : la carte
//! virtio-net (virtio_net.rs). Ce que voit la pile d'une carte : son
//! interface (interface.rs) ; ce qui circule : des paquets (paquet.rs).
//! Les étages : Ethernet (ethernet.rs), ARP (arp.rs), IPv4 (ipv4.rs) ; la
//! configuration au démarrage par DHCP (dhcp.rs) ; ce qu'en montre
//! /proc/net (proc.rs). Les règles (les routes, le client DHCP, les
//! voisins) sont dans la bibliothèque inet,
//! testée sur l'hôte ; les en-têtes, dans formats::reseau.

pub mod arp;
pub mod dhcp;
pub mod ethernet;
pub mod interface;
pub mod ipv4;
pub mod paquet;
pub mod proc;
pub mod tache;
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
    virtio_net::sonder();
    tache::lancer();
}

/// Configure le réseau par DHCP, et attend la fin : dans le lanceur, avant
/// /etc/demarrage.
pub fn configurer() {
    dhcp::configurer();
}
