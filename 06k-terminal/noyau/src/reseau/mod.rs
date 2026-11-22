//! Le réseau (6g) : les cartes, les interfaces, les paquets, la tâche du
//! noyau qui fait le travail des cartes, et la pile au-dessus.
//!
//! Comme dans Linux, une carte réseau ne fait presque rien dans son
//! interruption : elle dit qu'il y a du travail, et une tâche du noyau le
//! fait plus tard, interruptions permises (tache.rs). Les pilotes : la carte
//! virtio-net (virtio_net.rs). Ce que voit la pile d'une carte : son
//! interface (interface.rs) ; ce qui circule : des paquets (paquet.rs).
//! Les étages : Ethernet (ethernet.rs), ARP (arp.rs), IPv4 (ipv4.rs), ICMP
//! (icmp.rs), UDP (udp.rs), les sockets de ping (ping.rs), les groupes de
//! multidiffusion (multidiffusion.rs) ; les horodatages d'émission
//! (horodatage.rs) ; les sockets, ce qu'en voient les programmes (socket.rs, ce
//! qu'ont en commun celles de datagrammes : datagramme.rs, et leurs appels
//! système : ../appels_reseau.rs) ; l'interface de boucle,
//! `lo` (boucle.rs) ; la configuration au démarrage par DHCP (dhcp.rs) ;
//! ce qu'en montre /proc/net (proc.rs), dont les compteurs de
//! /proc/net/snmp (snmp.rs). Les règles (les routes, le client
//! DHCP, les voisins, les ports) sont dans la bibliothèque inet, testée
//! sur l'hôte ; les en-têtes, dans formats::reseau.

pub mod arp;
pub mod autotest;
pub mod boucle;
pub mod contexte;
pub mod datagramme;
pub mod dhcp;
pub mod ethernet;
pub mod filtre;
pub mod horodatage;
pub mod icmp;
pub mod interface;
pub mod ipv4;
pub mod multidiffusion;
pub mod paquet;
pub mod ping;
pub mod proc;
pub mod snmp;
pub mod socket;
pub mod tache;
pub mod tcp;
pub mod udp;
pub mod unix;
// La carte virtio-net : de la mémoire partagée avec elle (ses tampons).
#[allow(unsafe_code)]
pub mod virtio_net;
pub mod zerocopie;

use interface::Interface;
use paquet::Paquet;

/// Une trame reçue par l'interface `i`, dans la tâche du réseau (ou, pour
/// lo, dans le contexte de qui l'a envoyée) : son heure d'arrivée d'abord
/// (`net_timestamp_check`, voir paquet::Contexte).
pub fn recevoir(i: &'static Interface, mut p: Paquet) {
    p.horodater(socket::heure_d_arrivee());
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
    tache::initialiser();
    tcp::initialiser();
    boucle::ajouter();
    virtio_net::sonder();
    tache::lancer();
}

/// Le nombre de sockets liées dont quelqu'un attend une lecture (le
/// détecteur d'interblocage, attente.rs).
pub fn attentes() -> usize {
    udp::attentes() + ping::attentes() + tcp::attentes()
}

/// Une connexion TCP a-t-elle un minuteur armé (une retransmission, un ACK
/// retardé, une sonde) ? Même par `lo`, il peut encore réveiller un
/// programme (le détecteur d'interblocage).
pub fn minuteur_tcp_arme() -> bool {
    tcp::minuteurs_armes() > 0
}

/// Le réseau est-il au repos : plus rien dans une file du noyau (celle de
/// `lo`, la petite file d'émission d'une carte, la file d'un voisin qui se
/// cherche), ni de travail en attente ou en cours de la tâche du réseau, ni
/// de rapport d'IGMP à faire (les groupes qu'un programme a quittés en
/// finissant sont annoncés pendant une seconde environ, gardés jusque-là) ?
/// Le lanceur l'attend avant de mesurer la mémoire rendue par un
/// programme : un paquet qu'il a envoyé peut encore être en route, et tenir
/// de la mémoire, quand il finit.
pub fn au_repos() -> bool {
    boucle::au_repos() && virtio_net::au_repos() && !arp::en_attente() && tache::au_repos() && tcp::orphelines() == 0
        && multidiffusion::au_repos()
}

/// Configure le réseau par DHCP, et attend la fin : dans le lanceur, avant
/// /etc/demarrage.
pub fn configurer() {
    dhcp::configurer();
}
