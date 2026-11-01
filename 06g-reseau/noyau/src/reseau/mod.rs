//! Le réseau (6g) : les cartes, les interfaces, les paquets, et la tâche du
//! noyau qui fait le travail des cartes.
//!
//! Comme dans Linux, une carte réseau ne fait presque rien dans son
//! interruption : elle dit qu'il y a du travail, et une tâche du noyau le
//! fait plus tard, interruptions permises (tache.rs). Les pilotes : la carte
//! virtio-net (virtio_net.rs). Ce que voit la pile d'une carte : son
//! interface (interface.rs) ; ce qui circule : des paquets (paquet.rs).

pub mod interface;
pub mod paquet;
pub mod tache;
pub mod virtio_net;

use core::sync::atomic::{AtomicU64, Ordering};
use interface::Interface;
use paquet::Paquet;

/// Les trames reçues, par sorte (l'EtherType de leur en-tête Ethernet,
/// octets 12 et 13) : ARP (0x0806) ; les autres. Rien ne les lit encore
/// au-delà : la pile au-dessus d'Ethernet vient ensuite.
static ARP_RECUES: AtomicU64 = AtomicU64::new(0);

/// Une trame reçue par l'interface `i`, dans la tâche du réseau.
pub fn recevoir(_i: &'static Interface, p: Paquet) {
    if p.donnees().get(12..14) == Some(&[0x08, 0x06]) {
        ARP_RECUES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Le nombre de trames ARP reçues depuis le démarrage.
pub fn arp_recues() -> u64 {
    ARP_RECUES.load(Ordering::Relaxed)
}

/// Trouve les cartes réseau et met en service celles qu'on sait piloter,
/// puis lance la tâche du réseau. Au démarrage, une fois les tâches et les
/// interruptions en service.
pub fn demarrer() {
    virtio_net::sonder();
    tache::lancer();
}
