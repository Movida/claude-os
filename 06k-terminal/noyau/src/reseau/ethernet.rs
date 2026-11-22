//! Ethernet : l'étage qui reçoit les trames d'une carte et émet celles de
//! la pile (le `eth_type_trans` et le `eth_header` de Linux). Les en-têtes
//! eux-mêmes sont lus et écrits par formats::reseau::ethernet.

use super::interface::{Compteurs, Interface};
use super::paquet::{self, Contexte, Paquet};
use formats::reseau::ethernet::{self, Ethernet};

/// Une trame reçue par `i` : gardée si elle est pour nous (notre adresse
/// MAC), ou pour un groupe (la diffusion, ou une multidiffusion : le bit 0
/// du premier octet), comme le tri d'`eth_type_trans` (PACKET_HOST,
/// PACKET_BROADCAST, PACKET_MULTICAST ; IP et ARP jettent PACKET_OTHERHOST),
/// puis passée à l'étage de sa sorte (une autre sorte, comme les annonces
/// d'IPv6 de slirp, n'est pas suivie). Linux laisse la carte trier les
/// groupes (ou tout passer, en promiscuité) : IP trie ensuite (ipv4.rs : un
/// groupe que l'interface n'a pas est jeté). Une trame pour un groupe
/// n'appelle jamais d'erreur ICMP (`__icmp_send` : pkt_type ≠ PACKET_HOST),
/// et ne dit pas d'une voisine qu'elle est joignable (arp.rs).
pub fn recevoir(i: &'static Interface, mut p: Paquet) {
    let Ok((e, _)) = ethernet::lire(p.donnees()) else {
        return Compteurs::compter(&i.compteurs.jetes_reception, 1);
    };
    let groupe = e.vers_un_groupe();
    if e.destination != i.mac && !groupe {
        return;
    }
    // À qui allait la trame (`eth_type_trans` : `pkt_type`), et où commence son
    // en-tête : ce que voit le filtre d'une socket (paquet.rs, `Contexte`).
    let genre = match e.destination {
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff] => paquet::DIFFUSEE,
        _ if groupe => paquet::GROUPE,
        _ => paquet::HOTE,
    };
    p.poser_contexte(Contexte { genre, ..p.contexte() });
    p.noter_liaison();
    let _ = p.retirer_entete(ethernet::ENTETE);
    match e.genre {
        ethernet::IPV4 => super::ipv4::recevoir(i, p, groupe),
        ethernet::ARP => super::arp::recevoir(i, p.donnees(), groupe),
        _ => {}
    }
}

/// Émet le paquet `p` (la charge, en place) par `i`, vers la machine
/// d'adresse matérielle `destination` : l'en-tête Ethernet devant. Une
/// trame de moins de 60 octets n'est pas complétée ici : virtio-net ne le
/// demande pas (Linux non plus, virtio_net.c) ; sur un vrai câble, la carte
/// le fait, ou son pilote.
pub fn emettre(i: &'static Interface, destination: [u8; 6], genre: u16, mut p: Paquet) {
    let Some(entete) = p.ajouter_entete(ethernet::ENTETE) else {
        return Compteurs::compter(&i.compteurs.jetes_emission, 1);
    };
    let entete: &mut [u8; ethernet::ENTETE] = entete.try_into().expect("14 octets");
    ethernet::ecrire(entete, &Ethernet { destination, source: i.mac, genre });
    i.emettre(p);
}
