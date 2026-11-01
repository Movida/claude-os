//! Ethernet : l'étage qui reçoit les trames d'une carte et émet celles de
//! la pile (le `eth_type_trans` et le `eth_header` de Linux). Les en-têtes
//! eux-mêmes sont lus et écrits par formats::reseau::ethernet.

use super::interface::{Compteurs, Interface};
use super::paquet::Paquet;
use formats::reseau::ethernet::{self, Ethernet};

/// Une trame reçue par `i` : gardée si elle est pour nous (notre adresse
/// MAC, ou la diffusion), puis passée à l'étage de sa sorte. La
/// multidiffusion (les annonces d'IPv6 de slirp, par exemple) n'est pas
/// suivie : jetée, comme une sorte inconnue.
pub fn recevoir(i: &'static Interface, mut p: Paquet) {
    let Ok((e, _)) = ethernet::lire(p.donnees()) else {
        return Compteurs::compter(&i.compteurs.jetes_reception, 1);
    };
    if e.destination != i.mac && e.destination != ethernet::DIFFUSION {
        return;
    }
    let _ = p.retirer_entete(ethernet::ENTETE);
    match e.genre {
        ethernet::IPV4 => super::ipv4::recevoir(i, p),
        ethernet::ARP => super::compter_arp(),
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
