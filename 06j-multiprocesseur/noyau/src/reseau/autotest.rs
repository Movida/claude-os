//! L'auto-test du démarrage de la MTU du chemin : aucun lien de nos machines de test ne
//! dit « fragmentation nécessaire » (slirp n'en envoie pas, et nos programmes n'ont pas de
//! socket brute pour la forger). Plutôt qu'une interface de test, que seul un test
//! connaîtrait, le noyau s'envoie le message à lui-même, par le chemin entier d'un ICMP reçu
//! (`icmp::recevoir`), pour des connexions de `lo` vers des adresses à lui, comme
//! `linux/pmtu.c` le fait sur l'hôte avec une socket brute. Les valeurs attendues sont
//! celles qu'y donne Linux. Ce qu'on a appris est oublié à la fin.

use super::boucle;
use super::paquet::Paquet;
use super::socket::{Protocole, Socket};
use super::{datagramme, icmp, tcp};
use crate::partage::{Arc, ArcVide};
use formats::reseau::icmp as ficmp;
use formats::reseau::ipv4 as fipv4;

const SOCK_STREAM: u16 = 1;
const SOCK_DGRAM: u16 = 2;
const EMSGSIZE: i32 = 90;

/// Reçoit, comme de 127.0.0.1, l'ICMP « fragmentation nécessaire, `mtu` » pour un paquet
/// de `source`:`port_source` vers `destination`:`port_destination`, de ce protocole, au
/// numéro de séquence `seq`.
#[allow(clippy::too_many_arguments)]
fn fragmentation(source: [u8; 4], destination: [u8; 4], protocole: u8, port_source: u16, port_destination: u16, seq: u32, mtu: u16) -> Option<()> {
    let lo = boucle::interface()?;
    let mut p = Paquet::vide(ficmp::ENTETE + fipv4::ENTETE + 8)?;
    let o = p.ajouter_fin(ficmp::ENTETE + fipv4::ENTETE + 8)?;
    {
        let interne: &mut [u8; fipv4::ENTETE] = (&mut o[ficmp::ENTETE..ficmp::ENTETE + fipv4::ENTETE]).try_into().ok()?;
        fipv4::ecrire(interne, &fipv4::Ipv4 {
            tos: 0, longueur: mtu + 100, identifiant: 1, ne_pas_fragmenter: true, fragments_suivants: false, decalage: 0, ttl: 64,
            protocole, source, destination, longueur_entete: fipv4::ENTETE,
        });
    }
    let suite = &mut o[ficmp::ENTETE + fipv4::ENTETE..];
    suite[..2].copy_from_slice(&port_source.to_be_bytes());
    suite[2..4].copy_from_slice(&port_destination.to_be_bytes());
    suite[4..8].copy_from_slice(&seq.to_be_bytes());
    let mut reste = [0u8; 4];
    reste[2..4].copy_from_slice(&mtu.to_be_bytes());
    ficmp::ecrire(o, &ficmp::Icmp { genre: ficmp::INJOIGNABLE, code: ficmp::FRAGMENTATION, reste });
    let h = fipv4::Ipv4 {
        tos: 0, longueur: (fipv4::ENTETE + p.longueur()) as u16, identifiant: 2, ne_pas_fragmenter: false, fragments_suivants: false, decalage: 0, ttl: 64,
        protocole: fipv4::ICMP, source: boucle::ADRESSE, destination: boucle::ADRESSE, longueur_entete: fipv4::ENTETE,
    };
    icmp::recevoir(lo, &h, false, p);
    Some(())
}

fn creer(protocole: Protocole, sorte: u16, proto: u16) -> Option<Arc<Socket>> {
    let s = Socket::new(protocole, sorte, proto, 0)?;
    let s = if protocole == Protocole::Tcp { s.tcp()? } else { s };
    Some(ArcVide::new().ok()?.remplir(s))
}

/// Une adresse AF_INET.
fn adresse(a: [u8; 4], port: u16) -> [u8; 16] {
    let mut o = [0u8; 16];
    o[0] = 2;
    o[2..4].copy_from_slice(&port.to_be_bytes());
    o[4..8].copy_from_slice(&a);
    o
}

/// UDP : une socket connectée voit EMSGSIZE, et une autre vers la même destination voit la
/// MTU ; sous le plancher : 552, plus rien ne la change.
fn udp() -> Result<(), &'static str> {
    const D: [u8; 4] = [127, 0, 0, 77];
    const ETAPE: &str = "UDP : la mise en place";
    let s = creer(Protocole::Udp, SOCK_DGRAM, 17).ok_or(ETAPE)?;
    let autre = creer(Protocole::Udp, SOCK_DGRAM, 17).ok_or(ETAPE)?;
    datagramme::connecter(&s, &adresse(D, 9)).map_err(|_| ETAPE)?;
    datagramme::connecter(&autre, &adresse(D, 10)).map_err(|_| ETAPE)?;
    if datagramme::mtu(&s) != Some(65_535) {
        return Err("UDP : la MTU de lo au depart");
    }
    let (source, port) = {
        let i = s.appels.verrouiller();
        (i.source, i.port)
    };
    fragmentation(source, D, fipv4::UDP, port, 9, 0, 1200).ok_or(ETAPE)?;
    let e = s.prendre_erreur();
    if e != EMSGSIZE || datagramme::mtu(&s) != Some(1200) || datagramme::mtu(&autre) != Some(1200) {
        return Err("UDP : FRAG 1200 : EMSGSIZE, et la MTU de la route");
    }
    fragmentation(source, D, fipv4::UDP, port, 9, 0, 400).ok_or(ETAPE)?;
    s.prendre_erreur();
    if datagramme::mtu(&s) != Some(552) {
        return Err("UDP : FRAG 400 : 552");
    }
    fragmentation(source, D, fipv4::UDP, port, 9, 0, 1000).ok_or(ETAPE)?;
    s.prendre_erreur();
    if datagramme::mtu(&s) != Some(552) {
        return Err("UDP : verrouillee a 552");
    }
    super::ipv4::oublier_mtu(D);
    super::socket::fermer(&s);
    super::socket::fermer(&autre);
    Ok(())
}

/// TCP : un numéro hors du vol : rien ; dans le vol : le MSS baisse, sans erreur, et une
/// connexion neuve annonce d'après la MTU apprise.
fn tcp_mtu() -> Result<(), &'static str> {
    const D: [u8; 4] = [127, 0, 0, 78];
    const ETAPE: &str = "TCP : la mise en place";
    let l = creer(Protocole::Tcp, SOCK_STREAM, 6).ok_or(ETAPE)?;
    tcp::lier(&l, &adresse(D, 40078)).map_err(|_| ETAPE)?;
    tcp::ecouter(&l, 2).map_err(|_| ETAPE)?;
    // Un `accept` qui attend, borné : la livraison par `lo` se fait d'ordinaire dans `connect`, mais
    // si la tâche du réseau vide déjà sa file, c'est elle qui livrera.
    l.appels.verrouiller().options.rcvtimeo = Some(5_000_000_000);
    let c = creer(Protocole::Tcp, SOCK_STREAM, 6).ok_or(ETAPE)?;
    let _ = tcp::connecter(&c, &adresse(D, 40078), true);
    let (a, _, _) = tcp::accepter(&l, false).map_err(|_| "TCP : la connexion sur lo")?;
    let (source, port, _, nxt) = tcp::numeros_de(&c).ok_or(ETAPE)?;
    let hors = nxt.wrapping_add(100_000);
    fragmentation(source, D, fipv4::TCP, port, 40078, hors, 1000).ok_or(ETAPE)?;
    if tcp::mtu_du_chemin(&c) != Some(65_535) {
        return Err("TCP : FRAG hors du vol : rien, pas meme la route");
    }
    tcp::envoyer(&c, 1000, 0, |_, o| {
        o.fill(0);
        Ok(())
    }).map_err(|_| "TCP : l'envoi")?;
    let (_, _, _, nxt) = tcp::numeros_de(&c).ok_or(ETAPE)?;
    fragmentation(source, D, fipv4::TCP, port, 40078, nxt, 1000).ok_or(ETAPE)?;
    let (mss, pmtu) = tcp::mss_et_pmtu(&c).ok_or(ETAPE)?;
    if mss != 948 || pmtu != 1000 || tcp::mtu_du_chemin(&c) != Some(1000) {
        return Err("TCP : FRAG 1000 : MSS 948, pmtu 1000");
    }
    if c.prendre_erreur() != 0 {
        return Err("TCP : FRAG 1000 : aucune erreur");
    }
    let neuve = creer(Protocole::Tcp, SOCK_STREAM, 6).ok_or(ETAPE)?;
    let _ = tcp::connecter(&neuve, &adresse(D, 40078), true);
    let (b, _, _) = tcp::accepter(&l, false).map_err(|_| "TCP : la deuxieme connexion")?;
    if tcp::advmss_de(&neuve) != Some(948) {
        return Err("TCP : une connexion neuve : advmss 948");
    }
    // `a` a des données non lues : `fermer` coupe par un RST. `b` ferme la première de sa paire :
    // elle finira en TIME_WAIT, le temps de son minuteur, sans rien retenir d'autre.
    for s in [&a, &b, &c, &neuve, &l] {
        tcp::fermer(s);
    }
    super::ipv4::oublier_mtu(D);
    Ok(())
}

/// Tout, avant les programmes.
pub fn lancer() {
    match udp().and_then(|()| tcp_mtu()) {
        Ok(()) => afficherln!("[reseau] la MTU du chemin, par un ICMP recu : ok."),
        Err(e) => afficherln!("[reseau] la MTU du chemin : {} : ECHEC", e),
    }
}
