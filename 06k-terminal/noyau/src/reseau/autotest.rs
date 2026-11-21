//! L'auto-test du démarrage de la MTU du chemin : aucun lien de nos machines de test ne
//! dit « fragmentation nécessaire » (slirp n'en envoie pas, et nos programmes n'ont pas de
//! socket brute pour la forger). Plutôt qu'une interface de test, que seul un test
//! connaîtrait, le noyau s'envoie le message à lui-même, par le chemin entier d'un ICMP reçu
//! (`icmp::recevoir`), pour des connexions de `lo` vers des adresses à lui, comme
//! `linux/pmtu.c` le fait sur l'hôte avec une socket brute. Les valeurs attendues sont
//! celles qu'y donne Linux. Ce qu'on a appris est oublié à la fin.
//!
//! Les options IP d'un paquet reçu (les soldes d'avant 6k), de même : le noyau s'envoie par
//! `lo` des datagrammes à options, comme si une de ses sockets les avait écrits, et la
//! réception les lit comme tout paquet qui arrive. Trois cas de
//! formats/tests/reseau/options-ip.txt (que `linux/options-ip.c` vérifie sur Linux) : une
//! option fausse (son « problème de paramètre » revient à la socket, qui le voit dans sa
//! file d'erreurs avec l'octet fautif), une route source (jetée sans un mot), une route
//! notée (livrée).
//!
//! La somme d'un segment TCP de plus de 76 octets (CHECKSUM_BREAK), de même : Linux ne
//! l'achève qu'une fois sa socket trouvée, et une connexion ESTABLISHED compte alors une perte
//! (`sk_drops`, SO_MEMINFO). `lo` ne vérifie aucune somme, et nos programmes ne peuvent pas
//! forger de segment : le noyau donne à TCP des segments à la somme fausse comme reçus par la
//! carte (`tcp::recevoir`, après IPv4 : des adresses de `lo` ne passeraient pas sa vérification
//! des sources), pour une connexion de `lo`.

use super::boucle;
use super::paquet::Paquet;
use super::socket::{Protocole, Socket};
use super::snmp::MIB;
use super::{datagramme, icmp, tcp};
use crate::partage::{Arc, ArcVide};
use formats::reseau::icmp as ficmp;
use formats::reseau::ipv4 as fipv4;
use formats::reseau::tcp as ftcp;
use inet::snmp::Tcp as CompteurTcp;

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
    let entete = super::ipv4::EnteteRecu::de(&h, &[], fipv4::Options::AUCUNES, 0);
    icmp::recevoir(lo, lo.index, &h, &entete, false, p);
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

/// Envoie par `lo`, comme s'il venait de `source`:`port_source`, un datagramme UDP d'un
/// octet vers `destination`:`port_destination`, aux options `options` (un multiple de 4
/// octets) : la réception le lit avant que l'envoi ne rende la main (boucle.rs).
fn datagramme_a_options(source: [u8; 4], port_source: u16, destination: [u8; 4], port_destination: u16, options: &[u8]) -> Option<()> {
    let lo = boucle::interface()?;
    let entete = fipv4::ENTETE + options.len();
    let mut p = Paquet::vide(entete + 9)?;
    let o = p.ajouter_fin(entete + 9)?;
    {
        let e: &mut [u8; fipv4::ENTETE] = (&mut o[..fipv4::ENTETE]).try_into().ok()?;
        fipv4::ecrire(e, &fipv4::Ipv4 {
            tos: 0, longueur: (entete + 9) as u16, identifiant: 3, ne_pas_fragmenter: false, fragments_suivants: false, decalage: 0, ttl: 64,
            protocole: fipv4::UDP, source, destination, longueur_entete: entete,
        });
    }
    // `ecrire` n'écrit pas d'options : la longueur de l'en-tête et sa somme, refaites.
    o[0] = 0x40 | (entete / 4) as u8;
    o[fipv4::ENTETE..entete].copy_from_slice(options);
    o[10..12].fill(0);
    let somme = formats::reseau::plier(formats::reseau::somme(&o[..entete], 0));
    o[10..12].copy_from_slice(&somme.to_be_bytes());
    let u = &mut o[entete..];
    u[..2].copy_from_slice(&port_source.to_be_bytes());
    u[2..4].copy_from_slice(&port_destination.to_be_bytes());
    u[4..6].copy_from_slice(&9u16.to_be_bytes());
    u[8] = b'x';
    super::ethernet::emettre(lo, [0; 6], formats::reseau::ethernet::IPV4, p);
    Some(())
}

/// Les options IP d'un paquet reçu : une fausse, une route source, une route notée (voir
/// l'en-tête du module).
fn options() -> Result<(), &'static str> {
    const D: [u8; 4] = [127, 0, 0, 79];
    const ETAPE: &str = "options : la mise en place";
    const EPROTO: i32 = 71;
    let s = creer(Protocole::Udp, SOCK_DGRAM, 17).ok_or(ETAPE)?;
    let r = creer(Protocole::Udp, SOCK_DGRAM, 17).ok_or(ETAPE)?;
    datagramme::connecter(&s, &adresse(D, 9)).map_err(|_| ETAPE)?;
    datagramme::lier(&r, &adresse(D, 40079)).map_err(|_| ETAPE)?;
    s.recverr.store(true, core::sync::atomic::Ordering::Relaxed);
    let (source, port) = {
        let i = s.appels.verrouiller();
        (i.source, i.port)
    };
    // « route-courte » : une route notée de 2 octets ; l'octet 21 (sa longueur) est fautif.
    // La socket connectée voit EPROTO (SO_ERROR, qui laisse la file), puis la file dit
    // l'octet (la lire efface SO_ERROR, comme `sock_dequeue_err_skb`).
    datagramme_a_options(source, port, D, 9, &[7, 2, 0, 0]).ok_or(ETAPE)?;
    if s.prendre_erreur() != EPROTO {
        return Err("une option fausse : EPROTO pour la socket connectee");
    }
    match s.prendre_en_file() {
        Some(e) if e.errno == EPROTO && e.genre == ficmp::PARAMETRE && e.code == 0 && e.info == 21 => {}
        _ => return Err("une option fausse : le probleme de parametre, octet 21"),
    }
    // « route-source-lache » : jetée, sans un mot.
    datagramme_a_options(source, port, D, 9, &[0x83, 7, 4, 10, 0, 0, 2, 0]).ok_or(ETAPE)?;
    if s.prendre_en_file().is_some() || s.prendre_erreur() != 0 {
        return Err("une route source : jetee sans rien dire");
    }
    // « route-notee » : livrée.
    datagramme_a_options(source, port, D, 40079, &[7, 7, 4, 0, 0, 0, 0, 0]).ok_or(ETAPE)?;
    if r.reception.verrouiller().file.len() != 1 {
        return Err("une route notee : livree");
    }
    super::socket::fermer(&s);
    super::socket::fermer(&r);
    Ok(())
}

/// Donne à TCP, comme reçu par la carte `carte`, un segment de `de` vers `vers` (adresse,
/// port), ACK de `ack` (et SYN si `syn`), de numéro `seq`, à `n` octets de charge, la somme
/// fausse.
fn segment_faux(carte: &super::interface::Interface, de: ([u8; 4], u16), vers: ([u8; 4], u16), seq: u32, ack: u32, syn: bool, n: usize) -> Option<()> {
    let mut p = Paquet::vide(ftcp::ENTETE + n)?;
    let o = p.ajouter_fin(ftcp::ENTETE + n)?;
    let drapeaux = ftcp::ACK | if syn { ftcp::SYN } else { 0 };
    let t = ftcp::Tcp { source: de.1, destination: vers.1, seq, ack, drapeaux, fenetre: 65535, ..ftcp::Tcp::default() };
    ftcp::ecrire(o, &t, de.0, vers.0, true);
    o[16] ^= 0xff;
    let h = fipv4::Ipv4 {
        tos: 0, longueur: (fipv4::ENTETE + ftcp::ENTETE + n) as u16, identifiant: 4, ne_pas_fragmenter: true, fragments_suivants: false,
        decalage: 0, ttl: 64, protocole: fipv4::TCP, source: de.0, destination: vers.0, longueur_entete: fipv4::ENTETE,
    };
    let recu = super::ipv4::EnteteRecu::de(&h, &[], fipv4::Options::AUCUNES, 0);
    tcp::recevoir(&h, &recu, carte, carte.index, false, p);
    Some(())
}

/// La somme fausse d'un segment TCP (voir l'en-tête du module) : de plus de 76 octets, une
/// erreur et une perte pour une connexion ESTABLISHED ; une erreur seule pour une écoute, ou
/// sans socket (et pas de RST) ; jusqu'à 76 octets, une erreur seule, vue à l'arrivée.
fn somme_tcp() -> Result<(), &'static str> {
    const D: [u8; 4] = [127, 0, 0, 79];
    const ETAPE: &str = "la mise en place";
    // Sans carte (une machine sans réseau), rien à recevoir par elle.
    let Some(carte) = super::interface::premiere_carte() else { return Ok(()) };
    let l = creer(Protocole::Tcp, SOCK_STREAM, 6).ok_or(ETAPE)?;
    tcp::lier(&l, &adresse(D, 40079)).map_err(|_| ETAPE)?;
    tcp::ecouter(&l, 2).map_err(|_| ETAPE)?;
    l.appels.verrouiller().options.rcvtimeo = Some(5_000_000_000);
    let c = creer(Protocole::Tcp, SOCK_STREAM, 6).ok_or(ETAPE)?;
    let _ = tcp::connecter(&c, &adresse(D, 40079), true);
    let (a, _, _) = tcp::accepter(&l, false).map_err(|_| "la connexion sur lo")?;
    let (source, port, _, seq) = tcp::numeros_de(&c).ok_or(ETAPE)?;
    let (_, _, _, ack) = tcp::numeros_de(&a).ok_or(ETAPE)?;
    let compte = || (MIB.valeur_tcp(CompteurTcp::InCsumErrors), MIB.valeur_tcp(CompteurTcp::OutRsts), a.pertes.load(core::sync::atomic::Ordering::Relaxed), l.pertes.load(core::sync::atomic::Ordering::Relaxed));
    // (Le SYN pour l'écoute vient d'un autre port : celui de `c` désigne `a`.)
    let essai = |de: u16, vers: u16, syn: bool, n: usize, attendu: (u64, u64, u32, u32), message| {
        let (e, r, pa, pl) = compte();
        segment_faux(carte, (source, de), (D, vers), seq, ack, syn, n).ok_or(ETAPE)?;
        let (e2, r2, pa2, pl2) = compte();
        if (e2 - e, r2 - r, pa2 - pa, pl2 - pl) != attendu {
            return Err(message);
        }
        Ok(())
    };
    let autre = port.wrapping_add(1);
    let r = essai(port, 40079, false, 100, (1, 0, 1, 0), "ESTABLISHED, 120 octets : une erreur, une perte")
        .and_then(|()| essai(port, 40079, false, 56, (1, 0, 0, 0), "ESTABLISHED, 76 octets : une erreur, sans perte"))
        .and_then(|()| essai(autre, 40079, true, 100, (1, 0, 0, 0), "l'ecoute, un SYN de 120 octets : une erreur, sans perte"))
        .and_then(|()| essai(port, 40080, false, 100, (1, 0, 0, 0), "sans socket, 120 octets : une erreur, sans RST"));
    for s in [&a, &c, &l] {
        tcp::fermer(s);
    }
    r
}

/// Tout, avant les programmes.
pub fn lancer() {
    match udp().and_then(|()| tcp_mtu()) {
        Ok(()) => afficherln!("[reseau] la MTU du chemin, par un ICMP recu : ok."),
        Err(e) => afficherln!("[reseau] la MTU du chemin : {} : ECHEC", e),
    }
    match options() {
        Ok(()) => afficherln!("[reseau] les options IP d'un paquet recu, comme Linux : ok."),
        Err(e) => afficherln!("[reseau] les options IP : {} : ECHEC", e),
    }
    match somme_tcp() {
        Ok(()) => afficherln!("[reseau] la somme TCP d'un long segment, vue par sa socket : ok."),
        Err(e) => afficherln!("[reseau] la somme TCP d'un long segment : {} : ECHEC", e),
    }
}
