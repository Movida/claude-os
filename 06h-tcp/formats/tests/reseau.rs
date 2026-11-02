//! Les en-têtes du réseau contre de vraies trames, échangées avec le réseau
//! utilisateur de QEMU 8.2 (capturées par tests/reseau/capturer.sh) : une
//! réponse ARP de slirp, et l'échange DHCP (nos deux messages, les deux
//! siens) ; puis des en-têtes abîmés à la main, chacun refusé pour la
//! bonne raison ; puis des mutations au hasard, à graine fixe : aucune
//! panique, et ce qui est accepté reste dans les octets reçus.

use formats::reseau::{self, Erreur, arp, dhcp, ethernet, icmp, ipv4, tcp, udp};
use std::path::PathBuf;

fn trame(nom: &str) -> Vec<u8> {
    let chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reseau").join(format!("{nom}.dat"));
    std::fs::read(&chemin).unwrap_or_else(|_| panic!("pas de capture {} (tests/reseau/capturer.sh)", chemin.display()))
}

const NOTRE_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const SLIRP_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

#[test]
fn somme_de_l_internet() {
    // L'exemple de la RFC 1071 (section 3) : la somme 0xddf2, d'où 0x220d.
    let o = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(reseau::somme(&o, 0), 0x2ddf0);
    assert_eq!(reseau::plier(reseau::somme(&o, 0)), 0x220d);
    // En morceaux (pairs), la même ; un octet seul à la fin compte comme
    // l'octet fort d'un mot.
    assert_eq!(reseau::plier(reseau::somme(&o[4..], reseau::somme(&o[..4], 0))), 0x220d);
    assert_eq!(reseau::somme(&[0xab], 0), 0xab00);
}

/// L'en-tête IPv4 et la charge UDP d'une trame DHCP capturée.
fn dhcp_de(nom: &str) -> (ethernet::Ethernet, ipv4::Ipv4, udp::Udp, Vec<u8>) {
    let t = trame(nom);
    let (e, reste) = ethernet::lire(&t).unwrap();
    let (h, charge) = ipv4::lire(reste).unwrap();
    let (u, message) = udp::lire(charge, h.source, h.destination).unwrap();
    (e, h, u, message.to_vec())
}

#[test]
fn offre_et_accuse_de_slirp() {
    for nom in ["dhcp-offer", "dhcp-ack"] {
        let (e, h, u, message) = dhcp_de(nom);
        assert_eq!((e.destination, e.source, e.genre), (ethernet::DIFFUSION, SLIRP_MAC, ethernet::IPV4), "{nom}");
        assert!(e.vers_un_groupe());
        assert_eq!((h.source, h.destination, h.protocole, h.longueur, h.longueur_entete), ([10, 0, 2, 2], ipv4::DIFFUSION, ipv4::UDP, 576, 20));
        assert!(!h.est_un_fragment());
        assert_eq!((u.source, u.destination), (dhcp::PORT_SERVEUR, dhcp::PORT_CLIENT));
        let m = dhcp::lire(&message).unwrap();
        assert!(m.reponse);
        assert_eq!((m.adresse, m.client), ([10, 0, 2, 15], NOTRE_MAC));
        assert_eq!(m.sorte(), Some(if nom == "dhcp-offer" { dhcp::OFFER } else { dhcp::ACK }));
        // Ce que donne slirp (libslirp, bootp.c) : le serveur, le masque, la
        // passerelle, le DNS, un bail d'un jour ; pas de MTU ni de domaine.
        assert_eq!(m.adresse_option(dhcp::SERVEUR), Some([10, 0, 2, 2]));
        assert_eq!(m.adresse_option(dhcp::MASQUE), Some([255, 255, 255, 0]));
        assert_eq!(m.adresse_option(dhcp::PASSERELLES), Some([10, 0, 2, 2]));
        assert_eq!(m.option(dhcp::DNS), Some(&[10, 0, 2, 3][..]));
        assert_eq!(m.option(dhcp::BAIL), Some(&86_400u32.to_be_bytes()[..]));
        assert_eq!((m.option(dhcp::MTU), m.option(dhcp::DOMAINE)), (None, None));
    }
}

/// Récrit une trame DHCP du client comme le ferait notre noyau, d'après ce
/// que dit la capture (l'identifiant, les secondes, la sorte, l'offre) : les
/// mêmes octets, en-têtes et sommes compris.
fn recrire(nom: &str) -> Vec<u8> {
    let t = trame(nom);
    let (_, h, _, message) = dhcp_de(nom);
    let m = dhcp::lire(&message).unwrap();
    let secondes = u16::from_be_bytes([message[8], message[9]]);
    let mut charge = [0u8; dhcp::TAILLE];
    dhcp::ecrire_requete(&mut charge, m.sorte().unwrap(), m.xid, secondes, NOTRE_MAC,
                         m.adresse_option(dhcp::ADRESSE_DEMANDEE), m.adresse_option(dhcp::SERVEUR));
    let mut o = vec![0u8; ethernet::ENTETE + ipv4::ENTETE + udp::ENTETE + dhcp::TAILLE];
    o[42..].copy_from_slice(&charge);
    udp::ecrire(&mut o[34..], &udp::Udp { source: dhcp::PORT_CLIENT, destination: dhcp::PORT_SERVEUR }, ipv4::AUCUNE, ipv4::DIFFUSION);
    ipv4::ecrire((&mut o[14..34]).try_into().unwrap(), &ipv4::Ipv4 {
        tos: 0, longueur: 576, identifiant: h.identifiant, ne_pas_fragmenter: true, fragments_suivants: false, decalage: 0,
        ttl: 64, protocole: ipv4::UDP, source: ipv4::AUCUNE, destination: ipv4::DIFFUSION, longueur_entete: 20,
    });
    ethernet::ecrire((&mut o[..14]).try_into().unwrap(), &ethernet::Ethernet { destination: ethernet::DIFFUSION, source: NOTRE_MAC, genre: ethernet::IPV4 });
    assert_eq!(o.len(), t.len(), "{nom}");
    o
}

#[test]
fn nos_requetes_recrites() {
    assert_eq!(recrire("dhcp-discover"), trame("dhcp-discover"));
    assert_eq!(recrire("dhcp-request"), trame("dhcp-request"));
    let (_, h, _, message) = dhcp_de("dhcp-request");
    assert!(h.ne_pas_fragmenter && h.ttl == 64);
    let m = dhcp::lire(&message).unwrap();
    assert_eq!((m.reponse, m.sorte()), (false, Some(dhcp::REQUEST)));
    assert_eq!(m.adresse_option(dhcp::ADRESSE_DEMANDEE), Some([10, 0, 2, 15]));
}

#[test]
fn reponse_arp() {
    let t = trame("arp-reponse");
    let (e, reste) = ethernet::lire(&t).unwrap();
    assert_eq!((e.destination, e.source, e.genre), (NOTRE_MAC, SLIRP_MAC, ethernet::ARP));
    // slirp complète la trame à 64 octets (60, et 4 de plus).
    assert_eq!(reste.len(), 64 - ethernet::ENTETE);
    assert!(!e.vers_un_groupe());
    // La réponse à notre sonde de 0.0.0.0 : « 10.0.2.2, c'est moi ».
    let a = arp::lire(reste).unwrap();
    assert_eq!(a, arp::Arp { operation: arp::REPONSE, mac_emetteur: SLIRP_MAC, ip_emetteur: [10, 0, 2, 2],
                             mac_cible: NOTRE_MAC, ip_cible: [0; 4] });
    // Réécrite : les mêmes 28 octets.
    let mut o = [0u8; arp::TAILLE];
    arp::ecrire(&mut o, &a);
    assert_eq!(&o[..], &reste[..arp::TAILLE]);
    // Le type de matériel 6 (IEEE 802) est accepté, comme par Linux.
    let mut m = reste.to_vec();
    m[1] = 6;
    assert_eq!(arp::lire(&m), Ok(a));
    // Pas Ethernet, pas IPv4, des longueurs fausses, tronquée.
    for (i, v) in [(1, 7), (3, 0xdd), (4, 8), (5, 16)] {
        let mut m = reste.to_vec();
        m[i] = v;
        assert_eq!(arp::lire(&m), Err(Erreur::Invalide), "octet {i}");
    }
    assert_eq!(arp::lire(&reste[..27]), Err(Erreur::Tronque));
}

#[test]
fn ipv4_abime() {
    let t = trame("dhcp-offer");
    let ip = &t[14..];
    assert_eq!(ipv4::lire(&ip[..19]), Err(Erreur::Tronque));
    let mut o = ip.to_vec();
    o[0] = 0x65; // version 6
    assert_eq!(ipv4::lire(&o), Err(Erreur::Invalide));
    let mut o = ip.to_vec();
    o[0] = 0x44; // IHL 4
    assert_eq!(ipv4::lire(&o), Err(Erreur::Invalide));
    let mut o = ip.to_vec();
    o[0] = 0x4f; // IHL 15 : 60 octets d'en-tête, la somme ne tient plus
    assert_eq!(ipv4::lire(&o[..40]), Err(Erreur::Tronque));
    assert_eq!(ipv4::lire(&o), Err(Erreur::Somme));
    let mut o = ip.to_vec();
    o[8] ^= 1; // le TTL change, pas la somme
    assert_eq!(ipv4::lire(&o), Err(Erreur::Somme));
    // Une longueur totale au-delà de ce qui est reçu, ou plus courte que
    // l'en-tête (la somme refaite à chaque fois).
    for (longueur, attendu) in [(577u16, Erreur::Tronque), (19, Erreur::Invalide)] {
        let mut o = ip.to_vec();
        o[2..4].copy_from_slice(&longueur.to_be_bytes());
        o[10..12].fill(0);
        let s = reseau::plier(reseau::somme(&o[..20], 0));
        o[10..12].copy_from_slice(&s.to_be_bytes());
        assert_eq!(ipv4::lire(&o), Err(attendu));
        // L'en-tête seul (d'un paquet dont on n'a que le début) : une
        // longueur au-delà de ce qu'on a passe, pas une trop courte.
        let seul = if attendu == Erreur::Tronque { Ok(longueur) } else { Err(attendu) };
        assert_eq!(ipv4::lire_entete(&o).map(|h| h.longueur), seul);
    }
    // Du bourrage après la longueur totale : ôté de la charge.
    let mut o = ip.to_vec();
    o.extend_from_slice(&[0; 10]);
    assert_eq!(ipv4::lire(&o).unwrap().1.len(), 556);
}

#[test]
fn udp_abime() {
    let t = trame("dhcp-offer");
    let (h, charge) = ipv4::lire(&t[14..]).unwrap();
    let (s, d) = (h.source, h.destination);
    assert_eq!(udp::lire(&charge[..7], s, d), Err(Erreur::Tronque));
    // Une longueur au-delà du paquet, ou plus courte que l'en-tête.
    for longueur in [557u16, 7] {
        let mut o = charge.to_vec();
        o[4..6].copy_from_slice(&longueur.to_be_bytes());
        assert_eq!(udp::lire(&o, s, d), Err(Erreur::Tronque));
    }
    // Un octet changé : la somme ne va plus ; arrivé à une autre adresse
    // (le pseudo-en-tête) non plus ; une somme nulle : pas de somme.
    let mut o = charge.to_vec();
    o[100] ^= 0x10;
    assert_eq!(udp::lire(&o, s, d), Err(Erreur::Somme));
    assert_eq!(udp::lire(charge, s, [10, 0, 2, 15]), Err(Erreur::Somme));
    o[6..8].fill(0);
    assert!(udp::lire(&o, s, d).is_ok());
    // Une longueur plus courte que le paquet : le reste est ôté (et la
    // somme ne couvre que la longueur).
    let mut o = vec![0u8; 20];
    o[8..12].copy_from_slice(b"abcd");
    udp::ecrire(&mut o[..12], &udp::Udp { source: 1, destination: 2 }, [1, 2, 3, 4], [5, 6, 7, 8]);
    assert_eq!(udp::lire(&o, [1, 2, 3, 4], [5, 6, 7, 8]).unwrap().1, b"abcd");
}

#[test]
fn options_dhcp_abimees() {
    let (_, _, _, message) = dhcp_de("dhcp-offer");
    let mut o = message.clone();
    o[236] = 98; // le cookie
    assert_eq!(dhcp::lire(&o), Err(Erreur::Invalide));
    assert_eq!(dhcp::lire(&message[..239]), Err(Erreur::Tronque));
    // Des options faites à la main : bourrage, une option, une qui déborde.
    let mut o = message[..240].to_vec();
    o.extend_from_slice(&[0, 0, 53, 1, 2, 0, 6, 8, 10, 0, 2, 3]);
    let m = dhcp::lire(&o).unwrap();
    assert_eq!(m.options().collect::<Vec<_>>(), [(53, &[2][..])]);
    assert_eq!(m.option(dhcp::DNS), None);
    // FIN arrête, même suivie d'autres options.
    let mut o = message[..240].to_vec();
    o.extend_from_slice(&[53, 1, 5, 255, 6, 4, 1, 2, 3, 4]);
    assert_eq!(dhcp::lire(&o).unwrap().options().count(), 1);
    // Une option sans sa longueur : rien.
    let mut o = message[..240].to_vec();
    o.push(53);
    assert_eq!(dhcp::lire(&o).unwrap().options().count(), 0);
}

#[test]
fn masques() {
    assert_eq!(ipv4::masque(24), [255, 255, 255, 0]);
    assert_eq!((ipv4::masque(0), ipv4::masque(32)), ([0; 4], [255; 4]));
    assert_eq!(ipv4::prefixe([255, 255, 255, 0]), Some(24));
    assert_eq!(ipv4::prefixe([255, 0, 255, 0]), None);
    assert_eq!((ipv4::prefixe([0; 4]), ipv4::prefixe([255; 4])), (Some(0), Some(32)));
    assert!(ipv4::dans([10, 0, 2, 99], [10, 0, 2, 0], 24) && !ipv4::dans([10, 0, 3, 1], [10, 0, 2, 0], 24));
    assert!(ipv4::multidiffusion([224, 0, 0, 1]) && !ipv4::multidiffusion([10, 0, 2, 2]));
}

/// Un générateur à graine fixe (xorshift64*), pour des mutations qui se
/// rejouent.
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[test]
fn icmp_echo_et_erreur() {
    // Un écho de 4 octets : écrit, relu, sa somme couvre aussi les données.
    let mut o = vec![0u8; 12];
    o[8..].copy_from_slice(b"ping");
    let e = icmp::Icmp { genre: icmp::ECHO, code: 0, reste: icmp::reste_echo(0x1234, 7) };
    icmp::ecrire(&mut o, &e);
    let (lu, donnees) = icmp::lire(&o).unwrap();
    assert_eq!((lu, lu.echo(), donnees), (e, (0x1234, 7), &b"ping"[..]));
    o[10] ^= 1;
    assert_eq!(icmp::lire(&o), Err(Erreur::Somme));
    // Moins de 8 octets, la somme juste (0xFFFF, puis un mot nul : le
    // complément de leur somme est 0) : tronqué.
    assert_eq!(icmp::lire(&[0xFF, 0xFF, 0, 0]), Err(Erreur::Tronque));
    // Une erreur : le début du paquet d'origine, un datagramme UDP de
    // 10.0.2.15:40000 vers 10.0.2.2:9 ; il faut l'en-tête entier et 8
    // octets derrière.
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[9] = ipv4::UDP;
    p[12..16].copy_from_slice(&[10, 0, 2, 15]);
    p[16..20].copy_from_slice(&[10, 0, 2, 2]);
    p[20..22].copy_from_slice(&40000u16.to_be_bytes());
    p[22..24].copy_from_slice(&9u16.to_be_bytes());
    let i = icmp::interne(&p).unwrap();
    assert_eq!((i.protocole, i.source, i.destination, i.longueur_entete), (ipv4::UDP, [10, 0, 2, 15], [10, 0, 2, 2], 20));
    assert_eq!(icmp::ports(&p, &i), Some((40000, 9)));
    assert_eq!(icmp::interne(&p[..27]), None, "7 octets derrière l'en-tête");
    p[0] = 0x44;
    assert_eq!(icmp::interne(&p), None, "un en-tête de 4 mots");
    p[0] = 0x46;
    assert_eq!(icmp::interne(&p), None, "des options : l'en-tête et 8 octets ne tiennent plus");
    // Les genres qui sont des erreurs : ceux d'icmp_pointers (1, 2, 6, 7,
    // 9 et 10 compris), et les inconnus.
    let erreurs: Vec<u8> = (0..=255).filter(|&g| icmp::est_erreur(g)).collect();
    let attendues: Vec<u8> = [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12].into_iter().chain(19..=255).collect();
    assert_eq!(erreurs, attendues);
}

#[test]
fn mutations() {
    let mut h = Hasard(0x7e5e_a0de);
    let originaux: Vec<Vec<u8>> = ["arp-reponse", "dhcp-discover", "dhcp-offer", "dhcp-request", "dhcp-ack"].iter().map(|n| trame(n)).collect();
    let mut acceptes = 0;
    for n in 0..200_000 {
        let mut o = originaux[n % originaux.len()].clone();
        for _ in 0..1 + h.suivant() % 4 {
            let i = (h.suivant() as usize) % o.len();
            o[i] = h.suivant() as u8;
        }
        if h.suivant() % 8 == 0 {
            o.truncate((h.suivant() as usize) % (o.len() + 1));
        }
        // Le lecteur de DHCP seul, sur ce qui serait la charge d'UDP
        // (l'en-tête d'UDP n'a souvent plus sa somme après une mutation).
        if let Some(message) = o.get(42..) {
            if let Ok(m) = dhcp::lire(message) {
                acceptes += 1;
                assert!(m.options().count() <= message.len());
                let _ = (m.sorte(), m.adresse_option(dhcp::SERVEUR), m.option(dhcp::DNS));
            }
        }
        let Ok((_, reste)) = ethernet::lire(&o) else { continue };
        // Une mutation sur deux refait la somme d'IP, pour aller plus loin.
        let mut ip = reste.to_vec();
        if h.suivant() % 2 == 0 && ip.len() >= 20 {
            let ihl = ((ip[0] & 15) as usize * 4).max(20).min(ip.len());
            ip[10..12].fill(0);
            let s = reseau::plier(reseau::somme(&ip[..ihl], 0));
            ip[10..12].copy_from_slice(&s.to_be_bytes());
        }
        // L'en-tête seul : tout entier présent ; le même que celui de `lire`
        // quand `lire` l'accepte.
        let seul = ipv4::lire_entete(&ip);
        if let Ok(e) = seul {
            assert!(e.longueur_entete >= 20 && e.longueur_entete <= ip.len());
        }
        let Ok((entete, charge)) = ipv4::lire(&ip) else { continue };
        assert_eq!(seul, Ok(entete));
        assert!(entete.longueur_entete >= 20 && entete.longueur as usize <= ip.len() && charge.len() == entete.longueur as usize - entete.longueur_entete);
        if let Ok((_, message)) = udp::lire(charge, entete.source, entete.destination) {
            assert!(message.len() + udp::ENTETE <= charge.len());
        }
        // Lu comme un message ICMP, et comme le paquet qu'une erreur porte.
        if let Ok((_, donnees)) = icmp::lire(charge) {
            assert_eq!(donnees.len() + icmp::ENTETE, charge.len());
        }
        if let Some(i) = icmp::interne(charge) {
            assert!(i.longueur_entete + 8 <= charge.len() && icmp::ports(charge, &i).is_some());
        }
    }
    assert!(acceptes > 10_000, "trop peu de messages acceptés ({acceptes}) : le test ne mord plus");
}

/// Un segment écrit par `tcp::ecrire` : l'en-tête, ses options, la charge.
fn segment(t: &tcp::Tcp, charge: &[u8], s: [u8; 4], d: [u8; 4], somme: bool) -> Vec<u8> {
    let n = tcp::longueur_entete(&t.options);
    let mut o = vec![0u8; n + charge.len()];
    o[n..].copy_from_slice(charge);
    tcp::ecrire(&mut o, t, s, d, somme);
    o
}

#[test]
fn tcp_ecrit_puis_relu() {
    let (s, d) = ([10, 0, 2, 15], [160, 79, 104, 10]);
    let syn = tcp::Tcp {
        source: 40000, destination: 443, seq: 0xdead_beef, ack: 0, drapeaux: tcp::SYN, fenetre: 65535, urgent: 0,
        options: tcp::Options { mss: Some(1460), echelle: Some(7) },
    };
    let o = segment(&syn, &[], s, d, true);
    assert_eq!(o.len(), 28);
    // Les options comme Linux les aligne : MSS, puis NOP et l'échelle.
    assert_eq!(&o[20..], &[2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
    assert_eq!(tcp::lire(&o, s, d, true), Ok((syn, &[][..])));
    // Avec une charge, sans options.
    let t = tcp::Tcp { drapeaux: tcp::ACK | tcp::PSH, seq: 1, ack: 2, fenetre: 512, options: tcp::Options::default(), ..syn };
    let o = segment(&t, b"bonjour", s, d, true);
    assert_eq!(tcp::lire(&o, s, d, true), Ok((t, &b"bonjour"[..])));
    // Une charge de longueur impaire : la somme compte l'octet seul.
    let o = segment(&t, b"abc", s, d, true);
    assert!(tcp::lire(&o, s, d, true).is_ok());
    // Sans somme (lo) : relu sans la vérifier.
    let o = segment(&t, b"abc", s, d, false);
    assert_eq!(&o[16..18], &[0, 0]);
    assert_eq!(tcp::lire(&o, s, d, true), Err(Erreur::Somme));
    assert!(tcp::lire(&o, s, d, false).is_ok());
}

#[test]
fn tcp_abime() {
    let (s, d) = ([127, 0, 0, 1], [127, 0, 0, 1]);
    let t = tcp::Tcp { source: 1, destination: 2, seq: 3, ack: 4, drapeaux: tcp::ACK, fenetre: 5, ..Default::default() };
    let o = segment(&t, b"xy", s, d, true);
    assert_eq!(tcp::lire(&o[..19], s, d, true), Err(Erreur::Tronque));
    // Une longueur d'en-tête sous 20, ou au-delà du segment.
    let mut m = o.clone();
    m[12] = 4 << 4;
    assert_eq!(tcp::lire(&m, s, d, false), Err(Erreur::Invalide));
    m[12] = 6 << 4;
    assert_eq!(tcp::lire(&m[..22], s, d, false), Err(Erreur::Tronque));
    // Un octet changé : la somme ne va plus ; une autre adresse non plus.
    let mut m = o.clone();
    m[21] ^= 1;
    assert_eq!(tcp::lire(&m, s, d, true), Err(Erreur::Somme));
    assert_eq!(tcp::lire(&o, s, [127, 0, 0, 2], true), Err(Erreur::Somme));
}

#[test]
fn tcp_options_comme_linux() {
    let (s, d) = ([1, 1, 1, 1], [2, 2, 2, 2]);
    // Un en-tête de 32 octets aux options écrites à la main.
    let avec = |drapeaux: u8, opts: &[u8]| {
        let mut o = vec![0u8; 20 + opts.len()];
        o[12] = (((20 + opts.len()) / 4) as u8) << 4;
        o[13] = drapeaux;
        o[20..].copy_from_slice(opts);
        tcp::lire(&o, s, d, false).unwrap().0.options
    };
    // MSS et l'échelle, dans un SYN ; pas ailleurs.
    assert_eq!(avec(tcp::SYN, &[2, 4, 0, 200, 1, 3, 3, 9]), tcp::Options { mss: Some(200), echelle: Some(9) });
    assert_eq!(avec(tcp::ACK, &[2, 4, 0, 200, 1, 3, 3, 9]), tcp::Options::default());
    // Une échelle au-delà de 14 : 14.
    assert_eq!(avec(tcp::SYN, &[1, 3, 3, 20]).echelle, Some(14));
    // Les horodatages (8, longueur 10) et SACK permis (4, 2) : sautés.
    assert_eq!(avec(tcp::SYN, &[4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 2, 4, 5, 0]).mss, Some(0x500));
    // Une mauvaise longueur de MSS : ignorée ; une longueur 0 ou 1, ou qui
    // déborde : la lecture s'arrête, le segment reste bon.
    assert_eq!(avec(tcp::SYN, &[2, 3, 0, 1, 3, 3, 1, 0]).mss, None);
    assert_eq!(avec(tcp::SYN, &[8, 1, 2, 4, 0, 1, 0, 0]), tcp::Options::default());
    assert_eq!(avec(tcp::SYN, &[1, 1, 2, 9]), tcp::Options::default());
    // EOL arrête tout.
    assert_eq!(avec(tcp::SYN, &[0, 0, 2, 4, 0, 1, 0, 0]), tcp::Options::default());
}

#[test]
fn tcp_mutations() {
    // 200 000 segments abîmés au hasard : jamais de panique.
    let (s, d) = ([10, 0, 2, 15], [10, 0, 2, 2]);
    let t = tcp::Tcp { source: 9, destination: 80, drapeaux: tcp::SYN, options: tcp::Options { mss: Some(1460), echelle: Some(7) }, ..Default::default() };
    let base = segment(&t, b"donnees", s, d, true);
    let mut x = 0x1234_5678_9abc_def0u64;
    for _ in 0..200_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let mut m = base.clone();
        for k in 0..(x % 4 + 1) {
            let i = ((x >> (8 * k)) as usize) % m.len();
            m[i] = (x >> 32) as u8 ^ (k as u8);
        }
        m.truncate((x >> 40) as usize % (base.len() + 1));
        let _ = tcp::lire(&m, s, d, x & 1 == 0);
    }
}
