//! Les en-têtes du réseau contre de vraies trames, échangées avec le réseau
//! utilisateur de QEMU 8.2 (capturées par tests/reseau/capturer.sh) : une
//! réponse ARP de slirp, et l'échange DHCP (nos deux messages, les deux
//! siens) ; puis des en-têtes abîmés à la main, chacun refusé pour la
//! bonne raison ; puis des mutations au hasard, à graine fixe : aucune
//! panique, et ce qui est accepté reste dans les octets reçus.

use formats::reseau::{self, Erreur, arp, dhcp, ethernet, ipv4, udp};
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
        let Ok((entete, charge)) = ipv4::lire(&ip) else { continue };
        assert!(entete.longueur_entete >= 20 && entete.longueur as usize <= ip.len() && charge.len() == entete.longueur as usize - entete.longueur_entete);
        if let Ok((_, message)) = udp::lire(charge, entete.source, entete.destination) {
            assert!(message.len() + udp::ENTETE <= charge.len());
        }
    }
    assert!(acceptes > 10_000, "trop peu de messages acceptés ({acceptes}) : le test ne mord plus");
}
