//! Les en-têtes du réseau contre de vraies trames, échangées avec le réseau
//! utilisateur de QEMU 8.2 (capturées par tests/reseau/capturer.sh) : une
//! réponse ARP de slirp, et l'échange DHCP (nos deux messages, les deux
//! siens) ; puis des en-têtes abîmés à la main, chacun refusé pour la
//! bonne raison ; puis des mutations au hasard, à graine fixe : aucune
//! panique, et ce qui est accepté reste dans les octets reçus.

use formats::reseau::{self, Erreur, arp, dhcp, ethernet, icmp, ipv4, plier, somme, somme_linux, somme_linux_moins, tcp, udp};
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
        // L'en-tête cité (d'un paquet dont on n'a que le début) : une
        // longueur au-delà de ce qu'on a passe, pas une trop courte.
        let seul = if attendu == Erreur::Tronque { Ok(longueur) } else { Err(attendu) };
        assert_eq!(ipv4::lire_cite(&o).map(|h| h.longueur), seul);
    }
    // La somme fausse : refusée à la réception, pas dans l'en-tête cité
    // (les options notées depuis l'arrivée, sans refaire la somme).
    let mut o = ip.to_vec();
    o[8] ^= 1;
    assert_eq!(ipv4::lire_cite(&o).map(|h| h.ttl), Ok(ip[8] ^ 1));
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
fn fragments_comme_linux() {
    // La découpe de `ip_frag_next` : les fragments pleins arrondis à 8,
    // le dernier tel quel, jusqu'à `mtu - entete`. 1 480 est un multiple
    // de 8 : rien ne change pour l'en-tête simple et une MTU de 1 500.
    let decoupe = |charge: usize, mtu: usize, entete: usize| {
        let mut tailles = Vec::new();
        let mut debut = 0;
        while debut < charge {
            let n = ipv4::taille_du_fragment(charge, debut, mtu, entete);
            tailles.push(n);
            debut += n;
        }
        assert_eq!(tailles.len().max(1), ipv4::nombre_de_fragments(charge, mtu, entete));
        tailles
    };
    assert_eq!(decoupe(1480, 1500, 20), [1480]);
    assert_eq!(decoupe(2960, 1500, 20), [1480, 1480]);
    assert_eq!(decoupe(2961, 1500, 20), [1480, 1480, 1]);
    // 4 octets d'options : 1 476 de place, 1 472 pour un fragment plein ;
    // un dernier de 1 476 tient (Linux : deux fragments, pas trois).
    assert_eq!(decoupe(2948, 1500, 24), [1472, 1476]);
    assert_eq!(decoupe(2949, 1500, 24), [1472, 1472, 5]);
    // La MTU la plus petite qu'apprend Linux (552) : 532 de place, 528
    // pour un fragment plein.
    assert_eq!(decoupe(1060, 552, 20), [528, 532]);
    assert_eq!(decoupe(532, 552, 20), [532]);
    assert_eq!(ipv4::nombre_de_fragments(0, 1500, 20), 1);
    // 68 octets et 40 d'options : 8 octets par fragment.
    assert_eq!(decoupe(20, 68, 60), [8, 8, 4]);
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

/// Les options d'un paquet reçu, lues par `compiler_options` comme Linux les
/// lit : les cas de tests/reseau/options-ip.txt, que linux/options-ip.c
/// vérifie sur le vrai Linux. L'adresse notée est 127.0.0.1, comme pour un
/// paquet de lo ; l'heure, 01020304 (les « .. » du fichier).
#[test]
fn options_comme_linux() {
    let chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reseau/options-ip.txt");
    let texte = std::fs::read_to_string(&chemin).unwrap();
    let hex = |h: &str| -> Vec<u8> { (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect() };
    let unicast = |a: [u8; 4]| !(a[0] == 127 || a[0] == 0 || a == ipv4::DIFFUSION || ipv4::multidiffusion(a));
    let ici = ipv4::Ici { adresse: [127, 0, 0, 1], heure: 0x0102_0304, unicast: &unicast };
    let mut vus = 0;
    for ligne in texte.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let mots: Vec<&str> = ligne.split_whitespace().collect();
        let (nom, options, issue) = (mots[0], hex(mots[1]), mots[2]);
        let mut entete = vec![0u8; ipv4::ENTETE];
        entete.extend_from_slice(&options);
        let lu = ipv4::compiler_options(&mut entete, &ici);
        match issue {
            "parametre" | "cipso" => assert_eq!(lu.map_err(|f| f.place), Err(mots[3].parse().unwrap()), "{nom}"),
            "jete" => assert!(lu.is_ok_and(|o| o.route_source != 0), "{nom} : {lu:?}"),
            "livre" | "muet" => {
                let o = lu.unwrap_or_else(|e| panic!("{nom} : refusé à l'octet {}", e.place));
                assert_eq!(o.route_source, 0, "{nom}");
                assert_eq!(entete[ipv4::ENTETE..], hex(&mots[3].replace("........", "01020304"))[..], "{nom}");
                assert_eq!(o.modifiees, mots[1] != mots[3], "{nom}");
                // Muet : l'écho des options échoue (l'erreur ICMP se tait).
                let echo = ipv4::options_echo(&entete[ipv4::ENTETE..], &o, [0; 4], &unicast);
                assert_eq!(echo.is_ok(), issue == "livre", "{nom} : {echo:?}");
            }
            _ => panic!("{nom} : issue inconnue {issue}"),
        }
        vus += 1;
    }
    assert!(vus >= 30, "{vus} cas seulement");
    // Ce que notent les options lues : la place de chacune.
    let mut e = vec![0u8; ipv4::ENTETE];
    e.extend_from_slice(&hex("010707040000000044040500940400008903040000000000"));
    let o = ipv4::compiler_options(&mut e, &ici).unwrap();
    assert_eq!((o.route_notee, o.horodatage, o.alerte, o.route_source, o.stricte), (21, 28, 32, 36, true));
    assert_eq!((o.route_notee_adresse, o.horodatage_adresse, o.horodatage_heure), (true, false, false));
    // Une faute garde ce qui la précède (`IPCB(skb)->opt`), dont l'erreur
    // ICMP fait l'écho : ici la première route notée, avec sa place prise.
    let mut e = vec![0u8; ipv4::ENTETE];
    e.extend_from_slice(&hex("0707040000000007030400"));
    let f = ipv4::compiler_options(&mut e, &ici).unwrap_err();
    assert_eq!((f.place, f.options.route_notee, f.options.route_notee_adresse), (27, 20, true));
    // Des options au hasard (des genres connus le plus souvent, des
    // longueurs et des pointeurs proches des bords) : jamais de panique, une
    // faute désigne un octet des options, et rien ne change hors d'elles ;
    // leur écho non plus ne panique pas.
    let mut h = Hasard(0x0123_4567_89ab_cdef);
    let genres = [0u8, 1, 7, 68, 130, 131, 134, 136, 137, 148];
    let mut fautes = 0;
    for _ in 0..200_000 {
        let n = 4 * (1 + h.suivant() as usize % 10);
        let mut e = vec![0x45u8; ipv4::ENTETE];
        for _ in 0..n {
            let x = h.suivant();
            e.push(match x % 4 {
                0 => genres[(x >> 8) as usize % genres.len()],
                1 => (x >> 8) as u8 % 16,
                _ => (x >> 8) as u8,
            });
        }
        let avant = e.clone();
        match ipv4::compiler_options(&mut e, &ici) {
            Err(ipv4::Faute { place, .. }) => {
                assert!((ipv4::ENTETE..e.len()).contains(&(place as usize)), "{avant:02x?} : {place}");
                fautes += 1;
            }
            // L'écho, et défait : jamais de panique, et au plus 40 octets.
            Ok(o) => {
                if let Ok(mut d) = ipv4::options_echo(&e[ipv4::ENTETE..], &o, [10, 0, 0, 1], &unicast) {
                    d.defaire();
                    assert!(d.octets().len() <= e.len() - ipv4::ENTETE + 3, "{avant:02x?}");
                }
            }
        }
        assert_eq!((e.len(), &e[..ipv4::ENTETE]), (avant.len(), &avant[..ipv4::ENTETE]));
    }
    assert!(fautes > 10_000 && fautes < 190_000, "{fautes} fautes : le hasard ne couvre plus les deux issues");
}

/// L'écho des options reçues (`options_echo`), puis défait (`defaire`) :
/// ce que rend IP_RETOPTS. Les trois premiers cas sont mesurés sous Linux
/// 6.18, sur lo (soldes, sondes-sol-ip/cmsg.txt : les options envoyées par
/// IP_OPTIONS, telles qu'à l'arrivée, IP_RECVOPTS, puis IP_RETOPTS).
#[test]
fn echo_des_options() {
    let hex = |h: &str| -> Vec<u8> { (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect() };
    let unicast = |a: [u8; 4]| !(a[0] == 127 || a[0] == 0 || a == ipv4::DIFFUSION || ipv4::multidiffusion(a));
    let ici = ipv4::Ici { adresse: [127, 0, 0, 1], heure: 0x04c3_cc10, unicast: &unicast };
    let source = [127, 0, 0, 1];
    // Les options telles qu'envoyées (l'émetteur y a écrit), ce qu'elles
    // deviennent à l'arrivée (RECVOPTS), puis l'écho défait (RETOPTS).
    let retour = |envoyees: &str| -> (Vec<u8>, Result<Vec<u8>, ()>) {
        let mut e = vec![0u8; ipv4::ENTETE];
        e.extend_from_slice(&hex(envoyees));
        let o = ipv4::compiler_options(&mut e, &ici).unwrap();
        let echo = ipv4::options_echo(&e[ipv4::ENTETE..], &o, source, &unicast).map(|mut d| {
            d.defaire();
            d.octets().to_vec()
        });
        (e[ipv4::ENTETE..].to_vec(), echo)
    };
    let (recues, echo) = retour("070b087f0000010000000000");
    assert_eq!((recues, echo), (hex("070b0c7f0000017f00000100"), Ok(hex("070b0c7f0000017f00000100"))));
    let (recues, echo) = retour("440c0d017f00000104c3cc1001000000");
    assert_eq!((recues, echo), (hex("440c0d117f00000104c3cc1001000000"), Ok(hex("440c0d117f00000104c3cc10"))));
    let (recues, echo) = retour("440c0d037f00000104c3cc10");
    assert_eq!((recues, echo), (hex("440c0d037f00000104c3cc10"), Ok(hex("440c0d037f00000104c3cc10"))));
    // Avec de la place : l'écho la réserve (le pointeur avance), puis la
    // rend en se défaisant ; notre adresse, notée à l'arrivée, reste.
    assert_eq!(retour("070b04000000000000000000").1, Ok(hex("070b087f0000010000000000")));
    assert_eq!(retour("440c05000000000000000000").1, Ok(hex("440c090004c3cc1000000000")));
    assert_eq!(retour("4414050100000000000000000000000000000000").1, Ok(hex("44140d017f00000104c3cc100000000000000000")));
    // Les adresses données d'avance : la nôtre (127.0.0.1) a reçu l'heure ;
    // la suivante n'est pas quelqu'un d'autre (127.0.0.2) : sa place est
    // réservée, puis rendue, le pointeur ramené devant elle.
    assert_eq!(retour("441405037f000001000000007f00000200000000").1, Ok(hex("44140d037f00000104c3cc107f00000200000000")));
    // Une place annoncée qui ne tient pas : Err.
    assert_eq!(retour("070904000000000000000000").1, Err(()));
    // Sans options : rien.
    assert_eq!(ipv4::options_echo(&[], &ipv4::Options::default(), source, &unicast).map(|d| d.longueur), Ok(0));
    // La route source (jamais livrée chez nous : seulement l'écho d'une
    // erreur) : les étapes faites, retournées ; la source du paquet ôtée.
    let s = [10, 0, 0, 9];
    let mut e = vec![0u8; ipv4::ENTETE];
    e.extend_from_slice(&hex("83130c0a0000010a0000020a0000030a00000400"));
    let o = ipv4::compiler_options(&mut e, &ici).unwrap();
    let d = ipv4::options_echo(&e[ipv4::ENTETE..], &o, s, &unicast).unwrap();
    assert_eq!((d.octets(), d.premier_saut, d.places.route_source), (&hex("830b040a0000010000000000")[..], [10, 0, 0, 2], 20));
    let mut defaite = d;
    defaite.defaire();
    assert_eq!(defaite.octets(), hex("830b040a0000020a00000100"));
    // Une seule étape faite, la source elle-même : pas de route de retour.
    let mut e = vec![0u8; ipv4::ENTETE];
    e.extend_from_slice(&hex("830b080a0000010a00000200"));
    let o = ipv4::compiler_options(&mut e, &ici).unwrap();
    let d = ipv4::options_echo(&e[ipv4::ENTETE..], &o, [10, 0, 0, 1], &unicast).unwrap();
    assert_eq!((d.longueur, d.places.route_source), (0, 0));
}

/// Les options qu'un programme donne à ses envois (`options_a_envoyer`),
/// relues par `getsockopt` (défaites : `defaire`), puis complétées au
/// départ (`construire_options`, de 127.0.0.1 à 01:22:51.920, 0x04c3cc10),
/// comme Linux 6.18 (soldes, sondes-sol-ip/cmsg.txt ; ce qui en arrive est
/// le premier cas de chaque ligne d'`echo_des_options`).
#[test]
fn options_a_envoyer_comme_linux() {
    let hex = |h: &str| -> Vec<u8> { (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap()).collect() };
    let unicast = |a: [u8; 4]| !(a[0] == 127 || a[0] == 0 || a == ipv4::DIFFUSION || ipv4::multidiffusion(a));
    let source = [127, 0, 0, 1];
    // Donné, relu, puis tel qu'il part vers 127.0.0.3.
    let cas = |donne: &str, racine: bool| -> Result<(Vec<u8>, Vec<u8>), ()> {
        let o = ipv4::options_a_envoyer(&hex(donne), racine, &unicast)?;
        let mut relu = o;
        relu.defaire();
        let mut e = vec![0u8; ipv4::ENTETE + o.longueur as usize];
        ipv4::construire_options(&mut e, &o, [127, 0, 0, 3], source, 0x04c3_cc10);
        Ok((relu.octets().to_vec(), e[ipv4::ENTETE..].to_vec()))
    };
    let ok = |donne: &str, relu: &str, part: &str| {
        assert_eq!(cas(donne, false), Ok((hex(relu), hex(part))), "{donne}");
    };
    ok("070b040000000000000000", "070b04000000000000000000", "070b087f0000010000000000");
    ok("440c0501000000000000000001", "440c0501000000000000000001000000", "440c0d017f00000104c3cc1001000000");
    // Ce qui suit la fin (FIN) devient FIN.
    ok("440c050100000000000000000001", "440c0501000000000000000000000000", "440c0d017f00000104c3cc1000000000");
    ok("440c05010000000000000000" , "440c05010000000000000000", "440c0d017f00000104c3cc10");
    ok("440c05037f00000100000000", "440c05037f00000100000000", "440c0d037f00000104c3cc10");
    // Une adresse donnée d'avance qui est quelqu'un d'autre : rien à y mettre.
    ok("440c05030a00000100000000", "440c05030a00000100000000", "440c05030a00000100000000");
    // La route source : la première étape sort, la destination va au bout.
    let o = ipv4::options_a_envoyer(&hex("830b047f0000017f000002"), false, &unicast).unwrap();
    assert_eq!((o.premier_saut, o.places.route_source, o.places.stricte), ([127, 0, 0, 1], 20, false));
    ok("830b047f0000017f000002", "830b047f0000017f00000200", "830b047f0000027f00000300");
    ok("8307047f000001", "8307047f00000100", "8307047f00000300");
    // Les refus (EINVAL) : deux horodatages ; une route source dont la
    // longueur n'est pas faite de mots, au pointeur qui n'est pas 4, sans
    // étape ; sans CAP_NET_RAW : la sécurité, un drapeau d'horodatage
    // inconnu (avec de la place), une option inconnue ; CIPSO, toujours ;
    // plus de 40 octets.
    for (donne, racine) in [("440c0501000000000000000044080501", false), ("8308040102030405", false), ("83070801020304", false),
                            ("830304", false), ("82040000", false), ("440c0502000000000000000000", false), ("fe020000", false),
                            ("86080000000000000000", true), (&"01".repeat(41), true)] {
        assert_eq!(cas(donne, racine), Err(()), "{donne}");
    }
    // Avec CAP_NET_RAW, la sécurité, le drapeau inconnu et l'option inconnue
    // passent, telles quelles.
    assert_eq!(cas("82040000", true), Ok((hex("82040000"), hex("82040000"))));
    assert_eq!(cas("440c0502000000000000000000", true).map(|(r, _)| r), Ok(hex("440c0502000000000000000000000000")));
    // Sans place, l'horodatage passe, sans compter de débordement ; l'alerte,
    // une route notée pleine aussi.
    ok("44040502", "44040502", "44040502");
    ok("94040000", "94040000", "94040000");
    ok("07070800000000", "0707080000000000", "0707080000000000");
    ok("", "", "");
    ok(&"01".repeat(40), &"01".repeat(40), &"01".repeat(40));
    // Ce qu'un fragment après le premier en garde (`ip_options_fragment`) :
    // la route notée et l'horodatage deviennent des bourrages, la route
    // source reste.
    let mut f = hex("070b087f0000010000000001830704" );
    f.extend_from_slice(&hex("7f00000300"));
    ipv4::options_de_fragment(&mut f);
    assert_eq!(f, hex("0101010101010101010101018307047f00000300"));
}

/// La somme que garde Linux (`csum_partial` d'x86-64), rendue par
/// IP_CHECKSUM : mesurée sur la réponse d'un ping (sondes-sol-ip/erreurs.txt).
#[test]
fn somme_de_linux() {
    assert_eq!(somme_linux(&[0x00, 0x00, 0x19, 0xca, 0xe6, 0x2e, 0x00, 0x07]).to_le_bytes(), [0xe6, 0x2e, 0x19, 0xd1]);
    assert_eq!((somme_linux(&[]), somme_linux(&[0; 7]), somme_linux(&[0xff; 8])), (0, 0, 0xFFFF_FFFF));
    // Une fin de moins de 4 octets : complétée de zéros, à sa place.
    assert_eq!(somme_linux(&[1, 2, 3, 4, 5, 6]), 0x0403_0201 + 0x0605);
    // Pliée, la même somme de contrôle que celle de l'Internet.
    let o: Vec<u8> = (0..77u8).map(|i| i.wrapping_mul(37)).collect();
    let s = somme_linux(&o);
    let plie = |mut s: u32| {
        while s > 0xFFFF {
            s = (s & 0xFFFF) + (s >> 16);
        }
        s as u16
    };
    assert_eq!(plie(s).swap_bytes(), !plier(somme(&o, 0)));
    // `csum_sub` : la somme des 8 premiers octets ôtée.
    assert_eq!(somme_linux_moins(s, somme_linux(&o[..8])), somme_linux(&[&[0; 8][..], &o[8..]].concat()));
    assert_eq!(somme_linux_moins(5, 5), 0xFFFF_FFFF);
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

/// Un message d'erreur ICMP comme ceux de la sonde qui a mesuré Linux 6.18
/// (une socket brute qui se les envoie par lo, pour une socket UDP
/// connectée avec IP_RECVERR et IP_RECVERR_RFC4884) : le genre, l'octet 5
/// (la longueur de la copie en mots de 32 bits), la copie (un en-tête IPv4
/// de 20 octets, un en-tête UDP, puis `charge` octets), puis les
/// extensions, en hexadécimal, avec « xxxx » à la place de leur somme,
/// calculée (fausse si `faussee`).
fn erreur_rfc4884(genre: u8, longueur: u8, charge: usize, extensions: &str, faussee: bool) -> Vec<u8> {
    let mut m = vec![genre, if genre == icmp::INJOIGNABLE { icmp::PORT } else { 0 }, 0, 0, 0, longueur, 0, 0];
    let total = (28 + charge) as u16;
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip[8] = 64;
    ip[9] = ipv4::UDP;
    ip[12..16].copy_from_slice(&[127, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[127, 0, 0, 1]);
    m.extend_from_slice(&ip);
    m.extend_from_slice(&[0x9c, 0x40, 0, 9]);
    m.extend_from_slice(&(8 + charge as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0]);
    m.extend(std::iter::repeat_n(b'a', charge));
    let debut = m.len();
    let mut hexa = extensions.as_bytes().chunks(2);
    let a_calculer = extensions.get(4..8) == Some("xxxx");
    for (i, c) in (&mut hexa).enumerate() {
        let c = std::str::from_utf8(c).unwrap();
        m.push(if a_calculer && (i == 2 || i == 3) { 0 } else { u8::from_str_radix(c, 16).unwrap() });
    }
    if a_calculer {
        let s = plier(somme(&m[debut..], 0)) ^ if faussee { 0x5555 } else { 0 };
        m[debut + 2..debut + 4].copy_from_slice(&s.to_be_bytes());
    }
    m
}

#[test]
fn icmp_rfc4884() {
    // Les quinze cas mesurés (sauf le dernier, sans l'option : rien à
    // calculer) : ce que lit le programme, et le `ee_data` de l'erreur.
    let objet = "2000xxxx00080101deadbeef";
    let cas: [(&str, u8, u8, usize, &str, bool, usize, u32); 14] = [
        ("valide", 3, 32, 100, objet, false, 112, 0x64),
        ("somme fausse", 3, 32, 100, objet, true, 112, 0x10064),
        ("copie de 124 octets", 3, 31, 96, objet, false, 108, 0),
        ("version 1", 3, 32, 100, "1000123400080101", false, 108, 0x64),
        ("objet de 2 octets", 3, 32, 100, "2000000000020101", false, 108, 0x10064),
        ("objet trop long", 3, 32, 100, "200000000010010100000000", false, 112, 0x10064),
        ("sans extension", 3, 32, 100, "", false, 100, 0),
        ("somme nulle", 3, 32, 100, "2000000000080101deadbeef", false, 112, 0x64),
        ("temps depasse", 11, 32, 100, objet, false, 112, 0x64),
        ("probleme de parametre", 12, 32, 100, objet, false, 112, 0x64),
        ("copie au-dela de la fin", 3, 40, 100, objet, false, 112, 0),
        ("trois octets apres la copie", 3, 32, 100, "200000", false, 103, 0),
        ("l'en-tete des extensions seul", 3, 32, 100, "20000000", false, 104, 0x64),
        ("un octet d'objet", 3, 32, 100, "2000000000", false, 105, 0x10064),
    ];
    for (nom, genre, longueur, charge, extensions, faussee, lu, ee_data) in cas {
        let m = erreur_rfc4884(genre, longueur, charge, extensions, faussee);
        assert_eq!(m.len() - icmp::ENTETE - 28, lu, "{nom} : ce que lit le programme");
        let e = icmp::extensions_rfc4884(&m, 28).map_or(0, |e| e.ee_data());
        assert_eq!(e, ee_data, "{nom}");
    }
    // Un écho (ping) : le programme lit l'en-tête ICMP d'origine, seul
    // l'en-tête IPv4 est ôté (MESURÉ aussi : `rfc4884-ping`).
    let m = erreur_rfc4884(3, 32, 100, objet, false);
    assert_eq!(icmp::extensions_rfc4884(&m, 20).map(|e| e.ee_data()), Some(108));
    // Les autres genres n'en ont pas, et un message coupé n'en a pas.
    let mut m = erreur_rfc4884(3, 32, 100, objet, false);
    m[0] = icmp::REDIRECTION;
    assert_eq!(icmp::extensions_rfc4884(&m, 28), None);
    assert_eq!(icmp::extensions_rfc4884(&m[..5], 28), None);
    assert_eq!(icmp::extensions_rfc4884(&[], 28), None);
    // Une copie plus courte que les en-têtes ôtés (des options IPv4 de
    // 40 octets, et l'octet 5 au minimum, 32) : rien.
    let m = erreur_rfc4884(3, 32, 100, objet, false);
    assert_eq!(icmp::extensions_rfc4884(&m, 132), None);
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
        // L'en-tête cité : tout entier présent ; le même que celui de `lire`
        // quand `lire` l'accepte.
        let seul = ipv4::lire_cite(&ip);
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
        options: tcp::Options { mss: Some(1460), echelle: Some(7), horodatage: Some((0x0102_0304, 0x0506_0708)), sack_permis: true, ..tcp::Options::default() },
    };
    let o = segment(&syn, &[], s, d, true);
    assert_eq!(o.len(), 40);
    // Les options comme Linux les aligne : MSS, SACK permis et les horodatages
    // dans le même mot, NOP et l'échelle.
    assert_eq!(&o[20..], &[2, 4, 0x05, 0xb4, 4, 2, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 1, 3, 3, 7]);
    assert_eq!(tcp::lire(&o, s, d, true), Ok((syn, &[][..])));
    // SACK permis sans horodatages : deux NOP devant.
    let sans = tcp::Tcp { options: tcp::Options { mss: Some(1460), sack_permis: true, ..tcp::Options::default() }, ..syn };
    let o = segment(&sans, &[], s, d, true);
    assert_eq!(&o[20..], &[2, 4, 0x05, 0xb4, 1, 1, 4, 2]);
    assert_eq!(tcp::lire(&o, s, d, true), Ok((sans, &[][..])));
    // Des blocs, après les horodatages.
    let mut b = tcp::Options { horodatage: Some((1, 2)), nb_blocs: 2, ..tcp::Options::default() };
    b.blocs[0] = (0x10, 0x20);
    b.blocs[1] = (0x30, 0x40);
    let blocs = tcp::Tcp { drapeaux: tcp::ACK, options: b, ..syn };
    let o = segment(&blocs, &[], s, d, true);
    assert_eq!(o.len(), 20 + 12 + 4 + 16);
    assert_eq!(&o[32..36], &[1, 1, 5, 18]);
    assert_eq!(tcp::lire(&o, s, d, true), Ok((blocs, &[][..])));
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
    assert_eq!(avec(tcp::SYN, &[2, 4, 0, 200, 1, 3, 3, 9]), tcp::Options { mss: Some(200), echelle: Some(9), ..tcp::Options::default() });
    assert_eq!(avec(tcp::ACK, &[2, 4, 0, 200, 1, 3, 3, 9]), tcp::Options::default());
    // Une échelle au-delà de 14 : 14.
    assert_eq!(avec(tcp::SYN, &[1, 3, 3, 20]).echelle, Some(14));
    // SACK permis (4, 2), dans un SYN seulement. Les horodatages (8, longueur
    // 10) : lus, dans tout segment ; une autre longueur : ignorés.
    let o = avec(tcp::SYN, &[4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 2, 4, 5, 0]);
    assert_eq!((o.mss, o.horodatage, o.sack_permis), (Some(0x500), Some((1, 2)), true));
    assert!(!avec(tcp::ACK, &[4, 2, 1, 1]).sack_permis);
    // Un bloc SACK : une longueur de 10, 18, 26 ou 34 ; une autre : ignoré.
    let o = avec(tcp::ACK, &[1, 1, 5, 10, 0, 0, 0, 3, 0, 0, 0, 4]);
    assert_eq!((o.nb_blocs, o.blocs[0]), (1, (3, 4)));
    assert_eq!(avec(tcp::ACK, &[1, 1, 5, 9, 0, 0, 0, 3, 0, 0, 0, 4]).nb_blocs, 0);
    assert_eq!(avec(tcp::ACK, &[1, 1, 8, 10, 0, 0, 0, 7, 0, 0, 0, 8]).horodatage, Some((7, 8)));
    assert_eq!(avec(tcp::ACK, &[8, 9, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0]).horodatage, None);
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
    let t = tcp::Tcp { source: 9, destination: 80, drapeaux: tcp::SYN, options: tcp::Options { mss: Some(1460), echelle: Some(7), horodatage: Some((0x0102_0304, 0x0506_0708)), ..tcp::Options::default() }, ..Default::default() };
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
