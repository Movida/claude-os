//! Le client DHCP contre l'échange capturé avec slirp
//! (../formats/tests/reseau/, tests/reseau/capturer.sh) : il doit écrire les
//! mêmes messages que notre noyau, prendre l'offre, puis l'accusé ; puis,
//! à l'horloge simulée, les délais de Linux et l'abandon ; puis les
//! réponses qui ne sont pas pour lui.

use formats::reseau::{dhcp as format, ethernet, ipv4, udp};
use inet::dhcp::{Client, Evenement, Refus, DELAI_BASE, HASARD_MAX};
use std::path::PathBuf;

const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const S: u64 = 1_000_000_000;

/// La charge UDP (le message DHCP) d'une trame capturée.
fn message(nom: &str) -> Vec<u8> {
    let chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../formats/tests/reseau").join(format!("{nom}.dat"));
    let t = std::fs::read(&chemin).unwrap();
    let (_, reste) = ethernet::lire(&t).unwrap();
    let (h, charge) = ipv4::lire(reste).unwrap();
    udp::lire(charge, h.source, h.destination).unwrap().1.to_vec()
}

fn xid_capture() -> u32 {
    format::lire(&message("dhcp-discover")).unwrap().xid
}

fn ecrit(c: &Client, maintenant: u64) -> Vec<u8> {
    let mut o = [0u8; format::TAILLE];
    c.message(maintenant, &mut o);
    o.to_vec()
}

#[test]
fn echange_de_slirp() {
    let t0 = 1_000 * S;
    let mut c = Client::new(MAC, xid_capture(), 0, t0);
    // Le premier message : le DISCOVER capturé, octet pour octet.
    assert_eq!(ecrit(&c, t0), message("dhcp-discover"));
    assert_eq!(c.echeance(), Some(t0 + DELAI_BASE));
    // L'offre : le REQUEST part aussitôt, et c'est celui capturé.
    assert_eq!(c.recu(&message("dhcp-offer"), t0 + 1_000_000), Evenement::Envoyer);
    assert_eq!(ecrit(&c, t0 + 1_000_000), message("dhcp-request"));
    // Une seconde offre est ignorée.
    assert_eq!(c.recu(&message("dhcp-offer"), t0 + 2_000_000), Evenement::Rien);
    let Evenement::Configure(b) = c.recu(&message("dhcp-ack"), t0 + 3_000_000) else { panic!("pas configuré") };
    assert_eq!((b.adresse, b.prefixe, b.passerelle, b.serveur), ([10, 0, 2, 15], 24, Some([10, 0, 2, 2]), [10, 0, 2, 2]));
    assert_eq!(b.dns, [Some([10, 0, 2, 3]), None, None]);
    assert_eq!((b.duree, b.mtu, b.domaine()), (Some(86_400), None, None));
    assert_eq!(c.echeance(), None, "fini");
    assert_eq!(c.recu(&message("dhcp-ack"), t0 + 4_000_000), Evenement::Rien);
}

#[test]
fn delais_et_abandon() {
    // Sans hasard : 2 s, puis 3,5 s, puis 6,125 s, puis l'abandon.
    let mut c = Client::new(MAC, 1, 0, 0);
    assert_eq!(c.temps(2 * S - 1), Evenement::Rien);
    assert_eq!(c.temps(2 * S), Evenement::Envoyer);
    assert_eq!(c.echeance(), Some(2 * S + 3_500_000_000));
    assert_eq!(c.temps(5_500_000_000), Evenement::Envoyer);
    assert_eq!(c.echeance(), Some(5_500_000_000 + 6_125_000_000));
    assert_eq!(c.temps(11_625_000_000), Evenement::Abandon);
    assert_eq!((c.echeance(), c.temps(100 * S)), (None, Evenement::Rien));
    // Le plus de hasard : 3 s, 5,25 s, 9,1875 s : 17,4 s en tout (le
    // hasard est tiré une fois, comme dans ipconfig.c).
    let mut c = Client::new(MAC, 1, HASARD_MAX - 1, 0);
    let mut t = c.echeance().unwrap();
    while c.temps(t) == Evenement::Envoyer {
        t = c.echeance().unwrap();
    }
    assert!((17_400_000_000..17_450_000_000).contains(&t), "{t}");
    // Les secondes écrites dans le message : depuis le début de l'échange.
    let c = Client::new(MAC, 1, 0, 10 * S);
    assert_eq!(&ecrit(&c, 13 * S + 999)[8..10], &[0, 3]);
}

#[test]
fn reponses_qui_ne_sont_pas_pour_lui() {
    let offre = message("dhcp-offer");
    // Un autre identifiant de transaction, une autre adresse matérielle.
    let mut c = Client::new(MAC, xid_capture() ^ 1, 0, 0);
    assert_eq!(c.recu(&offre, 0), Evenement::Rien);
    let mut c = Client::new([2, 0, 0, 0, 0, 1], xid_capture(), 0, 0);
    assert_eq!(c.recu(&offre, 0), Evenement::Rien);
    // Notre propre DISCOVER (une requête, pas une réponse), un ACK sans
    // offre prise, des octets quelconques.
    let mut c = Client::new(MAC, xid_capture(), 0, 0);
    assert_eq!(c.recu(&message("dhcp-discover"), 0), Evenement::Rien);
    assert_eq!(c.recu(&message("dhcp-ack"), 0), Evenement::Rien);
    assert_eq!(c.recu(&[1, 2, 3], 0), Evenement::Rien);
    // Une offre sans serveur (option 54) : ignorée.
    let mut sans = offre.clone();
    let i = (240..sans.len()).find(|&i| sans[i] == format::SERVEUR).unwrap();
    sans[i] = 200;
    assert_eq!(c.recu(&sans, 0), Evenement::Rien);
    // Un NAK : l'offre est oubliée, le prochain envoi est un DISCOVER.
    assert_eq!(c.recu(&offre, 0), Evenement::Envoyer);
    let mut nak = message("dhcp-ack");
    let i = (240..nak.len()).find(|&i| nak[i] == format::SORTE).unwrap();
    nak[i + 2] = format::NAK;
    assert_eq!(c.recu(&nak, 0), Evenement::Rien);
    assert_eq!(ecrit(&c, 0), message("dhcp-discover"));
}

/// La position de l'option `code` du message `m` (son octet de code),
/// en suivant les options une à une.
fn option(m: &[u8], code: u8) -> Option<usize> {
    let mut i = 240;
    while i < m.len() && m[i] != 255 {
        if m[i] == code {
            return Some(i);
        }
        i += if m[i] == 0 { 1 } else { 2 + m[i + 1] as usize };
    }
    None
}

/// Le message `m` dont l'option `code` est renommée `nouveau` (une option
/// inconnue : elle n'est plus lue, sans rien décaler).
fn renommer(m: &[u8], code: u8, nouveau: u8) -> Vec<u8> {
    let mut o = m.to_vec();
    let i = option(&o, code).expect("l'option");
    o[i] = nouveau;
    o
}

/// L'échange de slirp, avec l'offre et l'accusé changés par `changer`.
fn bail_de(changer: impl Fn(&mut Vec<u8>)) -> Evenement {
    let mut c = Client::new(MAC, xid_capture(), 0, 0);
    let mut offre = message("dhcp-offer");
    let mut ack = message("dhcp-ack");
    changer(&mut offre);
    changer(&mut ack);
    assert_eq!(c.recu(&offre, 1), Evenement::Envoyer);
    c.recu(&ack, 2)
}

#[test]
fn le_bail_comme_ipconfig() {
    // slirp donne son adresse pour siaddr : le « bootserver ».
    let Evenement::Configure(b) = bail_de(|_| {}) else { panic!() };
    assert_eq!(b.amorce, [10, 0, 2, 2]);
    // Sans DNS, le serveur de l'amorçage en tient lieu.
    let Evenement::Configure(b) = bail_de(|m| *m = renommer(m, format::DNS, 250)) else { panic!() };
    assert_eq!(b.dns, [Some([10, 0, 2, 2]), None, None]);
    // Sans masque : la classe de l'adresse (C : /24).
    let Evenement::Configure(b) = bail_de(|m| {
        *m = renommer(&renommer(m, format::MASQUE, 250), format::PASSERELLES, 251);
        m[16..20].copy_from_slice(&[192, 168, 1, 15]);
    }) else { panic!() };
    assert_eq!((b.adresse, b.prefixe, b.passerelle), ([192, 168, 1, 15], 24, None));
    // Une adresse de multidiffusion sans masque : pas de classe, refusée.
    assert_eq!(bail_de(|m| {
        *m = renommer(m, format::MASQUE, 250);
        m[16..20].copy_from_slice(&[230, 1, 2, 3]);
    }), Evenement::Refuse(Refus::Masque));
    // Une passerelle hors du réseau reçu : refusée.
    assert_eq!(bail_de(|m| {
        let i = option(m, format::PASSERELLES).unwrap();
        m[i + 2..i + 6].copy_from_slice(&[10, 0, 3, 2]);
    }), Evenement::Refuse(Refus::Passerelle));
}
