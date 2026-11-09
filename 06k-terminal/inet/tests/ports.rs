//! La table des ports d'UDP : les règles de Linux une à une (le partage
//! d'un port, le choix de la socket qui reçoit, la diffusion), puis les
//! ports éphémères : tous dans la plage, tous différents tant qu'il en
//! reste, et dans un ordre qui ne se devine pas.

use inet::ports::{Lien, Refus, Table, EPHEMERE_MAX, EPHEMERE_MIN};

const LO: [u8; 4] = [127, 0, 0, 1];
const ICI: [u8; 4] = [10, 0, 2, 15];
const TOUT: [u8; 4] = [0; 4];

fn lien(adresse: [u8; 4], port: u16) -> Lien {
    Lien { adresse, port, distante: TOUT, port_distant: 0, reuseaddr: false, reuseport: false, uid: 1000 }
}

#[test]
fn partage_d_un_port() {
    let mut t: Table<u32> = Table::new().unwrap();
    assert_eq!(t.lier(1, lien(TOUT, 5000), 1, 0), Ok(5000));
    // 0.0.0.0 recouvre tout : refusé à 127.0.0.1 comme à 0.0.0.0.
    assert_eq!(t.lier(2, lien(LO, 5000), 2, 0), Err(Refus::Pris));
    assert_eq!(t.lier(2, lien(TOUT, 5000), 2, 0), Err(Refus::Pris));
    // Deux adresses précises différentes : permis.
    assert_eq!(t.lier(3, lien(LO, 6000), 3, 0), Ok(6000));
    assert_eq!(t.lier(4, lien(ICI, 6000), 4, 0), Ok(6000));
    // SO_REUSEADDR des deux côtés ; d'un seul : refusé.
    let r = Lien { reuseaddr: true, ..lien(TOUT, 7000) };
    assert_eq!(t.lier(5, r, 5, 0), Ok(7000));
    assert_eq!(t.lier(6, lien(TOUT, 7000), 6, 0), Err(Refus::Pris));
    assert_eq!(t.lier(6, r, 6, 0), Ok(7000));
    // SO_REUSEPORT : du même utilisateur seulement.
    let p = Lien { reuseport: true, ..lien(TOUT, 8000) };
    assert_eq!(t.lier(7, p, 7, 0), Ok(8000));
    assert_eq!(t.lier(8, Lien { uid: 0, ..p }, 8, 0), Err(Refus::Pris));
    assert_eq!(t.lier(8, p, 8, 0), Ok(8000));
    // SO_REUSEADDR posé après le bind : compte pour les suivants.
    assert_eq!(t.lier(10, lien(TOUT, 9000), 10, 0), Ok(9000));
    assert_eq!(t.lier(11, r, 11, 0), Ok(7000), "le port 7000 partagé, SO_REUSEADDR des deux côtés");
    assert_eq!(t.lier(12, Lien { port: 9000, ..r }, 12, 0), Err(Refus::Pris));
    t.reutiliser(10, true, false);
    assert_eq!(t.lier(12, Lien { port: 9000, ..r }, 12, 0), Ok(9000));
    // Retirée, la socket rend son port.
    t.retirer(1);
    assert_eq!(t.lier(9, lien(TOUT, 5000), 9, 0), Ok(5000));
}

#[test]
fn qui_recoit() {
    // (SO_REUSEADDR : sinon 127.0.0.1:53 serait refusé, 0.0.0.0:53 le
    // recouvrant.)
    let mut t: Table<u32> = Table::new().unwrap();
    t.lier(1, Lien { reuseaddr: true, ..lien(TOUT, 53) }, 1, 0).unwrap();
    t.lier(2, Lien { reuseaddr: true, ..lien(LO, 53) }, 2, 0).unwrap();
    // Liée à l'adresse de destination d'abord, puis à 0.0.0.0.
    assert_eq!(t.trouver(ICI, 4000, LO, 53), Some(2));
    assert_eq!(t.trouver(LO, 4000, ICI, 53), Some(1));
    assert_eq!(t.trouver(LO, 4000, LO, 54), None);
    // Une socket connectée à l'émetteur l'emporte sur une qui ne l'est pas ;
    // connectée ailleurs, elle n'est pas candidate.
    let mut t: Table<u32> = Table::new().unwrap();
    t.lier(1, lien(TOUT, 9000), 1, 0).unwrap();
    t.lier(2, Lien { reuseaddr: true, ..lien(TOUT, 9100) }, 2, 0).unwrap();
    t.lier(3, Lien { reuseaddr: true, ..lien(TOUT, 9100) }, 3, 0).unwrap();
    t.changer(3, LO, 5555, TOUT);
    assert_eq!(t.trouver(LO, 5555, LO, 9100), Some(3));
    assert_eq!(t.trouver(LO, 5556, LO, 9100), Some(2));
    t.changer(2, [10, 9, 9, 9], 1, TOUT);
    assert_eq!(t.trouver(LO, 5556, LO, 9100), None);
    // Connectée à une autre adresse, même du bon port : pas candidate non
    // plus.
    t.changer(2, [10, 9, 9, 9], 5556, TOUT);
    assert_eq!(t.trouver(LO, 5556, LO, 9100), None);
    assert_eq!(t.lien(3).map(|l| (l.distante, l.port_distant)), Some((LO, 5555)));
}

#[test]
fn diffusion() {
    let mut t: Table<u32> = Table::new().unwrap();
    let r = Lien { reuseaddr: true, ..lien(TOUT, 68) };
    t.lier(1, r, 1, 0).unwrap();
    t.lier(2, r, 2, 0).unwrap();
    t.lier(3, Lien { adresse: ICI, ..r }, 3, 0).unwrap();
    t.lier(4, lien(TOUT, 69), 4, 0).unwrap();
    let mut vues = Vec::new();
    t.pour_chaque_diffusion([10, 0, 2, 2], 67, [255; 4], 68, |&n| vues.push(n));
    assert_eq!(vues, [1, 2], "la socket liée à 10.0.2.15 n'est pas pour 255.255.255.255");
}

#[test]
fn ports_ephemeres() {
    let mut t: Table<u32> = Table::new().unwrap();
    let plage = EPHEMERE_MIN..=EPHEMERE_MAX;
    // Mille ports demandés : tous dans la plage, tous différents.
    let mut vus = std::collections::HashSet::new();
    let mut hasard = 12345u32;
    for n in 0..1000u64 {
        hasard = hasard.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let p = t.lier(n, lien(TOUT, 0), n as u32, hasard).unwrap();
        assert!(plage.contains(&p) && vus.insert(p), "port {p}");
    }
    // Le même hasard donne le même premier port ; s'il est pris, le suivant
    // essayé est dans sa classe (modulo 256), un pas plus loin (un multiple
    // impair de 256 tiré du hasard) : pas « le suivant libre ».
    let mut t: Table<u32> = Table::new().unwrap();
    let a = t.lier(1, lien(TOUT, 0), 1, 0x8000_0000).unwrap();
    t.retirer(1);
    let b = t.lier(2, lien(TOUT, 0), 2, 0x8000_0000).unwrap();
    assert_eq!(a, b, "le même premier port");
    let c = t.lier(3, lien(TOUT, 0), 3, 0x8000_0000).unwrap();
    assert!(c != a && c % 256 == a % 256, "{a} puis {c}");
    // La table pleine : 1024 sockets, puis ENOBUFS.
    let mut t: Table<u32> = Table::new().unwrap();
    for n in 0..1024u64 {
        t.lier(n, lien(TOUT, 0), 0, (n as u32).wrapping_mul(2_654_435_761)).unwrap();
    }
    assert_eq!(t.lier(1024, lien(TOUT, 0), 0, 1), Err(Refus::Plein));
}
