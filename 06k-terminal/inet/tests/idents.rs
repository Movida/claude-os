//! La table des sockets de ping : les identifiants donnés à la suite, le
//! partage avec SO_REUSEADDR, le choix de la socket d'une réponse.

use inet::idents::{Refus, Table};

const LO: [u8; 4] = [127, 0, 0, 1];
const ICI: [u8; 4] = [10, 0, 2, 15];
const TOUT: [u8; 4] = [0; 4];

#[test]
fn identifiants_a_la_suite() {
    let mut t: Table<u32> = Table::new().unwrap();
    // 0 demande le suivant du dernier donné : 1, 2, 3...
    assert_eq!(t.lier(1, 0, TOUT, false, 0, 1), Ok(1));
    assert_eq!(t.lier(2, 0, TOUT, false, 0, 2), Ok(2));
    // Un identifiant choisi, puis 0 : le suivant du dernier donné pour 0,
    // en sautant ceux qui sont pris.
    assert_eq!(t.lier(3, 3, TOUT, false, 0, 3), Ok(3));
    assert_eq!(t.lier(4, 0, TOUT, false, 0, 4), Ok(4));
    t.retirer(1);
    assert_eq!(t.lier(5, 0, TOUT, false, 0, 5), Ok(5), "pas de retour en arrière");
    // Au bout, on repart de 1 (0 n'est jamais donné).
    let mut t: Table<u32> = Table::new().unwrap();
    assert_eq!(t.lier(1, 65535, TOUT, false, 0, 1), Ok(65535));
    assert_eq!(t.lier(2, 0, TOUT, false, 0, 2), Ok(1));
    // Et quand le dernier donné est 65 535 : le suivant serait 0, sauté.
    let mut t: Table<u32> = Table::new().unwrap();
    for k in 1..=65535u64 {
        assert_eq!(t.lier(k, 0, TOUT, false, 0, 0), Ok(k as u16));
        t.retirer(k);
    }
    assert_eq!(t.lier(1, 0, TOUT, false, 0, 1), Ok(1), "0 sauté au bout");
}

#[test]
fn partage() {
    let mut t: Table<u32> = Table::new().unwrap();
    t.lier(1, 7, LO, false, 0, 1).unwrap();
    // Pris, quelle que soit l'adresse (pas comme UDP).
    assert_eq!(t.lier(2, 7, ICI, false, 0, 2), Err(Refus::Pris));
    // SO_REUSEADDR des deux côtés, lu au moment du conflit.
    assert_eq!(t.lier(2, 7, ICI, true, 0, 2), Err(Refus::Pris));
    t.reutiliser(1, true);
    assert_eq!(t.lier(2, 7, ICI, true, 0, 2), Ok(7));
}

#[test]
fn qui_recoit() {
    let mut t: Table<u32> = Table::new().unwrap();
    t.lier(1, 9, TOUT, true, 0, 1).unwrap();
    t.lier(2, 9, LO, true, 0, 2).unwrap();
    // La plus récente d'abord, si son adresse convient.
    assert_eq!(t.trouver(9, LO, 1), Some(2));
    assert_eq!(t.trouver(9, ICI, 1), Some(1));
    assert_eq!(t.trouver(8, LO, 1), None);
    t.changer(2, ICI);
    assert_eq!(t.trouver(9, LO, 1), Some(1));
    // Liée à une interface (SO_BINDTODEVICE) : seulement les réponses
    // arrivées par elle (`ping_lookup`, `inet_iif`) ; la liaison ne gêne
    // pas le partage d'un identifiant.
    let mut t: Table<u32> = Table::new().unwrap();
    t.lier(1, 9, TOUT, true, 2, 1).unwrap();
    assert_eq!(t.trouver(9, LO, 1), None, "liee a eth0, arrivee par lo");
    assert_eq!(t.trouver(9, ICI, 2), Some(1));
    assert_eq!(t.lier(2, 9, TOUT, false, 1, 2), Err(Refus::Pris), "le partage ignore la liaison");
    t.lier(2, 9, TOUT, true, 1, 2).unwrap();
    assert_eq!(t.trouver(9, LO, 1), Some(2));
    assert_eq!(t.trouver(9, ICI, 2), Some(1), "la plus recente sautee : liee a lo");
    t.changer_interface(1, 0);
    t.changer_interface(2, 0);
    assert_eq!(t.trouver(9, ICI, 2), Some(2));
    // Pleine : 1024 sockets.
    let mut t: Table<u32> = Table::new().unwrap();
    for n in 0..1024u64 {
        t.lier(n, 0, TOUT, false, 0, 0).unwrap();
    }
    assert_eq!(t.lier(1024, 0, TOUT, false, 0, 0), Err(Refus::Plein));
}
