//! La table des ports de TCP : les règles de `inet_bind_conflict`, les
//! ports éphémères de `bind` (impairs) et de `connect` (pairs), un
//! quadruplet jamais pris deux fois, la recherche d'un segment.

use inet::ports_tcp::{Destinataire, Lien, Refus, Sorte, Table, EPHEMERE_MAX, EPHEMERE_MIN};

const LO: [u8; 4] = [127, 0, 0, 1];
const TOUT: [u8; 4] = [0; 4];

fn lien(adresse: [u8; 4], port: u16) -> Lien {
    Lien { sorte: Sorte::Liee, adresse, port, distante: TOUT, port_distant: 0, reuseaddr: false, reuseport: false, uid: 1000, par_connect: false }
}

fn table() -> Table<u32> {
    let mut x = 7u32;
    Table::new(64, || {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        x
    })
    .unwrap()
}

#[test]
fn bind_et_ses_conflits() {
    let mut t = table();
    assert_eq!(t.lier(1, lien(LO, 8080), 1, 0), Ok(8080));
    assert_eq!(t.lier(2, lien(LO, 8080), 2, 0), Err(Refus::Pris));
    assert_eq!(t.lier(2, lien(TOUT, 8080), 2, 0), Err(Refus::Pris));
    assert_eq!(t.lier(2, lien([10, 0, 2, 15], 8080), 2, 0), Ok(8080));
    // SO_REUSEADDR des deux côtés : permis, tant que l'autre n'écoute pas.
    let mut t = table();
    let r = Lien { reuseaddr: true, ..lien(TOUT, 9000) };
    assert_eq!(t.lier(1, r, 1, 0), Ok(9000));
    assert_eq!(t.lier(2, r, 2, 0), Ok(9000));
    // Une seule des deux peut écouter.
    assert_eq!(t.ecouter(1), Ok(()));
    assert_eq!(t.ecouter(2), Err(Refus::Pris));
    assert_eq!(t.lier(3, r, 3, 0), Err(Refus::Pris));
    // SO_REUSEPORT du même utilisateur : permis, même pour écouter.
    let mut t = table();
    let p = Lien { reuseport: true, ..lien(TOUT, 9001) };
    assert_eq!(t.lier(1, p, 1, 0), Ok(9001));
    assert_eq!(t.lier(2, p, 2, 0), Ok(9001));
    assert_eq!(t.ecouter(1), Ok(()));
    assert_eq!(t.ecouter(2), Ok(()));
    assert_eq!(t.lier(3, Lien { uid: 0, ..p }, 3, 0), Err(Refus::Pris));
}

#[test]
fn ephemeres() {
    let mut t = table();
    // bind(0) : impair, dans la plage.
    for n in 1..=10u64 {
        let port = t.lier(n, lien(LO, 0), n as u32, (n * 7919) as u32).unwrap();
        assert!(port % 2 == 1 && (EPHEMERE_MIN..=EPHEMERE_MAX).contains(&port), "{}", port);
    }
    // connect : pair, et deux connexions vers le même pair ont des ports
    // différents.
    let mut t = table();
    let a = t.connecter(1, LO, LO, 80, lien(LO, 0), 1, 0x1234_5678_9abc, 3, |_, _| false).unwrap();
    let b = t.connecter(2, LO, LO, 80, lien(LO, 0), 2, 0x1234_5678_9abc, 5, |_, _| false).unwrap();
    assert!(a % 2 == 0 && b % 2 == 0 && a != b, "{} {}", a, b);
    // Vers un autre pair, le même port local peut resservir (un port de
    // connect se partage, le quadruplet diffère) : au moins, il est pair.
    let c = t.connecter(3, LO, [10, 0, 2, 2], 80, lien(LO, 0), 3, 0x1234_5678_9abc, 7, |_, _| false).unwrap();
    assert!(c % 2 == 0);
}

#[test]
fn connect_saute_les_ports_de_bind() {
    let mut t = table();
    // Tous les ports pairs pris par bind sauf un : connect le trouve.
    let mut n = 100;
    for port in (EPHEMERE_MIN..=EPHEMERE_MAX).step_by(2) {
        if port != 40000 && n < 162 {
            let _ = t.lier(n, lien(LO, port), 0, 0);
            n += 1;
        }
    }
    let p = t.connecter(1, LO, LO, 22, lien(LO, 0), 1, (40000u64 - EPHEMERE_MIN as u64 - 10) << 32, 0, |_, _| false).unwrap();
    assert!(p % 2 == 0);
    assert!(t.lien(1).is_some());
}

#[test]
fn quadruplet_et_temps_attente() {
    let mut t = table();
    assert_eq!(t.lier(1, lien(LO, 5000), 1, 0), Ok(5000));
    assert_eq!(t.connecter(1, LO, LO, 80, lien(LO, 0), 1, 0, 0, |_, _| false), Ok(5000));
    // Une autre socket liée au même port (SO_REUSEADDR) vers le même pair :
    // le quadruplet est pris.
    let r = Lien { reuseaddr: true, ..lien(LO, 5001) };
    assert_eq!(t.lier(2, r, 2, 0), Ok(5001));
    assert_eq!(t.lier(3, r, 3, 0), Ok(5001));
    assert_eq!(t.connecter(2, LO, LO, 80, r, 2, 0, 0, |_, _| false), Ok(5001));
    assert_eq!(t.connecter(3, LO, LO, 80, r, 3, 0, 0, |_, _| false), Err(Refus::Pris));
    // La connexion passe en TIME_WAIT, sous un numéro à elle : le
    // quadruplet reste pris, sans objet, et le numéro de la socket est libre.
    t.temps_attente(2, 20);
    assert_eq!(t.trouver(LO, 80, LO, 5001), Some(Destinataire::TempsAttente(20)));
    assert_eq!(t.connecter(3, LO, LO, 80, r, 3, 0, 0, |_, _| false), Err(Refus::Pris));
    assert_eq!((t.nombre_temps_attente(), t.objet(2), t.lien(2).is_none()), (1, None, true));
    t.retirer(20);
    assert_eq!(t.connecter(3, LO, LO, 80, r, 3, 0, 0, |_, _| false), Ok(5001));
}

#[test]
fn recherche_d_un_segment() {
    let mut t = table();
    t.lier(1, lien(TOUT, 80), 10, 0).unwrap();
    t.ecouter(1).unwrap();
    t.lier(2, lien(LO, 80), 20, 0).unwrap_err();
    assert_eq!(t.trouver([1, 2, 3, 4], 999, LO, 80), Some(Destinataire::Ecoute(10)));
    // Une fille de l'écoute : son quadruplet d'abord.
    t.ajouter_fille(3, Lien { adresse: LO, distante: [1, 2, 3, 4], port_distant: 999, ..lien(LO, 80) }, 30).unwrap();
    assert_eq!(t.trouver([1, 2, 3, 4], 999, LO, 80), Some(Destinataire::Connexion(30)));
    assert_eq!(t.trouver([1, 2, 3, 4], 998, LO, 80), Some(Destinataire::Ecoute(10)));
    t.changer_objet(3, 31);
    assert_eq!(t.trouver([1, 2, 3, 4], 999, LO, 80), Some(Destinataire::Connexion(31)));
    assert_eq!(t.trouver([1, 2, 3, 4], 999, LO, 81), None);
    // Une écoute liée à l'adresse exacte passe avant celle de 0.0.0.0.
    let mut t = table();
    t.lier(1, Lien { reuseport: true, ..lien(TOUT, 80) }, 10, 0).unwrap();
    t.ecouter(1).unwrap();
    t.lier(2, Lien { reuseport: true, ..lien(LO, 80) }, 20, 0).unwrap();
    t.ecouter(2).unwrap();
    assert_eq!(t.trouver([9, 9, 9, 9], 1, LO, 80), Some(Destinataire::Ecoute(20)));
    assert_eq!(t.trouver([9, 9, 9, 9], 1, [10, 0, 2, 15], 80), Some(Destinataire::Ecoute(10)));
}

/// Un `connect` reprend une entrée de TIME_WAIT du même quadruplet, si la
/// règle (`Attente::reprise`) le dit : elle sait si le port vient de `bind`.
#[test]
fn reprise_d_un_time_wait() {
    let mut t = Table::<u32>::new(10, || 1).unwrap();
    // Un port de `connect`.
    let p = t.connecter(1, LO, LO, 80, lien(LO, 0), 1, 0, 0, |_, _| false).unwrap();
    t.temps_attente(1, 100);
    // Refusée, le quadruplet reste pris : ce port-là est sauté.
    let q = t.connecter(2, LO, LO, 80, lien(LO, 0), 2, 0, 0, |n, lie| {
        assert_eq!((n, lie), (100, false));
        false
    }).unwrap();
    assert_ne!(p, q);
    t.retirer(2);
    // Acceptée : le même port, et l'entrée disparaît. (Le décalage ramène le
    // départ du balayage sur ce port : la perturbation a avancé deux fois de 4.)
    let retour = ((EPHEMERE_MAX as u64 - EPHEMERE_MIN as u64 + 1) & !1) - 8;
    let r = t.connecter(3, LO, LO, 80, lien(LO, 0), 3, retour << 32, 0, |n, _| n == 100).unwrap();
    assert_eq!(r, p);
    assert_eq!(t.nombre_temps_attente(), 0);
    // Un port lié par `bind` : refusée, EADDRNOTAVAIL ; acceptée, le port reste.
    let mut t = Table::<u32>::new(10, || 1).unwrap();
    let mut l = lien(LO, 5000);
    l.reuseaddr = true;
    t.lier(1, l, 1, 0).unwrap();
    t.connecter(1, LO, LO, 80, l, 1, 0, 0, |_, _| false).unwrap();
    t.temps_attente(1, 100);
    t.lier(2, l, 2, 0).unwrap();
    assert_eq!(t.connecter(2, LO, LO, 80, l, 2, 0, 0, |n, lie| {
        assert_eq!((n, lie), (100, true));
        false
    }), Err(Refus::Pris));
    assert_eq!(t.connecter(2, LO, LO, 80, l, 2, 0, 0, |_, _| true), Ok(5000));
    assert_eq!(t.nombre_temps_attente(), 0);
}

/// Une connexion morte dont le port vient de `bind` : son quadruplet est libre, son port non ;
/// elle ne repasse pas par les conflits, même à côté de son écoute.
#[test]
fn une_morte_garde_son_port() {
    let mut t = table();
    let mut l = lien(LO, 8080);
    l.reuseaddr = false;
    assert_eq!(t.lier(1, l, 1, 0), Ok(8080));
    t.ecouter(1).unwrap();
    let fille = Lien { sorte: Sorte::Connectee, distante: [10, 0, 2, 2], port_distant: 40000, ..l };
    t.ajouter_fille(2, fille, 2).unwrap();
    assert_eq!(t.trouver([10, 0, 2, 2], 40000, LO, 8080), Some(Destinataire::Connexion(2)));
    t.redevenir_liee(2, LO);
    assert_eq!(t.lien(2).map(|x| (x.sorte, x.distante, x.port_distant)), Some((Sorte::Liee, TOUT, 0)));
    // Le segment suivant du même client va à l'écoute.
    assert_eq!(t.trouver([10, 0, 2, 2], 40000, LO, 8080), Some(Destinataire::Ecoute(1)));
    t.retirer(1);
    // L'écoute partie, le port reste pris par elle.
    assert_eq!(t.lier(3, lien(LO, 8080), 3, 0), Err(Refus::Pris));
    t.retirer(2);
    assert_eq!(t.lier(3, lien(LO, 8080), 3, 0), Ok(8080));
}
