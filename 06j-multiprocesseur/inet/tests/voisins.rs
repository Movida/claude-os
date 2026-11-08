//! La table des voisins à l'horloge simulée : chaque état et chaque délai
//! de Linux (neighbour.c, avec les réglages d'ARP), ce que slirp, qui
//! répond toujours tout de suite, ne montre jamais.

use inet::voisins::{Action, Appris, Etat, Table, FILE_OCTETS, MAX};

const REPONSE: Appris = Appris::Message { joignable: true, gratuit: false };
const REQUETE: Appris = Appris::RequetePourNous;

const S: u64 = 1_000_000_000;
const ETH0: u32 = 1;
const GW: [u8; 4] = [10, 0, 2, 2];
const MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

/// Ce qu'a demandé la table, en clair.
#[derive(Debug, PartialEq, Eq)]
enum Fait {
    Envoye(u32, [u8; 6]),
    Diffusee([u8; 4]),
    Sondee([u8; 4], [u8; 6]),
    Jete(u32, bool),
}

fn noter(faits: &mut Vec<Fait>) -> impl FnMut(Action<u32>) + '_ {
    |a| faits.push(match a {
        Action::Envoyer { mac, paquet, .. } => Fait::Envoye(paquet, mac),
        Action::Requete { cible, mac: None, .. } => Fait::Diffusee(cible),
        Action::Requete { cible, mac: Some(m), .. } => Fait::Sondee(cible, m),
        Action::Jeter { paquet, echec } => Fait::Jete(paquet, echec),
    })
}

/// Une table dont le temps joignable vaut 15 s (le hasard 0).
fn table() -> Table<u32> {
    let t = Table::new(0, 0).unwrap();
    assert_eq!(t.temps_joignable(), 15 * S);
    t
}

fn etat(t: &Table<u32>, a: [u8; 4]) -> Option<Etat> {
    t.voisin(ETH0, a).map(|v| v.etat)
}

#[test]
fn resolution() {
    let mut t = table();
    let mut f = Vec::new();
    // Un premier paquet : la requête part tout de suite, le paquet attend.
    t.envoyer(ETH0, GW, 1, 1000, false, 0, &mut noter(&mut f));
    assert_eq!(f, [Fait::Diffusee(GW)]);
    assert_eq!((etat(&t, GW), t.echeance()), (Some(Etat::Incomplet), Some(S)));
    // Un deuxième attend aussi ; la réponse les envoie, dans l'ordre.
    f.clear();
    t.envoyer(ETH0, GW, 2, 1000, false, 100, &mut noter(&mut f));
    t.apprendre(ETH0, GW, MAC, REPONSE, 200, &mut noter(&mut f));
    assert_eq!(f, [Fait::Envoye(1, MAC), Fait::Envoye(2, MAC)]);
    assert_eq!((etat(&t, GW), t.echeance()), (Some(Etat::Joignable), Some(200 + 15 * S)));
    // Joignable : envoyé aussitôt.
    f.clear();
    t.envoyer(ETH0, GW, 3, 1000, false, S, &mut noter(&mut f));
    assert_eq!(f, [Fait::Envoye(3, MAC)]);
    // Une réponse pour une machine qu'on n'a pas demandée : ignorée
    // (arp_accept = 0).
    t.apprendre(ETH0, [10, 0, 2, 9], MAC, REPONSE, S, &mut noter(&mut f));
    assert_eq!(etat(&t, [10, 0, 2, 9]), None);
}

#[test]
fn voisin_muet() {
    let mut t = table();
    let mut f = Vec::new();
    let muet = [10, 0, 2, 99];
    t.envoyer(ETH0, muet, 7, 1000, false, 0, &mut noter(&mut f));
    // Trois requêtes en diffusion, à 0, 1 et 2 s, puis l'échec à 3 s : le
    // paquet jeté, à dire à son émetteur.
    t.temps(S - 1, 0, &mut noter(&mut f));
    t.temps(S, 0, &mut noter(&mut f));
    t.temps(2 * S, 0, &mut noter(&mut f));
    assert_eq!(f, [Fait::Diffusee(muet), Fait::Diffusee(muet), Fait::Diffusee(muet)]);
    assert_eq!(etat(&t, muet), Some(Etat::Incomplet));
    f.clear();
    t.temps(3 * S, 0, &mut noter(&mut f));
    assert_eq!(f, [Fait::Jete(7, true)]);
    assert_eq!((etat(&t, muet), t.echeance()), (Some(Etat::Echec), None));
    // Un nouvel envoi recommence une résolution.
    f.clear();
    t.envoyer(ETH0, muet, 8, 1000, false, 10 * S, &mut noter(&mut f));
    assert_eq!((f, etat(&t, muet)), (vec![Fait::Diffusee(muet)], Some(Etat::Incomplet)));
}

/// Une table où la passerelle est joignable depuis l'instant 0.
fn avec_passerelle() -> Table<u32> {
    let mut t = table();
    let mut f = Vec::new();
    t.envoyer(ETH0, GW, 0, 100, false, 0, &mut noter(&mut f));
    t.apprendre(ETH0, GW, MAC, REPONSE, 0, &mut noter(&mut f));
    t
}

#[test]
fn vieillissement_et_sondes() {
    // Passé le temps joignable sans envoi récent : PÉRIMÉ, sans minuteur.
    let mut t = avec_passerelle();
    let mut f = Vec::new();
    t.temps(15 * S + 1, 0, &mut noter(&mut f));
    assert_eq!((etat(&t, GW), t.echeance(), f.len()), (Some(Etat::Perime), None, 0));
    // Un envoi sur PÉRIMÉ : envoyé tout de suite, et RETARDÉ (5 s) ; sans
    // confirmation, SONDÉ : trois requêtes à l'adresse connue, une par
    // seconde, puis l'échec.
    t.envoyer(ETH0, GW, 1, 100, false, 20 * S, &mut noter(&mut f));
    assert_eq!((f.as_slice(), etat(&t, GW)), (&[Fait::Envoye(1, MAC)][..], Some(Etat::Retarde)));
    f.clear();
    t.temps(25 * S, 0, &mut noter(&mut f));
    t.temps(26 * S, 0, &mut noter(&mut f));
    t.temps(27 * S, 0, &mut noter(&mut f));
    assert_eq!(f, [Fait::Sondee(GW, MAC), Fait::Sondee(GW, MAC), Fait::Sondee(GW, MAC)]);
    assert_eq!(etat(&t, GW), Some(Etat::Sonde));
    // En SONDÉ, les paquets partent encore (l'adresse sert jusqu'à l'échec).
    f.clear();
    t.envoyer(ETH0, GW, 2, 100, false, 27 * S + 1, &mut noter(&mut f));
    assert_eq!(f, [Fait::Envoye(2, MAC)]);
    f.clear();
    t.temps(28 * S, 0, &mut noter(&mut f));
    assert_eq!((f.len(), etat(&t, GW)), (0, Some(Etat::Echec)));
    // Une réponse pendant les sondes : JOIGNABLE de nouveau.
    let mut t = avec_passerelle();
    t.temps(15 * S + 1, 0, &mut noter(&mut f));
    t.envoyer(ETH0, GW, 1, 100, false, 20 * S, &mut noter(&mut f));
    t.temps(25 * S, 0, &mut noter(&mut f));
    t.apprendre(ETH0, GW, MAC, REPONSE, 25 * S + 10, &mut noter(&mut f));
    assert_eq!(etat(&t, GW), Some(Etat::Joignable));
}

#[test]
fn confirmations() {
    // Un envoi récent quand le temps joignable finit : RETARDÉ ; une
    // confirmation (MSG_CONFIRM) pendant le délai : JOIGNABLE sans sonde.
    let mut t = avec_passerelle();
    let mut f = Vec::new();
    t.envoyer(ETH0, GW, 1, 100, false, 14 * S, &mut noter(&mut f));
    t.temps(15 * S + 1, 0, &mut noter(&mut f));
    assert_eq!(etat(&t, GW), Some(Etat::Retarde));
    t.envoyer(ETH0, GW, 2, 100, true, 17 * S, &mut noter(&mut f));
    t.temps(20 * S + 1, 0, &mut noter(&mut f));
    assert_eq!((etat(&t, GW), t.echeance()), (Some(Etat::Joignable), Some(17 * S + 15 * S)));
    assert!(f.iter().all(|x| matches!(x, Fait::Envoye(..))), "aucune requête : {f:?}");
}

#[test]
fn requete_qui_nous_vise() {
    // Elle apprend l'émetteur, PÉRIMÉ ; la même adresse de nouveau ne change
    // pas un état valide ; une autre adresse, si.
    let mut t = table();
    let mut f = Vec::new();
    let autre = [10, 0, 2, 50];
    t.apprendre(ETH0, autre, MAC, REQUETE, 0, &mut noter(&mut f));
    assert_eq!(etat(&t, autre), Some(Etat::Perime));
    let mut t = avec_passerelle();
    t.apprendre(ETH0, GW, MAC, REQUETE, S, &mut noter(&mut f));
    assert_eq!(etat(&t, GW), Some(Etat::Joignable));
    t.apprendre(ETH0, GW, [2; 6], REQUETE, S, &mut noter(&mut f));
    assert_eq!(t.voisin(ETH0, GW).map(|v| (v.etat, v.mac)), Some((Etat::Perime, [2; 6])));
    // Une requête qui arrive pendant une résolution : la file part.
    let mut t = table();
    t.envoyer(ETH0, autre, 9, 100, false, 0, &mut noter(&mut f));
    f.clear();
    t.apprendre(ETH0, autre, MAC, REQUETE, 10, &mut noter(&mut f));
    assert_eq!(f, [Fait::Envoye(9, MAC)]);
}

#[test]
fn file_et_table_pleines() {
    // La file d'attente : au-delà de 212 992 octets, les plus anciens jetés.
    let mut t = table();
    let mut f = Vec::new();
    let muet = [10, 0, 2, 99];
    for k in 0..4 {
        t.envoyer(ETH0, muet, k, FILE_OCTETS / 3, false, k as u64, &mut noter(&mut f));
    }
    assert_eq!(f, [Fait::Diffusee(muet), Fait::Jete(0, false)]);
    // La table pleine : l'entrée la plus ancienne qui n'attend rien est
    // reprise ; si toutes attendent, le paquet est jeté.
    let mut t = table();
    for k in 0..MAX as u8 {
        t.apprendre(ETH0, [10, 1, 0, k], MAC, REQUETE, k as u64, &mut noter(&mut f));
    }
    f.clear();
    t.envoyer(ETH0, GW, 1, 100, false, 1000, &mut noter(&mut f));
    assert_eq!((etat(&t, [10, 1, 0, 0]), etat(&t, GW)), (None, Some(Etat::Incomplet)));
    let mut t = table();
    for k in 0..MAX as u8 {
        t.envoyer(ETH0, [10, 1, 0, k], k as u32, 100, false, 0, &mut noter(&mut f));
    }
    f.clear();
    t.envoyer(ETH0, GW, 99, 100, false, 1, &mut noter(&mut f));
    assert_eq!((f, etat(&t, GW)), (vec![Fait::Jete(99, false)], None));
}

#[test]
fn temps_joignable_tire() {
    // Entre 15 et 45 s, tiré de nouveau toutes les 300 s.
    let t: Table<u32> = Table::new(u64::MAX, 0).unwrap();
    assert!((15 * S..45 * S).contains(&t.temps_joignable()));
    let mut t: Table<u32> = Table::new(0, 0).unwrap();
    t.temps(299 * S, 7 * S, &mut |_| {});
    assert_eq!(t.temps_joignable(), 15 * S);
    t.temps(300 * S, 7 * S, &mut |_| {});
    assert_eq!(t.temps_joignable(), 22 * S);
}

#[test]
fn messages_arp() {
    // Un message qui n'est pas une requête pour nous n'apprend rien d'une
    // machine inconnue (arp_accept = 0).
    let mut t = table();
    let mut f = Vec::new();
    let autre = [10, 0, 2, 60];
    t.apprendre(ETH0, autre, MAC, REPONSE, 0, &mut noter(&mut f));
    assert_eq!(etat(&t, autre), None);
    // Une réponse diffusée ne prouve pas que la machine est joignable :
    // PÉRIMÉ ; puis la même adresse annoncée PÉRIMÉE ne change pas un état
    // valide.
    let mut t = table();
    t.envoyer(ETH0, GW, 1, 100, false, 0, &mut noter(&mut f));
    t.apprendre(ETH0, GW, MAC, Appris::Message { joignable: false, gratuit: false }, 10, &mut noter(&mut f));
    assert_eq!(etat(&t, GW), Some(Etat::Perime));
    t.apprendre(ETH0, GW, MAC, REPONSE, 20, &mut noter(&mut f));
    t.apprendre(ETH0, GW, MAC, Appris::Message { joignable: false, gratuit: false }, 30, &mut noter(&mut f));
    assert_eq!(etat(&t, GW), Some(Etat::Joignable));
    // Une autre adresse moins d'une seconde après la dernière mise à jour :
    // la première gagne ; après une seconde, elle remplace ; une annonce
    // gratuite remplace tout de suite.
    let autre_mac = [2; 6];
    t.apprendre(ETH0, GW, autre_mac, REPONSE, S / 2, &mut noter(&mut f));
    assert_eq!(t.voisin(ETH0, GW).map(|v| v.mac), Some(MAC), "verrouillée une seconde");
    t.apprendre(ETH0, GW, autre_mac, REPONSE, 20 + S + 1, &mut noter(&mut f));
    assert_eq!(t.voisin(ETH0, GW).map(|v| (v.etat, v.mac)), Some((Etat::Joignable, autre_mac)));
    t.apprendre(ETH0, GW, MAC, Appris::Message { joignable: false, gratuit: true }, 20 + S + 2, &mut noter(&mut f));
    assert_eq!(t.voisin(ETH0, GW).map(|v| (v.etat, v.mac)), Some((Etat::Perime, MAC)), "l'annonce gratuite");
}
