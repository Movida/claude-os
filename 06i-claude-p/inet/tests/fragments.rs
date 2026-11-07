//! Le réassemblage (inet::fragments) : ce que fait `ip_frag_queue` de morceaux
//! dans l'ordre, dans le désordre, en double, à cheval, faux, qui n'arrivent pas.

use inet::fragments::{Cle, DELAI, Echue, Issue, MEMOIRE_MAX, Morceau, Reassemblage};

#[derive(Debug, PartialEq, Eq)]
struct Octets(Vec<u8>);

impl Morceau for Octets {
    fn octets(&self) -> &[u8] {
        &self.0
    }
    fn couper(&mut self, n: usize) {
        self.0.truncate(n);
    }
    fn taille_vraie(&self) -> usize {
        self.0.len() + 576
    }
}

const CLE: Cle = Cle { source: [10, 0, 2, 2], destination: [10, 0, 2, 15], identifiant: 7, protocole: 17 };

/// Un morceau [`debut`, `debut + n`[, ses octets disant leur place.
fn morceau(debut: u32, n: u32) -> Octets {
    Octets((debut..debut + n).map(|i| i as u8).collect())
}

fn table() -> Reassemblage<Octets> {
    Reassemblage::new().unwrap()
}

fn donner(r: &mut Reassemblage<Octets>, debut: u32, n: u32, suite: bool) -> Issue<Octets> {
    r.recevoir(CLE, debut, suite, 0, 20, morceau(debut, n), 1, 0)
}

/// Le paquet que donne `Complet`.
fn recolle(i: Issue<Octets>) -> Vec<u8> {
    let Issue::Complet { morceaux, longueur, entete, ecn } = i else { panic!("pas complet") };
    assert_eq!((entete, ecn), (20, 0));
    let d: Vec<u8> = morceaux.iter().flat_map(|m| m.0.iter().copied()).collect();
    assert_eq!(d.len() as u32, longueur);
    d
}

fn attendu(n: u32) -> Vec<u8> {
    (0..n).map(|i| i as u8).collect()
}

#[test]
fn dans_l_ordre_et_dans_le_desordre() {
    let mut r = table();
    assert_eq!(donner(&mut r, 0, 1480, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 1480, 1480, true), Issue::EnCours);
    assert_eq!(recolle(donner(&mut r, 2960, 100, false)), attendu(3060));
    assert_eq!(r.memoire(), 0);
    // À l'envers, et le milieu en dernier.
    for ordre in [[2, 1, 0], [0, 2, 1], [1, 0, 2], [2, 0, 1], [1, 2, 0]] {
        let mut d = None;
        for k in ordre {
            let (debut, n, suite) = [(0, 800, true), (800, 800, true), (1600, 5, false)][k];
            match donner(&mut r, debut, n, suite) {
                Issue::EnCours => {}
                i => d = Some(recolle(i)),
            }
        }
        assert_eq!(d.unwrap(), attendu(1605), "{ordre:?}");
    }
    assert_eq!(r.memoire(), 0);
}

/// Deux paquets à la fois : leurs clés les séparent.
#[test]
fn les_paquets_ne_se_melangent_pas() {
    let mut r = table();
    let autre = Cle { identifiant: 8, ..CLE };
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    assert_eq!(r.recevoir(autre, 0, true, 0, 20, morceau(100, 8), 1, 0), Issue::EnCours);
    let i = r.recevoir(autre, 8, false, 0, 20, morceau(108, 8), 1, 0);
    let Issue::Complet { morceaux, .. } = i else { panic!() };
    assert_eq!(morceaux[0].0, morceau(100, 8).0);
    assert_eq!(recolle(donner(&mut r, 8, 8, false)), attendu(16));
}

/// Un morceau en double est ignoré, et la file continue ; à cheval, toute la file est
/// jetée (RFC 5722) : ce qui vient ensuite ne recolle rien.
#[test]
fn doubles_et_chevauchements() {
    let mut r = table();
    assert_eq!(donner(&mut r, 0, 16, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 0, 16, true), Issue::Jete);
    assert_eq!(donner(&mut r, 8, 8, true), Issue::Jete, "tout entier dedans : un double");
    assert_eq!(recolle(donner(&mut r, 16, 8, false)), attendu(24));
    assert_eq!(r.memoire(), 0);
    // Au bout de la file, à cheval.
    assert_eq!(donner(&mut r, 0, 16, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 8, 16, true), Issue::Jete);
    assert_eq!(r.memoire(), 0, "toute la file");
    assert_eq!(donner(&mut r, 16, 8, false), Issue::EnCours, "une file neuve");
    assert_eq!(donner(&mut r, 8, 16, true), Issue::Jete);
    assert_eq!(r.memoire(), 0);
    // En plein milieu.
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 32, 8, false), Issue::EnCours);
    assert_eq!(donner(&mut r, 4, 16, true), Issue::Jete);
    assert_eq!(r.memoire(), 0);
}

/// `ip_frag_queue` : une fin contraire à ce qu'on sait jette la file ; un morceau qui
/// n'est pas le dernier est ramené à un multiple de 8 ; un morceau vide après cela, de même.
#[test]
fn fins_fausses() {
    let mut r = table();
    assert_eq!(donner(&mut r, 8, 8, false), Issue::EnCours);
    assert_eq!(donner(&mut r, 0, 4, false), Issue::Jete, "une autre fin");
    assert_eq!(r.memoire(), 0);
    assert_eq!(donner(&mut r, 8, 8, false), Issue::EnCours);
    assert_eq!(donner(&mut r, 16, 8, true), Issue::Jete, "au-delà de la fin");
    assert_eq!(r.memoire(), 0);
    assert_eq!(donner(&mut r, 16, 8, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 0, 8, false), Issue::Jete, "la fin avant ce qu'on a");
    assert_eq!(r.memoire(), 0);
    // 12 octets avec MF : coupés à 8.
    assert_eq!(donner(&mut r, 0, 12, true), Issue::EnCours);
    assert_eq!(recolle(donner(&mut r, 8, 2, false)), attendu(10));
    // Moins de 8 octets avec MF : plus rien.
    assert_eq!(donner(&mut r, 0, 4, true), Issue::Jete);
}

/// Un paquet recollé de plus de 65 535 octets : jeté.
#[test]
fn trop_long() {
    let mut r = table();
    assert_eq!(donner(&mut r, 0, 65_000, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 65_000, 600, false), Issue::Jete);
    assert_eq!(r.memoire(), 0);
    // 65 515 octets et 20 d'en-tête : tout juste.
    assert_eq!(donner(&mut r, 0, 65_000, true), Issue::EnCours);
    assert_eq!(recolle(donner(&mut r, 65_000, 515, false)).len(), 65_515);
}

/// Une file expire après 30 s ; son premier morceau rendu, pour le dire à l'émetteur.
#[test]
fn expiration() {
    let mut r = table();
    assert_eq!(r.echeance(), None);
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    assert_eq!(r.echeance(), Some(DELAI));
    assert!(r.prendre_echue(DELAI - 1).is_none());
    let Some(Echue { premier, entete, interface }) = r.prendre_echue(DELAI) else { panic!() };
    assert_eq!((premier.unwrap().0, entete, interface), (morceau(0, 8).0, 20, 1));
    assert_eq!((r.memoire(), r.echeance()), (0, None));
    // Sans le premier : rien à dire.
    assert_eq!(donner(&mut r, 8, 8, true), Issue::EnCours);
    assert!(r.prendre_echue(DELAI).unwrap().premier.is_none());
}

/// Au-delà de 4 Mio, plus de nouvelle file ; plus de 64 morceaux de la même source
/// depuis le dernier d'une file, et elle repart de rien (`ipfrag_max_dist`).
#[test]
fn memoire_bornee_et_files_en_retard() {
    let mut r = table();
    let mut decalage = 0;
    while r.memoire() <= MEMOIRE_MAX {
        assert_eq!(r.recevoir(Cle { identifiant: 1, ..CLE }, decalage, true, 0, 20, morceau(0, 60_000), 1, 0), Issue::EnCours);
        decalage += 60_000;
    }
    assert_eq!(donner(&mut r, 0, 8, true), Issue::Jete);
    let mut r = table();
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    for i in 0..65 {
        assert_eq!(r.recevoir(Cle { identifiant: 100 + i, ..CLE }, 0, true, 0, 20, morceau(0, 8), 1, 0), Issue::EnCours);
    }
    // Celui-ci serait la fin de la première : elle a oublié le début.
    assert_eq!(donner(&mut r, 8, 8, false), Issue::EnCours);
    // D'une autre source : rien ne l'éloigne.
    let mut r = table();
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    for i in 0..65 {
        let c = Cle { source: [10, 0, 2, 3], identifiant: 100 + i, ..CLE };
        assert_eq!(r.recevoir(c, 0, true, 0, 20, morceau(0, 8), 1, 0), Issue::EnCours);
    }
    assert_eq!(recolle(donner(&mut r, 8, 8, false)), attendu(16));
}

/// Les bits ECN (`ip_frag_ecn_table`) : CE d'un morceau parmi ECT devient celui du paquet ;
/// un morceau sans ECN parmi d'autres avec : tout est jeté.
#[test]
fn ecn() {
    let mut r = table();
    assert_eq!(r.recevoir(CLE, 0, true, 2, 20, morceau(0, 8), 1, 0), Issue::EnCours);
    let i = r.recevoir(CLE, 8, false, 3, 20, morceau(8, 8), 1, 0);
    let Issue::Complet { ecn, .. } = i else { panic!() };
    assert_eq!(ecn, 3);
    assert_eq!(r.recevoir(CLE, 0, true, 0, 20, morceau(0, 8), 1, 0), Issue::EnCours);
    assert_eq!(r.recevoir(CLE, 8, false, 1, 20, morceau(8, 8), 1, 0), Issue::Jete);
    assert_eq!(r.memoire(), 0);
}

/// Le dernier morceau redit : un double, pas une fin contraire ; un morceau non dernier qui finit
/// pile où finit le paquet, de même (`ip_frag_queue`).
#[test]
fn le_dernier_redit() {
    let mut r = table();
    assert_eq!(donner(&mut r, 16, 8, false), Issue::EnCours);
    // Jetés, mais la file reste.
    assert_eq!(donner(&mut r, 16, 8, false), Issue::Jete);
    assert_eq!(donner(&mut r, 16, 8, true), Issue::Jete);
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    assert_eq!(recolle(donner(&mut r, 8, 8, true)), attendu(24));
}

/// Un morceau qui n'est pas le dernier s'arrête à un multiple de 8 : le reste de sa charge est coupé
/// (`end &= ~7`), et le paquet recollé n'en garde rien.
#[test]
fn coupe_a_un_multiple_de_8() {
    let mut r = table();
    assert_eq!(donner(&mut r, 0, 13, true), Issue::EnCours);
    assert_eq!(recolle(donner(&mut r, 8, 8, false)), attendu(16));
}

/// `ipfrag_max_dist`, au bord (`ip_frag_too_far` : l'écart de ses numéros, plus de 64) : 63 autres
/// morceaux entre deux des siens : encore bon ; 64 : la file repart de rien.
#[test]
fn l_ecart_maximal() {
    for (autres, complet) in [(63u16, true), (64, false)] {
        let mut r = table();
        assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
        for k in 0..autres {
            assert_eq!(r.recevoir(Cle { identifiant: 100 + k, ..CLE }, 0, true, 0, 20, morceau(0, 8), 1, 0), Issue::EnCours);
        }
        let i = donner(&mut r, 8, 8, false);
        assert_eq!(matches!(i, Issue::Complet { .. }), complet, "{autres} autres");
    }
}

/// La borne de 4 Mio tient aussi pour les files déjà ouvertes : sans quoi des paquets commencés
/// avant elle continueraient à grossir (`inet_frag_find`).
#[test]
fn la_borne_vaut_pour_les_files_ouvertes() {
    let mut r = table();
    // Une source par file : `ipfrag_max_dist` ne les jette pas.
    let cle = |id: u16| Cle { source: [10, 0, 3, id as u8], destination: [10, 0, 2, 15], identifiant: id, protocole: 17 };
    for id in 0..128u16 {
        assert_eq!(r.recevoir(cle(id), 8, true, 0, 20, Octets(vec![0; 8]), 1, 0), Issue::EnCours);
    }
    let mut jetes = 0;
    for k in 2..8000u32 {
        for id in 0..128u16 {
            if r.recevoir(cle(id), 8 * k, true, 0, 20, Octets(vec![0; 8]), 1, 0) != Issue::EnCours {
                jetes += 1;
            }
        }
    }
    assert!(jetes > 0);
    assert!(r.memoire() <= MEMOIRE_MAX + 2048, "{} octets", r.memoire());
}

/// Un morceau qui n'est pas le dernier s'arrête à un multiple de 8 : le reste tombe, même au milieu
/// du paquet.
#[test]
fn un_morceau_coupe_au_milieu() {
    let mut r = table();
    assert_eq!(donner(&mut r, 8, 13, true), Issue::EnCours);
    assert_eq!(donner(&mut r, 0, 8, true), Issue::EnCours);
    assert_eq!(recolle(donner(&mut r, 16, 5, false)), attendu(21));
}

/// Tout juste `ipfrag_high_thresh` : on accepte encore ; au-delà, tout est jeté.
#[test]
fn la_memoire_tout_juste() {
    let mut r = table();
    let cle = Cle { identifiant: 1, ..CLE };
    // 69 morceaux de 60 000 + 576 octets, puis ce qu'il faut pour faire 4 Mio tout juste.
    let mut decalage = 0;
    for n in [60_000; 69].into_iter().chain([13_984]) {
        assert_eq!(r.recevoir(cle, decalage, true, 0, 20, morceau(0, n), 1, 0), Issue::EnCours);
        decalage += n;
    }
    assert_eq!(r.memoire(), MEMOIRE_MAX);
    assert_eq!(r.recevoir(cle, decalage, true, 0, 20, morceau(0, 8), 1, 0), Issue::EnCours);
    assert_eq!(r.recevoir(cle, decalage + 8, true, 0, 20, morceau(0, 8), 1, 0), Issue::Jete);
}
