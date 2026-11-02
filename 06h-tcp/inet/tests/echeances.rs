//! Les échéances du réseau, contre un modèle naïf : des milliers
//! d'opérations au hasard (armer, réarmer plus tôt ou plus tard, désarmer,
//! prendre les échues), et les cas de bord.

use inet::echeances::{Echeances, Pleine};
use std::collections::HashMap;

/// Un générateur simple et reproductible (xorshift).
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn cas_de_bord() {
    let mut e = Echeances::new(2).unwrap();
    assert_eq!(e.prochaine(), None);
    assert_eq!(e.prendre_echu(u64::MAX), None);
    e.armer(7, 100).unwrap();
    e.armer(8, 50).unwrap();
    assert_eq!(e.armer(9, 10), Err(Pleine));
    // Réarmer un objet déjà présent, même pleine : permis.
    e.armer(7, 10).unwrap();
    assert_eq!(e.prochaine(), Some(10));
    assert_eq!(e.echeance(8), Some(50));
    assert_eq!(e.prendre_echu(9), None);
    assert_eq!(e.prendre_echu(10), Some(7));
    assert_eq!(e.prendre_echu(10), None);
    e.desarmer(8);
    e.desarmer(8);
    assert!(e.is_empty());
    // À égalité : dans l'ordre où elles ont été armées.
    e.armer(1, 5).unwrap();
    e.armer(2, 5).unwrap();
    assert_eq!((e.prendre_echu(5), e.prendre_echu(5)), (Some(1), Some(2)));
}

#[test]
fn contre_un_modele() {
    for graine in 1..=20u64 {
        let mut h = Hasard(graine * 0x9E37_79B9_7F4A_7C15);
        let mut e = Echeances::new(32).unwrap();
        let mut modele: HashMap<u64, u64> = HashMap::new();
        let mut maintenant = 0u64;
        for _ in 0..5000 {
            let objet = h.suivant() % 40;
            match h.suivant() % 4 {
                0 | 1 => {
                    let echeance = maintenant + h.suivant() % 1000;
                    let r = e.armer(objet, echeance);
                    if modele.contains_key(&objet) || modele.len() < 32 {
                        assert_eq!(r, Ok(()));
                        modele.insert(objet, echeance);
                    } else {
                        assert_eq!(r, Err(Pleine));
                    }
                }
                2 => {
                    e.desarmer(objet);
                    modele.remove(&objet);
                }
                _ => {
                    maintenant += h.suivant() % 300;
                    // Toutes les échues, dans l'ordre de leurs échéances.
                    let mut derniere = 0;
                    while let Some(o) = e.prendre_echu(maintenant) {
                        let ech = modele.remove(&o).expect("un objet du modele");
                        assert!(ech <= maintenant && ech >= derniere);
                        derniere = ech;
                    }
                    assert!(modele.values().all(|&ech| ech > maintenant));
                }
            }
            assert_eq!(e.len(), modele.len());
            assert_eq!(e.prochaine(), modele.values().min().copied());
            for (o, ech) in &modele {
                assert_eq!(e.echeance(*o), Some(*ech));
            }
        }
    }
}
