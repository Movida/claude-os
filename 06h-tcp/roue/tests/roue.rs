//! La roue, contre ce que dit timer.c et contre un modèle naïf : ni trop tôt, ni plus tard que ce
//! que permet le niveau ; rien de perdu, ni rendu deux fois ; la prochaine échéance dit vrai.

use roue::{Pleine, Roue, TIC};
use std::collections::HashMap;

const MS: u64 = 1_000_000;

struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// L'heure à laquelle une échéance à `delai` de `0` part, et rien avant : le premier instant où
/// `prendre_echu` la rend.
fn part_a(delai: u64) -> u64 {
    let mut r = Roue::new(4).unwrap();
    r.armer(1, delai, 0).unwrap();
    let t = r.prochaine().unwrap();
    assert_eq!(r.prendre_echu(t.saturating_sub(1)), None, "pas avant");
    assert_eq!(r.prendre_echu(t), Some(1), "a son heure");
    t
}

/// Le tableau de timer.c, pour HZ 250 : chaque niveau arrondit à sa granularité, au-dessus.
#[test]
fn les_niveaux_de_timer_c() {
    // Niveau 0 : 4 ms, jusqu'à 62 tics (248 ms) : le tic suivant.
    assert_eq!(part_a(0), TIC);
    assert_eq!(part_a(MS), TIC);
    assert_eq!(part_a(200 * MS), 204 * MS);
    assert_eq!(part_a(248 * MS), 252 * MS);
    // Niveau 1 : 32 ms, à partir de 63 tics.
    assert_eq!(part_a(252 * MS), 256 * MS);
    assert_eq!(part_a(1000 * MS), 1024 * MS);
    assert_eq!(part_a(1024 * MS), 1056 * MS);
    // Niveau 2 : 256 ms, à partir de 504 tics (2016 ms).
    assert_eq!(part_a(2016 * MS), 2048 * MS);
    assert_eq!(part_a(3000 * MS), 3072 * MS);
    // Niveau 3 : 2048 ms, à partir de 16 128 ms.
    assert_eq!(part_a(60_000 * MS), 61_440 * MS);
    // Deux heures de keepalive : le niveau 5, 131 072 ms.
    assert_eq!(part_a(7_200_000 * MS), 7_208_960 * MS);
}

/// Une case qui tombe pile sur l'échéance de repli d'une roue vide : elle n'est pas perdue.
#[test]
fn pile_sur_l_echeance_de_repli() {
    let mut e = Roue::new(2).unwrap();
    let echeance = (63 << 24) * TIC;
    e.armer(1, echeance, TIC).unwrap();
    let t = e.prochaine().expect("elle a une echeance");
    assert!(t > echeance);
    assert_eq!(e.prendre_echu(t), Some(1));
}

/// Au-delà de 49 jours, à la limite de la roue, plutôt que jamais.
#[test]
fn au_dela_de_la_roue() {
    assert_eq!(part_a(100 * 24 * 3600 * 1000 * MS), (63 << 24) * TIC);
    // Depuis un tic qui n'est pas aligné : `WHEEL_TIMEOUT_MAX` (63 << 24, moins une case du dernier
    // niveau, 1 << 24) à partir de lui, arrondi à cette case.
    let mut e = Roue::new(2).unwrap();
    let clk = (1 << 24) - 1;
    e.armer(1, u64::MAX / 2, clk * TIC).unwrap();
    assert_eq!(e.prochaine(), Some((63 << 24) * TIC));
}

#[test]
fn cas_de_bord() {
    let mut e = Roue::new(2).unwrap();
    assert_eq!(e.prochaine(), None);
    assert_eq!(e.prendre_echu(u64::MAX / 2), None);
    e.armer(7, 100 * MS, 0).unwrap();
    e.armer(8, 50 * MS, 0).unwrap();
    assert_eq!(e.armer(9, 10 * MS, 0), Err(Pleine));
    // Réarmer un objet déjà présent, même pleine : permis.
    e.armer(7, 10 * MS, 0).unwrap();
    assert_eq!(e.echeance(8), Some(50 * MS));
    assert_eq!(e.echeance(9), None);
    assert_eq!(e.prochaine(), Some(12 * MS));
    assert_eq!(e.prendre_echu(11 * MS), None);
    assert_eq!(e.prendre_echu(12 * MS), Some(7));
    assert_eq!(e.prendre_echu(12 * MS), None);
    assert!(!e.is_empty());
    e.desarmer(8);
    e.desarmer(8);
    assert!(e.is_empty());
    assert_eq!(e.prochaine(), None);
    // Désarmé, un minuteur ne laisse pas une fausse échéance.
    e.armer(1, 100 * MS, 0).unwrap();
    e.armer(2, 200 * MS, 0).unwrap();
    e.desarmer(1);
    assert_eq!(e.prochaine(), Some(204 * MS));
}

/// Une échéance passée : au tic courant, sans attendre.
#[test]
fn deja_passee() {
    let mut e = Roue::new(2).unwrap();
    e.armer(1, 10 * MS, 0).unwrap();
    assert_eq!(e.prendre_echu(100 * MS), Some(1));
    e.armer(2, 0, 100 * MS).unwrap();
    let t = e.prochaine().unwrap();
    assert!(t <= 104 * MS, "{t}");
    assert_eq!(e.prendre_echu(104 * MS), Some(2));
    // Le tic traité est passé : `clk` le suit : une échéance déjà passée va au tic d'après, pas plus
    // tôt.
    let mut e = Roue::new(2).unwrap();
    e.armer(1, 10 * MS, 0).unwrap();
    assert_eq!(e.prendre_echu(12 * MS), Some(1));
    e.armer(2, 8 * MS, 12 * MS).unwrap();
    assert_eq!(e.prochaine(), Some(16 * MS));
}

/// Après un long silence, un minuteur s'arme par rapport à l'heure qu'il est : un délai court reste
/// dans le niveau 0 (`__forward_timer_base`).
#[test]
fn apres_un_long_silence() {
    let mut e = Roue::new(2).unwrap();
    let t0 = 3_600_000 * MS;
    e.armer(1, t0 + 200 * MS, t0).unwrap();
    assert_eq!(e.prochaine(), Some(t0 + 204 * MS));
    // Un minuteur déjà armé, qu'on réarme longtemps après.
    let mut e = Roue::new(2).unwrap();
    e.armer(1, 2 * t0, 0).unwrap();
    e.armer(1, t0 + 200 * MS, t0).unwrap();
    assert_eq!(e.prochaine(), Some(t0 + 204 * MS));
    // Un autre attend, loin : la roue avance quand même jusqu'à maintenant.
    let mut e = Roue::new(2).unwrap();
    e.armer(1, 2 * t0, 0).unwrap();
    e.armer(2, t0 + 200 * MS, t0).unwrap();
    assert_eq!(e.prochaine(), Some(t0 + 204 * MS));
    // Un autre est dû, pas encore servi : elle n'avance que jusqu'à lui, pour ne pas le perdre.
    let mut e = Roue::new(2).unwrap();
    e.armer(1, 100 * MS, 0).unwrap();
    e.armer(2, t0 + 200 * MS, t0).unwrap();
    assert_eq!(e.prochaine(), Some(104 * MS));
    assert_eq!(e.prendre_echu(t0), Some(1));
    assert_eq!(e.prochaine().map(|t| t >= t0 + 200 * MS), Some(true));
}

/// L'heure de la case d'une échéance, armée au tic `clk` (`calc_wheel_index`), recalculée à part.
fn heure_de_la_case(expire: u64, clk: u64) -> u64 {
    let delta = expire - clk;
    for n in 0..8 {
        if delta < 63 << (3 * n) {
            return ((expire >> (3 * n)) + 1) << (3 * n);
        }
    }
    ((expire >> 24) + 1) << 24
}

/// La prochaine échéance est exactement la plus proche, à tous les niveaux, même quand les bas
/// niveaux se sont vidés et que `clk` n'est aligné sur rien (`timer_recalc_next_expiry`).
#[test]
fn la_prochaine_est_la_plus_proche() {
    let mut h = Hasard(0xDEAD_BEEF_0BAD_F00D);
    for _ in 0..300 {
        let mut e = Roue::new(64).unwrap();
        // Une heure de départ quelconque : le tic n'est aligné sur aucun niveau.
        let t0 = (h.suivant() % (1 << 30)) * TIC;
        e.armer(1000, t0, t0).unwrap();
        while e.prendre_echu(t0 + TIC).is_some() {}
        let clk = t0 / TIC + 2;
        let mut attendues: Vec<(u64, u64)> = Vec::new();
        for objet in 0..40u64 {
            let delai = h.suivant() % (1 << (h.suivant() % 26 + 1));
            let e0 = clk * TIC;
            e.armer(objet, e0 + delai * TIC, e0).unwrap();
            attendues.push((heure_de_la_case(clk + delai, clk), objet));
        }
        // Quelques-uns désarmés : leur case peut se vider, et la prochaine doit se recalculer.
        for objet in 0..40u64 {
            if h.suivant() % 4 == 0 {
                e.desarmer(objet);
                attendues.retain(|&(_, o)| o != objet);
            }
        }
        attendues.sort();
        while let Some(&(heure, _)) = attendues.first() {
            assert_eq!(e.prochaine(), Some(heure * TIC));
            let mut rendus = Vec::new();
            while let Some(o) = e.prendre_echu(heure * TIC) {
                rendus.push(o);
            }
            let mut voulus: Vec<u64> = attendues.iter().take_while(|a| a.0 == heure).map(|a| a.1).collect();
            attendues.retain(|a| a.0 != heure);
            rendus.sort();
            voulus.sort();
            assert_eq!(rendus, voulus);
        }
        assert_eq!(e.prochaine(), None);
    }
}

/// Des numéros qui se heurtent dans la table : la suite ne se rompt pas quand on en retire un.
#[test]
fn des_numeros_qui_se_heurtent() {
    let mut h = Hasard(0x0123_4567_89AB_CDEF);
    // Une petite table, presque pleine : 2 fois sa capacité, moins ce qui est pris.
    let mut e = Roue::new(8).unwrap();
    let numeros: Vec<u64> = (0..200).map(|_| h.suivant()).collect();
    let mut modele: HashMap<u64, u64> = HashMap::new();
    for _ in 0..200_000 {
        let n = numeros[(h.suivant() % 12) as usize];
        if h.suivant() % 2 == 0 {
            let t = h.suivant() % (1 << 30);
            let r = e.armer(n, t, 0);
            if modele.contains_key(&n) || modele.len() < 8 {
                assert_eq!(r, Ok(()));
                modele.insert(n, t);
            } else {
                assert_eq!(r, Err(Pleine));
            }
        } else {
            e.desarmer(n);
            modele.remove(&n);
        }
        for k in numeros.iter().take(12) {
            assert_eq!(e.echeance(*k), modele.get(k).copied());
        }
    }
}

/// Repousser un minuteur dans la même case ne change rien à la roue ; désarmer pendant qu'on
/// rend les échus non plus ne perd personne.
#[test]
fn repousser_et_desarmer_en_route() {
    let mut e = Roue::new(8).unwrap();
    e.armer(1, 200 * MS, 0).unwrap();
    e.armer(1, 201 * MS, 0).unwrap();
    assert_eq!(e.echeance(1), Some(201 * MS));
    assert_eq!(e.prochaine(), Some(204 * MS));
    e.armer(2, 201 * MS, 0).unwrap();
    e.armer(3, 201 * MS, 0).unwrap();
    let a = e.prendre_echu(204 * MS).unwrap();
    assert!((1..=3).contains(&a));
    // Parmi les deux qui restent à rendre, un désarmé, et un réarmé plus tard.
    let autres: Vec<u64> = [1, 2, 3].into_iter().filter(|&x| x != a).collect();
    e.desarmer(autres[0]);
    e.armer(autres[1], 300 * MS, 204 * MS).unwrap();
    assert_eq!(e.prendre_echu(204 * MS), None);
    assert_eq!(e.prochaine(), Some(304 * MS));
    assert_eq!(e.prendre_echu(304 * MS), Some(autres[1]));
    assert!(e.is_empty());
}

/// Des milliers d'opérations au hasard, de toutes les distances, contre un modèle naïf.
#[test]
fn contre_un_modele() {
    for graine in 1..=30u64 {
        let mut h = Hasard(graine.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut e = Roue::new(64).unwrap();
        let mut modele: HashMap<u64, u64> = HashMap::new();
        let mut maintenant = 0u64;
        // Des numéros quelconques : ils se heurtent dans la table.
        let numeros: Vec<u64> = (0..80).map(|_| h.suivant()).collect();
        for _ in 0..20_000 {
            let objet = numeros[(h.suivant() % 80) as usize];
            match h.suivant() % 8 {
                0..=3 => {
                    // Toutes les échelles, de la milliseconde aux jours.
                    let echelle = 1u64 << (h.suivant() % 40);
                    let echeance = maintenant + h.suivant() % echelle.max(2);
                    let r = e.armer(objet, echeance, maintenant);
                    if modele.contains_key(&objet) || modele.len() < 64 {
                        assert_eq!(r, Ok(()));
                        modele.insert(objet, echeance);
                    } else {
                        assert_eq!(r, Err(Pleine));
                    }
                }
                4 => {
                    e.desarmer(objet);
                    modele.remove(&objet);
                }
                _ => {
                    // Le temps passe : parfois jusqu'à la prochaine échéance, parfois un peu.
                    maintenant = match e.prochaine() {
                        Some(t) if h.suivant() % 2 == 0 => maintenant.max(t),
                        _ => maintenant + h.suivant() % (32 * MS),
                    };
                    while let Some(o) = e.prendre_echu(maintenant) {
                        let voulue = modele.remove(&o).expect("rendu sans etre arme, ou deux fois");
                        assert!(voulue <= maintenant, "trop tot : {voulue} a {maintenant}");
                    }
                }
            }
            assert_eq!(e.len(), modele.len());
            for (&o, &t) in &modele {
                assert_eq!(e.echeance(o), Some(t));
            }
        }
        // Tout finit par partir, jamais avant son heure, et la prochaine échéance dit vrai.
        while let Some(t) = e.prochaine() {
            maintenant = maintenant.max(t);
            let mut n = 0;
            while let Some(o) = e.prendre_echu(maintenant) {
                let voulue = modele.remove(&o).expect("rendu sans etre arme");
                assert!(voulue <= maintenant);
                n += 1;
            }
            assert!(n > 0, "une prochaine echeance sans rien a rendre");
        }
        assert!(modele.is_empty(), "{} perdus", modele.len());
    }
}

/// Parmi d'autres minuteurs, armés à toute heure : pas plus en retard que ce que permet le niveau.
#[test]
fn le_retard_reste_borne() {
    for graine in 1..=20u64 {
        let mut h = Hasard(graine.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut e = Roue::new(64).unwrap();
        let mut modele: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut maintenant = 0u64;
        for _ in 0..50_000 {
            let objet = h.suivant() % 64;
            if h.suivant() % 2 == 0 {
                let delai = h.suivant() % (1u64 << (h.suivant() % 40 + 1));
                e.armer(objet, maintenant + delai, maintenant).unwrap();
                modele.insert(objet, (maintenant + delai, maintenant));
            } else if let Some(t) = e.prochaine() {
                maintenant = maintenant.max(t);
                while let Some(o) = e.prendre_echu(maintenant) {
                    let (voulue, armee) = modele.remove(&o).unwrap();
                    assert!(voulue <= maintenant);
                    let permis = (voulue - armee) / 63 * 8 + 3 * TIC;
                    assert!(maintenant - voulue <= permis, "{voulue} armee a {armee}, partie a {maintenant}");
                }
            }
        }
    }
}

/// Jamais plus tard que ce que permet son niveau : un huitième environ, plus un tic.
#[test]
fn au_plus_un_huitieme_plus_tard() {
    let mut h = Hasard(0x1234_5678_9ABC_DEF1);
    for _ in 0..200_000 {
        let delai = h.suivant() % (1u64 << (h.suivant() % 42));
        // La limite de la roue.
        if delai > 40 * 24 * 3600 * 1000 * MS {
            continue;
        }
        let t = part_a(delai);
        assert!(t >= delai, "trop tot : {delai} -> {t}");
        assert!(t - delai <= delai / 63 * 8 + 2 * TIC, "trop tard : {delai} -> {t}");
    }
}

/// Armé alors qu'une échéance est due (`__forward_timer_base`) : `clk` avance jusqu'à elle, pas plus
/// loin, et le neuf se range par rapport à elle : dans le niveau 0, pas dans celui que donnerait
/// un `clk` resté en arrière.
#[test]
fn armer_quand_une_echeance_est_due() {
    let mut e = Roue::new(4).unwrap();
    e.armer(1, 5000 * MS, 0).unwrap();
    assert_eq!(e.prochaine(), Some(5120 * MS));
    e.armer(2, 5200 * MS, 5120 * MS).unwrap();
    assert_eq!(e.prendre_echu(5120 * MS), Some(1));
    assert_eq!(e.prochaine(), Some(5204 * MS));
    assert_eq!(e.prendre_echu(5204 * MS), Some(2));
}

/// Réarmé pour la même heure alors qu'il attendait d'être rendu : il revient dans la roue, au tic
/// courant, comme une échéance passée.
#[test]
fn rearmer_un_echu_pour_la_meme_heure() {
    let mut e = Roue::new(4).unwrap();
    e.armer(1, 200 * MS, 0).unwrap();
    e.armer(2, 200 * MS, 0).unwrap();
    let a = e.prendre_echu(204 * MS).unwrap();
    let b = 3 - a;
    assert_eq!(e.prochaine(), Some(0), "l'autre attend d'être rendu");
    e.armer(b, 200 * MS, 204 * MS).unwrap();
    assert_eq!(e.prochaine(), Some(208 * MS));
    assert_eq!(e.prendre_echu(204 * MS), None);
    assert_eq!(e.prendre_echu(208 * MS), Some(b));
}

/// Réarmé au même tic : il reste dans sa case, même si un niveau plus fin conviendrait maintenant ;
/// à un autre tic, il est rangé d'après l'heure qu'il est.
#[test]
fn rearmer_au_meme_tic() {
    let mut e = Roue::new(4).unwrap();
    e.armer(1, 1000 * MS, 0).unwrap();
    assert_eq!(e.prochaine(), Some(1024 * MS));
    e.armer(1, 1000 * MS, 900 * MS).unwrap();
    assert_eq!(e.prochaine(), Some(1024 * MS));
    e.armer(1, 1001 * MS, 900 * MS).unwrap();
    assert_eq!(e.echeance(1), Some(1001 * MS));
    assert_eq!(e.prochaine(), Some(1024 * MS));
    e.armer(1, 1004 * MS, 900 * MS).unwrap();
    assert_eq!(e.prochaine(), Some(1008 * MS));
}

/// Repoussé dans la même case : la chaîne ne bouge pas (le cas fréquent, qui ne coûte rien). Les
/// échus sont rendus du dernier accroché au premier, donc dans l'ordre de la case retournée.
#[test]
fn repousser_dans_la_meme_case_garde_la_chaine() {
    let mut e = Roue::new(4).unwrap();
    e.armer(1, 1000 * MS, 0).unwrap();
    e.armer(2, 1000 * MS, 0).unwrap();
    e.armer(1, 1004 * MS, 0).unwrap();
    assert_eq!(e.echeance(1), Some(1004 * MS));
    assert_eq!(e.prendre_echu(1024 * MS), Some(1));
    assert_eq!(e.prendre_echu(1024 * MS), Some(2));
}

/// Le plus proche désarmé avant le premier tic : la prochaine se recalcule, `clk` à 0.
#[test]
fn desarmer_le_plus_proche_au_depart() {
    let mut e = Roue::new(4).unwrap();
    e.armer(1, 100 * MS, 0).unwrap();
    e.armer(2, 200 * MS, 0).unwrap();
    e.desarmer(1);
    assert_eq!(e.prochaine(), Some(204 * MS));
}
