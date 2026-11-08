//! Le ramasse-miettes des sockets en vol (inet::en_vol) : ce qui est mort, sur des graphes faits à
//! la main ; `linux/unix.c` regarde les mêmes formes, vraies, sur Linux et dans notre noyau.

use inet::en_vol::{Arete, mortes};
use std::collections::HashMap;

/// `(envolee, receveuse)` : les sockets sont leurs propres fichiers.
fn graphe(liens: &[(u64, u64)]) -> Vec<Arete> {
    liens.iter().enumerate().map(|(k, &(envolee, receveuse))| Arete { message: k as u64, envolee, fichier: envolee as u32, receveuse, ecoute: None }).collect()
}

/// Ce qui est mort, trié, sachant qu'une socket de `tenues` a un descripteur en plus de
/// ses exemplaires en vol.
fn ramasser(aretes: &[Arete], tenues: &[u64]) -> Vec<u64> {
    let mut comptes: HashMap<u32, u32> = HashMap::new();
    for a in aretes {
        *comptes.entry(a.fichier).or_default() += 1;
    }
    for t in tenues {
        *comptes.entry(*t as u32).or_default() += 1;
    }
    let mut m = mortes(aretes, |f| comptes.get(&f).copied().unwrap_or(0)).unwrap();
    m.sort();
    m
}

#[test]
fn une_socket_dans_sa_propre_file() {
    let g = graphe(&[(1, 1)]);
    assert_eq!(ramasser(&g, &[]), [1]);
    assert_eq!(ramasser(&g, &[1]), [0u64; 0]);
}

#[test]
fn sans_cycle() {
    // 1 dans la file de 2, qui n'est pas en vol : la fermeture de 2 suffira.
    assert_eq!(ramasser(&graphe(&[(1, 2)]), &[]), [0u64; 0]);
    // 1 dans la file de 2, 2 dans celle de 3, 3 pas en vol.
    assert_eq!(ramasser(&graphe(&[(1, 2), (2, 3)]), &[]), [0u64; 0]);
}

#[test]
fn deux_qui_se_tiennent() {
    let g = graphe(&[(1, 2), (2, 1)]);
    assert_eq!(ramasser(&g, &[]), [1, 2]);
    // Un descripteur sur l'une : on peut la lire, et donc sortir l'autre.
    assert_eq!(ramasser(&g, &[1]), [0u64; 0]);
    assert_eq!(ramasser(&g, &[2]), [0u64; 0]);
    // Plusieurs exemplaires de la même : ils comptent tous.
    let g = graphe(&[(1, 2), (1, 2), (2, 1)]);
    assert_eq!(ramasser(&g, &[]), [1, 2]);
}

/// Une composante qui a un exemplaire dans une file extérieure vit encore : cette file peut être lue.
#[test]
fn une_file_exterieure_la_tient() {
    assert_eq!(ramasser(&graphe(&[(1, 2), (2, 1), (1, 3)]), &[]), [0u64; 0]);
    // Un exemplaire de 3 dans la file morte : 3 n'est pas un cycle, il suivra ; le cycle part.
    assert_eq!(ramasser(&graphe(&[(1, 2), (2, 1), (3, 1)]), &[]), [1, 2]);
}

/// Deux cycles, l'un dans la file de l'autre : celui qui est tenu attend le tour d'après.
#[test]
fn deux_cycles_a_la_suite() {
    let g = graphe(&[(1, 2), (2, 1), (3, 4), (4, 3), (3, 1)]);
    assert_eq!(ramasser(&g, &[]), [1, 2]);
    // Le premier ramassé : ses messages partent, et le second est mort à son tour.
    let g = graphe(&[(3, 4), (4, 3)]);
    assert_eq!(ramasser(&g, &[]), [3, 4]);
}

/// La fille pas encore acceptée : sa file compte comme celle de son écoute.
#[test]
fn une_fille_et_son_ecoute() {
    let g = [Arete { message: 0, envolee: 1, fichier: 1, receveuse: 2, ecoute: Some(1) }];
    assert_eq!(ramasser(&g, &[]), [1]);
    assert_eq!(ramasser(&g, &[1]), [0u64; 0]);
    // Acceptée : elle a son fichier, et qui peut la lire.
    let g = [Arete { message: 0, envolee: 1, fichier: 1, receveuse: 2, ecoute: None }];
    assert_eq!(ramasser(&g, &[]), [0u64; 0]);
}

/// La forme où le `scc_index` de Linux dit vivante une composante morte (voir en_vol.rs).
#[test]
fn le_lowlink_ne_suffit_pas() {
    assert_eq!(ramasser(&graphe(&[(1, 2), (2, 3), (3, 2), (2, 1)]), &[]), [1, 2, 3]);
}

/// Sans récursion : une longue chaîne ne doit pas compter sur la pile. (Une pile de 16 Kio, chez
/// le noyau ; sur l'hôte, un parcours récursif de 200 000 appels déborderait déjà celle du test.)
#[test]
fn une_longue_chaine() {
    let n = 200_000u64;
    let mut liens: Vec<(u64, u64)> = (0..n).map(|k| (k, (k + 1) % n)).collect();
    assert_eq!(ramasser(&graphe(&liens), &[]).len(), n as usize);
    assert_eq!(ramasser(&graphe(&liens), &[7]).len(), 0);
    liens.pop();
    assert_eq!(ramasser(&graphe(&liens), &[]).len(), 0);
}
