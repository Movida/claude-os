//! La limite des erreurs ICMP par machine (inet::pairs) : le seau à jetons
//! d'`inet_peer_xrlim_allow`, avec les réglages de Linux (une seconde,
//! six d'un coup), et la table de taille fixe.

use inet::pairs::{DELAI, ENTREES, Pairs, RAFALE};

const A: [u8; 4] = [10, 0, 2, 2];
const B: [u8; 4] = [10, 0, 2, 3];
const MS: u64 = 1_000_000;
const S: u64 = 1000 * MS;

/// Combien d'erreurs passent pour `a` à l'instant `t`, sur `n` demandées.
fn passent(x: &mut Pairs, a: [u8; 4], t: u64, n: usize) -> usize {
    (0..n).filter(|_| x.permettre(a, t)).count()
}

/// La machine (le numéro `k`) d'un réseau à part.
fn machine(k: usize) -> [u8; 4] {
    [192, 168, (k >> 8) as u8, k as u8]
}

/// Une machine nouvelle : six d'un coup, puis plus rien dans la même
/// seconde ; une autre machine a son propre seau.
#[test]
fn six_d_un_coup() {
    assert_eq!((DELAI, RAFALE), (1000, 6));
    let mut x = Pairs::new();
    assert_eq!(passent(&mut x, A, 5 * S, 20), 6);
    assert_eq!(passent(&mut x, A, 5 * S + 999 * MS, 20), 0);
    assert_eq!(passent(&mut x, B, 5 * S, 20), 6);
}

/// Puis une par seconde : le jeton se gagne tic par tic, et un tic entamé
/// ne compte pas (les jiffies).
#[test]
fn puis_une_par_seconde() {
    let mut x = Pairs::new();
    assert_eq!(passent(&mut x, A, 0, 6), 6);
    assert!(!x.permettre(A, 999 * MS + MS - 1));
    assert!(x.permettre(A, S));
    assert!(!x.permettre(A, S));
    // Trois secondes et demie : trois, et la demie reste acquise.
    assert_eq!(passent(&mut x, A, 4 * S + 500 * MS, 10), 3);
    assert_eq!(passent(&mut x, A, 5 * S, 10), 1);
}

/// Les jetons ne dépassent jamais six délais : une heure de silence ne
/// donne pas plus de six.
#[test]
fn le_seau_plafonne() {
    let mut x = Pairs::new();
    assert_eq!(passent(&mut x, A, 0, 6), 6);
    assert_eq!(passent(&mut x, A, 3600 * S, 20), 6);
    // Une demande refusée ne coûte rien : la seconde suivante en donne une.
    assert_eq!(passent(&mut x, A, 3600 * S + 10 * MS, 50), 0);
    assert_eq!(passent(&mut x, A, 3601 * S, 50), 1);
}

/// Le temps qui recule (deux processeurs qui lisent l'horloge l'un après
/// l'autre) ne donne rien et ne casse rien.
#[test]
fn le_temps_qui_recule() {
    let mut x = Pairs::new();
    assert_eq!(passent(&mut x, A, 10 * S, 6), 6);
    assert_eq!(passent(&mut x, A, 9 * S, 6), 0);
    assert_eq!(passent(&mut x, A, 11 * S, 6), 1);
}

/// La table pleine de machines au seau rempli : une nouvelle prend la place
/// de l'une d'elles, et chacune, redemandée, a ce qu'elle aurait eu si on
/// l'avait gardée : six.
#[test]
fn oublier_un_seau_plein_ne_change_rien() {
    let mut x = Pairs::new();
    for k in 0..ENTREES {
        assert_eq!(passent(&mut x, machine(k), 0, 6), 6);
    }
    assert_eq!(x.nombre(), ENTREES);
    let t = RAFALE * DELAI * MS;
    assert_eq!(passent(&mut x, A, t, 6), 6);
    assert_eq!(x.nombre(), ENTREES);
    for k in 0..ENTREES {
        assert_eq!(passent(&mut x, machine(k), t, 7), 6, "machine {k}");
    }
}

/// La table pleine de machines sollicitées dans les six dernières secondes :
/// la plus anciennement sollicitée est oubliée (elle retrouve six), les
/// autres gardent leur compte (une seule après une seconde).
#[test]
fn la_plus_ancienne_cede_sa_place() {
    let mut x = Pairs::new();
    for k in 0..ENTREES {
        assert_eq!(passent(&mut x, machine(k), 0, 6), 6);
    }
    // Toutes sollicitées de nouveau à 1 s, sauf la 7 : la plus ancienne.
    for k in (0..ENTREES).filter(|&k| k != 7) {
        assert_eq!(passent(&mut x, machine(k), S, 1), 1);
    }
    assert_eq!(passent(&mut x, A, 2 * S, 6), 6);
    assert_eq!(x.nombre(), ENTREES);
    // Les autres : un jeton gagné en une seconde.
    assert_eq!(passent(&mut x, machine(3), 2 * S, 6), 1);
    // La 7, oubliée : un seau neuf (gardée, elle n'en aurait eu que deux).
    assert_eq!(passent(&mut x, machine(7), 2 * S, 6), 6);
}
