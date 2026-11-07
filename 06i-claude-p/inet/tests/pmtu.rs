//! La MTU du chemin (inet::pmtu) : les valeurs mesurées sur l'hôte, pour une exception
//! posée par ICMP (`linux/pmtu.c`).

use inet::pmtu::{ENTREES, EXPIRATION, Exceptions, MTU_MIN};

const A: [u8; 4] = [10, 0, 2, 2];
const B: [u8; 4] = [10, 0, 2, 3];
const ROUTE: u32 = 1500;

#[test]
fn une_mtu_retenue_par_destination() {
    let mut x = Exceptions::new();
    assert_eq!(x.mtu(A, ROUTE, 0), ROUTE);
    x.apprendre(A, 1200, ROUTE, 0);
    assert_eq!((x.mtu(A, ROUTE, 0), x.mtu(B, ROUTE, 0)), (1200, ROUTE));
    assert!(!x.verrouillee(A, 0));
    // Plus bas : oui ; plus haut : rien.
    x.apprendre(A, 1000, ROUTE, 1);
    assert_eq!(x.mtu(A, ROUTE, 1), 1000);
    x.apprendre(A, 1100, ROUTE, 2);
    assert_eq!(x.mtu(A, ROUTE, 2), 1000);
    // Plus que la route : rien de neuf.
    x.apprendre(B, 9000, ROUTE, 0);
    assert_eq!(x.mtu(B, ROUTE, 0), ROUTE);
}

/// 10 min, et la MTU de la carte revient.
#[test]
fn elle_expire() {
    let mut x = Exceptions::new();
    x.apprendre(A, 1200, ROUTE, 5);
    assert_eq!(x.mtu(A, ROUTE, 5 + EXPIRATION - 1), 1200);
    assert_eq!(x.mtu(A, ROUTE, 5 + EXPIRATION), ROUTE);
    // Une redite ne la repousse que passé la moitié du délai.
    x.apprendre(A, 1200, ROUTE, 5 + EXPIRATION);
    let debut = 5 + EXPIRATION;
    x.apprendre(A, 1200, ROUTE, debut + EXPIRATION / 2 - 1);
    assert_eq!(x.mtu(A, ROUTE, debut + EXPIRATION), ROUTE);
    x.apprendre(A, 1200, ROUTE, debut + EXPIRATION - 1);
    assert_eq!(x.mtu(A, ROUTE, debut + EXPIRATION), 1200);
}

/// Sous 552 : 552, verrouillée (mesuré : FRAG 400 → IP_MTU 552) ; plus rien ne la change.
#[test]
fn le_plancher() {
    let mut x = Exceptions::new();
    x.apprendre(A, 400, ROUTE, 0);
    assert_eq!((x.mtu(A, ROUTE, 0), x.verrouillee(A, 0)), (MTU_MIN, true));
    x.apprendre(A, 300, ROUTE, 1);
    assert_eq!(x.mtu(A, ROUTE, 1), MTU_MIN);
    x.apprendre(A, 500, ROUTE, 1);
    assert_eq!(x.mtu(A, ROUTE, 1), MTU_MIN);
    // Une carte plus petite que le plancher le reste.
    x.apprendre(B, 100, 400, 0);
    assert_eq!((x.mtu(B, 400, 0), x.verrouillee(B, 0)), (400, true));
    // Un ICMP sans MTU (un vieux routeur) vaut 0.
    let mut x = Exceptions::new();
    x.apprendre(A, 0, ROUTE, 0);
    assert_eq!(x.mtu(A, ROUTE, 0), MTU_MIN);
    // Expirée, elle cesse d'être verrouillée.
    assert!(!x.verrouillee(A, EXPIRATION));
}

/// La table pleine : celle qui expire le plus tôt cède sa place.
#[test]
fn table_pleine() {
    let mut x = Exceptions::new();
    for i in 0..ENTREES as u8 {
        x.apprendre([10, 0, 0, i], 1000, ROUTE, 100 + i as u64);
    }
    x.apprendre(A, 1000, ROUTE, 1000);
    assert_eq!(x.mtu(A, ROUTE, 1000), 1000);
    assert_eq!(x.mtu([10, 0, 0, 0], ROUTE, 1000), ROUTE, "la plus vieille");
    assert_eq!(x.mtu([10, 0, 0, 1], ROUTE, 1000), 1000);
    x.oublier(A);
    assert_eq!(x.mtu(A, ROUTE, 1000), ROUTE);
}

/// La même MTU redite : rien tant qu'il reste plus de la moitié du délai ; passé ce point, le délai
/// repart (`__ip_rt_update_pmtu`).
#[test]
fn la_meme_mtu_redite() {
    let s = 1_000_000_000u64;
    let mut e = Exceptions::new();
    let d = [10, 0, 0, 1];
    e.apprendre(d, 1000, 1500, 1);
    e.apprendre(d, 1000, 1500, 100 * s);
    assert_eq!(e.mtu(d, 1500, 600 * s), 1000);
    assert_eq!(e.mtu(d, 1500, 600 * s + 1), 1500);
    let mut e = Exceptions::new();
    e.apprendre(d, 1000, 1500, 1);
    e.apprendre(d, 1000, 1500, 300 * s + 1);
    assert_eq!(e.mtu(d, 1500, 900 * s), 1000);
    assert_eq!(e.mtu(d, 1500, 900 * s + 1), 1500);
    // Plus grande que ce qu'on sait : rien.
    e.apprendre(d, 1400, 1500, 300 * s);
    assert_eq!(e.mtu(d, 1500, 300 * s), 1000);
}

/// La table pleine : c'est celle qui expire le plus tôt qui part, où qu'elle soit.
#[test]
fn la_table_pleine_rend_la_plus_vieille() {
    let s = 1_000_000_000u64;
    let mut e = Exceptions::new();
    let ip = |k: u32| [10, 0, (k >> 8) as u8, k as u8];
    // La plus vieille au milieu.
    for k in 0..64u32 {
        let t = if k == 20 { 0 } else { 10 * s + k as u64 };
        e.apprendre(ip(k), 1000, 1500, t);
    }
    e.apprendre(ip(100), 1000, 1500, 20 * s);
    assert_eq!(e.mtu(ip(20), 1500, 20 * s), 1500);
    assert_eq!(e.mtu(ip(21), 1500, 20 * s), 1000);
    assert_eq!(e.mtu(ip(0), 1500, 20 * s), 1000);
    assert_eq!(e.mtu(ip(100), 1500, 20 * s), 1000);
}

/// Tout juste le plancher : une MTU comme une autre, pas verrouillée.
#[test]
fn le_plancher_tout_juste() {
    let mut x = Exceptions::new();
    x.apprendre(A, MTU_MIN, ROUTE, 0);
    assert_eq!(x.mtu(A, ROUTE, 0), MTU_MIN);
    assert!(!x.verrouillee(A, 0));
    x.apprendre(B, MTU_MIN - 1, ROUTE, 0);
    assert_eq!(x.mtu(B, ROUTE, 0), MTU_MIN);
    assert!(x.verrouillee(B, 0));
}
