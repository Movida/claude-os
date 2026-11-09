//! Les règles du générateur de Linux (crypto::alea) : les seuils du
//! réservoir, l'effacement de la clé, le réensemencement et son
//! intervalle, les lots, le petit réservoir des interruptions.

use crypto::alea::{self, Etat, Generateur, Lot, PetitReservoir, Reservoir, Seuil};
use crypto::{blake2s, chacha20};

const APPOINT: [u8; 32] = [7; 32];

fn tirage(g: &mut Generateur, r: &mut Reservoir, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    alea::tirer(g, r, &mut || APPOINT, &mut v);
    v
}

#[test]
fn seuils() {
    let mut r = Reservoir::new();
    let mut g = Generateur::new();
    assert_eq!(g.etat(), Etat::Vide);
    assert_eq!(g.crediter(&mut r, 100, 0, &mut || APPOINT), Seuil::Aucun);
    assert_eq!(g.crediter(&mut r, 28, 0, &mut || APPOINT), Seuil::Debut);
    assert_eq!(g.etat(), Etat::Debut);
    assert_eq!(g.crediter(&mut r, 127, 0, &mut || APPOINT), Seuil::Aucun);
    assert!(!g.pret());
    assert_eq!(g.crediter(&mut r, 1, 0, &mut || APPOINT), Seuil::Pret);
    assert!(g.pret() && r.bits() == 256);
    // Prêt, un crédit ne fait plus rien.
    assert_eq!(g.crediter(&mut r, 1000, 0, &mut || APPOINT), Seuil::Aucun);
    // D'un coup, au-delà des deux seuils : prêt directement.
    let (mut r, mut g) = (Reservoir::new(), Generateur::new());
    assert_eq!(g.crediter(&mut r, 5000, 0, &mut || APPOINT), Seuil::Pret);
    assert_eq!(r.bits(), 256);
}

#[test]
fn chaque_tirage_differe_et_la_cle_change() {
    for credit in [0, 128, 256] {
        let (mut r, mut g) = (Reservoir::new(), Generateur::new());
        r.melanger(b"graine");
        g.crediter(&mut r, credit, 0, &mut || APPOINT);
        let a = tirage(&mut g, &mut r, 32);
        let b = tirage(&mut g, &mut r, 32);
        assert_ne!(a, b, "credit {}", credit);
        assert_ne!(a, [0u8; 32].to_vec());
    }
}

#[test]
fn deterministe_a_meme_graine() {
    let suite = |graine: &[u8]| {
        let (mut r, mut g) = (Reservoir::new(), Generateur::new());
        r.melanger(graine);
        g.crediter(&mut r, 256, 3, &mut || APPOINT);
        (0..5).flat_map(|i| tirage(&mut g, &mut r, 7 + 100 * i)).collect::<Vec<u8>>()
    };
    assert_eq!(suite(b"x"), suite(b"x"));
    assert_ne!(suite(b"x"), suite(b"y"));
}

#[test]
fn le_vide_extrait_a_chaque_demande() {
    // En EMPTY, ce qui est versé entre deux tirages compte aussitôt.
    let mut r1 = Reservoir::new();
    let mut r2 = Reservoir::new();
    let (mut g1, mut g2) = (Generateur::new(), Generateur::new());
    assert_eq!(tirage(&mut g1, &mut r1, 32), tirage(&mut g2, &mut r2, 32));
    r1.melanger(b"a");
    r2.melanger(b"b");
    assert_ne!(tirage(&mut g1, &mut r1, 32), tirage(&mut g2, &mut r2, 32));
}

#[test]
fn reensemencement() {
    assert_eq!(alea::intervalle(0), 1);
    assert_eq!(alea::intervalle(10), 5);
    assert_eq!(alea::intervalle(119), 59);
    assert_eq!(alea::intervalle(120), 60);
    assert_eq!(alea::intervalle(100_000), 60);
    let (mut r, mut g) = (Reservoir::new(), Generateur::new());
    g.crediter(&mut r, 256, 10, &mut || APPOINT);
    let generation = g.generation();
    assert!(!g.a_reensemencer(14) && g.a_reensemencer(15));
    g.reensemencer(&mut r, 15, &mut || APPOINT);
    assert_eq!(g.generation(), generation + 1);
    assert!(!g.a_reensemencer(21) && g.a_reensemencer(22));
}

#[test]
fn tirages_longs() {
    // Plus de 32 octets : les blocs suivants du même état, sans répétition
    // de bloc, et une fin coupée juste.
    let (mut r, mut g) = (Reservoir::new(), Generateur::new());
    g.crediter(&mut r, 256, 0, &mut || APPOINT);
    let v = tirage(&mut g, &mut r, 32 + 64 * 100 + 5);
    let blocs: Vec<&[u8]> = v[32..32 + 6400].chunks(64).collect();
    for i in 0..blocs.len() {
        for j in i + 1..blocs.len() {
            assert_ne!(blocs[i], blocs[j]);
        }
    }
    // La retenue du compteur de 64 bits.
    let mut etat = [0u32; 16];
    etat[12] = u32::MAX;
    let mut o = [0u8; 128];
    alea::continuer(&mut etat, &mut o);
    assert_eq!((etat[12], etat[13]), (1, 1));
}

#[test]
fn lots() {
    let (mut r, mut g) = (Reservoir::new(), Generateur::new());
    let mut lot = Lot::new();
    // Pas prêt : un tirage direct, différent à chaque fois.
    let a: [u8; 4] = lot.prendre(&mut g, &mut r, &mut || APPOINT);
    let b: [u8; 4] = lot.prendre(&mut g, &mut r, &mut || APPOINT);
    assert_ne!(a, b);
    g.crediter(&mut r, 256, 0, &mut || APPOINT);
    let mut vus = std::collections::HashSet::new();
    for _ in 0..1000 {
        let v: [u8; 8] = lot.prendre(&mut g, &mut r, &mut || APPOINT);
        assert!(vus.insert(v));
    }
}

#[test]
fn petit_reservoir() {
    let mut p = PetitReservoir::new();
    assert!(p.verser(0).is_none());
    // 1023 interruptions dans la même seconde : pas encore temps.
    for i in 0..1023u64 {
        assert!(!p.ajouter(i * 977, i, 0), "{}", i);
    }
    let (octets, credit) = p.verser(0).unwrap();
    assert_eq!(credit, 1023 / 64);
    // La 1024e, si : (on recommence le compte.)
    for i in 0..1023u64 {
        p.ajouter(i, i, 0);
    }
    assert!(p.ajouter(5, 5, 0));
    assert_eq!(p.verser(0).unwrap().1, 16);
    assert_ne!(octets, [0; 16]);
    // Une seule interruption, une seconde plus tard : un bit.
    assert!(p.ajouter(1, 2, 1));
    assert_eq!(p.verser(1).unwrap().1, 1);
    // 100 000 interruptions : 128 bits au plus.
    for i in 0..100_000u64 {
        p.ajouter(i, i, 1);
    }
    assert_eq!(p.verser(1).unwrap().1, 128);
}

// --- La relecture de fin d'étape : ce que les tests ci-dessus ne voyaient
// pas (huit mutations y survivaient). Chaque valeur attendue est recalculée
// avec les primitives (vérifiées par les vecteurs officiels), donc sans
// alea.rs.

fn bloc_de(cle: &[u8; 32]) -> [u8; 64] {
    let mut e = [0u32; 16];
    chacha20::initialiser(&mut e, cle);
    let mut b = [0u8; 64];
    chacha20::bloc(&mut e, &mut b);
    b
}

/// HASHPRF(graine, appoint ‖ n) de extract_entropy.
fn prf(graine: &[u8; 32], n: u64) -> [u8; 32] {
    let mut bloc = [0u8; 40];
    bloc[..32].copy_from_slice(&APPOINT);
    bloc[32..].copy_from_slice(&n.to_le_bytes());
    let mut o = [0u8; 32];
    blake2s::blake2s(&mut o, &bloc, graine);
    o
}

#[test]
fn effacement_de_cle_sortie_et_cle_disjointes() {
    let ancienne: [u8; 32] = core::array::from_fn(|i| (i * 5 + 1) as u8);
    let mut cle = ancienne;
    let mut etat = [0u32; 16];
    let mut alea32 = [0u8; 32];
    alea::effacement_de_cle(&mut cle, &mut etat, &mut alea32);
    let b = bloc_de(&ancienne);
    assert_eq!(cle, b[..32], "la nouvelle cle : les 32 premiers octets");
    assert_eq!(alea32, b[32..], "la sortie : les 32 suivants, jamais la cle");
}

#[test]
fn extraction_comme_linux() {
    let mut r = Reservoir::new();
    r.melanger(b"x");
    let mut sortie = [0u8; 40];
    r.extraire(&mut sortie, &mut || APPOINT);
    let mut graine = [0u8; 32];
    blake2s::blake2s(&mut graine, b"x", &[]);
    assert_eq!(sortie[..32], prf(&graine, 1));
    // Le dernier morceau, 8 octets : BLAKE2s d'empreinte de 8 octets (la
    // longueur est dans les paramètres, comme `blake2s(buf, ..., i, ...)`
    // de Linux), pas les 8 premiers d'une empreinte de 32.
    let mut bloc = [0u8; 40];
    bloc[..32].copy_from_slice(&APPOINT);
    bloc[32..].copy_from_slice(&2u64.to_le_bytes());
    let mut huit = [0u8; 8];
    blake2s::blake2s(&mut huit, &bloc, &graine);
    assert_eq!(sortie[32..], huit);
    // Le réservoir suivant : BLAKE2s sous la clé HASHPRF(graine, appoint ‖ 0).
    let cle_suivante = prf(&graine, 0);
    r.melanger(b"y");
    let mut s2 = [0u8; 32];
    r.extraire(&mut s2, &mut || APPOINT);
    let mut graine2 = [0u8; 32];
    blake2s::blake2s(&mut graine2, b"y", &cle_suivante);
    assert_eq!(s2, prf(&graine2, 1));
}

fn pret(graine: &[u8]) -> (Reservoir, Generateur) {
    let (mut r, mut g) = (Reservoir::new(), Generateur::new());
    r.melanger(graine);
    g.crediter(&mut r, 256, 0, &mut || APPOINT);
    (r, g)
}

#[test]
fn le_reensemencement_change_la_cle_du_processeur() {
    let (mut r1, mut g1) = pret(b"commun");
    let (mut r2, mut g2) = pret(b"commun");
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    alea::tirer(&mut g1, &mut r1, &mut || APPOINT, &mut a);
    alea::tirer(&mut g2, &mut r2, &mut || APPOINT, &mut b);
    assert_eq!(a, b);
    r1.melanger(b"neuf 1");
    r2.melanger(b"neuf 2");
    g1.reensemencer(&mut r1, 100, &mut || APPOINT);
    g2.reensemencer(&mut r2, 100, &mut || APPOINT);
    alea::tirer(&mut g1, &mut r1, &mut || APPOINT, &mut a);
    alea::tirer(&mut g2, &mut r2, &mut || APPOINT, &mut b);
    assert_ne!(a, b, "apres un reensemencement, la cle du processeur vient du reservoir");
}

#[test]
fn le_reensemencement_jette_le_lot() {
    let (mut r1, mut g1) = pret(b"commun");
    let (mut r2, mut g2) = pret(b"commun");
    let (mut l1, mut l2) = (Lot::new(), Lot::new());
    let a: [u8; 4] = l1.prendre(&mut g1, &mut r1, &mut || APPOINT);
    let b: [u8; 4] = l2.prendre(&mut g2, &mut r2, &mut || APPOINT);
    assert_eq!(a, b);
    r1.melanger(b"neuf 1");
    r2.melanger(b"neuf 2");
    g1.reensemencer(&mut r1, 100, &mut || APPOINT);
    g2.reensemencer(&mut r2, 100, &mut || APPOINT);
    let a: [u8; 4] = l1.prendre(&mut g1, &mut r1, &mut || APPOINT);
    let b: [u8; 4] = l2.prendre(&mut g2, &mut r2, &mut || APPOINT);
    assert_ne!(a, b, "apres un reensemencement, le lot est refait");
}

#[test]
fn le_petit_reservoir_attend_une_seconde_apres_avoir_verse() {
    let mut p = PetitReservoir::new();
    assert!(p.ajouter(1, 1, 5));
    p.verser(5).unwrap();
    assert!(!p.ajouter(2, 2, 5), "verse a 5 s : pas avant 6 s");
    assert!(p.ajouter(3, 3, 6));
}

/// L'état d'un tirage pour un programme : la clé du processeur d'avant
/// l'effacement rapide y reste après `preparer` ; d'elle on refait la clé
/// suivante, et le tirage suivant. Écrasée par `cle_de_tirage` (comme
/// `get_random_bytes_user`), l'état ne dit plus rien, et ses blocs sont
/// ceux de ChaCha20 sous la clé neuve.
#[test]
fn l_etat_d_un_tirage_ne_dit_rien_des_suivants() {
    let (mut r, mut g) = pret(b"graine secrete");
    let mut x = [0u8; 40];
    alea::tirer(&mut g, &mut r, &mut || APPOINT, &mut x);
    let mut etat = [0u32; 16];
    let mut premiers = [0u8; 32];
    g.preparer(&mut r, &mut || APPOINT, &mut etat, &mut premiers);
    // Sans l'écraser : le bloc 0 de l'état redonne `premiers`, puis sa
    // première moitié est la clé qui fera le tirage suivant.
    let mut e = etat;
    e[12] = 0;
    e[13] = 0;
    let mut b = [0u8; 64];
    chacha20::bloc(&mut e, &mut b);
    assert_eq!(&b[32..], &premiers);
    let suivant_predit = bloc_de(&b[..32].try_into().unwrap());
    let mut suivant = [0u8; 32];
    alea::tirer(&mut g, &mut r, &mut || APPOINT, &mut suivant);
    assert_eq!(&suivant_predit[32..], &suivant);
    // Écrasée : le même calcul ne prédit plus rien.
    let mut etat = [0u32; 16];
    g.preparer(&mut r, &mut || APPOINT, &mut etat, &mut premiers);
    alea::cle_de_tirage(&mut etat, &premiers);
    let mut e = etat;
    e[12] = 0;
    e[13] = 0;
    let mut b = [0u8; 64];
    chacha20::bloc(&mut e, &mut b);
    assert_eq!(b, bloc_de(&premiers));
    let predit = bloc_de(&b[..32].try_into().unwrap());
    alea::tirer(&mut g, &mut r, &mut || APPOINT, &mut suivant);
    assert_ne!(&predit[32..], &suivant);
}
