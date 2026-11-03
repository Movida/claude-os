//! Les vecteurs officiels de ChaCha20 (RFC 8439), BLAKE2s (RFC 7693 et
//! les « KAT » de la référence) et SipHash-2-4 (les 64 vecteurs de la
//! référence), et des flots plus longs. Les valeurs attendues ont été
//! calculées par OpenSSL 3.0 (`openssl enc -chacha20`, `openssl mac
//! SIPHASH`) et par le module `hashlib` de Python (BLAKE2s), deux
//! implémentations indépendantes de la nôtre ; celles qui figurent aussi
//! dans les RFC y sont identiques.

use crypto::blake2s::{self, Blake2s};
use crypto::chacha20;
use crypto::siphash;

/// La clé 00, 01, ..., 1f de la RFC 8439 et des KAT de BLAKE2s.
fn cle_suite() -> [u8; 32] {
    core::array::from_fn(|i| i as u8)
}

/// Un état de ChaCha20 posé comme la RFC 8439 : compteur de 32 bits (mot
/// 12), nonce de 96 bits (mots 13 à 15).
fn etat_rfc(cle: &[u8; 32], compteur: u32, nonce: [u8; 12]) -> [u32; 16] {
    let mut e = [0u32; 16];
    chacha20::initialiser(&mut e, cle);
    e[12] = compteur;
    for (i, o) in nonce.chunks_exact(4).enumerate() {
        e[13 + i] = u32::from_le_bytes([o[0], o[1], o[2], o[3]]);
    }
    e
}

/// Le flot de `blocs` blocs à partir de `etat`.
fn flot(etat: &mut [u32; 16], blocs: usize) -> Vec<u8> {
    let mut v = Vec::new();
    let mut b = [0u8; 64];
    for _ in 0..blocs {
        chacha20::bloc(etat, &mut b);
        v.extend_from_slice(&b);
    }
    v
}

fn hex(o: &[u8]) -> String {
    o.iter().map(|x| format!("{:02x}", x)).collect()
}

#[test]
fn chacha20_bloc_rfc_8439() {
    // §2.3.2 : la clé 00..1f, le compteur 1, le nonce 00:00:00:09:00:00:00:4a:00:00:00:00.
    let mut e = etat_rfc(&cle_suite(), 1, [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
    let mut b = [0u8; 64];
    chacha20::bloc(&mut e, &mut b);
    assert_eq!(hex(&b), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    // Le compteur a avancé d'un, rien d'autre n'a bougé.
    assert_eq!(e[12], 2);
    assert_eq!(e, { let mut f = etat_rfc(&cle_suite(), 1, [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0]); f[12] = 2; f });
}

#[test]
fn chacha20_annexe_a1() {
    // Clé nulle, nonce nul : les compteurs 0 et 1.
    let mut e = etat_rfc(&[0; 32], 0, [0; 12]);
    let v = flot(&mut e, 2);
    assert_eq!(hex(&v[..64]), "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    assert_eq!(hex(&v[64..]), "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f");
}

#[test]
fn chacha20_chiffrement_rfc_8439() {
    // §2.4.2 : le texte chiffré par le flot (compteur 1, nonce
    // 00:00:00:00:00:00:00:4a:00:00:00:00), ou exclusif octet par octet.
    let texte = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let mut e = etat_rfc(&cle_suite(), 1, [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0]);
    let f = flot(&mut e, texte.len().div_ceil(64));
    let chiffre: Vec<u8> = texte.iter().zip(&f).map(|(a, b)| a ^ b).collect();
    assert_eq!(hex(&chiffre), "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d");
}

#[test]
fn chacha20_flot_long() {
    // 4096 blocs (256 Kio) d'une clé quelconque, à la façon de Linux
    // (compteur de 64 bits et nonce nuls) : le dernier bloc, et une
    // empreinte de tout le flot.
    let cle: [u8; 32] = core::array::from_fn(|i| (i * 3) as u8);
    let mut e = [0u32; 16];
    chacha20::initialiser(&mut e, &cle);
    let f = flot(&mut e, 4096);
    assert_eq!(hex(&f[f.len() - 64..]), "7f69c47c100c1e972bceee1afc6bdde38bc4e88c33fa06d2e81c58269df4b5381db111bfed52c989b8167e4d94405a94ead883d3f07396371548409ce2a02488");
    let mut h = [0u8; 32];
    blake2s::blake2s(&mut h, &f, &[]);
    assert_eq!(hex(&h), "acd72bba8e455c8b617659f566d386a4b7bbe9f516eef5d0084b5caa07fe0685");
    assert_eq!((e[12], e[13]), (4096, 0));
}

#[test]
fn blake2s_rfc_7693() {
    let mut h = [0u8; 32];
    blake2s::blake2s(&mut h, b"abc", &[]);
    assert_eq!(hex(&h), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    blake2s::blake2s(&mut h, b"", &[]);
    assert_eq!(hex(&h), "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
}

#[test]
fn blake2s_kat_avec_cle() {
    // Les vecteurs de la référence : la clé 00..1f, les messages 00..n-1
    // pour n de 0 à 255 ; quatre en entier, puis une empreinte des 256
    // empreintes mises bout à bout (comme les tests de Linux, qui les
    // vérifient toutes).
    let cle = cle_suite();
    let message: Vec<u8> = (0..=255u8).collect();
    let mut toutes = Vec::new();
    for n in 0..256 {
        let mut h = [0u8; 32];
        blake2s::blake2s(&mut h, &message[..n], &cle);
        match n {
            0 => assert_eq!(hex(&h), "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"),
            1 => assert_eq!(hex(&h), "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"),
            64 => assert_eq!(hex(&h), "8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"),
            255 => assert_eq!(hex(&h), "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"),
            _ => {}
        }
        toutes.extend_from_slice(&h);
    }
    let mut h = [0u8; 32];
    blake2s::blake2s(&mut h, &toutes, &[]);
    assert_eq!(hex(&h), "2582f7b18a91f66ef22aa9455384ada69b2590306a6470ee8588df75ee982f02");
}

#[test]
fn blake2s_courte_et_longue() {
    // Une empreinte de 16 octets sous une clé de 5 : les paramètres du
    // premier mot de l'état.
    let mut h = [0u8; 16];
    blake2s::blake2s(&mut h, b"abc", b"clefs");
    assert_eq!(hex(&h), "0b0e0b5c280cbe0a25641dac704af8b3");
    // 1 Mio, versé d'un coup puis en morceaux de toutes les tailles
    // (le dernier bloc plein gardé jusqu'à la fin : l'en-tête de
    // blake2s.rs) : la même empreinte.
    let gros: Vec<u8> = (0..1 << 20).map(|i: usize| (i * 7 % 251) as u8).collect();
    let mut d = [0u8; 32];
    blake2s::blake2s(&mut d, &gros, &[]);
    assert_eq!(hex(&d), "74517bb44ae0095ee2553ad801852f4fe63e6ab54103633342fe05c325929ca9");
    for pas in [1, 2, 63, 64, 65, 127, 128, 129, 4096, 70000] {
        let mut b = Blake2s::new(32, &[]);
        for m in gros.chunks(pas) {
            b.update(m);
        }
        let mut e = [0u8; 32];
        b.finale(&mut e);
        assert_eq!(e, d, "en morceaux de {}", pas);
    }
    // Un message vide versé plusieurs fois ne change rien.
    let mut b = Blake2s::new(32, &[]);
    b.update(&[]);
    b.update(b"abc");
    b.update(&[]);
    let mut e = [0u8; 32];
    b.finale(&mut e);
    assert_eq!(hex(&e), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
}

/// Les 64 vecteurs de la référence de SipHash-2-4 : la clé 00..0f, les
/// messages 00..n-1 pour n de 0 à 63.
const SIPHASH: [u64; 64] = [
    0x726fdb47dd0e0e31, 0x74f839c593dc67fd, 0x0d6c8009d9a94f5a, 0x85676696d7fb7e2d,
    0xcf2794e0277187b7, 0x18765564cd99a68d, 0xcbc9466e58fee3ce, 0xab0200f58b01d137,
    0x93f5f5799a932462, 0x9e0082df0ba9e4b0, 0x7a5dbbc594ddb9f3, 0xf4b32f46226bada7,
    0x751e8fbc860ee5fb, 0x14ea5627c0843d90, 0xf723ca908e7af2ee, 0xa129ca6149be45e5,
    0x3f2acc7f57c29bdb, 0x699ae9f52cbe4794, 0x4bc1b3f0968dd39c, 0xbb6dc91da77961bd,
    0xbed65cf21aa2ee98, 0xd0f2cbb02e3b67c7, 0x93536795e3a33e88, 0xa80c038ccd5ccec8,
    0xb8ad50c6f649af94, 0xbce192de8a85b8ea, 0x17d835b85bbb15f3, 0x2f2e6163076bcfad,
    0xde4daaaca71dc9a5, 0xa6a2506687956571, 0xad87a3535c49ef28, 0x32d892fad841c342,
    0x7127512f72f27cce, 0xa7f32346f95978e3, 0x12e0b01abb051238, 0x15e034d40fa197ae,
    0x314dffbe0815a3b4, 0x027990f029623981, 0xcadcd4e59ef40c4d, 0x9abfd8766a33735c,
    0x0e3ea96b5304a7d0, 0xad0c42d6fc585992, 0x187306c89bc215a9, 0xd4a60abcf3792b95,
    0xf935451de4f21df2, 0xa9538f0419755787, 0xdb9acddff56ca510, 0xd06c98cd5c0975eb,
    0xe612a3cb9ecba951, 0xc766e62cfcadaf96, 0xee64435a9752fe72, 0xa192d576b245165a,
    0x0a8787bf8ecb74b2, 0x81b3e73d20b49b6f, 0x7fa8220ba3b2ecea, 0x245731c13ca42499,
    0xb78dbfaf3a8d83bd, 0xea1ad565322a1a0b, 0x60e61c23a3795013, 0x6606d7e446282b93,
    0x6ca4ecb15c5f91e1, 0x9f626da15c9625f3, 0xe51b38608ef25f57, 0x958a324ceb064572,
];

#[test]
fn siphash_reference() {
    let k = siphash::cle(&core::array::from_fn(|i| i as u8));
    let message: Vec<u8> = (0..64u8).collect();
    for (n, attendu) in SIPHASH.iter().enumerate() {
        assert_eq!(siphash::siphash(&k, &message[..n]), *attendu, "{} octets", n);
    }
    // L'exemple de l'article (15 octets) : 0xa129ca6149be45e5.
    assert_eq!(siphash::siphash(&k, &message[..15]), 0xa129_ca61_49be_45e5);
}

#[test]
fn siphash_mots_de_32_bits() {
    // Les formes de Linux à 3 et 4 mots : le hachage de leurs octets.
    let k = siphash::cle(&core::array::from_fn(|i| i as u8));
    let o: Vec<u8> = (0..16u8).collect();
    let mot = |i: usize| u32::from_le_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
    assert_eq!(siphash::siphash_2u32(mot(0), mot(4), &k), SIPHASH[8]);
    assert_eq!(siphash::siphash_3u32(mot(0), mot(4), mot(8), &k), SIPHASH[12]);
    assert_eq!(siphash::siphash_4u32(mot(0), mot(4), mot(8), mot(12), &k), SIPHASH[16]);
}

#[test]
fn verification_du_noyau() {
    assert!(crypto::verifier());
}

#[test]
fn effacer() {
    let mut o = [0xa5u8; 37];
    crypto::effacer(&mut o);
    assert_eq!(o, [0; 37]);
    let mut m = [0xdead_beefu32; 16];
    crypto::effacer_mots(&mut m);
    assert_eq!(m, [0; 16]);
}
