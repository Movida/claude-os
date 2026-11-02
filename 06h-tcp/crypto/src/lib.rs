//! Les fonctions cryptographiques du noyau (6h), celles de Linux pour les
//! mêmes usages :
//!   - ChaCha20 (chacha20.rs), le générateur de nombres aléatoires de
//!     Linux depuis 4.8 (drivers/char/random.c) ;
//!   - BLAKE2s (blake2s.rs), qui mêle l'aléa recueilli dans le réservoir
//!     de ce générateur depuis Linux 5.17 ;
//!   - SipHash (siphash.rs), le hachage à clé des numéros de séquence de
//!     TCP, des ports éphémères et des identifiants IP (net/core/
//!     secure_seq.c, net/ipv4/route.c), et le brassage rapide de l'aléa des
//!     interruptions.
//!
//! Pourquoi une bibliothèque à part : ce ne sont que des calculs sur des
//! octets, qui ne touchent aucun matériel ; ici, on les vérifie sur l'hôte
//! avec les vecteurs des RFC et de leurs auteurs, ce que le noyau seul ne
//! permettrait pas. Option écartée : une crate de la communauté (`chacha20`,
//! `blake2`), contraire au projet (pas de crate qui fait le travail), pour
//! trois cents lignes en tout.
//!
//! Le noyau rejoue aussi quelques vecteurs au démarrage (`verifier`),
//! comme les tests de Linux (`blake2s_selftest`, CONFIG_CRYPTO_SELFTESTS) :
//! ce que vérifie l'hôte est le code compilé pour lui, pas celui du noyau
//! (une autre cible, d'autres options).
//!
//! EFFACER LES SECRETS : une clé, un état de ChaCha20, ne doivent pas
//! traîner en mémoire une fois servis (une fuite ultérieure révélerait ce
//! qui a été tiré : la « confidentialité persistante » que cherche
//! random.c). Les fonctions d'ici prennent donc leurs états par référence
//! (`&mut`), jamais par valeur, pour ne pas en semer de copies, et les
//! copies de travail sont remises à zéro par `effacer`, l'équivalent du
//! `memzero_explicit` de Linux. Il reste ce que le compilateur copie de
//! lui-même (registres, variables de travail sur la pile, comme l'état
//! permuté de `chacha20::bloc`) : Linux a la même limite.

#![no_std]
#![forbid(unsafe_code)]

pub mod blake2s;
pub mod chacha20;
pub mod siphash;

/// Remet `o` à zéro, d'une façon que le compilateur ne retire pas en
/// voyant que personne ne relit ces octets. Linux fait `memset`, puis
/// `barrier_data` (une instruction vide qui dit au compilateur que la
/// mémoire est lue : une promesse du langage). Ici `black_box`, sans
/// `unsafe` : sa documentation ne promet RIEN (« best-effort », « no
/// guarantees for cryptographic or security purposes ») ; de fait, rustc
/// le compile comme `barrier_data` et garde l'effacement (vérifié à
/// l'assembleur avec la chaîne figée, 1.99.1 : sans lui, l'effacement
/// disparaît). La seule garantie serait une écriture volatile
/// (`write_volatile`) ou une instruction en assembleur, qui demandent
/// `unsafe`, que cette bibliothèque n'a pas ; aucune ne couvre les copies
/// que le compilateur fait de lui-même. À revérifier à chaque changement
/// de chaîne.
pub fn effacer(o: &mut [u8]) {
    o.fill(0);
    core::hint::black_box(o);
}

/// La même chose pour des mots de 32 bits (un état de ChaCha20).
pub fn effacer_mots(o: &mut [u32]) {
    o.fill(0);
    core::hint::black_box(o);
}

/// Rejoue un vecteur officiel de chaque fonction (le bloc de la RFC 8439,
/// « abc » de la RFC 7693, le premier vecteur de SipHash) : vrai si les
/// trois sont justes. Pour le noyau, au démarrage.
pub fn verifier() -> bool {
    // RFC 8439, §2.3.2 : la clé 00..1f, le compteur 1, le nonce
    // 00:00:00:09:00:00:00:4a:00:00:00:00.
    let mut cle = [0u8; chacha20::CLE];
    for (i, o) in cle.iter_mut().enumerate() {
        *o = i as u8;
    }
    let mut etat = [0u32; 16];
    chacha20::initialiser(&mut etat, &cle);
    etat[12] = 1;
    etat[13] = 0x0900_0000;
    etat[14] = 0x4a00_0000;
    let mut bloc = [0u8; chacha20::BLOC];
    chacha20::bloc(&mut etat, &mut bloc);
    let chacha = bloc[..8] == [0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15]
        && bloc[56..] == [0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e]
        && etat[12] == 2;
    // RFC 7693, annexe B : BLAKE2s-256 de « abc ».
    let mut h = blake2s::Blake2s::new(32, &[]);
    h.update(b"abc");
    let mut empreinte = [0u8; 32];
    h.finale(&mut empreinte);
    let blake = empreinte[..4] == [0x50, 0x8c, 0x5e, 0x8c] && empreinte[28..] == [0x86, 0x67, 0x59, 0x82];
    // SipHash-2-4, la clé 00..0f, le message vide : 0x726fdb47dd0e0e31
    // (le premier vecteur de la référence).
    let sip = siphash::siphash(&siphash::cle(&core::array::from_fn(|i| i as u8)), &[]) == 0x726f_db47_dd0e_0e31;
    chacha && blake && sip
}
