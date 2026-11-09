//! ChaCha20 (Bernstein, 2008 ; la RFC 8439 le décrit), la fonction de bloc
//! seule : d'un état de 16 mots de 32 bits (4 constantes, la clé de
//! 256 bits, un compteur, un nonce), 64 octets d'apparence aléatoire.
//! C'est tout ce dont le générateur de Linux a besoin
//! (`chacha20_block`, lib/crypto/chacha-block-generic.c) : il ne chiffre
//! rien, il tire des blocs.
//!
//! La disposition de l'état est celle de Linux, pas celle de la RFC : le
//! compteur sur 64 bits (mots 12 et 13) et le nonce sur 64 bits (14 et 15),
//! la variante d'origine de Bernstein ; la RFC 8439 prend un compteur de 32
//! bits et un nonce de 96, pour TLS. La fonction de bloc est la même : seul
//! le sens donné aux quatre derniers mots change, et les vecteurs de la RFC
//! se rejouent en posant les mots 12 à 15 à la main.
//!
//! Pourquoi ChaCha20 plutôt qu'AES en mode compteur (l'autre générateur
//! courant, celui de Windows) : rien que des additions, des rotations et
//! des ou exclusifs sur 32 bits, aussi rapides partout, sans table
//! (donc sans fuite par le cache) et sans instruction spéciale du
//! processeur ; c'est le choix de Linux depuis 4.8, d'OpenBSD (arc4random)
//! et de TLS 1.3.

/// Les quatre constantes, « expand 32-byte k » en ASCII (petit-boutiste).
pub const CONSTANTES: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
/// La taille d'une clé et d'un bloc, en octets.
pub const CLE: usize = 32;
pub const BLOC: usize = 64;

/// Prépare `etat` : les constantes, la clé, le compteur et le nonce à zéro
/// (le `chacha_init_consts` de Linux, puis la clé).
pub fn initialiser(etat: &mut [u32; 16], cle: &[u8; CLE]) {
    etat[..4].copy_from_slice(&CONSTANTES);
    for (mot, octets) in etat[4..12].iter_mut().zip(cle.chunks_exact(4)) {
        *mot = u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]);
    }
    etat[12..].fill(0);
}

/// Un « quart de tour » sur les mots a, b, c, d.
fn quart(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Écrit dans `sortie` le bloc de `etat` : vingt tours (dix doubles tours :
/// les colonnes, puis les diagonales), puis l'état d'origine ajouté mot à
/// mot (sans quoi la permutation se défairait), en petit-boutiste ; puis le
/// compteur (mot 12) avance d'un, comme `chacha20_block`. Comme lui, la
/// retenue vers le mot 13 est à l'appelant (le générateur la fait) : un
/// bloc ne sait pas s'il sert un compteur de 32 ou de 64 bits.
pub fn bloc(etat: &mut [u32; 16], sortie: &mut [u8; BLOC]) {
    let mut x = *etat;
    for _ in 0..10 {
        quart(&mut x, 0, 4, 8, 12);
        quart(&mut x, 1, 5, 9, 13);
        quart(&mut x, 2, 6, 10, 14);
        quart(&mut x, 3, 7, 11, 15);
        quart(&mut x, 0, 5, 10, 15);
        quart(&mut x, 1, 6, 11, 12);
        quart(&mut x, 2, 7, 8, 13);
        quart(&mut x, 3, 4, 9, 14);
    }
    for ((o, mot), depart) in sortie.chunks_exact_mut(4).zip(x).zip(etat.iter()) {
        o.copy_from_slice(&mot.wrapping_add(*depart).to_le_bytes());
    }
    etat[12] = etat[12].wrapping_add(1);
}
