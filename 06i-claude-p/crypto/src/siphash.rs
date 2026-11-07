//! SipHash-2-4 (Aumasson et Bernstein, 2012) : une fonction de hachage À
//! CLÉ, rapide sur des messages courts, et sûre comme fonction
//! pseudo-aléatoire : sans la clé, sa sortie ne se prédit pas, même en
//! choisissant les messages. C'est ce qu'il faut pour cacher une règle
//! derrière un secret : le numéro de séquence initial d'une connexion TCP
//! (RFC 6528 : `secure_tcp_seq`), le point de départ de la recherche d'un
//! port éphémère (`secure_ipv4_port_ephemeral`), le compteur d'identifiants
//! IP d'une destination (`ip_idents`) ; sans clé, un tiers pourrait les
//! calculer, et usurper une connexion ou compter le trafic. Linux s'en sert
//! pour tout cela depuis 4.11 (lib/siphash.c), à la place de MD5.
//!
//! « 2-4 » : deux tours par mot du message, quatre à la fin. La clé fait
//! 128 bits, la sortie 64. L'état : quatre mots de 64 bits, partis de la
//! clé et de la constante « somepseudorandomlygeneratedbytes ».

/// Une clé (le `siphash_key_t` de Linux : deux mots de 64 bits).
pub type Cle = [u64; 2];

/// La clé faite de 16 octets (petit-boutiste, comme la référence).
pub fn cle(octets: &[u8; 16]) -> Cle {
    let mut k = [0u64; 2];
    for (mot, o) in k.iter_mut().zip(octets.chunks_exact(8)) {
        *mot = u64::from_le_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]);
    }
    k
}

/// Un tour (SIPROUND) : la permutation sur les quatre mots. Le petit
/// réservoir des interruptions de Linux l'emploie seule (`fast_mix`,
/// SIPHASH_PERMUTATION).
pub fn tour(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-2-4 de `message` sous la clé `k`.
pub fn siphash(k: &Cle, message: &[u8]) -> u64 {
    let mut v = [
        k[0] ^ 0x736f_6d65_7073_6575,
        k[1] ^ 0x646f_7261_6e64_6f6d,
        k[0] ^ 0x6c79_6765_6e65_7261,
        k[1] ^ 0x7465_6462_7974_6573,
    ];
    let mut morceaux = message.chunks_exact(8);
    for o in &mut morceaux {
        let m = u64::from_le_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]);
        v[3] ^= m;
        tour(&mut v);
        tour(&mut v);
        v[0] ^= m;
    }
    // Le dernier mot : les octets qui restent, et la longueur (modulo 256)
    // dans l'octet de poids fort.
    let mut dernier = [0u8; 8];
    let reste = morceaux.remainder();
    dernier[..reste.len()].copy_from_slice(reste);
    dernier[7] = message.len() as u8;
    let m = u64::from_le_bytes(dernier);
    v[3] ^= m;
    tour(&mut v);
    tour(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        tour(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// SipHash de deux mots de 32 bits (`siphash_2u32` : l'horodatage de TCP,
/// `secure_tcp_ts_off`).
pub fn siphash_2u32(a: u32, b: u32, k: &Cle) -> u64 {
    let mut o = [0u8; 8];
    o[..4].copy_from_slice(&a.to_le_bytes());
    o[4..].copy_from_slice(&b.to_le_bytes());
    siphash(k, &o)
}

/// SipHash de trois et de quatre mots de 32 bits, mis bout à bout en
/// petit-boutiste (les `siphash_3u32` et `siphash_4u32` de Linux, qui
/// donnent la même valeur que le hachage de ces 12 ou 16 octets).
pub fn siphash_3u32(a: u32, b: u32, c: u32, k: &Cle) -> u64 {
    let mut o = [0u8; 12];
    o[..4].copy_from_slice(&a.to_le_bytes());
    o[4..8].copy_from_slice(&b.to_le_bytes());
    o[8..].copy_from_slice(&c.to_le_bytes());
    siphash(k, &o)
}

pub fn siphash_4u32(a: u32, b: u32, c: u32, d: u32, k: &Cle) -> u64 {
    let mut o = [0u8; 16];
    o[..4].copy_from_slice(&a.to_le_bytes());
    o[4..8].copy_from_slice(&b.to_le_bytes());
    o[8..12].copy_from_slice(&c.to_le_bytes());
    o[12..].copy_from_slice(&d.to_le_bytes());
    siphash(k, &o)
}
