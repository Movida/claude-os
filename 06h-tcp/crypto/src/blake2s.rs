//! BLAKE2s (Aumasson, Neves, Wilcox-O'Hearn, Winnerlein, 2012 ; RFC 7693) :
//! une fonction de hachage de la famille de SHA-3 finaliste BLAKE, faite
//! pour les processeurs 32 bits (la variante « s »), au plus 32 octets
//! d'empreinte, avec une clé facultative (au plus 32 octets) qui en fait un
//! code d'authentification.
//!
//! Linux s'en sert depuis 5.17 pour le réservoir de son générateur
//! (drivers/char/random.c) : tout l'aléa recueilli y est versé
//! (`blake2s_update`), et l'empreinte en sort la clé de ChaCha20 ; avant,
//! un mélange maison à base de LFSR et de SHA-1, que BLAKE2s a remplacé
//! parce qu'une fonction de hachage éprouvée garantit qu'on ne perd rien
//! de ce qui est versé, et sans hypothèse sur sa forme. Pourquoi BLAKE2s
//! plutôt que SHA-256 : aussi sûr, plus rapide en logiciel pur, et une clé
//! sans construction HMAC.
//!
//! La construction : l'état (8 mots) part du vecteur d'initialisation de
//! SHA-256, modifié par les paramètres (longueur de l'empreinte, de la
//! clé) ; chaque bloc de 64 octets est « compressé » dans l'état (dix tours
//! de la fonction G de ChaCha, sur un état de travail de 16 mots), avec le
//! nombre d'octets déjà vus ; le DERNIER bloc est marqué (un mot à
//! 0xFFFFFFFF), d'où une règle qui surprend : un bloc plein n'est compressé
//! qu'une fois qu'on sait qu'il n'est pas le dernier.

/// La taille d'un bloc, et la plus grande empreinte (et clé), en octets.
pub const BLOC: usize = 64;
pub const EMPREINTE_MAX: usize = 32;

/// Le vecteur d'initialisation (celui de SHA-256 : les premiers bits des
/// racines carrées des huit premiers nombres premiers).
const IV: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
];

/// L'ordre dans lequel chaque tour lit les 16 mots du bloc.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Un hachage en cours (la `blake2s_state` de Linux).
#[derive(Clone)]
pub struct Blake2s {
    h: [u32; 8],
    /// Le nombre d'octets déjà compressés (un compteur de 64 bits).
    t: u64,
    /// Ce qui attend d'être compressé (jusqu'à un bloc plein : voir l'en-tête).
    tampon: [u8; BLOC],
    rempli: usize,
    longueur: usize,
}

impl Blake2s {
    /// Un hachage neuf, d'empreinte de `longueur` octets (1 à 32), avec la
    /// clé `cle` (0 à 32 octets) : elle forme le premier bloc, complété de
    /// zéros. Une longueur ou une clé hors de ces bornes est bornée (le
    /// noyau ne demande que 32, et des clés de 32).
    pub fn new(longueur: usize, cle: &[u8]) -> Blake2s {
        let longueur = longueur.clamp(1, EMPREINTE_MAX);
        let cle = &cle[..cle.len().min(EMPREINTE_MAX)];
        let mut h = IV;
        // Le bloc de paramètres, réduit à son premier mot : longueur de
        // l'empreinte, de la clé, « fanout » 1, profondeur 1 (pas d'arbre).
        h[0] ^= 0x0101_0000 ^ ((cle.len() as u32) << 8) ^ longueur as u32;
        let mut b = Blake2s { h, t: 0, tampon: [0; BLOC], rempli: 0, longueur };
        if !cle.is_empty() {
            b.tampon[..cle.len()].copy_from_slice(cle);
            b.rempli = BLOC;
        }
        b
    }

    /// Compresse le bloc `bloc` dans l'état ; `dernier` : c'est le dernier.
    fn compresser(&mut self, bloc: &[u8; BLOC], dernier: bool) {
        let mut m = [0u32; 16];
        for (mot, o) in m.iter_mut().zip(bloc.chunks_exact(4)) {
            *mot = u32::from_le_bytes([o[0], o[1], o[2], o[3]]);
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if dernier {
            v[14] = !v[14];
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Verse `octets` dans le hachage (le `blake2s_update` de Linux) : le
    /// tampon complété, puis compressé seulement si d'autres octets
    /// suivent ; les blocs pleins compressés directement, sauf le dernier,
    /// gardé.
    pub fn update(&mut self, mut octets: &[u8]) {
        while !octets.is_empty() {
            if self.rempli == BLOC {
                self.t = self.t.wrapping_add(BLOC as u64);
                let bloc = self.tampon;
                self.compresser(&bloc, false);
                self.rempli = 0;
            }
            let n = (BLOC - self.rempli).min(octets.len());
            self.tampon[self.rempli..self.rempli + n].copy_from_slice(&octets[..n]);
            self.rempli += n;
            octets = &octets[n..];
        }
    }

    /// Finit le hachage : le dernier bloc (complété de zéros, marqué),
    /// puis l'empreinte écrite dans `sortie` (ses `longueur` premiers
    /// octets : la sortie doit en avoir au moins autant). Puis l'état est
    /// effacé, comme le fait `blake2s_final` (`memzero_explicit`) : il
    /// contient l'empreinte elle-même, dont le générateur aléatoire de Linux
    /// fait des clés (le réservoir suivant, la clé de base). Le hachage ne
    /// sert plus.
    pub fn finale(&mut self, sortie: &mut [u8]) {
        self.t = self.t.wrapping_add(self.rempli as u64);
        self.tampon[self.rempli..].fill(0);
        let mut bloc = self.tampon;
        self.compresser(&bloc, true);
        let mut empreinte = [0u8; EMPREINTE_MAX];
        for (o, mot) in empreinte.chunks_exact_mut(4).zip(self.h) {
            o.copy_from_slice(&mot.to_le_bytes());
        }
        sortie[..self.longueur].copy_from_slice(&empreinte[..self.longueur]);
        crate::effacer(&mut empreinte);
        crate::effacer(&mut bloc);
        crate::effacer_mots(&mut self.h);
        crate::effacer(&mut self.tampon);
        self.t = 0;
        self.rempli = 0;
    }
}

/// Le hachage d'un trait (le `blake2s` de Linux) : empreinte de
/// `sortie.len()` octets de `octets`, sous la clé `cle`.
pub fn blake2s(sortie: &mut [u8], octets: &[u8], cle: &[u8]) {
    let mut h = Blake2s::new(sortie.len(), cle);
    h.update(octets);
    h.finale(sortie);
}

/// La fonction G : celle du quart de tour de ChaCha, avec deux mots du bloc
/// ajoutés, et des rotations de 16, 12, 8 et 7 bits.
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}
