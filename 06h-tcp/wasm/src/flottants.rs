//! Les nombres flottants de WebAssembly (IEEE 754, simple et double
//! précision), calculés à l'identique sur la machine hôte et dans le noyau.
//!
//! Deux difficultés.
//!
//! 1. `core` n'a ni racine carrée, ni arrondis (floor, ceil, trunc, à
//!    l'entier le plus proche) : ce sont des fonctions de la bibliothèque
//!    mathématique du système (la libm), et nous n'avons pas de système. Et
//!    le noyau est compilé sans SSE, pour ne pas avoir à sauvegarder les
//!    registres flottants à chaque interruption : Rust y calcule + - × ÷ en
//!    logiciel (« soft-float », les fonctions de compiler-builtins). Ces
//!    quatre opérations sont exactes partout (IEEE 754 impose l'arrondi
//!    correct, et le logiciel le respecte comme le processeur). Les autres,
//!    on les écrit nous-mêmes en arithmétique ENTIÈRE sur les bits : le
//!    résultat est exact, et le même octet pour octet sur l'hôte, où on le
//!    compare à la libm (tests en bas du fichier), et dans le noyau.
//!    Options écartées : une crate libm (aucune crate ne fait le travail à
//!    notre place), le jeu d'instructions x87 (fsqrt, frndint : son
//!    arrondi dépend d'un mode à régler, et il faudrait de l'assembleur
//!    hors de toute fonction qui touche le matériel), et SSE dans le noyau
//!    (une sauvegarde de 512 octets par interruption : Linux l'évite aussi).
//!
//! 2. Les NaN (« not a number », le résultat de 0/0 ou de la racine d'un
//!    négatif). IEEE 754 en a des millions : exposant à 1, mantisse non
//!    nulle ; le bit de poids fort de la mantisse distingue les NaN
//!    « silencieux » (à 1) des NaN « signalants ». Quand une opération
//!    produit un NaN, WebAssembly laisse le choix de ses bits : le NaN
//!    canonique (seul le bit silencieux à 1) si les entrées l'étaient,
//!    sinon n'importe quel NaN silencieux. SSE et soft-float ne font pas le
//!    même choix quand deux NaN se rencontrent. Ici, toute opération
//!    arithmétique qui produit un NaN rend le NaN canonique positif : c'est
//!    toujours permis, et le résultat ne dépend plus de la machine (c'est
//!    l'option « canonicalisation des NaN » de wasmtime, utilisée là où
//!    l'exécution doit être reproductible). Les opérations sur les bits
//!    (abs, neg, copysign), elles, ne touchent qu'au signe et gardent la
//!    charge du NaN, comme la spécification l'exige.
//!
//! Les fonctions prennent et rendent les bits (u32, u64), comme la pile de
//! l'interpréteur les garde : passer par un f32 ne changerait rien sur ces
//! machines, mais travailler sur les bits dit clairement ce qui est exact.

/// Engendre les opérations d'un format flottant : `$f` le type Rust, `$u`
/// l'entier de même taille, `$u2` un entier deux fois plus grand (pour la
/// racine carrée), `$mantisse` le nombre de bits de la mantisse (sans le
/// bit implicite), `$exposant` celui de l'exposant.
macro_rules! format_flottant {
    ($nom:ident, $f:ty, $u:ty, $u2:ty, $mantisse:literal, $exposant:literal) => {
        pub mod $nom {
            /// Bits de la mantisse, du nombre entier, de l'exposant.
            const M: u32 = $mantisse;
            const BITS: u32 = <$u>::BITS;
            const SIGNE: $u = 1 << (BITS - 1);
            const MASQUE_MANTISSE: $u = (1 << M) - 1;
            const MASQUE_EXPOSANT: $u = ((1 << $exposant) - 1) << M;
            /// Le biais de l'exposant : 127 en simple précision, 1023 en
            /// double. Un exposant stocké e vaut e - BIAIS.
            const BIAIS: i32 = (1 << ($exposant - 1)) - 1;

            /// Le NaN canonique positif : exposant à 1, seul le bit
            /// « silencieux » de la mantisse à 1.
            pub const NAN_CANONIQUE: $u = MASQUE_EXPOSANT | (1 << (M - 1));

            pub fn est_nan(x: $u) -> bool {
                x & MASQUE_EXPOSANT == MASQUE_EXPOSANT && x & MASQUE_MANTISSE != 0
            }

            /// Le résultat d'une opération arithmétique : un NaN, quel
            /// qu'il soit, devient le NaN canonique (voir plus haut).
            pub fn canonique(x: $u) -> $u {
                if est_nan(x) { NAN_CANONIQUE } else { x }
            }

            fn f(x: $u) -> $f {
                <$f>::from_bits(x)
            }

            pub fn add(a: $u, b: $u) -> $u {
                canonique((f(a) + f(b)).to_bits())
            }

            pub fn sub(a: $u, b: $u) -> $u {
                canonique((f(a) - f(b)).to_bits())
            }

            pub fn mul(a: $u, b: $u) -> $u {
                canonique((f(a) * f(b)).to_bits())
            }

            pub fn div(a: $u, b: $u) -> $u {
                canonique((f(a) / f(b)).to_bits())
            }

            // Les comparaisons : celles de Rust suivent IEEE 754 (un NaN
            // n'est égal à rien, pas même à lui-même ; -0 == +0).
            pub fn eq(a: $u, b: $u) -> bool {
                f(a) == f(b)
            }
            pub fn lt(a: $u, b: $u) -> bool {
                f(a) < f(b)
            }
            pub fn le(a: $u, b: $u) -> bool {
                f(a) <= f(b)
            }

            // Les opérations sur le seul bit de signe.
            pub fn abs(x: $u) -> $u {
                x & !SIGNE
            }
            pub fn neg(x: $u) -> $u {
                x ^ SIGNE
            }
            pub fn copysign(a: $u, b: $u) -> $u {
                (a & !SIGNE) | (b & SIGNE)
            }

            /// Le plus petit des deux. Différent du `min` de Rust : un NaN
            /// l'emporte, et -0 est plus petit que +0.
            pub fn min(a: $u, b: $u) -> $u {
                if est_nan(a) || est_nan(b) {
                    NAN_CANONIQUE
                } else if (a | b) & !SIGNE == 0 {
                    a | b // deux zéros : négatif si l'un l'est
                } else if f(a) < f(b) {
                    a
                } else {
                    b
                }
            }

            pub fn max(a: $u, b: $u) -> $u {
                if est_nan(a) || est_nan(b) {
                    NAN_CANONIQUE
                } else if (a | b) & !SIGNE == 0 {
                    a & b // deux zéros : positif si l'un l'est
                } else if f(a) > f(b) {
                    a
                } else {
                    b
                }
            }

            /// La racine carrée, correctement arrondie, en arithmétique
            /// entière.
            ///
            /// Un flottant positif fini vaut m × 2^(q - M), où m, la
            /// mantisse avec son bit implicite, a M + 1 bits. On rend q pair
            /// (quitte à doubler m) : sa racine vaut sqrt(m × 2^-M) × 2^(q/2),
            /// et sqrt(m × 2^-M) est entre 1 et 2. On calcule la racine
            /// entière R de m × 2^(M + 4) : elle a M + 3 bits, ceux du
            /// résultat plus deux de plus, qui servent à l'arrondir. Si la
            /// division n'est pas exacte (R² différent), un « bit collant »
            /// le note : c'est ce qui sépare « exactement au milieu » de
            /// « un peu au-dessus ».
            pub fn sqrt(x: $u) -> $u {
                if est_nan(x) {
                    return NAN_CANONIQUE;
                }
                if x & !SIGNE == 0 {
                    return x; // la racine de -0 est -0
                }
                if x & SIGNE != 0 {
                    return NAN_CANONIQUE; // racine d'un négatif
                }
                if x == MASQUE_EXPOSANT {
                    return x; // +infini
                }
                let exposant = ((x & MASQUE_EXPOSANT) >> M) as i32;
                let (mut m, mut q) = if exposant == 0 {
                    // Sous-normal : pas de bit implicite. On décale la
                    // mantisse jusqu'à ce que son bit de poids fort soit à
                    // la place du bit implicite, en baissant l'exposant
                    // d'autant.
                    let decalage = (x & MASQUE_MANTISSE).leading_zeros() - (BITS - M - 1);
                    ((x & MASQUE_MANTISSE) << decalage, 1 - BIAIS - decalage as i32)
                } else {
                    ((x & MASQUE_MANTISSE) | (1 << M), exposant - BIAIS)
                };
                if q & 1 != 0 {
                    m <<= 1;
                    q -= 1;
                }
                let n = (m as $u2) << (M + 4);
                let r = n.isqrt();
                let collant = r * r != n;
                // r a M + 3 bits : M + 1 pour le résultat, puis deux bits
                // d'arrondi. Arrondi au plus proche, à égalité vers le pair.
                let mut resultat = (r >> 2) as $u;
                let reste = (r & 3) as u32;
                if reste > 2 || (reste == 2 && (collant || resultat & 1 != 0)) {
                    resultat += 1;
                }
                // La racine d'un flottant positif est toujours un nombre
                // normal (la plus petite, celle du plus petit sous-normal,
                // vaut environ 2^-75 en simple précision). On retire le bit
                // implicite ; si l'arrondi a débordé jusqu'à 2^(M+1), la
                // retenue passe d'elle-même dans l'exposant.
                let exposant = (q / 2 + BIAIS) as $u;
                (exposant << M) + (resultat - (1 << M))
            }

            /// Les quatre arrondis à un entier (toujours représentable : un
            /// flottant assez grand n'a plus de partie fractionnaire).
            fn arrondi(x: $u, mode: Arrondi) -> $u {
                if est_nan(x) {
                    return NAN_CANONIQUE;
                }
                let exposant = ((x & MASQUE_EXPOSANT) >> M) as i32 - BIAIS;
                if exposant >= M as i32 {
                    return x; // déjà entier, ou infini
                }
                let negatif = x & SIGNE != 0;
                if exposant < 0 {
                    // |x| < 1 : le résultat vaut 0 ou 1, avec le signe de x.
                    if x & !SIGNE == 0 {
                        return x; // ±0
                    }
                    let un = (BIAIS as $u) << M;
                    let vers_un = match mode {
                        Arrondi::Zero => false,
                        Arrondi::Bas => negatif,
                        Arrondi::Haut => !negatif,
                        // 0,5 va vers 0 (le pair) ; au-dessus, vers 1.
                        Arrondi::Proche => exposant == -1 && x & MASQUE_MANTISSE != 0,
                    };
                    return (x & SIGNE) | if vers_un { un } else { 0 };
                }
                // 1 <= |x| < 2^M : les `fraction` bits de poids faible de la
                // mantisse sont la partie fractionnaire.
                let fraction = M - exposant as u32;
                let masque = ((1 as $u) << fraction) - 1;
                if x & masque == 0 {
                    return x;
                }
                let tronque = x & !masque;
                let unite = (1 as $u) << fraction;
                let plus_loin = match mode {
                    Arrondi::Zero => false,
                    Arrondi::Bas => negatif,
                    Arrondi::Haut => !negatif,
                    Arrondi::Proche => {
                        let reste = x & masque;
                        let moitie = unite >> 1;
                        // La parité de la partie entière : son dernier bit
                        // est celui juste au-dessus de la fraction, sauf si
                        // elle vaut 1 (exposant 0), le bit implicite.
                        let impaire = exposant == 0 || tronque & unite != 0;
                        reste > moitie || (reste == moitie && impaire)
                    }
                };
                // S'éloigner de zéro d'une unité : on ajoute aux bits, et
                // une retenue qui déborde de la mantisse passe dans
                // l'exposant, ce qui est juste (1,5 arrondi vers le haut :
                // la mantisse déborde, l'exposant passe de 0 à 1 : 2,0).
                if plus_loin { tronque + unite } else { tronque }
            }

            pub fn trunc(x: $u) -> $u {
                arrondi(x, Arrondi::Zero)
            }
            pub fn floor(x: $u) -> $u {
                arrondi(x, Arrondi::Bas)
            }
            pub fn ceil(x: $u) -> $u {
                arrondi(x, Arrondi::Haut)
            }
            pub fn nearest(x: $u) -> $u {
                arrondi(x, Arrondi::Proche)
            }

            use super::Arrondi;
        }
    };
}

#[derive(Clone, Copy)]
enum Arrondi {
    /// Vers zéro (trunc).
    Zero,
    /// Vers moins l'infini (floor).
    Bas,
    /// Vers plus l'infini (ceil).
    Haut,
    /// Vers l'entier le plus proche, à égalité vers le pair (nearest).
    Proche,
}

format_flottant!(f32, f32, u32, u64, 23, 8);
format_flottant!(f64, f64, u64, u128, 52, 11);

/// Comparaison avec la libm de la machine hôte (les fonctions de `std`,
/// correctement arrondies par le processeur), sur des valeurs particulières
/// et des millions de valeurs au hasard.
#[cfg(test)]
mod tests {
    extern crate std;
    use std::vec::Vec;

    struct Hasard(u64);
    impl Hasard {
        fn suivant(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Le même flottant, ou deux NaN dont le nôtre est canonique.
    fn pareil32(notre: u32, attendu: f32) -> bool {
        if attendu.is_nan() { notre == super::f32::NAN_CANONIQUE } else { notre == attendu.to_bits() }
    }
    fn pareil64(notre: u64, attendu: f64) -> bool {
        if attendu.is_nan() { notre == super::f64::NAN_CANONIQUE } else { notre == attendu.to_bits() }
    }

    /// Des bits à essayer : zéros, sous-normaux, 0,5, 1, 1,5, 2,5, grands
    /// nombres, infinis, NaN, puis du hasard (tous les exposants y passent).
    fn valeurs32() -> Vec<u32> {
        let mut v = std::vec![0, 1, 2, 0x007F_FFFF, 0x0080_0000, 0x3F00_0000, 0x3F00_0001, 0x3F7F_FFFF,
            0x3F80_0000, 0x3FC0_0000, 0x4020_0000, 0x4B00_0000, 0x4AFF_FFFF, 0x4B7F_FFFF, 0x7F7F_FFFF,
            0x7F80_0000, 0x7FC0_0000, 0x7FA0_0000, 0x7FFF_FFFF];
        let negatifs: Vec<u32> = v.iter().map(|x| x | 0x8000_0000).collect();
        v.extend(negatifs);
        let mut h = Hasard(0x2545_F491_4F6C_DD1D);
        v.extend((0..2_000_000).map(|_| h.suivant() as u32));
        v
    }

    fn valeurs64() -> Vec<u64> {
        let mut v = std::vec![0, 1, 2, 0x000F_FFFF_FFFF_FFFF, 0x0010_0000_0000_0000, 0x3FE0_0000_0000_0000,
            0x3FE0_0000_0000_0001, 0x3FEF_FFFF_FFFF_FFFF, 0x3FF0_0000_0000_0000, 0x3FF8_0000_0000_0000,
            0x4004_0000_0000_0000, 0x4330_0000_0000_0000, 0x432F_FFFF_FFFF_FFFF, 0x7FEF_FFFF_FFFF_FFFF,
            0x7FF0_0000_0000_0000, 0x7FF8_0000_0000_0000, 0x7FF4_0000_0000_0000];
        let negatifs: Vec<u64> = v.iter().map(|x| x | (1 << 63)).collect();
        v.extend(negatifs);
        let mut h = Hasard(0x9E37_79B9_7F4A_7C15);
        v.extend((0..2_000_000).map(|_| h.suivant()));
        v
    }

    #[test]
    fn racine_et_arrondis_simple_precision() {
        use super::f32 as f;
        for x in valeurs32() {
            let r = f32::from_bits(x);
            assert!(pareil32(f::sqrt(x), r.sqrt()), "sqrt({x:#x})");
            assert!(pareil32(f::floor(x), r.floor()), "floor({x:#x})");
            assert!(pareil32(f::ceil(x), r.ceil()), "ceil({x:#x})");
            assert!(pareil32(f::trunc(x), r.trunc()), "trunc({x:#x})");
            assert!(pareil32(f::nearest(x), r.round_ties_even()), "nearest({x:#x})");
        }
    }

    #[test]
    fn racine_et_arrondis_double_precision() {
        use super::f64 as f;
        for x in valeurs64() {
            let r = f64::from_bits(x);
            assert!(pareil64(f::sqrt(x), r.sqrt()), "sqrt({x:#x})");
            assert!(pareil64(f::floor(x), r.floor()), "floor({x:#x})");
            assert!(pareil64(f::ceil(x), r.ceil()), "ceil({x:#x})");
            assert!(pareil64(f::trunc(x), r.trunc()), "trunc({x:#x})");
            assert!(pareil64(f::nearest(x), r.round_ties_even()), "nearest({x:#x})");
        }
    }

    #[test]
    fn min_max_et_nan() {
        use super::f32 as f;
        let (zero, moins_zero, un, nan) = (0u32, 0x8000_0000u32, 0x3F80_0000u32, 0x7FA0_0001u32);
        assert_eq!(f::min(zero, moins_zero), moins_zero);
        assert_eq!(f::min(moins_zero, zero), moins_zero);
        assert_eq!(f::max(zero, moins_zero), zero);
        assert_eq!(f::min(un, zero), zero);
        assert_eq!(f::max(un, zero), un);
        // Un NaN l'emporte, et devient canonique.
        assert_eq!(f::min(nan, un), f::NAN_CANONIQUE);
        assert_eq!(f::max(un, nan), f::NAN_CANONIQUE);
        assert_eq!(f::add(nan, un), f::NAN_CANONIQUE);
        // Les opérations sur le signe gardent la charge du NaN.
        assert_eq!(f::neg(nan), nan | 0x8000_0000);
        assert_eq!(f::abs(nan | 0x8000_0000), nan);
        assert_eq!(f::copysign(nan, moins_zero), nan | 0x8000_0000);
    }
}
