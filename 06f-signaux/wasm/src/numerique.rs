//! Les opérations numériques (instructions.rs, la table `operations!`),
//! exécutées sur la pile de l'interpréteur.
//!
//! La pile est faite de cases de 64 bits sans type : un i32 y occupe les 32
//! bits de poids faible, complétés par des zéros ; un flottant y est rangé
//! en bits. La validation a garanti que les opérandes ont le bon type : on
//! se contente de les lire comme tels. Une opération dépile ses opérandes
//! et empile son résultat ; on écrit le résultat directement à la place du
//! premier opérande, sans dépiler-rempiler.
//!
//! Les entiers suivent l'arithmétique modulaire (wrapping_add...) : en
//! WebAssembly, i32.add de deux grands nombres « fait le tour », sans
//! erreur. Les seuls pièges sont la division par zéro, le débordement de
//! la division signée, et les conversions de flottants hors limites.

use alloc::vec::Vec;

use crate::flottants::{f32 as s, f64 as d};
use crate::instructions::Op;
use crate::magasin::Piege;

/// La validation garantit que la pile contient assez d'opérandes : si ce
/// n'était pas le cas, le validateur aurait un défaut. Rust refuse alors
/// d'aller plus loin (une panique), au lieu de lire n'importe quoi.
const VALIDE: &str = "pile garantie par la validation";

fn unaire(pile: &mut [u64], f: impl FnOnce(u64) -> Result<u64, Piege>) -> Result<(), Piege> {
    let a = pile.last_mut().expect(VALIDE);
    *a = f(*a)?;
    Ok(())
}

fn binaire(pile: &mut Vec<u64>, f: impl FnOnce(u64, u64) -> Result<u64, Piege>) -> Result<(), Piege> {
    let b = pile.pop().expect(VALIDE);
    let a = pile.last_mut().expect(VALIDE);
    *a = f(*a, b)?;
    Ok(())
}

// Lire une case comme... Les i32 et f32 sont dans les 32 bits de poids
// faible.
fn i32(x: u64) -> u32 {
    x as u32
}
fn si32(x: u64) -> i32 {
    x as u32 as i32
}
fn si64(x: u64) -> i64 {
    x as i64
}
fn booleen(b: bool) -> u64 {
    b as u64
}

/// Une conversion d'un flottant en entier, qui peut piéger : `x` (un f32
/// est d'abord converti en f64, exactement) doit être strictement entre
/// `min` et `max`, qui ne sont pas eux-mêmes des résultats possibles. Par
/// exemple, pour i32 signé : -2^31 - 1 < x < 2^31. Rust convertit ensuite
/// en tronquant vers zéro.
fn bornee(x: f64, min: f64, max: f64) -> Result<f64, Piege> {
    if x.is_nan() {
        return Err(Piege::ConversionInvalide);
    }
    if !(x > min && x < max) {
        return Err(Piege::DebordementEntier);
    }
    Ok(x)
}

const I32_S: (f64, f64) = (-2147483649.0, 2147483648.0);
const I32_U: (f64, f64) = (-1.0, 4294967296.0);
// -2^63 - 1 n'existe pas en f64 : le flottant juste en dessous de -2^63 est
// -2^63 - 2048, qui convient aussi comme borne exclue.
const I64_S: (f64, f64) = (-9223372036854777856.0, 9223372036854775808.0);
const I64_U: (f64, f64) = (-1.0, 18446744073709551616.0);

fn depuis_f32(x: u64) -> f64 {
    f32::from_bits(x as u32) as f64
}
fn depuis_f64(x: u64) -> f64 {
    f64::from_bits(x)
}

/// Exécute une opération numérique sur le sommet de la pile.
pub(crate) fn operation(op: Op, pile: &mut Vec<u64>) -> Result<(), Piege> {
    use Op::*;
    // Les fermetures rendent un Result : seules quelques-unes piègent.
    match op {
        // Comparaisons d'entiers : le résultat est un i32, 0 ou 1.
        I32Eqz => unaire(pile, |a| Ok(booleen(i32(a) == 0))),
        I32Eq => binaire(pile, |a, b| Ok(booleen(i32(a) == i32(b)))),
        I32Ne => binaire(pile, |a, b| Ok(booleen(i32(a) != i32(b)))),
        I32LtS => binaire(pile, |a, b| Ok(booleen(si32(a) < si32(b)))),
        I32LtU => binaire(pile, |a, b| Ok(booleen(i32(a) < i32(b)))),
        I32GtS => binaire(pile, |a, b| Ok(booleen(si32(a) > si32(b)))),
        I32GtU => binaire(pile, |a, b| Ok(booleen(i32(a) > i32(b)))),
        I32LeS => binaire(pile, |a, b| Ok(booleen(si32(a) <= si32(b)))),
        I32LeU => binaire(pile, |a, b| Ok(booleen(i32(a) <= i32(b)))),
        I32GeS => binaire(pile, |a, b| Ok(booleen(si32(a) >= si32(b)))),
        I32GeU => binaire(pile, |a, b| Ok(booleen(i32(a) >= i32(b)))),
        I64Eqz => unaire(pile, |a| Ok(booleen(a == 0))),
        I64Eq => binaire(pile, |a, b| Ok(booleen(a == b))),
        I64Ne => binaire(pile, |a, b| Ok(booleen(a != b))),
        I64LtS => binaire(pile, |a, b| Ok(booleen(si64(a) < si64(b)))),
        I64LtU => binaire(pile, |a, b| Ok(booleen(a < b))),
        I64GtS => binaire(pile, |a, b| Ok(booleen(si64(a) > si64(b)))),
        I64GtU => binaire(pile, |a, b| Ok(booleen(a > b))),
        I64LeS => binaire(pile, |a, b| Ok(booleen(si64(a) <= si64(b)))),
        I64LeU => binaire(pile, |a, b| Ok(booleen(a <= b))),
        I64GeS => binaire(pile, |a, b| Ok(booleen(si64(a) >= si64(b)))),
        I64GeU => binaire(pile, |a, b| Ok(booleen(a >= b))),

        // Comparaisons de flottants (a > b s'écrit b < a).
        F32Eq => binaire(pile, |a, b| Ok(booleen(s::eq(i32(a), i32(b))))),
        F32Ne => binaire(pile, |a, b| Ok(booleen(!s::eq(i32(a), i32(b))))),
        F32Lt => binaire(pile, |a, b| Ok(booleen(s::lt(i32(a), i32(b))))),
        F32Gt => binaire(pile, |a, b| Ok(booleen(s::lt(i32(b), i32(a))))),
        F32Le => binaire(pile, |a, b| Ok(booleen(s::le(i32(a), i32(b))))),
        F32Ge => binaire(pile, |a, b| Ok(booleen(s::le(i32(b), i32(a))))),
        F64Eq => binaire(pile, |a, b| Ok(booleen(d::eq(a, b)))),
        F64Ne => binaire(pile, |a, b| Ok(booleen(!d::eq(a, b)))),
        F64Lt => binaire(pile, |a, b| Ok(booleen(d::lt(a, b)))),
        F64Gt => binaire(pile, |a, b| Ok(booleen(d::lt(b, a)))),
        F64Le => binaire(pile, |a, b| Ok(booleen(d::le(a, b)))),
        F64Ge => binaire(pile, |a, b| Ok(booleen(d::le(b, a)))),

        // Arithmétique entière sur 32 bits.
        I32Clz => unaire(pile, |a| Ok(i32(a).leading_zeros() as u64)),
        I32Ctz => unaire(pile, |a| Ok(i32(a).trailing_zeros() as u64)),
        I32Popcnt => unaire(pile, |a| Ok(i32(a).count_ones() as u64)),
        I32Add => binaire(pile, |a, b| Ok(i32(a).wrapping_add(i32(b)) as u64)),
        I32Sub => binaire(pile, |a, b| Ok(i32(a).wrapping_sub(i32(b)) as u64)),
        I32Mul => binaire(pile, |a, b| Ok(i32(a).wrapping_mul(i32(b)) as u64)),
        I32DivS => binaire(pile, |a, b| {
            let (a, b) = (si32(a), si32(b));
            if b == 0 {
                return Err(Piege::DivisionParZero);
            }
            // -2^31 / -1 = 2^31, qui ne tient pas dans un i32.
            a.checked_div(b).map(|q| q as u32 as u64).ok_or(Piege::DebordementEntier)
        }),
        I32DivU => binaire(pile, |a, b| i32(a).checked_div(i32(b)).map(|q| q as u64).ok_or(Piege::DivisionParZero)),
        I32RemS => binaire(pile, |a, b| {
            if i32(b) == 0 {
                return Err(Piege::DivisionParZero);
            }
            // Le reste de -2^31 par -1 vaut 0 : wrapping_rem le rend sans
            // déborder.
            Ok(si32(a).wrapping_rem(si32(b)) as u32 as u64)
        }),
        I32RemU => binaire(pile, |a, b| i32(a).checked_rem(i32(b)).map(|r| r as u64).ok_or(Piege::DivisionParZero)),
        I32And => binaire(pile, |a, b| Ok((i32(a) & i32(b)) as u64)),
        I32Or => binaire(pile, |a, b| Ok((i32(a) | i32(b)) as u64)),
        I32Xor => binaire(pile, |a, b| Ok((i32(a) ^ i32(b)) as u64)),
        // Le nombre de positions d'un décalage est pris modulo 32 : c'est
        // ce que fait wrapping_shl.
        I32Shl => binaire(pile, |a, b| Ok(i32(a).wrapping_shl(i32(b)) as u64)),
        I32ShrS => binaire(pile, |a, b| Ok(si32(a).wrapping_shr(i32(b)) as u32 as u64)),
        I32ShrU => binaire(pile, |a, b| Ok(i32(a).wrapping_shr(i32(b)) as u64)),
        I32Rotl => binaire(pile, |a, b| Ok(i32(a).rotate_left(i32(b)) as u64)),
        I32Rotr => binaire(pile, |a, b| Ok(i32(a).rotate_right(i32(b)) as u64)),

        // Arithmétique entière sur 64 bits.
        I64Clz => unaire(pile, |a| Ok(a.leading_zeros() as u64)),
        I64Ctz => unaire(pile, |a| Ok(a.trailing_zeros() as u64)),
        I64Popcnt => unaire(pile, |a| Ok(a.count_ones() as u64)),
        I64Add => binaire(pile, |a, b| Ok(a.wrapping_add(b))),
        I64Sub => binaire(pile, |a, b| Ok(a.wrapping_sub(b))),
        I64Mul => binaire(pile, |a, b| Ok(a.wrapping_mul(b))),
        I64DivS => binaire(pile, |a, b| {
            if b == 0 {
                return Err(Piege::DivisionParZero);
            }
            si64(a).checked_div(si64(b)).map(|q| q as u64).ok_or(Piege::DebordementEntier)
        }),
        I64DivU => binaire(pile, |a, b| a.checked_div(b).ok_or(Piege::DivisionParZero)),
        I64RemS => binaire(pile, |a, b| {
            if b == 0 {
                return Err(Piege::DivisionParZero);
            }
            Ok(si64(a).wrapping_rem(si64(b)) as u64)
        }),
        I64RemU => binaire(pile, |a, b| a.checked_rem(b).ok_or(Piege::DivisionParZero)),
        I64And => binaire(pile, |a, b| Ok(a & b)),
        I64Or => binaire(pile, |a, b| Ok(a | b)),
        I64Xor => binaire(pile, |a, b| Ok(a ^ b)),
        I64Shl => binaire(pile, |a, b| Ok(a.wrapping_shl(b as u32))),
        I64ShrS => binaire(pile, |a, b| Ok(si64(a).wrapping_shr(b as u32) as u64)),
        I64ShrU => binaire(pile, |a, b| Ok(a.wrapping_shr(b as u32))),
        I64Rotl => binaire(pile, |a, b| Ok(a.rotate_left((b % 64) as u32))),
        I64Rotr => binaire(pile, |a, b| Ok(a.rotate_right((b % 64) as u32))),

        // Flottants (voir flottants.rs).
        F32Abs => unaire(pile, |a| Ok(s::abs(i32(a)) as u64)),
        F32Neg => unaire(pile, |a| Ok(s::neg(i32(a)) as u64)),
        F32Ceil => unaire(pile, |a| Ok(s::ceil(i32(a)) as u64)),
        F32Floor => unaire(pile, |a| Ok(s::floor(i32(a)) as u64)),
        F32Trunc => unaire(pile, |a| Ok(s::trunc(i32(a)) as u64)),
        F32Nearest => unaire(pile, |a| Ok(s::nearest(i32(a)) as u64)),
        F32Sqrt => unaire(pile, |a| Ok(s::sqrt(i32(a)) as u64)),
        F32Add => binaire(pile, |a, b| Ok(s::add(i32(a), i32(b)) as u64)),
        F32Sub => binaire(pile, |a, b| Ok(s::sub(i32(a), i32(b)) as u64)),
        F32Mul => binaire(pile, |a, b| Ok(s::mul(i32(a), i32(b)) as u64)),
        F32Div => binaire(pile, |a, b| Ok(s::div(i32(a), i32(b)) as u64)),
        F32Min => binaire(pile, |a, b| Ok(s::min(i32(a), i32(b)) as u64)),
        F32Max => binaire(pile, |a, b| Ok(s::max(i32(a), i32(b)) as u64)),
        F32Copysign => binaire(pile, |a, b| Ok(s::copysign(i32(a), i32(b)) as u64)),
        F64Abs => unaire(pile, |a| Ok(d::abs(a))),
        F64Neg => unaire(pile, |a| Ok(d::neg(a))),
        F64Ceil => unaire(pile, |a| Ok(d::ceil(a))),
        F64Floor => unaire(pile, |a| Ok(d::floor(a))),
        F64Trunc => unaire(pile, |a| Ok(d::trunc(a))),
        F64Nearest => unaire(pile, |a| Ok(d::nearest(a))),
        F64Sqrt => unaire(pile, |a| Ok(d::sqrt(a))),
        F64Add => binaire(pile, |a, b| Ok(d::add(a, b))),
        F64Sub => binaire(pile, |a, b| Ok(d::sub(a, b))),
        F64Mul => binaire(pile, |a, b| Ok(d::mul(a, b))),
        F64Div => binaire(pile, |a, b| Ok(d::div(a, b))),
        F64Min => binaire(pile, |a, b| Ok(d::min(a, b))),
        F64Max => binaire(pile, |a, b| Ok(d::max(a, b))),
        F64Copysign => binaire(pile, |a, b| Ok(d::copysign(a, b))),

        // Conversions entre entiers.
        I32WrapI64 => unaire(pile, |a| Ok(i32(a) as u64)),
        I64ExtendI32S => unaire(pile, |a| Ok(si32(a) as i64 as u64)),
        I64ExtendI32U => unaire(pile, |a| Ok(i32(a) as u64)),
        I32Extend8S => unaire(pile, |a| Ok(a as u8 as i8 as i32 as u32 as u64)),
        I32Extend16S => unaire(pile, |a| Ok(a as u16 as i16 as i32 as u32 as u64)),
        I64Extend8S => unaire(pile, |a| Ok(a as u8 as i8 as i64 as u64)),
        I64Extend16S => unaire(pile, |a| Ok(a as u16 as i16 as i64 as u64)),
        I64Extend32S => unaire(pile, |a| Ok(a as u32 as i32 as i64 as u64)),

        // Flottant vers entier, avec piège.
        I32TruncF32S => unaire(pile, |a| Ok(bornee(depuis_f32(a), I32_S.0, I32_S.1)? as i32 as u32 as u64)),
        I32TruncF32U => unaire(pile, |a| Ok(bornee(depuis_f32(a), I32_U.0, I32_U.1)? as u32 as u64)),
        I32TruncF64S => unaire(pile, |a| Ok(bornee(depuis_f64(a), I32_S.0, I32_S.1)? as i32 as u32 as u64)),
        I32TruncF64U => unaire(pile, |a| Ok(bornee(depuis_f64(a), I32_U.0, I32_U.1)? as u32 as u64)),
        I64TruncF32S => unaire(pile, |a| Ok(bornee(depuis_f32(a), I64_S.0, I64_S.1)? as i64 as u64)),
        I64TruncF32U => unaire(pile, |a| Ok(bornee(depuis_f32(a), I64_U.0, I64_U.1)? as u64)),
        I64TruncF64S => unaire(pile, |a| Ok(bornee(depuis_f64(a), I64_S.0, I64_S.1)? as i64 as u64)),
        I64TruncF64U => unaire(pile, |a| Ok(bornee(depuis_f64(a), I64_U.0, I64_U.1)? as u64)),
        // Flottant vers entier « saturant » : c'est exactement la
        // conversion `as` de Rust (NaN donne 0, le reste est borné).
        I32TruncSatF32S => unaire(pile, |a| Ok(depuis_f32(a) as i32 as u32 as u64)),
        I32TruncSatF32U => unaire(pile, |a| Ok(depuis_f32(a) as u32 as u64)),
        I32TruncSatF64S => unaire(pile, |a| Ok(depuis_f64(a) as i32 as u32 as u64)),
        I32TruncSatF64U => unaire(pile, |a| Ok(depuis_f64(a) as u32 as u64)),
        I64TruncSatF32S => unaire(pile, |a| Ok(depuis_f32(a) as i64 as u64)),
        I64TruncSatF32U => unaire(pile, |a| Ok(depuis_f32(a) as u64)),
        I64TruncSatF64S => unaire(pile, |a| Ok(depuis_f64(a) as i64 as u64)),
        I64TruncSatF64U => unaire(pile, |a| Ok(depuis_f64(a) as u64)),

        // Entier vers flottant : `as` arrondit au plus proche (à égalité,
        // vers le pair), comme WebAssembly ; le résultat n'est jamais NaN.
        F32ConvertI32S => unaire(pile, |a| Ok((si32(a) as f32).to_bits() as u64)),
        F32ConvertI32U => unaire(pile, |a| Ok((i32(a) as f32).to_bits() as u64)),
        F32ConvertI64S => unaire(pile, |a| Ok((si64(a) as f32).to_bits() as u64)),
        F32ConvertI64U => unaire(pile, |a| Ok((a as f32).to_bits() as u64)),
        F64ConvertI32S => unaire(pile, |a| Ok((si32(a) as f64).to_bits())),
        F64ConvertI32U => unaire(pile, |a| Ok((i32(a) as f64).to_bits())),
        F64ConvertI64S => unaire(pile, |a| Ok((si64(a) as f64).to_bits())),
        F64ConvertI64U => unaire(pile, |a| Ok((a as f64).to_bits())),
        // Entre flottants : un NaN devient le NaN canonique (flottants.rs).
        F32DemoteF64 => unaire(pile, |a| Ok(s::canonique((depuis_f64(a) as f32).to_bits()) as u64)),
        F64PromoteF32 => unaire(pile, |a| Ok(d::canonique(depuis_f32(a).to_bits()))),
        // Réinterpréter les bits : les cases n'ont pas de type, il n'y a
        // rien à faire.
        I32ReinterpretF32 | I64ReinterpretF64 | F32ReinterpretI32 | F64ReinterpretI64 => Ok(()),
    }
}
