//! Le jeu d'instructions de WebAssembly 2.0 (sans SIMD), et la lecture
//! d'une instruction dans les octets du code.
//!
//! WebAssembly est une machine à pile : `i32.add` dépile deux i32 et empile
//! leur somme. Chaque instruction est un octet (l'opcode), suivi parfois
//! d'arguments immédiats en LEB128 : un index de variable locale, une
//! constante, un décalage d'adresse... Les instructions ajoutées après la
//! version 1.0 commencent par le préfixe 0xFC, suivi d'un second opcode.
//!
//! On ne traduit pas le code dans un format interne : décodeur, validateur
//! et interpréteur lisent tous les octets d'origine avec `lire_instruction`
//! (voir module.rs). L'`Instruction` rendue est éphémère : elle décrit
//! l'instruction lue, le temps de la traiter.

use crate::erreur::{Erreur, Genre};
use crate::lecteur::Lecteur;
use crate::module::TypeValeur;

/// Le type d'un bloc (block, loop, if) : ce qu'il consomme et produit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeBloc {
    /// [] -> []
    Vide,
    /// [] -> [t]
    Valeur(TypeValeur),
    /// Un type de fonction du module : [paramètres] -> [résultats]
    /// (plusieurs résultats depuis la version 2.0, « multi-value »).
    Index(u32),
}

/// L'argument d'un accès mémoire : `offset` s'ajoute à l'adresse dépilée ;
/// `align` est le log2 de l'alignement promis, un simple indice de
/// performance (un accès mal aligné marche quand même).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgMemoire {
    pub align: u32,
    pub offset: u32,
}

/// Une instruction lue. Les variantes suivent la spécification ; les noms
/// entre crochets sont ceux du format texte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    // Contrôle
    Unreachable,
    Nop,
    Block(TypeBloc),
    Loop(TypeBloc),
    If(TypeBloc),
    Else,
    End,
    Br(u32),
    BrIf(u32),
    /// [br_table l* l] : `nombre` cibles, puis la cible par défaut. Les
    /// cibles sont des LEB128, de longueurs variables : on ne peut pas sauter
    /// directement à la n-ième. `cibles` est la position de la première ; on
    /// les relit avec `lire_cibles`.
    BrTable { nombre: u32, cibles: usize },
    Return,
    Call(u32),
    CallIndirect { type_fonction: u32, table: u32 },
    // Références
    RefNull(TypeValeur),
    RefIsNull,
    RefFunc(u32),
    // Paramétriques
    Drop,
    /// [select] sans type : seulement pour des nombres.
    Select,
    /// [select t*] : la liste de types doit contenir exactement un type
    /// (vérifié par le validateur) ; on garde son nombre et le premier.
    SelectT { nombre: u32, premier: Option<TypeValeur> },
    // Variables
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    // Tables
    TableGet(u32),
    TableSet(u32),
    TableInit { segment: u32, table: u32 },
    ElemDrop(u32),
    TableCopy { destination: u32, source: u32 },
    TableGrow(u32),
    TableSize(u32),
    TableFill(u32),
    // Mémoire
    Acces(Acces, ArgMemoire),
    MemorySize,
    MemoryGrow,
    MemoryInit(u32),
    DataDrop(u32),
    MemoryCopy,
    MemoryFill,
    // Constantes : les flottants gardés en bits (voir lecteur.rs).
    I32Const(i32),
    I64Const(i64),
    F32Const(u32),
    F64Const(u64),
    /// Les opérations numériques, sans argument immédiat.
    Op(Op),
}

/// Engendre un enum d'opérations depuis une table (opcode, nom, signature),
/// avec la fonction qui retrouve l'opération d'un opcode et celle qui donne
/// sa signature. Écrire la table une seule fois évite que le décodeur, le
/// validateur et l'interpréteur divergent.
macro_rules! operations {
    ($nom_enum:ident, $depuis:ident, $( $code:literal $nom:ident ( $($entree:ident)* -> $sortie:ident ) ),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $nom_enum { $( $nom ),* }

        impl $nom_enum {
            pub fn $depuis(code: u32) -> Option<$nom_enum> {
                match code {
                    $( $code => Some($nom_enum::$nom), )*
                    _ => None,
                }
            }

            /// Types dépilés (dans l'ordre où ils ont été empilés), et type
            /// empilé.
            pub fn signature(self) -> (&'static [TypeValeur], TypeValeur) {
                match self {
                    $( $nom_enum::$nom => (&[$(TypeValeur::$entree),*], TypeValeur::$sortie), )*
                }
            }
        }
    };
}

operations! { Op, depuis_opcode,
    0x45 I32Eqz(I32 -> I32), 0x46 I32Eq(I32 I32 -> I32), 0x47 I32Ne(I32 I32 -> I32),
    0x48 I32LtS(I32 I32 -> I32), 0x49 I32LtU(I32 I32 -> I32), 0x4A I32GtS(I32 I32 -> I32),
    0x4B I32GtU(I32 I32 -> I32), 0x4C I32LeS(I32 I32 -> I32), 0x4D I32LeU(I32 I32 -> I32),
    0x4E I32GeS(I32 I32 -> I32), 0x4F I32GeU(I32 I32 -> I32),

    0x50 I64Eqz(I64 -> I32), 0x51 I64Eq(I64 I64 -> I32), 0x52 I64Ne(I64 I64 -> I32),
    0x53 I64LtS(I64 I64 -> I32), 0x54 I64LtU(I64 I64 -> I32), 0x55 I64GtS(I64 I64 -> I32),
    0x56 I64GtU(I64 I64 -> I32), 0x57 I64LeS(I64 I64 -> I32), 0x58 I64LeU(I64 I64 -> I32),
    0x59 I64GeS(I64 I64 -> I32), 0x5A I64GeU(I64 I64 -> I32),

    0x5B F32Eq(F32 F32 -> I32), 0x5C F32Ne(F32 F32 -> I32), 0x5D F32Lt(F32 F32 -> I32),
    0x5E F32Gt(F32 F32 -> I32), 0x5F F32Le(F32 F32 -> I32), 0x60 F32Ge(F32 F32 -> I32),

    0x61 F64Eq(F64 F64 -> I32), 0x62 F64Ne(F64 F64 -> I32), 0x63 F64Lt(F64 F64 -> I32),
    0x64 F64Gt(F64 F64 -> I32), 0x65 F64Le(F64 F64 -> I32), 0x66 F64Ge(F64 F64 -> I32),

    0x67 I32Clz(I32 -> I32), 0x68 I32Ctz(I32 -> I32), 0x69 I32Popcnt(I32 -> I32),
    0x6A I32Add(I32 I32 -> I32), 0x6B I32Sub(I32 I32 -> I32), 0x6C I32Mul(I32 I32 -> I32),
    0x6D I32DivS(I32 I32 -> I32), 0x6E I32DivU(I32 I32 -> I32), 0x6F I32RemS(I32 I32 -> I32),
    0x70 I32RemU(I32 I32 -> I32), 0x71 I32And(I32 I32 -> I32), 0x72 I32Or(I32 I32 -> I32),
    0x73 I32Xor(I32 I32 -> I32), 0x74 I32Shl(I32 I32 -> I32), 0x75 I32ShrS(I32 I32 -> I32),
    0x76 I32ShrU(I32 I32 -> I32), 0x77 I32Rotl(I32 I32 -> I32), 0x78 I32Rotr(I32 I32 -> I32),

    0x79 I64Clz(I64 -> I64), 0x7A I64Ctz(I64 -> I64), 0x7B I64Popcnt(I64 -> I64),
    0x7C I64Add(I64 I64 -> I64), 0x7D I64Sub(I64 I64 -> I64), 0x7E I64Mul(I64 I64 -> I64),
    0x7F I64DivS(I64 I64 -> I64), 0x80 I64DivU(I64 I64 -> I64), 0x81 I64RemS(I64 I64 -> I64),
    0x82 I64RemU(I64 I64 -> I64), 0x83 I64And(I64 I64 -> I64), 0x84 I64Or(I64 I64 -> I64),
    0x85 I64Xor(I64 I64 -> I64), 0x86 I64Shl(I64 I64 -> I64), 0x87 I64ShrS(I64 I64 -> I64),
    0x88 I64ShrU(I64 I64 -> I64), 0x89 I64Rotl(I64 I64 -> I64), 0x8A I64Rotr(I64 I64 -> I64),

    0x8B F32Abs(F32 -> F32), 0x8C F32Neg(F32 -> F32), 0x8D F32Ceil(F32 -> F32),
    0x8E F32Floor(F32 -> F32), 0x8F F32Trunc(F32 -> F32), 0x90 F32Nearest(F32 -> F32),
    0x91 F32Sqrt(F32 -> F32), 0x92 F32Add(F32 F32 -> F32), 0x93 F32Sub(F32 F32 -> F32),
    0x94 F32Mul(F32 F32 -> F32), 0x95 F32Div(F32 F32 -> F32), 0x96 F32Min(F32 F32 -> F32),
    0x97 F32Max(F32 F32 -> F32), 0x98 F32Copysign(F32 F32 -> F32),

    0x99 F64Abs(F64 -> F64), 0x9A F64Neg(F64 -> F64), 0x9B F64Ceil(F64 -> F64),
    0x9C F64Floor(F64 -> F64), 0x9D F64Trunc(F64 -> F64), 0x9E F64Nearest(F64 -> F64),
    0x9F F64Sqrt(F64 -> F64), 0xA0 F64Add(F64 F64 -> F64), 0xA1 F64Sub(F64 F64 -> F64),
    0xA2 F64Mul(F64 F64 -> F64), 0xA3 F64Div(F64 F64 -> F64), 0xA4 F64Min(F64 F64 -> F64),
    0xA5 F64Max(F64 F64 -> F64), 0xA6 F64Copysign(F64 F64 -> F64),

    0xA7 I32WrapI64(I64 -> I32), 0xA8 I32TruncF32S(F32 -> I32), 0xA9 I32TruncF32U(F32 -> I32),
    0xAA I32TruncF64S(F64 -> I32), 0xAB I32TruncF64U(F64 -> I32), 0xAC I64ExtendI32S(I32 -> I64),
    0xAD I64ExtendI32U(I32 -> I64), 0xAE I64TruncF32S(F32 -> I64), 0xAF I64TruncF32U(F32 -> I64),
    0xB0 I64TruncF64S(F64 -> I64), 0xB1 I64TruncF64U(F64 -> I64), 0xB2 F32ConvertI32S(I32 -> F32),
    0xB3 F32ConvertI32U(I32 -> F32), 0xB4 F32ConvertI64S(I64 -> F32), 0xB5 F32ConvertI64U(I64 -> F32),
    0xB6 F32DemoteF64(F64 -> F32), 0xB7 F64ConvertI32S(I32 -> F64), 0xB8 F64ConvertI32U(I32 -> F64),
    0xB9 F64ConvertI64S(I64 -> F64), 0xBA F64ConvertI64U(I64 -> F64), 0xBB F64PromoteF32(F32 -> F64),
    0xBC I32ReinterpretF32(F32 -> I32), 0xBD I64ReinterpretF64(F64 -> I64),
    0xBE F32ReinterpretI32(I32 -> F32), 0xBF F64ReinterpretI64(I64 -> F64),

    // Extension de signe (2.0).
    0xC0 I32Extend8S(I32 -> I32), 0xC1 I32Extend16S(I32 -> I32), 0xC2 I64Extend8S(I64 -> I64),
    0xC3 I64Extend16S(I64 -> I64), 0xC4 I64Extend32S(I64 -> I64),

    // Conversions « saturantes » (2.0), préfixe 0xFC : codées ici 0xFC00 + n.
    0xFC00 I32TruncSatF32S(F32 -> I32), 0xFC01 I32TruncSatF32U(F32 -> I32),
    0xFC02 I32TruncSatF64S(F64 -> I32), 0xFC03 I32TruncSatF64U(F64 -> I32),
    0xFC04 I64TruncSatF32S(F32 -> I64), 0xFC05 I64TruncSatF32U(F32 -> I64),
    0xFC06 I64TruncSatF64S(F64 -> I64), 0xFC07 I64TruncSatF64U(F64 -> I64),
}

/// Les accès à la mémoire. Ici la « signature » est (type de la valeur,
/// taille de l'accès en octets) ; l'adresse est toujours un i32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acces {
    I32Load, I64Load, F32Load, F64Load,
    I32Load8S, I32Load8U, I32Load16S, I32Load16U,
    I64Load8S, I64Load8U, I64Load16S, I64Load16U, I64Load32S, I64Load32U,
    I32Store, I64Store, F32Store, F64Store,
    I32Store8, I32Store16, I64Store8, I64Store16, I64Store32,
}

impl Acces {
    const TOUS: [Acces; 23] = [
        Acces::I32Load, Acces::I64Load, Acces::F32Load, Acces::F64Load,
        Acces::I32Load8S, Acces::I32Load8U, Acces::I32Load16S, Acces::I32Load16U,
        Acces::I64Load8S, Acces::I64Load8U, Acces::I64Load16S, Acces::I64Load16U,
        Acces::I64Load32S, Acces::I64Load32U,
        Acces::I32Store, Acces::I64Store, Acces::F32Store, Acces::F64Store,
        Acces::I32Store8, Acces::I32Store16, Acces::I64Store8, Acces::I64Store16, Acces::I64Store32,
    ];

    /// Opcodes 0x28 à 0x3E, dans l'ordre de TOUS.
    fn depuis_opcode(code: u8) -> Option<Acces> {
        Acces::TOUS.get(code.checked_sub(0x28)? as usize).copied()
    }

    /// Le type de la valeur lue ou écrite, et la taille de l'accès.
    pub fn genre(self) -> (TypeValeur, u32) {
        use TypeValeur::*;
        match self {
            Acces::I32Load | Acces::I32Store => (I32, 4),
            Acces::I64Load | Acces::I64Store => (I64, 8),
            Acces::F32Load | Acces::F32Store => (F32, 4),
            Acces::F64Load | Acces::F64Store => (F64, 8),
            Acces::I32Load8S | Acces::I32Load8U | Acces::I32Store8 => (I32, 1),
            Acces::I32Load16S | Acces::I32Load16U | Acces::I32Store16 => (I32, 2),
            Acces::I64Load8S | Acces::I64Load8U | Acces::I64Store8 => (I64, 1),
            Acces::I64Load16S | Acces::I64Load16U | Acces::I64Store16 => (I64, 2),
            Acces::I64Load32S | Acces::I64Load32U | Acces::I64Store32 => (I64, 4),
        }
    }

    pub fn est_ecriture(self) -> bool {
        matches!(self, Acces::I32Store | Acces::I64Store | Acces::F32Store | Acces::F64Store
            | Acces::I32Store8 | Acces::I32Store16 | Acces::I64Store8 | Acces::I64Store16
            | Acces::I64Store32)
    }
}

/// Un lecteur placé sur les cibles d'un br_table (voir Instruction::BrTable) :
/// `nombre` cibles puis la cible par défaut, chacune un u32.
pub fn lire_cibles(octets: &[u8], cibles: usize) -> Lecteur<'_> {
    Lecteur::a_partir(octets, cibles)
}

/// Un type de valeur (un octet). Les types références et numériques
/// partagent le même espace de codes.
pub fn lire_type_valeur(l: &mut Lecteur) -> Result<TypeValeur, Erreur> {
    let octet = l.octet()?;
    type_valeur(octet).map_err(|genre| Erreur { position: l.position() - 1, genre })
}

fn type_valeur(octet: u8) -> Result<TypeValeur, Genre> {
    Ok(match octet {
        0x7F => TypeValeur::I32,
        0x7E => TypeValeur::I64,
        0x7D => TypeValeur::F32,
        0x7C => TypeValeur::F64,
        0x7B => return Err(Genre::NonPrisEnCharge), // v128 (SIMD)
        0x70 => TypeValeur::FuncRef,
        0x6F => TypeValeur::ExternRef,
        _ => return Err(Genre::TypeDeValeurInconnu(octet)),
    })
}

pub fn lire_type_reference(l: &mut Lecteur) -> Result<TypeValeur, Erreur> {
    match l.octet()? {
        0x70 => Ok(TypeValeur::FuncRef),
        0x6F => Ok(TypeValeur::ExternRef),
        _ => Err(Erreur { position: l.position() - 1, genre: Genre::ReferenceAttendue }),
    }
}

fn lire_type_bloc(l: &mut Lecteur) -> Result<TypeBloc, Erreur> {
    // 0x40 = vide ; un type de valeur tient sur un octet dont la valeur, lue
    // comme un s33, est négative ; sinon c'est un index de type.
    let position = l.position();
    let valeur = l.s33()?;
    if valeur < 0 {
        // Le type vide et les types de valeur s'écrivent sur UN octet. Un
        // négatif écrit sur plusieurs octets (C0 7F vaut aussi -64, comme
        // 0x40) n'est ni l'un, ni l'autre, ni un index : mal formé.
        if l.position() != position + 1 {
            return Err(Erreur { position, genre: Genre::TypeDeBlocMalForme });
        }
        if valeur == -0x40 {
            return Ok(TypeBloc::Vide);
        }
        // Sur un octet, (valeur & 0x7F) est l'octet d'origine.
        let octet = (valeur & 0x7F) as u8;
        return type_valeur(octet).map(TypeBloc::Valeur).map_err(|genre| Erreur { position, genre });
    }
    Ok(TypeBloc::Index(valeur as u32))
}

/// Les instructions memory.size, memory.grow... désignent la mémoire 0, la
/// seule en 2.0 ; l'octet qui suit est réservé à une future version
/// (plusieurs mémoires) et doit valoir 0.
fn zero(l: &mut Lecteur) -> Result<(), Erreur> {
    if l.octet()? != 0 {
        return Err(Erreur { position: l.position() - 1, genre: Genre::ZeroAttendu });
    }
    Ok(())
}

fn lire_arg_memoire(l: &mut Lecteur) -> Result<ArgMemoire, Erreur> {
    let position = l.position();
    let align = l.u32()?;
    // `align` est un exposant : 2^align doit tenir sur 32 bits. Au-delà,
    // c'est une erreur de format (les valeurs à partir de 64 sont réservées
    // à une future version, qui y codera un index de mémoire).
    if align >= 32 {
        return Err(Erreur { position, genre: Genre::AlignementMalForme });
    }
    let offset = l.u32()?;
    Ok(ArgMemoire { align, offset })
}

/// Lit une instruction et ses arguments immédiats.
pub fn lire_instruction(l: &mut Lecteur) -> Result<Instruction, Erreur> {
    let position = l.position();
    let code = l.octet()?;
    use Instruction::*;
    Ok(match code {
        0x00 => Unreachable,
        0x01 => Nop,
        0x02 => Block(lire_type_bloc(l)?),
        0x03 => Loop(lire_type_bloc(l)?),
        0x04 => If(lire_type_bloc(l)?),
        0x05 => Else,
        0x0B => End,
        0x0C => Br(l.u32()?),
        0x0D => BrIf(l.u32()?),
        0x0E => {
            let nombre = l.nombre()?;
            let cibles = l.position();
            // On lit les cibles une première fois pour vérifier leur format
            // et trouver la fin de l'instruction.
            for _ in 0..=nombre {
                l.u32()?;
            }
            BrTable { nombre, cibles }
        }
        0x0F => Return,
        0x10 => Call(l.u32()?),
        0x11 => {
            let type_fonction = l.u32()?;
            CallIndirect { type_fonction, table: l.u32()? }
        }
        0x1A => Drop,
        0x1B => Select,
        0x1C => {
            let nombre = l.nombre()?;
            let mut premier = None;
            for i in 0..nombre {
                let t = lire_type_valeur(l)?;
                if i == 0 {
                    premier = Some(t);
                }
            }
            SelectT { nombre, premier }
        }
        0x20 => LocalGet(l.u32()?),
        0x21 => LocalSet(l.u32()?),
        0x22 => LocalTee(l.u32()?),
        0x23 => GlobalGet(l.u32()?),
        0x24 => GlobalSet(l.u32()?),
        0x25 => TableGet(l.u32()?),
        0x26 => TableSet(l.u32()?),
        0x28..=0x3E => {
            let acces = self::Acces::depuis_opcode(code).expect("opcode d'acces memoire");
            Acces(acces, lire_arg_memoire(l)?)
        }
        0x3F => { zero(l)?; MemorySize }
        0x40 => { zero(l)?; MemoryGrow }
        0x41 => I32Const(l.s32()?),
        0x42 => I64Const(l.s64()?),
        0x43 => F32Const(l.f32()?),
        0x44 => F64Const(l.f64()?),
        0x45..=0xC4 => Op(self::Op::depuis_opcode(code as u32).expect("opcode numerique")),
        0xD0 => RefNull(lire_type_reference(l)?),
        0xD1 => RefIsNull,
        0xD2 => RefFunc(l.u32()?),
        0xFC => {
            let sous_code = l.u32()?;
            match sous_code {
                0..=7 => Op(self::Op::depuis_opcode(0xFC00 + sous_code).expect("conversion saturante")),
                8 => { let segment = l.u32()?; zero(l)?; MemoryInit(segment) }
                9 => DataDrop(l.u32()?),
                10 => { zero(l)?; zero(l)?; MemoryCopy }
                11 => { zero(l)?; MemoryFill }
                12 => { let segment = l.u32()?; TableInit { segment, table: l.u32()? } }
                13 => ElemDrop(l.u32()?),
                14 => { let destination = l.u32()?; TableCopy { destination, source: l.u32()? } }
                15 => TableGrow(l.u32()?),
                16 => TableSize(l.u32()?),
                17 => TableFill(l.u32()?),
                _ => return Err(Erreur { position, genre: Genre::InstructionFcInconnue(sous_code) }),
            }
        }
        // 0xFD : le préfixe des instructions SIMD.
        0xFD => return Err(Erreur { position, genre: Genre::NonPrisEnCharge }),
        _ => return Err(Erreur { position, genre: Genre::InstructionInconnue(code) }),
    })
}
