//! Un module WebAssembly décodé : ce que contient un fichier .wasm.
//!
//! Un module est une liste de déclarations, regroupées par sections :
//! les types de fonctions, les imports, les fonctions, les tables, la
//! mémoire, les variables globales, les exports, la fonction de démarrage,
//! les segments d'éléments (de quoi remplir les tables) et de données (de
//! quoi remplir la mémoire), et le code.
//!
//! Le code des fonctions n'est PAS traduit : on garde ses octets d'origine,
//! et l'interpréteur les lira directement (« interprétation sur place »,
//! voir interpreteur.rs à la sous-étape 3). Le module ne retient donc que la
//! PLAGE de chaque corps de fonction et de chaque expression constante dans
//! les octets du fichier, qu'il garde avec lui.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// Les types de valeurs de WebAssembly 2.0 (sans SIMD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeValeur {
    I32,
    I64,
    F32,
    F64,
    /// Référence à une fonction (dans une table, ou une valeur opaque).
    FuncRef,
    /// Référence à un objet de l'environnement, opaque pour le programme.
    ExternRef,
}

impl TypeValeur {
    pub fn est_reference(self) -> bool {
        matches!(self, TypeValeur::FuncRef | TypeValeur::ExternRef)
    }
}

/// Les noms du format texte, pour les messages d'erreur.
impl fmt::Display for TypeValeur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            TypeValeur::I32 => "i32",
            TypeValeur::I64 => "i64",
            TypeValeur::F32 => "f32",
            TypeValeur::F64 => "f64",
            TypeValeur::FuncRef => "funcref",
            TypeValeur::ExternRef => "externref",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeFonction {
    pub parametres: Box<[TypeValeur]>,
    pub resultats: Box<[TypeValeur]>,
}

/// Taille minimale et maximale (facultative) d'une mémoire, en pages de
/// 64 Kio, ou d'une table, en éléments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limites {
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeTable {
    /// FuncRef ou ExternRef.
    pub element: TypeValeur,
    pub limites: Limites,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeGlobale {
    pub valeur: TypeValeur,
    pub modifiable: bool,
}

/// Une plage d'octets du module : [debut, fin[.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plage {
    pub debut: u32,
    pub fin: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptionImport {
    /// L'index du type de la fonction.
    Fonction(u32),
    Table(TypeTable),
    Memoire(Limites),
    Globale(TypeGlobale),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub module: String,
    pub nom: String,
    pub description: DescriptionImport,
}

/// Ce qu'un export désigne : un index dans l'espace des fonctions, tables,
/// mémoires ou globales (imports d'abord, puis définitions du module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptionExport {
    Fonction(u32),
    Table(u32),
    Memoire(u32),
    Globale(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub nom: String,
    pub description: DescriptionExport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Globale {
    pub type_globale: TypeGlobale,
    /// L'expression constante qui donne sa valeur initiale.
    pub init: Plage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeSegment {
    /// Copié dans la table (ou la mémoire) à l'instanciation, à la
    /// position donnée par l'expression constante.
    Actif { index: u32, decalage: Plage },
    /// Copié seulement à la demande (table.init, memory.init).
    Passif,
    /// Segments d'éléments seulement : déclare les fonctions qu'on a le
    /// droit de référencer avec ref.func, sans rien copier.
    Declaratif,
}

/// Un élément d'un segment d'éléments. Le format binaire a deux écritures :
/// une liste d'index de fonctions (la forme de la version 1.0, compacte), ou
/// une liste d'expressions constantes (ref.func n, ref.null, global.get).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Element {
    Fonction(u32),
    Expression(Plage),
}

/// De quoi remplir une table : une liste de références.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentElements {
    pub type_element: TypeValeur,
    pub elements: Vec<Element>,
    pub mode: ModeSegment,
}

/// De quoi remplir la mémoire : des octets bruts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentDonnees {
    pub octets: Plage,
    pub mode: ModeSegment,
}

/// Le corps d'une fonction définie par le module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Corps {
    /// Les variables locales, en plus des paramètres : (nombre, type).
    pub locales: Box<[(u32, TypeValeur)]>,
    /// Les instructions, jusqu'au `end` final compris.
    pub code: Plage,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Module {
    /// Les octets du fichier, que les plages désignent.
    pub octets: Box<[u8]>,
    pub types: Vec<TypeFonction>,
    pub imports: Vec<Import>,
    /// Pour chaque fonction définie par le module, l'index de son type.
    pub fonctions: Vec<u32>,
    pub tables: Vec<TypeTable>,
    pub memoires: Vec<Limites>,
    pub globales: Vec<Globale>,
    pub exports: Vec<Export>,
    pub demarrage: Option<u32>,
    pub elements: Vec<SegmentElements>,
    /// Le nombre de segments de données annoncé avant le code (section 12) :
    /// il permet de valider memory.init et data.drop en une seule passe.
    pub nombre_donnees: Option<u32>,
    pub corps: Vec<Corps>,
    pub donnees: Vec<SegmentDonnees>,
    /// La position de chaque section, indexée par son numéro (0 si elle est
    /// absente). Le validateur s'en sert pour situer ses erreurs sur les
    /// déclarations, dont on ne garde pas la position une à une.
    pub sections: [u32; 13],
}

impl Module {
    /// Les octets d'une plage.
    pub fn tranche(&self, plage: Plage) -> &[u8] {
        &self.octets[plage.debut as usize..plage.fin as usize]
    }
}
