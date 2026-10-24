//! Les erreurs de lecture d'un module.
//!
//! La spécification distingue trois sortes de modules refusés, que la suite
//! de tests vérifie séparément :
//!   - mal formé (malformed) : les octets ne respectent pas le format binaire
//!     (c'est ce module) ;
//!   - invalide (invalid) : bien formé, mais les types ne collent pas
//!     (le validateur, sous-étape 2) ;
//!   - non liable (unlinkable) : les imports ne correspondent pas à ce que
//!     l'environnement fournit (l'instanciation, sous-étape 3).
//!
//! Les messages n'ont pas d'accents : le noyau les affichera avec la police
//! du BIOS (page de code 437).

use core::fmt;

use crate::limites::Limite;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erreur {
    /// Position de l'octet fautif dans le module.
    pub position: usize,
    pub genre: Genre,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Genre {
    FinInattendue,
    EntierTropLong,
    EntierTropGrand,
    Utf8Invalide,
    MagiqueAbsent,
    VersionInconnue,
    SectionInconnue(u8),
    SectionDansLeDesordre(u8),
    TailleDeSection,
    TypeDeValeurInconnu(u8),
    TypeDeBlocMalForme,
    TypeDeFonctionAttendu,
    ReferenceAttendue,
    LimitesInconnues(u8),
    MutabiliteInconnue(u8),
    GenreDImportInconnu(u8),
    GenreDExportInconnu(u8),
    SegmentDElementsInconnu(u32),
    SegmentDeDonneesInconnu(u32),
    ZeroAttendu,
    AlignementMalForme,
    TropDeVariablesLocales,
    FinDeFonctionAttendue,
    InstructionInconnue(u8),
    InstructionFcInconnue(u32),
    FonctionsEtCodeIncoherents,
    NombreDeDonneesIncoherent,
    SectionDeNombreDeDonneesRequise,
    /// Bien formé, mais hors de ce que l'interpréteur sait faire (SIMD).
    NonPrisEnCharge,
    /// Au-delà d'une limite de notre implémentation (limites.rs).
    LimiteDepassee(Limite),
}

impl fmt::Display for Genre {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Genre::FinInattendue => write!(f, "fin inattendue des octets"),
            Genre::EntierTropLong => write!(f, "entier LEB128 trop long"),
            Genre::EntierTropGrand => write!(f, "entier trop grand pour son type"),
            Genre::Utf8Invalide => write!(f, "nom qui n'est pas de l'UTF-8 valide"),
            Genre::MagiqueAbsent => write!(f, "pas de signature \\0asm"),
            Genre::VersionInconnue => write!(f, "version du format inconnue"),
            Genre::SectionInconnue(id) => write!(f, "section inconnue ({id})"),
            Genre::SectionDansLeDesordre(id) => write!(f, "section {id} en double ou dans le desordre"),
            Genre::TailleDeSection => write!(f, "taille de section incoherente"),
            Genre::TypeDeValeurInconnu(o) => write!(f, "type de valeur inconnu ({o:#04x})"),
            Genre::TypeDeBlocMalForme => write!(f, "type de bloc mal forme"),
            Genre::TypeDeFonctionAttendu => write!(f, "type de fonction attendu (0x60)"),
            Genre::ReferenceAttendue => write!(f, "type reference attendu"),
            Genre::LimitesInconnues(o) => write!(f, "drapeau de limites inconnu ({o:#04x})"),
            Genre::MutabiliteInconnue(o) => write!(f, "mutabilite inconnue ({o:#04x})"),
            Genre::GenreDImportInconnu(o) => write!(f, "genre d'import inconnu ({o:#04x})"),
            Genre::GenreDExportInconnu(o) => write!(f, "genre d'export inconnu ({o:#04x})"),
            Genre::SegmentDElementsInconnu(o) => write!(f, "segment d'elements de genre inconnu ({o})"),
            Genre::SegmentDeDonneesInconnu(o) => write!(f, "segment de donnees de genre inconnu ({o})"),
            Genre::ZeroAttendu => write!(f, "octet nul attendu"),
            Genre::AlignementMalForme => write!(f, "alignement d'acces memoire mal forme"),
            Genre::TropDeVariablesLocales => write!(f, "trop de variables locales"),
            Genre::FinDeFonctionAttendue => write!(f, "instruction end attendue en fin de fonction"),
            Genre::InstructionInconnue(o) => write!(f, "instruction inconnue ({o:#04x})"),
            Genre::InstructionFcInconnue(o) => write!(f, "instruction 0xfc inconnue ({o})"),
            Genre::FonctionsEtCodeIncoherents => write!(f, "sections de fonctions et de code incoherentes"),
            Genre::NombreDeDonneesIncoherent => write!(f, "nombre de segments de donnees incoherent"),
            Genre::SectionDeNombreDeDonneesRequise => write!(f, "section du nombre de donnees requise"),
            Genre::NonPrisEnCharge => write!(f, "fonctionnalite non prise en charge (SIMD)"),
            Genre::LimiteDepassee(limite) => write!(f, "limite de l'interpreteur depassee : {limite}"),
        }
    }
}

impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "octet {:#x} : {}", self.position, self.genre)
    }
}
