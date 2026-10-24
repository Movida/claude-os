//! Les erreurs de lecture d'un module.
//!
//! La spécification distingue trois sortes de modules refusés, que la suite
//! de tests vérifie séparément :
//!   - mal formé (malformed) : les octets ne respectent pas le format binaire
//!     (le décodeur) ;
//!   - invalide (invalid) : bien formé, mais les types ne collent pas, ou un
//!     index ne désigne rien (le validateur) ;
//!   - non liable (unlinkable) : les imports ne correspondent pas à ce que
//!     l'environnement fournit (l'instanciation, sous-étape 3).
//!
//! Les messages n'ont pas d'accents : le noyau les affichera avec la police
//! du BIOS (page de code 437).

use core::fmt;

use crate::limites::Limite;
use crate::module::TypeValeur;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erreur {
    /// Position de l'octet fautif dans le module. Pour une déclaration dont
    /// le décodeur n'a pas gardé la position (un import, un export, une
    /// limite...), celle du début de sa section.
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

    // Les genres suivants sont ceux d'un module bien formé mais invalide
    // (validateur.rs).
    /// Un index qui ne désigne rien.
    IndexInconnu(Espace, u32),
    /// Une instruction ne trouve pas sur la pile le type qu'elle attend.
    TypeInattendu { attendu: TypeValeur, trouve: TypeValeur },
    /// Une instruction attend une valeur, mais la pile du bloc est vide.
    PileVide,
    /// Un bloc, une fonction ou une expression constante se termine avec
    /// des valeurs en trop sur la pile.
    ValeursEnTrop,
    /// ref.is_null sur une valeur qui n'est pas une référence.
    ReferenceRequise(TypeValeur),
    /// select sans type sur une valeur qui n'est pas un nombre.
    NombreRequis(TypeValeur),
    /// select t* : la liste doit contenir exactement un type.
    TypesDuSelect(u32),
    /// br_table : toutes les cibles doivent recevoir autant de valeurs.
    CiblesIncompatibles,
    ElseSansIf,
    /// L'alignement promis dépasse la taille de l'accès.
    AlignementTropGrand,
    ExpressionNonConstante,
    GlobaleNonModifiable(u32),
    /// ref.func d'une fonction qui n'est mentionnée nulle part hors du code.
    ReferenceNonDeclaree(u32),
    PlusieursMemoires,
    MemoireTropGrande,
    LimitesInversees,
    /// L'export de cet index porte le nom d'un export précédent.
    ExportEnDouble(u32),
    FonctionDeDemarrage,
}

/// Les espaces d'index d'un module : chaque genre de déclaration est
/// numéroté à part (la fonction 3 et la table 3 n'ont rien à voir).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Espace {
    Type,
    Fonction,
    Table,
    Memoire,
    Globale,
    Locale,
    /// Les étiquettes des blocs englobants, numérotées de l'intérieur
    /// (0 = le bloc le plus proche).
    Etiquette,
    Elements,
    Donnees,
}

impl fmt::Display for Espace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Espace::Type => "type",
            Espace::Fonction => "fonction",
            Espace::Table => "table",
            Espace::Memoire => "memoire",
            Espace::Globale => "globale",
            Espace::Locale => "variable locale",
            Espace::Etiquette => "etiquette",
            Espace::Elements => "segment d'elements",
            Espace::Donnees => "segment de donnees",
        })
    }
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
            Genre::IndexInconnu(espace, index) => write!(f, "index {index} inconnu ({espace})"),
            Genre::TypeInattendu { attendu, trouve } => write!(f, "{attendu} attendu, {trouve} trouve"),
            Genre::PileVide => write!(f, "pile vide : il manque une valeur"),
            Genre::ValeursEnTrop => write!(f, "valeurs en trop sur la pile en fin de bloc"),
            Genre::ReferenceRequise(t) => write!(f, "reference attendue, {t} trouve"),
            Genre::NombreRequis(t) => write!(f, "select sans type : nombre attendu, {t} trouve"),
            Genre::TypesDuSelect(n) => write!(f, "select : un seul type attendu, {n} donnes"),
            Genre::CiblesIncompatibles => write!(f, "br_table : cibles qui recoivent des nombres de valeurs differents"),
            Genre::ElseSansIf => write!(f, "else sans if"),
            Genre::AlignementTropGrand => write!(f, "alignement plus grand que la taille de l'acces"),
            Genre::ExpressionNonConstante => write!(f, "expression constante requise"),
            Genre::GlobaleNonModifiable(index) => write!(f, "globale {index} non modifiable"),
            Genre::ReferenceNonDeclaree(index) => write!(f, "ref.func {index} : fonction non declaree hors du code"),
            Genre::PlusieursMemoires => write!(f, "plus d'une memoire (une seule en WebAssembly 2.0)"),
            Genre::MemoireTropGrande => write!(f, "memoire de plus de 65536 pages (4 Gio)"),
            Genre::LimitesInversees => write!(f, "limites : minimum plus grand que le maximum"),
            Genre::ExportEnDouble(index) => write!(f, "export {index} : nom deja exporte"),
            Genre::FonctionDeDemarrage => write!(f, "fonction de demarrage : type [] -> [] attendu"),
        }
    }
}

impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "octet {:#x} : {}", self.position, self.genre)
    }
}
