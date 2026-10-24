//! Les limites de notre implémentation.
//!
//! La spécification décrit des modules aussi grands qu'on veut : 4 milliards
//! de fonctions, de variables locales, de paramètres... Aucune machine ne
//! les tient, et un module malveillant de quelques octets peut en annoncer
//! autant. Son annexe « Implementation Limitations » permet donc à chaque
//! implémentation de fixer ses propres limites, et de refuser les modules
//! qui les dépassent.
//!
//! Elles ont deux rôles :
//!   - garantir que le décodeur et le validateur ne paniquent jamais et ne
//!     réservent jamais une quantité de mémoire sans rapport avec la taille
//!     du module : le noyau les fera tourner sur des programmes qu'il ne
//!     connaît pas ;
//!   - rendre exacts les calculs sur 32 bits (positions, tailles).

use core::fmt;

// Les limites qui suivent sont celles de l'interface JavaScript de
// WebAssembly (sa section « Limits »), que respectent tous les navigateurs
// et wasmtime : les compilateurs (rustc, clang) restent loin en dessous, et
// un module qu'un navigateur accepte, on l'accepte aussi.

/// Taille maximale d'un module : 1 Gio. Les positions dans le module
/// (`Plage`, sur 32 bits) ne débordent donc jamais.
pub const TAILLE_MODULE_MAX: usize = 1 << 30;

/// Taille maximale du corps d'une fonction. Elle borne le travail et la
/// mémoire que la validation d'une seule fonction peut demander.
pub const TAILLE_CORPS_MAX: usize = 7_654_321;

/// Nombre maximal de paramètres d'un type de fonction (donc d'un bloc).
pub const PARAMETRES_MAX: usize = 1000;

/// Nombre maximal de résultats d'un type de fonction (donc d'un bloc).
pub const RESULTATS_MAX: usize = 1000;

/// Nombre maximal de variables locales d'une fonction, paramètres compris.
/// Sans limite, un module de quelques octets peut en déclarer 4 milliards :
/// l'interpréteur devrait toutes les mettre à zéro à chaque appel.
pub const LOCALES_MAX: usize = 50_000;

/// Hauteur maximale de la pile d'opérandes d'une fonction : une limite à
/// nous, que l'interface JavaScript n'a pas. Cette hauteur n'est pas bornée
/// par la taille du code : un `call` de deux octets vers une fonction à
/// 1000 résultats empile 1000 valeurs, et quelques Kio de tels appels
/// feraient réserver des Gio au validateur, puis à l'interpréteur. La
/// machine virtuelle Java a la même limite (max_stack, sur 16 bits) ; le
/// code des compilateurs dépasse rarement quelques centaines.
pub const HAUTEUR_PILE_MAX: usize = 1 << 16;

/// Une limite dépassée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limite {
    TailleModule,
    TailleCorps,
    Parametres,
    Resultats,
    Locales,
    HauteurPile,
}

impl fmt::Display for Limite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Limite::TailleModule => write!(f, "module de plus de {TAILLE_MODULE_MAX} octets"),
            Limite::TailleCorps => write!(f, "corps de fonction de plus de {TAILLE_CORPS_MAX} octets"),
            Limite::Parametres => write!(f, "type de fonction a plus de {PARAMETRES_MAX} parametres"),
            Limite::Resultats => write!(f, "type de fonction a plus de {RESULTATS_MAX} resultats"),
            Limite::Locales => write!(f, "fonction a plus de {LOCALES_MAX} variables locales"),
            Limite::HauteurPile => write!(f, "fonction qui empile plus de {HAUTEUR_PILE_MAX} valeurs"),
        }
    }
}
