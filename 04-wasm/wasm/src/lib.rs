//! Un interpréteur WebAssembly 2.0 (sans SIMD), écrit pour notre noyau.
//!
//! WebAssembly sera le format natif des programmes de l'OS (voir CLAUDE.md).
//! Un programme .wasm ne voit que sa propre mémoire (un tableau d'octets)
//! et les fonctions que le noyau lui donne : il ne peut ni lire la mémoire
//! du noyau, ni sauter n'importe où. Cette isolation ne dépend pas du
//! processeur (pagination, anneaux de protection) mais de la VÉRIFICATION
//! du code avant de l'exécuter : c'est le « bac à sable » logiciel, comme
//! dans le projet Nebulet.
//!
//! Les étapes, dans l'ordre de la spécification :
//!   1. décoder : des octets au module (decodeur.rs) ;
//!   2. valider : vérifier les types de chaque instruction (validateur.rs) ;
//!   3. instancier : créer ses objets dans le magasin et le relier aux
//!      autres modules (magasin.rs, instanciation.rs) ;
//!   4. exécuter ses fonctions (interpreteur.rs, numerique.rs).
//!
//! La bibliothèque n'utilise que `core` et `alloc` : elle se compile pour
//! la machine hôte, où on la teste avec la suite de tests officielle
//! (tests/suite.rs), et pour notre noyau.

#![no_std]

extern crate alloc;

pub mod decodeur;
pub mod erreur;
pub mod flottants;
pub mod instanciation;
pub mod instructions;
mod interpreteur;
pub mod lecteur;
pub mod limites;
pub mod magasin;
pub mod module;
mod numerique;
pub mod validateur;

pub use decodeur::decoder;
pub use erreur::Erreur;
pub use instanciation::ErreurInstanciation;
pub use magasin::{Externe, Hote, Magasin, Piege, Valeur};
pub use module::Module;
pub use validateur::{ModuleValide, valider};
