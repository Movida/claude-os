//! Les formats de fichiers que lit le noyau, et les tables que lui laisse
//! le micrologiciel (ACPI).
//!
//! Ces octets viennent de l'extérieur (le disque, un programme) : rien ne
//! garantit qu'ils sont bien formés. Un fichier tronqué ou piégé ne doit
//! jamais faire lire le noyau hors du fichier, ni le faire paniquer : chaque
//! champ est vérifié, chaque addition aussi, avant de s'en servir. Le
//! code de lecture est donc à part, dans cette bibliothèque :
//!   - sans `unsafe` (`forbid` : même pas permis localement) : un accès hors
//!     des octets reçus est impossible, au pire une erreur ;
//!   - testée sur la machine hôte, avec des fichiers corrompus exprès, et
//!     passée au fuzzing lors de la relecture de fin d'étape ; depuis 6c,
//!     des milliers de mutations au hasard de vrais exécutables font aussi
//!     partie des tests (tests/elf_reels.rs) ;
//!   - sans `alloc` : elle ne copie rien, elle rend des tranches des octets
//!     reçus.
//!
//! Comme l'interpréteur WebAssembly (../wasm), elle se compile aussi bien
//! pour la machine hôte que pour le noyau.

#![no_std]
#![forbid(unsafe_code)]

pub mod acpi;
pub mod commande;
pub mod cpio;
pub mod elf;
