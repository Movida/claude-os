//! Les allocations qui peuvent échouer : la bibliothèque faillible/ (le
//! module du noyau jusqu'aux soldes d'avant 6k, devenu une bibliothèque que
//! partagent les autres). Ce module la rend sous son ancien nom, pour les
//! cent endroits du noyau qui l'appellent `crate::faillible`.

pub use ::faillible::*;
