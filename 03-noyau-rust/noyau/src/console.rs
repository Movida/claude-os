//! La console du noyau : tout ce qu'on affiche va à la fois à l'écran et
//! sur le port série, comme dans le chargeur.

use crate::serie::Serie;
use crate::verrou::Verrou;
use crate::vga::Ecran;
use core::fmt::{self, Write};

static ECRAN: Verrou<Ecran> = Verrou::new(Ecran::new());

pub fn initialiser() {
    crate::serie::initialiser();
    // Le noyau prend possession de l'écran : les lignes du chargeur restent
    // lisibles sur le port série.
    ECRAN.verrouiller().effacer();
}

/// Appelée par les macros afficher! et afficherln!.
pub fn _afficher(args: fmt::Arguments) {
    let mut ecran = ECRAN.verrouiller();
    // Le port série n'a pas d'état à protéger, mais on l'écrit sous le même
    // verrou pour que les deux sorties gardent le même ordre.
    let _ = Serie.write_fmt(args);
    let _ = ecran.write_fmt(args);
}

/// Comme print! de la bibliothèque standard, qu'on n'a pas.
#[macro_export]
macro_rules! afficher {
    ($($arg:tt)*) => { $crate::console::_afficher(format_args!($($arg)*)) };
}

/// Comme println!.
#[macro_export]
macro_rules! afficherln {
    () => { $crate::afficher!("\n") };
    ($($arg:tt)*) => { $crate::afficher!("{}\n", format_args!($($arg)*)) };
}
