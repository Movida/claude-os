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

/// Prépare la console pour le message d'une panique.
///
/// Si la panique (ou l'exception fatale) est survenue PENDANT un affichage,
/// le verrou de l'écran est encore pris par le code qui a planté : le
/// message de panique l'attendrait pour toujours, et la machine se
/// figerait sans un mot. Comme Linux pendant un « oops » (bust_spinlocks),
/// on force la libération : le code interrompu ne reprendra jamais, au pire
/// l'écran montrera une ligne à moitié écrite.
pub fn preparer_panique() {
    crate::cpu::couper_interruptions();
    // SAFETY : on ne revient pas de la panique, le détenteur éventuel du
    // verrou ne reprendra jamais la main.
    unsafe { ECRAN.forcer_liberation() };
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
