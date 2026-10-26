//! La console du noyau : tout ce qu'on affiche va à la fois à l'écran et
//! sur le port série, comme dans le chargeur.

use crate::attente::{GardeMutex, Mutex};
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

/// Le verrou des écritures, tenu pendant tout un `write` d'un programme et
/// tout un message du noyau : deux programmes qui écrivent en même temps
/// ne mêlent pas leurs lignes (le `atomic_write_lock` des terminaux de
/// Linux, tenu pendant tout `tty_write`). Un verrou qui dort (attente.rs) :
/// l'écriture d'une ligne sur un vrai port série dure des millisecondes.
/// Le verrou de l'écran, lui, n'est pris que par paquets de 8 octets pour
/// la sortie d'un programme (`ecrire_octets`), pour que l'horloge ne perde
/// pas ses tics ; un message du noyau, court, est écrit d'un coup.
static ECRITURES: Mutex<()> = Mutex::new(());

/// Le verrou des écritures, quand on a le droit de dormir pour l'attendre :
/// les tâches existent, et les interruptions sont actives (donc aucun
/// Verrou n'est tenu, et on n'est pas dans un gestionnaire d'interruption).
/// Sinon (le démarrage, un gestionnaire, une panique), on écrit sans lui :
/// un message du noyau ne doit jamais attendre (comme printk).
fn verrou_des_ecritures() -> Option<GardeMutex<'static, ()>> {
    (crate::tache::en_service() && crate::cpu::interruptions_actives()).then(|| ECRITURES.verrouiller())
}

/// Appelée par les macros afficher! et afficherln!.
pub fn _afficher(args: fmt::Arguments) {
    let _ecritures = verrou_des_ecritures();
    let mut ecran = ECRAN.verrouiller();
    // Le port série n'a pas d'état à protéger, mais on l'écrit sous le même
    // verrou pour que les deux sorties gardent le même ordre.
    let _ = Serie.write_fmt(args);
    let _ = ecran.write_fmt(args);
}

/// Écrit des octets tels quels, la sortie d'un programme par exemple : ils
/// ne sont pas forcément du texte valide, on ne les interprète pas. Par
/// paquets de 8 octets, en rendant le verrou (et donc les interruptions)
/// entre deux : sur un vrai port série, chaque octet fait attendre 87 µs,
/// et l'horloge ne doit pas manquer ses tics (un par milliseconde).
pub fn ecrire_octets(octets: &[u8]) {
    let _ecritures = verrou_des_ecritures();
    for paquet in octets.chunks(8) {
        let mut ecran = ECRAN.verrouiller();
        for &octet in paquet {
            crate::serie::ecrire_octet(octet);
            ecran.ecrire_octet(octet);
        }
    }
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
