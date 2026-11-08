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

/// Le processeur qui panique (ou dont l'exception est fatale), plus un ;
/// 0 : aucun. Le premier qui arrive gagne : les autres, s'ils paniquent en
/// même temps (un NMI du moniteur de QEMU va à TOUS les processeurs
/// virtuels ; une exception fatale sur un processeur pendant qu'un autre
/// panique), s'arrêtent sans rien dire, sinon leurs messages se mêleraient
/// (le `panic_cpu` et le `stopping_cpu` de Linux). Le gagnant arrête
/// ensuite tous les autres (smp::arreter_les_autres) avant d'écrire. Et
/// combien de fois le gagnant est entré ici (ENTREES) : une exception
/// fatale écrit ses registres puis panique (deux entrées) ; une panique
/// pendant l'affichage de la panique (un bogue dans la console elle-même)
/// recommencerait sans fin : à la troisième entrée, on s'arrête sans rien
/// dire. (Jusqu'à la relecture de 6j, un second mot, `EN_PANIQUE` dans
/// main.rs, disait « quelqu'un a déjà paniqué » sans dire qui : le gagnant
/// d'ici pouvait se taire parce qu'un perdant l'avait posé, et le perdant
/// s'arrêtait sans poser `arrete`, ce qui coûtait au gagnant une seconde
/// d'attente et un NMI.)
static PANIQUE_PAR: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static ENTREES: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Ce processeur est-il celui qui panique ? Pour le gestionnaire du NMI
/// (interruptions.rs) : un NMI reçu pendant qu'on écrit le message de la
/// panique (celui du moniteur de QEMU, qui frappe tous les processeurs) ne
/// doit pas nous arrêter. Interruptions coupées.
pub fn je_panique() -> bool {
    PANIQUE_PAR.load(core::sync::atomic::Ordering::Relaxed) == crate::processeur::numero() + 1
}

/// Prépare la console pour le message d'une panique. Ne revient que sur le
/// premier processeur qui panique (voir PANIQUE_PAR), deux fois au plus ;
/// les autres s'arrêtent ici.
///
/// Si la panique (ou l'exception fatale) est survenue PENDANT un affichage,
/// le verrou de l'écran est encore pris par le code qui a planté : le
/// message de panique l'attendrait pour toujours, et la machine se
/// figerait sans un mot. Comme Linux pendant un « oops » (bust_spinlocks,
/// puis zap_locks pour sa console), on remet le verrou à neuf : le code
/// interrompu ne reprendra jamais, au pire l'écran montrera une ligne à
/// moitié écrite. (Les autres processeurs, qui pourraient tenir ce verrou
/// ou l'attendre, sont arrêtés d'abord, smp::arreter_les_autres : l'IPI
/// d'arrêt, puis un NMI à ceux qui tournaient interruptions coupées.)
pub fn preparer_panique() {
    use core::sync::atomic::Ordering;
    crate::cpu::couper_interruptions();
    let moi = crate::processeur::numero() + 1;
    if PANIQUE_PAR.compare_exchange(0, moi, Ordering::AcqRel, Ordering::Acquire).is_err() && PANIQUE_PAR.load(Ordering::Relaxed) != moi {
        crate::smp::s_arreter();
    }
    if ENTREES.fetch_add(1, Ordering::Relaxed) >= 2 {
        crate::cpu::arreter();
    }
    crate::smp::arreter_les_autres();
    // Les autres processeurs sont arrêtés, au mieux : `arreter_les_autres`
    // a attendu leur `arrete` une seconde, puis dix millisecondes après un
    // NMI ; un processeur qui ne répond toujours pas (figé par
    // l'hyperviseur, ou par une erreur plus grave que la nôtre) pourrait
    // tenir encore ce verrou, et son écriture se mêler à notre message :
    // le prix d'un message qui part quoi qu'il arrive.
    // SAFETY: on ne revient pas de la panique, et les autres processeurs
    // sont arrêtés (voir ci-dessus) : le détenteur éventuel du verrou ne
    // reprendra jamais la main.
    unsafe { ECRAN.forcer_liberation() };
}

/// Un message d'urgence, sur le port série seul, SANS verrou : pour qui ne
/// peut en prendre aucun, parce que c'est peut-être celui de la console
/// qu'il attend (un `Verrou` attendu trop longtemps, verrou.rs). Les octets
/// peuvent se mêler à ceux d'un autre processeur : c'est le prix d'un
/// message qui part quoi qu'il arrive (le `printk` d'urgence de Linux
/// écrit de même, directement, quand sa console est perdue).
pub fn urgence(args: fmt::Arguments) {
    let _ = Serie.write_fmt(args);
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
