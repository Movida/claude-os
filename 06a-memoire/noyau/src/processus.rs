//! Le processus en cours : ce que les appels système d'un programme Linux
//! doivent pouvoir modifier (sa mémoire : zones, tables de pages, tas).
//! C'est une toute petite partie de la task_struct de Linux.
//!
//! Le noyau le range ici le temps de l'exécution (tache::executer), et le
//! reprend ensuite pour le détruire. Un seul processus à la fois : un
//! Verrou<Option<...>> ; l'ordonnanceur de l'étape 6 en fera une liste.
//!
//! Règle : jamais de copie depuis ou vers la mémoire du programme sous ce
//! verrou (une copie peut fauter, et plus tard attendre le disque). On y
//! lit ou change l'état, on rend le verrou, puis on copie.

use crate::memoire::Memoire;
use crate::verrou::Verrou;

pub struct Processus {
    /// Sa mémoire (la mm_struct de Linux, voir memoire.rs).
    pub memoire: Memoire,
}

static COURANT: Verrou<Option<Processus>> = Verrou::new(None);

/// Le processus devient le processus en cours.
pub fn installer(processus: Processus) {
    *COURANT.verrouiller() = Some(processus);
}

/// Reprend le processus en cours (pour le détruire).
pub fn retirer() -> Option<Processus> {
    COURANT.verrouiller().take()
}

/// Exécute `f` sur le processus en cours (il y en a toujours un pendant un
/// appel système), verrou tenu : `f` doit être court, et ne pas toucher à
/// la mémoire du programme par ses adresses.
pub fn avec<R>(f: impl FnOnce(&mut Processus) -> R) -> R {
    let mut courant = COURANT.verrouiller();
    f(courant.as_mut().expect("appel systeme sans processus en cours"))
}

/// Comme `avec`, s'il y a un processus en cours : une faute de page du
/// noyau peut arriver sans lui (le test du démarrage, dans main.rs).
pub fn essayer_avec<R>(f: impl FnOnce(&mut Processus) -> R) -> Option<R> {
    COURANT.verrouiller().as_mut().map(f)
}
