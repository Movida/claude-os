//! Le contexte réseau (6h) : la règle du softirq de Linux, pour la
//! livraison par `lo`.
//!
//! En 6g, ce qui part par `lo` est livré tout de suite, dans l'appel de
//! l'émetteur (boucle.rs) : un datagramme envoyé à soi-même est là quand
//! `sendto` revient. Mais on émet aussi en RECEVANT : la réponse à un écho,
//! une erreur ICMP, et avec TCP, l'ACK qu'envoie une socket sous son verrou
//! court, ou un minuteur. Livrer à cet endroit ferait revenir la réponse
//! de l'autre côté à la même socket, dans le même appel, sous un verrou
//! déjà pris : une panique (« verrou deja pris »), ou une réception au
//! milieu d'un traitement qui n'est pas fini.
//!
//! Linux ne le connaît pas : `loopback_xmit` met en file (`netif_rx`), et
//! la file n'est vidée qu'à la sortie du softirq, ou au `local_bh_enable`
//! de qui avait coupé les softirqs. Ici, pas de softirq : un compteur PAR
//! TÂCHE (`Tache::contexte_reseau`), monté par un garde (`entrer`) autour
//! de tout ce qui reçoit ou peut émettre sous un verrou court (le passage
//! de la tâche du réseau, le vidage de `lo`, puis les verrous courts de
//! TCP) ; tant qu'il n'est pas nul, `lo` ne fait que déposer ; quand il
//! retombe à zéro, la file de `lo` est vidée (le `local_bh_enable`).
//!
//! Pourquoi par tâche, quand Linux compte par processeur : Linux ne
//! préempte pas une tâche qui a coupé les softirqs ; la nôtre peut l'être
//! (la tâche du réseau reçoit interruptions permises). Un compteur du
//! processeur ferait alors attendre, pour rien, l'envoi d'une autre tâche
//! jusqu'à ce que la première reprenne. Ce qu'il faut éviter est la
//! réentrance DANS UN MÊME fil d'exécution : c'est une affaire de tâche.

use crate::tache;
use core::sync::atomic::Ordering;

/// Tant qu'il existe, la tâche courante est dans le contexte réseau.
pub struct Garde(());

/// Entre dans le contexte réseau (le `local_bh_disable`).
pub fn entrer() -> Garde {
    tache::courante().contexte_reseau.fetch_add(1, Ordering::Relaxed);
    Garde(())
}

/// La tâche courante est-elle dans le contexte réseau ?
pub fn actif() -> bool {
    tache::courante().contexte_reseau.load(Ordering::Relaxed) != 0
}

/// Fait `f` dans le contexte réseau, sans vider `lo` en sortant : pour le
/// vidage de `lo` lui-même, qui reprend la file jusqu'à la trouver vide.
pub fn pendant<R>(f: impl FnOnce() -> R) -> R {
    let t = tache::courante();
    t.contexte_reseau.fetch_add(1, Ordering::Relaxed);
    let r = f();
    t.contexte_reseau.fetch_sub(1, Ordering::Relaxed);
    r
}

impl Drop for Garde {
    /// En sort ; au dernier garde, ce que `lo` a reçu entre-temps est livré
    /// (le `local_bh_enable`, qui fait les softirqs en attente).
    fn drop(&mut self) {
        if tache::courante().contexte_reseau.fetch_sub(1, Ordering::Relaxed) == 1 {
            super::boucle::vider_en_attente();
        }
    }
}
