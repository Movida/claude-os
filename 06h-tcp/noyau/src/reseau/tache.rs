//! La tâche du réseau : le travail que les interruptions des cartes lui
//! laissent.
//!
//! Une interruption doit rendre la main vite, interruptions coupées : celle
//! d'une carte réseau ne fait que noter ce qui l'a levée (un changement de
//! lien, des trames reçues, des émissions finies) et réveiller cette tâche,
//! qui fait le travail ensuite, interruptions permises, préemptible comme
//! une autre. C'est ce que fait Linux de deux façons, que cette tâche
//! réunit : le « linkwatch » (une tâche différée qui suit l'état du lien
//! des cartes) et, depuis Linux 5.12, le NAPI « threaded » (la réception
//! faite dans un fil du noyau plutôt que dans un softirq). Option écartée :
//! un mécanisme de softirq, à la sortie de chaque interruption, avec sa
//! tâche de repli (ksoftirqd) quand il y a trop à faire : une tâche seule
//! suffit, et l'ordonnanceur (6e) la partage avec les programmes.
//!
//! NAPI (« New API », Linux 2.6) : une carte qui interrompt coupe ses
//! interruptions de réception, et la tâche vide son anneau par lots, au
//! plus 64 trames à la fois (le `napi_poll` et son poids, NAPI_POLL_WEIGHT)
//! avant de passer à l'interface suivante ; une interface qui n'a pas fini
//! est reprise au tour suivant. Une rafale coûte une interruption, pas une
//! par trame.
//!
//! Les minuteurs du réseau : une liste d'échéances, une par objet (la
//! table des voisins, arp.rs ; puis les connexions TCP), inet::echeances.
//! La tâche dort jusqu'à la plus proche, ou un réveil, et fait le travail
//! des objets échus.
//!
//! Sans réveil perdu : le travail est un mot de bits, sous un verrou ; une
//! interruption pose son bit puis réveille ; la tâche prend le mot, et ne
//! s'endort que s'il est vide, en s'inscrivant dans la file d'attente
//! interruptions coupées, comme celle du clavier.

use super::interface;
use crate::attente::{self, FileAttente, Sommeil};
use crate::programmes::NomCourt;
use crate::verrou::Verrou;
use crate::{cpu, tache, temps};
use inet::echeances::Echeances;

/// Du travail à faire : un changement dans la configuration d'une carte
/// (son lien).
pub const CONFIGURATION: u32 = 1 << 0;
/// Une échéance a été armée : recalculer le sommeil.
const ECHEANCE: u32 = 1 << 1;
/// Le travail d'une interface (sa réception, ses émissions finies) : le
/// bit `INTERFACES << index`.
const INTERFACES: u32 = 1 << 8;
/// Le nombre de trames reçues traitées d'une interface avant de passer à la
/// suivante (le poids de NAPI).
const BUDGET: usize = 64;

struct Travail {
    a_faire: u32,
    /// La tâche fait le travail qu'elle a pris (de la prise jusqu'à son
    /// retour dans `attendre`, qui le revoit vide avant de dormir).
    en_travail: bool,
    attente: FileAttente,
}

static TRAVAIL: Verrou<Travail> = Verrou::new(Travail { a_faire: 0, en_travail: false, attente: FileAttente::new() });

/// Signale du travail à la tâche du réseau (depuis une interruption, ou
/// d'ailleurs), et la réveille.
pub fn signaler(travail: u32) {
    let mut t = TRAVAIL.verrouiller();
    t.a_faire |= travail;
    t.attente.reveiller_toutes();
}

/// Signale du travail pour l'interface de numéro `index` (0 : pas encore
/// d'interface, rien).
pub fn signaler_interface(index: u32) {
    if (1..=16).contains(&index) {
        signaler(INTERFACES << (index - 1));
    }
}

/// La tâche n'a-t-elle aucun travail, ni en attente, ni en cours ?
pub fn au_repos() -> bool {
    let t = TRAVAIL.verrouiller();
    t.a_faire == 0 && !t.en_travail
}

/// Prend le travail en attente, en dormant tant qu'il n'y en a pas, et au
/// plus jusqu'à `echeance` (alors rien : c'est l'heure des minuteurs).
fn attendre(echeance: Option<u64>) -> u32 {
    let interruptions = cpu::couper_interruptions();
    let travail = loop {
        let mut t = TRAVAIL.verrouiller();
        if t.a_faire != 0 || echeance.is_some_and(|e| e <= temps::ns_monotone()) {
            t.en_travail = true;
            break core::mem::take(&mut t.a_faire);
        }
        t.en_travail = false;
        t.attente.inscrire();
        drop(t);
        attente::dormir(echeance, Sommeil::Ininterruptible);
        TRAVAIL.verrouiller().attente.retirer(tache::courante());
    };
    if interruptions {
        cpu::activer_interruptions();
    }
    travail
}

/// Lance la tâche du réseau.
pub fn lancer() {
    if tache::lancer_noyau(NomCourt::de(b"reseau"), boucle).is_none() {
        afficherln!("[reseau] pas de pile pour la tache du reseau : les cartes restent muettes.");
    }
}

/// Les échéances du réseau (inet::echeances) : quand se réveiller, et
/// pour qui. Faites au démarrage, à leur taille définitive.
static ECHEANCES: Verrou<Option<Echeances>> = Verrou::new(None);
/// Le nombre d'objets qui peuvent avoir une échéance à la fois.
const MAX_ECHEANCES: usize = 64;
/// L'objet « table des voisins » (arp.rs) ; les connexions TCP prendront
/// le numéro de leur socket, qui part de 1.
pub const OBJET_VOISINS: u64 = u64::MAX;

/// Fait la liste des échéances. Au démarrage, avant la tâche.
pub fn initialiser() {
    *ECHEANCES.verrouiller() = Echeances::new(MAX_ECHEANCES);
    if ECHEANCES.verrouiller().is_none() {
        afficherln!("[reseau] plus de memoire pour les echeances du reseau.");
    }
}

/// Réveille la tâche du réseau, pour qu'elle recalcule son sommeil (après
/// `inscrire`).
pub fn reveiller() {
    signaler(ECHEANCE);
}

/// Inscrit l'échéance de `objet` (None : retirée), sans réveiller la tâche
/// du réseau (qui l'appelle elle-même ; un autre appelant la réveille,
/// `reveiller`, une fois ses propres verrous rendus) : rend si
/// l'inscription a pu se faire.
pub fn inscrire(objet: u64, echeance: Option<u64>) -> bool {
    match ECHEANCES.verrouiller().as_mut() {
        Some(e) => match echeance {
            Some(t) => e.armer(objet, t).is_ok(),
            None => {
                e.desarmer(objet);
                true
            }
        },
        None => false,
    }
}

fn prochaine() -> Option<u64> {
    ECHEANCES.verrouiller().as_ref().and_then(Echeances::prochaine)
}

fn prendre_echu(maintenant: u64) -> Option<u64> {
    ECHEANCES.verrouiller().as_mut().and_then(|e| e.prendre_echu(maintenant))
}

fn boucle() {
    // Au premier tour, la table des voisins dit son échéance.
    let mut voisins = true;
    loop {
        let travail = attendre(prochaine());
        if travail & CONFIGURATION != 0 {
            super::virtio_net::configuration_changee();
        }
        // La réception des cartes, dans le contexte réseau : ce qu'elle
        // envoie par `lo` (une réponse) part à la fin du tour, en sortant
        // du contexte (contexte.rs).
        let contexte = super::contexte::entrer();
        for index in 1..=16u32 {
            if travail & INTERFACES << (index - 1) == 0 {
                continue;
            }
            // Pas fini (le budget épuisé) : au tour suivant, après les
            // autres interfaces.
            if interface::par_index(index).is_some_and(|i| i.travailler(BUDGET)) {
                signaler_interface(index);
            }
        }
        // Les objets dont l'échéance est passée.
        let maintenant = temps::ns_monotone();
        while let Some(objet) = prendre_echu(maintenant) {
            if objet == OBJET_VOISINS {
                voisins = true;
            }
        }
        if core::mem::take(&mut voisins) {
            super::arp::temps();
        }
        drop(contexte);
    }
}
