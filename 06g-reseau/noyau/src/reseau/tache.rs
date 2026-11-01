//! La tâche du réseau : le travail que les interruptions des cartes lui
//! laissent.
//!
//! Une interruption doit rendre la main vite, interruptions coupées : celle
//! d'une carte réseau ne fait que noter ce qui l'a levée (un changement de
//! lien, des trames reçues...) et réveiller cette tâche, qui fait le
//! travail ensuite, interruptions permises, préemptible comme une autre.
//! C'est ce que fait Linux de deux façons, que cette tâche réunit : le
//! « linkwatch » (une tâche différée qui suit l'état du lien des cartes)
//! et, depuis Linux 5.12, le NAPI « threaded » (la réception faite dans un
//! fil du noyau plutôt que dans un softirq). Option écartée : un mécanisme
//! de softirq, à la sortie de chaque interruption, avec sa tâche de repli
//! (ksoftirqd) quand il y a trop à faire : une tâche seule suffit, et
//! l'ordonnanceur (6e) la partage avec les programmes.
//!
//! Sans réveil perdu : le travail est un mot de bits, sous un verrou ; une
//! interruption pose son bit puis réveille ; la tâche prend le mot, et ne
//! s'endort que s'il est vide, en s'inscrivant dans la file d'attente
//! interruptions coupées, comme celle du clavier.

use crate::attente::{self, FileAttente, Sommeil};
use crate::programmes::NomCourt;
use crate::verrou::Verrou;
use crate::{cpu, tache};

/// Du travail à faire : un changement dans la configuration d'une carte
/// (son lien).
pub const CONFIGURATION: u32 = 1 << 0;

struct Travail {
    a_faire: u32,
    attente: FileAttente,
}

static TRAVAIL: Verrou<Travail> = Verrou::new(Travail { a_faire: 0, attente: FileAttente::new() });

/// Signale du travail à la tâche du réseau (depuis une interruption, ou
/// d'ailleurs), et la réveille.
pub fn signaler(travail: u32) {
    let mut t = TRAVAIL.verrouiller();
    t.a_faire |= travail;
    t.attente.reveiller_toutes();
}

/// Prend le travail en attente, en dormant tant qu'il n'y en a pas.
fn attendre() -> u32 {
    let interruptions = cpu::couper_interruptions();
    let travail = loop {
        let mut t = TRAVAIL.verrouiller();
        if t.a_faire != 0 {
            break core::mem::take(&mut t.a_faire);
        }
        t.attente.inscrire();
        drop(t);
        attente::dormir(None, Sommeil::Ininterruptible);
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

fn boucle() {
    loop {
        let travail = attendre();
        if travail & CONFIGURATION != 0 {
            super::virtio_net::configuration_changee();
        }
    }
}
