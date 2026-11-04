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
//! Les minuteurs du réseau : une échéance par objet (la table des voisins, arp.rs ; les
//! sockets TCP et les entrées de TIME_WAIT, tcp.rs ; les fragments, ipv4.rs), dans la roue de Linux
//! (../roue) ; quelques-unes, qui n'attendent pas son tic, dans une liste exacte
//! (inet::echeances). La tâche dort jusqu'à la plus proche, ou un réveil, et fait le travail
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
use roue::Roue;

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

/// Les échéances du réseau : quand se réveiller, et pour qui. Faites au démarrage, à leur taille
/// définitive.
struct Minuteurs {
    roue: Roue,
    precises: Echeances,
}

impl Minuteurs {
    fn prochaine(&mut self) -> Option<u64> {
        match (self.roue.prochaine(), self.precises.prochaine()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

static MINUTEURS: Verrou<Option<Minuteurs>> = Verrou::new(None);
/// Le nombre d'objets qui peuvent avoir une échéance à la fois, dans la roue, et dans la liste.
const MAX_ECHEANCES: usize = 8192;
const MAX_PRECISES: usize = 64;
/// L'objet « table des voisins » (arp.rs) ; les connexions TCP prendront
/// le numéro de leur socket, qui part de 1.
pub const OBJET_VOISINS: u64 = u64::MAX;
/// L'objet « files de fragments » (ipv4.rs).
pub const OBJET_FRAGMENTS: u64 = u64::MAX - 1;

/// Fait les échéances. Au démarrage, avant la tâche.
pub fn initialiser() {
    let m = Roue::new(MAX_ECHEANCES).zip(Echeances::new(MAX_PRECISES)).map(|(roue, precises)| Minuteurs { roue, precises });
    if m.is_none() {
        afficherln!("[reseau] plus de memoire pour les echeances du reseau.");
    }
    *MINUTEURS.verrouiller() = m;
}

/// L'objet `objet` veut la tâche du réseau à `echeance` (None : plus
/// jamais), et la réveille pour qu'elle recalcule son sommeil si la
/// prochaine échéance est maintenant plus proche (plus loin, elle se
/// réveillera pour rien, et se rendormira : moins coûteux qu'un réveil à
/// chaque ACK, qui repousse le minuteur de retransmission d'une
/// connexion). false : la liste est pleine (l'objet ne sera pas servi à
/// l'heure : à lui de s'en accommoder).
pub fn armer(objet: u64, echeance: Option<u64>) -> bool {
    let (ok, plus_tot) = inscrire(objet, echeance);
    if plus_tot {
        reveiller();
    }
    ok
}

/// De même, à l'instant dit, sans le tic de la roue (Linux : un hrtimer, ou une tâche sans délai).
pub fn armer_precis(objet: u64, echeance: u64) -> bool {
    let (ok, plus_tot) = inscrire_en(objet, Some(echeance), true);
    if plus_tot {
        reveiller();
    }
    ok
}

/// Réveille la tâche du réseau, pour une échéance plus proche que son
/// sommeil (après `inscrire`).
pub fn reveiller() {
    signaler(ECHEANCE);
}

/// Inscrit l'échéance de `objet` (None : retirée), sans réveiller la tâche
/// du réseau : rend si l'inscription a pu se faire, et si la première
/// échéance de la liste est maintenant plus proche (l'appelant réveille
/// alors la tâche, `reveiller`, une fois ses propres verrous rendus). La
/// première échéance d'avant et celle d'après sont lues dans le même
/// passage sous le verrou de la liste que l'inscription : la tâche du
/// réseau lit la sienne sous ce verrou avant de dormir ; ou elle voit
/// l'inscription, ou bien celle d'avant est son sommeil. (Lue hors de ce
/// passage, la première échéance pourrait avoir été prise entre-temps par
/// la tâche : le réveil manquerait.)
pub fn inscrire(objet: u64, echeance: Option<u64>) -> (bool, bool) {
    inscrire_en(objet, echeance, false)
}

/// Un objet n'est que dans l'une des deux. La liste pleine (ce qui ne devrait pas arriver : elle se
/// vide vite) : la roue, un peu plus tard qu'on ne voulait.
fn inscrire_en(objet: u64, echeance: Option<u64>, precise: bool) -> (bool, bool) {
    let maintenant = temps::ns_monotone();
    match MINUTEURS.verrouiller().as_mut() {
        Some(m) => {
            let avant = m.prochaine();
            let ok = match echeance {
                Some(t) if precise && m.precises.armer(objet, t).is_ok() => {
                    m.roue.desarmer(objet);
                    true
                }
                Some(t) => {
                    let ok = m.roue.armer(objet, t, maintenant).is_ok();
                    if ok {
                        m.precises.desarmer(objet);
                    }
                    ok
                }
                None => {
                    m.roue.desarmer(objet);
                    m.precises.desarmer(objet);
                    true
                }
            };
            let apres = m.prochaine();
            (ok, apres.is_some_and(|a| avant.is_none_or(|b| a < b)))
        }
        None => (false, false),
    }
}

fn prochaine() -> Option<u64> {
    MINUTEURS.verrouiller().as_mut().and_then(Minuteurs::prochaine)
}

fn prendre_echu(maintenant: u64) -> Option<u64> {
    MINUTEURS.verrouiller().as_mut().and_then(|m| m.precises.prendre_echu(maintenant).or_else(|| m.roue.prendre_echu(maintenant)))
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
            } else if objet == OBJET_FRAGMENTS {
                super::ipv4::fragments_echus();
            } else {
                // Une connexion TCP, ou une entrée de TIME_WAIT.
                super::tcp::echeance(objet);
            }
        }
        if core::mem::take(&mut voisins) {
            super::arp::temps();
        }
        drop(contexte);
    }
}
