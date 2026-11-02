//! L'interface de boucle, `lo` (drivers/net/loopback.c) : ce que la
//! machine s'envoie à elle-même, à 127.0.0.1 comme à 10.0.2.15 (une de nos
//! adresses : la route locale passe par `lo`, comme chez Linux).
//!
//! Émettre par `lo`, c'est recevoir. Comme Linux : la trame va dans une
//! file (le `netif_rx`, et sa file `backlog`), que vide aussitôt, dans le
//! contexte de qui l'a envoyée, avant que son appel ne rende la main, ce
//! que Linux fait par le softirq qu'exécute la fin de `__dev_queue_xmit` :
//! un datagramme envoyé à soi-même est livré quand `sendto` revient, et
//! l'erreur ICMP qu'il provoque aussi. Un seul vidage à la fois
//! (`VIDAGE`) : une réception qui émet à son tour par `lo` (une réponse à
//! l'écho, un ICMP d'erreur) ne fait que déposer, et le vidage en cours,
//! plus haut sur la même pile, la prend au tour suivant ; pas de
//! récursion. Et dans le CONTEXTE RÉSEAU (contexte.rs, 6h : une
//! réception, la tâche du réseau, un verrou court de TCP), l'envoi ne fait
//! que déposer, et la file est vidée quand le contexte finit : jamais de
//! livraison à une socket sous le verrou d'une autre, ni de la même.
//! Options écartées : livrer la trame sans file, dans l'appel même (une réception en provoquerait une autre, sans borne, sur la pile
//! du noyau) ; ne la faire recevoir que par la tâche du réseau (elle
//! arriverait quand l'ordonnanceur la choisit : un `recv` sans attendre ne
//! la trouverait pas encore, mesuré). La tâche du réseau vide aussi la
//! file, par sécurité. La file a la borne de Linux (`netdev_max_backlog`,
//! 1000 trames) : au-delà, la trame est jetée, et l'envoi n'en sait rien
//! (comme un datagramme perdu sur un câble). Sa place est réservée au
//! démarrage : déposer une trame n'alloue rien.
//!
//! Les trames de `lo` ont un en-tête Ethernet, d'adresses nulles (Linux
//! aussi : `eth_header`), et jamais de voisin à résoudre (IFF_NOARP). Ses
//! compteurs, comme `loopback_xmit` : une trame déposée compte à la fois
//! reçue et émise (son `dev_lstats_add` sert aux deux sens), sans son
//! en-tête Ethernet (que `eth_type_trans` a déjà retiré) ; jetée, elle ne
//! compte que dans « drop » de la réception (`enqueue_to_backlog`).

use super::interface::{self, Compteurs, Interface, Materiel};
use super::paquet::Paquet;
use crate::faillible::FileFaillible;
use crate::verrou::Verrou;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use formats::reseau::ethernet;
use inet::routes::Adresse;

/// La borne de la file (`netdev_max_backlog`).
const MAX: usize = 1000;
/// La MTU de `lo` (celle de Linux depuis 3.7).
pub const MTU: u32 = 65_536;
/// Son adresse et son réseau.
pub const ADRESSE: [u8; 4] = [127, 0, 0, 1];
const PREFIXE: u8 = 8;

/// Les trames émises, pas encore reçues.
static FILE: Verrou<VecDeque<Paquet>> = Verrou::new(VecDeque::new());

/// Quelqu'un vide la file en ce moment.
static VIDAGE: AtomicBool = AtomicBool::new(false);

/// L'interface, une fois faite.
static LO: Verrou<Option<&'static Interface>> = Verrou::new(None);

/// Fait l'interface `lo` (la première : son numéro est 1, comme chez
/// Linux), son adresse 127.0.0.1/8 et sa file. Au démarrage.
pub fn ajouter() {
    if FILE.verrouiller().try_reserve_exact(MAX).is_err() {
        return afficherln!("[reseau] lo : plus de memoire pour sa file.");
    }
    let Some(i) = interface::ajouter("lo", [0; 6], MTU, true, Materiel::Boucle) else { return };
    *LO.verrouiller() = Some(i);
    super::ipv4::avec_table(|t| {
        let _ = t.ajouter_adresse(Adresse { interface: i.index, adresse: ADRESSE, prefixe: PREFIXE, boucle: true });
    });
    afficherln!("[reseau] lo : boucle locale, 127.0.0.1/8, mtu {}.", MTU);
}

/// L'interface `lo`.
pub fn interface() -> Option<&'static Interface> {
    *LO.verrouiller()
}

/// Émet la trame `p` par `lo` : dans la file (comptée, voir l'en-tête),
/// puis la file vidée tout de suite, dans le contexte de qui l'envoie. Sans
/// aucun verrou tenu : la réception en prendra.
pub fn emettre(i: &Interface, p: Paquet) {
    let longueur = p.longueur().saturating_sub(ethernet::ENTETE) as u64;
    {
        let mut f = FILE.verrouiller();
        if f.len() >= MAX {
            drop(f);
            return Compteurs::compter(&i.compteurs.jetes_reception, 1);
        }
        // La place de MAX paquets est prise au démarrage (`ajouter`).
        f.ajouter_derriere_dans_la_place(p);
    }
    for (paquets, octets) in [(&i.compteurs.recus, &i.compteurs.octets_recus), (&i.compteurs.emis, &i.compteurs.octets_emis)] {
        Compteurs::compter(paquets, 1);
        Compteurs::compter(octets, longueur);
    }
    // La tâche du réseau aussi, au cas où le vidage serait déjà pris par
    // une tâche préemptée (elle reprendra, mais plus tard).
    super::tache::signaler_interface(i.index);
    // Dans le contexte réseau (une réception, un verrou court de TCP) :
    // seulement déposée, livrée quand le contexte finit (contexte.rs).
    if !super::contexte::actif() {
        vider_en_attente();
    }
}

/// Livre ce qui attend dans la file de `lo`, s'il y a quelque chose (à la
/// fin du contexte réseau, ou d'un envoi hors de lui).
pub fn vider_en_attente() {
    if FILE.verrouiller().is_empty() {
        return;
    }
    if let Some(lo) = interface() {
        vider(lo, usize::MAX);
    }
}

/// Reçoit les trames de la file, `budget` au plus, si personne d'autre ne
/// le fait : rend vrai s'il en reste. Le vidage rendu, la file est revue :
/// une trame déposée pendant qu'on la vidait, par qui a vu le vidage pris,
/// n'est pas oubliée.
fn vider(i: &'static Interface, budget: usize) -> bool {
    let mut n = 0;
    loop {
        if VIDAGE.swap(true, Ordering::Acquire) {
            return false;
        }
        // Dans le contexte réseau : une réception qui émet à son tour par
        // `lo` (une réponse) ne fait que déposer, et ce tour-ci la prend.
        super::contexte::pendant(|| {
            while n < budget {
                // Prise sous le verrou, reçue sans lui.
                let Some(p) = FILE.verrouiller().pop_front() else { break };
                super::recevoir(i, p);
                n += 1;
            }
        });
        VIDAGE.store(false, Ordering::Release);
        if FILE.verrouiller().is_empty() {
            return false;
        }
        if n >= budget {
            return true;
        }
    }
}

/// Le travail de `lo`, dans la tâche du réseau : au plus `budget` trames de
/// la file reçues. Rend vrai s'il en reste.
pub fn travailler(i: &'static Interface, budget: usize) -> bool {
    vider(i, budget)
}

/// La file est-elle vide, et personne ne la vide-t-il ?
pub fn au_repos() -> bool {
    FILE.verrouiller().is_empty() && !VIDAGE.load(Ordering::Acquire)
}
