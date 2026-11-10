//! L'interface de boucle, `lo` (drivers/net/loopback.c) : ce que la
//! machine s'envoie à elle-même, à 127.0.0.1 comme à 10.0.2.15 (une de nos
//! adresses : la route locale passe par `lo`, comme chez Linux).
//!
//! Émettre par `lo`, c'est recevoir. Comme Linux : la trame va dans une
//! file (le `netif_rx`, et sa file `backlog`), que vide aussitôt, dans le
//! contexte de qui l'a envoyée, avant que son appel ne rende la main, ce
//! que Linux fait par le softirq qu'exécute la fin de `__dev_queue_xmit` :
//! un datagramme envoyé à soi-même est livré quand `sendto` revient, et
//! l'erreur ICMP qu'il provoque aussi. La file est celle de la TÂCHE qui
//! émet (`Tache::file_lo`, 6j), comme le `backlog` de Linux est celui du
//! processeur qui émet, vidé par son propre softirq avant le retour :
//! jusqu'à 6i, une seule file pour la machine, et la promesse ne tenait
//! que sur un processeur ; avec deux, la tâche du réseau pouvait prendre
//! la trame dans la file pendant que l'émetteur trouvait la file vide et
//! rendait la main, le datagramme pas encore livré (vu : `reseau`,
//! « chacun deja la quand sendto revient »). Dans le CONTEXTE RÉSEAU
//! (contexte.rs, 6h : une réception, la tâche du réseau, un verrou court de
//! TCP), l'envoi ne fait que déposer, et la file est vidée quand le
//! contexte finit : jamais de livraison à une socket sous le verrou d'une
//! autre, ni de la même ; une réception qui émet à son tour par `lo` (une
//! réponse à l'écho, un ICMP d'erreur) ne fait que déposer, et le vidage en
//! cours, plus haut sur la même pile, la prend au tour suivant : pas de
//! récursion. Options écartées : livrer la trame sans file, dans l'appel
//! même (une réception en provoquerait une autre, sans borne, sur la pile
//! du noyau) ; ne la faire recevoir que par la tâche du réseau (elle
//! arriverait quand l'ordonnanceur la choisit : un `recv` sans attendre ne
//! la trouverait pas encore, mesuré) ; une file par processeur, comme
//! Linux : une tâche préemptée entre le dépôt et le vidage changerait de
//! processeur, et sa trame resterait dans la file de l'ancien. La file a
//! la borne de Linux (`netdev_max_backlog`, 1000 trames) : au-delà, la
//! trame est jetée, et l'envoi n'en sait rien (comme un datagramme perdu
//! sur un câble). Sa place est prise à la première émission de la tâche
//! (sans mémoire, la trame est jetée) : les tâches qui n'émettent jamais
//! par `lo` ne paient rien.
//!
//! Les trames de `lo` ont un en-tête Ethernet, d'adresses nulles (Linux
//! aussi : `eth_header`), et jamais de voisin à résoudre (IFF_NOARP). Ses
//! compteurs, comme `loopback_xmit` : une trame déposée compte à la fois
//! reçue et émise (son `dev_lstats_add` sert aux deux sens), sans son
//! en-tête Ethernet (que `eth_type_trans` a déjà retiré) ; jetée, elle ne
//! compte que dans « drop » de la réception (`enqueue_to_backlog`).
//!
//! La même file porte la copie d'une diffusion que la machine envoie par
//! une carte (ipv4.rs) : Linux la rend aux sockets de la machine par le
//! même chemin (`ip_mc_output`, `dev_loopback_xmit`, puis `netif_rx` : le
//! `backlog`), livrée comme arrivée par la carte, sans compter ni pour la
//! carte ni pour `lo`.

use super::interface::{self, Compteurs, Interface, Materiel};
use super::paquet::Paquet;
use crate::faillible::FileFaillible;
use crate::tache;
use crate::verrou::Verrou;
use alloc::collections::VecDeque;
use formats::reseau::ethernet;
use inet::routes::Adresse;

/// La borne de la file (`netdev_max_backlog`).
const MAX: usize = 1000;

/// Ce qu'attend la file : une trame émise par `lo` (avec son en-tête
/// Ethernet), ou la copie d'un paquet IPv4 diffusé par la carte `copie_de`.
pub struct Trame {
    pub paquet: Paquet,
    pub copie_de: Option<&'static Interface>,
}
/// La MTU de `lo` (celle de Linux depuis 3.7).
pub const MTU: u32 = 65_536;
/// Son adresse et son réseau.
pub const ADRESSE: [u8; 4] = [127, 0, 0, 1];
const PREFIXE: u8 = 8;

/// L'interface, une fois faite.
static LO: Verrou<Option<&'static Interface>> = Verrou::new(None);

/// Fait l'interface `lo` (la première : son numéro est 1, comme chez
/// Linux), son adresse 127.0.0.1/8 et sa file. Au démarrage.
pub fn ajouter() {
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

/// Émet la trame `p` par `lo` : dans la file de la tâche courante
/// (comptée, voir l'en-tête), puis la file vidée tout de suite, dans le
/// contexte de qui l'envoie. Sans aucun verrou tenu : la réception en
/// prendra.
pub fn emettre(i: &Interface, mut p: Paquet) {
    // Rien n'attend ici (`loopback_xmit` : `skb_orphan`).
    p.orpheliner();
    let longueur = p.longueur().saturating_sub(ethernet::ENTETE) as u64;
    if !deposer(Trame { paquet: p, copie_de: None }) {
        return Compteurs::compter(&i.compteurs.jetes_reception, 1);
    }
    for (paquets, octets) in [(&i.compteurs.recus, &i.compteurs.octets_recus), (&i.compteurs.emis, &i.compteurs.octets_emis)] {
        Compteurs::compter(paquets, 1);
        Compteurs::compter(octets, longueur);
    }
    livrer_bientot();
}

/// Rend aux sockets de la machine la copie `p` (un paquet IPv4 entier,
/// son en-tête devant) d'une diffusion envoyée par la carte `i`
/// (`dev_loopback_xmit`) : par la file, livrée comme arrivée par `i`.
/// Jetée si la file est pleine, et comptée parmi les trames que la carte
/// a jetées en réception (`netif_rx`, `enqueue_to_backlog` :
/// `dev_core_stats_rx_dropped_inc` de la carte de la copie).
pub fn rendre_la_diffusion(i: &'static Interface, mut p: Paquet) {
    p.orpheliner();
    if deposer(Trame { paquet: p, copie_de: Some(i) }) {
        livrer_bientot();
    } else {
        super::interface::Compteurs::compter(&i.compteurs.jetes_reception, 1);
    }
}

/// Dépose `t` dans la file de la tâche courante ; false : jetée (plus de
/// mémoire pour la faire, ou pleine).
fn deposer(t: Trame) -> bool {
    let mut file = tache::courante().file_lo.verrouiller();
    // La file de la tâche, faite à sa première trame, avec la place de
    // MAX trames : déposer n'alloue plus rien ensuite.
    let f = file.get_or_insert_with(VecDeque::new);
    if (f.capacity() == 0 && f.try_reserve_exact(MAX).is_err()) || f.len() >= MAX {
        return false;
    }
    f.ajouter_derriere_dans_la_place(t);
    true
}

/// Dans le contexte réseau (une réception, un verrou court de TCP) :
/// seulement déposée, livrée quand le contexte finit (contexte.rs) ;
/// sinon, tout de suite.
fn livrer_bientot() {
    if !super::contexte::actif() {
        vider_en_attente();
    }
}

/// Fait d'avance la file de `lo` de la tâche courante : pour la tâche du
/// réseau (reseau/tache.rs), qui émet par `lo` au nom des programmes (un
/// ACK de TCP à son minuteur) et vit pour toujours : faite à sa première
/// trame, pendant un programme, elle compterait comme de la mémoire que ce
/// programme n'a pas rendue (le contrôle « memoire rendue » du lanceur).
pub fn preparer_la_file() {
    let mut file = tache::courante().file_lo.verrouiller();
    let f = file.get_or_insert_with(VecDeque::new);
    if f.try_reserve_exact(MAX).is_err() {
        afficherln!("[reseau] lo : plus de memoire pour la file de la tache du reseau.");
    }
}

/// La prochaine trame de la file de la tâche courante, s'il y en a une.
fn prochaine() -> Option<Trame> {
    tache::courante().file_lo.verrouiller().as_mut().and_then(VecDeque::pop_front)
}

/// Livre ce qui attend dans la file de `lo` de la tâche courante, s'il y a
/// quelque chose (à la fin du contexte réseau, ou d'un envoi hors de lui).
/// Dans le contexte réseau le temps du vidage : une réception qui émet à
/// son tour par `lo` (une réponse) ne fait que déposer, et ce vidage la
/// prend au tour suivant.
pub fn vider_en_attente() {
    let Some(lo) = interface() else { return };
    super::contexte::pendant(|| {
        // Prise sous le verrou, reçue sans lui.
        while let Some(t) = prochaine() {
            match t.copie_de {
                None => super::recevoir(lo, t.paquet),
                Some(i) => super::ipv4::recevoir_la_diffusion(i, t.paquet),
            }
        }
    });
}

/// Le travail de `lo`, dans la tâche du réseau : rien. Chaque tâche vide
/// sa propre file avant de rendre la main (voir l'en-tête).
pub fn travailler(_i: &'static Interface, _budget: usize) -> bool {
    false
}

/// Toutes les files de `lo` sont-elles vides ? Une tâche vide la sienne
/// avant de rendre la main ; préemptée au milieu, elle garde des trames un
/// instant.
pub fn au_repos() -> bool {
    let mut vides = true;
    tache::pour_chaque(|t| vides &= t.file_lo.verrouiller().as_ref().is_none_or(VecDeque::is_empty));
    vides
}
