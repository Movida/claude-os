//! ARP dans le noyau (net/ipv4/arp.c) : répondre à qui demande notre
//! adresse, apprendre celles des voisins, et faire attendre les paquets
//! d'une machine dont on ne connaît pas encore l'adresse matérielle.
//!
//! Les règles de la table des voisins (les états, les délais) sont dans la
//! bibliothèque inet (inet::voisins), testée sur l'hôte ; la table vit ici,
//! sous un verrou, faite au démarrage. Ses actions (envoyer un paquet, une
//! requête) se font sous ce verrou, puis dans celui de la file d'émission
//! de la carte : l'ordre voisins, puis carte, jamais l'inverse.
//!
//! La réception, comme `arp_process` : seulement Ethernet (types de
//! matériel 1 et 6) et IPv4 ; une cible de multidiffusion ou de boucle
//! ignorée ; une requête de 0.0.0.0 (la vérification qu'une adresse est
//! libre, RFC 5227) reçoit sa réponse si elle vise une de nos adresses,
//! sans rien apprendre ; une requête pour une de nos adresses (de
//! n'importe laquelle de nos interfaces : `arp_ignore` à 0), d'une source
//! qui n'est pas un martien (une diffusion, une multidiffusion, une boucle,
//! une de nos adresses : ce que refuse `ip_route_input_noref`), reçoit sa
//! réponse et apprend l'émetteur ; tout autre message (une réponse, une
//! requête pour un autre, une annonce « gratuite ») met à jour l'entrée de
//! son émetteur si elle existe (les règles d'inet::voisins : JOIGNABLE
//! pour une réponse qui nous était adressée, la première réponse qui gagne
//! pendant une seconde).

use super::interface::Interface;
use super::paquet::Paquet;
use crate::verrou::Verrou;
use crate::{aleatoire, temps};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use formats::reseau::arp::{self, Arp};
use formats::reseau::{ethernet, icmp, ipv4};
use inet::voisins::{Action, Appris, Etat, Table};

static VOISINS: Verrou<Option<Table<Paquet>>> = Verrou::new(None);

/// Les paquets jetés faute de voisin (la file pleine, ou le voisin muet).
static JETES: AtomicU64 = AtomicU64::new(0);

fn hasard() -> u64 {
    aleatoire::u64()
}

/// Fait la table (vide). Au démarrage.
pub fn initialiser() {
    *VOISINS.verrouiller() = Table::new(hasard(), temps::ns_monotone());
}

/// L'adresse IPv4 de `i` qui sert de source à ses requêtes : sa première
/// (le `inet_select_addr` de Linux, sans portée) ; 0.0.0.0 sans adresse.
fn source(i: &Interface) -> [u8; 4] {
    super::ipv4::avec_table(|t| t.adresses_de(i.index).next().map(|a| a.adresse)).flatten().unwrap_or(ipv4::AUCUNE)
}

/// Envoie un message ARP par `i`, à l'adresse matérielle `destination`.
fn emettre(i: &'static Interface, destination: [u8; 6], a: &Arp) {
    let Some(mut p) = Paquet::vide(arp::TAILLE) else { return };
    let Some(m) = p.ajouter_fin(arp::TAILLE) else { return };
    arp::ecrire(m.try_into().expect("28 octets"), a);
    super::ethernet::emettre(i, destination, ethernet::ARP, p);
}

/// Fait une action de la table, sous son verrou.
fn faire(a: Action<Paquet>) {
    match a {
        Action::Envoyer { interface, mac, paquet } => {
            if let Some(i) = super::interface::par_index(interface) {
                super::ethernet::emettre(i, mac, ethernet::IPV4, paquet);
            }
        }
        Action::Requete { interface, cible, mac } => {
            let Some(i) = super::interface::par_index(interface) else { return };
            let requete = Arp { operation: arp::REQUETE, mac_emetteur: i.mac, ip_emetteur: source(i), mac_cible: [0; 6], ip_cible: cible };
            emettre(i, mac.unwrap_or(ethernet::DIFFUSION), &requete);
        }
        Action::Jeter { .. } => {
            JETES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Envoie le paquet IPv4 `p` (son en-tête en place) par `i` à la machine
/// `prochain` du réseau local : tout de suite si son adresse matérielle est
/// connue, après la résolution sinon (le `neigh_output` de Linux).
/// `confirmer` : MSG_CONFIRM, la machine est là.
pub fn envoyer(i: &'static Interface, prochain: [u8; 4], p: Paquet, confirmer: bool) {
    let taille = p.taille_vraie();
    let mut v = VOISINS.verrouiller();
    match v.as_mut() {
        Some(t) => t.envoyer(i.index, prochain, p, taille, confirmer, temps::ns_monotone(), &mut faire),
        None => faire(Action::Jeter { paquet: p, echec: false }),
    }
    drop(v);
    super::tache::signaler(super::tache::VOISINS);
}

/// Les minuteurs des voisins (dans la tâche du réseau), et la prochaine
/// échéance. Un voisin passé en ÉCHEC jette sa file : pour chacun de ses
/// paquets, une erreur ICMP « hôte injoignable » de nous vers nous (le
/// `neigh_invalidate` de Linux, puis `arp_error_report` et
/// `ipv4_send_dest_unreach`), envoyée une fois le verrou des voisins rendu
/// : elle passe par `lo`, puis par le chemin de toute erreur ICMP reçue,
/// jusqu'à la socket qui avait envoyé le paquet (qui le dit selon ses
/// règles : icmp.rs, udp.rs). Aucun verrou de socket n'est pris sous
/// celui des voisins. Plus de mémoire pour retenir un paquet : il est jeté
/// sans erreur.
pub fn temps() -> Option<u64> {
    let mut echecs: Vec<Paquet> = Vec::new();
    let echeance = {
        let mut v = VOISINS.verrouiller();
        let t = v.as_mut()?;
        t.temps(temps::ns_monotone(), hasard(), &mut |a| match a {
            Action::Jeter { paquet, echec: true } => {
                JETES.fetch_add(1, Ordering::Relaxed);
                if echecs.try_reserve(1).is_ok() {
                    echecs.push(paquet);
                }
            }
            a => faire(a),
        });
        t.echeance()
    };
    for p in echecs {
        super::icmp::envoyer_erreur(icmp::INJOIGNABLE, icmp::HOTE, 0, p.donnees(), false, false, false);
    }
    echeance
}

/// Un message ARP reçu par `i` (la charge de la trame), dans la tâche du
/// réseau ; `trame_diffusee` : sa trame allait à toutes les machines (une
/// réponse diffusée ne prouve pas que son émetteur nous entend).
pub fn recevoir(i: &'static Interface, a: &[u8], trame_diffusee: bool) {
    let Ok(a) = arp::lire(a) else { return };
    if a.operation != arp::REQUETE && a.operation != arp::REPONSE {
        return;
    }
    let (sip, tip) = (a.ip_emetteur, a.ip_cible);
    if ipv4::multidiffusion(tip) || ipv4::boucle(tip) {
        return;
    }
    let (cible_a_nous, source_martienne, source_unicast) = super::ipv4::avec_table(|t| (
        t.est_a_nous(tip),
        ipv4::multidiffusion(sip) || sip == ipv4::DIFFUSION || ipv4::boucle(sip) || t.est_a_nous(sip),
        !t.est_a_nous(sip) && !t.est_diffusion(i.index, sip) && !ipv4::multidiffusion(sip),
    )).unwrap_or((false, true, false));
    let repondre = || {
        let reponse = Arp { operation: arp::REPONSE, mac_emetteur: i.mac, ip_emetteur: tip, mac_cible: a.mac_emetteur, ip_cible: sip };
        emettre(i, a.mac_emetteur, &reponse);
    };
    if sip == ipv4::AUCUNE {
        if a.operation == arp::REQUETE && cible_a_nous {
            repondre();
        }
        return;
    }
    let appris = if a.operation == arp::REQUETE && cible_a_nous && !source_martienne {
        Appris::RequetePourNous
    } else {
        // Une annonce gratuite : la machine demande sa propre adresse (une
        // réponse gratuite porte aussi son adresse matérielle pour cible),
        // une adresse ordinaire d'une autre machine (`arp_is_garp`).
        let gratuit = sip == tip && (a.operation != arp::REPONSE || a.mac_cible == a.mac_emetteur) && source_unicast;
        Appris::Message { joignable: a.operation == arp::REPONSE && !trame_diffusee, gratuit }
    };
    if let Some(t) = VOISINS.verrouiller().as_mut() {
        t.apprendre(i.index, sip, a.mac_emetteur, appris, temps::ns_monotone(), &mut faire);
    }
    if appris == Appris::RequetePourNous {
        repondre();
    }
    super::tache::signaler(super::tache::VOISINS);
}

/// Un paquet attend-il un voisin qui se cherche ?
pub fn en_attente() -> bool {
    VOISINS.verrouiller().as_ref().is_some_and(|t| t.en_attente())
}

/// L'état du voisin `adresse` de `i`, et son adresse matérielle.
pub fn voisin(i: &Interface, adresse: [u8; 4]) -> Option<(Etat, [u8; 6])> {
    VOISINS.verrouiller().as_ref()?.voisin(i.index, adresse).map(|v| (v.etat, v.mac))
}

/// Le nombre de paquets jetés faute de voisin (pour la vérification du
/// voisin muet, dans le noyau des tests).
#[cfg(feature = "test-programmes")]
pub fn jetes() -> u64 {
    JETES.load(Ordering::Relaxed)
}

/// La ligne `n` (à partir de 0, l'en-tête) de /proc/net/arp, dans `ecrire`.
pub fn ligne_proc(n: u64, ecrire: &mut dyn core::fmt::Write) -> Result<bool, core::fmt::Error> {
    use core::fmt::Write;
    if n == 0 {
        ecrire.write_str("IP address       HW type     Flags       HW address            Mask     Device\n")?;
        return Ok(true);
    }
    let v = VOISINS.verrouiller();
    let Some(voisin) = v.as_ref().and_then(|t| t.voisins().nth(n as usize - 1)) else { return Ok(false) };
    let (adresse, mac, etat, interface) = (voisin.adresse, voisin.mac, voisin.etat, voisin.interface);
    drop(v);
    // Le format d'`arp_format_neigh_entry` ; ATF_COM (0x2) : l'adresse
    // matérielle est connue. L'adresse et la MAC écrites d'abord dans un
    // tampon de la pile (une allocation ne doit pas pouvoir faire paniquer
    // le noyau), pour les aligner.
    let mut ip = Pile::<16>::new();
    let mut m = Pile::<17>::new();
    write!(ip, "{}", formats::reseau::Ipv4Affichee(adresse))?;
    write!(m, "{}", super::virtio_net::Mac(mac))?;
    let nom = super::interface::par_index(interface).map_or("?", |i| i.nom);
    writeln!(ecrire, "{:<16} 0x{:<10x}0x{:<10x}{:<17}     *        {}", ip.texte(), 1, if etat.valide() { 2 } else { 0 }, m.texte(), nom)?;
    Ok(true)
}

/// Un petit texte dans un tampon de la pile, de `N` octets au plus.
struct Pile<const N: usize> {
    octets: [u8; N],
    longueur: usize,
}

impl<const N: usize> Pile<N> {
    fn new() -> Self {
        Pile { octets: [0; N], longueur: 0 }
    }

    fn texte(&self) -> &str {
        core::str::from_utf8(&self.octets[..self.longueur]).unwrap_or("")
    }
}

impl<const N: usize> core::fmt::Write for Pile<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let fin = self.longueur.checked_add(s.len()).filter(|&f| f <= N).ok_or(core::fmt::Error)?;
        self.octets[self.longueur..fin].copy_from_slice(s.as_bytes());
        self.longueur = fin;
        Ok(())
    }
}
