//! La configuration du réseau au démarrage, par DHCP : le noyau autour du
//! client d'inet::dhcp, comme `ip_auto_config` dans Linux (le paramètre
//! `ip=dhcp`, net/ipv4/ipconfig.c).
//!
//! Choix de conception. Sur une distribution, c'est un programme qui
//! demande l'adresse (dhclient, systemd-networkd...) : il lui faut des
//! sockets brutes (AF_PACKET) pour parler sans adresse, et netlink pour
//! poser celle qu'il reçoit ; nous n'avons ni l'un ni l'autre. Une adresse
//! écrite en dur (10.0.2.15) ne vaudrait que pour le réseau de QEMU. Linux
//! a, pour les machines qui démarrent par le réseau, un client DHCP dans le
//! noyau : nous faisons de même. Le lanceur l'attend avant /etc/demarrage
//! (Linux attend `ip_auto_config` avant de lancer /init), les programmes
//! trouvent donc le réseau prêt.
//!
//! Les messages partent en diffusion limitée, de 0.0.0.0:68 vers
//! 255.255.255.255:67 ; les réponses arrivent par l'entrée d'IPv4, qui les
//! passe ici avant de regarder leur destination. Ce que donne le serveur
//! est posé : l'adresse et son réseau sur l'interface (la route du réseau
//! avec elle), la route par défaut par la passerelle, et les serveurs DNS,
//! que montre /proc/net/pnp au format de /etc/resolv.conf (l'archive fait
//! de /etc/resolv.conf un lien vers lui, comme le propose la documentation
//! de Linux pour ses machines sans disque).

use super::interface::{self, Interface};
use super::paquet::Paquet;
use crate::attente::{self, FileAttente, Sommeil};
use crate::verrou::Verrou;
use crate::{aleatoire, cpu, tache, temps};
use formats::reseau::{Ipv4Affichee, dhcp as format, ipv4, udp};
use inet::dhcp::{Bail, Client, Evenement};
use inet::routes::{Adresse, Route};

/// Où en est la configuration d'une interface.
struct Configuration {
    interface: u32,
    client: Client,
    /// Fini : configurée, ou abandonnée.
    fini: bool,
    debut: u64,
    /// Le lanceur qui attend la fin.
    attente: FileAttente,
}

static EN_COURS: Verrou<Option<Configuration>> = Verrou::new(None);

/// Le bail obtenu (pour /proc/net/pnp), pour toujours.
static BAIL: Verrou<Option<Bail>> = Verrou::new(None);

/// Le client DHCP de l'interface `index` attend-il des réponses ?
pub fn en_cours(index: u32) -> bool {
    EN_COURS.verrouiller().as_ref().is_some_and(|c| c.interface == index && !c.fini)
}

/// Le bail obtenu au démarrage, s'il y en a un.
pub fn bail() -> Option<Bail> {
    *BAIL.verrouiller()
}

/// Envoie le message du moment de `c` par `i`.
fn envoyer(i: &'static Interface, c: &Client) {
    let Some(mut p) = Paquet::vide(udp::ENTETE + format::TAILLE) else { return };
    let Some(m) = p.ajouter_fin(format::TAILLE) else { return };
    let m: &mut [u8; format::TAILLE] = m.try_into().expect("la taille d'un message");
    c.message(temps::ns_monotone(), m);
    if p.ajouter_entete(udp::ENTETE).is_none() {
        return;
    }
    let u = udp::Udp { source: format::PORT_CLIENT, destination: format::PORT_SERVEUR };
    udp::ecrire(p.donnees_mut(), &u, ipv4::AUCUNE, ipv4::DIFFUSION);
    super::ipv4::emettre_en_diffusion(i, ipv4::AUCUNE, ipv4::UDP, p);
}

/// La fin de la configuration, à dire hors des verrous.
enum Fin {
    Configuree(Bail, u64),
    Refusee(inet::dhcp::Refus),
    Abandonnee,
}

/// Ce que fait un événement du client : envoyer, poser la configuration,
/// abandonner. Sous le verrou d'EN_COURS ; rend la fin, s'il y en a une.
fn traiter(i: &'static Interface, c: &mut Configuration, e: Evenement) -> Option<Fin> {
    let fin = match e {
        Evenement::Rien => return None,
        Evenement::Envoyer => {
            envoyer(i, &c.client);
            return None;
        }
        Evenement::Configure(b) => {
            appliquer(i, &b);
            *BAIL.verrouiller() = Some(b);
            Fin::Configuree(b, (temps::ns_monotone() - c.debut) / 1_000_000)
        }
        Evenement::Refuse(r) => Fin::Refusee(r),
        Evenement::Abandon => Fin::Abandonnee,
    };
    c.fini = true;
    c.attente.reveiller_toutes();
    Some(fin)
}

/// Dit la fin de la configuration de `i`.
fn dire(i: &Interface, f: Fin) {
    match f {
        Fin::Configuree(b, ms) => {
            afficher!("[reseau] {} : {}/{}", i.nom, Ipv4Affichee(b.adresse), b.prefixe);
            if let Some(p) = b.passerelle {
                afficher!(", passerelle {}", Ipv4Affichee(p));
            }
            for d in b.dns.iter().flatten() {
                afficher!(", DNS {}", Ipv4Affichee(*d));
            }
            afficherln!(" (DHCP de {}, {} ms).", Ipv4Affichee(b.serveur), ms);
            if let Some(m) = b.mtu {
                afficherln!("[reseau] {} : mtu {} (DHCP){}.", i.nom, m, if i.mtu() == m as u32 { "" } else { " : hors des bornes de la carte, non posee" });
            }
        }
        Fin::Refusee(r) => afficherln!("[reseau] {} : bail DHCP refuse ({}) : pas d'adresse.", i.nom, match r {
            inet::dhcp::Refus::Masque => "pas de masque pour une adresse de multidiffusion",
            inet::dhcp::Refus::Passerelle => "passerelle hors du reseau",
        }),
        Fin::Abandonnee => afficherln!("[reseau] {} : pas de reponse DHCP ({} essais) : pas d'adresse.", i.nom, inet::dhcp::ESSAIS),
    }
}

/// Pose le bail `b` : l'adresse (et la route de son réseau), la route par
/// défaut, et la MTU s'il en donne une (`ic_setup_if` : `dev_set_mtu`,
/// dans les bornes de la carte).
fn appliquer(i: &Interface, b: &Bail) {
    if let Some(m) = b.mtu {
        i.changer_mtu(m as u32);
    }
    super::ipv4::avec_table(|t| {
        let _ = t.ajouter_adresse(Adresse { interface: i.index, adresse: b.adresse, prefixe: b.prefixe, boucle: false });
        if let Some(passerelle) = b.passerelle {
            let _ = t.ajouter_route(Route { reseau: ipv4::AUCUNE, prefixe: 0, passerelle: Some(passerelle), interface: i.index, source: b.adresse });
        }
    });
}

/// Un message de DHCP (la charge d'un datagramme du port 67 vers le port
/// 68) reçu par `i`, dans la tâche du réseau.
pub fn recu(i: &'static Interface, message: &[u8]) {
    let fin = {
        let mut g = EN_COURS.verrouiller();
        let Some(c) = g.as_mut().filter(|c| c.interface == i.index && !c.fini) else { return };
        let e = c.client.recu(message, temps::ns_monotone());
        traiter(i, c, e)
    };
    if let Some(f) = fin {
        dire(i, f);
    }
}

/// Configure la première interface (eth0) par DHCP, et attend la fin :
/// l'adresse obtenue, ou l'abandon. Dans la tâche du lanceur, avant
/// /etc/demarrage. Sans interface, ou son câble débranché : rien.
pub fn configurer() {
    let Some(i) = interface::premiere_carte() else { return };
    if !i.lien.load(core::sync::atomic::Ordering::Relaxed) {
        return afficherln!("[reseau] {} : lien coupe, pas de DHCP.", i.nom);
    }
    let mut hasard = [0u8; 12];
    aleatoire::obtenir(&mut hasard);
    let xid = u32::from_le_bytes([hasard[0], hasard[1], hasard[2], hasard[3]]);
    let delai = u64::from_le_bytes([hasard[4], hasard[5], hasard[6], hasard[7], hasard[8], hasard[9], hasard[10], hasard[11]]);
    let maintenant = temps::ns_monotone();
    {
        let mut g = EN_COURS.verrouiller();
        let c = g.insert(Configuration {
            interface: i.index,
            client: Client::new(i.mac, xid, delai, maintenant),
            fini: false,
            debut: maintenant,
            attente: FileAttente::new(),
        });
        envoyer(i, &c.client);
    }
    loop {
        // S'inscrire, puis dormir jusqu'à l'échéance du client ou sa fin
        // (une réponse arrivée entre-temps réveille), interruptions
        // coupées entre les deux : rien ne se perd.
        let interruptions = cpu::couper_interruptions();
        let echeance = match EN_COURS.verrouiller().as_ref() {
            Some(c) if !c.fini => {
                c.attente.inscrire();
                c.client.echeance()
            }
            _ => None,
        };
        let Some(echeance) = echeance else {
            if interruptions {
                cpu::activer_interruptions();
            }
            break;
        };
        attente::dormir(Some(echeance), Sommeil::Ininterruptible);
        if let Some(c) = EN_COURS.verrouiller().as_ref() {
            c.attente.retirer(tache::courante());
        }
        if interruptions {
            cpu::activer_interruptions();
        }
        let fin = {
            let mut g = EN_COURS.verrouiller();
            g.as_mut().filter(|c| !c.fini).and_then(|c| {
                let e = c.client.temps(temps::ns_monotone());
                traiter(i, c, e)
            })
        };
        if let Some(f) = fin {
            dire(i, f);
        }
    }
}
