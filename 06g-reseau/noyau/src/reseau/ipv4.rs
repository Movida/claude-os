//! IPv4 : les adresses des interfaces, la table de routage, et l'entrée
//! des paquets (net/ipv4/ip_input.c, et les refus de `ip_route_input_slow`).
//!
//! Les règles (quelle route, quelles adresses sont à nous) sont dans la
//! bibliothèque inet (inet::routes), testée sur l'hôte ; la table vit ici,
//! sous un verrou, faite au démarrage à sa taille définitive.
//!
//! L'ENTRÉE, dans l'ordre de Linux : l'en-tête vérifié (formats, l'ordre
//! d'`ip_rcv_core`) ; puis les « martiens », jetés et comptés sans rien
//! dire (Linux les dit seulement avec `log_martians`) : une source de
//! multidiffusion ou de diffusion, une source 0.0.0.0 (sauf vers la
//! diffusion limitée : c'est ainsi que parle un client DHCP), une
//! destination 0.0.0.0 (sauf de 0.0.0.0 : Linux reçoit ce paquet comme une
//! diffusion), une adresse de boucle (127.0.0.0/8) venue d'une
//! carte, une source qui est une de NOS adresses venue d'une carte. slirp
//! en envoie : l'ICMP d'un port fermé de 10.0.2.2 porte la source 127.0.0.1
//! (ce que dit l'hôte), et Linux le jette. Puis la destination : une de nos
//! adresses, ou une diffusion de l'interface ; sinon, le paquet n'est pas
//! pour nous (pas de routage entre interfaces : nous ne sommes pas un
//! routeur, `ip_forward` = 0). Un fragment est jeté (pas de réassemblage :
//! « Reste à faire »). Les options : un paquet à route source (LSRR, SSRR)
//! est jeté, comme Linux par défaut (`accept_source_route` à 0), et un
//! en-tête dont les options ne se lisent pas aussi ; les autres sont
//! sautées (Linux les vérifie une à une, `ip_options_compile`, et répond à
//! une option fausse par un « problème de paramètre » : un écart). Avant la
//! configuration,
//! les réponses au client DHCP (port 68) lui sont passées quelle que soit
//! leur destination (le `ic_bootp_recv` de Linux, branché avant ce tri).

use super::interface::Interface;
use super::paquet::Paquet;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicU64, Ordering};
use formats::reseau::{dhcp as format_dhcp, ipv4, udp};
use inet::routes::Table;

/// Les adresses et les routes ; faites au démarrage.
static TABLE: Verrou<Option<Table>> = Verrou::new(None);

/// Les paquets jetés à l'entrée (les compteurs d'`/proc/net/snmp` de Linux,
/// pas encore montrés) : en-tête faux, martiens, pas pour nous, fragments.
static ENTETES_FAUX: AtomicU64 = AtomicU64::new(0);
static MARTIENS: AtomicU64 = AtomicU64::new(0);
static PAS_POUR_NOUS: AtomicU64 = AtomicU64::new(0);
static FRAGMENTS: AtomicU64 = AtomicU64::new(0);
static OPTIONS: AtomicU64 = AtomicU64::new(0);

/// Fait la table (vide). Au démarrage.
pub fn initialiser() {
    *TABLE.verrouiller() = Table::new(inet::routes::MAX);
}

/// Fait `f` sur la table (sous son verrou : `f` ne dort pas). None : pas de
/// table (plus de mémoire au démarrage).
pub fn avec_table<R>(f: impl FnOnce(&mut Table) -> R) -> Option<R> {
    TABLE.verrouiller().as_mut().map(f)
}

fn compter(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// Le paquet `h` est-il de 0.0.0.0 pour 0.0.0.0 (une diffusion, pour
/// `ip_route_input_slow`) ?
fn de_rien_a_rien(h: &ipv4::Ipv4) -> bool {
    h.source == ipv4::AUCUNE && h.destination == ipv4::AUCUNE
}

/// Un martien (voir plus haut) ?
fn martien(i: &Interface, h: &ipv4::Ipv4, table: &Table) -> bool {
    let carte = !i.boucle();
    if de_rien_a_rien(h) {
        return false;
    }
    ipv4::multidiffusion(h.source)
        || h.source == ipv4::DIFFUSION
        || (h.source == ipv4::AUCUNE && h.destination != ipv4::DIFFUSION)
        || h.destination == ipv4::AUCUNE
        || (carte && (ipv4::boucle(h.source) || ipv4::boucle(h.destination)))
        || (carte && table.est_a_nous(h.source))
}

/// Les options de l'en-tête `entete` (au-delà des 20 octets) se lisent-elles,
/// sans route source (`ip_rcv_options` : LSRR 131, SSRR 137) ? Chaque
/// option : un octet de genre, puis (sauf la fin, 0, et le bourrage, 1)
/// un octet de longueur, qui couvre ces deux octets et tient dans l'en-tête.
fn options_acceptees(entete: &[u8]) -> bool {
    const FIN: u8 = 0;
    const BOURRAGE: u8 = 1;
    const LSRR: u8 = 131;
    const SSRR: u8 = 137;
    let mut o = entete.get(ipv4::ENTETE..).unwrap_or(&[]);
    while let Some(&genre) = o.first() {
        match genre {
            FIN => return true,
            BOURRAGE => o = &o[1..],
            LSRR | SSRR => return false,
            _ => {
                let Some(&longueur) = o.get(1) else { return false };
                if longueur < 2 || longueur as usize > o.len() {
                    return false;
                }
                o = &o[longueur as usize..];
            }
        }
    }
    true
}

/// Un paquet IPv4 (sans son en-tête Ethernet) reçu par `i`, dans la tâche
/// du réseau.
pub fn recevoir(i: &'static Interface, p: Paquet) {
    let Ok((h, charge)) = ipv4::lire(p.donnees()) else { return compter(&ENTETES_FAUX) };
    // Le client DHCP d'abord, avant le tri des destinations : l'interface
    // n'a pas encore d'adresse.
    if h.protocole == ipv4::UDP && !h.est_un_fragment() && super::dhcp::en_cours(i.index) {
        if let Ok((u, message)) = udp::lire(charge, h.source, h.destination) {
            if u.source == format_dhcp::PORT_SERVEUR && u.destination == format_dhcp::PORT_CLIENT {
                return super::dhcp::recu(i, message);
            }
        }
    }
    let pour_nous = TABLE.verrouiller().as_ref().map(|t| {
        if martien(i, &h, t) {
            Err(&MARTIENS)
        } else if t.est_a_nous(h.destination) || t.est_diffusion(i.index, h.destination) || de_rien_a_rien(&h) {
            Ok(())
        } else {
            Err(&PAS_POUR_NOUS)
        }
    });
    match pour_nous {
        Some(Ok(())) => {}
        Some(Err(c)) => return compter(c),
        None => return,
    }
    if h.est_un_fragment() {
        return compter(&FRAGMENTS);
    }
    if !options_acceptees(&p.donnees()[..h.longueur_entete]) {
        return compter(&OPTIONS);
    }
    // Aucun protocole au-dessus d'IPv4 pour l'instant : le paquet s'arrête
    // ici.
}

/// Émet par `i` le paquet `p` (sa charge en place) en diffusion limitée
/// (255.255.255.255), de la source `source` (0.0.0.0 avant d'avoir une
/// adresse), pour le protocole `protocole` : le client DHCP. TTL 64 (le
/// `ip_default_ttl` de Linux), DF (comme `ipconfig.c`), identifiant 0 (DF :
/// le paquet ne sera jamais fragmenté).
pub fn emettre_en_diffusion(i: &'static Interface, source: [u8; 4], protocole: u8, mut p: Paquet) {
    let longueur = (p.longueur() + ipv4::ENTETE) as u16;
    let Some(entete) = p.ajouter_entete(ipv4::ENTETE) else { return };
    let entete: &mut [u8; ipv4::ENTETE] = entete.try_into().expect("20 octets");
    ipv4::ecrire(entete, &ipv4::Ipv4 {
        tos: 0,
        longueur,
        identifiant: 0,
        ne_pas_fragmenter: true,
        fragments_suivants: false,
        decalage: 0,
        ttl: 64,
        protocole,
        source,
        destination: ipv4::DIFFUSION,
        longueur_entete: ipv4::ENTETE,
    });
    super::ethernet::emettre(i, formats::reseau::ethernet::DIFFUSION, formats::reseau::ethernet::IPV4, p);
}
