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
//! une option fausse par un « problème de paramètre » : un écart). Avant
//! la configuration, les réponses au client DHCP (port 68) lui sont
//! passées quelle que soit leur destination (le `ic_bootp_recv` de Linux,
//! branché avant ce tri).
//! Puis le protocole : UDP (udp.rs), ICMP (icmp.rs) ; un autre, ou un
//! datagramme UDP sans socket, reçoit l'erreur ICMP de Linux.
//!
//! LA SORTIE (`ip_queue_xmit`, `ip_make_skb`) : la route (`router`), puis
//! l'en-tête, puis l'interface : `lo` pour une de nos adresses (Linux
//! aussi : la route locale passe par `lo`), la diffusion d'Ethernet pour
//! une diffusion, le voisin (ARP) pour le reste. Pas de fragmentation : un
//! paquet plus grand que la MTU est refusé avant (EMSGSIZE, udp.rs ; un
//! écart, Linux le fragmente avec IP_PMTUDISC_WANT, le réglage par
//! défaut). Une diffusion envoyée n'est pas rendue aussi aux sockets de la
//! machine (Linux en fait toujours une copie par la boucle, `ip_mc_output` ;
//! IP_MULTICAST_LOOP ne règle que la multidiffusion) : un écart écrit.

use super::interface::{self, Interface};
use super::paquet::Paquet;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use formats::reseau::{dhcp as format_dhcp, ethernet, icmp, ipv4, udp};
use inet::routes::{Chemin, Table};

const ENETUNREACH: i64 = 101;

/// Les adresses et les routes ; faites au démarrage.
static TABLE: Verrou<Option<Table>> = Verrou::new(None);

/// Les paquets jetés à l'entrée (les compteurs d'`/proc/net/snmp` de Linux,
/// pas encore montrés) : en-tête faux, martiens, pas pour nous, fragments.
static ENTETES_FAUX: AtomicU64 = AtomicU64::new(0);
static MARTIENS: AtomicU64 = AtomicU64::new(0);
static PAS_POUR_NOUS: AtomicU64 = AtomicU64::new(0);
static FRAGMENTS: AtomicU64 = AtomicU64::new(0);
static OPTIONS: AtomicU64 = AtomicU64::new(0);

/// L'identifiant des paquets qui en demandent un sans être d'une socket
/// connectée (voir `identifiant`).
static IDENTIFIANT: AtomicU16 = AtomicU16::new(0);

/// Fait la table (vide), et tire le premier identifiant. Au démarrage.
pub fn initialiser() {
    *TABLE.verrouiller() = Table::new(inet::routes::MAX);
    let mut h = [0u8; 2];
    crate::aleatoire::remplir(&mut h);
    IDENTIFIANT.store(u16::from_le_bytes(h), Ordering::Relaxed);
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
/// du réseau ; `trame_diffusee` : sa trame allait à toutes les machines
/// (jamais d'erreur ICMP en réponse).
pub fn recevoir(i: &'static Interface, p: Paquet, trame_diffusee: bool) {
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
    // Une diffusion (la limitée, ou celle d'un réseau de l'interface) va à
    // chaque socket qui l'accepte.
    let diffusion = TABLE.verrouiller().as_ref().is_some_and(|t| t.est_diffusion(i.index, h.destination)) || de_rien_a_rien(&h);
    let mut p = p;
    let longueur = h.longueur as usize - h.longueur_entete;
    let _ = p.retirer_entete(h.longueur_entete);
    p.couper(longueur);
    // Un protocole sans destinataire : l'erreur ICMP de Linux (« port
    // injoignable » d'UDP, `__udp4_lib_rcv` ; « protocole injoignable »
    // sinon, `ip_local_deliver_finish`), avec le paquet d'origine, son
    // en-tête remis devant ; jamais pour une diffusion.
    let injoignable = |code: u8, mut p: Paquet| {
        if diffusion || p.ajouter_entete(h.longueur_entete).is_none() {
            return;
        }
        super::icmp::envoyer_erreur(icmp::INJOIGNABLE, code, 0, p.donnees(), i.boucle(), true, trame_diffusee);
    };
    match h.protocole {
        ipv4::UDP => {
            if let Err(p) = super::udp::recevoir(i.index, h.source, h.destination, diffusion, p) {
                injoignable(icmp::PORT, p);
            }
        }
        ipv4::ICMP => super::icmp::recevoir(i, &h, diffusion, p),
        _ => injoignable(icmp::PROTOCOLE, p),
    }
}

/// Ce que précise l'envoi d'un paquet (le `flowi4` et l'`ipcm_cookie` de
/// Linux) : les adresses, le protocole, et les champs de l'en-tête.
pub struct Envoi {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub protocole: u8,
    pub ttl: u8,
    pub tos: u8,
    pub identifiant: u16,
    pub ne_pas_fragmenter: bool,
    /// MSG_CONFIRM : la machine voisine est là (arp.rs).
    pub confirmer: bool,
}

/// Le chemin vers `destination` (l'`ip_route_output_key` de Linux), et la
/// destination à mettre dans l'en-tête : 0.0.0.0 veut dire « cette
/// machine », et devient la source demandée (`source` : celle de `bind`
/// ou d'IP_PKTINFO), ou sans elle 127.0.0.1, comme
/// `ip_route_output_key_hash_rcu`. Pas de route : ENETUNREACH.
pub fn router(destination: [u8; 4], source: Option<[u8; 4]>) -> Result<(Chemin, [u8; 4]), i64> {
    let destination = if destination == ipv4::AUCUNE {
        source.filter(|&s| s != ipv4::AUCUNE).unwrap_or(super::boucle::ADRESSE)
    } else {
        destination
    };
    match TABLE.verrouiller().as_ref().and_then(|t| t.chercher(destination)) {
        Some(c) => Ok((c, destination)),
        None => Err(-ENETUNREACH),
    }
}

/// L'adresse source que propose le chemin `c`.
pub fn source(c: &Chemin) -> [u8; 4] {
    match *c {
        Chemin::Locale { source } | Chemin::Diffusion { source, .. } | Chemin::Unicast { source, .. } => source,
    }
}

/// Le chemin `c` passe-t-il par `lo` ?
pub fn par_lo(c: &Chemin) -> bool {
    interface_de(c).is_some_and(|i| i.boucle())
}

/// L'interface qui porte notre adresse `a`, s'il y en a une.
pub fn interface_de_l_adresse(a: [u8; 4]) -> Option<u32> {
    avec_table(|t| t.interface_de(a)).flatten()
}

/// L'interface par où part ce qui suit le chemin `c`.
fn interface_de(c: &Chemin) -> Option<&'static Interface> {
    match *c {
        Chemin::Locale { .. } => super::boucle::interface(),
        Chemin::Diffusion { interface, .. } | Chemin::Unicast { interface, .. } => interface::par_index(interface),
    }
}

/// La MTU du chemin `c` : celle de son interface, au plus 65 535 (la plus
/// grande longueur que dit un en-tête IPv4 : `ipv4_mtu` borne aussi celle
/// de lo, 65 536, à IP_MAX_MTU). Linux mémorise aussi celle qu'apprend un
/// ICMP « fragmentation nécessaire » : pas encore.
pub fn mtu(c: &Chemin) -> u32 {
    interface_de(c).map_or(super::boucle::MTU, |i| i.mtu()).min(0xFFFF)
}

/// Un identifiant pour un paquet qui n'est pas d'une socket connectée :
/// un envoi d'UDP ou de ping (sauf IP_PMTUDISC_DO et PROBE, qui ont 0 :
/// voir `datagramme::preparer`), et chaque réponse et erreur d'ICMP. Linux
/// le tire de compteurs choisis par un hachage à clé secrète de la
/// destination (`__ip_select_ident`), pour qu'un tiers ne puisse pas
/// compter, par la différence de deux identifiants qu'il reçoit, ce que la
/// machine envoie aux autres ; chez nous, un compteur parti du hasard, que
/// ce tiers peut lire (deux pings lui disent combien d'ICMP sont partis
/// entre-temps vers d'autres) : un écart écrit, jusqu'au générateur
/// ChaCha20 de 6h (qui servira aussi aux numéros de séquence de TCP).
pub fn identifiant() -> u16 {
    IDENTIFIANT.fetch_add(1, Ordering::Relaxed)
}

/// Émet le paquet `p` (sa charge en place, l'en-tête du protocole
/// compris) selon `e`, par le chemin `c` : l'en-tête IPv4 devant, puis
/// l'interface du chemin, dans le contexte de qui envoie (le
/// `dev_queue_xmit` de Linux). Rien ne revient : un paquet perdu en route
/// (file pleine, voisin muet) l'est sans le dire, comme sur un câble.
pub fn emettre(c: Chemin, e: &Envoi, mut p: Paquet) {
    let longueur = (p.longueur() + ipv4::ENTETE) as u16;
    let Some(entete) = p.ajouter_entete(ipv4::ENTETE) else { return };
    let entete: &mut [u8; ipv4::ENTETE] = entete.try_into().expect("20 octets");
    ipv4::ecrire(entete, &ipv4::Ipv4 {
        tos: e.tos,
        longueur,
        identifiant: e.identifiant,
        ne_pas_fragmenter: e.ne_pas_fragmenter,
        fragments_suivants: false,
        decalage: 0,
        ttl: e.ttl,
        protocole: e.protocole,
        source: e.source,
        destination: e.destination,
        longueur_entete: ipv4::ENTETE,
    });
    let Some(i) = interface_de(&c) else { return };
    match c {
        // lo : pas de voisin (IFF_NOARP), une adresse matérielle nulle.
        Chemin::Locale { .. } => super::ethernet::emettre(i, [0; 6], ethernet::IPV4, p),
        Chemin::Diffusion { .. } => super::ethernet::emettre(i, ethernet::DIFFUSION, ethernet::IPV4, p),
        Chemin::Unicast { prochain, .. } => super::arp::envoyer(i, prochain, p, e.confirmer),
    }
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
    super::ethernet::emettre(i, ethernet::DIFFUSION, ethernet::IPV4, p);
}
