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
//! routeur, `ip_forward` = 0). Un paquet pour un groupe de multidiffusion
//! est trié avant tout : jeté sans rien compter si l'interface n'a pas le
//! groupe, ou que son filtre refuse la source (multidiffusion.rs) ; puis les
//! martiens (une source 0.0.0.0 y est permise vers 224.0.0.0/24, et pour
//! IGMP) ; puis il est pour nous, comme une diffusion. Les options, entre les deux comme chez
//! Linux (`ip_rcv_options`, après la route d'entrée, que Linux fait aussi
//! pour un paquet qui n'est pas pour lui) : vérifiées une à une et notées
//! sur place (`compiler_options`, l'`ip_options_compile` de Linux) ; une
//! option fausse reçoit un « problème de paramètre » qui dit son octet, et
//! le paquet est jeté ; un paquet à route source (LSRR, SSRR) est jeté sans
//! rien dire, comme Linux par défaut (`accept_source_route` à 0). Un
//! fragment va au réassemblage (inet::fragments). Avant la configuration,
//! les réponses au client DHCP (port 68) lui sont passées quelle que soit
//! leur destination (le `ic_bootp_recv` de Linux, branché avant ce tri,
//! qui ne prend qu'un paquet entier, sans options).
//! Puis le protocole : UDP (udp.rs), ICMP (icmp.rs) ; un autre, ou un
//! datagramme UDP sans socket, reçoit l'erreur ICMP de Linux.
//!
//! Un paquet que nous nous sommes envoyé par lo n'a pas ce tri : comme chez
//! Linux, il garde la route de sa sortie (`loopback_xmit` ne lâche pas son
//! `skb_dst`, et `ip_rcv_finish_core` ne cherche pas de route d'entrée à un
//! paquet qui en a une). Il est pour nous quelle que soit sa destination
//! (`ip_local_deliver` : par un envoi forcé par lo, une adresse d'ailleurs
//! aussi, mesuré), une diffusion si sa route l'était, et arrivé par
//! l'interface de sa route (`inet_iif`) : la carte pour l'adresse de la
//! carte, lo pour 127.0.0.0/8, l'interface demandée pour un envoi forcé.
//!
//! LES COMPTEURS d'IP (/proc/net/snmp, snmp.rs), aux places de Linux :
//! chaque paquet arrivé (InReceives), avant tout examen ; un en-tête ou une
//! option faux (InHdrErrors), sauf un paquet plus court que ne le dit un
//! en-tête juste (InTruncatedPkts, d'IpExt, que /proc/net/snmp ne montre
//! pas) ; un paquet pas pour nous (InAddrErrors : `ip_error`, nous ne
//! routons pas) ; livré à un protocole (InDelivers), ou d'un protocole
//! inconnu (InUnknownProtos) ; le réassemblage (inet::fragments, et ReasmOKs
//! ici). Les martiens et les routes sources ne sont pas des compteurs de
//! snmp (Linux : /proc/net/stat/rt_cache, et un message) : les nôtres
//! (MARTIENS, ROUTES_SOURCES) ne sont pas montrés. À la sortie : chaque
//! paquet à émettre (OutRequests : `__ip_local_out`), chaque paquet ou
//! morceau confié à une interface (OutTransmits : `ip_finish_output2`), le
//! découpage (FragOKs, FragFails, FragCreates). OutNoRoutes et OutDiscards
//! sont comptés par qui envoie (datagramme.rs, icmp.rs, tcp.rs).
//!
//! LA SORTIE (`ip_queue_xmit`, `ip_make_skb`) : la route (`router`), puis
//! l'en-tête, avec les options de l'envoi (IP_OPTIONS, IP_RETOPTS, l'écho de
//! celles d'un paquet auquel on répond), complétées une fois
//! (`ip_options_build` : notre adresse, l'heure, la vraie destination au bout
//! d'une route source, l'en-tête allant à sa première étape), puis l'interface : `lo` pour une de nos adresses (Linux
//! aussi : la route locale passe par `lo`) et pour un envoi forcé par lo
//! (IP_PKTINFO, IP_UNICAST_IF), sans voisin, le paquet marqué de sa route
//! (`Sortie`) ; la diffusion d'Ethernet pour une diffusion, l'adresse MAC du
//! groupe pour une multidiffusion, le voisin (ARP)
//! pour le reste. Un paquet plus grand que la MTU
//! part en fragments, sauf DF (`ip_do_fragment`). Une diffusion envoyée par une
//! carte est aussi rendue aux sockets de la machine, comme chez Linux, qui en fait
//! toujours une copie par la boucle (`ip_mc_output` ; IP_MULTICAST_LOOP ne règle que
//! la multidiffusion) : le paquet entier, avant tout découpage, livré comme arrivé
//! par la carte (boucle.rs, `rendre_la_diffusion`). Par `lo`, la diffusion de `lo`
//! (127.255.255.255) n'arrive qu'une fois, comme chez Linux (mesuré). De même pour
//! un groupe que la carte laisse entrer (`emettre`), sauf IP_MULTICAST_LOOP 0.

use super::interface::{self, Interface};
use super::paquet::{Contexte, Paquet, Sortie};
use super::snmp::MIB;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use formats::reseau::{Erreur, dhcp as format_dhcp, ethernet, icmp, ipv4, udp};
use inet::fragments::{Cle, Issue, Morceau, Reassemblage};
use inet::snmp::Ip;
use inet::pmtu::Exceptions;
use inet::routes::{Chemin, Portee, Table};

const ENETUNREACH: i64 = 101;

/// Le TTL d'un paquet sans IP_TTL (le réglage `ip_default_ttl`, que
/// montrent /proc/sys/net et /proc/net/snmp).
pub const TTL_DEFAUT: u8 = 64;

/// Les deux bits ECN du TOS (`INET_ECN_MASK`, RFC 3168) : ceux de la
/// congestion, que tient TCP ; le reste est le DSCP.
pub const ECN: u8 = 3;

/// Les adresses et les routes ; faites au démarrage.
static TABLE: Verrou<Option<Table>> = Verrou::new(None);

/// La MTU du chemin de chaque destination apprise par ICMP (inet::pmtu).
static EXCEPTIONS: Verrou<Exceptions> = Verrou::new(Exceptions::new());

/// Les paquets en morceaux qui nous arrivent (inet::fragments), et ceux qu'on a pu
/// recoller ou non : faits au démarrage.
static REASSEMBLAGE: Verrou<Option<Reassemblage<Fragment>>> = Verrou::new(None);

/// Un morceau en attente : le paquet (sans son en-tête, que garde encore son tampon), et
/// ce que la vérification de ses options en a tiré (son `IPCB(skb)->opt` : celui du
/// premier morceau vaut pour le paquet recollé, `ip_frag_reasm` gardant sa tête).
struct Fragment {
    paquet: Paquet,
    options: ipv4::Options,
}

impl Morceau for Fragment {
    fn octets(&self) -> &[u8] {
        self.paquet.donnees()
    }
    fn couper(&mut self, n: usize) {
        self.paquet.couper(n);
    }
    fn taille_vraie(&self) -> usize {
        self.paquet.taille_vraie()
    }
}

/// Ce que la réception garde de l'en-tête IPv4 d'un paquet pour nous, que relisent les
/// messages de contrôle d'une réception (IP_RECVTTL, IP_RECVTOS, IP_RECVOPTS,
/// IP_RETOPTS, IP_RECVFRAGSIZE : `ip_cmsg_recv_offset`), d'un datagramme en file ou
/// d'une erreur ICMP en file (alors celui du message ICMP).
///
/// Choix de conception : une copie à part, une soixantaine d'octets avec chaque
/// datagramme en file. Linux relit l'en-tête dans le paquet même (`ip_hdr(skb)`), et
/// garde à côté ce que la réception en a tiré (`IPCB(skb)` : les options vérifiées,
/// `frag_max_size`) ; ses copies d'une diffusion partagent le paquet (`skb_clone`). Les
/// nôtres ne copient que la charge (udp.rs, `Paquet::copie`), et une erreur en file ne
/// garde que ce que le programme lira : y garder aussi l'en-tête coûterait sa place à
/// chaque copie, et lierait la lecture à la forme du tampon. Écarté aussi : ne garder
/// que ce qu'ont demandé les options de la socket à l'arrivée ; Linux lit les options au
/// moment de la lecture, un drapeau posé entre les deux vaut pour ce qui est en file.
#[derive(Clone, Copy)]
pub struct EnteteRecu {
    pub ttl: u8,
    pub tos: u8,
    /// Les options après ce que la réception y a noté (`opt.optlen` octets, bourrage
    /// compris), et ce qu'elle en a tiré.
    pub options: [u8; ipv4::OPTIONS_MAX],
    pub longueur_options: u8,
    pub compilees: ipv4::Options,
    /// La taille du plus grand morceau d'un paquet recollé, son en-tête compris
    /// (`frag_max_size`) ; 0 : il n'était pas en morceaux.
    pub fragment_max: u16,
}

impl EnteteRecu {
    /// Rien (une erreur locale, qui n'a pas de message de contrôle IP).
    pub const AUCUN: EnteteRecu = EnteteRecu {
        ttl: 0, tos: 0, options: [0; ipv4::OPTIONS_MAX], longueur_options: 0, compilees: ipv4::Options::AUCUNES, fragment_max: 0,
    };

    /// Celui du paquet `paquet` (son en-tête au début), lu `h`, aux options vérifiées `o`.
    pub fn de(h: &ipv4::Ipv4, paquet: &[u8], compilees: ipv4::Options, fragment_max: u16) -> EnteteRecu {
        let mut options = [0; ipv4::OPTIONS_MAX];
        let n = h.longueur_entete.saturating_sub(ipv4::ENTETE).min(ipv4::OPTIONS_MAX);
        if let Some(o) = paquet.get(ipv4::ENTETE..ipv4::ENTETE + n) {
            options[..n].copy_from_slice(o);
        }
        EnteteRecu { ttl: h.ttl, tos: h.tos, options, longueur_options: n as u8, compilees, fragment_max }
    }

    /// Les octets des options.
    pub fn options(&self) -> &[u8] {
        &self.options[..self.longueur_options as usize]
    }
}

/// Les paquets jetés à l'entrée qui ne sont pas des compteurs de
/// /proc/net/snmp : les martiens (le `in_martian_src` et `in_martian_dst`
/// de /proc/net/stat/rt_cache chez Linux), les routes sources (un message,
/// avec `log_martians`). Pas montrés.
static MARTIENS: AtomicU64 = AtomicU64::new(0);
static ROUTES_SOURCES: AtomicU64 = AtomicU64::new(0);

/// Les identifiants des paquets qui en demandent un sans être d'une
/// socket connectée (voir `identifiant`) : 2048 compteurs (`ip_idents`),
/// partis du hasard, et le tic de leur dernier usage (`ip_tstamps`).
const IDENTS: usize = 2048;
static IDENTS_COMPTEURS: [AtomicU32; IDENTS] = [const { AtomicU32::new(0) }; IDENTS];
static IDENTS_TICS: [AtomicU32; IDENTS] = [const { AtomicU32::new(0) }; IDENTS];
/// La clé secrète qui choisit le compteur d'une destination
/// (`net->ipv4.ip_id_key`).
static CLE_IDENTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Fait la table (vide), et tire les compteurs d'identifiants et leur clé.
/// Au démarrage.
pub fn initialiser() {
    *TABLE.verrouiller() = Table::new(inet::routes::MAX);
    *REASSEMBLAGE.verrouiller() = Reassemblage::new(&MIB);
    for c in &IDENTS_COMPTEURS {
        c.store(crate::aleatoire::u32(), Ordering::Relaxed);
    }
    for k in &CLE_IDENTS {
        k.store(crate::aleatoire::u64(), Ordering::Relaxed);
    }
}

/// Fait `f` sur la table (sous son verrou : `f` ne dort pas). None : pas de
/// table (plus de mémoire au démarrage).
#[track_caller]
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

/// Un martien (voir plus haut) ? Pour un groupe, les mêmes règles
/// (`ip_mc_validate_source`), sauf la source 0.0.0.0, permise vers un groupe
/// du lien (224.0.0.0/24) et pour IGMP (un rapport d'une machine qui n'a
/// pas encore d'adresse, RFC 3376, 4.2.13).
fn martien(i: &Interface, h: &ipv4::Ipv4, table: &Table) -> bool {
    let carte = !i.boucle();
    if de_rien_a_rien(h) {
        return false;
    }
    let source_nulle_permise = h.destination == ipv4::DIFFUSION
        || (ipv4::multidiffusion(h.destination) && (ipv4::multidiffusion_du_lien(h.destination) || h.protocole == ipv4::IGMP));
    ipv4::multidiffusion(h.source)
        || h.source == ipv4::DIFFUSION
        || (h.source == ipv4::AUCUNE && !source_nulle_permise)
        || h.destination == ipv4::AUCUNE
        || (carte && (ipv4::boucle(h.source) || ipv4::boucle(h.destination)))
        || (carte && table.est_a_nous(h.source))
}

/// Les options du paquet reçu `p` par `i` (son en-tête : `h`), vérifiées
/// et notées sur place (`ip_options_compile`), sous le verrou de la table :
/// ce qu'elles notent de nous est l'adresse par laquelle l'émetteur nous
/// joint (`fib_compute_spec_dst`) : la destination d'un paquet pour une
/// seule de nos adresses (`locale`), sinon celle que propose la route vers
/// l'émetteur, ou l'interface (inet::routes, `adresse_pour_repondre`).
/// None : pas de table.
fn lire_options(i: &Interface, h: &ipv4::Ipv4, p: &mut Paquet, locale: bool) -> Option<Result<ipv4::Options, ipv4::Faute>> {
    let garde = TABLE.verrouiller();
    let t = garde.as_ref()?;
    let adresse = if locale { h.destination } else { t.adresse_pour_repondre(h.source, i.index) };
    let ici = ipv4::Ici { adresse, heure: super::icmp::horodatage(), unicast: &|a| t.est_unicast(a) };
    let entete = p.donnees_mut().get_mut(..h.longueur_entete)?;
    Some(ipv4::compiler_options(entete, &ici))
}

/// Un paquet IPv4 (sans son en-tête Ethernet) reçu par `i`, dans la tâche
/// du réseau ; `trame_diffusee` : sa trame allait à toutes les machines
/// (jamais d'erreur ICMP en réponse).
pub fn recevoir(i: &'static Interface, mut p: Paquet, trame_diffusee: bool) {
    MIB.ip(Ip::InReceives);
    // Où commence son en-tête (`ip_rcv_core` : `skb_reset_network_header`).
    p.noter_reseau();
    let (h, charge) = match ipv4::lire(p.donnees()) {
        Ok(x) => x,
        Err(e) => {
            if !(e == Erreur::Tronque && ipv4::lire_cite(p.donnees()).is_ok()) {
                MIB.ip(Ip::InHdrErrors);
            }
            return;
        }
    };
    // Le client DHCP d'abord, avant le tri des destinations : l'interface
    // n'a pas encore d'adresse. Linux lui passe la trame à côté d'IP (deux
    // gestionnaires de trames IPv4, `ic_bootp_recv` et `ip_rcv`) ; nous ne la
    // passons qu'à lui : notre client peut prendre son adresse avant qu'IP
    // ne trie la trame, qui serait alors « pour nous », vers un port 68 sans
    // socket : une erreur ICMP partirait vers le serveur. Comptée à
    // l'arrivée seulement.
    if h.protocole == ipv4::UDP && !h.est_un_fragment() && h.longueur_entete == ipv4::ENTETE && super::dhcp::en_cours(i.index) {
        if let Ok((u, message)) = udp::lire(charge, h.source, h.destination) {
            if u.source == format_dhcp::PORT_SERVEUR && u.destination == format_dhcp::PORT_CLIENT {
                return super::dhcp::recu(i, message);
            }
        }
    }
    // Le tri de la route d'entrée : un martien, ou pour nous (à une de nos
    // adresses, ou en diffusion), ou pas ; arrivé par `i`. Sans tri, ce que
    // nous nous sommes envoyé par lo (voir l'en-tête) : la route de sa sortie,
    // qui jette sans rien compter un groupe que lo n'a pas (`dst_discard`).
    // Un groupe (`ip_route_input_rcu`) : que l'interface n'a pas, ou dont le
    // filtre refuse la source, jeté sans rien compter ; puis les martiens ;
    // pour nous, comme une diffusion (`ip_route_input_mc`). (Les groupes
    // d'abord, seuls : jamais sous le verrou de la table, multidiffusion.rs.)
    let de_nous = p.sortie().is_some();
    let tri = match p.sortie() {
        Some(s) if !s.livre => return,
        Some(s) => Some(Some((true, s.diffusion, s.interface))),
        None if ipv4::multidiffusion(h.destination) => {
            if !super::multidiffusion::verifier(i.index, h.destination, h.source, h.protocole) {
                return;
            }
            TABLE.verrouiller().as_ref().map(|t| (!martien(i, &h, t)).then_some((true, true, i.index)))
        }
        None => TABLE.verrouiller().as_ref().map(|t| {
            if martien(i, &h, t) {
                None
            } else {
                let diffusion = t.est_diffusion(i.index, h.destination) || de_rien_a_rien(&h);
                Some((t.est_a_nous(h.destination) || diffusion, diffusion, i.index))
            }
        }),
    };
    let (pour_nous, diffusion, interface) = match tri {
        Some(Some(x)) => x,
        Some(None) => return compter(&MARTIENS),
        None => return,
    };
    let mut p = p;
    let mut compilees = ipv4::Options::AUCUNES;
    if h.longueur_entete > ipv4::ENTETE {
        match lire_options(i, &h, &mut p, pour_nous && !diffusion) {
            None => return,
            // Une option fausse : le « problème de paramètre » dit son
            // octet, dans les 8 bits forts de ses 4 octets (`icmp_send`
            // d'`ip_options_compile`) ; jamais pour une diffusion.
            // Elle fait l'écho de ce qui précède la faute.
            Some(Err(f)) => {
                MIB.ip(Ip::InHdrErrors);
                if !diffusion {
                    super::icmp::envoyer_erreur(icmp::PARAMETRE, 0, (f.place as u32) << 24, p.donnees(), &f.options, i.boucle(),
                                                pour_nous, trame_diffusee);
                }
                return;
            }
            Some(Ok(o)) if o.route_source != 0 => return compter(&ROUTES_SOURCES),
            Some(Ok(o)) => compilees = o,
        }
    }
    if !pour_nous {
        return MIB.ip(Ip::InAddrErrors);
    }
    let a_verifier = !i.boucle();
    livrer(i, h, p, compilees, Arrivee { diffusion, trame_diffusee, a_verifier, interface, de_nous });
}

/// Comment un paquet est arrivé : sa destination est une diffusion ; sa trame Ethernet
/// allait à toutes les machines (jamais d'erreur ICMP en réponse) ; sa somme UDP reste à
/// calculer en entier (udp.rs, IP_CHECKSUM) ; l'interface par laquelle on le dit
/// arrivé (`inet_iif` : celle qui l'a reçu, ou celle de sa route s'il est parti
/// par lo).
///
/// La dernière est le `CHECKSUM_NONE` de Linux : notre virtio-net ne demande pas à la
/// carte de vérifier les sommes (VIRTIO_NET_F_GUEST_CSUM), comme une carte sans ce
/// réglage chez Linux. Par `lo`, Linux laisse UDP à CHECKSUM_PARTIAL (l'envoi ne l'a
/// pas calculée : `lo` « sait » le faire) ; la copie d'une diffusion qu'il se rend
/// est CHECKSUM_UNNECESSARY (`dev_loopback_xmit`) : aucune n'aura de somme complète.
#[derive(Clone, Copy)]
struct Arrivee {
    diffusion: bool,
    trame_diffusee: bool,
    a_verifier: bool,
    interface: u32,
    /// Il vient de nous : parti par lo, ou la copie d'un envoi par une
    /// carte (sa route est celle d'une sortie, `rt_is_output_route`).
    de_nous: bool,
}

/// Où un datagramme pour nous est arrivé, ce que prépare IP_PKTINFO pour une
/// socket qui l'a (`ipv4_pktinfo_prepare`, udp.rs) : l'interface (`inet_iif`)
/// et l'adresse par laquelle l'émetteur nous joint (`fib_compute_spec_dst`) ;
/// et la carte qui l'a reçu (`skb->dev` : lo pour tout ce que nous nous
/// envoyons, même à l'adresse d'une autre carte, que dit pourtant `interface`),
/// ce que voit un filtre (filtre.rs).
#[derive(Clone, Copy)]
pub struct Lieu {
    pub interface: u32,
    pub reponse: [u8; 4],
    pub carte: inet::filtre::Carte,
}

/// La copie `p` d'une diffusion (ou d'un envoi pour un groupe qu'elle a) que
/// nous avons envoyée par la carte `i`
/// (boucle.rs, `rendre_la_diffusion`) : livrée comme arrivée par `i`, sans le
/// tri de l'entrée (Linux garde la route de la sortie, `skb_dst` : la source,
/// qui est à nous, n'est pas un martien). Elle compte comme un paquet arrivé
/// (Linux la fait repasser par `ip_rcv`), et ses options (IP_OPTIONS) sont
/// revues comme celles de tout paquet reçu (`ip_rcv_options`) : notées (la
/// route notée y reçoit encore notre adresse), une route source jetée, une
/// option fausse aussi (sans « problème de paramètre » : jamais pour une
/// diffusion).
pub fn recevoir_la_diffusion(i: &'static Interface, mut p: Paquet) {
    MIB.ip(Ip::InReceives);
    // Sans en-tête de liaison : celui de réseau en tient lieu (`dev_loopback_xmit` :
    // `skb_reset_mac_header` sur l'en-tête IPv4).
    p.noter_reseau();
    p.noter_liaison();
    let Ok((h, _)) = ipv4::lire(p.donnees()) else { return };
    let mut compilees = ipv4::Options::AUCUNES;
    if h.longueur_entete > ipv4::ENTETE {
        match lire_options(i, &h, &mut p, false) {
            None => return,
            Some(Err(_)) => return MIB.ip(Ip::InHdrErrors),
            Some(Ok(o)) if o.route_source != 0 => return compter(&ROUTES_SOURCES),
            Some(Ok(o)) => compilees = o,
        }
    }
    livrer(i, h, p, compilees, Arrivee { diffusion: true, trame_diffusee: false, a_verifier: false, interface: i.index, de_nous: true });
}

/// Livre aux protocoles le paquet `p` pour nous (son en-tête : `h`, ses options
/// vérifiées : `compilees`) arrivé par `i` (`ip_local_deliver`).
fn livrer(i: &'static Interface, h: ipv4::Ipv4, p: Paquet, compilees: ipv4::Options, a: Arrivee) {
    let Arrivee { diffusion, trame_diffusee, a_verifier, interface, de_nous } = a;
    // Un morceau : ce qui suit ne voit que des paquets entiers (`ip_local_deliver`).
    let (h, mut p, compilees, fragment_max) = if h.est_un_fragment() {
        match recoller(i, &h, Fragment { paquet: p, options: compilees }) {
            Some(x) => x,
            None => return,
        }
    } else {
        (h, p, compilees, 0)
    };
    let entete = EnteteRecu::de(&h, p.donnees(), compilees, fragment_max);
    // Une diffusion (la limitée, ou celle d'un réseau de l'interface) va à
    // chaque socket qui l'accepte.
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
        super::icmp::envoyer_erreur(icmp::INJOIGNABLE, code, 0, p.donnees(), &compilees, i.boucle(), true, trame_diffusee);
    };
    // Livré, même jeté ensuite par le protocole (`ip_protocol_deliver_rcu`).
    MIB.ip(if matches!(h.protocole, ipv4::UDP | ipv4::ICMP | ipv4::TCP | ipv4::IGMP) { Ip::InDelivers } else { Ip::InUnknownProtos });
    match h.protocole {
        ipv4::UDP => {
            // Ce que préparera IP_PKTINFO : l'adresse par laquelle l'émetteur
            // nous joint est la destination d'un paquet pour une seule de nos
            // adresses (ce qui n'est pas pour nous n'arrive pas jusqu'ici),
            // sinon celle que propose la route vers lui, ou l'interface qui a
            // reçu le paquet (le `skb->dev` de `fib_compute_spec_dst`).
            let reponse = if diffusion {
                avec_table(|t| t.adresse_pour_repondre(h.source, i.index)).unwrap_or(ipv4::AUCUNE)
            } else {
                h.destination
            };
            let lieu = Lieu { interface, reponse, carte: super::filtre::carte(i) };
            if let Err(p) = super::udp::recevoir(lieu, h.source, h.destination, &entete, diffusion, a_verifier, p) {
                injoignable(icmp::PORT, p);
            }
        }
        ipv4::ICMP => super::icmp::recevoir(i, interface, &h, &entete, diffusion, p),
        // TCP : jamais d'une trame pour plusieurs machines, que `tcp_v4_rcv`
        // jette avant même InSegs (`pkt_type != PACKET_HOST` : une trame de
        // diffusion ou de groupe, qu'IP livre pourtant, et qu'UDP reçoit).
        // Une destination de diffusion ou de groupe dans une trame pour nous
        // seuls passe (Linux trie la trame, pas l'adresse) : TCP la compte,
        // et sait qu'elle n'ouvre rien (`diffusion`). (La copie d'une
        // diffusion que nous envoyons, PACKET_LOOPBACK chez Linux, n'est
        // jamais de TCP : `connect` refuse une diffusion ou un groupe.)
        ipv4::TCP if trame_diffusee => {}
        ipv4::TCP => super::tcp::recevoir(&h, &entete, i, interface, diffusion, p),
        // Par l'interface qui l'a reçu (le `skb->dev` d'`igmp_rcv`).
        ipv4::IGMP => super::multidiffusion::recevoir(i.index, p.donnees(), de_nous, trame_diffusee),
        _ => injoignable(icmp::PROTOCOLE, p),
    }
}

/// Le morceau `f` du paquet que dit son en-tête `h` : gardé (None), ou le dernier : le
/// paquet recopié d'un seul tenant, derrière l'en-tête de son premier morceau
/// (`ip_defrag`, `ip_frag_reasm`), avec les options vérifiées de celui-ci et la taille
/// du plus grand morceau. Linux enchaîne les morceaux sans les recopier ; nos paquets
/// ont un tampon d'un seul tenant, que relisent UDP, ICMP et TCP.
fn recoller(i: &'static Interface, h: &ipv4::Ipv4, mut f: Fragment) -> Option<(ipv4::Ipv4, Paquet, ipv4::Options, u16)> {
    // L'heure du dernier morceau arrivé (`ip_frag_queue` : `qp->q.stamp`), que
    // prend le paquet recollé (`ip_frag_reasm`).
    let horodatage = f.paquet.contexte().horodatage;
    f.paquet.retirer_entete(h.longueur_entete)?;
    f.paquet.couper(h.longueur as usize - h.longueur_entete);
    let cle = Cle { source: h.source, destination: h.destination, identifiant: h.identifiant, protocole: h.protocole };
    let (issue, echeance) = {
        let mut t = REASSEMBLAGE.verrouiller();
        let Some(r) = t.as_mut() else {
            // Pas de table (plus de mémoire au démarrage) : le `ip_find` raté d'`ip_defrag`.
            MIB.ip(Ip::ReasmReqds);
            MIB.ip(Ip::ReasmFails);
            return None;
        };
        let issue = r.recevoir(cle, h.decalage as u32 * 8, h.fragments_suivants, h.tos, h.longueur_entete as u32, f, i.index, crate::temps::ns_monotone());
        (issue, r.echeance())
    };
    super::tache::armer(super::tache::OBJET_FRAGMENTS, echeance);
    let Issue::Complet { mut morceaux, longueur, entete, ecn, taille_max } = issue else { return None };
    // La fin d'`ip_frag_reasm` : un paquet recollé (ReasmOKs), ou pas de mémoire pour lui.
    let recolle = coller(&mut morceaux, longueur as usize, entete as usize, ecn);
    MIB.ip(if recolle.is_some() { Ip::ReasmOKs } else { Ip::ReasmFails });
    let (h, mut p) = recolle?;
    // Le paquet recollé est le premier morceau chez Linux (`ip_frag_reasm`
    // réutilise sa tête) : sa marque et sa priorité, l'heure du dernier.
    let premier = morceaux.first()?;
    p.poser_contexte(Contexte { horodatage, ..premier.paquet.contexte() });
    Some((h, p, premier.options, taille_max))
}

/// Les morceaux d'un paquet complet (`longueur` octets de données, derrière les `entete`
/// octets d'en-tête du premier), recopiés en un paquet neuf ; None : plus de mémoire.
fn coller(morceaux: &mut [Fragment], longueur: usize, entete: usize, ecn: u8) -> Option<(ipv4::Ipv4, Paquet)> {
    let mut neuf = Paquet::vide(entete + longueur)?;
    // La tête du premier morceau, son en-tête de liaison compris (`ip_frag_reasm`
    // la réutilise) : ce que lit le filtre d'une socket (paquet.rs).
    neuf.poser_liaison(morceaux.first()?.paquet.entete_de_liaison());
    let o = neuf.ajouter_fin(entete + longueur)?;
    let tete = morceaux.first_mut()?.paquet.ajouter_entete(entete)?;
    o[..entete].copy_from_slice(tete);
    let mut k = entete;
    for (n, m) in morceaux.iter().enumerate() {
        let d = if n == 0 { &m.paquet.donnees()[entete..] } else { m.paquet.donnees() };
        o[k..k + d.len()].copy_from_slice(d);
        k += d.len();
    }
    ipv4::finir_recollage(&mut o[..entete], (entete + longueur) as u16, ecn);
    let (h, _) = ipv4::lire(neuf.donnees()).ok()?;
    Some((h, neuf))
}

/// Les files de fragments échues (`ip_expire`) : si leur premier morceau était là,
/// l'émetteur l'apprend (« temps de réassemblage dépassé », RFC 792). Dans la tâche du réseau.
pub fn fragments_echus() {
    let maintenant = crate::temps::ns_monotone();
    loop {
        let Some(e) = REASSEMBLAGE.verrouiller().as_mut().and_then(|r| r.prendre_echue(maintenant)) else { break };
        if let Some(Fragment { paquet: mut p, options }) = e.premier
            && p.ajouter_entete(e.entete as usize).is_some()
        {
            let par_lo = interface::par_index(e.interface).is_some_and(|i| i.boucle());
            super::icmp::envoyer_erreur(icmp::TEMPS_DEPASSE, 1, 0, p.donnees(), &options, par_lo, true, false);
        }
    }
    let prochaine = REASSEMBLAGE.verrouiller().as_ref().and_then(|r| r.echeance());
    super::tache::armer(super::tache::OBJET_FRAGMENTS, prochaine);
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
    /// La taille au-delà de laquelle il faudra le découper (`ip_skb_dst_mtu`).
    pub mtu: u32,
    /// MSG_CONFIRM : la machine voisine est là (arp.rs).
    pub confirmer: bool,
    /// Les options IP (IP_OPTIONS ou IP_RETOPTS, l'écho de celles d'un paquet
    /// reçu pour lui répondre : l'`opt` de l'`ipcm_cookie`), et la vraie
    /// destination, que reçoit le dernier mot d'une route source (`cork->addr` :
    /// l'en-tête, lui, va à sa première étape).
    pub options: ipv4::OptionsSortantes,
    pub destination_finale: [u8; 4],
    /// IP_MULTICAST_LOOP (`sk_mc_loop` ; vrai pour un paquet du noyau) :
    /// vers un groupe de la carte, une copie revient à la machine.
    pub boucle_mc: bool,
}

/// Le chemin vers `destination` d'un envoi qui ne demande pas de source
/// (l'`ip_route_output_key` de Linux, `saddr` nul ; avec une source :
/// `router_depuis`), par l'interface `oif` si l'envoi en demande une (0 :
/// aucune), et la destination à mettre dans l'en-tête : 0.0.0.0 veut dire
/// « cette machine », et devient l'adresse que propose l'interface demandée,
/// ou 127.0.0.1 (inet::routes, `Table::router`, comme
/// `ip_route_output_key_hash_rcu`), parmi les routes de portée `portee` au
/// moins (« lien » : SO_DONTROUTE, voir inet::routes). Une interface qui
/// n'existe pas : ENODEV ; pas de route : ENETUNREACH ; la source de la
/// route, de la boucle, qui sortirait par une carte : EINVAL
/// (`__mkroute_output`, par où passe toute route de Linux, comme
/// `router_depuis`). Nos routes n'en donnent pas (celles du DHCP ont
/// l'adresse de la carte, lo ne propose la sienne qu'à « cette machine »),
/// mais la règle est ici, et pas chez chaque appelant : elle tiendra pour
/// une route qui en aurait une (`ip route ... src`).
pub fn router(destination: [u8; 4], oif: u32, portee: Portee) -> Result<(Chemin, [u8; 4]), i64> {
    const ENODEV: i64 = 19;
    const EINVAL: i64 = 22;
    if oif != 0 && interface::par_index(oif).is_none() {
        return Err(-ENODEV);
    }
    let route = TABLE.verrouiller().as_ref().and_then(|t| t.router(destination, None, oif, portee)).ok_or(-ENETUNREACH)?;
    if ipv4::boucle(route.0.source()) && !par_lo(&route.0) {
        return Err(-EINVAL);
    }
    Ok(route)
}

/// Le même, pour un envoi qui part d'une source demandée, `source` (celle de
/// `bind`, d'IP_PKTINFO ou d'IP_MULTICAST_IF pour UDP et ping, celle d'une
/// connexion TCP et de chacun de ses segments), dans l'ordre
/// d'`ip_route_output_key_hash_rcu` : une source de groupe ou la diffusion
/// limitée n'a jamais de route (EINVAL), même pour `toute_source` ; sans
/// interface demandée (`oif` 0), vers un groupe ou la diffusion limitée,
/// l'envoi part par l'interface de la source, qui doit être à nous, même
/// pour `toute_source` (ENETUNREACH sinon) : le « hack de vic/vat » de Linux
/// (« This hack is not just for fun, it allows vic, vat and friends to
/// work » : des outils de visioconférence, liés à 127.0.0.1, qui diffusaient
/// par lo avec un TTL nul) ; vers le reste, une source qui n'est pas à nous
/// non plus (ENETUNREACH), sauf `toute_source` (FLOWI_FLAG_ANYSRC :
/// IP_TRANSPARENT, qui laisse partir de la diffusion d'un réseau). Tout cela
/// sous le même verrou que la route (`__ip_dev_find`) : une adresse qui
/// change entre les deux (le DHCP) ne laisse pas partir d'une source qui
/// n'est plus à nous. Puis comme `router` : l'interface demandée qui n'existe
/// pas : ENODEV, pas de route : ENETUNREACH ; et une source de la boucle
/// (127.0.0.0/8) qui sortirait par une carte : EINVAL (`__mkroute_output` :
/// l'autre bout la jetterait comme un martien ; une connexion de 127.0.0.1
/// liée à la carte). Rend aussi l'interface demandée, celle de la source
/// après le hack (le `flowi4_oif` que Linux y change), que garde la route
/// d'une socket UDP connectée.
///
/// Un seul chemin pour UDP, ping et TCP, comme chez Linux, où
/// `ip_route_connect` de TCP passe par la même fonction : ainsi TCP lié à
/// 127.0.0.1 a aussi le hack, et `connect` vers un groupe y trouve une
/// route par lo, qu'il refuse ensuite comme groupe (ENETUNREACH), pas la
/// route par défaut et une source de la boucle hors de lo (EINVAL).
pub fn router_depuis(destination: [u8; 4], source: [u8; 4], oif: u32, toute_source: bool, portee: Portee)
                     -> Result<(Chemin, [u8; 4], u32), i64> {
    const ENODEV: i64 = 19;
    const EINVAL: i64 = 22;
    if ipv4::multidiffusion(source) || source == ipv4::DIFFUSION {
        return Err(-EINVAL);
    }
    let (route, oif) = {
        let g = TABLE.verrouiller();
        let t = g.as_ref().ok_or(-ENETUNREACH)?;
        let oif = if oif == 0 && (ipv4::multidiffusion(destination) || destination == ipv4::DIFFUSION) {
            t.interface_locale(source).ok_or(-ENETUNREACH)?
        } else if !toute_source && !t.est_a_nous(source) {
            return Err(-ENETUNREACH);
        } else {
            oif
        };
        // INTERFACES est une feuille (rien ne se prend sous elle) : la
        // prendre sous TABLE ne peut pas croiser un autre ordre.
        if oif != 0 && interface::par_index(oif).is_none() {
            return Err(-ENODEV);
        }
        (t.router(destination, Some(source), oif, portee).ok_or(-ENETUNREACH)?, oif)
    };
    if ipv4::boucle(source) && !par_lo(&route.0) {
        return Err(-EINVAL);
    }
    Ok((route.0, route.1, oif))
}

/// Le chemin `c` passe-t-il par `lo` ?
pub fn par_lo(c: &Chemin) -> bool {
    interface_de(c).is_some_and(|i| i.boucle())
}

/// L'index de l'interface par où part ce qui suit le chemin `c` (le
/// `dst.dev` de sa route : lo pour une de nos adresses).
pub fn sortie(c: &Chemin) -> Option<u32> {
    interface_de(c).map(|i| i.index)
}

/// `a` est-elle une de nos adresses (le réseau de lo compris, sa diffusion
/// exceptée) ?
pub fn est_a_nous(a: [u8; 4]) -> bool {
    avec_table(|t| t.est_a_nous(a)).unwrap_or(false)
}

/// L'interface par où part ce qui suit le chemin `c`.
fn interface_de(c: &Chemin) -> Option<&'static Interface> {
    match *c {
        Chemin::Locale { .. } => super::boucle::interface(),
        Chemin::Diffusion { interface, .. } | Chemin::Unicast { interface, .. } | Chemin::Multidiffusion { interface, .. } => {
            interface::par_index(interface)
        }
    }
}

/// La MTU du chemin `c` : celle de son interface, au plus 65 535 (la plus
/// grande longueur que dit un en-tête IPv4 : `ipv4_mtu` borne aussi celle
/// de lo, 65 536, à IP_MAX_MTU). Celle qu'apprend un ICMP « fragmentation
/// nécessaire » est dans inet::pmtu.
pub fn mtu(c: &Chemin) -> u32 {
    interface_de(c).map_or(super::boucle::MTU, |i| i.mtu()).min(0xFFFF)
}

/// La MTU du chemin `c` vers `destination`, ce que l'ICMP a appris compris (`dst_mtu`).
pub fn mtu_vers(c: &Chemin, destination: [u8; 4]) -> u32 {
    EXCEPTIONS.verrouiller().mtu(destination, mtu(c), crate::temps::ns_monotone())
}

/// Cette MTU est-elle verrouillée (sous le plancher : `ip_mtu_locked`) ?
pub fn mtu_verrouillee(destination: [u8; 4]) -> bool {
    EXCEPTIONS.verrouiller().verrouillee(destination, crate::temps::ns_monotone())
}

/// Une MTU apprise mène-t-elle vers `destination` (une route qui expire) ?
pub fn mtu_apprise(destination: [u8; 4]) -> bool {
    EXCEPTIONS.verrouiller().retenue(destination, crate::temps::ns_monotone())
}

/// ICMP dit `info` vers `destination` (`__ip_rt_update_pmtu`).
pub fn apprendre_mtu(destination: [u8; 4], info: u32) {
    if let Ok((c, d)) = router(destination, 0, Portee::Univers) {
        EXCEPTIONS.verrouiller().apprendre(d, info, mtu(&c), crate::temps::ns_monotone());
    }
}

/// Oublie ce qu'on sait de `destination` (l'auto-test du démarrage).
pub fn oublier_mtu(destination: [u8; 4]) {
    EXCEPTIONS.verrouiller().oublier(destination);
}

/// `ip_dont_fragment` : DF pour un paquet de cette socket, d'après IP_MTU_DISCOVER :
/// IP_PMTUDISC_DO, ou WANT tant que la MTU n'est pas verrouillée : sous le plancher,
/// qu'un vrai petit lien le découpe.
pub fn ne_pas_fragmenter(pmtudisc: u8, destination: [u8; 4]) -> bool {
    pmtudisc == 2 || (pmtudisc == 1 && !mtu_verrouillee(destination))
}

/// La taille où découper un paquet de cette socket (`ip_skb_dst_mtu`) : la MTU du chemin,
/// sauf IP_PMTUDISC_PROBE, INTERFACE et OMIT (`ip_sk_use_pmtu`), qui n'en veulent pas.
pub fn mtu_d_envoi(pmtudisc: u8, c: &Chemin, destination: [u8; 4]) -> u32 {
    if pmtudisc < 3 { mtu_vers(c, destination) } else { mtu(c) }
}

/// Un identifiant pour un paquet qui n'est pas d'une socket connectée :
/// un envoi d'UDP ou de ping (sauf IP_PMTUDISC_DO et PROBE, qui ont 0 :
/// voir `datagramme::preparer`), et chaque réponse et erreur d'ICMP ;
/// celui de `__ip_select_ident` : SipHash de (destination, source,
/// protocole), sous une clé secrète, choisit l'un des 2048 compteurs, qui
/// avance d'un pas tiré entre 0 et le nombre de tics depuis son dernier
/// usage (`ip_idents_reserve`). Pourquoi : avec un seul compteur pour
/// tous, un tiers qui reçoit deux paquets de nous saurait, par la
/// différence de leurs identifiants, combien nous en avons envoyé aux
/// autres entre-temps (une machine « idle » sert ainsi de relais à un
/// balayage de ports caché, l'« idle scan » de nmap) ; avec un compteur
/// par destination qu'on ne peut pas deviner, et des pas au hasard, il
/// n'apprend plus rien. Linux compte en jiffies ; nous, en tics (1 ms).
pub fn identifiant(destination: [u8; 4], source: [u8; 4], protocole: u8) -> u16 {
    let cle = [CLE_IDENTS[0].load(Ordering::Relaxed), CLE_IDENTS[1].load(Ordering::Relaxed)];
    let hachage = crypto::siphash::siphash_3u32(u32::from_ne_bytes(destination), u32::from_ne_bytes(source), protocole as u32, &cle);
    let case = hachage as usize & (IDENTS - 1);
    let maintenant = crate::horloge::tics() as u32;
    let ancien = IDENTS_TICS[case].load(Ordering::Relaxed);
    let mut pas = 0;
    if ancien != maintenant
        && IDENTS_TICS[case].compare_exchange(ancien, maintenant, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    {
        pas = crate::aleatoire::u32_sous(maintenant.wrapping_sub(ancien));
    }
    IDENTS_COMPTEURS[case].fetch_add(1 + pas, Ordering::Relaxed).wrapping_add(pas) as u16
}

/// Notre adresse `a` n'est-elle ni à nous, ni une diffusion, ni une
/// multidiffusion (`inet_addr_type` == RTN_UNICAST) ? Pour les options.
pub fn unicast(a: [u8; 4]) -> bool {
    avec_table(|t| t.est_unicast(a)).unwrap_or(false)
}

/// Les options du paquet `p` que nous avions envoyé, revues comme à une
/// réception pour l'erreur ICMP qui le cite, quand la voisine ne répond pas
/// (`ipv4_send_dest_unreach` : Linux les recompile sur place, le paquet
/// compris : la route notée y reçoit encore notre adresse, l'horodatage
/// l'heure). Notre adresse pour lui (`fib_compute_spec_dst` d'une route de
/// sortie) : sa source. None : un en-tête illisible, ou une option fausse
/// (pas d'erreur ICMP).
pub fn options_d_un_envoi(p: &mut Paquet) -> Option<ipv4::Options> {
    let h = ipv4::lire_cite(p.donnees()).ok()?;
    let entete = p.donnees_mut().get_mut(..h.longueur_entete)?;
    let ici = ipv4::Ici { adresse: h.source, heure: super::icmp::horodatage(), unicast: &unicast };
    ipv4::compiler_options(entete, &ici).ok()
}

/// Émet le paquet `p` (sa charge en place, l'en-tête du protocole
/// compris) selon `e`, par le chemin `c` : l'en-tête IPv4 devant, avec ses
/// options, puis l'interface du chemin, dans le contexte de qui envoie (le
/// `dev_queue_xmit` de Linux). Rien ne revient : un paquet perdu en route
/// (file pleine, voisin muet) l'est sans le dire, comme sur un câble.
/// Les options sont complétées une fois (`ip_options_build`, quand
/// `__ip_make_skb` fait le paquet) : la copie d'une diffusion et chaque
/// fragment reprennent les mêmes, la même heure comprise.
///
/// Vers un groupe que la carte a, et qu'elle laisse entrer de cette source
/// (`locale`, RTCF_LOCAL : sa route sort par `ip_mc_output`), une copie
/// revient aux sockets de la machine, sauf IP_MULTICAST_LOOP 0 ; puis un TTL
/// 0 ne sort pas (« Multicasts with ttl 0 must not go beyond the host » :
/// ni OutTransmits, ni trame). Vers un autre groupe, la route sort par
/// `ip_output`, comme l'unicast : ni copie, ni regard sur le TTL (mesuré :
/// un TTL 0 sort).
pub fn emettre(c: Chemin, e: &Envoi, p: Paquet) {
    MIB.ip(Ip::OutRequests);
    let mut entete = [0u8; ipv4::ENTETE + ipv4::OPTIONS_MAX];
    let n = ipv4::ENTETE + e.options.longueur as usize;
    let heure = if e.options.places.horodatage_heure { super::icmp::horodatage() } else { 0 };
    ipv4::construire_options(&mut entete[..n], &e.options, e.destination_finale, e.source, heure);
    let options = &entete[ipv4::ENTETE..n];
    let carte = interface_de(&c).filter(|i| !i.boucle());
    match (c, carte) {
        (Chemin::Diffusion { .. }, Some(i)) => rendre_une_copie(i, e, options, &p),
        (Chemin::Multidiffusion { locale: true, .. }, Some(i)) => {
            if e.boucle_mc {
                rendre_une_copie(i, e, options, &p);
            }
            if e.ttl == 0 {
                return;
            }
        }
        _ => {}
    }
    if p.longueur() + n > e.mtu as usize {
        return fragmenter(c, e, options, p);
    }
    envoyer(c, e, options, p, 0, false);
}

/// `ip_fragment`, `ip_do_fragment` : un paquet trop grand. Avec DF, il ne passera pas :
/// l'erreur ICMP, à nous-mêmes (« fragmentation nécessaire », avec la MTU ; l'écho de ses
/// options, celles de l'envoi : son `IPCB(skb)->opt`) ; sinon, en morceaux, chacun un
/// multiple de 8 octets sauf le dernier (`ipv4::taille_du_fragment`), sa place et MF dans
/// son en-tête, qui a la taille de celui du paquet (`options` : complétées) ; après le
/// premier, sans les options qui ne se recopient pas (`ip_options_fragment`). Un morceau
/// qu'on ne peut pas faire : le paquet est perdu.
fn fragmenter(c: Chemin, e: &Envoi, options: &[u8], mut p: Paquet) {
    let n = ipv4::ENTETE + options.len();
    if e.ne_pas_fragmenter {
        MIB.ip(Ip::FragFails);
        let total = (p.longueur() + n) as u16;
        let Some(entete) = p.ajouter_entete(n) else { return };
        entete[ipv4::ENTETE..].copy_from_slice(options);
        ipv4::ecrire(entete, &en_tete(e, total, 0, false));
        return super::icmp::envoyer_erreur(icmp::INJOIGNABLE, icmp::FRAGMENTATION, e.mtu, p.donnees(), &e.options.places,
                                           par_lo(&c), false, false);
    }
    let mut suite = [0u8; ipv4::OPTIONS_MAX];
    let suite = &mut suite[..options.len()];
    suite.copy_from_slice(options);
    ipv4::options_de_fragment(suite);
    let mut debut = 0;
    let mut demande = p.prendre_demande();
    let total = p.donnees().len();
    while debut < total {
        let reste = total - debut;
        let longueur = ipv4::taille_du_fragment(total, debut, e.mtu as usize, n);
        let Some(mut q) = Paquet::vide(longueur) else { return MIB.ip(Ip::FragFails) };
        // La marque et la priorité du paquet (`ip_copy_metadata`).
        q.poser_contexte(p.contexte());
        // Chaque morceau compte dans le SO_SNDBUF de la socket, comme le
        // paquet entier (`__ip_append_data` les lui attache un à un) ; seul
        // le premier est horodaté (« only the initial fragment is time
        // stamped »).
        if let Some(r) = p.retenue() {
            q.attacher(r, 0);
        }
        if let Some(d) = demande.take() {
            q.poser_demande(d);
        }
        // L'avis de MSG_ZEROCOPY, au dernier : Linux en donne une référence à
        // chaque morceau, il vient quand le dernier est fini (zerocopie.rs).
        // Jusque-là, `p` le garde (fini avec lui s'il est jeté avant).
        if longueur == reste
            && let Some(a) = p.prendre_avis()
        {
            q.poser_avis(a);
        }
        let Some(o) = q.ajouter_fin(longueur) else { return MIB.ip(Ip::FragFails) };
        o.copy_from_slice(&p.donnees()[debut..debut + longueur]);
        envoyer(c, e, if debut == 0 { options } else { suite }, q, (debut / 8) as u16, longueur < reste);
        MIB.ip(Ip::FragCreates);
        debut += longueur;
    }
    MIB.ip(Ip::FragOKs);
}

/// La copie du paquet diffusé `p` (sa charge), pour les sockets de la machine
/// (`ip_mc_output`) : le paquet entier, son en-tête devant (même plus grand que
/// la MTU : Linux copie avant `ip_fragment`). Sans mémoire, pas de copie (le
/// `skb_clone` qui échoue).
fn rendre_une_copie(i: &'static Interface, e: &Envoi, options: &[u8], p: &Paquet) {
    let n = ipv4::ENTETE + options.len();
    let total = p.longueur() + n;
    let Some(mut q) = Paquet::vide(total) else { return };
    q.poser_contexte(p.contexte());
    let Some(o) = q.ajouter_fin(total) else { return };
    let (entete, charge) = o.split_at_mut(n);
    entete[ipv4::ENTETE..].copy_from_slice(options);
    ipv4::ecrire(entete, &en_tete(e, total as u16, 0, false));
    charge.copy_from_slice(p.donnees());
    super::boucle::rendre_la_diffusion(i, q);
}

/// L'en-tête d'un paquet ou d'un morceau de l'envoi `e`.
fn en_tete(e: &Envoi, longueur: u16, decalage: u16, suite: bool) -> ipv4::Ipv4 {
    ipv4::Ipv4 {
        tos: e.tos,
        longueur,
        identifiant: e.identifiant,
        ne_pas_fragmenter: e.ne_pas_fragmenter,
        fragments_suivants: suite,
        decalage,
        ttl: e.ttl,
        protocole: e.protocole,
        source: e.source,
        destination: e.destination,
        longueur_entete: ipv4::ENTETE + e.options.longueur as usize,
    }
}

/// L'en-tête IPv4 devant `p`, avec les `options` (complétées), puis
/// l'interface du chemin.
fn envoyer(c: Chemin, e: &Envoi, options: &[u8], mut p: Paquet, decalage: u16, suite: bool) {
    let n = ipv4::ENTETE + options.len();
    let longueur = (p.longueur() + n) as u16;
    let Some(entete) = p.ajouter_entete(n) else { return };
    entete[ipv4::ENTETE..].copy_from_slice(options);
    ipv4::ecrire(entete, &en_tete(e, longueur, decalage, suite));
    let Some(i) = interface_de(&c) else { return };
    MIB.ip(Ip::OutTransmits);
    // Par lo (une de nos adresses, ou un envoi forcé par lo) : pas de voisin
    // (IFF_NOARP), une adresse matérielle nulle ; et le paquet garde sa route
    // (voir l'en-tête) : il sera vu arrivé par l'interface de l'entrée locale
    // trouvée, ou par lo (le `rt_iif` d'un envoi forcé par lo est lo, celui
    // d'un envoi à 0.0.0.0 sans interface demandée est nul, et `inet_iif`
    // prend alors l'interface qui reçoit : lo). Vers un groupe que lo n'a
    // pas, la route n'est pas locale : le paquet passe par lo, puis est jeté
    // (mesuré : personne ne le reçoit).
    if i.boucle() {
        let interface = match c {
            Chemin::Locale { interface, .. } if interface != 0 => interface,
            _ => i.index,
        };
        let diffusion = matches!(c, Chemin::Diffusion { .. } | Chemin::Multidiffusion { .. });
        let livre = !matches!(c, Chemin::Multidiffusion { locale: false, .. });
        p.marquer(Sortie { interface, diffusion, livre });
        return super::ethernet::emettre(i, [0; 6], ethernet::IPV4, p);
    }
    match c {
        Chemin::Diffusion { .. } => super::ethernet::emettre(i, ethernet::DIFFUSION, ethernet::IPV4, p),
        // Sans voisin : l'adresse MAC du groupe (`arp_mc_map`, NUD_NOARP).
        Chemin::Multidiffusion { .. } => super::ethernet::emettre(i, ethernet::de_groupe(e.destination), ethernet::IPV4, p),
        Chemin::Unicast { prochain, .. } => super::arp::envoyer(i, prochain, p, e.confirmer),
        // Toujours par lo (`interface_de`), plus haut.
        Chemin::Locale { .. } => {}
    }
}

/// Émet par `i` le paquet `p` (sa charge en place) en diffusion limitée
/// (255.255.255.255), de la source `source` (0.0.0.0 avant d'avoir une
/// adresse), pour le protocole `protocole` : le client DHCP. TTL 64 (le
/// `ip_default_ttl`), DF (comme `ipconfig.c`), identifiant 0 (DF :
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
        ttl: TTL_DEFAUT,
        protocole,
        source,
        destination: ipv4::DIFFUSION,
        longueur_entete: ipv4::ENTETE,
    });
    super::ethernet::emettre(i, ethernet::DIFFUSION, ethernet::IPV4, p);
}
