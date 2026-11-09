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
//! routeur, `ip_forward` = 0). Un fragment va au réassemblage
//! (inet::fragments). Les options : un paquet à route source (LSRR, SSRR)
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
//! une diffusion, le voisin (ARP) pour le reste. Un paquet plus grand que la MTU
//! part en fragments, sauf DF (`ip_do_fragment`). Une diffusion envoyée n'est pas rendue aussi aux sockets de la
//! machine (Linux en fait toujours une copie par la boucle, `ip_mc_output` ;
//! IP_MULTICAST_LOOP ne règle que la multidiffusion) : un écart écrit.

use super::interface::{self, Interface};
use super::paquet::Paquet;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use formats::reseau::{dhcp as format_dhcp, ethernet, icmp, ipv4, udp};
use inet::fragments::{Cle, Issue, Morceau, Reassemblage};
use inet::pmtu::Exceptions;
use inet::routes::{Chemin, Table};

const ENETUNREACH: i64 = 101;

/// Les adresses et les routes ; faites au démarrage.
static TABLE: Verrou<Option<Table>> = Verrou::new(None);

/// La MTU du chemin de chaque destination apprise par ICMP (inet::pmtu).
static EXCEPTIONS: Verrou<Exceptions> = Verrou::new(Exceptions::new());

/// Les paquets en morceaux qui nous arrivent (inet::fragments), et ceux qu'on a pu
/// recoller ou non : faits au démarrage.
static REASSEMBLAGE: Verrou<Option<Reassemblage<Paquet>>> = Verrou::new(None);

impl Morceau for Paquet {
    fn octets(&self) -> &[u8] {
        self.donnees()
    }
    fn couper(&mut self, n: usize) {
        Paquet::couper(self, n);
    }
    fn taille_vraie(&self) -> usize {
        Paquet::taille_vraie(self)
    }
}

/// Les paquets jetés à l'entrée (les compteurs d'`/proc/net/snmp` de Linux,
/// pas encore montrés) : en-tête faux, martiens, pas pour nous.
static ENTETES_FAUX: AtomicU64 = AtomicU64::new(0);
static MARTIENS: AtomicU64 = AtomicU64::new(0);
static PAS_POUR_NOUS: AtomicU64 = AtomicU64::new(0);
static OPTIONS: AtomicU64 = AtomicU64::new(0);

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
    *REASSEMBLAGE.verrouiller() = Reassemblage::new();
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
    if !options_acceptees(&p.donnees()[..h.longueur_entete]) {
        return compter(&OPTIONS);
    }
    // Un morceau : ce qui suit ne voit que des paquets entiers (`ip_local_deliver`).
    let (h, p) = if h.est_un_fragment() {
        match recoller(i, &h, p) {
            Some(x) => x,
            None => return,
        }
    } else {
        (h, p)
    };
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
        // TCP : jamais pour une diffusion (`tcp_v4_rcv` jette tout ce qui
        // n'est pas pour une seule machine).
        ipv4::TCP if !diffusion => super::tcp::recevoir(h.source, h.destination, i.boucle(), p),
        ipv4::TCP => {}
        _ => injoignable(icmp::PROTOCOLE, p),
    }
}

/// Le morceau `p` du paquet que dit son en-tête `h` : gardé (None), ou le dernier : le
/// paquet recopié d'un seul tenant, derrière l'en-tête de son premier morceau
/// (`ip_defrag`, `ip_frag_reasm`). Linux enchaîne les morceaux sans les recopier ; nos
/// paquets ont un tampon d'un seul tenant, que relisent UDP, ICMP et TCP.
fn recoller(i: &'static Interface, h: &ipv4::Ipv4, mut p: Paquet) -> Option<(ipv4::Ipv4, Paquet)> {
    p.retirer_entete(h.longueur_entete)?;
    p.couper(h.longueur as usize - h.longueur_entete);
    let cle = Cle { source: h.source, destination: h.destination, identifiant: h.identifiant, protocole: h.protocole };
    let (issue, echeance) = {
        let mut t = REASSEMBLAGE.verrouiller();
        let r = t.as_mut()?;
        let issue = r.recevoir(cle, h.decalage as u32 * 8, h.fragments_suivants, h.tos, h.longueur_entete as u32, p, i.index, crate::temps::ns_monotone());
        (issue, r.echeance())
    };
    super::tache::armer(super::tache::OBJET_FRAGMENTS, echeance);
    let Issue::Complet { mut morceaux, longueur, entete, ecn } = issue else { return None };
    let (longueur, entete) = (longueur as usize, entete as usize);
    let mut neuf = Paquet::vide(entete + longueur)?;
    let o = neuf.ajouter_fin(entete + longueur)?;
    let tete = morceaux.first_mut()?.ajouter_entete(entete)?;
    o[..entete].copy_from_slice(tete);
    let mut k = entete;
    for (n, m) in morceaux.iter().enumerate() {
        let d = if n == 0 { &m.donnees()[entete..] } else { m.donnees() };
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
        if let Some(mut p) = e.premier
            && p.ajouter_entete(e.entete as usize).is_some()
        {
            let par_lo = interface::par_index(e.interface).is_some_and(|i| i.boucle());
            super::icmp::envoyer_erreur(icmp::TEMPS_DEPASSE, 1, 0, p.donnees(), par_lo, true, false);
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

/// ICMP dit `info` vers `destination` (`__ip_rt_update_pmtu`).
pub fn apprendre_mtu(destination: [u8; 4], info: u32) {
    if let Ok((c, d)) = router(destination, None) {
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

/// Émet le paquet `p` (sa charge en place, l'en-tête du protocole
/// compris) selon `e`, par le chemin `c` : l'en-tête IPv4 devant, puis
/// l'interface du chemin, dans le contexte de qui envoie (le
/// `dev_queue_xmit` de Linux). Rien ne revient : un paquet perdu en route
/// (file pleine, voisin muet) l'est sans le dire, comme sur un câble.
pub fn emettre(c: Chemin, e: &Envoi, p: Paquet) {
    if p.longueur() + ipv4::ENTETE > e.mtu as usize {
        return fragmenter(c, e, p);
    }
    envoyer(c, e, p, 0, false);
}

/// `ip_fragment`, `ip_do_fragment` : un paquet trop grand. Avec DF, il ne passera pas :
/// l'erreur ICMP, à nous-mêmes (« fragmentation nécessaire », avec la MTU) ; sinon, en
/// morceaux, chacun un multiple de 8 octets sauf le dernier, sa place et MF dans son
/// en-tête. Un morceau qu'on ne peut pas faire : le paquet est perdu.
fn fragmenter(c: Chemin, e: &Envoi, mut p: Paquet) {
    if e.ne_pas_fragmenter {
        let total = (p.longueur() + ipv4::ENTETE) as u16;
        let Some(entete) = p.ajouter_entete(ipv4::ENTETE) else { return };
        let entete: &mut [u8; ipv4::ENTETE] = entete.try_into().expect("20 octets");
        ipv4::ecrire(entete, &en_tete(e, total, 0, false));
        return super::icmp::envoyer_erreur(icmp::INJOIGNABLE, icmp::FRAGMENTATION, e.mtu, p.donnees(), par_lo(&c), false, false);
    }
    let place = (e.mtu as usize - ipv4::ENTETE) & !7;
    let mut debut = 0;
    let donnees = p.donnees();
    while debut < donnees.len() {
        let reste = donnees.len() - debut;
        let n = if reste > place { place } else { reste };
        let Some(mut q) = Paquet::vide(n) else { return };
        let Some(o) = q.ajouter_fin(n) else { return };
        o.copy_from_slice(&donnees[debut..debut + n]);
        envoyer(c, e, q, (debut / 8) as u16, n < reste);
        debut += n;
    }
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
        longueur_entete: ipv4::ENTETE,
    }
}

/// L'en-tête IPv4 devant `p`, puis l'interface du chemin.
fn envoyer(c: Chemin, e: &Envoi, mut p: Paquet, decalage: u16, suite: bool) {
    let longueur = (p.longueur() + ipv4::ENTETE) as u16;
    let Some(entete) = p.ajouter_entete(ipv4::ENTETE) else { return };
    let entete: &mut [u8; ipv4::ENTETE] = entete.try_into().expect("20 octets");
    ipv4::ecrire(entete, &en_tete(e, longueur, decalage, suite));
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
