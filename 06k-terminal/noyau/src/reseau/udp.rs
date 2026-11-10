//! UDP (RFC 768 ; net/ipv4/udp.c) : des datagrammes, sans connexion ni
//! garantie, chacun avec ses ports.
//!
//! Les règles des ports (qui peut prendre lequel, à qui va un datagramme)
//! sont dans inet::ports, testées sur l'hôte ; la table vit ici, sous un
//! `Verrou`, faite au démarrage. Chaque appel suit l'ordre de vérification
//! de Linux (mesuré, ou lu dans udp.c) ; ce qui est commun aux sockets de
//! datagrammes (bind, connect, le port éphémère) est dans datagramme.rs, et
//! à toutes les sockets (recevoir, attendre, l'erreur en attente, l'arrêt)
//! dans socket.rs.
//!
//! Ce qui manque, écrit : MSG_MORE et UDP_CORK ; la multidiffusion. (SO_SNDBUF fait attendre
//! depuis les soldes d'avant 6k : datagramme::attendre_place.)

use super::datagramme::{self, Controle};
use super::ipv4;
use super::paquet::Paquet;
use super::icmp::ErreurRecue;
use super::socket::{self, Admission, AF_INET, AF_UNSPEC, Datagramme, ErreurEnFile, Inet, Socket};
use crate::aleatoire;
use crate::partage::Arc;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicU64, Ordering};
use formats::reseau::{ipv4 as format_ipv4, udp};
use inet::ports::{Lien, Refus, Table};

const EINVAL: i64 = 22;
const EDESTADDRREQ: i64 = 89;
const EMSGSIZE: i64 = 90;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;
const EAFNOSUPPORT: i64 = 97;
const ENOBUFS: i64 = 105;

/// La table des ports ; faite au démarrage.
static PORTS: Verrou<Option<Table<Arc<Socket>>>> = Verrou::new(None);

/// Les datagrammes jetés à l'arrivée (les `UdpInErrors`, `RcvbufErrors`,
/// `NoPorts` de Linux, pas encore montrés).
static FAUX: AtomicU64 = AtomicU64::new(0);
static FILE_PLEINE: AtomicU64 = AtomicU64::new(0);
static SANS_SOCKET: AtomicU64 = AtomicU64::new(0);

pub fn initialiser() {
    *PORTS.verrouiller() = Table::new();
}

fn hasard() -> u32 {
    aleatoire::u32()
}

/// Retire la socket `s` de la table des ports (son dernier close).
pub fn liberer(s: &Socket) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.retirer(s.numero);
    }
}

/// Le lien de `inet` pour la table des ports.
fn lien(s: &Socket, inet: &Inet, port: u16) -> Lien {
    Lien {
        adresse: inet.adresse, port, distante: inet.distante, port_distant: inet.port_distant,
        reuseaddr: inet.options.reuseaddr, reuseport: inet.options.reuseport, uid: s.uid,
    }
}

/// Inscrit `s` dans la table, au port `port` (0 : éphémère). Sous le `Mutex`.
pub fn inscrire(s: &Arc<Socket>, inet: &mut Inet, port: u16) -> Result<(), i64> {
    let mut g = PORTS.verrouiller();
    let Some(t) = g.as_mut() else { return Err(-ENOBUFS) };
    let l = lien(s, inet, port);
    match t.lier(s.numero, l, s.clone(), hasard()) {
        Ok(p) => {
            inet.port = p;
            inet.lie = true;
            Ok(())
        }
        Err(Refus::Pris) => Err(-EADDRINUSE),
        Err(Refus::Plein) => Err(-ENOBUFS),
    }
}

/// Récrit le lien de `s` dans la table (connect, ou sa fin).
pub fn changer(s: &Socket, inet: &Inet) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.changer(s.numero, inet.distante, inet.port_distant, inet.adresse);
    }
}

/// SO_REUSEADDR ou SO_REUSEPORT a changé : la table le saura au prochain
/// conflit. Sous le `Mutex`.
pub fn reutilisation_changee(s: &Socket, inet: &Inet) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.reutiliser(s.numero, inet.options.reuseaddr, inet.options.reuseport);
    }
}

/// Envoie `longueur` octets, que `remplir` copie du programme dans le
/// paquet, à la destination `nom` (la `sockaddr` de sendto ou de sendmsg ;
/// None : celle de la connexion), dans l'ordre d'`inet_sendmsg` et
/// d'`udp_sendmsg` :
///   - un port éphémère s'il le faut, avant tout (EAGAIN) ;
///   - plus de 65 535 octets : EMSGSIZE ; MSG_OOB : EOPNOTSUPP ; MSG_MORE
///     (le « bouchon » d'UDP, qui réunit plusieurs envois en un
///     datagramme) : EOPNOTSUPP, un écart : plutôt que d'envoyer en deux
///     datagrammes ce qui n'en fait qu'un ;
///   - la destination : moins de 16 octets, ou le port 0 : EINVAL ; une
///     autre famille qu'AF_INET ou AF_UNSPEC : EAFNOSUPPORT ; aucune, et
///     pas connectée : EDESTADDRREQ ;
///   - les messages de contrôle (`controle`, lus par l'appel : leur erreur
///     sort ici, EINVAL) ;
///   - ce que fait toute socket de datagrammes (`datagramme::preparer`) :
///     la route, l'adresse source, la MTU, l'erreur en attente, l'arrêt ;
///   - la place dans SO_SNDBUF (`datagramme::attendre_place` : EAGAIN,
///     ou l'attente) ; des morceaux au-delà de son double : ENOBUFS ;
///   - le paquet (ENOBUFS), la copie (EFAULT), et il part.
///
/// Rend la longueur envoyée.
pub fn envoyer(s: &Arc<Socket>, nom: Option<&[u8]>, longueur: usize, drapeaux: u64, controle: Result<Controle, i64>,
               mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_MORE: u64 = 0x8000;
    let mut inet = s.appels.verrouiller();
    datagramme::lier_au_besoin(s, &mut inet)?;
    if longueur > 0xFFFF {
        return Err(-EMSGSIZE);
    }
    if drapeaux & (MSG_OOB | MSG_MORE) != 0 {
        return Err(-EOPNOTSUPP);
    }
    let (adresse, port) = match nom {
        Some(o) => {
            let Some(a) = socket::lire_adresse(o) else { return Err(-EINVAL) };
            if a.famille != AF_INET && a.famille != AF_UNSPEC {
                return Err(-EAFNOSUPPORT);
            }
            if a.port == 0 {
                return Err(-EINVAL);
            }
            (a.adresse, a.port)
        }
        None if inet.connecte => (inet.distante, inet.port_distant),
        None => return Err(-EDESTADDRREQ),
    };
    let c = controle?;
    let (chemin, envoi) = datagramme::preparer(s, &mut inet, adresse, udp::ENTETE + longueur, format_ipv4::UDP, drapeaux, &c)?;
    let adresse = envoi.destination;
    let u = udp::Udp { source: inet.port, destination: port };
    let delai = inet.options.sndtimeo;
    drop(inet);
    datagramme::attendre_place(s, drapeaux & MSG_DONTWAIT != 0, delai)?;
    datagramme::morceaux_permis(s, udp::ENTETE + longueur, &envoi)?;
    let Some(mut p) = Paquet::vide(udp::ENTETE + longueur) else { return Err(-ENOBUFS) };
    datagramme::attacher(s, &mut p);
    let Some(segment) = p.ajouter_fin(udp::ENTETE + longueur) else { return Err(-ENOBUFS) };
    remplir(0, &mut segment[udp::ENTETE..])?;
    udp::ecrire(segment, &u, envoi.source, adresse);
    ipv4::emettre(chemin, &envoi, p);
    Ok(longueur)
}

/// Un datagramme UDP (`p` : le segment, en-tête compris, sans l'en-tête
/// d'IPv4) reçu par l'interface `interface`, pour `destination`, de
/// `source`, dans la tâche du réseau : `__udp4_lib_rcv`, la somme
/// vérifiée (fausse : jeté, sans rien dire), puis la socket qui le reçoit ;
/// une diffusion à chacune de celles du port. Sans socket, le segment est
/// rendu, son en-tête remis, pour l'erreur ICMP « port injoignable » (que
/// l'appelant envoie : il a l'en-tête d'IPv4).
pub fn recevoir(interface: u32, source: [u8; 4], destination: [u8; 4], diffusion: bool, mut p: Paquet) -> Result<(), Paquet> {
    let Ok((u, charge)) = udp::lire(p.donnees(), source, destination) else {
        FAUX.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    };
    let longueur = charge.len();
    let _ = p.retirer_entete(udp::ENTETE);
    p.couper(longueur);
    if diffusion {
        // Une copie pour chacune, déposée sous le verrou de la table (son
        // ordre permet de prendre ensuite celui de la file d'une socket).
        if let Some(t) = PORTS.verrouiller().as_ref() {
            t.pour_chaque_diffusion(source, u.source, destination, u.destination, |s| {
                if let Some(copie) = Paquet::copie(p.donnees()) {
                    deposer(s, copie, source, u.source, destination, interface);
                }
            });
        }
        return Ok(());
    }
    let s = PORTS.verrouiller().as_ref().and_then(|t| t.trouver(source, u.source, destination, u.destination));
    match s {
        Some(s) => {
            deposer(&s, p, source, u.source, destination, interface);
            Ok(())
        }
        None => {
            SANS_SOCKET.fetch_add(1, Ordering::Relaxed);
            let _ = p.ajouter_entete(udp::ENTETE);
            Err(p)
        }
    }
}

fn deposer(s: &Socket, p: Paquet, source: [u8; 4], port: u16, destination: [u8; 4], interface: u32) {
    let taille = p.taille_vraie();
    let d = Datagramme { regarde: false, paquet: p, source, port, destination, interface, taille };
    if !s.deposer(d, Admission::Udp) {
        FILE_PLEINE.fetch_add(1, Ordering::Relaxed);
    }
}

/// Ce que veut dire une erreur ICMP pour une socket (l'`icmp_err_convert`
/// de Linux, pour ICMP_DEST_UNREACH) : son errno, et si elle est « fatale »
/// (une socket connectée sans IP_RECVERR ne voit que celles-là : l'hôte
/// injoignable, qui peut n'être que passager, ne lui est pas dit).
pub fn convertir(genre: u8, code: u8, pmtudisc: bool) -> Option<(i32, bool)> {
    const ENOPROTOOPT: i32 = 92;
    const ECONNREFUSED: i32 = 111;
    const ENETUNREACH: i32 = 101;
    const EHOSTUNREACH: i32 = 113;
    const EMSGSIZE: i32 = 90;
    const EOPNOTSUPP: i32 = 95;
    const EHOSTDOWN: i32 = 112;
    const ENONET: i32 = 64;
    const EPROTO: i32 = 71;
    use formats::reseau::icmp;
    const TABLE: [(i32, bool); 16] = [
        (ENETUNREACH, false), (EHOSTUNREACH, false), (ENOPROTOOPT, true), (ECONNREFUSED, true), (EMSGSIZE, false),
        (EOPNOTSUPP, false), (ENETUNREACH, true), (EHOSTDOWN, true), (ENONET, true), (ENETUNREACH, true),
        (EHOSTUNREACH, true), (ENETUNREACH, false), (EHOSTUNREACH, false), (EHOSTUNREACH, true), (EHOSTUNREACH, true),
        (EHOSTUNREACH, true),
    ];
    match genre {
        // La fragmentation nécessaire : retenue pour la route par `apprendre_si_mtu` ;
        // une erreur fatale, sauf avec IP_PMTUDISC_DONT.
        icmp::INJOIGNABLE if code == icmp::FRAGMENTATION => pmtudisc.then_some((EMSGSIZE, true)),
        icmp::INJOIGNABLE => Some(TABLE.get(code as usize).copied().unwrap_or((EHOSTUNREACH, false))),
        icmp::PARAMETRE => Some((EPROTO, true)),
        // Une redirection (Linux la retient pour la route, pas nous) et
        // l'étouffement ne sont pas des erreurs pour la socket.
        icmp::REDIRECTION | icmp::ETOUFFEMENT => None,
        _ => Some((EHOSTUNREACH, false)),
    }
}

/// Une erreur ICMP pour un datagramme UDP que nous avons envoyé, dans la
/// tâche du réseau (`__udp4_lib_err`) : la socket qui l'a envoyé, retrouvée
/// par les adresses et les ports de sa copie (comme on trouve celle d'un
/// datagramme reçu, les deux bouts inversés) ; sans IP_RECVERR, seule une
/// socket connectée voit une erreur fatale (`sk_err`, le prochain appel la
/// rend) ; avec, toute erreur va aussi dans sa file d'erreurs, avec ce que
/// le message portait de la charge d'origine.
pub fn erreur(e: &ErreurRecue) {
    let Some((port_source, port_destination)) = formats::reseau::icmp::ports(e.origine, &e.interne) else { return };
    let i = &e.interne;
    let Some(s) = PORTS.verrouiller().as_ref().and_then(|t| t.trouver(i.destination, port_destination, i.source, port_source)) else {
        return;
    };
    apprendre_si_mtu(e);
    let Some((errno, fatale)) = convertir(e.genre, e.code, fragmentation_dite(&s)) else { return };
    signaler(&s, e, errno, fatale, port_destination, udp::ENTETE);
}

/// « Fragmentation nécessaire », pour un paquet d'une socket qu'on a retrouvée :
/// sa route retient la MTU (`ipv4_sk_update_pmtu`).
pub fn apprendre_si_mtu(e: &ErreurRecue) {
    use formats::reseau::icmp;
    if e.genre == icmp::INJOIGNABLE && e.code == icmp::FRAGMENTATION {
        ipv4::apprendre_mtu(e.interne.destination, e.info);
    }
}

/// Faut-il dire à la socket `s` qu'un paquet devait être fragmenté (ICMP
/// « fragmentation nécessaire ») ? Oui, sauf avec IP_PMTUDISC_DONT (0), lu
/// par sa copie atomique : la tâche du réseau ne prend pas le `Mutex`.
pub fn fragmentation_dite(s: &Socket) -> bool {
    s.pmtudisc.load(Ordering::Relaxed) != 0
}

/// Ce que fait une erreur ICMP à la socket `s` (la fin d'`__udp4_lib_err`
/// et de `ping_err`) : voir `erreur`. `port` : celui de la destination
/// d'origine (0 pour ping) ; `debut` : où commence, après l'en-tête IPv4
/// de la copie, ce que lira le programme.
pub fn signaler(s: &Socket, e: &ErreurRecue, errno: i32, fatale: bool, port: u16, debut: usize) {
    if !s.recverr.load(Ordering::Relaxed) {
        if !fatale || !s.connectee.load(Ordering::Relaxed) {
            return;
        }
    } else {
        let charge = e.origine.get(e.interne.longueur_entete + debut..).unwrap_or(&[]);
        if let Some(donnees) = Paquet::copie(charge) {
            let taille = donnees.taille_vraie();
            s.mettre_en_file(ErreurEnFile {
                errno, origine: socket::ORIGINE_ICMP, genre: e.genre, code: e.code, info: e.info,
                adresse: e.interne.destination, port, emetteur: e.emetteur, interface: e.interface,
                arrivee: e.destination, donnees, taille,
            });
        }
    }
    s.signaler_erreur(errno);
}

/// La socket UDP de numéro `n`, si elle est liée (pour lui rendre sa place :
/// datagramme::place_rendue).
pub fn par_numero(n: u64) -> Option<Arc<Socket>> {
    let mut trouvee = None;
    if let Some(t) = PORTS.verrouiller().as_ref() {
        t.pour_chaque(|s| {
            if s.numero == n {
                trouvee = Some(s.clone());
            }
        });
    }
    trouvee
}

/// Le nombre de sockets dont quelqu'un attend une lecture (le détecteur
/// d'interblocage : attente.rs).
pub fn attentes() -> usize {
    let mut n = 0;
    if let Some(t) = PORTS.verrouiller().as_ref() {
        t.pour_chaque(|s| n += s.attente.active() as usize);
    }
    n
}
