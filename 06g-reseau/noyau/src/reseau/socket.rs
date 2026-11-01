//! Les sockets : ce qu'ont en commun toutes les sortes (la `struct socket`
//! et la `struct sock` de Linux, net/socket.c et net/core/sock.c).
//!
//! Choix de conception. Deux étages, comme Linux : la SOCKET, objet du
//! noyau derrière un fichier ouvert de sorte `Socket` (son `Prive`, comme
//! l'eventfd et le tube de 6f), avec ce qu'ont toutes les sortes : sa file
//! de réception, son erreur en attente (`sk_err`), ses drapeaux d'arrêt
//! (`shutdown`), ses options, sa file d'attente pour poll et epoll ; et son
//! PROTOCOLE (UDP, udp.rs), qui fait le reste. Un `enum` des protocoles
//! plutôt qu'une table de fonctions (les `proto_ops` de Linux) : une
//! poignée, et chaque `match` dit en un endroit ce que fait chacun ; TCP et
//! AF_UNIX y ajouteront une ligne (6h). Écarté : un objet par protocole
//! sans couche commune (chaque appel refaisait les vérifications communes,
//! et read, write, poll ne sauraient pas à qui parler).
//!
//! LES DEUX VERROUS DE LINUX :
//!   - un `Verrou` pour ce que touche la tâche du réseau quand un datagramme
//!     arrive (la file de réception et sa taille, l'erreur, l'arrêt) : le
//!     spinlock de `sk_receive_queue`. Il se prend après celui de la table
//!     des ports, jamais l'inverse ;
//!   - un `Mutex`, le `lock_sock` : ce que font les appels du programme
//!     (lier, connecter, envoyer, prendre un datagramme et le copier), que
//!     la tâche du réseau ne prend jamais. Un `recvmsg` attend sans aucun
//!     des deux (dans la file d'attente de la socket), puis prend le
//!     `Mutex` pour retirer ou lire (MSG_PEEK) le premier datagramme et le
//!     copier : deux fils qui lisent la même socket ne se marchent pas
//!     dessus, et un MSG_PEEK ne voit pas son datagramme disparaître
//!     pendant sa copie.
//!
//! La socket vit tant qu'on la tient : son fichier ouvert, un appel en
//! cours, la table des ports. Son DERNIER `close` (le fichier ouvert rendu,
//! `fichier_ferme`) la retire de la table des ports : elle ne reçoit plus
//! rien, et ce qui restait dans sa file est rendu avec elle. Un `recv` qui
//! dort dans un autre fil n'est pas réveillé (Linux non plus, mesuré) : il
//! tient la socket (le `fdget` de 6e) jusqu'à ce qu'un datagramme arrive.

use super::paquet::Paquet;
use crate::appels_fichiers::FichierTenu;
use crate::attente::{self, FileAttente, Mutex, Sommeil};
use crate::descripteurs::{FichierOuvert, Prive};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM, Table};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::{cpu, temps};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// POLLRDHUP : l'autre côté a fermé (ou la lecture est arrêtée).
pub const POLLRDHUP: u32 = 0x2000;

// Les familles (include/linux/socket.h).
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
/// Le nombre de familles que connaît Linux (NPROTO = AF_MAX) : au-delà,
/// EAFNOSUPPORT sans chercher.
pub const NPROTO: u64 = 46;
// Les sortes.
pub const SOCK_DGRAM: u64 = 2;
pub const SOCK_MAX: u64 = 11;
/// Les drapeaux que `socket` accepte avec la sorte.
pub const SOCK_NONBLOCK: u64 = 0o4000;
pub const SOCK_CLOEXEC: u64 = 0o2000000;
// Les protocoles d'IPv4.
pub const IPPROTO_IP: u64 = 0;
pub const IPPROTO_UDP: u64 = 17;
pub const IPPROTO_MAX: u64 = 263;

/// Les drapeaux d'arrêt (`sk_shutdown`).
pub const ARRET_LECTURE: u8 = 1;
pub const ARRET_ECRITURE: u8 = 2;

/// Les tailles des files, comme Linux sur une machine nue : la valeur par
/// défaut (`rmem_default`, `wmem_default`) et le plafond d'une demande
/// (`rmem_max`, `wmem_max`), puis le minimum (SOCK_MIN_RCVBUF,
/// SOCK_MIN_SNDBUF : 2048 et deux fois 2048, plus la taille d'un sk_buff).
pub const TAMPON_DEFAUT: u32 = 212_992;
pub const TAMPON_MAX: u32 = 212_992;
pub const RCVBUF_MIN: u32 = 2304;
pub const SNDBUF_MIN: u32 = 4608;

/// La taille d'une `sockaddr_in` (famille, port, adresse, 8 octets nuls).
pub const SOCKADDR_IN: usize = 16;

/// Une adresse d'IPv4 lue d'une `sockaddr_in` : sa famille (vérifiée par
/// l'appel, chacun à sa façon), son adresse et son port.
#[derive(Clone, Copy)]
pub struct AdresseInet {
    pub famille: u16,
    pub adresse: [u8; 4],
    pub port: u16,
}

/// Lit une `sockaddr_in` (la famille dans l'ordre de la machine, le port
/// et l'adresse dans celui du réseau). None : moins de 16 octets.
pub fn lire_adresse(o: &[u8]) -> Option<AdresseInet> {
    let o = o.get(..SOCKADDR_IN)?;
    Some(AdresseInet {
        famille: u16::from_le_bytes([o[0], o[1]]),
        port: u16::from_be_bytes([o[2], o[3]]),
        adresse: [o[4], o[5], o[6], o[7]],
    })
}

/// La famille seule d'une adresse (`sa_family`). None : moins de 2 octets.
pub fn famille(o: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes([*o.first()?, *o.get(1)?]))
}

/// Écrit une `sockaddr_in`.
pub fn sockaddr_in(adresse: [u8; 4], port: u16) -> [u8; SOCKADDR_IN] {
    let mut o = [0u8; SOCKADDR_IN];
    o[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    o[2..4].copy_from_slice(&port.to_be_bytes());
    o[4..8].copy_from_slice(&adresse);
    o
}

const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;

/// Le numéro de la prochaine socket (pour la table des ports).
static NUMEROS: AtomicU64 = AtomicU64::new(1);

/// Les sortes de sockets qui existent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocole {
    Udp,
}

/// Un datagramme reçu, en file : sa charge (les données du paquet), qui
/// l'a envoyé, à quelle adresse et par quelle interface il est arrivé (pour
/// IP_PKTINFO), et sa taille vraie (ce qu'il compte dans SO_RCVBUF).
pub struct Datagramme {
    pub paquet: Paquet,
    pub source: [u8; 4],
    pub port: u16,
    pub destination: [u8; 4],
    pub interface: u32,
    pub taille: usize,
}

/// Ce que touche la tâche du réseau (sous le `Verrou`).
pub struct Reception {
    pub file: VecDeque<Datagramme>,
    /// La taille vraie de ce qui est en file (`sk_rmem_alloc`).
    pub octets: usize,
    /// L'erreur en attente (`sk_err`, un errno positif ; 0 : aucune).
    pub erreur: i32,
    /// ARRET_LECTURE, ARRET_ECRITURE.
    pub arret: u8,
}

/// Les options d'une socket que lisent ses appels (sous le `Mutex`).
#[derive(Clone, Copy)]
pub struct Options {
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub broadcast: bool,
    pub keepalive: bool,
    /// SO_DEBUG (root seul), SO_OOBINLINE et SO_NO_CHECK : gardés et
    /// relus, sans effet sur UDP ; SO_DONTROUTE : seulement les machines
    /// d'un réseau directement branché (datagramme::router).
    pub debug: bool,
    pub dontroute: bool,
    pub oobinline: bool,
    pub no_check: bool,
    pub priority: u32,
    pub linger: (bool, u32),
    pub rcvlowat: u32,
    /// Les délais de réception et d'émission (SO_RCVTIMEO, SO_SNDTIMEO), en
    /// nanosecondes, déjà arrondis au tic ; None : sans délai.
    pub rcvtimeo: Option<u64>,
    pub sndtimeo: Option<u64>,
    pub tos: u8,
    /// IP_TTL : None, celui du système (64).
    pub ttl: Option<u8>,
    pub pktinfo: bool,
    pub recverr: bool,
    /// IP_MTU_DISCOVER (IP_PMTUDISC_WANT, 1, par défaut).
    pub pmtudisc: u8,
}

impl Options {
    const DEFAUT: Options = Options {
        reuseaddr: false, reuseport: false, broadcast: false, keepalive: false, debug: false, dontroute: false,
        oobinline: false, no_check: false, priority: 0, linger: (false, 0), rcvlowat: 1,
        rcvtimeo: None, sndtimeo: None, tos: 0, ttl: None, pktinfo: false, recverr: false, pmtudisc: 1,
    };
}

/// Où est la socket (l'`inet_sock` de Linux), et ses options : sous le
/// `Mutex`.
#[derive(Clone, Copy)]
pub struct Inet {
    /// A-t-elle un port (dans la table des ports) ?
    pub lie: bool,
    pub adresse: [u8; 4],
    pub port: u16,
    /// Le port a-t-il été choisi par `bind` (SOCK_BINDPORT_LOCK : gardé à
    /// la déconnexion), l'adresse aussi (SOCK_BINDADDR_LOCK) ?
    pub port_choisi: bool,
    pub adresse_choisie: bool,
    pub connecte: bool,
    pub distante: [u8; 4],
    pub port_distant: u16,
    /// L'adresse source de la connexion (pour getsockname).
    pub source: [u8; 4],
    /// L'identifiant IP des paquets d'une socket connectée (l'`inet_id`).
    pub identifiant: u16,
    pub options: Options,
}

pub struct Socket {
    pub numero: u64,
    pub protocole: Protocole,
    /// La sorte et le protocole demandés (SO_TYPE, SO_PROTOCOL).
    pub sorte: u16,
    pub proto: u16,
    /// L'utilisateur qui l'a créée (SO_REUSEPORT ; un port privilégié).
    pub uid: u32,
    /// Qui attend : `recv`, `poll`, epoll (le `sk_wq`).
    pub attente: FileAttente,
    pub reception: Verrou<Reception>,
    pub appels: Mutex<Inet>,
    /// SO_RCVBUF et SO_SNDBUF (lus par la tâche du réseau sans le Mutex).
    pub rcvbuf: AtomicU32,
    pub sndbuf: AtomicU32,
}

impl Socket {
    /// Une socket neuve, sans port.
    pub fn new(protocole: Protocole, sorte: u16, proto: u16, uid: u32) -> Socket {
        Socket {
            numero: NUMEROS.fetch_add(1, Ordering::Relaxed),
            protocole, sorte, proto, uid,
            attente: FileAttente::new(),
            reception: Verrou::new(Reception { file: VecDeque::new(), octets: 0, erreur: 0, arret: 0 }),
            appels: Mutex::new(Inet {
                lie: false, adresse: [0; 4], port: 0, port_choisi: false, adresse_choisie: false, connecte: false,
                distante: [0; 4], port_distant: 0, source: [0; 4], identifiant: 0, options: Options::DEFAUT,
            }),
            rcvbuf: AtomicU32::new(TAMPON_DEFAUT),
            sndbuf: AtomicU32::new(TAMPON_DEFAUT),
        }
    }

    /// Dépose un datagramme reçu (dans la tâche du réseau), si la file le
    /// permet : la règle d'`__udp_enqueue_schedule_skb`, une file vide
    /// accepte toujours ; sinon il faut que sa taille vraie tienne dans
    /// SO_RCVBUF. Puis ceux qui attendent sont réveillés (le
    /// `sock_def_readable`). false : jeté.
    pub fn deposer(&self, d: Datagramme) -> bool {
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        {
            let mut r = self.reception.verrouiller();
            if r.octets > 0 && r.octets + d.taille > rcvbuf {
                return false;
            }
            if r.file.try_reserve(1).is_err() {
                return false;
            }
            r.octets += d.taille;
            r.file.push_back(d);
        }
        self.attente.reveiller(POLLIN | POLLRDNORM, 1);
        true
    }

    /// Prend l'erreur en attente (le `sock_error` : lue et effacée).
    pub fn prendre_erreur(&self) -> i32 {
        core::mem::take(&mut self.reception.verrouiller().erreur)
    }

    /// Ce qu'on peut faire de la socket sans attendre (le `datagram_poll`
    /// de Linux) : une erreur (POLLERR), l'arrêt de la lecture (POLLRDHUP,
    /// et POLLIN : un recv rendra 0), les deux arrêts (POLLHUP), un
    /// datagramme en file (POLLIN), et toujours l'écriture (nos envois ne
    /// comptent pas dans SO_SNDBUF : « Reste à faire »).
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        table.attendre(&self.attente, tenu);
        let r = self.reception.verrouiller();
        let mut m = POLLOUT | POLLWRNORM | POLLWRBAND;
        if r.erreur != 0 {
            m |= POLLERR;
        }
        if r.arret & ARRET_LECTURE != 0 {
            m |= POLLRDHUP | POLLIN | POLLRDNORM;
        }
        if r.arret == ARRET_LECTURE | ARRET_ECRITURE {
            m |= POLLHUP;
        }
        if !r.file.is_empty() {
            m |= POLLIN | POLLRDNORM;
        }
        m
    }

    /// Attend qu'il y ait de quoi lire : un datagramme, une erreur, ou
    /// l'arrêt de la lecture (le `__skb_wait_for_more_packets`). Ok : il y
    /// en a. EAGAIN : l'échéance `echeance` (celle de SO_RCVTIMEO, en temps
    /// monotone) passée ; un signal : ERESTARTSYS
    /// sans délai, EINTR avec (le `sock_intr_errno` de Linux : un appel qui
    /// a un délai n'est pas refait). L'attente est exclusive : un datagramme
    /// arrivé ne réveille qu'un des fils qui attendent (le
    /// `prepare_to_wait_exclusive` de Linux), pas tous pour un seul.
    pub fn attendre_lecture(&self, echeance: Option<u64>) -> Result<(), i64> {
        const EINTR: i64 = 4;
        let pret = || {
            let r = self.reception.verrouiller();
            !r.file.is_empty() || r.erreur != 0 || r.arret & ARRET_LECTURE != 0
        };
        if pret() {
            return Ok(());
        }
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        let r = loop {
            // La condition d'abord, à chaque tour, même réveillé par un
            // signal : un datagramme arrivé en même temps se lit.
            if pret() {
                break Ok(());
            }
            if tache::signal_en_attente() {
                break Err(if echeance.is_some() { -EINTR } else { -crate::reprise::ERESTARTSYS });
            }
            if echeance.is_some_and(|e| e <= temps::ns_monotone()) {
                break Err(-EAGAIN);
            }
            self.attente.inscrire_exclusive();
            let reveil = attente::dormir(echeance, Sommeil::Interruptible);
            self.attente.retirer(t);
            if reveil == Reveil::Echeance && !pret() {
                break Err(-EAGAIN);
            }
        };
        if interruptions {
            cpu::activer_interruptions();
        }
        r
    }

    /// Arrête la lecture, l'écriture, ou les deux (les drapeaux de
    /// `shutdown`), et réveille tout le monde : un recv bloqué rend 0.
    pub fn arreter(&self, arret: u8) {
        self.reception.verrouiller().arret |= arret;
        self.attente.reveiller(0, 0);
    }

    /// La longueur du premier datagramme en file (FIONREAD, SIOCINQ : pas le
    /// total, mesuré), 0 sans datagramme.
    pub fn premier(&self) -> usize {
        self.reception.verrouiller().file.front().map_or(0, |d| d.paquet.longueur())
    }
}

/// Ce que rend une réception : la longueur copiée (ou, avec MSG_TRUNC, la
/// vraie), l'émetteur, l'adresse d'arrivée et son interface, si le
/// datagramme a été coupé ; `vide` : aucun datagramme (la lecture
/// arrêtée), donc pas d'émetteur à dire.
pub struct Recu {
    pub vide: bool,
    pub longueur: usize,
    pub source: [u8; 4],
    pub port: u16,
    pub destination: [u8; 4],
    pub interface: u32,
    pub coupe: bool,
}

/// Prend (ou lit, MSG_PEEK) le premier datagramme et le copie par `copier`
/// (au plus ce qu'elle peut prendre : elle rend combien elle a copié, ou
/// EFAULT), dans l'ordre d'`__skb_recv_udp` : l'erreur en attente d'abord
/// (lue et effacée), même s'il y a des datagrammes ; puis le premier
/// datagramme ; rien : EAGAIN sans attendre (MSG_DONTWAIT, le fichier en
/// O_NONBLOCK) ; une lecture arrêtée : 0 ; sinon attendre, au plus
/// SO_RCVTIMEO. Le datagramme est retiré sous le `Mutex`, puis copié sans
/// le `Verrou` (une copie peut fauter, et dormir pour servir une faute de
/// page). Un datagramme plus long que ce qui est copié est coupé, et le
/// reste perdu (MSG_TRUNC le dit dans `msg_flags`, ou fait rendre la vraie
/// longueur).
///
/// MSG_PEEK laisse le datagramme en file : Linux le copie depuis la file,
/// le paquet tenu par un compteur de références (`skb_get`). Le nôtre est
/// copié d'abord dans un tampon du noyau, sous le `Verrou`, puis de là au
/// programme : une copie de plus (un écart, pour MSG_PEEK seulement), et
/// pas de paquet partagé entre la file et l'appel.
pub fn prendre(s: &Socket, drapeaux: u64, non_bloquant: bool, mut copier: impl FnMut(&[u8]) -> Result<usize, i64>)
               -> Result<Recu, i64> {
    const MSG_PEEK: u64 = 2;
    const MSG_TRUNC: u64 = 0x20;
    const MSG_DONTWAIT: u64 = 0x40;
    let delai = s.appels.verrouiller().options.rcvtimeo;
    let echeance = delai.map(|d| crate::temps::ns_monotone().saturating_add(d));
    // SO_RCVTIMEO négatif : 0, une réception qui n'attend pas (Linux).
    let non_bloquant = non_bloquant || drapeaux & MSG_DONTWAIT != 0 || delai == Some(0);
    loop {
        let erreur = s.prendre_erreur();
        if erreur != 0 {
            return Err(-(erreur as i64));
        }
        {
            let _appel = s.appels.verrouiller();
            let mut r = s.reception.verrouiller();
            if let Some(premier) = r.file.front() {
                let (source, port, destination, interface) = (premier.source, premier.port, premier.destination, premier.interface);
                let total = premier.paquet.longueur();
                let copie = if drapeaux & MSG_PEEK != 0 {
                    let mut v = Vec::new();
                    v.try_reserve_exact(total).map_err(|_| -ENOMEM)?;
                    v.extend_from_slice(premier.paquet.donnees());
                    drop(r);
                    copier(&v)?
                } else {
                    let d = r.file.pop_front().expect("le premier datagramme");
                    r.octets = r.octets.saturating_sub(d.taille);
                    drop(r);
                    copier(d.paquet.donnees())?
                };
                return Ok(Recu {
                    vide: false,
                    longueur: if drapeaux & MSG_TRUNC != 0 { total } else { copie },
                    source, port, destination, interface, coupe: copie < total,
                });
            }
        }
        // Rien en file : EAGAIN sans attendre, même après l'arrêt de la
        // lecture (Linux ne regarde l'arrêt qu'en attendant) ; sinon une
        // lecture arrêtée rend 0, et on attend.
        if non_bloquant {
            return Err(-EAGAIN);
        }
        if s.reception.verrouiller().arret & ARRET_LECTURE != 0 {
            return Ok(Recu { vide: true, longueur: 0, source: [0; 4], port: 0, destination: [0; 4], interface: 0, coupe: false });
        }
        s.attendre_lecture(echeance)?;
    }
}

/// Le dernier `close` d'un fichier ouvert : s'il tenait une socket, elle
/// quitte la table des ports (le `sock_close`, puis `udp_lib_unhash`).
/// Sous le verrou des fichiers : ne dort pas (la table des ports a un
/// `Verrou`).
pub fn fichier_ferme(ferme: &FichierOuvert) {
    if let Prive::Socket(s) = &ferme.prive {
        match s.protocole {
            Protocole::Udp => super::udp::liberer(s),
        }
    }
}
