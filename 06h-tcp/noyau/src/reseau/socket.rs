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
//! `fichier_ferme`) l'accroche à la tâche, et la sortie de l'appel la
//! retire de la table des ports (6h : la fermeture différée de Linux,
//! `fermer_les_differees`) : elle ne reçoit plus rien, et ce qui restait
//! dans sa file est rendu avec elle. Un `recv` qui
//! dort dans un autre fil n'est pas réveillé (Linux non plus, mesuré) : il
//! tient la socket (le `fdget` de 6e) jusqu'à ce qu'un datagramme arrive.

use super::paquet::Paquet;
use crate::appels_fichiers::FichierTenu;
use crate::attente::{self, FileAttente, Mutex, Sommeil};
use crate::descripteurs::{FichierOuvert, Prive};
use crate::partage::Arc;
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM, Table};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::faillible::{self, FileFaillible};
use crate::{cpu, temps};
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

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
pub const SOCK_RAW: u64 = 3;
pub const SOCK_MAX: u64 = 11;
/// Les drapeaux que `socket` accepte avec la sorte.
pub const SOCK_NONBLOCK: u64 = 0o4000;
pub const SOCK_CLOEXEC: u64 = 0o2000000;
// Les protocoles d'IPv4.
pub const IPPROTO_IP: u64 = 0;
pub const IPPROTO_ICMP: u64 = 1;
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
    /// Les sockets de ping (ping.rs) : SOCK_DGRAM et IPPROTO_ICMP.
    Ping,
    /// TCP (tcp.rs, 6h) : SOCK_STREAM.
    Tcp,
}

/// La règle qui accepte un datagramme en file.
#[derive(Clone, Copy)]
pub enum Admission {
    /// Celle d'UDP (`__udp_enqueue_schedule_skb`) : une file vide accepte
    /// toujours ; sinon la taille vraie du datagramme doit tenir dans
    /// SO_RCVBUF.
    Udp,
    /// Celle des autres (`__sock_queue_rcv_skb`) : accepté tant que la file
    /// n'a pas atteint SO_RCVBUF, quelle que soit sa taille.
    Ordinaire,
}

// D'où vient une erreur de la file d'erreurs (SO_EE_ORIGIN_*).
pub const ORIGINE_LOCALE: u8 = 1;
pub const ORIGINE_ICMP: u8 = 2;

/// Une erreur dans la file d'erreurs (la `sk_error_queue` de Linux, avec
/// IP_RECVERR), lue par MSG_ERRQUEUE : sa `sock_extended_err` (l'errno,
/// l'origine, le genre et le code du message ICMP, son `info`), la
/// destination du paquet qui l'a causée (le `msg_name` rendu), qui l'a dite
/// (SO_EE_OFFENDER : la source du message ICMP), où ce message est arrivé
/// (IP_PKTINFO), et ce que lira le programme : ce que le message portait de
/// la charge d'origine (rien pour une erreur locale).
pub struct ErreurEnFile {
    pub errno: i32,
    pub origine: u8,
    pub genre: u8,
    pub code: u8,
    pub info: u32,
    pub adresse: [u8; 4],
    pub port: u16,
    pub emetteur: [u8; 4],
    pub interface: u32,
    pub arrivee: [u8; 4],
    pub donnees: Paquet,
    /// Sa taille vraie (elle compte dans SO_RCVBUF, avec les datagrammes).
    pub taille: usize,
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

impl ErreurEnFile {
    /// Une erreur « locale » (`ip_local_error`) : vue par l'envoi lui-même,
    /// sans message ICMP ni données. None : plus de mémoire.
    pub fn locale(errno: i32, info: u32, adresse: [u8; 4], port: u16) -> Option<ErreurEnFile> {
        let donnees = Paquet::vide(0)?;
        Some(ErreurEnFile {
            errno, origine: ORIGINE_LOCALE, genre: 0, code: 0, info, adresse, port, emetteur: [0; 4], interface: 0,
            arrivee: [0; 4], taille: donnees.taille_vraie(), donnees,
        })
    }
}

/// Ce que touche la tâche du réseau (sous le `Verrou`).
pub struct Reception {
    pub file: VecDeque<Datagramme>,
    /// La file d'erreurs (IP_RECVERR).
    pub erreurs: VecDeque<ErreurEnFile>,
    /// La taille vraie de ce qui est en file, dans les deux files
    /// (`sk_rmem_alloc`).
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
    /// Ce que la tâche du réseau doit savoir d'une socket quand une erreur
    /// ICMP arrive, sans prendre le `Mutex` : est-elle connectée (le
    /// `sk_state` de Linux) ? a-t-elle IP_RECVERR (un bit atomique de
    /// Linux aussi) ? et IP_MTU_DISCOVER (lu par READ_ONCE chez Linux) ?
    /// Écrits sous le `Mutex`, avec leurs copies d'`Inet`.
    pub connectee: AtomicBool,
    pub recverr: AtomicBool,
    pub pmtudisc: AtomicU8,
    /// Le numéro de son inode (/proc/net/tcp le montre), posé quand son
    /// fichier est fait ; 0 avant (une fille d'une écoute pas encore
    /// acceptée n'en a pas, chez Linux non plus).
    pub inode: AtomicU32,
    /// La suivante des sockets qu'une tâche a à fermer (sa liste
    /// `Tache::fermetures`, voir `fichier_ferme`).
    suivante: Verrou<Option<Arc<Socket>>>,
    /// Le flux d'une socket TCP (tcp.rs) : sa possession et sa connexion.
    pub flux: Option<alloc::boxed::Box<crate::attente::Possession<super::tcp::Partie>>>,
}

impl Socket {
    /// Une socket neuve, sans port.
    pub fn new(protocole: Protocole, sorte: u16, proto: u16, uid: u32) -> Socket {
        Socket {
            numero: NUMEROS.fetch_add(1, Ordering::Relaxed),
            protocole, sorte, proto, uid,
            attente: FileAttente::new(),
            reception: Verrou::new(Reception { file: VecDeque::new(), erreurs: VecDeque::new(), octets: 0, erreur: 0, arret: 0 }),
            appels: Mutex::new(Inet {
                lie: false, adresse: [0; 4], port: 0, port_choisi: false, adresse_choisie: false, connecte: false,
                distante: [0; 4], port_distant: 0, source: [0; 4], identifiant: 0, options: Options::DEFAUT,
            }),
            rcvbuf: AtomicU32::new(TAMPON_DEFAUT),
            sndbuf: AtomicU32::new(TAMPON_DEFAUT),
            connectee: AtomicBool::new(false),
            recverr: AtomicBool::new(false),
            pmtudisc: AtomicU8::new(Options::DEFAUT.pmtudisc),
            inode: AtomicU32::new(0),
            suivante: Verrou::new(None),
            flux: None,
        }
    }

    /// Une socket TCP : son flux, et ses tampons de départ (`tcp_rmem[1]`,
    /// `tcp_wmem[1]`). None : plus de mémoire pour le flux.
    pub fn tcp(mut self) -> Option<Socket> {
        self.flux = Some(faillible::boite(super::tcp::nouvelle(self.numero)).ok()?);
        self.rcvbuf.store(super::tcp::RCVBUF_DEFAUT, Ordering::Relaxed);
        self.sndbuf.store(super::tcp::SNDBUF_DEFAUT, Ordering::Relaxed);
        Some(self)
    }

    /// La même, avec un flux déjà fait (la fille d'une écoute, à
    /// `accept`).
    pub fn avec_flux(mut self, f: alloc::boxed::Box<crate::attente::Possession<super::tcp::Partie>>) -> Socket {
        self.flux = Some(f);
        self.rcvbuf.store(super::tcp::RCVBUF_DEFAUT, Ordering::Relaxed);
        self.sndbuf.store(super::tcp::SNDBUF_DEFAUT, Ordering::Relaxed);
        self
    }

    /// La même, avec le numéro `n` (celui de la fille, déjà dans la table).
    pub fn avec_numero(mut self, n: u64) -> Socket {
        self.numero = n;
        self
    }

    /// Dépose un datagramme reçu (dans la tâche du réseau), si la règle
    /// `admission` le permet ; puis ceux qui attendent sont réveillés (le
    /// `sock_def_readable`). false : jeté.
    pub fn deposer(&self, d: Datagramme, admission: Admission) -> bool {
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        {
            let mut r = self.reception.verrouiller();
            let refuse = match admission {
                Admission::Udp => r.octets > 0 && r.octets + d.taille > rcvbuf,
                Admission::Ordinaire => r.octets >= rcvbuf,
            };
            if refuse {
                return false;
            }
            let taille = d.taille;
            if r.file.ajouter_derriere(d).is_err() {
                return false;
            }
            r.octets += taille;
        }
        self.attente.reveiller(POLLIN | POLLRDNORM, 1);
        true
    }

    /// Pose l'erreur `errno` (`sk_err`) et réveille (le `sk_error_report`).
    pub fn signaler_erreur(&self, errno: i32) {
        self.reception.verrouiller().erreur = errno;
        self.attente.reveiller(POLLERR, 1);
    }

    /// Met l'erreur `e` dans la file d'erreurs, s'il y a la place
    /// (`sock_queue_err_skb` : elle compte avec les datagrammes, et doit
    /// laisser de la place sous SO_RCVBUF), et réveille. false : jetée.
    pub fn mettre_en_file(&self, e: ErreurEnFile) -> bool {
        let rcvbuf = self.rcvbuf.load(Ordering::Relaxed) as usize;
        {
            let mut r = self.reception.verrouiller();
            let taille = e.taille;
            if r.octets + taille >= rcvbuf || r.erreurs.ajouter_derriere(e).is_err() {
                return false;
            }
            r.octets += taille;
        }
        self.attente.reveiller(POLLERR, 1);
        true
    }

    /// Prend la première erreur de la file (`sock_dequeue_err_skb`) : l'erreur
    /// en attente devient celle de la suivante si elle vient d'ICMP, ou 0 si
    /// celle-ci en venait et qu'il n'en reste pas d'ICMP ; une erreur locale
    /// n'y touche pas. S'il en reste, ceux qui attendent sont réveillés.
    pub fn prendre_en_file(&self) -> Option<ErreurEnFile> {
        let (e, reste) = {
            let mut r = self.reception.verrouiller();
            let e = r.erreurs.pop_front()?;
            r.octets = r.octets.saturating_sub(e.taille);
            let suivante_icmp = r.erreurs.front().filter(|s| s.origine == ORIGINE_ICMP).map(|s| s.errno);
            if let Some(errno) = suivante_icmp {
                r.erreur = errno;
            } else if e.origine == ORIGINE_ICMP {
                r.erreur = 0;
            }
            (e, !r.erreurs.is_empty())
        };
        if reste {
            self.attente.reveiller(POLLERR, 1);
        }
        Some(e)
    }

    /// Vide la file d'erreurs (IP_RECVERR remis à 0).
    pub fn vider_erreurs(&self) {
        let mut r = self.reception.verrouiller();
        let rendus: usize = r.erreurs.iter().map(|e| e.taille).sum();
        r.octets = r.octets.saturating_sub(rendus);
        r.erreurs.clear();
    }

    /// Prend l'erreur en attente (le `sock_error` : lue et effacée).
    pub fn prendre_erreur(&self) -> i32 {
        core::mem::take(&mut self.reception.verrouiller().erreur)
    }

    /// Ce qu'on peut faire de la socket sans attendre (le `datagram_poll`
    /// de Linux) : une erreur en attente ou en file (POLLERR), l'arrêt de la lecture (POLLRDHUP,
    /// et POLLIN : un recv rendra 0), les deux arrêts (POLLHUP), un
    /// datagramme en file (POLLIN), et toujours l'écriture (nos envois ne
    /// comptent pas dans SO_SNDBUF : « Reste à faire »).
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        if let Some(f) = &self.flux {
            table.attendre(&f.file, tenu);
            return super::tcp::sonder(self);
        }
        table.attendre(&self.attente, tenu);
        let r = self.reception.verrouiller();
        let mut m = POLLOUT | POLLWRNORM | POLLWRBAND;
        if r.erreur != 0 || !r.erreurs.is_empty() {
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
/// longueur, pour UDP).
///
/// MSG_PEEK laisse le datagramme en file : Linux le copie depuis la file,
/// le paquet tenu par un compteur de références (`skb_get`). Le nôtre est
/// copié d'abord dans un tampon du noyau, sous le `Verrou`, puis de là au
/// programme : une copie de plus (un écart, pour MSG_PEEK seulement), et
/// pas de paquet partagé entre la file et l'appel.
pub fn prendre(s: &Socket, drapeaux: u64, non_bloquant: bool, mut copier: impl FnMut(&[u8]) -> Result<usize, i64>)
               -> Result<Recu, i64> {
    // MSG_TRUNC fait rendre la vraie longueur à UDP (`udp_recvmsg`), pas à
    // ping (`ping_recvmsg` rend ce qu'il a copié).
    let vraie = s.protocole == Protocole::Udp;
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
                    let v = faillible::copie(premier.paquet.donnees()).map_err(|_| -ENOMEM)?;
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
                    longueur: if vraie && drapeaux & MSG_TRUNC != 0 { total } else { copie },
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
/// est accrochée à la tâche courante, et sera fermée à la sortie de son
/// appel (`fermer_les_differees`). Le `__fput` de Linux, remis par
/// `task_work_add` au retour vers l'anneau 3 : le dernier `close` se fait
/// sous le verrou des fichiers (vfs.rs), où l'on ne peut ni dormir ni
/// prendre la possession d'une socket, ce que demandera la fermeture d'une
/// socket TCP (envoyer FIN, attendre SO_LINGER) ; une socket UDP s'en
/// passerait, mais toutes suivent le même chemin, comme chez Linux. Sans
/// allocation : la liste est chaînée par les sockets elles-mêmes.
pub fn fichier_ferme(ferme: &FichierOuvert) {
    if let Prive::Socket(s) = &ferme.prive {
        let t = tache::courante();
        let mut tete = t.fermetures.verrouiller();
        *s.suivante.verrouiller() = tete.take();
        *tete = Some(s.clone());
    }
}

/// Ferme les sockets dont la tâche courante a fait le dernier `close` (le
/// `task_work_run`) : à la sortie de chaque appel système et de chaque
/// appel WASI, et à la fin de la tâche. Sans verrou tenu. Une socket
/// quitte alors sa table des ports (le `sock_close`, puis
/// `udp_lib_unhash`) : elle ne reçoit plus rien, et ce qui restait dans sa
/// file est rendu avec elle.
pub fn fermer_les_differees() {
    let t = tache::courante();
    loop {
        let s = {
            let mut tete = t.fermetures.verrouiller();
            let Some(s) = tete.take() else { return };
            *tete = s.suivante.verrouiller().take();
            s
        };
        match s.protocole {
            Protocole::Tcp => super::tcp::fermer(&s),
            _ => super::datagramme::table::retirer(&s),
        }
    }
}

/// Un numéro de socket neuf (la fille d'une écoute en prend un).
pub fn nouveau_numero() -> u64 {
    NUMEROS.fetch_add(1, Ordering::Relaxed)
}
