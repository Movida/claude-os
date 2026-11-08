//! Les sockets AF_UNIX (6h) : des sockets d'une même machine, sans réseau
//! (net/unix/af_unix.c). Trois sortes : SOCK_STREAM (un flux, comme TCP),
//! SOCK_DGRAM (des datagrammes, comme UDP, adressés par nom), SOCK_SEQPACKET
//! (des messages qui gardent leurs limites, sur une connexion). Claude Code
//! s'en sert pour parler à ses sous-processus (`socketpair`, vingt fois au
//! lancement de `claude -p`, mesuré) et pour sa propre écoute ; la glibc,
//! pour nscd.
//!
//! LA SOCKET (la `unix_sock` de Linux) : une `Socket` de 6g (son fichier,
//! ses options, sa file d'attente pour poll et epoll), plus un `Unix` : sa
//! sorte, son état sous un `Verrou` (la phase, le nom, le pair, les arrêts,
//! l'erreur, les droits du pair, la file des messages reçus) et ce qu'elle a
//! envoyé que le destinataire n'a pas encore lu (`envoyes`).
//!
//! LES MESSAGES : chaque envoi devient un ou plusieurs messages, mis dans
//! la file du destinataire. Leur place compte contre SO_SNDBUF de
//! L'ÉMETTEUR, en taille vraie, tant qu'ils ne sont pas lus (le
//! `sk_wmem_alloc` de Linux, rendu par le destructeur du paquet) : c'est
//! l'émetteur qui attend quand le lecteur traîne (mesuré : 93 envois de 1000
//! octets, puis EAGAIN). La taille vraie est celle d'un paquet de Linux
//! (`taille_vraie`) : une tête (la charge et ses 320 octets de structures,
//! arrondies à la puissance de deux, plus 256 ; mesuré : 1536 pour deux
//! envois de 5 et 3 octets, par TIOCOUTQ) et, au-delà de ce qu'elle prend,
//! des pages (mesuré : 33 536 pour 32 Kio). Un flux lit les messages à la
//! suite ; SEQPACKET et DGRAM, un par lecture, MSG_TRUNC si la place
//! manque. Un DGRAM non connecté au destinataire attend aussi que sa file
//! ait de la place (`max_dgram_qlen`, 10 : onze datagrammes, puis EAGAIN,
//! mesuré).
//!
//! LES CONNEXIONS (STREAM, SEQPACKET) : `connect` crée tout de suite la
//! socket fille (dans l'appel système : l'allocation infaillible d'un appel,
//! l'écart déjà écrit de 6h), la connecte à la socket qui se connecte, et la
//! met dans la file de l'écoute (au plus `backlog + 1`, mesuré) : la paire
//! est connectée avant `accept`, et l'on peut déjà écrire. Les deux pairs se
//! tiennent l'un l'autre (un cycle, de références fortes, comme Linux) ; le
//! dernier `close` le casse (`unix_release_sock`) : le pair voit ses deux
//! sens arrêtés (POLLHUP), et ECONNRESET s'il restait des données non lues
//! (mesuré). Une écoute fermée défait ses filles pas encore acceptées : leurs
//! clients voient ECONNRESET.
//!
//! LES NOMS : un chemin (`bind` crée un inode S_IFSOCK dans le tmpfs, 0777
//! moins l'umask ; ce n'est qu'un nom : l'ouvrir rend ENXIO) ; un nom
//! « abstrait » (un premier octet nul, sans fichier, comparé avec sa
//! longueur) ; ou un nom donné par le noyau (`\0` et cinq chiffres
//! hexadécimaux : `bind` d'une adresse vide, ou `connect` et `sendto` d'une
//! socket sans nom qui a SO_PASSCRED). La socket TIENT l'inode de son
//! chemin jusqu'à sa fermeture : le tmpfs réutilise les numéros d'inode, et
//! sans cela un `connect` vers un fichier neuf trouverait une ancienne
//! socket. Toutes les sockets AF_UNIX sont inscrites dans un registre (des
//! références faibles, et leur nom) : les noms y sont cherchés, et
//! /proc/net/unix le parcourt. Une liste, pas les tables de hachage de
//! Linux : il n'y a que quelques dizaines de sockets.
//!
//! LES VERROUS : Linux en a trois par socket (l'état, la file de réception,
//! les lecteurs). Ici, l'état et la file sous un seul `Verrou` (un seul
//! processeur : le partage n'y gagnerait rien), plus le `Mutex` des
//! lecteurs (le `iolock` : deux lecteurs d'un même flux ne se marchent pas
//! dessus, et un message qu'une lecture a sorti de la file pour le copier y
//! est remis avant qu'un autre lise), rendu pendant que la lecture attend,
//! comme Linux (un `recv(MSG_DONTWAIT)` d'un autre fil n'attend pas qu'un
//! lecteur bloqué ait reçu). Deux sockets ne sont jamais verrouillées en
//! même temps ; le registre, jamais sous l'état d'une socket. Aucune copie
//! depuis ou vers un programme sous un `Verrou` ; aucune référence à une
//! socket rendue sous lui (son dernier `drop` pourrait rendre un inode).
//! Aucune attente AF_UNIX ne compte pour le détecteur d'interblocage
//! (attente.rs) : une socket que personne d'autre ne tient ne recevra
//! rien.
//!
//! LES DESCRIPTEURS EN VOL (SCM_RIGHTS) : un message tient des fichiers (`fichiers`), rendus à la
//! lecture : un flux s'arrête après le message qui en porte, MSG_PEEK sur lui (`recevoir_flux`).
//! Une file qui tient une socket peut la tenir sans fin, dans un cycle : le ramasse-miettes
//! (`ramasser`, `GRAPHE`, inet::en_vol) les retrouve à chaque fermeture tant qu'il en reste en
//! vol. Choix de conception : synchrone, à la fin de `fermer`. Linux passe par une file de travail
//! pour ne pas ralentir `close` : là où il y a des milliers de sockets en vol. Ici, le graphe est
//! petit ; et « mémoire rendue » n'a pas à attendre qu'il se soit passé quelque chose.
//!
//! LES DROITS (SCM_CREDENTIALS) : un message porte ceux qu'a donnés l'émetteur, ou les siens dès que
//! l'une des deux sockets a SO_PASSCRED, ou que la receveuse n'a pas encore été acceptée, et qu'elle
//! pourrait donc le demander (« Some apps rely on write() giving SCM_CREDENTIALS »). Une lecture ne
//! colle jamais deux messages de droits différents.
//!
//! L'OCTET URGENT (MSG_OOB, un flux seulement ; Linux l'a depuis 5.15) : le dernier octet de
//! l'envoi, un message à lui, que la socket désigne (`oob`). Une lecture ordinaire s'arrête devant lui,
//! et le saute ensuite, sauf SO_OOBINLINE. Un second envoi urgent ne fait que le remplacer : le
//! précédent redevient un octet comme un autre. Lu à part, il reste en file, vide : une marque
//! (SIOCATMARK), où s'arrête la lecture d'avant, et que jette celle d'après (`prochain_du_flux`).
//!
//! ÉCART : SIOCINQ dit ce qui reste à lire : Linux 6.18 tient un
//! compte à part (`inq_len`), qui ne descend qu'à la fin d'un message (mesuré : 6 à lire, 1 lu : 6
//! encore), et qui oublie l'octet urgent sauté (il dit 1, la file vide, pour toujours) : pas un
//! comportement sur lequel un programme peut compter.

use super::socket::{Protocole, Socket, ARRET_ECRITURE, ARRET_LECTURE, POLLRDHUP};
use crate::asynchrone::Raison;
use crate::appels_fichiers::FichierTenu;
use crate::descripteurs::{Fichier, Sorte as SorteFichier};
use crate::attente::{self, FileAttente, GardeMutex, Mutex, PorteFile, Relais, Sommeil};
use crate::faillible::{self, FileFaillible, VecFaillible};
use crate::partage::{Arc, Weak};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDBAND, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use crate::tache::Reveil;
use crate::verrou::Verrou;
use crate::{processus, temps};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use inet::en_vol::{self, Arete};

pub const AF_UNIX: u16 = 1;
pub const SOCK_STREAM: u16 = 1;
pub const SOCK_DGRAM: u16 = 2;
pub const SOCK_SEQPACKET: u16 = 5;
/// La place d'une `sockaddr_un` : sa famille et 108 octets de chemin.
pub const ADRESSE_MAX: usize = 110;
/// La place d'un nom : un chemin de 108 octets sans nul a la longueur 111
/// (`unix_mkname_bsd` compte le nul qu'il pose après lui).
const NOM_MAX: usize = ADRESSE_MAX + 1;
/// La file d'un DGRAM : au-delà de 10 datagrammes en file, l'émetteur
/// attend (`max_dgram_qlen`).
const DGRAM_QLEN: usize = 10;
/// La plus grande écoute (`somaxconn`).
const SOMAXCONN: usize = 4096;
/// Le plus gros message d'un flux : la moitié de SO_SNDBUF moins 64, au
/// plus une tête et 32 Kio de pages (`unix_stream_sendmsg` : deux messages
/// en route, et des allocations qui restent petites).
const MESSAGE_MAX: usize = (4096 - 320) + (32 << 10);

/// La limite d'un envoi (SCM_MAX_FD).
pub const SCM_MAX_FD: usize = 253;
/// Au-delà de tant de sockets en vol, un envoi ramasse d'abord (`UNIX_INFLIGHT_TRIGGER_GC`).
const EN_VOL_TROP: usize = 16_000;

const EPERM: i64 = 1;
const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const EINVAL: i64 = 22;
const EPIPE: i64 = 32;
const EMSGSIZE: i64 = 90;
const EPROTOTYPE: i64 = 91;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;
const ECONNRESET: i64 = 104;
const ENOBUFS: i64 = 105;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const ETOOMANYREFS: i64 = 109;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const ECONNREFUSED: i64 = 111;

/// Les sortes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sorte {
    Flux,
    Datagrammes,
    Paquets,
}

impl Sorte {
    /// La sorte d'une demande (`unix_create`) : SOCK_RAW devient SOCK_DGRAM
    /// (mesuré : SO_TYPE 2) ; SOCK_RDM et les autres : ESOCKTNOSUPPORT.
    pub fn de(sorte: u16) -> Option<Sorte> {
        match sorte {
            SOCK_STREAM => Some(Sorte::Flux),
            SOCK_DGRAM | 3 => Some(Sorte::Datagrammes),
            SOCK_SEQPACKET => Some(Sorte::Paquets),
            _ => None,
        }
    }

    pub fn linux(self) -> u16 {
        match self {
            Sorte::Flux => SOCK_STREAM,
            Sorte::Datagrammes => SOCK_DGRAM,
            Sorte::Paquets => SOCK_SEQPACKET,
        }
    }

    /// Avec connexion (STREAM, SEQPACKET) ?
    fn connexion(self) -> bool {
        self != Sorte::Datagrammes
    }
}

/// Un nom : l'adresse telle que la rend `getsockname` (la `sockaddr_un` et
/// sa longueur) ; pour un chemin, l'inode tenu par la socket qui l'a lié.
#[derive(Clone, Copy)]
pub struct Nom {
    octets: [u8; NOM_MAX],
    longueur: usize,
    inode: Option<u32>,
}

impl Nom {
    pub fn octets(&self) -> &[u8] {
        &self.octets[..self.longueur]
    }

    /// Un nom abstrait (le premier octet du chemin est nul) ?
    fn abstrait(&self) -> bool {
        self.longueur > 2 && self.octets[2] == 0
    }

    /// Un nom sans adresse : la famille seule (une socket sans nom).
    fn vide() -> Nom {
        let mut octets = [0u8; NOM_MAX];
        octets[..2].copy_from_slice(&AF_UNIX.to_le_bytes());
        Nom { octets, longueur: 2, inode: None }
    }
}

/// L'adresse qu'un programme a donnée, lue (`unix_validate_addr`, puis
/// `unix_mkname_bsd`) : moins de 2 octets ou plus de 110, ou une autre
/// famille : EINVAL ; un chemin est coupé à son premier octet nul, et sa
/// longueur recalculée avec le nul (mesuré : « sock1 » fait 8 ; un chemin
/// de 108 octets sans nul, 111) ; un nom abstrait garde la longueur donnée.
fn lire_nom(o: &[u8]) -> Result<Nom, i64> {
    if o.len() < 2 || o.len() > ADRESSE_MAX || u16::from_le_bytes([o[0], o[1]]) != AF_UNIX {
        return Err(-EINVAL);
    }
    let mut n = Nom { octets: [0; NOM_MAX], longueur: o.len(), inode: None };
    n.octets[..o.len()].copy_from_slice(o);
    if o.len() > 2 && o[2] != 0 {
        let chemin = o[2..].iter().position(|&c| c == 0).unwrap_or(o.len() - 2);
        n.longueur = 2 + chemin + 1;
    }
    Ok(n)
}

/// Le chemin d'un nom de chemin (sans le nul).
fn chemin(n: &Nom) -> &[u8] {
    let o = &n.octets[2..n.longueur];
    &o[..o.iter().position(|&c| c == 0).unwrap_or(o.len())]
}

/// Les droits du pair (SO_PEERCRED : la `struct ucred`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Droits {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Ceux d'un message qui n'en porte pas, tels que les lit qui les demande (pas de pid, et
/// `overflowuid` : `from_kuid_munged`, mesuré).
const SANS_DROITS: Droits = Droits { pid: 0, uid: 65534, gid: 65534 };

/// Ce que porte un envoi, en plus de ses octets (la `scm_cookie`).
#[derive(Default)]
pub struct Scm {
    pub fichiers: Vec<FichierTenu>,
    /// Les droits donnés par l'émetteur, déjà vérifiés (`scm_check_creds`).
    pub droits: Option<Droits>,
}

/// Ceux du processus courant (`init_peercred`).
fn droits_courants() -> Droits {
    processus::avec(|p| Droits { pid: p.pid, uid: p.identite.uid, gid: p.identite.gid })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Neuve,
    Ecoute { backlog: usize },
    Connectee,
}

/// Un message en file : sa charge (et ce qui en a déjà été lu, pour un
/// flux), sa taille vraie, qui l'a envoyé (pour lui rendre sa place, et
/// pour l'adresse d'un DGRAM), ou, dans la file d'une écoute, la fille qu'il
/// apporte.
struct Message {
    octets: Vec<u8>,
    lus: usize,
    taille: usize,
    emetteur: Option<Arc<Socket>>,
    enfant: Option<Arc<Socket>>,
    /// Les fichiers qu'il tient (`UNIXCB(skb).fp`), et son numéro dans `GRAPHE` s'il y a des sockets
    /// parmi eux (0 : aucune).
    fichiers: Vec<FichierTenu>,
    vol: u64,
    /// Ses droits (`UNIXCB(skb).pid`, `uid`, `gid`).
    droits: Option<Droits>,
    /// Un octet urgent : son numéro, à comparer à `oob` de la socket (0 : un message ordinaire).
    numero_oob: u64,
    /// Un message vide déjà vu par MSG_PEEK (`skb->peeked`) : SO_PEEK_OFF passe au suivant.
    regarde: bool,
}

impl Message {
    fn restant(&self) -> &[u8] {
        &self.octets[self.lus..]
    }
}

/// L'état d'une socket, sous son `Verrou`.
struct Etat {
    phase: Phase,
    nom: Option<Nom>,
    pair: Option<Arc<Socket>>,
    arret: u8,
    erreur: i32,
    /// Fermée (`SOCK_DEAD`) : plus rien n'y entre.
    morte: bool,
    passcred: bool,
    /// Elle accepte qu'on lui envoie des descripteurs (SO_PASSRIGHTS, `sk_scm_rights`).
    passrights: bool,
    /// Une fille pas encore acceptée : le numéro de l'écoute qui la tient (`u->listener`).
    ecoute: Option<u64>,
    /// L'octet urgent en file, son numéro (`u->oob_skb` ; 0 : aucun).
    oob: u64,
    /// Les droits du pair (pour une écoute, les siens, posés à `listen`).
    droits: Option<Droits>,
    file: VecDeque<Message>,
}

/// La partie AF_UNIX d'une socket.
pub struct Unix {
    pub sorte: Sorte,
    etat: Verrou<Etat>,
    /// Ce qu'elle a envoyé, pas encore lu, en taille vraie.
    envoyes: AtomicUsize,
    /// Les lecteurs, un à la fois (le `iolock`).
    lecteurs: Mutex<()>,
    /// Ceux qui attendent qu'elle lise (la `peer_wait` de Linux) : les
    /// relais des DGRAM connectés à elle qui ont trouvé sa file pleine ;
    /// réveillée à chaque message lu, et à sa fermeture.
    attente_pairs: FileAttente,
    /// Son propre relais, inscrit dans la `attente_pairs` de son pair
    /// quand `poll` le trouve plein (`unix_dgram_peer_wake_me`) : il
    /// réveille sa file à elle.
    relais: Pin<alloc::boxed::Box<Relais<Socket>>>,
}

impl Unix {
    /// None : plus de mémoire (pour son relais).
    pub fn new(sorte: Sorte) -> Option<Unix> {
        Some(Unix {
            sorte,
            etat: Verrou::new(Etat {
                phase: Phase::Neuve, nom: None, pair: None, arret: 0, erreur: 0, morte: false, passcred: false, passrights: true, ecoute: None, oob: 0, droits: None,
                file: VecDeque::new(),
            }),
            envoyes: AtomicUsize::new(0),
            lecteurs: Mutex::new(()),
            attente_pairs: FileAttente::new(),
            relais: Relais::nouveau()?,
        })
    }
}

impl PorteFile for Socket {
    /// La file qu'écoutent les relais de ses pairs.
    fn file_ecoutee(&self) -> &FileAttente {
        &unix(self).attente_pairs
    }
}

fn unix(s: &Socket) -> &Unix {
    s.unix.as_deref().expect("une socket AF_UNIX a sa partie AF_UNIX")
}

/// La taille vraie d'un message de `n` octets de la sorte `sorte`, celle
/// du paquet que ferait Linux (`sock_alloc_send_pskb`) : une tête de `n -
/// pages` octets (sa charge et les 320 octets de `skb_shared_info`,
/// arrondis par kmalloc, plus les 256 de la `sk_buff`), et des pages. Un
/// flux (`unix_stream_sendmsg`) met en pages ce qui dépasse SKB_MAX_HEAD(0),
/// 3776 octets, arrondi à la page ; un DGRAM ou un SEQPACKET
/// (`unix_dgram_sendmsg`), ce qui dépasse SKB_MAX_ALLOC, 16 064.
fn taille_vraie(sorte: Sorte, n: usize) -> usize {
    const PAGE: usize = 4096;
    let seuil = if sorte == Sorte::Flux { PAGE - 320 } else { 4 * PAGE - 320 };
    let pages = if n > seuil { (n - seuil).next_multiple_of(PAGE).min(n) } else { 0 };
    (n - pages + 320).next_power_of_two() + 256 + pages
}

// --- Le registre ---

/// Une socket inscrite : son numéro, une référence faible, et son nom s'il
/// est cherchable (celui qu'elle a lié ; pas celui qu'une fille copie de son
/// écoute).
struct Inscrite {
    numero: u64,
    socket: Weak<Socket>,
    /// Sa sorte : un nom abstrait n'est cherché que parmi les sockets de la
    /// sorte qui le cherche (`unix_abstract_hash` y mêle la sorte).
    sorte: Sorte,
    nom: Option<Nom>,
}

static REGISTRE: Verrou<Vec<Inscrite>> = Verrou::new(Vec::new());

/// Inscrit une socket neuve. ENOBUFS : plus de mémoire.
pub fn inscrire(s: &Arc<Socket>) -> Result<(), i64> {
    let mut r = REGISTRE.verrouiller();
    if r.try_reserve(1).is_err() {
        return Err(-ENOBUFS);
    }
    // La place est prise juste avant.
    r.ajouter_dans_la_place(Inscrite { numero: s.numero, socket: Arc::downgrade(s), sorte: unix(s).sorte, nom: None });
    Ok(())
}

/// Retire la socket `numero` du registre ; vide, il rend sa place.
fn desinscrire(numero: u64) {
    let rendue = {
        let mut r = REGISTRE.verrouiller();
        r.retain(|i| i.numero != numero && i.socket.strong_count() > 0);
        if r.is_empty() { Some(core::mem::take(&mut *r)) } else { None }
    };
    drop(rendue);
}

/// La socket de numéro `numero`.
fn par_numero(numero: u64) -> Option<Arc<Socket>> {
    REGISTRE.verrouiller().iter().find(|i| i.numero == numero).and_then(|i| i.socket.upgrade())
}

/// La socket liée au nom `n` : par son inode pour un chemin, par ses octets
/// (et sa longueur) pour un nom abstrait, parmi ceux de la sorte `sorte`.
fn trouver(n: &Nom, sorte: Sorte) -> Option<Arc<Socket>> {
    let r = REGISTRE.verrouiller();
    r.iter()
        .find(|i| {
            i.nom.is_some_and(|m| match n.inode {
                Some(inode) => m.inode == Some(inode),
                None => i.sorte == sorte && m.inode.is_none() && m.octets() == n.octets(),
            })
        })
        .and_then(|i| i.socket.upgrade())
}

/// Inscrit le nom `n` de la socket `numero`, de la sorte `sorte` ; un nom
/// abstrait déjà pris par une socket de la même sorte : EADDRINUSE (une
/// autre sorte peut porter le même : Linux les range à part).
fn nommer(numero: u64, sorte: Sorte, n: Nom) -> Result<(), i64> {
    let mut r = REGISTRE.verrouiller();
    if n.abstrait()
        && r.iter().any(|i| {
            i.sorte == sorte && i.socket.strong_count() > 0 && i.nom.is_some_and(|m| m.inode.is_none() && m.octets() == n.octets())
        })
    {
        return Err(-EADDRINUSE);
    }
    if let Some(i) = r.iter_mut().find(|i| i.numero == numero) {
        i.nom = Some(n);
    }
    Ok(())
}

// --- Les noms ---

/// Lie `s` au nom `n` : un chemin (son inode créé, puis tenu), ou un nom
/// abstrait. Déjà liée : EINVAL (Linux crée le fichier, voit qu'elle l'est,
/// et l'efface : le même résultat).
fn lier_nom(s: &Socket, mut n: Nom) -> Result<(), i64> {
    if unix(s).etat.verrouiller().nom.is_some() {
        return Err(-EINVAL);
    }
    if !n.abstrait() {
        n.inode = Some(crate::appels_fichiers::creer_noeud_socket(chemin(&n))?);
    }
    if let Err(e) = nommer(s.numero, unix(s).sorte, n) {
        return Err(e);
    }
    let deja = {
        let mut e = unix(s).etat.verrouiller();
        let deja = e.nom.is_some();
        if !deja {
            e.nom = Some(n);
        }
        deja
    };
    if deja {
        // Un autre fil l'a liée entre-temps.
        if let Some(i) = n.inode {
            crate::appels_fichiers::lacher_noeud(i);
        }
        return Err(-EINVAL);
    }
    Ok(())
}

/// Le nom automatique (`unix_autobind`) : `\0` et cinq chiffres
/// hexadécimaux, le premier libre à partir d'un nombre tiré au hasard
/// (comme Linux : un nom qu'on ne devine pas) ; tous pris : ENOSPC ; déjà
/// liée : rien.
fn autonommer(s: &Socket) -> Result<(), i64> {
    const ENOSPC: i64 = 28;
    if unix(s).etat.verrouiller().nom.is_some() {
        return Ok(());
    }
    let depart = crate::aleatoire::u32();
    for i in 1..=0x10_0000u32 {
        let k = depart.wrapping_add(i) & 0xF_FFFF;
        let mut n = Nom::vide();
        n.octets[3..8].copy_from_slice(&chiffres_hexa(k));
        n.longueur = 8;
        match lier_nom(s, n) {
            Err(e) if e == -EADDRINUSE => continue,
            r => return r,
        }
    }
    Err(-ENOSPC)
}

/// Cinq chiffres hexadécimaux minuscules (le `%05x` de Linux).
fn chiffres_hexa(k: u32) -> [u8; 5] {
    let mut o = [0u8; 5];
    for (i, c) in o.iter_mut().enumerate() {
        let v = (k >> (4 * (4 - i))) & 0xF;
        *c = if v < 10 { b'0' + v as u8 } else { b'a' + v as u8 - 10 };
    }
    o
}

/// La socket que désigne l'adresse `n` pour une socket de sorte `sorte`
/// (`unix_find_other`) : par son chemin (ENOENT, EACCES, ECONNREFUSED pour
/// un fichier qui n'est pas une socket, ou une socket fermée ; une socket
/// d'une autre sorte : EPROTOTYPE, `unix_find_bsd`) ou par son nom abstrait
/// parmi ceux de sa sorte (sinon ECONNREFUSED, `unix_find_abstract`).
fn chercher(n: &Nom, sorte: Sorte) -> Result<Arc<Socket>, i64> {
    let mut n = *n;
    if !n.abstrait() {
        n.inode = Some(crate::appels_fichiers::trouver_noeud_socket(chemin(&n))?);
    }
    let autre = trouver(&n, sorte).ok_or(-ECONNREFUSED)?;
    if unix(&autre).sorte != sorte {
        return Err(-EPROTOTYPE);
    }
    Ok(autre)
}

/// bind (`unix_bind`) : une adresse vide (la famille seule) : le nom
/// automatique ; sinon un chemin ou un nom abstrait.
pub fn lier(s: &Socket, o: &[u8]) -> Result<(), i64> {
    if o.len() == 2 && u16::from_le_bytes([o[0], o[1]]) == AF_UNIX {
        return autonommer(s);
    }
    lier_nom(s, lire_nom(o)?)
}

/// getsockname : son nom, ou la famille seule (mesuré : longueur 2).
pub fn nom(s: &Socket) -> Nom {
    unix(s).etat.verrouiller().nom.unwrap_or_else(Nom::vide)
}

/// getpeername : le nom de son pair (le nom de l'écoute, pour une
/// socket qui s'est connectée) ; pas de pair : ENOTCONN.
pub fn pair(s: &Socket) -> Result<Nom, i64> {
    let p = unix(s).etat.verrouiller().pair.clone().ok_or(-ENOTCONN)?;
    Ok(nom(&p))
}

/// SO_PEERCRED : les droits du pair ; sans pair, ceux d'aucun processus
/// (pid 0, l'utilisateur et le groupe « hors de portée », 65534, comme
/// Linux).
pub fn droits_du_pair(s: &Socket) -> Droits {
    unix(s).etat.verrouiller().droits.unwrap_or(Droits { pid: 0, uid: 65_534, gid: 65_534 })
}

/// SO_PASSRIGHTS.
pub fn passrights(s: &Socket) -> bool {
    unix(s).etat.verrouiller().passrights
}

pub fn changer_passrights(s: &Socket, oui: bool) {
    unix(s).etat.verrouiller().passrights = oui;
}

/// SO_PASSCRED.
pub fn passcred(s: &Socket) -> bool {
    unix(s).etat.verrouiller().passcred
}

pub fn changer_passcred(s: &Socket, oui: bool) {
    unix(s).etat.verrouiller().passcred = oui;
}

/// SO_ERROR : l'erreur en attente, prise.
pub fn prendre_erreur(s: &Socket) -> i32 {
    core::mem::take(&mut unix(s).etat.verrouiller().erreur)
}

/// SO_ACCEPTCONN.
pub fn ecoute(s: &Socket) -> bool {
    matches!(unix(s).etat.verrouiller().phase, Phase::Ecoute { .. })
}

// --- Les attentes ---

/// Attend que `pret` soit vrai, dans la file d'attente `file`, au plus
/// jusqu'à `echeance` : EAGAIN à l'échéance ; un signal : ERESTARTSYS, ou
/// EINTR avec un délai (`sock_intr_errno`). La condition est revue sous
/// l'inscription, interruptions coupées : un réveil ne se perd pas.
fn attendre(file: &FileAttente, echeance: Option<u64>, delai: bool, pret: impl Fn() -> bool) -> Result<(), i64> {
    if pret() {
        return Ok(());
    }
    // Les sept pas d'attente.rs (`attendre_que`) : la condition est revue
    // une dernière fois après l'échéance ou le signal.
    match attente::attendre_que(file, attente::Inscription::Ordinaire, Sommeil::Interruptible, echeance, pret) {
        Reveil::Reveillee => Ok(()),
        Reveil::Echeance => Err(-EAGAIN),
        Reveil::Signal => Err(if delai { -EINTR } else { -crate::reprise::ERESTARTSYS }),
    }
}

/// L'échéance d'un délai (SO_SNDTIMEO, SO_RCVTIMEO), et s'il y en a un.
fn echeance(delai: Option<u64>) -> (Option<u64>, bool) {
    (delai.map(|d| temps::ns_monotone().saturating_add(d)), delai.is_some())
}

/// Réveille ceux qui attendent la socket `s`.
fn reveiller(s: &Socket, m: u32) {
    s.attente.reveiller(m, 0);
}

/// Rend sa place à l'émetteur d'un message lu ou jeté (`sock_wfree`), et
/// le réveille s'il attend de la place. Hors de tout verrou : la fille
/// d'un message d'écoute, ou l'émetteur, peuvent être rendus ici. Pour un
/// message déposé seulement (`deposer` a compté sa place) : un message
/// refusé avant est simplement jeté.
fn liberer(mut m: Message) {
    drop(detacher(&mut m));
    if let Some(e) = &m.emetteur {
        unix(e).envoyes.fetch_sub(m.taille, Ordering::Relaxed);
        reveiller(e, POLLOUT | POLLWRNORM | POLLWRBAND);
        // (`unix_write_space` : au quart de SO_SNDBUF, comme `unix_writable`.)
        if unix(e).envoyes.load(Ordering::Relaxed) * 4 <= e.sndbuf.load(Ordering::Relaxed) as usize {
            e.asynchrone.place();
        }
    }
}

// --- Les descripteurs en vol ---

/// Les sockets en vol, en arêtes (`unix_add_edges`), sous ce verrou avec le dépôt du message, et
/// qui se prend avant l'état d'une socket, et le verrou des fichiers.
static GRAPHE: Verrou<Vec<Arete>> = Verrou::new(Vec::new());

/// Les fichiers en vol, sockets ou non (`user->unix_inflight`) : un seul compte, pour tous : tous
/// nos programmes sont le même utilisateur (pile.rs).
static EN_VOL: AtomicUsize = AtomicUsize::new(0);

/// Les numéros des messages de `GRAPHE`, et des octets urgents.
static NUMEROS_DE_MESSAGE: AtomicU64 = AtomicU64::new(1);

/// Le fichier `f` est-il une socket AF_UNIX (`unix_get_socket`) ?
fn socket_du_fichier(f: &FichierTenu) -> Option<&Arc<Socket>> {
    (f.sorte == SorteFichier::Socket && f.socket().protocole == Protocole::Unix).then(|| f.socket())
}

/// Un message quitte sa file avec ses fichiers (`unix_detach_fds`) : ils ne sont plus en vol. Rendus à
/// l'appelant, qui les lâche sans verrou tenu.
fn detacher(m: &mut Message) -> Vec<FichierTenu> {
    if !m.fichiers.is_empty() {
        EN_VOL.fetch_sub(m.fichiers.len(), Ordering::Relaxed);
        if m.vol != 0 {
            let vol = core::mem::take(&mut m.vol);
            GRAPHE.verrouiller().retain(|a| a.message != vol);
        }
    }
    core::mem::take(&mut m.fichiers)
}

/// `too_many_unix_fds` : un utilisateur ne fait pas voler plus de fichiers que RLIMIT_NOFILE (sinon
/// un programme pourrait fermer tous ses descripteurs, en ayant mis ses fichiers en vol,
/// et en ouvrir sans fin).
fn trop_en_vol() -> bool {
    EN_VOL.load(Ordering::Relaxed) as u64 > processus::avec(|p| p.descripteurs.limite.0)
}

/// Le ramasse-miettes (`__unix_gc`) : jette les files des sockets en vol que plus rien ne peut lire
/// (inet::en_vol). Sans verrou tenu. Le graphe et les comptes sont lus ensemble sous `GRAPHE` :
/// sinon, une lecture ferait sortir une socket de la file, en gardant sa référence, entre les deux,
/// et son nouveau descripteur passerait pour un exemplaire encore en vol. Ce qu'il jette ne ferme
/// rien ici : le dernier `close` des sockets qu'il lâche est différé (`socket::fichier_ferme`),
/// et chacun ramassera à son tour. Plus de mémoire pour le parcours : rien, la prochaine
/// fermeture réessaiera.
fn ramasser() {
    let mut jetees: Vec<(Arc<Socket>, VecDeque<Message>)> = Vec::new();
    {
        let graphe = GRAPHE.verrouiller();
        if graphe.is_empty() {
            return;
        }
        let mortes = crate::vfs::avec_systeme(|s, _| en_vol::mortes(&graphe, |f| s.ouverts.references(Fichier::de(f))));
        let Ok(mortes) = mortes else { return };
        for numero in mortes {
            // Une socket en vol a son fichier : elle n'a pas quitté le registre, et ce qui la tient
            // ici n'est pas sa dernière référence : le message la tient encore.
            let Some(s) = par_numero(numero) else { continue };
            let e = unix(&s).etat.verrouiller();
            if !matches!(e.phase, Phase::Ecoute { .. }) {
                drop(e);
                jeter(&mut jetees, s);
                continue;
            }
            // La file d'une écoute apporte ses filles : c'est la leur qu'on jette
            // (`unix_collect_skb`).
            let mut enfants = Vec::new();
            if enfants.ajouter_tout(e.file.iter().filter_map(|m| m.enfant.clone())).is_err() {
                continue;
            }
            drop(e);
            for enfant in enfants {
                jeter(&mut jetees, enfant);
            }
        }
    }
    for (_, file) in jetees {
        for m in file {
            liberer(m);
        }
    }
}

/// La file de `s`, parmi ce qu'on jette ; plus de mémoire : elle reste où elle était, jusqu'à la
/// prochaine fois.
fn jeter(jetees: &mut Vec<(Arc<Socket>, VecDeque<Message>)>, s: Arc<Socket>) {
    if jetees.try_reserve(1).is_ok() {
        let file = core::mem::take(&mut unix(&s).etat.verrouiller().file);
        jetees.ajouter_dans_la_place((s, file));
    }
}

// --- Les connexions ---

/// listen (`unix_listen`) : seulement STREAM et SEQPACKET (EOPNOTSUPP),
/// liées (EINVAL, mesuré), neuves ou qui écoutent déjà (le backlog
/// change) ; ses propres droits posés, que les clients copieront.
pub fn ecouter(s: &Socket, backlog: i32) -> Result<(), i64> {
    let u = unix(s);
    if !u.sorte.connexion() {
        return Err(-EOPNOTSUPP);
    }
    let backlog = if backlog < 0 { SOMAXCONN } else { (backlog as usize).min(SOMAXCONN) };
    {
        let mut e = u.etat.verrouiller();
        if e.nom.is_none() || e.phase == Phase::Connectee {
            return Err(-EINVAL);
        }
        e.phase = Phase::Ecoute { backlog };
        e.droits = Some(droits_courants());
    }
    reveiller(s, POLLOUT | POLLWRNORM);
    Ok(())
}

/// Une socket neuve de la même sorte que `s` (la fille d'une connexion,
/// ou l'autre bout d'une paire) ; inscrite.
fn neuve(s: &Socket, sorte: Sorte) -> Result<Arc<Socket>, i64> {
    let place = crate::partage::ArcVide::new().map_err(|_| -ENOBUFS)?;
    let n = Socket::new(super::socket::Protocole::Unix, sorte.linux(), s.proto, s.uid).unix(sorte).ok_or(-ENOBUFS)?;
    let n = place.remplir(n);
    inscrire(&n)?;
    Ok(n)
}

/// connect d'un flux ou de SEQPACKET (`unix_stream_connect`) : la fille
/// d'abord ; puis l'écoute (une socket qui écoute : sinon ECONNREFUSED ;
/// sa file pleine : attendre, SO_SNDTIMEO, ou EAGAIN) ; la socket doit être
/// neuve (connectée : EISCONN ; qui écoute : EINVAL). La fille est
/// connectée à la socket, prend le nom de l'écoute et les droits du client ;
/// la socket, ceux de l'écoute.
fn connecter_flux(s: &Arc<Socket>, n: &Nom, non_bloquant: bool) -> Result<(), i64> {
    let u = unix(s);
    let (echeance, delai) = echeance(s.appels.verrouiller().options.sndtimeo);
    let enfant = neuve(s, u.sorte)?;
    let r = loop {
        let autre = match chercher(n, u.sorte) {
            Ok(a) => a,
            Err(e) => break Err(e),
        };
        let ua = unix(&autre);
        // L'écoute, et sa file.
        let (ecoute, pleine, nom_ecoute, droits_ecoute, passcred_ecoute, passrights_ecoute) = {
            let e = ua.etat.verrouiller();
            match e.phase {
                Phase::Ecoute { backlog } if !e.morte && e.arret & ARRET_LECTURE == 0 => {
                    (true, e.file.len() > backlog, e.nom, e.droits, e.passcred, e.passrights)
                }
                _ => (false, false, None, None, false, true),
            }
        };
        if !ecoute {
            break Err(-ECONNREFUSED);
        }
        if pleine {
            if non_bloquant || delai && echeance.is_some_and(|e| e <= temps::ns_monotone()) {
                break Err(-EAGAIN);
            }
            let attendu = attendre(&autre.attente, echeance, delai, || {
                let e = ua.etat.verrouiller();
                e.morte || !matches!(e.phase, Phase::Ecoute { backlog } if e.file.len() > backlog)
            });
            if let Err(e) = attendu {
                break Err(e);
            }
            continue;
        }
        // La socket elle-même.
        {
            let mut e = u.etat.verrouiller();
            match e.phase {
                Phase::Neuve => {}
                Phase::Connectee => break Err(-EISCONN),
                Phase::Ecoute { .. } => break Err(-EINVAL),
            }
            e.phase = Phase::Connectee;
            e.pair = Some(enfant.clone());
            e.droits = droits_ecoute;
        }
        {
            let mut e = unix(&enfant).etat.verrouiller();
            e.phase = Phase::Connectee;
            e.pair = Some(s.clone());
            e.nom = nom_ecoute.map(|n| Nom { inode: None, ..n });
            e.droits = Some(droits_courants());
            // Les drapeaux de réception de l'écoute (SO_PASSCRED :
            // `sk_scm_recv_flags`).
            e.passcred = passcred_ecoute;
            e.passrights = passrights_ecoute;
            e.ecoute = Some(autre.numero);
        }
        // Le message qui apporte la fille à l'écoute.
        let mut ea = ua.etat.verrouiller();
        let deposee = !ea.morte && ea.file.ajouter_derriere(Message { regarde: false, octets: Vec::new(), lus: 0, taille: 0, emetteur: None, fichiers: Vec::new(), vol: 0, droits: None, numero_oob: 0, enfant: Some(enfant.clone()) }).is_ok();
        drop(ea);
        if !deposee {
            // L'écoute vient de fermer, ou plus de mémoire : défaire, des deux
            // côtés (la fille fermée ensuite ne doit plus voir de pair : elle
            // arrêterait la socket, qui doit rester réutilisable).
            let mut e = u.etat.verrouiller();
            e.phase = Phase::Neuve;
            let p = e.pair.take();
            e.droits = None;
            drop(e);
            drop(p);
            let q = unix(&enfant).etat.verrouiller().pair.take();
            drop(q);
            break Err(-ECONNREFUSED);
        }
        reveiller(&autre, POLLIN | POLLRDNORM);
        autre.asynchrone.lecture(Raison::Entree);
        break Ok(());
    };
    if r.is_err() {
        fermer_avec(&enfant, false);
    }
    r
}

/// connect d'un DGRAM (`unix_dgram_connect`) : AF_UNSPEC défait la
/// connexion ; sinon le pair désigné (une socket connectée à une autre :
/// EPERM).
fn connecter_datagrammes(s: &Arc<Socket>, o: &[u8]) -> Result<(), i64> {
    let u = unix(s);
    let autre = if o.len() >= 2 && u16::from_le_bytes([o[0], o[1]]) == 0 {
        None
    } else {
        let n = lire_nom(o)?;
        if u.etat.verrouiller().passcred {
            autonommer(s)?;
        }
        let a = chercher(&n, u.sorte)?;
        let peut = {
            let ea = unix(&a).etat.verrouiller();
            ea.pair.as_ref().is_none_or(|p| Arc::ptr_eq(p, s))
        };
        if !peut {
            return Err(-EPERM);
        }
        Some(a)
    };
    let ancien = {
        let mut e = u.etat.verrouiller();
        e.phase = if autre.is_some() { Phase::Connectee } else { Phase::Neuve };
        core::mem::replace(&mut e.pair, autre)
    };
    // L'ancien pair ne nous concerne plus (`unix_dgram_peer_wake_disconnect_wakeup`) : qui attend de
    // pouvoir écrire revoit où il en est.
    if let Some(ancien) = ancien {
        u.relais.retirer();
        reveiller(s, POLLOUT | POLLWRNORM | POLLWRBAND);
        let meme = u.etat.verrouiller().pair.as_ref().is_some_and(|p| Arc::ptr_eq(p, &ancien));
        if !meme {
            dgram_deconnectee(s, &ancien);
        }
    }
    Ok(())
}

/// Un DGRAM a quitté son pair (`unix_dgram_disconnected`) : sa file est jetée (il ne doit recevoir
/// que de son pair, et la place ne se compte plus que chez l'émetteur) ; si l'ancien pair était
/// connecté à lui, ses messages sont perdus : il l'apprend : ECONNRESET. Une file vide : rien.
fn dgram_deconnectee(s: &Arc<Socket>, ancien: &Arc<Socket>) {
    let u = unix(s);
    let file = core::mem::take(&mut u.etat.verrouiller().file);
    if file.is_empty() {
        return;
    }
    for m in file {
        liberer(m);
    }
    u.attente_pairs.reveiller(POLLOUT | POLLWRNORM | POLLWRBAND, 0);
    let touche = {
        let mut e = unix(ancien).etat.verrouiller();
        let touche = !e.morte && e.pair.as_ref().is_some_and(|p| Arc::ptr_eq(p, s));
        if touche {
            e.erreur = ECONNRESET as i32;
        }
        touche
    };
    if touche {
        reveiller(ancien, POLLERR);
        ancien.asynchrone.evenement(Raison::Erreur);
    }
}

/// connect.
pub fn connecter(s: &Arc<Socket>, o: &[u8], non_bloquant: bool) -> Result<(), i64> {
    let u = unix(s);
    if u.sorte == Sorte::Datagrammes {
        return connecter_datagrammes(s, o);
    }
    let n = lire_nom(o)?;
    if u.etat.verrouiller().passcred {
        autonommer(s)?;
    }
    connecter_flux(s, &n, non_bloquant)
}

/// accept (`unix_accept`) : une écoute (EINVAL ; un DGRAM : EOPNOTSUPP) ;
/// la première fille de sa file, en attendant (SO_RCVTIMEO) ou EAGAIN.
pub fn accepter(s: &Socket, non_bloquant: bool) -> Result<Arc<Socket>, i64> {
    let u = unix(s);
    if !u.sorte.connexion() {
        return Err(-EOPNOTSUPP);
    }
    let (echeance, delai) = echeance(s.appels.verrouiller().options.rcvtimeo);
    loop {
        let m = {
            let mut e = u.etat.verrouiller();
            if !matches!(e.phase, Phase::Ecoute { .. }) {
                return Err(-EINVAL);
            }
            e.file.pop_front()
        };
        if let Some(mut m) = m {
            // Une place de plus dans l'écoute.
            reveiller(s, POLLOUT | POLLWRNORM);
            let enfant = m.enfant.take().ok_or(-EINVAL)?;
            // Elle a maintenant son fichier : plus la peine de passer par l'écoute
            // (`unix_update_edges`).
            let numero = enfant.numero;
            let mut graphe = GRAPHE.verrouiller();
            unix(&enfant).etat.verrouiller().ecoute = None;
            for a in graphe.iter_mut().filter(|a| a.receveuse == numero) {
                a.ecoute = None;
            }
            drop(graphe);
            return Ok(enfant);
        }
        if non_bloquant {
            return Err(-EAGAIN);
        }
        // `shutdown` sur l'écoute : la façon ordinaire d'arrêter un fil d'accept : EINVAL (« This
        // means receive shutdown »).
        if u.etat.verrouiller().arret & ARRET_LECTURE != 0 {
            return Err(-EINVAL);
        }
        attendre(&s.attente, echeance, delai, || {
            let e = u.etat.verrouiller();
            !e.file.is_empty() || !matches!(e.phase, Phase::Ecoute { .. }) || e.arret & ARRET_LECTURE != 0
        })?;
    }
}

/// socketpair (`unix_socketpair`) : deux sockets neuves, connectées l'une à
/// l'autre, avec les droits du processus.
pub fn paire(s: &Arc<Socket>) -> Result<Arc<Socket>, i64> {
    let u = unix(s);
    let autre = neuve(s, u.sorte)?;
    let droits = droits_courants();
    for (a, b) in [(s, &autre), (&autre, s)] {
        let mut e = unix(a).etat.verrouiller();
        e.phase = Phase::Connectee;
        e.pair = Some(b.clone());
        e.droits = Some(droits);
    }
    Ok(autre)
}

// --- L'envoi ---

/// Envoie `longueur` octets remplis par `remplir`, à `destination` (un DGRAM
/// non connecté), avec `drapeaux` (MSG_DONTWAIT). Rend ce qui a été envoyé.
pub fn envoyer(s: &Arc<Socket>, destination: Option<&[u8]>, longueur: usize, drapeaux: u64, scm: Scm,
               remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    // `wait_for_unix_gc`.
    if !scm.fichiers.is_empty() && GRAPHE.verrouiller().len() > EN_VOL_TROP {
        ramasser();
    }
    if !scm.fichiers.is_empty() && trop_en_vol() {
        return Err(-ETOOMANYREFS);
    }
    match unix(s).sorte {
        Sorte::Flux => envoyer_flux(s, destination, longueur, drapeaux, scm, remplir),
        // Seul un flux a un octet urgent (`unix_dgram_sendmsg`).
        _ if drapeaux & MSG_OOB != 0 => Err(-EOPNOTSUPP),
        _ => envoyer_message(s, destination, longueur, drapeaux, scm, remplir),
    }
}

/// Attend que l'émetteur ait de la place (`sock_alloc_send_pskb`, dans son ordre) : une erreur en
/// attente, prise, et rendue telle quelle ; l'écriture arrêtée : EPIPE ; moins que SO_SNDBUF en
/// route : la place ; MSG_DONTWAIT : EAGAIN ; sinon attendre, et revoir tout cela.
fn attendre_place(s: &Socket, non_bloquant: bool, echeance: Option<u64>, delai: bool) -> Result<(), i64> {
    let u = unix(s);
    let sndbuf = || s.sndbuf.load(Ordering::Relaxed) as usize;
    let place = || u.envoyes.load(Ordering::Relaxed) < sndbuf();
    loop {
        {
            let mut e = u.etat.verrouiller();
            let erreur = core::mem::take(&mut e.erreur);
            if erreur != 0 {
                return Err(-(erreur as i64));
            }
            if e.arret & ARRET_ECRITURE != 0 {
                return Err(-EPIPE);
            }
        }
        if place() {
            return Ok(());
        }
        // (`sock_alloc_send_pskb` : SOCKWQ_ASYNC_NOSPACE.) La place revue
        // derrière le drapeau (asynchrone.rs).
        s.asynchrone.marquer_sans_place(|| !place());
        if non_bloquant {
            return Err(-EAGAIN);
        }
        attendre(&s.attente, echeance, delai, || {
            let e = u.etat.verrouiller();
            place() || e.arret & ARRET_ECRITURE != 0 || e.erreur != 0
        })?;
    }
}

/// Un message de `n` octets, rempli par `remplir` à partir de l'octet
/// `decalage` de l'envoi. ENOBUFS : plus de mémoire.
fn message(s: &Arc<Socket>, n: usize, decalage: usize, remplir: &mut impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<Message, i64> {
    let mut octets = faillible::remplie(n, 0u8).map_err(|_| -ENOBUFS)?;
    remplir(decalage, &mut octets)?;
    Ok(Message { regarde: false, octets, lus: 0, taille: taille_vraie(unix(s).sorte, n), emetteur: Some(s.clone()), enfant: None, fichiers: Vec::new(), vol: 0, droits: None, numero_oob: 0 })
}

/// Met le message `m` dans la file de `autre` et compte sa place chez
/// l'émetteur ; `autre` fermée, ou sa lecture arrêtée : rend le message
/// (Err, avec EPIPE) ; elle refuse les descripteurs qu'il porte (SO_PASSRIGHTS) : EPERM ; plus de
/// mémoire pour leurs arêtes (`unix_prepare_fpl`) : ENOMEM.
fn deposer(autre: &Socket, mut m: Message) -> Result<(), (Message, i64)> {
    // Les droits, si l'une des deux sockets les demande (`unix_maybe_add_creds`) : lus avant de
    // prendre le verrou de la receveuse : ni deux sockets, ni le processus, sous lui.
    let (moi, passcred) = match &m.emetteur {
        Some(e) if m.droits.is_none() => (Some(droits_courants()), unix(e).etat.verrouiller().passcred),
        _ => (None, false),
    };
    // Comptée d'abord : le destinataire peut la lire, et la rendre, dès
    // que le verrou est lâché.
    let compter = |m: &Message, plus: bool| {
        if let Some(e) = &m.emetteur {
            let envoyes = &unix(e).envoyes;
            if plus {
                envoyes.fetch_add(m.taille, Ordering::Relaxed);
            } else {
                envoyes.fetch_sub(m.taille, Ordering::Relaxed);
            }
        }
    };
    compter(&m, true);
    let mut urgent = false;
    {
        let en_vol = m.fichiers.iter().filter(|f| socket_du_fichier(f).is_some()).count();
        let mut graphe = (en_vol > 0).then(|| GRAPHE.verrouiller());
        if let Some(g) = &mut graphe
            && g.try_reserve(en_vol).is_err()
        {
            drop(graphe);
            compter(&m, false);
            return Err((m, -ENOMEM));
        }
        let mut e = unix(autre).etat.verrouiller();
        let refus = if e.morte || e.arret & ARRET_LECTURE != 0 || e.file.try_reserve(1).is_err() {
            Some(-EPIPE)
        } else if !m.fichiers.is_empty() && !e.passrights {
            Some(-EPERM)
        } else {
            None
        };
        if let Some(errno) = refus {
            drop(e);
            drop(graphe);
            compter(&m, false);
            return Err((m, errno));
        }
        if passcred || e.passcred || e.ecoute.is_some() {
            m.droits = m.droits.or(moi);
        }
        if m.numero_oob != 0 {
            e.oob = m.numero_oob;
            urgent = true;
        }
        EN_VOL.fetch_add(m.fichiers.len(), Ordering::Relaxed);
        if let Some(g) = &mut graphe {
            m.vol = NUMEROS_DE_MESSAGE.fetch_add(1, Ordering::Relaxed);
            for s in m.fichiers.iter().filter_map(|f| socket_du_fichier(f).map(|s| (s.numero, f.fichier().numero()))) {
                g.ajouter_dans_la_place(Arete { message: m.vol, envolee: s.0, fichier: s.1, receveuse: autre.numero, ecoute: e.ecoute });
            }
        }
        e.file.ajouter_derriere_dans_la_place(m);
    }
    // Tout ce que dit `sock_def_readable`, POLLPRI compris : un epoll sur l'octet urgent seul.
    // L'octet urgent passe par SIGURG d'abord (`queue_oob` : `sk_send_sigurg`).
    if urgent {
        autre.asynchrone.urgent();
    }
    reveiller(autre, POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND);
    autre.asynchrone.lecture(Raison::Entree);
    Ok(())
}

/// SIGPIPE, où Linux va à `out_pipe` : à l'entrée, ou le pair mort ou qui ne lit plus, et rien
/// d'envoyé. Pas sur ce qui attendait de la place : ni l'erreur qu'on y prend, ni l'arrêt qu'on y voit.
fn signaler_tube(drapeaux: u64) {
    const MSG_NOSIGNAL: u64 = 0x4000;
    if drapeaux & MSG_NOSIGNAL == 0 {
        crate::signaux::au_fil_courant(13);
    }
}

/// Un flux (`unix_stream_sendmsg`) : une adresse donnée : EISCONN connecté,
/// EOPNOTSUPP sinon ; sans pair : ENOTCONN ; l'écriture arrêtée, ou le pair
/// fermé ou qui ne lit plus : EPIPE ; des messages d'au plus la moitié de
/// SO_SNDBUF, chacun quand il y a la place. Rend ce qui a été envoyé, ou
/// l'erreur si rien ne l'a été.
fn envoyer_flux(s: &Arc<Socket>, destination: Option<&[u8]>, longueur: usize, drapeaux: u64, scm: Scm,
                mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_DONTWAIT: u64 = 0x40;
    const MSG_OOB: u64 = 1;
    let oob = drapeaux & MSG_OOB != 0;
    if oob && longueur == 0 {
        return Err(-EOPNOTSUPP);
    }
    let Scm { mut fichiers, droits } = scm;
    let u = unix(s);
    let (pair, arret, phase) = {
        let e = u.etat.verrouiller();
        (e.pair.clone(), e.arret, e.phase)
    };
    if destination.is_some_and(|d| !d.is_empty()) {
        return Err(if phase == Phase::Connectee { -EISCONN } else { -EOPNOTSUPP });
    }
    let pair = pair.ok_or(-ENOTCONN)?;
    if arret & ARRET_ECRITURE != 0 {
        signaler_tube(drapeaux);
        return Err(-EPIPE);
    }
    let (echeance, delai) = echeance(s.appels.verrouiller().options.sndtimeo);
    let mut fait = 0;
    // Le dernier octet d'un envoi urgent part à part (`queue_oob`).
    let ordinaires = longueur - usize::from(oob);
    while fait < longueur {
        if let Err(e) = attendre_place(s, drapeaux & MSG_DONTWAIT != 0, echeance, delai) {
            return if fait > 0 { Ok(fait) } else { Err(e) };
        }
        let urgent = fait == ordinaires;
        let n = if urgent { 1 } else { (ordinaires - fait).min((s.sndbuf.load(Ordering::Relaxed) as usize / 2).saturating_sub(64).max(1)).min(MESSAGE_MAX) };
        let mut m = match message(s, n, fait, &mut remplir) {
            Ok(m) => m,
            Err(e) => return if fait > 0 { Ok(fait) } else { Err(e) },
        };
        // Les descripteurs : avec le premier message seulement ; sans octet, il n'y en a pas, et ils
        // sont perdus (`unix_stream_sendmsg`).
        m.fichiers = core::mem::take(&mut fichiers);
        m.droits = droits;
        if urgent {
            m.numero_oob = NUMEROS_DE_MESSAGE.fetch_add(1, Ordering::Relaxed);
        }
        if let Err((m, errno)) = deposer(&pair, m) {
            drop(m);
            if fait > 0 {
                return Ok(fait);
            }
            // L'octet urgent n'envoie pas le signal (`queue_oob` : `out_err`).
            if errno == -EPIPE && !urgent {
                signaler_tube(drapeaux);
            }
            return Err(errno);
        }
        fait += n;
    }
    Ok(fait)
}

/// Un DGRAM ou un SEQPACKET (`unix_dgram_sendmsg`) : plus que SO_SNDBUF
/// moins 32 : EMSGSIZE ; la place chez l'émetteur ; le destinataire (son
/// nom, ou le pair ; SEQPACKET : le pair seul, ENOTCONN sans) ; il en a un
/// autre que nous : EPERM ; fermé : ECONNREFUSED (ou EPIPE pour SEQPACKET) ;
/// sa file pleine (un DGRAM qui n'est pas son pair) : attendre, ou EAGAIN.
fn envoyer_message(s: &Arc<Socket>, destination: Option<&[u8]>, longueur: usize, drapeaux: u64, scm: Scm,
                   mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_DONTWAIT: u64 = 0x40;
    let u = unix(s);
    let non_bloquant = drapeaux & MSG_DONTWAIT != 0;
    let paquets = u.sorte == Sorte::Paquets;
    let (pair, phase, passcred, erreur) = {
        let mut e = u.etat.verrouiller();
        // SEQPACKET : l'erreur en attente d'abord (`unix_seqpacket_sendmsg` :
        // `sock_error`), ECONNRESET d'un pair fermé sans tout lire.
        let erreur = if paquets { core::mem::take(&mut e.erreur) } else { 0 };
        (e.pair.clone(), e.phase, e.passcred, erreur)
    };
    if erreur != 0 {
        return Err(-(erreur as i64));
    }
    if paquets && phase != Phase::Connectee {
        return Err(-ENOTCONN);
    }
    let destination = if paquets { None } else { destination.filter(|d| !d.is_empty()) };
    let nom = destination.map(lire_nom).transpose()?;
    if passcred {
        autonommer(s)?;
    }
    if longueur > (s.sndbuf.load(Ordering::Relaxed) as usize).saturating_sub(32) {
        return Err(-EMSGSIZE);
    }
    let (echeance, delai) = echeance(s.appels.verrouiller().options.sndtimeo);
    attendre_place(s, non_bloquant, echeance, delai)?;
    let autre = match &nom {
        Some(n) => chercher(n, u.sorte)?,
        None => pair.clone().ok_or(-ENOTCONN)?,
    };
    let mut m = message(s, longueur, 0, &mut remplir)?;
    m.fichiers = scm.fichiers;
    m.droits = scm.droits;
    loop {
        let ua = unix(&autre);
        let (morte, son_pair_ok, pleine) = {
            let ea = ua.etat.verrouiller();
            let son_pair = ea.pair.as_ref().map(|p| Arc::ptr_eq(p, s));
            (ea.morte, son_pair, ea.file.len() > DGRAM_QLEN)
        };
        if son_pair_ok == Some(false) {
            drop(m);
            return Err(-EPERM);
        }
        if morte {
            drop(m);
            if paquets {
                return Err(-EPIPE);
            }
            // Le pair connecté est mort : la connexion est défaite.
            let ancien = {
                let mut e = u.etat.verrouiller();
                if e.pair.as_ref().is_some_and(|p| Arc::ptr_eq(p, &autre)) {
                    e.phase = Phase::Neuve;
                    e.pair.take()
                } else {
                    None
                }
            };
            if let Some(ancien) = ancien {
                u.relais.retirer();
                reveiller(s, POLLOUT | POLLWRNORM | POLLWRBAND);
                dgram_deconnectee(s, &ancien);
            }
            return Err(-ECONNREFUSED);
        }
        // Une file pleine n'arrête qu'un DGRAM qui n'est pas son pair.
        if pleine && !Arc::ptr_eq(&autre, s) && son_pair_ok != Some(true) {
            if non_bloquant || delai && echeance.is_some_and(|e| e <= temps::ns_monotone()) {
                drop(m);
                return Err(-EAGAIN);
            }
            if let Err(e) = attendre(&autre.attente, echeance, delai, || {
                let ea = ua.etat.verrouiller();
                ea.morte || ea.file.len() <= DGRAM_QLEN
            }) {
                drop(m);
                return Err(e);
            }
            continue;
        }
        match deposer(&autre, m) {
            Ok(()) => return Ok(longueur),
            Err((r, errno)) => {
                m = r;
                if errno != -EPIPE {
                    drop(m);
                    return Err(errno);
                }
                let lecture_arretee = ua.etat.verrouiller().arret & ARRET_LECTURE != 0;
                drop(m);
                return Err(if lecture_arretee { -EPIPE } else { -ENOBUFS });
            }
        }
    }
}

// --- La réception ---

/// Ce qu'une réception a rendu : la longueur, l'adresse de l'émetteur (un
/// DGRAM), si le message a été coupé (MSG_TRUNC).
pub struct Recu {
    pub longueur: usize,
    pub adresse: Option<Nom>,
    pub coupe: bool,
    /// Les descripteurs qui arrivent (`scm.fp`), à installer, ou à lâcher.
    pub fichiers: Vec<FichierTenu>,
    /// Les droits de ce qui a été lu, et s'il y a de quoi les dire : pas à la fin d'un SEQPACKET.
    pub droits: Droits,
    pub scm: bool,
    /// C'était l'octet urgent (MSG_OOB dans `msg_flags`).
    pub urgent: bool,
}

/// Reçoit au plus `longueur` octets par `copier` (`decalage`, octets) avec
/// `drapeaux` (MSG_OOB, MSG_PEEK, MSG_DONTWAIT, MSG_WAITALL, MSG_TRUNC).
pub fn recevoir(s: &Socket, longueur: usize, drapeaux: u64, non_bloquant: bool,
                copier: impl FnMut(usize, &[u8]) -> Result<usize, i64>) -> Result<Recu, i64> {
    const MSG_OOB: u64 = 1;
    const MSG_DONTWAIT: u64 = 0x40;
    let u = unix(s);
    if drapeaux & MSG_OOB != 0 && u.sorte != Sorte::Flux {
        return Err(-EOPNOTSUPP);
    }
    let (delai, rcvlowat) = {
        let i = s.appels.verrouiller();
        (i.options.rcvtimeo, i.options.rcvlowat as usize)
    };
    let non_bloquant = non_bloquant || drapeaux & MSG_DONTWAIT != 0 || delai == Some(0);
    let (echeance, delai) = echeance(delai);
    let mut a = Attente { lecteur: Some(u.lecteurs.verrouiller()), lecteurs: &u.lecteurs, non_bloquant, echeance, delai };
    match u.sorte {
        Sorte::Flux if drapeaux & MSG_OOB != 0 => recevoir_urgent(s, longueur, drapeaux, copier),
        Sorte::Flux => recevoir_flux(s, longueur, drapeaux, rcvlowat, &mut a, copier),
        _ => recevoir_message(s, longueur, drapeaux, &mut a, copier),
    }
}

/// SO_PEEK_OFF (`unix_set_peek_off`) : pas pendant une lecture.
pub fn poser_peek_off(s: &Socket, valeur: i32) {
    let _lecteur = unix(s).lecteurs.verrouiller();
    s.peek_off.store(valeur, Ordering::Relaxed);
}

/// Comment une réception attend : sans attendre, ou jusqu'à son échéance ;
/// le `iolock` qu'elle tient, rendu pendant l'attente (`unix_stream_data_wait`
/// et `__skb_wait_for_more_packets` sont appelés sans lui), repris ensuite.
struct Attente<'a> {
    lecteur: Option<GardeMutex<'a, ()>>,
    lecteurs: &'a Mutex<()>,
    non_bloquant: bool,
    echeance: Option<u64>,
    delai: bool,
}

/// Rien à lire : l'erreur en attente (prise), la lecture arrêtée (0, None),
/// EAGAIN sans attendre, ou attendre (le `iolock` rendu pendant ce temps) ;
/// Some(()) : il y a peut-être de quoi lire. Un flux regarde l'arrêt avant
/// de ne pas attendre (`unix_stream_read_generic` : 0) ; un DGRAM ou un
/// SEQPACKET non bloquant rend EAGAIN d'abord, il ne regarde l'arrêt qu'en
/// attendant (`__skb_wait_for_more_packets`). `deja` : les messages que le décalage de MSG_PEEK a
/// passés : il en faut un de plus.
fn rien_a_lire(s: &Socket, a: &mut Attente, non_bloquant: bool, deja: usize) -> Result<Option<()>, i64> {
    let u = unix(s);
    {
        let mut e = u.etat.verrouiller();
        if e.file.len() > deja {
            return Ok(Some(()));
        }
        let erreur = core::mem::take(&mut e.erreur);
        if erreur != 0 {
            return Err(-(erreur as i64));
        }
        if e.arret & ARRET_LECTURE != 0 && (u.sorte == Sorte::Flux || !non_bloquant) {
            return Ok(None);
        }
    }
    if non_bloquant {
        return Err(-EAGAIN);
    }
    drop(a.lecteur.take());
    // (`unix_stream_data_wait` : SOCKWQ_ASYNC_WAITDATA ; un DGRAM n'y passe pas.)
    let flux = u.sorte == Sorte::Flux;
    if flux {
        s.asynchrone.attendre_donnees(true);
    }
    let attendu = attendre(&s.attente, a.echeance, a.delai, || {
        let e = u.etat.verrouiller();
        e.file.len() > deja || e.erreur != 0 || e.arret & ARRET_LECTURE != 0
    });
    if flux {
        s.asynchrone.attendre_donnees(false);
    }
    a.lecteur = Some(a.lecteurs.verrouiller());
    attendu?;
    Ok(Some(()))
}

/// L'octet urgent (`unix_stream_recv_urg`) : SO_OOBINLINE, ou aucun : EINVAL. Rend 1 même sans
/// place pour lui (mesuré : `recv(s, o, 0, MSG_OOB)`, 1, et il est perdu). Sans MSG_PEEK, il reste
/// en file, vide : une marque ; celle d'avant, s'il y en avait une juste devant, s'en va.
fn recevoir_urgent(s: &Socket, place: usize, drapeaux: u64, mut copier: impl FnMut(usize, &[u8]) -> Result<usize, i64>) -> Result<Recu, i64> {
    const MSG_PEEK: u64 = 2;
    let u = unix(s);
    let en_ligne = s.appels.verrouiller().options.oobinline;
    let (octet, jete) = {
        let mut e = u.etat.verrouiller();
        if e.phase != Phase::Connectee || en_ligne || e.oob == 0 {
            return Err(-EINVAL);
        }
        let oob = e.oob;
        let k = e.file.iter().position(|m| m.numero_oob == oob).ok_or(-EINVAL)?;
        let octet = e.file[k].restant().first().copied().ok_or(-EINVAL)?;
        let mut jete = None;
        if drapeaux & MSG_PEEK == 0 {
            e.oob = 0;
            e.file[k].lus += 1;
            if k > 0 && e.file[k - 1].restant().is_empty() {
                jete = e.file.remove(k - 1);
            }
        }
        (octet, jete)
    };
    // Sans place, rien à copier, donc pas de faute (le `short_copy` de `skb_copy_datagram_iter`).
    let r = if place > 0 { copier(0, &[octet]) } else { Ok(0) };
    if let Some(m) = jete {
        liberer(m);
    }
    r.map_err(|_| -EFAULT)?;
    Ok(Recu { longueur: 1, adresse: None, coupe: false, fichiers: Vec::new(), droits: SANS_DROITS, scm: false, urgent: true })
}

/// Le message suivant d'un flux, compte tenu de l'octet urgent (`manage_oob`). None : plus rien, ou
/// une marque qui arrête la lecture (`copie` : déjà des octets de lus). Ce qu'on saute : `vus`
/// pour MSG_PEEK (sa place est prise), `jetes` sinon, à lâcher hors du verrou.
fn prochain_du_flux(e: &mut Etat, regarder: bool, en_ligne: bool, copie: bool, vus: &mut VecDeque<Message>, jetes: &mut [Option<Message>; 2]) -> Option<Message> {
    let oob = e.oob;
    let est_oob = move |m: &Message| m.numero_oob != 0 && m.numero_oob == oob;
    let tete = e.file.front()?;
    if !tete.restant().is_empty() && !est_oob(tete) {
        return e.file.pop_front();
    }
    if tete.restant().is_empty() {
        if copie && (oob == 0 || est_oob(tete)) {
            return None;
        }
        let marque = e.file.pop_front()?;
        if regarder {
            vus.ajouter_derriere_dans_la_place(marque);
        } else {
            jetes[0] = Some(marque);
        }
    }
    let tete = e.file.front()?;
    if !est_oob(tete) {
        return e.file.pop_front();
    }
    if copie {
        return None;
    }
    if !regarder {
        e.oob = 0;
        if !en_ligne {
            jetes[1] = e.file.pop_front();
        }
        return e.file.pop_front();
    }
    if !en_ligne {
        let saute = e.file.pop_front()?;
        vus.ajouter_derriere_dans_la_place(saute);
    }
    e.file.pop_front()
}

/// Un flux (`unix_stream_read_generic`) : pas connectée : EINVAL (mesuré) ;
/// les messages à la suite, jusqu'à `longueur` (MSG_WAITALL : en attendant
/// le reste ; sinon SO_RCVLOWAT, 1 par défaut : `sock_rcvlowat`) ; un
/// message lu en partie garde le reste, et la lecture s'arrête là ;
/// MSG_PEEK laisse tout. L'adresse : celle de l'émetteur du premier message
/// lu (`unix_copy_addr`), le nom de l'écoute pour un client.
fn recevoir_flux(s: &Socket, longueur: usize, drapeaux: u64, rcvlowat: usize, a: &mut Attente,
                 mut copier: impl FnMut(usize, &[u8]) -> Result<usize, i64>) -> Result<Recu, i64> {
    const MSG_PEEK: u64 = 2;
    const MSG_WAITALL: u64 = 0x100;
    let u = unix(s);
    if u.etat.verrouiller().phase != Phase::Connectee {
        return Err(-EINVAL);
    }
    let regarder = drapeaux & MSG_PEEK != 0;
    // Au moins 1, même pour une longueur nulle (`sock_rcvlowat` : `v ?: 1`) : elle attend aussi.
    let cible = (if drapeaux & MSG_WAITALL != 0 { longueur } else { rcvlowat.min(longueur) }).max(1);
    let en_ligne = s.appels.verrouiller().options.oobinline;
    let mut adresse = None;
    let mut fait = 0;
    let mut fichiers = Vec::new();
    // Les droits de la lecture : aucun avant le premier message (à la fin du flux, mesuré : tout à
    // zéro), puis ceux du premier, s'ils sont demandés ; et on ne colle pas ceux d'un autre.
    let mut droits = Droits { pid: 0, uid: 0, gid: 0 };
    let mut droits_vus = false;
    // MSG_PEEK : les messages déjà regardés, remis en tête à la fin ; et ce que SO_PEEK_OFF veut
    // qu'on passe, sans le copier (`skip`).
    let mut vus: VecDeque<Message> = VecDeque::new();
    let mut saut = if regarder { s.decalage_de_peek() } else { 0 };
    let r = loop {
        // MSG_PEEK ne s'arrête pas là : il va jusqu'au prochain message qui porte des descripteurs,
        // pour les donner (`goto again`, sans regarder ce qu'il reste de place).
        if !regarder && fait >= longueur && longueur > 0 {
            break Ok(());
        }
        // Pour MSG_PEEK : la place de ce qu'on saute, et de ce message.
        if regarder && vus.try_reserve(3).is_err() {
            break Ok(());
        }
        let mut jetes = [None, None];
        let (m, avait, passcred) = {
            let mut e = u.etat.verrouiller();
            let avait = !e.file.is_empty();
            (prochain_du_flux(&mut e, regarder, en_ligne, fait > 0, &mut vus, &mut jetes), avait, e.passcred)
        };
        for j in jetes.into_iter().flatten() {
            liberer(j);
        }
        let Some(mut m) = m else {
            // Arrêtée par la marque, quoi qu'attende la lecture.
            if avait && fait > 0 {
                break Ok(());
            }
            if fait >= cible {
                break Ok(());
            }
            // Pendant l'attente, l'iolock est rendu : ce qu'a sauté MSG_PEEK (la marque, un urgent) ne
            // peut pas rester entre nos mains.
            while let Some(v) = vus.pop_back() {
                remettre(s, v);
            }
            let deja = u.etat.verrouiller().file.len();
            match rien_a_lire(s, a, a.non_bloquant, if regarder { deja } else { 0 }) {
                Ok(Some(())) => {
                    // De retour à la tête : le décalage aussi (ce qui a été copié en est déjà compté).
                    saut = if regarder { s.decalage_de_peek() } else { 0 };
                    continue;
                }
                Ok(None) => break Ok(()),
                Err(e) => break if fait > 0 { Ok(()) } else { Err(e) },
            }
        };
        // Passé en entier, sans y regarder de plus près (`while (skip >= unix_skb_len(skb))`).
        if saut >= m.restant().len() && regarder {
            saut -= m.restant().len();
            vus.ajouter_derriere_dans_la_place(m);
            continue;
        }
        if droits_vus {
            if m.droits.unwrap_or(SANS_DROITS) != droits {
                remettre(s, m);
                break Ok(());
            }
        } else if passcred {
            droits = m.droits.unwrap_or(SANS_DROITS);
            droits_vus = true;
        }
        if adresse.is_none() {
            adresse = Some(m.emetteur.as_ref().and_then(|e| unix(e).etat.verrouiller().nom));
        }
        let n = (m.restant().len() - saut).min(longueur - fait);
        let c = match copier(fait, &m.restant()[saut..][..n]) {
            Ok(c) => c,
            Err(e) => {
                remettre(s, m);
                break if fait > 0 { Ok(()) } else { Err(e) };
            }
        };
        fait += c;
        if regarder {
            saut = 0;
            s.peek_avance(c);
            // Regardé : des copies de ses descripteurs (`unix_peek_fds`), et on s'arrête sur lui.
            let porte = !m.fichiers.is_empty();
            fichiers = copies(&m.fichiers);
            vus.ajouter_derriere_dans_la_place(m);
            if porte {
                break Ok(());
            }
            continue;
        }
        m.lus += c;
        s.peek_recule(c);
        // Ses descripteurs, au premier octet lu, et la lecture ne va pas plus loin que lui.
        let porte = !m.fichiers.is_empty();
        if porte {
            fichiers = detacher(&mut m);
        }
        if !m.restant().is_empty() {
            remettre(s, m);
            break Ok(());
        }
        liberer(m);
        if porte {
            break Ok(());
        }
    };
    while let Some(m) = vus.pop_back() {
        remettre(s, m);
    }
    r.map(|()| Recu { longueur: fait, adresse: adresse.flatten(), coupe: false, fichiers, droits, scm: true, urgent: false })
}

/// Des copies de ses descripteurs (`scm_fp_dup`) ; plus de mémoire : aucune, comme lui.
fn copies(fichiers: &[FichierTenu]) -> Vec<FichierTenu> {
    let mut v = Vec::new();
    if v.ajouter_tout(fichiers.iter().map(FichierTenu::dupliquer)).is_err() {
        return Vec::new();
    }
    v
}

/// Remet un message en tête de la file (sorti pour être copié, et pas tout
/// lu). La place, qu'il vient de quitter, y est encore. Et un `poll` d'un autre fil a pu voir
/// la file vide pendant ce temps, et s'endormir : réveillé (écart : chez Linux, le paquet reste en
/// file pendant sa copie ; ici, une copie peut fauter et dormir, et les octets du message ne se
/// prêtent pas hors de son verrou).
fn remettre(s: &Socket, m: Message) {
    remettre_a(s, 0, m);
}

/// De même, à sa place dans la file (SO_PEEK_OFF regarde plus loin que la tête).
fn remettre_a(s: &Socket, place: usize, m: Message) {
    let mut e = unix(s).etat.verrouiller();
    if e.file.try_reserve(1).is_ok() {
        let place = place.min(e.file.len());
        e.file.inserer_dans_la_place(place, m);
        drop(e);
        reveiller(s, POLLIN | POLLRDNORM);
    } else {
        drop(e);
        liberer(m);
    }
}

/// Un DGRAM ou un SEQPACKET (`__unix_dgram_recvmsg`) : un message par
/// lecture, coupé à `longueur` (MSG_TRUNC le dit, et fait rendre sa vraie
/// longueur) ; l'adresse de l'émetteur (vide s'il n'a pas de nom). Un
/// SEQPACKET qui n'est pas connecté (neuve, ou une écoute, dont la file
/// apporte les filles) : ENOTCONN, sans toucher à sa file
/// (`unix_seqpacket_recvmsg`).
fn recevoir_message(s: &Socket, longueur: usize, drapeaux: u64, a: &mut Attente,
                    mut copier: impl FnMut(usize, &[u8]) -> Result<usize, i64>) -> Result<Recu, i64> {
    const MSG_PEEK: u64 = 2;
    const MSG_TRUNC: u64 = 0x20;
    let u = unix(s);
    if u.sorte == Sorte::Paquets && u.etat.verrouiller().phase != Phase::Connectee {
        return Err(-ENOTCONN);
    }
    let regarder = drapeaux & MSG_PEEK != 0;
    loop {
        // MSG_PEEK et SO_PEEK_OFF (`__skb_try_recv_from_queue`) : le message où tombe le décalage, la
        // place dedans, et sa place dans la file ; un message vide compte une fois, regardé.
        let mut saut = 0;
        let mut place = 0;
        let mut deja = 0;
        let m = {
            let mut e = u.etat.verrouiller();
            // Une erreur en attente passe avant la file (`__skb_try_recv_datagram` : `sock_error`).
            let erreur = core::mem::take(&mut e.erreur);
            if erreur != 0 {
                return Err(-(erreur as i64));
            }
            if regarder {
                let decalage = s.peek_off.load(Ordering::Relaxed);
                saut = decalage.max(0) as usize;
                let trouve = e.file.iter().position(|m| {
                    let n = m.restant().len();
                    if decalage >= 0 && saut >= n && (saut > 0 || m.regarde) {
                        saut -= n;
                        return false;
                    }
                    true
                });
                match trouve {
                    Some(k) => {
                        place = k;
                        let m = e.file.remove(k);
                        m.map(|mut m| {
                            m.regarde |= m.restant().is_empty();
                            m
                        })
                    }
                    None => {
                        deja = e.file.len();
                        None
                    }
                }
            } else {
                e.file.pop_front()
            }
        };
        let Some(m) = m else {
            let non_bloquant = a.non_bloquant;
            match rien_a_lire(s, a, non_bloquant, deja) {
                Ok(Some(())) => continue,
                Ok(None) => return Ok(Recu { longueur: 0, adresse: None, coupe: false, fichiers: Vec::new(), droits: SANS_DROITS, scm: false, urgent: false }),
                Err(e) => {
                    // SEQPACKET non bloquante, connexion défaite : 0 (la fin).
                    let fin = u.sorte == Sorte::Paquets && e == -EAGAIN && u.etat.verrouiller().arret & ARRET_LECTURE != 0;
                    return if fin { Ok(Recu { longueur: 0, adresse: None, coupe: false, fichiers: Vec::new(), droits: SANS_DROITS, scm: false, urgent: false }) } else { Err(e) };
                }
            }
        };
        // De la place dans la file : l'émetteur d'un DGRAM qui attendait
        // (dans notre file), et ceux qui la surveillent par poll (leurs
        // relais, dans `attente_pairs`).
        reveiller(s, POLLOUT | POLLWRNORM | POLLWRBAND);
        u.attente_pairs.reveiller(POLLOUT | POLLWRNORM | POLLWRBAND, 0);
        let total = m.restant().len();
        let dispo = total - saut;
        let n = dispo.min(longueur);
        let adresse = m.emetteur.as_ref().and_then(|e| unix(e).etat.verrouiller().nom);
        let r = copier(0, &m.restant()[saut..][..n]);
        let droits = m.droits.unwrap_or(SANS_DROITS);
        let mut m = m;
        let fichiers = if r.is_err() {
            Vec::new()
        } else if drapeaux & MSG_PEEK != 0 {
            copies(&m.fichiers)
        } else {
            detacher(&mut m)
        };
        if regarder {
            s.peek_avance(n);
            remettre_a(s, place, m);
        } else {
            s.peek_recule(total);
            liberer(m);
        }
        let c = r?;
        return Ok(Recu { longueur: if drapeaux & MSG_TRUNC != 0 { dispo } else { c }, adresse, coupe: n < dispo, fichiers, droits, scm: true, urgent: false });
    }
}

// --- L'arrêt, la fermeture ---

/// shutdown (`unix_shutdown`) : SHUT_RD, SHUT_WR, SHUT_RDWR deviennent les
/// arrêts ; pour une connexion, le pair voit l'arrêt correspondant (la
/// lecture arrêtée ici arrête son écriture, et l'inverse).
pub fn arreter(s: &Socket, arret: u8) {
    let u = unix(s);
    let pair = {
        let mut e = u.etat.verrouiller();
        e.arret |= arret;
        e.pair.clone()
    };
    reveiller(s, 0);
    if let Some(p) = pair
        && u.sorte.connexion()
    {
        let mut miroir = 0;
        if arret & ARRET_LECTURE != 0 {
            miroir |= ARRET_ECRITURE;
        }
        if arret & ARRET_ECRITURE != 0 {
            miroir |= ARRET_LECTURE;
        }
        unix(&p).etat.verrouiller().arret |= miroir;
        reveiller(&p, 0);
        // `unix_shutdown`.
        if miroir == ARRET_LECTURE | ARRET_ECRITURE {
            p.asynchrone.lecture(Raison::Coupure);
        } else if miroir & ARRET_LECTURE != 0 {
            p.asynchrone.lecture(Raison::Entree);
        }
    }
}

/// Le dernier `close` (`unix_release_sock`).
pub fn fermer(s: &Socket) {
    fermer_avec(s, false);
    // Une fermeture peut avoir laissé un cycle sans lecteur (`unix_release_sock`).
    ramasser();
}

/// Ferme `s` : retirée du registre, morte, ses deux sens arrêtés ; son pair
/// d'une connexion voit les siens arrêtés, et ECONNRESET s'il nous restait
/// des données non lues, ou si `s` était une fille jamais acceptée
/// (`embryon`) ; sa file jetée (les filles d'une écoute défaites à leur
/// tour) ; l'inode de son nom rendu.
fn fermer_avec(s: &Socket, embryon: bool) {
    let u = unix(s);
    desinscrire(s.numero);
    // Son relais quitte son pair ; ceux qui attendaient qu'elle lise sont
    // réveillés (`wake_up_interruptible_all(&u->peer_wait)`) : leur poll la
    // verra fermée.
    u.relais.retirer();
    u.attente_pairs.reveiller(POLLOUT | POLLWRNORM | POLLWRBAND | POLLHUP, 0);
    let (pair, file, nom, ecoute) = {
        let mut e = u.etat.verrouiller();
        e.morte = true;
        e.arret = ARRET_LECTURE | ARRET_ECRITURE;
        let ecoute = matches!(e.phase, Phase::Ecoute { .. });
        // Le nom reste (`u->addr`, rendu avec la socket) : le pair le lit
        // encore (getpeername, l'adresse d'un datagramme) ; seul l'inode de
        // son chemin est rendu (`u->path`).
        let inode = e.nom.as_mut().and_then(|n| n.inode.take());
        (e.pair.take(), core::mem::take(&mut e.file), inode, ecoute)
    };
    reveiller(s, 0);
    if let Some(p) = pair {
        if u.sorte.connexion() {
            {
                let mut e = unix(&p).etat.verrouiller();
                e.arret = ARRET_LECTURE | ARRET_ECRITURE;
                // Des données non lues ; une tête vide (la marque de l'octet urgent, un message
                // SEQPACKET vide) ne compte pas, seulement ce qui la suit (`unix_release_sock`).
                let reste = match file.front() {
                    Some(m) if m.restant().is_empty() => file.len() > 1,
                    tete => tete.is_some(),
                };
                if reste || embryon {
                    e.erreur = ECONNRESET as i32;
                }
            }
            reveiller(&p, POLLIN | POLLOUT | POLLERR | POLLHUP);
            p.asynchrone.lecture(Raison::Coupure);
        }
        drop(p);
    }
    for mut m in file {
        if ecoute && let Some(enfant) = m.enfant.take() {
            fermer_avec(&enfant, true);
        }
        liberer(m);
    }
    if let Some(i) = nom {
        crate::appels_fichiers::lacher_noeud(i);
    }
}

// --- Ce qu'on peut faire sans attendre, et les files ---

/// poll (`unix_poll` pour un flux, `unix_dgram_poll` pour les autres) :
/// POLLERR (une erreur), POLLHUP (les deux sens arrêtés ; ou, avec
/// connexion, pas connectée), POLLIN (un message, ou la lecture arrêtée,
/// avec POLLRDHUP), POLLOUT (pas une écoute, et pas plus d'un quart de
/// SO_SNDBUF en route ; un DGRAM connecté dont le pair a sa file pleine
/// attend).
pub fn sonder(s: &Socket) -> u32 {
    let u = unix(s);
    let (phase, arret, erreur, vide, pair, oob) = {
        let e = u.etat.verrouiller();
        (e.phase, e.arret, e.erreur, e.file.is_empty(), e.pair.clone(), e.oob != 0)
    };
    let mut m = 0;
    if oob {
        m |= POLLPRI;
    }
    if erreur != 0 {
        m |= POLLERR;
    }
    if arret == ARRET_LECTURE | ARRET_ECRITURE {
        m |= POLLHUP;
    }
    if arret & ARRET_LECTURE != 0 {
        m |= POLLRDHUP | POLLIN | POLLRDNORM;
    }
    if !vide {
        m |= POLLIN | POLLRDNORM;
    }
    let ecoute = matches!(phase, Phase::Ecoute { .. });
    if u.sorte.connexion() && phase == Phase::Neuve {
        m |= POLLHUP;
    }
    let mut ecrire = !ecoute && u.envoyes.load(Ordering::Relaxed) * 4 <= s.sndbuf.load(Ordering::Relaxed) as usize;
    if ecrire
        && u.sorte == Sorte::Datagrammes
        && let Some(p) = &pair
    {
        // Un DGRAM connecté dont le pair a sa file pleine (et n'est pas
        // connecté à lui) : pas de POLLOUT, et son relais s'inscrit chez le
        // pair, qui le réveillera en lisant (`unix_dgram_peer_wake_me`) ;
        // puis la file est revue (elle a pu se vider entre-temps).
        let pleine = || {
            let ep = unix(p).etat.verrouiller();
            let son_pair = ep.pair.as_ref().is_some_and(|q| core::ptr::eq(&**q, s));
            !son_pair && ep.file.len() > DGRAM_QLEN
        };
        if pleine() {
            u.relais.as_ref().inscrire(p, &s.attente);
            ecrire = !pleine();
        }
    }
    if ecrire {
        m |= POLLOUT | POLLWRNORM | POLLWRBAND;
    } else {
        // (`unix_poll` : SOCKWQ_ASYNC_NOSPACE.) La place revue derrière
        // le drapeau (asynchrone.rs).
        s.asynchrone.marquer_sans_place(|| ecoute || u.envoyes.load(Ordering::SeqCst) * 4 > s.sndbuf.load(Ordering::Relaxed) as usize);
    }
    drop(pair);
    m
}

/// FIONREAD (`unix_inq_len`) : un flux ou SEQPACKET, tout ce qui est en
/// file ; un DGRAM, le premier message ; une écoute : EINVAL.
pub fn a_lire(s: &Socket) -> Result<usize, i64> {
    let u = unix(s);
    let e = u.etat.verrouiller();
    if matches!(e.phase, Phase::Ecoute { .. }) {
        return Err(-EINVAL);
    }
    Ok(match u.sorte {
        Sorte::Datagrammes => e.file.front().map_or(0, |m| m.restant().len()),
        _ => e.file.iter().map(|m| m.restant().len()).sum(),
    })
}

/// SIOCATMARK : la lecture est-elle devant l'octet urgent, ou sur sa marque ?
pub fn a_la_marque(s: &Socket) -> Result<bool, i64> {
    let u = unix(s);
    if u.sorte != Sorte::Flux {
        return Err(-EOPNOTSUPP);
    }
    // Sous l'iolock : un lecteur peut avoir la tête entre ses mains.
    let _lecteur = u.lecteurs.verrouiller();
    let e = u.etat.verrouiller();
    let Some(tete) = e.file.front() else { return Ok(false) };
    let est_oob = |m: &Message| m.numero_oob != 0 && m.numero_oob == e.oob;
    Ok(est_oob(tete) || (tete.restant().is_empty() && (e.oob == 0 || e.file.get(1).is_some_and(est_oob))))
}

/// SIOCOUTQ (`unix_outq_len`) : ce qu'elle a envoyé, pas encore lu, en
/// taille vraie (mesuré : 1536 pour deux envois de 5 et 3 octets).
pub fn en_route(s: &Socket) -> usize {
    unix(s).envoyes.load(Ordering::Relaxed)
}

/// La ligne `n` de /proc/net/unix (`unix_seq_show`) : l'en-tête, puis
/// chaque socket inscrite (l'adresse du noyau, `%pK`, écrite en zéros,
/// comme la voit un programme sans CAP_SYSLOG) : ses références, l'écoute
/// (`__SO_ACCEPTCON`), sa sorte, son état (connectée 03, sinon 01 ; une
/// fille pas encore acceptée, sans fichier : 02, ou 04), son inode et son
/// nom (un nom abstrait commence par @, et ses nuls s'écrivent @).
pub fn ligne_proc(n: u64, t: &mut dyn core::fmt::Write) -> Result<bool, core::fmt::Error> {
    if n == 0 {
        t.write_str("Num       RefCount Protocol Flags    Type St Inode Path\n")?;
        return Ok(true);
    }
    let s = {
        let r = REGISTRE.verrouiller();
        r.iter().filter_map(|i| i.socket.upgrade()).nth(n as usize - 1)
    };
    let Some(s) = s else { return Ok(false) };
    let u = unix(&s);
    let (phase, nom) = {
        let e = u.etat.verrouiller();
        (e.phase, e.nom)
    };
    let fichier = s.inode.load(Ordering::Relaxed) != 0;
    let etat = match (fichier, phase == Phase::Connectee) {
        (true, true) => 3,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 4,
    };
    let drapeaux = if matches!(phase, Phase::Ecoute { .. }) { 1 << 16 } else { 0 };
    write!(t, "{:016x}: {:08X} {:08X} {:08X} {:04X} {:02X} {:5}", 0, 2, 0, drapeaux, u.sorte.linux(), etat, s.inode.load(Ordering::Relaxed))?;
    if let Some(nom) = nom {
        t.write_char(' ')?;
        let o = &nom.octets()[2..];
        let o = if nom.abstrait() {
            o
        } else {
            &o[..o.len().saturating_sub(1)]
        };
        for &c in o {
            t.write_char(if c == 0 { '@' } else { c as char })?;
        }
    }
    t.write_char('\n')?;
    drop(s);
    Ok(true)
}
