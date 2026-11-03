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
//! ÉCARTS : SCM_RIGHTS et SCM_CREDENTIALS (passer un descripteur, ou ses
//! droits) attendent 6l (avec `fork`, et le ramasse-miettes des sockets en
//! vol) : EINVAL, ce que rend `__scm_send` pour un genre inconnu. MSG_OOB
//! sur un flux AF_UNIX (Linux l'a depuis 5.15) : EOPNOTSUPP.

use super::socket::{Socket, ARRET_ECRITURE, ARRET_LECTURE, POLLRDHUP};
use crate::attente::{self, FileAttente, GardeMutex, Mutex, PorteFile, Relais, Sommeil};
use crate::faillible::{self, FileFaillible, VecFaillible};
use crate::partage::{Arc, Weak};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::{cpu, processus, temps};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};

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
#[derive(Clone, Copy)]
pub struct Droits {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
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
                phase: Phase::Neuve, nom: None, pair: None, arret: 0, erreur: 0, morte: false, passcred: false, droits: None,
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
    let interruptions = cpu::couper_interruptions();
    let t = tache::courante();
    let r = loop {
        if pret() {
            break Ok(());
        }
        if tache::signal_en_attente() {
            break Err(if delai { -EINTR } else { -crate::reprise::ERESTARTSYS });
        }
        if echeance.is_some_and(|e| e <= temps::ns_monotone()) {
            break Err(-EAGAIN);
        }
        file.inscrire();
        let reveil = attente::dormir(echeance, Sommeil::Interruptible);
        file.retirer(&t);
        if reveil == Reveil::Echeance && !pret() {
            break Err(-EAGAIN);
        }
    };
    if interruptions {
        cpu::activer_interruptions();
    }
    r
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
fn liberer(m: Message) {
    if let Some(e) = &m.emetteur {
        unix(e).envoyes.fetch_sub(m.taille, Ordering::Relaxed);
        reveiller(e, POLLOUT | POLLWRNORM | POLLWRBAND);
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
        let (ecoute, pleine, nom_ecoute, droits_ecoute, passcred_ecoute) = {
            let e = ua.etat.verrouiller();
            match e.phase {
                Phase::Ecoute { backlog } if !e.morte && e.arret & ARRET_LECTURE == 0 => {
                    (true, e.file.len() > backlog, e.nom, e.droits, e.passcred)
                }
                _ => (false, false, None, None, false),
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
        }
        // Le message qui apporte la fille à l'écoute.
        let mut ea = ua.etat.verrouiller();
        let deposee = !ea.morte && ea.file.ajouter_derriere(Message { octets: Vec::new(), lus: 0, taille: 0, emetteur: None, enfant: Some(enfant.clone()) }).is_ok();
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
    // L'ancien pair ne nous concerne plus (`unix_dgram_peer_wake_disconnect`).
    u.relais.retirer();
    drop(ancien);
    Ok(())
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
            return m.enfant.take().ok_or(-EINVAL);
        }
        if non_bloquant {
            return Err(-EAGAIN);
        }
        attendre(&s.attente, echeance, delai, || {
            let e = u.etat.verrouiller();
            !e.file.is_empty() || !matches!(e.phase, Phase::Ecoute { .. })
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
pub fn envoyer(s: &Arc<Socket>, destination: Option<&[u8]>, longueur: usize, drapeaux: u64,
               remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    if drapeaux & MSG_OOB != 0 {
        return Err(-EOPNOTSUPP);
    }
    match unix(s).sorte {
        Sorte::Flux => envoyer_flux(s, destination, longueur, drapeaux, remplir),
        _ => envoyer_message(s, destination, longueur, drapeaux, remplir),
    }
}

/// Attend que l'émetteur ait de la place (`sock_alloc_send_pskb` :
/// moins que SO_SNDBUF en route) ; MSG_DONTWAIT : EAGAIN ; l'écriture
/// arrêtée, ou une erreur, entre-temps : EPIPE.
fn attendre_place(s: &Socket, non_bloquant: bool, echeance: Option<u64>, delai: bool) -> Result<(), i64> {
    let u = unix(s);
    let sndbuf = || s.sndbuf.load(Ordering::Relaxed) as usize;
    let place = || u.envoyes.load(Ordering::Relaxed) < sndbuf();
    if place() {
        return Ok(());
    }
    if non_bloquant {
        return Err(-EAGAIN);
    }
    attendre(&s.attente, echeance, delai, || {
        let e = u.etat.verrouiller();
        place() || e.arret & ARRET_ECRITURE != 0 || e.erreur != 0
    })?;
    let e = u.etat.verrouiller();
    if e.arret & ARRET_ECRITURE != 0 || e.erreur != 0 {
        return Err(-EPIPE);
    }
    Ok(())
}

/// Un message de `n` octets, rempli par `remplir` à partir de l'octet
/// `decalage` de l'envoi. ENOBUFS : plus de mémoire.
fn message(s: &Arc<Socket>, n: usize, decalage: usize, remplir: &mut impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<Message, i64> {
    let mut octets = faillible::remplie(n, 0u8).map_err(|_| -ENOBUFS)?;
    remplir(decalage, &mut octets)?;
    Ok(Message { octets, lus: 0, taille: taille_vraie(unix(s).sorte, n), emetteur: Some(s.clone()), enfant: None })
}

/// Met le message `m` dans la file de `autre` et compte sa place chez
/// l'émetteur ; `autre` fermée, ou sa lecture arrêtée : rend le message
/// (Err).
fn deposer(autre: &Socket, m: Message) -> Result<(), Message> {
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
    {
        let mut e = unix(autre).etat.verrouiller();
        if e.morte || e.arret & ARRET_LECTURE != 0 || e.file.try_reserve(1).is_err() {
            drop(e);
            compter(&m, false);
            return Err(m);
        }
        e.file.ajouter_derriere_dans_la_place(m);
    }
    reveiller(autre, POLLIN | POLLRDNORM);
    Ok(())
}

/// Un flux (`unix_stream_sendmsg`) : une adresse donnée : EISCONN connecté,
/// EOPNOTSUPP sinon ; sans pair : ENOTCONN ; l'écriture arrêtée, ou le pair
/// fermé ou qui ne lit plus : EPIPE ; des messages d'au plus la moitié de
/// SO_SNDBUF, chacun quand il y a la place. Rend ce qui a été envoyé, ou
/// l'erreur si rien ne l'a été.
fn envoyer_flux(s: &Arc<Socket>, destination: Option<&[u8]>, longueur: usize, drapeaux: u64,
                mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_DONTWAIT: u64 = 0x40;
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
        return Err(-EPIPE);
    }
    let (echeance, delai) = echeance(s.appels.verrouiller().options.sndtimeo);
    let mut fait = 0;
    while fait < longueur {
        if let Err(e) = attendre_place(s, drapeaux & MSG_DONTWAIT != 0, echeance, delai) {
            return if fait > 0 { Ok(fait) } else { Err(e) };
        }
        let n = (longueur - fait).min((s.sndbuf.load(Ordering::Relaxed) as usize / 2).saturating_sub(64).max(1)).min(MESSAGE_MAX);
        let m = match message(s, n, fait, &mut remplir) {
            Ok(m) => m,
            Err(e) => return if fait > 0 { Ok(fait) } else { Err(e) },
        };
        if let Err(m) = deposer(&pair, m) {
            drop(m);
            return if fait > 0 { Ok(fait) } else { Err(-EPIPE) };
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
fn envoyer_message(s: &Arc<Socket>, destination: Option<&[u8]>, longueur: usize, drapeaux: u64,
                   mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_DONTWAIT: u64 = 0x40;
    let u = unix(s);
    let non_bloquant = drapeaux & MSG_DONTWAIT != 0;
    let paquets = u.sorte == Sorte::Paquets;
    let (pair, phase, passcred, arret, erreur) = {
        let mut e = u.etat.verrouiller();
        // SEQPACKET : l'erreur en attente d'abord (`unix_seqpacket_sendmsg` :
        // `sock_error`), ECONNRESET d'un pair fermé sans tout lire.
        let erreur = if paquets { core::mem::take(&mut e.erreur) } else { 0 };
        (e.pair.clone(), e.phase, e.passcred, e.arret, erreur)
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
    if paquets && arret & ARRET_ECRITURE != 0 {
        return Err(-EPIPE);
    }
    let (echeance, delai) = echeance(s.appels.verrouiller().options.sndtimeo);
    attendre_place(s, non_bloquant, echeance, delai)?;
    let autre = match &nom {
        Some(n) => chercher(n, u.sorte)?,
        None => pair.clone().ok_or(-ENOTCONN)?,
    };
    let mut m = message(s, longueur, 0, &mut remplir)?;
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
            drop(ancien);
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
            Err(r) => {
                m = r;
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
}

/// Reçoit au plus `longueur` octets par `copier` (`decalage`, octets) avec
/// `drapeaux` (MSG_PEEK, MSG_DONTWAIT, MSG_WAITALL, MSG_TRUNC).
pub fn recevoir(s: &Socket, longueur: usize, drapeaux: u64, non_bloquant: bool,
                copier: impl FnMut(usize, &[u8]) -> Result<usize, i64>) -> Result<Recu, i64> {
    const MSG_OOB: u64 = 1;
    const MSG_DONTWAIT: u64 = 0x40;
    if drapeaux & MSG_OOB != 0 {
        return Err(-EOPNOTSUPP);
    }
    let u = unix(s);
    let (delai, rcvlowat) = {
        let i = s.appels.verrouiller();
        (i.options.rcvtimeo, i.options.rcvlowat as usize)
    };
    let non_bloquant = non_bloquant || drapeaux & MSG_DONTWAIT != 0 || delai == Some(0);
    let (echeance, delai) = echeance(delai);
    let mut a = Attente { lecteur: Some(u.lecteurs.verrouiller()), lecteurs: &u.lecteurs, non_bloquant, echeance, delai };
    match u.sorte {
        Sorte::Flux => recevoir_flux(s, longueur, drapeaux, rcvlowat, &mut a, copier),
        _ => recevoir_message(s, longueur, drapeaux, &mut a, copier),
    }
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
/// attendant (`__skb_wait_for_more_packets`).
fn rien_a_lire(s: &Socket, a: &mut Attente, non_bloquant: bool) -> Result<Option<()>, i64> {
    let u = unix(s);
    {
        let mut e = u.etat.verrouiller();
        if !e.file.is_empty() {
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
    let attendu = attendre(&s.attente, a.echeance, a.delai, || {
        let e = u.etat.verrouiller();
        !e.file.is_empty() || e.erreur != 0 || e.arret & ARRET_LECTURE != 0
    });
    a.lecteur = Some(a.lecteurs.verrouiller());
    attendu?;
    Ok(Some(()))
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
    let cible = if drapeaux & MSG_WAITALL != 0 { longueur } else { rcvlowat.min(longueur) };
    let mut adresse = None;
    let mut fait = 0;
    // MSG_PEEK : les messages déjà regardés, remis en tête à la fin.
    let mut vus: VecDeque<Message> = VecDeque::new();
    let r = loop {
        if fait >= longueur && longueur > 0 {
            break Ok(());
        }
        let m = u.etat.verrouiller().file.pop_front();
        let Some(mut m) = m else {
            if fait >= cible || longueur == 0 {
                break Ok(());
            }
            let non_bloquant = a.non_bloquant || !vus.is_empty();
            match rien_a_lire(s, a, non_bloquant) {
                Ok(Some(())) => continue,
                Ok(None) => break Ok(()),
                Err(e) => break if fait > 0 { Ok(()) } else { Err(e) },
            }
        };
        if adresse.is_none() {
            adresse = Some(m.emetteur.as_ref().and_then(|e| unix(e).etat.verrouiller().nom));
        }
        let n = m.restant().len().min(longueur - fait);
        let c = match copier(fait, &m.restant()[..n]) {
            Ok(c) => c,
            Err(e) => {
                remettre(u, m);
                break if fait > 0 { Ok(()) } else { Err(e) };
            }
        };
        fait += c;
        if regarder {
            if vus.try_reserve(1).is_err() {
                remettre(u, m);
                break Ok(());
            }
            vus.ajouter_derriere_dans_la_place(m);
            continue;
        }
        m.lus += c;
        if !m.restant().is_empty() {
            remettre(u, m);
            break Ok(());
        }
        liberer(m);
    };
    while let Some(m) = vus.pop_back() {
        remettre(u, m);
    }
    r.map(|()| Recu { longueur: fait, adresse: adresse.flatten(), coupe: false })
}

/// Remet un message en tête de la file (sorti pour être copié, et pas tout
/// lu). La place, qu'il vient de quitter, y est encore.
fn remettre(u: &Unix, m: Message) {
    let mut e = u.etat.verrouiller();
    if e.file.try_reserve(1).is_ok() {
        e.file.ajouter_devant_dans_la_place(m);
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
    loop {
        let m = u.etat.verrouiller().file.pop_front();
        let Some(m) = m else {
            let non_bloquant = a.non_bloquant;
            match rien_a_lire(s, a, non_bloquant) {
                Ok(Some(())) => continue,
                Ok(None) => return Ok(Recu { longueur: 0, adresse: None, coupe: false }),
                Err(e) => {
                    // SEQPACKET non bloquante, connexion défaite : 0 (la fin).
                    let fin = u.sorte == Sorte::Paquets && e == -EAGAIN && u.etat.verrouiller().arret & ARRET_LECTURE != 0;
                    return if fin { Ok(Recu { longueur: 0, adresse: None, coupe: false }) } else { Err(e) };
                }
            }
        };
        // De la place dans la file : l'émetteur d'un DGRAM qui attendait
        // (dans notre file), et ceux qui la surveillent par poll (leurs
        // relais, dans `attente_pairs`).
        reveiller(s, POLLOUT | POLLWRNORM | POLLWRBAND);
        u.attente_pairs.reveiller(POLLOUT | POLLWRNORM | POLLWRBAND, 0);
        let total = m.restant().len();
        let n = total.min(longueur);
        let adresse = m.emetteur.as_ref().and_then(|e| unix(e).etat.verrouiller().nom);
        let r = copier(0, &m.restant()[..n]);
        if drapeaux & MSG_PEEK != 0 {
            remettre(u, m);
        } else {
            liberer(m);
        }
        let c = r?;
        return Ok(Recu { longueur: if drapeaux & MSG_TRUNC != 0 { total } else { c }, adresse, coupe: n < total });
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
    }
}

/// Le dernier `close` (`unix_release_sock`).
pub fn fermer(s: &Socket) {
    fermer_avec(s, false);
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
                if !file.is_empty() || embryon {
                    e.erreur = ECONNRESET as i32;
                }
            }
            reveiller(&p, POLLIN | POLLOUT | POLLERR | POLLHUP);
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
    let (phase, arret, erreur, vide, pair) = {
        let e = u.etat.verrouiller();
        (e.phase, e.arret, e.erreur, e.file.is_empty(), e.pair.clone())
    };
    let mut m = 0;
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
