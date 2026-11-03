//! Les appels système des sockets (net/socket.c), et ce que font read,
//! write, ioctl sur une socket (le `socket_file_ops` de Linux).
//!
//! Chaque appel suit l'ordre de Linux, parce qu'un programme voit l'ordre
//! des vérifications dans ses erreurs : d'abord ce que vérifie net/socket.c
//! (les drapeaux, le descripteur : EBADF, puis ENOTSOCK ; les adresses
//! copiées comme `move_addr_to_kernel`, 128 octets au plus), puis la
//! famille (af_inet.c), puis le protocole (udp.rs). Ce qui touche la
//! mémoire du programme est ici ; les règles des sockets sont dans
//! reseau/socket.rs et reseau/udp.rs, qui ne copient jamais rien
//! eux-mêmes (on leur passe de quoi le faire : une adresse déjà copiée, une
//! fonction qui copie la charge).
//!
//! Les familles : AF_INET seule (6h ajoutera AF_UNIX) ; une autre rend
//! EAFNOSUPPORT, comme un Linux qui ne l'a pas compilée. Les sortes
//! d'AF_INET : SOCK_DGRAM et UDP ; SOCK_STREAM rend ESOCKTNOSUPPORT (ce que
//! rend `inet_create` pour une sorte sans protocole inscrit : un Linux sans
//! TCP, jusqu'à 6h ; mesuré, `claude -p` le prend pour une connexion
//! refusée).

use crate::appels_fichiers::{self, FichierTenu, installer_fichier};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::partage::{Arc, ArcVide};
use crate::reseau::socket::{self, Protocole, Socket, AF_INET, ARRET_ECRITURE, ARRET_LECTURE, IPPROTO_IP, IPPROTO_MAX,
                            IPPROTO_ICMP, IPPROTO_UDP, NPROTO, RCVBUF_MIN, SNDBUF_MIN, SOCK_CLOEXEC, SOCK_DGRAM, SOCK_MAX,
                            SOCK_NONBLOCK, SOCK_RAW, TAMPON_MAX};
use crate::reseau::datagramme::{self, Controle};
use crate::reseau::{ping, tcp, udp};
use crate::{faillible, processus, temps, vfs};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use fichiers::tmpfs::Ouvert;

const EPERM: i64 = 1;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENFILE: i64 = 23;
const ENOTTY: i64 = 25;
const EDOM: i64 = 33;
const ENOTSOCK: i64 = 88;
const EMSGSIZE: i64 = 90;
const ENOPROTOOPT: i64 = 92;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EOPNOTSUPP: i64 = 95;
const EAFNOSUPPORT: i64 = 97;
const ENOBUFS: i64 = 105;
const ENOTCONN: i64 = 107;
const EPIPE: i64 = 32;

const O_RDWR: u32 = 2;
const O_NONBLOCK: u32 = 0o4000;

/// La plus longue adresse que copie un appel (`sizeof(struct
/// sockaddr_storage)`).
const ADRESSE_MAX: usize = 128;
/// SOCK_PACKET, la vieille façon d'AF_INET d'ouvrir une socket « paquet » :
/// Linux la renvoie à AF_PACKET.
const SOCK_PACKET: i32 = 10;

// Les drapeaux de sendmsg et recvmsg.
const MSG_OOB: u64 = 1;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_CTRUNC: u32 = 0x08;
const MSG_ERRQUEUE: u64 = 0x2000;
const MSG_WAITFORONE: u64 = 0x10000;
const MSG_CMSG_COMPAT: u64 = 0x8000_0000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
/// La plus grande place de messages de contrôle d'un envoi (`optmem_max`,
/// ce que `sock_kmalloc` accepte d'allouer pour une socket).
const OPTMEM_MAX: u64 = 131_072;

// Les niveaux et les options.
const SOL_IP: i32 = 0;
const SOL_SOCKET: i32 = 1;
const SOL_UDP: i32 = 17;
const SOL_TCP: i32 = 6;
// Les options de SOL_TCP (include/uapi/linux/tcp.h).
const TCP_NODELAY: i32 = 1;
const TCP_MAXSEG: i32 = 2;
const TCP_CORK: i32 = 3;
const TCP_KEEPIDLE: i32 = 4;
const TCP_KEEPINTVL: i32 = 5;
const TCP_KEEPCNT: i32 = 6;
const TCP_SYNCNT: i32 = 7;
const TCP_LINGER2: i32 = 8;
const TCP_DEFER_ACCEPT: i32 = 9;
const TCP_INFO: i32 = 11;
const TCP_QUICKACK: i32 = 12;
const TCP_CONGESTION: i32 = 13;
const TCP_USER_TIMEOUT: i32 = 18;
const SO_DEBUG: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_DONTROUTE: i32 = 5;
const SO_BROADCAST: i32 = 6;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_OOBINLINE: i32 = 10;
const SO_NO_CHECK: i32 = 11;
const SO_PRIORITY: i32 = 12;
const SO_LINGER: i32 = 13;
const SO_BSDCOMPAT: i32 = 14;
const SO_REUSEPORT: i32 = 15;
const SO_RCVLOWAT: i32 = 18;
const SO_SNDLOWAT: i32 = 19;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;
const SO_ACCEPTCONN: i32 = 30;
const SO_PROTOCOL: i32 = 38;
const SO_DOMAIN: i32 = 39;
const SO_RCVTIMEO_NEW: i32 = 66;
const SO_SNDTIMEO_NEW: i32 = 67;
const IP_TOS: i32 = 1;
const IP_TTL: i32 = 2;
const IP_PKTINFO: i32 = 8;
const IP_MTU_DISCOVER: i32 = 10;
const IP_RECVERR: i32 = 11;
const IP_MTU: i32 = 14;
const IP_PMTUDISC_OMIT: i32 = 5;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;

/// Le tic des délais des sockets (le HZ de Linux) : 1 ms, celui de notre
/// horloge (6e).
const TIC: u64 = 1_000_000;

fn en_i64(r: Result<i64, i64>) -> i64 {
    r.unwrap_or_else(|e| e)
}

/// La socket du descripteur `fd` (le `sockfd_lookup` de Linux) : EBADF
/// (pas de descripteur, ou ouvert en O_PATH), ENOTSOCK (un autre fichier).
fn tenir(fd: u64) -> Result<FichierTenu, i64> {
    socket_de(tenir_fichier(fd)?)
}

/// Le fichier du descripteur `fd`, quel qu'il soit (le `CLASS(fd)` de
/// Linux) : EBADF, aussi pour un fichier ouvert en O_PATH (`fdget` ne les
/// rend pas).
fn tenir_fichier(fd: u64) -> Result<FichierTenu, i64> {
    let o = appels_fichiers::tenir(fd)?;
    if o.sorte == Sorte::Chemin {
        return Err(-EBADF);
    }
    Ok(o)
}

/// Le fichier `o` est-il une socket (`sock_from_file`) ? ENOTSOCK sinon.
fn socket_de(o: FichierTenu) -> Result<FichierTenu, i64> {
    if o.sorte == Sorte::Socket { Ok(o) } else { Err(-ENOTSOCK) }
}

/// Le fichier est-il en O_NONBLOCK ?
fn non_bloquant(o: &FichierTenu) -> bool {
    o.drapeaux & O_NONBLOCK != 0
}

/// Une adresse copiée du programme (`move_addr_to_kernel`) : une longueur
/// négative ou de plus de 128 octets : EINVAL ; la copie : EFAULT.
struct Adresse {
    octets: [u8; ADRESSE_MAX],
    longueur: usize,
}

impl Adresse {
    fn octets(&self) -> &[u8] {
        &self.octets[..self.longueur]
    }
}

fn copier_adresse(adresse: u64, longueur: u64) -> Result<Adresse, i64> {
    let longueur = longueur as i32;
    if longueur < 0 || longueur as usize > ADRESSE_MAX {
        return Err(-EINVAL);
    }
    let mut a = Adresse { octets: [0; ADRESSE_MAX], longueur: longueur as usize };
    if longueur > 0 {
        copier_depuis_utilisateur(&mut a.octets[..longueur as usize], adresse).map_err(|_| -EFAULT)?;
    }
    Ok(a)
}

/// Rend l'adresse `k` au programme (`move_addr_to_user`) : la place
/// qu'il donne lue à `longueur` (EFAULT ; négative : EINVAL), l'adresse
/// coupée à cette place, puis sa vraie longueur écrite à `longueur`.
fn rendre_adresse(k: &[u8], adresse: u64, longueur: u64) -> Result<(), i64> {
    let mut l = [0u8; 4];
    copier_depuis_utilisateur(&mut l, longueur).map_err(|_| -EFAULT)?;
    let place = i32::from_le_bytes(l);
    if place < 0 {
        return Err(-EINVAL);
    }
    let n = (place as usize).min(k.len());
    if n > 0 {
        copier_vers_utilisateur(adresse, &k[..n]).map_err(|_| -EFAULT)?;
    }
    copier_vers_utilisateur(longueur, &(k.len() as i32).to_le_bytes()).map_err(|_| -EFAULT)
}

/// Le protocole d'une socket qu'on crée, dans l'ordre de `__sock_create`
/// et d'`inet_create` : une famille hors de 0..NPROTO : EAFNOSUPPORT ; une
/// sorte hors de 0..SOCK_MAX : EINVAL ; une famille absente : EAFNOSUPPORT ;
/// un protocole hors de 0..IPPROTO_MAX : EINVAL ; une sorte sans protocole
/// inscrit : ESOCKTNOSUPPORT ; un protocole qui n'est pas celui de la
/// sorte : EPROTONOSUPPORT.
fn choisir(famille: i32, sorte: i32, protocole: i32) -> Result<(Protocole, u16), i64> {
    if famille < 0 || famille as u64 >= NPROTO {
        return Err(-EAFNOSUPPORT);
    }
    if sorte < 0 || sorte as u64 >= SOCK_MAX {
        return Err(-EINVAL);
    }
    if famille as u16 != AF_INET || sorte == SOCK_PACKET {
        return Err(-EAFNOSUPPORT);
    }
    if protocole < 0 || protocole as u64 >= IPPROTO_MAX {
        return Err(-EINVAL);
    }
    // La table `inetsw` de 6g : SOCK_DGRAM a UDP (le protocole par défaut)
    // et ping (IPPROTO_ICMP : `ping_group_range` les permet à tous, voir
    // reseau/ping.rs) ; SOCK_RAW a son entrée, au protocole joker
    // (IPPROTO_IP), qui accepte tout protocole sauf 0 lui-même (la boucle
    // d'`inet_create` ne s'arrête sur un joker que pour un protocole
    // demandé : sinon EPROTONOSUPPORT), et demande CAP_NET_RAW : EPERM (un
    // écart pour root, qui l'a chez Linux : nous n'avons pas de sockets
    // RAW, et aucun de nos programmes n'est root) ; SOCK_STREAM (TCP, 6h)
    // n'a encore rien.
    match (sorte as u64, protocole as u64) {
        (SOCK_DGRAM, IPPROTO_IP | IPPROTO_UDP) => Ok((Protocole::Udp, IPPROTO_UDP as u16)),
        (SOCK_DGRAM, IPPROTO_ICMP) => Ok((Protocole::Ping, IPPROTO_ICMP as u16)),
        (SOCK_DGRAM, _) => Err(-EPROTONOSUPPORT),
        // TCP (6h) : le protocole par défaut de SOCK_STREAM.
        (tcp::SOCK_STREAM, IPPROTO_IP | tcp::IPPROTO_TCP) => Ok((Protocole::Tcp, tcp::IPPROTO_TCP as u16)),
        (tcp::SOCK_STREAM, _) => Err(-EPROTONOSUPPORT),
        (SOCK_RAW, IPPROTO_IP) => Err(-EPROTONOSUPPORT),
        (SOCK_RAW, _) => Err(-EPERM),
        // SOCK_STREAM compris.
        _ => Err(-ESOCKTNOSUPPORT),
    }
}

/// Les drapeaux qui accompagnent la sorte (`SOCK_CLOEXEC`,
/// `SOCK_NONBLOCK`) ; un autre : EINVAL.
fn separer(sorte: u64) -> Result<(i32, u64), i64> {
    let sorte = sorte as i32;
    let drapeaux = (sorte & !0xf) as u32 as u64;
    if drapeaux & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
        return Err(-EINVAL);
    }
    Ok((sorte & 0xf, drapeaux))
}

/// Le « chemin » d'une socket dans /proc/<pid>/fd : « socket:[inode] ».
fn nom(numero: u32) -> Vec<u8> {
    let mut t = [0u8; 10];
    let n = vfs::decimal(numero, &mut t);
    faillible::concatenation(&[b"socket:[", n, b"]"]).unwrap_or_default()
}

/// socket(famille, sorte, protocole) : la socket (son protocole choisi),
/// son inode (S_IFSOCK 0777, sans nom : ENFILE s'il n'y en a plus, le
/// `sock_alloc`), et son fichier ouvert en lecture et écriture, O_NONBLOCK
/// si demandé (F_GETFL le rend).
pub fn socket(famille: u64, sorte: u64, protocole: u64) -> i64 {
    let (sorte, drapeaux) = match separer(sorte) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let (p, proto) = match choisir(famille as i32, sorte, protocole as i32) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let identite = processus::avec(|p| p.identite);
    // Dans l'ordre de `__sock_create` : la socket d'abord (`sock_alloc` :
    // ENFILE), puis ce que demande son protocole (`sk_alloc` : ENOBUFS).
    let Ok(place) = ArcVide::new() else { return -ENFILE };
    let s = Socket::new(p, sorte as u16, proto, identite.uid);
    let Some(s) = (if p == Protocole::Tcp { s.tcp() } else { Some(s) }) else { return -ENOBUFS };
    installer(place.remplir(s), drapeaux)
}

/// Le fichier ouvert d'une socket neuve (`sock_alloc_file`) : son inode
/// (S_IFSOCK 0777, sans nom : ENFILE s'il n'y en a plus), ouvert en
/// lecture et écriture, O_NONBLOCK et FD_CLOEXEC si demandés.
fn installer(s: Arc<Socket>, drapeaux: u64) -> i64 {
    let identite = processus::avec(|p| p.identite);
    match fichier_sans_socket(identite, drapeaux & SOCK_NONBLOCK != 0) {
        Ok(mut f) => {
            attacher(&mut f, s);
            installer_fichier(f, drapeaux & SOCK_CLOEXEC != 0)
        }
        Err(e) => e,
    }
}

/// Le fichier ouvert d'une socket, encore sans elle : `accept` le prépare
/// AVANT de prendre la connexion, comme le `do_accept` de Linux
/// (`sock_alloc`, `sock_alloc_file`, puis `ops->accept`) : sans inode
/// (ENFILE), la connexion reste dans la file de l'écoute. Refusé, il se
/// rend par `appels_fichiers::rendre_fichier`.
fn fichier_sans_socket(identite: fichiers::Identite, non_bloquant: bool) -> Result<FichierOuvert, i64> {
    let maintenant = temps::maintenant();
    let Ok(numero) = vfs::avec(|fs, _| {
        let n = fs.creer_socket(identite, maintenant)?;
        fs.prendre(n);
        Ok::<_, fichiers::Erreur>(n)
    }) else {
        return Err(-ENFILE);
    };
    let ouvert = Ouvert { numero, cree: false, tronquer: false, ecrivain: false };
    let mut f = FichierOuvert::new(Sorte::Socket, Tenu::Tmpfs(ouvert), true, true,
                                   O_RDWR | if non_bloquant { O_NONBLOCK } else { 0 }, b"socket");
    f.chemin = nom(numero.0);
    Ok(f)
}

/// Met la socket `s` dans le fichier `f`, de `fichier_sans_socket` : elle y
/// apprend son inode (/proc/net/tcp).
fn attacher(f: &mut FichierOuvert, s: Arc<Socket>) {
    s.inode.store(f.inode().0, Ordering::Relaxed);
    f.prive = Prive::Socket(s);
}

/// socketpair(famille, sorte, protocole, tableau) : les drapeaux (EINVAL),
/// la socket (les erreurs de `socket`), puis EOPNOTSUPP : une paire n'a de
/// sens que dans une même machine (AF_UNIX, 6h), et AF_INET n'en fait pas
/// (`sock_no_socketpair`). Linux réserve d'abord les deux descripteurs et
/// écrit leurs numéros (EMFILE, EFAULT) avant de créer les sockets : nous
/// ne les réservons pas pour rien (un écart, sans effet sur ce qui est
/// rendu quand tout va bien).
pub fn socketpair(famille: u64, sorte: u64, protocole: u64, _tableau: u64) -> i64 {
    let (sorte, _) = match separer(sorte) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match choisir(famille as i32, sorte, protocole as i32) {
        Ok(_) => -EOPNOTSUPP,
        Err(e) => e,
    }
}

/// bind(fd, adresse, longueur).
pub fn bind(fd: u64, adresse: u64, longueur: u64) -> i64 {
    en_i64((|| {
        let o = tenir(fd)?;
        let a = copier_adresse(adresse, longueur)?;
        match o.socket().protocole {
            Protocole::Udp | Protocole::Ping => datagramme::lier(o.socket(), a.octets()).map(|()| 0),
            Protocole::Tcp => tcp::lier(o.socket(), a.octets()).map(|()| 0),
        }
    })())
}

/// connect(fd, adresse, longueur) : le descripteur (EBADF), l'adresse
/// copiée (EINVAL, EFAULT), puis seulement ENOTSOCK (`__sys_connect` :
/// bind, lui, regarde ENOTSOCK avant l'adresse).
pub fn connect(fd: u64, adresse: u64, longueur: u64) -> i64 {
    en_i64((|| {
        let o = tenir_fichier(fd)?;
        let a = copier_adresse(adresse, longueur)?;
        let o = socket_de(o)?;
        match o.socket().protocole {
            Protocole::Udp | Protocole::Ping => datagramme::connecter(o.socket(), a.octets()).map(|()| 0),
            Protocole::Tcp => tcp::connecter(o.socket(), a.octets(), non_bloquant(&o)).map(|()| 0),
        }
    })())
}

/// listen(fd, file) : EOPNOTSUPP pour une socket sans connexion
/// (`sock_no_listen`) ; TCP (`inet_listen`).
pub fn listen(fd: u64, file: u64) -> i64 {
    match tenir(fd) {
        Ok(o) if o.socket().protocole == Protocole::Tcp => en_i64(tcp::ecouter(o.socket(), file as i32).map(|()| 0)),
        Ok(_) => -EOPNOTSUPP,
        Err(e) => e,
    }
}

/// accept4(fd, adresse, longueur, drapeaux), dans l'ordre de Linux 6.18
/// (`__sys_accept4_file`, puis `do_accept`) : le descripteur (EBADF), les
/// drapeaux (EINVAL), puis ENOTSOCK, puis EOPNOTSUPP (`sock_no_accept`) ;
/// puis, AVANT de prendre une connexion, le numéro du descripteur (EMFILE)
/// et le fichier de la socket (ENFILE) : sans eux, la connexion reste dans
/// la file de l'écoute, pour un `accept` suivant. Puis la connexion, et
/// l'adresse du pair copiée avant d'installer le descripteur : une faute
/// (EFAULT) ferme la connexion, et le numéro est rendu, comme chez Linux
/// (`fput` du fichier neuf). Seule la place de la table des fichiers peut
/// encore manquer après (ENOMEM) : la connexion est alors fermée aussi.
pub fn accept4(fd: u64, adresse: u64, longueur: u64, drapeaux: u64) -> i64 {
    en_i64((|| {
        let o = tenir_fichier(fd)?;
        let drapeaux = drapeaux as u32 as u64;
        if drapeaux & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 {
            return Err(-EINVAL);
        }
        let o = socket_de(o)?;
        if o.socket().protocole != Protocole::Tcp {
            return Err(-EOPNOTSUPP);
        }
        let numero = appels_fichiers::reserver()?;
        let identite = processus::avec(|p| p.identite);
        let mut f = fichier_sans_socket(identite, drapeaux & SOCK_NONBLOCK != 0)?;
        // La fille, devenue socket, et l'adresse de son pair.
        let (enfant, distante, port) = match tcp::accepter(o.socket(), non_bloquant(&o)) {
            Ok(p) => p,
            Err(e) => {
                appels_fichiers::rendre_fichier(f);
                return Err(e);
            }
        };
        attacher(&mut f, enfant.clone());
        // Le fichier neuf qui n'atteint pas la table ne fermera pas la
        // socket : elle se ferme ici, comme à son dernier `close`.
        let abandonner = |f, e| {
            appels_fichiers::rendre_fichier(f);
            tcp::fermer(&enfant);
            Err(e)
        };
        if adresse != 0
            && let Err(e) = rendre_adresse(&socket::sockaddr_in(distante, port), adresse, longueur)
        {
            return abandonner(f, e);
        }
        match appels_fichiers::installer_reserve_puis(numero, f, drapeaux & SOCK_CLOEXEC != 0, |_| {}) {
            Ok(fd) => Ok(fd as i64),
            Err(f) => abandonner(f, -ENOMEM),
        }
    })())
}

/// getsockname(fd, adresse, longueur) : l'adresse locale (0.0.0.0:0 avant
/// `bind`), en 16 octets.
pub fn getsockname(fd: u64, adresse: u64, longueur: u64) -> i64 {
    en_i64((|| {
        let o = tenir(fd)?;
        let (a, port) = match o.socket().protocole {
            Protocole::Tcp => tcp::nom(o.socket()),
            _ => datagramme::nom(o.socket()),
        };
        rendre_adresse(&socket::sockaddr_in(a, port), adresse, longueur).map(|()| 0)
    })())
}

/// getpeername(fd, adresse, longueur) : l'adresse distante ; pas
/// connectée : ENOTCONN, avant de rien lire.
pub fn getpeername(fd: u64, adresse: u64, longueur: u64) -> i64 {
    en_i64((|| {
        let o = tenir(fd)?;
        let (a, port) = match o.socket().protocole {
            Protocole::Tcp => tcp::pair(o.socket()),
            _ => datagramme::pair(o.socket()),
        }
        .ok_or(-ENOTCONN)?;
        rendre_adresse(&socket::sockaddr_in(a, port), adresse, longueur).map(|()| 0)
    })())
}

/// Copie `octets` dans les morceaux du programme, à la suite ; rend ce qui
/// a été copié (au plus la place des morceaux). Une faute : EFAULT.
fn copier_vers_morceaux(morceaux: &[(u64, u64)], octets: &[u8]) -> Result<usize, i64> {
    let mut fait = 0;
    for &(base, longueur) in morceaux {
        if fait == octets.len() {
            break;
        }
        let n = (longueur as usize).min(octets.len() - fait);
        copier_vers_utilisateur(base, &octets[fait..fait + n]).map_err(|_| -EFAULT)?;
        fait += n;
    }
    Ok(fait)
}

/// Copie `octets` dans les morceaux du programme à partir de l'octet
/// `decalage` de leur suite ; rend ce qui a été copié. Une faute : EFAULT
/// si rien n'a été copié, sinon ce qui l'a été.
fn copier_vers_morceaux_depuis(morceaux: &[(u64, u64)], decalage: usize, octets: &[u8]) -> Result<usize, i64> {
    let (mut saute, mut fait) = (decalage, 0);
    for &(base, longueur) in morceaux {
        let longueur = longueur as usize;
        if saute >= longueur {
            saute -= longueur;
            continue;
        }
        let n = (longueur - saute).min(octets.len() - fait);
        let c = crate::copie_utilisateur::copier_vers_utilisateur_partiel(base + saute as u64, &octets[fait..fait + n]);
        fait += c;
        if c < n {
            return if fait == 0 { Err(-EFAULT) } else { Ok(fait) };
        }
        saute = 0;
        if fait == octets.len() {
            break;
        }
    }
    Ok(fait)
}

/// Remplit `destination` des morceaux du programme, à partir de l'octet
/// `decalage` de leur suite.
fn copier_des_morceaux(morceaux: &[(u64, u64)], decalage: usize, destination: &mut [u8]) -> Result<(), i64> {
    let (mut saute, mut fait) = (decalage, 0);
    for &(base, longueur) in morceaux {
        let longueur = longueur as usize;
        if saute >= longueur {
            saute -= longueur;
            continue;
        }
        let n = (longueur - saute).min(destination.len() - fait);
        copier_depuis_utilisateur(&mut destination[fait..fait + n], base + saute as u64).map_err(|_| -EFAULT)?;
        saute = 0;
        fait += n;
        if fait == destination.len() {
            break;
        }
    }
    Ok(())
}

/// La longueur totale des morceaux (déjà plafonnée à MAX_RW_COUNT).
fn total(morceaux: &[(u64, u64)]) -> usize {
    morceaux.iter().map(|&(_, l)| l as usize).sum()
}

/// Envoie les morceaux `morceaux` (le `sock_sendmsg` de Linux), à `nom`
/// (None : la destination de la connexion), avec `drapeaux` et les messages
/// de contrôle `controle`.
fn envoyer(o: &FichierTenu, nom: Option<&[u8]>, morceaux: &[(u64, u64)], mut drapeaux: u64, controle: Result<Controle, i64>) -> i64 {
    if non_bloquant(o) {
        drapeaux |= MSG_DONTWAIT;
    }
    let longueur = total(morceaux);
    let remplir = |decalage, d: &mut [u8]| copier_des_morceaux(morceaux, decalage, d);
    let r = match o.socket().protocole {
        Protocole::Udp => udp::envoyer(o.socket(), nom, longueur, drapeaux, controle, remplir),
        Protocole::Ping => ping::envoyer(o.socket(), nom, longueur, drapeaux, controle, remplir),
        // TCP : l'adresse donnée est ignorée (mesuré) ; EPIPE envoie aussi
        // SIGPIPE, sauf MSG_NOSIGNAL (`sk_stream_error`).
        Protocole::Tcp => {
            const MSG_NOSIGNAL: u64 = 0x4000;
            if let Err(e) = controle {
                return e;
            }
            let r = tcp::envoyer(o.socket(), longueur, drapeaux, remplir);
            if r == Err(-EPIPE) && drapeaux & MSG_NOSIGNAL == 0 {
                crate::signaux::au_fil_courant(13);
            }
            r
        }
    };
    en_i64(r.map(|n| n as i64))
}

/// Ce qu'a rendu une réception, et ce qu'il faut en dire au programme.
struct Reception {
    recu: socket::Recu,
    /// MSG_TRUNC, MSG_CTRUNC, MSG_ERRQUEUE.
    drapeaux: u32,
    /// L'erreur prise de la file d'erreurs (MSG_ERRQUEUE).
    erreur: Option<socket::ErreurEnFile>,
}

/// Reçoit dans les morceaux `morceaux` (le `sock_recvmsg`) : une socket de
/// ping refuse MSG_OOB avant tout (`ping_recvmsg` : EOPNOTSUPP ; UDP
/// l'ignore) ; MSG_ERRQUEUE : la première erreur de la file d'erreurs
/// (`ip_recv_error` : EAGAIN s'il n'y en a pas, sans attendre ; ce qu'elle
/// porte, coupé à la place donnée, MSG_TRUNC le dit ; l'adresse visée par
/// le paquet d'origine).
fn recevoir(o: &FichierTenu, morceaux: &[(u64, u64)], drapeaux: u64) -> Result<Reception, i64> {
    if drapeaux & MSG_OOB != 0 && o.socket().protocole == Protocole::Ping {
        return Err(-EOPNOTSUPP);
    }
    if drapeaux & MSG_ERRQUEUE != 0 {
        let e = o.socket().prendre_en_file().ok_or(-EAGAIN)?;
        let total = e.donnees.longueur();
        let copie = copier_vers_morceaux(morceaux, e.donnees.donnees())?;
        let recu = socket::Recu {
            vide: false, longueur: copie, source: e.adresse, port: e.port, destination: e.arrivee, interface: e.interface,
            coupe: copie < total,
        };
        let d = if recu.coupe { MSG_TRUNC } else { 0 } | MSG_ERRQUEUE as u32;
        return Ok(Reception { recu, drapeaux: d, erreur: Some(e) });
    }
    if o.socket().protocole == Protocole::Tcp && drapeaux & MSG_OOB != 0 {
        // L'octet urgent (`tcp_recv_urg`) : MSG_OOB dans `msg_flags`, et
        // MSG_TRUNC s'il n'y avait pas de place pour lui.
        let place = total(morceaux);
        let n = tcp::recevoir_urgent(o.socket(), drapeaux, place, |octet| copier_vers_morceaux(morceaux, &[octet]).map(|_| ()))?;
        let recu = socket::Recu { vide: true, longueur: n.unwrap_or(0), source: [0; 4], port: 0, destination: [0; 4], interface: 0, coupe: false };
        let d = if n.is_some() { MSG_OOB as u32 | if place == 0 { MSG_TRUNC } else { 0 } } else { 0 };
        return Ok(Reception { recu, drapeaux: d, erreur: None });
    }
    if o.socket().protocole == Protocole::Tcp {
        // Un flux : les octets à la suite dans les morceaux, sans émetteur
        // (`recvfrom` rend une adresse de longueur 0, mesuré).
        let n = tcp::recevoir_programme(o.socket(), total(morceaux), drapeaux, non_bloquant(o), |decalage, octets| {
            copier_vers_morceaux_depuis(morceaux, decalage, octets)
        })?;
        let recu = socket::Recu { vide: true, longueur: n, source: [0; 4], port: 0, destination: [0; 4], interface: 0, coupe: false };
        return Ok(Reception { recu, drapeaux: 0, erreur: None });
    }
    let recu = socket::prendre(o.socket(), drapeaux, non_bloquant(o), |octets| copier_vers_morceaux(morceaux, octets))?;
    let drapeaux = if recu.coupe { MSG_TRUNC } else { 0 };
    Ok(Reception { recu, drapeaux, erreur: None })
}

/// sendto(fd, tampon, longueur, drapeaux, adresse, longueur de l'adresse) :
/// le tampon vérifié d'abord (EFAULT), puis le descripteur, puis
/// l'adresse (si `adresse` n'est pas nulle : même vide, elle compte).
pub fn sendto(fd: u64, tampon: u64, longueur: u64, drapeaux: u64, adresse: u64, longueur_adresse: u64) -> i64 {
    let longueur = longueur.min(0x7fff_f000);
    if !crate::copie_utilisateur::dans_les_bornes(tampon, longueur) {
        return -EFAULT;
    }
    en_i64((|| {
        let o = tenir(fd)?;
        let a = if adresse != 0 { Some(copier_adresse(adresse, longueur_adresse)?) } else { None };
        Ok(envoyer(&o, a.as_ref().map(Adresse::octets), &[(tampon, longueur)], drapeaux as u32 as u64, Ok(Controle::default())))
    })())
}

/// recvfrom(fd, tampon, longueur, drapeaux, adresse, longueur de
/// l'adresse) : l'émetteur rendu si `adresse` n'est pas nulle, après la
/// réception (une faute là rend EFAULT, le datagramme pris).
pub fn recvfrom(fd: u64, tampon: u64, longueur: u64, drapeaux: u64, adresse: u64, longueur_adresse: u64) -> i64 {
    let longueur = longueur.min(0x7fff_f000);
    if !crate::copie_utilisateur::dans_les_bornes(tampon, longueur) {
        return -EFAULT;
    }
    en_i64((|| {
        let o = tenir(fd)?;
        let r = recevoir(&o, &[(tampon, longueur)], drapeaux as u32 as u64)?;
        if adresse != 0 {
            let source = socket::sockaddr_in(r.recu.source, r.recu.port);
            rendre_adresse(if r.recu.vide { &[] } else { &source }, adresse, longueur_adresse)?;
        }
        Ok(r.recu.longueur as i64)
    })())
}

/// Un `struct msghdr` lu du programme (`copy_msghdr_from_user`).
struct Message {
    nom: u64,
    longueur_nom: usize,
    morceaux: Vec<(u64, u64)>,
    controle: u64,
    longueur_controle: u64,
}

/// Lit le `msghdr` à `adresse` : une copie (EFAULT) ; sans nom, sa
/// longueur est 0 ; négative : EINVAL ; plus de 128 : 128 ; plus de 1024
/// morceaux : EMSGSIZE ; puis les morceaux (EINVAL, EFAULT).
fn lire_message(adresse: u64) -> Result<Message, i64> {
    let mut o = [0u8; 56];
    copier_depuis_utilisateur(&mut o, adresse).map_err(|_| -EFAULT)?;
    let mot = |i: usize| u64::from_le_bytes(o[i..i + 8].try_into().unwrap_or([0; 8]));
    let nom = mot(0);
    let mut longueur_nom = i32::from_le_bytes(o[8..12].try_into().unwrap_or([0; 4]));
    if nom == 0 {
        longueur_nom = 0;
    }
    if longueur_nom < 0 {
        return Err(-EINVAL);
    }
    let longueur_nom = (longueur_nom as usize).min(ADRESSE_MAX);
    let (iov, nombre) = (mot(16), mot(24));
    if nombre > 1024 {
        return Err(-EMSGSIZE);
    }
    let morceaux = appels_fichiers::morceaux(iov, nombre)?;
    Ok(Message { nom, longueur_nom, morceaux, controle: mot(32), longueur_controle: mot(40) })
}

/// L'en-tête d'un message de contrôle (`struct cmsghdr`) : sa longueur,
/// son niveau, sa sorte ; 16 octets.
const CMSG_ENTETE: usize = 16;

fn aligner(n: usize) -> usize {
    (n + 7) & !7
}

/// Les messages de contrôle d'un envoi (`ip_cmsg_send`, et
/// `__sock_cmsg_send` pour SOL_SOCKET), déjà copiés : chacun doit tenir
/// (`CMSG_OK` : EINVAL) ; SOL_IP : IP_PKTINFO (sa source), IP_TTL (1 à
/// 255), IP_TOS (un entier ou un octet, 0 à 255), un autre : EINVAL ;
/// SOL_SOCKET : SCM_RIGHTS et SCM_CREDENTIALS ignorés (ceux d'AF_UNIX), un
/// autre : EINVAL (un écart pour SO_MARK, SO_PRIORITY, l'horodatage :
/// Linux les prend) ; SOL_UDP : EINVAL (UDP_SEGMENT : un écart) ; un autre
/// niveau est ignoré.
fn lire_controle(c: &[u8]) -> Result<Controle, i64> {
    let mut r = Controle::default();
    let mut i = 0;
    while c.len() >= i + CMSG_ENTETE {
        let longueur = u64::from_le_bytes(c[i..i + 8].try_into().unwrap_or([0; 8])) as usize;
        if longueur < CMSG_ENTETE || longueur > c.len() - i {
            return Err(-EINVAL);
        }
        let niveau = i32::from_le_bytes(c[i + 8..i + 12].try_into().unwrap_or([0; 4]));
        let sorte = i32::from_le_bytes(c[i + 12..i + 16].try_into().unwrap_or([0; 4]));
        let d = &c[i + CMSG_ENTETE..i + longueur];
        let entier = || -> Result<i32, i64> {
            if d.len() != 4 {
                return Err(-EINVAL);
            }
            Ok(i32::from_le_bytes([d[0], d[1], d[2], d[3]]))
        };
        match (niveau, sorte) {
            (SOL_IP, IP_PKTINFO) => {
                if d.len() != 12 {
                    return Err(-EINVAL);
                }
                r.interface = Some(i32::from_le_bytes([d[0], d[1], d[2], d[3]]) as u32);
                r.source = Some([d[4], d[5], d[6], d[7]]);
            }
            (SOL_IP, IP_TTL) => match entier()? {
                v @ 1..=255 => r.ttl = Some(v as u8),
                _ => return Err(-EINVAL),
            },
            (SOL_IP, IP_TOS) => {
                let v = if d.len() == 1 { d[0] as i32 } else { entier()? };
                if !(0..=255).contains(&v) {
                    return Err(-EINVAL);
                }
                r.tos = Some(v as u8);
            }
            (SOL_IP, _) | (SOL_UDP, _) => return Err(-EINVAL),
            (SOL_SOCKET, SCM_RIGHTS | SCM_CREDENTIALS) => {}
            (SOL_SOCKET, _) => return Err(-EINVAL),
            _ => {}
        }
        i += aligner(longueur);
    }
    Ok(r)
}

/// Envoie un `msghdr` déjà lu (`____sys_sendmsg`) : ses messages de
/// contrôle copiés (plus d'`optmem_max`, 128 Kio : ENOBUFS, avant d'allouer
/// quoi que ce soit, comme `sock_kmalloc` ; EFAULT), puis l'envoi.
fn envoyer_message(o: &FichierTenu, m: &Message, drapeaux: u64) -> i64 {
    let nom = if m.longueur_nom > 0 {
        match copier_adresse(m.nom, m.longueur_nom as u64) {
            Ok(a) => Some(a),
            Err(e) => return e,
        }
    } else {
        None
    };
    let controle = if m.longueur_controle > 0 {
        if m.longueur_controle > OPTMEM_MAX {
            return -ENOBUFS;
        }
        let Ok(mut c) = faillible::remplie(m.longueur_controle as usize, 0) else { return -ENOMEM };
        if copier_depuis_utilisateur(&mut c, m.controle).is_err() {
            return -EFAULT;
        }
        lire_controle(&c)
    } else {
        Ok(Controle::default())
    };
    envoyer(o, nom.as_ref().map(Adresse::octets), &m.morceaux, drapeaux, controle)
}

/// sendmsg(fd, message, drapeaux) : MSG_CMSG_COMPAT (EINVAL), le
/// descripteur, puis le `msghdr`.
pub fn sendmsg(fd: u64, message: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & MSG_CMSG_COMPAT != 0 {
        return -EINVAL;
    }
    en_i64((|| {
        let o = tenir(fd)?;
        let m = lire_message(message)?;
        Ok(envoyer_message(&o, &m, drapeaux))
    })())
}

/// sendmmsg(fd, messages, nombre, drapeaux) (`__sys_sendmmsg`) :
/// MSG_CMSG_COMPAT (EINVAL), le descripteur ; au plus 1024 messages ;
/// chacun envoyé, sa longueur écrite dans son `msg_len` ; arrêté à la
/// première erreur ; rend le nombre envoyé, ou l'erreur si aucun ne l'a
/// été.
pub fn sendmmsg(fd: u64, messages: u64, nombre: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & MSG_CMSG_COMPAT != 0 {
        return -EINVAL;
    }
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let nombre = (nombre as u32).min(1024) as u64;
    let mut faits = 0;
    let mut erreur = 0;
    for k in 0..nombre {
        let entree = messages + k * 64;
        let r = match lire_message(entree) {
            Ok(m) => envoyer_message(&o, &m, drapeaux),
            Err(e) => e,
        };
        if r < 0 {
            erreur = r;
            break;
        }
        if copier_vers_utilisateur(entree + 56, &(r as u32).to_le_bytes()).is_err() {
            erreur = -EFAULT;
            break;
        }
        faits += 1;
    }
    if faits > 0 { faits } else { erreur }
}

/// Les messages de contrôle d'une réception, écrits à la suite dans la
/// place du programme (`put_cmsg`) : un qui ne tient pas est coupé (ou
/// omis s'il n'y a pas même la place de son en-tête), et MSG_CTRUNC le dit.
struct ControleSortant {
    adresse: u64,
    place: u64,
    utilise: u64,
}

impl ControleSortant {
    /// Une faute en l'écrivant ne fait rien : il n'est pas compté (Linux
    /// ignore ce que rend `put_cmsg` sur ce chemin ; l'appel réussit, la
    /// place prise ne bouge pas).
    fn ecrire(&mut self, niveau: i32, sorte: i32, donnees: &[u8], drapeaux: &mut u32) {
        let reste = self.place - self.utilise;
        if self.adresse == 0 || reste < CMSG_ENTETE as u64 {
            *drapeaux |= MSG_CTRUNC;
            return;
        }
        let mut longueur = (CMSG_ENTETE + donnees.len()) as u64;
        if reste < longueur {
            *drapeaux |= MSG_CTRUNC;
            longueur = reste;
        }
        let mut o = [0u8; CMSG_ENTETE + 32];
        o[..8].copy_from_slice(&longueur.to_le_bytes());
        o[8..12].copy_from_slice(&niveau.to_le_bytes());
        o[12..16].copy_from_slice(&sorte.to_le_bytes());
        o[16..16 + donnees.len()].copy_from_slice(donnees);
        if copier_vers_utilisateur(self.adresse + self.utilise, &o[..longueur as usize]).is_err() {
            return;
        }
        self.utilise += (aligner(CMSG_ENTETE + donnees.len()) as u64).min(reste);
    }
}

/// Reçoit dans un `msghdr` déjà lu, à `adresse` (`____sys_recvmsg`) :
/// l'émetteur (si le message a un nom), IP_PKTINFO si la socket le
/// demande, puis `msg_flags` et la place prise par les messages de
/// contrôle. Rend la longueur reçue.
fn recevoir_message(o: &FichierTenu, adresse: u64, m: &Message, drapeaux: u64) -> i64 {
    let mut r = match recevoir(o, &m.morceaux, drapeaux) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if m.nom != 0 {
        let source = socket::sockaddr_in(r.recu.source, r.recu.port);
        if let Err(e) = rendre_adresse(if r.recu.vide { &[] } else { &source }, m.nom, adresse + 8) {
            return e;
        }
    }
    // MSG_CMSG_CLOEXEC demandé revient dans msg_flags (`____sys_recvmsg`).
    r.drapeaux |= (drapeaux & MSG_CMSG_CLOEXEC) as u32;
    let mut c = ControleSortant { adresse: m.controle, place: m.longueur_controle, utilise: 0 };
    // IP_PKTINFO : pour un datagramme ; pour une erreur, seulement si elle
    // vient d'ICMP (`ipv4_datagram_support_cmsg`), celui de son message.
    let icmp = r.erreur.as_ref().is_none_or(|e| e.origine == socket::ORIGINE_ICMP);
    if o.socket().appels.verrouiller().options.pktinfo && !r.recu.vide && icmp {
        use crate::reseau::ipv4;
        // in_pktinfo : l'interface d'arrivée, l'adresse locale à laquelle
        // répondre, la destination. Pour un datagramme, ce que prépare
        // `ipv4_pktinfo_prepare` : venu par lo à l'une de nos adresses d'une
        // carte, l'interface qui porte l'adresse ; l'adresse locale, la
        // destination, ou pour une diffusion celle qu'aurait la réponse
        // (`fib_compute_spec_dst`). Pour une erreur, `ip_recv_error` rend le
        // contrôle du message ICMP, que rien n'a préparé : l'interface
        // d'arrivée telle quelle, et 0.0.0.0 (le `faddr` de ses options IP).
        let (interface, locale) = if r.erreur.is_some() {
            (r.recu.interface, [0; 4])
        } else {
            let lo = crate::reseau::boucle::interface().map(|i| i.index);
            let interface = match ipv4::interface_de_l_adresse(r.recu.destination) {
                Some(k) if Some(r.recu.interface) == lo => k,
                _ => r.recu.interface,
            };
            let locale = if ipv4::avec_table(|t| t.est_a_nous(r.recu.destination)).unwrap_or(false) {
                r.recu.destination
            } else {
                ipv4::router(r.recu.source, None).map_or([0; 4], |(c, _)| ipv4::source(&c))
            };
            (interface, locale)
        };
        let mut info = [0u8; 12];
        info[..4].copy_from_slice(&(interface as i32).to_le_bytes());
        info[4..8].copy_from_slice(&locale);
        info[8..12].copy_from_slice(&r.recu.destination);
        c.ecrire(SOL_IP, IP_PKTINFO, &info, &mut r.drapeaux);
    }
    // L'erreur elle-même (IP_RECVERR) : sa `sock_extended_err` (errno,
    // origine, genre, code, un octet nul, info, data nul), puis
    // SO_EE_OFFENDER, l'adresse de qui l'a dite (nulle pour une erreur
    // locale).
    if let Some(e) = &r.erreur {
        let mut o = [0u8; 32];
        o[..4].copy_from_slice(&e.errno.to_le_bytes());
        o[4] = e.origine;
        o[5] = e.genre;
        o[6] = e.code;
        o[8..12].copy_from_slice(&e.info.to_le_bytes());
        if e.origine == socket::ORIGINE_ICMP {
            o[16..32].copy_from_slice(&socket::sockaddr_in(e.emetteur, 0));
        }
        c.ecrire(SOL_IP, IP_RECVERR, &o, &mut r.drapeaux);
    }
    if copier_vers_utilisateur(adresse + 48, &r.drapeaux.to_le_bytes()).is_err()
        || copier_vers_utilisateur(adresse + 40, &c.utilise.to_le_bytes()).is_err() {
        return -EFAULT;
    }
    r.recu.longueur as i64
}

/// recvmsg(fd, message, drapeaux).
pub fn recvmsg(fd: u64, message: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & MSG_CMSG_COMPAT != 0 {
        return -EINVAL;
    }
    en_i64((|| {
        let o = tenir(fd)?;
        let m = lire_message(message)?;
        Ok(recevoir_message(&o, message, &m, drapeaux))
    })())
}

/// recvmmsg(fd, messages, nombre, drapeaux, délai) (`do_recvmmsg`) :
/// MSG_CMSG_COMPAT (EINVAL), le délai lu (EFAULT, EINVAL), le
/// descripteur ; l'erreur en attente rendue d'abord (sauf MSG_ERRQUEUE) ; puis chaque
/// message reçu, sa longueur dans son `msg_len` ; MSG_WAITFORONE : sans
/// attendre après le premier ; le délai n'est regardé qu'entre deux
/// messages (une bizarrerie de Linux, que dit sa page de manuel), et ce
/// qu'il en reste est réécrit. Une erreur après des messages est gardée
/// pour l'appel suivant (`sk_err`), sauf EAGAIN.
pub fn recvmmsg(fd: u64, messages: u64, nombre: u64, drapeaux: u64, delai: u64) -> i64 {
    let mut drapeaux = drapeaux as u32 as u64;
    if drapeaux & MSG_CMSG_COMPAT != 0 {
        return -EINVAL;
    }
    let echeance = if delai != 0 {
        let mut t = [0u8; 16];
        if copier_depuis_utilisateur(&mut t, delai).is_err() {
            return -EFAULT;
        }
        let (s, ns) = (i64::from_le_bytes(t[..8].try_into().unwrap_or([0; 8])), i64::from_le_bytes(t[8..].try_into().unwrap_or([0; 8])));
        if s < 0 || !(0..1_000_000_000).contains(&ns) {
            return -EINVAL;
        }
        Some(temps::ns_monotone().saturating_add((s as u64).saturating_mul(1_000_000_000)).saturating_add(ns as u64))
    } else {
        None
    };
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let s = o.socket();
    let mut faits: i64 = 0;
    let mut erreur = 0;
    if drapeaux & MSG_ERRQUEUE == 0 {
        let e = s.prendre_erreur();
        if e != 0 {
            return -(e as i64);
        }
    }
    let mut reste = None;
    while (faits as u64) < nombre as u32 as u64 {
        let entree = messages + faits as u64 * 64;
        let r = match lire_message(entree) {
            Ok(m) => recevoir_message(&o, entree, &m, drapeaux & !MSG_WAITFORONE),
            Err(e) => e,
        };
        if r < 0 {
            erreur = r;
            break;
        }
        if copier_vers_utilisateur(entree + 56, &(r as u32).to_le_bytes()).is_err() {
            erreur = -EFAULT;
            break;
        }
        faits += 1;
        if drapeaux & MSG_WAITFORONE != 0 {
            drapeaux |= MSG_DONTWAIT;
        }
        if let Some(e) = echeance {
            let maintenant = temps::ns_monotone();
            let r = e.saturating_sub(maintenant);
            reste = Some(r);
            if r == 0 {
                break;
            }
        }
    }
    if let Some(r) = reste {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&((r / 1_000_000_000) as i64).to_le_bytes());
        t[8..].copy_from_slice(&((r % 1_000_000_000) as i64).to_le_bytes());
        if faits > 0 && copier_vers_utilisateur(delai, &t).is_err() {
            return -EFAULT;
        }
    }
    if erreur == 0 {
        return faits;
    }
    if faits == 0 {
        return erreur;
    }
    if erreur != -EAGAIN {
        s.reception.verrouiller().erreur = -erreur as i32;
    }
    faits
}

/// shutdown(fd, comment) (`inet_shutdown`) : 0, 1, 2 (SHUT_RD, SHUT_WR,
/// SHUT_RDWR), un autre : EINVAL ; une socket non connectée rend ENOTCONN,
/// MAIS ses drapeaux sont posés quand même (« pour réveiller ceux qui
/// attendent », dit Linux) : un `recv` bloqué rend 0, un `send` EPIPE. Tous
/// ceux qui attendent sont réveillés.
pub fn shutdown(fd: u64, comment: u64) -> i64 {
    let o = match tenir(fd) {
        Ok(o) => o,
        Err(e) => return e,
    };
    let comment = (comment as i32).wrapping_add(1);
    if comment & !3 != 0 || comment == 0 {
        return -EINVAL;
    }
    let s = o.socket();
    let mut arret = 0;
    if comment & 1 != 0 {
        arret |= ARRET_LECTURE;
    }
    if comment & 2 != 0 {
        arret |= ARRET_ECRITURE;
    }
    if s.protocole == Protocole::Tcp {
        return en_i64(tcp::arreter(s, arret).map(|()| 0));
    }
    let connecte = s.appels.verrouiller().connecte;
    s.arreter(arret);
    if connecte { 0 } else { -ENOTCONN }
}

/// Lit l'entier d'une option (au moins 4 octets : EINVAL ; EFAULT).
fn entier(valeur: u64, longueur: i32) -> Result<i32, i64> {
    if longueur < 4 {
        return Err(-EINVAL);
    }
    let mut o = [0u8; 4];
    copier_depuis_utilisateur(&mut o, valeur).map_err(|_| -EFAULT)?;
    Ok(i32::from_le_bytes(o))
}

/// Lit un délai (SO_RCVTIMEO, SO_SNDTIMEO : une `timeval` de 16 octets, au
/// moins : EINVAL), comme `sock_set_timeout` : des microsecondes hors de
/// [0, 10⁶[ : EDOM ; des secondes négatives : 0 (ne pas attendre) ; 0 :
/// sans délai ; sinon arrondi au tic supérieur.
fn delai(valeur: u64, longueur: i32) -> Result<Option<u64>, i64> {
    if longueur < 16 {
        return Err(-EINVAL);
    }
    let mut o = [0u8; 16];
    copier_depuis_utilisateur(&mut o, valeur).map_err(|_| -EFAULT)?;
    let s = i64::from_le_bytes(o[..8].try_into().unwrap_or([0; 8]));
    let us = i64::from_le_bytes(o[8..].try_into().unwrap_or([0; 8]));
    if !(0..1_000_000).contains(&us) {
        return Err(-EDOM);
    }
    if s < 0 {
        return Ok(Some(0));
    }
    if s == 0 && us == 0 {
        return Ok(None);
    }
    let tics = (s as u64).saturating_mul(1000).saturating_add((us as u64).div_ceil(1000));
    Ok(Some(tics.saturating_mul(TIC)))
}

/// La priorité qu'implique un TOS (le `rt_tos2priority` de Linux, sa
/// table `ip_tos2prio`) : IP_TOS change aussi SO_PRIORITY.
fn priorite_du_tos(tos: u8) -> u32 {
    const TABLE: [u32; 16] = [0, 0, 0, 0, 2, 2, 2, 2, 6, 6, 6, 6, 4, 4, 4, 4];
    TABLE[((tos & 0x1e) >> 1) as usize]
}

/// setsockopt(fd, niveau, option, valeur, longueur) (`do_sock_setsockopt`) :
/// une longueur négative : EINVAL ; SOL_SOCKET (`sk_setsockopt`) ; SOL_UDP
/// (`udp_lib_setsockopt` : ENOPROTOOPT, un écart pour UDP_CORK et ses
/// voisines) ; SOL_IP (`do_ip_setsockopt`) ; un autre niveau : ENOPROTOOPT.
pub fn setsockopt(fd: u64, niveau: u64, option: u64, valeur: u64, longueur: u64) -> i64 {
    let (niveau, option, longueur) = (niveau as i32, option as i32, longueur as i32);
    en_i64((|| {
        let o = tenir(fd)?;
        if longueur < 0 {
            return Err(-EINVAL);
        }
        let s = o.socket();
        match niveau {
            SOL_SOCKET => options_socket(s, option, valeur, longueur),
            // SOL_UDP n'est pas un niveau d'une socket de ping (elle va
            // droit à IP : ENOPROTOOPT sans rien lire).
            SOL_UDP if s.protocole == Protocole::Udp => {
                entier(valeur, longueur)?;
                Err(-ENOPROTOOPT)
            }
            SOL_IP => options_ip(s, option, valeur, longueur),
            SOL_TCP if s.protocole == Protocole::Tcp => options_tcp(s, option, valeur, longueur),
            _ => Err(-ENOPROTOOPT),
        }
        .map(|()| 0)
    })())
}

/// Les options de SOL_SOCKET, dans l'ordre de `sk_setsockopt` : une valeur
/// d'au moins 4 octets (EINVAL), lue (EFAULT), puis l'option.
fn options_socket(s: &Socket, option: i32, valeur: u64, longueur: i32) -> Result<(), i64> {
    let v = entier(valeur, longueur)?;
    let oui = v != 0;
    // SO_PRIORITY et SO_RCVLOWAT, sans le verrou de la socket (Linux non
    // plus).
    match option {
        // 0 à 6 pour tous ; au-delà, CAP_NET_ADMIN (root).
        SO_PRIORITY => {
            if !(0..=6).contains(&v) && s.uid != 0 {
                return Err(-EPERM);
            }
            s.appels.verrouiller().options.priority = v as u32;
            return Ok(());
        }
        // Négatif : le plus grand ; 0 se relit 1.
        SO_RCVLOWAT => {
            let v = if v < 0 { i32::MAX as u32 } else { (v as u32).max(1) };
            s.appels.verrouiller().options.rcvlowat = v;
            if s.protocole == Protocole::Tcp {
                tcp::avec_options(s, |op, _| op.rcvlowat = v);
            }
            return Ok(());
        }
        _ => {}
    }
    let mut inet = s.appels.verrouiller();
    let op = &mut inet.options;
    match option {
        SO_DEBUG if oui && s.uid != 0 => return Err(-EACCES),
        SO_DEBUG => op.debug = oui,
        SO_DONTROUTE => op.dontroute = oui,
        SO_OOBINLINE => op.oobinline = oui,
        SO_NO_CHECK => op.no_check = oui,
        SO_BSDCOMPAT => {}
        SO_REUSEADDR | SO_REUSEPORT => {
            if option == SO_REUSEADDR {
                op.reuseaddr = oui;
            } else {
                op.reuseport = oui;
            }
            datagramme::table::reutilisation_changee(s, &inet);
        }
        SO_BROADCAST => op.broadcast = oui,
        SO_KEEPALIVE => op.keepalive = oui,
        // Bornés par `wmem_max` et `rmem_max` (comparés sans signe : un
        // négatif devient le plafond), puis doublés (la place des
        // structures du noyau, dit Linux), au moins les minimums.
        SO_SNDBUF => {
            let v = (v as u32).min(TAMPON_MAX).min(i32::MAX as u32 / 2);
            s.sndbuf.store((v * 2).max(SNDBUF_MIN), Ordering::Relaxed);
        }
        SO_RCVBUF => {
            let v = (v as u32).min(TAMPON_MAX).min(i32::MAX as u32 / 2);
            s.rcvbuf.store((v * 2).max(RCVBUF_MIN), Ordering::Relaxed);
        }
        SO_LINGER => {
            if longueur < 8 {
                return Err(-EINVAL);
            }
            let mut l = [0u8; 8];
            copier_depuis_utilisateur(&mut l, valeur).map_err(|_| -EFAULT)?;
            let marche = i32::from_le_bytes([l[0], l[1], l[2], l[3]]) != 0;
            op.linger = (marche, if marche { u32::from_le_bytes([l[4], l[5], l[6], l[7]]) } else { op.linger.1 });
        }
        SO_RCVTIMEO | SO_RCVTIMEO_NEW => op.rcvtimeo = delai(valeur, longueur)?,
        SO_SNDTIMEO | SO_SNDTIMEO_NEW => op.sndtimeo = delai(valeur, longueur)?,
        _ => return Err(-ENOPROTOOPT),
    }
    let (keepalive, oobinline) = (inet.options.keepalive, inet.options.oobinline);
    drop(inet);
    if s.protocole == Protocole::Tcp && matches!(option, SO_RCVBUF | SO_SNDBUF) {
        tcp::tampons_changes(s, option == SO_SNDBUF, option == SO_RCVBUF);
    }
    if s.protocole == Protocole::Tcp && matches!(option, SO_KEEPALIVE | SO_OOBINLINE) {
        tcp::options_socket_changees(s, keepalive, oobinline);
    }
    Ok(())
}

/// Les options de SOL_TCP (`do_tcp_setsockopt`), sous la possession de la
/// socket : TCP_CONGESTION, une chaîne (seul « reno » existe : ENOENT
/// sinon) ; les autres, un entier d'au moins 4 octets (EINVAL), avec les
/// bornes de Linux (mesurées) ; une inconnue : ENOPROTOOPT.
fn options_tcp(s: &Arc<Socket>, option: i32, valeur: u64, longueur: i32) -> Result<(), i64> {
    const ENOENT: i64 = 2;
    if option == TCP_CONGESTION {
        let mut nom = [0u8; 16];
        let n = (longueur.max(0) as usize).min(15);
        copier_depuis_utilisateur(&mut nom[..n], valeur).map_err(|_| -EFAULT)?;
        let fin = nom[..n].iter().position(|&o| o == 0).unwrap_or(n);
        return if &nom[..fin] == b"reno" { Ok(()) } else { Err(-ENOENT) };
    }
    let v = entier(valeur, longueur)?;
    tcp::avec_options(s, |op, mut tcb| {
        match option {
            TCP_NODELAY => op.nodelay = v != 0,
            TCP_CORK => op.cork = v != 0,
            TCP_MAXSEG => {
                if v != 0 && !(88..=32767).contains(&v) {
                    return Err(-EINVAL);
                }
                op.maxseg = v as u16;
                if let Some(t) = tcb.as_deref_mut() {
                    t.mss_utilisateur = v as u16;
                }
            }
            TCP_KEEPIDLE | TCP_KEEPINTVL => {
                if !(1..=32767).contains(&v) {
                    return Err(-EINVAL);
                }
                if option == TCP_KEEPIDLE { op.keepidle = v as u32 } else { op.keepintvl = v as u32 }
            }
            TCP_KEEPCNT | TCP_SYNCNT => {
                if !(1..=127).contains(&v) {
                    return Err(-EINVAL);
                }
                if option == TCP_KEEPCNT { op.keepcnt = v as u32 } else { op.syncnt = v as u32 }
            }
            // Négatif : pas d'attente en FIN_WAIT_2 (RST) ; au plus 120 s
            // (TCP_FIN_TIMEOUT_MAX) ; 0 : celui du système (60 s).
            TCP_LINGER2 => op.linger2 = if v < 0 { -1 } else { v.min(120) },
            // Gardé en retransmissions de SYN-ACK, comme Linux
            // (`secs_to_retrans`) : il se relit arrondi au délai qu'elles
            // couvrent (5 s → 7 s). Sans effet chez nous : la fille est
            // donnée à accept dès sa poignée de main (un écart écrit).
            TCP_DEFER_ACCEPT => op.defer_accept = secondes_en_essais(v),
            TCP_QUICKACK => {
                op.quickack = v != 0;
                if let Some(t) = tcb.as_deref_mut() {
                    t.quickack(v != 0);
                }
            }
            TCP_USER_TIMEOUT => {
                if v < 0 {
                    return Err(-EINVAL);
                }
                op.user_timeout = v as u32;
            }
            _ => return Err(-ENOPROTOOPT),
        }
        // Ce que la connexion en retient (TCP_SYNCNT, TCP_USER_TIMEOUT,
        // TCP_NODELAY, TCP_CORK, le keepalive), et ce que cela change.
        if let Some(t) = tcb {
            t.regler(op.reglages(t.reglages.orpheline), crate::temps::ns_monotone());
        }
        Ok(())
    })
}

/// La valeur d'une option de SOL_TCP (`do_tcp_getsockopt`), et sa
/// longueur : un entier ; TCP_CONGESTION, son nom ; TCP_INFO, la
/// `struct tcp_info` jusqu'à `tcpi_total_retrans` (104 octets : les champs
/// que nous tenons, zéro ailleurs).
fn lire_option_tcp(s: &Arc<Socket>, option: i32) -> Result<([u8; 104], usize), i64> {
    let mut o = [0u8; 104];
    let ecoute = tcp::ecoute(s);
    let n = tcp::avec_options(s, |op, tcb| {
        let v = match option {
            TCP_NODELAY => op.nodelay as i32,
            TCP_CORK => op.cork as i32,
            TCP_MAXSEG => tcb.map_or(if op.maxseg != 0 { op.maxseg } else { inet::tcp::MSS_DEFAUT }, |t| t.mss()) as i32,
            TCP_KEEPIDLE => op.keepidle as i32,
            TCP_KEEPINTVL => op.keepintvl as i32,
            TCP_KEEPCNT => op.keepcnt as i32,
            // 0 : celui du système, `tcp_syn_retries`.
            TCP_SYNCNT => if op.syncnt == 0 { inet::tcp::SYN_ESSAIS as i32 } else { op.syncnt as i32 },
            TCP_LINGER2 => if op.linger2 == 0 { 60 } else { op.linger2 },
            TCP_DEFER_ACCEPT => essais_en_secondes(op.defer_accept),
            TCP_QUICKACK => op.quickack as i32,
            TCP_USER_TIMEOUT => op.user_timeout as i32,
            TCP_CONGESTION => {
                o[..4].copy_from_slice(b"reno");
                return Ok(16);
            }
            TCP_INFO => {
                match tcb {
                    Some(t) => {
                        let mut i = t.info(crate::temps::ns_monotone());
                        // TIME_WAIT est, vu de la socket, TCP_CLOSE (la
                        // connexion est passée à sa petite structure).
                        if t.etat() == inet::tcp::Etat::TempsAttente {
                            i.etat = 7;
                        }
                        ecrire_info(&mut o, &i)
                    }
                    // TCP_LISTEN, ou TCP_CLOSE.
                    None => o[0] = if ecoute { 10 } else { 7 },
                }
                return Ok(104);
            }
            _ => return Err(-ENOPROTOOPT),
        };
        o[..4].copy_from_slice(&v.to_le_bytes());
        Ok(4)
    })?;
    Ok((o, n))
}

/// TCP_DEFER_ACCEPT en retransmissions de SYN-ACK (`secs_to_retrans` : la
/// première après 1 s, chacune doublant, au plus 120 s).
fn secondes_en_essais(secondes: i32) -> u32 {
    let (mut essais, mut delai, mut periode) = (0u32, 1i32, 1i32);
    if secondes > 0 {
        essais = 1;
        while secondes > periode && essais < 255 {
            essais += 1;
            delai = (delai * 2).min(120);
            periode += delai;
        }
    }
    essais
}

/// Et en secondes (`retrans_to_secs`).
fn essais_en_secondes(essais: u32) -> i32 {
    let (mut periode, mut delai) = (0i32, 1i32);
    if essais > 0 {
        periode = 1;
        for _ in 1..essais {
            delai = (delai * 2).min(120);
            periode += delai;
        }
    }
    periode
}

/// La `struct tcp_info` de Linux jusqu'à `tcpi_total_retrans` (104
/// octets) : les champs que nous tenons, zéro ailleurs (SACK, les pertes
/// comptées par SACK, `tcpi_last_ack_sent` que Linux laisse aussi à 0).
fn ecrire_info(o: &mut [u8; 104], i: &inet::tcp::Info) {
    o[..8].copy_from_slice(&[i.etat, i.phase, i.retransmissions, i.sondes, i.recul, i.options, i.echelle_envoi | i.echelle_reception << 4, 0]);
    let mots = [
        (8, i.rto), (12, i.ato), (16, i.snd_mss), (20, i.rcv_mss), (24, i.non_acquittes), (36, i.retransmis),
        (44, i.dernier_envoi), (52, i.dernier_recu), (56, i.dernier_ack), (60, i.advmss + 40), (68, i.rtt), (72, i.rttvar),
        (76, i.ssthresh), (80, i.cwnd), (84, i.advmss), (88, i.reordonnancement), (100, i.total_retrans),
    ];
    for (decalage, v) in mots {
        o[decalage..decalage + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// Les options de SOL_IP (`do_ip_setsockopt`) : la valeur lue en entier
/// (4 octets ou plus), ou en octet (1 à 3), ou 0 (longueur nulle) ; puis
/// l'option. IP_OPTIONS, la multidiffusion, IP_RECVTTL et les autres :
/// ENOPROTOOPT, un écart écrit.
fn options_ip(s: &Socket, option: i32, valeur: u64, longueur: i32) -> Result<(), i64> {
    let v = if longueur >= 4 {
        entier(valeur, longueur)?
    } else if longueur >= 1 {
        let mut o = [0u8; 1];
        copier_depuis_utilisateur(&mut o, valeur).map_err(|_| -EFAULT)?;
        o[0] as i32
    } else {
        0
    };
    let mut inet = s.appels.verrouiller();
    let op = &mut inet.options;
    match option {
        IP_PKTINFO => op.pktinfo = v != 0,
        // Retiré, il vide la file d'erreurs (`skb_errqueue_purge`). Sa copie
        // atomique, pour la tâche du réseau.
        IP_RECVERR => {
            op.recverr = v != 0;
            s.recverr.store(v != 0, Ordering::Relaxed);
            if v == 0 {
                s.vider_erreurs();
            }
        }
        // La priorité ne suit que si le TOS change (`__ip_sock_set_tos`).
        IP_TOS if op.tos != v as u8 => {
            op.tos = v as u8;
            op.priority = priorite_du_tos(v as u8);
        }
        IP_TOS => {}
        IP_TTL => {
            if longueur < 1 || (v != -1 && !(1..=255).contains(&v)) {
                return Err(-EINVAL);
            }
            op.ttl = if v == -1 { None } else { Some(v as u8) };
        }
        IP_MTU_DISCOVER => {
            if !(0..=IP_PMTUDISC_OMIT).contains(&v) {
                return Err(-EINVAL);
            }
            op.pmtudisc = v as u8;
            s.pmtudisc.store(v as u8, Ordering::Relaxed);
        }
        _ => return Err(-ENOPROTOOPT),
    }
    // TCP émet ses segments sans le Mutex : ses copies d'IP_TTL et d'IP_TOS.
    let (ttl, tos) = (op.ttl.unwrap_or(64), op.tos);
    drop(inet);
    if s.protocole == Protocole::Tcp && matches!(option, IP_TTL | IP_TOS) {
        tcp::avec_options(s, |o, _| {
            o.ttl = ttl;
            o.tos = tos;
        });
    }
    Ok(())
}

/// getsockopt(fd, niveau, option, valeur, longueur) (`do_sock_getsockopt`) :
/// SOL_SOCKET (`sk_getsockopt`) ; SOL_UDP : la longueur lue (EFAULT,
/// EINVAL), puis ENOPROTOOPT (un écart) ; un autre niveau va à IP
/// (`do_ip_getsockopt`), qui rend EOPNOTSUPP pour ce qui n'est pas SOL_IP.
pub fn getsockopt(fd: u64, niveau: u64, option: u64, valeur: u64, longueur: u64) -> i64 {
    let (niveau, option) = (niveau as i32, option as i32);
    en_i64((|| {
        let o = tenir(fd)?;
        let s = o.socket();
        let mut l = [0u8; 4];
        let lire_longueur = |l: &mut [u8; 4]| -> Result<i32, i64> {
            copier_depuis_utilisateur(l, longueur).map_err(|_| -EFAULT)?;
            let n = i32::from_le_bytes(*l);
            if n < 0 { Err(-EINVAL) } else { Ok(n) }
        };
        match niveau {
            SOL_SOCKET => {
                let place = lire_longueur(&mut l)?;
                let v = lire_option_socket(s, option)?;
                let n = (place as usize).min(v.1);
                copier_vers_utilisateur(valeur, &v.0[..n]).map_err(|_| -EFAULT)?;
                copier_vers_utilisateur(longueur, &(n as i32).to_le_bytes()).map_err(|_| -EFAULT)?;
                Ok(0)
            }
            SOL_UDP if s.protocole == Protocole::Udp => {
                lire_longueur(&mut l)?;
                Err(-ENOPROTOOPT)
            }
            SOL_TCP if s.protocole == Protocole::Tcp => {
                let place = lire_longueur(&mut l)?;
                let (v, n) = lire_option_tcp(s, option)?;
                let n = (place as usize).min(n);
                copier_vers_utilisateur(valeur, &v[..n]).map_err(|_| -EFAULT)?;
                copier_vers_utilisateur(longueur, &(n as i32).to_le_bytes()).map_err(|_| -EFAULT)?;
                Ok(0)
            }
            SOL_IP => {
                let place = lire_longueur(&mut l)?;
                let v = lire_option_ip(s, option)?;
                // Une place de 1 à 3 octets, et une valeur qui tient dans un
                // octet : un octet (`copyval`).
                if place > 0 && place < 4 && (0..=255).contains(&v) {
                    copier_vers_utilisateur(longueur, &1i32.to_le_bytes()).map_err(|_| -EFAULT)?;
                    copier_vers_utilisateur(valeur, &[v as u8]).map_err(|_| -EFAULT)?;
                } else {
                    let n = (place as usize).min(4);
                    copier_vers_utilisateur(longueur, &(n as i32).to_le_bytes()).map_err(|_| -EFAULT)?;
                    copier_vers_utilisateur(valeur, &v.to_le_bytes()[..n]).map_err(|_| -EFAULT)?;
                }
                Ok(0)
            }
            _ => Err(-EOPNOTSUPP),
        }
    })())
}

/// La valeur d'une option de SOL_SOCKET, et sa longueur (un entier, sauf
/// SO_LINGER et les délais) ; une inconnue : ENOPROTOOPT.
fn lire_option_socket(s: &Socket, option: i32) -> Result<([u8; 16], usize), i64> {
    let mut o = [0u8; 16];
    let entier = |o: &mut [u8; 16], v: i32| {
        o[..4].copy_from_slice(&v.to_le_bytes());
        4
    };
    let timeval = |o: &mut [u8; 16], d: Option<u64>| {
        let tics = d.map_or(0, |ns| ns / TIC);
        o[..8].copy_from_slice(&((tics / 1000) as i64).to_le_bytes());
        o[8..].copy_from_slice(&((tics % 1000 * 1000) as i64).to_le_bytes());
        16
    };
    let inet = *s.appels.verrouiller();
    let op = inet.options;
    let n = match option {
        SO_DEBUG => entier(&mut o, op.debug as i32),
        SO_DONTROUTE => entier(&mut o, op.dontroute as i32),
        SO_OOBINLINE => entier(&mut o, op.oobinline as i32),
        SO_NO_CHECK => entier(&mut o, op.no_check as i32),
        SO_ACCEPTCONN => entier(&mut o, (s.protocole == Protocole::Tcp && tcp::ecoute(s)) as i32),
        SO_BSDCOMPAT => entier(&mut o, 0),
        SO_BROADCAST => entier(&mut o, op.broadcast as i32),
        // Celui d'une connexion TCP grandit de lui-même.
        SO_SNDBUF if s.protocole == Protocole::Tcp => entier(&mut o, tcp::sndbuf(s) as i32),
        SO_SNDBUF => entier(&mut o, s.sndbuf.load(Ordering::Relaxed) as i32),
        SO_RCVBUF => entier(&mut o, s.rcvbuf.load(Ordering::Relaxed) as i32),
        SO_REUSEADDR => entier(&mut o, op.reuseaddr as i32),
        SO_REUSEPORT => entier(&mut o, op.reuseport as i32),
        SO_KEEPALIVE => entier(&mut o, op.keepalive as i32),
        SO_TYPE => entier(&mut o, s.sorte as i32),
        SO_PROTOCOL => entier(&mut o, s.proto as i32),
        SO_DOMAIN => entier(&mut o, AF_INET as i32),
        // Lue et effacée (`sock_error`).
        SO_ERROR if s.protocole == Protocole::Tcp => entier(&mut o, tcp::prendre_erreur(s)),
        SO_ERROR => entier(&mut o, s.prendre_erreur()),
        SO_PRIORITY => entier(&mut o, op.priority as i32),
        SO_LINGER => {
            o[..4].copy_from_slice(&(op.linger.0 as i32).to_le_bytes());
            o[4..8].copy_from_slice(&op.linger.1.to_le_bytes());
            8
        }
        SO_RCVTIMEO | SO_RCVTIMEO_NEW => timeval(&mut o, op.rcvtimeo),
        SO_SNDTIMEO | SO_SNDTIMEO_NEW => timeval(&mut o, op.sndtimeo),
        SO_RCVLOWAT => entier(&mut o, op.rcvlowat as i32),
        SO_SNDLOWAT => entier(&mut o, 1),
        _ => return Err(-ENOPROTOOPT),
    };
    Ok((o, n))
}

/// La valeur d'une option de SOL_IP ; une inconnue : ENOPROTOOPT ; IP_MTU
/// d'une socket non connectée : ENOTCONN.
fn lire_option_ip(s: &Socket, option: i32) -> Result<i32, i64> {
    if option == IP_MTU {
        return datagramme::mtu(s).map(|m| m as i32).ok_or(-ENOTCONN);
    }
    let op = s.appels.verrouiller().options;
    Ok(match option {
        IP_PKTINFO => op.pktinfo as i32,
        IP_RECVERR => op.recverr as i32,
        IP_TOS => op.tos as i32,
        IP_TTL => op.ttl.unwrap_or(64) as i32,
        IP_MTU_DISCOVER => op.pmtudisc as i32,
        _ => return Err(-ENOPROTOOPT),
    })
}

/// read et readv d'une socket (`sock_read_iter`) : rien à lire demandé :
/// 0, sans attendre ; sinon une réception, l'émetteur oublié.
pub fn lire(o: &FichierTenu, morceaux: &[(u64, u64)]) -> i64 {
    if total(morceaux) == 0 {
        return 0;
    }
    match recevoir(o, morceaux, 0) {
        Ok(r) => r.recu.longueur as i64,
        Err(e) => e,
    }
}

/// write et writev d'une socket (`sock_write_iter`) : un envoi sans
/// destination (celle de la connexion ; pas connectée : EDESTADDRREQ, même
/// pour 0 octet).
pub fn ecrire(o: &FichierTenu, morceaux: &[(u64, u64)]) -> i64 {
    envoyer(o, None, morceaux, 0, Ok(Controle::default()))
}

/// ioctl d'une socket, une fois passées celles de tous les fichiers
/// (`sock_ioctl` puis `udp_ioctl`) : FIONREAD (SIOCINQ) : la longueur du
/// PREMIER datagramme en file (pas le total) ; SIOCOUTQ : ce qui attend de
/// partir (rien chez nous : un datagramme part tout de suite) ; une autre
/// (les requêtes des terminaux comprises) : ENOTTY.
pub fn ioctl(o: &FichierTenu, requete: u64, argument: u64) -> i64 {
    const SIOCINQ: u64 = 0x541b;
    const SIOCOUTQ: u64 = 0x5411;
    const SIOCOUTQNSD: u64 = 0x894b;
    const SIOCATMARK: u64 = 0x8905;
    if o.socket().protocole == Protocole::Tcp {
        // `tcp_ioctl` : ce qui est à lire, pas encore acquitté, pas encore
        // envoyé, la lecture à la marque urgente ; une écoute : EINVAL.
        let (lisibles, non_acquittes, non_envoyes, marque) = match tcp::files(o.socket()) {
            Ok(x) => x,
            Err(e) => return e,
        };
        let v = match requete {
            SIOCINQ => lisibles,
            SIOCOUTQ => non_acquittes,
            SIOCOUTQNSD => non_envoyes,
            SIOCATMARK => marque as usize,
            _ => return -ENOTTY,
        } as i32;
        return match copier_vers_utilisateur(argument, &v.to_le_bytes()) {
            Ok(()) => 0,
            Err(_) => -EFAULT,
        };
    }
    // Une socket de ping n'en a aucune (`ping_prot` n'a pas d'ioctl).
    if o.socket().protocole == Protocole::Ping {
        return -ENOTTY;
    }
    let v: i32 = match requete {
        SIOCINQ => o.socket().premier() as i32,
        SIOCOUTQ => 0,
        _ => return -ENOTTY,
    };
    match copier_vers_utilisateur(argument, &v.to_le_bytes()) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}
