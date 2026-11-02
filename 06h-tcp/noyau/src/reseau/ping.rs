//! Les sockets de ping (net/ipv4/ping.c) : SOCK_DGRAM et IPPROTO_ICMP, de
//! quoi envoyer des échos ICMP et lire leurs réponses sans être root (une
//! socket RAW demanderait CAP_NET_RAW).
//!
//! Linux ne les permet qu'aux groupes de `ping_group_range` (« 1 0 » par
//! défaut : personne) ; les distributions l'ouvrent à tous (systemd :
//! « 0 2147483647 »), ce que nous faisons : tout programme peut en créer
//! une. Seul l'écho (genre 8, code 0) s'envoie ; son identifiant est
//! remplacé par le « port » de la socket, qu'elle prend comme un port
//! d'UDP mais dans sa propre table (inet::idents : des identifiants qui se
//! suivent, sans regarder l'adresse) ; une réponse revient à la socket de
//! son identifiant, et se lit sans en-tête IPv4, de l'adresse qui répond,
//! port 0. Elle se lie à 0.0.0.0 ou à l'une de nos adresses, jamais à une
//! diffusion ni à une multidiffusion (`ping_check_bind_addr`) ; MSG_OOB
//! est refusé, à l'envoi comme à la lecture (EOPNOTSUPP). Ce qui est
//! commun aux sockets de datagrammes (bind, connect, recevoir) est dans
//! datagramme.rs et socket.rs.

use super::datagramme::{self, Controle};
use super::icmp::ErreurRecue;
use super::ipv4;
use super::paquet::Paquet;
use super::socket::{self, Admission, AF_INET, Datagramme, Inet, Socket};
use crate::verrou::Verrou;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use formats::reseau::icmp::{self, Icmp};
use formats::reseau::ipv4 as format_ipv4;
use inet::idents::{Refus, Table};

const EINVAL: i64 = 22;
const EDESTADDRREQ: i64 = 89;
const EMSGSIZE: i64 = 90;
const EOPNOTSUPP: i64 = 95;
const EAFNOSUPPORT: i64 = 97;
const EADDRINUSE: i64 = 98;
const ENOBUFS: i64 = 105;

/// La table des identifiants ; faite au démarrage.
static IDENTS: Verrou<Option<Table<Arc<Socket>>>> = Verrou::new(None);

/// Les réponses jetées : sans socket, ou la file pleine.
static SANS_SOCKET: AtomicU64 = AtomicU64::new(0);
static FILE_PLEINE: AtomicU64 = AtomicU64::new(0);

pub fn initialiser() {
    *IDENTS.verrouiller() = Table::new();
}

/// Inscrit `s` dans la table, à l'identifiant `ident` (0 : le suivant
/// libre). Sous le `Mutex`.
pub fn inscrire(s: &Arc<Socket>, inet: &mut Inet, ident: u16) -> Result<(), i64> {
    let mut g = IDENTS.verrouiller();
    let Some(t) = g.as_mut() else { return Err(-ENOBUFS) };
    match t.lier(s.numero, ident, inet.adresse, inet.options.reuseaddr, s.clone()) {
        Ok(i) => {
            inet.port = i;
            inet.lie = true;
            Ok(())
        }
        Err(Refus::Pris) => Err(-EADDRINUSE),
        Err(Refus::Plein) => Err(-ENOBUFS),
    }
}

/// L'adresse locale de `s` a changé (connect, ou sa fin).
pub fn changer(s: &Socket, inet: &Inet) {
    if let Some(t) = IDENTS.verrouiller().as_mut() {
        t.changer(s.numero, inet.adresse);
    }
}

/// Retire `s` de la table (son dernier close, ou la fin d'une connexion
/// qui rend son identifiant).
pub fn liberer(s: &Socket) {
    if let Some(t) = IDENTS.verrouiller().as_mut() {
        t.retirer(s.numero);
    }
}

/// SO_REUSEADDR a changé.
pub fn reutilisation_changee(s: &Socket, inet: &Inet) {
    if let Some(t) = IDENTS.verrouiller().as_mut() {
        t.reutiliser(s.numero, inet.options.reuseaddr);
    }
}

/// Envoie un écho de `longueur` octets (son en-tête ICMP compris), que
/// `remplir` copie du programme, à `nom` (None : la destination de la
/// connexion), dans l'ordre d'`inet_sendmsg` et de `ping_v4_sendmsg` :
///   - un identifiant s'il le faut, avant tout (EAGAIN) ;
///   - plus de 65 535 octets : EMSGSIZE ; moins que l'en-tête ICMP :
///     EINVAL ; MSG_OOB : EOPNOTSUPP ; l'en-tête copié (EFAULT) : autre
///     chose qu'un écho de code 0 : EINVAL ;
///   - la destination : moins de 16 octets : EINVAL ; une autre famille
///     qu'AF_INET : EAFNOSUPPORT (AF_UNSPEC aussi, au contraire d'UDP) ;
///     aucune, et pas connectée : EDESTADDRREQ ;
///   - les messages de contrôle, puis ce que fait toute socket de
///     datagrammes (`datagramme::preparer`) ;
///   - le paquet (ENOBUFS), le reste copié (EFAULT), l'identifiant de la
///     socket mis à la place de celui du programme, la somme, et il part.
pub fn envoyer(s: &Arc<Socket>, nom: Option<&[u8]>, longueur: usize, drapeaux: u64, controle: Result<Controle, i64>,
               mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    let mut inet = s.appels.verrouiller();
    datagramme::lier_au_besoin(s, &mut inet)?;
    if longueur > 0xFFFF {
        return Err(-EMSGSIZE);
    }
    if longueur < icmp::ENTETE {
        return Err(-EINVAL);
    }
    if drapeaux & MSG_OOB != 0 {
        return Err(-EOPNOTSUPP);
    }
    let mut entete = [0u8; icmp::ENTETE];
    remplir(0, &mut entete)?;
    if entete[0] != icmp::ECHO || entete[1] != 0 {
        return Err(-EINVAL);
    }
    let adresse = match nom {
        Some(o) => {
            let Some(a) = socket::lire_adresse(o) else { return Err(-EINVAL) };
            if a.famille != AF_INET {
                return Err(-EAFNOSUPPORT);
            }
            a.adresse
        }
        None if inet.connecte => inet.distante,
        None => return Err(-EDESTADDRREQ),
    };
    let c = controle?;
    let (chemin, envoi) = datagramme::preparer(s, &mut inet, adresse, longueur, format_ipv4::ICMP, drapeaux, &c)?;
    let ident = inet.port;
    drop(inet);
    let Some(mut p) = Paquet::vide(longueur) else { return Err(-ENOBUFS) };
    let Some(m) = p.ajouter_fin(longueur) else { return Err(-ENOBUFS) };
    remplir(icmp::ENTETE, &mut m[icmp::ENTETE..])?;
    let numero = u16::from_be_bytes([entete[6], entete[7]]);
    icmp::ecrire(m, &Icmp { genre: icmp::ECHO, code: 0, reste: icmp::reste_echo(ident, numero) });
    ipv4::emettre(chemin, &envoi, p);
    Ok(longueur)
}

/// Une réponse à l'écho (`p` : le message ICMP entier) reçue par
/// l'interface `interface`, de `source`, pour `destination`, dans la tâche
/// du réseau (`ping_rcv`) : à la socket de son identifiant, telle quelle
/// (l'en-tête ICMP compris), avec la règle ordinaire des files.
pub fn recevoir(interface: u32, source: [u8; 4], destination: [u8; 4], p: Paquet) {
    let Ok((m, _)) = icmp::lire(p.donnees()) else { return };
    let (ident, _) = m.echo();
    let Some(s) = IDENTS.verrouiller().as_ref().and_then(|t| t.trouver(ident, destination)) else {
        SANS_SOCKET.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let taille = p.taille_vraie();
    let d = Datagramme { paquet: p, source, port: 0, destination, interface, taille };
    if !s.deposer(d, Admission::Ordinaire) {
        FILE_PLEINE.fetch_add(1, Ordering::Relaxed);
    }
}

/// Une erreur ICMP pour un écho que nous avons envoyé (`ping_err`) : la
/// copie doit être celle d'un écho de code 0 ; la socket, celle de son
/// identifiant ; l'errno comme pour UDP, sauf l'étouffement et la
/// redirection, que ping veut voir (EREMOTEIO, sans être fatales). Ce que
/// lira le programme : l'écho d'origine, son en-tête ICMP compris.
pub fn erreur(e: &ErreurRecue) {
    const EREMOTEIO: i32 = 121;
    let debut = e.interne.longueur_entete;
    let (Some(&genre), Some(&code)) = (e.origine.get(debut), e.origine.get(debut + 1)) else { return };
    if genre != icmp::ECHO || code != 0 {
        return;
    }
    let Some(ident) = e.origine.get(debut + 4..debut + 6).map(|o| u16::from_be_bytes([o[0], o[1]])) else { return };
    let Some(s) = IDENTS.verrouiller().as_ref().and_then(|t| t.trouver(ident, e.destination)) else { return };
    let (errno, fatale) = match e.genre {
        icmp::ETOUFFEMENT | icmp::REDIRECTION => (EREMOTEIO, false),
        _ => match super::udp::convertir(e.genre, e.code, super::udp::fragmentation_dite(&s)) {
            Some(x) => x,
            None => return,
        },
    };
    super::udp::signaler(&s, e, errno, fatale, 0, 0);
}

/// Le nombre de sockets de ping dont quelqu'un attend une lecture.
pub fn attentes() -> usize {
    let mut n = 0;
    if let Some(t) = IDENTS.verrouiller().as_ref() {
        t.pour_chaque(|s| n += s.attente.active() as usize);
    }
    n
}
