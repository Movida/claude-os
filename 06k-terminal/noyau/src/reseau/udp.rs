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
//! Depuis les soldes d'avant 6k, rien ne manque, écrit : SO_SNDBUF fait
//! attendre (datagramme::attendre_place), MSG_MORE et UDP_CORK bouchent la
//! socket (`Bouchon`), MSG_PROBE ne fait que chercher la route
//! (datagramme::preparer), et un datagramme pour un groupe va à chaque
//! socket que ses adhésions laissent le prendre (`recevoir`, et
//! multidiffusion.rs).
//!
//! LES COMPTEURS d'UDP (/proc/net/snmp, snmp.rs), aux places de Linux : à
//! l'arrivée, un datagramme faux (InErrors, et InCsumErrors pour sa somme),
//! sans socket (NoPorts), une diffusion que personne n'écoute
//! (IgnoredMulti), une file pleine (RcvbufErrors) ou sans mémoire
//! (MemErrors), ces deux-là avec InErrors ; à la lecture, un datagramme lu
//! (InDatagrams, socket.rs) ; à l'envoi, un datagramme parti (OutDatagrams)
//! ou qui manque de place (SndbufErrors).

use super::datagramme::{self, Controle, Depart, trop_gros};
use super::filtre::{self, Verdict};
use super::ipv4;
use super::paquet::{self, Paquet};
use super::icmp::ErreurRecue;
use super::snmp::MIB;
use super::zerocopie::{AuBouchon, MSG_ZEROCOPY};
use super::socket::{self, Admission, AF_INET, AF_UNSPEC, Datagramme, ErreurEnFile, Inet, Rejet, Socket, Somme};
use crate::aleatoire;
use crate::attente::GardeMutex;
use crate::partage::Arc;
use crate::verrou::Verrou;
use core::sync::atomic::Ordering;
use formats::reseau::{Erreur, ipv4 as format_ipv4, somme_linux, somme_linux_moins, udp};
use inet::ports::{Lien, Refus, Table};
use inet::snmp::Udp as Compteur;

const EINVAL: i64 = 22;
const EDESTADDRREQ: i64 = 89;
const EMSGSIZE: i64 = 90;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;
const EAFNOSUPPORT: i64 = 97;
const ENOBUFS: i64 = 105;

/// La table des ports ; faite au démarrage.
static PORTS: Verrou<Option<Table<Arc<Socket>>>> = Verrou::new(None);

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
        plage: inet.options.local_port_range, interface: inet.options.interface,
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

/// La liaison à une interface a changé (SO_BINDTODEVICE, le `rehash` d'UDP).
pub fn interface_changee(s: &Socket, interface: u32) {
    if let Some(t) = PORTS.verrouiller().as_mut() {
        t.changer_interface(s.numero, interface);
    }
}

/// Le « bouchon » d'UDP (MSG_MORE, UDP_CORK) : un datagramme qui
/// s'assemble envoi après envoi, et ne part qu'avec le dernier (le `pending`
/// d'`udp_sock`, l'`inet_cork` et la `sk_write_queue` de Linux). Dans
/// `Inet`, sous le `Mutex` : le `lock_sock` que Linux prend pour tout envoi
/// bouché, attente de la place et copie comprises (un autre fil qui envoie
/// attend son tour, et ajoute derrière). Son paquet compte dans SO_SNDBUF
/// (mesuré : SIOCOUTQ le voit grandir de chaque ajout, POLLOUT aussi).
///
/// Un écart voulu, avec une route source (IP_OPTIONS) : bouché, Linux
/// adresse le datagramme à sa destination finale (le `flowi4` du bouchon
/// garde `daddr`, pas la première étape : l'en-tête, la somme d'UDP et
/// l'erreur locale la prennent ; mesuré), quand le même envoi sans bouchon
/// part vers la première étape, comme le veut la route source. Un accident
/// de `udp_sendmsg` (le chemin bouché remplit un autre `flowi4`), qu'aucun
/// programme ne peut attendre : le nôtre part toujours vers la première
/// étape.
pub struct Bouchon {
    /// Le segment : la place de l'en-tête UDP, puis les données.
    paquet: Paquet,
    /// Ce que le premier envoi a fixé (la route, les adresses, la MTU, le
    /// TTL et le TOS de ses messages de contrôle), et le port de
    /// destination (`fl4_dport`). Le port source est celui de la socket
    /// quand il part (mesuré : 0 si une déconnexion l'a rendu entre-temps).
    depart: Depart,
    port: u16,
}

/// Envoie `longueur` octets, que `remplir` copie du programme dans le
/// paquet, à la destination `nom` (la `sockaddr` de sendto ou de sendmsg ;
/// None : celle de la connexion), dans l'ordre d'`inet_sendmsg` et
/// d'`udp_sendmsg` :
///   - un port éphémère s'il le faut, avant tout (EAGAIN) ;
///   - plus de 65 535 octets : EMSGSIZE ; MSG_OOB : EOPNOTSUPP ;
///   - un bouchon déjà posé (`Bouchon`) : les octets s'y ajoutent
///     (`ajouter`), sans regarder la destination ni les messages de
///     contrôle (mesuré : une adresse de port 0, un IP_TTL de 300 passent,
///     et tout part vers la destination du premier envoi) ;
///   - la destination : moins de 16 octets, ou le port 0 : EINVAL ; une
///     autre famille qu'AF_INET ou AF_UNSPEC : EAFNOSUPPORT ; aucune, et
///     pas connectée : EDESTADDRREQ ;
///   - les messages de contrôle (`controle`, lus par l'appel : leur erreur
///     sort ici, EINVAL) ;
///   - ce que fait toute socket de datagrammes (`datagramme::preparer`) :
///     la route, l'adresse source, la MTU, l'erreur en attente, l'arrêt ;
///   - le paquet (`datagramme::faire_paquet`) : la place dans SO_SNDBUF,
///     les morceaux au-delà de son double, la copie ;
///   - avec MSG_MORE ou UDP_CORK (`corkreq`), le bouchon se pose : le
///     paquet attend ; sinon, il part.
///
/// Rend la longueur envoyée (ou ajoutée). Une erreur après les messages de
/// contrôle (le `out:` d'`udp_sendmsg`) compte un SndbufErrors si c'est
/// ENOBUFS, ou si la socket a déjà manqué de place (`place_manquee`,
/// SOCK_NOSPACE) : Linux n'a pas d'autre compteur pour dire « la place a
/// manqué » (son commentaire), même au prix d'en compter trop.
pub fn envoyer(s: &Arc<Socket>, nom: Option<&[u8]>, longueur: usize, drapeaux: u64, controle: Result<Controle, i64>,
               remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const MSG_OOB: u64 = 1;
    const MSG_MORE: u64 = 0x8000;
    let mut inet = s.appels.verrouiller();
    datagramme::lier_au_besoin(s, &mut inet)?;
    if longueur > 0xFFFF {
        return Err(-EMSGSIZE);
    }
    if drapeaux & MSG_OOB != 0 {
        return Err(-EOPNOTSUPP);
    }
    let bouche = inet.options.udp_cork || drapeaux & MSG_MORE != 0;
    let envoye = if inet.bouchon.is_some() {
        ajouter(s, &mut inet, longueur, bouche, drapeaux & datagramme::MSG_PROBE != 0, drapeaux & MSG_ZEROCOPY != 0, remplir)
    } else {
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
        envoyer_vers(s, inet, (adresse, port, nom.is_none()), longueur, drapeaux, bouche, &c, remplir)
    };
    if let Err(e) = envoye
        && (e == -ENOBUFS || s.place_manquee.load(Ordering::Relaxed))
    {
        MIB.udp(Compteur::SndbufErrors);
    }
    envoye
}

/// La suite d'`envoyer`, vers `adresse`:`port` (`connectee` : ceux de la
/// connexion, sans adresse donnée), sans bouchon posé. Sans MSG_MORE ni
/// UDP_CORK, le `Mutex` est lâché pendant l'attente de la place et la copie
/// (le chemin « sans verrou » d'`udp_sendmsg`), et repris pour l'en-tête ;
/// avec, il est tenu jusqu'à la pose du bouchon (`lock_sock`).
#[allow(clippy::too_many_arguments)]
fn envoyer_vers(s: &Arc<Socket>, mut inet: GardeMutex<'_, Inet>, (adresse, port, connectee): ([u8; 4], u16, bool), longueur: usize,
                drapeaux: u64, bouche: bool, c: &Controle, mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>)
                -> Result<usize, i64> {
    const MSG_DONTWAIT: u64 = 0x40;
    let d = datagramme::preparer(s, &mut inet, adresse, udp::ENTETE + longueur, drapeaux, c, connectee, format_ipv4::UDP)?;
    // MSG_PROBE : la route seulement (`preparer`) ; pas de bouchon non plus
    // (la file de Linux reste vide : `pending` revient à 0).
    if drapeaux & datagramme::MSG_PROBE != 0 {
        return Ok(longueur);
    }
    let (delai, pmtudisc) = (inet.options.sndtimeo, inet.options.pmtudisc);
    let non_bloquant = drapeaux & MSG_DONTWAIT != 0;
    let copier = |segment: &mut [u8]| remplir(0, &mut segment[udp::ENTETE..]);
    // L'avis compte l'en-tête UDP d'un datagramme neuf (la `length`
    // d'`__ip_append_data` : mesuré, un envoi de 0 octet prend un numéro,
    // et RLIMIT_MEMLOCK compte ses 8 octets).
    let zerocopie = if drapeaux & MSG_ZEROCOPY != 0 { udp::ENTETE + longueur } else { 0 };
    if bouche {
        let paquet = datagramme::faire_paquet(s, &d, udp::ENTETE + longueur, pmtudisc, non_bloquant, delai, zerocopie, copier)?;
        inet.bouchon = Some(Bouchon { paquet, depart: d, port });
        return Ok(longueur);
    }
    drop(inet);
    let p = datagramme::faire_paquet(s, &d, udp::ENTETE + longueur, pmtudisc, non_bloquant, delai, zerocopie, copier)?;
    emettre(&mut s.appels.verrouiller(), &d, port, p);
    Ok(longueur)
}

/// Ajoute `longueur` octets au bouchon de la socket (`ip_append_data` sur
/// une file qui n'est pas vide), sous le `Mutex` : au-delà de ce qu'on a le
/// droit d'envoyer en tout (`Depart::permis`, avec IP_MTU_DISCOVER d'alors
/// et la MTU du premier envoi) : `trop_gros` ; un morceau de plus à
/// faire (le datagramme passe une MTU de plus : les `sk_buff` que Linux
/// enchaîne pendant qu'il bouche ont la géométrie de ses fragments,
/// `format_ipv4::nombre_de_fragments`, et chacun coûte un `alloc_skb` et
/// sa place dans SO_SNDBUF) quand ce que tient la socket irait au-delà du
/// double de SO_SNDBUF : ENOBUFS ;
/// plus de mémoire : ENOBUFS pour un morceau de plus, ENOMEM sinon (les
/// `alloc_skb` et `sk_page_frag_refill` de Linux) ; la copie : EFAULT.
/// Ni l'attente de la place, ni l'erreur en attente, ni l'arrêt ne
/// comptent ici (mesuré : un shutdown(SHUT_WR) n'empêche ni l'ajout, ni le
/// départ ; seul le premier envoi passe par `sock_alloc_send_skb`). Une
/// erreur vide le bouchon (`udp_flush_pending_frames`) : tout ce qui
/// attendait est perdu. Sans MSG_MORE ni UDP_CORK, le datagramme part.
/// Avec MSG_PROBE (`sonde`), rien n'est ajouté ni vérifié (`ip_append_data`
/// rend 0 aussitôt), mais sans MSG_MORE ni UDP_CORK le bouchon part quand
/// même, sans ces octets-là (mesuré).
fn ajouter(s: &Arc<Socket>, inet: &mut Inet, longueur: usize, bouche: bool, sonde: bool, zerocopie: bool,
           mut remplir: impl FnMut(usize, &mut [u8]) -> Result<(), i64>) -> Result<usize, i64> {
    const ENOMEM: i64 = 12;
    let pmtudisc = inet.options.pmtudisc;
    if sonde {
        if !bouche {
            pousser(inet);
        }
        return Ok(longueur);
    }
    let Some(b) = inet.bouchon.as_mut() else { return Ok(0) };
    let avant = b.paquet.longueur();
    let apres = avant + longueur;
    let r = if apres + b.depart.entete() > b.depart.permis(pmtudisc) {
        let d = b.depart;
        Err(trop_gros(s, inet, &d))
    } else {
        // L'avis de MSG_ZEROCOPY, après la taille, avant la place et la copie
        // (`__ip_append_data`) ; son ENOBUFS vide le bouchon comme les autres
        // erreurs (`udp_flush_pending_frames`).
        let z = if zerocopie { super::zerocopie::au_bouchon(s, &mut b.paquet, longueur) } else { Ok(AuBouchon::Rien) };
        match z {
            Err(e) => Err(e),
            Ok(z) => {
                let r = (|| {
                    let (entete, mtu) = (b.depart.entete(), b.depart.mtu as usize);
                    let morceaux_avant = format_ipv4::nombre_de_fragments(avant, mtu, entete);
                    let nouveaux = format_ipv4::nombre_de_fragments(apres, mtu, entete) - morceaux_avant;
                    let retenue = longueur + nouveaux * (paquet::MARGE + paquet::SURCOUT);
                    // Chaque morceau neuf, avant d'être fait, ne doit pas mener ce que
                    // tient la socket, plus ce que cet ajout y a déjà mis (les octets
                    // qui remplissent le morceau en cours, puis les morceaux neufs
                    // d'avant, pleins), au-delà du double de SO_SNDBUF (le
                    // `wmem_alloc_delta` de `__ip_append_data`) : le plus exigeant est
                    // le dernier.
                    let plein = mtu.saturating_sub(entete) & !7;
                    let remplissage = plein.saturating_sub(avant - (morceaux_avant - 1) * plein);
                    let deja = remplissage + nouveaux.saturating_sub(1) * (paquet::MARGE + plein + paquet::SURCOUT);
                    if nouveaux > 0 && s.envois.as_ref().is_some_and(|r| r.octets() + deja > 2 * r.limite()) {
                        Err(datagramme::jete(-ENOBUFS))
                    } else {
                        match b.paquet.agrandir(longueur) {
                            None => Err(datagramme::jete(if nouveaux > 0 { -ENOBUFS } else { -ENOMEM })),
                            Some(o) => match remplir(0, o) {
                                Err(e) => Err(datagramme::jete(e)),
                                Ok(()) => {
                                    b.paquet.retenir_en_plus(retenue);
                                    Ok(longueur)
                                }
                            },
                        }
                    }
                })();
                super::zerocopie::apres_le_bouchon(s, &mut b.paquet, z, r.is_ok());
                r
            }
        }
    };
    if r.is_err() {
        inet.bouchon = None;
    } else if !bouche {
        pousser(inet);
    }
    r
}

/// Le bouchon de la socket part, s'il y en a un (`udp_push_pending_frames`) :
/// la fin d'un envoi sans MSG_MORE ni UDP_CORK, UDP_CORK retiré, la fin
/// d'un sendfile (`fin_d_episse`). Sous le `Mutex`.
pub fn pousser(inet: &mut Inet) {
    if let Some(b) = inet.bouchon.take() {
        emettre(inet, &b.depart, b.port, b.paquet);
    }
}

/// Le segment `p` (la place de l'en-tête UDP, puis les données) part vers
/// `d`, au port `port` (`udp_send_skb`), sous le `Mutex` : l'en-tête IPv4
/// d'alors (`Depart::envoi`), l'en-tête UDP (le port de la socket d'alors)
/// et sa somme, sur tout le segment ; avec SO_NO_CHECK d'alors, aucune
/// (`sk_no_check_tx` : 0, CHECKSUM_NONE ; mesuré, une socket brute).
fn emettre(inet: &mut Inet, d: &Depart, port: u16, mut p: Paquet) {
    let envoi = d.envoi(inet, p.longueur(), format_ipv4::UDP);
    let u = udp::Udp { source: inet.port, destination: port };
    if inet.options.no_check {
        udp::ecrire_sans_somme(p.donnees_mut(), &u);
    } else {
        udp::ecrire(p.donnees_mut(), &u, envoi.source, envoi.destination);
    }
    ipv4::emettre(d.chemin, &envoi, p);
    MIB.udp(Compteur::OutDatagrams);
}

/// UDP_CORK (`udp_lib_setsockopt`) : posé, tout envoi bouche ; retiré, le
/// bouchon part, s'il y en a un (son erreur n'est pas rendue).
pub fn boucher(s: &Socket, oui: bool) {
    let mut inet = s.appels.verrouiller();
    inet.options.udp_cork = oui;
    if !oui {
        pousser(&mut inet);
    }
}

/// La fin d'un sendfile vers la socket (`udp_splice_eof`) : sans UDP_CORK,
/// le bouchon des rondes envoyées avec MSG_MORE part.
pub fn fin_d_episse(s: &Socket) {
    let mut inet = s.appels.verrouiller();
    if !inet.options.udp_cork {
        pousser(&mut inet);
    }
}

/// Le dernier close (`udp_destroy_sock`) : le bouchon est perdu, et la
/// socket quitte la table des ports.
pub fn fermer(s: &Socket) {
    let bouchon = s.appels.verrouiller().bouchon.take();
    drop(bouchon);
    liberer(s);
}

/// Un datagramme UDP (`p` : le segment, en-tête compris, sans l'en-tête
/// d'IPv4, dont la réception a gardé `entete`) arrivé là où dit `lieu`
/// (ce que préparera IP_PKTINFO), pour `destination`, de `source`, dans la
/// tâche du réseau :
/// `__udp4_lib_rcv`, la somme vérifiée (fausse : jeté, sans rien dire,
/// compté), puis la socket qui le reçoit ; une diffusion à chacune de
/// celles du port. Sans socket, le segment est rendu, son en-tête remis,
/// pour l'erreur ICMP « port injoignable » (que l'appelant envoie : il a
/// l'en-tête d'IPv4).
///
/// La somme que rendra IP_CHECKSUM (la `__wsum` de Linux) : un datagramme
/// dont la somme reste à vérifier (`a_verifier` : venu par une carte, voir
/// ipv4.rs, `Arrivee`) et n'est pas nulle (une somme nulle n'est pas
/// vérifiée : `skb_checksum_init_zero_check`) l'a, calculée tout de suite
/// pour un segment de 76 octets au plus (CHECKSUM_BREAK : Linux juge moins
/// cher de vérifier un petit datagramme tout de suite), sur le segment
/// entier puis réduite de celle de l'en-tête quand il est ôté
/// (`udp_csum_pull_header`, `skb_pull_rcsum`) ; plus long, sur les données
/// seules, par la première lecture qui le coupe ou le regarde
/// (socket.rs, `somme_lue`). Les deux calculs ne donnent pas toujours la
/// même valeur pour les mêmes données (des données nulles : 0xFFFFFFFF,
/// puis 0) : comme chez Linux.
pub fn recevoir(lieu: ipv4::Lieu, source: [u8; 4], destination: [u8; 4], entete: &ipv4::EnteteRecu, diffusion: bool, a_verifier: bool,
                mut p: Paquet) -> Result<(), Paquet> {
    // Choix de conception : la somme vérifiée à l'arrivée, pour tout datagramme.
    // Linux ne la vérifie, pour un datagramme qui a une socket, qu'à sa lecture
    // (`udp_recvmsg`, `csum_copy_err`) : elle se calcule alors pendant la copie
    // vers le programme, une seule passe sur les données. Notre copie vers le
    // programme (`copier`, qui peut fauter et dormir) ne calcule rien : la somme
    // coûte une passe de plus à l'arrivée comme à la lecture. À l'arrivée, un
    // datagramme faux ne prend pas la place de la file, et `poll` ne l'annonce
    // pas : chez Linux, il dit « lisible », puis `recv` le jette et attend (le
    // piège connu de select avec une socket bloquante). Les compteurs sont les
    // mêmes, comptés plus tôt (et même si personne ne lit) : pour un datagramme
    // pour nous seuls, ou de 76 octets au plus (CHECKSUM_BREAK : Linux le
    // vérifie tout de suite, `udp4_csum_init`), InCsumErrors et InErrors ;
    // une diffusion plus longue, Linux la donne sans la vérifier à chaque
    // socket qui la prend (`__udp4_lib_mcast_deliver`), et chacune la jette à
    // sa lecture : autant de fois InCsumErrors et InErrors ; à aucune :
    // IgnoredMulti, comme une diffusion juste que personne n'écoute.
    let (u, charge) = match udp::lire(p.donnees(), source, destination) {
        Ok(x) => x,
        // (La longueur d'UDP : `udp::lire` l'a vérifiée avant la somme.)
        // Plus long, et pour une socket, Linux le jette à la lecture, qui compte une perte pour
        // elle (`__sk_queue_drop_skb`) : nous, à l'arrivée, comme les compteurs.
        Err(Erreur::Somme) if diffusion && u16::from_be_bytes([p.donnees()[4], p.donnees()[5]]) > 76 => {
            let o = p.donnees();
            let ports = (u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]));
            let mut sockets = 0;
            if let Some(t) = PORTS.verrouiller().as_ref() {
                t.pour_chaque_diffusion(source, ports.0, destination, ports.1, lieu.interface, |s| {
                    if super::multidiffusion::permet(s, destination, source, lieu.interface) {
                        sockets += 1;
                        s.pertes.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            if sockets == 0 {
                MIB.udp(Compteur::IgnoredMulti);
            }
            for _ in 0..sockets {
                MIB.udp(Compteur::InCsumErrors);
                MIB.udp(Compteur::InErrors);
            }
            return Ok(());
        }
        Err(e) => {
            if e == Erreur::Somme {
                MIB.udp(Compteur::InCsumErrors);
                let o = p.donnees();
                if u16::from_be_bytes([o[4], o[5]]) > 76 {
                    let ports = (u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]));
                    let ici = crate::processeur::numero() as i32;
                    let s = PORTS.verrouiller().as_ref().and_then(|t| {
                        t.trouver(source, ports.0, destination, ports.1, lieu.interface, |s| de_ce_processeur(s, ici))
                    });
                    if let Some(s) = s {
                        s.pertes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            MIB.udp(Compteur::InErrors);
            return Ok(());
        }
    };
    let longueur = charge.len();
    let segment = &p.donnees()[..udp::ENTETE + longueur];
    let somme = if !a_verifier || segment[6..8] == [0, 0] {
        Somme::Aucune
    } else if segment.len() <= 76 {
        Somme::Calculee(somme_linux_moins(somme_linux(segment), somme_linux(&segment[..udp::ENTETE])))
    } else {
        Somme::ALaLecture
    };
    let _ = p.retirer_entete(udp::ENTETE);
    p.couper(longueur);
    let arrivee = Arrivee { source, port: u.source, destination, port_destination: u.destination, lieu, entete: *entete, somme };
    if diffusion {
        // Une copie pour chacune, déposée sous le verrou de la table (son
        // ordre permet de prendre ensuite celui de la file d'une socket) ;
        // une copie ratée (le `skb_clone` d'`__udp4_lib_mcast_deliver`) est
        // comptée comme une file pleine. Pour un groupe, seulement celles
        // que leurs adhésions laissent le prendre, de cette source, arrivé
        // par cette interface (`__udp_is_mcast_sock` : `ip_mc_sf_allow`).
        // Aucune socket : IgnoredMulti.
        let mut sockets = 0;
        if let Some(t) = PORTS.verrouiller().as_ref() {
            t.pour_chaque_diffusion(source, u.source, destination, u.destination, lieu.interface, |s| {
                if !super::multidiffusion::permet(s, destination, source, lieu.interface) {
                    return;
                }
                sockets += 1;
                // La copie d'abord, puis le filtre de la socket, sur l'original :
                // la copie n'a que la charge, sans les en-têtes qu'il peut lire.
                match Paquet::copie(p.donnees()) {
                    Some(mut copie) => match filtrer(s, &p, lieu.carte, arrivee.somme) {
                        Some((n, somme)) => {
                            copie.poser_contexte(p.contexte());
                            copie.couper(n);
                            deposer(s, copie, &Arrivee { somme, ..arrivee })
                        }
                        None => jete_par_le_filtre(s),
                    },
                    None => {
                        s.pertes.fetch_add(1, Ordering::Relaxed);
                        MIB.udp(Compteur::RcvbufErrors);
                        MIB.udp(Compteur::InErrors);
                    }
                }
            });
        }
        if sockets == 0 {
            MIB.udp(Compteur::IgnoredMulti);
        }
        return Ok(());
    }
    let ici = crate::processeur::numero() as i32;
    let s = PORTS.verrouiller().as_ref().and_then(|t| {
        t.trouver(source, u.source, destination, u.destination, lieu.interface, |s| de_ce_processeur(s, ici))
    });
    match s {
        Some(s) => {
            match filtrer(&s, &p, lieu.carte, arrivee.somme) {
                Some((n, somme)) => {
                    p.couper(n);
                    deposer(&s, p, &Arrivee { somme, ..arrivee });
                }
                None => jete_par_le_filtre(&s),
            }
            Ok(())
        }
        None => {
            MIB.udp(Compteur::NoPorts);
            let _ = p.ajouter_entete(udp::ENTETE);
            Err(p)
        }
    }
}

/// La socket dit-elle (SO_INCOMING_CPU) le processeur `ici`, celui qui cherche ?
/// À note égale, elle l'emporte (`compute_score`, inet::ports).
fn de_ce_processeur(s: &Arc<Socket>, ici: i32) -> bool {
    s.processeur.load(Ordering::Relaxed) == ici
}

/// Le filtre de la socket `s` (filtre.rs), s'il en a un, sur le datagramme `p`
/// (sa charge, son en-tête juste devant) arrivé par la carte `carte`
/// (`udp_queue_rcv_one_skb`, `sk_filter_trim_cap` : au moins l'en-tête, 8 octets ;
/// la charge commence après lui) : None, jeté ; sinon les octets de charge
/// gardés, et sa somme (voir `recevoir`). Avec un filtre, Linux l'achève avant lui
/// (`udp_lib_checksum_complete`), sur le segment entier, et la coupe ne la change
/// pas (`pskb_trim` ne touche pas à `skb->csum`) : celle d'un datagramme qui
/// l'aurait eue à la lecture (`Somme::ALaLecture`) est calculée ici, comme celle
/// d'un petit datagramme. Avant de le déposer, donc avant que la socket ne note le
/// processeur qui l'a reçu (`__udp_queue_rcv_skb`, après le filtre). À part, comme
/// celui de TCP (tcp.rs, `filtrer`).
#[inline(never)]
fn filtrer(s: &Socket, p: &Paquet, carte: inet::filtre::Carte, somme: Somme) -> Option<(usize, Somme)> {
    let Some(f) = filtre::de(s) else { return Some((p.longueur(), somme)) };
    let somme = match somme {
        Somme::ALaLecture => {
            let (o, d, ..) = p.pour_filtre(udp::ENTETE)?;
            let segment = &o[d..];
            Somme::Calculee(somme_linux_moins(somme_linux(segment), somme_linux(&segment[..udp::ENTETE])))
        }
        autre => autre,
    };
    match filtre::passer_ip(&f, p, udp::ENTETE, udp::ENTETE, carte, udp::ENTETE as u32) {
        Verdict::Jeter => None,
        Verdict::Garder(n) => Some((n - udp::ENTETE, somme)),
    }
}

/// Un datagramme que le filtre de `s` a jeté : une perte pour elle, une erreur
/// d'UDP (mesuré).
fn jete_par_le_filtre(s: &Socket) {
    s.pertes.fetch_add(1, Ordering::Relaxed);
    MIB.udp(Compteur::InErrors);
}

/// D'où vient un datagramme reçu, et ce qu'en garde la file avec lui.
#[derive(Clone, Copy)]
struct Arrivee {
    source: [u8; 4],
    port: u16,
    destination: [u8; 4],
    port_destination: u16,
    lieu: ipv4::Lieu,
    entete: ipv4::EnteteRecu,
    somme: Somme,
}

/// Le datagramme `p` dans la file de la socket `s`, IP_PKTINFO préparé si
/// elle l'a à cet instant (`udp_queue_rcv_one_skb`, `ipv4_pktinfo_prepare` :
/// posé plus tard, la lecture dira l'interface 0 et l'adresse 0.0.0.0). Une
/// socket connectée note le processeur qui l'a reçu, même si sa file le
/// refuse (`__udp_queue_rcv_skb` : SO_INCOMING_CPU) ; une qui ne l'est pas
/// reçoit de tout le monde, et Linux ne le note pas (mesuré : -1).
fn deposer(s: &Socket, p: Paquet, a: &Arrivee) {
    if s.connectee.load(Ordering::Relaxed) {
        s.arrivee_ici();
    }
    let taille = p.taille_vraie();
    let pktinfo = if s.pktinfo.load(Ordering::Relaxed) { (a.lieu.interface, a.lieu.reponse) } else { (0, format_ipv4::AUCUNE) };
    let d = Datagramme {
        regarde: false, paquet: p, source: a.source, port: a.port, destination: a.destination, pktinfo,
        entete: a.entete, port_destination: a.port_destination, somme: a.somme, taille, pertes: 0,
    };
    // `__udp_queue_rcv_skb`.
    if let Err(r) = s.deposer(d, Admission::Udp) {
        MIB.udp(if r == Rejet::Pleine { Compteur::RcvbufErrors } else { Compteur::MemErrors });
        MIB.udp(Compteur::InErrors);
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
/// le message portait de la charge d'origine. Sans socket, l'erreur est
/// refusée (ICMP InErrors, comme chez Linux).
pub fn erreur(e: &ErreurRecue) {
    let Some((port_source, port_destination)) = formats::reseau::icmp::ports(e.origine, &e.interne) else { return };
    let i = &e.interne;
    // La socket d'une erreur : cherchée par l'interface qui l'a reçue (le
    // `skb->dev` d'`__udp4_lib_err`), pas par celle de sa route (TCP et ping
    // prennent celle-là).
    let ici = crate::processeur::numero() as i32;
    let Some(s) = PORTS.verrouiller().as_ref()
        .and_then(|t| t.trouver(i.destination, port_destination, i.source, port_source, e.interface, |s| de_ce_processeur(s, ici))) else {
        return MIB.icmp(inet::snmp::Icmp::InErrors);
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
/// de la copie, ce que lira le programme. Avec IP_RECVERR_RFC4884, l'erreur
/// en file dit aussi où y commencent les extensions du message (RFC 4884,
/// `ip_icmp_error`), comptées dans ce que lit le programme.
pub fn signaler(s: &Socket, e: &ErreurRecue, errno: i32, fatale: bool, port: u16, debut: usize) {
    if !s.recverr.load(Ordering::Relaxed) {
        if !fatale || !s.connectee.load(Ordering::Relaxed) {
            return;
        }
    } else {
        let entetes = e.interne.longueur_entete + debut;
        let charge = e.origine.get(entetes..).unwrap_or(&[]);
        let ee_data = if s.rfc4884.load(Ordering::Relaxed) {
            formats::reseau::icmp::extensions_rfc4884(e.message, entetes).map_or(0, |x| x.ee_data())
        } else {
            0
        };
        if let Some(donnees) = Paquet::copie(charge) {
            let taille = donnees.taille_vraie();
            s.mettre_en_file(ErreurEnFile {
                errno, origine: socket::ORIGINE_ICMP, genre: e.genre, code: e.code, info: e.info, ee_data,
                adresse: e.interne.destination, port, emetteur: e.emetteur, interface: e.interface,
                arrivee: e.destination, entete: *e.entete, somme: somme_linux(e.message), horodatage: e.horodatage, donnees, taille,
                stats: false,
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
