//! La multidiffusion (les soldes d'avant 6k) : les groupes de chaque
//! interface, les adhésions des sockets, et IGMP. Les règles (qui adhère à
//! quoi, les filtres de sources, ce qui entre, ce que disent les rapports
//! et quand) sont dans inet::multidiffusion, testées sur l'hôte ; ici, la
//! colle : le verrou de l'ensemble et l'heure qu'il donne, la recherche de
//! l'interface d'une demande (`ip_mc_find_dev`, qui lit les interfaces et
//! la table de routage), l'envoi des rapports et la réception des
//! messages d'IGMP, leur minuteur dans la tâche du réseau, le filtre de la
//! carte prévenu quand les adresses MAC de ses groupes changent, et
//! /proc/net/igmp, mcfilter et dev_mcast.
//!
//! LES VERROUS. `GROUPES` fait de chaque opération un tout (le `rtnl_lock`
//! de Linux) ; les adhésions de chaque socket ont le leur (`Socket::
//! adhesions`), que lit aussi la livraison d'un datagramme. L'ordre : la
//! table de routage d'abord, seule (`trouver` la lit et la lâche), ou la
//! file de contrôle de la carte (un verrou qui dort, tenu par la tâche du
//! réseau pendant qu'elle refait le filtre : virtio_net.rs), puis
//! `GROUPES`, puis les adhésions d'une socket, ou les échéances de la tâche
//! du réseau (`tache::inscrire`, qui ne prend rien d'autre) ; à la
//! livraison, la table des ports d'UDP, puis les adhésions. Jamais
//! l'inverse. Un rapport part une fois `GROUPES` lâché (`finir`) : l'envoi
//! prend la table, les MTU, la carte ; et la copie d'un rapport v2 vers un
//! de nos groupes revient (boucle.rs) jusqu'à `recevoir`, qui le reprend.
//!
//! LES ÉCARTS VOULUS. Pas d'IPv6, ni ses groupes. Pas de routage de la
//! multidiffusion (MRT_*, refusés : EOPNOTSUPP). Une interface ne descend
//! jamais (pas d'`ip_mc_down`). /proc/net/mcfilter montre toujours toutes
//! les sources (`ligne_mcfilter`).
//! Pas de /proc/net/netstat (InMcastPkts, OutMcastPkts…).
//! Pas de NETDEV_RESEND_IGMP : la carte n'annonce pas qu'elle a changé de
//! réseau (pas de VIRTIO_NET_F_GUEST_ANNOUNCE), et nos rapports ne sont
//! redits qu'aux requêtes.
//! /proc/net/dev_mcast n'a pas 33:33:00:00:00:01 (l'adresse MAC du groupe
//! de tous les nœuds d'IPv6, que Linux y montre aussi).

use super::interface;
use super::ipv4;
use super::paquet::Paquet;
use super::socket::{self, Socket};
use super::tache;
use crate::verrou::{Garde, Verrou};
use crate::{aleatoire, horloge, temps};
use core::fmt::{self, Write};
use core::sync::atomic::Ordering;
use formats::reseau::ipv4 as format_ipv4;
use inet::multidiffusion::{Demande, Envoi, Groupes, MAX_SOURCES, Mac, Mode, Refus};
use inet::routes::{Chemin, Portee};

const EINVAL: i64 = 22;
const ENODEV: i64 = 19;
const EADDRINUSE: i64 = 98;
const ENOBUFS: i64 = 105;
const EADDRNOTAVAIL: i64 = 99;

/// Les groupes de chaque interface.
static GROUPES: Verrou<Groupes> = Verrou::new(Groupes::new(aleatoire::u32_sous, mtu));

// Les délais d'IGMP sont comptés en jiffies de notre horloge.
const _: () = assert!(inet::multidiffusion::HZ == horloge::HZ as u64);

/// La MTU de l'interface `index` (0 : elle n'existe pas ; aucun rapport).
fn mtu(index: u32) -> u32 {
    interface::par_index(index).map_or(0, |i| i.mtu())
}

/// Les groupes, sous leur verrou, réglés à l'heure qu'il est.
fn groupes() -> Garde<'static, Groupes> {
    let mut g = GROUPES.verrouiller();
    g.regler(temps::ns_monotone());
    g
}

/// Après une opération sur les groupes : la prochaine échéance d'IGMP dans
/// la tâche du réseau (sous le verrou des groupes : deux opérations sur
/// deux processeurs ne peuvent pas s'y croiser, la dernière inscrite étant
/// celle des groupes tels qu'elle les a laissés), puis, le verrou lâché, le
/// filtre de la carte à refaire si les adresses MAC des groupes ont changé
/// (`__dev_set_rx_mode`, qui confie la commande à une tâche : la tâche du
/// réseau, ici, qui relira la liste telle qu'elle sera alors), et les
/// rapports prêts.
fn finir(mut g: Garde<'static, Groupes>) {
    let envois = g.prendre_les_envois();
    let filtre = g.prendre_les_macs_touchees();
    let (_, plus_tot) = tache::inscrire(tache::OBJET_IGMP, g.prochaine_echeance());
    drop(g);
    if plus_tot {
        tache::reveiller();
    }
    if filtre {
        tache::signaler(tache::FILTRE);
    }
    for e in envois {
        emettre(e);
    }
}

/// L'alerte aux routeurs (RFC 2113, « examine this packet ») : chaque
/// message d'IGMP la porte (`IPOPT_RA`), pour qu'un routeur le lise même
/// s'il n'est pas pour lui.
const ALERTE: [u8; 4] = [format_ipv4::option::ALERTE, 4, 0, 0];

/// Envoie le message d'IGMP `e` (`igmpv3_newpack`, `igmp_send_report`) :
/// par son interface, toujours (`ip_route_output_ports` avec son index),
/// de l'adresse qu'elle propose pour le lien (pour IGMP, Linux prend la
/// portée du lien, `ip_route_output_key_hash_rcu`), qu'un rapport v3 ne
/// garde que si elle est à cette interface (sinon 0.0.0.0 : par lo, mesuré)
/// ; TTL 1, TOS 0xc0 (la priorité du contrôle du réseau), DF, identifiant
/// 0 (DF sans socket, `ip_select_ident`), l'alerte aux routeurs. Vers un
/// groupe de l'interface (un rapport v2), une copie revient à la machine
/// (`ip_mc_output`), qu'IGMP ignorera. Un envoi qui ne se fait pas (pas de
/// mémoire) est perdu, comme chez Linux.
fn emettre(e: Envoi) {
    let index = e.interface;
    let Some(i) = interface::par_index(index) else { return };
    let proposee = ipv4::avec_table(|t| t.adresse_proposee(index, format_ipv4::AUCUNE, Portee::Lien)).flatten()
        .unwrap_or(format_ipv4::AUCUNE);
    let source = if e.v3 && ipv4::avec_table(|t| t.interface_locale(proposee)).flatten() != Some(index) {
        format_ipv4::AUCUNE
    } else {
        proposee
    };
    let locale = verifier(index, e.destination, source, format_ipv4::IGMP);
    let chemin = Chemin::Multidiffusion { interface: index, source, locale };
    let Some(mut p) = Paquet::vide(e.octets.len()) else { return };
    let Some(o) = p.ajouter_fin(e.octets.len()) else { return };
    o.copy_from_slice(&e.octets);
    let mut options = format_ipv4::OptionsSortantes::AUCUNE;
    options.octets[..ALERTE.len()].copy_from_slice(&ALERTE);
    options.longueur = ALERTE.len() as u8;
    let envoi = ipv4::Envoi {
        source,
        destination: e.destination,
        protocole: format_ipv4::IGMP,
        ttl: 1,
        tos: 0xc0,
        identifiant: 0,
        ne_pas_fragmenter: true,
        mtu: i.mtu(),
        confirmer: false,
        options,
        destination_finale: e.destination,
        boucle_mc: true,
    };
    ipv4::emettre(chemin, &envoi, p);
}

/// IGMP n'a-t-il plus rien à faire (aucune échéance : ni rapport à venir,
/// ni groupe parti à annoncer) ?
pub fn au_repos() -> bool {
    GROUPES.verrouiller().prochaine_echeance().is_none()
}

/// L'échéance d'IGMP est passée (la tâche du réseau) : les minuteurs échus
/// font leurs rapports.
pub fn temps() {
    let mut g = groupes();
    g.temps();
    finir(g);
}

/// Un message d'IGMP (`o` : ce que porte le paquet) arrivé par l'interface
/// `index` (`igmp_rcv`) : `de_nous`, notre propre envoi rendu par la boucle ;
/// `diffuse`, dans une trame pour plusieurs machines.
pub fn recevoir(index: u32, o: &[u8], de_nous: bool, diffuse: bool) {
    let mut g = groupes();
    g.recevoir(index, o, de_nous, diffuse);
    finir(g);
}

fn errno(r: Refus) -> i64 {
    match r {
        Refus::Invalide => -EINVAL,
        Refus::PasDInterface => -ENODEV,
        Refus::DejaMembre => -EADDRINUSE,
        Refus::PlusDePlace => -ENOBUFS,
        Refus::Introuvable => -EADDRNOTAVAIL,
    }
}

/// L'interface `index` monte (`ip_mc_up`) : elle adhère à 224.0.0.1.
/// `ethernet` : une carte (ses groupes ont une adresse MAC, pour son
/// filtre). Sans mémoire, elle n'aura aucun groupe : aucune adhésion ne s'y
/// fera (ENODEV), rien n'y entrera pour un groupe.
pub fn monter(index: u32, ethernet: bool) {
    let mut g = groupes();
    let _ = g.monter(index, ethernet);
    finir(g);
}

/// `f` sur les adresses MAC des groupes de l'interface `index` (aucune pour
/// lo, ou une interface sans groupes), sous le verrou des groupes : le
/// filtre de la carte (`netdev_for_each_mc_addr`).
pub fn avec_les_macs<T>(index: u32, f: impl FnOnce(&[Mac]) -> T) -> T {
    let g = GROUPES.verrouiller();
    f(g.interface(index).map_or(&[], |i| i.macs()))
}

/// L'interface que désigne la demande `d` (`ip_mc_find_dev`) : celle de son
/// index s'il en a un (qui n'existe pas : aucune) ; sinon celle qui porte
/// son adresse (`__ip_dev_find` : nos adresses, et lo pour 127.0.0.0/8) ;
/// sinon celle de la route vers le groupe (pas de route : aucune).
fn trouver(d: Demande) -> Option<u32> {
    if d.index != 0 {
        return interface::par_index(d.index).map(|i| i.index);
    }
    if d.adresse != format_ipv4::AUCUNE {
        return ipv4::avec_table(|t| t.interface_locale(d.adresse)).flatten();
    }
    ipv4::router(d.groupe, 0, Portee::Univers).ok().and_then(|(c, _)| ipv4::sortie(&c))
}

/// La place que les autres options de `s` laissent à ses adhésions dans la mémoire
/// de ses options (`Adhesions::borner` : son filtre, ses avis de MSG_ZEROCOPY). Les
/// changements qui en prennent la lisent, puis s'y tiennent, sous le `Mutex` des
/// appels de `s` (le `lock_sock` de Linux), comme SO_ATTACH_FILTER (filtre.rs) :
/// un filtre ne se pose pas entre les deux. (Un avis de MSG_ZEROCOPY peut venir :
/// Linux non plus ne le retient pas, `sock_omalloc` ne prend pas le verrou.)
fn place(s: &Socket) -> usize {
    socket::OPTMEM_MAX.saturating_sub(s.memoire_hors_adhesions())
}

/// Adhère au groupe de `d` dans le mode `mode` (`__ip_mc_join_group`) ;
/// rend l'index de l'interface.
pub fn joindre(s: &Socket, d: Demande, mode: Mode) -> Result<u32, i64> {
    let trouvee = trouver(d);
    let appels = s.appels.verrouiller();
    let place = place(s);
    let mut g = groupes();
    let r = {
        let mut a = s.adhesions.verrouiller();
        a.borner(place);
        a.joindre(&mut g, d, trouvee, mode).map_err(errno)
    };
    drop(appels);
    finir(g);
    r
}

/// Quitte le groupe de `d` (`ip_mc_leave_group`).
pub fn quitter(s: &Socket, d: Demande) -> Result<(), i64> {
    let trouvee = trouver(d);
    let mut g = groupes();
    let r = s.adhesions.verrouiller().quitter(&mut g, d, trouvee).map_err(errno);
    finir(g);
    r
}

/// Ajoute ou retire une source du filtre de mode `mode` (`ip_mc_source`).
pub fn source(s: &Socket, ajout: bool, mode: Mode, d: Demande, source: [u8; 4]) -> Result<(), i64> {
    let trouvee = trouver(d);
    let appels = s.appels.verrouiller();
    let place = place(s);
    let mut g = groupes();
    let r = {
        let mut a = s.adhesions.verrouiller();
        a.borner(place);
        a.source(&mut g, ajout, mode, d, trouvee, source).map_err(errno)
    };
    drop(appels);
    finir(g);
    r
}

/// Adhère au groupe de `d` en INCLUDE et y ajoute la source `source`
/// (IP_ADD_SOURCE_MEMBERSHIP, MCAST_JOIN_SOURCE_GROUP), d'un seul tenant :
/// sous une seule prise de `GROUPES` (inet::multidiffusion,
/// `Adhesions::joindre_avec_source`).
pub fn joindre_avec_source(s: &Socket, d: Demande, source: [u8; 4]) -> Result<(), i64> {
    let trouvee = trouver(d);
    let appels = s.appels.verrouiller();
    let place = place(s);
    let mut g = groupes();
    let r = {
        let mut a = s.adhesions.verrouiller();
        a.borner(place);
        a.joindre_avec_source(&mut g, d, trouvee, source).map_err(errno)
    };
    drop(appels);
    finir(g);
    r
}

/// Remplace le filtre (`ip_mc_msfilter`).
pub fn filtrer(s: &Socket, d: Demande, fmode: u32, sources: &[[u8; 4]]) -> Result<(), i64> {
    let trouvee = trouver(d);
    let appels = s.appels.verrouiller();
    let place = place(s);
    let mut g = groupes();
    let r = {
        let mut a = s.adhesions.verrouiller();
        a.borner(place);
        a.filtrer(&mut g, d, trouvee, fmode, sources).map_err(errno)
    };
    drop(appels);
    finir(g);
    r
}

/// Un filtre lu : son mode, ses sources (les `n` premières).
pub struct Filtre {
    pub mode: Mode,
    pub n: usize,
    pub sources: [[u8; 4]; MAX_SOURCES],
}

fn copier_filtre(r: Result<(Mode, &[[u8; 4]]), Refus>) -> Result<Filtre, i64> {
    let (mode, s) = r.map_err(errno)?;
    let mut f = Filtre { mode, n: s.len(), sources: [[0; 4]; MAX_SOURCES] };
    f.sources[..s.len()].copy_from_slice(s);
    Ok(f)
}

/// Le filtre de l'adhésion au groupe de `d` par l'interface qu'elle désigne
/// (`ip_mc_msfget`), copié : les verrous sont lâchés avant de l'écrire au
/// programme.
pub fn filtre(s: &Socket, d: Demande) -> Result<Filtre, i64> {
    let trouvee = trouver(d);
    copier_filtre(s.adhesions.verrouiller().filtre(d.groupe, trouvee))
}

/// Le même, par l'index d'une interface (`ip_mc_gsfget`).
pub fn filtre_par_index(s: &Socket, groupe: [u8; 4], index: u32) -> Result<Filtre, i64> {
    copier_filtre(s.adhesions.verrouiller().filtre_par_index(groupe, index))
}

/// La socket se ferme (`ip_mc_drop_socket`) : ses adhésions sont rendues.
pub fn fermer(s: &Socket) {
    if s.adhesions.verrouiller().est_vide() {
        return;
    }
    let mut g = groupes();
    s.adhesions.verrouiller().vider(&mut g);
    finir(g);
}

/// La socket `s` prend-elle ce datagramme de `source` pour `destination`,
/// arrivé par l'interface `dif` (`ip_mc_sf_allow`) ? Vrai pour ce qui n'est
/// pas pour un groupe ; sinon, selon ses adhésions (et IP_MULTICAST_ALL).
/// Lu à la livraison, sous la table des ports d'UDP.
pub fn permet(s: &Socket, destination: [u8; 4], source: [u8; 4], dif: u32) -> bool {
    if !format_ipv4::multidiffusion(destination) {
        return true;
    }
    s.adhesions.verrouiller().permet(destination, source, dif, s.mc_all.load(Ordering::Relaxed))
}

/// Un paquet de `source` pour `groupe`, de protocole `protocole`, entre-t-il
/// par l'interface `index` (`ip_check_mc_rcu`) ? À l'arrivée par une carte
/// (ipv4.rs), et à l'envoi : RTCF_LOCAL (datagramme.rs).
pub fn verifier(index: u32, groupe: [u8; 4], source: [u8; 4], protocole: u8) -> bool {
    GROUPES.verrouiller().verifier(index, groupe, source, protocole)
}

/// Une adresse comme la montre /proc/net/igmp : l'entier de l'ordre du
/// réseau, lu par une machine petit-boutiste (224.0.0.1 : 010000E0).
fn hexa(a: [u8; 4]) -> u32 {
    u32::from_le_bytes(a)
}

/// Le nom de l'interface `index`.
fn nom(index: u32) -> &'static str {
    interface::par_index(index).map_or("", |i| i.nom)
}

/// Une ligne de /proc/net/igmp, copiée sous le verrou des groupes.
struct LigneIgmp {
    index: u32,
    compte: usize,
    premier: bool,
    version: u8,
    groupe: [u8; 4],
    utilisateurs: u32,
    /// Ce qui reste au minuteur du groupe, s'il tourne, en ns.
    minuteur: Option<u64>,
    rapporteur: bool,
}

/// L'enregistrement `n` de /proc/net/igmp (`igmp_mc_seq_show`), dans `t` :
/// l'en-tête, puis un par groupe de chaque interface, le plus récent
/// d'abord ; le premier d'une interface est précédé d'une ligne pour elle
/// (son index, son nom, son nombre de groupes, et la version d'IGMP de son
/// routeur : V1 ou V2 s'il en a entendu un depuis assez peu, sinon V3).
/// Puis, par groupe : ses membres, son minuteur (« 1: » et ce qui lui
/// reste, en centièmes de seconde, les `clock_t` de USER_HZ, s'il tourne ;
/// sinon « 0:00000000 »), et si le dernier rapport sur lui vient de nous.
/// Faux : il n'y en a plus.
pub fn ligne_igmp(n: u64, t: &mut dyn Write) -> Result<bool, fmt::Error> {
    if n == 0 {
        t.write_str("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n")?;
        return Ok(true);
    }
    let mut reste = n as usize - 1;
    let maintenant = temps::ns_monotone();
    let ligne = {
        let g = GROUPES.verrouiller();
        let mut trouve = None;
        for i in g.interfaces() {
            let compte = i.groupes().count();
            if reste < compte {
                trouve = i.groupes().nth(reste).map(|x| LigneIgmp {
                    index: i.index(),
                    compte,
                    premier: reste == 0,
                    version: i.version(maintenant),
                    groupe: x.adresse(),
                    utilisateurs: x.utilisateurs(),
                    minuteur: x.minuteur().map(|e| e.saturating_sub(maintenant)),
                    rapporteur: x.rapporteur(),
                });
                break;
            }
            reste -= compte;
        }
        trouve
    };
    let Some(l) = ligne else { return Ok(false) };
    if l.premier {
        writeln!(t, "{}\t{:<10}: {:>5} {:>7}", l.index, nom(l.index), l.compte, ["V1", "V2", "V3"][l.version as usize - 1])?;
    }
    // `jiffies_delta_to_clock_t` : en centièmes, arrondi vers le bas.
    let (court, reste) = match l.minuteur {
        Some(r) => (1, r / 10_000_000),
        None => (0, 0),
    };
    writeln!(t, "\t\t\t\t{:08X} {:>5} {}:{:08X}\t\t{}", hexa(l.groupe), l.utilisateurs, court, reste, l.rapporteur as u8)?;
    Ok(true)
}

/// L'enregistrement `n` de /proc/net/dev_mcast (`dev_mc_seq_show`) :
/// chaque adresse MAC de groupe de chaque interface (lo n'en a pas), dans
/// l'ordre de leur venue, avec ses groupes ; le deuxième compte, celui des
/// adresses « globales » (`dev_mc_add_global`, des pilotes de pont), est
/// toujours 0. Pas d'en-tête.
pub fn ligne_dev_mcast(n: u64, t: &mut dyn Write) -> Result<bool, fmt::Error> {
    let ligne = {
        let g = GROUPES.verrouiller();
        let mut toutes = g.interfaces().flat_map(|i| i.macs().iter().map(move |m| (i.index(), *m)));
        toutes.nth(n as usize)
    };
    let Some((index, m)) = ligne else { return Ok(false) };
    let a = m.adresse;
    writeln!(t, "{:<4} {:<15} {:<5} {:<5} {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", index, nom(index), m.groupes, 0, a[0], a[1],
             a[2], a[3], a[4], a[5])?;
    Ok(true)
}

/// L'enregistrement `n` de /proc/net/mcfilter (`igmp_mcf_seq_show`) :
/// l'en-tête, puis chaque source de chaque groupe (le plus récent d'abord)
/// de chaque interface, avec les sockets qui l'incluent et celles qui
/// l'excluent ; les adresses en entiers (`ntohl`), le nom coupé à 6
/// caractères.
///
/// Écart voulu : toutes les sources, toujours. L'itérateur de Linux
/// (`igmp_mcf_get_first`) ne regarde, pour commencer, que le groupe le plus
/// récent de chaque interface : tant que celui-là n'a pas de source, il
/// passe à l'interface suivante, et les autres groupes de celle-ci ne sont
/// pas montrés (`igmp_mcf_get_next`, lui, parcourt tout). Mesuré sous Linux
/// 6.18.33 : une adhésion à 239.77.1.1 en INCLUDE {10.0.0.1}, puis une à
/// 239.77.2.2 sans source, et le fichier n'a plus que son en-tête ; une
/// troisième, avec une source, et les deux lignes reviennent. Un accident
/// de son code, qu'aucun programme ne peut attendre.
pub fn ligne_mcfilter(n: u64, t: &mut dyn Write) -> Result<bool, fmt::Error> {
    if n == 0 {
        t.write_str("Idx Device        MCA        SRC    INC    EXC\n")?;
        return Ok(true);
    }
    let ligne = {
        let g = GROUPES.verrouiller();
        let mut toutes = g.interfaces()
            .flat_map(|i| i.groupes().flat_map(move |x| x.sources().map(move |s| (i.index(), x.adresse(), *s))));
        toutes.nth(n as usize - 1).map(|(index, groupe, s)| (index, groupe, s.adresse(), s.inclus(), s.exclus()))
    };
    let Some((index, groupe, source, inclus, exclus)) = ligne else { return Ok(false) };
    writeln!(t, "{:>3} {:>6.6} 0x{:08x} 0x{:08x} {:>6} {:>6}", index, nom(index), u32::from_be_bytes(groupe),
             u32::from_be_bytes(source), inclus, exclus)?;
    Ok(true)
}
