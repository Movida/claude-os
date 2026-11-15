//! La multidiffusion (les soldes d'avant 6k) : les groupes de chaque
//! interface, et les adhésions des sockets. Les règles (qui adhère à quoi,
//! les filtres de sources, ce qui entre) sont dans inet::multidiffusion,
//! testées sur l'hôte ; ici, la colle : le verrou de l'ensemble, la
//! recherche de l'interface d'une demande (`ip_mc_find_dev`, qui lit les
//! interfaces et la table de routage), et /proc/net/igmp et mcfilter.
//!
//! LES VERROUS. `GROUPES` fait de chaque opération un tout (le `rtnl_lock`
//! de Linux) ; les adhésions de chaque socket ont le leur (`Socket::
//! adhesions`), que lit aussi la livraison d'un datagramme. L'ordre : la
//! table de routage d'abord, seule (`trouver` la lit et la lâche), puis
//! `GROUPES`, puis les adhésions d'une socket ; à la livraison, la table des
//! ports d'UDP, puis les adhésions. Jamais l'inverse.
//!
//! LES ÉCARTS VOULUS. Pas d'IPv6, ni ses groupes. Pas de routage de la
//! multidiffusion (MRT_*, refusés : EOPNOTSUPP). Une interface ne descend
//! jamais (pas d'`ip_mc_down`). /proc/net/mcfilter montre toujours toutes
//! les sources (`ligne_mcfilter`).
//! Pas de /proc/net/netstat (InMcastPkts, OutMcastPkts…).

use super::interface;
use super::ipv4;
use super::socket::Socket;
use crate::verrou::Verrou;
use core::fmt::{self, Write};
use core::sync::atomic::Ordering;
use formats::reseau::ipv4 as format_ipv4;
use inet::multidiffusion::{Demande, Groupes, MAX_SOURCES, Mode, Refus};
use inet::routes::Portee;

const EINVAL: i64 = 22;
const ENODEV: i64 = 19;
const EADDRINUSE: i64 = 98;
const ENOBUFS: i64 = 105;
const EADDRNOTAVAIL: i64 = 99;

/// Les groupes de chaque interface.
static GROUPES: Verrou<Groupes> = Verrou::new(Groupes::new());

fn errno(r: Refus) -> i64 {
    match r {
        Refus::Invalide => -EINVAL,
        Refus::PasDInterface => -ENODEV,
        Refus::DejaMembre => -EADDRINUSE,
        Refus::PlusDePlace => -ENOBUFS,
        Refus::Introuvable => -EADDRNOTAVAIL,
    }
}

/// L'interface `index` monte (`ip_mc_up`) : elle adhère à 224.0.0.1. Sans
/// mémoire, elle n'aura aucun groupe : aucune adhésion ne s'y fera
/// (ENODEV), rien n'y entrera pour un groupe.
pub fn monter(index: u32) {
    let _ = GROUPES.verrouiller().monter(index);
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

/// Adhère au groupe de `d` dans le mode `mode` (`__ip_mc_join_group`) ;
/// rend l'index de l'interface.
pub fn joindre(s: &Socket, d: Demande, mode: Mode) -> Result<u32, i64> {
    let trouvee = trouver(d);
    let mut g = GROUPES.verrouiller();
    s.adhesions.verrouiller().joindre(&mut g, d, trouvee, mode).map_err(errno)
}

/// Quitte le groupe de `d` (`ip_mc_leave_group`).
pub fn quitter(s: &Socket, d: Demande) -> Result<(), i64> {
    let trouvee = trouver(d);
    let mut g = GROUPES.verrouiller();
    s.adhesions.verrouiller().quitter(&mut g, d, trouvee).map_err(errno)
}

/// Ajoute ou retire une source du filtre de mode `mode` (`ip_mc_source`).
pub fn source(s: &Socket, ajout: bool, mode: Mode, d: Demande, source: [u8; 4]) -> Result<(), i64> {
    let trouvee = trouver(d);
    let mut g = GROUPES.verrouiller();
    s.adhesions.verrouiller().source(&mut g, ajout, mode, d, trouvee, source).map_err(errno)
}

/// Adhère au groupe de `d` en INCLUDE et y ajoute la source `source`
/// (IP_ADD_SOURCE_MEMBERSHIP, MCAST_JOIN_SOURCE_GROUP), d'un seul tenant :
/// sous une seule prise de `GROUPES` (inet::multidiffusion,
/// `Adhesions::joindre_avec_source`).
pub fn joindre_avec_source(s: &Socket, d: Demande, source: [u8; 4]) -> Result<(), i64> {
    let trouvee = trouver(d);
    let mut g = GROUPES.verrouiller();
    s.adhesions.verrouiller().joindre_avec_source(&mut g, d, trouvee, source).map_err(errno)
}

/// Remplace le filtre (`ip_mc_msfilter`).
pub fn filtrer(s: &Socket, d: Demande, fmode: u32, sources: &[[u8; 4]]) -> Result<(), i64> {
    let trouvee = trouver(d);
    let mut g = GROUPES.verrouiller();
    s.adhesions.verrouiller().filtrer(&mut g, d, trouvee, fmode, sources).map_err(errno)
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
    let mut g = GROUPES.verrouiller();
    s.adhesions.verrouiller().vider(&mut g);
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

/// L'enregistrement `n` de /proc/net/igmp (`igmp_mc_seq_show`), dans `t` :
/// l'en-tête, puis un par groupe de chaque interface, le plus récent
/// d'abord ; le premier d'une interface est précédé d'une ligne pour elle
/// (son index, son nom, son nombre de groupes, et la version d'IGMP de son
/// routeur, V3 sans en avoir entendu un plus vieux). Sans IGMP, aucun
/// minuteur ne tourne (« 0:00000000 ») et aucun rapport n'a été envoyé.
/// Faux : il n'y en a plus.
pub fn ligne_igmp(n: u64, t: &mut dyn Write) -> Result<bool, fmt::Error> {
    if n == 0 {
        t.write_str("Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n")?;
        return Ok(true);
    }
    let mut reste = n as usize - 1;
    let ligne = {
        let g = GROUPES.verrouiller();
        let mut trouve = None;
        for i in g.interfaces() {
            let compte = i.groupes().count();
            if reste < compte {
                let x = i.groupes().nth(reste);
                trouve = x.map(|x| (i.index(), compte, reste == 0, x.adresse(), x.utilisateurs()));
                break;
            }
            reste -= compte;
        }
        trouve
    };
    let Some((index, compte, premier, groupe, utilisateurs)) = ligne else { return Ok(false) };
    if premier {
        writeln!(t, "{}\t{:<10}: {:>5} {:>7}", index, nom(index), compte, "V3")?;
    }
    writeln!(t, "\t\t\t\t{:08X} {:>5} {}:{:08X}\t\t{}", hexa(groupe), utilisateurs, 0, 0, 0)?;
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
