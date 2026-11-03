//! Ce que montre /proc/net du réseau, ligne par ligne, aux formats de Linux
//! (procfs.rs les sert, comme ses autres séquences) :
//!   - `pnp` : la configuration reçue au démarrage, au format de
//!     /etc/resolv.conf (le `pnp_seq_show` d'ipconfig.c) ;
//!   - `route` : la table de routage principale (le `fib_route_seq_show`
//!     de fib_trie.c), chaque ligne complétée à 127 colonnes ;
//!   - `dev` : les compteurs de chaque interface (le `dev_seq_show` de
//!     net-procfs.c) ;
//!   - `arp` : la table des voisins (le `arp_seq_show` d'arp.c) ;
//!   - `tcp` : les sockets TCP (le `tcp4_seq_show` de tcp_ipv4.c, 6h) ;
//!   - `unix` : les sockets AF_UNIX (le `unix_seq_show` d'af_unix.c, 6h).
//! Les adresses de `route` s'écrivent comme Linux les imprime : le mot de
//! 32 bits gros-boutiste lu comme un nombre de la machine (petit-boutiste),
//! en hexadécimal : 10.0.2.2 donne 0202000A.

use super::interface;
use crate::faillible::VecFaillible;
use alloc::vec::Vec;
use core::fmt::{self, Write};
use core::sync::atomic::Ordering;
use formats::reseau::Ipv4Affichee;

/// Les fichiers de /proc/net.
#[derive(Clone, Copy)]
pub enum Fichier {
    Pnp,
    Route,
    Dev,
    Arp,
    Tcp,
    Unix,
}

/// Un bloc du tas où écrire avec `write!`, qui échoue sans paniquer.
struct Texte(Vec<u8>);

impl Write for Texte {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.ajouter_tranche(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Une adresse comme la montre /proc/net/route.
fn hexa(a: [u8; 4]) -> u32 {
    u32::from_le_bytes(a)
}

/// La ligne `n` (à partir de 0) du fichier `f`, sans le dernier saut de
/// ligne pour `route` (ajouté avec le bourrage) ; None : il n'y en a plus.
/// Err : plus de mémoire.
pub fn ligne(f: Fichier, n: u64) -> Result<Option<Vec<u8>>, ()> {
    let mut t = Texte(Vec::new());
    let ecrite = match f {
        Fichier::Pnp => pnp(&mut t, n),
        Fichier::Route => route(&mut t, n),
        Fichier::Dev => dev(&mut t, n),
        Fichier::Arp => super::arp::ligne_proc(n, &mut t),
        Fichier::Tcp => super::tcp::ligne_proc(n, &mut t),
        Fichier::Unix => super::unix::ligne_proc(n, &mut t),
    };
    match ecrite {
        Ok(true) => Ok(Some(t.0)),
        Ok(false) => Ok(None),
        Err(fmt::Error) => Err(()),
    }
}

/// /proc/net/pnp : « #PROTO: DHCP », le domaine, les serveurs DNS, le
/// serveur DHCP ; « #MANUAL » sans bail.
fn pnp(t: &mut Texte, n: u64) -> Result<bool, fmt::Error> {
    let Some(b) = super::dhcp::bail() else {
        if n == 0 {
            writeln!(t, "#MANUAL")?;
        }
        return Ok(n == 0);
    };
    let mut lignes: [Option<Ligne>; 6] = [None; 6];
    lignes[0] = Some(Ligne::Proto);
    let mut k = 1;
    if b.domaine().is_some() {
        lignes[k] = Some(Ligne::Domaine);
        k += 1;
    }
    for d in b.dns.iter().flatten() {
        lignes[k] = Some(Ligne::Dns(*d));
        k += 1;
    }
    lignes[k] = Some(Ligne::Serveur(b.amorce));
    let Some(Some(l)) = lignes.get(n as usize) else { return Ok(false) };
    match *l {
        Ligne::Proto => writeln!(t, "#PROTO: DHCP")?,
        Ligne::Domaine => {
            t.write_str("domain ")?;
            for &o in b.domaine().unwrap_or(&[]) {
                // Un nom de domaine est de l'ASCII ; le reste remplacé.
                t.write_char(if o.is_ascii_graphic() { o as char } else { '?' })?;
            }
            t.write_char('\n')?;
        }
        Ligne::Dns(a) => writeln!(t, "nameserver {}", Ipv4Affichee(a))?,
        Ligne::Serveur(a) => writeln!(t, "bootserver {}", Ipv4Affichee(a))?,
    }
    Ok(true)
}

#[derive(Clone, Copy)]
enum Ligne {
    Proto,
    Domaine,
    Dns([u8; 4]),
    Serveur([u8; 4]),
}

/// Complète la ligne à 127 colonnes, puis le saut de ligne (le
/// `seq_setwidth` et `seq_pad` de Linux).
fn bourrer(t: &mut Texte) -> fmt::Result {
    while t.0.len() < 127 {
        t.write_char(' ')?;
    }
    t.write_char('\n')
}

/// /proc/net/route : l'en-tête, puis une ligne par route principale.
fn route(t: &mut Texte, n: u64) -> Result<bool, fmt::Error> {
    if n == 0 {
        t.write_str("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT")?;
        bourrer(t)?;
        return Ok(true);
    }
    let Some(r) = super::ipv4::avec_table(|table| table.principales().nth(n as usize - 1)).flatten() else {
        return Ok(false);
    };
    let nom = interface::par_index(r.interface).map_or("*", |i| i.nom);
    // RTF_UP, et RTF_GATEWAY pour une route par une passerelle.
    let drapeaux = 1 | if r.passerelle.is_some() { 2 } else { 0 };
    write!(t, "{}\t{:08X}\t{:08X}\t{:04X}\t{}\t{}\t{}\t{:08X}\t{}\t{}\t{}", nom, hexa(r.reseau),
           hexa(r.passerelle.unwrap_or([0; 4])), drapeaux, 0, 0, 0, hexa(formats::reseau::ipv4::masque(r.prefixe)), 0, 0, 0)?;
    bourrer(t)?;
    Ok(true)
}

/// /proc/net/dev : deux lignes d'en-tête, puis une par interface.
fn dev(t: &mut Texte, n: u64) -> Result<bool, fmt::Error> {
    match n {
        0 => writeln!(t, "Inter-|   Receive                                                |  Transmit")?,
        1 => writeln!(t, " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed")?,
        _ => {
            let Some(i) = interface::par_index(n as u32 - 1) else { return Ok(false) };
            let c = &i.compteurs;
            let l = |x: &core::sync::atomic::AtomicU64| x.load(Ordering::Relaxed);
            writeln!(t, "{:>6}: {:>7} {:>7} {:>4} {:>4} {:>4} {:>5} {:>10} {:>9} {:>8} {:>7} {:>4} {:>4} {:>4} {:>5} {:>7} {:>10}",
                     i.nom, l(&c.octets_recus), l(&c.recus), 0, l(&c.jetes_reception), 0, 0, 0, 0,
                     l(&c.octets_emis), l(&c.emis), 0, l(&c.jetes_emission), 0, 0, 0, 0)?;
        }
    }
    Ok(true)
}
