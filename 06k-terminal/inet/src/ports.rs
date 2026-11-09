//! La table des ports d'UDP (l'`udp_table` de Linux, net/ipv4/udp.c) : à
//! quelle socket va un datagramme reçu, et quels ports une socket peut
//! prendre.
//!
//! Une socket UDP a une adresse et un port LOCAUX (0.0.0.0 : toutes nos
//! adresses), et, si elle est connectée, une adresse et un port DISTANTS
//! (alors elle ne reçoit que de là). Les règles de Linux :
//!   - PRENDRE UN PORT (`udp_lib_get_port`) : un port pris par une autre
//!     socket dont l'adresse locale recouvre la nôtre (égale, ou l'une des
//!     deux 0.0.0.0) est refusé (EADDRINUSE), sauf si les deux ont
//!     SO_REUSEADDR, ou SO_REUSEPORT et le même utilisateur. Le port 0
//!     demande un port ÉPHÉMÈRE, au hasard dans la plage (32768 à 60999,
//!     `ip_local_port_range`), comme Linux : un premier port tiré, puis des
//!     pas d'un multiple impair et tiré de la taille de la table, dans la
//!     même classe (modulo la taille), puis la classe suivante : tous les
//!     ports sont essayés, dans un ordre qu'un autre ne peut pas deviner
//!     (un port prévisible aide à usurper une réponse DNS) ;
//!   - CHOISIR LA SOCKET d'un datagramme (`__udp4_lib_lookup`) : d'abord
//!     celles liées à l'adresse de destination, puis celles liées à
//!     0.0.0.0 ; parmi elles, la mieux notée (`compute_score` : connectée à
//!     l'émetteur, +4 pour l'adresse, +4 pour le port ; une socket
//!     connectée ailleurs n'est pas candidate) ;
//!   - une DIFFUSION va à chaque socket du port qui l'accepte
//!     (`__udp4_lib_mcast_deliver`).
//!
//! Une taille fixe, réservée d'avance (1024 sockets liées à la fois : un
//! écart, Linux n'a d'autre limite que la mémoire) : lier une socket ne
//! prend pas de mémoire, et « mémoire rendue » ne bouge pas. Chaque entrée
//! porte un numéro (celui de la socket, pour la retrouver) et un objet `T`
//! (la socket du noyau).

use alloc::vec::Vec;

/// La taille de la table.
pub const MAX: usize = 1024;
/// La taille des « classes » du choix éphémère (celle de la table de
/// hachage de Linux pour une petite machine, `uhash_entries` minimal).
const CLASSES: u32 = 256;
/// La plage des ports éphémères (`ip_local_port_range`).
pub const EPHEMERE_MIN: u16 = 32768;
pub const EPHEMERE_MAX: u16 = 60999;
/// Le premier port qu'un programme sans privilège peut prendre
/// (`ip_unprivileged_port_start`).
pub const PRIVILEGIE: u16 = 1024;

/// Où est liée une socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lien {
    pub adresse: [u8; 4],
    pub port: u16,
    /// La destination d'une socket connectée (0.0.0.0:0 sinon).
    pub distante: [u8; 4],
    pub port_distant: u16,
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub uid: u32,
}

/// Pourquoi un port n'est pas donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Pris (EADDRINUSE) ; ou, pour un port éphémère, plus aucun libre
    /// (EADDRINUSE aussi chez Linux, faute de mieux).
    Pris,
    /// La table est pleine (ENOBUFS : un écart).
    Plein,
}

struct Entree<T> {
    numero: u64,
    lien: Lien,
    objet: T,
}

/// La table.
pub struct Table<T> {
    entrees: Vec<Entree<T>>,
}

/// Deux liens se gênent-ils sur le même port ?
fn conflit(a: &Lien, b: &Lien) -> bool {
    let reutilise = (a.reuseaddr && b.reuseaddr) || (a.reuseport && b.reuseport && a.uid == b.uid);
    let recouvre = a.adresse == [0; 4] || b.adresse == [0; 4] || a.adresse == b.adresse;
    !reutilise && recouvre
}

impl<T: Clone> Table<T> {
    /// Une table vide, sa place réservée. None : plus de mémoire.
    pub fn new() -> Option<Table<T>> {
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(MAX).ok()?;
        Some(Table { entrees })
    }

    /// Le port `port` est-il libre pour `lien` (sauf la socket `numero`
    /// elle-même) ?
    fn libre(&self, numero: u64, port: u16, lien: &Lien) -> bool {
        !self.entrees.iter().any(|e| e.numero != numero && e.lien.port == port && conflit(&e.lien, lien))
    }

    /// Lie la socket `numero` (objet `objet`) selon `lien` ; son port 0
    /// demande un port éphémère, tiré d'après `hasard`. Rend le port.
    pub fn lier(&mut self, numero: u64, lien: Lien, objet: T, hasard: u32) -> Result<u16, Refus> {
        if self.entrees.len() >= MAX {
            return Err(Refus::Plein);
        }
        let port = if lien.port != 0 {
            if !self.libre(numero, lien.port, &lien) {
                return Err(Refus::Pris);
            }
            lien.port
        } else {
            self.ephemere(numero, &lien, hasard).ok_or(Refus::Pris)?
        };
        self.entrees.push(Entree { numero, lien: Lien { port, ..lien }, objet });
        Ok(port)
    }

    /// Le choix d'un port éphémère de `udp_lib_get_port` (voir plus haut).
    fn ephemere(&self, numero: u64, lien: &Lien, hasard: u32) -> Option<u16> {
        let (bas, haut) = (EPHEMERE_MIN as u32, EPHEMERE_MAX as u32);
        let restant = haut - bas + 1;
        // Le `reciprocal_scale` de Linux : le hasard ramené à [0, restant[.
        let mut premier = ((hasard as u64 * restant as u64) >> 32) as u32 + bas;
        let pas = (hasard | 1).wrapping_mul(CLASSES) as u16;
        for _ in 0..CLASSES {
            let mut port = premier as u16;
            loop {
                if (bas..=haut).contains(&(port as u32)) && self.libre(numero, port, lien) {
                    return Some(port);
                }
                port = port.wrapping_add(pas);
                if port == premier as u16 {
                    break;
                }
            }
            premier += 1;
        }
        None
    }

    /// Change le lien de la socket `numero` (connect, ou la fin d'une
    /// connexion), son port gardé.
    pub fn changer(&mut self, numero: u64, distante: [u8; 4], port_distant: u16, adresse: [u8; 4]) {
        if let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) {
            e.lien.distante = distante;
            e.lien.port_distant = port_distant;
            e.lien.adresse = adresse;
        }
    }

    /// Change SO_REUSEADDR et SO_REUSEPORT de la socket `numero` : Linux lit
    /// l'option de chaque socket au moment du conflit, pas à son `bind`.
    pub fn reutiliser(&mut self, numero: u64, reuseaddr: bool, reuseport: bool) {
        if let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) {
            e.lien.reuseaddr = reuseaddr;
            e.lien.reuseport = reuseport;
        }
    }

    /// Retire la socket `numero` (son port est rendu).
    pub fn retirer(&mut self, numero: u64) {
        self.entrees.retain(|e| e.numero != numero);
    }

    /// Le lien de la socket `numero`.
    pub fn lien(&self, numero: u64) -> Option<Lien> {
        self.entrees.iter().find(|e| e.numero == numero).map(|e| e.lien)
    }

    /// La socket qui reçoit un datagramme de `source`:`port_source` pour
    /// `destination`:`port` (voir plus haut).
    pub fn trouver(&self, source: [u8; 4], port_source: u16, destination: [u8; 4], port: u16) -> Option<T> {
        let note = |l: &Lien, locale: [u8; 4]| -> Option<u32> {
            if l.port != port || l.adresse != locale {
                return None;
            }
            let mut n = 2;
            if l.distante != [0; 4] {
                if l.distante != source {
                    return None;
                }
                n += 4;
            }
            if l.port_distant != 0 {
                if l.port_distant != port_source {
                    return None;
                }
                n += 4;
            }
            Some(n)
        };
        for locale in [destination, [0; 4]] {
            // La meilleure note ; à égalité, la première liée (Linux, sans
            // groupe SO_REUSEPORT, prend la dernière vue de sa liste : la
            // plus récente en tête. Nous gardons l'ordre d'arrivée.)
            let mut meilleure: Option<(u32, &Entree<T>)> = None;
            for e in &self.entrees {
                if let Some(n) = note(&e.lien, locale) {
                    if meilleure.is_none_or(|(m, _)| n > m) {
                        meilleure = Some((n, e));
                    }
                }
            }
            if let Some((_, e)) = meilleure {
                return Some(e.objet.clone());
            }
        }
        None
    }

    /// Chaque socket qui reçoit une diffusion pour `destination`:`port` de
    /// `source`:`port_source` (`__udp_is_mcast_sock`).
    pub fn pour_chaque_diffusion(&self, source: [u8; 4], port_source: u16, destination: [u8; 4], port: u16, mut f: impl FnMut(&T)) {
        for e in &self.entrees {
            let l = &e.lien;
            if l.port == port
                && (l.adresse == [0; 4] || l.adresse == destination)
                && (l.distante == [0; 4] || l.distante == source)
                && (l.port_distant == 0 || l.port_distant == port_source)
            {
                f(&e.objet);
            }
        }
    }

    /// Chaque socket de la table.
    pub fn pour_chaque(&self, mut f: impl FnMut(&T)) {
        for e in &self.entrees {
            f(&e.objet);
        }
    }
}
