//! La table des sockets de ping (la `ping_table` de Linux, net/ipv4/ping.c)
//! : à quelle socket va une réponse à l'écho, et quels identifiants une
//! socket peut prendre.
//!
//! Une socket de ping n'a pas de port : son « port » est l'identifiant de
//! ses échos (le noyau le met dans chaque écho qu'elle envoie, à la place
//! de celui du programme), et une réponse revient à la socket qui a cet
//! identifiant. Les règles de Linux, différentes de celles d'UDP
//! (ports.rs) :
//!   - PRENDRE UN IDENTIFIANT (`ping_get_port`) : un identifiant pris par
//!     une autre socket est refusé, quelle que soit son adresse, sauf si
//!     les deux ont SO_REUSEADDR. L'identifiant 0 demande le suivant libre
//!     après le dernier donné (le `ping_port_rover`), en sautant 0 : des
//!     identifiants qui se suivent, pas tirés au hasard (Linux non plus :
//!     une réponse à l'écho ne se fabrique pas sans savoir quel écho est
//!     parti, et seul l'émetteur le sait) ;
//!   - TROUVER LA SOCKET d'une réponse (`ping_lookup`) : la première qui a
//!     l'identifiant, et dont l'adresse locale est 0.0.0.0 ou la
//!     destination de la réponse ; Linux parcourt son seau de la socket
//!     la plus récente à la plus ancienne, nous aussi.
//!
//! Une taille fixe, réservée d'avance (1024 sockets à la fois, comme la
//! table des ports : un écart), et chaque entrée porte le numéro de la
//! socket et un objet `T` (la socket du noyau).

use alloc::vec::Vec;
use faillible::VecFaillible;

/// La taille de la table.
pub const MAX: usize = 1024;

/// Pourquoi un identifiant n'est pas donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Pris (EADDRINUSE) ; ou, pour 0, plus aucun de libre.
    Pris,
    /// La table est pleine (ENOBUFS : un écart).
    Plein,
}

struct Entree<T> {
    numero: u64,
    ident: u16,
    adresse: [u8; 4],
    reutilise: bool,
    objet: T,
}

/// La table.
pub struct Table<T> {
    entrees: Vec<Entree<T>>,
    /// Le dernier identifiant donné pour une demande de 0.
    dernier: u16,
}

impl<T: Clone> Table<T> {
    /// Une table vide, sa place réservée. None : plus de mémoire.
    pub fn new() -> Option<Table<T>> {
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(MAX).ok()?;
        Some(Table { entrees, dernier: 0 })
    }

    fn pris(&self, ident: u16) -> bool {
        self.entrees.iter().any(|e| e.ident == ident)
    }

    /// Inscrit la socket `numero` (objet `objet`), liée à `adresse`, avec
    /// l'identifiant `ident` (0 : le suivant libre) ; `reutilise` :
    /// SO_REUSEADDR. Rend l'identifiant.
    pub fn lier(&mut self, numero: u64, ident: u16, adresse: [u8; 4], reutilise: bool, objet: T) -> Result<u16, Refus> {
        if self.entrees.len() >= MAX {
            return Err(Refus::Plein);
        }
        let ident = if ident == 0 {
            let mut candidat = self.dernier;
            let trouve = (0..=u16::MAX as u32).find_map(|_| {
                candidat = candidat.wrapping_add(1);
                if candidat == 0 {
                    candidat = 1;
                }
                (!self.pris(candidat)).then_some(candidat)
            });
            let i = trouve.ok_or(Refus::Pris)?;
            self.dernier = i;
            i
        } else {
            if self.entrees.iter().any(|e| e.ident == ident && e.numero != numero && !(e.reutilise && reutilise)) {
                return Err(Refus::Pris);
            }
            ident
        };
        self.entrees.ajouter_dans_la_place(Entree { numero, ident, adresse, reutilise, objet });
        Ok(ident)
    }

    /// SO_REUSEADDR de la socket `numero` a changé.
    pub fn reutiliser(&mut self, numero: u64, reutilise: bool) {
        if let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) {
            e.reutilise = reutilise;
        }
    }

    /// L'adresse locale de la socket `numero` a changé (connect, ou sa fin).
    pub fn changer(&mut self, numero: u64, adresse: [u8; 4]) {
        if let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) {
            e.adresse = adresse;
        }
    }

    /// Retire la socket `numero` (son identifiant est rendu).
    pub fn retirer(&mut self, numero: u64) {
        self.entrees.retain(|e| e.numero != numero);
    }

    /// La socket qui reçoit une réponse d'identifiant `ident` arrivée pour
    /// `destination` (voir plus haut).
    pub fn trouver(&self, ident: u16, destination: [u8; 4]) -> Option<T> {
        self.entrees.iter().rev()
            .find(|e| e.ident == ident && (e.adresse == [0; 4] || e.adresse == destination))
            .map(|e| e.objet.clone())
    }

    /// Chaque socket de la table.
    pub fn pour_chaque(&self, mut f: impl FnMut(&T)) {
        for e in &self.entrees {
            f(&e.objet);
        }
    }
}
