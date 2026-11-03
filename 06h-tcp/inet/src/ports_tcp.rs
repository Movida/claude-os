//! La table des ports de TCP (les tables `bhash`, `ehash` et d'écoute de
//! Linux, net/ipv4/inet_hashtables.c et inet_connection_sock.c) : quels
//! ports une socket peut prendre, et à qui va un segment reçu.
//!
//! Chaque entrée est une socket TCP liée à un port local : liée seulement
//! (`bind`), qui ÉCOUTE (`listen`), CONNECTÉE (le quadruplet complet : une
//! socket de `connect`, ou la fille d'une écoute, qui partage son port), ou
//! en TIME_WAIT (la petite structure qui reste d'une connexion fermée,
//! plan de 6h, section 4 ; son numéro est à la table, pas à une socket).
//!
//! LES RÈGLES DE LINUX :
//!   - `bind` d'un port (`inet_csk_get_port`, `inet_bind_conflict`) : refusé
//!     (EADDRINUSE) si une autre entrée du même port a une adresse qui
//!     recouvre la nôtre (égale, ou l'une des deux 0.0.0.0), sauf si les
//!     deux ont SO_REUSEADDR et que l'autre n'écoute pas, ou si les deux ont
//!     SO_REUSEPORT et le même utilisateur (ou l'autre est en TIME_WAIT) ;
//!     un TIME_WAIT garde le SO_REUSEADDR de sa socket. `listen` revérifie,
//!     avec l'écoute pour nouvel état : deux sockets liées au même port par
//!     SO_REUSEADDR ne peuvent pas écouter toutes les deux ;
//!   - le port éphémère de `bind(0)` et de `listen` sans `bind`
//!     (`inet_csk_find_open_port`) : un départ au hasard, IMPAIR d'abord,
//!     de deux en deux, puis les pairs ; sans la tolérance de SO_REUSEADDR ;
//!   - le port éphémère de `connect` (`__inet_hash_connect`) : PAIR d'abord
//!     (Linux laisse les impairs à `bind`, mesuré), à partir d'un décalage
//!     secret (`secure_ipv4_port_ephemeral`, tiré par le noyau) plus une
//!     perturbation qui avance à chaque choix (`table_perturb` : un tiers ne
//!     peut pas deviner le port suivant d'après le précédent) ; un port déjà
//!     pris par `bind` est sauté ; un port pris par d'autres `connect` sert
//!     encore, si le quadruplet est neuf. Un TIME_WAIT du même quadruplet
//!     n'est jamais repris : Linux ne le fait qu'avec les horodatages
//!     (`tcp_twsk_unique`), que nous n'avons pas ;
//!   - un segment reçu (`__inet_lookup`) : d'abord la connexion de son
//!     quadruplet exact (une socket connectée ou un TIME_WAIT), puis
//!     l'écoute de son adresse de destination, puis celle de 0.0.0.0.
//!
//! Une taille fixe, réservée au démarrage (comme la table d'UDP), et des
//! recherches en parcourant la table : quelques dizaines de sockets.
//! Linux hache : « Reste à faire » si une mesure le demande.

use alloc::vec::Vec;

/// La plage des ports éphémères (`ip_local_port_range`).
pub const EPHEMERE_MIN: u16 = 32768;
pub const EPHEMERE_MAX: u16 = 60999;
/// Le premier port non privilégié (`ip_unprivileged_port_start`).
pub const PRIVILEGIE: u16 = 1024;
/// La taille de la table de perturbation (INET_TABLE_PERTURB_SIZE, en
/// plus petit).
const PERTURBATION: usize = 256;

/// Ce qu'est une entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sorte {
    /// Liée, sans plus (`bind`, ou avant que `connect` n'ait fini).
    Liee,
    Ecoute,
    /// Une connexion (de `connect`, ou la fille d'une écoute).
    Connectee,
    TempsAttente,
}

/// Une entrée : la socket (son numéro), son adresse et son port locaux, le
/// pair d'une connexion, ses options de partage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lien {
    pub sorte: Sorte,
    pub adresse: [u8; 4],
    pub port: u16,
    pub distante: [u8; 4],
    pub port_distant: u16,
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub uid: u32,
    /// Le port a été donné par `connect` (le `fastreuse == -1` de Linux) :
    /// d'autres `connect` peuvent le partager.
    pub par_connect: bool,
}

/// Pourquoi un port n'est pas donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Pris (EADDRINUSE), ou plus aucun éphémère libre (EADDRNOTAVAIL pour
    /// `connect`, EADDRINUSE pour `bind`).
    Pris,
    /// La table est pleine (ENOBUFS : un écart).
    Plein,
}

/// À qui va un segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destinataire<T> {
    Connexion(T),
    TempsAttente(u64),
    Ecoute(T),
}

struct Entree<T> {
    numero: u64,
    lien: Lien,
    objet: Option<T>,
}

/// La table.
pub struct Table<T> {
    entrees: Vec<Entree<T>>,
    max: usize,
    perturbation: [u32; PERTURBATION],
}

/// Deux adresses locales se recouvrent-elles ?
fn recouvre(a: [u8; 4], b: [u8; 4]) -> bool {
    a == [0; 4] || b == [0; 4] || a == b
}

/// L'entrée `a` (qui veut le port) est-elle gênée par `b`
/// (`inet_bind_conflict`) ? `tolerant` : le partage par SO_REUSEADDR est
/// permis (un port demandé ; pas dans la recherche d'un éphémère).
fn conflit(a: &Lien, b: &Lien, tolerant: bool) -> bool {
    if !recouvre(a.adresse, b.adresse) {
        return false;
    }
    if a.reuseaddr && b.reuseaddr && b.sorte != Sorte::Ecoute {
        return !tolerant;
    }
    // SO_REUSEPORT : seulement pour un port demandé (`reuseport_ok`).
    let reuseport = a.reuseport && b.reuseport && (b.sorte == Sorte::TempsAttente || a.uid == b.uid);
    !(tolerant && reuseport)
}

impl<T: Clone> Table<T> {
    /// Une table pour `max` entrées, sa place réservée ; `hasard` remplit la
    /// table de perturbation. None : plus de mémoire.
    pub fn new(max: usize, mut hasard: impl FnMut() -> u32) -> Option<Table<T>> {
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(max).ok()?;
        Some(Table { entrees, max, perturbation: core::array::from_fn(|_| hasard()) })
    }

    fn entree(&mut self, numero: u64) -> Option<&mut Entree<T>> {
        self.entrees.iter_mut().find(|e| e.numero == numero)
    }

    /// L'objet de l'entrée `numero`.
    pub fn objet(&self, numero: u64) -> Option<T> {
        self.entrees.iter().find(|e| e.numero == numero).and_then(|e| e.objet.clone())
    }

    /// Le lien de l'entrée `numero`.
    pub fn lien(&self, numero: u64) -> Option<Lien> {
        self.entrees.iter().find(|e| e.numero == numero).map(|e| e.lien)
    }

    /// Le port `port` est-il libre pour `lien` (hors l'entrée `numero`) ?
    fn libre(&self, numero: u64, port: u16, lien: &Lien, tolerant: bool) -> bool {
        !self.entrees.iter().any(|e| e.numero != numero && e.lien.port == port && conflit(lien, &e.lien, tolerant))
    }

    /// Lie la socket `numero` selon `lien` (`bind`, ou `listen` sans
    /// `bind`) : son port 0 demande un éphémère, à partir de `hasard`.
    /// Rend le port.
    pub fn lier(&mut self, numero: u64, lien: Lien, objet: T, hasard: u32) -> Result<u16, Refus> {
        if self.entrees.len() >= self.max {
            return Err(Refus::Plein);
        }
        let port = if lien.port != 0 {
            if !self.libre(numero, lien.port, &lien, true) {
                return Err(Refus::Pris);
            }
            lien.port
        } else {
            self.ephemere_de_bind(numero, &lien, hasard).ok_or(Refus::Pris)?
        };
        self.entrees.push(Entree { numero, lien: Lien { port, ..lien }, objet: Some(objet) });
        Ok(port)
    }

    /// `inet_csk_find_open_port` : impairs, puis pairs, d'un départ tiré.
    fn ephemere_de_bind(&self, numero: u64, lien: &Lien, hasard: u32) -> Option<u16> {
        let (bas, haut) = (EPHEMERE_MIN as u32, EPHEMERE_MAX as u32);
        let restant = (haut - bas + 1) & !1;
        let depart = (hasard % restant) | 1;
        for parite in 0..2 {
            let mut i = 0;
            while i < restant {
                let port = bas + (depart + parite + i) % restant;
                if port <= haut && self.libre(numero, port as u16, lien, false) {
                    return Some(port as u16);
                }
                i += 2;
            }
        }
        None
    }

    /// La socket `numero`, liée, écoute (`listen`) : refusé si une autre
    /// socket du port l'en empêche maintenant qu'elle écoute.
    pub fn ecouter(&mut self, numero: u64) -> Result<(), Refus> {
        let Some(l) = self.lien(numero) else { return Err(Refus::Pris) };
        let lien = Lien { sorte: Sorte::Ecoute, ..l };
        // Le conflit vu de la socket qui écoute, comme `inet_csk_get_port`
        // rappelé par `inet_csk_listen_start` : une autre qui écoute déjà
        // la gêne malgré SO_REUSEADDR.
        let gene = self.entrees.iter().any(|e| e.numero != numero && e.lien.port == lien.port && conflit(&lien, &e.lien, true));
        if gene {
            return Err(Refus::Pris);
        }
        if let Some(e) = self.entree(numero) {
            e.lien.sorte = Sorte::Ecoute;
        }
        Ok(())
    }

    /// Le quadruplet (`locale`, `port`, `distante`, `port_distant`) est-il
    /// déjà pris (une connexion ou un TIME_WAIT) ?
    fn quadruplet_pris(&self, locale: [u8; 4], port: u16, distante: [u8; 4], port_distant: u16) -> bool {
        self.entrees.iter().any(|e| {
            matches!(e.lien.sorte, Sorte::Connectee | Sorte::TempsAttente)
                && e.lien.port == port
                && e.lien.adresse == locale
                && e.lien.distante == distante
                && e.lien.port_distant == port_distant
        })
    }

    /// Connecte la socket `numero` (`connect`) depuis `locale` vers
    /// `distante`:`port_distant`. Liée d'avance (par `bind`) : son port,
    /// si le quadruplet est libre. Sinon : un port éphémère, pair d'abord,
    /// à partir du décalage secret `decalage` (64 bits : l'index de la
    /// perturbation dans les bits bas, le reste dans les hauts), et le
    /// `hasard` qui fait avancer la perturbation. Rend le port local.
    pub fn connecter(&mut self, numero: u64, locale: [u8; 4], distante: [u8; 4], port_distant: u16, lien: Lien, objet: T,
                     decalage: u64, hasard: u32) -> Result<u16, Refus> {
        if let Some(e) = self.entrees.iter().find(|e| e.numero == numero) {
            let port = e.lien.port;
            if self.quadruplet_pris(locale, port, distante, port_distant) {
                return Err(Refus::Pris);
            }
            let e = self.entree(numero).expect("l'entree");
            e.lien = Lien { sorte: Sorte::Connectee, adresse: locale, distante, port_distant, ..e.lien };
            return Ok(port);
        }
        if self.entrees.len() >= self.max {
            return Err(Refus::Plein);
        }
        let (bas, haut) = (EPHEMERE_MIN as u32, EPHEMERE_MAX as u32);
        let restant = (haut - bas + 1) & !1;
        let index = decalage as usize % PERTURBATION;
        let mut depart = self.perturbation[index].wrapping_add((decalage >> 32) as u32) % restant;
        depart &= !1;
        for parite in 0..2u32 {
            let mut i = 0;
            while i < restant {
                let port = (bas + (depart + parite + i) % restant) as u16;
                i += 2;
                if port as u32 > haut {
                    continue;
                }
                // Un port pris par `bind` (ou une écoute) est sauté ; un
                // port de `connect` se partage, si le quadruplet est neuf.
                let du_port = |e: &&Entree<T>| e.lien.port == port;
                if self.entrees.iter().filter(du_port).any(|e| !e.lien.par_connect) {
                    continue;
                }
                if self.quadruplet_pris(locale, port, distante, port_distant) {
                    continue;
                }
                // La perturbation avance (d'au moins deux, d'un peu plus au
                // hasard) : le prochain départ ne se devine pas.
                let saut = i.max((hasard % 8) * 2) + 2;
                self.perturbation[index] = self.perturbation[index].wrapping_add(saut);
                self.entrees.push(Entree {
                    numero,
                    lien: Lien { sorte: Sorte::Connectee, adresse: locale, port, distante, port_distant, par_connect: true, ..lien },
                    objet: Some(objet),
                });
                return Ok(port);
            }
        }
        Err(Refus::Pris)
    }

    /// Ajoute la fille `numero` d'une écoute : une connexion de quadruplet
    /// donné, sur le port de l'écoute.
    pub fn ajouter_fille(&mut self, numero: u64, lien: Lien, objet: T) -> Result<(), Refus> {
        if self.entrees.len() >= self.max {
            return Err(Refus::Plein);
        }
        self.entrees.push(Entree { numero, lien: Lien { sorte: Sorte::Connectee, ..lien }, objet: Some(objet) });
        Ok(())
    }

    /// Change l'objet de l'entrée `numero` (la fille d'une écoute devient
    /// une socket à elle, à son `accept`).
    pub fn changer_objet(&mut self, numero: u64, objet: T) {
        if let Some(e) = self.entree(numero) {
            e.objet = Some(objet);
        }
    }

    /// L'entrée `numero` passe en TIME_WAIT, sous le numéro `nouveau` : le
    /// quadruplet reste pris, sans objet. Un numéro à elle : la socket peut
    /// survivre à sa connexion (le programme la tient encore) et en ouvrir
    /// une autre, qui reprendrait son numéro ; l'entrée de TIME_WAIT, à son
    /// échéance, retirerait alors la neuve.
    pub fn temps_attente(&mut self, numero: u64, nouveau: u64) {
        if let Some(e) = self.entree(numero) {
            e.numero = nouveau;
            e.lien.sorte = Sorte::TempsAttente;
            e.objet = None;
        }
    }

    /// Le nombre d'entrées en TIME_WAIT.
    pub fn nombre_temps_attente(&self) -> usize {
        self.entrees.iter().filter(|e| e.lien.sorte == Sorte::TempsAttente).count()
    }

    /// Change SO_REUSEADDR et SO_REUSEPORT de l'entrée `numero`.
    pub fn reutiliser(&mut self, numero: u64, reuseaddr: bool, reuseport: bool) {
        if let Some(e) = self.entree(numero) {
            e.lien.reuseaddr = reuseaddr;
            e.lien.reuseport = reuseport;
        }
    }

    /// Retire l'entrée `numero` (son port est rendu).
    pub fn retirer(&mut self, numero: u64) {
        self.entrees.retain(|e| e.numero != numero);
    }

    /// À qui va un segment de `source`:`port_source` pour
    /// `destination`:`port`.
    pub fn trouver(&self, source: [u8; 4], port_source: u16, destination: [u8; 4], port: u16) -> Option<Destinataire<T>> {
        for e in &self.entrees {
            let l = &e.lien;
            if matches!(l.sorte, Sorte::Connectee | Sorte::TempsAttente)
                && l.port == port
                && l.adresse == destination
                && l.distante == source
                && l.port_distant == port_source
            {
                return match (&e.objet, l.sorte) {
                    (Some(o), _) => Some(Destinataire::Connexion(o.clone())),
                    (None, _) => Some(Destinataire::TempsAttente(e.numero)),
                };
            }
        }
        self.ecoute(destination, port).map(Destinataire::Ecoute)
    }

    /// L'écoute de `destination`:`port`, ou de 0.0.0.0:`port`
    /// (`inet_lookup_listener`).
    pub fn ecoute(&self, destination: [u8; 4], port: u16) -> Option<T> {
        for locale in [destination, [0; 4]] {
            if let Some(e) = self.entrees.iter().find(|e| e.lien.sorte == Sorte::Ecoute && e.lien.port == port && e.lien.adresse == locale) {
                return e.objet.clone();
            }
        }
        None
    }

    /// Chaque entrée de la table (/proc/net/tcp).
    pub fn pour_chaque(&self, mut f: impl FnMut(u64, &Lien, Option<&T>)) {
        for e in &self.entrees {
            f(e.numero, &e.lien, e.objet.as_ref());
        }
    }
}
