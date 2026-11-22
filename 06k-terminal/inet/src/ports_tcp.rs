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
//!     SO_REUSEADDR ne peuvent pas écouter toutes les deux. Deux sockets
//!     liées à deux interfaces différentes (SO_BINDTODEVICE) ne se gênent
//!     jamais (deux écoutes du même port, l'une sur lo, l'autre sur eth0 :
//!     mesuré) ; une socket non liée gêne toutes les autres ;
//!   - le port éphémère de `bind(0)` et de `listen` sans `bind`
//!     (`inet_csk_find_open_port`) : un départ au hasard, IMPAIR d'abord,
//!     de deux en deux, puis les pairs ; sans la tolérance de SO_REUSEADDR ;
//!     une socket qui a SO_REUSEADDR cherche d'abord dans la moitié basse de
//!     la plage, puis dans la haute (Linux garde la haute aux autres) ;
//!   - le port éphémère de `connect` (`__inet_hash_connect`) : PAIR d'abord
//!     (Linux laisse les impairs à `bind`, mesuré) ; avec une plage à elle
//!     (IP_LOCAL_PORT_RANGE), de un en un, sans parité (le programme a
//!     choisi peu de ports : tous servent) ; à partir d'un décalage
//!     secret (`secure_ipv4_port_ephemeral`, tiré par le noyau) plus une
//!     perturbation qui avance à chaque choix (`table_perturb` : un tiers ne
//!     peut pas deviner le port suivant d'après le précédent) ; un port déjà
//!     pris par `bind` est sauté ; un port pris par d'autres `connect` sert
//!     encore, si le quadruplet est neuf. Un TIME_WAIT du même quadruplet
//!     est repris s'il a des horodatages (`tcp_twsk_unique` : les règles sont
//!     celles de la connexion, inet::tcp::attente). Une connexion existante
//!     liée à une autre interface que celle de qui se connecte ne compte pas
//!     (`inet_match` : la sienne, 0 ou l'autre) ;
//!   - un segment reçu (`__inet_lookup`) : d'abord la connexion de son
//!     quadruplet exact (une socket connectée ou un TIME_WAIT), puis
//!     l'écoute de son adresse de destination, puis celle de 0.0.0.0 ; une
//!     socket liée à une interface ne voit que ce qui arrive par elle, et
//!     une écoute liée l'emporte sur une qui ne l'est pas (`compute_score` :
//!     3 contre 2, et un point de plus pour celle qui dit, par
//!     SO_INCOMING_CPU, le processeur qui cherche : une écoute non liée de ce
//!     processeur égale une liée qui ne l'est pas ; la plus récente à
//!     égalité) ; la première qui passe en tête et a un groupe SO_REUSEPORT
//!     rend aussitôt la membre que choisit le groupe. L'interface d'arrivée
//!     est celle de la route du paquet (`inet_iif`, voir `ports`).
//!
//! LES GROUPES SO_REUSEPORT (groupes.rs) : une socket qui a SO_REUSEPORT
//! entre à son `listen` (`inet_reuseport_add_sock`) dans le groupe de la plus
//! récente écoute du même port, de la même adresse, de la même interface,
//! qui a SO_REUSEPORT et le même utilisateur (ou dans un groupe neuf, ou
//! dans celui qu'elle s'est fait avant, par un programme), et en sort quand
//! elle cesse d'écouter (`inet_unhash`, `reuseport_stop_listen_sock`) : une
//! fille n'est jamais dans un groupe (`sk_clone_lock`). Une socket qui a
//! déjà un groupe ne partage pas un port par SO_REUSEPORT (le
//! `reuseport_cb_ok` d'`inet_bind_conflict` : EADDRINUSE au `bind`, ou au
//! `listen`, mesuré). L'ordre de la table est celui de la liste des écoutes
//! de Linux (la plus récente en tête) : `listen` met l'entrée à la fin, et la
//! recherche parcourt la table à l'envers.
//!
//! Une taille fixe, réservée au démarrage (comme la table d'UDP), et des
//! recherches en parcourant la table : quelques dizaines de sockets.
//! Linux hache : « Reste à faire » si une mesure le demande.

use crate::groupes::{Choix, Groupes, Refus as RefusDeGroupe};
use crate::ports::{memes_interfaces, voit};
use alloc::vec::Vec;
use faillible::VecFaillible;

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
    /// IP_LOCAL_PORT_RANGE de la socket (`ports::plage`), pour son port
    /// éphémère.
    pub plage: u32,
    /// L'interface à laquelle la socket est liée (SO_BINDTODEVICE, son
    /// index ; 0 : aucune). La fille d'une écoute a la sienne
    /// (`sk_clone_lock`), un TIME_WAIT celle de sa connexion
    /// (`tw_bound_dev_if`).
    pub interface: u32,
}

/// Pourquoi un port n'est pas donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Pris (EADDRINUSE), ou plus aucun éphémère libre (EADDRNOTAVAIL pour
    /// `connect`, EADDRINUSE pour `bind`).
    Pris,
    /// La table est pleine (ENOBUFS : un écart).
    Plein,
    /// Plus de mémoire pour un groupe SO_REUSEPORT (ENOMEM).
    Memoire,
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

/// La table. `P` : le programme des groupes SO_REUSEPORT (filtre.rs, dans le
/// noyau).
pub struct Table<T, P = ()> {
    entrees: Vec<Entree<T>>,
    max: usize,
    perturbation: [u32; PERTURBATION],
    groupes: Groupes<P>,
    /// Le processeur que dit une socket (SO_INCOMING_CPU, -1 : aucun), lu à son entrée dans
    /// un groupe et à sa sortie (le compte du groupe, groupes.rs).
    processeur: fn(&T) -> i32,
}

/// Deux adresses locales se recouvrent-elles ?
fn recouvre(a: [u8; 4], b: [u8; 4]) -> bool {
    a == [0; 4] || b == [0; 4] || a == b
}

/// L'entrée `a` (qui veut le port ; `a_groupe` : elle a un groupe
/// SO_REUSEPORT) est-elle gênée par `b` (`inet_bind_conflict`) ?
/// `tolerant` : le partage par SO_REUSEADDR est permis (un port demandé ; pas
/// dans la recherche d'un éphémère).
fn conflit(a: &Lien, b: &Lien, tolerant: bool, a_groupe: bool) -> bool {
    if !recouvre(a.adresse, b.adresse) || !memes_interfaces(a.interface, b.interface) {
        return false;
    }
    if a.reuseaddr && b.reuseaddr && b.sorte != Sorte::Ecoute {
        return !tolerant;
    }
    // SO_REUSEPORT : seulement pour un port demandé (`reuseport_ok`), et pas
    // pour une socket qui a déjà un groupe (`reuseport_cb_ok`).
    let reuseport = a.reuseport && b.reuseport && !a_groupe && (b.sorte == Sorte::TempsAttente || a.uid == b.uid);
    !(tolerant && reuseport)
}

impl<T: Clone, P> Table<T, P> {
    /// Une table pour `max` entrées, sa place réservée ; `hasard` remplit la
    /// table de perturbation. None : plus de mémoire.
    pub fn new(max: usize, mut hasard: impl FnMut() -> u32) -> Option<Table<T, P>> {
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(max).ok()?;
        Some(Table { entrees, max, perturbation: core::array::from_fn(|_| hasard()), groupes: Groupes::new(), processeur: |_| -1 })
    }

    /// Le processeur de ses sockets (`Choix::processeur`) ; sans, aucune n'en dit.
    pub fn avec_processeur(self, processeur: fn(&T) -> i32) -> Table<T, P> {
        Table { processeur, ..self }
    }

    /// La socket `numero` dit-elle un processeur ?
    fn dit(&self, numero: u64) -> bool {
        self.entrees.iter().find(|e| e.numero == numero).and_then(|e| e.objet.as_ref()).is_some_and(|o| (self.processeur)(o) >= 0)
    }

    /// Son SO_INCOMING_CPU passe de `ancien` à `nouveau` (groupes.rs).
    pub fn processeur_change(&mut self, numero: u64, ancien: i32, nouveau: i32) {
        self.groupes.processeur_change(numero, ancien >= 0, nouveau >= 0);
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
        let a_groupe = self.groupes.a_un_groupe(numero);
        !self.entrees.iter().any(|e| e.numero != numero && e.lien.port == port && conflit(lien, &e.lien, tolerant, a_groupe))
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
        self.entrees.ajouter_dans_la_place(Entree { numero, lien: Lien { port, ..lien }, objet: Some(objet) });
        Ok(port)
    }

    /// `inet_csk_find_open_port` : dans la plage de la socket (sa moitié
    /// basse d'abord, puis la haute, si elle a SO_REUSEADDR : une plage de
    /// moins de quatre ports ne se coupe pas), les impairs d'un départ tiré
    /// (`get_random_u32_below`, ici les 16 bits bas de `hasard` pour la
    /// première moitié, les hauts pour la seconde : une plage a au plus
    /// 65 536 ports), de deux en deux, puis les pairs à partir du port
    /// d'avant. Le nombre de ports essayés est pair (le dernier d'une plage
    /// impaire n'est jamais pris : mesuré sous Linux, comme sa source).
    fn ephemere_de_bind(&self, numero: u64, lien: &Lien, hasard: u32) -> Option<u16> {
        let moities = if lien.reuseaddr { [1, 2] } else { [0, 0] };
        for (k, &moitie) in moities.iter().enumerate() {
            if k == 1 && moitie == 0 {
                break;
            }
            let (mut bas, haut, _) = crate::ports::plage(lien.plage);
            let mut haut = haut + 1;
            let moitie = if haut - bas < 4 { 0 } else { moitie };
            if moitie != 0 {
                let milieu = bas + (((haut - bas) >> 2) << 1);
                if moitie == 1 {
                    haut = milieu;
                } else {
                    bas = milieu;
                }
            }
            let mut restant = haut - bas;
            if restant > 1 {
                restant &= !1;
            }
            let tire = if k == 0 { hasard & 0xFFFF } else { hasard >> 16 };
            let mut decalage = ((tire * restant) >> 16) | 1;
            for passe in 0..2 {
                // Les pairs partent du port d'avant le premier impair : un seul
                // pas en arrière, entre les deux passes (Linux décrémente aussi
                // après la seconde, un `u32` qui peut faire le tour sans
                // conséquence : la valeur ne sert plus).
                if passe == 1 {
                    decalage -= 1;
                }
                let mut port = bas + decalage;
                let mut i = 0;
                while i < restant {
                    if port >= haut {
                        port -= restant;
                    }
                    if self.libre(numero, port as u16, lien, false) {
                        return Some(port as u16);
                    }
                    i += 2;
                    port += 2;
                }
            }
            if moitie != 1 {
                break;
            }
        }
        None
    }

    /// La socket `numero`, liée, écoute (`listen`, `inet_csk_listen_start`) :
    /// refusé si une autre socket du port l'en empêche maintenant qu'elle
    /// écoute (EADDRINUSE) ; puis, avec SO_REUSEPORT, elle entre dans un
    /// groupe (`inet_hash`, voir plus haut ; sans mémoire, ENOMEM) ; puis elle
    /// passe en tête de la liste des écoutes (ici, à la fin de la table).
    pub fn ecouter(&mut self, numero: u64) -> Result<(), Refus> {
        let Some(i) = self.entrees.iter().position(|e| e.numero == numero) else { return Err(Refus::Pris) };
        let lien = Lien { sorte: Sorte::Ecoute, ..self.entrees[i].lien };
        // Le conflit vu de la socket qui écoute, comme `inet_csk_get_port`
        // rappelé par `inet_csk_listen_start` : une autre qui écoute déjà
        // la gêne malgré SO_REUSEADDR.
        let a_groupe = self.groupes.a_un_groupe(numero);
        let gene = self.entrees.iter()
            .any(|e| e.numero != numero && e.lien.port == lien.port && conflit(&lien, &e.lien, true, a_groupe));
        if gene {
            return Err(Refus::Pris);
        }
        if lien.reuseport {
            let autre = self.entrees.iter().rev()
                .find(|e| {
                    let l = &e.lien;
                    e.numero != numero && l.sorte == Sorte::Ecoute && l.port == lien.port && l.adresse == lien.adresse
                        && l.interface == lien.interface && l.reuseport && l.uid == lien.uid
                })
                .map(|e| e.numero);
            let entree = match autre {
                Some(autre) => self.groupes.ajouter(numero, self.dit(numero), autre, self.dit(autre)),
                None => self.groupes.allouer(numero, self.dit(numero)),
            };
            entree.map_err(|_| Refus::Memoire)?;
        }
        let mut e = self.entrees.remove(i);
        e.lien.sorte = Sorte::Ecoute;
        self.entrees.ajouter_dans_la_place(e);
        Ok(())
    }

    /// Le quadruplet (`locale`, `port`, `distante`, `port_distant`) est-il
    /// pris (`__inet_check_established`) pour une socket liée à `interface` ?
    /// Par une connexion, oui ; par une entrée de TIME_WAIT, sauf si
    /// `reprendre` la reprend (son numéro, et si le port vient de `bind`) :
    /// l'entrée disparaît alors de la table. Une entrée liée à une autre
    /// interface ne compte pas (`inet_match`, avec pour interface celle de la
    /// socket qui se connecte : une entrée non liée compte toujours, une
    /// socket non liée ne voit pas celles qui le sont).
    #[allow(clippy::too_many_arguments)]
    fn quadruplet_pris(&mut self, locale: [u8; 4], port: u16, distante: [u8; 4], port_distant: u16, interface: u32,
                       port_lie: bool, reprendre: &mut impl FnMut(u64, bool) -> bool) -> bool {
        let Some(i) = self.entrees.iter().position(|e| {
            matches!(e.lien.sorte, Sorte::Connectee | Sorte::TempsAttente)
                && e.lien.port == port
                && e.lien.adresse == locale
                && e.lien.distante == distante
                && e.lien.port_distant == port_distant
                && voit(e.lien.interface, interface)
        }) else {
            return false;
        };
        let e = &self.entrees[i];
        if e.lien.sorte == Sorte::TempsAttente && reprendre(e.numero, port_lie) {
            self.entrees.remove(i);
            return false;
        }
        true
    }

    /// Connecte la socket `numero` (`connect`) depuis `locale` vers
    /// `distante`:`port_distant`. Liée d'avance (par `bind`) : son port,
    /// si le quadruplet est libre. Sinon : un port éphémère, pair d'abord,
    /// à partir du décalage secret `decalage` (64 bits : l'index de la
    /// perturbation dans les bits bas, le reste dans les hauts), et le
    /// `hasard` qui fait avancer la perturbation. `reprendre` dit si une
    /// entrée de TIME_WAIT du quadruplet peut être reprise. Rend le port local.
    #[allow(clippy::too_many_arguments)]
    pub fn connecter(&mut self, numero: u64, locale: [u8; 4], distante: [u8; 4], port_distant: u16, lien: Lien, objet: T,
                     decalage: u64, hasard: u32, mut reprendre: impl FnMut(u64, bool) -> bool) -> Result<u16, Refus> {
        if let Some(e) = self.entrees.iter().find(|e| e.numero == numero) {
            let (port, interface) = (e.lien.port, e.lien.interface);
            if self.quadruplet_pris(locale, port, distante, port_distant, interface, true, &mut reprendre) {
                return Err(Refus::Pris);
            }
            let e = self.entree(numero).expect("l'entree");
            e.lien = Lien { sorte: Sorte::Connectee, adresse: locale, distante, port_distant, ..e.lien };
            return Ok(port);
        }
        if self.entrees.len() >= self.max {
            return Err(Refus::Plein);
        }
        let (bas, haut, propre) = crate::ports::plage(lien.plage);
        let pas = if propre { 1 } else { 2 };
        let haut = haut + 1;
        let mut restant = haut - bas;
        if !propre && restant > 1 {
            restant &= !1;
        }
        let index = decalage as usize % PERTURBATION;
        let mut depart = self.perturbation[index].wrapping_add((decalage >> 32) as u32) % restant;
        if !propre {
            depart &= !1;
        }
        loop {
            let mut port = bas + depart;
            let mut i = 0;
            while i < restant {
                if port >= haut {
                    port -= restant;
                }
                let essai = port as u16;
                let (essai_i, suivant) = (i, port + pas);
                i += pas;
                port = suivant;
                // Un port pris par `bind` (ou une écoute) est sauté ; un
                // port de `connect` se partage, si le quadruplet est neuf.
                let du_port = |e: &&Entree<T>| e.lien.port == essai;
                if self.entrees.iter().filter(du_port).any(|e| !e.lien.par_connect) {
                    continue;
                }
                if self.quadruplet_pris(locale, essai, distante, port_distant, lien.interface, false, &mut reprendre) {
                    continue;
                }
                // La perturbation avance de l'indice du port trouvé, ou d'un
                // peu plus au hasard (moins de huit pas), plus un pas : le
                // prochain départ ne se devine pas.
                let saut = essai_i.max((hasard % 8) * pas) + pas;
                self.perturbation[index] = self.perturbation[index].wrapping_add(saut);
                self.entrees.ajouter_dans_la_place(Entree {
                    numero,
                    lien: Lien { sorte: Sorte::Connectee, adresse: locale, port: essai, distante, port_distant, par_connect: true, ..lien },
                    objet: Some(objet),
                });
                return Ok(essai);
            }
            // Les impairs, une seule fois (sans plage à elle).
            if propre || depart & 1 == 1 || restant <= 1 {
                break;
            }
            depart += 1;
        }
        Err(Refus::Pris)
    }

    /// Ajoute la fille `numero` d'une écoute : une connexion de quadruplet
    /// donné, sur le port de l'écoute.
    pub fn ajouter_fille(&mut self, numero: u64, lien: Lien, objet: T) -> Result<(), Refus> {
        if self.entrees.len() >= self.max {
            return Err(Refus::Plein);
        }
        self.entrees.ajouter_dans_la_place(Entree { numero, lien: Lien { sorte: Sorte::Connectee, ..lien }, objet: Some(objet) });
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

    /// Change la liaison à une interface de l'entrée `numero`
    /// (SO_BINDTODEVICE) : Linux la lit sur la socket à chaque conflit et à
    /// chaque recherche, une écoute ou une connexion comprises.
    pub fn changer_interface(&mut self, numero: u64, interface: u32) {
        if let Some(e) = self.entree(numero) {
            e.lien.interface = interface;
        }
    }

    /// Change SO_REUSEADDR et SO_REUSEPORT de l'entrée `numero`.
    pub fn reutiliser(&mut self, numero: u64, reuseaddr: bool, reuseport: bool) {
        if let Some(e) = self.entree(numero) {
            e.lien.reuseaddr = reuseaddr;
            e.lien.reuseport = reuseport;
        }
    }

    /// Une connexion finie dont le port vient de `bind` : elle quitte son quadruplet, garde son
    /// port (SOCK_BINDPORT_LOCK), sans repasser par les conflits : elle ne l'a jamais rendu.
    /// `adresse` : celle qu'elle garde (`tcp_disconnect` efface celle que `bind` n'a pas nommée).
    pub fn redevenir_liee(&mut self, numero: u64, adresse: [u8; 4]) {
        self.quitter_l_ecoute(numero);
        if let Some(e) = self.entree(numero) {
            e.lien.sorte = Sorte::Liee;
            e.lien.adresse = adresse;
            e.lien.distante = [0; 4];
            e.lien.port_distant = 0;
        }
    }

    /// Une écoute qui cesse d'écouter quitte son groupe (`inet_unhash`,
    /// `reuseport_stop_listen_sock`) ; les autres entrées gardent le leur
    /// (une connexion qui avait un programme avant `connect` : mesuré).
    fn quitter_l_ecoute(&mut self, numero: u64) {
        if self.lien(numero).is_some_and(|l| l.sorte == Sorte::Ecoute) {
            let dit = self.dit(numero);
            self.groupes.detacher(numero, dit);
        }
    }

    /// Retire l'entrée `numero` (son port est rendu).
    pub fn retirer(&mut self, numero: u64) {
        self.quitter_l_ecoute(numero);
        self.entrees.retain(|e| e.numero != numero);
    }

    /// La socket `numero` est détruite (son dernier close, `sk_destruct`) :
    /// elle quitte son groupe, même sans entrée (un programme posé avant
    /// `bind`). Son entrée, si sa connexion continue sans elle, reste.
    pub fn detruire(&mut self, numero: u64) {
        let dit = self.dit(numero);
        self.groupes.detacher(numero, dit);
    }

    /// SO_ATTACH_REUSEPORT_CBPF (groupes.rs, `attacher_programme`) : une
    /// socket TCP est « dans la table » quand elle écoute ou se connecte (une
    /// socket liée seulement ne l'est pas, `sk_unhashed`) ; `reuseport` : son
    /// SO_REUSEPORT. Rend l'ancien programme.
    /// `processeur` : celui que dit la socket (SO_INCOMING_CPU), compté dans un groupe fait pour
    /// elle.
    pub fn attacher_programme(&mut self, numero: u64, programme: P, reuseport: bool, processeur: i32)
                              -> Result<Option<P>, RefusDeGroupe> {
        let hachee = self.lien(numero).is_some_and(|l| matches!(l.sorte, Sorte::Ecoute | Sorte::Connectee));
        self.groupes.attacher_programme(numero, programme, hachee, reuseport, processeur >= 0)
    }

    /// SO_DETACH_REUSEPORT_BPF (groupes.rs, `detacher_programme`).
    pub fn detacher_programme(&mut self, numero: u64, reuseport: bool) -> Result<P, RefusDeGroupe> {
        self.groupes.detacher_programme(numero, reuseport)
    }

    /// À qui va un segment de `source`:`port_source` pour
    /// `destination`:`port`, arrivé par l'interface `iif` ; `c` : voir
    /// `ecoute`.
    pub fn trouver(&self, source: [u8; 4], port_source: u16, destination: [u8; 4], port: u16, iif: u32, c: &Choix<T, P>)
                   -> Option<Destinataire<T>> {
        for e in &self.entrees {
            let l = &e.lien;
            if matches!(l.sorte, Sorte::Connectee | Sorte::TempsAttente)
                && l.port == port
                && l.adresse == destination
                && l.distante == source
                && l.port_distant == port_source
                && voit(l.interface, iif)
            {
                return match (&e.objet, l.sorte) {
                    (Some(o), _) => Some(Destinataire::Connexion(o.clone())),
                    (None, _) => Some(Destinataire::TempsAttente(e.numero)),
                };
            }
        }
        self.ecoute(destination, port, iif, c).map(Destinataire::Ecoute)
    }

    /// L'écoute de `destination`:`port`, ou de 0.0.0.0:`port`
    /// (`__inet_lookup_listener`, `inet_lhash2_lookup`), pour un segment
    /// arrivé par `iif` : dans chaque passe, de la plus récente à la plus
    /// ancienne, la mieux notée (`compute_score` : liée à `iif`, 2 ; non
    /// liée, 1 ; liée à une autre, jamais ; un point d'IPv4 ; un point de plus
    /// si elle dit, par SO_INCOMING_CPU, le processeur qui cherche) ; la
    /// première qui passe en tête et a un groupe rend la membre qu'il choisit
    /// (`inet_lookup_reuseport`, groupes.rs ; `c` : de quoi choisir).
    pub fn ecoute(&self, destination: [u8; 4], port: u16, iif: u32, c: &Choix<T, P>) -> Option<T> {
        let objet = |m: u64| self.entrees.iter().find(|e| e.numero == m).and_then(|e| e.objet.clone());
        for locale in [destination, [0; 4]] {
            let (mut resultat, mut meilleure): (Option<&Entree<T>>, u32) = (None, 0);
            for e in self.entrees.iter().rev() {
                let l = &e.lien;
                if l.sorte != Sorte::Ecoute || l.port != port || l.adresse != locale || !voit(l.interface, iif) {
                    continue;
                }
                let note = if l.interface != 0 { 2 } else { 1 } + 1 + e.objet.as_ref().is_some_and(|o| c.ici(o)) as u32;
                if note <= meilleure {
                    continue;
                }
                if l.reuseport {
                    // Un groupe n'a que des écoutes : toutes valides.
                    let processeur = |m: u64| objet(m).map_or(-1, |o| (c.processeur)(&o));
                    if let Some(o) = self.groupes.choisir(e.numero, c, |_| true, processeur).and_then(objet) {
                        return Some(o);
                    }
                }
                resultat = Some(e);
                meilleure = note;
            }
            if let Some(e) = resultat {
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
