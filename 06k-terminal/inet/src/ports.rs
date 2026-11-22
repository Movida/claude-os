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
//!     SO_REUSEADDR, ou SO_REUSEPORT et le même utilisateur, ou si elles
//!     sont liées à deux interfaces différentes (SO_BINDTODEVICE : une
//!     socket non liée gêne toutes les autres). Le port 0
//!     demande un port ÉPHÉMÈRE, au hasard dans la plage (32768 à 60999,
//!     `ip_local_port_range`, ou celle d'IP_LOCAL_PORT_RANGE, `plage`),
//!     comme Linux : un premier port tiré, puis des
//!     pas d'un multiple impair et tiré de la taille de la table, dans la
//!     même classe (modulo la taille), puis la classe suivante : tous les
//!     ports sont essayés, dans un ordre qu'un autre ne peut pas deviner
//!     (un port prévisible aide à usurper une réponse DNS) ;
//!   - CHOISIR LA SOCKET d'un datagramme (`__udp4_lib_lookup`) : d'abord
//!     une socket connectée à son émetteur, exactement (`udp4_lib_lookup4`,
//!     la table de leurs quadruplets), la plus récemment entrée dans cette
//!     table : chacune y entre à son premier `connect` (`udp_lib_hash4`, en
//!     tête de sa liste), y reste au même rang, pour le même quadruplet,
//!     quand elle se reconnecte ou se déconnecte (une connectée ailleurs
//!     depuis n'y est plus trouvée : mesuré, sondes r4a et r4b de la relecture
//!     du lot 6 des soldes), et n'en sort qu'avec son adresse locale
//!     (`udp_unhash4` : déconnectée d'une adresse que `bind` n'a pas
//!     choisie) ou son port ; puis celles liées à l'adresse de
//!     destination, puis celles liées à 0.0.0.0 ; parmi elles, la mieux
//!     notée (`compute_score` : connectée à l'émetteur, +4 pour l'adresse,
//!     +4 pour le port ; une socket connectée ailleurs n'est pas candidate ;
//!     liée à l'interface d'arrivée, +4, à une autre, pas candidate ; +1 si
//!     elle dit, par SO_INCOMING_CPU, le processeur qui cherche), la plus
//!     récente à égalité ; mais la première socket non connectée qui a un
//!     groupe SO_REUSEPORT (groupes.rs) et passe en tête rend aussitôt la
//!     membre que choisit le groupe, sans voir les suivantes, même mieux
//!     notées (mesuré, sonde c10f du lot 6 des soldes : une socket liée à
//!     `lo`, plus ancienne qu'un groupe, ne reçoit rien) ; sauf si une
//!     membre du groupe s'est connectée un jour (`has_conns`) : la membre
//!     choisie prend alors la note du groupe, et la recherche continue ;
//!   - une DIFFUSION va à chaque socket du port qui l'accepte
//!     (`__udp4_lib_mcast_deliver`), liée à aucune interface ou à celle
//!     d'arrivée, sans groupe.
//!
//! LES GROUPES SO_REUSEPORT (groupes.rs) : une socket qui a SO_REUSEPORT
//! entre à son `bind` (`udp_reuseport_add_sock`) dans le groupe de la plus
//! récemment liée qui a le même port, la même adresse, la même interface,
//! SO_REUSEPORT et le même utilisateur (ou dans un groupe neuf), et en sort
//! quand elle quitte la table (`udp_lib_unhash`), quand elle est ré-hachée
//! (`udp_lib_rehash` : son adresse locale change, par `connect` d'une socket
//! liée à 0.0.0.0, ou la fin d'une connexion qui oublie l'adresse, même
//! jamais connectée ; ou SO_BINDTODEVICE), et quand
//! elle se connecte (`udp_lib_hash4`, depuis Linux 6.13 : une socket
//! connectée n'est plus jamais dans un groupe). Une socket qui a déjà un
//! groupe à elle (un programme posé avant `bind`) ne partage pas un port par
//! SO_REUSEPORT (EADDRINUSE : mesuré).
//!
//! L'ORDRE de la table est celui de la liste de Linux qu'on parcourt pour
//! chercher (le `hslot2` d'une adresse et d'un port : la plus récente en
//! tête) : une socket va à la fin quand elle est liée, et quand son adresse
//! locale change (`udp_lib_rehash` la remet en tête de la liste de sa
//! nouvelle adresse) ; la recherche parcourt la table à l'envers. L'entrée
//! dans un groupe parcourt une autre liste, celle des ports (`hslot`), que
//! `connect` ne réordonne pas : chaque entrée garde son rang de liaison.
//!
//! L'interface d'arrivée est celle de la route du paquet (`inet_iif`),
//! pas toujours la carte qui l'a reçu : un paquet envoyé à notre propre
//! adresse passe par lo, et arrive « par eth0 », l'interface de cette
//! adresse.
//!
//! Une taille fixe, réservée d'avance (1024 sockets liées à la fois : un
//! écart, Linux n'a d'autre limite que la mémoire) : lier une socket ne
//! prend pas de mémoire, et « mémoire rendue » ne bouge pas. Chaque entrée
//! porte un numéro (celui de la socket, pour la retrouver) et un objet `T`
//! (la socket du noyau).

use crate::groupes::{Choix, Groupes, Refus as RefusDeGroupe};
use alloc::vec::Vec;
use faillible::VecFaillible;

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

/// La plage des ports éphémères d'une socket (`inet_sk_get_local_port_range`),
/// d'après son IP_LOCAL_PORT_RANGE `reglage` (le bas dans les 16 bits bas,
/// le haut dans les hauts ; 0 : aucun) : chaque borne n'est prise que si elle
/// tombe dans celle du système, le bas d'abord, le haut ensuite comparé au
/// bas déjà pris (une borne hors plage est ignorée, sans erreur : mesuré,
/// 1000-2000 donne toute la plage, 0-32770 donne 32768-32770). Rend le bas,
/// le haut, et si la socket a sa plage à elle (TCP en change sa façon de
/// chercher : `__inet_hash_connect`). Partagée avec la table de TCP.
pub fn plage(reglage: u32) -> (u32, u32, bool) {
    let (mut bas, mut haut) = (EPHEMERE_MIN as u32, EPHEMERE_MAX as u32);
    if reglage == 0 {
        return (bas, haut, false);
    }
    let (b, h) = (reglage & 0xFFFF, reglage >> 16);
    if (bas..=haut).contains(&b) {
        bas = b;
    }
    if (bas..=haut).contains(&h) {
        haut = h;
    }
    (bas, haut, true)
}

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
    /// IP_LOCAL_PORT_RANGE de la socket (`plage`), pour son port éphémère.
    pub plage: u32,
    /// L'interface à laquelle la socket est liée (SO_BINDTODEVICE, son
    /// index ; 0 : aucune).
    pub interface: u32,
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
    /// Le rang de sa liaison (l'ordre de la liste des ports de Linux, `hslot`).
    liee: u64,
    /// Son entrée dans la table des quadruplets des connectées (`hslot4`) : son rang, et
    /// l'adresse et le port distants de son premier `connect` (`udp_lrpa_hash`, que les
    /// suivants ne changent pas) ; None : pas entrée.
    quadruplet: Option<(u64, [u8; 4], u16)>,
}

/// La table. `P` : le programme des groupes SO_REUSEPORT (filtre.rs, dans le
/// noyau).
pub struct Table<T, P = ()> {
    entrees: Vec<Entree<T>>,
    groupes: Groupes<P>,
    /// Le rang de la prochaine liaison.
    liaisons: u64,
    /// Le rang de la prochaine entrée dans la table des quadruplets.
    quadruplets: u64,
    /// Le processeur que dit une socket (SO_INCOMING_CPU, -1 : aucun), lu à son entrée dans
    /// un groupe et à sa sortie (le compte du groupe, groupes.rs).
    processeur: fn(&T) -> i32,
}

/// Le lien `a` (d'une socket qui a un groupe, `a_groupe`, ou non) est-il
/// gêné par `b` sur le même port (`udp_lib_lport_inuse`) ? Le partage par
/// SO_REUSEPORT n'est pas permis à une socket qui a déjà un groupe (son
/// `sk_reuseport_cb`).
fn conflit(a: &Lien, b: &Lien, a_groupe: bool) -> bool {
    let reutilise = (a.reuseaddr && b.reuseaddr) || (a.reuseport && b.reuseport && !a_groupe && a.uid == b.uid);
    let recouvre = a.adresse == [0; 4] || b.adresse == [0; 4] || a.adresse == b.adresse;
    !reutilise && recouvre && memes_interfaces(a.interface, b.interface)
}

/// Deux liaisons à une interface peuvent-elles voir les mêmes paquets ?
/// Oui, sauf si chacune est liée à la sienne (les tables de TCP font de même,
/// `inet_bind_conflict`).
pub fn memes_interfaces(a: u32, b: u32) -> bool {
    a == 0 || b == 0 || a == b
}

/// Une socket liée à l'interface `liee` (0 : aucune) voit-elle un paquet
/// arrivé par `iif` (`inet_bound_dev_eq`, sans VRF) ? Partagée avec TCP.
pub fn voit(liee: u32, iif: u32) -> bool {
    liee == 0 || liee == iif
}

impl<T: Clone, P> Table<T, P> {
    /// Une table vide, sa place réservée. None : plus de mémoire.
    pub fn new() -> Option<Table<T, P>> {
        let mut entrees = Vec::new();
        entrees.try_reserve_exact(MAX).ok()?;
        Some(Table { entrees, groupes: Groupes::new(), liaisons: 0, quadruplets: 0, processeur: |_| -1 })
    }

    /// Le processeur de ses sockets (`Choix::processeur`) ; sans, aucune n'en dit.
    pub fn avec_processeur(self, processeur: fn(&T) -> i32) -> Table<T, P> {
        Table { processeur, ..self }
    }

    /// La socket `numero` dit-elle un processeur ?
    fn dit(&self, numero: u64) -> bool {
        self.entrees.iter().find(|e| e.numero == numero).is_some_and(|e| (self.processeur)(&e.objet) >= 0)
    }

    /// Son SO_INCOMING_CPU passe de `ancien` à `nouveau` (groupes.rs).
    pub fn processeur_change(&mut self, numero: u64, ancien: i32, nouveau: i32) {
        self.groupes.processeur_change(numero, ancien >= 0, nouveau >= 0);
    }

    /// Le port `port` est-il libre pour `lien` (sauf la socket `numero`
    /// elle-même) ?
    fn libre(&self, numero: u64, port: u16, lien: &Lien) -> bool {
        let a_groupe = self.groupes.a_un_groupe(numero);
        !self.entrees.iter().any(|e| e.numero != numero && e.lien.port == port && conflit(lien, &e.lien, a_groupe))
    }

    /// Lie la socket `numero` (objet `objet`) selon `lien` ; son port 0
    /// demande un port éphémère, tiré d'après `hasard` (il peut être celui
    /// d'un groupe qu'elle peut rejoindre : Linux ne compte pas pris un port
    /// qu'il permet de partager). Rend le port. Avec SO_REUSEPORT, elle entre
    /// dans un groupe (voir plus haut) ; sans la mémoire du groupe, Linux
    /// refuse le port (EADDRINUSE : `udp_lib_get_port` n'a qu'un échec).
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
        if lien.reuseport {
            // La plus récemment liée du même port, de la même adresse et de la
            // même interface, exactement.
            let autre = self.entrees.iter()
                .filter(|e| {
                    let l = &e.lien;
                    l.port == port && l.adresse == lien.adresse && l.interface == lien.interface && l.reuseport && l.uid == lien.uid
                })
                .max_by_key(|e| e.liee)
                .map(|e| e.numero);
            let entree = match autre {
                Some(autre) => self.groupes.ajouter(numero, (self.processeur)(&objet) >= 0, autre, self.dit(autre)),
                None => self.groupes.allouer(numero, (self.processeur)(&objet) >= 0),
            };
            entree.map_err(|_| Refus::Pris)?;
        }
        self.liaisons += 1;
        self.entrees.ajouter_dans_la_place(Entree { numero, lien: Lien { port, ..lien }, objet, liee: self.liaisons, quadruplet: None });
        Ok(port)
    }

    /// Le choix d'un port éphémère de `udp_lib_get_port` (voir plus haut).
    fn ephemere(&self, numero: u64, lien: &Lien, hasard: u32) -> Option<u16> {
        let (bas, haut, _) = plage(lien.plage);
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

    /// `udp_lib_rehash` : l'adresse locale de la socket `numero` devient
    /// `adresse` ; si elle change, l'entrée passe en tête de sa nouvelle liste
    /// (ici, à la fin de la table), et de même dans la table des quadruplets
    /// si elle y est (`udp_rehash4`, avec sa destination d'alors), qu'elle
    /// quitte pour 0.0.0.0 (`udp_unhash4`). Dans tous les cas, la socket
    /// quitte son groupe.
    pub fn rehacher(&mut self, numero: u64, adresse: [u8; 4]) {
        let Some(i) = self.entrees.iter().position(|e| e.numero == numero) else { return };
        if self.entrees[i].lien.adresse != adresse {
            let mut e = self.entrees.remove(i);
            e.lien.adresse = adresse;
            if adresse == [0; 4] {
                e.quadruplet = None;
            } else if e.quadruplet.is_some() {
                self.quadruplets += 1;
                e.quadruplet = Some((self.quadruplets, e.lien.distante, e.lien.port_distant));
            }
            self.entrees.ajouter_dans_la_place(e);
        }
        let dit = self.dit(numero);
        self.groupes.detacher(numero, dit);
    }

    /// La socket `numero`, d'adresse locale `adresse`, se connecte à
    /// `distante`:`port_distant` (`__ip4_datagram_connect`, puis
    /// `udp4_hash4`) : une adresse locale qui change d'abord (celle de la
    /// route, pour une socket liée à 0.0.0.0 : `rehacher`, qui fait quitter le
    /// groupe), puis son groupe, si elle en a encore un, apprend qu'une membre
    /// s'est connectée, puis elle le quitte. Elle entre dans la table des
    /// quadruplets si elle n'y est pas déjà (`udp4_hash4`, `udp_lib_hash4` :
    /// pas liée à 0.0.0.0).
    pub fn connecter(&mut self, numero: u64, distante: [u8; 4], port_distant: u16, adresse: [u8; 4]) {
        let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) else { return };
        e.lien.distante = distante;
        e.lien.port_distant = port_distant;
        // (Une adresse qui change est celle d'une socket liée à 0.0.0.0, qui n'est pas
        // dans la table des quadruplets : son ré-hachage ne l'y touche pas.)
        if e.lien.adresse != adresse {
            self.rehacher(numero, adresse);
        }
        let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) else { return };
        if e.quadruplet.is_none() && adresse != [0; 4] {
            self.quadruplets += 1;
            e.quadruplet = Some((self.quadruplets, distante, port_distant));
        }
        self.groupes.connectee(numero);
        let dit = self.dit(numero);
        self.groupes.detacher(numero, dit);
    }

    /// La fin de la connexion de la socket `numero`, son port gardé
    /// (`__udp_disconnect`) : plus de destination, plus d'interface (sans
    /// ré-hacher pour elle : son groupe SO_REUSEPORT est gardé, `rehash` ne
    /// vient qu'après, pour l'adresse) ; son
    /// adresse locale oubliée, si `bind` ne l'avait pas choisie
    /// (`oublier_adresse`, et `rehacher`).
    pub fn deconnecter(&mut self, numero: u64, oublier_adresse: bool) {
        let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) else { return };
        e.lien.distante = [0; 4];
        e.lien.port_distant = 0;
        e.lien.interface = 0;
        if oublier_adresse {
            self.rehacher(numero, [0; 4]);
        }
    }

    /// Change la liaison à une interface de la socket `numero`
    /// (SO_BINDTODEVICE) : comme SO_REUSEADDR, Linux la lit à chaque conflit
    /// et à chaque recherche, pas à son `bind`. Elle ré-hache la socket
    /// (`sock_bindtoindex_locked`, `udp_v4_rehash`) : son adresse ne change
    /// pas, mais elle quitte son groupe (mesuré ; TCP n'a pas de `rehash` :
    /// une écoute garde le sien).
    pub fn changer_interface(&mut self, numero: u64, interface: u32) {
        let dit = self.dit(numero);
        if let Some(e) = self.entrees.iter_mut().find(|e| e.numero == numero) {
            e.lien.interface = interface;
            self.groupes.detacher(numero, dit);
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

    /// Retire la socket `numero` (son port est rendu), et, si elle était
    /// dans la table, de son groupe (`udp_lib_unhash`).
    pub fn retirer(&mut self, numero: u64) {
        let dit = self.dit(numero);
        let n = self.entrees.len();
        self.entrees.retain(|e| e.numero != numero);
        if self.entrees.len() != n {
            self.groupes.detacher(numero, dit);
        }
    }

    /// La socket `numero` est détruite : son port, et son groupe, même sans
    /// port (`sk_destruct` : un programme posé avant `bind`).
    pub fn oublier(&mut self, numero: u64) {
        self.retirer(numero);
        // Un groupe sans port n'a qu'elle : il disparaît, son compte avec lui.
        self.groupes.detacher(numero, false);
    }

    /// SO_ATTACH_REUSEPORT_CBPF (groupes.rs, `attacher_programme`) : la socket
    /// est « dans la table » quand elle a un port ; `reuseport` : son
    /// SO_REUSEPORT. Rend l'ancien programme.
    /// `processeur` : celui que dit la socket (SO_INCOMING_CPU), compté dans un groupe fait pour
    /// elle.
    pub fn attacher_programme(&mut self, numero: u64, programme: P, reuseport: bool, processeur: i32)
                              -> Result<Option<P>, RefusDeGroupe> {
        let hachee = self.entrees.iter().any(|e| e.numero == numero);
        self.groupes.attacher_programme(numero, programme, hachee, reuseport, processeur >= 0)
    }

    /// SO_DETACH_REUSEPORT_BPF (groupes.rs, `detacher_programme`).
    pub fn detacher_programme(&mut self, numero: u64, reuseport: bool) -> Result<P, RefusDeGroupe> {
        self.groupes.detacher_programme(numero, reuseport)
    }

    /// Le lien de la socket `numero`.
    pub fn lien(&self, numero: u64) -> Option<Lien> {
        self.entrees.iter().find(|e| e.numero == numero).map(|e| e.lien)
    }

    /// La socket qui reçoit un datagramme de `source`:`port_source` pour
    /// `destination`:`port`, arrivé par l'interface `iif`
    /// (`__udp4_lib_lookup`, voir plus haut) ; `c` : de quoi choisir dans un
    /// groupe, et le processeur qui cherche.
    pub fn trouver(&self, source: [u8; 4], port_source: u16, destination: [u8; 4], port: u16, iif: u32, c: &Choix<T, P>)
                   -> Option<T> {
        // `compute_score`.
        let note = |e: &Entree<T>, locale: [u8; 4]| -> Option<u32> {
            let l = &e.lien;
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
            if !voit(l.interface, iif) {
                return None;
            }
            if l.interface != 0 {
                n += 4;
            }
            Some(n + c.ici(&e.objet) as u32)
        };
        // `udp4_lib_lookup4` : une connectée à l'émetteur, exactement, dans la liste de son
        // quadruplet (celui de son premier `connect`), la plus récemment entrée.
        let exacte = self
            .entrees
            .iter()
            .filter(|e| {
                let l = &e.lien;
                e.quadruplet.is_some_and(|(_, d, p)| (d, p) == (source, port_source))
                    && (l.adresse, l.port, l.distante, l.port_distant) == (destination, port, source, port_source)
                    && voit(l.interface, iif)
            })
            .max_by_key(|e| e.quadruplet.map_or(0, |(rang, ..)| rang));
        if let Some(e) = exacte {
            return Some(e.objet.clone());
        }
        // `udp4_lib_lookup2`, pour l'adresse de destination, puis pour 0.0.0.0.
        let entree = |m: u64| self.entrees.iter().find(|e| e.numero == m);
        for locale in [destination, [0; 4]] {
            let (mut resultat, mut meilleure): (Option<&Entree<T>>, u32) = (None, 0);
            for e in self.entrees.iter().rev() {
                let Some(n) = note(e, locale) else { continue };
                if n <= meilleure {
                    continue;
                }
                meilleure = n;
                if e.lien.distante != [0; 4] || !e.lien.reuseport {
                    resultat = Some(e);
                    continue;
                }
                let valide = |m: u64| entree(m).is_some_and(|x| x.lien.distante == [0; 4]);
                let processeur = |m: u64| entree(m).map_or(-1, |x| (c.processeur)(&x.objet));
                match self.groupes.choisir(e.numero, c, valide, processeur).and_then(entree) {
                    None => resultat = Some(e),
                    Some(choisie) if !self.groupes.connexions(e.numero) => return Some(choisie.objet.clone()),
                    // La choisie prend sa propre note, si elle est meilleure.
                    Some(choisie) => {
                        resultat = Some(choisie);
                        meilleure = meilleure.max(note(choisie, locale).unwrap_or(0));
                    }
                }
            }
            if let Some(e) = resultat {
                return Some(e.objet.clone());
            }
        }
        None
    }

    /// Chaque socket qui reçoit une diffusion pour `destination`:`port` de
    /// `source`:`port_source`, arrivée par `iif` (`__udp_is_mcast_sock`).
    pub fn pour_chaque_diffusion(&self, source: [u8; 4], port_source: u16, destination: [u8; 4], port: u16, iif: u32,
                                 mut f: impl FnMut(&T)) {
        for e in &self.entrees {
            let l = &e.lien;
            if l.port == port
                && (l.adresse == [0; 4] || l.adresse == destination)
                && (l.distante == [0; 4] || l.distante == source)
                && (l.port_distant == 0 || l.port_distant == port_source)
                && voit(l.interface, iif)
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
