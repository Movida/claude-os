//! Les adresses des interfaces et la table de routage d'IPv4 (la FIB de
//! Linux, net/ipv4/fib_*.c, en bien plus petit).
//!
//! Linux a deux tables. La table LOCALE dit ce qui est à nous : chaque
//! adresse d'une interface (un paquet pour elle est livré ici), et les
//! adresses de diffusion de ses réseaux. La table PRINCIPALE dit par où
//! envoyer le reste : une route par réseau directement branché (ajoutée
//! avec l'adresse de l'interface, `fib_add_ifaddr` : « 10.0.2.0/24 dev
//! eth0 »), et celles qu'on ajoute (la route par défaut, « 0.0.0.0/0 via
//! 10.0.2.2 »). On cherche d'abord dans la locale, puis la route de la
//! principale au plus long préfixe qui contient la destination. Linux range
//! ses tables dans un arbre (le `fib_trie`) pour des centaines de milliers
//! de routes ; une poignée tient dans un tableau parcouru en entier.
//!
//! L'interface de boucle (lo, 127.0.0.1/8) est à part : tout son réseau est
//! à nous (127.0.0.2 aussi), sauf sa diffusion (127.255.255.255, une
//! diffusion de lo comme pour tout réseau, « broadcast 127.255.255.255 dev
//! lo » dans la table locale de Linux), et sa route va dans la table
//! locale (`fib_add_ifaddr` lui donne le type RTN_LOCAL) ; /proc/net/route ne la
//! montre donc pas : il ne montre que la principale, dans l'ordre des
//! réseaux (celui de l'arbre de Linux) : `principales`.
//!
//! Un envoi peut demander son interface de sortie (IP_PKTINFO, IP_UNICAST_IF,
//! et SO_BINDTODEVICE : l'`oif` du `flowi4` de Linux) : seules comptent alors
//! les entrées des deux tables qui passent par elle, et sans rien trouver, la
//! destination est réputée « sur le lien » de l'interface (`chercher`).
//! Chaque recherche a aussi sa portée (le `flowi4_scope`) : « univers » pour
//! tout envoi, « lien » avec SO_DONTROUTE, MSG_DONTROUTE ou une route source
//! stricte (`ip_sendmsg_scope`, `ip_sock_rt_scope`). Une route a la sienne
//! (`fib_scope`) : « univers » par une passerelle, « lien » sans elle (le
//! réseau d'une interface), « hôte » pour une de nos adresses ; une route de
//! portée plus large que la recherche ne compte pas (`fib_table_lookup` :
//! `fib_scope < flowi4_scope`). Avec SO_DONTROUTE, la route par défaut est
//! donc ignorée : une machine d'ailleurs n'a pas de route, sauf par une
//! interface demandée, sur le lien de laquelle on la croit alors (mesuré).
//! Chaque entrée locale garde son interface : celle qu'on voit à l'arrivée
//! d'un paquet qu'elle livre par lo (le `rt_iif` de Linux, que lit IP_PKTINFO).
//!
//! Un groupe de multidiffusion n'est dans aucune table : il part par
//! l'interface demandée (IP_MULTICAST_IF, IP_PKTINFO, SO_BINDTODEVICE),
//! sinon par celle de la route qui le contient (la route par défaut), sans
//! jamais aller à sa passerelle : toutes les machines du lien qui l'écoutent
//! le prennent (`Chemin::Multidiffusion`).

use alloc::vec::Vec;
use formats::reseau::ipv4;
use faillible::VecFaillible;

/// Une adresse d'interface : l'interface, l'adresse, la longueur du préfixe
/// de son réseau (le `in_ifaddr` de Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adresse {
    pub interface: u32,
    pub adresse: [u8; 4],
    pub prefixe: u8,
    /// L'adresse de l'interface de boucle : tout son réseau est local.
    pub boucle: bool,
}

/// La portée d'une adresse (le `ifa_scope` de Linux, RT_SCOPE_*), de la plus
/// large à la plus étroite : joignable de partout (`RT_SCOPE_UNIVERSE`, 0),
/// du lien seulement (`RT_SCOPE_LINK`, 253), de cette machine seulement
/// (`RT_SCOPE_HOST`, 254). L'ordre des variantes est celui des nombres de
/// Linux : « au plus de portée p » se dit `portee <= p`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Portee {
    Univers,
    Lien,
    Hote,
}

/// 127.0.0.1 (INADDR_LOOPBACK) : « cette machine » faute de mieux.
const BOUCLE: [u8; 4] = [127, 0, 0, 1];

impl Adresse {
    /// Sa portée : « hôte » pour une adresse de 127.0.0.0/8 (celle de lo :
    /// `inet_set_ifa`), « univers » pour les autres (celles que donne le
    /// DHCP).
    pub fn portee(&self) -> Portee {
        if self.boucle { Portee::Hote } else { Portee::Univers }
    }

    /// L'adresse de diffusion de son réseau (10.0.2.255 pour 10.0.2.15/24).
    pub fn diffusion(&self) -> [u8; 4] {
        let m = u32::from_be_bytes(ipv4::masque(self.prefixe));
        (u32::from_be_bytes(self.adresse) | !m).to_be_bytes()
    }

    /// L'adresse de son réseau (10.0.2.0).
    pub fn reseau(&self) -> [u8; 4] {
        (u32::from_be_bytes(self.adresse) & u32::from_be_bytes(ipv4::masque(self.prefixe))).to_be_bytes()
    }
}

/// Une route de la table principale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub reseau: [u8; 4],
    pub prefixe: u8,
    /// La passerelle (RTF_GATEWAY), ou rien : la destination est sur le
    /// réseau de l'interface, on lui envoie directement.
    pub passerelle: Option<[u8; 4]>,
    pub interface: u32,
    /// L'adresse source qu'elle propose (le `prefsrc` de Linux).
    pub source: [u8; 4],
}

impl Route {
    /// Sa portée (le `fib_scope` que lui donne Linux : RT_SCOPE_UNIVERSE par
    /// une passerelle, RT_SCOPE_LINK pour un réseau directement branché).
    pub fn portee(&self) -> Portee {
        if self.passerelle.is_some() { Portee::Univers } else { Portee::Lien }
    }
}

/// Ce que donne la recherche d'une destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chemin {
    /// Une de nos adresses : livré ici (par l'interface de boucle), comme
    /// arrivé par `interface`, celle de l'entrée locale trouvée (la carte pour
    /// son adresse, lo pour son réseau : le `FIB_RES_OIF` dont Linux fait le
    /// `rt_iif` de la route) ; 0 : lo.
    Locale { source: [u8; 4], interface: u32 },
    /// La diffusion d'un de nos réseaux, ou la diffusion limitée
    /// (255.255.255.255) : à toutes les machines du réseau de `interface`.
    Diffusion { interface: u32, source: [u8; 4] },
    /// Par `interface`, à la machine `prochain` (la destination elle-même,
    /// ou la passerelle), depuis `source`.
    Unicast { interface: u32, prochain: [u8; 4], source: [u8; 4] },
    /// Un groupe de multidiffusion (RTN_MULTICAST) : par `interface`, à
    /// toutes les machines du lien qui l'écoutent, depuis `source`.
    /// `locale` : l'interface a le groupe, et son filtre laisse entrer la
    /// source (RTCF_LOCAL, `ip_check_mc_rcu`) : par une carte, une copie en
    /// revient aux sockets de la machine ; par lo, il n'est livré ici
    /// qu'alors. Les groupes des interfaces vivent dans le noyau, que la
    /// table ne voit pas : elle le laisse faux, le noyau le pose une fois la
    /// source connue.
    Multidiffusion { interface: u32, source: [u8; 4], locale: bool },
}

impl Chemin {
    /// L'adresse source qu'il propose (le `prefsrc` de sa route).
    pub fn source(&self) -> [u8; 4] {
        match *self {
            Chemin::Locale { source, .. }
            | Chemin::Diffusion { source, .. }
            | Chemin::Unicast { source, .. }
            | Chemin::Multidiffusion { source, .. } => source,
        }
    }
}

/// Pourquoi une route n'est pas ajoutée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// La table est pleine.
    Plein,
    /// Elle y est déjà (EEXIST chez Linux).
    Existe,
}

/// Le plus d'adresses, et de routes, que tient une table.
pub const MAX: usize = 64;

/// Les adresses et la table principale, de taille fixe.
pub struct Table {
    adresses: Vec<Adresse>,
    routes: Vec<Route>,
    max: usize,
}

impl Table {
    /// Une table vide, qui tiendra `max` adresses et `max` routes (64 au
    /// plus) : la place est réservée tout de suite (le noyau la fait au
    /// démarrage, et elle ne grandit plus). None : plus de mémoire.
    pub fn new(max: usize) -> Option<Table> {
        let max = max.min(MAX);
        let mut adresses = Vec::new();
        let mut routes = Vec::new();
        adresses.try_reserve_exact(max).ok()?;
        routes.try_reserve_exact(max).ok()?;
        Some(Table { adresses, routes, max })
    }

    /// Donne l'adresse `a` à son interface, et ajoute la route de son
    /// réseau (sauf pour un préfixe /32, qui n'a pas de réseau, et pour
    /// l'interface de boucle, dont le réseau est dans la table locale), comme
    /// `fib_add_ifaddr`.
    pub fn ajouter_adresse(&mut self, a: Adresse) -> Result<(), Refus> {
        if self.adresses.contains(&a) {
            return Err(Refus::Existe);
        }
        if self.adresses.len() >= self.max {
            return Err(Refus::Plein);
        }
        if a.prefixe < 32 && !a.boucle {
            let r = Route { reseau: a.reseau(), prefixe: a.prefixe, passerelle: None, interface: a.interface, source: a.adresse };
            if !self.routes.contains(&r) {
                self.ajouter_route(r)?;
            }
        }
        self.adresses.ajouter_dans_la_place(a);
        Ok(())
    }

    /// Ajoute une route à la table principale.
    pub fn ajouter_route(&mut self, r: Route) -> Result<(), Refus> {
        if self.routes.iter().any(|x| x.reseau == r.reseau && x.prefixe == r.prefixe && x.interface == r.interface) {
            return Err(Refus::Existe);
        }
        if self.routes.len() >= self.max {
            return Err(Refus::Plein);
        }
        self.routes.ajouter_dans_la_place(r);
        Ok(())
    }

    /// Les adresses de l'interface `interface`.
    pub fn adresses_de(&self, interface: u32) -> impl Iterator<Item = &Adresse> {
        self.adresses.iter().filter(move |a| a.interface == interface)
    }

    /// `a` est-elle une de nos adresses (ou du réseau de l'interface de
    /// boucle, sa diffusion exceptée) ?
    pub fn est_a_nous(&self, a: [u8; 4]) -> bool {
        self.adresses.iter().any(|x| x.adresse == a || (x.boucle && ipv4::dans(a, x.adresse, x.prefixe) && x.diffusion() != a))
    }

    /// L'interface qui porte notre adresse `a` (pas le reste du réseau de
    /// lo).
    pub fn interface_de(&self, a: [u8; 4]) -> Option<u32> {
        self.adresses.iter().find(|x| x.adresse == a).map(|x| x.interface)
    }

    /// L'interface d'une adresse à nous (`__ip_dev_find`) : celle qui la
    /// porte, ou lo pour une autre adresse de son réseau (Linux se rabat sur
    /// la table locale : « local 127.0.0.0/8 dev lo »).
    pub fn interface_locale(&self, a: [u8; 4]) -> Option<u32> {
        self.interface_de(a).or_else(|| {
            self.adresses.iter().find(|x| x.boucle && ipv4::dans(a, x.adresse, x.prefixe) && x.diffusion() != a).map(|x| x.interface)
        })
    }

    /// L'adresse que propose l'interface `interface` pour parler à `vers`, de
    /// portée `portee` au plus (`inet_select_addr`) : parmi ses adresses de
    /// cette portée, la première dont le réseau contient `vers` (0.0.0.0 :
    /// n'importe laquelle), sinon la première ; sinon, sur les interfaces
    /// dans l'ordre de leur numéro (lo d'abord), la première adresse de cette
    /// portée qui ne soit pas « du lien » (`in_dev_select_addr`). Ainsi lo,
    /// dont l'adresse est de portée « hôte », propose pour son lien celle de
    /// la carte (mesuré : un envoi forcé par lo vers 192.0.2.1 part de
    /// l'adresse de la carte).
    pub fn adresse_proposee(&self, interface: u32, vers: [u8; 4], portee: Portee) -> Option<[u8; 4]> {
        let mut premiere = None;
        for x in self.adresses_de(interface).filter(|x| x.portee() <= portee) {
            if vers == ipv4::AUCUNE || ipv4::dans(vers, x.adresse, x.prefixe) {
                return Some(x.adresse);
            }
            premiere = premiere.or(Some(x.adresse));
        }
        // `min_by_key` rend la première de plus petit numéro.
        premiere.or_else(|| {
            self.adresses.iter().filter(|x| x.portee() != Portee::Lien && x.portee() <= portee).min_by_key(|x| x.interface).map(|x| x.adresse)
        })
    }

    /// L'adresse par laquelle l'émetteur `source` d'un paquet arrivé par
    /// `interface` nous joint, quand ce paquet n'était pas pour une seule de
    /// nos adresses (une diffusion, ou pas pour nous) : celle que propose la
    /// route vers lui, sinon celle que propose l'interface, de portée « lien »
    /// pour une source de 0.0.0.0/8 (`fib_compute_spec_dst` : l'adresse
    /// locale d'IP_PKTINFO, celle que notent les options reçues). Pour un
    /// paquet livré à une seule de nos adresses, c'est sa destination.
    pub fn adresse_pour_repondre(&self, source: [u8; 4], interface: u32) -> [u8; 4] {
        let portee = if source[0] != 0 {
            if let Some(c) = self.chercher(source, 0, Portee::Univers) {
                return c.source();
            }
            Portee::Univers
        } else {
            Portee::Lien
        };
        self.adresse_proposee(interface, source, portee).unwrap_or(ipv4::AUCUNE)
    }

    /// `a` est-elle une adresse de diffusion pour l'interface `interface` :
    /// la diffusion limitée, ou celle d'un de ses réseaux ?
    pub fn est_diffusion(&self, interface: u32, a: [u8; 4]) -> bool {
        a == ipv4::DIFFUSION || self.adresses_de(interface).any(|x| x.prefixe < 31 && x.diffusion() == a)
    }

    /// `a` est-elle l'adresse de quelqu'un d'autre (`inet_addr_type` de
    /// Linux, RTN_UNICAST) : ni à nous (le réseau de lo compris), ni une
    /// diffusion (d'un de nos réseaux, la limitée, ou 0.0.0.0/8, que Linux
    /// compte aussi comme diffusion), ni une multidiffusion ?
    pub fn est_unicast(&self, a: [u8; 4]) -> bool {
        !(a[0] == 0
            || a == ipv4::DIFFUSION
            || ipv4::multidiffusion(a)
            || self.est_a_nous(a)
            || self.adresses.iter().any(|x| x.prefixe < 31 && x.diffusion() == a))
    }

    /// La route de la table principale au plus long préfixe qui contient
    /// `destination`, parmi celles de l'interface `oif` (0 : toutes) de portée
    /// `portee` au moins.
    fn meilleure(&self, destination: [u8; 4], oif: u32, portee: Portee) -> Option<&Route> {
        self.routes.iter()
            .filter(|r| (oif == 0 || r.interface == oif) && r.portee() >= portee && ipv4::dans(destination, r.reseau, r.prefixe))
            .max_by_key(|r| r.prefixe)
    }

    /// Le chemin d'un paquet vers `destination`, par l'interface `oif` si un
    /// envoi la demande (0 : celle de la route), parmi les routes de portée
    /// `portee` au moins (les entrées de la table locale sont de portée
    /// « hôte » pour nos adresses et le réseau de lo, « lien » pour les
    /// diffusions), comme `ip_route_output_key_hash_rcu` une fois la source
    /// vérifiée :
    ///   - avec une interface, la diffusion limitée part par elle, sans
    ///     table, de l'adresse qu'elle propose pour son lien ;
    ///   - la table locale d'abord (nos adresses, le réseau de lo, la
    ///     diffusion de nos réseaux), puis la principale ; avec une
    ///     interface, seules comptent ses entrées (`fib_lookup_good_nhc` :
    ///     notre adresse de la carte n'est pas à lo, ni 127.0.0.0/8 à la
    ///     carte : par la carte, 127.0.0.1 va à la passerelle, mesuré) ;
    ///   - rien de trouvé avec une interface : la destination est « sur le
    ///     lien », envoyée directement par elle, de l'adresse qu'elle propose
    ///     (Linux : « we are allowed to send to iface even if it has NO
    ///     routes and NO assigned addresses ») : par lo, tout est livré ici.
    ///
    /// Sans interface, la diffusion limitée part par celle de la route par
    /// défaut (la principale, comme toute destination). Un groupe de
    /// multidiffusion a ses règles (`multidiffusion`).
    pub fn chercher(&self, destination: [u8; 4], oif: u32, portee: Portee) -> Option<Chemin> {
        if ipv4::multidiffusion(destination) {
            return self.multidiffusion(destination, oif, portee);
        }
        let par = |k: u32| oif == 0 || oif == k;
        let proposee = || self.adresse_proposee(oif, ipv4::AUCUNE, Portee::Lien).unwrap_or(ipv4::AUCUNE);
        if oif != 0 && destination == ipv4::DIFFUSION {
            return Some(Chemin::Diffusion { interface: oif, source: proposee() });
        }
        // Une de nos adresses : elle-même pour source ; une autre adresse du
        // réseau de lo (127.1.2.3) : celle de lo, la `prefsrc` de sa route
        // locale (« local 127.0.0.0/8 dev lo src 127.0.0.1 »).
        if let Some(x) = self.adresses.iter().find(|x| x.adresse == destination && par(x.interface)) {
            return Some(Chemin::Locale { source: destination, interface: x.interface });
        }
        if let Some(x) = self.adresses.iter()
            .find(|x| x.boucle && ipv4::dans(destination, x.adresse, x.prefixe) && x.diffusion() != destination && par(x.interface))
        {
            return Some(Chemin::Locale { source: x.adresse, interface: x.interface });
        }
        if let Some(a) = self.adresses.iter()
            .find(|a| a.prefixe < 31 && a.diffusion() == destination && par(a.interface) && portee <= Portee::Lien)
        {
            return Some(Chemin::Diffusion { interface: a.interface, source: a.adresse });
        }
        match self.meilleure(destination, oif, portee) {
            Some(r) if destination == ipv4::DIFFUSION => Some(Chemin::Diffusion { interface: r.interface, source: r.source }),
            Some(r) => Some(Chemin::Unicast { interface: r.interface, prochain: r.passerelle.unwrap_or(destination), source: r.source }),
            None if oif != 0 => Some(Chemin::Unicast { interface: oif, prochain: destination, source: proposee() }),
            None => None,
        }
    }

    /// Le chemin vers le groupe `groupe` (`ip_route_output_key_hash_rcu`,
    /// puis `__mkroute_output` pour RTN_MULTICAST), qu'aucune entrée de la
    /// table locale ne contient :
    ///   - avec une interface : par elle, toujours, de l'adresse qu'elle
    ///     propose, de portée « lien » pour un groupe du lien (224.0.0.0/24,
    ///     sans regarder la table), de la portée de la recherche sinon (par
    ///     lo, dont l'adresse est de portée « hôte » : celle de la carte,
    ///     mesuré). Linux cherche ensuite une route par elle, qui ne
    ///     pourrait donner que sa source (le `prefsrc`, une de nos adresses
    ///     de portée « univers », qu'elle aurait déjà proposée), et sans
    ///     rien trouver le croit sur son lien : rien ne change ;
    ///   - sans interface : par celle de la route au plus long préfixe qui
    ///     le contient (la route par défaut), de sa source, mais jamais vers
    ///     sa passerelle (« If multicast route do not exist use default one,
    ///     but do not gateway in this case. Yes, it is hack. » : `fi = NULL`
    ///     pour un préfixe de moins de 4 bits ; une route de 4 bits ou plus
    ///     vers des groupes garderait la sienne, mais seul le DHCP ajoute
    ///     des routes ici : celle du réseau et la route par défaut). Aucune
    ///     (avant le DHCP, ou la route par défaut ignorée par la portée du
    ///     lien) : pas de chemin.
    fn multidiffusion(&self, groupe: [u8; 4], oif: u32, portee: Portee) -> Option<Chemin> {
        if oif == 0 {
            return self.meilleure(groupe, 0, portee)
                .map(|r| Chemin::Multidiffusion { interface: r.interface, source: r.source, locale: false });
        }
        let portee = if ipv4::multidiffusion_du_lien(groupe) { Portee::Lien } else { portee };
        let source = self.adresse_proposee(oif, ipv4::AUCUNE, portee).unwrap_or(ipv4::AUCUNE);
        Some(Chemin::Multidiffusion { interface: oif, source, locale: false })
    }

    /// La route d'un envoi vers `destination`, de la source `source` s'il en
    /// demande une, par l'interface `oif` s'il en demande une (0 : aucune), de
    /// portée `portee` :
    /// `chercher`, sauf vers 0.0.0.0, « cette machine », que Linux livre par
    /// lo sans table (`ip_route_output_key_hash_rcu`) : la destination devient
    /// la source demandée, sinon, avec une interface, l'adresse qu'elle
    /// propose de portée « hôte », sinon 127.0.0.1 ; l'arrivée a lieu par
    /// l'interface demandée (le `rt_iif` est l'`oif` d'origine), lo sans
    /// elle. Rend aussi la destination de l'en-tête. None : pas de route.
    pub fn router(&self, destination: [u8; 4], source: Option<[u8; 4]>, oif: u32, portee: Portee) -> Option<(Chemin, [u8; 4])> {
        if destination != ipv4::AUCUNE {
            return self.chercher(destination, oif, portee).map(|c| (c, destination));
        }
        let s = source.filter(|&s| s != ipv4::AUCUNE)
            .or_else(|| if oif != 0 { self.adresse_proposee(oif, ipv4::AUCUNE, Portee::Hote) } else { None })
            .unwrap_or(BOUCLE);
        let lo = self.adresses.iter().find(|x| x.boucle).map_or(0, |x| x.interface);
        Some((Chemin::Locale { source: s, interface: if oif != 0 { oif } else { lo } }, s))
    }

    /// Les routes de la table principale, dans l'ordre où les montre
    /// /proc/net/route : par réseau croissant (la clé de l'arbre de
    /// Linux), le plus long préfixe d'abord pour un même réseau.
    pub fn principales(&self) -> impl Iterator<Item = Route> + '_ {
        let mut ordre: [usize; MAX] = core::array::from_fn(|i| i);
        let n = self.routes.len();
        // Sans tampon (`sort_unstable`), et l'indice en dernier pour garder
        // l'ordre d'ajout de deux routes de même clé, comme un tri stable.
        ordre[..n].sort_unstable_by_key(|&i| (u32::from_be_bytes(self.routes[i].reseau), u8::MAX - self.routes[i].prefixe, i));
        (0..n).map(move |k| self.routes[ordre[k]])
    }
}
