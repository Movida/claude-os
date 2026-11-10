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

use alloc::vec::Vec;
use formats::reseau::ipv4;

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

impl Adresse {
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

/// Ce que donne la recherche d'une destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chemin {
    /// Une de nos adresses : livré ici (par l'interface de boucle).
    Locale { source: [u8; 4] },
    /// La diffusion d'un de nos réseaux, ou la diffusion limitée
    /// (255.255.255.255) : à toutes les machines du réseau de `interface`.
    Diffusion { interface: u32, source: [u8; 4] },
    /// Par `interface`, à la machine `prochain` (la destination elle-même,
    /// ou la passerelle), depuis `source`.
    Unicast { interface: u32, prochain: [u8; 4], source: [u8; 4] },
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
        self.adresses.push(a);
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
        self.routes.push(r);
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
    /// `destination`.
    fn meilleure(&self, destination: [u8; 4]) -> Option<&Route> {
        self.routes.iter().filter(|r| ipv4::dans(destination, r.reseau, r.prefixe)).max_by_key(|r| r.prefixe)
    }

    /// Le chemin d'un paquet vers `destination` : la table locale d'abord
    /// (nos adresses, la diffusion de nos réseaux), puis la principale.
    /// La diffusion limitée part par l'interface de la route par défaut
    /// (Linux : la recherche dans la principale, faute d'interface choisie).
    pub fn chercher(&self, destination: [u8; 4]) -> Option<Chemin> {
        // Une de nos adresses : elle-même pour source ; une autre adresse du
        // réseau de lo (127.1.2.3) : celle de lo, la `prefsrc` de sa route
        // locale (« local 127.0.0.0/8 dev lo src 127.0.0.1 »).
        if self.adresses.iter().any(|x| x.adresse == destination) {
            return Some(Chemin::Locale { source: destination });
        }
        if let Some(x) = self.adresses.iter().find(|x| x.boucle && ipv4::dans(destination, x.adresse, x.prefixe) && x.diffusion() != destination) {
            return Some(Chemin::Locale { source: x.adresse });
        }
        if let Some(a) = self.adresses.iter().find(|a| a.prefixe < 31 && a.diffusion() == destination) {
            return Some(Chemin::Diffusion { interface: a.interface, source: a.adresse });
        }
        let r = self.meilleure(destination)?;
        if destination == ipv4::DIFFUSION {
            return Some(Chemin::Diffusion { interface: r.interface, source: r.source });
        }
        Some(Chemin::Unicast { interface: r.interface, prochain: r.passerelle.unwrap_or(destination), source: r.source })
    }

    /// Les routes de la table principale, dans l'ordre où les montre
    /// /proc/net/route : par réseau croissant (la clé de l'arbre de
    /// Linux), le plus long préfixe d'abord pour un même réseau.
    pub fn principales(&self) -> impl Iterator<Item = Route> + '_ {
        let mut ordre: [usize; MAX] = core::array::from_fn(|i| i);
        let n = self.routes.len();
        ordre[..n].sort_by_key(|&i| (u32::from_be_bytes(self.routes[i].reseau), u8::MAX - self.routes[i].prefixe));
        (0..n).map(move |k| self.routes[ordre[k]])
    }
}
