//! La multidiffusion d'IPv4 (RFC 1112, et les filtres de sources de la RFC
//! 3376, 3.2) : à quels groupes adhère chaque socket, avec quel filtre
//! (`Adhesions`, la `mc_list` d'une `inet_sock` de Linux) ; quels groupes a
//! chaque interface, et le filtre qui en résulte (`Groupes`, la `mc_list`
//! de chaque `in_device`). Les fonctions de net/ipv4/igmp.c sont recopiées
//! ici une à une ; chacune dit son nom.
//!
//! Le filtre d'une socket pour un groupe : un mode, et au plus 10 sources
//! (`igmp_max_msf`). INCLUDE {S} ne reçoit que de S ; EXCLUDE {S}, de tous
//! sauf de S ; une adhésion simple (IP_ADD_MEMBERSHIP) est EXCLUDE {}.
//! Celui d'une interface les réunit (RFC 3376, 3.2) : elle est en EXCLUDE
//! dès qu'une de ses sockets l'est, et une source y est refusée quand
//! aucune socket ne l'inclut et que toutes celles en EXCLUDE l'excluent.
//! Pour cela, chaque groupe compte ses sockets dans chaque mode
//! (`sfcount`), et chaque source les sockets qui la nomment dans chaque mode
//! (`sf_count`). Le filtre de l'interface décide de ce qu'elle laisse entrer
//! (`ip_check_mc_rcu`, `verifier`) ; celui de chaque socket, de ce qu'elle
//! reçoit (`ip_mc_sf_allow`, `permet`).
//!
//! La bibliothèque ne connaît ni les interfaces ni les routes : l'appelant
//! lui dit laquelle désigne une demande (`trouvee` : ce que rend
//! `ip_mc_find_dev`, l'index donné s'il existe, sinon l'interface qui porte
//! l'adresse donnée, sinon celle de la route vers le groupe), et tient le
//! verrou qui fait de chaque opération un tout (le `rtnl_lock` de Linux).
//!
//! Ce qu'ajoute IGMP (les rapports aux routeurs, leurs requêtes, les
//! minuteurs : le `CONFIG_IP_MULTICAST` de Linux) est dans le module
//! `igmp`. Ici n'en restent que les lignes qu'il ajoute aux fonctions des
//! filtres (`sf_markstate` et `sf_setstate` autour de chaque changement,
//! les sources parties gardées pour les rapports), à leur place, comme
//! chez Linux : chaque changement de filtre décide de ce que diront les
//! rapports suivants. Les rapports ne partent pas d'ici : ils attendent
//! dans `Groupes::envois`, que le noyau prend une fois son verrou lâché.
//!
//! Chaque interface Ethernet tient aussi les adresses MAC de ses groupes
//! (`Interface::macs` : la liste `dev->mc` de la carte, que remplissent
//! `ip_mc_filter_add` et `ip_mc_filter_del` quand un groupe arrive ou
//! part), pour le filtre de sa carte, qui ne laisse entrer que les trames de
//! multidiffusion vers l'une d'elles. Choix de conception : elle vit ici,
//! avec les groupes, plutôt que dans le pilote : chez Linux, elle appartient
//! à la `net_device` (IPv6 y met aussi les siennes), mais nous n'avons
//! qu'IPv4, et la changer au même endroit et sous le même verrou que les
//! groupes la garde juste sans rien recopier ; le pilote la lit quand on lui
//! dit qu'elle a changé (`prendre_les_macs_touchees`).
//!
//! Choix de conception : les deux côtés dans une même bibliothèque. Chaque
//! opération d'une socket change le filtre de l'interface dans un ordre
//! précis (`ip_mc_add_src` avant `ip_mc_del_src`, pour qu'un groupe ne
//! passe jamais par « aucune socket »), en même temps que l'état de la
//! socket : les tester ensemble est ce qui garantit cet ordre. Écartés : la
//! socket qui rend une liste de changements à appliquer (un intermédiaire
//! de plus, à tenir dans l'ordre par l'appelant), ou des appels du noyau
//! d'un côté puis de l'autre (l'ordre se perdrait dans la colle).
//!
//! Choix de conception : une allocation qui échoue fait échouer toute
//! l'opération (ENOBUFS), rien n'étant changé. Linux, lui, ignore l'échec de
//! deux allocations : celle du groupe d'une interface à l'adhésion
//! (`____ip_mc_inc_group` : la socket adhère, l'interface n'a pas le
//! groupe), et celle d'une source ajoutée (`ip_mc_source` n'en regarde pas
//! le résultat) : la socket et l'interface ne disent plus la même chose. Ici,
//! la place est prise avant, puis tout est fait. Seuls les souvenirs
//! d'IGMP (une source ou un groupe partis, que les rapports suivants
//! annonceront) restent sans place réservée, comme chez Linux : leur
//! allocation qui échoue fait perdre un enregistrement à un rapport, comme
//! un paquet perdu en route, mais ce qui entre ne dépend jamais d'eux.

mod igmp;

use alloc::vec::Vec;
use faillible::VecFaillible;
use formats::reseau::{ethernet, ipv4};
pub use igmp::{Envoi, HZ};

/// Le plus d'adhésions d'une socket (`igmp_max_memberships`).
pub const MAX_ADHESIONS: usize = 20;
/// Le plus de sources d'une adhésion (`igmp_max_msf`).
pub const MAX_SOURCES: usize = 10;
/// 224.0.0.1, tous les hôtes (IGMP_ALL_HOSTS) : chaque interface en est
/// membre dès qu'elle monte.
pub const TOUS_LES_HOTES: [u8; 4] = [224, 0, 0, 1];
/// Le protocole d'IGMP dans l'en-tête IPv4 : un paquet IGMP pour un groupe
/// de l'interface entre toujours, quelle que soit sa source.
pub use formats::reseau::ipv4::IGMP;

/// Une adresse MAC de groupe d'une carte (une `netdev_hw_addr` de sa liste
/// `dev->mc`), et le nombre de ses groupes qui y mènent (`refcount` : 32
/// groupes ont la même, `ip_eth_mc_map` ne gardant que 23 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mac {
    pub adresse: [u8; 6],
    pub groupes: u32,
}

/// Le mode d'un filtre : ses nombres sont ceux de Linux (MCAST_EXCLUDE 0,
/// MCAST_INCLUDE 1), qui servent aussi d'indices aux compteurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Exclure = 0,
    Inclure = 1,
}

impl Mode {
    /// Le mode du nombre `n` (`imsf_fmode`, `gf_fmode`) ; un autre : None.
    pub fn de(n: u32) -> Option<Mode> {
        match n {
            0 => Some(Mode::Exclure),
            1 => Some(Mode::Inclure),
            _ => None,
        }
    }

    pub fn numero(self) -> u32 {
        self as u32
    }
}

/// Pourquoi une opération est refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// EINVAL : pas un groupe de multidiffusion, un mode inconnu, pas
    /// d'adhésion pour changer ses sources, l'autre mode déjà pris.
    Invalide,
    /// ENODEV : aucune interface pour la demande.
    PasDInterface,
    /// EADDRINUSE : déjà membre du groupe par cette interface.
    DejaMembre,
    /// ENOBUFS : trop d'adhésions ou de sources, ou plus de mémoire.
    PlusDePlace,
    /// EADDRNOTAVAIL : pas d'adhésion, ou pas cette source.
    Introuvable,
}

/// Une demande (l'`ip_mreqn` de Linux) : le groupe, l'adresse d'une
/// interface (0.0.0.0 : aucune), l'index d'une interface (0 : aucun).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Demande {
    pub groupe: [u8; 4],
    pub adresse: [u8; 4],
    pub index: u32,
}

/// Les places que gagne une liste de sources trop petite pour une de plus
/// (`IP_SFBLOCK`).
const BLOC_DE_SOURCES: usize = 10;
/// Ce que coûtent, dans la mémoire des options d'une socket (`sk_omem_alloc`,
/// SO_MEMINFO), une adhésion (`struct ip_mc_socklist`) et l'en-tête d'une
/// liste de sources (`struct ip_sf_socklist`, sans ses adresses) : leurs
/// tailles sur x86_64, que `sock_kmalloc` compte chez Linux (mesuré).
const COUT_ADHESION: usize = 48;
const COUT_LISTE: usize = 24;

/// Les sources d'une adhésion (`ip_sf_socklist`), dans l'ordre où elles ont
/// été données : au plus 10, d'où un tableau.
#[derive(Debug, Clone, Copy)]
struct Liste {
    n: usize,
    sources: [[u8; 4]; MAX_SOURCES],
    /// Les places de la liste de Linux (`sl_max`), que compte la mémoire
    /// des options : BLOC_DE_SOURCES pour la première source d'IP_ADD_SOURCE_
    /// MEMBERSHIP, autant de plus quand elle est pleine (`ip_mc_source`) ;
    /// exactement le nombre de sources d'IP_MSFILTER (`ip_mc_msfilter`). Elle
    /// ne rétrécit pas quand une source s'en va.
    places: usize,
}

impl Liste {
    const VIDE: Liste = Liste { n: 0, sources: [[0; 4]; MAX_SOURCES], places: BLOC_DE_SOURCES };

    fn de(sources: &[[u8; 4]]) -> Liste {
        let mut l = Liste::VIDE;
        let n = sources.len().min(MAX_SOURCES);
        l.sources[..n].copy_from_slice(&sources[..n]);
        l.n = n;
        l.places = n;
        l
    }

    fn adresses(&self) -> &[[u8; 4]] {
        &self.sources[..self.n]
    }

    fn position(&self, a: [u8; 4]) -> Option<usize> {
        self.adresses().iter().position(|&x| x == a)
    }
}

/// Une adhésion d'une socket (`ip_mc_socklist`).
#[derive(Debug, Clone, Copy)]
struct Adhesion {
    groupe: [u8; 4],
    /// L'adresse de la demande, gardée telle quelle (`imr_address`) :
    /// IP_DROP_MEMBERSHIP la compare quand il ne trouve pas d'interface.
    adresse: [u8; 4],
    /// L'interface trouvée à l'adhésion (`imr_ifindex`).
    interface: u32,
    mode: Mode,
    /// Ses sources (`sflist`) : None tant qu'aucune n'a été donnée. Une
    /// liste vidée reste une liste : le mode ne change plus alors que par
    /// IP_MSFILTER (`ip_mc_source` : « allow mode switches for empty-set
    /// filters », seulement sans liste).
    liste: Option<Liste>,
}

impl Adhesion {
    fn sources(&self) -> &[[u8; 4]] {
        self.liste.as_ref().map_or(&[], |l| l.adresses())
    }
}

/// Les adhésions d'une socket, dans l'ordre où elles ont été faites. Linux
/// met la plus récente en tête de sa liste, et la parcourt dans cet ordre :
/// nous la parcourons à l'envers.
pub struct Adhesions {
    entrees: Vec<Adhesion>,
    /// La mémoire des options de la socket que lui laissent ses autres options
    /// (`borner`) : chaque adhésion, chaque liste de sources neuve ou plus
    /// grande, doit y tenir (sans limite tant que rien n'est posé).
    place: usize,
}

impl Default for Adhesions {
    fn default() -> Self {
        Adhesions::new()
    }
}

impl Adhesions {
    /// Aucune adhésion (et aucune allocation : la place vient à la première).
    pub const fn new() -> Adhesions {
        Adhesions { entrees: Vec::new(), place: usize::MAX }
    }

    /// La mémoire des options de la socket, `optmem_max`, moins ce qu'y comptent
    /// ses autres options (son filtre, ses avis de MSG_ZEROCOPY) : posée par le
    /// noyau avant chaque changement. Une adhésion, une liste de sources neuve ou
    /// plus grande, n'est prise que si les adhésions, avec elle, restent
    /// strictement en dessous (`sock_kmalloc` : `omem + taille < optmem_max`), la
    /// liste qu'elle remplace encore comptée ; sinon ENOBUFS.
    pub fn borner(&mut self, place: usize) {
        self.place = place;
    }

    /// `taille` octets de plus tiennent-ils (`borner`) ?
    fn peut_prendre(&self, taille: usize) -> bool {
        self.memoire().saturating_add(taille) < self.place
    }

    pub fn est_vide(&self) -> bool {
        self.entrees.is_empty()
    }

    /// Ce que coûtent les adhésions dans la mémoire des options de la socket
    /// (`sk_omem_alloc`, SO_MEMINFO) : chacune, et sa liste de sources.
    pub fn memoire(&self) -> usize {
        self.entrees.iter().map(|e| COUT_ADHESION + e.liste.map_or(0, |l| COUT_LISTE + 4 * l.places)).sum()
    }

    /// L'adhésion au groupe `groupe` par l'interface `interface`, la plus
    /// récente d'abord.
    fn trouver(&self, groupe: [u8; 4], interface: u32) -> Option<usize> {
        self.entrees.iter().rposition(|e| e.groupe == groupe && e.interface == interface)
    }

    /// Adhère au groupe de `d` par l'interface `trouvee`, dans le mode `mode`
    /// et sans source (`__ip_mc_join_group` : EXCLUDE pour IP_ADD_MEMBERSHIP
    /// et MCAST_JOIN_GROUP, INCLUDE avant d'ajouter une source,
    /// `ip_mc_join_group_ssm`) : pas un groupe : EINVAL ; pas d'interface :
    /// ENODEV ; déjà membre par elle : EADDRINUSE ; 20 adhésions, ou plus la place
    /// dans la mémoire des options (`borner`) : ENOBUFS.
    /// L'interface gagne un membre du groupe. Rend son index.
    pub fn joindre(&mut self, groupes: &mut Groupes, d: Demande, trouvee: Option<u32>, mode: Mode) -> Result<u32, Refus> {
        if !ipv4::multidiffusion(d.groupe) {
            return Err(Refus::Invalide);
        }
        let Some(k) = trouvee else { return Err(Refus::PasDInterface) };
        if self.trouver(d.groupe, k).is_some() {
            return Err(Refus::DejaMembre);
        }
        if self.entrees.len() >= MAX_ADHESIONS || !self.peut_prendre(COUT_ADHESION) {
            return Err(Refus::PlusDePlace);
        }
        self.entrees.try_reserve(1).map_err(|_| Refus::PlusDePlace)?;
        let (i, mut c) = groupes.interface_mut(k).ok_or(Refus::PasDInterface)?;
        i.inc_group(d.groupe, mode, &mut c)?;
        self.entrees.ajouter_dans_la_place(Adhesion { groupe: d.groupe, adresse: d.adresse, interface: k, mode, liste: None });
        Ok(k)
    }

    /// Quitte le groupe de `d` (`ip_mc_leave_group`) : sans index, sans
    /// adresse et sans interface trouvée (pas de route) : ENODEV ; l'adhésion
    /// par l'interface trouvée, ou, sans elle, celle d'un index donné, sinon
    /// celle qu'a demandée la même adresse (n'importe laquelle sans adresse) ;
    /// aucune : EADDRNOTAVAIL. Pas de contrôle du groupe. Ses sources
    /// quittent le filtre de l'interface, qui perd un membre.
    ///
    /// Linux retire du filtre l'interface trouvée par la demande, et pas
    /// celle de l'adhésion ; quand il n'en trouve pas (l'adhésion choisie par
    /// son adresse, une adresse qui n'est pas à nous), l'interface garde le
    /// groupe pour toujours, sans plus aucune socket. Ici, celle de
    /// l'adhésion, comme à la fermeture de la socket (`ip_mc_drop_socket`) :
    /// c'est la même quand Linux en trouve une.
    pub fn quitter(&mut self, groupes: &mut Groupes, d: Demande, trouvee: Option<u32>) -> Result<(), Refus> {
        if d.index == 0 && d.adresse == ipv4::AUCUNE && trouvee.is_none() {
            return Err(Refus::PasDInterface);
        }
        let index = trouvee.unwrap_or(d.index);
        let p = self.entrees.iter().rposition(|e| {
            e.groupe == d.groupe
                && if index != 0 { e.interface == index } else { d.adresse == ipv4::AUCUNE || d.adresse == e.adresse }
        });
        let Some(p) = p else { return Err(Refus::Introuvable) };
        self.retirer(groupes, p);
        Ok(())
    }

    /// Retire l'adhésion `p`, et ce qu'elle fait à son interface
    /// (`ip_mc_leave_src`, puis `ip_mc_dec_group`).
    fn retirer(&mut self, groupes: &mut Groupes, p: usize) {
        let e = self.entrees.remove(p);
        self.entrees.rendre_la_place();
        if let Some((i, mut c)) = groupes.interface_mut(e.interface) {
            i.del_src(e.groupe, e.mode, e.sources(), false, &mut c);
            i.dec_group(e.groupe, &mut c);
        }
    }

    /// Ajoute (`ajout`) ou retire la source `source` du filtre de mode `mode`
    /// de l'adhésion de `d` (`ip_mc_source` : IP_BLOCK_SOURCE et
    /// IP_UNBLOCK_SOURCE en EXCLUDE, IP_ADD_SOURCE_MEMBERSHIP et
    /// IP_DROP_SOURCE_MEMBERSHIP en INCLUDE, et leurs équivalents MCAST_*) :
    /// pas un groupe : EINVAL ; pas d'interface : ENODEV ; pas d'adhésion :
    /// EINVAL ; une liste dans l'autre mode : EINVAL ; sans liste, l'adhésion
    /// prend ce mode (même si la suite échoue) ; retirer une source absente,
    /// ou sans liste : EADDRNOTAVAIL ; retirer la dernière source d'un
    /// INCLUDE : quitter le groupe ; ajouter une source déjà là :
    /// EADDRNOTAVAIL, à 10 sources : ENOBUFS (d'abord). Une source ajoutée va
    /// en fin de liste. Le filtre de l'interface suit.
    pub fn source(&mut self, groupes: &mut Groupes, ajout: bool, mode: Mode, d: Demande, trouvee: Option<u32>, source: [u8; 4])
                  -> Result<(), Refus> {
        if !ipv4::multidiffusion(d.groupe) {
            return Err(Refus::Invalide);
        }
        let Some(k) = trouvee else { return Err(Refus::PasDInterface) };
        let Some(p) = self.trouver(d.groupe, k) else { return Err(Refus::Invalide) };
        let (i, mut c) = groupes.interface_mut(k).ok_or(Refus::PasDInterface)?;
        let (memoire, place) = (self.memoire(), self.place);
        let e = &mut self.entrees[p];
        if e.liste.is_some() {
            if e.mode != mode {
                return Err(Refus::Invalide);
            }
        } else if e.mode != mode {
            let _ = i.add_src(d.groupe, mode, &[], false, &mut c);
            i.del_src(d.groupe, e.mode, &[], false, &mut c);
            e.mode = mode;
        }
        if !ajout {
            let Some(l) = e.liste.as_mut() else { return Err(Refus::Introuvable) };
            let Some(j) = l.position(source) else { return Err(Refus::Introuvable) };
            if l.n == 1 && mode == Mode::Inclure {
                // INCLUDE {} : quitter le groupe (la demande, l'interface trouvée).
                self.retirer(groupes, p);
                return Ok(());
            }
            i.del_src(d.groupe, mode, &[source], true, &mut c);
            l.sources.copy_within(j + 1..l.n, j);
            l.n -= 1;
            return Ok(());
        }
        let l = e.liste.unwrap_or(Liste::VIDE);
        if l.n >= MAX_SOURCES {
            return Err(Refus::PlusDePlace);
        }
        // La liste neuve, ou plus grande (voir `grandir`), doit tenir dans la mémoire
        // des options, l'ancienne encore comptée (`borner`).
        let neuve = match e.liste {
            None => Some(l.places),
            Some(l) if l.n == l.places => Some(l.places + BLOC_DE_SOURCES),
            Some(_) => None,
        };
        if neuve.is_some_and(|places| memoire.saturating_add(COUT_LISTE + 4 * places) >= place) {
            return Err(Refus::PlusDePlace);
        }
        // Une liste pleine grandit avant que la source y soit cherchée
        // (`ip_mc_source`) : même pour une source qui y est déjà. (Une liste
        // qui naît est vide : la source n'y est pas.)
        let grandir = |l: &mut Liste| {
            if l.n == l.places {
                l.places += BLOC_DE_SOURCES;
            }
        };
        if l.position(source).is_some() {
            if let Some(l) = e.liste.as_mut() {
                grandir(l);
            }
            return Err(Refus::Introuvable);
        }
        i.add_src(d.groupe, mode, &[source], true, &mut c)?;
        let l = e.liste.get_or_insert(Liste::VIDE);
        grandir(l);
        l.sources[l.n] = source;
        l.n += 1;
        Ok(())
    }

    /// Adhère au groupe de `d` en INCLUDE (sauf déjà membre par l'interface
    /// `trouvee`), puis ajoute la source `source` à son filtre
    /// (IP_ADD_SOURCE_MEMBERSHIP et MCAST_JOIN_SOURCE_GROUP :
    /// `ip_mc_join_group_ssm`, dont EADDRINUSE est oublié, puis
    /// `ip_mc_source`) : les refus de `joindre`, puis ceux de `source`.
    ///
    /// D'un seul tenant : l'appelant tient les groupes et ces adhésions
    /// pendant les deux, comme Linux tient `rtnl_lock` et `lock_sock` pendant
    /// tout `do_ip_setsockopt`. Deux opérations à la suite lâcheraient les
    /// verrous entre elles : un autre fil du programme qui quitterait le
    /// groupe à ce moment ferait rendre EINVAL (« pas d'adhésion ») à
    /// l'ajout, ce que Linux ne rend jamais pour un groupe valide, et les
    /// rapports partiraient pour un état de passage (INCLUDE {}). La même
    /// interface sert aux deux : Linux la cherche deux fois, sous `rtnl_lock`,
    /// qui fige les adresses et les routes entre-temps.
    pub fn joindre_avec_source(&mut self, groupes: &mut Groupes, d: Demande, trouvee: Option<u32>, source: [u8; 4])
                               -> Result<(), Refus> {
        match self.joindre(groupes, d, trouvee, Mode::Inclure) {
            Ok(_) | Err(Refus::DejaMembre) => self.source(groupes, true, Mode::Inclure, d, trouvee, source),
            Err(r) => Err(r),
        }
    }

    /// Remplace le filtre de l'adhésion de `d` (`ip_mc_msfilter` :
    /// IP_MSFILTER, MCAST_MSFILTER) : pas un groupe, ou un mode inconnu :
    /// EINVAL ; pas d'interface : ENODEV ; INCLUDE sans source : quitter le
    /// groupe (EADDRNOTAVAIL sans adhésion) ; pas d'adhésion : EINVAL. Les
    /// nouvelles sources entrent dans le filtre de l'interface avant que les
    /// anciennes n'en sortent ; EXCLUDE sans source n'a plus de liste. Au plus
    /// 10 sources (l'appelant a refusé au-delà : ENOBUFS), qui peuvent se
    /// répéter : Linux ne le regarde pas.
    pub fn filtrer(&mut self, groupes: &mut Groupes, d: Demande, trouvee: Option<u32>, fmode: u32, sources: &[[u8; 4]])
                   -> Result<(), Refus> {
        if !ipv4::multidiffusion(d.groupe) {
            return Err(Refus::Invalide);
        }
        let Some(mode) = Mode::de(fmode) else { return Err(Refus::Invalide) };
        let Some(k) = trouvee else { return Err(Refus::PasDInterface) };
        if mode == Mode::Inclure && sources.is_empty() {
            return self.quitter(groupes, Demande { index: k, ..d }, Some(k));
        }
        let Some(p) = self.trouver(d.groupe, k) else { return Err(Refus::Invalide) };
        // La liste neuve (`borner`), l'ancienne encore comptée.
        if sources.len() > MAX_SOURCES || (!sources.is_empty() && !self.peut_prendre(COUT_LISTE + 4 * sources.len())) {
            return Err(Refus::PlusDePlace);
        }
        let (i, mut c) = groupes.interface_mut(k).ok_or(Refus::PasDInterface)?;
        i.add_src(d.groupe, mode, sources, false, &mut c)?;
        let e = &mut self.entrees[p];
        i.del_src(d.groupe, e.mode, e.sources(), false, &mut c);
        e.liste = if sources.is_empty() { None } else { Some(Liste::de(sources)) };
        e.mode = mode;
        Ok(())
    }

    /// Le filtre de l'adhésion au groupe `groupe` par l'interface `trouvee`
    /// (`ip_mc_msfget`, IP_MSFILTER lu) : pas un groupe : EINVAL ; pas
    /// d'interface : ENODEV ; pas d'adhésion : EADDRNOTAVAIL. Son mode et
    /// ses sources.
    pub fn filtre(&self, groupe: [u8; 4], trouvee: Option<u32>) -> Result<(Mode, &[[u8; 4]]), Refus> {
        if !ipv4::multidiffusion(groupe) {
            return Err(Refus::Invalide);
        }
        let Some(k) = trouvee else { return Err(Refus::PasDInterface) };
        self.filtre_par_index(groupe, k)
    }

    /// Le même, l'interface dite par son index, sans rien chercher
    /// (`ip_mc_gsfget`, MCAST_MSFILTER lu : l'index 0 n'est celui d'aucune
    /// adhésion) : pas un groupe : EINVAL ; pas d'adhésion : EADDRNOTAVAIL.
    pub fn filtre_par_index(&self, groupe: [u8; 4], index: u32) -> Result<(Mode, &[[u8; 4]]), Refus> {
        if !ipv4::multidiffusion(groupe) {
            return Err(Refus::Invalide);
        }
        let p = self.trouver(groupe, index).ok_or(Refus::Introuvable)?;
        let e = &self.entrees[p];
        Ok((e.mode, e.sources()))
    }

    /// La socket reçoit-elle un datagramme de `source` pour `destination`,
    /// arrivé par l'interface `dif` (`ip_mc_sf_allow`) ? Toujours s'il n'est
    /// pas pour un groupe ; sans adhésion au groupe par cette interface,
    /// selon IP_MULTICAST_ALL (`tous`) ; sinon selon son filtre (sans liste :
    /// EXCLUDE reçoit tout, INCLUDE rien).
    pub fn permet(&self, destination: [u8; 4], source: [u8; 4], dif: u32, tous: bool) -> bool {
        if !ipv4::multidiffusion(destination) {
            return true;
        }
        let Some(p) = self.trouver(destination, dif) else { return tous };
        let e = &self.entrees[p];
        match &e.liste {
            None => e.mode == Mode::Exclure,
            Some(l) => (l.position(source).is_some()) == (e.mode == Mode::Inclure),
        }
    }

    /// La socket se ferme (`ip_mc_drop_socket`) : chaque adhésion est
    /// rendue, la plus récente d'abord, à l'interface où elle a été faite.
    pub fn vider(&mut self, groupes: &mut Groupes) {
        while let Some(p) = self.entrees.len().checked_sub(1) {
            self.retirer(groupes, p);
        }
        self.entrees = Vec::new();
    }
}

/// Une source du filtre d'un groupe d'une interface (`ip_sf_list`) : les
/// sockets qui l'incluent, et celles qui l'excluent ; pour IGMP, ce qu'il
/// reste à en dire.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    adresse: [u8; 4],
    comptes: [u32; 2],
    /// Les rapports qui doivent encore la nommer (`sf_crcount`).
    crcount: u8,
    /// Elle entrait avant le changement en cours (`sf_oldin`, posé par
    /// `markstate`).
    avant: bool,
    /// Une requête du routeur la nomme ; la réponse la dira (`sf_gsresp`).
    demandee: bool,
}

impl Source {
    fn nouvelle(adresse: [u8; 4]) -> Source {
        Source { adresse, comptes: [0; 2], crcount: 0, avant: false, demandee: false }
    }

    pub fn adresse(&self) -> [u8; 4] {
        self.adresse
    }

    /// Les sockets qui l'incluent (`sf_count[MCAST_INCLUDE]`).
    pub fn inclus(&self) -> u32 {
        self.comptes[Mode::Inclure as usize]
    }

    /// Les sockets qui l'excluent (`sf_count[MCAST_EXCLUDE]`).
    pub fn exclus(&self) -> u32 {
        self.comptes[Mode::Exclure as usize]
    }
}

/// Un groupe d'une interface (`ip_mc_list`) : ses membres (les adhésions des
/// sockets, et l'interface elle-même pour 224.0.0.1), le mode de son
/// filtre, ses sockets dans chaque mode, et ses sources, dans l'ordre où
/// elles sont venues ; pour IGMP, ses sources parties, et son minuteur.
///
/// Un groupe parti dont les rapports ne sont pas finis a la même forme
/// (Linux fait de même : « Using the same structure for deleted items
/// allows change reports to use common code »), dans les tombes de son
/// interface.
pub struct Groupe {
    adresse: [u8; 4],
    utilisateurs: u32,
    mode: Mode,
    comptes: [u32; 2],
    sources: Vec<Source>,
    /// Les sources parties que les rapports doivent encore nommer
    /// (`tomb`), la dernière partie d'abord (la tête de la liste de Linux).
    tombe: Vec<Source>,
    /// Les rapports qui doivent encore dire le mode du filtre (`crcount`).
    crcount: u8,
    /// Une requête du routeur nomme certaines de ses sources
    /// (`gsquery`) : la réponse ne dira qu'elles.
    demande: bool,
    /// L'échéance de son minuteur (`timer`, `tm_running`) : un rapport v1
    /// ou v2, ou la réponse à une requête qui le nomme.
    minuteur: Option<u64>,
    /// Le dernier rapport sur lui vient de nous (`reporter`) : en v2, son
    /// départ sera annoncé.
    rapporteur: bool,
    /// Les rapports non sollicités qui restent à faire en v1 et v2
    /// (`unsolicit_count`).
    non_sollicites: u8,
}

impl Groupe {
    /// `____ip_mc_inc_group` : un groupe nouveau, d'un membre dans le mode
    /// `mode`, sans source.
    fn nouveau(adresse: [u8; 4], mode: Mode) -> Groupe {
        let mut comptes = [0; 2];
        comptes[mode as usize] = 1;
        Groupe {
            adresse,
            utilisateurs: 1,
            mode,
            comptes,
            sources: Vec::new(),
            tombe: Vec::new(),
            crcount: 0,
            demande: false,
            minuteur: None,
            rapporteur: false,
            non_sollicites: 0,
        }
    }

    pub fn adresse(&self) -> [u8; 4] {
        self.adresse
    }

    /// Ses membres (`users`).
    pub fn utilisateurs(&self) -> u32 {
        self.utilisateurs
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn sources(&self) -> impl Iterator<Item = &Source> {
        self.sources.iter()
    }

    /// L'échéance de son minuteur, s'il tourne (/proc/net/igmp : `Timer`).
    pub fn minuteur(&self) -> Option<u64> {
        self.minuteur
    }

    /// Le dernier rapport sur lui vient-il de nous (`Reporter`) ?
    pub fn rapporteur(&self) -> bool {
        self.rapporteur
    }

    /// `ip_mc_add1_src` : la source `s` (nouvelle : en fin de liste ; plus
    /// de mémoire : ENOBUFS) compte une socket de plus dans le mode `mode`.
    fn add1_src(&mut self, mode: Mode, s: [u8; 4]) -> Result<(), Refus> {
        let k = match self.sources.iter().position(|x| x.adresse == s) {
            Some(k) => k,
            None => {
                self.sources.ajouter(Source::nouvelle(s)).map_err(|_| Refus::PlusDePlace)?;
                self.sources.len() - 1
            }
        };
        self.sources[k].comptes[mode as usize] += 1;
        Ok(())
    }

    /// `ip_mc_del1_src` : la source `s` compte une socket de moins dans le
    /// mode `mode` ; plus aucune : elle quitte la liste, et, si elle entrait
    /// (`avant`) et que le routeur parle IGMPv3 (`v3`), va dans la tombe,
    /// pour que `qrv` rapports annoncent son départ : vrai. Absente, ou à
    /// zéro dans ce mode (« bug » pour Linux, qui l'ignore) : rien.
    fn del1_src(&mut self, mode: Mode, s: [u8; 4], v3: bool, qrv: u8) -> bool {
        let Some(k) = self.sources.iter().position(|x| x.adresse == s) else { return false };
        let c = &mut self.sources[k].comptes;
        if c[mode as usize] == 0 {
            return false;
        }
        c[mode as usize] -= 1;
        if c[0] != 0 || c[1] != 0 {
            return false;
        }
        let mut x = self.sources.remove(k);
        self.sources.rendre_la_place();
        if x.avant && v3 {
            x.crcount = qrv;
            // La tête de la tombe ; sans mémoire, un départ qu'aucun rapport
            // ne dira (Linux ne peut pas échouer ici : il déplace la source).
            return self.tombe.inserer(0, x).is_ok();
        }
        false
    }
}

/// Une interface, ses groupes (son `in_device`), dans l'ordre où ils sont
/// venus (/proc/net/igmp les montre le plus récent d'abord : `groupes`), et
/// ce qu'IGMP sait de son routeur.
pub struct Interface {
    index: u32,
    groupes: Vec<Groupe>,
    /// Les groupes partis que les rapports doivent encore annoncer
    /// (`mc_tomb`), le dernier parti d'abord.
    tombes: Vec<Groupe>,
    /// Combien de rapports répètent un changement (`mr_qrv` : 2, ou ce
    /// qu'a dit la dernière requête v3).
    qrv: u8,
    /// L'intervalle des requêtes du routeur et leur délai de réponse
    /// (`mr_qi`, `mr_qri`), en ns.
    qi: u64,
    qri: u64,
    /// Le délai de réponse de la dernière requête générale v3
    /// (`mr_maxdelay`), en jiffies.
    delai_max: u32,
    /// Un routeur v1, ou v2, entendu : jusqu'à cette heure, on lui parle sa
    /// langue (`mr_v1_seen`, `mr_v2_seen`).
    v1_vu: Option<u64>,
    v2_vu: Option<u64>,
    /// Le minuteur des rapports de changement (`mr_ifc_timer`), et combien
    /// il en reste à faire (`mr_ifc_count`).
    ifc: Option<u64>,
    ifc_restants: u8,
    /// Le minuteur de la réponse à une requête générale v3 (`mr_gq_timer`,
    /// `mr_gq_running`).
    gq: Option<u64>,
    /// Une carte Ethernet : ses groupes ont une adresse MAC (`arp_mc_map` ;
    /// lo, ARPHRD_LOOPBACK, n'en a pas).
    ethernet: bool,
    /// Les adresses MAC de ses groupes, chacune une fois, dans l'ordre de
    /// leur venue (une adresse déjà là garde sa place quand un autre groupe
    /// y mène : mesuré, /proc/net/dev_mcast).
    macs: Vec<Mac>,
    /// La liste a été touchée depuis que le noyau l'a regardée : chaque
    /// `dev_mc_add` et `dev_mc_del` de Linux appelle `__dev_set_rx_mode`,
    /// même quand seul un compte change.
    macs_touchees: bool,
}

impl Interface {
    /// `ip_mc_init_dev` et `ip_mc_reset` : une interface sans groupe.
    fn nouvelle(index: u32, ethernet: bool) -> Interface {
        Interface {
            index,
            groupes: Vec::new(),
            tombes: Vec::new(),
            qrv: igmp::QRV,
            qi: igmp::INTERVALLE_DES_REQUETES,
            qri: igmp::DELAI_DE_REPONSE,
            delai_max: 0,
            v1_vu: None,
            v2_vu: None,
            ifc: None,
            ifc_restants: 0,
            gq: None,
            ethernet,
            macs: Vec::new(),
            macs_touchees: false,
        }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Ses groupes, le plus récent d'abord (la tête de la `mc_list` de
    /// Linux).
    pub fn groupes(&self) -> impl Iterator<Item = &Groupe> {
        self.groupes.iter().rev()
    }

    /// Le groupe `groupe`, s'il est à elle.
    pub fn groupe(&self, groupe: [u8; 4]) -> Option<&Groupe> {
        self.groupes.iter().find(|g| g.adresse == groupe)
    }

    fn position(&self, groupe: [u8; 4]) -> Option<usize> {
        self.groupes.iter().position(|g| g.adresse == groupe)
    }

    /// Les adresses MAC de ses groupes (vide pour lo), dans l'ordre de
    /// /proc/net/dev_mcast.
    pub fn macs(&self) -> &[Mac] {
        &self.macs
    }

    /// La place de l'adresse MAC du groupe `groupe` s'il en faut une (une
    /// carte Ethernet, une adresse qu'aucun groupe n'a encore), prise avant
    /// que le groupe n'entre dans la liste : `filter_add` ne peut plus échouer.
    fn place_pour_la_mac(&mut self, groupe: [u8; 4]) -> Result<(), Refus> {
        let mac = ethernet::de_groupe(groupe);
        if !self.ethernet || self.macs.iter().any(|m| m.adresse == mac) {
            return Ok(());
        }
        self.macs.try_reserve(1).map_err(|_| Refus::PlusDePlace)
    }

    /// `ip_mc_filter_add` (par `dev_mc_add`) : l'adresse MAC du groupe
    /// `groupe` dans la liste de la carte, une de plus si elle y est déjà,
    /// à la fin sinon, dans la place prise par `place_pour_la_mac`. Rien pour
    /// lo.
    fn filter_add(&mut self, groupe: [u8; 4]) {
        if !self.ethernet {
            return;
        }
        let mac = ethernet::de_groupe(groupe);
        match self.macs.iter_mut().find(|m| m.adresse == mac) {
            Some(m) => m.groupes += 1,
            None => self.macs.ajouter_dans_la_place(Mac { adresse: mac, groupes: 1 }),
        }
        self.macs_touchees = true;
    }

    /// `ip_mc_filter_del` (par `dev_mc_del`) : un groupe de moins pour
    /// l'adresse MAC de `groupe` ; plus aucun, elle quitte la liste.
    fn filter_del(&mut self, groupe: [u8; 4]) {
        let mac = ethernet::de_groupe(groupe);
        let Some(k) = self.macs.iter().position(|m| m.adresse == mac) else { return };
        self.macs[k].groupes -= 1;
        if self.macs[k].groupes == 0 {
            self.macs.remove(k);
            self.macs.rendre_la_place();
        }
        self.macs_touchees = true;
    }

    /// `____ip_mc_inc_group` : un membre de plus pour le groupe `groupe`, dans
    /// le mode `mode` sans source ; un groupe nouveau prend ce mode (plus de
    /// mémoire : ENOBUFS), reprend ce qui restait à dire de lui s'il était
    /// parti (`igmpv3_del_delrec`), et IGMP l'annonce (`igmp_group_added`).
    fn inc_group(&mut self, groupe: [u8; 4], mode: Mode, c: &mut Contexte) -> Result<(), Refus> {
        if let Some(k) = self.position(groupe) {
            self.groupes[k].utilisateurs += 1;
            return self.add_src(groupe, mode, &[], false, c);
        }
        // Linux ignore un `dev_mc_add` sans mémoire (la carte ne laisse
        // alors pas entrer le groupe) ; ici, comme toute allocation, il fait
        // échouer l'adhésion.
        self.place_pour_la_mac(groupe)?;
        self.groupes.ajouter(Groupe::nouveau(groupe, mode)).map_err(|_| Refus::PlusDePlace)?;
        let k = self.groupes.len() - 1;
        self.del_delrec(k);
        self.group_added(k, c);
        Ok(())
    }

    /// `__ip_mc_dec_group` : un membre de moins ; plus aucun : le groupe
    /// quitte la liste, IGMP annonce son départ (`igmp_group_dropped`), et
    /// ses sources s'en vont avec lui (`ip_mc_clear_src`).
    fn dec_group(&mut self, groupe: [u8; 4], c: &mut Contexte) {
        let Some(k) = self.position(groupe) else { return };
        let g = &mut self.groupes[k];
        g.utilisateurs -= 1;
        if g.utilisateurs == 0 {
            let g = self.groupes.remove(k);
            self.groupes.rendre_la_place();
            self.group_dropped(g, c);
        }
    }

    /// `ip_mc_add_src` : une socket de plus dans le mode `mode` (sauf
    /// `delta` : des sources ajoutées à une socket qui y est déjà), et
    /// chacune des `sources` ; une source qui ne peut pas être ajoutée
    /// (ENOBUFS) défait tout. Le mode du filtre suit : EXCLUDE dès qu'une
    /// socket l'est, sinon INCLUDE (sans aucune socket, il reste). Pour
    /// IGMP, ce qui entrait avant est noté (`sf_markstate`), et ce qui
    /// change ensuite sera annoncé : le mode (`qrv` rapports le diront), ou
    /// les sources qui entrent ou sortent (`sf_setstate`).
    fn add_src(&mut self, groupe: [u8; 4], mode: Mode, sources: &[[u8; 4]], delta: bool, c: &mut Contexte)
               -> Result<(), Refus> {
        let (v3, qrv) = (self.v3(c.h.maintenant), self.qrv);
        let Some(k) = self.position(groupe) else { return Err(Refus::Introuvable) };
        let g = &mut self.groupes[k];
        g.markstate();
        let exclusion = g.mode == Mode::Exclure;
        if !delta {
            g.comptes[mode as usize] += 1;
        }
        for (j, &s) in sources.iter().enumerate() {
            if let Err(e) = g.add1_src(mode, s) {
                if !delta {
                    g.comptes[mode as usize] -= 1;
                }
                for &s in &sources[..j] {
                    g.del1_src(mode, s, v3, qrv);
                }
                return Err(e);
            }
        }
        let (inclus, exclus) = (g.comptes[Mode::Inclure as usize], g.comptes[Mode::Exclure as usize]);
        let evenement = if exclusion != (exclus != 0) {
            if exclus != 0 {
                g.mode = Mode::Exclure;
            } else if inclus != 0 {
                g.mode = Mode::Inclure;
            }
            // Sans socket, le mode reste celui d'avant : les rapports le
            // diront (« else no filters; keep old mode for reports »).
            g.changement_de_mode(qrv);
            self.ifc_restants = qrv;
            true
        } else {
            g.setstate(qrv) != 0
        };
        if evenement {
            self.ifc_event(c);
        }
        Ok(())
    }

    /// `ip_mc_del_src` : une socket de moins dans le mode `mode` (sauf
    /// `delta` ; déjà aucune : rien du tout, le EINVAL que personne ne lit),
    /// et chacune des `sources`. Le dernier EXCLUDE parti, avec des INCLUDE,
    /// le filtre passe en INCLUDE. IGMP comme pour `add_src`, et les
    /// sources parties qui entraient.
    fn del_src(&mut self, groupe: [u8; 4], mode: Mode, sources: &[[u8; 4]], delta: bool, c: &mut Contexte) {
        let (v3, qrv) = (self.v3(c.h.maintenant), self.qrv);
        let Some(k) = self.position(groupe) else { return };
        let g = &mut self.groupes[k];
        g.markstate();
        if !delta {
            if g.comptes[mode as usize] == 0 {
                return;
            }
            g.comptes[mode as usize] -= 1;
        }
        let mut tombees = false;
        for &s in sources {
            tombees |= g.del1_src(mode, s, v3, qrv);
        }
        let evenement = if g.mode == Mode::Exclure && g.comptes[Mode::Exclure as usize] == 0
            && g.comptes[Mode::Inclure as usize] != 0 {
            g.mode = Mode::Inclure;
            g.changement_de_mode(qrv);
            self.ifc_restants = qrv;
            true
        } else {
            // `sf_setstate` d'abord, toujours : il pose les comptes.
            g.setstate(qrv) != 0 || tombees
        };
        if evenement {
            self.ifc_event(c);
        }
    }
}

/// Ce dont une opération sur les groupes d'une interface a besoin pour
/// IGMP : l'heure et le hasard, et où laisser les rapports à envoyer.
struct Contexte<'a> {
    h: Horloge,
    envois: &'a mut Vec<Envoi>,
}

/// Ce que le noyau prête à la bibliothèque : l'heure (en ns, celle de ses
/// échéances), le hasard (`get_random_u32_below` : un nombre de 0 à `n`
/// exclu ; 0 pour 0), et la MTU d'une interface (`dev->mtu`, que le DHCP
/// peut changer : lue à chaque rapport).
#[derive(Clone, Copy)]
pub struct Horloge {
    pub maintenant: u64,
    pub alea: fn(u32) -> u32,
    pub mtu: fn(u32) -> u32,
}

/// Les groupes de chaque interface de la machine, dans l'ordre de leur
/// index (celui de /proc/net/igmp), et les rapports d'IGMP prêts à partir.
pub struct Groupes {
    interfaces: Vec<Interface>,
    horloge: Horloge,
    envois: Vec<Envoi>,
}

impl Groupes {
    /// Aucune interface ; le hasard et la MTU que donne le noyau.
    pub const fn new(alea: fn(u32) -> u32, mtu: fn(u32) -> u32) -> Groupes {
        Groupes { interfaces: Vec::new(), horloge: Horloge { maintenant: 0, alea, mtu }, envois: Vec::new() }
    }

    /// L'heure de ce qui suit (le noyau la donne à chaque prise de son
    /// verrou : les jiffies que Linux lit).
    pub fn regler(&mut self, maintenant: u64) {
        self.horloge.maintenant = maintenant;
    }

    /// L'interface `index` monte (`ip_mc_init_dev`, `ip_mc_up`) : elle
    /// adhère à 224.0.0.1, qu'elle n'annonce jamais. `ethernet` : une carte,
    /// dont les groupes ont une adresse MAC (pas lo). Plus de mémoire :
    /// ENOBUFS (elle n'aura aucun groupe). Déjà montée : rien.
    pub fn monter(&mut self, index: u32, ethernet: bool) -> Result<(), Refus> {
        if self.interface(index).is_some() {
            return Ok(());
        }
        let mut i = Interface::nouvelle(index, ethernet);
        let mut c = Contexte { h: self.horloge, envois: &mut self.envois };
        i.inc_group(TOUS_LES_HOTES, Mode::Exclure, &mut c)?;
        let k = self.interfaces.iter().position(|x| x.index > index).unwrap_or(self.interfaces.len());
        self.interfaces.inserer(k, i).map_err(|_| Refus::PlusDePlace)
    }

    pub fn interface(&self, index: u32) -> Option<&Interface> {
        self.interfaces.iter().find(|i| i.index == index)
    }

    /// L'interface `index`, et de quoi faire IGMP.
    fn interface_mut(&mut self, index: u32) -> Option<(&mut Interface, Contexte<'_>)> {
        let h = self.horloge;
        let i = self.interfaces.iter_mut().find(|i| i.index == index)?;
        Some((i, Contexte { h, envois: &mut self.envois }))
    }

    pub fn interfaces(&self) -> impl Iterator<Item = &Interface> {
        self.interfaces.iter()
    }

    /// Les adresses MAC de groupe d'une interface au moins ont-elles changé
    /// depuis le dernier appel ? Le noyau le demande après chaque opération,
    /// et refait alors le filtre de la carte (`__dev_set_rx_mode`).
    pub fn prendre_les_macs_touchees(&mut self) -> bool {
        let mut touchees = false;
        for i in &mut self.interfaces {
            touchees |= core::mem::take(&mut i.macs_touchees);
        }
        touchees
    }

    /// Un paquet de `source` pour le groupe `groupe`, de protocole
    /// `protocole`, entre-t-il par l'interface `index` (`ip_check_mc_rcu`) ?
    /// Si elle a le groupe : IGMP toujours, une source 0.0.0.0 aussi (« not
    /// specified ; tentatively allow ») ; sinon selon son filtre : une
    /// source nommée entre si une socket l'inclut, ou si toutes celles en
    /// EXCLUDE ne l'excluent pas ; une autre, s'il y a une socket en
    /// EXCLUDE. Sert aussi à l'envoi : une copie n'est rendue à la machine
    /// que pour un groupe qu'elle laisse entrer (`__mkroute_output`,
    /// RTCF_LOCAL).
    pub fn verifier(&self, index: u32, groupe: [u8; 4], source: [u8; 4], protocole: u8) -> bool {
        let Some(g) = self.interface(index).and_then(|i| i.groupe(groupe)) else { return false };
        if protocole == IGMP || source == ipv4::AUCUNE {
            return true;
        }
        let exclus = g.comptes[Mode::Exclure as usize];
        match g.sources.iter().find(|s| s.adresse == source) {
            Some(s) => s.inclus() != 0 || s.exclus() != exclus,
            None => exclus != 0,
        }
    }
}
