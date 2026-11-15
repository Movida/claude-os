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
//! Ce qu'ajoute IGMP (les rapports, les requêtes, l'état qu'ils demandent :
//! le `CONFIG_IP_MULTICAST` de Linux) n'est pas encore ici : ce module est
//! igmp.c sans lui. Un groupe n'est donc annoncé à personne, ce qui suffit
//! au réseau local de QEMU, que le pilote laisse tout entendre.
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
//! la place est prise avant, puis tout est fait.

use alloc::vec::Vec;
use faillible::VecFaillible;
use formats::reseau::ipv4;

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

/// Les sources d'une adhésion (`ip_sf_socklist`), dans l'ordre où elles ont
/// été données : au plus 10, d'où un tableau.
#[derive(Debug, Clone, Copy)]
struct Liste {
    n: usize,
    sources: [[u8; 4]; MAX_SOURCES],
}

impl Liste {
    const VIDE: Liste = Liste { n: 0, sources: [[0; 4]; MAX_SOURCES] };

    fn de(sources: &[[u8; 4]]) -> Liste {
        let mut l = Liste::VIDE;
        let n = sources.len().min(MAX_SOURCES);
        l.sources[..n].copy_from_slice(&sources[..n]);
        l.n = n;
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
}

impl Default for Adhesions {
    fn default() -> Self {
        Adhesions::new()
    }
}

impl Adhesions {
    /// Aucune adhésion (et aucune allocation : la place vient à la première).
    pub const fn new() -> Adhesions {
        Adhesions { entrees: Vec::new() }
    }

    pub fn est_vide(&self) -> bool {
        self.entrees.is_empty()
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
    /// ENODEV ; déjà membre par elle : EADDRINUSE ; 20 adhésions : ENOBUFS.
    /// L'interface gagne un membre du groupe. Rend son index.
    pub fn joindre(&mut self, groupes: &mut Groupes, d: Demande, trouvee: Option<u32>, mode: Mode) -> Result<u32, Refus> {
        if !ipv4::multidiffusion(d.groupe) {
            return Err(Refus::Invalide);
        }
        let Some(k) = trouvee else { return Err(Refus::PasDInterface) };
        if self.trouver(d.groupe, k).is_some() {
            return Err(Refus::DejaMembre);
        }
        if self.entrees.len() >= MAX_ADHESIONS {
            return Err(Refus::PlusDePlace);
        }
        self.entrees.try_reserve(1).map_err(|_| Refus::PlusDePlace)?;
        let i = groupes.interface_mut(k).ok_or(Refus::PasDInterface)?;
        i.inc_group(d.groupe, mode)?;
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
        if let Some(i) = groupes.interface_mut(e.interface) {
            i.del_src(e.groupe, e.mode, e.sources(), false);
            i.dec_group(e.groupe);
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
        let i = groupes.interface_mut(k).ok_or(Refus::PasDInterface)?;
        let e = &mut self.entrees[p];
        if e.liste.is_some() {
            if e.mode != mode {
                return Err(Refus::Invalide);
            }
        } else if e.mode != mode {
            let _ = i.add_src(d.groupe, mode, &[], false);
            i.del_src(d.groupe, e.mode, &[], false);
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
            i.del_src(d.groupe, mode, &[source], true);
            l.sources.copy_within(j + 1..l.n, j);
            l.n -= 1;
            return Ok(());
        }
        let l = e.liste.unwrap_or(Liste::VIDE);
        if l.n >= MAX_SOURCES {
            return Err(Refus::PlusDePlace);
        }
        if l.position(source).is_some() {
            return Err(Refus::Introuvable);
        }
        i.add_src(d.groupe, mode, &[source], true)?;
        let l = e.liste.get_or_insert(Liste::VIDE);
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
        if sources.len() > MAX_SOURCES {
            return Err(Refus::PlusDePlace);
        }
        let i = groupes.interface_mut(k).ok_or(Refus::PasDInterface)?;
        i.add_src(d.groupe, mode, sources, false)?;
        let e = &mut self.entrees[p];
        i.del_src(d.groupe, e.mode, e.sources(), false);
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
/// sockets qui l'incluent, et celles qui l'excluent.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    adresse: [u8; 4],
    comptes: [u32; 2],
}

impl Source {
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
/// elles sont venues.
pub struct Groupe {
    adresse: [u8; 4],
    utilisateurs: u32,
    mode: Mode,
    comptes: [u32; 2],
    sources: Vec<Source>,
}

impl Groupe {
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

    /// `ip_mc_add1_src` : la source `s` (nouvelle : en fin de liste ; plus
    /// de mémoire : ENOBUFS) compte une socket de plus dans le mode `mode`.
    fn add1_src(&mut self, mode: Mode, s: [u8; 4]) -> Result<(), Refus> {
        let k = match self.sources.iter().position(|x| x.adresse == s) {
            Some(k) => k,
            None => {
                self.sources.ajouter(Source { adresse: s, comptes: [0; 2] }).map_err(|_| Refus::PlusDePlace)?;
                self.sources.len() - 1
            }
        };
        self.sources[k].comptes[mode as usize] += 1;
        Ok(())
    }

    /// `ip_mc_del1_src` : la source `s` compte une socket de moins dans le
    /// mode `mode` ; plus aucune : elle quitte la liste. Absente, ou à zéro
    /// dans ce mode (« bug » pour Linux, qui l'ignore) : rien.
    fn del1_src(&mut self, mode: Mode, s: [u8; 4]) {
        let Some(k) = self.sources.iter().position(|x| x.adresse == s) else { return };
        let c = &mut self.sources[k].comptes;
        if c[mode as usize] == 0 {
            return;
        }
        c[mode as usize] -= 1;
        if c[0] == 0 && c[1] == 0 {
            self.sources.remove(k);
            self.sources.rendre_la_place();
        }
    }
}

/// Une interface et ses groupes (son `in_device`), dans l'ordre où ils sont
/// venus ; /proc/net/igmp les montre le plus récent d'abord (`groupes`).
pub struct Interface {
    index: u32,
    groupes: Vec<Groupe>,
}

impl Interface {
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

    fn groupe_mut(&mut self, groupe: [u8; 4]) -> Option<&mut Groupe> {
        self.groupes.iter_mut().find(|g| g.adresse == groupe)
    }

    /// `____ip_mc_inc_group` : un membre de plus pour le groupe `groupe`, dans
    /// le mode `mode` sans source ; un groupe nouveau prend ce mode (plus de
    /// mémoire : ENOBUFS).
    fn inc_group(&mut self, groupe: [u8; 4], mode: Mode) -> Result<(), Refus> {
        if let Some(g) = self.groupe_mut(groupe) {
            g.utilisateurs += 1;
            return self.add_src(groupe, mode, &[], false);
        }
        let mut comptes = [0; 2];
        comptes[mode as usize] = 1;
        self.groupes.ajouter(Groupe { adresse: groupe, utilisateurs: 1, mode, comptes, sources: Vec::new() })
            .map_err(|_| Refus::PlusDePlace)
    }

    /// `__ip_mc_dec_group` : un membre de moins ; plus aucun : le groupe et
    /// ses sources s'en vont (`ip_mc_clear_src`).
    fn dec_group(&mut self, groupe: [u8; 4]) {
        let Some(k) = self.groupes.iter().position(|g| g.adresse == groupe) else { return };
        let g = &mut self.groupes[k];
        g.utilisateurs -= 1;
        if g.utilisateurs == 0 {
            self.groupes.remove(k);
            self.groupes.rendre_la_place();
        }
    }

    /// `ip_mc_add_src` : une socket de plus dans le mode `mode` (sauf
    /// `delta` : des sources ajoutées à une socket qui y est déjà), et
    /// chacune des `sources` ; une source qui ne peut pas être ajoutée
    /// (ENOBUFS) défait tout. Le mode du filtre suit : EXCLUDE dès qu'une
    /// socket l'est, sinon INCLUDE (sans aucune socket, il reste).
    fn add_src(&mut self, groupe: [u8; 4], mode: Mode, sources: &[[u8; 4]], delta: bool) -> Result<(), Refus> {
        let Some(g) = self.groupe_mut(groupe) else { return Err(Refus::Introuvable) };
        let exclusion = g.mode == Mode::Exclure;
        if !delta {
            g.comptes[mode as usize] += 1;
        }
        for (k, &s) in sources.iter().enumerate() {
            if let Err(e) = g.add1_src(mode, s) {
                if !delta {
                    g.comptes[mode as usize] -= 1;
                }
                for &s in &sources[..k] {
                    g.del1_src(mode, s);
                }
                return Err(e);
            }
        }
        let (inclus, exclus) = (g.comptes[Mode::Inclure as usize], g.comptes[Mode::Exclure as usize]);
        if exclusion != (exclus != 0) {
            if exclus != 0 {
                g.mode = Mode::Exclure;
            } else if inclus != 0 {
                g.mode = Mode::Inclure;
            }
        }
        Ok(())
    }

    /// `ip_mc_del_src` : une socket de moins dans le mode `mode` (sauf
    /// `delta` ; déjà aucune : rien du tout, le EINVAL que personne ne lit),
    /// et chacune des `sources`. Le dernier EXCLUDE parti, avec des INCLUDE,
    /// le filtre passe en INCLUDE.
    fn del_src(&mut self, groupe: [u8; 4], mode: Mode, sources: &[[u8; 4]], delta: bool) {
        let Some(g) = self.groupe_mut(groupe) else { return };
        if !delta {
            if g.comptes[mode as usize] == 0 {
                return;
            }
            g.comptes[mode as usize] -= 1;
        }
        for &s in sources {
            g.del1_src(mode, s);
        }
        if g.mode == Mode::Exclure && g.comptes[Mode::Exclure as usize] == 0 && g.comptes[Mode::Inclure as usize] != 0 {
            g.mode = Mode::Inclure;
        }
    }
}

/// Les groupes de chaque interface de la machine, dans l'ordre de leur
/// index (celui de /proc/net/igmp).
pub struct Groupes {
    interfaces: Vec<Interface>,
}

impl Default for Groupes {
    fn default() -> Self {
        Groupes::new()
    }
}

impl Groupes {
    pub const fn new() -> Groupes {
        Groupes { interfaces: Vec::new() }
    }

    /// L'interface `index` monte (`ip_mc_init_dev`, `ip_mc_up`) : elle
    /// adhère à 224.0.0.1. Plus de mémoire : ENOBUFS (elle n'aura aucun
    /// groupe). Déjà montée : rien.
    pub fn monter(&mut self, index: u32) -> Result<(), Refus> {
        if self.interface(index).is_some() {
            return Ok(());
        }
        let mut i = Interface { index, groupes: Vec::new() };
        i.inc_group(TOUS_LES_HOTES, Mode::Exclure)?;
        let k = self.interfaces.iter().position(|x| x.index > index).unwrap_or(self.interfaces.len());
        self.interfaces.inserer(k, i).map_err(|_| Refus::PlusDePlace)
    }

    pub fn interface(&self, index: u32) -> Option<&Interface> {
        self.interfaces.iter().find(|i| i.index == index)
    }

    fn interface_mut(&mut self, index: u32) -> Option<&mut Interface> {
        self.interfaces.iter_mut().find(|i| i.index == index)
    }

    pub fn interfaces(&self) -> impl Iterator<Item = &Interface> {
        self.interfaces.iter()
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
