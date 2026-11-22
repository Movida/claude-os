//! Les groupes SO_REUSEPORT (le `sock_reuseport` de Linux,
//! net/core/sock_reuseport.c) : des sockets qui partagent un port, et entre
//! lesquelles le noyau répartit ce qui arrive.
//!
//! SO_REUSEPORT permet à plusieurs sockets du même utilisateur de prendre le
//! même port ; le GROUPE dit ensuite laquelle reçoit chaque datagramme
//! (UDP) ou chaque connexion (TCP) : un serveur ouvre une socket par fil ou
//! par processeur, et le noyau répartit le travail sans verrou partagé côté
//! programme. Le choix (`reuseport_select_sock`) :
//!   - si le groupe a un programme (SO_ATTACH_REUSEPORT_CBPF), il est passé
//!     sur le paquet (ses données commencent après l'en-tête de transport) et
//!     rend un INDEX dans le groupe ; trop grand, on retombe sur le hachage ;
//!   - sinon, le hachage du flux (ses deux adresses et ses deux ports, sous
//!     une clé secrète) ramené au nombre de membres (`reciprocal_scale`)
//!     donne un premier index ; à partir de lui, la première membre qui n'est
//!     pas connectée (UDP), et, si le groupe compte une membre qui dit un
//!     processeur (SO_INCOMING_CPU ; un compte tenu comme Linux, voir
//!     `Groupe::processeurs`), la première qui dit celui qui cherche, sinon
//!     la première trouvée.
//!
//! L'ORDRE des membres est celui de Linux, qu'un programme voit (son index) :
//! chaque nouvelle à la fin ; une qui part est remplacée par la dernière
//! (`socks[i] = socks[n - 1]`, mesuré, sonde c10f du lot 6 des soldes).
//!
//! Comment une socket entre dans un groupe, et en sort : c'est son protocole
//! qui le dit (ports.rs pour UDP, ports_tcp.rs pour TCP, idents.rs pour
//! ping), comme chez Linux, où chaque protocole appelle `reuseport_alloc`,
//! `reuseport_add_sock` et `reuseport_detach_sock` à sa façon. Ici, les
//! opérations elles-mêmes, et le choix.
//!
//! Choix de conception : les groupes de chaque protocole dans sa table (une
//! liste de groupes, chacun la liste des NUMÉROS de ses sockets), sous le
//! verrou de la table. Linux attache le groupe à la socket (`sk_reuseport_cb`)
//! et le protège d'un verrou global (`reuseport_lock`), pris après celui de
//! la table du protocole : notre verrou de table fait les deux, ce qui rend
//! atomiques, comme chez Linux, la vérification des conflits d'un `bind` et
//! l'entrée dans le groupe. Une socket sans port (un programme posé avant
//! `bind`) a son groupe dans la table de son protocole, sans entrée de port.
//! Options écartées : un pointeur vers le groupe dans chaque socket (le
//! noyau garderait un verrou de plus à prendre dans le bon ordre, pour
//! chaque paquet) ; un numéro de groupe dans chaque entrée de la table (une
//! socket sans port n'en a pas). Les groupes se trouvent en parcourant la
//! liste, comme les entrées des tables : quelques dizaines de sockets.
//!
//! Ce que nous n'avons pas : les programmes d'eBPF (BPF_PROG_TYPE_SK_REUSEPORT,
//! l'appel `bpf` n'existe pas ici), donc ni la migration des requêtes d'une
//! écoute fermée (`tcp_migrate_req`, 0 par défaut, ou un programme eBPF :
//! les « sockets fermées » d'un groupe, `num_closed_socks`, n'existent pas
//! sans elles), ni le groupe vu par un programme (`reuseport_id`). La
//! limite de Linux, 32 768 sockets par groupe (`reuseport_grow`, des index de
//! 16 bits), est au-delà de celle de nos tables.

use alloc::vec::Vec;
use faillible::VecFaillible;

/// Un groupe : ses sockets, dans l'ordre de Linux, et ce qu'il garde.
pub struct Groupe<P> {
    membres: Vec<u64>,
    /// SO_ATTACH_REUSEPORT_CBPF : le programme de BPF classique du groupe,
    /// posé par l'une de ses membres, pour toutes.
    programme: Option<P>,
    /// Une membre s'est connectée (`has_conns`, UDP) : la recherche d'UDP ne
    /// rend plus aussitôt la membre choisie (ports.rs). Jamais remis à faux.
    connexions: bool,
    /// Le compte des membres qui disent un processeur (`incoming_cpu`) : un de plus pour
    /// chacune qui en dit un à son entrée, un de moins pour chacune qui en dit un à sa sortie,
    /// et SO_INCOMING_CPU qui passe de -1 à un processeur ou l'inverse (`processeur_change`).
    /// Pas un processeur que la réception change (`sk_incoming_cpu_update`, une membre UDP
    /// connectée) : le compte peut alors dire autre chose que les membres, et même repasser
    /// sous 0 (un `u16` qui tourne, comme celui de Linux) ; le choix le suit quand même
    /// (mesuré : sonde r4c de la relecture du lot 6 des soldes).
    processeurs: u16,
}

/// Les groupes d'un protocole.
pub struct Groupes<P> {
    groupes: Vec<Groupe<P>>,
}

/// Pourquoi une opération est refusée.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// ENOMEM : plus de mémoire pour un groupe.
    Memoire,
    /// EBUSY : la socket est déjà dans un groupe d'autres.
    Occupe,
    /// EINVAL.
    Invalide,
    /// ENOENT : pas de programme à retirer.
    Absent,
}

/// Ce que sait une recherche de socket pour choisir dans un groupe.
pub struct Choix<'a, T, P> {
    /// Le processeur qui cherche (`raw_smp_processor_id`).
    pub ici: i32,
    /// Le processeur que dit une socket (SO_INCOMING_CPU, -1 : aucun).
    pub processeur: &'a dyn Fn(&T) -> i32,
    /// Le hachage du flux (`udp_ehashfn`, `inet_ehashfn`), calculé seulement
    /// s'il sert.
    pub hachage: &'a dyn Fn() -> u32,
    /// Le programme d'un groupe passé sur le paquet : l'index qu'il rend.
    /// None : la recherche n'a pas de paquet (celle d'une erreur ICMP,
    /// `__udp4_lib_err` : le hachage seul).
    pub programme: Option<&'a dyn Fn(&P) -> u32>,
}

impl<T, P> Choix<'_, T, P> {
    /// La socket `o` dit-elle le processeur qui cherche ? Une recherche lui
    /// donne un point de plus (`compute_score`).
    pub fn ici(&self, o: &T) -> bool {
        (self.processeur)(o) == self.ici
    }
}

impl<P> Default for Groupes<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Groupes<P> {
    /// Aucun groupe (rien n'est alloué avant le premier).
    pub const fn new() -> Groupes<P> {
        Groupes { groupes: Vec::new() }
    }

    fn ou(&self, numero: u64) -> Option<usize> {
        self.groupes.iter().position(|g| g.membres.contains(&numero))
    }

    /// La socket `numero` a-t-elle un groupe (`sk_reuseport_cb`) ?
    pub fn a_un_groupe(&self, numero: u64) -> bool {
        self.ou(numero).is_some()
    }

    /// Le groupe de la socket `numero` a-t-il eu une membre connectée
    /// (`reuseport_has_conns`) ?
    pub fn connexions(&self, numero: u64) -> bool {
        self.ou(numero).is_some_and(|i| self.groupes[i].connexions)
    }

    /// `reuseport_alloc` : un groupe pour `numero` seule ; si elle en a déjà
    /// un, elle le garde (un programme posé avant `bind` reste au groupe que
    /// `bind` ou `listen` lui fait).
    /// `dit` : la socket dit un processeur (SO_INCOMING_CPU), compté.
    pub fn allouer(&mut self, numero: u64, dit: bool) -> Result<(), Refus> {
        if self.a_un_groupe(numero) {
            return Ok(());
        }
        let mut membres = Vec::new();
        membres.ajouter(numero).map_err(|_| Refus::Memoire)?;
        self.groupes.ajouter(Groupe { membres, programme: None, connexions: false, processeurs: dit as u16 }).map_err(|_| Refus::Memoire)
    }

    /// `reuseport_add_sock` : `numero` entre dans le groupe d'`autre` (fait
    /// pour elle si elle n'en a pas : SO_REUSEPORT posé après son `bind`), à
    /// la fin. Le groupe qu'avait `numero`, elle seule, disparaît, et son
    /// programme avec lui (mesuré : deux sockets avec SO_REUSEADDR, la
    /// seconde avec son programme d'avant `bind` ; c'est celui de la première
    /// qui choisit) ; un groupe à plusieurs, EBUSY. `dit`, `dit_autre` : l'une et
    /// l'autre disent un processeur (voir `allouer`).
    pub fn ajouter(&mut self, numero: u64, dit: bool, autre: u64, dit_autre: bool) -> Result<(), Refus> {
        self.allouer(autre, dit_autre)?;
        let ancien = self.ou(numero);
        if let Some(a) = ancien
            && self.groupes[a].membres.len() != 1
        {
            return Err(Refus::Occupe);
        }
        let Some(g) = self.ou(autre) else { return Err(Refus::Memoire) };
        if ancien == Some(g) {
            return Ok(());
        }
        self.groupes[g].membres.ajouter(numero).map_err(|_| Refus::Memoire)?;
        self.groupes[g].processeurs = self.groupes[g].processeurs.wrapping_add(dit as u16);
        if let Some(a) = ancien {
            self.groupes.swap_remove(a);
        }
        Ok(())
    }

    /// `reuseport_detach_sock` : `numero` quitte son groupe, et la dernière
    /// membre prend sa place ; vide, le groupe disparaît, avec son programme.
    /// `dit` : elle dit un processeur maintenant (`reuseport_put_incoming_cpu`).
    pub fn detacher(&mut self, numero: u64, dit: bool) {
        let Some(i) = self.ou(numero) else { return };
        let g = &mut self.groupes[i];
        if let Some(k) = g.membres.iter().position(|&m| m == numero) {
            g.membres.swap_remove(k);
            g.processeurs = g.processeurs.wrapping_sub(dit as u16);
        }
        if g.membres.is_empty() {
            self.groupes.swap_remove(i);
        }
    }

    /// SO_INCOMING_CPU de `numero` passe de `ancien` à `nouveau` (disent-ils un
    /// processeur ?) : le compte de son groupe le suit
    /// (`reuseport_update_incoming_cpu`).
    pub fn processeur_change(&mut self, numero: u64, ancien: bool, nouveau: bool) {
        if let Some(i) = self.ou(numero) {
            let g = &mut self.groupes[i];
            g.processeurs = g.processeurs.wrapping_add(nouveau as u16).wrapping_sub(ancien as u16);
        }
    }

    /// `reuseport_has_conns_set` : une membre du groupe de `numero` se
    /// connecte.
    pub fn connectee(&mut self, numero: u64) {
        if let Some(i) = self.ou(numero) {
            self.groupes[i].connexions = true;
        }
    }

    /// `reuseport_attach_prog` : pose `programme` sur le groupe de `numero`,
    /// et rend l'ancien. `hachee` : la socket est dans la table de son
    /// protocole (le `sk_unhashed` de Linux, faux : une socket UDP ou de ping
    /// liée, une écoute ou une connexion TCP) ; sinon, elle doit avoir
    /// SO_REUSEPORT (EINVAL), et un groupe lui est fait si elle n'en a pas ;
    /// dans la table sans groupe : EINVAL. `dit` : elle dit un processeur.
    pub fn attacher_programme(&mut self, numero: u64, programme: P, hachee: bool, reuseport: bool, dit: bool)
                              -> Result<Option<P>, Refus> {
        if !hachee {
            if !reuseport {
                return Err(Refus::Invalide);
            }
            self.allouer(numero, dit)?;
        }
        let Some(i) = self.ou(numero) else { return Err(Refus::Invalide) };
        Ok(self.groupes[i].programme.replace(programme))
    }

    /// `reuseport_detach_prog` : retire le programme du groupe de `numero`
    /// et le rend. Sans groupe : ENOENT avec SO_REUSEPORT, EINVAL sans ; sans
    /// programme, ENOENT.
    pub fn detacher_programme(&mut self, numero: u64, reuseport: bool) -> Result<P, Refus> {
        let Some(i) = self.ou(numero) else {
            return Err(if reuseport { Refus::Absent } else { Refus::Invalide });
        };
        self.groupes[i].programme.take().ok_or(Refus::Absent)
    }

    /// `reuseport_select_sock` : la membre du groupe de `numero` qui reçoit
    /// (voir plus haut). `valide` : une membre peut-elle être choisie par le
    /// hachage (pas connectée : `TCP_ESTABLISHED`) ; `processeur` : celui
    /// qu'elle dit (SO_INCOMING_CPU). None : `numero` n'a pas de groupe. Le
    /// processeur ne compte que si le compte du groupe n'est pas nul
    /// (`processeurs`) : comme Linux, pas les membres d'aujourd'hui (une
    /// socket UDP déjà connectée entre dans le groupe d'une autre qui se lie
    /// après elle, y reçoit, ce qui change son processeur sans le compte, puis
    /// `connect(AF_UNSPEC)` l'y laisse).
    pub fn choisir<T>(&self, numero: u64, c: &Choix<T, P>, valide: impl Fn(u64) -> bool, processeur: impl Fn(u64) -> i32)
                      -> Option<u64> {
        let g = &self.groupes[self.ou(numero)?];
        if let (Some(p), Some(executer)) = (&g.programme, c.programme)
            && let Some(&m) = g.membres.get(executer(p) as usize)
        {
            return Some(m);
        }
        // `reuseport_select_sock_by_hash`.
        let n = g.membres.len();
        let depart = ((((c.hachage)() as u64) * n as u64) >> 32) as usize;
        let par_processeur = g.processeurs != 0;
        let mut premiere = None;
        for k in 0..n {
            let m = g.membres[(depart + k) % n];
            if valide(m) {
                if !par_processeur || processeur(m) == c.ici {
                    return Some(m);
                }
                premiere = premiere.or(Some(m));
            }
        }
        premiere
    }
}
