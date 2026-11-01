//! La table des voisins (le `neighbour` de Linux, net/core/neighbour.c, et
//! ses réglages pour ARP, net/ipv4/arp.c) : l'adresse matérielle de chaque
//! machine du réseau local à qui l'on parle, et ce qu'on sait d'elle.
//!
//! Pour envoyer un paquet IPv4 à une machine du réseau (la destination, ou
//! la passerelle), il faut son adresse Ethernet : ARP la demande à tout le
//! réseau (« qui a 10.0.2.2 ? »), la machine répond. Une adresse apprise
//! n'est pas crue pour toujours : la machine peut changer de carte, ou
//! disparaître. Les ÉTATS de Linux :
//!   - INCOMPLET : on a demandé, pas de réponse encore ; les paquets
//!     attendent dans la file de l'entrée (212 992 octets de taille vraie au
//!     plus, `unres_qlen_bytes` : les plus anciens jetés). Trois requêtes en
//!     diffusion, une par seconde (`mcast_probes`, `retrans_time`), puis
//!     ÉCHEC ;
//!   - JOIGNABLE : une réponse est venue, l'adresse est sûre pendant un
//!     temps tiré entre 15 et 45 s (`base_reachable_time` de 30 s, entre la
//!     moitié et une fois et demie : `neigh_rand_reach_time`) ;
//!   - PÉRIMÉ (« stale ») : ce temps est passé ; l'adresse sert encore, mais
//!     le premier envoi la fait vérifier : RETARDÉ (« delay », 5 s,
//!     `delay_first_probe_time`, le temps qu'une confirmation arrive
//!     d'ailleurs), puis SONDÉ (« probe ») : trois requêtes envoyées à
//!     l'adresse connue (`ucast_probes`), puis ÉCHEC ;
//!   - ÉCHEC : la file est jetée ; le prochain envoi recommence une
//!     résolution.
//! Ce qu'un message ARP apprend d'une machine (`apprendre`, les règles de
//! `__neigh_update`) : une requête qui nous vise crée ou met à jour
//! l'entrée de qui la pose (PÉRIMÉ, comme `neigh_event_ns`), ce qui évite
//! de lui redemander pour répondre ; tout autre message (une réponse, une
//! requête pour un autre, une annonce « gratuite ») ne fait que mettre à
//! jour une entrée qui existe (`arp_accept` à 0) : JOIGNABLE pour une
//! réponse qui nous était adressée, PÉRIMÉ sinon. Une adresse différente
//! de celle qu'on connaît ne remplace celle-ci qu'une seconde après la
//! dernière mise à jour (le `locktime` : « Taking the first reply prevents
//! arp trashing and chooses the fastest router »), ou par une annonce
//! gratuite ; la même adresse dite PÉRIMÉE ne change pas l'état.
//!
//! La table a une taille fixe (64 entrées, le `gc_thresh3` de Linux en plus
//! petit), faite d'avance : parler à une machine nouvelle ne prend pas de
//! mémoire. Pleine, elle reprend la plus ancienne entrée qui n'attend rien
//! (le `neigh_forced_gc`).
//!
//! Le temps est donné en nanosecondes, le hasard en argument. Les actions
//! (envoyer un paquet, une requête) sont rendues à l'appelant, qui les
//! fait : la table ne sait rien des cartes. `T` est le paquet du noyau.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

const SECONDE: u64 = 1_000_000_000;
/// Les réglages de Linux pour ARP.
pub const RETRANSMISSION: u64 = SECONDE;
pub const BASE_JOIGNABLE: u64 = 30 * SECONDE;
pub const DELAI_PREMIERE_SONDE: u64 = 5 * SECONDE;
pub const SONDES_DIFFUSEES: u32 = 3;
pub const SONDES_UNICAST: u32 = 3;
pub const FILE_OCTETS: usize = 212_992;
/// Le `locktime` d'ARP.
pub const VERROUILLAGE: u64 = SECONDE;
/// Le temps joignable est tiré de nouveau tous les 300 s
/// (`neigh_periodic_work`).
const RETIRAGE: u64 = 300 * SECONDE;
/// La taille de la table.
pub const MAX: usize = 64;

/// L'état d'une entrée (les NUD_* de Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    Incomplet,
    Joignable,
    Perime,
    Retarde,
    Sonde,
    Echec,
}

impl Etat {
    /// L'adresse matérielle est-elle connue (NUD_VALID, sauf NOARP et
    /// PERMANENT, que nous n'avons pas) ?
    pub fn valide(self) -> bool {
        matches!(self, Etat::Joignable | Etat::Perime | Etat::Retarde | Etat::Sonde)
    }
}

/// Une entrée.
pub struct Voisin<T> {
    pub interface: u32,
    pub adresse: [u8; 4],
    pub mac: [u8; 6],
    pub etat: Etat,
    /// L'échéance de son minuteur (None : aucun, comme PÉRIMÉ ou ÉCHEC).
    echeance: Option<u64>,
    /// Le nombre de requêtes déjà comptées (`probes` : il commence à
    /// SONDES_UNICAST pour INCOMPLET, comme chez Linux, et le maximum est
    /// alors unicast + diffusées).
    sondes: u32,
    /// La dernière confirmation (une réponse), le dernier envoi, et la
    /// dernière mise à jour qui a changé l'état ou l'adresse (`updated`).
    confirme: u64,
    utilise: u64,
    mis_a_jour: u64,
    attente: VecDeque<(T, usize)>,
    octets: usize,
}

/// Ce que l'appelant doit faire.
pub enum Action<T> {
    /// Envoyer `paquet` par `interface`, à l'adresse matérielle `mac`.
    Envoyer { interface: u32, mac: [u8; 6], paquet: T },
    /// Envoyer une requête ARP pour `cible` par `interface` : en diffusion
    /// (`mac` None), ou à l'adresse connue (une sonde).
    Requete { interface: u32, cible: [u8; 4], mac: Option<[u8; 6]> },
    /// Le paquet est jeté : la file était pleine, ou le voisin ne répond
    /// pas (`echec` : à dire à son émetteur, l'ICMP « hôte injoignable »).
    Jeter { paquet: T, echec: bool },
}

/// Ce que dit un message ARP de son émetteur (voir l'en-tête).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appris {
    /// Une requête pour une de nos adresses (`neigh_event_ns`) : l'entrée
    /// créée s'il le faut, PÉRIMÉE, l'adresse remplacée.
    RequetePourNous,
    /// Un autre message : seulement une entrée qui existe. `joignable` :
    /// une réponse qui nous était adressée (pas diffusée) ; `gratuit` : une
    /// annonce de la machine elle-même (sa propre adresse demandée), qui
    /// remplace l'adresse sans attendre le `locktime`.
    Message { joignable: bool, gratuit: bool },
}

/// La table.
pub struct Table<T> {
    voisins: Vec<Voisin<T>>,
    /// Le temps joignable en cours, et quand le tirer de nouveau.
    joignable: u64,
    retirage: u64,
}

/// Le temps joignable, tiré entre la moitié et une fois et demie de la base.
fn tirer(hasard: u64) -> u64 {
    BASE_JOIGNABLE / 2 + hasard % BASE_JOIGNABLE
}

impl<T> Table<T> {
    /// Une table vide, sa place réservée. None : plus de mémoire.
    pub fn new(hasard: u64, maintenant: u64) -> Option<Table<T>> {
        let mut voisins = Vec::new();
        voisins.try_reserve_exact(MAX).ok()?;
        Some(Table { voisins, joignable: tirer(hasard), retirage: maintenant + RETIRAGE })
    }

    /// Le temps joignable en cours.
    pub fn temps_joignable(&self) -> u64 {
        self.joignable
    }

    fn trouver(&self, interface: u32, adresse: [u8; 4]) -> Option<usize> {
        self.voisins.iter().position(|v| v.interface == interface && v.adresse == adresse)
    }

    /// Une entrée neuve pour `adresse`, à la place d'une ancienne si la
    /// table est pleine. None : aucune ne peut être reprise.
    fn creer(&mut self, interface: u32, adresse: [u8; 4], maintenant: u64) -> Option<usize> {
        let v = Voisin {
            interface, adresse, mac: [0; 6], etat: Etat::Echec, echeance: None, sondes: 0, confirme: 0, utilise: maintenant,
            mis_a_jour: maintenant, attente: VecDeque::new(), octets: 0,
        };
        if self.voisins.len() < MAX {
            self.voisins.push(v);
            return Some(self.voisins.len() - 1);
        }
        let i = self.voisins.iter().enumerate().filter(|(_, v)| v.attente.is_empty()).min_by_key(|(_, v)| v.utilise).map(|(i, _)| i)?;
        self.voisins[i] = v;
        Some(i)
    }

    /// Les entrées, pour /proc/net/arp.
    pub fn voisins(&self) -> impl Iterator<Item = &Voisin<T>> {
        self.voisins.iter()
    }

    /// L'entrée de `adresse`.
    pub fn voisin(&self, interface: u32, adresse: [u8; 4]) -> Option<&Voisin<T>> {
        self.trouver(interface, adresse).map(|i| &self.voisins[i])
    }

    /// La prochaine échéance d'un minuteur.
    pub fn echeance(&self) -> Option<u64> {
        self.voisins.iter().filter_map(|v| v.echeance).min()
    }

    /// Envoyer `paquet` (de taille vraie `taille`) à `adresse`, par
    /// `interface` (le `neigh_event_send`, puis la sortie de Linux) : tout
    /// de suite si l'adresse matérielle est connue, sinon après la
    /// résolution. `confirmer` : l'appelant sait que la machine est là
    /// (MSG_CONFIRM, `dst_confirm_neigh`).
    pub fn envoyer(&mut self, interface: u32, adresse: [u8; 4], paquet: T, taille: usize, confirmer: bool, maintenant: u64,
                   faire: &mut impl FnMut(Action<T>)) {
        let i = match self.trouver(interface, adresse) {
            Some(i) => i,
            None => match self.creer(interface, adresse, maintenant) {
                Some(i) => i,
                None => return faire(Action::Jeter { paquet, echec: false }),
            },
        };
        let v = &mut self.voisins[i];
        v.utilise = maintenant;
        if confirmer && v.etat.valide() {
            v.confirme = maintenant;
        }
        match v.etat {
            Etat::Joignable | Etat::Retarde | Etat::Sonde => {
                return faire(Action::Envoyer { interface, mac: v.mac, paquet });
            }
            Etat::Perime => {
                v.etat = Etat::Retarde;
                v.echeance = Some(maintenant + DELAI_PREMIERE_SONDE);
                return faire(Action::Envoyer { interface, mac: v.mac, paquet });
            }
            Etat::Echec => {
                // Une nouvelle résolution : la première requête tout de suite.
                v.etat = Etat::Incomplet;
                v.sondes = SONDES_UNICAST + 1;
                v.echeance = Some(maintenant + RETRANSMISSION);
                faire(Action::Requete { interface, cible: adresse, mac: None });
            }
            Etat::Incomplet => {}
        }
        // INCOMPLET : dans la file, les plus anciens jetés s'il le faut.
        let v = &mut self.voisins[i];
        while v.octets + taille > FILE_OCTETS {
            let Some((ancien, t)) = v.attente.pop_front() else { break };
            v.octets -= t;
            faire(Action::Jeter { paquet: ancien, echec: false });
        }
        if v.attente.try_reserve(1).is_err() {
            return faire(Action::Jeter { paquet, echec: false });
        }
        v.attente.push_back((paquet, taille));
        v.octets += taille;
    }

    /// L'adresse matérielle `mac` apprise pour `adresse` par un message ARP
    /// (`appris`, voir l'en-tête), comme `__neigh_update` : une adresse
    /// différente d'une adresse valide n'est prise qu'avec le droit de la
    /// remplacer (sinon rien ne change) ; la même, annoncée PÉRIMÉE, laisse
    /// l'état ; une adresse neuve qui n'est pas confirmée ne l'est pas non
    /// plus (sa dernière confirmation reculée de deux temps de base, comme
    /// Linux) ; une entrée qui attendait son adresse envoie sa file.
    pub fn apprendre(&mut self, interface: u32, adresse: [u8; 4], mac: [u8; 6], appris: Appris, maintenant: u64,
                     faire: &mut impl FnMut(Action<T>)) {
        let i = match (self.trouver(interface, adresse), appris) {
            (Some(i), _) => i,
            (None, Appris::RequetePourNous) => match self.creer(interface, adresse, maintenant) {
                Some(i) => i,
                None => return,
            },
            (None, Appris::Message { .. }) => return,
        };
        let joignable = self.joignable;
        let v = &mut self.voisins[i];
        let (mut nouveau, remplacer) = match appris {
            Appris::RequetePourNous => (Etat::Perime, true),
            Appris::Message { joignable, gratuit } => (
                if joignable { Etat::Joignable } else { Etat::Perime },
                gratuit || maintenant > v.mis_a_jour + VERROUILLAGE,
            ),
        };
        let ancien = v.etat;
        let meme = ancien.valide() && v.mac == mac;
        if nouveau == Etat::Joignable {
            v.confirme = maintenant;
        }
        if ancien.valide() {
            if !meme && !remplacer {
                return;
            }
            if meme && nouveau == Etat::Perime {
                nouveau = ancien;
            }
        }
        if nouveau != ancien || !meme {
            v.mis_a_jour = maintenant;
        }
        if nouveau != ancien {
            v.etat = nouveau;
            v.echeance = (nouveau == Etat::Joignable).then_some(maintenant + joignable);
        }
        if !meme {
            v.mac = mac;
            if nouveau != Etat::Joignable {
                v.confirme = maintenant.saturating_sub(2 * BASE_JOIGNABLE);
            }
        }
        if !ancien.valide() {
            while let Some((paquet, _)) = v.attente.pop_front() {
                faire(Action::Envoyer { interface, mac, paquet });
            }
            v.octets = 0;
        }
    }

    /// Les minuteurs échus, dans l'ordre de `neigh_timer_handler`.
    pub fn temps(&mut self, maintenant: u64, hasard: u64, faire: &mut impl FnMut(Action<T>)) {
        if maintenant >= self.retirage {
            self.joignable = tirer(hasard);
            self.retirage = maintenant + RETIRAGE;
        }
        let joignable = self.joignable;
        for v in self.voisins.iter_mut() {
            let Some(e) = v.echeance else { continue };
            if maintenant < e {
                continue;
            }
            match v.etat {
                Etat::Joignable => {
                    if maintenant <= v.confirme + joignable {
                        v.echeance = Some(v.confirme + joignable);
                    } else if maintenant <= v.utilise + DELAI_PREMIERE_SONDE {
                        v.etat = Etat::Retarde;
                        v.echeance = Some(maintenant + DELAI_PREMIERE_SONDE);
                    } else {
                        v.etat = Etat::Perime;
                        v.echeance = None;
                    }
                    continue;
                }
                Etat::Retarde => {
                    if maintenant <= v.confirme + DELAI_PREMIERE_SONDE {
                        v.etat = Etat::Joignable;
                        v.echeance = Some(v.confirme + joignable);
                        continue;
                    }
                    v.etat = Etat::Sonde;
                    v.sondes = 0;
                }
                Etat::Incomplet | Etat::Sonde => {}
                Etat::Perime | Etat::Echec => {
                    v.echeance = None;
                    continue;
                }
            }
            // INCOMPLET ou SONDÉ : encore une requête, ou l'échec.
            let max = if v.etat == Etat::Sonde { SONDES_UNICAST } else { SONDES_UNICAST + SONDES_DIFFUSEES };
            if v.sondes >= max {
                v.etat = Etat::Echec;
                v.echeance = None;
                v.octets = 0;
                while let Some((paquet, _)) = v.attente.pop_front() {
                    faire(Action::Jeter { paquet, echec: true });
                }
                continue;
            }
            v.sondes += 1;
            v.echeance = Some(maintenant + RETRANSMISSION);
            let mac = (v.etat == Etat::Sonde).then_some(v.mac);
            faire(Action::Requete { interface: v.interface, cible: v.adresse, mac });
        }
    }
}
