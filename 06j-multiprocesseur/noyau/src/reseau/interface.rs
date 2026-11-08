//! Les interfaces réseau (la `net_device` de Linux) : ce que la pile voit
//! d'une carte.
//!
//! Une interface a un nom (`eth0`), un numéro (son `ifindex`, à partir de
//! 1), une adresse MAC, une MTU (la plus grande charge d'une trame : 1500
//! octets pour Ethernet), l'état de son lien, ses compteurs (ceux que montre
//! /proc/net/dev), et son matériel, qui sait émettre une trame et faire le
//! travail de sa réception (le `poll` de NAPI). Les interfaces sont faites
//! au démarrage, dans une table fixe, et ne disparaissent pas (pas de carte
//! retirée à chaud) : chacun les tient par une référence `'static`.
//!
//! Le matériel est un `enum` plutôt qu'un trait (les `net_device_ops` de
//! Linux sont une table de fonctions) : il n'y en a qu'une poignée, et le
//! `match` dit en un endroit ce que fait chacun.

use super::paquet::Paquet;
use super::virtio_net::{self, Carte};
use crate::faillible;
use crate::verrou::Verrou;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Le matériel derrière une interface.
pub enum Materiel {
    /// L'interface de boucle (boucle.rs) : pas de matériel, une file.
    Boucle,
    VirtioNet(&'static Carte),
}

/// Les compteurs d'une interface (les `rtnl_link_stats64` de Linux), ceux
/// que montre /proc/net/dev.
#[derive(Default)]
pub struct Compteurs {
    pub recus: AtomicU64,
    pub octets_recus: AtomicU64,
    pub jetes_reception: AtomicU64,
    pub emis: AtomicU64,
    pub octets_emis: AtomicU64,
    pub jetes_emission: AtomicU64,
}

impl Compteurs {
    pub fn compter(compteur: &AtomicU64, n: u64) {
        compteur.fetch_add(n, Ordering::Relaxed);
    }
}

pub struct Interface {
    pub nom: &'static str,
    pub index: u32,
    pub mac: [u8; 6],
    /// La MTU, que le DHCP peut baisser (`changer_mtu`), et la plus grande
    /// que la carte accepte (celle de sa création).
    mtu: AtomicU32,
    mtu_max: u32,
    /// Le lien (le « carrier » de Linux) : le câble est-il branché ?
    pub lien: AtomicBool,
    pub compteurs: Compteurs,
    pub materiel: Materiel,
}

/// Le nombre maximal d'interfaces.
const MAX: usize = 4;

/// Les interfaces, dans l'ordre de leur numéro : `lo` d'abord (1), puis
/// les cartes (`eth0` : 2), comme chez Linux.
static INTERFACES: Verrou<[Option<&'static Interface>; MAX]> = Verrou::new([None; MAX]);

/// Ajoute une interface ; son numéro est le suivant. None : la table est
/// pleine, ou le tas.
pub fn ajouter(nom: &'static str, mac: [u8; 6], mtu: u32, lien: bool, materiel: Materiel) -> Option<&'static Interface> {
    let mut t = INTERFACES.verrouiller();
    let place = t.iter().position(Option::is_none)?;
    let i = faillible::boite(Interface {
        nom, index: place as u32 + 1, mac, mtu: AtomicU32::new(mtu), mtu_max: mtu, lien: AtomicBool::new(lien),
        compteurs: Compteurs::default(), materiel,
    }).ok()?;
    let i: &'static Interface = alloc::boxed::Box::leak(i);
    t[place] = Some(i);
    Some(i)
}

/// L'interface de numéro `index`.
pub fn par_index(index: u32) -> Option<&'static Interface> {
    let t = INTERFACES.verrouiller();
    t.get((index as usize).checked_sub(1)?).copied().flatten()
}

/// La première carte (la première interface qui n'est pas `lo`) : `eth0`,
/// que configure le DHCP.
pub fn premiere_carte() -> Option<&'static Interface> {
    INTERFACES.verrouiller().iter().flatten().find(|i| !i.boucle()).copied()
}

/// Une interface autre que `lo` a-t-elle son lien (le détecteur
/// d'interblocage : une réponse peut encore venir du dehors) ?
pub fn une_carte_a_son_lien() -> bool {
    INTERFACES.verrouiller().iter().flatten().any(|i| !i.boucle() && i.lien.load(Ordering::Relaxed))
}

impl Interface {
    pub fn mtu(&self) -> u32 {
        self.mtu.load(Ordering::Relaxed)
    }

    /// Change la MTU (le `dev_set_mtu` de Linux) : de 68 (le plus petit
    /// paquet qu'IPv4 doit faire passer, ETH_MIN_MTU) à celle de la carte.
    /// false : hors de ces bornes, rien ne change.
    pub fn changer_mtu(&self, mtu: u32) -> bool {
        if !(68..=self.mtu_max).contains(&mtu) {
            return false;
        }
        self.mtu.store(mtu, Ordering::Relaxed);
        true
    }

    /// Est-ce une interface de boucle (lo), plutôt qu'une carte ?
    pub fn boucle(&self) -> bool {
        matches!(self.materiel, Materiel::Boucle)
    }

    /// Émet la trame `p` (le `dev_queue_xmit` de Linux), dans le contexte
    /// de qui l'envoie. Lien coupé, ou file d'émission pleine : jetée, et
    /// comptée.
    pub fn emettre(&self, p: Paquet) {
        if !self.lien.load(Ordering::Relaxed) {
            Compteurs::compter(&self.compteurs.jetes_emission, 1);
            return;
        }
        let longueur = p.longueur() as u64;
        let parti = match self.materiel {
            // lo compte elle-même (boucle.rs : ses deux sens à la fois).
            Materiel::Boucle => return super::boucle::emettre(self, p),
            Materiel::VirtioNet(c) => c.emettre(p),
        };
        if parti {
            Compteurs::compter(&self.compteurs.emis, 1);
            Compteurs::compter(&self.compteurs.octets_emis, longueur);
        } else {
            Compteurs::compter(&self.compteurs.jetes_emission, 1);
        }
    }

    /// Le travail de réception et d'émission de l'interface (le `poll` de
    /// NAPI), dans la tâche du réseau : au plus `budget` trames reçues,
    /// livrées à `super::recevoir`. Rend vrai s'il en reste.
    pub fn travailler(&'static self, budget: usize) -> bool {
        match self.materiel {
            Materiel::Boucle => super::boucle::travailler(self, budget),
            Materiel::VirtioNet(c) => c.travailler(self, budget),
        }
    }
}

/// Le matériel d'une interface, pour un message.
pub fn decrire(i: &Interface) -> impl core::fmt::Display + '_ {
    struct D<'a>(&'a Interface);
    impl core::fmt::Display for D<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            match self.0.materiel {
                Materiel::Boucle => write!(f, "boucle locale"),
                Materiel::VirtioNet(_) => write!(f, "virtio-net {}", virtio_net::Mac(self.0.mac)),
            }
        }
    }
    D(i)
}
