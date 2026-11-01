//! Le pilote de la carte réseau virtio-net (spécification de virtio 1.2,
//! section 5.1 ; drivers/net/virtio_net.c de Linux).
//!
//! La carte est une fonction PCI de fabricant 0x1af4, modèle 0x1000
//! (« transitionnelle », dont le sous-système dit la sorte : 1 = réseau) ou
//! 0x1041 (moderne), mise en service par le transport de virtio.rs. Sa zone
//! de configuration porte son adresse MAC (fonctionnalité VIRTIO_NET_F_MAC)
//! et l'état de son lien (VIRTIO_NET_F_STATUS : le câble branché ou non,
//! que le moniteur de QEMU change par `set_link`). Un changement du lien
//! lève l'interruption de configuration (l'entrée 0 de la table MSI-X) ;
//! comme le « linkwatch » de Linux, son gestionnaire ne fait que le
//! signaler à la tâche du réseau, qui relit l'état et le dit.
//!
//! Les fonctionnalités : on n'accepte que VERSION_1 (le transport moderne),
//! MAC, STATUS et EVENT_IDX (moins d'interruptions, ce que négocie Linux).
//! Jamais une offre GUEST_* ou HOST_* (le calcul des sommes de contrôle et
//! le découpage des gros paquets par la carte) : la pile fait tout en
//! logiciel. Une seule carte est mise en service, la première : `eth0`.

use crate::pci::{self, Fonction};
use crate::virtio::{self, Virtio};
use crate::{irq, verrou::Verrou};
use core::sync::atomic::{AtomicBool, Ordering};

// Les fonctionnalités de virtio-net (include/uapi/linux/virtio_net.h).
const F_MAC: u32 = 5;
const F_STATUS: u32 = 16;
/// Dans le champ `status` de la configuration : le lien est actif.
const LIEN_ACTIF: u16 = 1;
/// La position du champ `status` dans la configuration (après les 6
/// octets de la MAC).
const STATUS: u64 = 6;
/// L'entrée MSI-X des interruptions de configuration (Linux prend aussi la
/// première : `vp_request_msix_vectors`).
const ENTREE_CONFIGURATION: u16 = 0;

/// La carte en service.
pub struct Carte {
    pub adresse: pci::Adresse,
    virtio: Virtio,
    pub mac: [u8; 6],
    /// L'état du lien, tel que dit la dernière fois.
    lien: AtomicBool,
}

/// La carte `eth0`, une fois en service (pour toujours : on ne retire pas
/// une carte).
static CARTE: Verrou<Option<&'static Carte>> = Verrou::new(None);

/// Est-ce une carte réseau virtio ?
fn est_virtio_net(f: &Fonction) -> bool {
    let e = &f.entete;
    let sous_systeme = match e.genre {
        formats::pci::Genre::Ordinaire { sous_systeme, .. } => sous_systeme,
        _ => return false,
    };
    e.vendeur == virtio::FABRICANT
        && (e.peripherique == virtio::MODERNE + virtio::SORTE_RESEAU
            || (e.peripherique == virtio::RESEAU_TRANSITIONNEL && sous_systeme == virtio::SORTE_RESEAU))
}

/// L'interruption de configuration : le dire à la tâche du réseau.
fn interruption_configuration(_: usize) {
    super::tache::signaler(super::tache::CONFIGURATION);
}

/// Les noms des fonctionnalités négociées, pour le journal.
fn nommer(v: &Virtio) -> impl core::fmt::Display + '_ {
    struct Noms<'a>(&'a Virtio);
    impl core::fmt::Display for Noms<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            let mut premier = true;
            for (bit, nom) in [(virtio::F_VERSION_1, "VERSION_1"), (F_MAC, "MAC"), (F_STATUS, "STATUS"), (virtio::F_EVENT_IDX, "EVENT_IDX")] {
                if self.0.a(bit) {
                    write!(f, "{}{}", if premier { "" } else { " " }, nom)?;
                    premier = false;
                }
            }
            Ok(())
        }
    }
    Noms(v)
}

/// Met en service la première carte virtio-net du bus, et le dit.
pub fn sonder() {
    let Some(f) = pci::fonctions().iter().find(|f| est_virtio_net(f)) else {
        return afficherln!("[virtio] pas de carte reseau virtio.");
    };
    match ouvrir(f) {
        Ok(c) => {
            afficherln!("[virtio] {} : reseau, fonctionnalites {}, {} files.", c.adresse, nommer(&c.virtio), c.virtio.nb_files());
            afficherln!("[reseau] eth0 : virtio-net {}, lien {}.", Mac(c.mac),
                        if c.lien.load(Ordering::Relaxed) { "actif" } else { "coupe" });
            *CARTE.verrouiller() = Some(c);
        }
        Err(e) => afficherln!("[virtio] {} : {} : carte laissee eteinte.", f.adresse, e),
    }
}

/// La poignée de main, la configuration lue, l'interruption de
/// configuration branchée, DRIVER_OK.
fn ouvrir(f: &Fonction) -> Result<&'static Carte, virtio::Refus> {
    let mut v = Virtio::ouvrir(f)?;
    let voulues = 1 << virtio::F_VERSION_1 | 1 << virtio::F_EVENT_IDX | 1 << F_MAC | 1 << F_STATUS;
    v.negocier(voulues)?;
    // Sans MAC donnée par la carte, Linux en tire une au hasard ; QEMU en
    // donne toujours une (52:54:00:12:34:56 par défaut).
    let mac = if v.a(F_MAC) {
        v.configuration(|c| core::array::from_fn(|i| c.octet(i as u64).unwrap_or(0)))
    } else {
        let mut m = [0u8; 6];
        crate::aleatoire::remplir(&mut m);
        // Une adresse « administrée localement » (bit 1), pas de groupe
        // (bit 0) : le `eth_random_addr` de Linux.
        m[0] = m[0] & !1 | 2;
        m
    };
    let lien = !v.a(F_STATUS) || v.configuration(|c| c.mot16(STATUS)).is_some_and(|s| s & LIEN_ACTIF != 0);
    let vecteur = irq::allouer(interruption_configuration, 0).ok_or_else(|| v.echouer(virtio::Refus::Vecteur))?;
    v.msix.programmer(ENTREE_CONFIGURATION, vecteur);
    if let Err(e) = v.vecteur_de_configuration(ENTREE_CONFIGURATION) {
        irq::liberer(vecteur);
        return Err(v.echouer(e));
    }
    v.demarrer();
    let carte = alloc::boxed::Box::new(Carte { adresse: f.adresse, virtio: v, mac, lien: AtomicBool::new(lien) });
    Ok(alloc::boxed::Box::leak(carte))
}

/// Une interruption de configuration est arrivée : relire le lien, et dire
/// s'il a changé (le `virtnet_config_changed_work` de Linux, puis le
/// linkwatch). Dans la tâche du réseau.
pub fn configuration_changee() {
    let Some(c) = *CARTE.verrouiller() else { return };
    if !c.virtio.a(F_STATUS) {
        return;
    }
    let actif = c.virtio.configuration(|l| l.mot16(STATUS)).is_some_and(|s| s & LIEN_ACTIF != 0);
    if c.lien.swap(actif, Ordering::Relaxed) != actif {
        afficherln!("[reseau] eth0 : lien {}.", if actif { "retabli" } else { "coupe" });
    }
}

/// Une adresse MAC, affichée comme `ip link` : 52:54:00:12:34:56.
pub struct Mac(pub [u8; 6]);

impl core::fmt::Display for Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}
