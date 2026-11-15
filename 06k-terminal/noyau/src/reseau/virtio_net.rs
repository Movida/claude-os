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
//! MAC, STATUS, EVENT_IDX (moins d'interruptions, ce que négocie Linux), et
//! CTRL_VQ avec CTRL_RX (la file de contrôle et le filtre des adresses, plus
//! bas). Jamais une offre GUEST_* ou HOST_* (le calcul des sommes de
//! contrôle et le découpage des gros paquets par la carte) : la pile fait
//! tout en logiciel. Une seule carte est mise en service, la première :
//! `eth0`.
//!
//! LES FILES : une paire, la file 0 reçoit, la file 1 émet, chacune avec son
//! entrée MSI-X (1 et 2), comme Linux ; puis la file de contrôle (2), sans
//! interruption.
//!   - Réception : 256 tampons de 2 Kio (deux par page), tous confiés à la
//!     carte au départ. Sans VIRTIO_NET_F_MRG_RXBUF ni réception de gros
//!     paquets, une trame tient dans un tampon : 12 octets d'en-tête de
//!     virtio-net (VERSION_1), puis au plus 1518 octets de trame (les
//!     tampons « small » de Linux). Chaque trame est COPIÉE dans un paquet
//!     du tas, et le tampon rendu aussitôt à la carte (le « copybreak » de
//!     nombreux pilotes) : un tampon n'est jamais tenu par une file de
//!     socket. Option écartée : passer le tampon lui-même à la pile (le
//!     zéro-copie), qui demande de recycler les pages que les sockets
//!     gardent (le `page_pool` de Linux) ; à 1500 octets, la copie ne se
//!     mesurera pas.
//!   - Émission : 256 cases de 2 Kio ; une trame y est copiée derrière un
//!     en-tête de virtio-net nul (« pas de somme à calculer, pas de
//!     découpage »), et la case rendue quand la carte a fini. Les cases
//!     finies sont reprises à chaque émission (le `free_old_xmit` de
//!     Linux), sans interruption ; si l'anneau est plein, la trame attend
//!     dans une petite file (le « qdisc » de Linux, 1000 trames :
//!     `txqueuelen`), et l'interruption d'émission est rallumée pour que la
//!     tâche du réseau la vide quand des cases se libèrent.
//! Les interruptions des deux files ne font que couper les suivantes de
//! leur file et réveiller la tâche du réseau (NAPI) : `travailler` vide
//! l'anneau de réception par lots, livre les trames, rallume, et revérifie
//! (une trame arrivée entre les deux n'est pas perdue).
//!
//! LE FILTRE DES ADRESSES. Une carte remise à zéro laisse tout entrer (la
//! promiscuité de QEMU, `virtio_net_reset`) : chaque trame de
//! multidiffusion du réseau arrive jusqu'à IP, qui la jette si la machine
//! n'est pas du groupe. Avec CTRL_RX, le pilote le dit à la carte par sa
//! file de contrôle (une commande : une classe et un numéro, des données,
//! et la réponse que la carte écrit) : pas de promiscuité, pas « toute la
//! multidiffusion », puis la table de ses adresses (MAC_TABLE_SET) : aucune
//! adresse individuelle de plus que la sienne, et les adresses MAC des
//! groupes de l'interface (multidiffusion.rs, la liste `dev->mc`). La carte
//! laisse alors entrer sa propre adresse, la diffusion, et ces groupes ; le
//! reste ne coûte plus rien à la machine. C'est le `virtnet_rx_mode_work`
//! de Linux, que fait la tâche du réseau à chaque changement de la liste
//! (`tache::FILTRE`) : les trois commandes, l'une après l'autre, chacune
//! attendue en tournant sur l'anneau utilisé (QEMU l'a faite pendant
//! l'écriture de la notification), la file tenue par un verrou qui dort
//! (le `cvq_lock` de Linux : la tâche reste préemptible). Comme Linux, on
//! attend la réponse sans limite : une carte lente (une vraie, derrière
//! vDPA) n'est pas une carte morte.
//! Une liste plus longue que la page de commande (680 adresses) : « toute
//! la multidiffusion » (ALLMULTI), et une table sans groupe, ce que fait
//! un pilote dont la table de la carte déborde (QEMU lui-même passe à
//! toute la multidiffusion au-delà de 64 adresses). Options écartées :
//! rester en promiscuité (la pile trierait tout le réseau, et une vraie
//! carte en promiscuité reçoit aussi les trames des autres machines) ; une
//! table de hachage des adresses (le filtre de bien des cartes, que virtio
//! n'a pas). Sans CTRL_VLAN, la carte laisse passer tous les VLAN.

use super::interface::{self, Interface, Materiel};
use super::paquet::{Paquet, Proprietaire};
use crate::faillible::{self, FileFaillible, VecFaillible};
use crate::pci::{self, Fonction};
use crate::virtio::{self, Notifieur, Virtio};
use crate::virtqueue::{ECRIT_PAR_PERIPHERIQUE, Tampon, Virtqueue};
use crate::attente::Mutex;
use crate::{espace, irq, pages, verrou::Verrou};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

// Les fonctionnalités de virtio-net (include/uapi/linux/virtio_net.h).
const F_MAC: u32 = 5;
const F_STATUS: u32 = 16;
/// La file de contrôle, et les commandes du filtre (qui la demandent).
const F_CTRL_VQ: u32 = 17;
const F_CTRL_RX: u32 = 18;
/// Dans le champ `status` de la configuration : le lien est actif.
const LIEN_ACTIF: u16 = 1;
/// La position du champ `status` dans la configuration (après les 6
/// octets de la MAC).
const STATUS: u64 = 6;
/// Les entrées MSI-X : la configuration (Linux prend aussi la première,
/// `vp_request_msix_vectors`), puis une par file. Une carte qui n'en a que
/// deux : la configuration, puis une seule pour les deux files, comme le
/// repli de Linux (`vp_find_vqs`, « shared » : un vecteur pour toutes les
/// files) ; son gestionnaire fait le travail des deux. Moins de deux : la
/// carte reste éteinte ; Linux se replierait encore sur INTx, dont la
/// ligne se lit dans la table `_PRT` de l'ACPI (l'AML), que nous ne lisons
/// pas (avec les pilotes du vrai matériel).
const ENTREE_CONFIGURATION: u16 = 0;
const ENTREE_RECEPTION: u16 = 1;
const ENTREE_EMISSION: u16 = 2;
/// L'entrée des deux files, quand elles la partagent.
const ENTREE_FILES: u16 = 1;
/// Les numéros des files : la paire 0 (réception 0, émission 1).
const FILE_RECEPTION: u16 = 0;
const FILE_EMISSION: u16 = 1;
/// La taille de chaque file (celle de la carte de QEMU, et le plus que
/// tient une page de descripteurs).
const TAILLE_FILE: u16 = 256;
/// La file de contrôle : après la paire.
const FILE_CONTROLE: u16 = 2;
/// Sa taille, au plus (celle de QEMU) ; une commande y prend jusqu'à quatre
/// descripteurs (l'en-tête, deux tables, la réponse).
const TAILLE_CONTROLE: u16 = 64;
const DESCRIPTEURS_PAR_COMMANDE: usize = 4;
// Les commandes : la classe, puis le numéro (include/uapi/linux/virtio_net.h).
const CLASSE_RX: u8 = 0;
const RX_PROMISC: u8 = 0;
const RX_ALLMULTI: u8 = 1;
const CLASSE_MAC: u8 = 1;
const MAC_TABLE_SET: u8 = 0;
/// La réponse de la carte à une commande faite (VIRTIO_NET_OK).
const FAITE: u8 = 0;
// La page de commande : l'en-tête (`virtio_net_ctrl_hdr`, classe et numéro),
// la réponse (`virtio_net_ctrl_ack`), l'octet d'une commande RX (0 ou 1),
// puis les deux tables de MAC_TABLE_SET (`virtio_net_ctrl_mac` : un
// compte sur 32 bits petit-boutiste, puis les adresses) : celle des
// adresses individuelles (vide), puis celle des groupes.
const PAGE_ENTETE: u64 = 0;
const PAGE_REPONSE: u64 = 2;
const PAGE_OCTET: u64 = 3;
const PAGE_INDIVIDUELLES: u64 = 4;
const PAGE_GROUPES: u64 = 8;
/// Les adresses de groupe que tient la page.
const GROUPES_MAX: usize = (4096 - PAGE_GROUPES as usize - 4) / 6;
/// La taille d'un tampon de réception ou d'une case d'émission.
const TAILLE_TAMPON: u64 = 2048;
/// L'en-tête de virtio-net devant chaque trame (`struct virtio_net_hdr`,
/// avec `num_buffers` : 12 octets dès VERSION_1).
const ENTETE: usize = 12;
/// La plus grande trame Ethernet sans le code de contrôle : en-tête (14),
/// étiquette de VLAN (4), charge (1500).
const TRAME_MAX: usize = 1518;
/// La petite file d'émission (`txqueuelen` de Linux).
const ATTENTE_MAX: usize = 1000;
/// Le nombre de trames reçues traitées d'un coup, le verrou rendu entre
/// deux lots.
const LOT: usize = 16;

struct Reception {
    file: Virtqueue,
    notifieur: Notifieur,
}

/// La file de contrôle, et sa page de commande (une commande à la fois).
struct Controle {
    file: Virtqueue,
    notifieur: Notifieur,
    page: Tampons,
}

struct Emission {
    file: Virtqueue,
    notifieur: Notifieur,
    /// Les cases libres (leur numéro).
    libres: Vec<u16>,
    /// Les trames qui attendent une case.
    attente: VecDeque<Paquet>,
    /// La socket de la trame de chaque case (le `skb->sk` d'un paquet que la carte n'a
    /// pas encore fini), et combien il y en a. Tant qu'il en reste, l'interruption
    /// d'émission reste allumée : la socket attend peut-être cette fin d'émission (TSQ).
    proprietaires: Vec<Option<Proprietaire>>,
    suivies: usize,
}

/// La carte en service.
pub struct Carte {
    pub adresse: pci::Adresse,
    virtio: Virtio,
    /// Le numéro de son interface (0 avant qu'elle n'en ait une).
    interface: AtomicU32,
    /// Les pages des tampons de réception, puis d'émission.
    pages_reception: Tampons,
    pages_emission: Tampons,
    reception: Verrou<Reception>,
    emission: Verrou<Emission>,
    /// La file de contrôle, si la carte a CTRL_RX.
    controle: Option<Mutex<Controle>>,
}
// Une `Carte` rendue (sa mise en service a échoué) l'est dans l'ordre de ses
// champs : `virtio` d'abord, qui remet la carte à zéro (elle ne touche plus
// à la mémoire), puis ses tampons et ses files.

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

/// L'adresse de la carte, passée en argument aux gestionnaires de ses
/// files.
fn carte_de(argument: usize) -> &'static Carte {
    // SAFETY: l'argument est l'adresse d'une `Carte` laissée pour toujours
    // dans le tas (`ouvrir`), donné à `irq::allouer` par elle seule.
    unsafe { &*(argument as *const Carte) }
}

/// L'interruption de la file de réception : couper les suivantes, et
/// laisser le travail à la tâche du réseau (le `virtqueue_napi_schedule`
/// de Linux).
fn interruption_reception(argument: usize) {
    let c = carte_de(argument);
    c.reception.verrouiller().file.couper();
    super::tache::signaler_interface(c.interface.load(Ordering::Relaxed));
}

/// L'interruption de la file d'émission : des cases sont libres, la petite
/// file peut se vider.
fn interruption_emission(argument: usize) {
    let c = carte_de(argument);
    c.emission.verrouiller().file.couper();
    super::tache::signaler_interface(c.interface.load(Ordering::Relaxed));
}

/// L'interruption des deux files, quand elles partagent une entrée MSI-X
/// (`vp_vring_interrupt` de Linux : toutes les files, chacune ce qu'elle a).
fn interruption_files(argument: usize) {
    interruption_reception(argument);
    interruption_emission(argument);
}

/// Les noms des fonctionnalités négociées, pour le journal.
fn nommer(v: &Virtio) -> impl core::fmt::Display + '_ {
    struct Noms<'a>(&'a Virtio);
    impl core::fmt::Display for Noms<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            let mut premier = true;
            let noms = [(virtio::F_VERSION_1, "VERSION_1"), (F_MAC, "MAC"), (F_STATUS, "STATUS"), (F_CTRL_VQ, "CTRL_VQ"),
                        (F_CTRL_RX, "CTRL_RX"), (virtio::F_EVENT_IDX, "EVENT_IDX")];
            for (bit, nom) in noms {
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

/// Met en service la première carte virtio-net du bus, lui donne son
/// interface (`eth0`), et le dit.
pub fn sonder() {
    let Some(f) = pci::fonctions().iter().find(|f| est_virtio_net(f)) else {
        return afficherln!("[virtio] pas de carte reseau virtio.");
    };
    let (c, mac, lien) = match ouvrir(f) {
        Ok(r) => r,
        Err(e) => return afficherln!("[virtio] {} : {} : carte laissee eteinte.", f.adresse, e),
    };
    afficherln!("[virtio] {} : reseau, fonctionnalites {}, {} files.", c.adresse, nommer(&c.virtio), c.virtio.nb_files());
    if c.virtio.msix.entrees() < 3 {
        afficherln!("[virtio] {} : deux entrees MSI-X : une pour la configuration, une pour les deux files.", c.adresse);
    }
    let Some(i) = interface::ajouter("eth0", mac, 1500, lien, Materiel::VirtioNet(c)) else {
        return afficherln!("[reseau] plus de place pour une interface.");
    };
    c.interface.store(i.index, Ordering::Relaxed);
    *CARTE.verrouiller() = Some(c);
    // Son filtre : l'interface a déjà 224.0.0.1 (`interface::ajouter`), et
    // la tâche a pu chercher la carte avant qu'elle ne soit là.
    super::tache::signaler(super::tache::FILTRE);
    afficherln!("[reseau] {} : {}, mtu {}, lien {}.", i.nom, interface::decrire(i), i.mtu(), if lien { "actif" } else { "coupe" });
    // Des trames ont pu arriver avant que l'interface n'existe (la file
    // de réception était déjà ouverte) : la tâche les prendra.
    super::tache::signaler_interface(i.index);
}

/// Des pages de tampons, deux tampons de 2 Kio par page : l'adresse
/// physique de chacune. Rendues avec elles.
struct Tampons(Vec<u64>);

impl Tampons {
    /// Prend `n` pages. None : plus de mémoire (rien n'est gardé).
    fn new(n: usize) -> Option<Tampons> {
        let mut t = Tampons(faillible::avec_capacite(n).ok()?);
        for _ in 0..n {
            t.0.ajouter_dans_la_place(pages::allouer(0)?);
        }
        Some(t)
    }

    /// L'adresse physique du tampon `k` (deux par page).
    fn adresse(&self, k: u16) -> u64 {
        self.0[k as usize / 2] + (k as u64 % 2) * TAILLE_TAMPON
    }
}

impl Drop for Tampons {
    fn drop(&mut self) {
        for &p in &self.0 {
            pages::liberer(p, 0);
        }
    }
}

/// Renonce à une carte qui n'est pas encore en service : FAILED, puis la
/// remise à zéro (le `drop` de `v`), AVANT que ses files et ses tampons ne
/// soient rendus (Rust rend les variables d'une fonction dans l'ordre
/// inverse de leur déclaration : `v`, la première, le serait la dernière).
fn renoncer(v: Virtio, r: virtio::Refus) -> virtio::Refus {
    let r = v.echouer(r);
    drop(v);
    r
}

/// La poignée de main, les deux files, leurs tampons et leurs
/// interruptions, DRIVER_OK. Rend la carte, sa MAC et son lien.
fn ouvrir(f: &Fonction) -> Result<(&'static Carte, [u8; 6], bool), virtio::Refus> {
    let mut v = Virtio::ouvrir(f)?;
    let mut voulues = 1 << virtio::F_VERSION_1 | 1 << virtio::F_EVENT_IDX | 1 << F_MAC | 1 << F_STATUS;
    // La file de contrôle ne sert qu'au filtre : les deux, ou aucune
    // (CTRL_RX demande CTRL_VQ, 5.1.3.1).
    let filtre = 1 << F_CTRL_VQ | 1 << F_CTRL_RX;
    if v.offertes() & filtre == filtre {
        voulues |= filtre;
    }
    v.negocier(voulues)?;
    // Sans MAC donnée par la carte, Linux en tire une au hasard ; QEMU en
    // donne toujours une (52:54:00:12:34:56 par défaut).
    let mac = if v.a(F_MAC) {
        v.configuration(|c| core::array::from_fn(|i| c.octet(i as u64).unwrap_or(0)))
    } else {
        let mut m = [0u8; 6];
        crate::aleatoire::obtenir(&mut m);
        // Une adresse « administrée localement » (bit 1), pas de groupe
        // (bit 0) : le `eth_random_addr` de Linux.
        m[0] = m[0] & !1 | 2;
        m
    };
    let lien = !v.a(F_STATUS) || v.configuration(|c| c.mot16(STATUS)).is_some_and(|s| s & LIEN_ACTIF != 0);
    if v.taille_max(FILE_RECEPTION) < TAILLE_FILE || v.taille_max(FILE_EMISSION) < TAILLE_FILE {
        return Err(renoncer(v, virtio::Refus::Structure));
    }
    let evenements = v.a(virtio::F_EVENT_IDX);
    let (Some(rx), Some(tx)) = (Virtqueue::new(TAILLE_FILE, evenements), Virtqueue::new(TAILLE_FILE, evenements)) else {
        return Err(renoncer(v, virtio::Refus::Memoire));
    };
    let n = TAILLE_FILE as usize / 2;
    let (Some(pages_reception), Some(pages_emission)) = (Tampons::new(n), Tampons::new(n)) else {
        return Err(renoncer(v, virtio::Refus::Memoire));
    };
    // La file de contrôle (sa taille : celle de la carte, une puissance de 2,
    // 64 au plus), et sa page ; sans interruption (lue en tournant).
    let controle = if v.a(F_CTRL_VQ) {
        let taille = v.taille_max(FILE_CONTROLE).min(TAILLE_CONTROLE);
        if (taille as usize) < DESCRIPTEURS_PAR_COMMANDE || !taille.is_power_of_two() {
            return Err(renoncer(v, virtio::Refus::Structure));
        }
        let (Some(mut file), Some(page)) = (Virtqueue::new(taille, evenements), Tampons::new(1)) else {
            return Err(renoncer(v, virtio::Refus::Memoire));
        };
        file.couper();
        Some((file, page))
    } else {
        None
    };
    let mut libres = Vec::new();
    let mut attente = VecDeque::new();
    // La place de toutes les cases, et de la petite file : l'émission
    // n'alloue jamais (elle rend une case à sa place, met un paquet en
    // attente dans la sienne).
    let mut proprietaires = Vec::new();
    if libres.try_reserve_exact(TAILLE_FILE as usize).is_err() || attente.try_reserve_exact(ATTENTE_MAX).is_err() || proprietaires.try_reserve_exact(TAILLE_FILE as usize).is_err() {
        return Err(renoncer(v, virtio::Refus::Memoire));
    }
    for case in (0..TAILLE_FILE).rev() {
        libres.ajouter_dans_la_place(case);
        proprietaires.ajouter_dans_la_place(None);
    }
    // Les files d'abord, puis leurs interruptions : la carte est dans le
    // tas (son adresse, l'argument des gestionnaires, ne bouge plus), et
    // n'y est laissée pour toujours qu'une fois en service.
    let partage = v.msix.entrees() < 3;
    let (entree_rx, entree_tx) = if partage { (ENTREE_FILES, ENTREE_FILES) } else { (ENTREE_RECEPTION, ENTREE_EMISSION) };
    let rx_notifieur = match v.installer_file(FILE_RECEPTION, &rx, Some(entree_rx)) {
        Ok(n) => n,
        Err(e) => return Err(renoncer(v, e)),
    };
    let tx_notifieur = match v.installer_file(FILE_EMISSION, &tx, Some(entree_tx)) {
        Ok(n) => n,
        Err(e) => return Err(renoncer(v, e)),
    };
    let controle = match controle {
        Some((file, page)) => match v.installer_file(FILE_CONTROLE, &file, None) {
            Ok(notifieur) => Some(Mutex::new(Controle { file, notifieur, page })),
            Err(e) => return Err(renoncer(v, e)),
        },
        None => None,
    };
    let Ok(place) = faillible::boite_vide::<Carte>() else { return Err(renoncer(v, virtio::Refus::Memoire)) };
    let carte = alloc::boxed::Box::write(place, Carte {
        adresse: f.adresse,
        virtio: v,
        interface: AtomicU32::new(0),
        pages_reception,
        pages_emission,
        reception: Verrou::new(Reception { file: rx, notifieur: rx_notifieur }),
        emission: Verrou::new(Emission { file: tx, notifieur: tx_notifieur, libres, attente, proprietaires, suivies: 0 }),
        controle,
    });
    let argument = &*carte as *const Carte as usize;
    // Un échec à partir d'ici rend les vecteurs déjà donnés, puis la carte
    // (FAILED, remise à zéro, ses files et ses tampons : l'ordre de ses
    // champs) ; sans DRIVER_OK, elle n'a encore rien envoyé.
    let mut vecteurs = [None; 3];
    let rendre = |vecteurs: [Option<u8>; 3]| vecteurs.into_iter().flatten().for_each(irq::liberer);
    let separees = [
        (ENTREE_CONFIGURATION, interruption_configuration as fn(usize)),
        (ENTREE_RECEPTION, interruption_reception),
        (ENTREE_EMISSION, interruption_emission),
    ];
    let partagees = [(ENTREE_CONFIGURATION, interruption_configuration as fn(usize)), (ENTREE_FILES, interruption_files)];
    for (k, &(entree, gestionnaire)) in if partage { &partagees[..] } else { &separees[..] }.iter().enumerate() {
        let Some(vecteur) = irq::allouer(gestionnaire, argument) else {
            rendre(vecteurs);
            return Err(carte.virtio.echouer(virtio::Refus::Vecteur));
        };
        vecteurs[k] = Some(vecteur);
        carte.virtio.msix.programmer(entree, vecteur);
    }
    if let Err(e) = carte.virtio.vecteur_de_configuration(ENTREE_CONFIGURATION) {
        rendre(vecteurs);
        return Err(carte.virtio.echouer(e));
    }
    let carte: &'static Carte = alloc::boxed::Box::leak(carte);
    // Tous les tampons de réception confiés à la carte, l'émission sans
    // interruption (reprise à chaque envoi), puis DRIVER_OK.
    {
        let mut r = carte.reception.verrouiller();
        for k in 0..TAILLE_FILE {
            let t = Tampon { physique: carte.pages_reception.adresse(k), longueur: TAILLE_TAMPON as u32, drapeaux: ECRIT_PAR_PERIPHERIQUE };
            r.file.ajouter(&[t], k as u32);
        }
    }
    carte.emission.verrouiller().file.couper();
    carte.virtio.demarrer();
    let mut r = carte.reception.verrouiller();
    if r.file.faut_il_notifier() {
        r.notifieur.notifier();
    }
    Ok((carte, mac, lien))
}

/// La petite file d'émission de la carte est-elle vide (vrai sans carte) ?
pub fn au_repos() -> bool {
    let carte = *CARTE.verrouiller();
    carte.is_none_or(|c| {
        let e = c.emission.verrouiller();
        e.attente.is_empty() && e.suivies == 0
    })
}

impl Carte {
    /// Émet la trame `p` : dans une case de l'anneau si possible, sinon dans
    /// la petite file. false : jetée (plus grande qu'une case : elle ne
    /// partirait jamais, et bloquerait la petite file ; ou la petite file
    /// est pleine).
    pub fn emettre(&self, mut p: Paquet) -> bool {
        if p.longueur() > TAILLE_TAMPON as usize - ENTETE {
            return false;
        }
        let mut e = self.emission.verrouiller();
        self.reprendre_cases(&mut e);
        if e.attente.is_empty() && self.poser(&mut e, &mut p) {
            self.suivre_les_cases(&mut e);
            return true;
        }
        if e.attente.len() >= ATTENTE_MAX {
            return false;
        }
        e.attente.ajouter_derriere_dans_la_place(p);
        // Être prévenu quand des cases se libèrent.
        if !e.file.rallumer() {
            super::tache::signaler_interface(self.interface.load(Ordering::Relaxed));
        }
        true
    }

    /// Reprend les cases que la carte a finies d'émettre : leurs sockets sont
    /// prévenues (`tcp_wfree`).
    fn reprendre_cases(&self, e: &mut Emission) {
        while let Some((case, _)) = e.file.obtenir() {
            e.libres.ajouter_dans_la_place(case as u16);
            if let Some(p) = e.proprietaires[case as usize].take() {
                p.rendre();
                e.suivies -= 1;
            }
        }
    }

    /// Des sockets attendent la fin d'émission de leurs trames : l'interruption allumée,
    /// en revenant tout de suite si c'est déjà fait.
    fn suivre_les_cases(&self, e: &mut Emission) {
        if e.suivies > 0 && !e.file.rallumer() {
            super::tache::signaler_interface(self.interface.load(Ordering::Relaxed));
        }
    }

    /// Copie `p` dans une case libre, derrière un en-tête nul, et la confie
    /// à la carte, avec le lien à sa socket. false : pas de case libre.
    fn poser(&self, e: &mut Emission, p: &mut Paquet) -> bool {
        let donnees = p.donnees();
        if donnees.len() > TAILLE_TAMPON as usize - ENTETE || e.file.libres() == 0 {
            return false;
        }
        let Some(case) = e.libres.pop() else { return false };
        let physique = self.pages_emission.adresse(case);
        // SAFETY: la case est à nous (libre, pas dans l'anneau), 2 Kio dans
        // une page vue par la projection directe ; la trame y tient (vérifié).
        unsafe {
            let o = espace::virtuelle(physique) as *mut u8;
            core::ptr::write_bytes(o, 0, ENTETE);
            core::ptr::copy_nonoverlapping(donnees.as_ptr(), o.add(ENTETE), donnees.len());
        }
        let t = Tampon { physique, longueur: (ENTETE + donnees.len()) as u32, drapeaux: 0 };
        e.file.ajouter(&[t], case as u32);
        if let Some(q) = p.prendre_proprietaire() {
            e.proprietaires[case as usize] = Some(q);
            e.suivies += 1;
        }
        if e.file.faut_il_notifier() {
            e.notifieur.notifier();
        }
        true
    }

    /// Le travail de la tâche du réseau pour cette carte : les cases
    /// d'émission finies et la petite file ; puis au plus `budget` trames
    /// reçues, par lots, chacune copiée dans un paquet et livrée, son tampon
    /// rendu à la carte. Puis les interruptions rallumées, si le budget n'a
    /// pas été épuisé. Rend vrai s'il reste du travail.
    pub fn travailler(&self, i: &'static Interface, budget: usize) -> bool {
        {
            let mut e = self.emission.verrouiller();
            self.reprendre_cases(&mut e);
            while let Some(mut p) = e.attente.pop_front() {
                if !self.poser(&mut e, &mut p) {
                    e.attente.ajouter_devant_dans_la_place(p);
                    break;
                }
            }
            // La petite file vide, et aucune socket n'attend de fin d'émission :
            // plus besoin d'interruption d'émission ; sinon, être prévenu des
            // prochaines cases libérées (et revenir tout de suite si c'est déjà fait).
            if e.attente.is_empty() && e.suivies == 0 {
                e.file.couper();
            } else if !e.file.rallumer() {
                super::tache::signaler_interface(i.index);
            }
        }
        let mut faites = 0;
        loop {
            // Un lot de trames, prises sous le verrou ; copiées, leurs
            // tampons rendus, puis livrées hors de lui.
            let mut lot = [(0u32, 0u32); LOT];
            let mut n = 0;
            {
                let mut r = self.reception.verrouiller();
                while n < LOT && faites + n < budget {
                    let Some(t) = r.file.obtenir() else { break };
                    lot[n] = t;
                    n += 1;
                }
            }
            let mut paquets: [Option<Paquet>; LOT] = [const { None }; LOT];
            for (k, &(jeton, longueur)) in lot[..n].iter().enumerate() {
                let longueur = longueur as usize;
                let physique = self.pages_reception.adresse(jeton as u16);
                // SAFETY: la carte nous a rendu ce tampon (obtenir), elle
                // n'y écrit plus jusqu'à ce qu'on le lui redonne ; la
                // longueur est bornée à celle du tampon.
                let octets = unsafe { core::slice::from_raw_parts(espace::virtuelle(physique) as *const u8, longueur.min(TAILLE_TAMPON as usize)) };
                if longueur < ENTETE || longueur - ENTETE > TRAME_MAX {
                    interface::Compteurs::compter(&i.compteurs.jetes_reception, 1);
                    continue;
                }
                match Paquet::copie(&octets[ENTETE..]) {
                    Some(p) => paquets[k] = Some(p),
                    None => interface::Compteurs::compter(&i.compteurs.jetes_reception, 1),
                }
            }
            {
                let mut r = self.reception.verrouiller();
                for &(jeton, _) in &lot[..n] {
                    let t = Tampon { physique: self.pages_reception.adresse(jeton as u16), longueur: TAILLE_TAMPON as u32, drapeaux: ECRIT_PAR_PERIPHERIQUE };
                    r.file.ajouter(&[t], jeton);
                }
                if n > 0 && r.file.faut_il_notifier() {
                    r.notifieur.notifier();
                }
            }
            for p in paquets.iter_mut().filter_map(Option::take) {
                interface::Compteurs::compter(&i.compteurs.recus, 1);
                interface::Compteurs::compter(&i.compteurs.octets_recus, p.longueur() as u64);
                super::recevoir(i, p);
            }
            faites += n;
            if faites >= budget {
                return true;
            }
            if n < LOT {
                // L'anneau est vide : rallumer, et revérifier.
                if self.reception.verrouiller().file.rallumer() {
                    return false;
                }
            }
        }
    }
}

/// Une interruption de configuration est arrivée : relire le lien, et dire
/// s'il a changé (le `virtnet_config_changed_work` de Linux, puis le
/// linkwatch). Dans la tâche du réseau.
pub fn configuration_changee() {
    let Some(c) = *CARTE.verrouiller() else { return };
    let Some(i) = interface::par_index(c.interface.load(Ordering::Relaxed)) else { return };
    if !c.virtio.a(F_STATUS) {
        return;
    }
    let actif = c.virtio.configuration(|l| l.mot16(STATUS)).is_some_and(|s| s & LIEN_ACTIF != 0);
    if i.lien.swap(actif, Ordering::Relaxed) != actif {
        afficherln!("[reseau] {} : lien {}.", i.nom, if actif { "retabli" } else { "coupe" });
    }
}

impl Controle {
    /// L'adresse physique de la page, à `decalage`.
    fn physique(&self, decalage: u64) -> u64 {
        self.page.0[0] + decalage
    }

    /// Écrit `octets` dans la page, à `decalage`.
    fn ecrire(&mut self, decalage: u64, octets: &[u8]) {
        assert!(decalage as usize + octets.len() <= 4096, "hors de la page de commande");
        // SAFETY: la page est à nous, vue par la projection directe, et
        // l'écriture y tient (vérifié) ; entre deux commandes, la carte n'y
        // touche pas (elle a rendu la dernière, `envoyer` l'a attendue), et
        // `&mut self` (sous le verrou de la file) écarte tout autre écrivain.
        unsafe {
            core::ptr::copy_nonoverlapping(octets.as_ptr(), espace::virtuelle(self.physique(decalage)) as *mut u8, octets.len())
        }
    }

    /// Envoie la commande (`classe`, `numero`), dont les données sont déjà
    /// dans la page aux places `donnees` (décalage, longueur), et attend que
    /// la carte la rende (`virtnet_send_command_reply`). Vrai : faite.
    fn envoyer(&mut self, classe: u8, numero: u8, donnees: &[(u64, u32)]) -> bool {
        self.ecrire(PAGE_ENTETE, &[classe, numero]);
        // Une réponse que la carte n'écrirait pas se lit « refusée » (le
        // `status = ~0` de Linux).
        self.ecrire(PAGE_REPONSE, &[0xff]);
        let mut chaine = [Tampon { physique: 0, longueur: 0, drapeaux: 0 }; DESCRIPTEURS_PAR_COMMANDE];
        let mut n = 0;
        let mut ajouter = |physique, longueur, drapeaux| {
            chaine[n] = Tampon { physique, longueur, drapeaux };
            n += 1;
        };
        ajouter(self.physique(PAGE_ENTETE), 2, 0);
        for &(decalage, longueur) in donnees {
            ajouter(self.physique(decalage), longueur, 0);
        }
        ajouter(self.physique(PAGE_REPONSE), 1, ECRIT_PAR_PERIPHERIQUE);
        // La file est vide (la dernière commande a été rendue) : la chaîne y
        // tient.
        if !self.file.ajouter(&chaine[..n], 0) {
            return false;
        }
        if self.file.faut_il_notifier() {
            self.notifieur.notifier();
        }
        // Tourner, préemptible (aucun Verrou n'est tenu) : la réponse.
        while self.file.obtenir().is_none() {
            core::hint::spin_loop();
        }
        // SAFETY: l'octet de la réponse, dans notre page ; la carte l'a écrit
        // avant de rendre la chaîne (`obtenir` lit l'index avant les entrées).
        let reponse = unsafe { (espace::virtuelle(self.physique(PAGE_REPONSE)) as *const u8).read_volatile() };
        reponse == FAITE
    }
}

/// Les adresses MAC des groupes ont changé, ou la carte vient d'être mise
/// en service : son filtre, refait (le `virtnet_rx_mode_work` de Linux) :
/// ni promiscuité, ni toute la multidiffusion (sauf si la liste déborde de
/// la page), puis la table : aucune adresse individuelle, et les adresses
/// des groupes, recopiées sous le verrou des groupes. Dans la tâche du
/// réseau, qui ne tient aucun Verrou (la file de contrôle est un verrou qui
/// dort, pris avant les groupes). Une commande refusée est dite, et la
/// suite essayée quand même, comme chez Linux.
pub fn filtrer() {
    let Some(c) = *CARTE.verrouiller() else { return };
    let Some(controle) = &c.controle else { return };
    let mut k = controle.verrouiller();
    let index = c.interface.load(Ordering::Relaxed);
    let groupes = super::multidiffusion::avec_les_macs(index, |macs| {
        if macs.len() > GROUPES_MAX {
            return None;
        }
        for (j, m) in macs.iter().enumerate() {
            k.ecrire(PAGE_GROUPES + 4 + 6 * j as u64, &m.adresse);
        }
        Some(macs.len())
    });
    let toute = groupes.is_none();
    let n = groupes.unwrap_or(0);
    k.ecrire(PAGE_INDIVIDUELLES, &0u32.to_le_bytes());
    k.ecrire(PAGE_GROUPES, &(n as u32).to_le_bytes());
    let refus = |quoi| afficherln!("[virtio] {} : la carte refuse {}.", c.adresse, quoi);
    k.ecrire(PAGE_OCTET, &[0]);
    if !k.envoyer(CLASSE_RX, RX_PROMISC, &[(PAGE_OCTET, 1)]) {
        refus("de quitter la promiscuite");
    }
    k.ecrire(PAGE_OCTET, &[toute as u8]);
    if !k.envoyer(CLASSE_RX, RX_ALLMULTI, &[(PAGE_OCTET, 1)]) {
        refus(if toute { "toute la multidiffusion" } else { "de quitter toute la multidiffusion" });
    }
    let tables = [(PAGE_INDIVIDUELLES, 4), (PAGE_GROUPES, 4 + 6 * n as u32)];
    if !k.envoyer(CLASSE_MAC, MAC_TABLE_SET, &tables) {
        refus("sa table d'adresses");
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
