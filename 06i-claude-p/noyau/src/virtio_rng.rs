//! virtio-rng : le générateur matériel d'une machine virtuelle
//! (spécification virtio 1.x, 5.4 ; drivers/char/hw_random/virtio-rng.c
//! et core.c de Linux). QEMU le donne par `-device virtio-rng-pci` : une
//! seule file, où le pilote dépose des tampons vides, que le périphérique
//! rend remplis d'octets aléatoires de l'hôte (son /dev/urandom par
//! défaut).
//!
//! Pourquoi : c'est la source que Linux emploie dans une machine
//! virtuelle, et la machine de l'étape (`-cpu Nehalem`) n'a ni RDRAND ni
//! RDSEED. Sans elle, le générateur attend la gigue (aleatoire.rs) ; avec
//! elle, il est prêt en quelques millisecondes au démarrage, quel que soit
//! le temps sous QEMU.
//!
//! Comme Linux, une tâche du noyau, `hwrng` (le `hwrng_fillfn` du fil
//! « hwrng »), lit 64 octets (RNG_BUFFER_SIZE sur x86), les verse au
//! générateur, crédités en entier (`add_hwgenerator_randomness`, la
//! qualité 1024 sur 1024 que Linux donne par défaut à virtio-rng), puis
//! dort jusqu'au prochain réensemencement (`crng_reseed_interval`) : ses
//! octets servent à chacun. L'interruption de la file ne fait que réveiller
//! la tâche.
//!
//! Option écartée : verser ce que rend la carte depuis l'interruption
//! (le verrou du générateur serait pris dans une interruption, et le
//! générateur ne demande de l'aléa qu'à chaque réensemencement).

use crate::attente::{self, FileAttente, Sommeil};
use crate::pci::Fonction;
use crate::programmes::NomCourt;
use crate::verrou::Verrou;
use crate::virtio::{self, Notifieur, Virtio};
use crate::virtqueue::{ECRIT_PAR_PERIPHERIQUE, Tampon, Virtqueue};
use crate::{cpu, espace, faillible, irq, pages, tache, temps};

/// Les modèles : transitionnel (0x1005, sous-système 4) et moderne
/// (0x1040 + 4).
const TRANSITIONNEL: u16 = 0x1005;
const SORTE_ALEA: u16 = 4;
/// Les entrées MSI-X : la configuration (que virtio-rng n'emploie pas),
/// puis la file, comme Linux.
const ENTREE_FILE: u16 = 1;
/// La taille de la file : un tampon à la fois suffit (Linux en garde un).
const TAILLE_FILE: u16 = 4;
/// Ce qu'on demande d'un coup (RNG_BUFFER_SIZE).
const LECTURE: usize = 64;

/// La carte en service.
struct Carte {
    virtio: Virtio,
    file: Verrou<Virtqueue>,
    notifieur: Notifieur,
    /// La page du tampon (adresse physique).
    page: u64,
    /// La tâche `hwrng` y attend que la carte rende le tampon.
    attente: FileAttente,
}

fn est_virtio_rng(f: &Fonction) -> bool {
    let e = &f.entete;
    let sous_systeme = match e.genre {
        formats::pci::Genre::Ordinaire { sous_systeme, .. } => sous_systeme,
        _ => return false,
    };
    e.vendeur == virtio::FABRICANT
        && (e.peripherique == virtio::MODERNE + SORTE_ALEA || (e.peripherique == TRANSITIONNEL && sous_systeme == SORTE_ALEA))
}

/// L'interruption de la file : le tampon est rendu, la tâche réveillée.
fn interruption(argument: usize) {
    // SAFETY: l'argument est l'adresse de la carte, laissée pour toujours
    // dans le tas (`Box::leak`) avant que l'interruption ne soit posée.
    let c = unsafe { &*(argument as *const Carte) };
    c.attente.reveiller_toutes();
}

/// Trouve une carte virtio-rng, la met en service et lance la tâche
/// `hwrng`. Sans carte : rien (la plupart des machines n'en ont pas).
pub fn sonder() {
    let Some(f) = crate::pci::fonctions().iter().find(|f| est_virtio_rng(f)) else { return };
    let c = match ouvrir(f) {
        Ok(c) => c,
        Err(e) => return afficherln!("[virtio] {} : {} : generateur laisse eteint.", f.adresse, e),
    };
    afficherln!("[virtio] {} : alea.", f.adresse);
    if tache::lancer_noyau(NomCourt::de(b"hwrng"), move || boucle(c)).is_none() {
        afficherln!("[virtio] pas de pile pour la tache hwrng : generateur inutilise.");
    }
}

/// La poignée de main (VERSION_1 seule : virtio-rng n'a pas de
/// fonctionnalité à lui), la file, son interruption, DRIVER_OK.
fn ouvrir(f: &Fonction) -> Result<&'static Carte, virtio::Refus> {
    let mut v = Virtio::ouvrir(f)?;
    v.negocier(1 << virtio::F_VERSION_1)?;
    if v.taille_max(0) < TAILLE_FILE {
        return Err(v.echouer(virtio::Refus::Structure));
    }
    let Some(file) = Virtqueue::new(TAILLE_FILE, false) else { return Err(v.echouer(virtio::Refus::Memoire)) };
    let Some(page) = pages::allouer(0) else { return Err(v.echouer(virtio::Refus::Memoire)) };
    let notifieur = match v.installer_file(0, &file, ENTREE_FILE) {
        Ok(n) => n,
        Err(e) => {
            pages::liberer(page, 0);
            return Err(v.echouer(e));
        }
    };
    let Ok(place) = faillible::boite_vide::<Carte>() else {
        pages::liberer(page, 0);
        return Err(v.echouer(virtio::Refus::Memoire));
    };
    let carte = alloc::boxed::Box::write(place, Carte { virtio: v, file: Verrou::new(file), notifieur, page, attente: FileAttente::new() });
    let Some(vecteur) = irq::allouer(interruption, &*carte as *const Carte as usize) else {
        pages::liberer(carte.page, 0);
        return Err(carte.virtio.echouer(virtio::Refus::Vecteur));
    };
    carte.virtio.msix.programmer(ENTREE_FILE, vecteur);
    let carte: &'static Carte = alloc::boxed::Box::leak(carte);
    carte.virtio.demarrer();
    Ok(carte)
}

/// Demande `LECTURE` octets à la carte et attend sa réponse : rend combien
/// elle en a écrit dans la page.
fn lire(c: &Carte) -> usize {
    {
        let mut f = c.file.verrouiller();
        let t = Tampon { physique: c.page, longueur: LECTURE as u32, drapeaux: ECRIT_PAR_PERIPHERIQUE };
        f.ajouter(&[t], 0);
        if f.faut_il_notifier() {
            c.notifieur.notifier();
        }
    }
    let interruptions = cpu::couper_interruptions();
    let t = tache::courante();
    let n = loop {
        if let Some((_, n)) = c.file.verrouiller().obtenir() {
            break n as usize;
        }
        c.attente.inscrire();
        attente::dormir(None, Sommeil::Ininterruptible);
        c.attente.retirer(&t);
    };
    if interruptions {
        cpu::activer_interruptions();
    }
    n.min(LECTURE)
}

/// La tâche `hwrng` : lire, verser, dormir jusqu'au prochain
/// réensemencement, comme le fil de Linux.
fn boucle(c: &'static Carte) {
    loop {
        let n = lire(c);
        let mut octets = [0u8; LECTURE];
        // SAFETY: la page est à nous, et la carte a fini d'y écrire (elle
        // a rendu le tampon) ; `n` octets au plus, sous la taille du tampon.
        unsafe { core::ptr::copy_nonoverlapping(espace::virtuelle(c.page) as *const u8, octets.as_mut_ptr(), n) };
        crate::aleatoire::verser(&octets[..n], n as u32 * 8, "virtio-rng");
        crypto::effacer(&mut octets);
        let attente = crypto::alea::intervalle(temps::ns_monotone() / 1_000_000_000);
        let interruptions = cpu::couper_interruptions();
        attente::dormir(Some(temps::ns_monotone() + attente * 1_000_000_000), Sommeil::Ininterruptible);
        if interruptions {
            cpu::activer_interruptions();
        }
    }
}
