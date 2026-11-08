//! /sys : le noyau décrit ses objets en fichiers (le sysfs de Linux, au-
//! dessus de kernfs). Bun y lit le nombre de processeurs en marche
//! (`/sys/devices/system/cpu/online`, par `get_nprocs` de la glibc) et le
//! réglage des grandes pages (`/sys/kernel/mm/transparent_hugepage/
//! enabled`) ; la glibc lit aussi `possible` (`get_nprocs_conf`, mesuré).
//!
//! Comme /proc, un système de fichiers du noyau (fichiers::noyaufs), monté
//! sur /sys au démarrage. Chaque fichier est un « attribut » : une petite
//! valeur, lue comme un seq_file d'un seul enregistrement, d'une taille
//! annoncée d'une page (kernfs). Rien n'y est écrit : le réglage des
//! grandes pages, 0644 à root, n'est inscriptible que par root, et nos
//! programmes ne le sont jamais.
//!
//! Le contenu, ce que fait notre noyau :
//!   - les processeurs : online, ceux qui sont en service ; possible et
//!     present, ceux de la machine (la MADT), répondu ou non (processeur.rs),
//!     en listes au format de Linux : « 0-3 », « 0,2-3 » ;
//!   - pas de grandes pages transparentes : « always madvise [never] »,
//!     la valeur entre crochets étant celle en vigueur, ce que 6a a déjà
//!     promis (MADV_HUGEPAGE accepté, sans effet).
//! Pas de /sys/devices/system/node : comme une machine sans NUMA (Linux ne
//! le crée qu'avec CONFIG_NUMA, lu), les `access(".../node1")` de Bun
//! rendent ENOENT.

use alloc::vec::Vec;
use crate::faillible::{self, VecFaillible};
use fichiers::noyaufs::{Contenu, Genre, NoyauFs};
use fichiers::{Erreur, Temps};

/// Les sources des fichiers de /sys (après celles de /proc, procfs.rs).
pub const CPU_ONLINE: u32 = 10;
pub const CPU_POSSIBLE: u32 = 11;
pub const CPU_PRESENT: u32 = 12;
pub const THP_ENABLED: u32 = 13;

/// Le périphérique de sysfs (un numéro anonyme, après celui de procfs).
const PERIPHERIQUE: (u32, u32) = (0, 22);

/// Le sysfs neuf, avec les droits de Linux (mesurés) : /sys 0555, ses
/// dossiers 0755, les attributs 0444 (0644 pour un réglage).
pub fn creer(maintenant: Temps) -> Result<NoyauFs, Erreur> {
    let mut s = NoyauFs::new(Genre::Sys, PERIPHERIQUE, 0o555, maintenant)?;
    let racine = s.racine();
    let dossier = |s: &mut NoyauFs, parent, nom: &[u8]| s.ajouter(parent, nom, 0o755, (0, 0), Contenu::Dossier, maintenant);
    let attribut = |source| Contenu::Fichier { source, argument: 0 };
    let devices = dossier(&mut s, racine, b"devices")?;
    let system = dossier(&mut s, devices, b"system")?;
    let cpu = dossier(&mut s, system, b"cpu")?;
    s.ajouter(cpu, b"online", 0o444, (0, 0), attribut(CPU_ONLINE), maintenant)?;
    s.ajouter(cpu, b"possible", 0o444, (0, 0), attribut(CPU_POSSIBLE), maintenant)?;
    s.ajouter(cpu, b"present", 0o444, (0, 0), attribut(CPU_PRESENT), maintenant)?;
    let kernel = dossier(&mut s, racine, b"kernel")?;
    let mm = dossier(&mut s, kernel, b"mm")?;
    let thp = dossier(&mut s, mm, b"transparent_hugepage")?;
    s.ajouter(thp, b"enabled", 0o644, (0, 0), attribut(THP_ENABLED), maintenant)?;
    Ok(s)
}

/// La valeur de l'attribut `source`, s'il est de /sys, fabriquée à la
/// lecture (ENOMEM si la mémoire manque).
pub fn attribut(source: u32) -> Option<Result<Vec<u8>, Erreur>> {
    match source {
        CPU_ONLINE => Some(liste(crate::processeur::masque_en_service())),
        CPU_POSSIBLE | CPU_PRESENT => Some(liste(crate::processeur::masque_possible())),
        THP_ENABLED => Some(faillible::copie(b"always madvise [never]\n").map_err(|_| Erreur::ENOMEM)),
        _ => None,
    }
}

/// Une liste de processeurs au format de Linux (le `%*pbl` de lib/vsprintf.c,
/// `bitmap_list_string`) : les plages de numéros consécutifs, « 0-3 »,
/// séparées par des virgules, « 0,2-3 », et un saut de ligne.
fn liste(masque: u64) -> Result<Vec<u8>, Erreur> {
    let mut v: Vec<u8> = faillible::avec_capacite(64).map_err(|_| Erreur::ENOMEM)?;
    let nombre = |v: &mut Vec<u8>, n: u32| -> Result<(), Erreur> {
        let mut texte = [0u8; 10];
        let d = crate::vfs::decimal(n, &mut texte);
        v.ajouter_tranche(if d.is_empty() { b"0" } else { d }).map_err(|_| Erreur::ENOMEM)
    };
    let mut n = 0u32;
    while n < 64 {
        if masque >> n & 1 == 0 {
            n += 1;
            continue;
        }
        let debut = n;
        while n < 64 && masque >> n & 1 == 1 {
            n += 1;
        }
        if debut != 0 {
            v.ajouter(b',').map_err(|_| Erreur::ENOMEM)?;
        }
        nombre(&mut v, debut)?;
        if n - 1 > debut {
            v.ajouter(b'-').map_err(|_| Erreur::ENOMEM)?;
            nombre(&mut v, n - 1)?;
        }
    }
    v.ajouter(b'\n').map_err(|_| Erreur::ENOMEM)?;
    Ok(v)
}
