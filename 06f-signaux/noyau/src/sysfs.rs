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
//!   - un processeur, le 0 : online, possible, present valent « 0 » (une
//!     liste de processeurs, au format de Linux) ;
//!   - pas de grandes pages transparentes : « always madvise [never] »,
//!     la valeur entre crochets étant celle en vigueur, ce que 6a a déjà
//!     promis (MADV_HUGEPAGE accepté, sans effet).
//! Pas de /sys/devices/system/node : comme une machine sans NUMA (Linux ne
//! le crée qu'avec CONFIG_NUMA, lu), les `access(".../node1")` de Bun
//! rendent ENOENT.

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
    let dossier = |s: &mut NoyauFs, parent, nom: &[u8]| s.ajouter(parent, nom, 0o755, (0, 0), Contenu::Dossier, false, maintenant);
    let attribut = |source| Contenu::Fichier { source, argument: 0 };
    let devices = dossier(&mut s, racine, b"devices")?;
    let system = dossier(&mut s, devices, b"system")?;
    let cpu = dossier(&mut s, system, b"cpu")?;
    s.ajouter(cpu, b"online", 0o444, (0, 0), attribut(CPU_ONLINE), false, maintenant)?;
    s.ajouter(cpu, b"possible", 0o444, (0, 0), attribut(CPU_POSSIBLE), false, maintenant)?;
    s.ajouter(cpu, b"present", 0o444, (0, 0), attribut(CPU_PRESENT), false, maintenant)?;
    let kernel = dossier(&mut s, racine, b"kernel")?;
    let mm = dossier(&mut s, kernel, b"mm")?;
    let thp = dossier(&mut s, mm, b"transparent_hugepage")?;
    s.ajouter(thp, b"enabled", 0o644, (0, 0), attribut(THP_ENABLED), false, maintenant)?;
    Ok(s)
}

/// La valeur de l'attribut `source`, s'il est de /sys.
pub fn attribut(source: u32) -> Option<&'static [u8]> {
    match source {
        CPU_ONLINE | CPU_POSSIBLE | CPU_PRESENT => Some(b"0\n"),
        THP_ENABLED => Some(b"always madvise [never]\n"),
        _ => None,
    }
}
