//! /proc : ce que le noyau sait des processus et de lui-même, en fichiers
//! (le procfs de Linux, fs/proc/). Bun y lit sa propre carte de la mémoire
//! (`/proc/self/maps`, par `pthread_getattr_np` de la glibc, qui y cherche
//! sa pile), sa mémoire résidente (`statm`), deux réglages de la mémoire
//! (`/proc/sys/vm/...`).
//!
//! L'arborescence est un système de fichiers du noyau (fichiers::noyaufs),
//! monté sur /proc au démarrage (vfs.rs) :
//!   - /proc/self : un lien vers le numéro du processus qui le lit ;
//!   - /proc/<pid>/ pour chaque processus, ajouté à son lancement et retiré
//!     à sa fin (programmes.rs) : `maps`, `statm`, et le lien `exe` vers le
//!     chemin canonique de son exécutable ; à lui (son utilisateur), comme
//!     sous Linux ;
//!   - /proc/sys/vm/overcommit_memory et mmap_min_addr, à root.
//! Le reste viendra avec son besoin : /proc/<pid>/fd (6f), task (6e),
//! /proc/meminfo si une mesure le demande. /proc/self/cgroup est absent,
//! comme sur un Linux construit sans les cgroups (nous n'en avons pas) :
//! libuv le prévoit (« aucune limite »).
//!
//! Le contenu d'un fichier est fabriqué à la lecture, par une « source » :
//! `maps` ligne par ligne (le parcours reprend à l'adresse de fin de la
//! dernière zone écrite, comme `m_start` de Linux : une carte qui change
//! entre deux lectures ne fait ni sauter ni répéter de zone), `statm` d'un
//! seul enregistrement, les réglages en une valeur.
//!
//! Les verrous, dans l'ordre de toujours : celui du processus (la carte des
//! zones), rendu, puis celui des fichiers (le chemin du fichier d'une
//! zone) ; la copie vers le programme, hors des deux (appels_fichiers.rs).

use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::descripteurs::{Donnees, Fichier, Lecture};
use crate::espace_utilisateur::ADRESSE_MIN;
use crate::{appels_fichiers, processus, sysfs, vfs};
use fichiers::montages::Monte;
use fichiers::noyaufs::{Cible, Contenu, Enregistrement, Genre, NoyauFs};
use fichiers::{Erreur, Temps};
use zones::Nature;

/// Les sources des fichiers de /proc.
const MAPS: u32 = 1;
const STATM: u32 = 2;
const OVERCOMMIT_MEMORY: u32 = 3;
const MMAP_MIN_ADDR: u32 = 4;

/// Le périphérique de procfs (un numéro anonyme, après celui du tmpfs de la
/// racine, 0:20).
const PERIPHERIQUE: (u32, u32) = (0, 21);

/// Le plus d'octets qu'une lecture rend d'un coup (64 Kio : un programme
/// relit pour la suite, comme pour tout fichier).
const LECTURE_MAX: u64 = 64 << 10;

/// Le procfs neuf : /proc/self et /proc/sys/vm. Assez de place d'avance
/// pour le dossier d'un processus : sinon la table des entrées grandirait
/// pendant le premier programme, et « memoire rendue » le compterait.
pub fn creer(maintenant: Temps) -> Result<NoyauFs, Erreur> {
    let mut p = NoyauFs::new(Genre::Proc, PERIPHERIQUE, 0o555, maintenant)?;
    let racine = p.racine();
    p.reserver(16)?;
    p.ajouter(racine, b"self", 0o777, (0, 0), Contenu::Lien(Cible::Lecteur), false, maintenant)?;
    let sys = p.ajouter(racine, b"sys", 0o555, (0, 0), Contenu::Dossier, false, maintenant)?;
    let vm = p.ajouter(sys, b"vm", 0o555, (0, 0), Contenu::Dossier, false, maintenant)?;
    let reglage = |source| Contenu::Fichier { source, argument: 0 };
    p.ajouter(vm, b"overcommit_memory", 0o644, (0, 0), reglage(OVERCOMMIT_MEMORY), false, maintenant)?;
    p.ajouter(vm, b"mmap_min_addr", 0o644, (0, 0), reglage(MMAP_MIN_ADDR), false, maintenant)?;
    Ok(p)
}

/// Ajoute /proc/<pid> pour le processus `pid`, d'identité (`uid`, `gid`),
/// d'exécutable `exe` (son chemin canonique). Un échec (plus de mémoire)
/// est dit, et le programme tourne sans.
pub fn ajouter_processus(pid: u32, proprietaire: (u32, u32), exe: &[u8]) {
    let maintenant = crate::temps::maintenant();
    let mut cible = Vec::new();
    if cible.try_reserve_exact(exe.len()).is_ok() {
        cible.extend_from_slice(exe);
    }
    let fait = vfs::avec_systeme(|s, _| -> Result<(), Erreur> {
        let p = &mut s.montes[vfs::PROC].1;
        let mut nom = [0u8; 10];
        let nom = vfs::decimal(pid, &mut nom);
        let d = p.ajouter(p.racine(), nom, 0o555, proprietaire, Contenu::Dossier, true, maintenant)?;
        let fichier = |source| Contenu::Fichier { source, argument: pid };
        let r = p.ajouter(d, b"maps", 0o444, proprietaire, fichier(MAPS), true, maintenant)
            .and_then(|_| p.ajouter(d, b"statm", 0o444, proprietaire, fichier(STATM), true, maintenant))
            .and_then(|_| p.ajouter(d, b"exe", 0o777, proprietaire, Contenu::Lien(Cible::Fixe(cible)), true, maintenant));
        if r.is_err() {
            p.retirer(d);
        }
        r.map(|_| ())
    });
    if let Err(e) = fait {
        afficherln!("[noyau] /proc/{} : impossible a creer (errno {})", pid, e.errno());
    }
}

/// Retire /proc/<pid> (le processus est terminé).
pub fn retirer_processus(pid: u32) {
    vfs::avec_systeme(|s, _| {
        let p = &mut s.montes[vfs::PROC].1;
        let mut nom = [0u8; 10];
        let nom = vfs::decimal(pid, &mut nom);
        if let Some(d) = p.chercher(p.racine(), nom) {
            p.retirer(d);
        }
    })
}

/// Comment se lit la source `source` d'un système du noyau : les
/// séquences et les valeurs de /proc, les attributs de /sys.
pub fn lecture(source: u32) -> Lecture {
    match source {
        OVERCOMMIT_MEMORY | MMAP_MIN_ADDR => Lecture::Valeur,
        MAPS | STATM => Lecture::Sequence,
        _ => Lecture::Attribut,
    }
}

/// Les données du fichier ouvert d'une source.
pub fn donnees(source: u32, argument: u32) -> Donnees {
    Donnees::Noyau { source, argument, sequence: Default::default() }
}

/// Lit le fichier ouvert `f` (une source du noyau) à `position` : au plus
/// `longueur` octets (et LECTURE_MAX), dans un bloc du tas que
/// l'appelant copie vers le programme. Une valeur de /proc/sys ne se lit
/// qu'à la position 0 (rien ailleurs : `proc_dointvec`, mesuré) ; le
/// reste, comme une séquence.
pub fn lire(f: Fichier, position: u64, longueur: u64) -> Result<Vec<u8>, i64> {
    let longueur = longueur.min(LECTURE_MAX) as usize;
    // L'état de la lecture sort du fichier ouvert le temps de fabriquer le
    // contenu (qui prend d'autres verrous), puis y revient.
    let (source, argument, mut sequence) = vfs::avec_systeme(|s, _| match &mut s.ouverts.fichier(f).donnees {
        Donnees::Noyau { source, argument, sequence } => (*source, *argument, core::mem::take(sequence)),
        _ => unreachable!("un fichier du noyau sans source"),
    });
    let lu = match lecture(source) {
        Lecture::Valeur if position > 0 => Ok(Vec::new()),
        Lecture::Valeur => valeur(source).map(|mut v| {
            v.truncate(longueur);
            v
        }),
        Lecture::Sequence | Lecture::Attribut => sequence.lire(position, longueur, |curseur| produire(source, argument, curseur)),
    };
    vfs::avec_systeme(|s, _| {
        if let Donnees::Noyau { sequence: place, .. } = &mut s.ouverts.fichier(f).donnees {
            *place = sequence;
        }
    });
    lu.map_err(|e| -e.errno())
}

/// lseek sur un fichier d'un système du noyau, de position `position` :
/// la nouvelle position, ou -errno. Les trois façons de Linux (mesuré) :
///   - une séquence (`seq_lseek`) : SEEK_SET et SEEK_CUR, EINVAL sinon ;
///   - une valeur de /proc/sys (`default_llseek`, d'un fichier de taille
///     nulle) : SEEK_END part de 0 ; SEEK_DATA et SEEK_HOLE, ENXIO à la
///     fin et au-delà ; avant la fin, c'est-à-dire un décalage négatif,
///     SEEK_DATA le garde (puis EINVAL) et SEEK_HOLE rend la fin, 0 ;
///   - un attribut de sysfs (`generic_file_llseek`, d'une page) : SEEK_END
///     part de 4096 ; SEEK_DATA rend la position si elle est avant la fin,
///     SEEK_HOLE la fin, ENXIO au-delà, la position comparée SANS signe :
///     un décalage négatif est au-delà (ENXIO).
/// Une position négative : EINVAL. (Tout est mesuré, décalages négatifs
/// compris.)
pub fn deplacer(l: Lecture, position: u64, decalage: i64, depuis: u64) -> i64 {
    const EINVAL: i64 = 22;
    const ENXIO: i64 = 6;
    let taille: i64 = if l == Lecture::Attribut { 4096 } else { 0 };
    let nouvelle = match (l, depuis) {
        (_, 0) => Some(decalage),
        (_, 1) => (position as i64).checked_add(decalage),
        (Lecture::Sequence, _) => None,
        (_, 2) => taille.checked_add(decalage),
        (Lecture::Attribut, 3 | 4) if decalage as u64 >= taille as u64 => return -ENXIO,
        (_, 3 | 4) if decalage >= taille => return -ENXIO,
        (_, 3) => Some(decalage),
        (_, _) => Some(taille),
    };
    match nouvelle {
        Some(p) if p >= 0 => p,
        _ => -EINVAL,
    }
}

/// Un bloc du tas où écrire un enregistrement avec `write!`, qui échoue
/// (sans paniquer) quand la mémoire manque.
struct Texte(Vec<u8>);

impl Write for Texte {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.try_reserve(s.len()).map_err(|_| fmt::Error)?;
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// La valeur d'un réglage de /proc/sys, avec son saut de ligne.
fn valeur(source: u32) -> Result<Vec<u8>, Erreur> {
    let mut t = Texte(Vec::new());
    let r = match source {
        // OVERCOMMIT_GUESS : la politique de 6a (memoire.rs).
        OVERCOMMIT_MEMORY => writeln!(t, "0"),
        // La plus petite adresse qu'un programme peut projeter.
        _ => writeln!(t, "{}", ADRESSE_MIN),
    };
    r.map_err(|_| Erreur::ENOMEM)?;
    Ok(t.0)
}

/// L'enregistrement de la source `source` (pour le processus `argument`)
/// qui suit `curseur` : celles de /proc ici, celles de /sys (un seul
/// enregistrement, sa valeur) dans sysfs.rs.
fn produire(source: u32, argument: u32, curseur: u64) -> Result<Enregistrement, Erreur> {
    if let Some(valeur) = sysfs::attribut(source) {
        if curseur > 0 {
            return Ok(None);
        }
        let mut v = Vec::new();
        v.try_reserve_exact(valeur.len()).map_err(|_| Erreur::ENOMEM)?;
        v.extend_from_slice(valeur);
        return Ok(Some((v, 1)));
    }
    // Le dossier d'un processus terminé a été retiré avec ses fichiers ;
    // avec un seul processus à la fois, celui qu'on lit est le processus en
    // cours.
    if processus::essayer_avec(|p| p.pid) != Some(argument) {
        return Ok(None);
    }
    match source {
        MAPS => ligne_maps(curseur),
        STATM if curseur == 0 => statm().map(|t| Some((t, u64::MAX))),
        _ => Ok(None),
    }
}

/// /proc/<pid>/statm : sept nombres de pages, comme `task_statm` de Linux :
/// la taille virtuelle ; le résident (pages à lui, plus pages de fichiers) ;
/// les pages de fichiers ; le code (de la première à la dernière page du
/// segment exécutable du programme : `end_code - start_code`) ; 0 (les
/// bibliothèques, toujours 0 depuis Linux 2.6) ; les données (les zones
/// privées inscriptibles, hors pile, plus la pile : `data_vm + stack_vm`) ;
/// 0. Les compteurs du résident sont ceux que tient déjà l'espace
/// d'adressage (les `rss_stat` de Linux) ; le reste, sommé sur les zones.
fn statm() -> Result<Vec<u8>, Erreur> {
    let (taille, resident, partage, code, donnees) = processus::avec(|p| {
        let m = &p.memoire;
        let (debut, fin) = m.code;
        let code = if fin > debut { (fin.next_multiple_of(4096) - (debut & !4095)) / 4096 } else { 0 };
        let donnees: u64 = m.zones.zones().iter()
            .filter(|z| z.nature == Nature::Pile || z.droits.ecriture)
            .map(|z| z.taille() / 4096)
            .sum();
        let (pages, fichier) = (m.espace.pages() as u64, m.espace.pages_fichier() as u64);
        (m.taille_virtuelle() / 4096, pages + fichier, fichier, code, donnees)
    });
    let mut t = Texte(Vec::new());
    writeln!(t, "{} {} {} {} 0 {} 0", taille, resident, partage, code, donnees).map_err(|_| Erreur::ENOMEM)?;
    Ok(t.0)
}

/// La ligne de /proc/<pid>/maps de la première zone qui finit après
/// `curseur`, et le curseur suivant (sa fin). Le format de Linux
/// (`show_map_vma`, mesuré) :
///   début-fin, en hexadécimal sur 8 chiffres au moins ; les droits (r, w,
///   x, puis p : toutes nos projections sont privées) ; le décalage dans
///   le fichier, en octets ; son périphérique (majeur:mineur, en
///   hexadécimal) et son inode ; puis, s'il y a un nom, des espaces
///   jusqu'à la colonne 72, une de plus, et le nom : le chemin canonique
///   du fichier (suivi de « (deleted) » s'il n'a plus de nom), [heap] pour
///   le tas, [stack] pour la pile. Une zone anonyme sans nom garde
///   l'espace qui suit l'inode, 0.
fn ligne_maps(curseur: u64) -> Result<Enregistrement, Erreur> {
    let Some(z) = processus::avec(|p| p.memoire.zones.zones().iter().find(|z| z.fin > curseur).copied()) else {
        return Ok(None);
    };
    // Le fichier projeté : son chemin (copié : le verrou des fichiers ne
    // reste pas pris), son inode, s'il a encore un nom.
    let fichier = match z.fichier {
        None => None,
        Some(projection) => Some(vfs::avec_systeme(|s, _| -> Result<_, Erreur> {
            let f = s.ouverts.fichier(Fichier::de(projection.fichier));
            let mut chemin = Vec::new();
            let source = if f.chemin.is_empty() { f.nom.octets() } else { &f.chemin[..] };
            chemin.try_reserve_exact(source.len()).map_err(|_| Erreur::ENOMEM)?;
            chemin.extend_from_slice(source);
            let numero = f.numero();
            let efface = numero.is_some_and(|n| s.fs.attributs(n).nlink == 0);
            Ok((chemin, numero.map_or(0, |n| n.0), efface, projection.page * 4096))
        })?),
    };
    let lettre = |oui: bool, c: char| if oui { c } else { '-' };
    let (dev, inode, decalage) = match &fichier {
        Some((_, inode, _, decalage)) => (appels_fichiers::DEV_RACINE, *inode, *decalage),
        None => ((0, 0), 0, 0),
    };
    let mut t = Texte(Vec::new());
    write!(t, "{:08x}-{:08x} {}{}{}p {:08x} {:02x}:{:02x} {} ", z.debut, z.fin, lettre(z.droits.lecture, 'r'),
           lettre(z.droits.ecriture, 'w'), lettre(z.droits.execution, 'x'), decalage, dev.0, dev.1, inode)
        .map_err(|_| Erreur::ENOMEM)?;
    let nom: Option<&[u8]> = match (&fichier, z.nature) {
        (Some((chemin, ..)), _) => Some(chemin),
        (None, Nature::Tas) => Some(b"[heap]"),
        (None, Nature::Pile) => Some(b"[stack]"),
        (None, _) => None,
    };
    let mut ligne = t.0;
    if let Some(nom) = nom {
        let efface = matches!(fichier, Some((_, _, true, _)));
        let place = 72usize.saturating_sub(ligne.len()) + 1 + nom.len() + if efface { 10 } else { 0 } + 1;
        ligne.try_reserve(place).map_err(|_| Erreur::ENOMEM)?;
        while ligne.len() < 72 {
            ligne.push(b' ');
        }
        ligne.push(b' ');
        ligne.extend_from_slice(nom);
        if efface {
            ligne.extend_from_slice(b" (deleted)");
        }
    }
    ligne.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
    ligne.push(b'\n');
    Ok(Some((ligne, z.fin)))
}
