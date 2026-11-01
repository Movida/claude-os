//! /proc : ce que le noyau sait des processus et de lui-même, en fichiers
//! (le procfs de Linux, fs/proc/). Bun y lit sa propre carte de la mémoire
//! (`/proc/self/maps`, par `pthread_getattr_np` de la glibc, qui y cherche
//! sa pile), sa mémoire résidente (`statm`), deux réglages de la mémoire
//! (`/proc/sys/vm/...`).
//!
//! Comme chez Linux, /proc est FABRIQUÉ À LA DEMANDE (depuis 6f) : rien n'y
//! est gardé pour un processus. Sa partie fixe est un système de fichiers
//! du noyau tout fait (fichiers::noyaufs, monté sur /proc au démarrage,
//! vfs.rs) : /proc/sys/vm/overcommit_memory et mmap_min_addr,
//! /proc/sys/fs/pipe-max-size et pipe-user-pages-*, à root ; /proc/self,
//! un lien vers le numéro du processus qui le lit, et /proc/thread-self,
//! vers « <pid>/task/<tid> », le dossier du fil qui le lit. Le reste, la
//! vue de /proc le fabrique le temps d'un appel (`ProcVue`), d'après la
//! table des processus et de leurs fils :
//!   - /proc/<pid>/ pour chaque processus vivant ou zombie (jusqu'à ce
//!     qu'il soit recueilli), à lui (son utilisateur), immuable : `maps`,
//!     `statm`, `comm` (le nom de son fil principal), le lien `exe` vers le
//!     chemin canonique de son exécutable, et `task/<tid>/comm` pour chacun
//!     de ses fils (celui du fil principal reste jusqu'au processus, comme
//!     Linux garde sa tâche) ;
//!   - /proc/<tid> d'un fil qui n'est pas le principal : résolu, sans être
//!     listé, comme Linux (mesuré) ; son `comm` est celui du fil, sa mémoire
//!     celle de son processus.
//! Le numéro d'inode d'une entrée fabriquée dit ce qu'elle est : son genre
//! (8 bits), le numéro du processus ou du fil (32), et un fil (24 : un
//! numéro de Linux tient en 22, pid_max ; les nôtres ne sont jamais
//! repris, et un fil créé après 2^24 tâches ne se verrait pas dans task/,
//! une borne à nous, hors d'atteinte aujourd'hui) ; celles
//! de la partie fixe ont un numéro de moins de 32 bits. Un numéro gardé (un
//! dossier courant, un descripteur ouvert) dont le processus est parti :
//! l'entrée garde son mode et ses liens, et passe à root (`pid_getattr`) ;
//! ENOENT pour y chercher ou la lister, ESRCH pour lire un fichier ouvert
//! (Linux rend ESRCH pour y chercher aussi, par la permission de
//! traverser, `proc_pid_permission` : un écart, que nos systèmes montés ne
//! savent pas dire). Un zombie (Linux : sans mémoire) : ce qui n'est pas
//! un dossier 0555 de son /proc passe à root (`task_dump_owner`). Option
//! écartée, celle de 6b à 6e :
//! des entrées gardées, ajoutées au lancement et à chaque fil, retirées à
//! la fin ; la table grandissait avec les fils (une réserve de 3 Mio pour
//! qu'elle ne grandisse pas pendant un programme), et /proc/<pid>/fd
//! changerait à chaque `open`.
//! Un écart voulu, mesuré sous Linux 6.18 : quand le fil principal a fini
//! mais que d'autres vivent, Linux montre maps vide et statm à zéro (il
//! rattache la mémoire à la tâche du fil principal), nous les vraies
//! valeurs du processus. /proc/self/cgroup est absent, comme sur un Linux
//! construit sans les cgroups (nous n'en avons pas) : libuv le prévoit
//! (« aucune limite »).
//!
//! Les verrous : une vue de /proc travaille sous le verrou des fichiers
//! (celui de la résolution des chemins), et y prend celui de la table des
//! processus, puis d'un processus. L'inverse se fait aussi : le verrou des
//! fichiers pris sous celui d'un processus, pour le dossier de départ d'une
//! résolution (appels_fichiers.rs, rendu avant de résoudre), getcwd, la
//! faute de page d'une projection, et ici `ligne_maps` (le chemin du
//! fichier d'une zone). Aucun de ces endroits ne résout de chemin ni
//! n'entre dans une vue de /proc : le verrou d'un processus n'est jamais
//! pris deux fois, et sur un seul processeur (un `Verrou` coupe les
//! interruptions) ces deux ordres ne peuvent pas s'interbloquer. Avec
//! plusieurs processeurs, il faudra un ordre total (vfs.rs).
//!
//! Le contenu d'un fichier est fabriqué à la lecture, par une « source » :
//! `maps` ligne par ligne (le parcours reprend à l'adresse de fin de la
//! dernière zone écrite, comme `m_start` de Linux : une carte qui change
//! entre deux lectures ne fait ni sauter ni répéter de zone), `statm` d'un
//! seul enregistrement, les réglages en une valeur ; la copie vers le
//! programme, hors de tout verrou (appels_fichiers.rs).

use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::descripteurs::{Donnees, Fichier, Lecture};
use crate::espace_utilisateur::ADRESSE_MIN;
use crate::{appels_fichiers, processus, sysfs, vfs};
use fichiers::chemins::Texte;
use fichiers::montages::{Interne, Monte};
use fichiers::noyaufs::{Cible, Contenu, Enregistrement, Genre, NoyauFs, Proprietes, refus};
use fichiers::tmpfs::{Attributs, DT_DIR, DT_LNK, DT_REG};
use fichiers::{Erreur, Identite, S_IFDIR, S_IFLNK, S_IFREG, Temps};
use zones::{Nature, Zone};

const ESRCH: i64 = 3;

/// Les sources des fichiers de /proc.
const MAPS: u32 = 1;
const STATM: u32 = 2;
const OVERCOMMIT_MEMORY: u32 = 3;
const MMAP_MIN_ADDR: u32 = 4;
/// Le nom d'un fil (/proc/<pid>/comm, task/<tid>/comm : l'argument est le
/// numéro du fil, celui du processus pour son fil principal).
const COMM: u32 = 5;
/// /proc/sys/fs/pipe-max-size, pipe-user-pages-soft, pipe-user-pages-hard
/// (tube.rs).
const PIPE_MAX_SIZE: u32 = 6;
const PIPE_USER_PAGES_SOFT: u32 = 7;
const PIPE_USER_PAGES_HARD: u32 = 8;

/// Le périphérique de procfs (un numéro anonyme, après celui du tmpfs de la
/// racine, 0:20).
const PERIPHERIQUE: (u32, u32) = (0, 21);

/// Le plus d'octets qu'une lecture rend d'un coup (64 Kio : un programme
/// relit pour la suite, comme pour tout fichier).
const LECTURE_MAX: u64 = 64 << 10;

/// La partie fixe de /proc : /proc/sys, puis /proc/self et
/// /proc/thread-self (dans l'ordre où Linux les liste : ses entrées
/// fixes, puis ces deux liens, puis les processus).
pub fn creer(maintenant: Temps) -> Result<NoyauFs, Erreur> {
    let mut p = NoyauFs::new(Genre::Proc, PERIPHERIQUE, 0o555, maintenant)?;
    let racine = p.racine();
    let sys = p.ajouter(racine, b"sys", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let vm = p.ajouter(sys, b"vm", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let reglage = |source| Contenu::Fichier { source, argument: 0 };
    p.ajouter(vm, b"overcommit_memory", 0o644, (0, 0), reglage(OVERCOMMIT_MEMORY), maintenant)?;
    p.ajouter(vm, b"mmap_min_addr", 0o644, (0, 0), reglage(MMAP_MIN_ADDR), maintenant)?;
    let fs = p.ajouter(sys, b"fs", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    p.ajouter(fs, b"pipe-max-size", 0o644, (0, 0), reglage(PIPE_MAX_SIZE), maintenant)?;
    p.ajouter(fs, b"pipe-user-pages-hard", 0o644, (0, 0), reglage(PIPE_USER_PAGES_HARD), maintenant)?;
    p.ajouter(fs, b"pipe-user-pages-soft", 0o644, (0, 0), reglage(PIPE_USER_PAGES_SOFT), maintenant)?;
    p.ajouter(racine, b"self", 0o777, (0, 0), Contenu::Lien(Cible::Lecteur), maintenant)?;
    p.ajouter(racine, b"thread-self", 0o777, (0, 0), Contenu::Lien(Cible::LecteurFil), maintenant)?;
    Ok(p)
}

// Les genres des entrées fabriquées (les 8 bits hauts de leur numéro).
/// /proc/<n> : le dossier d'un processus, ou d'un fil (n).
const PROCESSUS: u64 = 1;
const FICHIER_MAPS: u64 = 2;
const FICHIER_STATM: u64 = 3;
const FICHIER_COMM: u64 = 4;
const LIEN_EXE: u64 = 5;
const DOSSIER_TASK: u64 = 6;
/// task/<tid> (le fil dans les 24 bits bas).
const FIL: u64 = 7;
const FIL_COMM: u64 = 8;

/// Les entrées d'un dossier de processus, dans l'ordre où elles se
/// listent.
const ENTREES_DU_PROCESSUS: [(&[u8], u64); 5] =
    [(b"maps", FICHIER_MAPS), (b"statm", FICHIER_STATM), (b"comm", FICHIER_COMM), (b"exe", LIEN_EXE), (b"task", DOSSIER_TASK)];

/// Le numéro de l'entrée de genre `genre` pour le processus (ou fil) `n`,
/// et le fil `fil`.
fn numero(genre: u64, n: u32, fil: u32) -> u64 {
    genre << 56 | (n as u64) << 24 | fil as u64
}

/// Ce que dit un numéro : son genre (0 : la partie fixe), le processus ou
/// fil, le fil.
fn decoder(i: u64) -> (u64, u32, u32) {
    (i >> 56, (i >> 24) as u32, (i & 0xff_ffff) as u32)
}

/// La position dans /proc du premier processus listé (après les entrées
/// fixes) : `PREMIER_PROCESSUS + pid`, comme le FIRST_PROCESS_ENTRY de Linux.
const PREMIER_PROCESSUS: u64 = 1 << 32;

/// Un nom de /proc qui est un numéro (`name_to_int` : des chiffres, sans
/// zéro devant ; au plus 32 bits).
fn nombre(nom: &[u8]) -> Option<u32> {
    if nom.is_empty() || (nom.len() > 1 && nom[0] == b'0') || !nom.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(nom).ok()?.parse().ok()
}

/// Le processus que montre /proc/<n> : n lui-même, ou le processus du fil n.
fn processus_de(n: u32) -> Option<u32> {
    if processus::existe(n) { Some(n) } else { crate::tache::processus_du_fil(n) }
}

/// Le fil `tid` est-il de ceux de task/ du processus `pid` : le principal
/// (tant que le processus existe), ou un fil vivant.
fn fil_de(pid: u32, tid: u32) -> bool {
    if tid == pid {
        return processus::existe(pid);
    }
    let mut trouve = false;
    processus::pour_chaque_fil(pid, |t| trouve |= t == tid);
    trouve
}

/// La vue de /proc le temps d'un appel, sous le verrou des fichiers : sa
/// partie fixe, et ce qu'elle fabrique des processus.
pub struct ProcVue<'a> {
    fixe: &'a NoyauFs,
}

impl<'a> ProcVue<'a> {
    pub fn new(fixe: &'a NoyauFs) -> ProcVue<'a> {
        ProcVue { fixe }
    }

    /// L'entrée fabriquée `i` existe-t-elle encore (son processus, son fil) ?
    fn existe(&self, i: u64) -> bool {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => true,
            FIL | FIL_COMM => processus_de(n).is_some_and(|p| fil_de(p, fil)),
            _ => processus_de(n).is_some(),
        }
    }

    /// Ce qu'il faut savoir d'une entrée pour la modifier
    /// (noyaufs::refus) ; pour une entrée fabriquée : son mode, son
    /// propriétaire (le processus), son parent. Le dossier d'un processus
    /// et celui d'un fil sont immuables (`proc_pid_instantiate`,
    /// `proc_task_instantiate`), et une écriture y est refusée avant les
    /// droits, comme dans fd/ (sa propre permission) ; pas dans task/, qui
    /// suit ses droits (mesuré : rmdir d'un task/<tid>, EACCES).
    fn proprietes(&self, i: u64) -> Proprietes {
        let (genre, _, _) = decoder(i);
        if genre == 0 {
            return self.fixe.proprietes(i);
        }
        let a = self.attributs(i);
        Proprietes {
            mode: a.mode,
            uid: a.uid,
            gid: a.gid,
            parent: self.parent(i),
            processus: genre != DOSSIER_TASK,
            immuable: matches!(genre, PROCESSUS | FIL) && self.existe(i),
            dans_proc_sys: false,
        }
    }
}

impl Monte for ProcVue<'_> {
    fn racine(&self) -> u64 {
        self.fixe.racine()
    }

    fn peripherique(&self) -> (u32, u32) {
        self.fixe.peripherique()
    }

    fn taille_de_bloc(&self) -> u64 {
        self.fixe.taille_de_bloc()
    }

    /// Celles d'une entrée fabriquée : à l'utilisateur du processus, datées
    /// de son lancement, une taille nulle ; un dossier a deux liens et un
    /// par sous-dossier (le dossier d'un processus : task ; task : un par
    /// fil). Le processus parti : le même mode et les mêmes liens, à
    /// root, sans date ni taille (`pid_getattr`) ; un zombie : ce qui n'est
    /// pas un dossier 0555 à root (`task_dump_owner`). La racine de /proc
    /// compte aussi un lien par processus (`proc_root_getattr`).
    fn attributs(&self, i: u64) -> Attributs {
        let (genre, n, _) = decoder(i);
        if genre == 0 {
            let mut a = self.fixe.attributs(i);
            if i == self.fixe.racine() {
                a.nlink += processus::nombre();
            }
            return a;
        }
        let vu = processus_de(n).and_then(processus::vu_de_proc).filter(|_| self.existe(i));
        let (mode, nlink) = match genre {
            PROCESSUS => (S_IFDIR | 0o555, 3),
            FICHIER_MAPS | FICHIER_STATM => (S_IFREG | 0o444, 1),
            FICHIER_COMM | FIL_COMM => (S_IFREG | 0o644, 1),
            LIEN_EXE => (S_IFLNK | 0o777, 1),
            DOSSIER_TASK => {
                let mut fils = 0;
                if let Some(p) = processus_de(n) {
                    fils = 1;
                    processus::pour_chaque_fil(p, |t| fils += (t != p) as u32);
                }
                (S_IFDIR | 0o555, 2 + fils)
            }
            _ => (S_IFDIR | 0o555, 2),
        };
        let (uid, gid, date) = match vu {
            Some((_, lance, true)) if mode != S_IFDIR | 0o555 => (0, 0, lance),
            Some((identite, lance, _)) => (identite.uid, identite.gid, lance),
            None => (0, 0, Temps::default()),
        };
        Attributs { numero: i, mode, nlink, uid, gid, rdev: (0, 0), taille: 0, blocs: 0, atime: date, mtime: date, ctime: date }
    }

    fn chercher(&self, dossier: u64, nom: &[u8]) -> Option<u64> {
        let (genre, n, fil) = decoder(dossier);
        if genre == 0 {
            if let Some(i) = self.fixe.chercher(dossier, nom) {
                return Some(i);
            }
            if dossier != self.fixe.racine() {
                return None;
            }
            let n = nombre(nom)?;
            return processus_de(n).map(|_| numero(PROCESSUS, n, 0));
        }
        if !self.existe(dossier) {
            return None;
        }
        match genre {
            PROCESSUS => ENTREES_DU_PROCESSUS.iter().find(|(e, _)| *e == nom).map(|&(_, g)| numero(g, n, 0)),
            DOSSIER_TASK => {
                let tid = nombre(nom)?;
                let p = processus_de(n)?;
                (tid < 1 << 24 && fil_de(p, tid)).then(|| numero(FIL, n, tid))
            }
            FIL if nom == b"comm" => Some(numero(FIL_COMM, n, fil)),
            _ => None,
        }
    }

    fn parent(&self, i: u64) -> u64 {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => self.fixe.parent(i),
            PROCESSUS => self.fixe.racine(),
            FIL => numero(DOSSIER_TASK, n, 0),
            FIL_COMM => numero(FIL, n, fil),
            _ => numero(PROCESSUS, n, 0),
        }
    }

    fn nom(&self, i: u64) -> Texte<'_> {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => self.fixe.nom(i),
            PROCESSUS => Texte::nombre(n as u64),
            FIL => Texte::nombre(fil as u64),
            FIL_COMM => Texte::Emprunte(b"comm"),
            g => Texte::Emprunte(ENTREES_DU_PROCESSUS.iter().find(|&&(_, x)| x == g).map_or(&b""[..], |&(e, _)| e)),
        }
    }

    fn cible<'b>(&'b self, lien: u64, lecteur: &'b [u8], fil: &'b [u8]) -> Texte<'b> {
        match decoder(lien) {
            (0, _, _) => self.fixe.cible(lien, lecteur, fil),
            (LIEN_EXE, n, _) => match processus_de(n).and_then(processus::exe) {
                Some(exe) => Texte::Long(exe),
                None => Texte::Emprunte(&[]),
            },
            _ => Texte::Emprunte(&[]),
        }
    }

    /// La racine : « . », « .. », les entrées fixes, puis les processus (à
    /// la position PREMIER_PROCESSUS + pid) ; le dossier d'un processus, ses
    /// cinq entrées ; task/, ses fils (à la position 3 + tid) ; un fil, son
    /// comm. Un dossier dont le processus est parti : ENOENT.
    fn lire_dossier(&self, dossier: u64, position: u64, entree: &mut dyn FnMut(&[u8], u64, u8, u64) -> bool)
        -> Result<(), Erreur> {
        let (genre, n, fil) = decoder(dossier);
        if genre == 0 {
            let mut encore = true;
            if position < PREMIER_PROCESSUS {
                self.fixe.lire_dossier(dossier, position, &mut |nom, i, t, suivante| {
                    encore = entree(nom, i, t, suivante);
                    encore
                })?;
            }
            if !encore || dossier != self.fixe.racine() {
                return Ok(());
            }
            let mut depuis = position.max(PREMIER_PROCESSUS) - PREMIER_PROCESSUS;
            while let Some(pid) = processus::pid_suivant(depuis.min(u32::MAX as u64) as u32) {
                let nom = Texte::nombre(pid as u64);
                if !entree(&nom, numero(PROCESSUS, pid, 0), DT_DIR, PREMIER_PROCESSUS + pid as u64 + 1) {
                    break;
                }
                depuis = pid as u64 + 1;
            }
            return Ok(());
        }
        if !self.existe(dossier) {
            return Err(Erreur::ENOENT);
        }
        if !matches!(genre, PROCESSUS | DOSSIER_TASK | FIL) {
            return Err(Erreur::ENOTDIR);
        }
        if position == 0 && !entree(b".", dossier, DT_DIR, 1) {
            return Ok(());
        }
        if position <= 1 && !entree(b"..", self.parent(dossier), DT_DIR, 2) {
            return Ok(());
        }
        match genre {
            PROCESSUS => {
                for (k, &(nom, g)) in ENTREES_DU_PROCESSUS.iter().enumerate().skip((position.max(2) - 2) as usize) {
                    let t = match g {
                        LIEN_EXE => DT_LNK,
                        DOSSIER_TASK => DT_DIR,
                        _ => DT_REG,
                    };
                    if !entree(nom, numero(g, n, 0), t, k as u64 + 3) {
                        break;
                    }
                }
            }
            DOSSIER_TASK => {
                let Some(p) = processus_de(n) else { return Ok(()) };
                // Le fil principal d'abord, puis les autres, dans l'ordre de
                // leurs numéros (ils ne font que croître).
                let suivant = |depuis: u64| -> Option<u32> {
                    let mut meilleur: Option<u32> = None;
                    if p as u64 + 3 > depuis {
                        meilleur = Some(p);
                    }
                    processus::pour_chaque_fil(p, |t| {
                        if t != p && t as u64 + 3 > depuis && meilleur.is_none_or(|m| t < m) {
                            meilleur = Some(t);
                        }
                    });
                    meilleur
                };
                let mut depuis = position;
                while let Some(t) = suivant(depuis) {
                    if t >= 1 << 24 {
                        break;
                    }
                    let nom = Texte::nombre(t as u64);
                    if !entree(&nom, numero(FIL, n, t), DT_DIR, t as u64 + 3) {
                        break;
                    }
                    depuis = t as u64 + 3;
                }
            }
            _ => {
                if position <= 2 {
                    let _ = entree(b"comm", numero(FIL_COMM, n, fil), DT_REG, 3);
                }
            }
        }
        Ok(())
    }

    /// La source d'un fichier : maps et statm du processus du numéro (celui
    /// d'un fil aussi), comm du fil (le processus : son fil principal).
    fn contenu(&self, i: u64) -> Option<(u32, u32)> {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => self.fixe.contenu(i),
            FICHIER_MAPS => Some((MAPS, processus_de(n).unwrap_or(n))),
            FICHIER_STATM => Some((STATM, processus_de(n).unwrap_or(n))),
            FICHIER_COMM => Some((COMM, n)),
            FIL_COMM => Some((COMM, fil)),
            _ => None,
        }
    }

    fn refuser(&self, qui: Identite, m: Interne) -> Result<(), Erreur> {
        refus(Genre::Proc, qui, m, |i| self.proprietes(i))
    }
}

/// Comment se lit la source `source` d'un système du noyau : les
/// séquences et les valeurs de /proc, les attributs de /sys.
pub fn lecture(source: u32) -> Lecture {
    match source {
        OVERCOMMIT_MEMORY | MMAP_MIN_ADDR | PIPE_MAX_SIZE | PIPE_USER_PAGES_SOFT | PIPE_USER_PAGES_HARD => Lecture::Valeur,
        MAPS | STATM | COMM => Lecture::Sequence,
        _ => Lecture::Attribut,
    }
}

/// Les données du fichier ouvert d'une source.
pub fn donnees(source: u32, argument: u32) -> Donnees {
    Donnees::Noyau { source, argument, sequence: Default::default() }
}

/// La source du fichier ouvert `f` (d'un système du noyau), et son argument.
pub fn source(f: Fichier) -> (u32, u32) {
    vfs::avec_systeme(|s, _| match &s.ouverts.fichier(f).donnees {
        Donnees::Noyau { source, argument, .. } => (*source, *argument),
        _ => unreachable!("un fichier du noyau sans source"),
    })
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
    // Le fichier d'un processus recueilli (sa tâche est morte, et init l'a
    // retiré de la table), ou d'un fil fini : ESRCH, comme Linux (mesuré).
    // Celui d'un zombie se lit encore (voir `produire`).
    let disparu = match source {
        MAPS | STATM => !processus::existe(argument),
        COMM => nom(argument).is_none(),
        _ => false,
    };
    if disparu {
        vfs::avec_systeme(|s, _| {
            if let Donnees::Noyau { sequence: place, .. } = &mut s.ouverts.fichier(f).donnees {
                *place = sequence;
            }
        });
        return Err(-ESRCH);
    }
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
struct Ecrit(Vec<u8>);

impl Write for Ecrit {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.try_reserve(s.len()).map_err(|_| fmt::Error)?;
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// La valeur d'un réglage de /proc/sys, avec son saut de ligne.
fn valeur(source: u32) -> Result<Vec<u8>, Erreur> {
    let mut t = Ecrit(Vec::new());
    let r = match source {
        // OVERCOMMIT_GUESS : la politique de 6a (memoire.rs).
        OVERCOMMIT_MEMORY => writeln!(t, "0"),
        PIPE_MAX_SIZE => writeln!(t, "{}", crate::tube::TAILLE_MAX),
        PIPE_USER_PAGES_SOFT => writeln!(t, "{}", crate::tube::PAGES_UTILISATEUR_DOUCE),
        PIPE_USER_PAGES_HARD => writeln!(t, "{}", crate::tube::PAGES_UTILISATEUR_DURE),
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
    // Le processus `argument`. Un zombie (sa tâche est morte, il attend
    // d'être recueilli) n'a plus de mémoire : maps vide, statm à zéro,
    // comme Linux (mesuré).
    match source {
        MAPS => ligne_maps(argument, curseur),
        STATM if curseur == 0 => statm(argument).map(|t| Some((t, u64::MAX))),
        COMM if curseur == 0 => comm(argument).map(|t| Some((t, u64::MAX))),
        _ => Ok(None),
    }
}

/// Le nom du fil `tid` : celui de sa tâche si elle vit ; sinon, pour un fil
/// principal, celui que garde son processus (un zombie, ou dont seul le fil
/// principal a fini : Linux garde sa tâche jusqu'au bout). None pour un fil
/// fini (ESRCH, `lire`).
fn nom(tid: u32) -> Option<crate::programmes::NomCourt> {
    crate::tache::nom_du_fil(tid).or_else(|| processus::nom_du_principal(tid))
}

/// /proc/.../comm : le nom du fil, avec un saut de ligne (`comm_show`) ;
/// vide si le fil vient de finir.
fn comm(tid: u32) -> Result<Vec<u8>, Erreur> {
    let nom = nom(tid).unwrap_or(crate::programmes::NomCourt::VIDE);
    let mut t = Vec::new();
    t.try_reserve_exact(nom.octets().len() + 1).map_err(|_| Erreur::ENOMEM)?;
    t.extend_from_slice(nom.octets());
    t.push(b'\n');
    Ok(t)
}

/// La source `source` s'écrit-elle (le fichier s'ouvre-t-il en écriture,
/// si ses droits le permettent) ? Seul `comm`, parmi les nôtres.
pub fn ecrivable(source: u32) -> bool {
    source == COMM
}

/// Écrit `octets` dans le fichier de la source `source` (pour `argument`),
/// à n'importe quelle position : rend le nombre d'octets pris, ou -errno.
/// Pour `comm`, comme `comm_write` (mesuré sous Linux 6.18) : les 15
/// premiers octets deviennent le nom du fil, tels quels jusqu'au premier
/// octet nul (un saut de ligne écrit en fait partie ; rien écrit : un nom
/// vide), et tout compte comme écrit ; seul un fil du même processus peut être renommé (EINVAL sinon),
/// un fil fini : ESRCH.
pub fn ecrire(source: u32, argument: u32, octets: &[u8], longueur: u64) -> Result<u64, i64> {
    const EINVAL: i64 = 22;
    if source != COMM {
        return Err(-EINVAL);
    }
    let nom = octets.split(|&o| o == 0).next().unwrap_or(&[]);
    match crate::tache::renommer_fil(argument, crate::programmes::NomCourt::de(nom)) {
        Ok(()) => Ok(longueur),
        Err(crate::tache::RefusNom::Absent) => Err(-ESRCH),
        Err(crate::tache::RefusNom::AutreProcessus) => Err(-EINVAL),
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
fn statm(pid: u32) -> Result<Vec<u8>, Erreur> {
    let (taille, resident, partage, code, donnees) = processus::avec_pid(pid, |p| {
        let m = &p.memoire;
        let (debut, fin) = m.code;
        let code = if fin > debut { (fin.next_multiple_of(4096) - (debut & !4095)) / 4096 } else { 0 };
        let donnees: u64 = m.zones.zones().iter()
            .filter(|z| z.nature == Nature::Pile || z.droits.ecriture)
            .map(|z| z.taille() / 4096)
            .sum();
        let (pages, fichier) = (m.espace.pages() as u64, m.espace.pages_fichier() as u64);
        (m.taille_virtuelle() / 4096, pages + fichier, fichier, code, donnees)
    }).unwrap_or((0, 0, 0, 0, 0));
    let mut t = Ecrit(Vec::new());
    writeln!(t, "{} {} {} {} 0 {} 0", taille, resident, partage, code, donnees).map_err(|_| Erreur::ENOMEM)?;
    Ok(t.0)
}

/// Ce que montre maps du fichier que projette la zone `z` (s'il y en a un) :
/// son chemin, son inode, s'il est effacé, et le décalage de la projection
/// en octets. Sous le verrou du processus de la zone (`ligne_maps`).
fn fichier_de_zone(z: &Zone) -> Result<Option<(Vec<u8>, u32, bool, u64)>, Erreur> {
    let Some(projection) = z.fichier else { return Ok(None) };
    vfs::avec_systeme(|s, _| {
        let f = s.ouverts.fichier(Fichier::de(projection.fichier));
        let mut chemin = Vec::new();
        let source = if f.chemin.is_empty() { f.nom.octets() } else { &f.chemin[..] };
        chemin.try_reserve_exact(source.len()).map_err(|_| Erreur::ENOMEM)?;
        chemin.extend_from_slice(source);
        let numero = f.numero();
        let efface = numero.is_some_and(|n| s.fs.attributs(n).nlink == 0);
        Ok(Some((chemin, numero.map_or(0, |n| n.0), efface, projection.page * 4096)))
    })
}

/// La ligne de /proc/<pid>/maps du processus `pid` de la première zone qui finit après
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
fn ligne_maps(pid: u32, curseur: u64) -> Result<Enregistrement, Erreur> {
    // La zone, et le fichier qu'elle projette : son chemin (copié : les
    // verrous ne restent pas pris), son inode, s'il a encore un nom. Lus
    // sous le verrou du processus, celui des fichiers pris dedans : la zone
    // tient son fichier tant qu'elle existe, mais le processus peut la
    // retirer (munmap) dès qu'on rend son verrou, et le numéro du fichier
    // servir à un autre. Linux lit de même maps sous le verrou de la
    // mémoire du processus (`mmap_read_lock`).
    let Some(lu) = processus::avec_pid(pid, |p| {
        let z = p.memoire.zones.zones().iter().find(|z| z.fin > curseur).copied()?;
        Some(fichier_de_zone(&z).map(|fichier| (z, fichier)))
    })
    .flatten() else {
        return Ok(None);
    };
    let (z, fichier) = lu?;
    let lettre = |oui: bool, c: char| if oui { c } else { '-' };
    let (dev, inode, decalage) = match &fichier {
        Some((_, inode, _, decalage)) => (appels_fichiers::DEV_RACINE, *inode, *decalage),
        None => ((0, 0), 0, 0),
    };
    let mut t = Ecrit(Vec::new());
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
