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
//! /proc/sys/fs/pipe-max-size et pipe-user-pages-*, à root ; /proc/net
//! (arp, dev, pnp, route : le réseau, 6g, reseau/proc.rs) ; /proc/version
//! (qui est le noyau, et qui l'a construit) ; /proc/self,
//! un lien vers le numéro du processus qui le lit, et /proc/thread-self,
//! vers « <pid>/task/<tid> », le dossier du fil qui le lit. Le reste, la
//! vue de /proc le fabrique le temps d'un appel (`ProcVue`), d'après la
//! table des processus et de leurs fils :
//!   - /proc/<pid>/ pour chaque processus vivant ou zombie (jusqu'à ce
//!     qu'il soit recueilli), à lui (son utilisateur), immuable : `maps`,
//!     `statm`, `stat` et `status` (son état, ses comptes, ses signaux, sa
//!     mémoire : ce qu'y lisent ps, top, les bibliothèques qui comptent les
//!     fils d'un processus), `comm` (le nom de son fil principal), le lien
//!     `exe` vers son exécutable, `task/<tid>/` pour chacun de ses fils,
//!     avec `status`, `comm` et `stat` (celui du fil principal reste
//!     jusqu'au processus, comme Linux garde sa tâche), et `fd/<n>` pour
//!     chacun de ses descripteurs ;
//!   - /proc/<tid> d'un fil qui n'est pas le principal : résolu, sans être
//!     listé, comme Linux (mesuré) ; son `comm` est celui du fil, sa mémoire
//!     celle de son processus.
//! /proc/<n> montre la TÂCHE n, comme Linux : sa mémoire (maps, statm,
//! exe), ses descripteurs (fd/) tant qu'elle les a. Un fil qui finit les
//! quitte (`exit_mm`, `exit_files` : tache::a_sa_memoire) ; un fil principal
//! parti avant les autres n'en a plus, et son /proc/<pid> dit alors ce
//! qu'en dit Linux (mesuré sous 6.18) : maps vide, statm à zéro, ni exe
//! (ENOENT) ni descripteur (fd/ vide, à root), alors que les fils vivants
//! montrent tout dans /proc/<tid>. Option écartée, celle de 6f à 6j (un
//! « écart voulu ») : la mémoire du processus pour /proc/<pid> tant
//! qu'un fil vit ; un programme qui surveille un processus par son pid
//! verrait autre chose que sous Linux.
//! `exe` et les liens de fd/ sont des LIENS MAGIQUES, comme chez Linux :
//! les suivre mène droit au fichier (l'exécutable, le fichier ouvert),
//! même effacé ou sans nom ; leur texte n'est que son chemin, pour
//! readlink.
//! Le numéro d'inode d'une entrée fabriquée dit ce qu'elle est : son genre
//! (8 bits), le numéro du processus ou du fil (32), et un fil ou un
//! descripteur (24 : un numéro de Linux tient en 22, pid_max ; les nôtres
//! ne sont jamais repris, et un fil créé après 2^24 tâches ne se verrait
//! pas dans task/, une borne à nous, hors d'atteinte aujourd'hui) ; celles
//! de la partie fixe ont un numéro de moins de 32 bits. Un numéro gardé (un
//! dossier courant, un descripteur ouvert) dont le processus est parti :
//! l'entrée garde son mode et ses liens, et passe à root (`pid_getattr`) ;
//! ESRCH pour y chercher (la permission de traverser, `proc_pid_permission`,
//! dite par `traverser` depuis les soldes d'avant 6k) ou pour lire un
//! fichier ouvert, ENOENT pour la lister. Une tâche sans mémoire (un
//! zombie, un fil principal parti) n'a plus d'`exe`, et ce qui n'est pas
//! un dossier 0555 de son /proc passe à root (`task_dump_owner`) : fd/ ne
//! se lit plus que par les fils de son processus (`proc_fd_permission`,
//! `permis_en_plus`), vide. Option écartée, celle de 6b à 6e :
//! des entrées gardées, ajoutées au lancement et à chaque fil, retirées à
//! la fin ; la table grandissait avec les fils (une réserve de 3 Mio pour
//! qu'elle ne grandisse pas pendant un programme), et /proc/<pid>/fd
//! changerait à chaque `open`.
//! /proc/self/cgroup est absent, comme sur un Linux
//! construit sans les cgroups (nous n'en avons pas) : libuv le prévoit
//! (« aucune limite »).
//!
//! Les verrous : une vue de /proc travaille sous le verrou des fichiers
//! (celui de la résolution des chemins), et n'y lit un processus que par
//! les verrous du dernier niveau de l'ordre (processus.rs) : la table des
//! processus (son existence, son identité, son nom, son exécutable), ses
//! descripteurs sous leur propre verrou (fd/ : `processus::descripteur`),
//! ses fils par la table des tâches (task/ : `processus::pour_chaque_fil`).
//! Jamais le verrou du processus : il se prend AVANT celui des fichiers
//! (le dossier de départ d'une résolution, appels_fichiers.rs, rendu avant
//! de résoudre ; getcwd), et deux processeurs qui prendraient les deux dans
//! les deux ordres s'attendraient pour toujours (jusqu'à 6i, la vue le
//! prenait : sans danger sur un seul processeur, dont le premier `Verrou`
//! coupait les interruptions). Le verrou des fichiers se prend aussi sous
//! la mémoire d'un processus (un verrou qui dort, processus.rs), pour la
//! faute de page d'une projection et ici `ligne_maps` (le chemin du fichier
//! d'une zone) ; aucun de ces endroits ne résout de chemin ni n'entre dans
//! une vue de /proc.
//!
//! Le contenu d'un fichier est fabriqué à la lecture, par une « source » :
//! `maps` ligne par ligne (le parcours reprend à l'adresse de fin de la
//! dernière zone écrite, comme `m_start` de Linux : une carte qui change
//! entre deux lectures ne fait ni sauter ni répéter de zone), `statm` d'un
//! seul enregistrement, les réglages en une valeur ; la copie vers le
//! programme, hors de tout verrou (appels_fichiers.rs).

use alloc::vec::Vec;
use core::fmt::{self, Write};

use crate::descripteurs::{Donnees, Fichier, FichierOuvert, Lecture, Ouverts, Sorte};
use crate::espace_utilisateur::ADRESSE_MIN;
use crate::faillible::{self, VecFaillible};
use crate::memoire::Resume;
use crate::partage::Arc;
use crate::tache::Tache;
use crate::{appels_fichiers, processus, sysfs, vfs};
use fichiers::chemins::Texte;
use fichiers::montages::{Interne, Monte, Objet};
use fichiers::noyaufs::{Cible, Contenu, Enregistrement, Genre, NoyauFs, Proprietes, refus};
use fichiers::tmpfs::{Attributs, DT_DIR, DT_LNK, DT_REG, Tmpfs};
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
/// /proc/version (`banniere`).
const BANNIERE: u32 = 9;
/// /proc/<n>/stat (le processus entier, le `whole` de Linux), task/<tid>/stat
/// (le fil seul), et status (les deux) : l'argument est la tâche.
const STAT: u32 = 40;
const STAT_FIL: u32 = 41;
const STATUS: u32 = 42;
/// maps ouvert quand sa tâche n'avait plus de mémoire : il reste vide
/// (Linux prend la mémoire de la tâche à l'ouverture, `proc_mem_open`, et
/// la garde : maps ouvert avant la fin du fil principal se lit encore
/// après, tant que le processus a sa mémoire).
const MAPS_SANS_MEMOIRE: u32 = 39;
/// /proc/sys/fs/pipe-max-size, pipe-user-pages-soft, pipe-user-pages-hard
/// (tube.rs).
const PIPE_MAX_SIZE: u32 = 6;
const PIPE_USER_PAGES_SOFT: u32 = 7;
const PIPE_USER_PAGES_HARD: u32 = 8;
/// /proc/sys/kernel/random/ (6h) : boot_id, uuid, entropy_avail, poolsize
/// (après les numéros de /sys, sysfs.rs : 10 à 13).
const RANDOM_BOOT_ID: u32 = 30;
const RANDOM_UUID: u32 = 31;
const RANDOM_ENTROPY_AVAIL: u32 = 32;
const RANDOM_POOLSIZE: u32 = 33;
/// write_wakeup_threshold et urandom_min_reseed_secs : sans effet depuis
/// Linux 5.18, mais montrés à tous (256 et 60).
const RANDOM_WAKEUP: u32 = 34;
const RANDOM_RESEED: u32 = 35;
/// /proc/sys/fs/inotify (6i) : max_queued_events, max_user_instances,
/// max_user_watches (surveillance.rs).
const INOTIFY_EVENEMENTS: u32 = 36;
const INOTIFY_INSTANCES: u32 = 37;
const INOTIFY_SURVEILLANCES: u32 = 38;
/// /proc/sys/net (6h, reseau/proc.rs, `REGLAGES`) : ce numéro, plus le rang du réglage.
const SYSCTL_NET: u32 = 100;
/// /proc/net/pnp, route, dev et arp (6g, reseau/proc.rs).
const NET_PNP: u32 = 20;
const NET_ROUTE: u32 = 21;
const NET_DEV: u32 = 22;
const NET_ARP: u32 = 23;
const NET_TCP: u32 = 24;
const NET_UNIX: u32 = 25;
/// /proc/net/snmp (les soldes d'avant 6k, reseau/snmp.rs).
const NET_SNMP: u32 = 26;
/// /proc/net/igmp, mcfilter et dev_mcast (les soldes d'avant 6k, reseau/multidiffusion.rs).
const NET_IGMP: u32 = 27;
const NET_MCFILTER: u32 = 28;
const NET_DEV_MCAST: u32 = 29;

/// Le périphérique de procfs (un numéro anonyme, après celui du tmpfs de la
/// racine, 0:20).
const PERIPHERIQUE: (u32, u32) = (0, 21);

/// Le plus d'octets qu'une lecture rend d'un coup (64 Kio : un programme
/// relit pour la suite, comme pour tout fichier).
const LECTURE_MAX: u64 = 64 << 10;

/// La partie fixe de /proc : /proc/sys, /proc/net, puis /proc/self et
/// /proc/thread-self. Chaque entrée prend sa place dans l'ordre où Linux
/// liste son dossier (noyaufs.rs : par la longueur du nom dans /proc et
/// /proc/net, par ses octets dans /proc/sys ; self et thread-self après
/// les autres, puis les processus) ; ces deux liens s'ajoutent en dernier,
/// dans leur ordre.
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
    // Les limites d'inotify (`inotify_table`), dans l'ordre de Linux, en
    // 0644 à root : root seul pourrait les changer.
    let inotify = p.ajouter(fs, b"inotify", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    p.ajouter(inotify, b"max_queued_events", 0o644, (0, 0), reglage(INOTIFY_EVENEMENTS), maintenant)?;
    p.ajouter(inotify, b"max_user_instances", 0o644, (0, 0), reglage(INOTIFY_INSTANCES), maintenant)?;
    p.ajouter(inotify, b"max_user_watches", 0o644, (0, 0), reglage(INOTIFY_SURVEILLANCES), maintenant)?;
    // Le générateur aléatoire (le `random_table` de drivers/char/random.c) :
    // ses six fichiers ; les deux réglages sans effet depuis Linux 5.18,
    // que root peut y écrire, en 0644 à root comme chez lui (nos programmes
    // ne sont pas root : EACCES ; un écrit de root rendrait EINVAL, comme
    // pour tout réglage de /proc/sys chez nous).
    let kernel = p.ajouter(sys, b"kernel", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let random = p.ajouter(kernel, b"random", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    p.ajouter(random, b"boot_id", 0o444, (0, 0), reglage(RANDOM_BOOT_ID), maintenant)?;
    p.ajouter(random, b"entropy_avail", 0o444, (0, 0), reglage(RANDOM_ENTROPY_AVAIL), maintenant)?;
    p.ajouter(random, b"poolsize", 0o444, (0, 0), reglage(RANDOM_POOLSIZE), maintenant)?;
    p.ajouter(random, b"urandom_min_reseed_secs", 0o644, (0, 0), reglage(RANDOM_RESEED), maintenant)?;
    p.ajouter(random, b"uuid", 0o444, (0, 0), reglage(RANDOM_UUID), maintenant)?;
    p.ajouter(random, b"write_wakeup_threshold", 0o644, (0, 0), reglage(RANDOM_WAKEUP), maintenant)?;
    // /proc/sys/net : les réglages du réseau, 0644 à root comme chez Linux (nos programmes
    // ne sont pas root : EACCES pour y écrire, et rien n'y change).
    let net_sys = p.ajouter(sys, b"net", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let core = p.ajouter(net_sys, b"core", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let ipv4 = p.ajouter(net_sys, b"ipv4", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let route = p.ajouter(ipv4, b"route", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    for (k, r) in crate::reseau::proc::REGLAGES.iter().enumerate() {
        let dossier = match r.dossier {
            crate::reseau::proc::Dossier::Core => core,
            crate::reseau::proc::Dossier::Ipv4 => ipv4,
            crate::reseau::proc::Dossier::Route => route,
        };
        p.ajouter(dossier, r.nom, r.droits, (0, 0), reglage(SYSCTL_NET + k as u32), maintenant)?;
    }
    // /proc/net : chez Linux, un lien vers self/net, le réseau de l'espace
    // de noms du processus qui lit ; sans espaces de noms (un seul réseau),
    // un dossier de la partie fixe : un écart, qu'aucun programme ne voit
    // en lisant /proc/net/route ou pnp.
    let net = p.ajouter(racine, b"net", 0o555, (0, 0), Contenu::Dossier, maintenant)?;
    let net_fichier = |source| Contenu::Fichier { source, argument: 0 };
    p.ajouter(net, b"arp", 0o444, (0, 0), net_fichier(NET_ARP), maintenant)?;
    p.ajouter(net, b"dev", 0o444, (0, 0), net_fichier(NET_DEV), maintenant)?;
    p.ajouter(net, b"dev_mcast", 0o444, (0, 0), net_fichier(NET_DEV_MCAST), maintenant)?;
    p.ajouter(net, b"igmp", 0o444, (0, 0), net_fichier(NET_IGMP), maintenant)?;
    p.ajouter(net, b"mcfilter", 0o444, (0, 0), net_fichier(NET_MCFILTER), maintenant)?;
    p.ajouter(net, b"pnp", 0o444, (0, 0), net_fichier(NET_PNP), maintenant)?;
    p.ajouter(net, b"route", 0o444, (0, 0), net_fichier(NET_ROUTE), maintenant)?;
    p.ajouter(net, b"snmp", 0o444, (0, 0), net_fichier(NET_SNMP), maintenant)?;
    p.ajouter(net, b"tcp", 0o444, (0, 0), net_fichier(NET_TCP), maintenant)?;
    p.ajouter(net, b"unix", 0o444, (0, 0), net_fichier(NET_UNIX), maintenant)?;
    p.ajouter(racine, b"version", 0o444, (0, 0), Contenu::Fichier { source: BANNIERE, argument: 0 }, maintenant)?;
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
/// fd/, et fd/<n> (le descripteur dans les 24 bits bas : nr_open, 2^20,
/// y tient).
const DOSSIER_FD: u64 = 9;
const LIEN_FD: u64 = 10;
const FICHIER_STATUS: u64 = 11;
const FICHIER_STAT: u64 = 12;
const FIL_STATUS: u64 = 13;
const FIL_STAT: u64 = 14;

/// Les entrées d'un dossier de processus, dans l'ordre où elles se
/// listent : celui de Linux, le rang dans son tableau `tgid_base_stuff`
/// (mesuré : task, fd, ..., status, ..., comm, ..., stat, statm, maps, ...,
/// exe).
const ENTREES_DU_PROCESSUS: [(&[u8], u64); 8] = [(b"task", DOSSIER_TASK), (b"fd", DOSSIER_FD), (b"status", FICHIER_STATUS),
                                                 (b"comm", FICHIER_COMM), (b"stat", FICHIER_STAT), (b"statm", FICHIER_STATM),
                                                 (b"maps", FICHIER_MAPS), (b"exe", LIEN_EXE)];

/// Celles du dossier d'un fil (task/<tid>), dans l'ordre de `tid_base_stuff`.
/// Linux y met aussi fd/, statm, maps, exe... : pas encore chez nous (aucun
/// programme ne les y cherche).
const ENTREES_DU_FIL: [(&[u8], u64); 3] = [(b"status", FIL_STATUS), (b"comm", FIL_COMM), (b"stat", FIL_STAT)];

/// Les genres des fichiers d'un fil.
fn est_du_fil(genre: u64) -> bool {
    matches!(genre, FIL_COMM | FIL_STATUS | FIL_STAT)
}

/// Les droits d'un lien de fd/ : r-x pour un fichier ouvert en lecture,
/// -wx en écriture, les deux s'il fait les deux, rien pour un O_PATH (le
/// `proc_fd_instantiate` de Linux, mesuré : 0500, 0300, 0700, 0). Ni l'un
/// ni l'autre pour un O_ACCMODE de 3 (OPEN_FMODE de Linux : (3 + 1) & 3,
/// mesuré : 0), qui nous permet pourtant de lire et d'écrire (un écart
/// d'appels_fichiers.rs).
fn droits_du_lien(f: &FichierOuvert) -> u32 {
    if f.sorte == Sorte::Chemin || f.drapeaux & 3 == 3 {
        return 0;
    }
    (if f.lecture { 0o500 } else { 0 }) | (if f.ecriture { 0o300 } else { 0 })
}

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

/// Le processus dont /proc/<n>/exe montre l'exécutable : celui de la tâche
/// n, si elle a encore sa mémoire (Linux le trouve par elle,
/// `get_task_exe_file` : ENOENT sans).
fn exe_de(n: u32) -> Option<u32> {
    processus_de(n).filter(|_| crate::tache::a_sa_memoire(n))
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
/// partie fixe, et ce qu'elle fabrique des processus ; la table des
/// fichiers ouverts et le tmpfs, pour fd/ (le chemin d'un fichier ouvert,
/// s'il est effacé).
pub struct ProcVue<'a> {
    fixe: &'a NoyauFs,
    ouverts: &'a Ouverts,
    fs: &'a Tmpfs,
}

impl<'a> ProcVue<'a> {
    pub fn new(fixe: &'a NoyauFs, ouverts: &'a Ouverts, fs: &'a Tmpfs) -> ProcVue<'a> {
        ProcVue { fixe, ouverts, fs }
    }

    /// Le fichier ouvert du lien fd/<fd> de la tâche `n` (le processus, ou
    /// un fil), si elle a encore ses descripteurs.
    fn ouvert(&self, n: u32, fd: u32) -> Option<&'a FichierOuvert> {
        let pid = processus_de(n).filter(|_| crate::tache::a_sa_memoire(n))?;
        self.ouverts.voir(processus::descripteur(pid, fd as u64)?)
    }

    /// L'entrée fabriquée `i` existe-t-elle encore (son processus, son fil) ?
    fn existe(&self, i: u64) -> bool {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => true,
            g if g == FIL || est_du_fil(g) => processus_de(n).is_some_and(|p| fil_de(p, fil)),
            LIEN_FD => self.ouvert(n, fil).is_some(),
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
        let (genre, n, _) = decoder(i);
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
            // Le processus qui demande : celui de la tâche courante.
            fd_du_lecteur: genre == DOSSIER_FD
                && processus_de(n).is_some_and(|p| processus_de(crate::tache::courante().tid()) == Some(p)),
        }
    }
}

impl Monte for ProcVue<'_> {
    fn racine(&self) -> u64 {
        self.fixe.racine()
    }

    /// Chercher dans le dossier d'un processus parti (/proc/<n>), ou dans
    /// son task/ : ESRCH, avant les droits (le `proc_pid_permission` de
    /// Linux, qui ne trouve plus la tâche). Seuls ces deux-là l'ont :
    /// task/<tid> (aucune permission) cherche, et ne trouve plus rien
    /// (ENOENT) ; fd/ a ses droits ordinaires (0500), puis ENOENT. Un écart
    /// voulu : sous Linux, l'inode de fd/ garde le propriétaire du processus
    /// vivant, qui passe ; nos attributs se calculent à chaque fois, et ceux
    /// d'un processus parti sont à root : EACCES pour son ancien
    /// propriétaire (garder l'identité de chaque processus recueilli, pour ce
    /// seul cas, coûterait plus qu'il n'apporte). Les lister rend toujours
    /// ENOENT (`proc_pident_readdir`).
    fn traverser(&self, dossier: u64) -> Result<(), Erreur> {
        if matches!(decoder(dossier).0, PROCESSUS | DOSSIER_TASK) && !self.existe(dossier) {
            return Err(Erreur::ESRCH);
        }
        Ok(())
    }

    /// fd/ d'un processus se lit et se traverse par chacun de ses fils,
    /// même quand ses droits le refusent (le `proc_fd_permission` de
    /// Linux : `generic_permission`, puis le même groupe de fils) : fd/ d'un
    /// fil principal parti, à root, reste lisible des autres (vide).
    fn permis_en_plus(&self, i: u64, _masque: u32) -> bool {
        decoder(i).0 == DOSSIER_FD && self.proprietes(i).fd_du_lecteur
    }

    fn peripherique(&self) -> (u32, u32) {
        self.fixe.peripherique()
    }

    fn taille_de_bloc(&self) -> u64 {
        self.fixe.taille_de_bloc()
    }

    /// Celles d'une entrée fabriquée : à l'utilisateur du processus, datées
    /// de son lancement, une taille nulle ; un dossier a deux liens et un
    /// par sous-dossier (le dossier d'un processus : task et fd ; task : un
    /// par fil). Le processus parti : le même mode et les mêmes liens, à
    /// root, sans date ni taille (`pid_getattr`) ; une tâche sans mémoire
    /// (un zombie, un fil principal parti) : ce qui n'est pas un dossier
    /// 0555 à root (`task_dump_owner`). La racine de /proc compte aussi un
    /// lien par processus (`proc_root_getattr`).
    fn attributs(&self, i: u64) -> Attributs {
        let (genre, n, fil) = decoder(i);
        if genre == 0 {
            let mut a = self.fixe.attributs(i);
            if i == self.fixe.racine() {
                a.nlink += processus::nombre();
            }
            return a;
        }
        let vu = processus_de(n).and_then(processus::vu_de_proc).filter(|_| self.existe(i));
        let mut taille = 0;
        let (mode, nlink) = match genre {
            PROCESSUS => (S_IFDIR | 0o555, 4),
            // fd/ : dr-x------, et sa taille est le nombre de descripteurs
            // (`proc_fd_getattr`, mesuré).
            DOSSIER_FD => {
                taille = processus_de(n).filter(|_| crate::tache::a_sa_memoire(n)).map_or(0, processus::nombre_de_descripteurs);
                (S_IFDIR | 0o500, 2)
            }
            // Un lien de fd/ : ses droits disent le mode d'ouverture, sa
            // taille est 64 (mesuré).
            LIEN_FD => {
                taille = 64;
                (S_IFLNK | self.ouvert(n, decoder(i).2).map_or(0, droits_du_lien), 1)
            }
            FICHIER_MAPS | FICHIER_STATM | FICHIER_STATUS | FICHIER_STAT | FIL_STATUS | FIL_STAT => (S_IFREG | 0o444, 1),
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
        // La tâche de l'entrée : le fil, sous task/<tid> ; n, ailleurs.
        let tache = if genre == FIL || est_du_fil(genre) { fil } else { n };
        let (uid, gid, date) = match vu {
            Some((_, lance)) if mode != S_IFDIR | 0o555 && !crate::tache::a_sa_memoire(tache) => (0, 0, lance),
            Some((identite, lance)) => (identite.uid, identite.gid, lance),
            None => (0, 0, Temps::default()),
        };
        let taille = if vu.is_some() { taille } else { 0 };
        Attributs { numero: i, mode, nlink, uid, gid, rdev: (0, 0), taille, blocs: 0, atime: date, mtime: date, ctime: date }
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
            FIL => ENTREES_DU_FIL.iter().find(|(e, _)| *e == nom).map(|&(_, g)| numero(g, n, fil)),
            DOSSIER_FD => {
                let fd = nombre(nom)?;
                (fd < 1 << 24 && self.ouvert(n, fd).is_some()).then(|| numero(LIEN_FD, n, fd))
            }
            _ => None,
        }
    }

    fn parent(&self, i: u64) -> u64 {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => self.fixe.parent(i),
            PROCESSUS => self.fixe.racine(),
            FIL => numero(DOSSIER_TASK, n, 0),
            g if est_du_fil(g) => numero(FIL, n, fil),
            LIEN_FD => numero(DOSSIER_FD, n, 0),
            _ => numero(PROCESSUS, n, 0),
        }
    }

    fn nom(&self, i: u64) -> Texte<'_> {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => self.fixe.nom(i),
            PROCESSUS => Texte::nombre(n as u64),
            FIL | LIEN_FD => Texte::nombre(fil as u64),
            g => Texte::Emprunte(ENTREES_DU_PROCESSUS.iter().chain(ENTREES_DU_FIL.iter()).find(|&&(_, x)| x == g)
                .map_or(&b""[..], |&(e, _)| e)),
        }
    }

    /// Le texte d'`exe` et d'un lien de fd/ : le chemin du fichier, suivi
    /// de « (deleted) » s'il n'a plus de nom (le `d_path` de Linux) ; un
    /// fichier sans nom dit ce qu'il est (anon_inode:[eventfd],
    /// pipe:[123]). Le chemin d'un fichier ouvert est celui de son
    /// ouverture (Linux montre le nouveau nom d'un fichier renommé : voir
    /// FichierOuvert::chemin, l'écart), et « (deleted) » se décide par son
    /// lieu (`FichierOuvert::efface` : le nom qui l'a ouvert a disparu, même
    /// si un autre lien physique garde l'inode). Un zombie n'a
    /// plus d'`exe`, un descripteur fermé plus de lien, et sans mémoire :
    /// vide (readlink rend ENOENT).
    fn cible<'b>(&'b self, lien: u64, lecteur: &'b [u8], fil: &'b [u8]) -> Texte<'b> {
        let (chemin, efface) = match decoder(lien) {
            (0, _, _) => return self.fixe.cible(lien, lecteur, fil),
            (LIEN_EXE, n, _) => match exe_de(n).and_then(|p| Some((processus::chemin_exe(p)?, processus::exe(p)?))) {
                Some((chemin, inode)) => (Texte::Long(chemin), self.fs.attributs(inode).nlink == 0),
                None => return Texte::Emprunte(&[]),
            },
            (LIEN_FD, n, fd) => {
                let Some(f) = self.ouvert(n, fd) else { return Texte::Emprunte(&[]) };
                let chemin = if f.chemin.is_empty() { f.nom.octets() } else { &f.chemin[..] };
                (Texte::Emprunte(chemin), f.efface(self.fs))
            }
            _ => return Texte::Emprunte(&[]),
        };
        if !efface {
            return chemin;
        }
        match faillible::concatenation(&[&chemin, b" (deleted)"]) {
            Ok(v) => Texte::Long(v),
            Err(_) => Texte::Emprunte(&[]),
        }
    }

    /// `exe` et les liens de fd/ sont des LIENS MAGIQUES : les suivre mène
    /// droit à l'exécutable ou au fichier ouvert (son objet), même effacé ou
    /// sans nom, sans lire leur texte (`proc_exe_link`, `proc_fd_link`,
    /// puis `nd_jump_link`).
    fn saut(&self, lien: u64) -> Option<Objet> {
        match decoder(lien) {
            (LIEN_EXE, n, _) => exe_de(n).and_then(processus::exe).map(Objet::Tmpfs),
            (LIEN_FD, n, fd) => self.ouvert(n, fd).map(FichierOuvert::objet),
            _ => None,
        }
    }

    /// Ce qu'ouvre un lien magique garde le chemin du fichier qu'il
    /// désigne : celui de l'exécutable, celui du fichier ouvert (pipe:[123],
    /// anon_inode:[eventfd] pour un fichier sans nom).
    fn chemin_du_saut(&self, lien: u64) -> Option<Texte<'_>> {
        match decoder(lien) {
            (LIEN_EXE, n, _) => exe_de(n).and_then(processus::chemin_exe).map(Texte::Long),
            (LIEN_FD, n, fd) => self.ouvert(n, fd).map(|f| Texte::Emprunte(&f.chemin[..])),
            _ => None,
        }
    }

    /// La racine : « . », « .. », les entrées fixes, puis les processus (à
    /// la position PREMIER_PROCESSUS + pid) ; le dossier d'un processus, ses
    /// huit entrées ; task/, ses fils (à la position 3 + tid) ; un fil, ses
    /// trois. Un dossier dont le processus est parti : ENOENT.
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
        if !matches!(genre, PROCESSUS | DOSSIER_TASK | FIL | DOSSIER_FD) {
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
                        DOSSIER_TASK | DOSSIER_FD => DT_DIR,
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
            // fd/ : ses descripteurs, dans l'ordre (à la position 3 + fd).
            DOSSIER_FD => {
                let Some(p) = processus_de(n).filter(|_| crate::tache::a_sa_memoire(n)) else { return Ok(()) };
                let mut depuis = position.max(2) - 2;
                while let Some(fd) = processus::descripteur_suivant(p, depuis) {
                    if fd >= 1 << 24 {
                        break;
                    }
                    let nom = Texte::nombre(fd);
                    if !entree(&nom, numero(LIEN_FD, n, fd as u32), DT_LNK, fd + 3) {
                        break;
                    }
                    depuis = fd + 1;
                }
            }
            _ => {
                for (k, &(nom, g)) in ENTREES_DU_FIL.iter().enumerate().skip((position.max(2) - 2) as usize) {
                    if !entree(nom, numero(g, n, fil), DT_REG, k as u64 + 3) {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// La source d'un fichier, à son ouverture, et son argument : la tâche
    /// (n, ou le fil sous task/). maps garde ce qu'il trouve à l'ouverture :
    /// la mémoire de la tâche, ou rien (MAPS_SANS_MEMOIRE) ; statm, stat,
    /// status, comm regardent à chaque lecture.
    fn contenu(&self, i: u64) -> Option<(u32, u32)> {
        let (genre, n, fil) = decoder(i);
        match genre {
            0 => self.fixe.contenu(i),
            FICHIER_MAPS if crate::tache::a_sa_memoire(n) => Some((MAPS, n)),
            FICHIER_MAPS => Some((MAPS_SANS_MEMOIRE, n)),
            FICHIER_STATM => Some((STATM, n)),
            FICHIER_COMM => Some((COMM, n)),
            FIL_COMM => Some((COMM, fil)),
            FICHIER_STAT => Some((STAT, n)),
            FIL_STAT => Some((STAT_FIL, fil)),
            FICHIER_STATUS => Some((STATUS, n)),
            FIL_STATUS => Some((STATUS, fil)),
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
        s if s >= SYSCTL_NET => Lecture::Valeur,
        OVERCOMMIT_MEMORY | MMAP_MIN_ADDR | PIPE_MAX_SIZE | PIPE_USER_PAGES_SOFT | PIPE_USER_PAGES_HARD | RANDOM_BOOT_ID
        | RANDOM_UUID | RANDOM_ENTROPY_AVAIL | RANDOM_POOLSIZE | RANDOM_WAKEUP | RANDOM_RESEED | INOTIFY_EVENEMENTS
        | INOTIFY_INSTANCES | INOTIFY_SURVEILLANCES => Lecture::Valeur,
        MAPS | MAPS_SANS_MEMOIRE | STATM | COMM | STAT | STAT_FIL | STATUS | BANNIERE | NET_PNP | NET_ROUTE | NET_DEV | NET_ARP | NET_SNMP | NET_TCP | NET_UNIX | NET_IGMP
        | NET_MCFILTER | NET_DEV_MCAST => Lecture::Sequence,
        // Nommées une à une, sans cas par défaut : /proc/net/tcp et unix
        // (6h) y étaient tombés, et se comportaient en attributs de /sys
        // (lseek SEEK_END donnait 4096 ; Linux : EINVAL, `seq_lseek`).
        crate::sysfs::CPU_ONLINE | crate::sysfs::CPU_POSSIBLE | crate::sysfs::CPU_PRESENT | crate::sysfs::THP_ENABLED => Lecture::Attribut,
        _ => unreachable!("source de fichier du noyau inconnue"),
    }
}

/// Le fichier ouvert que désigne le lien magique `lien` (/proc/<pid>/fd/N),
/// s'il en est un (6i : appels_fichiers::saut, le lieu d'un fichier qu'on
/// rouvre par lui).
pub fn fichier_du_saut(lien: Objet) -> Option<crate::descripteurs::Fichier> {
    let Objet::Monte(fichiers::montages::Systeme(s), i) = lien else { return None };
    let (genre, n, fd) = decoder(i);
    if s as usize != crate::vfs::PROC || genre != LIEN_FD {
        return None;
    }
    processus::descripteur(processus_de(n)?, fd as u64)
}

/// Les données du fichier ouvert d'une source.
pub fn donnees(source: u32, argument: u32) -> Donnees {
    Donnees::Noyau { source, argument, sequence: Default::default() }
}

/// Le fichier ouvert `f` se lit-il par `read_iter` chez Linux ? Ce qui
/// décide des drapeaux RWF_* que preadv2 y accepte (appels_fichiers.rs,
/// `operation`). Oui pour /proc/sys (`proc_sys_read`), /sys
/// (`kernfs_fop_read_iter`), /proc/version et /proc/net/pnp
/// (`proc_create_single` : `seq_read_iter`) ; non pour /proc/<pid> et le
/// reste de /proc/net (`proc_create_net*`), lus par `seq_read` (mesuré sous
/// Linux 6.18, `linux/fichiers.c` ; pnp lu dans les sources, le Linux de
/// WSL n'ayant pas CONFIG_IP_PNP).
pub fn par_iter(f: Fichier) -> bool {
    let (source, _) = source(f);
    matches!(source, BANNIERE | NET_PNP) || lecture(source) != Lecture::Sequence
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
    // Le fichier d'une tâche partie : un processus recueilli (sa tâche est
    // morte, et init l'a retiré de la table), un fil fini ; ESRCH, comme
    // Linux (mesuré : `get_proc_task` ne la trouve plus). Celui d'un zombie,
    // ou d'un fil principal parti avant les autres, se lit encore (voir
    // `produire`) : Linux garde sa tâche jusqu'au recueil.
    let disparu = match source {
        MAPS | MAPS_SANS_MEMOIRE | STATM | COMM | STAT | STAT_FIL | STATUS => nom(argument).is_none(),
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
        self.0.ajouter_tranche(s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Un UUID au format de Linux (`%pU` : 8-4-4-4-12 chiffres hexadécimaux
/// minuscules), avec son saut de ligne.
fn ecrire_uuid(t: &mut Ecrit, u: [u8; 16]) -> fmt::Result {
    for (i, o) in u.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            t.write_str("-")?;
        }
        write!(t, "{:02x}", o)?;
    }
    writeln!(t)
}

/// La valeur d'un réglage de /proc/sys, avec son saut de ligne.
fn valeur(source: u32) -> Result<Vec<u8>, Erreur> {
    let mut t = Ecrit(Vec::new());
    let r = match source {
        s if s >= SYSCTL_NET => crate::reseau::proc::valeur_de_reglage(s - SYSCTL_NET, &mut t),
        // OVERCOMMIT_GUESS : la politique de 6a (memoire.rs).
        OVERCOMMIT_MEMORY => writeln!(t, "0"),
        PIPE_MAX_SIZE => writeln!(t, "{}", crate::tube::TAILLE_MAX),
        PIPE_USER_PAGES_SOFT => writeln!(t, "{}", crate::tube::PAGES_UTILISATEUR_DOUCE),
        PIPE_USER_PAGES_HARD => writeln!(t, "{}", crate::tube::PAGES_UTILISATEUR_DURE),
        // boot_id : tiré une fois, au premier usage ; uuid : neuf à chaque
        // lecture (`proc_do_uuid`).
        RANDOM_BOOT_ID => ecrire_uuid(&mut t, crate::aleatoire::identifiant_du_demarrage()),
        RANDOM_UUID => ecrire_uuid(&mut t, crate::aleatoire::uuid()),
        // Les bits crédités, 256 une fois prêt (POOL_BITS, comme poolsize).
        RANDOM_ENTROPY_AVAIL => writeln!(t, "{}", crate::aleatoire::bits()),
        RANDOM_POOLSIZE => writeln!(t, "256"),
        RANDOM_WAKEUP => writeln!(t, "256"),
        RANDOM_RESEED => writeln!(t, "60"),
        INOTIFY_EVENEMENTS => writeln!(t, "{}", crate::surveillance::EVENEMENTS_MAX),
        INOTIFY_INSTANCES => writeln!(t, "{}", crate::surveillance::INSTANCES_MAX),
        INOTIFY_SURVEILLANCES => writeln!(t, "{}", crate::surveillance::surveillances_max()),
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
        return Ok(Some((valeur?, 1)));
    }
    // La tâche `argument`. Sans mémoire (un zombie : sa tâche est morte, il
    // attend d'être recueilli ; un fil principal parti avant les autres) :
    // maps vide, statm à zéro, comme Linux (mesuré). maps ouvert avec la
    // mémoire la lit tant que le processus l'a (`contenu`).
    match source {
        MAPS => match processus_de(argument) {
            Some(pid) => ligne_maps(pid, curseur),
            None => Ok(None),
        },
        STATM if curseur == 0 => statm(argument).map(|t| Some((t, u64::MAX))),
        COMM if curseur == 0 => comm(argument).map(|t| Some((t, u64::MAX))),
        STAT | STAT_FIL if curseur == 0 => stat(argument, source == STAT).map(|t| Some((t, u64::MAX))),
        STATUS if curseur == 0 => status(argument).map(|t| Some((t, u64::MAX))),
        BANNIERE if curseur == 0 => banniere().map(|t| Some((t, u64::MAX))),
        NET_PNP | NET_ROUTE | NET_DEV | NET_ARP | NET_SNMP | NET_TCP | NET_UNIX | NET_IGMP | NET_MCFILTER | NET_DEV_MCAST => {
            let f = match source {
                NET_PNP => crate::reseau::proc::Fichier::Pnp,
                NET_ROUTE => crate::reseau::proc::Fichier::Route,
                NET_DEV => crate::reseau::proc::Fichier::Dev,
                NET_SNMP => crate::reseau::proc::Fichier::Snmp,
                NET_TCP => crate::reseau::proc::Fichier::Tcp,
                NET_UNIX => crate::reseau::proc::Fichier::Unix,
                NET_IGMP => crate::reseau::proc::Fichier::Igmp,
                NET_MCFILTER => crate::reseau::proc::Fichier::Mcfilter,
                NET_DEV_MCAST => crate::reseau::proc::Fichier::DevMcast,
                _ => crate::reseau::proc::Fichier::Arp,
            };
            match crate::reseau::proc::ligne(f, curseur) {
                Ok(l) => Ok(l.map(|l| (l, curseur + 1))),
                Err(()) => Err(Erreur::ENOMEM),
            }
        }
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
    Ok(faillible::concatenation(&[nom.octets(), b"\n"])?)
}

/// Ce que stat et status disent d'une tâche, pris verrou après verrou,
/// jamais l'un sous l'autre (`produire` est hors du verrou des fichiers) :
/// la tâche (son Arc, cloné sous la table des tâches ou sous l'entrée de
/// son processus), la vue de son processus (sous son verrou), l'identité du
/// lecteur, sa mémoire en lecture si elle l'a encore, sa table des
/// descripteurs.
struct DeLaTache {
    t: Arc<Tache>,
    pid: u32,
    vue: processus::VueDuProcessus,
    /// Le lecteur peut-il voir ce qui dit où en est la tâche (ses adresses,
    /// ses registres, son statut) : le `ptrace_may_access(...,
    /// PTRACE_MODE_READ_FSCREDS)` de Linux, c'est-à-dire le même processus,
    /// ou root, ou le même utilisateur et le même groupe (nos programmes
    /// n'ont ni capacités ni « dumpable » à vérifier).
    permis: bool,
    memoire: Option<DeLaMemoire>,
    /// La taille de sa table des descripteurs (FDSize), 0 sans elle.
    descripteurs: u64,
}

/// La mémoire d'une tâche, telle que la montrent stat et status (ses
/// compteurs, lus sans verrou, et sa carte, mémoire tenue en lecture).
struct DeLaMemoire {
    resume: Resume,
    /// Pages anonymes, de fichiers, le plus grand RSS, les tables.
    anonymes: u64,
    fichiers: u64,
    pic_resident: u64,
    tables: u64,
    code: (u64, u64),
    donnees: (u64, u64),
    debut_tas: u64,
    pile_de_depart: u64,
    arguments: (u64, u64),
    environnement: (u64, u64),
}

/// La tâche `n` (le fil principal d'un processus jusqu'à son recueil, ou un
/// fil vivant) et tout ce qu'en disent stat et status ; None si elle vient
/// de partir (ESRCH).
fn de_la_tache(n: u32) -> Option<DeLaTache> {
    let (t, pid) = match processus::principal(n) {
        Some(t) => (t, n),
        None => {
            let t = crate::tache::trouver(n)?;
            let pid = t.processus()?.pid();
            (t, pid)
        }
    };
    let vue = processus::vue(pid, n)?;
    // Le lecteur : une tâche du noyau, sans processus, voit tout.
    let lecteur = processus::essayer_avec(|p| (p.pid, p.identite));
    let permis = lecteur.is_none_or(|(lp, li)| lp == pid || li.root() || (li.uid == vue.identite.uid && li.gid == vue.identite.gid));
    let a_sa_memoire = t.a_sa_memoire();
    let memoire = a_sa_memoire.then(|| processus::memoire_du_pid(pid, |m| {
        let c = m.compteurs();
        DeLaMemoire {
            resume: m.resume(), anonymes: c.pages() as u64, fichiers: c.pages_fichier() as u64, pic_resident: c.pic() as u64,
            tables: c.tables() as u64, code: m.code, donnees: m.donnees, debut_tas: m.debut_tas, pile_de_depart: m.pile_de_depart,
            arguments: m.arguments, environnement: m.environnement,
        }
    })).flatten();
    let descripteurs = if a_sa_memoire { processus::descripteurs_du_pid(pid, |d| d.taille_linux()).unwrap_or(0) } else { 0 };
    Some(DeLaTache { t, pid, vue, permis, memoire, descripteurs })
}

/// La tâche est-elle « en marche » pour Linux (TASK_RUNNING : sur un
/// processeur, ou prête, réveillée) ?
fn en_marche(etat: u8) -> bool {
    use crate::tache::etat::*;
    matches!(etat, EN_COURS | REVEILLEE | ECHEANCE | SIGNAL)
}

/// La lettre et le mot de son état (`task_state_array` de Linux) : R en
/// marche, S endormie et interruptible, D endormie sans l'être ; morte, Z
/// pour un fil principal (un zombie jusqu'au recueil, même si d'autres fils
/// vivent : Linux le garde ainsi), X pour un autre fil (rendu aussitôt).
fn etat_de(t: &Tache, principal: bool) -> (char, &'static str) {
    use crate::tache::etat::*;
    match t.etat() {
        DORT => ('D', "disk sleep"),
        DORT_INTERRUPTIBLE => ('S', "sleeping"),
        MORTE if principal => ('Z', "zombie"),
        MORTE => ('X', "dead"),
        _ => ('R', "running"),
    }
}

/// Des nanosecondes en tics d'horloge de l'utilisateur (USER_HZ, 100 :
/// `nsec_to_clock_t`).
fn tics(ns: u64) -> u64 {
    ns / 10_000_000
}

/// /proc/<n>/stat (`processus_entier` : le `whole` de Linux) et
/// task/<tid>/stat : une ligne de 52 champs séparés par une espace, ceux de
/// `do_task_stat` dans son ordre (fs/proc/array.c, relu dans 6.18 et
/// mesuré). Ce qui n'a pas de sens chez nous y est à sa valeur de Linux
/// sans la fonction : pas de terminal (tty 0, tpgid -1), pas de fautes
/// majeures ni de fils recueillis (cmin_flt, cutime... 0), la priorité 20
/// et le nice 0 de tout programme, pas de temps réel ni de délais comptés.
/// Le processus entier somme les fautes de ses fils, morts et vivants,
/// partage son temps comme getrusage(RUSAGE_SELF) (le même partage
/// précédent : les deux ne reculent jamais l'un par rapport à l'autre), et
/// donne le statut de la fin de son groupe ; un fil, les siens. Les
/// signaux, en DÉCIMAL et sur 31 bits (« obsolète », dit Linux : status les
/// a tous) : ceux qui attendent le fil seul, son masque, les ignorés et les
/// attrapés du processus.
fn stat(n: u32, processus_entier: bool) -> Result<Vec<u8>, Erreur> {
    let d = de_la_tache(n).ok_or(Erreur::ESRCH)?;
    let (t, v) = (&d.t, &d.vue);
    let principal = t.tid() == d.pid;
    let (fautes, utime, stime) = if processus_entier {
        (v.cumul.fautes(), v.utime, v.stime)
    } else {
        let (c, utime, stime) = crate::rusage::du_fil(t);
        (c.fautes(), utime, stime)
    };
    let mm = d.memoire.as_ref();
    let permis = d.permis;
    // Les registres d'une tâche dans sa sortie, sa mémoire encore là.
    let (esp, eip) = if permis && mm.is_some() { t.registres_de_sortie() } else { (0, 0) };
    // « wchan » n'est plus qu'un drapeau (une adresse du noyau était une
    // fuite) : la tâche dort, ou est morte ; pour le processus entier,
    // seulement s'il n'a qu'un fil.
    let wchan = permis && (!processus_entier || v.fils < 2) && !en_marche(t.etat());
    let exit_code = match (permis, processus_entier, v.fin_de_groupe) {
        (false, _, _) => 0,
        (true, true, Some(code)) => code,
        _ => t.code_sortie(),
    };
    let reserve = |valeur: u64| if permis { valeur } else { 1 };
    let mut e = Ecrit(Vec::new());
    write!(e, "{} (", n).map_err(|_| Erreur::ENOMEM)?;
    e.0.ajouter_tranche(t.nom().octets())?;
    let r = (|| -> fmt::Result {
        let masque = |s: u64| s & 0x7fff_ffff;
        write!(e, ") {} 1 {} {} 0 -1 {} {} 0 0 0 {} {} 0 0 20 0 {} 0 {} {} {} {} ", etat_de(t, principal).0, d.pid, d.pid,
               t.drapeaux(), fautes, tics(utime), tics(stime), v.fils, tics(t.debut()), mm.map_or(0, |m| m.resume.taille),
               mm.map_or(0, |m| m.anonymes + m.fichiers), v.limite_rss)?;
        write!(e, "{} {} {} {} {} ", mm.map_or(0, |m| reserve(m.code.0)), mm.map_or(0, |m| reserve(m.code.1)),
               mm.filter(|_| permis).map_or(0, |m| m.pile_de_depart), esp, eip)?;
        write!(e, "{} {} {} {} {} 0 0 {} {} 0 0 0 0 0", masque(v.attente), masque(v.masque), masque(v.ignores), masque(v.attrapes),
               wchan as u8, if principal { 17 } else { -1 }, t.processeur())?;
        match mm.filter(|_| permis) {
            Some(m) => write!(e, " {} {} {} {} {} {} {}", m.donnees.0, m.donnees.1, m.debut_tas, m.arguments.0, m.arguments.1,
                              m.environnement.0, m.environnement.1)?,
            None => write!(e, " 0 0 0 0 0 0 0")?,
        }
        writeln!(e, " {}", exit_code)
    })();
    r.map_err(|_| Erreur::ENOMEM)?;
    Ok(e.0)
}

/// /proc/<n>/status et task/<tid>/status : le `proc_pid_status` de Linux,
/// ligne par ligne dans son ordre, avec ses formats (fs/proc/array.c, relus
/// dans 6.18 ; l'ordre des lignes, mesuré). Celles d'un Linux construit
/// sans ce que nous n'avons pas : ni espaces de noms des processus
/// (NStgid...), ni seccomp, ni grandes pages (HugetlbPages), ni cpusets
/// (Mems_allowed), ni pile fantôme (x86_Thread_features). Le masque du
/// fichier n'apparaît que si la tâche a encore son dossier courant (sa
/// mémoire, chez nous : `a_sa_memoire`), les lignes Vm* et les trois qui
/// suivent que si elle a sa mémoire. Les capacités : toutes pour root,
/// aucune pour un autre (comme un programme que lance root, ou un autre).
/// Speculation_* : aucune commande de spéculation (notre prctl rend EINVAL
/// à PR_GET_SPECULATION_CTRL, le comportement par défaut de Linux), ce que
/// Linux écrit « unknown » pour la première et « unsupported » pour la
/// seconde.
fn status(n: u32) -> Result<Vec<u8>, Erreur> {
    let d = de_la_tache(n).ok_or(Erreur::ESRCH)?;
    let (t, v) = (&d.t, &d.vue);
    let principal = t.tid() == d.pid;
    let mut e = Ecrit(Vec::new());
    // Le nom, ses sauts de ligne et ses barres obliques inverses échappés
    // (`proc_task_name(..., true)`) ; ses autres octets tels quels.
    e.write_str("Name:\t").map_err(|_| Erreur::ENOMEM)?;
    for &o in t.nom().octets() {
        match o {
            b'\n' => e.0.ajouter_tranche(b"\\n")?,
            b'\\' => e.0.ajouter_tranche(b"\\\\")?,
            _ => e.0.ajouter(o)?,
        }
    }
    let r = (|| -> fmt::Result {
        writeln!(e)?;
        if t.a_sa_memoire() {
            writeln!(e, "Umask:\t{:04o}", v.umask)?;
        }
        let (lettre, mot) = etat_de(t, principal);
        let (u, g) = (v.identite.uid, v.identite.gid);
        writeln!(e, "State:\t{} ({})\nTgid:\t{}\nNgid:\t0\nPid:\t{}\nPPid:\t1\nTracerPid:\t0", lettre, mot, d.pid, n)?;
        writeln!(e, "Uid:\t{u}\t{u}\t{u}\t{u}\nGid:\t{g}\t{g}\t{g}\t{g}\nFDSize:\t{}\nGroups:\t \nKthread:\t0", d.descripteurs)?;
        if let Some(m) = &d.memoire {
            let r = &m.resume;
            let kio = |pages: u64| pages * 4;
            // Le code du programme (VmExe), borné par les zones exécutables,
            // et le reste de celles-ci (VmLib, les bibliothèques).
            let texte = if m.code.1 > m.code.0 { m.code.1.next_multiple_of(4096) - (m.code.0 & !4095) } else { 0 }.min(r.code);
            let resident = m.anonymes + m.fichiers;
            for (nom, valeur) in [("VmPeak", r.pic / 1024), ("VmSize", r.taille / 1024), ("VmLck", 0), ("VmPin", 0),
                                  ("VmHWM", kio(m.pic_resident.max(resident))), ("VmRSS", kio(resident)), ("RssAnon", kio(m.anonymes)),
                                  ("RssFile", 0), ("RssShmem", kio(m.fichiers)), ("VmData", r.donnees / 1024), ("VmStk", r.pile / 1024),
                                  ("VmExe", texte / 1024), ("VmLib", (r.code - texte) / 1024), ("VmPTE", kio(m.tables)), ("VmSwap", 0)] {
                writeln!(e, "{}:\t{:>8} kB", nom, valeur)?;
            }
            writeln!(e, "CoreDumping:\t0\nTHP_enabled:\t1\nuntag_mask:\t0xffffffffffffffff")?;
        }
        writeln!(e, "Threads:\t{}\nSigQ:\t{}/{}", v.fils, crate::signaux::en_file(), v.limite_signaux)?;
        for (nom, s) in [("SigPnd", v.attente), ("ShdPnd", v.attente_partagee), ("SigBlk", v.masque), ("SigIgn", v.ignores), ("SigCgt", v.attrapes)] {
            writeln!(e, "{}:\t{:016x}", nom, s)?;
        }
        // Les capacités : CAP_LAST_CAP de 6.18, 40 (CAP_CHECKPOINT_RESTORE).
        const TOUTES: u64 = (1 << 41) - 1;
        let effectives = if v.identite.root() { TOUTES } else { 0 };
        writeln!(e, "CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}", 0, effectives, effectives,
                 TOUTES, 0)?;
        writeln!(e, "NoNewPrivs:\t0\nSpeculation_Store_Bypass:\tunknown\nSpeculationIndirectBranch:\tunsupported")?;
        e.write_str("Cpus_allowed:\t")?;
        let possibles = crate::processeur::masque_possible();
        ecrire_masque(&mut e, t.affinite() & possibles, 64 - possibles.leading_zeros())
    })();
    r.map_err(|_| Erreur::ENOMEM)?;
    e.write_str("\nCpus_allowed_list:\t").map_err(|_| Erreur::ENOMEM)?;
    e.0.ajouter_tranche(&sysfs::liste(t.affinite() & crate::processeur::masque_possible())?)?;
    let (volontaires, forcees) = t.usage().lire().bascules();
    writeln!(e, "voluntary_ctxt_switches:\t{}\nnonvoluntary_ctxt_switches:\t{}", volontaires, forcees).map_err(|_| Erreur::ENOMEM)?;
    Ok(e.0)
}

/// Un masque de processeurs au format `%*pb` de Linux (`bitmap_string`) sur
/// `bits` bits (le `nr_cpu_ids`, le plus grand numéro possible plus un) :
/// en hexadécimal, par groupes de 32 bits du plus haut au plus bas, séparés
/// par des virgules, chacun sur 8 chiffres sauf le premier, sur autant de
/// chiffres que ses bits en demandent (4 processeurs : « f »).
fn ecrire_masque(e: &mut Ecrit, masque: u64, bits: u32) -> fmt::Result {
    let bits = bits.max(1);
    let mut premier = bits % 32;
    if premier == 0 {
        premier = 32;
    }
    let mut i = bits.next_multiple_of(32) - 32;
    let mut largeur = premier.div_ceil(4) as usize;
    let mut morceau = premier;
    loop {
        let valeur = (masque >> i) & ((1u64 << morceau) - 1);
        write!(e, "{:0largeur$x}", valeur, largeur = largeur)?;
        if i == 0 {
            return Ok(());
        }
        e.write_str(",")?;
        i -= 32;
        largeur = 8;
        morceau = 32;
    }
}

/// /proc/version : le `linux_proc_banner` de Linux (fs/proc/version.c), le
/// nom du système, sa version et sa construction, ceux d'uname
/// (linux.rs), avec entre eux qui a construit le noyau, sur quelle machine,
/// et avec quel compilateur (build.rs). Qui et où : Linux prend `whoami` et
/// `hostname` à la construction, sauf quand KBUILD_BUILD_USER et
/// KBUILD_BUILD_HOST les fixent, pour une construction reproductible ; les
/// nôtres sont fixés, sans quoi la même image dirait autre chose construite
/// dans la machine de David ou dans la CI. Des programmes y cherchent ce
/// qu'uname ne dit pas toujours (Claude Code y reconnaît WSL, à
/// « microsoft »).
fn banniere() -> Result<Vec<u8>, Erreur> {
    use crate::linux::{CONSTRUCTION, SYSTEME, VERSION};
    let mut t = Ecrit(Vec::new());
    writeln!(t, "{} version {} (claude-os@claude-os) ({}) {}", SYSTEME, VERSION, env!("COMPILATEUR"), CONSTRUCTION)
        .map_err(|_| Erreur::ENOMEM)?;
    Ok(t.0)
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

/// /proc/<n>/statm de la tâche `n` : sept nombres de pages, comme
/// `task_statm` de Linux (tous à zéro si elle n'a plus de mémoire) :
/// la taille virtuelle ; le résident (pages à lui, plus pages de fichiers) ;
/// les pages de fichiers ; le code (de la première à la dernière page du
/// segment exécutable du programme : `end_code - start_code`) ; 0 (les
/// bibliothèques, toujours 0 depuis Linux 2.6) ; les données (les zones
/// privées inscriptibles, hors pile, plus la pile : `data_vm + stack_vm` ;
/// jusqu'aux soldes d'avant 6k, la pile ne comptait que par sa nature, et
/// une zone MAP_GROWSDOWN non inscriptible y manquait) ; 0. Le résident vient des compteurs de l'espace, lus sans verrou (les
/// `rss_stat` de Linux, 6j) ; le reste est sommé sur les zones, mémoire
/// tenue en lecture. Linux a aussi ceux-là en compteurs (`total_vm`,
/// `data_vm`, `stack_vm`), entretenus à chaque changement de zone, et lit
/// tout sans le mmap_lock ; sommer les zones sous la lecture, qui ne fait
/// attendre qu'un mmap ou un munmap, jamais une faute, est plus simple à
/// tenir juste.
fn statm(n: u32) -> Result<Vec<u8>, Erreur> {
    let pid = processus_de(n).filter(|_| crate::tache::a_sa_memoire(n));
    let (taille, resident, partage, code, donnees) = pid.and_then(|pid| processus::memoire_du_pid(pid, |m| {
        let (debut, fin) = m.code;
        let code = if fin > debut { (fin.next_multiple_of(4096) - (debut & !4095)) / 4096 } else { 0 };
        let r = m.resume();
        let c = m.compteurs();
        (r.taille / 4096, c.resident() as u64, c.pages_fichier() as u64, code, (r.donnees + r.pile) / 4096)
    })).unwrap_or((0, 0, 0, 0, 0));
    let mut t = Ecrit(Vec::new());
    writeln!(t, "{} {} {} {} 0 {} 0", taille, resident, partage, code, donnees).map_err(|_| Erreur::ENOMEM)?;
    Ok(t.0)
}

/// Ce que montre maps du fichier que projette la zone `z` (s'il y en a un) :
/// son chemin, son inode, s'il est effacé, et le décalage de la projection
/// en octets. Sous la mémoire du processus de la zone, tenue en lecture
/// (`ligne_maps`).
fn fichier_de_zone(z: &Zone) -> Result<Option<(Vec<u8>, u32, bool, u64)>, Erreur> {
    let Some(projection) = z.fichier else { return Ok(None) };
    vfs::avec_systeme(|s, _| {
        let f = s.ouverts.fichier(Fichier::de(projection.fichier));
        let source = if f.chemin.is_empty() { f.nom.octets() } else { &f.chemin[..] };
        let chemin = faillible::copie(source)?;
        let numero = f.numero();
        let efface = f.efface(&s.fs);
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
    // mémoire du processus tenue en lecture, celui des fichiers pris
    // dedans : la zone tient son fichier tant qu'elle existe, mais le
    // processus peut la retirer (munmap) dès qu'on rend la mémoire, et le
    // numéro du fichier servir à un autre. Linux lit de même maps sous le
    // verrou de la mémoire du processus (`mmap_read_lock`).
    let Some(lu) = processus::memoire_du_pid(pid, |m| {
        let z = m.zones.zones().iter().find(|z| z.fin > curseur).copied()?;
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
        // Une seule allocation pour tout ce qui suit.
        ligne.try_reserve(place).map_err(|_| Erreur::ENOMEM)?;
        ligne.redimensionner(ligne.len().max(72), b' ')?;
        ligne.ajouter(b' ')?;
        ligne.ajouter_tranche(nom)?;
        if efface {
            ligne.ajouter_tranche(b" (deleted)")?;
        }
    }
    ligne.ajouter(b'\n')?;
    Ok(Some((ligne, z.fin)))
}
