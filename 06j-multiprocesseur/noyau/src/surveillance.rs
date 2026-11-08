//! inotify (6i) : surveiller des fichiers et des dossiers, et lire par un
//! descripteur ce qui leur arrive (fs/notify/ de Linux 6.18 :
//! inotify/inotify_user.c, inotify/inotify_fsnotify.c, fsnotify.c, et les
//! `fsnotify_*` de include/linux/fsnotify.h). claude s'en sert pour suivre
//! ses réglages : il crée une instance, surveille son dossier de réglages,
//! et une sonde dans son dossier temporaire, qu'il modifie pour voir si la
//! surveillance marche.
//!
//! Les objets, ceux de Linux :
//!   - une INSTANCE (`Groupe`, le `fsnotify_group`) derrière un descripteur
//!     (inotify_init1) : la file de ses événements, lue par `read` (des
//!     `struct inotify_event`, chacune suivie de son nom complété de zéros
//!     jusqu'à un multiple de 16 octets), sondée par poll et epoll ;
//!   - une SURVEILLANCE (`Marque`, l'`inotify_inode_mark`) : un objet, une
//!     instance, un numéro (le `wd`, propre à l'instance, alloué en cercle
//!     à partir de 1, comme l'`idr_alloc_cyclic` de Linux : un numéro rendu
//!     ne resert pas tout de suite), et ce qu'elle veut savoir ;
//!   - un ÉVÉNEMENT, posé par les appels du système de fichiers aux
//!     endroits de Linux (appels_fichiers.rs, vfs.rs, programmes.rs,
//!     wasi.rs) : à l'objet lui-même (sans nom), et à son dossier s'il
//!     surveille ses enfants (avec le nom de l'objet dans le dossier). Pour
//!     ce nom, un fichier ouvert garde le dossier et l'entrée par lesquels on
//!     l'a trouvé (`Lieu`, le `dentry` de son ouverture chez Linux) : un
//!     renommage le met à jour, un effacement le laisse (Linux adresse
//!     encore au dossier les événements d'un fichier effacé encore ouvert,
//!     sous son ancien nom). Un `Lieu` tient son dossier, comme un dentry
//!     tient son parent : un dossier effacé dont un fichier est encore
//!     ouvert ne finit (IN_DELETE_SELF) qu'à la fermeture de ce fichier
//!     (mesuré sous Linux 6.18).
//!
//! Les règles de Linux 6.18, vérifiées sur l'hôte par linux/surveillance.c
//! (et mesurées par deux sondes au début du commit) :
//!   - un événement identique au DERNIER de la file (même numéro, même
//!     masque, même nom ; le cookie n'est pas comparé) n'est pas ajouté ;
//!     jamais après un IN_IGNORED. Un dossier et un fichier qu'il contient,
//!     surveillés tous deux, reçoivent donc chacun le leur, en alternance :
//!     trois écritures font six événements ;
//!   - la file tient 16384 événements (max_queued_events) ; au-delà, un seul
//!     IN_Q_OVERFLOW (numéro -1) est ajouté, et ce qui suit est perdu tant
//!     qu'il est dans la file et qu'elle est pleine. Un événement qu'on n'a
//!     pas la mémoire de noter est perdu de même, et signalé par
//!     IN_Q_OVERFLOW : la réponse de Linux à une allocation qui échoue, que
//!     la règle du noyau (aucune allocation qui panique) trouve toute faite.
//!     Sa place est réservée d'avance (l'`overflow_event` de Linux) ;
//!   - IN_DELETE_SELF, puis IN_IGNORED, quand meurt une entrée d'un inode
//!     qui n'a plus de nom (`dentry_unlink_inode`), pas à l'effacement d'un
//!     fichier encore ouvert : `unlink` donne IN_ATTRIB (le nombre de liens)
//!     au fichier et IN_DELETE au dossier, le reste vient au dernier `close`
//!     de ce qui a été ouvert par ce nom. C'est la fin de l'inode (son
//!     dernier nom et sa dernière référence partis), que le tmpfs annonce
//!     (`Cadres::inode_detruit`) et que vfs.rs transmet ici ; sauf pour un
//!     fichier à plusieurs noms, ouvert par l'un, effacé par tous : une
//!     entrée que personne ne tient meurt à son effacement
//!     (vfs::Systeme::entree_morte), et la fin vient alors. Un tube ou une socket (surveillés par
//!     /proc/self/fd/N) ne finissent pas ainsi : Linux garde leur inode tant
//!     qu'une surveillance le tient, sans rien dire ; ici leur surveillance
//!     devient orpheline (aucun événement ne peut plus l'atteindre, et son
//!     numéro d'inode peut resservir), et `inotify_rm_watch` la retire
//!     comme chez Linux (IN_IGNORED) ;
//!   - les limites, par utilisateur : 128 instances (EMFILE), et des
//!     surveillances pour 1 % de la mémoire (ENOSPC) : `max_user_watches`,
//!     calculé comme Linux (le coût d'une surveillance, 1296 octets, est
//!     celui de Linux 6.18 mesuré sur l'hôte : une `inotify_inode_mark` de 80
//!     octets et deux inodes de 608) ; /proc/sys/fs/inotify les montre ;
//!   - IN_ONESHOT : le premier événement, puis IN_IGNORED ; IN_EXCL_UNLINK :
//!     rien des événements d'un fichier ouvert (ouverture, lecture,
//!     écriture, fermeture) une fois son nom effacé ; IN_MASK_ADD ajoute au
//!     masque d'une surveillance qui existe, IN_MASK_CREATE refuse
//!     (EEXIST) ; IN_ONLYDIR, IN_DONT_FOLLOW comme leur nom ;
//!   - O_ASYNC : SIGIO à chaque événement ajouté (le `kill_fasync` de
//!     `fsnotify_add_event`), envoyé à la sortie de l'appel qui l'a causé
//!     (asynchrone.rs : un signal ne s'envoie pas sous le verrou des
//!     fichiers, où naissent presque tous les événements).
//!
//! Les verrous, dans cet ordre : celui des fichiers (vfs.rs), sous lequel
//! se posent presque tous les événements ; celui des surveillances
//! (`MARQUES`) ; celui de la file d'une instance ; les compteurs par
//! utilisateur (`COMPTES`), une feuille. Tous des `Verrou` : presque tous
//! les événements naissent sous le verrou des fichiers, un verrou court, où
//! l'on ne dort pas (une fermeture faite par munmap ou la fin d'un
//! processus comprise : la mémoire, elle, est sous un verrou qui dort,
//! mais elle rend ses fichiers par celui des fichiers). Sans aucun événement
//! surveillé, un appel ne prend aucun verrou de plus : `NOMBRE` est lu
//! d'abord (le `fsnotify_sb_has_watchers` de Linux).
//!
//! Options écartées : des surveillances rangées dans chaque inode, comme
//! Linux (le tmpfs est une bibliothèque qui ne connaît pas les instances,
//! et la plupart des inodes n'en ont jamais) ; une table indexée par objet
//! (une `BTreeMap` alloue sans pouvoir échouer) : un vecteur trié par objet,
//! où l'on cherche par dichotomie, et où l'on insère en déplaçant la fin
//! (une surveillance se pose rarement, un événement se cherche souvent).

use crate::appels_fichiers::{self, FichierTenu};
use crate::asynchrone::{self, ListeAsync, Raison};
use crate::attente::{self, FileAttente, Sommeil};
use crate::copie_utilisateur::copier_vers_utilisateur;
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::faillible::{FileFaillible, PlusDeMemoire, VecFaillible};
use crate::partage::Arc;
use crate::sondage::{POLLIN, POLLRDNORM, Table};
use crate::tache::Reveil;
use crate::verrou::Verrou;
use crate::{cpu, faillible, pages, processus, tache, vfs};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use fichiers::montages::{Objet, Systeme as Montage};
use fichiers::tmpfs::{Numero, Tmpfs};

const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const ENOTDIR: i64 = 20;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTTY: i64 = 25;
const ENOSPC: i64 = 28;

// Les événements et les drapeaux (include/uapi/linux/inotify.h).
pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_UNMOUNT: u32 = 0x0000_2000;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
/// Tous les événements qu'on peut demander.
const IN_ALL_EVENTS: u32 = 0x0000_0fff;
/// Tout ce qu'accepte inotify_add_watch (`ALL_INOTIFY_BITS`, 22 bits) : un
/// autre bit, EINVAL ; aucun de ceux-là, EINVAL aussi (mesuré : IN_ONESHOT
/// seul, IN_IGNORED seul sont acceptés, et ne demandent aucun événement).
const TOUS_LES_BITS: u32 = IN_ALL_EVENTS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED | IN_ONLYDIR | IN_DONT_FOLLOW
    | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD | IN_ISDIR | IN_ONESHOT;
/// Ce qu'un dossier reçoit de ses enfants (`FS_EVENTS_POSS_ON_CHILD`) ; le
/// reste (création, effacement, déplacement) lui est adressé à lui.
const DES_ENFANTS: u32 = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_OPEN;

const IN_CLOEXEC: u64 = 0o2000000;
const IN_NONBLOCK: u64 = 0o4000;
const O_RDONLY: u32 = 0;
const FIONREAD: u64 = 0x541b;
/// INOTIFY_IOC_SETNEXTWD (`_IOW('I', 0, __s32)`) : le prochain numéro de
/// surveillance (pour CRIU, qui restaure une instance ; Ubuntu a
/// CONFIG_CHECKPOINT_RESTORE).
const INOTIFY_IOC_SETNEXTWD: u64 = 0x4004_4900;

/// La taille d'un `struct inotify_event` sans son nom.
const TAILLE_EVENEMENT: usize = 16;

// Les limites (inotify_user_setup), par utilisateur.
/// max_queued_events : les événements de la file d'une instance.
pub const EVENEMENTS_MAX: usize = 16384;
/// max_user_instances.
pub const INSTANCES_MAX: u32 = 128;
/// Le coût d'une surveillance, `INOTIFY_WATCH_COST` : sizeof(struct
/// inotify_inode_mark) + 2 * sizeof(struct inode), mesurés sous Linux 6.18
/// (/sys/kernel/slab/inotify_inode_mark et inode_cache : 80 et 608).
const COUT_D_UNE_SURVEILLANCE: u64 = 80 + 2 * 608;

/// max_user_watches : 1 % de la mémoire, divisé par le coût d'une
/// surveillance, entre 8192 et 1048576 (inotify_user_setup).
pub fn surveillances_max() -> u32 {
    let octets = (pages::total() as u64 / 100) << 12;
    (octets / COUT_D_UNE_SURVEILLANCE).clamp(8192, 1_048_576) as u32
}

// ----- Le lieu d'un fichier ouvert -----

/// Le dossier et l'entrée par lesquels un fichier a été trouvé, et son nom
/// (le `dentry` de Linux) : à qui le dossier doit les événements du
/// fichier. Dans le tmpfs, le cookie de l'entrée
/// (fichiers::tmpfs::Tmpfs::entree) dit si elle existe encore (le
/// `d_unlinked` de Linux, pour IN_EXCL_UNLINK), et le lieu tient une
/// référence à son dossier, à rendre quand il ne sert plus
/// (`vfs::Systeme::lacher` pour un fichier ouvert). Dans /proc et /sys
/// aussi (mesuré : lire /proc/self/comm se dit à une surveillance de
/// /proc/self, sous le nom « comm ») : leurs entrées ne s'effacent pas et
/// leurs dossiers ne se tiennent pas (cookie 0).
pub struct Lieu {
    pub dossier: Objet,
    pub cookie: u64,
    pub nom: Vec<u8>,
}

/// Le lieu d'un objet qu'on va ouvrir (ou tenir), préparé avant : son nom
/// copié, pour que rien ne puisse plus échouer une fois l'objet ouvert, ou
/// créé. Achevé ensuite (`achever`) : le cookie de son entrée, si on ne le
/// connaissait pas (une création), et son dossier tenu.
pub struct LieuPrepare {
    dossier: Objet,
    cookie: Option<u64>,
    nom: Vec<u8>,
}

impl LieuPrepare {
    /// L'entrée `nom` de `dossier` (du tmpfs, qui existe ou va être créée,
    /// ou d'un système monté).
    pub fn entree(dossier: Objet, nom: &[u8]) -> Result<LieuPrepare, PlusDeMemoire> {
        let cookie = if matches!(dossier, Objet::Tmpfs(_)) { None } else { Some(0) };
        Ok(LieuPrepare { dossier, cookie, nom: faillible::copie(nom)? })
    }

    /// Le dossier `n` dans son parent (pour « . », « .. » et la racine, que
    /// la résolution ne trouve pas par un nom) ; None pour la racine, ou un
    /// dossier effacé.
    pub fn du_dossier(fs: &Tmpfs, n: Numero) -> Result<Option<LieuPrepare>, PlusDeMemoire> {
        let Some((parent, cookie, nom)) = fs.nom_du_dossier(n) else { return Ok(None) };
        Ok(Some(LieuPrepare { dossier: Objet::Tmpfs(parent), cookie: Some(cookie), nom: faillible::copie(nom)? }))
    }

    /// De même, le dossier `o` d'un système monté dans son parent ; None
    /// pour sa racine (Linux ne remonte pas au-delà de la racine d'un
    /// système : `IS_ROOT`), ou ce qui n'est pas monté.
    pub fn du_dossier_monte(vue: &fichiers::montages::Vue<'_, vfs::Montage<'_>>, o: Objet) -> Result<Option<LieuPrepare>, PlusDeMemoire> {
        let Some((parent, nom)) = vue.dans_son_parent(o) else { return Ok(None) };
        Ok(Some(LieuPrepare { dossier: parent, cookie: Some(0), nom: faillible::copie(&nom)? }))
    }

    /// Le lieu d'un fichier ouvert (rouvert par /proc/self/fd/N, ou tenu
    /// pour un appel).
    pub fn copie(l: &Lieu) -> Result<LieuPrepare, PlusDeMemoire> {
        Ok(LieuPrepare { dossier: l.dossier, cookie: Some(l.cookie), nom: faillible::copie(&l.nom)? })
    }

    /// Le lieu de l'objet `o` qu'on vient d'ouvrir : son dossier tenu, s'il
    /// est au tmpfs. None si l'entrée qu'on attendait ne le désigne pas.
    pub fn achever(self, fs: &mut Tmpfs, o: Objet) -> Option<Lieu> {
        let cookie = match (self.cookie, self.dossier) {
            (Some(c), _) => c,
            (None, Objet::Tmpfs(d)) => fs.entree(d, &self.nom).filter(|&(m, _)| Objet::Tmpfs(m) == o)?.1,
            (None, _) => return None,
        };
        if let Objet::Tmpfs(d) = self.dossier {
            fs.prendre(d);
        }
        Some(Lieu { dossier: self.dossier, cookie, nom: self.nom })
    }
}

impl Lieu {
    /// Ce que voit un événement : le dossier, le nom, et si l'entrée de
    /// l'objet `n` (du tmpfs) a disparu.
    fn parent(&self, fs: &Tmpfs, n: Option<Numero>) -> Parent<'_> {
        let delie = match self.dossier {
            Objet::Tmpfs(d) => n.is_none_or(|n| !fs.a_l_entree(d, self.cookie, n)),
            _ => false,
        };
        Parent { dossier: self.dossier, nom: &self.nom, delie }
    }
}

/// Le dossier d'un événement, son nom dedans, et si ce nom a été effacé.
#[derive(Clone, Copy)]
struct Parent<'a> {
    dossier: Objet,
    nom: &'a [u8],
    delie: bool,
}

// ----- Les instances -----

/// Une instance (le `fsnotify_group`) : sa file sous son verrou, ceux qui
/// attendent qu'elle se remplisse (lecteurs, poll, epoll), et ses inscrits
/// O_ASYNC.
pub struct Groupe {
    file: Verrou<File>,
    attente: FileAttente,
    pub async_lecteurs: ListeAsync,
    /// Inscrite dans la liste des instances à signaler de la tâche
    /// courante (`a_signaler`), chaînée par `suivante`.
    a_signaler: AtomicBool,
    suivante: Verrou<Option<Arc<Groupe>>>,
    /// L'utilisateur qui l'a créée : elle et ses surveillances lui sont
    /// comptées.
    uid: u32,
}

/// La file d'une instance.
struct File {
    evenements: VecDeque<Evenement>,
    /// Ce que rendrait sa lecture, en octets (FIONREAD).
    octets: usize,
    /// IN_Q_OVERFLOW est dans la file (une fois au plus).
    debordement: bool,
    /// Le prochain numéro de surveillance à essayer.
    curseur: i32,
}

/// Un événement dans la file (l'`inotify_event_info`) ; sans nom : `nom`
/// vide.
struct Evenement {
    wd: i32,
    masque: u32,
    cookie: u32,
    nom: Vec<u8>,
}

impl Evenement {
    /// Sa taille lue : l'en-tête, puis le nom et au moins un zéro, jusqu'à
    /// un multiple de 16 octets (`round_event_name_len`).
    fn taille(&self) -> usize {
        TAILLE_EVENEMENT + if self.nom.is_empty() { 0 } else { (self.nom.len() + 1).next_multiple_of(TAILLE_EVENEMENT) }
    }
}

impl Drop for Groupe {
    /// La fin d'une instance (`inotify_free_group_priv`) : une de moins pour
    /// son utilisateur.
    fn drop(&mut self) {
        compter(self.uid, |c| c.instances -= 1);
    }
}

/// Le dernier cookie donné à un déplacement (le `fsnotify_sync_cookie` de
/// Linux) : il en faut un neuf par renommage, surveillé ou non.
static COOKIE: AtomicU32 = AtomicU32::new(0);

/// Le cookie d'un renommage : IN_MOVED_FROM et IN_MOVED_TO l'ont tous deux.
pub fn cookie() -> u32 {
    COOKIE.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

// ----- Les surveillances -----

/// Une surveillance.
struct Marque {
    /// Son objet, par sa clé (`cle`), selon laquelle la table est triée ;
    /// None : orpheline (son tube ou sa socket a fini).
    objet: Option<Objet>,
    cle: u128,
    groupe: Arc<Groupe>,
    wd: i32,
    /// Les événements qu'elle veut (IN_ALL_EVENTS).
    masque: u32,
    oneshot: bool,
    excl_unlink: bool,
    /// Un dossier : il reçoit aussi les événements de ses enfants
    /// (`FS_EVENT_ON_CHILD`).
    enfants: bool,
    /// Retirée pendant la livraison en cours (IN_ONESHOT) : enlevée de la
    /// table à la fin.
    morte: bool,
}

/// Toutes les surveillances, triées par objet.
static MARQUES: Verrou<Vec<Marque>> = Verrou::new(Vec::new());
/// Leur nombre : zéro, et aucun événement n'est à poser.
static NOMBRE: AtomicUsize = AtomicUsize::new(0);

/// La clé d'un objet : les inodes du tmpfs d'abord, puis ceux des systèmes
/// montés (leurs numéros, de 64 bits, entiers : procfs en fabrique pour
/// chaque processus, et un numéro de processus ne resert jamais,
/// processus::numero_neuf), puis l'inode anonyme ; les orphelines tout au
/// bout.
fn cle(o: Objet) -> u128 {
    match o {
        Objet::Tmpfs(n) => n.0 as u128,
        Objet::Monte(Montage(s), n) => ((s as u128 + 1) << 64) | n as u128,
        Objet::Anonyme => u128::MAX - 1,
    }
}
const ORPHELINE: u128 = u128::MAX;

/// Les surveillances de l'objet de clé `c` : leurs indices dans la table.
fn de(marques: &[Marque], c: u128) -> core::ops::Range<usize> {
    let debut = marques.partition_point(|m| m.cle < c);
    debut..debut + marques[debut..].partition_point(|m| m.cle == c)
}

/// Y a-t-il quelque chose à surveiller ? Sans verrou : un événement qui
/// naît pendant qu'une première surveillance se pose peut lui échapper,
/// comme chez Linux.
pub fn actif() -> bool {
    NOMBRE.load(Ordering::Relaxed) != 0
}

// ----- Les comptes par utilisateur -----

/// Les instances et les surveillances d'un utilisateur (les `ucounts`).
struct Compte {
    uid: u32,
    instances: u32,
    surveillances: u32,
}

static COMPTES: Verrou<Vec<Compte>> = Verrou::new(Vec::new());

/// Change le compte de `uid` (créé à zéro s'il n'existe pas ; un compte
/// revenu à zéro est retiré). Rend ce que rend `f`, ou None s'il n'y a pas
/// la place d'un compte neuf.
fn compter<R>(uid: u32, f: impl FnOnce(&mut Compte) -> R) -> Option<R> {
    let mut comptes = COMPTES.verrouiller();
    let i = match comptes.iter().position(|c| c.uid == uid) {
        Some(i) => i,
        None => {
            comptes.ajouter(Compte { uid, instances: 0, surveillances: 0 }).ok()?;
            comptes.len() - 1
        }
    };
    let r = f(&mut comptes[i]);
    if comptes[i].instances == 0 && comptes[i].surveillances == 0 {
        comptes.swap_remove(i);
        // Plus personne : la table rend sa mémoire (comme celle des
        // fichiers ouverts).
        if comptes.is_empty() {
            *comptes = Vec::new();
        }
    }
    Some(r)
}

// ----- Poser les événements -----

/// Ajoute un événement à la file de `g` (`fsnotify_add_event`), dans
/// l'ordre de `fsnotify_insert_event` : sans la mémoire de le noter, ou la
/// file pleine, IN_Q_OVERFLOW à sa place, s'il n'y est pas déjà ; sinon,
/// rien s'il est le même que le dernier (`inotify_merge`) ; sinon il est
/// ajouté. Ce qui est ajouté réveille qui attend, et prévoit SIGIO pour les
/// inscrits O_ASYNC.
fn deposer(g: &Arc<Groupe>, wd: i32, masque: u32, cookie: u32, nom: &[u8]) {
    // Le drapeau IN_ISDIR n'accompagne jamais IN_DELETE_SELF ni
    // IN_MOVE_SELF (un oubli de Linux qu'il garde : inotify_handle_inode_event).
    let masque = if masque & (IN_DELETE_SELF | IN_MOVE_SELF) != 0 { masque & !IN_ISDIR } else { masque };
    // Le nom noté avant le verrou, comme l'événement de Linux (son
    // `kmalloc`, dans inotify_handle_inode_event).
    let note = faillible::copie(nom).ok();
    {
        let mut f = g.file.verrouiller();
        let plein = f.evenements.len() >= EVENEMENTS_MAX;
        let note = note.filter(|_| !plein);
        if note.is_some()
            && let Some(d) = f.evenements.back()
            && d.masque & IN_IGNORED == 0
            && d.masque == masque
            && d.wd == wd
            && d.nom == nom
        {
            return;
        }
        // La place de l'événement, et toujours une de plus, pour
        // IN_Q_OVERFLOW (réservée d'avance : la file de Linux est une liste,
        // l'ajout n'y échoue jamais).
        let note = note.filter(|_| f.evenements.try_reserve(2).is_ok());
        let e = match note {
            Some(nom) => Evenement { wd, masque, cookie, nom },
            None if f.debordement => return,
            None => {
                f.debordement = true;
                Evenement { wd: -1, masque: IN_Q_OVERFLOW, cookie: 0, nom: Vec::new() }
            }
        };
        f.octets += e.taille();
        f.evenements.ajouter_derriere_dans_la_place(e);
    }
    g.attente.reveiller_une();
    if g.async_lecteurs.occupee() && !g.a_signaler.swap(true, Ordering::Relaxed) {
        let mut tete = tache::courante().instances_a_signaler.verrouiller();
        *g.suivante.verrouiller() = tete.take();
        *tete = Some(g.clone());
    }
}

/// Les SIGIO des instances où la tâche courante a ajouté des événements (à
/// la sortie de chaque appel, avec la fermeture des sockets : voir
/// reseau::socket::fermer_les_differees). Sans verrou tenu.
pub fn signaler_les_instances() {
    let tache = tache::courante();
    loop {
        let g = {
            let mut tete = tache.instances_a_signaler.verrouiller();
            let Some(g) = tete.take() else { return };
            *tete = g.suivante.verrouiller().take();
            g
        };
        g.a_signaler.store(false, Ordering::Relaxed);
        g.async_lecteurs.tuer(asynchrone::SIGIO, Raison::Entree);
    }
}

/// Livre un événement, sous le verrou des surveillances
/// (`fsnotify_handle_event`) : à chaque surveillance du dossier `parent`
/// qui suit ses enfants (avec le nom de l'objet dans le dossier), puis à
/// celle de l'objet dans la même instance ; puis aux surveillances de
/// l'objet des autres instances. Celles de l'objet reçoivent `nom` (vide,
/// sauf pour un dossier qui reçoit un événement sur une de ses entrées :
/// création, effacement, déplacement, avec `cookie`). `fichier` :
/// l'événement d'un fichier ouvert, qu'IN_EXCL_UNLINK écarte une fois son
/// nom effacé (`delie`). Les surveillances IN_ONESHOT qui ont servi
/// reçoivent IN_IGNORED, puis sont retirées.
#[allow(clippy::too_many_arguments)]
fn livrer(marques: &mut Vec<Marque>, objet: Objet, nom: &[u8], masque: u32, parent: Option<Parent>, cookie: u32, fichier: bool,
          delie: bool) {
    let interesse = |m: &Marque, delie: bool| !m.morte && masque & m.masque != 0 && !(fichier && delie && m.excl_unlink);
    let parent = parent.filter(|_| masque & DES_ENFANTS != 0);
    let de_l_objet = de(marques, cle(objet));
    let du_parent = parent.map_or(0..0, |p| de(marques, cle(p.dossier)));
    let mut mortes = false;
    let mut servir = |marques: &mut Vec<Marque>, i: usize, nom: &[u8], cookie: u32| {
        let m = &mut marques[i];
        deposer(&m.groupe, m.wd, masque, cookie, nom);
        if m.oneshot {
            deposer(&m.groupe, m.wd, IN_IGNORED, 0, &[]);
            m.morte = true;
            mortes = true;
        }
    };
    if let Some(p) = parent {
        for i in du_parent.clone() {
            if marques[i].enfants && interesse(&marques[i], p.delie) {
                servir(marques, i, p.nom, 0);
            }
            // La surveillance de l'objet dans la même instance : après celle
            // du dossier, même si celle-ci ne voulait rien.
            let groupe = &marques[i].groupe;
            if let Some(j) = de_l_objet.clone().find(|&j| Arc::ptr_eq(&marques[j].groupe, groupe))
                && interesse(&marques[j], delie)
            {
                servir(marques, j, &[], 0);
            }
        }
    }
    for j in de_l_objet {
        let deja = du_parent.clone().any(|i| Arc::ptr_eq(&marques[i].groupe, &marques[j].groupe));
        if !deja && interesse(&marques[j], delie) {
            servir(marques, j, nom, cookie);
        }
    }
    if mortes {
        retirer_mortes(marques);
    }
}

/// Enlève de la table les surveillances mortes, et les décompte. Vide, la
/// table rend sa mémoire.
fn retirer_mortes(marques: &mut Vec<Marque>) {
    let mut i = 0;
    while i < marques.len() {
        if marques[i].morte {
            let m = marques.remove(i);
            NOMBRE.fetch_sub(1, Ordering::Relaxed);
            compter(m.groupe.uid, |c| c.surveillances -= 1);
        } else {
            i += 1;
        }
    }
    if marques.is_empty() {
        *marques = Vec::new();
    }
}

/// Un événement d'un fichier ouvert (`fsnotify_file` : ouverture, lecture,
/// écriture, fermeture, lecture d'un dossier) : à l'objet, et à son dossier
/// s'il le surveille, sous son nom d'ouverture. Rien pour O_PATH (un
/// descripteur qui ne fait que désigner : Linux n'en dit rien). Sous le
/// verrou des fichiers.
pub fn du_fichier(fs: &Tmpfs, f: &FichierOuvert, masque: u32) {
    if !actif() || f.sorte == Sorte::Chemin {
        return;
    }
    let dossier = f.sorte == Sorte::Dossier;
    let parent = f.lieu.as_ref().map(|l| l.parent(fs, f.numero()));
    let delie = parent.is_some_and(|p| p.delie);
    let masque = if dossier { masque | IN_ISDIR } else { masque };
    livrer(&mut MARQUES.verrouiller(), f.objet(), &[], masque, parent, 0, true, delie);
}

/// `du_fichier`, pour un appel qui a fini de lire ou d'écrire `o` (hors du
/// verrou des fichiers).
pub fn apres_l_appel(o: &FichierTenu, masque: u32) {
    if actif() {
        vfs::avec_systeme(|s, _| du_fichier(&s.fs, s.ouverts.fichier(o.fichier()), masque));
    }
}

/// Un changement d'un objet tenu par un fichier ouvert, ou par un chemin
/// (`fsnotify_change` : ses attributs, sa taille, ses dates ;
/// `fsnotify_dentry`) : à l'objet, et à son dossier s'il le surveille, sous
/// le lieu du fichier. IN_EXCL_UNLINK ne l'écarte pas (Linux ne le regarde
/// que pour les événements d'un fichier ouvert : mesuré, fchmod d'un
/// fichier effacé se voit). Sous le verrou des fichiers.
pub fn changement(fs: &Tmpfs, f: &FichierOuvert, masque: u32) {
    if !actif() || masque == 0 {
        return;
    }
    let dossier = match f.objet() {
        Objet::Tmpfs(n) => fs.est_un_dossier(n),
        _ => f.sorte == Sorte::Dossier,
    };
    let parent = f.lieu.as_ref().map(|l| l.parent(fs, f.numero()));
    let masque = if dossier { masque | IN_ISDIR } else { masque };
    livrer(&mut MARQUES.verrouiller(), f.objet(), &[], masque, parent, 0, false, false);
}

/// Un événement d'un dossier sur une de ses entrées (`fsnotify_name` :
/// création, effacement, déplacement, avec le nom de l'entrée et le cookie
/// d'un déplacement). `dossier_cible` : l'entrée désigne un dossier
/// (IN_ISDIR).
pub fn dans_le_dossier(dossier: Numero, nom: &[u8], masque: u32, dossier_cible: bool, cookie: u32) {
    if !actif() {
        return;
    }
    let masque = if dossier_cible { masque | IN_ISDIR } else { masque };
    livrer(&mut MARQUES.verrouiller(), Objet::Tmpfs(dossier), nom, masque, None, cookie, false, false);
}

/// Un événement de l'inode seul (`fsnotify_inode` : son nombre de liens,
/// son déplacement).
pub fn de_l_inode(n: Numero, dossier: bool, masque: u32) {
    if !actif() {
        return;
    }
    let masque = if dossier { masque | IN_ISDIR } else { masque };
    livrer(&mut MARQUES.verrouiller(), Objet::Tmpfs(n), &[], masque, None, 0, false, false);
}

/// La fin de l'inode `n` du tmpfs (`fsnotify_inoderemove`) : IN_DELETE_SELF
/// à ses surveillances, puis chacune reçoit IN_IGNORED et disparaît. Un
/// tube ou une socket (`anonyme`) : ses surveillances deviennent
/// orphelines, sans rien dire. Sous le verrou des fichiers, avant que le
/// numéro ne resserve (vfs.rs).
pub fn inode_fini(n: Numero, anonyme: bool) {
    if !actif() {
        return;
    }
    let mut marques = MARQUES.verrouiller();
    let c = cle(Objet::Tmpfs(n));
    if de(&marques, c).is_empty() {
        return;
    }
    if anonyme {
        // Au bout de la table, où leur clé les range.
        for i in de(&marques, c).rev() {
            let mut m = marques.remove(i);
            (m.objet, m.cle) = (None, ORPHELINE);
            marques.ajouter_dans_la_place(m);
        }
        return;
    }
    livrer(&mut marques, Objet::Tmpfs(n), &[], IN_DELETE_SELF, None, 0, false, false);
    for i in de(&marques, c) {
        let m = &mut marques[i];
        deposer(&m.groupe, m.wd, IN_IGNORED, 0, &[]);
        m.morte = true;
    }
    retirer_mortes(&mut marques);
}

// ----- Les appels système -----

/// inotify_init1(drapeaux) : IN_NONBLOCK et IN_CLOEXEC (EINVAL pour un
/// autre) ; une instance de plus pour l'utilisateur (EMFILE au-delà de
/// 128), puis son descripteur, en lecture seule (F_GETFL : O_RDONLY, et
/// O_NONBLOCK s'il est demandé, mesuré : 0x800), sur l'inode anonyme
/// (« anon_inode:inotify »).
pub fn inotify_init1(drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & !(IN_CLOEXEC | IN_NONBLOCK) != 0 {
        return -EINVAL;
    }
    let uid = processus::avec(|p| p.identite.uid);
    let Some(permis) = compter(uid, |c| {
        let permis = c.instances < INSTANCES_MAX;
        if permis {
            c.instances += 1;
        }
        permis
    }) else {
        return -ENOMEM;
    };
    if !permis {
        return -EMFILE;
    }
    let groupe = Groupe {
        file: Verrou::new(File { evenements: VecDeque::new(), octets: 0, debordement: false, curseur: 1 }),
        attente: FileAttente::new(),
        async_lecteurs: ListeAsync::new(),
        a_signaler: AtomicBool::new(false),
        suivante: Verrou::new(None),
        uid,
    };
    // La place d'IN_Q_OVERFLOW, d'avance.
    let groupe = {
        let mut g = groupe;
        if g.file.get_mut().evenements.try_reserve(1).is_err() {
            return -ENOMEM;
        }
        g
    };
    let Ok(groupe) = Arc::new(groupe) else { return -ENOMEM };
    let mut f = FichierOuvert::new(Sorte::Inotify, Tenu::Noyau(Objet::Anonyme), true, false,
                                   O_RDONLY | (drapeaux & IN_NONBLOCK) as u32, b"anon_inode:inotify");
    f.chemin = crate::evenements::nom_anonyme(b"anon_inode:inotify");
    f.prive = Prive::Inotify(groupe);
    appels_fichiers::installer_fichier(f, drapeaux & IN_CLOEXEC != 0)
}

/// inotify_init() : inotify_init1 sans drapeaux.
pub fn inotify_init() -> i64 {
    inotify_init1(0)
}

/// inotify_add_watch(fd, chemin, masque), dans l'ordre de Linux (mesuré) :
/// le masque (EINVAL), le descripteur (EBADF, O_PATH aussi), IN_MASK_ADD
/// avec IN_MASK_CREATE (EINVAL), une instance (EINVAL), le chemin (EFAULT,
/// ENOENT... ; suivi sauf IN_DONT_FOLLOW), un dossier avec IN_ONLYDIR
/// (ENOTDIR), le droit de lire l'objet (EACCES : l'inode anonyme, à root en
/// 0600, ne se surveille donc pas). Puis la surveillance de l'objet dans
/// l'instance : changée si elle existe (son masque remplacé, ou complété
/// avec IN_MASK_ADD ; EEXIST avec IN_MASK_CREATE), créée sinon (un numéro
/// neuf, ENOSPC au-delà des surveillances permises). Rend son numéro.
pub fn inotify_add_watch(fd: u64, adresse: u64, masque: u64) -> i64 {
    let masque = masque as u32;
    if masque & !TOUS_LES_BITS != 0 || masque & TOUS_LES_BITS == 0 {
        return -EINVAL;
    }
    // Un descripteur O_PATH n'est pas un descripteur pour `fdget` : EBADF.
    let o = match appels_fichiers::tenir(fd) {
        Ok(o) if o.sorte == Sorte::Chemin => return -EBADF,
        Ok(o) => o,
        Err(e) => return e,
    };
    if masque & IN_MASK_ADD != 0 && masque & IN_MASK_CREATE != 0 {
        return -EINVAL;
    }
    let Some(groupe) = o.inotify() else { return -EINVAL };
    let (objet, dossier, lisible) = match appels_fichiers::objet_pour_surveiller(adresse, masque & IN_DONT_FOLLOW == 0) {
        Ok(t) => t,
        Err(e) => return e,
    };
    if masque & IN_ONLYDIR != 0 && !dossier {
        return -ENOTDIR;
    }
    if !lisible {
        return -EACCES;
    }
    let voulus = masque & IN_ALL_EVENTS;
    let mut marques = MARQUES.verrouiller();
    let c = cle(objet.objet());
    if let Some(i) = de(&marques, c).find(|&i| Arc::ptr_eq(&marques[i].groupe, groupe)) {
        if masque & IN_MASK_CREATE != 0 {
            return -EEXIST;
        }
        let m = &mut marques[i];
        if masque & IN_MASK_ADD == 0 {
            (m.masque, m.oneshot, m.excl_unlink) = (0, false, false);
        }
        m.masque |= voulus;
        m.oneshot |= masque & IN_ONESHOT != 0;
        m.excl_unlink |= masque & IN_EXCL_UNLINK != 0;
        return m.wd as i64;
    }
    // Un numéro neuf, en cercle à partir du curseur ; il avance même si la
    // surveillance est ensuite refusée (Linux l'a pris dans son idr).
    let wd = {
        let mut f = groupe.file.verrouiller();
        let mut wd = f.curseur;
        while marques.iter().any(|m| m.wd == wd && Arc::ptr_eq(&m.groupe, groupe)) {
            wd = if wd == i32::MAX { 1 } else { wd + 1 };
        }
        f.curseur = if wd == i32::MAX { 1 } else { wd + 1 };
        wd
    };
    let max = surveillances_max();
    match compter(groupe.uid, |c| {
        let permis = c.surveillances < max;
        if permis {
            c.surveillances += 1;
        }
        permis
    }) {
        None => return -ENOMEM,
        Some(false) => return -ENOSPC,
        Some(true) => {}
    }
    let m = Marque {
        objet: Some(objet.objet()),
        cle: c,
        groupe: groupe.clone(),
        wd,
        masque: voulus,
        oneshot: masque & IN_ONESHOT != 0,
        excl_unlink: masque & IN_EXCL_UNLINK != 0,
        enfants: dossier,
        morte: false,
    };
    let place = de(&marques, c).end;
    if marques.inserer(place, m).is_err() {
        compter(groupe.uid, |c| c.surveillances -= 1);
        return -ENOMEM;
    }
    NOMBRE.fetch_add(1, Ordering::Relaxed);
    // L'objet, tenu jusqu'ici, peut être lâché : s'il finit, sa
    // surveillance l'apprendra (inode_fini).
    drop(marques);
    drop(objet);
    wd as i64
}

/// inotify_rm_watch(fd, wd) : EBADF (O_PATH aussi), EINVAL (pas une
/// instance, ou pas de surveillance de ce numéro) ; IN_IGNORED, puis la
/// surveillance retirée.
pub fn inotify_rm_watch(fd: u64, wd: u64) -> i64 {
    let o = match appels_fichiers::tenir(fd) {
        Ok(o) if o.sorte == Sorte::Chemin => return -EBADF,
        Ok(o) => o,
        Err(e) => return e,
    };
    let Some(groupe) = o.inotify() else { return -EINVAL };
    let wd = wd as i32;
    let mut marques = MARQUES.verrouiller();
    let Some(i) = marques.iter().position(|m| m.wd == wd && Arc::ptr_eq(&m.groupe, groupe)) else { return -EINVAL };
    deposer(&marques[i].groupe, wd, IN_IGNORED, 0, &[]);
    marques[i].morte = true;
    retirer_mortes(&mut marques);
    0
}

/// La dernière fermeture d'une instance (`fsnotify_destroy_group`) : ses
/// surveillances disparaissent (sans IN_IGNORED : personne ne les lira),
/// puis l'instance avec son dernier Arc. Sous le verrou des fichiers
/// (descripteurs::Ouverts::lacher).
pub fn fichier_ferme(ferme: &FichierOuvert, fichier: crate::descripteurs::Fichier) {
    if let Prive::Inotify(g) = &ferme.prive {
        g.async_lecteurs.fichier_ferme(fichier);
        let mut marques = MARQUES.verrouiller();
        for m in marques.iter_mut().filter(|m| Arc::ptr_eq(&m.groupe, g)) {
            m.morte = true;
        }
        retirer_mortes(&mut marques);
    }
}

// ----- Lire une instance -----

impl Groupe {
    /// Le premier événement de la file, s'il tient dans `place` octets
    /// (`get_one_event`) : Ok(None) si la file est vide, Err(EINVAL) s'il ne
    /// tient pas (il reste alors dans la file).
    fn prendre(&self, place: usize) -> Result<Option<Evenement>, i64> {
        let mut f = self.file.verrouiller();
        let Some(e) = f.evenements.front() else { return Ok(None) };
        let taille = e.taille();
        if taille > place {
            return Err(-EINVAL);
        }
        f.octets -= taille;
        let e = f.evenements.pop_front().expect("vu en tete");
        if e.masque == IN_Q_OVERFLOW && e.wd == -1 {
            f.debordement = false;
        }
        Ok(Some(e))
    }

    /// Le sondage (`inotify_poll`) : s'inscrit dans la file d'attente, puis
    /// POLLIN | POLLRDNORM s'il y a un événement à lire.
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        table.attendre(&self.attente, tenu);
        if self.file.verrouiller().evenements.is_empty() { 0 } else { POLLIN | POLLRDNORM }
    }

    /// FIONREAD : ce que rendrait la lecture de toute la file.
    fn octets(&self) -> usize {
        self.file.verrouiller().octets
    }
}

/// Copie un événement à `adresse` : l'en-tête, le nom, puis des zéros
/// (`copy_event_to_user`). Rend sa taille.
fn copier(e: &Evenement, adresse: u64) -> Result<usize, i64> {
    let taille = e.taille();
    let mut entete = [0u8; TAILLE_EVENEMENT];
    entete[0..4].copy_from_slice(&e.wd.to_le_bytes());
    entete[4..8].copy_from_slice(&e.masque.to_le_bytes());
    entete[8..12].copy_from_slice(&e.cookie.to_le_bytes());
    entete[12..16].copy_from_slice(&((taille - TAILLE_EVENEMENT) as u32).to_le_bytes());
    copier_vers_utilisateur(adresse, &entete).map_err(|_| -EFAULT)?;
    if !e.nom.is_empty() {
        let nom = adresse + TAILLE_EVENEMENT as u64;
        copier_vers_utilisateur(nom, &e.nom).map_err(|_| -EFAULT)?;
        // Au plus 16 zéros : le nom et son zéro final, complétés jusqu'au
        // multiple de 16 suivant.
        let zeros = [0u8; TAILLE_EVENEMENT];
        copier_vers_utilisateur(nom + e.nom.len() as u64, &zeros[..taille - TAILLE_EVENEMENT - e.nom.len()]).map_err(|_| -EFAULT)?;
    }
    Ok(taille)
}

/// read d'une instance (`inotify_read`) : autant d'événements entiers qu'il
/// en tient dans le tampon. Le premier ne tient pas : EINVAL (même un read
/// de 0 octet, s'il y a un événement). Rien à lire : EAGAIN en non
/// bloquant, sinon on attend ; un signal : ERESTARTSYS (reprise.rs) ; ce qui
/// est déjà lu est rendu. Un événement qui ne se copie pas (EFAULT) est
/// perdu, et l'appel rend EFAULT, même après d'autres (Linux).
pub fn lire(g: &Groupe, non_bloquant: bool, tampon: u64, longueur: u64) -> Result<u64, i64> {
    let mut lus: u64 = 0;
    let mut signal = false;
    let r = loop {
        match g.prendre((longueur - lus).min(usize::MAX as u64) as usize) {
            Err(e) => break Err(e),
            Ok(Some(e)) => {
                // Pris sous le verrou de la file, copié hors de lui (la
                // copie peut fauter).
                match copier(&e, tampon + lus) {
                    Ok(n) => lus += n as u64,
                    Err(e) => break Err(e),
                }
                continue;
            }
            Ok(None) => {}
        }
        if non_bloquant {
            break Err(-EAGAIN);
        }
        if signal {
            break Err(-crate::reprise::ERESTARTSYS);
        }
        if lus > 0 {
            break Ok(lus);
        }
        // Attendre, sans réveil perdu : inscrit dans la file d'attente, puis
        // la file d'événements regardée encore une fois, interruptions
        // coupées jusqu'au sommeil (attente.rs).
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        t.preparer_sommeil(Sommeil::Interruptible);
        g.attente.inscrire();
        if g.file.verrouiller().evenements.is_empty() {
            signal = attente::dormir(None, Sommeil::Interruptible) == Reveil::Signal;
        }
        g.attente.retirer(t);
        t.reveille();
        if interruptions {
            cpu::activer_interruptions();
        }
    };
    match r {
        Err(e) if e == -EFAULT => Err(e),
        _ if lus > 0 => Ok(lus),
        r => r,
    }
}

/// readv d'une instance : rien à lire en tout, 0, sans la regarder
/// (`vfs_readv`) ; sinon chaque morceau lu à son tour, comme un read (une
/// instance n'a pas de `read_iter` : `do_loop_readv_writev`), le premier tel
/// qu'il est, les morceaux vides qui suivent sautés (`iov_iter_advance`) ;
/// on s'arrête à la première erreur, ou au premier morceau pas rempli.
/// Mesuré : un premier morceau de 20 octets rend EINVAL, même si le suivant
/// est assez grand ; {0, 16} aussi, s'il y a un événement ; {16, 0, 16} lit
/// deux événements de 16 octets ; {0} rend 0, même vide et bloquante.
pub fn lire_morceaux(g: &Groupe, non_bloquant: bool, morceaux: &[(u64, u64)]) -> Result<u64, i64> {
    if morceaux.iter().all(|&(_, l)| l == 0) {
        return Ok(0);
    }
    let mut total = 0u64;
    for (i, &(base, longueur)) in morceaux.iter().enumerate() {
        if longueur == 0 && i > 0 {
            continue;
        }
        match lire(g, non_bloquant, base, longueur) {
            Ok(n) => {
                total += n;
                if n != longueur {
                    break;
                }
            }
            Err(e) if total == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(total)
}

/// ioctl d'une instance (`inotify_ioctl`) : FIONREAD (un int),
/// INOTIFY_IOC_SETNEXTWD (de 1 à INT_MAX, EINVAL sinon) ; le reste :
/// ENOTTY.
pub fn ioctl(g: &Groupe, requete: u64, argument: u64) -> i64 {
    match requete {
        FIONREAD => {
            let n = g.octets() as i32;
            match copier_vers_utilisateur(argument, &n.to_le_bytes()) {
                Ok(()) => 0,
                Err(_) => -EFAULT,
            }
        }
        INOTIFY_IOC_SETNEXTWD if (1..=i32::MAX as u64).contains(&argument) => {
            g.file.verrouiller().curseur = argument as i32;
            0
        }
        INOTIFY_IOC_SETNEXTWD => -EINVAL,
        _ => -ENOTTY,
    }
}
