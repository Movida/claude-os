//! WASI, côté noyau : les appels système des programmes WebAssembly.
//!
//! WASI (« WebAssembly System Interface ») est l'interface système faite
//! pour WebAssembly : un programme importe ses appels système, comme des
//! fonctions, du module « wasi_snapshot_preview1 » (la version « preview
//! 1 », celle que visent les compilateurs). Le noyau les fournit comme
//! fonctions hôtes (voir wasm::Hote) :
//!   - fd_write, fd_read, fd_seek, fd_tell, fd_close : lire et écrire ses
//!     descripteurs (la console, des fichiers) ;
//!   - fd_prestat_get, fd_prestat_dir_name : les dossiers « pré-ouverts »
//!     qu'on lui donne (les `--dir=` de sa ligne de /etc/demarrage) ;
//!   - args_sizes_get, args_get, environ_sizes_get, environ_get : ses
//!     arguments et son environnement, ceux de sa ligne ;
//!   - path_open, path_filestat_get, fd_filestat_get, fd_fdstat_get,
//!     fd_readdir : les fichiers et les dossiers, sur le même système de
//!     fichiers que les programmes Linux (vfs.rs) ;
//!   - clock_time_get : l'heure (temps.rs) ;
//!   - poll_oneoff : attendre une échéance, ou qu'un descripteur soit prêt
//!     (6f) ; sched_yield : céder le processeur (6f) ;
//!   - sock_accept, sock_recv, sock_send, sock_shutdown (6h) : les sockets
//!     TCP, sur une écoute pré-ouverte (les `--tcplisten=` de sa ligne) ;
//!     fd_read, fd_write, fd_close, fd_fdstat_get et poll_oneoff s'en
//!     servent aussi ; fd_fdstat_set_flags (6h) : APPEND et NONBLOCK ;
//!   - proc_exit : terminer le programme.
//!
//! Tout passe par la mémoire du programme : il donne des adresses dans SA
//! mémoire linéaire, où le noyau lit ce qu'il faut écrire et écrit le
//! résultat. Chaque adresse est vérifiée : hors de cette mémoire, l'appel
//! rend EFAULT, comme Linux pour un pointeur invalide. Le programme ne peut
//! désigner que sa propre mémoire : le bac à sable tient aussi à travers
//! les appels système.
//!
//! Il tient aussi pour les fichiers (l'isolation à la façon de Nebulet,
//! voir CLAUDE.md) : un programme WASI n'a pas de racine ni de dossier
//! courant, seulement des dossiers pré-ouverts (les descripteurs 3, 4...,
//! dans l'ordre des `--dir=` de sa ligne, comme `wasmtime --dir` ; aucun
//! sans option) ; chaque chemin part de l'un d'eux, et ne doit jamais en
//! sortir.
//! La résolution « sous » un dossier (../fichiers/src/chemins.rs, le
//! RESOLVE_BENEATH de Linux) refuse un « .. » qui remonterait au-dessus, un
//! chemin absolu, un lien symbolique absolu : EPERM, comme wasmtime. Les
//! « droits » de preview1 (fs_rights_base) ne décident que du mode
//! d'ouverture (lecture, écriture), comme chez wasmtime, qui ne les
//! vérifie plus vraiment ; les droits Unix du fichier, eux, s'appliquent
//! (le programme est l'utilisateur 1000, comme les programmes Linux).
//!
//! Les sockets suivent le modèle de capacités de WASI preview 1 : un
//! programme ne crée pas de socket (ni `socket`, ni `connect`, ni `bind` :
//! preview 1 ne les a pas), il reçoit des écoutes du lanceur, et les
//! connexions qu'il y accepte. Preview 2 (`wasi:sockets`) en crée, mais
//! demande le modèle de composants : hors de propos. Notre modèle est
//! l'ancienne implémentation de wasmtime, `wasi-common` (gardée pour
//! wasi-threads) : le preview 1 du wasmtime d'aujourd'hui, bâti sur preview
//! 2, n'a plus de sockets (ses `sock_*` rendent ENOTSOCK), mais son lanceur
//! crée encore les écoutes de `--tcplisten`. Les écoutes viennent APRÈS les
//! dossiers pré-ouverts (3, 4... pour les dossiers, puis les écoutes) :
//! wasi-libc cherche ses dossiers en parcourant 3, 4... jusqu'au premier
//! EBADF de `fd_prestat_get`, qu'une socket rend (wasmtime, qui les met
//! avant, cache ainsi les dossiers à wasi-libc). Un programme trouve son
//! écoute par `fd_fdstat_get` (une SOCKET_STREAM).
//!
//! Un appel système ne doit pas non plus prendre la machine en otage : il
//! n'est pas interrompu par le carburant (voir wasm::Hote). Chaque appel
//! fait donc un travail borné (au plus 1024 octets lus ou écrits, sauf
//! RECV_WAITALL, voir `sock_recv`), et compte ce travail en carburant.
//! Mais il peut ATTENDRE, en dormant (le processeur passe aux autres) :
//! `poll_oneoff` jusqu'à son échéance ou un descripteur prêt (6f, et une
//! socket depuis 6h), comme nanosleep et poll pour un programme Linux ; et
//! depuis 6h, la réception d'une socket bloquante, son envoi quand la place
//! manque, et `sock_accept` d'une écoute que le programme a rendue
//! bloquante (`fd_fdstat_set_flags`), comme dans wasi-common. Un
//! programme WebAssembly n'a pas de signal pour l'interrompre (ni de ^C
//! avant le terminal, 6k) : un client qui ne vient jamais le laisse
//! attendre pour toujours (le détecteur d'interblocage ne s'occupe que des
//! programmes Linux, qu'il peut arrêter par SIGKILL).

use alloc::vec::Vec;
use core::fmt;
use wasm::module::{DescriptionImport, TypeFonction, TypeValeur};
use wasm::validateur::ModuleValide;
use wasm::{Externe, Hote, Magasin, Piege, Valeur};

use crate::appels_fichiers::FichierTenu;
use crate::descripteurs::{Descripteur, Descripteurs, Fichier, FichierOuvert, Refus, Sorte};
use crate::faillible::{self, VecFaillible};
use crate::partage::ArcVide;
use crate::reseau::socket::{self, Protocole, Socket};
use crate::reseau::tcp;
use crate::sondage::{self, Delai, POLLERR, POLLHUP, POLLIN, POLLOUT, Table};
use crate::{appels_fichiers, appels_reseau, console, temps, vfs};
use crate::descripteurs::Tenu;
use fichiers::chemins::Depart;
use fichiers::montages::{Creation, Modification, Objet, en_tmpfs};
use fichiers::tmpfs::{Attributs, Numero, Ouverture, suivre_pour};
use fichiers::{Erreur, Identite, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, Temps};

/// Le module d'où un programme WASI importe ses appels système.
const MODULE: &str = "wasi_snapshot_preview1";

// Les codes d'erreur de WASI (les errno de POSIX, numérotés autrement :
// la liste de wasi_snapshot_preview1).
const SUCCES: u32 = 0;
const EACCES: u32 = 2;
const EADDRINUSE: u32 = 3;
const EADDRNOTAVAIL: u32 = 4;
const EAGAIN: u32 = 6;
const EBADF: u32 = 8;
const EBUSY: u32 = 10;
const ECONNABORTED: u32 = 13;
const ECONNREFUSED: u32 = 14;
const ECONNRESET: u32 = 15;
const EEXIST: u32 = 20;
const EFAULT: u32 = 21;
const EFBIG: u32 = 22;
const EHOSTUNREACH: u32 = 23;
const EINTR: u32 = 27;
const EINVAL: u32 = 28;
const EIO: u32 = 29;
const EISDIR: u32 = 31;
const ELOOP: u32 = 32;
const EMFILE: u32 = 33;
const EMLINK: u32 = 34;
const EMSGSIZE: u32 = 35;
const ENAMETOOLONG: u32 = 37;
const ENETDOWN: u32 = 38;
const ENETUNREACH: u32 = 40;
const ENFILE: u32 = 41;
const ENOBUFS: u32 = 42;
const ENOENT: u32 = 44;
const ENOMEM: u32 = 48;
const ENOSPC: u32 = 51;
const ENOTCONN: u32 = 53;
const ENOTDIR: u32 = 54;
const ENOTEMPTY: u32 = 55;
const ENOTSOCK: u32 = 57;
const ENOTSUP: u32 = 58;
const ENXIO: u32 = 60;
const EPERM: u32 = 63;
const EPIPE: u32 = 64;
const ESPIPE: u32 = 70;
const ETIMEDOUT: u32 = 73;
const ETXTBSY: u32 = 74;

/// Une erreur du système de fichiers, en errno de WASI. Sortir du dossier
/// pré-ouvert (EXDEV de la résolution « sous ») : EPERM, comme wasmtime.
fn errno(e: Erreur) -> u32 {
    match e {
        Erreur::EPERM | Erreur::EXDEV => EPERM,
        Erreur::ENOENT => ENOENT,
        Erreur::ENXIO => ENXIO,
        Erreur::ENOMEM => ENOMEM,
        Erreur::EACCES => EACCES,
        Erreur::EBUSY => EBUSY,
        Erreur::EEXIST => EEXIST,
        Erreur::ENOTDIR => ENOTDIR,
        Erreur::EISDIR => EISDIR,
        Erreur::EINVAL => EINVAL,
        Erreur::ETXTBSY => ETXTBSY,
        Erreur::EFBIG => EFBIG,
        Erreur::ENOSPC => ENOSPC,
        Erreur::EMLINK => EMLINK,
        Erreur::ENAMETOOLONG => ENAMETOOLONG,
        Erreur::ENOTEMPTY => ENOTEMPTY,
        Erreur::ELOOP => ELOOP,
        Erreur::EOPNOTSUPP => ENOTSUP,
    }
}

/// Une erreur d'une socket (l'errno de Linux, négatif, que rendent
/// reseau/tcp.rs et appels_reseau.rs), en errno de WASI : les mêmes noms,
/// numérotés autrement. ERESTARTSYS (une attente interrompue : la tâche
/// qu'on arrête, un programme WebAssembly n'a pas de signaux) : EINTR.
/// Toutes les erreurs que rendent nos sockets TCP ; une autre (il n'y en a
/// pas aujourd'hui) : EIO.
fn errno_reseau(e: i64) -> u32 {
    const EAFNOSUPPORT_: u32 = 5;
    const EALREADY_: u32 = 7;
    const EINPROGRESS_: u32 = 26;
    const EISCONN_: u32 = 30;
    match -e {
        1 => EPERM,
        88 => ENOTSOCK,
        97 => EAFNOSUPPORT_,
        106 => EISCONN_,
        114 => EALREADY_,
        115 => EINPROGRESS_,
        4 | 512 => EINTR,
        9 => EBADF,
        11 => EAGAIN,
        12 => ENOMEM,
        13 => EACCES,
        14 => EFAULT,
        22 => EINVAL,
        23 => ENFILE,
        24 => EMFILE,
        32 => EPIPE,
        90 => EMSGSIZE,
        95 => ENOTSUP,
        98 => EADDRINUSE,
        99 => EADDRNOTAVAIL,
        100 => ENETDOWN,
        101 => ENETUNREACH,
        103 => ECONNABORTED,
        104 => ECONNRESET,
        105 => ENOBUFS,
        107 => ENOTCONN,
        110 => ETIMEDOUT,
        111 => ECONNREFUSED,
        113 => EHOSTUNREACH,
        _ => EIO,
    }
}

/// Les numéros de nos fonctions hôtes, donnés à `Magasin::ajouter_fonction_hote`.
const FD_WRITE: u32 = 0;
const PROC_EXIT: u32 = 1;
const FD_READ: u32 = 2;
const FD_SEEK: u32 = 3;
const FD_TELL: u32 = 4;
const FD_CLOSE: u32 = 5;
const FD_PRESTAT_GET: u32 = 6;
const FD_PRESTAT_DIR_NAME: u32 = 7;
const PATH_OPEN: u32 = 8;
const FD_FDSTAT_GET: u32 = 9;
const FD_FILESTAT_GET: u32 = 10;
const PATH_FILESTAT_GET: u32 = 11;
const FD_READDIR: u32 = 12;
const CLOCK_TIME_GET: u32 = 13;
const ARGS_SIZES_GET: u32 = 14;
const ARGS_GET: u32 = 15;
const ENVIRON_SIZES_GET: u32 = 16;
const ENVIRON_GET: u32 = 17;
const POLL_ONEOFF: u32 = 18;
const SCHED_YIELD: u32 = 19;
const SOCK_ACCEPT: u32 = 20;
const SOCK_RECV: u32 = 21;
const SOCK_SEND: u32 = 22;
const SOCK_SHUTDOWN: u32 = 23;
const FD_FDSTAT_SET_FLAGS: u32 = 24;

/// Le plus de morceaux qu'un fd_write ou un fd_read peut décrire : l'IOV_MAX
/// de POSIX, que Linux impose aussi (UIO_MAXIOV). Au-delà : EINVAL.
const MORCEAUX_MAX: u32 = 1024;

/// Le plus d'octets qu'un fd_write ou un fd_read transfère : au-delà, une
/// partie, et le nombre le dit, ce que POSIX et WASI permettent ; le
/// programme recommence avec la suite. Sur un vrai port série à 115 200
/// bauds, 1024 octets prennent déjà 90 ms.
const TRANSFERT_MAX: u32 = 1024;

/// Le premier descripteur pré-ouvert (après la console, 0, 1 et 2).
const PREMIER_PREOUVERT: u64 = 3;

/// Le `backlog` d'une écoute pré-ouverte : 128, celui de la bibliothèque
/// standard de Rust (`TcpListener::bind`), qui crée celles de wasmtime.
const BACKLOG: i32 = 128;

/// Les drapeaux d'un fichier ouvert (ceux de Linux, F_GETFL).
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
/// Les `fdflags` de WASI : APPEND, NONBLOCK.
const FDFLAGS_APPEND: u16 = 1;
const FDFLAGS_NONBLOCK: u16 = 4;

/// Les écoutes TCP pré-ouvertes d'un programme (les `--tcplisten=` de sa
/// ligne), créées par le lanceur AVANT sa tâche, comme le lanceur de
/// wasmtime avant d'instancier le module : une adresse prise refuse la
/// ligne, et la ligne suivante de /etc/demarrage (un client) trouve déjà
/// l'écoute. Leurs fichiers ouverts, dans l'ordre ; ceux que le programme
/// n'a pas reçus (sa tâche n'a pas pu partir, ses descripteurs n'ont pas pu
/// être faits) sont lâchés, et leurs sockets fermées, à la disparition de
/// `Ecoutes`.
pub struct Ecoutes(Vec<Fichier>);

impl Ecoutes {
    pub fn new() -> Ecoutes {
        Ecoutes(Vec::new())
    }

    /// Ajoute l'écoute de `adresse`:`port` pour le programme `qui` : une
    /// socket TCP à lui, liée, qui écoute, dans un fichier ouvert NON
    /// BLOQUANT, comme celles du lanceur de wasmtime (`set_nonblocking(true)` :
    /// un programme attend un client par poll_oneoff, puis l'accepte ; il
    /// peut la rendre bloquante, `fd_fdstat_set_flags`, comme le font mio et
    /// tokio pour leurs propres réglages). L'errno de Linux sinon (les
    /// refus de `bind` et `listen` : EADDRINUSE, EADDRNOTAVAIL, EACCES pour
    /// un port sous 1024...), et rien ne reste.
    pub fn ouvrir(&mut self, qui: Identite, adresse: [u8; 4], port: u16) -> Result<(), i64> {
        const ENOMEM_: i64 = 12;
        const ENFILE_: i64 = 23;
        const ENOBUFS_: i64 = 105;
        self.0.try_reserve(1).map_err(|_| -ENOMEM_)?;
        let place = ArcVide::new().map_err(|_| -ENFILE_)?;
        let s = Socket::new(Protocole::Tcp, tcp::SOCK_STREAM as u16, tcp::IPPROTO_TCP as u16, qui.uid).and_then(Socket::tcp).ok_or(-ENOBUFS_)?;
        let s = place.remplir(s);
        // Liée, la socket est dans la table des ports : un refus doit la
        // fermer, pour qu'elle en sorte.
        let ecoute = tcp::lier(&s, &socket::sockaddr_in(adresse, port))
            .and_then(|()| tcp::ecouter(&s, BACKLOG))
            .and_then(|()| appels_reseau::fichier_de_socket(s.clone(), qui, true));
        let f = match ecoute {
            Ok(f) => f,
            Err(e) => {
                socket::fermer(&s);
                return Err(e);
            }
        };
        match vfs::avec_systeme(|sys, _| sys.ouverts.ajouter(f)) {
            Ok(fichier) => {
                self.0.ajouter_dans_la_place(fichier);
                Ok(())
            }
            Err(f) => {
                if let Tenu::Tmpfs(o) = f.tenu {
                    vfs::avec(|fs, cadres| fs.fermer(&o, cadres));
                }
                socket::fermer(&s);
                Err(-ENOMEM_)
            }
        }
    }
}

impl Drop for Ecoutes {
    /// Les écoutes que le programme n'a pas reçues : leurs fichiers lâchés
    /// (le dernier `close`), leurs sockets fermées tout de suite.
    fn drop(&mut self) {
        for f in self.0.drain(..) {
            vfs::avec_systeme(|s, cadres| s.lacher(f, cadres));
        }
        socket::fermer_les_differees();
    }
}

/// Un dossier pré-ouvert : son descripteur, et le nom que voit le
/// programme (le chemin donné à `--dir=`).
struct Preouvert {
    fd: u64,
    nom: Vec<u8>,
}

/// L'hôte des programmes WASI : ses descripteurs, comme un processus
/// Linux (la même table, sur les mêmes fichiers ouverts), ses dossiers
/// pré-ouverts, ses arguments et son environnement.
pub struct Wasi {
    descripteurs: Descripteurs,
    /// Qui il est, pour les droits des fichiers.
    identite: Identite,
    /// Les dossiers pré-ouverts encore ouverts. Fermé, un descripteur en
    /// sort : son numéro peut être repris par path_open, ce n'est plus lui
    /// (wasmtime garde de même, dans sa table, quels descripteurs sont
    /// pré-ouverts).
    preouverts: Vec<Preouvert>,
    /// argv et envp, chacun d'un bloc : les chaînes à la suite, chacune
    /// avec son zéro final (ce que args_get écrit tel quel).
    arguments: (Vec<u8>, u32),
    environnement: (Vec<u8>, u32),
}

/// Des chaînes mises à la suite, chacune avec son zéro final, et leur
/// nombre ; ENOMEM si la place manque. (Aucune ne contient de zéro :
/// formats::commande les refuse.)
fn a_la_suite(chaines: &[&[u8]]) -> Result<(Vec<u8>, u32), Erreur> {
    let mut v = faillible::avec_capacite(chaines.iter().map(|c| c.len() + 1).sum())?;
    for c in chaines {
        v.ajouter_tranche(c)?;
        v.ajouter(0)?;
    }
    Ok((v, chaines.len() as u32))
}

impl Wasi {
    /// Un hôte neuf pour l'identité `identite` : la console en 0, 1 et 2,
    /// puis les `dossiers` pré-ouverts en 3, 4... (ouverts avec ses droits :
    /// il doit pouvoir les traverser et les lire), puis ses `ecoutes`, ses
    /// `arguments` et son `environnement`. En cas d'échec, l'erreur, et le
    /// dossier en cause (aucun pour la console ou la mémoire) ; rien ne
    /// reste ouvert.
    pub fn new<'a>(identite: Identite, dossiers: &[&'a [u8]], mut ecoutes: Ecoutes, arguments: &[&[u8]], environnement: &[&[u8]])
        -> Result<Wasi, (Erreur, Option<&'a [u8]>)> {
        // Les chaînes d'abord : rien n'est encore ouvert si la place
        // manque (Descripteurs ne ferme rien en disparaissant).
        let (arguments, environnement) = match (a_la_suite(arguments), a_la_suite(environnement)) {
            (Ok(a), Ok(e)) => (a, e),
            _ => return Err((Erreur::ENOMEM, None)),
        };
        let mut descripteurs = Descripteurs::new();
        appels_fichiers::ouvrir_console(&mut descripteurs).map_err(|e| (e, None))?;
        let mut wasi = Wasi { descripteurs, identite, preouverts: Vec::new(), arguments, environnement };
        if wasi.preouverts.try_reserve_exact(dossiers.len()).is_err() {
            return Err((Erreur::ENOMEM, None));
        }
        for (i, &dossier) in dossiers.iter().enumerate() {
            let fd = PREMIER_PREOUVERT + i as u64;
            let nom = faillible::copie(dossier).map_err(|_| (Erreur::ENOMEM, None))?;
            // `wasi` est rendu en cas d'erreur : son Drop ferme ce qui est
            // déjà ouvert.
            let f = appels_fichiers::ouvrir_pour(identite, dossier, true, false, true).map_err(|e| (e, Some(dossier)))?;
            if wasi.descripteurs.remplacer(fd, Descripteur { fichier: f, fermer_a_l_exec: false }).is_err() {
                vfs::avec_systeme(|s, cadres| s.lacher(f, cadres));
                return Err((Erreur::ENOMEM, None));
            }
            wasi.preouverts.ajouter(Preouvert { fd, nom }).map_err(|_| (Erreur::ENOMEM, None))?;
        }
        // Les écoutes, après les dossiers : prises de la fin, chacune à son
        // numéro ; celles qui restent si l'une échoue sont lâchées avec
        // `ecoutes`, celles qui sont rangées avec `wasi`.
        let premiere = PREMIER_PREOUVERT + dossiers.len() as u64;
        while let Some(f) = ecoutes.0.pop() {
            let fd = premiere + ecoutes.0.len() as u64;
            if wasi.descripteurs.remplacer(fd, Descripteur { fichier: f, fermer_a_l_exec: false }).is_err() {
                vfs::avec_systeme(|s, cadres| s.lacher(f, cadres));
                return Err((Erreur::ENOMEM, None));
            }
        }
        Ok(wasi)
    }

    /// Le dossier pré-ouvert du descripteur `fd`, s'il en est un.
    fn preouvert(&self, fd: u32) -> Option<&Preouvert> {
        self.preouverts.iter().find(|p| p.fd == fd as u64)
    }
}

impl Drop for Wasi {
    /// La fin du programme : ses descripteurs fermés.
    fn drop(&mut self) {
        self.descripteurs.fermer_tous();
        crate::reseau::socket::fermer_les_differees();
    }
}

/// Pourquoi les imports d'un module ne peuvent pas être fournis.
pub enum RefusImports<'a> {
    /// Un import que nous n'avons pas : son module et son nom.
    Inconnu(&'a str, &'a str),
    PlusDeMemoire,
}

impl fmt::Display for RefusImports<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RefusImports::Inconnu(module, nom) => write!(f, "import inconnu : {} {}", module, nom),
            RefusImports::PlusDeMemoire => f.write_str("plus de memoire"),
        }
    }
}

/// Ce qu'il faut donner aux imports de `module` (dans leur ordre), après
/// avoir ajouté nos fonctions au magasin ; ou pourquoi on ne peut pas.
pub fn imports<'a>(magasin: &mut Magasin, module: &'a ModuleValide) -> Result<Vec<Externe>, RefusImports<'a>> {
    use TypeValeur::{I32, I64};
    let mut externes = Vec::new();
    for import in &module.module().imports {
        let inconnu = RefusImports::Inconnu(&import.module, &import.nom);
        let DescriptionImport::Fonction(_) = import.description else { return Err(inconnu) };
        if import.module != MODULE {
            return Err(inconnu);
        }
        let (numero, parametres, resultats): (u32, &[TypeValeur], &[TypeValeur]) = match import.nom.as_str() {
            // fd_write(fichier, morceaux, nombre, ecrits) -> errno
            "fd_write" => (FD_WRITE, &[I32, I32, I32, I32], &[I32]),
            // fd_read(fichier, morceaux, nombre, lus) -> errno
            "fd_read" => (FD_READ, &[I32, I32, I32, I32], &[I32]),
            // fd_seek(fichier, decalage, d_ou, nouvelle) -> errno
            "fd_seek" => (FD_SEEK, &[I32, I64, I32, I32], &[I32]),
            // fd_tell(fichier, position) -> errno
            "fd_tell" => (FD_TELL, &[I32, I32], &[I32]),
            // fd_close(fichier) -> errno
            "fd_close" => (FD_CLOSE, &[I32], &[I32]),
            // fd_prestat_get(fichier, prestat) -> errno
            "fd_prestat_get" => (FD_PRESTAT_GET, &[I32, I32], &[I32]),
            // fd_prestat_dir_name(fichier, chemin, longueur) -> errno
            "fd_prestat_dir_name" => (FD_PRESTAT_DIR_NAME, &[I32, I32, I32], &[I32]),
            // path_open(dossier, drapeaux, chemin, longueur, oflags,
            //           droits, droits_herites, fdflags, fichier) -> errno
            "path_open" => (PATH_OPEN, &[I32, I32, I32, I32, I32, I64, I64, I32, I32], &[I32]),
            // fd_fdstat_get(fichier, fdstat) -> errno
            "fd_fdstat_get" => (FD_FDSTAT_GET, &[I32, I32], &[I32]),
            // fd_fdstat_set_flags(fichier, fdflags) -> errno
            "fd_fdstat_set_flags" => (FD_FDSTAT_SET_FLAGS, &[I32, I32], &[I32]),
            // fd_filestat_get(fichier, filestat) -> errno
            "fd_filestat_get" => (FD_FILESTAT_GET, &[I32, I32], &[I32]),
            // path_filestat_get(dossier, drapeaux, chemin, longueur, filestat) -> errno
            "path_filestat_get" => (PATH_FILESTAT_GET, &[I32, I32, I32, I32, I32], &[I32]),
            // fd_readdir(dossier, tampon, longueur, cookie, utilises) -> errno
            "fd_readdir" => (FD_READDIR, &[I32, I32, I32, I64, I32], &[I32]),
            // clock_time_get(horloge, precision, temps) -> errno
            "clock_time_get" => (CLOCK_TIME_GET, &[I32, I64, I32], &[I32]),
            // args_sizes_get(nombre, taille) -> errno
            "args_sizes_get" => (ARGS_SIZES_GET, &[I32, I32], &[I32]),
            // args_get(pointeurs, chaines) -> errno
            "args_get" => (ARGS_GET, &[I32, I32], &[I32]),
            // environ_sizes_get(nombre, taille) -> errno
            "environ_sizes_get" => (ENVIRON_SIZES_GET, &[I32, I32], &[I32]),
            // environ_get(pointeurs, chaines) -> errno
            "environ_get" => (ENVIRON_GET, &[I32, I32], &[I32]),
            // poll_oneoff(abonnements, evenements, nombre, publies) -> errno
            "poll_oneoff" => (POLL_ONEOFF, &[I32, I32, I32, I32], &[I32]),
            // sched_yield() -> errno
            "sched_yield" => (SCHED_YIELD, &[], &[I32]),
            // sock_accept(ecoute, fdflags, fichier) -> errno
            "sock_accept" => (SOCK_ACCEPT, &[I32, I32, I32], &[I32]),
            // sock_recv(socket, morceaux, nombre, riflags, recus, roflags) -> errno
            "sock_recv" => (SOCK_RECV, &[I32, I32, I32, I32, I32, I32], &[I32]),
            // sock_send(socket, morceaux, nombre, siflags, envoyes) -> errno
            "sock_send" => (SOCK_SEND, &[I32, I32, I32, I32, I32], &[I32]),
            // sock_shutdown(socket, sdflags) -> errno
            "sock_shutdown" => (SOCK_SHUTDOWN, &[I32, I32], &[I32]),
            // proc_exit(code)
            "proc_exit" => (PROC_EXIT, &[I32], &[]),
            _ => return Err(inconnu),
        };
        // Le type exact : l'instanciation refusera un programme qui déclare
        // une fonction autrement.
        let boite = |types: &[TypeValeur]| faillible::boite_de_tranche(types).map_err(|_| RefusImports::PlusDeMemoire);
        let t = TypeFonction { parametres: boite(parametres)?, resultats: boite(resultats)? };
        externes.ajouter(magasin.ajouter_fonction_hote(t, numero)).map_err(|_| RefusImports::PlusDeMemoire)?;
    }
    Ok(externes)
}

impl Hote for Wasi {
    fn appeler(
        &mut self,
        numero: u32,
        arguments: &[Valeur],
        resultats: &mut [Valeur],
        memoire: Option<&mut [u8]>,
        cout: &mut u64,
    ) -> Result<(), Piege> {
        // Les types sont ceux que `imports` a déclarés : l'interpréteur les
        // a vérifiés.
        let a = |i: usize| match arguments[i] {
            Valeur::I32(x) => x,
            _ => unreachable!("argument i32"),
        };
        let a64 = |i: usize| match arguments[i] {
            Valeur::I64(x) => x,
            _ => unreachable!("argument i64"),
        };
        if numero == SCHED_YIELD {
            crate::ordonnanceur::ceder();
            resultats[0] = Valeur::I32(SUCCES);
            return Ok(());
        }
        if numero == PROC_EXIT {
            // Terminer : un « piège » de l'hôte, qui arrête l'exécution avec
            // le code de sortie ; le noyau le reconnaît (programmes.rs).
            return Err(Piege::Hote(a(0)));
        }
        let Some(m) = memoire else {
            resultats[0] = Valeur::I32(EFAULT);
            return Ok(());
        };
        let errno = match numero {
            FD_WRITE => self.fd_rw(a(0), a(1), a(2), a(3), m, cout, true),
            FD_READ => self.fd_rw(a(0), a(1), a(2), a(3), m, cout, false),
            FD_SEEK => self.fd_seek(a(0), a64(1) as i64, a(2), a(3), m),
            FD_TELL => self.fd_seek(a(0), 0, 1, a(1), m),
            FD_CLOSE => self.fd_close(a(0)),
            FD_PRESTAT_GET => self.fd_prestat_get(a(0), a(1), m),
            FD_PRESTAT_DIR_NAME => self.fd_prestat_dir_name(a(0), a(1), a(2), m),
            PATH_OPEN => self.path_open(a(0), a(1), a(2), a(3), a(4), a64(5), a(7), a(8), m),
            FD_FDSTAT_GET => self.fd_fdstat_get(a(0), a(1), m),
            FD_FILESTAT_GET => self.fd_filestat_get(a(0), a(1), m),
            PATH_FILESTAT_GET => self.path_filestat_get(a(0), a(1), a(2), a(3), a(4), m),
            FD_READDIR => self.fd_readdir(a(0), a(1), a(2), a64(3), a(4), m, cout),
            CLOCK_TIME_GET => clock_time_get(a(0), a(2), m),
            POLL_ONEOFF => self.poll_oneoff(a(0), a(1), a(2), a(3), m, cout),
            ARGS_SIZES_GET => tailles(&self.arguments, a(0), a(1), m),
            ARGS_GET => chaines(&self.arguments, a(0), a(1), m, cout),
            ENVIRON_SIZES_GET => tailles(&self.environnement, a(0), a(1), m),
            ENVIRON_GET => chaines(&self.environnement, a(0), a(1), m, cout),
            SOCK_ACCEPT => self.sock_accept(a(0), a(1), a(2), m),
            SOCK_RECV => self.sock_recv(a(0), a(1), a(2), a(3), a(4), a(5), m, cout),
            SOCK_SEND => self.sock_send(a(0), a(1), a(2), a(3), a(4), m, cout),
            SOCK_SHUTDOWN => self.sock_shutdown(a(0), a(1)),
            FD_FDSTAT_SET_FLAGS => self.fd_fdstat_set_flags(a(0), a(1)),
            _ => unreachable!("fonction hote inconnue"),
        };
        // Les sockets dont l'appel a fait le dernier `close` (comme à la
        // sortie d'un appel système, reseau/socket.rs).
        crate::reseau::socket::fermer_les_differees();
        resultats[0] = Valeur::I32(errno);
        Ok(())
    }
}

/// args_sizes_get, environ_sizes_get : le nombre de chaînes, et la place
/// qu'elles prennent (zéros finaux compris).
fn tailles(chaines: &(Vec<u8>, u32), nombre: u32, taille: u32, m: &mut [u8]) -> u32 {
    match ecrire(m, nombre, &chaines.1.to_le_bytes()).and_then(|()| ecrire(m, taille, &(chaines.0.len() as u32).to_le_bytes())) {
        Ok(()) => SUCCES,
        Err(e) => e,
    }
}

/// args_get, environ_get : les chaînes à `tampon`, à la suite, et l'adresse
/// de chacune dans le tableau `pointeurs` (des adresses de 32 bits). Tout
/// est vérifié avant d'écrire : un tableau hors de la mémoire ne laisse
/// rien d'écrit à moitié. Le travail, proportionnel aux octets, est compté
/// en carburant.
fn chaines(chaines: &(Vec<u8>, u32), pointeurs: u32, tampon: u32, m: &mut [u8], cout: &mut u64) -> u32 {
    let (octets, nombre) = (&chaines.0, chaines.1);
    let taille_tableau = nombre.checked_mul(4);
    if taille_tableau.and_then(|t| plage(m, pointeurs, t)).is_none() || plage(m, tampon, octets.len() as u32).is_none() {
        return EFAULT;
    }
    *cout += octets.len() as u64 + nombre as u64;
    let mut adresse = tampon;
    let mut i = 0;
    for chaine in octets.split_inclusive(|&o| o == 0) {
        // Vérifiés plus haut : ces écritures tiennent dans la mémoire.
        let _ = ecrire(m, pointeurs + 4 * i, &adresse.to_le_bytes());
        adresse += chaine.len() as u32;
        i += 1;
    }
    let _ = ecrire(m, tampon, octets);
    SUCCES
}

/// Les `longueur` octets de la mémoire du programme à partir de `adresse`,
/// s'ils y sont tous.
fn plage(memoire: &[u8], adresse: u32, longueur: u32) -> Option<&[u8]> {
    memoire.get(adresse as usize..(adresse as usize).checked_add(longueur as usize)?)
}

fn plage_mut(memoire: &mut [u8], adresse: u32, longueur: u32) -> Option<&mut [u8]> {
    memoire.get_mut(adresse as usize..(adresse as usize).checked_add(longueur as usize)?)
}

fn lire_u32(memoire: &[u8], adresse: u32) -> Option<u32> {
    let octets = plage(memoire, adresse, 4)?;
    Some(u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]))
}

/// Écrit `octets` à l'adresse `adresse` de la mémoire du programme, s'ils y
/// tiennent.
fn ecrire(memoire: &mut [u8], adresse: u32, octets: &[u8]) -> Result<(), u32> {
    plage_mut(memoire, adresse, octets.len() as u32).ok_or(EFAULT)?.copy_from_slice(octets);
    Ok(())
}

/// Le i-ième morceau décrit à `morceaux` (chacun : adresse sur 32 bits,
/// puis longueur sur 32 bits) : son adresse et sa longueur, s'il est tout
/// entier dans la mémoire.
fn morceau(memoire: &[u8], morceaux: u32, i: u32) -> Option<(u32, u32)> {
    let lire = |decalage: u32| lire_u32(memoire, morceaux.checked_add(i.checked_mul(8)?)?.checked_add(decalage)?);
    let (adresse, longueur) = (lire(0)?, lire(4)?);
    plage(memoire, adresse, longueur)?;
    Some((adresse, longueur))
}

/// Les `nombre` morceaux décrits à `morceaux`, copiés d'abord (comme
/// l'`import_iovec` de Linux : ce que la réception écrira ne peut plus les
/// changer), chacun dans la mémoire : EINVAL au-delà de MORCEAUX_MAX,
/// EFAULT, ENOMEM.
fn lire_morceaux(m: &[u8], morceaux: u32, nombre: u32) -> Result<Vec<(u32, u32)>, u32> {
    if nombre > MORCEAUX_MAX {
        return Err(EINVAL);
    }
    let mut v = faillible::avec_capacite(nombre as usize).map_err(|_| ENOMEM)?;
    for i in 0..nombre {
        v.ajouter_dans_la_place(morceau(m, morceaux, i).ok_or(EFAULT)?);
    }
    Ok(v)
}

/// Copie `octets` dans les morceaux `v` (déjà vérifiés), à partir de
/// l'octet `decalage` de leur suite.
fn vers_morceaux(m: &mut [u8], v: &[(u32, u32)], mut decalage: usize, octets: &[u8]) {
    let mut fait = 0;
    for &(adresse, longueur) in v {
        let longueur = longueur as usize;
        if decalage >= longueur {
            decalage -= longueur;
            continue;
        }
        let n = (longueur - decalage).min(octets.len() - fait);
        if let Some(d) = plage_mut(m, adresse + decalage as u32, n as u32) {
            d.copy_from_slice(&octets[fait..fait + n]);
        }
        fait += n;
        decalage = 0;
        if fait == octets.len() {
            return;
        }
    }
}

/// Remplit `destination` des octets des morceaux `v` (déjà vérifiés), à
/// partir de l'octet `decalage` de leur suite.
fn des_morceaux(m: &[u8], v: &[(u32, u32)], mut decalage: usize, destination: &mut [u8]) {
    let mut fait = 0;
    for &(adresse, longueur) in v {
        let longueur = longueur as usize;
        if decalage >= longueur {
            decalage -= longueur;
            continue;
        }
        let n = (longueur - decalage).min(destination.len() - fait);
        if let Some(o) = plage(m, adresse + decalage as u32, n as u32) {
            destination[fait..fait + n].copy_from_slice(o);
        }
        fait += n;
        decalage = 0;
        if fait == destination.len() {
            return;
        }
    }
}

/// Reçoit d'une socket TCP dans les morceaux `v`, avec les drapeaux de
/// `recvmsg` (MSG_PEEK, MSG_WAITALL), sans attendre si son fichier est
/// NONBLOCK (EAGAIN) : le nombre d'octets reçus, compté en carburant. Au
/// plus TRANSFERT_MAX octets, sauf MSG_WAITALL (voir `sock_recv`).
fn recevoir(o: &FichierTenu, v: &[(u32, u32)], m: &mut [u8], drapeaux: u64, cout: &mut u64) -> Result<u32, u32> {
    const MSG_WAITALL: u64 = 0x100;
    let place: usize = v.iter().map(|&(_, l)| l as usize).sum();
    let longueur = if drapeaux & MSG_WAITALL != 0 { place } else { place.min(TRANSFERT_MAX as usize) };
    let n = tcp::recevoir_programme(o.socket(), longueur, drapeaux, o.drapeaux & O_NONBLOCK != 0, |decalage, octets| {
        vers_morceaux(m, v, decalage, octets);
        Ok(octets.len())
    })
    .map_err(errno_reseau)?;
    *cout += n as u64 + v.len() as u64;
    Ok(n as u32)
}

/// Envoie les morceaux `v` par une socket TCP, au plus TRANSFERT_MAX octets,
/// sans attendre la place si son fichier est NONBLOCK (MSG_DONTWAIT :
/// EAGAIN si rien n'est parti) : le nombre d'octets envoyés, compté en
/// carburant.
fn envoyer(o: &FichierTenu, v: &[(u32, u32)], m: &[u8], cout: &mut u64) -> Result<u32, u32> {
    const MSG_DONTWAIT: u64 = 0x40;
    let place: usize = v.iter().map(|&(_, l)| l as usize).sum();
    let longueur = place.min(TRANSFERT_MAX as usize);
    let drapeaux = if o.drapeaux & O_NONBLOCK != 0 { MSG_DONTWAIT } else { 0 };
    let n = tcp::envoyer(o.socket(), longueur, drapeaux, |decalage, d| {
        des_morceaux(m, v, decalage, d);
        Ok(())
    })
    .map_err(errno_reseau)?;
    *cout += n as u64 + v.len() as u64;
    Ok(n as u32)
}

/// Le chemin à `adresse` dans la mémoire du programme (WASI le donne avec
/// sa longueur, sans zéro final).
fn chemin(memoire: &[u8], adresse: u32, longueur: u32) -> Result<Vec<u8>, u32> {
    let octets = plage(memoire, adresse, longueur).ok_or(EFAULT)?;
    faillible::copie(octets).map_err(|_| ENOMEM)
}

// Les types de fichiers de WASI (filetype).
const TYPE_INCONNU: u8 = 0;
const TYPE_CARACTERE: u8 = 2;
const TYPE_DOSSIER: u8 = 3;
const TYPE_FICHIER: u8 = 4;
const TYPE_SOCKET_STREAM: u8 = 6;
const TYPE_LIEN: u8 = 7;

/// Le type WASI d'un mode. Une socket : SOCKET_STREAM, la seule sorte de
/// socket d'un programme WebAssembly (TCP), et ce que rend wasmtime pour
/// un fichier de socket (AF_UNIX) dans un dossier.
fn type_wasi(mode: u32) -> u8 {
    match mode & S_IFMT {
        S_IFDIR => TYPE_DOSSIER,
        S_IFLNK => TYPE_LIEN,
        S_IFCHR => TYPE_CARACTERE,
        fichiers::S_IFREG => TYPE_FICHIER,
        fichiers::S_IFSOCK => TYPE_SOCKET_STREAM,
        _ => TYPE_INCONNU,
    }
}

/// Une date en nanosecondes depuis 1970 (les « timestamp » de WASI).
fn nanosecondes(t: Temps) -> u64 {
    (t.secondes.max(0) as u64).saturating_mul(1_000_000_000).saturating_add(t.nanosecondes as u64)
}

/// L'inode du tmpfs d'un fichier ordinaire : sa sorte (Sorte::Fichier) ne
/// vient que du tmpfs.
fn inode(o: Objet) -> Numero {
    o.tmpfs().expect("un fichier ordinaire hors du tmpfs")
}

/// Le « filestat » de WASI (64 octets), d'après les attributs d'un objet
/// et le périphérique de son système de fichiers.
fn filestat(a: &Attributs, dev: (u32, u32)) -> [u8; 64] {
    let mut s = [0u8; 64];
    // dev : celui de son système de fichiers, codé comme st_dev.
    s[0..8].copy_from_slice(&appels_fichiers::encoder_peripherique(dev).to_le_bytes());
    s[8..16].copy_from_slice(&a.numero.to_le_bytes());
    s[16] = type_wasi(a.mode);
    s[24..32].copy_from_slice(&(a.nlink as u64).to_le_bytes());
    s[32..40].copy_from_slice(&a.taille.to_le_bytes());
    s[40..48].copy_from_slice(&nanosecondes(a.atime).to_le_bytes());
    s[48..56].copy_from_slice(&nanosecondes(a.mtime).to_le_bytes());
    s[56..64].copy_from_slice(&nanosecondes(a.ctime).to_le_bytes());
    s
}

/// clock_time_get(horloge, précision, temps) : les horloges de WASI
/// (REALTIME, MONOTONIC, PROCESS_CPUTIME_ID, THREAD_CPUTIME_ID), en
/// nanosecondes ; la précision demandée ne change rien.
fn clock_time_get(horloge: u32, adresse: u32, m: &mut [u8]) -> u32 {
    let t = match horloge {
        0 => temps::maintenant(),
        1 => temps::monotone(),
        2 | 3 => temps::temps_du_programme(),
        _ => return EINVAL,
    };
    match ecrire(m, adresse, &nanosecondes(t).to_le_bytes()) {
        Ok(()) => SUCCES,
        Err(e) => e,
    }
}

/// La taille d'un abonnement de poll_oneoff (`subscription`), et d'un
/// événement (`event`), dans la mémoire du programme.
const ABONNEMENT: u32 = 48;
const EVENEMENT: u32 = 32;
/// Les genres d'abonnements (`eventtype`).
const HORLOGE: u8 = 0;
const LECTURE: u8 = 1;
const ECRITURE: u8 = 2;
/// `subclockflags` : l'échéance est absolue.
const ABSOLUE: u16 = 1;

/// L'abonnement `i` (48 octets), copié de la mémoire (déjà vérifiée).
fn abonnement(m: &[u8], entree: u32, i: u32) -> [u8; 48] {
    let mut a = [0u8; 48];
    if let Some(o) = plage(m, entree + i * ABONNEMENT, ABONNEMENT) {
        a.copy_from_slice(o);
    }
    a
}

/// L'échéance d'un abonnement d'horloge, en temps monotone : `maintenant`
/// (monotone) et `reel` (la date) pris au début de l'appel. Une échéance
/// absolue de la date devient monotone par leur écart (la date ne se règle
/// pas encore). None : une horloge sans échéance chez nous (les temps de
/// calcul).
fn echeance(a: &[u8; 48], maintenant: u64, reel: u64) -> Option<u64> {
    let horloge = u32::from_le_bytes([a[16], a[17], a[18], a[19]]);
    let delai = u64::from_le_bytes([a[24], a[25], a[26], a[27], a[28], a[29], a[30], a[31]]);
    let absolue = u16::from_le_bytes([a[40], a[41]]) & ABSOLUE != 0;
    match (horloge, absolue) {
        (0, true) => Some(maintenant.saturating_add(delai.saturating_sub(reel))),
        (1, true) => Some(delai),
        (0 | 1, false) => Some(maintenant.saturating_add(delai)),
        _ => None,
    }
}

impl Wasi {
    /// poll_oneoff(abonnements, événements, nombre, publiés) : `nombre`
    /// abonnements (48 octets chacun) ; les événements arrivés sont écrits à
    /// `evenements` (32 octets chacun), leur nombre à `publies`. Comme
    /// wasmtime : aucun abonnement, EINVAL ; une horloge inconnue (seules
    /// celles de la date et du temps monotone ont une échéance), EINVAL.
    /// Tout est vérifié avant d'attendre. Puis l'attente de `poll` (le
    /// `do_poll` de sondage.rs, sa table et ses entrées) : jusqu'à ce qu'un
    /// abonnement soit prêt, ou la première échéance. Un fichier, un
    /// dossier, la console sont toujours prêts ; une socket (6h), quand
    /// `poll` le dirait (`evenement`). Tout ce qui est prêt est publié : les
    /// descripteurs, et les horloges échues (une échéance nulle ou passée
    /// l'est même à côté d'un descripteur). Deux écarts voulus avec le
    /// wasmtime d'aujourd'hui (p1.rs), qui fait échouer tout l'appel pour un
    /// mauvais descripteur (EBADF) et annonce 1 octet à lire : ce que dit la
    /// spécification (l'`error` d'un événement), et ce que faisait l'ancien
    /// wasi-common de wasmtime ; un descripteur qui n'est pas à lui, ou un
    /// dossier : l'événement porte EBADF ; lire un fichier : combien
    /// d'octets restent (`nbytes`) ; une socket : combien sont arrivés.
    fn poll_oneoff(&self, entree: u32, sortie: u32, nombre: u32, publies: u32, m: &mut [u8], cout: &mut u64) -> u32 {
        if nombre == 0 {
            return EINVAL;
        }
        if nombre > MORCEAUX_MAX {
            return EINVAL;
        }
        let (Some(_), Some(_), Some(_)) = (plage(m, entree, nombre * ABONNEMENT), plage(m, sortie, nombre * EVENEMENT), plage(m, publies, 4))
        else {
            return EFAULT;
        };
        *cout += nombre as u64;
        // Les horloges, et la première échéance.
        let (maintenant, reel) = (temps::ns_monotone(), nanosecondes(temps::maintenant()));
        let mut premiere: Option<u64> = None;
        for i in 0..nombre {
            let a = abonnement(m, entree, i);
            match a[8] {
                HORLOGE => {
                    let Some(e) = echeance(&a, maintenant, reel) else { return EINVAL };
                    premiere = Some(premiere.map_or(e, |p| p.min(e)));
                }
                LECTURE | ECRITURE => {}
                _ => return EINVAL,
            }
        }
        // Attendre que l'un soit prêt : chaque tour les regarde tous (le
        // premier inscrit la tâche dans la file de chaque socket).
        let delai = premiere.map_or(Delai::Infini, Delai::Jusqua);
        let attente = sondage::attendre_prets(delai, |table| {
            (0..nombre).filter(|&i| self.evenement(&abonnement(m, entree, i), maintenant, reel, table).is_some()).count()
        });
        match attente {
            Ok(_) => {}
            // La place des entrées de sondage a manqué.
            Err(-12) => return ENOMEM,
            // La tâche est arrêtée (ERESTARTNOHAND : elle n'a pas de signal
            // à recevoir, seulement sa fin).
            Err(_) => return EINTR,
        }
        // Les événements : ce qui est prêt maintenant.
        let mut n = 0u32;
        for i in 0..nombre {
            let a = abonnement(m, entree, i);
            if let Some(e) = self.evenement(&a, maintenant, reel, &mut Table::new(None)) {
                let _ = ecrire(m, sortie + n * EVENEMENT, &e);
                n += 1;
            }
        }
        match ecrire(m, publies, &n.to_le_bytes()) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// L'événement de l'abonnement `a` s'il est arrivé (son `event`, 32
    /// octets), None sinon, en inscrivant par `table` la tâche dans la file
    /// d'une socket. Une horloge : son échéance passée. Un descripteur :
    /// celui d'une socket, quand son sondage le dit (lire : POLLIN, avec ce
    /// qui est arrivé, FIONREAD ; écrire : POLLOUT ; puis POLLHUP, prêt avec
    /// FD_READWRITE_HANGUP, comme l'ancien wasi-common ; POLLERR seul :
    /// l'erreur EIO, que lire ou écrire précisera) ; un autre, tout de
    /// suite.
    fn evenement(&self, a: &[u8; 48], maintenant: u64, reel: u64, table: &mut Table) -> Option<[u8; 32]> {
        /// `eventrwflags` : l'autre bout a raccroché.
        const RACCROCHE: u16 = 1;
        let mut e = [0u8; 32];
        e[..8].copy_from_slice(&a[..8]);
        e[10] = a[8];
        if a[8] == HORLOGE {
            return echeance(a, maintenant, reel).filter(|&x| x <= temps::ns_monotone()).map(|_| e);
        }
        let fd = u32::from_le_bytes([a[16], a[17], a[18], a[19]]);
        let (erreur, octets, drapeaux) = match self.ouvert(fd) {
            Ok((_, Sorte::Socket, ..)) => {
                let o = self.tenir(fd).ok()?;
                let voulu = if a[8] == LECTURE { POLLIN } else { POLLOUT };
                table.changer_cle(voulu | POLLERR | POLLHUP);
                let masque = sondage::sonder(&o, table);
                let raccroche = if masque & POLLHUP != 0 { RACCROCHE } else { 0 };
                if masque & voulu != 0 {
                    let arrives = if a[8] == LECTURE { tcp::files(o.socket()).map_or(0, |f| f.0) } else { 0 };
                    (0u16, arrives as u64, raccroche)
                } else if raccroche != 0 {
                    (0, 0, raccroche)
                } else if masque & POLLERR != 0 {
                    (EIO as u16, 0, 0)
                } else {
                    return None;
                }
            }
            Ok((_, Sorte::Fichier, objet, _, _, _, position)) if a[8] == LECTURE => {
                let taille = objet.tmpfs().map_or(0, |n| vfs::avec(|fs, _| fs.attributs(n).taille));
                (0, taille.saturating_sub(position), 0)
            }
            Ok((_, Sorte::Dossier | Sorte::Chemin, ..)) | Err(_) => (EBADF as u16, 0, 0),
            Ok(_) => (0, 0, 0),
        };
        e[8..10].copy_from_slice(&erreur.to_le_bytes());
        e[16..24].copy_from_slice(&octets.to_le_bytes());
        e[24..26].copy_from_slice(&drapeaux.to_le_bytes());
        Some(e)
    }

    /// Le fichier du descripteur `fd`, tenu (comme `appels_fichiers::tenir`
    /// pour un programme Linux) : ce qu'il faut pour une socket, son objet
    /// et ses drapeaux.
    fn tenir(&self, fd: u32) -> Result<FichierTenu, u32> {
        let d = self.descripteurs.get(fd as u64).ok_or(EBADF)?;
        Ok(vfs::avec_systeme(|s, _| appels_fichiers::tenir_ouvert(s, d.fichier)))
    }

    /// La socket TCP du descripteur `fd` : EBADF (pas de descripteur),
    /// ENOTSOCK (un autre fichier). (Un programme WebAssembly n'a que des
    /// sockets TCP : ses écoutes, et ce qu'il y accepte.)
    fn socket(&self, fd: u32) -> Result<FichierTenu, u32> {
        let o = self.tenir(fd)?;
        if o.sorte != Sorte::Socket || o.socket().protocole != Protocole::Tcp {
            return Err(ENOTSOCK);
        }
        Ok(o)
    }

    /// Le fichier ouvert du descripteur `fd`, et ce qu'il faut en savoir. Sans
    /// le tenir (`appels_fichiers::FichierTenu`) : les descripteurs d'un
    /// programme WebAssembly ne sont qu'à lui, une seule tâche (WASI preview
    /// 1 n'a pas de fils), personne ne peut les fermer pendant un appel.
    fn ouvert(&self, fd: u32) -> Result<(Descripteur, Sorte, Objet, bool, bool, u32, u64), u32> {
        let d = self.descripteurs.get(fd as u64).ok_or(EBADF)?;
        Ok(vfs::avec_systeme(|s, _| {
            let f = s.ouverts.fichier(d.fichier);
            (d, f.sorte, f.objet(), f.lecture, f.ecriture, f.drapeaux, f.position)
        }))
    }

    /// fd_write et fd_read : `nombre` morceaux décrits à `morceaux`, au plus
    /// TRANSFERT_MAX octets en tout ; le total est écrit à `total`. Tout est
    /// vérifié d'abord, comme Linux (import_iovec) : une erreur ne doit rien
    /// avoir transféré. Sur un fichier, à sa position (à la fin avec
    /// O_APPEND), qui avance d'autant.
    #[allow(clippy::too_many_arguments)]
    fn fd_rw(&mut self, fd: u32, morceaux: u32, nombre: u32, total: u32, m: &mut [u8], cout: &mut u64, ecriture: bool) -> u32 {
        let (d, sorte, objet, lecture, ecrit, drapeaux, position) = match self.ouvert(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        // Un fichier ordinaire est un inode du tmpfs (sa sorte vient de lui).
        let n = || inode(objet);
        if (ecriture && !ecrit) || (!ecriture && !lecture) {
            return EBADF;
        }
        if nombre > MORCEAUX_MAX {
            return EINVAL;
        }
        if (0..nombre).any(|i| morceau(m, morceaux, i).is_none()) || plage(m, total, 4).is_none() {
            return EFAULT;
        }
        if sorte == Sorte::Socket {
            // Une socket (6h) : lire et écrire, c'est recevoir et envoyer
            // sans drapeaux, comme read et write sur une socket Linux.
            let r = self.socket(fd).and_then(|o| {
                let v = lire_morceaux(m, morceaux, nombre)?;
                if ecriture { envoyer(&o, &v, m, cout) } else { recevoir(&o, &v, m, 0, cout) }
            });
            if let Ok(n) = r
                && n > 0
            {
                let masque = if ecriture { crate::surveillance::IN_MODIFY } else { crate::surveillance::IN_ACCESS };
                if crate::surveillance::actif() {
                    vfs::avec_systeme(|s, _| crate::surveillance::du_fichier(&s.fs, s.ouverts.fichier(d.fichier), masque));
                }
            }
            return match r.and_then(|n| ecrire(m, total, &n.to_le_bytes())) {
                Ok(()) => SUCCES,
                Err(e) => e,
            };
        }
        // Le verrou d'écriture de l'inode, comme pour un programme Linux
        // (appels_fichiers.rs) : la fin lue et l'écriture ne se séparent pas.
        let _ecriture = (ecriture && sorte == Sorte::Fichier).then(|| crate::appels_fichiers::verrou_d_ecriture(n()));
        // Les bits setuid et setgid tombent à une écriture qui écrit quelque
        // chose, comme pour un programme Linux (`file_remove_privs`).
        if ecriture && sorte == Sorte::Fichier && (0..nombre).any(|i| morceau(m, morceaux, i).is_some_and(|(_, l)| l > 0)) {
            let qui = self.identite;
            vfs::avec_systeme(|s, _| {
                if s.fs.retirer_les_privileges(qui, n(), temps::maintenant()) {
                    crate::surveillance::changement(&s.fs, s.ouverts.fichier(d.fichier), crate::surveillance::IN_ATTRIB);
                }
            });
        }
        let maintenant = temps::maintenant();
        let mut ici = if ecriture && drapeaux & O_APPEND != 0 && sorte == Sorte::Fichier {
            vfs::avec(|fs, _| fs.attributs(n()).taille)
        } else {
            position
        };
        let mut fait: u32 = 0;
        for i in 0..nombre {
            let (adresse, longueur) = morceau(m, morceaux, i).expect("verifie plus haut");
            let n_octets = longueur.min(TRANSFERT_MAX - fait);
            let octets = plage_mut(m, adresse, n_octets).expect("verifie plus haut");
            let r = match (sorte, ecriture) {
                (Sorte::Console, true) => {
                    console::ecrire_octets(octets);
                    Ok(octets.len())
                }
                (Sorte::Null | Sorte::Zero, true) => Ok(octets.len()),
                // Écrire dans /dev/random ou /dev/urandom : mêlé au
                // réservoir, sans crédit (`write_pool_user`), comme pour un
                // programme Linux.
                (Sorte::Aleatoire { .. }, true) => {
                    crate::aleatoire::melanger(octets);
                    Ok(octets.len())
                }
                (Sorte::Plein, true) => Err(ENOSPC),
                (Sorte::Fichier, true) => vfs::avec(|fs, cadres| fs.ecrire(n(), ici, octets, maintenant, cadres)).map_err(errno),
                (Sorte::Fichier, false) => Ok(vfs::avec(|fs, cadres| fs.lire(n(), ici, octets, cadres))),
                (Sorte::Null | Sorte::Console, false) => Ok(0),
                (Sorte::Zero | Sorte::Plein, false) => {
                    octets.fill(0);
                    Ok(octets.len())
                }
                // Lire /dev/random attend que le générateur soit prêt
                // (`random_read_iter`) : un programme WebAssembly n'a pas de
                // signal, l'attente ne finit qu'à « prêt » (ou à l'arrêt de
                // sa tâche : EINTR). /dev/urandom n'attend pas, mais lance
                // la gigue (`urandom_read_iter`). Comme pour un programme
                // Linux (appels_fichiers.rs).
                (Sorte::Aleatoire { random }, false) => {
                    let pret = if random {
                        crate::aleatoire::attendre_pret().map_err(|_| EINTR)
                    } else {
                        crate::aleatoire::essayer_la_gigue();
                        Ok(())
                    };
                    pret.map(|()| {
                        crate::aleatoire::obtenir(octets);
                        octets.len()
                    })
                }
                (Sorte::Dossier, _) => Err(EISDIR),
                // Un programme WebAssembly n'a ni eventfd, ni epoll, ni
                // tube : ce descripteur ne peut pas être à lui (une socket
                // est passée plus haut).
                (Sorte::Chemin | Sorte::EventFd | Sorte::Epoll | Sorte::Tube | Sorte::Socket | Sorte::Inotify, _) => Err(EBADF),
                // Un fichier de /proc ou de /sys : son contenu fabriqué à la
                // lecture, comme pour un programme Linux (seule une mémoire
                // qui manque peut échouer) ; il ne s'écrit pas.
                (Sorte::Noyau { .. }, false) => crate::procfs::lire(d.fichier, ici, octets.len() as u64)
                    .map(|v| {
                        octets[..v.len()].copy_from_slice(&v);
                        v.len()
                    })
                    .map_err(|_| ENOMEM),
                (Sorte::Noyau { .. }, true) => Err(EBADF),
            };
            match r {
                Ok(k) => {
                    fait += k as u32;
                    ici += k as u64;
                    if (k as u32) < n_octets || fait == TRANSFERT_MAX {
                        break;
                    }
                }
                Err(e) if fait == 0 => return e,
                Err(_) => break,
            }
        }
        if sorte == Sorte::Fichier || matches!(sorte, Sorte::Noyau { .. }) {
            vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).position = ici);
            if !ecriture && sorte == Sorte::Fichier {
                vfs::avec(|fs, _| fs.acceder(n(), maintenant));
            }
        }
        // Ce qu'en voit inotify, comme d'un read ou d'un write d'un
        // programme Linux (surveillance.rs).
        if fait > 0 && crate::surveillance::actif() {
            let masque = if ecriture { crate::surveillance::IN_MODIFY } else { crate::surveillance::IN_ACCESS };
            vfs::avec_systeme(|s, _| crate::surveillance::du_fichier(&s.fs, s.ouverts.fichier(d.fichier), masque));
        }
        // Le travail : une unité de carburant par octet, et par morceau lu.
        *cout += fait as u64 + nombre as u64;
        match ecrire(m, total, &fait.to_le_bytes()) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_seek(fd, décalage, d'où, nouvelle) et fd_tell : SET (0), CUR (1),
    /// END (2) ; une position négative : EINVAL ; la console, une socket :
    /// ESPIPE.
    fn fd_seek(&mut self, fd: u32, decalage: i64, depuis: u32, adresse: u32, m: &mut [u8]) -> u32 {
        let (d, sorte, objet, _, _, _, position) = match self.ouvert(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let base = match (sorte, depuis) {
            (Sorte::Console | Sorte::Socket, _) => return ESPIPE,
            (Sorte::Chemin, _) => return EBADF,
            (_, 0) => 0,
            (_, 1) => position as i64,
            (Sorte::Fichier, 2) => vfs::avec(|fs, _| fs.attributs(inode(objet)).taille) as i64,
            _ => return EINVAL,
        };
        let Some(nouvelle) = base.checked_add(decalage).filter(|&p| p >= 0) else { return EINVAL };
        if let Err(e) = ecrire(m, adresse, &(nouvelle as u64).to_le_bytes()) {
            return e;
        }
        vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).position = nouvelle as u64);
        SUCCES
    }

    /// sock_accept(écoute, fdflags, fichier) : une connexion de l'écoute,
    /// dans un descripteur neuf (le plus petit libre), NON BLOQUANT si
    /// `fdflags` le demande, son numéro écrit à `fichier`. Comme l'ancien
    /// wasi-common de wasmtime : d'autres drapeaux que NONBLOCK, EINVAL
    /// (lui acceptait d'abord et perdait la connexion : nous vérifions
    /// avant) ; une écoute non bloquante sans client : EAGAIN, sinon on
    /// attend. Une socket qui n'écoute pas : EINVAL (`inet_accept`).
    /// L'adresse du client n'est pas rendue : preview 1 n'a pas d'adresses.
    /// Tout ce qui peut échouer passe avant de prendre la connexion
    /// (l'adresse du résultat, un numéro libre, le fichier de la socket),
    /// comme le `do_accept` de Linux et notre `accept4` : la connexion reste
    /// alors dans la file ; après, seule la place de la table des fichiers
    /// peut manquer, et la connexion est fermée, pas perdue.
    fn sock_accept(&mut self, fd: u32, fdflags: u32, sortie: u32, m: &mut [u8]) -> u32 {
        let o = match self.socket(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        if fdflags & !(FDFLAGS_NONBLOCK as u32) != 0 {
            return EINVAL;
        }
        if plage(m, sortie, 4).is_none() {
            return EFAULT;
        }
        let numero = match self.descripteurs.reserver(0) {
            Ok(n) => n,
            Err(Refus::PlusDeMemoire) => return ENOMEM,
            Err(_) => return EMFILE,
        };
        let mut f = match appels_reseau::fichier_sans_socket(self.identite, fdflags & FDFLAGS_NONBLOCK as u32 != 0) {
            Ok(f) => f,
            Err(e) => {
                self.descripteurs.liberer(numero);
                return errno_reseau(e);
            }
        };
        let enfant = match tcp::accepter(o.socket(), o.drapeaux & O_NONBLOCK != 0) {
            Ok((enfant, _, _)) => enfant,
            Err(e) => {
                appels_fichiers::rendre_fichier(f);
                self.descripteurs.liberer(numero);
                return errno_reseau(e);
            }
        };
        appels_reseau::attacher(&mut f, enfant.clone());
        match vfs::avec_systeme(|s, _| s.ouverts.ajouter(f)) {
            Ok(fichier) => {
                self.descripteurs.installer(numero, Descripteur { fichier, fermer_a_l_exec: false });
                let _ = ecrire(m, sortie, &(numero as u32).to_le_bytes());
                SUCCES
            }
            Err(f) => {
                appels_fichiers::rendre_fichier(f);
                self.descripteurs.liberer(numero);
                socket::fermer(&enfant);
                ENOMEM
            }
        }
    }

    /// sock_recv(socket, morceaux, nombre, riflags, reçus, roflags) :
    /// recevoir dans les morceaux, comme `recvmsg` : RECV_PEEK (MSG_PEEK)
    /// laisse les octets, RECV_WAITALL (MSG_WAITALL) attend qu'ils soient
    /// tous là (moins seulement à la fin du flux, ou sur une erreur, comme
    /// Linux) ; un autre drapeau : ENOTSUP (wasi-common). Le nombre d'octets
    /// à `recus`, et `roflags` à 0 (RECV_DATA_TRUNCATED ne concerne que les
    /// datagrammes). Au plus 1024 octets, comme fd_read, sauf RECV_WAITALL :
    /// le programme a demandé de tout recevoir, et le recevoir par morceaux
    /// le lui refuserait ; ce travail reste borné par la place de ses
    /// morceaux (qui peuvent se recouvrir : au plus 1024 fois sa mémoire) et
    /// compté en carburant, et l'attente dort entre les arrivées.
    #[allow(clippy::too_many_arguments)]
    fn sock_recv(&mut self, fd: u32, morceaux: u32, nombre: u32, riflags: u32, recus: u32, roflags: u32, m: &mut [u8],
                 cout: &mut u64) -> u32 {
        const RECV_PEEK: u32 = 1;
        const RECV_WAITALL: u32 = 2;
        const MSG_PEEK: u64 = 2;
        const MSG_WAITALL: u64 = 0x100;
        let r = self.socket(fd).and_then(|o| {
            if riflags & !(RECV_PEEK | RECV_WAITALL) != 0 {
                return Err(ENOTSUP);
            }
            let v = lire_morceaux(m, morceaux, nombre)?;
            if plage(m, recus, 4).is_none() || plage(m, roflags, 2).is_none() {
                return Err(EFAULT);
            }
            let drapeaux = if riflags & RECV_PEEK != 0 { MSG_PEEK } else { 0 } | if riflags & RECV_WAITALL != 0 { MSG_WAITALL } else { 0 };
            recevoir(&o, &v, m, drapeaux, cout)
        });
        match r.and_then(|n| ecrire(m, recus, &n.to_le_bytes())).and_then(|()| ecrire(m, roflags, &0u16.to_le_bytes())) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// sock_send(socket, morceaux, nombre, siflags, envoyés) : envoyer les
    /// morceaux, au plus 1024 octets (comme fd_write : le nombre envoyé le
    /// dit, le programme recommence avec la suite). `siflags` n'a aucun
    /// drapeau défini : autre chose que 0, ENOTSUP (wasi-common). Une
    /// connexion fermée : EPIPE, sans signal (un programme WebAssembly n'en
    /// a pas ; MSG_NOSIGNAL).
    #[allow(clippy::too_many_arguments)]
    fn sock_send(&mut self, fd: u32, morceaux: u32, nombre: u32, siflags: u32, envoyes: u32, m: &mut [u8], cout: &mut u64) -> u32 {
        let r = self.socket(fd).and_then(|o| {
            if siflags != 0 {
                return Err(ENOTSUP);
            }
            let v = lire_morceaux(m, morceaux, nombre)?;
            if plage(m, envoyes, 4).is_none() {
                return Err(EFAULT);
            }
            envoyer(&o, &v, m, cout)
        });
        match r.and_then(|n| ecrire(m, envoyes, &n.to_le_bytes())) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// sock_shutdown(socket, sdflags) : arrêter la lecture (RD, 1),
    /// l'écriture (WR, 2 : FIN), ou les deux, comme `shutdown` ; aucun ou un
    /// autre drapeau : EINVAL (wasi-common) ; pas connectée : ENOTCONN.
    fn sock_shutdown(&mut self, fd: u32, sdflags: u32) -> u32 {
        const RD: u32 = 1;
        const WR: u32 = 2;
        let o = match self.socket(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        if sdflags == 0 || sdflags & !(RD | WR) != 0 {
            return EINVAL;
        }
        let arret = if sdflags & RD != 0 { socket::ARRET_LECTURE } else { 0 } | if sdflags & WR != 0 { socket::ARRET_ECRITURE } else { 0 };
        match tcp::arreter(o.socket(), arret) {
            Ok(()) => SUCCES,
            Err(e) => errno_reseau(e),
        }
    }

    /// fd_close.
    fn fd_close(&mut self, fd: u32) -> u32 {
        match self.descripteurs.retirer(fd as u64) {
            Some(d) => {
                vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
                self.preouverts.retain(|p| p.fd != fd as u64);
                SUCCES
            }
            None => EBADF,
        }
    }

    /// fd_prestat_get : les descripteurs des dossiers pré-ouverts, tant
    /// qu'ils n'ont pas été fermés ; les autres n'en sont pas (EBADF :
    /// wasi-libc parcourt 3, 4... et s'arrête au premier EBADF).
    fn fd_prestat_get(&self, fd: u32, adresse: u32, m: &mut [u8]) -> u32 {
        let Some(p) = self.preouvert(fd) else { return EBADF };
        // Le « prestat » : une étiquette (0 : un dossier), puis la longueur
        // de son nom sur 32 bits.
        let longueur = p.nom.len() as u32;
        let mut p = [0u8; 8];
        p[4..].copy_from_slice(&longueur.to_le_bytes());
        match ecrire(m, adresse, &p) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_prestat_dir_name : le nom du dossier pré-ouvert. Une place trop
    /// petite pour le nom : ENAMETOOLONG, comme wasmtime.
    fn fd_prestat_dir_name(&self, fd: u32, adresse: u32, longueur: u32, m: &mut [u8]) -> u32 {
        let Some(p) = self.preouvert(fd) else { return EBADF };
        if (longueur as usize) < p.nom.len() {
            return ENAMETOOLONG;
        }
        match ecrire(m, adresse, &p.nom) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// path_open(dossier, drapeaux, chemin, longueur, oflags, droits, _,
    /// fdflags, fichier) : ouvre `chemin`, sous le dossier `dossier`
    /// (résolution « sous » : il ne doit jamais en sortir). drapeaux :
    /// suivre un lien final (LOOKUPFLAGS_SYMLINK_FOLLOW). oflags : CREAT,
    /// DIRECTORY, EXCL, TRUNC. droits : lecture (FD_READ, FD_READDIR) et
    /// écriture (FD_WRITE) ; aucun des deux : lecture. fdflags : APPEND.
    /// Les vérifications sont celles d'open (Tmpfs::ouvrir).
    #[allow(clippy::too_many_arguments)]
    fn path_open(&mut self, dossier: u32, suivre: u32, adresse: u32, longueur: u32, oflags: u32, droits: u64,
                 fdflags: u32, sortie: u32, m: &mut [u8]) -> u32 {
        const LIRE: u64 = 1 << 1;
        const LIRE_DOSSIER: u64 = 1 << 14;
        const ECRIRE: u64 = 1 << 6;
        let (_, sorte_dossier, base, ..) = match self.ouvert(dossier) {
            Ok(o) => o,
            Err(e) => return e,
        };
        if sorte_dossier != Sorte::Dossier {
            return ENOTDIR;
        }
        if plage(m, sortie, 4).is_none() {
            return EFAULT;
        }
        let chemin = match chemin(m, adresse, longueur) {
            Ok(c) => c,
            Err(e) => return e,
        };
        // Réservé d'abord, comme pour un programme Linux : EMFILE avant de
        // regarder le chemin.
        let fd = match self.descripteurs.reserver(0) {
            Ok(fd) => fd,
            Err(Refus::PlusDeMemoire) => return ENOMEM,
            Err(_) => return EMFILE,
        };
        let ecriture = droits & ECRIRE != 0;
        let o = Ouverture {
            lecture: droits & (LIRE | LIRE_DOSSIER) != 0 || !ecriture,
            ecriture,
            creer: oflags & 1 != 0,
            mode: 0o644,
            exclusif: oflags & 4 != 0,
            tronquer: oflags & 8 != 0,
            dossier: oflags & 2 != 0,
            chemin_seul: false,
        };
        let qui = self.identite;
        let maintenant = temps::maintenant();
        let drapeaux = if fdflags & FDFLAGS_APPEND as u32 != 0 { O_APPEND } else { 0 };
        let ouvert = vfs::avec_systeme(|s, cadres| {
            let racine = s.racine();
            let depart = Depart { racine, dossier: base, qui, sous: true };
            let fin = s.resoudre(0, &depart, &chemin, suivre_pour(&o, suivre & 1 == 0)).map_err(errno)?;
            let complet = s.avec_vue(0, |vue| vue.chemin_de(&fin)).unwrap_or_default();
            // Le lieu du fichier, pour inotify : préparé d'abord, rien ne
            // doit échouer une fois le fichier créé ou ouvert.
            let lieu = appels_fichiers::preparer_lieu(s, 0, &fin).map_err(|_| ENOMEM)?;
            // Un programme WebAssembly voit les systèmes montés comme un
            // programme Linux.
            let fin = match en_tmpfs(fin) {
                Ok(fin) => fin,
                Err(fin) => {
                    // O_CREAT et une barre finale : EISDIR, avant de
                    // chercher le nom (`open_last_lookups`).
                    if o.creer && fin.barre {
                        return Err(errno(Erreur::EISDIR));
                    }
                    let Some(objet) = fin.objet else {
                        let refus = s.avec_vue(0, |vue| vue.refus(qui, Modification::Creer(&fin, Creation::Ouvrir)));
                        return Err(errno(if o.creer { refus.err().unwrap_or(Erreur::ENOENT) } else { Erreur::ENOENT }));
                    };
                    let f = s.avec_vue(0, |vue| appels_fichiers::ouvrir_monte(vue, qui, objet, &o, drapeaux, &chemin)).map_err(errno)?;
                    let fichier = s.ouverts.ajouter(f.avec_chemin(complet)).map_err(|_| ENOMEM)?;
                    s.ouverts.fichier(fichier).lieu = lieu.and_then(|l| l.achever(&mut s.fs, objet));
                    crate::surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), crate::surveillance::IN_OPEN);
                    return Ok(fichier);
                }
            };
            let ouvert = s.fs.ouvrir(qui, &fin, &o, maintenant).map_err(errno)?;
            let a = s.fs.attributs(ouvert.numero);
            let sorte = match a.mode & S_IFMT {
                fichiers::S_IFREG => Sorte::Fichier,
                S_IFDIR => Sorte::Dossier,
                S_IFCHR if a.rdev == vfs::NULL => Sorte::Null,
                S_IFCHR if a.rdev == vfs::ZERO => Sorte::Zero,
                S_IFCHR if a.rdev == vfs::CONSOLE => Sorte::Console,
                S_IFCHR if a.rdev == vfs::RANDOM => Sorte::Aleatoire { random: true },
                S_IFCHR if a.rdev == vfs::URANDOM => Sorte::Aleatoire { random: false },
                S_IFCHR if a.rdev == vfs::FULL => Sorte::Plein,
                // Un fichier de socket (AF_UNIX) ne s'ouvre pas : ENXIO,
                // comme pour un programme Linux.
                fichiers::S_IFSOCK => {
                    s.fs.fermer(&ouvert, cadres);
                    return Err(ENXIO);
                }
                _ => {
                    s.fs.fermer(&ouvert, cadres);
                    return Err(EIO);
                }
            };
            // O_TRUNC : vidé, et ses bits setuid et setgid tombent
            // (`do_truncate`).
            let attrib = ouvert.tronquer && {
                let _ = s.fs.tronquer(ouvert.numero, 0, maintenant, cadres);
                s.fs.retirer_les_privileges(qui, ouvert.numero, maintenant)
            };
            let fichier = s.ouverts
                .ajouter(FichierOuvert::new(sorte, Tenu::Tmpfs(ouvert), o.lecture, o.ecriture, drapeaux, &chemin).avec_chemin(complet))
                .map_err(|_| {
                    s.fs.fermer(&ouvert, cadres);
                    ENOMEM
                })?;
            // Ce qu'en voit inotify, comme d'un open d'un programme Linux :
            // la création, l'ouverture, puis la troncature (O_TRUNC).
            use crate::surveillance::{IN_CREATE, IN_MODIFY, IN_OPEN};
            s.ouverts.fichier(fichier).lieu = lieu.and_then(|l| l.achever(&mut s.fs, Objet::Tmpfs(ouvert.numero)));
            if ouvert.cree {
                crate::surveillance::dans_le_dossier(fin.dossier, &fin.nom, IN_CREATE, false, 0);
            }
            crate::surveillance::du_fichier(&s.fs, s.ouverts.fichier(fichier), IN_OPEN);
            if ouvert.tronquer {
                let attrib = if attrib { crate::surveillance::IN_ATTRIB } else { 0 };
                crate::surveillance::changement(&s.fs, s.ouverts.fichier(fichier), IN_MODIFY | attrib);
            }
            Ok(fichier)
        });
        let fichier = match ouvert {
            Ok(f) => f,
            Err(e) => {
                self.descripteurs.liberer(fd);
                return e;
            }
        };
        self.descripteurs.installer(fd, Descripteur { fichier, fermer_a_l_exec: false });
        match ecrire(m, sortie, &(fd as u32).to_le_bytes()) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_fdstat_get : le type du fichier, ses drapeaux (APPEND, NONBLOCK),
    /// et ses droits : tous, sauf se déplacer pour la console (c'est ce qui
    /// dit à wasi-libc que c'est un terminal, pour isatty) et une socket.
    fn fd_fdstat_get(&self, fd: u32, adresse: u32, m: &mut [u8]) -> u32 {
        let (_, sorte, objet, _, _, drapeaux, _) = match self.ouvert(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        const SE_DEPLACER: u64 = (1 << 2) | (1 << 5); // FD_SEEK, FD_TELL
        let mut s = [0u8; 24];
        s[0] = type_wasi(appels_fichiers::attributs(objet).mode);
        let fdflags = if drapeaux & O_APPEND != 0 { FDFLAGS_APPEND } else { 0 } | if drapeaux & O_NONBLOCK != 0 { FDFLAGS_NONBLOCK } else { 0 };
        s[2..4].copy_from_slice(&fdflags.to_le_bytes());
        let droits = if matches!(sorte, Sorte::Console | Sorte::Socket) { u64::MAX & !SE_DEPLACER } else { u64::MAX };
        s[8..16].copy_from_slice(&droits.to_le_bytes());
        s[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        match ecrire(m, adresse, &s) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_fdstat_set_flags(fichier, fdflags) : APPEND et NONBLOCK, posés ou
    /// retirés (le F_SETFL de POSIX) ; DSYNC, RSYNC, SYNC : EINVAL, comme
    /// wasmtime (on ne les change pas après l'ouverture).
    fn fd_fdstat_set_flags(&mut self, fd: u32, fdflags: u32) -> u32 {
        const SYNCS: u32 = 2 | 8 | 16;
        let Some(d) = self.descripteurs.get(fd as u64) else { return EBADF };
        if fdflags & SYNCS != 0 || fdflags > 0xffff {
            return EINVAL;
        }
        vfs::avec_systeme(|s, _| {
            let f = s.ouverts.fichier(d.fichier);
            f.drapeaux &= !(O_APPEND | O_NONBLOCK);
            if fdflags & FDFLAGS_APPEND as u32 != 0 {
                f.drapeaux |= O_APPEND;
            }
            if fdflags & FDFLAGS_NONBLOCK as u32 != 0 {
                f.drapeaux |= O_NONBLOCK;
            }
        });
        SUCCES
    }

    /// fd_filestat_get : l'objet est tenu par son descripteur.
    fn fd_filestat_get(&self, fd: u32, adresse: u32, m: &mut [u8]) -> u32 {
        let objet = match self.ouvert(fd) {
            Ok((_, _, objet, ..)) => objet,
            Err(e) => return e,
        };
        let stat = filestat(&appels_fichiers::attributs(objet), appels_fichiers::systeme_de(objet).0);
        match ecrire(m, adresse, &stat) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// path_filestat_get(dossier, drapeaux, chemin, longueur, filestat) :
    /// sous le dossier, comme path_open.
    fn path_filestat_get(&self, dossier: u32, suivre: u32, adresse: u32, longueur: u32, sortie: u32, m: &mut [u8]) -> u32 {
        let (_, sorte, base, ..) = match self.ouvert(dossier) {
            Ok(o) => o,
            Err(e) => return e,
        };
        if sorte != Sorte::Dossier {
            return ENOTDIR;
        }
        let chemin = match chemin(m, adresse, longueur) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let qui = self.identite;
        // Les attributs, lus dans la même section du verrou des fichiers que
        // la résolution : l'objet trouvé n'est pas tenu, et un autre
        // programme pourrait l'effacer juste après (son inode n'existerait
        // plus).
        let stat = vfs::avec_systeme(|s, _| {
            let depart = Depart { racine: s.racine(), dossier: base, qui, sous: true };
            s.avec_vue(0, |vue| {
                let o = fichiers::chemins::trouver(vue, &depart, &chemin, suivre & 1 != 0)?;
                Ok(filestat(&vue.attributs(o), vue.peripherique(o).map_or(appels_fichiers::DEV_RACINE, |(dev, _)| dev)))
            })
        });
        match stat {
            Ok(stat) => match ecrire(m, sortie, &stat) {
                Ok(()) => SUCCES,
                Err(e) => e,
            },
            Err(e) => errno(e),
        }
    }

    /// fd_readdir(dossier, tampon, longueur, cookie, utilisés) : les entrées
    /// à partir de `cookie` (0 : le début), chacune un « dirent » de 24
    /// octets (le cookie de la suivante, l'inode, la longueur du nom, le
    /// type) suivi du nom. Comme le veut WASI, la dernière peut être
    /// coupée : un tampon rempli jusqu'au bout dit au programme qu'il y en
    /// a d'autres.
    #[allow(clippy::too_many_arguments)]
    fn fd_readdir(&self, dossier: u32, tampon: u32, longueur: u32, cookie: u64, utilises: u32, m: &mut [u8],
                  cout: &mut u64) -> u32 {
        let (d, sorte, objet, ..) = match self.ouvert(dossier) {
            Ok(o) => o,
            Err(e) => return e,
        };
        if sorte != Sorte::Dossier {
            return ENOTDIR;
        }
        if plage(m, tampon, longueur).is_none() || plage(m, utilises, 4).is_none() {
            return EFAULT;
        }
        let mut fait: u32 = 0;
        let r = vfs::avec_systeme(|s, _| {
            s.avec_vue(0, |vue| vue.lire_dossier(objet, cookie, |nom, numero, genre, suivante| {
                if fait >= longueur {
                    return false;
                }
                let mut entree = [0u8; 24];
                entree[0..8].copy_from_slice(&suivante.to_le_bytes());
                entree[8..16].copy_from_slice(&numero.to_le_bytes());
                entree[16..20].copy_from_slice(&(nom.len() as u32).to_le_bytes());
                entree[20] = match genre {
                    fichiers::tmpfs::DT_DIR => TYPE_DOSSIER,
                    fichiers::tmpfs::DT_LNK => TYPE_LIEN,
                    fichiers::tmpfs::DT_CHR => TYPE_CARACTERE,
                    _ => TYPE_FICHIER,
                };
                for morceau in [&entree[..], nom] {
                    let n = (morceau.len() as u32).min(longueur - fait);
                    let place = plage_mut(m, tampon + fait, n).expect("verifie plus haut");
                    place.copy_from_slice(&morceau[..n as usize]);
                    fait += n;
                }
                true
            }))
            .inspect(|_| crate::surveillance::du_fichier(&s.fs, s.ouverts.fichier(d.fichier), crate::surveillance::IN_ACCESS))
        });
        if let Err(e) = r {
            return errno(e);
        }
        *cout += fait as u64;
        match ecrire(m, utilises, &fait.to_le_bytes()) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }
}
