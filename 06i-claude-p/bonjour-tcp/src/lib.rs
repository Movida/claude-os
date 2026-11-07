//! Bonjour-tcp : un serveur TCP en WebAssembly, par les sockets de WASI.
//!
//! WASI preview 1 ne crée pas de socket (ni `socket`, ni `bind`, ni
//! `connect` : c'est son modèle de capacités). Le lanceur lui en ouvre une
//! qui écoute, d'après sa ligne de /etc/demarrage
//! (`--tcplisten=127.0.0.1:8080`, comme wasmtime), et la lui donne après ses
//! dossiers pré-ouverts : il la trouve en parcourant ses descripteurs à
//! partir de 3 (fd_fdstat_get : une SOCKET_STREAM). Il y accepte deux
//! connexions, l'une après l'autre ; de chacune, il lit une ligne et la
//! renvoie à l'envers. La première par les appels des sockets (sock_recv,
//! d'abord en RECV_PEEK, puis sock_send et sock_shutdown, après lequel il
//! lit encore le dernier mot du client : seule l'écriture est arrêtée),
//! attendue par poll_oneoff : l'écoute est NON BLOQUANTE (comme chez
//! wasmtime). La seconde, acceptée en bloquant (l'écoute rendue bloquante
//! par fd_fdstat_set_flags, le temps de l'accept), par fd_read et fd_write,
//! comme un fichier. Puis il vérifie les refus. Son client est un
//! programme Linux (../linux/client-tcp.c), lancé sur la ligne suivante.

#![no_std]

use core::fmt::{self, Write};
use core::panic::PanicInfo;

/// Un morceau de mémoire à lire ou à écrire (le struct iovec de POSIX).
#[repr(C)]
struct Morceau {
    adresse: *const u8,
    longueur: usize,
}

/// Le `fdstat` de WASI (24 octets) : le type du fichier, ses drapeaux, ses
/// droits.
#[repr(C)]
#[derive(Default)]
struct Fdstat {
    type_fichier: u8,
    drapeaux: u16,
    droits: u64,
    droits_herites: u64,
}

/// Un abonnement de poll_oneoff (la `subscription` de WASI, 48 octets) : sa
/// donnée, son genre (0 une horloge, 1 lire, 2 écrire), puis l'horloge et
/// son délai, ou le descripteur.
#[repr(C)]
struct Abonnement {
    donnee: u64,
    genre: u8,
    _vide: [u8; 7],
    horloge_ou_fd: u32,
    _vide2: u32,
    delai: u64,
    precision: u64,
    drapeaux: u16,
    _vide3: [u8; 6],
}

/// Un événement (l'`event` de WASI, 32 octets) : la donnée de son
/// abonnement, une erreur, son genre, puis pour un descripteur ce qui est
/// prêt et ses drapeaux (1 : l'autre bout a raccroché).
#[repr(C)]
#[derive(Clone, Copy)]
struct Evenement {
    donnee: u64,
    erreur: u16,
    genre: u8,
    _vide: [u8; 5],
    octets: u64,
    drapeaux: u16,
    _vide2: [u8; 6],
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    fn fd_write(fichier: u32, morceaux: *const Morceau, nombre: usize, ecrits: *mut usize) -> u16;
    fn fd_read(fichier: u32, morceaux: *const Morceau, nombre: usize, lus: *mut usize) -> u16;
    fn fd_close(fichier: u32) -> u16;
    fn fd_seek(fichier: u32, decalage: i64, depuis: u32, position: *mut u64) -> u16;
    fn fd_fdstat_get(fichier: u32, fdstat: *mut Fdstat) -> u16;
    fn fd_fdstat_set_flags(fichier: u32, fdflags: u32) -> u16;
    fn fd_prestat_get(fichier: u32, prestat: *mut [u32; 2]) -> u16;
    fn poll_oneoff(abonnements: *const Abonnement, evenements: *mut Evenement, nombre: usize, publies: *mut usize) -> u16;
    fn sock_accept(ecoute: u32, fdflags: u32, fichier: *mut u32) -> u16;
    fn sock_recv(socket: u32, morceaux: *const Morceau, nombre: usize, riflags: u32, recus: *mut usize, roflags: *mut u16) -> u16;
    fn sock_send(socket: u32, morceaux: *const Morceau, nombre: usize, siflags: u32, envoyes: *mut usize) -> u16;
    fn sock_shutdown(socket: u32, sdflags: u32) -> u16;
    fn proc_exit(code: u32) -> !;
}

// Les types de fichiers, les drapeaux et les errno de WASI.
const SOCKET_STREAM: u8 = 6;
const FDFLAGS_APPEND: u32 = 1;
const FDFLAGS_NONBLOCK: u16 = 4;
const RECV_PEEK: u32 = 1;
const SHUT_WR: u32 = 2;
const LIRE: u8 = 1;
const EAGAIN: u16 = 6;
const EBADF: u16 = 8;
const EINVAL: u16 = 28;
const ENOTCONN: u16 = 53;
const ENOTSOCK: u16 = 57;
const ESPIPE: u16 = 70;

/// La sortie standard, pour formater du texte avec write! (core::fmt), ligne
/// par ligne : chaque ligne part d'un seul fd_write, pour ne pas se mêler à
/// celles du client, qui écrit en même temps (writeln! écrit une ligne en
/// plusieurs morceaux, et la console écrit chaque appel d'un tenant).
struct Sortie {
    ligne: [u8; 256],
    n: usize,
}

impl Sortie {
    fn vider(&mut self) -> fmt::Result {
        let r = ecrire_tout(1, &self.ligne[..self.n], false);
        self.n = 0;
        r.map_err(|_| fmt::Error)
    }
}

impl Write for Sortie {
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        for &o in texte.as_bytes() {
            if self.n == self.ligne.len() {
                self.vider()?;
            }
            self.ligne[self.n] = o;
            self.n += 1;
            if o == b'\n' {
                self.vider()?;
            }
        }
        Ok(())
    }
}

/// Écrit tous les `octets` dans `fd`, par sock_send ou par fd_write : l'un
/// et l'autre peuvent n'en écrire qu'une partie (au plus 1024 octets chez
/// nous), on recommence avec la suite. L'errno sinon.
fn ecrire_tout(fd: u32, octets: &[u8], socket: bool) -> Result<(), u16> {
    let mut reste = octets;
    while !reste.is_empty() {
        let morceau = Morceau { adresse: reste.as_ptr(), longueur: reste.len() };
        let mut ecrits = 0;
        // SAFETY : `morceau` et `ecrits` sont dans notre mémoire.
        let code = unsafe { if socket { sock_send(fd, &morceau, 1, 0, &mut ecrits) } else { fd_write(fd, &morceau, 1, &mut ecrits) } };
        if code != 0 {
            return Err(code);
        }
        if ecrits == 0 || ecrits > reste.len() {
            return Err(0);
        }
        reste = &reste[ecrits..];
    }
    Ok(())
}

/// Reçoit de `fd` dans `tampon` (sock_recv avec `riflags`, ou fd_read) :
/// le nombre d'octets (0 : la fin du flux), ou l'errno.
fn recevoir(fd: u32, tampon: &mut [u8], riflags: u32, socket: bool) -> Result<usize, u16> {
    let morceau = Morceau { adresse: tampon.as_ptr(), longueur: tampon.len() };
    let (mut recus, mut roflags) = (0, 0u16);
    // SAFETY : le morceau désigne notre tampon ; `recus` et `roflags` sont
    // dans notre mémoire.
    let code = unsafe {
        if socket { sock_recv(fd, &morceau, 1, riflags, &mut recus, &mut roflags) } else { fd_read(fd, &morceau, 1, &mut recus) }
    };
    if code != 0 { Err(code) } else { Ok(recus) }
}

/// Lit une ligne de `fd` dans `tampon`, jusqu'à sa fin de ligne comprise
/// (ou la fin du flux) : sa longueur.
fn lire_ligne(fd: u32, tampon: &mut [u8], socket: bool) -> Result<usize, u16> {
    let mut n = 0;
    while n < tampon.len() && !tampon[..n].contains(&b'\n') {
        let k = recevoir(fd, &mut tampon[n..], 0, socket)?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

/// Le type et les drapeaux du descripteur `fd`, ou l'errno.
fn fdstat(fd: u32) -> Result<Fdstat, u16> {
    let mut f = Fdstat::default();
    // SAFETY : `f` est dans notre mémoire.
    let code = unsafe { fd_fdstat_get(fd, &mut f) };
    if code != 0 { Err(code) } else { Ok(f) }
}

fn lire_abonnement(fd: u32, donnee: u64) -> Abonnement {
    Abonnement { donnee, genre: LIRE, _vide: [0; 7], horloge_ou_fd: fd, _vide2: 0, delai: 0, precision: 0, drapeaux: 0, _vide3: [0; 6] }
}

/// poll_oneoff de ces abonnements : les événements publiés, et leur nombre.
fn sonder(abonnements: &[Abonnement]) -> ([Evenement; 2], usize) {
    let vide = Evenement { donnee: 0, erreur: 0, genre: 9, _vide: [0; 5], octets: 0, drapeaux: 0, _vide2: [0; 6] };
    let mut evenements = [vide; 2];
    let mut publies = 0;
    // SAFETY : les tableaux et `publies` sont dans notre mémoire ; au plus
    // deux abonnements, deux événements.
    let code = unsafe { poll_oneoff(abonnements.as_ptr(), evenements.as_mut_ptr(), abonnements.len().min(2), &mut publies) };
    (evenements, if code == 0 { publies } else { 0 })
}

/// L'écoute pré-ouverte : le premier descripteur à partir de 3 qui est une
/// SOCKET_STREAM (avant le premier EBADF).
fn trouver_ecoute() -> Option<u32> {
    (3..64).map_while(|fd| fdstat(fd).ok().map(|f| (fd, f))).find(|(_, f)| f.type_fichier == SOCKET_STREAM).map(|(fd, _)| fd)
}

fn texte(octets: &[u8]) -> &str {
    core::str::from_utf8(octets).unwrap_or("?").trim_end_matches('\n')
}

/// Une connexion : attendre le client (poll_oneoff sur l'écoute), l'accepter
/// (bloquante : sans NONBLOCK), lire sa ligne, la renvoyer à l'envers, et
/// fermer. La première par les appels des sockets, la seconde comme un
/// fichier. Rend vrai si tout s'est passé comme prévu.
fn servir(s: &mut Sortie, ecoute: u32, numero: u32) -> bool {
    let par_sockets = numero == 1;
    let mut fd = 0;
    let (attendu, accepte) = if par_sockets {
        // Attendre le client par poll_oneoff, puis l'accepter.
        let (evenements, publies) = sonder(&[lire_abonnement(ecoute, numero as u64)]);
        let attendu = publies == 1 && evenements[0].donnee == numero as u64 && evenements[0].genre == LIRE && evenements[0].erreur == 0;
        // SAFETY : `fd` est dans notre mémoire.
        (attendu, attendu && unsafe { sock_accept(ecoute, 0, &mut fd) } == 0)
    } else {
        // L'écoute rendue bloquante : sock_accept attend le client ; puis
        // de nouveau non bloquante.
        // SAFETY : sans mémoire.
        let bloquante = unsafe { fd_fdstat_set_flags(ecoute, 0) } == 0 && fdstat(ecoute).is_ok_and(|f| f.drapeaux & FDFLAGS_NONBLOCK == 0);
        // SAFETY : `fd` est dans notre mémoire.
        let accepte = bloquante && unsafe { sock_accept(ecoute, 0, &mut fd) } == 0;
        // SAFETY : sans mémoire.
        let rendue = unsafe { fd_fdstat_set_flags(ecoute, FDFLAGS_NONBLOCK as u32) } == 0;
        (bloquante && rendue, accepte)
    };
    let bloquante = accepte && fdstat(fd).is_ok_and(|f| f.type_fichier == SOCKET_STREAM && f.drapeaux & FDFLAGS_NONBLOCK == 0);
    let mut ligne = [0u8; 64];
    let mut lu = 0;
    let mut regard = true;
    if accepte && par_sockets {
        // Attendre ses octets, les regarder sans les prendre (RECV_PEEK),
        // puis les lire : les mêmes.
        let (evenements, publies) = sonder(&[lire_abonnement(fd, 7)]);
        let arrives = if publies == 1 && evenements[0].erreur == 0 { evenements[0].octets as usize } else { 0 };
        let mut apercu = [0u8; 64];
        let vus = recevoir(fd, &mut apercu, RECV_PEEK, true).unwrap_or(0);
        lu = lire_ligne(fd, &mut ligne, true).unwrap_or(0);
        regard = arrives > 0 && vus > 0 && vus <= lu && apercu[..vus] == ligne[..vus];
    } else if accepte {
        lu = lire_ligne(fd, &mut ligne, false).unwrap_or(0);
    }
    let fin = lu > 0 && ligne[lu - 1] == b'\n';
    // La ligne à l'envers, et sa fin de ligne.
    let mut envers = [0u8; 65];
    let n = if fin { lu - 1 } else { lu };
    for i in 0..n {
        envers[i] = ligne[n - 1 - i];
    }
    envers[n] = b'\n';
    let rendu = fin && ecrire_tout(fd, &envers[..n + 1], par_sockets).is_ok();
    // La première : la fin de l'écriture annoncée (FIN) ; le client, qui
    // voit alors la fin du flux, répond un dernier mot, que la lecture,
    // toujours ouverte, reçoit.
    let mut dernier = [0u8; 16];
    let arret = !par_sockets
        // SAFETY : sans mémoire.
        || (unsafe { sock_shutdown(fd, SHUT_WR) } == 0 && lire_ligne(fd, &mut dernier, true).is_ok_and(|n| &dernier[..n] == b"merci\n"));
    // SAFETY : sans mémoire.
    let ferme = accepte && unsafe { fd_close(fd) } == 0;
    let ok = attendu && accepte && bloquante && regard && rendu && arret && ferme;
    let comment = if par_sockets { "poll_oneoff, sock_recv, sock_send, sock_shutdown" } else { "accept bloquant, fd_read, fd_write" };
    let suite = if par_sockets { ", puis 'merci' apres sock_shutdown" } else { "" };
    let _ = writeln!(s, "[wasm] bonjour-tcp : connexion {} ({}) : recu '{}', rendu '{}'{} : {}", numero, comment, texte(&ligne[..lu]),
                     texte(&envers[..n]), suite, if ok { "ok" } else { "ECHEC" });
    ok
}

/// Après les deux clients : les refus. Accepter sans client sur l'écoute
/// non bloquante : EAGAIN ; et poll_oneoff ne la publie pas, seulement
/// l'horloge de 20 ms à côté d'elle. Recevoir d'une écoute : ENOTCONN ; s'y
/// déplacer : ESPIPE ; accepter sur la console : ENOTSOCK ; un arrêt sans
/// drapeau, ou accepter avec APPEND : EINVAL.
fn refus(s: &mut Sortie, ecoute: u32) -> bool {
    let mut fd = 0;
    // SAFETY : `fd` est dans notre mémoire.
    let sans_client = unsafe { sock_accept(ecoute, 0, &mut fd) } == EAGAIN;
    let horloge = Abonnement {
        donnee: 2, genre: 0, _vide: [0; 7], horloge_ou_fd: 1, _vide2: 0, delai: 20_000_000, precision: 0, drapeaux: 0, _vide3: [0; 6],
    };
    let (evenements, publies) = sonder(&[lire_abonnement(ecoute, 1), horloge]);
    let seule_horloge = publies == 1 && evenements[0].donnee == 2 && evenements[0].genre == 0;
    let mut tampon = [0u8; 8];
    let mut position = 0;
    // SAFETY : `position` et `fd` sont dans notre mémoire.
    let refus = recevoir(ecoute, &mut tampon, 0, true) == Err(ENOTCONN)
        && unsafe { fd_seek(ecoute, 0, 1, &mut position) } == ESPIPE
        && unsafe { sock_accept(1, 0, &mut fd) } == ENOTSOCK
        && unsafe { sock_shutdown(ecoute, 0) } == EINVAL
        && unsafe { sock_accept(ecoute, FDFLAGS_APPEND, &mut fd) } == EINVAL;
    let _ = writeln!(s, "[wasm] bonjour-tcp : sans client : EAGAIN, et poll_oneoff ne publie que l'horloge : {}",
                     if sans_client && seule_horloge { "ok" } else { "ECHEC" });
    let _ = writeln!(s, "[wasm] bonjour-tcp : refus : ENOTCONN, ESPIPE, ENOTSOCK, EINVAL : {}", if refus { "ok" } else { "ECHEC" });
    sans_client && seule_horloge && refus
}

/// Le point d'entrée d'un programme WASI.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut s = Sortie { ligne: [0; 256], n: 0 };
    let Some(ecoute) = trouver_ecoute() else {
        let _ = writeln!(s, "[wasm] bonjour-tcp : pas d'ecoute pre-ouverte (--tcplisten=) : ECHEC");
        // SAFETY : proc_exit ne revient pas.
        unsafe { proc_exit(1) }
    };
    // Une écoute non bloquante, et pas un dossier pré-ouvert : wasi-libc,
    // qui parcourt ces derniers jusqu'au premier EBADF de fd_prestat_get,
    // s'y arrête.
    let mut prestat = [0u32; 2];
    // SAFETY : `prestat` est dans notre mémoire.
    let pas_un_dossier = unsafe { fd_prestat_get(ecoute, &mut prestat) } == EBADF;
    let non_bloquante = fdstat(ecoute).is_ok_and(|f| f.drapeaux & FDFLAGS_NONBLOCK != 0);
    let mut ok = pas_un_dossier && non_bloquante;
    let _ = writeln!(s, "[wasm] bonjour-tcp : ecoute pre-ouverte en {} : SOCKET_STREAM, non bloquante, pas un dossier : {}", ecoute,
                     if ok { "ok" } else { "ECHEC" });
    ok &= servir(&mut s, ecoute, 1);
    ok &= servir(&mut s, ecoute, 2);
    ok &= refus(&mut s, ecoute);
    // SAFETY : proc_exit ne revient pas.
    unsafe { proc_exit(if ok { 0 } else { 1 }) }
}

/// Une panique termine le programme, avec un code reconnaissable.
#[panic_handler]
fn panique(_: &PanicInfo) -> ! {
    // SAFETY : proc_exit ne revient pas.
    unsafe { proc_exit(101) }
}
