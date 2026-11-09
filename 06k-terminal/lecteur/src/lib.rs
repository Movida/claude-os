//! Lecteur : un programme WebAssembly qui se sert des fichiers, par WASI.
//!
//! Il affiche ses arguments (ceux de sa ligne de /etc/demarrage), puis ne
//! voit du système que son dossier « pré-ouvert » (le descripteur 3, « / »,
//! donné par `--dir=/`) : chaque chemin part de là, et n'a pas le droit
//! d'en sortir (le noyau refuse « .. » au-dessus du dossier, et un lien
//! symbolique absolu). Il lit /etc/bonjour.txt, directement puis par un
//! lien, liste /etc, écrit puis relit un fichier dans /tmp, et vérifie
//! qu'il ne peut pas s'échapper. Chaque ligne affichée dit ce qu'il a vu.
//! Lancé sans `--dir=`, il n'a aucun dossier, le dit, et s'arrête.

#![no_std]

use core::fmt::{self, Write};
use core::panic::PanicInfo;

/// Un morceau de mémoire à lire ou à écrire (le struct iovec de POSIX).
#[repr(C)]
struct Morceau {
    adresse: *const u8,
    longueur: usize,
}

// Les droits de WASI (rights) et les drapeaux de path_open.
const FD_READ: u64 = 1 << 1;
const FD_WRITE: u64 = 1 << 6;
const FD_READDIR: u64 = 1 << 14;
const SUIVRE_LES_LIENS: u32 = 1;
const OFLAGS_CREAT: u32 = 1;
const OFLAGS_DIRECTORY: u32 = 2;
const OFLAGS_TRUNC: u32 = 8;
// Les errno de WASI : « mauvais descripteur », « opération interdite ».
const EBADF: u16 = 8;
const EPERM: u16 = 63;
const PREOUVERT: u32 = 3;

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    fn fd_write(fichier: u32, morceaux: *const Morceau, nombre: usize, ecrits: *mut usize) -> u16;
    fn fd_read(fichier: u32, morceaux: *const Morceau, nombre: usize, lus: *mut usize) -> u16;
    fn fd_close(fichier: u32) -> u16;
    fn fd_prestat_get(fichier: u32, prestat: *mut [u32; 2]) -> u16;
    #[allow(clippy::too_many_arguments)]
    fn path_open(dossier: u32, drapeaux: u32, chemin: *const u8, longueur: usize, oflags: u32, droits: u64,
                 droits_herites: u64, fdflags: u32, fichier: *mut u32) -> u16;
    fn fd_readdir(dossier: u32, tampon: *mut u8, longueur: usize, cookie: u64, utilises: *mut usize) -> u16;
    fn args_sizes_get(nombre: *mut usize, taille: *mut usize) -> u16;
    fn args_get(pointeurs: *mut *const u8, chaines: *mut u8) -> u16;
    fn clock_time_get(horloge: u32, precision: u64, temps: *mut u64) -> u16;
    fn poll_oneoff(abonnements: *const Abonnement, evenements: *mut Evenement, nombre: usize, publies: *mut usize) -> u16;
    fn sched_yield() -> u16;
    fn proc_exit(code: u32) -> !;
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

/// Un événement (l'`event` de WASI, 32 octets).
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

const EINVAL: u16 = 28;

/// Le temps monotone, en ns.
fn monotone() -> u64 {
    let mut t = 0;
    // SAFETY : `t` est dans notre mémoire.
    unsafe { clock_time_get(1, 1, &mut t) };
    t
}

/// poll_oneoff : une horloge de 20 ms seule fait attendre 20 ms au moins,
/// et rend un événement d'horloge avec sa donnée ; une horloge lointaine
/// avec un descripteur à écrire (la sortie) n'attend pas : seul le
/// descripteur est publié ; une horloge échue (un délai nul) avec lui :
/// les deux ; aucun abonnement : EINVAL. Et sched_yield.
fn attendre(s: &mut Sortie) -> bool {
    let horloge = |delai: u64, donnee: u64| Abonnement {
        donnee, genre: 0, _vide: [0; 7], horloge_ou_fd: 1, _vide2: 0, delai, precision: 0, drapeaux: 0, _vide3: [0; 6],
    };
    let vide = Evenement { donnee: 0, erreur: 0, genre: 9, _vide: [0; 5], octets: 0, drapeaux: 0, _vide2: [0; 6] };
    let mut evenements = [vide; 2];
    let mut publies = 0;
    let avant = monotone();
    // SAFETY : les tableaux et `publies` sont dans notre mémoire.
    let r = unsafe { poll_oneoff(&horloge(20_000_000, 7), evenements.as_mut_ptr(), 1, &mut publies) };
    let duree = monotone() - avant;
    let dort = r == 0 && publies == 1 && evenements[0].donnee == 7 && evenements[0].genre == 0 && duree >= 20_000_000;
    let _ = writeln!(s, "[wasm] lecteur : poll_oneoff d'une horloge de 20 ms : attendu, un evenement : {}", if dort { "ok" } else { "ECHEC" });
    let abonnements = [horloge(3_600_000_000_000, 1),
                       Abonnement { donnee: 2, genre: 2, _vide: [0; 7], horloge_ou_fd: 1, _vide2: 0, delai: 0, precision: 0, drapeaux: 0,
                                    _vide3: [0; 6] }];
    let avant = monotone();
    // SAFETY : comme ci-dessus.
    let r = unsafe { poll_oneoff(abonnements.as_ptr(), evenements.as_mut_ptr(), 2, &mut publies) };
    let pret = r == 0 && publies == 1 && evenements[0].donnee == 2 && evenements[0].genre == 2 && evenements[0].erreur == 0
               && monotone() - avant < 1_000_000_000;
    let _ = writeln!(s, "[wasm] lecteur : poll_oneoff, une heure et la sortie a ecrire : la sortie, sans attendre : {}",
                     if pret { "ok" } else { "ECHEC" });
    let abonnements = [horloge(0, 3),
                       Abonnement { donnee: 4, genre: 2, _vide: [0; 7], horloge_ou_fd: 1, _vide2: 0, delai: 0, precision: 0, drapeaux: 0,
                                    _vide3: [0; 6] }];
    // SAFETY : comme ci-dessus.
    let r = unsafe { poll_oneoff(abonnements.as_ptr(), evenements.as_mut_ptr(), 2, &mut publies) };
    let deux = r == 0 && publies == 2 && evenements[0].donnee == 3 && evenements[0].genre == 0 && evenements[1].donnee == 4
               && evenements[1].genre == 2;
    let _ = writeln!(s, "[wasm] lecteur : poll_oneoff, une horloge echue et la sortie a ecrire : les deux : {}",
                     if deux { "ok" } else { "ECHEC" });
    // SAFETY : comme ci-dessus.
    let refus = unsafe { poll_oneoff(abonnements.as_ptr(), evenements.as_mut_ptr(), 0, &mut publies) } == EINVAL;
    // SAFETY : sans argument.
    let cede = unsafe { sched_yield() } == 0;
    let _ = writeln!(s, "[wasm] lecteur : poll_oneoff sans abonnement : EINVAL ; sched_yield : 0 : {}", if refus && cede { "ok" } else { "ECHEC" });
    dort && pret && deux && refus && cede
}

/// La sortie standard, pour formater du texte avec write! (core::fmt).
struct Sortie;

impl Write for Sortie {
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        let mut reste = texte.as_bytes();
        while !reste.is_empty() {
            let morceau = Morceau { adresse: reste.as_ptr(), longueur: reste.len() };
            let mut ecrits = 0;
            // SAFETY : `morceau` et `ecrits` sont dans notre mémoire.
            let code = unsafe { fd_write(1, &morceau, 1, &mut ecrits) };
            if code != 0 || ecrits == 0 || ecrits > reste.len() {
                return Err(fmt::Error);
            }
            reste = &reste[ecrits..];
        }
        Ok(())
    }
}

/// Ouvre `chemin` sous le dossier pré-ouvert : le descripteur, ou l'errno.
fn ouvrir(chemin: &str, oflags: u32, droits: u64) -> Result<u32, u16> {
    let mut fd = 0;
    // SAFETY : le chemin et `fd` sont dans notre mémoire.
    let code = unsafe {
        path_open(PREOUVERT, SUIVRE_LES_LIENS, chemin.as_ptr(), chemin.len(), oflags, droits, 0, 0, &mut fd)
    };
    if code == 0 { Ok(fd) } else { Err(code) }
}

/// Lit tout ce que donne `fd`, dans `tampon` : le nombre d'octets.
fn lire(fd: u32, tampon: &mut [u8]) -> usize {
    let mut total = 0;
    loop {
        let morceau = Morceau { adresse: tampon[total..].as_ptr(), longueur: tampon.len() - total };
        let mut lus = 0;
        // SAFETY : le morceau désigne notre tampon.
        if unsafe { fd_read(fd, &morceau, 1, &mut lus) } != 0 || lus == 0 {
            return total;
        }
        total += lus;
    }
}

fn texte(octets: &[u8]) -> &str {
    core::str::from_utf8(octets).unwrap_or("?").trim_end_matches('\n')
}

/// Affiche ses arguments sur une ligne : « argc = 2, argv = /bin/lecteur.wasm
/// ... » (argc d'abord : un argument en trop ne passerait pas inaperçu).
/// Rend faux si WASI ne les donne pas.
fn afficher_arguments(s: &mut Sortie) -> bool {
    let (mut nombre, mut taille) = (0, 0);
    let mut pointeurs = [core::ptr::null::<u8>(); 8];
    let mut chaines = [0u8; 256];
    // SAFETY : tout est dans notre mémoire ; args_get n'écrit que si les
    // tailles annoncées tiennent dans nos tableaux (vérifié avant).
    let lus = unsafe {
        args_sizes_get(&mut nombre, &mut taille) == 0
            && nombre <= pointeurs.len()
            && taille <= chaines.len()
            && args_get(pointeurs.as_mut_ptr(), chaines.as_mut_ptr()) == 0
    };
    if !lus {
        let _ = writeln!(s, "[wasm] lecteur : argv : ECHEC");
        return false;
    }
    let _ = write!(s, "[wasm] lecteur : argc = {nombre}, argv =");
    // Chaque argument : de son adresse au zéro qui le termine, dans
    // `chaines`.
    for p in &pointeurs[..nombre] {
        let debut = (*p as usize).wrapping_sub(chaines.as_ptr() as usize);
        let Some(reste) = chaines.get(debut..taille) else { return false };
        let fin = reste.iter().position(|&o| o == 0).unwrap_or(reste.len());
        let _ = write!(s, " {}", texte(&reste[..fin]));
    }
    let _ = writeln!(s);
    true
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut s = Sortie;
    let mut ok = afficher_arguments(&mut s);
    let mut prestat = [0u32; 2];
    // SAFETY : `prestat` est dans notre mémoire.
    let code = unsafe { fd_prestat_get(PREOUVERT, &mut prestat) };
    if code == EBADF {
        // Lancé sans --dir= : rien à lire, et c'est ce qu'on attendait.
        let _ = writeln!(s, "[wasm] lecteur : aucun dossier pre-ouvert.");
        // SAFETY : proc_exit ne revient pas.
        unsafe { proc_exit(if ok { 0 } else { 1 }) }
    }
    let preouvert = code == 0 && prestat[1] == 1;
    let _ = writeln!(s, "[wasm] lecteur : dossier pre-ouvert 3 : {}", if preouvert { "ok" } else { "ECHEC" });
    ok &= preouvert;

    // Lire un fichier, puis le même par un lien symbolique relatif.
    let mut tampon = [0u8; 128];
    for chemin in ["etc/bonjour.txt", "etc/lien-bonjour"] {
        match ouvrir(chemin, 0, FD_READ) {
            Ok(fd) => {
                let n = lire(fd, &mut tampon);
                let _ = writeln!(s, "[wasm] lecteur : /{chemin} : {}", texte(&tampon[..n]));
                // SAFETY : un descripteur à nous.
                unsafe { fd_close(fd) };
            }
            Err(e) => {
                let _ = writeln!(s, "[wasm] lecteur : /{chemin} : ECHEC (errno {e})");
                ok = false;
            }
        }
    }

    // Lister /etc, dans l'ordre du système de fichiers.
    match ouvrir("etc", OFLAGS_DIRECTORY, FD_READDIR) {
        Ok(fd) => {
            let mut entrees = [0u8; 512];
            let mut utilises = 0;
            // SAFETY : le tampon et `utilises` sont dans notre mémoire.
            let code = unsafe { fd_readdir(fd, entrees.as_mut_ptr(), entrees.len(), 0, &mut utilises) };
            let _ = write!(s, "[wasm] lecteur : /etc contient :");
            let mut p = 0;
            while code == 0 && p + 24 <= utilises {
                let longueur = u32::from_le_bytes([entrees[p + 16], entrees[p + 17], entrees[p + 18], entrees[p + 19]]) as usize;
                let nom = &entrees[p + 24..(p + 24 + longueur).min(utilises)];
                let _ = write!(s, " {}", texte(nom));
                p += 24 + longueur;
            }
            let _ = writeln!(s);
            // SAFETY : un descripteur à nous.
            unsafe { fd_close(fd) };
        }
        Err(e) => {
            let _ = writeln!(s, "[wasm] lecteur : ouvrir /etc : ECHEC (errno {e})");
            ok = false;
        }
    }

    // Écrire un fichier dans /tmp, puis le relire.
    let ecrit = ouvrir("tmp/lecteur.txt", OFLAGS_CREAT | OFLAGS_TRUNC, FD_WRITE).map(|fd| {
        let morceau = Morceau { adresse: b"ecrit par WASI".as_ptr(), longueur: 14 };
        let mut n = 0;
        // SAFETY : le morceau est dans notre mémoire ; un descripteur à nous.
        unsafe {
            fd_write(fd, &morceau, 1, &mut n);
            fd_close(fd);
        }
        n
    });
    let relu = ouvrir("tmp/lecteur.txt", 0, FD_READ).map(|fd| {
        let n = lire(fd, &mut tampon);
        // SAFETY : un descripteur à nous.
        unsafe { fd_close(fd) };
        n
    });
    let ecriture = ecrit == Ok(14) && relu == Ok(14) && &tampon[..14] == b"ecrit par WASI";
    let _ = writeln!(s, "[wasm] lecteur : ecrire puis relire /tmp/lecteur.txt : {}", if ecriture { "ok" } else { "ECHEC" });
    ok &= ecriture;

    // S'échapper du dossier pré-ouvert : interdit.
    for chemin in ["../../etc/bonjour.txt", "etc/lien-absolu"] {
        let refuse = ouvrir(chemin, 0, FD_READ) == Err(EPERM);
        let _ = writeln!(s, "[wasm] lecteur : {chemin} refuse (EPERM) : {}", if refuse { "ok" } else { "ECHEC" });
        ok &= refuse;
    }

    // Le dossier pré-ouvert fermé, son numéro repris par un fichier : ce
    // n'est plus un dossier pré-ouvert (EBADF).
    let ferme = ouvrir("etc", OFLAGS_DIRECTORY, FD_READDIR).is_ok_and(|etc| {
        let mut fd = 0;
        // SAFETY : le chemin, `fd` et `prestat` sont dans notre mémoire ;
        // des descripteurs à nous.
        unsafe {
            fd_close(PREOUVERT) == 0
                && path_open(etc, 0, b"bonjour.txt".as_ptr(), 11, 0, FD_READ, 0, 0, &mut fd) == 0
                && fd == PREOUVERT
                && fd_prestat_get(PREOUVERT, &mut prestat) == EBADF
        }
    });
    let _ = writeln!(s, "[wasm] lecteur : le 3 ferme puis repris n'est plus pre-ouvert : {}", if ferme { "ok" } else { "ECHEC" });
    ok &= ferme;
    ok &= attendre(&mut s);
    // SAFETY : proc_exit ne revient pas.
    unsafe { proc_exit(if ok { 0 } else { 1 }) }
}

/// Une panique termine le programme, avec un code reconnaissable.
#[panic_handler]
fn panique(_: &PanicInfo) -> ! {
    // SAFETY : proc_exit ne revient pas.
    unsafe { proc_exit(101) }
}
