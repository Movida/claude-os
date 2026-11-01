//! Bonjour : le premier programme WebAssembly de notre OS.
//!
//! Il ne voit du système que WASI (« WebAssembly System Interface »), une
//! interface d'appels système faite pour WebAssembly, dans sa version
//! « preview 1 » : des fonctions importées du module
//! « wasi_snapshot_preview1 », dont il n'utilise que deux. Tout ce qu'il
//! échange avec elles passe par SA mémoire : il donne des adresses dans sa
//! propre mémoire linéaire, le noyau les lit et y écrit (voir
//! ../noyau/src/wasi.rs).

#![no_std]

use core::fmt::{self, Write};
use core::panic::PanicInfo;

/// Un morceau de mémoire à écrire, tel que WASI le décrit (le struct iovec
/// de POSIX) : son adresse et sa longueur, dans la mémoire du programme.
#[repr(C)]
struct Morceau {
    adresse: *const u8,
    longueur: usize,
}

#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    /// Écrit des morceaux de mémoire dans un fichier ouvert (1 : la sortie
    /// standard). Écrit à `ecrits` le nombre d'octets écrits, et rend un
    /// code d'erreur (0 : tout va bien).
    fn fd_write(fichier: u32, morceaux: *const Morceau, nombre: usize, ecrits: *mut usize) -> u16;
    /// Termine le programme, avec ce code de sortie.
    fn proc_exit(code: u32) -> !;
}

/// La sortie standard, pour formater du texte avec write! (core::fmt).
struct Sortie;

impl Write for Sortie {
    /// Écrit tout le texte. Le système peut n'en écrire qu'une partie à
    /// chaque appel (une écriture « partielle », que POSIX et WASI
    /// permettent) : on recommence avec la suite.
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        let mut reste = texte.as_bytes();
        while !reste.is_empty() {
            let morceau = Morceau { adresse: reste.as_ptr(), longueur: reste.len() };
            let mut ecrits = 0;
            // SAFETY : `morceau` et `ecrits` sont dans notre mémoire, valides
            // pendant l'appel.
            let code = unsafe { fd_write(1, &morceau, 1, &mut ecrits) };
            if code != 0 || ecrits == 0 || ecrits > reste.len() {
                return Err(fmt::Error);
            }
            reste = &reste[ecrits..];
        }
        Ok(())
    }
}

/// Le point d'entrée d'un programme WASI.
#[unsafe(no_mangle)]
pub extern "C" fn _start() {
    let mut sortie = Sortie;
    let mut resultat = writeln!(sortie, "[wasm] Bonjour depuis WebAssembly !");
    // Un peu de calcul, pour exercer l'interpréteur : les dix premiers
    // nombres premiers, formatés par core::fmt.
    resultat = resultat.and_then(|()| write!(sortie, "[wasm] Nombres premiers :"));
    let mut trouves = 0;
    let mut n = 2u32;
    while trouves < 10 {
        if (2..n).take_while(|d| d * d <= n).all(|d| n % d != 0) {
            resultat = resultat.and_then(|()| write!(sortie, " {n}"));
            trouves += 1;
        }
        n += 1;
    }
    resultat = resultat.and_then(|()| writeln!(sortie));
    // SAFETY : proc_exit ne revient pas.
    unsafe { proc_exit(if resultat.is_ok() { 0 } else { 1 }) }
}

/// Une panique termine le programme, avec un code reconnaissable.
#[panic_handler]
fn panique(_: &PanicInfo) -> ! {
    // SAFETY : proc_exit ne revient pas.
    unsafe { proc_exit(101) }
}
