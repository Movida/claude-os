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
//! Un appel système ne doit pas non plus prendre la machine en otage : il
//! n'est pas interrompu par le carburant (voir wasm::Hote). Chaque appel
//! fait donc un travail borné (au plus 1024 octets lus ou écrits), et
//! compte ce travail en carburant.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use wasm::module::{DescriptionImport, TypeFonction, TypeValeur};
use wasm::validateur::ModuleValide;
use wasm::{Externe, Hote, Magasin, Piege, Valeur};

use crate::descripteurs::{Descripteur, Descripteurs, FichierOuvert, Sorte};
use crate::{appels_fichiers, console, temps, vfs};
use crate::descripteurs::Tenu;
use fichiers::chemins::Depart;
use fichiers::montages::{Creation, Modification, Objet, en_tmpfs};
use fichiers::tmpfs::{Numero, Ouverture, suivre_pour};
use fichiers::{Erreur, Identite, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, Temps};

/// Le module d'où un programme WASI importe ses appels système.
const MODULE: &str = "wasi_snapshot_preview1";

// Les codes d'erreur de WASI (les errno de POSIX, numérotés autrement :
// la liste de wasi_snapshot_preview1).
const SUCCES: u32 = 0;
const EACCES: u32 = 2;
const EBADF: u32 = 8;
const EBUSY: u32 = 10;
const EEXIST: u32 = 20;
const EFAULT: u32 = 21;
const EFBIG: u32 = 22;
const EINVAL: u32 = 28;
const EIO: u32 = 29;
const EISDIR: u32 = 31;
const ELOOP: u32 = 32;
const EMFILE: u32 = 33;
const EMLINK: u32 = 34;
const ENAMETOOLONG: u32 = 37;
const ENOENT: u32 = 44;
const ENOMEM: u32 = 48;
const ENOSPC: u32 = 51;
const ENOTDIR: u32 = 54;
const ENOTEMPTY: u32 = 55;
const ENXIO: u32 = 60;
const EPERM: u32 = 63;
const ESPIPE: u32 = 70;
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
    let mut v = Vec::new();
    v.try_reserve_exact(chaines.iter().map(|c| c.len() + 1).sum()).map_err(|_| Erreur::ENOMEM)?;
    for c in chaines {
        v.extend_from_slice(c);
        v.push(0);
    }
    Ok((v, chaines.len() as u32))
}

impl Wasi {
    /// Un hôte neuf pour l'identité `identite` : la console en 0, 1 et 2,
    /// puis les `dossiers` pré-ouverts en 3, 4... (ouverts avec ses droits :
    /// il doit pouvoir les traverser et les lire), ses `arguments` et son
    /// `environnement`. En cas d'échec, l'erreur, et le dossier en cause
    /// (aucun pour la console ou la mémoire) ; rien ne reste ouvert.
    pub fn new<'a>(identite: Identite, dossiers: &[&'a [u8]], arguments: &[&[u8]], environnement: &[&[u8]])
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
            let mut nom = Vec::new();
            nom.try_reserve_exact(dossier.len()).map_err(|_| (Erreur::ENOMEM, None))?;
            nom.extend_from_slice(dossier);
            // `wasi` est rendu en cas d'erreur : son Drop ferme ce qui est
            // déjà ouvert.
            let f = appels_fichiers::ouvrir_pour(identite, dossier, true, false, true).map_err(|e| (e, Some(dossier)))?;
            if wasi.descripteurs.installer(fd, Descripteur { fichier: f, fermer_a_l_exec: false }).is_err() {
                vfs::avec_systeme(|s, cadres| s.lacher(f, cadres));
                return Err((Erreur::ENOMEM, None));
            }
            wasi.preouverts.push(Preouvert { fd, nom });
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
        loop {
            let Some(fd) = self.descripteurs.ouverts(0, u64::MAX).next() else { break };
            if let Some(d) = self.descripteurs.retirer(fd) {
                vfs::avec_systeme(|s, cadres| s.lacher(d.fichier, cadres));
            }
        }
    }
}

/// Ce qu'il faut donner aux imports de `module` (dans leur ordre), après
/// avoir ajouté nos fonctions au magasin ; ou pourquoi on ne peut pas.
pub fn imports(magasin: &mut Magasin, module: &ModuleValide) -> Result<Vec<Externe>, String> {
    use TypeValeur::{I32, I64};
    let mut externes = Vec::new();
    for import in &module.module().imports {
        let DescriptionImport::Fonction(_) = import.description else {
            return Err(format!("import inconnu : {} {}", import.module, import.nom));
        };
        if import.module != MODULE {
            return Err(format!("import inconnu : {} {}", import.module, import.nom));
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
            // proc_exit(code)
            "proc_exit" => (PROC_EXIT, &[I32], &[]),
            _ => return Err(format!("import inconnu : {} {}", import.module, import.nom)),
        };
        // Le type exact : l'instanciation refusera un programme qui déclare
        // une fonction autrement.
        let t = TypeFonction { parametres: Box::from(parametres), resultats: Box::from(resultats) };
        externes.push(magasin.ajouter_fonction_hote(t, numero));
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
            ARGS_SIZES_GET => tailles(&self.arguments, a(0), a(1), m),
            ARGS_GET => chaines(&self.arguments, a(0), a(1), m, cout),
            ENVIRON_SIZES_GET => tailles(&self.environnement, a(0), a(1), m),
            ENVIRON_GET => chaines(&self.environnement, a(0), a(1), m, cout),
            _ => unreachable!("fonction hote inconnue"),
        };
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

/// Le chemin à `adresse` dans la mémoire du programme (WASI le donne avec
/// sa longueur, sans zéro final).
fn chemin(memoire: &[u8], adresse: u32, longueur: u32) -> Result<Vec<u8>, u32> {
    let octets = plage(memoire, adresse, longueur).ok_or(EFAULT)?;
    let mut copie = Vec::new();
    copie.try_reserve_exact(octets.len()).map_err(|_| ENOMEM)?;
    copie.extend_from_slice(octets);
    Ok(copie)
}

// Les types de fichiers de WASI (filetype).
const TYPE_INCONNU: u8 = 0;
const TYPE_CARACTERE: u8 = 2;
const TYPE_DOSSIER: u8 = 3;
const TYPE_FICHIER: u8 = 4;
const TYPE_LIEN: u8 = 7;

fn type_wasi(mode: u32) -> u8 {
    match mode & S_IFMT {
        S_IFDIR => TYPE_DOSSIER,
        S_IFLNK => TYPE_LIEN,
        S_IFCHR => TYPE_CARACTERE,
        fichiers::S_IFREG => TYPE_FICHIER,
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

/// Le « filestat » de WASI (64 octets) de l'objet `o`.
fn filestat(o: Objet) -> [u8; 64] {
    let a = appels_fichiers::attributs(o);
    let (dev, _) = appels_fichiers::systeme_de(o);
    let mut s = [0u8; 64];
    // dev : celui de son système de fichiers, codé comme st_dev.
    s[0..8].copy_from_slice(&appels_fichiers::encoder_peripherique(dev).to_le_bytes());
    s[8..16].copy_from_slice(&(a.numero.0 as u64).to_le_bytes());
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

impl Wasi {
    /// Le fichier ouvert du descripteur `fd`, et ce qu'il faut en savoir.
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
        const O_APPEND: u32 = 0o2000;
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
                (Sorte::Null | Sorte::Zero | Sorte::Aleatoire, true) => Ok(octets.len()),
                (Sorte::Plein, true) => Err(ENOSPC),
                (Sorte::Fichier, true) => vfs::avec(|fs, cadres| fs.ecrire(n(), ici, octets, maintenant, cadres)).map_err(errno),
                (Sorte::Fichier, false) => Ok(vfs::avec(|fs, cadres| fs.lire(n(), ici, octets, cadres))),
                (Sorte::Null | Sorte::Console, false) => Ok(0),
                (Sorte::Zero | Sorte::Plein, false) => {
                    octets.fill(0);
                    Ok(octets.len())
                }
                (Sorte::Aleatoire, false) => {
                    crate::aleatoire::remplir(octets);
                    Ok(octets.len())
                }
                (Sorte::Dossier, _) => Err(EISDIR),
                (Sorte::Chemin, _) => Err(EBADF),
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
        if sorte == Sorte::Fichier {
            vfs::avec_systeme(|s, _| s.ouverts.fichier(d.fichier).position = ici);
            if !ecriture {
                vfs::avec(|fs, _| fs.acceder(n(), maintenant));
            }
        }
        // Le travail : une unité de carburant par octet, et par morceau lu.
        *cout += fait as u64 + nombre as u64;
        match ecrire(m, total, &fait.to_le_bytes()) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_seek(fd, décalage, d'où, nouvelle) et fd_tell : SET (0), CUR (1),
    /// END (2) ; une position négative : EINVAL ; la console : ESPIPE.
    fn fd_seek(&mut self, fd: u32, decalage: i64, depuis: u32, adresse: u32, m: &mut [u8]) -> u32 {
        let (d, sorte, objet, _, _, _, position) = match self.ouvert(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let base = match (sorte, depuis) {
            (Sorte::Console, _) => return ESPIPE,
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
        let Some(fd) = self.descripteurs.libre(0) else { return EMFILE };
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
        let drapeaux = if fdflags & 1 != 0 { 0o2000 } else { 0 };
        let ouvert = vfs::avec_systeme(|s, cadres| {
            let racine = s.racine();
            let depart = Depart { racine, dossier: base, qui, sous: true };
            let fin = s.resoudre(0, &depart, &chemin, suivre_pour(&o, suivre & 1 == 0)).map_err(errno)?;
            // Un programme WebAssembly voit les systèmes montés comme un
            // programme Linux.
            let fin = match en_tmpfs(fin) {
                Ok(fin) => fin,
                Err(fin) => {
                    let Some(objet) = fin.objet else {
                        let e = if o.creer { s.avec_vue(0, |vue| vue.refus(qui, Modification::Creer(&fin, Creation::Ouvrir))) } else { Erreur::ENOENT };
                        return Err(errno(e));
                    };
                    let sorte = s.avec_vue(0, |vue| appels_fichiers::sorte_montee(vue, qui, objet, &o)).map_err(errno)?;
                    let f = FichierOuvert::new(sorte, Tenu::Noyau(objet), o.lecture, o.ecriture, drapeaux, &chemin);
                    return s.ouverts.ajouter(f).map_err(|_| ENOMEM);
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
                S_IFCHR if a.rdev == vfs::RANDOM || a.rdev == vfs::URANDOM => Sorte::Aleatoire,
                S_IFCHR if a.rdev == vfs::FULL => Sorte::Plein,
                _ => {
                    s.fs.fermer(&ouvert, cadres);
                    return Err(EIO);
                }
            };
            if ouvert.tronquer {
                let _ = s.fs.tronquer(ouvert.numero, 0, maintenant, cadres);
            }
            s.ouverts
                .ajouter(FichierOuvert::new(sorte, Tenu::Tmpfs(ouvert), o.lecture, o.ecriture, drapeaux, &chemin))
                .map_err(|_| {
                    s.fs.fermer(&ouvert, cadres);
                    ENOMEM
                })
        });
        let fichier = match ouvert {
            Ok(f) => f,
            Err(e) => return e,
        };
        if self.descripteurs.installer(fd, Descripteur { fichier, fermer_a_l_exec: false }).is_err() {
            vfs::avec_systeme(|s, cadres| s.lacher(fichier, cadres));
            return ENOMEM;
        }
        match ecrire(m, sortie, &(fd as u32).to_le_bytes()) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_fdstat_get : le type du fichier, ses drapeaux (APPEND), et ses
    /// droits : tous, sauf se déplacer pour la console (c'est ce qui dit à
    /// wasi-libc que c'est un terminal, pour isatty).
    fn fd_fdstat_get(&self, fd: u32, adresse: u32, m: &mut [u8]) -> u32 {
        let (_, sorte, objet, _, _, drapeaux, _) = match self.ouvert(fd) {
            Ok(o) => o,
            Err(e) => return e,
        };
        const SE_DEPLACER: u64 = (1 << 2) | (1 << 5); // FD_SEEK, FD_TELL
        let mut s = [0u8; 24];
        s[0] = type_wasi(appels_fichiers::attributs(objet).mode);
        s[2..4].copy_from_slice(&(if drapeaux & 0o2000 != 0 { 1u16 } else { 0 }).to_le_bytes());
        let droits = if sorte == Sorte::Console { u64::MAX & !SE_DEPLACER } else { u64::MAX };
        s[8..16].copy_from_slice(&droits.to_le_bytes());
        s[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        match ecrire(m, adresse, &s) {
            Ok(()) => SUCCES,
            Err(e) => e,
        }
    }

    /// fd_filestat_get.
    fn fd_filestat_get(&self, fd: u32, adresse: u32, m: &mut [u8]) -> u32 {
        match self.ouvert(fd) {
            Ok((_, _, objet, ..)) => match ecrire(m, adresse, &filestat(objet)) {
                Ok(()) => SUCCES,
                Err(e) => e,
            },
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
        let o = vfs::avec_systeme(|s, _| {
            let depart = Depart { racine: s.racine(), dossier: base, qui, sous: true };
            s.avec_vue(0, |vue| fichiers::chemins::trouver(vue, &depart, &chemin, suivre & 1 != 0))
        });
        match o {
            Ok(o) => match ecrire(m, sortie, &filestat(o)) {
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
        let (_, sorte, objet, ..) = match self.ouvert(dossier) {
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
