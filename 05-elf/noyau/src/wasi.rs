//! WASI, côté noyau : les appels système des programmes WebAssembly.
//!
//! WASI (« WebAssembly System Interface ») est l'interface système faite
//! pour WebAssembly : un programme importe ses appels système, comme des
//! fonctions, du module « wasi_snapshot_preview1 » (la version « preview
//! 1 », celle que visent les compilateurs). Le noyau les fournit comme
//! fonctions hôtes (voir wasm::Hote). Pour l'instant, deux :
//!   - fd_write : écrire sur la sortie standard ou d'erreur, la console ;
//!   - proc_exit : terminer le programme.
//!
//! Tout passe par la mémoire du programme : il donne des adresses dans SA
//! mémoire linéaire, où le noyau lit ce qu'il faut écrire et écrit le
//! résultat. Chaque adresse est vérifiée : hors de cette mémoire, l'appel
//! rend EFAULT, comme Linux pour un pointeur invalide. Le programme ne peut
//! désigner que sa propre mémoire : le bac à sable tient aussi à travers
//! les appels système.
//!
//! Un appel système ne doit pas non plus prendre la machine en otage : il
//! n'est pas interrompu par le carburant (voir wasm::Hote). Chaque appel
//! fait donc un travail borné, et compte ce travail en carburant.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use wasm::module::{DescriptionImport, TypeFonction, TypeValeur};
use wasm::validateur::ModuleValide;
use wasm::{Externe, Hote, Magasin, Piege, Valeur};

use crate::console;

/// Le module d'où un programme WASI importe ses appels système.
const MODULE: &str = "wasi_snapshot_preview1";

/// Les numéros de nos fonctions hôtes, donnés à `Magasin::ajouter_fonction_hote`.
const FD_WRITE: u32 = 0;
const PROC_EXIT: u32 = 1;

// Les codes d'erreur de WASI (les errno de POSIX, numérotés autrement).
const SUCCES: u32 = 0;
const EBADF: u32 = 8;
const EFAULT: u32 = 21;
const EINVAL: u32 = 28;

/// Le plus de morceaux qu'un fd_write peut décrire : l'IOV_MAX de POSIX,
/// que Linux impose aussi (UIO_MAXIOV). Au-delà : EINVAL.
const MORCEAUX_MAX: u32 = 1024;

/// Le plus d'octets qu'un fd_write écrit : au-delà, il en écrit une partie
/// et le dit (le nombre écrit), ce que POSIX et WASI permettent ; le
/// programme recommence avec la suite. Sur un vrai port série à 115 200
/// bauds, 1024 octets prennent déjà 90 ms.
const ECRITURE_MAX: u32 = 1024;

/// L'hôte des programmes WASI.
pub struct Wasi;

/// Ce qu'il faut donner aux imports de `module` (dans leur ordre), après
/// avoir ajouté nos fonctions au magasin ; ou pourquoi on ne peut pas.
pub fn imports(magasin: &mut Magasin, module: &ModuleValide) -> Result<Vec<Externe>, String> {
    use TypeValeur::I32;
    let mut externes = Vec::new();
    for import in &module.module().imports {
        let (numero, parametres, resultats): (u32, &[TypeValeur], &[TypeValeur]) =
            match (import.module.as_str(), import.nom.as_str(), &import.description) {
                // fd_write(fichier, morceaux, nombre, ecrits) -> errno
                (MODULE, "fd_write", DescriptionImport::Fonction(_)) => (FD_WRITE, &[I32, I32, I32, I32], &[I32]),
                // proc_exit(code)
                (MODULE, "proc_exit", DescriptionImport::Fonction(_)) => (PROC_EXIT, &[I32], &[]),
                _ => return Err(format!("import inconnu : {} {}", import.module, import.nom)),
            };
        // Le type exact : l'instanciation refusera un programme qui déclare
        // fd_write autrement.
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
        let entier = |i: usize| match arguments[i] {
            Valeur::I32(x) => x,
            _ => unreachable!("argument i32"),
        };
        match numero {
            FD_WRITE => {
                let errno = fd_write(entier(0), entier(1), entier(2), entier(3), memoire, cout);
                resultats[0] = Valeur::I32(errno);
                Ok(())
            }
            // Terminer : un « piège » de l'hôte, qui arrête l'exécution avec
            // le code de sortie ; le noyau le reconnaît (voir main.rs).
            PROC_EXIT => Err(Piege::Hote(entier(0))),
            _ => unreachable!("fonction hote inconnue"),
        }
    }
}

/// Les `longueur` octets de la mémoire du programme à partir de `adresse`,
/// s'ils y sont tous.
fn plage(memoire: &[u8], adresse: u32, longueur: u32) -> Option<&[u8]> {
    memoire.get(adresse as usize..(adresse as usize).checked_add(longueur as usize)?)
}

fn lire_u32(memoire: &[u8], adresse: u32) -> Option<u32> {
    let octets = plage(memoire, adresse, 4)?;
    Some(u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]))
}

/// Le i-ième morceau décrit à `morceaux` (chacun : adresse sur 32 bits,
/// puis longueur sur 32 bits), s'il est tout entier dans la mémoire.
fn morceau(memoire: &[u8], morceaux: u32, i: u32) -> Option<&[u8]> {
    let lire = |decalage: u32| lire_u32(memoire, morceaux.checked_add(i.checked_mul(8)?)?.checked_add(decalage)?);
    plage(memoire, lire(0)?, lire(4)?)
}

/// fd_write : écrit `nombre` morceaux, décrits à `morceaux` dans la mémoire
/// du programme, et écrit le total à `ecrits`. Rend un errno.
fn fd_write(fichier: u32, morceaux: u32, nombre: u32, ecrits: u32, memoire: Option<&mut [u8]>, cout: &mut u64) -> u32 {
    let Some(memoire) = memoire else { return EFAULT };
    if fichier != 1 && fichier != 2 {
        return EBADF;
    }
    if nombre > MORCEAUX_MAX {
        return EINVAL;
    }
    // Tout vérifier d'abord, comme Linux (import_iovec) : une erreur ne doit
    // rien avoir écrit.
    if (0..nombre).any(|i| morceau(memoire, morceaux, i).is_none()) || plage(memoire, ecrits, 4).is_none() {
        return EFAULT;
    }
    // Puis écrire, au plus ECRITURE_MAX octets en tout.
    let mut total: u32 = 0;
    for i in 0..nombre {
        let octets = morceau(memoire, morceaux, i).expect("verifie plus haut");
        let n = octets.len().min((ECRITURE_MAX - total) as usize);
        console::ecrire_octets(&octets[..n]);
        total += n as u32;
        if total == ECRITURE_MAX {
            break;
        }
    }
    // Le travail : une unité de carburant par octet écrit, et par morceau lu.
    *cout += total as u64 + nombre as u64;
    match memoire.get_mut(ecrits as usize..ecrits as usize + 4) {
        Some(case) => case.copy_from_slice(&total.to_le_bytes()),
        None => return EFAULT,
    }
    SUCCES
}
