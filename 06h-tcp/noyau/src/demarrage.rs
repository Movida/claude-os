//! Les informations de démarrage, transmises par le chargeur.
//!
//! Le chargeur sait des choses que le noyau ne peut plus apprendre seul :
//! la carte de la mémoire (le BIOS ne la donne qu'en mode réel) et
//! l'endroit où il a déposé l'archive de programmes. Il les range dans une
//! structure en mémoire basse et nous en donne l'adresse (dans rdi, donc
//! en paramètre de noyau_main). C'est le rôle des « boot_params » de Linux
//! (arch/x86/include/uapi/asm/bootparam.h).
//!
//! On la recopie dès le début, comme la carte de la mémoire jusqu'ici : la
//! mémoire du chargeur n'est pas à nous, et le noyau ne doit dépendre de
//! rien qui y reste.

use crate::carte_memoire::{self, Zone};
use crate::verrou::Verrou;
use core::mem::size_of;

/// Le format écrit par le chargeur (voir INFOS dans ../boot.asm).
#[repr(C)]
struct InfosChargeur {
    signature: [u8; 4],
    /// La taille de la structure : un chargeur plus récent y ajoutera des
    /// champs, à la fin.
    taille: u32,
    archive: u64,
    taille_archive: u64,
    nombre_zones: u32,
    _inutilise: u32,
    zones: [Zone; carte_memoire::MAX_ZONES],
}

/// Une étendue de mémoire physique, [debut, fin[.
#[derive(Clone, Copy)]
pub struct Etendue {
    pub debut: u64,
    pub fin: u64,
}

/// Ce qu'on garde des informations de démarrage (la carte, elle, va dans
/// carte_memoire).
struct Infos {
    archive: Option<Etendue>,
}

static INFOS: Verrou<Infos> = Verrou::new(Infos { archive: None });

/// Recopie les informations laissées par le chargeur à l'adresse physique
/// `adresse`.
///
/// # Safety
/// `adresse` doit être celle que le chargeur a passée au noyau dans rdi,
/// et la mémoire basse ne doit pas encore avoir été réutilisée.
pub unsafe fn recopier(adresse: u64) -> Result<(), &'static str> {
    // SAFETY : garanti par l'appelant ; la mémoire basse est vue par la
    // projection directe (tables de démarrage, premier Gio).
    let source = unsafe { &*(crate::espace::virtuelle(adresse) as *const InfosChargeur) };
    if &source.signature != b"INFO" {
        return Err("signature absente : ce n'est pas notre chargeur");
    }
    // Une structure plus petite que la nôtre vient d'un chargeur plus
    // ancien, qui n'a pas écrit tous nos champs : on ne les lit pas au
    // hasard. Une plus grande, d'un chargeur plus récent : on ignore ses
    // champs en plus.
    if (source.taille as usize) < size_of::<InfosChargeur>() {
        return Err("structure trop petite : chargeur d'une autre version");
    }
    let nombre = (source.nombre_zones as usize).min(carte_memoire::MAX_ZONES);
    carte_memoire::installer(&source.zones[..nombre]);
    // Une archive qui déborderait de l'espace physique est un chargeur
    // fautif : mieux vaut l'ignorer que la réserver de travers.
    let archive = match source.archive.checked_add(source.taille_archive) {
        Some(fin) if source.taille_archive > 0 => Some(Etendue { debut: source.archive, fin }),
        Some(_) => None,
        None => return Err("archive hors de l'espace physique"),
    };
    INFOS.verrouiller().archive = archive;
    Ok(())
}

/// Où le chargeur a déposé l'archive de programmes, s'il y en a une.
pub fn archive() -> Option<Etendue> {
    INFOS.verrouiller().archive
}
