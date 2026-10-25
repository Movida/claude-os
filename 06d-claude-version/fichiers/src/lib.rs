//! Les fichiers : le système de fichiers en mémoire de Linux (le tmpfs,
//! mm/shmem.c, où l'initramfs est déballé au démarrage) et la résolution
//! des chemins (fs/namei.c).
//!
//! Trois morceaux :
//!   - `index` : l'index des pages d'un fichier (le cache des pages : pour
//!     un fichier de tmpfs, ses pages sont ses données) ;
//!   - `chemins` : la résolution d'un chemin, composant par composant, avec
//!     les liens symboliques, les droits de traverser, la barre finale. Elle
//!     ne connaît d'un système de fichiers que ce que dit le trait `Arbre`
//!     (chercher un nom dans un dossier, le parent, la cible d'un lien) :
//!     c'est ainsi qu'elle traverse les points de montage (`montages`, 6d)
//!     sans avoir changé d'une ligne ;
//!   - `tmpfs` : l'arborescence elle-même (inodes, dossiers, liens), et les
//!     opérations des appels système (créer, effacer, renommer, ouvrir...),
//!     avec les vérifications et les codes d'erreur de Linux, dans son
//!     ordre ;
//!   - `montages` (6d) : les systèmes de fichiers montés sur des dossiers du
//!     tmpfs (/proc, /sys), la vue de tous les systèmes que parcourt la
//!     résolution, et les règles de Linux pour ce qui passe d'un système à
//!     l'autre.
//!
//! La bibliothèque ne sait rien des cadres de la mémoire, des processus ni
//! des copies depuis ou vers un programme : c'est le noyau qui les fait.
//! Elle ne fait que décider. Sans `unsafe`, testée sur l'hôte : des cas
//! écrits à la main pour chaque règle, et des milliers d'opérations au
//! hasard comparées à un modèle naïf (tests/modele.rs). Toute opération est
//! tout ou rien : la mémoire qu'elle demande est obtenue avant de rien
//! changer, et une allocation qui échoue rend ENOMEM sans rien avoir
//! changé (le noyau ne doit jamais paniquer pour un programme).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod chemins;
pub mod index;
pub mod montages;
pub mod tmpfs;

/// La taille d'une page.
pub const PAGE: u64 = 4096;

// Le type d'un fichier, dans les bits hauts de son mode (st_mode) : les
// valeurs de POSIX, celles de Linux (include/uapi/linux/stat.h).
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFCHR: u32 = 0o020_000;
// Les bits spéciaux des droits.
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
/// Le bit « sticky » : dans un dossier (/tmp), on n'efface que ses propres
/// fichiers.
pub const S_ISVTX: u32 = 0o1000;

/// Les droits qu'une opération demande sur un inode : lire, écrire,
/// exécuter (ou traverser, pour un dossier). Les valeurs de R_OK, W_OK et
/// X_OK (access), et des bits rwx du mode.
pub const LIRE: u32 = 4;
pub const ECRIRE: u32 = 2;
pub const EXECUTER: u32 = 1;

/// Qui fait l'opération : ses numéros d'utilisateur et de groupe (les
/// fsuid et fsgid de Linux). L'utilisateur 0 est root : il passe outre les
/// droits (CAP_DAC_OVERRIDE), sauf pour exécuter un fichier qui n'est
/// exécutable par personne.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identite {
    pub uid: u32,
    pub gid: u32,
}

impl Identite {
    pub const ROOT: Identite = Identite { uid: 0, gid: 0 };

    pub fn root(&self) -> bool {
        self.uid == 0
    }
}

/// Une date : des secondes et des nanosecondes depuis le 1er janvier 1970
/// à 0 h UTC (le `struct timespec` de POSIX).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Temps {
    pub secondes: i64,
    pub nanosecondes: u32,
}

/// Les erreurs, sous les noms et avec les numéros de Linux
/// (include/uapi/asm-generic/errno-base.h et errno.h) : le noyau les rend
/// telles quelles aux programmes Linux, et les traduit pour WASI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Erreur {
    /// Opération interdite (pas les droits du propriétaire, un lien
    /// physique vers un dossier...).
    EPERM,
    /// Le fichier n'existe pas.
    ENOENT,
    /// Pas de donnée au-delà (SEEK_DATA après la fin).
    ENXIO,
    /// Plus de mémoire.
    ENOMEM,
    /// Les droits ne le permettent pas.
    EACCES,
    /// Occupé : la racine, un point de montage.
    EBUSY,
    /// Existe déjà.
    EEXIST,
    /// Hors du système de fichiers, ou du dossier de départ (la résolution
    /// « sous » un dossier, RESOLVE_BENEATH).
    EXDEV,
    /// Pas un dossier.
    ENOTDIR,
    /// Un dossier.
    EISDIR,
    /// Argument invalide.
    EINVAL,
    /// Le fichier est un programme en cours d'exécution (ou ouvert en
    /// écriture, pour l'exécuter).
    ETXTBSY,
    /// Fichier trop grand.
    EFBIG,
    /// Plus de place dans le système de fichiers.
    ENOSPC,
    /// Trop de liens physiques.
    EMLINK,
    /// Nom ou chemin trop long.
    ENAMETOOLONG,
    /// Dossier non vide.
    ENOTEMPTY,
    /// Trop de liens symboliques à suivre (une boucle), ou un lien là où on
    /// n'en voulait pas (O_NOFOLLOW).
    ELOOP,
}

impl Erreur {
    /// Le numéro de l'erreur pour Linux.
    pub fn errno(self) -> i64 {
        match self {
            Erreur::EPERM => 1,
            Erreur::ENOENT => 2,
            Erreur::ENXIO => 6,
            Erreur::ENOMEM => 12,
            Erreur::EACCES => 13,
            Erreur::EBUSY => 16,
            Erreur::EEXIST => 17,
            Erreur::EXDEV => 18,
            Erreur::ENOTDIR => 20,
            Erreur::EISDIR => 21,
            Erreur::EINVAL => 22,
            Erreur::ETXTBSY => 26,
            Erreur::EFBIG => 27,
            Erreur::ENOSPC => 28,
            Erreur::EMLINK => 31,
            Erreur::ENAMETOOLONG => 36,
            Erreur::ENOTEMPTY => 39,
            Erreur::ELOOP => 40,
        }
    }
}

/// Les droits `masque` (LIRE, ECRIRE, EXECUTER, combinés) sont-ils permis
/// à `qui` sur un inode de mode `mode`, à l'utilisateur `uid` et au groupe
/// `gid` ? C'est le `generic_permission` de Linux : on regarde les trois
/// bits du propriétaire si c'est lui, sinon ceux du groupe si c'est le
/// sien, sinon ceux des autres. Pas de groupes supplémentaires : nos
/// programmes n'en ont pas.
///
/// Root passe outre (CAP_DAC_OVERRIDE) : il peut tout lire, tout écrire,
/// et traverser tout dossier ; mais il n'exécute un fichier que si l'un
/// des trois bits x est mis (sinon ce n'est pas un programme).
pub fn permis(mode: u32, uid: u32, gid: u32, qui: Identite, masque: u32) -> bool {
    if qui.root() {
        let dossier = mode & S_IFMT == S_IFDIR;
        return masque & EXECUTER == 0 || dossier || mode & 0o111 != 0;
    }
    let bits = if qui.uid == uid {
        mode >> 6
    } else if qui.gid == gid {
        mode >> 3
    } else {
        mode
    } & 7;
    bits & masque == masque
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droits_unix() {
        let david = Identite { uid: 1000, gid: 1000 };
        // Le propriétaire regarde ses bits, et seulement eux : un fichier
        // 0077 lui est fermé, même si les autres peuvent tout.
        assert!(permis(S_IFREG | 0o644, 1000, 1000, david, LIRE | ECRIRE));
        assert!(!permis(S_IFREG | 0o644, 1000, 1000, david, EXECUTER));
        assert!(!permis(S_IFREG | 0o077, 1000, 1000, david, LIRE));
        // Le groupe, puis les autres.
        assert!(permis(S_IFREG | 0o640, 0, 1000, david, LIRE));
        assert!(!permis(S_IFREG | 0o640, 0, 0, david, LIRE));
        assert!(permis(S_IFDIR | 0o755, 0, 0, david, LIRE | EXECUTER));
        assert!(!permis(S_IFDIR | 0o755, 0, 0, david, ECRIRE));
        // Root : tout, sauf exécuter un fichier que personne ne peut
        // exécuter.
        assert!(permis(S_IFREG, 1000, 1000, Identite::ROOT, LIRE | ECRIRE));
        assert!(!permis(S_IFREG | 0o666, 1000, 1000, Identite::ROOT, EXECUTER));
        assert!(permis(S_IFREG | 0o100, 1000, 1000, Identite::ROOT, EXECUTER));
        assert!(permis(S_IFDIR, 1000, 1000, Identite::ROOT, EXECUTER | ECRIRE));
    }
}
