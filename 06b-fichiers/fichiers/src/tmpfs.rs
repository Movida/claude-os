//! Le système de fichiers en mémoire : le tmpfs de Linux (mm/shmem.c), où
//! Linux déballe l'initramfs au démarrage (le rootfs), et qui sert aussi
//! /tmp et /dev/shm. Tout y est en mémoire : l'arborescence, et les pages
//! des fichiers (il n'y a pas de disque derrière, ces pages SONT les
//! données).
//!
//! Les objets :
//!   - un INODE par fichier, dossier, lien symbolique ou périphérique : son
//!     type et ses droits (le mode), son propriétaire, ses horodatages, sa
//!     taille, son contenu, et deux compteurs, comme dans Linux : `nlink`,
//!     le nombre de noms qui le désignent (ses entrées dans des dossiers),
//!     et `refs` (le `i_count`), le nombre de choses qui le tiennent sans
//!     nom (un fichier ouvert, une projection, un dossier courant, un
//!     programme en cours). Un inode vit tant que l'un des deux n'est pas
//!     nul : un fichier effacé mais encore ouvert se lit toujours, et
//!     disparaît à la dernière fermeture ;
//!   - un DOSSIER est une liste d'entrées (un nom, un inode). Pas d'entrées
//!     « . » et « .. » : `lire_dossier` les donne d'abord, et le dossier
//!     connaît son parent.
//!
//! Les inodes sont rangés dans une table à deux niveaux : des blocs d'une
//! page (un peu plus d'une vingtaine d'inodes), pris un à un. Le numéro
//! d'inode est le rang dans la table plus 1 (la racine est le 1). Options
//! écartées :
//!   - une table d'un seul tenant : un bloc du tas du noyau fait au plus 4
//!     Mio, soit 40 000 inodes, quand la limite de tmpfs (la moitié des
//!     pages de la machine) en permet 260 000 sur 2 Gio ;
//!   - des `Rc` ou des `Box` par inode, comme les pointeurs de Linux : leur
//!     allocation ne sait pas échouer, et une allocation demandée par un
//!     programme doit pouvoir rendre ENOMEM. Les numéros font aussi des
//!     poignées que le noyau peut garder sans emprunt : une poignée tient
//!     une référence (`refs`), l'inode ne peut donc pas disparaître sous
//!     elle, et un numéro n'est réutilisé qu'après la fin de l'inode (pas
//!     besoin de « génération »).
//!
//! Les entrées d'un dossier sont rangées dans l'ordre de création, chacune
//! avec un « cookie » croissant, et lues du plus récent au plus ancien :
//! c'est l'ordre de tmpfs depuis Linux 6.14 (mesuré sur 6.18 : a, b, c, d
//! créés, b effacé, e créé, `readdir` donne . .. e d c a). La position de
//! `readdir` est le cookie de la dernière entrée lue : elle reste juste
//! quand des entrées disparaissent pendant la lecture (POSIX interdit alors
//! de sauter ou de répéter une autre entrée), ce que ne ferait pas un rang
//! dans la liste. Un nom se cherche en parcourant la liste : quelques
//! centaines d'entrées au plus (/etc/ssl/certs) ; Linux a une table de
//! hachage (le dcache), on en mettra une si une mesure le demande.
//!
//! Les opérations prennent un `Fin` (ce que rend la résolution des
//! chemins, chemins.rs) et font les vérifications de Linux, dans son ordre
//! (fs/namei.c : `may_create`, `may_delete`, `do_renameat2`,
//! `do_linkat`, `do_open`...), avec ses codes d'erreur : les programmes de
//! test les comparent au vrai Linux. Chacune est tout ou rien.
//!
//! Les pages : le tmpfs ne sait pas ce qu'est une page de mémoire. Le
//! propriétaire (le noyau, ou les tests) les fournit par le trait `Cadres`
//! ; l'index de chaque fichier (index.rs) range leurs numéros. Une règle
//! tient toujours : au-delà de la taille du fichier, la dernière page ne
//! contient que des zéros. Sans elle, raccourcir un fichier puis le
//! rallonger ferait réapparaître ses anciens octets.

use crate::chemins::{Arbre, Dernier, Fin, PATH_MAX};
use crate::index::{ErreurIndex, INDEX_MAX, IndexPages};
use crate::{
    ECRIRE, EXECUTER, Erreur, Identite, LIRE, PAGE, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, S_ISGID, S_ISUID,
    S_ISVTX, Temps, permis,
};
use alloc::vec::Vec;

/// Ce qui fournit les pages des fichiers : le noyau (des cadres de la
/// mémoire physique), ou les tests (des tableaux). Une page est désignée
/// par un nombre non nul.
pub trait Cadres {
    /// Une page neuve, à zéro ; `None` s'il n'y a plus de mémoire.
    fn allouer(&mut self) -> Option<u64>;
    /// Le système de fichiers ne se sert plus de cette page.
    fn lacher(&mut self, page: u64);
    /// Écrit `octets` dans la page, à partir de l'octet `decalage`.
    fn ecrire(&mut self, page: u64, decalage: usize, octets: &[u8]);
    /// Lit la page, à partir de l'octet `decalage`.
    fn lire(&self, page: u64, decalage: usize, tampon: &mut [u8]);
    /// Met à zéro les octets [debut, fin[ de la page.
    fn effacer(&mut self, page: u64, debut: usize, fin: usize) {
        const ZEROS: [u8; PAGE as usize] = [0; PAGE as usize];
        self.ecrire(page, debut, &ZEROS[..fin - debut]);
    }
}

/// Un numéro d'inode (1 : la racine).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Numero(pub u32);

/// Les limites du système de fichiers : au-delà, ENOSPC. Celles de tmpfs
/// par défaut : la moitié des pages de la machine, et autant d'inodes.
#[derive(Clone, Copy, Debug)]
pub struct Limites {
    pub inodes: u32,
    pub pages: u64,
}

/// La plus grande taille de fichier (MAX_LFS_FILESIZE de Linux).
pub const TAILLE_MAX: u64 = i64::MAX as u64;

/// Ce que dit `stat` d'un inode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributs {
    pub numero: Numero,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Majeur et mineur d'un périphérique.
    pub rdev: (u32, u32),
    pub taille: u64,
    /// La place occupée, en blocs de 512 octets (st_blocks).
    pub blocs: u64,
    pub atime: Temps,
    pub mtime: Temps,
    pub ctime: Temps,
}

/// Comment ouvrir un fichier (les drapeaux d'open qui regardent le
/// système de fichiers ; le noyau garde les autres).
#[derive(Clone, Copy, Debug, Default)]
pub struct Ouverture {
    pub lecture: bool,
    pub ecriture: bool,
    /// O_CREAT, avec les droits `mode` (umask déjà appliqué).
    pub creer: bool,
    pub mode: u32,
    /// O_EXCL
    pub exclusif: bool,
    /// O_TRUNC
    pub tronquer: bool,
    /// O_DIRECTORY
    pub dossier: bool,
    /// O_PATH : ni lecture ni écriture, aucun droit vérifié sur l'objet.
    pub chemin_seul: bool,
}

/// Ce qu'a fait `ouvrir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ouvert {
    pub numero: Numero,
    /// Le fichier vient d'être créé.
    pub cree: bool,
    /// Le noyau doit le ramener à une taille nulle (O_TRUNC) : c'est lui
    /// qui sait retirer d'abord les pages projetées par les programmes.
    pub tronquer: bool,
    /// L'ouverture compte parmi les écrivains du fichier (à rendre à la
    /// fermeture : voir `fermer`).
    pub ecrivain: bool,
}

/// Combien des `longueur` octets à écrire à `position` peuvent l'être : on
/// s'arrête à la plus grande taille de fichier, et on ne peut rien écrire
/// à partir d'elle (EFBIG), comme `generic_write_check_limits`.
pub fn limite_ecriture(position: u64, longueur: usize) -> Result<usize, Erreur> {
    if position >= TAILLE_MAX && longueur > 0 {
        return Err(Erreur::EFBIG);
    }
    Ok((longueur as u64).min(TAILLE_MAX.saturating_sub(position)) as usize)
}

/// Un horodatage à poser (utimensat).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Horodatage {
    /// UTIME_OMIT
    Garder,
    /// UTIME_NOW
    Maintenant,
    Valeur(Temps),
}

// Les drapeaux de renameat2.
pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;

/// Les drapeaux de renameat2 : inconnus, ou EXCHANGE avec NOREPLACE ou
/// WHITEOUT, EINVAL. Linux le vérifie avant même de résoudre les chemins
/// (`do_renameat2`) : le noyau l'appelle donc en premier ; `renommer` le
/// refait, pour qui l'appelle directement.
pub fn verifier_renommage(drapeaux: u32) -> Result<(), Erreur> {
    if drapeaux & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        || (drapeaux & RENAME_EXCHANGE != 0 && drapeaux & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0)
    {
        return Err(Erreur::EINVAL);
    }
    Ok(())
}

// Les types des entrées de dossier (d_type, include/linux/fs_types.h).
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

/// La taille d'un dossier : tmpfs compte 20 octets par entrée (son
/// BOGO_DIRENT_SIZE), « . » et « .. » compris. Linux le fait pour que des
/// programmes qui regardent st_size d'un dossier vide (des outils de
/// sauvegarde) voient autre chose que 0.
const TAILLE_ENTREE: u64 = 20;

/// Une entrée de dossier.
struct Entree {
    nom: Vec<u8>,
    numero: Numero,
    cookie: u64,
}

struct Dossier {
    /// Dans l'ordre de création (les cookies croissent).
    entrees: Vec<Entree>,
    /// Le cookie de la prochaine entrée. Les positions 0, 1 et 2 de
    /// `lire_dossier` sont « avant . », « avant .. » et « avant la plus
    /// récente » : les cookies commencent à 3.
    prochain: u64,
    /// Le dossier parent. Un dossier effacé (encore tenu, par exemple comme
    /// dossier courant) devient son propre parent : « .. » y reste (Linux,
    /// lui, remonte encore à l'ancien parent ; il faudrait tenir une
    /// référence au parent jusqu'à la fin du dossier, pour un cas sans
    /// usage).
    parent: Numero,
}

enum Contenu {
    Fichier(IndexPages),
    Dossier(Dossier),
    Lien(Vec<u8>),
    /// Un périphérique : le noyau sait ce qu'il fait.
    Rien,
}

struct Inode {
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    refs: u32,
    /// Le compteur d'écrivains (le `i_writecount` de Linux) : positif, le
    /// nombre d'ouvertures en écriture ; négatif, le nombre de programmes
    /// en cours qui l'exécutent (personne ne peut alors l'écrire : ETXTBSY).
    ecrivains: i32,
    taille: u64,
    rdev: (u32, u32),
    atime: Temps,
    mtime: Temps,
    ctime: Temps,
    contenu: Contenu,
}

impl Inode {
    fn genre(&self) -> u32 {
        self.mode & S_IFMT
    }

    fn est_dossier(&self) -> bool {
        self.genre() == S_IFDIR
    }

    fn dossier(&self) -> &Dossier {
        match &self.contenu {
            Contenu::Dossier(d) => d,
            _ => panic!("tmpfs : un dossier attendu"),
        }
    }

    fn dossier_mut(&mut self) -> &mut Dossier {
        match &mut self.contenu {
            Contenu::Dossier(d) => d,
            _ => panic!("tmpfs : un dossier attendu"),
        }
    }

    fn permis(&self, qui: Identite, masque: u32) -> bool {
        permis(self.mode, self.uid, self.gid, qui, masque)
    }
}

/// Un bloc de la table des inodes : autant d'inodes qu'il en tient dans une
/// page.
struct Bloc {
    cases: Vec<Option<Inode>>,
    prises: usize,
}

const PAR_BLOC: usize = {
    let n = 4096 / core::mem::size_of::<Option<Inode>>();
    if n == 0 { 1 } else { n }
};

/// Un système de fichiers en mémoire.
pub struct Tmpfs {
    blocs: Vec<Bloc>,
    /// Le premier bloc qui a peut-être une case libre.
    non_plein: usize,
    inodes: u32,
    pages: u64,
    limites: Limites,
}

fn reserver<T>(v: &mut Vec<T>, n: usize) -> Result<(), Erreur> {
    v.try_reserve(n).map_err(|_| Erreur::ENOMEM)
}

fn copie(octets: &[u8]) -> Result<Vec<u8>, Erreur> {
    let mut v = Vec::new();
    v.try_reserve_exact(octets.len()).map_err(|_| Erreur::ENOMEM)?;
    v.extend_from_slice(octets);
    Ok(v)
}

impl Tmpfs {
    /// Un système de fichiers vide : sa racine seule, à root, en 0755. La
    /// table des blocs d'inodes est réservée tout de suite pour la limite
    /// entière (quelques dizaines d'octets par bloc) : elle ne grandira
    /// jamais, et un programme qui crée puis efface des fichiers laisse la
    /// mémoire exactement comme il l'a trouvée.
    pub fn new(limites: Limites, maintenant: Temps) -> Result<Tmpfs, Erreur> {
        let mut blocs = Vec::new();
        blocs.try_reserve_exact((limites.inodes as usize).div_ceil(PAR_BLOC)).map_err(|_| Erreur::ENOMEM)?;
        let mut fs = Tmpfs { blocs, non_plein: 0, inodes: 0, pages: 0, limites };
        let dossier = Dossier { entrees: Vec::new(), prochain: 3, parent: Numero(1) };
        let racine = fs.nouvel_inode(Identite::ROOT, S_IFDIR | 0o755, Contenu::Dossier(dossier), maintenant)?;
        debug_assert_eq!(racine, Numero(1));
        let r = fs.inode_mut(racine);
        r.nlink = 2;
        r.taille = 2 * TAILLE_ENTREE;
        // La racine est tenue par le montage : elle ne disparaît jamais.
        r.refs = 1;
        Ok(fs)
    }

    pub fn racine(&self) -> Numero {
        Numero(1)
    }

    /// Le nombre d'inodes et de pages occupés.
    pub fn occupation(&self) -> (u32, u64) {
        (self.inodes, self.pages)
    }

    pub fn limites(&self) -> Limites {
        self.limites
    }

    fn case(&self, n: Numero) -> Option<&Inode> {
        let i = n.0.checked_sub(1)? as usize;
        self.blocs.get(i / PAR_BLOC)?.cases[i % PAR_BLOC].as_ref()
    }

    fn inode(&self, n: Numero) -> &Inode {
        self.case(n).expect("tmpfs : numero d'inode sans inode")
    }

    fn inode_mut(&mut self, n: Numero) -> &mut Inode {
        let i = n.0 as usize - 1;
        self.blocs[i / PAR_BLOC].cases[i % PAR_BLOC].as_mut().expect("tmpfs : numero d'inode sans inode")
    }

    /// L'inode `n` existe-t-il ? (Pour le noyau, qui reçoit un numéro de
    /// l'archive, par exemple.)
    pub fn existe(&self, n: Numero) -> bool {
        self.case(n).is_some()
    }

    /// Range un inode neuf (nlink 0, refs 0) dans la première case libre.
    /// Seule allocation possible : un bloc neuf, dans une table déjà
    /// réservée.
    fn nouvel_inode(&mut self, qui: Identite, mode: u32, contenu: Contenu, maintenant: Temps) -> Result<Numero, Erreur> {
        if self.inodes >= self.limites.inodes {
            return Err(Erreur::ENOSPC);
        }
        let inode = Inode {
            mode,
            uid: qui.uid,
            gid: qui.gid,
            nlink: 0,
            refs: 0,
            ecrivains: 0,
            taille: 0,
            rdev: (0, 0),
            atime: maintenant,
            mtime: maintenant,
            ctime: maintenant,
            contenu,
        };
        while self.non_plein < self.blocs.len() && self.blocs[self.non_plein].prises == PAR_BLOC {
            self.non_plein += 1;
        }
        if self.non_plein == self.blocs.len() {
            let mut cases = Vec::new();
            cases.try_reserve_exact(PAR_BLOC).map_err(|_| Erreur::ENOMEM)?;
            cases.resize_with(PAR_BLOC, || None);
            reserver(&mut self.blocs, 1)?;
            self.blocs.push(Bloc { cases, prises: 0 });
        }
        let b = self.non_plein;
        let bloc = &mut self.blocs[b];
        let c = bloc.cases.iter().position(Option::is_none).expect("un bloc non plein a une case libre");
        bloc.cases[c] = Some(inode);
        bloc.prises += 1;
        self.inodes += 1;
        Ok(Numero((b * PAR_BLOC + c + 1) as u32))
    }

    /// La fin d'un inode : ses pages sont rendues, sa case libérée, et les
    /// blocs vides en fin de table rendus.
    fn detruire(&mut self, n: Numero, cadres: &mut impl Cadres) {
        let i = n.0 as usize - 1;
        let (b, c) = (i / PAR_BLOC, i % PAR_BLOC);
        let inode = self.blocs[b].cases[c].take().expect("tmpfs : inode deja detruit");
        self.blocs[b].prises -= 1;
        self.inodes -= 1;
        self.non_plein = self.non_plein.min(b);
        if let Contenu::Fichier(mut index) = inode.contenu {
            self.pages -= index.pages();
            index.retirer_depuis(0, |p| cadres.lacher(p));
        }
        while self.blocs.last().is_some_and(|b| b.prises == 0) {
            self.blocs.pop();
        }
    }

    // ----- Ce que voit la résolution des chemins (et `stat`) -----

    /// Les attributs de l'inode (stat).
    pub fn attributs(&self, n: Numero) -> Attributs {
        let i = self.inode(n);
        // Un lien de plus de 128 octets (SHORT_SYMLINK_LEN) : tmpfs range sa
        // cible dans une page, que stat compte. Nous la gardons dans le tas
        // du noyau, mais montrons ce que montre Linux.
        let blocs = match &i.contenu {
            Contenu::Fichier(index) => index.pages() * (PAGE / 512),
            Contenu::Lien(cible) if cible.len() > 128 => PAGE / 512,
            _ => 0,
        };
        Attributs {
            numero: n,
            mode: i.mode,
            nlink: i.nlink,
            uid: i.uid,
            gid: i.gid,
            rdev: i.rdev,
            taille: i.taille,
            blocs,
            atime: i.atime,
            mtime: i.mtime,
            ctime: i.ctime,
        }
    }

    /// Le mode de l'inode (type et droits).
    pub fn mode(&self, n: Numero) -> u32 {
        self.inode(n).mode
    }

    fn est_dossier(&self, n: Numero) -> bool {
        self.inode(n).est_dossier()
    }

    /// `access` : `qui` a-t-il les droits `masque` (LIRE, ECRIRE, EXECUTER
    /// ; 0 : seulement l'existence) ?
    pub fn acces(&self, qui: Identite, n: Numero, masque: u32) -> Result<(), Erreur> {
        if self.inode(n).permis(qui, masque) { Ok(()) } else { Err(Erreur::EACCES) }
    }

    // ----- Créer -----

    /// Peut-on créer une entrée dans le dossier `dossier` (le `may_create`
    /// de Linux) ? Pas dans un dossier effacé (ENOENT), et il faut le droit
    /// d'y écrire et de le traverser (EACCES).
    fn peut_creer(&self, qui: Identite, dossier: Numero) -> Result<(), Erreur> {
        let d = self.inode(dossier);
        if d.nlink == 0 {
            return Err(Erreur::ENOENT);
        }
        if !d.permis(qui, ECRIRE | EXECUTER) {
            return Err(Erreur::EACCES);
        }
        Ok(())
    }

    /// Crée un fichier, un dossier, un lien symbolique (de contenu `cible`)
    /// ou un périphérique (`rdev`), de type et de droits `mode` (umask déjà
    /// appliqué), au dernier composant de `fin` : open avec O_CREAT, mkdir,
    /// symlink, mknod. Les vérifications de `filename_create`, puis de
    /// `vfs_mkdir`, `vfs_symlink`, `vfs_mknod` :
    ///   - un lien vide (ENOENT) ou trop long (ENAMETOOLONG) : Linux le voit
    ///     en copiant la cible (`getname`), avant tout le reste ;
    ///   - pas un nom ordinaire (« . », « .. », la racine), ou un nom qui
    ///     existe : EEXIST ;
    ///   - une barre finale pour autre chose qu'un dossier : ENOENT ;
    ///   - dossier effacé (ENOENT), pas le droit d'y écrire (EACCES) ;
    ///   - un périphérique, sans être root : EPERM ;
    ///   - plus d'inode (ENOSPC), plus de mémoire (ENOMEM).
    /// Le nouvel inode appartient à `qui` ; son groupe est celui du dossier
    /// si le dossier a le bit S_ISGID (et un sous-dossier en hérite), comme
    /// Linux. Un fichier créé là, setgid et exécutable par le groupe, par
    /// quelqu'un qui n'est pas de ce groupe (ni root), perd son S_ISGID
    /// (`mode_strip_sgid`) : sans cela, on fabriquerait un exécutable
    /// setgid d'un groupe dont on n'est pas (la faille CVE-2018-13405).
    pub fn creer(&mut self, qui: Identite, fin: &Fin<Numero>, mode: u32, rdev: (u32, u32), cible: &[u8], maintenant: Temps)
        -> Result<Numero, Erreur> {
        let genre = mode & S_IFMT;
        if genre == S_IFLNK {
            if cible.is_empty() {
                return Err(Erreur::ENOENT);
            }
            if cible.len() >= PATH_MAX {
                return Err(Erreur::ENAMETOOLONG);
            }
        }
        if fin.dernier != Dernier::Nom || fin.objet.is_some() {
            return Err(Erreur::EEXIST);
        }
        if fin.barre && genre != S_IFDIR {
            return Err(Erreur::ENOENT);
        }
        self.peut_creer(qui, fin.dossier)?;
        let contenu = match genre {
            S_IFREG => Contenu::Fichier(IndexPages::new()),
            S_IFDIR => {
                if self.inode(fin.dossier).nlink == u32::MAX {
                    return Err(Erreur::EMLINK);
                }
                Contenu::Dossier(Dossier { entrees: Vec::new(), prochain: 3, parent: fin.dossier })
            }
            S_IFLNK => Contenu::Lien(copie(cible)?),
            S_IFCHR if !qui.root() => return Err(Erreur::EPERM),
            S_IFCHR => Contenu::Rien,
            _ => return Err(Erreur::EINVAL),
        };
        let parent = self.inode(fin.dossier);
        let herite = parent.mode & S_ISGID != 0;
        let gid = if herite { parent.gid } else { qui.gid };
        let mode = if herite && genre == S_IFDIR {
            mode | S_ISGID
        } else if herite && mode & (S_ISGID | 0o010) == S_ISGID | 0o010 && !qui.root() && qui.gid != gid {
            mode & !S_ISGID
        } else {
            mode
        };
        // La place de l'entrée, puis l'inode (la seule chose qui peut encore
        // échouer, et en dernier).
        let nom = copie(&fin.nom)?;
        reserver(&mut self.inode_mut(fin.dossier).dossier_mut().entrees, 1)?;
        let n = self.nouvel_inode(Identite { uid: qui.uid, gid }, mode & (S_IFMT | 0o7777), contenu, maintenant)?;
        let i = self.inode_mut(n);
        i.nlink = if genre == S_IFDIR { 2 } else { 1 };
        i.rdev = rdev;
        i.taille = match genre {
            S_IFDIR => 2 * TAILLE_ENTREE,
            S_IFLNK => cible.len() as u64,
            _ => 0,
        };
        self.ajouter_entree(fin.dossier, nom, n, maintenant);
        if genre == S_IFDIR {
            self.inode_mut(fin.dossier).nlink += 1;
        }
        Ok(n)
    }

    /// Ajoute l'entrée (place déjà réservée).
    fn ajouter_entree(&mut self, dossier: Numero, nom: Vec<u8>, numero: Numero, maintenant: Temps) {
        let d = self.inode_mut(dossier);
        d.taille += TAILLE_ENTREE;
        d.mtime = maintenant;
        d.ctime = maintenant;
        let d = d.dossier_mut();
        let cookie = d.prochain;
        d.prochain += 1;
        d.entrees.push(Entree { nom, numero, cookie });
    }

    /// Retire l'entrée `nom` du dossier. Avec `rendre`, un dossier vidé rend
    /// sa liste (sans, sa place reste pour une entrée qu'on va ajouter).
    fn retirer_entree(&mut self, dossier: Numero, nom: &[u8], rendre: bool, maintenant: Temps) {
        let d = self.inode_mut(dossier);
        d.taille -= TAILLE_ENTREE;
        d.mtime = maintenant;
        d.ctime = maintenant;
        let entrees = &mut d.dossier_mut().entrees;
        let i = entrees.iter().position(|e| e.nom == nom).expect("tmpfs : entree introuvable");
        entrees.remove(i);
        if rendre && entrees.is_empty() {
            *entrees = Vec::new();
        }
    }

    // ----- Effacer -----

    /// Peut-on effacer `victime` du dossier `dossier` (le `may_delete` de
    /// Linux) ? Le droit d'écrire dans le dossier et de le traverser
    /// (EACCES) ; dans un dossier « sticky » (/tmp), seul le propriétaire
    /// du fichier ou du dossier (ou root) le peut (EPERM) ; puis le type :
    /// `dossier` attendu et ce n'en est pas un (ENOTDIR), ou l'inverse
    /// (EISDIR).
    fn peut_effacer(&self, qui: Identite, dossier: Numero, victime: Numero, dossier_attendu: bool) -> Result<(), Erreur> {
        let d = self.inode(dossier);
        let v = self.inode(victime);
        if !d.permis(qui, ECRIRE | EXECUTER) {
            return Err(Erreur::EACCES);
        }
        if d.mode & S_ISVTX != 0 && !qui.root() && qui.uid != v.uid && qui.uid != d.uid {
            return Err(Erreur::EPERM);
        }
        match (dossier_attendu, v.est_dossier()) {
            (true, false) => Err(Erreur::ENOTDIR),
            (false, true) => Err(Erreur::EISDIR),
            _ => Ok(()),
        }
    }

    fn vide(&self, dossier: Numero) -> bool {
        self.inode(dossier).dossier().entrees.is_empty()
    }

    /// Un nom de moins pour `victime`, qu'on vient de retirer du dossier
    /// `dossier` : un dossier perd ses deux liens (son nom et son « . ») et
    /// son parent un (son « .. »). L'inode disparaît s'il n'a plus ni nom ni
    /// référence.
    fn oublier_nom(&mut self, victime: Numero, dossier: Numero, maintenant: Temps, cadres: &mut impl Cadres) {
        let v = self.inode_mut(victime);
        v.ctime = maintenant;
        if v.est_dossier() {
            v.nlink = 0;
            v.dossier_mut().parent = victime;
            self.inode_mut(dossier).nlink -= 1;
        } else {
            v.nlink -= 1;
        }
        let v = self.inode(victime);
        if v.nlink == 0 && v.refs == 0 {
            self.detruire(victime, cadres);
        }
    }

    /// Efface le dernier composant de `fin` : unlink (`dossier` faux) ou
    /// rmdir. Dans l'ordre de `do_unlinkat` et `do_rmdir` :
    ///   - unlink de « . », « .. » ou de la racine : EISDIR ; rmdir de « . » :
    ///     EINVAL, de « .. » : ENOTEMPTY, de la racine : EBUSY ;
    ///   - rien à ce nom : ENOENT ;
    ///   - unlink avec une barre finale : EISDIR pour un dossier, ENOTDIR
    ///     sinon ;
    ///   - les droits et le type (`peut_effacer`) ;
    ///   - rmdir d'un dossier qui n'est pas vide : ENOTEMPTY.
    pub fn effacer(&mut self, qui: Identite, fin: &Fin<Numero>, dossier: bool, maintenant: Temps, cadres: &mut impl Cadres)
        -> Result<(), Erreur> {
        match (fin.dernier, dossier) {
            (Dernier::Nom, _) => {}
            (_, false) => return Err(Erreur::EISDIR),
            (Dernier::Point, true) => return Err(Erreur::EINVAL),
            (Dernier::PointPoint, true) => return Err(Erreur::ENOTEMPTY),
            (Dernier::Racine, true) => return Err(Erreur::EBUSY),
        }
        let victime = fin.objet.ok_or(Erreur::ENOENT)?;
        if !dossier && fin.barre {
            return Err(if self.est_dossier(victime) { Erreur::EISDIR } else { Erreur::ENOTDIR });
        }
        self.peut_effacer(qui, fin.dossier, victime, dossier)?;
        if dossier && !self.vide(victime) {
            return Err(Erreur::ENOTEMPTY);
        }
        self.retirer_entree(fin.dossier, &fin.nom, true, maintenant);
        self.oublier_nom(victime, fin.dossier, maintenant, cadres);
        Ok(())
    }

    // ----- Renommer -----

    /// `a` est-il `b`, ou un de ses ancêtres ?
    fn ancetre(&self, a: Numero, mut b: Numero) -> bool {
        loop {
            if a == b {
                return true;
            }
            let parent = self.inode(b).dossier().parent;
            if parent == b {
                return false;
            }
            b = parent;
        }
    }

    /// Renomme le dernier composant de `ancien` en celui de `nouveau`
    /// (renameat2, avec RENAME_NOREPLACE ou RENAME_EXCHANGE). Les
    /// vérifications de `do_renameat2` puis de `vfs_rename`, dans leur
    /// ordre :
    ///   - les drapeaux (`verifier_renommage`) : EINVAL ; RENAME_WHITEOUT
    ///     (laisser à l'ancien nom une entrée spéciale, qui masque un fichier
    ///     des couches du dessous d'overlayfs) : EINVAL, la réponse d'un
    ///     système de fichiers qui ne le connaît pas. Le tmpfs de Linux sait
    ///     le faire (et sans être root depuis 5.8) ; nous n'avons pas
    ///     d'overlayfs pour s'en servir ;
    ///   - un des deux n'est pas un nom ordinaire : EBUSY (EEXIST pour le
    ///     nouveau avec NOREPLACE) ;
    ///   - pas d'ancien : ENOENT ; un nouveau avec NOREPLACE : EEXIST ; pas
    ///     de nouveau avec EXCHANGE : ENOENT ;
    ///   - une barre finale sur ce qui n'est pas un dossier : ENOTDIR ;
    ///   - l'ancien est un ancêtre du nouveau (un dossier dans son propre
    ///     sous-arbre) : EINVAL ; le nouveau est un ancêtre de l'ancien :
    ///     ENOTEMPTY (EINVAL avec EXCHANGE) ;
    ///   - le même inode des deux côtés (deux liens physiques) : rien à
    ///     faire, succès ;
    ///   - effacer l'ancien (`peut_effacer`), et effacer le nouveau s'il
    ///     existe, sinon créer (`peut_creer`) : les types doivent
    ///     s'accorder (dossier sur fichier : ENOTDIR ; fichier sur dossier :
    ///     EISDIR) ;
    ///   - un dossier qui change de parent doit être inscriptible (son
    ///     « .. » change) : EACCES ;
    ///   - un dossier non vide à écraser : ENOTEMPTY ; trop de liens dans le
    ///     nouveau parent : EMLINK.
    /// L'entrée renommée prend un cookie neuf dans son nouveau dossier
    /// (comme `simple_offset_rename` de Linux) ; l'inode écrasé perd un
    /// nom.
    pub fn renommer(&mut self, qui: Identite, ancien: &Fin<Numero>, nouveau: &Fin<Numero>, drapeaux: u32, maintenant: Temps,
                    cadres: &mut impl Cadres) -> Result<(), Erreur> {
        verifier_renommage(drapeaux)?;
        if drapeaux & RENAME_WHITEOUT != 0 {
            return Err(Erreur::EINVAL);
        }
        let echange = drapeaux & RENAME_EXCHANGE != 0;
        let sans_ecraser = drapeaux & RENAME_NOREPLACE != 0;
        if ancien.dernier != Dernier::Nom {
            return Err(Erreur::EBUSY);
        }
        if nouveau.dernier != Dernier::Nom {
            return Err(if sans_ecraser { Erreur::EEXIST } else { Erreur::EBUSY });
        }
        let source = ancien.objet.ok_or(Erreur::ENOENT)?;
        let cible = nouveau.objet;
        if sans_ecraser && cible.is_some() {
            return Err(Erreur::EEXIST);
        }
        if echange {
            let c = cible.ok_or(Erreur::ENOENT)?;
            if !self.est_dossier(c) && nouveau.barre {
                return Err(Erreur::ENOTDIR);
            }
        }
        let dossier_source = self.est_dossier(source);
        if !dossier_source && (ancien.barre || (!echange && nouveau.barre)) {
            return Err(Erreur::ENOTDIR);
        }
        if dossier_source && self.ancetre(source, nouveau.dossier) {
            return Err(Erreur::EINVAL);
        }
        if let Some(c) = cible
            && self.est_dossier(c)
            && self.ancetre(c, ancien.dossier)
        {
            return Err(if echange { Erreur::EINVAL } else { Erreur::ENOTEMPTY });
        }
        if Some(source) == cible {
            return Ok(());
        }
        self.peut_effacer(qui, ancien.dossier, source, dossier_source)?;
        match cible {
            Some(c) => {
                let attendu = if echange { self.est_dossier(c) } else { dossier_source };
                self.peut_effacer(qui, nouveau.dossier, c, attendu)?;
            }
            None => self.peut_creer(qui, nouveau.dossier)?,
        }
        let deplace = ancien.dossier != nouveau.dossier;
        if deplace && dossier_source && !self.inode(source).permis(qui, ECRIRE) {
            return Err(Erreur::EACCES);
        }
        if let Some(c) = cible.filter(|_| echange)
            && deplace
            && self.est_dossier(c)
            && !self.inode(c).permis(qui, ECRIRE)
        {
            return Err(Erreur::EACCES);
        }
        if echange {
            self.echanger(ancien, nouveau, source, cible.expect("verifie plus haut"), maintenant);
            return Ok(());
        }
        if let Some(c) = cible
            && self.est_dossier(c)
            && !self.vide(c)
        {
            return Err(Erreur::ENOTEMPTY);
        }
        let ecrase_dossier = cible.is_some_and(|c| self.est_dossier(c));
        if deplace && dossier_source && !ecrase_dossier && self.inode(nouveau.dossier).nlink == u32::MAX {
            return Err(Erreur::EMLINK);
        }
        // La mémoire d'abord : le nom, et la place de l'entrée s'il n'y a
        // rien à écraser (sinon on prend celle de l'écrasée).
        let nom = copie(&nouveau.nom)?;
        if cible.is_none() {
            reserver(&mut self.inode_mut(nouveau.dossier).dossier_mut().entrees, 1)?;
        }
        // L'écrasée d'abord (sa place servira), la nouvelle entrée ensuite,
        // l'ancienne en dernier : dans le même dossier, la retirer avant
        // d'ajouter pourrait rendre la liste qu'on allait remplir.
        if let Some(c) = cible {
            self.retirer_entree(nouveau.dossier, &nouveau.nom, false, maintenant);
            self.oublier_nom(c, nouveau.dossier, maintenant, cadres);
        }
        self.ajouter_entree(nouveau.dossier, nom, source, maintenant);
        self.retirer_entree(ancien.dossier, &ancien.nom, true, maintenant);
        self.inode_mut(source).ctime = maintenant;
        if deplace && dossier_source {
            self.inode_mut(source).dossier_mut().parent = nouveau.dossier;
            self.inode_mut(ancien.dossier).nlink -= 1;
            self.inode_mut(nouveau.dossier).nlink += 1;
        }
        Ok(())
    }

    /// RENAME_EXCHANGE : les deux entrées échangent leurs inodes.
    fn echanger(&mut self, ancien: &Fin<Numero>, nouveau: &Fin<Numero>, source: Numero, cible: Numero, maintenant: Temps) {
        for (dossier, nom, numero) in [(ancien.dossier, &ancien.nom, cible), (nouveau.dossier, &nouveau.nom, source)] {
            let d = self.inode_mut(dossier);
            d.mtime = maintenant;
            d.ctime = maintenant;
            let e = d.dossier_mut().entrees.iter_mut().find(|e| e.nom == *nom).expect("tmpfs : entree introuvable");
            e.numero = numero;
        }
        for n in [source, cible] {
            self.inode_mut(n).ctime = maintenant;
        }
        if ancien.dossier != nouveau.dossier {
            for (n, vers, depuis) in [(source, nouveau.dossier, ancien.dossier), (cible, ancien.dossier, nouveau.dossier)] {
                if self.est_dossier(n) {
                    self.inode_mut(n).dossier_mut().parent = vers;
                    self.inode_mut(depuis).nlink -= 1;
                    self.inode_mut(vers).nlink += 1;
                }
            }
        }
    }

    // ----- Liens physiques et symboliques -----

    /// Un nom de plus pour `source`, au dernier composant de `nouveau`
    /// (link). Dans l'ordre de `do_linkat` et `vfs_link` :
    ///   - nom pas ordinaire, ou qui existe : EEXIST ; barre finale : ENOENT
    ///     ;
    ///   - `protected_hardlinks` : sans être son propriétaire (ni root), on
    ///     ne lie qu'un fichier ordinaire, sans setuid ni setgid exécutable,
    ///     qu'on peut lire et écrire : sinon EPERM. Le noyau Linux le laisse
    ///     à 0, mais systemd le met à 1 (sysctl.d/50-default.conf) : c'est
    ///     ce que voit tout Linux de bureau ou de serveur. Ses voisins posés
    ///     par le même fichier (`protected_symlinks`, `protected_regular`,
    ///     qui protègent les dossiers comme /tmp contre les liens et les
    ///     fichiers piégés d'un autre) ne sont pas suivis : sans plusieurs
    ///     utilisateurs, ils ne protègent encore de rien ;
    ///   - les droits sur le dossier (`peut_creer`) ;
    ///   - un dossier : EPERM ; un inode qui n'a plus de nom : ENOENT ; trop
    ///     de liens : EMLINK.
    pub fn lier(&mut self, qui: Identite, source: Numero, nouveau: &Fin<Numero>, maintenant: Temps) -> Result<(), Erreur> {
        if nouveau.dernier != Dernier::Nom || nouveau.objet.is_some() {
            return Err(Erreur::EEXIST);
        }
        if nouveau.barre {
            return Err(Erreur::ENOENT);
        }
        let s = self.inode(source);
        if !qui.root() && qui.uid != s.uid {
            let setgid_exec = s.mode & S_ISGID != 0 && s.mode & 0o010 != 0;
            if s.genre() != S_IFREG || s.mode & S_ISUID != 0 || setgid_exec || !s.permis(qui, LIRE | ECRIRE) {
                return Err(Erreur::EPERM);
            }
        }
        self.peut_creer(qui, nouveau.dossier)?;
        let s = self.inode(source);
        if s.est_dossier() {
            return Err(Erreur::EPERM);
        }
        if s.nlink == 0 {
            return Err(Erreur::ENOENT);
        }
        if s.nlink == u32::MAX {
            return Err(Erreur::EMLINK);
        }
        let nom = copie(&nouveau.nom)?;
        reserver(&mut self.inode_mut(nouveau.dossier).dossier_mut().entrees, 1)?;
        self.ajouter_entree(nouveau.dossier, nom, source, maintenant);
        let s = self.inode_mut(source);
        s.nlink += 1;
        s.ctime = maintenant;
        Ok(())
    }

    /// Le contenu du lien symbolique `n` (readlink) ; EINVAL si ce n'en est
    /// pas un.
    pub fn lire_lien(&self, n: Numero) -> Result<&[u8], Erreur> {
        match &self.inode(n).contenu {
            Contenu::Lien(cible) => Ok(cible),
            _ => Err(Erreur::EINVAL),
        }
    }

    // ----- Ouvrir, tenir, fermer -----

    /// Ouvre le dernier composant de `fin` (résolu en suivant un lien final,
    /// sauf avec O_NOFOLLOW ou O_EXCL), en le créant s'il le faut. Dans
    /// l'ordre de `do_open` et `may_open` :
    ///   - O_CREAT avec O_DIRECTORY : EINVAL ;
    ///   - avec O_CREAT : « . », « .. » ou la racine : EEXIST avec O_EXCL,
    ///     EISDIR sinon ; une barre finale : EISDIR (un lien final n'est
    ///     alors pas suivi : `Suivre::SaufBarre`) ; rien à ce nom : on crée
    ///     (voir `creer`) ; sinon O_EXCL : EEXIST, un dossier : EISDIR ;
    ///   - sans O_CREAT : rien à ce nom, ENOENT ; une barre finale ou
    ///     O_DIRECTORY sur ce qui n'est pas un dossier : ENOTDIR ;
    ///   - sur ce qui existait déjà (sauf O_PATH) : un lien (O_NOFOLLOW) :
    ///     ELOOP ; un dossier en écriture (ou avec O_TRUNC) : EISDIR ; les
    ///     droits de lire, d'écrire (O_TRUNC demande aussi d'écrire) :
    ///     EACCES ;
    ///   - un programme en cours d'exécution, en écriture ou avec O_TRUNC :
    ///     ETXTBSY.
    /// Un fichier qu'on vient de créer s'ouvre quels que soient ses droits
    /// (un fichier 0444 créé en O_RDWR, comme Linux). L'ouverture tient une
    /// référence à l'inode, à rendre par `fermer`.
    pub fn ouvrir(&mut self, qui: Identite, fin: &Fin<Numero>, o: &Ouverture, maintenant: Temps) -> Result<Ouvert, Erreur> {
        if o.creer && o.dossier {
            return Err(Erreur::EINVAL);
        }
        let (numero, cree) = if o.creer {
            if fin.dernier != Dernier::Nom {
                return Err(if o.exclusif { Erreur::EEXIST } else { Erreur::EISDIR });
            }
            if fin.barre {
                return Err(Erreur::EISDIR);
            }
            match fin.objet {
                None => (self.creer(qui, fin, S_IFREG | (o.mode & 0o7777), (0, 0), &[], maintenant)?, true),
                Some(_) if o.exclusif => return Err(Erreur::EEXIST),
                Some(n) if self.est_dossier(n) => return Err(Erreur::EISDIR),
                Some(n) => (n, false),
            }
        } else {
            let n = fin.objet.ok_or(Erreur::ENOENT)?;
            if (fin.barre || o.dossier) && !self.est_dossier(n) {
                return Err(Erreur::ENOTDIR);
            }
            (n, false)
        };
        let i = self.inode(numero);
        let genre = i.genre();
        let ecrire = o.ecriture || o.tronquer;
        if !cree && !o.chemin_seul {
            if genre == S_IFLNK {
                return Err(Erreur::ELOOP);
            }
            if genre == S_IFDIR && ecrire {
                return Err(Erreur::EISDIR);
            }
            let masque = if o.lecture { LIRE } else { 0 } | if ecrire { ECRIRE } else { 0 };
            if !i.permis(qui, masque) {
                return Err(Erreur::EACCES);
            }
        }
        let fichier = genre == S_IFREG && !o.chemin_seul;
        let tronquer = fichier && o.tronquer && !cree;
        if fichier && (o.ecriture || tronquer) && i.ecrivains < 0 {
            return Err(Erreur::ETXTBSY);
        }
        let ecrivain = fichier && o.ecriture;
        let i = self.inode_mut(numero);
        if ecrivain {
            i.ecrivains += 1;
        }
        i.refs += 1;
        Ok(Ouvert { numero, cree, tronquer, ecrivain })
    }

    /// Une référence de plus à l'inode (un dossier courant, une projection,
    /// un programme en cours : tout ce qui le tient sans passer par
    /// `ouvrir`).
    pub fn prendre(&mut self, n: Numero) {
        self.inode_mut(n).refs += 1;
    }

    /// Une référence de moins. L'inode disparaît s'il n'a plus ni nom ni
    /// référence.
    pub fn lacher(&mut self, n: Numero, cadres: &mut impl Cadres) {
        let i = self.inode_mut(n);
        i.refs -= 1;
        if i.refs == 0 && i.nlink == 0 {
            self.detruire(n, cadres);
        }
    }

    /// La fin d'une ouverture : l'écrivain rendu s'il en était un, puis la
    /// référence.
    pub fn fermer(&mut self, ouvert: &Ouvert, cadres: &mut impl Cadres) {
        if ouvert.ecrivain {
            self.inode_mut(ouvert.numero).ecrivains -= 1;
        }
        self.lacher(ouvert.numero, cadres);
    }

    /// `qui` peut-il exécuter `n` (execve) ? Un fichier ordinaire, avec le
    /// droit d'exécuter : sinon EACCES.
    pub fn peut_executer(&self, qui: Identite, n: Numero) -> Result<(), Erreur> {
        let i = self.inode(n);
        if i.genre() != S_IFREG || !i.permis(qui, EXECUTER) { Err(Erreur::EACCES) } else { Ok(()) }
    }

    /// Un programme commence à exécuter `n` : plus personne ne peut l'écrire
    /// (le `deny_write_access` de Linux). ETXTBSY s'il est ouvert en
    /// écriture.
    pub fn refuser_ecriture(&mut self, n: Numero) -> Result<(), Erreur> {
        let i = self.inode_mut(n);
        if i.ecrivains > 0 {
            return Err(Erreur::ETXTBSY);
        }
        i.ecrivains -= 1;
        Ok(())
    }

    /// Le programme qui exécutait `n` s'est terminé.
    pub fn permettre_ecriture(&mut self, n: Numero) {
        self.inode_mut(n).ecrivains += 1;
    }

    // ----- Les données -----

    fn index(&self, n: Numero) -> &IndexPages {
        match &self.inode(n).contenu {
            Contenu::Fichier(index) => index,
            _ => panic!("tmpfs : un fichier attendu"),
        }
    }

    /// La page numéro `index` du fichier `n`, s'il y en a une (sinon c'est
    /// un trou, ou c'est au-delà de la fin : des zéros).
    pub fn page(&self, n: Numero, index: u64) -> Option<u64> {
        self.index(n).trouver(index)
    }

    /// La page numéro `index` du fichier `n`, créée (à zéro) s'il n'y en a
    /// pas : avant d'y écrire, ou pour une faute de page dans une
    /// projection du fichier. Au-delà de la plus grande taille de fichier :
    /// EFBIG ; au-delà de la limite de pages : ENOSPC ; plus de mémoire :
    /// ENOMEM. La taille du fichier ne change pas (voir `ecrit`).
    pub fn page_pour_ecrire(&mut self, n: Numero, index: u64, cadres: &mut impl Cadres) -> Result<u64, Erreur> {
        if index >= INDEX_MAX {
            return Err(Erreur::EFBIG);
        }
        if let Some(p) = self.page(n, index) {
            return Ok(p);
        }
        if self.pages >= self.limites.pages {
            return Err(Erreur::ENOSPC);
        }
        let page = cadres.allouer().ok_or(Erreur::ENOMEM)?;
        let Contenu::Fichier(ix) = &mut self.inode_mut(n).contenu else {
            panic!("tmpfs : un fichier attendu");
        };
        match ix.inserer(index, page) {
            Ok(_) => {
                self.pages += 1;
                Ok(page)
            }
            Err(e) => {
                cadres.lacher(page);
                Err(if e == ErreurIndex::HorsLimite { Erreur::EFBIG } else { Erreur::ENOMEM })
            }
        }
    }

    /// On vient d'écrire dans le fichier `n` jusqu'à la position `fin`
    /// (exclue) : sa taille grandit s'il le faut, et ses dates changent.
    pub fn ecrit(&mut self, n: Numero, fin: u64, maintenant: Temps) {
        let i = self.inode_mut(n);
        i.taille = i.taille.max(fin);
        i.mtime = maintenant;
        i.ctime = maintenant;
    }

    /// Écrit `octets` à la position `position` du fichier `n`, page à page
    /// (pour le noyau lui-même : le déballage de l'archive, par exemple ;
    /// les écritures des programmes copient directement dans les pages).
    /// Rend le nombre d'octets écrits : tous, ou ceux d'avant la première
    /// page refusée ; si aucun ne l'a été, l'erreur de cette page.
    pub fn ecrire(&mut self, n: Numero, position: u64, octets: &[u8], maintenant: Temps, cadres: &mut impl Cadres)
        -> Result<usize, Erreur> {
        let octets = &octets[..limite_ecriture(position, octets.len())?];
        let mut ecrits = 0;
        while ecrits < octets.len() {
            let ici = position + ecrits as u64;
            let decalage = (ici % PAGE) as usize;
            let morceau = (PAGE as usize - decalage).min(octets.len() - ecrits);
            let page = match self.page_pour_ecrire(n, ici / PAGE, cadres) {
                Ok(p) => p,
                Err(e) if ecrits == 0 => return Err(e),
                Err(_) => break,
            };
            cadres.ecrire(page, decalage, &octets[ecrits..ecrits + morceau]);
            ecrits += morceau;
        }
        if ecrits > 0 {
            self.ecrit(n, position + ecrits as u64, maintenant);
        }
        Ok(ecrits)
    }

    /// Lit le fichier `n` à partir de `position`, jusqu'à la fin du tampon
    /// ou du fichier : rend le nombre d'octets lus. Un trou se lit comme
    /// des zéros, sans rien allouer.
    pub fn lire(&self, n: Numero, position: u64, tampon: &mut [u8], cadres: &impl Cadres) -> usize {
        let taille = self.inode(n).taille;
        if position >= taille {
            return 0;
        }
        let total = ((taille - position) as usize).min(tampon.len());
        let mut lus = 0;
        while lus < total {
            let ici = position + lus as u64;
            let decalage = (ici % PAGE) as usize;
            let morceau = (PAGE as usize - decalage).min(total - lus);
            match self.page(n, ici / PAGE) {
                Some(p) => cadres.lire(p, decalage, &mut tampon[lus..lus + morceau]),
                None => tampon[lus..lus + morceau].fill(0),
            }
            lus += morceau;
        }
        total
    }

    /// SEEK_DATA (`donnee`) ou SEEK_HOLE à partir de `position` : la
    /// première position, à la page près, où il y a des données (ou un
    /// trou : la fin du fichier en est un). ENXIO à la fin du fichier ou
    /// au-delà, ou s'il n'y a plus de données. Comme `shmem_file_llseek` :
    /// tmpfs connaît ses trous.
    pub fn chercher(&self, n: Numero, position: u64, donnee: bool) -> Result<u64, Erreur> {
        let taille = self.inode(n).taille;
        if position >= taille {
            return Err(Erreur::ENXIO);
        }
        let index = self.index(n);
        let page = position / PAGE;
        let trouvee = if donnee { index.suivante(page) } else { Some(index.trou(page)) };
        match trouvee.map(|p| (p * PAGE).max(position)) {
            Some(p) if p < taille => Ok(p),
            Some(_) if !donnee => Ok(taille),
            _ => Err(Erreur::ENXIO),
        }
    }

    /// `truncate` par un chemin : un dossier (EISDIR), autre chose qu'un
    /// fichier (EINVAL), pas le droit d'écrire (EACCES), un programme en
    /// cours d'exécution (ETXTBSY), dans l'ordre de `vfs_truncate`.
    /// (`ftruncate`, lui, passe par un descripteur ouvert en écriture : le
    /// noyau vérifie le descripteur.)
    pub fn verifier_tronquer(&self, qui: Identite, n: Numero) -> Result<(), Erreur> {
        let i = self.inode(n);
        match i.genre() {
            S_IFDIR => return Err(Erreur::EISDIR),
            S_IFREG => {}
            _ => return Err(Erreur::EINVAL),
        }
        if !i.permis(qui, ECRIRE) {
            return Err(Erreur::EACCES);
        }
        if i.ecrivains < 0 {
            return Err(Erreur::ETXTBSY);
        }
        Ok(())
    }

    /// Change la taille du fichier `n` (truncate, ftruncate, O_TRUNC). Les
    /// pages au-delà sont rendues ; la fin de la dernière page gardée,
    /// au-delà de la nouvelle taille, est remise à zéro (voir l'en-tête).
    /// Plus grande que la taille maximale : EFBIG. Les dates changent même
    /// si la taille reste la même, comme Linux (ATTR_MTIME | ATTR_CTIME).
    ///
    /// Le noyau doit d'abord retirer ces pages des projections des
    /// programmes : le tmpfs ne sait rien d'elles.
    pub fn tronquer(&mut self, n: Numero, taille: u64, maintenant: Temps, cadres: &mut impl Cadres) -> Result<(), Erreur> {
        if self.inode(n).genre() != S_IFREG {
            return Err(Erreur::EINVAL);
        }
        if taille > TAILLE_MAX {
            return Err(Erreur::EFBIG);
        }
        let i = self.inode_mut(n);
        let ancienne = i.taille;
        i.taille = taille;
        i.mtime = maintenant;
        i.ctime = maintenant;
        if taille >= ancienne {
            return Ok(());
        }
        let Contenu::Fichier(index) = &mut i.contenu else {
            panic!("tmpfs : un fichier attendu");
        };
        let avant = index.pages();
        index.retirer_depuis(taille.div_ceil(PAGE), |p| cadres.lacher(p));
        let rendues = avant - index.pages();
        let partielle = index.trouver(taille / PAGE).filter(|_| taille % PAGE != 0);
        self.pages -= rendues;
        if let Some(p) = partielle {
            cadres.effacer(p, (taille % PAGE) as usize, PAGE as usize);
        }
        Ok(())
    }

    // ----- Les dossiers -----

    /// Lit le dossier `n` à partir de la position `position` (0 au début) :
    /// appelle `entree(nom, numéro, type, position suivante)` pour « . »,
    /// « .. », puis chaque entrée, de la plus récente à la plus ancienne,
    /// tant qu'elle rend vrai (faux : l'entrée n'a pas été prise, on
    /// s'arrête). ENOTDIR si ce n'est pas un dossier ; ENOENT s'il a été
    /// effacé (encore ouvert, ou dossier courant), comme Linux
    /// (`iterate_dir` et IS_DEADDIR), plutôt que d'y montrer « . » et « .. ».
    pub fn lire_dossier(&self, n: Numero, position: u64, mut entree: impl FnMut(&[u8], Numero, u8, u64) -> bool)
        -> Result<(), Erreur> {
        let i = self.inode(n);
        let Contenu::Dossier(d) = &i.contenu else {
            return Err(Erreur::ENOTDIR);
        };
        if i.nlink == 0 {
            return Err(Erreur::ENOENT);
        }
        if position == 0 && !entree(b".", n, DT_DIR, 1) {
            return Ok(());
        }
        if position <= 1 && !entree(b"..", d.parent, DT_DIR, 2) {
            return Ok(());
        }
        // Les entrées de cookie plus petit que la position (toutes, à la
        // position 2), de la plus récente à la plus ancienne.
        let borne = if position <= 2 { u64::MAX } else { position };
        let fin = d.entrees.partition_point(|e| e.cookie < borne);
        for e in d.entrees[..fin].iter().rev() {
            let genre = match self.inode(e.numero).genre() {
                S_IFDIR => DT_DIR,
                S_IFLNK => DT_LNK,
                S_IFCHR => DT_CHR,
                _ => DT_REG,
            };
            if !entree(&e.nom, e.numero, genre, e.cookie) {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Le chemin absolu du dossier `n` (getcwd), en remontant les parents.
    /// ENOENT pour un dossier effacé ; ENAMETOOLONG s'il ne tient pas, avec
    /// son zéro final, dans PATH_MAX octets (la page où Linux l'écrit). La
    /// glibc compte sur cette erreur : elle se rabat alors sur sa propre
    /// méthode (remonter les « .. » un à un), sans limite de longueur.
    pub fn chemin(&self, n: Numero) -> Result<Vec<u8>, Erreur> {
        if self.inode(n).nlink == 0 {
            return Err(Erreur::ENOENT);
        }
        // Les noms, du bas vers le haut, puis retournés.
        let mut noms: Vec<&[u8]> = Vec::new();
        let mut courant = n;
        let mut longueur = 0;
        while courant != self.racine() {
            let parent = self.inode(courant).dossier().parent;
            let e = self.inode(parent).dossier().entrees.iter().find(|e| e.numero == courant).ok_or(Erreur::ENOENT)?;
            longueur += e.nom.len() + 1;
            if longueur >= PATH_MAX {
                return Err(Erreur::ENAMETOOLONG);
            }
            reserver(&mut noms, 1)?;
            noms.push(&e.nom);
            courant = parent;
        }
        let mut chemin = Vec::new();
        chemin.try_reserve_exact(longueur.max(1)).map_err(|_| Erreur::ENOMEM)?;
        for nom in noms.iter().rev() {
            chemin.push(b'/');
            chemin.extend_from_slice(nom);
        }
        if chemin.is_empty() {
            chemin.push(b'/');
        }
        Ok(chemin)
    }

    // ----- Les attributs -----

    /// L'heure d'accès, au réglage `relatime` (le réglage par défaut de
    /// Linux) : mise à jour seulement si elle n'est pas plus récente que
    /// les dates de modification, ou si elle a plus d'un jour. Un programme
    /// qui lit sans cesse un fichier n'en change pas la date à chaque fois,
    /// mais `atime` dit toujours si le fichier a été lu depuis sa dernière
    /// modification.
    pub fn acceder(&mut self, n: Numero, maintenant: Temps) {
        let i = self.inode_mut(n);
        if i.atime <= i.mtime || i.atime <= i.ctime || maintenant.secondes - i.atime.secondes >= 24 * 3600 {
            i.atime = maintenant;
        }
    }

    /// chmod : seul le propriétaire (ou root) peut changer les droits
    /// (EPERM). Le bit S_ISGID tombe si celui qui le pose n'est pas du
    /// groupe du fichier (et n'est pas root), comme Linux.
    pub fn changer_mode(&mut self, qui: Identite, n: Numero, mode: u32, maintenant: Temps) -> Result<(), Erreur> {
        let i = self.inode_mut(n);
        if !qui.root() && qui.uid != i.uid {
            return Err(Erreur::EPERM);
        }
        let mut droits = mode & 0o7777;
        if !qui.root() && qui.gid != i.gid {
            droits &= !S_ISGID;
        }
        i.mode = (i.mode & S_IFMT) | droits;
        i.ctime = maintenant;
        Ok(())
    }

    /// chown : seul root change le propriétaire ; le propriétaire peut
    /// donner le fichier à son propre groupe (EPERM sinon). Pour autre chose
    /// qu'un dossier, comme `chown_common` et `setattr_should_drop_sgid` de
    /// Linux, même avec chown(-1, -1) et même par root :
    ///   - S_ISUID tombe toujours ;
    ///   - S_ISGID tombe s'il va avec le droit d'exécuter du groupe (un vrai
    ///     setgid ; sans ce x, c'est l'ancienne marque du verrouillage
    ///     obligatoire, qui reste), ou si l'appelant n'est pas du groupe du
    ///     fichier (ni root).
    /// Changer ainsi les droits demande d'être le propriétaire : un autre
    /// reçoit EPERM, même pour chown(-1, -1) (mesuré sur Linux 6.18).
    pub fn changer_proprietaire(&mut self, qui: Identite, n: Numero, uid: Option<u32>, gid: Option<u32>, maintenant: Temps)
        -> Result<(), Erreur> {
        let i = self.inode_mut(n);
        let proprietaire = qui.root() || qui.uid == i.uid;
        if !qui.root() {
            let uid_ok = uid.is_none_or(|u| u == i.uid);
            let gid_ok = gid.is_none_or(|g| g == i.gid || (qui.uid == i.uid && g == qui.gid));
            if !uid_ok || !gid_ok || (!proprietaire && (uid.is_some() || gid.is_some())) {
                return Err(Erreur::EPERM);
            }
        }
        let mut mode = i.mode;
        if i.genre() != S_IFDIR {
            mode &= !S_ISUID;
            if mode & S_ISGID != 0 && (mode & 0o010 != 0 || (!qui.root() && qui.gid != i.gid)) {
                mode &= !S_ISGID;
            }
        }
        if mode != i.mode && !proprietaire {
            return Err(Erreur::EPERM);
        }
        i.mode = mode;
        i.uid = uid.unwrap_or(i.uid);
        i.gid = gid.unwrap_or(i.gid);
        i.ctime = maintenant;
        Ok(())
    }

    /// utimensat : poser les dates d'accès et de modification. Les deux à
    /// « maintenant » (le `touch` ordinaire) : le propriétaire, ou qui a le
    /// droit d'écrire (sinon EACCES) ; tout autre couple, même une seule
    /// date à « maintenant » et l'autre gardée : le propriétaire seulement
    /// (EPERM), comme `vfs_utimes`, pour qui ce n'est plus un simple
    /// ATTR_TOUCH. Les deux à « garder » : rien du tout.
    pub fn changer_temps(&mut self, qui: Identite, n: Numero, acces: Horodatage, modification: Horodatage, maintenant: Temps)
        -> Result<(), Erreur> {
        if acces == Horodatage::Garder && modification == Horodatage::Garder {
            return Ok(());
        }
        let i = self.inode_mut(n);
        let proprietaire = qui.root() || qui.uid == i.uid;
        let touch = acces == Horodatage::Maintenant && modification == Horodatage::Maintenant;
        if !proprietaire {
            if !touch {
                return Err(Erreur::EPERM);
            }
            if !i.permis(qui, ECRIRE) {
                return Err(Erreur::EACCES);
            }
        }
        let valeur = |h: Horodatage, ancienne: Temps| match h {
            Horodatage::Garder => ancienne,
            Horodatage::Maintenant => maintenant,
            Horodatage::Valeur(t) => t,
        };
        i.atime = valeur(acces, i.atime);
        i.mtime = valeur(modification, i.mtime);
        i.ctime = maintenant;
        Ok(())
    }

    // ----- Les invariants, pour les tests -----

    /// Vérifie toute la structure : chaque dossier atteignable depuis la
    /// racine a un seul parent, le bon nombre de liens (2 plus ses
    /// sous-dossiers) et la bonne taille ; chaque autre inode a autant de
    /// liens que de noms ; les cookies croissent ; les comptes d'inodes et
    /// de pages sont justes ; un inode sans nom est tenu (sinon il aurait
    /// dû disparaître) ; pas de bloc vide en fin de table.
    pub fn invariants(&self) -> Result<(), &'static str> {
        let mut noms = Vec::new();
        noms.resize(self.blocs.len() * PAR_BLOC + 1, 0u32);
        let (mut inodes, mut pages) = (0u32, 0u64);
        for (b, bloc) in self.blocs.iter().enumerate() {
            if bloc.prises != bloc.cases.iter().filter(|c| c.is_some()).count() {
                return Err("compte des cases prises faux");
            }
            for (c, i) in bloc.cases.iter().enumerate() {
                let Some(i) = i else { continue };
                inodes += 1;
                if let Contenu::Fichier(index) = &i.contenu {
                    pages += index.pages();
                    index.invariants()?;
                    if index.suivante(i.taille.div_ceil(PAGE)).is_some() {
                        return Err("une page au-dela de la fin du fichier");
                    }
                }
                if let Contenu::Dossier(d) = &i.contenu {
                    let n = Numero((b * PAR_BLOC + c + 1) as u32);
                    if d.entrees.windows(2).any(|w| w[0].cookie >= w[1].cookie) || d.entrees.iter().any(|e| e.cookie >= d.prochain) {
                        return Err("cookies desordonnes");
                    }
                    if i.taille != (2 + d.entrees.len() as u64) * TAILLE_ENTREE {
                        return Err("taille de dossier fausse");
                    }
                    let sous = d.entrees.iter().filter(|e| self.inode(e.numero).est_dossier()).count() as u32;
                    if i.nlink != 0 && i.nlink != 2 + sous {
                        return Err("liens de dossier faux");
                    }
                    for e in &d.entrees {
                        noms[e.numero.0 as usize] += 1;
                        let enfant = self.case(e.numero).ok_or("entree vers un inode detruit")?;
                        if enfant.est_dossier() && enfant.dossier().parent != n {
                            return Err("parent faux");
                        }
                        if e.nom.is_empty() || e.nom.len() > 255 || e.nom.contains(&b'/') || e.nom == b"." || e.nom == b".." {
                            return Err("nom invalide");
                        }
                        if d.entrees.iter().filter(|f| f.nom == e.nom).count() != 1 {
                            return Err("nom en double");
                        }
                    }
                }
            }
        }
        for (b, bloc) in self.blocs.iter().enumerate() {
            for (c, i) in bloc.cases.iter().enumerate() {
                let Some(i) = i else { continue };
                let numero = b * PAR_BLOC + c + 1;
                let attendu = if i.est_dossier() { u32::from(noms[numero] > 0 || numero == 1) } else { noms[numero] };
                if i.est_dossier() && noms[numero] > 1 {
                    return Err("dossier a plusieurs noms");
                }
                if !i.est_dossier() && i.nlink != attendu {
                    return Err("nlink different du nombre de noms");
                }
                if i.est_dossier() && (i.nlink > 0) != (attendu == 1) {
                    return Err("dossier efface encore nomme, ou l'inverse");
                }
                if i.nlink == 0 && i.refs == 0 {
                    return Err("inode sans nom ni reference");
                }
            }
        }
        if inodes != self.inodes || pages != self.pages {
            return Err("comptes du systeme de fichiers faux");
        }
        if self.blocs.last().is_some_and(|b| b.prises == 0) {
            return Err("bloc vide en fin de table");
        }
        Ok(())
    }
}

impl Arbre for Tmpfs {
    type Objet = Numero;

    fn mode(&self, n: Numero) -> u32 {
        self.inode(n).mode
    }

    fn proprietaire(&self, n: Numero) -> (u32, u32) {
        let i = self.inode(n);
        (i.uid, i.gid)
    }

    fn chercher(&self, dossier: Numero, nom: &[u8]) -> Option<Numero> {
        self.inode(dossier).dossier().entrees.iter().find(|e| e.nom == nom).map(|e| e.numero)
    }

    fn parent(&self, dossier: Numero) -> Numero {
        self.inode(dossier).dossier().parent
    }

    fn cible(&self, lien: Numero) -> &[u8] {
        match &self.inode(lien).contenu {
            Contenu::Lien(c) => c,
            _ => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chemins::{Depart, Suivre, resoudre, trouver};
    use alloc::boxed::Box;
    use alloc::vec;

    /// Les pages, sur l'hôte : des tableaux, comptés.
    #[derive(Default)]
    struct Hote {
        pages: Vec<Option<Box<[u8; 4096]>>>,
    }

    impl Hote {
        fn vivantes(&self) -> usize {
            self.pages.iter().filter(|p| p.is_some()).count()
        }
    }

    impl Cadres for Hote {
        fn allouer(&mut self) -> Option<u64> {
            self.pages.push(Some(Box::new([0; 4096])));
            Some(self.pages.len() as u64)
        }
        fn lacher(&mut self, page: u64) {
            assert!(self.pages[page as usize - 1].take().is_some(), "page rendue deux fois");
        }
        fn ecrire(&mut self, page: u64, decalage: usize, octets: &[u8]) {
            self.pages[page as usize - 1].as_mut().unwrap()[decalage..decalage + octets.len()].copy_from_slice(octets);
        }
        fn lire(&self, page: u64, decalage: usize, tampon: &mut [u8]) {
            tampon.copy_from_slice(&self.pages[page as usize - 1].as_ref().unwrap()[decalage..decalage + tampon.len()]);
        }
    }

    const DAVID: Identite = Identite { uid: 1000, gid: 1000 };
    const AUTRE: Identite = Identite { uid: 1001, gid: 1001 };
    const T0: Temps = Temps { secondes: 1_790_000_000, nanosecondes: 0 };

    /// Un tmpfs de test, avec /tmp (1777) et /home/david (à David).
    struct T {
        fs: Tmpfs,
        c: Hote,
        qui: Identite,
    }

    use Erreur::*;

    impl T {
        fn new() -> T {
            let fs = Tmpfs::new(Limites { inodes: 1000, pages: 1000 }, T0).unwrap();
            let mut t = T { fs, c: Hote::default(), qui: Identite::ROOT };
            let tmp = t.mkdir(b"/tmp").unwrap();
            t.fs.changer_mode(Identite::ROOT, tmp, 0o1777, T0).unwrap();
            t.mkdir(b"/home").unwrap();
            let home = t.mkdir(b"/home/david").unwrap();
            t.fs.changer_proprietaire(Identite::ROOT, home, Some(1000), Some(1000), T0).unwrap();
            t.qui = DAVID;
            t
        }
        fn depart(&self) -> Depart<Numero> {
            Depart { racine: self.fs.racine(), dossier: self.fs.racine(), qui: self.qui, sous: false }
        }
        fn fin(&self, p: &[u8], s: Suivre) -> Result<Fin<Numero>, Erreur> {
            resoudre(&self.fs, &self.depart(), p, s)
        }
        fn trouver(&self, p: &[u8]) -> Result<Numero, Erreur> {
            trouver(&self.fs, &self.depart(), p, true)
        }
        fn mkdir(&mut self, p: &[u8]) -> Result<Numero, Erreur> {
            let f = self.fin(p, Suivre::Jamais)?;
            self.fs.creer(self.qui, &f, S_IFDIR | 0o755, (0, 0), &[], T0)
        }
        fn symlink(&mut self, cible: &[u8], p: &[u8]) -> Result<Numero, Erreur> {
            let f = self.fin(p, Suivre::Jamais)?;
            self.fs.creer(self.qui, &f, S_IFLNK | 0o777, (0, 0), cible, T0)
        }
        /// open, comme Linux résout le dernier composant : suivi, sauf
        /// O_NOFOLLOW ou O_EXCL.
        fn ouvrir(&mut self, p: &[u8], o: Ouverture, nofollow: bool) -> Result<Ouvert, Erreur> {
            let suivre = if nofollow || o.exclusif { Suivre::AvecBarre } else { Suivre::Toujours };
            let suivre = if o.creer && suivre == Suivre::AvecBarre { Suivre::Jamais } else { suivre };
            let f = self.fin(p, suivre)?;
            self.fs.ouvrir(self.qui, &f, &o, T0)
        }
        /// Crée un fichier et le referme.
        fn fichier(&mut self, p: &[u8]) -> Result<Numero, Erreur> {
            let o = self.ouvrir(p, Ouverture { creer: true, exclusif: true, mode: 0o644, ecriture: true, ..Default::default() }, false)?;
            self.fs.fermer(&o, &mut self.c);
            Ok(o.numero)
        }
        fn unlink(&mut self, p: &[u8]) -> Result<(), Erreur> {
            let f = self.fin(p, Suivre::Jamais)?;
            self.fs.effacer(self.qui, &f, false, T0, &mut self.c)
        }
        fn rmdir(&mut self, p: &[u8]) -> Result<(), Erreur> {
            let f = self.fin(p, Suivre::Jamais)?;
            self.fs.effacer(self.qui, &f, true, T0, &mut self.c)
        }
        fn rename(&mut self, a: &[u8], b: &[u8], drapeaux: u32) -> Result<(), Erreur> {
            let fa = self.fin(a, Suivre::Jamais)?;
            let fb = self.fin(b, Suivre::Jamais)?;
            self.fs.renommer(self.qui, &fa, &fb, drapeaux, T0, &mut self.c)
        }
        fn link(&mut self, a: &[u8], b: &[u8]) -> Result<(), Erreur> {
            let source = trouver(&self.fs, &self.depart(), a, false)?;
            let fb = self.fin(b, Suivre::Jamais)?;
            self.fs.lier(self.qui, source, &fb, T0)
        }
        fn ecrire(&mut self, n: Numero, position: u64, octets: &[u8]) -> Result<usize, Erreur> {
            self.fs.ecrire(n, position, octets, T0, &mut self.c)
        }
        fn lire(&self, n: Numero, position: u64, longueur: usize) -> Vec<u8> {
            let mut v = vec![0xAA; longueur];
            let lus = self.fs.lire(n, position, &mut v, &self.c);
            v.truncate(lus);
            v
        }
        fn liste(&self, p: &[u8]) -> Vec<Vec<u8>> {
            let mut noms = Vec::new();
            self.fs.lire_dossier(self.trouver(p).unwrap(), 0, |nom, _, _, _| {
                noms.push(nom.to_vec());
                true
            }).unwrap();
            noms
        }
        fn verifier(&self) {
            self.fs.invariants().unwrap();
            assert_eq!(self.c.vivantes() as u64, self.fs.occupation().1, "pages du systeme de fichiers");
        }
    }

    fn rw() -> Ouverture {
        Ouverture { lecture: true, ecriture: true, ..Default::default() }
    }

    fn lecture() -> Ouverture {
        Ouverture { lecture: true, ..Default::default() }
    }

    #[test]
    fn creer_et_exister() {
        let mut t = T::new();
        t.fichier(b"/tmp/f").unwrap();
        assert_eq!(t.fichier(b"/tmp/f"), Err(EEXIST));
        t.mkdir(b"/tmp/d").unwrap();
        assert_eq!(t.mkdir(b"/tmp/d"), Err(EEXIST));
        assert_eq!(t.mkdir(b"/tmp/f"), Err(EEXIST));
        assert_eq!(t.mkdir(b"/"), Err(EEXIST));
        assert_eq!(t.mkdir(b"/tmp/d/."), Err(EEXIST));
        // mkdir avec une barre finale : permis ; un fichier ou un lien : non.
        t.mkdir(b"/tmp/e/").unwrap();
        assert_eq!(t.symlink(b"x", b"/tmp/s/"), Err(ENOENT));
        let creer = Ouverture { creer: true, ecriture: true, mode: 0o644, ..Default::default() };
        assert_eq!(t.ouvrir(b"/tmp/neuf/", creer, false), Err(EISDIR));
        assert_eq!(t.ouvrir(b"/tmp/f/", creer, false), Err(EISDIR));
        assert_eq!(t.ouvrir(b"/tmp/d", creer, false), Err(EISDIR));
        assert_eq!(t.ouvrir(b"/tmp/neuf", Ouverture { dossier: true, ..creer }, false), Err(EINVAL));
        // « . », « .. », la racine : EEXIST avec O_EXCL, EISDIR sans ; une
        // barre finale : EISDIR même avec O_EXCL (mesuré sur Linux 6.18).
        let excl = Ouverture { exclusif: true, ..creer };
        assert_eq!(t.ouvrir(b"/tmp/.", excl, false), Err(EEXIST));
        assert_eq!(t.ouvrir(b"/", excl, false), Err(EEXIST));
        assert_eq!(t.ouvrir(b"/tmp/d/..", excl, false), Err(EEXIST));
        assert_eq!(t.ouvrir(b"/tmp/d/", excl, false), Err(EISDIR));
        assert_eq!(t.ouvrir(b"/tmp/.", creer, false), Err(EISDIR));
        // Pas de droit d'écrire dans /, mais EEXIST passe avant (Linux
        // cherche le nom d'abord) ; un nom neuf : EACCES.
        assert_eq!(t.mkdir(b"/tmp"), Err(EEXIST));
        assert_eq!(t.mkdir(b"/neuf"), Err(EACCES));
        // Un périphérique, sans être root.
        let f = t.fin(b"/tmp/null", Suivre::Jamais).unwrap();
        assert_eq!(t.fs.creer(DAVID, &f, S_IFCHR | 0o666, (1, 3), &[], T0), Err(EPERM));
        assert_eq!(t.symlink(b"", b"/tmp/vide"), Err(ENOENT));
        // Un lien vide est refusé avant de regarder le nom : ENOENT, même
        // sur un nom qui existe.
        assert_eq!(t.symlink(b"", b"/tmp/f"), Err(ENOENT));
        assert_eq!(t.symlink(&[b'x'; PATH_MAX], b"/tmp/f"), Err(ENAMETOOLONG));
        // st_blocks d'un lien : 0 jusqu'à 128 octets, une page au-delà.
        let court = t.symlink(&[b'x'; 128], b"/tmp/court").unwrap();
        let long = t.symlink(&[b'x'; 129], b"/tmp/long").unwrap();
        assert_eq!((t.fs.attributs(court).blocs, t.fs.attributs(long).blocs), (0, 8));
        t.verifier();
    }

    #[test]
    fn ouvrir() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/f").unwrap();
        t.mkdir(b"/tmp/d").unwrap();
        assert_eq!(t.ouvrir(b"/tmp/d", rw(), false), Err(EISDIR));
        assert_eq!(t.ouvrir(b"/tmp/d", Ouverture { tronquer: true, ..lecture() }, false), Err(EISDIR));
        assert!(t.ouvrir(b"/tmp/d", lecture(), false).is_ok());
        assert_eq!(t.ouvrir(b"/tmp/f/x", lecture(), false), Err(ENOTDIR));
        assert_eq!(t.ouvrir(b"/tmp/f", Ouverture { dossier: true, ..lecture() }, false), Err(ENOTDIR));
        assert_eq!(t.ouvrir(b"/tmp/rien", lecture(), false), Err(ENOENT));
        // Un lien : O_NOFOLLOW refuse ; O_PATH avec O_NOFOLLOW ouvre le lien.
        t.symlink(b"f", b"/tmp/lien").unwrap();
        assert_eq!(t.ouvrir(b"/tmp/lien", lecture(), true), Err(ELOOP));
        assert_eq!(t.ouvrir(b"/tmp/lien", lecture(), false).map(|o| o.numero), Ok(f));
        let lien = t.ouvrir(b"/tmp/lien", Ouverture { chemin_seul: true, ..Default::default() }, true).unwrap();
        assert_ne!(lien.numero, f);
        // Un lien pendant avec O_CREAT : sa cible est créée ; avec O_EXCL :
        // EEXIST (le lien lui-même existe).
        t.symlink(b"cible", b"/tmp/pendant").unwrap();
        let creer = Ouverture { creer: true, ecriture: true, mode: 0o600, ..Default::default() };
        assert_eq!(t.ouvrir(b"/tmp/pendant", Ouverture { exclusif: true, ..creer }, false), Err(EEXIST));
        let o = t.ouvrir(b"/tmp/pendant", creer, false).unwrap();
        assert!(o.cree);
        assert_eq!(t.trouver(b"/tmp/cible"), Ok(o.numero));
        // Les droits : 0644 à root, ni écriture ni exécution pour David ;
        // un fichier créé s'ouvre quels que soient ses droits.
        t.qui = Identite::ROOT;
        t.fichier(b"/a-root").unwrap();
        t.qui = DAVID;
        assert_eq!(t.ouvrir(b"/a-root", rw(), false), Err(EACCES));
        assert_eq!(t.ouvrir(b"/a-root", Ouverture { tronquer: true, ..lecture() }, false), Err(EACCES));
        assert!(t.ouvrir(b"/a-root", lecture(), false).is_ok());
        let ro = Ouverture { creer: true, lecture: true, ecriture: true, mode: 0o444, ..Default::default() };
        assert!(t.ouvrir(b"/tmp/ro", ro, false).is_ok());
        assert_eq!(t.fs.acces(DAVID, t.trouver(b"/tmp/f").unwrap(), EXECUTER), Err(EACCES));
        t.verifier();
    }

    #[test]
    fn effacer() {
        let mut t = T::new();
        t.fichier(b"/tmp/f").unwrap();
        t.mkdir(b"/tmp/d").unwrap();
        t.fichier(b"/tmp/d/g").unwrap();
        assert_eq!(t.rmdir(b"/tmp/f"), Err(ENOTDIR));
        assert_eq!(t.unlink(b"/tmp/d"), Err(EISDIR));
        assert_eq!(t.rmdir(b"/tmp/d"), Err(ENOTEMPTY));
        assert_eq!(t.rmdir(b"/tmp/d/."), Err(EINVAL));
        assert_eq!(t.rmdir(b"/tmp/d/.."), Err(ENOTEMPTY));
        assert_eq!(t.unlink(b"/tmp/d/.."), Err(EISDIR));
        assert_eq!(t.rmdir(b"/"), Err(EBUSY));
        assert_eq!(t.unlink(b"/tmp/f/"), Err(ENOTDIR));
        assert_eq!(t.unlink(b"/tmp/d/"), Err(EISDIR));
        assert_eq!(t.unlink(b"/tmp/rien"), Err(ENOENT));
        assert_eq!(t.unlink(b"/tmp/rien/"), Err(ENOENT));
        t.unlink(b"/tmp/d/g").unwrap();
        t.rmdir(b"/tmp/d/").unwrap();
        t.unlink(b"/tmp/f").unwrap();
        // Le sticky de /tmp : on n'efface pas le fichier d'un autre, même
        // avec le droit d'écrire dans /tmp ; root, si.
        t.qui = AUTRE;
        t.fichier(b"/tmp/a-autre").unwrap();
        t.qui = DAVID;
        assert_eq!(t.unlink(b"/tmp/a-autre"), Err(EPERM));
        assert_eq!(t.rename(b"/tmp/a-autre", b"/tmp/x", 0), Err(EPERM));
        t.qui = Identite::ROOT;
        t.unlink(b"/tmp/a-autre").unwrap();
        // Pas le droit d'écrire dans le dossier.
        t.qui = DAVID;
        assert_eq!(t.unlink(b"/home"), Err(EACCES));
        t.verifier();
    }

    #[test]
    fn renommer() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/f").unwrap();
        t.fichier(b"/tmp/g").unwrap();
        let d = t.mkdir(b"/tmp/d").unwrap();
        t.mkdir(b"/tmp/d/sous").unwrap();
        t.mkdir(b"/tmp/vide").unwrap();
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/d", 0), Err(EISDIR));
        // Des drapeaux impossibles, et RENAME_WHITEOUT, qu'on ne sait pas
        // faire : EINVAL.
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/g", RENAME_NOREPLACE | RENAME_EXCHANGE), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/g", RENAME_WHITEOUT | RENAME_EXCHANGE), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/g", 8), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/neuf", RENAME_WHITEOUT), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/d", b"/tmp/f", 0), Err(ENOTDIR));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/x/", 0), Err(ENOTDIR));
        assert_eq!(t.rename(b"/tmp/d", b"/tmp/d/sous/x", 0), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/d", b"/tmp/d/x", 0), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/d/sous", b"/tmp/d", 0), Err(ENOTEMPTY));
        assert_eq!(t.rename(b"/tmp/vide", b"/tmp/d", 0), Err(ENOTEMPTY));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/g", RENAME_NOREPLACE), Err(EEXIST));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/x", RENAME_EXCHANGE), Err(ENOENT));
        assert_eq!(t.rename(b"/tmp/f", b"/tmp/x", RENAME_EXCHANGE | RENAME_NOREPLACE), Err(EINVAL));
        assert_eq!(t.rename(b"/tmp/rien", b"/tmp/x", 0), Err(ENOENT));
        assert_eq!(t.rename(b"/tmp/.", b"/tmp/x", 0), Err(EBUSY));
        // Écraser un fichier : l'écrasé disparaît.
        t.rename(b"/tmp/f", b"/tmp/g", 0).unwrap();
        assert_eq!(t.trouver(b"/tmp/g"), Ok(f));
        assert_eq!(t.trouver(b"/tmp/f"), Err(ENOENT));
        // Un dossier sur un dossier vide, dans un autre parent : les liens et
        // « .. » suivent.
        t.rename(b"/tmp/d/sous", b"/tmp/vide", 0).unwrap();
        assert_eq!(t.fs.attributs(d).nlink, 2);
        let sous = t.trouver(b"/tmp/vide").unwrap();
        assert_eq!(t.fs.parent(sous), t.trouver(b"/tmp").unwrap());
        // RENAME_EXCHANGE d'un fichier et d'un dossier.
        t.rename(b"/tmp/g", b"/tmp/vide", RENAME_EXCHANGE).unwrap();
        assert_eq!((t.trouver(b"/tmp/vide"), t.trouver(b"/tmp/g")), (Ok(f), Ok(sous)));
        // Deux liens physiques du même fichier : rien à faire.
        t.link(b"/tmp/vide", b"/tmp/autre-nom").unwrap();
        t.rename(b"/tmp/vide", b"/tmp/autre-nom", 0).unwrap();
        assert_eq!((t.trouver(b"/tmp/vide"), t.trouver(b"/tmp/autre-nom")), (Ok(f), Ok(f)));
        // Dans le même dossier, de deux entrées à une.
        let h = t.mkdir(b"/tmp/h").unwrap();
        t.fichier(b"/tmp/h/a").unwrap();
        t.fichier(b"/tmp/h/b").unwrap();
        t.rename(b"/tmp/h/a", b"/tmp/h/b", 0).unwrap();
        assert_eq!(t.liste(b"/tmp/h"), [&b"."[..], b"..", b"b"]);
        assert_eq!(t.fs.attributs(h).taille, 3 * TAILLE_ENTREE);
        t.verifier();
    }

    #[test]
    fn liens_physiques() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/f").unwrap();
        t.mkdir(b"/tmp/d").unwrap();
        assert_eq!(t.link(b"/tmp/d", b"/tmp/d2"), Err(EPERM));
        assert_eq!(t.link(b"/tmp/f", b"/tmp/d"), Err(EEXIST));
        t.link(b"/tmp/f", b"/tmp/f2").unwrap();
        assert_eq!(t.fs.attributs(f).nlink, 2);
        // Le fichier d'un autre, qu'on ne peut pas écrire : EPERM
        // (protected_hardlinks).
        t.qui = AUTRE;
        assert_eq!(t.link(b"/tmp/f", b"/tmp/f3"), Err(EPERM));
        t.qui = DAVID;
        // Ouvert, puis effacé de ses deux noms : il se lit encore.
        let o = t.ouvrir(b"/tmp/f", rw(), false).unwrap();
        t.ecrire(f, 0, b"bonjour").unwrap();
        t.unlink(b"/tmp/f").unwrap();
        t.unlink(b"/tmp/f2").unwrap();
        assert_eq!(t.lire(f, 0, 100), b"bonjour");
        t.verifier();
        t.fs.fermer(&o, &mut t.c);
        assert!(!t.fs.existe(f));
        assert_eq!(t.c.vivantes(), 0);
        t.verifier();
    }

    #[test]
    fn donnees() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/f").unwrap();
        // À cheval sur deux pages, après un trou d'une page.
        t.ecrire(f, 8190, b"abcd").unwrap();
        assert_eq!(t.fs.attributs(f).taille, 8194);
        assert_eq!(t.fs.attributs(f).blocs, 16);
        assert_eq!(t.lire(f, 8188, 100), b"\0\0abcd");
        assert_eq!(t.lire(f, 0, 2), b"\0\0");
        assert_eq!(t.lire(f, 9000, 10), b"");
        // Raccourcir puis rallonger : les anciens octets ne reviennent pas.
        t.tronquer_ok(f, 8191);
        t.tronquer_ok(f, 8194);
        assert_eq!(t.lire(f, 8188, 100), b"\0\0a\0\0\0");
        t.tronquer_ok(f, 0);
        assert_eq!(t.fs.attributs(f).blocs, 0);
        // SEEK_DATA et SEEK_HOLE, les valeurs mesurées sous Linux : un
        // fichier de 1 Mio écrit à 512 Kio.
        t.tronquer_ok(f, 1 << 20);
        t.ecrire(f, 512 << 10, b"x").unwrap();
        assert_eq!(t.fs.chercher(f, 0, true), Ok(524_288));
        assert_eq!(t.fs.chercher(f, 512 << 10, false), Ok(528_384));
        assert_eq!(t.fs.chercher(f, 0, false), Ok(0));
        assert_eq!(t.fs.chercher(f, 600 << 10, true), Err(ENXIO));
        assert_eq!(t.fs.chercher(f, 600 << 10, false), Ok(600 << 10));
        assert_eq!(t.fs.chercher(f, 2 << 20, true), Err(ENXIO));
        assert_eq!(t.fs.chercher(f, 1 << 20, false), Err(ENXIO));
        // Trop grand.
        assert_eq!(t.fs.tronquer(f, TAILLE_MAX + 1, T0, &mut t.c), Err(EFBIG));
        assert_eq!(t.ecrire(f, TAILLE_MAX, b"x"), Err(EFBIG));
        t.verifier();
    }

    impl T {
        fn tronquer_ok(&mut self, n: Numero, taille: u64) {
            self.fs.tronquer(n, taille, T0, &mut self.c).unwrap();
            self.verifier();
        }
    }

    #[test]
    fn plus_de_place() {
        let fs = Tmpfs::new(Limites { inodes: 3, pages: 2 }, T0).unwrap();
        let mut t = T { fs, c: Hote::default(), qui: Identite::ROOT };
        let f = t.fichier(b"/f").unwrap();
        // Deux pages, pas trois ; une écriture partielle rend ce qu'elle a
        // écrit.
        assert_eq!(t.ecrire(f, 0, &[1; 8192 + 10]), Ok(8192));
        assert_eq!(t.ecrire(f, 8192, b"x"), Err(ENOSPC));
        t.fichier(b"/g").unwrap();
        assert_eq!(t.fichier(b"/h"), Err(ENOSPC));
        t.verifier();
    }

    #[test]
    fn programme_en_cours() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/prog").unwrap();
        t.fs.refuser_ecriture(f).unwrap();
        assert_eq!(t.ouvrir(b"/tmp/prog", rw(), false), Err(ETXTBSY));
        assert_eq!(t.ouvrir(b"/tmp/prog", Ouverture { tronquer: true, ..lecture() }, false), Err(ETXTBSY));
        assert_eq!(t.fs.verifier_tronquer(DAVID, f), Err(ETXTBSY));
        assert!(t.ouvrir(b"/tmp/prog", lecture(), false).is_ok());
        t.fs.permettre_ecriture(f);
        let o = t.ouvrir(b"/tmp/prog", rw(), false).unwrap();
        assert_eq!(t.fs.refuser_ecriture(f), Err(ETXTBSY));
        t.fs.fermer(&o, &mut t.c);
        t.fs.refuser_ecriture(f).unwrap();
        // Les droits passent avant : un programme à root, 0755.
        t.qui = Identite::ROOT;
        let p = t.fichier(b"/prog").unwrap();
        t.fs.changer_mode(Identite::ROOT, p, 0o755, T0).unwrap();
        t.fs.refuser_ecriture(p).unwrap();
        t.qui = DAVID;
        assert_eq!(t.ouvrir(b"/prog", rw(), false), Err(EACCES));
        assert_eq!(t.fs.peut_executer(DAVID, p), Ok(()));
        assert_eq!(t.fs.peut_executer(DAVID, t.trouver(b"/tmp").unwrap()), Err(EACCES));
    }

    #[test]
    fn lire_un_dossier() {
        let mut t = T::new();
        for nom in [&b"/tmp/a"[..], b"/tmp/b", b"/tmp/c", b"/tmp/d"] {
            t.fichier(nom).unwrap();
        }
        t.unlink(b"/tmp/b").unwrap();
        t.fichier(b"/tmp/e").unwrap();
        // L'ordre de Linux 6.18 : du plus récent au plus ancien.
        assert_eq!(t.liste(b"/tmp"), [&b"."[..], b"..", b"e", b"d", b"c", b"a"]);
        // Une entrée par appel, en repartant chaque fois de la position
        // rendue : la même liste, sans répétition.
        let tmp = t.trouver(b"/tmp").unwrap();
        let (mut position, mut une_a_une) = (0, Vec::new());
        loop {
            let mut lue = None;
            t.fs.lire_dossier(tmp, position, |nom, _, _, suivante| {
                if lue.is_some() {
                    return false;
                }
                lue = Some((nom.to_vec(), suivante));
                true
            }).unwrap();
            let Some((nom, suivante)) = lue else { break };
            une_a_une.push(nom);
            position = suivante;
        }
        assert_eq!(une_a_une, t.liste(b"/tmp"));
        // Lire par morceaux, en effaçant pendant la lecture : aucune autre
        // entrée n'est sautée ni répétée.
        let tmp = t.trouver(b"/tmp").unwrap();
        let mut position = 0;
        let mut lus = Vec::new();
        for _ in 0..2 {
            let mut n = 0;
            t.fs.lire_dossier(tmp, position, |nom, _, _, suivante| {
                if n == 2 {
                    return false;
                }
                n += 1;
                lus.push(nom.to_vec());
                position = suivante;
                true
            }).unwrap();
        }
        assert_eq!(lus, [&b"."[..], b"..", b"e", b"d"]);
        t.unlink(b"/tmp/d").unwrap();
        t.unlink(b"/tmp/e").unwrap();
        t.fichier(b"/tmp/f").unwrap();
        t.fs.lire_dossier(tmp, position, |nom, _, _, _| {
            lus.push(nom.to_vec());
            true
        }).unwrap();
        assert_eq!(&lus[4..], [&b"c"[..], b"a"]);
        assert_eq!(t.fs.lire_dossier(t.trouver(b"/tmp/a").unwrap(), 0, |_, _, _, _| true), Err(ENOTDIR));
        // Les types, et « .. ».
        t.mkdir(b"/tmp/sous").unwrap();
        let mut types = Vec::new();
        t.fs.lire_dossier(t.trouver(b"/tmp/sous").unwrap(), 0, |nom, n, genre, _| {
            types.push((nom.to_vec(), n, genre));
            true
        }).unwrap();
        assert_eq!(types[1], (b"..".to_vec(), tmp, DT_DIR));
    }

    #[test]
    fn chemin_du_dossier() {
        let mut t = T::new();
        let d = t.mkdir(b"/home/david/projet").unwrap();
        assert_eq!(t.fs.chemin(d).unwrap(), b"/home/david/projet");
        assert_eq!(t.fs.chemin(t.fs.racine()).unwrap(), b"/");
        // Au plus PATH_MAX octets, le zéro final compris : sous /tmp, 20
        // dossiers de 200 caractères font 4024 octets, un de plus 4225. (Créés
        // un à un depuis le précédent : leur chemin complet est trop long
        // pour être résolu.)
        let mut dernier = t.trouver(b"/tmp").unwrap();
        for _ in 0..21 {
            let f = Fin { dossier: dernier, nom: vec![b'n'; 200], objet: None, dernier: Dernier::Nom, barre: false };
            dernier = t.fs.creer(DAVID, &f, S_IFDIR | 0o755, (0, 0), &[], T0).unwrap();
        }
        assert_eq!(t.fs.chemin(t.fs.inode(dernier).dossier().parent).map(|c| c.len()), Ok(4 + 20 * 201));
        assert_eq!(t.fs.chemin(dernier), Err(ENAMETOOLONG));
        t.fs.prendre(d);
        t.rmdir(b"/home/david/projet").unwrap();
        assert_eq!(t.fs.chemin(d), Err(ENOENT));
        assert_eq!(t.fs.lire_dossier(d, 0, |_, _, _, _| true), Err(ENOENT));
        // Un dossier effacé est vide pour toujours.
        let f = Fin { dossier: d, nom: b"x".to_vec(), objet: None, dernier: Dernier::Nom, barre: false };
        assert_eq!(t.fs.creer(DAVID, &f, S_IFREG | 0o644, (0, 0), &[], T0), Err(ENOENT));
        t.verifier();
        t.fs.lacher(d, &mut t.c);
        assert!(!t.fs.existe(d));
    }

    #[test]
    fn attributs_et_dates() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/f").unwrap();
        let plus_tard = Temps { secondes: T0.secondes + 10, nanosecondes: 0 };
        // relatime : l'heure d'accès suit la première lecture après une
        // modification, pas les suivantes (avant un jour).
        t.fs.acceder(f, plus_tard);
        assert_eq!(t.fs.attributs(f).atime, plus_tard);
        let encore = Temps { secondes: T0.secondes + 20, nanosecondes: 0 };
        t.fs.acceder(f, encore);
        assert_eq!(t.fs.attributs(f).atime, plus_tard);
        let demain = Temps { secondes: T0.secondes + 10 + 86_400, nanosecondes: 0 };
        t.fs.acceder(f, demain);
        assert_eq!(t.fs.attributs(f).atime, demain);
        // chmod, chown, utimens : les droits du propriétaire.
        assert_eq!(t.fs.changer_mode(AUTRE, f, 0o777, T0), Err(EPERM));
        t.fs.changer_mode(DAVID, f, 0o2755, T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o2755);
        assert_eq!(t.fs.changer_proprietaire(DAVID, f, Some(0), None, T0), Err(EPERM));
        t.fs.changer_proprietaire(Identite::ROOT, f, None, Some(5), T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o755);
        let a = Horodatage::Valeur(Temps { secondes: 1, nanosecondes: 2 });
        assert_eq!(t.fs.changer_temps(AUTRE, f, a, Horodatage::Garder, T0), Err(EPERM));
        assert_eq!(t.fs.changer_temps(AUTRE, f, Horodatage::Maintenant, Horodatage::Maintenant, T0), Err(EACCES));
        t.fs.changer_temps(DAVID, f, a, Horodatage::Garder, plus_tard).unwrap();
        let at = t.fs.attributs(f);
        assert_eq!((at.atime, at.ctime), (Temps { secondes: 1, nanosecondes: 2 }, plus_tard));
        // Le groupe hérité d'un dossier setgid.
        let d = t.mkdir(b"/home/david/partage").unwrap();
        t.fs.changer_proprietaire(Identite::ROOT, d, None, Some(50), T0).unwrap();
        t.fs.changer_mode(Identite::ROOT, d, 0o2777, T0).unwrap();
        let g = t.fichier(b"/home/david/partage/g").unwrap();
        let s = t.mkdir(b"/home/david/partage/s").unwrap();
        assert_eq!((t.fs.attributs(g).gid, t.fs.mode(s) & S_ISGID), (50, S_ISGID));
        // Un exécutable setgid créé là par David, qui n'est pas du groupe 50
        // : son S_ISGID tombe (mode_strip_sgid). Sans le x du groupe, ou par
        // root, il reste.
        let creer = |mode| Ouverture { creer: true, ecriture: true, mode, ..Default::default() };
        let x = t.ouvrir(b"/home/david/partage/x", creer(0o2755), false).unwrap();
        let y = t.ouvrir(b"/home/david/partage/y", creer(0o2745), false).unwrap();
        t.qui = Identite::ROOT;
        let z = t.ouvrir(b"/home/david/partage/z", creer(0o2755), false).unwrap();
        t.qui = DAVID;
        let modes = [x, y, z].map(|o| t.fs.mode(o.numero));
        assert_eq!(modes, [S_IFREG | 0o755, S_IFREG | 0o2745, S_IFREG | 0o2755]);
    }

    /// chown et les bits setuid et setgid, et utimensat par un autre que le
    /// propriétaire : les cas mesurés sur Linux 6.18.
    #[test]
    fn chown_et_bits_speciaux() {
        let mut t = T::new();
        let f = t.fichier(b"/tmp/f").unwrap();
        // chown(-1, -1) retire S_ISUID, même à root ; un vrai setgid (avec
        // le x du groupe) aussi.
        t.fs.changer_mode(DAVID, f, 0o4755, T0).unwrap();
        t.fs.changer_proprietaire(DAVID, f, None, None, T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o755);
        t.fs.changer_mode(DAVID, f, 0o6755, T0).unwrap();
        t.fs.changer_proprietaire(Identite::ROOT, f, None, None, T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o755);
        // Sans le x du groupe, S_ISGID reste pour un membre du groupe...
        t.fs.changer_mode(DAVID, f, 0o2745, T0).unwrap();
        t.fs.changer_proprietaire(DAVID, f, None, Some(1000), T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o2745);
        // ... et tombe pour qui n'en est pas (le fichier est passé au groupe
        // 5 : David n'en est pas).
        t.fs.changer_proprietaire(Identite::ROOT, f, None, Some(5), T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o2745);
        t.fs.changer_proprietaire(DAVID, f, None, None, T0).unwrap();
        assert_eq!(t.fs.mode(f), S_IFREG | 0o745);
        // Un autre que le propriétaire : chown(-1, -1) passe s'il ne change
        // rien, EPERM s'il devait retirer un bit.
        t.fs.changer_proprietaire(AUTRE, f, None, None, T0).unwrap();
        t.fs.changer_mode(DAVID, f, 0o4755, T0).unwrap();
        assert_eq!(t.fs.changer_proprietaire(AUTRE, f, None, None, T0), Err(EPERM));
        assert_eq!(t.fs.mode(f), S_IFREG | 0o4755);
        // Un dossier garde ses bits.
        let d = t.mkdir(b"/tmp/d").unwrap();
        t.fs.changer_mode(DAVID, d, 0o2755, T0).unwrap();
        t.fs.changer_proprietaire(DAVID, d, None, None, T0).unwrap();
        assert_eq!(t.fs.mode(d), S_IFDIR | 0o2755);
        // utimensat par qui peut écrire sans être le propriétaire : seul
        // (NOW, NOW) passe ; (OMIT, NOW) et (NOW, OMIT) demandent d'être le
        // propriétaire.
        t.fs.changer_mode(DAVID, f, 0o666, T0).unwrap();
        let (garder, maintenant) = (Horodatage::Garder, Horodatage::Maintenant);
        assert_eq!(t.fs.changer_temps(AUTRE, f, garder, maintenant, T0), Err(EPERM));
        assert_eq!(t.fs.changer_temps(AUTRE, f, maintenant, garder, T0), Err(EPERM));
        t.fs.changer_temps(AUTRE, f, maintenant, maintenant, T0).unwrap();
        t.verifier();
    }

    #[test]
    fn tout_effacer_rend_tout() {
        let mut t = T::new();
        let avant = t.fs.occupation();
        for i in 0..200u32 {
            let nom = alloc::format!("/tmp/f{i}");
            let f = t.fichier(nom.as_bytes()).unwrap();
            t.ecrire(f, u64::from(i) * 1000, b"donnees").unwrap();
        }
        assert!(t.fs.blocs.len() > 1);
        for i in 0..200u32 {
            t.unlink(alloc::format!("/tmp/f{i}").as_bytes()).unwrap();
        }
        assert_eq!(t.fs.occupation(), avant);
        assert_eq!(t.c.vivantes(), 0);
        assert_eq!(t.fs.blocs.len(), 1);
        t.verifier();
    }
}
