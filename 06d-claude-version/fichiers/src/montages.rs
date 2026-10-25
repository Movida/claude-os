//! Les points de montage : d'autres systèmes de fichiers, accrochés à des
//! dossiers du tmpfs de la racine, comme `/proc` et `/sys` sous Linux (le
//! `vfsmount` et `follow_mount` de fs/namespace.c et fs/namei.c).
//!
//! Un objet de l'arborescence n'est plus seulement un inode du tmpfs : c'est
//! un inode d'un des systèmes de fichiers (`Objet`). La résolution des
//! chemins (chemins.rs) n'en sait rien : elle parcourt une `Vue` de tous
//! les systèmes, qui implémente son trait `Arbre`, et traverse les points
//! de montage dans les deux sens :
//!   - chercher un nom dont l'inode est un point de montage rend la racine
//!     du système monté (`follow_mount`) : le dossier du tmpfs qui est
//!     dessous ne se voit plus ;
//!   - le parent de la racine d'un système monté est le parent du point de
//!     montage (`follow_dotdot`) : « /proc/.. » est « / ».
//!
//! Les systèmes montés ici sont ceux du noyau (procfs, sysfs : leur
//! contenu est fabriqué par le noyau, rien ne s'y crée ni ne s'y efface).
//! Ils ne connaissent qu'un trait, `Monte`, à la façon des
//! `inode_operations` de Linux. Les règles qui ne dépendent pas du système
//! (on ne renomme ni ne lie d'un système à l'autre : EXDEV ; on n'efface
//! pas un point de montage : EBUSY) sont ici, dans `Vue::refus`, comme
//! dans la couche commune de Linux (le VFS) ; ce qui dépend du système est
//! demandé au système (`Monte::refuser`).
//!
//! Options écartées : mettre /proc dans le tmpfs, avec des inodes spéciaux
//! (/proc/self ne pourrait pas dépendre de qui lit, root pourrait les
//! effacer, et `st_dev` serait celui de la racine) ; intercepter les chemins
//! qui commencent par « /proc » dans `open` (un « .. », un lien, un dossier
//! courant dans /proc le contourneraient). Et le disque de 6l se montera de
//! la même façon.

use crate::chemins::{Arbre, Dernier, Fin, PATH_MAX};
use crate::tmpfs::{Attributs, Numero, RENAME_EXCHANGE, RENAME_NOREPLACE, Tmpfs};
use crate::{Erreur, Identite, S_IFDIR, S_IFMT, S_IFREG};
use alloc::vec::Vec;

/// Le numéro d'un système monté : sa place dans la table des montages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Systeme(pub u8);

/// Un objet de l'arborescence : un inode du tmpfs de la racine, ou d'un
/// système monté (le numéro de l'inode dans ce système).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Objet {
    Tmpfs(Numero),
    Monte(Systeme, u32),
}

impl Objet {
    /// L'inode du tmpfs, si c'en est un.
    pub fn tmpfs(self) -> Option<Numero> {
        match self {
            Objet::Tmpfs(n) => Some(n),
            Objet::Monte(..) => None,
        }
    }

    /// Le système de l'objet : None pour le tmpfs.
    fn systeme(self) -> Option<Systeme> {
        match self {
            Objet::Tmpfs(_) => None,
            Objet::Monte(s, _) => Some(s),
        }
    }
}

/// Ce qu'on demande à un système monté (un peu des `inode_operations` et
/// des `file_operations` de Linux) : ses inodes sont numérotés par des
/// `u32`, sa racine est l'un d'eux.
pub trait Monte {
    fn racine(&self) -> u32;
    /// Son périphérique (majeur, mineur), le `st_dev` de ses inodes : un
    /// numéro anonyme, comme Linux en donne à procfs et sysfs.
    fn peripherique(&self) -> (u32, u32);
    /// La taille de bloc qu'il annonce (`st_blksize`) : 1024 pour procfs,
    /// une page pour sysfs (mesuré). stdio la prend pour ses tampons : c'est
    /// pourquoi la glibc lit /proc/self/maps par tranches de 1024 octets.
    fn taille_de_bloc(&self) -> u64;
    /// Ce que dit `stat` de l'inode `n` (son champ `numero` est `n`).
    fn attributs(&self, n: u32) -> Attributs;
    /// Ce que désigne `nom` dans le dossier `dossier`.
    fn chercher(&self, dossier: u32, nom: &[u8]) -> Option<u32>;
    /// Le parent du dossier (la racine est son propre parent).
    fn parent(&self, n: u32) -> u32;
    /// Le nom de `n` dans son parent (vide pour la racine).
    fn nom(&self, n: u32) -> &[u8];
    /// Le contenu du lien `lien`, pour le lecteur dont le numéro de
    /// processus s'écrit `lecteur` (/proc/self dépend de qui le lit).
    fn cible<'a>(&'a self, lien: u32, lecteur: &'a [u8]) -> &'a [u8];
    /// Les entrées du dossier à partir de `position`, comme
    /// `Tmpfs::lire_dossier` : `entree(nom, inode, type, position suivante)`
    /// tant qu'elle rend vrai.
    fn lire_dossier(&self, dossier: u32, position: u64, entree: &mut dyn FnMut(&[u8], u64, u8, u64) -> bool)
        -> Result<(), Erreur>;
    /// Ce que ce système répond à une modification de son arborescence ou
    /// de ses inodes, qui y reste entièrement (ce qui en sort a déjà été
    /// refusé par la `Vue`). Rien ne s'y modifie : c'est toujours une
    /// erreur, mais laquelle dépend du système (procfs, sysfs).
    fn refuser(&self, qui: Identite, m: Interne) -> Erreur;
}

/// Une modification qui reste dans un système monté, pour `Monte::refuser`.
#[derive(Clone, Copy, Debug)]
pub enum Interne {
    /// Créer un nom absent dans `dossier` (open avec O_CREAT si `ouvrir`,
    /// sinon mkdir, symlink, mknod, le nouveau nom de link ou de rename :
    /// Linux ne répond pas la même chose, `lookup_open` rendant EACCES là
    /// où `vfs_mkdir` et les autres rendent EPERM).
    Creer { dossier: u32, ouvrir: bool },
    /// Effacer `objet` de `dossier` (unlink, ou rmdir si `rmdir`).
    Effacer { dossier: u32, objet: u32, rmdir: bool },
    /// Renommer, dans le même système ; `nouveau` existe peut-être.
    Renommer { ancien: u32, nouveau: Option<u32> },
    /// Un lien physique vers `source`, dans le même système.
    Lier { source: u32 },
    ChangerMode { objet: u32 },
    /// `uid` et `gid` : None pour « sans changement ».
    ChangerProprietaire { objet: u32, uid: Option<u32>, gid: Option<u32> },
    /// `maintenant` : les deux dates à maintenant (un pointeur nul, ou
    /// UTIME_NOW), qui demande seulement le droit d'écrire ; sinon des
    /// dates données, qui demandent d'être le propriétaire.
    ChangerTemps { objet: u32, maintenant: bool },
    /// truncate.
    Tronquer { objet: u32 },
}

/// Ce qu'on crée : la couche commune ne répond pas de même à une barre
/// finale (seul mkdir l'accepte), ni le système à une ouverture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Creation {
    /// open avec O_CREAT.
    Ouvrir,
    /// mkdir.
    Dossier,
    /// symlink, mknod.
    Autre,
}

/// Une modification demandée, telle que la voit la couche commune.
#[derive(Clone, Copy)]
pub enum Modification<'a> {
    Creer(&'a Fin<Objet>, Creation),
    /// Effacer ; rmdir si vrai.
    Effacer(&'a Fin<Objet>, bool),
    /// Renommer, avec les drapeaux de renameat2 (déjà vérifiés).
    Renommer(&'a Fin<Objet>, &'a Fin<Objet>, u32),
    Lier(Objet, &'a Fin<Objet>),
    ChangerMode(Objet),
    ChangerProprietaire(Objet, Option<u32>, Option<u32>),
    ChangerTemps(Objet, bool),
    Tronquer(Objet),
}

/// Tous les systèmes, vus d'un processus : le tmpfs de la racine, et les
/// systèmes montés avec leur point de montage (un dossier du tmpfs, que le
/// montage tient). `lecteur` : le numéro du processus qui résout, écrit
/// en décimal.
pub struct Vue<'a> {
    pub fs: &'a Tmpfs,
    pub montes: &'a [(Numero, &'a dyn Monte)],
    pub lecteur: &'a [u8],
}

impl<'a> Vue<'a> {
    fn monte(&self, s: Systeme) -> &'a dyn Monte {
        self.montes[s.0 as usize].1
    }

    fn point(&self, s: Systeme) -> Numero {
        self.montes[s.0 as usize].0
    }

    /// L'objet qu'on voit à la place de l'inode `n` du tmpfs : la racine du
    /// système qui y est monté, s'il y en a un.
    fn par_dessus(&self, n: Numero) -> Objet {
        match self.montes.iter().position(|(point, _)| *point == n) {
            Some(i) => Objet::Monte(Systeme(i as u8), self.montes[i].1.racine()),
            None => Objet::Tmpfs(n),
        }
    }

    /// Le périphérique et la taille de bloc du système d'un objet monté
    /// (None pour le tmpfs, que le noyau connaît).
    pub fn peripherique(&self, o: Objet) -> Option<((u32, u32), u64)> {
        let s = o.systeme()?;
        Some((self.monte(s).peripherique(), self.monte(s).taille_de_bloc()))
    }

    /// Ce que dit `stat` de l'objet.
    pub fn attributs(&self, o: Objet) -> Attributs {
        match o {
            Objet::Tmpfs(n) => self.fs.attributs(n),
            Objet::Monte(s, n) => self.monte(s).attributs(n),
        }
    }

    /// Les entrées du dossier `o` (getdents64) : `entree(nom, inode, type,
    /// position suivante)`. Un point de montage s'y montre avec l'inode du
    /// dossier qui est dessous, comme sous Linux.
    pub fn lire_dossier(&self, o: Objet, position: u64, mut entree: impl FnMut(&[u8], u64, u8, u64) -> bool)
        -> Result<(), Erreur> {
        match o {
            Objet::Tmpfs(n) => self.fs.lire_dossier(n, position, |nom, numero, genre, suivante| {
                entree(nom, numero.0 as u64, genre, suivante)
            }),
            Objet::Monte(s, n) => self.monte(s).lire_dossier(n, position, &mut entree),
        }
    }

    /// Le chemin absolu du dossier `o` (getcwd), à travers les montages :
    /// celui du point de montage, puis les noms dans le système monté.
    /// ENOENT pour un dossier effacé, ENAMETOOLONG au-delà de PATH_MAX,
    /// comme `Tmpfs::chemin`.
    pub fn chemin(&self, o: Objet) -> Result<Vec<u8>, Erreur> {
        let (s, mut n) = match o {
            Objet::Tmpfs(n) => return self.fs.chemin(n),
            Objet::Monte(s, n) => (s, n),
        };
        let m = self.monte(s);
        let mut chemin = self.fs.chemin(self.point(s))?;
        // Les noms, du bas vers le haut, puis retournés.
        let mut noms: Vec<&[u8]> = Vec::new();
        let mut longueur = chemin.len();
        while n != m.racine() {
            longueur += m.nom(n).len() + 1;
            if longueur >= PATH_MAX {
                return Err(Erreur::ENAMETOOLONG);
            }
            noms.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
            noms.push(m.nom(n));
            n = m.parent(n);
        }
        chemin.try_reserve_exact(longueur - chemin.len()).map_err(|_| Erreur::ENOMEM)?;
        if chemin == b"/" {
            chemin.clear();
        }
        for nom in noms.iter().rev() {
            chemin.push(b'/');
            chemin.extend_from_slice(nom);
        }
        if chemin.is_empty() {
            chemin.push(b'/');
        }
        Ok(chemin)
    }

    /// L'erreur d'une modification qui touche un système monté (`fin` ou un
    /// objet qui n'est pas dans le tmpfs, ou un point de montage), dans
    /// l'ordre de Linux (mesuré sous Linux 6.18) :
    ///   - créer : un nom qui existe, EEXIST (même un point de montage,
    ///     mkdir("/proc")) ; une barre finale pour autre chose que mkdir,
    ///     ENOENT (`filename_create` ne crée alors pas) ; sinon le système
    ///     répond (procfs : ENOENT, sa recherche d'un nom absent échoue) ;
    ///   - effacer : comme `do_unlinkat` et `Tmpfs::effacer`, « . », « .. »
    ///     et la racine d'abord, puis un nom absent (ENOENT), puis une barre
    ///     finale pour unlink (EISDIR pour un dossier, ENOTDIR sinon) ; un
    ///     point de montage : `may_delete` dans son parent (le droit d'y
    ///     écrire, EACCES ; le bit collant, EPERM ; le type), puis EBUSY ;
    ///     ce qui est dans un système monté : le système répond ;
    ///   - renommer : d'un système à l'autre, EXDEV, vérifié tôt
    ///     (`do_renameat2` le fait dès qu'il a les deux dossiers, avant même
    ///     de chercher les noms) ; puis les vérifications de `do_renameat2`,
    ///     dans l'ordre de `Tmpfs::renommer`, avec les drapeaux ; puis
    ///     celles de `vfs_rename` : `may_delete` de l'ancien, `may_delete`
    ///     ou `may_create` du nouveau quand leur dossier est dans le tmpfs,
    ///     puis EBUSY pour un point de montage, et le système pour le reste ;
    ///   - lier : EEXIST, puis EXDEV (`do_linkat`, après avoir préparé le
    ///     nouveau nom, qu'un procfs refuse d'abord) ;
    ///   - tronquer : un dossier, EISDIR ; autre chose qu'un fichier
    ///     ordinaire, EINVAL (`vfs_truncate`) ; puis le système ;
    ///   - les autres attributs (droits, propriétaire, dates) : le
    ///     système répond.
    pub fn refus(&self, qui: Identite, m: Modification) -> Erreur {
        match m {
            Modification::Creer(fin, creation) => {
                if fin.objet.is_some() || fin.dernier != Dernier::Nom {
                    return Erreur::EEXIST;
                }
                if fin.barre && creation != Creation::Dossier {
                    return Erreur::ENOENT;
                }
                match fin.dossier {
                    Objet::Monte(s, d) => {
                        self.monte(s).refuser(qui, Interne::Creer { dossier: d, ouvrir: creation == Creation::Ouvrir })
                    }
                    // Le dossier est dans le tmpfs, le nom est absent : rien ne
                    // touche un système monté (l'appelant ne vient pas ici).
                    Objet::Tmpfs(_) => Erreur::EINVAL,
                }
            }
            Modification::Effacer(fin, rmdir) => {
                // « . », « .. », la racine : comme `Tmpfs::effacer`.
                match (fin.dernier, rmdir) {
                    (Dernier::Nom, _) => {}
                    (_, false) => return Erreur::EISDIR,
                    (Dernier::Point, true) => return Erreur::EINVAL,
                    (Dernier::PointPoint, true) => return Erreur::ENOTEMPTY,
                    (Dernier::Racine, true) => return Erreur::EBUSY,
                }
                let Some(objet) = fin.objet else { return Erreur::ENOENT };
                if !rmdir && fin.barre {
                    return if est_dossier(self, objet) { Erreur::EISDIR } else { Erreur::ENOTDIR };
                }
                match (fin.dossier, objet) {
                    (Objet::Tmpfs(d), Objet::Monte(s, _)) => self.point_occupe(qui, d, s, rmdir),
                    (Objet::Monte(s, d), Objet::Monte(_, n)) => {
                        self.monte(s).refuser(qui, Interne::Effacer { dossier: d, objet: n, rmdir })
                    }
                    _ => Erreur::EINVAL,
                }
            }
            Modification::Renommer(ancien, nouveau, drapeaux) => self.renommer(qui, ancien, nouveau, drapeaux),
            Modification::Lier(source, nouveau) => {
                if self.nom_refuse(qui, nouveau) {
                    return Erreur::ENOENT;
                }
                if nouveau.objet.is_some() {
                    return Erreur::EEXIST;
                }
                if source.systeme() != nouveau.dossier.systeme() {
                    return Erreur::EXDEV;
                }
                match source {
                    Objet::Monte(s, n) => self.monte(s).refuser(qui, Interne::Lier { source: n }),
                    Objet::Tmpfs(_) => Erreur::EINVAL,
                }
            }
            Modification::ChangerMode(o) => self.interne(qui, o, |n| Interne::ChangerMode { objet: n }),
            Modification::ChangerProprietaire(o, uid, gid) => {
                self.interne(qui, o, |n| Interne::ChangerProprietaire { objet: n, uid, gid })
            }
            Modification::ChangerTemps(o, maintenant) => {
                self.interne(qui, o, |n| Interne::ChangerTemps { objet: n, maintenant })
            }
            Modification::Tronquer(o) => {
                let mode = self.mode(o) & S_IFMT;
                if mode == S_IFDIR {
                    return Erreur::EISDIR;
                }
                if mode != S_IFREG {
                    return Erreur::EINVAL;
                }
                self.interne(qui, o, |n| Interne::Tronquer { objet: n })
            }
        }
    }

    /// Le nouveau nom absent `fin`, dans un système monté, y est-il refusé
    /// dès sa recherche ? (procfs : un nom absent n'y est jamais une
    /// entrée « négative », sa recherche échoue par ENOENT, avant toute
    /// autre vérification de link ou de rename.)
    fn nom_refuse(&self, qui: Identite, fin: &Fin<Objet>) -> bool {
        match (fin.dossier, fin.objet) {
            (Objet::Monte(s, d), None) => {
                self.monte(s).refuser(qui, Interne::Creer { dossier: d, ouvrir: false }) == Erreur::ENOENT
            }
            _ => false,
        }
    }

    /// `a` est-il `b`, ou un de ses ancêtres, dans le même système monté ?
    /// (Un dossier ne se renomme pas dans son propre sous-arbre.) Entre le
    /// tmpfs et un système monté, la question ne se pose pas ici : un point
    /// de montage cache tout ce qui est dessous.
    fn ancetre(&self, a: Objet, b: Objet) -> bool {
        let (Objet::Monte(s, a), Objet::Monte(t, mut b)) = (a, b) else { return false };
        if s != t {
            return false;
        }
        let m = self.monte(s);
        // Borné par la profondeur de l'arbre : un parent est toujours plus
        // près de la racine, qui est son propre parent.
        loop {
            if a == b {
                return true;
            }
            let p = m.parent(b);
            if p == b {
                return false;
            }
            b = p;
        }
    }

    /// rename dans un système monté, ou d'un point de montage (voir
    /// `refus`) : l'ordre de `do_renameat2`, puis de `vfs_rename`.
    fn renommer(&self, qui: Identite, ancien: &Fin<Objet>, nouveau: &Fin<Objet>, drapeaux: u32) -> Erreur {
        let echange = drapeaux & RENAME_EXCHANGE != 0;
        let sans_ecraser = drapeaux & RENAME_NOREPLACE != 0;
        if ancien.dossier.systeme() != nouveau.dossier.systeme() {
            return Erreur::EXDEV;
        }
        if ancien.dernier != Dernier::Nom {
            return Erreur::EBUSY;
        }
        if nouveau.dernier != Dernier::Nom {
            return if sans_ecraser { Erreur::EEXIST } else { Erreur::EBUSY };
        }
        let Some(source) = ancien.objet else { return Erreur::ENOENT };
        if self.nom_refuse(qui, nouveau) {
            return Erreur::ENOENT;
        }
        let cible = nouveau.objet;
        if sans_ecraser && cible.is_some() {
            return Erreur::EEXIST;
        }
        if echange {
            let Some(c) = cible else { return Erreur::ENOENT };
            if !est_dossier(self, c) && nouveau.barre {
                return Erreur::ENOTDIR;
            }
        }
        let dossier_source = est_dossier(self, source);
        if !dossier_source && (ancien.barre || (!echange && nouveau.barre)) {
            return Erreur::ENOTDIR;
        }
        if dossier_source && self.ancetre(source, nouveau.dossier) {
            return Erreur::EINVAL;
        }
        if let Some(c) = cible
            && est_dossier(self, c)
            && self.ancetre(c, ancien.dossier)
        {
            return if echange { Erreur::EINVAL } else { Erreur::ENOTEMPTY };
        }
        // `may_delete` et `may_create`, pour ce qui est dans un dossier du
        // tmpfs : l'objet du tmpfs d'un point de montage est le dossier
        // qu'il cache.
        let dans_le_tmpfs = |o: Objet| match o {
            Objet::Tmpfs(n) => n,
            Objet::Monte(s, _) => self.point(s),
        };
        if let Objet::Tmpfs(d) = ancien.dossier
            && let Err(e) = self.fs.peut_effacer(qui, d, dans_le_tmpfs(source), dossier_source)
        {
            return e;
        }
        if let Objet::Tmpfs(d) = nouveau.dossier {
            let r = match cible {
                Some(c) => {
                    let attendu = if echange { est_dossier(self, c) } else { dossier_source };
                    self.fs.peut_effacer(qui, d, dans_le_tmpfs(c), attendu)
                }
                None => self.fs.peut_creer(qui, d),
            };
            if let Err(e) = r {
                return e;
            }
        }
        match (ancien.dossier, source) {
            // Un point de montage, d'un côté ou de l'autre.
            (Objet::Tmpfs(_), _) => Erreur::EBUSY,
            (Objet::Monte(s, _), Objet::Monte(_, a)) => {
                let n = cible.and_then(|o| match o {
                    Objet::Monte(_, n) => Some(n),
                    Objet::Tmpfs(_) => None,
                });
                self.monte(s).refuser(qui, Interne::Renommer { ancien: a, nouveau: n })
            }
            _ => Erreur::EINVAL,
        }
    }

    /// Effacer un point de montage (`s` est monté sur un dossier du tmpfs
    /// que contient `d`) : `may_delete` d'abord (le droit d'écrire dans `d`,
    /// EACCES ; son bit collant, EPERM ; unlink d'un dossier, EISDIR), puis
    /// il est occupé (EBUSY), comme `is_local_mountpoint` dans Linux.
    fn point_occupe(&self, qui: Identite, d: Numero, s: Systeme, rmdir: bool) -> Erreur {
        match self.fs.peut_effacer(qui, d, self.point(s), rmdir) {
            Err(e) => e,
            Ok(()) => Erreur::EBUSY,
        }
    }

    fn interne(&self, qui: Identite, o: Objet, m: impl FnOnce(u32) -> Interne) -> Erreur {
        match o {
            Objet::Monte(s, n) => self.monte(s).refuser(qui, m(n)),
            Objet::Tmpfs(_) => Erreur::EINVAL,
        }
    }
}

/// `fin` est-il entièrement dans le tmpfs (son dossier, et son objet s'il
/// existe, qui n'est pas la racine d'un système monté) ?
pub fn dans_le_tmpfs(fin: &Fin<Objet>) -> bool {
    fin.dossier.tmpfs().is_some() && fin.objet.is_none_or(|o| o.tmpfs().is_some())
}

/// `fin` entièrement dans le tmpfs : le même résultat, pour les opérations
/// du tmpfs. Sinon il est rendu tel quel, pour `Vue::refus`.
pub fn en_tmpfs(fin: Fin<Objet>) -> Result<Fin<Numero>, Fin<Objet>> {
    let dossier = fin.dossier.tmpfs();
    let objet = match fin.objet {
        None => Some(None),
        Some(o) => o.tmpfs().map(Some),
    };
    match (dossier, objet) {
        (Some(dossier), Some(objet)) => {
            Ok(Fin { dossier, nom: fin.nom, objet, dernier: fin.dernier, barre: fin.barre })
        }
        _ => Err(fin),
    }
}

impl Arbre for Vue<'_> {
    type Objet = Objet;

    fn mode(&self, o: Objet) -> u32 {
        match o {
            Objet::Tmpfs(n) => self.fs.mode(n),
            Objet::Monte(s, n) => self.monte(s).attributs(n).mode,
        }
    }

    fn proprietaire(&self, o: Objet) -> (u32, u32) {
        match o {
            Objet::Tmpfs(n) => <Tmpfs as Arbre>::proprietaire(self.fs, n),
            Objet::Monte(s, n) => {
                let a = self.monte(s).attributs(n);
                (a.uid, a.gid)
            }
        }
    }

    fn chercher(&self, dossier: Objet, nom: &[u8]) -> Option<Objet> {
        match dossier {
            Objet::Tmpfs(d) => <Tmpfs as Arbre>::chercher(self.fs, d, nom).map(|n| self.par_dessus(n)),
            Objet::Monte(s, d) => self.monte(s).chercher(d, nom).map(|n| Objet::Monte(s, n)),
        }
    }

    fn parent(&self, dossier: Objet) -> Objet {
        match dossier {
            Objet::Tmpfs(d) => self.par_dessus(<Tmpfs as Arbre>::parent(self.fs, d)),
            Objet::Monte(s, d) if d == self.monte(s).racine() => {
                self.par_dessus(<Tmpfs as Arbre>::parent(self.fs, self.point(s)))
            }
            Objet::Monte(s, d) => Objet::Monte(s, self.monte(s).parent(d)),
        }
    }

    fn cible(&self, lien: Objet) -> &[u8] {
        match lien {
            Objet::Tmpfs(n) => <Tmpfs as Arbre>::cible(self.fs, n),
            Objet::Monte(s, n) => self.monte(s).cible(n, self.lecteur),
        }
    }
}

/// Le dossier `o` est-il un dossier ? (Pour la couche commune.)
pub fn est_dossier(vue: &Vue, o: Objet) -> bool {
    vue.mode(o) & S_IFMT == S_IFDIR
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chemins::{Depart, Suivre, resoudre, trouver};
    use crate::tmpfs::Limites;
    use crate::{S_IFLNK, Temps};
    use alloc::vec;

    /// Un petit système à monter : une racine (0), un dossier « d » (1) qui
    /// contient un fichier « f » (2), et un lien « soi » (3) vers le lecteur.
    struct Petit;
    const NOMS: [&[u8]; 4] = [b"", b"d", b"f", b"soi"];
    const PARENTS: [u32; 4] = [0, 0, 1, 0];
    impl Monte for Petit {
        fn racine(&self) -> u32 {
            0
        }
        fn peripherique(&self) -> (u32, u32) {
            (0, 21)
        }
        fn taille_de_bloc(&self) -> u64 {
            1024
        }
        fn attributs(&self, n: u32) -> Attributs {
            let mode = match n {
                0 | 1 => S_IFDIR | 0o555,
                2 => S_IFREG | 0o444,
                _ => S_IFLNK | 0o777,
            };
            Attributs {
                numero: Numero(n),
                mode,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: (0, 0),
                taille: 0,
                blocs: 0,
                atime: Temps::default(),
                mtime: Temps::default(),
                ctime: Temps::default(),
            }
        }
        fn chercher(&self, dossier: u32, nom: &[u8]) -> Option<u32> {
            (0..4).find(|&n| n != 0 && PARENTS[n as usize] == dossier && NOMS[n as usize] == nom)
        }
        fn parent(&self, n: u32) -> u32 {
            PARENTS[n as usize]
        }
        fn nom(&self, n: u32) -> &[u8] {
            NOMS[n as usize]
        }
        fn cible<'a>(&'a self, _: u32, lecteur: &'a [u8]) -> &'a [u8] {
            lecteur
        }
        fn lire_dossier(&self, dossier: u32, position: u64, entree: &mut dyn FnMut(&[u8], u64, u8, u64) -> bool)
            -> Result<(), Erreur> {
            for n in 1..4u32 {
                if PARENTS[n as usize] == dossier && n as u64 > position && !entree(NOMS[n as usize], n as u64, 0, n as u64) {
                    break;
                }
            }
            Ok(())
        }
        fn refuser(&self, _: Identite, m: Interne) -> Erreur {
            match m {
                Interne::Creer { .. } => Erreur::ENOENT,
                _ => Erreur::EPERM,
            }
        }
    }

    const DAVID: Identite = Identite { uid: 1000, gid: 1000 };

    /// Un tmpfs avec /proc (le point de montage), /tmp, et un lien
    /// /lien-proc -> proc/d.
    fn arbre() -> (Tmpfs, Numero) {
        let mut fs = Tmpfs::new(Limites { inodes: 100, pages: 0 }, Temps::default()).unwrap();
        let racine = fs.racine();
        let depart = Depart { racine, dossier: racine, qui: Identite::ROOT, sous: false };
        let creer = |fs: &mut Tmpfs, chemin: &[u8], mode: u32, cible: &[u8]| {
            let fin = resoudre(fs, &depart, chemin, Suivre::Jamais).unwrap();
            fs.creer(Identite::ROOT, &fin, mode, (0, 0), cible, Temps::default()).unwrap()
        };
        let proc_ = creer(&mut fs, b"/proc", S_IFDIR | 0o555, b"");
        creer(&mut fs, b"/tmp", S_IFDIR | 0o1777, b"");
        creer(&mut fs, b"/lien-proc", S_IFLNK | 0o777, b"proc/d");
        (fs, proc_)
    }

    #[test]
    fn traverser_le_montage() {
        let (fs, point) = arbre();
        let petit = Petit;
        let montes: [(Numero, &dyn Monte); 1] = [(point, &petit)];
        let vue = Vue { fs: &fs, montes: &montes, lecteur: b"42" };
        let racine = Objet::Tmpfs(fs.racine());
        let depart = Depart { racine, dossier: racine, qui: DAVID, sous: false };
        let p = Systeme(0);
        // Le point de montage montre la racine du système monté.
        assert_eq!(trouver(&vue, &depart, b"/proc", true), Ok(Objet::Monte(p, 0)));
        assert_eq!(trouver(&vue, &depart, b"/proc/d/f", true), Ok(Objet::Monte(p, 2)));
        // Et « .. » en sort, d'où qu'on vienne.
        assert_eq!(trouver(&vue, &depart, b"/proc/..", true), Ok(racine));
        assert_eq!(trouver(&vue, &depart, b"/proc/d/../../tmp", true), trouver(&vue, &depart, b"/tmp", true));
        // Un lien du tmpfs qui mène dans le système monté, et un lien du
        // système monté (sa cible dépend du lecteur : « 42 », relatif).
        assert_eq!(trouver(&vue, &depart, b"/lien-proc/f", true), Ok(Objet::Monte(p, 2)));
        assert_eq!(trouver(&vue, &depart, b"/proc/soi", true), Err(Erreur::ENOENT));
        // Un chemin relatif depuis un dossier du système monté.
        let dedans = Depart { dossier: Objet::Monte(p, 1), ..depart };
        assert_eq!(trouver(&vue, &dedans, b"f", true), Ok(Objet::Monte(p, 2)));
        assert_eq!(trouver(&vue, &dedans, b"../../tmp", true), trouver(&vue, &depart, b"/tmp", true));
        // Une barre finale sur un fichier du système monté : ENOTDIR.
        assert_eq!(trouver(&vue, &depart, b"/proc/d/f/", true), Err(Erreur::ENOTDIR));
        // La résolution « sous » un dossier (WASI) ne sort pas plus d'un
        // système monté que du tmpfs.
        let sous = Depart { dossier: Objet::Monte(p, 1), sous: true, ..depart };
        assert_eq!(trouver(&vue, &sous, b"../../tmp", true), Err(Erreur::EXDEV));
        // Une barre finale sur le point de montage : le dossier monté.
        assert_eq!(trouver(&vue, &depart, b"/proc/", true), Ok(Objet::Monte(p, 0)));
        // Une racine de processus dans le système monté (un chroot) : « .. »
        // ne la dépasse pas.
        let enferme = Depart { racine: Objet::Monte(p, 0), dossier: Objet::Monte(p, 1), ..depart };
        assert_eq!(trouver(&vue, &enferme, b"../..", true), Ok(Objet::Monte(p, 0)));
        assert_eq!(trouver(&vue, &enferme, b"/d/f", true), Ok(Objet::Monte(p, 2)));
    }

    #[test]
    fn chemins_et_attributs() {
        let (fs, point) = arbre();
        let petit = Petit;
        let montes: [(Numero, &dyn Monte); 1] = [(point, &petit)];
        let vue = Vue { fs: &fs, montes: &montes, lecteur: b"42" };
        let p = Systeme(0);
        assert_eq!(vue.chemin(Objet::Monte(p, 0)).unwrap(), b"/proc");
        assert_eq!(vue.chemin(Objet::Monte(p, 1)).unwrap(), b"/proc/d");
        assert_eq!(vue.chemin(Objet::Tmpfs(fs.racine())).unwrap(), b"/");
        assert_eq!(vue.attributs(Objet::Monte(p, 2)).mode, S_IFREG | 0o444);
        assert_eq!(vue.peripherique(Objet::Monte(p, 2)), Some(((0, 21), 1024)));
        assert_eq!(vue.peripherique(Objet::Tmpfs(fs.racine())), None);
        assert!(est_dossier(&vue, Objet::Monte(p, 1)));
        let mut noms = vec![];
        vue.lire_dossier(Objet::Monte(p, 0), 0, |nom, _, _, _| {
            noms.push(nom.to_vec());
            true
        })
        .unwrap();
        assert_eq!(noms, vec![b"d".to_vec(), b"soi".to_vec()]);
        // Le point de montage se lit dans la racine avec l'inode du dossier
        // qui est dessous.
        let mut vu = None;
        vue.lire_dossier(Objet::Tmpfs(fs.racine()), 0, |nom, n, _, _| {
            if nom == b"proc" {
                vu = Some(n);
            }
            true
        })
        .unwrap();
        assert_eq!(vu, Some(point.0 as u64));
    }

    #[test]
    fn modifications_refusees() {
        let (fs, point) = arbre();
        let petit = Petit;
        let racine = Objet::Tmpfs(fs.racine());
        let fin = |fs: &Tmpfs, qui: Identite, chemin: &[u8]| {
            let montes: [(Numero, &dyn Monte); 1] = [(point, &petit)];
            let vue = Vue { fs, montes: &montes, lecteur: b"42" };
            let depart = Depart { racine, dossier: racine, qui, sous: false };
            resoudre(&vue, &depart, chemin, Suivre::Jamais).unwrap()
        };
        let refus = |fs: &Tmpfs, qui: Identite, m: Modification| {
            let montes: [(Numero, &dyn Monte); 1] = [(point, &petit)];
            Vue { fs, montes: &montes, lecteur: b"42" }.refus(qui, m)
        };
        let dans = fin(&fs, DAVID, b"/proc/d/neuf");
        let existe = fin(&fs, DAVID, b"/proc/d/f");
        let point_fin = fin(&fs, DAVID, b"/proc");
        let tmp = fin(&fs, DAVID, b"/tmp/x");
        // Créer : le système répond (ENOENT ici) ; un nom qui existe, même
        // le point de montage : EEXIST.
        assert_eq!(refus(&fs, DAVID, Modification::Creer(&dans, Creation::Autre)), Erreur::ENOENT);
        assert_eq!(refus(&fs, DAVID, Modification::Creer(&existe, Creation::Autre)), Erreur::EEXIST);
        assert_eq!(refus(&fs, DAVID, Modification::Creer(&point_fin, Creation::Autre)), Erreur::EEXIST);
        // Effacer le point de montage : sans le droit d'écrire dans « / »,
        // EACCES ; root : EBUSY (rmdir), EISDIR (unlink).
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&point_fin, true)), Erreur::EACCES);
        let point_root = fin(&fs, Identite::ROOT, b"/proc");
        assert_eq!(refus(&fs, Identite::ROOT, Modification::Effacer(&point_root, true)), Erreur::EBUSY);
        assert_eq!(refus(&fs, Identite::ROOT, Modification::Effacer(&point_root, false)), Erreur::EISDIR);
        // Effacer dans le système : absent ENOENT, sinon le système (EPERM).
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&dans, false)), Erreur::ENOENT);
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&existe, false)), Erreur::EPERM);
        // Renommer ou lier d'un système à l'autre : EXDEV, même si l'ancien
        // n'existe pas ; lier vers un dossier qui refuse les noms absents :
        // son erreur d'abord.
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&existe, &tmp, 0)), Erreur::EXDEV);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&dans, &tmp, 0)), Erreur::EXDEV);
        // Vers un nom absent d'un système qui refuse les noms absents dès
        // leur recherche (Petit, comme procfs) : ENOENT, avant le reste.
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&existe, &dans, 0)), Erreur::ENOENT);
        assert_eq!(refus(&fs, DAVID, Modification::Lier(existe.objet.unwrap(), &tmp)), Erreur::EXDEV);
        assert_eq!(refus(&fs, DAVID, Modification::Lier(existe.objet.unwrap(), &dans)), Erreur::ENOENT);
        // Renommer le point de montage : le droit d'écrire, puis EBUSY.
        let tmp_root = fin(&fs, Identite::ROOT, b"/tmp/x");
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&point_fin, &tmp, 0)), Erreur::EACCES);
        assert_eq!(refus(&fs, Identite::ROOT, Modification::Renommer(&point_root, &tmp_root, 0)), Erreur::EBUSY);
        // Les attributs : le système répond.
        assert_eq!(refus(&fs, DAVID, Modification::ChangerMode(existe.objet.unwrap())), Erreur::EPERM);
        // Tronquer un dossier monté : EISDIR, avant le système.
        assert_eq!(refus(&fs, DAVID, Modification::Tronquer(Objet::Monte(Systeme(0), 1))), Erreur::EISDIR);
        // Une barre finale, pour unlink : un fichier, ENOTDIR ; un dossier
        // ou le point de montage, EISDIR ; avant les droits et le système.
        let f_barre = fin(&fs, DAVID, b"/proc/d/f/");
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&f_barre, false)), Erreur::ENOTDIR);
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&fin(&fs, DAVID, b"/proc/d/"), false)), Erreur::EISDIR);
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&fin(&fs, DAVID, b"/proc/"), false)), Erreur::EISDIR);
        // « . » et « .. » : unlink EISDIR, rmdir EINVAL et ENOTEMPTY ;
        // créer, EEXIST.
        let point_d = fin(&fs, DAVID, b"/proc/d/.");
        let point_point_d = fin(&fs, DAVID, b"/proc/d/..");
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&point_d, false)), Erreur::EISDIR);
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&point_d, true)), Erreur::EINVAL);
        assert_eq!(refus(&fs, DAVID, Modification::Effacer(&point_point_d, true)), Erreur::ENOTEMPTY);
        for c in [&point_d, &point_point_d, &point_fin] {
            assert_eq!(refus(&fs, DAVID, Modification::Creer(c, Creation::Dossier)), Erreur::EEXIST);
        }
        // Créer avec une barre finale autre chose qu'un dossier : ENOENT.
        let neuf_barre = fin(&fs, DAVID, b"/tmp/x/");
        let neuf_barre = Fin { dossier: Objet::Monte(Systeme(0), 1), ..neuf_barre };
        assert_eq!(refus(&fs, DAVID, Modification::Creer(&neuf_barre, Creation::Autre)), Erreur::ENOENT);
        // Renommer, dans l'ordre de Linux : « . » des deux côtés, EBUSY (et
        // EEXIST avec NOREPLACE pour le nouveau) ; l'ancien absent, ENOENT ;
        // un nouveau qui existe et NOREPLACE, EEXIST ; EXCHANGE sans
        // nouveau, ENOENT ; une barre finale sur un fichier, ENOTDIR ; un
        // dossier dans son propre sous-arbre, EINVAL.
        let soi = fin(&fs, DAVID, b"/proc/soi");
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&point_d, &soi, 0)), Erreur::EBUSY);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&existe, &point_d, 0)), Erreur::EBUSY);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&existe, &point_d, RENAME_NOREPLACE)), Erreur::EEXIST);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&dans, &soi, 0)), Erreur::ENOENT);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&existe, &soi, RENAME_NOREPLACE)), Erreur::EEXIST);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&point_fin, &tmp, RENAME_EXCHANGE)), Erreur::ENOENT);
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&f_barre, &soi, 0)), Erreur::ENOTDIR);
        let d = fin(&fs, DAVID, b"/proc/d");
        assert_eq!(refus(&fs, DAVID, Modification::Renommer(&d, &existe, 0)), Erreur::EINVAL);
        // Renommer un fichier du tmpfs sur le point de montage : `may_delete`
        // du nouveau d'abord (root : un dossier attendu fichier, EISDIR).
        let fichier_root = fin(&fs, Identite::ROOT, b"/lien-proc");
        assert_eq!(refus(&fs, Identite::ROOT, Modification::Renommer(&fichier_root, &point_root, 0)), Erreur::EISDIR);
        // Lier vers un nom qui existe : EEXIST.
        assert_eq!(refus(&fs, DAVID, Modification::Lier(existe.objet.unwrap(), &existe)), Erreur::EEXIST);
        // en_tmpfs : seulement ce qui est entièrement dans le tmpfs.
        assert!(dans_le_tmpfs(&fin(&fs, DAVID, b"/tmp/x")) && !dans_le_tmpfs(&fin(&fs, DAVID, b"/proc")));
        assert!(en_tmpfs(fin(&fs, DAVID, b"/tmp/x")).is_ok());
        assert!(en_tmpfs(fin(&fs, DAVID, b"/proc")).is_err());
        assert!(en_tmpfs(fin(&fs, DAVID, b"/proc/d/f")).is_err());
    }
}
