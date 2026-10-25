//! La résolution des chemins : de « /home/utilisateur/../../etc/./hosts »
//! à l'objet qu'il désigne. C'est le `namei` de Linux (fs/namei.c,
//! `link_path_walk` et `walk_component`), dans le même ordre :
//!   - un chemin absolu part de la racine du processus, un chemin relatif
//!     du dossier de départ (le dossier courant, ou celui d'un descripteur
//!     pour les appels `*at`) ;
//!   - on avance composant par composant ; il faut le droit de TRAVERSER
//!     (x) chaque dossier pour y chercher un nom ;
//!   - « . » reste sur place, « .. » remonte au parent (jamais au-dessus de
//!     la racine du processus) ;
//!   - un lien symbolique au milieu du chemin est toujours suivi : son
//!     contenu remplace le composant, relatif au dossier où est le lien (ou
//!     à la racine s'il commence par « / ») ; au plus 40 liens suivis en
//!     tout (MAXSYMLINKS), au-delà ELOOP : c'est ce qui arrête une boucle ;
//!   - le DERNIER composant est traité à part : selon l'appel, un lien
//!     symbolique y est suivi (open, stat) ou non (lstat, unlink, rename) ;
//!     et il peut ne pas exister (open avec O_CREAT, mkdir...). La
//!     résolution rend donc le dossier où il est (ou serait), son nom, et
//!     ce qu'il désigne s'il existe : à chaque appel de décider (le
//!     `path_parentat` suivi d'une recherche, dans Linux) ;
//!   - une barre finale (« d/ ») veut un dossier : elle fait suivre un lien
//!     final (sauf pour open avec O_CREAT, qui la refuse d'emblée), et
//!     c'est à l'appel de refuser un fichier (ENOTDIR, ou EISDIR avec
//!     O_CREAT, comme Linux).
//!
//! La résolution ne connaît d'un système de fichiers que le trait `Arbre`.
//! Traverser un point de montage, c'est à son implémentation de le faire :
//! chercher un nom dont l'inode est un point de montage rend la racine du
//! système monté, et le parent de cette racine est le parent du point de
//! montage. C'est ce que fera le noyau quand `/proc` sera monté (6d) ; la
//! résolution, elle, ne changera pas.
//!
//! Sans récursion : les liens en cours sont dans une pile explicite (prise
//! au tas, faillible), comme le `nd->stack` de Linux. La pile du noyau ne
//! fait que 16 Kio, et 40 liens imbriqués y tiendraient mal. Les contenus
//! des liens ne sont pas copiés : la résolution les lit en place, dans
//! l'arbre, qu'elle ne modifie pas.
//!
//! Une option pour WASI : la résolution « sous » le dossier de départ (le
//! RESOLVE_BENEATH d'`openat2`) refuse tout ce qui en sortirait, un « .. »
//! au-dessus de lui comme un chemin ou un lien absolus (EXDEV). C'est ce
//! qui confine un programme WebAssembly à son dossier pré-ouvert.

use crate::{EXECUTER, Erreur, Identite, S_IFDIR, S_IFLNK, S_IFMT, permis};
use alloc::vec::Vec;

/// La plus longue chaîne de chemin acceptée, zéro final compris : un
/// chemin de 4096 octets ou plus est refusé (ENAMETOOLONG), comme Linux.
pub const PATH_MAX: usize = 4096;
/// Le plus long nom d'un composant.
pub const NAME_MAX: usize = 255;
/// Le plus de liens symboliques suivis pour un chemin (MAXSYMLINKS).
pub const LIENS_MAX: u32 = 40;

/// Ce que la résolution doit savoir d'un système de fichiers (le
/// `inode_operations->lookup` de Linux, et un peu plus).
pub trait Arbre {
    /// Ce qui désigne un objet de l'arbre (un numéro d'inode, ou le couple
    /// système de fichiers et numéro).
    type Objet: Copy + Eq;
    /// Son mode (type et droits, comme st_mode).
    fn mode(&self, objet: Self::Objet) -> u32;
    /// Son propriétaire : utilisateur et groupe.
    fn proprietaire(&self, objet: Self::Objet) -> (u32, u32);
    /// Ce que désigne `nom` (ni « . » ni « .. ») dans le dossier `dossier`.
    fn chercher(&self, dossier: Self::Objet, nom: &[u8]) -> Option<Self::Objet>;
    /// Le parent du dossier (la racine est son propre parent).
    fn parent(&self, dossier: Self::Objet) -> Self::Objet;
    /// Le contenu du lien symbolique `lien`.
    fn cible(&self, lien: Self::Objet) -> &[u8];
}

/// D'où part la résolution, et pour qui.
#[derive(Clone, Copy, Debug)]
pub struct Depart<O> {
    /// La racine du processus : un chemin absolu part d'ici, et « .. » n'y
    /// remonte pas plus haut.
    pub racine: O,
    /// Le dossier d'où part un chemin relatif.
    pub dossier: O,
    /// Celui dont on vérifie le droit de traverser.
    pub qui: Identite,
    /// Rester sous `dossier` (RESOLVE_BENEATH) : pour WASI.
    pub sous: bool,
}

/// Que faire d'un lien symbolique en dernier composant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Suivre {
    /// Le suivre : open, stat, chdir...
    Toujours,
    /// Seulement si le chemin finit par une barre (« lien/ » désigne le
    /// dossier, même pour lstat ou O_NOFOLLOW, comme Linux).
    AvecBarre,
    /// Toujours, sauf devant une barre finale : open avec O_CREAT, qui
    /// refuse alors « lien/ » (EISDIR) sans regarder où il mène.
    SaufBarre,
    /// Jamais : les appels qui agissent sur le nom lui-même (unlink, rmdir,
    /// rename, link, mkdir, symlink), barre finale ou non.
    Jamais,
}

/// Ce qu'était le dernier composant (le `last_type` de Linux).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dernier {
    /// Un nom ordinaire.
    Nom,
    /// « . »
    Point,
    /// « .. »
    PointPoint,
    /// Le chemin ne désignait que la racine (« / », « /// »).
    Racine,
}

/// Le résultat de la résolution : où est le dernier composant.
#[derive(Debug)]
pub struct Fin<O> {
    /// Le dossier qui contient (ou contiendrait) le dernier composant.
    pub dossier: O,
    /// Son nom (vide si ce n'est pas un nom ordinaire).
    pub nom: Vec<u8>,
    /// Ce qu'il désigne, s'il existe. Pour « . », « .. » et la racine, le
    /// dossier désigné.
    pub objet: Option<O>,
    pub dernier: Dernier,
    /// Le chemin finit-il par une barre (ou un lien final suivi, dont le
    /// nom était suivi d'une barre) ?
    pub barre: bool,
}

/// Un morceau de chemin en cours de lecture : le chemin donné, ou le
/// contenu d'un lien qu'on suit.
struct Morceau<'a> {
    texte: &'a [u8],
    position: usize,
    /// Le lien dont c'est le contenu était le dernier composant, suivi d'une
    /// barre : le dernier composant de ce contenu en hérite.
    barre: bool,
}

impl Morceau<'_> {
    fn sauter_barres(&mut self) {
        while self.texte.get(self.position) == Some(&b'/') {
            self.position += 1;
        }
    }

    fn epuise(&self) -> bool {
        self.position == self.texte.len()
    }
}

fn type_de(mode: u32) -> u32 {
    mode & S_IFMT
}

/// Résout `chemin` depuis `depart`, jusqu'au dernier composant (voir
/// l'en-tête). Erreurs, dans l'ordre où on les rencontre : chemin vide
/// (ENOENT) ou trop long (ENAMETOOLONG) ; dossier de départ qui n'en est
/// pas un (ENOTDIR) ; puis pour chaque composant : pas le droit de
/// traverser (EACCES), nom trop long (ENAMETOOLONG), introuvable au
/// milieu du chemin (ENOENT), pas un dossier au milieu (ENOTDIR), trop de
/// liens (ELOOP), lien vide (ENOENT), sortie du dossier de départ (EXDEV).
pub fn resoudre<'a, A: Arbre>(arbre: &'a A, depart: &Depart<A::Objet>, chemin: &'a [u8], suivre: Suivre)
    -> Result<Fin<A::Objet>, Erreur> {
    if chemin.is_empty() {
        return Err(Erreur::ENOENT);
    }
    if chemin.len() >= PATH_MAX {
        return Err(Erreur::ENAMETOOLONG);
    }
    let est_dossier = |o: A::Objet| type_de(arbre.mode(o)) == S_IFDIR;
    let mut courant = if chemin[0] == b'/' {
        if depart.sous {
            return Err(Erreur::EXDEV);
        }
        depart.racine
    } else {
        if !est_dossier(depart.dossier) {
            return Err(Erreur::ENOTDIR);
        }
        depart.dossier
    };
    let mut pile: Vec<Morceau<'a>> = Vec::new();
    pile.try_reserve(4).map_err(|_| Erreur::ENOMEM)?;
    pile.push(Morceau { texte: chemin, position: 0, barre: false });
    let mut liens = 0u32;
    loop {
        // Les morceaux finis (des barres, puis rien) cèdent la place à
        // celui d'en dessous.
        while let Some(m) = pile.last_mut() {
            m.sauter_barres();
            if !m.epuise() {
                break;
            }
            pile.pop();
        }
        let Some(haut) = pile.len().checked_sub(1) else {
            // Plus aucun composant : le chemin (ou le contenu d'un lien
            // final suivi) ne désignait que la racine.
            return Ok(Fin { dossier: courant, nom: Vec::new(), objet: Some(courant), dernier: Dernier::Racine, barre: false });
        };
        // Le composant suivant, et ce qui le suit.
        let m = &mut pile[haut];
        let debut = m.position;
        let fin = m.texte[debut..].iter().position(|&o| o == b'/').map_or(m.texte.len(), |p| debut + p);
        let texte = m.texte;
        let nom = &texte[debut..fin];
        let barre_ici = fin < texte.len();
        m.position = fin;
        m.sauter_barres();
        let barre_heritee = m.barre;
        let dernier = pile.iter().all(Morceau::epuise);
        let barre = dernier && (barre_ici || barre_heritee);

        // Le droit de traverser le dossier, avant d'y chercher quoi que ce
        // soit (même « . » et « .. », comme le may_lookup de Linux).
        let (uid, gid) = arbre.proprietaire(courant);
        if !permis(arbre.mode(courant), uid, gid, depart.qui, EXECUTER) {
            return Err(Erreur::EACCES);
        }
        if nom.len() > NAME_MAX {
            return Err(Erreur::ENAMETOOLONG);
        }
        if nom == b"." {
            if dernier {
                return Ok(Fin { dossier: courant, nom: Vec::new(), objet: Some(courant), dernier: Dernier::Point, barre });
            }
            continue;
        }
        if nom == b".." {
            if depart.sous && courant == depart.dossier {
                return Err(Erreur::EXDEV);
            }
            let parent = if courant == depart.racine { courant } else { arbre.parent(courant) };
            if dernier {
                return Ok(Fin { dossier: courant, nom: Vec::new(), objet: Some(parent), dernier: Dernier::PointPoint, barre });
            }
            courant = parent;
            continue;
        }
        let objet = arbre.chercher(courant, nom);
        let lien = objet.filter(|&o| type_de(arbre.mode(o)) == S_IFLNK);
        if dernier {
            let suivre_ici = match suivre {
                Suivre::Toujours => true,
                Suivre::AvecBarre => barre,
                Suivre::SaufBarre => !barre,
                Suivre::Jamais => false,
            };
            if let Some(lien) = lien.filter(|_| suivre_ici) {
                courant = suivre_lien(arbre, depart, lien, &mut liens, &mut pile, barre, courant)?;
                continue;
            }
            let mut copie = Vec::new();
            copie.try_reserve_exact(nom.len()).map_err(|_| Erreur::ENOMEM)?;
            copie.extend_from_slice(nom);
            return Ok(Fin { dossier: courant, nom: copie, objet, dernier: Dernier::Nom, barre });
        }
        let Some(objet) = objet else {
            return Err(Erreur::ENOENT);
        };
        if let Some(lien) = lien {
            courant = suivre_lien(arbre, depart, lien, &mut liens, &mut pile, false, courant)?;
            continue;
        }
        if !est_dossier(objet) {
            return Err(Erreur::ENOTDIR);
        }
        courant = objet;
    }
}

/// Suit le lien `lien`, rencontré dans le dossier `courant` : son contenu
/// devient le morceau à lire. Rend le dossier d'où il part.
fn suivre_lien<'a, A: Arbre>(arbre: &'a A, depart: &Depart<A::Objet>, lien: A::Objet, liens: &mut u32,
                             pile: &mut Vec<Morceau<'a>>, barre: bool, courant: A::Objet) -> Result<A::Objet, Erreur> {
    *liens += 1;
    if *liens > LIENS_MAX {
        return Err(Erreur::ELOOP);
    }
    let cible = arbre.cible(lien);
    if cible.is_empty() {
        return Err(Erreur::ENOENT);
    }
    let depuis = if cible[0] == b'/' {
        if depart.sous {
            return Err(Erreur::EXDEV);
        }
        depart.racine
    } else {
        courant
    };
    pile.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
    pile.push(Morceau { texte: cible, position: 0, barre });
    Ok(depuis)
}

/// Résout `chemin` jusqu'à un objet qui existe : stat, open sans O_CREAT,
/// chdir... `suivre` : suivre un lien final (sinon seulement avec une
/// barre finale). Une barre finale sur autre chose qu'un dossier : ENOTDIR.
pub fn trouver<A: Arbre>(arbre: &A, depart: &Depart<A::Objet>, chemin: &[u8], suivre: bool) -> Result<A::Objet, Erreur> {
    let fin = resoudre(arbre, depart, chemin, if suivre { Suivre::Toujours } else { Suivre::AvecBarre })?;
    let objet = fin.objet.ok_or(Erreur::ENOENT)?;
    if fin.barre && type_de(arbre.mode(objet)) != S_IFDIR {
        return Err(Erreur::ENOTDIR);
    }
    Ok(objet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{S_IFREG, Identite};
    use alloc::vec;

    /// Un petit arbre à la main : (nom, parent, mode, cible).
    struct Petit(Vec<(&'static [u8], usize, u32, &'static [u8])>);

    impl Arbre for Petit {
        type Objet = usize;
        fn mode(&self, o: usize) -> u32 {
            self.0[o].2
        }
        fn proprietaire(&self, _: usize) -> (u32, u32) {
            (0, 0)
        }
        fn chercher(&self, dossier: usize, nom: &[u8]) -> Option<usize> {
            (1..self.0.len()).find(|&i| self.0[i].1 == dossier && self.0[i].0 == nom)
        }
        fn parent(&self, dossier: usize) -> usize {
            self.0[dossier].1
        }
        fn cible(&self, lien: usize) -> &[u8] {
            self.0[lien].3
        }
    }

    const D: u32 = S_IFDIR | 0o755;
    const F: u32 = S_IFREG | 0o644;
    const L: u32 = S_IFLNK | 0o777;
    const FERME: u32 = S_IFDIR | 0o700;

    // 0 /, 1 /etc, 2 /etc/hosts, 3 /lien -> etc, 4 /boucle -> boucle,
    // 5 /abs -> /etc/hosts, 6 /prive (0700), 7 /prive/x, 8 /pendant -> nulle/part,
    // 9 /vide -> "", 10 /etc/sous, 11 /racine -> /
    fn arbre() -> Petit {
        Petit(vec![
            (b"", 0, D, b""),
            (b"etc", 0, D, b""),
            (b"hosts", 1, F, b""),
            (b"lien", 0, L, b"etc"),
            (b"boucle", 0, L, b"boucle"),
            (b"abs", 0, L, b"/etc/hosts"),
            (b"prive", 0, FERME, b""),
            (b"x", 6, F, b""),
            (b"pendant", 0, L, b"nulle/part"),
            (b"vide", 0, L, b""),
            (b"sous", 1, D, b""),
            (b"racine", 0, L, b"/"),
        ])
    }

    const ROOT: Identite = Identite::ROOT;
    const DAVID: Identite = Identite { uid: 1000, gid: 1000 };

    fn depart(qui: Identite) -> Depart<usize> {
        Depart { racine: 0, dossier: 0, qui, sous: false }
    }

    fn t(chemin: &[u8], suivre: bool) -> Result<usize, Erreur> {
        trouver(&arbre(), &depart(DAVID), chemin, suivre)
    }

    #[test]
    fn chemins_ordinaires() {
        assert_eq!(t(b"/etc/hosts", true), Ok(2));
        assert_eq!(t(b"etc//hosts", true), Ok(2));
        assert_eq!(t(b"/etc/./sous/../hosts", true), Ok(2));
        assert_eq!(t(b"/../../etc", true), Ok(1));
        assert_eq!(t(b"/", true), Ok(0));
        assert_eq!(t(b"///", true), Ok(0));
        assert_eq!(t(b".", true), Ok(0));
        assert_eq!(t(b"", true), Err(Erreur::ENOENT));
        assert_eq!(t(b"/etc/rien", true), Err(Erreur::ENOENT));
        assert_eq!(t(b"/rien/hosts", true), Err(Erreur::ENOENT));
        // Un fichier au milieu, ou avec une barre finale.
        assert_eq!(t(b"/etc/hosts/x", true), Err(Erreur::ENOTDIR));
        assert_eq!(t(b"/etc/hosts/", true), Err(Erreur::ENOTDIR));
        assert_eq!(t(b"/etc/", true), Ok(1));
        // Des noms et des chemins trop longs.
        let long = [b'a'; 256];
        assert_eq!(t(&long, true), Err(Erreur::ENAMETOOLONG));
        assert_eq!(t(&[b'/'; 4096], true), Err(Erreur::ENAMETOOLONG));
        assert_eq!(t(&[b'/'; 4095], true), Ok(0));
    }

    #[test]
    fn liens_symboliques() {
        assert_eq!(t(b"/lien/hosts", false), Ok(2));
        assert_eq!(t(b"/abs", true), Ok(2));
        // Sans suivre, le lien lui-même ; avec une barre, le dossier.
        assert_eq!(t(b"/lien", false), Ok(3));
        assert_eq!(t(b"/lien", true), Ok(1));
        assert_eq!(t(b"/lien/", false), Ok(1));
        // Un lien vers « / », au bout ou au milieu.
        assert_eq!(t(b"/racine", true), Ok(0));
        assert_eq!(t(b"/racine/etc", true), Ok(1));
        assert_eq!(t(b"/boucle", true), Err(Erreur::ELOOP));
        assert_eq!(t(b"/boucle", false), Ok(4));
        assert_eq!(t(b"/boucle/x", false), Err(Erreur::ELOOP));
        assert_eq!(t(b"/vide", true), Err(Erreur::ENOENT));
        assert_eq!(t(b"/pendant", true), Err(Erreur::ENOENT));
        // Un lien pendant en dernier composant : la résolution rend où
        // serait sa cible (open avec O_CREAT la crée).
        let a = arbre();
        let fin = resoudre(&a, &depart(DAVID), b"/pendant", Suivre::Toujours);
        assert_eq!(fin.unwrap_err(), Erreur::ENOENT); // « nulle » manque au milieu
        let fin = resoudre(&a, &depart(DAVID), b"/lien/neuf", Suivre::Toujours).unwrap();
        assert_eq!((fin.dossier, fin.nom.as_slice(), fin.objet), (1, &b"neuf"[..], None));
        // Sans suivre, même avec une barre : le nom du lien.
        let fin = resoudre(&a, &depart(DAVID), b"/lien/", Suivre::Jamais).unwrap();
        assert_eq!((fin.dossier, fin.objet, fin.barre), (0, Some(3), true));
    }

    #[test]
    fn quarante_liens_au_plus() {
        // Une chaîne de liens l1 -> l2 -> ... -> l41 -> etc.
        let mut a = arbre();
        let noms: Vec<&'static [u8]> = (0..=41).map(|i| alloc::format!("l{i}").leak().as_bytes()).collect();
        for i in 1..=41 {
            let cible: &'static [u8] = if i == 41 { b"etc" } else { noms[i + 1] };
            a.0.push((noms[i], 0, L, cible));
        }
        // De l1 : 41 liens à suivre, un de trop ; de l2 : 40, tout juste.
        assert_eq!(trouver(&a, &depart(DAVID), b"l1", true), Err(Erreur::ELOOP));
        assert_eq!(trouver(&a, &depart(DAVID), b"l2", true), Ok(1));
    }

    #[test]
    fn droit_de_traverser() {
        assert_eq!(t(b"/prive/x", true), Err(Erreur::EACCES));
        // Même « . » demande le droit de traverser.
        assert_eq!(t(b"/prive/.", true), Err(Erreur::EACCES));
        // Le dossier lui-même se trouve : c'est son parent qu'on traverse.
        assert_eq!(t(b"/prive", true), Ok(6));
        assert_eq!(trouver(&arbre(), &depart(ROOT), b"/prive/x", true), Ok(7));
    }

    #[test]
    fn dernier_composant() {
        let a = arbre();
        let r = |chemin: &'static [u8]| resoudre(&a, &depart(DAVID), chemin, Suivre::Jamais).unwrap();
        let fin = r(b"/etc/neuf/");
        assert_eq!((fin.dossier, fin.nom.as_slice(), fin.objet, fin.barre), (1, &b"neuf"[..], None, true));
        let fin = r(b"/etc/.");
        assert_eq!((fin.dernier, fin.objet), (Dernier::Point, Some(1)));
        let fin = r(b"/etc/..");
        assert_eq!((fin.dernier, fin.dossier, fin.objet), (Dernier::PointPoint, 1, Some(0)));
        let fin = r(b"/");
        assert_eq!((fin.dernier, fin.objet), (Dernier::Racine, Some(0)));
    }

    #[test]
    fn sous_le_dossier_de_depart() {
        let a = arbre();
        let sous = Depart { racine: 0, dossier: 1, qui: DAVID, sous: true };
        assert_eq!(trouver(&a, &sous, b"hosts", true), Ok(2));
        assert_eq!(trouver(&a, &sous, b"sous/../hosts", true), Ok(2));
        assert_eq!(trouver(&a, &sous, b"..", true), Err(Erreur::EXDEV));
        assert_eq!(trouver(&a, &sous, b"sous/../../etc", true), Err(Erreur::EXDEV));
        assert_eq!(trouver(&a, &sous, b"/etc", true), Err(Erreur::EXDEV));
        // Un lien absolu, même vers un fichier du dossier.
        let racine = Depart { dossier: 0, ..sous };
        assert_eq!(trouver(&a, &racine, b"abs", true), Err(Erreur::EXDEV));
        assert_eq!(trouver(&a, &racine, b"lien/hosts", true), Ok(2));
        // Partir d'un fichier.
        assert_eq!(trouver(&a, &Depart { dossier: 2, ..sous }, b"x", true), Err(Erreur::ENOTDIR));
    }
}
