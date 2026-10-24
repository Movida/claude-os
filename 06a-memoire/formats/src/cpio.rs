//! L'archive de programmes : le format cpio « newc », celui de
//! l'initramfs de Linux.
//!
//! Le chargeur dépose en mémoire, à côté du noyau, une archive qui contient
//! les programmes à exécuter. Linux fait de même avec son initramfs : un
//! système de fichiers complet dans une archive cpio, que le noyau déballe
//! en mémoire au démarrage, avant le moindre pilote de disque. C'est aussi
//! notre chemin vers `claude` sur du vrai matériel.
//!
//! Le format (Documentation/driver-api/early-userspace/buffer-format.rst) :
//! une suite d'entrées, chacune
//!   - un en-tête de 110 octets en ASCII : la marque « 070701 », puis 13
//!     champs de 8 chiffres hexadécimaux : inode, mode (type et droits),
//!     uid, gid, nombre de liens, date, TAILLE du contenu, périphérique
//!     (majeur, mineur), périphérique spécial (majeur, mineur), TAILLE DU
//!     NOM (zéro final compris), somme de contrôle (inutilisée ici) ;
//!   - le nom, terminé par un octet nul, puis des zéros jusqu'au multiple
//!     de 4 suivant ;
//!   - le contenu, puis des zéros jusqu'au multiple de 4 suivant.
//! La dernière entrée s'appelle « TRAILER!!! » : elle marque la fin.
//!
//! Pourquoi cpio plutôt que tar : c'est le choix de Linux pour l'initramfs
//! (2001), pour sa simplicité ; un en-tête tar fait 512 octets, avec des
//! champs en octal de longueurs diverses et des extensions (noms longs,
//! GNU ou POSIX) qu'il faudrait reconnaître. Le « newc » plutôt que l'ancien
//! format binaire de cpio : ses champs en texte n'ont pas de boutisme, et
//! ses tailles vont jusqu'à 4 Gio.
//!
//! On ignore ce qui suit l'entrée de fin (des zéros de remplissage, en
//! général). Ce qu'on ne fait pas encore : les archives concaténées
//! (Linux lit ce qui suit la fin) et compressées, la marque « 070702 »
//! (avec somme de contrôle), et les liens physiques (un fichier à
//! plusieurs noms, dont GNU cpio n'écrit le contenu qu'avec le dernier ;
//! les précédents apparaissent ici vides). Notre script de construction
//! n'écrit rien de tout cela.

use core::fmt;

/// La marque de début de chaque en-tête.
const MAGIQUE: &[u8; 6] = b"070701";
/// La taille d'un en-tête : la marque et 13 champs de 8 caractères.
const TAILLE_ENTETE: usize = 6 + 13 * 8;
/// Le nom de l'entrée qui termine l'archive.
const FIN: &[u8] = b"TRAILER!!!";
/// Le plus long nom accepté, zéro final compris : le PATH_MAX de Linux,
/// qui refuse lui aussi les noms plus longs.
const NOM_MAX: usize = 4096;

/// Les bits du type de fichier, dans le mode (S_IFMT), et le type « fichier
/// ordinaire » (S_IFREG) : les valeurs de POSIX, que cpio reprend.
const TYPE: u32 = 0o170000;
const FICHIER: u32 = 0o100000;

/// Les noms des champs de l'en-tête, dans l'ordre, pour les erreurs.
const CHAMPS: [&str; 13] = [
    "inode", "mode", "uid", "gid", "liens", "date", "taille",
    "majeur", "mineur", "rmajeur", "rmineur", "taille du nom", "somme",
];
const CHAMP_MODE: usize = 1;
const CHAMP_TAILLE: usize = 6;
const CHAMP_TAILLE_NOM: usize = 11;

/// Une entrée de l'archive : des tranches des octets de l'archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entree<'a> {
    /// Le nom, sans le zéro final.
    pub nom: &'a [u8],
    /// Le type et les droits, comme st_mode.
    pub mode: u32,
    pub contenu: &'a [u8],
}

impl Entree<'_> {
    /// Un fichier ordinaire ? (Les autres : dossiers, liens symboliques,
    /// périphériques, que le noyau ne sait pas encore créer.)
    pub fn est_fichier(&self) -> bool {
        self.mode & TYPE == FICHIER
    }
}

/// Pourquoi une archive est refusée. `position` : le début de l'en-tête de
/// l'entrée fautive, depuis le début de l'archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// L'en-tête, le nom ou le contenu dépasse la fin de l'archive.
    Tronquee { position: usize },
    /// Pas de marque « 070701 » au début de l'en-tête.
    Magique { position: usize },
    /// Un champ de l'en-tête n'est pas fait de 8 chiffres hexadécimaux.
    Champ { position: usize, champ: &'static str },
    /// Taille du nom nulle ou trop grande, nom sans zéro final, ou avec un
    /// zéro au milieu.
    Nom { position: usize },
    /// La fin de l'archive arrive sans l'entrée « TRAILER!!! ».
    SansFin,
}

// Ces messages sont affichés par le noyau : sans accents (page de code 437).
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::Tronquee { position } => write!(f, "archive tronquee (entree a l'octet {position})"),
            Erreur::Magique { position } => write!(f, "pas d'en-tete cpio newc a l'octet {position}"),
            Erreur::Champ { position, champ } => {
                write!(f, "champ '{champ}' non hexadecimal (entree a l'octet {position})")
            }
            Erreur::Nom { position } => write!(f, "nom invalide (entree a l'octet {position})"),
            Erreur::SansFin => write!(f, "archive sans entree de fin (TRAILER!!!)"),
        }
    }
}

/// Lit l'archive `octets`, entrée par entrée.
pub fn lire(octets: &[u8]) -> Archive<'_> {
    Archive { octets, position: 0, finie: false }
}

/// Le parcours d'une archive : un itérateur qui rend chaque entrée (sauf
/// celle de fin), ou la première erreur, après laquelle il s'arrête. On
/// n'a donc pas à valider toute l'archive avant de s'en servir ; un
/// appelant qui veut tout ou rien la parcourt une première fois.
pub struct Archive<'a> {
    octets: &'a [u8],
    position: usize,
    finie: bool,
}

/// Un champ de 8 chiffres hexadécimaux (majuscules ou minuscules), lu
/// strictement : ni espace, ni signe, ni préfixe « 0x », contrairement à
/// strtoul. Huit chiffres tiennent toujours dans un u32.
fn hexadecimal(champ: &[u8]) -> Option<u32> {
    champ.iter().try_fold(0u32, |valeur, &c| {
        let chiffre = (c as char).to_digit(16)?;
        Some(valeur << 4 | chiffre)
    })
}

/// `n` arrondi au multiple de 4 suivant, sans débordement possible.
fn aligner4(n: usize) -> Option<usize> {
    n.checked_add(3).map(|n| n & !3)
}

impl<'a> Archive<'a> {
    /// L'entrée qui commence à `self.position`, et la position de la
    /// suivante.
    fn entree(&self) -> Result<(Entree<'a>, usize), Erreur> {
        let position = self.position;
        let tronquee = Erreur::Tronquee { position };
        let entete = self.octets.get(position..).ok_or(tronquee)?;
        if entete.is_empty() {
            return Err(Erreur::SansFin);
        }
        let entete = entete.get(..TAILLE_ENTETE).ok_or(tronquee)?;
        if &entete[..6] != MAGIQUE {
            return Err(Erreur::Magique { position });
        }
        let champ = |i: usize| {
            let debut = 6 + 8 * i;
            hexadecimal(&entete[debut..debut + 8]).ok_or(Erreur::Champ { position, champ: CHAMPS[i] })
        };
        // Tous les champs, même ceux dont on ne se sert pas : un en-tête
        // abîmé l'est rarement à un seul endroit, et mieux vaut le refuser.
        for i in 0..CHAMPS.len() {
            champ(i)?;
        }
        let mode = champ(CHAMP_MODE)?;
        let taille = champ(CHAMP_TAILLE)? as usize;
        let taille_nom = champ(CHAMP_TAILLE_NOM)? as usize;
        if taille_nom == 0 || taille_nom > NOM_MAX {
            return Err(Erreur::Nom { position });
        }

        // Le nom, juste après l'en-tête ; puis le contenu, au multiple de 4
        // suivant ; puis l'entrée suivante, au multiple de 4 suivant.
        // Toutes les additions sont vérifiées : sur une machine 32 bits, ou
        // avec une archive placée tout en haut de la mémoire, elles
        // pourraient déborder.
        let debut_nom = position + TAILLE_ENTETE;
        let fin_nom = debut_nom.checked_add(taille_nom).ok_or(tronquee)?;
        let nom = self.octets.get(debut_nom..fin_nom).ok_or(tronquee)?;
        let (zero, nom) = nom.split_last().ok_or(Erreur::Nom { position })?;
        if *zero != 0 || nom.contains(&0) {
            return Err(Erreur::Nom { position });
        }
        let debut_contenu = aligner4(fin_nom).ok_or(tronquee)?;
        let fin_contenu = debut_contenu.checked_add(taille).ok_or(tronquee)?;
        let contenu = self.octets.get(debut_contenu..fin_contenu).ok_or(tronquee)?;
        // Le remplissage après le contenu peut manquer à la toute fin : la
        // position suivante est alors hors de l'archive, et l'entrée
        // suivante sera « tronquée » (ou ce sera la fin).
        let suivante = aligner4(fin_contenu).ok_or(tronquee)?;
        Ok((Entree { nom, mode, contenu }, suivante))
    }
}

impl<'a> Iterator for Archive<'a> {
    type Item = Result<Entree<'a>, Erreur>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finie {
            return None;
        }
        match self.entree() {
            Ok((entree, _)) if entree.nom == FIN => {
                self.finie = true;
                None
            }
            Ok((entree, suivante)) => {
                self.position = suivante;
                Some(Ok(entree))
            }
            Err(e) => {
                self.finie = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Ajoute une entrée à l'archive en construction, comme ../archive.sh.
    fn ajouter(archive: &mut Vec<u8>, nom: &[u8], mode: u32, contenu: &[u8]) {
        let champs = [1, mode, 0, 0, 1, 0, contenu.len() as u32, 0, 0, 0, 0, nom.len() as u32 + 1, 0];
        archive.extend_from_slice(MAGIQUE);
        for c in champs {
            archive.extend_from_slice(std::format!("{c:08X}").as_bytes());
        }
        archive.extend_from_slice(nom);
        archive.push(0);
        while archive.len() % 4 != 0 {
            archive.push(0);
        }
        archive.extend_from_slice(contenu);
        while archive.len() % 4 != 0 {
            archive.push(0);
        }
    }

    fn fin(archive: &mut Vec<u8>) {
        ajouter(archive, FIN, 0, &[]);
    }

    /// Une archive de deux fichiers et d'un dossier, comme celle du noyau.
    fn exemple() -> Vec<u8> {
        let mut a = Vec::new();
        ajouter(&mut a, b"bonjour.wasm", 0o100755, b"\0asm\x01\0\0\0");
        ajouter(&mut a, b"bin", 0o040755, &[]);
        ajouter(&mut a, b"bin/c", 0o100644, b"\x7fELF...");
        fin(&mut a);
        a
    }

    fn tout(octets: &[u8]) -> Result<Vec<Entree<'_>>, Erreur> {
        lire(octets).collect()
    }

    #[test]
    fn archive_valide() {
        let a = exemple();
        let entrees = tout(&a).unwrap();
        assert_eq!(entrees.len(), 3);
        assert_eq!(entrees[0].nom, b"bonjour.wasm");
        assert_eq!(entrees[0].contenu, b"\0asm\x01\0\0\0");
        assert!(entrees[0].est_fichier());
        assert_eq!(entrees[1].nom, b"bin");
        assert!(!entrees[1].est_fichier());
        assert_eq!(entrees[2].contenu, b"\x7fELF...");
    }

    #[test]
    fn hexadecimal_en_minuscules() {
        let mut a = exemple();
        // La taille du premier nom (13 = 0000000D) en minuscules.
        let champ = 6 + 8 * CHAMP_TAILLE_NOM;
        assert_eq!(&a[champ..champ + 8], b"0000000D");
        a[champ + 7] = b'd';
        assert_eq!(tout(&a).unwrap().len(), 3);
    }

    #[test]
    fn rien_apres_la_fin() {
        // Ce qui suit TRAILER!!! est ignoré (ici des zéros de remplissage,
        // comme l'image disque en ajoute jusqu'au secteur), et l'itérateur
        // ne rend plus rien.
        let mut a = exemple();
        a.extend_from_slice(&[0; 300]);
        let mut archive = lire(&a);
        assert_eq!(archive.by_ref().count(), 3);
        assert!(archive.next().is_none());
    }

    #[test]
    fn fin_avec_contenu_puis_entree() {
        // L'entrée de fin termine l'archive même si elle a un contenu, et
        // une entrée valide placée après elle n'est pas lue (Linux, lui,
        // continuerait : il accepte les archives concaténées).
        let mut a = Vec::new();
        ajouter(&mut a, b"premier", 0o100644, b"abc");
        ajouter(&mut a, FIN, 0, b"ignore");
        ajouter(&mut a, b"apres", 0o100644, b"xyz");
        fin(&mut a);
        let entrees = tout(&a).unwrap();
        assert_eq!(entrees.len(), 1);
        assert_eq!(entrees[0].nom, b"premier");
    }

    #[test]
    fn archive_vide_ou_sans_fin() {
        assert_eq!(tout(&[]), Err(Erreur::SansFin));
        let mut a = Vec::new();
        ajouter(&mut a, b"seul", 0o100644, b"abc");
        assert_eq!(tout(&a), Err(Erreur::SansFin));
        // Une archive réduite à son entrée de fin est vide, et valide.
        let mut a = Vec::new();
        fin(&mut a);
        assert_eq!(tout(&a), Ok(Vec::new()));
    }

    #[test]
    fn tronquee_partout() {
        // Coupée à chaque octet possible : jamais de panique, jamais
        // d'entrée inventée. Avant la fin du premier contenu : une erreur
        // d'emblée ; ensuite, les entrées complètes, puis une erreur.
        let a = exemple();
        for n in 0..a.len() {
            let resultat = tout(&a[..n]);
            assert!(resultat.is_err(), "coupee a {n} : acceptee");
            let entrees: Vec<_> = lire(&a[..n]).filter_map(Result::ok).collect();
            let completes = tout(&a).unwrap();
            assert!(entrees.iter().zip(&completes).all(|(x, y)| x == y));
        }
    }

    #[test]
    fn mauvaise_magique() {
        let mut a = exemple();
        a[5] = b'2'; // 070702 : le format avec somme de contrôle.
        assert_eq!(tout(&a), Err(Erreur::Magique { position: 0 }));
    }

    #[test]
    fn champ_non_hexadecimal() {
        for (i, nom) in CHAMPS.iter().enumerate() {
            for intrus in [b'G', b' ', b'-', b'x', 0xC3] {
                let mut a = exemple();
                a[6 + 8 * i + 3] = intrus;
                assert_eq!(tout(&a), Err(Erreur::Champ { position: 0, champ: nom }));
            }
        }
    }

    #[test]
    fn taille_qui_deborde() {
        // Une taille de contenu de 4 Gio - 1, puis juste un octet de trop.
        let mut a = exemple();
        let champ = 6 + 8 * CHAMP_TAILLE;
        a[champ..champ + 8].copy_from_slice(b"FFFFFFFF");
        assert_eq!(tout(&a), Err(Erreur::Tronquee { position: 0 }));
        let mut a = Vec::new();
        ajouter(&mut a, b"x", 0o100644, b"abcd");
        a[champ..champ + 8].copy_from_slice(b"00000005");
        assert_eq!(tout(&a), Err(Erreur::Tronquee { position: 0 }));
    }

    #[test]
    fn noms_invalides() {
        let champ = 6 + 8 * CHAMP_TAILLE_NOM;
        // Taille du nom nulle, ou plus grande que PATH_MAX.
        for taille in [b"00000000", b"00001001"] {
            let mut a = exemple();
            a[champ..champ + 8].copy_from_slice(taille);
            assert_eq!(tout(&a), Err(Erreur::Nom { position: 0 }));
        }
        // Pas de zéro final (la taille annoncée avale le zéro du nom en
        // moins), ou un zéro au milieu.
        let mut a = exemple();
        a[champ..champ + 8].copy_from_slice(b"0000000C");
        assert_eq!(tout(&a), Err(Erreur::Nom { position: 0 }));
        let mut a = exemple();
        a[TAILLE_ENTETE + 3] = 0;
        assert_eq!(tout(&a), Err(Erreur::Nom { position: 0 }));
    }

    #[test]
    fn erreur_dans_la_deuxieme_entree() {
        // La première est rendue, puis l'erreur, puis plus rien.
        // La deuxième entrée commence après l'en-tête, le nom (13 octets
        // avec son zéro) et le contenu (8 octets) de la première, chacun
        // aligné sur 4 : 124 + 8 = 132.
        let mut a = exemple();
        let deuxieme = aligner4(aligner4(TAILLE_ENTETE + 13).unwrap() + 8).unwrap();
        assert_eq!(deuxieme, 132);
        a[deuxieme] = b'1';
        let mut archive = lire(&a);
        assert!(matches!(archive.next(), Some(Ok(e)) if e.nom == b"bonjour.wasm"));
        assert_eq!(archive.next(), Some(Err(Erreur::Magique { position: deuxieme })));
        assert_eq!(archive.next(), None);
    }

    #[test]
    fn messages_sans_accents() {
        let erreurs = [
            Erreur::Tronquee { position: 1 },
            Erreur::Magique { position: 2 },
            Erreur::Champ { position: 3, champ: "mode" },
            Erreur::Nom { position: 4 },
            Erreur::SansFin,
        ];
        for e in erreurs {
            assert!(std::format!("{e}").is_ascii());
        }
    }
}
