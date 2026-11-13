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
//!     NOM (zéro final compris), somme de contrôle (voir « 070702 ») ;
//!   - le nom, terminé par un octet nul, puis des zéros jusqu'au multiple
//!     de 4 suivant ;
//!   - le contenu, puis des zéros jusqu'au multiple de 4 suivant.
//! La dernière entrée s'appelle « TRAILER!!! » : elle marque la fin de
//! l'archive.
//!
//! Pourquoi cpio plutôt que tar : c'est le choix de Linux pour l'initramfs
//! (2001), pour sa simplicité ; un en-tête tar fait 512 octets, avec des
//! champs en octal de longueurs diverses et des extensions (noms longs,
//! GNU ou POSIX) qu'il faudrait reconnaître. Le « newc » plutôt que l'ancien
//! format binaire de cpio : ses champs en texte n'ont pas de boutisme, et
//! ses tailles vont jusqu'à 4 Gio.
//!
//! Comme Linux (`unpack_to_rootfs`, init/initramfs.c), on lit aussi :
//!   - des archives mises bout à bout : l'entrée de fin ne termine que son
//!     archive, la lecture continue après elle (c'est ainsi qu'un chargeur
//!     ajoute un microcode ou des modules à un initramfs : par `cat`) ;
//!   - des octets nuls entre deux entrées, avant la première ou après la
//!     dernière, en nombre quelconque (Linux les saute après chaque entrée,
//!     `do_reset`) ; mais l'en-tête qui les suit commence à un multiple de 4
//!     depuis le début de l'archive, sinon le remplissage est cassé (« broken
//!     padding ») ;
//!   - la marque « 070702 » : le même format, avec une somme de contrôle,
//!     celle de `cpio -H crc` : la somme des octets du contenu (chacun ajouté
//!     à un entier de 32 bits, qui déborde en rebouclant), vérifiée pour les
//!     fichiers ordinaires seulement. Avec « 070701 », le champ ne compte
//!     pas. La marque « 070707 » (l'ancien format ASCII, « odc ») a son
//!     message, comme chez Linux (« use -H newc option »).
//!
//! Deux écarts voulus avec Linux, qui déballe au fil de l'eau ce qu'il peut :
//!   - une archive dont la fin manque (coupée entre deux entrées, ou au
//!     milieu d'une) est refusée : Linux s'arrête sans rien dire (l'entrée
//!     de fin lui est facultative), et une archive à moitié lue le laisse
//!     démarrer sur la moitié d'un système. La nôtre est chargée par notre
//!     chargeur et vérifiée en entier avant de déballer quoi que ce soit
//!     (`programmes.rs`) : il faut donc qu'elle finisse par une entrée de fin,
//!     suivie de zéros au plus ;
//!   - les archives compressées (gzip, zstd...) ne sont pas lues : Linux les
//!     accepte parce qu'un initramfs vient de distributions qui les
//!     compressent ; la nôtre est la nôtre (archive.sh), et la décompresser
//!     demanderait un décompresseur dans le noyau, sans rien gagner.
//!
//! On est aussi plus strict que lui sur les en-têtes : un champ qui n'est
//! pas hexadécimal, un nom vide ou trop long sont des erreurs, quand Linux
//! lit ce qu'il peut (`simple_strntoul`) ou saute l'entrée. Et sur ce
//! qu'une entrée porte, que Linux trie en silence : un type inconnu (il ne
//! le crée pas, `do_name`), un contenu pour un dossier, une FIFO, une
//! socket ou un périphérique (il saute l'entrée entière, `do_header`), la
//! cible d'un lien symbolique vide, trop longue ou avec un octet nul (il la
//! coupe au premier, `do_symlink`, ou la voit refusée par symlink) : tout
//! cela refuse l'archive, avant que rien ne soit déballé.
//!
//! Les liens physiques (un fichier à plusieurs noms : le même périphérique
//! d'origine et le même numéro d'inode, un nombre de liens d'au moins 2, et
//! le contenu seulement dans la dernière de ses entrées, comme l'écrivent
//! GNU cpio et le gen_init_cpio de Linux) sont lus tels quels : c'est à qui
//! déballe l'archive de les relier (6b), dans une même archive seulement
//! (Linux oublie les siens à chaque entrée de fin, `free_hash`) : d'où le
//! rang de l'archive dans chaque entrée.

use core::fmt;

/// La marque de début de chaque en-tête ; avec une somme de contrôle ;
/// celle de l'ancien format ASCII, refusé.
const MAGIQUE: &[u8; 6] = b"070701";
const MAGIQUE_SOMME: &[u8; 6] = b"070702";
const MAGIQUE_ODC: &[u8; 6] = b"070707";
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
const CHAMP_INODE: usize = 0;
const CHAMP_MODE: usize = 1;
const CHAMP_UID: usize = 2;
const CHAMP_GID: usize = 3;
const CHAMP_LIENS: usize = 4;
const CHAMP_DATE: usize = 5;
const CHAMP_TAILLE: usize = 6;
const CHAMP_MAJEUR: usize = 7;
const CHAMP_MINEUR: usize = 8;
const CHAMP_RMAJEUR: usize = 9;
const CHAMP_RMINEUR: usize = 10;
const CHAMP_TAILLE_NOM: usize = 11;
const CHAMP_SOMME: usize = 12;

const DOSSIER: u32 = 0o040000;
const LIEN: u32 = 0o120000;
const FIFO: u32 = 0o010000;
const CARACTERES: u32 = 0o020000;
const BLOCS: u32 = 0o060000;
const SOCKET: u32 = 0o140000;

/// Une entrée de l'archive : ses champs, et des tranches des octets de
/// l'archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entree<'a> {
    /// Le nom, sans le zéro final (un chemin, sans « / » au début chez
    /// gen_init_cpio).
    pub nom: &'a [u8],
    /// Le numéro d'inode dans l'archive : le même pour les liens physiques
    /// d'un fichier.
    pub inode: u32,
    /// Le périphérique (majeur, mineur) qui portait le fichier quand
    /// l'archive a été faite : avec l'inode, ce qui désigne un fichier (GNU
    /// cpio archive des fichiers de plusieurs systèmes de fichiers, dont les
    /// inodes peuvent se répéter).
    pub dev: (u32, u32),
    /// Le type et les droits, comme st_mode.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Le nombre de liens physiques.
    pub liens: u32,
    /// La date de modification, en secondes depuis 1970.
    pub date: u32,
    /// Le périphérique désigné, pour un nœud de périphérique.
    pub rdev: (u32, u32),
    /// Le contenu : celui d'un fichier, ou la cible d'un lien symbolique.
    pub contenu: &'a [u8],
    /// Le rang, dans une suite d'archives mises bout à bout, de celle qui
    /// contient l'entrée (0 pour la première) : les liens physiques ne se
    /// cherchent que dans la même.
    pub archive: usize,
}

impl Entree<'_> {
    /// Un fichier ordinaire ?
    pub fn est_fichier(&self) -> bool {
        self.mode & TYPE == FICHIER
    }

    pub fn est_dossier(&self) -> bool {
        self.mode & TYPE == DOSSIER
    }

    pub fn est_lien(&self) -> bool {
        self.mode & TYPE == LIEN
    }
}

/// Pourquoi une archive est refusée. `position` : le début de l'en-tête de
/// l'entrée fautive, depuis le début de l'archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// L'en-tête, le nom ou le contenu dépasse la fin de l'archive.
    Tronquee { position: usize },
    /// Pas de marque « 070701 » ou « 070702 » au début de l'en-tête.
    Magique { position: usize },
    /// La marque « 070707 » : l'ancien format ASCII de cpio (« odc »).
    Odc { position: usize },
    /// Après des octets nuls, un en-tête qui ne commence pas à un multiple
    /// de 4 (`position` : son début).
    Remplissage { position: usize },
    /// « 070702 » : la somme des octets du contenu n'est pas celle de
    /// l'en-tête.
    Somme { position: usize },
    /// Un champ de l'en-tête n'est pas fait de 8 chiffres hexadécimaux.
    Champ { position: usize, champ: &'static str },
    /// Taille du nom nulle ou trop grande, nom sans zéro final, ou avec un
    /// zéro au milieu.
    Nom { position: usize },
    /// Un type de fichier que Linux ne crée pas (ni fichier ordinaire,
    /// dossier, lien symbolique, FIFO, socket, ni périphérique).
    Type { position: usize },
    /// Un contenu pour une entrée qui n'en a pas : un dossier, une FIFO,
    /// une socket, un périphérique.
    Contenu { position: usize },
    /// La cible d'un lien symbolique : vide, d'au moins PATH_MAX octets, ou
    /// avec un octet nul.
    Lien { position: usize },
    /// Les octets s'arrêtent (ou ne sont plus que des zéros) sans que la
    /// dernière entrée soit « TRAILER!!! » : une archive coupée.
    SansFin,
}

// Ces messages sont affichés par le noyau : sans accents (page de code 437).
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::Tronquee { position } => write!(f, "archive tronquee (entree a l'octet {position})"),
            Erreur::Magique { position } => write!(f, "pas d'en-tete cpio newc a l'octet {position}"),
            Erreur::Odc { position } => {
                write!(f, "archive cpio odc (070707) a l'octet {position} : il faut le format newc (-H newc)")
            }
            Erreur::Remplissage { position } => write!(f, "remplissage casse : en-tete a l'octet {position}"),
            Erreur::Somme { position } => write!(f, "somme de controle fausse (entree a l'octet {position})"),
            Erreur::Champ { position, champ } => {
                write!(f, "champ '{champ}' non hexadecimal (entree a l'octet {position})")
            }
            Erreur::Nom { position } => write!(f, "nom invalide (entree a l'octet {position})"),
            Erreur::Type { position } => write!(f, "type de fichier inconnu (entree a l'octet {position})"),
            Erreur::Contenu { position } => write!(f, "contenu pour un type qui n'en a pas (entree a l'octet {position})"),
            Erreur::Lien { position } => write!(f, "cible de lien symbolique invalide (entree a l'octet {position})"),
            Erreur::SansFin => write!(f, "archive sans entree de fin (TRAILER!!!)"),
        }
    }
}

/// Lit l'archive `octets` (ou la suite d'archives), entrée par entrée.
pub fn lire(octets: &[u8]) -> Archive<'_> {
    Archive { octets, position: 0, rang: 0, fin_vue: false, finie: false }
}

/// Le parcours d'une archive : un itérateur qui rend chaque entrée (sauf
/// celles de fin), ou la première erreur, après laquelle il s'arrête. On
/// n'a donc pas à valider toute l'archive avant de s'en servir ; un
/// appelant qui veut tout ou rien la parcourt une première fois.
pub struct Archive<'a> {
    octets: &'a [u8],
    position: usize,
    /// Le rang de l'archive en cours dans la suite : les entrées de fin
    /// lues jusqu'ici.
    rang: usize,
    /// La dernière entrée lue était une entrée de fin : les octets peuvent
    /// s'arrêter là.
    fin_vue: bool,
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
        let debut = self.octets.get(position..).ok_or(tronquee)?;
        // La marque d'abord : un en-tête odc (76 octets) plus court que les
        // nôtres doit être dit odc, et des octets qui ne commencent aucune
        // marque, étrangers, même s'ils sont moins de 6 ; tronqué, seulement
        // le début d'une marque.
        let avec_somme = match debut.get(..6).unwrap_or(debut) {
            marque if marque == MAGIQUE => false,
            marque if marque == MAGIQUE_SOMME => true,
            marque if marque == MAGIQUE_ODC => return Err(Erreur::Odc { position }),
            marque if marque.len() < 6 && [MAGIQUE, MAGIQUE_SOMME, MAGIQUE_ODC].iter().any(|m| m.starts_with(marque)) => {
                return Err(tronquee);
            }
            _ => return Err(Erreur::Magique { position }),
        };
        let entete = debut.get(..TAILLE_ENTETE).ok_or(tronquee)?;
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
        let (inode, uid, gid, liens, date) =
            (champ(CHAMP_INODE)?, champ(CHAMP_UID)?, champ(CHAMP_GID)?, champ(CHAMP_LIENS)?, champ(CHAMP_DATE)?);
        let dev = (champ(CHAMP_MAJEUR)?, champ(CHAMP_MINEUR)?);
        let rdev = (champ(CHAMP_RMAJEUR)?, champ(CHAMP_RMINEUR)?);
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
        // La somme d'un fichier ordinaire, comme Linux : celle des octets
        // écrits (`xwrite`), comparée à la fin de la copie (`do_copy`).
        if avec_somme && mode & TYPE == FICHIER {
            let somme = contenu.iter().fold(0u32, |somme, &octet| somme.wrapping_add(u32::from(octet)));
            if somme != champ(CHAMP_SOMME)? {
                return Err(Erreur::Somme { position });
            }
        }
        // Le type, et le contenu qui va avec (voir l'en-tête). Pas pour
        // l'entrée de fin, que rien ne type (mode 0 chez GNU cpio).
        if nom != FIN {
            match mode & TYPE {
                FICHIER => {}
                LIEN if contenu.is_empty() || contenu.len() >= NOM_MAX || contenu.contains(&0) => {
                    return Err(Erreur::Lien { position });
                }
                LIEN => {}
                DOSSIER | FIFO | CARACTERES | BLOCS | SOCKET if !contenu.is_empty() => return Err(Erreur::Contenu { position }),
                DOSSIER | FIFO | CARACTERES | BLOCS | SOCKET => {}
                _ => return Err(Erreur::Type { position }),
            }
        }
        // Le remplissage après le contenu peut manquer à la toute fin : la
        // position suivante est alors hors de l'archive, ce qui en est la
        // fin.
        let suivante = aligner4(fin_contenu).ok_or(tronquee)?;
        let entree = Entree { nom, inode, dev, mode, uid, gid, liens, date, rdev, contenu, archive: self.rang };
        Ok((entree, suivante))
    }
}

impl<'a> Iterator for Archive<'a> {
    type Item = Result<Entree<'a>, Erreur>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finie {
            // Les octets nuls avant l'entrée : sautés, puis l'en-tête doit
            // commencer à un multiple de 4 (`do_reset`). Au bout des octets,
            // la fin n'est bonne que juste après une entrée de fin.
            let reste = self.octets.get(self.position..).unwrap_or(&[]);
            let Some(zeros) = reste.iter().position(|&octet| octet != 0) else {
                self.finie = true;
                return (!self.fin_vue).then_some(Err(Erreur::SansFin));
            };
            self.position += zeros;
            if self.position % 4 != 0 {
                self.finie = true;
                return Some(Err(Erreur::Remplissage { position: self.position }));
            }
            match self.entree() {
                Ok((entree, suivante)) => {
                    self.position = suivante;
                    self.fin_vue = entree.nom == FIN;
                    if !self.fin_vue {
                        return Some(Ok(entree));
                    }
                    // La fin d'une archive : une autre peut suivre (chaque
                    // entrée de fin en compte au moins 124 octets : le rang
                    // ne peut pas déborder).
                    self.rang += 1;
                }
                Err(e) => {
                    self.finie = true;
                    return Some(Err(e));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Ajoute une entrée à l'archive en construction, comme ../archive.sh.
    fn ajouter(archive: &mut Vec<u8>, nom: &[u8], mode: u32, contenu: &[u8]) {
        ajouter_avec(archive, nom, [1, mode, 0, 0, 1, 0, 0, 0, 0, 0, 0], contenu);
    }

    /// Avec tous les champs : inode, mode, uid, gid, liens, date, (taille),
    /// majeur, mineur, rmajeur, rmineur.
    fn ajouter_avec(archive: &mut Vec<u8>, nom: &[u8], c: [u32; 11], contenu: &[u8]) {
        ajouter_marque(archive, MAGIQUE, nom, c, contenu, 0);
    }

    /// Avec aussi la marque et la somme de contrôle.
    fn ajouter_marque(archive: &mut Vec<u8>, marque: &[u8; 6], nom: &[u8], c: [u32; 11], contenu: &[u8], somme: u32) {
        let champs = [c[0], c[1], c[2], c[3], c[4], c[5], contenu.len() as u32, c[7], c[8], c[9], c[10], nom.len() as u32 + 1, somme];
        archive.extend_from_slice(marque);
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
        assert!(!entrees[1].est_fichier() && entrees[1].est_dossier());
        assert_eq!(entrees[2].contenu, b"\x7fELF...");
    }

    #[test]
    fn tous_les_champs() {
        let mut a = Vec::new();
        ajouter_avec(&mut a, b"dev/console", [7, 0o020620, 1000, 5, 2, 123, 0, 8, 3, 5, 1], &[]);
        ajouter_avec(&mut a, b"lien", [8, 0o120777, 0, 0, 1, 0, 0, 0, 0, 0, 0], b"cible");
        fin(&mut a);
        let e = tout(&a).unwrap();
        assert_eq!((e[0].inode, e[0].mode, e[0].uid, e[0].gid, e[0].liens, e[0].date, e[0].rdev), (7, 0o020620, 1000, 5, 2, 123, (5, 1)));
        assert_eq!((e[0].dev, e[0].archive), ((8, 3), 0));
        assert!(!e[0].est_fichier() && !e[0].est_dossier() && !e[0].est_lien());
        assert!(e[1].est_lien());
        assert_eq!(e[1].contenu, b"cible");
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
        // Des zéros après l'entrée de fin (un remplissage jusqu'à la fin
        // d'un secteur) : sautés, et l'itérateur ne rend plus rien.
        let mut a = exemple();
        a.extend_from_slice(&[0; 300]);
        let mut archive = lire(&a);
        assert_eq!(archive.by_ref().count(), 3);
        assert!(archive.next().is_none());
    }

    #[test]
    fn archives_bout_a_bout() {
        // Trois archives : chaque entrée dit la sienne ; l'entrée de fin
        // termine son archive même si elle a un contenu ; une archive vide
        // (sa seule entrée de fin) compte dans les rangs.
        let mut a = exemple();
        ajouter(&mut a, FIN, 0, b"ignore");
        ajouter(&mut a, b"apres", 0o100644, b"xyz");
        fin(&mut a);
        let entrees = tout(&a).unwrap();
        let rangs: Vec<_> = entrees.iter().map(|e| (e.nom, e.archive)).collect();
        assert_eq!(rangs, [(&b"bonjour.wasm"[..], 0), (&b"bin"[..], 0), (&b"bin/c"[..], 0), (&b"apres"[..], 2)]);
        assert_eq!(entrees[3].contenu, b"xyz");
    }

    #[test]
    fn zeros_entre_les_entrees() {
        // Des zéros avant la première entrée, entre deux entrées d'une
        // archive, entre deux archives et après la dernière : sautés, tant
        // que l'en-tête suivant est à un multiple de 4.
        let mut a = std::vec![0; 8];
        ajouter(&mut a, b"premier", 0o100644, b"abc");
        a.extend_from_slice(&[0; 4]);
        fin(&mut a);
        a.extend_from_slice(&[0; 512]);
        ajouter(&mut a, b"second", 0o100644, b"de");
        fin(&mut a);
        a.extend_from_slice(&[0; 7]);
        let entrees = tout(&a).unwrap();
        assert_eq!(entrees.iter().map(|e| (e.nom, e.archive)).collect::<Vec<_>>(), [(&b"premier"[..], 0), (&b"second"[..], 1)]);
        // De 1 à 3 zéros de trop : le remplissage est cassé (au début, au
        // milieu d'une archive, entre deux).
        for n in 1..4 {
            let mut a = std::vec![0; n];
            ajouter(&mut a, b"x", 0o100644, b"abc");
            assert_eq!(tout(&a), Err(Erreur::Remplissage { position: n }));
            let mut a = Vec::new();
            ajouter(&mut a, b"x", 0o100644, b"abc");
            let suivante = a.len();
            a.extend_from_slice(&std::vec![0; n]);
            fin(&mut a);
            let mut archive = lire(&a);
            assert!(matches!(archive.next(), Some(Ok(e)) if e.nom == b"x"));
            assert_eq!(archive.next(), Some(Err(Erreur::Remplissage { position: suivante + n })));
            assert_eq!(archive.next(), None);
        }
    }

    #[test]
    fn autre_chose_apres_la_fin() {
        // Ce qui suit une entrée de fin et n'est pas un zéro doit être une
        // archive : sinon, une erreur (Linux y chercherait une archive
        // compressée).
        let mut a = exemple();
        let fin_archive = a.len();
        a.extend_from_slice(b"abcd");
        assert_eq!(tout(&a), Err(Erreur::Magique { position: fin_archive }));
        let mut a = exemple();
        a.extend_from_slice(b"\0\0x");
        assert_eq!(tout(&a), Err(Erreur::Remplissage { position: fin_archive + 2 }));
    }

    #[test]
    fn archive_vide_ou_sans_fin() {
        assert_eq!(tout(&[]), Err(Erreur::SansFin));
        assert_eq!(tout(&[0; 512]), Err(Erreur::SansFin));
        let mut a = Vec::new();
        ajouter(&mut a, b"seul", 0o100644, b"abc");
        assert_eq!(tout(&a), Err(Erreur::SansFin));
        a.extend_from_slice(&[0; 64]);
        assert_eq!(tout(&a), Err(Erreur::SansFin));
        // Une seconde archive coupée entre deux entrées : la première
        // compte, la suite est refusée.
        let mut a = exemple();
        ajouter(&mut a, b"suite", 0o100644, b"abc");
        let entrees: Vec<_> = lire(&a).collect();
        assert_eq!(entrees.len(), 5);
        assert!(entrees[..4].iter().all(Result::is_ok));
        assert_eq!(entrees[4], Err(Erreur::SansFin));
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
        a[5] = b'3';
        assert_eq!(tout(&a), Err(Erreur::Magique { position: 0 }));
        // L'ancien format ASCII : dit comme tel, même dans une archive plus
        // courte qu'un de nos en-têtes.
        a[5] = b'7';
        assert_eq!(tout(&a), Err(Erreur::Odc { position: 0 }));
        assert_eq!(tout(b"070707000000"), Err(Erreur::Odc { position: 0 }));
        assert_eq!(tout(b"07070"), Err(Erreur::Tronquee { position: 0 }));
        assert_eq!(tout(b"0708"), Err(Erreur::Magique { position: 0 }));
    }

    #[test]
    fn somme_de_controle() {
        // « 070702 » : la somme des octets d'un fichier ordinaire, vérifiée ;
        // celle d'un dossier ou d'un lien, et le champ des « 070701 », non.
        let bonne = 0x61 + 0x62 + 0x63;
        let essai = |marque: &[u8; 6], mode: u32, somme: u32| {
            let mut a = Vec::new();
            ajouter_marque(&mut a, marque, b"x", [1, mode, 0, 0, 1, 0, 0, 0, 0, 0, 0], b"abc", somme);
            fin(&mut a);
            tout(&a).map(|e| e.len())
        };
        assert_eq!(essai(MAGIQUE_SOMME, 0o100644, bonne), Ok(1));
        assert_eq!(essai(MAGIQUE_SOMME, 0o100644, bonne + 1), Err(Erreur::Somme { position: 0 }));
        assert_eq!(essai(MAGIQUE_SOMME, 0o120777, 12345), Ok(1));
        assert_eq!(essai(MAGIQUE, 0o100644, 12345), Ok(1));
        // La somme reboucle sur 32 bits : 16 843 010 octets 0xFF font
        // 4 294 967 550, soit 254.
        let mut a = Vec::new();
        ajouter_marque(&mut a, MAGIQUE_SOMME, b"gros", [1, 0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0], &std::vec![0xFF; 16_843_010], 254);
        fin(&mut a);
        assert_eq!(tout(&a).map(|e| e.len()), Ok(1));
    }

    #[test]
    fn contenu_selon_le_type() {
        let essai = |mode: u32, contenu: &[u8]| {
            let mut a = Vec::new();
            ajouter(&mut a, b"x", mode, contenu);
            fin(&mut a);
            tout(&a).map(|e| e.len())
        };
        // Un fichier ordinaire, avec ou sans contenu ; les autres, sans.
        assert_eq!(essai(0o100644, b"abc"), Ok(1));
        assert_eq!(essai(0o100644, b""), Ok(1));
        for mode in [0o040755, 0o010644, 0o020644, 0o060644, 0o140755] {
            assert_eq!(essai(mode, b""), Ok(1));
            assert_eq!(essai(mode, b"a"), Err(Erreur::Contenu { position: 0 }));
        }
        // Un lien symbolique : une cible d'un à 4095 octets, sans octet nul.
        assert_eq!(essai(0o120777, b"cible"), Ok(1));
        assert_eq!(essai(0o120777, &[b'a'; 4095]), Ok(1));
        assert_eq!(essai(0o120777, &[b'a'; 4096]), Err(Erreur::Lien { position: 0 }));
        assert_eq!(essai(0o120777, b""), Err(Erreur::Lien { position: 0 }));
        assert_eq!(essai(0o120777, b"ci\0ble"), Err(Erreur::Lien { position: 0 }));
        // Un type que Linux ne crée pas.
        assert_eq!(essai(0o000644, b""), Err(Erreur::Type { position: 0 }));
        assert_eq!(essai(0o170644, b""), Err(Erreur::Type { position: 0 }));
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
            Erreur::Odc { position: 2 },
            Erreur::Remplissage { position: 2 },
            Erreur::Somme { position: 2 },
            Erreur::Champ { position: 3, champ: "mode" },
            Erreur::Nom { position: 4 },
            Erreur::SansFin,
        ];
        for e in erreurs {
            assert!(std::format!("{e}").is_ascii());
        }
    }
}
