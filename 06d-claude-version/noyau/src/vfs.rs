//! Les fichiers, côté noyau : le système de fichiers de démarrage (un
//! tmpfs, ../fichiers), ses pages, et le déballage de l'archive.
//!
//! C'est le rootfs de Linux : au démarrage, avant tout pilote de disque,
//! Linux monte un tmpfs à la racine et y déballe l'initramfs, l'archive
//! cpio que lui a laissée le chargeur (init/initramfs.c,
//! `populate_rootfs`) ; puis il rend la mémoire de l'archive
//! (`free_initrd_mem`). On fait de même :
//!   - chaque entrée de l'archive devient un dossier, un fichier, un lien
//!     symbolique ou un nœud de périphérique, avec ses droits, son
//!     propriétaire et sa date ; les liens physiques (le même numéro
//!     d'inode, plusieurs liens, le contenu dans la dernière entrée) sont
//!     reliés, comme le `maybe_link` de Linux ;
//!   - le contenu d'un fichier est copié dans ses pages, une à une : le
//!     cpio aligne les contenus sur 4 octets, pas sur 4 Kio, une page de
//!     fichier ne peut donc pas être une page de l'archive. Le pic de
//!     mémoire est le double de l'archive, le temps du déballage ;
//!   - puis /dev, que Linux remplit avec son devtmpfs : null, zero, full,
//!     random, urandom, console ;
//!   - enfin l'archive retourne à l'allocateur de pages.
//!
//! Les pages des fichiers viennent de l'allocateur de pages, au-dessus de
//! la réserve du noyau (comme celles des programmes) : un programme qui
//! remplit /tmp ne prive pas le noyau. Le tmpfs a les limites de Linux par
//! défaut : la moitié de la mémoire, et autant d'inodes que la moitié des
//! pages (ENOSPC au-delà).
//!
//! Le système de fichiers est sous un verrou. Règles :
//!   - l'ordre : le verrou du processus, puis celui des fichiers, jamais
//!     l'inverse (une faute de page dans une projection de fichier tiendra
//!     le premier et prendra le second) ;
//!   - jamais de copie depuis ou vers un programme sous ce verrou : une
//!     copie peut faire une faute de page.
//! D'autres systèmes de fichiers se montent sur des dossiers du tmpfs
//! (../fichiers/src/montages.rs, 6d) : la résolution des chemins parcourt
//! une `Vue` de tous (`Systeme::avec_vue`), qui traverse les points de
//! montage.

use alloc::vec::Vec;
use core::fmt;

use crate::descripteurs::{Fichier, Ouverts, Tenu};
use crate::memoire::Echec;
use crate::verrou::Verrou;
use crate::{espace, pages, pile, temps};
use fichiers::chemins::{Depart, Fin, Suivre, resoudre};
use fichiers::montages::{Objet, Vue};
use fichiers::noyaufs::NoyauFs;
use fichiers::tmpfs::{Cadres, Horodatage, Limites, Numero, Tmpfs};
use fichiers::{Erreur, Identite, PAGE, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Temps};

/// Les pages des fichiers : des cadres de la mémoire, pris au-dessus de la
/// réserve du noyau, lus et écrits par la projection directe.
pub struct CadresDuNoyau;

impl Cadres for CadresDuNoyau {
    fn allouer(&mut self) -> Option<u64> {
        let cadre = pages::allouer_pour_programme()?;
        // SAFETY : le cadre vient d'être alloué, personne d'autre ne le
        // voit ; il contenait ce qu'y avait laissé son précédent occupant.
        unsafe { core::ptr::write_bytes(espace::virtuelle(cadre) as *mut u8, 0, PAGE as usize) };
        // Une page de fichier : jamais inscriptible dans une projection
        // privée (espace_utilisateur.rs, entree_finale).
        pages::marquer(cadre, pages::FICHIER);
        Some(cadre)
    }

    fn lacher(&mut self, page: u64) {
        pages::lacher(page);
    }

    fn ecrire(&mut self, page: u64, decalage: usize, octets: &[u8]) {
        assert!(decalage + octets.len() <= PAGE as usize);
        // SAFETY : `page` est une page d'un fichier, tenue par le système de
        // fichiers (dont on tient le verrou) ; on reste dans la page.
        unsafe {
            let destination = (espace::virtuelle(page) as *mut u8).add(decalage);
            core::ptr::copy_nonoverlapping(octets.as_ptr(), destination, octets.len());
        }
    }

    fn lire(&self, page: u64, decalage: usize, tampon: &mut [u8]) {
        assert!(decalage + tampon.len() <= PAGE as usize);
        // SAFETY : comme `ecrire`, en lecture.
        unsafe {
            let source = (espace::virtuelle(page) as *const u8).add(decalage);
            core::ptr::copy_nonoverlapping(source, tampon.as_mut_ptr(), tampon.len());
        }
    }
}

/// Ce que garde le verrou des fichiers : le système de fichiers de la
/// racine, la table des fichiers ouverts (descripteurs.rs), et les systèmes
/// montés, chacun avec son point de montage (un dossier du tmpfs, tenu) :
/// procfs sur /proc (le premier, `PROC`), sysfs sur /sys.
pub struct Systeme {
    pub fs: Tmpfs,
    pub ouverts: Ouverts,
    pub montes: Vec<(Numero, NoyauFs)>,
}

/// La place de procfs dans la table des montages (sysfs est la suivante).
pub const PROC: usize = 0;

impl Systeme {
    /// Le fichier ouvert `f` est tenu une fois de moins ; au dernier, il est
    /// fermé : le tmpfs rend son inode (et ses pages, si plus rien ne le
    /// tient).
    pub fn lacher(&mut self, f: Fichier, cadres: &mut CadresDuNoyau) {
        if let Some(ferme) = self.ouverts.lacher(f)
            && let Tenu::Tmpfs(ouvert) = ferme.tenu
        {
            self.fs.fermer(&ouvert, cadres);
        }
    }

    /// Appelle `f` avec la vue de tous les systèmes de fichiers, telle que
    /// la voit le processus `pid` (pour /proc/self ; 0 : le noyau, ou un
    /// programme WebAssembly, qui n'est pas un processus Linux).
    pub fn avec_vue<R>(&self, pid: u32, f: impl FnOnce(&Vue<NoyauFs>) -> R) -> R {
        let mut texte = [0u8; 10];
        let lecteur = decimal(pid, &mut texte);
        f(&Vue { fs: &self.fs, montes: &self.montes, lecteur })
    }

    /// Résout `chemin` depuis `depart`, pour le processus `pid`, à travers
    /// les montages (fichiers::montages).
    pub fn resoudre(&self, pid: u32, depart: &Depart<Objet>, chemin: &[u8], suivre: Suivre) -> Result<Fin<Objet>, Erreur> {
        self.avec_vue(pid, |vue| resoudre(vue, depart, chemin, suivre))
    }

    /// La racine de l'arborescence (celle du tmpfs).
    pub fn racine(&self) -> Objet {
        Objet::Tmpfs(self.fs.racine())
    }
}

/// `n` en décimal, dans `texte` (rien pour 0).
pub fn decimal(mut n: u32, texte: &mut [u8; 10]) -> &[u8] {
    let mut i = texte.len();
    while n > 0 {
        i -= 1;
        texte[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &texte[i..]
}

static RACINE: Verrou<Option<Systeme>> = Verrou::new(None);

/// Exécute `f` sur le système de fichiers, verrou tenu : court, et sans
/// copie depuis ou vers un programme.
pub fn avec<R>(f: impl FnOnce(&mut Tmpfs, &mut CadresDuNoyau) -> R) -> R {
    avec_systeme(|s, cadres| f(&mut s.fs, cadres))
}

/// Comme `avec`, avec aussi la table des fichiers ouverts.
pub fn avec_systeme<R>(f: impl FnOnce(&mut Systeme, &mut CadresDuNoyau) -> R) -> R {
    let mut racine = RACINE.verrouiller();
    f(racine.as_mut().expect("systeme de fichiers pas encore monte"), &mut CadresDuNoyau)
}

/// La page `cadre` d'un fichier, que l'appelant tient (pages::prendre),
/// vue par la projection directe : pour la copier vers un programme.
pub fn octets(cadre: u64) -> &'static [u8] {
    // SAFETY : le cadre est une page allouée, tenue par l'appelant : elle ne
    // sera pas rendue tant qu'il ne l'a pas lâchée. Un seul processeur :
    // personne ne l'écrit pendant qu'on la lit.
    unsafe { core::slice::from_raw_parts(espace::virtuelle(cadre) as *const u8, PAGE as usize) }
}

/// La même, pour y écrire (write) : l'appelant la tient, et elle est à un
/// fichier, pas projetée en écriture chez un programme.
#[allow(clippy::mut_from_ref)]
pub fn octets_mut(cadre: u64) -> &'static mut [u8] {
    // SAFETY : comme `octets` ; la page n'est vue que par le noyau, qui
    // l'écrit ici, et les projections en lecture des programmes.
    unsafe { core::slice::from_raw_parts_mut(espace::virtuelle(cadre) as *mut u8, PAGE as usize) }
}

/// La page numéro `index` du fichier ouvert `f`, pour une faute de page
/// dans une zone qui le projette : créée si c'est un trou (comme le
/// `shmem_fault` de Linux, pour qu'une page privée pas encore copiée soit
/// toujours la page du fichier). Au-delà de la fin du fichier (à la page
/// près) : `HorsDuFichier` (SIGBUS) ; le tmpfs plein : `PlusDePlace`
/// (SIGBUS aussi, comme Linux) ; plus de mémoire : `PlusDeMemoire` (le
/// tueur OOM).
pub fn page_projetee(f: Fichier, index: u64) -> Result<u64, Echec> {
    avec_systeme(|s, cadres| {
        let n = s.ouverts.fichier(f).inode();
        if index >= s.fs.attributs(n).taille.div_ceil(PAGE) {
            return Err(Echec::HorsDuFichier);
        }
        s.fs.page_pour_ecrire(n, index, cadres).map_err(|e| match e {
            Erreur::ENOSPC => Echec::PlusDePlace,
            Erreur::ENOMEM => Echec::PlusDeMemoire,
            _ => Echec::HorsDuFichier,
        })
    })
}

/// Lit le fichier `n` à partir de `position` dans `tampon` (pour le
/// noyau : un programme à exécuter). Rend le nombre d'octets lus, moins que
/// demandé à la fin du fichier.
pub fn lire(n: Numero, position: u64, tampon: &mut [u8]) -> usize {
    avec(|fs, cadres| fs.lire(n, position, tampon, cadres))
}

/// Ce que le déballage a fait, pour l'afficher.
#[derive(Default)]
pub struct Bilan {
    pub dossiers: usize,
    pub fichiers: usize,
    pub liens_symboliques: usize,
    pub liens_physiques: usize,
    /// Les entrées refusées (le noyau a dit pourquoi).
    pub refusees: usize,
}

/// Une date de l'archive (en secondes).
fn date(secondes: u32) -> Horodatage {
    Horodatage::Valeur(Temps { secondes: secondes as i64, nanosecondes: 0 })
}

/// Le chemin absolu d'une entrée de l'archive (« bin/x » : « /bin/x »).
fn absolu(nom: &[u8]) -> Result<Vec<u8>, Erreur> {
    let mut chemin = Vec::new();
    chemin.try_reserve_exact(nom.len() + 1).map_err(|_| Erreur::ENOMEM)?;
    chemin.push(b'/');
    chemin.extend_from_slice(nom);
    Ok(chemin)
}

/// Le nom d'une entrée, pour un message (sans accents : tel quel, l'ASCII
/// imprimable seulement).
struct Chemin<'a>(&'a [u8]);

impl fmt::Display for Chemin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", crate::programmes::Nom(self.0))
    }
}

/// Monte le système de fichiers de la racine, y déballe `archive` (si le
/// chargeur en a laissé une), puis crée /dev.
pub fn initialiser(archive: Option<&[u8]>) -> Result<Bilan, Erreur> {
    let total = pages::total() as u64;
    let limites = Limites { inodes: (total / 2).min(u32::MAX as u64) as u32, pages: total / 2 };
    *RACINE.verrouiller() = Some(Systeme { fs: Tmpfs::new(limites, temps::maintenant())?, ouverts: Ouverts::default(), montes: Vec::new() });
    let mut bilan = Bilan::default();
    if let Some(octets) = archive {
        deballer(octets, &mut bilan)?;
    }
    creer_dev()?;
    monter("procfs", b"/proc", crate::procfs::creer)?;
    monter("sysfs", b"/sys", crate::sysfs::creer)?;
    Ok(bilan)
}

/// Monte le système que fabrique `creer` sur le dossier `chemin` du tmpfs,
/// créé s'il n'existe pas (0555, à root, comme /proc et /sys dans une
/// distribution), comme le fait un init (« mount -t proc proc /proc ») :
/// ici, le noyau en tient le rôle. Le dossier est tenu tant que le système
/// y est monté.
fn monter(nom: &str, chemin: &[u8], creer: fn(Temps) -> Result<NoyauFs, Erreur>) -> Result<(), Erreur> {
    let maintenant = temps::maintenant();
    let systeme = creer(maintenant)?;
    avec_systeme(|s, _| {
        s.montes.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
        let racine = s.fs.racine();
        let depart = Depart { racine, dossier: racine, qui: Identite::ROOT, sous: false };
        let fin = resoudre(&s.fs, &depart, chemin, Suivre::Jamais)?;
        let point = match fin.objet {
            Some(n) if s.fs.mode(n) & S_IFMT == S_IFDIR => n,
            Some(_) => return Err(Erreur::ENOTDIR),
            None => s.fs.creer(Identite::ROOT, &fin, S_IFDIR | 0o555, (0, 0), &[], maintenant)?,
        };
        s.fs.prendre(point);
        s.montes.push((point, systeme));
        Ok(())
    })?;
    afficherln!("[noyau] {} monte sur {}.", nom, Chemin(chemin));
    Ok(())
}

/// Le déballage, entrée par entrée. Une entrée refusée (un dossier parent
/// qui manque, plus de place) est signalée, et la suite continue, comme
/// Linux. L'archive a été vérifiée d'avance, en entier.
fn deballer(octets: &[u8], bilan: &mut Bilan) -> Result<(), Erreur> {
    // Les fichiers déjà vus qui ont des liens physiques : (inode dans
    // l'archive, inode chez nous).
    let mut vus: Vec<(u32, Numero)> = Vec::new();
    for entree in formats::cpio::lire(octets).flatten() {
        if entree.nom.is_empty() || entree.nom == b"." {
            continue;
        }
        let chemin = absolu(entree.nom)?;
        let resultat = deballer_entree(&entree, &chemin, &mut vus, bilan);
        if let Err(e) = resultat {
            afficherln!("[noyau] archive : {} refuse (errno {})", Chemin(&chemin), e.errno());
            bilan.refusees += 1;
        }
    }
    Ok(())
}

fn deballer_entree(entree: &formats::cpio::Entree, chemin: &[u8], vus: &mut Vec<(u32, Numero)>, bilan: &mut Bilan)
    -> Result<(), Erreur> {
    let root = Identite::ROOT;
    let maintenant = temps::maintenant();
    let droits = entree.mode & 0o7777;
    let numero = avec(|fs, cadres| -> Result<Option<Numero>, Erreur> {
        let racine = fs.racine();
        let depart = Depart { racine, dossier: racine, qui: root, sous: false };
        let fin = resoudre(fs, &depart, chemin, Suivre::Jamais)?;
        let genre = entree.mode & S_IFMT;
        // Ce qui est déjà là sous ce nom : un dossier se garde (on lui
        // applique les droits de l'archive), le reste s'efface (le
        // `clean_path` de Linux), sauf un lien physique déjà vu.
        if let Some(existant) = fin.objet {
            let dossier_existant = fs.mode(existant) & S_IFMT == S_IFDIR;
            if genre == S_IFDIR && dossier_existant {
                proprietes(fs, existant, entree, maintenant)?;
                return Ok(None);
            }
            fs.effacer(root, &fin, dossier_existant, maintenant, cadres)?;
        }
        let fin = resoudre(fs, &depart, chemin, Suivre::Jamais)?;
        if genre == S_IFREG
            && entree.liens >= 2
            && let Some(&(_, premier)) = vus.iter().find(|(ino, _)| *ino == entree.inode)
        {
            fs.lier(root, premier, &fin, maintenant)?;
            bilan.liens_physiques += 1;
            return Ok(Some(premier));
        }
        let (mode, cible) = match genre {
            S_IFDIR => (S_IFDIR | droits, &[][..]),
            S_IFREG => (S_IFREG | droits, &[][..]),
            S_IFLNK => (S_IFLNK | droits, entree.contenu),
            S_IFCHR => (S_IFCHR | droits, &[][..]),
            _ => return Err(Erreur::EINVAL),
        };
        let n = fs.creer(root, &fin, mode, entree.rdev, cible, maintenant)?;
        match genre {
            S_IFDIR => bilan.dossiers += 1,
            S_IFREG => bilan.fichiers += 1,
            S_IFLNK => bilan.liens_symboliques += 1,
            _ => {}
        }
        if genre == S_IFREG && entree.liens >= 2 {
            vus.try_reserve(1).map_err(|_| Erreur::ENOMEM)?;
            vus.push((entree.inode, n));
        }
        Ok(Some(n))
    })?;
    // (Un nom que l'archive répète : le dernier compte, comme pour Linux ;
    // l'ancien a été effacé plus haut.)
    let Some(n) = numero else { return Ok(()) };
    // Le contenu d'un fichier, page à page, en rendant le verrou entre
    // deux : copier des centaines de Mio d'un coup, interruptions coupées,
    // ferait perdre ses tics à l'horloge (et l'heure retarderait).
    if entree.mode & S_IFMT == S_IFREG {
        let mut fait = 0;
        while fait < entree.contenu.len() {
            let morceau = &entree.contenu[fait..(fait + PAGE as usize).min(entree.contenu.len())];
            let ecrits = avec(|fs, cadres| fs.ecrire(n, fait as u64, morceau, maintenant, cadres))?;
            fait += ecrits;
        }
    }
    avec(|fs, _| proprietes(fs, n, entree, maintenant))
}

/// Le propriétaire, les droits et la date de l'archive (dans cet ordre :
/// changer de propriétaire fait tomber les bits setuid et setgid).
fn proprietes(fs: &mut Tmpfs, n: Numero, entree: &formats::cpio::Entree, maintenant: Temps) -> Result<(), Erreur> {
    let root = Identite::ROOT;
    fs.changer_proprietaire(root, n, Some(entree.uid), Some(entree.gid), maintenant)?;
    if entree.mode & S_IFMT != S_IFLNK {
        fs.changer_mode(root, n, entree.mode, maintenant)?;
    }
    fs.changer_temps(root, n, date(entree.date), date(entree.date), maintenant)
}

// Les périphériques de /dev : majeur, mineur (Documentation/admin-guide/
// devices.txt), nom, droits.
pub const NULL: (u32, u32) = (1, 3);
pub const ZERO: (u32, u32) = (1, 5);
pub const FULL: (u32, u32) = (1, 7);
pub const RANDOM: (u32, u32) = (1, 8);
pub const URANDOM: (u32, u32) = (1, 9);
pub const CONSOLE: (u32, u32) = (5, 1);

/// Crée /dev et ses périphériques, comme le devtmpfs de Linux : à root, en
/// 0666, sauf la console, qui est au terminal de l'utilisateur (0620, à
/// lui), comme celle d'une session ouverte (et comme fstat la décrivait
/// déjà, à l'étape 5).
fn creer_dev() -> Result<(), Erreur> {
    let maintenant = temps::maintenant();
    avec(|fs, _| {
        let racine = fs.racine();
        let depart = Depart { racine, dossier: racine, qui: Identite::ROOT, sous: false };
        let fin = resoudre(fs, &depart, b"/dev", Suivre::Jamais)?;
        if fin.objet.is_none() {
            fs.creer(Identite::ROOT, &fin, S_IFDIR | 0o755, (0, 0), &[], maintenant)?;
        }
        let peripheriques: [(&[u8], (u32, u32), u32); 6] = [
            (b"/dev/null", NULL, 0o666),
            (b"/dev/zero", ZERO, 0o666),
            (b"/dev/full", FULL, 0o666),
            (b"/dev/random", RANDOM, 0o666),
            (b"/dev/urandom", URANDOM, 0o666),
            (b"/dev/console", CONSOLE, 0o620),
        ];
        for (chemin, rdev, droits) in peripheriques {
            let fin = resoudre(fs, &depart, chemin, Suivre::Jamais)?;
            if fin.objet.is_some() {
                continue;
            }
            let n = fs.creer(Identite::ROOT, &fin, S_IFCHR | droits, rdev, &[], maintenant)?;
            if rdev == CONSOLE {
                fs.changer_proprietaire(Identite::ROOT, n, Some(pile::UTILISATEUR as u32), Some(pile::GROUPE as u32), maintenant)?;
            }
        }
        Ok(())
    })
}
