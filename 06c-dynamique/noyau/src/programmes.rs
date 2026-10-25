//! Les programmes de l'archive de démarrage : la déballer, lancer ce que
//! dit /etc/demarrage, reconnaître le format de chaque programme, les
//! exécuter.
//!
//! Le chargeur a déposé à côté du noyau une archive cpio (voir
//! ../formats/src/cpio.rs) ; le noyau la déballe dans son système de
//! fichiers (vfs.rs), puis lit /etc/demarrage : une commande par ligne,
//! avec ses arguments et son environnement, lancées l'une après l'autre
//! (la syntaxe : ../formats/src/commande.rs). Sans `fork` ni `execve`
//! (6k), aucun programme ne peut en lancer un autre : le noyau joue le
//! rôle d'`init` en attendant. En 6k, un vrai /init, lancé par son chemin
//! comme sous Linux, lancera un shell, et ce fichier deviendra un script.
//!
//! Le format d'un programme se reconnaît à ses premiers octets, sa
//! « signature » (magic number) :
//!   - « \0asm » : un module WebAssembly, le format natif de l'OS ;
//!   - « \x7fELF » : un exécutable Linux.
//! C'est le principe des « binfmt » de Linux (fs/binfmt_elf.c,
//! fs/binfmt_script.c pour « #! », binfmt_misc pour le reste) : chaque
//! format est essayé tour à tour, et le premier qui reconnaît le fichier
//! s'en charge. Le nom du fichier (son extension) ne compte pas.

use crate::descripteurs::Descripteurs;
use crate::memoire::Acces;
use crate::{appels_fichiers, chargeur_elf, demarrage, espace, pages, pile, processus, tache, vfs, wasi};
use fichiers::Identite;
use alloc::vec::Vec;
use core::fmt;
use fichiers::tmpfs::Numero;

/// L'environnement des programmes : de quoi savoir où est le dossier
/// personnel (/home/utilisateur, à l'utilisateur 1000, voir archive.txt),
/// et quel terminal les affiche (la console : un terminal « linux », comme
/// la console de Linux). Une ligne de /etc/demarrage peut en remplacer une
/// variable, ou en ajouter (`NOM=valeur` en tête, comme le shell).
const ENVIRONNEMENT: &[&[u8]] = &[b"HOME=/home/utilisateur", b"TERM=linux"];

/// Le fichier des commandes à lancer, et sa taille maximale : une page
/// suffit à des dizaines de lignes ; 64 Kio laissent de la marge sans
/// laisser un fichier géant remplir le tas du noyau.
const DEMARRAGE: &[u8] = b"/etc/demarrage";
const DEMARRAGE_MAX: u64 = 64 << 10;

/// L'identité des programmes : l'utilisateur 1000 (pile.rs).
const IDENTITE: Identite = Identite { uid: pile::UTILISATEUR as u32, gid: pile::GROUPE as u32 };

/// Le nom d'un programme en cours, pour les messages : le nom de base de
/// son fichier, coupé à 15 octets, comme le `comm` de la task_struct de
/// Linux (TASK_COMM_LEN, 16 avec le zéro final). Une valeur, et pas une
/// tranche : le fichier peut être renommé ou effacé pendant que le
/// programme tourne.
#[derive(Clone, Copy)]
pub struct NomCourt {
    octets: [u8; 15],
    longueur: u8,
}

impl NomCourt {
    pub const VIDE: NomCourt = NomCourt { octets: [0; 15], longueur: 0 };

    pub fn de(nom: &[u8]) -> NomCourt {
        let mut n = NomCourt::VIDE;
        let longueur = nom.len().min(n.octets.len());
        n.octets[..longueur].copy_from_slice(&nom[..longueur]);
        n.longueur = longueur as u8;
        n
    }

    pub fn octets(&self) -> &[u8] {
        &self.octets[..self.longueur as usize]
    }
}

impl fmt::Display for NomCourt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Nom(self.octets()).fmt(f)
    }
}

/// Le nom d'une entrée, pour l'afficher : un nom de fichier peut contenir
/// n'importe quel octet, que la console afficherait de travers. On montre
/// l'ASCII imprimable tel quel, et « ? » pour le reste.
#[derive(Clone, Copy)]
pub struct Nom<'a>(pub &'a [u8]);

impl fmt::Display for Nom<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &o in self.0 {
            let c = if o.is_ascii_graphic() || o == b' ' { o as char } else { '?' };
            fmt::Write::write_char(f, c)?;
        }
        // Une largeur demandée ({:<24}) : des espaces après le nom (un
        // caractère affiché par octet).
        for _ in self.0.len()..f.width().unwrap_or(0) {
            fmt::Write::write_char(f, ' ')?;
        }
        Ok(())
    }
}

/// L'archive de démarrage, telle que le chargeur l'a déposée : une tranche
/// de mémoire physique, vue par la projection directe. Elle ne sert que le
/// temps du déballage (voir `demarrer`).
fn archive() -> Option<&'static [u8]> {
    let etendue = demarrage::archive()?;
    // SAFETY : l'étendue est celle que le chargeur a remplie avec l'archive ;
    // l'allocateur de démarrage l'a réservée (cadres.rs), elle n'a donc été
    // donnée à personne d'autre, et personne ne l'écrit. Elle est dans la
    // mémoire libre de la carte (le chargeur l'a vérifié), donc dans la
    // projection directe. Elle n'est rendue à l'allocateur de pages qu'une
    // fois déballée, quand plus personne ne la lit.
    Some(unsafe {
        core::slice::from_raw_parts(espace::virtuelle(etendue.debut) as *const u8, (etendue.fin - etendue.debut) as usize)
    })
}

/// Déballe l'archive de démarrage dans le système de fichiers de la racine
/// (vfs.rs), rend sa mémoire, puis lance les commandes de /etc/demarrage.
/// Une archive mal formée est refusée en entier, avant de rien déballer :
/// on ne lance pas la moitié d'un système.
pub fn demarrer() {
    let octets = archive();
    let mut valide = octets;
    match octets {
        None => afficherln!("[noyau] Pas d'archive de programmes."),
        Some(o) => {
            afficherln!("[noyau] Archive de programmes : {} octets a {:#x}.", o.len(), demarrage::archive().map_or(0, |a| a.debut));
            if let Some(Err(e)) = formats::cpio::lire(o).find(Result::is_err) {
                afficherln!("[noyau] Archive refusee : {}", e);
                valide = None;
            }
        }
    }
    let bilan = match vfs::initialiser(valide) {
        Ok(b) => b,
        Err(e) => return afficherln!("[noyau] Systeme de fichiers impossible a monter (errno {}).", e.errno()),
    };
    // L'archive retourne à l'allocateur de pages : ses pages entières (les
    // deux du bord peuvent être partagées avec ce qui la touche).
    let rendus = demarrage::archive().map_or(0, |a| {
        let (debut, fin) = (a.debut.next_multiple_of(4096), a.fin / 4096 * 4096);
        if fin > debut {
            pages::ajouter_memoire(debut, fin);
        }
        fin.saturating_sub(debut)
    });
    if valide.is_some() {
        afficherln!("[noyau] Archive deballee : dossiers {}, fichiers {}, liens symboliques {}, liens physiques {}{} ; archive rendue ({} Kio).",
                    bilan.dossiers, bilan.fichiers, bilan.liens_symboliques, bilan.liens_physiques,
                    if bilan.refusees > 0 { " (des entrees refusees)" } else { "" }, rendus >> 10);
    }
    let texte = match lire_demarrage() {
        Ok(t) => t,
        // Linux, sans init, panique (« No working init found ») : ici, le
        // noyau le dit et continue (il n'a plus rien à faire, mais le
        // clavier marche encore).
        Err(e) => return afficherln!("[noyau] {} illisible (errno {}) : rien a lancer.", Nom(DEMARRAGE), e.errno()),
    };
    // Les lignes qui ont une commande (ou une erreur) : les autres sont
    // vides, ou des commentaires.
    let commandes = formats::commande::lignes(&texte)
        .filter(|(_, l)| tampon_pour(l).is_none_or(|mut t| !matches!(formats::commande::decouper(l, &mut t), Ok(None))))
        .count();
    afficherln!("[noyau] Lancement : {}, {} commandes.", Nom(DEMARRAGE), commandes);
    for (numero, ligne) in formats::commande::lignes(&texte) {
        let Some(mut tampon) = tampon_pour(ligne) else {
            afficherln!("[noyau] {}, ligne {} : plus de memoire pour la lire", Nom(DEMARRAGE), numero);
            continue;
        };
        match formats::commande::decouper(ligne, &mut tampon) {
            Ok(None) => {}
            Ok(Some(commande)) => lancer(numero, &commande),
            Err(e) => afficherln!("[noyau] {}, ligne {} : refusee : {}", Nom(DEMARRAGE), numero, e),
        }
    }
}

/// Le tampon où découper `ligne` (formats::commande), s'il y a la place.
fn tampon_pour(ligne: &[u8]) -> Option<Vec<u8>> {
    let mut tampon = Vec::new();
    tampon.try_reserve_exact(formats::commande::taille_tampon(ligne)).ok()?;
    tampon.resize(formats::commande::taille_tampon(ligne), 0);
    Some(tampon)
}

/// Le contenu de /etc/demarrage, lu en root (comme `init` lit son
/// `inittab`), dans un bloc du tas.
fn lire_demarrage() -> Result<Vec<u8>, fichiers::Erreur> {
    let n = appels_fichiers::trouver_pour(Identite::ROOT, DEMARRAGE)?;
    let (mode, taille) = vfs::avec(|fs, _| {
        let a = fs.attributs(n);
        (a.mode, a.taille)
    });
    let mut texte = Vec::new();
    // Un fichier ordinaire seulement : vfs::lire ne sait lire que lui.
    let lu = if mode & fichiers::S_IFMT == fichiers::S_IFDIR {
        Err(fichiers::Erreur::EISDIR)
    } else if mode & fichiers::S_IFMT != fichiers::S_IFREG {
        Err(fichiers::Erreur::EINVAL)
    } else if taille > DEMARRAGE_MAX {
        Err(fichiers::Erreur::EFBIG)
    } else if texte.try_reserve_exact(taille as usize).is_err() {
        Err(fichiers::Erreur::ENOMEM)
    } else {
        texte.resize(taille as usize, 0);
        let lus = vfs::lire(n, 0, &mut texte);
        texte.truncate(lus);
        Ok(texte)
    };
    vfs::avec(|fs, cadres| fs.lacher(n, cadres));
    lu
}

/// Lance la commande de la ligne `numero` : son environnement (celui du
/// noyau, remplacé ou complété par ses affectations), son programme
/// (résolu comme `execve`, sans `PATH`, avec les droits de l'utilisateur
/// 1000), ses arguments.
fn lancer(numero: usize, commande: &formats::commande::Commande) {
    let programme = commande.programme();
    let refus = |raison: &dyn fmt::Display| afficherln!("[noyau] {}, ligne {} : refusee : {}", Nom(DEMARRAGE), numero, raison);
    let (mut environnement, mut arguments, mut dossiers) = (Vec::new(), Vec::new(), Vec::new());
    let place = ENVIRONNEMENT.len() + commande.affectations().count();
    if environnement.try_reserve_exact(place).is_err()
        || arguments.try_reserve_exact(commande.arguments().count()).is_err()
        || dossiers.try_reserve_exact(commande.dossiers().count()).is_err()
    {
        return refus(&"plus de memoire");
    }
    environnement.extend_from_slice(ENVIRONNEMENT);
    for affectation in commande.affectations() {
        // « NOM=... » remplace la variable NOM du noyau, comme le shell.
        let nom = &affectation[..=affectation.iter().position(|&o| o == b'=').unwrap_or(0)];
        match environnement.iter().position(|v| v.starts_with(nom)) {
            Some(i) => environnement[i] = affectation,
            None => environnement.push(affectation),
        }
    }
    arguments.extend(commande.arguments());
    dossiers.extend(commande.dossiers());
    let n = match appels_fichiers::trouver_pour(IDENTITE, programme) {
        Ok(n) => n,
        Err(e) => return refus(&format_args!("{} : introuvable (errno {})", Nom(programme), e.errno())),
    };
    let lancement = Lancement { chemin: programme, arguments: &arguments, environnement: &environnement, dossiers: &dossiers };
    executer(numero, n, &lancement);
    vfs::avec(|fs, cadres| fs.lacher(n, cadres));
}

/// Ce qu'une ligne de /etc/demarrage donne au programme.
struct Lancement<'a> {
    /// Son chemin (AT_EXECFN), tel qu'écrit.
    chemin: &'a [u8],
    /// argv : le chemin, puis les arguments.
    arguments: &'a [&'a [u8]],
    /// envp : des « NOM=valeur ».
    environnement: &'a [&'a [u8]],
    /// Les dossiers pré-ouverts d'un programme WebAssembly.
    dossiers: &'a [&'a [u8]],
}

/// Exécute le programme du fichier `n`, d'après sa signature.
fn executer(numero: usize, n: Numero, lancement: &Lancement) {
    let chemin = lancement.chemin;
    let nom = NomCourt::de(chemin.rsplit(|&o| o == b'/').next().unwrap_or(chemin));
    // Le droit de l'exécuter d'abord, quel que soit son format : un fichier
    // ordinaire, avec le bit x pour l'utilisateur 1000 (EACCES sinon, pour
    // un dossier ou un périphérique aussi, comme do_open_execat). Avant de
    // rien lire : vfs::lire ne sait lire qu'un fichier ordinaire.
    if let Err(e) = vfs::avec(|fs, _| fs.peut_executer(IDENTITE, n)) {
        return afficherln!("[noyau] {} : pas le droit de l'executer (errno {})", nom, e.errno());
    }
    let mut signature = [0u8; 4];
    let lus = vfs::lire(n, 0, &mut signature);
    match &signature[..lus] {
        [0, b'a', b's', b'm'] => executer_wasm(nom, n, lancement),
        // Les dossiers pré-ouverts sont une affaire de WebAssembly : un
        // programme Linux voit tout l'arbre, avec ses droits.
        [0x7f, b'E', b'L', b'F'] if !lancement.dossiers.is_empty() => {
            afficherln!("[noyau] {}, ligne {} : refusee : --dir= pour un programme Linux", Nom(DEMARRAGE), numero)
        }
        [0x7f, b'E', b'L', b'F'] => executer_elf(nom, n, lancement),
        _ => afficherln!("[noyau] {} : format inconnu, ignore.", nom),
    }
}

/// Un programme Linux : on vérifie le fichier, on le charge dans un espace
/// d'adressage neuf, puis on l'exécute, dans l'anneau 3, jusqu'à ce qu'il se
/// termine. Son espace est alors détruit, et doit rendre toute sa mémoire.
fn executer_elf(nom: NomCourt, n: Numero, lancement: &Lancement) {
    let chemin = lancement.chemin;
    // Le fichier, lu par morceaux : la bibliothèque des formats ne voit que
    // des copies (chargeur_elf::verifier).
    let lire = |position: u64, tampon: &mut [u8]| vfs::lire(n, position, tampon) == tampon.len();
    let taille = vfs::avec(|fs, _| fs.attributs(n).taille);
    let (entete, table) = match chargeur_elf::verifier(taille, lire) {
        Ok(v) => v,
        Err(e) => return afficherln!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    let executable = match formats::elf::lire_entetes(&entete, &table, taille) {
        Ok(x) => x,
        Err(e) => return afficherln!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    // Un programme dynamique : le chemin de son interpréteur, lu dans le
    // fichier (hors de la table des en-têtes), dans un bloc du tas (4 Kio
    // au plus : la pile du noyau ne fait que 16 Kio).
    if let Some((position, longueur)) = executable.interpreteur() {
        let mut interpreteur = Vec::new();
        if interpreteur.try_reserve_exact(longueur).is_err() {
            return afficherln!("[noyau] {} : plus de memoire pour le chemin de l'interpreteur", nom);
        }
        interpreteur.resize(longueur, 0);
        if !lire(position, &mut interpreteur) {
            return afficherln!("[noyau] {} : programme Linux refuse : {}", nom, formats::elf::Erreur::InterpreteurHorsDuFichier);
        }
        return match formats::elf::chemin_interpreteur(&interpreteur) {
            Ok(c) => afficherln!("[noyau] {} : programme dynamique (PT_INTERP {}) : pas encore pris en charge", nom, Nom(c)),
            Err(e) => afficherln!("[noyau] {} : programme Linux refuse : {}", nom, e),
        };
    }
    if executable.genre() == formats::elf::Genre::Relogeable {
        return afficherln!("[noyau] {} : programme Linux refuse : ELF ET_DYN : pas encore pris en charge", nom);
    }
    // Un ET_EXEC : à ses propres adresses, qui doivent être permises.
    let executable = match executable.placer(executable.etendue().0, chargeur_elf::PERMISES) {
        Ok(x) => x,
        Err(e) => return afficherln!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    afficherln!("[noyau] {} : programme Linux (ELF), {} octets, point d'entree {:#x}, segments :",
                nom, taille, executable.entree());
    for s in executable.segments() {
        afficherln!("        {:#010x}-{:#010x} {}{}{} ({} octets du fichier)",
                    s.adresse, s.adresse + s.taille, 'r',
                    if s.ecriture { 'w' } else { '-' }, if s.execution { 'x' } else { '-' }, s.taille_fichier);
    }
    let identite = IDENTITE;
    let libres = pages::libres();
    // Le fichier ouvert que projetteront ses segments : chaque zone le
    // tiendra ; l'ouverture du chargeur est lâchée ensuite.
    let fichier = match appels_fichiers::ouvrir_inode(n, chemin, crate::descripteurs::Sorte::Fichier) {
        Ok(f) => f,
        Err(e) => return afficherln!("[noyau] {} : ouverture impossible (errno {})", nom, e.errno()),
    };
    let charge = chargeur_elf::charger(&executable, nom, fichier);
    vfs::avec_systeme(|s, cadres| s.lacher(fichier, cadres));
    let mut programme = match charge {
        Ok(p) => p,
        Err(e) => return afficherln!("[noyau] {} : chargement impossible : {}", nom, e),
    };
    // Le code au point d'entrée, relu dans l'espace du programme, doit être
    // celui du fichier.
    // (16 octets au plus : ce qu'il reste du fichier après le point
    // d'entrée, dans son segment.)
    let mut attendu = [0u8; 16];
    let longueur = executable
        .segments()
        .find_map(|s| {
            let decalage = programme.entree.checked_sub(s.adresse).filter(|&d| d < s.taille_fichier)?;
            let longueur = (s.taille_fichier - decalage).min(16) as usize;
            lire(s.position + decalage, &mut attendu[..longueur]).then_some(longueur)
        })
        .unwrap_or(0);
    // La page du point d'entrée vient d'abord, comme le ferait la première
    // instruction du programme (elle n'est en place qu'à la faute).
    let mut code = [0u8; 16];
    let code_ok = programme.memoire.servir(programme.entree, Acces::Lecture).is_ok()
        && programme.memoire.espace.lire(programme.entree, &mut code[..longueur]).is_ok()
        && code[..longueur] == attendu[..longueur];
    // Le tas commence à la page qui suit le dernier segment.
    afficherln!("        en-tetes de programme a {:#x} ({} de {} octets), tas a partir de {:#x}, code en place : {}.",
                programme.adresse_entetes.unwrap_or(0), programme.nombre_entetes, programme.taille_entete,
                programme.fin.next_multiple_of(4096), if code_ok { "ok" } else { "ECHEC" });
    // Sa pile initiale : les arguments et l'environnement de sa ligne,
    // son chemin pour AT_EXECFN (comme Linux, le chemin donné à execve).
    let rsp = match pile::construire(&mut programme, lancement.arguments, lancement.environnement, chemin) {
        Ok(rsp) => rsp,
        Err(e) => return afficherln!("[noyau] {} : pile initiale impossible : {}", nom, e),
    };
    // Le programme devient le processus en cours : avec la console en 0,
    // 1 et 2, la racine pour dossier courant, l'umask de Linux, et
    // l'identité de l'utilisateur 1000.
    let mut descripteurs = Descripteurs::new();
    if let Err(e) = appels_fichiers::ouvrir_console(&mut descripteurs) {
        return afficherln!("[noyau] {} : pas de console (errno {})", nom, e.errno());
    }
    let racine = vfs::avec(|fs, _| {
        let r = fs.racine();
        // Le dossier courant et la racine tiennent chacun l'inode.
        fs.prendre(r);
        fs.prendre(r);
        r
    });
    let (pml4, entree) = (programme.memoire.espace.pml4(), programme.entree);
    processus::installer(processus::Processus {
        memoire: programme.memoire,
        descripteurs,
        dossier: racine,
        racine,
        umask: 0o022,
        identite,
        limites: processus::LIMITES_PAR_DEFAUT,
    });
    // Plus personne ne peut écrire le fichier tant qu'il s'exécute
    // (ETXTBSY) : ses pages seront bientôt celles du programme.
    let code = match vfs::avec(|fs, _| fs.refuser_ecriture(n)) {
        Ok(()) => {
            let code = tache::executer(nom, pml4, entree, rsp);
            vfs::avec(|fs, _| fs.permettre_ecriture(n));
            code
        }
        Err(_) => {
            afficherln!("[noyau] {} : ouvert en ecriture, ne peut pas etre execute (ETXTBSY)", nom);
            -1
        }
    };
    drop(processus::retirer());
    afficherln!("[noyau] {} : termine, code de sortie {} ; memoire rendue : {}.",
                nom, code, if pages::libres() == libres { "ok" } else { "ECHEC" });
}

/// Un programme WebAssembly : on le décode, le valide, l'instancie avec
/// WASI, puis on appelle son point d'entrée _start par tranches de
/// carburant : entre deux tranches, le noyau pourrait faire autre chose
/// (exécuter un autre programme). Les interruptions de l'horloge et du
/// clavier, elles, continuent d'arriver pendant tout ce temps, même pendant
/// une écriture du programme (la console écrit par petits paquets).
fn executer_wasm(nom: NomCourt, n: Numero, lancement: &Lancement) {
    use alloc::sync::Arc;
    use wasm::{Etat, Externe, Magasin, Piege};

    const TRANCHE: u64 = 1000;

    // L'interpréteur veut le module d'un seul tenant : il est lu dans un
    // bloc du tas, qui fait au plus 4 Mio (tas.rs) ; un module plus gros est
    // refusé, jusqu'à ce que le noyau sache projeter des pages éparses d'un
    // seul tenant (vmalloc).
    let taille = vfs::avec(|fs, _| fs.attributs(n).taille) as usize;
    let mut octets = Vec::new();
    if octets.try_reserve_exact(taille).is_err() {
        return afficherln!("[noyau] {} : module WebAssembly de {} octets, trop gros pour le tas", nom, taille);
    }
    octets.resize(taille, 0);
    if vfs::lire(n, 0, &mut octets) != taille {
        return afficherln!("[noyau] {} : module WebAssembly illisible", nom);
    }

    let module = match wasm::decoder(&octets).and_then(wasm::valider) {
        Ok(m) => Arc::new(m),
        Err(e) => return afficherln!("[noyau] {} : programme WebAssembly refuse : {}", nom, e),
    };
    afficherln!("[noyau] {} : programme WebAssembly, {} octets, decode et valide.", nom, octets.len());
    // Son budget de mémoire : 16 Mio pour ses tables et sa mémoire, chacune
    // d'au plus 4 Mio (un bloc du tas, voir tas.rs).
    let mut magasin = Magasin::avec_budget(16 << 20);
    // Ses descripteurs : la console, et les dossiers pré-ouverts de sa
    // ligne ; ses arguments et son environnement.
    let mut hote = match wasi::Wasi::new(IDENTITE, lancement.dossiers, lancement.arguments, lancement.environnement) {
        Ok(h) => h,
        Err((e, Some(dossier))) => {
            return afficherln!("[noyau] {} : --dir={} impossible (errno {})", nom, Nom(dossier), e.errno());
        }
        Err((e, None)) => return afficherln!("[noyau] {} : pas de descripteurs (errno {})", nom, e.errno()),
    };
    let imports = match wasi::imports(&mut magasin, &module) {
        Ok(i) => i,
        Err(e) => return afficherln!("[noyau] {} : programme non liable : {}", nom, e),
    };
    let instance = match magasin.instancier(module, &imports) {
        Ok(i) if i.demarrage.is_none() => i.instance,
        Ok(_) => return afficherln!("[noyau] {} : programme refuse, fonction de demarrage inattendue", nom),
        Err(e) => return afficherln!("[noyau] {} : programme non instanciable : {}", nom, e),
    };
    let Some(Externe::Fonction(debut)) = magasin.exporte(instance, "_start") else {
        return afficherln!("[noyau] {} : programme sans _start", nom);
    };
    // WASI veut un _start de type [] -> [] : un programme qui en attend des
    // arguments est refusé, comme le reste, sans que le noyau s'arrête.
    let Ok(mut execution) = magasin.preparer(debut, &[]) else {
        return afficherln!("[noyau] {} : programme refuse, _start doit etre de type [] -> []", nom);
    };
    let (mut tranches, mut consomme) = (0u64, 0u64);
    let fin = loop {
        let mut carburant = TRANCHE;
        let etat = execution.reprendre(&mut magasin, &mut hote, &mut carburant);
        tranches += 1;
        consomme += TRANCHE - carburant;
        match etat {
            Ok(Etat::Interrompue) => continue,
            autre => break autre,
        }
    };
    let code = match fin {
        // proc_exit(code), ou _start qui revient sans l'appeler : code 0.
        Err(Piege::Hote(code)) => code,
        Ok(_) => 0,
        Err(p) => return afficherln!("[noyau] {} : programme arrete par un piege : {}", nom, p),
    };
    afficherln!("[noyau] {} : termine, code de sortie {}, {} unites de carburant en {} tranches.",
                nom, code, consomme, tranches);
}
