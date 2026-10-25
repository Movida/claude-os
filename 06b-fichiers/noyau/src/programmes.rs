//! Les programmes de l'archive de démarrage : les déballer, reconnaître
//! leur format, les exécuter.
//!
//! Le chargeur a déposé à côté du noyau une archive cpio (voir
//! ../formats/src/cpio.rs) ; le noyau la déballe dans son système de
//! fichiers (vfs.rs), puis exécute chacun des fichiers de /bin, dans
//! l'ordre de l'archive. Le premier programme lancé par son chemin, qui
//! lance les autres (le /init de Linux), c'est pour 6c. Le format d'un
//! programme se reconnaît à ses
//! premiers octets, sa « signature » (magic number) :
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

/// L'environnement des programmes Linux : de quoi savoir où est le
/// dossier personnel (/home/utilisateur, à l'utilisateur 1000, voir
/// archive.txt), et quel terminal les affiche (la console : un terminal
/// « linux », comme la console de Linux).
const ENVIRONNEMENT: &[&[u8]] = &[b"HOME=/home/utilisateur", b"TERM=linux"];

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
/// (vfs.rs), rend sa mémoire, puis exécute les programmes de /bin, dans
/// l'ordre de l'archive. Une archive mal formée est refusée en entier,
/// avant de rien déballer : on ne lance pas la moitié d'un système.
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
    afficherln!("[noyau] Programmes de /bin :");
    for (n, chemin) in &bilan.programmes {
        let taille = vfs::avec(|fs, _| fs.attributs(*n).taille);
        afficherln!("        {:<24} {:>8} octets", Nom(&chemin[5..]), taille);
    }
    for (n, chemin) in &bilan.programmes {
        executer(*n, chemin);
        vfs::avec(|fs, cadres| fs.lacher(*n, cadres));
    }
}

/// Exécute le programme du fichier `n`, de chemin `chemin`, d'après sa
/// signature.
fn executer(n: Numero, chemin: &[u8]) {
    let nom = NomCourt::de(chemin.rsplit(|&o| o == b'/').next().unwrap_or(chemin));
    let mut signature = [0u8; 4];
    let lus = vfs::lire(n, 0, &mut signature);
    match &signature[..lus] {
        [0, b'a', b's', b'm'] => executer_wasm(nom, n),
        [0x7f, b'E', b'L', b'F'] => executer_elf(nom, n, chemin),
        _ => afficherln!("[noyau] {} : format inconnu, ignore.", nom),
    }
}

/// Un programme Linux : on vérifie le fichier, on le charge dans un espace
/// d'adressage neuf, puis on l'exécute, dans l'anneau 3, jusqu'à ce qu'il se
/// termine. Son espace est alors détruit, et doit rendre toute sa mémoire.
fn executer_elf(nom: NomCourt, n: Numero, chemin: &[u8]) {
    // Le fichier, lu par morceaux : la bibliothèque des formats ne voit que
    // des copies (chargeur_elf::verifier).
    let lire = |position: u64, tampon: &mut [u8]| vfs::lire(n, position, tampon) == tampon.len();
    let taille = vfs::avec(|fs, _| fs.attributs(n).taille);
    let (entete, table) = match chargeur_elf::verifier(taille, lire) {
        Ok(v) => v,
        Err(e) => return afficherln!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    let executable = match formats::elf::lire_entetes(&entete, &table, taille, chargeur_elf::PERMISES) {
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
    let identite = Identite { uid: pile::UTILISATEUR as u32, gid: pile::GROUPE as u32 };
    if vfs::avec(|fs, _| fs.peut_executer(identite, n)).is_err() {
        return afficherln!("[noyau] {} : pas le droit de l'executer (EACCES)", nom);
    }
    let libres = pages::libres();
    // Le fichier ouvert que projetteront ses segments : chaque zone le
    // tiendra ; l'ouverture du chargeur est lâchée ensuite.
    let fichier = match appels_fichiers::ouvrir_inode(n, chemin) {
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
    // Sa pile initiale : son chemin pour seul argument (argv[0] et
    // AT_EXECFN, comme Linux), un petit environnement.
    let rsp = match pile::construire(&mut programme, &[chemin], ENVIRONNEMENT, chemin) {
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
fn executer_wasm(nom: NomCourt, n: Numero) {
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
        let etat = execution.reprendre(&mut magasin, &mut wasi::Wasi, &mut carburant);
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
