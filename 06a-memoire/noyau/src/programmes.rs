//! Les programmes de l'archive de démarrage : les lister, reconnaître leur
//! format, les exécuter.
//!
//! Le chargeur a déposé à côté du noyau une archive cpio (voir
//! ../formats/src/cpio.rs) ; on exécute chacun de ses fichiers, dans
//! l'ordre de l'archive. Le format d'un programme se reconnaît à ses
//! premiers octets, sa « signature » (magic number) :
//!   - « \0asm » : un module WebAssembly, le format natif de l'OS ;
//!   - « \x7fELF » : un exécutable Linux.
//! C'est le principe des « binfmt » de Linux (fs/binfmt_elf.c,
//! fs/binfmt_script.c pour « #! », binfmt_misc pour le reste) : chaque
//! format est essayé tour à tour, et le premier qui reconnaît le fichier
//! s'en charge. Le nom du fichier (son extension) ne compte pas.

use crate::{chargeur_elf, demarrage, espace, pages, pile, processus, tache, wasi};

/// L'environnement des programmes Linux : de quoi savoir où est le
/// dossier personnel, et quel terminal les affiche (la console : un
/// terminal « linux », comme la console de Linux).
const ENVIRONNEMENT: &[&[u8]] = &[b"HOME=/", b"TERM=linux"];
use core::fmt;

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
/// de mémoire physique, vue par la projection directe.
fn archive() -> Option<&'static [u8]> {
    let etendue = demarrage::archive()?;
    // SAFETY : l'étendue est celle que le chargeur a remplie avec l'archive ;
    // l'allocateur de démarrage l'a réservée (cadres.rs), elle n'a donc été
    // donnée à personne d'autre, et personne ne l'écrit. Elle est dans la
    // mémoire libre de la carte (le chargeur l'a vérifié), donc dans la
    // projection directe.
    Some(unsafe {
        core::slice::from_raw_parts(espace::virtuelle(etendue.debut) as *const u8, (etendue.fin - etendue.debut) as usize)
    })
}

/// Liste l'archive de démarrage, puis exécute chacun de ses fichiers. Une
/// archive mal formée est refusée en entier, avant d'exécuter quoi que ce
/// soit : on ne lance pas la moitié d'un système.
pub fn executer_archive() {
    let Some(octets) = archive() else {
        return afficherln!("[noyau] Pas d'archive de programmes.");
    };
    let adresse = demarrage::archive().map_or(0, |a| a.debut);
    afficherln!("[noyau] Archive de programmes : {} octets a {:#x}.", octets.len(), adresse);
    for entree in formats::cpio::lire(octets) {
        match entree {
            Ok(e) => afficherln!("        {:<24} {:>8} octets{}", Nom(e.nom), e.contenu.len(),
                                 if e.est_fichier() { "" } else { " (pas un fichier, ignore)" }),
            Err(e) => return afficherln!("[noyau] Archive refusee : {}", e),
        }
    }
    for entree in formats::cpio::lire(octets).flatten().filter(|e| e.est_fichier()) {
        executer(Nom(entree.nom), entree.contenu);
    }
}

/// Exécute un programme, d'après sa signature.
fn executer(nom: Nom<'static>, octets: &[u8]) {
    match octets {
        [0, b'a', b's', b'm', ..] => executer_wasm(nom, octets),
        [0x7f, b'E', b'L', b'F', ..] => executer_elf(nom, octets),
        _ => afficherln!("[noyau] {} : format inconnu, ignore.", nom),
    }
}

/// Un programme Linux : on vérifie le fichier, on le charge dans un espace
/// d'adressage neuf, puis on l'exécute, dans l'anneau 3, jusqu'à ce qu'il se
/// termine. Son espace est alors détruit, et doit rendre toute sa mémoire.
fn executer_elf(nom: Nom<'static>, octets: &[u8]) {
    let executable = match formats::elf::lire(octets, chargeur_elf::PERMISES) {
        Ok(x) => x,
        Err(e) => return afficherln!("[noyau] {} : programme Linux refuse : {}", nom, e),
    };
    afficherln!("[noyau] {} : programme Linux (ELF), {} octets, point d'entree {:#x}, segments :",
                nom, octets.len(), executable.entree());
    for s in executable.segments() {
        afficherln!("        {:#010x}-{:#010x} {}{}{} ({} octets du fichier)",
                    s.adresse, s.adresse + s.taille, 'r',
                    if s.ecriture { 'w' } else { '-' }, if s.execution { 'x' } else { '-' }, s.contenu.len());
    }
    let libres = pages::libres();
    let mut programme = match chargeur_elf::charger(&executable) {
        Ok(p) => p,
        Err(e) => return afficherln!("[noyau] {} : chargement impossible : {}", nom, e),
    };
    // Le code au point d'entrée, relu dans l'espace du programme, doit être
    // celui du fichier.
    // (16 octets au plus : ce qu'il reste du fichier après le point
    // d'entrée, dans son segment.)
    let attendu = executable
        .segments()
        .find_map(|s| s.contenu.get(programme.entree.checked_sub(s.adresse)? as usize..))
        .map_or(&[][..], |reste| &reste[..reste.len().min(16)]);
    let mut code = [0u8; 16];
    let code = &mut code[..attendu.len()];
    let code_ok = programme.memoire.espace.lire(programme.entree, code).is_ok() && code == attendu;
    // Le tas commence à la page qui suit le dernier segment.
    afficherln!("        en-tetes de programme a {:#x} ({} de {} octets), tas a partir de {:#x}, code en place : {}.",
                programme.adresse_entetes.unwrap_or(0), programme.nombre_entetes, programme.taille_entete,
                programme.fin.next_multiple_of(4096), if code_ok { "ok" } else { "ECHEC" });
    // Sa pile initiale : son nom pour seul argument, un petit
    // environnement.
    let rsp = match pile::construire(&mut programme, &[nom.0], ENVIRONNEMENT, nom.0) {
        Ok(rsp) => rsp,
        Err(e) => return afficherln!("[noyau] {} : pile initiale impossible : {}", nom, e),
    };
    // Le programme devient le processus en cours.
    let (pml4, entree) = (programme.memoire.espace.pml4(), programme.entree);
    processus::installer(processus::Processus { memoire: programme.memoire });
    let code = tache::executer(nom.0, pml4, entree, rsp);
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
fn executer_wasm(nom: Nom, octets: &[u8]) {
    use alloc::sync::Arc;
    use wasm::{Etat, Externe, Magasin, Piege};

    const TRANCHE: u64 = 1000;

    let module = match wasm::decoder(octets).and_then(wasm::valider) {
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
