//! Les programmes de l'archive de démarrage : les lister, reconnaître leur
//! format, les exécuter.
//!
//! Le chargeur a déposé à côté du noyau une archive cpio (voir
//! ../formats/src/cpio.rs) ; on exécute chacun de ses fichiers, dans
//! l'ordre de l'archive. Le format d'un programme se reconnaît à ses
//! premiers octets, sa « signature » (magic number) :
//!   - « \0asm » : un module WebAssembly, le format natif de l'OS ;
//!   - « \x7fELF » : un exécutable Linux (sous-étapes suivantes).
//! C'est le principe des « binfmt » de Linux (fs/binfmt_elf.c,
//! fs/binfmt_script.c pour « #! », binfmt_misc pour le reste) : chaque
//! format est essayé tour à tour, et le premier qui reconnaît le fichier
//! s'en charge. Le nom du fichier (son extension) ne compte pas.

use crate::demarrage;
use crate::espace;
use crate::wasi;
use core::fmt;

/// Le nom d'une entrée, pour l'afficher : un nom de fichier peut contenir
/// n'importe quel octet, que la console afficherait de travers. On montre
/// l'ASCII imprimable tel quel, et « ? » pour le reste.
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
fn executer(nom: Nom, octets: &[u8]) {
    match octets {
        [0, b'a', b's', b'm', ..] => executer_wasm(nom, octets),
        _ => afficherln!("[noyau] {} : format inconnu, ignore.", nom),
    }
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
