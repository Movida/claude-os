//! Le banc d'essai : la suite de tests officielle de WebAssembly 2.0.
//!
//! Chaque fichier .wast de la spécification (test/core/) est une suite de
//! commandes : « ce module doit se charger », « celui-ci est mal formé »,
//! « tel appel doit rendre telle valeur »... `make suite` les convertit
//! avec wast2json en modules binaires (.wasm) et en un fichier .json qui
//! liste les commandes ; ce test les rejoue toutes contre notre
//! bibliothèque.
//!
//! Lancer : `make tests-hote` dans 04-wasm (ou `cargo test -- --nocapture` dans
//! 04-wasm/wasm une fois la suite convertie). Le tableau affiché donne, par
//! fichier, les commandes réussies, échouées et pas encore prises en charge :
//! à chaque sous-étape, des commandes « ignorées » deviennent « réussies ».

mod json;

use std::fs;
use std::path::{Path, PathBuf};

use json::Valeur;

/// Le résultat d'une commande.
enum Verdict {
    Reussi,
    Echoue(String),
    /// Pas encore testable : la fonctionnalité viendra à une sous-étape
    /// suivante (validation, exécution), ou le module est au format texte.
    Ignore,
}

fn dossier_suite() -> PathBuf {
    match std::env::var_os("SUITE_WASM") {
        Some(d) => PathBuf::from(d),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../suite"),
    }
}

/// Rejoue une commande. `dossier` : où sont les .wasm du fichier.
fn rejouer(commande: &Valeur, dossier: &Path) -> Verdict {
    let genre = commande.champ("type").texte().unwrap_or("");
    let fichier = commande.champ("filename").texte();
    let binaire = commande.champ("module_type").texte() != Some("text");
    let lire = || fs::read(dossier.join(fichier.unwrap())).expect("module de la suite illisible");
    match genre {
        // Ces modules sont bien formés : ils doivent se décoder. Les
        // « invalides » le sont au sens du validateur (sous-étape 2), les
        // « non liables » et « non instanciables » à l'instanciation (3).
        "module" | "assert_invalid" | "assert_unlinkable" | "assert_uninstantiable"
            if fichier.is_some() && binaire =>
        {
            match wasm::decoder(&lire()) {
                Ok(_) => Verdict::Reussi,
                Err(e) if e.genre == wasm::erreur::Genre::NonPrisEnCharge => Verdict::Ignore,
                // Un artefact de la conversion : dans le .wast, un module
                // texte sans segment de données qui fait data.drop 0 ou
                // memory.init 1 est invalide (segment ou mémoire inconnus).
                // wast2json l'écrit en binaire sans section 12, ce qui le
                // rend mal formé (voir decodeur.rs). Il est refusé dans les
                // deux cas.
                Err(e) if genre == "assert_invalid"
                    && e.genre == wasm::erreur::Genre::SectionDeNombreDeDonneesRequise =>
                {
                    Verdict::Reussi
                }
                Err(e) => Verdict::Echoue(format!("refuse a tort : {e}")),
            }
        }
        "assert_malformed" if binaire => match wasm::decoder(&lire()) {
            Ok(_) => Verdict::Echoue(format!(
                "accepte a tort (attendu : {})",
                commande.champ("text").texte().unwrap_or("?")
            )),
            Err(_) => Verdict::Reussi,
        },
        _ => Verdict::Ignore,
    }
}

#[test]
fn suite_officielle() {
    let dossier = dossier_suite();
    let mut fichiers: Vec<PathBuf> = match fs::read_dir(&dossier) {
        Ok(entrees) => entrees
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect(),
        Err(_) => panic!("suite absente ({}) : lancer `make suite` dans 04-wasm", dossier.display()),
    };
    fichiers.sort();
    assert!(!fichiers.is_empty(), "suite vide : lancer `make suite` dans 04-wasm");

    let (mut total_reussis, mut total_echecs, mut total_ignores) = (0, 0, 0);
    let mut details = Vec::new();
    println!("{:<28} {:>8} {:>8} {:>8}", "fichier", "reussis", "echoues", "ignores");
    for chemin in &fichiers {
        let texte = fs::read_to_string(chemin).unwrap();
        let racine = json::analyser(&texte).unwrap_or_else(|e| panic!("{} : {e}", chemin.display()));
        let (mut reussis, mut echecs, mut ignores) = (0, 0, 0);
        for commande in racine.champ("commands").tableau() {
            match rejouer(commande, &dossier) {
                Verdict::Reussi => reussis += 1,
                Verdict::Ignore => ignores += 1,
                Verdict::Echoue(raison) => {
                    echecs += 1;
                    let ligne = commande.champ("line").nombre().unwrap_or(0.0);
                    let nom = chemin.file_stem().unwrap().to_string_lossy();
                    details.push(format!("{nom}.wast:{ligne} : {raison}"));
                }
            }
        }
        let nom = chemin.file_stem().unwrap().to_string_lossy();
        println!("{nom:<28} {reussis:>8} {echecs:>8} {ignores:>8}");
        total_reussis += reussis;
        total_echecs += echecs;
        total_ignores += ignores;
    }
    println!("{:<28} {total_reussis:>8} {total_echecs:>8} {total_ignores:>8}", "TOTAL");
    for d in details.iter().take(50) {
        println!("  {d}");
    }
    if details.len() > 50 {
        println!("  ... et {} autres", details.len() - 50);
    }
    assert_eq!(total_echecs, 0, "{total_echecs} commandes echouent");
}
