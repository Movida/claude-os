//! Le banc d'essai : la suite de tests officielle de WebAssembly 2.0.
//!
//! Chaque fichier .wast de la spécification (test/core/) est une suite de
//! commandes : « ce module doit se charger », « celui-ci est mal formé »,
//! « tel appel doit rendre telle valeur »... `make suite` les convertit
//! avec wast2json en modules binaires (.wasm) et en un fichier .json qui
//! liste les commandes ; ce test les rejoue toutes contre notre
//! bibliothèque.
//!
//! Lancer : `make tests-hote` dans 05-elf (ou `cargo test -- --nocapture` dans
//! 05-elf/wasm une fois la suite convertie). Le tableau affiché donne, par
//! fichier, les commandes réussies, échouées et ignorées. Restent ignorés
//! les modules au format texte (wast2json n'en fait pas des .wasm : ils
//! testent l'analyseur de texte, que nous n'avons pas) et ceux qui
//! utilisent SIMD.

mod json;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use json::Valeur;
use wasm::erreur::Genre;
use wasm::module::{Limites, TypeFonction, TypeGlobale, TypeTable, TypeValeur};
use wasm::validateur::ModuleValide;
use wasm::{ErreurInstanciation, Etat, Externe, Hote, Magasin, Piege, Valeur as ValeurWasm};

/// Le résultat d'une commande.
enum Verdict {
    Reussi,
    Echoue(String),
    /// Pas testable ici : le module est au format texte (nous ne lisons que
    /// le binaire), ou utilise SIMD.
    Ignore,
}

fn dossier_suite() -> PathBuf {
    match std::env::var_os("SUITE_WASM") {
        Some(d) => PathBuf::from(d),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../suite"),
    }
}

/// L'hôte du banc : les fonctions du module « spectest » (print_i32...),
/// qui n'affichent rien.
struct Spectest;

impl Hote for Spectest {
    fn appeler(
        &mut self,
        _: u32,
        _: &[ValeurWasm],
        _: &mut [ValeurWasm],
        _: Option<&mut [u8]>,
        _: &mut u64,
    ) -> Result<(), Piege> {
        Ok(())
    }
}

/// Le module « spectest » que la suite importe, celui de l'interpréteur de
/// référence : des fonctions print, quatre globales valant 666 (ou 666,6),
/// une table de 10 à 20 éléments, une mémoire de 1 à 2 pages.
fn spectest(m: &mut Magasin) -> BTreeMap<&'static str, Externe> {
    use TypeValeur::*;
    let mut s = BTreeMap::new();
    let fonctions: [(&str, &[TypeValeur]); 7] = [
        ("print", &[]),
        ("print_i32", &[I32]),
        ("print_i64", &[I64]),
        ("print_f32", &[F32]),
        ("print_f64", &[F64]),
        ("print_i32_f32", &[I32, F32]),
        ("print_f64_f64", &[F64, F64]),
    ];
    for (nom, parametres) in fonctions {
        let t = TypeFonction { parametres: parametres.into(), resultats: Box::new([]) };
        s.insert(nom, m.ajouter_fonction_hote(t, 0));
    }
    let globales = [
        ("global_i32", ValeurWasm::I32(666)),
        ("global_i64", ValeurWasm::I64(666)),
        ("global_f32", ValeurWasm::F32(666.6f32.to_bits())),
        ("global_f64", ValeurWasm::F64(666.6f64.to_bits())),
    ];
    for (nom, v) in globales {
        let t = TypeGlobale { valeur: v.type_valeur(), modifiable: false };
        s.insert(nom, m.ajouter_globale(t, v).unwrap());
    }
    let table = TypeTable { element: FuncRef, limites: Limites { min: 10, max: Some(20) } };
    s.insert("table", m.ajouter_table(table).unwrap());
    s.insert("memory", m.ajouter_memoire(Limites { min: 1, max: Some(2) }).unwrap());
    s
}

/// Une valeur de la suite : {"type": "i32", "value": "42"}. Les entiers
/// sont écrits sans signe, les flottants par leurs bits, les références
/// par leur numéro ou « null ».
fn valeur(v: &Valeur) -> Option<ValeurWasm> {
    let texte = v.champ("value").texte()?;
    let reference = || if texte == "null" { Some(None) } else { texte.parse().ok().map(Some) };
    Some(match v.champ("type").texte()? {
        "i32" => ValeurWasm::I32(texte.parse().ok()?),
        "i64" => ValeurWasm::I64(texte.parse().ok()?),
        "f32" => ValeurWasm::F32(texte.parse().ok()?),
        "f64" => ValeurWasm::F64(texte.parse().ok()?),
        "externref" => ValeurWasm::ExternRef(reference()?),
        "funcref" => ValeurWasm::FuncRef(reference()?),
        _ => return None,
    })
}

/// Le résultat obtenu est-il celui qu'attend la suite ? Pour un NaN, elle
/// n'attend pas des bits précis mais une forme : « canonique » (seul le
/// bit silencieux de la mantisse à 1, signe quelconque) ou « arithmétique »
/// (le bit silencieux à 1, le reste quelconque).
fn conforme(attendu: &Valeur, obtenu: ValeurWasm) -> bool {
    match (attendu.champ("value").texte(), obtenu) {
        (Some("nan:canonical"), ValeurWasm::F32(b)) => b & 0x7FFF_FFFF == 0x7FC0_0000,
        (Some("nan:arithmetic"), ValeurWasm::F32(b)) => b & 0x7FC0_0000 == 0x7FC0_0000,
        (Some("nan:canonical"), ValeurWasm::F64(b)) => b & 0x7FFF_FFFF_FFFF_FFFF == 0x7FF8_0000_0000_0000,
        (Some("nan:arithmetic"), ValeurWasm::F64(b)) => b & 0x7FF8_0000_0000_0000 == 0x7FF8_0000_0000_0000,
        _ => valeur(attendu) == Some(obtenu),
    }
}

/// Le piège obtenu est-il celui qu'attend la suite ?
fn piege_attendu(texte: &str, p: Piege) -> bool {
    use Piege::*;
    p == match texte.trim_end_matches(|c: char| c.is_ascii_digit()).trim_end() {
        "unreachable" => Inatteignable,
        "out of bounds memory access" => AccesMemoireHorsLimites,
        "out of bounds table access" => AccesTableHorsLimites,
        "undefined element" => ElementIndefini,
        "uninitialized element" => ElementNonInitialise,
        "indirect call type mismatch" => TypeDAppelIndirect,
        "integer divide by zero" => DivisionParZero,
        "integer overflow" => DebordementEntier,
        "invalid conversion to integer" => ConversionInvalide,
        "call stack exhausted" => PileEpuisee,
        // Un message que la table ne connaît pas encore : à y ajouter.
        _ => return false,
    }
}

/// Le carburant d'une action (ou d'une fonction de démarrage) : 2^26
/// unités, plus de cinquante fois l'action la plus longue de la suite
/// (environ 1,2 million, affiché à la fin). Une boucle sans fin, un défaut
/// de l'interpréteur par exemple, échoue alors en une fraction de seconde
/// au lieu de bloquer le banc.
const CARBURANT: u64 = 1 << 26;

/// L'état du banc pendant un fichier de la suite. Chaque fichier repart
/// d'un magasin neuf, comme avec l'interpréteur de référence.
struct Banc {
    dossier: PathBuf,
    magasin: Magasin,
    spectest: BTreeMap<&'static str, Externe>,
    /// Les modules nommés dans le .wast ($M), le dernier chargé (celui des
    /// actions qui ne nomment pas de module), et ceux enregistrés sous un
    /// nom de module (register), que les suivants peuvent importer.
    noms: BTreeMap<String, u32>,
    dernier: Option<u32>,
    enregistres: BTreeMap<String, u32>,
    /// Le plus de carburant qu'une action ait consommé.
    consommation_max: u64,
}

impl Banc {
    fn new(dossier: &Path) -> Banc {
        let mut magasin = Magasin::new();
        let spectest = spectest(&mut magasin);
        Banc {
            dossier: dossier.to_path_buf(),
            magasin,
            spectest,
            noms: BTreeMap::new(),
            dernier: None,
            enregistres: BTreeMap::new(),
            consommation_max: 0,
        }
    }

    /// Décode et valide le module d'une commande. Un module SIMD est ignoré.
    fn charger(&self, commande: &Valeur) -> Result<Arc<ModuleValide>, Verdict> {
        let fichier = commande.champ("filename").texte().expect("commande sans module");
        let octets = fs::read(self.dossier.join(fichier)).expect("module de la suite illisible");
        let module = wasm::decoder(&octets).and_then(wasm::valider).map_err(|e| match e.genre {
            Genre::NonPrisEnCharge => Verdict::Ignore,
            _ => Verdict::Echoue(format!("refuse a tort : {e}")),
        })?;
        verifier_branchements(&module).map_err(Verdict::Echoue)?;
        Ok(Arc::new(module))
    }

    /// Ce que le banc, qui joue l'environnement, donne aux imports d'un
    /// module : spectest, ou ce qu'exporte un module enregistré.
    fn imports(&self, module: &ModuleValide) -> Result<Vec<Externe>, String> {
        module
            .module()
            .imports
            .iter()
            .map(|i| {
                let trouve = if i.module == "spectest" {
                    self.spectest.get(i.nom.as_str()).copied()
                } else {
                    self.enregistres.get(&i.module).and_then(|&n| self.magasin.exporte(n, &i.nom))
                };
                trouve.ok_or_else(|| format!("import inconnu : {} {}", i.module, i.nom))
            })
            .collect()
    }

    /// Instancie un module, puis exécute sa fonction de démarrage avec le
    /// carburant d'une action. Un piège au démarrage fait échouer
    /// l'instanciation, comme un piège pendant l'initialisation.
    fn instancier(&mut self, module: Arc<ModuleValide>, imports: &[Externe]) -> Result<u32, String> {
        let instanciation = self.magasin.instancier(module, imports).map_err(|e| e.to_string())?;
        if let Some(mut demarrage) = instanciation.demarrage {
            let mut carburant = CARBURANT;
            match demarrage.reprendre(&mut self.magasin, &mut Spectest, &mut carburant) {
                Ok(Etat::Terminee(_)) => {}
                Ok(Etat::Interrompue) => return Err(format!("demarrage : carburant epuise ({CARBURANT} unites)")),
                Err(p) => return Err(format!("piege au demarrage : {p}")),
            }
        }
        Ok(instanciation.instance)
    }

    /// Une action : appeler une fonction exportée, ou lire une globale
    /// exportée. L'erreur extérieure est celle du banc (module ou export
    /// absent), l'intérieure un piège.
    fn action(&mut self, action: &Valeur) -> Result<Result<Vec<ValeurWasm>, Piege>, Verdict> {
        let instance = match action.champ("module").texte() {
            Some(nom) => self.noms.get(nom).copied(),
            None => self.dernier,
        };
        // Pas de module : il était ignoré (SIMD), ou son échec est déjà
        // compté.
        let instance = instance.ok_or(Verdict::Ignore)?;
        let champ = action.champ("field").texte().unwrap_or("");
        match (action.champ("type").texte(), self.magasin.exporte(instance, champ)) {
            (Some("invoke"), Some(Externe::Fonction(f))) => {
                let arguments: Option<Vec<ValeurWasm>> = action.champ("args").tableau().iter().map(valeur).collect();
                let arguments = arguments.ok_or(Verdict::Echoue("argument illisible".into()))?;
                let mut execution = match self.magasin.preparer(f, &arguments) {
                    Ok(e) => e,
                    Err(p) => return Ok(Err(p)),
                };
                let mut carburant = CARBURANT;
                let etat = execution.reprendre(&mut self.magasin, &mut Spectest, &mut carburant);
                self.consommation_max = self.consommation_max.max(CARBURANT - carburant);
                match etat {
                    Ok(Etat::Terminee(resultats)) => Ok(Ok(resultats)),
                    Ok(Etat::Interrompue) => Err(Verdict::Echoue(format!("carburant epuise ({CARBURANT} unites)"))),
                    Err(p) => Ok(Err(p)),
                }
            }
            (Some("get"), Some(Externe::Globale(g))) => Ok(Ok(vec![self.magasin.valeur_globale(g).unwrap()])),
            _ => Err(Verdict::Echoue(format!("export introuvable : {champ}"))),
        }
    }

    /// Rejoue une commande.
    fn rejouer(&mut self, commande: &Valeur) -> Verdict {
        let genre = commande.champ("type").texte().unwrap_or("");
        let binaire = commande.champ("module_type").texte() != Some("text");
        let attendu = commande.champ("text").texte().unwrap_or("?");
        let lire = || fs::read(self.dossier.join(commande.champ("filename").texte().unwrap())).expect("module illisible");
        macro_rules! essayer {
            ($e:expr) => {
                match $e {
                    Ok(v) => v,
                    Err(verdict) => return verdict,
                }
            };
        }
        match genre {
            "module" if binaire => {
                self.dernier = None;
                let module = essayer!(self.charger(commande));
                let imports = essayer!(self.imports(&module).map_err(Verdict::Echoue));
                match self.instancier(module, &imports) {
                    Ok(n) => {
                        self.dernier = Some(n);
                        if let Some(nom) = commande.champ("name").texte() {
                            self.noms.insert(nom.into(), n);
                        }
                        Verdict::Reussi
                    }
                    Err(e) => Verdict::Echoue(format!("instanciation : {e}")),
                }
            }
            "register" => {
                let instance = match commande.champ("name").texte() {
                    Some(nom) => self.noms.get(nom).copied(),
                    None => self.dernier,
                };
                let Some(instance) = instance else { return Verdict::Ignore };
                self.enregistres.insert(commande.champ("as").texte().unwrap().into(), instance);
                Verdict::Reussi
            }
            "action" => match essayer!(self.action(commande.champ("action"))) {
                Ok(_) => Verdict::Reussi,
                Err(p) => Verdict::Echoue(format!("piege inattendu : {p}")),
            },
            "assert_return" => match essayer!(self.action(commande.champ("action"))) {
                Err(p) => Verdict::Echoue(format!("piege inattendu : {p}")),
                Ok(resultats) => {
                    let attendus = commande.champ("expected").tableau();
                    if attendus.len() == resultats.len() && attendus.iter().zip(&resultats).all(|(a, &r)| conforme(a, r)) {
                        Verdict::Reussi
                    } else {
                        let attendus: Vec<String> = attendus
                            .iter()
                            .map(|a| format!("{}:{}", a.champ("type").texte().unwrap_or("?"), a.champ("value").texte().unwrap_or("?")))
                            .collect();
                        Verdict::Echoue(format!("{resultats:?} rendu, {attendus:?} attendu"))
                    }
                }
            },
            "assert_trap" | "assert_exhaustion" => match essayer!(self.action(commande.champ("action"))) {
                Ok(resultats) => Verdict::Echoue(format!("{resultats:?} rendu, piege attendu : {attendu}")),
                Err(p) if piege_attendu(attendu, p) => Verdict::Reussi,
                Err(p) => Verdict::Echoue(format!("piege « {p} », attendu : {attendu}")),
            },
            // Des modules valides, que l'instanciation doit refuser : un
            // import inconnu (le banc ne trouve rien à lui donner) ou d'un
            // type incompatible ; ou un piège pendant l'initialisation.
            "assert_unlinkable" if binaire => {
                let module = essayer!(self.charger(commande));
                match (self.imports(&module), attendu) {
                    (Err(_), "unknown import") => Verdict::Reussi,
                    (Err(e), _) => Verdict::Echoue(e),
                    (Ok(imports), _) => match self.magasin.instancier(module, &imports).map(|i| i.instance) {
                        Err(ErreurInstanciation::ImportIncompatible(_)) if attendu == "incompatible import type" => {
                            Verdict::Reussi
                        }
                        Err(e) => Verdict::Echoue(format!("refuse pour une autre raison : {e} (attendu : {attendu})")),
                        Ok(_) => Verdict::Echoue(format!("instancie a tort (attendu : {attendu})")),
                    },
                }
            }
            "assert_uninstantiable" if binaire => {
                let module = essayer!(self.charger(commande));
                let imports = essayer!(self.imports(&module).map_err(Verdict::Echoue));
                // Le piège peut venir de l'initialisation des segments ou de
                // la fonction de démarrage.
                let instanciation = match self.magasin.instancier(module, &imports) {
                    Ok(i) => i,
                    Err(ErreurInstanciation::Piege(p)) if piege_attendu(attendu, p) => return Verdict::Reussi,
                    Err(e) => return Verdict::Echoue(format!("refuse pour une autre raison : {e} (attendu : {attendu})")),
                };
                let Some(mut demarrage) = instanciation.demarrage else {
                    return Verdict::Echoue(format!("instancie a tort (attendu : {attendu})"));
                };
                let mut carburant = CARBURANT;
                match demarrage.reprendre(&mut self.magasin, &mut Spectest, &mut carburant) {
                    Err(p) if piege_attendu(attendu, p) => Verdict::Reussi,
                    Err(p) => Verdict::Echoue(format!("piege « {p} », attendu : {attendu}")),
                    Ok(etat) => Verdict::Echoue(format!("demarrage {etat:?} (attendu : {attendu})")),
                }
            }
            // Bien formés, mais invalides : le décodeur doit les accepter, et
            // le validateur les refuser.
            "assert_invalid" if binaire => match wasm::decoder(&lire()) {
                Ok(module) => match wasm::valider(module) {
                    Ok(_) => Verdict::Echoue(format!("accepte a tort (attendu : {attendu})")),
                    Err(e) if raison_attendue(attendu, e.genre) => Verdict::Reussi,
                    Err(e) => Verdict::Echoue(format!("refuse pour une autre raison : {e} (attendu : {attendu})")),
                },
                Err(e) if e.genre == Genre::NonPrisEnCharge => Verdict::Ignore,
                // Un artefact de la conversion : dans le .wast, un module
                // texte sans segment de données qui fait data.drop 0 ou
                // memory.init 1 est invalide (segment ou mémoire inconnus).
                // wast2json l'écrit en binaire sans section 12, ce qui le
                // rend mal formé (voir decodeur.rs). Il est refusé dans les
                // deux cas.
                Err(e) if e.genre == Genre::SectionDeNombreDeDonneesRequise => Verdict::Reussi,
                Err(e) => Verdict::Echoue(format!("mal forme au lieu d'invalide : {e}")),
            },
            "assert_malformed" if binaire => match wasm::decoder(&lire()) {
                Ok(_) => Verdict::Echoue(format!("accepte a tort (attendu : {attendu})")),
                Err(_) => Verdict::Reussi,
            },
            _ => Verdict::Ignore,
        }
    }
}

/// Le validateur refuse-t-il pour la raison qu'attend la suite ? Refuser un
/// module invalide pour une autre raison pourrait cacher un défaut : la
/// vraie erreur passerait inaperçue. On fait correspondre à chaque message
/// de la suite (sans l'index qui le termine parfois : « unknown global 1 »)
/// les genres d'erreur qui l'expriment.
fn raison_attendue(texte: &str, genre: wasm::erreur::Genre) -> bool {
    use wasm::erreur::{Espace, Genre::*};
    let index_inconnu = |espace| matches!(genre, IndexInconnu(e, _) if e == espace);
    match texte.trim_end_matches(|c: char| c.is_ascii_digit()).trim_end() {
        "type mismatch" => matches!(
            genre,
            TypeInattendu { .. } | PileVide | ValeursEnTrop | ReferenceRequise(_) | NombreRequis(_) | CiblesIncompatibles
        ),
        "unknown type" => index_inconnu(Espace::Type),
        "unknown function" => index_inconnu(Espace::Fonction),
        "unknown table" => index_inconnu(Espace::Table),
        "unknown memory" => index_inconnu(Espace::Memoire),
        "unknown global" => index_inconnu(Espace::Globale),
        "unknown local" => index_inconnu(Espace::Locale),
        "unknown label" => index_inconnu(Espace::Etiquette),
        "unknown elem segment" => index_inconnu(Espace::Elements),
        "unknown data segment" => index_inconnu(Espace::Donnees),
        // Un artefact de plus : wast2json écrit `select (result)`, sans
        // type, comme le `select` sans type, qui trouve alors la pile vide.
        "invalid result arity" => matches!(genre, TypesDuSelect(_) | PileVide),
        "alignment must not be larger than natural" => genre == AlignementTropGrand,
        "constant expression required" => genre == ExpressionNonConstante,
        "global is immutable" => matches!(genre, GlobaleNonModifiable(_)),
        "undeclared function reference" => matches!(genre, ReferenceNonDeclaree(_)),
        "duplicate export name" => matches!(genre, ExportEnDouble(_)),
        "multiple memories" => genre == PlusieursMemoires,
        "memory size must be at most 65536 pages (4GiB)" => genre == MemoireTropGrande,
        "size minimum must not be greater than maximum" => genre == LimitesInversees,
        "start function" => genre == FonctionDeDemarrage,
        // Un message que la table ne connaît pas encore : à y ajouter.
        _ => false,
    }
}

/// Vérifie la table annexe des branchements d'un module validé, sans
/// refaire le travail du validateur : on relit le code, on compte les
/// branchements (un par br, br_if, if, else ; un par cible de br_table), et
/// chaque entrée doit mener au début d'une instruction, avec pour `suite`
/// le nombre de branchements situés avant elle. C'est l'invariant sur
/// lequel l'interpréteur comptera (voir validateur.rs). Que chaque saut
/// mène au BON endroit, l'exécution le vérifiera à la sous-étape 3.
fn verifier_branchements(valide: &wasm::ModuleValide) -> Result<(), String> {
    use wasm::instructions::{Instruction, lire_instruction};
    let module = valide.module();
    for (i, corps) in module.corps.iter().enumerate() {
        let table = &valide.code(i).branchements;
        // Pour chaque début d'instruction : le nombre de branchements avant.
        let mut avant = BTreeMap::new();
        let octets = &module.octets[..corps.code.fin as usize];
        let mut l = wasm::lecteur::Lecteur::a_partir(octets, corps.code.debut as usize);
        let mut nombre = 0;
        while !l.fini() {
            avant.insert(l.position() as u32, nombre);
            nombre += match lire_instruction(&mut l).unwrap() {
                Instruction::Br(_) | Instruction::BrIf(_) | Instruction::If(_) | Instruction::Else => 1,
                Instruction::BrTable { nombre, .. } => nombre + 1,
                _ => 0,
            };
        }
        if nombre as usize != table.len() {
            return Err(format!("fonction {i} : {nombre} branchements, {} entrees", table.len()));
        }
        for (k, b) in table.iter().enumerate() {
            if avant.get(&b.cible) != Some(&b.suite) {
                return Err(format!("fonction {i}, entree {k} : cible {:#x} et suite {} incoherentes", b.cible, b.suite));
            }
        }
    }
    Ok(())
}

#[test]
fn suite_officielle() {
    let dossier = dossier_suite();
    let mut fichiers: Vec<PathBuf> = match fs::read_dir(&dossier) {
        Ok(entrees) => entrees
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect(),
        Err(_) => panic!("suite absente ({}) : lancer `make suite` dans 05-elf", dossier.display()),
    };
    fichiers.sort();
    assert!(!fichiers.is_empty(), "suite vide : lancer `make suite` dans 05-elf");

    let (mut total_reussis, mut total_echecs, mut total_ignores) = (0, 0, 0);
    let mut consommation_max = 0;
    let mut details = Vec::new();
    println!("{:<28} {:>8} {:>8} {:>8}", "fichier", "reussis", "echoues", "ignores");
    for chemin in &fichiers {
        let texte = fs::read_to_string(chemin).unwrap();
        let racine = json::analyser(&texte).unwrap_or_else(|e| panic!("{} : {e}", chemin.display()));
        let (mut reussis, mut echecs, mut ignores) = (0, 0, 0);
        let mut banc = Banc::new(&dossier);
        for commande in racine.champ("commands").tableau() {
            match banc.rejouer(commande) {
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
        consommation_max = consommation_max.max(banc.consommation_max);
        let nom = chemin.file_stem().unwrap().to_string_lossy();
        println!("{nom:<28} {reussis:>8} {echecs:>8} {ignores:>8}");
        total_reussis += reussis;
        total_echecs += echecs;
        total_ignores += ignores;
    }
    println!("{:<28} {total_reussis:>8} {total_echecs:>8} {total_ignores:>8}", "TOTAL");
    println!("action la plus longue : {consommation_max} unites de carburant");
    for d in details.iter().take(50) {
        println!("  {d}");
    }
    if details.len() > 50 {
        println!("  ... et {} autres", details.len() - 50);
    }
    assert_eq!(total_echecs, 0, "{total_echecs} commandes echouent");
}
