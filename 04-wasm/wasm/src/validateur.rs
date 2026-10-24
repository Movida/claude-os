//! Le validateur : vérifie qu'un module bien formé a un sens, avant de
//! l'exécuter.
//!
//! C'est lui, plus que l'interpréteur, qui fait le bac à sable (voir
//! lib.rs). Il garantit, une fois pour toutes et avant la première
//! instruction exécutée, que :
//!   - chaque index désigne quelque chose qui existe : fonction, variable
//!     locale, globale, table, mémoire, étiquette de bloc... ;
//!   - chaque instruction trouve sur la pile les types qu'elle attend, et
//!     chaque bloc se termine avec les types qu'il annonce ;
//!   - aucune instruction ne dépile ce que son bloc n'a pas empilé.
//! L'interpréteur s'appuiera sur ces garanties pour ne plus rien vérifier
//! de tout cela pendant l'exécution : ses cases de pile ne porteront pas de
//! type, et il ne regardera jamais si la pile est vide. Une erreur ici
//! serait un trou dans le bac à sable ; on suit donc à la lettre
//! l'algorithme de l'annexe de la spécification (« Validation Algorithm »).
//!
//! L'algorithme exécute le code « en types » : une pile de TYPES remplace
//! la pile des valeurs. `i32.const 1` empile i32 ; `i32.add` dépile deux
//! i32 et empile un i32 ; `f32.neg` sur un i32 est une erreur. Une seconde
//! pile, celle des cadres, suit les blocs ouverts (block, loop, if) : pour
//! chacun, la hauteur de la pile des types à son ouverture (on ne dépile
//! jamais en dessous) et les types qu'il doit laisser en se terminant. Il
//! suffit d'une seule passe, sans jamais revenir en arrière : chaque
//! instruction est vue une fois. La validation prend donc un temps
//! proportionnel à la taille du code, à un facteur près : une instruction
//! manipule au plus 1000 types (un appel, la fin d'un bloc ; voir
//! limites.rs).
//!
//! Le code inaccessible. Après `br`, `return` ou `unreachable`, la fin du
//! bloc ne sera jamais exécutée. La spécification veut quand même qu'elle
//! soit typée, mais avec une pile « polymorphe » : dépiler sous la hauteur
//! du bloc y donne un type inconnu, compatible avec tout, au lieu d'une
//! erreur. Ainsi :
//!     unreachable  i32.add                  est valide (deux inconnus) ;
//!     unreachable  i64.const 0  i32.add     ne l'est pas (un i64 connu).
//! Dans la pile des types, `None` est ce type inconnu.
//!
//! La validation prépare aussi l'exécution. L'interpréteur (sous-étape 3)
//! lira directement les octets du code, sans les retraduire (voir
//! module.rs). Il lui manque alors une information que le code ne donne
//! pas : OÙ mène un branchement. `br 1` désigne « le deuxième bloc
//! englobant », et sortir d'un `block` mène à son `end`, plus loin, à une
//! position que rien n'indique. Le validateur la découvre en passant, et
//! remplit pour chaque fonction une table annexe (voir `Branchement`).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::erreur::{Erreur, Espace, Genre};
use crate::instructions::{Instruction, TypeBloc, lire_cibles, lire_instruction};
use crate::lecteur::Lecteur;
use crate::limites::*;
use crate::module::*;

/// Une entrée de la table annexe des branchements : ce que fait
/// l'interpréteur quand il prend un branchement.
///
/// Le choix : l'interprétation « sur place » (Ben Titzer, « A fast in-place
/// interpreter for WebAssembly », 2022, moteur Wizard). Le code reste tel
/// qu'il est dans le module ; le validateur, qui connaît déjà la structure
/// des blocs, calcule au passage une petite table, une entrée par
/// branchement. Options écartées :
///   - chercher le `end` correspondant à chaque branchement pris : il
///     faudrait relire tout le bloc, à chaque fois ;
///   - retraduire le code en un format interne aux sauts résolus (wasmi,
///     WAMR, wasm3) : l'exécution est un peu plus rapide, mais la
///     traduction coûte au chargement, le code existe alors en deux
///     exemplaires, et la position d'exécution ne correspond plus à rien
///     dans le fichier (débogage, messages d'erreur) ;
///   - compiler en code machine (wasmtime, ou Nebulet avec Cranelift) : de
///     loin le plus rapide, et la cible à long terme de notre OS, mais un
///     compilateur est un projet en soi.
///
/// Les entrées sont rangées dans l'ordre des instructions du code :
///   - `br` et `br_if` : une entrée ;
///   - `br_table` : une par cible, la cible par défaut en dernier ;
///   - `if` : une, prise si la condition est fausse (vers la branche
///     « sinon », ou vers la fin s'il n'y en a pas) ;
///   - `else` : une, prise en arrivant au bout de la branche « alors »
///     (vers la fin).
/// L'interpréteur tient, à côté de la position `ip` de l'instruction en
/// cours, l'index `stp` de l'entrée du prochain branchement. Un branchement
/// non pris (`br_if` faux, `if` vrai) fait `stp += 1`. Un branchement pris
/// lit son entrée (pour un `br_table`, l'entrée `stp + i`, où l'index i est
/// ramené à la cible par défaut s'il dépasse), saute à `cible` et fait
/// `stp = suite`. L'invariant : `stp` est toujours le nombre de
/// branchements situés avant `ip` dans la fonction.
///
/// En sautant, les valeurs passées à l'étiquette (les résultats d'un bloc,
/// les paramètres d'une boucle) restent au sommet de la pile, et ce que le
/// bloc avait empilé en dessous disparaît : on recopie les `gardees`
/// valeurs du sommet `retirees` cases plus bas. Ces deux nombres sont
/// fixes : dans du code valide, la pile a toujours la même hauteur à une
/// instruction donnée, quel que soit le chemin suivi pour y arriver. (Dans
/// du code inaccessible, la hauteur calculée n'a pas de sens, mais ces
/// entrées ne seront jamais lues.)
///
/// Wizard range des écarts relatifs ; des positions absolues sont plus
/// simples à lire, et tiennent aussi sur 32 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Branchement {
    /// La position, dans les octets du module, de l'instruction à exécuter
    /// ensuite : juste après le `end` d'un bloc, au début du corps d'une
    /// boucle, juste après le `else` d'un `if`. Un branchement vers le corps
    /// de la fonction mène à son `end` final, qui fait le retour.
    pub cible: u32,
    /// L'index de l'entrée du premier branchement situé après `cible`.
    pub suite: u32,
    /// Le nombre de valeurs passées à l'étiquette, gardées au sommet.
    pub gardees: u32,
    /// Le nombre de valeurs à retirer sous elles.
    pub retirees: u32,
}

/// Ce que la validation a appris du corps d'une fonction, et dont
/// l'interpréteur aura besoin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeValide {
    /// La table annexe des branchements de la fonction.
    pub branchements: Box<[Branchement]>,
    /// Nombre de variables locales déclarées, paramètres non compris.
    pub locales: u32,
    /// Hauteur maximale de la pile d'opérandes de la fonction (comme le
    /// max_stack de Java). À chaque appel, l'interpréteur vérifiera UNE
    /// fois qu'il lui reste assez de place, au lieu de le faire à chaque
    /// valeur empilée.
    pub hauteur_max: u32,
}

/// Un module validé.
///
/// `valider` est le seul moyen d'en obtenir un, et ses champs sont privés :
/// l'instanciation (sous-étape 3) prendra un `ModuleValide`. Il sera donc
/// IMPOSSIBLE, dès la compilation, d'exécuter un module qui n'a pas été
/// validé, ou de le modifier après sa validation. C'est le système de types
/// de Rust qui garde l'invariant à notre place (on parle d'« état typé »,
/// typestate).
///
/// Pour que la garantie tienne, `valider` ne suppose rien du `Module` qu'il
/// reçoit, dont les champs sont publics : il relit le code et les
/// expressions dans les octets, et revérifie ce que le décodeur garantit
/// déjà (autant de corps que de fonctions, des plages dans le module, des
/// tables de références). Un `Module` fabriqué à la main, ou un défaut du
/// décodeur, ne peut pas donner un `ModuleValide` incohérent.
#[derive(Debug)]
pub struct ModuleValide {
    module: Module,
    code: Box<[CodeValide]>,
}

impl ModuleValide {
    pub fn module(&self) -> &Module {
        &self.module
    }

    /// Ce que la validation a calculé pour la fonction `i` du module (sa
    /// i-ième fonction DÉFINIE : les fonctions importées n'ont pas de code).
    pub fn code(&self, i: usize) -> &CodeValide {
        &self.code[i]
    }
}

/// Valide un module décodé. Le module est pris par valeur : on le rend,
/// intact, à l'intérieur du `ModuleValide`.
pub fn valider(module: Module) -> Result<ModuleValide, Erreur> {
    if module.corps.len() != module.fonctions.len() {
        return Err(erreur(module.sections[10] as usize, Genre::FonctionsEtCodeIncoherents));
    }
    let code = {
        let contexte = Contexte::construire(&module)?;
        let mut code = Vec::with_capacity(module.corps.len());
        for (corps, &type_fonction) in module.corps.iter().zip(&module.fonctions) {
            let type_fonction = &module.types[type_fonction as usize];
            code.push(Validateur::valider(&contexte, type_fonction, corps)?);
        }
        code
    };
    Ok(ModuleValide { module, code: code.into() })
}

fn erreur(position: usize, genre: Genre) -> Erreur {
    Erreur { position, genre }
}

/// Les octets du module jusqu'à la fin de `plage`, pour la lire avec un
/// `Lecteur` qui ne pourra pas aller au-delà. Le décodeur ne produit que
/// des plages valides, mais `valider` ne le suppose pas (voir
/// `ModuleValide`) : une plage hors du module est une erreur, pas une
/// panique.
fn jusqua(module: &Module, plage: Plage) -> Result<&[u8], Erreur> {
    let (debut, fin) = (plage.debut as usize, plage.fin as usize);
    if debut > fin || fin > module.octets.len() {
        return Err(erreur(debut.min(module.octets.len()), Genre::FinInattendue));
    }
    Ok(&module.octets[..fin])
}

/// Une table ne contient que des références, et ses limites sont valides.
fn verifier_table(t: TypeTable, position: usize) -> Result<(), Erreur> {
    if !t.element.est_reference() {
        return Err(erreur(position, Genre::ReferenceRequise(t.element)));
    }
    verifier_limites(t.limites, false, position)
}

/// La taille maximale d'une mémoire, en pages de 64 Kio : 4 Gio, tout ce
/// qu'une adresse i32 peut atteindre.
const PAGES_MAX: u32 = 65536;

/// Le contexte de validation (C dans la spécification) : le type de tout ce
/// que le module importe ou déclare, dans l'ordre des index. Dans chaque
/// espace d'index, les imports viennent d'abord : si un module importe deux
/// fonctions et en définit trois, ses fonctions sont numérotées 0 à 4, et
/// la 2 est la première de son code.
struct Contexte<'m> {
    module: &'m Module,
    /// Pour chaque fonction, l'index de son type.
    fonctions: Vec<u32>,
    tables: Vec<TypeTable>,
    memoires: Vec<Limites>,
    globales: Vec<TypeGlobale>,
    /// Les premières globales sont les importées : les seules que les
    /// expressions constantes peuvent lire (voir `constante`).
    globales_importees: usize,
    /// Les fonctions dont le code a le droit de prendre une référence avec
    /// `ref.func` (C.refs) : celles qui sont mentionnées ailleurs que dans
    /// le code, dans un export, un segment d'éléments ou une globale.
    /// Ainsi, la liste des fonctions qui peuvent devenir des valeurs se lit
    /// dans les déclarations, sans parcourir le code : un compilateur peut
    /// préparer leur forme « appelable indirectement » d'avance.
    declarees: Vec<bool>,
}

impl<'m> Contexte<'m> {
    /// Valide les déclarations du module, tout sauf le code des fonctions,
    /// et construit le contexte. Dans l'ordre de la spécification : on
    /// connaît ainsi toutes les fonctions et tous les types avant les
    /// expressions qui les mentionnent.
    fn construire(module: &'m Module) -> Result<Self, Erreur> {
        let section = |id: usize| module.sections[id] as usize;
        let mut c = Contexte {
            module,
            fonctions: Vec::new(),
            tables: Vec::new(),
            memoires: Vec::new(),
            globales: Vec::new(),
            globales_importees: 0,
            declarees: Vec::new(),
        };

        // Tout type de fonction est valide en 2.0 ; seules nos limites
        // s'appliquent (voir limites.rs).
        for t in &module.types {
            if t.parametres.len() > PARAMETRES_MAX {
                return Err(erreur(section(1), Genre::LimiteDepassee(Limite::Parametres)));
            }
            if t.resultats.len() > RESULTATS_MAX {
                return Err(erreur(section(1), Genre::LimiteDepassee(Limite::Resultats)));
            }
        }

        for import in &module.imports {
            match import.description {
                DescriptionImport::Fonction(t) => {
                    c.type_fonction(t, section(2))?;
                    c.fonctions.push(t);
                }
                DescriptionImport::Table(t) => {
                    verifier_table(t, section(2))?;
                    c.tables.push(t);
                }
                DescriptionImport::Memoire(limites) => {
                    verifier_limites(limites, true, section(2))?;
                    c.memoires.push(limites);
                }
                DescriptionImport::Globale(g) => c.globales.push(g),
            }
        }
        c.globales_importees = c.globales.len();

        for &t in &module.fonctions {
            c.type_fonction(t, section(3))?;
            c.fonctions.push(t);
        }
        c.declarees = vec![false; c.fonctions.len()];
        for t in &module.tables {
            verifier_table(*t, section(4))?;
            c.tables.push(*t);
        }
        for &limites in &module.memoires {
            verifier_limites(limites, true, section(5))?;
            c.memoires.push(limites);
        }
        // Une seule mémoire en 2.0 : les instructions d'accès n'ont pas de
        // place pour un index de mémoire (proposition « multi-memory »).
        if c.memoires.len() > 1 {
            let position = if module.memoires.len() > 1 { section(5) } else { section(2) };
            return Err(erreur(position, Genre::PlusieursMemoires));
        }

        for g in &module.globales {
            c.constante(g.init, g.type_globale.valeur)?;
            c.globales.push(g.type_globale);
        }

        for segment in &module.elements {
            if !segment.type_element.est_reference() {
                return Err(erreur(section(9), Genre::ReferenceRequise(segment.type_element)));
            }
            for element in &segment.elements {
                match *element {
                    // Un index de fonction donne une funcref : le décodeur
                    // ne l'écrit que dans des segments de ce type.
                    Element::Fonction(_) if segment.type_element != TypeValeur::FuncRef => {
                        return Err(erreur(
                            section(9),
                            Genre::TypeInattendu { attendu: segment.type_element, trouve: TypeValeur::FuncRef },
                        ));
                    }
                    Element::Fonction(x) => c.declarer(x, section(9))?,
                    Element::Expression(plage) => c.constante(plage, segment.type_element)?,
                }
            }
            if let ModeSegment::Actif { index, decalage } = segment.mode {
                let table = c.table(index, decalage.debut as usize)?;
                if table.element != segment.type_element {
                    return Err(erreur(
                        decalage.debut as usize,
                        Genre::TypeInattendu { attendu: table.element, trouve: segment.type_element },
                    ));
                }
                c.constante(decalage, TypeValeur::I32)?;
            }
        }

        for segment in &module.donnees {
            // Les octets du segment seront copiés à l'instanciation.
            jusqua(module, segment.octets)?;
            if let ModeSegment::Actif { index, decalage } = segment.mode {
                c.memoire(index, decalage.debut as usize)?;
                c.constante(decalage, TypeValeur::I32)?;
            }
        }

        for export in &module.exports {
            match export.description {
                DescriptionExport::Fonction(x) => c.declarer(x, section(7))?,
                DescriptionExport::Table(x) => {
                    c.table(x, section(7))?;
                }
                DescriptionExport::Memoire(x) => c.memoire(x, section(7))?,
                DescriptionExport::Globale(x) => {
                    c.globale(x, section(7))?;
                }
            }
        }
        // Deux exports ne peuvent pas porter le même nom : l'environnement
        // les cherche par leur nom. On trie les noms (avec leur index) pour
        // que deux noms égaux se retrouvent côte à côte : n log n, au lieu
        // de comparer chaque nom à tous les autres.
        let mut noms: Vec<(&str, usize)> =
            module.exports.iter().enumerate().map(|(i, e)| (e.nom.as_str(), i)).collect();
        noms.sort_unstable();
        if let Some(paire) = noms.windows(2).find(|paire| paire[0].0 == paire[1].0) {
            return Err(erreur(section(7), Genre::ExportEnDouble(paire[1].1 as u32)));
        }

        // La fonction de démarrage est appelée par l'instanciation, qui n'a
        // rien à lui donner ni rien à faire de ses résultats.
        if let Some(x) = module.demarrage {
            let t = c.fonction(x, section(8))?;
            if !t.parametres.is_empty() || !t.resultats.is_empty() {
                return Err(erreur(section(8), Genre::FonctionDeDemarrage));
            }
        }
        Ok(c)
    }

    fn type_fonction(&self, x: u32, position: usize) -> Result<&'m TypeFonction, Erreur> {
        let module: &'m Module = self.module;
        module.types.get(x as usize).ok_or(erreur(position, Genre::IndexInconnu(Espace::Type, x)))
    }

    /// Le type de la fonction `x`.
    fn fonction(&self, x: u32, position: usize) -> Result<&'m TypeFonction, Erreur> {
        let t = *self.fonctions.get(x as usize).ok_or(erreur(position, Genre::IndexInconnu(Espace::Fonction, x)))?;
        self.type_fonction(t, position)
    }

    fn table(&self, x: u32, position: usize) -> Result<TypeTable, Erreur> {
        self.tables.get(x as usize).copied().ok_or(erreur(position, Genre::IndexInconnu(Espace::Table, x)))
    }

    fn memoire(&self, x: u32, position: usize) -> Result<(), Erreur> {
        if x as usize >= self.memoires.len() {
            return Err(erreur(position, Genre::IndexInconnu(Espace::Memoire, x)));
        }
        Ok(())
    }

    fn globale(&self, x: u32, position: usize) -> Result<TypeGlobale, Erreur> {
        self.globales.get(x as usize).copied().ok_or(erreur(position, Genre::IndexInconnu(Espace::Globale, x)))
    }

    /// Le type des références d'un segment d'éléments.
    fn elements(&self, x: u32, position: usize) -> Result<TypeValeur, Erreur> {
        let segment = self.module.elements.get(x as usize);
        segment.map(|s| s.type_element).ok_or(erreur(position, Genre::IndexInconnu(Espace::Elements, x)))
    }

    fn donnees(&self, x: u32, position: usize) -> Result<(), Erreur> {
        if x as usize >= self.module.donnees.len() {
            return Err(erreur(position, Genre::IndexInconnu(Espace::Donnees, x)));
        }
        Ok(())
    }

    /// Note que la fonction `x` est mentionnée hors du code (voir
    /// `declarees`).
    fn declarer(&mut self, x: u32, position: usize) -> Result<(), Erreur> {
        self.fonction(x, position)?;
        self.declarees[x as usize] = true;
        Ok(())
    }

    /// Valide une expression constante (valeur initiale d'une globale,
    /// position d'un segment, élément d'un segment), qui doit produire une
    /// valeur de type `attendu`.
    ///
    /// Une expression constante est calculée à l'instanciation, avant que
    /// le code ne tourne : elle n'a droit qu'aux constantes (t.const,
    /// ref.null, ref.func) et à la lecture d'une globale NON MODIFIABLE et
    /// IMPORTÉE. Importée, parce que les globales du module sont elles-mêmes
    /// initialisées par des expressions constantes, dans l'ordre : lire la
    /// globale 3 depuis la globale 2 lirait une valeur pas encore calculée.
    /// (La version 3.0 autorise les globales précédentes, et un peu
    /// d'arithmétique.) Chacune de ces instructions empile une valeur sans
    /// rien dépiler : une expression valide en contient exactement une.
    fn constante(&mut self, plage: Plage, attendu: TypeValeur) -> Result<(), Erreur> {
        let octets = jusqua(self.module, plage)?;
        let mut l = Lecteur::a_partir(octets, plage.debut as usize);
        let mut produit = None;
        loop {
            let position = l.position();
            let t = match lire_instruction(&mut l)? {
                Instruction::End => break,
                Instruction::I32Const(_) => TypeValeur::I32,
                Instruction::I64Const(_) => TypeValeur::I64,
                Instruction::F32Const(_) => TypeValeur::F32,
                Instruction::F64Const(_) => TypeValeur::F64,
                Instruction::RefNull(t) => t,
                Instruction::RefFunc(x) => {
                    self.declarer(x, position)?;
                    TypeValeur::FuncRef
                }
                Instruction::GlobalGet(x) => {
                    let importees = &self.globales[..self.globales_importees];
                    let g = importees.get(x as usize).ok_or(erreur(position, Genre::IndexInconnu(Espace::Globale, x)))?;
                    if g.modifiable {
                        return Err(erreur(position, Genre::ExpressionNonConstante));
                    }
                    g.valeur
                }
                _ => return Err(erreur(position, Genre::ExpressionNonConstante)),
            };
            if produit.is_some() {
                return Err(erreur(position, Genre::ValeursEnTrop));
            }
            produit = Some(t);
        }
        // `l` est maintenant juste après le `end`.
        let fin = l.position() - 1;
        match produit {
            None => Err(erreur(fin, Genre::PileVide)),
            Some(trouve) if trouve != attendu => Err(erreur(fin, Genre::TypeInattendu { attendu, trouve })),
            Some(_) => Ok(()),
        }
    }
}

/// Des limites sont valides si le minimum ne dépasse pas le maximum. Pour
/// une mémoire, tous deux tiennent aussi en PAGES_MAX ; une table n'a pas
/// d'autre borne que celle des u32 (4 milliards d'éléments).
fn verifier_limites(limites: Limites, memoire: bool, position: usize) -> Result<(), Erreur> {
    if memoire && (limites.min > PAGES_MAX || limites.max.is_some_and(|max| max > PAGES_MAX)) {
        return Err(erreur(position, Genre::MemoireTropGrande));
    }
    if limites.max.is_some_and(|max| max < limites.min) {
        return Err(erreur(position, Genre::LimitesInversees));
    }
    Ok(())
}

/// Les genres de cadres de contrôle : le corps de la fonction, et les
/// trois instructions de bloc (le `else` ouvre un nouveau cadre).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GenreCadre {
    Fonction,
    Bloc,
    Boucle,
    Si,
    Sinon,
}

/// Un bloc ouvert (ctrl_frame dans la spécification).
struct Cadre<'m> {
    genre: GenreCadre,
    /// Les types que le bloc reçoit (ses paramètres) et ceux qu'il laisse.
    entree: &'m [TypeValeur],
    sortie: &'m [TypeValeur],
    /// La hauteur de la pile des types à l'ouverture, paramètres retirés :
    /// le bloc ne dépile jamais en dessous.
    hauteur: usize,
    /// La suite du bloc est-elle inaccessible (après br, return...) ?
    inaccessible: bool,
    /// La position du dernier `br_table` qui a vérifié les types de
    /// l'étiquette du bloc (0 : aucun ; voir BrTable).
    verifiee_par: usize,
    /// Boucle : la position de la première instruction de son corps, et le
    /// nombre d'entrées de la table annexe à cet endroit. C'est là que
    /// mènent ses branchements.
    debut: u32,
    debut_table: u32,
    /// Les autres genres : les branchements vers la fin du bloc, encore
    /// inconnue, attendent dans une « chaîne de correction », la technique
    /// des assembleurs en une passe pour les sauts vers l'avant. `attente`
    /// vaut l'index + 1 de la dernière entrée en attente (0 : aucune), et
    /// chaque entrée en attente garde dans son champ `cible`, en attendant
    /// la vraie, l'index + 1 de la précédente. La chaîne traverse la table
    /// elle-même : pas de liste à part, pas d'allocation par bloc. Au `end`,
    /// `completer` la parcourt. (Une vraie cible ne vaut jamais 0 : la
    /// position 0 du module est la signature \0asm.)
    attente: u32,
    /// Si : l'entrée du `if` lui-même (condition fausse), complétée au
    /// `else`, ou au `end` s'il n'y en a pas.
    saut_si: u32,
}

impl<'m> Cadre<'m> {
    /// Les types que reçoit l'étiquette du bloc, c'est-à-dire ce qu'un
    /// branchement vers ce bloc doit fournir. Brancher vers un `block` ou un
    /// `if` saute à sa FIN : il faut ses résultats. Brancher vers une
    /// `loop` saute à son DÉBUT (on recommence un tour) : il faut ses
    /// paramètres.
    fn etiquette(&self) -> &'m [TypeValeur] {
        if self.genre == GenreCadre::Boucle { self.entree } else { self.sortie }
    }
}

/// Un type de valeur seul, sous forme de liste (pour les blocs de type
/// `[] -> [t]`), sans allocation : une tranche statique par type.
fn un_seul(t: TypeValeur) -> &'static [TypeValeur] {
    match t {
        TypeValeur::I32 => &[TypeValeur::I32],
        TypeValeur::I64 => &[TypeValeur::I64],
        TypeValeur::F32 => &[TypeValeur::F32],
        TypeValeur::F64 => &[TypeValeur::F64],
        TypeValeur::FuncRef => &[TypeValeur::FuncRef],
        TypeValeur::ExternRef => &[TypeValeur::ExternRef],
    }
}

/// La validation du corps d'une fonction.
struct Validateur<'c, 'm> {
    contexte: &'c Contexte<'m>,
    /// Les variables locales : les paramètres, puis celles déclarées. Au
    /// plus LOCALES_MAX : on peut les déplier en un simple tableau.
    locales: Vec<TypeValeur>,
    /// Les résultats de la fonction, pour `return`.
    resultats: &'m [TypeValeur],
    /// La pile des types (vals) ; `None` est le type inconnu.
    pile: Vec<Option<TypeValeur>>,
    /// La pile des cadres (ctrls) ; le dernier est le bloc courant.
    cadres: Vec<Cadre<'m>>,
    /// La table annexe des branchements, remplie au fil du code.
    table: Vec<Branchement>,
    hauteur_max: usize,
    /// La position de l'instruction en cours, pour les erreurs.
    position: usize,
}

impl<'c, 'm> Validateur<'c, 'm> {
    fn valider(contexte: &'c Contexte<'m>, type_fonction: &'m TypeFonction, corps: &Corps) -> Result<CodeValide, Erreur> {
        let declarees: u64 = corps.locales.iter().map(|&(nombre, _)| nombre as u64).sum();
        if type_fonction.parametres.len() as u64 + declarees > LOCALES_MAX as u64 {
            return Err(erreur(corps.code.debut as usize, Genre::LimiteDepassee(Limite::Locales)));
        }
        let mut locales = type_fonction.parametres.to_vec();
        for &(nombre, t) in corps.locales.iter() {
            locales.extend(core::iter::repeat_n(t, nombre as usize));
        }
        let mut v = Validateur {
            contexte,
            locales,
            resultats: &type_fonction.resultats,
            pile: Vec::new(),
            cadres: Vec::new(),
            table: Vec::new(),
            hauteur_max: 0,
            position: corps.code.debut as usize,
        };
        // Le corps de la fonction est un bloc implicite, qui doit laisser
        // les résultats de la fonction ; brancher vers lui équivaut à
        // `return`.
        v.ouvrir(GenreCadre::Fonction, &[], &type_fonction.resultats);

        let octets = jusqua(contexte.module, corps.code)?;
        let mut l = Lecteur::a_partir(octets, corps.code.debut as usize);
        loop {
            v.position = l.position();
            let instruction = lire_instruction(&mut l)?;
            let fini = v.instruction(instruction, l.position() as u32, octets)?;
            // Chaque instruction dépile ses opérandes AVANT d'empiler ses
            // résultats : la hauteur la plus grande est atteinte entre deux
            // instructions, et il suffit de la mesurer ici. Une instruction
            // empile au plus PARAMETRES_MAX ou RESULTATS_MAX valeurs (un
            // bloc, un appel) : la pile ne dépasse la limite que de peu.
            v.hauteur_max = v.hauteur_max.max(v.pile.len());
            if v.hauteur_max > HAUTEUR_PILE_MAX {
                return Err(v.erreur(Genre::LimiteDepassee(Limite::HauteurPile)));
            }
            if fini {
                break;
            }
        }
        // Le décodeur a vérifié que le `end` qui ferme le corps est son
        // dernier octet, en comptant les blocs comme nous : on ne peut
        // pas s'arrêter avant.
        if !l.fini() {
            return Err(erreur(l.position(), Genre::FinDeFonctionAttendue));
        }
        Ok(CodeValide { branchements: v.table.into(), locales: declarees as u32, hauteur_max: v.hauteur_max as u32 })
    }

    fn erreur(&self, genre: Genre) -> Erreur {
        erreur(self.position, genre)
    }

    /// Le bloc courant. Il y en a toujours un : le corps de la fonction
    /// reste ouvert jusqu'à son `end`, qui arrête la validation.
    fn cadre(&self) -> &Cadre<'m> {
        self.cadres.last().expect("pile des cadres vide")
    }

    fn empiler(&mut self, t: Option<TypeValeur>) {
        self.pile.push(t);
    }

    fn empiler_types(&mut self, types: &[TypeValeur]) {
        self.pile.extend(types.iter().map(|&t| Some(t)));
    }

    /// Dépile un type, quel qu'il soit (pop_val).
    fn depiler(&mut self) -> Result<Option<TypeValeur>, Erreur> {
        let cadre = self.cadre();
        if self.pile.len() == cadre.hauteur {
            // Rien à dépiler dans ce bloc : c'est une erreur, sauf dans du
            // code inaccessible, où la pile est polymorphe.
            if cadre.inaccessible {
                return Ok(None);
            }
            return Err(self.erreur(Genre::PileVide));
        }
        Ok(self.pile.pop().expect("pile plus basse que son cadre"))
    }

    /// Dépile un type, qui doit être `attendu` (ou inconnu). Rend le type
    /// trouvé.
    fn depiler_type(&mut self, attendu: TypeValeur) -> Result<Option<TypeValeur>, Erreur> {
        let trouve = self.depiler()?;
        match trouve {
            Some(t) if t != attendu => Err(self.erreur(Genre::TypeInattendu { attendu, trouve: t })),
            _ => Ok(trouve),
        }
    }

    /// Dépile une liste de types, empilés dans l'ordre de la liste : on
    /// les retrouve donc en partant de la fin.
    fn depiler_types(&mut self, types: &[TypeValeur]) -> Result<(), Erreur> {
        for &t in types.iter().rev() {
            self.depiler_type(t)?;
        }
        Ok(())
    }

    fn ouvrir(&mut self, genre: GenreCadre, entree: &'m [TypeValeur], sortie: &'m [TypeValeur]) {
        let hauteur = self.pile.len();
        self.cadres.push(Cadre {
            genre,
            entree,
            sortie,
            hauteur,
            inaccessible: false,
            verifiee_par: 0,
            debut: 0,
            debut_table: 0,
            attente: 0,
            saut_si: 0,
        });
        self.empiler_types(entree);
    }

    /// Ferme le bloc courant : il doit laisser exactement ses types de
    /// sortie sur la pile, ni moins, ni plus.
    fn fermer(&mut self) -> Result<Cadre<'m>, Erreur> {
        let sortie = self.cadre().sortie;
        self.depiler_types(sortie)?;
        if self.pile.len() != self.cadre().hauteur {
            return Err(self.erreur(Genre::ValeursEnTrop));
        }
        Ok(self.cadres.pop().expect("pile des cadres vide"))
    }

    /// La suite du bloc courant est inaccessible : la pile retombe à la
    /// hauteur du bloc, et devient polymorphe.
    fn inaccessible(&mut self) {
        let cadre = self.cadres.last_mut().expect("pile des cadres vide");
        self.pile.truncate(cadre.hauteur);
        cadre.inaccessible = true;
    }

    /// Ajoute à la table annexe l'entrée d'un branchement vers l'étiquette du
    /// cadre `index`, pris avec la pile telle qu'elle est maintenant (la
    /// condition d'un `br_if`, l'index d'un `br_table` déjà dépilés).
    fn branchement(&mut self, index: usize) {
        let numero = self.table.len();
        let cadre = &mut self.cadres[index];
        let gardees = cadre.etiquette().len();
        // Dans du code inaccessible, la pile peut être plus basse que ce
        // que l'étiquette reçoit : l'entrée ne servira pas (voir
        // `Branchement`), mais le calcul ne doit pas déborder.
        let retirees = self.pile.len().saturating_sub(cadre.hauteur + gardees);
        let mut entree = Branchement { cible: 0, suite: 0, gardees: gardees as u32, retirees: retirees as u32 };
        if cadre.genre == GenreCadre::Boucle {
            // On a déjà passé le début de la boucle : la cible est connue.
            entree.cible = cadre.debut;
            entree.suite = cadre.debut_table;
        } else {
            entree.cible = cadre.attente;
            cadre.attente = numero as u32 + 1;
        }
        self.table.push(entree);
    }

    /// Ajoute l'entrée d'un `if` ou d'un `else`, qui ne déplace aucune
    /// valeur, et rend son index : sa cible sera complétée plus loin.
    fn saut(&mut self) -> u32 {
        self.table.push(Branchement { cible: 0, suite: 0, gardees: 0, retirees: 0 });
        self.table.len() as u32 - 1
    }

    /// Ajoute l'entrée `numero` à la chaîne `attente` (voir `Cadre`), et
    /// rend la nouvelle tête de la chaîne.
    fn chainer(&mut self, attente: u32, numero: u32) -> u32 {
        self.table[numero as usize].cible = attente;
        numero + 1
    }

    /// Complète les entrées de la chaîne `attente`, qui mènent à `cible`.
    /// La prochaine entrée créée sera celle du premier branchement après la
    /// cible : c'est leur `suite`.
    fn completer(&mut self, mut attente: u32, cible: u32) {
        let suite = self.table.len() as u32;
        while attente != 0 {
            let entree = &mut self.table[attente as usize - 1];
            attente = entree.cible;
            entree.cible = cible;
            entree.suite = suite;
        }
    }

    /// L'index, dans `cadres`, du bloc désigné par l'étiquette `profondeur`
    /// (0 = le bloc courant, 1 = celui qui l'englobe...).
    fn etiquette(&self, profondeur: u32) -> Result<usize, Erreur> {
        let n = self.cadres.len();
        if profondeur as usize >= n {
            return Err(self.erreur(Genre::IndexInconnu(Espace::Etiquette, profondeur)));
        }
        Ok(n - 1 - profondeur as usize)
    }

    /// Les types d'entrée et de sortie d'un bloc.
    fn types_bloc(&self, type_bloc: TypeBloc) -> Result<(&'m [TypeValeur], &'m [TypeValeur]), Erreur> {
        Ok(match type_bloc {
            TypeBloc::Vide => (&[], &[]),
            TypeBloc::Valeur(t) => (&[], un_seul(t)),
            TypeBloc::Index(x) => {
                let t = self.contexte.type_fonction(x, self.position)?;
                (&t.parametres, &t.resultats)
            }
        })
    }

    fn locale(&self, x: u32) -> Result<TypeValeur, Erreur> {
        self.locales.get(x as usize).copied().ok_or(self.erreur(Genre::IndexInconnu(Espace::Locale, x)))
    }

    /// Valide une instruction. `apres` : la position de l'instruction
    /// suivante. `octets` : le module, jusqu'à la fin du corps (pour relire
    /// les cibles d'un br_table). Rend vrai au `end` qui ferme le corps de
    /// la fonction.
    fn instruction(&mut self, instruction: Instruction, apres: u32, octets: &[u8]) -> Result<bool, Erreur> {
        use Instruction::*;
        use TypeValeur::{F32, F64, FuncRef, I32, I64};
        let p = self.position;
        let c = self.contexte;
        match instruction {
            // Contrôle
            Unreachable => self.inaccessible(),
            Nop => {}
            Block(type_bloc) | Loop(type_bloc) => {
                let (entree, sortie) = self.types_bloc(type_bloc)?;
                self.depiler_types(entree)?;
                let genre = if matches!(instruction, Block(_)) { GenreCadre::Bloc } else { GenreCadre::Boucle };
                self.ouvrir(genre, entree, sortie);
                if genre == GenreCadre::Boucle {
                    let debut_table = self.table.len() as u32;
                    let boucle = self.cadres.last_mut().expect("boucle ouverte");
                    boucle.debut = apres;
                    boucle.debut_table = debut_table;
                }
            }
            If(type_bloc) => {
                let (entree, sortie) = self.types_bloc(type_bloc)?;
                self.depiler_type(I32)?;
                self.depiler_types(entree)?;
                // Si la condition est fausse, on saute la branche « alors ».
                // Les paramètres du bloc restent sur la pile, pour la
                // branche « sinon » : rien à déplacer.
                let saut_si = self.saut();
                self.ouvrir(GenreCadre::Si, entree, sortie);
                self.cadres.last_mut().expect("if ouvert").saut_si = saut_si;
            }
            Else => {
                // Le format binaire n'a de `else` que dans un `if` : la
                // spécification classe un `else` isolé parmi les modules mal
                // formés. Le décodeur ne suit pas le genre des blocs ; c'est
                // ici qu'on le voit.
                if self.cadre().genre != GenreCadre::Si {
                    return Err(self.erreur(Genre::ElseSansIf));
                }
                // La branche « alors » doit laisser les résultats du `if` ;
                // la branche « sinon » repart de ses paramètres.
                let si = self.fermer()?;
                // Arrivé au `else`, l'exécution a fini la branche « alors » :
                // elle saute à la fin. La pile contient exactement les
                // résultats (`fermer` vient de le vérifier) : rien à
                // déplacer.
                let saut_else = self.saut();
                // Si la condition est fausse, la branche « sinon » commence
                // juste après le `else` (l'entrée du `if` est seule dans sa
                // chaîne).
                self.completer(si.saut_si + 1, apres);
                // Les branchements vers la fin du `if` mènent à la fin du
                // `else` : c'est la même. Leur chaîne passe au `else`.
                let attente = self.chainer(si.attente, saut_else);
                self.ouvrir(GenreCadre::Sinon, si.entree, si.sortie);
                self.cadres.last_mut().expect("else ouvert").attente = attente;
            }
            End => {
                // `if ... end` sans `else` abrège `if ... else end` : la
                // branche « sinon », vide, doit transformer les paramètres
                // du `if` en ses résultats. Ils doivent donc être les mêmes.
                // Une condition fausse mène alors directement à la fin.
                if self.cadre().genre == GenreCadre::Si {
                    let si = self.fermer()?;
                    let attente = self.chainer(si.attente, si.saut_si);
                    self.ouvrir(GenreCadre::Sinon, si.entree, si.sortie);
                    self.cadres.last_mut().expect("else ouvert").attente = attente;
                }
                let cadre = self.fermer()?;
                if cadre.genre == GenreCadre::Fonction {
                    // Les branchements vers le corps de la fonction mènent à
                    // ce `end` final : l'exécuter fait le retour.
                    self.completer(cadre.attente, self.position as u32);
                    return Ok(true);
                }
                self.completer(cadre.attente, apres);
                self.empiler_types(cadre.sortie);
            }
            Br(profondeur) => {
                let cible = self.etiquette(profondeur)?;
                self.branchement(cible);
                self.depiler_types(self.cadres[cible].etiquette())?;
                self.inaccessible();
            }
            BrIf(profondeur) => {
                let cible = self.etiquette(profondeur)?;
                self.depiler_type(I32)?;
                self.branchement(cible);
                let types = self.cadres[cible].etiquette();
                self.depiler_types(types)?;
                self.empiler_types(types);
            }
            BrTable { nombre, cibles } => {
                self.depiler_type(I32)?;
                // La cible par défaut vient en dernier ; il faut la
                // connaître d'abord : toutes les cibles doivent recevoir
                // autant de valeurs qu'elle.
                let mut l = lire_cibles(octets, cibles);
                for _ in 0..nombre {
                    l.u32()?;
                }
                let defaut = self.etiquette(l.u32()?)?;
                let arite = self.cadres[defaut].etiquette().len();
                let mut l = lire_cibles(octets, cibles);
                let mut trouves = Vec::new();
                for _ in 0..nombre {
                    let cible = self.etiquette(l.u32()?)?;
                    let types = self.cadres[cible].etiquette();
                    if types.len() != arite {
                        return Err(self.erreur(Genre::CiblesIncompatibles));
                    }
                    self.branchement(cible);
                    // Dépiler les types de la cible, puis rempiler ceux
                    // qu'on a TROUVÉS (push_vals(pop_vals(...))) : dans du
                    // code inaccessible, des inconnus restent des inconnus,
                    // et peuvent servir à des cibles de types différents.
                    // La pile en ressort telle qu'après le premier passage :
                    // le refaire pour une étiquette déjà vue ne vérifierait
                    // rien de plus. On ne le fait donc qu'une fois par
                    // étiquette ; sinon, un br_table d'un million de cibles
                    // vers un bloc à 1000 résultats coûterait un milliard
                    // d'opérations, pour quelques Mio de code.
                    if self.cadres[cible].verifiee_par == p {
                        continue;
                    }
                    self.cadres[cible].verifiee_par = p;
                    trouves.clear();
                    for &t in types.iter().rev() {
                        trouves.push(self.depiler_type(t)?);
                    }
                    for &t in trouves.iter().rev() {
                        self.empiler(t);
                    }
                }
                self.branchement(defaut);
                self.depiler_types(self.cadres[defaut].etiquette())?;
                self.inaccessible();
            }
            Return => {
                self.depiler_types(self.resultats)?;
                self.inaccessible();
            }
            Call(x) => {
                let t = c.fonction(x, p)?;
                self.depiler_types(&t.parametres)?;
                self.empiler_types(&t.resultats);
            }
            CallIndirect { type_fonction, table } => {
                let table = c.table(table, p)?;
                if table.element != FuncRef {
                    return Err(self.erreur(Genre::TypeInattendu { attendu: FuncRef, trouve: table.element }));
                }
                let t = c.type_fonction(type_fonction, p)?;
                self.depiler_type(I32)?;
                self.depiler_types(&t.parametres)?;
                self.empiler_types(&t.resultats);
            }

            // Références
            RefNull(t) => self.empiler(Some(t)),
            RefIsNull => {
                if let Some(t) = self.depiler()? {
                    if !t.est_reference() {
                        return Err(self.erreur(Genre::ReferenceRequise(t)));
                    }
                }
                self.empiler(Some(I32));
            }
            RefFunc(x) => {
                c.fonction(x, p)?;
                if !c.declarees[x as usize] {
                    return Err(self.erreur(Genre::ReferenceNonDeclaree(x)));
                }
                self.empiler(Some(FuncRef));
            }

            // Paramétriques
            Drop => {
                self.depiler()?;
            }
            Select => {
                // Sans type écrit, le type du résultat se déduit des
                // opérandes. C'est immédiat pour les nombres. Pour les
                // références, les extensions suivantes de WebAssembly
                // ajoutent du sous-typage (une référence a plusieurs types
                // à la fois), et il faudrait calculer un type commun : on
                // exige donc `select t`, avec le type écrit.
                self.depiler_type(I32)?;
                let t1 = self.depiler()?;
                let t2 = self.depiler()?;
                for t in [t1, t2].into_iter().flatten() {
                    if t.est_reference() {
                        return Err(self.erreur(Genre::NombreRequis(t)));
                    }
                }
                if let (Some(a), Some(b)) = (t1, t2) {
                    if a != b {
                        return Err(self.erreur(Genre::TypeInattendu { attendu: a, trouve: b }));
                    }
                }
                self.empiler(t1.or(t2));
            }
            SelectT { nombre, premier } => {
                // Une liste de types, pour une future extension où `select`
                // rendrait plusieurs valeurs ; en 2.0, exactement une.
                let t = match (nombre, premier) {
                    (1, Some(t)) => t,
                    _ => return Err(self.erreur(Genre::TypesDuSelect(nombre))),
                };
                self.depiler_type(I32)?;
                self.depiler_type(t)?;
                self.depiler_type(t)?;
                self.empiler(Some(t));
            }

            // Variables
            LocalGet(x) => {
                let t = self.locale(x)?;
                self.empiler(Some(t));
            }
            LocalSet(x) => {
                let t = self.locale(x)?;
                self.depiler_type(t)?;
            }
            LocalTee(x) => {
                let t = self.locale(x)?;
                self.depiler_type(t)?;
                self.empiler(Some(t));
            }
            GlobalGet(x) => {
                let g = c.globale(x, p)?;
                self.empiler(Some(g.valeur));
            }
            GlobalSet(x) => {
                let g = c.globale(x, p)?;
                if !g.modifiable {
                    return Err(self.erreur(Genre::GlobaleNonModifiable(x)));
                }
                self.depiler_type(g.valeur)?;
            }

            // Tables. Les opérandes sont dépilés dans l'ordre inverse de
            // leur empilement : `table.set` attend [index, valeur], la
            // valeur au sommet.
            TableGet(x) => {
                let t = c.table(x, p)?;
                self.depiler_type(I32)?;
                self.empiler(Some(t.element));
            }
            TableSet(x) => {
                let t = c.table(x, p)?;
                self.depiler_type(t.element)?;
                self.depiler_type(I32)?;
            }
            TableInit { segment, table } => {
                let t = c.table(table, p)?;
                let element = c.elements(segment, p)?;
                if element != t.element {
                    return Err(self.erreur(Genre::TypeInattendu { attendu: t.element, trouve: element }));
                }
                self.depiler_types(&[I32, I32, I32])?;
            }
            ElemDrop(x) => {
                c.elements(x, p)?;
            }
            TableCopy { destination, source } => {
                let d = c.table(destination, p)?;
                let s = c.table(source, p)?;
                if s.element != d.element {
                    return Err(self.erreur(Genre::TypeInattendu { attendu: d.element, trouve: s.element }));
                }
                self.depiler_types(&[I32, I32, I32])?;
            }
            TableGrow(x) => {
                // [valeur initiale, nombre d'éléments ajoutés] -> [ancienne taille]
                let t = c.table(x, p)?;
                self.depiler_type(I32)?;
                self.depiler_type(t.element)?;
                self.empiler(Some(I32));
            }
            TableSize(x) => {
                c.table(x, p)?;
                self.empiler(Some(I32));
            }
            TableFill(x) => {
                // [début, valeur, nombre]
                let t = c.table(x, p)?;
                self.depiler_type(I32)?;
                self.depiler_type(t.element)?;
                self.depiler_type(I32)?;
            }

            // Mémoire
            Acces(acces, arg) => {
                c.memoire(0, p)?;
                // L'alignement promis ne peut pas dépasser la taille de
                // l'accès : promettre qu'un octet est aligné sur 4 n'a pas
                // de sens. (Un accès moins aligné que promis marche quand
                // même : c'est un indice de performance, pas une règle.)
                let (t, taille) = acces.genre();
                if 1u32 << arg.align > taille {
                    return Err(self.erreur(Genre::AlignementTropGrand));
                }
                if acces.est_ecriture() {
                    self.depiler_type(t)?;
                    self.depiler_type(I32)?;
                } else {
                    self.depiler_type(I32)?;
                    self.empiler(Some(t));
                }
            }
            MemorySize => {
                c.memoire(0, p)?;
                self.empiler(Some(I32));
            }
            MemoryGrow => {
                c.memoire(0, p)?;
                self.depiler_type(I32)?;
                self.empiler(Some(I32));
            }
            MemoryInit(x) => {
                c.memoire(0, p)?;
                c.donnees(x, p)?;
                self.depiler_types(&[I32, I32, I32])?;
            }
            DataDrop(x) => c.donnees(x, p)?,
            MemoryCopy | MemoryFill => {
                c.memoire(0, p)?;
                self.depiler_types(&[I32, I32, I32])?;
            }

            // Constantes et opérations numériques
            I32Const(_) => self.empiler(Some(I32)),
            I64Const(_) => self.empiler(Some(I64)),
            F32Const(_) => self.empiler(Some(F32)),
            F64Const(_) => self.empiler(Some(F64)),
            Op(op) => {
                let (entrees, sortie) = op.signature();
                self.depiler_types(entrees)?;
                self.empiler(Some(sortie));
            }
        }
        Ok(false)
    }
}

/// Les cas que la suite officielle ne couvre pas : nos limites, et
/// quelques recoins de l'algorithme. Les modules sont assemblés à la main.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder;

    fn leb(mut n: u32, sortie: &mut Vec<u8>) {
        loop {
            let octet = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                sortie.push(octet);
                return;
            }
            sortie.push(octet | 0x80);
        }
    }

    fn section(id: u8, contenu: &[u8], module: &mut Vec<u8>) {
        module.push(id);
        leb(contenu.len() as u32, module);
        module.extend_from_slice(contenu);
    }

    /// Un module d'une seule fonction, de type `parametres -> resultats`,
    /// avec des groupes de locales (nombre, type) et `code` (sans le `end`
    /// final).
    fn module(parametres: &[u8], resultats: &[u8], locales: &[(u32, u8)], code: &[u8]) -> Vec<u8> {
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        let mut types = vec![1, 0x60];
        leb(parametres.len() as u32, &mut types);
        types.extend_from_slice(parametres);
        leb(resultats.len() as u32, &mut types);
        types.extend_from_slice(resultats);
        section(1, &types, &mut m);
        section(3, &[1, 0], &mut m);
        let mut corps = Vec::new();
        leb(locales.len() as u32, &mut corps);
        for &(nombre, t) in locales {
            leb(nombre, &mut corps);
            corps.push(t);
        }
        corps.extend_from_slice(code);
        corps.push(0x0B);
        let mut code = vec![1];
        leb(corps.len() as u32, &mut code);
        code.extend_from_slice(&corps);
        section(10, &code, &mut m);
        m
    }

    fn verdict(octets: &[u8]) -> Result<ModuleValide, Genre> {
        decoder(octets).and_then(valider).map_err(|e| e.genre)
    }

    const I32: u8 = 0x7F;
    const F32: u8 = 0x7D;

    #[test]
    fn else_isole() {
        // block else end : le `else` ferme un `block`.
        assert_eq!(verdict(&module(&[], &[], &[], &[0x02, 0x40, 0x05, 0x0B])).unwrap_err(), Genre::ElseSansIf);
        // else : au niveau de la fonction.
        assert_eq!(verdict(&module(&[], &[], &[], &[0x05])).unwrap_err(), Genre::ElseSansIf);
    }

    #[test]
    fn if_sans_else() {
        // i32.const 1  if (result i32) i32.const 2 end : la branche
        // « sinon » implicite ne fournit pas d'i32.
        let code = [0x41, 1, 0x04, I32, 0x41, 2, 0x0B];
        assert_eq!(verdict(&module(&[], &[I32], &[], &code)).unwrap_err(), Genre::PileVide);
        // Avec un type [i32] -> [i32] (le type 0 lui-même), la branche
        // implicite rend son paramètre : valide.
        let code = [0x41, 1, 0x41, 1, 0x04, 0x00, 0x0B];
        assert!(verdict(&module(&[I32], &[I32], &[], &code)).is_ok());
    }

    #[test]
    fn br_table_inaccessible() {
        // block (result f32)
        //   block (result i32)
        //     <avant>  br_table 0 1 1
        //   end
        //   drop  f32.const 0
        // end
        // drop
        let code = |avant: &[u8]| {
            let mut c = vec![0x02, F32, 0x02, I32];
            c.extend_from_slice(avant);
            c.extend_from_slice(&[0x0E, 2, 0, 1, 1, 0x0B, 0x1A, 0x43, 0, 0, 0, 0, 0x0B, 0x1A]);
            c
        };
        // Après `unreachable`, l'inconnu dépilé pour la cible i32 est
        // rempilé tel quel, et convient ensuite aux cibles f32 : valide.
        assert!(verdict(&module(&[], &[], &[], &code(&[0x00]))).is_ok());
        // Avec un vrai i32 (et l'index), la cible f32 le refuse.
        let avant = [0x41, 0, 0x41, 0];
        assert_eq!(
            verdict(&module(&[], &[], &[], &code(&avant))).unwrap_err(),
            Genre::TypeInattendu { attendu: TypeValeur::F32, trouve: TypeValeur::I32 }
        );
    }

    /// La table annexe de la fonction, avec les cibles comptées depuis le
    /// début de son code : (cible, suite, gardees, retirees).
    fn table(parametres: &[u8], resultats: &[u8], code: &[u8]) -> Vec<(u32, u32, u32, u32)> {
        let v = verdict(&module(parametres, resultats, &[], code)).unwrap();
        let debut = v.module().corps[0].code.debut;
        v.code(0).branchements.iter().map(|b| (b.cible - debut, b.suite, b.gardees, b.retirees)).collect()
    }

    #[test]
    fn table_bloc() {
        //  0  block (result i32)
        //  2    i32.const 1
        //  4    i32.const 2
        //  6    br 0          -> 9 ; garde le 2, retire le 1
        //  8  end
        //  9  end
        let code = [0x02, I32, 0x41, 1, 0x41, 2, 0x0C, 0, 0x0B];
        assert_eq!(table(&[], &[I32], &code), [(9, 1, 1, 1)]);
    }

    #[test]
    fn table_boucle() {
        // Une boucle de type [i32] -> [i32] (le type 0) : brancher vers elle
        // lui repasse son paramètre.
        //  0  local.get 0
        //  2  loop (type 0)
        //  4    i32.const 1
        //  6    i32.sub
        //  7    local.tee 0
        //  9    local.get 0
        // 11    br_if 0       -> 4 (début du corps), entrée 0 ; garde 1
        // 13  end
        // 14  end
        let code = [0x20, 0, 0x03, 0, 0x41, 1, 0x6B, 0x22, 0, 0x20, 0, 0x0D, 0, 0x0B];
        assert_eq!(table(&[I32], &[I32], &code), [(4, 0, 1, 0)]);
    }

    #[test]
    fn table_si() {
        //  0  i32.const 1
        //  2  if (result i32)  faux -> 7 (après else), entrée 2
        //  4    i32.const 2
        //  6  else             -> 10 (après end), entrée 2
        //  7    i32.const 3
        //  9  end
        // 10  end
        let code = [0x41, 1, 0x04, I32, 0x41, 2, 0x05, 0x41, 3, 0x0B];
        assert_eq!(table(&[], &[I32], &code), [(7, 2, 0, 0), (10, 2, 0, 0)]);
        // Sans else, le `if` et le `br` mènent tous deux à la fin.
        //  0  i32.const 1
        //  2  if             faux -> 7
        //  4    br 0         -> 7
        //  6  end
        //  7  end
        let code = [0x41, 1, 0x04, 0x40, 0x0C, 0, 0x0B];
        assert_eq!(table(&[], &[], &code), [(7, 2, 0, 0), (7, 2, 0, 0)]);
    }

    #[test]
    fn table_br_table_et_retour() {
        // Les deux cibles reçoivent un i32 (sinon : CiblesIncompatibles).
        //  0  block (result i32)
        //  2    i32.const 7
        //  4    i32.const 8
        //  6    i32.const 0
        //  8    br_table 0 1  cible 0 -> 13 ; garde le 8, retire le 7
        //                     défaut (la fonction) -> 16, le `end` final
        // 12  end
        // 13  drop
        // 14  i32.const 9
        // 16  end
        let code = [0x02, I32, 0x41, 7, 0x41, 8, 0x41, 0, 0x0E, 1, 0, 1, 0x0B, 0x1A, 0x41, 9];
        assert_eq!(table(&[], &[I32], &code), [(13, 2, 1, 1), (16, 2, 1, 1)]);
        let v = verdict(&module(&[], &[I32], &[], &code)).unwrap();
        assert_eq!(v.code(0).hauteur_max, 3);
    }

    #[test]
    fn module_fabrique() {
        // Les champs de `Module` sont publics : `valider` doit refuser, sans
        // paniquer, ce que le décodeur n'aurait jamais produit.
        let octets = module(&[], &[], &[], &[]);
        let bon = decoder(&octets).unwrap();
        let refuse = |m: Module| valider(m).map(|_| ()).unwrap_err().genre;

        let mut m = bon.clone();
        m.fonctions.push(0); // une fonction sans corps
        assert_eq!(refuse(m), Genre::FonctionsEtCodeIncoherents);

        let mut m = bon.clone();
        m.corps[0].code.fin = octets.len() as u32 + 1; // hors du module
        assert_eq!(refuse(m), Genre::FinInattendue);

        let mut m = bon.clone();
        m.tables.push(TypeTable { element: TypeValeur::I32, limites: Limites { min: 0, max: None } });
        assert_eq!(refuse(m), Genre::ReferenceRequise(TypeValeur::I32));

        let mut m = bon;
        m.elements.push(SegmentElements {
            type_element: TypeValeur::ExternRef,
            elements: vec![Element::Fonction(0)],
            mode: ModeSegment::Passif,
        });
        let erreur = refuse(m);
        assert_eq!(erreur, Genre::TypeInattendu { attendu: TypeValeur::ExternRef, trouve: TypeValeur::FuncRef });
    }

    #[test]
    fn limites() {
        let parametres = vec![I32; PARAMETRES_MAX + 1];
        assert_eq!(verdict(&module(&parametres, &[], &[], &[])).unwrap_err(), Genre::LimiteDepassee(Limite::Parametres));
        let resultats = vec![I32; RESULTATS_MAX + 1];
        let erreur = verdict(&module(&[], &resultats, &[], &[0x00])).unwrap_err();
        assert_eq!(erreur, Genre::LimiteDepassee(Limite::Resultats));

        // Les paramètres comptent parmi les locales.
        let locales = [(LOCALES_MAX as u32 - 1, I32)];
        assert!(verdict(&module(&[I32], &[], &locales, &[])).is_ok());
        let erreur = verdict(&module(&[I32, I32], &[], &locales, &[])).unwrap_err();
        assert_eq!(erreur, Genre::LimiteDepassee(Limite::Locales));

        // HAUTEUR_PILE_MAX constantes empilées, puis une de trop. Le
        // `unreachable` final rend la fin de la fonction valide.
        let mut code: Vec<u8> = [0x41, 0].repeat(HAUTEUR_PILE_MAX);
        code.push(0x00);
        let v = verdict(&module(&[], &[], &[], &code)).unwrap();
        assert_eq!(v.code(0).hauteur_max as usize, HAUTEUR_PILE_MAX);
        code.splice(0..0, [0x41, 0]);
        assert_eq!(verdict(&module(&[], &[], &[], &code)).unwrap_err(), Genre::LimiteDepassee(Limite::HauteurPile));
    }
}
