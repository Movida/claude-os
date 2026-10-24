//! L'instanciation : d'un module validé à une instance vivante dans le
//! magasin, reliée à ce que l'environnement lui fournit.
//!
//! Dans l'ordre de la spécification (exec/modules, « Instantiation ») :
//!   1. les imports : autant que le module en déclare, chacun du bon genre
//!      et d'un type compatible (la « liaison ») ;
//!   2. l'allocation des fonctions, tables, mémoires, globales et segments
//!      du module, les valeurs initiales des globales calculées par leurs
//!      expressions constantes ;
//!   3. l'initialisation : chaque segment d'éléments actif est copié dans
//!      sa table (comme un table.init), chaque segment de données actif
//!      dans sa mémoire (memory.init), puis la fonction de démarrage est
//!      appelée.
//! Un piège pendant l'étape 3 fait échouer l'instanciation, mais ce qui a
//! déjà été écrit reste écrit : si la table ou la mémoire est importée,
//! d'autres modules le voient (linking.wast le vérifie).
//!
//! La fonction de démarrage est du code du module, qui peut boucler sans
//! fin : `instancier` ne l'exécute pas lui-même, il rend son appel, une
//! `Execution` que l'environnement fait tourner avec du carburant, comme
//! tout autre appel (voir interpreteur.rs). Aucun code WebAssembly ne
//! s'exécute donc jamais sans limite.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::instructions::{Instruction, lire_instruction};
use crate::lecteur::Lecteur;
use crate::interpreteur::Execution;
use crate::magasin::*;
use crate::module::{DescriptionImport, Element, Limites, ModeSegment, Module, Plage};
use crate::validateur::ModuleValide;

/// Une instance créée, pas encore démarrée.
#[must_use = "la fonction de demarrage doit s'executer avant d'utiliser l'instance"]
pub struct Instanciation {
    /// Le numéro de la nouvelle instance.
    pub instance: u32,
    /// L'appel de la fonction de démarrage du module, s'il en a une : à
    /// mener à son terme (`Execution::reprendre`) avant de se servir de
    /// l'instance. S'il piège, l'instanciation a échoué.
    pub demarrage: Option<Execution>,
}

/// Pourquoi une instanciation a échoué.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErreurInstanciation {
    /// Le module déclare `attendus` imports, on lui en donne `fournis`.
    NombreDImports { attendus: u32, fournis: u32 },
    /// L'import de cet index n'est pas du genre, ou du type, déclaré.
    ImportIncompatible(u32),
    /// Une table ou une mémoire dépasse nos limites, ou la mémoire de la
    /// machine.
    Ressources,
    /// L'initialisation a déclenché un piège.
    Piege(Piege),
}

impl fmt::Display for ErreurInstanciation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErreurInstanciation::NombreDImports { attendus, fournis } => {
                write!(f, "{attendus} imports attendus, {fournis} fournis")
            }
            ErreurInstanciation::ImportIncompatible(i) => write!(f, "import {i} de genre ou de type incompatible"),
            ErreurInstanciation::Ressources => write!(f, "table ou memoire trop grande"),
            ErreurInstanciation::Piege(p) => write!(f, "piege pendant l'initialisation : {p}"),
        }
    }
}

/// Des limites réelles (`min`, `max` d'un objet existant) conviennent-elles
/// à celles qu'un import déclare ? L'objet doit être au moins aussi grand,
/// et, si l'import promet un maximum au module, l'objet ne doit pas pouvoir
/// grandir au-delà : le module compte peut-être dessus.
fn limites_compatibles(min: u32, max: Option<u32>, declarees: Limites) -> bool {
    min >= declarees.min && declarees.max.is_none_or(|d| max.is_some_and(|m| m <= d))
}

impl Magasin {
    /// L'objet `externe` convient-il à l'import `import` du module ?
    fn import_compatible(&self, module: &Module, import: &DescriptionImport, externe: Externe) -> bool {
        match (import, externe) {
            (DescriptionImport::Fonction(t), Externe::Fonction(a)) => {
                self.fonctions.get(a as usize).is_some_and(|f| *f.type_fonction() == module.types[*t as usize])
            }
            (DescriptionImport::Table(t), Externe::Table(a)) => self.tables.get(a as usize).is_some_and(|table| {
                table.element == t.element && limites_compatibles(table.elements.len() as u32, table.max, t.limites)
            }),
            (DescriptionImport::Memoire(limites), Externe::Memoire(a)) => {
                self.memoires.get(a as usize).is_some_and(|m| limites_compatibles(m.pages(), m.max, *limites))
            }
            (DescriptionImport::Globale(g), Externe::Globale(a)) => {
                self.globales.get(a as usize).is_some_and(|globale| globale.type_globale == *g)
            }
            _ => false,
        }
    }

    /// La valeur d'une expression constante, dans l'instance `instance`.
    /// La validation garantit sa forme : une seule instruction constante.
    fn constante(&self, instance: usize, plage: Plage) -> u64 {
        let i = &self.instances[instance];
        let octets = &i.module.module().octets[..plage.fin as usize];
        let mut l = Lecteur::a_partir(octets, plage.debut as usize);
        match lire_instruction(&mut l).expect("expression constante validee") {
            Instruction::I32Const(v) => v as u32 as u64,
            Instruction::I64Const(v) => v as u64,
            Instruction::F32Const(bits) => bits as u64,
            Instruction::F64Const(bits) => bits,
            Instruction::RefNull(_) => 0,
            Instruction::RefFunc(x) => i.fonctions[x as usize] as u64 + 1,
            Instruction::GlobalGet(x) => self.globales[i.globales[x as usize] as usize].valeur,
            _ => unreachable!("expression constante validee"),
        }
    }

    /// Instancie `module` avec `imports` (dans l'ordre de ses imports), et
    /// rend la nouvelle instance, avec l'appel de sa fonction de démarrage.
    pub fn instancier(&mut self, module: Arc<ModuleValide>, imports: &[Externe]) -> Result<Instanciation, ErreurInstanciation> {
        let md = module.module();

        // 1. La liaison.
        if imports.len() != md.imports.len() {
            return Err(ErreurInstanciation::NombreDImports {
                attendus: md.imports.len() as u32,
                fournis: imports.len() as u32,
            });
        }
        for (i, (import, &externe)) in md.imports.iter().zip(imports).enumerate() {
            if !self.import_compatible(md, &import.description, externe) {
                return Err(ErreurInstanciation::ImportIncompatible(i as u32));
            }
        }

        // 2. L'allocation. Tables et mémoires d'abord, avant de toucher au
        // magasin : ce sont les seules allocations qui peuvent échouer (nos
        // limites, le budget, la mémoire de la machine), et un échec doit
        // laisser le magasin tel qu'il était. La spécification le dit
        // (« all failure conditions are checked before any observable
        // mutation of the store ») ; sinon, des fonctions déjà ajoutées
        // resteraient attachées au numéro d'instance, que la prochaine
        // instanciation reprendrait : elles verraient sa mémoire.
        let mut budget = self.budget;
        let tables: Option<Vec<InstanceTable>> = md.tables.iter().map(|&t| nouvelle_table(t, &mut budget)).collect();
        let tables = tables.ok_or(ErreurInstanciation::Ressources)?;
        let memoires: Option<Vec<InstanceMemoire>> =
            md.memoires.iter().map(|&l| nouvelle_memoire(l, &mut budget)).collect();
        let memoires = memoires.ok_or(ErreurInstanciation::Ressources)?;
        self.budget = budget;

        // Puis les imports, d'abord dans chaque espace d'index.
        let numero = self.instances.len();
        let mut instance = InstanceModule {
            module: module.clone(),
            fonctions: Vec::new(),
            tables: Vec::new(),
            memoires: Vec::new(),
            globales: Vec::new(),
            elements: Vec::new(),
            donnees: Vec::new(),
        };
        for &externe in imports {
            match externe {
                Externe::Fonction(a) => instance.fonctions.push(a),
                Externe::Table(a) => instance.tables.push(a),
                Externe::Memoire(a) => instance.memoires.push(a),
                Externe::Globale(a) => instance.globales.push(a),
            }
        }
        for index in 0..md.fonctions.len() as u32 {
            instance.fonctions.push(self.fonctions.len() as u32);
            self.fonctions.push(InstanceFonction::Wasm { module: module.clone(), instance: numero as u32, index });
        }
        for table in tables {
            instance.tables.push(self.tables.len() as u32);
            self.tables.push(table);
        }
        for memoire in memoires {
            instance.memoires.push(self.memoires.len() as u32);
            self.memoires.push(memoire);
        }
        // L'instance entre dans le magasin dès maintenant : les expressions
        // constantes qui suivent y lisent ses fonctions et ses globales
        // importées (les seules qu'elles ont le droit de lire).
        self.instances.push(instance);
        for g in &md.globales {
            let valeur = self.constante(numero, g.init);
            self.instances[numero].globales.push(self.globales.len() as u32);
            self.globales.push(InstanceGlobale { type_globale: g.type_globale, valeur });
        }
        for segment in &md.elements {
            let references = segment
                .elements
                .iter()
                .map(|e| match *e {
                    Element::Fonction(x) => self.instances[numero].fonctions[x as usize] as u64 + 1,
                    Element::Expression(plage) => self.constante(numero, plage),
                })
                .collect();
            self.instances[numero].elements.push(self.elements.len() as u32);
            self.elements.push(InstanceElements { references });
        }
        for segment in &md.donnees {
            self.instances[numero].donnees.push(self.donnees.len() as u32);
            self.donnees.push(InstanceDonnees { module: module.clone(), plage: segment.octets });
        }

        // 3. L'initialisation, puis l'appel du démarrage, que l'appelant
        // exécutera.
        let piege = ErreurInstanciation::Piege;
        for (x, segment) in md.elements.iter().enumerate() {
            let adresse = self.instances[numero].elements[x] as usize;
            match segment.mode {
                ModeSegment::Actif { index, decalage } => {
                    let d = self.constante(numero, decalage) as u32 as usize;
                    let table = self.instances[numero].tables[index as usize] as usize;
                    let source = &self.elements[adresse].references;
                    let elements = &mut self.tables[table].elements;
                    if d as u64 + source.len() as u64 > elements.len() as u64 {
                        return Err(piege(Piege::AccesTableHorsLimites));
                    }
                    elements[d..d + source.len()].copy_from_slice(source);
                    self.elements[adresse].references = Vec::new();
                }
                // Un segment déclaratif ne sert qu'à la validation (ref.func).
                ModeSegment::Declaratif => self.elements[adresse].references = Vec::new(),
                ModeSegment::Passif => {}
            }
        }
        for (x, segment) in md.donnees.iter().enumerate() {
            if let ModeSegment::Actif { index, decalage } = segment.mode {
                let d = self.constante(numero, decalage) as u32 as usize;
                let adresse = self.instances[numero].donnees[x] as usize;
                let memoire = self.instances[numero].memoires[index as usize] as usize;
                let source = self.donnees[adresse].octets();
                let octets = &mut self.memoires[memoire].octets;
                if d as u64 + source.len() as u64 > octets.len() as u64 {
                    return Err(piege(Piege::AccesMemoireHorsLimites));
                }
                octets[d..d + source.len()].copy_from_slice(source);
                self.donnees[adresse].plage = Plage { debut: 0, fin: 0 };
            }
        }
        let demarrage = md.demarrage.map(|x| {
            let f = self.instances[numero].fonctions[x as usize];
            // Sans argument : la validation a vérifié son type, [] -> [].
            self.preparer(f, &[]).expect("type de demarrage valide")
        });
        Ok(Instanciation { instance: numero as u32, demarrage })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::{TypeGlobale, TypeValeur};
    use alloc::vec;

    struct SansHote;
    impl Hote for SansHote {
        fn appeler(&mut self, _: u32, _: &[Valeur], _: &mut [Valeur], _: Option<&mut [u8]>, _: &mut u64) -> Result<(), Piege> {
            unreachable!("les modules n'importent rien")
        }
    }

    fn valide(octets: &[u8]) -> Arc<ModuleValide> {
        Arc::new(crate::decoder(octets).and_then(crate::valider).unwrap())
    }

    /// (module (memory 20000) (func (export "f") (result i32) (i32.const 7)))
    /// 20 000 pages : au-delà de PAGES_MEMOIRE_MAX.
    const TROP_GRAND: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x02, 0x01,
        0x00, 0x05, 0x05, 0x01, 0x00, 0xa0, 0x9c, 0x01, 0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00, 0x0a, 0x06, 0x01,
        0x04, 0x00, 0x41, 0x07, 0x0b,
    ];

    /// (module (memory 1) (data (i32.const 0) "\2a")
    ///   (func (export "f") (result i32) (i32.load (i32.const 0))))
    const LECTEUR: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x02, 0x01,
        0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00,
        0x41, 0x00, 0x28, 0x02, 0x00, 0x0b, 0x0b, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x2a,
    ];

    #[test]
    fn un_echec_ne_laisse_rien_dans_le_magasin() {
        let mut m = Magasin::new();
        let erreur = m.instancier(valide(TROP_GRAND), &[]).map(|i| i.instance);
        assert_eq!(erreur, Err(ErreurInstanciation::Ressources));
        // Ni fonction, ni instance : la fonction de TROP_GRAND ne doit pas
        // se retrouver attachée à l'instance suivante.
        assert!(m.fonctions.is_empty() && m.instances.is_empty() && m.memoires.is_empty());
        let n = m.instancier(valide(LECTEUR), &[]).unwrap().instance;
        assert_eq!(m.fonctions.len(), 1);
        let Some(Externe::Fonction(f)) = m.exporte(n, "f") else { panic!("export f") };
        assert_eq!(m.invoquer(&mut SansHote, f, &[]), Ok(vec![Valeur::I32(42)]));
    }

    #[test]
    fn budget_du_magasin() {
        // (module (table 200000 funcref)) : 1,6 Mo de références.
        let tables = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x04, 0x06, 0x01, 0x70, 0x00, 0xc0, 0x9a, 0x0c];
        let mut m = Magasin::avec_budget(1 << 20);
        let erreur = m.instancier(valide(&tables), &[]).map(|i| i.instance);
        assert_eq!(erreur, Err(ErreurInstanciation::Ressources));
        assert_eq!(m.budget, 1 << 20);
        // (module (memory 0) (func (export "f") (param i32) (result i32)
        //   (memory.grow (local.get 0)))), avec un budget de deux pages.
        let grandir = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x03, 0x02,
            0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x00, 0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00, 0x0a, 0x08, 0x01, 0x06,
            0x00, 0x20, 0x00, 0x40, 0x00, 0x0b,
        ];
        let mut m = Magasin::avec_budget(2 * PAGE);
        let n = m.instancier(valide(&grandir), &[]).unwrap().instance;
        let Some(Externe::Fonction(f)) = m.exporte(n, "f") else { panic!("export f") };
        let mut grandir = |pages| m.invoquer(&mut SansHote, f, &[Valeur::I32(pages)]);
        assert_eq!(grandir(3), Ok(vec![Valeur::I32(u32::MAX)])); // -1 : au-delà du budget
        assert_eq!(grandir(2), Ok(vec![Valeur::I32(0)]));
        assert_eq!(grandir(1), Ok(vec![Valeur::I32(u32::MAX)]));
    }

    #[test]
    fn globale_de_l_hote_verifiee() {
        let mut m = Magasin::new();
        let t = TypeGlobale { valeur: TypeValeur::FuncRef, modifiable: false };
        // Une référence vers une fonction qui n'existe pas : refusée.
        assert_eq!(m.ajouter_globale(t, Valeur::FuncRef(Some(1000))), None);
        assert!(m.ajouter_globale(t, Valeur::FuncRef(None)).is_some());
    }
}
