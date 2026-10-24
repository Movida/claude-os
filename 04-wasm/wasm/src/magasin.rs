//! Le magasin (le « store » de la spécification) : tout l'état des
//! programmes WebAssembly en cours, et les valeurs qu'ils échangent avec
//! l'environnement.
//!
//! Un module validé n'est qu'une description. L'instancier crée ses objets
//! dans le magasin : des fonctions, des tables, des mémoires, des globales,
//! des segments d'éléments et de données. Chaque objet y a une ADRESSE, son
//! rang dans la liste de son genre ; une instance de module traduit les
//! index de son code (la fonction 3, la mémoire 0) en adresses. Deux
//! instances partagent ainsi un objet quand l'une importe ce que l'autre
//! exporte : elles ont la même adresse.
//!
//! Le magasin n'oublie rien : une instance devenue inutile y reste. C'est la
//! spécification (elle laisse le ramassage aux implémentations), et c'est
//! sans conséquence ici : le noyau donnera à chaque programme son propre
//! magasin, libéré d'un coup à la fin du programme.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::limites::{BUDGET_MAGASIN, ELEMENTS_TABLE_MAX, PAGES_MEMOIRE_MAX};
use crate::module::{Limites, Plage, TypeFonction, TypeGlobale, TypeTable, TypeValeur};
use crate::validateur::ModuleValide;

/// La taille d'une page de mémoire : 64 Kio.
pub const PAGE: usize = 65536;

/// Une valeur avec son type, telle que l'environnement la donne à une
/// fonction ou la reçoit. Les entiers sont des suites de bits, sans signe :
/// c'est l'instruction (i32.div_s ou i32.div_u) qui décide comment les lire.
/// Les flottants aussi sont gardés en bits (voir flottants.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Valeur {
    I32(u32),
    I64(u64),
    F32(u32),
    F64(u64),
    /// Une fonction du magasin (son adresse), ou la référence nulle.
    FuncRef(Option<u32>),
    /// Une référence de l'environnement, opaque pour le programme (un
    /// fichier ouvert, par exemple), ou la référence nulle.
    ExternRef(Option<u32>),
}

impl Valeur {
    pub fn type_valeur(self) -> TypeValeur {
        match self {
            Valeur::I32(_) => TypeValeur::I32,
            Valeur::I64(_) => TypeValeur::I64,
            Valeur::F32(_) => TypeValeur::F32,
            Valeur::F64(_) => TypeValeur::F64,
            Valeur::FuncRef(_) => TypeValeur::FuncRef,
            Valeur::ExternRef(_) => TypeValeur::ExternRef,
        }
    }

    /// La valeur par défaut d'un type : zéro, ou la référence nulle.
    pub fn defaut(t: TypeValeur) -> Valeur {
        Valeur::depuis_case(t, 0)
    }

    /// La valeur dans une case de la pile de l'interpréteur : 64 bits sans
    /// type. Un i32 y est complété par des zéros ; une référence y vaut son
    /// adresse + 1, et 0 est la référence nulle.
    pub(crate) fn en_case(self) -> u64 {
        match self {
            Valeur::I32(x) | Valeur::F32(x) => x as u64,
            Valeur::I64(x) | Valeur::F64(x) => x,
            Valeur::FuncRef(r) | Valeur::ExternRef(r) => r.map_or(0, |a| a as u64 + 1),
        }
    }

    /// L'inverse : le type vient de la validation ou de la déclaration de
    /// la fonction, puisque la case n'en garde pas.
    pub(crate) fn depuis_case(t: TypeValeur, case: u64) -> Valeur {
        let reference = (case != 0).then(|| (case - 1) as u32);
        match t {
            TypeValeur::I32 => Valeur::I32(case as u32),
            TypeValeur::I64 => Valeur::I64(case),
            TypeValeur::F32 => Valeur::F32(case as u32),
            TypeValeur::F64 => Valeur::F64(case),
            TypeValeur::FuncRef => Valeur::FuncRef(reference),
            TypeValeur::ExternRef => Valeur::ExternRef(reference),
        }
    }
}

/// Un piège (« trap ») : l'exécution s'arrête net, sur une erreur que la
/// spécification définit. Le programme ne peut pas le rattraper ; c'est à
/// l'environnement (le noyau) de décider de la suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Piege {
    /// L'instruction `unreachable`.
    Inatteignable,
    /// Un accès en dehors de la mémoire linéaire.
    AccesMemoireHorsLimites,
    /// Un accès en dehors d'une table, ou d'un segment d'éléments.
    AccesTableHorsLimites,
    /// call_indirect : l'index dépasse la taille de la table.
    ElementIndefini,
    /// call_indirect : la case de la table contient la référence nulle.
    ElementNonInitialise,
    /// call_indirect : la fonction trouvée n'a pas le type attendu.
    TypeDAppelIndirect,
    DivisionParZero,
    /// Un résultat qui ne tient pas dans son type (i32.div_s de -2^31 par
    /// -1, conversion d'un flottant trop grand en entier).
    DebordementEntier,
    /// La conversion d'un NaN en entier.
    ConversionInvalide,
    /// Plus de place sur la pile des valeurs ou des appels (voir
    /// limites.rs).
    PileEpuisee,
    /// L'environnement a donné ou rendu des valeurs d'un autre type que
    /// celui de la fonction (une erreur de l'hôte, pas du programme).
    ValeursIncoherentes,
    /// Une fonction de l'hôte a arrêté l'exécution, avec ce code (la sortie
    /// du programme, par exemple).
    Hote(u32),
}

impl fmt::Display for Piege {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Piege::Inatteignable => write!(f, "instruction unreachable atteinte"),
            Piege::AccesMemoireHorsLimites => write!(f, "acces memoire hors limites"),
            Piege::AccesTableHorsLimites => write!(f, "acces a une table hors limites"),
            Piege::ElementIndefini => write!(f, "appel indirect : element hors de la table"),
            Piege::ElementNonInitialise => write!(f, "appel indirect : element nul"),
            Piege::TypeDAppelIndirect => write!(f, "appel indirect : type de fonction different"),
            Piege::DivisionParZero => write!(f, "division entiere par zero"),
            Piege::DebordementEntier => write!(f, "debordement entier"),
            Piege::ConversionInvalide => write!(f, "conversion d'un NaN en entier"),
            Piege::PileEpuisee => write!(f, "pile epuisee"),
            Piege::ValeursIncoherentes => write!(f, "valeurs de l'hote d'un type inattendu"),
            Piege::Hote(code) => write!(f, "arret demande par l'hote (code {code})"),
        }
    }
}

/// Un objet du magasin, désigné par son genre et son adresse : ce qu'un
/// module exporte, ou ce qu'on lui donne pour ses imports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Externe {
    Fonction(u32),
    Table(u32),
    Memoire(u32),
    Globale(u32),
}

/// Les fonctions que l'environnement fournit aux modules (le noyau, avec
/// WASI ; le banc d'essai, avec le module « spectest »).
///
/// L'interpréteur ne garde pas de pointeur vers du code de l'hôte : une
/// fonction hôte n'est, dans le magasin, qu'un type et un numéro, et
/// l'interpréteur passe le numéro à `appeler`. C'est plus simple que des
/// fermetures rangées dans le magasin (leur durée de vie, leur partage), et
/// l'hôte reste maître de son propre état.
pub trait Hote {
    /// Exécute la fonction hôte `numero`. `arguments` ont les types de ses
    /// paramètres ; `resultats` arrive rempli des valeurs par défaut des
    /// types de ses résultats, que l'hôte remplace. `memoire` : la mémoire
    /// du module appelant, s'il en a une (WASI y lit et y écrit).
    fn appeler(
        &mut self,
        numero: u32,
        arguments: &[Valeur],
        resultats: &mut [Valeur],
        memoire: Option<&mut [u8]>,
    ) -> Result<(), Piege>;
}

/// Une fonction du magasin.
pub(crate) enum InstanceFonction {
    /// Une fonction d'un module : sa `index`-ième fonction définie, dans
    /// l'instance `instance`.
    Wasm { module: Arc<ModuleValide>, instance: u32, index: u32 },
    Hote { type_fonction: TypeFonction, numero: u32 },
}

impl InstanceFonction {
    pub(crate) fn type_fonction(&self) -> &TypeFonction {
        match self {
            InstanceFonction::Wasm { module, index, .. } => {
                let m = module.module();
                &m.types[m.fonctions[*index as usize] as usize]
            }
            InstanceFonction::Hote { type_fonction, .. } => type_fonction,
        }
    }
}

pub(crate) struct InstanceTable {
    pub element: TypeValeur,
    pub max: Option<u32>,
    /// Les références, en cases (0 = nulle).
    pub elements: Vec<u64>,
}

impl InstanceTable {
    /// Ajoute `n` éléments valant `valeur`, pris sur `budget` (voir
    /// `Magasin`) ; rend l'ancienne taille, ou None si la table ne peut pas
    /// grandir autant (maximum déclaré, notre limite, budget ou mémoire de
    /// la machine épuisés). Le budget n'est entamé qu'en cas de succès.
    pub(crate) fn grandir(&mut self, n: u32, valeur: u64, budget: &mut usize) -> Option<u32> {
        let ancienne = self.elements.len() as u32;
        let nouvelle = ancienne.checked_add(n)?;
        let octets = n as usize * size_of::<u64>();
        if nouvelle > self.max.unwrap_or(u32::MAX).min(ELEMENTS_TABLE_MAX) || octets > *budget {
            return None;
        }
        self.elements.try_reserve_exact(n as usize).ok()?;
        self.elements.resize(nouvelle as usize, valeur);
        *budget -= octets;
        Some(ancienne)
    }
}

/// Une mémoire linéaire : un tableau d'octets, dont chaque accès vérifie
/// les bornes (voir interpreteur.rs). À terme, avec un compilateur, on
/// réservera 4 Gio d'adresses virtuelles suivies de pages de garde, comme
/// wasmtime : une adresse i32 ne peut pas en sortir, et le contrôle des
/// bornes disparaît du code, remplacé par la faute de page.
pub(crate) struct InstanceMemoire {
    pub max: Option<u32>,
    pub octets: Vec<u8>,
}

impl InstanceMemoire {
    pub(crate) fn pages(&self) -> u32 {
        (self.octets.len() / PAGE) as u32
    }

    /// Ajoute `n` pages mises à zéro, prises sur `budget` ; rend
    /// l'ancienne taille en pages, ou None (memory.grow rendra alors -1).
    pub(crate) fn grandir(&mut self, n: u32, budget: &mut usize) -> Option<u32> {
        let anciennes = self.pages();
        let nouvelles = anciennes.checked_add(n)?;
        let octets = n as usize * PAGE;
        if nouvelles > self.max.unwrap_or(u32::MAX).min(PAGES_MEMOIRE_MAX) || octets > *budget {
            return None;
        }
        // try_reserve plutôt qu'un simple resize : si la mémoire de la
        // machine manque, memory.grow échoue proprement au lieu d'arrêter
        // le noyau.
        self.octets.try_reserve_exact(octets).ok()?;
        self.octets.resize(nouvelles as usize * PAGE, 0);
        *budget -= octets;
        Some(anciennes)
    }
}

pub(crate) struct InstanceGlobale {
    pub type_globale: TypeGlobale,
    pub valeur: u64,
}

/// Un segment d'éléments : ses références, calculées à l'instanciation.
/// `elem.drop` le vide.
pub(crate) struct InstanceElements {
    pub references: Vec<u64>,
}

/// Un segment de données : ses octets restent dans le module, qu'on
/// partage sans recopier. `data.drop` vide la plage.
pub(crate) struct InstanceDonnees {
    pub module: Arc<ModuleValide>,
    pub plage: Plage,
}

impl InstanceDonnees {
    pub(crate) fn octets(&self) -> &[u8] {
        self.module.module().tranche(self.plage)
    }
}

/// Une instance de module : pour chaque espace d'index, l'adresse dans le
/// magasin de chaque objet (imports d'abord, comme dans le module).
pub(crate) struct InstanceModule {
    pub module: Arc<ModuleValide>,
    pub fonctions: Vec<u32>,
    pub tables: Vec<u32>,
    pub memoires: Vec<u32>,
    pub globales: Vec<u32>,
    pub elements: Vec<u32>,
    pub donnees: Vec<u32>,
}

/// Le magasin. Ses listes ne sont accessibles qu'à la bibliothèque :
/// l'environnement passe par les adresses, et les méthodes ci-dessous.
pub struct Magasin {
    pub(crate) fonctions: Vec<InstanceFonction>,
    pub(crate) tables: Vec<InstanceTable>,
    pub(crate) memoires: Vec<InstanceMemoire>,
    pub(crate) globales: Vec<InstanceGlobale>,
    pub(crate) elements: Vec<InstanceElements>,
    pub(crate) donnees: Vec<InstanceDonnees>,
    pub(crate) instances: Vec<InstanceModule>,
    /// Les octets que les tables et les mémoires peuvent encore prendre
    /// (voir limites.rs, BUDGET_MAGASIN).
    pub(crate) budget: usize,
}

impl Default for Magasin {
    fn default() -> Self {
        Magasin::avec_budget(BUDGET_MAGASIN)
    }
}

impl Magasin {
    pub fn new() -> Self {
        Magasin::default()
    }

    /// Un magasin dont les tables et les mémoires, ensemble, ne prendront
    /// jamais plus de `octets`.
    pub fn avec_budget(octets: usize) -> Self {
        Magasin {
            fonctions: Vec::new(),
            tables: Vec::new(),
            memoires: Vec::new(),
            globales: Vec::new(),
            elements: Vec::new(),
            donnees: Vec::new(),
            instances: Vec::new(),
            budget: octets,
        }
    }

    /// Une fonction de l'hôte (voir `Hote`), à donner en import.
    pub fn ajouter_fonction_hote(&mut self, type_fonction: TypeFonction, numero: u32) -> Externe {
        self.fonctions.push(InstanceFonction::Hote { type_fonction, numero });
        Externe::Fonction(self.fonctions.len() as u32 - 1)
    }

    /// Une table vide (pleine de références nulles), créée par l'hôte, ou
    /// None si elle dépasse nos limites ou la mémoire disponible.
    pub fn ajouter_table(&mut self, type_table: TypeTable) -> Option<Externe> {
        let table = nouvelle_table(type_table, &mut self.budget)?;
        self.tables.push(table);
        Some(Externe::Table(self.tables.len() as u32 - 1))
    }

    /// Une mémoire mise à zéro, créée par l'hôte, ou None (voir
    /// `ajouter_table`).
    pub fn ajouter_memoire(&mut self, limites: Limites) -> Option<Externe> {
        let memoire = nouvelle_memoire(limites, &mut self.budget)?;
        self.memoires.push(memoire);
        Some(Externe::Memoire(self.memoires.len() as u32 - 1))
    }

    /// Une globale, ou None si la valeur n'a pas le type annoncé (ou
    /// désigne une fonction qui n'existe pas : voir `valeur_acceptable`).
    pub fn ajouter_globale(&mut self, type_globale: TypeGlobale, valeur: Valeur) -> Option<Externe> {
        if !self.valeur_acceptable(valeur, type_globale.valeur) {
            return None;
        }
        self.globales.push(InstanceGlobale { type_globale, valeur: valeur.en_case() });
        Some(Externe::Globale(self.globales.len() as u32 - 1))
    }

    /// Ce que l'instance `instance` exporte sous le nom `nom`.
    pub fn exporte(&self, instance: u32, nom: &str) -> Option<Externe> {
        let i = self.instances.get(instance as usize)?;
        let export = i.module.module().exports.iter().find(|e| e.nom == nom)?;
        use crate::module::DescriptionExport as D;
        Some(match export.description {
            D::Fonction(x) => Externe::Fonction(i.fonctions[x as usize]),
            D::Table(x) => Externe::Table(i.tables[x as usize]),
            D::Memoire(x) => Externe::Memoire(i.memoires[x as usize]),
            D::Globale(x) => Externe::Globale(i.globales[x as usize]),
        })
    }

    /// La valeur actuelle d'une globale.
    pub fn valeur_globale(&self, globale: u32) -> Option<Valeur> {
        let g = self.globales.get(globale as usize)?;
        Some(Valeur::depuis_case(g.type_globale.valeur, g.valeur))
    }

    /// Les octets d'une mémoire, pour l'hôte (charger un programme, lire ce
    /// qu'il a écrit).
    pub fn memoire(&mut self, memoire: u32) -> Option<&mut [u8]> {
        self.memoires.get_mut(memoire as usize).map(|m| &mut m.octets[..])
    }
}

/// Une table de `type_table.limites.min` références nulles, si nos limites,
/// le budget et la mémoire de la machine le permettent.
pub(crate) fn nouvelle_table(type_table: TypeTable, budget: &mut usize) -> Option<InstanceTable> {
    let mut table = InstanceTable { element: type_table.element, max: type_table.limites.max, elements: Vec::new() };
    table.grandir(type_table.limites.min, 0, budget)?;
    Some(table)
}

pub(crate) fn nouvelle_memoire(limites: Limites, budget: &mut usize) -> Option<InstanceMemoire> {
    let mut memoire = InstanceMemoire { max: limites.max, octets: Vec::new() };
    memoire.grandir(limites.min, budget)?;
    Some(memoire)
}
