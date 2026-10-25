//! L'interpréteur : exécute le code des fonctions, sur place.
//!
//! Trois choix le structurent.
//!
//! 1. Les octets du code sont lus tels quels (« interprétation sur
//!    place ») : `lire_instruction`, le lecteur du décodeur, décode chaque
//!    instruction au moment de l'exécuter, et la table annexe calculée par
//!    le validateur donne la cible des branchements (voir `Branchement`).
//!
//! 2. La pile des valeurs est faite de cases de 64 bits SANS type (voir
//!    numerique.rs). Un interpréteur qui vérifierait les types à chaque
//!    instruction referait le travail du validateur, à chaque exécution.
//!
//! 3. L'interpréteur n'est pas récursif. Un appel WebAssembly n'appelle
//!    pas de fonction Rust : il empile un `Cadre` (la fonction, la base de
//!    ses variables locales, où reprendre) dans un Vec, sur le tas, et la
//!    boucle principale continue au cadre du sommet. Une récursion
//!    WebAssembly, même profonde, ne consomme donc jamais la pile du
//!    noyau, qui est petite et dont le débordement serait fatal ; sa
//!    profondeur est bornée par nos limites (le piège « pile épuisée »).
//!    Et tout l'état d'une exécution tient dans deux Vec : on peut
//!    l'interrompre, puis la reprendre (voir `Execution::reprendre`).
//!    Option écartée : un interpréteur qui s'appelle lui-même à chaque
//!    appel WebAssembly, plus court à écrire, mais lié à la pile du noyau,
//!    et qu'on ne peut pas arrêter au milieu sans perdre son état.
//!
//! Les variables locales d'une fonction vivent dans la pile des valeurs,
//! au début de son cadre : l'appelant y a empilé les arguments, qui
//! deviennent les premières locales sans être recopiés ; les autres sont
//! mises à zéro. Ensuite viennent les opérandes. Au retour, on recopie les
//! résultats à la place des arguments.
//!
//! Défense en profondeur : l'interpréteur ne vérifie ni les types, ni que
//! la pile contient assez d'opérandes, puisque la validation le garantit.
//! Si le validateur avait malgré tout un défaut, Rust (sans `unsafe`)
//! transformerait l'accès fautif en panique, jamais en lecture hors
//! limites : au pire on perd la disponibilité, jamais l'isolation.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::instructions::{Acces as GenreAcces, Instruction, lire_instruction};
use crate::lecteur::Lecteur;
use crate::limites::{APPELS_MAX, PILE_VALEURS_MAX};
use crate::magasin::*;
use crate::module::{Plage, TypeValeur};
use crate::numerique::operation;
use crate::validateur::Branchement;

const VALIDE: &str = "garanti par la validation";

/// Un appel en cours d'une fonction WebAssembly.
#[derive(Clone, Copy)]
struct Cadre {
    /// L'adresse de la fonction dans le magasin.
    fonction: u32,
    /// L'index, dans la pile des valeurs, de sa variable locale 0.
    base: usize,
    /// Où reprendre (position dans le module, entrée de la table annexe),
    /// quand ce cadre n'est pas celui qui s'exécute : il a appelé une autre
    /// fonction.
    ip: usize,
    stp: usize,
}

/// Une exécution : l'appel d'une fonction, avec tout ce qu'il a lui-même
/// appelé, et qu'on peut interrompre puis reprendre.
///
/// C'est la base de la préemption. Un programme WebAssembly peut boucler
/// sans fin ; le noyau ne doit pas pour autant lui céder le processeur pour
/// toujours. `reprendre` exécute au plus un nombre donné d'instructions, le
/// « carburant », puis rend la main : l'état de l'exécution (ses deux
/// piles, où reprendre chaque appel) reste dans l'`Execution`, et un
/// nouvel appel à `reprendre` continue exactement au même point. Entre les
/// deux, le noyau peut faire tourner autre chose. (C'est l'idée du
/// carburant de wasmtime ; un interrupteur matériel, l'horloge, qui arrête
/// un programme n'importe où, viendra avec du code compilé.)
///
/// Une instruction coûte une unité, plus une par 256 octets qu'elle touche
/// (memory.fill, la mise à zéro des locales d'un appel...) : le carburant
/// mesure à peu près le temps. Une instruction ne peut pas s'arrêter au
/// milieu (un memory.fill fait à moitié changerait sa sémantique) : si la
/// tranche n'y suffit pas, elle se fait quand même, et le reste devient une
/// dette, payée au début des tranches suivantes. Le total consommé reste
/// exact, et un programme qui a beaucoup travaillé attend son tour.
pub struct Execution {
    pile: Vec<u64>,
    cadres: Vec<Cadre>,
    /// La fonction appelée, tant que l'appel n'a pas commencé.
    a_appeler: Option<u32>,
    /// Les types de ses résultats.
    resultats: Box<[TypeValeur]>,
    /// Le carburant dû par les instructions déjà faites.
    dette: u64,
    /// Le piège qui a arrêté l'exécution, s'il y en a eu un : elle est
    /// alors finie, et chaque reprise le rend à nouveau.
    piege: Option<Piege>,
}

/// Le carburant de plus qu'une instruction doit pour `octets` touchés.
fn cout(octets: u64) -> u64 {
    octets / 256
}

/// Où en est une exécution après `reprendre`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Etat {
    /// La fonction a retourné ces résultats.
    Terminee(Vec<Valeur>),
    /// Le carburant est épuisé : `reprendre` continuera.
    Interrompue,
}

impl Magasin {
    /// Prépare l'appel de la fonction d'adresse `fonction` avec
    /// `arguments`, sans rien exécuter encore.
    pub fn preparer(&self, fonction: u32, arguments: &[Valeur]) -> Result<Execution, Piege> {
        let f = self.fonctions.get(fonction as usize).ok_or(Piege::ValeursIncoherentes)?;
        let t = f.type_fonction();
        if arguments.len() != t.parametres.len()
            || arguments.iter().zip(t.parametres.iter()).any(|(v, &p)| !self.valeur_acceptable(*v, p))
        {
            return Err(Piege::ValeursIncoherentes);
        }
        Ok(Execution {
            pile: arguments.iter().map(|v| v.en_case()).collect(),
            cadres: Vec::new(),
            a_appeler: Some(fonction),
            resultats: t.resultats.clone(),
            dette: 0,
            piege: None,
        })
    }

    /// Appelle la fonction d'adresse `fonction` avec `arguments`, jusqu'au
    /// bout, et rend ses résultats, ou le piège qui l'a arrêtée.
    pub fn invoquer(&mut self, hote: &mut dyn Hote, fonction: u32, arguments: &[Valeur]) -> Result<Vec<Valeur>, Piege> {
        let mut e = self.preparer(fonction, arguments)?;
        // 2^64 instructions : des siècles, autant dire sans limite.
        let mut carburant = u64::MAX;
        loop {
            if let Etat::Terminee(resultats) = e.reprendre(self, hote, &mut carburant)? {
                return Ok(resultats);
            }
        }
    }

    /// Une valeur venue de l'environnement a-t-elle le type attendu, et,
    /// si c'est une fonction, désigne-t-elle une fonction qui existe ? (Une
    /// référence inventée, rangée dans une table puis appelée, ferait
    /// sinon paniquer l'interpréteur.)
    pub(crate) fn valeur_acceptable(&self, v: Valeur, t: TypeValeur) -> bool {
        v.type_valeur() == t && !matches!(v, Valeur::FuncRef(Some(a)) if a as usize >= self.fonctions.len())
    }
}

/// `debut + n` ne dépasse pas `longueur` (en 64 bits : la somme de deux u32
/// peut déborder d'un u32).
fn dans(debut: u32, n: u32, longueur: usize) -> bool {
    debut as u64 + n as u64 <= longueur as u64
}

/// L'adresse effective d'un accès mémoire de `taille` octets : l'adresse
/// dépilée (un i32, sans signe) plus le décalage de l'instruction. On la
/// calcule sur 64 bits : la somme de deux u32 ne déborde pas, et un accès
/// juste après la fin de la mémoire est bien refusé.
fn effective(adresse: u64, decalage: u32, taille: usize, longueur: usize) -> Result<usize, Piege> {
    let a = adresse as u32 as u64 + decalage as u64;
    if a + taille as u64 > longueur as u64 {
        return Err(Piege::AccesMemoireHorsLimites);
    }
    Ok(a as usize)
}

/// Prend un branchement : garde les `gardees` valeurs du sommet de la pile
/// et retire les `retirees` d'en dessous. Rend où continuer : la position
/// dans le module et l'entrée suivante de la table annexe.
fn brancher(pile: &mut Vec<u64>, b: Branchement) -> (usize, usize) {
    if b.retirees > 0 {
        let haut = pile.len();
        let (g, r) = (b.gardees as usize, b.retirees as usize);
        pile.copy_within(haut - g..haut, haut - g - r);
        pile.truncate(haut - r);
    }
    (b.cible as usize, b.suite as usize)
}

/// Deux tables distinctes du magasin, l'une à modifier (pour table.copy).
fn deux_tables(tables: &mut [InstanceTable], destination: usize, source: usize) -> (&mut InstanceTable, &InstanceTable) {
    if destination < source {
        let (gauche, droite) = tables.split_at_mut(source);
        (&mut gauche[destination], &droite[0])
    } else {
        let (gauche, droite) = tables.split_at_mut(destination);
        (&mut droite[0], &gauche[source])
    }
}

impl Execution {
    /// Continue l'exécution, avec au plus `*carburant` unités de carburant ;
    /// le carburant restant y est noté (l'hôte sait ainsi ce que le
    /// programme a consommé). Après un piège, l'exécution est finie, et
    /// chaque reprise rend le même piège.
    pub fn reprendre(&mut self, m: &mut Magasin, hote: &mut dyn Hote, carburant: &mut u64) -> Result<Etat, Piege> {
        if let Some(p) = self.piege {
            return Err(p);
        }
        let etat = self.continuer(m, hote, carburant);
        if let Err(p) = etat {
            self.piege = Some(p);
        }
        etat
    }

    fn continuer(&mut self, m: &mut Magasin, hote: &mut dyn Hote, carburant: &mut u64) -> Result<Etat, Piege> {
        if let Some(f) = self.a_appeler.take() {
            self.appeler(m, hote, f, None)?;
        }
        let fini = self.executer(m, hote, carburant)?;
        // Ce que la dernière instruction devait encore : tant qu'il en
        // reste, le résultat attend la reprise suivante.
        self.payer(carburant);
        if !fini || self.dette > 0 {
            return Ok(Etat::Interrompue);
        }
        let resultats = self.resultats.iter().zip(&self.pile).map(|(&t, &c)| Valeur::depuis_case(t, c)).collect();
        Ok(Etat::Terminee(resultats))
    }

    /// Paie la dette avec ce qu'il reste de carburant.
    fn payer(&mut self, carburant: &mut u64) {
        let paye = self.dette.min(*carburant);
        self.dette -= paye;
        *carburant -= paye;
    }

    fn depiler(&mut self) -> u64 {
        self.pile.pop().expect(VALIDE)
    }

    fn depiler32(&mut self) -> u32 {
        self.depiler() as u32
    }

    fn sommet(&mut self) -> &mut u64 {
        self.pile.last_mut().expect(VALIDE)
    }

    /// Note où reprendre le cadre du sommet, qui va appeler une fonction.
    fn noter(&mut self, ip: usize, stp: usize) {
        let cadre = self.cadres.last_mut().expect(VALIDE);
        cadre.ip = ip;
        cadre.stp = stp;
    }

    /// Appelle la fonction d'adresse `f`, dont les arguments sont au sommet
    /// de la pile. Une fonction de l'hôte s'exécute tout de suite. Pour une
    /// fonction WebAssembly, on empile son cadre, et la boucle de `executer`
    /// continuera dans son code : on rend alors vrai. `memoire` : celle de
    /// l'appelant, que l'hôte peut lire.
    fn appeler(&mut self, m: &mut Magasin, hote: &mut dyn Hote, f: u32, memoire: Option<u32>) -> Result<bool, Piege> {
        match &m.fonctions[f as usize] {
            InstanceFonction::Hote { type_fonction, numero } => {
                let debut = self.pile.len() - type_fonction.parametres.len();
                let arguments: Vec<Valeur> = type_fonction
                    .parametres
                    .iter()
                    .zip(&self.pile[debut..])
                    .map(|(&t, &case)| Valeur::depuis_case(t, case))
                    .collect();
                let mut resultats: Vec<Valeur> = type_fonction.resultats.iter().map(|&t| Valeur::defaut(t)).collect();
                self.pile.truncate(debut);
                let memoire = memoire.map(|a| &mut m.memoires[a as usize].octets[..]);
                // Le travail de l'hôte s'ajoute à la dette (voir Execution).
                hote.appeler(*numero, &arguments, &mut resultats, memoire, &mut self.dette)?;
                // L'hôte n'est pas validé : on vérifie ce qu'il rend.
                for (&v, &t) in resultats.iter().zip(type_fonction.resultats.iter()) {
                    if v.type_valeur() != t || matches!(v, Valeur::FuncRef(Some(a)) if a as usize >= m.fonctions.len()) {
                        return Err(Piege::ValeursIncoherentes);
                    }
                    self.pile.push(v.en_case());
                }
                Ok(false)
            }
            InstanceFonction::Wasm { module, index, .. } => {
                let code = module.code(*index as usize);
                let debut_code = module.module().corps[*index as usize].code.debut as usize;
                let base = self.pile.len() - m.fonctions[f as usize].type_fonction().parametres.len();
                // La place qu'il faudra au plus : on la vérifie une fois,
                // ici, et aucun empilement ne la dépassera (hauteur_max).
                let locales = self.pile.len() + code.locales as usize;
                if self.cadres.len() >= APPELS_MAX || locales + code.hauteur_max as usize > PILE_VALEURS_MAX {
                    return Err(Piege::PileEpuisee);
                }
                self.dette += cout(code.locales as u64 * 8);
                self.pile.resize(locales, 0);
                self.pile.reserve(code.hauteur_max as usize);
                self.cadres.push(Cadre { fonction: f, base, ip: debut_code, stp: 0 });
                Ok(true)
            }
        }
    }

    /// Retourne de la fonction du sommet : ses `n` résultats, au sommet de
    /// la pile, prennent la place de ses variables locales.
    fn retourner(&mut self, base: usize, n: usize) {
        let haut = self.pile.len();
        self.pile.copy_within(haut - n..haut, base);
        self.pile.truncate(base + n);
        self.cadres.pop();
    }

    /// Exécute jusqu'à ce que la pile des appels soit vide (rend vrai), ou
    /// que le carburant soit épuisé (rend faux).
    fn executer(&mut self, m: &mut Magasin, hote: &mut dyn Hote, carburant: &mut u64) -> Result<bool, Piege> {
        use Instruction::*;
        // À chaque changement de cadre (appel, retour), on prépare de quoi
        // exécuter le code de celui du sommet.
        'cadres: while let Some(&cadre) = self.cadres.last() {
            let (module, instance, index) = match &m.fonctions[cadre.fonction as usize] {
                InstanceFonction::Wasm { module, instance, index } => (module.clone(), *instance as usize, *index as usize),
                InstanceFonction::Hote { .. } => unreachable!("un cadre est toujours une fonction WebAssembly"),
            };
            let md = module.module();
            let fin = md.corps[index].code.fin as usize;
            let octets = &md.octets[..fin];
            let table = &module.code(index).branchements[..];
            let resultats = md.types[md.fonctions[index] as usize].resultats.len();
            let memoire = m.instances[instance].memoires.first().copied();
            let base = cadre.base;
            let mut stp = cadre.stp;
            // Un lecteur sur tout le module (jusqu'à la fin de la fonction),
            // pour que les positions de la table annexe soient directement
            // les siennes, en avant comme en arrière.
            let mut l = Lecteur::new(octets);
            l.aller(cadre.ip);

            macro_rules! adresse {
                ($espace:ident, $x:expr) => {
                    m.instances[instance].$espace[$x as usize] as usize
                };
            }

            loop {
                // La dette d'abord, puis une unité par instruction. À sec, on
                // note où reprendre, comme pour un appel.
                self.payer(carburant);
                if *carburant == 0 {
                    self.noter(l.position(), stp);
                    return Ok(false);
                }
                *carburant -= 1;
                // br_table : `lire_instruction` relirait toutes ses cibles,
                // pour trouver la fin de l'instruction. Inutile ici : la
                // table annexe dit où aller. On ne lit que leur nombre.
                if octets[l.position()] == 0x0E {
                    l.octet().expect(VALIDE);
                    let nombre = l.u32().expect(VALIDE);
                    let i = self.depiler32().min(nombre);
                    let (cible, suite) = brancher(&mut self.pile, table[stp + i as usize]);
                    l.aller(cible);
                    stp = suite;
                    continue;
                }
                match lire_instruction(&mut l).expect(VALIDE) {
                    // Contrôle
                    Unreachable => return Err(Piege::Inatteignable),
                    Nop | Block(_) | Loop(_) => {}
                    If(_) => {
                        if self.depiler32() == 0 {
                            let (cible, suite) = brancher(&mut self.pile, table[stp]);
                            l.aller(cible);
                            stp = suite;
                        } else {
                            stp += 1;
                        }
                    }
                    Else | Br(_) => {
                        let (cible, suite) = brancher(&mut self.pile, table[stp]);
                        l.aller(cible);
                        stp = suite;
                    }
                    BrIf(_) => {
                        if self.depiler32() != 0 {
                            let (cible, suite) = brancher(&mut self.pile, table[stp]);
                            l.aller(cible);
                            stp = suite;
                        } else {
                            stp += 1;
                        }
                    }
                    BrTable { .. } => unreachable!("traité plus haut"),
                    // Le `end` d'un bloc ne fait rien ; celui qui termine la
                    // fonction, son dernier octet, la fait retourner.
                    End if l.position() == fin => {
                        self.retourner(base, resultats);
                        continue 'cadres;
                    }
                    End => {}
                    Return => {
                        self.retourner(base, resultats);
                        continue 'cadres;
                    }
                    Call(x) => {
                        let f = adresse!(fonctions, x) as u32;
                        self.noter(l.position(), stp);
                        if self.appeler(m, hote, f, memoire)? {
                            continue 'cadres;
                        }
                    }
                    CallIndirect { type_fonction, table: t } => {
                        let i = self.depiler32() as usize;
                        let reference = *m.tables[adresse!(tables, t)].elements.get(i).ok_or(Piege::ElementIndefini)?;
                        if reference == 0 {
                            return Err(Piege::ElementNonInitialise);
                        }
                        let f = (reference - 1) as u32;
                        // Les types se comparent par leur contenu : la
                        // fonction peut venir d'un autre module.
                        if *m.fonctions[f as usize].type_fonction() != md.types[type_fonction as usize] {
                            return Err(Piege::TypeDAppelIndirect);
                        }
                        self.noter(l.position(), stp);
                        if self.appeler(m, hote, f, memoire)? {
                            continue 'cadres;
                        }
                    }

                    // Références
                    RefNull(_) => self.pile.push(0),
                    RefIsNull => {
                        let r = self.sommet();
                        *r = (*r == 0) as u64;
                    }
                    RefFunc(x) => self.pile.push(adresse!(fonctions, x) as u64 + 1),

                    // Paramétriques
                    Drop => {
                        self.depiler();
                    }
                    Select | SelectT { .. } => {
                        let condition = self.depiler32();
                        let b = self.depiler();
                        if condition == 0 {
                            *self.sommet() = b;
                        }
                    }

                    // Variables
                    LocalGet(x) => self.pile.push(self.pile[base + x as usize]),
                    LocalSet(x) => {
                        let v = self.depiler();
                        self.pile[base + x as usize] = v;
                    }
                    LocalTee(x) => {
                        let v = *self.sommet();
                        self.pile[base + x as usize] = v;
                    }
                    GlobalGet(x) => self.pile.push(m.globales[adresse!(globales, x)].valeur),
                    GlobalSet(x) => {
                        let v = self.depiler();
                        m.globales[adresse!(globales, x)].valeur = v;
                    }

                    // Tables
                    TableGet(x) => {
                        let i = self.depiler32() as usize;
                        let v = *m.tables[adresse!(tables, x)].elements.get(i).ok_or(Piege::AccesTableHorsLimites)?;
                        self.pile.push(v);
                    }
                    TableSet(x) => {
                        let v = self.depiler();
                        let i = self.depiler32() as usize;
                        let case = m.tables[adresse!(tables, x)].elements.get_mut(i).ok_or(Piege::AccesTableHorsLimites)?;
                        *case = v;
                    }
                    TableSize(x) => self.pile.push(m.tables[adresse!(tables, x)].elements.len() as u64),
                    TableGrow(x) => {
                        let n = self.depiler32();
                        let v = self.depiler();
                        let ancienne = m.tables[adresse!(tables, x)].grandir(n, v, &mut m.budget);
                        if ancienne.is_some() {
                            self.dette += cout(n as u64 * 8);
                        }
                        self.pile.push(ancienne.unwrap_or(u32::MAX) as u64);
                    }
                    TableFill(x) => {
                        let n = self.depiler32();
                        let v = self.depiler();
                        let i = self.depiler32();
                        let elements = &mut m.tables[adresse!(tables, x)].elements;
                        if !dans(i, n, elements.len()) {
                            return Err(Piege::AccesTableHorsLimites);
                        }
                        elements[i as usize..(i + n) as usize].fill(v);
                        self.dette += cout(n as u64 * 8);
                    }
                    TableCopy { destination, source } => {
                        let n = self.depiler32();
                        let s = self.depiler32();
                        let d = self.depiler32();
                        let (ad, as_) = (adresse!(tables, destination), adresse!(tables, source));
                        let (s, d, n) = (s as usize, d as usize, n as usize);
                        if ad == as_ {
                            let elements = &mut m.tables[ad].elements;
                            if !dans(s as u32, n as u32, elements.len()) || !dans(d as u32, n as u32, elements.len()) {
                                return Err(Piege::AccesTableHorsLimites);
                            }
                            elements.copy_within(s..s + n, d);
                        } else {
                            let (vers, depuis) = deux_tables(&mut m.tables, ad, as_);
                            if !dans(s as u32, n as u32, depuis.elements.len()) || !dans(d as u32, n as u32, vers.elements.len())
                            {
                                return Err(Piege::AccesTableHorsLimites);
                            }
                            vers.elements[d..d + n].copy_from_slice(&depuis.elements[s..s + n]);
                        }
                        self.dette += cout(n as u64 * 8);
                    }
                    TableInit { segment, table: t } => {
                        let n = self.depiler32();
                        let s = self.depiler32();
                        let d = self.depiler32();
                        let source = &m.elements[adresse!(elements, segment)].references;
                        let elements = &mut m.tables[adresse!(tables, t)].elements;
                        if !dans(s, n, source.len()) || !dans(d, n, elements.len()) {
                            return Err(Piege::AccesTableHorsLimites);
                        }
                        let (s, d, n) = (s as usize, d as usize, n as usize);
                        elements[d..d + n].copy_from_slice(&source[s..s + n]);
                        self.dette += cout(n as u64 * 8);
                    }
                    ElemDrop(x) => m.elements[adresse!(elements, x)].references = Vec::new(),

                    // Mémoire
                    Acces(acces, arg) => {
                        let octets_memoire = &mut m.memoires[memoire.expect(VALIDE) as usize].octets;
                        let taille = acces.genre().1 as usize;
                        if acces.est_ecriture() {
                            let v = self.depiler();
                            let a = effective(self.depiler(), arg.offset, taille, octets_memoire.len())?;
                            octets_memoire[a..a + taille].copy_from_slice(&v.to_le_bytes()[..taille]);
                        } else {
                            let a = effective(self.depiler(), arg.offset, taille, octets_memoire.len())?;
                            let mut brut = [0; 8];
                            brut[..taille].copy_from_slice(&octets_memoire[a..a + taille]);
                            let brut = u64::from_le_bytes(brut);
                            // Les lectures plus courtes que la valeur
                            // complètent par des zéros (ce qu'on a fait) ou
                            // par le signe (_s).
                            self.pile.push(match acces {
                                GenreAcces::I32Load8S => brut as u8 as i8 as i32 as u32 as u64,
                                GenreAcces::I32Load16S => brut as u16 as i16 as i32 as u32 as u64,
                                GenreAcces::I64Load8S => brut as u8 as i8 as i64 as u64,
                                GenreAcces::I64Load16S => brut as u16 as i16 as i64 as u64,
                                GenreAcces::I64Load32S => brut as u32 as i32 as i64 as u64,
                                _ => brut,
                            });
                        }
                    }
                    MemorySize => self.pile.push(m.memoires[memoire.expect(VALIDE) as usize].pages() as u64),
                    MemoryGrow => {
                        let n = self.depiler32();
                        let anciennes = m.memoires[memoire.expect(VALIDE) as usize].grandir(n, &mut m.budget);
                        if anciennes.is_some() {
                            self.dette += cout(n as u64 * PAGE as u64);
                        }
                        self.pile.push(anciennes.unwrap_or(u32::MAX) as u64);
                    }
                    MemoryInit(x) => {
                        let n = self.depiler32();
                        let s = self.depiler32();
                        let d = self.depiler32();
                        let source = m.donnees[adresse!(donnees, x)].octets();
                        let octets_memoire = &mut m.memoires[memoire.expect(VALIDE) as usize].octets;
                        if !dans(s, n, source.len()) || !dans(d, n, octets_memoire.len()) {
                            return Err(Piege::AccesMemoireHorsLimites);
                        }
                        let (s, d, n) = (s as usize, d as usize, n as usize);
                        octets_memoire[d..d + n].copy_from_slice(&source[s..s + n]);
                        self.dette += cout(n as u64);
                    }
                    DataDrop(x) => m.donnees[adresse!(donnees, x)].plage = Plage { debut: 0, fin: 0 },
                    MemoryCopy => {
                        let n = self.depiler32();
                        let s = self.depiler32();
                        let d = self.depiler32();
                        let octets_memoire = &mut m.memoires[memoire.expect(VALIDE) as usize].octets;
                        if !dans(s, n, octets_memoire.len()) || !dans(d, n, octets_memoire.len()) {
                            return Err(Piege::AccesMemoireHorsLimites);
                        }
                        let (s, d, n) = (s as usize, d as usize, n as usize);
                        octets_memoire.copy_within(s..s + n, d);
                        self.dette += cout(n as u64);
                    }
                    MemoryFill => {
                        let n = self.depiler32();
                        let v = self.depiler32();
                        let d = self.depiler32();
                        let octets_memoire = &mut m.memoires[memoire.expect(VALIDE) as usize].octets;
                        if !dans(d, n, octets_memoire.len()) {
                            return Err(Piege::AccesMemoireHorsLimites);
                        }
                        octets_memoire[d as usize..(d + n) as usize].fill(v as u8);
                        self.dette += cout(n as u64);
                    }

                    // Constantes et opérations numériques
                    I32Const(v) => self.pile.push(v as u32 as u64),
                    I64Const(v) => self.pile.push(v as u64),
                    F32Const(bits) => self.pile.push(bits as u64),
                    F64Const(bits) => self.pile.push(bits),
                    Op(op) => operation(op, &mut self.pile)?,
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;

    struct SansHote;
    impl Hote for SansHote {
        fn appeler(&mut self, _: u32, _: &[Valeur], _: &mut [Valeur], _: Option<&mut [u8]>, _: &mut u64) -> Result<(), Piege> {
            unreachable!("le module n'importe rien")
        }
    }

    /// Un module qui exporte « f » : f(n) = si n = 0 alors 0 sinon f(n - 1) + 1,
    /// une récursion de profondeur n.
    fn module_recursif() -> Vec<u8> {
        let mut m = b"\0asm\x01\0\0\0".to_vec();
        m.extend_from_slice(&[1, 6, 1, 0x60, 1, 0x7F, 1, 0x7F]); // type (i32) -> (i32)
        m.extend_from_slice(&[3, 2, 1, 0]); // une fonction, de type 0
        m.extend_from_slice(&[7, 5, 1, 1, b'f', 0, 0]); // export « f »
        let code = [
            0x20, 0, 0x45, // local.get 0, i32.eqz
            0x04, 0x7F, 0x41, 0, // if (result i32)  i32.const 0
            0x05, 0x20, 0, 0x41, 1, 0x6B, 0x10, 0, // else  local.get 0, i32.const 1, i32.sub, call 0
            0x41, 1, 0x6A, 0x0B, // i32.const 1, i32.add, end
            0x0B,
        ];
        m.extend_from_slice(&[10, code.len() as u8 + 3, 1, code.len() as u8 + 1, 0]);
        m.extend_from_slice(&code);
        m
    }

    /// Instancie un module et rend son magasin et l'adresse de son export
    /// « f ».
    fn instancier(octets: &[u8]) -> (Magasin, u32) {
        let module = crate::decoder(octets).and_then(crate::valider).unwrap();
        let mut m = Magasin::new();
        let instance = m.instancier(Arc::new(module), &[]).unwrap().instance;
        let Some(Externe::Fonction(f)) = m.exporte(instance, "f") else { panic!("export f") };
        (m, f)
    }

    #[test]
    fn interrompre_puis_reprendre() {
        let (mut m, f) = instancier(&module_recursif());
        let arguments = [Valeur::I32(1000)];
        // D'une traite : on note le carburant consommé.
        let mut carburant = u64::MAX;
        let etat = m.preparer(f, &arguments).unwrap().reprendre(&mut m, &mut SansHote, &mut carburant);
        assert_eq!(etat, Ok(Etat::Terminee(vec![Valeur::I32(1000)])));
        let consomme = u64::MAX - carburant;
        // Par tranches de 7 instructions : même résultat, même consommation
        // (la reprise ne perd ni ne recompte rien).
        let mut e = m.preparer(f, &arguments).unwrap();
        let (mut tranches, mut total) = (0, 0);
        let resultat = loop {
            let mut carburant = 7;
            let etat = e.reprendre(&mut m, &mut SansHote, &mut carburant).unwrap();
            tranches += 1;
            total += 7 - carburant;
            if let Etat::Terminee(r) = etat {
                break r;
            }
        };
        assert_eq!(resultat, vec![Valeur::I32(1000)]);
        assert_eq!(total, consomme);
        assert!(tranches as u64 >= consomme / 7);
    }

    #[test]
    fn boucle_sans_fin() {
        // f : loop br 0 end
        let mut octets = b"\0asm\x01\0\0\0".to_vec();
        octets.extend_from_slice(&[1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 7, 5, 1, 1, b'f', 0, 0]);
        octets.extend_from_slice(&[10, 9, 1, 7, 0, 0x03, 0x40, 0x0C, 0, 0x0B, 0x0B]);
        let (mut m, f) = instancier(&octets);
        let mut e = m.preparer(f, &[]).unwrap();
        for _ in 0..3 {
            let mut carburant = 1000;
            assert_eq!(e.reprendre(&mut m, &mut SansHote, &mut carburant), Ok(Etat::Interrompue));
            assert_eq!(carburant, 0);
        }
    }

    #[test]
    fn dette_de_carburant() {
        // (module (memory 16) (func (export "f")
        //   (memory.fill (i32.const 0) (i32.const 1) (i32.const 1048576))))
        let octets = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
            0x05, 0x03, 0x01, 0x00, 0x10, 0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00, 0x0a, 0x10, 0x01, 0x0e, 0x00, 0x41,
            0x00, 0x41, 0x01, 0x41, 0x80, 0x80, 0xc0, 0x00, 0xfc, 0x0b, 0x00, 0x0b,
        ];
        // Cinq instructions (trois constantes, memory.fill, end), plus une
        // unité par 256 octets remplis : 5 + 4096.
        let (mut m, f) = instancier(&octets);
        let mut carburant = u64::MAX;
        let etat = m.preparer(f, &[]).unwrap().reprendre(&mut m, &mut SansHote, &mut carburant);
        assert_eq!((etat, u64::MAX - carburant), (Ok(Etat::Terminee(vec![])), 4101));
        // Par tranches de 10 : memory.fill se fait d'un coup, dans la
        // deuxième tranche, puis l'exécution paie sa dette sur les
        // suivantes avant de finir.
        let (mut m, f) = instancier(&octets);
        let mut e = m.preparer(f, &[]).unwrap();
        let mut tranches = 0;
        loop {
            let mut carburant = 10;
            tranches += 1;
            if e.reprendre(&mut m, &mut SansHote, &mut carburant).unwrap() != Etat::Interrompue {
                break;
            }
        }
        assert_eq!(tranches, 4101_u32.div_ceil(10));
        assert!(m.memoire(0).unwrap()[..1 << 20].iter().all(|&o| o == 1));
    }

    #[test]
    fn cout_de_l_hote() {
        // (module (import "" "h" (func $h)) (func (export "f") (call $h)))
        let octets = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02, 0x06, 0x01, 0x00,
            0x01, 0x68, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x01, 0x0a, 0x06, 0x01,
            0x04, 0x00, 0x10, 0x00, 0x0b,
        ];
        // Un hôte dont la fonction vaut 1000 unités de travail.
        struct Couteux;
        impl Hote for Couteux {
            fn appeler(&mut self, _: u32, _: &[Valeur], _: &mut [Valeur], _: Option<&mut [u8]>, cout: &mut u64) -> Result<(), Piege> {
                *cout += 1000;
                Ok(())
            }
        }
        let module = crate::decoder(&octets).and_then(crate::valider).unwrap();
        let mut m = Magasin::new();
        let t = crate::module::TypeFonction { parametres: Box::new([]), resultats: Box::new([]) };
        let h = m.ajouter_fonction_hote(t, 0);
        let instance = m.instancier(Arc::new(module), &[h]).unwrap().instance;
        let Some(Externe::Fonction(f)) = m.exporte(instance, "f") else { panic!("export f") };
        // call et end : deux instructions, plus les 1000 unités de l'hôte.
        let mut carburant = u64::MAX;
        let etat = m.preparer(f, &[]).unwrap().reprendre(&mut m, &mut Couteux, &mut carburant);
        assert_eq!((etat, u64::MAX - carburant), (Ok(Etat::Terminee(vec![])), 1002));
    }

    #[test]
    fn un_piege_est_definitif() {
        // (module (func (export "f") unreachable))
        let octets = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
            0x07, 0x05, 0x01, 0x01, 0x66, 0x00, 0x00, 0x0a, 0x05, 0x01, 0x03, 0x00, 0x00, 0x0b,
        ];
        let (mut m, f) = instancier(&octets);
        let mut e = m.preparer(f, &[]).unwrap();
        for _ in 0..2 {
            assert_eq!(e.reprendre(&mut m, &mut SansHote, &mut 100), Err(Piege::Inatteignable));
        }
    }

    #[test]
    fn la_recursion_n_use_pas_la_pile_de_rust() {
        // 64 Kio de pile pour le fil : un interpréteur récursif y
        // déborderait après quelques centaines d'appels WebAssembly.
        let fil = std::thread::Builder::new().stack_size(64 * 1024).spawn(|| {
            let (mut m, f) = instancier(&module_recursif());
            let profond = m.invoquer(&mut SansHote, f, &[Valeur::I32(50_000)]);
            let trop_profond = m.invoquer(&mut SansHote, f, &[Valeur::I32(100_000)]);
            (profond, trop_profond)
        });
        let (profond, trop_profond) = fil.unwrap().join().unwrap();
        assert_eq!(profond, Ok(vec![Valeur::I32(50_000)]));
        assert_eq!(trop_profond, Err(Piege::PileEpuisee));
    }
}
