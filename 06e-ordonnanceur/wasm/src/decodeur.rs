//! Le décodeur : des octets d'un fichier .wasm à un `Module`.
//!
//! Un fichier .wasm commence par la signature « \0asm » et la version 1 du
//! format (sur 4 octets), puis une suite de sections :
//!     [id : 1 octet] [taille : u32] [contenu : taille octets]
//! Chaque section a un numéro, et apparaît au plus une fois, dans un ordre
//! imposé ; seules les sections « personnalisées » (id 0 : nom des
//! fonctions pour les débogueurs...) peuvent apparaître n'importe où, et on
//! les ignore.
//!
//! Le décodeur vérifie que le module est BIEN FORMÉ : chaque octet est à sa
//! place. Il ne vérifie pas encore qu'il a un sens (un index de fonction qui
//! existe, des types qui collent) : c'est le travail du validateur. Les
//! deux sont séparés dans la spécification, et la suite de tests les
//! distingue (assert_malformed et assert_invalid).

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::erreur::{Erreur, Genre};
use crate::instructions::{Instruction, lire_instruction, lire_type_reference, lire_type_valeur};
use crate::lecteur::Lecteur;
use crate::limites::{Limite, TAILLE_CORPS_MAX, TAILLE_MODULE_MAX};
use crate::module::*;

/// Lit un module complet.
pub fn decoder(octets: &[u8]) -> Result<Module, Erreur> {
    if octets.len() > TAILLE_MODULE_MAX {
        return Err(Erreur { position: 0, genre: Genre::LimiteDepassee(Limite::TailleModule) });
    }
    let mut module = Module { octets: octets.into(), ..Module::default() };
    let mut l = Lecteur::new(octets);

    if l.octets(4).ok() != Some(b"\0asm".as_slice()) {
        return Err(Erreur { position: 0, genre: Genre::MagiqueAbsent });
    }
    if l.octets(4).ok() != Some([1, 0, 0, 0].as_slice()) {
        return Err(Erreur { position: 4, genre: Genre::VersionInconnue });
    }

    // Le rang de la dernière section lue, pour vérifier l'ordre. La section
    // 12 (nombre de segments de données), ajoutée en 2.0, se place entre les
    // éléments (9) et le code (10) : l'ordre n'est pas celui des numéros.
    let mut dernier_rang = 0;
    let mut code_vu = false;
    let mut donnees_vues = false;
    // Le code utilise-t-il memory.init ou data.drop ? (voir plus bas)
    let mut utilise_donnees = false;
    while !l.fini() {
        let position = l.position();
        let id = l.octet()?;
        let taille = l.u32()? as usize;
        let mut s = l.sous_lecteur(taille)?;
        if id != 0 {
            let rang = match id {
                1..=9 => id,
                12 => 10,
                10 => 11,
                11 => 12,
                _ => return Err(Erreur { position, genre: Genre::SectionInconnue(id) }),
            };
            if rang <= dernier_rang {
                return Err(Erreur { position, genre: Genre::SectionDansLeDesordre(id) });
            }
            dernier_rang = rang;
            module.sections[id as usize] = position as u32;
        }
        match id {
            0 => {
                // Section personnalisée : un nom, puis n'importe quoi.
                s.nom()?;
                s.octets(s.reste())?;
            }
            1 => module.types = vecteur(&mut s, lire_type_fonction)?,
            2 => module.imports = vecteur(&mut s, lire_import)?,
            3 => module.fonctions = vecteur(&mut s, |s| s.u32())?,
            4 => module.tables = vecteur(&mut s, lire_type_table)?,
            5 => module.memoires = vecteur(&mut s, lire_limites)?,
            6 => module.globales = vecteur(&mut s, lire_globale)?,
            7 => module.exports = vecteur(&mut s, lire_export)?,
            8 => module.demarrage = Some(s.u32()?),
            9 => module.elements = vecteur(&mut s, lire_segment_elements)?,
            12 => module.nombre_donnees = Some(s.u32()?),
            10 => {
                module.corps = vecteur(&mut s, |s| lire_corps(s, &mut utilise_donnees))?;
                code_vu = true;
            }
            11 => {
                module.donnees = vecteur(&mut s, lire_segment_donnees)?;
                donnees_vues = true;
            }
            _ => unreachable!(),
        }
        if !s.fini() {
            return Err(s.erreur(Genre::TailleDeSection));
        }
    }

    // Les fonctions sont déclarées en deux endroits : leurs types (section 3)
    // et leurs corps (section 10). Les deux listes doivent correspondre.
    if module.fonctions.len() != module.corps.len() && (code_vu || !module.fonctions.is_empty()) {
        return Err(l.erreur(Genre::FonctionsEtCodeIncoherents));
    }
    // La section 12 (nombre de segments de données) annonce, AVANT le code,
    // combien de segments de données suivront APRÈS : sans elle, on ne
    // pourrait pas vérifier en une seule passe l'index d'un memory.init ou
    // d'un data.drop. C'est sa raison d'être : un code qui désigne un
    // segment de données, quel qu'il soit, exige cette section.
    if module.nombre_donnees.is_none() && utilise_donnees {
        return Err(l.erreur(Genre::SectionDeNombreDeDonneesRequise));
    }
    if let Some(n) = module.nombre_donnees {
        if n as usize != module.donnees.len() && (donnees_vues || n != 0) {
            return Err(l.erreur(Genre::NombreDeDonneesIncoherent));
        }
    }
    Ok(module)
}

/// Un vecteur : un nombre, puis autant d'éléments.
fn vecteur<'a, T>(
    l: &mut Lecteur<'a>,
    mut lire: impl FnMut(&mut Lecteur<'a>) -> Result<T, Erreur>,
) -> Result<Vec<T>, Erreur> {
    let n = l.nombre()?;
    // Pas de Vec::with_capacity(n) : n vient du module, et `nombre` ne
    // garantit qu'un octet par élément annoncé, alors qu'un élément décodé
    // occupe jusqu'à 64 octets en mémoire (un import). Réserver d'avance
    // ferait allouer 64 fois la taille de la section avant d'en avoir lu
    // un seul élément. Le Vec grandit avec ce qui est réellement lu.
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(lire(l)?);
    }
    Ok(v)
}

fn lire_type_fonction(l: &mut Lecteur) -> Result<TypeFonction, Erreur> {
    if l.octet()? != 0x60 {
        return Err(Erreur { position: l.position() - 1, genre: Genre::TypeDeFonctionAttendu });
    }
    let parametres: Box<[TypeValeur]> = vecteur(l, lire_type_valeur)?.into();
    let resultats: Box<[TypeValeur]> = vecteur(l, lire_type_valeur)?.into();
    Ok(TypeFonction { parametres, resultats })
}

fn lire_limites(l: &mut Lecteur) -> Result<Limites, Erreur> {
    match l.octet()? {
        0x00 => Ok(Limites { min: l.u32()?, max: None }),
        0x01 => {
            let min = l.u32()?;
            Ok(Limites { min, max: Some(l.u32()?) })
        }
        // 0x02 et 0x03 désigneront une mémoire partagée entre fils
        // d'exécution (proposition « threads »), hors de la version 2.0.
        drapeau => Err(Erreur { position: l.position() - 1, genre: Genre::LimitesInconnues(drapeau) }),
    }
}

fn lire_type_table(l: &mut Lecteur) -> Result<TypeTable, Erreur> {
    let element = lire_type_reference(l)?;
    Ok(TypeTable { element, limites: lire_limites(l)? })
}

fn lire_type_globale(l: &mut Lecteur) -> Result<TypeGlobale, Erreur> {
    let valeur = lire_type_valeur(l)?;
    let modifiable = match l.octet()? {
        0 => false,
        1 => true,
        o => return Err(Erreur { position: l.position() - 1, genre: Genre::MutabiliteInconnue(o) }),
    };
    Ok(TypeGlobale { valeur, modifiable })
}

fn lire_import(l: &mut Lecteur) -> Result<Import, Erreur> {
    let module = l.nom()?.to_string();
    let nom = l.nom()?.to_string();
    let description = match l.octet()? {
        0 => DescriptionImport::Fonction(l.u32()?),
        1 => DescriptionImport::Table(lire_type_table(l)?),
        2 => DescriptionImport::Memoire(lire_limites(l)?),
        3 => DescriptionImport::Globale(lire_type_globale(l)?),
        o => return Err(Erreur { position: l.position() - 1, genre: Genre::GenreDImportInconnu(o) }),
    };
    Ok(Import { module, nom, description })
}

fn lire_export(l: &mut Lecteur) -> Result<Export, Erreur> {
    let nom = l.nom()?.to_string();
    let description = match l.octet()? {
        0 => DescriptionExport::Fonction(l.u32()?),
        1 => DescriptionExport::Table(l.u32()?),
        2 => DescriptionExport::Memoire(l.u32()?),
        3 => DescriptionExport::Globale(l.u32()?),
        o => return Err(Erreur { position: l.position() - 1, genre: Genre::GenreDExportInconnu(o) }),
    };
    Ok(Export { nom, description })
}

/// Une expression : des instructions jusqu'au `end` qui la termine. Les
/// blocs imbriqués ont leur propre `end` : on compte la profondeur. On rend
/// la plage, `end` final compris.
///
/// `utilise_donnees` passe à vrai si l'expression contient memory.init ou
/// data.drop (voir `decoder`).
fn lire_expression(l: &mut Lecteur, utilise_donnees: &mut bool) -> Result<Plage, Erreur> {
    let debut = l.position() as u32;
    let mut profondeur = 0u32;
    loop {
        match lire_instruction(l)? {
            Instruction::Block(_) | Instruction::Loop(_) | Instruction::If(_) => profondeur += 1,
            Instruction::End if profondeur == 0 => break,
            Instruction::End => profondeur -= 1,
            Instruction::MemoryInit(_) | Instruction::DataDrop(_) => *utilise_donnees = true,
            _ => {}
        }
    }
    Ok(Plage { debut, fin: l.position() as u32 })
}

fn lire_globale(l: &mut Lecteur) -> Result<Globale, Erreur> {
    let type_globale = lire_type_globale(l)?;
    Ok(Globale { type_globale, init: lire_expression(l, &mut false)? })
}

/// Les segments d'éléments ont huit formes, selon les trois bits d'un
/// drapeau (version 2.0) :
///   bit 0 : passif ou déclaratif (1), plutôt qu'actif (0) ;
///   bit 1 : actif avec un index de table explicite, ou déclaratif (si bit 0) ;
///   bit 2 : éléments donnés par des expressions, plutôt que par des index
///           de fonctions.
/// La forme 0 est celle de la version 1.0 : table 0, index de fonctions.
fn lire_segment_elements(l: &mut Lecteur) -> Result<SegmentElements, Erreur> {
    let position = l.position();
    let drapeau = l.u32()?;
    if drapeau > 7 {
        return Err(Erreur { position, genre: Genre::SegmentDElementsInconnu(drapeau) });
    }
    let expressions = drapeau & 4 != 0;
    let mode = match drapeau & 3 {
        0 => ModeSegment::Actif { index: 0, decalage: lire_expression(l, &mut false)? },
        2 => {
            let index = l.u32()?;
            ModeSegment::Actif { index, decalage: lire_expression(l, &mut false)? }
        }
        1 => ModeSegment::Passif,
        _ => ModeSegment::Declaratif,
    };
    // Les formes 0 et 4 n'écrivent pas le type : c'est funcref. Les autres
    // l'écrivent : un « genre d'élément » (0x00 = funcref, le seul) pour les
    // index de fonctions, un type référence pour les expressions.
    let type_element = if drapeau == 0 || drapeau == 4 {
        TypeValeur::FuncRef
    } else if expressions {
        lire_type_reference(l)?
    } else {
        if l.octet()? != 0x00 {
            return Err(Erreur { position: l.position() - 1, genre: Genre::ReferenceAttendue });
        }
        TypeValeur::FuncRef
    };
    let elements = if expressions {
        vecteur(l, |l| Ok(Element::Expression(lire_expression(l, &mut false)?)))?
    } else {
        vecteur(l, |l| Ok(Element::Fonction(l.u32()?)))?
    };
    Ok(SegmentElements { type_element, elements, mode })
}

/// Trois formes : 0 = actif en mémoire 0, 1 = passif, 2 = actif avec un
/// index de mémoire explicite.
fn lire_segment_donnees(l: &mut Lecteur) -> Result<SegmentDonnees, Erreur> {
    let position = l.position();
    let mode = match l.u32()? {
        0 => ModeSegment::Actif { index: 0, decalage: lire_expression(l, &mut false)? },
        1 => ModeSegment::Passif,
        2 => {
            let index = l.u32()?;
            ModeSegment::Actif { index, decalage: lire_expression(l, &mut false)? }
        }
        drapeau => return Err(Erreur { position, genre: Genre::SegmentDeDonneesInconnu(drapeau) }),
    };
    let taille = l.u32()? as usize;
    let debut = l.position() as u32;
    l.octets(taille)?;
    Ok(SegmentDonnees { octets: Plage { debut, fin: l.position() as u32 }, mode })
}

/// Le corps d'une fonction : sa taille, ses variables locales, son code.
fn lire_corps(l: &mut Lecteur, utilise_donnees: &mut bool) -> Result<Corps, Erreur> {
    let position = l.position();
    let taille = l.u32()? as usize;
    if taille > TAILLE_CORPS_MAX {
        return Err(Erreur { position, genre: Genre::LimiteDepassee(Limite::TailleCorps) });
    }
    let mut c = l.sous_lecteur(taille)?;
    let groupes = c.nombre()?;
    let mut locales = Vec::new();
    // Le nombre total de locales doit tenir sur 32 bits : un module peut en
    // annoncer 4 milliards en quelques octets (groupes de 0xFFFFFFFF).
    let mut total: u64 = 0;
    for _ in 0..groupes {
        let nombre = c.u32()?;
        total += nombre as u64;
        if total > u32::MAX as u64 {
            return Err(c.erreur(Genre::TropDeVariablesLocales));
        }
        locales.push((nombre, lire_type_valeur(&mut c)?));
    }
    let code = lire_expression(&mut c, utilise_donnees)?;
    // Le `end` final doit être le dernier octet du corps.
    if !c.fini() {
        return Err(c.erreur(Genre::FinDeFonctionAttendue));
    }
    Ok(Corps { locales: locales.into(), code })
}

/// Les cas que la suite officielle ne couvre pas.
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// L'en-tête, un type [] -> [] et une fonction de ce type.
    const DEBUT: [u8; 14] = [0x00, 0x61, 0x73, 0x6D, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0];

    fn module(suite: &[u8]) -> Vec<u8> {
        let mut m = DEBUT.to_vec();
        m.extend_from_slice(&[3, 2, 1, 0]);
        m.extend_from_slice(suite);
        m
    }

    #[test]
    fn type_de_bloc_sur_deux_octets() {
        // block [40] end : le type vide, sur un octet.
        let bon = module(&[0x0A, 7, 1, 5, 0, 0x02, 0x40, 0x0B, 0x0B]);
        assert!(decoder(&bon).is_ok());
        // block [C0 7F] end : -64 aussi, mais sur deux octets.
        let mauvais = module(&[0x0A, 8, 1, 6, 0, 0x02, 0xC0, 0x7F, 0x0B, 0x0B]);
        assert_eq!(decoder(&mauvais).unwrap_err().genre, Genre::TypeDeBlocMalForme);
    }

    #[test]
    fn corps_trop_grand() {
        // Un corps qui annonce TAILLE_CORPS_MAX + 1 octets est refusé avant
        // d'être lu : le module n'a pas besoin de les contenir.
        let mut taille = Vec::new();
        let mut n = TAILLE_CORPS_MAX as u32 + 1;
        while n >= 0x80 {
            taille.push(n as u8 | 0x80);
            n >>= 7;
        }
        taille.push(n as u8);
        let mut code = vec![0x0A, 1 + taille.len() as u8, 1];
        code.extend_from_slice(&taille);
        let erreur = decoder(&module(&code)).unwrap_err();
        assert_eq!(erreur.genre, Genre::LimiteDepassee(Limite::TailleCorps));
    }
}
