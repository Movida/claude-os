//! La carte des zones contre un modèle : des milliers d'opérations au
//! hasard sur un petit espace de 256 pages, appliquées à la fois à la carte
//! et à un tableau qui décrit chaque page une à une (son genre, et pour une
//! projection de fichier, la page du fichier qu'elle montre ; ou rien).
//! Le tableau est trop simple pour se tromper : après chaque opération, la
//! carte doit dire exactement la même chose que lui, et respecter ses
//! invariants. Les références aux fichiers annoncées par la carte (+1, -1)
//! doivent toujours faire, pour chaque fichier, le nombre de ses zones.
//!
//! Le hasard vient d'un générateur xorshift écrit ici, avec des graines
//! fixes : un échec se rejoue à l'identique.

use std::collections::BTreeMap;

use zones::{Drapeaux, Droits, Erreur, Nature, Projection, Sens, Zone, Zones, PAGE};

const PAGES: u64 = 256;
const ECART: u64 = 3 * PAGE;

/// Ce que le modèle sait d'une page projetée.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Genre {
    droits: Droits,
    nature: Nature,
    drapeaux: Drapeaux,
    fichier: Option<u32>,
}

fn genre(z: &Zone) -> Genre {
    Genre { droits: z.droits, nature: z.nature, drapeaux: z.drapeaux, fichier: z.fichier.map(|p| p.fichier) }
}

/// Le genre de la page, et la page du fichier qu'elle montre (0 pour de
/// l'anonyme).
type Page = (Genre, u64);
type Modele = [Option<Page>; PAGES as usize];

/// Ce que dit la carte de la page de la zone `z` à l'adresse `a`.
fn page_de(z: &Zone, a: u64) -> Page {
    (genre(z), z.page_de(a).unwrap_or(0))
}

/// xorshift64 (Marsaglia, 2003).
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn moins_de(&mut self, n: u64) -> u64 {
        self.suivant() % n
    }

    fn booleen(&mut self) -> bool {
        self.suivant() & 1 == 1
    }

    /// Une plage de pages [debut, fin[, parfois vide, plutôt courte.
    fn plage(&mut self) -> (u64, u64) {
        let debut = self.moins_de(PAGES);
        let longueur = if self.booleen() { self.moins_de(8) } else { self.moins_de(PAGES) };
        (debut, (debut + longueur).min(PAGES))
    }

    /// Un genre parmi peu de choix, pour que les fusions arrivent souvent.
    fn genre(&mut self) -> Genre {
        let droits = [
            Droits::AUCUN,
            Droits { lecture: true, ecriture: false, execution: false },
            Droits { lecture: true, ecriture: true, execution: false },
        ][self.moins_de(3) as usize];
        let nature = [Nature::Anonyme, Nature::Pile, Nature::Tas][self.moins_de(3) as usize];
        let vers_le_bas = nature == Nature::Pile;
        // Un fichier sur trois, pas pour une pile (MAP_GROWSDOWN est refusé
        // par le noyau).
        let fichier = (nature != Nature::Pile && self.moins_de(3) == 0).then(|| 1 + self.moins_de(2) as u32);
        Genre {
            droits,
            nature,
            drapeaux: Drapeaux { vers_le_bas, sans_reserve: self.moins_de(4) == 0, ..Drapeaux::default() },
            fichier,
        }
    }
}

/// Les zones que décrit le modèle : ses suites maximales de pages du même
/// genre (et, pour un fichier, de pages du fichier qui se suivent), avec
/// leur page du fichier de début.
fn zones_du_modele(m: &Modele) -> Vec<(u64, u64, Genre, u64)> {
    let mut zones: Vec<(u64, u64, Genre, u64)> = Vec::new();
    for (p, page) in m.iter().enumerate() {
        let Some((g, pf)) = *page else { continue };
        let p = p as u64;
        match zones.last_mut() {
            Some((debut, fin, h, pd)) if *fin == p && *h == g && (g.fichier.is_none() || *pd + (p - *debut) == pf) => *fin += 1,
            _ => zones.push((p, p + 1, g, if g.fichier.is_some() { pf } else { 0 })),
        }
    }
    zones
}

fn comparer(c: &Zones, m: &Modele, references: &BTreeMap<u32, i32>, contexte: &str) {
    c.invariants().unwrap_or_else(|e| panic!("{contexte} : {e}"));
    let carte: Vec<_> = c
        .zones()
        .iter()
        .map(|z| (z.debut / PAGE, z.fin / PAGE, genre(z), z.fichier.map_or(0, |p| p.page)))
        .collect();
    assert_eq!(carte, zones_du_modele(m), "{contexte}");
    for f in 1..=2 {
        let zones = c.zones().iter().filter(|z| z.fichier.map(|p| p.fichier) == Some(f)).count() as i32;
        assert_eq!(references.get(&f).copied().unwrap_or(0), zones, "{contexte} : references du fichier {f}");
    }
}

/// La page de début de la zone qui contient la page `p` dans le modèle.
fn debut_de_zone(m: &Modele, p: u64) -> u64 {
    zones_du_modele(m).into_iter().find(|&(d, f, _, _)| (d..f).contains(&p)).map_or(p, |(d, ..)| d)
}

/// Le trou attendu, cherché page par page.
fn trou_du_modele(m: &Modele, taille: u64, plancher: u64, plafond: u64, sens: Sens) -> Option<u64> {
    let libre = |a: u64| libre_du_modele(m, a, a + taille);
    let candidats = plancher..=plafond.saturating_sub(taille);
    if taille == 0 || plafond < plancher + taille {
        return None;
    }
    match sens {
        Sens::DuHaut => candidats.rev().find(|&a| libre(a)),
        Sens::DuBas => candidats.into_iter().find(|&a| libre(a)),
    }
}

/// [debut, fin[ (en pages) est-il libre, écart de garde compris ?
fn libre_du_modele(m: &Modele, debut: u64, fin: u64) -> bool {
    // La première page projetée à partir de `debut`.
    let Some(q) = (debut..PAGES).find(|&p| m[p as usize].is_some()) else { return true };
    let g = m[q as usize].unwrap();
    // Si q est dans une zone commencée avant `debut`, ce n'est pas libre ;
    // sinon q est le début de sa zone.
    if q < fin {
        return false;
    }
    let ecart = if g.0.drapeaux.vers_le_bas { ECART / PAGE } else { 0 };
    fin <= q.saturating_sub(ecart)
}

/// L'extension de pile attendue, page par page. Rend le modèle changé, ou
/// None si elle est refusée.
fn etendre_du_modele(m: &Modele, adresse: u64, taille_max: u64) -> Option<Modele> {
    if m[adresse as usize].is_some() {
        return None;
    }
    let q = (adresse..PAGES).find(|&p| m[p as usize].is_some())?;
    let g = m[q as usize].unwrap();
    let fin = (q..PAGES).find(|&p| m[p as usize] != Some(g)).unwrap_or(PAGES);
    if !g.0.drapeaux.vers_le_bas || fin - adresse > taille_max {
        return None;
    }
    if let Some(p) = (0..adresse).rev().find(|&p| m[p as usize].is_some()) {
        let h = m[p as usize].unwrap().0;
        if h.droits.accessible() && !h.drapeaux.vers_le_bas && adresse - (p + 1) < ECART / PAGE {
            return None;
        }
    }
    let mut n = *m;
    n[adresse as usize..q as usize].fill(Some(g));
    Some(n)
}

fn jouer(graine: u64, operations: usize, maximum: usize) {
    let mut h = Hasard(graine);
    let mut c = Zones::avec_maximum(maximum);
    let mut m: Modele = [None; PAGES as usize];
    let mut references: BTreeMap<u32, i32> = BTreeMap::new();
    for numero in 0..operations {
        let contexte = format!("graine {graine}, operation {numero}");
        let (debut, fin) = h.plage();
        let (a, b) = (debut * PAGE, fin * PAGE);
        match h.moins_de(6) {
            // Insérer une zone.
            0 => {
                let g = h.genre();
                // La page du fichier de début : le plus souvent celle qui a
                // le numéro de l'adresse (des zones voisines du même fichier
                // se suivent alors dans le fichier, et fusionnent), parfois
                // n'importe laquelle.
                let page = if h.booleen() { debut } else { h.moins_de(1000) };
                let fichier = g.fichier.map(|f| Projection { fichier: f, page });
                let zone = Zone { debut: a, fin: b, droits: g.droits, nature: g.nature, drapeaux: g.drapeaux, fichier };
                let mut n = m;
                for (k, p) in n[debut as usize..fin as usize].iter_mut().enumerate() {
                    *p = Some((g, if fichier.is_some() { page + k as u64 } else { 0 }));
                }
                let attendu = if debut == fin {
                    Err(Erreur::PlageInvalide)
                } else if m[debut as usize..fin as usize].iter().any(Option::is_some) {
                    Err(Erreur::Chevauchement)
                } else if zones_du_modele(&n).len() > maximum {
                    Err(Erreur::TropDeZones)
                } else {
                    Ok(())
                };
                let r = c.inserer(zone, &mut |f, d| *references.entry(f).or_default() += d);
                assert_eq!(r, attendu, "{contexte} : inserer {debut}..{fin}");
                if attendu.is_ok() {
                    m = n;
                }
            }
            // Retirer une plage : les morceaux annoncés doivent être
            // exactement les pages projetées de la plage.
            1 => {
                let mut n = m;
                n[debut as usize..fin as usize].fill(None);
                let attendu = if zones_du_modele(&n).len() > maximum { Err(Erreur::TropDeZones) } else { Ok(()) };
                let mut annonces: Vec<Option<Page>> = vec![None; PAGES as usize];
                let mut prochain = 0;
                let r = c.retirer(a, b, |z| {
                    assert!(z.debut >= prochain && z.debut >= a && z.fin <= b, "{contexte} : morceau {z:?}");
                    prochain = z.fin;
                    for q in z.debut / PAGE..z.fin / PAGE {
                        annonces[q as usize] = Some(page_de(z, q * PAGE));
                    }
                }, &mut |f, d| *references.entry(f).or_default() += d);
                assert_eq!(r, attendu, "{contexte} : retirer {debut}..{fin}");
                if r.is_ok() {
                    assert_eq!(annonces[debut as usize..fin as usize], m[debut as usize..fin as usize], "{contexte}");
                    m = n;
                } else {
                    assert!(annonces.iter().all(Option::is_none), "{contexte} : morceaux annonces malgre l'echec");
                }
            }
            // Changer les droits, ou un drapeau, de ce qui est projeté.
            2 | 3 => {
                let nouveaux = h.genre().droits;
                let changer_droits = h.booleen();
                let change = |g: &mut Genre| {
                    if changer_droits {
                        g.droits = nouveaux;
                    } else {
                        g.drapeaux.ne_pas_dupliquer = !g.drapeaux.ne_pas_dupliquer;
                    }
                };
                let mut n = m;
                for (g, _) in n[debut as usize..fin as usize].iter_mut().flatten() {
                    change(g);
                }
                let attendu = if zones_du_modele(&n).len() > maximum { Err(Erreur::TropDeZones) } else { Ok(()) };
                let r = c.changer(a, b, |z| {
                    let mut g = genre(z);
                    change(&mut g);
                    (z.droits, z.drapeaux) = (g.droits, g.drapeaux);
                }, &mut |f, d| *references.entry(f).or_default() += d);
                assert_eq!(r, attendu, "{contexte} : changer {debut}..{fin}");
                if r.is_ok() {
                    m = n;
                }
            }
            // Étendre une pile vers le bas.
            4 => {
                let taille_max = h.moins_de(PAGES) + 1;
                let attendu = etendre_du_modele(&m, debut, taille_max);
                assert_eq!(c.etendre_pile(a, taille_max * PAGE, ECART), attendu.is_some(), "{contexte} : etendre {debut}");
                if let Some(n) = attendu {
                    m = n;
                }
            }
            // Les questions, qui ne changent rien.
            _ => {
                let taille = h.moins_de(16);
                let sens = if h.booleen() { Sens::DuHaut } else { Sens::DuBas };
                let attendu = trou_du_modele(&m, taille, debut, fin, sens).map(|p| p * PAGE);
                assert_eq!(c.trou(taille * PAGE, a, b, ECART, sens), attendu, "{contexte} : trou de {taille} dans {debut}..{fin}");
                if fin > debut {
                    assert_eq!(c.libre(a, b, ECART), libre_du_modele(&m, debut, fin), "{contexte} : libre {debut}..{fin}");
                }
                let couverte = m[debut as usize..fin as usize].iter().all(Option::is_some);
                assert_eq!(c.couverte(a, b), couverte, "{contexte} : couverte {debut}..{fin}");
                let p = h.moins_de(PAGES);
                let trouvee = c.trouver(p * PAGE + h.moins_de(PAGE));
                assert_eq!(trouvee.map(|z| page_de(z, p * PAGE)), m[p as usize], "{contexte} : trouver {p}");
                if let Some(z) = trouvee {
                    assert_eq!(z.debut / PAGE, debut_de_zone(&m, p), "{contexte} : debut de la zone de {p}");
                }
            }
        }
        comparer(&c, &m, &references, &contexte);
    }
}

#[test]
fn operations_au_hasard() {
    for graine in 1..=40 {
        jouer(graine * 0x9e37_79b9_7f4a_7c15, 5000, usize::MAX);
    }
}

/// Avec un maximum bas, les refus pour « trop de zones » arrivent souvent :
/// ils ne doivent rien changer.
#[test]
fn operations_au_hasard_avec_maximum() {
    for graine in 1..=40 {
        jouer(graine * 0x2545_f491_4f6c_dd1d, 5000, 6);
    }
}
