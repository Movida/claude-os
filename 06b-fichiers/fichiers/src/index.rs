//! L'index des pages d'un fichier : pour chaque page du fichier (son
//! numéro, la position divisée par 4096), la page de mémoire qui la
//! contient, ou rien (un « trou », qui se lit comme des zéros). C'est le
//! cœur du cache des pages de Linux (l'`address_space` d'un inode, et son
//! xarray, lib/xarray.c). Pour un fichier de tmpfs, ces pages ne sont pas
//! une copie d'un disque : ce sont les données elles-mêmes.
//!
//! La structure : un arbre à 512 branches, comme les tables de pages du
//! processeur. Chaque nœud a 512 cases de 8 octets, soit exactement une
//! page de 4 Kio ; une case d'une feuille désigne une page du fichier, une
//! case d'une branche désigne un nœud du niveau d'en dessous, 0 désigne
//! rien. Un arbre de hauteur h couvre 512^h pages : une feuille seule, 2
//! Mio ; deux niveaux, 1 Gio ; six niveaux, 2^54 pages, plus que la plus
//! grande taille de fichier de Linux (MAX_LFS_FILESIZE, 2^63 octets, soit
//! 2^51 pages). La hauteur grandit et diminue avec le plus grand numéro
//! de page présent.
//!
//! Options écartées :
//!   - un `Vec` dense, une case par page jusqu'à la fin du fichier : un
//!     fichier creux (`ftruncate` à 1 Tio, puis une page écrite) coûterait
//!     2 Gio de cases ;
//!   - un `Vec` trié de couples (numéro, page), en dichotomie : compact pour
//!     un fichier creux, mais une insertion au milieu d'un fichier de 291 Mo
//!     (`claude`, 71 000 pages) déplacerait plus d'1 Mio, et ce `Vec` ne
//!     tiendrait plus dans un bloc du tas du noyau (4 Mio au plus) au-delà
//!     de 260 000 pages ;
//!   - l'xarray de Linux, à 64 branches : des nœuds de 576 octets, pensés
//!     pour être lus sans verrou (RCU) par plusieurs processeurs pendant
//!     qu'un autre écrit. Sans RCU, des nœuds d'une page sont plus simples,
//!     et l'arbre plus plat : 291 Mo de `claude` font 140 feuilles et une
//!     racine, 0,2 % de plus que les données.
//!
//! Les nœuds sont rangés dans une table (`noeuds`), et se désignent par
//! leur rang dans la table plus 1 : pas de `Box`, dont l'allocation ne sait
//! pas échouer. Chaque nœud est un `Vec<u64>` de 512 cases, réservé par
//! `try_reserve_exact` : 4096 octets d'un coup, que le tas du noyau prend
//! directement à l'allocateur de pages et lui rend à la libération. Toute
//! opération qui doit créer des nœuds les obtient d'abord ; en cas d'échec,
//! l'index dit exactement la même chose qu'avant.
//!
//! L'index ne sait rien de ce qu'est une page : il range des nombres non
//! nuls (dans le noyau, l'adresse physique d'un cadre ; dans les tests, un
//! rang dans un tableau). C'est son propriétaire qui les prend et les rend.

use alloc::vec::Vec;

/// Le nombre de cases d'un nœud.
pub const BRANCHES: usize = 512;
/// Les bits du numéro de page qu'un niveau consomme (512 = 2^9).
const BITS: u32 = 9;
/// La hauteur maximale : 6 niveaux couvrent 2^54 pages.
const HAUTEUR_MAX: u32 = 6;
/// Le premier numéro de page qu'un fichier ne peut pas avoir : la plus
/// grande taille de fichier de Linux (MAX_LFS_FILESIZE, 2^63 - 1 octets)
/// tient dans les pages 0 à 2^51 - 1.
pub const INDEX_MAX: u64 = 1 << 51;

/// Pourquoi une insertion est refusée. L'index n'a alors pas changé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErreurIndex {
    /// Plus de mémoire pour un nœud.
    PlusDeMemoire,
    /// Un numéro de page au-delà de INDEX_MAX.
    HorsLimite,
}

/// Le nombre de pages que couvre un arbre de hauteur `hauteur` (ou une
/// case d'un nœud du niveau `hauteur`, les feuilles étant au niveau 0).
const fn couvre(hauteur: u32) -> u64 {
    1 << (BITS * hauteur)
}

/// La case du niveau `niveau` qui mène à la page `index`.
fn case(index: u64, niveau: u32) -> usize {
    ((index >> (BITS * niveau)) as usize) & (BRANCHES - 1)
}

/// L'index des pages d'un fichier.
#[derive(Default)]
pub struct IndexPages {
    /// Les nœuds ; un `Vec` vide est une place libre.
    noeuds: Vec<Vec<u64>>,
    /// Les places libres de `noeuds`. Sa capacité est toujours au moins le
    /// nombre de places : rendre un nœud ne demande donc jamais de
    /// mémoire.
    libres: Vec<u32>,
    /// La racine (rang + 1), 0 pour un index vide.
    racine: u32,
    /// Le nombre de niveaux : 0 pour un index vide, sinon le plus petit
    /// qui couvre le plus grand numéro présent (au moins 1).
    hauteur: u32,
    /// Le nombre de pages rangées.
    pages: u64,
}

impl IndexPages {
    pub const fn new() -> IndexPages {
        IndexPages { noeuds: Vec::new(), libres: Vec::new(), racine: 0, hauteur: 0, pages: 0 }
    }

    /// Le nombre de pages rangées.
    pub fn pages(&self) -> u64 {
        self.pages
    }

    /// Le nombre de nœuds de l'arbre (pour les tests).
    pub fn noeuds(&self) -> usize {
        self.noeuds.len() - self.libres.len()
    }

    /// La page numéro `index`, s'il y en a une.
    pub fn trouver(&self, index: u64) -> Option<u64> {
        if self.racine == 0 || index >= couvre(self.hauteur) {
            return None;
        }
        let mut noeud = self.racine;
        for niveau in (0..self.hauteur).rev() {
            let valeur = self.noeuds[noeud as usize - 1][case(index, niveau)];
            if valeur == 0 {
                return None;
            }
            if niveau == 0 {
                return Some(valeur);
            }
            noeud = valeur as u32;
        }
        None
    }

    /// Range `page` (non nulle) au numéro `index`, où il n'y a encore rien.
    /// Rend la page qui y était, s'il y en avait une (le propriétaire doit
    /// alors la rendre : ce n'est pas une façon normale de s'en servir).
    pub fn inserer(&mut self, index: u64, page: u64) -> Result<Option<u64>, ErreurIndex> {
        if index >= INDEX_MAX {
            return Err(ErreurIndex::HorsLimite);
        }
        debug_assert!(page != 0, "une page de l'index n'est jamais 0");
        // L'arbre grandit par le haut jusqu'à couvrir `index` : l'ancienne
        // racine devient la première case d'une nouvelle. Un échec en
        // chemin laisse un arbre plus haut que nécessaire mais juste, que
        // `retrecir` remet à sa hauteur.
        if self.racine != 0 {
            while index >= couvre(self.hauteur) {
                let Ok(n) = self.nouveau_noeud() else {
                    self.retrecir();
                    return Err(ErreurIndex::PlusDeMemoire);
                };
                self.noeuds[n as usize - 1][0] = self.racine as u64;
                self.racine = n;
                self.hauteur += 1;
            }
        }
        // Les nœuds qui manquent sur le chemin, obtenus tous avant d'en
        // poser un seul.
        let (manquants, depuis) = self.manquants(index);
        let mut neufs = [0u32; HAUTEUR_MAX as usize];
        for k in 0..manquants {
            match self.nouveau_noeud() {
                Ok(n) => neufs[k] = n,
                Err(()) => {
                    for &n in &neufs[..k] {
                        self.liberer_noeud(n);
                    }
                    self.retrecir();
                    return Err(ErreurIndex::PlusDeMemoire);
                }
            }
        }
        if self.racine == 0 {
            // Un index vide : le premier neuf est la racine, de la plus
            // petite hauteur qui couvre `index`.
            self.racine = neufs[0];
            self.hauteur = manquants as u32;
        }
        // La descente, en posant les neufs là où il n'y avait rien.
        let mut neufs = neufs[..manquants].iter().copied().skip(usize::from(depuis == self.hauteur));
        let mut noeud = self.racine;
        for niveau in (1..self.hauteur).rev() {
            let c = case(index, niveau);
            if self.noeuds[noeud as usize - 1][c] == 0 {
                let n = neufs.next().expect("un neuf par nœud manquant");
                self.noeuds[noeud as usize - 1][c] = n as u64;
            }
            noeud = self.noeuds[noeud as usize - 1][c] as u32;
        }
        let place = &mut self.noeuds[noeud as usize - 1][case(index, 0)];
        let ancienne = core::mem::replace(place, page);
        if ancienne == 0 {
            self.pages += 1;
            Ok(None)
        } else {
            Ok(Some(ancienne))
        }
    }

    /// Combien de nœuds manquent sur le chemin de `index` (l'arbre le
    /// couvre déjà, sauf s'il est vide), et le niveau du premier nœud
    /// manquant plus 1 (égal à la hauteur quand c'est la racine qui manque).
    fn manquants(&self, index: u64) -> (usize, u32) {
        if self.racine == 0 {
            // Toute la hauteur, de la racine à la feuille.
            let mut h = 1;
            while index >= couvre(h) {
                h += 1;
            }
            return (h as usize, h);
        }
        let mut noeud = self.racine;
        for niveau in (1..self.hauteur).rev() {
            let valeur = self.noeuds[noeud as usize - 1][case(index, niveau)];
            if valeur == 0 {
                // Il manque un nœud à chaque niveau sous celui-ci.
                return (niveau as usize, niveau);
            }
            noeud = valeur as u32;
        }
        (0, 0)
    }

    /// Retire toutes les pages de numéro `debut` ou plus, et appelle `lache`
    /// pour chacune (dans l'ordre des numéros) : `truncate`. Les nœuds
    /// devenus vides sont rendus, et l'arbre redescend à sa hauteur.
    pub fn retirer_depuis(&mut self, debut: u64, mut lache: impl FnMut(u64)) {
        if self.racine == 0 || debut >= couvre(self.hauteur) {
            return;
        }
        if self.couper(self.racine, self.hauteur - 1, 0, debut, &mut lache) {
            self.liberer_noeud(self.racine);
            self.racine = 0;
            self.hauteur = 0;
        }
        self.retrecir();
    }

    /// Retire de `noeud` (du niveau `niveau`, qui couvre les pages à partir
    /// de `base`) les pages de numéro `debut` ou plus. Rend vrai si le nœud
    /// est devenu vide (à l'appelant de le rendre).
    fn couper(&mut self, noeud: u32, niveau: u32, base: u64, debut: u64, lache: &mut impl FnMut(u64)) -> bool {
        let pas = couvre(niveau);
        for c in 0..BRANCHES {
            let premier = base + c as u64 * pas;
            if premier + pas <= debut {
                continue;
            }
            let valeur = self.noeuds[noeud as usize - 1][c];
            if valeur == 0 {
                continue;
            }
            let vide = if niveau == 0 {
                lache(valeur);
                self.pages -= 1;
                true
            } else {
                self.couper(valeur as u32, niveau - 1, premier, debut.max(premier), lache)
            };
            if vide {
                if niveau > 0 {
                    self.liberer_noeud(valeur as u32);
                }
                self.noeuds[noeud as usize - 1][c] = 0;
            }
        }
        self.noeuds[noeud as usize - 1].iter().all(|&v| v == 0)
    }

    /// Le plus petit numéro de page présent, `depuis` ou au-delà (pour
    /// SEEK_DATA).
    pub fn suivante(&self, depuis: u64) -> Option<u64> {
        if self.racine == 0 || depuis >= couvre(self.hauteur) {
            return None;
        }
        self.suivante_dans(self.racine, self.hauteur - 1, 0, depuis)
    }

    fn suivante_dans(&self, noeud: u32, niveau: u32, base: u64, depuis: u64) -> Option<u64> {
        let pas = couvre(niveau);
        let premiere = ((depuis - base) / pas) as usize;
        for c in premiere..BRANCHES {
            let valeur = self.noeuds[noeud as usize - 1][c];
            if valeur == 0 {
                continue;
            }
            let debut = base + c as u64 * pas;
            if niveau == 0 {
                return Some(debut);
            }
            if let Some(trouvee) = self.suivante_dans(valeur as u32, niveau - 1, debut, depuis.max(debut)) {
                return Some(trouvee);
            }
        }
        None
    }

    /// Le plus petit numéro de page absent, `depuis` ou au-delà (pour
    /// SEEK_HOLE). Il y en a toujours un.
    pub fn trou(&self, depuis: u64) -> u64 {
        if self.racine == 0 || depuis >= couvre(self.hauteur) {
            return depuis;
        }
        self.trou_dans(self.racine, self.hauteur - 1, 0, depuis).unwrap_or(couvre(self.hauteur))
    }

    fn trou_dans(&self, noeud: u32, niveau: u32, base: u64, depuis: u64) -> Option<u64> {
        let pas = couvre(niveau);
        let premiere = ((depuis - base) / pas) as usize;
        for c in premiere..BRANCHES {
            let debut = base + c as u64 * pas;
            let valeur = self.noeuds[noeud as usize - 1][c];
            if valeur == 0 {
                return Some(depuis.max(debut));
            }
            if niveau > 0
                && let Some(trou) = self.trou_dans(valeur as u32, niveau - 1, debut, depuis.max(debut))
            {
                return Some(trou);
            }
        }
        None
    }

    /// Appelle `f` pour chaque page présente (numéro, page), dans l'ordre.
    pub fn parcourir(&self, mut f: impl FnMut(u64, u64)) {
        if self.racine != 0 {
            self.parcourir_dans(self.racine, self.hauteur - 1, 0, &mut f);
        }
    }

    fn parcourir_dans(&self, noeud: u32, niveau: u32, base: u64, f: &mut impl FnMut(u64, u64)) {
        let pas = couvre(niveau);
        for (c, &valeur) in self.noeuds[noeud as usize - 1].iter().enumerate() {
            if valeur == 0 {
                continue;
            }
            let debut = base + c as u64 * pas;
            if niveau == 0 {
                f(debut, valeur);
            } else {
                self.parcourir_dans(valeur as u32, niveau - 1, debut, f);
            }
        }
    }

    /// Un nœud neuf, à zéro (son rang + 1).
    fn nouveau_noeud(&mut self) -> Result<u32, ()> {
        let mut cases = Vec::new();
        cases.try_reserve_exact(BRANCHES).map_err(|_| ())?;
        cases.resize(BRANCHES, 0);
        if let Some(place) = self.libres.pop() {
            self.noeuds[place as usize] = cases;
            return Ok(place + 1);
        }
        // Une place de plus dans la table, et de quoi la noter libre un jour
        // sans rien demander (voir `libres`).
        self.noeuds.try_reserve(1).map_err(|_| ())?;
        self.libres.try_reserve(self.noeuds.len() + 1 - self.libres.len()).map_err(|_| ())?;
        self.noeuds.push(cases);
        Ok(self.noeuds.len() as u32)
    }

    /// Rend le nœud `noeud` (rang + 1) : ses 4 Kio retournent au tas.
    fn liberer_noeud(&mut self, noeud: u32) {
        self.noeuds[noeud as usize - 1] = Vec::new();
        self.libres.push(noeud - 1);
    }

    /// Ramène l'arbre à sa hauteur : tant que la racine ne mène qu'à sa
    /// première case, celle-ci devient la racine. Un index vide rend aussi
    /// sa table de nœuds.
    fn retrecir(&mut self) {
        while self.racine != 0 {
            let racine = &self.noeuds[self.racine as usize - 1];
            if racine[1..].iter().any(|&v| v != 0) || (self.hauteur == 1 && racine[0] != 0) {
                break;
            }
            let premier = racine[0] as u32;
            self.liberer_noeud(self.racine);
            self.racine = premier;
            self.hauteur = if premier == 0 { 0 } else { self.hauteur - 1 };
        }
        if self.racine == 0 {
            self.noeuds = Vec::new();
            self.libres = Vec::new();
        }
    }

    /// Les invariants de l'index (pour les tests) : chaque nœud de l'arbre
    /// a au moins une case non nulle, le compte des pages est juste, la
    /// hauteur est la plus petite possible, et les places libres sont
    /// exactement les nœuds hors de l'arbre.
    pub fn invariants(&self) -> Result<(), &'static str> {
        if (self.racine == 0) != (self.hauteur == 0) {
            return Err("racine et hauteur ne s'accordent pas");
        }
        if self.racine == 0 {
            return if self.pages == 0 && self.noeuds.is_empty() { Ok(()) } else { Err("index vide avec des restes") };
        }
        if self.hauteur > HAUTEUR_MAX {
            return Err("trop haut");
        }
        let racine = &self.noeuds[self.racine as usize - 1];
        if self.hauteur > 1 && racine[1..].iter().all(|&v| v == 0) {
            return Err("hauteur pas minimale");
        }
        let (mut noeuds, mut pages) = (0usize, 0u64);
        self.compter(self.racine, self.hauteur - 1, &mut noeuds, &mut pages)?;
        if pages != self.pages {
            return Err("compte des pages faux");
        }
        if noeuds != self.noeuds() {
            return Err("nœuds perdus");
        }
        if self.libres.capacity() < self.noeuds.len() {
            return Err("pas de place pour noter les nœuds libres");
        }
        Ok(())
    }

    fn compter(&self, noeud: u32, niveau: u32, noeuds: &mut usize, pages: &mut u64) -> Result<(), &'static str> {
        let cases = &self.noeuds[noeud as usize - 1];
        if cases.len() != BRANCHES {
            return Err("nœud libre dans l'arbre");
        }
        if cases.iter().all(|&v| v == 0) {
            return Err("nœud vide dans l'arbre");
        }
        *noeuds += 1;
        for &v in cases.iter().filter(|&&v| v != 0) {
            if niveau == 0 {
                *pages += 1;
            } else {
                self.compter(v as u32, niveau - 1, noeuds, pages)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    #[test]
    fn insertion_et_recherche() {
        let mut ix = IndexPages::new();
        assert_eq!(ix.trouver(0), None);
        assert_eq!(ix.inserer(0, 10), Ok(None));
        assert_eq!((ix.hauteur, ix.noeuds()), (1, 1));
        // Au-delà de 2 Mio de fichier : un niveau de plus.
        assert_eq!(ix.inserer(512, 11), Ok(None));
        assert_eq!((ix.hauteur, ix.noeuds()), (2, 3));
        // Très loin : un fichier creux de 1 Tio ne coûte que son chemin.
        assert_eq!(ix.inserer(1 << 28, 12), Ok(None));
        assert_eq!(ix.hauteur, 4);
        assert_eq!(ix.noeuds(), 3 + 2 + 3);
        assert_eq!((ix.trouver(0), ix.trouver(512), ix.trouver(1 << 28)), (Some(10), Some(11), Some(12)));
        assert_eq!((ix.trouver(1), ix.trouver(513), ix.trouver(1 << 40)), (None, None, None));
        assert_eq!(ix.inserer(0, 13), Ok(Some(10)));
        assert_eq!(ix.pages(), 3);
        assert_eq!(ix.inserer(INDEX_MAX, 1), Err(ErreurIndex::HorsLimite));
        assert_eq!(ix.inserer(INDEX_MAX - 1, 14), Ok(None));
        assert_eq!(ix.hauteur, HAUTEUR_MAX);
        ix.invariants().unwrap();
    }

    #[test]
    fn retrait_et_hauteur() {
        let mut ix = IndexPages::new();
        for i in [0, 1, 511, 512, 100_000, 1 << 30] {
            ix.inserer(i, i + 1).unwrap();
        }
        let mut lachees = Vec::new();
        ix.retirer_depuis(512, |p| lachees.push(p));
        assert_eq!(lachees, [513, 100_001, (1 << 30) + 1]);
        assert_eq!((ix.hauteur, ix.noeuds(), ix.pages()), (1, 1, 3));
        ix.invariants().unwrap();
        ix.retirer_depuis(1, |_| ());
        assert_eq!((ix.trouver(0), ix.pages()), (Some(1), 1));
        ix.retirer_depuis(0, |_| ());
        assert_eq!((ix.hauteur, ix.noeuds(), ix.noeuds.capacity()), (0, 0, 0));
        ix.invariants().unwrap();
        // Retirer au-delà de tout ne fait rien.
        ix.inserer(3, 4).unwrap();
        ix.retirer_depuis(1 << 40, |_| panic!("rien a retirer"));
        assert_eq!(ix.pages(), 1);
    }

    #[test]
    fn donnees_et_trous() {
        let mut ix = IndexPages::new();
        assert_eq!((ix.suivante(0), ix.trou(5)), (None, 5));
        for i in [3, 4, 5, 1000, 1001] {
            ix.inserer(i, 1).unwrap();
        }
        assert_eq!(ix.suivante(0), Some(3));
        assert_eq!(ix.suivante(4), Some(4));
        assert_eq!(ix.suivante(6), Some(1000));
        assert_eq!(ix.suivante(1002), None);
        assert_eq!(ix.trou(0), 0);
        assert_eq!(ix.trou(3), 6);
        assert_eq!(ix.trou(1000), 1002);
        // Une feuille pleine : le trou est après elle.
        let mut plein = IndexPages::new();
        for i in 0..512 {
            plein.inserer(i, 1).unwrap();
        }
        assert_eq!(plein.trou(0), 512);
    }

    /// Des opérations au hasard, comparées à un BTreeMap.
    #[test]
    fn contre_un_modele() {
        let mut graine: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut hasard = move || {
            graine ^= graine << 13;
            graine ^= graine >> 7;
            graine ^= graine << 17;
            graine
        };
        for _ in 0..20 {
            let mut ix = IndexPages::new();
            let mut modele = BTreeMap::new();
            for _ in 0..2000 {
                // Des numéros groupés (voisins) et quelques-uns lointains.
                let i = match hasard() % 4 {
                    0 => hasard() % (1 << 30),
                    _ => hasard() % 2000,
                };
                if hasard() % 5 == 0 {
                    let mut lachees = Vec::new();
                    ix.retirer_depuis(i, |p| lachees.push(p));
                    let attendues: Vec<u64> = modele.range(i..).map(|(_, &p)| p).collect();
                    assert_eq!(lachees, attendues);
                    modele.retain(|&k, _| k < i);
                } else {
                    let p = hasard() | 1;
                    assert_eq!(ix.inserer(i, p).unwrap(), modele.insert(i, p));
                }
                ix.invariants().unwrap();
                assert_eq!(ix.pages(), modele.len() as u64);
                let j = hasard() % 2100;
                assert_eq!(ix.trouver(j), modele.get(&j).copied());
                assert_eq!(ix.suivante(j), modele.range(j..).next().map(|(&k, _)| k));
                let mut t = j;
                while modele.contains_key(&t) {
                    t += 1;
                }
                assert_eq!(ix.trou(j), t);
            }
            let mut toutes = Vec::new();
            ix.parcourir(|i, p| toutes.push((i, p)));
            assert_eq!(toutes, modele.into_iter().collect::<Vec<_>>());
        }
    }
}
