//! Le tmpfs contre un modèle : des milliers d'opérations au hasard (créer,
//! effacer, renommer, lier, écrire, raccourcir) sur un petit arbre,
//! appliquées à la fois au tmpfs et à un modèle naïf, une table « chemin
//! complet → objet » où renommer un dossier, c'est réécrire le début de
//! tous les chemins qui sont dessous. Le modèle est trop simple pour se
//! tromper : chaque opération doit y avoir le même résultat (le même code
//! d'erreur), et après chacune, l'arbre entier du tmpfs (lu par
//! `lire_dossier`, comme le ferait `ls -R`) doit être exactement celui du
//! modèle : mêmes noms, mêmes types, mêmes contenus, mêmes liens physiques.
//!
//! Le hasard vient d'un générateur xorshift écrit ici, avec des graines
//! fixes : un échec se rejoue à l'identique.

use std::collections::BTreeMap;

use fichiers::chemins::{Depart, Suivre, resoudre};
use fichiers::tmpfs::{Cadres, Limites, Numero, Ouverture, Tmpfs};
use fichiers::{Erreur, Identite, S_IFDIR, S_IFLNK, S_IFMT, Temps};

const T0: Temps = Temps { secondes: 1_790_000_000, nanosecondes: 0 };
/// La cible de tous les liens symboliques du modèle : nulle part. Un lien
/// au milieu d'un chemin y mène donc toujours à ENOENT.
const NULLE_PART: &[u8] = b"/nulle/part";

/// Les pages, sur l'hôte.
#[derive(Default)]
struct Hote {
    pages: Vec<Option<Box<[u8; 4096]>>>,
}

impl Cadres for Hote {
    fn allouer(&mut self) -> Option<u64> {
        self.pages.push(Some(Box::new([0; 4096])));
        Some(self.pages.len() as u64)
    }
    fn lacher(&mut self, page: u64) {
        assert!(self.pages[page as usize - 1].take().is_some(), "page rendue deux fois");
    }
    fn ecrire(&mut self, page: u64, decalage: usize, octets: &[u8]) {
        self.pages[page as usize - 1].as_mut().unwrap()[decalage..decalage + octets.len()].copy_from_slice(octets);
    }
    fn lire(&self, page: u64, decalage: usize, tampon: &mut [u8]) {
        tampon.copy_from_slice(&self.pages[page as usize - 1].as_ref().unwrap()[decalage..decalage + tampon.len()]);
    }
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
}

/// Ce que le modèle sait d'un chemin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Objet {
    Dossier,
    /// Un fichier : le numéro de son contenu (deux liens physiques ont le
    /// même).
    Fichier(usize),
    /// Un lien symbolique : son numéro (un lien physique vers un lien
    /// symbolique est le même inode).
    Lien(usize),
}

#[derive(Default)]
struct Modele {
    chemins: BTreeMap<Vec<u8>, Objet>,
    contenus: Vec<Vec<u8>>,
    liens: usize,
}

fn parent(chemin: &[u8]) -> &[u8] {
    let i = chemin.iter().rposition(|&o| o == b'/').unwrap();
    if i == 0 { b"/" } else { &chemin[..i] }
}

/// `a` est-il `b`, ou un de ses ancêtres ?
fn ancetre(a: &[u8], b: &[u8]) -> bool {
    b == a || (a == b"/" && !b.is_empty()) || (b.starts_with(a) && b.get(a.len()) == Some(&b'/'))
}

impl Modele {
    fn objet(&self, chemin: &[u8]) -> Option<Objet> {
        if chemin == b"/" { Some(Objet::Dossier) } else { self.chemins.get(chemin).copied() }
    }

    /// Le dossier parent doit exister et en être un : sinon l'erreur de la
    /// résolution (un lien au milieu mène nulle part).
    fn verifier_parent(&self, chemin: &[u8]) -> Result<(), Erreur> {
        let mut courant = Vec::new();
        let p = parent(chemin);
        if p == b"/" {
            return Ok(());
        }
        for composant in p[1..].split(|&o| o == b'/') {
            courant.push(b'/');
            courant.extend_from_slice(composant);
            match self.objet(&courant) {
                None | Some(Objet::Lien(_)) => return Err(Erreur::ENOENT),
                Some(Objet::Fichier(_)) => return Err(Erreur::ENOTDIR),
                Some(Objet::Dossier) => {}
            }
        }
        Ok(())
    }

    fn vide(&self, dossier: &[u8]) -> bool {
        !self.chemins.keys().any(|c| c.as_slice() != dossier && ancetre(dossier, c))
    }

    fn creer(&mut self, chemin: &[u8], objet: Objet) -> Result<(), Erreur> {
        self.verifier_parent(chemin)?;
        if self.objet(chemin).is_some() {
            return Err(Erreur::EEXIST);
        }
        let objet = match objet {
            Objet::Fichier(_) => {
                self.contenus.push(Vec::new());
                Objet::Fichier(self.contenus.len() - 1)
            }
            Objet::Lien(_) => {
                self.liens += 1;
                Objet::Lien(self.liens)
            }
            o => o,
        };
        self.chemins.insert(chemin.to_vec(), objet);
        Ok(())
    }

    fn effacer(&mut self, chemin: &[u8], dossier: bool) -> Result<(), Erreur> {
        self.verifier_parent(chemin)?;
        let objet = self.objet(chemin).ok_or(Erreur::ENOENT)?;
        match (dossier, objet) {
            (false, Objet::Dossier) => return Err(Erreur::EISDIR),
            (true, Objet::Fichier(_) | Objet::Lien(_)) => return Err(Erreur::ENOTDIR),
            (true, Objet::Dossier) if !self.vide(chemin) => return Err(Erreur::ENOTEMPTY),
            _ => {}
        }
        self.chemins.remove(chemin);
        Ok(())
    }

    fn renommer(&mut self, a: &[u8], b: &[u8]) -> Result<(), Erreur> {
        self.verifier_parent(a)?;
        self.verifier_parent(b)?;
        let source = self.objet(a).ok_or(Erreur::ENOENT)?;
        let cible = self.objet(b);
        if source == Objet::Dossier && ancetre(a, parent(b)) {
            return Err(Erreur::EINVAL);
        }
        if cible == Some(Objet::Dossier) && ancetre(b, parent(a)) {
            return Err(Erreur::ENOTEMPTY);
        }
        if a == b || (cible == Some(source) && source != Objet::Dossier) {
            return Ok(());
        }
        match (source, cible) {
            (Objet::Dossier, Some(Objet::Fichier(_) | Objet::Lien(_))) => return Err(Erreur::ENOTDIR),
            (Objet::Fichier(_) | Objet::Lien(_), Some(Objet::Dossier)) => return Err(Erreur::EISDIR),
            (_, Some(Objet::Dossier)) if !self.vide(b) => return Err(Erreur::ENOTEMPTY),
            _ => {}
        }
        self.chemins.remove(b);
        // Le chemin et tout ce qui est dessous changent de début.
        let deplaces: Vec<Vec<u8>> = self.chemins.keys().filter(|c| ancetre(a, c)).cloned().collect();
        for ancien in deplaces {
            let objet = self.chemins.remove(&ancien).unwrap();
            let mut nouveau = b.to_vec();
            nouveau.extend_from_slice(&ancien[a.len()..]);
            self.chemins.insert(nouveau, objet);
        }
        Ok(())
    }

    fn lier(&mut self, a: &[u8], b: &[u8]) -> Result<(), Erreur> {
        self.verifier_parent(a)?;
        let source = self.objet(a).ok_or(Erreur::ENOENT)?;
        self.verifier_parent(b)?;
        if self.objet(b).is_some() {
            return Err(Erreur::EEXIST);
        }
        if source == Objet::Dossier {
            return Err(Erreur::EPERM);
        }
        self.chemins.insert(b.to_vec(), source);
        Ok(())
    }
}

/// Le tmpfs, et les mêmes opérations, par la résolution des chemins.
struct Reel {
    fs: Tmpfs,
    cadres: Hote,
}

impl Reel {
    fn fin(&self, chemin: &[u8]) -> Result<fichiers::chemins::Fin<Numero>, Erreur> {
        let r = self.fs.racine();
        resoudre(&self.fs, &Depart { racine: r, dossier: r, qui: Identite::ROOT, sous: false }, chemin, Suivre::Jamais)
    }

    fn creer(&mut self, chemin: &[u8], objet: Objet) -> Result<(), Erreur> {
        let f = self.fin(chemin)?;
        match objet {
            Objet::Fichier(_) => {
                let o = Ouverture { creer: true, exclusif: true, ecriture: true, mode: 0o644, ..Default::default() };
                let ouvert = self.fs.ouvrir(Identite::ROOT, &f, &o, T0)?;
                self.fs.fermer(&ouvert, &mut self.cadres);
                Ok(())
            }
            Objet::Dossier => self.fs.creer(Identite::ROOT, &f, S_IFDIR | 0o755, (0, 0), &[], T0).map(|_| ()),
            Objet::Lien(_) => self.fs.creer(Identite::ROOT, &f, S_IFLNK | 0o777, (0, 0), NULLE_PART, T0).map(|_| ()),
        }
    }

    fn effacer(&mut self, chemin: &[u8], dossier: bool) -> Result<(), Erreur> {
        let f = self.fin(chemin)?;
        self.fs.effacer(Identite::ROOT, &f, dossier, T0, &mut self.cadres)
    }

    fn renommer(&mut self, a: &[u8], b: &[u8]) -> Result<(), Erreur> {
        let fa = self.fin(a)?;
        let fb = self.fin(b)?;
        self.fs.renommer(Identite::ROOT, &fa, &fb, 0, T0, &mut self.cadres)
    }

    fn lier(&mut self, a: &[u8], b: &[u8]) -> Result<(), Erreur> {
        let fa = self.fin(a)?;
        let source = fa.objet.ok_or(Erreur::ENOENT)?;
        let fb = self.fin(b)?;
        self.fs.lier(Identite::ROOT, source, &fb, T0)
    }

    /// L'arbre entier : chemin → (type, inode, contenu d'un fichier).
    fn arbre(&self) -> BTreeMap<Vec<u8>, (u32, Numero, Vec<u8>)> {
        let mut tout = BTreeMap::new();
        let mut a_voir = vec![(b"".to_vec(), self.fs.racine())];
        while let Some((chemin, dossier)) = a_voir.pop() {
            self.fs
                .lire_dossier(dossier, 2, |nom, n, _, _| {
                    let mut c = chemin.clone();
                    c.push(b'/');
                    c.extend_from_slice(nom);
                    let genre = self.fs.mode(n) & S_IFMT;
                    let mut contenu = Vec::new();
                    if genre == S_IFDIR {
                        a_voir.push((c.clone(), n));
                    } else if genre != S_IFLNK {
                        contenu.resize(self.fs.attributs(n).taille as usize, 0);
                        self.fs.lire(n, 0, &mut contenu, &self.cadres);
                    }
                    tout.insert(c, (genre, n, contenu));
                    true
                })
                .unwrap();
        }
        tout
    }
}

const NOMS: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];

/// Un chemin au hasard : le plus souvent dans un dossier qui existe,
/// parfois n'importe où (sous un fichier, sous rien).
fn chemin(h: &mut Hasard, m: &Modele) -> Vec<u8> {
    let dossiers: Vec<&Vec<u8>> = m.chemins.iter().filter(|(_, o)| **o == Objet::Dossier).map(|(c, _)| c).collect();
    let mut c = if h.moins_de(5) == 0 || dossiers.is_empty() {
        let mut c = Vec::new();
        for _ in 0..h.moins_de(3) {
            c.push(b'/');
            c.extend_from_slice(NOMS[h.moins_de(4) as usize]);
        }
        c
    } else if h.moins_de(4) == 0 {
        Vec::new()
    } else {
        dossiers[h.moins_de(dossiers.len() as u64) as usize].clone()
    };
    c.push(b'/');
    c.extend_from_slice(NOMS[h.moins_de(4) as usize]);
    c
}

fn comparer(m: &Modele, r: &Reel, operation: &str) {
    r.fs.invariants().unwrap();
    let vivantes = r.cadres.pages.iter().filter(|p| p.is_some()).count() as u64;
    assert_eq!(vivantes, r.fs.occupation().1, "pages comptees");
    let arbre = r.arbre();
    assert_eq!(arbre.keys().collect::<Vec<_>>(), m.chemins.keys().collect::<Vec<_>>(), "les memes chemins apres {operation}");
    // Les liens physiques : deux chemins ont le même inode si et seulement
    // si le modèle leur donne le même contenu.
    let mut inode_de: BTreeMap<usize, Numero> = BTreeMap::new();
    let mut lien_de: BTreeMap<usize, Numero> = BTreeMap::new();
    for (c, objet) in &m.chemins {
        let (genre, n, contenu) = &arbre[c];
        match objet {
            Objet::Dossier => assert_eq!(*genre, S_IFDIR),
            Objet::Lien(id) => {
                assert_eq!(*genre, S_IFLNK);
                assert_eq!(*lien_de.entry(*id).or_insert(*n), *n, "un meme lien, un meme inode");
            }
            Objet::Fichier(id) => {
                assert_eq!(contenu, &m.contenus[*id], "contenu de {}", String::from_utf8_lossy(c));
                assert_eq!(*inode_de.entry(*id).or_insert(*n), *n, "un meme fichier, un meme inode");
                let noms = m.chemins.values().filter(|o| **o == Objet::Fichier(*id)).count() as u32;
                assert_eq!(r.fs.attributs(*n).nlink, noms);
            }
        }
    }
    let distincts: std::collections::BTreeSet<_> = inode_de.values().collect();
    assert_eq!(distincts.len(), inode_de.len(), "deux fichiers, deux inodes");
}

#[test]
fn contre_le_modele() {
    // Combien de fois chaque résultat est sorti : le test ne vaut que s'il
    // passe par toutes les erreurs.
    let mut resultats: BTreeMap<Result<(), Erreur>, usize> = BTreeMap::new();
    for graine in 1..=40u64 {
        let mut h = Hasard(graine.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut m = Modele::default();
        let mut r = Reel { fs: Tmpfs::new(Limites { inodes: 10_000, pages: 10_000 }, T0).unwrap(), cadres: Hote::default() };
        for _ in 0..1500 {
            let texte = |c: &[u8]| String::from_utf8_lossy(c).into_owned();
            let (operation, attendu, obtenu) = match h.moins_de(10) {
                0 | 1 => {
                    let c = chemin(&mut h, &m);
                    (format!("fichier {}", texte(&c)), m.creer(&c, Objet::Fichier(0)), r.creer(&c, Objet::Fichier(0)))
                }
                2 => {
                    let c = chemin(&mut h, &m);
                    (format!("mkdir {}", texte(&c)), m.creer(&c, Objet::Dossier), r.creer(&c, Objet::Dossier))
                }
                3 => {
                    let c = chemin(&mut h, &m);
                    (format!("symlink {}", texte(&c)), m.creer(&c, Objet::Lien(0)), r.creer(&c, Objet::Lien(0)))
                }
                4 => {
                    let c = chemin(&mut h, &m);
                    let d = h.moins_de(2) == 0;
                    (format!("effacer {} {d}", texte(&c)), m.effacer(&c, d), r.effacer(&c, d))
                }
                5 | 6 => {
                    let (a, b) = (chemin(&mut h, &m), chemin(&mut h, &m));
                    (format!("rename {} {}", texte(&a), texte(&b)), m.renommer(&a, &b), r.renommer(&a, &b))
                }
                7 => {
                    let (a, b) = (chemin(&mut h, &m), chemin(&mut h, &m));
                    (format!("link {} {}", texte(&a), texte(&b)), m.lier(&a, &b), r.lier(&a, &b))
                }
                _ => {
                    // Écrire dans un fichier, ou le raccourcir.
                    let fichiers: Vec<(Vec<u8>, usize)> = m.chemins.iter()
                        .filter_map(|(c, o)| if let Objet::Fichier(id) = o { Some((c.clone(), *id)) } else { None })
                        .collect();
                    if fichiers.is_empty() {
                        continue;
                    }
                    let (c, id) = &fichiers[h.moins_de(fichiers.len() as u64) as usize];
                    let n = r.fin(c).unwrap().objet.unwrap();
                    let position = h.moins_de(12_000) as usize;
                    if h.moins_de(3) == 0 {
                        m.contenus[*id].resize(position, 0);
                        r.fs.tronquer(n, position as u64, T0, &mut r.cadres).unwrap();
                    } else {
                        let octets: Vec<u8> = (0..1 + h.moins_de(5000)).map(|_| h.suivant() as u8 | 1).collect();
                        let contenu = &mut m.contenus[*id];
                        if contenu.len() < position + octets.len() {
                            contenu.resize(position + octets.len(), 0);
                        }
                        contenu[position..position + octets.len()].copy_from_slice(&octets);
                        assert_eq!(r.fs.ecrire(n, position as u64, &octets, T0, &mut r.cadres), Ok(octets.len()));
                    }
                    (format!("ecrire {}", texte(c)), Ok(()), Ok(()))
                }
            };
            assert_eq!(obtenu, attendu, "graine {graine} : {operation}");
            *resultats.entry(obtenu).or_default() += 1;
            comparer(&m, &r, &operation);
        }
        // Tout effacer : il ne doit rien rester.
        let mut chemins: Vec<Vec<u8>> = m.chemins.keys().cloned().collect();
        chemins.sort_by_key(|c| std::cmp::Reverse(c.len()));
        for c in chemins {
            let dossier = m.chemins[&c] == Objet::Dossier;
            r.effacer(&c, dossier).unwrap();
        }
        assert_eq!(r.fs.occupation(), (1, 0));
        assert!(r.cadres.pages.iter().all(Option::is_none));
        r.fs.invariants().unwrap();
    }
    for e in [Erreur::ENOENT, Erreur::EEXIST, Erreur::ENOTDIR, Erreur::EISDIR, Erreur::ENOTEMPTY, Erreur::EINVAL, Erreur::EPERM] {
        assert!(resultats.get(&Err(e)).is_some_and(|&n| n >= 20), "{e:?} trop rare : {resultats:?}");
    }
    assert!(resultats[&Ok(())] > 10_000, "{resultats:?}");
}
