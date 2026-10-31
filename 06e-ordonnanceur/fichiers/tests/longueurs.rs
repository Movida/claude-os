//! PATH_MAX pour Vue::chemin et Vue::chemin_de, à travers un montage : la
//! même borne que Tmpfs::chemin (4095 octets acceptés, 4096 refusés),
//! que le point de montage soit court ou presque à la limite.

use fichiers::chemins::{Arbre, Dernier, Fin};
use fichiers::montages::{Objet, Systeme, Vue};
use fichiers::noyaufs::{Contenu, Genre, NoyauFs};
use fichiers::tmpfs::{Limites, Numero, Tmpfs};
use fichiers::{Erreur, Identite, S_IFDIR, Temps};

fn creer(fs: &mut Tmpfs, parent: Numero, nom: &[u8]) -> Numero {
    let fin = Fin { dossier: parent, nom: nom.to_vec(), objet: None, dernier: Dernier::Nom, barre: false };
    fs.creer(Identite::ROOT, &fin, S_IFDIR | 0o755, (0, 0), b"", Temps::default()).unwrap()
}

/// Un point de montage à `/xxx...` (longueur `l_point`, un seul composant
/// d'au plus 255, plusieurs sinon), puis dans le système monté des
/// dossiers de façon à atteindre `l_total`.
fn essai(l_point: usize, l_total: usize) -> (Result<usize, Erreur>, Result<usize, Erreur>, Result<usize, Erreur>) {
    let mut fs = Tmpfs::new(Limites { inodes: 10000, pages: 0 }, Temps::default()).unwrap();
    let mut d = fs.racine();
    let mut l = 0;
    while l < l_point {
        let n = (l_point - l - 1).min(255);
        d = creer(&mut fs, d, &vec![b'p'; n.max(1)]);
        l += 1 + n.max(1);
    }
    let mut m = NoyauFs::new(Genre::Proc, (0, 21), 0o555, Temps::default()).unwrap();
    let mut n = m.racine();
    let mut total = l;
    let mut dernier_nom = 0;
    while total < l_total {
        let k = (l_total - total - 1).min(255).max(1);
        n = m.ajouter(n, &vec![b'q'; k], 0o555, (0, 0), Contenu::Dossier, false, Temps::default()).unwrap();
        total += 1 + k;
        dernier_nom = k;
    }
    let montes = [(d, m)];
    let vue = Vue { fs: &fs, montes: &montes, lecteur: b"", fil: b"" };
    let o = Objet::Monte(Systeme(0), n);
    let chemin = vue.chemin(o).map(|c| c.len());
    // Le même chemin, comme nom à créer dans le parent.
    let parent = vue.parent(o);
    let nom = if dernier_nom > 0 { vec![b'q'; dernier_nom] } else { vec![] };
    let fin = Fin { dossier: parent, nom, objet: Some(o), dernier: Dernier::Nom, barre: false };
    let de = vue.chemin_de(&fin).map(|c| c.len());
    // Le même pour le tmpfs seul : un chemin de la même longueur.
    let mut fs2 = Tmpfs::new(Limites { inodes: 10000, pages: 0 }, Temps::default()).unwrap();
    let mut d2 = fs2.racine();
    let mut l2 = 0;
    while l2 < l_total {
        let k = (l_total - l2 - 1).min(255).max(1);
        d2 = creer(&mut fs2, d2, &vec![b'r'; k]);
        l2 += 1 + k;
    }
    let t = fs2.chemin(d2).map(|c| c.len());
    (chemin, de, t)
}

#[test]
fn bornes() {
    for &(lp, lt) in &[(5usize, 4094usize), (5, 4095), (5, 4096), (5, 4097), (4090, 4095), (4093, 4096), (300, 4095), (300, 4096)] {
        let (c, de, t) = essai(lp, lt);
        eprintln!("point {lp:>4}, total {lt}: Vue::chemin {c:?}, chemin_de {de:?}, Tmpfs::chemin {t:?}");
        assert_eq!(c, t, "chemin {lp} {lt}");
        assert_eq!(de, t, "chemin_de {lp} {lt}");
    }
}
