//! Les adhésions et les filtres de sources : chaque suite mesurée sous
//! Linux 6.18.33 (une sonde, les options de multidiffusion une à une, puis
//! /proc/net/igmp et /proc/net/mcfilter), sur une machine où lo est 1
//! (127.0.0.1) et la carte 2 (172.17.0.2, la route vers les groupes).
//! L'appelant (ici `trouver`) fait ce que fait `ip_mc_find_dev`.

use inet::multidiffusion::{Adhesions, Demande, Groupes, Mode, Refus, IGMP};

const LO: u32 = 1;
const ETH: u32 = 2;
const NOUS: [u8; 4] = [172, 17, 0, 2];
const RIEN: [u8; 4] = [0; 4];

/// `ip_mc_find_dev` sur cette machine : l'index s'il existe, sinon
/// l'interface de l'adresse (127.0.0.0/8 : lo), sinon celle de la route
/// vers le groupe (la carte).
fn trouver(d: Demande) -> Option<u32> {
    if d.index != 0 {
        return [LO, ETH].contains(&d.index).then_some(d.index);
    }
    if d.adresse != RIEN {
        return if d.adresse[0] == 127 { Some(LO) } else if d.adresse == NOUS { Some(ETH) } else { None };
    }
    Some(ETH)
}

fn demande(groupe: [u8; 4], adresse: [u8; 4], index: u32) -> Demande {
    Demande { groupe, adresse, index }
}

/// Le hasard et la MTU de la machine : sans importance ici (aucun test de
/// ce fichier ne regarde les rapports d'IGMP, `tests/igmp.rs`).
fn zero(_: u32) -> u32 {
    0
}

fn mtu(_: u32) -> u32 {
    1500
}

fn machine() -> Groupes {
    let mut g = Groupes::new(zero, mtu);
    g.monter(ETH, true).unwrap();
    g.monter(LO, false).unwrap();
    g
}

/// /proc/net/igmp : par interface, ses groupes (le plus récent d'abord) et
/// leurs membres.
fn igmp(g: &Groupes) -> Vec<(u32, Vec<([u8; 4], u32)>)> {
    g.interfaces().map(|i| (i.index(), i.groupes().map(|x| (x.adresse(), x.utilisateurs())).collect())).collect()
}

/// /proc/net/mcfilter : chaque source de chaque groupe, avec les sockets
/// qui l'incluent et celles qui l'excluent.
fn mcfilter(g: &Groupes) -> Vec<(u32, [u8; 4], [u8; 4], u32, u32)> {
    let mut v = Vec::new();
    for i in g.interfaces() {
        for x in i.groupes() {
            for s in x.sources() {
                v.push((i.index(), x.adresse(), s.adresse(), s.inclus(), s.exclus()));
            }
        }
    }
    v
}

fn joindre(a: &mut Adhesions, g: &mut Groupes, d: Demande, mode: Mode) -> Result<u32, Refus> {
    a.joindre(g, d, trouver(d), mode)
}

fn quitter(a: &mut Adhesions, g: &mut Groupes, d: Demande) -> Result<(), Refus> {
    a.quitter(g, d, trouver(d))
}

/// IP_BLOCK_SOURCE et les autres (`ip_mreq_source`, `ip_mc_source`).
fn source(a: &mut Adhesions, g: &mut Groupes, ajout: bool, mode: Mode, groupe: [u8; 4], s: [u8; 4]) -> Result<(), Refus> {
    let d = demande(groupe, RIEN, 0);
    a.source(g, ajout, mode, d, trouver(d), s)
}

/// IP_ADD_SOURCE_MEMBERSHIP : adhérer en INCLUDE (EADDRINUSE ignoré), puis
/// ajouter la source, d'un seul tenant.
fn ajouter_source(a: &mut Adhesions, g: &mut Groupes, groupe: [u8; 4], s: [u8; 4]) -> Result<(), Refus> {
    let d = demande(groupe, RIEN, 0);
    a.joindre_avec_source(g, d, trouver(d), s)
}

fn filtre(a: &Adhesions, groupe: [u8; 4], d: Demande) -> Result<(Mode, Vec<[u8; 4]>), Refus> {
    a.filtre(groupe, trouver(d)).map(|(m, s)| (m, s.to_vec()))
}

fn dix(n: u8) -> [u8; 4] {
    [10, 0, 0, n]
}

#[test]
fn chaque_interface_a_tous_les_hotes() {
    let g = machine();
    assert_eq!(igmp(&g), vec![(LO, vec![([224, 0, 0, 1], 1)]), (ETH, vec![([224, 0, 0, 1], 1)])]);
}

/// IP_ADD_MEMBERSHIP et IP_DROP_MEMBERSHIP, dans l'ordre de la sonde.
#[test]
fn adhesions() {
    let mut g = machine();
    let mut a = Adhesions::new();
    let g3 = [239, 1, 2, 3];
    assert_eq!(joindre(&mut a, &mut g, demande([10, 0, 0, 1], RIEN, 0), Mode::Exclure), Err(Refus::Invalide));
    assert_eq!(joindre(&mut a, &mut g, demande([255; 4], RIEN, 0), Mode::Exclure), Err(Refus::Invalide));
    assert_eq!(joindre(&mut a, &mut g, demande([224, 0, 0, 1], RIEN, 0), Mode::Exclure), Ok(ETH));
    assert_eq!(joindre(&mut a, &mut g, demande(g3, RIEN, 0), Mode::Exclure), Ok(ETH));
    for d in [demande(g3, RIEN, 0), demande(g3, RIEN, ETH), demande(g3, NOUS, 0)] {
        assert_eq!(joindre(&mut a, &mut g, d, Mode::Exclure), Err(Refus::DejaMembre), "{d:?}");
    }
    assert_eq!(joindre(&mut a, &mut g, demande(g3, RIEN, LO), Mode::Exclure), Ok(LO));
    for d in [demande(g3, [127, 0, 0, 1], 0), demande(g3, [127, 0, 0, 2], 0)] {
        assert_eq!(joindre(&mut a, &mut g, d, Mode::Exclure), Err(Refus::DejaMembre), "{d:?}");
    }
    assert_eq!(joindre(&mut a, &mut g, demande([239, 1, 2, 4], RIEN, 9999), Mode::Exclure), Err(Refus::PasDInterface));
    assert_eq!(joindre(&mut a, &mut g, demande([239, 1, 2, 4], [1, 2, 3, 4], 0), Mode::Exclure), Err(Refus::PasDInterface));
    // L'index l'emporte : l'adresse est gardée telle quelle.
    assert_eq!(joindre(&mut a, &mut g, demande([239, 1, 2, 4], [1, 2, 3, 4], LO), Mode::Exclure), Ok(LO));
    assert_eq!(joindre(&mut a, &mut g, demande([239, 1, 2, 5], RIEN, 0), Mode::Exclure), Ok(ETH));
    assert_eq!(igmp(&g), vec![
        (LO, vec![([239, 1, 2, 4], 1), (g3, 1), ([224, 0, 0, 1], 1)]),
        (ETH, vec![([239, 1, 2, 5], 1), (g3, 1), ([224, 0, 0, 1], 2)]),
    ]);
    // 20 adhésions par socket.
    for n in 0..15 {
        assert_eq!(joindre(&mut a, &mut g, demande([239, 2, 0, n], RIEN, 0), Mode::Exclure), Ok(ETH));
    }
    assert_eq!(joindre(&mut a, &mut g, demande([239, 2, 0, 99], RIEN, 0), Mode::Exclure), Err(Refus::PlusDePlace));
    assert_eq!(quitter(&mut a, &mut g, demande(g3, RIEN, 0)), Ok(()));
    assert_eq!(quitter(&mut a, &mut g, demande(g3, RIEN, 0)), Err(Refus::Introuvable));
    assert_eq!(quitter(&mut a, &mut g, demande(g3, RIEN, 9999)), Err(Refus::Introuvable));
    assert_eq!(quitter(&mut a, &mut g, demande(g3, [1, 2, 3, 4], 0)), Err(Refus::Introuvable));
    assert_eq!(quitter(&mut a, &mut g, demande(g3, [127, 0, 0, 1], 0)), Ok(()));
    // Pas de contrôle du groupe : la route mène à la carte, sans adhésion.
    assert_eq!(quitter(&mut a, &mut g, demande([10, 0, 0, 1], RIEN, 0)), Err(Refus::Introuvable));
    assert_eq!(joindre(&mut a, &mut g, demande(g3, RIEN, 0), Mode::Exclure), Ok(ETH));
    // La fermeture rend tout.
    a.vider(&mut g);
    assert!(a.est_vide());
    assert_eq!(igmp(&g), igmp(&machine()));
}

/// Quitter par l'adresse seule, quand elle n'est pas à nous : l'adhésion
/// faite avec elle (et un index) part, et son interface perd le groupe (Linux
/// le lui laisse, sans plus aucune socket).
#[test]
fn quitter_par_une_adresse_d_ailleurs() {
    let mut g = machine();
    let mut a = Adhesions::new();
    let g4 = [239, 1, 2, 4];
    assert_eq!(joindre(&mut a, &mut g, demande(g4, [1, 2, 3, 4], LO), Mode::Exclure), Ok(LO));
    assert_eq!(quitter(&mut a, &mut g, demande(g4, [1, 2, 3, 4], 0)), Ok(()));
    assert_eq!(igmp(&g), igmp(&machine()));
    // Sans index, sans adresse et sans route : ENODEV (ici, la route existe :
    // seul un appelant sans route le voit).
    assert_eq!(a.quitter(&mut g, demande(g4, RIEN, 0), None), Err(Refus::PasDInterface));
}

/// Les sources d'une adhésion (IP_BLOCK_SOURCE, IP_ADD_SOURCE_MEMBERSHIP...),
/// IP_MSFILTER lu, /proc/net/mcfilter : la suite de la sonde.
#[test]
fn sources() {
    let mut g = machine();
    let mut a = Adhesions::new();
    let g3 = [239, 3, 3, 3];
    let ex = Mode::Exclure;
    assert_eq!(source(&mut a, &mut g, true, ex, g3, dix(1)), Err(Refus::Invalide));
    assert_eq!(source(&mut a, &mut g, true, ex, [10, 0, 0, 9], dix(1)), Err(Refus::Invalide));
    assert_eq!(joindre(&mut a, &mut g, demande(g3, RIEN, 0), ex), Ok(ETH));
    let d = demande(g3, [1, 2, 3, 4], 0);
    assert_eq!(a.source(&mut g, true, ex, d, trouver(d), dix(1)), Err(Refus::PasDInterface));
    assert_eq!(source(&mut a, &mut g, false, ex, g3, dix(1)), Err(Refus::Introuvable));
    assert_eq!(source(&mut a, &mut g, true, ex, g3, dix(1)), Ok(()));
    assert_eq!(source(&mut a, &mut g, true, ex, g3, dix(1)), Err(Refus::Introuvable));
    assert_eq!(source(&mut a, &mut g, false, ex, g3, dix(2)), Err(Refus::Introuvable));
    assert_eq!(ajouter_source(&mut a, &mut g, g3, dix(3)), Err(Refus::Invalide));
    assert_eq!(source(&mut a, &mut g, false, Mode::Inclure, g3, dix(1)), Err(Refus::Invalide));
    // Dix sources, ajoutées en fin de liste ; la onzième : ENOBUFS, même
    // déjà là.
    for n in (10..=18).rev() {
        assert_eq!(source(&mut a, &mut g, true, ex, g3, dix(n)), Ok(()));
    }
    assert_eq!(source(&mut a, &mut g, true, ex, g3, dix(9)), Err(Refus::PlusDePlace));
    assert_eq!(source(&mut a, &mut g, true, ex, g3, dix(1)), Err(Refus::PlusDePlace));
    let liste: Vec<[u8; 4]> = [1, 18, 17, 16, 15, 14, 13, 12, 11, 10].into_iter().map(dix).collect();
    assert_eq!(filtre(&a, g3, demande(g3, RIEN, 0)), Ok((ex, liste.clone())));
    assert_eq!(filtre(&a, [239, 3, 3, 4], demande(g3, RIEN, 0)), Err(Refus::Introuvable));
    assert_eq!(filtre(&a, dix(1), demande(g3, RIEN, 0)), Err(Refus::Invalide));
    assert_eq!(filtre(&a, g3, demande(g3, [1, 2, 3, 4], 0)), Err(Refus::PasDInterface));
    assert_eq!(a.filtre_par_index(g3, ETH).map(|(m, s)| (m, s.to_vec())), Ok((ex, liste.clone())));
    assert_eq!(a.filtre_par_index(g3, 0).map(|(m, _)| m), Err(Refus::Introuvable));
    let attendu: Vec<_> = liste.iter().map(|&s| (ETH, g3, s, 0, 1)).collect();
    assert_eq!(mcfilter(&g), attendu);
    assert_eq!(source(&mut a, &mut g, false, ex, g3, dix(1)), Ok(()));
    assert_eq!(filtre(&a, g3, demande(g3, RIEN, 0)).map(|(_, s)| s), Ok(liste[1..].to_vec()));
    assert_eq!(quitter(&mut a, &mut g, demande(g3, RIEN, 0)), Ok(()));
    assert_eq!(mcfilter(&g), vec![]);

    // INCLUDE : IP_ADD_SOURCE_MEMBERSHIP adhère d'abord.
    let g5 = [239, 3, 3, 5];
    assert_eq!(ajouter_source(&mut a, &mut g, g5, dix(1)), Ok(()));
    assert_eq!(ajouter_source(&mut a, &mut g, g5, dix(2)), Ok(()));
    assert_eq!(ajouter_source(&mut a, &mut g, g5, dix(2)), Err(Refus::Introuvable));
    assert_eq!(joindre(&mut a, &mut g, demande(g5, RIEN, 0), ex), Err(Refus::DejaMembre));
    assert_eq!(source(&mut a, &mut g, true, ex, g5, dix(3)), Err(Refus::Invalide));
    assert_eq!(filtre(&a, g5, demande(g5, RIEN, 0)), Ok((Mode::Inclure, vec![dix(1), dix(2)])));
    assert_eq!(mcfilter(&g), vec![(ETH, g5, dix(1), 1, 0), (ETH, g5, dix(2), 1, 0)]);
    // La dernière source d'un INCLUDE retirée : le groupe est quitté.
    assert_eq!(source(&mut a, &mut g, false, Mode::Inclure, g5, dix(1)), Ok(()));
    assert_eq!(source(&mut a, &mut g, false, Mode::Inclure, g5, dix(2)), Ok(()));
    assert_eq!(filtre(&a, g5, demande(g5, RIEN, 0)), Err(Refus::Introuvable));
    assert_eq!(quitter(&mut a, &mut g, demande(g5, RIEN, 0)), Err(Refus::Introuvable));

    // Une adhésion simple sans liste change de mode à la première source.
    let g6 = [239, 3, 3, 6];
    assert_eq!(joindre(&mut a, &mut g, demande(g6, RIEN, 0), ex), Ok(ETH));
    assert_eq!(ajouter_source(&mut a, &mut g, g6, dix(1)), Ok(()));
    assert_eq!(filtre(&a, g6, demande(g6, RIEN, 0)), Ok((Mode::Inclure, vec![dix(1)])));
    assert_eq!(mcfilter(&g), vec![(ETH, g6, dix(1), 1, 0)]);
    a.vider(&mut g);
    assert_eq!(igmp(&g), igmp(&machine()));
}

/// Une liste vidée reste une liste : le mode ne change plus (Linux :
/// `pmc->sflist` non nul). Retirer une source sans liste change pourtant le
/// mode, avant de dire EADDRNOTAVAIL : une adhésion simple devient INCLUDE
/// {}, et l'interface la compte ainsi ; la socket ne reçoit plus rien du
/// groupe (`ip_mc_sf_allow` : INCLUDE sans liste, rien ne passe).
#[test]
fn liste_videe_et_changement_de_mode() {
    let mut g = machine();
    let mut a = Adhesions::new();
    let g7 = [239, 3, 3, 7];
    let ex = Mode::Exclure;
    assert_eq!(joindre(&mut a, &mut g, demande(g7, RIEN, 0), ex), Ok(ETH));
    assert_eq!(source(&mut a, &mut g, true, ex, g7, dix(1)), Ok(()));
    assert_eq!(source(&mut a, &mut g, false, ex, g7, dix(1)), Ok(()));
    assert_eq!(ajouter_source(&mut a, &mut g, g7, dix(2)), Err(Refus::Invalide));
    let g8 = [239, 3, 3, 8];
    assert_eq!(joindre(&mut a, &mut g, demande(g8, RIEN, 0), ex), Ok(ETH));
    assert!(a.permet(g8, dix(1), ETH, false));
    assert_eq!(source(&mut a, &mut g, false, Mode::Inclure, g8, dix(1)), Err(Refus::Introuvable));
    assert!(!a.permet(g8, dix(1), ETH, true));
    assert_eq!(filtre(&a, g8, demande(g8, RIEN, 0)), Ok((Mode::Inclure, vec![])));
    let x = g.interface(ETH).unwrap().groupe(g8).unwrap();
    assert_eq!(x.mode(), Mode::Inclure);
    assert!(!g.verifier(ETH, g8, dix(1), 17));
}

/// IP_MSFILTER et MCAST_MSFILTER posés, puis MCAST_*_SOURCE.
#[test]
fn filtres() {
    let mut g = machine();
    let mut a = Adhesions::new();
    let ex = Mode::Exclure;
    let g6 = [239, 3, 3, 6];
    let filtrer = |a: &mut Adhesions, g: &mut Groupes, d: Demande, fmode: u32, s: &[[u8; 4]]| a.filtrer(g, d, trouver(d), fmode, s);
    let d6 = demande(g6, RIEN, 0);
    assert_eq!(filtrer(&mut a, &mut g, demande(dix(1), RIEN, 0), 0, &[]), Err(Refus::Invalide));
    assert_eq!(filtrer(&mut a, &mut g, d6, 2, &[]), Err(Refus::Invalide));
    assert_eq!(filtrer(&mut a, &mut g, d6, 0, &[]), Err(Refus::Invalide));
    assert_eq!(filtrer(&mut a, &mut g, d6, 1, &[]), Err(Refus::Introuvable));
    assert_eq!(filtrer(&mut a, &mut g, demande(g6, [1, 2, 3, 4], 0), 0, &[]), Err(Refus::PasDInterface));
    assert_eq!(joindre(&mut a, &mut g, d6, ex), Ok(ETH));
    assert_eq!(ajouter_source(&mut a, &mut g, g6, dix(1)), Ok(()));
    let un = [[10, 1, 1, 1], [10, 1, 1, 2], [10, 1, 1, 3]];
    assert_eq!(filtrer(&mut a, &mut g, d6, 0, &un), Ok(()));
    assert_eq!(filtre(&a, g6, d6), Ok((ex, un.to_vec())));
    assert_eq!(mcfilter(&g), un.iter().map(|&s| (ETH, g6, s, 0, 1)).collect::<Vec<_>>());
    assert_eq!(filtrer(&mut a, &mut g, d6, 1, &un[..2]), Ok(()));
    assert_eq!(filtre(&a, g6, d6), Ok((Mode::Inclure, un[..2].to_vec())));
    assert_eq!(mcfilter(&g), vec![(ETH, g6, un[0], 1, 0), (ETH, g6, un[1], 1, 0)]);
    // INCLUDE {} : le départ.
    assert_eq!(filtrer(&mut a, &mut g, d6, 1, &[]), Ok(()));
    assert_eq!(filtre(&a, g6, d6), Err(Refus::Introuvable));
    // MCAST_MSFILTER : par l'index (0 : la route).
    let g8 = [239, 3, 3, 8];
    let deux = [[10, 2, 2, 1], [10, 2, 2, 2]];
    assert_eq!(joindre(&mut a, &mut g, demande(g8, RIEN, ETH), ex), Ok(ETH));
    assert_eq!(filtrer(&mut a, &mut g, demande(g8, RIEN, ETH), 1, &deux), Ok(()));
    assert_eq!(a.filtre_par_index(g8, ETH).map(|(m, s)| (m, s.to_vec())), Ok((Mode::Inclure, deux.to_vec())));
    assert_eq!(filtrer(&mut a, &mut g, demande(g8, RIEN, 0), 0, &deux[..1]), Ok(()));
    assert_eq!(a.filtre_par_index(g8, ETH).map(|(m, s)| (m, s.to_vec())), Ok((ex, deux[..1].to_vec())));
    // MCAST_JOIN_SOURCE_GROUP : adhérer en INCLUDE par l'index, puis la
    // source par l'interface trouvée.
    let g9 = [239, 3, 3, 9];
    for (s, index) in [(dix(1), ETH), (dix(2), 0)] {
        let d = demande(g9, RIEN, index);
        let k = match a.joindre(&mut g, d, trouver(d), Mode::Inclure) {
            Ok(k) => k,
            Err(Refus::DejaMembre) => trouver(d).unwrap(),
            Err(e) => panic!("{e:?}"),
        };
        let d = demande(g9, RIEN, k);
        assert_eq!(a.source(&mut g, true, Mode::Inclure, d, trouver(d), s), Ok(()));
    }
    assert_eq!(a.filtre_par_index(g9, ETH).map(|(m, s)| (m, s.to_vec())), Ok((Mode::Inclure, vec![dix(1), dix(2)])));
    let d = demande(g9, RIEN, ETH);
    assert_eq!(a.source(&mut g, true, ex, d, trouver(d), dix(3)), Err(Refus::Invalide));
    assert_eq!(a.source(&mut g, false, Mode::Inclure, d, trouver(d), dix(1)), Ok(()));
    assert_eq!(igmp(&g)[1], (ETH, vec![(g9, 1), (g8, 1), ([224, 0, 0, 1], 1)]));
    assert_eq!(mcfilter(&g), vec![(ETH, g9, dix(2), 1, 0), (ETH, g8, deux[0], 0, 1)]);
}

/// Le filtre de l'interface réunit ceux de ses sockets (RFC 3376, 3.2), et
/// celui de chaque socket décide de ce qu'elle reçoit.
#[test]
fn filtre_de_l_interface() {
    let mut g = machine();
    let (mut a, mut b, mut c) = (Adhesions::new(), Adhesions::new(), Adhesions::new());
    let gr = [239, 9, 9, 9];
    let (s1, s2, s3) = (dix(1), dix(2), dix(3));
    let ex = Mode::Exclure;
    let udp = 17;
    // Rien : rien n'entre, pas même IGMP ; 224.0.0.1, tout.
    assert!(!g.verifier(ETH, gr, s1, IGMP));
    assert!(g.verifier(ETH, [224, 0, 0, 1], s1, udp));
    // A : EXCLUDE {S1} ; B : EXCLUDE {S1, S2}.
    joindre(&mut a, &mut g, demande(gr, RIEN, 0), ex).unwrap();
    source(&mut a, &mut g, true, ex, gr, s1).unwrap();
    joindre(&mut b, &mut g, demande(gr, RIEN, 0), ex).unwrap();
    source(&mut b, &mut g, true, ex, gr, s1).unwrap();
    source(&mut b, &mut g, true, ex, gr, s2).unwrap();
    assert!(!g.verifier(ETH, gr, s1, udp), "exclue par toutes");
    assert!(g.verifier(ETH, gr, s2, udp), "exclue par une seule");
    assert!(g.verifier(ETH, gr, s3, udp));
    assert!(g.verifier(ETH, gr, s1, IGMP));
    assert!(g.verifier(ETH, gr, RIEN, udp));
    assert!(!g.verifier(LO, gr, s3, udp), "pas par lo");
    assert!(!a.permet(gr, s1, ETH, true) && a.permet(gr, s2, ETH, false) && !b.permet(gr, s2, ETH, true));
    // Par une autre interface, ou pour un autre groupe : IP_MULTICAST_ALL.
    assert!(a.permet(gr, s1, LO, true) && !a.permet(gr, s1, LO, false));
    assert!(a.permet([239, 1, 1, 1], s1, ETH, true) && !a.permet([239, 1, 1, 1], s1, ETH, false));
    assert!(a.permet([10, 0, 2, 15], s1, ETH, false), "pas une multidiffusion");
    // C : INCLUDE {S1} : S1 entre de nouveau.
    joindre(&mut c, &mut g, demande(gr, RIEN, 0), Mode::Inclure).unwrap();
    source(&mut c, &mut g, true, Mode::Inclure, gr, s1).unwrap();
    assert!(g.verifier(ETH, gr, s1, udp));
    assert!(c.permet(gr, s1, ETH, false) && !c.permet(gr, s2, ETH, true));
    assert_eq!(g.interface(ETH).unwrap().groupe(gr).unwrap().mode(), ex);
    // A et B partis : le filtre passe en INCLUDE {S1}.
    a.vider(&mut g);
    b.vider(&mut g);
    let x = g.interface(ETH).unwrap().groupe(gr).unwrap();
    assert_eq!((x.mode(), x.utilisateurs()), (Mode::Inclure, 1));
    assert!(g.verifier(ETH, gr, s1, udp) && !g.verifier(ETH, gr, s3, udp));
    assert_eq!(mcfilter(&g), vec![(ETH, gr, s1, 1, 0)]);
    c.vider(&mut g);
    assert_eq!(igmp(&g), igmp(&machine()));
}

/// Une liste qui s'est vidée rend sa place (`rendre_la_place`, de la
/// bibliothèque faillible, que prennent les groupes d'une interface, leurs
/// sources et les adhésions d'une socket) : ce qu'un programme a fait
/// grandir est rendu quand il le défait.
#[test]
fn la_place_rendue() {
    use faillible::VecFaillible;
    let mut v: Vec<u64> = Vec::new();
    v.ajouter(0).unwrap();
    let depart = v.capacity();
    for n in 1..40 {
        v.ajouter(n).unwrap();
    }
    assert_eq!(v.capacity(), 64);
    v.truncate(17);
    v.rendre_la_place();
    assert_eq!((v.len(), v.capacity()), (17, 64), "pas encore le quart");
    v.truncate(16);
    v.rendre_la_place();
    assert_eq!((v.len(), v.capacity(), v[15]), (16, 32, 15));
    v.truncate(1);
    v.rendre_la_place();
    assert_eq!(v.capacity(), depart);
}

/// /proc/net/dev_mcast d'une interface : les trois derniers octets de
/// chaque adresse MAC de groupe (01:00:5e devant), et ses groupes.
fn macs(g: &Groupes, index: u32) -> Vec<([u8; 3], u32)> {
    let i = g.interface(index).unwrap();
    i.macs().iter().map(|m| {
        assert_eq!(m.adresse[..3], [0x01, 0x00, 0x5e]);
        ([m.adresse[3], m.adresse[4], m.adresse[5]], m.groupes)
    }).collect()
}

/// Les adresses MAC de groupe de la carte, dans l'ordre de la sonde
/// (`reseau.c`, mesuré sous Linux 6.18.33) : une par groupe, 239.129.2.3
/// sur celle de 239.1.2.3 (23 bits) ; un groupe parti laisse l'adresse à
/// sa place pour l'autre, puis elle part avec lui ; un groupe revenu la
/// remet à la fin. lo n'en a aucune. Chaque changement de groupe touche la
/// liste (même quand seul un compte change) ; une adhésion de plus à un
/// groupe déjà là, non.
#[test]
fn adresses_mac_des_groupes() {
    let mut g = machine();
    assert!(g.prendre_les_macs_touchees(), "224.0.0.1 des deux interfaces");
    assert!(!g.prendre_les_macs_touchees());
    assert_eq!(macs(&g, ETH), vec![([0, 0, 1], 1)]);
    assert_eq!(macs(&g, LO), vec![]);
    let (mut s, mut q) = (Adhesions::new(), Adhesions::new());
    let (g3, g5, g129) = ([239, 1, 2, 3], [239, 1, 2, 5], [239, 129, 2, 3]);
    joindre(&mut s, &mut g, demande(g3, RIEN, 0), Mode::Exclure).unwrap();
    joindre(&mut s, &mut g, demande(g3, RIEN, LO), Mode::Exclure).unwrap();
    joindre(&mut s, &mut g, demande(g5, RIEN, 0), Mode::Exclure).unwrap();
    joindre(&mut q, &mut g, demande(g129, RIEN, 0), Mode::Exclure).unwrap();
    assert!(g.prendre_les_macs_touchees());
    assert_eq!(macs(&g, ETH), vec![([0, 0, 1], 1), ([1, 2, 3], 2), ([1, 2, 5], 1)]);
    assert_eq!(macs(&g, LO), vec![]);
    // Un membre de plus pour un groupe déjà là : rien ne change.
    let mut t = Adhesions::new();
    joindre(&mut t, &mut g, demande(g3, RIEN, 0), Mode::Exclure).unwrap();
    assert!(!g.prendre_les_macs_touchees());
    quitter(&mut t, &mut g, demande(g3, RIEN, 0)).unwrap();
    assert!(!g.prendre_les_macs_touchees());
    quitter(&mut s, &mut g, demande(g3, RIEN, 0)).unwrap();
    assert!(g.prendre_les_macs_touchees(), "seul un compte a change");
    assert_eq!(macs(&g, ETH), vec![([0, 0, 1], 1), ([1, 2, 3], 1), ([1, 2, 5], 1)]);
    quitter(&mut q, &mut g, demande(g129, RIEN, 0)).unwrap();
    assert_eq!(macs(&g, ETH), vec![([0, 0, 1], 1), ([1, 2, 5], 1)]);
    joindre(&mut s, &mut g, demande(g3, RIEN, 0), Mode::Exclure).unwrap();
    assert_eq!(macs(&g, ETH), vec![([0, 0, 1], 1), ([1, 2, 5], 1), ([1, 2, 3], 1)]);
    s.vider(&mut g);
    assert!(g.prendre_les_macs_touchees());
    assert_eq!(macs(&g, ETH), vec![([0, 0, 1], 1)]);
    assert_eq!(macs(&g, LO), vec![]);
}

/// Une interface ne monte qu'une fois ; elles sont rangées par index.
#[test]
fn monter() {
    let mut g = Groupes::new(zero, mtu);
    g.monter(3, true).unwrap();
    g.monter(1, false).unwrap();
    g.monter(3, true).unwrap();
    assert_eq!(g.interfaces().map(|i| i.index()).collect::<Vec<_>>(), vec![1, 3]);
    assert_eq!(g.interface(3).unwrap().groupes().count(), 1);
}

#[test]
fn la_memoire_des_options() {
    // Ce que les autres options laissent (`borner`) : chaque adhésion (48 octets), chaque
    // liste de sources neuve (64, ses dix places) ou plus grande, l'ancienne encore comptée,
    // y tient strictement (mesuré : derrière un filtre de 130976 octets, il reste 96 : un
    // groupe passe, le second non ; derrière 130848, 224 : un groupe et sa liste).
    let mut g = machine();
    let mut a = Adhesions::new();
    a.borner(131_072 - 130_976);
    assert_eq!(joindre(&mut a, &mut g, demande([239, 2, 0, 1], RIEN, 0), Mode::Exclure), Ok(ETH));
    assert_eq!(a.memoire(), 48);
    assert_eq!(joindre(&mut a, &mut g, demande([239, 2, 0, 2], RIEN, 0), Mode::Exclure), Err(Refus::PlusDePlace));
    let mut a = Adhesions::new();
    a.borner(131_072 - 130_848);
    for n in 1..=4 {
        assert_eq!(ajouter_source(&mut a, &mut g, [239, 3, 0, 1], dix(n)), Ok(()));
    }
    assert_eq!(a.memoire(), 48 + 64);
    // Un filtre de trois sources (une liste de trois places, 36), puis une quatrième : la
    // liste grandit de dix places (76), l'ancienne encore comptée.
    let mut a = Adhesions::new();
    let d = demande([239, 4, 0, 1], RIEN, 0);
    assert_eq!(joindre(&mut a, &mut g, d, Mode::Exclure), Ok(ETH));
    assert_eq!(a.filtrer(&mut g, d, trouver(d), 0, &[dix(1), dix(2), dix(3)]), Ok(()));
    assert_eq!(a.memoire(), 48 + 36);
    a.borner(48 + 36 + 76);
    assert_eq!(source(&mut a, &mut g, true, Mode::Exclure, [239, 4, 0, 1], dix(4)), Err(Refus::PlusDePlace));
    a.borner(48 + 36 + 77);
    assert_eq!(source(&mut a, &mut g, true, Mode::Exclure, [239, 4, 0, 1], dix(4)), Ok(()));
    assert_eq!(a.memoire(), 48 + 76);
    // IP_MSFILTER : la liste neuve, l'ancienne encore comptée.
    a.borner(48 + 76 + 24 + 8);
    assert_eq!(a.filtrer(&mut g, d, trouver(d), 1, &[dix(1), dix(2)]), Err(Refus::PlusDePlace));
    a.borner(48 + 76 + 24 + 9);
    assert_eq!(a.filtrer(&mut g, d, trouver(d), 1, &[dix(1), dix(2)]), Ok(()));
    assert_eq!(a.memoire(), 48 + 32);
}
