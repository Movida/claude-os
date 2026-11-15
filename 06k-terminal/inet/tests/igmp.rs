//! IGMP : les rapports, rejoués tels que les a mesurés une sonde sous Linux
//! 6.18.33 (un pcap de la carte et de lo pendant chaque changement, les cas
//! a et j à q de l'étude de la multidiffusion), sur une machine où lo est 1
//! et la carte 2 (172.17.0.2). Le hasard est fixé (`zero` : chaque minuteur
//! échoit au plus tôt, 2 jiffies après son armement) : les tests disent ce
//! que contient chaque rapport, et son heure quand elle est sûre.

use formats::reseau::igmp::{self, ANCIENNES, DEPART, EST_EXCLURE, NOUVELLES, RAPPORT_V2, VERS_EXCLURE, VERS_INCLURE};
use inet::multidiffusion::{Adhesions, Demande, Envoi, Groupes, Mode, HZ};

const LO: u32 = 1;
const ETH: u32 = 2;
/// Une interface à la plus petite MTU (68 : 44 octets d'IGMP).
const ETROITE: u32 = 3;
const NOUS: [u8; 4] = [172, 17, 0, 2];
const RIEN: [u8; 4] = [0; 4];
const MS: u64 = 1_000_000;
const JIFFY: u64 = 1_000_000_000 / HZ;
const G3: [u8; 4] = [239, 1, 2, 3];

fn zero(_: u32) -> u32 {
    0
}

fn mtu(i: u32) -> u32 {
    match i {
        LO => 65536,
        ETROITE => 68,
        _ => 1500,
    }
}

fn dix(n: u8) -> [u8; 4] {
    [10, 0, 0, n]
}

/// Un message envoyé, lu : un rapport v3 (ses enregistrements : genre,
/// groupe, sources), ou un message v1 ou v2 (genre, groupe).
#[derive(Debug, PartialEq)]
enum Message {
    V3(Vec<(u8, [u8; 4], Vec<[u8; 4]>)>),
    V12(u8, [u8; 4]),
}

fn v3(e: &[(u8, [u8; 4], &[[u8; 4]])]) -> Message {
    Message::V3(e.iter().map(|&(t, g, s)| (t, g, s.to_vec())).collect())
}

/// Ce qu'a envoyé la machine : l'heure (depuis le début du banc), l'interface,
/// la destination, le message.
type Vu = (u64, u32, [u8; 4], Message);

fn lire(t: u64, e: Envoi) -> Vu {
    let m = igmp::lire(&e.octets).expect("un message juste, somme comprise");
    let message = if m.genre == igmp::RAPPORT_V3 {
        assert!(e.v3);
        assert_eq!(e.destination, igmp::ROUTEURS_V3);
        let r = igmp::enregistrements(&e.octets).unwrap();
        Message::V3(r.map(|x| (x.genre, x.groupe, x.sources().collect())).collect())
    } else {
        assert!(!e.v3);
        assert_eq!(e.octets.len(), igmp::ENTETE);
        Message::V12(m.genre, m.groupe)
    };
    (t, e.interface, e.destination, message)
}

/// La machine, son heure, ses adhésions (une socket : r ; une autre : c).
struct Banc {
    g: Groupes,
    debut: u64,
    t: u64,
    r: Adhesions,
    c: Adhesions,
}

impl Banc {
    fn nouveau() -> Banc {
        let mut g = Groupes::new(zero, mtu);
        let t = 1_000_000_000;
        g.regler(t);
        g.monter(ETH).unwrap();
        g.monter(LO).unwrap();
        g.monter(ETROITE).unwrap();
        assert!(g.prendre_les_envois().is_empty());
        assert_eq!(g.prochaine_echeance(), None, "224.0.0.1 ne s'annonce pas");
        Banc { g, debut: t, t, r: Adhesions::new(), c: Adhesions::new() }
    }

    /// Ce qui part tout de suite (un départ v2).
    fn tout_de_suite(&mut self) -> Vec<Vu> {
        let t = self.t - self.debut;
        self.g.prendre_les_envois().into_iter().map(|e| lire(t, e)).collect()
    }

    /// Le temps passe de `duree` : ce que font les minuteurs, dans l'ordre.
    fn attendre(&mut self, duree: u64) -> Vec<Vu> {
        let fin = self.t + duree;
        let mut vus = self.tout_de_suite();
        while let Some(e) = self.g.prochaine_echeance().filter(|&e| e <= fin) {
            self.t = self.t.max(e);
            self.g.regler(self.t);
            self.g.temps();
            vus.extend(self.tout_de_suite());
        }
        self.t = fin;
        self.g.regler(fin);
        vus
    }

    /// Le temps passe jusqu'à ce que plus rien ne reste à dire.
    fn tout(&mut self) -> Vec<Vu> {
        let v = self.attendre(30_000 * MS);
        assert_eq!(self.g.prochaine_echeance(), None);
        v
    }

    fn trouver(d: Demande) -> Option<u32> {
        if d.index != 0 {
            return Some(d.index);
        }
        if d.adresse == NOUS {
            return Some(ETH);
        }
        Some(ETH)
    }

    fn joindre(&mut self, c: bool, groupe: [u8; 4], index: u32) {
        let d = Demande { groupe, adresse: RIEN, index };
        let a = if c { &mut self.c } else { &mut self.r };
        a.joindre(&mut self.g, d, Banc::trouver(d), Mode::Exclure).unwrap();
    }

    fn quitter(&mut self, c: bool, groupe: [u8; 4], index: u32) {
        let d = Demande { groupe, adresse: RIEN, index };
        let a = if c { &mut self.c } else { &mut self.r };
        a.quitter(&mut self.g, d, Banc::trouver(d)).unwrap();
    }

    fn filtrer(&mut self, groupe: [u8; 4], index: u32, mode: Mode, sources: &[[u8; 4]]) {
        let d = Demande { groupe, adresse: RIEN, index };
        self.r.filtrer(&mut self.g, d, Banc::trouver(d), mode.numero(), sources).unwrap();
    }

    fn source(&mut self, ajout: bool, groupe: [u8; 4], index: u32, s: [u8; 4]) {
        let d = Demande { groupe, adresse: RIEN, index };
        self.r.source(&mut self.g, ajout, Mode::Inclure, d, Banc::trouver(d), s).unwrap();
    }

    /// Une requête injectée par l'interface `index`.
    fn requete(&mut self, index: u32, o: &[u8]) {
        self.g.recevoir(index, o, false, true);
    }

    /// /proc/net/igmp d'une interface : sa version, et par groupe (le plus
    /// récent d'abord) son minuteur et le drapeau `Reporter`.
    fn proc(&self, index: u32) -> (u8, Vec<([u8; 4], bool, bool)>) {
        let i = self.g.interface(index).unwrap();
        (i.version(self.t), i.groupes().map(|g| (g.adresse(), g.minuteur().is_some(), g.rapporteur())).collect())
    }
}

/// Une requête v1 ou v2 de 8 octets.
fn requete_v12(code: u8, groupe: [u8; 4]) -> Vec<u8> {
    let mut o = [0u8; 8];
    igmp::ecrire(&mut o, igmp::REQUETE, groupe);
    o[1] = code;
    igmp::sceller(&mut o);
    o.to_vec()
}

/// Une requête v3 : son délai codé, le groupe, QRV, QQIC, les sources.
fn requete_v3(code: u8, groupe: [u8; 4], qrv: u8, qqic: u8, sources: &[[u8; 4]]) -> Vec<u8> {
    let mut o = vec![igmp::REQUETE, code, 0, 0, groupe[0], groupe[1], groupe[2], groupe[3], qrv, qqic];
    o.extend_from_slice(&(sources.len() as u16).to_be_bytes());
    for s in sources {
        o.extend_from_slice(s);
    }
    igmp::sceller(&mut o);
    o
}

fn messages(v: &[Vu]) -> Vec<&Message> {
    v.iter().map(|x| &x.3).collect()
}

/// a. Une adhésion simple par la carte : TO_EX {}, deux fois (qrv 2), le
/// premier 2 jiffies après, le second dans la seconde (ici, au plus tôt).
#[test]
fn adhesion() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    let v = b.tout();
    let to_ex = v3(&[(VERS_EXCLURE, G3, &[])]);
    assert_eq!(v, vec![
        (2 * JIFFY, ETH, igmp::ROUTEURS_V3, v3(&[(VERS_EXCLURE, G3, &[])])),
        (4 * JIFFY, ETH, igmp::ROUTEURS_V3, to_ex),
    ]);
    assert_eq!(b.proc(ETH), (3, vec![(G3, false, false), ([224, 0, 0, 1], false, false)]));
}

/// Le second rapport tombe au hasard dans la seconde (`igmp_ifc_start_timer`
/// avec l'intervalle non sollicité de v3) : avec le plus grand hasard, une
/// seconde et un jiffy plus tard.
#[test]
fn le_hasard_des_rapports() {
    fn max(n: u32) -> u32 {
        n - 1
    }
    let mut g = Groupes::new(max, mtu);
    g.regler(0);
    g.monter(ETH).unwrap();
    let mut a = Adhesions::new();
    let d = Demande { groupe: G3, adresse: RIEN, index: ETH };
    a.joindre(&mut g, d, Some(ETH), Mode::Exclure).unwrap();
    // `igmp_ifc_event` : au hasard dans 1 jiffy, soit 0, plus 2.
    assert_eq!(g.prochaine_echeance(), Some(2 * JIFFY));
    g.regler(2 * JIFFY);
    g.temps();
    assert_eq!(g.prendre_les_envois().len(), 1);
    assert_eq!(g.prochaine_echeance(), Some(2 * JIFFY + (999 + 2) * JIFFY));
}

/// j à n : les filtres d'une socket, puis une autre socket, puis les
/// départs (la suite de la sonde, sur la même adhésion).
#[test]
fn filtres_et_departs() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    b.tout();
    let s1 = [1, 2, 3, 4];
    // j. INCLUDE {1.2.3.4} : TO_IN {1.2.3.4}.
    b.filtrer(G3, 0, Mode::Inclure, &[s1]);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(VERS_INCLURE, G3, &[s1])]); 2]);
    // k. EXCLUDE {1.2.3.4} : TO_EX {1.2.3.4}.
    b.filtrer(G3, 0, Mode::Exclure, &[s1]);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(VERS_EXCLURE, G3, &[s1])]); 2]);
    // l. EXCLUDE {nous} : BLOCK {nous} et ALLOW {1.2.3.4}, dans un rapport.
    b.filtrer(G3, 0, Mode::Exclure, &[NOUS]);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(ANCIENNES, G3, &[NOUS]), (NOUVELLES, G3, &[s1])]); 2]);
    // m. c adhère aussi (ASM) : l'interface n'exclut plus personne : ALLOW
    // {nous}.
    b.joindre(true, G3, 0);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(NOUVELLES, G3, &[NOUS])]); 2]);
    // n. c part : BLOCK {nous} ; puis r : TO_IN {}.
    b.quitter(true, G3, 0);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(ANCIENNES, G3, &[NOUS])]); 2]);
    b.quitter(false, G3, 0);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(VERS_INCLURE, G3, &[])]); 2]);
    assert_eq!(b.proc(ETH), (3, vec![([224, 0, 0, 1], false, false)]));
}

/// o. Une adhésion avec une source (INCLUDE {10.0.0.1}), une de plus, puis
/// leurs départs : ALLOW, ALLOW, BLOCK, BLOCK ; le dernier départ fait
/// partir le groupe, sans TO_IN (un groupe en INCLUDE ne dit que ses
/// sources).
#[test]
fn sources() {
    let mut b = Banc::nouveau();
    let g4 = [239, 1, 2, 4];
    let d = Demande { groupe: g4, adresse: RIEN, index: 0 };
    b.r.joindre(&mut b.g, d, Some(ETH), Mode::Inclure).unwrap();
    b.source(true, g4, 0, dix(1));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(NOUVELLES, g4, &[dix(1)])]); 2]);
    b.source(true, g4, 0, dix(2));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(NOUVELLES, g4, &[dix(2)])]); 2]);
    b.source(false, g4, 0, dix(1));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(ANCIENNES, g4, &[dix(1)])]); 2]);
    b.source(false, g4, 0, dix(2));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(ANCIENNES, g4, &[dix(2)])]); 2]);
    assert!(b.g.interface(ETH).unwrap().groupe(g4).is_none());
}

/// p. 224.0.0.251, un groupe du lien : annoncé comme un autre.
#[test]
fn groupe_du_lien() {
    let mut b = Banc::nouveau();
    let mdns = [224, 0, 0, 251];
    b.joindre(false, mdns, 0);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(VERS_EXCLURE, mdns, &[])]); 2]);
    b.quitter(false, mdns, 0);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(VERS_INCLURE, mdns, &[])]); 2]);
}

/// Un groupe qui revient avant que son départ soit dit : ce qui restait à
/// dire de lui reprend (`igmpv3_del_delrec`), son mode pour `qrv`
/// rapports ; le départ n'est plus annoncé.
#[test]
fn retour_avant_la_fin_du_depart() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    b.tout();
    b.quitter(false, G3, 0);
    let v = b.attendre(3 * JIFFY);
    assert_eq!(messages(&v), vec![&v3(&[(VERS_INCLURE, G3, &[])])]);
    b.joindre(false, G3, 0);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(VERS_EXCLURE, G3, &[])]); 2]);
}

/// q. Par lo : l'adhésion, les filtres, les requêtes v3 (générale, de
/// groupe, d'un groupe absent, de délai 0), puis une requête v2 : les
/// rapports v2 vers le groupe, une adhésion en v2 (deux rapports), les
/// départs (vers 224.0.0.2, tout de suite : nous avions fait le dernier
/// rapport).
#[test]
fn requetes_par_lo() {
    let mut b = Banc::nouveau();
    let g9 = [239, 9, 9, 9];
    let s9 = [10, 9, 9, 9];
    b.joindre(false, g9, LO);
    let v = b.tout();
    assert_eq!(v.iter().map(|x| (x.1, &x.3)).collect::<Vec<_>>(), vec![(LO, &v3(&[(VERS_EXCLURE, g9, &[])])); 2]);
    b.filtrer(g9, LO, Mode::Exclure, &[s9]);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(ANCIENNES, g9, &[s9])]); 2]);
    b.filtrer(g9, LO, Mode::Exclure, &[]);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(NOUVELLES, g9, &[s9])]); 2]);
    // Une requête générale, délai 2 s (code 20) : un rapport de l'état
    // courant, au hasard dans le délai (ici au plus tôt).
    let t0 = b.t - b.debut;
    b.requete(LO, &requete_v3(20, RIEN, 0, 0, &[]));
    let v = b.tout();
    assert_eq!(v.iter().map(|x| (x.0 - t0, &x.3)).collect::<Vec<_>>(),
               vec![(2 * JIFFY, &v3(&[(EST_EXCLURE, g9, &[])]))]);
    // Une requête du groupe : le minuteur du groupe, un rapport ; elle fait
    // de nous le rapporteur.
    b.requete(LO, &requete_v3(20, g9, 0, 0, &[]));
    assert_eq!(b.proc(LO).1[0], (g9, true, false));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(EST_EXCLURE, g9, &[])])]);
    assert_eq!(b.proc(LO), (3, vec![(g9, false, true), ([224, 0, 0, 1], false, false)]));
    // Un groupe que nous n'avons pas : rien ; délai 0 : au plus tôt.
    b.requete(LO, &requete_v3(20, [239, 9, 9, 7], 0, 0, &[]));
    assert!(b.tout().is_empty());
    b.requete(LO, &requete_v3(0, RIEN, 0, 0, &[]));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(EST_EXCLURE, g9, &[])])]);
    // Une requête v2 : l'interface passe en v2, le rapport aussi.
    b.requete(LO, &requete_v12(20, RIEN));
    assert_eq!(b.proc(LO).0, 2);
    let v = b.tout();
    assert_eq!(v.iter().map(|x| (x.2, &x.3)).collect::<Vec<_>>(), vec![(g9, &Message::V12(RAPPORT_V2, g9))]);
    // Une adhésion en v2 : deux rapports vers le groupe (le second dans les
    // 10 s), sans rapport de changement.
    let g10 = [239, 9, 9, 10];
    b.joindre(false, g10, LO);
    let v = b.tout();
    assert_eq!(v.iter().map(|x| (x.2, &x.3)).collect::<Vec<_>>(),
               vec![(g10, &Message::V12(RAPPORT_V2, g10)), (g10, &Message::V12(RAPPORT_V2, g10))]);
    assert_eq!(b.proc(LO), (2, vec![(g10, false, true), (g9, false, true), ([224, 0, 0, 1], false, false)]));
    // Les départs : tout de suite, vers 224.0.0.2.
    b.quitter(false, g9, LO);
    let v = b.tout_de_suite();
    assert_eq!(v.iter().map(|x| (x.2, &x.3)).collect::<Vec<_>>(), vec![(igmp::TOUS_LES_ROUTEURS, &Message::V12(DEPART, g9))]);
    b.quitter(false, g10, LO);
    assert_eq!(messages(&b.tout_de_suite()), vec![&Message::V12(DEPART, g10)]);
    assert!(b.tout().is_empty());
    // 260 s plus tard (qrv × qi + qri), l'interface revient en v3.
    b.attendre(231_000 * MS);
    assert_eq!(b.proc(LO).0, 3);
}

/// Après une requête v3 de QRV 3, un changement est dit trois fois (mesuré
/// sur lo : `multidiffusion-lo.txt`) ; la carte, elle, reste à 2.
#[test]
fn qrv_d_une_requete() {
    let mut b = Banc::nouveau();
    b.requete(LO, &requete_v3(20, RIEN, 3, 0, &[]));
    assert!(b.tout().is_empty());
    b.joindre(false, [239, 7, 7, 7], LO);
    assert_eq!(b.tout().len(), 3);
    b.joindre(false, [239, 7, 7, 8], ETH);
    assert_eq!(b.tout().len(), 2);
}

/// Une requête v3 de groupe et de sources : seules les sources nommées que
/// le filtre laisse entrer sont dites (IS_IN) ; aucune : pas de réponse.
#[test]
fn requete_de_sources() {
    let mut b = Banc::nouveau();
    let g4 = [239, 1, 2, 4];
    let d = Demande { groupe: g4, adresse: RIEN, index: 0 };
    b.r.joindre(&mut b.g, d, Some(ETH), Mode::Inclure).unwrap();
    b.source(true, g4, 0, dix(1));
    b.source(true, g4, 0, dix(2));
    b.tout();
    b.requete(ETH, &requete_v3(20, g4, 0, 0, &[dix(2), dix(9)]));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(igmp::EST_INCLURE, g4, &[dix(2)])])]);
    b.requete(ETH, &requete_v3(20, g4, 0, 0, &[dix(9)]));
    assert!(b.tout().is_empty());
}

/// Une requête de sources pour un groupe en EXCLUDE (`igmp_xmarksources`) :
/// pas de réponse si chaque source nommée est exclue par toutes les sockets
/// (elle n'entre pas) ; une source qu'une socket seulement exclut (elle
/// entre par l'autre : un filtre « inactif », que Linux saute) ne compte
/// pas : réponse, l'état courant, IS_EX des sources que toutes excluent.
#[test]
fn requete_de_sources_en_exclude() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    b.joindre(true, G3, 0);
    b.filtrer(G3, 0, Mode::Exclure, &[dix(1), dix(2)]);
    let d = Demande { groupe: G3, adresse: RIEN, index: 0 };
    b.c.filtrer(&mut b.g, d, Banc::trouver(d), Mode::Exclure.numero(), &[dix(1)]).unwrap();
    b.tout();
    b.requete(ETH, &requete_v3(20, G3, 0, 0, &[dix(1)]));
    assert!(b.tout().is_empty());
    b.requete(ETH, &requete_v3(20, G3, 0, 0, &[dix(2)]));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(EST_EXCLURE, G3, &[dix(1)])])]);
}

/// Deux requêtes pendant que le minuteur du groupe tourne (`igmp_heard_query`
/// : la réponse ne dit que des sources nommées que si chaque requête en
/// nommait) : celle du groupe, puis une d'une de ses sources : la réponse
/// dit tout l'état (IS_IN des deux sources), pas seulement la source nommée.
#[test]
fn requetes_pendant_le_minuteur() {
    let mut b = Banc::nouveau();
    let g4 = [239, 1, 2, 4];
    let d = Demande { groupe: g4, adresse: RIEN, index: 0 };
    b.r.joindre(&mut b.g, d, Some(ETH), Mode::Inclure).unwrap();
    b.source(true, g4, 0, dix(1));
    b.source(true, g4, 0, dix(2));
    b.tout();
    b.requete(ETH, &requete_v3(20, g4, 0, 0, &[]));
    b.requete(ETH, &requete_v3(20, g4, 0, 0, &[dix(2)]));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(igmp::EST_INCLURE, g4, &[dix(1), dix(2)])])]);
}

/// Une requête v3 d'un intervalle court (QQIC 5 : 5 s) raccourcit le délai
/// de réponse au-dessous (RFC 3376, 8.3 : ses 10 s deviennent 4 s) : un
/// routeur v2 entendu ensuite est noté pour qrv × qi + qri, 2 × 5 + 4 = 14 s.
#[test]
fn intervalle_de_requete_court() {
    let mut b = Banc::nouveau();
    b.requete(ETH, &requete_v3(20, RIEN, 2, 5, &[]));
    assert!(b.tout().is_empty());
    b.requete(ETH, &requete_v12(20, RIEN));
    assert_eq!(b.proc(ETH).0, 2);
    b.attendre(13_900 * MS);
    assert_eq!(b.proc(ETH).0, 2);
    b.attendre(200 * MS);
    assert_eq!(b.proc(ETH).0, 3);
}

/// Une requête v2 oublie les rapports de changement en attente
/// (`igmpv3_clear_delrec`) : un groupe parti juste avant, dont le départ
/// n'est pas encore dit, ne l'est jamais, même quand l'interface revient en
/// v3 et qu'un autre changement part.
#[test]
fn requete_v2_et_tombes() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    b.tout();
    b.quitter(false, G3, 0);
    b.requete(ETH, &requete_v12(20, RIEN));
    assert!(b.tout().is_empty());
    b.attendre(261_000 * MS);
    assert_eq!(b.proc(ETH).0, 3);
    let g4 = [239, 1, 2, 4];
    b.joindre(false, g4, 0);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(VERS_EXCLURE, g4, &[])]); 2]);
}

/// En v2, un filtre qui change ne dit rien (`igmp_ifc_event` ne part qu'en
/// v3) : une source bloquée sur un groupe déjà là, aucun rapport v3.
#[test]
fn filtre_change_en_v2() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    b.tout();
    b.requete(ETH, &requete_v12(20, RIEN));
    assert_eq!(messages(&b.tout()), vec![&Message::V12(RAPPORT_V2, G3)]);
    b.filtrer(G3, 0, Mode::Exclure, &[dix(1)]);
    assert!(b.tout().is_empty());
}

/// Une requête v1 (code 0) : l'interface passe en v1 ; une adhésion y dit
/// deux rapports v1, vers le groupe, et son départ rien : v1 n'a pas de
/// message de départ, et le groupe ne va pas dans les tombes (revenue en
/// v3, l'interface ne le dit pas au changement suivant).
#[test]
fn en_v1() {
    let mut b = Banc::nouveau();
    b.requete(ETH, &requete_v12(0, RIEN));
    assert_eq!(b.proc(ETH).0, 1);
    b.joindre(false, G3, 0);
    let v = b.tout();
    assert_eq!(v.iter().map(|x| (x.2, &x.3)).collect::<Vec<_>>(), vec![(G3, &Message::V12(igmp::RAPPORT_V1, G3)); 2]);
    b.quitter(false, G3, 0);
    assert!(b.tout().is_empty());
    b.attendre(261_000 * MS);
    assert_eq!(b.proc(ETH).0, 3);
    let g4 = [239, 1, 2, 4];
    b.joindre(false, g4, 0);
    assert_eq!(messages(&b.tout()), vec![&v3(&[(VERS_EXCLURE, g4, &[])]); 2]);
}

/// En v2, une source qui part ne va pas dans la tombe de son groupe
/// (`ip_mc_del1_src` : seulement en v3) : revenue en v3, l'interface ne la
/// dit pas au changement suivant (ALLOW de la nouvelle source, sans BLOCK).
#[test]
fn source_partie_en_v2() {
    let mut b = Banc::nouveau();
    let g4 = [239, 1, 2, 4];
    let d = Demande { groupe: g4, adresse: RIEN, index: 0 };
    b.r.joindre(&mut b.g, d, Some(ETH), Mode::Inclure).unwrap();
    b.source(true, g4, 0, dix(1));
    b.source(true, g4, 0, dix(2));
    b.tout();
    b.requete(ETH, &requete_v12(20, RIEN));
    assert_eq!(messages(&b.tout()), vec![&Message::V12(RAPPORT_V2, g4)]);
    b.source(false, g4, 0, dix(1));
    assert!(b.tout().is_empty());
    b.attendre(261_000 * MS);
    assert_eq!(b.proc(ETH).0, 3);
    b.source(true, g4, 0, dix(3));
    assert_eq!(messages(&b.tout()), vec![&v3(&[(NOUVELLES, g4, &[dix(3)])]); 2]);
}

/// Le rapport v2 d'une autre machine sur notre groupe arrête le nôtre ; le
/// nôtre, rendu par la boucle, ou reçu dans une trame pour nous seuls, non.
#[test]
fn rapport_d_une_autre_machine() {
    let mut b = Banc::nouveau();
    b.requete(ETH, &requete_v12(100, RIEN));
    b.joindre(false, G3, 0);
    let mut o = [0u8; 8];
    igmp::ecrire(&mut o, RAPPORT_V2, G3);
    b.g.recevoir(ETH, &o, true, true);
    b.g.recevoir(ETH, &o, false, false);
    assert_eq!(b.proc(ETH).1[0], (G3, true, false));
    b.g.recevoir(ETH, &o, false, true);
    assert_eq!(b.proc(ETH).1[0], (G3, false, false));
    assert!(b.tout().is_empty());
    // Plus rapporteur : son départ n'est pas annoncé.
    b.quitter(false, G3, 0);
    assert!(b.tout().is_empty());
}

/// Des messages faux : trop courts, une somme fausse, une requête de 9 à
/// 11 octets, une requête v3 qui annonce plus de sources qu'elle n'en
/// porte, une requête générale avec des sources : ignorés.
#[test]
fn messages_faux() {
    let mut b = Banc::nouveau();
    b.joindre(false, G3, 0);
    b.tout();
    let mut faux = requete_v12(20, RIEN);
    faux[7] ^= 1;
    let mut longue = requete_v3(20, G3, 0, 0, &[dix(1)]);
    longue[11] = 2;
    igmp::sceller(&mut longue);
    let mut neuf = requete_v12(20, RIEN);
    neuf.push(0);
    igmp::sceller(&mut neuf);
    for o in [&requete_v12(20, RIEN)[..7], &faux[..], &neuf[..], &longue[..], &requete_v3(20, RIEN, 0, 0, &[dix(1)])[..]] {
        b.requete(ETH, o);
        assert_eq!(b.proc(ETH).0, 3);
        assert!(b.tout().is_empty(), "{o:?}");
    }
}

/// Un rapport plus grand que la MTU (68 : 44 octets d'IGMP, 7 sources par
/// enregistrement) : un ALLOW continue dans un second paquet ; un TO_EX est
/// coupé (« truncate these »).
#[test]
fn rapports_a_la_mtu() {
    let mut b = Banc::nouveau();
    let g4 = [239, 1, 2, 4];
    let d = Demande { groupe: g4, adresse: RIEN, index: ETROITE };
    b.r.joindre(&mut b.g, d, Some(ETROITE), Mode::Inclure).unwrap();
    let dix_sources: Vec<[u8; 4]> = (1..=10).map(dix).collect();
    b.filtrer(g4, ETROITE, Mode::Inclure, &dix_sources);
    let v = b.tout();
    assert!(v.iter().all(|x| x.1 == ETROITE));
    // ALLOW {les 10} (l'adhésion est déjà en INCLUDE) : continué dans un
    // second paquet.
    let attendu = [v3(&[(NOUVELLES, g4, &dix_sources[..7])]), v3(&[(NOUVELLES, g4, &dix_sources[7..])])];
    assert_eq!(messages(&v), vec![&attendu[0], &attendu[1], &attendu[0], &attendu[1]]);
    b.filtrer(g4, ETROITE, Mode::Exclure, &dix_sources);
    let v = b.tout();
    assert_eq!(messages(&v), vec![&v3(&[(VERS_EXCLURE, g4, &dix_sources[..7])]); 2]);
}
