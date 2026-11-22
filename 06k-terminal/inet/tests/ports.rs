//! La table des ports d'UDP : les règles de Linux une à une (le partage
//! d'un port, le choix de la socket qui reçoit, la diffusion), puis les
//! ports éphémères : tous dans la plage, tous différents tant qu'il en
//! reste, et dans un ordre qui ne se devine pas ; puis les groupes
//! SO_REUSEPORT (mesurés sous Linux, sonde c10f du lot 6 des soldes).

use inet::groupes::{Choix, Refus as RefusDeGroupe};
use inet::ports::{Lien, Refus, Table, EPHEMERE_MAX, EPHEMERE_MIN};

const LO: [u8; 4] = [127, 0, 0, 1];
const ICI: [u8; 4] = [10, 0, 2, 15];
const TOUT: [u8; 4] = [0; 4];

fn lien(adresse: [u8; 4], port: u16) -> Lien {
    Lien { adresse, port, distante: TOUT, port_distant: 0, reuseaddr: false, reuseport: false, uid: 1000, plage: 0, interface: 0 }
}

fn aucun_processeur(_: &u32) -> i32 {
    -1
}

fn hachage_nul() -> u32 {
    0
}

/// Une recherche sur le processeur 0, sans programme ni processeur dit, d'un
/// flux de hachage nul (le premier index d'un groupe).
const AUCUN: Choix<'static, u32, u32> = Choix { ici: 0, processeur: &aucun_processeur, hachage: &hachage_nul, programme: None };

#[test]
fn partage_d_un_port() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    assert_eq!(t.lier(1, lien(TOUT, 5000), 1, 0), Ok(5000));
    // 0.0.0.0 recouvre tout : refusé à 127.0.0.1 comme à 0.0.0.0.
    assert_eq!(t.lier(2, lien(LO, 5000), 2, 0), Err(Refus::Pris));
    assert_eq!(t.lier(2, lien(TOUT, 5000), 2, 0), Err(Refus::Pris));
    // Deux adresses précises différentes : permis.
    assert_eq!(t.lier(3, lien(LO, 6000), 3, 0), Ok(6000));
    assert_eq!(t.lier(4, lien(ICI, 6000), 4, 0), Ok(6000));
    // SO_REUSEADDR des deux côtés ; d'un seul : refusé.
    let r = Lien { reuseaddr: true, ..lien(TOUT, 7000) };
    assert_eq!(t.lier(5, r, 5, 0), Ok(7000));
    assert_eq!(t.lier(6, lien(TOUT, 7000), 6, 0), Err(Refus::Pris));
    assert_eq!(t.lier(6, r, 6, 0), Ok(7000));
    // SO_REUSEPORT : du même utilisateur seulement.
    let p = Lien { reuseport: true, ..lien(TOUT, 8000) };
    assert_eq!(t.lier(7, p, 7, 0), Ok(8000));
    assert_eq!(t.lier(8, Lien { uid: 0, ..p }, 8, 0), Err(Refus::Pris));
    assert_eq!(t.lier(8, p, 8, 0), Ok(8000));
    // SO_REUSEADDR posé après le bind : compte pour les suivants.
    assert_eq!(t.lier(10, lien(TOUT, 9000), 10, 0), Ok(9000));
    assert_eq!(t.lier(11, r, 11, 0), Ok(7000), "le port 7000 partagé, SO_REUSEADDR des deux côtés");
    assert_eq!(t.lier(12, Lien { port: 9000, ..r }, 12, 0), Err(Refus::Pris));
    t.reutiliser(10, true, false);
    assert_eq!(t.lier(12, Lien { port: 9000, ..r }, 12, 0), Ok(9000));
    // Retirée, la socket rend son port.
    t.retirer(1);
    assert_eq!(t.lier(9, lien(TOUT, 5000), 9, 0), Ok(5000));
}

#[test]
fn qui_recoit() {
    // (SO_REUSEADDR : sinon 127.0.0.1:53 serait refusé, 0.0.0.0:53 le
    // recouvrant.)
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, Lien { reuseaddr: true, ..lien(TOUT, 53) }, 1, 0).unwrap();
    t.lier(2, Lien { reuseaddr: true, ..lien(LO, 53) }, 2, 0).unwrap();
    // Liée à l'adresse de destination d'abord, puis à 0.0.0.0.
    assert_eq!(t.trouver(ICI, 4000, LO, 53, 1, &AUCUN), Some(2));
    assert_eq!(t.trouver(LO, 4000, ICI, 53, 1, &AUCUN), Some(1));
    assert_eq!(t.trouver(LO, 4000, LO, 54, 1, &AUCUN), None);
    // Une socket connectée à l'émetteur l'emporte sur une qui ne l'est pas ;
    // connectée ailleurs, elle n'est pas candidate.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, lien(TOUT, 9000), 1, 0).unwrap();
    t.lier(2, Lien { reuseaddr: true, ..lien(TOUT, 9100) }, 2, 0).unwrap();
    t.lier(3, Lien { reuseaddr: true, ..lien(TOUT, 9100) }, 3, 0).unwrap();
    t.connecter(3, LO, 5555, TOUT);
    assert_eq!(t.trouver(LO, 5555, LO, 9100, 1, &AUCUN), Some(3));
    assert_eq!(t.trouver(LO, 5556, LO, 9100, 1, &AUCUN), Some(2));
    t.connecter(2, [10, 9, 9, 9], 1, TOUT);
    assert_eq!(t.trouver(LO, 5556, LO, 9100, 1, &AUCUN), None);
    // Connectée à une autre adresse, même du bon port : pas candidate non
    // plus.
    t.connecter(2, [10, 9, 9, 9], 5556, TOUT);
    assert_eq!(t.trouver(LO, 5556, LO, 9100, 1, &AUCUN), None);
    assert_eq!(t.lien(3).map(|l| (l.distante, l.port_distant)), Some((LO, 5555)));
}

#[test]
fn diffusion() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let r = Lien { reuseaddr: true, ..lien(TOUT, 68) };
    t.lier(1, r, 1, 0).unwrap();
    t.lier(2, r, 2, 0).unwrap();
    t.lier(3, Lien { adresse: ICI, ..r }, 3, 0).unwrap();
    t.lier(4, lien(TOUT, 69), 4, 0).unwrap();
    let mut vues = Vec::new();
    t.pour_chaque_diffusion([10, 0, 2, 2], 67, [255; 4], 68, 2, |&n| vues.push(n));
    assert_eq!(vues, [1, 2], "la socket liée à 10.0.2.15 n'est pas pour 255.255.255.255");
}

/// SO_BINDTODEVICE (mesuré sous Linux 6.18, `interface-suite.txt` des
/// sondes) : une socket liée à une interface ne reçoit que ce qui arrive par
/// elle, et l'emporte sur une non liée ; deux liaisons différentes ne se
/// gênent pas au `bind`, une socket non liée gêne toutes les autres.
#[test]
fn liees_a_une_interface() {
    const IF_LO: u32 = 1;
    const IF_ETH0: u32 = 2;
    let mut t: Table<u32, u32> = Table::new().unwrap();
    assert_eq!(t.lier(1, Lien { interface: IF_LO, ..lien(TOUT, 5000) }, 1, 0), Ok(5000));
    assert_eq!(t.lier(2, Lien { interface: IF_ETH0, ..lien(TOUT, 5000) }, 2, 0), Ok(5000), "deux liaisons differentes");
    assert_eq!(t.lier(3, lien(TOUT, 5000), 3, 0), Err(Refus::Pris), "non liee contre liees");
    assert_eq!(t.lier(3, Lien { interface: IF_LO, ..lien(TOUT, 5000) }, 3, 0), Err(Refus::Pris), "la meme liaison");
    // Chacune voit ce qui arrive par son interface, rien d'autre.
    assert_eq!(t.trouver(LO, 4000, LO, 5000, IF_LO, &AUCUN), Some(1));
    assert_eq!(t.trouver(ICI, 4000, ICI, 5000, IF_ETH0, &AUCUN), Some(2));
    assert_eq!(t.trouver(ICI, 4000, ICI, 5000, 3, &AUCUN), None, "une troisieme interface");
    // Une non liée sur un autre port, plus une liée posée APRÈS le bind (Linux
    // lit la liaison à chaque recherche et à chaque conflit).
    let r = Lien { reuseaddr: true, ..lien(TOUT, 6000) };
    t.lier(4, r, 4, 0).unwrap();
    t.lier(5, r, 5, 0).unwrap();
    assert_eq!(t.trouver(LO, 4000, LO, 6000, IF_LO, &AUCUN), Some(5), "a egalite, la plus recente");
    // SO_INCOMING_CPU : à note égale, celle du processeur qui cherche ; une
    // meilleure note l'emporte quand même.
    let quatre = |&o: &u32| if o == 4 { 0 } else { -1 };
    let de_4 = Choix { processeur: &quatre, ..AUCUN };
    assert_eq!(t.trouver(LO, 4000, LO, 6000, IF_LO, &de_4), Some(4), "a egalite, celle de ce processeur");
    t.changer_interface(5, IF_LO);
    assert_eq!(t.trouver(LO, 4000, LO, 6000, IF_LO, &AUCUN), Some(5), "liee : +4");
    assert_eq!(t.trouver(LO, 4000, LO, 6000, IF_LO, &de_4), Some(5), "liee : +4, plus que le processeur");
    assert_eq!(t.trouver(ICI, 4000, ICI, 6000, IF_ETH0, &AUCUN), Some(4));
    // La liaison compte moins que l'adresse : une socket liée à 0.0.0.0 et à
    // l'interface perd contre une liée à l'adresse (la première passe).
    t.lier(6, Lien { adresse: LO, ..r }, 6, 0).unwrap();
    assert_eq!(t.trouver(LO, 4000, LO, 6000, IF_LO, &AUCUN), Some(6));
    t.retirer(6);
    // La connexion compte autant que la liaison : connectée à l'émetteur
    // (+4 +4) l'emporte sur liée (+4).
    t.connecter(4, LO, 4000, TOUT);
    assert_eq!(t.trouver(LO, 4000, LO, 6000, IF_LO, &AUCUN), Some(4));
    // Un conflit lit la liaison du moment : délier la 5 la fait gêner une
    // nouvelle venue sans SO_REUSEADDR.
    t.deconnecter(4, false);
    t.retirer(4);
    assert_eq!(t.lier(7, Lien { interface: IF_ETH0, ..lien(TOUT, 6000) }, 7, 0), Ok(6000));
    t.retirer(7);
    t.changer_interface(5, 0);
    assert_eq!(t.lier(7, Lien { interface: IF_ETH0, ..lien(TOUT, 6000) }, 7, 0), Err(Refus::Pris));
    // Une diffusion : les non liées et celles de l'interface d'arrivée.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let r = Lien { reuseaddr: true, ..lien(TOUT, 68) };
    t.lier(1, r, 1, 0).unwrap();
    t.lier(2, Lien { interface: IF_LO, ..r }, 2, 0).unwrap();
    t.lier(3, Lien { interface: IF_ETH0, ..r }, 3, 0).unwrap();
    let mut vues = Vec::new();
    t.pour_chaque_diffusion([10, 0, 2, 2], 67, [255; 4], 68, IF_ETH0, |&n| vues.push(n));
    assert_eq!(vues, [1, 3]);
}

#[test]
fn ports_ephemeres() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let plage = EPHEMERE_MIN..=EPHEMERE_MAX;
    // Mille ports demandés : tous dans la plage, tous différents.
    let mut vus = std::collections::HashSet::new();
    let mut hasard = 12345u32;
    for n in 0..1000u64 {
        hasard = hasard.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let p = t.lier(n, lien(TOUT, 0), n as u32, hasard).unwrap();
        assert!(plage.contains(&p) && vus.insert(p), "port {p}");
    }
    // Le même hasard donne le même premier port ; s'il est pris, le suivant
    // essayé est dans sa classe (modulo 256), un pas plus loin (un multiple
    // impair de 256 tiré du hasard) : pas « le suivant libre ».
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let a = t.lier(1, lien(TOUT, 0), 1, 0x8000_0000).unwrap();
    t.retirer(1);
    let b = t.lier(2, lien(TOUT, 0), 2, 0x8000_0000).unwrap();
    assert_eq!(a, b, "le même premier port");
    let c = t.lier(3, lien(TOUT, 0), 3, 0x8000_0000).unwrap();
    assert!(c != a && c % 256 == a % 256, "{a} puis {c}");
    // La table pleine : 1024 sockets, puis ENOBUFS.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    for n in 0..1024u64 {
        t.lier(n, lien(TOUT, 0), 0, (n as u32).wrapping_mul(2_654_435_761)).unwrap();
    }
    assert_eq!(t.lier(1024, lien(TOUT, 0), 0, 1), Err(Refus::Plein));
}

/// IP_LOCAL_PORT_RANGE (`inet_sk_get_local_port_range`) : chaque borne
/// seulement si elle tombe dans celle du système (mesures de Linux 6.18).
#[test]
fn plage_d_une_socket() {
    use inet::ports::plage;
    assert_eq!(plage(0), (32768, 60999, false));
    assert_eq!(plage(40000 | 40001 << 16), (40000, 40001, true));
    assert_eq!(plage(1000 | 2000 << 16), (32768, 60999, true), "hors plage : ignoree");
    assert_eq!(plage(32770 << 16), (32768, 32770, true), "0-32770");
    assert_eq!(plage(50000), (50000, 60999, true), "le bas seul");
    assert_eq!(plage(70 | 40000 << 16), (32768, 40000, true), "le haut seul");
    // Un port éphémère d'UDP reste dans la plage de sa socket, et la
    // remplit.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let l = Lien { plage: 40000 | 40001 << 16, ..lien(TOUT, 0) };
    let a = t.lier(1, l, 1, 0x9e37_79b9).unwrap();
    let b = t.lier(2, l, 2, 0x7f4a_7c15).unwrap();
    assert!(a != b && (40000..=40001).contains(&a) && (40000..=40001).contains(&b), "{} {}", a, b);
    assert_eq!(t.lier(3, l, 3, 5), Err(Refus::Pris));
    // Une autre socket, sans plage, n'est pas gênée.
    assert!(t.lier(4, lien(TOUT, 0), 4, 5).is_ok());
}

/// Un groupe de `n` sockets (1 à n), liées à `adresse`:`port` avec SO_REUSEPORT.
fn groupe(t: &mut Table<u32, u32>, adresse: [u8; 4], port: u16, n: u64) {
    for k in 1..=n {
        assert_eq!(t.lier(k, Lien { reuseport: true, ..lien(adresse, port) }, k as u32, 0), Ok(port));
    }
}

/// Le programme « rend son propre nombre » : posé avec la valeur `k`, il rend
/// l'index `k`.
fn programme(k: &u32) -> u32 {
    *k
}

const PROGRAMME: Choix<'static, u32, u32> = Choix { programme: Some(&programme), ..AUCUN };

/// L'ordre des membres (`socks[]`) : celui des `bind` ; une qui part est
/// remplacée par la dernière ; le programme choisit par son index, trop grand
/// on retombe sur le hachage ; posé par n'importe quelle membre, et même avant
/// `bind`.
#[test]
fn groupe_et_son_programme() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    // Le programme posé avant `bind`, sans SO_REUSEPORT : EINVAL ; avec : il
    // fait un groupe à la socket, que son `bind` garde.
    assert_eq!(t.attacher_programme(1, 1, false, -1), Err(RefusDeGroupe::Invalide));
    assert_eq!(t.attacher_programme(1, 1, true, -1), Ok(None));
    groupe(&mut t, LO, 7000, 4);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(2), "index 1 : la deuxieme liee");
    for k in 0..4 {
        assert_eq!(t.attacher_programme(4, k, true, -1), Ok(Some(if k == 0 { 1 } else { k - 1 })), "pose par la derniere");
        assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(k + 1));
    }
    t.attacher_programme(1, 7, true, -1).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(1), "index 7 : le hachage (nul : la premiere)");
    // Le hachage ramené au nombre de membres (`reciprocal_scale`).
    let trois_quarts = || 0xC000_0000;
    let haut = Choix { hachage: &trois_quarts, ..AUCUN };
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &haut), Some(4));
    // La 2 part : la 4 prend sa place.
    t.oublier(2);
    t.attacher_programme(1, 1, true, -1).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(4), "apres le depart de la 2, index 1");
    t.attacher_programme(1, 2, true, -1).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(3));
    // Sans paquet (une erreur ICMP) : le hachage seul.
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &AUCUN), Some(1));
    // Retirer le programme : une fois, puis ENOENT ; sans groupe, ENOENT avec
    // SO_REUSEPORT, EINVAL sans.
    assert_eq!(t.detacher_programme(3, true), Ok(2));
    assert_eq!(t.detacher_programme(3, true), Err(RefusDeGroupe::Absent));
    assert_eq!(t.detacher_programme(9, true), Err(RefusDeGroupe::Absent));
    assert_eq!(t.detacher_programme(9, false), Err(RefusDeGroupe::Invalide));
    // Liée sans groupe (SO_REUSEPORT posé après `bind`) : EINVAL.
    t.lier(9, lien(LO, 7100), 9, 0).unwrap();
    t.reutiliser(9, false, true);
    assert_eq!(t.attacher_programme(9, 0, true, -1), Err(RefusDeGroupe::Invalide));
    // Une autre la rejoint : un groupe est fait pour elle, à qui le programme
    // peut alors être posé.
    t.lier(10, Lien { reuseport: true, ..lien(LO, 7100) }, 10, 0).unwrap();
    assert_eq!(t.attacher_programme(9, 1, true, -1), Ok(None));
    assert_eq!(t.trouver(ICI, 1, LO, 7100, 1, &PROGRAMME), Some(10));
}

/// Qui entre dans quel groupe : la même adresse, la même interface ; une
/// socket qui a déjà un groupe ne partage pas un port par SO_REUSEPORT, mais
/// par SO_REUSEADDR, si : elle entre dans celui de l'autre, son programme
/// perdu.
#[test]
fn former_un_groupe() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    groupe(&mut t, LO, 7000, 1);
    t.attacher_programme(5, 0, true, -1).unwrap();
    assert_eq!(t.lier(5, Lien { reuseport: true, ..lien(LO, 7000) }, 5, 0), Err(Refus::Pris), "un groupe avant bind");
    assert_eq!(t.lier(5, Lien { reuseport: true, ..lien(LO, 7001) }, 5, 0), Ok(7001), "un port libre");
    // SO_REUSEADDR des deux.
    let deux = Lien { reuseport: true, reuseaddr: true, ..lien(LO, 7200) };
    t.lier(6, deux, 6, 0).unwrap();
    t.attacher_programme(6, 0, true, -1).unwrap();
    t.attacher_programme(7, 1, true, -1).unwrap();
    assert_eq!(t.lier(7, deux, 7, 0), Ok(7200));
    assert_eq!(t.trouver(ICI, 1, LO, 7200, 1, &PROGRAMME), Some(6), "le programme de la premiere");
    assert_eq!(t.detacher_programme(7, true), Ok(0));
    // Deux adresses : deux groupes ; la plus précise d'abord.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, Lien { reuseport: true, ..lien(LO, 7000) }, 1, 0).unwrap();
    t.lier(2, Lien { reuseport: true, ..lien(TOUT, 7000) }, 2, 0).unwrap();
    t.attacher_programme(1, 1, true, -1).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(1));
    assert_eq!(t.trouver(ICI, 1, [127, 0, 0, 2], 7000, 1, &PROGRAMME), Some(2));
    // Un autre utilisateur : ni le port, ni le groupe.
    assert_eq!(t.lier(3, Lien { reuseport: true, uid: 0, ..lien(LO, 7000) }, 3, 0), Err(Refus::Pris));
}

/// Les sorties d'un groupe : `connect`, la fin d'une connexion qui oublie
/// l'adresse (même jamais connectée), SO_BINDTODEVICE ; le port rendu.
#[test]
fn quitter_un_groupe() {
    // Liées à une adresse précise : `connect` fait quitter le groupe (et
    // marque has_conns).
    let mut t: Table<u32, u32> = Table::new().unwrap();
    groupe(&mut t, LO, 7000, 3);
    t.connecter(1, LO, 9, LO);
    t.attacher_programme(2, 0, true, -1).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(3), "la 3 a pris la place de la 1");
    assert_eq!(t.attacher_programme(1, 0, true, -1), Err(RefusDeGroupe::Invalide), "la connectee n'a plus de groupe");
    assert_eq!(t.trouver(LO, 9, LO, 7000, 1, &PROGRAMME), Some(1), "son emetteur la trouve");
    // Liées à 0.0.0.0, la fin d'une connexion jamais faite, le port gardé et
    // l'adresse oubliée : le groupe est quitté ; l'adresse gardée : non.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    groupe(&mut t, TOUT, 7000, 3);
    t.attacher_programme(1, 0, true, -1).unwrap();
    t.deconnecter(1, true);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(3));
    assert_eq!(t.detacher_programme(1, true), Err(RefusDeGroupe::Absent));
    let mut t: Table<u32, u32> = Table::new().unwrap();
    groupe(&mut t, LO, 7000, 3);
    t.attacher_programme(1, 0, true, -1).unwrap();
    t.deconnecter(1, false);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(1));
    // SO_BINDTODEVICE.
    t.changer_interface(1, 1);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 2, &PROGRAMME), Some(3));
    // Le port rendu : le groupe aussi (restée, elle en retirerait le programme).
    t.retirer(3);
    assert_eq!(t.detacher_programme(3, true), Err(RefusDeGroupe::Absent));
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 2, &PROGRAMME), Some(2));
    // Détruite sans port : son groupe d'avant `bind` disparaît.
    t.attacher_programme(8, 0, true, -1).unwrap();
    t.oublier(8);
    assert_eq!(t.detacher_programme(8, true), Err(RefusDeGroupe::Absent));
}

/// La recherche de Linux, telle que mesurée : la plus récente à égalité ; un
/// groupe en tête rend sa membre sans voir les suivantes, même mieux notées,
/// sauf has_conns ; une connectée à l'émetteur d'abord.
#[test]
fn recherche_et_groupes() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    // Une liée à lo (1), plus ancienne que le groupe (2 et 3).
    t.lier(1, Lien { reuseport: true, interface: 1, ..lien(LO, 7000) }, 1, 0).unwrap();
    groupe2(&mut t, LO, 7000, 2..=3);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &AUCUN), Some(2), "le groupe, pas la liee a lo");
    // Une membre se connecte (son adresse ne change pas) : has_conns.
    t.connecter(2, LO, 9, LO);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &AUCUN), Some(1), "has_conns : la liee a lo");
    // Liées à 0.0.0.0 : `connect` change l'adresse, le groupe est quitté avant.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, Lien { reuseport: true, interface: 1, ..lien(TOUT, 7000) }, 1, 0).unwrap();
    groupe2(&mut t, TOUT, 7000, 2..=3);
    t.connecter(2, LO, 9, LO);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &AUCUN), Some(3));
    // SO_REUSEADDR seul : la plus récente.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, Lien { reuseaddr: true, ..lien(LO, 7000) }, 1, 0).unwrap();
    t.lier(2, Lien { reuseaddr: true, ..lien(LO, 7000) }, 2, 0).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &AUCUN), Some(2));
    // Une connectée exactement à l'émetteur, plus ancienne qu'un groupe (par
    // SO_REUSEADDR) : trouvée d'abord.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let deux = Lien { reuseport: true, reuseaddr: true, ..lien(LO, 7000) };
    t.lier(1, Lien { reuseaddr: true, ..lien(LO, 7000) }, 1, 0).unwrap();
    t.connecter(1, ICI, 1, LO);
    t.lier(2, deux, 2, 0).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &AUCUN), Some(1));
    assert_eq!(t.trouver(ICI, 2, LO, 7000, 1, &AUCUN), Some(2));
    // L'ordre de la recherche suit `connect` (le ré-hachage remet en tête),
    // celui de l'entrée dans un groupe, non : la 3 (liée à 0.0.0.0 puis
    // déconnectée, son port gardé) est la plus récente pour la recherche,
    // la 4 rejoint quand même le groupe de la 2, la plus récemment liée.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let r = Lien { reuseport: true, reuseaddr: true, ..lien(TOUT, 7000) };
    t.lier(3, r, 3, 0).unwrap();
    t.lier(2, r, 2, 0).unwrap();
    t.connecter(3, LO, 9, LO);
    t.deconnecter(3, true);
    t.lier(4, r, 4, 0).unwrap();
    t.attacher_programme(4, 1, true, -1).unwrap();
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &PROGRAMME), Some(4), "le groupe de 2 et 4");
    assert_eq!(t.attacher_programme(3, 0, true, -1), Err(RefusDeGroupe::Invalide), "la 3 sans groupe");
    // La table des quadruplets (`udp4_lib_lookup4`) : la plus récemment connectée, pas la
    // plus récemment liée ; une connectée ailleurs d'abord, reconnectée ensuite, n'y est pas
    // pour le nouveau (mesuré : sondes r4a et r4b de la relecture du lot 6 des soldes).
    let ra = Lien { reuseaddr: true, ..lien(LO, 7000) };
    for (premiere, seconde) in [(2, 1), (1, 2)] {
        let mut t: Table<u32, u32> = Table::new().unwrap();
        t.lier(1, ra, 1, 0).unwrap();
        t.lier(2, ra, 2, 0).unwrap();
        t.connecter(premiere, LO, 9, LO);
        t.connecter(seconde, LO, 9, LO);
        assert_eq!(t.trouver(LO, 9, LO, 7000, 1, &AUCUN), Some(seconde as u32), "la plus recemment connectee");
    }
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, ra, 1, 0).unwrap();
    t.lier(2, ra, 2, 0).unwrap();
    t.connecter(2, LO, 8, LO);
    t.connecter(1, LO, 9, LO);
    t.connecter(2, LO, 9, LO);
    assert_eq!(t.trouver(LO, 9, LO, 7000, 1, &AUCUN), Some(1), "reconnectee : son premier quadruplet");
    // Déconnectée d'une adresse choisie par `bind` : elle y reste ; d'une adresse de route, non.
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, ra, 1, 0).unwrap();
    t.lier(2, ra, 2, 0).unwrap();
    t.connecter(1, LO, 9, LO);
    t.connecter(2, LO, 9, LO);
    t.deconnecter(2, false);
    t.connecter(2, LO, 9, LO);
    assert_eq!(t.trouver(LO, 9, LO, 7000, 1, &AUCUN), Some(2), "son rang garde");
    let r = Lien { reuseaddr: true, ..lien(TOUT, 7000) };
    let mut t: Table<u32, u32> = Table::new().unwrap();
    t.lier(1, r, 1, 0).unwrap();
    t.lier(2, r, 2, 0).unwrap();
    t.connecter(2, LO, 9, LO);
    t.connecter(1, LO, 9, LO);
    t.deconnecter(2, true);
    t.connecter(2, LO, 9, LO);
    assert_eq!(t.trouver(LO, 9, LO, 7000, 1, &AUCUN), Some(2), "sortie avec son adresse, rentree en tete");
}

/// SO_INCOMING_CPU dans un groupe : la membre du processeur qui cherche ;
/// aucune : la première depuis l'index du hachage. Le groupe compte celles qui
/// en disent un (`processeur_change`).
#[test]
fn groupe_et_processeurs() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    groupe(&mut t, LO, 7000, 4);
    t.processeur_change(3, -1, 1);
    let trois_sur_1 = |&o: &u32| if o == 3 { 1 } else { -1 };
    let depuis_1 = Choix { ici: 1, processeur: &trois_sur_1, ..AUCUN };
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &depuis_1), Some(3));
    let depuis_2 = Choix { ici: 2, processeur: &trois_sur_1, ..AUCUN };
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &depuis_2), Some(1));
    // Le compte revenu à 0 : le hachage seul, même si la 3 dit encore 1.
    t.processeur_change(3, 1, -1);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &depuis_1), Some(1));
    // Comptée à son entrée, décomptée à sa sortie (le processeur de la table).
    let mut t: Table<u32, u32> = Table::new().unwrap().avec_processeur(|&o| if o == 3 { 1 } else { -1 });
    groupe(&mut t, LO, 7000, 4);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &depuis_1), Some(3));
    t.retirer(3);
    assert_eq!(t.trouver(ICI, 1, LO, 7000, 1, &depuis_1), Some(1));
}

/// Le compte est celui de Linux, pas les membres d'aujourd'hui : une membre
/// connectée dont la réception a changé le processeur (sans le compte), puis
/// déconnectée sans quitter le groupe, ne le fait pas choisir par processeur
/// (mesuré : sonde r4c de la relecture du lot 6 des soldes).
#[test]
fn groupe_et_processeur_non_compte() {
    let mut t: Table<u32, u32> = Table::new().unwrap();
    let r = Lien { reuseport: true, ..lien(LO, 7000) };
    t.lier(2, r, 2, 0).unwrap();
    t.connecter(2, LO, 9, LO);
    t.lier(1, r, 1, 0).unwrap();
    t.deconnecter(2, false);
    let deux_sur_1 = |&o: &u32| if o == 2 { 1 } else { -1 };
    let mut vues = [false; 3];
    for h in [0u32, 0x4000_0000, 0x8000_0000, 0xc000_0000] {
        let hachage = move || h;
        let c = Choix { ici: 1, processeur: &deux_sur_1, hachage: &hachage, ..AUCUN };
        vues[t.trouver(ICI, 1, LO, 7000, 1, &c).unwrap() as usize] = true;
    }
    assert!(vues[1] && vues[2], "les deux membres, par le hachage");
}

fn groupe2(t: &mut Table<u32, u32>, adresse: [u8; 4], port: u16, numeros: std::ops::RangeInclusive<u64>) {
    for k in numeros {
        t.lier(k, Lien { reuseport: true, ..lien(adresse, port) }, k as u32, 0).unwrap();
    }
}
