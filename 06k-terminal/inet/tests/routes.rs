//! Les adresses et la table de routage : ce que donnent la configuration de
//! slirp (10.0.2.15/24, la route par défaut par 10.0.2.2) et les cas de
//! Linux (la table locale d'abord, le plus long préfixe, la diffusion), puis
//! une interface de sortie demandée, chaque cas mesuré sous Linux 6.18.33
//! (une machine où lo est 1 et la carte 2 : IP_PKTINFO, IP_UNICAST_IF).

use inet::routes::{Adresse, Chemin, Portee, Refus, Route, Table};

const LO: u32 = 1;
const ETH0: u32 = 2;
const MOI: [u8; 4] = [10, 0, 2, 15];
const DEFAUT: Route = Route { reseau: [0; 4], prefixe: 0, passerelle: Some([10, 0, 2, 2]), interface: ETH0, source: MOI };

fn slirp() -> Table {
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24, boucle: false }).unwrap();
    t.ajouter_route(Route { reseau: [0; 4], prefixe: 0, passerelle: Some([10, 0, 2, 2]), interface: ETH0, source: [10, 0, 2, 15] }).unwrap();
    t
}

#[test]
fn chemins() {
    let t = slirp();
    let src = [10, 0, 2, 15];
    assert_eq!(t.chercher([10, 0, 2, 15], 0), Some(Chemin::Locale { source: src, interface: ETH0 }));
    assert_eq!(t.chercher([10, 0, 2, 255], 0), Some(Chemin::Diffusion { interface: ETH0, source: src }));
    assert_eq!(t.chercher([255; 4], 0), Some(Chemin::Diffusion { interface: ETH0, source: src }));
    // Sur le réseau : directement ; ailleurs : par la passerelle.
    assert_eq!(t.chercher([10, 0, 2, 3], 0), Some(Chemin::Unicast { interface: ETH0, prochain: [10, 0, 2, 3], source: src }));
    assert_eq!(t.chercher([160, 79, 104, 10], 0), Some(Chemin::Unicast { interface: ETH0, prochain: [10, 0, 2, 2], source: src }));
    assert!(t.est_a_nous(src) && !t.est_a_nous([10, 0, 2, 2]));
    assert!(t.est_diffusion(ETH0, [10, 0, 2, 255]) && t.est_diffusion(ETH0, [255; 4]) && !t.est_diffusion(ETH0, [10, 0, 2, 2]));
    // Sans route par défaut : rien hors du réseau.
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: src, prefixe: 24, boucle: false }).unwrap();
    assert_eq!(t.chercher([8, 8, 8, 8], 0), None);
    // Sans adresse du tout : rien, pas même la diffusion.
    assert_eq!(Table::new(8).unwrap().chercher([255; 4], 0), None);
}

#[test]
fn plus_long_prefixe_et_ordre() {
    let mut t = slirp();
    t.ajouter_route(Route { reseau: [10, 0, 0, 0], prefixe: 8, passerelle: Some([10, 0, 2, 9]), interface: ETH0, source: [10, 0, 2, 15] }).unwrap();
    // 10.0.2.3 reste sur son réseau (/24 l'emporte sur /8), 10.1.1.1 passe
    // par la route /8.
    assert!(matches!(t.chercher([10, 0, 2, 3], 0), Some(Chemin::Unicast { prochain: [10, 0, 2, 3], .. })));
    assert!(matches!(t.chercher([10, 1, 1, 1], 0), Some(Chemin::Unicast { prochain: [10, 0, 2, 9], .. })));
    // L'ordre de /proc/net/route : par réseau, le plus long préfixe d'abord.
    let r: Vec<([u8; 4], u8)> = t.principales().map(|r| (r.reseau, r.prefixe)).collect();
    assert_eq!(r, [([0; 4], 0), ([10, 0, 0, 0], 8), ([10, 0, 2, 0], 24)]);
}

#[test]
fn refus() {
    let mut t = slirp();
    let a = Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24, boucle: false };
    assert_eq!(t.ajouter_adresse(a), Err(Refus::Existe));
    let defaut = Route { reseau: [0; 4], prefixe: 0, passerelle: Some([10, 0, 2, 2]), interface: ETH0, source: [10, 0, 2, 15] };
    assert_eq!(t.ajouter_route(defaut), Err(Refus::Existe));
    // Une table de deux routes : la troisième ne tient pas.
    let mut t = Table::new(2).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24, boucle: false }).unwrap();
    t.ajouter_route(defaut).unwrap();
    let autre = Route { reseau: [192, 168, 0, 0], prefixe: 16, ..defaut };
    assert_eq!(t.ajouter_route(autre), Err(Refus::Plein));
    // Une adresse en /32 n'a pas de réseau : pas de route.
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: [10, 9, 9, 9], prefixe: 32, boucle: false }).unwrap();
    assert_eq!(t.principales().count(), 0);
    assert_eq!(Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24, boucle: false }.diffusion(), [10, 0, 2, 255]);
}

#[test]
fn boucle() {
    // lo : 127.0.0.1/8, tout son réseau est à nous, sans route principale
    // (rien de plus dans /proc/net/route).
    let mut t = slirp();
    t.ajouter_adresse(Adresse { interface: 9, adresse: [127, 0, 0, 1], prefixe: 8, boucle: true }).unwrap();
    assert_eq!(t.chercher([127, 0, 0, 1], 0), Some(Chemin::Locale { source: [127, 0, 0, 1], interface: 9 }));
    // Une autre adresse de son réseau : la source est celle de lo (la
    // `prefsrc` de la route locale de Linux).
    assert_eq!(t.chercher([127, 1, 2, 3], 0), Some(Chemin::Locale { source: [127, 0, 0, 1], interface: 9 }));
    assert!(t.est_a_nous([127, 9, 9, 9]));
    // Sa diffusion, comme celle de tout réseau : pas à nous, une diffusion
    // de lo, de la source 127.0.0.1.
    assert!(!t.est_a_nous([127, 255, 255, 255]) && t.est_diffusion(9, [127, 255, 255, 255]));
    assert_eq!(t.chercher([127, 255, 255, 255], 0), Some(Chemin::Diffusion { interface: 9, source: [127, 0, 0, 1] }));
    // L'interface qui porte une adresse : la nôtre, pas le reste de 127/8.
    assert_eq!((t.interface_de([10, 0, 2, 15]), t.interface_de([127, 0, 0, 1]), t.interface_de([127, 1, 2, 3])), (Some(ETH0), Some(9), None));
    assert_eq!(t.principales().count(), 2);
}

/// Quelqu'un d'autre (`inet_addr_type` == RTN_UNICAST) : ni nos adresses
/// (127/8 compris), ni une diffusion, ni 0/8, ni une multidiffusion.
#[test]
fn unicast() {
    let mut t = slirp();
    t.ajouter_adresse(Adresse { interface: 9, adresse: [127, 0, 0, 1], prefixe: 8, boucle: true }).unwrap();
    for a in [[10, 0, 2, 2], [10, 0, 2, 3], [8, 8, 8, 8], [10, 0, 3, 255]] {
        assert!(t.est_unicast(a), "{a:?}");
    }
    for a in [[10, 0, 2, 15], [127, 0, 0, 1], [127, 9, 9, 9], [127, 255, 255, 255], [10, 0, 2, 255], [255; 4], [0; 4], [0, 1, 2, 3], [224, 0, 0, 1]] {
        assert!(!t.est_unicast(a), "{a:?}");
    }
}

/// La machine de QEMU telle que la fait le noyau : lo d'abord (1,
/// 127.0.0.1/8), puis la carte (2, 10.0.2.15/24) et la route par défaut.
fn machine() -> Table {
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: LO, adresse: [127, 0, 0, 1], prefixe: 8, boucle: true }).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: MOI, prefixe: 24, boucle: false }).unwrap();
    t.ajouter_route(DEFAUT).unwrap();
    t
}

/// Une interface demandée (l'`oif` de Linux) : seules ses entrées comptent,
/// et sans rien trouver, la destination est sur son lien.
#[test]
fn interface_demandee() {
    let t = machine();
    let lo = [127, 0, 0, 1];
    // Sans interface : notre adresse arrive « par la carte » (sa route
    // locale est la sienne), 127.0.0.2 par lo.
    assert_eq!(t.chercher(MOI, 0), Some(Chemin::Locale { source: MOI, interface: ETH0 }));
    assert_eq!(t.chercher([127, 0, 0, 2], 0), Some(Chemin::Locale { source: lo, interface: LO }));
    // Par lo : tout est livré ici, de l'adresse de la carte (celle de lo est
    // de portée « hôte ») : une adresse d'ailleurs, la passerelle, notre
    // adresse (sa route locale est celle de la carte), la diffusion du
    // réseau (un unicast), la diffusion limitée.
    for d in [[192, 0, 2, 1], [10, 0, 2, 2], MOI, [10, 0, 2, 255]] {
        assert_eq!(t.chercher(d, LO), Some(Chemin::Unicast { interface: LO, prochain: d, source: MOI }), "{d:?}");
    }
    assert_eq!(t.chercher([255; 4], LO), Some(Chemin::Diffusion { interface: LO, source: MOI }));
    // ... sauf son réseau : 127.0.0.2 de 127.0.0.1.
    assert_eq!(t.chercher([127, 0, 0, 2], LO), Some(Chemin::Locale { source: lo, interface: LO }));
    assert_eq!(t.chercher([127, 255, 255, 255], LO), Some(Chemin::Diffusion { interface: LO, source: lo }));
    // Par la carte : 127.0.0.1 va à la passerelle ; notre adresse est à
    // elle ; la diffusion limitée part par elle, sans table.
    assert_eq!(t.chercher(lo, ETH0), Some(Chemin::Unicast { interface: ETH0, prochain: [10, 0, 2, 2], source: MOI }));
    assert_eq!(t.chercher(MOI, ETH0), Some(Chemin::Locale { source: MOI, interface: ETH0 }));
    assert_eq!(t.chercher([255; 4], ETH0), Some(Chemin::Diffusion { interface: ETH0, source: MOI }));
    assert_eq!(t.chercher([10, 0, 2, 255], ETH0), Some(Chemin::Diffusion { interface: ETH0, source: MOI }));
    // Une interface sans adresse ni route : la destination sur son lien, la
    // source de la première interface qui en propose une.
    assert_eq!(t.chercher([192, 0, 2, 1], 3), Some(Chemin::Unicast { interface: 3, prochain: [192, 0, 2, 1], source: MOI }));
    assert_eq!(t.chercher([255; 4], 3), Some(Chemin::Diffusion { interface: 3, source: MOI }));
}

/// 0.0.0.0, « cette machine » : livré par lo, sans table.
#[test]
fn cette_machine() {
    let t = machine();
    let lo = [127, 0, 0, 1];
    // La source demandée devient la destination, sinon 127.0.0.1 ; arrivée
    // par lo.
    assert_eq!(t.router([0; 4], None, 0), Some((Chemin::Locale { source: lo, interface: LO }, lo)));
    assert_eq!(t.router([0; 4], Some(MOI), 0), Some((Chemin::Locale { source: MOI, interface: LO }, MOI)));
    // Avec une interface : l'adresse qu'elle propose de portée « hôte »,
    // arrivée par elle (mesuré : par la carte, la source 127.0.0.1 donne
    // 127.0.0.1 vers 127.0.0.1, par lo).
    assert_eq!(t.router([0; 4], None, ETH0), Some((Chemin::Locale { source: MOI, interface: ETH0 }, MOI)));
    assert_eq!(t.router([0; 4], Some(lo), ETH0), Some((Chemin::Locale { source: lo, interface: ETH0 }, lo)));
    assert_eq!(t.router([0; 4], None, LO), Some((Chemin::Locale { source: lo, interface: LO }, lo)));
    // Ailleurs : `chercher`.
    assert_eq!(t.router([8, 8, 8, 8], None, 0), Some((Chemin::Unicast { interface: ETH0, prochain: [10, 0, 2, 2], source: MOI }, [8, 8, 8, 8])));
    assert_eq!(t.router([8, 8, 8, 8], None, LO), Some((Chemin::Unicast { interface: LO, prochain: [8, 8, 8, 8], source: MOI }, [8, 8, 8, 8])));
}

/// `inet_select_addr`, et l'interface d'une adresse à nous.
#[test]
fn adresses_proposees() {
    let t = machine();
    let lo = [127, 0, 0, 1];
    assert_eq!(t.adresse_proposee(ETH0, [0; 4], Portee::Univers), Some(MOI));
    assert_eq!(t.adresse_proposee(LO, [0; 4], Portee::Hote), Some(lo));
    assert_eq!(t.adresse_proposee(LO, [0; 4], Portee::Lien), Some(MOI));
    assert_eq!(t.adresse_proposee(LO, [0; 4], Portee::Univers), Some(MOI));
    // lo seule : rien pour un lien.
    let mut seule = Table::new(4).unwrap();
    seule.ajouter_adresse(Adresse { interface: LO, adresse: lo, prefixe: 8, boucle: true }).unwrap();
    assert_eq!(seule.adresse_proposee(LO, [0; 4], Portee::Lien), None);
    // Deux adresses sur la carte : celle du réseau de `vers`, sinon la
    // première.
    let mut deux = machine();
    deux.ajouter_adresse(Adresse { interface: ETH0, adresse: [192, 168, 1, 5], prefixe: 24, boucle: false }).unwrap();
    assert_eq!(deux.adresse_proposee(ETH0, [192, 168, 1, 77], Portee::Univers), Some([192, 168, 1, 5]));
    assert_eq!(deux.adresse_proposee(ETH0, [172, 16, 0, 1], Portee::Univers), Some(MOI));
    // Ailleurs que sur l'interface : la première dans l'ordre des numéros,
    // pas des ajouts.
    let mut ordre = Table::new(4).unwrap();
    ordre.ajouter_adresse(Adresse { interface: LO, adresse: lo, prefixe: 8, boucle: true }).unwrap();
    ordre.ajouter_adresse(Adresse { interface: 5, adresse: [10, 5, 5, 5], prefixe: 8, boucle: false }).unwrap();
    ordre.ajouter_adresse(Adresse { interface: 3, adresse: [10, 3, 3, 3], prefixe: 8, boucle: false }).unwrap();
    assert_eq!(ordre.adresse_proposee(LO, [0; 4], Portee::Lien), Some([10, 3, 3, 3]));
    // L'interface d'une adresse à nous : 127.0.0.2 est à lo, pas sa
    // diffusion.
    assert_eq!(t.interface_locale(MOI), Some(ETH0));
    assert_eq!(t.interface_locale([127, 0, 0, 2]), Some(LO));
    assert_eq!(t.interface_locale([127, 255, 255, 255]), None);
    assert_eq!(t.interface_locale([192, 0, 2, 1]), None);
}

/// `fib_compute_spec_dst` pour ce qui n'était pas pour une seule de nos
/// adresses.
#[test]
fn adresse_pour_repondre() {
    let t = machine();
    let lo = [127, 0, 0, 1];
    // La source de la route vers l'émetteur.
    assert_eq!(t.adresse_pour_repondre([10, 0, 2, 2], ETH0), MOI);
    assert_eq!(t.adresse_pour_repondre([8, 8, 8, 8], ETH0), MOI);
    assert_eq!(t.adresse_pour_repondre(lo, LO), lo);
    assert_eq!(t.adresse_pour_repondre(MOI, LO), MOI);
    // De 0.0.0.0 (un client DHCP) : celle de l'interface pour son lien.
    assert_eq!(t.adresse_pour_repondre([0; 4], ETH0), MOI);
    // Pas de route vers l'émetteur : celle de l'interface de portée
    // « univers » (par lo : celle de la carte).
    let mut sans_defaut = Table::new(4).unwrap();
    sans_defaut.ajouter_adresse(Adresse { interface: LO, adresse: lo, prefixe: 8, boucle: true }).unwrap();
    sans_defaut.ajouter_adresse(Adresse { interface: ETH0, adresse: MOI, prefixe: 24, boucle: false }).unwrap();
    assert_eq!(sans_defaut.adresse_pour_repondre([8, 8, 8, 8], LO), MOI);
    assert_eq!(sans_defaut.adresse_pour_repondre([8, 8, 8, 8], ETH0), MOI);
}
