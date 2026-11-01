//! Les adresses et la table de routage : ce que donnent la configuration de
//! slirp (10.0.2.15/24, la route par défaut par 10.0.2.2) et les cas de
//! Linux (la table locale d'abord, le plus long préfixe, la diffusion).

use inet::routes::{Adresse, Chemin, Refus, Route, Table};

const ETH0: u32 = 1;

fn slirp() -> Table {
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24 }).unwrap();
    t.ajouter_route(Route { reseau: [0; 4], prefixe: 0, passerelle: Some([10, 0, 2, 2]), interface: ETH0, source: [10, 0, 2, 15] }).unwrap();
    t
}

#[test]
fn chemins() {
    let t = slirp();
    let src = [10, 0, 2, 15];
    assert_eq!(t.chercher([10, 0, 2, 15]), Some(Chemin::Locale { source: src }));
    assert_eq!(t.chercher([10, 0, 2, 255]), Some(Chemin::Diffusion { interface: ETH0, source: src }));
    assert_eq!(t.chercher([255; 4]), Some(Chemin::Diffusion { interface: ETH0, source: src }));
    // Sur le réseau : directement ; ailleurs : par la passerelle.
    assert_eq!(t.chercher([10, 0, 2, 3]), Some(Chemin::Unicast { interface: ETH0, prochain: [10, 0, 2, 3], source: src }));
    assert_eq!(t.chercher([160, 79, 104, 10]), Some(Chemin::Unicast { interface: ETH0, prochain: [10, 0, 2, 2], source: src }));
    assert!(t.est_a_nous(src) && !t.est_a_nous([10, 0, 2, 2]));
    assert!(t.est_diffusion(ETH0, [10, 0, 2, 255]) && t.est_diffusion(ETH0, [255; 4]) && !t.est_diffusion(ETH0, [10, 0, 2, 2]));
    // Sans route par défaut : rien hors du réseau.
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: src, prefixe: 24 }).unwrap();
    assert_eq!(t.chercher([8, 8, 8, 8]), None);
    // Sans adresse du tout : rien, pas même la diffusion.
    assert_eq!(Table::new(8).unwrap().chercher([255; 4]), None);
}

#[test]
fn plus_long_prefixe_et_ordre() {
    let mut t = slirp();
    t.ajouter_route(Route { reseau: [10, 0, 0, 0], prefixe: 8, passerelle: Some([10, 0, 2, 9]), interface: ETH0, source: [10, 0, 2, 15] }).unwrap();
    // 10.0.2.3 reste sur son réseau (/24 l'emporte sur /8), 10.1.1.1 passe
    // par la route /8.
    assert!(matches!(t.chercher([10, 0, 2, 3]), Some(Chemin::Unicast { prochain: [10, 0, 2, 3], .. })));
    assert!(matches!(t.chercher([10, 1, 1, 1]), Some(Chemin::Unicast { prochain: [10, 0, 2, 9], .. })));
    // L'ordre de /proc/net/route : par réseau, le plus long préfixe d'abord.
    let r: Vec<([u8; 4], u8)> = t.principales().map(|r| (r.reseau, r.prefixe)).collect();
    assert_eq!(r, [([0; 4], 0), ([10, 0, 0, 0], 8), ([10, 0, 2, 0], 24)]);
}

#[test]
fn refus() {
    let mut t = slirp();
    let a = Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24 };
    assert_eq!(t.ajouter_adresse(a), Err(Refus::Existe));
    let defaut = Route { reseau: [0; 4], prefixe: 0, passerelle: Some([10, 0, 2, 2]), interface: ETH0, source: [10, 0, 2, 15] };
    assert_eq!(t.ajouter_route(defaut), Err(Refus::Existe));
    // Une table de deux routes : la troisième ne tient pas.
    let mut t = Table::new(2).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24 }).unwrap();
    t.ajouter_route(defaut).unwrap();
    let autre = Route { reseau: [192, 168, 0, 0], prefixe: 16, ..defaut };
    assert_eq!(t.ajouter_route(autre), Err(Refus::Plein));
    // Une adresse en /32 n'a pas de réseau : pas de route.
    let mut t = Table::new(8).unwrap();
    t.ajouter_adresse(Adresse { interface: ETH0, adresse: [10, 9, 9, 9], prefixe: 32 }).unwrap();
    assert_eq!(t.principales().count(), 0);
    assert_eq!(Adresse { interface: ETH0, adresse: [10, 0, 2, 15], prefixe: 24 }.diffusion(), [10, 0, 2, 255]);
}
