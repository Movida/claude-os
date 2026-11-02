//! Le décodeur de l'espace de configuration PCI contre les vraies fonctions
//! de QEMU 8.2 (machine `pc`, avec deux cartes virtio-net dont une derrière
//! un pont, capturées par le moniteur de QEMU : tests/pci/capturer.sh),
//! puis contre des espaces abîmés à la main, puis des mutations au hasard,
//! à graine fixe : aucune panique, et ce qui est accepté vérifie ses
//! invariants.

use formats::pci::{self, Bar, CapaciteVirtio, Entete, Erreur, Genre, MsiX, StructureVirtio};
use std::path::PathBuf;

/// L'espace capturé de la fonction bus:periph.fonction.
fn capture(nom: &str) -> Vec<u8> {
    let chemin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pci").join(format!("{nom}.dat"));
    std::fs::read(&chemin).unwrap_or_else(|_| panic!("pas de capture {} (tests/pci/capturer.sh)", chemin.display()))
}

fn capacites(o: &[u8]) -> Vec<(usize, u8)> {
    pci::lire_entete(o).unwrap().capacites(o).collect()
}

#[test]
fn fonctions_de_qemu() {
    // (fonction, fabricant, modèle, classe, multifonction, genre)
    let attendu: [(&str, u16, u16, u32, bool, Genre); 9] = [
        ("00-00-0", 0x8086, 0x1237, 0x06_00_00, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x1100 }),
        ("00-01-0", 0x8086, 0x7000, 0x06_01_00, true, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x1100 }),
        ("00-01-1", 0x8086, 0x7010, 0x01_01_80, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x1100 }),
        ("00-01-3", 0x8086, 0x7113, 0x06_80_00, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x1100 }),
        ("00-02-0", 0x1234, 0x1111, 0x03_00_00, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x1100 }),
        ("00-03-0", 0x1af4, 0x1000, 0x02_00_00, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x0001 }),
        ("00-04-0", 0x1b36, 0x0001, 0x06_04_00, false, Genre::Pont { primaire: 0, secondaire: 1, subordonne: 1 }),
        ("00-05-0", 0x1af4, 0x1001, 0x01_00_00, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x0002 }),
        ("01-01-0", 0x1af4, 0x1000, 0x02_00_00, false, Genre::Ordinaire { sous_vendeur: 0x1af4, sous_systeme: 0x0001 }),
    ];
    for (nom, vendeur, peripherique, classe, multifonction, genre) in attendu {
        let e: Entete = pci::lire_entete(&capture(nom)).unwrap();
        assert_eq!((e.vendeur, e.peripherique, e.classe, e.multifonction, e.genre),
                   (vendeur, peripherique, classe, multifonction, genre), "{nom}");
    }
    // Les fonctions du chipset n'ont pas de capacités ; le pont a les
    // siennes (son numéro de fente, MSI, l'ajout à chaud de QEMU).
    assert_eq!(capacites(&capture("00-00-0")), []);
    assert_eq!(capacites(&capture("00-04-0")), [(0x4c, 0x05), (0x48, 0x04), (0x40, 0x0c)]);
}

#[test]
fn virtio_net() {
    let o = capture("00-03-0");
    let e = pci::lire_entete(&o).unwrap();
    assert_eq!(e.nb_bar(), 6);
    assert_eq!(e.broche, 1, "INTA");
    let liste = capacites(&o);
    assert_eq!(liste, [(0x98, 0x11), (0x84, 0x09), (0x70, 0x09), (0x60, 0x09), (0x50, 0x09), (0x40, 0x09)]);
    // MSI-X : 4 entrées (la configuration, puis réception et émission, et
    // la file de contrôle), la table au début de la BAR 1, le PBA à 2 Kio.
    assert_eq!(pci::lire_msix(&o, 0x98).unwrap(),
               MsiX { position: 0x98, entrees: 4, bar_table: 1, decalage_table: 0, bar_pba: 1, decalage_pba: 0x800 });
    // Les structures de virtio 1.x, toutes dans la BAR 4, une page chacune.
    let structures: Vec<CapaciteVirtio> = liste[1..].iter().map(|&(p, _)| pci::lire_virtio(&o, p).unwrap()).collect();
    let page = |structure, decalage| CapaciteVirtio { structure, bar: 4, decalage, longueur: 0x1000 };
    assert_eq!(structures, [
        CapaciteVirtio { structure: StructureVirtio::AccesPci, bar: 0, decalage: 0, longueur: 0 },
        page(StructureVirtio::Notification { multiplicateur: 4 }, 0x3000),
        page(StructureVirtio::Peripherique, 0x2000),
        page(StructureVirtio::Isr, 0x1000),
        page(StructureVirtio::Commune, 0),
    ]);
    // Les BAR telles que les a placées SeaBIOS : leurs valeurs, avant toute
    // mesure. BAR0 des ports d'E/S (l'interface d'avant 1.0), BAR1 la table
    // MSI-X, BAR4 (64 bits, prefetchable) occupe aussi BAR5.
    let bar = |i: usize| u32::from_le_bytes(o[pci::BAR0 + 4 * i..pci::BAR0 + 4 * i + 4].try_into().unwrap());
    assert_eq!(bar(0) & 1, 1);
    assert!(!pci::bar_64(bar(1)) && pci::bar_64(bar(4)));
}

#[test]
fn derriere_le_pont() {
    // La même carte, sur le bus 1 : les BAR sont dans la fenêtre du pont,
    // les capacités les mêmes.
    let o = capture("01-01-0");
    assert_eq!(capacites(&o), capacites(&capture("00-03-0")));
}

#[test]
fn bar() {
    // Ports d'E/S : 32 ports (les bits 0 à 4 ne sont pas décodés) ; les 16
    // bits hauts de la mesure ne comptent pas.
    assert_eq!(pci::decoder_bar(0xc081, 0xffff_ffe1, None), Bar::Es { port: 0xc080, taille: 32 });
    assert_eq!(pci::decoder_bar(0xc081, 0x0000_ffe1, None), Bar::Es { port: 0xc080, taille: 32 });
    // Mémoire 32 bits, 4 Kio ; 16 Mio prefetchable.
    assert_eq!(pci::decoder_bar(0xfeb9_1000, 0xffff_f000, None),
               Bar::Memoire { adresse: 0xfeb9_1000, taille: 4096, bits64: false, prefetchable: false });
    assert_eq!(pci::decoder_bar(0xfd00_0008, 0xff00_0008, None),
               Bar::Memoire { adresse: 0xfd00_0000, taille: 16 << 20, bits64: false, prefetchable: true });
    // 64 bits : 16 Kio, et une fenêtre de 8 Gio placée au-dessus de 4 Gio.
    assert_eq!(pci::decoder_bar(0xfe00_000c, 0xffff_c00c, Some((0, 0xffff_ffff))),
               Bar::Memoire { adresse: 0xfe00_0000, taille: 16 << 10, bits64: true, prefetchable: true });
    assert_eq!(pci::decoder_bar(0x0000_000c, 0x0000_000c, Some((0x8, 0xffff_fffe))),
               Bar::Memoire { adresse: 0x8_0000_0000, taille: 8 << 30, bits64: true, prefetchable: true });
    // Pas de BAR : la mesure ne garde aucun bit d'adresse.
    assert_eq!(pci::decoder_bar(0, 0, None), Bar::Aucune);
    assert_eq!(pci::decoder_bar(1, 1, None), Bar::Aucune);
    assert_eq!(pci::decoder_bar(4, 4, Some((0, 0))), Bar::Aucune);
    // Tout à 1 : personne ne répond (le cas de Linux, PCI_POSSIBLE_ERROR),
    // pour des ports comme pour de la mémoire.
    assert_eq!(pci::decoder_bar(0xfeb9_1000, 0xffff_ffff, None), Bar::Aucune);
    assert_eq!(pci::decoder_bar(0x0000_c001, 0xffff_ffff, None), Bar::Aucune);
    assert_eq!(pci::decoder_bar(0xffff_ffff, 0xffff_f000, None), Bar::Aucune);
}

#[test]
fn espaces_abimes() {
    let base = capture("00-03-0");
    assert_eq!(pci::lire_entete(&base[..255]), Err(Erreur::Tronque));
    let mut o = base.clone();
    o[0] = 0xff;
    o[1] = 0xff;
    assert_eq!(pci::lire_entete(&o), Err(Erreur::Absente));
    let mut o = base.clone();
    o[0x0e] = 2;
    assert_eq!(pci::lire_entete(&o), Err(Erreur::TypeInconnu(2)));
    // Sans le bit d'état, la liste n'est pas lue (le pointeur y est encore).
    let mut o = base.clone();
    o[pci::ETAT] &= !(pci::ETAT_CAPACITES as u8);
    assert_eq!(capacites(&o), []);
    // Une capacité qui pointe sur elle-même : 48 maillons, puis on s'arrête.
    let mut o = base.clone();
    o[0x99] = 0x98;
    assert_eq!(capacites(&o).len(), pci::MAILLONS_MAX);
    // Un pointeur dans l'en-tête arrête la liste ; ses deux bits bas sont
    // ignorés ; le numéro 0xFF aussi l'arrête.
    let mut o = base.clone();
    o[0x85] = 0x3c;
    assert_eq!(capacites(&o), [(0x98, 0x11), (0x84, 0x09)]);
    let mut o = base.clone();
    o[0x99] = 0x87;
    assert_eq!(capacites(&o)[1], (0x84, 0x09));
    let mut o = base.clone();
    o[0x70] = 0xff;
    assert_eq!(capacites(&o), [(0x98, 0x11), (0x84, 0x09)]);
    // Des capacités qui débordent, ou trop courtes pour leur type.
    let mut o = base.clone();
    o[0xf8] = pci::CAPACITE_MSIX;
    assert_eq!(pci::lire_msix(&o, 0xf8), Err(Erreur::Capacite));
    assert_eq!(pci::lire_msix(&o, 0x84), Err(Erreur::Capacite), "pas MSI-X");
    let mut o = base.clone();
    o[0x72] = 16;
    assert_eq!(pci::lire_virtio(&o, 0x70), Err(Erreur::Capacite), "notification sans multiplicateur");
    let mut o = base.clone();
    o[0xf4] = pci::CAPACITE_FABRICANT;
    o[0xf6] = 16;
    o[0xf7] = 1;
    assert_eq!(pci::lire_virtio(&o, 0xf4), Err(Erreur::Capacite), "hors de l'espace");
}

/// Un générateur à graine fixe (xorshift64*), pour des mutations qui se
/// rejouent.
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[test]
fn mutations() {
    let mut h = Hasard(0x9c1_c0de);
    let originaux: Vec<Vec<u8>> = ["00-00-0", "00-01-0", "00-02-0", "00-03-0", "00-04-0", "00-05-0"].iter().map(|n| capture(n)).collect();
    let mut acceptes = 0;
    for n in 0..200_000 {
        let mut o = originaux[n % originaux.len()].clone();
        for _ in 0..1 + h.suivant() % 6 {
            let i = (h.suivant() as usize) % o.len();
            o[i] = h.suivant() as u8;
        }
        if h.suivant() % 16 == 0 {
            o.truncate((h.suivant() as usize) % (o.len() + 1));
        }
        if let Ok(e) = pci::lire_entete(&o) {
            acceptes += 1;
            let liste: Vec<(usize, u8)> = e.capacites(&o).collect();
            assert!(liste.len() <= pci::MAILLONS_MAX);
            for &(p, numero) in &liste {
                assert!(p >= pci::TAILLE_ENTETE && p < pci::TAILLE_ESPACE && p % 4 == 0 && o[p] == numero);
                if let Ok(m) = pci::lire_msix(&o, p) {
                    assert!((1..=2048).contains(&m.entrees) && m.bar_table < 8 && m.decalage_table % 8 == 0);
                }
                if let Ok(v) = pci::lire_virtio(&o, p) {
                    assert!(p + o[p + 2] as usize <= pci::TAILLE_ESPACE);
                    let _ = v;
                }
            }
        }
        let b = h.suivant();
        let _ = pci::decoder_bar(b as u32, (b >> 32) as u32, Some((h.suivant() as u32, h.suivant() as u32)));
    }
    assert!(acceptes > 100_000, "trop peu d'espaces acceptés ({acceptes}) : le test ne mord plus");
}
