//! Le lecteur des tables ACPI contre les vraies tables de QEMU 8.2
//! (machines `pc` et `q35`, capturées par tests/acpi/capturer.sh), puis
//! contre des tables faites à la main (la XSDT d'ACPI 2.0, que QEMU n'a
//! pas, et chaque cas d'erreur), puis des mutations au hasard, à graine
//! fixe (un échec se rejoue) : aucune panique, et tout ce qui est accepté
//! vérifie ses invariants.

use formats::acpi::{self, Entree, Erreur, Madt};
use std::path::PathBuf;

/// Les octets capturés pour `machine` : (adresse du premier octet, octets),
/// pour la page de la RSDP et la zone des tables.
fn capture(machine: &str, genre: &str) -> (u64, Vec<u8>) {
    let dossier = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/acpi");
    let prefixe = format!("{machine}-{genre}-");
    for e in std::fs::read_dir(&dossier).expect("tests/acpi") {
        let nom = e.unwrap().file_name().into_string().unwrap();
        if let Some(reste) = nom.strip_prefix(&prefixe).and_then(|r| r.strip_suffix(".dat")) {
            let base = u64::from_str_radix(reste, 16).expect("adresse dans le nom");
            return (base, std::fs::read(dossier.join(&nom)).unwrap());
        }
    }
    panic!("pas de capture {prefixe}*.dat (tests/acpi/capturer.sh)")
}

/// Les octets de la mémoire capturée à l'adresse physique `adresse`.
fn a(zone: &(u64, Vec<u8>), adresse: u64) -> &[u8] {
    let i = adresse.checked_sub(zone.0).expect("adresse avant la capture") as usize;
    zone.1.get(i..).unwrap_or_else(|| panic!("adresse {adresse:#x} hors de la capture"))
}

/// Ce que la machine `machine` doit montrer, comme le noyau le lit.
fn verifier_machine(machine: &str, signatures: &[&[u8; 4]], revision_fadt: u8, siecle: Option<u8>) {
    let rsdp_page = capture(machine, "rsdp");
    let tables = capture(machine, "tables");
    let i = acpi::chercher_rsdp(&rsdp_page.1).expect("RSDP introuvable");
    assert_eq!(i % 16, 0);
    let rsdp = acpi::lire_rsdp(&rsdp_page.1[i..]).unwrap();
    assert_eq!((rsdp.revision, &rsdp.oem, rsdp.xsdt), (0, b"BOCHS ", None), "{machine} : ACPI 1.0, sans XSDT");
    let rsdt = acpi::lire_table_signee(a(&tables, rsdp.rsdt as u64), b"RSDT").unwrap();
    let adresses: Vec<u64> = acpi::adresses(&rsdt, false).collect();
    let lues: Vec<[u8; 4]> = adresses.iter().map(|&x| acpi::lire_table(a(&tables, x)).unwrap().signature).collect();
    assert_eq!(lues.iter().collect::<Vec<_>>(), signatures.to_vec(), "{machine} : les tables de la RSDT");
    for &x in &adresses {
        let t = acpi::lire_table(a(&tables, x)).unwrap();
        match &t.signature {
            b"APIC" => {
                let m = Madt::lire(&t).unwrap();
                assert_eq!((m.apic_local, m.drapeaux & acpi::PCAT_COMPAT), (0xfee0_0000, 1));
                let entrees: Vec<Entree> = m.entrees().map(Result::unwrap).collect();
                // Mesuré : un processeur, un IO-APIC, l'IRQ 0 sur le GSI 2,
                // les IRQ 5, 9, 10, 11 en niveau actif haut, le NMI sur LINT1.
                let mut attendu = vec![
                    Entree::Processeur { processeur: 0, apic: 0, drapeaux: 1 },
                    Entree::IoApic { numero: 0, adresse: 0xfec0_0000, gsi_base: 0 },
                    Entree::Remplacement { bus: 0, source: 0, gsi: 2, drapeaux: 0 },
                ];
                for irq in [5, 9, 10, 11] {
                    attendu.push(Entree::Remplacement { bus: 0, source: irq, gsi: irq as u32, drapeaux: 0xd });
                }
                attendu.push(Entree::NmiApic { processeur: 0xff, drapeaux: 0, lint: 1 });
                assert_eq!(entrees, attendu, "{machine} : la MADT");
            }
            b"FACP" => {
                assert_eq!(t.revision, revision_fadt, "{machine} : la révision de la FADT");
                assert_eq!(acpi::registre_du_siecle(&t), siecle, "{machine} : le siècle");
            }
            _ => {}
        }
    }
}

#[test]
fn qemu_pc() {
    // FADT de révision 1 : son registre du siècle (0x32) n'est pas pris,
    // comme sous Linux.
    verifier_machine("pc", &[b"FACP", b"APIC", b"HPET", b"WAET"], 1, None);
}

#[test]
fn qemu_q35() {
    verifier_machine("q35", &[b"FACP", b"APIC", b"HPET", b"MCFG", b"WAET"], 3, Some(0x32));
}

/// Rend nulle la somme des octets de `o`, en changeant l'octet `i`.
fn sommer(o: &mut [u8], i: usize) {
    o[i] = 0;
    let s = o.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    o[i] = 0u8.wrapping_sub(s);
}

/// Une table d'en-tête complet, de signature `signature`, avec `corps`.
fn table(signature: &[u8; 4], revision: u8, corps: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; acpi::TAILLE_ENTETE];
    t[..4].copy_from_slice(signature);
    t[4..8].copy_from_slice(&((acpi::TAILLE_ENTETE + corps.len()) as u32).to_le_bytes());
    t[8] = revision;
    t.extend_from_slice(corps);
    sommer(&mut t, 9);
    t
}

/// Une RSDP d'ACPI 2.0 qui désigne une XSDT.
fn rsdp_2(xsdt: u64) -> Vec<u8> {
    let mut r = vec![0u8; acpi::TAILLE_RSDP_2];
    r[..8].copy_from_slice(acpi::SIGNATURE_RSDP);
    r[9..15].copy_from_slice(b"MAISON");
    r[15] = 2;
    r[16..20].copy_from_slice(&0x1234u32.to_le_bytes());
    r[20..24].copy_from_slice(&(acpi::TAILLE_RSDP_2 as u32).to_le_bytes());
    r[24..32].copy_from_slice(&xsdt.to_le_bytes());
    sommer(&mut r[..20], 8);
    sommer(&mut r, 32);
    r
}

#[test]
fn xsdt_faite_a_la_main() {
    let r = rsdp_2(0x1_0000_0000);
    let lue = acpi::lire_rsdp(&r).unwrap();
    assert_eq!((lue.revision, lue.rsdt, lue.xsdt), (2, 0x1234, Some(0x1_0000_0000)));
    // Une XSDT de deux adresses de 64 bits, plus 4 octets en trop (ignorés).
    let mut corps = Vec::new();
    corps.extend_from_slice(&0xdead_beef_0000u64.to_le_bytes());
    corps.extend_from_slice(&0x7ffe_0000u64.to_le_bytes());
    corps.extend_from_slice(&[1, 2, 3, 4]);
    let x = table(b"XSDT", 1, &corps);
    let t = acpi::lire_table_signee(&x, b"XSDT").unwrap();
    assert_eq!(acpi::adresses(&t, true).collect::<Vec<_>>(), [0xdead_beef_0000, 0x7ffe_0000]);
    assert_eq!(acpi::lire_table_signee(&x, b"RSDT"), Err(Erreur::Signature));
}

#[test]
fn rsdp_refusees() {
    let bonne = rsdp_2(0x1000);
    // La seconde somme fausse, la première juste.
    let mut r = bonne.clone();
    r[33] ^= 1;
    assert_eq!(acpi::lire_rsdp(&r), Err(Erreur::Somme));
    // La première fausse.
    let mut r = bonne.clone();
    r[10] ^= 1;
    assert_eq!(acpi::lire_rsdp(&r), Err(Erreur::Somme));
    // Une longueur de moins de 36 octets pour une révision 2.
    let mut r = bonne.clone();
    r[20..24].copy_from_slice(&20u32.to_le_bytes());
    sommer(&mut r[..20], 8);
    assert_eq!(acpi::lire_rsdp(&r), Err(Erreur::Longueur));
    // Tronquée : 30 octets pour une révision 2, 19 pour toute RSDP.
    assert_eq!(acpi::lire_rsdp(&bonne[..30]), Err(Erreur::Tronquee));
    assert_eq!(acpi::lire_rsdp(&bonne[..19]), Err(Erreur::Tronquee));
    // Une révision 0 n'a que 20 octets à vérifier : ce qui suit est ignoré.
    let mut r = bonne[..20].to_vec();
    r[15] = 0;
    sommer(&mut r, 8);
    r.extend_from_slice(&[0xff; 16]);
    assert_eq!(acpi::lire_rsdp(&r).map(|x| x.xsdt), Ok(None));
    // La signature.
    let mut r = bonne.clone();
    r[0] = b'X';
    assert_eq!(acpi::lire_rsdp(&r), Err(Erreur::Signature));
    // La recherche ne regarde qu'aux multiples de 16.
    let mut zone = vec![0u8; 64];
    zone[8..8 + 36].copy_from_slice(&bonne);
    assert_eq!(acpi::chercher_rsdp(&zone), None);
    let mut zone = vec![0u8; 64];
    zone[16..16 + 36].copy_from_slice(&bonne);
    assert_eq!(acpi::chercher_rsdp(&zone), Some(16));
}

#[test]
fn tables_refusees() {
    let t = table(b"TEST", 1, &[1, 2, 3]);
    assert!(acpi::lire_table(&t).is_ok());
    let mut faux = t.clone();
    faux[37] ^= 1;
    assert_eq!(acpi::lire_table(&faux), Err(Erreur::Somme));
    assert_eq!(acpi::lire_table(&t[..t.len() - 1]), Err(Erreur::Tronquee));
    assert_eq!(acpi::lire_table(&t[..7]), Err(Erreur::Tronquee));
    let mut court = t.clone();
    court[4..8].copy_from_slice(&35u32.to_le_bytes());
    assert_eq!(acpi::lire_table(&court), Err(Erreur::Longueur));
    // Des octets après la table : ignorés.
    let mut long = t.clone();
    long.extend_from_slice(&[9; 10]);
    assert_eq!(acpi::lire_table(&long).map(|x| x.corps), Ok(&[1u8, 2, 3][..]));
}

/// Une MADT faite de ces entrées (des octets bruts).
fn madt(entrees: &[&[u8]]) -> Vec<u8> {
    let mut corps = vec![0, 0, 0xe0, 0xfe, 1, 0, 0, 0];
    for e in entrees {
        corps.extend_from_slice(e);
    }
    table(b"APIC", 3, &corps)
}

fn lire_entrees(t: &[u8]) -> Vec<Result<Entree, Erreur>> {
    let t = acpi::lire_table(t).unwrap();
    Madt::lire(&t).unwrap().entrees().collect()
}

#[test]
fn entrees_de_la_madt() {
    // L'adresse 64 bits de l'APIC, un type inconnu (x2APIC, 16 octets).
    let t = madt(&[&[5, 12, 0, 0, 0, 0, 0xfe, 0, 1, 0, 0, 0], &[9, 16, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0]]);
    assert_eq!(lire_entrees(&t), [Ok(Entree::AdresseApic(0x1_00fe_0000)), Ok(Entree::Autre(9))]);
    // Une entrée de longueur 0 ou 1 : la lecture s'arrête (sinon, on
    // tournerait sur place).
    for l in [0, 1] {
        let t = madt(&[&[0, 8, 0, 0, 1, 0, 0, 0], &[7, l]]);
        let e = lire_entrees(&t);
        assert_eq!(e.len(), 2);
        assert_eq!(e[1], Err(Erreur::Longueur));
    }
    // Une entrée qui dépasse la table, ou trop courte pour son type.
    let t = madt(&[&[1, 20, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0]]);
    assert_eq!(lire_entrees(&t), [Err(Erreur::Longueur)]);
    let t = madt(&[&[1, 8, 0, 0, 0, 0, 0xc0, 0xfe]]);
    assert_eq!(lire_entrees(&t), [Err(Erreur::Longueur)]);
    // Un octet seul en fin de table : une entrée tronquée.
    let t = madt(&[&[0]]);
    assert_eq!(lire_entrees(&t), [Err(Erreur::Longueur)]);
    // La MADT elle-même : son en-tête propre (8 octets) doit y être.
    let t = table(b"APIC", 3, &[0, 0, 0xe0]);
    assert_eq!(Madt::lire(&acpi::lire_table(&t).unwrap()), Err(Erreur::Tronquee));
}

#[test]
fn siecle() {
    let mut corps = vec![0u8; 116 - acpi::TAILLE_ENTETE];
    corps[108 - acpi::TAILLE_ENTETE] = 0x32;
    let fadt = |revision| table(b"FACP", revision, &corps);
    for (revision, attendu) in [(1, None), (2, None), (3, Some(0x32)), (6, Some(0x32))] {
        assert_eq!(acpi::registre_du_siecle(&acpi::lire_table(&fadt(revision)).unwrap()), attendu);
    }
    // Trop courte, ou un registre nul : pas de siècle.
    let courte = table(b"FACP", 3, &[0; 60]);
    assert_eq!(acpi::registre_du_siecle(&acpi::lire_table(&courte).unwrap()), None);
    corps[108 - acpi::TAILLE_ENTETE] = 0;
    assert_eq!(acpi::registre_du_siecle(&acpi::lire_table(&table(b"FACP", 3, &corps)).unwrap()), None);
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
    let mut h = Hasard(0x6e5a_c0de);
    let mut originaux = Vec::new();
    for machine in ["pc", "q35"] {
        let tables = capture(machine, "tables");
        let rsdp_page = capture(machine, "rsdp");
        let i = acpi::chercher_rsdp(&rsdp_page.1).unwrap();
        let rsdp = acpi::lire_rsdp(&rsdp_page.1[i..]).unwrap();
        originaux.push(rsdp_page.1[i..i + 20].to_vec());
        let rsdt = acpi::lire_table(a(&tables, rsdp.rsdt as u64)).unwrap();
        for x in acpi::adresses(&rsdt, false) {
            let o = a(&tables, x);
            originaux.push(o[..acpi::longueur(o).unwrap()].to_vec());
        }
    }
    originaux.push(rsdp_2(0x1000));
    let mut acceptees = 0;
    for n in 0..200_000 {
        let mut o = originaux[n % originaux.len()].clone();
        for _ in 0..1 + h.suivant() % 4 {
            let i = (h.suivant() as usize) % o.len();
            o[i] = h.suivant() as u8;
        }
        // Parfois tronquée, parfois rallongée.
        match h.suivant() % 8 {
            0 => o.truncate((h.suivant() as usize) % (o.len() + 1)),
            1 => o.extend((0..h.suivant() % 64).map(|_| h.suivant() as u8)),
            _ => {}
        }
        // Une mutation sur deux est « réparée » : la somme recalculée, pour
        // passer la somme et atteindre la lecture des champs.
        if h.suivant() % 2 == 0 && o.len() > 9 {
            if let Ok(l) = acpi::longueur(&o) {
                if l <= o.len() {
                    sommer(&mut o[..l], 9);
                }
            }
        }
        let _ = acpi::lire_rsdp(&o);
        let _ = acpi::chercher_rsdp(&o);
        if let Ok(t) = acpi::lire_table(&o) {
            acceptees += 1;
            // Invariants : le corps est dans les octets donnés, la somme de
            // la table entière est nulle.
            let l = acpi::TAILLE_ENTETE + t.corps.len();
            assert_eq!(l, acpi::longueur(&o).unwrap());
            assert_eq!(o[..l].iter().fold(0u8, |s, &b| s.wrapping_add(b)), 0);
            let _ = acpi::adresses(&t, false).count();
            let _ = acpi::adresses(&t, true).count();
            let _ = acpi::registre_du_siecle(&t);
            if let Ok(m) = Madt::lire(&t) {
                // La lecture des entrées finit toujours, et après une erreur
                // il n'y a plus rien.
                let entrees: Vec<_> = m.entrees().collect();
                assert!(entrees.len() <= t.corps.len() / 2 + 1);
                if let Some(p) = entrees.iter().position(Result::is_err) {
                    assert_eq!(p, entrees.len() - 1);
                }
            }
        }
    }
    assert!(acceptees > 10_000, "trop peu de mutations acceptées ({acceptees}) : le test ne mord plus");
}
