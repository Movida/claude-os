//! Le lecteur ELF contre de vrais exécutables, construits par le Makefile
//! (`make tests-hote`) dans linux/construits/ :
//!   - bonjour-c : `gcc -static`, avec la glibc d'Ubuntu ;
//!   - bonjour-asm : nasm et ld, sans bibliothèque ;
//!   - bonjour-c-pie : `gcc -static-pie`, un ET_DYN ;
//!   - bonjour-c-dynamique : `gcc` sans option, lié à ld-linux et à la glibc
//!     partagée (un ET_DYN avec PT_INTERP) ;
//!   - bonjour-asm-wx : ld -N, un segment inscriptible et exécutable ;
//!   - bonjour-c-deux-segments : gcc -static -z noseparate-code, la
//!     disposition d'avant binutils 2.31 : code et en-têtes dans un seul
//!     segment, données dans un second qui commence au milieu d'une page.
//! Puis contre des variantes du vrai bonjour-c, abîmées exprès.

use formats::elf::{self, Erreur, Plage};
use std::path::PathBuf;

const PERMISES: Plage = Plage { debut: 0x1_0000, fin: 0x7fff_ffff_f000 };

fn lire_programme(nom: &str) -> Vec<u8> {
    let dossier = match std::env::var_os("PROGRAMMES_LINUX") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../linux/construits"),
    };
    let chemin = dossier.join(nom);
    std::fs::read(&chemin).unwrap_or_else(|e| panic!("{} : {e} (lancer `make tests-hote` dans 05-elf)", chemin.display()))
}

/// Position du i-ième en-tête de programme d'un ELF valide.
fn entete(o: &[u8], i: usize) -> usize {
    u64::from_le_bytes(o[32..40].try_into().unwrap()) as usize + 56 * i
}

fn champ32(o: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(o[i..i + 4].try_into().unwrap())
}

#[test]
fn gcc_statique() {
    let o = lire_programme("bonjour-c");
    let x = elf::lire(&o, PERMISES).expect("gcc -static refuse");
    let segments: Vec<_> = x.segments().collect();
    // R (en-têtes), R+X (code), R (constantes), RW (données) : la
    // disposition de ld depuis -z separate-code.
    assert_eq!(segments.len(), 4);
    assert!(segments.windows(2).all(|p| p[0].pages().1 <= p[1].pages().0));
    assert!(segments.iter().any(|s| s.execution && (s.adresse..s.adresse + s.taille).contains(&x.entree())));
    assert!(segments.iter().all(|s| !(s.ecriture && s.execution)));
    // Les en-têtes de programme sont chargés par le premier segment.
    assert_eq!(x.adresse_entetes(), Some(segments[0].adresse + 64));
    assert_eq!(x.nombre_entetes(), u16::from_le_bytes([o[56], o[57]]) as usize);
    // Le .bss : plus grand en mémoire que dans le fichier.
    assert!(segments[3].taille > segments[3].contenu.len() as u64);
    assert_eq!(x.fin(), segments[3].adresse + segments[3].taille);
    // gcc écrit un PT_GNU_STACK sans PF_X : pile non exécutable.
    assert!(!x.pile_executable());
}

#[test]
fn pile_executable_demandee() {
    let o = lire_programme("bonjour-asm-pile-executable");
    let x = elf::lire(&o, PERMISES).expect("ld -z execstack refuse");
    assert!(x.pile_executable());
    // Assemblé par nasm et lié par ld sans option : pas de PT_GNU_STACK.
    assert!(!elf::lire(&lire_programme("bonjour-asm"), PERMISES).unwrap().pile_executable());
}

#[test]
fn gcc_statique_deux_segments() {
    let o = lire_programme("bonjour-c-deux-segments");
    let x = elf::lire(&o, PERMISES).expect("gcc -z noseparate-code refuse");
    let segments: Vec<_> = x.segments().collect();
    assert_eq!(segments.len(), 2);
    assert!(segments[0].execution && !segments[0].ecriture);
    assert!(segments[1].ecriture && !segments[1].execution && segments[1].adresse % 4096 != 0);
    assert_eq!(x.adresse_entetes(), Some(segments[0].adresse + 64));
}

#[test]
fn assembleur_sans_bibliotheque() {
    let o = lire_programme("bonjour-asm");
    let x = elf::lire(&o, PERMISES).expect("bonjour-asm refuse");
    assert_eq!(x.entree(), 0x401000);
    assert!(x.segments().any(|s| s.execution && s.adresse == 0x401000));
}

#[test]
fn refus_de_vrais_executables() {
    assert_eq!(elf::lire(&lire_programme("bonjour-c-pie"), PERMISES).map(|_| ()), Err(Erreur::Dynamique));
    assert_eq!(elf::lire(&lire_programme("bonjour-c-dynamique"), PERMISES).map(|_| ()), Err(Erreur::Dynamique));
    assert!(matches!(
        elf::lire(&lire_programme("bonjour-asm-wx"), PERMISES),
        Err(Erreur::Segment { raison: "inscriptible et executable (W+X)", .. })
    ));
    // Un fichier objet (.o) : ET_REL.
    assert_eq!(elf::lire(&lire_programme("bonjour-asm.o"), PERMISES).map(|_| ()), Err(Erreur::Type(1)));
}

#[test]
fn variantes_abimees() {
    let original = lire_programme("bonjour-c");
    let essayer = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut o = original.clone();
        f(&mut o);
        elf::lire(&o, PERMISES).map(|_| ())
    };
    // Le premier PT_LOAD devient un PT_INTERP.
    assert_eq!(essayer(&|o| { let p = entete(o, 0); o[p..p + 4].copy_from_slice(&3u32.to_le_bytes()) }), Err(Erreur::Interpreteur));
    // Le code devient aussi inscriptible.
    let code = (0..10).find(|&i| champ32(&original, entete(&original, i) + 4) == 5).unwrap();
    assert!(matches!(
        essayer(&|o| { let p = entete(o, code) + 4; o[p..p + 4].copy_from_slice(&7u32.to_le_bytes()) }),
        Err(Erreur::Segment { .. })
    ));
    // Le code perd le droit d'exécution : le point d'entrée n'est plus
    // dans un segment exécutable.
    assert!(matches!(
        essayer(&|o| { let p = entete(o, code) + 4; o[p..p + 4].copy_from_slice(&4u32.to_le_bytes()) }),
        Err(Erreur::Entree(_))
    ));
    // Les données déplacées dans la dernière page de la moitié basse.
    assert!(matches!(
        essayer(&|o| {
            let p = entete(o, 3) + 16;
            let decalage = u64::from_le_bytes(o[p..p + 8].try_into().unwrap()) % 4096;
            o[p..p + 8].copy_from_slice(&(0x7fff_ffff_f000u64 + decalage).to_le_bytes())
        }),
        Err(Erreur::Segment { numero: 3, .. })
    ));
    // Coupé n'importe où avant la fin du dernier segment : refusé.
    let fin_contenu = (0..4)
        .map(|i| {
            let p = entete(&original, i);
            u64::from_le_bytes(original[p + 8..p + 16].try_into().unwrap())
                + u64::from_le_bytes(original[p + 32..p + 40].try_into().unwrap())
        })
        .max()
        .unwrap() as usize;
    for n in (0..fin_contenu).step_by(997).chain(fin_contenu - 8..fin_contenu) {
        assert!(elf::lire(&original[..n], PERMISES).is_err(), "coupe a {n} : accepte");
    }
    // Chaque octet de l'en-tête et des en-têtes de programme mis à 0xFF, un
    // à un : jamais de panique ; et si c'est accepté, les segments restent
    // dans les adresses permises, sans W+X.
    let fin_table = entete(&original, 10);
    for i in 0..fin_table {
        let mut o = original.clone();
        o[i] = 0xFF;
        if let Ok(x) = elf::lire(&o, PERMISES) {
            let mut fin_precedent = 0;
            for s in x.segments() {
                let (debut, fin) = s.pages();
                assert!(debut >= PERMISES.debut && fin <= PERMISES.fin && !(s.ecriture && s.execution));
                // Croissants, sans page commune.
                assert!(debut >= fin_precedent);
                fin_precedent = fin;
            }
        }
    }
}
