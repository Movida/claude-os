//! Le lecteur ELF contre de vrais exécutables, construits par le Makefile
//! (`make tests-hote`) dans linux/construits/ :
//!   - bonjour-c : `gcc -static`, avec la glibc d'Ubuntu ;
//!   - bonjour-asm : nasm et ld, sans bibliothèque ;
//!   - bonjour-c-pie : `gcc -static-pie`, un ET_DYN sans interpréteur ;
//!   - bonjour-c-dynamique : `gcc` sans option, lié à ld-linux et à la glibc
//!     partagée (un ET_DYN avec PT_INTERP) ;
//!   - bonjour-asm-wx : ld -N, un segment inscriptible et exécutable ;
//!   - bonjour-c-deux-segments : gcc -static -z noseparate-code, la
//!     disposition d'avant binutils 2.31 : code et en-têtes dans un seul
//!     segment, données dans un second qui commence au milieu d'une page.
//! Et contre ld-linux et la glibc partagée de la machine, lus là où Ubuntu
//! les installe (/usr/lib/x86_64-linux-gnu), jamais copiés dans le dépôt.
//! Ces fichiers changent d'une révision de la glibc à l'autre (la CI peut
//! en avoir une autre que la machine de développement) : on vérifie des
//! PROPRIÉTÉS (le genre, l'interpréteur, un point d'entrée exécutable...),
//! jamais des valeurs exactes.
//!
//! Puis des variantes abîmées exprès, et des milliers de mutations au
//! hasard (à graine fixe : un échec se rejoue), dont chaque résultat
//! accepté est contrôlé par un second calcul, indépendant du lecteur.

use formats::elf::{self, Erreur, Executable, Genre, Image, Plage};
use std::path::{Path, PathBuf};

const PERMISES: Plage = Plage { debut: 0x1_0000, fin: 0x7fff_ffff_f000 };
/// Où Linux pose un PIE (ELF_ET_DYN_BASE, à la page), sans ASLR.
const BASE_PIE: u64 = 0x5555_5555_4000;
/// Le dossier des bibliothèques d'Ubuntu (/usr fusionné).
const GLIBC: &str = "/usr/lib/x86_64-linux-gnu";
const INTERPRETEUR: &[u8] = b"/lib64/ld-linux-x86-64.so.2";

fn lire_fichier(chemin: &Path) -> Vec<u8> {
    std::fs::read(chemin).unwrap_or_else(|e| panic!("{} : {e} (lancer `make tests-hote`)", chemin.display()))
}

fn lire_programme(nom: &str) -> Vec<u8> {
    let dossier = match std::env::var_os("PROGRAMMES_LINUX") {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../linux/construits"),
    };
    lire_fichier(&dossier.join(nom))
}

fn lire_glibc(nom: &str) -> Vec<u8> {
    lire_fichier(&Path::new(GLIBC).join(nom))
}

/// Un ET_EXEC, posé à ses adresses, comme le fait le noyau.
fn placer_fixe(o: &[u8]) -> Result<Image<'_>, Erreur> {
    let x = elf::lire(o)?;
    x.placer(x.etendue().0, PERMISES)
}

/// Le chemin de l'interpréteur que demande l'exécutable, lu comme le fait
/// le noyau : à l'endroit que dit la table, puis vérifié.
fn interpreteur<'a>(o: &'a [u8], x: &Executable) -> Option<&'a [u8]> {
    let (position, longueur) = x.interpreteur()?;
    let octets = &o[position as usize..position as usize + longueur];
    Some(elf::chemin_interpreteur(octets).expect("chemin de l'interpreteur refuse"))
}

/// Position du i-ième en-tête de programme d'un ELF valide.
fn entete(o: &[u8], i: usize) -> usize {
    u64::from_le_bytes(o[32..40].try_into().unwrap()) as usize + 56 * i
}

fn champ32(o: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(o[i..i + 4].try_into().unwrap())
}

fn champ64(o: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(o[i..i + 8].try_into().unwrap())
}

/// Les propriétés que doit avoir toute image acceptée : chaque segment dans
/// les adresses permises, croissants sans page commune, jamais W+X, et le
/// point d'entrée dans un segment exécutable.
fn verifier_image(i: &Image) {
    let mut fin_precedent = 0;
    for s in i.segments() {
        let (debut, fin) = s.pages();
        assert!(debut >= PERMISES.debut && fin <= PERMISES.fin, "segment hors des adresses permises");
        assert!(debut >= fin_precedent, "segments qui se chevauchent");
        assert!(!(s.ecriture && s.execution), "segment W+X");
        assert!(debut >= i.etendue().0 && fin <= i.etendue().1, "segment hors de l'etendue");
        fin_precedent = fin;
    }
    assert!(i.segments().any(|s| s.execution && (s.adresse..s.adresse + s.taille).contains(&i.entree())));
}

#[test]
fn gcc_statique() {
    let o = lire_programme("bonjour-c");
    let x = placer_fixe(&o).expect("gcc -static refuse");
    assert_eq!(x.executable().genre(), Genre::Fixe);
    assert_eq!(x.executable().interpreteur(), None);
    let segments: Vec<_> = x.segments().collect();
    // R (en-têtes), R+X (code), R (constantes), RW (données) : la
    // disposition de ld depuis -z separate-code.
    assert_eq!(segments.len(), 4);
    verifier_image(&x);
    // Les en-têtes de programme sont chargés par le premier segment.
    assert_eq!(x.adresse_entetes(), Some(segments[0].adresse + 64));
    assert_eq!(x.executable().nombre_entetes(), u16::from_le_bytes([o[56], o[57]]) as usize);
    // Le .bss : plus grand en mémoire que dans le fichier.
    assert!(segments[3].taille > segments[3].taille_fichier);
    assert_eq!(x.fin(), segments[3].adresse + segments[3].taille);
    // gcc écrit un PT_GNU_STACK sans PF_X : pile non exécutable.
    assert!(!x.executable().pile_executable());
    // Un ET_EXEC ne se pose nulle part ailleurs.
    assert_eq!(x.executable().placer(BASE_PIE, PERMISES).map(|_| ()), Err(Erreur::Placement));
}

#[test]
fn pile_executable_demandee() {
    let o = lire_programme("bonjour-asm-pile-executable");
    let x = elf::lire(&o).expect("ld -z execstack refuse");
    assert!(x.pile_executable());
    // Assemblé par nasm et lié par ld sans option : pas de PT_GNU_STACK.
    assert!(!elf::lire(&lire_programme("bonjour-asm")).unwrap().pile_executable());
}

#[test]
fn gcc_statique_deux_segments() {
    let o = lire_programme("bonjour-c-deux-segments");
    let x = placer_fixe(&o).expect("gcc -z noseparate-code refuse");
    let segments: Vec<_> = x.segments().collect();
    assert_eq!(segments.len(), 2);
    assert!(segments[0].execution && !segments[0].ecriture);
    assert!(segments[1].ecriture && !segments[1].execution && segments[1].adresse % 4096 != 0);
    assert_eq!(x.adresse_entetes(), Some(segments[0].adresse + 64));
}

#[test]
fn assembleur_sans_bibliotheque() {
    let o = lire_programme("bonjour-asm");
    let x = placer_fixe(&o).expect("bonjour-asm refuse");
    assert_eq!(x.entree(), 0x401000);
    assert!(x.segments().any(|s| s.execution && s.adresse == 0x401000));
}

/// `gcc -static-pie` : un ET_DYN sans interpréteur, qui se reloge lui-même.
#[test]
fn gcc_static_pie() {
    let o = lire_programme("bonjour-c-pie");
    let x = elf::lire(&o).expect("gcc -static-pie refuse");
    assert_eq!(x.genre(), Genre::Relogeable);
    assert_eq!(x.interpreteur(), None);
    // Ses adresses partent de 0 : l'image se pose n'importe où, à la page.
    assert_eq!(x.etendue().0, 0);
    let i = x.placer(BASE_PIE, PERMISES).expect("placement refuse");
    verifier_image(&i);
    assert_eq!(i.decalage(), BASE_PIE);
    assert_eq!(i.entree(), BASE_PIE + x.entree());
    assert_eq!(i.adresse_entetes(), Some(BASE_PIE + 64));
    // Tout en haut des adresses permises aussi, mais pas une page plus loin.
    let taille = x.etendue().1;
    assert!(x.placer(PERMISES.fin - taille, PERMISES).is_ok());
    assert!(x.placer(PERMISES.fin - taille + 4096, PERMISES).is_err());
}

/// `gcc` sans option : un PIE qui demande ld-linux.
#[test]
fn gcc_dynamique() {
    let o = lire_programme("bonjour-c-dynamique");
    let x = elf::lire(&o).expect("gcc (PIE dynamique) refuse");
    assert_eq!(x.genre(), Genre::Relogeable);
    assert_eq!(interpreteur(&o, &x), Some(INTERPRETEUR));
    verifier_image(&x.placer(BASE_PIE, PERMISES).expect("placement refuse"));
}

/// ld-linux lui-même : un ET_DYN sans interpréteur (il en est un).
#[test]
fn ld_linux() {
    let o = lire_glibc("ld-linux-x86-64.so.2");
    let x = elf::lire(&o).expect("ld-linux refuse");
    assert_eq!(x.genre(), Genre::Relogeable);
    assert_eq!(x.interpreteur(), None);
    assert_eq!(x.etendue().0, 0);
    let i = x.placer(PERMISES.fin - 0x1000_0000 - x.etendue().1, PERMISES).expect("placement refuse");
    verifier_image(&i);
}

/// La glibc partagée : une bibliothèque, qu'on peut aussi exécuter (elle
/// affiche sa version), et qui demande donc ld-linux.
#[test]
fn glibc_partagee() {
    let o = lire_glibc("libc.so.6");
    let x = elf::lire(&o).expect("libc.so.6 refusee");
    assert_eq!(x.genre(), Genre::Relogeable);
    assert_eq!(interpreteur(&o, &x), Some(INTERPRETEUR));
    verifier_image(&x.placer(0x7fff_0000_0000, PERMISES).expect("placement refuse"));
    // Une bibliothèque qui n'est pas faite pour être exécutée : son point
    // d'entrée est 0, hors de tout segment exécutable. Refusée (Linux la
    // chargerait, et le programme sauterait au début de l'image) ; ld-linux,
    // lui, la projette par mmap, sans passer par le chargeur du noyau.
    assert_eq!(elf::lire(&lire_glibc("libm.so.6")).map(|_| ()), Err(Erreur::Entree(0)));
}

#[test]
fn refus_de_vrais_executables() {
    assert!(matches!(
        placer_fixe(&lire_programme("bonjour-asm-wx")),
        Err(Erreur::Segment { raison: "inscriptible et executable (W+X)", .. })
    ));
    // Un fichier objet (.o) : ET_REL.
    assert_eq!(elf::lire(&lire_programme("bonjour-asm.o")).map(|_| ()), Err(Erreur::Type(1)));
}

#[test]
fn variantes_abimees() {
    let original = lire_programme("bonjour-c");
    let essayer = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut o = original.clone();
        f(&mut o);
        placer_fixe(&o).map(|_| ())
    };
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
            let decalage = champ64(o, p) % 4096;
            o[p..p + 8].copy_from_slice(&(0x7fff_ffff_f000u64 + decalage).to_le_bytes())
        }),
        Err(Erreur::Segment { numero: 3, .. })
    ));
    // Un PT_NOTE devient un PT_INTERP qui sort du fichier, ou trop long.
    let note = (0..10).find(|&i| champ32(&original, entete(&original, i)) == 4).unwrap();
    assert_eq!(
        essayer(&|o| {
            let p = entete(o, note);
            o[p..p + 4].copy_from_slice(&3u32.to_le_bytes());
            let presque_la_fin = o.len() as u64 - 8;
            o[p + 8..p + 16].copy_from_slice(&presque_la_fin.to_le_bytes());
            o[p + 32..p + 40].copy_from_slice(&16u64.to_le_bytes());
        }),
        Err(Erreur::InterpreteurHorsDuFichier)
    );
    assert_eq!(
        essayer(&|o| {
            let p = entete(o, note);
            o[p..p + 4].copy_from_slice(&3u32.to_le_bytes());
            o[p + 32..p + 40].copy_from_slice(&5000u64.to_le_bytes());
        }),
        Err(Erreur::InterpreteurTaille(5000))
    );
    // Coupé n'importe où avant la fin du dernier segment : refusé.
    let fin_contenu = (0..4)
        .map(|i| {
            let p = entete(&original, i);
            champ64(&original, p + 8) + champ64(&original, p + 32)
        })
        .max()
        .unwrap() as usize;
    for n in (0..fin_contenu).step_by(997).chain(fin_contenu - 8..fin_contenu) {
        assert!(elf::lire(&original[..n]).is_err(), "coupe a {n} : accepte");
    }
}

/// Un générateur pseudo-aléatoire (xorshift64*), à graine fixe : les
/// mutations sont les mêmes à chaque fois, un échec se rejoue.
struct Hasard(u64);

impl Hasard {
    fn suivant(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn jusqua(&mut self, n: u64) -> u64 {
        self.suivant() % n
    }
}

/// Le contrôle des mutations, INDÉPENDANT du lecteur : relit la table des
/// en-têtes dans les octets bruts, recalcule où chaque PT_LOAD doit aller
/// pour une image posée à `debut`, et vérifie que l'image acceptée dit la
/// même chose, et que tout tient dans les adresses permises. (Passer par
/// `placer` ou par les segments du lecteur pour ce calcul vérifierait le
/// lecteur par lui-même.)
fn controler(o: &[u8], debut: u64, i: &Image) {
    let position = champ64(o, 32) as usize;
    let nombre = u16::from_le_bytes([o[56], o[57]]) as usize;
    let mut attendus = Vec::new();
    for n in 0..nombre {
        let e = position + 56 * n;
        let (genre, drapeaux) = (champ32(o, e), champ32(o, e + 4));
        let (adresse, taille) = (champ64(o, e + 16), champ64(o, e + 40));
        if genre != 1 || taille == 0 {
            continue;
        }
        // En u128 : aucun débordement possible dans ce calcul de contrôle.
        attendus.push((adresse as u128, taille as u128, drapeaux));
    }
    let premiere = attendus.iter().map(|a| a.0 / 4096 * 4096).min().expect("accepte sans segment");
    let segments: Vec<_> = i.segments().collect();
    assert_eq!(segments.len(), attendus.len(), "nombre de segments");
    for (s, &(adresse, taille, drapeaux)) in segments.iter().zip(&attendus) {
        let absolue = adresse - premiere + debut as u128;
        let fin = (absolue + taille).div_ceil(4096) * 4096;
        assert!(absolue / 4096 * 4096 >= PERMISES.debut as u128 && fin <= PERMISES.fin as u128,
                "segment accepte hors des adresses permises");
        assert_eq!(s.adresse as u128, absolue, "adresse du segment");
        assert_eq!(s.taille as u128, taille, "taille du segment");
        assert!(drapeaux & 3 != 3, "segment W+X accepte");
    }
}

/// Des milliers de vrais ET_DYN (et un ET_EXEC) abîmés au hasard dans leur
/// en-tête et leur table : jamais de panique ; ce qui est accepté, puis
/// posé à quelques bases (dont des bases absurdes), passe le contrôle
/// indépendant.
#[test]
fn mutations_au_hasard() {
    let fichiers = [
        lire_programme("bonjour-c-pie"),
        lire_programme("bonjour-c-dynamique"),
        lire_programme("bonjour-c"),
        lire_glibc("ld-linux-x86-64.so.2"),
        lire_glibc("libc.so.6"),
    ];
    let mut hasard = Hasard(0x6c_6463_2d36_63);
    let (mut acceptes, mut places) = (0u64, 0u64);
    for original in &fichiers {
        let fin_table = entete(original, u16::from_le_bytes([original[56], original[57]]) as usize);
        for _ in 0..4000 {
            let mut o = original.clone();
            // Un à huit octets changés, dans l'en-tête ou la table ; parfois
            // un champ de 64 bits entier (adresse, taille, position).
            for _ in 0..=hasard.jusqua(8) {
                let p = hasard.jusqua(fin_table as u64) as usize;
                if hasard.jusqua(4) == 0 && p + 8 <= fin_table {
                    let v = match hasard.jusqua(4) {
                        0 => u64::MAX - hasard.jusqua(0x10000),
                        1 => hasard.suivant(),
                        2 => 0x7fff_ffff_f000 - hasard.jusqua(0x10_0000),
                        _ => hasard.jusqua(0x1_0000_0000),
                    };
                    o[p..p + 8].copy_from_slice(&v.to_le_bytes());
                } else {
                    o[p] = hasard.suivant() as u8;
                }
            }
            let Ok(x) = elf::lire(&o) else { continue };
            acceptes += 1;
            let bases = [x.etendue().0, BASE_PIE, 0, 0x1_0000, PERMISES.fin - 0x1000, u64::MAX / 4096 * 4096,
                         hasard.suivant() / 4096 * 4096];
            for debut in bases {
                if let Ok(i) = x.placer(debut, PERMISES) {
                    places += 1;
                    controler(&o, debut, &i);
                    let _ = (i.entree(), i.adresse_entetes(), i.fin(), i.decalage());
                }
            }
            if let Some((position, longueur)) = x.interpreteur() {
                // Toujours dans le fichier, de 2 à 4096 octets.
                assert!((2..=4096).contains(&longueur));
                assert!(position as usize + longueur <= o.len());
            }
        }
    }
    // Le test ne mord que si des mutations passent : il faut des cas
    // acceptés et placés en nombre.
    assert!(acceptes > 2000 && places > 2000, "trop peu de cas acceptes : {acceptes}, places : {places}");
}
