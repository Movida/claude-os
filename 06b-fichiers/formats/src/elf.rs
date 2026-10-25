//! Les exécutables ELF : le format des programmes de Linux.
//!
//! Un fichier ELF commence par un en-tête de 64 octets (la marque
//! « \x7fELF », la classe 32 ou 64 bits, le boutisme, la machine, le point
//! d'entrée...), qui donne la position d'une table d'EN-TÊTES DE PROGRAMME
//! (program headers) : la vue « chargement » du fichier. Chaque en-tête de
//! type PT_LOAD dit : « les `p_filesz` octets du fichier à la position
//! `p_offset` vont à l'adresse `p_vaddr`, sur `p_memsz` octets (le reste à
//! zéro : c'est le .bss), avec ces droits (lecture, écriture, exécution) ».
//! C'est tout ce qu'il faut pour charger un programme ; les SECTIONS
//! (.text, .data, les symboles) ne servent qu'à l'éditeur de liens et au
//! débogueur, on ne les lit pas. Référence : la spécification System V
//! (gABI) et son supplément x86_64 (psABI) ; et fs/binfmt_elf.c de Linux.
//!
//! On ne prend que ce que la sous-étape sait exécuter, et on le dit :
//!   - ELF 64 bits, petit-boutiste, pour x86_64 ;
//!   - ET_EXEC seulement : un exécutable lié à des adresses fixes, comme
//!     `gcc -static`. Les ET_DYN (exécutables « PIE », placés n'importe
//!     où, et bibliothèques partagées) viendront à l'étape 6, avec ld-linux
//!     et la glibc partagée qu'exige `claude` ;
//!   - pas de PT_INTERP : un programme qui demande un interpréteur (ld-linux)
//!     est dynamique, même lié à une adresse fixe.
//!
//! Chaque champ est vérifié avant de servir, chaque addition aussi : un
//! fichier piégé ne doit ni faire lire le noyau hors du fichier, ni lui
//! faire projeter une page hors des adresses permises (la moitié haute est
//! au noyau !), ni écraser une page par une autre.

use core::fmt;

/// Taille de l'en-tête ELF 64 bits, et d'un en-tête de programme.
const TAILLE_ENTETE: usize = 64;
const TAILLE_ENTETE_PROGRAMME: usize = 56;
/// Le plus de place que peuvent prendre les en-têtes de programme : 64 Kio,
/// la limite de Linux (load_elf_phdrs), soit 1170 en-têtes. Un vrai
/// programme en a une dizaine.
const ENTETES_MAX: usize = 65536;

const PAGE: u64 = 4096;

// Valeurs des champs (gABI, psABI x86_64).
const CLASSE_64: u8 = 2;
const PETIT_BOUTISTE: u8 = 1;
const VERSION_COURANTE: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
/// La pile du programme doit-elle être exécutable ? (Une extension GNU,
/// que gcc et ld écrivent toujours ; PF_X la demande exécutable.)
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

/// Les adresses qu'un programme a le droit d'occuper : [debut, fin[,
/// alignées sur une page. Le noyau donne les siennes (voir
/// noyau/src/espace_utilisateur.rs) : la bibliothèque n'en sait rien.
#[derive(Debug, Clone, Copy)]
pub struct Plage {
    pub debut: u64,
    pub fin: u64,
}

/// Pourquoi un exécutable est refusé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Le fichier est trop court pour l'en-tête ou les en-têtes de programme.
    Tronque,
    /// Pas de marque « \x7fELF ».
    PasElf,
    /// Un ELF, mais pas pour nous : 32 bits, gros-boutiste, autre version,
    /// autre processeur.
    Classe,
    Boutisme,
    Version,
    Machine(u16),
    /// ET_DYN : un exécutable PIE ou une bibliothèque partagée.
    Dynamique,
    /// Ni ET_EXEC ni ET_DYN (un fichier objet .o, un fichier « core »...).
    Type(u16),
    /// Un en-tête PT_INTERP : le programme demande ld-linux.
    Interpreteur,
    /// e_phentsize n'est pas 56, ou trop d'en-têtes (plus de 64 Kio), ou
    /// aucun.
    EntetesProgramme,
    /// Un PT_LOAD fautif (son numéro dans la table, et pourquoi).
    Segment { numero: usize, raison: &'static str },
    /// Aucun segment à charger.
    AucunSegment,
    /// Le point d'entrée n'est dans aucun segment exécutable.
    Entree(u64),
}

// Ces messages sont affichés par le noyau : sans accents (page de code 437).
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::Tronque => write!(f, "fichier ELF tronque"),
            Erreur::PasElf => write!(f, "pas un fichier ELF"),
            Erreur::Classe => write!(f, "ELF 32 bits non pris en charge"),
            Erreur::Boutisme => write!(f, "ELF gros-boutiste non pris en charge"),
            Erreur::Version => write!(f, "version d'ELF inconnue"),
            Erreur::Machine(m) => write!(f, "ELF pour une autre machine ({m}), pas x86_64"),
            Erreur::Dynamique => write!(f, "ELF ET_DYN (PIE ou bibliotheque) : pas encore pris en charge"),
            Erreur::Type(t) => write!(f, "ELF de type {t} : pas un executable"),
            Erreur::Interpreteur => write!(f, "programme dynamique (PT_INTERP) : pas encore pris en charge"),
            Erreur::EntetesProgramme => write!(f, "table des en-tetes de programme invalide"),
            Erreur::Segment { numero, raison } => write!(f, "segment {numero} : {raison}"),
            Erreur::AucunSegment => write!(f, "aucun segment a charger"),
            Erreur::Entree(e) => write!(f, "point d'entree {e:#x} hors de tout segment executable"),
        }
    }
}

/// Un segment à charger (PT_LOAD), vérifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Son adresse (pas forcément alignée sur une page).
    pub adresse: u64,
    /// Sa taille en mémoire (au moins celle de son contenu ; le reste est
    /// à zéro).
    pub taille: u64,
    /// La part du fichier à copier à `adresse`.
    pub contenu: &'a [u8],
    pub ecriture: bool,
    pub execution: bool,
}

impl Segment<'_> {
    /// La première page du segment, et la fin de sa dernière page (exclue).
    pub fn pages(&self) -> (u64, u64) {
        // Pas de débordement : vérifié par `lire` (la fin est sous la
        // limite des adresses permises).
        (self.adresse / PAGE * PAGE, (self.adresse + self.taille).next_multiple_of(PAGE))
    }
}

/// Un exécutable vérifié.
#[derive(Debug, Clone, Copy)]
pub struct Executable<'a> {
    octets: &'a [u8],
    entree: u64,
    position_entetes: usize,
    nombre_entetes: usize,
    adresse_entetes: Option<u64>,
}

fn u16_a(o: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(o.get(i..i.checked_add(2)?)?.try_into().ok()?))
}
fn u32_a(o: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(o.get(i..i.checked_add(4)?)?.try_into().ok()?))
}
fn u64_a(o: &[u8], i: usize) -> Option<u64> {
    Some(u64::from_le_bytes(o.get(i..i.checked_add(8)?)?.try_into().ok()?))
}

/// Les champs d'un en-tête de programme (Elf64_Phdr), sauf p_paddr (une
/// adresse physique, sans objet ici) et p_align (voir `lire`).
struct EnteteProgramme {
    genre: u32,
    drapeaux: u32,
    position: u64,
    adresse: u64,
    taille_fichier: u64,
    taille_memoire: u64,
}

impl Executable<'_> {
    /// Le i-ième en-tête de programme. Sa place dans le fichier a été
    /// vérifiée par `lire`.
    fn entete(&self, i: usize) -> EnteteProgramme {
        let o = &self.octets[self.position_entetes + i * TAILLE_ENTETE_PROGRAMME..][..TAILLE_ENTETE_PROGRAMME];
        let champ32 = |j| u32_a(o, j).unwrap_or(0);
        let champ64 = |j| u64_a(o, j).unwrap_or(0);
        EnteteProgramme {
            genre: champ32(0),
            drapeaux: champ32(4),
            position: champ64(8),
            adresse: champ64(16),
            taille_fichier: champ64(32),
            taille_memoire: champ64(40),
        }
    }
}

impl<'a> Executable<'a> {
    /// Le point d'entrée (e_entry) : là où le programme commence.
    pub fn entree(&self) -> u64 {
        self.entree
    }

    /// L'adresse en mémoire des en-têtes de programme, si un segment les
    /// charge : la valeur d'AT_PHDR, que la glibc statique lit pour trouver
    /// son segment PT_TLS.
    pub fn adresse_entetes(&self) -> Option<u64> {
        self.adresse_entetes
    }

    /// Le nombre d'en-têtes de programme (AT_PHNUM).
    pub fn nombre_entetes(&self) -> usize {
        self.nombre_entetes
    }

    /// La taille d'un en-tête de programme (AT_PHENT).
    pub fn taille_entete(&self) -> usize {
        TAILLE_ENTETE_PROGRAMME
    }

    /// Les segments à charger, dans l'ordre croissant des adresses, sans
    /// page commune. (Les PT_LOAD de taille nulle, qui n'occupent rien,
    /// sont omis.)
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + '_ {
        (0..self.nombre_entetes).filter_map(move |i| {
            let e = self.entete(i);
            if e.genre != PT_LOAD || e.taille_memoire == 0 {
                return None;
            }
            // Bornes vérifiées par `lire` (sauf pour un segment sans octets
            // du fichier, dont la position ne compte pas).
            let octets: &'a [u8] = self.octets;
            let contenu = match e.taille_fichier {
                0 => &[][..],
                n => &octets[e.position as usize..(e.position + n) as usize],
            };
            Some(Segment {
                adresse: e.adresse,
                taille: e.taille_memoire,
                contenu,
                ecriture: e.drapeaux & PF_W != 0,
                execution: e.drapeaux & PF_X != 0,
            })
        })
    }

    /// La pile doit-elle être exécutable ? Oui si un en-tête PT_GNU_STACK
    /// porte PF_X (`ld -z execstack`, ou un objet assemblé sans la note
    /// .note.GNU-stack, quand l'éditeur de liens en déduit une pile
    /// exécutable) ; non sans PT_GNU_STACK, comme Linux pour un programme
    /// 64 bits (EXSTACK_DEFAULT : sur x86_64, pas de « lecture implique
    /// exécution »). Le dernier en-tête l'emporte, comme dans Linux
    /// (load_elf_binary).
    pub fn pile_executable(&self) -> bool {
        (0..self.nombre_entetes)
            .map(|i| self.entete(i))
            .filter(|e| e.genre == PT_GNU_STACK)
            .last()
            .is_some_and(|e| e.drapeaux & PF_X != 0)
    }

    /// La fin du dernier segment (son adresse plus sa taille en mémoire) :
    /// là où commence le tas du programme (brk).
    pub fn fin(&self) -> u64 {
        self.segments().map(|s| s.adresse + s.taille).max().unwrap_or(0)
    }
}

/// Vérifie l'exécutable `octets`, destiné aux adresses `permises`.
pub fn lire(octets: &[u8], permises: Plage) -> Result<Executable<'_>, Erreur> {
    let entete = octets.get(..TAILLE_ENTETE).ok_or(Erreur::Tronque)?;
    if entete[..4] != *b"\x7fELF" {
        return Err(Erreur::PasElf);
    }
    // e_ident : classe, boutisme, version ; l'OS/ABI (octet 7) est ignoré,
    // comme le fait Linux (gcc écrit 3, « GNU », quand il y a des
    // fonctions GNU_IFUNC, ce qui est le cas de la glibc statique).
    if entete[4] != CLASSE_64 {
        return Err(Erreur::Classe);
    }
    if entete[5] != PETIT_BOUTISTE {
        return Err(Erreur::Boutisme);
    }
    if entete[6] != VERSION_COURANTE || u32_a(entete, 20) != Some(1) {
        return Err(Erreur::Version);
    }
    let champ16 = |i| u16_a(entete, i).unwrap_or(0);
    let machine = champ16(18);
    if machine != EM_X86_64 {
        return Err(Erreur::Machine(machine));
    }
    match champ16(16) {
        ET_EXEC => {}
        ET_DYN => return Err(Erreur::Dynamique),
        t => return Err(Erreur::Type(t)),
    }
    let entree = u64_a(entete, 24).unwrap_or(0);
    let position_entetes = u64_a(entete, 32).unwrap_or(0);
    let taille_entete = champ16(54) as usize;
    let nombre_entetes = champ16(56) as usize;
    if taille_entete != TAILLE_ENTETE_PROGRAMME
        || nombre_entetes == 0
        || nombre_entetes * TAILLE_ENTETE_PROGRAMME > ENTETES_MAX
    {
        return Err(Erreur::EntetesProgramme);
    }
    // La table entière doit être dans le fichier.
    let taille_table = nombre_entetes * TAILLE_ENTETE_PROGRAMME;
    let position_entetes = usize::try_from(position_entetes).map_err(|_| Erreur::Tronque)?;
    let fin_table = position_entetes.checked_add(taille_table).ok_or(Erreur::Tronque)?;
    if fin_table > octets.len() {
        return Err(Erreur::Tronque);
    }
    let mut executable =
        Executable { octets, entree, position_entetes, nombre_entetes, adresse_entetes: None };

    // Les segments, un par un.
    let mut fin_precedent = 0u64; // Fin (arrondie à la page) du PT_LOAD précédent.
    let mut entree_trouvee = false;
    let mut segments = 0;
    for numero in 0..nombre_entetes {
        let e = executable.entete(numero);
        if e.genre == PT_INTERP {
            return Err(Erreur::Interpreteur);
        }
        if e.genre != PT_LOAD {
            continue;
        }
        let refus = |raison| Err(Erreur::Segment { numero, raison });
        if e.taille_fichier > e.taille_memoire {
            return refus("plus grand dans le fichier qu'en memoire");
        }
        // Un segment sans octets du fichier (que du .bss) : sa position
        // dans le fichier ne sert à rien, et Linux ne la regarde pas. Les
        // deux vérifications qui suivent ne valent que pour les autres.
        let fin_fichier = match e.position.checked_add(e.taille_fichier) {
            _ if e.taille_fichier == 0 => 0,
            Some(f) if f <= octets.len() as u64 => f,
            _ => return refus("hors du fichier"),
        };
        if e.taille_memoire == 0 {
            continue;
        }
        // La page d'adresse p_vaddr doit recevoir la page du fichier qui
        // contient p_offset : même position dans la page. (p_align n'est
        // pas lu : Linux ne s'en sert que pour les ET_DYN. Ce qui compte
        // pour nous est la congruence modulo la page.)
        if e.taille_fichier > 0 && e.adresse % PAGE != e.position % PAGE {
            return refus("adresse et position dans le fichier non congruentes modulo 4096");
        }
        // Dans les adresses permises : du début de sa première page à la
        // fin de sa dernière, sans débordement.
        let premiere_page = e.adresse / PAGE * PAGE;
        let fin = match e.adresse.checked_add(e.taille_memoire).and_then(|f| f.checked_next_multiple_of(PAGE)) {
            Some(f) if premiere_page >= permises.debut && f <= permises.fin => f,
            _ => return refus("hors des adresses permises"),
        };
        // Croissants et sans page commune : chaque page appartient à un
        // seul segment, avec ses droits. (Le psABI exige l'ordre croissant ;
        // ld ne fait jamais partager une page à deux segments aux droits
        // différents depuis -z separate-code, 2018.)
        if premiere_page < fin_precedent {
            return refus("chevauche le segment precedent, ou le precede");
        }
        // W^X : jamais à la fois inscriptible et exécutable. ld n'en
        // produit plus sans qu'on le demande (il avertit depuis binutils
        // 2.39) ; un tel segment ne sert qu'à du code qui se modifie, ou à
        // une attaque.
        if e.drapeaux & PF_W != 0 && e.drapeaux & PF_X != 0 {
            return refus("inscriptible et executable (W+X)");
        }
        if e.drapeaux & PF_X != 0 && (e.adresse..e.adresse + e.taille_memoire).contains(&entree) {
            entree_trouvee = true;
        }
        // Les en-têtes de programme sont-ils chargés par ce segment ?
        if e.position <= position_entetes as u64 && fin_table as u64 <= fin_fichier {
            executable.adresse_entetes = Some(e.adresse + (position_entetes as u64 - e.position));
        }
        fin_precedent = fin;
        segments += 1;
    }
    if segments == 0 {
        return Err(Erreur::AucunSegment);
    }
    if !entree_trouvee {
        return Err(Erreur::Entree(entree));
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const PERMISES: Plage = Plage { debut: 0x1_0000, fin: 0x7fff_ffff_f000 };

    /// Un petit exécutable : un segment de code R+X à 0x401000 (16 octets
    /// du fichier à la position 0x1000), un segment de données RW à
    /// 0x402000 (8 octets du fichier, 0x100 en mémoire). Les en-têtes sont
    /// à la position 64, hors de tout segment.
    fn exemple() -> Vec<u8> {
        let mut o = std::vec![0u8; 0x2008];
        o[..4].copy_from_slice(b"\x7fELF");
        o[4] = CLASSE_64;
        o[5] = PETIT_BOUTISTE;
        o[6] = VERSION_COURANTE;
        o[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        o[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        o[20..24].copy_from_slice(&1u32.to_le_bytes());
        o[24..32].copy_from_slice(&0x401004u64.to_le_bytes());
        o[32..40].copy_from_slice(&64u64.to_le_bytes());
        o[54..56].copy_from_slice(&56u16.to_le_bytes());
        o[56..58].copy_from_slice(&2u16.to_le_bytes());
        entete(&mut o, 0, PT_LOAD, 5, 0x1000, 0x401000, 16, 16);
        entete(&mut o, 1, PT_LOAD, 6, 0x2000, 0x402000, 8, 0x100);
        o
    }

    #[allow(clippy::too_many_arguments)]
    fn entete(o: &mut [u8], i: usize, genre: u32, drapeaux: u32, position: u64, adresse: u64, fichier: u64, memoire: u64) {
        let e = &mut o[64 + 56 * i..64 + 56 * (i + 1)];
        e[0..4].copy_from_slice(&genre.to_le_bytes());
        e[4..8].copy_from_slice(&drapeaux.to_le_bytes());
        e[8..16].copy_from_slice(&position.to_le_bytes());
        e[16..24].copy_from_slice(&adresse.to_le_bytes());
        e[32..40].copy_from_slice(&fichier.to_le_bytes());
        e[40..48].copy_from_slice(&memoire.to_le_bytes());
        e[48..56].copy_from_slice(&PAGE.to_le_bytes());
    }

    #[test]
    fn exemple_valide() {
        let o = exemple();
        let x = lire(&o, PERMISES).unwrap();
        assert_eq!(x.entree(), 0x401004);
        let s: Vec<_> = x.segments().collect();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].adresse, s[0].taille, s[0].contenu.len(), s[0].ecriture, s[0].execution), (0x401000, 16, 16, false, true));
        assert_eq!((s[1].adresse, s[1].taille, s[1].contenu.len(), s[1].ecriture, s[1].execution), (0x402000, 0x100, 8, true, false));
        assert_eq!(s[1].pages(), (0x402000, 0x403000));
        assert_eq!(x.fin(), 0x402100);
        // Les en-têtes (position 64) ne sont dans aucun segment.
        assert_eq!(x.adresse_entetes(), None);
        // Sans PT_GNU_STACK : pile non exécutable.
        assert!(!x.pile_executable());
    }

    #[test]
    fn pile_executable() {
        let mut o = exemple();
        o[56..58].copy_from_slice(&3u16.to_le_bytes());
        entete(&mut o, 2, PT_GNU_STACK, 6, 0, 0, 0, 0);
        assert!(!lire(&o, PERMISES).unwrap().pile_executable());
        entete(&mut o, 2, PT_GNU_STACK, 7, 0, 0, 0, 0);
        assert!(lire(&o, PERMISES).unwrap().pile_executable());
        // Deux en-têtes : le dernier l'emporte.
        o[56..58].copy_from_slice(&4u16.to_le_bytes());
        entete(&mut o, 3, PT_GNU_STACK, 6, 0, 0, 0, 0);
        assert!(!lire(&o, PERMISES).unwrap().pile_executable());
    }

    #[test]
    fn identite_refusee() {
        let modifier = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut o = exemple();
            f(&mut o);
            lire(&o, PERMISES).map(|_| ())
        };
        assert_eq!(modifier(&|o| o[0] = 0), Err(Erreur::PasElf));
        assert_eq!(modifier(&|o| o[4] = 1), Err(Erreur::Classe));
        assert_eq!(modifier(&|o| o[5] = 2), Err(Erreur::Boutisme));
        assert_eq!(modifier(&|o| o[6] = 2), Err(Erreur::Version));
        assert_eq!(modifier(&|o| o[20] = 2), Err(Erreur::Version));
        assert_eq!(modifier(&|o| o[18] = 3), Err(Erreur::Machine(3)));
        assert_eq!(modifier(&|o| o[16] = 3), Err(Erreur::Dynamique));
        assert_eq!(modifier(&|o| o[16] = 1), Err(Erreur::Type(1)));
        assert_eq!(modifier(&|o| o[16] = 4), Err(Erreur::Type(4)));
        // L'OS/ABI est ignoré.
        assert_eq!(modifier(&|o| o[7] = 3), Ok(()));
    }

    #[test]
    fn table_des_entetes() {
        let modifier = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut o = exemple();
            f(&mut o);
            lire(&o, PERMISES).map(|_| ())
        };
        assert_eq!(modifier(&|o| o[54] = 32), Err(Erreur::EntetesProgramme));
        assert_eq!(modifier(&|o| o[56..58].copy_from_slice(&0u16.to_le_bytes())), Err(Erreur::EntetesProgramme));
        assert_eq!(modifier(&|o| o[56..58].copy_from_slice(&0xFFFFu16.to_le_bytes())), Err(Erreur::EntetesProgramme));
        // Position des en-têtes au-delà du fichier, ou qui déborde.
        assert_eq!(modifier(&|o| o[32..40].copy_from_slice(&0x2000u64.to_le_bytes())), Err(Erreur::Tronque));
        assert_eq!(modifier(&|o| o[32..40].copy_from_slice(&u64::MAX.to_le_bytes())), Err(Erreur::Tronque));
        assert_eq!(modifier(&|o| o[32..40].copy_from_slice(&(u64::MAX - 50).to_le_bytes())), Err(Erreur::Tronque));
    }

    #[test]
    fn tronque_partout() {
        let o = exemple();
        for n in 0..o.len() {
            assert!(lire(&o[..n], PERMISES).is_err(), "coupe a {n} : accepte");
        }
    }

    #[test]
    fn segments_refuses() {
        let refus = |i: usize, genre, drapeaux, position, adresse, fichier, memoire| {
            let mut o = exemple();
            entete(&mut o, i, genre, drapeaux, position, adresse, fichier, memoire);
            match lire(&o, PERMISES) {
                Err(Erreur::Segment { numero, raison }) if numero == i => Some(raison),
                Err(e) => panic!("autre erreur : {e}"),
                Ok(_) => None,
            }
        };
        const PLUS_GRAND: &str = "plus grand dans le fichier qu'en memoire";
        const HORS_FICHIER: &str = "hors du fichier";
        const CONGRUENCE: &str = "adresse et position dans le fichier non congruentes modulo 4096";
        const HORS_PERMISES: &str = "hors des adresses permises";
        const ORDRE: &str = "chevauche le segment precedent, ou le precede";
        const WX: &str = "inscriptible et executable (W+X)";
        // Plus grand dans le fichier qu'en mémoire.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402000, 8, 4), Some(PLUS_GRAND));
        // Hors du fichier, ou position qui déborde.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402000, 9, 0x100), Some(HORS_FICHIER));
        assert_eq!(refus(1, PT_LOAD, 6, u64::MAX - 4, 0x402000, 8, 0x100), Some(HORS_FICHIER));
        // Non congruents.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402010, 8, 0x100), Some(CONGRUENCE));
        // Hors des adresses permises : sous 64 Kio, la dernière page de la
        // moitié basse, la moitié haute, un débordement de l'adresse.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0xF000, 8, 0x100), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x7fff_ffff_f000, 8, 0x100), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x7fff_ffff_e000, 8, 0x1001), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0xffff_8000_0000_0000, 8, 0x100), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0xffff_ffff_ffff_f000, 8, 0x1001), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402000, 8, u64::MAX), Some(HORS_PERMISES));
        // Dans la page du précédent (au début ou à sa fin), ou avant lui.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x401000, 8, 0x100), Some(ORDRE));
        assert_eq!(refus(1, PT_LOAD, 6, 0x1010, 0x401010, 8, 0x100), Some(ORDRE));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x400000, 8, 0x100), Some(ORDRE));
        // W+X.
        assert_eq!(refus(1, PT_LOAD, 7, 0x2000, 0x402000, 8, 0x100), Some(WX));
        // Les segments valides ne sont pas refusés pour autant : collé au
        // bout des adresses permises, ou tout au début (64 Kio).
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x7fff_ffff_e000, 8, 0x1000), None);
        let mut o = exemple();
        entete(&mut o, 0, PT_LOAD, 5, 0x1000, 0x10000, 16, 16);
        o[24..32].copy_from_slice(&0x10004u64.to_le_bytes());
        assert!(lire(&o, PERMISES).is_ok());
        // Toutes les raisons sont en ASCII (affichées par le noyau).
        for r in [PLUS_GRAND, HORS_FICHIER, CONGRUENCE, HORS_PERMISES, ORDRE, WX] {
            assert!(r.is_ascii());
        }
    }

    #[test]
    fn segment_sans_octets_du_fichier() {
        // Que du .bss : sa position dans le fichier ne compte pas, même hors
        // du fichier ou non congrue (Linux ne la regarde pas).
        for position in [0x3000, 0x2001, u64::MAX] {
            let mut o = exemple();
            entete(&mut o, 1, PT_LOAD, 6, position, 0x402000, 0, 0x100);
            let x = lire(&o, PERMISES).unwrap();
            let s: Vec<_> = x.segments().collect();
            assert_eq!((s[1].adresse, s[1].taille, s[1].contenu.len()), (0x402000, 0x100, 0));
        }
        // Un PT_LOAD de taille nulle en mémoire n'occupe rien : omis, où
        // qu'il prétende être.
        let mut o = exemple();
        entete(&mut o, 1, PT_LOAD, 7, 0x2000, 0xffff_8000_0000_0000, 0, 0);
        assert_eq!(lire(&o, PERMISES).unwrap().segments().count(), 1);
    }

    #[test]
    fn entree_et_interpreteur() {
        let mut o = exemple();
        o[24..32].copy_from_slice(&0x402000u64.to_le_bytes()); // Dans les données.
        assert_eq!(lire(&o, PERMISES).map(|_| ()), Err(Erreur::Entree(0x402000)));
        let mut o = exemple();
        entete(&mut o, 1, PT_INTERP, 4, 0x2000, 0, 8, 8);
        assert_eq!(lire(&o, PERMISES).map(|_| ()), Err(Erreur::Interpreteur));
        let mut o = exemple();
        entete(&mut o, 0, 6 /* PT_PHDR */, 4, 0, 0, 0, 0);
        entete(&mut o, 1, 6, 4, 0, 0, 0, 0);
        assert_eq!(lire(&o, PERMISES).map(|_| ()), Err(Erreur::AucunSegment));
    }

    #[test]
    fn point_d_entree_aux_bornes() {
        // Le dernier octet du segment de code : accepté ; juste après (la
        // borne exclue) : refusé.
        let mut o = exemple();
        o[24..32].copy_from_slice(&0x40100Fu64.to_le_bytes());
        assert!(lire(&o, PERMISES).is_ok());
        o[24..32].copy_from_slice(&0x401010u64.to_le_bytes());
        assert_eq!(lire(&o, PERMISES).map(|_| ()), Err(Erreur::Entree(0x401010)));
    }

    #[test]
    fn adresse_des_entetes() {
        // Un premier segment qui charge le début du fichier : les en-têtes
        // (position 64) sont à son adresse + 64.
        let mut o = exemple();
        entete(&mut o, 0, PT_LOAD, 5, 0, 0x400000, 0x1010, 0x1010);
        o[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
        let x = lire(&o, PERMISES).unwrap();
        assert_eq!(x.adresse_entetes(), Some(0x400040));
        assert_eq!((x.nombre_entetes(), x.taille_entete()), (2, 56));
        // Le premier segment ne charge que 100 octets du fichier : la table
        // (64 + 2 x 56 = 176) déborde, elle n'est pas en mémoire.
        entete(&mut o, 0, PT_LOAD, 5, 0, 0x400000, 100, 0x1010);
        assert_eq!(lire(&o, PERMISES).unwrap().adresse_entetes(), None);
        // Chargée par le deuxième segment (des données qui commencent au
        // début du fichier, sur une autre page) : son adresse à lui.
        let mut o = exemple();
        entete(&mut o, 1, PT_LOAD, 6, 0, 0x402000, 0x200, 0x200);
        assert_eq!(lire(&o, PERMISES).unwrap().adresse_entetes(), Some(0x402040));
    }

    #[test]
    fn messages_sans_accents() {
        let erreurs = [
            Erreur::Tronque, Erreur::PasElf, Erreur::Classe, Erreur::Boutisme, Erreur::Version,
            Erreur::Machine(3), Erreur::Dynamique, Erreur::Type(1), Erreur::Interpreteur,
            Erreur::EntetesProgramme, Erreur::Segment { numero: 1, raison: "x" }, Erreur::AucunSegment,
            Erreur::Entree(5),
        ];
        for e in erreurs {
            assert!(std::format!("{e}").is_ascii());
        }
    }
}
