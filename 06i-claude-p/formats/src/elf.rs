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
//! Deux genres d'exécutables (6c) :
//!   - ET_EXEC : lié à des adresses fixes (`gcc -static`, `-no-pie`, et
//!     `claude`) ; ses `p_vaddr` sont les vraies adresses ;
//!   - ET_DYN : sans adresse fixe (un exécutable « PIE », une bibliothèque
//!     partagée, ld-linux lui-même) ; ses `p_vaddr` sont relatives, et le
//!     noyau choisit où poser l'image : une BASE ajoutée à chaque adresse.
//! D'où deux temps (le « placement » de Linux, `load_bias`) :
//!   1. `lire_entetes` vérifie la disposition RELATIVE des segments (dans
//!      le fichier, croissants, sans page commune, jamais W+X...), la même
//!      pour les deux genres ;
//!   2. `Executable::placer` vérifie que l'image, posée à l'adresse que le
//!      noyau a choisie, tient dans les adresses permises. Un ET_EXEC ne se
//!      pose qu'à ses propres adresses. Le noyau ne voit les adresses
//!      absolues qu'à travers l'`Image` placée : impossible de projeter un
//!      segment d'un ET_DYN à son adresse relative par mégarde.
//!
//! Un programme dynamique nomme son INTERPRÉTEUR (PT_INTERP) : l'éditeur
//! de liens dynamique, ld-linux, que le noyau charge à côté de lui et qui
//! fera le reste (trouver et projeter la glibc). Le chemin est une chaîne
//! dans le fichier, hors de la table : la bibliothèque dit où la lire,
//! le noyau la lit, et `chemin_interpreteur` la vérifie.
//!
//! Chaque champ est vérifié avant de servir, chaque addition aussi : un
//! fichier piégé ne doit ni faire lire le noyau hors du fichier, ni lui
//! faire projeter une page hors des adresses permises (la moitié haute est
//! au noyau !), ni écraser une page par une autre. Une base vient du noyau,
//! mais l'étendue qu'on lui ajoute vient du fichier : l'addition est
//! vérifiée elle aussi.
//!
//! La bibliothèque ne voit jamais le fichier entier (6b) : il peut faire
//! 291 Mo (`claude`), et il est fait des pages éparses du système de
//! fichiers. Comme Linux (`load_elf_binary`, puis `load_elf_phdrs`), on lit
//! en deux temps : l'en-tête de 64 octets (`lire_entete`), qui dit où est
//! la table des en-têtes de programme ; puis cette table, avec la taille du
//! fichier pour borner les segments (`lire_entetes`). Le noyau lit chaque
//! morceau dans un tampon à lui : la vérification porte sur une COPIE, que
//! personne ne peut changer ensuite (un fichier, lui, peut être réécrit
//! entre la vérification et l'usage). Un segment dit seulement où sont ses
//! octets dans le fichier ; c'est le noyau qui les lit, ou les projette.

use core::fmt;

/// Taille de l'en-tête ELF 64 bits, et d'un en-tête de programme.
const TAILLE_ENTETE: usize = 64;
const TAILLE_ENTETE_PROGRAMME: usize = 56;
/// Le plus de place que peuvent prendre les en-têtes de programme : 64 Kio,
/// la limite de Linux (load_elf_phdrs), soit 1170 en-têtes. Un vrai
/// programme en a une dizaine.
const ENTETES_MAX: usize = 65536;
/// La longueur permise du chemin de l'interpréteur, zéro final compris :
/// de 2 à PATH_MAX (4096) octets, comme Linux (load_elf_binary).
pub const INTERPRETEUR_MAX: usize = 4096;
const INTERPRETEUR_MIN: u64 = 2;

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

/// Le genre d'un exécutable (e_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Genre {
    /// ET_EXEC : à ses propres adresses.
    Fixe,
    /// ET_DYN : à l'adresse que choisit le noyau (PIE, bibliothèque,
    /// ld-linux).
    Relogeable,
}

/// Pourquoi un exécutable est refusé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erreur {
    /// Le fichier est trop court pour l'en-tête de 64 octets. (Pour un
    /// interpréteur, Linux dit EIO : la lecture de l'en-tête est courte.)
    Tronque,
    /// La table des en-têtes de programme sort du fichier. (Pour un
    /// interpréteur, Linux dit ELIBBAD : `load_elf_phdrs` échoue.)
    TableTronquee,
    /// Pas de marque « \x7fELF ».
    PasElf,
    /// Un ELF, mais pas pour nous : 32 bits, gros-boutiste, autre version,
    /// autre processeur.
    Classe,
    Boutisme,
    Version,
    Machine(u16),
    /// Ni ET_EXEC ni ET_DYN (un fichier objet .o, un fichier « core »...).
    Type(u16),
    /// e_phentsize n'est pas 56, ou trop d'en-têtes (plus de 64 Kio), ou
    /// aucun.
    EntetesProgramme,
    /// Le chemin de l'interpréteur (PT_INTERP) fait moins de 2 octets ou
    /// plus de 4096 (Linux : ENOEXEC) ;
    InterpreteurTaille(u64),
    /// ... il sort du fichier (Linux : EIO, une lecture courte) ;
    InterpreteurHorsDuFichier,
    /// ... il ne finit pas par un zéro (Linux : ENOEXEC).
    InterpreteurSansZero,
    /// Un PT_LOAD fautif (son numéro dans la table, et pourquoi).
    Segment { numero: usize, raison: &'static str },
    /// Aucun segment à charger.
    AucunSegment,
    /// Le point d'entrée n'est dans aucun segment exécutable.
    Entree(u64),
    /// Une base qui n'est pas une adresse de page, ou un ET_EXEC qu'on
    /// voudrait poser ailleurs qu'à ses adresses : une erreur du noyau, pas
    /// du fichier.
    Placement,
}

/// Les raisons du refus d'un segment, affichées par le noyau : sans
/// accents (page de code 437).
const PLUS_GRAND: &str = "plus grand dans le fichier qu'en memoire";
const HORS_FICHIER: &str = "hors du fichier";
const CONGRUENCE: &str = "adresse et position dans le fichier non congruentes modulo 4096";
const HORS_PERMISES: &str = "hors des adresses permises";
const ORDRE: &str = "chevauche le segment precedent, ou le precede";
const WX: &str = "inscriptible et executable (W+X)";

// Ces messages sont affichés par le noyau : sans accents (page de code 437).
impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Erreur::Tronque => write!(f, "fichier ELF tronque"),
            Erreur::TableTronquee => write!(f, "table des en-tetes de programme hors du fichier"),
            Erreur::PasElf => write!(f, "pas un fichier ELF"),
            Erreur::Classe => write!(f, "ELF 32 bits non pris en charge"),
            Erreur::Boutisme => write!(f, "ELF gros-boutiste non pris en charge"),
            Erreur::Version => write!(f, "version d'ELF inconnue"),
            Erreur::Machine(m) => write!(f, "ELF pour une autre machine ({m}), pas x86_64"),
            Erreur::Type(t) => write!(f, "ELF de type {t} : pas un executable"),
            Erreur::EntetesProgramme => write!(f, "table des en-tetes de programme invalide"),
            Erreur::InterpreteurTaille(n) => write!(f, "chemin de l'interpreteur (PT_INTERP) de {n} octets, pas de 2 a 4096"),
            Erreur::InterpreteurHorsDuFichier => write!(f, "chemin de l'interpreteur (PT_INTERP) hors du fichier"),
            Erreur::InterpreteurSansZero => write!(f, "chemin de l'interpreteur (PT_INTERP) sans zero final"),
            Erreur::Segment { numero, raison } => write!(f, "segment {numero} : {raison}"),
            Erreur::AucunSegment => write!(f, "aucun segment a charger"),
            Erreur::Entree(e) => write!(f, "point d'entree {e:#x} hors de tout segment executable"),
            Erreur::Placement => write!(f, "placement impossible a cette adresse"),
        }
    }
}

/// Un segment à charger (PT_LOAD), vérifié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Son adresse (pas forcément alignée sur une page) : relative pour
    /// un ET_DYN pas encore placé (`Executable::segments`), absolue une
    /// fois placé (`Image::segments`).
    pub adresse: u64,
    /// Sa taille en mémoire (au moins celle de son contenu ; le reste est
    /// à zéro).
    pub taille: u64,
    /// La part du fichier qui va à `adresse` : `taille_fichier` octets à la
    /// position `position` (dans le fichier, vérifié ; même place dans la
    /// page que `adresse`).
    pub position: u64,
    pub taille_fichier: u64,
    pub ecriture: bool,
    pub execution: bool,
}

impl Segment {
    /// La première page du segment, et la fin de sa dernière page (exclue).
    pub fn pages(&self) -> (u64, u64) {
        // Pas de débordement : vérifié par `lire_entetes` (la fin, arrondie
        // à la page, tient dans un u64), puis par `placer` pour l'image
        // posée.
        (self.adresse / PAGE * PAGE, (self.adresse + self.taille).next_multiple_of(PAGE))
    }
}

/// L'en-tête d'un exécutable, vérifié : son genre, et où lire sa table des
/// en-têtes de programme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entete {
    genre: Genre,
    entree: u64,
    position_entetes: u64,
    nombre_entetes: usize,
}

impl Entete {
    /// La position de la table des en-têtes de programme dans le fichier,
    /// et sa taille (au plus 64 Kio).
    pub fn table(&self) -> (u64, usize) {
        (self.position_entetes, self.nombre_entetes * TAILLE_ENTETE_PROGRAMME)
    }

    pub fn genre(&self) -> Genre {
        self.genre
    }
}

/// Un exécutable vérifié, pas encore placé : son en-tête, (une copie de) sa
/// table des en-têtes de programme, et ce que la vérification en a tiré.
/// Ses adresses sont celles du fichier : relatives pour un ET_DYN.
#[derive(Debug, Clone, Copy)]
pub struct Executable<'a> {
    table: &'a [u8],
    genre: Genre,
    entree: u64,
    nombre_entetes: usize,
    adresse_entetes: Option<u64>,
    /// Où lire le chemin de l'interpréteur : position et longueur.
    interpreteur: Option<(u64, usize)>,
    /// La première page du premier segment, et la fin de la dernière page
    /// du dernier (le `total_mapping_size` de Linux : la place à réserver
    /// d'un bloc).
    etendue: (u64, u64),
    alignement: u64,
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
/// adresse physique, sans objet ici).
struct EnteteProgramme {
    genre: u32,
    drapeaux: u32,
    position: u64,
    adresse: u64,
    taille_fichier: u64,
    taille_memoire: u64,
    alignement: u64,
}

impl Executable<'_> {
    /// Le i-ième en-tête de programme (la taille de la table a été
    /// vérifiée par `lire_entetes`).
    fn entete(&self, i: usize) -> EnteteProgramme {
        let o = &self.table[i * TAILLE_ENTETE_PROGRAMME..][..TAILLE_ENTETE_PROGRAMME];
        let champ32 = |j| u32_a(o, j).unwrap_or(0);
        let champ64 = |j| u64_a(o, j).unwrap_or(0);
        EnteteProgramme {
            genre: champ32(0),
            drapeaux: champ32(4),
            position: champ64(8),
            adresse: champ64(16),
            taille_fichier: champ64(32),
            taille_memoire: champ64(40),
            alignement: champ64(48),
        }
    }
}

impl<'a> Executable<'a> {
    pub fn genre(&self) -> Genre {
        self.genre
    }

    /// Le point d'entrée (e_entry), à l'adresse du fichier.
    pub fn entree(&self) -> u64 {
        self.entree
    }

    /// Où lire le chemin de l'interpréteur dans le fichier (position,
    /// longueur, de 2 à 4096 octets, dans le fichier : vérifié), si le
    /// programme en demande un (PT_INTERP). Le premier PT_INTERP compte,
    /// comme pour Linux (load_elf_binary s'arrête au premier).
    pub fn interpreteur(&self) -> Option<(u64, usize)> {
        self.interpreteur
    }

    /// Le nombre d'en-têtes de programme (AT_PHNUM).
    pub fn nombre_entetes(&self) -> usize {
        self.nombre_entetes
    }

    /// La taille d'un en-tête de programme (AT_PHENT).
    pub fn taille_entete(&self) -> usize {
        TAILLE_ENTETE_PROGRAMME
    }

    /// La place qu'occupe l'image : de la première page du premier
    /// segment à la fin de la dernière page du dernier, aux adresses du
    /// fichier. Les trous entre segments restent vides une fois l'image
    /// posée, mais leurs écarts ne bougent pas : le noyau réserve
    /// l'étendue entière d'un bloc.
    pub fn etendue(&self) -> (u64, u64) {
        self.etendue
    }

    /// L'alignement que demande l'image : le plus grand `p_align` des
    /// PT_LOAD qui est une puissance de deux, une page au moins (le
    /// `maximum_alignment` de Linux, qui saute les valeurs invalides). Il
    /// ne conditionne pas la justesse (les adresses internes sont
    /// relatives à la base, seule compte la congruence modulo la page,
    /// déjà vérifiée) : il permet les grandes pages, et les ABI à pages de
    /// 64 Kio. Linux s'en sert pour un ET_DYN, pas pour l'interpréteur.
    pub fn alignement(&self) -> u64 {
        self.alignement
    }

    /// Les segments à charger, aux adresses du fichier, dans l'ordre
    /// croissant, sans page commune. (Les PT_LOAD de taille nulle, qui
    /// n'occupent rien, sont omis.)
    pub fn segments(&self) -> impl Iterator<Item = Segment> + '_ {
        (0..self.nombre_entetes).filter_map(move |i| self.segment(i))
    }

    /// Le segment de l'en-tête `i`, si c'en est un qui occupe de la place.
    fn segment(&self, i: usize) -> Option<Segment> {
        let e = self.entete(i);
        if e.genre != PT_LOAD || e.taille_memoire == 0 {
            return None;
        }
        // Bornes vérifiées par `lire_entetes`. Un segment sans octets du
        // fichier (que du .bss) : sa position ne compte pas, on la met à
        // 0.
        Some(Segment {
            adresse: e.adresse,
            taille: e.taille_memoire,
            position: if e.taille_fichier == 0 { 0 } else { e.position },
            taille_fichier: e.taille_fichier,
            ecriture: e.drapeaux & PF_W != 0,
            execution: e.drapeaux & PF_X != 0,
        })
    }

    /// La pile doit-elle être exécutable ? Oui si un en-tête PT_GNU_STACK
    /// porte PF_X (`ld -z execstack`, ou un objet assemblé sans la note
    /// .note.GNU-stack, quand l'éditeur de liens en déduit une pile
    /// exécutable) ; non sans PT_GNU_STACK, comme Linux pour un programme
    /// 64 bits (EXSTACK_DEFAULT : sur x86_64, pas de « lecture implique
    /// exécution »). Le dernier en-tête l'emporte, comme dans Linux
    /// (load_elf_binary). Seul celui du programme compte : Linux ignore
    /// celui de l'interpréteur.
    pub fn pile_executable(&self) -> bool {
        (0..self.nombre_entetes)
            .map(|i| self.entete(i))
            .filter(|e| e.genre == PT_GNU_STACK)
            .last()
            .is_some_and(|e| e.drapeaux & PF_X != 0)
    }

    /// Pose l'image à l'adresse `debut` (sa première page y va), dans les
    /// adresses `permises` : chaque segment, décalé, doit y tenir, sans
    /// débordement. Un ET_EXEC ne se pose qu'à ses propres adresses
    /// (`debut` égal au début de son étendue) ; `debut` est une adresse de
    /// page. Rend l'image placée, la seule à donner des adresses absolues.
    pub fn placer(&self, debut: u64, permises: Plage) -> Result<Image<'a>, Erreur> {
        if debut % PAGE != 0 || (self.genre == Genre::Fixe && debut != self.etendue.0) {
            return Err(Erreur::Placement);
        }
        let image = Image { executable: *self, debut };
        for numero in 0..self.nombre_entetes {
            let Some(s) = self.segment(numero) else { continue };
            // Les pages du segment, décalées : `pages()` ne déborde pas
            // (vérifié par lire_entetes), le premier segment commence au
            // début de l'étendue, les soustractions sont donc positives ;
            // l'addition à `debut`, elle, se vérifie.
            let (premiere, fin) = s.pages();
            let deplacer = |a: u64| (a - self.etendue.0).checked_add(debut);
            match (deplacer(premiere), deplacer(fin)) {
                (Some(p), Some(f)) if p >= permises.debut && f <= permises.fin => {}
                _ => return Err(Erreur::Segment { numero, raison: HORS_PERMISES }),
            }
        }
        Ok(image)
    }
}

/// Un exécutable placé : ses adresses absolues, une fois sa première page
/// posée à `debut`. Toutes ses additions ont été vérifiées par `placer`.
#[derive(Debug, Clone, Copy)]
pub struct Image<'a> {
    executable: Executable<'a>,
    debut: u64,
}

impl<'a> Image<'a> {
    /// L'exécutable, aux adresses du fichier.
    pub fn executable(&self) -> &Executable<'a> {
        &self.executable
    }

    /// Une adresse du fichier, comprise dans l'image, vue où l'image est
    /// posée.
    fn deplacer(&self, a: u64) -> u64 {
        a - self.executable.etendue.0 + self.debut
    }

    /// Le décalage entre les adresses du fichier et celles de l'image (le
    /// `load_bias` de Linux) : 0 pour un ET_EXEC ; pour un ET_DYN dont le
    /// premier segment est à l'adresse 0 (le cas ordinaire), l'adresse où
    /// l'image est posée. C'est AT_BASE pour un interpréteur. Calculé
    /// modulo 2^64, comme Linux : un ET_DYN dont le premier segment n'est
    /// pas à 0 peut avoir un décalage « négatif ».
    pub fn decalage(&self) -> u64 {
        self.debut.wrapping_sub(self.executable.etendue.0)
    }

    /// L'étendue de l'image posée : [debut, fin[.
    pub fn etendue(&self) -> (u64, u64) {
        (self.debut, self.deplacer(self.executable.etendue.1))
    }

    /// Le point d'entrée, dans un segment exécutable (vérifié).
    pub fn entree(&self) -> u64 {
        self.deplacer(self.executable.entree)
    }

    /// L'adresse en mémoire des en-têtes de programme, si un segment les
    /// charge : la valeur d'AT_PHDR, que la glibc lit pour trouver son
    /// segment PT_TLS, et ld-linux pour trouver PT_DYNAMIC.
    pub fn adresse_entetes(&self) -> Option<u64> {
        self.executable.adresse_entetes.map(|a| self.deplacer(a))
    }

    /// Les segments, à leurs adresses absolues.
    pub fn segments(&self) -> impl Iterator<Item = Segment> + '_ {
        self.executable.segments().map(|s| Segment { adresse: self.deplacer(s.adresse), ..s })
    }

    /// La fin du dernier segment (son adresse plus sa taille en mémoire) :
    /// là où commence le tas d'un programme (brk).
    pub fn fin(&self) -> u64 {
        self.segments().map(|s| s.adresse + s.taille).max().unwrap_or(self.debut)
    }
}

/// Vérifie l'exécutable `octets`, en entier en mémoire : `lire_entete`
/// puis `lire_entetes`, sur les morceaux du fichier. (Pour les tests, et
/// pour qui a le fichier d'un seul tenant.)
pub fn lire(octets: &[u8]) -> Result<Executable<'_>, Erreur> {
    let entete = lire_entete(octets)?;
    let (position, taille) = entete.table();
    let table = usize::try_from(position)
        .ok()
        .and_then(|p| octets.get(p..p.checked_add(taille)?))
        .ok_or(Erreur::TableTronquee)?;
    lire_entetes(&entete, table, octets.len() as u64)
}

/// Vérifie l'en-tête d'un exécutable : `premiers`, les premiers octets du
/// fichier (au moins 64). Rend son genre, et où lire la table des en-têtes
/// de programme.
pub fn lire_entete(premiers: &[u8]) -> Result<Entete, Erreur> {
    let entete = premiers.get(..TAILLE_ENTETE).ok_or(Erreur::Tronque)?;
    if entete[..4] != *b"\x7fELF" {
        return Err(Erreur::PasElf);
    }
    // e_ident : classe, boutisme, version ; l'OS/ABI (octet 7) est ignoré,
    // comme le fait Linux (gcc écrit 3, « GNU », quand il y a des
    // fonctions GNU_IFUNC, ce qui est le cas de la glibc, statique ou
    // partagée).
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
    let genre = match champ16(16) {
        ET_EXEC => Genre::Fixe,
        ET_DYN => Genre::Relogeable,
        t => return Err(Erreur::Type(t)),
    };
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
    Ok(Entete { genre, entree, position_entetes, nombre_entetes })
}

/// Vérifie les en-têtes de programme de l'exécutable d'en-tête `entete` :
/// `table`, une copie de la table qu'il désigne, lue dans un fichier de
/// `taille_fichier` octets. Les segments doivent être dans le fichier, et
/// leur disposition (relative) juste ; où l'image ira, c'est `placer`.
pub fn lire_entetes<'a>(entete: &Entete, table: &'a [u8], taille_fichier: u64) -> Result<Executable<'a>, Erreur> {
    let (position_entetes, taille_table) = entete.table();
    // La table entière doit être dans le fichier, et c'est elle qu'on a.
    let fin_table = position_entetes.checked_add(taille_table as u64).ok_or(Erreur::TableTronquee)?;
    if fin_table > taille_fichier || table.len() != taille_table {
        return Err(Erreur::TableTronquee);
    }
    let entree = entete.entree;
    let mut executable = Executable {
        table,
        genre: entete.genre,
        entree,
        nombre_entetes: entete.nombre_entetes,
        adresse_entetes: None,
        interpreteur: None,
        etendue: (0, 0),
        alignement: PAGE,
    };

    // Les segments, un par un.
    let mut fin_precedent = 0u64; // Fin (arrondie à la page) du PT_LOAD précédent.
    let mut entree_trouvee = false;
    let mut segments = 0;
    for numero in 0..entete.nombre_entetes {
        let e = executable.entete(numero);
        if e.genre == PT_INTERP && executable.interpreteur.is_none() {
            // Dans l'ordre de Linux : la longueur d'abord (ENOEXEC), puis
            // la lecture (EIO si elle sort du fichier).
            if !(INTERPRETEUR_MIN..=INTERPRETEUR_MAX as u64).contains(&e.taille_fichier) {
                return Err(Erreur::InterpreteurTaille(e.taille_fichier));
            }
            if e.position.checked_add(e.taille_fichier).is_none_or(|fin| fin > taille_fichier) {
                return Err(Erreur::InterpreteurHorsDuFichier);
            }
            executable.interpreteur = Some((e.position, e.taille_fichier as usize));
        }
        if e.genre != PT_LOAD {
            continue;
        }
        // L'alignement : de tout PT_LOAD, même vide, comme
        // maximum_alignment.
        if e.alignement.is_power_of_two() {
            executable.alignement = executable.alignement.max(e.alignement);
        }
        let refus = |raison| Err(Erreur::Segment { numero, raison });
        if e.taille_fichier > e.taille_memoire {
            return refus(PLUS_GRAND);
        }
        // Un segment sans octets du fichier (que du .bss) : sa position
        // dans le fichier ne sert à rien, et Linux ne la regarde pas. Les
        // deux vérifications qui suivent ne valent que pour les autres.
        let fin_fichier = match e.position.checked_add(e.taille_fichier) {
            _ if e.taille_fichier == 0 => 0,
            Some(f) if f <= taille_fichier => f,
            _ => return refus(HORS_FICHIER),
        };
        if e.taille_memoire == 0 {
            continue;
        }
        // La page d'adresse p_vaddr doit recevoir la page du fichier qui
        // contient p_offset : même position dans la page. (C'est ce qui
        // compte pour projeter ; l'alignement demandé, lui, ne sert qu'au
        // placement, voir `alignement`.)
        if e.taille_fichier > 0 && e.adresse % PAGE != e.position % PAGE {
            return refus(CONGRUENCE);
        }
        // La fin de sa dernière page doit tenir dans les adresses : pas de
        // débordement. Où l'image ira, `placer` le vérifie. (Linux, lui,
        // refuse aussi un ET_DYN dont un `p_vaddr` relatif dépasse
        // TASK_SIZE, avant tout décalage : load_elf_binary, EINVAL. Ici,
        // seules comptent les adresses absolues de l'image posée : un
        // écart voulu, sans danger, puisque `placer` les vérifie toutes.)
        let premiere_page = e.adresse / PAGE * PAGE;
        let Some(fin) = e.adresse.checked_add(e.taille_memoire).and_then(|f| f.checked_next_multiple_of(PAGE)) else {
            return refus(HORS_PERMISES);
        };
        // Croissants et sans page commune : chaque page appartient à un
        // seul segment, avec ses droits. (Le psABI exige l'ordre croissant ;
        // ld ne fait jamais partager une page à deux segments aux droits
        // différents depuis -z separate-code, 2018.)
        if segments > 0 && premiere_page < fin_precedent {
            return refus(ORDRE);
        }
        // W^X : jamais à la fois inscriptible et exécutable. ld n'en
        // produit plus sans qu'on le demande (il avertit depuis binutils
        // 2.39) ; un tel segment ne sert qu'à du code qui se modifie, ou à
        // une attaque. (Linux les accepte ; ni ld-linux, ni la glibc, ni
        // `claude` n'en ont.)
        if e.drapeaux & PF_W != 0 && e.drapeaux & PF_X != 0 {
            return refus(WX);
        }
        if e.drapeaux & PF_X != 0 && (e.adresse..e.adresse + e.taille_memoire).contains(&entree) {
            entree_trouvee = true;
        }
        // Les en-têtes de programme sont-ils chargés par ce segment ?
        if e.position <= position_entetes && fin_table <= fin_fichier {
            executable.adresse_entetes = Some(e.adresse + (position_entetes - e.position));
        }
        if segments == 0 {
            executable.etendue.0 = premiere_page;
        }
        executable.etendue.1 = fin;
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

/// Vérifie le chemin de l'interpréteur, `octets`, lu par le noyau à
/// l'endroit que dit `Executable::interpreteur` : il doit finir par un
/// zéro (sinon ENOEXEC, comme Linux). Rend le chemin, sans zéro : ce qui
/// précède le PREMIER zéro (Linux passe la chaîne C telle quelle à
/// `open_exec`, qui s'arrête là ; mesuré : « /lib64/ld-linux-x86-64.so.2\0XXX »
/// lance ld-linux). Il peut être vide (Linux : ENOENT à l'ouverture).
pub fn chemin_interpreteur(octets: &[u8]) -> Result<&[u8], Erreur> {
    match octets.last() {
        Some(0) => {}
        _ => return Err(Erreur::InterpreteurSansZero),
    }
    let fin = octets.iter().position(|&o| o == 0).unwrap_or(octets.len());
    Ok(&octets[..fin])
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

    /// Le même, en ET_DYN : un premier segment R à l'adresse 0, qui charge
    /// le début du fichier (les en-têtes), puis le code à 0x1000 et les
    /// données à 0x2000 (la disposition de `gcc -static-pie`, en petit).
    fn exemple_dyn() -> Vec<u8> {
        let mut o = exemple();
        o[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        o[24..32].copy_from_slice(&0x1004u64.to_le_bytes());
        o[56..58].copy_from_slice(&3u16.to_le_bytes());
        entete(&mut o, 0, PT_LOAD, 4, 0, 0, 0x200, 0x200);
        entete(&mut o, 1, PT_LOAD, 5, 0x1000, 0x1000, 16, 16);
        entete(&mut o, 2, PT_LOAD, 6, 0x2000, 0x2000, 8, 0x100);
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

    fn alignement(o: &mut [u8], i: usize, a: u64) {
        o[64 + 56 * i + 48..64 + 56 * i + 56].copy_from_slice(&a.to_le_bytes());
    }

    /// Lit un ET_EXEC et le pose à ses propres adresses, comme le noyau.
    fn placer(o: &[u8]) -> Result<Image<'_>, Erreur> {
        let x = lire(o)?;
        x.placer(x.etendue().0, PERMISES)
    }

    #[test]
    fn exemple_valide() {
        let o = exemple();
        let x = placer(&o).unwrap();
        assert_eq!(x.executable().genre(), Genre::Fixe);
        assert_eq!(x.entree(), 0x401004);
        assert_eq!(x.decalage(), 0);
        assert_eq!(x.etendue(), (0x401000, 0x403000));
        let s: Vec<_> = x.segments().collect();
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].adresse, s[0].taille, s[0].position, s[0].taille_fichier, s[0].ecriture, s[0].execution),
                   (0x401000, 16, 0x1000, 16, false, true));
        assert_eq!((s[1].adresse, s[1].taille, s[1].position, s[1].taille_fichier, s[1].ecriture, s[1].execution),
                   (0x402000, 0x100, 0x2000, 8, true, false));
        assert_eq!(s[1].pages(), (0x402000, 0x403000));
        assert_eq!(x.fin(), 0x402100);
        // Les en-têtes (position 64) ne sont dans aucun segment.
        assert_eq!(x.adresse_entetes(), None);
        // Sans PT_GNU_STACK : pile non exécutable ; sans PT_INTERP : pas
        // d'interpréteur.
        assert!(!x.executable().pile_executable());
        assert_eq!(x.executable().interpreteur(), None);
        assert_eq!(x.executable().alignement(), PAGE);
    }

    #[test]
    fn pile_executable() {
        let mut o = exemple();
        o[56..58].copy_from_slice(&3u16.to_le_bytes());
        entete(&mut o, 2, PT_GNU_STACK, 6, 0, 0, 0, 0);
        assert!(!lire(&o).unwrap().pile_executable());
        entete(&mut o, 2, PT_GNU_STACK, 7, 0, 0, 0, 0);
        assert!(lire(&o).unwrap().pile_executable());
        // Deux en-têtes : le dernier l'emporte.
        o[56..58].copy_from_slice(&4u16.to_le_bytes());
        entete(&mut o, 3, PT_GNU_STACK, 6, 0, 0, 0, 0);
        assert!(!lire(&o).unwrap().pile_executable());
    }

    #[test]
    fn identite_refusee() {
        let modifier = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut o = exemple();
            f(&mut o);
            lire(&o).map(|x| x.genre())
        };
        assert_eq!(modifier(&|o| o[0] = 0), Err(Erreur::PasElf));
        assert_eq!(modifier(&|o| o[4] = 1), Err(Erreur::Classe));
        assert_eq!(modifier(&|o| o[5] = 2), Err(Erreur::Boutisme));
        assert_eq!(modifier(&|o| o[6] = 2), Err(Erreur::Version));
        assert_eq!(modifier(&|o| o[20] = 2), Err(Erreur::Version));
        assert_eq!(modifier(&|o| o[18] = 3), Err(Erreur::Machine(3)));
        // ET_DYN : accepté, relogeable.
        assert_eq!(modifier(&|o| o[16] = 3), Ok(Genre::Relogeable));
        assert_eq!(modifier(&|o| o[16] = 1), Err(Erreur::Type(1)));
        assert_eq!(modifier(&|o| o[16] = 4), Err(Erreur::Type(4)));
        // L'OS/ABI est ignoré.
        assert_eq!(modifier(&|o| o[7] = 3), Ok(Genre::Fixe));
    }

    #[test]
    fn table_des_entetes() {
        let modifier = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut o = exemple();
            f(&mut o);
            lire(&o).map(|_| ())
        };
        assert_eq!(modifier(&|o| o[54] = 32), Err(Erreur::EntetesProgramme));
        assert_eq!(modifier(&|o| o[56..58].copy_from_slice(&0u16.to_le_bytes())), Err(Erreur::EntetesProgramme));
        assert_eq!(modifier(&|o| o[56..58].copy_from_slice(&0xFFFFu16.to_le_bytes())), Err(Erreur::EntetesProgramme));
        // Position des en-têtes au-delà du fichier, ou qui déborde : la
        // table est coupée (l'en-tête, lui, est entier).
        assert_eq!(modifier(&|o| o[32..40].copy_from_slice(&0x2000u64.to_le_bytes())), Err(Erreur::TableTronquee));
        assert_eq!(modifier(&|o| o[32..40].copy_from_slice(&u64::MAX.to_le_bytes())), Err(Erreur::TableTronquee));
        assert_eq!(modifier(&|o| o[32..40].copy_from_slice(&(u64::MAX - 50).to_le_bytes())), Err(Erreur::TableTronquee));
    }

    /// Les bornes exactes : 1170 en-têtes de programme (65 520 octets)
    /// passent, 1171 (65 576, plus que 64 Kio) non ; une table qui finit au
    /// dernier octet du fichier est dans le fichier, un octet de moins non.
    #[test]
    fn bornes_de_la_table() {
        let mut o = exemple();
        o[56..58].copy_from_slice(&1170u16.to_le_bytes());
        assert!(lire_entete(&o).is_ok());
        o[56..58].copy_from_slice(&1171u16.to_le_bytes());
        assert_eq!(lire_entete(&o), Err(Erreur::EntetesProgramme));
        let o = exemple();
        let e = lire_entete(&o).unwrap();
        let table = &o[64..64 + 112];
        assert_eq!(lire_entetes(&e, table, 175).map(|_| ()), Err(Erreur::TableTronquee));
        // 176 : la table est entière ; c'est le segment de données qui sort
        // du fichier.
        assert!(matches!(lire_entetes(&e, table, 176), Err(Erreur::Segment { numero: 0, .. })));
    }

    #[test]
    fn tronque_partout() {
        let o = exemple();
        for n in 0..o.len() {
            assert!(lire(&o[..n]).is_err(), "coupe a {n} : accepte");
        }
        // Moins de 64 octets : l'en-tête lui-même est coupé ; au-delà, la
        // table (EIO et ELIBBAD pour un interpréteur, chez Linux).
        assert_eq!(lire(&o[..63]).map(|_| ()), Err(Erreur::Tronque));
        assert_eq!(lire(&o[..100]).map(|_| ()), Err(Erreur::TableTronquee));
    }

    #[test]
    fn segments_refuses() {
        let refus = |i: usize, genre, drapeaux, position, adresse, fichier, memoire| {
            let mut o = exemple();
            entete(&mut o, i, genre, drapeaux, position, adresse, fichier, memoire);
            match placer(&o) {
                Err(Erreur::Segment { numero, raison }) if numero == i => Some(raison),
                Err(e) => panic!("autre erreur : {e}"),
                Ok(_) => None,
            }
        };
        // Plus grand dans le fichier qu'en mémoire.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402000, 8, 4), Some(PLUS_GRAND));
        // Hors du fichier, ou position qui déborde.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402000, 9, 0x100), Some(HORS_FICHIER));
        assert_eq!(refus(1, PT_LOAD, 6, u64::MAX - 4, 0x402000, 8, 0x100), Some(HORS_FICHIER));
        // Non congruents.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402010, 8, 0x100), Some(CONGRUENCE));
        // Hors des adresses permises : la dernière page de la moitié
        // basse, la moitié haute (vus par `placer`), un débordement de
        // l'adresse (vu dès `lire_entetes`).
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x7fff_ffff_f000, 8, 0x100), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x7fff_ffff_e000, 8, 0x1001), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0xffff_8000_0000_0000, 8, 0x100), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0xffff_ffff_ffff_f000, 8, 0x1001), Some(HORS_PERMISES));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x402000, 8, u64::MAX), Some(HORS_PERMISES));
        // Sous 64 Kio : le premier segment (le second, plus bas, serait
        // d'abord hors de l'ordre).
        let mut o = exemple();
        entete(&mut o, 0, PT_LOAD, 5, 0x1000, 0xF000, 16, 16);
        o[24..32].copy_from_slice(&0xF004u64.to_le_bytes());
        assert_eq!(placer(&o).map(|_| ()), Err(Erreur::Segment { numero: 0, raison: HORS_PERMISES }));
        // Dans la page du précédent (au début ou à sa fin), ou avant lui.
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x401000, 8, 0x100), Some(ORDRE));
        assert_eq!(refus(1, PT_LOAD, 6, 0x1010, 0x401010, 8, 0x100), Some(ORDRE));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x400000, 8, 0x100), Some(ORDRE));
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0xF000, 8, 0x100), Some(ORDRE));
        // W+X.
        assert_eq!(refus(1, PT_LOAD, 7, 0x2000, 0x402000, 8, 0x100), Some(WX));
        // Les segments valides ne sont pas refusés pour autant : collé au
        // bout des adresses permises, ou tout au début (64 Kio).
        assert_eq!(refus(1, PT_LOAD, 6, 0x2000, 0x7fff_ffff_e000, 8, 0x1000), None);
        let mut o = exemple();
        entete(&mut o, 0, PT_LOAD, 5, 0x1000, 0x10000, 16, 16);
        o[24..32].copy_from_slice(&0x10004u64.to_le_bytes());
        assert!(placer(&o).is_ok());
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
            let x = placer(&o).unwrap();
            let s: Vec<_> = x.segments().collect();
            assert_eq!((s[1].adresse, s[1].taille, s[1].position, s[1].taille_fichier), (0x402000, 0x100, 0, 0));
        }
        // Un PT_LOAD de taille nulle en mémoire n'occupe rien : omis, où
        // qu'il prétende être.
        let mut o = exemple();
        entete(&mut o, 1, PT_LOAD, 7, 0x2000, 0xffff_8000_0000_0000, 0, 0);
        let x = placer(&o).unwrap();
        assert_eq!(x.segments().count(), 1);
        assert_eq!(x.etendue(), (0x401000, 0x402000));
    }

    #[test]
    fn entree_et_aucun_segment() {
        let mut o = exemple();
        o[24..32].copy_from_slice(&0x402000u64.to_le_bytes()); // Dans les données.
        assert_eq!(lire(&o).map(|_| ()), Err(Erreur::Entree(0x402000)));
        let mut o = exemple();
        entete(&mut o, 0, 6 /* PT_PHDR */, 4, 0, 0, 0, 0);
        entete(&mut o, 1, 6, 4, 0, 0, 0, 0);
        assert_eq!(lire(&o).map(|_| ()), Err(Erreur::AucunSegment));
    }

    #[test]
    fn point_d_entree_aux_bornes() {
        // Le dernier octet du segment de code : accepté ; juste après (la
        // borne exclue) : refusé.
        let mut o = exemple();
        o[24..32].copy_from_slice(&0x40100Fu64.to_le_bytes());
        assert!(lire(&o).is_ok());
        o[24..32].copy_from_slice(&0x401010u64.to_le_bytes());
        assert_eq!(lire(&o).map(|_| ()), Err(Erreur::Entree(0x401010)));
    }

    #[test]
    fn adresse_des_entetes() {
        // Un premier segment qui charge le début du fichier : les en-têtes
        // (position 64) sont à son adresse + 64.
        let mut o = exemple();
        entete(&mut o, 0, PT_LOAD, 5, 0, 0x400000, 0x1010, 0x1010);
        o[24..32].copy_from_slice(&0x400100u64.to_le_bytes());
        let x = placer(&o).unwrap();
        assert_eq!(x.adresse_entetes(), Some(0x400040));
        assert_eq!((x.executable().nombre_entetes(), x.executable().taille_entete()), (2, 56));
        // Le premier segment ne charge que 100 octets du fichier : la table
        // (64 + 2 x 56 = 176) déborde, elle n'est pas en mémoire.
        entete(&mut o, 0, PT_LOAD, 5, 0, 0x400000, 100, 0x1010);
        assert_eq!(placer(&o).unwrap().adresse_entetes(), None);
        // Chargée par le deuxième segment (des données qui commencent au
        // début du fichier, sur une autre page) : son adresse à lui.
        let mut o = exemple();
        entete(&mut o, 1, PT_LOAD, 6, 0, 0x402000, 0x200, 0x200);
        assert_eq!(placer(&o).unwrap().adresse_entetes(), Some(0x402040));
    }

    /// Le noyau lit l'en-tête, puis une copie de la table, avec la taille du
    /// fichier : les segments sont bornés par elle, et la table doit être
    /// celle que désigne l'en-tête.
    #[test]
    fn en_deux_temps() {
        let o = exemple();
        assert_eq!(lire_entete(&o[..63]), Err(Erreur::Tronque));
        let e = lire_entete(&o[..64]).unwrap();
        assert_eq!(e.table(), (64, 2 * 56));
        assert_eq!(e.genre(), Genre::Fixe);
        let table = &o[64..64 + 112];
        let x = lire_entetes(&e, table, o.len() as u64).unwrap();
        assert_eq!(x.segments().count(), 2);
        // Une table plus courte ou plus longue que celle de l'en-tête.
        assert_eq!(lire_entetes(&e, &o[64..64 + 111], o.len() as u64).map(|_| ()), Err(Erreur::TableTronquee));
        assert_eq!(lire_entetes(&e, &o[64..64 + 113], o.len() as u64).map(|_| ()), Err(Erreur::TableTronquee));
        // Un fichier qui s'arrête avant la fin du segment de données
        // (0x2008), ou avant la fin de la table.
        assert!(matches!(lire_entetes(&e, table, 0x2007), Err(Erreur::Segment { numero: 1, .. })));
        assert_eq!(lire_entetes(&e, table, 100).map(|_| ()), Err(Erreur::TableTronquee));
        assert!(lire_entetes(&e, table, 0x2008).is_ok());
    }

    /// Un ET_DYN : vérifié aux adresses du fichier, puis posé là où le
    /// noyau le décide.
    #[test]
    fn relogeable_place() {
        let o = exemple_dyn();
        let x = lire(&o).unwrap();
        assert_eq!(x.genre(), Genre::Relogeable);
        assert_eq!(x.etendue(), (0, 0x3000));
        assert_eq!(x.entree(), 0x1004);
        // À l'adresse d'un PIE sous Linux (ELF_ET_DYN_BASE, à la page).
        let i = x.placer(0x5555_5555_4000, PERMISES).unwrap();
        assert_eq!(i.decalage(), 0x5555_5555_4000);
        assert_eq!(i.etendue(), (0x5555_5555_4000, 0x5555_5555_7000));
        assert_eq!(i.entree(), 0x5555_5555_5004);
        assert_eq!(i.adresse_entetes(), Some(0x5555_5555_4040));
        let s: Vec<_> = i.segments().collect();
        assert_eq!(s.iter().map(|s| s.adresse).collect::<Vec<_>>(), [0x5555_5555_4000, 0x5555_5555_5000, 0x5555_5555_6000]);
        // Les positions dans le fichier ne bougent pas.
        assert_eq!(s.iter().map(|s| s.position).collect::<Vec<_>>(), [0, 0x1000, 0x2000]);
        assert_eq!(i.fin(), 0x5555_5555_6100);
        // Tout au bout des adresses permises : accepté ; une page plus
        // loin, ou là où l'addition déborderait : refusé.
        assert!(x.placer(PERMISES.fin - 0x3000, PERMISES).is_ok());
        assert_eq!(x.placer(PERMISES.fin - 0x2000, PERMISES).map(|_| ()),
                   Err(Erreur::Segment { numero: 2, raison: HORS_PERMISES }));
        assert!(matches!(x.placer(u64::MAX / PAGE * PAGE, PERMISES), Err(Erreur::Segment { .. })));
        assert_eq!(x.placer(0, PERMISES).map(|_| ()), Err(Erreur::Segment { numero: 0, raison: HORS_PERMISES }));
        // Une base qui n'est pas une adresse de page : une erreur du noyau.
        assert_eq!(x.placer(0x5555_5555_4010, PERMISES).map(|_| ()), Err(Erreur::Placement));
        // Un ET_EXEC ne va qu'à ses adresses.
        let o = exemple();
        let x = lire(&o).unwrap();
        assert_eq!(x.placer(0x5555_5555_4000, PERMISES).map(|_| ()), Err(Erreur::Placement));
        assert!(x.placer(0x401000, PERMISES).is_ok());
    }

    /// Un ET_DYN dont le premier segment n'est pas à 0 : le décalage est
    /// l'adresse moins celle du fichier, modulo 2^64 comme chez Linux.
    #[test]
    fn decalage_negatif() {
        let mut o = exemple();
        o[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        let x = lire(&o).unwrap();
        let i = x.placer(0x20_0000, PERMISES).unwrap();
        assert_eq!(i.etendue(), (0x20_0000, 0x20_2000));
        assert_eq!(i.entree(), 0x20_0004);
        assert_eq!(i.decalage(), 0x20_0000u64.wrapping_sub(0x401000));
        assert_eq!(i.segments().next().unwrap().adresse.wrapping_sub(i.decalage()), 0x401000);
    }

    #[test]
    fn alignement_demande() {
        let mut o = exemple_dyn();
        assert_eq!(lire(&o).unwrap().alignement(), PAGE);
        // Le plus grand des PT_LOAD, s'il est une puissance de deux.
        alignement(&mut o, 1, 0x20_0000);
        assert_eq!(lire(&o).unwrap().alignement(), 0x20_0000);
        alignement(&mut o, 2, 0x30_0000);
        assert_eq!(lire(&o).unwrap().alignement(), 0x20_0000);
        // Une page au moins : 0, 1 ou 16 donnent une page.
        for a in [0, 1, 16] {
            let mut o = exemple_dyn();
            alignement(&mut o, 0, a);
            assert_eq!(lire(&o).unwrap().alignement(), PAGE);
        }
        // Un PT_LOAD vide compte aussi, comme pour maximum_alignment.
        let mut o = exemple_dyn();
        o[56..58].copy_from_slice(&4u16.to_le_bytes());
        entete(&mut o, 3, PT_LOAD, 4, 0, 0x3000, 0, 0);
        alignement(&mut o, 3, 0x20_0000);
        assert_eq!(lire(&o).unwrap().alignement(), 0x20_0000);
        // Les autres en-têtes ne comptent pas.
        let mut o = exemple_dyn();
        o[56..58].copy_from_slice(&4u16.to_le_bytes());
        entete(&mut o, 3, PT_GNU_STACK, 6, 0, 0, 0, 0);
        alignement(&mut o, 3, 0x100_0000);
        assert_eq!(lire(&o).unwrap().alignement(), PAGE);
    }

    #[test]
    fn interpreteur() {
        // Un PT_INTERP de 28 octets à la position 0x1800 (dans le fichier).
        let avec = |position: u64, longueur: u64| {
            let mut o = exemple_dyn();
            o[56..58].copy_from_slice(&4u16.to_le_bytes());
            entete(&mut o, 3, PT_INTERP, 4, position, 0, longueur, longueur);
            o
        };
        let o = avec(0x1800, 28);
        assert_eq!(lire(&o).unwrap().interpreteur(), Some((0x1800, 28)));
        // De 2 à 4096 octets ; dans le fichier (0x2008 octets).
        assert_eq!(lire(&avec(0x1800, 1)).map(|_| ()), Err(Erreur::InterpreteurTaille(1)));
        assert_eq!(lire(&avec(0x1800, 0)).map(|_| ()), Err(Erreur::InterpreteurTaille(0)));
        assert_eq!(lire(&avec(0, 4097)).map(|_| ()), Err(Erreur::InterpreteurTaille(4097)));
        assert_eq!(lire(&avec(0, 4096)).unwrap().interpreteur(), Some((0, 4096)));
        assert_eq!(lire(&avec(0x2000, 8)).unwrap().interpreteur(), Some((0x2000, 8)));
        assert_eq!(lire(&avec(0x2000, 9)).map(|_| ()), Err(Erreur::InterpreteurHorsDuFichier));
        assert_eq!(lire(&avec(u64::MAX - 4, 28)).map(|_| ()), Err(Erreur::InterpreteurHorsDuFichier));
        // Deux PT_INTERP : le premier compte, le second n'est pas regardé.
        let mut o = avec(0x1800, 28);
        o[56..58].copy_from_slice(&5u16.to_le_bytes());
        o.resize(0x2008.max(64 + 5 * 56), 0);
        entete(&mut o, 4, PT_INTERP, 4, u64::MAX, 0, 1, 1);
        assert_eq!(lire(&o).unwrap().interpreteur(), Some((0x1800, 28)));
        // Un ET_EXEC peut aussi en demander un (comme `claude`).
        let mut o = exemple();
        entete(&mut o, 1, PT_INTERP, 4, 0x1800, 0, 28, 28);
        assert_eq!(lire(&o).unwrap().interpreteur(), Some((0x1800, 28)));
    }

    #[test]
    fn chemin_de_l_interpreteur() {
        assert_eq!(chemin_interpreteur(b"/lib64/ld-linux-x86-64.so.2\0"), Ok(&b"/lib64/ld-linux-x86-64.so.2"[..]));
        // Sans zéro final : refusé ; un zéro au milieu : le préfixe, comme
        // Linux ; un chemin vide est rendu tel quel (ENOENT à l'ouverture).
        assert_eq!(chemin_interpreteur(b"/lib64/ld"), Err(Erreur::InterpreteurSansZero));
        assert_eq!(chemin_interpreteur(b""), Err(Erreur::InterpreteurSansZero));
        assert_eq!(chemin_interpreteur(b"/lib\0XXX\0"), Ok(&b"/lib"[..]));
        assert_eq!(chemin_interpreteur(b"\0\0"), Ok(&b""[..]));
    }

    #[test]
    fn messages_sans_accents() {
        let erreurs = [
            Erreur::Tronque, Erreur::TableTronquee, Erreur::PasElf, Erreur::Classe, Erreur::Boutisme,
            Erreur::Version, Erreur::Machine(3), Erreur::Type(1), Erreur::EntetesProgramme,
            Erreur::InterpreteurTaille(1), Erreur::InterpreteurHorsDuFichier, Erreur::InterpreteurSansZero,
            Erreur::Segment { numero: 1, raison: "x" }, Erreur::AucunSegment, Erreur::Entree(5), Erreur::Placement,
        ];
        for e in erreurs {
            assert!(std::format!("{e}").is_ascii());
        }
    }
}
