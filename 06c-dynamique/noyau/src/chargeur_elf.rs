//! Le chargeur d'exécutables ELF : d'un fichier vérifié à un espace
//! d'adressage prêt à exécuter (le cœur de load_elf_binary, dans
//! fs/binfmt_elf.c de Linux).
//!
//! Le fichier est vérifié par la bibliothèque des formats
//! (../formats/src/elf.rs), sur une copie de son en-tête et de sa table
//! des en-têtes de programme (`verifier`), comme `load_elf_phdrs` : la
//! bibliothèque ne voit jamais le fichier entier, que le noyau lit par
//! morceaux. Segments dans les adresses permises, croissants, sans page
//! commune, jamais W+X.
//!
//! Comme Linux (`elf_map`, puis `elf_load`), le chargeur ne copie rien : il
//! PROJETTE le fichier (6b). Chaque segment devient une zone de fichier,
//! en privé, avec ses droits : ses pages sont celles du fichier, données à
//! la faute, en lecture seule, et copiées à la première écriture (memoire.rs,
//! espace_utilisateur.rs). Pour `claude` (291 Mo, dont 86 Mo de code),
//! seul ce que le programme touche est en place, et une page de code est
//! la même pour tous les programmes qui l'exécutent.
//!
//! Le .bss : la partie d'un segment qui n'est pas dans le fichier, à zéro.
//!   - la fin de la dernière page du fichier, au-delà de `p_filesz`,
//!     contient les octets qui suivent dans le fichier : le noyau la met à
//!     zéro (le `padzero` de Linux), seulement si le segment a un .bss
//!     (`p_memsz > p_filesz`) et s'il est inscriptible (Linux ignore
//!     l'échec sinon) ; c'est une écriture, donc une copie de cette seule
//!     page ;
//!   - les pages entières au-delà forment une zone anonyme, comme sous
//!     Linux (`vm_brk_flags`) : en lecture et écriture, et exécutable si le
//!     segment l'est, quels que soient ses autres droits.
//! La différence compte : MADV_DONTNEED fait relire le FICHIER aux pages
//! du segment, et des zéros à celles du .bss (le cas de Bun et de sa
//! section `.bun`).
//!
//! Le noyau écrit (padzero, la pile initiale) par la projection directe
//! des cadres (voir Memoire::ecrire) : il n'écrit jamais par les adresses
//! du programme, il n'a donc rien à ouvrir côté SMAP (copie_utilisateur.rs).

use alloc::vec::Vec;
use core::fmt;

use crate::descripteurs::Fichier;
use crate::espace_utilisateur;
use crate::memoire::{self, Memoire};
use crate::programmes::NomCourt;
use formats::elf::{Entete, Image, Plage};
use zones::{Drapeaux, Droits, Nature, Projection, Zone};

/// Les adresses que les segments d'un programme ont le droit d'occuper,
/// pour la vérification du fichier : celles des programmes (voir
/// espace_utilisateur.rs), sous la base des projections (memoire.rs,
/// disposition) : au-dessus, la place est à mmap et à la pile, qui doit
/// pouvoir grandir jusqu'à sa limite. Un fichier qui voudrait y mettre un
/// segment est refusé d'emblée, avec un message qui le dit (« hors des
/// adresses permises »).
pub const PERMISES: Plage = Plage { debut: espace_utilisateur::ADRESSE_MIN, fin: memoire::disposition().base_mmap };

/// Un programme chargé, prêt à partir.
pub struct Programme {
    pub memoire: Memoire,
    /// Le point d'entrée.
    pub entree: u64,
    /// Pour le vecteur auxiliaire (AT_PHDR, AT_PHNUM, AT_PHENT).
    pub adresse_entetes: Option<u64>,
    pub nombre_entetes: usize,
    pub taille_entete: usize,
    /// La fin du dernier segment (le tas commence à la page suivante).
    pub fin: u64,
    /// Le sommet de sa pile.
    pub sommet_pile: u64,
}

/// La place qu'arguments et environnement peuvent prendre en haut de la
/// pile : un quart de sa taille maximale (2 Mio), comme Linux. La zone de
/// pile la couvre le temps d'écrire la pile initiale (pile.rs), puis elle
/// est ramenée à ce qui est occupé, plus PILE_INITIALE.
pub const PLACE_ARGUMENTS: u64 = memoire::PILE_MAX / 4;

/// Pourquoi un fichier n'a pas pu être vérifié.
pub enum Refus {
    /// Ce que dit la bibliothèque des formats.
    Format(formats::elf::Erreur),
    /// Plus de mémoire pour la copie de la table.
    PlusDeMemoire,
}

// Affiché par le noyau : sans accents.
impl fmt::Display for Refus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Refus::Format(e) => write!(f, "{e}"),
            Refus::PlusDeMemoire => f.write_str("plus de memoire pour la table des en-tetes"),
        }
    }
}

/// Lit et vérifie l'en-tête d'un fichier de `taille` octets, puis copie sa
/// table des en-têtes de programme (64 Kio au plus) dans un bloc du tas :
/// la pile du noyau ne fait que 16 Kio. `lire(position, tampon)` remplit
/// le tampon avec les octets du fichier à cette position, et dit faux si
/// le fichier s'arrête avant. Rend l'en-tête et la copie de la table, que
/// `formats::elf::lire_entetes` vérifie ensuite.
pub fn verifier(taille: u64, lire: impl Fn(u64, &mut [u8]) -> bool) -> Result<(Entete, Vec<u8>), Refus> {
    let mut premiers = [0u8; 64];
    if !lire(0, &mut premiers) {
        return Err(Refus::Format(formats::elf::Erreur::Tronque));
    }
    let entete = formats::elf::lire_entete(&premiers).map_err(Refus::Format)?;
    let (position, longueur) = entete.table();
    let mut table = Vec::new();
    table.try_reserve_exact(longueur).map_err(|_| Refus::PlusDeMemoire)?;
    table.resize(longueur, 0);
    if position.checked_add(longueur as u64).is_none_or(|fin| fin > taille) || !lire(position, &mut table) {
        return Err(Refus::Format(formats::elf::Erreur::TableTronquee));
    }
    Ok((entete, table))
}

/// Charge l'exécutable vérifié et placé `executable`, du fichier ouvert `fichier`,
/// dans un espace d'adressage neuf : chaque zone de segment tient le
/// fichier (une référence). En cas d'échec (plus de mémoire), tout ce qui a
/// été pris est rendu (l'espace et ses zones sont détruits en sortant de la
/// fonction).
pub fn charger(executable: &Image, nom: NomCourt, fichier: Fichier) -> Result<Programme, espace_utilisateur::Erreur> {
    let mut memoire = Memoire::creer(nom)?;
    for segment in executable.segments() {
        let droits = Droits { lecture: true, ecriture: segment.ecriture, execution: segment.execution };
        let (debut, fin) = segment.pages();
        // Les pages qui contiennent une part du fichier : une zone du
        // fichier, à partir de la page qui contient `p_offset` (la
        // bibliothèque a vérifié qu'il a la même place dans sa page que
        // `p_vaddr`). Les pages entières du .bss, au-delà : une zone
        // anonyme à part (voir l'en-tête).
        let fin_fichier = match segment.taille_fichier {
            0 => debut,
            n => (segment.adresse + n).next_multiple_of(4096),
        };
        let drapeaux = Drapeaux::default();
        if fin_fichier > debut {
            let projection = Projection { fichier: fichier.numero(), page: segment.position / 4096 };
            let zone = Zone { debut, fin: fin_fichier, droits, nature: Nature::Programme, drapeaux, fichier: Some(projection) };
            memoire.zones.inserer(zone, &mut memoire::references)?;
        }
        if fin > fin_fichier {
            let bss = Droits { lecture: true, ecriture: true, execution: segment.execution };
            let zone = Zone { debut: fin_fichier, fin, droits: bss, nature: Nature::Anonyme, drapeaux, fichier: None };
            memoire.zones.inserer(zone, &mut memoire::references)?;
        }
        // padzero : la fin de la dernière page du fichier, s'il y a un .bss
        // et que le segment est inscriptible.
        let fin_contenu = segment.adresse + segment.taille_fichier;
        if segment.taille > segment.taille_fichier && segment.ecriture && segment.taille_fichier > 0 && fin_contenu % 4096 != 0 {
            let zeros = [0u8; 512];
            let mut a = fin_contenu;
            while a < fin_fichier {
                let n = ((fin_fichier - a) as usize).min(zeros.len());
                memoire.ecrire(a, &zeros[..n])?;
                a += n as u64;
            }
        }
    }
    // La pile : inscriptible, une zone qui grandit vers le bas. Aucune page
    // tant que le noyau n'y a rien écrit. Exécutable seulement si le
    // programme le demande (PT_GNU_STACK avec PF_X) : Linux l'accepte, et
    // un vieux programme qui pose du code sur sa pile (les « trampolines »
    // de gcc pour les fonctions imbriquées) planterait sinon sans
    // explication. Le refuser serait plus sûr, mais pas Linux.
    let sommet_pile = memoire::disposition().sommet_pile;
    let pile = Zone {
        debut: sommet_pile - PLACE_ARGUMENTS,
        fin: sommet_pile,
        droits: Droits { lecture: true, ecriture: true, execution: executable.executable().pile_executable() },
        nature: Nature::Pile,
        drapeaux: Drapeaux { vers_le_bas: true, ..Drapeaux::default() },
        fichier: None,
    };
    memoire.zones.inserer(pile, &mut memoire::references)?;
    // Un tas vide, à la page qui suit le dernier segment (comme Linux sans
    // ASLR).
    let tas = executable.fin().next_multiple_of(4096);
    (memoire.debut_tas, memoire.fin_tas) = (tas, tas);
    Ok(Programme {
        memoire,
        entree: executable.entree(),
        adresse_entetes: executable.adresse_entetes(),
        nombre_entetes: executable.executable().nombre_entetes(),
        taille_entete: executable.executable().taille_entete(),
        fin: executable.fin(),
        sommet_pile,
    })
}
