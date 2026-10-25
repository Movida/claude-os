//! Le chargeur d'exécutables ELF : d'un fichier vérifié à un espace
//! d'adressage prêt à exécuter (le cœur de load_elf_binary, dans
//! fs/binfmt_elf.c de Linux).
//!
//! Le fichier est vérifié par la bibliothèque des formats
//! (../formats/src/elf.rs), sur une copie de son en-tête et de sa table
//! des en-têtes de programme (`verifier`), comme `load_elf_phdrs` : la
//! bibliothèque ne voit jamais le fichier entier, que le noyau lit par
//! morceaux. Segments dans les adresses permises, croissants, sans page
//! commune, jamais W+X. Chaque segment devient une
//! zone de la mémoire du programme (memoire.rs), avec ses droits ; les
//! pages qui contiennent une part du fichier reçoivent chacune un cadre
//! neuf, mis à zéro, où l'on copie cette part. Le reste d'une telle page
//! reste à zéro, et les pages entières du .bss (la partie d'un segment qui
//! n'est pas dans le fichier) forment une zone anonyme, comme sous Linux,
//! sans aucune page : la première faute leur donnera la page de zéros,
//! puis une page neuve à la première écriture.
//!
//! Linux fait plus : il projette le FICHIER lui-même (mmap), et les pages
//! du code ne sont lues qu'au premier accès. Il faut pour cela un cache
//! des fichiers (6b). Copier d'avance ce qui vient du fichier coûte de la
//! mémoire (le code de `claude` pèse près de 100 Mo) mais n'a besoin de
//! rien d'autre.
//!
//! La copie passe par la projection directe des cadres (voir
//! Memoire::ecrire) : le noyau n'écrit jamais par les adresses du
//! programme, il n'a donc rien à ouvrir côté SMAP (copie_utilisateur.rs).

use alloc::vec::Vec;
use core::fmt;

use crate::espace_utilisateur;
use crate::memoire::{self, Memoire};
use crate::programmes::NomCourt;
use formats::elf::{Entete, Executable, Plage};
use zones::{Drapeaux, Droits, Nature, Zone};

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
        return Err(Refus::Format(formats::elf::Erreur::Tronque));
    }
    Ok((entete, table))
}

/// Charge l'exécutable vérifié `executable` dans un espace d'adressage neuf
/// ; `lire` lit le fichier (voir `verifier`). En cas d'échec (plus de
/// mémoire), tout ce qui a été pris est rendu (l'espace est détruit en
/// sortant de la fonction).
pub fn charger(executable: &Executable, nom: NomCourt, lire: impl Fn(u64, &mut [u8]) -> bool)
    -> Result<Programme, espace_utilisateur::Erreur> {
    let mut memoire = Memoire::creer(nom)?;
    for segment in executable.segments() {
        let droits = Droits { lecture: true, ecriture: segment.ecriture, execution: segment.execution };
        let (debut, fin) = segment.pages();
        // Les pages qui contiennent une part du fichier : une zone du
        // programme. Les pages entières du .bss, au-delà : une zone
        // anonyme à part, comme Linux (vm_brk_flags dans load_elf_binary).
        // La différence compte : sous Linux, MADV_DONTNEED fait relire le
        // FICHIER aux premières, et des zéros aux secondes (voir madvise,
        // dans linux.rs).
        let fin_fichier = match segment.taille_fichier {
            0 => debut,
            n => (segment.adresse + n).next_multiple_of(4096),
        };
        let drapeaux = Drapeaux::default();
        if fin_fichier > debut {
            let zone = Zone { debut, fin: fin_fichier, droits, nature: Nature::Programme, drapeaux, fichier: None };
            memoire.zones.inserer(zone, &mut memoire::references)?;
        }
        if fin > fin_fichier {
            let zone = Zone { debut: fin_fichier, fin, droits, nature: Nature::Anonyme, drapeaux, fichier: None };
            memoire.zones.inserer(zone, &mut memoire::references)?;
        }
        // La part du fichier, copiée par morceaux (la bibliothèque a
        // vérifié qu'elle est dans le fichier).
        let mut morceau = [0u8; 512];
        let mut fait = 0;
        while fait < segment.taille_fichier {
            let n = (segment.taille_fichier - fait).min(morceau.len() as u64) as usize;
            if !lire(segment.position + fait, &mut morceau[..n]) {
                return Err(espace_utilisateur::Erreur::NonProjetee);
            }
            memoire.ecrire(segment.adresse + fait, &morceau[..n])?;
            fait += n as u64;
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
        droits: Droits { lecture: true, ecriture: true, execution: executable.pile_executable() },
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
        nombre_entetes: executable.nombre_entetes(),
        taille_entete: executable.taille_entete(),
        fin: executable.fin(),
        sommet_pile,
    })
}
