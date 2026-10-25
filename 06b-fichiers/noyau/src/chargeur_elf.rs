//! Le chargeur d'exécutables ELF : d'un fichier vérifié à un espace
//! d'adressage prêt à exécuter (le cœur de load_elf_binary, dans
//! fs/binfmt_elf.c de Linux).
//!
//! Le fichier a été vérifié par la bibliothèque des formats
//! (../formats/src/elf.rs) : segments dans les adresses permises,
//! croissants, sans page commune, jamais W+X. Chaque segment devient une
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

use crate::espace_utilisateur;
use crate::memoire::{self, Memoire};
use formats::elf::{Executable, Plage};
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

/// Charge l'exécutable vérifié `executable` dans un espace d'adressage neuf.
/// En cas d'échec (plus de mémoire), tout ce qui a été pris est rendu
/// (l'espace est détruit en sortant de la fonction).
pub fn charger(executable: &Executable, nom: &'static [u8]) -> Result<Programme, espace_utilisateur::Erreur> {
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
        let fin_fichier = match segment.contenu.len() as u64 {
            0 => debut,
            n => (segment.adresse + n).next_multiple_of(4096),
        };
        let drapeaux = Drapeaux::default();
        if fin_fichier > debut {
            memoire.zones.inserer(Zone { debut, fin: fin_fichier, droits, nature: Nature::Programme, drapeaux })?;
        }
        if fin > fin_fichier {
            memoire.zones.inserer(Zone { debut: fin_fichier, fin, droits, nature: Nature::Anonyme, drapeaux })?;
        }
        memoire.ecrire(segment.adresse, segment.contenu)?;
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
    };
    memoire.zones.inserer(pile)?;
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
