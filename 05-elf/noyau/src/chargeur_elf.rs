//! Le chargeur d'exécutables ELF : d'un fichier vérifié à un espace
//! d'adressage prêt à exécuter (le cœur de load_elf_binary, dans
//! fs/binfmt_elf.c de Linux).
//!
//! Le fichier a été vérifié par la bibliothèque des formats
//! (../formats/src/elf.rs) : segments dans les adresses permises,
//! croissants, sans page commune, jamais W+X. Il reste à donner à chaque
//! page de chaque segment un cadre neuf, mis à zéro, avec les droits du
//! segment, et à y copier la part du fichier qui lui revient. Le reste de
//! la page reste à zéro : c'est ainsi que le .bss (la partie d'un segment
//! qui n'est pas dans le fichier) est nul d'office.
//!
//! Linux fait autrement : il projette le FICHIER lui-même (mmap), et les
//! pages ne sont lues qu'au premier accès (pagination à la demande). Il
//! faut pour cela un cache des fichiers et un gestionnaire de fautes de
//! page qui sait les servir : l'étape 6. Copier tout d'avance coûte de la
//! mémoire (le code de `claude` pèse près de 100 Mo) mais n'a besoin de
//! rien d'autre.
//!
//! La copie passe par la projection directe des cadres (voir
//! EspaceUtilisateur::ecrire) : le noyau n'écrit jamais par les adresses
//! du programme, il n'a donc rien à ouvrir côté SMAP (sous-étape 7).

use crate::espace_utilisateur::{self, EspaceUtilisateur};
use crate::pagination;
use formats::elf::{Executable, Plage};

/// Les adresses que les segments d'un programme ont le droit d'occuper,
/// pour la vérification du fichier : celles des programmes (voir
/// espace_utilisateur.rs), sauf la pile, tout en haut, et une page
/// d'écart sous elle. Un fichier qui voudrait y mettre un segment est
/// refusé d'emblée, avec un message qui le dit (« hors des adresses
/// permises »), plutôt que d'échouer au chargement sur une page « déjà
/// projetée ».
pub const PERMISES: Plage = Plage { debut: espace_utilisateur::ADRESSE_MIN, fin: SOMMET_PILE - TAILLE_PILE - 4096 };

/// Un programme chargé, prêt à partir.
pub struct Programme {
    pub espace: EspaceUtilisateur,
    /// Le point d'entrée.
    pub entree: u64,
    /// Pour le vecteur auxiliaire (AT_PHDR, AT_PHNUM, AT_PHENT).
    pub adresse_entetes: Option<u64>,
    pub nombre_entetes: usize,
    pub taille_entete: usize,
    /// La fin du dernier segment : le début du tas (brk).
    pub fin: u64,
    /// Le sommet de sa pile.
    pub sommet_pile: u64,
}

/// La pile du programme : 128 Kio projetés d'avance, juste sous la fin des
/// adresses permises, rien en dessous. Linux, lui, la fait grandir à la
/// demande (une faute de page sous la pile l'étend), jusqu'à 8 Mio par
/// défaut (RLIMIT_STACK) : il faut la pagination à la demande (étape 6).
/// 128 Kio, c'est ce que Linux projette d'avance lui aussi au lancement
/// (stack_guard_gap mis à part), et bien plus qu'un programme C ordinaire
/// n'en utilise. Un programme qui déborde fait une faute de page sous la
/// pile, et il est arrêté.
pub const TAILLE_PILE: u64 = 128 << 10;
pub const SOMMET_PILE: u64 = espace_utilisateur::ADRESSE_MAX;

/// Charge l'exécutable vérifié `executable` dans un espace d'adressage neuf.
/// En cas d'échec (plus de mémoire), tout ce qui a été pris est rendu
/// (l'espace est détruit en sortant de la fonction).
pub fn charger(executable: &Executable) -> Result<Programme, espace_utilisateur::Erreur> {
    let mut espace = EspaceUtilisateur::creer()?;
    for segment in executable.segments() {
        let mut droits = 0;
        if segment.ecriture {
            droits |= pagination::ECRITURE;
        }
        if !segment.execution {
            droits |= pagination::non_executable();
        }
        let (debut, fin) = segment.pages();
        for page in (debut..fin).step_by(4096) {
            espace.projeter_neuve(page, droits)?;
        }
        espace.ecrire(segment.adresse, segment.contenu)?;
    }
    // La pile : inscriptible, jamais exécutable.
    for page in (SOMMET_PILE - TAILLE_PILE..SOMMET_PILE).step_by(4096) {
        espace.projeter_neuve(page, pagination::ECRITURE | pagination::non_executable())?;
    }
    Ok(Programme {
        espace,
        entree: executable.entree(),
        adresse_entetes: executable.adresse_entetes(),
        nombre_entetes: executable.nombre_entetes(),
        taille_entete: executable.taille_entete(),
        fin: executable.fin(),
        sommet_pile: SOMMET_PILE,
    })
}
