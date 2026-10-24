//! La pile initiale d'un programme Linux : ce qu'il trouve au sommet de sa
//! pile en démarrant (create_elf_tables, dans fs/binfmt_elf.c de Linux).
//!
//! Un programme ne reçoit aucun paramètre dans ses registres (ils sont
//! tous à zéro, voir tache.rs) : tout est sur la pile, selon l'ABI System V
//! pour x86_64 (§3.4.1). De RSP vers le haut :
//!
//!     RSP ->  argc                       le nombre d'arguments
//!             argv[0] ... argv[argc-1]   des pointeurs vers les chaînes
//!             0
//!             envp[0] ... envp[n-1]      l'environnement (« NOM=valeur »)
//!             0
//!             auxv : paires (type, valeur), terminées par (AT_NULL, 0)
//!             (remplissage)
//!             16 octets aléatoires       (AT_RANDOM)
//!             "x86_64"                   (AT_PLATFORM)
//!             les chaînes d'argv, puis celles d'envp
//!             le nom du programme        (AT_EXECFN)
//!             8 octets nuls
//!     sommet de la pile
//!
//! RSP est aligné sur 16 octets : l'ABI le garantit au point d'entrée, et
//! le code compilé s'en sert (les instructions SSE `movaps` sur la pile).
//!
//! Le VECTEUR AUXILIAIRE (auxv) est ce que le noyau dit au programme sur
//! lui-même et sur la machine, sans appel système : où sont ses en-têtes
//! de programme (la glibc statique y trouve son PT_TLS), la taille des
//! pages, son point d'entrée, ses identités, les fonctions du processeur...
//! La glibc le lit avant même main (_dl_aux_init), et getauxval() le rend.

use crate::aleatoire;
use crate::chargeur_elf::{self, Programme};
use crate::espace_utilisateur;

// Les types de l'auxv (include/uapi/linux/auxvec.h).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;

/// L'identité du programme : l'utilisateur 1000, le premier utilisateur
/// ordinaire des distributions Linux, plutôt que root (0). Il n'y a qu'un
/// utilisateur sur cette machine, mais un programme n'a aucune raison de
/// se croire tout-puissant ; et certains refusent de tourner en root, ou
/// changent de comportement (Claude Code refuse
/// --dangerously-skip-permissions en root).
pub const UTILISATEUR: u64 = 1000;
pub const GROUPE: u64 = 1000;

/// La fréquence des « tics » que voient les programmes (times(), le
/// USER_HZ de Linux) : 100, quelle que soit la fréquence de l'horloge du
/// noyau, pour que l'ABI ne change pas.
pub const USER_HZ: u64 = 100;

/// Au plus un quart de la pile pour les chaînes et les tables, comme
/// Linux (un quart de RLIMIT_STACK) : le programme doit garder de la
/// place pour lui.
const PLACE_MAX: u64 = chargeur_elf::TAILLE_PILE / 4;

/// Pourquoi la pile n'a pas pu être construite.
#[derive(Debug)]
pub enum Erreur {
    /// Arguments et environnement trop longs (E2BIG).
    TropLong,
    Espace(espace_utilisateur::Erreur),
}

impl core::fmt::Display for Erreur {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Erreur::TropLong => f.write_str("arguments et environnement trop longs"),
            Erreur::Espace(e) => write!(f, "{e}"),
        }
    }
}

impl From<espace_utilisateur::Erreur> for Erreur {
    fn from(e: espace_utilisateur::Erreur) -> Self {
        Erreur::Espace(e)
    }
}

/// Une écriture de haut en bas dans la pile du programme.
struct Curseur<'a> {
    programme: &'a mut Programme,
    sp: u64,
}

impl Curseur<'_> {
    /// Range `octets` juste sous le curseur, et rend leur adresse.
    fn empiler(&mut self, octets: &[u8]) -> Result<u64, Erreur> {
        let n = octets.len() as u64;
        if self.programme.sommet_pile - self.sp + n > PLACE_MAX {
            return Err(Erreur::TropLong);
        }
        self.sp -= n;
        self.programme.espace.ecrire(self.sp, octets)?;
        Ok(self.sp)
    }

    /// Une chaîne et son zéro final.
    fn chaine(&mut self, texte: &[u8]) -> Result<u64, Erreur> {
        self.empiler(&[0])?;
        self.empiler(texte)
    }
}

/// Construit la pile initiale du programme `programme` : `argv` (argv[0]
/// est d'habitude son nom), `envp` (des chaînes « NOM=valeur »), `nom` (le
/// chemin du fichier exécuté, pour AT_EXECFN). Aucune chaîne ne doit
/// contenir d'octet nul. Rend la valeur de RSP au départ.
///
/// Le noyau écrit par la projection directe des cadres
/// (EspaceUtilisateur::ecrire) : l'espace du programme n'a pas besoin
/// d'être actif.
pub fn construire(programme: &mut Programme, argv: &[&[u8]], envp: &[&[u8]], nom: &[u8]) -> Result<u64, Erreur> {
    let sommet = programme.sommet_pile;
    let mut c = Curseur { programme, sp: sommet };

    // Du haut vers le bas : le marqueur de fin, les chaînes, l'aléa.
    c.empiler(&[0; 8])?;
    let execfn = c.chaine(nom)?;
    let mut adresses_envp = [0u64; 32];
    let mut adresses_argv = [0u64; 32];
    if envp.len() > adresses_envp.len() || argv.len() > adresses_argv.len() {
        return Err(Erreur::TropLong);
    }
    for (i, e) in envp.iter().enumerate().rev() {
        adresses_envp[i] = c.chaine(e)?;
    }
    for (i, a) in argv.iter().enumerate().rev() {
        adresses_argv[i] = c.chaine(a)?;
    }
    let plateforme = c.chaine(b"x86_64")?;
    c.sp &= !15;
    let mut alea = [0u8; 16];
    aleatoire::remplir(&mut alea);
    let random = c.empiler(&alea)?;

    // Les tables : argc, argv, envp, auxv, toutes en mots de 8 octets,
    // préparées dans un tableau du noyau puis écrites d'un bloc.
    let p = &*c.programme;
    let auxv: [(u64, u64); 19] = [
        (AT_PHDR, p.adresse_entetes.unwrap_or(0)),
        (AT_PHENT, p.taille_entete as u64),
        (AT_PHNUM, p.nombre_entetes as u64),
        (AT_PAGESZ, 4096),
        // Pas d'interpréteur (ld-linux) : il serait chargé à AT_BASE.
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, p.entree),
        (AT_UID, UTILISATEUR),
        (AT_EUID, UTILISATEUR),
        (AT_GID, GROUPE),
        (AT_EGID, GROUPE),
        // Pas un programme « setuid » : la glibc peut écouter
        // l'environnement (LD_..., MALLOC_...).
        (AT_SECURE, 0),
        (AT_RANDOM, random),
        // Les fonctions du processeur, comme Linux : EDX de CPUID feuille
        // 1 (FPU, TSC, SSE, SSE2...). AT_HWCAP2 : rien (ring3mwait, fsgsbase).
        (AT_HWCAP, core::arch::x86_64::__cpuid(1).edx as u64),
        (AT_HWCAP2, 0),
        (AT_CLKTCK, USER_HZ),
        (AT_PLATFORM, plateforme),
        (AT_EXECFN, execfn),
        (AT_NULL, 0),
    ];
    let mut table = [0u64; 1 + 33 + 33 + 2 * 19];
    let mut n = 0;
    let mut mettre = |valeur: u64| {
        table[n] = valeur;
        n += 1;
    };
    mettre(argv.len() as u64);
    adresses_argv[..argv.len()].iter().for_each(|&a| mettre(a));
    mettre(0);
    adresses_envp[..envp.len()].iter().for_each(|&a| mettre(a));
    mettre(0);
    for (genre, valeur) in auxv {
        mettre(genre);
        mettre(valeur);
    }
    // Ses octets, dans l'ordre du processeur (petit-boutiste).
    let mut octets = [0u8; 8 * (1 + 33 + 33 + 2 * 19)];
    for (i, mot) in table[..n].iter().enumerate() {
        octets[8 * i..8 * i + 8].copy_from_slice(&mot.to_le_bytes());
    }
    let octets = &octets[..8 * n];
    // RSP aligné sur 16 : on place la table pour que son début (argc) le
    // soit.
    let rsp = (c.sp - octets.len() as u64) & !15;
    c.empiler(&[0; 16][..(c.sp - octets.len() as u64 - rsp) as usize])?;
    let debut = c.empiler(octets)?;
    debug_assert_eq!(debut, rsp);
    Ok(rsp)
}
