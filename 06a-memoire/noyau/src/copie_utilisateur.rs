//! Les copies entre la mémoire du noyau et celle du programme en cours :
//! le seul chemin par lequel le noyau touche à la mémoire d'un programme
//! (copy_from_user et copy_to_user de Linux).
//!
//! Un appel système reçoit des adresses choisies par le programme, qui
//! peuvent désigner n'importe quoi : la mémoire du noyau, une page absente,
//! une page qui disparaîtra (étape 6 : un autre fil du programme fait
//! munmap pendant l'appel). Deux protections :
//!
//!   1. LES BORNES D'ABORD : toute la plage doit être dans les adresses
//!      des programmes (sous ADRESSE_MAX, le TASK_SIZE_MAX de Linux). En
//!      anneau 0, le bit UTILISATEUR des pages ne protège RIEN : sans cette
//!      vérification, un `write(1, adresse_du_noyau, n)` ferait afficher
//!      au noyau sa propre mémoire. C'est access_ok() dans Linux.
//!
//!   2. LA FAUTE PRÉVUE : dans les bornes, une page peut quand même être
//!      absente. Plutôt que de parcourir les tables avant chaque copie
//!      (lent, et faux dès qu'une autre tâche peut les changer pendant la
//!      copie), on copie directement, par le processeur, et on PRÉVOIT la
//!      faute de page : l'adresse de l'instruction de copie est rangée
//!      dans la TABLE D'EXCEPTIONS (la section __ex_table), avec une
//!      adresse de reprise. Le gestionnaire de faute de page, quand une
//!      faute du noyau tombe sur une instruction de la table, reprend
//!      l'exécution à l'adresse de reprise au lieu de paniquer
//!      (interruptions.rs). La copie s'arrête là, et l'appel rend EFAULT.
//!      C'est le mécanisme de Linux (arch/x86/mm/extable.c), qui servira
//!      aussi à la pagination à la demande : la faute pourra alors être
//!      SERVIE (la page lue sur le disque), et la copie reprendre.
//!
//! Une seule routine, `rep movsb`, pour les deux sens : elle copie RCX
//! octets de [RSI] vers [RDI] ; interrompue par une faute, elle laisse
//! dans RCX le nombre d'octets NON copiés. Sur les processeurs récents
//! (FSRM, depuis 2019), c'est aussi la copie la plus rapide ; Linux la
//! choisit alors. Sur les anciens, une boucle déroulée irait plus vite
//! pour les grosses copies : on verra si ça compte.
//!
//! SMAP (Supervisor Mode Access Prevention, Intel 2014, AMD 2017) : quand
//! le processeur l'a, le noyau ne peut plus toucher une page UTILISATEUR,
//! sauf si le drapeau AC de RFLAGS vaut 1. Une erreur du noyau qui
//! suivrait un pointeur fourni par un programme sans passer par ici fait
//! alors une faute, au lieu de lire ou d'écrire ce que le programme a
//! préparé. La copie ouvre la porte (`stac`, AC = 1) juste avant
//! `rep movsb` et la referme (`clac`) juste après. Sans SMAP, `stac` et
//! `clac` sont des instructions invalides : on les saute, d'après un octet
//! lu à chaque fois (SMAP_ACTIF). Linux, lui, réécrit son propre code au
//! démarrage (les « alternatives ») pour ne garder que les instructions
//! utiles : plus rapide, mais un mécanisme entier pour quelques cycles.
//!
//! Jamais sous un verrou : une copie peut fauter (et, plus tard, attendre
//! le disque). On copie dans un tampon du noyau, puis on s'en sert.

use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::espace_utilisateur::ADRESSE_MAX;

/// SMAP est-il en service ? Lu par l'assembleur (un octet : AtomicBool a
/// la taille et la représentation d'un u8), dans la copie et en tête de
/// chaque talon d'interruption.
#[unsafe(no_mangle)]
pub static SMAP_ACTIF: AtomicBool = AtomicBool::new(false);

/// L'adresse est hors du programme, ou une page est absente (EFAULT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Faute;

global_asm!(
    r#"
    .section .text
    /* copie_brute(destination (rdi), source (rsi), n (rdx)) : rend le
       nombre d'octets NON copiés (0 : tout est copié). */
    .global copie_brute
copie_brute:
    mov rcx, rdx
    cmp byte ptr [rip + SMAP_ACTIF], 0
    je 1f
    stac
1:  cld
2:  rep movsb
3:  cmp byte ptr [rip + SMAP_ACTIF], 0
    je 4f
    clac
4:  mov rax, rcx
    ret

    /* L'entrée de la table d'exceptions : une faute sur `rep movsb` (2)
       reprend à 3, avec dans RCX ce qui restait à copier. */
    .pushsection __ex_table, "a"
    .balign 8
    .quad 2b, 3b
    .popsection

    /* lire_octet_direct(adresse (rdi)) : lit un octet SANS ouvrir SMAP ;
       rend l'octet, ou -1 si la lecture a fait faute. Ne sert qu'à
       vérifier, au démarrage, que SMAP protège vraiment. */
    .global lire_octet_direct
lire_octet_direct:
    xor eax, eax
5:  mov al, [rdi]
    ret
6:  mov rax, -1
    ret
    .pushsection __ex_table, "a"
    .balign 8
    .quad 5b, 6b
    .popsection
    "#
);

unsafe extern "C" {
    fn copie_brute(destination: *mut u8, source: *const u8, n: usize) -> usize;
    fn lire_octet_direct(adresse: u64) -> i64;
    // Les bornes de la table d'exceptions (linker.ld).
    static __debut_ex_table: [u64; 0];
    static __fin_ex_table: [u64; 0];
}

/// La plage [adresse, adresse + n[ est-elle dans les adresses des
/// programmes ? (access_ok de Linux.)
fn dans_les_bornes(adresse: u64, n: usize) -> bool {
    adresse.checked_add(n as u64).is_some_and(|fin| fin <= ADRESSE_MAX)
}

/// Copie `destination.len()` octets depuis l'adresse `source` du programme
/// en cours. En cas de faute, une partie a pu être copiée : le contenu de
/// `destination` n'a alors pas de sens.
pub fn copier_depuis_utilisateur(destination: &mut [u8], source: u64) -> Result<(), Faute> {
    if !dans_les_bornes(source, destination.len()) {
        return Err(Faute);
    }
    // SAFETY : `destination` est à nous ; la source est dans les adresses
    // des programmes (vérifié), lue par `rep movsb` sous la protection de
    // la table d'exceptions : une page absente fait reprendre la copie à
    // son adresse de reprise, jamais une lecture hors des bornes.
    let reste = unsafe { copie_brute(destination.as_mut_ptr(), source as *const u8, destination.len()) };
    if reste == 0 { Ok(()) } else { Err(Faute) }
}

/// Copie `source` à l'adresse `destination` du programme en cours.
pub fn copier_vers_utilisateur(destination: u64, source: &[u8]) -> Result<(), Faute> {
    if !dans_les_bornes(destination, source.len()) {
        return Err(Faute);
    }
    // SAFETY : comme copier_depuis_utilisateur, dans l'autre sens. Les
    // pages du programme en lecture seule font faute (CR0.WP : le noyau
    // respecte les droits des pages).
    let reste = unsafe { copie_brute(destination as *mut u8, source.as_ptr(), source.len()) };
    if reste == 0 { Ok(()) } else { Err(Faute) }
}

/// L'adresse de reprise prévue pour une faute du noyau à l'adresse `rip`,
/// s'il y en a une (search_exception_tables de Linux). La table est petite
/// (une entrée par instruction qui touche la mémoire des programmes) : on
/// la parcourt ; Linux, qui en a des milliers, la trie et cherche par
/// dichotomie.
pub fn reprise(rip: u64) -> Option<u64> {
    // SAFETY : la table est rangée par l'éditeur de liens entre ces deux
    // symboles (linker.ld), en paires d'adresses de 8 octets, en lecture
    // seule.
    let table = unsafe {
        let debut = &raw const __debut_ex_table as *const u64;
        let fin = &raw const __fin_ex_table as *const u64;
        core::slice::from_raw_parts(debut, fin.offset_from(debut) as usize)
    };
    table.chunks_exact(2).find(|e| e[0] == rip).map(|e| e[1])
}

/// Les protections que le processeur offre au noyau contre les programmes,
/// pour l'affichage.
pub struct Protections {
    pub smep: bool,
    pub smap: bool,
    pub umip: bool,
}

/// Met en service SMEP, SMAP et UMIP, si le processeur les a :
///   - SMEP (Supervisor Mode Execution Prevention, CR4 bit 20) : le noyau
///     ne peut pas exécuter une page UTILISATEUR. Une erreur du noyau qui
///     sauterait à une adresse choisie par un programme fait une faute au
///     lieu d'exécuter son code avec les droits du noyau ;
///   - SMAP (CR4 bit 21) : voir plus haut ;
///   - UMIP (User Mode Instruction Prevention, CR4 bit 11) : `sgdt`, `sidt`,
///     `sldt`, `smsw` et `str` deviennent interdits aux programmes. Ils
///     donneraient l'adresse des tables du noyau, une aide pour une
///     attaque. (Linux les imite pour les vieux programmes qui s'en
///     servent ; nous les refusons simplement.)
/// Tous trois sont décrits par CPUID, feuille 7 : SMEP bit 7 et SMAP bit 20
/// d'EBX, UMIP bit 2 d'ECX.
pub fn activer_protections() -> Protections {
    use core::arch::x86_64::__cpuid;
    let a_la_feuille_7 = __cpuid(0).eax >= 7;
    let feuille = if a_la_feuille_7 { __cpuid(7) } else { __cpuid(0) };
    let p = Protections {
        smep: a_la_feuille_7 && feuille.ebx & 1 << 7 != 0,
        smap: a_la_feuille_7 && feuille.ebx & 1 << 20 != 0,
        umip: a_la_feuille_7 && feuille.ecx & 1 << 2 != 0,
    };
    let bits = (p.smep as u64) << 20 | (p.smap as u64) << 21 | (p.umip as u64) << 11;
    // SMAP_ACTIF avant CR4 : dès que SMAP est en service, les talons
    // doivent faire `clac`.
    SMAP_ACTIF.store(p.smap, Ordering::Relaxed);
    // SAFETY : on n'active que ce que CPUID annonce ; le noyau ne touche la
    // mémoire des programmes que par les copies de ce module, et n'exécute
    // jamais leurs pages.
    unsafe {
        asm!("mov {t}, cr4", "or {t}, {bits}", "mov cr4, {t}", t = out(reg) _, bits = in(reg) bits,
             options(nostack));
    }
    p
}

/// SMAP protège-t-il vraiment ? Une lecture directe, sans `stac`, d'une
/// page du programme projetée à `adresse` doit faire faute. (Sans SMAP,
/// elle réussit : rien à vérifier.)
pub fn smap_verifie(adresse: u64) -> bool {
    // SAFETY : la lecture est protégée par la table d'exceptions ;
    // `adresse` est une page projetée de l'espace actif.
    unsafe { lire_octet_direct(adresse) == -1 }
}
