//! La faute de page (vecteur 14) : une page absente, ou un accès que son
//! entrée ne permet pas. Le processeur range l'adresse fautive dans CR2 et
//! empile un code d'erreur qui dit ce qui s'est passé (manuel d'Intel,
//! vol. 3A, 4.7).
//!
//! Jusqu'à l'étape 5, une faute de page était toujours une erreur : le
//! programme était arrêté, ou le noyau rendait EFAULT (une copie vers une
//! page absente). Avec la pagination à la demande, c'est la façon normale
//! dont un programme reçoit ses pages : si l'adresse est dans une de ses
//! zones et que la zone permet l'accès, le noyau donne la page et
//! l'instruction reprend (memoire.rs, `servir`). C'est le do_user_addr_fault
//! de Linux (arch/x86/mm/fault.c), dans le même ordre :
//!   1. lire CR2 tout de suite : une autre faute l'écraserait ;
//!   2. un bit réservé dans une entrée (RSVD) : une table abîmée par le
//!      noyau lui-même, on s'arrête ;
//!   3. la faute vient du noyau : voir `faute_du_noyau` ;
//!   4. elle vient du programme : servie si une zone la permet, sinon le
//!      programme est arrêté (SIGSEGV, ou SIGKILL quand la mémoire manque).
//!
//! Depuis 6i, la faute est servie INTERRUPTIONS ACTIVES, comme chez Linux :
//! la porte d'interruption les a coupées en entrant ; on les rouvre pour
//! une faute du programme dès CR2 lu et le bit réservé regardé, et pour une
//! faute du noyau seulement une fois sûr qu'elle sera servie (une copie,
//! une adresse du programme, les contrôles de `faute_du_noyau` passés),
//! comme `do_user_addr_fault`, qui ne les rouvre qu'après ses contrôles ;
//! jamais pour une erreur du noyau, ni pour une adresse du noyau
//! (`do_kern_addr_fault`), qui s'arrête sans laisser tourner personne sur
//! un état faux. Puis la mémoire du processus est prise
//! en lecture : un verrou qui dort (processus::servir_faute), qu'un munmap
//! d'un autre fil peut tenir. La faute peut donc dormir, être préemptée,
//! et laisser passer le tic d'horloge pendant qu'elle met une page à zéro.
//! Avant, sous le verrou du processus, elle les coupait : correct tant
//! qu'elle était courte, mais elle attendait aussi, interruptions coupées,
//! tout ce que les autres fils faisaient de la mémoire.

use crate::copie_utilisateur::{self, SMAP_ACTIF};
use crate::espace_utilisateur::ADRESSE_MAX;
use crate::interruptions::{Cadre, exception_fatale, lire_cr2};
use crate::memoire::{Acces, Echec};
use crate::{cpu, linux, processus, tache};
use core::sync::atomic::Ordering;

// Les bits du code d'erreur d'une faute de page.
/// L'accès était une écriture.
const ECRITURE: u64 = 1 << 1;
/// Un bit réservé est à 1 dans une entrée des tables.
const RESERVE: u64 = 1 << 3;
/// L'accès était la lecture d'une instruction (une page NX, ou une page
/// du programme exécutée par le noyau malgré SMEP).
const INSTRUCTION: u64 = 1 << 4;

/// Le drapeau AC de RFLAGS : avec SMAP, le noyau ne touche une page du
/// programme que s'il vaut 1 (entre `stac` et `clac`).
const AC: u64 = 1 << 18;
/// Le drapeau IF de RFLAGS : le code interrompu avait les interruptions
/// actives.
const IF: u64 = 1 << 9;

/// Appelée par gerer_interruption pour le vecteur 14.
pub fn gerer(cadre: &mut Cadre) {
    let cr2 = lire_cr2();
    let code = cadre.code_erreur;
    if code & RESERVE != 0 {
        exception_fatale(cadre);
    }
    let acces = if code & INSTRUCTION != 0 {
        Acces::Execution
    } else if code & ECRITURE != 0 {
        Acces::Ecriture
    } else {
        Acces::Lecture
    };
    // CR2 et le code lus : pour une faute du programme, les interruptions
    // peuvent revenir (le `local_irq_enable` de `do_user_addr_fault`) ; pour
    // une faute du noyau, voir `faute_du_noyau`. Elles seront coupées de
    // nouveau par `iretq`, qui rend au code interrompu ses drapeaux.
    if cadre.cs & 3 == 3 {
        cpu::activer_interruptions();
        faute_du_programme(cadre, cr2, acces);
    } else {
        faute_du_noyau(cadre, cr2, acces);
    }
}

/// Une faute du programme : servie, ou le programme sera arrêté au retour
/// vers l'anneau 3 (tache.rs), qui suit aussitôt : il ne reprend pas
/// l'instruction fautive.
fn faute_du_programme(cadre: &Cadre, cr2: u64, acces: Acces) {
    // Une adresse de la moitié haute (le noyau), ou la dernière page de la
    // moitié basse : jamais une zone.
    let resultat = if cr2 < ADRESSE_MAX {
        processus::servir_faute(cr2, acces).expect("faute d'un programme sans processus")
    } else {
        Err(Echec::SansZone)
    };
    match resultat {
        Ok(()) => tache::courante().usage().compter_faute(),
        Err(Echec::PlusDeMemoire) => tache::tuer_au_retour(),
        Err(cause) => {
            let zone = processus::memoire_lue(|m| m.zone_du_code(cadre.rip));
            let (signal, raison) = linux::signal_de_l_exception(14, cadre, cr2, Some(cause), zone, 0);
            tache::forcer_par_faute(signal, raison)
        }
    }
}

/// Une faute du noyau. Elle n'est servie que dans une copie depuis ou vers
/// le programme (copie_utilisateur.rs) : l'instruction est dans la table
/// d'exceptions. Une copie que la faute interrompt reprend où elle en
/// était une fois la page en place : `rep movsb` garde dans RCX, RSI et RDI
/// où il en est. Toute autre faute du noyau est une erreur du noyau : on
/// s'arrête.
///
/// Même dans la table, quatre cas ne sont jamais servis ; la copie s'arrête
/// alors à son adresse de reprise, et l'appel système rend EFAULT :
///   - une violation de SMAP : SMAP actif, et le drapeau AC à 0 au moment
///     de la faute (hors de `stac` ... `clac`). La page est présente et
///     permise : la servir ne changerait rien, la faute recommencerait sans
///     fin. C'est le test du démarrage (lire_octet_direct), et la règle de
///     Linux. Cette règle passe avant toute recherche ;
///   - pas de processus en cours : le test du démarrage copie vers un
///     espace créé à la main (main.rs) ;
///   - une adresse qu'aucune zone ne permet ;
///   - une copie faite sans servir de faute (`tache::sans_faute_servie` :
///     la lecture d'un futex sous le verrou de son seau, qui recommence
///     après avoir fait venir la page autrement).
/// Une page qui manque, faute de mémoire, rend aussi EFAULT, et le
/// programme sera tué à son retour (tache::tuer_au_retour).
///
/// Servir la faute prend la mémoire du processus, un verrou qui dort. Dans
/// l'ordre de Linux 6.18 (`do_user_addr_fault`) :
///   - SMAP, puis une copie qui ne fait pas servir ses fautes
///     (`sans_faute_servie`, le `faulthandler_disabled` de Linux), ou pas
///     de processus (le test du démarrage, une tâche du noyau) : EFAULT ;
///   - une copie sous un verrou court, ou sous la mémoire du processus que
///     la tâche tient déjà : on ne peut pas dormir, ou on s'attendrait
///     soi-même. Chaque copie le vérifie déjà (copie_utilisateur.rs, le
///     `__might_fault` de Linux) : arriver ici est une erreur du noyau, on
///     s'arrête en le disant ;
///   - le code interrompu avait coupé les interruptions : de même (Linux
///     l'avertit, « WARN_ON_ONCE(!(regs->flags & X86_EFLAGS_IF)) », et ne
///     sert jamais cette faute) : une copie au milieu d'une section qu'il
///     protège ainsi la couperait en deux en dormant ;
///   - sinon les interruptions reviennent (le code interrompu les avait),
///     et la faute est servie. Une erreur du noyau, elle, s'arrête
///     interruptions coupées.
fn faute_du_noyau(cadre: &mut Cadre, cr2: u64, acces: Acces) {
    let Some(reprise) = copie_utilisateur::reprise(cadre.rip) else {
        exception_fatale(cadre);
    };
    let smap_viole = SMAP_ACTIF.load(Ordering::Relaxed) && cadre.rflags & AC == 0;
    let a_servir = !smap_viole
        && tache::en_service()
        && tache::courante().faute_servie()
        && tache::courante().processus().is_some()
        && cr2 < ADRESSE_MAX
        && acces != Acces::Execution;
    if a_servir {
        let tenus = crate::verrou::tenus();
        assert!(tenus == 0, "faute d'une copie sous {} verrou(s) court(s), a RIP={:#x}", tenus, cadre.rip);
        assert!(!tache::courante().tient_sa_memoire(),
                "faute d'une copie sous le verrou de la memoire de son processus, a RIP={:#x}", cadre.rip);
        assert!(cadre.rflags & IF != 0, "faute d'une copie interruptions coupees, a RIP={:#x}", cadre.rip);
        cpu::activer_interruptions();
    }
    let servie = a_servir
        && match processus::servir_faute(cr2, acces) {
            Some(Ok(())) => true,
            Some(Err(Echec::PlusDeMemoire)) => {
                tache::tuer_au_retour();
                false
            }
            _ => false,
        };
    if servie {
        // Une faute du noyau dans une copie compte pour le programme (le
        // `mm_account_fault` de Linux, getrusage : rusage.rs).
        crate::tache::courante().usage().compter_faute();
    } else {
        cadre.rip = reprise;
    }
}
