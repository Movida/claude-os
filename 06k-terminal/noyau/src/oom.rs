//! Le tueur OOM (le `out_of_memory` de Linux, mm/oom_kill.c) : quand une
//! page manque vraiment à la faute d'un programme (la réserve du noyau
//! comprise, voir pages.rs et memoire.rs), on tue le programme qui occupe le
//! plus de mémoire, pas forcément celui qui faute.
//!
//! Comme Linux :
//!   - celui qui faute alors qu'il va mourir (un SIGKILL en attente, la fin
//!     de son groupe commencée) meurt lui-même, sans tuer personne : il
//!     rendra bientôt sa mémoire (`task_will_free_mem(current)`) ;
//!   - le plus gros : ses pages en place, anonymes et de fichiers, et ses
//!     tables de pages (`oom_badness` : `get_mm_rss` + tables ; pas de
//!     mémoire d'échange chez nous), lus sans verrou dans ses compteurs
//!     (espace_utilisateur.rs) ; un processus dont la mémoire est déjà
//!     rendue (un zombie, ou un dernier fil qui finit) ne compte pas
//!     (`find_lock_task_mm`) ;
//!   - une seule victime à la fois : tant qu'elle n'a pas rendu sa mémoire,
//!     on n'en choisit pas d'autre (`tsk_is_oom_victim`, « abort ») ;
//!   - si c'est le programme qui faute, il meurt au retour de la faute
//!     (tache::arreter_plus_de_memoire, le message de Linux) ; sinon la
//!     victime reçoit SIGKILL, le noyau le dit (« Out of memory: Killed
//!     process »), et celui qui faute attend qu'elle ait rendu sa mémoire,
//!     puis recommence sa faute (la boucle de l'allocateur de Linux).
//!
//! Ce qui diffère : Linux a un moissonneur (l'`oom_reaper`) qui reprend la
//! mémoire d'une victime sans attendre qu'elle meure, au cas où elle serait
//! bloquée dans le noyau (sur un verrou que tiendrait celui qui faute). Ici,
//! l'attente est bornée à trois secondes (le temps que se donne
//! l'oom_reaper de Linux avant de marquer la victime : OOM_REAPER_DELAY,
//! deux secondes, puis MAX_OOM_REAP_RETRIES essais tous les dixièmes) ;
//! au-delà, la victime est mise de côté (le MMF_OOM_SKIP de Linux, un
//! drapeau de chaque processus : processus::mettre_de_cote) et un autre
//! choix est fait, peut-être celui qui faute. Écarté : un moissonneur à
//! nous, qui prendrait la mémoire d'un autre processus sous son verrou :
//! rien ne le demande tant qu'aucun appel ne dort sans fin sous un verrou
//! que tiendrait une faute (le sommeil « tuable » viendra avec 6m).
//!
//! Avant les soldes d'avant 6k, le programme qui faute était toujours tué :
//! un petit pouvait payer pour un gros, avec plusieurs programmes à la fois
//! (`&`, 6e).

use crate::attente::{self, FileAttente, Inscription, Sommeil};
use crate::{processus, signaux, tache, temps};
use core::sync::atomic::{AtomicU32, Ordering::SeqCst};

/// Le processus en train de mourir pour rendre sa mémoire, 0 s'il n'y en a
/// pas.
static VICTIME: AtomicU32 = AtomicU32::new(0);

/// Ceux qui attendent que la victime ait rendu sa mémoire.
static ATTENTE: FileAttente = FileAttente::new();

/// Ce que doit faire celui qui faute.
pub enum Issue {
    /// Mourir : c'est lui le plus gros (ou il n'y a personne d'autre).
    Mourir,
    /// Recommencer sa faute : une victime rend sa mémoire.
    Recommencer,
}

/// Une page manque à la faute d'un fil du processus `moi` : choisir, tuer,
/// et dire quoi faire. Sans verrou de la mémoire tenu (l'attente dort).
pub fn plus_de_memoire(moi: u32) -> Issue {
    let victime = VICTIME.load(SeqCst);
    if victime == moi || va_mourir() {
        return Issue::Mourir;
    }
    if victime == 0 {
        let Some(c) = processus::le_plus_gros() else {
            return Issue::Mourir;
        };
        if c.pid == moi {
            return Issue::Mourir;
        }
        if VICTIME.compare_exchange(0, c.pid, SeqCst, SeqCst).is_ok() {
            if signaux::tuer_processus(c.pid) {
                afficherln!("[noyau] plus de memoire : {} ({}) tue, le plus gros : anonyme {} Kio, fichiers {} Kio, tables {} Kio",
                            c.nom, c.pid, c.pages * 4, c.pages_fichier * 4, c.tables * 4);
            } else if VICTIME.compare_exchange(c.pid, 0, SeqCst, SeqCst).is_ok() {
                // Parti entre-temps : sa mémoire est déjà rendue. Seulement
                // s'il est encore la victime : un autre fil a pu en choisir
                // une autre depuis.
                ATTENTE.reveiller_toutes();
            }
        }
    }
    // Attendre la victime (celle-ci, ou celle d'un autre fil qui faute en
    // même temps), trois secondes au plus, puis recommencer.
    let attendue = VICTIME.load(SeqCst);
    if attendue != 0 {
        let echeance = temps::ns_monotone() + DELAI;
        let r = attente::attendre_que(&ATTENTE, Inscription::Ordinaire, Sommeil::Ininterruptible, Some(echeance),
                                      || VICTIME.load(SeqCst) != attendue);
        if r == tache::Reveil::Echeance && VICTIME.compare_exchange(attendue, 0, SeqCst, SeqCst).is_ok() {
            processus::mettre_de_cote(attendue);
            afficherln!("[noyau] plus de memoire : {} n'a pas rendu sa memoire en trois secondes, mis de cote", attendue);
            ATTENTE.reveiller_toutes();
        }
    }
    Issue::Recommencer
}

/// Le délai d'une victime pour rendre sa mémoire : OOM_REAPER_DELAY (2 s),
/// puis MAX_OOM_REAP_RETRIES (10) fois HZ/10.
const DELAI: u64 = 3_000_000_000;

/// Le processus courant va-t-il mourir (`task_will_free_mem(current)`) : la
/// fin de son groupe a commencé, ou la mort de son fil est prévue (un
/// SIGKILL en attente) ?
fn va_mourir() -> bool {
    tache::courante().fin_prevue() || processus::essayer_avec(|p| p.fin_de_groupe.is_some()).unwrap_or(false)
}

/// Le processus `pid` vient de rendre sa mémoire (processus::fil_termine) :
/// s'il était la victime, ceux qui l'attendaient recommencent.
pub fn memoire_rendue(pid: u32) {
    if VICTIME.compare_exchange(pid, 0, SeqCst, SeqCst).is_ok() {
        ATTENTE.reveiller_toutes();
    }
}
