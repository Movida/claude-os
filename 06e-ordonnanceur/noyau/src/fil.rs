//! Les fils d'un processus : ce qui est à chacun d'eux, et pas au processus
//! qu'ils partagent.
//!
//! Un processus Linux est un GROUPE DE FILS (le « thread group ») qui
//! partagent tout ce qui fait le programme : sa mémoire, ses descripteurs,
//! son dossier courant, son identité, ses limites, l'action de chaque
//! signal, les signaux envoyés au processus. Chaque fil a, lui, ce qui fait
//! une exécution : son numéro (le tid ; celui du fil principal est le pid),
//! son nom (le `comm`), ses registres, sa pile noyau, son état x87/SSE et
//! sa base de FS, son temps de calcul (tout cela dans sa tâche, tache.rs),
//! et, ici, ce qui touche aux signaux : son masque, les signaux envoyés à
//! lui seul (tkill, une faute), sa pile de secours.
//!
//! Le partage, ligne par ligne (le tableau de la section 4 du plan de 6e) :
//!
//! | Au processus (partagé par ses fils)      | Au fil                       |
//! |------------------------------------------|------------------------------|
//! | pid, mémoire, descripteurs, dossiers,    | tid, nom, état, pile noyau,  |
//! | umask, identité, limites                 | registres, x87/SSE, base FS  |
//! | actions des signaux, signaux envoyés au  | masque, signaux envoyés au   |
//! | processus, fin de groupe et son code     | fil, pile de secours, signal |
//! |                                          | forcé d'une faute            |
//! | temps de calcul de tous ses fils         | temps de calcul              |
//!
//! Les `Fil` d'un processus sont rangés DANS le processus (`Processus::fils`),
//! sous son verrou : c'est le `siglock` de Linux, un seul verrou pour les
//! actions, les signaux du processus, et le masque et les signaux de chacun
//! de ses fils (envoyer un signal au processus, c'est choisir un fil qui ne
//! le bloque pas : il faut voir les deux ensemble). La liste sert aussi de
//! liste des fils du groupe (le `thread_head` de Linux), pour réveiller,
//! arrêter (exit_group) ou montrer (/proc/<pid>/task) chacun d'eux.
//! Options écartées :
//!   - l'état des signaux du fil dans sa tâche, sous un verrou à elle : deux
//!     verrous à prendre dans le bon ordre pour chaque signal, sans rien
//!     gagner (un fil ne change son masque qu'en appel système, où il prend
//!     de toute façon celui du processus) ;
//!   - le même dans sa tâche, mais protégé par le verrou du processus
//!     (exactement Linux) : en Rust, une cellule que garde le verrou d'un
//!     autre objet demande du code `unsafe` à chaque accès, et un noyau qui
//!     le réserve au matériel ne le veut pas.
//!
//! Les processus d'un seul fil gardent leur comportement : jusqu'au commit
//! des fils (clone), chaque processus n'a que son fil principal.

use alloc::sync::{Arc, Weak};

use crate::processus;
use crate::signaux::SignauxDuFil;
use crate::tache::{self, Tache};

/// Un fil d'un processus, vu du processus.
pub struct Fil {
    /// Son numéro (le tid) : celui de sa tâche.
    pub tid: u32,
    /// Sa tâche, pour la réveiller (un signal) : un lien faible, pour que le
    /// processus et ses tâches ne se tiennent pas l'un l'autre (une tâche
    /// tient son processus). Il ne sert que tant que le fil est dans la
    /// liste : sa tâche l'en retire en mourant.
    pub tache: Weak<Tache>,
    /// Son masque, ses signaux, sa pile de secours (signaux.rs).
    pub signaux: SignauxDuFil,
}

impl Fil {
    /// Le fil de la tâche `t`, sans signal bloqué ni en attente ni pile de
    /// secours (comme le fil principal d'un programme qui commence).
    pub fn de(t: &Arc<Tache>) -> Fil {
        Fil { tid: t.tid(), tache: Arc::downgrade(t), signaux: SignauxDuFil::default() }
    }
}

/// Exécute `f` sur le fil courant, sous le verrou de son processus (il y en
/// a toujours un pendant un appel système d'un programme Linux) : court, et
/// sans copie vers ou depuis le programme, comme `processus::avec`.
pub fn avec<R>(f: impl FnOnce(&mut Fil) -> R) -> R {
    let tid = tache::courante().tid();
    processus::avec(|p| f(p.fil(tid).expect("appel systeme d'un fil qui a quitte son processus")))
}
