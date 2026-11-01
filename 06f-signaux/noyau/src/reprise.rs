//! Reprendre un appel système interrompu par un signal (SA_RESTART,
//! restart_syscall).
//!
//! Un appel qui dort (une lecture qui attend des données, un futex, un
//! sommeil) est réveillé par un signal : il doit rendre la main pour que le
//! signal soit livré. Mais faut-il ensuite rendre EINTR au programme, ou
//! refaire l'appel comme si rien ne s'était passé ? Cela dépend de l'appel,
//! et de ce qui arrive au signal. Comme Linux, l'appel ne décide pas : il
//! rend l'un de quatre codes INTERNES, que le programme ne voit jamais, et
//! la sortie vers l'anneau 3 tranche (`handle_signal` et
//! `arch_do_signal_or_restart`, arch/x86/kernel/signal.c) :
//!   - ERESTARTSYS (512) : refait si le signal n'a pas de gestionnaire, ou
//!     si son gestionnaire a SA_RESTART ; EINTR sinon. Les lectures et
//!     écritures qui attendent, un futex sans délai ;
//!   - ERESTARTNOINTR (513) : toujours refait (clone, interrompu au milieu
//!     de la création d'un fil) ;
//!   - ERESTARTNOHAND (514) : refait sans gestionnaire, EINTR avec (un
//!     sommeil à échéance absolue : le refaire ne change rien) ;
//!   - ERESTART_RESTARTBLOCK (516) : sans gestionnaire, le programme fait
//!     `restart_syscall` (219) au lieu de l'appel, qui reprend ce que le
//!     noyau a gardé pour lui dans le fil (le `restart_block` : un sommeil
//!     relatif devenu échéance absolue, pour ne pas recommencer le délai) ;
//!     EINTR avec un gestionnaire. nanosleep, clock_nanosleep relatif, un
//!     futex à délai.
//! « Refaire » : remettre dans rax le numéro de l'appel (gardé dans le
//! cadre : `code_erreur`, l'orig_ax de Linux), et reculer RIP de 2 octets,
//! la taille de l'instruction `syscall` : le programme la refait en
//! reprenant. Seulement pour le cadre d'un appel système : le cadre d'une
//! interruption (vecteur < 256) porte 0 ou un code d'erreur, et son rax est
//! une valeur du programme, qu'on ne doit pas toucher même si elle vaut -512
//! (un programme peut le faire exprès) ; et pas après rt_sigreturn, qui met
//! orig_ax à -1 (u64::MAX).
//!
//! Sans gestionnaire, un signal qui a réveillé l'appel arrive chez nous
//! quand un signal du processus réveille un fil puis est pris par un autre,
//! ou devient ignoré entre-temps (rt_sigaction) ; chez Linux aussi avec
//! SIGSTOP et SIGCONT.

use crate::appel_systeme::VECTEUR_SYSCALL;
use crate::interruptions::Cadre;
use crate::tache;

pub const ERESTARTSYS: i64 = 512;
pub const ERESTARTNOINTR: i64 = 513;
pub const ERESTARTNOHAND: i64 = 514;
pub const ERESTART_RESTARTBLOCK: i64 = 516;
const EINTR: i64 = 4;
/// restart_syscall.
const RESTART_SYSCALL: u64 = 219;

/// Ce que `restart_syscall` reprendra (le `restart_block` de Linux).
#[derive(Clone, Copy)]
pub enum Reprise {
    /// Un sommeil relatif (nanosleep, clock_nanosleep sans TIMER_ABSTIME),
    /// jusqu'à son échéance devenue absolue : en temps monotone, ou en temps
    /// de calcul du processus (`calcul`) ; le temps restant à écrire en
    /// `reste` s'il est de nouveau interrompu.
    Sommeil { calcul: bool, cible: u64, reste: u64 },
    /// Un futex attendu avec un délai, jusqu'à son échéance absolue (sur
    /// CLOCK_REALTIME si `reelle`).
    Futex { adresse: u64, partage: bool, val: u32, reelle: bool, echeance: i128, bitset: u32 },
}

/// Garde dans le fil courant ce que reprendra `restart_syscall`.
pub fn garder(r: Reprise) {
    tache::courante().garder_reprise(Some(r));
}

/// restart_syscall (219) : reprend l'appel gardé ; sans rien de gardé (un
/// programme qui l'appelle de lui-même, ou après rt_sigreturn, qui l'efface :
/// `do_no_restart_syscall`), EINTR.
pub fn restart_syscall() -> i64 {
    match tache::courante().prendre_reprise() {
        Some(Reprise::Sommeil { calcul, cible, reste }) => crate::linux::reprendre_sommeil(calcul, cible, reste),
        Some(Reprise::Futex { adresse, partage, val, reelle, echeance, bitset }) => {
            crate::futex::reprendre_attente(adresse, partage, val, reelle, echeance, bitset)
        }
        None => -EINTR,
    }
}

/// Le cadre vient-il d'un appel système qu'on peut refaire ?
fn d_un_appel(cadre: &Cadre) -> bool {
    cadre.vecteur == VECTEUR_SYSCALL && cadre.code_erreur != u64::MAX
}

/// Refait l'appel : son numéro dans rax, RIP sur l'instruction `syscall`.
fn refaire(cadre: &mut Cadre, numero: u64) {
    cadre.rax = numero;
    cadre.rip = cadre.rip.wrapping_sub(2);
}

/// Un gestionnaire va être appelé, `sa_restart` s'il a SA_RESTART : l'appel
/// interrompu rend EINTR, ou sera refait (`handle_signal`). Avant que le
/// contexte soit rangé dans le cadre de signal : c'est ce contexte-là qui
/// reviendra après le gestionnaire.
pub fn avant_gestionnaire(cadre: &mut Cadre, sa_restart: bool) {
    if !d_un_appel(cadre) {
        return;
    }
    match -(cadre.rax as i64) {
        ERESTART_RESTARTBLOCK | ERESTARTNOHAND => cadre.rax = -EINTR as u64,
        ERESTARTSYS if !sa_restart => cadre.rax = -EINTR as u64,
        ERESTARTSYS | ERESTARTNOINTR => refaire(cadre, cadre.code_erreur),
        _ => {}
    }
}

/// Le programme repart sans gestionnaire appelé : un appel interrompu est
/// refait, par `restart_syscall` pour ERESTART_RESTARTBLOCK
/// (`arch_do_signal_or_restart`). Aucun code interne ne sort ainsi du noyau.
pub fn sans_gestionnaire(cadre: &mut Cadre) {
    if !d_un_appel(cadre) {
        return;
    }
    match -(cadre.rax as i64) {
        ERESTARTNOHAND | ERESTARTSYS | ERESTARTNOINTR => refaire(cadre, cadre.code_erreur),
        ERESTART_RESTARTBLOCK => refaire(cadre, RESTART_SYSCALL),
        _ => {}
    }
}
