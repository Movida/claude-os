//! Les signaux d'entrée-sortie (fs/fcntl.c) : le PROPRIÉTAIRE d'un fichier (F_SETOWN et ses
//! variantes), à qui parlent SIGURG (l'octet urgent d'une socket) et SIGIO (O_ASYNC : le fichier
//! a changé, sans que personne attende dedans).
//!
//! Le propriétaire appartient au fichier ouvert, pas au descripteur : `dup` le partage, une fille
//! d'écoute n'en a pas. C'est un objet à part (le `fown_struct`, alloué à la première demande depuis
//! Linux 6.12) : presque aucun fichier n'en a, et une socket a besoin de l'atteindre depuis la
//! réception, qui ne sait rien du fichier. Il retient un numéro, pas un processus : celui-ci peut
//! disparaître, et F_GETOWN rend alors 0 (`pid_task`).
//!
//! O_ASYNC inscrit le fichier dans une liste (la `fasync_list`, `ListeAsync`) de ce qu'il surveille :
//! une par socket, deux par tube (les lecteurs, les écrivains). `tuer` y envoie le signal de chaque
//! inscrit (`kill_fasync`). Par défaut SIGIO, sans rien dire de la raison (SEND_SIG_PRIV) ; avec
//! F_SETSIG, le signal choisi, avec le numéro du descripteur (`si_fd`), et ce qui s'est passé
//! (`si_code`, `si_band`). Un fichier sans liste (fichier ordinaire, eventfd...) accepte O_ASYNC sans
//! le retenir (`setfl` : pas de `fasync`). Le terminal aura la sienne avec lui, en 6k.
//!
//! Depuis où : envoyer un signal prend le verrou de la table des processus et celui du processus. On
//! n'envoie donc jamais sous un verrou que ces chemins connaissent, et la liste ne reste pas
//! verrouillée pendant l'envoi : l'ordre connu est processus, puis fichiers (`vfs`). D'où le tube
//! fermé (`tube::fichier_ferme`, sous le verrou des fichiers), qui signale à la sortie de l'appel.
//! Options écartées : une file de signaux à envoyer, vidée par une tâche (elle arriverait quand
//! l'ordonnanceur la choisit, et il faudrait la place dans la file au moment de l'événement) ; un
//! masque atomique lu au retour vers l'anneau 3 (pas de place pour un `si_fd` et un `si_band`, ni
//! pour un processus qui dort).

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::{Fichier, Prive};
use crate::faillible::VecFaillible;
use crate::partage::Arc;
use crate::signaux::{self, Destinataire, Info};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDBAND, POLLRDNORM, POLLWRBAND, POLLWRNORM};
use crate::verrou::Verrou;
use crate::{processus, tache, vfs};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

const ESRCH: i64 = 3;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
pub const SIGURG: u64 = 23;
pub const SIGIO: u64 = 29;
/// `si_code` d'un signal qui a déjà ses propres codes (`SI_SIGIO`).
const SI_SIGIO: i32 = -5;

/// À qui parle-t-il (PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID) ?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Genre {
    Fil,
    Processus,
    Groupe,
}

#[derive(Clone, Copy)]
struct Qui {
    genre: Genre,
    /// 0 : personne.
    numero: u32,
    /// F_SETSIG ; 0 : SIGIO.
    signal: u32,
    /// Qui l'a posé (`fown->uid`, `euid`) : il faut en avoir le droit quand le signal part. Nous
    /// n'avons qu'un uid par processus.
    uid: u32,
}

/// Le propriétaire d'un fichier (`fown_struct`).
pub struct Proprietaire {
    qui: Verrou<Qui>,
}

/// Le numéro existe-t-il : un processus, ou un fil (`find_vpid`) ?
pub fn numero_existe(numero: u32) -> bool {
    processus::existe(numero) || tache::processus_du_fil(numero).is_some()
}

impl Proprietaire {
    /// Un neuf : personne. ENOMEM s'il n'y a plus de place.
    pub fn neuf() -> Result<Arc<Proprietaire>, i64> {
        // (Le genre d'un fichier auquel on n'a rien demandé : `f_getown_ex` dit F_OWNER_TID.)
        let qui = Verrou::new(Qui { genre: Genre::Fil, numero: 0, signal: 0, uid: 0 });
        Arc::new(Proprietaire { qui }).map_err(|_| -ENOMEM)
    }

    /// `__f_setown` : `numero` 0, personne ; il retient qui le pose. F_SETSIG reste.
    pub fn poser(&self, genre: Genre, numero: u32, uid: u32) {
        let mut q = self.qui.verrouiller();
        q.genre = genre;
        q.numero = numero;
        q.uid = uid;
    }

    /// Le genre et le numéro (le numéro à 0 si plus personne n'y répond : `pid_task`) ; et ce que
    /// retient F_GETOWNER_UIDS.
    pub fn lire(&self) -> (Genre, u32, u32) {
        let q = *self.qui.verrouiller();
        let vivant = match q.genre {
            Genre::Fil => tache::processus_du_fil(q.numero).is_some(),
            // Chaque programme mène son propre groupe (signaux.rs, `kill`).
            Genre::Processus | Genre::Groupe => processus::existe(q.numero),
        };
        (q.genre, if vivant { q.numero } else { 0 }, q.uid)
    }

    pub fn signal(&self) -> u32 {
        self.qui.verrouiller().signal
    }

    pub fn poser_signal(&self, signal: u32) {
        self.qui.verrouiller().signal = signal;
    }

    /// Le signal `sig`, s'il y a qui le prendre (`do_send_sig_info` et `sigio_perm`). Err : la file
    /// des signaux est pleine.
    fn envoyer(q: &Qui, sig: u64, info: Info) -> Result<(), i64> {
        let (pid, a) = match q.genre {
            Genre::Fil => match tache::processus_du_fil(q.numero) {
                Some(pid) => (pid, Destinataire::Fil(q.numero)),
                None => return Ok(()),
            },
            Genre::Processus | Genre::Groupe => (q.numero, Destinataire::Processus),
        };
        signaux::du_proprietaire(pid, a, sig, info, q.uid)
    }

    /// `send_sigurg` : rend vrai s'il y a un propriétaire ; F_SETSIG n'y change rien.
    fn sigurg(&self) -> bool {
        let q = *self.qui.verrouiller();
        if q.numero == 0 {
            return false;
        }
        let _ = Proprietaire::envoyer(&q, SIGURG, Info::du_noyau(SIGURG));
        true
    }

    /// `send_sigio` : le signal choisi avec ses raisons ; sans lui, ou s'il ne peut pas se mettre en
    /// file, SIGIO tout court.
    fn sigio(&self, fd: i32, raison: Raison) {
        let q = *self.qui.verrouiller();
        if q.numero == 0 {
            return;
        }
        if q.signal != 0 {
            let sig = q.signal as u64;
            // Un signal qui a déjà ses propres codes ne les mélange pas à ceux-ci, sauf SIGIO.
            let code = if signaux::a_ses_propres_codes(sig) && sig != SIGIO { SI_SIGIO } else { raison as i32 };
            if Proprietaire::envoyer(&q, sig, Info::entree_sortie(sig, code, raison.bande(), fd)).is_ok() {
                return;
            }
        }
        let _ = Proprietaire::envoyer(&q, SIGIO, Info::du_noyau(SIGIO));
    }
}

/// Ce qui s'est passé (POLL_IN..., `si_code`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Raison {
    Entree = 1,
    Sortie = 2,
    Erreur = 4,
    Prioritaire = 5,
    Coupure = 6,
}

impl Raison {
    /// `band_table`.
    fn bande(self) -> i64 {
        (match self {
            Raison::Entree => POLLIN | POLLRDNORM,
            Raison::Sortie => POLLOUT | POLLWRNORM | POLLWRBAND,
            Raison::Erreur => POLLERR,
            Raison::Prioritaire => POLLPRI | POLLRDBAND,
            Raison::Coupure => POLLHUP | POLLERR,
        }) as i64
    }
}

/// Une inscription O_ASYNC (`fasync_struct`) : le fichier, le descripteur par lequel elle a été
/// demandée (`si_fd`), son propriétaire.
struct Inscrit {
    fichier: Fichier,
    fd: i32,
    proprietaire: Arc<Proprietaire>,
}

/// Ce que dit la réception à `Possession::reveiller`, en plus des événements de `poll` : des bits
/// au-dessus de tous ceux de POLL*.
pub const A_LECTURE: u32 = 1 << 24;
pub const A_COUPURE: u32 = 1 << 25;
pub const A_ETABLIE: u32 = 1 << 26;
pub const A_ERREUR: u32 = 1 << 27;
pub const A_PLACE: u32 = 1 << 28;
pub const A_URGENT: u32 = 1 << 29;
/// L'octet urgent lui-même arrive (`tcp_urg` : `sk_data_ready`).
pub const A_OCTET_URGENT: u32 = 1 << 30;
/// Le FIN, sans que tout soit fini (`tcp_fin` : POLL_IN, en plus de `sk_data_ready`).
pub const A_FIN: u32 = 1 << 31;
pub const A_TOUS: u32 = A_LECTURE | A_COUPURE | A_ETABLIE | A_ERREUR | A_PLACE | A_URGENT | A_OCTET_URGENT | A_FIN;

/// Ce qu'un objet garde de ceux qui veulent un signal (`fasync_list`, et ce que `socket_wq` tient
/// avec : ses SOCKWQ_ASYNC_*).
pub struct ListeAsync {
    inscrits: Verrou<Vec<Inscrit>>,
    /// Sans verrou : presque personne n'a d'inscrit.
    occupee: AtomicBool,
    /// Le propriétaire du fichier d'une socket (`sk->sk_socket->file`), pour SIGURG, qui ne demande
    /// pas O_ASYNC.
    proprietaire: Verrou<Option<Arc<Proprietaire>>>,
    /// Un lecteur attend dans l'appel (SOCKWQ_ASYNC_WAITDATA) : ce qui arrive est pour lui.
    attend_donnees: AtomicBool,
    /// Un écrivain, ou `poll`, a vu qu'il n'y avait plus de place (SOCKWQ_ASYNC_NOSPACE) : sans quoi
    /// la place qui revient ne se dit pas.
    sans_place: AtomicBool,
}

impl ListeAsync {
    pub fn new() -> ListeAsync {
        ListeAsync {
            inscrits: Verrou::new(Vec::new()),
            occupee: AtomicBool::new(false),
            proprietaire: Verrou::new(None),
            attend_donnees: AtomicBool::new(false),
            sans_place: AtomicBool::new(false),
        }
    }

    /// O_ASYNC posé (`fasync_helper`) : inscrit, ou le descripteur mis à jour s'il l'est déjà.
    pub fn inscrire(&self, fichier: Fichier, fd: i32, proprietaire: &Arc<Proprietaire>) -> Result<(), i64> {
        let mut l = self.inscrits.verrouiller();
        if let Some(i) = l.iter_mut().find(|i| i.fichier == fichier) {
            i.fd = fd;
            return Ok(());
        }
        l.ajouter(Inscrit { fichier, fd, proprietaire: proprietaire.clone() }).map_err(|_| -ENOMEM)?;
        self.occupee.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// O_ASYNC retiré, ou le fichier fermé.
    pub fn retirer(&self, fichier: Fichier) {
        let mut l = self.inscrits.verrouiller();
        l.retain(|i| i.fichier != fichier);
        self.occupee.store(!l.is_empty(), Ordering::Relaxed);
    }

    pub fn occupee(&self) -> bool {
        self.occupee.load(Ordering::Relaxed)
    }

    /// `kill_fasync` : `sig` vaut SIGIO ou SIGURG. SIGURG a déjà son envoi à lui : seuls ceux qui ont
    /// choisi un signal en reçoivent un de plus ici. Un inscrit à la fois, la liste rendue pendant
    /// l'envoi (voir l'en-tête) : un autre qui s'inscrit pendant ce temps peut être servi ou non,
    /// comme chez Linux.
    pub fn tuer(&self, sig: u64, raison: Raison) {
        if !self.occupee() {
            return;
        }
        let mut k = 0;
        loop {
            let (p, fd) = {
                let l = self.inscrits.verrouiller();
                let Some(i) = l.get(k) else { return };
                (i.proprietaire.clone(), i.fd)
            };
            if sig != SIGURG || p.signal() != 0 {
                p.sigio(fd, raison);
            }
            k += 1;
        }
    }

    // --- Pour une socket (`sk_wake_async`, `sock_wake_async`) ---

    pub fn poser_proprietaire(&self, p: &Arc<Proprietaire>) {
        *self.proprietaire.verrouiller() = Some(p.clone());
    }

    /// Le fichier de la socket est fermé (`sk->sk_socket` nul) : plus personne à prévenir.
    pub fn fichier_ferme(&self, fichier: Fichier) {
        self.retirer(fichier);
        // (Pas sous le verrou : c'est peut-être la dernière référence.)
        let p = self.proprietaire.verrouiller().take();
        drop(p);
    }

    /// L'octet urgent arrive (`sk_send_sigurg`).
    pub fn urgent(&self) {
        let p = self.proprietaire.verrouiller().clone();
        if p.is_some_and(|p| p.sigurg()) {
            self.tuer(SIGURG, Raison::Prioritaire);
        }
    }

    /// SOCK_WAKE_WAITD : pas si un lecteur attend dans l'appel.
    pub fn lecture(&self, raison: Raison) {
        if !self.attend_donnees.load(Ordering::Relaxed) {
            self.tuer(SIGIO, raison);
        }
    }

    /// SOCK_WAKE_SPACE : seulement si quelqu'un a vu qu'il n'y avait plus de place.
    pub fn place(&self) {
        // SeqCst : la paire de `marquer_sans_place`.
        if self.occupee() && self.sans_place.swap(false, Ordering::SeqCst) {
            self.tuer(SIGIO, Raison::Sortie);
        }
    }

    /// SOCKWQ_ASYNC_NOSPACE effacé : un écrivain va attendre dans l'appel,
    /// la place rendue ne doit pas lui envoyer SIGIO (`sock_wait_for_wmem`).
    pub fn oublier_sans_place(&self) {
        self.sans_place.store(false, Ordering::SeqCst);
    }

    /// SOCK_WAKE_IO.
    pub fn evenement(&self, raison: Raison) {
        self.tuer(SIGIO, raison);
    }

    /// SOCKWQ_ASYNC_NOSPACE : la place manquait ; `encore_sans_place` le
    /// revérifie APRÈS que le drapeau est posé, derrière une barrière
    /// complète (le `set_bit` puis `smp_mb__after_atomic` du `tcp_poll` de
    /// Linux) : celui qui rend de la place sur un autre processeur lit le
    /// drapeau après l'avoir rendue (`place`) ; ou bien il le voit, ou bien
    /// nous voyons sa place, et nous signalons nous-mêmes. Sans cela, la
    /// place rendue entre le constat et le drapeau ne donnait pas de SIGIO.
    pub fn marquer_sans_place(&self, encore_sans_place: impl FnOnce() -> bool) {
        self.sans_place.store(true, Ordering::SeqCst);
        if !encore_sans_place() {
            self.place();
        }
    }

    /// Le temps d'une attente de données dans l'appel (`sk_wait_data`).
    pub fn attendre_donnees(&self, oui: bool) {
        self.attend_donnees.store(oui, Ordering::Relaxed);
    }

    /// Les bits A_* que rend le premier étage de TCP, dans l'ordre de `tcp_rcv_established` :
    /// l'urgent d'abord.
    pub fn evenements(&self, m: u32) {
        if m & A_URGENT != 0 {
            self.urgent();
        }
        if m & A_OCTET_URGENT != 0 {
            self.lecture(Raison::Entree);
        }
        if m & A_LECTURE != 0 {
            self.lecture(Raison::Entree);
        }
        if m & A_FIN != 0 {
            self.lecture(Raison::Entree);
        }
        if m & A_COUPURE != 0 {
            self.lecture(Raison::Coupure);
        }
        if m & A_ETABLIE != 0 {
            self.evenement(Raison::Sortie);
        }
        if m & A_ERREUR != 0 {
            self.evenement(Raison::Erreur);
        }
        if m & A_PLACE != 0 {
            self.place();
        }
    }
}

// --- fcntl (`do_fcntl`) ---

/// Son propriétaire, s'il en a un.
fn existant(f: Fichier) -> Option<Arc<Proprietaire>> {
    vfs::avec_systeme(|s, _| s.ouverts.fichier(f).proprietaire.clone())
}

/// Celui du fichier, fait à la première demande (`file_f_owner_allocate`). Une socket en reçoit une
/// référence : la réception n'atteint pas le fichier.
pub fn du_fichier(f: Fichier) -> Result<Arc<Proprietaire>, i64> {
    if let Some(p) = existant(f) {
        return Ok(p);
    }
    let neuf = Proprietaire::neuf()?;
    Ok(vfs::avec_systeme(|s, _| {
        let o = s.ouverts.fichier(f);
        if let Some(p) = &o.proprietaire {
            return p.clone();
        }
        o.proprietaire = Some(neuf.clone());
        if let Prive::Socket(sk) = &o.prive {
            sk.liste_async().poser_proprietaire(&neuf);
        }
        neuf
    }))
}

fn poser(f: Fichier, genre: Genre, numero: u32) -> i64 {
    if numero != 0 && !numero_existe(numero) {
        return -ESRCH;
    }
    match du_fichier(f) {
        Ok(p) => {
            p.poser(genre, numero, processus::avec(|p| p.identite.uid));
            0
        }
        Err(e) => e,
    }
}

/// F_SETOWN : un numéro de processus, ou négatif, d'un groupe (`f_setown`). Le plus petit entier n'a
/// pas d'opposé.
pub fn f_setown(f: Fichier, qui: i32) -> i64 {
    if qui == i32::MIN {
        return -EINVAL;
    }
    if qui < 0 {
        poser(f, Genre::Groupe, qui.unsigned_abs())
    } else {
        poser(f, Genre::Processus, qui as u32)
    }
}

/// F_GETOWN : celui d'un groupe, négatif ; 0 s'il n'y a personne, ou plus personne.
pub fn f_getown(f: Fichier) -> i64 {
    match existant(f).map(|p| p.lire()) {
        Some((Genre::Groupe, n, _)) => -(n as i64),
        Some((_, n, _)) => n as i64,
        None => 0,
    }
}

const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;

/// F_SETOWN_EX : `struct f_owner_ex { int type; pid_t pid; }`, un fil possible.
pub fn f_setown_ex(f: Fichier, adresse: u64) -> i64 {
    let mut o = [0u8; 8];
    if copier_depuis_utilisateur(&mut o, adresse).is_err() {
        return -EFAULT;
    }
    let genre = match i32::from_le_bytes([o[0], o[1], o[2], o[3]]) {
        F_OWNER_TID => Genre::Fil,
        F_OWNER_PID => Genre::Processus,
        F_OWNER_PGRP => Genre::Groupe,
        _ => return -EINVAL,
    };
    let numero = i32::from_le_bytes([o[4], o[5], o[6], o[7]]);
    if numero < 0 {
        return -ESRCH;
    }
    poser(f, genre, numero as u32)
}

/// F_GETOWN_EX : sans propriétaire, F_OWNER_TID et 0.
pub fn f_getown_ex(f: Fichier, adresse: u64) -> i64 {
    let (genre, numero, _) = existant(f).map_or((Genre::Fil, 0, 0), |p| p.lire());
    let genre = match genre {
        Genre::Fil => F_OWNER_TID,
        Genre::Processus => F_OWNER_PID,
        Genre::Groupe => F_OWNER_PGRP,
    };
    let mut o = [0u8; 8];
    o[..4].copy_from_slice(&genre.to_le_bytes());
    o[4..].copy_from_slice(&numero.to_le_bytes());
    match copier_vers_utilisateur(adresse, &o) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

/// F_GETOWNER_UIDS : `uid_t [2]`, qui a posé le propriétaire (uid et euid) ; 0 sans lui.
pub fn f_getowner_uids(f: Fichier, adresse: u64) -> i64 {
    let uid = existant(f).map_or(0, |p| p.lire().2);
    let mut o = [0u8; 8];
    o[..4].copy_from_slice(&uid.to_le_bytes());
    o[4..].copy_from_slice(&uid.to_le_bytes());
    match copier_vers_utilisateur(adresse, &o) {
        Ok(()) => 0,
        Err(_) => -EFAULT,
    }
}

pub fn f_getsig(f: Fichier) -> i64 {
    existant(f).map_or(0, |p| p.signal() as i64)
}

/// F_SETSIG : 0 à 64 (`valid_signal`).
pub fn f_setsig(f: Fichier, signal: i32) -> i64 {
    if !(0..=64).contains(&signal) {
        return -EINVAL;
    }
    match du_fichier(f) {
        Ok(p) => {
            p.poser_signal(signal as u32);
            0
        }
        Err(e) => e,
    }
}
