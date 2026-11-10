//! Les verrous de fichiers (fs/locks.c de Linux ; les soldes d'avant 6k :
//! jusque-là, fcntl et flock vérifiaient leur demande, puis l'accordaient
//! toujours, et deux programmes lancés par `&` ne s'excluaient pas).
//!
//! Deux familles, qui s'ignorent l'une l'autre (Linux, depuis 2.0) :
//!   - les verrous de PLAGES d'octets de fcntl (F_SETLK, F_SETLKW,
//!     F_GETLK), de lecture (partagés) ou d'écriture (exclusifs). Leur
//!     PROPRIÉTAIRE est le processus (les verrous « POSIX », le
//!     `files_struct` de Linux : nos fils partagent la table des
//!     descripteurs, comme les siens), ou la description de fichier ouverte
//!     (les verrous « OFD », F_OFD_*, Linux 3.15). Un propriétaire n'est
//!     jamais en conflit avec lui-même : il remplace ses propres verrous, les
//!     fusionne quand ils se touchent et sont du même genre, les coupe
//!     quand une nouvelle demande d'un autre genre (ou F_UNLCK) en recouvre
//!     une partie (`posix_lock_inode`). Les POSIX d'un processus tombent
//!     dès qu'il ferme UN descripteur du fichier, même un autre que celui
//!     du verrou (le défaut célèbre de POSIX, que les OFD corrigent :
//!     `locks_remove_posix`, depuis `filp_close`), et à sa fin ; les OFD,
//!     à la dernière fermeture de leur description (`locks_remove_file`).
//!     F_SETLKW attend ; un processus qui attendrait, de proche en proche,
//!     un verrou qu'il tient : EDEADLK (`posix_locks_deadlock`, dix
//!     maillons au plus ; pas pour les OFD, qui n'ont pas de processus) ;
//!   - les verrous de flock(2), sur tout le fichier, partagés ou exclusifs,
//!     à la description de fichier ouverte ; une conversion (partagé vers
//!     exclusif, ou l'inverse) rend d'abord l'ancien, puis demande le
//!     nouveau, sans rien garantir entre les deux (`flock_lock_inode`).
//!
//! Une seule table pour toute la machine, sous un verrou court, plutôt
//! qu'une liste par inode (le `file_lock_context` de Linux) : il y a peu de
//! verrous à la fois (aucun, le plus souvent : la fermeture d'un
//! descripteur le voit sans prendre le verrou, `OCCUPEE`), et nos inodes
//! n'ont pas de structure où l'attacher (un objet de chaque système de
//! fichiers). Une seule file d'attente aussi, réveillée à chaque verrou
//! rendu ou réduit, chacun revoyant sa demande, plutôt que la liste des
//! demandes bloquées par chaque verrou (`fl_blocked_requests`) : les
//! attentes sont rares, et chacune revoit sa demande sous le verrou de la
//! table. Option écartée : les verrous obligatoires (mandatory locking),
//! retirés de Linux en 5.15.

use crate::attente::{self, FileAttente, Sommeil};
use crate::descripteurs::Fichier;
use crate::faillible::VecFaillible;
use crate::tache::Reveil;
use crate::verrou::Verrou;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use fichiers::montages::Objet;

const EAGAIN: i64 = 11;
const EDEADLK: i64 = 35;
const ENOLCK: i64 = 37;

/// La plus grande position d'un verrou (l'OFFSET_MAX de Linux) : une
/// longueur nulle verrouille jusque-là, « jusqu'à la fin, même plus tard ».
pub const POSITION_MAX: u64 = i64::MAX as u64;

/// Le propriétaire d'un verrou de plage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proprietaire {
    /// Un processus (son pid) : les verrous POSIX.
    Processus(u32),
    /// Une description de fichier ouverte : les verrous OFD.
    Fichier(Fichier),
}

/// Un verrou de plage, ou une demande : [debut, fin], fin comprise.
#[derive(Clone, Copy, Debug)]
pub struct Plage {
    pub objet: Objet,
    pub proprietaire: Proprietaire,
    pub ecriture: bool,
    pub debut: u64,
    pub fin: u64,
}

impl Plage {
    fn recouvre(&self, autre: &Plage) -> bool {
        self.objet == autre.objet && self.debut <= autre.fin && autre.debut <= self.fin
    }

    /// `posix_locks_conflict` : sur le même objet, d'un autre propriétaire,
    /// des plages qui se recouvrent, et au moins une écriture.
    fn en_conflit(&self, autre: &Plage) -> bool {
        self.proprietaire != autre.proprietaire && self.recouvre(autre) && (self.ecriture || autre.ecriture)
    }
}

/// Un verrou de flock : tout l'objet, pour une description de fichier.
#[derive(Clone, Copy)]
struct Flock {
    objet: Objet,
    fichier: Fichier,
    exclusif: bool,
}

struct Table {
    /// Groupées par objet et propriétaire, chaque groupe trié par début
    /// (l'ordre de la liste `flc_posix` de Linux, que suit F_GETLK).
    plages: Vec<Plage>,
    flocks: Vec<Flock>,
    /// Les demandes POSIX qui attendent : qui attend, et qui tient le
    /// verrou qu'il attend (le `blocked_hash` et son `fl_blocker`), pour
    /// EDEADLK.
    attentes: Vec<(Proprietaire, Proprietaire)>,
}

static TABLE: Verrou<Table> = Verrou::new(Table { plages: Vec::new(), flocks: Vec::new(), attentes: Vec::new() });
/// Y a-t-il un verrou (une plage ou un flock) ? Lu sans le verrou par les
/// fermetures : sans verrou, rien à faire (le `i_flctx` nul de Linux).
static OCCUPEE: AtomicBool = AtomicBool::new(false);
/// Compte chaque verrou rendu ou réduit : qui attend revoit sa demande
/// quand il a changé.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static ATTENTE: FileAttente = FileAttente::new();

impl Table {
    fn conflit(&self, d: &Plage) -> Option<Plage> {
        self.plages.iter().find(|p| d.en_conflit(p)).copied()
    }

    /// EDEADLK : le propriétaire de `bloquant` attend-il, de proche en
    /// proche, `demandeur` ? Dix maillons au plus, comme Linux
    /// (MAX_DEADLK_ITERATIONS) : au-delà, on attend.
    fn interblocage(&self, demandeur: Proprietaire, mut bloquant: Proprietaire) -> bool {
        for _ in 0..=10 {
            let Some(&(_, suivant)) = self.attentes.iter().find(|(qui, _)| *qui == bloquant) else { return false };
            if suivant == demandeur {
                return true;
            }
            bloquant = suivant;
        }
        false
    }

    /// Applique la demande `d` (de son propriétaire, sans conflit avec
    /// personne : vérifié avant) : ses verrous du même genre qui touchent
    /// la plage s'y fondent, ceux d'un autre genre qui la recouvrent sont
    /// coupés ; puis la plage, si ce n'est pas F_UNLCK (`ecriture` : None).
    /// La place d'abord : un verrou coupé en deux, et le nouveau (ENOLCK
    /// sinon, rien n'a changé). Vrai si un verrou a été rendu ou réduit.
    fn appliquer(&mut self, d: &Plage, genre: Option<bool>) -> Result<bool, i64> {
        self.plages.try_reserve(2).map_err(|_| -ENOLCK)?;
        // La place du groupe dans la table, gardée même s'il se vide le
        // temps de fondre ou de couper : Linux change ses verrous EN PLACE
        // dans sa liste, et F_GETLK rend le premier qui gêne dans cet ordre
        // (la relecture des soldes). Les retraits sont tous à cet indice ou
        // après : il reste juste.
        let ancre = self.plages.iter().position(|q| q.objet == d.objet && q.proprietaire == d.proprietaire);
        let (mut debut, mut fin) = (d.debut, d.fin);
        let mut reduit = false;
        let mut i = 0;
        while i < self.plages.len() {
            let p = self.plages[i];
            if p.objet != d.objet || p.proprietaire != d.proprietaire {
                i += 1;
                continue;
            }
            let touche = p.debut <= d.fin.saturating_add(1) && d.debut <= p.fin.saturating_add(1);
            if genre == Some(p.ecriture) && touche {
                debut = debut.min(p.debut);
                fin = fin.max(p.fin);
                self.plages.remove(i);
                continue;
            }
            if p.debut <= d.fin && d.debut <= p.fin {
                self.plages.remove(i);
                reduit = true;
                if p.debut < d.debut {
                    self.inserer(Plage { fin: d.debut - 1, ..p }, ancre);
                }
                if p.fin > d.fin {
                    self.inserer(Plage { debut: d.fin + 1, ..p }, ancre);
                }
                // Les morceaux insérés sont triés : la recherche reprend du
                // début du groupe, sans les revoir (ils ne recouvrent plus
                // la demande).
                i = 0;
                continue;
            }
            i += 1;
        }
        if let Some(ecriture) = genre {
            self.inserer(Plage { ecriture, debut, fin, ..*d }, ancre);
        }
        Ok(reduit)
    }

    /// Insère `p` dans son groupe (objet, propriétaire), trié par début ; un
    /// groupe vidé à sa place d'avant (`ancre`), un groupe neuf à la fin. La
    /// place est réservée (`appliquer`).
    fn inserer(&mut self, p: Plage, ancre: Option<usize>) {
        let meme = |q: &Plage| q.objet == p.objet && q.proprietaire == p.proprietaire;
        let i = match self.plages.iter().position(meme) {
            Some(premier) => {
                self.plages[premier..].iter().position(|q| !meme(q) || q.debut > p.debut).map_or(self.plages.len(), |k| premier + k)
            }
            None => ancre.unwrap_or(self.plages.len()).min(self.plages.len()),
        };
        self.plages.inserer_dans_la_place(i, p);
    }

    /// OCCUPEE suit la table ; une liste vide rend sa mémoire (le contrôle
    /// « memoire rendue » des programmes le verrait).
    fn mettre_a_jour(&mut self) {
        for v in [&mut self.plages as &mut dyn Vide, &mut self.flocks, &mut self.attentes] {
            v.rendre_si_vide();
        }
        OCCUPEE.store(!self.plages.is_empty() || !self.flocks.is_empty(), Ordering::Relaxed);
    }
}

/// Une liste qui rend sa mémoire quand elle est vide.
trait Vide {
    fn rendre_si_vide(&mut self);
}

impl<T> Vide for Vec<T> {
    fn rendre_si_vide(&mut self) {
        if self.is_empty() {
            *self = Vec::new();
        }
    }
}

/// Réveille qui attend, après qu'un verrou a été rendu ou réduit (hors du
/// verrou de la table).
fn reveiller() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
    ATTENTE.reveiller(0, 0);
}

/// Attend que la table change (un verrou rendu ou réduit) depuis `vue` ;
/// un signal : ERESTARTSYS (F_SETLKW et flock sont repris avec SA_RESTART,
/// signal(7)).
fn attendre(vue: u64) -> Result<(), i64> {
    match attente::attendre_que(&ATTENTE, attente::Inscription::Ordinaire, Sommeil::Interruptible, None,
                                || GENERATION.load(Ordering::SeqCst) != vue) {
        Reveil::Signal => Err(-crate::reprise::ERESTARTSYS),
        _ => Ok(()),
    }
}

/// F_GETLK, F_OFD_GETLK : le premier verrou qui empêcherait la demande
/// `d` (`posix_test_lock`), s'il y en a un. F_OFD_GETLK de F_UNLCK
/// (`deverrouiller`, Linux 6.10) : le premier verrou du MÊME propriétaire
/// qui recouvre la plage (« F_UNLCK checks any locks on the same fd »).
pub fn tester(d: &Plage, deverrouiller: bool) -> Option<Plage> {
    let t = TABLE.verrouiller();
    if deverrouiller {
        return t.plages.iter().find(|p| p.proprietaire == d.proprietaire && d.recouvre(p)).copied();
    }
    t.conflit(d)
}

/// F_SETLK, F_SETLKW et leurs OFD : pose (`genre` : Some(ecriture)) ou
/// rend (None) la plage `d`. Un conflit : EAGAIN sans `attendre` ; sinon
/// EDEADLK pour un processus qui s'attendrait lui-même, ou l'attente.
pub fn poser(d: &Plage, genre: Option<bool>, attendre_le_verrou: bool) -> Result<(), i64> {
    let demande = Plage { ecriture: genre.unwrap_or(false), ..*d };
    loop {
        let vue = GENERATION.load(Ordering::SeqCst);
        let mut t = TABLE.verrouiller();
        if genre.is_some()
            && let Some(c) = t.conflit(&demande)
        {
            if !attendre_le_verrou {
                return Err(-EAGAIN);
            }
            let posix = matches!(d.proprietaire, Proprietaire::Processus(_));
            if posix && t.interblocage(d.proprietaire, c.proprietaire) {
                return Err(-EDEADLK);
            }
            if posix {
                t.attentes.ajouter((d.proprietaire, c.proprietaire)).map_err(|_| -ENOLCK)?;
            }
            drop(t);
            let r = attendre(vue);
            if posix {
                let mut t = TABLE.verrouiller();
                if let Some(i) = t.attentes.iter().position(|&a| a == (d.proprietaire, c.proprietaire)) {
                    t.attentes.swap_remove(i);
                }
                t.mettre_a_jour();
            }
            r?;
            continue;
        }
        let reduit = t.appliquer(&demande, genre)?;
        t.mettre_a_jour();
        drop(t);
        if reduit || genre != Some(true) {
            reveiller();
        }
        return Ok(());
    }
}

/// flock(2) sur l'objet `objet` par la description `fichier` : LOCK_SH
/// (`exclusif` faux), LOCK_EX, ou LOCK_UN (`genre` : None). Une conversion
/// rend d'abord l'ancien verrou (les autres sont réveillés), puis demande
/// le nouveau. Un conflit : EWOULDBLOCK (EAGAIN) avec LOCK_NB, sinon
/// l'attente.
pub fn flock(objet: Objet, fichier: Fichier, genre: Option<bool>, attendre_le_verrou: bool) -> Result<(), i64> {
    {
        let mut t = TABLE.verrouiller();
        let i = t.flocks.iter().position(|f| f.objet == objet && f.fichier == fichier);
        if let Some(i) = i {
            if genre == Some(t.flocks[i].exclusif) {
                return Ok(());
            }
            t.flocks.swap_remove(i);
            t.mettre_a_jour();
        }
        drop(t);
        if i.is_some() {
            reveiller();
        }
    }
    let Some(exclusif) = genre else { return Ok(()) };
    loop {
        let vue = GENERATION.load(Ordering::SeqCst);
        let mut t = TABLE.verrouiller();
        let conflit = t.flocks.iter().any(|f| f.objet == objet && f.fichier != fichier && (f.exclusif || exclusif));
        if !conflit {
            t.flocks.ajouter(Flock { objet, fichier, exclusif }).map_err(|_| -ENOLCK)?;
            t.mettre_a_jour();
            return Ok(());
        }
        if !attendre_le_verrou {
            return Err(-EAGAIN);
        }
        drop(t);
        attendre(vue)?;
    }
}

/// Le processus `pid` ferme un descripteur de l'objet `objet` : tous ses
/// verrous POSIX sur lui tombent (`locks_remove_posix`).
pub fn fermeture(pid: u32, objet: Objet) {
    retirer(|p| p.proprietaire == Proprietaire::Processus(pid) && p.objet == objet, |_| false);
}

/// La dernière référence à la description `fichier` s'en va (`__fput`,
/// `locks_remove_file`) : ses verrous OFD et son flock tombent. Sous le
/// verrou des fichiers (descripteurs.rs, `Ouverts::lacher`) : avant que
/// sa case ne puisse resservir à une autre description.
pub fn derniere_fermeture(fichier: Fichier) {
    retirer(|p| p.proprietaire == Proprietaire::Fichier(fichier), |f| f.fichier == fichier);
}

/// Le processus `pid` finit : ses verrous POSIX tombent, sur tous les
/// objets (ses descripteurs sont fermés : chacun l'aurait fait).
pub fn fin_du_processus(pid: u32) {
    retirer(|p| p.proprietaire == Proprietaire::Processus(pid), |_| false);
}

fn retirer(plage: impl Fn(&Plage) -> bool, flock: impl Fn(&Flock) -> bool) {
    if !OCCUPEE.load(Ordering::Relaxed) {
        return;
    }
    let mut t = TABLE.verrouiller();
    let avant = t.plages.len() + t.flocks.len();
    t.plages.retain(|p| !plage(p));
    t.flocks.retain(|f| !flock(f));
    let retires = avant != t.plages.len() + t.flocks.len();
    t.mettre_a_jour();
    drop(t);
    if retires {
        reveiller();
    }
}
