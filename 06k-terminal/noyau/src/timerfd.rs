//! timerfd : un minuteur derrière un descripteur. Armé par
//! `timerfd_settime` (une fois, ou périodique), il devient lisible à son
//! échéance ; `read` rend le nombre d'échéances passées depuis la
//! dernière lecture (8 octets), et le remet à zéro. C'est l'autre moitié
//! d'une boucle d'événements bâtie sur epoll (evenements.rs pour
//! eventfd) : libuv, la boucle de Node, en arme un pour ses délais ; Bun
//! (claude) prend le délai d'`epoll_pwait`, mais une bibliothèque qu'il
//! charge peut en vouloir un. Il n'a pas de nom : l'inode anonyme
//! (« anon_inode:[timerfd] »), comme eventfd.
//!
//! Tout se fait comme Linux (fs/timerfd.c, mesuré sous 6.18), sur un
//! minuteur du noyau (minuteurs.rs) dont l'état garde aussi les `ticks`,
//! `expired` et la période (`tintv`) du timerfd, sous le même verrou,
//! comme la `timerfd_ctx` les garde sous celui de sa file :
//!   - à l'échéance, le compte augmente de un et la file est réveillée
//!     (POLLIN) ; un minuteur périodique n'est PAS réarmé là, mais à la
//!     lecture suivante (ou à `timerfd_gettime`, `timerfd_settime`), qui
//!     compte d'un coup toutes les périodes passées (`avancer`) : un
//!     programme qui arme une période d'une microseconde et ne lit jamais
//!     ne fait pas tourner le noyau un million de fois par seconde (« to
//!     avoid DoS attacks specifying a very short timer period ») ;
//!   - les horloges : REALTIME, MONOTONIC, BOOTTIME (sans mise en veille,
//!     BOOTTIME est MONOTONIC), et les deux horloges d'alarme, refusées
//!     (EPERM) : elles demandent de pouvoir réveiller la machine
//!     (CAP_WAKE_ALARM), qu'un programme n'a pas ici. L'échéance est
//!     rangée en temps monotone : une date absolue (REALTIME) est
//!     convertie à l'armement ; la date ne se réglant pas (pas de
//!     `clock_settime`), elle ne diffère du temps monotone que d'un écart
//!     fixe, et TFD_TIMER_CANCEL_ON_SET, accepté, n'annule jamais rien :
//!     c'est ce qu'il ferait sous Linux tant que personne ne règle
//!     l'heure.

use crate::appels_fichiers::{FichierTenu, installer_fichier, tenir};
use crate::attente::{self, Inscription, Sommeil};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur_partiel};
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::minuteurs::{Minuteur, Quoi};
use crate::partage::Arc;
use crate::sondage::{POLLIN, Table};
use crate::tache::Reveil;
use crate::{attente::FileAttente, temps};
use fichiers::montages::Objet;

const EAGAIN: i64 = 11;
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;
const ENOTTY: i64 = 25;
const EPERM: i64 = 1;

const O_RDWR: u32 = 2;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const TFD_TIMER_ABSTIME: u64 = 1;
const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
const CLOCK_REALTIME_ALARM: u64 = 8;
const CLOCK_BOOTTIME_ALARM: u64 = 9;
/// `_IOW('T', 0, u64)` : poser le compte des échéances (CONFIG_CHECKPOINT_RESTORE,
/// pour CRIU, qui recrée un timerfd tel qu'il était).
const TFD_IOC_SET_TICKS: u64 = 0x4008_5400;

/// Un timerfd (la `timerfd_ctx` de Linux) : son minuteur, qui porte sa
/// file d'attente et son état. Fermé, le minuteur est désarmé (le
/// `timerfd_release` de Linux : `Minuteur::drop`).
pub struct TimerFd {
    minuteur: Minuteur,
    /// Son horloge (REALTIME, MONOTONIC ou BOOTTIME), pour la base d'une
    /// échéance absolue.
    horloge: u64,
}

/// timerfd_create(horloge, drapeaux) : TFD_NONBLOCK et TFD_CLOEXEC (les
/// valeurs d'O_NONBLOCK et d'O_CLOEXEC). Dans l'ordre de Linux : un
/// drapeau inconnu ou une horloge sans minuteur, EINVAL ; une horloge
/// d'alarme, EPERM. F_GETFL rendra O_RDWR, plus O_NONBLOCK s'il est
/// demandé (comme eventfd : 0x802).
pub fn timerfd_create(horloge: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    let horloge = horloge as u32 as i32 as i64 as u64;
    let connue = matches!(horloge, temps::CLOCK_REALTIME | temps::CLOCK_MONOTONIC | temps::CLOCK_BOOTTIME
                                   | CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM);
    if drapeaux & !(O_NONBLOCK | O_CLOEXEC) != 0 || !connue {
        return -EINVAL;
    }
    if matches!(horloge, CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM) {
        return -EPERM;
    }
    let Some(minuteur) = Minuteur::nouveau(Quoi::Fichier(FileAttente::new())) else { return -ENOMEM };
    let Ok(t) = Arc::new(TimerFd { minuteur, horloge }) else { return -ENOMEM };
    let mut f = FichierOuvert::new(Sorte::TimerFd, Tenu::Noyau(Objet::Anonyme), true, true,
                                   O_RDWR | (drapeaux & O_NONBLOCK) as u32, b"anon_inode:[timerfd]");
    f.chemin = crate::evenements::nom_anonyme(b"anon_inode:[timerfd]");
    f.prive = Prive::TimerFd(t);
    installer_fichier(f, drapeaux & O_CLOEXEC != 0)
}

/// Le timerfd du descripteur `fd` (`timerfd_fget`) : EBADF s'il n'est pas
/// ouvert (ou s'il l'est en O_PATH, que `fdget` ne voit pas), EINVAL si ce
/// n'est pas un timerfd.
fn timerfd_de(fd: u64) -> Result<FichierTenu, i64> {
    match tenir(fd) {
        Ok(o) if o.sorte == Sorte::Chemin => Err(-EBADF),
        Ok(o) if o.sorte == Sorte::TimerFd => Ok(o),
        Ok(_) => Err(-EINVAL),
        Err(e) => Err(e),
    }
}

/// timerfd_settime(fd, drapeaux, nouvelle, ancienne) : dans l'ordre de
/// Linux, la nouvelle valeur lue (EFAULT), puis les drapeaux et la valeur
/// vérifiés (EINVAL), puis le descripteur (EBADF, EINVAL). L'ancienne
/// valeur est celle d'avant (un périodique échu d'abord avancé, sans
/// compter ses périodes : elles sont perdues avec le réarmement). Puis le
/// minuteur est remis à zéro (compte et échéance effacés) et armé si la
/// première échéance n'est pas nulle : absolue (TFD_TIMER_ABSTIME), dans
/// l'horloge du timerfd, ou relative. L'ancienne valeur s'écrit après :
/// une adresse invalide rend EFAULT, le minuteur armé quand même.
pub fn timerfd_settime(fd: u64, drapeaux: u64, nouvelle: u64, ancienne: u64) -> i64 {
    let mut o = [0u8; 32];
    if copier_depuis_utilisateur(&mut o, nouvelle).is_err() {
        return -EFAULT;
    }
    let drapeaux = drapeaux as u32 as u64;
    let Some((intervalle, valeur)) = temps::lire_itimerspec(&o) else { return -EINVAL };
    if drapeaux & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return -EINVAL;
    }
    let f = match timerfd_de(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let t = f.timerfd();
    let (ancien_intervalle, ancienne_valeur) = {
        let mut m = t.minuteur.verrouiller();
        m.desarmer();
        let maintenant = temps::ns_monotone();
        if m.echu && m.intervalle != 0 {
            let i = m.intervalle;
            m.avancer(maintenant, i);
        }
        let avant = (m.intervalle, m.restant(maintenant));
        m.echu = false;
        m.echus = 0;
        m.intervalle = intervalle;
        m.effacer();
        if valeur != 0 {
            // La base de l'armement (minuteurs.rs) : la date pour un
            // REALTIME absolu ; le temps monotone sinon, un REALTIME
            // relatif compris.
            let echeance = if drapeaux & TFD_TIMER_ABSTIME == 0 {
                m.echeance_relative(maintenant, valeur, 0)
            } else {
                let decalage = if t.horloge == temps::CLOCK_REALTIME { temps::decalage_de_la_date() } else { 0 };
                m.echeance_absolue(valeur, decalage)
            };
            m.armer(echeance);
        }
        avant
    };
    if ancienne != 0 {
        if let Err(e) = temps::ecrire_itimerspec(ancienne, ancien_intervalle, ancienne_valeur) {
            return e;
        }
    }
    0
}

/// timerfd_gettime(fd, valeur) : le descripteur (EBADF, EINVAL), puis la
/// période et le temps restant (nul s'il est désarmé ou échu, une fois),
/// écrits (EFAULT). Un périodique échu est d'abord avancé et réarmé, ses
/// périodes passées comptées (comme à la lecture).
pub fn timerfd_gettime(fd: u64, valeur: u64) -> i64 {
    let f = match timerfd_de(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let (intervalle, restant) = {
        let mut m = f.timerfd().minuteur.verrouiller();
        let maintenant = temps::ns_monotone();
        rearmer_si_echu(&mut m, maintenant);
        (m.intervalle, m.restant(maintenant))
    };
    match temps::ecrire_itimerspec(valeur, intervalle, restant) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Un périodique échu : avancé au-delà de `maintenant`, ses périodes
/// passées ajoutées au compte (moins celle que le tic a déjà comptée), et
/// réarmé.
fn rearmer_si_echu(m: &mut crate::minuteurs::GardeMinuteur<'_>, maintenant: u64) {
    if m.echu && m.intervalle != 0 {
        m.echu = false;
        let i = m.intervalle;
        let periodes = m.avancer(maintenant, i);
        m.echus = m.echus.saturating_add(periodes.saturating_sub(1));
        m.rearmer();
    }
}

impl TimerFd {
    fn file(&self) -> &FileAttente {
        match self.minuteur.quoi() {
            Quoi::Fichier(f) => f,
            // `timerfd_create` lui donne toujours une file.
            Quoi::Alarme(_) | Quoi::Posix(..) => unreachable!("timerfd sans file"),
        }
    }

    /// Le sondage (`timerfd_poll`) : inscrit d'abord dans la file, puis
    /// POLLIN s'il y a des échéances à lire (sans POLLRDNORM, mesuré : 0x1).
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        table.attendre(self.file(), tenu);
        if self.minuteur.verrouiller().echus > 0 { POLLIN } else { 0 }
    }
}

/// read d'un timerfd (`timerfd_read_iter`) : au moins 8 octets en tout,
/// sur tous les morceaux (EINVAL) ; sans échéance à lire, attendre (EAGAIN
/// en non bloquant ; un signal : ERESTARTSYS, EINTR ou refaite,
/// reprise.rs) ; puis le compte pris (un périodique réarmé), et écrit en 8
/// octets, à la suite d'un morceau à l'autre. Comme Linux, le compte est
/// pris avant la copie, et la copie s'arrête à la première faute : elle
/// rend les octets écrits jusque-là, EFAULT si aucun (`copy_to_iter`, pas
/// `copy_to_iter_full` comme eventfd et signalfd) ; le compte est perdu
/// dans les deux cas.
pub fn lire_morceaux(o: &FichierTenu, morceaux: &[(u64, u64)]) -> Result<u64, i64> {
    if morceaux.iter().fold(0u64, |t, &(_, l)| t.saturating_add(l)) < 8 {
        return Err(-EINVAL);
    }
    let t = o.timerfd();
    let non_bloquant = o.drapeaux as u64 & O_NONBLOCK != 0;
    let compte = loop {
        {
            let mut m = t.minuteur.verrouiller();
            if m.echus > 0 {
                let maintenant = temps::ns_monotone();
                rearmer_si_echu(&mut m, maintenant);
                let compte = m.echus;
                m.echus = 0;
                m.echu = false;
                break compte;
            }
        }
        if non_bloquant {
            return Err(-EAGAIN);
        }
        // Sans réveil perdu (attente.rs) : le tic compte l'échéance, puis
        // réveille la file. Un autre lecteur peut prendre le compte entre
        // notre réveil et notre lecture : on attend de nouveau.
        let r = attente::attendre_que(t.file(), Inscription::Ordinaire, Sommeil::Interruptible, None,
                                      || t.minuteur.verrouiller().echus > 0);
        if r == Reveil::Signal {
            return Err(-crate::reprise::ERESTARTSYS);
        }
    };
    let octets = compte.to_le_bytes();
    let mut faits = 0;
    for &(base, longueur) in morceaux {
        let n = (longueur as usize).min(8 - faits);
        let copies = copier_vers_utilisateur_partiel(base, &octets[faits..faits + n]);
        faits += copies;
        if copies < n || faits == 8 {
            break;
        }
    }
    if faits == 0 { Err(-EFAULT) } else { Ok(faits as u64) }
}

/// ioctl d'un timerfd (`timerfd_ioctl`) : TFD_IOC_SET_TICKS pose le compte
/// des échéances (lu : EFAULT ; nul : EINVAL), et réveille qui attend ;
/// toute autre requête : ENOTTY.
pub fn ioctl(o: &FichierTenu, requete: u64, argument: u64) -> i64 {
    if requete != TFD_IOC_SET_TICKS {
        return -ENOTTY;
    }
    let mut v = [0u8; 8];
    if copier_depuis_utilisateur(&mut v, argument).is_err() {
        return -EFAULT;
    }
    let compte = u64::from_le_bytes(v);
    if compte == 0 {
        return -EINVAL;
    }
    let t = o.timerfd();
    t.minuteur.verrouiller().echus = compte;
    t.file().reveiller(POLLIN, 1);
    0
}
