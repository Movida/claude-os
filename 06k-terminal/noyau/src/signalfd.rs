//! signalfd : des signaux lus comme un fichier. Un programme bloque les
//! signaux qui l'intéressent (ils ne sont plus livrés à un gestionnaire),
//! et les lit par un descripteur : `read` rend, pour chacun, ses 128
//! octets de `signalfd_siginfo` (qui l'a envoyé, pourquoi), et le retire
//! de l'attente. C'est le troisième fichier d'une boucle d'événements
//! bâtie sur epoll, avec eventfd (evenements.rs) et timerfd (timerfd.rs) :
//! un signal y devient un événement comme un autre, sans gestionnaire
//! qui interrompt n'importe quelle instruction (libuv, la boucle de Node,
//! prend ainsi SIGCHLD et SIGWINCH). Il n'a pas de nom : l'inode anonyme
//! (« anon_inode:[signalfd] »), comme eventfd.
//!
//! Tout se fait comme Linux (fs/signalfd.c, mesuré sous 6.18 :
//! linux/signaux.c, la partie signalfd) :
//!   - le fichier ne garde que son MASQUE (la `signalfd_ctx`), sans
//!     SIGKILL ni SIGSTOP, qu'aucun programme ne prend ; les signaux lus
//!     sont ceux de QUI LIT, pas de qui l'a créé : le fil qui lit prend les
//!     siens, puis ceux de son processus (`signaux::prendre_pour_signalfd`,
//!     le `dequeue_signal` de Linux, avec les minuteurs POSIX réarmés et
//!     les siginfo périmés jetés). Un signalfd passé à un autre processus
//!     (SCM_RIGHTS) y lit les signaux de cet autre processus ;
//!   - on n'y attend pas dans une file du fichier, mais dans celle du
//!     PROCESSUS de qui attend (`Signaux::file_signalfd`, le `signalfd_wqh`
//!     de la `sighand_struct`), que réveille chaque signal mis en attente,
//!     quel que soit son numéro : un signalfd réveillé pour un signal hors
//!     de son masque revoit le sien, et se rendort. Un epoll s'inscrit dans
//!     celle du processus qui l'ajoute ; s'il est transmis à un autre
//!     processus, qui survit au premier, l'élément y reste inscrit, et
//!     l'entrée tient la file (attente.rs, `FileVisee::Partagee`) : un
//!     dernier réveil, POLLFREE, quand le premier finit, puis plus rien,
//!     comme Linux ;
//!   - `read` demande au moins 128 octets (EINVAL), et rend autant de
//!     signaux que le tampon en tient, mais n'attend que le premier ; un
//!     signal dont la copie échoue est perdu (comme Linux, qui le prend
//!     avant de le copier) ;
//!   - signalfd et signalfd4 sur un signalfd existant n'en changent que le
//!     masque, et réveillent qui attend : il revoit l'attente avec le
//!     nouveau masque. Les drapeaux, vérifiés, ne s'appliquent qu'à la
//!     création.
//! Ni write (EINVAL), ni ioctl à lui (ENOTTY), ni position (lseek rend 0,
//! pread ESPIPE). Ce que Linux montre en plus, son masque dans
//! /proc/<pid>/fdinfo/<fd> (« sigmask: »), attend /proc/<pid>/fdinfo, que
//! nous n'avons pour aucun fichier.

use crate::appels_fichiers::{FichierTenu, installer_fichier, tenir};
use crate::attente::{self, Inscription, Sommeil};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::partage::Arc;
use crate::sondage::{POLLIN, Table};
use crate::signaux::{self, IMBLOQUABLES, Info};
use crate::tache::{self, Reveil};
use crate::processus;
use core::sync::atomic::{AtomicU64, Ordering};
use fichiers::montages::Objet;

const EAGAIN: i64 = 11;
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;

const O_RDWR: u32 = 2;
/// SFD_NONBLOCK et SFD_CLOEXEC : les valeurs d'O_NONBLOCK et d'O_CLOEXEC.
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
/// La taille d'un `signalfd_siginfo`.
const TAILLE: u64 = 128;

/// Un signalfd (la `signalfd_ctx` de Linux) : les signaux qu'il prend.
/// Un atomique : signalfd4 le change pendant qu'un autre fil lit ; une
/// lecture prend l'ancien masque ou le nouveau, jamais un mélange.
pub struct SignalFd {
    masque: AtomicU64,
}

/// signalfd(fd, masque, taille) : signalfd4 sans drapeaux.
pub fn signalfd(fd: u64, masque: u64, taille: u64) -> i64 {
    signalfd4(fd, masque, taille, 0)
}

/// signalfd4(fd, masque, taille, drapeaux), dans l'ordre de Linux : la
/// taille du masque (8, sinon EINVAL), le masque lu (EFAULT), les drapeaux
/// (SFD_NONBLOCK, SFD_CLOEXEC ; un autre : EINVAL). Puis, pour fd = -1, un
/// signalfd neuf (O_RDWR, plus O_NONBLOCK s'il est demandé) ; sinon le
/// signalfd `fd` (fermé ou en O_PATH, EBADF ; un autre fichier, EINVAL)
/// prend le nouveau masque, et `fd` est rendu.
pub fn signalfd4(fd: u64, masque: u64, taille: u64, drapeaux: u64) -> i64 {
    if taille != 8 {
        return -EINVAL;
    }
    let mut o = [0u8; 8];
    if copier_depuis_utilisateur(&mut o, masque).is_err() {
        return -EFAULT;
    }
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & !(O_NONBLOCK | O_CLOEXEC) != 0 {
        return -EINVAL;
    }
    let masque = u64::from_le_bytes(o) & !IMBLOQUABLES;
    // Un int pour Linux : seul -1 crée ; les autres numéros négatifs ne
    // désignent aucun descripteur.
    let fd = fd as u32;
    if fd as i32 == -1 {
        let Ok(s) = Arc::new(SignalFd { masque: AtomicU64::new(masque) }) else { return -ENOMEM };
        let mut f = FichierOuvert::new(Sorte::SignalFd, Tenu::Noyau(Objet::Anonyme), true, true,
                                       O_RDWR | (drapeaux & O_NONBLOCK) as u32, b"anon_inode:[signalfd]");
        f.chemin = crate::evenements::nom_anonyme(b"anon_inode:[signalfd]");
        f.prive = Prive::SignalFd(s);
        return installer_fichier(f, drapeaux & O_CLOEXEC != 0);
    }
    let f = match tenir(fd as u64) {
        Ok(f) if f.sorte == Sorte::Chemin => return -EBADF,
        Ok(f) if f.sorte == Sorte::SignalFd => f,
        Ok(_) => return -EINVAL,
        Err(e) => return e,
    };
    // Sous le verrou du processus, comme Linux sous le `siglock` ; puis
    // ceux qui attendent revoient l'attente avec le nouveau masque.
    let file = processus::avec(|p| {
        f.signalfd().masque.store(masque, Ordering::Relaxed);
        p.signaux.file_signalfd.clone()
    });
    file.reveiller_une();
    fd as i64
}

impl SignalFd {
    fn masque(&self) -> u64 {
        self.masque.load(Ordering::Relaxed)
    }

    /// Le sondage (`signalfd_poll`) : inscrit d'abord dans la file des
    /// signaux du processus de qui sonde, puis POLLIN si un signal du
    /// masque attend ce fil (sans POLLRDNORM, mesuré : 0x1).
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        let tid = tache::courante().tid();
        let file = processus::avec(|p| p.signaux.file_signalfd.clone());
        table.attendre_partagee(&file, tenu);
        if processus::avec(|p| signaux::en_attente_parmi(p, tid, self.masque())) { POLLIN } else { 0 }
    }
}

/// Un signal du masque de `s`, pris pour le fil courant (`signalfd_dequeue`)
/// : tout de suite, ou en attendant s'il n'y en a pas et que la lecture est
/// bloquante (EAGAIN sinon). L'attente, dans la file des signaux du
/// processus (sans réveil perdu : attente.rs), finit quand un signal du
/// masque est pris ; ou sur un signal à livrer (ERESTARTSYS : EINTR, ou
/// l'appel refait, reprise.rs), APRÈS avoir essayé de prendre (un signal du
/// masque qui n'est pas bloqué est lu, pas livré).
fn prendre(s: &SignalFd, non_bloquant: bool) -> Result<Info, i64> {
    let tid = tache::courante().tid();
    if let Some(info) = processus::avec(|p| signaux::prendre_pour_signalfd(p, tid, s.masque())) {
        return Ok(info);
    }
    if non_bloquant {
        return Err(-EAGAIN);
    }
    let file = processus::avec(|p| p.signaux.file_signalfd.clone());
    let mut pris = None;
    let r = attente::attendre_que(&file, Inscription::Ordinaire, Sommeil::Interruptible, None, || {
        pris = processus::avec(|p| signaux::prendre_pour_signalfd(p, tid, s.masque()));
        pris.is_some()
    });
    match pris {
        Some(info) => Ok(info),
        // Sans échéance, l'attente ne finit autrement que par un signal.
        None => {
            debug_assert!(r == Reveil::Signal);
            Err(-crate::reprise::ERESTARTSYS)
        }
    }
}

/// read d'un signalfd (`signalfd_read_iter`) : au moins 128 octets en
/// tout, sur tous les morceaux (EINVAL) ; puis autant de signaux que le
/// tampon en tient, chacun écrit à la suite du précédent, d'un morceau à
/// l'autre. Seul le premier est attendu (s'il le faut) : les suivants, s'il
/// y en a déjà. Un signal est pris avant d'être copié : une copie qui
/// échoue le perd, et rend EFAULT si rien n'a été écrit avant lui, sinon
/// ce qui l'a été. `non_bloquant` : O_NONBLOCK, ou RWF_NOWAIT de preadv2.
pub fn lire_morceaux(o: &FichierTenu, morceaux: &[(u64, u64)], mut non_bloquant: bool) -> Result<u64, i64> {
    let total = morceaux.iter().fold(0u64, |t, &(_, l)| t.saturating_add(l));
    let mut reste = total / TAILLE;
    if reste == 0 {
        return Err(-EINVAL);
    }
    let s = o.signalfd();
    let mut faits = 0u64;
    while reste > 0 {
        let echec = match prendre(s, non_bloquant) {
            Ok(info) if ecrire_a_la_suite(morceaux, faits, &info.pour_signalfd()) => None,
            Ok(_) => Some(-EFAULT),
            Err(e) => Some(e),
        };
        if let Some(e) = echec {
            return if faits > 0 { Ok(faits) } else { Err(e) };
        }
        faits += TAILLE;
        non_bloquant = true;
        reste -= 1;
    }
    Ok(faits)
}

/// Écrit `octets` dans la suite des morceaux, à partir de son octet `deja`
/// (le `copy_to_iter_full` de Linux). Faux si une copie échoue : ce qui a
/// été écrit reste dans le tampon, mais ne compte pas.
fn ecrire_a_la_suite(morceaux: &[(u64, u64)], deja: u64, octets: &[u8]) -> bool {
    let mut saut = deja;
    let mut faits = 0;
    for &(base, longueur) in morceaux {
        if saut >= longueur {
            saut -= longueur;
            continue;
        }
        let n = ((longueur - saut) as usize).min(octets.len() - faits);
        if copier_vers_utilisateur(base.saturating_add(saut), &octets[faits..faits + n]).is_err() {
            return false;
        }
        faits += n;
        saut = 0;
        if faits == octets.len() {
            break;
        }
    }
    faits == octets.len()
}
