//! eventfd : un compteur de 64 bits derrière un descripteur, de quoi bâtir
//! une boucle d'événements avec epoll (epoll.rs), comme celle de Bun. `write`
//! lui ajoute un nombre, `read` le prend (et le remet à zéro, ou n'en prend
//! qu'un avec EFD_SEMAPHORE). Un fil s'en sert pour en réveiller un autre
//! qui attend sur epoll. Il n'a pas de nom : il tient l'inode anonyme
//! (fichiers::montages::Objet::Anonyme), comme sous Linux.
//!
//! Tout est fait et vérifié comme Linux (mesuré sur Linux 6.18). Depuis
//! 6e, une lecture bloquante d'un eventfd vide (ou une écriture qui le
//! ferait déborder) attend vraiment, dans la file d'attente de l'eventfd,
//! qu'une écriture (ou une lecture) change le compteur. Depuis 6f, l'eventfd
//! est un objet à lui (`EventFd`), avec son verrou, hors de celui des
//! fichiers, et il se sonde (`sonder`) : poll et epoll l'attendent.

use crate::appels_fichiers::installer_fichier;
use crate::attente::{self, FileAttente, Sommeil};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::partage::Arc;
use crate::sondage::{POLLERR, POLLIN, POLLOUT, Table};
use crate::tache::Reveil;
use crate::verrou::Verrou;
use crate::{cpu, faillible, tache};
use fichiers::montages::Objet;

const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOMEM: i64 = 12;

const O_RDWR: u32 = 2;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const EFD_SEMAPHORE: u64 = 1;

/// Un eventfd (l'`eventfd_ctx` de Linux) : son compteur, sous son propre
/// verrou, et la file de ceux qui attendent qu'il change, lecteurs et
/// écrivains ensemble (le `wqh` de Linux) : un lecteur vide le compteur et
/// réveille avec POLLOUT, un écrivain le remplit et réveille avec POLLIN.
pub struct EventFd {
    compteur: Verrou<u64>,
    /// EFD_SEMAPHORE : une lecture n'en prend qu'un.
    semaphore: bool,
    attente: FileAttente,
}

/// eventfd2(valeur initiale, drapeaux) : EFD_SEMAPHORE, EFD_NONBLOCK et
/// EFD_CLOEXEC (les valeurs d'O_NONBLOCK et d'O_CLOEXEC) ; un autre :
/// EINVAL. F_GETFL rendra O_RDWR, plus O_NONBLOCK s'il est demandé
/// (mesuré : 0x802 ; pas d'O_LARGEFILE, celui d'`anon_inode_getfile`).
pub fn eventfd2(initiale: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & !(EFD_SEMAPHORE | O_NONBLOCK | O_CLOEXEC) != 0 {
        return -EINVAL;
    }
    let mut f = FichierOuvert::new(Sorte::EventFd, Tenu::Noyau(Objet::Anonyme), true, true,
                                   O_RDWR | (drapeaux & O_NONBLOCK) as u32, b"anon_inode:[eventfd]");
    f.chemin = nom_anonyme(b"anon_inode:[eventfd]");
    let Ok(e) = Arc::new(EventFd {
        compteur: Verrou::new(initiale as u32 as u64),
        semaphore: drapeaux & EFD_SEMAPHORE != 0,
        attente: FileAttente::new(),
    }) else {
        return -ENOMEM;
    };
    f.prive = Prive::EventFd(e);
    installer_fichier(f, drapeaux & O_CLOEXEC != 0)
}

/// Le « chemin » d'un fichier anonyme, celui que Linux montre dans
/// /proc/self/fd (vide s'il n'y a pas la place de le copier).
pub fn nom_anonyme(nom: &[u8]) -> alloc::vec::Vec<u8> {
    faillible::copie(nom).unwrap_or_default()
}

/// eventfd(valeur initiale) : eventfd2 sans drapeaux.
pub fn eventfd(initiale: u64) -> i64 {
    eventfd2(initiale, 0)
}

impl EventFd {
    /// Attend, si besoin, que `essayer` réussisse sur le compteur (sous son
    /// verrou) : il rend Some quand l'opération est faite, None quand elle
    /// doit attendre. Une opération faite réveille la file avec `cle` (qui
    /// attendait dans l'autre sens, et qui le sonde : une seule file, dont
    /// toutes les entrées ordinaires sont réveillées, et une exclusive,
    /// celle d'un epoll en EPOLLEXCLUSIVE, comme par le `wake_up_poll` de
    /// Linux). Non bloquant : EAGAIN. Dans
    /// l'ordre du `wait_event_interruptible` de Linux : la condition
    /// d'abord, à chaque tour, même réveillé par un signal (une écriture
    /// arrivée en même temps se lit) ; puis seulement le signal :
    /// ERESTARTSYS (EINTR, ou refaite : reprise.rs). Sans réveil perdu
    /// (attente.rs).
    fn attendre<R>(&self, non_bloquant: bool, cle: u32, mut essayer: impl FnMut(&mut u64, bool) -> Option<R>) -> Result<R, i64> {
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        let mut signal = false;
        let r = loop {
            // « Je vais dormir » avant d'essayer (attente.rs) : qui écrit ou
            // lit le compteur le change, puis réveille la file.
            t.preparer_sommeil(Sommeil::Interruptible);
            let fait = essayer(&mut self.compteur.verrouiller(), self.semaphore);
            if let Some(r) = fait {
                self.attente.reveiller(cle, 1);
                break Ok(r);
            }
            if non_bloquant {
                break Err(-EAGAIN);
            }
            if signal {
                // Refaite d'elle-même après le signal, sauf gestionnaire sans
                // SA_RESTART (reprise.rs).
                break Err(-crate::reprise::ERESTARTSYS);
            }
            self.attente.inscrire();
            signal = attente::dormir(None, Sommeil::Interruptible) == Reveil::Signal;
            self.attente.retirer(t);
        };
        t.reveille();
        if interruptions {
            cpu::activer_interruptions();
        }
        r
    }

    /// Le sondage (`eventfd_poll`) : s'inscrit d'abord dans la file (une
    /// écriture qui suit le verra), puis lit le compteur : POLLIN s'il
    /// n'est pas nul, POLLOUT si une écriture de 1 passerait, POLLERR s'il
    /// est au maximum (impossible par write ; Linux le garde pour
    /// `eventfd_signal`). Sans POLLRDNORM ni POLLWRNORM (mesuré : 0x5).
    pub fn sonder(&self, table: &mut Table, tenu: &crate::appels_fichiers::FichierTenu) -> u32 {
        table.attendre(&self.attente, tenu);
        let c = *self.compteur.verrouiller();
        let mut m = 0;
        if c > 0 {
            m |= POLLIN;
        }
        if c == u64::MAX {
            m |= POLLERR;
        }
        if u64::MAX - 1 > c {
            m |= POLLOUT;
        }
        m
    }
}

/// read d'un eventfd (`eventfd_read`) : au moins 8 octets (EINVAL) ; un
/// compteur nul fait attendre (EAGAIN en non bloquant) ; sinon on prend le
/// compteur (ou 1 avec EFD_SEMAPHORE), puis on l'écrit en 8 octets. Comme
/// Linux, le compteur est pris avant la copie : une copie qui échoue
/// (EFAULT) l'a perdu.
pub fn lire(e: &EventFd, non_bloquant: bool, tampon: u64, longueur: u64) -> Result<u64, i64> {
    lire_morceaux(e, non_bloquant, &[(tampon, longueur)])
}

/// readv d'un eventfd : Linux lit un eventfd par `read_iter`, qui voit
/// tous les morceaux d'un coup. C'est leur longueur TOTALE qui doit faire
/// 8 octets (mesuré : deux morceaux de 4 rendent 8), et les 8 octets du
/// compteur sont écrits à la suite, d'un morceau à l'autre ; une faute
/// avant le huitième : EFAULT. (writev, lui, passe morceau par morceau :
/// `eventfd_write` n'est pas un `write_iter`, et 4 + 4 rend EINVAL.)
pub fn lire_morceaux(e: &EventFd, non_bloquant: bool, morceaux: &[(u64, u64)]) -> Result<u64, i64> {
    if morceaux.iter().fold(0u64, |t, &(_, l)| t.saturating_add(l)) < 8 {
        return Err(-EINVAL);
    }
    let pris = e.attendre(non_bloquant, POLLOUT, |c, semaphore| {
        if *c == 0 {
            return None;
        }
        let pris = if semaphore { 1 } else { *c };
        *c -= pris;
        Some(pris)
    })?;
    let octets = pris.to_le_bytes();
    let mut faits = 0;
    for &(base, longueur) in morceaux {
        let n = (longueur as usize).min(8 - faits);
        copier_vers_utilisateur(base, &octets[faits..faits + n]).map_err(|_| -EFAULT)?;
        faits += n;
        if faits == 8 {
            break;
        }
    }
    Ok(8)
}

/// write d'un eventfd (`eventfd_write`) : exactement 8 octets (EINVAL ;
/// depuis Linux 6.6, mesuré : 16 aussi, alors qu'une lecture en prend au
/// moins 8), lus (EFAULT) ; 0xffffffffffffffff est refusé (EINVAL : le
/// compteur ne peut jamais l'atteindre) ; un ajout qui l'atteindrait fait
/// attendre qu'un lecteur le vide (EAGAIN en non bloquant).
pub fn ecrire(e: &EventFd, non_bloquant: bool, tampon: u64, longueur: u64) -> Result<u64, i64> {
    if longueur != 8 {
        return Err(-EINVAL);
    }
    let mut o = [0u8; 8];
    copier_depuis_utilisateur(&mut o, tampon).map_err(|_| -EFAULT)?;
    let ajout = u64::from_le_bytes(o);
    if ajout == u64::MAX {
        return Err(-EINVAL);
    }
    e.attendre(non_bloquant, POLLIN, |c, _| {
        if u64::MAX - *c <= ajout {
            return None;
        }
        *c += ajout;
        Some(())
    })?;
    Ok(8)
}
