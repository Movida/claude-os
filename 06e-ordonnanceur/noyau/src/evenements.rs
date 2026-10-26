//! eventfd et epoll : de quoi bâtir une boucle d'événements, comme celle de
//! Bun (`claude --version` en crée une, sans jamais l'attendre).
//!
//!   - Un EVENTFD est un compteur de 64 bits derrière un descripteur :
//!     `write` lui ajoute un nombre, `read` le prend (et le remet à zéro, ou
//!     n'en prend qu'un avec EFD_SEMAPHORE). Un fil s'en sert pour en
//!     réveiller un autre qui attend sur epoll.
//!   - Un EPOLL est une liste de descripteurs à surveiller (`epoll_ctl`),
//!     et `epoll_wait` attend que l'un d'eux soit prêt.
//! Aucun des deux n'a de nom : ils tiennent l'inode anonyme
//! (fichiers::montages::Objet::Anonyme), comme sous Linux.
//!
//! En 6d, tout est fait et vérifié comme Linux (mesuré sur Linux 6.18),
//! sauf attendre : sans ordonnanceur, rien d'autre ne s'exécute pendant
//! qu'un programme attend, et rien ne peut lui arriver. Une lecture
//! bloquante d'un eventfd vide (ou une écriture qui le ferait déborder)
//! arrête donc le programme, comme une attente de futex sans délai (la
//! même règle, futex.rs) ; `epoll_wait` rend ENOSYS jusqu'en 6f, où chaque
//! sorte de fichier apprendra à dire « prêt » et à réveiller qui l'attend.

use crate::appels_fichiers::installer_fichier;
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::{Donnees, FichierOuvert, Interet, Sorte, Tenu};
use crate::{linux, processus, tache, vfs};
use fichiers::montages::Objet;

const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const ENOENT: i64 = 2;
const EPERM: i64 = 1;
const ENOSYS: i64 = 38;
const ELOOP: i64 = 40;
const ENOMEM: i64 = 12;
const EINTR: i64 = 4;

const O_RDWR: u32 = 2;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const EFD_SEMAPHORE: u64 = 1;

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
    f.donnees = Donnees::EventFd { compteur: initiale as u32 as u64, semaphore: drapeaux & EFD_SEMAPHORE != 0 };
    installer_fichier(f, drapeaux & O_CLOEXEC != 0)
}

/// Le « chemin » d'un fichier anonyme, celui que Linux montre dans
/// /proc/self/fd (vide s'il n'y a pas la place de le copier).
fn nom_anonyme(nom: &[u8]) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    if v.try_reserve_exact(nom.len()).is_ok() {
        v.extend_from_slice(nom);
    }
    v
}

/// eventfd(valeur initiale) : eventfd2 sans drapeaux.
pub fn eventfd(initiale: u64) -> i64 {
    eventfd2(initiale, 0)
}

/// Le compteur d'un eventfd, sous le verrou des fichiers.
fn compteur(f: &mut FichierOuvert) -> (&mut u64, bool) {
    match &mut f.donnees {
        Donnees::EventFd { compteur, semaphore } => (compteur, *semaphore),
        _ => unreachable!("un eventfd sans compteur"),
    }
}

/// Une lecture ou une écriture bloquante que rien ne finira : le programme
/// sera arrêté au retour vers l'anneau 3 (voir l'en-tête) ; il ne verra
/// pas le résultat rendu.
fn attente_sans_fin() -> i64 {
    tache::forcer(linux::SIGKILL, "attente sans fin d'un eventfd : un seul fil, rien ne peut la terminer");
    -EINTR
}

/// read d'un eventfd (`eventfd_read`) : au moins 8 octets (EINVAL) ; un
/// compteur nul fait attendre (EAGAIN en non bloquant) ; sinon on prend le
/// compteur (ou 1 avec EFD_SEMAPHORE), puis on l'écrit en 8 octets. Comme
/// Linux, le compteur est pris avant la copie : une copie qui échoue
/// (EFAULT) l'a perdu.
pub fn lire(f: crate::descripteurs::Fichier, non_bloquant: bool, tampon: u64, longueur: u64) -> Result<u64, i64> {
    lire_morceaux(f, non_bloquant, &[(tampon, longueur)])
}

/// readv d'un eventfd : Linux lit un eventfd par `read_iter`, qui voit
/// tous les morceaux d'un coup. C'est leur longueur TOTALE qui doit faire
/// 8 octets (mesuré : deux morceaux de 4 rendent 8), et les 8 octets du
/// compteur sont écrits à la suite, d'un morceau à l'autre ; une faute
/// avant le huitième : EFAULT. (writev, lui, passe morceau par morceau :
/// `eventfd_write` n'est pas un `write_iter`, et 4 + 4 rend EINVAL.)
pub fn lire_morceaux(f: crate::descripteurs::Fichier, non_bloquant: bool, morceaux: &[(u64, u64)]) -> Result<u64, i64> {
    if morceaux.iter().fold(0u64, |t, &(_, l)| t.saturating_add(l)) < 8 {
        return Err(-EINVAL);
    }
    let pris = vfs::avec_systeme(|s, _| {
        let (c, semaphore) = compteur(s.ouverts.fichier(f));
        if *c == 0 {
            return None;
        }
        let pris = if semaphore { 1 } else { *c };
        *c -= pris;
        Some(pris)
    });
    let Some(pris) = pris else {
        if non_bloquant {
            return Err(-EAGAIN);
        }
        return Err(attente_sans_fin());
    };
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

/// write d'un eventfd (`eventfd_write`) : au moins 8 octets (EINVAL), lus
/// (EFAULT) ; 0xffffffffffffffff est refusé (EINVAL : le compteur ne peut
/// jamais l'atteindre) ; un ajout qui l'atteindrait fait attendre qu'un
/// lecteur le vide (EAGAIN en non bloquant).
pub fn ecrire(f: crate::descripteurs::Fichier, non_bloquant: bool, tampon: u64, longueur: u64) -> Result<u64, i64> {
    if longueur < 8 {
        return Err(-EINVAL);
    }
    let mut o = [0u8; 8];
    copier_depuis_utilisateur(&mut o, tampon).map_err(|_| -EFAULT)?;
    let ajout = u64::from_le_bytes(o);
    if ajout == u64::MAX {
        return Err(-EINVAL);
    }
    let fait = vfs::avec_systeme(|s, _| {
        let (c, _) = compteur(s.ouverts.fichier(f));
        if u64::MAX - *c <= ajout {
            return false;
        }
        *c += ajout;
        true
    });
    if !fait {
        if non_bloquant {
            return Err(-EAGAIN);
        }
        return Err(attente_sans_fin());
    }
    Ok(8)
}

/// epoll_create1(drapeaux) : EPOLL_CLOEXEC seul (EINVAL sinon). F_GETFL
/// rendra O_RDWR (mesuré).
pub fn epoll_create1(drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & !O_CLOEXEC != 0 {
        return -EINVAL;
    }
    let mut f = FichierOuvert::new(Sorte::Epoll, Tenu::Noyau(Objet::Anonyme), true, true, O_RDWR, b"anon_inode:[eventpoll]");
    f.chemin = nom_anonyme(b"anon_inode:[eventpoll]");
    f.donnees = Donnees::Epoll(alloc::vec::Vec::new());
    installer_fichier(f, drapeaux & O_CLOEXEC != 0)
}

/// epoll_create(taille) : l'ancien appel ; la taille ne sert plus, mais
/// doit être positive (EINVAL).
pub fn epoll_create(taille: u64) -> i64 {
    if taille as i32 <= 0 {
        return -EINVAL;
    }
    epoll_create1(0)
}

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLWAKEUP: u32 = 1 << 29;
/// Le plus d'étages d'epoll les uns dans les autres (fs/eventpoll.c).
const EP_MAX_NESTS: u32 = 4;
/// Ce qu'une inscription EPOLLEXCLUSIVE peut demander de plus : lire,
/// écrire (EPOLLIN, EPOLLOUT, EPOLLRDNORM, EPOLLRDBAND, EPOLLWRNORM,
/// EPOLLWRBAND), EPOLLERR, EPOLLHUP, EPOLLWAKEUP, EPOLLET.
const EXCLUSIVE_PERMIS: u32 = 0x001 | 0x004 | 0x040 | 0x080 | 0x100 | 0x200 | EPOLLERR | EPOLLHUP | EPOLLWAKEUP
    | (1 << 31) | EPOLLEXCLUSIVE;

/// epoll_ctl(epoll, opération, fd, événement), dans l'ordre de Linux
/// (`sys_epoll_ctl` puis `do_epoll_ctl`) :
///   1. l'événement est lu, sauf pour EPOLL_CTL_DEL (EFAULT, avant même
///      de regarder les descripteurs, mesuré) ;
///   2. les deux descripteurs (EBADF ; un O_PATH n'en est pas un ici) ;
///   3. le fichier visé doit savoir dire « prêt » (EPERM : un fichier
///      ordinaire, un dossier, /dev/null...) ;
///   4. EPOLLWAKEUP est retiré (il faut CAP_BLOCK_SUSPEND) ;
///   5. le premier doit être un epoll, et pas le fichier visé (EINVAL) ;
///   6. EPOLLEXCLUSIVE : pas pour MOD, ni pour un epoll visé, ni avec
///      d'autres événements que ceux qu'il permet (EINVAL) ;
///   7. un epoll dans un epoll : pas de boucle, et pas plus de
///      EP_MAX_NESTS (4) étages d'epoll en tout, de ce qu'il y a sous
///      l'epoll ajouté à ce qu'il y a au-dessus de celui qui le reçoit
///      (`ep_loop_check`, ELOOP ; mesuré : le cinquième emboîtement d'une
///      chaîne est refusé) ;
///   8. l'opération : ADD (EEXIST s'il est déjà inscrit, sous ce numéro),
///      DEL (ENOENT s'il ne l'est pas), MOD (ENOENT ; EINVAL pour une
///      inscription EPOLLEXCLUSIVE), une autre (EINVAL). ADD et MOD
///      ajoutent toujours EPOLLERR et EPOLLHUP.
/// La « struct epoll_event » est tassée sur x86_64 : 4 octets
/// d'événements, puis 8 de donnée.
pub fn epoll_ctl(epfd: u64, operation: u64, fd: u64, evenement: u64) -> i64 {
    let operation = operation as u32 as u64;
    let mut lu = (0u32, 0u64);
    if operation != EPOLL_CTL_DEL {
        let mut o = [0u8; 12];
        if copier_depuis_utilisateur(&mut o, evenement).is_err() {
            return -EFAULT;
        }
        lu = (u32::from_le_bytes(o[..4].try_into().unwrap_or([0; 4])), u64::from_le_bytes(o[4..].try_into().unwrap_or([0; 8])));
    }
    let (Some(e), Some(cible)) = processus::avec(|p| (p.descripteurs.get(epfd), p.descripteurs.get(fd))) else {
        return -EBADF;
    };
    let fd = fd as u32;
    vfs::avec_systeme(|s, _| {
        let (sorte_e, sorte_cible) = (s.ouverts.fichier(e.fichier).sorte, s.ouverts.fichier(cible.fichier).sorte);
        if sorte_e == Sorte::Chemin || sorte_cible == Sorte::Chemin {
            return -EBADF;
        }
        if !sorte_cible.sait_attendre() {
            return -EPERM;
        }
        let mut evenements = lu.0 & !EPOLLWAKEUP;
        if e.fichier == cible.fichier || sorte_e != Sorte::Epoll {
            return -EINVAL;
        }
        if operation != EPOLL_CTL_DEL
            && evenements & EPOLLEXCLUSIVE != 0
            && (operation == EPOLL_CTL_MOD || sorte_cible == Sorte::Epoll || evenements & !EXCLUSIVE_PERMIS != 0)
        {
            return -EINVAL;
        }
        if operation == EPOLL_CTL_ADD && sorte_cible == Sorte::Epoll {
            if s.ouverts.surveille(cible.fichier, e.fichier) {
                return -ELOOP;
            }
            let (Some(dessous), Some(dessus)) =
                (s.ouverts.etages(cible.fichier, true, EP_MAX_NESTS), s.ouverts.etages(e.fichier, false, EP_MAX_NESTS))
            else {
                return -ENOMEM;
            };
            if dessous + 1 + dessus > EP_MAX_NESTS {
                return -ELOOP;
            }
        }
        let Donnees::Epoll(interets) = &mut s.ouverts.fichier(e.fichier).donnees else {
            unreachable!("un epoll sans liste")
        };
        let ici = interets.iter().position(|i| i.fichier == cible.fichier && i.fd == fd);
        evenements |= EPOLLERR | EPOLLHUP;
        match (operation, ici) {
            (EPOLL_CTL_ADD, None) => {
                if interets.try_reserve(1).is_err() {
                    return -ENOMEM;
                }
                interets.push(Interet { fichier: cible.fichier, fd, evenements, donnees: lu.1 });
                0
            }
            (EPOLL_CTL_ADD, Some(_)) => -EEXIST,
            (EPOLL_CTL_DEL, Some(i)) => {
                interets.remove(i);
                0
            }
            (EPOLL_CTL_MOD, Some(i)) if interets[i].evenements & EPOLLEXCLUSIVE != 0 => -EINVAL,
            (EPOLL_CTL_MOD, Some(i)) => {
                interets[i].evenements = evenements;
                interets[i].donnees = lu.1;
                0
            }
            (EPOLL_CTL_DEL | EPOLL_CTL_MOD, None) => -ENOENT,
            _ => -EINVAL,
        }
    })
}

/// epoll_wait, epoll_pwait, epoll_pwait2 : attendre qu'un fichier soit
/// prêt. En 6f.
pub fn epoll_wait() -> i64 {
    afficherln!("[noyau] epoll_wait : l'attente d'evenements viendra en 6f");
    -ENOSYS
}
