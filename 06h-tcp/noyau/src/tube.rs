//! Les tubes : pipe (22) et pipe2 (293), comme fs/pipe.c de Linux 6.18.
//!
//! Un tube est un ANNEAU DE PAGES (16 par défaut, 64 Kio) : une écriture
//! remplit des pages, une lecture les vide dans l'ordre. Ce sont bien des
//! pages, pas des octets : une page n'est pas partagée entre deux
//! écritures, sauf une règle de FUSION. Les premiers octets d'une écriture,
//! autant que sa longueur modulo 4096, se collent à la dernière page s'ils
//! y tiennent ; le reste s'écrit par pages entières. D'où ce que
//! mesure Linux : 64 écritures de 1000 octets remplissent un tube de 16
//! pages (quatre par page), et sur un tube plein, une écriture de 10 octets
//! passe encore quand la dernière page a la place, mais pas une de 100. C'est
//! aussi ce qui rend atomique une écriture d'au plus PIPE_BUF (4096) octets :
//! elle tient dans la dernière page ou dans une page neuve, jamais à cheval.
//!
//! Deux verrous, comme Linux : l'anneau sous un `Mutex` (qui dort : on le
//! tient en copiant depuis et vers le programme, la copie peut fauter), et
//! sous un `Verrou` ce que lisent sans lui les attentes et le sondage (la
//! tête, la queue, le nombre de lecteurs et d'écrivains : Linux les lit par
//! READ_ONCE). Deux files d'attente : les lecteurs qui attendent des
//! données (`rd_wait`), les écrivains qui attendent de la place
//! (`wr_wait`), en EXCLUSIVES : une écriture d'un octet ne réveille qu'un
//! lecteur, qui réveille le suivant s'il reste de quoi lire.
//!
//! Sans lecteur, écrire rend EPIPE et envoie SIGPIPE à qui écrit ; sans
//! écrivain, lire rend 0 (la fin). O_DIRECT fait un tube de PAQUETS :
//! chaque page écrite est un paquet (une écriture de plus d'une page en
//! fait plusieurs), et une lecture plus courte en jette le reste.
//!
//! L'inode d'un tube est un inode sans nom du tmpfs (`Tmpfs::creer_tube`),
//! celui de pipefs chez Linux : fstat, fchmod, fchown, futimens s'en
//! servent ; son lien dans /proc/self/fd est « pipe:[numero] ».

use crate::appels_fichiers::{FichierTenu, installer_paire};
use crate::attente::{self, FileAttente, Mutex, Sommeil};
use crate::copie_utilisateur::{copier_depuis_utilisateur_partiel, copier_vers_utilisateur, copier_vers_utilisateur_partiel};
use crate::descripteurs::{FichierOuvert, Prive, Sorte, Tenu};
use crate::partage::{Arc, Weak};
use crate::sondage::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, Table};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::faillible::{self, VecFaillible};
use crate::{cpu, espace, pages, processus, signaux, temps, vfs};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use fichiers::tmpfs::Ouvert;

const EPERM: i64 = 1;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EBUSY: i64 = 16;
const ENFILE: i64 = 23;
const EINVAL: i64 = 22;
const EPIPE: i64 = 32;
const ENOPKG: i64 = 65;

const O_WRONLY: u32 = 0o1;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u64 = 0o4000;
const O_DIRECT: u64 = 0o40000;
const O_CLOEXEC: u64 = 0o2000000;
/// O_NOTIFICATION_PIPE vaut O_EXCL : un tube de notifications (watch
/// queue), que Linux sans CONFIG_WATCH_QUEUE refuse (ENOPKG, mesuré).
const O_NOTIFICATION_PIPE: u64 = O_EXCL;
const SIGPIPE: u64 = 13;

const PAGE: usize = 4096;
/// Les pages d'un tube neuf (PIPE_DEF_BUFFERS), et le moins qu'on lui donne
/// quand l'utilisateur a passé sa limite douce (PIPE_MIN_DEF_BUFFERS).
const PAGES_PAR_DEFAUT: u32 = 16;
const PAGES_AU_MOINS: u32 = 2;

/// /proc/sys/fs/pipe-max-size : la plus grande taille qu'un utilisateur
/// sans CAP_SYS_RESOURCE peut demander (F_SETPIPE_SZ).
pub const TAILLE_MAX: u64 = 1 << 20;
/// /proc/sys/fs/pipe-user-pages-soft : au-delà, les tubes neufs d'un
/// utilisateur n'ont plus que deux pages ; et /proc/sys/fs/pipe-user-pages-hard
/// (0 : sans limite dure).
pub const PAGES_UTILISATEUR_DOUCE: u64 = 16 * 1024;
pub const PAGES_UTILISATEUR_DURE: u64 = 0;

/// Les tubes vivants, par le numéro de leur inode (pipefs) : pour en rouvrir
/// un par /proc/<pid>/fd (Linux : `inode->i_pipe`). Un tube la quitte quand
/// son dernier bout est fermé, avant que le tmpfs ne puisse redonner son
/// numéro d'inode (`put_pipe_info`, qui coupe `i_pipe`) ; elle est rendue
/// vide quand il n'y en a plus.
static TUBES: Verrou<Vec<(u32, Weak<Tube>)>> = Verrou::new(Vec::new());

/// Les pages de tubes de l'utilisateur (le `pipe_bufs` de sa `user_struct` :
/// nos programmes n'en ont qu'un).
static PAGES_UTILISATEUR: AtomicU64 = AtomicU64::new(0);

/// Le compte de l'utilisateur passe de `ancien` à `nouveau` pages pour un
/// tube (`account_pipe_buffers`) : rend le nouveau total.
fn compter(ancien: u64, nouveau: u64) -> u64 {
    if nouveau >= ancien {
        PAGES_UTILISATEUR.fetch_add(nouveau - ancien, Relaxed) + (nouveau - ancien)
    } else {
        PAGES_UTILISATEUR.fetch_sub(ancien - nouveau, Relaxed) - (ancien - nouveau)
    }
}

/// Au-delà de la limite douce, ou de la dure (0 : aucune).
fn trop(compte: u64) -> (bool, bool) {
    (PAGES_UTILISATEUR_DOUCE != 0 && compte > PAGES_UTILISATEUR_DOUCE, PAGES_UTILISATEUR_DURE != 0 && compte > PAGES_UTILISATEUR_DURE)
}

/// Une page de l'anneau (la `pipe_buffer` de Linux).
#[derive(Clone, Copy, Default)]
struct Tampon {
    /// Le cadre de la page ; 0 : la case est vide.
    cadre: u64,
    debut: usize,
    longueur: usize,
    /// Un paquet (O_DIRECT) : lu d'un coup, le reste jeté.
    paquet: bool,
    /// Une écriture peut s'y ajouter (PIPE_BUF_FLAG_CAN_MERGE).
    fusionnable: bool,
}

impl Tampon {
    /// Ses octets, dans la page.
    fn octets(&mut self) -> &mut [u8] {
        // SAFETY : la page est au tube, qui ne la touche que sous son Mutex
        // (que tient l'appelant, qui a la case en &mut) ; personne d'autre
        // ne la projette.
        unsafe { core::slice::from_raw_parts_mut(espace::virtuelle(self.cadre) as *mut u8, PAGE) }
    }
}

/// Ce que lisent les attentes et le sondage, sous le Verrou.
#[derive(Clone, Copy)]
struct Etat {
    /// La tête (la prochaine case à écrire) et la queue (la prochaine à
    /// lire), qui ne font que croître (modulo 2^32) : l'anneau contient
    /// tete - queue pages.
    tete: u32,
    queue: u32,
    /// Combien de pages on peut remplir (le `max_usage`), la taille de
    /// l'anneau (`ring_size`, une puissance de deux).
    max: u32,
    taille: u32,
    lecteurs: u32,
    ecrivains: u32,
}

impl Etat {
    fn vide(&self) -> bool {
        self.tete == self.queue
    }

    fn plein(&self) -> bool {
        self.tete.wrapping_sub(self.queue) >= self.max
    }
}

/// Un tube (la `pipe_inode_info` de Linux).
pub struct Tube {
    anneau: Mutex<Vec<Tampon>>,
    etat: Verrou<Etat>,
    rd_wait: FileAttente,
    wr_wait: FileAttente,
    /// Il a été sondé (le `poll_usage`) : epoll veut alors un réveil à
    /// chaque écriture, même si le tube n'était pas vide (sans cela, un tube
    /// en EPOLLET ne redonnerait rien à la deuxième écriture).
    sonde: AtomicBool,
    /// Les pages comptées à l'utilisateur (`nr_accounted`).
    comptees: AtomicU64,
}

/// Un morceau d'un tampon du programme (un iovec) parcouru par un appel.
struct Morceaux<'a> {
    reste: &'a [(u64, u64)],
    fait: u64,
}

impl Morceaux<'_> {
    fn restant(&self) -> usize {
        self.reste.iter().map(|&(_, l)| l).sum::<u64>().saturating_sub(self.fait) as usize
    }

    /// Copie `octets` vers le programme, d'un morceau au suivant : rend ce
    /// qui a été copié (moins à une faute).
    fn vers(&mut self, mut octets: &[u8]) -> usize {
        let mut copies = 0;
        while !octets.is_empty() {
            let Some(&(base, longueur)) = self.reste.first() else { break };
            let n = (longueur - self.fait).min(octets.len() as u64) as usize;
            let c = copier_vers_utilisateur_partiel(base + self.fait, &octets[..n]);
            copies += c;
            self.avancer(c as u64, longueur);
            if c < n {
                break;
            }
            octets = &octets[n..];
        }
        copies
    }

    /// Copie du programme vers `octets` : rend ce qui a été copié.
    fn depuis(&mut self, octets: &mut [u8]) -> usize {
        let mut copies = 0;
        while copies < octets.len() {
            let Some(&(base, longueur)) = self.reste.first() else { break };
            let n = (longueur - self.fait).min((octets.len() - copies) as u64) as usize;
            let c = copier_depuis_utilisateur_partiel(&mut octets[copies..copies + n], base + self.fait);
            copies += c;
            self.avancer(c as u64, longueur);
            if c < n {
                break;
            }
        }
        copies
    }

    fn avancer(&mut self, n: u64, longueur: u64) {
        self.fait += n;
        if self.fait == longueur {
            self.reste = &self.reste[1..];
            self.fait = 0;
        }
        while self.reste.first().is_some_and(|&(_, l)| l == 0) {
            self.reste = &self.reste[1..];
        }
    }
}

/// Attend dans `file`, en exclusive, que `condition` soit vraie
/// (`wait_event_interruptible_exclusive`) ; faux : un signal.
fn attendre(file: &FileAttente, mut condition: impl FnMut() -> bool) -> bool {
    let interruptions = cpu::couper_interruptions();
    let t = tache::courante();
    let mut signal = false;
    let r = loop {
        if condition() {
            break true;
        }
        if signal {
            break false;
        }
        file.inscrire_exclusive();
        signal = attente::dormir(None, Sommeil::Interruptible) == Reveil::Signal;
        file.retirer(t);
    };
    if interruptions {
        cpu::activer_interruptions();
    }
    r
}

impl Tube {
    /// Un tube neuf (`alloc_pipe_info`) : seize pages, ou moins si
    /// pipe-max-size est plus petit, ou deux au-delà de la limite douce de
    /// l'utilisateur ; None au-delà de sa limite dure.
    fn new() -> Option<Tube> {
        let mut n = PAGES_PAR_DEFAUT;
        if n as u64 * PAGE as u64 > TAILLE_MAX {
            n = (TAILLE_MAX / PAGE as u64) as u32;
        }
        let mut compte = compter(0, n as u64);
        if trop(compte).0 {
            compte = compter(n as u64, PAGES_AU_MOINS as u64);
            n = PAGES_AU_MOINS;
        }
        let anneau = match faillible::remplie(n as usize, Tampon::default()) {
            Ok(a) if !trop(compte).1 => a,
            _ => {
                compter(n as u64, 0);
                return None;
            }
        };
        Some(Tube {
            anneau: Mutex::new(anneau),
            etat: Verrou::new(Etat { tete: 0, queue: 0, max: n, taille: n, lecteurs: 1, ecrivains: 1 }),
            rd_wait: FileAttente::new(),
            wr_wait: FileAttente::new(),
            sonde: AtomicBool::new(false),
            comptees: AtomicU64::new(n as u64),
        })
    }

    fn etat(&self) -> Etat {
        *self.etat.verrouiller()
    }

    /// Lit dans les `morceaux` du programme (`anon_pipe_read`) : ce qu'il y
    /// a, au plus leur longueur ; vide, attendre un écrivain (EAGAIN en non
    /// bloquant ; ERESTARTSYS sur un signal) ; sans écrivain, 0. Réveille
    /// les écrivains si le tube était plein, et le lecteur suivant s'il reste
    /// à lire après une attente.
    pub fn lire(&self, morceaux: &[(u64, u64)], non_bloquant: bool) -> i64 {
        let mut m = Morceaux { reste: morceaux, fait: 0 };
        m.avancer(0, morceaux.first().map_or(0, |&(_, l)| l));
        let mut total = m.restant();
        if total == 0 {
            return 0;
        }
        let mut r: i64 = 0;
        let (mut reveiller_ecrivain, mut reveiller_lecteur) = (false, false);
        let mut anneau = self.anneau.verrouiller();
        loop {
            let e = self.etat();
            if !e.vide() {
                let case = (e.queue & (e.taille - 1)) as usize;
                let t = &mut anneau[case];
                let n = t.longueur.min(total);
                let (debut, octets) = (t.debut, t.octets());
                let copies = m.vers(&octets[debut..debut + n]);
                if copies < n {
                    if r == 0 {
                        r = -EFAULT;
                    }
                    break;
                }
                r += n as i64;
                t.debut += n;
                t.longueur -= n;
                if t.paquet {
                    total = n;
                    t.longueur = 0;
                }
                if t.longueur == 0 {
                    reveiller_ecrivain |= e.plein();
                    pages::lacher(t.cadre);
                    *t = Tampon::default();
                    self.etat.verrouiller().queue = e.queue.wrapping_add(1);
                }
                total -= n;
                if total == 0 {
                    break;
                }
                if !self.etat().vide() {
                    continue;
                }
            }
            if self.etat().ecrivains == 0 || r != 0 {
                break;
            }
            if non_bloquant {
                r = -EAGAIN;
                break;
            }
            drop(anneau);
            let lisible = || {
                let e = self.etat();
                !e.vide() || e.ecrivains == 0
            };
            if !attendre(&self.rd_wait, lisible) {
                return -crate::reprise::ERESTARTSYS;
            }
            reveiller_lecteur = true;
            anneau = self.anneau.verrouiller();
        }
        if self.etat().vide() {
            reveiller_lecteur = false;
        }
        drop(anneau);
        if reveiller_ecrivain {
            self.wr_wait.reveiller(POLLOUT | POLLWRNORM, 1);
        }
        if reveiller_lecteur {
            self.rd_wait.reveiller(POLLIN | POLLRDNORM, 1);
        }
        r
    }

    /// Écrit les `morceaux` du programme (`anon_pipe_write`) : sans lecteur,
    /// SIGPIPE et EPIPE ; le reste de la longueur modulo 4096 collé à la
    /// dernière page s'il y tient, puis des pages entières ; plein, attendre
    /// un lecteur (EAGAIN en non bloquant, ERESTARTSYS sur un signal, ce qui
    /// est écrit étant rendu). `paquets` : O_DIRECT.
    pub fn ecrire(&self, morceaux: &[(u64, u64)], non_bloquant: bool, paquets: bool) -> i64 {
        let mut m = Morceaux { reste: morceaux, fait: 0 };
        m.avancer(0, morceaux.first().map_or(0, |&(_, l)| l));
        let total = m.restant();
        if total == 0 {
            return 0;
        }
        let mut r: i64 = 0;
        let mut etait_vide = false;
        let mut reveiller_ecrivain = false;
        // Les lecteurs ne se comptent qu'à l'entrée et après chaque
        // attente : Linux les change sous `pipe->mutex` (pipe_release), que
        // l'écriture tient entre deux attentes ; nous sans lui (le dernier
        // close est sous le verrou des fichiers, qui ne dort pas). Sans
        // cela, une écriture de plusieurs pages pourrait rendre une partie
        // écrite et SIGPIPE sans avoir attendu, ce que Linux ne fait jamais.
        let mut apres_attente = false;
        let mut anneau = self.anneau.verrouiller();
        'ecrire: {
            let e = self.etat();
            if e.lecteurs == 0 {
                signaux::au_fil_courant(SIGPIPE);
                r = -EPIPE;
                break 'ecrire;
            }
            etait_vide = e.vide();
            let n = total & (PAGE - 1);
            if n != 0 && !etait_vide {
                let case = (e.tete.wrapping_sub(1) & (e.taille - 1)) as usize;
                let t = &mut anneau[case];
                let fin = t.debut + t.longueur;
                if t.fusionnable && fin + n <= PAGE {
                    let copies = m.depuis(&mut t.octets()[fin..fin + n]);
                    if copies < n {
                        r = -EFAULT;
                        break 'ecrire;
                    }
                    t.longueur += n;
                    r = n as i64;
                    if m.restant() == 0 {
                        break 'ecrire;
                    }
                }
            }
            loop {
                let e = self.etat();
                if apres_attente && e.lecteurs == 0 {
                    signaux::au_fil_courant(SIGPIPE);
                    if r == 0 {
                        r = -EPIPE;
                    }
                    break;
                }
                apres_attente = false;
                if !e.plein() {
                    let Some(cadre) = pages::allouer_pour_programme() else {
                        if r == 0 {
                            r = -ENOMEM;
                        }
                        break;
                    };
                    let mut t = Tampon { cadre, debut: 0, longueur: 0, paquet: paquets, fusionnable: !paquets };
                    let copies = m.depuis(t.octets());
                    if copies < PAGE && m.restant() != 0 {
                        pages::lacher(cadre);
                        if r == 0 {
                            r = -EFAULT;
                        }
                        break;
                    }
                    t.longueur = copies;
                    anneau[(e.tete & (e.taille - 1)) as usize] = t;
                    self.etat.verrouiller().tete = e.tete.wrapping_add(1);
                    r += copies as i64;
                    if m.restant() == 0 {
                        break;
                    }
                    continue;
                }
                if non_bloquant {
                    if r == 0 {
                        r = -EAGAIN;
                    }
                    break;
                }
                if tache::signal_en_attente() {
                    if r == 0 {
                        r = -crate::reprise::ERESTARTSYS;
                    }
                    break;
                }
                drop(anneau);
                if etait_vide {
                    self.rd_wait.reveiller(POLLIN | POLLRDNORM, 1);
                }
                let inscriptible = || {
                    let e = self.etat();
                    !e.plein() || e.lecteurs == 0
                };
                attendre(&self.wr_wait, inscriptible);
                apres_attente = true;
                anneau = self.anneau.verrouiller();
                etait_vide = self.etat().vide();
                reveiller_ecrivain = true;
            }
        }
        if self.etat().plein() {
            reveiller_ecrivain = false;
        }
        drop(anneau);
        if etait_vide || self.sonde.load(Relaxed) {
            self.rd_wait.reveiller(POLLIN | POLLRDNORM, 1);
        }
        if reveiller_ecrivain {
            self.wr_wait.reveiller(POLLOUT | POLLWRNORM, 1);
        }
        r
    }

    /// Le sondage d'un bout (`pipe_poll`) : ses files d'abord, puis l'état.
    /// Côté lecture : POLLIN s'il y a de quoi lire, POLLHUP sans écrivain ;
    /// côté écriture : POLLOUT s'il y a de la place, POLLERR sans lecteur.
    pub fn sonder(&self, table: &mut Table, tenu: &FichierTenu) -> u32 {
        self.sonde.store(true, Relaxed);
        if tenu.lecture {
            table.attendre(&self.rd_wait, tenu);
        }
        if tenu.ecriture {
            table.attendre(&self.wr_wait, tenu);
        }
        let e = self.etat();
        let mut m = 0;
        if tenu.lecture {
            if !e.vide() {
                m |= POLLIN | POLLRDNORM;
            }
            if e.ecrivains == 0 {
                m |= POLLHUP;
            }
        }
        if tenu.ecriture {
            if !e.plein() {
                m |= POLLOUT | POLLWRNORM;
            }
            if e.lecteurs == 0 {
                m |= POLLERR;
            }
        }
        m
    }

    /// Les octets présents (FIONREAD).
    pub fn octets_presents(&self) -> u32 {
        let anneau = self.anneau.verrouiller();
        let e = self.etat();
        (0..e.tete.wrapping_sub(e.queue)).map(|i| anneau[(e.queue.wrapping_add(i) & (e.taille - 1)) as usize].longueur as u32).sum()
    }

    /// F_GETPIPE_SZ : la capacité, en octets.
    pub fn capacite(&self) -> i64 {
        let _anneau = self.anneau.verrouiller();
        self.etat().max as i64 * PAGE as i64
    }

    /// F_SETPIPE_SZ (`pipe_set_size`) : arrondie à une puissance de deux
    /// pages, une au moins (EINVAL au-delà de 2^31) ; agrandir au-delà de
    /// pipe-max-size, ou des limites de l'utilisateur, sans être root
    /// (CAP_SYS_RESOURCE) : EPERM ; plus petite que ce qu'il contient :
    /// EBUSY. Rend la nouvelle capacité.
    pub fn changer_capacite(&self, demande: u64, root: bool) -> i64 {
        let demande = demande as u32 as u64;
        let taille = if demande > 1 << 31 {
            return -EINVAL;
        } else {
            demande.max(PAGE as u64).next_power_of_two()
        };
        let n = (taille / PAGE as u64) as u32;
        let mut anneau = self.anneau.verrouiller();
        let e = self.etat();
        if n > e.max && taille > TAILLE_MAX && !root {
            return -EPERM;
        }
        let avant = self.comptees.load(Relaxed);
        let compte = compter(avant, n as u64);
        let rendre = || {
            compter(n as u64, avant);
        };
        let (douce, dure) = trop(compte);
        if n > e.max && (douce || dure) && !root {
            rendre();
            return -EPERM;
        }
        // `pipe_resize_ring` : le nouvel anneau, les pages présentes au
        // début, dans l'ordre.
        let presentes = e.tete.wrapping_sub(e.queue);
        if n < presentes {
            rendre();
            return -EBUSY;
        }
        let mut neuf = Vec::new();
        let copie = neuf.try_reserve_exact(n as usize).is_ok()
            && neuf.ajouter_tout((0..presentes).map(|i| anneau[(e.queue.wrapping_add(i) & (e.taille - 1)) as usize])).is_ok()
            && neuf.redimensionner(n as usize, Tampon::default()).is_ok();
        if !copie {
            rendre();
            return -ENOMEM;
        }
        *anneau = neuf;
        {
            let mut e = self.etat.verrouiller();
            e.queue = 0;
            e.tete = presentes;
            e.taille = n;
            e.max = n;
        }
        self.comptees.store(n as u64, Relaxed);
        drop(anneau);
        self.wr_wait.reveiller(0, 1);
        n as i64 * PAGE as i64
    }

    /// Un bout de plus, rouvert par /proc/<pid>/fd (le `fifo_open` d'un
    /// tube, qui n'attend jamais l'autre bout) : un lecteur ou un écrivain
    /// de plus ; le premier d'un côté réveille qui attend de l'autre.
    fn ouvrir_bout(&self, lecture: bool, ecriture: bool) {
        let premier = {
            let mut e = self.etat.verrouiller();
            let premier = (lecture && e.lecteurs == 0) || (ecriture && e.ecrivains == 0);
            e.lecteurs += lecture as u32;
            e.ecrivains += ecriture as u32;
            premier
        };
        if premier {
            self.rd_wait.reveiller_toutes();
        }
    }

    /// Le dernier close d'un bout (`pipe_release`), sous le verrou des
    /// fichiers : un lecteur ou un écrivain de moins ; si c'était le dernier
    /// d'un côté seulement, tout le monde est réveillé (clé nulle : tous les
    /// événements), pour voir la fin ou l'erreur.
    pub fn fermer_bout(&self, lecture: bool, ecriture: bool) {
        let (fin, plus_aucun) = {
            let mut e = self.etat.verrouiller();
            if lecture {
                e.lecteurs -= 1;
            }
            if ecriture {
                e.ecrivains -= 1;
            }
            ((e.lecteurs == 0) != (e.ecrivains == 0), e.lecteurs == 0 && e.ecrivains == 0)
        };
        // Plus aucun bout : l'inode n'a plus de tube. Un O_PATH qui le tient
        // encore ne peut plus le rouvrir (ENXIO ; Linux en fabrique un neuf,
        // `fifo_open` : un écart, pour un cas que rien ne demande).
        if plus_aucun {
            TUBES.verrouiller().retain(|(_, t)| !core::ptr::eq(t.as_ptr(), self));
        }
        if fin {
            self.rd_wait.reveiller_toutes();
            self.wr_wait.reveiller_toutes();
        }
    }
}

impl Drop for Tube {
    /// La fin du tube (`free_pipe_info`) : ses pages rendues, et le compte
    /// de l'utilisateur ; il quitte la table des tubes.
    fn drop(&mut self) {
        let mut tubes = TUBES.verrouiller();
        tubes.retain(|(_, t)| t.strong_count() > 0);
        if tubes.is_empty() {
            *tubes = Vec::new();
        }
        drop(tubes);
        // Le dernier Arc rendu, souvent sous le verrou des fichiers (le
        // dernier close) : l'anneau sans son Mutex, que personne ne tient.
        for t in self.anneau.seul().iter().filter(|t| t.cadre != 0) {
            pages::lacher(t.cadre);
        }
        compter(self.comptees.load(Relaxed), 0);
    }
}

/// Le chemin d'un bout, celui que montre /proc/self/fd : « pipe:[inode] ».
fn chemin(numero: u32) -> Vec<u8> {
    let mut t = [0u8; 10];
    let n = vfs::decimal(numero, &mut t);
    faillible::concatenation(&[b"pipe:[", n, b"]"]).unwrap_or_default()
}

/// pipe2(tableau, drapeaux), dans l'ordre de `do_pipe2` : un drapeau autre
/// que O_CLOEXEC, O_NONBLOCK, O_DIRECT (ou O_NOTIFICATION_PIPE) : EINVAL ;
/// O_NOTIFICATION_PIPE : ENOPKG ; l'inode et le tube (ENFILE) ; deux numéros
/// (EMFILE) ; les deux numéros écrits (EFAULT : rien ne reste). Le bout de
/// lecture : O_RDONLY (et O_NONBLOCK) ; celui d'écriture : O_WRONLY, et
/// O_NONBLOCK et O_DIRECT (mesuré : 0x800 et 0x4801).
pub fn pipe2(tableau: u64, drapeaux: u64) -> i64 {
    let drapeaux = drapeaux as u32 as u64;
    if drapeaux & !(O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE) != 0 {
        return -EINVAL;
    }
    if drapeaux & O_NOTIFICATION_PIPE != 0 {
        return -ENOPKG;
    }
    let Some(tube) = Tube::new() else { return -ENFILE };
    let Ok(tube) = Arc::new(tube) else { return -ENFILE };
    if TUBES.verrouiller().try_reserve(1).is_err() {
        return -ENFILE;
    }
    let identite = processus::avec(|p| p.identite);
    let maintenant = temps::maintenant();
    let Ok(numero) = vfs::avec(|fs, _| {
        let n = fs.creer_tube(identite, maintenant)?;
        fs.prendre(n);
        fs.prendre(n);
        Ok::<_, fichiers::Erreur>(n)
    }) else {
        return -ENFILE;
    };
    // La place prise plus haut a pu servir entre-temps à un autre pipe2
    // (le verrou est rendu pendant la création de l'inode) : sans place, le
    // tube marche, mais /proc/<pid>/fd ne pourra pas le rouvrir (ENXIO), le
    // seul usage de la table.
    let _ = TUBES.verrouiller().ajouter((numero.0, Arc::downgrade(&tube)));
    let bout = |lecture: bool, ecriture: bool, etat: u32| {
        let ouvert = Ouvert { numero, cree: false, tronquer: false, ecrivain: false };
        let mut f = FichierOuvert::new(Sorte::Tube, Tenu::Tmpfs(ouvert), lecture, ecriture, etat, b"pipe");
        f.chemin = chemin(numero.0);
        f.prive = Prive::Tube(tube.clone());
        f
    };
    let lecture = bout(true, false, (drapeaux & O_NONBLOCK) as u32);
    let ecriture = bout(false, true, O_WRONLY | (drapeaux & (O_NONBLOCK | O_DIRECT)) as u32);
    installer_paire(lecture, ecriture, drapeaux & O_CLOEXEC != 0, |fd| {
        let mut o = [0u8; 8];
        o[..4].copy_from_slice(&(fd[0] as i32).to_le_bytes());
        o[4..].copy_from_slice(&(fd[1] as i32).to_le_bytes());
        copier_vers_utilisateur(tableau, &o).is_ok()
    })
}

/// pipe(tableau) : pipe2 sans drapeaux.
pub fn pipe(tableau: u64) -> i64 {
    pipe2(tableau, 0)
}

/// Rouvre le tube de l'inode `numero` (par /proc/<pid>/fd) : un bout de
/// plus, en lecture, en écriture ou les deux ; rend son tube et le nom du
/// bout (« pipe:[numero] »). None : plus de tube à cet inode.
pub fn rouvrir(numero: fichiers::tmpfs::Numero, lecture: bool, ecriture: bool) -> Option<(Arc<Tube>, Vec<u8>)> {
    let tube = TUBES.verrouiller().iter().filter(|(n, _)| *n == numero.0).find_map(|(_, t)| t.upgrade())?;
    tube.ouvrir_bout(lecture, ecriture);
    Some((tube, chemin(numero.0)))
}

/// Le bout `tenu` d'un tube, fermé pour la dernière fois.
pub fn fichier_ferme(ferme: &FichierOuvert) {
    if let Prive::Tube(t) = &ferme.prive {
        t.fermer_bout(ferme.lecture, ferme.ecriture);
    }
}
