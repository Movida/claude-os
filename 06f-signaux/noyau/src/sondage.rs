//! Le sondage des fichiers, et les appels qui attendent plusieurs fichiers à
//! la fois : poll (7), ppoll (271), select (23) et pselect6 (270).
//!
//! SONDER un fichier, c'est lui demander ce qu'on peut y faire sans attendre
//! : lire (POLLIN), écrire (POLLOUT), ou ce qui ne va pas (POLLERR, POLLHUP).
//! C'est l'opération `poll` des file_operations de Linux, et chaque sorte de
//! fichier a la sienne (`sonder`) ; celles qui n'en ont pas sont toujours
//! prêtes (DEFAULT_POLLMASK : un fichier, un dossier, /dev/null...).
//!
//! Attendre plusieurs fichiers, c'est le travail de la TABLE de sondage (le
//! `poll_table` de Linux). Au premier tour, `poll` sonde chaque fichier avec
//! une table qui inscrit une entrée dans chaque file d'attente rencontrée
//! (`Table::attendre`, le `poll_wait` de Linux : un eventfd a une file, un
//! tube en aura deux) ; si rien n'est prêt, il dort. Quand l'une de ces
//! files est réveillée avec une clé qui intéresse son entrée (une écriture
//! d'eventfd réveille avec POLLIN : un `poll` qui n'attend que POLLOUT ne
//! bouge pas), l'entrée réveille la tâche (le `pollwake` de Linux), qui
//! resonde tout, sans réinscrire : ses entrées y sont encore. À la fin,
//! chaque entrée est retirée de sa file (le `poll_freewait`). Chaque entrée
//! tient son fichier ouvert (le `get_file`) : fermé entre-temps par un autre
//! fil, il ne disparaît pas sous elle.
//!
//! Sans réveil perdu : sonder un fichier inscrit son entrée AVANT de lire
//! son état (comme le `poll_wait` en tête de chaque `poll` de Linux) ; un
//! changement qui arrive après l'inscription réveille l'entrée, un
//! changement d'avant se voit dans l'état lu. Et un réveil arrivé pendant un
//! tour, avant le sommeil, a « déclenché » l'attente (`declenchee`) : elle
//! ne s'endort pas, elle refait un tour.
//!
//! Tout se fait dans l'ordre de `fs/select.c` (Linux 6.18), mesuré : les
//! vérifications et leurs codes d'erreur, les délais (`poll_select_set_timeout`)
//! et le temps restant écrit au retour (`poll_select_finish`), le masque de
//! ppoll et pselect6, et la reprise après un signal (reprise.rs) : poll est
//! repris par restart_syscall avec son échéance absolue (sinon chaque signal
//! sans gestionnaire recommencerait le délai) ; ppoll, select et pselect6
//! rendent ERESTARTNOHAND, et leur délai restant est déjà écrit.

use crate::appels_fichiers::{FichierTenu, tenir};
use crate::attente::{self, EntreeAttente, FileAttente, Rappel, Sommeil};
use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::descripteurs::Sorte;
use crate::reprise::{self, ERESTART_RESTARTBLOCK, ERESTARTNOHAND, Reprise};
use crate::tache::{self, Reveil, Tache};
use crate::{cpu, processus, signaux, temps};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::Pin;

const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EBADF: i64 = 9;
const EINTR: i64 = 4;

pub const POLLIN: u32 = 0x001;
pub const POLLPRI: u32 = 0x002;
pub const POLLOUT: u32 = 0x004;
pub const POLLERR: u32 = 0x008;
pub const POLLHUP: u32 = 0x010;
pub const POLLNVAL: u32 = 0x020;
pub const POLLRDNORM: u32 = 0x040;
pub const POLLRDBAND: u32 = 0x080;
pub const POLLWRNORM: u32 = 0x100;
pub const POLLWRBAND: u32 = 0x200;
/// Ce que rend un fichier sans opération de sondage (le DEFAULT_POLLMASK de
/// Linux) : toujours prêt, à lire comme à écrire (mesuré : 0x145).
pub const PAR_DEFAUT: u32 = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// Qui inscrit une entrée dans chaque file que rencontre un sondage (le
/// `_qproc` du `poll_table` de Linux) : `poll` et `select` (`Entrees`), et
/// l'ajout d'un élément d'epoll (epoll.rs).
pub trait Inscrire {
    /// `tenu` peut changer quand `file` est réveillée ; `cle` : ce qui
    /// intéresse.
    fn inscrire(&mut self, file: &FileAttente, tenu: &FichierTenu, cle: u32);
}

/// La table d'un sondage (le `poll_table` de Linux).
pub struct Table<'a> {
    /// Les événements qui intéressent (le `_key`) : l'entrée inscrite n'est
    /// réveillée que par eux.
    cle: u32,
    /// Qui inscrit ; None : un sondage qui n'attend pas.
    inscrire: Option<&'a mut dyn Inscrire>,
}

impl<'a> Table<'a> {
    /// Une table qui inscrit par `inscrire` (None : rien).
    pub fn new(inscrire: Option<&'a mut dyn Inscrire>) -> Table<'a> {
        Table { cle: !0, inscrire }
    }

    /// Le fichier `tenu` peut changer quand `file` est réveillée (le
    /// `poll_wait` de Linux). Au début du sondage, avant d'en lire l'état et
    /// sans aucun verrou tenu (l'inscription tient le fichier : elle prend
    /// le verrou des fichiers).
    pub fn attendre(&mut self, file: &FileAttente, tenu: &FichierTenu) {
        if let Some(i) = self.inscrire.as_deref_mut() {
            i.inscrire(file, tenu, self.cle);
        }
    }

    /// Ce qui intéresse désormais (le `_key`) : ce que demande un élément
    /// d'epoll.
    pub fn changer_cle(&mut self, cle: u32) {
        self.cle = cle;
    }

    /// Plus d'inscription : quelque chose est prêt, l'appel ne dormira pas
    /// (Linux annule alors `_qproc`).
    fn arreter(&mut self) {
        self.inscrire = None;
    }
}

/// Ce qu'on peut faire du fichier `o` sans attendre (le `vfs_poll` de Linux),
/// en inscrivant par `table` une entrée dans les files de ce qui pourrait le
/// changer.
pub fn sonder(o: &FichierTenu, table: &mut Table) -> u32 {
    match o.sorte {
        Sorte::EventFd => o.eventfd().sonder(table, o),
        // /dev/random : prêt à lire dès que son générateur l'est, et le
        // nôtre l'est dès le démarrage (`random_poll` : POLLIN | POLLRDNORM,
        // 0x41 mesuré). /dev/urandom n'a pas d'opération de sondage.
        Sorte::Aleatoire { random: true } => POLLIN | POLLRDNORM,
        // Un epoll : prêt si l'un de ses prêts l'est vraiment (epoll.rs).
        Sorte::Epoll => o.epoll().sonder(table, o),
        // Les autres n'ont pas d'opération de sondage chez nous : toujours
        // prêts. La console n'est pas encore un terminal (6j) : sa lecture
        // rend « fin de fichier » sans attendre. Une valeur de /proc/sys ou
        // un attribut de /sys en ont une chez Linux, mais ne changent jamais
        // d'eux-mêmes ici : DEFAULT_POLLMASK aussi (mesuré).
        _ => PAR_DEFAUT,
    }
}

/// Une attente de `poll` ou de `select` (le `poll_wqueues` de Linux) : la
/// tâche qui sonde, et « déclenchée » si l'une de ses entrées a été
/// réveillée depuis son dernier sommeil (le `triggered`).
struct Attente {
    tache: Arc<Tache>,
    declenchee: core::cell::Cell<bool>,
}

/// Une entrée de sondage (la `poll_table_entry` de Linux), inscrite dans la
/// file d'un fichier.
struct EntreeSondage {
    entree: EntreeAttente,
    /// La file où elle est inscrite (le `wait_address`).
    file: *const FileAttente,
    /// Ce qu'elle attend (le `key`).
    cle: u32,
    /// Le fichier, tenu tant qu'elle est inscrite : sa file ne disparaît pas.
    _tenu: FichierTenu,
    /// L'attente dont elle fait partie.
    attente: *const Attente,
}

impl Rappel for EntreeSondage {
    /// Le `pollwake` de Linux : rien si la clé ne l'intéresse pas ; sinon
    /// l'attente est déclenchée, et sa tâche réveillée.
    fn rappel(&self, cle: u32) -> bool {
        if cle != 0 && cle & self.cle == 0 {
            return false;
        }
        // SAFETY : l'attente vit plus longtemps que ses entrées (`Entrees`
        // l'emprunte, et retire ses entrées avant de la rendre).
        let a = unsafe { &*self.attente };
        a.declenchee.set(true);
        tache::reveiller(a.tache.clone(), Reveil::Reveillee)
    }
}

/// Les entrées par bloc : un bloc de 16 tient dans un objet du tas de 2 Kio.
const PAR_BLOC: usize = 16;

/// Les entrées d'une attente, par blocs alloués au besoin (comme les pages de
/// `poll_table_page` de Linux). Un bloc a sa capacité dès sa création et
/// n'est jamais agrandi : une entrée inscrite y reste à sa place.
struct Entrees<'a> {
    attente: &'a Attente,
    blocs: Vec<Vec<EntreeSondage>>,
    /// Plus de mémoire pour une entrée (le `error` de Linux) : ENOMEM si
    /// rien n'est prêt, plutôt qu'une attente qui ne serait pas réveillée.
    erreur: bool,
}

impl Entrees<'_> {
    /// Le bloc où mettre l'entrée suivante.
    fn place(&mut self) -> Option<&mut Vec<EntreeSondage>> {
        if self.blocs.last().is_none_or(|b| b.len() == b.capacity()) {
            let mut b = Vec::new();
            b.try_reserve_exact(PAR_BLOC).ok()?;
            self.blocs.try_reserve(1).ok()?;
            self.blocs.push(b);
        }
        self.blocs.last_mut()
    }
}

impl Inscrire for Entrees<'_> {
    /// Le `__pollwait` de Linux.
    fn inscrire(&mut self, file: &FileAttente, tenu: &FichierTenu, cle: u32) {
        let attente: *const Attente = self.attente;
        let Some(bloc) = self.place() else {
            self.erreur = true;
            return;
        };
        bloc.push(EntreeSondage { entree: EntreeAttente::new(), file, cle, _tenu: tenu.dupliquer(), attente });
        let Some(e) = bloc.last() else { return };
        let qui: *const dyn Rappel = e;
        // SAFETY : l'entrée est dans `e`, qui ne bouge plus (son bloc n'est
        // jamais agrandi) et n'est rendu qu'après qu'elle a été retirée
        // (`drop`).
        unsafe { e.entree.preparer_rappel(qui, false) };
        // SAFETY : comme ci-dessus.
        file.ajouter(unsafe { Pin::new_unchecked(&e.entree) });
    }
}

impl Drop for Entrees<'_> {
    /// Le `poll_freewait` de Linux : chaque entrée retirée de sa file ; ses
    /// fichiers rendus ensuite, avec les blocs.
    fn drop(&mut self) {
        for e in self.blocs.iter().flatten() {
            // SAFETY : la file vit tant que l'entrée tient son fichier.
            unsafe { (*e.file).enlever(&e.entree) };
        }
    }
}

/// Combien de temps attendre : toujours, pas du tout, ou jusqu'à un instant
/// du temps monotone (en ns).
#[derive(Clone, Copy)]
pub enum Delai {
    Infini,
    Nul,
    Jusqua(u64),
}

/// L'échéance d'un délai de `secondes` et `nanosecondes`
/// (`poll_select_set_timeout`) : invalide (secondes négatives, nanosecondes
/// hors de [0, 1e9[) : EINVAL ; nul : ne pas attendre ; sinon maintenant
/// plus le délai, sans déborder (`timespec64_add_safe`).
fn delai(secondes: i64, nanosecondes: i64) -> Result<Delai, i64> {
    if secondes < 0 || !(0..1_000_000_000).contains(&nanosecondes) {
        return Err(-EINVAL);
    }
    if secondes == 0 && nanosecondes == 0 {
        return Ok(Delai::Nul);
    }
    let duree = (secondes as u64).saturating_mul(1_000_000_000).saturating_add(nanosecondes as u64);
    Ok(Delai::Jusqua(temps::ns_monotone().saturating_add(duree)))
}

/// Deux nombres de 64 bits lus chez le programme (un timespec, un timeval).
fn lire_paire(adresse: u64) -> Result<(i64, i64), i64> {
    let mut o = [0u8; 16];
    copier_depuis_utilisateur(&mut o, adresse).map_err(|_| -EFAULT)?;
    let a = i64::from_le_bytes(o[..8].try_into().unwrap_or([0; 8]));
    let b = i64::from_le_bytes(o[8..].try_into().unwrap_or([0; 8]));
    Ok((a, b))
}

/// Un délai donné en timespec par le programme (EFAULT, EINVAL) ; une
/// adresse nulle : attendre toujours.
pub fn delai_timespec(adresse: u64) -> Result<Delai, i64> {
    if adresse == 0 {
        return Ok(Delai::Infini);
    }
    let (s, ns) = lire_paire(adresse)?;
    delai(s, ns)
}

/// La boucle de `do_poll` et de `do_select` : `tour` sonde tout avec la
/// table qu'il reçoit (qui n'inscrit qu'au premier tour) et rend le nombre
/// de prêts ; tant qu'il n'y en a pas, la tâche dort, jusqu'au délai, au
/// réveil d'une de ses entrées, ou à un signal (ERESTARTNOHAND, après un
/// dernier tour : ce qui est prêt passe avant le signal). Un délai nul ne
/// dort ni n'inscrit rien.
fn attendre_prets(delai: Delai, mut tour: impl FnMut(&mut Table) -> usize) -> Result<usize, i64> {
    let attente = Attente { tache: tache::courante_arc(), declenchee: core::cell::Cell::new(false) };
    let mut entrees = Entrees { attente: &attente, blocs: Vec::new(), erreur: false };
    let mut fini = matches!(delai, Delai::Nul);
    let mut premier = !fini;
    let r = loop {
        let n = if premier { tour(&mut Table::new(Some(&mut entrees as &mut dyn Inscrire))) } else { tour(&mut Table::new(None)) };
        premier = false;
        if n > 0 {
            break Ok(n);
        }
        if tache::signal_en_attente() {
            break Err(-ERESTARTNOHAND);
        }
        if entrees.erreur {
            break Err(-ENOMEM);
        }
        if fini {
            break Ok(0);
        }
        // Le `poll_schedule_timeout` de Linux : pas de sommeil si une entrée
        // a déjà été réveillée ; interruptions coupées entre ce constat et
        // le sommeil (attente.rs).
        let interruptions = cpu::couper_interruptions();
        if !attente.declenchee.get() {
            let echeance = match delai {
                Delai::Jusqua(e) => Some(e),
                Delai::Infini | Delai::Nul => None,
            };
            fini = attente::dormir(echeance, Sommeil::Interruptible) == Reveil::Echeance;
        }
        attente.declenchee.set(false);
        if interruptions {
            cpu::activer_interruptions();
        }
    };
    drop(entrees);
    r
}

/// Ce que rend `poll` pour un `struct pollfd` (le `do_pollfd` de Linux) :
/// un numéro négatif ne compte pas (0) ; un numéro fermé, ou un O_PATH (que
/// `fdget` ne rend pas) : POLLNVAL ; sinon ce que dit le sondage, réduit à
/// ce qui est demandé, plus POLLERR et POLLHUP, toujours rendus.
fn sonder_pollfd(fd: i32, evenements: u16, table: &mut Table) -> u32 {
    if fd < 0 {
        return 0;
    }
    let Ok(o) = tenir(fd as u64) else { return POLLNVAL };
    if o.sorte == Sorte::Chemin {
        return POLLNVAL;
    }
    let filtre = evenements as u32 | POLLERR | POLLHUP;
    table.cle = filtre;
    sonder(&o, table) & filtre
}

/// Le `do_sys_poll` de Linux : nfds au-delà de RLIMIT_NOFILE : EINVAL ; le
/// tableau copié (EFAULT) ; l'attente ; puis les `revents` écrits, même
/// interrompu, et pour chaque entrée (EFAULT). Rend le nombre d'entrées
/// prêtes.
fn sys_poll(tableau: u64, nombre: u32, delai: Delai) -> i64 {
    if nombre as u64 > processus::avec(|p| p.descripteurs.limite.0) {
        return -EINVAL;
    }
    let mut octets: Vec<u8> = Vec::new();
    if octets.try_reserve_exact(nombre as usize * 8).is_err() {
        return -ENOMEM;
    }
    octets.resize(nombre as usize * 8, 0);
    if copier_depuis_utilisateur(&mut octets, tableau).is_err() {
        return -EFAULT;
    }
    // Chaque `struct pollfd` : fd (4 octets), events (2), revents (2).
    let r = attendre_prets(delai, |table| {
        let mut prets = 0;
        for p in octets.chunks_exact_mut(8) {
            let fd = i32::from_le_bytes([p[0], p[1], p[2], p[3]]);
            let evenements = u16::from_le_bytes([p[4], p[5]]);
            let m = sonder_pollfd(fd, evenements, table) as u16;
            p[6..8].copy_from_slice(&m.to_le_bytes());
            if m != 0 {
                prets += 1;
                table.arreter();
            }
        }
        prets
    });
    for (i, p) in octets.chunks_exact(8).enumerate() {
        if copier_vers_utilisateur(tableau + i as u64 * 8 + 6, &p[6..8]).is_err() {
            return -EFAULT;
        }
    }
    match r {
        Ok(n) => n as i64,
        Err(e) => e,
    }
}

/// poll(tableau, nombre, délai en ms) : un délai négatif attend toujours.
/// Interrompu par un signal, il sera repris par restart_syscall jusqu'à la
/// même échéance (ERESTART_RESTARTBLOCK : EINTR avec un gestionnaire, même
/// avec SA_RESTART, mesuré).
pub fn poll(tableau: u64, nombre: u64, ms: u64) -> i64 {
    let ms = ms as i32;
    let d = if ms < 0 {
        Delai::Infini
    } else {
        match delai(ms as i64 / 1000, ms as i64 % 1000 * 1_000_000) {
            Ok(d) => d,
            Err(e) => return e,
        }
    };
    reprendre_poll(tableau, nombre as u32, d)
}

/// poll, ou sa reprise par restart_syscall (`do_restart_poll`).
pub fn reprendre_poll(tableau: u64, nombre: u32, delai: Delai) -> i64 {
    let r = sys_poll(tableau, nombre, delai);
    if r == -ERESTARTNOHAND {
        reprise::garder(Reprise::Poll { tableau, nombre, delai });
        return -ERESTART_RESTARTBLOCK;
    }
    r
}

/// Comment écrire le temps restant.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Forme {
    /// Un timespec (secondes, nanosecondes) : ppoll, pselect6.
    Timespec,
    /// Un timeval (secondes, microsecondes) : select.
    Timeval,
}

/// La fin de ppoll, select et pselect6 (`poll_select_finish`) : le masque
/// temporaire rendu, sauf interrompu ; puis, s'il y avait un délai non nul,
/// le temps qui restait écrit à son adresse (même après un succès). S'il ne
/// peut pas l'être, un appel interrompu rend EINTR au lieu d'être refait :
/// refait, il attendrait de nouveau tout son délai.
fn finir(delai: Delai, adresse: u64, forme: Forme, r: i64) -> i64 {
    signaux::fin_du_masque_temporaire(r == -ERESTARTNOHAND);
    let Delai::Jusqua(echeance) = delai else { return r };
    if adresse == 0 {
        return r;
    }
    let reste = echeance.saturating_sub(temps::ns_monotone());
    let secondes = reste / 1_000_000_000;
    let fraction = reste % 1_000_000_000;
    let fraction = if forme == Forme::Timeval { fraction / 1000 } else { fraction };
    let mut o = [0u8; 16];
    o[..8].copy_from_slice(&secondes.to_le_bytes());
    o[8..].copy_from_slice(&fraction.to_le_bytes());
    if copier_vers_utilisateur(adresse, &o).is_ok() {
        return r;
    }
    if r == -ERESTARTNOHAND { -EINTR } else { r }
}

/// ppoll(tableau, nombre, délai en timespec, masque, taille du masque) :
/// dans l'ordre de Linux, le délai (EFAULT, EINVAL), le masque temporaire
/// (EINVAL, EFAULT), puis poll ; ERESTARTNOHAND s'il est interrompu.
pub fn ppoll(tableau: u64, nombre: u64, tsp: u64, masque: u64, taille: u64) -> i64 {
    let d = match delai_timespec(tsp) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if let Err(e) = signaux::masque_temporaire(masque, taille) {
        return e;
    }
    let r = sys_poll(tableau, nombre as u32, d);
    finir(d, tsp, Forme::Timespec, r)
}

/// Ce que demande `select` d'un fichier, et ce qui y répond. POLLNVAL dans
/// les trois : un numéro sans fichier (fermé pendant l'attente par un autre
/// fil, ou un O_PATH) est rendu prêt, pour que le programme le voie (mesuré
/// : un O_PATH demandé en lecture et en écriture compte deux fois).
const POLLIN_SET: u32 = POLLRDNORM | POLLRDBAND | POLLIN | POLLHUP | POLLERR | POLLNVAL;
const POLLOUT_SET: u32 = POLLWRBAND | POLLWRNORM | POLLOUT | POLLERR | POLLNVAL;
const POLLEX_SET: u32 = POLLPRI | POLLNVAL;

/// Les trois ensembles de `select` : lecture, écriture, exceptions, en mots
/// de 64 bits.
type Ensembles = [Vec<u64>; 3];

/// Le `do_select` de Linux : un numéro demandé qui n'est pas pris (ni
/// ouvert, ni réservé par un appel en cours) : EBADF (`max_select_fd`) ;
/// `n` réduit au plus grand demandé ; puis la boucle, qui sonde chaque
/// numéro demandé et range les prêts dans `resultats`. Rend leur nombre (un
/// fichier prêt à lire et à écrire compte deux fois).
fn faire_select(n: u64, demandes: &Ensembles, resultats: &mut Ensembles, d: Delai) -> Result<usize, i64> {
    let bit = |e: &Vec<u64>, fd: u64| e[(fd / 64) as usize] >> (fd % 64) & 1 != 0;
    let demande = |fd: u64| demandes.iter().any(|e| bit(e, fd));
    let mut fin = 0;
    for fd in 0..n {
        if demande(fd) {
            if !processus::avec(|p| p.descripteurs.pris(fd)) {
                return Err(-EBADF);
            }
            fin = fd + 1;
        }
    }
    attendre_prets(d, |table| {
        for r in resultats.iter_mut() {
            r.fill(0);
        }
        let mut prets = 0;
        for fd in (0..fin).filter(|&fd| demande(fd)) {
            let (lire, ecrire, exception) = (bit(&demandes[0], fd), bit(&demandes[1], fd), bit(&demandes[2], fd));
            // `select_poll_one` : un numéro sans fichier (réservé par un appel
            // en cours, ou fermé depuis) ou un O_PATH (que `fdget` ne rend
            // pas) : POLLNVAL.
            let m = match tenir(fd) {
                Ok(o) if o.sorte != Sorte::Chemin => {
                    table.cle = POLLEX_SET | if lire { POLLIN_SET } else { 0 } | if ecrire { POLLOUT_SET } else { 0 };
                    sonder(&o, table)
                }
                _ => POLLNVAL,
            };
            let (mot, masque) = ((fd / 64) as usize, 1u64 << (fd % 64));
            for (k, (voulu, ensemble)) in [(lire, POLLIN_SET), (ecrire, POLLOUT_SET), (exception, POLLEX_SET)].into_iter().enumerate() {
                if voulu && m & ensemble != 0 {
                    resultats[k][mot] |= masque;
                    prets += 1;
                    table.arreter();
                }
            }
        }
        prets
    })
}

/// Le `core_sys_select` de Linux : `n` négatif : EINVAL ; au-delà de la
/// table des descripteurs (la taille qu'aurait celle de Linux), réduit à
/// elle : les bits suivants ne sont ni lus ni écrits ; les ensembles copiés
/// (EFAULT ; une adresse nulle : aucun) ; l'attente ; puis, si rien n'est
/// prêt et qu'un signal attend : ERESTARTNOHAND, les ensembles du programme
/// laissés tels quels ; sinon les résultats écrits (EFAULT).
fn sys_select(n: u64, adresses: [u64; 3], d: Delai) -> i64 {
    let n = n as i32;
    if n < 0 {
        return -EINVAL;
    }
    let n = (n as u64).min(processus::avec(|p| p.descripteurs.taille_linux()));
    let mots = n.div_ceil(64) as usize;
    let mut demandes: Ensembles = [Vec::new(), Vec::new(), Vec::new()];
    let mut resultats: Ensembles = [Vec::new(), Vec::new(), Vec::new()];
    for e in demandes.iter_mut().chain(resultats.iter_mut()) {
        if e.try_reserve_exact(mots).is_err() {
            return -ENOMEM;
        }
        e.resize(mots, 0);
    }
    for (e, &adresse) in demandes.iter_mut().zip(&adresses) {
        if adresse == 0 {
            continue;
        }
        let mut o: Vec<u8> = Vec::new();
        if o.try_reserve_exact(mots * 8).is_err() {
            return -ENOMEM;
        }
        o.resize(mots * 8, 0);
        if copier_depuis_utilisateur(&mut o, adresse).is_err() {
            return -EFAULT;
        }
        for (m, c) in e.iter_mut().zip(o.chunks_exact(8)) {
            *m = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
        }
    }
    let r = match faire_select(n, &demandes, &mut resultats, d) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if r == 0 && tache::signal_en_attente() {
        return -ERESTARTNOHAND;
    }
    for (e, &adresse) in resultats.iter().zip(&adresses) {
        if adresse == 0 {
            continue;
        }
        for (i, m) in e.iter().enumerate() {
            if copier_vers_utilisateur(adresse + i as u64 * 8, &m.to_le_bytes()).is_err() {
                return -EFAULT;
            }
        }
    }
    r as i64
}

/// select(n, lecture, écriture, exceptions, délai en timeval) : le délai
/// (EFAULT ; les microsecondes au-delà d'une seconde comptent comme des
/// secondes, mais négatives : EINVAL, `kern_select`), puis le select ; le
/// temps restant écrit dans le timeval.
pub fn select(n: u64, lecture: u64, ecriture: u64, exceptions: u64, tvp: u64) -> i64 {
    let d = if tvp == 0 {
        Delai::Infini
    } else {
        let r = lire_paire(tvp).and_then(|(s, us)| delai(s.wrapping_add(us / 1_000_000), us % 1_000_000 * 1000));
        match r {
            Ok(d) => d,
            Err(e) => return e,
        }
    };
    let r = sys_select(n, [lecture, ecriture, exceptions], d);
    finir(d, tvp, Forme::Timeval, r)
}

/// pselect6(n, lecture, écriture, exceptions, délai en timespec, {masque,
/// taille}) : le sixième argument désigne une paire (l'adresse du masque et
/// sa taille, EFAULT), lue en premier ; puis le délai, le masque
/// temporaire, et le select.
pub fn pselect6(n: u64, lecture: u64, ecriture: u64, exceptions: u64, tsp: u64, signaux_: u64) -> i64 {
    let (masque, taille) = if signaux_ == 0 {
        (0, 0)
    } else {
        match lire_paire(signaux_) {
            Ok((m, t)) => (m as u64, t as u64),
            Err(e) => return e,
        }
    };
    let d = match delai_timespec(tsp) {
        Ok(d) => d,
        Err(e) => return e,
    };
    if let Err(e) = signaux::masque_temporaire(masque, taille) {
        return e;
    }
    let r = sys_select(n, [lecture, ecriture, exceptions], d);
    finir(d, tsp, Forme::Timespec, r)
}
