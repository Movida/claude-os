//! getrusage : ce qu'un programme a consommé (le temps de calcul, en
//! anneau 3 et dans le noyau, sa plus grande mémoire résidente, ses fautes
//! de page, ses bascules). `claude -p` le demande dès son démarrage
//! (`process.cpuUsage()` de Bun) : sans lui, « Failed to get CPU usage ».
//!
//! Le temps (choix de conception) : comme le Linux d'une distribution
//! (CONFIG_TICK_CPU_ACCOUNTING), en deux temps :
//!   1. à chaque tic d'horloge, la tâche courante compte un tic « en
//!      anneau 3 » ou « dans le noyau », d'après l'endroit où le tic l'a
//!      trouvée (le CS du cadre interrompu : `account_process_tick`) ;
//!   2. à la lecture, ces deux comptes ne donnent que la PROPORTION : le
//!      temps total est le temps de calcul exact, celui que l'ordonnanceur
//!      compte au TSC à chaque bascule et à chaque tic (le
//!      `sum_exec_runtime`) ; utime + stime lui sont égaux, dans la
//!      proportion des tics (`cputime_adjust`, kernel/sched/cputime.c).
//!      Sans tic du tout, tout est compté en anneau 3. Et rien ne recule
//!      jamais : le dernier résultat rendu est gardé, et l'un des deux ne
//!      peut que grandir (ce que vérifie un programme qui fait deux
//!      mesures).
//! Options écartées :
//!   - mesurer au TSC chaque entrée dans le noyau et chaque sortie (le
//!     VIRT_CPU_ACCOUNTING_GEN de Linux) : exact, mais deux lectures du
//!     TSC et de la comptabilité par appel système et par interruption ;
//!     Linux ne le prend que pour les processeurs sans tic (nohz_full) ;
//!   - tout rendre en utime : un programme qui compare les deux (un
//!     profileur, `time`) se tromperait du tout au tout.
//!
//! Le reste, comme Linux (`getrusage`, kernel/sys.c) :
//!   - `ru_maxrss` : la plus grande mémoire résidente du processus, en Kio
//!     (le `hiwater_rss` de l'espace d'adressage, espace_utilisateur.rs) ;
//!   - `ru_minflt` : les fautes de page servies, celles du programme et
//!     celles des copies du noyau vers lui (`mm_account_fault`) ;
//!     `ru_majflt` : 0, aucune n'attend un disque (6l) ;
//!   - `ru_nvcsw` : les bascules où la tâche a cédé le processeur parce
//!     qu'elle s'endormait (ou mourait) ; `ru_nivcsw` : celles où elle a été
//!     préemptée, ou a cédé par sched_yield en restant prête (`__schedule`) ;
//!   - les autres champs à 0, comme chez Linux (ixrss, idrss, isrss, nswap,
//!     msgsnd, msgrcv, nsignals n'y sont plus tenus ; inblock et oublock
//!     comptent les blocs d'un disque).
//! Pour RUSAGE_SELF, tous les fils : les vivants, et ce que les morts ont
//! laissé à leur processus en finissant (le `signal_struct` de Linux) ;
//! pour RUSAGE_THREAD, le fil seul (le temps est celui de la tâche
//! courante, le reste de même, maxrss celle du processus) ; RUSAGE_CHILDREN,
//! les enfants recueillis : aucun programme n'en a avant 6k (fork), tout est
//! à 0, ce que dirait Linux pour un processus sans enfant recueilli.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::copie_utilisateur::copier_vers_utilisateur;
use crate::verrou::Verrou;
use crate::{processus, tache};

const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

const RUSAGE_SELF: i32 = 0;
const RUSAGE_CHILDREN: i32 = -1;
const RUSAGE_THREAD: i32 = 1;

/// Ce que compte une tâche (le fil d'un programme) pour getrusage. Atomique :
/// le gestionnaire d'horloge et l'ordonnanceur comptent sans verrou.
#[derive(Default)]
pub struct Compteurs {
    /// Les tics qui l'ont trouvée en anneau 3, et dans le noyau.
    tics_programme: AtomicU64,
    tics_noyau: AtomicU64,
    /// Les fautes de page servies pour elle.
    fautes: AtomicU64,
    /// Ses bascules volontaires (elle s'endort) et forcées (préemptée).
    volontaires: AtomicU64,
    forcees: AtomicU64,
}

impl Compteurs {
    /// Un tic d'horloge l'a trouvée en anneau 3 (`programme`) ou dans le
    /// noyau.
    pub fn compter_tic(&self, programme: bool) {
        let c = if programme { &self.tics_programme } else { &self.tics_noyau };
        c.fetch_add(1, Ordering::Relaxed);
    }

    /// Une faute de page servie pour elle.
    pub fn compter_faute(&self) {
        self.fautes.fetch_add(1, Ordering::Relaxed);
    }

    /// Elle cède le processeur, en s'endormant (`volontaire`) ou non.
    pub fn compter_bascule(&self, volontaire: bool) {
        let c = if volontaire { &self.volontaires } else { &self.forcees };
        c.fetch_add(1, Ordering::Relaxed);
    }

    fn lire(&self) -> Cumul {
        Cumul {
            tics_programme: self.tics_programme.load(Ordering::Relaxed),
            tics_noyau: self.tics_noyau.load(Ordering::Relaxed),
            fautes: self.fautes.load(Ordering::Relaxed),
            volontaires: self.volontaires.load(Ordering::Relaxed),
            forcees: self.forcees.load(Ordering::Relaxed),
        }
    }
}

/// Des comptes additionnés : ceux d'un fil, ou ce que les fils morts d'un
/// processus lui ont laissé.
#[derive(Clone, Copy, Default)]
pub struct Cumul {
    tics_programme: u64,
    tics_noyau: u64,
    fautes: u64,
    volontaires: u64,
    forcees: u64,
}

impl Cumul {
    fn ajouter(&mut self, autre: Cumul) {
        self.tics_programme += autre.tics_programme;
        self.tics_noyau += autre.tics_noyau;
        self.fautes += autre.fautes;
        self.volontaires += autre.volontaires;
        self.forcees += autre.forcees;
    }
}

/// Le dernier partage rendu entre utime et stime (le `prev_cputime` de
/// Linux) : une tâche, et un processus, ont le leur.
pub struct Precedent(Verrou<(u64, u64)>);

impl Precedent {
    pub const fn new() -> Precedent {
        Precedent(Verrou::new((0, 0)))
    }

    /// Partage `total` (le temps de calcul exact, en ns) entre l'anneau 3
    /// et le noyau, dans la proportion des tics comptés : le
    /// `cputime_adjust` de Linux, ligne à ligne. Rend (utime, stime).
    fn partager(&self, tics_programme: u64, tics_noyau: u64, total: u64) -> (u64, u64) {
        let mut prec = self.0.verrouiller();
        let (prec_u, prec_s) = *prec;
        // Le temps total ne recule pas : s'il n'a pas avancé depuis la
        // dernière fois, le même partage.
        if prec_u + prec_s >= total {
            return *prec;
        }
        let mut stime = if tics_noyau == 0 {
            0
        } else if tics_programme == 0 {
            total
        } else {
            // Sur 128 bits : tics × temps en ns ne tient pas toujours en 64.
            ((tics_noyau as u128 * total as u128) / (tics_noyau + tics_programme) as u128) as u64
        };
        // stime ne recule pas ; utime non plus, puisque le total avance.
        stime = stime.max(prec_s).min(total);
        let mut utime = total - stime;
        if utime < prec_u {
            utime = prec_u;
            stime = total - utime;
        }
        *prec = (utime, stime);
        (utime, stime)
    }
}

/// Ce que les fils morts d'un processus lui ont laissé, et son dernier
/// partage du temps (au processus : `processus::Entree`).
pub struct DuProcessus {
    morts: Verrou<Cumul>,
    precedent: Precedent,
}

impl DuProcessus {
    pub const fn new() -> DuProcessus {
        DuProcessus {
            morts: Verrou::new(Cumul { tics_programme: 0, tics_noyau: 0, fautes: 0, volontaires: 0, forcees: 0 }),
            precedent: Precedent::new(),
        }
    }

    /// Un fil du processus finit : ses comptes restent au processus (le
    /// `__exit_signal` de Linux).
    pub fn garder(&self, c: &Compteurs) {
        self.morts.verrouiller().ajouter(c.lire());
    }
}

/// Le `struct rusage` de Linux (144 octets) : utime et stime en `timeval`,
/// puis quatorze `long`.
fn octets(utime: u64, stime: u64, c: &Cumul, maxrss_kio: u64) -> [u8; 144] {
    let mut o = [0u8; 144];
    let mut mot = |i: usize, v: u64| o[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    mot(0, utime / 1_000_000_000);
    mot(1, utime % 1_000_000_000 / 1000);
    mot(2, stime / 1_000_000_000);
    mot(3, stime % 1_000_000_000 / 1000);
    // ru_maxrss, ixrss, idrss, isrss, minflt, majflt, nswap, inblock,
    // oublock, msgsnd, msgrcv, nsignals, nvcsw, nivcsw.
    mot(4, maxrss_kio);
    mot(8, c.fautes);
    mot(16, c.volontaires);
    mot(17, c.forcees);
    o
}

/// getrusage(qui, tampon) : RUSAGE_SELF, RUSAGE_THREAD, RUSAGE_CHILDREN ;
/// tout autre (RUSAGE_BOTH compris, qui ne sert qu'au noyau) : EINVAL,
/// avant le tampon. Un tampon invalide : EFAULT.
pub fn getrusage(qui: u64, tampon: u64) -> i64 {
    let qui = qui as u32 as i32;
    if qui != RUSAGE_SELF && qui != RUSAGE_THREAD && qui != RUSAGE_CHILDREN {
        return -EINVAL;
    }
    let o = if qui == RUSAGE_CHILDREN {
        octets(0, 0, &Cumul::default(), 0)
    } else {
        let t = tache::courante();
        let entree = t.processus().expect("getrusage sans processus").clone();
        let (cumul, maxrss) = processus::avec(|p| {
            let maxrss = p.memoire.espace.pic() as u64 * 4;
            if qui == RUSAGE_THREAD {
                return (t.usage().lire(), maxrss);
            }
            let mut c = *entree.usage().morts.verrouiller();
            for f in p.fils.iter() {
                if let Some(tf) = f.tache.upgrade() {
                    c.ajouter(tf.usage().lire());
                }
            }
            (c, maxrss)
        });
        let (utime, stime) = if qui == RUSAGE_THREAD {
            t.precedent().partager(cumul.tics_programme, cumul.tics_noyau, tache::temps_de_calcul())
        } else {
            entree.usage().precedent.partager(cumul.tics_programme, cumul.tics_noyau, entree.temps_de_calcul())
        };
        octets(utime, stime, &cumul, maxrss)
    };
    if copier_vers_utilisateur(tampon, &o).is_err() {
        return -EFAULT;
    }
    0
}
