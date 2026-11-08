//! Un verrou à attente active (« spinlock »), écrit à la main.
//!
//! Pourquoi un verrou ? Parce que Rust refuse, à juste titre, une variable
//! globale modifiable sans protection : dès qu'il y a des interruptions
//! matérielles (horloge, clavier), des tâches qui se passent le processeur
//! (6e), ou plusieurs processeurs (6j), deux morceaux de code peuvent y
//! écrire en même temps. Le verrou garantit qu'un seul à la fois y accède.
//!
//! Depuis 6j, un TICKET LOCK, le verrou de Linux de 2008 à 2015 : la file
//! d'attente d'une boulangerie. Qui arrive prend un numéro (`prochain`,
//! incrémenté d'une instruction indivisible, `lock xadd`), puis attend que
//! le numéro servi (`servi`) soit le sien ; qui rend le verrou sert le
//! numéro suivant. Chacun passe dans l'ordre d'arrivée : aucun processeur
//! ne peut attendre indéfiniment pendant que d'autres se repassent le
//! verrou, ce qu'un simple « test et bascule » (compare_exchange sur un
//! booléen, le verrou des étapes 3 à 6i) permettrait. Options écartées :
//!   - le qspinlock de Linux (depuis 4.2) : une file MCS, où chaque
//!     attendant tourne sur SA ligne de cache au lieu de tous lire le même
//!     `servi`, dans un mot de 32 bits découpé en champs, avec quatre
//!     niveaux d'imbrication pour les interruptions et le NMI. Il ne gagne
//!     que lorsque des dizaines de processeurs tournent sur le même verrou,
//!     et il prend des centaines de lignes ; le ticket tient en dix ;
//!   - garder le booléen : le verrou de 6e paniquait s'il le trouvait pris,
//!     puisque sur un seul processeur c'était forcément un interblocage ;
//!     avec deux, un verrou pris par l'autre se libère, il faut attendre.
//! Le diagnostic de 6e est gardé pour le cas qu'il visait : le processeur
//! qui tient un verrou le note (`proprietaire`, le `owner_cpu` des
//! spinlocks de débogage de Linux), et le reprendre LUI-MÊME est encore
//! l'interblocage d'un seul processeur (il a coupé les interruptions, rien
//! ne le rendra) : panique, avec l'endroit (#[track_caller]).
//!
//! Piège des interruptions : si le noyau tient le verrou de la console et
//! qu'une interruption d'horloge arrive, et que son gestionnaire veut
//! afficher, il attend un verrou que personne ne rendra jamais (le code qui
//! le tient est justement celui qui a été interrompu) : blocage définitif.
//! D'où la règle de Linux pour les données partagées avec un gestionnaire
//! d'interruption, spin_lock_irqsave : on coupe les interruptions AVANT de
//! prendre le verrou, et on remet leur état d'origine APRÈS l'avoir rendu.
//! Options écartées :
//!   - deux sortes de verrous (avec et sans coupure), comme spin_lock et
//!     spin_lock_irqsave : plus rapide, mais un mauvais choix ne se voit
//!     qu'au premier blocage, des semaines plus tard, et Linux a lockdep
//!     pour l'attraper. Le coût de cli/sti est négligeable pour nous ; ce
//!     que ça coûte vraiment, la latence (un tic retardé), `make verrous`
//!     le mesure pour chaque endroit ; on pourra spécialiser si une mesure
//!     le demande. Et avec une seule sorte, « les interruptions étaient
//!     actives » veut toujours dire « aucun verrou court tenu », ce dont la
//!     préemption se sert (ordonnanceur.rs) ;
//!   - couper les interruptions sans mémoriser leur état, puis toujours les
//!     réactiver : faux si le verrou est pris dans un gestionnaire (elles
//!     doivent y rester coupées) ou pendant le démarrage.
//!
//! LA RÈGLE DES ATTENTES (6j) : on n'attend jamais, interruptions coupées,
//! une chose dont la fin peut elle-même attendre une interruption entre
//! processeurs (une IPI : smp.rs). Le ticket lock la respecte parce qu'on
//! n'ATTEND jamais la réponse d'une IPI en tenant un `Verrou` (le vidage
//! des TLB se fait hors du verrou des tables, espace_utilisateur.rs ; une
//! IPI de reprogrammation, envoyée sous le verrou d'une file des prêtes,
//! n'attend rien) : celui qu'on attend finira. Un verrou perdu (une erreur du noyau) se verrait sinon par une
//! machine figée : une attente de plus d'une seconde est dite, une fois,
//! sur le port série seul (sans verrou : c'est peut-être celui de la
//! console qu'on attend), et une attente de trente secondes panique. Pas
//! avant : sous QEMU sans accélération, un fil de processeur virtuel peut
//! être suspendu par la machine hôte, et un ticket lock sert dans l'ordre,
//! l'attendant suspendu bloque ceux qui sont derrière lui même quand le
//! verrou est libre (la raison pour laquelle Linux, dans une machine
//! virtuelle, a remplacé le ticket par un qspinlock « paravirtualisé »).
//! Sans TSC fiable (tsc.rs), l'attente n'est pas mesurée.
//!
//! Combien de temps un verrou garde-t-il les interruptions coupées, et
//! combien de temps attend-on pour le prendre ? Avec la fonctionnalité
//! `verrous` (make verrous), le noyau le mesure pour chaque endroit qui en
//! prend un (`statistiques`, plus bas) : le `lock_stat` de Linux, pour la
//! part qui nous importe.

use crate::{cpu, processeur};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// Le nombre de verrous tenus sur le processeur (le `preempt_count` de
/// Linux, pour la part des verrous) : l'ordonnanceur refuse de céder le
/// processeur s'il n'est pas nul (ordonnanceur.rs). Un compteur pour le
/// processeur, pas pour la tâche : un verrou coupe les interruptions, la
/// tâche qui le tient ne peut pas être remplacée avant de l'avoir rendu.
/// Dans la zone du processeur (processeur.rs). Lu interruptions actives
/// aussi : s'il n'est pas nul, c'est nous qui tenons ces verrous, et nous
/// ne pouvons pas être déplacés sur un autre processeur ; s'il est nul, il
/// le reste tant que nous ne prenons rien (l'exception écrite dans
/// processeur.rs).
pub fn tenus() -> u32 {
    processeur::tenus_bruts()
}

pub struct Verrou<T> {
    /// Le prochain numéro à distribuer (la « queue » de la file, le `tail`
    /// de Linux), pris par `lock xadd`.
    prochain: AtomicU16,
    /// Le numéro servi (la « tête », le `head`), écrit par le seul
    /// détenteur quand il rend le verrou.
    servi: AtomicU16,
    /// Le processeur qui le tient, plus un (0 : personne) : le diagnostic
    /// de l'interblocage d'un seul processeur, voir l'en-tête.
    proprietaire: AtomicU32,
    donnee: UnsafeCell<T>,
}

// SAFETY: l'accès à `donnee` ne se fait qu'à travers une Garde, et le
// ticket garantit qu'il n'existe qu'une Garde à la fois (un seul numéro
// est servi).
unsafe impl<T: Send> Sync for Verrou<T> {}

/// Une seconde, puis trente, en nanosecondes : l'attente dite, puis celle
/// qui panique (voir l'en-tête).
const ATTENTE_DITE: u64 = 1_000_000_000;
const ATTENTE_FATALE: u64 = 30_000_000_000;

impl<T> Verrou<T> {
    pub const fn new(donnee: T) -> Self {
        Verrou {
            prochain: AtomicU16::new(0),
            servi: AtomicU16::new(0),
            proprietaire: AtomicU32::new(0),
            donnee: UnsafeCell::new(donnee),
        }
    }

    /// Prend le verrou : coupe les interruptions, prend un numéro, attend
    /// son tour. Un verrou que ce processeur tient déjà ne sera JAMAIS
    /// rendu (son détenteur, c'est nous, interrompus par une exception ou
    /// un NMI, ou revenus là par erreur) : panique avec l'endroit, plutôt
    /// qu'attendre pour toujours. La panique peut toujours afficher : elle
    /// force d'abord le verrou de la console (console::preparer_panique).
    #[track_caller]
    pub fn verrouiller(&self) -> Garde<'_, T> {
        let interruptions_actives = cpu::couper_interruptions();
        // Interruptions coupées : la zone est celle de ce processeur.
        let p = processeur::courant();
        let moi = p.numero + 1;
        if self.proprietaire.load(Ordering::Relaxed) == moi {
            panic!("verrou deja pris par ce processeur : interblocage");
        }
        // SeqCst, pour le modèle de Rust (sur x86, `lock xadd` quel que
        // soit l'ordre demandé) : une tâche qui a posé « je vais dormir »
        // (un xchg) puis prend un verrou pour lire sa condition doit voir
        // ce qu'un autre processeur a écrit sous ce verrou avant de la
        // réveiller (attente.rs : le motif de Dekker, fermé par deux
        // barrières complètes).
        let mon = self.prochain.fetch_add(1, Ordering::SeqCst);
        // Acquire : les écritures faites sous le verrou par le détenteur
        // précédent sont visibles une fois son `servi` (Release) lu.
        let attente = if self.servi.load(Ordering::Acquire) == mon { None } else { Some(self.attendre(mon)) };
        self.proprietaire.store(moi, Ordering::Relaxed);
        p.tenus.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(feature = "verrous"))]
        let _ = attente;
        Garde {
            verrou: self,
            interruptions_actives,
            #[cfg(feature = "verrous")]
            debut: statistiques::Debut::maintenant(attente),
        }
    }

    /// Attend que `mon` soit servi : la boucle des spinlocks, `pause` entre
    /// deux lectures (le processeur relâche l'autre fil de son cœur, et ne
    /// spécule pas des dizaines de lectures d'avance). Rend la durée de
    /// l'attente en cycles du TSC (0 sans TSC fiable). Toutes les 1024
    /// lectures, le temps : dit à une seconde, fatal à trente.
    #[track_caller]
    fn attendre(&self, mon: u16) -> u64 {
        let debut = crate::tsc::lire();
        let mut tours: u32 = 0;
        let mut dit = false;
        while self.servi.load(Ordering::Acquire) != mon {
            core::hint::spin_loop();
            tours = tours.wrapping_add(1);
            if tours % 1024 == 0 {
                let ns = crate::tsc::en_nanosecondes(crate::tsc::lire().wrapping_sub(debut));
                if ns > ATTENTE_FATALE {
                    panic!("verrou attendu depuis {} s : perdu", ns / 1_000_000_000);
                }
                if ns > ATTENTE_DITE && !dit {
                    dit = true;
                    let lieu = core::panic::Location::caller();
                    crate::console::urgence(format_args!(
                        "[verrou] {}:{} : le processeur {} attend depuis plus d'une seconde (tenu par le processeur {})\n",
                        lieu.file(), lieu.line(), processeur::numero(),
                        self.proprietaire.load(Ordering::Relaxed).wrapping_sub(1)));
                }
            }
        }
        crate::tsc::lire().wrapping_sub(debut)
    }

    /// Ce processeur tient-il ce verrou ? Pour un `assert!` d'ordre des
    /// verrous (processus.rs : jamais celui d'un processus sous celui des
    /// fichiers). S'il ne tient aucun verrou, non, et les deux lectures qui
    /// suivent ne sont pas faites : interruptions actives, la tâche
    /// pourrait être déplacée entre la lecture de son numéro de processeur
    /// et celle du propriétaire, et se croire détentrice d'un verrou que
    /// son ancien processeur vient de prendre. S'il en tient un, les
    /// interruptions sont coupées et son numéro ne bouge pas.
    pub fn tenu_par_ce_processeur(&self) -> bool {
        tenus() != 0 && self.proprietaire.load(Ordering::Relaxed) == processeur::numero() + 1
    }

    /// La donnée, sans prendre le verrou : `&mut self` prouve que personne
    /// d'autre ne peut l'avoir (le `get_mut` des verrous de la bibliothèque
    /// standard). Les interruptions restent comme elles sont : celui qui
    /// tient la mémoire d'un processus en écriture touche ainsi ses tables
    /// de pages sans les couper (memoire.rs).
    pub fn get_mut(&mut self) -> &mut T {
        self.donnee.get_mut()
    }

    /// Remet le verrou à neuf, libre, même si quelqu'un le tient ou
    /// l'attend : le `zap_locks` de Linux pour sa console en cas de panique.
    ///
    /// # Safety
    /// Seulement quand le détenteur et les attendants ne reprendront jamais
    /// la main : en cas de panique, les autres processeurs arrêtés, juste
    /// avant d'écrire le message (voir console.rs).
    pub unsafe fn forcer_liberation(&self) {
        self.proprietaire.store(0, Ordering::Relaxed);
        self.prochain.store(0, Ordering::Relaxed);
        self.servi.store(0, Ordering::Release);
    }
}

/// Tant qu'elle existe, on tient le verrou ; il se libère tout seul quand
/// elle disparaît (Drop), même en sortie anticipée : impossible de l'oublier.
pub struct Garde<'a, T> {
    verrou: &'a Verrou<T>,
    interruptions_actives: bool,
    /// Quand et où les interruptions ont été coupées, et combien on a
    /// attendu (make verrous).
    #[cfg(feature = "verrous")]
    debut: statistiques::Debut,
}

impl<T> Deref for Garde<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: la Garde prouve qu'on tient le verrou.
        unsafe { &*self.verrou.donnee.get() }
    }
}

impl<T> DerefMut for Garde<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: idem, et &mut self garantit l'exclusivité locale.
        unsafe { &mut *self.verrou.donnee.get() }
    }
}

impl<T> Drop for Garde<'_, T> {
    fn drop(&mut self) {
        // Encore interruptions coupées (elles ne reviennent qu'en dessous).
        processeur::courant().tenus.fetch_sub(1, Ordering::Relaxed);
        // Le propriétaire effacé AVANT de servir le suivant (sinon « le même
        // processeur reprend son verrou » pourrait se tromper sur une
        // valeur restée), puis le numéro suivant servi : une simple
        // écriture, seul le détenteur touche à `servi`. Release : ce qu'on
        // a écrit sous le verrou est visible par le prochain qui le prend.
        self.verrou.proprietaire.store(0, Ordering::Relaxed);
        let servi = self.verrou.servi.load(Ordering::Relaxed);
        self.verrou.servi.store(servi.wrapping_add(1), Ordering::Release);
        // Dans cet ordre : rendre le verrou, puis seulement laisser revenir
        // les interruptions, sinon une interruption pourrait encore le
        // trouver pris.
        if self.interruptions_actives {
            // Le premier verrou de la série, celui qui a coupé les
            // interruptions : il les remet, on compte depuis lui. Ceux
            // qu'on a pris en le tenant sont dans son temps.
            #[cfg(feature = "verrous")]
            statistiques::noter(&self.debut);
            cpu::activer_interruptions();
        }
    }
}

/// Les statistiques des verrous (la fonctionnalité `verrous`, make
/// verrous) : pour chaque endroit du noyau qui prend un `Verrou` alors que
/// les interruptions étaient actives (le premier d'une série : il les
/// coupe, et les remet en le rendant), le plus long temps qu'il les a
/// gardées coupées, combien de fois au-delà d'une milliseconde, combien de
/// prises ; et depuis 6j la CONTENTION : combien de fois il a dû attendre
/// qu'un autre processeur rende le verrou, et le plus longtemps. Le
/// lanceur les affiche après chaque programme (programmes.rs), et les
/// remet à zéro.
///
/// Pourquoi ce temps-là : tant que les interruptions sont coupées, le tic
/// d'horloge attend (une échéance de TCP, un réveil, la préemption), et
/// les suivants sont perdus : l'APIC ne garde qu'une interruption en
/// attente par vecteur. C'est ce que le verrou de la mémoire qui dort (6i)
/// devait faire baisser. Et la contention dit quels verrous un cache par
/// processeur soulagerait (le tas, le générateur : 6j, d'après la mesure).
///
/// L'endroit : celui de l'appel à `verrouiller`, ou à la fonction qui le
/// prend pour son appelant (`processus::avec`, `vfs::avec_systeme`...,
/// marquées `#[track_caller]`) : sinon, tout le processus serait « dans
/// processus.rs ».
///
/// C'est le `lock_stat` de Linux (CONFIG_LOCK_STAT, /proc/lock_stat, ses
/// colonnes holdtime-max, waittime-max et contentions), et son traceur
/// `irqsoff` pour la part qui coupe les interruptions ; mesuré au TSC
/// (`tsc::lire`, quelques dizaines de cycles). Sans la fonctionnalité,
/// rien n'est mesuré ni gardé : la garde n'a pas même le champ.
///
/// UNE TABLE PAR PROCESSEUR, comme les compteurs de lock_stat : chaque
/// processeur écrit dans la sienne (interruptions coupées : c'est bien la
/// sienne), et l'affichage les réunit. Une seule table, d'atomiques, serait
/// juste aussi, mais chaque libération y ferait écrire quatre processeurs
/// dans les mêmes lignes de cache : l'outil de mesure disputerait ce qu'il
/// mesure. Les tables sont statiques (dans la .bss, mise à zéro au
/// démarrage) : mesurer ne doit rien allouer, on est sous un verrou,
/// peut-être celui du tas ; 10 Kio par processeur, seulement avec la
/// fonctionnalité. Une mesure faite pendant l'affichage, par un autre
/// processeur, peut être perdue : sans conséquence pour un outil.
///
/// Options écartées : un seuil d'ECHEC au démarrage (sous QEMU sans
/// accélération, ce temps dépend de la machine hôte, de 10 à 30 fois celui
/// d'un vrai processeur, et la console, qui attend le port série octet par
/// octet, dépasse tout jusqu'en 6k) ; mesurer aussi les interruptions
/// coupées hors des verrous (les gestionnaires d'interruption, `dormir`) :
/// il faudrait instrumenter chaque `cli` et l'entrée de chaque vecteur,
/// pour des sections courtes, que le code borne déjà.
#[cfg(feature = "verrous")]
pub mod statistiques {
    use crate::processeur;
    use core::panic::Location;
    use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

    /// Quand et où une série de verrous a commencé, et l'attente qui a
    /// précédé (en cycles ; None : pris du premier coup).
    pub struct Debut {
        tsc: u64,
        lieu: &'static Location<'static>,
        attente: Option<u64>,
    }

    impl Debut {
        /// Maintenant, à l'endroit de l'appel (à travers les fonctions
        /// `#[track_caller]` qui ont mené jusqu'ici).
        #[track_caller]
        pub fn maintenant(attente: Option<u64>) -> Debut {
            Debut { tsc: crate::tsc::lire(), lieu: Location::caller(), attente }
        }
    }

    /// Un endroit du noyau et ce qu'on a mesuré de lui. Tout en atomiques :
    /// une place se prend sans verrou (on mesure les verrous), et les
    /// compteurs s'écrivent depuis n'importe quelle tâche ou interruption.
    struct Endroit {
        lieu: AtomicPtr<Location<'static>>,
        max: AtomicU64,
        longues: AtomicU32,
        prises: AtomicU64,
        /// La plus longue attente d'un autre processeur, et combien de fois
        /// il a fallu attendre.
        attente_max: AtomicU64,
        contentions: AtomicU32,
    }

    impl Endroit {
        const fn new() -> Endroit {
            Endroit {
                lieu: AtomicPtr::new(core::ptr::null_mut()),
                max: AtomicU64::new(0),
                longues: AtomicU32::new(0),
                prises: AtomicU64::new(0),
                attente_max: AtomicU64::new(0),
                contentions: AtomicU32::new(0),
            }
        }

        /// Les compteurs à zéro ; l'endroit garde sa place pour toujours :
        /// la rendre pendant qu'un autre processeur, qui vient de la
        /// trouver pour cet endroit, y écrit encore, la laisserait prendre
        /// par un autre endroit, et les deux se mêleraient (la relecture de
        /// 6j). Les places ne manquent pas (voir PLACES).
        fn remettre_a_zero(&self) {
            self.max.store(0, Ordering::Relaxed);
            self.longues.store(0, Ordering::Relaxed);
            self.prises.store(0, Ordering::Relaxed);
            self.attente_max.store(0, Ordering::Relaxed);
            self.contentions.store(0, Ordering::Relaxed);
        }
    }

    /// Les endroits mesurés depuis la dernière remise à zéro, par
    /// processeur. Une table fixe, pas un tableau qui grandit : mesurer ne
    /// doit rien allouer. 256 places : le démarrage complet de 6h en prend
    /// un peu plus de 120.
    const PLACES: usize = 256;
    struct Table([Endroit; PLACES]);
    static TABLES: [Table; processeur::MAX] = [const { Table([const { Endroit::new() }; PLACES]) }; processeur::MAX];
    /// Les mesures perdues faute de place (dites à l'affichage).
    static PERDUES: AtomicU64 = AtomicU64::new(0);

    /// La place de l'endroit `cle` dans la table `t`, ou la première libre
    /// (prise d'un seul compare_exchange : jamais deux places pour un même
    /// endroit dans une table).
    fn place<'a>(t: &'a Table, cle: *mut Location<'static>) -> Option<&'a Endroit> {
        t.0.iter().find(|e| {
            let lieu = e.lieu.load(Ordering::Relaxed);
            lieu == cle
                || (lieu.is_null()
                    && e.lieu.compare_exchange(lieu, cle, Ordering::Relaxed, Ordering::Relaxed).map_or_else(|autre| autre == cle, |_| true))
        })
    }

    /// Note la fin d'une série commencée à `debut`. Interruptions encore
    /// coupées : la table est celle de ce processeur.
    pub fn noter(debut: &Debut) {
        let duree = crate::tsc::lire().wrapping_sub(debut.tsc);
        let cle = debut.lieu as *const Location<'static> as *mut Location<'static>;
        let t = &TABLES[processeur::courant().numero as usize];
        let Some(e) = place(t, cle) else {
            PERDUES.fetch_add(1, Ordering::Relaxed);
            return;
        };
        e.max.fetch_max(duree, Ordering::Relaxed);
        e.prises.fetch_add(1, Ordering::Relaxed);
        if crate::tsc::en_nanosecondes(duree) > 1_000_000 {
            e.longues.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(attente) = debut.attente {
            e.attente_max.fetch_max(attente, Ordering::Relaxed);
            e.contentions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Un endroit réuni sur tous les processeurs (l'adresse de son
    /// `Location`, en entier : un pointeur brut n'irait pas sous un Verrou).
    #[derive(Clone, Copy)]
    struct Reuni {
        lieu: usize,
        max: u64,
        longues: u32,
        prises: u64,
        attente_max: u64,
        contentions: u32,
    }

    /// La table des endroits réunis, pour l'affichage : statique (12 Kio),
    /// pas sur la pile de la tâche qui affiche (16 Kio, dont le lanceur a
    /// besoin pour lui : « Piles du noyau » le mesure).
    static REUNIS: crate::verrou::Verrou<[Option<Reuni>; PLACES]> = crate::verrou::Verrou::new([None; PLACES]);

    /// Affiche les `n` endroits qui ont gardé les interruptions coupées le
    /// plus longtemps depuis la dernière fois (pour `quoi` : un programme,
    /// le démarrage), avec leur contention, puis remet tout à zéro. Les
    /// tables des processeurs en service sont réunies endroit par endroit.
    pub fn afficher(quoi: impl core::fmt::Display) {
        const N: usize = 8;
        let mut reunis = REUNIS.verrouiller();
        reunis.fill(None);
        let mut perdues = 0u64;
        for n in 0..processeur::nombre() {
            for e in &TABLES[n].0 {
                let lieu = e.lieu.load(Ordering::Relaxed) as usize;
                if lieu == 0 {
                    continue;
                }
                let mesure = Reuni {
                    lieu,
                    max: e.max.load(Ordering::Relaxed),
                    longues: e.longues.load(Ordering::Relaxed),
                    prises: e.prises.load(Ordering::Relaxed),
                    attente_max: e.attente_max.load(Ordering::Relaxed),
                    contentions: e.contentions.load(Ordering::Relaxed),
                };
                match reunis.iter_mut().find(|r| r.is_none_or(|r| r.lieu == lieu)) {
                    Some(Some(r)) => {
                        r.max = r.max.max(mesure.max);
                        r.longues += mesure.longues;
                        r.prises += mesure.prises;
                        r.attente_max = r.attente_max.max(mesure.attente_max);
                        r.contentions += mesure.contentions;
                    }
                    Some(place) => *place = Some(mesure),
                    None => perdues += 1,
                }
            }
        }
        // Les N plus longs, par sélection (sans allouer ni trier la table).
        let mut choisis: [Option<usize>; N] = [None; N];
        for rang in 0..N {
            let meilleur = (0..PLACES)
                .filter(|&i| reunis[i].is_some() && !choisis.contains(&Some(i)))
                .max_by_key(|&i| reunis[i].map_or(0, |r| r.max));
            choisis[rang] = meilleur;
        }
        afficherln!("[verrous] {} : les interruptions coupees le plus longtemps, par endroit :", quoi);
        for r in choisis.into_iter().flatten().filter_map(|i| reunis[i]) {
            // SAFETY: on ne range dans `lieu` que des `&'static Location`
            // (`noter`), jamais libérées ; non nul : filtré plus haut.
            let lieu = unsafe { &*(r.lieu as *const Location<'static>) };
            afficherln!("[verrous]   {}:{} : {} us au plus, {} fois plus d'1 ms, {} prises ; attendu {} fois, {} us au plus",
                        lieu.file(), lieu.line(), crate::tsc::en_nanosecondes(r.max) / 1000, r.longues, r.prises,
                        r.contentions, crate::tsc::en_nanosecondes(r.attente_max) / 1000);
        }
        let perdues = perdues + PERDUES.swap(0, Ordering::Relaxed);
        if perdues > 0 {
            afficherln!("[verrous]   ({} mesures perdues : plus de {} endroits)", perdues, PLACES);
        }
        for n in 0..processeur::nombre() {
            for e in &TABLES[n].0 {
                e.remettre_a_zero();
            }
        }
    }
}
