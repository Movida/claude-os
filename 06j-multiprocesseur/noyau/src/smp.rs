//! Les processeurs secondaires : leur réveil par le premier (INIT, puis
//! deux SIPI), leur première fonction Rust (`depart_secondaire`), et la
//! poignée de main entre les deux.
//!
//! Au démarrage de la machine, un seul processeur exécute le micrologiciel
//! puis notre chargeur : le « processeur de démarrage » (le BSP d'Intel).
//! Les autres (les AP) attendent, arrêtés, qu'on leur envoie par l'APIC la
//! séquence définie par la « MultiProcessor Specification » (1997) et
//! toujours en vigueur : une interruption INIT (le processeur revient à son
//! état de mise sous tension), 10 ms, puis deux SIPI (Startup IPI : « va
//! exécuter la page N de la mémoire basse »), à 200 µs d'intervalle ; le
//! second SIPI est pour les anciens processeurs qui rataient le premier,
//! et un processeur déjà parti l'ignore. C'est `wakeup_secondary_cpu_via_init`
//! de Linux (smpboot.c), un processeur à la fois, dans l'ordre de la MADT
//! (acpi.rs), sauf le nôtre (un INIT à soi-même redémarrerait la machine).
//! Options écartées : réveiller les processeurs en parallèle
//! (STARTUP_PARALLEL, Linux 6.5 et plus, pour des machines à centaines de
//! cœurs) ; sauter les 10 ms de l'INIT, comme Linux sur les Intel de
//! famille 6 (notre Nehalem en est) : 30 ms au démarrage pour trois
//! processeurs ne valent pas un chemin qui dépend du fabricant.
//!
//! Ce que le premier processeur PRÉPARE pour chacun avant son SIPI : sa
//! zone (processeur.rs), sa tâche inactive (une `Tache` « inactive-N », sa
//! pile de vmalloc sous sa page de garde ; elle n'entre ni dans la table des
//! tâches ni dans une file), ses quatre piles de l'IST (gdt.rs : celles du
//! premier sont dans la .bss, celles des secondaires viennent de vmalloc),
//! et l'en-tête du trampoline (trampoline.rs : sa pile, sa zone, son
//! numéro, le numéro d'APIC attendu).
//!
//! Ce que le secondaire fait ensuite lui-même, dans `depart_secondaire`,
//! c'est ce que `noyau_main` fait pour le processeur et rien de ce qu'il
//! fait pour la machine (le `cpu_init` de Linux) : sa GDT et sa TSS, l'IDT
//! commune, les MSR de `syscall`, XCR0 ; puis il COMPARE ses CR0, CR4, EFER
//! et XCR0 à ceux du premier, et dit ECHEC s'ils diffèrent (sans CR0.WP, par
//! exemple, une copie du noyau vers une page en lecture seule d'un programme
//! écrirait à travers, et la page de zéros, partagée par tous les
//! programmes, cesserait d'être nulle sans un mot) ; son APIC local
//! (apic.rs, `initialiser_processeur` : SVR, LVT, TPR, ESR ; la projection
//! de la page et la lecture de la MADT restent au premier) ; puis la
//! vérification de son TSC (tsc.rs), et sa boucle d'inactivité.
//!
//! LA POIGNÉE DE MAIN, dans les deux sens, par un mot de sa zone
//! (`demarrage`, les valeurs du module `etape`) : le secondaire dit
//! « arrivé » ; le premier attend ce mot jusqu'à 5 s (sinon il le dit,
//! « ne repond pas », et continue avec un processeur de moins), puis mène
//! la vérification du TSC, puis dit « en service » ; le secondaire attend
//! ce dernier mot avant de continuer (le `cpuhp_ap_sync_alive` de Linux :
//! un secondaire ne fait rien que le premier n'ait vu). Un secondaire en
//! retard, que le premier a abandonné, trouve « abandonné » et s'arrête
//! (`cli ; hlt`) ; s'il arrive après que l'en-tête du trampoline a été
//! réécrit pour le suivant, le trampoline lui-même l'arrête, avant qu'il
//! ne touche à une pile qui n'est plus la sienne (trampoline.rs).
//!
//! À ce commit, un secondaire en service ne fait encore que `cli ; hlt` :
//! le timer de son APIC reste masqué (sans file des prêtes par
//! processeur, un tic sur un secondaire ferait choisir dans la file commune
//! la tâche qui s'exécute sur le premier), et il ne reçoit pas encore
//! d'interruption entre processeurs. Son tic, sa file et ses IPI viennent
//! avec les commits suivants de 6j.

use crate::gdt::PilesIst;
use crate::verrou::Verrou;
use crate::vmalloc::Pile;
use crate::{acpi, apic, appel_systeme, cpu, gdt, horloge, interruptions, pagination, processeur, sse, tache, trampoline, tsc};
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// Les mots de la poignée de main (`Processeur::demarrage`).
pub mod etape {
    /// Le premier a envoyé le SIPI, le secondaire n'a encore rien dit.
    pub const ATTENDU: u8 = 0;
    /// Le secondaire est arrivé dans `depart_secondaire`, prêt pour la
    /// vérification du TSC (écrit par lui, sur ATTENDU ou sur REESSAI, par
    /// un compare_exchange : tout autre mot l'arrête).
    pub const ARRIVE: u8 = 1;
    /// Le premier mène la mesure du TSC : le secondaire y participe
    /// (écrit par le premier).
    pub const MESURE: u8 = 2;
    /// La mesure du secondaire est faite, son résultat dans RECUL_CIBLE
    /// (écrit par lui, sur MESURE).
    pub const FINI: u8 = 3;
    /// Le premier demande une correction de TSC_ADJUST (CORRECTION), puis
    /// une nouvelle mesure (écrit par le premier).
    pub const REESSAI: u8 = 4;
    /// En service : le secondaire peut continuer (écrit par le premier).
    pub const EN_SERVICE: u8 = 5;
    /// Le premier a renoncé (pas venu en cinq secondes : écrit sur ATTENDU
    /// par un compare_exchange, et un INIT le suit ; ou sa mesure du TSC
    /// n'a pas abouti) : le secondaire s'arrête dès qu'il le lit.
    pub const ABANDONNE: u8 = 6;
}

/// Ce que le premier processeur prépare pour un secondaire, et que celui-ci
/// vient prendre à son départ : ses piles de l'IST (ses sommets).
static PREPARATIONS: Verrou<[Option<PilesIst>; processeur::MAX]> = Verrou::new([const { None }; processeur::MAX]);

/// Les registres de contrôle du premier processeur (CR0, CR4, EFER, XCR0),
/// que chaque secondaire compare aux siens. Une constante du démarrage,
/// écrite avant le premier SIPI.
static REFERENCE: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

/// La vérification du TSC : le recul vu par le secondaire (tsc.rs), s'il
/// a TSC_ADJUST, et la correction que lui demande le premier. Écrits d'un
/// côté, lus de l'autre, après la poignée de main (Release/Acquire sur
/// `demarrage`).
static RECUL_CIBLE: AtomicU64 = AtomicU64::new(0);
static CIBLE_A_TSC_ADJUST: AtomicBool = AtomicBool::new(false);
static CORRECTION: AtomicI64 = AtomicI64::new(0);

/// Combien de temps le premier attend un secondaire : 5 s, comme Linux
/// (`do_boot_cpu` : « 5 seconds » pour `cpu_callin_mask`). Un processeur
/// qui ne répond pas en 5 s ne répondra plus.
const ATTENTE_SECONDAIRE_NS: u64 = 5_000_000_000;
/// Et une étape de la vérification du TSC : 1 s (la mesure dure 2 ms).
const ATTENTE_MESURE_NS: u64 = 1_000_000_000;

/// Démarre les processeurs secondaires que liste la MADT, un à un. Sur le
/// premier processeur, interruptions actives, l'APIC en service, les
/// registres de contrôle à leur valeur finale, vmalloc et les tâches en
/// place.
pub fn demarrer_secondaires() {
    if !crate::irq::apic() {
        afficherln!("[noyau] 1 processeur en service : pas d'APIC local, pas de secondaire.");
        return;
    }
    // Les numéros d'APIC des autres processeurs, copiés hors du verrou des
    // tables ACPI (on ne démarre personne sous un verrou).
    let moi = apic::id_du_premier();
    let mut apics = [0u8; processeur::MAX];
    let mut n = 0;
    let mut listes = 0;
    acpi::avec(|c| {
        if let Some(m) = &c.madt {
            for &(_, a) in &m.processeurs {
                listes += 1;
                if a != moi && n < processeur::MAX - 1 {
                    apics[n] = a;
                    n += 1;
                }
            }
        }
    });
    for numero in 1..=n {
        processeur::declarer_possible(numero);
    }
    if n == 0 {
        afficherln!("[noyau] 1 processeur en service : la MADT n'en liste pas d'autre.");
        return;
    }
    if listes > processeur::MAX {
        afficherln!("[noyau] La MADT liste {} processeurs : seuls les {} premiers seront demarres.", listes, processeur::MAX);
    }
    trampoline::installer(depart_secondaire);
    for (i, r) in trampoline::registres_de_reference().into_iter().enumerate() {
        REFERENCE[i].store(r, Ordering::Relaxed);
    }
    for (i, &apic) in apics[..n].iter().enumerate() {
        demarrer_un(i + 1, apic);
    }
    let en_service = processeur::nombre();
    if en_service == 1 {
        afficherln!("[noyau] 1 processeur en service : aucun secondaire n'a repondu.");
    } else {
        afficherln!("[noyau] {} processeurs en service.", en_service);
    }
}

/// Prépare le processeur `numero` (son APIC : `apic`), le réveille, et
/// attend qu'il soit en service.
fn demarrer_un(numero: usize, apic: u8) {
    let zone = processeur::zone(numero);
    zone.apic.store(apic, Ordering::Relaxed);
    let Some(inactive) = tache::inactive_secondaire(numero) else {
        afficherln!("[noyau] Processeur {} (APIC {}) : pas de pile pour sa tache inactive : laisse de cote.", numero, apic);
        return;
    };
    // Ses piles de l'IST, de vmalloc : quatre piles de tâche (16 Kio sous
    // leur garde), gardées pour toujours comme celles du premier dans la
    // .bss (jamais rendues : un processeur en service ne s'arrête pas),
    // nommées (vmalloc.rs : un débordement dit laquelle) et retranchées du
    // nombre de fils possibles (`vmalloc::max_threads`).
    let mut sommets = [0u64; 4];
    for (role, s) in sommets.iter_mut().enumerate() {
        let Some(p) = Pile::allouer() else {
            afficherln!("[noyau] Processeur {} (APIC {}) : pas de pile pour son IST : laisse de cote.", numero, apic);
            return;
        };
        *s = crate::vmalloc::garder_pour_ist(p, numero, role);
    }
    PREPARATIONS.verrouiller()[numero] = Some(PilesIst(sommets));
    // Sa tâche inactive est sa tâche courante dès sa première instruction
    // Rust (`tache::courante`), et le reste pour toujours : la référence
    // est gardée telle quelle (comme celle de l'inactive du premier,
    // tache::initialiser).
    let t = crate::partage::Arc::into_raw(inactive) as *mut tache::Tache;
    zone.inactive.store(t, Ordering::Relaxed);
    zone.courante.store(t, Ordering::Relaxed);
    zone.demarrage.store(etape::ATTENDU, Ordering::Relaxed);
    // SAFETY: `t` vient d'un Arc gardé pour toujours.
    let pile = unsafe { (*t).sommet_de_pile() };
    trampoline::preparer_processeur(numero as u32, apic, pile, zone as *const processeur::Processeur as u64);
    // Tout ce qui précède doit être en mémoire avant le SIPI (le `mb()` de
    // `do_boot_cpu`) : l'écriture dans l'ICR est une écriture de registre,
    // que le processeur ordonne après les précédentes, mais la barrière le
    // dit au compilateur aussi.
    core::sync::atomic::fence(Ordering::SeqCst);

    // INIT, en niveau : posé, 10 ms, levé.
    apic::envoyer_init(apic);
    if !apic::attendre_envoi() {
        afficherln!("[noyau] Processeur {} (APIC {}) : l'APIC n'envoie pas l'INIT : abandonne.", numero, apic);
        return;
    }
    horloge::attendre_ms(10);
    apic::lever_init(apic);
    let _ = apic::attendre_envoi();
    let _ = apic::erreurs();
    // Deux SIPI vers la page du trampoline, 300 µs puis 200 µs (les
    // `udelay` de Linux), l'ESR regardé après chacun.
    for _ in 0..2 {
        apic::envoyer_demarrage(apic, (trampoline::CODE >> 12) as u8);
        horloge::attendre_us(300);
        let envoye = apic::attendre_envoi();
        horloge::attendre_us(200);
        let erreurs = apic::erreurs();
        if !envoye || erreurs != 0 {
            afficherln!("[noyau] Processeur {} (APIC {}) : SIPI {} (ESR {:#x}).", numero, apic,
                        if envoye { "refuse" } else { "pas envoye" }, erreurs);
            break;
        }
    }

    // La poignée de main. Chaque mot y est posé par un compare_exchange,
    // des deux côtés : celui qui écrit vérifie que l'autre en est bien là
    // où il le croit. Pas venu en cinq secondes : ATTENDU devient
    // ABANDONNE ; s'il arrive à cet instant même et gagne (ARRIVE), on
    // continue avec lui ; sinon il trouvera ABANDONNE et s'arrêtera (un
    // simple `store` écrasait ARRIVE, et le secondaire, lui, écrivait
    // ARRIVE sur un ABANDONNE sans le voir : la relecture de 6j). Et un
    // INIT, pour qu'il ne s'exécute plus du tout, où qu'il en soit (en
    // route dans le trampoline, par exemple) : Linux, lui, le laisse tourner
    // dans `start_secondary` sans jamais l'appeler.
    if !attendre_etape(zone, etape::ARRIVE, ATTENTE_SECONDAIRE_NS)
        && zone.demarrage.compare_exchange(etape::ATTENDU, etape::ABANDONNE, Ordering::AcqRel, Ordering::Acquire).is_ok()
    {
        afficherln!("[noyau] Processeur {} (APIC {}) ne repond pas : abandonne.", numero, apic);
        // Le scénario test-retard (voir `depart_secondaire`) veut voir le
        // retardataire trouver ABANDONNE : pas d'INIT.
        #[cfg(not(feature = "test-retard"))]
        {
            apic::envoyer_init(apic);
            let _ = apic::attendre_envoi();
            horloge::attendre_ms(10);
            apic::lever_init(apic);
            let _ = apic::attendre_envoi();
        }
        return;
    }
    if !verifier_tsc(zone, numero) {
        // Sa mesure n'a pas abouti : abandonné là où il en est (sa prochaine
        // lecture du mot l'arrête), jamais déclaré en service.
        zone.demarrage.store(etape::ABANDONNE, Ordering::Release);
        afficherln!("[noyau] Processeur {} (APIC {}) : abandonne.", numero, apic);
        return;
    }
    processeur::declarer_en_service(numero);
    zone.demarrage.store(etape::EN_SERVICE, Ordering::Release);
    afficherln!("[noyau] Processeur {} (APIC {}) en service.", numero, apic);
}

/// Attend que `zone.demarrage` vaille `attendue`, au plus `ns`
/// nanosecondes (interruptions actives : le temps avance par le TSC ou par
/// les tics). Acquire : ce que le secondaire a écrit avant est visible.
fn attendre_etape(zone: &processeur::Processeur, attendue: u8, ns: u64) -> bool {
    let debut = crate::temps::ns_monotone();
    while zone.demarrage.load(Ordering::Acquire) != attendue {
        if crate::temps::ns_monotone().wrapping_sub(debut) > ns {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// Mène, depuis le premier processeur, la vérification de l'accord du TSC
/// du secondaire `numero` (voir tsc.rs : `verifier_accord`) : une mesure,
/// et si les deux TSC ne sont pas accordés, une correction par TSC_ADJUST
/// du secondaire et une nouvelle mesure (trois fois au plus, comme les
/// `test_runs` de Linux) ; sinon, le TSC est déclassé et l'heure revient
/// au tic (`tsc::declasser`). Sans TSC fiable, rien à vérifier. Faux si le
/// secondaire n'a pas suivi le protocole (pas venu mesurer, pas fini, pas
/// revenu) : il est abandonné (jusqu'à la relecture de 6j, il était
/// déclaré en service quand même, avec un TSC jamais comparé).
fn verifier_tsc(zone: &processeur::Processeur, numero: usize) -> bool {
    if tsc::khz().is_none() {
        return true;
    }
    let mut essais = 0;
    loop {
        zone.demarrage.store(etape::MESURE, Ordering::Release);
        let Some(recul_source) = tsc::verifier_accord(tsc::Role::Source) else {
            afficherln!("[noyau] Processeur {} : pas venu mesurer son TSC en une seconde.", numero);
            tsc::fin_de_verification();
            return false;
        };
        if !attendre_etape(zone, etape::FINI, ATTENTE_MESURE_NS) {
            afficherln!("[noyau] Processeur {} : sa mesure du TSC n'a pas fini en une seconde.", numero);
            tsc::fin_de_verification();
            return false;
        }
        let recul_cible = RECUL_CIBLE.load(Ordering::Acquire);
        tsc::fin_de_verification();
        // Le scénario de `make tests-qemu` (test-tsc) : sous QEMU, les TSC
        // des processeurs virtuels viennent de la même horloge et sont
        // toujours accordés ; on fait comme si le premier secondaire avait
        // vu le sien reculer d'un million de cycles, sans TSC_ADJUST, pour
        // passer par le déclassement.
        #[cfg(feature = "test-tsc")]
        let (recul_cible, a_tsc_adjust) = if numero == 1 { (1_000_000, false) } else { (recul_cible, CIBLE_A_TSC_ADJUST.load(Ordering::Relaxed)) };
        #[cfg(not(feature = "test-tsc"))]
        let a_tsc_adjust = CIBLE_A_TSC_ADJUST.load(Ordering::Relaxed);
        if recul_source == 0 && recul_cible == 0 {
            return true;
        }
        essais += 1;
        // Qui est en avance ? Si le secondaire a vu l'heure reculer, c'est
        // qu'il a lu moins que ce que le premier venait d'écrire : il est
        // en retard, et avance de ce recul ; si c'est le premier qui l'a
        // vu, le secondaire est en avance, et recule d'autant (le
        // raisonnement de `check_tsc_sync_target`).
        let correction = if recul_cible != 0 { recul_cible as i64 } else { -(recul_source as i64) };
        if essais < 3 && a_tsc_adjust {
            CORRECTION.store(correction, Ordering::Relaxed);
            afficherln!("[noyau] TSC du processeur {} : recul de {} cycles vu par le processeur {} ; TSC_ADJUST corrige de {}, nouvelle mesure.",
                        numero, correction.unsigned_abs(), if recul_cible != 0 { numero } else { 0 }, correction);
            zone.demarrage.store(etape::REESSAI, Ordering::Release);
            if !attendre_etape(zone, etape::ARRIVE, ATTENTE_MESURE_NS) {
                afficherln!("[noyau] Processeur {} : pas revenu pour une nouvelle mesure du TSC en une seconde.", numero);
                return false;
            }
            continue;
        }
        let decalage = tsc::declasser();
        afficherln!("[noyau] TSC : le processeur {} n'est pas accorde avec le premier (recul de {} cycles{}) : l'heure au tic, decalage de {} ns.",
                    numero, correction.unsigned_abs(), if a_tsc_adjust { ", malgre TSC_ADJUST" } else { ", pas de TSC_ADJUST" }, decalage);
        return true;
    }
}

/// La première fonction Rust d'un processeur secondaire, appelée par le
/// trampoline (trampoline.rs) sur la pile de sa tâche inactive,
/// interruptions coupées, GS_BASE sur sa zone, encore sous la PML4 du
/// trampoline (dont la moitié haute est celle du noyau : ce code, la pile
/// et la zone s'y trouvent). Ce que `noyau_main` fait pour un processeur
/// (voir l'en-tête), puis la poignée de main, puis la boucle
/// d'inactivité.
extern "C" fn depart_secondaire(numero: u32) -> ! {
    // D'abord la PML4 du noyau : celle du trampoline n'a servi qu'à
    // arriver ici (le `secondary_startup_64` de Linux charge de même
    // `init_top_pgt` en premier).
    // SAFETY: la PML4 du noyau est complète ; ce code, la pile et la zone
    // y sont projetés aux mêmes adresses que dans celle du trampoline.
    unsafe { pagination::activer(pagination::pml4_noyau()) };
    let numero = numero as usize;
    let zone = processeur::zone(numero);
    let piles = PREPARATIONS.verrouiller()[numero].take().expect("processeur secondaire sans piles preparees");
    gdt::initialiser(zone, piles);
    interruptions::charger_idt();
    appel_systeme::initialiser();
    sse::initialiser_secondaire();
    // La base de GS du programme (KERNEL_GS_BASE, celle que `swapgs`
    // rendra active au retour vers l'anneau 3) : nulle, comme à la mise
    // sous tension ; explicite, pour ne dépendre de rien.
    processeur::effacer_base_gs_programme();

    let registres = trampoline::registres_de_reference();
    let noms = ["CR0", "CR4", "EFER", "XCR0"];
    for (i, r) in registres.into_iter().enumerate() {
        let attendu = REFERENCE[i].load(Ordering::Relaxed);
        if r != attendu {
            afficherln!("[noyau] Processeur {} : ECHEC, {} vaut {:#x} au lieu de {:#x} (le premier processeur).", numero, noms[i], r, attendu);
        }
    }

    acpi::avec(|c| apic::initialiser_processeur(c.madt.as_ref().expect("secondaire sans MADT"), false));
    let id = apic::id_local();
    if id != zone.apic.load(Ordering::Relaxed) {
        afficherln!("[noyau] Processeur {} : ECHEC, son APIC se dit {} et la MADT disait {}.", numero, id, zone.apic.load(Ordering::Relaxed));
        zone.apic.store(id, Ordering::Relaxed);
    }
    CIBLE_A_TSC_ADJUST.store(tsc::a_tsc_adjust(), Ordering::Relaxed);

    // Le scénario test-retard de `make tests-qemu` : le processeur 1 tarde
    // six secondes à se présenter ; le premier l'abandonne au bout de
    // cinq, sans INIT, et il doit trouver ABANDONNE ci-dessous et
    // s'arrêter sans un mot (le compare_exchange ; un `store` l'aurait
    // déclaré arrivé dans un noyau qui ne l'attendait plus).
    #[cfg(feature = "test-retard")]
    if numero == 1 {
        let khz = tsc::khz().unwrap_or(1_000_000);
        let debut = tsc::lire();
        while tsc::lire().wrapping_sub(debut) < khz * 6_000 {
            core::hint::spin_loop();
        }
    }

    // La poignée de main (voir `demarrer_un`) : chaque mot posé par un
    // compare_exchange sur celui que le premier doit avoir écrit ; un
    // autre mot (ABANDONNE : le premier a renoncé à nous), et on s'arrête.
    let mut attendu = etape::ATTENDU;
    loop {
        if zone.demarrage.compare_exchange(attendu, etape::ARRIVE, Ordering::AcqRel, Ordering::Acquire).is_err() {
            cpu::arreter();
        }
        match attendre_l_un(zone, &[etape::MESURE, etape::EN_SERVICE, etape::ABANDONNE]) {
            etape::MESURE => {
                // None (le premier n'est pas venu en une seconde) : rien à
                // dire, c'est lui qui en tire la conclusion.
                let recul = tsc::verifier_accord(tsc::Role::Cible).unwrap_or(0);
                RECUL_CIBLE.store(recul, Ordering::Relaxed);
                if zone.demarrage.compare_exchange(etape::MESURE, etape::FINI, Ordering::AcqRel, Ordering::Acquire).is_err() {
                    cpu::arreter();
                }
                match attendre_l_un(zone, &[etape::EN_SERVICE, etape::REESSAI, etape::ABANDONNE]) {
                    etape::EN_SERVICE => break,
                    etape::REESSAI => {
                        tsc::ajuster(CORRECTION.load(Ordering::Acquire));
                        attendu = etape::REESSAI;
                    }
                    _ => cpu::arreter(),
                }
            }
            etape::EN_SERVICE => break,
            _ => cpu::arreter(),
        }
    }
    // En service. La boucle d'inactivité d'un secondaire, à ce commit :
    // `cli ; hlt` pour toujours (voir l'en-tête).
    cpu::arreter()
}

/// Attend que `zone.demarrage` prenne l'une des valeurs `attendues`, et la
/// rend. Sans borne : le premier processeur, qui l'écrit, est en marche.
fn attendre_l_un(zone: &processeur::Processeur, attendues: &[u8]) -> u8 {
    loop {
        let e = zone.demarrage.load(Ordering::Acquire);
        if attendues.contains(&e) {
            return e;
        }
        core::hint::spin_loop();
    }
}
