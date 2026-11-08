//! Le TSC (Time Stamp Counter) : le compteur de cycles du processeur,
//! l'horloge fine du noyau.
//!
//! RDTSC rend en une instruction un compteur de 64 bits qui avance depuis
//! la mise sous tension. Sur les processeurs récents, il avance à une
//! fréquence CONSTANTE, quelle que soit la vitesse du cœur (les économies
//! d'énergie la changent sans cesse) : c'est alors la meilleure horloge du
//! PC, à la nanoseconde près, et c'est celle de Linux. Il faut deux
//! choses avant de s'en servir :
//!   - savoir s'il est constant. Le processeur le dit (CPUID 0x80000007,
//!     bit 8 d'EDX, « invariant TSC ») ; certains processeurs Intel l'ont
//!     constant sans le dire, et Linux les reconnaît à leur modèle
//!     (cpu/intel.c, 6.18) : le Core de Yonah à Ivy Bridge (famille 6,
//!     modèles 0x0E à 0x3A, Nehalem compris) et le Pentium 4 de Prescott à
//!     Cedar Mill (famille 15, modèles 3 à 6). Chez AMD, le bit seul.
//!     Sinon, le temps reste compté en tics du PIT, comme aux étapes 3 à 6d.
//!     (Sous QEMU sans KVM, aucun processeur n'a le bit : Nehalem passe
//!     par son modèle, qemu64 et max, des AMD, n'ont pas de TSC fiable :
//!     les deux chemins sont donc vérifiés.)
//!   - connaître sa fréquence : on la MESURE contre le canal 2 du PIT, dont
//!     le quartz est connu (1 193 182 Hz), comme `pit_calibrate_tsc` de
//!     Linux : on arme le canal pour 10 ms, on lit le TSC au départ et
//!     quand le canal a fini. Cinq essais. Un essai est rejeté si le PIT a
//!     été lu moins de 1000 fois pendant ces 10 ms (un PIT qui ne répond
//!     pas, ou une machine trop lente pour la mesure). On prend la MÉDIANE
//!     des essais, et il en faut au moins trois à 0,5 % d'elle, sinon le
//!     TSC n'est pas utilisé : un vol de temps (une interruption de gestion
//!     du système, l'hôte qui fait tourner QEMU) au bord d'un essai le
//!     fausse, et l'écarte.
//!     Deux écarts avec Linux, mesurés sous QEMU sans KVM : Linux rejette
//!     aussi un essai dont un tour de boucle a duré plus de 10 fois le plus
//!     court ; sous QEMU, c'est le cas de TOUS les essais (le plus long
//!     tour dure de 200 à 6000 fois le plus court : l'émulateur s'arrête à
//!     chaque accès au port, et l'hôte l'interrompt), qui s'accordent
//!     pourtant à 0,3 % près. Et Linux garde le plus petit essai ; mais un
//!     retard au bord d'un essai (juste après l'armement du canal, ou juste
//!     avant de voir sa fin) le raccourcit : le plus petit serait celui-là.
//! Linux affine ensuite la fréquence une seconde plus tard, contre le
//! HPET ou le timer d'ACPI, dont nous n'avons pas les pilotes : nos dix
//! millisecondes, sur un PIT lu à la microseconde, donnent la fréquence à
//! un dix-millième près (moins de 9 secondes par jour).
//!
//! La conversion en nanosecondes ne fait pas de division à chaque lecture :
//! ns = (cycles × mult) >> 32, avec mult = 10^6 × 2^32 / fréquence en kHz
//! (le `mult` et le `shift` des clocksources de Linux) ; le produit est
//! calculé sur 128 bits, il ne déborde jamais.

//!
//! PLUSIEURS PROCESSEURS (6j) : `ns_monotone` lit le TSC du processeur où
//! elle est ; il faut que tous disent la même heure. Sous QEMU, les TSC des
//! processeurs virtuels viennent de la même horloge ; sur une vraie
//! machine, presque toujours (le TSC invariant), mais on VÉRIFIE, comme
//! Linux (`check_tsc_sync_source` et `_target`, tsc_sync.c) : au départ de
//! chaque secondaire, lui et le premier lisent chacun leur TSC à tour de
//! rôle pendant 20 ms, en se passant la main sous un verrou ; si l'un voit
//! l'heure de l'autre dépasser la sienne lue après (le temps recule), les
//! TSC ne sont pas accordés (`verifier_accord`). Alors, comme Linux, le MSR
//! TSC_ADJUST d'abord, si le processeur l'a (CPUID.7:EBX bit 1) : l'écart
//! mesuré y est écrit (`ajuster`), et la vérification refaite ; sinon
//! seulement, le TSC est DÉCLASSÉ (`declasser`) : l'heure revient au tic,
//! avec le décalage entre le temps du TSC et celui des tics à cet instant,
//! pour que `ns_monotone` ne recule ni ne saute. Les paramètres changent
//! alors pendant que d'autres processeurs lisent l'heure : un seqlock les
//! publie (voir SEQUENCE).

use crate::port;
use crate::verrou::Verrou;
use core::arch::asm;
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

/// Les paramètres de l'horloge du TSC : la fréquence mesurée en kHz (0 :
/// pas de TSC fiable, ou déclassé), le facteur de conversion en
/// nanosecondes (voir l'en-tête), le TSC à l'instant pris pour origine du
/// temps du noyau, et le DÉCALAGE à ajouter au temps des tics quand le TSC
/// est déclassé (`declasser`, 0 sinon). Écrits ensemble par l'étalonnage,
/// puis au plus une fois par le déclassement ; lus par tous les
/// processeurs à chaque lecture de l'heure. Un SEQLOCK les publie (le
/// `tk_core.seq` de Linux) : l'écrivain rend le compteur impair, écrit les
/// quatre mots, le rend pair ; un lecteur lit le compteur, les quatre mots,
/// le compteur encore, et recommence s'il était impair ou a changé. Sans
/// lui, un lecteur pourrait voir une fréquence nulle avec un décalage encore
/// nul, et l'heure sauter en arrière d'une seconde. Option écartée : un
/// seul mot atomique qui désigne une structure immuable (le motif RCU) :
/// il faudrait une allocation, et savoir rendre l'ancienne quand plus
/// personne ne la lit.
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
static KHZ: AtomicU64 = AtomicU64::new(0);
static MULT: AtomicU64 = AtomicU64::new(0);
static ORIGINE: AtomicU64 = AtomicU64::new(0);
static DECALAGE: AtomicI64 = AtomicI64::new(0);

/// Les quatre paramètres, d'un même état (voir SEQUENCE) : kHz, mult,
/// origine, décalage.
fn lire_parametres() -> (u64, u64, u64, i64) {
    loop {
        // Acquire : les quatre lectures viennent après celle du compteur.
        let s1 = SEQUENCE.load(Ordering::Acquire);
        if s1 & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        let p = (KHZ.load(Ordering::Relaxed), MULT.load(Ordering::Relaxed), ORIGINE.load(Ordering::Relaxed),
                 DECALAGE.load(Ordering::Relaxed));
        // Et elles sont faites avant la relecture du compteur (une barrière
        // Acquire : sur x86, pour le compilateur seul, les lectures ne se
        // dépassent pas).
        core::sync::atomic::fence(Ordering::Acquire);
        if SEQUENCE.load(Ordering::Relaxed) == s1 {
            return p;
        }
    }
}

/// Publie de nouveaux paramètres (voir SEQUENCE). Un seul écrivain à la
/// fois : l'étalonnage, puis le déclassement, tous deux sur le premier
/// processeur, pendant le démarrage.
fn publier(khz: u64, mult: u64, origine: u64, decalage: i64) {
    let s = SEQUENCE.load(Ordering::Relaxed);
    SEQUENCE.store(s.wrapping_add(1), Ordering::Relaxed);
    // Une barrière complète de part et d'autre des quatre écritures : un
    // lecteur qui a vu le compteur impair ne lit rien d'à moitié écrit, et
    // celui qui le voit pair après coup voit les quatre mots (le tampon
    // d'écriture de x86 garde l'ordre des écritures ; le compilateur, non).
    core::sync::atomic::fence(Ordering::SeqCst);
    KHZ.store(khz, Ordering::Relaxed);
    MULT.store(mult, Ordering::Relaxed);
    ORIGINE.store(origine, Ordering::Relaxed);
    DECALAGE.store(decalage, Ordering::Relaxed);
    core::sync::atomic::fence(Ordering::SeqCst);
    SEQUENCE.store(s.wrapping_add(2), Ordering::Release);
}

/// Lit le TSC. LFENCE avant RDTSC : sinon le processeur peut exécuter la
/// lecture en avance, avant les instructions qui la précèdent, et deux
/// lectures de suite pourraient sembler reculer (le `rdtsc_ordered` de
/// Linux, qui choisit LFENCE sur Intel comme sur AMD).
pub fn lire() -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY: LFENCE et RDTSC ne font que lire ; RDTSC est permis en
    // anneau 0 quel que soit CR4.TSD.
    unsafe { asm!("lfence", "rdtsc", out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}

/// Le TSC est-il constant, d'après le processeur (voir l'en-tête) ?
fn constant() -> bool {
    use core::arch::x86_64::__cpuid;
    if __cpuid(0x8000_0000).eax >= 0x8000_0007 && __cpuid(0x8000_0007).edx & 1 << 8 != 0 {
        return true;
    }
    let f = __cpuid(0);
    if (f.ebx, f.edx, f.ecx) != (0x756e_6547, 0x4965_6e69, 0x6c65_746e) {
        return false; // pas « GenuineIntel »
    }
    let s = __cpuid(1).eax;
    let famille = (s >> 8 & 0xF) + if s >> 8 & 0xF == 0xF { s >> 20 & 0xFF } else { 0 };
    let modele = (s >> 4 & 0xF) | if matches!(s >> 8 & 0xF, 6 | 0xF) { (s >> 16 & 0xF) << 4 } else { 0 };
    (famille == 6 && (0x0E..=0x3A).contains(&modele)) || (famille == 15 && (3..=6).contains(&modele))
}

/// Les ports du PIT et de sa porte (le port 0x61 du PC/AT : bit 0, la
/// porte du canal 2 ; bit 1, le haut-parleur ; bit 5, la sortie du canal 2).
const PIT_CANAL2: u16 = 0x42;
const PIT_COMMANDE: u16 = 0x43;
const PORTE: u16 = 0x61;

/// Prépare le canal 2 du PIT pour compter `ms` millisecondes (54 au plus :
/// un décompte de 16 bits à 1,19 MHz) : la porte ouverte sans le
/// haut-parleur, le mode 0 (« compte à rebours, puis la sortie monte »),
/// comptage binaire, décompte en deux octets, dont le premier est écrit ;
/// le canal compte dès l'écriture du second (`lancer_canal2`), rendu ici.
/// Le canal 2 ne sert qu'aux mesures : celle du TSC, et celle du timer de
/// l'APIC (horloge.rs).
fn preparer_canal2(ms: u64) -> u8 {
    let decompte = (crate::horloge::FREQUENCE_PIT as u64 * ms / 1000) as u16;
    // SAFETY: registres documentés du PIT et de sa porte.
    unsafe {
        port::ecrire(PORTE, (port::lire(PORTE) & !0x02) | 0x01);
        port::ecrire(PIT_COMMANDE, 0xB0);
        port::ecrire(PIT_CANAL2, decompte as u8);
    }
    (decompte >> 8) as u8
}

/// Écrit le second octet du décompte : le canal 2 compte.
fn lancer_canal2(haut: u8) {
    // SAFETY: le canal 2, préparé par `preparer_canal2`.
    unsafe { port::ecrire(PIT_CANAL2, haut) };
}

/// La sortie du canal 2 est-elle montée (le compte est fini) ?
fn canal2_fini() -> bool {
    // SAFETY: lire la porte ne change rien.
    let porte = unsafe { port::lire(PORTE) };
    porte & 0x20 != 0
}

/// Fait compter le canal 2 du PIT pendant `ms` millisecondes et attend sa
/// fin ; faux si sa porte a été lue moins de 1000 fois pendant ce temps
/// (un PIT qui ne répond pas, ou une machine trop lente pour la mesure).
/// Pour mesurer le timer de l'APIC contre le PIT (horloge.rs).
pub fn attendre_canal2(ms: u64) -> bool {
    let haut = preparer_canal2(ms);
    lancer_canal2(haut);
    let mut lectures = 0u32;
    while !canal2_fini() {
        lectures += 1;
    }
    lectures >= 1000
}

/// Un essai de mesure : le nombre de cycles du TSC pendant `ms`
/// millisecondes du canal 2 du PIT, ou None si l'essai est rejeté.
fn essai(ms: u64) -> Option<u64> {
    let haut = preparer_canal2(ms);
    // Le canal compte dès que le second octet du décompte est écrit :
    // l'instant du départ est pris au milieu de deux lectures du TSC qui
    // encadrent cette écriture, et celui de la fin, entre la dernière
    // lecture qui précède la sortie montée et celle qui la suit.
    let avant = lire();
    lancer_canal2(haut);
    let apres = lire();
    let mut fin = apres;
    let mut lectures = 0u32;
    while !canal2_fini() {
        fin = lire();
        lectures += 1;
    }
    let vue = lire();
    if lectures < 1000 {
        return None;
    }
    Some((fin / 2 + vue / 2) - (avant / 2 + apres / 2))
}

/// Ce que l'étalonnage a donné, pour l'afficher.
pub enum Bilan {
    /// La fréquence, en kHz, et le nombre d'essais à 0,5 % de la médiane.
    Fiable { khz: u64, essais: u32 },
    /// Le processeur ne dit pas son TSC constant.
    NonConstant,
    /// Les essais ont été rejetés, ou ne s'accordent pas.
    Mesure,
}

/// Mesure la fréquence du TSC, s'il est constant. Interruptions coupées
/// (les essais ne doivent pas être interrompus), avant que le PIT serve
/// d'horloge.
pub fn etalonner() -> Bilan {
    if !constant() {
        return Bilan::NonConstant;
    }
    let interruptions = crate::cpu::couper_interruptions();
    // Un premier essai pour rien : le premier passage dans ce code est
    // plus lent (sous QEMU, l'émulateur le traduit alors), et fausserait
    // son départ (mesuré : un essai sur deux trop court de 0,5 %).
    let _ = essai(1);
    let (mut retenus, mut n) = ([0u64; 5], 0);
    for _ in 0..5 {
        if let Some(cycles) = essai(10) {
            // Des cycles en 10 ms aux kHz : / 10.
            retenus[n] = cycles / 10;
            n += 1;
        }
    }
    if interruptions {
        crate::cpu::activer_interruptions();
    }
    let retenus = &mut retenus[..n];
    retenus.sort_unstable();
    // La médiane, et au moins trois essais à 0,5 % d'elle.
    let khz = retenus.get(n / 2).copied().unwrap_or(0);
    let proches = retenus.iter().filter(|&&k| k.abs_diff(khz) * 200 <= khz).count();
    if khz == 0 || proches < 3 {
        return Bilan::Mesure;
    }
    publier(khz, ((1_000_000u128 << 32) / khz as u128) as u64, lire(), 0);
    Bilan::Fiable { khz, essais: proches as u32 }
}

/// La fréquence du TSC en kHz, s'il sert d'horloge.
pub fn khz() -> Option<u64> {
    Some(lire_parametres().0).filter(|&k| k != 0)
}

/// Des cycles du TSC en nanosecondes. Le facteur ne change plus après
/// l'étalonnage (le déclassement le garde : des durées mesurées sur un seul
/// processeur, comme l'attente d'un verrou, se convertissent encore) :
/// lisible sans le seqlock.
pub fn en_nanosecondes(cycles: u64) -> u64 {
    ((cycles as u128 * MULT.load(Ordering::Relaxed) as u128) >> 32) as u64
}

/// Les nanosecondes depuis l'origine (l'étalonnage), si le TSC sert
/// d'horloge. L'origine est soustraite sans passer en dessous : un
/// secondaire dont le TSC serait d'un cycle en retard sur l'origine (lue
/// sur le premier) rendrait sinon un temps énorme.
pub fn nanosecondes() -> Option<u64> {
    let (khz, mult, origine, _) = lire_parametres();
    if khz == 0 {
        return None;
    }
    Some(((lire().saturating_sub(origine) as u128 * mult as u128) >> 32) as u64)
}

/// Le décalage à ajouter au temps des tics (temps.rs) : nul tant que le TSC
/// n'est pas déclassé.
pub fn decalage() -> i64 {
    lire_parametres().3
}

/// Déclasse le TSC (voir l'en-tête) : l'heure revient au tic, comme sans
/// TSC fiable, avec le décalage qui fait que `ns_monotone` ne recule ni ne
/// saute : à cet instant, le temps du TSC moins celui des tics ; le temps
/// des tics plus ce décalage prend la suite (temps.rs). `clock_getres` dit
/// désormais le tic (temps::resolution). Rend le décalage, en ns. Sur le
/// premier processeur, interruptions actives (les tics avancent), au plus
/// une fois (smp.rs).
pub fn declasser() -> i64 {
    let (khz, mult, origine, _) = lire_parametres();
    assert!(khz != 0, "TSC declasse sans etre en service");
    // Les deux heures lues au même instant : interruptions coupées, un tic
    // ne tombe pas entre les deux.
    let interruptions = crate::cpu::couper_interruptions();
    let ns_tsc = ((lire().saturating_sub(origine) as u128 * mult as u128) >> 32) as i64;
    let ns_tics = crate::horloge::nanosecondes(crate::horloge::tics()) as i64;
    let decalage = ns_tsc - ns_tics;
    publier(0, mult, origine, decalage);
    if interruptions {
        crate::cpu::activer_interruptions();
    }
    decalage
}

/// Quel côté de la vérification de l'accord des TSC on tient : le premier
/// processeur (la source), ou le secondaire qui démarre (la cible).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Source,
    Cible,
}

/// La vérification en cours : combien de processeurs y sont entrés (les
/// deux doivent y être avant de mesurer), et la dernière heure lue, par
/// l'un ou l'autre, sous son verrou (le `sync_lock` et le `last_tsc` de
/// Linux). Remis à zéro entre deux secondaires (`fin_de_verification`).
static PARTICIPANTS: AtomicU32 = AtomicU32::new(0);
static DERNIERE_HEURE: Verrou<u64> = Verrou::new(0);

/// La durée de la mesure : celle de Linux pour des cœurs sans
/// hyper-threading (`loop_timeout` : 20 ms ; 2 ms entre deux fils d'un
/// même cœur, qui partagent leur TSC), les seuls que nous sachions
/// reconnaître. Et l'attente de l'autre processeur : 1 s au plus.
const DUREE_MESURE_MS: u64 = 20;
const ATTENTE_AUTRE_MS: u64 = 1000;

/// Un côté de la vérification de l'accord du TSC de deux processeurs (voir
/// l'en-tête) : attend l'autre, puis, pendant 20 ms, lit son TSC sous le
/// verrou et le compare à la dernière heure qu'y a laissée l'un ou l'autre.
/// Rend le plus grand RECUL vu de ce côté, en cycles : 0 si l'heure de
/// l'autre n'a jamais dépassé la sienne (de ce côté ; l'autre a pu voir un
/// recul, lui). Un recul vu par la cible : elle est en retard sur la
/// source ; vu par la source : la cible est en avance. None si l'autre
/// n'est pas venu en une seconde : rien n'a été comparé, et le premier processeur ne conclut pas
/// « accordés » (il abandonne le secondaire, smp.rs ; jusqu'à la relecture
/// de 6j, 0 était rendu, et valait un accord). Interruptions actives ou
/// non ; sur les deux processeurs à la fois (smp.rs).
pub fn verifier_accord(role: Role) -> Option<u64> {
    let khz = khz().unwrap_or(1);
    PARTICIPANTS.fetch_add(1, Ordering::AcqRel);
    let arrivee = lire();
    while PARTICIPANTS.load(Ordering::Acquire) < 2 {
        if lire().wrapping_sub(arrivee) > khz * ATTENTE_AUTRE_MS {
            return None;
        }
        core::hint::spin_loop();
    }
    let _ = role;
    let debut = lire();
    let mut recul = 0;
    loop {
        let (precedente, maintenant) = {
            let mut d = DERNIERE_HEURE.verrouiller();
            let maintenant = lire();
            (core::mem::replace(&mut *d, maintenant), maintenant)
        };
        if precedente > maintenant {
            recul = recul.max(precedente - maintenant);
        }
        if maintenant.wrapping_sub(debut) >= khz * DUREE_MESURE_MS {
            return Some(recul);
        }
        core::hint::spin_loop();
    }
}

/// Après une vérification, des deux côtés finis : prête pour la suivante.
/// Sur le premier processeur, une fois que la cible a dit avoir fini.
pub fn fin_de_verification() {
    PARTICIPANTS.store(0, Ordering::Relaxed);
    *DERNIERE_HEURE.verrouiller() = 0;
}

/// Le processeur a-t-il le MSR TSC_ADJUST (CPUID.7.0:EBX, bit 1) ? Un
/// décalage qu'on y écrit s'ajoute à son TSC sans toucher au compteur
/// lui-même (Ivy Bridge et plus ; QEMU sans KVM ne l'imite pas).
pub fn a_tsc_adjust() -> bool {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & 1 << 1 != 0
}

/// Ajoute `correction` cycles au TSC de ce processeur, par TSC_ADJUST
/// (smp.rs, sur la cible). Seulement si `a_tsc_adjust`.
pub fn ajuster(correction: i64) {
    const TSC_ADJUST: u32 = 0x3B;
    assert!(a_tsc_adjust(), "TSC_ADJUST absent");
    // SAFETY: le MSR existe (CPUID vient de le dire) ; toute valeur signée
    // y a un sens (un décalage).
    unsafe {
        let v = crate::cpu::lire_msr(TSC_ADJUST) as i64;
        crate::cpu::ecrire_msr(TSC_ADJUST, v.wrapping_add(correction) as u64);
    }
}
