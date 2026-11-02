//! Le générateur aléatoire du noyau : celui de Linux (drivers/char/random.c),
//! pour les programmes (getrandom, /dev/random, /dev/urandom, AT_RANDOM)
//! et pour le noyau lui-même (ports éphémères, identifiants IP, DHCP...).
//!
//! Ses règles (le réservoir BLAKE2s, ses crédits, ChaCha20 et l'effacement
//! de sa clé, le réensemencement, les lots, le petit réservoir des
//! interruptions) sont dans la bibliothèque crypto (crypto::alea), testée
//! sur l'hôte ; ici, ce que la bibliothèque ne peut pas faire : les SOURCES
//! d'aléa, les verrous, l'heure, et l'attente des programmes.
//!
//! LES SOURCES, comme Linux :
//!   - au démarrage, RDSEED puis RDRAND, les générateurs du processeur
//!     (Intel depuis Ivy Bridge et Broadwell, AMD depuis 2015), crédités
//!     comme le fait Linux par défaut (`random.trust_cpu`) : 512 bits, donc
//!     prêt d'emblée ; puis, sans crédit, ce qui distingue cette machine et
//!     cet instant (le compteur de cycles, l'identité du processeur, plus
//!     tard l'heure CMOS) ;
//!   - les interruptions des PÉRIPHÉRIQUES (le clavier, le port série, les
//!     MSI-X des cartes ; pas l'horloge, que Linux ne compte pas non plus :
//!     elle est périodique, et l'hyperviseur en décide l'instant) :
//!     l'instant (le compteur de cycles) et l'adresse interrompue, brassés
//!     dans un petit réservoir à part, versé dans le grand quand on tire ;
//!   - la GIGUE (`gigue`, le `try_to_generate_entropy` de Linux), quand un
//!     programme attend un générateur pas encore prêt : le compteur de
//!     cycles lu à chaque fin de sommeil d'une milliseconde, dont l'instant
//!     exact dépend de tout ce que fait la machine ;
//!   - virtio-rng, le générateur de l'hyperviseur (virtio_rng.rs), quand
//!     la machine en a un.
//!
//! Sans RDRAND ni RDSEED (`-cpu Nehalem`, de 2008, le processeur de la
//! machine de l'étape), le générateur n'est pas prêt au démarrage :
//! virtio-rng le rend prêt avant le réseau sur la machine de l'étape ; sans
//! lui (la machine des programmes de test), la gigue ou les interruptions.
//! En attendant, le noyau tire quand même (ce qu'il a, comme Linux), mais
//! un programme qui demande de l'aléa sûr attend, ou reçoit EAGAIN s'il ne
//! veut pas attendre.
//!
//! LE VERROU : un seul, court (interruptions coupées), pour le réservoir,
//! le générateur et le lot (Linux en a trois, plus un par processeur, pour
//! que les processeurs ne se gênent pas). Aucun calcul long dessous : un
//! tirage ne prépare sous le verrou que son premier bloc (`preparer`),
//! puis tire les suivants sans lui, d'un état de ChaCha20 qui n'appartient
//! qu'à lui. Le petit réservoir des interruptions a son propre verrou, le
//! seul que prennent les interruptions.
//!
//! UNIPROCESSEUR : un seul verrou suffit ; avec plusieurs processeurs, un
//! générateur et un lot par processeur, comme Linux.

use crate::attente::{self, FileAttente, Sommeil};
use crate::tache::{self, Reveil};
use crate::verrou::Verrou;
use crate::{cpu, temps};
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};
use crypto::alea::{self, Generateur, Lot, PetitReservoir, Reservoir, Seuil};

/// RDRAND et RDSEED peuvent échouer (CF = 0) quand le générateur du
/// processeur est momentanément vide : Intel conseille de réessayer, dix
/// fois au plus (Linux : RDRAND_RETRY_LOOPS = 10).
const ESSAIS: usize = 10;

struct Alea {
    reservoir: Option<Reservoir>,
    generateur: Generateur,
    lot: Lot,
}

impl Alea {
    /// Le réservoir, fait au premier usage (un `Blake2s` ne se construit
    /// pas en constante).
    fn reservoir(&mut self) -> &mut Reservoir {
        self.reservoir.get_or_insert_with(Reservoir::new)
    }
}

static ALEA: Verrou<Alea> = Verrou::new(Alea { reservoir: None, generateur: Generateur::new(), lot: Lot::new() });
static PETIT: Verrou<PetitReservoir> = Verrou::new(PetitReservoir::new());
/// Le petit réservoir est à verser (1024 interruptions, ou une seconde).
static A_VERSER: AtomicBool = AtomicBool::new(false);
/// Ceux qui attendent que le générateur soit prêt (`crng_init_wait`), et
/// /dev/random dans poll et epoll.
pub static PRET: FileAttente = FileAttente::new();
/// Prêt, lu sans verrou (le `crng_is_ready` de Linux, une clé statique).
static EST_PRET: AtomicBool = AtomicBool::new(false);
/// RDRAND et RDSEED existent-ils ? Lus une fois au démarrage (`initialiser`),
/// comme les caractéristiques du processeur de Linux : un CPUID par tirage
/// serait une sortie vers l'hyperviseur sous KVM.
static RDRAND: AtomicBool = AtomicBool::new(false);
static RDSEED: AtomicBool = AtomicBool::new(false);

fn a_rdrand() -> bool {
    RDRAND.load(Ordering::Relaxed)
}

fn a_rdseed() -> bool {
    RDSEED.load(Ordering::Relaxed)
}

fn rdrand() -> Option<u64> {
    for _ in 0..ESSAIS {
        let (valeur, ok): (u64, u8);
        // SAFETY : RDRAND existe (a_rdrand), et ne fait que rendre un nombre.
        unsafe { asm!("rdrand {v}", "setc {ok}", v = out(reg) valeur, ok = out(reg_byte) ok, options(nomem, nostack)) };
        if ok != 0 {
            return Some(valeur);
        }
    }
    None
}

fn rdseed() -> Option<u64> {
    for _ in 0..ESSAIS {
        let (valeur, ok): (u64, u8);
        // SAFETY : RDSEED existe (a_rdseed), et ne fait que rendre un nombre.
        unsafe { asm!("rdseed {v}", "setc {ok}", v = out(reg) valeur, ok = out(reg_byte) ok, options(nomem, nostack)) };
        if ok != 0 {
            return Some(valeur);
        }
    }
    None
}

/// Le compteur de cycles (le `random_get_entropy` de Linux sur x86).
fn cycles() -> u64 {
    let (bas, haut): (u32, u32);
    // SAFETY : RDTSC ne fait que lire le compteur de cycles.
    unsafe { asm!("rdtsc", out("eax") bas, out("edx") haut, options(nomem, nostack)) };
    (haut as u64) << 32 | bas as u64
}

/// Les 32 octets d'appoint d'une extraction : RDSEED, sinon RDRAND, sinon
/// le compteur de cycles, mot par mot (comme `extract_entropy`). La
/// bibliothèque l'appelle seulement quand elle extrait (un crédit qui
/// franchit un seuil, un réensemencement) : RDSEED est lent, et son débit
/// partagé par tous les cœurs.
fn appoint() -> [u8; 32] {
    let (seed, rand) = (a_rdseed(), a_rdrand());
    let mut o = [0u8; 32];
    for m in o.chunks_exact_mut(8) {
        let v = seed.then(rdseed).flatten().or_else(|| rand.then(rdrand).flatten()).unwrap_or_else(cycles);
        m.copy_from_slice(&v.to_le_bytes());
    }
    o
}

/// Les secondes depuis le démarrage (le réensemencement et le petit
/// réservoir comptent en secondes).
fn secondes() -> u64 {
    temps::ns_monotone() / 1_000_000_000
}

/// Ce qu'un crédit a fait : prêt, il le dit et réveille ceux qui
/// attendent (hors du verrou).
fn apres_credit(seuil: Seuil, source: &str) {
    if seuil == Seuil::Pret {
        EST_PRET.store(true, Ordering::Release);
        afficherln!("[alea] pret ({}).", source);
        PRET.reveiller_toutes();
    }
}

/// Crédite `bits` en versant `octets` (le `mix_pool_bytes` puis
/// `credit_init_bits` de Linux) ; `source` : pour le message de « prêt ».
pub fn verser(octets: &[u8], bits: u32, source: &str) {
    let seuil = {
        let mut a = ALEA.verrouiller();
        let a = &mut *a;
        let r = a.reservoir.get_or_insert_with(Reservoir::new);
        r.melanger(octets);
        a.generateur.crediter(r, bits, secondes(), &mut appoint)
    };
    apres_credit(seuil, source);
}

/// Au démarrage, interruptions encore coupées (`random_init_early` puis
/// `random_init`) : RDSEED et RDRAND, crédités s'ils répondent ; le
/// compteur de cycles et l'identité du processeur, sans crédit.
pub fn initialiser() {
    RDRAND.store(core::arch::x86_64::__cpuid(1).ecx & 1 << 30 != 0, Ordering::Relaxed);
    RDSEED.store(core::arch::x86_64::__cpuid_count(7, 0).ebx & 1 << 18 != 0, Ordering::Relaxed);
    let mut credites = 0;
    let mut octets = [0u8; 64];
    for m in octets.chunks_exact_mut(8) {
        let v = if a_rdseed() { rdseed() } else { None }.or_else(|| if a_rdrand() { rdrand() } else { None });
        if let Some(v) = v {
            m.copy_from_slice(&v.to_le_bytes());
            credites += 64;
        }
    }
    let mut identite = [0u8; 24];
    identite[..8].copy_from_slice(&cycles().to_le_bytes());
    let c = core::arch::x86_64::__cpuid(1);
    identite[8..12].copy_from_slice(&c.eax.to_le_bytes());
    identite[12..16].copy_from_slice(&c.ebx.to_le_bytes());
    identite[16..24].copy_from_slice(&cycles().to_le_bytes());
    let source = if a_rdseed() { "RDSEED" } else { "RDRAND" };
    verser(&identite, 0, source);
    verser(&octets, credites, source);
    crypto::effacer(&mut octets);
    if !pret() {
        afficherln!("[alea] pas encore pret (ni RDRAND ni RDSEED) : il attend la gigue, les interruptions ou un generateur materiel.");
    }
}

/// Le générateur est-il prêt ?
pub fn pret() -> bool {
    EST_PRET.load(Ordering::Acquire)
}

/// Les bits crédités (RNDGETENTCNT, entropy_avail).
pub fn bits() -> u32 {
    ALEA.verrouiller().reservoir().bits()
}

/// Une interruption d'un périphérique, le vecteur `vecteur`, qui a
/// interrompu l'adresse `rip` (le `add_interrupt_randomness` de Linux).
/// Dans l'interruption : seulement le petit réservoir, sous son verrou.
pub fn ajouter_interruption(vecteur: u64, rip: u64) {
    if PETIT.verrouiller().ajouter(cycles(), rip ^ vecteur.swap_bytes(), secondes()) {
        A_VERSER.store(true, Ordering::Relaxed);
    }
}

/// Verse le petit réservoir s'il est temps (le `mix_interrupt_randomness`
/// de Linux, ici au moment où l'on tire : section 4 du plan).
fn verser_les_interruptions() {
    if !A_VERSER.swap(false, Ordering::Relaxed) {
        return;
    }
    let Some((mut octets, credit)) = PETIT.verrouiller().verser(secondes()) else { return };
    verser(&octets, credit, "interruptions");
    crypto::effacer(&mut octets);
}

/// Un tirage en cours : l'état de ChaCha20 qui donne la suite d'une
/// demande, à lui seul (le `chacha_state` de `_get_random_bytes`), effacé
/// à la fin.
pub struct Tirage {
    etat: [u32; 16],
}

impl Tirage {
    /// Les blocs suivants, sans verrou.
    pub fn suite(&mut self, sortie: &mut [u8]) {
        alea::continuer(&mut self.etat, sortie);
    }

    /// Le tirage prend pour clé 32 octets aléatoires (alea::cle_de_tirage :
    /// la clé d'avant l'effacement rapide ne reste pas dans l'état pendant
    /// une copie qui peut dormir).
    pub fn changer_de_cle(&mut self, cle: &[u8; 32]) {
        alea::cle_de_tirage(&mut self.etat, cle);
    }
}

impl Drop for Tirage {
    fn drop(&mut self) {
        crypto::effacer_mots(&mut self.etat);
    }
}

/// Commence un tirage (`crng_make_state`) : `premiers` (32 octets au plus)
/// reçoit ses premiers octets, sous le verrou, et le tirage rendu donne la
/// suite. Réensemence d'abord si l'échéance est passée.
pub fn commencer(premiers: &mut [u8]) -> Tirage {
    verser_les_interruptions();
    let mut t = Tirage { etat: [0; 16] };
    let mut a = ALEA.verrouiller();
    let a = &mut *a;
    let r = a.reservoir.get_or_insert_with(Reservoir::new);
    let maintenant = secondes();
    if a.generateur.a_reensemencer(maintenant) {
        a.generateur.reensemencer(r, maintenant, &mut appoint);
    }
    a.generateur.preparer(r, &mut appoint, &mut t.etat, premiers);
    t
}

/// Des octets aléatoires pour le noyau (`get_random_bytes`), même avant
/// d'être prêt (avec ce qu'il a).
pub fn obtenir(sortie: &mut [u8]) {
    let n = sortie.len().min(32);
    let (debut, suite) = sortie.split_at_mut(n);
    commencer(debut).suite(suite);
}

/// Un nombre de 32 et de 64 bits, par lots (`get_random_u32/u64`).
pub fn u32() -> u32 {
    u32::from_le_bytes(prendre::<4>())
}

pub fn u64() -> u64 {
    u64::from_le_bytes(prendre::<8>())
}

fn prendre<const N: usize>() -> [u8; N] {
    verser_les_interruptions();
    let mut a = ALEA.verrouiller();
    let a = &mut *a;
    let r = a.reservoir.get_or_insert_with(Reservoir::new);
    a.lot.prendre::<N>(&mut a.generateur, r, &mut appoint)
}

/// Un nombre au hasard dans 0..borne (`get_random_u32_below`), sans biais :
/// la méthode de Lemire, comme Linux (le produit de 64 bits, retiré quand
/// il tombe dans la petite zone qui avantagerait certaines valeurs).
pub fn u32_sous(borne: u32) -> u32 {
    if borne <= 1 {
        return 0;
    }
    loop {
        let m = u32() as u64 * borne as u64;
        if (m as u32) >= borne.wrapping_neg() % borne {
            return (m >> 32) as u32;
        }
    }
}

/// La gigue (`try_to_generate_entropy`) : si le compteur de cycles change
/// assez souvent pour qu'on en tire quelque chose, le lire à chaque fin de
/// sommeil d'un tic, le verser, et créditer un bit tous les
/// `par_bit` échantillons, jusqu'à être prêt ou qu'un signal arrive.
///
/// Linux lit le compteur dans une minuterie, sur un AUTRE processeur que
/// celui qui boucle, et la boucle verse aussi le sien : ce qui compte est
/// que l'instant d'une interruption, mesuré en cycles, n'est pas
/// prévisible. Avec un seul processeur, l'instant du réveil de la tâche,
/// juste après l'interruption de l'horloge, en est la même mesure.
fn gigue() {
    // Combien de lectures successives du compteur diffèrent, sur 8192
    // (NUM_TRIAL_SAMPLES) : un compteur trop grossier ne vaut rien.
    const ESSAIS_GIGUE: u32 = 8192;
    let mut differents = 0;
    let mut dernier = cycles();
    for _ in 0..ESSAIS_GIGUE - 1 {
        let c = cycles();
        if c != dernier {
            differents += 1;
        }
        dernier = c;
    }
    let par_bit = ESSAIS_GIGUE.div_ceil(differents + 1);
    // MAX_SAMPLES_PER_BIT = HZ / 15.
    if par_bit > crate::horloge::HZ as u32 / 15 {
        return;
    }
    let mut echantillons = 0u32;
    while !pret() && !tache::signal_en_attente() {
        let interruptions = cpu::couper_interruptions();
        attente::dormir(Some(temps::ns_monotone() + 1_000_000), Sommeil::Interruptible);
        if interruptions {
            cpu::activer_interruptions();
        }
        echantillons += 1;
        let c = cycles().to_le_bytes();
        verser(&c, u32::from(echantillons % par_bit == 0), "gigue");
        verser_les_interruptions();
    }
}

/// Attend que le générateur soit prêt (`wait_for_random_bytes`) : la gigue,
/// puis au plus une seconde d'attente d'un réveil « prêt », et ainsi de
/// suite ; un signal : ERESTARTSYS (l'appel sera refait, ou rendra EINTR).
pub fn attendre_pret() -> Result<(), i64> {
    loop {
        verser_les_interruptions();
        if pret() {
            return Ok(());
        }
        gigue();
        let echeance = temps::ns_monotone() + 1_000_000_000;
        let interruptions = cpu::couper_interruptions();
        let t = tache::courante();
        let mut r = Ok(());
        if !pret() {
            if tache::signal_en_attente() {
                r = Err(-crate::reprise::ERESTARTSYS);
            } else {
                PRET.inscrire();
                if attente::dormir(Some(echeance), Sommeil::Interruptible) == Reveil::Signal && !pret() {
                    r = Err(-crate::reprise::ERESTARTSYS);
                }
                PRET.retirer(&t);
            }
        }
        if interruptions {
            cpu::activer_interruptions();
        }
        r?;
    }
}

/// Lance la gigue sans attendre au-delà (le `/dev/urandom` d'un générateur
/// pas prêt) : elle s'arrête à « prêt », à un signal, ou tout de suite si
/// le compteur de cycles est trop grossier.
pub fn essayer_la_gigue() {
    verser_les_interruptions();
    if !pret() {
        gigue();
    }
}

/// Mêle des octets sans crédit (écrire dans /dev/random ou /dev/urandom).
pub fn melanger(octets: &[u8]) {
    verser(octets, 0, "");
}

/// Un UUID aléatoire, de version 4 (`generate_random_uuid` : la version
/// dans les 4 bits hauts de l'octet 6, la variante RFC 4122 dans les 2
/// bits hauts de l'octet 8).
pub fn uuid() -> [u8; 16] {
    let mut u = [0u8; 16];
    obtenir(&mut u);
    u[6] = u[6] & 0x0f | 0x40;
    u[8] = u[8] & 0x3f | 0x80;
    u
}

/// L'identifiant de ce démarrage (/proc/sys/kernel/random/boot_id) : un
/// UUID tiré au premier usage, le même ensuite.
pub fn identifiant_du_demarrage() -> [u8; 16] {
    static ID: Verrou<Option<[u8; 16]>> = Verrou::new(None);
    if let Some(u) = *ID.verrouiller() {
        return u;
    }
    let u = uuid();
    *ID.verrouiller().get_or_insert(u)
}
