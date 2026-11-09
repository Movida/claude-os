//! SSE pour les programmes : les registres XMM et leurs instructions.
//!
//! Tout programme x86_64 compilé normalement se sert de SSE et SSE2 :
//! l'ABI System V les rend obligatoires (les nombres à virgule passent
//! dans xmm0...), et la glibc s'en sert pour memcpy, strlen... Au
//! démarrage, le processeur les refuse : une instruction SSE fait une
//! exception « instruction invalide » tant que le système ne s'est pas
//! déclaré capable de sauvegarder leurs registres (CR4.OSFXSR). Le
//! système s'y engage ici, avec :
//!   - CR0.EM = 0 : pas d'émulation du coprocesseur (sinon, toute
//!     instruction x87 ou SSE fait une exception) ;
//!   - CR0.MP = 1 : `wait`/`fwait` tiennent compte de CR0.TS ;
//!   - CR0.NE = 1 : les erreurs du x87 arrivent comme l'exception 16, et
//!     non par l'ancienne ligne d'interruption externe du PC/AT (FERR#) ;
//!   - CR0.TS = 0 : pas de « changement de tâche » à signaler, les
//!     instructions SSE marchent tout de suite ;
//!   - CR4.OSFXSR : le système sait sauvegarder l'état SSE (`fxsave`) ;
//!   - CR4.OSXMMEXCPT : les erreurs de calcul SSE démasquées arrivent comme
//!     l'exception 19 (#XM), et non comme une instruction invalide.
//!
//! Depuis 6e, XSAVE quand le processeur l'a (CPUID.1:ECX, bit 26) : les
//! registres plus larges (AVX : YMM, 256 bits) se sauvent avec le reste.
//! Le système s'y engage par CR4.OSXSAVE, puis dit ce qu'il sauvera par
//! XCR0 (`xsetbv`) : x87, SSE, et AVX si le processeur l'a. Le processeur
//! le dit alors aux programmes (CPUID.1:ECX.OSXSAVE, et XCR0 par
//! `xgetbv`), et la glibc, Bun, choisissent leurs versions AVX : ce que
//! Linux leur donnerait. Options écartées :
//!   - XSAVEOPT (ne sauver que ce qui a changé depuis le dernier XRSTOR) :
//!     QEMU sans KVM n'en imite pas les optimisations (il sauve tout, lu
//!     dans son code), on ne pourrait pas vérifier l'invariant qu'elle
//!     demande (ne jamais écrire la zone entre son XRSTOR et le XSAVEOPT
//!     suivant, ce que fera `rt_sigreturn` en 6f) ;
//!   - le format compacté (XSAVEC, XSAVES) : TCG ne l'a pas, et le format
//!     standard est celui que verront les gestionnaires de signaux (6f) ;
//!   - AVX-512 : refusé par QEMU sans KVM (mesuré), un chemin jamais
//!     exécuté, qui triplerait la zone de chaque tâche (2,7 Kio) ; AMX (8
//!     Kio de plus, et Linux le fait demander par arch_prctl) ; PKRU (il
//!     faudrait CR4.PKE et les clés de protection) ;
//!   - la « sauvegarde paresseuse » (attendre la première instruction SSE
//!     du programme suivant, CR0.TS) : c'est la faille LazyFP,
//!     CVE-2018-3665, et Linux l'a abandonnée.
//! Sans XSAVE (qemu64, Nehalem) : FXSAVE, x87 et SSE, comme avant.
//!
//! La sauvegarde : à chaque bascule (tache.rs), de la tâche qu'on quitte si
//! c'est un programme, et le rétablissement de celle qui reprend. Le noyau,
//! compilé pour la cible x86_64-unknown-none, n'utilise jamais SSE (le
//! compilateur n'en émet pas) : les registres du programme ne sont touchés
//! par personne pendant un appel système ou une interruption, ni par une
//! tâche du noyau. Chaque tâche de programme a sa zone (`ZoneFpu`), de la
//! taille que dit le processeur (CPUID 0xD, une fois XCR0 posé), alignée
//! sur 64 octets comme l'exige XSAVE.
//!
//! Chaque programme part d'un état propre : sa zone reçoit l'image de
//! l'état initial, rétablie par la bascule, comme
//! restore_fpregs_from_init_fpstate dans Linux. Mot de contrôle x87 0x037F,
//! MXCSR = 0x1F80 (toutes les exceptions SSE masquées, arrondi au plus
//! près : la valeur de l'ABI), et TOUS les registres de données à zéro :
//! XMM0-XMM15, mais aussi ST0-ST7, que partagent les registres MMX. (`fninit`
//! ne suffirait pas : il remet le contrôle et les étiquettes à l'état
//! initial, mais laisse les données de ST0-ST7 ; un programme qui lirait
//! mm0 trouverait ce qu'y a laissé le précédent.) Avec XSAVE, l'en-tête de
//! la zone (octets 512 à 575) est nul : tous les composants à leur état
//! initial, sauf MXCSR, que XRSTOR lit toujours dans la zone (manuel
//! d'Intel, vol. 1, 13.8) ; le reste de la zone, à zéro aussi.

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use core::arch::{asm, global_asm};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Les composants que sauve XSAVE (XCR0) ; 0 : FXSAVE.
static COMPOSANTS: AtomicU64 = AtomicU64::new(0);
/// La taille de la zone d'une tâche.
static TAILLE: AtomicU64 = AtomicU64::new(512);
/// Les bits de MXCSR que le processeur accepte (MXCSR_MASK, que rend
/// FXSAVE ; 0xFFBF s'il y laisse 0, manuel d'Intel vol. 1, 11.6.6) : un
/// MXCSR rendu par un gestionnaire de signal avec un autre bit ferait une
/// faute de protection générale au XRSTOR (le `mxcsr_feature_mask` de
/// Linux).
static MASQUE_MXCSR: AtomicU32 = AtomicU32::new(0xFFBF);

/// La plus grande zone que le noyau sache mettre dans un cadre de signal
/// (cadre_signal.rs) : celle de x87, SSE et AVX fait 832 octets ; AVX-512
/// (2,7 Kio), que nous ne prenons pas, n'y tiendrait pas.
pub const TAILLE_MAX: usize = 1024;

/// L'état initial, pour FXRSTOR et pour XRSTOR (aligné sur 64 octets) : mot
/// de contrôle x87 0x037F, MXCSR 0x1F80, tout le reste à zéro, en-tête de
/// XSAVE compris (tous les composants à leur état initial ; MXCSR est lu
/// dans la zone même alors). Ce que reçoit un gestionnaire de signal (le
/// `init_fpstate` de Linux).
#[repr(C, align(64))]
struct Initial([u8; TAILLE_MAX]);

static INITIAL: Initial = {
    let mut o = [0u8; TAILLE_MAX];
    o[0] = 0x7F;
    o[1] = 0x03;
    o[24] = 0x80;
    o[25] = 0x1F;
    Initial(o)
};

// XRSTOR et FXRSTOR depuis une zone du noyau, avec une entrée dans la table
// d'exceptions (copie_utilisateur.rs) : une faute de protection générale
// (un en-tête ou un MXCSR que le processeur refuse, venus d'un programme
// par rt_sigreturn) reprend à l'étiquette 2, qui rend 1, au lieu d'arrêter
// le noyau (le `os_xrstor_safe` de Linux). Les vérifications de
// cadre_signal.rs refusent déjà ce qui ferait cette faute : la table est
// la seconde ligne de défense.
global_asm!(
    r#"
    .section .text
    /* xrstor_protege(zone (rdi), composants : eax (esi) et edx (edx)) */
    .global xrstor_protege
xrstor_protege:
    mov eax, esi
1:  xrstor64 [rdi]
    xor eax, eax
    ret
2:  mov eax, 1
    ret
    .pushsection __ex_table, "a"
    .balign 8
    .quad 1b, 2b
    .popsection

    /* fxrstor_protege(zone (rdi)) */
    .global fxrstor_protege
fxrstor_protege:
3:  fxrstor64 [rdi]
    xor eax, eax
    ret
4:  mov eax, 1
    ret
    .pushsection __ex_table, "a"
    .balign 8
    .quad 3b, 4b
    .popsection
    "#
);

unsafe extern "C" {
    fn xrstor_protege(zone: *const u8, bas: u32, haut: u32) -> u32;
    fn fxrstor_protege(zone: *const u8) -> u32;
}

const X87: u64 = 1 << 0;
const SSE: u64 = 1 << 1;
const AVX: u64 = 1 << 2;

/// Ce que l'initialisation a fait, pour l'afficher.
pub struct Bilan {
    /// XSAVE est-il en service ?
    pub xsave: bool,
    /// AVX aussi ?
    pub avx: bool,
    /// La taille de la zone d'une tâche, en octets.
    pub taille: u64,
}

/// Les bits de CR0 et CR4 de SSE (voir l'en-tête), sur le processeur qui
/// exécute ceci.
fn activer_registres() {
    // SAFETY: les bits écrits sont ceux décrits plus haut ; le noyau ne
    // se sert pas de SSE, rien ne change pour lui.
    unsafe {
        asm!(
            "mov {t}, cr0",
            "and {t}, ~((1 << 2) | (1 << 3))", // EM = 0, TS = 0
            "or {t}, (1 << 1) | (1 << 5)",     // MP = 1, NE = 1
            "mov cr0, {t}",
            "mov {t}, cr4",
            "or {t}, (1 << 9) | (1 << 10)",    // OSFXSR, OSXMMEXCPT
            "mov cr4, {t}",
            t = out(reg) _,
            options(nostack),
        );
    }
}

/// CR4.OSXSAVE, puis XCR0 = `composants` (`xsetbv`), sur le processeur qui
/// exécute ceci.
///
/// # Safety
/// `composants` ne doit contenir que des composants que le processeur
/// offre (CPUID 0xD), x87 compris.
unsafe fn poser_xcr0(composants: u64) {
    // SAFETY: CR4.OSXSAVE (bit 18) permet xsetbv ; garanti par l'appelant
    // pour les composants.
    unsafe {
        asm!("mov {t}, cr4", "or {t}, 1 << 18", "mov cr4, {t}", t = out(reg) _, options(nostack));
        asm!("xsetbv", in("ecx") 0, in("eax") composants as u32, in("edx") (composants >> 32) as u32, options(nostack));
    }
}

/// Un processeur secondaire (smp.rs) : les mêmes registres que le premier
/// (le trampoline les a déjà copiés, CR0 et CR4 compris ; reposés ici pour
/// ne dépendre de rien, comme le `fpu__init_cpu` de Linux), et XCR0 à ce
/// que le premier a choisi : tous les processeurs sauvent les mêmes
/// composants, dans des zones de la même taille.
pub fn initialiser_secondaire() {
    activer_registres();
    let composants = composants();
    if composants != 0 {
        // SAFETY: ces composants, le premier processeur les a trouvés
        // offerts par CPUID ; les processeurs d'une machine sont les mêmes
        // (smp.rs le vérifie ensuite en comparant XCR0).
        unsafe { poser_xcr0(composants) };
    }
}

/// XCR0 (`xgetbv`), 0 sans XSAVE : pour le comparer d'un processeur à
/// l'autre (smp.rs).
pub fn xcr0() -> u64 {
    if composants() == 0 {
        return 0;
    }
    let (bas, haut): (u32, u32);
    // SAFETY: CR4.OSXSAVE est posé dès que COMPOSANTS n'est pas nul ;
    // xgetbv ne fait que lire.
    unsafe { asm!("xgetbv", in("ecx") 0, out("eax") bas, out("edx") haut, options(nomem, nostack, preserves_flags)) };
    (haut as u64) << 32 | bas as u64
}

/// Met SSE en service pour les programmes, et XSAVE si le processeur l'a.
/// Tout processeur 64 bits a SSE, SSE2 et FXSAVE (l'architecture x86_64 les
/// exige) : rien à vérifier pour eux. Sur le premier processeur ; les
/// secondaires reprennent ses choix (`initialiser_secondaire`).
pub fn initialiser() -> Bilan {
    activer_registres();
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    // MXCSR_MASK : les octets 28 à 31 d'une image FXSAVE.
    let mut image = Initial([0; TAILLE_MAX]);
    // SAFETY: FXSAVE écrit 512 octets dans une zone alignée à nous ; le
    // processeur n'a encore l'état d'aucun programme.
    unsafe { asm!("fxsave64 [{}]", in(reg) image.0.as_mut_ptr(), options(nostack)) };
    let masque = u32::from_le_bytes([image.0[28], image.0[29], image.0[30], image.0[31]]);
    if masque != 0 {
        MASQUE_MXCSR.store(masque, Ordering::Relaxed);
    }
    if __cpuid(1).ecx & 1 << 26 == 0 {
        return Bilan { xsave: false, avx: false, taille: 512 };
    }
    // Les composants que le processeur sait sauver (CPUID 0xD, EDX:EAX) ;
    // nous n'en prenons que x87, SSE et AVX.
    let d = __cpuid_count(0xD, 0);
    let offerts = (d.edx as u64) << 32 | d.eax as u64;
    let composants = (X87 | SSE | AVX) & offerts;
    // SAFETY: XCR0 ne reçoit que des composants que le processeur offre,
    // x87 compris (obligatoire).
    unsafe { poser_xcr0(composants) };
    // La taille de la zone pour les composants en service (EBX, une fois
    // XCR0 posé).
    let taille = __cpuid_count(0xD, 0).ebx as u64;
    assert!(taille as usize <= TAILLE_MAX, "zone XSAVE trop grande pour un cadre de signal");
    COMPOSANTS.store(composants, Ordering::Relaxed);
    TAILLE.store(taille, Ordering::Relaxed);
    Bilan { xsave: true, avx: composants & AVX != 0, taille }
}

/// Les composants que sauve XSAVE (XCR0), 0 sans XSAVE (FXSAVE).
pub fn composants() -> u64 {
    COMPOSANTS.load(Ordering::Relaxed)
}

/// La taille de l'image de l'état : 512 octets avec FXSAVE, ce que dit le
/// processeur avec XSAVE (832 pour x87, SSE et AVX).
pub fn taille() -> usize {
    TAILLE.load(Ordering::Relaxed) as usize
}

/// Les bits permis de MXCSR.
pub fn masque_mxcsr() -> u32 {
    MASQUE_MXCSR.load(Ordering::Relaxed)
}

/// Les exceptions flottantes signalées et non masquées du programme, lues
/// dans ses registres, encore en place après sa faute : pour #MF (16), le
/// mot d'état x87 moins son mot de contrôle (les bits masqués) ; pour #XM
/// (19), MXCSR, ses drapeaux moins ses masques (7 bits plus haut). Les
/// mêmes bits pour les deux (invalide, dénormal, division par zéro,
/// débordements, inexact), que linux.rs traduit en si_code.
pub fn exceptions_en_attente(vecteur: usize) -> u32 {
    if vecteur == 16 {
        let (mut controle, mut etat) = (0u16, 0u16);
        // SAFETY: lire le mot de contrôle et le mot d'état x87 ne change
        // rien ; ce sont ceux du programme (le noyau ne s'en sert pas).
        unsafe {
            asm!("fnstcw [{}]", in(reg) &mut controle, options(nostack));
            asm!("fnstsw [{}]", in(reg) &mut etat, options(nostack));
        }
        (etat & !controle) as u32
    } else {
        let mut mxcsr = 0u32;
        // SAFETY: lire MXCSR ne change rien ; c'est celui du programme.
        unsafe { asm!("stmxcsr [{}]", in(reg) &mut mxcsr, options(nostack)) };
        !(mxcsr >> 7) & mxcsr
    }
}

/// Sauve l'état x87/SSE/AVX du processeur (celui de la tâche courante,
/// un programme) dans `zone`, au format standard (cadre_signal.rs).
pub fn sauver_dans(zone: &mut ImageFpu) {
    let c = composants();
    // SAFETY: la zone est alignée sur 64 et assez grande (TAILLE_MAX) ;
    // le noyau ne se sert pas de SSE : l'état est celui du programme.
    unsafe {
        if c == 0 {
            asm!("fxsave64 [{}]", in(reg) zone.0.as_mut_ptr(), options(nostack));
        } else {
            asm!("xsave64 [{}]", in(reg) zone.0.as_mut_ptr(), in("eax") c as u32, in("edx") (c >> 32) as u32,
                 options(nostack));
        }
    }
}

/// Met l'état x87/SSE/AVX du processeur à l'état initial (pour un
/// gestionnaire de signal : `fpu__clear_user_states`).
pub fn charger_initial() {
    let c = composants();
    // SAFETY: l'image initiale est valide (en-tête nul, MXCSR permis).
    unsafe {
        if c == 0 {
            fxrstor_protege(INITIAL.0.as_ptr());
        } else {
            xrstor_protege(INITIAL.0.as_ptr(), c as u32, (c >> 32) as u32);
        }
    }
}

/// Charge dans le processeur les composants `rfbm` de `zone` (XRSTOR ;
/// FXRSTOR si `rfbm` vaut 0). Faux si le processeur l'a refusé (une faute
/// de protection générale, reprise par la table d'exceptions).
pub fn charger(zone: &ImageFpu, rfbm: u64) -> bool {
    // SAFETY: la zone est alignée et assez grande ; un contenu refusé fait
    // une faute reprise.
    unsafe {
        if rfbm == 0 {
            fxrstor_protege(zone.0.as_ptr()) == 0
        } else {
            xrstor_protege(zone.0.as_ptr(), rfbm as u32, (rfbm >> 32) as u32) == 0
        }
    }
}

/// Une image de l'état x87/SSE/AVX dans le noyau (pour un cadre de signal),
/// alignée sur 64 octets, de la plus grande taille possible.
#[repr(C, align(64))]
pub struct ImageFpu(pub [u8; TAILLE_MAX]);

/// La zone de l'état x87, SSE (et AVX) d'une tâche de programme, au format
/// de FXSAVE ou de XSAVE (standard), alignée sur 64 octets.
pub struct ZoneFpu {
    octets: NonNull<u8>,
}

// SAFETY: la zone n'est lue et écrite que par la bascule (tache.rs),
// interruptions coupées, et par qui la crée ou la copie.
unsafe impl Send for ZoneFpu {}

fn disposition() -> Layout {
    Layout::from_size_align(TAILLE.load(Ordering::Relaxed) as usize, 64).expect("taille de la zone FPU")
}

impl ZoneFpu {
    /// Une zone à l'état initial (`initiale` : l'image de 512 octets de
    /// l'état initial, au format de FXSAVE) ; None : plus de mémoire.
    pub fn neuve(initiale: &[u8; 512]) -> Option<ZoneFpu> {
        // SAFETY: la disposition a une taille non nulle (512 au moins).
        let p = NonNull::new(unsafe { alloc_zeroed(disposition()) })?;
        // SAFETY: la zone fait au moins 512 octets, et vient d'être allouée.
        unsafe { core::ptr::copy_nonoverlapping(initiale.as_ptr(), p.as_ptr(), 512) };
        Some(ZoneFpu { octets: p })
    }

    /// Une zone qui reçoit l'état x87/SSE/AVX du processeur, celui de la
    /// tâche courante : l'état d'un fil neuf, copié de son créateur (le
    /// `fpu_clone` de Linux : un fil hérite de son mode d'arrondi, mesuré).
    /// None : plus de mémoire.
    pub fn du_processeur() -> Option<ZoneFpu> {
        // SAFETY: comme `neuve`.
        let p = NonNull::new(unsafe { alloc_zeroed(disposition()) })?;
        let mut zone = ZoneFpu { octets: p };
        let interruptions = crate::cpu::couper_interruptions();
        // SAFETY: interruptions coupées, l'état du processeur est celui de
        // la tâche courante ; la copie va dans une zone à nous.
        unsafe { zone.sauver() };
        if interruptions {
            crate::cpu::activer_interruptions();
        }
        Some(zone)
    }

    /// Sauve l'état x87/SSE/AVX du processeur dans la zone.
    ///
    /// # Safety
    /// Interruptions coupées : l'état doit être celui de la tâche à qui est
    /// la zone.
    pub unsafe fn sauver(&mut self) {
        let composants = COMPOSANTS.load(Ordering::Relaxed);
        // SAFETY: la zone est alignée sur 64 et de la taille que dit le
        // processeur ; garanti par l'appelant pour le reste.
        unsafe {
            if composants == 0 {
                asm!("fxsave64 [{}]", in(reg) self.octets.as_ptr(), options(nostack));
            } else {
                asm!("xsave64 [{}]", in(reg) self.octets.as_ptr(), in("eax") composants as u32,
                     in("edx") (composants >> 32) as u32, options(nostack));
            }
        }
    }

    /// Rétablit l'état x87/SSE/AVX de la zone dans le processeur.
    ///
    /// # Safety
    /// Comme `sauver`, et la zone a été écrite par `sauver` ou `neuve`.
    pub unsafe fn retablir(&self) {
        let composants = COMPOSANTS.load(Ordering::Relaxed);
        // SAFETY: comme `sauver` ; l'en-tête d'une zone neuve est nul et
        // son MXCSR valide : XRSTOR ne fait pas de faute.
        unsafe {
            if composants == 0 {
                asm!("fxrstor64 [{}]", in(reg) self.octets.as_ptr(), options(nostack));
            } else {
                asm!("xrstor64 [{}]", in(reg) self.octets.as_ptr(), in("eax") composants as u32,
                     in("edx") (composants >> 32) as u32, options(nostack));
            }
        }
    }
}

impl Drop for ZoneFpu {
    fn drop(&mut self) {
        // SAFETY: la zone vient d'alloc_zeroed, avec la même disposition.
        unsafe { dealloc(self.octets.as_ptr(), disposition()) };
    }
}
