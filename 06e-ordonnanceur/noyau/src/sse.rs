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
use core::arch::asm;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

/// Les composants que sauve XSAVE (XCR0) ; 0 : FXSAVE.
static COMPOSANTS: AtomicU64 = AtomicU64::new(0);
/// La taille de la zone d'une tâche.
static TAILLE: AtomicU64 = AtomicU64::new(512);

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

/// Met SSE en service pour les programmes, et XSAVE si le processeur l'a.
/// Tout processeur 64 bits a SSE, SSE2 et FXSAVE (l'architecture x86_64 les
/// exige) : rien à vérifier pour eux.
pub fn initialiser() -> Bilan {
    // SAFETY : les bits écrits sont ceux décrits plus haut ; le noyau ne
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
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    if __cpuid(1).ecx & 1 << 26 == 0 {
        return Bilan { xsave: false, avx: false, taille: 512 };
    }
    // Les composants que le processeur sait sauver (CPUID 0xD, EDX:EAX) ;
    // nous n'en prenons que x87, SSE et AVX.
    let d = __cpuid_count(0xD, 0);
    let offerts = (d.edx as u64) << 32 | d.eax as u64;
    let composants = (X87 | SSE | AVX) & offerts;
    // SAFETY : CR4.OSXSAVE (bit 18) permet xsetbv ; XCR0 ne reçoit que des
    // composants que le processeur offre, x87 compris (obligatoire).
    unsafe {
        asm!("mov {t}, cr4", "or {t}, 1 << 18", "mov cr4, {t}", t = out(reg) _, options(nostack));
        asm!("xsetbv", in("ecx") 0, in("eax") composants as u32, in("edx") (composants >> 32) as u32, options(nostack));
    }
    // La taille de la zone pour les composants en service (EBX, une fois
    // XCR0 posé).
    let taille = __cpuid_count(0xD, 0).ebx as u64;
    COMPOSANTS.store(composants, Ordering::Relaxed);
    TAILLE.store(taille, Ordering::Relaxed);
    Bilan { xsave: true, avx: composants & AVX != 0, taille }
}

/// La zone de l'état x87, SSE (et AVX) d'une tâche de programme, au format
/// de FXSAVE ou de XSAVE (standard), alignée sur 64 octets.
pub struct ZoneFpu {
    octets: NonNull<u8>,
}

// SAFETY : la zone n'est lue et écrite que par la bascule (tache.rs),
// interruptions coupées, et par qui la crée ou la copie.
unsafe impl Send for ZoneFpu {}

fn disposition() -> Layout {
    Layout::from_size_align(TAILLE.load(Ordering::Relaxed) as usize, 64).expect("taille de la zone FPU")
}

impl ZoneFpu {
    /// Une zone à l'état initial (`initiale` : l'image de 512 octets de
    /// l'état initial, au format de FXSAVE) ; None : plus de mémoire.
    pub fn neuve(initiale: &[u8; 512]) -> Option<ZoneFpu> {
        // SAFETY : la disposition a une taille non nulle (512 au moins).
        let p = NonNull::new(unsafe { alloc_zeroed(disposition()) })?;
        // SAFETY : la zone fait au moins 512 octets, et vient d'être allouée.
        unsafe { core::ptr::copy_nonoverlapping(initiale.as_ptr(), p.as_ptr(), 512) };
        Some(ZoneFpu { octets: p })
    }

    /// Sauve l'état x87/SSE/AVX du processeur dans la zone.
    ///
    /// # Safety
    /// Interruptions coupées : l'état doit être celui de la tâche à qui est
    /// la zone.
    pub unsafe fn sauver(&mut self) {
        let composants = COMPOSANTS.load(Ordering::Relaxed);
        // SAFETY : la zone est alignée sur 64 et de la taille que dit le
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
        // SAFETY : comme `sauver` ; l'en-tête d'une zone neuve est nul et
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
        // SAFETY : la zone vient d'alloc_zeroed, avec la même disposition.
        unsafe { dealloc(self.octets.as_ptr(), disposition()) };
    }
}
