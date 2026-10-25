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
//! Ce qu'on NE fait PAS encore :
//!   - CR4.OSXSAVE : XSAVE sauvegarde aussi les registres plus larges
//!     (AVX : 256 bits, AVX-512 : 512 bits). Sans OSXSAVE, le processeur
//!     refuse AVX, et CPUID le dit aux programmes (le bit OSXSAVE reste à
//!     0) : la glibc choisit alors d'elle-même ses versions SSE2. On ne
//!     promet que ce qu'on sait faire. (Le processeur qemu64 n'a d'ailleurs
//!     pas XSAVE.)
//!   - La sauvegarde à chaque bascule : un seul programme à la fois, et le
//!     noyau, compilé pour la cible x86_64-unknown-none, n'utilise jamais
//!     SSE (le compilateur n'en émet pas) : les registres XMM du programme
//!     ne sont touchés par personne pendant un appel système ou une
//!     interruption. À l'étape 6, avec l'ordonnanceur : XSAVE à chaque
//!     bascule, sans « sauvegarde paresseuse » (attendre la première
//!     instruction SSE du programme suivant, CR0.TS, pour sauvegarder :
//!     c'est la faille LazyFP, CVE-2018-3665, et Linux l'a abandonnée),
//!     et XCR0 sans AMX (8 Kio d'état de plus par tâche).
//!
//! Chaque programme part d'un état propre (tache.rs, premier_depart) : un
//! seul `fxrstor` depuis une image de l'état initial, comme
//! restore_fpregs_from_init_fpstate dans Linux. Mot de contrôle x87 0x037F,
//! MXCSR = 0x1F80 (toutes les exceptions SSE masquées, arrondi au plus
//! près : la valeur de l'ABI), et TOUS les registres de données à zéro :
//! XMM0-XMM15, mais aussi ST0-ST7, que partagent les registres MMX. (`fninit`
//! ne suffirait pas : il remet le contrôle et les étiquettes à l'état
//! initial, mais laisse les données de ST0-ST7 ; un programme qui lirait
//! mm0 trouverait ce qu'y a laissé le précédent.)

use core::arch::asm;

/// Met SSE en service pour les programmes. Tout processeur 64 bits a SSE,
/// SSE2 et FXSAVE (l'architecture x86_64 les exige) : rien à vérifier.
pub fn initialiser() {
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
}
