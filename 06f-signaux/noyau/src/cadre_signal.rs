//! Le cadre de signal : appeler le gestionnaire d'un programme, et en
//! revenir (rt_sigreturn).
//!
//! Un gestionnaire est une fonction du programme, que le noyau doit faire
//! exécuter AU MILIEU de ce que faisait le programme, puis faire reprendre
//! celui-ci exactement là où il était, tous ses registres intacts. Le noyau
//! ne garde rien de ce contexte : il le range dans la mémoire du programme,
//! sur sa pile (ou sur sa pile de secours, SA_ONSTACK), dans un CADRE DE
//! SIGNAL, puis change le cadre de retour vers l'anneau 3 (le `Cadre` en
//! haut de la pile noyau du fil) pour « appeler » le gestionnaire :
//!   - RIP : le gestionnaire ; RSP : le cadre de signal, dont le premier mot
//!     est l'adresse de retour du gestionnaire, le `__restore_rt` de la
//!     glibc (sa_restorer), qui fait l'appel système rt_sigreturn ;
//!   - rdi : le numéro du signal ; rsi : son siginfo ; rdx : l'ucontext, le
//!     contexte rangé (que le gestionnaire peut lire et CHANGER : un JIT
//!     saute l'instruction fautive en changeant RIP) ; rax : 0.
//! rt_sigreturn relit le contexte rangé (peut-être changé), le vérifie, et
//! le rétablit dans le cadre de retour : le programme reprend.
//!
//! Choix de conception : le cadre de Linux pour x86_64, octet pour octet
//! (mesuré sur Linux 6.18 par une sonde, et lu dans arch/x86/kernel/
//! signal.c, signal_64.c, fpu/signal.c). La glibc, Bun et JavaScriptCore
//! lisent l'ucontext : JSC y prend les registres d'un fil suspendu pour son
//! ramasse-miettes, Bun y lit RIP pour son rapport de plantage. Un cadre à
//! nous casserait tout programme qui touche à son contexte. Depuis le RSP
//! interrompu, vers le bas :
//!   - la zone rouge de l'ABI, 128 octets, que le programme peut utiliser
//!     sans déplacer RSP : sautée ;
//!   - l'état x87/SSE/AVX du programme (`fpstate`), aligné sur 64 : l'image
//!     de XSAVE au format standard, avec dans ses octets 464 à 511 (que le
//!     processeur laisse au logiciel) les `fpx_sw_bytes` : FP_XSTATE_MAGIC1,
//!     la taille, les composants ; et FP_XSTATE_MAGIC2 juste après l'image.
//!     Sans XSAVE, l'image de FXSAVE (512 octets), avec les mêmes
//!     `fpx_sw_bytes` (extended_size 516, aucun composant : Linux les écrit
//!     aussi, `save_xstate_epilog`), mais sans MAGIC2 ;
//!   - le `rt_sigframe` (440 octets) : l'adresse de retour, l'ucontext (304
//!     octets : drapeaux, lien, pile de secours, le `sigcontext` de 256
//!     octets avec les registres, le masque d'avant), le siginfo (128) ;
//!     son début arrondi à 16 octets, moins 8 : le RSP qu'aurait une
//!     fonction appelée par `call` (l'ABI : RSP + 8 multiple de 16).
//! Mesuré : pour un RSP interrompu S, le gestionnaire voit RSP = S - 1448
//! (XSAVE de 832 octets), l'ucontext à RSP + 8, le siginfo à RSP + 312, le
//! fpstate à l'ucontext + 448.
//!
//! Le gestionnaire part de l'état x87/SSE initial (MXCSR 0x1F80, contrôle
//! x87 0x037F), comme sous Linux (`fpu__clear_user_states`) : celui du
//! programme est dans le cadre, rétabli au retour.
//!
//! Le cadre est préparé dans un tampon du noyau puis copié d'un coup (les
//! copies protégées de copie_utilisateur.rs) ; jamais sous un verrou : la
//! copie peut faire une faute de page, servie. Un cadre qu'on ne peut pas
//! écrire (une pile pleine, une pile de secours trop petite, un RSP
//! absurde) : SIGSEGV forcé (`force_sigsegv`), mortel si c'était déjà
//! SIGSEGV. Option écartée : écrire les champs un à un dans la mémoire du
//! programme (Linux, avec `unsafe_put_user`, pour la vitesse) : un tampon
//! et une copie se relisent mieux, et 1,4 Kio par signal ne coûtent rien.
//!
//! Le retour (rt_sigreturn) : le contexte est lu, puis rétabli comme le fait
//! `restore_sigcontext` : les registres tels quels ; CS et SS forcés en
//! anneau 3 (un sélecteur invalide fera faire une faute à `iretq` : un
//! signal pour le programme, voir l'en-tête d'interruptions.rs) ; seuls les
//! drapeaux de FIX_EFLAGS (AC, OF, DF, TF, SF, ZF, AF, PF, CF, RF) viennent
//! du contexte, jamais IF ni IOPL ; le masque (sans SIGKILL ni SIGSTOP), la
//! pile de secours. L'état x87/SSE est copié dans un tampon du noyau et
//! VÉRIFIÉ avant d'être chargé : la magie (sans elle, une image FXSAVE
//! seule, les composants suivants remis à l'état initial), l'en-tête de
//! XSAVE (des composants permis, le format standard, des réserves nulles),
//! MXCSR. Un contexte refusé : SIGSEGV forcé. Le chargement lui-même est
//! dans la table d'exceptions (sse.rs) : si le processeur refusait quand
//! même, ce serait un SIGSEGV, jamais une faute du noyau.

use crate::copie_utilisateur::{copier_depuis_utilisateur, copier_vers_utilisateur};
use crate::interruptions::Cadre;
use crate::signaux::{self, Action, Info, PileDeSecours};
use crate::sse::{self, ImageFpu};
use crate::{gdt, linux, processus, tache};

/// Les drapeaux de l'ucontext (uc_flags) : l'état est au format XSAVE ;
/// SS est rangé dans le sigcontext ; et rt_sigreturn doit le rétablir tel
/// quel (sans lui, un SS invalide est remplacé : `force_valid_ss`).
const UC_FP_XSTATE: u64 = 1;
const UC_SIGCONTEXT_SS: u64 = 2;
const UC_STRICT_RESTORE_SS: u64 = 4;

/// Les mots magiques de l'état étendu (asm/sigcontext.h).
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;

/// La taille du `rt_sigframe` : l'adresse de retour (8), l'ucontext (304),
/// le siginfo (128).
const TAILLE_RT_SIGFRAME: u64 = 440;
/// Les positions dans le `rt_sigframe`.
const UC: usize = 8;
const UC_STACK: usize = UC + 16;
const UC_MCONTEXT: usize = UC + 40;
const UC_SIGMASK: usize = UC + 296;
const INFO: usize = UC + 304;
/// Dans le sigcontext : les seize registres généraux dans l'ordre r8 à r15,
/// rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp, puis rip, eflags, puis cs, gs,
/// fs, ss (16 bits chacun), err, trapno, oldmask, cr2, fpstate.
const SC_RIP: usize = 16 * 8;
const SC_EFLAGS: usize = 17 * 8;
const SC_CS: usize = 18 * 8;
const SC_ERR: usize = 19 * 8;
const SC_TRAPNO: usize = 20 * 8;
const SC_OLDMASK: usize = 21 * 8;
const SC_CR2: usize = 22 * 8;
const SC_FPSTATE: usize = 23 * 8;

/// Les drapeaux de RFLAGS que rt_sigreturn reprend du contexte (FIX_EFLAGS).
const FIX_EFLAGS: u64 = 1 << 18 | 1 << 11 | 1 << 10 | 1 << 8 | 1 << 7 | 1 << 6 | 1 << 4 | 1 << 2 | 1 << 0 | 1 << 16;
/// Ceux qu'efface l'entrée dans un gestionnaire : DF (l'ABI le veut à 0 à
/// l'entrée d'une fonction), RF et TF (pas de pas-à-pas dans le
/// gestionnaire : `handle_signal`).
const EFFACES_A_L_ENTREE: u64 = 1 << 10 | 1 << 16 | 1 << 8;

/// La zone rouge de l'ABI System V : 128 octets sous RSP.
const ZONE_ROUGE: u64 = 128;

/// La taille de l'état dans un cadre : l'image, plus MAGIC2 avec XSAVE.
fn taille_etat() -> u64 {
    let t = sse::taille() as u64;
    if sse::composants() != 0 { t + 4 } else { t }
}

/// AT_MINSIGSTKSZ, la plus petite pile de secours qui tienne un cadre : le
/// calcul de Linux (`init_sigframe_size`) pour un noyau 64 bits seul, sans
/// émulation 32 bits : le rt_sigframe, le pire alignement à 16, l'état, le
/// pire alignement à 64, arrondi à 16. 1360 octets avec XSAVE (x87, SSE,
/// AVX), 1040 avec FXSAVE.
pub fn taille_minimale() -> u64 {
    (TAILLE_RT_SIGFRAME + 15 + taille_etat() + 63).next_multiple_of(16)
}

/// Le tampon où se prépare un cadre : la place du plus grand (le
/// rt_sigframe, son alignement, la plus grande image d'état), aligné sur 64
/// comme l'image que XSAVE y écrit.
#[repr(C, align(64))]
struct Tampon([u8; 512 + sse::TAILLE_MAX + 64]);

/// Un mot de 64 bits à la position `i` du tampon.
fn poser(o: &mut [u8], i: usize, v: u64) {
    o[i..i + 8].copy_from_slice(&v.to_le_bytes());
}

fn lire(o: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(o[i..i + 8].try_into().unwrap_or([0; 8]))
}

/// Les registres généraux du cadre de retour, dans l'ordre du sigcontext.
fn registres(c: &Cadre) -> [u64; 16] {
    [c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15, c.rdi, c.rsi, c.rbp, c.rbx, c.rdx, c.rax, c.rcx, c.rsp]
}

fn retablir_registres(c: &mut Cadre, r: &[u64; 16]) {
    [c.r8, c.r9, c.r10, c.r11, c.r12, c.r13, c.r14, c.r15, c.rdi, c.rsi, c.rbp, c.rbx, c.rdx, c.rax, c.rcx, c.rsp] = *r;
}

/// Pourquoi un cadre n'a pas pu être posé.
pub struct Impossible;

/// Pose le cadre du signal `sig` (siginfo `info`, action `action`) pour la
/// tâche courante, dont `cadre` est le cadre de retour vers l'anneau 3, et
/// change ce dernier pour entrer dans le gestionnaire. `masque` : le masque
/// à rétablir au retour (celui d'avant). Dans l'ordre de `handle_signal`
/// puis `x64_setup_rt_frame` et `get_sigframe`. Err : le cadre ne peut pas
/// être posé (SA_RESTORER absent, plus de place sur la pile de secours, une
/// pile où l'on ne peut pas écrire) ; rien n'a changé, et l'appelant force
/// SIGSEGV.
pub fn poser_cadre(cadre: &mut Cadre, sig: u64, info: &Info, action: &Action, masque: u64, pile: PileDeSecours)
    -> Result<(), Impossible> {
    // x86_64 exige que la glibc donne son __restore_rt.
    if action.drapeaux & signaux::SA_RESTORER == 0 {
        afficherln!("[noyau] {} : gestionnaire de {} sans SA_RESTORER (pas d'adresse de retour)", tache::nom(), signaux::signal(sig).nom);
        return Err(Impossible);
    }
    let sp = cadre.rsp.wrapping_sub(ZONE_ROUGE);
    let deja_dessus = pile.dessus(cadre.rsp);
    let mut sp_cadre = sp;
    let mut entre = false;
    // SA_ONSTACK : sur la pile de secours, si elle est armée et qu'on n'y est
    // pas déjà (`sas_ss_flags(sp) == 0`).
    if action.drapeaux & signaux::SA_ONSTACK != 0 && pile.etat(sp) == 0 {
        sp_cadre = pile.adresse.wrapping_add(pile.taille);
        entre = true;
    }
    let fpstate = sp_cadre.wrapping_sub(taille_etat()) & !63;
    let debut = (fpstate.wrapping_sub(TAILLE_RT_SIGFRAME) & !15).wrapping_sub(8);
    // Un cadre qui sortirait de la pile de secours : une adresse toujours
    // fausse, pour mourir de SIGSEGV (Linux : « overflowed sigaltstack »).
    if (deja_dessus || entre) && !pile.contient(debut) {
        afficherln!("[noyau] {} : debordement de la pile de secours (cadre du signal {})", tache::nom(), signaux::signal(sig).nom);
        return Err(Impossible);
    }
    // Le tampon commence à l'adresse alignée sur 64 qui précède le cadre ;
    // l'image d'état y est donc alignée sur 64 comme dans le programme.
    let base = debut & !63;
    let (o_cadre, o_fp) = ((debut - base) as usize, (fpstate - base) as usize);
    let fin = o_fp + taille_etat() as usize;
    let mut t = Tampon([0; 512 + sse::TAILLE_MAX + 64]);
    debug_assert!(fin <= t.0.len());

    // L'état x87/SSE/AVX du programme (dans les registres pendant son
    // appel, ou son interruption : le noyau ne s'en sert pas), puis les
    // octets du logiciel et MAGIC2 (`save_xstate_epilog`).
    let mut image = ImageFpu([0; sse::TAILLE_MAX]);
    sse::sauver_dans(&mut image);
    let taille = sse::taille();
    t.0[o_fp..o_fp + taille].copy_from_slice(&image.0[..taille]);
    let composants = sse::composants();
    let sw = o_fp + 464;
    t.0[sw..sw + 4].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    t.0[sw + 4..sw + 8].copy_from_slice(&((taille + 4) as u32).to_le_bytes());
    poser(&mut t.0, sw + 8, composants);
    t.0[sw + 16..sw + 20].copy_from_slice(&(taille as u32).to_le_bytes());
    if composants != 0 {
        t.0[o_fp + taille..o_fp + taille + 4].copy_from_slice(&FP_XSTATE_MAGIC2.to_le_bytes());
        // x87 et SSE toujours dits présents dans l'en-tête : un programme
        // qui ne connaît que l'image FXSAVE peut les changer, rt_sigreturn
        // les verra (`set_xfeature_in_sigframe`).
        let xstate_bv = lire(&t.0, o_fp + 512) | 3;
        poser(&mut t.0, o_fp + 512, xstate_bv);
    }

    // Le rt_sigframe.
    let f = &mut t.0[o_cadre..o_cadre + TAILLE_RT_SIGFRAME as usize];
    poser(f, 0, action.restaurateur);
    // UC_STRICT_RESTORE_SS seulement si le programme interrompu était en 64
    // bits (`frame_uc_flags`) : après un iretq refusé, son CS est celui,
    // faux, qu'il avait rendu, et rt_sigreturn devra pouvoir réparer SS
    // quand le gestionnaire n'aura réparé que CS.
    let strict = if cadre.cs == gdt::CODE_UTILISATEUR as u64 { UC_STRICT_RESTORE_SS } else { 0 };
    let uc_flags = if composants != 0 { UC_FP_XSTATE } else { 0 } | UC_SIGCONTEXT_SS | strict;
    poser(f, UC, uc_flags);
    poser(f, UC + 8, 0);
    // La pile de secours telle qu'elle est posée (`__save_altstack`).
    poser(f, UC_STACK, pile.adresse);
    f[UC_STACK + 8..UC_STACK + 12].copy_from_slice(&pile.drapeaux.to_le_bytes());
    poser(f, UC_STACK + 16, pile.taille);
    let mc = UC_MCONTEXT;
    for (i, r) in registres(cadre).iter().enumerate() {
        poser(f, mc + i * 8, *r);
    }
    poser(f, mc + SC_RIP, cadre.rip);
    poser(f, mc + SC_EFLAGS, cadre.rflags);
    // cs, gs, fs, ss : gs et fs à 0 (ils ne servent plus en 64 bits).
    poser(f, mc + SC_CS, cadre.cs & 0xffff | (cadre.ss & 0xffff) << 48);
    let (piege, erreur, cr2) = tache::courante().derniere_exception();
    poser(f, mc + SC_ERR, erreur);
    poser(f, mc + SC_TRAPNO, piege);
    poser(f, mc + SC_OLDMASK, masque);
    poser(f, mc + SC_CR2, cr2);
    poser(f, mc + SC_FPSTATE, fpstate);
    poser(f, UC_SIGMASK, masque);
    if action.drapeaux & signaux::SA_SIGINFO != 0 {
        f[INFO..INFO + 128].copy_from_slice(&info.octets());
    }

    // Une seule copie, du début du cadre à la fin de l'image d'état.
    if copier_vers_utilisateur(debut, &t.0[o_cadre..fin]).is_err() {
        afficherln!("[noyau] {} : impossible d'ecrire le cadre du signal {} a {:#x}", tache::nom(), signaux::signal(sig).nom, debut);
        return Err(Impossible);
    }

    // Entrer dans le gestionnaire.
    cadre.rdi = sig;
    cadre.rax = 0;
    cadre.rsi = debut + INFO as u64;
    cadre.rdx = debut + UC as u64;
    cadre.rip = action.gestionnaire;
    cadre.rsp = debut;
    cadre.cs = gdt::CODE_UTILISATEUR as u64;
    // SS : gardé s'il est valide, sinon remplacé (`force_valid_ss` : le seul
    // segment de données de l'anneau 3 de notre GDT).
    if cadre.ss != gdt::DONNEES_UTILISATEUR as u64 {
        cadre.ss = gdt::DONNEES_UTILISATEUR as u64;
    }
    cadre.rflags &= !EFFACES_A_L_ENTREE;
    sse::charger_initial();
    Ok(())
}

/// rt_sigreturn (15) : le retour d'un gestionnaire, par le `__restore_rt` de
/// la glibc. Le cadre est à RSP - 8 (le gestionnaire a dépilé l'adresse de
/// retour). Dans l'ordre de Linux : le masque, puis la pile de secours, puis
/// le contexte. Seuls l'adresse de retour et l'ucontext (312 octets) se
/// lisent, jamais le siginfo qui les suit (Linux non plus : un cadre posé
/// juste avant une page qui n'est plus projetée revient). Un cadre
/// illisible, ou un état x87/SSE refusé : SIGSEGV forcé (`signal_fault`,
/// `mauvais_cadre`). Rend le rax rétabli, pour que la sortie de l'appel
/// système ne l'écrase pas.
pub fn rt_sigreturn(cadre: &mut Cadre) -> i64 {
    let debut = cadre.rsp.wrapping_sub(8);
    let mut f = [0u8; INFO];
    if copier_depuis_utilisateur(&mut f, debut).is_err() {
        return mauvais_cadre(cadre, debut);
    }
    let tid = tache::courante().tid();
    let masque = lire(&f, UC_SIGMASK);
    let uc_flags = lire(&f, UC);
    let pile = PileDeSecours {
        adresse: lire(&f, UC_STACK),
        taille: lire(&f, UC_STACK + 16),
        drapeaux: u32::from_le_bytes(f[UC_STACK + 8..UC_STACK + 12].try_into().unwrap_or([0; 4])),
    };
    let sp = cadre.rsp;
    processus::avec(|p| {
        signaux::poser_masque(p, tid, masque);
        signaux::retablir_pile(p, tid, pile, sp);
    });
    // Le contexte (`restore_sigcontext`) : les registres, puis l'état
    // x87/SSE.
    let mc = UC_MCONTEXT;
    let mut r = [0u64; 16];
    for (i, v) in r.iter_mut().enumerate() {
        *v = lire(&f, mc + i * 8);
    }
    let segments = lire(&f, mc + SC_CS);
    let fpstate = lire(&f, mc + SC_FPSTATE);
    retablir_registres(cadre, &r);
    cadre.rip = lire(&f, mc + SC_RIP);
    cadre.rflags = cadre.rflags & !FIX_EFLAGS | lire(&f, mc + SC_EFLAGS) & FIX_EFLAGS;
    cadre.cs = segments & 0xffff | 3;
    cadre.ss = (segments >> 48) & 0xffff | 3;
    // Plus d'appel système à reprendre (orig_ax = -1).
    cadre.code_erreur = u64::MAX;
    // SS remis valide sans UC_STRICT_RESTORE_SS, pour un retour en 64 bits
    // (`force_valid_ss`, si `user_64bit_mode`).
    let en_64_bits = cadre.cs == gdt::CODE_UTILISATEUR as u64;
    if uc_flags & UC_STRICT_RESTORE_SS == 0 && en_64_bits && cadre.ss != gdt::DONNEES_UTILISATEUR as u64 {
        cadre.ss = gdt::DONNEES_UTILISATEUR as u64;
    }
    if !retablir_etat(fpstate) {
        return mauvais_cadre(cadre, debut);
    }
    cadre.rax as i64
}

/// Un cadre de rt_sigreturn illisible ou refusé : le programme meurt de
/// SIGSEGV (`signal_fault` puis `force_sig(SIGSEGV)` : même avec un
/// gestionnaire de SIGSEGV, qui serait appelé sur un contexte faux, Linux le
/// livre ; nous le livrons aussi, et s'il revient par le même cadre, il
/// meurt de même).
fn mauvais_cadre(cadre: &Cadre, debut: u64) -> i64 {
    afficherln!("[noyau] {} : mauvais cadre de signal a {:#x} (rt_sigreturn, ip {:#x})", tache::nom(), debut, cadre.rip);
    let tid = tache::courante().tid();
    let sig = linux::SIGSEGV.numero as u64;
    let t = processus::avec(|p| signaux::forcer_au_fil(p, tid, sig, Info::du_noyau(sig), false));
    signaux::reveiller(t);
    0
}

/// Lit, vérifie et charge l'état x87/SSE/AVX rangé à `fpstate` (le
/// `__fpu_restore_sig` de Linux, pour un programme 64 bits). Faux s'il est
/// illisible ou refusé ; un `fpstate` nul : l'état initial (Linux le permet,
/// « no FPU context »).
fn retablir_etat(fpstate: u64) -> bool {
    if fpstate == 0 {
        sse::charger_initial();
        return true;
    }
    // L'image de FXSAVE est alignée sur 16, celle de XSAVE sur 64 : un
    // fpstate qui ne l'est pas ferait une faute de FXRSTOR ou XRSTOR.
    let composants = sse::composants();
    let taille = sse::taille();
    let mut image = ImageFpu([0; sse::TAILLE_MAX]);
    // Linux charge l'image directement depuis la mémoire du programme :
    // FXRSTOR la veut alignée sur 16, XRSTOR sur 64, sinon une faute de
    // protection générale, et SIGSEGV. Nous la copions d'abord ; la règle
    // est gardée.
    if fpstate % 16 != 0 || copier_depuis_utilisateur(&mut image.0[..512], fpstate).is_err() {
        return false;
    }
    // MXCSR : un bit que le processeur n'a pas ferait une faute au
    // chargement (Linux, en 64 bits : SIGSEGV). FXRSTOR le charge toujours,
    // XRSTOR seulement avec SSE ou AVX.
    let mxcsr = u32::from_le_bytes(image.0[24..28].try_into().unwrap_or([0; 4]));
    let mxcsr_permis = mxcsr & !sse::masque_mxcsr() == 0;
    if composants == 0 {
        return mxcsr_permis && sse::charger(&image, 0);
    }
    // Avec XSAVE : MAGIC1 dans les octets du logiciel, et MAGIC2 après
    // l'image de la taille que nous donnons (`check_xstate_in_sigframe` ; un
    // MAGIC2 illisible : SIGSEGV) ; sinon, une image FXSAVE seule (un
    // programme qui a recopié l'ancienne disposition sans l'état étendu).
    let magic1 = u32::from_le_bytes(image.0[464..468].try_into().unwrap_or([0; 4]));
    let etendu = if magic1 == FP_XSTATE_MAGIC1 {
        let mut magic2 = [0u8; 4];
        if copier_depuis_utilisateur(&mut magic2, fpstate + taille as u64).is_err() {
            return false;
        }
        u32::from_le_bytes(magic2) == FP_XSTATE_MAGIC2
    } else {
        false
    };
    if !etendu {
        // x87 et SSE de l'image FXSAVE, le reste à l'état initial : un seul
        // XRSTOR, l'en-tête disant x87 et SSE présents (le reste de l'image
        // est nul). Linux fait FXRSTOR puis XRSTOR de l'état initial pour
        // les autres composants ; mesuré sur l'hôte, le MXCSR de l'image
        // reste : c'est ce que garantit notre XRSTOR unique, sur tout
        // processeur.
        if !mxcsr_permis {
            return false;
        }
        image.0[464..512].fill(0);
        poser(&mut image.0, 512, 3);
        return sse::charger(&image, composants);
    }
    if fpstate % 64 != 0 || copier_depuis_utilisateur(&mut image.0[512..taille], fpstate + 512).is_err() {
        return false;
    }
    // Les composants que demande le programme (ses octets du logiciel),
    // parmi les nôtres ; l'en-tête de XSAVE, ce que XRSTOR refuserait
    // (mesuré sur l'hôte, où Linux charge l'image directement) : un
    // composant que XCR0 n'a pas, le format compacté (xcomp_bv), les octets
    // 16 à 23 ; les octets 24 à 63 sont ignorés (remis à zéro ici, pour
    // qu'aucun processeur n'y regarde).
    let demandes = u64::from_le_bytes(image.0[472..480].try_into().unwrap_or([0; 8])) & composants;
    let xstate_bv = lire(&image.0, 512);
    let xcomp_bv = lire(&image.0, 520);
    if xstate_bv & !composants != 0 || xcomp_bv != 0 || lire(&image.0, 528) != 0 {
        return false;
    }
    image.0[536..576].fill(0);
    if demandes & 6 != 0 && !mxcsr_permis {
        return false;
    }
    // Ceux qu'on charge de l'image, et ceux qu'elle ne donne pas, à l'état
    // initial (`__restore_fpregs_from_user`), d'un seul XRSTOR : leur bit de
    // XSTATE_BV à 0, il les remet à l'état initial. Option écartée : un
    // second XRSTOR, de l'état initial, pour ceux-là ; au format standard,
    // il rechargerait MXCSR (XRSTOR le charge dès que RFBM demande SSE ou
    // AVX, quel que soit XSTATE_BV), et celui que rend le programme serait
    // perdu (mesuré : Linux, qui le fait par XRSTORS, le garde). MXCSR ne
    // vient de l'image que si le programme demande SSE ou AVX ; sinon,
    // celui de l'état initial (0x1F80, mesuré).
    poser(&mut image.0, 512, xstate_bv & demandes);
    if demandes & 6 == 0 {
        image.0[24..28].copy_from_slice(&0x1F80u32.to_le_bytes());
    }
    sse::charger(&image, composants)
}
