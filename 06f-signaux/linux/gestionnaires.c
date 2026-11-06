/*
 * Les gestionnaires de signaux (6f) : le cadre de signal posé par le
 * noyau, ce que voit le gestionnaire en entrant, ce qui revient après
 * rt_sigreturn, la pile de secours, les drapeaux d'une action, l'ordre de
 * plusieurs signaux ; puis les fautes livrées à leur gestionnaire (le
 * siginfo et le contexte de chaque exception). Il tourne dans notre noyau (au démarrage avec
 * Nehalem, sans XSAVE ; dans make tests-qemu avec qemu64 et -cpu max, avec
 * XSAVE et AVX) et sur l'hôte (make tests-hote) : chaque ligne doit dire
 * « ok » partout. Ce qui dépend du processeur (XSAVE, AVX) est demandé à
 * CPUID ; ce qui dépend du noyau de l'hôte (AT_MINSIGSTKSZ, que Linux
 * calcule avec son émulation 32 bits) n'y est vérifié qu'au plus large.
 *
 * Les mesures exactes du cadre se font avec un gestionnaire écrit en
 * assembleur (`entree`), qui range ses registres avant que le compilateur
 * n'y touche, et un envoi par l'appel système brut, aux registres connus.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#define SS_AUTODISARM (1U << 31)
#ifndef AT_MINSIGSTKSZ
#define AT_MINSIGSTKSZ 51
#endif

static int echecs;
static int chez_nous;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] gestionnaires : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* XSAVE en service (CPUID.1:ECX.OSXSAVE), et AVX (CPUID.1:ECX.AVX, et
 * XCR0 qui le sauve). */
static int xsave, avx;
static uint64_t xcr0;

static void processeur(void)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    __get_cpuid(1, &a, &b, &c, &d);
    xsave = (c >> 27) & 1;
    if (xsave) {
        uint32_t bas, haut;
        __asm__ volatile("xgetbv" : "=a"(bas), "=d"(haut) : "c"(0));
        xcr0 = (uint64_t)haut << 32 | bas;
        avx = (c >> 28) & 1 && (xcr0 & 6) == 6;
    }
}

/* ---- Ce que voit le gestionnaire en entrant ---- */

/* Rangés par `entree`, le gestionnaire en assembleur, avant toute autre
 * instruction. */
uint64_t vu_rsp, vu_rax, vu_rdi, vu_rsi, vu_rdx, vu_r12, vu_r8, vu_rflags;
uint32_t vu_mxcsr;
uint16_t vu_fcw;
/* Une copie du cadre, faite dans le gestionnaire (après son retour, la
 * pile est réécrite). */
static unsigned char cadre[8192];
static uint64_t cadre_debut;
static uint64_t masque_dedans;

void copier_cadre(void)
{
    cadre_debut = vu_rsp;
    /* Du RSP du gestionnaire jusqu'à la fin de l'état x87/SSE rangé (1292
     * octets avec XSAVE, mesuré) : 1792 octets, sans sortir de la pile (le
     * RSP interrompu est 256 octets sous celui de cadre_de_signal, et
     * au-dessus il y a encore argv, envp et le vecteur auxiliaire). */
    /* Le cadre et son état étendu, jusqu'à MAGIC2 : l'état grandit avec le processeur (2 700 octets
     * avec PKRU, mesuré sous QEMU ; 836 avec x87, SSE et AVX seuls). */
    size_t n = 1792;
    if (xsave) {
        unsigned char *fp = *(unsigned char **)(vu_rsp + 48 + 23 * 8);
        size_t jusqu_a_magic2 = (size_t)(fp - (unsigned char *)vu_rsp) + *(uint32_t *)(fp + 480) + 4;
        if (jusqu_a_magic2 > n)
            n = jusqu_a_magic2 < sizeof cadre ? jusqu_a_magic2 : sizeof cadre;
    }
    memcpy(cadre, (void *)vu_rsp, n);
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    memcpy(&masque_dedans, &m, 8);
}

__attribute__((naked)) static void entree(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    (void)uc;
    __asm__ volatile(
        "mov %rsp, vu_rsp(%rip)\n\t"
        "mov %rax, vu_rax(%rip)\n\t"
        "mov %rdi, vu_rdi(%rip)\n\t"
        "mov %rsi, vu_rsi(%rip)\n\t"
        "mov %rdx, vu_rdx(%rip)\n\t"
        "mov %r12, vu_r12(%rip)\n\t"
        "mov %r8, vu_r8(%rip)\n\t"
        "pushfq\n\t"
        "pop %rax\n\t"
        "mov %rax, vu_rflags(%rip)\n\t"
        "stmxcsr vu_mxcsr(%rip)\n\t"
        "fnstcw vu_fcw(%rip)\n\t"
        "sub $8, %rsp\n\t"
        "call copier_cadre\n\t"
        "add $8, %rsp\n\t"
        "ret\n\t");
}

#define LIRE64(o) (*(uint64_t *)(cadre + (o)))
#define LIRE32(o) (*(uint32_t *)(cadre + (o)))
#define LIRE16(o) (*(uint16_t *)(cadre + (o)))

static void cadre_de_signal(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = entree;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    sigaction(SIGUSR1, &sa, NULL);
    sigset_t winch;
    sigemptyset(&winch);
    sigaddset(&winch, SIGWINCH);
    sigprocmask(SIG_BLOCK, &winch, NULL);

    /* L'état x87/SSE du programme, changé : le gestionnaire doit partir de
     * l'état initial, et celui-ci revenir après. */
    uint32_t mxcsr = 0x5f80, mxcsr_apres;
    uint16_t fcw = 0x027f, fcw_apres;
    __asm__ volatile("ldmxcsr %0" ::"m"(mxcsr));
    __asm__ volatile("fldcw %0" ::"m"(fcw));
    long pid = getpid(), tid = syscall(SYS_gettid);
    register long rax __asm__("rax") = SYS_tgkill;
    register long rdi __asm__("rdi") = pid;
    register long rsi __asm__("rsi") = tid;
    register long rdx __asm__("rdx") = SIGUSR1;
    register long r12 __asm__("r12") = 0x1212121212121212;
    register long r8 __asm__("r8") = 0x0808080808080808;
    register long r13 __asm__("r13");
    register long r14 __asm__("r14");
    /* 256 octets plus bas que la pile du compilateur, DF armé : le
     * gestionnaire doit le voir effacé, et le contexte rangé le garder. */
    __asm__ volatile("sub $256, %%rsp\n\t"
                     "mov %%rsp, %%r13\n\t"
                     "lea 1f(%%rip), %%r14\n\t"
                     "std\n\t"
                     "syscall\n"
                     "1:\n\t"
                     "cld\n\t"
                     "add $256, %%rsp"
                     : "=r"(r13), "=r"(r14), "+r"(rax)
                     : "r"(rdi), "r"(rsi), "r"(rdx), "r"(r12), "r"(r8)
                     : "rcx", "r11", "memory", "cc");
    uint64_t s = r13, apres_syscall = r14;
    __asm__ volatile("stmxcsr %0" : "=m"(mxcsr_apres));
    __asm__ volatile("fnstcw %0" : "=m"(fcw_apres));
    mxcsr = 0x1f80;
    fcw = 0x037f;
    __asm__ volatile("ldmxcsr %0" ::"m"(mxcsr));
    __asm__ volatile("fldcw %0" ::"m"(fcw));
    sigprocmask(SIG_UNBLOCK, &winch, NULL);

    uint64_t debut = cadre_debut, uc = debut + 8, info = debut + 312;
    verifier(rax == 0 && (vu_rsp + 8) % 16 == 0 && vu_rsp < s - 128, "le gestionnaire appele, RSP + 8 multiple de 16, sous la zone rouge");
    verifier(vu_rdi == SIGUSR1 && vu_rsi == info && vu_rdx == uc && vu_rax == 0,
             "a l'entree : rdi le signal, rsi le siginfo (RSP + 312), rdx l'ucontext (RSP + 8), rax 0");
    verifier(vu_r12 == 0x1212121212121212 && vu_r8 == 0x0808080808080808, "les autres registres sont ceux du programme");
    verifier(!(vu_rflags & 0x400) && (vu_rflags & 0x200), "RFLAGS du gestionnaire : DF efface, IF arme");
    verifier(vu_mxcsr == 0x1f80 && vu_fcw == 0x037f, "le gestionnaire part de l'etat x87/SSE initial");
    verifier(mxcsr_apres == 0x5f80 && fcw_apres == 0x027f, "apres rt_sigreturn, l'etat x87/SSE du programme");
    /* L'action telle que l'a posée la glibc (son sigaction ajoute
     * SA_RESTORER et son __restore_rt), relue par l'appel brut. */
    uint64_t action_noyau[4];
    syscall(SYS_rt_sigaction, SIGUSR1, NULL, action_noyau, 8);
    verifier(LIRE64(0) != 0 && LIRE64(0) == action_noyau[2], "l'adresse de retour : le __restore_rt de la glibc (sa_restorer)");

    /* L'ucontext. */
    uint64_t uc_flags = LIRE64(8);
    verifier(uc_flags == (xsave ? 7u : 6u) && LIRE64(16) == 0, "uc_flags : 7 avec XSAVE, 6 sans ; uc_link nul");
    /* (Sur l'hôte, ss_flags vient de nos ancêtres : SS_DISABLE, si l'un d'eux était un fil sans pile
     * de secours ; voir linux/signaux.c.) */
    verifier(LIRE64(24) == 0 && (LIRE32(32) == 0 || (!chez_nous && LIRE32(32) == SS_DISABLE)) && LIRE64(40) == 0, "uc_stack : la pile de secours, ici aucune {0, 0, 0}");
    const int mc = 48;
    verifier(LIRE64(mc + 4 * 8) == 0x1212121212121212 && LIRE64(mc + 0) == 0x0808080808080808 && LIRE64(mc + 15 * 8) == s
             && LIRE64(mc + 16 * 8) == apres_syscall, "le sigcontext : r12, r8, rsp et rip du programme");
    verifier((LIRE64(mc + 17 * 8) & 0x400) && LIRE16(mc + 18 * 8) == 0x33 && LIRE16(mc + 18 * 8 + 6) == 0x2b
             && LIRE16(mc + 18 * 8 + 2) == 0 && LIRE16(mc + 18 * 8 + 4) == 0,
             "le sigcontext : RFLAGS avec DF, CS 0x33, SS 0x2b, fs et gs a 0");
    verifier(LIRE64(mc + 13 * 8) == 0, "le sigcontext : rax, ce qu'avait rendu tgkill (0)");
    uint64_t masque_avant = 1ull << (SIGWINCH - 1);
    verifier(LIRE64(mc + 21 * 8) == masque_avant && LIRE64(8 + 296) == masque_avant,
             "oldmask et uc_sigmask : le masque d'avant (SIGWINCH)");
    verifier(masque_dedans == (masque_avant | 1ull << (SIGUSR1 - 1) | 1ull << (SIGUSR2 - 1)),
             "pendant le gestionnaire : bloques le masque d'avant, le signal et sa_mask");

    /* Le siginfo. */
    siginfo_t *si = (siginfo_t *)(cadre + 312);
    verifier(si->si_signo == SIGUSR1 && si->si_code == SI_TKILL && si->si_pid == pid && si->si_uid == getuid(),
             "le siginfo : SIGUSR1, SI_TKILL, le pid et l'uid");

    /* L'état x87/SSE rangé. */
    uint64_t fpstate = LIRE64(mc + 23 * 8);
    unsigned char *fp = cadre + (fpstate - debut);
    verifier(fpstate == uc + 448 && fpstate % 64 == 0, "fpstate a l'ucontext + 448, aligne sur 64");
    verifier(*(uint16_t *)fp == 0x027f && *(uint32_t *)(fp + 24) == 0x5f80, "fpstate : le controle x87 et MXCSR du programme");
    uint64_t taille = 512;
    if (xsave) {
        uint32_t magic1 = *(uint32_t *)(fp + 464), etendue = *(uint32_t *)(fp + 468), xsz = *(uint32_t *)(fp + 480);
        uint64_t xfeat = *(uint64_t *)(fp + 472);
        taille = xsz + 4;
        verifier(magic1 == 0x46505853 && etendue == xsz + 4 && (chez_nous ? xfeat == (xcr0 & 7) : (xfeat & 7) == (xcr0 & 7) && (xfeat & ~xcr0) == 0) && *(uint32_t *)(fp + xsz) == 0x46505845,
                 "XSAVE : les octets du logiciel (magie, tailles, composants) et MAGIC2");
        verifier((*(uint64_t *)(fp + 512) & 3) == 3 && *(uint64_t *)(fp + 520) == 0, "XSAVE : l'en-tete, x87 et SSE presents, format standard");
    } else if (chez_nous) {
        /* Sans XSAVE, Linux écrit quand même les octets du logiciel
         * (`save_xstate_epilog`), sans MAGIC2 ; l'hôte a XSAVE : seulement
         * chez nous (Nehalem, qemu64). */
        verifier(*(uint32_t *)(fp + 464) == 0x46505853 && *(uint32_t *)(fp + 468) == 516 && *(uint64_t *)(fp + 472) == 0
                 && *(uint32_t *)(fp + 480) == 512, "FXSAVE : les octets du logiciel (magie, 516, aucun composant, 512), sans MAGIC2");
    }
    verifier(s - (fpstate + taille) >= 128, "la zone rouge du programme est intacte (128 octets sous son RSP)");
    uint64_t minimal = getauxval(AT_MINSIGSTKSZ);
    verifier(minimal >= s - 128 - debut, "AT_MINSIGSTKSZ : au moins la place que prend le cadre");
    if (chez_nous)
        verifier(minimal == ((440 + 15 + taille + 63 + 15) & ~15ull), "AT_MINSIGSTKSZ, chez nous : le calcul de Linux sans emulation 32 bits");
}

/* ---- L'état vectoriel préservé ---- */

static void ecraser_vecteurs(int sig)
{
    (void)sig;
    __asm__ volatile("pcmpeqd %%xmm0, %%xmm0\n\t" "pcmpeqd %%xmm7, %%xmm7\n\t" "pcmpeqd %%xmm15, %%xmm15"
                     ::: "xmm0", "xmm7", "xmm15");
    if (avx)
        __asm__ volatile("vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n\t" "vpcmpeqd %%ymm14, %%ymm14, %%ymm14" ::: "xmm1", "xmm14");
    uint32_t m = 0x7f80;
    __asm__ volatile("ldmxcsr %0" ::"m"(m));
}

static void vecteurs(void)
{
    signal(SIGUSR2, ecraser_vecteurs);
    static uint8_t avant[16][32] __attribute__((aligned(32))), apres[16][32] __attribute__((aligned(32)));
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 32; j++)
            avant[i][j] = (uint8_t)(i * 32 + j + 1);
    long pid = getpid(), tid = syscall(SYS_gettid);
    if (avx) {
        __asm__ volatile(
            "vmovdqa 0(%0), %%ymm0\n\t" "vmovdqa 32(%0), %%ymm1\n\t" "vmovdqa 64(%0), %%ymm2\n\t" "vmovdqa 96(%0), %%ymm3\n\t"
            "vmovdqa 128(%0), %%ymm4\n\t" "vmovdqa 160(%0), %%ymm5\n\t" "vmovdqa 192(%0), %%ymm6\n\t" "vmovdqa 224(%0), %%ymm7\n\t"
            "vmovdqa 256(%0), %%ymm8\n\t" "vmovdqa 288(%0), %%ymm9\n\t" "vmovdqa 320(%0), %%ymm10\n\t" "vmovdqa 352(%0), %%ymm11\n\t"
            "vmovdqa 384(%0), %%ymm12\n\t" "vmovdqa 416(%0), %%ymm13\n\t" "vmovdqa 448(%0), %%ymm14\n\t" "vmovdqa 480(%0), %%ymm15\n\t"
            "mov %2, %%rdi\n\t" "mov %3, %%rsi\n\t" "mov $12, %%edx\n\t" "mov %4, %%eax\n\t" "syscall\n\t"
            "vmovdqa %%ymm0, 0(%1)\n\t" "vmovdqa %%ymm1, 32(%1)\n\t" "vmovdqa %%ymm2, 64(%1)\n\t" "vmovdqa %%ymm3, 96(%1)\n\t"
            "vmovdqa %%ymm4, 128(%1)\n\t" "vmovdqa %%ymm5, 160(%1)\n\t" "vmovdqa %%ymm6, 192(%1)\n\t" "vmovdqa %%ymm7, 224(%1)\n\t"
            "vmovdqa %%ymm8, 256(%1)\n\t" "vmovdqa %%ymm9, 288(%1)\n\t" "vmovdqa %%ymm10, 320(%1)\n\t" "vmovdqa %%ymm11, 352(%1)\n\t"
            "vmovdqa %%ymm12, 384(%1)\n\t" "vmovdqa %%ymm13, 416(%1)\n\t" "vmovdqa %%ymm14, 448(%1)\n\t" "vmovdqa %%ymm15, 480(%1)\n\t"
            "vzeroupper"
            :
            : "r"(avant), "r"(apres), "r"(pid), "r"(tid), "i"(SYS_tgkill)
            : "rax", "rcx", "rdx", "rsi", "rdi", "r11", "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
              "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
    } else {
        __asm__ volatile(
            "movdqa 0(%0), %%xmm0\n\t" "movdqa 32(%0), %%xmm1\n\t" "movdqa 64(%0), %%xmm2\n\t" "movdqa 96(%0), %%xmm3\n\t"
            "movdqa 128(%0), %%xmm4\n\t" "movdqa 160(%0), %%xmm5\n\t" "movdqa 192(%0), %%xmm6\n\t" "movdqa 224(%0), %%xmm7\n\t"
            "movdqa 256(%0), %%xmm8\n\t" "movdqa 288(%0), %%xmm9\n\t" "movdqa 320(%0), %%xmm10\n\t" "movdqa 352(%0), %%xmm11\n\t"
            "movdqa 384(%0), %%xmm12\n\t" "movdqa 416(%0), %%xmm13\n\t" "movdqa 448(%0), %%xmm14\n\t" "movdqa 480(%0), %%xmm15\n\t"
            "mov %2, %%rdi\n\t" "mov %3, %%rsi\n\t" "mov $12, %%edx\n\t" "mov %4, %%eax\n\t" "syscall\n\t"
            "movdqa %%xmm0, 0(%1)\n\t" "movdqa %%xmm1, 32(%1)\n\t" "movdqa %%xmm2, 64(%1)\n\t" "movdqa %%xmm3, 96(%1)\n\t"
            "movdqa %%xmm4, 128(%1)\n\t" "movdqa %%xmm5, 160(%1)\n\t" "movdqa %%xmm6, 192(%1)\n\t" "movdqa %%xmm7, 224(%1)\n\t"
            "movdqa %%xmm8, 256(%1)\n\t" "movdqa %%xmm9, 288(%1)\n\t" "movdqa %%xmm10, 320(%1)\n\t" "movdqa %%xmm11, 352(%1)\n\t"
            "movdqa %%xmm12, 384(%1)\n\t" "movdqa %%xmm13, 416(%1)\n\t" "movdqa %%xmm14, 448(%1)\n\t" "movdqa %%xmm15, 480(%1)"
            :
            : "r"(avant), "r"(apres), "r"(pid), "r"(tid), "i"(SYS_tgkill)
            : "rax", "rcx", "rdx", "rsi", "rdi", "r11", "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
              "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
    }
    int n = avx ? 32 : 16, intact = 1;
    for (int i = 0; i < 16; i++)
        intact &= memcmp(avant[i], apres[i], n) == 0;
    uint32_t m;
    __asm__ volatile("stmxcsr %0" : "=m"(m));
    verifier(intact && m == 0x1f80, avx ? "YMM0-15 (moities hautes comprises) et MXCSR intacts apres un gestionnaire qui les ecrase"
                                        : "XMM0-15 et MXCSR intacts apres un gestionnaire qui les ecrase");
    signal(SIGUSR2, SIG_DFL);
}

/* ---- Le gestionnaire change le contexte ---- */

static void changer_rax(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    uc->uc_mcontext.gregs[REG_RAX] = 1234;
}

static void changer_ss(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    uint16_t *segments = (uint16_t *)&uc->uc_mcontext.gregs[REG_CSGSFS];
    segments[3] = 0;
    uc->uc_flags &= ~4ul;
}

/* Les octets du logiciel du cadre réduits à x87 et SSE (xfeatures 3,
 * MAGIC1 gardé) : rt_sigreturn charge x87 et SSE de l'image, AVX à l'état
 * initial, et garde le MXCSR rendu ; réduits à x87 (xfeatures 1) : MXCSR
 * revient à l'état initial, 0x1F80 (mesuré). Sans XSAVE, l'image FXSAVE :
 * le MXCSR rendu, toujours. */
static uint64_t xfeatures_rendus;

static void reduire_xfeatures(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    unsigned char *fp = (unsigned char *)uc->uc_mcontext.fpregs;
    uint32_t m = 0x7f80;
    memcpy(fp + 24, &m, 4);
    if (xsave)
        memcpy(fp + 464 + 8, &xfeatures_rendus, 8);
}

static uint32_t mxcsr_apres_retour(uint64_t xfeatures)
{
    uint32_t m, initial = 0x1f80;
    xfeatures_rendus = xfeatures;
    raise(SIGUSR1);
    __asm__ volatile("stmxcsr %0" : "=m"(m));
    __asm__ volatile("ldmxcsr %0" ::"m"(initial));
    return m;
}

/* rt_sigreturn ne lit que l'adresse de retour et l'ucontext (312 octets),
 * jamais le siginfo qui les suit (Linux non plus, mesuré) : le
 * gestionnaire recopie son cadre (sans le siginfo, et fpstate nul : l'état
 * initial) juste avant une page PROT_NONE, et y appelle rt_sigreturn. */
static unsigned char *bord;

static void retour_au_bord(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    unsigned char *cadre = bord - 312;
    memcpy(cadre, (unsigned char *)c - 8, 312);
    ((ucontext_t *)(cadre + 8))->uc_mcontext.fpregs = NULL;
    __asm__ volatile("mov %0, %%rsp\n\tmov $15, %%eax\n\tsyscall" ::"r"(cadre + 8) : "memory");
    __builtin_unreachable();
}

static void contexte(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = changer_rax;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    long r = syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
    verifier(r == 1234, "le gestionnaire change rax dans le contexte : l'appel interrompu rend 1234");
    sa.sa_sigaction = changer_ss;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    uint16_t ss;
    __asm__ volatile("mov %%ss, %0" : "=r"(ss));
    verifier(ss == 0x2b, "SS nul rendu sans UC_STRICT_RESTORE_SS : remplace par 0x2b (force_valid_ss)");
    sa.sa_sigaction = reduire_xfeatures;
    sigaction(SIGUSR1, &sa, NULL);
    uint32_t m3 = mxcsr_apres_retour(3), m1 = mxcsr_apres_retour(1);
    verifier(m3 == 0x7f80 && m1 == (xsave ? 0x1f80u : 0x7f80u),
             "xfeatures du cadre reduits : x87 et SSE, le MXCSR rendu ; x87 seul, MXCSR initial (avec XSAVE)");
    unsigned char *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(pages + 4096, 4096, PROT_NONE);
    bord = pages + 4096;
    sa.sa_sigaction = retour_au_bord;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    verifier(1, "rt_sigreturn d'un cadre a 312 octets d'une page PROT_NONE : revenu (le siginfo n'est pas lu)");
    munmap(pages, 8192);
    signal(SIGUSR1, SIG_DFL);
}

/* ---- La pile de secours ---- */

static char pile[65536] __attribute__((aligned(16)));
static volatile uint64_t rsp_dedans, rsp_imbrique;
static volatile int etat_dedans, changer_dedans, imbriquer;
static stack_t vu_ss_cadre;

static void sur_la_pile(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    int x;
    rsp_dedans = (uint64_t)&x;
    vu_ss_cadre = uc->uc_stack;
    stack_t o, n = { .ss_sp = pile, .ss_flags = 0, .ss_size = 8192 };
    sigaltstack(NULL, &o);
    etat_dedans = o.ss_flags;
    changer_dedans = sigaltstack(&n, NULL) == -1 ? errno : 0;
    if (imbriquer) {
        imbriquer = 0;
        raise(SIGUSR2);
    }
}

static void imbrique(int sig)
{
    (void)sig;
    int x;
    rsp_imbrique = (uint64_t)&x;
}

static void pile_de_secours(void)
{
    stack_t s = { .ss_sp = pile, .ss_flags = 0, .ss_size = sizeof pile }, lue;
    sigaltstack(&s, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sur_la_pile;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    int dessus = rsp_dedans > (uint64_t)pile && rsp_dedans < (uint64_t)pile + sizeof pile;
    verifier(dessus && etat_dedans == SS_ONSTACK && changer_dedans == EPERM,
             "SA_ONSTACK : sur la pile de secours ; sigaltstack y dit SS_ONSTACK, la changer : EPERM");
    verifier(vu_ss_cadre.ss_sp == pile && vu_ss_cadre.ss_size == sizeof pile && vu_ss_cadre.ss_flags == 0,
             "uc_stack : la pile de secours telle que posee");
    uint64_t haut = (uint64_t)pile + sizeof pile;
    verifier(haut - rsp_dedans <= getauxval(AT_MINSIGSTKSZ) + 256, "le cadre au sommet de la pile de secours, en AT_MINSIGSTKSZ");

    /* Un second signal SA_ONSTACK pendant le premier : son cadre se pose
     * sous le premier, toujours sur la pile de secours. */
    struct sigaction sb;
    memset(&sb, 0, sizeof sb);
    sb.sa_handler = imbrique;
    sb.sa_flags = SA_ONSTACK;
    sigaction(SIGUSR2, &sb, NULL);
    imbriquer = 1;
    raise(SIGUSR1);
    verifier(rsp_imbrique < rsp_dedans && rsp_imbrique > (uint64_t)pile, "un signal pendant un autre : son cadre sous le premier, sur la pile de secours");

    /* SS_AUTODISARM : désarmée pendant le gestionnaire (on peut la changer),
     * rétablie au retour. */
    s.ss_flags = (int)SS_AUTODISARM;
    sigaltstack(&s, NULL);
    raise(SIGUSR1);
    sigaltstack(NULL, &lue);
    verifier(etat_dedans == SS_DISABLE && changer_dedans == 0 && lue.ss_sp == pile && lue.ss_size == sizeof pile
             && (unsigned)lue.ss_flags == SS_AUTODISARM,
             "SS_AUTODISARM : desarmee dedans (SS_DISABLE, changeable), retablie apres rt_sigreturn");
    s.ss_flags = SS_DISABLE;
    sigaltstack(&s, NULL);
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
}

/* ---- Les drapeaux d'une action ---- */

static volatile int appels;
static volatile uint64_t bloques_dedans;

static void compter(int sig)
{
    (void)sig;
    appels++;
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    memcpy((void *)&bloques_dedans, &m, 8);
}

static void drapeaux(void)
{
    struct sigaction sa, lue;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = compter;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    verifier(!(bloques_dedans & 1ull << (SIGUSR1 - 1)), "SA_NODEFER : le signal n'est pas bloque pendant son gestionnaire");
    appels = 0;
    sa.sa_flags = SA_RESETHAND | SA_RESTART;
    sigaction(SIGURG, &sa, NULL);
    raise(SIGURG);
    raise(SIGURG);
    sigaction(SIGURG, NULL, &lue);
    verifier(appels == 1 && lue.sa_handler == SIG_DFL && (lue.sa_flags & (SA_RESETHAND | SA_RESTART)) == (SA_RESETHAND | SA_RESTART),
             "SA_RESETHAND : un appel, puis l'action par defaut (SIGURG ignore), les drapeaux restent");
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    verifier(!sigismember(&m, SIGUSR1) && !sigismember(&m, SIGURG), "apres les gestionnaires : le masque d'avant");
    signal(SIGUSR1, SIG_DFL);
}

/* ---- L'ordre de plusieurs signaux ---- */

static char ordre[8];
static int n_ordre;

static void noter(int sig)
{
    ordre[n_ordre++] = sig == SIGUSR1 ? '1' : sig == SIGUSR2 ? '2' : 'w';
}

static void plusieurs(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = noter;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGWINCH, &sa, NULL);
    sigset_t b;
    sigemptyset(&b);
    sigaddset(&b, SIGUSR1);
    sigaddset(&b, SIGUSR2);
    sigaddset(&b, SIGWINCH);
    sigprocmask(SIG_BLOCK, &b, NULL);
    raise(SIGUSR2);
    raise(SIGWINCH);
    raise(SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &b, NULL);
    verifier(strcmp(ordre, "w21") == 0, "trois signaux debloques ensemble : trois cadres empiles, executes SIGWINCH, SIGUSR2, SIGUSR1");
    memset(ordre, 0, sizeof ordre);
    n_ordre = 0;
    sigaddset(&sa.sa_mask, SIGUSR2);
    sigaddset(&sa.sa_mask, SIGWINCH);
    sigaction(SIGUSR1, &sa, NULL);
    sigprocmask(SIG_BLOCK, &b, NULL);
    raise(SIGUSR2);
    raise(SIGWINCH);
    raise(SIGUSR1);
    sigprocmask(SIG_UNBLOCK, &b, NULL);
    verifier(strcmp(ordre, "1w2") == 0, "SIGUSR1 masquant les deux autres : lui d'abord, puis SIGWINCH et SIGUSR2 empiles");
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
    signal(SIGWINCH, SIG_DFL);
}

/* ---- abort, quitté par siglongjmp ---- */

static sigjmp_buf saut;

static void sortir(int sig)
{
    (void)sig;
    siglongjmp(saut, 1);
}

static void abandonner(void)
{
    signal(SIGABRT, sortir);
    int revenu = 0;
    if (sigsetjmp(saut, 1) == 0)
        abort();
    else
        revenu = 1;
    sigset_t m;
    sigprocmask(SIG_BLOCK, NULL, &m);
    verifier(revenu && !sigismember(&m, SIGABRT), "abort, quitte par siglongjmp depuis le gestionnaire : on continue, SIGABRT debloque");
    signal(SIGABRT, SIG_DFL);
}

/* ---- Un signal pour un fil à peine créé ---- */

static volatile long tid_du_gestionnaire, tid_du_fil;
static volatile int fil_continue;

static void dans_le_fil(int sig)
{
    (void)sig;
    tid_du_gestionnaire = syscall(SYS_gettid);
}

static void *corps(void *rien)
{
    (void)rien;
    tid_du_fil = syscall(SYS_gettid);
    while (!tid_du_gestionnaire)
        sched_yield();
    fil_continue = 1;
    return NULL;
}

static void fil_neuf(void)
{
    signal(SIGUSR2, dans_le_fil);
    pthread_t f;
    pthread_create(&f, NULL, corps, NULL);
    /* Chez nous, le fil neuf n'a pas encore tourné : le signal est livré à
     * son premier départ vers l'anneau 3 (le cadre préparé par clone). Sur
     * l'hôte, il a peut-être déjà commencé : le signal tombe ailleurs. */
    pthread_kill(f, SIGUSR2);
    pthread_join(f, NULL);
    verifier(tid_du_gestionnaire == tid_du_fil && fil_continue, "un signal vise un fil a peine cree : son gestionnaire tourne dans ce fil, qui continue");
    signal(SIGUSR2, SIG_DFL);
}

/* ---- Les fautes livrées à leur gestionnaire ---- */

static sigjmp_buf apres_faute;
static volatile int f_sig, f_code;
static volatile uint64_t f_addr, f_err, f_trapno, f_cr2, f_rip;

static void sur_faute(int sig, siginfo_t *si, void *c)
{
    /* AC d'abord : le gestionnaire hérite des drapeaux du programme (Linux
     * garde AC), et une faute d'alignement l'a peut-être mis ; sans cela,
     * ce gestionnaire referait la même faute. */
    __asm__ volatile("pushfq\n\tandq $~0x40000, (%%rsp)\n\tpopfq" ::: "cc", "memory");
    ucontext_t *uc = c;
    f_sig = sig;
    f_code = si->si_code;
    f_addr = (uint64_t)si->si_addr;
    f_err = uc->uc_mcontext.gregs[REG_ERR];
    f_trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
    f_cr2 = uc->uc_mcontext.gregs[REG_CR2];
    f_rip = uc->uc_mcontext.gregs[REG_RIP];
    siglongjmp(apres_faute, 1);
}

static void faire(void (*f)(void))
{
    f_sig = 0;
    if (!sigsetjmp(apres_faute, 1))
        f();
}

static const int lecture_seule = 1;
static char *page_interdite, *fichier_projete;
/* L'adresse attendue de RIP, rangée par l'assembleur AVANT la faute (le
 * gestionnaire part par siglongjmp : une sortie de l'asm ne serait jamais
 * écrite). */
uint64_t etiquette;

static volatile uintptr_t adresse_basse = 0x10;
static void lire_0x10(void) { (void)*(volatile int *)adresse_basse; }
static void ecrire_rodata(void) { *(volatile int *)&lecture_seule = 2; }
static void lire_interdite(void) { (void)*(volatile char *)page_interdite; }
static void au_dela(void) { (void)*(volatile char *)(fichier_projete + 8192); }
static void executer_pile(void) { volatile unsigned char code[16] = { 0xc3 }; ((void (*)(void))code)(); }
static void instruction_ud2(void) { __asm__ volatile("lea 1f(%%rip), %%rax\n\tmov %%rax, etiquette(%%rip)\n1:\tud2" ::: "rax", "memory"); }
static void division(void) { volatile int a = 1, b = 0; a = a / b; }
static void point_d_arret(void) { __asm__ volatile("lea 1f(%%rip), %%rax\n\tmov %%rax, etiquette(%%rip)\n\tint3\n1:" ::: "rax", "memory"); }
static void instruction_hlt(void) { __asm__ volatile("hlt"); }
static void int_0x81(void) { __asm__ volatile("int $0x81"); }
static void pas_a_pas(void)
{
    /* Le pas-à-pas s'arrête APRÈS l'instruction qui suit popfq (le nop). */
    __asm__ volatile("lea 1f(%%rip), %%rax\n\tmov %%rax, etiquette(%%rip)\n\t"
                     "pushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\tnop\n1:\tnop" ::: "rax", "cc", "memory");
}
static void instruction_icebp(void) { __asm__ volatile(".byte 0xf1"); }
static void alignement(void)
{
    static char t[16] __attribute__((aligned(16)));
    __asm__ volatile("pushfq\n\torq $0x40000, (%%rsp)\n\tpopfq\n\tmovl $1, 1(%0)\n\t"
                     "pushfq\n\tandq $~0x40000, (%%rsp)\n\tpopfq" :: "r"(t) : "cc", "memory");
}
static void division_sse(void)
{
    uint32_t m = 0x1f80 & ~0x200u;
    float un = 1.0f, zero = 0.0f;
    __asm__ volatile("ldmxcsr %0\n\tmovss %1, %%xmm0\n\tlea 1f(%%rip), %%rax\n\tmov %%rax, etiquette(%%rip)\n1:\tdivss %2, %%xmm0"
                     :: "m"(m), "m"(un), "m"(zero) : "rax", "xmm0", "memory");
}
static void division_x87(void)
{
    uint16_t cw = 0x037b;
    double un = 1.0, zero = 0.0;
    __asm__ volatile("fldcw %0\n\tfldl %1\n\tfdivl %2\n\tfwait\n\tfstp %%st(0)" :: "m"(cw), "m"(un), "m"(zero));
}
static void saut_non_canonique(void) { ((void (*)(void))0x8000000000000000ull)(); }

/* Une faute, et ce qu'en dit le gestionnaire : le signal, si_code, si_addr,
 * trapno et err du contexte. */
static int vu(int sig, int code, uint64_t addr, uint64_t trapno, uint64_t err)
{
    int ok = f_sig == sig && f_code == code && f_addr == addr && f_trapno == trapno && f_err == err;
    if (!ok)
        printf("[linux] gestionnaires : (vu : signal %d, si_code %d, si_addr %#lx, trapno %lu, err %#lx)\n", f_sig, f_code,
               (unsigned long)f_addr, (unsigned long)f_trapno, (unsigned long)f_err);
    return ok;
}

/* Le gestionnaire répare : il saute l'ud2 (2 octets) en changeant RIP dans
 * son contexte, comme un JIT qui intercepte ses propres fautes. */
static void sauter_ud2(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    uc->uc_mcontext.gregs[REG_RIP] += 2;
}

/* Un SS invalide rendu par un gestionnaire : l'iretq qui retourne au
 * programme fait une faute, le noyau en fait un SIGSEGV du programme (le
 * « bad iret »), dont le gestionnaire voit le SS fautif dans son contexte,
 * le répare, et le programme continue (Linux le permet : SS est remis
 * valide pour entrer dans ce gestionnaire). */
static volatile uint16_t ss_vu_par_segv;
static volatile int code_segv;

static void abimer_ss(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    ((uint16_t *)&uc->uc_mcontext.gregs[REG_CSGSFS])[3] = 0x33;
}

static void reparer_ss(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    ucontext_t *uc = c;
    uint16_t *segments = (uint16_t *)&uc->uc_mcontext.gregs[REG_CSGSFS];
    ss_vu_par_segv = segments[3];
    code_segv = si->si_code;
    segments[3] = 0x2b;
}

/* CS et SS faux rendus ensemble (0x2b, 0x33) : iretq refuse, et le cadre
 * de SIGSEGV n'a pas UC_STRICT_RESTORE_SS (le CS interrompu n'est pas celui
 * du mode 64 bits, `frame_uc_flags`) ; son gestionnaire ne répare que CS,
 * et rt_sigreturn remet SS valide (`force_valid_ss`) : le programme
 * continue (mesuré). */
static volatile uint64_t drapeaux_de_segv;

static void abimer_cs_ss(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    uint16_t *segments = (uint16_t *)&((ucontext_t *)c)->uc_mcontext.gregs[REG_CSGSFS];
    segments[0] = 0x2b;
    segments[3] = 0x33;
}

static void reparer_cs(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = c;
    drapeaux_de_segv = uc->uc_flags;
    uint16_t *segments = (uint16_t *)&uc->uc_mcontext.gregs[REG_CSGSFS];
    segments[0] = 0x33;
}

static void fautes(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sur_faute;
    sa.sa_flags = SA_SIGINFO;
    int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGTRAP };
    for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++)
        sigaction(sigs[i], &sa, NULL);
    page_interdite = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char chemin[64];
    snprintf(chemin, sizeof chemin, "/tmp/gestionnaires-%d", (int)getpid());
    int fd = open(chemin, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (write(fd, "x", 1) != 1)
        verifier(0, "fichier de test");
    fichier_projete = mmap(NULL, 16384, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    unlink(chemin);

    faire(lire_0x10);
    verifier(vu(SIGSEGV, SEGV_MAPERR, 0x10, 14, 4) && f_cr2 == 0x10, "lecture de 0x10 : SIGSEGV SEGV_MAPERR, si_addr et cr2 0x10, trapno 14, err 4");
    faire(ecrire_rodata);
    uint64_t a = (uint64_t)&lecture_seule;
    verifier(vu(SIGSEGV, SEGV_ACCERR, a, 14, 7) && f_cr2 == a, "ecriture dans .rodata : SIGSEGV SEGV_ACCERR, err 7");
    faire(lire_interdite);
    verifier(vu(SIGSEGV, SEGV_ACCERR, (uint64_t)page_interdite, 14, 4), "lecture d'une page PROT_NONE : SEGV_ACCERR, err 4");
    faire(executer_pile);
    verifier(f_sig == SIGSEGV && f_code == SEGV_ACCERR && f_trapno == 14 && f_err == 0x15 && f_addr == f_rip,
             "executer la pile : SEGV_ACCERR, err 0x15, si_addr = RIP");
    faire(au_dela);
    uint64_t b = (uint64_t)fichier_projete + 8192;
    verifier(vu(SIGBUS, BUS_ADRERR, b, 14, 4), "au-dela de la fin d'un fichier projete : SIGBUS BUS_ADRERR");
    faire(instruction_ud2);
    verifier(vu(SIGILL, ILL_ILLOPN, etiquette, 6, 0) && f_rip == etiquette && f_cr2 == b,
             "ud2 : SIGILL ILL_ILLOPN, si_addr = RIP, trapno 6 ; cr2 garde la derniere faute de page");
    faire(division);
    verifier(f_sig == SIGFPE && f_code == FPE_INTDIV && f_addr == f_rip && f_trapno == 0, "division par zero : SIGFPE FPE_INTDIV, si_addr = RIP");
    faire(point_d_arret);
    verifier(vu(SIGTRAP, SI_KERNEL, 0, 3, 0) && f_rip == etiquette, "int3 : SIGTRAP SI_KERNEL, trapno 3, RIP apres l'instruction");
    faire(instruction_hlt);
    verifier(vu(SIGSEGV, SI_KERNEL, 0, 13, 0), "hlt : SIGSEGV SI_KERNEL, trapno 13, err 0");
    faire(int_0x81);
    verifier(vu(SIGSEGV, SI_KERNEL, 0, 13, 0x40a), "int 0x81 : SIGSEGV, err 0x40a (le vecteur x 8 + 2)");
    faire(pas_a_pas);
    verifier(vu(SIGTRAP, TRAP_TRACE, etiquette, 1, 0) && f_rip == etiquette, "pas-a-pas (TF) : SIGTRAP TRAP_TRACE, si_addr = RIP, trapno 1");
    faire(instruction_icebp);
    /* Sous QEMU sans accélération, icebp est une instruction invalide. */
    verifier((f_sig == SIGTRAP && f_code == TRAP_BRKPT && f_trapno == 1) || (f_sig == SIGILL && f_code == ILL_ILLOPN && f_trapno == 6),
             "icebp : SIGTRAP TRAP_BRKPT (ou SIGILL sous QEMU sans acceleration)");
    /* QEMU sans accélération n'imite ni le contrôle de l'alignement (#AC)
     * ni les exceptions SIMD (#XM, lu dans target/i386/tcg/fpu_helper.c de
     * QEMU 8.2.2 : il ne lève que #MF) : là, aucune faute. Sur un vrai
     * processeur, et sur l'hôte, la faute et son siginfo. */
    faire(alignement);
    verifier(f_sig == 0 || vu(SIGBUS, BUS_ADRALN, 0, 17, 0),
             "acces non aligne sous AC : SIGBUS BUS_ADRALN, sans adresse, trapno 17 (rien sous QEMU sans acceleration)");
    faire(division_sse);
    verifier(f_sig == 0 || vu(SIGFPE, FPE_FLTDIV, etiquette, 19, 0),
             "division SSE par zero demasquee : SIGFPE FPE_FLTDIV, trapno 19 (rien sous QEMU sans acceleration)");
    faire(division_x87);
    verifier(f_sig == SIGFPE && f_code == FPE_FLTDIV && f_trapno == 16, "division x87 par zero demasquee : SIGFPE FPE_FLTDIV, trapno 16");
    faire(saut_non_canonique);
    /* Le matériel refuse le saut (#GP : SI_KERNEL) ; QEMU sans
     * accélération fait une faute de page en chargeant l'instruction. */
    verifier(f_sig == SIGSEGV, "un saut a une adresse non canonique : SIGSEGV");

    sa.sa_sigaction = sauter_ud2;
    sigaction(SIGILL, &sa, NULL);
    __asm__ volatile("ud2");
    verifier(1, "un gestionnaire saute l'ud2 en changeant RIP : le programme continue");

    sa.sa_sigaction = abimer_ss;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_sigaction = reparer_ss;
    sigaction(SIGSEGV, &sa, NULL);
    raise(SIGUSR1);
    uint16_t ss;
    __asm__ volatile("mov %%ss, %0" : "=r"(ss));
    verifier(ss_vu_par_segv == 0x33 && code_segv == SI_KERNEL && ss == 0x2b,
             "SS 0x33 rendu : iretq refuse, SIGSEGV livre, son gestionnaire voit 0x33, le repare, on continue");
    sa.sa_sigaction = abimer_cs_ss;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_sigaction = reparer_cs;
    sigaction(SIGSEGV, &sa, NULL);
    raise(SIGUSR1);
    __asm__ volatile("mov %%ss, %0" : "=r"(ss));
    verifier((drapeaux_de_segv & 6) == 2 && ss == 0x2b,
             "CS et SS faux rendus : le cadre de SIGSEGV sans UC_STRICT_RESTORE_SS ; CS seul repare, SS remis valide, on continue");
    for (unsigned i = 0; i < sizeof sigs / sizeof *sigs; i++)
        signal(sigs[i], SIG_DFL);
    signal(SIGUSR1, SIG_DFL);
}

int main(void)
{
    chez_nous = access("/etc/bonjour.txt", F_OK) == 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    processeur();
    printf("[linux] gestionnaires : processeur : %s\n", avx ? "XSAVE et AVX" : xsave ? "XSAVE" : "FXSAVE");
    cadre_de_signal();
    vecteurs();
    contexte();
    pile_de_secours();
    drapeaux();
    plusieurs();
    abandonner();
    fil_neuf();
    fautes();
    printf("[linux] gestionnaires : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
