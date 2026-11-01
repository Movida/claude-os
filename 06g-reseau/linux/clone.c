/*
 * clone et clone3 (6e) : les refus, dans l'ordre de Linux, puis un fil créé
 * par l'appel brut, sans la glibc. Il tourne dans notre noyau et sur l'hôte
 * (make tests-hote) : chaque ligne doit dire « ok » des deux côtés.
 *
 * Le filtre seccomp de Docker (le devcontainer) rend ENOSYS pour tout
 * clone3, pour que la glibc se replie sur clone : sur un hôte filtré (la
 * ligne « Seccomp: 2 » de /proc/self/status, que notre /proc n'a pas), les
 * refus de clone3 sont sautés, en le disant. La CI les vérifie sur un
 * hôte sans filtre.
 *
 * Seuls des appels qui doivent échouer sont faits avec des drapeaux de
 * processus : sur l'hôte, un clone qui réussirait créerait un processus.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif
#define CLONE_CLEAR_SIGHAND 0x100000000ULL

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] clone : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Le numéro d'erreur d'un appel système brut (0 s'il a réussi). */
static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

/* La struct clone_args, avec de la place derrière pour les octets « d'une
 * version future ». */
struct arguments {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls, set_tid, set_tid_size, cgroup;
    uint64_t futur[2];
};

static long clone3_brut(struct arguments *a, long taille)
{
    return erreur(syscall(SYS_clone3, a, taille));
}

/* L'hôte filtre-t-il les appels (seccomp) ? */
static int hote_filtre(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char ligne[256];
    int filtre = 0;
    if (f == NULL)
        return 0;
    while (fgets(ligne, sizeof ligne, f))
        if (strncmp(ligne, "Seccomp:", 8) == 0 && strtol(ligne + 8, NULL, 10) == 2)
            filtre = 1;
    fclose(f);
    return filtre;
}

#define UN_FIL (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM)

static void refus_clone3(void)
{
    struct arguments a;
    if (hote_filtre()) {
        printf("[linux] clone : refus de clone3 sautes (filtre seccomp de l'hote)\n");
        return;
    }
    memset(&a, 0, sizeof a);
    verifier(clone3_brut(&a, 0) == EINVAL, "clone3, taille 0 : EINVAL");
    verifier(clone3_brut(&a, 4097) == E2BIG, "clone3, plus d'une page : E2BIG");
    verifier(clone3_brut(NULL, 64) == EFAULT, "clone3, adresse nulle : EFAULT");
    a.futur[0] = 1;
    verifier(clone3_brut(&a, sizeof a) == E2BIG, "clone3, un octet inconnu non nul : E2BIG");
    a.futur[0] = 0;
    a.set_tid_size = 1;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, set_tid_size sans set_tid : EINVAL");
    a.set_tid_size = 0;
    a.exit_signal = 0x100;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, signal de fin hors de l'octet : EINVAL");
    a.exit_signal = 0;
    a.flags = 1ULL << 40;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, drapeau inconnu : EINVAL");
    a.flags = CLONE_DETACHED;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, CLONE_DETACHED : EINVAL");
    a.flags = 17; /* SIGCHLD dans les drapeaux : les bits du signal */
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, signal dans les drapeaux : EINVAL");
    a.flags = CLONE_SIGHAND | CLONE_VM | CLONE_CLEAR_SIGHAND;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, CLONE_SIGHAND et CLONE_CLEAR_SIGHAND : EINVAL");
    a.flags = UN_FIL;
    a.exit_signal = 17;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, un fil avec un signal de fin : EINVAL");
    a.exit_signal = 0;
    a.stack_size = 4096;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, une taille de pile sans pile : EINVAL");
    a.stack_size = 0;
    a.stack = 0x10000;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, une pile sans taille : EINVAL");
    a.stack_size = 1ULL << 63;
    verifier(clone3_brut(&a, 88) == EINVAL, "clone3, une pile hors des adresses : EINVAL");
    a.stack = a.stack_size = 0;
    a.flags = CLONE_THREAD | CLONE_VM;
    verifier(clone3_brut(&a, 64) == EINVAL, "clone3, un fil sans CLONE_SIGHAND : EINVAL");
}

static long clone_brut(unsigned long drapeaux, void *pile, int *ptid, int *ctid, unsigned long tls)
{
    return erreur(syscall(SYS_clone, drapeaux, pile, ptid, ctid, tls));
}

static void refus_clone(void)
{
    int a;
    verifier(clone_brut(CLONE_THREAD | CLONE_VM, NULL, NULL, NULL, 0) == EINVAL, "clone, un fil sans CLONE_SIGHAND : EINVAL");
    verifier(clone_brut(CLONE_SIGHAND, NULL, NULL, NULL, 0) == EINVAL, "clone, CLONE_SIGHAND sans CLONE_VM : EINVAL");
    /* (Le filtre de Docker rend EPERM pour tout espace de noms, avant
     * Linux.) */
    if (!hote_filtre())
        verifier(clone_brut(CLONE_FS | CLONE_NEWNS, NULL, NULL, NULL, 0) == EINVAL, "clone, CLONE_FS et CLONE_NEWNS : EINVAL");
    verifier(clone_brut(CLONE_PIDFD | CLONE_PARENT_SETTID, NULL, &a, NULL, 0) == EINVAL,
             "clone, CLONE_PIDFD et CLONE_PARENT_SETTID au meme endroit : EINVAL");
    verifier(clone_brut(UN_FIL | CLONE_SETTLS, NULL, NULL, NULL, 0x800000000000UL) == EPERM,
             "clone, CLONE_SETTLS hors des adresses : EPERM");
}

/* ----- Un fil par l'appel brut ----- */

/* Le fil ne passe pas par la glibc : sans TLS à lui (pas de CLONE_SETTLS),
 * il ne doit toucher ni errno ni rien de ce qui en dépend. D'où ces appels
 * en assembleur. */
static long brut0(long n)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n) : "rcx", "r11", "memory");
    return r;
}

static long brut1(long n, long a)
{
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a) : "rcx", "r11", "memory");
    return r;
}

static volatile long vu_tid, vu_pid, passages;

static __attribute__((noreturn)) void corps_du_fil(void)
{
    vu_tid = brut0(SYS_gettid);
    vu_pid = brut0(SYS_getpid);
    passages++;
    brut1(SYS_exit, 0);
    for (;;)
        ;
}

/* clone, puis, dans le fil (rax = 0, sur sa pile), corps_du_fil. Le
 * créateur revient avec le numéro du fil, ou -errno. */
static long cloner_fil(unsigned long drapeaux, void *haut, int *ptid, int *ctid)
{
    long r;
    register long r10 __asm__("r10") = (long)ctid;
    register long r8 __asm__("r8") = 0;
    register void (*f)(void) __asm__("r12") = corps_du_fil;
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "call *%%r12\n\t"
                     "1:"
                     : "=a"(r)
                     : "a"(SYS_clone), "D"(drapeaux), "S"(haut), "d"(ptid), "r"(r10), "r"(r8), "r"(f)
                     : "rcx", "r11", "memory");
    return r;
}

static void fil_brut(void)
{
    static int ptid, ctid;
    const size_t taille = 64 << 10;
    char *pile = mmap(NULL, taille, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pile == MAP_FAILED) {
        verifier(0, "pile du fil");
        return;
    }
    /* Pas 0 : le fil n'a peut-être pas encore écrit son numéro quand on
     * le lit (CLONE_CHILD_SETTID est écrit par lui, à son départ). */
    ctid = -1;
    long tid = cloner_fil(UN_FIL | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID, pile + taille, &ptid,
                          &ctid);
    verifier(tid > 0 && tid != getpid(), "un fil, de numero different du processus");
    verifier(ptid == tid, "CLONE_PARENT_SETTID ecrit avant le retour");
    /* CLONE_CHILD_CLEARTID : le noyau efface ctid à la fin du fil et
     * réveille qui attend (ce que fait pthread_join). ctid vaut -1, le
     * numéro (CLONE_CHILD_SETTID, écrit par le fil), ou 0 s'il a fini. */
    for (;;) {
        int v = __atomic_load_n(&ctid, __ATOMIC_ACQUIRE);
        if (v == 0)
            break;
        syscall(SYS_futex, &ctid, FUTEX_WAIT, v, NULL, NULL, 0);
    }
    verifier(passages == 1, "le fil a tourne une fois");
    verifier(vu_tid == tid, "gettid dans le fil");
    verifier(vu_pid == getpid(), "getpid dans le fil : celui du processus");
    verifier(syscall(SYS_tgkill, getpid(), getpid(), 0) == 0, "tgkill vers le fil principal");
    /* Le fil a effacé ctid un peu avant de disparaître tout à fait : il
     * finit de mourir pendant qu'on cède le processeur. */
    int disparu = 0;
    for (int i = 0; i < 1000 && !disparu; i++) {
        disparu = syscall(SYS_tgkill, getpid(), tid, 0) == -1 && errno == ESRCH;
        if (!disparu)
            sched_yield();
    }
    verifier(disparu, "tgkill vers le fil fini : ESRCH");
    munmap(pile, taille);
}

int main(void)
{
    refus_clone3();
    refus_clone();
    fil_brut();
    printf("[linux] clone : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
