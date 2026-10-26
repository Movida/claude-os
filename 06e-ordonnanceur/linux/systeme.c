/*
 * Les petits appels de claude --version (6d) : uname, sched_getaffinity,
 * sched_yield, futex, prctl. Il tourne dans notre noyau et sur l'hôte
 * (make tests-hote) : chaque ligne doit dire « ok » des deux côtés. Ce qui
 * dépend du noyau de l'hôte (le nombre de processeurs, sa version,
 * PR_SET_VMA, qu'un Linux peut avoir ou non) n'y est vérifié qu'au plus
 * large ; chez nous, la valeur exacte.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] systeme : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Le numéro d'erreur d'un appel système brut (0 s'il a réussi). */
static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static long futex(void *adresse, int operation, uint32_t val, const struct timespec *delai, void *adresse2, uint32_t val3)
{
    return erreur(syscall(SYS_futex, adresse, operation, val, delai, adresse2, val3));
}

static long long ns(struct timespec t)
{
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static long long horloge(clockid_t h)
{
    struct timespec t;
    clock_gettime(h, &t);
    return ns(t);
}

static int chez_nous;

static void systeme(void)
{
    struct utsname u;
    verifier(uname(&u) == 0 && strcmp(u.sysname, "Linux") == 0 && strcmp(u.machine, "x86_64") == 0
             && u.release[0] >= '0' && u.release[0] <= '9', "uname : Linux, x86_64, une version");
    if (chez_nous)
        verifier(strcmp(u.release, "6.18.0-claude-os") == 0 && strcmp(u.version, "#1") == 0
                 && strcmp(u.nodename, "(none)") == 0 && strcmp(u.domainname, "(none)") == 0,
                 "uname, chez nous : 6.18.0-claude-os, #1, (none)");
    verifier(erreur(syscall(SYS_uname, (void *)8)) == EFAULT, "uname a une adresse invalide : EFAULT");
    verifier(sched_yield() == 0, "sched_yield : 0");
}

static void processeurs(void)
{
    unsigned char masque[1024];
    memset(masque, 0xff, sizeof masque);
    long r = syscall(SYS_sched_getaffinity, 0, sizeof masque, masque);
    int un = 0;
    for (long i = 0; i < r; i++)
        un |= masque[i];
    verifier(r > 0 && r % 8 == 0 && r <= 1024 && un, "sched_getaffinity : un multiple de 8, au moins un processeur");
    if (chez_nous)
        verifier(r == 8 && masque[0] == 1 && masque[1] == 0 && masque[8] == 0xff,
                 "sched_getaffinity, chez nous : 8 octets, le processeur 0 seul, rien d'ecrit apres");
    verifier(erreur(syscall(SYS_sched_getaffinity, 0, 4, masque)) == EINVAL, "4 octets : EINVAL");
    verifier(erreur(syscall(SYS_sched_getaffinity, 0, 1028, masque)) == EINVAL, "1028 octets (pas un multiple de 8) : EINVAL");
    verifier(erreur(syscall(SYS_sched_getaffinity, 2147483000, 1024, masque)) == ESRCH,
             "un processus qui n'existe pas : ESRCH");
    verifier(erreur(syscall(SYS_sched_getaffinity, 2147483000, 4, masque)) == EINVAL,
             "la longueur verifiee avant le processus : EINVAL");
    verifier(erreur(syscall(SYS_sched_getaffinity, 0, 1024, (void *)8)) == EFAULT, "a une adresse invalide : EFAULT");
}

static void futexes(void)
{
    static uint32_t x = 5, y = 5;
    char *octets = (char *)&x;
    struct timespec zero = { 0, 0 }, cent = { 0, 100000000 }, faux = { 0, 1000000000 };
    verifier(futex(&x, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0) == 0, "futex WAKE prive : personne a reveiller, 0");
    verifier(futex(NULL, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0) == 0, "WAKE prive a l'adresse 0 : 0 (rien n'est lu)");
    verifier(futex(&x, FUTEX_WAKE, 1, NULL, NULL, 0) == 0, "WAKE partage : 0");
    verifier(futex(NULL, FUTEX_WAKE, 1, NULL, NULL, 0) == EFAULT, "WAKE partage a l'adresse 0 : EFAULT");
    verifier(futex(octets + 1, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0) == EINVAL, "WAKE non aligne : EINVAL");
    verifier(futex(octets + 1, FUTEX_WAIT_PRIVATE, 5, NULL, NULL, 0) == EINVAL, "WAIT non aligne : EINVAL");
    verifier(futex(&x, FUTEX_WAIT_PRIVATE, 4, NULL, NULL, 0) == EAGAIN, "WAIT sur une autre valeur : EAGAIN");
    verifier(futex(NULL, FUTEX_WAIT_PRIVATE, 5, NULL, NULL, 0) == EFAULT, "WAIT a l'adresse 0 : EFAULT");
    verifier(futex(&x, FUTEX_WAIT_PRIVATE, 4, &faux, NULL, 0) == EINVAL, "un delai invalide : EINVAL, avant la valeur");
    verifier(futex(&x, FUTEX_WAIT_PRIVATE, 4, (void *)8, NULL, 0) == EFAULT, "un delai a une adresse invalide : EFAULT");
    verifier(futex(&x, FUTEX_WAIT_PRIVATE, 5, &zero, NULL, 0) == ETIMEDOUT, "un delai nul : ETIMEDOUT");
    long long avant = horloge(CLOCK_MONOTONIC);
    long r = futex(&x, FUTEX_WAIT_PRIVATE, 5, &cent, NULL, 0);
    long long duree = horloge(CLOCK_MONOTONIC) - avant;
    verifier(r == ETIMEDOUT && duree >= 100000000, "WAIT de 100 ms : ETIMEDOUT, pas avant 100 ms");
    verifier(futex(&x, FUTEX_WAIT | FUTEX_CLOCK_REALTIME, 5, &zero, NULL, 0) == ENOSYS,
             "WAIT avec FUTEX_CLOCK_REALTIME : ENOSYS");
    verifier(futex(&x, FUTEX_WAIT_BITSET_PRIVATE, 5, &zero, NULL, 0) == EINVAL, "WAIT_BITSET d'un ensemble vide : EINVAL");
    verifier(futex(&x, FUTEX_WAKE_BITSET_PRIVATE, 1, NULL, NULL, 0) == EINVAL, "WAKE_BITSET d'un ensemble vide : EINVAL");
    verifier(futex(&x, FUTEX_WAIT_BITSET_PRIVATE, 5, &zero, NULL, FUTEX_BITSET_MATCH_ANY) == ETIMEDOUT,
             "WAIT_BITSET, echeance absolue passee (MONOTONIC) : ETIMEDOUT");
    verifier(futex(&x, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME, 5, &zero, NULL, FUTEX_BITSET_MATCH_ANY) == ETIMEDOUT,
             "WAIT_BITSET, echeance absolue passee (REALTIME) : ETIMEDOUT");
    uint32_t *lecture = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    verifier(futex(lecture, FUTEX_WAIT_PRIVATE, 0, &zero, NULL, 0) == ETIMEDOUT, "WAIT sur une page en lecture seule : permis");
    munmap(lecture, 4096);
    verifier(syscall(SYS_futex, &x, FUTEX_REQUEUE_PRIVATE, 1, 1, &y, 0) == 0, "REQUEUE : 0");
    verifier(futex(&x, FUTEX_CMP_REQUEUE_PRIVATE, 1, NULL, &y, 4) == EAGAIN, "CMP_REQUEUE sur une autre valeur : EAGAIN");
    verifier(syscall(SYS_futex, &x, FUTEX_CMP_REQUEUE_PRIVATE, 1, 1, &y, 5) == 0, "CMP_REQUEUE : 0");
    verifier(syscall(SYS_futex, &x, FUTEX_WAKE_OP_PRIVATE, 1, 1, &y, FUTEX_OP(FUTEX_OP_ADD, 3, FUTEX_OP_CMP_EQ, 5)) == 0
             && y == 8, "WAKE_OP : 0, et la seconde adresse changee (5 + 3)");
    /* Une comparaison inconnue (7) : Linux fait quand même l'opération,
     * puis rend ENOSYS ; une opération inconnue (6), elle, n'écrit rien. */
    y = 7;
    verifier(erreur(syscall(SYS_futex, &x, FUTEX_WAKE_OP_PRIVATE, 1, 1, &y, FUTEX_OP(FUTEX_OP_ADD, 3, 7, 0))) == ENOSYS
             && y == 10, "WAKE_OP, comparaison inconnue : l'operation faite (7 + 3), puis ENOSYS");
    verifier(erreur(syscall(SYS_futex, &x, FUTEX_WAKE_OP_PRIVATE, 1, 1, &y, FUTEX_OP(6, 3, FUTEX_OP_CMP_EQ, 0))) == ENOSYS
             && y == 10, "WAKE_OP, operation inconnue : rien d'ecrit, ENOSYS");
    verifier(futex(&x, 99, 0, NULL, NULL, 0) == ENOSYS, "une operation inconnue : ENOSYS");

    /* Attendre n'est pas calculer : 1,5 s d'attente sous une limite de
     * temps de calcul d'une seconde, et le programme est toujours là. */
    struct rlimit avant_limite, une = { 1, 2 };
    getrlimit(RLIMIT_CPU, &avant_limite);
    setrlimit(RLIMIT_CPU, &une);
    long long cpu = horloge(CLOCK_PROCESS_CPUTIME_ID);
    struct timespec long_delai = { 1, 500000000 };
    r = futex(&x, FUTEX_WAIT_PRIVATE, 5, &long_delai, NULL, 0);
    cpu = horloge(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    verifier(r == ETIMEDOUT && cpu < 500000000, "attendre 1,5 s sous RLIMIT_CPU d'une seconde : vivant, presque sans calcul");
    setrlimit(RLIMIT_CPU, &avant_limite);
}

static void nom(void)
{
    char lu[32];
    memset(lu, 'x', sizeof lu);
    verifier(prctl(PR_SET_NAME, "abcdefghijklmnopqrstuvwxyz") == 0 && prctl(PR_GET_NAME, lu) == 0
             && strcmp(lu, "abcdefghijklmno") == 0 && lu[16] == 'x', "PR_SET_NAME tronque a 15, PR_GET_NAME en rend 16");
    prctl(PR_SET_NAME, "systeme");
    verifier(prctl(PR_SET_NAME, (void *)8) == -1 && errno == EFAULT, "PR_SET_NAME a une adresse invalide : EFAULT");
    verifier(prctl(9999, 0) == -1 && errno == EINVAL, "une option inconnue : EINVAL");
    if (chez_nous) {
        static char zone[4096] __attribute__((aligned(4096)));
        verifier(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zone, sizeof zone, "nom") == -1 && errno == EINVAL,
                 "PR_SET_VMA, chez nous : EINVAL (pas de nom de zone)");
    }
}

int main(void)
{
    chez_nous = access("/etc/bonjour.txt", F_OK) == 0;
    systeme();
    processeurs();
    futexes();
    nom();
    printf("[linux] systeme : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
