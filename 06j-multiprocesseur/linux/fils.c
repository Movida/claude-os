/*
 * Des programmes à plusieurs fils (6e), par la glibc (pthread), comme les
 * écrit tout programme : créer, attendre, se partager un verrou et une
 * condition, des variables par fil, un verrou robuste dont le détenteur
 * meurt, le mode d'arrondi hérité, les masques de signaux propres à chaque
 * fil. Il tourne dans notre noyau et sur l'hôte (make tests-hote) : chaque
 * ligne doit dire « ok » des deux côtés.
 *
 * Trois façons de finir, mesurées sous Linux 6.18 :
 *   - sans argument, le fil principal finit le premier (pthread_exit) ; le
 *     processus vit tant qu'un fil vit, et prend le code du dernier
 *     (0 si tout va bien, 1 sinon : un exit du fil seul, par l'appel brut) ;
 *   - « groupe » : un fil appelle exit(7) pendant que le principal attend
 *     un fil qui ne finira jamais : tout le groupe s'arrête, code 7 ;
 *   - « faute » (make tests-qemu) : un fil nommé « fautif » écrit à
 *     l'adresse 0 : tout le groupe meurt de SIGSEGV (139), et le message du
 *     noyau porte le nom du fil.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <fenv.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] fils : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static pid_t gettid_(void)
{
    return syscall(SYS_gettid);
}

/* ----- Créer et attendre ----- */

#define N 8

static void *carre(void *a)
{
    long n = (long)a;
    return (void *)(n * n);
}

static void creer_et_attendre(void)
{
    pthread_t f[N];
    int ok = 1;
    for (long i = 0; i < N; i++)
        ok &= pthread_create(&f[i], NULL, carre, (void *)i) == 0;
    for (long i = 0; i < N; i++) {
        void *r;
        ok &= pthread_join(f[i], &r) == 0 && (long)r == i * i;
    }
    verifier(ok, "huit fils crees puis attendus, chacun son resultat");
}

/* Deux cents fils vivants à la fois (chacun a son dossier dans /proc :
 * le noyau doit avoir la place d'avance, sinon « memoire rendue » le
 * dit). */
#define BEAUCOUP 200
static pthread_barrier_t barriere;

static void *attendre_les_autres(void *a)
{
    pthread_barrier_wait(&barriere);
    return a;
}

static void beaucoup_de_fils(void)
{
    static pthread_t f[BEAUCOUP];
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 << 10);
    pthread_barrier_init(&barriere, NULL, BEAUCOUP + 1);
    int crees = 0;
    while (crees < BEAUCOUP && pthread_create(&f[crees], &attr, attendre_les_autres, NULL) == 0)
        crees++;
    if (crees == BEAUCOUP)
        pthread_barrier_wait(&barriere);
    for (int i = 0; i < crees; i++)
        pthread_join(f[i], NULL);
    verifier(crees == BEAUCOUP, "deux cents fils vivants a la fois");
}

/* ----- Un verrou et une condition ----- */

static pthread_mutex_t verrou = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static long compteur;

static void *compter(void *a)
{
    for (int i = 0; i < 20000; i++) {
        pthread_mutex_lock(&verrou);
        compteur++;
        pthread_mutex_unlock(&verrou);
        /* Céder de temps en temps : que les fils se croisent aussi sur un
         * seul processeur. */
        if (i % 1000 == 0)
            sched_yield();
    }
    return a;
}

static void un_verrou(void)
{
    pthread_t f[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&f[i], NULL, compter, NULL);
    for (int i = 0; i < 4; i++)
        pthread_join(f[i], NULL);
    verifier(compteur == 80000, "quatre fils, un verrou, 80000 increments");
}

static int tour; /* 0 : au principal ; 1 : à l'autre */
static int balles;

static void *renvoyer(void *a)
{
    pthread_mutex_lock(&verrou);
    for (int i = 0; i < 100; i++) {
        while (tour != 1)
            pthread_cond_wait(&condition, &verrou);
        balles++;
        tour = 0;
        pthread_cond_signal(&condition);
    }
    pthread_mutex_unlock(&verrou);
    return a;
}

static void une_condition(void)
{
    pthread_t f;
    pthread_create(&f, NULL, renvoyer, NULL);
    pthread_mutex_lock(&verrou);
    for (int i = 0; i < 100; i++) {
        tour = 1;
        pthread_cond_signal(&condition);
        while (tour != 0)
            pthread_cond_wait(&condition, &verrou);
    }
    pthread_mutex_unlock(&verrou);
    pthread_join(f, NULL);
    verifier(balles == 100, "cent allers-retours par une condition");
}

/* ----- Ce qui est à chaque fil ----- */

static __thread int a_moi = 1;
static pid_t tid_vu, pid_vu;
static int a_moi_vu, arrondi_vu;
static unsigned long long masque_vu;

static void *regarder(void *a)
{
    a_moi += 41;
    a_moi_vu = a_moi;
    tid_vu = gettid_();
    pid_vu = getpid();
    arrondi_vu = fegetround();
    fesetround(FE_TOWARDZERO);
    sigset_t m;
    pthread_sigmask(SIG_SETMASK, NULL, &m);
    masque_vu = sigismember(&m, SIGUSR1);
    /* Son masque à lui : débloquer SIGUSR1 ne change pas celui du principal. */
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &m, NULL);
    return a;
}

static void a_chacun(void)
{
    sigset_t m, apres;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &m, NULL);
    fesetround(FE_UPWARD);
    pthread_t f;
    pthread_create(&f, NULL, regarder, NULL);
    pthread_join(f, NULL);
    verifier(a_moi_vu == 42 && a_moi == 1, "une variable __thread par fil");
    verifier(tid_vu != gettid_() && pid_vu == getpid(), "un numero de fil a lui, le numero du processus commun");
    verifier(arrondi_vu == FE_UPWARD, "le mode d'arrondi herite du createur");
    verifier(fegetround() == FE_UPWARD, "le mode d'arrondi change par le fil reste le sien");
    fesetround(FE_TONEAREST);
    pthread_sigmask(SIG_SETMASK, NULL, &apres);
    verifier(masque_vu == 1 && sigismember(&apres, SIGUSR1), "le masque des signaux herite, puis propre a chaque fil");
    pthread_sigmask(SIG_UNBLOCK, &m, NULL);
}

/* ----- Un verrou robuste ----- */

static pthread_mutex_t robuste;

static void *prendre_et_mourir(void *a)
{
    pthread_mutex_lock(&robuste);
    return a; /* sans le rendre */
}

static void verrou_robuste(void)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_setrobust(&attr, PTHREAD_MUTEX_ROBUST);
    pthread_mutex_init(&robuste, &attr);
    pthread_t f;
    pthread_create(&f, NULL, prendre_et_mourir, NULL);
    pthread_join(f, NULL);
    int r = pthread_mutex_lock(&robuste);
    verifier(r == EOWNERDEAD, "un verrou robuste dont le detenteur est mort : EOWNERDEAD");
    verifier(pthread_mutex_consistent(&robuste) == 0 && pthread_mutex_unlock(&robuste) == 0
             && pthread_mutex_lock(&robuste) == 0 && pthread_mutex_unlock(&robuste) == 0,
             "puis rendu coherent, il se reprend");
}

/* ----- Un futex déplacé vers lui-même ----- */

static int mot_futex;
static volatile int attend;

static volatile pid_t tid_autre_futex;

static void *attendre_futex(void *a)
{
    tid_autre_futex = gettid_();
    attend = 1;
    while (__atomic_load_n(&mot_futex, __ATOMIC_ACQUIRE) == 0)
        syscall(SYS_futex, &mot_futex, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    return a;
}

/* FUTEX_REQUEUE de l'adresse vers elle-même, avec un fil qui y attend :
 * Linux compte l'attente « déplacée » et rend 1, tout de suite. Un noyau
 * qui la retirerait et la remettrait à la fin de la même file la
 * retrouverait 2^30 fois, interruptions coupées. */
static void requeue_sur_soi(void)
{
    pthread_t f;
    pthread_create(&f, NULL, attendre_futex, NULL);
    while (!attend)
        sched_yield();
    struct timespec dix = { 0, 10000000 };
    nanosleep(&dix, NULL); /* qu'il dorme vraiment dans le futex */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long r = syscall(SYS_futex, &mot_futex, FUTEX_REQUEUE_PRIVATE, 0, (void *)(1L << 30), &mot_futex, 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(r == 1 && ms < 100, "FUTEX_REQUEUE vers la meme adresse : 1, aussitot");
    /* kill vers le numéro d'un fil : le signal va à son processus. */
    verifier(kill(tid_autre_futex, 0) == 0, "kill vers le numero d'un fil : son processus");
    __atomic_store_n(&mot_futex, 1, __ATOMIC_RELEASE);
    syscall(SYS_futex, &mot_futex, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    pthread_join(f, NULL);
}

/* ----- Finir ----- */

static void *dernier(void *a)
{
    struct timespec t = { 0, 50000000 };
    nanosleep(&t, NULL);
    printf("[linux] fils : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    fflush(stdout);
    /* exit du fil seul (pas exit_group) : le processus finit avec lui, le
     * dernier, et prend son code. */
    syscall(SYS_exit, echecs != 0);
    return a;
}

static void *dormir_toujours(void *a)
{
    pthread_mutex_lock(&verrou);
    for (;;)
        pthread_cond_wait(&condition, &verrou);
    return a;
}

static void *finir_le_groupe(void *a)
{
    struct timespec t = { 0, 20000000 };
    nanosleep(&t, NULL);
    printf("[linux] fils : exit(7) dans un fil, le principal attend\n");
    exit(7);
    return a;
}

static void *fauter(void *a)
{
    prctl(PR_SET_NAME, "fautif");
    printf("[linux] fils : un fil ecrit a l'adresse 0\n");
    fflush(stdout);
    *(volatile int *)a = 1;
    return a;
}

int main(int argc, char **argv)
{
    pthread_t f;
    if (argc == 2 && strcmp(argv[1], "groupe") == 0) {
        pthread_t g;
        pthread_create(&f, NULL, dormir_toujours, NULL);
        pthread_create(&g, NULL, finir_le_groupe, NULL);
        pthread_join(f, NULL);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "faute") == 0) {
        pthread_create(&f, NULL, fauter, NULL);
        pthread_join(f, NULL);
        return 0;
    }
    creer_et_attendre();
    beaucoup_de_fils();
    un_verrou();
    une_condition();
    a_chacun();
    verrou_robuste();
    requeue_sur_soi();
    fflush(stdout);
    pthread_create(&f, NULL, dernier, NULL);
    pthread_exit(NULL);
}
