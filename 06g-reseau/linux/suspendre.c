/*
 * Suspendre des fils par un signal, comme le fait JavaScriptCore (le
 * moteur JavaScript de Bun) pour son ramasse-miettes (6f) : le fil qui
 * suspend envoie SIGPWR à un autre ; le gestionnaire de SIGPWR (SA_SIGINFO,
 * SIGPWR bloqué pendant lui) range les registres du fil (ceux du contexte),
 * le dit par un sémaphore, puis attend dans sigsuspend, avec tout bloqué
 * sauf SIGPWR ; le fil qui suspend lit ce qu'il veut, puis renvoie SIGPWR :
 * le second gestionnaire, appelé DANS sigsuspend, voit qu'il est déjà
 * suspendu et rend la main ; sigsuspend finit, le premier gestionnaire
 * aussi, et le fil reprend (WTF/wtf/posix/ThreadingPOSIX.cpp).
 *
 * Quatre fils qui comptent sans arrêt, suspendus et relancés chacun cinquante
 * fois : pendant qu'il est suspendu, un fil ne compte plus ; ses registres
 * rangés désignent sa pile et son code ; il reprend sans rien perdre, et
 * son masque est revenu. Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#define FILS 4
#define TOURS 50

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] suspendre : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static sem_t suspendu;
static __thread int deja_suspendu;
static volatile uint64_t compte[FILS];
static volatile uint64_t rsp_vu[FILS], rip_vu[FILS];
static __thread int numero;
static volatile int fini;
static char *bas_pile[FILS], *haut_pile[FILS];

static void suspension(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)si;
    if (deja_suspendu)
        return; /* le signal de relance, dans sigsuspend */
    ucontext_t *uc = c;
    rsp_vu[numero] = uc->uc_mcontext.gregs[REG_RSP];
    rip_vu[numero] = uc->uc_mcontext.gregs[REG_RIP];
    deja_suspendu = 1;
    sem_post(&suspendu);
    sigset_t tout_sauf;
    sigfillset(&tout_sauf);
    sigdelset(&tout_sauf, SIGPWR);
    sigsuspend(&tout_sauf);
    deja_suspendu = 0;
}

static void *compter(void *n)
{
    numero = (int)(intptr_t)n;
    pthread_attr_t a;
    pthread_getattr_np(pthread_self(), &a);
    void *base;
    size_t taille;
    pthread_attr_getstack(&a, &base, &taille);
    bas_pile[numero] = base;
    haut_pile[numero] = (char *)base + taille;
    pthread_attr_destroy(&a);
    while (!fini)
        compte[numero]++;
    sigset_t m;
    pthread_sigmask(SIG_BLOCK, NULL, &m);
    return (void *)(intptr_t)sigismember(&m, SIGPWR);
}

extern char __executable_start[], etext[];

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    sem_init(&suspendu, 0, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = suspension;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGPWR);
    sigaction(SIGPWR, &sa, NULL);
    pthread_t f[FILS];
    for (int i = 0; i < FILS; i++)
        pthread_create(&f[i], NULL, compter, (void *)(intptr_t)i);
    for (int i = 0; i < FILS; i++)
        while (!compte[i])
            sched_yield();

    int arrete = 1, registres = 1, reprend = 1;
    for (int t = 0; t < TOURS; t++) {
        for (int i = 0; i < FILS; i++) {
            pthread_kill(f[i], SIGPWR);
            while (sem_wait(&suspendu) != 0)
                ;
            uint64_t avant = compte[i];
            sched_yield();
            sched_yield();
            arrete &= compte[i] == avant;
            registres &= rsp_vu[i] > (uint64_t)bas_pile[i] && rsp_vu[i] <= (uint64_t)haut_pile[i]
                         && rip_vu[i] >= (uint64_t)__executable_start && rip_vu[i] < (uint64_t)etext;
            pthread_kill(f[i], SIGPWR);
            uint64_t repris = compte[i];
            while (compte[i] == repris)
                sched_yield();
            reprend &= compte[i] > avant;
        }
    }
    fini = 1;
    int masques = 1;
    for (int i = 0; i < FILS; i++) {
        void *r;
        pthread_join(f[i], &r);
        masques &= r == NULL;
    }
    verifier(arrete, "quatre fils suspendus cinquante fois chacun par SIGPWR : pendant la suspension, ils ne comptent plus");
    verifier(registres, "les registres ranges par le gestionnaire : RSP dans la pile du fil, RIP dans le programme");
    verifier(reprend, "relances par un second SIGPWR (livre dans sigsuspend) : ils reprennent");
    verifier(masques, "a la fin, SIGPWR n'est plus bloque dans aucun fil");
    printf("[linux] suspendre : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
