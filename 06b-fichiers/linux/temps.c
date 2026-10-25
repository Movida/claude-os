/*
 * L'heure, vue d'un programme : clock_gettime, clock_getres,
 * gettimeofday, time. Il tourne dans notre noyau et sur l'hôte (make
 * tests-hote), et n'affiche que des faits vrais des deux côtés : jamais
 * l'heure elle-même, qui change, ni la résolution exacte (une
 * nanoseconde sous Linux, une milliseconde chez nous : on vérifie
 * seulement qu'elle ne dépasse pas une milliseconde).
 */
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] temps : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static long long ns(struct timespec t)
{
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(void)
{
    struct timespec reel, mono, cpu, res, avant, apres;
    clock_gettime(CLOCK_REALTIME, &reel);
    /* Le 1er janvier 2024 et le 1er janvier 2100, en secondes depuis 1970. */
    verifier(reel.tv_sec > 1704067200 && reel.tv_sec < 4102444800 && reel.tv_nsec < 1000000000,
             "date plausible (entre 2024 et 2100)");

    /* Mille lectures : MONOTONIC ne recule jamais. */
    int recule = 0;
    clock_gettime(CLOCK_MONOTONIC, &avant);
    for (int i = 0; i < 1000; i++) {
        clock_gettime(CLOCK_MONOTONIC, &apres);
        recule |= ns(apres) < ns(avant);
        avant = apres;
    }
    verifier(!recule, "CLOCK_MONOTONIC ne recule pas");

    /* Un calcul d'au moins quelques millisecondes : le temps de calcul et le
     * temps monotone avancent tous les deux. */
    struct timespec cpu_avant, mono_avant;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_avant);
    clock_gettime(CLOCK_MONOTONIC, &mono_avant);
    volatile unsigned long somme = 0;
    do {
        for (int i = 0; i < 100000; i++)
            somme += i;
        clock_gettime(CLOCK_MONOTONIC, &mono);
    } while (ns(mono) - ns(mono_avant) < 5000000);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
    verifier(ns(cpu) > ns(cpu_avant), "CLOCK_PROCESS_CPUTIME_ID avance avec le calcul");

    verifier(clock_getres(CLOCK_MONOTONIC, &res) == 0 && res.tv_sec == 0 && res.tv_nsec > 0 && res.tv_nsec <= 1000000,
             "resolution de CLOCK_MONOTONIC d'une milliseconde au plus");
    verifier(clock_getres(CLOCK_REALTIME, NULL) == 0, "clock_getres sans resultat");

    /* gettimeofday et time disent la même date que CLOCK_REALTIME, à une
     * seconde près. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_REALTIME, &reel);
    verifier(tv.tv_usec < 1000000 && reel.tv_sec - tv.tv_sec <= 1 && reel.tv_sec >= tv.tv_sec,
             "gettimeofday d'accord avec CLOCK_REALTIME");
    time_t t = 0;
    time_t r = time(&t);
    verifier(r == t && r - reel.tv_sec <= 1 && r >= reel.tv_sec, "time d'accord avec CLOCK_REALTIME");

    struct timespec grossier;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &grossier);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    verifier(ns(mono) - ns(grossier) < 20000000 && ns(mono) - ns(grossier) > -20000000,
             "CLOCK_MONOTONIC_COARSE proche de CLOCK_MONOTONIC");
    clock_gettime(CLOCK_BOOTTIME, &apres);
    verifier(ns(apres) >= ns(mono), "CLOCK_BOOTTIME au moins CLOCK_MONOTONIC");

    errno = 0;
    verifier(clock_gettime(99, &reel) == -1 && errno == EINVAL, "horloge inconnue : EINVAL");

    printf("[linux] temps : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
