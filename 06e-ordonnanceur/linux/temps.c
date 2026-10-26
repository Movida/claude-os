/*
 * L'heure, vue d'un programme : clock_gettime, clock_getres,
 * gettimeofday, time ; et dormir : nanosleep, clock_nanosleep. Il tourne
 * dans notre noyau et sur l'hôte (make
 * tests-hote), et n'affiche que des faits vrais des deux côtés : jamais
 * l'heure elle-même, qui change, ni la résolution exacte (une
 * nanoseconde sous Linux, et chez nous quand le TSC est fiable ; sinon un
 * tic : on vérifie seulement qu'elle ne dépasse pas une milliseconde).
 */
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

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
    /* Une horloge qui se dit fine (une nanoseconde, sous Linux comme chez
     * nous avec le TSC) doit l'être : sur 1000 paires de lectures de
     * suite, au moins un écart non nul et de moins de 100 µs. Une
     * horloge au tic n'en a que de nuls ou d'un tic. */
    if (res.tv_nsec == 1) {
        int fin = 0;
        for (int i = 0; i < 1000 && !fin; i++) {
            struct timespec a, b;
            clock_gettime(CLOCK_MONOTONIC, &a);
            clock_gettime(CLOCK_MONOTONIC, &b);
            long long d = ns(b) - ns(a);
            fin = d > 0 && d < 100000;
        }
        verifier(fin, "CLOCK_MONOTONIC a la nanoseconde (resolution 1 ns)");
    } else {
        printf("[linux] temps : CLOCK_MONOTONIC au tic (resolution %ld ns)\n", res.tv_nsec);
    }
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

    /* nanosleep de 50 ms : jamais plus tôt. Le retard n'est qu'affiché :
     * il dépend de la machine (mesuré sur l'hôte : jusqu'à 2,5 ms au
     * repos, 17 ms quand elle calcule), et sous QEMU de l'hôte aussi. */
    struct timespec cinquante = { 0, 50000000 };
    clock_gettime(CLOCK_MONOTONIC, &avant);
    int n = nanosleep(&cinquante, NULL);
    clock_gettime(CLOCK_MONOTONIC, &apres);
    long long duree = ns(apres) - ns(avant);
    verifier(n == 0 && duree >= 50000000, "nanosleep de 50 ms : pas avant 50 ms");
    fprintf(stderr, "[linux] temps : nanosleep de 50 ms : retard de %lld us\n", (duree - 50000000) / 1000);

    /* clock_nanosleep, par l'appel brut (la glibc refuse elle-même
     * THREAD_CPUTIME_ID, sans appeler le noyau) : ce que rend chaque
     * horloge pour une échéance absolue déjà passée (0 : elle sait dormir),
     * mesuré sous Linux 6.18. */
    struct { int horloge; long attendu; const char *nom; } horloges[] = {
        { CLOCK_REALTIME, 0, "REALTIME" }, { CLOCK_MONOTONIC, 0, "MONOTONIC" },
        { CLOCK_PROCESS_CPUTIME_ID, 0, "PROCESS_CPUTIME_ID" }, { CLOCK_THREAD_CPUTIME_ID, -EOPNOTSUPP, "THREAD_CPUTIME_ID" },
        { CLOCK_MONOTONIC_RAW, -EOPNOTSUPP, "MONOTONIC_RAW" }, { CLOCK_REALTIME_COARSE, -EOPNOTSUPP, "REALTIME_COARSE" },
        { CLOCK_MONOTONIC_COARSE, -EOPNOTSUPP, "MONOTONIC_COARSE" }, { CLOCK_BOOTTIME, 0, "BOOTTIME" },
        { CLOCK_REALTIME_ALARM, -EPERM, "REALTIME_ALARM" }, { CLOCK_BOOTTIME_ALARM, -EPERM, "BOOTTIME_ALARM" },
        { 10, -EINVAL, "10" }, { CLOCK_TAI, 0, "TAI" }, { 99, -EINVAL, "99" },
    };
    struct timespec zero = { 0, 0 };
    int bonnes = 1;
    for (unsigned i = 0; i < sizeof horloges / sizeof horloges[0]; i++) {
        long r = syscall(SYS_clock_nanosleep, horloges[i].horloge, TIMER_ABSTIME, &zero, NULL);
        long e = r == 0 ? 0 : -errno;
        if (e != horloges[i].attendu) {
            printf("[linux] temps : clock_nanosleep(%s) : %ld au lieu de %ld\n", horloges[i].nom, e, horloges[i].attendu);
            bonnes = 0;
        }
    }
    verifier(bonnes, "clock_nanosleep : ce que rend chaque horloge");
    struct timespec faux = { 0, 1000000000 }, negatif = { -1, 0 };
    errno = 0;
    long r1 = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &faux, NULL);
    int e1 = errno;
    errno = 0;
    long r2 = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &negatif, NULL);
    int e2 = errno;
    errno = 0;
    long r3 = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, (void *)8, NULL);
    int e3 = errno;
    errno = 0;
    long r4 = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC_RAW, 0, (void *)8, NULL);
    int e4 = errno;
    verifier(r1 == -1 && e1 == EINVAL && r2 == -1 && e2 == EINVAL && r3 == -1 && e3 == EFAULT && r4 == -1 && e4 == EOPNOTSUPP,
             "clock_nanosleep : duree invalide EINVAL, illisible EFAULT, horloge verifiee avant");
    /* Une échéance absolue sur MONOTONIC, 20 ms plus loin, avec un drapeau
     * inconnu (ignoré) ; puis sur REALTIME. */
    clock_gettime(CLOCK_MONOTONIC, &avant);
    struct timespec echeance = avant;
    echeance.tv_nsec += 20000000;
    if (echeance.tv_nsec >= 1000000000) {
        echeance.tv_sec++;
        echeance.tv_nsec -= 1000000000;
    }
    long r5 = syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME | 2, &echeance, NULL);
    clock_gettime(CLOCK_MONOTONIC, &apres);
    clock_gettime(CLOCK_REALTIME, &reel);
    struct timespec echeance_reelle = reel;
    echeance_reelle.tv_nsec += 20000000;
    if (echeance_reelle.tv_nsec >= 1000000000) {
        echeance_reelle.tv_sec++;
        echeance_reelle.tv_nsec -= 1000000000;
    }
    long r6 = syscall(SYS_clock_nanosleep, CLOCK_REALTIME, TIMER_ABSTIME, &echeance_reelle, NULL);
    struct timespec reel_apres;
    clock_gettime(CLOCK_REALTIME, &reel_apres);
    verifier(r5 == 0 && ns(apres) >= ns(echeance) && r6 == 0 && ns(reel_apres) >= ns(echeance_reelle),
             "clock_nanosleep : echeances absolues sur MONOTONIC et REALTIME, pas avant");

    printf("[linux] temps : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
