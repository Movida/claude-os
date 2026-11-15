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
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
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

/* Les horloges de calcul encodées (posix-cpu-timers.c) : le pid ou le tid
 * complémenté, décalé de trois bits, le bit 2 pour un fil, la mesure dans
 * les bits 0 et 1 (PROF 0, VIRT 1, SCHED 2 ; 3 avec le bit 2 : aucune). Le
 * calcul en non signé : décaler un int négatif n'est pas défini en C. */
#define HORLOGE_PROCESSUS(pid, mesure) ((clockid_t)((~(unsigned)(pid) << 3) | (mesure)))
#define HORLOGE_FIL(tid, mesure) ((clockid_t)((~(unsigned)(tid) << 3) | 4 | (mesure)))
#define PROF 0
#define VIRT 1
#define SCHED 2

static void sur_alarme(int sig)
{
    (void)sig;
}

static long erreur(long r)
{
    return r == -1 ? -errno : r;
}

static long long lire(clockid_t c)
{
    struct timespec t;
    return clock_gettime(c, &t) == 0 ? ns(t) : -errno;
}

static void calculer(long long duree)
{
    long long debut = lire(CLOCK_THREAD_CPUTIME_ID);
    volatile unsigned long somme = 0;
    while (lire(CLOCK_THREAD_CPUTIME_ID) - debut < duree)
        for (int i = 0; i < 10000; i++)
            somme += i;
}

static atomic_int arreter;

static void *calculateur(void *rien)
{
    volatile unsigned long somme = 0;
    while (!atomic_load(&arreter))
        for (int i = 0; i < 10000; i++)
            somme += i;
    return rien;
}

/* Ce que la glibc fait des horloges de calcul : clock_getcpuclockid et
 * pthread_getcpuclockid les encodent (le premier les vérifie par
 * clock_getres), et clock_nanosleep passe -6 pour CLOCK_PROCESS_CPUTIME_ID
 * (mesuré par strace sous Linux 6.18) ; puis les mêmes par l'appel brut,
 * les horloges PROF et VIRT, celle d'un autre fil. */
static void horloges_de_calcul(void)
{
    clockid_t c = 0, c_pid = 0, c_fil = 0;
    long long avant = lire(CLOCK_PROCESS_CPUTIME_ID);
    int r = clock_getcpuclockid(0, &c);
    verifier(r == 0 && c == -6 && lire(c) >= avant, "clock_getcpuclockid(0) : -6, lue par clock_gettime");
    r = clock_getcpuclockid(getpid(), &c_pid);
    verifier(r == 0 && c_pid == HORLOGE_PROCESSUS(getpid(), SCHED) && lire(c_pid) >= avant,
             "clock_getcpuclockid(getpid()) : l'horloge du pid, lue");
    verifier(clock_getcpuclockid(0x0fffffff, &c) == ESRCH, "clock_getcpuclockid d'un pid qui n'existe pas : ESRCH");
    long long fil = lire(CLOCK_THREAD_CPUTIME_ID);
    r = pthread_getcpuclockid(pthread_self(), &c_fil);
    verifier(r == 0 && c_fil == HORLOGE_FIL(syscall(SYS_gettid), SCHED) && lire(c_fil) >= fil,
             "pthread_getcpuclockid : l'horloge du fil, lue");
    struct timespec zero = { 0, 0 }, res;
    verifier(clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, TIMER_ABSTIME, &zero, NULL) == 0,
             "clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID) par la glibc (-6) : echeance passee, 0");

    long n1 = erreur(syscall(SYS_clock_nanosleep, HORLOGE_FIL(0, SCHED), TIMER_ABSTIME, &zero, NULL));
    long n2 = erreur(syscall(SYS_clock_nanosleep, c_fil, TIMER_ABSTIME, &zero, NULL));
    long n3 = erreur(syscall(SYS_clock_nanosleep, HORLOGE_PROCESSUS(0, PROF), TIMER_ABSTIME, &zero, NULL));
    long n4 = erreur(syscall(SYS_clock_nanosleep, HORLOGE_PROCESSUS(0, 3), TIMER_ABSTIME, &zero, NULL));
    long n5 = erreur(syscall(SYS_clock_nanosleep, HORLOGE_FIL(0, 3), TIMER_ABSTIME, &zero, NULL));
    long n6 = erreur(syscall(SYS_clock_nanosleep, HORLOGE_PROCESSUS(0x0fffffff, SCHED), TIMER_ABSTIME, &zero, NULL));
    verifier(n1 == -EINVAL && n2 == -EINVAL && n3 == 0 && n4 == -EOPNOTSUPP && n5 == -EINVAL && n6 == -EINVAL,
             "clock_nanosleep : son propre fil EINVAL, PROF 0, descripteur EOPNOTSUPP, mesure 3 et pid absent EINVAL");
    long g1 = erreur(syscall(SYS_clock_getres, HORLOGE_PROCESSUS(0, 3), &res));
    long g2 = erreur(syscall(SYS_clock_getres, HORLOGE_FIL(0, 3), &res));
    long g3 = erreur(syscall(SYS_clock_gettime, HORLOGE_FIL(0, 3), &res));
    long g4 = erreur(syscall(SYS_clock_gettime, HORLOGE_PROCESSUS(0x0fffffff, SCHED), &res));
    long g5 = erreur(syscall(SYS_clock_gettime, HORLOGE_FIL(0x0fffffff, SCHED), &res));
    verifier(g1 == -EINVAL && g2 == -EINVAL && g3 == -EINVAL && g4 == -EINVAL && g5 == -EINVAL,
             "clock_getres et clock_gettime : descripteur, mesure 3, pid ou tid absent : EINVAL");

    /* PROF et VIRT : comptées au tic (sa durée : 1 ms chez nous, 4 ms sous
     * le Linux de WSL, HZ 250) ; PROF au moins VIRT, et elles avancent. */
    struct timespec res_prof = { 0, 0 }, res_virt = { 0, 0 };
    clock_getres(HORLOGE_PROCESSUS(0, PROF), &res_prof);
    clock_getres(HORLOGE_FIL(0, VIRT), &res_virt);
    verifier(res_prof.tv_sec == 0 && res_prof.tv_nsec == res_virt.tv_nsec && res_prof.tv_nsec >= 1000000
             && res_prof.tv_nsec <= 10000000, "PROF et VIRT : la finesse d'un tic");
    long long virt = lire(HORLOGE_PROCESSUS(0, VIRT)), prof = lire(HORLOGE_PROCESSUS(0, PROF));
    long long virt_fil = lire(HORLOGE_FIL(0, VIRT)), prof_fil = lire(HORLOGE_FIL(0, PROF));
    calculer(50000000);
    long long prof_apres = lire(HORLOGE_PROCESSUS(0, PROF)), prof_fil_apres = lire(HORLOGE_FIL(0, PROF));
    verifier(virt >= 0 && prof >= virt && virt_fil >= 0 && prof_fil >= virt_fil && prof_apres > prof && prof_fil_apres > prof_fil,
             "PROF au moins VIRT, et PROF avance avec le calcul, du processus et du fil");

    /* Un autre fil, qui calcule : son horloge se lit, et on dort sur elle
     * (relatif, 20 ms de son calcul), puis sur celle du processus par la
     * glibc (10 ms), puis sur PROF du fil ; finie, elle n'est plus. */
    pthread_t autre;
    pthread_create(&autre, NULL, calculateur, NULL);
    clockid_t c_autre;
    pthread_getcpuclockid(autre, &c_autre);
    struct timespec vingt = { 0, 20000000 }, dix = { 0, 10000000 };
    long long a0 = lire(c_autre);
    long s1 = erreur(syscall(SYS_clock_nanosleep, c_autre, 0, &vingt, NULL));
    long long a1 = lire(c_autre);
    long long p0 = lire(CLOCK_PROCESS_CPUTIME_ID);
    int s2 = clock_nanosleep(CLOCK_PROCESS_CPUTIME_ID, 0, &dix, NULL);
    long long p1 = lire(CLOCK_PROCESS_CPUTIME_ID);
    clockid_t c_autre_prof = (c_autre & ~3) | PROF;
    long long q0 = lire(c_autre_prof);
    long s3 = erreur(syscall(SYS_clock_nanosleep, c_autre_prof, 0, &dix, NULL));
    long long q1 = lire(c_autre_prof);
    verifier(a0 >= 0 && s1 == 0 && a1 - a0 >= 20000000 && s2 == 0 && p1 - p0 >= 10000000 && s3 == 0 && q1 - q0 >= 10000000,
             "dormir sur l'horloge d'un autre fil (SCHED, PROF) et sur celle du processus");
    atomic_store(&arreter, 1);
    pthread_join(autre, NULL);
    /* Fini, son horloge n'est plus ; sous Linux, pas tout de suite.
     * pthread_join revient dès que le fil a effacé son tid et réveillé
     * qui l'attend (CLONE_CHILD_CLEARTID : mm_release, au début de
     * do_exit), et le fil ne quitte la table des pid qu'à la fin
     * (release_task, depuis exit_notify) : entre les deux, son horloge se
     * lit encore (vu une fois sous le Linux de référence, la machine
     * chargée). On la relit donc jusqu'à EINVAL, une seconde au plus. */
    int fini = 0;
    for (int i = 0; i < 1000 && !(fini = lire(c_autre) == -EINVAL); i++)
        usleep(1000);
    verifier(fini, "l'horloge d'un fil fini : EINVAL");
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
    /* Sur l'hôte, time() lit l'horloge grossière (le vDSO,
     * CLOCK_REALTIME_COARSE, en retard d'un tic au plus) : juste après un
     * changement de seconde, il peut encore dire la précédente. */
    verifier(r == t && r - reel.tv_sec <= 1 && r >= reel.tv_sec - 1, "time d'accord avec CLOCK_REALTIME");

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

    horloges_de_calcul();

    /* Une durée énorme, interrompue : le reste dit où l'échéance a été
     * ramenée, au KTIME_MAX (292 ans) de la base de l'attente : TAI dort
     * dans la sienne, REALTIME relatif dans MONOTONIC (mesuré). */
    struct sigaction rien = { 0 };
    rien.sa_handler = sur_alarme;
    sigaction(SIGALRM, &rien, NULL);
    clockid_t enormes[] = { CLOCK_MONOTONIC, CLOCK_REALTIME, CLOCK_TAI }, bases[] = { CLOCK_MONOTONIC, CLOCK_MONOTONIC, CLOCK_TAI };
    int bornees = 1;
    for (int k = 0; k < 3; k++) {
        struct timespec enorme = { INT64_MAX, 0 }, reste = { 0, 0 };
        ualarm(20000, 0);
        int r = clock_nanosleep(enormes[k], 0, &enorme, &reste);
        clock_gettime(bases[k], &apres);
        long long attendu = INT64_MAX / 1000000000 - apres.tv_sec;
        if (r != EINTR || reste.tv_sec < attendu - 1 || reste.tv_sec > attendu + 1) {
            printf("[linux] temps : clock_nanosleep(%d) de LONG_MAX s : %d, reste %lld au lieu de %lld\n", enormes[k], r, (long long)reste.tv_sec, attendu);
            bornees = 0;
        }
    }
    verifier(bornees, "clock_nanosleep de LONG_MAX s, interrompu : le reste jusqu'a KTIME_MAX de sa base");

    printf("[linux] temps : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
