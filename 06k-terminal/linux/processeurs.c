/* processeurs : ce qu'un programme voit des processeurs (6j), chez nous
 * comme sous Linux : combien il y en a (get_nprocs, /sys/devices/system/
 * cpu/online), sur lesquels il a le droit de tourner (sched_getaffinity),
 * et le droit de le restreindre (sched_setaffinity), avec les refus de
 * Linux ; où il tourne (getcpu, sched_getcpu).
 *
 * Et des fils épinglés chacun sur un processeur (quatre au plus), qui
 * calculent en vérifiant sans cesse par getcpu qu'ils y sont : l'affinité
 * est honorée par le placement des tâches (la file des prêtes par
 * processeur). Puis un fil déplacé par sched_setaffinity vers un
 * processeur où un autre calcule : il doit s'y exécuter en moins de 100 ms,
 * que ce soit lui qui change son masque pendant qu'il s'exécute (son
 * processeur le pousse dès qu'il l'a quitté) ou un autre fil qui change le
 * sien pendant qu'il est prêt ou en cours (la relecture de 6j l'a vu
 * attendre que la destination n'ait plus rien à faire : 300 ms ici).
 * Compilé avec gcc -static ; sur l'hôte aussi (make tests-hote), adapté au
 * nombre de processeurs de la machine.
 *
 * Avec l'argument « boucle » (make tests-qemu, le scénario du NMI) : deux
 * fils épinglés sur les processeurs 1 et 2 qui bouclent sur getpid pour
 * toujours (l'anneau 3, l'entrée et la sortie de syscall : là où un NMI
 * trouve la base de GS du programme active dans le noyau), les autres
 * processeurs inactifs ; le programme dit quand ils tournent, puis attend. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

static int echecs;
static int chez_nous;

/* Un fil épinglé sur le processeur de son argument : 100 ms de calcul, et
 * à chaque tour (un sched_yield), là où il tourne doit être ce processeur.
 * Rend le nombre de tours où ce n'était pas le cas. */
static void *epingle(void *arg)
{
    int cpu = (int)(long)arg;
    cpu_set_t c;
    CPU_ZERO(&c);
    CPU_SET(cpu, &c);
    if (pthread_setaffinity_np(pthread_self(), sizeof c, &c) != 0)
        return (void *)-1L;
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    long fin = t.tv_sec * 1000 + t.tv_nsec / 1000000 + 100, ailleurs = 0;
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t);
        if (t.tv_sec * 1000 + t.tv_nsec / 1000000 >= fin)
            break;
        for (volatile int i = 0; i < 1000; i++)
            ;
        if (sched_getcpu() != cpu)
            ailleurs++;
        sched_yield();
    }
    return (void *)ailleurs;
}

static void *boucleur(void *arg)
{
    cpu_set_t c;
    CPU_ZERO(&c);
    CPU_SET((int)(long)arg, &c);
    pthread_setaffinity_np(pthread_self(), sizeof c, &c);
    for (;;)
        syscall(SYS_getpid);
    return NULL;
}

static int boucler(void)
{
    pthread_t fils[2];
    for (int i = 0; i < 2; i++)
        pthread_create(&fils[i], NULL, boucleur, (void *)(long)(i + 1));
    printf("[linux] processeurs : 2 fils bouclent sur getpid, processeurs 1 et 2\n");
    fflush(stdout);
    pause();
    return 0;
}

static long ms_monotone(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void epingler_sur(int cpu)
{
    cpu_set_t c;
    CPU_ZERO(&c);
    CPU_SET(cpu, &c);
    pthread_setaffinity_np(pthread_self(), sizeof c, &c);
}

/* Le test du déplacement : d'où part le fil, où il doit arriver, et le
 * temps qu'il a mis à s'y voir (-1 : jamais). */
struct deplacement {
    int depart, arrivee;
    volatile long delai_ms;
};

/* Un fil qui calcule 300 ms sur le processeur de son argument : il occupe
 * l'arrivée, ou dispute le départ. */
static void *calculeur(void *arg)
{
    epingler_sur((int)(long)arg);
    long fin = ms_monotone() + 300;
    while (ms_monotone() < fin)
        for (volatile int i = 0; i < 1000; i++)
            ;
    return NULL;
}

/* Le migrant : sur son départ, il change lui-même son masque vers
 * l'arrivée, et mesure le temps jusqu'à s'y voir. */
static void *migrant(void *arg)
{
    struct deplacement *d = arg;
    epingler_sur(d->depart);
    sched_yield();
    long debut = ms_monotone();
    epingler_sur(d->arrivee);
    d->delai_ms = -1;
    while (ms_monotone() - debut < 1000) {
        for (volatile int i = 0; i < 1000; i++)
            ;
        if (sched_getcpu() == d->arrivee) {
            d->delai_ms = ms_monotone() - debut;
            break;
        }
    }
    return NULL;
}

/* Le déplacé : il calcule sur son départ (qu'un rival lui dispute : il y
 * est tantôt en cours, tantôt prêt) ; c'est le fil principal qui change
 * son masque, et note l'instant (top_deplacement). */
static volatile long top_deplacement;

static void *deplace(void *arg)
{
    struct deplacement *d = arg;
    epingler_sur(d->depart);
    long fin = ms_monotone() + 600;
    d->delai_ms = -1;
    while (ms_monotone() < fin) {
        for (volatile int i = 0; i < 1000; i++)
            ;
        long top = __atomic_load_n(&top_deplacement, __ATOMIC_ACQUIRE);
        if (top && sched_getcpu() == d->arrivee) {
            d->delai_ms = ms_monotone() - top;
            break;
        }
    }
    return NULL;
}

static void verifier(int ok, const char *quoi)
{
    printf("[linux] processeurs : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Le numéro d'erreur d'un appel système brut (0 s'il a réussi). */
static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

/* Le nombre de processeurs d'une liste de Linux (« 0-3 », « 0,2-3 »). */
static int compter(const char *liste)
{
    int n = 0;
    while (*liste && *liste != '\n') {
        char *fin;
        long a = strtol(liste, &fin, 10), b = a;
        if (*fin == '-')
            b = strtol(fin + 1, &fin, 10);
        n += b - a + 1;
        liste = *fin == ',' ? fin + 1 : fin;
    }
    return n;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "boucle") == 0)
        return boucler();
    chez_nous = access("/etc/bonjour.txt", F_OK) == 0;

    /* Combien : get_nprocs lit /sys/devices/system/cpu/online. */
    char online[64] = { 0 };
    FILE *f = fopen("/sys/devices/system/cpu/online", "r");
    verifier(f && fgets(online, sizeof online, f), "/sys/devices/system/cpu/online : lisible");
    if (f)
        fclose(f);
    int n = get_nprocs();
    verifier(n >= 1 && compter(online) == n, "get_nprocs : le nombre de processeurs de cpu/online");
    if (chez_nous)
        verifier(n == 4 && !strcmp(online, "0-3\n"), "chez nous : quatre processeurs, 0-3");

    /* Où l'on a le droit de tourner : au moins un processeur, tous parmi
       ceux de la machine (sur l'hôte, un cgroup ou taskset peuvent en
       retirer : on ne demande pas tous). */
    unsigned long initial = 0;
    verifier(syscall(SYS_sched_getaffinity, 0, sizeof initial, &initial) == 8 && initial != 0,
             "sched_getaffinity : 8 octets, au moins un processeur");
    int tous = 1;
    for (int i = 0; i < 64; i++)
        if (initial >> i & 1 && i >= n)
            tous = 0;
    verifier(tous, "sched_getaffinity : seulement des processeurs de la machine");
    if (chez_nous)
        verifier(initial == 0x0f, "chez nous : les quatre processeurs");

    /* Se restreindre à un seul processeur, le premier permis : accepté,
       relu tel quel ; sur l'hôte, c'est là qu'on tourne ensuite. */
    int premier = 0;
    while (!(initial >> premier & 1))
        premier++;
    unsigned long seul = 1UL << premier, relu = 0;
    verifier(syscall(SYS_sched_setaffinity, 0, sizeof seul, &seul) == 0, "sched_setaffinity : un seul processeur");
    verifier(syscall(SYS_sched_getaffinity, 0, sizeof relu, &relu) == 8 && relu == seul,
             "sched_getaffinity : le masque pose, relu tel quel");
    unsigned c = 99, noeud = 99;
    verifier(syscall(SYS_getcpu, &c, &noeud, NULL) == 0 && (int)c < n, "getcpu : un processeur de la machine");
    verifier(sched_getcpu() >= 0 && sched_getcpu() < n, "sched_getcpu : un processeur de la machine");
    /* Le fil tourne là où on l'a épinglé : au plus tard après avoir cédé
       le processeur (chez nous, le processeur permis le tire ; sur l'hôte,
       sched_setaffinity l'y déplace lui-même). */
    verifier(sched_yield() == 0 && sched_getcpu() == premier, "sched_getcpu dit le processeur demande");

    /* Les bits des processeurs absents sont gardés tels quels, et
       sched_getaffinity ne rend que ceux de la machine (Linux : cpus_mask
       tel que demandé, restreint à cpu_active_mask à la lecture). */
    if (n < 63) {
        unsigned long large = seul | 1UL << 63;
        verifier(syscall(SYS_sched_setaffinity, 0, sizeof large, &large) == 0
                     && syscall(SYS_sched_getaffinity, 0, sizeof relu, &relu) == 8 && relu == seul,
                 "un masque avec un processeur absent : accepte, le present seul relu");
    }
    /* Les refus : aucun processeur de la machine (EINVAL) ; une longueur
       nulle vaut un masque vide (EINVAL) ; une longueur courte est lue
       telle quelle, les octets manquants a zero (le premier octet suffit
       pour le processeur `premier` s'il est sous 8) ; un fil qui n'existe
       pas (ESRCH) ; une adresse invalide (EFAULT). */
    unsigned long vide = 0, haut = n < 63 ? 1UL << 63 : 0;
    verifier(erreur(syscall(SYS_sched_setaffinity, 0, sizeof vide, &vide)) == EINVAL, "un masque vide : EINVAL");
    if (n < 63)
        verifier(erreur(syscall(SYS_sched_setaffinity, 0, sizeof haut, &haut)) == EINVAL,
                 "un masque sans processeur de la machine : EINVAL");
    verifier(erreur(syscall(SYS_sched_setaffinity, 0, 0, &seul)) == EINVAL, "une longueur nulle : EINVAL");
    if (premier < 8)
        verifier(syscall(SYS_sched_setaffinity, 0, 1, &seul) == 0
                     && syscall(SYS_sched_getaffinity, 0, sizeof relu, &relu) == 8 && relu == seul,
                 "une longueur d'un octet : lue telle quelle");
    verifier(erreur(syscall(SYS_sched_setaffinity, 2147483000, sizeof seul, &seul)) == ESRCH,
             "un fil qui n'existe pas : ESRCH");
    verifier(erreur(syscall(SYS_sched_setaffinity, 0, sizeof seul, (void *)8)) == EFAULT, "a une adresse invalide : EFAULT");

    /* Le masque initial rendu. */
    verifier(syscall(SYS_sched_setaffinity, 0, sizeof initial, &initial) == 0
                 && syscall(SYS_sched_getaffinity, 0, sizeof relu, &relu) == 8 && relu == initial,
             "le masque initial rendu");

    /* Des fils épinglés, un par processeur permis (quatre au plus), qui
       calculent 100 ms chacun : aucun ne doit se voir ailleurs. */
    pthread_t fils[4];
    int cpus[4], nf = 0;
    for (int i = 0; i < 64 && nf < 4; i++)
        if (initial >> i & 1)
            cpus[nf++] = i;
    for (int i = 0; i < nf; i++)
        pthread_create(&fils[i], NULL, epingle, (void *)(long)cpus[i]);
    long ailleurs = 0;
    for (int i = 0; i < nf; i++) {
        void *r;
        pthread_join(fils[i], &r);
        ailleurs += (long)r < 0 ? 1000000 : (long)r;
    }
    char quoi[96];
    snprintf(quoi, sizeof quoi, "%d fils epingles chacun sur son processeur, 100 ms : jamais vus ailleurs", nf);
    verifier(ailleurs == 0, quoi);
    if (chez_nous)
        verifier(nf == 4, "chez nous : quatre fils, un par processeur");

    /* Le déplacement (voir l'en-tête) : quatre processeurs permis au moins ;
       le calculeur occupe le troisième, le migrant part du deuxième, le
       déplacé et son rival se disputent le quatrième. */
    if (nf < 4) {
        printf("[linux] processeurs : deplacement par sched_setaffinity : moins de quatre processeurs permis, rien a mesurer\n");
    } else {
        pthread_t calc, mig, dep, rival;
        struct deplacement m = { cpus[1], cpus[2], 0 }, d = { cpus[3], cpus[2], 0 };
        pthread_create(&calc, NULL, calculeur, (void *)(long)cpus[2]);
        pthread_create(&mig, NULL, migrant, &m);
        pthread_join(mig, NULL);
        pthread_join(calc, NULL);
        verifier(m.delai_ms >= 0 && m.delai_ms < 100, "un fil qui change son masque vers un processeur occupe s'y execute en moins de 100 ms");
        pthread_create(&calc, NULL, calculeur, (void *)(long)cpus[2]);
        pthread_create(&rival, NULL, calculeur, (void *)(long)cpus[3]);
        pthread_create(&dep, NULL, deplace, &d);
        struct timespec attente = { 0, 50 * 1000000 };
        nanosleep(&attente, NULL);
        cpu_set_t vers;
        CPU_ZERO(&vers);
        CPU_SET(cpus[2], &vers);
        __atomic_store_n(&top_deplacement, ms_monotone(), __ATOMIC_RELEASE);
        pthread_setaffinity_np(dep, sizeof vers, &vers);
        pthread_join(dep, NULL);
        pthread_join(rival, NULL);
        pthread_join(calc, NULL);
        verifier(d.delai_ms >= 0 && d.delai_ms < 100, "un fil dont un autre change le masque vers un processeur occupe s'y execute en moins de 100 ms");
    }

    printf("[linux] processeurs : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
