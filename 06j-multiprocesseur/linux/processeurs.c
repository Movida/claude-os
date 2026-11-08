/* processeurs : ce qu'un programme voit des processeurs (6j), chez nous
 * comme sous Linux : combien il y en a (get_nprocs, /sys/devices/system/
 * cpu/online), sur lesquels il a le droit de tourner (sched_getaffinity),
 * et le droit de le restreindre (sched_setaffinity), avec les refus de
 * Linux ; où il tourne (getcpu, sched_getcpu).
 *
 * Chez nous, à ce commit, sched_setaffinity est gardé mais pas encore
 * honoré : un fil peut encore tourner sur un processeur qu'il a exclu
 * (le placement des tâches vient avec la file des prêtes par processeur).
 * Sur l'hôte, il l'est : sched_getcpu dit le processeur demandé. Compilé
 * avec gcc -static ; sur l'hôte aussi (make tests-hote). */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

static int echecs;
static int chez_nous;

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

int main(void)
{
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
    if (!chez_nous)
        verifier(sched_yield() == 0 && sched_getcpu() == premier, "sur l'hote : sched_getcpu dit le processeur demande");

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

    printf("[linux] processeurs : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
