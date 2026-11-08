/*
 * Deux programmes qui calculent en même temps doivent se partager le
 * processeur (6e) : lancé deux fois par /etc/demarrage, l'un par `&`,
 * chacun attend l'autre (un rendez-vous par deux fichiers de /tmp : chacun
 * crée le sien, puis attend celui de l'autre en dormant), puis calcule
 * 200 ms de temps de calcul. Sur un seul processeur partagé équitablement,
 * son temps réel vaut environ deux fois son temps de calcul ; sans
 * préemption, l'un finirait avant que l'autre commence (rapport 1). Il ne
 * tourne que dans notre noyau : sur l'hôte, à plusieurs cœurs, chacun en
 * aurait un.
 */
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static long long ns(clockid_t h)
{
    struct timespec t;
    clock_gettime(h, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("[linux] partage : usage : partage <moi> <autre>\n");
        return 2;
    }
    char moi[64], autre[64];
    snprintf(moi, sizeof moi, "/tmp/partage-%s", argv[1]);
    snprintf(autre, sizeof autre, "/tmp/partage-%s", argv[2]);
    close(open(moi, O_CREAT | O_WRONLY, 0644));
    struct timespec ms = { 0, 1000000 };
    for (int i = 0; i < 10000 && access(autre, F_OK) != 0; i++)
        nanosleep(&ms, NULL);
    long long reel = ns(CLOCK_MONOTONIC), calcul = ns(CLOCK_PROCESS_CPUTIME_ID);
    volatile unsigned long somme = 0;
    while (ns(CLOCK_PROCESS_CPUTIME_ID) - calcul < 200000000)
        for (int i = 0; i < 10000; i++)
            somme += i;
    reel = ns(CLOCK_MONOTONIC) - reel;
    calcul = ns(CLOCK_PROCESS_CPUTIME_ID) - calcul;
    /* L'autre a vu ce fichier bien avant : 200 ms de calcul plus tôt. */
    unlink(moi);
    long rapport = (long)(reel * 10 / calcul);
    printf("[linux] partage %s : temps reel / temps de calcul entre 1,6 et 2,6 : %s\n", argv[1],
           rapport >= 16 && rapport <= 26 ? "ok" : "ECHEC");
    if (rapport < 16 || rapport > 26)
        printf("[linux] partage %s : rapport %ld,%ld\n", argv[1], rapport / 10, rapport % 10);
    return 0;
}
