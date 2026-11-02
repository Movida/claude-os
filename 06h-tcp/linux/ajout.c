/*
 * Deux programmes qui ajoutent au même fichier (O_APPEND) en même temps
 * ne doivent rien perdre (6e) : « ajout ecrire <nom> <n> », lancé deux
 * fois par `&`, ajoute n lignes longues (2000 octets, sur plusieurs pages)
 * à /tmp/ajout/texte, une par write, après un rendez-vous avec l'autre ;
 * « ajout verifier <n> » attend qu'ils aient fini, puis vérifie que le
 * fichier a exactement n lignes de chacun, toutes entières, et efface
 * tout (les trois tournent ensemble : la mémoire que gardait le fichier
 * est rendue quand le dernier finit). Sans le verrou d'écriture de
 * l'inode, deux écritures qui lisent la même fin s'écraseraient. Sur
 * l'hôte aussi.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define LONGUEUR 2000
/* Dans un dossier à eux, effacé à la fin : la liste des entrées de /tmp,
 * qui garde sa place une fois agrandie (tant qu'il n'est pas vide), ne
 * grandit pas pour eux, et « memoire rendue » reste juste. */
#define DOSSIER "/tmp/ajout"
#define FICHIER DOSSIER "/texte"

static void ligne(char *l, char nom, int i)
{
    memset(l, nom, LONGUEUR - 1);
    snprintf(l, 16, "%c %06d ", nom, i);
    l[strlen(l)] = nom;
    l[LONGUEUR - 1] = '\n';
}

int main(int argc, char **argv)
{
    static char l[LONGUEUR], lu[LONGUEUR];
    if (argc == 4 && strcmp(argv[1], "ecrire") == 0) {
        char nom = argv[2][0], moi[64], autre[64];
        int n = atoi(argv[3]);
        snprintf(moi, sizeof moi, DOSSIER "/pret-%c", nom);
        snprintf(autre, sizeof autre, DOSSIER "/pret-%c", nom == 'a' ? 'b' : 'a');
        mkdir(DOSSIER, 0777);
        int fd = open(FICHIER, O_CREAT | O_WRONLY | O_APPEND, 0644);
        close(open(moi, O_CREAT | O_WRONLY, 0644));
        struct timespec ms = { 0, 1000000 };
        for (int i = 0; i < 10000 && access(autre, F_OK) != 0; i++)
            nanosleep(&ms, NULL);
        int faits = 0;
        for (int i = 0; i < n; i++) {
            ligne(l, nom, i);
            faits += write(fd, l, LONGUEUR) == LONGUEUR;
        }
        close(fd);
        printf("[linux] ajout %c : %d lignes ecrites : %s\n", nom, n, faits == n ? "ok" : "ECHEC");
        snprintf(moi, sizeof moi, DOSSIER "/fini-%c", nom);
        close(open(moi, O_CREAT | O_WRONLY, 0644));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "verifier") == 0) {
        int n = atoi(argv[2]), vus[2] = { 0, 0 }, mauvaises = 0;
        struct timespec ms = { 0, 1000000 };
        for (int i = 0; i < 100000 && (access(DOSSIER "/fini-a", F_OK) != 0 || access(DOSSIER "/fini-b", F_OK) != 0); i++)
            nanosleep(&ms, NULL);
        int fd = open(FICHIER, O_RDONLY);
        while (read(fd, lu, LONGUEUR) == LONGUEUR) {
            char nom = lu[0];
            int i = atoi(lu + 2);
            ligne(l, nom, i);
            if ((nom != 'a' && nom != 'b') || memcmp(l, lu, LONGUEUR) != 0 || i != vus[nom - 'a'])
                mauvaises++;
            else
                vus[nom - 'a']++;
        }
        close(fd);
        unlink(FICHIER);
        unlink(DOSSIER "/pret-a");
        unlink(DOSSIER "/pret-b");
        unlink(DOSSIER "/fini-a");
        unlink(DOSSIER "/fini-b");
        rmdir(DOSSIER);
        printf("[linux] ajout : %d lignes de chacun, entieres et dans l'ordre : %s\n", n,
               vus[0] == n && vus[1] == n && mauvaises == 0 ? "ok" : "ECHEC");
        return 0;
    }
    printf("[linux] ajout : usage : ajout ecrire <a|b> <n> | ajout verifier <n>\n");
    return 2;
}
