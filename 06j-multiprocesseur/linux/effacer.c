/*
 * Efface des fichiers et des dossiers, comme `rm -rf` (6i) : pour qu'un
 * groupe de /etc/demarrage rende toute sa mémoire, ce qu'un programme a
 * laissé dans le système de fichiers (claude : sa configuration, sa
 * conversation) est effacé à la fin du groupe ; le lanceur vérifie alors que
 * la mémoire libre est revenue, à la page près.
 *     effacer CHEMIN...           efface chaque chemin, et ce qu'il contient
 *                                 (un chemin absent n'est pas une erreur)
 *     effacer --contenu DOSSIER   efface ce que contient le dossier, et le
 *                                 garde
 *     effacer --creer DOSSIER N   crée le dossier, N fichiers de tailles
 *                                 croissantes (de 0 à N - 1 pages et
 *                                 quelques octets) et un sous-dossier : de
 *                                 quoi l'essayer
 * Chaque effacement est fait du plus profond au plus haut (nftw, FTW_DEPTH),
 * sans suivre les liens (FTW_PHYS) : un lien est effacé, pas sa cible.
 * Il tourne dans notre noyau et sur l'hôte.
 */
#define _XOPEN_SOURCE 700
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int echecs;
static int garder_la_racine;

static int effacer_un(const char *chemin, const struct stat *st, int genre, struct FTW *ou)
{
    (void)st;
    (void)genre;
    if (ou->level == 0 && garder_la_racine)
        return 0;
    if (remove(chemin) != 0) {
        printf("[linux] effacer : %s : errno %d : ECHEC\n", chemin, errno);
        echecs++;
    }
    return 0;
}

static void effacer(const char *chemin)
{
    struct stat st;
    if (lstat(chemin, &st) != 0 && errno == ENOENT)
        return;
    if (nftw(chemin, effacer_un, 16, FTW_DEPTH | FTW_PHYS) != 0) {
        printf("[linux] effacer : %s : parcours impossible (errno %d) : ECHEC\n", chemin, errno);
        echecs++;
    }
}

static int creer(const char *dossier, int n)
{
    char chemin[4096];
    if (mkdir(dossier, 0755) != 0 && errno != EEXIST)
        return 1;
    snprintf(chemin, sizeof chemin, "%s/sous-dossier", dossier);
    if (mkdir(chemin, 0755) != 0 && errno != EEXIST)
        return 1;
    static char page[4096];
    memset(page, 'x', sizeof page);
    for (int i = 0; i < n; i++) {
        snprintf(chemin, sizeof chemin, "%s/%s/fichier-%d", dossier, i % 2 ? "sous-dossier" : ".", i);
        int fd = open(chemin, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0)
            return 1;
        for (int p = 0; p < i; p++)
            if (write(fd, page, sizeof page) != (ssize_t)sizeof page)
                return 1;
        if (write(fd, "fin\n", 4) != 4)
            return 1;
        close(fd);
    }
    printf("[linux] effacer : %s cree, %d fichiers : ok\n", dossier, n);
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 4 && strcmp(argv[1], "--creer") == 0)
        return creer(argv[2], atoi(argv[3]));
    if (argc == 3 && strcmp(argv[1], "--contenu") == 0) {
        garder_la_racine = 1;
        effacer(argv[2]);
        /* Le dossier reste, vide : rien d'autre que . et .. */
        int entrees = -1;
        DIR *d = opendir(argv[2]);
        if (d) {
            struct dirent *e;
            entrees = 0;
            while ((e = readdir(d)))
                entrees += strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
            closedir(d);
        }
        if (echecs == 0 && entrees == 0)
            printf("[linux] effacer : %s vide : ok\n", argv[2]);
        else if (echecs == 0)
            printf("[linux] effacer : %s : %d entrees restent : ECHEC\n", argv[2], entrees);
        return echecs != 0 || entrees != 0;
    }
    if (argc < 2) {
        printf("[linux] effacer : usage : effacer CHEMIN..., --contenu DOSSIER, ou --creer DOSSIER N : ECHEC\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        effacer(argv[i]);
        struct stat st;
        if (lstat(argv[i], &st) == 0) {
            printf("[linux] effacer : %s existe encore : ECHEC\n", argv[i]);
            echecs++;
        } else if (echecs == 0) {
            printf("[linux] effacer : %s efface : ok\n", argv[i]);
        }
    }
    return echecs != 0;
}
