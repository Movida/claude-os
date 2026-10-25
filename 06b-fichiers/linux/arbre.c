/*
 * Liste un dossier et ce qu'il contient, comme `ls -lR` en plus court :
 * pour chaque entrée, son type, ses droits, son propriétaire, sa taille,
 * et la cible d'un lien symbolique. Dans notre noyau, il montre ce que le
 * déballage de l'archive a mis dans /etc, /home et /dev (le jalon de 6b :
 * « liste un dossier »). Les entrées sont triées par nom pour l'affichage :
 * l'ordre de readdir, lui, est celui du système de fichiers.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int par_nom(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static void lister(const char *dossier, int profondeur)
{
    DIR *d = opendir(dossier);
    if (!d) {
        printf("[linux] arbre : %s illisible\n", dossier);
        return;
    }
    char *noms[64];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < 64)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            noms[n++] = strdup(e->d_name);
    closedir(d);
    qsort(noms, n, sizeof *noms, par_nom);
    for (int i = 0; i < n; i++) {
        char chemin[256];
        snprintf(chemin, sizeof chemin, "%s/%s", strcmp(dossier, "/") == 0 ? "" : dossier, noms[i]);
        struct stat st;
        if (lstat(chemin, &st) != 0)
            continue;
        char genre = S_ISDIR(st.st_mode) ? 'd' : S_ISLNK(st.st_mode) ? 'l' : S_ISCHR(st.st_mode) ? 'c' : '-';
        printf("[linux] arbre : %c %04o %4u %4u ", genre, st.st_mode & 07777, st.st_uid, st.st_gid);
        if (S_ISCHR(st.st_mode))
            printf("%3u, %3u", major(st.st_rdev), minor(st.st_rdev));
        else
            printf("%8lld", (long long)st.st_size);
        printf(" %s", chemin);
        if (S_ISLNK(st.st_mode)) {
            char cible[256] = {0};
            if (readlink(chemin, cible, sizeof cible - 1) > 0)
                printf(" -> %s", cible);
        }
        if (st.st_nlink > 1 && !S_ISDIR(st.st_mode))
            printf(" (%lu liens)", (unsigned long)st.st_nlink);
        printf("\n");
        if (S_ISDIR(st.st_mode) && profondeur < 3)
            lister(chemin, profondeur + 1);
        free(noms[i]);
    }
}

int main(void)
{
    lister("/etc", 0);
    lister("/home", 0);
    lister("/dev", 0);
    return 0;
}
