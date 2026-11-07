/*
 * Le dossier courant d'un programme lancé (6i) : `cd` dans /etc/demarrage
 * change celui des commandes suivantes, et, comme dash, leur donne PWD (le
 * chemin de `cd`, en forme simple) et OLDPWD (le précédent). Lancé par
 *     dossier GETCWD PWD OLDPWD
 * il vérifie son getcwd() et ces deux variables (« * » : ne pas regarder).
 * Il tourne dans notre noyau et sur l'hôte.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int ecarts;

static void comparer(const char *quoi, const char *lu, const char *attendu)
{
    if (strcmp(attendu, "*") == 0)
        return;
    if (lu == NULL || strcmp(lu, attendu) != 0) {
        printf("[linux] dossier : %s = %s, %s attendu : ECHEC\n", quoi, lu ? lu : "(absent)", attendu);
        ecarts++;
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 4) {
        printf("[linux] dossier : usage : dossier GETCWD PWD OLDPWD : ECHEC\n");
        return 1;
    }
    char ici[4096];
    comparer("getcwd", getcwd(ici, sizeof ici), argv[1]);
    comparer("PWD", getenv("PWD"), argv[2]);
    comparer("OLDPWD", getenv("OLDPWD"), argv[3]);
    if (ecarts == 0)
        printf("[linux] dossier : getcwd = %s, PWD = %s, OLDPWD = %s : ok\n", argv[1], argv[2], argv[3]);
    return ecarts != 0;
}
