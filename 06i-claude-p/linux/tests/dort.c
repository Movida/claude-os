/*
 * Dormir une seconde et demie (nanosleep), pendant que le clavier sert :
 * make tests-qemu envoie une touche dès qu'il voit la première ligne, et
 * vérifie que son écho (la tâche du clavier du noyau) s'affiche AVANT la
 * seconde. Sans ordonnanceur, sans files d'attente ni minuteries, le noyau
 * attendait dans le programme, et l'écho venait après.
 */
#include <stdio.h>
#include <time.h>

int main(void)
{
    printf("[linux] Test : dort 1,5 s.\n");
    fflush(stdout);
    struct timespec t = { 1, 500000000 };
    int r = nanosleep(&t, NULL);
    printf("[linux] dort : reveille (%d).\n", r);
    return 0;
}
