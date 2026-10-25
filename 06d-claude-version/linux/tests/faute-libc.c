/*
 * Un programme dynamique qui fait une faute DANS la glibc partagée :
 * strlen sur un pointeur nul. Le noyau doit l'arrêter (SIGSEGV, code de
 * sortie 139) en nommant le fichier de la zone où était RIP : libc.so.6,
 * projetée par ld-linux (make tests-qemu).
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    /* volatile : sinon gcc voit le pointeur nul, et refuse de compiler
     * (-Werror=nonnull), ou remplace l'appel par un piège. */
    const char *volatile rien = NULL;
    printf("[linux] faute-libc : strlen(NULL), dans la glibc partagee.\n");
    fflush(stdout);
    return (int)strlen(rien);
}
