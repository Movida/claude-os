/* Attendre sans délai un futex sur sa propre valeur : avec un seul fil, et
 * sans signal livré avant 6f, rien ne pourra jamais le réveiller. Linux le
 * laisserait bloqué pour toujours (sur l'hôte, ce programme ne finit pas) ;
 * notre noyau l'arrête et le dit (SIGKILL, code 137). */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    static uint32_t verrou = 1;
    puts("[linux] Test : futex WAIT sans delai, que personne ne reveillera.");
    fflush(stdout);
    syscall(SYS_futex, &verrou, FUTEX_WAIT_PRIVATE, 1, NULL, NULL, 0);
    puts("[linux] futex-sans-fin : ECHEC, reveille");
    return 1;
}
