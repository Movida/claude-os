/*
 * La cible d'un signal envoyé par un autre programme (6e) : lancée par
 * `&`, elle écrit son numéro dans /tmp/cible.pid, puis dort 10 s ; signaler
 * lui envoie SIGTERM, qui doit la réveiller et l'arrêter aussitôt.
 */
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    char t[16];
    int k = snprintf(t, sizeof t, "%d", getpid());
    int fd = open("/tmp/cible.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (write(fd, t, k) != k)
        return 1;
    close(fd);
    rename("/tmp/cible.tmp", "/tmp/cible.pid");
    printf("[linux] cible : dort 10 s.\n");
    fflush(stdout);
    struct timespec dix = { 10, 0 };
    nanosleep(&dix, NULL);
    printf("[linux] cible : reveillee sans signal : ECHEC\n");
    return 0;
}
