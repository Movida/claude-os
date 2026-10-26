/*
 * Envoyer un signal à un autre programme (6e) : attend le numéro de cible
 * (/tmp/cible.pid), vérifie que sched_getaffinity le connaît, puis lui
 * envoie SIGTERM.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    struct timespec ms = { 0, 1000000 };
    int fd = -1;
    for (int i = 0; i < 10000 && (fd = open("/tmp/cible.pid", O_RDONLY)) < 0; i++)
        nanosleep(&ms, NULL);
    char t[16] = { 0 };
    if (read(fd, t, sizeof t - 1) <= 0)
        return 1;
    close(fd);
    unlink("/tmp/cible.pid");
    pid_t cible = atoi(t);
    unsigned char masque[8];
    long r = syscall(SYS_sched_getaffinity, cible, sizeof masque, masque);
    int k = kill(cible, SIGTERM);
    printf("[linux] signaler : sched_getaffinity de cible, et SIGTERM envoye : %s\n", r == 8 && k == 0 ? "ok" : "ECHEC");
    return 0;
}
