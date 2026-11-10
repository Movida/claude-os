/*
 * oom-gros (soldes d'avant 6k) : le plus gros de deux programmes quand la
 * mémoire manque. Touche les trois cinquièmes de la mémoire libre, le dit
 * dans /tmp/oom-gros.pret, puis attend : oom-petit, lancé après lui, touche
 * à son tour plus qu'il ne reste ; le tueur OOM doit le choisir, lui, le
 * plus gros (`oom_badness`), et laisser finir oom-petit. Lancé par `&`
 * (tests-demarrage.txt) ; jamais sur l'hôte, dont il ferait tuer d'autres
 * programmes.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>

int main(void)
{
    struct sysinfo s;
    sysinfo(&s);
    size_t taille = (size_t)s.freeram * s.mem_unit / 5 * 3;
    char *p = mmap(NULL, taille, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("[linux] oom-gros : mmap : ECHEC\n");
        return 1;
    }
    for (size_t i = 0; i < taille; i += 4096)
        p[i] = 1;
    printf("[linux] oom-gros : %zu Mio touches, j'attends\n", taille >> 20);
    fflush(stdout);
    close(open("/tmp/oom-gros.pret", O_WRONLY | O_CREAT, 0600));
    for (;;)
        pause();
}
