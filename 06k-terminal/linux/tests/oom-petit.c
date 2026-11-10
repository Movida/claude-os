/*
 * oom-petit (soldes d'avant 6k) : attend qu'oom-gros ait touché les trois
 * cinquièmes de la mémoire libre, puis en touche autant de ce qu'il en
 * reste : une page manque à sa faute. Le tueur OOM doit tuer oom-gros, le
 * plus gros, et sa faute recommencer : il finit, et le dit. Avant les
 * soldes, c'est lui qui était tué (le programme qui faute).
 */
#include <stdio.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    struct timespec ms = { 0, 1000000 };
    for (int i = 0; i < 20000 && access("/tmp/oom-gros.pret", F_OK) != 0; i++)
        nanosleep(&ms, NULL);
    unlink("/tmp/oom-gros.pret");
    struct sysinfo s;
    sysinfo(&s);
    /* Plus qu'il ne reste de libre, moins que ce que tient oom-gros. */
    size_t taille = (size_t)s.freeram * s.mem_unit / 2 * 3;
    char *p = mmap(NULL, taille, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) {
        printf("[linux] oom-petit : mmap : ECHEC\n");
        return 1;
    }
    for (size_t i = 0; i < taille; i += 4096)
        p[i] = 1;
    printf("[linux] oom-petit : plus de pages que la memoire libre, touchees apres la mort du plus gros : ok\n");
    return 0;
}
