/*
 * Les redirections de /etc/demarrage (6i). Lancé par
 *     redirections CHEMIN0 CHEMIN3 < CHEMIN0 3< CHEMIN3
 * (par notre lanceur, ou par sh sur l'hôte), il vérifie que ses
 * descripteurs 0 et 3 sont ces fichiers (le même inode que les chemins qu'il
 * ouvre lui-même), en lecture seule, sans FD_CLOEXEC, au début du fichier,
 * et que 4 à 9 sont fermés. Puis, le fichier du 3 étant à lui, il lui
 * retire tous les droits (fchmod) : rouvrir /proc/self/fd/3 rend alors
 * EACCES (il faut le droit de lire le fichier, comme par un chemin : la
 * règle de Linux), mais le descripteur reste lisible. Il rend ensuite ses
 * droits au fichier.
 * Il tourne dans notre noyau et sur l'hôte (pas sous root : root lirait
 * le fichier sans droits).
 *
 *     redirections --ecrire CHEMIN MS
 *     redirections --dormir MS
 *
 * La première tient CHEMIN ouvert en écriture pendant MS millisecondes : un
 * programme qu'on lance alors est refusé (ETXTBSY), après que le lanceur a
 * ouvert ses redirections, qui doivent être refermées (un groupe de
 * /etc/demarrage le vérifie : « memoire rendue ») ; la seconde lui laisse
 * le temps de l'ouvrir, avant que la ligne suivante ne lance le programme.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int ecarts;

static void verifier(int ok, const char *quoi)
{
    if (!ok) {
        printf("[linux] redirections : %s : ECHEC (errno %d)\n", quoi, errno);
        ecarts++;
    }
}

/* Le descripteur `fd` est-il le fichier `chemin`, ouvert en lecture seule,
 * au début ? Rend vrai si oui. */
static int est(int fd, const char *chemin)
{
    struct stat a, b;
    if (fstat(fd, &a) != 0 || stat(chemin, &b) != 0)
        return 0;
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && (fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY
           && lseek(fd, 0, SEEK_CUR) == 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && strcmp(argv[1], "--dormir") == 0) {
        struct timespec t = {atoi(argv[2]) / 1000, atoi(argv[2]) % 1000 * 1000000L};
        nanosleep(&t, NULL);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--ecrire") == 0) {
        int f = open(argv[2], O_WRONLY);
        struct timespec t = {atoi(argv[3]) / 1000, atoi(argv[3]) % 1000 * 1000000L};
        nanosleep(&t, NULL);
        if (f >= 0)
            close(f);
        printf("[linux] redirections : %s tenu en ecriture : %s\n", argv[2], f >= 0 ? "ok" : "ECHEC");
        return f < 0;
    }
    if (argc != 3) {
        printf("[linux] redirections : usage : redirections CHEMIN0 CHEMIN3 < CHEMIN0 3< CHEMIN3 : ECHEC\n");
        return 1;
    }
    verifier(est(0, argv[1]), "l'entree standard est le fichier donne, en lecture, au debut");
    verifier(est(3, argv[2]), "le descripteur 3 est le fichier donne, en lecture, au debut");
    verifier(fcntl(3, F_GETFD) == 0, "le descripteur 3 sans FD_CLOEXEC");
    for (int fd = 4; fd <= 9; fd++)
        verifier(fcntl(fd, F_GETFD) == -1 && errno == EBADF, "les descripteurs 4 a 9 fermes");
    /* Le contenu, par le descripteur et par le chemin. */
    char par_fd[256] = {0}, par_chemin[256] = {0};
    ssize_t n = pread(3, par_fd, sizeof par_fd - 1, 0);
    int f = open(argv[2], O_RDONLY);
    ssize_t m = f >= 0 ? read(f, par_chemin, sizeof par_chemin - 1) : -1;
    if (f >= 0)
        close(f);
    verifier(n > 0 && n == m && memcmp(par_fd, par_chemin, (size_t)n) == 0, "le descripteur 3 lit le fichier");
    /* Sans droits : /proc/self/fd/3 refusé, le descripteur toujours lisible. */
    struct stat avant;
    verifier(fstat(3, &avant) == 0 && fchmod(3, 0) == 0, "fchmod(3, 0) d'un fichier a soi");
    errno = 0;
    int r = open("/proc/self/fd/3", O_RDONLY);
    verifier(r == -1 && errno == EACCES, "/proc/self/fd/3 d'un fichier sans droits : EACCES");
    if (r >= 0)
        close(r);
    char encore[256] = {0};
    verifier(pread(3, encore, sizeof encore - 1, 0) == n && memcmp(encore, par_fd, (size_t)n) == 0,
             "le descripteur reste lisible");
    verifier(fchmod(3, avant.st_mode & 07777) == 0, "les droits rendus");
    if (ecarts == 0)
        printf("[linux] redirections : 0 et 3 sont les fichiers donnes, en lecture, sans FD_CLOEXEC ; "
               "/proc/self/fd/3 d'un fichier sans droits : EACCES, le descripteur reste lisible : ok\n");
    return ecarts != 0;
}
