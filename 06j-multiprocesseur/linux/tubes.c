/*
 * Les tubes (6f), contre ce qu'en fait Linux 6.18 (mesuré) : pipe2 et ses
 * drapeaux, ce que dit fstat des deux bouts, les pages et la règle de
 * fusion (64 écritures de 1000 octets remplissent un tube ; sur un tube
 * plein, 10 octets passent encore, pas 100 ; write(5000) rend 904), la
 * capacité (F_GETPIPE_SZ, F_SETPIPE_SZ), la fin (sans écrivain : 0 ; sans
 * lecteur : EPIPE et SIGPIPE), les paquets (O_DIRECT), FIONREAD ; puis deux
 * fils qui s'envoient 10 Mo et vérifient chaque octet, poll et epoll sur un
 * tube. Sur l'hôte comme chez nous. `tubes sigpipe` écrit dans un tube sans
 * lecteur, SIGPIPE à son action par défaut : il doit mourir avec le code
 * 141 (128 + 13).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] tubes : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static char octets[8192];

/* Un tube, ou l'arrêt du test. */
static void tube(int t[2], int drapeaux)
{
    if (pipe2(t, drapeaux) != 0) {
        printf("[linux] tubes : pipe2 : ECHEC\n");
        _exit(1);
    }
}

static long ecrire(int fd, size_t n)
{
    return write(fd, octets, n);
}

static void creation(void)
{
    int t[2];
    verifier(pipe2(t, O_CLOEXEC | O_NONBLOCK) == 0 && fcntl(t[0], F_GETFD) == FD_CLOEXEC && fcntl(t[0], F_GETFL) == O_NONBLOCK
                 && fcntl(t[1], F_GETFL) == (O_WRONLY | O_NONBLOCK),
             "pipe2(O_CLOEXEC | O_NONBLOCK) : les deux bouts, F_GETFL O_RDONLY et O_WRONLY");
    close(t[0]);
    close(t[1]);
    verifier(pipe2(t, O_DIRECT) == 0 && fcntl(t[0], F_GETFL) == 0 && fcntl(t[1], F_GETFL) == (O_WRONLY | O_DIRECT),
             "pipe2(O_DIRECT) : O_DIRECT sur le bout d'ecriture seulement");
    close(t[0]);
    close(t[1]);
    /* ENOPKG sans CONFIG_WATCH_QUEUE : notre noyau, et celui de WSL. Sur l'hôte, avec (le noyau de
     * la CI), un tube, comme les autres. */
    int notification = erreur(syscall(SYS_pipe2, t, O_EXCL));
    if (notification == 0) {
        close(t[0]);
        close(t[1]);
    }
    verifier(notification == ENOPKG || (access("/etc/bonjour.txt", F_OK) != 0 && notification == 0),
             "pipe2(O_NOTIFICATION_PIPE) : ENOPKG");
    verifier(erreur(syscall(SYS_pipe2, t, O_APPEND)) == EINVAL, "pipe2(O_APPEND) : EINVAL");
    verifier(erreur(syscall(SYS_pipe2, (void *)8, 0)) == EFAULT, "pipe2 vers l'adresse 8 : EFAULT");

    verifier(pipe(t) == 0, "pipe");
    struct stat a, b;
    fstat(t[0], &a);
    fstat(t[1], &b);
    verifier(a.st_mode == (S_IFIFO | 0600) && b.st_mode == a.st_mode && a.st_ino == b.st_ino && a.st_nlink == 1
                 && a.st_uid == getuid() && a.st_size == 0 && a.st_blksize == 4096 && a.st_dev == b.st_dev,
             "fstat des deux bouts : S_IFIFO | 0600, le meme inode, nlink 1, au createur, taille 0, blocs de 4096");
    verifier(fchmod(t[0], 0640) == 0 && fstat(t[1], &b) == 0 && b.st_mode == (S_IFIFO | 0640),
             "fchmod d'un bout : l'inode commun change");
    verifier(erreur(lseek(t[0], 0, SEEK_CUR)) == ESPIPE && erreur(pread(t[0], octets, 1, 0)) == ESPIPE
                 && erreur(pwrite(t[1], octets, 1, 0)) == ESPIPE,
             "lseek, pread, pwrite : ESPIPE");
    verifier(erreur(write(t[0], octets, 1)) == EBADF && erreur(read(t[1], octets, 1)) == EBADF,
             "ecrire le bout de lecture, lire celui d'ecriture : EBADF");
    verifier(erreur(ftruncate(t[1], 0)) == EINVAL && erreur(fsync(t[1])) == EINVAL && erreur(fchdir(t[0])) == ENOTDIR,
             "ftruncate, fsync : EINVAL ; fchdir : ENOTDIR");
    verifier(read(t[0], octets, 0) == 0 && write(t[1], octets, 0) == 0, "lire et ecrire 0 octet : 0");
    close(t[0]);
    close(t[1]);
}

static void pages(void)
{
    int t[2];
    tube(t, O_NONBLOCK);
    int n = 0;
    while (ecrire(t[1], 1000) == 1000)
        n++;
    int present;
    ioctl(t[0], FIONREAD, &present);
    verifier(n == 64 && errno == EAGAIN && present == 64000, "64 ecritures de 1000 octets remplissent le tube (quatre par page), FIONREAD 64000");
    char lu[100];
    long r = read(t[0], lu, 100);
    long a = erreur(ecrire(t[1], 4096)), b = erreur(ecrire(t[1], 100)), c = ecrire(t[1], 10);
    verifier(r == 100 && a == EAGAIN && b == EAGAIN && c == 10,
             "100 octets lus : 4096 et 100 refuses (EAGAIN), 10 passent (la place de la derniere page)");
    close(t[0]);
    close(t[1]);

    tube(t, O_NONBLOCK);
    for (int i = 0; i < 15; i++)
        if (ecrire(t[1], 4096) != 4096)
            echecs++;
    if (ecrire(t[1], 100) != 100)
        echecs++;
    r = ecrire(t[1], 5000);
    verifier(r == 904, "15 pages pleines et 100 octets : write(5000) rend 904 (le reste modulo 4096, colle a la derniere page)");
    close(t[0]);
    close(t[1]);

    tube(t, O_NONBLOCK);
    for (int i = 0; i < 15; i++)
        if (ecrire(t[1], 4096) != 4096)
            echecs++;
    r = ecrire(t[1], 8192);
    verifier(r == 4096, "au-dela de PIPE_BUF, non bloquant : ce qui tient (4096 sur 8192)");
    close(t[0]);
    close(t[1]);
}

static void capacite(void)
{
    int t[2];
    tube(t, 0);
    verifier(fcntl(t[0], F_GETPIPE_SZ) == 65536, "F_GETPIPE_SZ : 65536");
    verifier(fcntl(t[0], F_SETPIPE_SZ, 100000) == 131072 && fcntl(t[1], F_GETPIPE_SZ) == 131072,
             "F_SETPIPE_SZ(100000) : 131072 (une puissance de deux pages), sur les deux bouts");
    verifier(fcntl(t[0], F_SETPIPE_SZ, 1) == 4096, "F_SETPIPE_SZ(1) : une page");
    verifier(erreur(fcntl(t[0], F_SETPIPE_SZ, 2 << 20)) == EPERM, "F_SETPIPE_SZ au-dela de pipe-max-size (1 Mio), sans etre root : EPERM");
    verifier(fcntl(t[0], F_SETPIPE_SZ, 1 << 20) == 1 << 20, "F_SETPIPE_SZ(1 Mio) : permis");
    for (int i = 0; i < 3; i++)
        if (ecrire(t[1], 4096) != 4096)
            echecs++;
    verifier(erreur(fcntl(t[0], F_SETPIPE_SZ, 8192)) == EBUSY, "F_SETPIPE_SZ sous ce qu'il contient : EBUSY");
    verifier(fcntl(t[0], F_SETPIPE_SZ, 16384) == 16384 && read(t[0], octets, 8192) == 8192,
             "F_SETPIPE_SZ(16384) avec trois pages : permis, le contenu garde");
    int f = open("/tmp", O_RDONLY);
    verifier(erreur(fcntl(f, F_GETPIPE_SZ)) == EBADF, "F_GETPIPE_SZ d'un dossier : EBADF");
    close(f);
    char v[32] = { 0 };
    f = open("/proc/sys/fs/pipe-max-size", O_RDONLY);
    verifier(f >= 0 && read(f, v, sizeof v - 1) > 0 && strcmp(v, "1048576\n") == 0, "/proc/sys/fs/pipe-max-size : 1048576");
    close(f);
    close(t[0]);
    close(t[1]);
}

static volatile int recus, code_recu;

static void sur_sigpipe(int sig, siginfo_t *si, void *c)
{
    (void)sig;
    (void)c;
    recus++;
    code_recu = si->si_code;
}

static void fins(void)
{
    int t[2];
    tube(t, 0);
    if (ecrire(t[1], 10) != 10)
        echecs++;
    close(t[1]);
    verifier(read(t[0], octets, 100) == 10 && read(t[0], octets, 100) == 0, "sans ecrivain : ce qui reste, puis 0 (la fin)");
    close(t[0]);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sur_sigpipe;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGPIPE, &sa, NULL);
    tube(t, 0);
    close(t[0]);
    recus = 0;
    long r = erreur(ecrire(t[1], 10));
    verifier(r == EPIPE && recus == 1 && code_recu == SI_USER, "sans lecteur : EPIPE, et SIGPIPE (SI_USER)");
    signal(SIGPIPE, SIG_IGN);
    verifier(erreur(ecrire(t[1], 10)) == EPIPE, "SIGPIPE ignore : EPIPE seul");
    signal(SIGPIPE, SIG_DFL);
    close(t[1]);

    tube(t, O_DIRECT);
    if (write(t[1], "abcdef", 6) != 6 || write(t[1], "gh", 2) != 2)
        echecs++;
    char lu[16] = { 0 };
    long a = read(t[0], lu, 3);
    long b = read(t[0], lu + 3, 8);
    verifier(a == 3 && b == 2 && memcmp(lu, "abcgh", 5) == 0, "O_DIRECT : chaque ecriture un paquet ; lire 3 octets d'un paquet de 6 jette les 3 autres");
    close(t[0]);
    close(t[1]);
}

/* Deux fils : l'un écrit 10 Mo par morceaux de tailles variées, l'autre
 * les lit et vérifie chaque octet. Le tube se remplit et se vide sans
 * cesse : les deux attendent l'un l'autre. */
#define TOTAL (10 << 20)
static int ecrivain_fd;

static void *envoyer(void *rien)
{
    (void)rien;
    static unsigned char m[70000];
    size_t envoye = 0, taille = 1;
    while (envoye < TOTAL) {
        size_t n = taille % sizeof m;
        if (n > TOTAL - envoye)
            n = TOTAL - envoye;
        for (size_t i = 0; i < n; i++)
            m[i] = (unsigned char)((envoye + i) * 7);
        size_t fait = 0;
        while (fait < n) {
            long w = write(ecrivain_fd, m + fait, n - fait);
            if (w <= 0)
                return NULL;
            fait += w;
        }
        envoye += n;
        taille = taille * 37 + 11;
    }
    close(ecrivain_fd);
    return NULL;
}

static void dix_mega(void)
{
    int t[2];
    tube(t, 0);
    ecrivain_fd = t[1];
    pthread_t f;
    pthread_create(&f, NULL, envoyer, NULL);
    static unsigned char m[65536];
    size_t recu = 0;
    int faux = 0;
    for (;;) {
        long r = read(t[0], m, (recu % 5 + 1) * 13000 % sizeof m + 1);
        if (r <= 0)
            break;
        for (long i = 0; i < r; i++)
            faux |= m[i] != (unsigned char)((recu + i) * 7);
        recu += r;
    }
    pthread_join(f, NULL);
    verifier(recu == TOTAL && !faux, "deux fils s'envoient 10 Mo : chaque octet a sa place, puis la fin");
    close(t[0]);
}

static void attentes(void)
{
    int t[2];
    tube(t, 0);
    struct pollfd p[2] = { { t[0], -1, 0 }, { t[1], -1, 0 } };
    poll(p, 2, 0);
    short vide_l = p[0].revents, vide_e = p[1].revents;
    if (ecrire(t[1], 1) != 1)
        echecs++;
    poll(p, 2, 0);
    short plein_l = p[0].revents;
    verifier(vide_l == 0 && vide_e == (POLLOUT | POLLWRNORM) && plein_l == (POLLIN | POLLRDNORM),
             "poll : vide, la lecture 0 et l'ecriture 0x104 ; un octet, la lecture 0x41");

    int ep = epoll_create1(0);
    struct epoll_event e = { .events = EPOLLIN | EPOLLET };
    epoll_ctl(ep, EPOLL_CTL_ADD, t[0], &e);
    struct epoll_event r;
    int a = epoll_wait(ep, &r, 1, 0);
    int b = epoll_wait(ep, &r, 1, 0);
    if (ecrire(t[1], 1) != 1)
        echecs++;
    int c = epoll_wait(ep, &r, 1, 0);
    verifier(a == 1 && b == 0 && c == 1, "EPOLLET sur un tube : une ecriture, meme sur un tube pas vide, redonne EPOLLIN");
    close(ep);

    close(t[1]);
    p[0].revents = 0;
    poll(p, 1, 0);
    verifier(p[0].revents == (POLLIN | POLLRDNORM | POLLHUP), "sans ecrivain : POLLHUP (et POLLIN, il reste un octet)");
    close(t[0]);
    tube(t, 0);
    close(t[0]);
    p[1].fd = t[1];
    poll(&p[1], 1, 0);
    verifier(p[1].revents == (POLLOUT | POLLWRNORM | POLLERR), "sans lecteur, cote ecriture : 0x10c (POLLERR)");
    close(t[1]);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 1 && strcmp(argv[1], "sigpipe") == 0) {
        /* L'action par défaut, débloquée, quoi qu'ait hérité le programme
         * (un service systemd ignore SIGPIPE, et l'ignorer passe execve). */
        sigset_t pipe;
        sigemptyset(&pipe);
        sigaddset(&pipe, SIGPIPE);
        signal(SIGPIPE, SIG_DFL);
        sigprocmask(SIG_UNBLOCK, &pipe, NULL);
        int t[2];
        tube(t, 0);
        close(t[0]);
        printf("[linux] tubes : ecrire sans lecteur, SIGPIPE par defaut\n");
        if (ecrire(t[1], 1) != 1)
            echecs++;
        printf("[linux] tubes : toujours vivant apres SIGPIPE : ECHEC\n");
        return 0;
    }
    creation();
    pages();
    capacite();
    fins();
    dix_mega();
    attentes();
    printf("[linux] tubes : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
