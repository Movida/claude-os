/*
 * Les tubes (6f), contre ce qu'en fait Linux 6.18 (mesuré) : pipe2 et ses
 * drapeaux, ce que dit fstat des deux bouts, les pages et la règle de
 * fusion (64 écritures de 1000 octets remplissent un tube ; sur un tube
 * plein, 10 octets passent encore, pas 100 ; write(5000) rend 904), la
 * capacité (F_GETPIPE_SZ, F_SETPIPE_SZ), la fin (sans écrivain : 0 ; sans
 * lecteur : EPIPE et SIGPIPE), les paquets (O_DIRECT), FIONREAD ; puis deux
 * fils qui s'envoient 10 Mo et vérifient chaque octet, poll et epoll sur un
 * tube. Puis les tubes nommés (les soldes d'avant 6k) : mknod et ses
 * vérifications, l'ouverture qui attend l'autre bout (un fil en face, un
 * signal qui l'interrompt, SA_RESTART qui la reprend), le non bloquant
 * (ENXIO, POLLHUP seulement après un écrivain), un tube qui naît et meurt
 * avec ses bouts, le tube d'un pipe2 refait par un O_PATH ; et les autres
 * sortes de mknod (fichier, socket, « whiteout », périphériques pour
 * root) avec leur type dans un dossier. Sur l'hôte comme chez nous.
 * `tubes sigpipe` écrit dans un tube sans lecteur, SIGPIPE à son action par
 * défaut : il doit mourir avec le code 141 (128 + 13).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/un.h>
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

/* CAP_SYS_RESOURCE (24) dans les capacités effectives (CapEff de
 * /proc/self/status) ; sans ce fichier, aucune. */
static int sys_resource(void)
{
    char b[4096];
    int f = open("/proc/self/status", O_RDONLY);
    if (f < 0)
        return 0;
    long n = read(f, b, sizeof b - 1);
    close(f);
    if (n <= 0)
        return 0;
    b[n] = 0;
    char *c = strstr(b, "\nCapEff:\t");
    return c != NULL && (strtoull(c + 9, NULL, 16) >> 24 & 1);
}

static void capacite(void)
{
    int t[2];
    tube(t, 0);
    verifier(fcntl(t[0], F_GETPIPE_SZ) == 65536, "F_GETPIPE_SZ : 65536");
    verifier(fcntl(t[0], F_SETPIPE_SZ, 100000) == 131072 && fcntl(t[1], F_GETPIPE_SZ) == 131072,
             "F_SETPIPE_SZ(100000) : 131072 (une puissance de deux pages), sur les deux bouts");
    verifier(fcntl(t[0], F_SETPIPE_SZ, 1) == 4096, "F_SETPIPE_SZ(1) : une page");
    /* CAP_SYS_RESOURCE passe outre pipe-max-size (`pipe_set_size`), et
     * `make tests-hote-root` lance aussi ce programme en root : le root de la
     * machine du Linux de référence l'a, celui du devcontainer non (Docker ne
     * la donne pas). La capacité se lit donc, pas l'identité. */
    if (sys_resource())
        verifier(fcntl(t[0], F_SETPIPE_SZ, 2 << 20) == 2 << 20, "F_SETPIPE_SZ au-dela de pipe-max-size (1 Mio), avec CAP_SYS_RESOURCE : permis");
    else
        verifier(erreur(fcntl(t[0], F_SETPIPE_SZ, 2 << 20)) == EPERM, "F_SETPIPE_SZ au-dela de pipe-max-size (1 Mio), sans CAP_SYS_RESOURCE : EPERM");
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

/* ----- Les tubes nommés ----- */

/* Leur dossier : /dev/shm sur l'hôte (un tmpfs, comme notre /tmp ; le /tmp
 * de la machine de référence est un overlayfs, qui refuse le « whiteout »),
 * /tmp chez nous. */
static char dossier[64], fifo[96];
static volatile int lecteur_ouvert, alarmes;

static void *lire_le_tube(void *rien)
{
    (void)rien;
    int fd = open(fifo, O_RDONLY);
    lecteur_ouvert = 1;
    char b[8];
    long n = read(fd, b, sizeof b);
    close(fd);
    return (void *)n;
}

/* Attend trois SIGALRM (bloqués ici : ils vont au fil principal, qui attend
 * dans open), puis ouvre l'autre bout. */
static void *lecteur_tardif(void *rien)
{
    (void)rien;
    while (alarmes < 3)
        usleep(1000);
    return (void *)(long)open(fifo, O_RDONLY | O_NONBLOCK);
}

static void sur_alarme(int sig)
{
    (void)sig;
    alarmes++;
}

static volatile sig_atomic_t sigio_recus;

static void sur_sigio(int sig)
{
    (void)sig;
    sigio_recus++;
}

/* SIGALRM toutes les `us` microsecondes (0 : plus rien). */
static void alarme(long us)
{
    struct itimerval t = { { 0, us }, { 0, us } };
    setitimer(ITIMER_REAL, &t, NULL);
}

static void attendre_l_autre_bout(void)
{
    /* Un fil ouvre en lecture : il attend un écrivain, et inotify ne voit
     * pas encore l'ouverture (`fsnotify_open` suit `fifo_open`). */
    int in = inotify_init1(IN_NONBLOCK);
    inotify_add_watch(in, dossier, IN_OPEN | IN_CLOSE);
    char ev[256];
    pthread_t f;
    void *lu;
    lecteur_ouvert = 0;
    pthread_create(&f, NULL, lire_le_tube, NULL);
    usleep(50000);
    errno = 0;
    long n = read(in, ev, sizeof ev);
    verifier(!lecteur_ouvert && n == -1 && errno == EAGAIN, "open(O_RDONLY) attend un ecrivain, rien pour inotify");
    int w = open(fifo, O_WRONLY);
    verifier(w >= 0 && write(w, "abc", 3) == 3, "open(O_WRONLY) face a lui, write");
    close(w);
    pthread_join(f, &lu);
    verifier(lecteur_ouvert && (long)lu == 3, "le lecteur ouvert lit les 3 octets");
    while (read(in, ev, sizeof ev) > 0)
        ;

    /* Un signal sans SA_RESTART interrompt l'attente (EINTR), et le bout
     * qui attendait ne compte plus : un lecteur non bloquant lit la fin (0),
     * pas EAGAIN (un écrivain resté) ; un écrivain non bloquant reçoit ENXIO
     * (pas de lecteur resté). */
    struct sigaction sa = { 0 };
    sa.sa_handler = sur_alarme;
    sigaction(SIGALRM, &sa, NULL);
    alarme(20000);
    errno = 0;
    int r = open(fifo, O_WRONLY);
    int e = errno;
    alarme(0);
    verifier(r == -1 && e == EINTR, "open(O_WRONLY) sans lecteur, un signal : EINTR");
    r = open(fifo, O_RDONLY | O_NONBLOCK);
    char b[4];
    verifier(read(r, b, sizeof b) == 0, "l'ecrivain interrompu ne compte plus (read : 0)");
    close(r);
    alarme(20000);
    errno = 0;
    r = open(fifo, O_RDONLY);
    e = errno;
    alarme(0);
    verifier(r == -1 && e == EINTR, "open(O_RDONLY) sans ecrivain, un signal : EINTR");
    errno = 0;
    r = open(fifo, O_WRONLY | O_NONBLOCK);
    verifier(r == -1 && errno == ENXIO, "le lecteur interrompu ne compte plus (ENXIO)");
    /* Les ouvertures interrompues ou refusées ne se voient pas d'inotify :
     * seul le lecteur non bloquant, ouvert puis fermé. */
    n = read(in, ev, sizeof ev);
    struct inotify_event *e1 = (struct inotify_event *)ev;
    struct inotify_event *e2 = (struct inotify_event *)(ev + sizeof *e1 + e1->len);
    verifier(n == (long)(2 * sizeof *e1 + e1->len + e2->len) && e1->mask == IN_OPEN && e2->mask == IN_CLOSE_NOWRITE
             && strcmp(e1->name, "f") == 0, "inotify : IN_OPEN et IN_CLOSE_NOWRITE du seul lecteur non bloquant");
    close(in);

    /* Une ouverture interrompue ne ferme pas de bout (`err_rd`, `err_wr` de
     * Linux, pas `pipe_release`) : ni fin à dire, ni SIGIO au bout resté
     * en O_ASYNC ; un écrivain, puis un lecteur. */
    struct sigaction sio = { 0 };
    sio.sa_handler = sur_sigio;
    sigaction(SIGIO, &sio, NULL);
    int resultats = 1;
    for (int lecteur = 0; lecteur < 2; lecteur++) {
        sigio_recus = 0;
        int lu_ = open(fifo, O_RDONLY | O_NONBLOCK);
        int ecrit = open(fifo, O_WRONLY | O_NONBLOCK);
        int reste = lecteur ? lu_ : ecrit;
        fcntl(reste, F_SETOWN, getpid());
        fcntl(reste, F_SETFL, fcntl(reste, F_GETFL) | O_ASYNC);
        /* Le côté qui va attendre perd son seul bout : SIGIO au bout resté. */
        close(lecteur ? ecrit : lu_);
        usleep(10000);
        int apres_close = sigio_recus;
        alarme(20000);
        errno = 0;
        int attendu_ = open(fifo, lecteur ? O_RDONLY : O_WRONLY);
        e = errno;
        alarme(0);
        usleep(10000);
        resultats &= apres_close == 1 && attendu_ == -1 && e == EINTR && sigio_recus == 1;
        close(reste);
    }
    signal(SIGIO, SIG_DFL);
    verifier(resultats, "une ouverture interrompue : pas de SIGIO au bout reste en O_ASYNC");

    /* Avec SA_RESTART, open reprend après chaque signal, jusqu'au lecteur. */
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);
    sigset_t alrm, ancien;
    sigemptyset(&alrm);
    sigaddset(&alrm, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &alrm, &ancien);
    alarmes = 0;
    pthread_create(&f, NULL, lecteur_tardif, NULL);
    pthread_sigmask(SIG_SETMASK, &ancien, NULL);
    alarme(10000);
    w = open(fifo, O_WRONLY);
    alarme(0);
    pthread_join(f, &lu);
    verifier(w >= 0 && alarmes >= 3 && (long)lu >= 0, "open(O_WRONLY) repris apres trois signaux (SA_RESTART)");
    close(w);
    close((int)(long)lu);
    signal(SIGALRM, SIG_IGN);
}

static void nommes(void)
{
    snprintf(dossier, sizeof dossier, "%s/tubes-%d", access("/dev/shm", W_OK) == 0 ? "/dev/shm" : "/tmp", getpid());
    snprintf(fifo, sizeof fifo, "%s/f", dossier);
    char chemin[128];
    struct stat st;
    mkdir(dossier, 0700);
    mode_t umask_avant = umask(022);

    /* mknod et ses vérifications : le type avant le chemin. */
    verifier(mknod(fifo, S_IFIFO | 07777, 0) == 0 && stat(fifo, &st) == 0 && st.st_mode == (S_IFIFO | 07755)
             && st.st_size == 0 && st.st_nlink == 1 && st.st_rdev == 0, "mknod(S_IFIFO | 07777) sous l'umask 022 : 07755");
    errno = 0;
    verifier(mknod(fifo, S_IFDIR | 0777, 0) == -1 && errno == EPERM, "mknod(S_IFDIR) : EPERM");
    snprintf(chemin, sizeof chemin, "%s/absent/x", dossier);
    errno = 0;
    verifier(mknod(chemin, S_IFDIR | 0777, 0) == -1 && errno == EPERM, "mknod(S_IFDIR) dans un dossier absent : EPERM d'abord");
    errno = 0;
    verifier(mknod(chemin, 0170000 | 0777, 0) == -1 && errno == EINVAL, "mknod d'un type inconnu : EINVAL d'abord");
    errno = 0;
    verifier(mknod(fifo, S_IFIFO | 0644, 0) == -1 && errno == EEXIST, "mknod sur un nom pris : EEXIST");
    int d = open(dossier, O_RDONLY | O_DIRECTORY);
    verifier(syscall(SYS_mknodat, d, "t", S_IFIFO | 0600, 0x12345678L) == 0 && fstatat(d, "t", &st, 0) == 0
             && st.st_mode == (S_IFIFO | 0600) && st.st_rdev == 0, "mknodat par un dossier ouvert ; le peripherique ignore");
    unlinkat(d, "t", 0);
    snprintf(chemin, sizeof chemin, "%s/r", dossier);
    verifier(mknod(chemin, 0644, 99) == 0 && stat(chemin, &st) == 0 && st.st_mode == (S_IFREG | 0644) && st.st_rdev == 0,
             "mknod sans type : un fichier ordinaire");

    /* Le non bloquant : un lecteur passe et lit la fin, sans POLLHUP tant
     * qu'aucun écrivain n'est venu ; un écrivain sans lecteur : ENXIO. */
    errno = 0;
    verifier(open(fifo, O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO, "O_WRONLY | O_NONBLOCK sans lecteur : ENXIO");
    errno = 0;
    verifier(open(fifo, O_ACCMODE) == -1 && errno == EINVAL, "O_ACCMODE (3) : EINVAL");
    int r = open(fifo, O_RDONLY | O_NONBLOCK);
    char b[8];
    struct pollfd p = { r, POLLIN, 0 };
    verifier(r >= 0 && poll(&p, 1, 0) == 0 && read(r, b, sizeof b) == 0, "O_RDONLY | O_NONBLOCK : ouvert, ni POLLHUP ni donnees, read : 0");
    errno = 0;
    /* F_GETFL : O_LARGEFILE (0100000 pour le noyau ; la glibc 64 bits le
     * définit à 0). */
    verifier(lseek(r, 0, SEEK_SET) == -1 && errno == ESPIPE && fcntl(r, F_GETPIPE_SZ) == 65536
             && fcntl(r, F_GETFL) == (O_RDONLY | O_NONBLOCK | 0100000), "lseek : ESPIPE ; 64 Kio ; F_GETFL");
    char lien[128] = { 0 };
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", r);
    verifier(readlink(chemin, lien, sizeof lien - 1) > 0 && strcmp(lien, fifo) == 0, "/proc/self/fd : le chemin du tube nomme");
    int w = open(fifo, O_WRONLY | O_NONBLOCK);
    verifier(w >= 0 && write(w, "abc", 3) == 3 && fstat(w, &st) == 0 && S_ISFIFO(st.st_mode) && st.st_size == 0,
             "un ecrivain, maintenant ; fstat : S_IFIFO, taille 0");
    poll(&p, 1, 0);
    verifier(p.revents == POLLIN, "poll : POLLIN");
    close(w);
    poll(&p, 1, 0);
    verifier(p.revents == (POLLIN | POLLHUP), "l'ecrivain parti : POLLIN | POLLHUP");
    verifier(read(r, b, sizeof b) == 3 && read(r, b, sizeof b) == 0, "read : les 3 octets, puis la fin");
    close(r);

    /* O_RDWR n'attend jamais ; ce qui reste dans le tube meurt avec le
     * dernier bout ; un tube nommé effacé vit tant qu'il est ouvert. */
    int x = open(fifo, O_RDWR);
    verifier(x >= 0 && write(x, "xyz", 3) == 3, "O_RDWR, sans attendre");
    close(x);
    x = open(fifo, O_RDWR | O_NONBLOCK);
    errno = 0;
    verifier(read(x, b, sizeof b) == -1 && errno == EAGAIN, "rouvert : un tube neuf, vide");
    unlink(fifo);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", x);
    memset(lien, 0, sizeof lien);
    char efface[128];
    snprintf(efface, sizeof efface, "%s (deleted)", fifo);
    verifier(readlink(chemin, lien, sizeof lien - 1) > 0 && strcmp(lien, efface) == 0, "efface : /proc/self/fd le dit (deleted)");
    verifier(write(x, "uv", 2) == 2 && read(x, b, sizeof b) == 2, "efface, il marche encore");
    close(x);
    mknod(fifo, S_IFIFO | 0600, 0);
    attendre_l_autre_bout();
    unlink(fifo);

    /* Le tube d'un pipe2, refait par un O_PATH après la fermeture de ses
     * deux bouts : un tube neuf, sans attente (ce n'est pas un tube nommé),
     * sans écrivain : POLLHUP. */
    int t[2];
    tube(t, 0);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", t[0]);
    int o = open(chemin, O_PATH);
    close(t[0]);
    close(t[1]);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", o);
    r = open(chemin, O_RDONLY);
    p.fd = r;
    verifier(r >= 0 && read(r, b, sizeof b) == 0 && poll(&p, 1, 0) == 1 && p.revents == POLLHUP,
             "un pipe2 sans bouts, rouvert par O_PATH : un tube neuf, POLLHUP");
    w = open(chemin, O_WRONLY);
    verifier(w >= 0 && write(w, "ab", 2) == 2 && read(r, b, sizeof b) == 2, "et son ecrivain");
    close(w);
    close(r);
    close(o);

    /* Une socket par mknod : un nom sans socket. */
    snprintf(chemin, sizeof chemin, "%s/s", dossier);
    verifier(mknod(chemin, S_IFSOCK | 0777, 0) == 0 && stat(chemin, &st) == 0 && st.st_mode == (S_IFSOCK | 0755),
             "mknod(S_IFSOCK)");
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    strcpy(a.sun_path, chemin);
    errno = 0;
    verifier(connect(s, (struct sockaddr *)&a, sizeof a) == -1 && errno == ECONNREFUSED, "connect : ECONNREFUSED");
    close(s);
    errno = 0;
    verifier(open(chemin, O_RDONLY) == -1 && errno == ENXIO, "open : ENXIO");

    /* Le « whiteout » (caractères 0:0) se crée sans être root ; pas les
     * autres périphériques. */
    snprintf(chemin, sizeof chemin, "%s/w", dossier);
    verifier(mknod(chemin, S_IFCHR | 0666, 0) == 0 && stat(chemin, &st) == 0 && st.st_mode == (S_IFCHR | 0644)
             && st.st_rdev == 0, "mknod du whiteout (caracteres 0:0)");
    char cn[128], bn[128];
    snprintf(cn, sizeof cn, "%s/c", dossier);
    snprintf(bn, sizeof bn, "%s/b", dossier);
    if (geteuid() != 0) {
        errno = 0;
        verifier(mknod(cn, S_IFCHR | 0666, makedev(1, 3)) == -1 && errno == EPERM, "un peripherique sans etre root : EPERM");
        errno = 0;
        verifier(mknod(bn, S_IFBLK | 0666, 0) == -1 && errno == EPERM, "un disque, meme 0:0 : EPERM");
    } else {
        /* /dev/null refait ; un disque, sans pilote : ENXIO (EACCES dans
         * /dev/shm, monté nodev sur l'hôte). */
        verifier(mknod(cn, S_IFCHR | 0666, makedev(1, 3)) == 0 && stat(cn, &st) == 0 && major(st.st_rdev) == 1
                 && minor(st.st_rdev) == 3, "root : mknod de /dev/null (1:3)");
        verifier(mknod(bn, S_IFBLK | 0600, makedev(259, 70000)) == 0 && stat(bn, &st) == 0 && S_ISBLK(st.st_mode)
                 && major(st.st_rdev) == 259 && minor(st.st_rdev) == 70000, "root : un disque 259:70000");
        int nodev = strncmp(dossier, "/dev/shm", 8) == 0;
        x = open(cn, O_RDWR);
        verifier(nodev || (x >= 0 && write(x, "x", 1) == 1 && read(x, b, 1) == 0), "root : il se comporte comme /dev/null");
        close(x);
        errno = 0;
        verifier(open(bn, O_RDONLY) == -1 && errno == (nodev ? EACCES : ENXIO), "root : le disque, sans pilote : ENXIO");
        unlink(cn);
        unlink(bn);
    }

    /* Leurs types dans le dossier (d_type). */
    mknod(fifo, S_IFIFO | 0600, 0);
    DIR *dir = fdopendir(d);
    struct dirent *de;
    int types = 0;
    while ((de = readdir(dir)) != NULL) {
        types += strcmp(de->d_name, "f") == 0 && de->d_type == DT_FIFO;
        types += strcmp(de->d_name, "s") == 0 && de->d_type == DT_SOCK;
        types += strcmp(de->d_name, "w") == 0 && de->d_type == DT_CHR;
        types += strcmp(de->d_name, "r") == 0 && de->d_type == DT_REG;
    }
    verifier(types == 4, "d_type : DT_FIFO, DT_SOCK, DT_CHR, DT_REG");
    closedir(dir);
    for (const char *n = "fswr"; *n; n++) {
        snprintf(chemin, sizeof chemin, "%s/%c", dossier, *n);
        unlink(chemin);
    }
    rmdir(dossier);
    umask(umask_avant);
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
    nommes();
    printf("[linux] tubes : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
