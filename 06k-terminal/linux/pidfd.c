/* Les pidfd (le lot 6 des soldes : le noyau n'en avait aucun). Sur l'hôte,
 * sous le Linux de référence (Yama à 1, comme Ubuntu), comme chez nous ;
 * sans fork (6l) : un processus, puis deux (a et b, lancés ensemble), qui se
 * parlent par des fichiers témoins dans DOSSIER (un tmpfs : /dev/shm sur
 * l'hôte, /tmp chez nous).
 *
 *   pidfd DOSSIER : dans un seul processus :
 *     - pidfd_open et ses refus ; le fichier : FD_CLOEXEC, ses drapeaux
 *       (PIDFD_THREAD visible), fstat (l'inode de pidfs : 0700 sans type, à
 *       root, le périphérique 0:5, le même numéro pour deux pidfd du même
 *       processus, daté de sa création, puis d'une date neuve quand tous ses
 *       pidfd fermés il est rouvert), /proc/self/fd, read, write, lseek,
 *       pread, ftruncate, fchmod, fsync ; poll et epoll ;
 *     - un fil : son pidfd (PIDFD_THREAD), pidfd_send_signal et ses portées
 *       (fil, processus, groupe), ses refus, un siginfo donné ; PIDFD_GET_INFO
 *       (le masque sans CGROUPID, que nous n'avons pas), les autres ioctl ;
 *       la fin du fil : POLLHUP, ESRCH, son statut ;
 *     - pidfd_getfd sur soi ; CLONE_PIDFD (clone de la glibc : le pidfd à
 *       parent_tid) ; PR_SET_PTRACER ; /proc/sys/kernel/yama/ptrace_scope.
 *   pidfd DOSSIER a &  puis  pidfd DOSSIER b : b ouvre le pidfd de a ;
 *     pidfd_getfd lui est refusé (EPERM : Yama, a ne descend pas de b) ; a
 *     permet b par PR_SET_PTRACER ; b copie alors le descripteur témoin de a
 *     et le lit ; a finit, b le voit (POLLIN).
 * Les numéros de descripteurs et d'inodes diffèrent de l'hôte : seuls leurs
 * rapports sont vérifiés. Un espace de noms (ioctl _IO(0xFF, n)) : Linux
 * rend un descripteur de nsfs, nous EOPNOTSUPP (aucun espace de noms) ; non
 * vérifié.
 *
 * Le filtre seccomp de Docker (le devcontainer) refuse pidfd_getfd sans
 * CAP_SYS_PTRACE (EPERM, même sur soi, ce que ptrace permet toujours) : sur
 * un hôte filtré (la ligne « Seccomp: 2 » de /proc/self/status, que notre
 * /proc n'a pas) où pidfd_getfd sur soi rend EPERM, ses vérifications sont
 * sautées, en le disant. La CI les fait sous le Linux de référence, sans
 * filtre.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define PIDFD_NONBLOCK O_NONBLOCK
#define PIDFD_THREAD O_EXCL
#define PIDFD_SIGNAL_THREAD 1
#define PIDFD_SIGNAL_THREAD_GROUP 2
#define PIDFD_SIGNAL_PROCESS_GROUP 4
#define PIDFD_SELF_THREAD -10000
#define PIDFD_SELF_THREAD_GROUP -10001
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x1000
#endif
#define CGROUPID 4

struct info {
    uint64_t mask, cgroupid;
    uint32_t pid, tgid, ppid, ruid, rgid, euid, egid, suid, sgid, fsuid, fsgid;
    int32_t exit_code;
    uint32_t coredump_mask, spare;
};

static int echecs;
static const char *role = "";
static char dossier[200];

static void verifier(int ok, const char *quoi)
{
    printf("[linux] pidfd%s%s : %s : %s\n", *role ? " " : "", role, quoi, ok ? "ok" : "ECHEC");
    fflush(stdout);
    echecs += !ok;
}

/* Le résultat d'un appel : la valeur, ou -errno. */
static long r(long v) { return v < 0 ? -errno : v; }
static long popen_(long pid, unsigned f) { return r(syscall(SYS_pidfd_open, pid, f)); }
static long psig(int fd, int sig, siginfo_t *i, unsigned f) { return r(syscall(SYS_pidfd_send_signal, fd, sig, i, f)); }
static long pget(int fd, int cible, unsigned f) { return r(syscall(SYS_pidfd_getfd, fd, cible, f)); }

/* pidfd_getfd est-il refusé par un filtre seccomp de l'hôte (voir l'en-tête) ? */
static int getfd_filtre(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char ligne[256];
    int filtre = 0;
    if (f == NULL)
        return 0;
    while (fgets(ligne, sizeof ligne, f))
        if (strncmp(ligne, "Seccomp:", 8) == 0 && strtol(ligne + 8, NULL, 10) == 2)
            filtre = 1;
    fclose(f);
    if (!filtre)
        return 0;
    int p = popen_(getpid(), 0), g = p < 0 ? -1 : pget(p, p, 0);
    if (g >= 0)
        close(g);
    if (p >= 0)
        close(p);
    return g == -EPERM;
}
static int sonder(int fd, int delai)
{
    struct pollfd p = { fd, POLLIN | POLLOUT | POLLPRI | POLLRDNORM | POLLRDHUP, 0 };
    int n = poll(&p, 1, delai);
    return n < 0 ? -errno : p.revents;
}

/* Les événements du pidfd `fd` d'un fil qui finit, une fois qu'ils sont `attendus`, 5 s au
 * plus. Linux le dit fini (POLLIN, `do_notify_pidfd`) dans `exit_notify`, avant de le
 * retirer de la table des pid (`release_task`, que fait le fil lui-même) : un poll qui
 * s'éveille entre les deux n'a pas encore POLLHUP, et l'ESRCH qui va avec n'est pas encore
 * là. `pthread_join`, qui rend la main à l'effacement du tid du fil, ne l'attend pas non
 * plus (la même course que `temps`, les soldes d'avant 6k, lot 5). Vu une fois sur WSL,
 * sous la charge d'une vérification : relu toutes les millisecondes jusqu'à eux. */
static int sonder_jusqua(int fd, int attendus)
{
    int v = 0;
    for (int i = 0; i < 5000 && (v = sonder(fd, 1000)) != attendus; i++)
        usleep(1000);
    return v;
}

/* PIDFD_GET_INFO de `taille` octets, le masque `masque` demandé, la
 * structure d'abord remplie de 0xaa : -errno, ou 0 et `i` (et l'octet 72). */
static long info(int fd, uint64_t masque, size_t taille, struct info *i, unsigned char *octet72)
{
    union { struct info i; unsigned char o[128]; } u;
    memset(&u, 0xaa, sizeof u);
    u.i.mask = masque;
    long v = r(ioctl(fd, _IOC(_IOC_READ | _IOC_WRITE, 0xFF, 11, taille), &u));
    memcpy(i, &u.i, sizeof *i);
    i->mask &= ~(uint64_t)CGROUPID;
    if (octet72)
        *octet72 = u.o[72];
    return v;
}

static volatile int vu_sig, vu_tid, vu_code, vu_pid;
static void gestionnaire(int s, siginfo_t *si, void *c)
{
    (void)c;
    vu_tid = gettid();
    vu_code = si->si_code;
    vu_pid = si->si_pid;
    vu_sig = s;
}

/* Attend le gestionnaire (un signal du processus peut aller à l'autre fil). */
static int attendre_signal(void)
{
    for (int k = 0; k < 2000 && !vu_sig; k++)
        usleep(1000);
    return vu_sig;
}

static int tube[2];
static volatile int tid_fil;
static void *fil(void *a)
{
    (void)a;
    tid_fil = gettid();
    char c;
    while (read(tube[0], &c, 1) < 0 && errno == EINTR)
        ;
    return 0;
}

/* Le corps d'un fil de clone (CLONE_PIDFD) : il attend un octet du tube,
 * puis rend la main à la glibc, qui finit le fil (SYS_exit). Sans la TLS
 * de la glibc : rien d'autre qu'un appel système brut. */
static int tube_clone[2];
static int corps_clone(void *a)
{
    (void)a;
    char c;
    syscall(SYS_read, tube_clone[0], &c, 1);
    return 0;
}

static double date(const struct stat *s) { return s->st_ctim.tv_sec + s->st_ctim.tv_nsec / 1e9; }

static void un_processus(void)
{
    int filtre = getfd_filtre();
    if (filtre)
        printf("[linux] pidfd : pidfd_getfd sautes (filtre seccomp de l'hote)\n");
    /* pidfd_open et ses refus. */
    verifier(popen_(getpid(), 1) == -EINVAL, "pidfd_open, drapeau 1 : EINVAL");
    verifier(popen_(getpid(), O_CLOEXEC) == -EINVAL, "pidfd_open, O_CLOEXEC : EINVAL");
    verifier(popen_(0, 0) == -EINVAL && popen_(-1, 0) == -EINVAL, "pidfd_open, pid 0 et -1 : EINVAL");
    verifier(popen_(4000000, 0) == -ESRCH, "pidfd_open, pid inconnu : ESRCH");
    int p = popen_(getpid(), 0), pn = popen_(getpid(), PIDFD_NONBLOCK), pt = popen_(getpid(), PIDFD_THREAD);
    verifier(p >= 0 && pn >= 0 && pt >= 0 && fcntl(p, F_GETFD) == FD_CLOEXEC, "pidfd_open : FD_CLOEXEC");
    verifier(fcntl(p, F_GETFL) == 2 && fcntl(pn, F_GETFL) == 0x802 && fcntl(pt, F_GETFL) == 0x82,
             "F_GETFL : O_RDWR, PIDFD_NONBLOCK, PIDFD_THREAD");
    verifier(fcntl(p, F_SETFL, O_NONBLOCK | O_APPEND) == 0 && fcntl(p, F_GETFL) == 0xc02, "F_SETFL O_NONBLOCK|O_APPEND : 0xc02");
    fcntl(p, F_SETFL, 0);
    /* Le fichier. */
    struct stat s, s2, se;
    int e = eventfd(0, 0);
    fstat(p, &s);
    fstat(pt, &s2);
    fstat(e, &se);
    verifier(s.st_mode == 0700 && s.st_nlink == 1 && s.st_uid == 0 && s.st_gid == 0 && s.st_size == 0 && s.st_blksize == 4096
             && s.st_blocks == 0 && s.st_rdev == 0, "fstat : 0700 sans type, root, vide");
    verifier(major(s.st_dev) == 0 && minor(s.st_dev) == 5 && s.st_ino == s2.st_ino && s.st_ino != se.st_ino,
             "fstat : pidfs (0:5), le meme inode pour le processus et son fil principal");
    verifier(s.st_atime == s.st_mtime && s.st_mtime == s.st_ctime && labs((long)(s.st_ctime - time(NULL))) <= 2,
             "fstat : date de la creation de l'inode");
    char lien[64] = { 0 }, chemin[64];
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", p);
    if (readlink(chemin, lien, sizeof lien - 1) < 0)
        lien[0] = 0;
    verifier(!strcmp(lien, "anon_inode:[pidfd]"), "/proc/self/fd : anon_inode:[pidfd]");
    char b[8];
    verifier(r(read(p, b, 8)) == -EINVAL && r(write(p, b, 8)) == -EINVAL && r(pread(p, b, 8, 0)) == -EINVAL,
             "read, write, pread : EINVAL");
    verifier(r(lseek(p, 0, SEEK_CUR)) == -ESPIPE, "lseek : ESPIPE");
    verifier(r(ftruncate(p, 0)) == -EOPNOTSUPP && r(fchmod(p, 0600)) == -EOPNOTSUPP, "ftruncate, fchmod : EOPNOTSUPP");
    verifier(r(fsync(p)) == -EINVAL, "fsync : EINVAL");
    verifier(sonder(p, 0) == 0 && sonder(pt, 0) == 0, "poll d'un processus vivant : 0");
    int ep = epoll_create1(0);
    struct epoll_event ev = { EPOLLIN, { 0 } };
    verifier(epoll_ctl(ep, EPOLL_CTL_ADD, p, &ev) == 0 && epoll_wait(ep, &ev, 1, 0) == 0, "epoll : accepte, rien de pret");
    char proc[40];
    snprintf(proc, sizeof proc, "/proc/%d", getpid());
    int dproc = open(proc, O_RDONLY | O_DIRECTORY);

    /* Un fil. */
    if (pipe(tube) != 0)
        verifier(0, "pipe");
    pthread_t t;
    pthread_create(&t, 0, fil, 0);
    while (!tid_fil)
        usleep(1000);
    verifier(popen_(tid_fil, 0) == -ENOENT, "pidfd_open d'un fil sans PIDFD_THREAD : ENOENT");
    int ft = popen_(tid_fil, PIDFD_THREAD);
    verifier(ft >= 0 && sonder(ft, 0) == 0 && fcntl(ft, F_GETFL) == 0x82, "pidfd d'un fil : PIDFD_THREAD, poll 0");
    /* Un inode par numéro : le fil n'a pas celui du processus. */
    struct stat sf;
    verifier(fstat(ft, &sf) == 0 && sf.st_ino != s.st_ino && sf.st_dev == s.st_dev, "fstat d'un fil : un autre inode de pidfs");
    struct sigaction sa = { 0 };
    sa.sa_sigaction = gestionnaire;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &sa, 0);
    sigaction(SIGUSR2, &sa, 0);
    vu_sig = 0;
    verifier(psig(ft, SIGUSR1, 0, 0) == 0 && attendre_signal() && vu_tid == tid_fil && vu_code == SI_TKILL && vu_pid == getpid(),
             "pidfd_send_signal au fil : le fil, SI_TKILL");
    vu_sig = 0;
    verifier(psig(p, SIGUSR1, 0, PIDFD_SIGNAL_THREAD) == 0 && attendre_signal() && vu_tid == getpid(),
             "PIDFD_SIGNAL_THREAD sur le processus : son fil principal");
    vu_sig = 0;
    verifier(psig(ft, SIGUSR1, 0, PIDFD_SIGNAL_THREAD_GROUP) == 0 && attendre_signal() && vu_code == SI_USER,
             "PIDFD_SIGNAL_THREAD_GROUP sur le fil : le processus, SI_USER");
    /* Le groupe : le processus le mène (chez nous toujours ; sur l'hôte,
     * lancé par un shell, il le devient). */
    if (getpgrp() != getpid())
        setpgid(0, 0);
    vu_sig = 0;
    verifier(psig(p, SIGUSR1, 0, PIDFD_SIGNAL_PROCESS_GROUP) == 0 && attendre_signal() && vu_code == SI_USER,
             "PIDFD_SIGNAL_PROCESS_GROUP : son groupe, SI_USER");
    verifier(psig(ft, SIGUSR1, 0, PIDFD_SIGNAL_PROCESS_GROUP) == -ESRCH, "PIDFD_SIGNAL_PROCESS_GROUP sur un fil : ESRCH");
    vu_sig = 0;
    verifier(psig(pt, SIGUSR1, 0, 0) == 0 && attendre_signal() && vu_tid == getpid() && vu_code == SI_TKILL,
             "PIDFD_THREAD du processus : son fil principal, SI_TKILL");
    verifier(psig(PIDFD_SELF_THREAD, 0, 0, 0) == 0 && psig(PIDFD_SELF_THREAD_GROUP, 0, 0, 0) == 0, "PIDFD_SELF_THREAD et _GROUP");
    verifier(psig(-1, 0, 0, 0) == -EBADF && psig(e, 0, 0, 0) == -EBADF, "un descripteur ferme, un eventfd : EBADF");
    verifier(psig(dproc, 0, 0, 0) == 0, "un dossier /proc/<pid> ouvert : le processus");
    verifier(psig(p, 0, 0, 8) == -EINVAL && psig(p, 0, 0, 3) == -EINVAL, "drapeaux inconnus, deux portees : EINVAL");
    verifier(psig(p, 65, 0, 0) == -EINVAL && psig(p, -1, 0, 0) == -EINVAL, "signal 65 et -1 : EINVAL");
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR2;
    si.si_code = SI_QUEUE;
    si.si_pid = 4242;
    verifier(psig(p, SIGUSR1, &si, 0) == -EINVAL, "siginfo d'un autre signal : EINVAL");
    vu_sig = 0;
    verifier(psig(p, SIGUSR2, &si, 0) == 0 && attendre_signal() && vu_code == SI_QUEUE && vu_pid == 4242,
             "siginfo SI_QUEUE a soi : livre tel quel");
    si.si_code = SI_USER;
    vu_sig = 0;
    verifier(psig(p, SIGUSR2, &si, 0) == 0 && attendre_signal(), "siginfo SI_USER a soi : permis");
    si.si_code = SI_TKILL;
    vu_sig = 0;
    verifier(psig(p, SIGUSR2, &si, 0) == 0 && attendre_signal(), "siginfo SI_TKILL a soi : permis");
    si.si_code = SI_QUEUE;
    vu_sig = 0;
    verifier(psig(ft, SIGUSR2, &si, 0) == 0 && attendre_signal() && vu_tid == tid_fil, "siginfo SI_QUEUE au fil : permis");
    si.si_code = SI_USER;
    verifier(psig(ft, SIGUSR2, &si, 0) == -EPERM, "siginfo SI_USER a un autre fil : EPERM");
    verifier(psig(PIDFD_SELF_THREAD_GROUP, SIGUSR2, &si, PIDFD_SIGNAL_PROCESS_GROUP) == -EPERM,
             "siginfo SI_USER a son groupe : EPERM");
    verifier(psig(p, SIGUSR2, (siginfo_t *)8, 0) == -EFAULT, "siginfo illisible : EFAULT");
    /* PIDFD_GET_INFO. */
    struct info i;
    unsigned char o72;
    verifier(info(p, 0, 64, &i, 0) == 0 && i.mask == 3 && i.pid == (uint32_t)getpid() && i.tgid == (uint32_t)getpid()
             && i.ppid == (uint32_t)getppid() && i.ruid == getuid() && i.euid == getuid() && i.suid == getuid() && i.fsuid == getuid()
             && i.rgid == getgid() && i.egid == getgid() && i.sgid == getgid() && i.fsgid == getgid()
             && i.coredump_mask == 0xaaaaaaaa, "PIDFD_GET_INFO de 64 octets : PID et CREDS, rien au-dela");
    verifier(info(p, 0, 80, &i, &o72) == 0 && i.coredump_mask == 0 && i.spare == 0 && o72 == 0, "de 80 octets : des zeros au-dela de 72");
    verifier(info(p, 8, 72, &i, 0) == 0 && i.mask == 3 && i.exit_code == 0, "EXIT demande d'un vivant : absent");
    verifier(info(p, 0x10, 72, &i, 0) == 0 && i.mask == 0x13 && i.coredump_mask == 4, "COREDUMP : PIDFD_COREDUMP_USER");
    verifier(info(p, 0, 63, &i, 0) == -ENOTTY, "de 63 octets : ENOTTY");
    verifier(info(ft, 0, 72, &i, 0) == 0 && i.pid == (uint32_t)tid_fil && i.tgid == (uint32_t)getpid(), "d'un fil : son numero");
    verifier(info(pt, 0, 72, &i, 0) == 0 && i.pid == (uint32_t)getpid(), "PIDFD_THREAD du processus : le fil principal");
    verifier(r(ioctl(p, _IOC(_IOC_READ | _IOC_WRITE, 0xFF, 11, 72), 0)) == -EINVAL, "PIDFD_GET_INFO sans adresse : EINVAL");
    verifier(r(ioctl(p, _IOC(_IOC_READ, 0xFF, 11, 72), 0)) == -ENOTTY, "PIDFD_GET_INFO en lecture seule : ENOTTY");
    verifier(r(ioctl(p, _IO(0xFF, 4), 1)) == -EINVAL, "un espace de noms, avec un argument : EINVAL");
    verifier(r(ioctl(p, _IO(0xFF, 12), 0)) == -ENOTTY && r(ioctl(p, FIONREAD, b)) == -ENOTTY, "_IO(0xFF, 12), FIONREAD : ENOTTY");
    unsigned generation = 7;
    verifier(ioctl(p, _IOR('v', 1, long), &generation) == 0 && generation == 0 && r(ioctl(p, _IOR('v', 1, long), 0)) == -EINVAL,
             "FS_IOC_GETVERSION : 0 ; sans adresse, EINVAL");
    /* La fin du fil. */
    if (write(tube[1], "x", 1) != 1)
        verifier(0, "le fil libere");
    pthread_join(t, 0);
    verifier(sonder_jusqua(ft, POLLIN | POLLRDNORM | POLLHUP) == (POLLIN | POLLRDNORM | POLLHUP), "le fil fini : POLLIN|POLLRDNORM|POLLHUP");
    verifier(psig(ft, 0, 0, 0) == -ESRCH && popen_(tid_fil, PIDFD_THREAD) == -ESRCH && (filtre || pget(ft, 0, 0) == -ESRCH),
             "le fil fini : ESRCH");
    verifier(info(ft, 8, 72, &i, 0) == 0 && i.mask == 8 && i.exit_code == 0 && i.pid == 0 && i.tgid == 0 && i.ruid == 0,
             "le fil fini : son statut seul");
    verifier(info(ft, 0, 72, &i, 0) == -ESRCH, "le fil fini, sans EXIT : ESRCH");
    /* pidfd_getfd sur soi. */
    int f = open("/proc/self/stat", O_RDONLY);
    if (!filtre) {
        verifier(pget(p, f, 1) == -EINVAL, "pidfd_getfd, drapeau 1 : EINVAL");
        int g = pget(p, f, 0);
        verifier(g >= 0 && fcntl(g, F_GETFD) == FD_CLOEXEC && lseek(f, 5, SEEK_SET) == 5 && lseek(g, 0, SEEK_CUR) == 5,
                 "pidfd_getfd sur soi : le meme fichier ouvert, FD_CLOEXEC");
        verifier(pget(p, 999, 0) == -EBADF && pget(p, -1, 0) == -EBADF, "pidfd_getfd d'un descripteur ferme : EBADF");
        verifier(pget(e, f, 0) == -EBADF && pget(PIDFD_SELF_THREAD_GROUP, f, 0) == -EBADF && pget(dproc, f, 0) == -EBADF,
                 "pidfd_getfd sans pidfd : EBADF");
        verifier(pget(pt, f, 0) >= 0, "pidfd_getfd par PIDFD_THREAD du processus");
    }
    /* CLONE_PIDFD : le pidfd du fil neuf, à parent_tid. */
    static char pile[65536] __attribute__((aligned(16)));
    int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_PIDFD;
    if (pipe(tube_clone) != 0)
        verifier(0, "pipe");
    int cp = -1;
    int tc = clone(corps_clone, pile + sizeof pile, flags, 0, &cp);
    verifier(tc > 0 && cp >= 0 && fcntl(cp, F_GETFD) == FD_CLOEXEC && fcntl(cp, F_GETFL) == 0x82 && sonder(cp, 0) == 0,
             "CLONE_PIDFD : le pidfd du fil, PIDFD_THREAD, FD_CLOEXEC");
    verifier(info(cp, 0, 72, &i, 0) == 0 && i.pid == (uint32_t)tc && i.tgid == (uint32_t)getpid(), "CLONE_PIDFD : son numero");
    if (write(tube_clone[1], "x", 1) != 1)
        verifier(0, "le fil de clone libere");
    verifier(sonder_jusqua(cp, POLLIN | POLLRDNORM | POLLHUP) == (POLLIN | POLLRDNORM | POLLHUP), "CLONE_PIDFD : le fil fini, POLLHUP");
    /* Le pidfd réservé, puis rendu : le plus petit numéro libre est le même après. */
    int libre = dup(0);
    close(libre);
    errno = 0;
    verifier(clone(corps_clone, pile + sizeof pile, flags, 0, (int *)8) == -1 && errno == EFAULT,
             "CLONE_PIDFD a une adresse illisible : EFAULT");
    int apres = dup(0);
    close(apres);
    verifier(apres == libre, "CLONE_PIDFD a une adresse illisible : le pidfd defait");
    /* Yama. */
    verifier(r(prctl(PR_SET_PTRACER, 4000000)) == -EINVAL, "PR_SET_PTRACER d'un inconnu : EINVAL");
    verifier(prctl(PR_SET_PTRACER, -1) == 0 && prctl(PR_SET_PTRACER, getpid()) == 0 && prctl(PR_SET_PTRACER, 0) == 0,
             "PR_SET_PTRACER : -1, soi, 0");
    char reglage[8] = { 0 };
    int y = open("/proc/sys/kernel/yama/ptrace_scope", O_RDONLY);
    verifier(y >= 0 && read(y, reglage, sizeof reglage - 1) == 2 && !strcmp(reglage, "1\n"), "ptrace_scope : 1");
    /* Tous ses pidfd fermés, un O_PATH par /proc/self/fd/N (permis sans droit de lecture)
     * tient l'inode, comme un pidfd : sa date reste, et un pidfd_open la retrouve. */
    double avant = date(&s);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", p);
    int o = open(chemin, O_PATH);
    close(p);
    close(pn);
    close(pt);
    struct timespec pause = { 1, 100000000 };
    nanosleep(&pause, 0);
    struct stat so;
    verifier(o >= 0 && fstat(o, &so) == 0 && date(&so) == avant && so.st_ino == s.st_ino,
             "un O_PATH par /proc/self/fd : l'inode tenu, sa date gardee");
    p = popen_(getpid(), 0);
    verifier(fstat(p, &s) == 0 && date(&s) == avant, "un O_PATH tenu : pidfd_open retrouve la date");
    /* Puis tous fermés, l'inode part : rouvert, il a une date neuve. */
    close(p);
    close(o);
    nanosleep(&pause, 0);
    p = popen_(getpid(), 0);
    fstat(p, &s);
    verifier(date(&s) - avant >= 1.0, "rouvert apres 1,1 s : une date neuve");
}

/* Les deux processus : des fichiers témoins dans le dossier. */
static void ecrire_temoin(const char *nom, long valeur)
{
    char chemin[240], neuf[256];
    snprintf(chemin, sizeof chemin, "%s/pidfd-%s", dossier, nom);
    snprintf(neuf, sizeof neuf, "%s.neuf", chemin);
    FILE *f = fopen(neuf, "w");
    fprintf(f, "%ld\n", valeur);
    fclose(f);
    rename(neuf, chemin);
}

static long lire_temoin(const char *nom)
{
    char chemin[256];
    snprintf(chemin, sizeof chemin, "%s/pidfd-%s", dossier, nom);
    for (int k = 0; k < 30000; k++) {
        FILE *f = fopen(chemin, "r");
        long v;
        if (f != NULL && fscanf(f, "%ld", &v) == 1) {
            fclose(f);
            return v;
        }
        if (f != NULL)
            fclose(f);
        usleep(2000);
    }
    return -1;
}

/* a : un descripteur témoin, son numéro et son pid annoncés ; il attend que
 * b demande la permission, la donne, puis attend que b ait fini. */
static void processus_a(void)
{
    char chemin[256];
    snprintf(chemin, sizeof chemin, "%s/pidfd-contenu", dossier);
    int f = open(chemin, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (write(f, "temoin", 6) != 6)
        verifier(0, "le temoin ecrit");
    ecrire_temoin("fd", f);
    ecrire_temoin("a", getpid());
    long b = lire_temoin("demande");
    verifier(b > 0 && prctl(PR_SET_PTRACER, b) == 0, "PR_SET_PTRACER de b");
    ecrire_temoin("permis", 1);
    verifier(lire_temoin("fin") == 1, "b a fini");
}

static void processus_b(void)
{
    long a = lire_temoin("a"), fa = lire_temoin("fd");
    int p = popen_(a, 0);
    verifier(p >= 0 && psig(p, 0, 0, 0) == 0, "pidfd_open de a, pidfd_send_signal 0");
    int filtre = getfd_filtre();
    if (filtre)
        printf("[linux] pidfd b : pidfd_getfd sautes (filtre seccomp de l'hote)\n");
    else
        verifier(pget(p, fa, 0) == -EPERM, "pidfd_getfd sans permission : EPERM (Yama)");
    ecrire_temoin("demande", getpid());
    lire_temoin("permis");
    if (!filtre) {
        int g = pget(p, fa, 0);
        char c[8] = { 0 };
        verifier(g >= 0 && fcntl(g, F_GETFD) == FD_CLOEXEC && pread(g, c, 6, 0) == 6 && !strcmp(c, "temoin"),
                 "pidfd_getfd permis par PR_SET_PTRACER : le temoin de a");
    }
    ecrire_temoin("fin", 1);
    verifier(sonder(p, 10000) & POLLIN, "la fin de a : POLLIN");
    /* Les témoins effacés : chez nous, /tmp est en mémoire, et ce qui
     * resterait compterait contre « memoire rendue ». */
    const char *noms[] = { "contenu", "fd", "a", "demande", "permis", "fin" };
    for (unsigned k = 0; k < sizeof noms / sizeof noms[0]; k++) {
        char chemin[256];
        snprintf(chemin, sizeof chemin, "%s/pidfd-%s", dossier, noms[k]);
        unlink(chemin);
    }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, 0, _IOLBF, 0);
    snprintf(dossier, sizeof dossier, "%s", argc > 1 ? argv[1] : "/tmp");
    if (argc > 2) {
        role = argv[2];
        if (!strcmp(role, "a"))
            processus_a();
        else
            processus_b();
    } else {
        un_processus();
    }
    printf("[linux] pidfd%s%s : %s\n", *role ? " " : "", role, echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
