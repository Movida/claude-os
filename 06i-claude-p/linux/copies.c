/*
 * Les transferts dans le noyau (6i) : copy_file_range, sendfile, et le
 * conseil fadvise64, avec les codes d'erreur de Linux 6.18, dans leur ordre
 * (relevés sur l'hôte par la relecture du plan de 6i). claude s'en sert
 * pour copier un fichier (Bun : copy_file_range, puis sendfile s'il manque,
 * puis read et write). Depuis la relecture de 6i, ce que fait chaque sorte
 * de fichier, en entrée et en sortie, vers un tube et ailleurs : les cases
 * d'un tube qui désignent les pages d'un fichier, les rondes du tube
 * interne (un datagramme par ronde), les sockets vers un tube, les
 * positions extrêmes.
 *
 *     copies [DOSSIER]
 *
 * Les fichiers de l'essai sont dans DOSSIER (/tmp par défaut ; /dev/shm sur
 * l'hôte, un tmpfs comme le nôtre : les positions extrêmes dépendent du
 * système de fichiers). Il tourne dans notre noyau et sur l'hôte.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int ecarts;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] copies : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    if (!ok)
        ecarts++;
}

/* Le résultat d'un appel : sa valeur, ou -errno. */
static long r(long v)
{
    return v < 0 ? -errno : v;
}

static long cfr(int a, loff_t *pa, int b, loff_t *pb, size_t n, unsigned drapeaux)
{
    return r(syscall(SYS_copy_file_range, a, pa, b, pb, n, drapeaux));
}

static int contenu(const char *chemin, const char *attendu, size_t n)
{
    char lu[16384];
    int fd = open(chemin, O_RDONLY);
    ssize_t l = fd >= 0 ? read(fd, lu, sizeof lu) : -1;
    if (fd >= 0)
        close(fd);
    return l == (ssize_t)n && memcmp(lu, attendu, n) == 0;
}

static void ecrire_fichier(const char *chemin, const char *octets, size_t n)
{
    int fd = open(chemin, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, octets, n) != (ssize_t)n)
        verifier(0, "creer un fichier d'essai");
    if (fd >= 0)
        close(fd);
}

/* Un appel de préparation, dont le résultat ne sert pas : son échec est
 * une vérification ratée. */
#define FAIT(appel)                                \
    do {                                           \
        if ((long)(appel) < 0)                     \
            verifier(0, "preparation : " #appel);  \
    } while (0)

static char A[256], B[256], C[256];

/* Lit tout ce que rend `fd` (non bloquant). */
static long vider(int fd)
{
    static char poubelle[1 << 17];
    long n = 0, l;
    while ((l = read(fd, poubelle, sizeof poubelle)) > 0)
        n += l;
    return n;
}

/* Ce que rend read d'un fichier fraîchement ouvert : sa longueur. */
static long longueur_lue(const char *chemin)
{
    char lu[4096];
    int fd = open(chemin, O_RDONLY);
    long n = fd >= 0 ? read(fd, lu, sizeof lu) : -1;
    if (fd >= 0)
        close(fd);
    return n;
}

/* Chaque sorte en entrée (mesuré sous Linux 6.18) : une position donnée
 * (FMODE_PREAD, sinon ESPIPE), 0 octet vers un fichier (FMODE_LSEEK, sinon
 * EINVAL), 8 octets vers un fichier, 0 puis 8 vers un tube (le splice_read,
 * sinon EINVAL). */
static void entrees(const char *d)
{
    int a = open(A, O_RDWR), b = open(B, O_RDWR | O_TRUNC);
    int t[2], sv[2], dg[2];
    if (pipe2(t, O_NONBLOCK) != 0 || socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) != 0
        || socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, dg) != 0) {
        verifier(0, "entrees : tubes et sockets");
        return;
    }
    int t2[2];
    FAIT(pipe2(t2, O_NONBLOCK));
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001) };
    socklen_t sl = sizeof sa;
    if (bind(udp, (void *)&sa, sizeof sa) != 0 || getsockname(udp, (void *)&sa, &sl) != 0)
        verifier(0, "entrees : socket UDP");
    /* La valeur, la longueur des fichiers dont le contenu change d'une
     * machine à l'autre : celle que rend read. */
    struct {
        const char *nom, *chemin;
        int fd;
        long position, vide, huit, tube_vide, tube_huit;
    } e[] = {
        { "un fichier", NULL, a, 0, 0, 8, 0, 8 },
        { "un dossier", NULL, open(d, O_RDONLY | O_DIRECTORY), 0, 0, -EINVAL, 0, -EINVAL },
        { "/dev/null", NULL, open("/dev/null", O_RDWR), 0, 0, -EINVAL, 0, -EINVAL },
        { "/dev/zero", NULL, open("/dev/zero", O_RDWR), 0, 0, 8, 0, 8 },
        { "/dev/full", NULL, open("/dev/full", O_RDWR), 0, 0, 8, 0, 8 },
        { "/dev/urandom", NULL, open("/dev/urandom", O_RDWR), 0, 0, 8, 0, 8 },
        { "un eventfd", NULL, eventfd(0, EFD_NONBLOCK), -ESPIPE, 0, -EINVAL, 0, -EINVAL },
        { "un epoll", NULL, epoll_create1(0), -ESPIPE, 0, -EINVAL, 0, -EINVAL },
        { "un tube", NULL, t2[0], -ESPIPE, -EINVAL, -EINVAL, 0, -EINVAL },
        { "un flux AF_UNIX", NULL, sv[0], -ESPIPE, -EINVAL, -EINVAL, 0, 3 },
        { "des datagrammes AF_UNIX", NULL, dg[0], -ESPIPE, -EINVAL, -EINVAL, 0, 3 },
        { "une socket UDP", NULL, udp, -ESPIPE, -EINVAL, -EINVAL, 0, 3 },
        { "/proc/self/statm", "/proc/self/statm", -1, 0, 0, -EINVAL, 0, -EINVAL },
        { "/proc/self/maps", "/proc/self/maps", -1, 0, 0, -EINVAL, 0, -EINVAL },
        { "/proc/self/comm", "/proc/self/comm", -1, 0, 0, -EINVAL, 0, -EINVAL },
        { "/proc/net/dev", "/proc/net/dev", -1, 0, 0, -EINVAL, 0, -EINVAL },
        { "/proc/net/tcp", "/proc/net/tcp", -1, 0, 0, -EINVAL, 0, -EINVAL },
        { "/proc/net/unix", "/proc/net/unix", -1, 0, 0, -EINVAL, 0, -EINVAL },
        /* Les valeurs : 8 au plus, puis la suite. */
        { "/proc/sys/vm/overcommit_memory", "/proc/sys/vm/overcommit_memory", -1, 0, 0, 1000, 0, 1000 },
        { "/proc/sys/net/core/somaxconn", "/proc/sys/net/core/somaxconn", -1, 0, 0, 1000, 0, 1000 },
        { "/sys/devices/system/cpu/online", "/sys/devices/system/cpu/online", -1, 0, 0, 1000, 0, 1000 },
        { "/sys/kernel/mm/transparent_hugepage/enabled", "/sys/kernel/mm/transparent_hugepage/enabled", -1, 0, 0, 1000, 0, 1000 },
    };
    for (unsigned i = 0; i < sizeof e / sizeof e[0]; i++) {
        int in = e[i].chemin ? open(e[i].chemin, O_RDONLY) : e[i].fd;
        long attendu_huit = e[i].huit, attendu_tube = e[i].tube_huit;
        if (e[i].huit == 1000) {
            long l = longueur_lue(e[i].chemin);
            attendu_huit = l < 8 ? l : 8;
            attendu_tube = l - attendu_huit < 8 ? l - attendu_huit : 8;
        }
        lseek(b, 0, SEEK_SET);
        lseek(a, 0, SEEK_SET);
        long p = r(sendfile(b, in, &(off_t){0}, 0)), v = r(sendfile(b, in, NULL, 0));
        if (in == sv[0])
            FAIT(write(sv[1], "xyz", 3));
        if (in == dg[0])
            FAIT(write(dg[1], "xyz", 3));
        if (in == udp)
            FAIT(sendto(udp, "xyz", 3, 0, (void *)&sa, sizeof sa));
        long h = r(sendfile(b, in, NULL, 8));
        lseek(a, 0, SEEK_SET);
        long tv = r(sendfile(t[1], in, NULL, 0)), th = r(sendfile(t[1], in, NULL, 8));
        long dans = vider(t[0]);
        char quoi[160];
        snprintf(quoi, sizeof quoi, "sendfile depuis %s : %ld %ld %ld, vers un tube %ld %ld", e[i].nom, p, v, h, tv, th);
        verifier(p == e[i].position && v == e[i].vide && h == attendu_huit && tv == e[i].tube_vide && th == attendu_tube
                 && dans == (th > 0 ? th : 0), quoi);
        if (e[i].chemin)
            close(in);
    }
    /* Les sockets vides : EAGAIN (non bloquantes). */
    verifier(r(sendfile(t[1], sv[0], NULL, 8)) == -EAGAIN && r(sendfile(t[1], dg[0], NULL, 8)) == -EAGAIN
             && r(sendfile(t[1], udp, NULL, 8)) == -EAGAIN, "sendfile d'une socket vide vers un tube : EAGAIN");
    close(t[0]);
    close(t[1]);
    close(t2[0]);
    close(t2[1]);
    close(sv[0]);
    close(sv[1]);
    close(dg[0]);
    close(dg[1]);
    close(udp);
    close(a);
    close(b);
}

/* Chaque sorte en sortie, depuis un fichier ordinaire : 8 octets (le
 * splice_write, sinon EINVAL), à la fin de l'entrée (0, avant de regarder la
 * sortie), 0 octet. */
static void sorties(void)
{
    int a = open(A, O_RDWR), b = open(B, O_RDWR | O_TRUNC);
    int t[2], sv[2], dg[2];
    FAIT(pipe2(t, O_NONBLOCK));
    FAIT(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv));
    FAIT(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, dg));
    struct {
        const char *nom;
        int fd;
        long huit;
    } s[] = {
        { "un fichier", b, 8 }, { "/dev/null", open("/dev/null", O_WRONLY), 8 }, { "/dev/zero", open("/dev/zero", O_WRONLY), 8 },
        { "/dev/full", open("/dev/full", O_WRONLY), -EINVAL }, { "/dev/urandom", open("/dev/urandom", O_WRONLY), 8 },
        { "un eventfd", eventfd(0, EFD_NONBLOCK), -EINVAL }, { "un epoll", epoll_create1(0), -EINVAL },
        { "un tube", t[1], 8 }, { "un flux AF_UNIX", sv[1], 8 }, { "des datagrammes AF_UNIX", dg[1], 8 },
    };
    for (unsigned i = 0; i < sizeof s / sizeof s[0]; i++) {
        long h = r(sendfile(s[i].fd, a, &(off_t){0}, 8)), f = r(sendfile(s[i].fd, a, &(off_t){16}, 8));
        long z = r(sendfile(s[i].fd, a, &(off_t){0}, 0));
        vider(t[0]);
        vider(sv[0]);
        vider(dg[0]);
        char quoi[160];
        snprintf(quoi, sizeof quoi, "sendfile vers %s : %ld, a la fin %ld, 0 octet %ld", s[i].nom, h, f, z);
        verifier(h == s[i].huit && f == 0 && z == 0, quoi);
    }
    int u = open("/dev/urandom", O_RDONLY), plein = open("/dev/full", O_WRONLY);
    verifier(r(sendfile(plein, u, NULL, 64)) == -EINVAL, "sendfile de /dev/urandom vers /dev/full : EINVAL");
    close(u);
    close(plein);
    for (unsigned i = 1; i < sizeof s / sizeof s[0]; i++)
        if (s[i].fd != t[1] && s[i].fd != sv[1] && s[i].fd != dg[1])
            close(s[i].fd);
    close(t[0]);
    close(t[1]);
    close(sv[0]);
    close(sv[1]);
    close(dg[0]);
    close(dg[1]);
    close(a);
    close(b);
}

/* Les positions, et leurs extrêmes : tmpfs va jusqu'à 2^63 - 1, /proc et
 * /sys jusqu'à 2^31 - 1 (MAX_NON_LFS). */
static void positions(void)
{
    int a = open(A, O_RDWR), b = open(B, O_RDWR | O_TRUNC);
    int sys = open("/proc/sys/vm/overcommit_memory", O_RDONLY), sysfs = open("/sys/devices/system/cpu/online", O_RDONLY);
    int maps = open("/proc/self/maps", O_RDONLY), zero = open("/dev/zero", O_RDONLY), ur = open("/dev/urandom", O_RDONLY);
    long l = longueur_lue("/proc/sys/vm/overcommit_memory");
    off_t o = 0x7fffffff;
    long v = r(sendfile(b, sys, &o, 8));
    verifier(v == -EOVERFLOW && o == 0x7fffffff, "sendfile de /proc/sys a la position 2^31 - 1 : EOVERFLOW, la position rendue");
    o = 0x80000000;
    long v2 = r(sendfile(b, sysfs, &o, 8));
    o = 0x80000000;
    long v3 = r(sendfile(b, maps, &o, 0));
    verifier(v2 == -EOVERFLOW && v3 == -EOVERFLOW, "sendfile de /sys, et de /proc pour 0 octet, au-dela de 2^31 - 1 : EOVERFLOW");
    o = 0x7ffffffe;
    verifier(r(sendfile(b, sys, &o, 8)) == 0, "sendfile de /proc/sys a 2^31 - 2 : ramene a 1 octet, rien a lire");
    o = 0;
    v = r(sendfile(b, sys, &o, 8));
    verifier(v == l && o == l, "sendfile de /proc/sys, position donnee : elle avance");
    o = 0;
    v = r(sendfile(b, zero, &o, 8));
    off_t o2 = 5;
    long w = r(sendfile(b, ur, &o2, 8));
    verifier(v == 8 && o == 0 && w == 8 && o2 == 5, "sendfile de /dev/zero, /dev/urandom : la position donnee ne bouge pas");
    o = 3;
    v = r(sendfile(b, a, &o, 4));
    verifier(v == 4 && o == 7 && lseek(a, 0, SEEK_CUR) == 0, "sendfile d'un fichier, position donnee : elle avance, pas celle du fichier");
    o = INT64_MAX;
    verifier(r(sendfile(b, a, &o, 0)) == 0, "sendfile a la position 2^63 - 1, 0 octet : 0");
    o = INT64_MAX - 4;
    verifier(r(sendfile(b, a, &o, 8)) == -EINVAL, "sendfile a 2^63 - 5, 8 octets : EINVAL");
    lseek(b, INT64_MAX - 4, SEEK_SET);
    v = r(sendfile(b, a, &(off_t){0}, 8));
    lseek(b, INT64_MAX - 8, SEEK_SET);
    w = r(sendfile(b, a, &(off_t){0}, 8));
    lseek(b, INT64_MAX, SEEK_SET);
    long z = r(sendfile(b, a, &(off_t){0}, 0));
    verifier(v == -EINVAL && w == 8 && z == 0, "sendfile vers un fichier a 2^63 - 5 : EINVAL ; a 2^63 - 9 : 8 ; a 2^63 - 1, 0 octet : 0");
    FAIT(ftruncate(b, 0));
    lseek(b, 0, SEEK_SET);
    verifier(r(sendfile(b, a, &(off_t){0}, (size_t)-1)) == -EINVAL && r(sendfile(b, a, &(off_t){0}, (size_t)1 << 63)) == -EINVAL,
             "sendfile d'une longueur negative : EINVAL");
    verifier(cfr(a, &(loff_t){0}, b, &(loff_t){-4096}, 8, 0) == -EINVAL && cfr(a, &(loff_t){-4096}, b, &(loff_t){0}, 8, 0) == -EINVAL,
             "copy_file_range, une position a -4096 : EINVAL (rw_verify_area)");
    verifier(cfr(a, &(loff_t){100}, b, &(loff_t){INT64_MAX}, 8, 0) == -EFBIG,
             "copy_file_range vers 2^63 - 1, rien a copier : EFBIG");
    verifier(cfr(a, &(loff_t){0}, b, &(loff_t){INT64_MAX - 4}, 8, 0) == 4, "copy_file_range vers 2^63 - 5 : 4 octets");
    FAIT(ftruncate(b, 0));
    verifier(cfr(a, &(loff_t){0}, b, &(loff_t){0}, (size_t)-1, 0) == 16, "copy_file_range d'une longueur de 2^64 - 1 : ramenee a l'entree");
    /* La position rendue au programme, même après une erreur. */
    off_t *lecture_seule = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    verifier(r(sendfile(b, 999, lecture_seule, 8)) == -EFAULT && r(sendfile(b, a, lecture_seule, 8)) == -EFAULT,
             "sendfile, la position dans une page en lecture seule : EFAULT, meme apres une erreur");
    munmap(lecture_seule, 4096);
    int tcp = open("/proc/net/tcp", O_RDONLY), un = open("/proc/net/unix", O_RDONLY);
    verifier(r(lseek(tcp, 0, SEEK_END)) == -EINVAL && r(lseek(un, 0, SEEK_END)) == -EINVAL,
             "lseek SEEK_END de /proc/net/tcp et unix : EINVAL (des sequences)");
    close(tcp);
    close(un);
    int c = open(C, O_RDWR | O_CREAT | O_TRUNC | O_APPEND, 0600);
    verifier(r(sendfile(c, a, &(off_t){0}, 0)) == -EINVAL, "sendfile vers O_APPEND, 0 octet : EINVAL");
    close(c);
    lseek(a, 16, SEEK_SET);
    verifier(r(sendfile(a, a, &(off_t){0}, 8)) == 8 && lseek(a, 0, SEEK_CUR) == 24, "sendfile d'un fichier vers lui-meme : a sa position");
    FAIT(ftruncate(a, 16));
    close(sys);
    close(sysfs);
    close(maps);
    close(zero);
    close(ur);
    close(a);
    close(b);
}

/* Les cases d'un tube : elles désignent les pages du fichier (ce qui s'y
 * écrit avant la lecture se lit ; une troncature laisse l'ancienne), la page
 * de zéros pour un trou ; jamais fusionnables, jamais des paquets ; une
 * seule lecture, au plus ce que tiennent les cases libres. */
static void cases(void)
{
    int a = open(A, O_RDWR);
    int t[2];
    FAIT(pipe2(t, O_NONBLOCK));
    char lu[70000];
    long n;
    FAIT(sendfile(t[1], a, &(off_t){0}, 8));
    FAIT(pwrite(a, "XYZ", 3, 0));
    n = read(t[0], lu, sizeof lu);
    verifier(n == 8 && memcmp(lu, "XYZ34567", 8) == 0, "sendfile vers un tube, puis pwrite : le tube rend la page ecrite");
    FAIT(pwrite(a, "012", 3, 0));
    FAIT(sendfile(t[1], a, &(off_t){0}, 8));
    FAIT(ftruncate(a, 0));
    FAIT(ftruncate(a, 16));
    FAIT(pwrite(a, "QQ", 2, 0));
    n = read(t[0], lu, sizeof lu);
    verifier(n == 8 && memcmp(lu, "01234567", 8) == 0, "sendfile, ftruncate, pwrite : le tube rend l'ancienne page");
    FAIT(ftruncate(a, 0));
    FAIT(ftruncate(a, 8192));
    FAIT(sendfile(t[1], a, &(off_t){0}, 8));
    FAIT(pwrite(a, "TROU", 4, 0));
    n = read(t[0], lu, sizeof lu);
    verifier(n == 8 && memcmp(lu, "\0\0\0\0\0\0\0\0", 8) == 0, "sendfile d'un trou : des zeros, meme ecrit ensuite");
    static char grand[5 * 4096];
    for (size_t i = 0; i < sizeof grand; i++)
        grand[i] = (char)('a' + i % 23);
    FAIT(ftruncate(a, 0));
    FAIT(pwrite(a, grand, sizeof grand, 0));
    int ad = open(A, O_RDONLY | O_DIRECT);
    if (ad >= 0) {
        FAIT(sendfile(t[1], ad, &(off_t){0}, 8));
        FAIT(pwrite(a, "XYZ", 3, 0));
        n = read(t[0], lu, sizeof lu);
        verifier(n == 8 && memcmp(lu, grand, 8) == 0, "sendfile d'un fichier en O_DIRECT : une copie");
        FAIT(pwrite(a, grand, 3, 0));
        close(ad);
    } else
        verifier(0, "ouvrir en O_DIRECT");
    fcntl(t[1], F_SETPIPE_SZ, 4096);
    long e = r(write(t[1], "xy", 2)), s = r(sendfile(t[1], a, &(off_t){0}, 6));
    n = read(t[0], lu, sizeof lu);
    verifier(e == 2 && s == -EAGAIN && n == 2, "tube d'une case : write de 2, puis sendfile : EAGAIN");
    s = r(sendfile(t[1], a, &(off_t){0}, 6));
    e = r(write(t[1], "xy", 2));
    n = read(t[0], lu, sizeof lu);
    verifier(s == 6 && e == -EAGAIN && n == 6, "tube d'une case : sendfile de 6, puis write : EAGAIN (pas de fusion)");
    fcntl(t[1], F_SETPIPE_SZ, 8192);
    s = r(sendfile(t[1], a, &(off_t){0}, 3 * 4096));
    n = vider(t[0]);
    long s2 = r(sendfile(t[1], a, &(off_t){4000}, 8192));
    long n2 = vider(t[0]);
    verifier(s == 8192 && n == 8192 && s2 == 4192 && n2 == 4192, "tube de deux cases : sendfile de 3 pages, 8192 ; a 4000, 96 + 4096");
    int zero = open("/dev/zero", O_RDONLY);
    s = r(sendfile(t[1], zero, NULL, 100000));
    n = vider(t[0]);
    verifier(s == 8192 && n == 8192, "tube de deux cases : sendfile de /dev/zero, 8192");
    close(zero);
    fcntl(t[1], F_SETPIPE_SZ, 65536);
    s = r(sendfile(t[1], a, &(off_t){15}, 1));
    e = r(write(t[1], "0123456789", 10));
    n = read(t[0], lu, sizeof lu);
    verifier(s == 1 && e == 10 && n == 11, "sendfile d'un octet puis write de 10 : 11 a lire");
    off_t o = 2;
    s = r(sendfile(t[1], a, &o, 4));
    n = read(t[0], lu, sizeof lu);
    verifier(s == 4 && o == 6 && n == 4 && memcmp(lu, grand + 2, 4) == 0, "sendfile vers un tube, position donnee : elle avance");
    int p[2];
    FAIT(pipe2(p, O_NONBLOCK | O_DIRECT));
    FAIT(write(p[1], "ab", 2));
    FAIT(sendfile(p[1], a, &(off_t){0}, 6));
    FAIT(sendfile(p[1], a, &(off_t){6}, 4));
    long l1 = read(p[0], lu, 100), l2 = read(p[0], lu, 100);
    FAIT(sendfile(p[1], a, &(off_t){0}, 6));
    FAIT(sendfile(p[1], a, &(off_t){6}, 4));
    long l3 = read(p[0], lu, 3), l4 = read(p[0], lu, 100);
    verifier(l1 == 2 && l2 == 10 && l3 == 3 && l4 == 7, "tube O_DIRECT : les cases de sendfile ne sont pas des paquets");
    verifier(r(sendfile(t[1], t[0], NULL, 8)) == -EINVAL, "sendfile d'un tube vers lui-meme : EINVAL");
    close(p[0]);
    close(p[1]);
    int q[2];
    FAIT(pipe(q));
    close(q[0]);
    int nul = open("/dev/null", O_RDONLY);
    verifier(r(sendfile(q[1], nul, NULL, 8)) == -EPIPE && r(sendfile(q[1], a, NULL, 0)) == -EPIPE,
             "sendfile vers un tube sans lecteur : EPIPE d'abord, meme de /dev/null ou pour 0 octet");
    close(q[1]);
    fcntl(t[1], F_SETPIPE_SZ, 4096);
    FAIT(write(t[1], lu, 4096));
    verifier(r(sendfile(t[1], a, &(off_t){0}, 8)) == -EAGAIN && r(sendfile(t[1], a, &(off_t){0}, 0)) == -EAGAIN
             && r(sendfile(t[1], nul, NULL, 8)) == -EAGAIN, "sendfile vers un tube plein : EAGAIN d'abord");
    close(nul);
    close(t[0]);
    close(t[1]);
    FAIT(ftruncate(a, 0));
    FAIT(pwrite(a, "0123456789abcdef", 16, 0));
    close(a);
}

/* Les sockets : vers un tube (une case par morceau reçu), et en sortie, un
 * datagramme par ronde du tube interne (seize pages). */
static void sockets(void)
{
    int a = open(A, O_RDWR);
    static char grand[200000];
    memset(grand, 'g', sizeof grand);
    FAIT(pwrite(a, grand, sizeof grand, 0));
    int t[2], sv[2], dg[2];
    FAIT(pipe2(t, O_NONBLOCK));
    FAIT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    FAIT(socketpair(AF_UNIX, SOCK_DGRAM, 0, dg));
    char lu[1 << 17];
    verifier(r(sendfile(t[1], sv[0], NULL, 8)) == -EAGAIN, "flux AF_UNIX bloquant vers un tube non bloquant, vide : EAGAIN");
    /* copy_splice_read ne regarde que la socket : elle attend (ici, son
     * délai SO_RCVTIMEO, puis EAGAIN). */
    struct timeval delai = { .tv_usec = 100000 };
    FAIT(setsockopt(dg[0], SOL_SOCKET, SO_RCVTIMEO, &delai, sizeof delai));
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long v = r(sendfile(t[1], dg[0], NULL, 8));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(v == -EAGAIN && ms >= 90, "datagrammes AF_UNIX bloquants vers un tube non bloquant : on attend (SO_RCVTIMEO)");
    delai.tv_usec = 0;
    FAIT(setsockopt(dg[0], SOL_SOCKET, SO_RCVTIMEO, &delai, sizeof delai));
    FAIT(write(sv[1], "abc", 3));
    FAIT(write(sv[1], "def", 3));
    v = r(sendfile(t[1], sv[0], NULL, 8));
    verifier(v == 6 && vider(t[0]) == 6, "flux AF_UNIX, deux envois de 3 : 6");
    FAIT(write(dg[1], "abc", 3));
    FAIT(write(dg[1], "def", 3));
    v = r(sendfile(t[1], dg[0], NULL, 8));
    long w = r(sendfile(t[1], dg[0], NULL, 2));
    verifier(v == 3 && w == 2 && vider(t[0]) == 5 && r(recv(dg[0], lu, 10, MSG_DONTWAIT)) == -EAGAIN,
             "datagrammes AF_UNIX : un a la fois, coupe a la longueur");
    fcntl(t[1], F_SETPIPE_SZ, 4096);
    FAIT(write(sv[1], "abc", 3));
    FAIT(write(sv[1], "def", 3));
    v = r(sendfile(t[1], sv[0], NULL, 8));
    verifier(v == 3 && vider(t[0]) == 3 && read(sv[0], lu, 10) == 3, "tube d'une case, flux AF_UNIX : un envoi, le reste attend");
    close(t[0]);
    close(t[1]);
    int taille = 1 << 20;
    FAIT(setsockopt(dg[0], SOL_SOCKET, SO_SNDBUF, &taille, sizeof taille));
    FAIT(setsockopt(dg[1], SOL_SOCKET, SO_RCVBUF, &taille, sizeof taille));
    v = r(sendfile(dg[0], a, &(off_t){0}, 10000));
    long l1 = r(recv(dg[1], lu, sizeof lu, MSG_DONTWAIT)), l2 = r(recv(dg[1], lu, sizeof lu, MSG_DONTWAIT));
    verifier(v == 10000 && l1 == 10000 && l2 == -EAGAIN, "sendfile de 10000 octets vers des datagrammes AF_UNIX : un datagramme");
    v = r(sendfile(dg[0], a, &(off_t){0}, 100000));
    l1 = r(recv(dg[1], lu, sizeof lu, MSG_DONTWAIT));
    l2 = r(recv(dg[1], lu, sizeof lu, MSG_DONTWAIT));
    verifier(v == 100000 && l1 == 65536 && l2 == 34464, "sendfile de 100000 octets : un datagramme par ronde de seize pages");
    int u = socket(AF_INET, SOCK_DGRAM, 0), x = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ad = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001) };
    socklen_t l = sizeof ad;
    FAIT(bind(u, (void *)&ad, sizeof ad));
    FAIT(getsockname(u, (void *)&ad, &l));
    FAIT(connect(x, (void *)&ad, sizeof ad));
    v = r(sendfile(x, a, &(off_t){0}, 10000));
    l1 = r(recv(u, lu, sizeof lu, MSG_DONTWAIT));
    l2 = r(recv(u, lu, sizeof lu, MSG_DONTWAIT));
    verifier(v == 10000 && l1 == 10000 && l2 == -EAGAIN, "sendfile de 10000 octets vers UDP : un datagramme");
    /* TCP, par la boucle locale, vers un tube. */
    int ecoute = socket(AF_INET, SOCK_STREAM, 0), cl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in at = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001) };
    l = sizeof at;
    FAIT(bind(ecoute, (void *)&at, sizeof at));
    FAIT(listen(ecoute, 1));
    FAIT(getsockname(ecoute, (void *)&at, &l));
    FAIT(connect(cl, (void *)&at, sizeof at));
    int sr = accept4(ecoute, NULL, NULL, SOCK_NONBLOCK);
    int tt[2];
    FAIT(pipe2(tt, O_NONBLOCK));
    FAIT(write(cl, "abc", 3));
    usleep(20000);
    v = r(sendfile(tt[1], sr, NULL, 8));
    w = r(sendfile(tt[1], sr, NULL, 8));
    verifier(v == 3 && w == -EAGAIN && vider(tt[0]) == 3, "sendfile d'une socket TCP vers un tube : ce qui est arrive, puis EAGAIN");
    close(tt[0]);
    close(tt[1]);
    close(sr);
    close(cl);
    close(ecoute);
    close(u);
    close(x);
    close(sv[0]);
    close(sv[1]);
    close(dg[0]);
    close(dg[1]);
    FAIT(ftruncate(a, 0));
    FAIT(pwrite(a, "0123456789abcdef", 16, 0));
    close(a);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    const char *lieu = argc > 1 ? argv[1] : "/tmp";
    snprintf(A, sizeof A, "%s/copies-a", lieu);
    snprintf(B, sizeof B, "%s/copies-b", lieu);
    snprintf(C, sizeof C, "%s/copies-c", lieu);
    ecrire_fichier(A, "0123456789abcdef", 16);
    ecrire_fichier(B, "", 0);
    int a = open(A, O_RDWR), b = open(B, O_RDWR), ap = open(B, O_WRONLY | O_APPEND), ro = open(B, O_RDONLY);
    int wo = open(A, O_WRONLY), chemin = open(A, O_PATH), dossier = open("/tmp", O_RDONLY | O_DIRECTORY);
    int proc = open("/proc/self/statm", O_RDONLY), nul = open("/dev/null", O_RDWR), zero = open("/dev/zero", O_RDONLY);
    int t[2], sv[2];
    if (pipe(t) != 0 || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        verifier(0, "tube et paire de sockets");
    int ev = eventfd(0, 0);

    /* copy_file_range : une copie, ses positions avancées. */
    loff_t pa = 4, pb = 0;
    verifier(cfr(a, &pa, b, &pb, 8, 0) == 8 && pa == 12 && pb == 8 && contenu(B, "456789ab", 8),
             "copy_file_range de 8 octets, les positions donnees avancent");
    verifier(lseek(a, 0, SEEK_CUR) == 0 && lseek(b, 0, SEEK_CUR) == 0, "copy_file_range : les positions des fichiers restent");
    /* Sans positions : celles des fichiers, qui avancent. */
    lseek(a, 10, SEEK_SET);
    lseek(b, 8, SEEK_SET);
    verifier(cfr(a, NULL, b, NULL, 100, 0) == 6 && lseek(a, 0, SEEK_CUR) == 16 && lseek(b, 0, SEEK_CUR) == 14
             && contenu(B, "456789ababcdef", 14), "copy_file_range sans positions, ramenee a la fin de l'entree");
    verifier(cfr(a, &(loff_t){100}, b, &(loff_t){0}, 8, 0) == 0, "copy_file_range au-dela de la fin : 0");
    verifier(cfr(a, &(loff_t){0}, b, &(loff_t){0}, 0, 0) == 0, "copy_file_range de 0 octet : 0");
    /* Les refus, dans l'ordre de Linux. */
    verifier(cfr(a, &(loff_t){0}, b, &(loff_t){0}, 8, 1) == -EINVAL, "copy_file_range, des drapeaux : EINVAL");
    verifier(cfr(a, (loff_t *)8, b, NULL, 8, 1) == -EFAULT, "copy_file_range, position fautive et drapeaux : EFAULT d'abord");
    verifier(cfr(a, &(loff_t){0}, ap, NULL, 8, 0) == -EBADF, "copy_file_range vers O_APPEND : EBADF");
    verifier(cfr(a, &(loff_t){0}, ro, NULL, 8, 0) == -EBADF, "copy_file_range vers un fichier en lecture : EBADF");
    verifier(cfr(wo, &(loff_t){0}, b, NULL, 8, 0) == -EBADF, "copy_file_range depuis un fichier en ecriture : EBADF");
    verifier(cfr(t[0], NULL, b, NULL, 8, 0) == -EINVAL && cfr(a, &(loff_t){0}, t[1], NULL, 8, 0) == -EINVAL,
             "copy_file_range d'un tube, vers un tube : EINVAL");
    verifier(cfr(a, &(loff_t){0}, sv[0], NULL, 8, 0) == -EINVAL && cfr(a, &(loff_t){0}, nul, NULL, 8, 0) == -EINVAL,
             "copy_file_range vers une socket, /dev/null : EINVAL");
    verifier(cfr(a, &(loff_t){0}, dossier, NULL, 8, 0) == -EISDIR, "copy_file_range vers un dossier : EISDIR");
    verifier(cfr(a, &(loff_t){0}, chemin, NULL, 8, 0) == -EBADF, "copy_file_range vers O_PATH : EBADF");
    verifier(cfr(proc, NULL, b, &(loff_t){0}, 8, 0) == -EXDEV, "copy_file_range de /proc : EXDEV");
    verifier(cfr(a, &(loff_t){0}, a, &(loff_t){4}, 8, 0) == -EINVAL, "copy_file_range dans le meme fichier, chevauche : EINVAL");
    verifier(cfr(a, &(loff_t){0}, a, &(loff_t){16}, 8, 0) == 8 && contenu(A, "0123456789abcdef01234567", 24),
             "copy_file_range dans le meme fichier, sans chevauchement");
    verifier(cfr(a, &(loff_t){-1}, b, &(loff_t){0}, 8, 0) == -EOVERFLOW, "copy_file_range, position negative : EOVERFLOW");
    verifier(cfr(a, &(loff_t){-1}, b, &(loff_t){0}, 0, 0) == -EINVAL, "copy_file_range de 0 octet, position negative : EINVAL");

    /* sendfile : vers un fichier, un tube, une socket, /dev/null. */
    ecrire_fichier(B, "", 0);
    lseek(b, 0, SEEK_SET);
    lseek(a, 0, SEEK_SET);
    off_t o = 2;
    verifier(r(sendfile(b, a, &o, 4)) == 4 && o == 6 && lseek(a, 0, SEEK_CUR) == 0 && lseek(b, 0, SEEK_CUR) == 4
             && contenu(B, "2345", 4), "sendfile vers un fichier, la position donnee avance, celle de l'entree reste");
    verifier(r(sendfile(b, a, NULL, 3)) == 3 && lseek(a, 0, SEEK_CUR) == 3 && contenu(B, "2345012", 7),
             "sendfile sans position : celle de l'entree avance");
    char lu[16] = {0};
    verifier(r(sendfile(t[1], a, &(off_t){10}, 6)) == 6 && read(t[0], lu, sizeof lu) == 6 && memcmp(lu, "abcdef", 6) == 0,
             "sendfile vers un tube");
    verifier(r(sendfile(sv[0], a, &(off_t){0}, 5)) == 5 && read(sv[1], lu, sizeof lu) == 5 && memcmp(lu, "01234", 5) == 0,
             "sendfile vers une socket");
    verifier(r(sendfile(nul, a, &(off_t){0}, 8)) == 8, "sendfile vers /dev/null");
    verifier(r(sendfile(b, zero, NULL, 4)) == 4, "sendfile depuis /dev/zero");
    verifier(r(sendfile(ap, a, &(off_t){0}, 8)) == -EINVAL, "sendfile vers O_APPEND : EINVAL");
    verifier(r(sendfile(ev, a, &(off_t){0}, 8)) == -EINVAL, "sendfile vers un eventfd : EINVAL");
    verifier(r(sendfile(b, t[0], NULL, 8)) == -EINVAL && r(sendfile(b, t[0], &(off_t){0}, 8)) == -ESPIPE,
             "sendfile depuis un tube : EINVAL, ESPIPE avec une position");
    verifier(r(sendfile(b, nul, NULL, 8)) == -EINVAL && r(sendfile(b, proc, NULL, 8)) == -EINVAL
             && r(sendfile(b, dossier, NULL, 8)) == -EINVAL, "sendfile depuis /dev/null, /proc, un dossier : EINVAL");
    verifier(r(sendfile(b, a, &(off_t){-1}, 8)) == -EINVAL, "sendfile, position negative : EINVAL");
    verifier(r(sendfile(b, wo, &(off_t){0}, 8)) == -EBADF, "sendfile depuis un fichier en ecriture : EBADF");
    verifier(r(sendfile(b, a, (off_t *)8, 8)) == -EFAULT, "sendfile, position fautive : EFAULT");

    /* Plusieurs pages, par l'un et l'autre. */
    static char grand[3 * 4096 + 100];
    for (size_t i = 0; i < sizeof grand; i++)
        grand[i] = (char)('a' + i % 23);
    ecrire_fichier(A, grand, sizeof grand);
    ecrire_fichier(B, "", 0);
    verifier(cfr(a, &(loff_t){0}, b, &(loff_t){0}, sizeof grand, 0) == (long)sizeof grand && contenu(B, grand, sizeof grand),
             "copy_file_range de trois pages et 100 octets");
    ecrire_fichier(B, "", 0);
    lseek(b, 0, SEEK_SET);
    verifier(r(sendfile(b, a, &(off_t){0}, sizeof grand)) == (long)sizeof grand && contenu(B, grand, sizeof grand),
             "sendfile de trois pages et 100 octets");

    /* fadvise64. */
    verifier(r(posix_fadvise(a, 0, 0, POSIX_FADV_SEQUENTIAL) == 0 ? 0 : -1) == 0
             && posix_fadvise(a, -5, 10, POSIX_FADV_DONTNEED) == 0, "fadvise64 d'un fichier : 0, une position negative aussi");
    verifier(r(syscall(SYS_fadvise64, a, 0, 0, 99)) == -EINVAL && r(syscall(SYS_fadvise64, a, 0, -1L, 0)) == -EINVAL,
             "fadvise64, conseil inconnu, longueur negative : EINVAL");
    verifier(r(syscall(SYS_fadvise64, t[0], 0, 0, 99)) == -ESPIPE, "fadvise64 d'un tube : ESPIPE, avant le conseil");
    verifier(r(syscall(SYS_fadvise64, chemin, 0, 0, 0)) == -EBADF && r(syscall(SYS_fadvise64, 999, 0, 0, 0)) == -EBADF,
             "fadvise64 d'O_PATH, d'un descripteur ferme : EBADF");
    verifier(r(syscall(SYS_fadvise64, sv[0], 0, 0, 4)) == 0 && r(syscall(SYS_fadvise64, nul, 0, 0, 4)) == 0,
             "fadvise64 d'une socket, de /dev/null : 0");

    ecrire_fichier(A, "0123456789abcdef", 16);
    entrees(lieu);
    sorties();
    positions();
    cases();
    sockets();
    unlink(A);
    unlink(B);
    unlink(C);
    if (ecarts == 0)
        printf("[linux] copies : toutes les verifications : ok\n");
    return ecarts != 0;
}
