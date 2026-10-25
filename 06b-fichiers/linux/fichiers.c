/*
 * Les appels système des fichiers, contre ce qu'en fait le vrai Linux.
 * Comme memoire.c : ce programme tourne dans notre noyau ET sur l'hôte
 * (`make tests-hote` le lance), et chaque ligne doit dire « ok » des deux
 * côtés. C'est la vérification que nos codes d'erreur sont ceux de Linux.
 *
 * Rien ici ne doit dépendre du système de fichiers de l'hôte (ext4,
 * tmpfs, overlay : ni l'ordre de readdir, ni st_blocks, ni les numéros
 * d'inode), ni de qui le lance : les cas de droits sont sautés en root, et
 * ce qui suppose notre archive (/etc/bonjour.txt) n'est vérifié que si elle
 * est là. Tout se passe dans /tmp, sous des noms à ce programme
 * (fichiers.<pid>.*), effacés à la fin : chez nous, le noyau vérifie ensuite
 * que toute la mémoire est revenue.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] fichiers : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    if (!ok)
        echecs++;
}

/* L'appel `r` a-t-il échoué avec l'erreur `e` ? */
#define ERREUR(r, e) ((r) == -1 && errno == (e))

static char nom_a[64];

/* Un nom de fichier à nous, dans /tmp. */
static const char *nom(char *tampon, const char *suffixe)
{
    snprintf(tampon, 64, "/tmp/fichiers.%d.%s", getpid(), suffixe);
    return tampon;
}

static void ecrire_lire(void)
{
    const char *a = nom(nom_a, "a");
    int fd = open(a, O_CREAT | O_EXCL | O_RDWR, 0644);
    verifier(fd >= 3, "creer un fichier (O_CREAT | O_EXCL)");
    errno = 0;
    verifier(ERREUR(open(a, O_CREAT | O_EXCL | O_RDWR, 0644), EEXIST), "le recreer avec O_EXCL : EEXIST");
    char lu[16] = {0};
    verifier(write(fd, "bonjour", 7) == 7 && lseek(fd, 0, SEEK_SET) == 0 && read(fd, lu, sizeof lu) == 7
             && memcmp(lu, "bonjour", 7) == 0, "ecrire, revenir au debut, relire");
    verifier(read(fd, lu, sizeof lu) == 0, "a la fin : 0 octet");
    struct stat st;
    verifier(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0644 && st.st_size == 7
             && st.st_nlink == 1 && st.st_uid == getuid(), "fstat : fichier ordinaire, 0644, 7 octets, a nous");

    /* La position est celle du fichier ouvert : partagée par dup. */
    int copie = dup(fd);
    lseek(fd, 2, SEEK_SET);
    verifier(copie > fd && lseek(copie, 0, SEEK_CUR) == 2, "dup partage la position");
    close(copie);

    /* pread et pwrite ne bougent pas la position. */
    memset(lu, 0, sizeof lu);
    verifier(pread(fd, lu, 3, 3) == 3 && memcmp(lu, "jou", 3) == 0 && lseek(fd, 0, SEEK_CUR) == 2,
             "pread lit ailleurs sans bouger la position");
    verifier(pwrite(fd, "B", 1, 0) == 1 && lseek(fd, 0, SEEK_CUR) == 2 && pread(fd, lu, 1, 0) == 1 && lu[0] == 'B',
             "pwrite ecrit ailleurs sans bouger la position");

    /* Un trou : écrire loin, la taille suit, le trou se lit à zéro. */
    char zeros[100], trou[100];
    memset(zeros, 0, sizeof zeros);
    memset(trou, 1, sizeof trou);
    verifier(pwrite(fd, "x", 1, 10000) == 1 && fstat(fd, &st) == 0 && st.st_size == 10001
             && pread(fd, trou, sizeof trou, 5000) == sizeof trou && memcmp(trou, zeros, sizeof trou) == 0,
             "ecrire au-dela de la fin : un trou, lu a zero");
    errno = 0;
    verifier(lseek(fd, 0, SEEK_DATA) == 0, "SEEK_DATA depuis le debut : 0");
    errno = 0;
    verifier(ERREUR(lseek(fd, 20000, SEEK_DATA), ENXIO), "SEEK_DATA au-dela de la fin : ENXIO");
    errno = 0;
    verifier(lseek(fd, 0, SEEK_END) == 10001 && ERREUR(lseek(fd, -1, SEEK_SET), EINVAL),
             "SEEK_END, et une position negative : EINVAL");

    /* readv et writev : plusieurs morceaux d'un coup. */
    struct iovec v[2] = {{"abc", 3}, {"defg", 4}};
    lseek(fd, 0, SEEK_SET);
    verifier(writev(fd, v, 2) == 7, "writev de deux morceaux");
    char x[3], y[4];
    struct iovec w[2] = {{x, 3}, {y, 4}};
    lseek(fd, 0, SEEK_SET);
    verifier(readv(fd, w, 2) == 7 && memcmp(x, "abc", 3) == 0 && memcmp(y, "defg", 4) == 0, "readv de deux morceaux");
    /* Un morceau dans la moitié haute (le noyau) : rien n'est écrit,
     * EFAULT, même si le premier morceau était bon (Linux vérifie tout
     * avant d'écrire). */
    struct iovec mauvais[2] = {{"zzz", 3}, {(void *)0xffff800000000000UL, 4}};
    lseek(fd, 0, SEEK_SET);
    errno = 0;
    verifier(ERREUR(writev(fd, mauvais, 2), EFAULT) && pread(fd, x, 3, 0) == 3 && memcmp(x, "abc", 3) == 0,
             "writev avec un morceau hors des adresses : EFAULT, rien d'ecrit");

    /* FIONREAD : ce qu'il reste à lire ; TCGETS (isatty) : ENOTTY. */
    int reste = -1;
    lseek(fd, 10000, SEEK_SET);
    verifier(ioctl(fd, FIONREAD, &reste) == 0 && reste == 1, "ioctl FIONREAD : ce qu'il reste");
    errno = 0;
    verifier(!isatty(fd) && errno == ENOTTY, "isatty d'un fichier : ENOTTY");
    verifier(flock(fd, LOCK_EX) == 0 && flock(fd, LOCK_UN) == 0, "flock pose et retire un verrou");
    errno = 0;
    verifier(ERREUR(flock(fd, 0), EINVAL), "flock, operation inconnue : EINVAL");
    close(fd);

    /* O_APPEND : toujours à la fin, même après lseek. */
    fd = open(a, O_WRONLY | O_APPEND);
    lseek(fd, 0, SEEK_SET);
    verifier(write(fd, "!", 1) == 1 && fstat(fd, &st) == 0 && st.st_size == 10002, "O_APPEND ecrit a la fin");
    verifier((fcntl(fd, F_GETFL) & (O_ACCMODE | O_APPEND)) == (O_WRONLY | O_APPEND), "F_GETFL : O_WRONLY | O_APPEND");
    errno = 0;
    verifier(ERREUR(read(fd, lu, 1), EBADF), "lire un fichier ouvert en ecriture seule : EBADF");
    close(fd);
    /* O_TRUNC : le fichier revient à zéro octet. */
    fd = open(a, O_RDWR | O_TRUNC);
    verifier(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 0, "O_TRUNC vide le fichier");
    verifier(close(fd) == 0, "fermer");
    errno = 0;
    verifier(ERREUR(close(fd), EBADF), "fermer deux fois : EBADF");
}

static void erreurs(void)
{
    const char *a = nom_a;
    errno = 0;
    verifier(ERREUR(open("/tmp/fichiers-inexistant/x", O_RDONLY), ENOENT), "un chemin qui n'existe pas : ENOENT");
    char sous[80];
    snprintf(sous, sizeof sous, "%s/x", a);
    errno = 0;
    verifier(ERREUR(open(sous, O_RDONLY), ENOTDIR), "sous un fichier : ENOTDIR");
    errno = 0;
    verifier(ERREUR(open(a, O_RDONLY | O_DIRECTORY), ENOTDIR), "O_DIRECTORY sur un fichier : ENOTDIR");
    errno = 0;
    verifier(ERREUR(open("/tmp", O_RDWR), EISDIR), "un dossier en ecriture : EISDIR");
    errno = 0;
    verifier(ERREUR(open("/tmp/fichiers-neuf", O_CREAT | O_DIRECTORY | O_RDWR, 0644), EINVAL),
             "O_CREAT avec O_DIRECTORY : EINVAL");
    char barre[80];
    snprintf(barre, sizeof barre, "/tmp/fichiers.%d.neuf/", getpid());
    errno = 0;
    verifier(ERREUR(open(barre, O_CREAT | O_RDWR, 0644), EISDIR), "O_CREAT avec une barre finale : EISDIR");
    int dossier = open("/tmp", O_RDONLY | O_DIRECTORY);
    char octet;
    errno = 0;
    verifier(dossier >= 0 && ERREUR(read(dossier, &octet, 1), EISDIR), "lire un dossier : EISDIR");
    errno = 0;
    verifier(ERREUR(write(dossier, "x", 1), EBADF), "ecrire dans un dossier ouvert en lecture : EBADF");
    close(dossier);
    errno = 0;
    verifier(ERREUR(access(a, X_OK), EACCES) && access(a, R_OK | W_OK) == 0, "access : X_OK refuse, R_OK | W_OK permis");
    errno = 0;
    verifier(ERREUR(access(a, 8), EINVAL), "access, droit inconnu : EINVAL");
}

/* close_range avec CLOSE_RANGE_CLOEXEC, par l'appel direct (pas
 * d'enveloppe dans toutes les glibc) : le descripteur reste ouvert, marqué
 * FD_CLOEXEC. */
static int syscall_close_range_cloexec(int fd)
{
    if (syscall(SYS_close_range, fd, fd, 4 /* CLOSE_RANGE_CLOEXEC */) != 0)
        return 0;
    return fcntl(fd, F_GETFD) == FD_CLOEXEC;
}

static void descripteurs(void)
{
    /* La limite par défaut de Linux, posée par le test lui-même : l'hôte
     * peut en avoir une autre. */
    struct rlimit l = {1024, 4096};
    verifier(setrlimit(RLIMIT_NOFILE, &l) == 0, "RLIMIT_NOFILE a 1024");
    int fd = open(nom_a, O_RDONLY);
    errno = 0;
    verifier(dup2(fd, 1023) == 1023 && ERREUR(dup2(fd, 1024), EBADF), "dup2 a 1023 permis, a 1024 : EBADF");
    close(1023);
    errno = 0;
    verifier(ERREUR(fcntl(fd, F_DUPFD, 1024), EINVAL), "F_DUPFD au-dela de la limite : EINVAL");
    int haut = fcntl(fd, F_DUPFD, 100);
    verifier(haut == 100, "F_DUPFD : le plus petit numero libre a partir de 100");
    close(haut);
    errno = 0;
    verifier(ERREUR(dup3(fd, fd, 0), EINVAL) && dup2(fd, fd) == fd, "dup3 sur lui-meme : EINVAL ; dup2 : permis");
    verifier(fcntl(fd, F_GETFD) == 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC,
             "F_GETFD et F_SETFD : FD_CLOEXEC");
    int ce = open(nom_a, O_RDONLY | O_CLOEXEC);
    verifier(fcntl(ce, F_GETFD) == FD_CLOEXEC, "O_CLOEXEC pose FD_CLOEXEC");
    fcntl(fd, F_SETFD, 0);
    verifier(syscall_close_range_cloexec(fd), "close_range avec CLOSE_RANGE_CLOEXEC");
    close(ce);
    /* EMFILE : une limite de 8 descripteurs, puis on ouvre jusqu'au refus. */
    struct rlimit petite = {8, 4096};
    setrlimit(RLIMIT_NOFILE, &petite);
    int ouverts[8], n = 0, dernier;
    errno = 0;
    while ((dernier = open(nom_a, O_RDONLY)) >= 0 && n < 8)
        ouverts[n++] = dernier;
    verifier(dernier == -1 && errno == EMFILE, "plus de numero libre : EMFILE");
    while (n > 0)
        close(ouverts[--n]);
    setrlimit(RLIMIT_NOFILE, &l);
    close(fd);
}

/* Les bornes de read, write et des appels voisins : ce que Linux vérifie
 * avant de transférer, et ce qu'il rend quand le tampon s'arrête au milieu.
 * Un tampon de 100 octets valides suivis d'une page absente : une page
 * anonyme, puis un trou (la page d'après rendue par munmap). */
static void bornes(void)
{
    char *m = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(m, 'x', 4096);
    munmap(m + 4096, 4096);
    char *cent = m + 4096 - 100;
    char z[8192];
    struct stat st;
    int fd = open(nom_a, O_RDWR | O_TRUNC);
    verifier(pwrite(fd, cent, 300, 0) == 100 && fstat(fd, &st) == 0 && st.st_size == 100,
             "pwrite, tampon coupe apres 100 octets : 100, et le fichier les a");
    memset(z, 'a', sizeof z);
    int x = 0;
    verifier(pwrite(fd, z, sizeof z, 0) == sizeof z && pwrite(fd, cent, 300, 10) == 100 && pread(fd, z, 400, 0) == 400,
             "pwrite coupe au milieu du fichier : 100");
    for (int i = 0; i < 400; i++)
        x += z[i] == 'x';
    verifier(x == 100, "les 100 octets sont ecrits, pas un de plus");
    verifier(pread(fd, cent, 300, 0) == 100, "pread dans un tampon coupe : 100");
    int zero = open("/dev/zero", O_RDONLY), null = open("/dev/null", O_RDWR);
    verifier(read(zero, cent, 300) == 100, "read de /dev/zero dans un tampon coupe : 100");
    /* access_ok : toute la plage, même vide, avant de rien toucher. */
    errno = 0;
    verifier(ERREUR(syscall(SYS_read, zero, z, 1UL << 62), EFAULT), "read de 2^62 octets : EFAULT, rien d'ecrit");
    errno = 0;
    verifier(ERREUR(syscall(SYS_write, null, z, (size_t)-1), EFAULT), "write de SIZE_MAX octets : EFAULT");
    errno = 0;
    verifier(ERREUR(syscall(SYS_read, fd, (void *)0xffff800000000000UL, 0), EFAULT), "read de 0 octet vers le noyau : EFAULT");
    verifier(syscall(SYS_write, null, NULL, 10) == 10, "write de NULL vers /dev/null : 10 (le tampon n'est pas lu)");
    /* La position plus la longueur sous 2^63 : EINVAL, avant le plafond. */
    errno = 0;
    verifier(ERREUR(pwrite(fd, z, 100, INT64_MAX - 10), EINVAL) && ERREUR(pread(fd, z, 100, INT64_MAX - 10), EINVAL),
             "pwrite et pread a 2^63 - 11 : EINVAL");
    verifier(pwrite(fd, z, 0, INT64_MAX) == 0, "pwrite de 0 octet a 2^63 - 1 : 0");
    errno = 0;
    verifier(ERREUR(syscall(SYS_pread64, 999, z, 1, -1L), EINVAL) && ERREUR(syscall(SYS_pwrite64, 999, z, 1, -1L), EINVAL),
             "pread et pwrite a -1, descripteur invalide : EINVAL d'abord");
    /* readv et writev : le total plafonné à 2 Gio moins une page. */
    /* (Des adresses basses, celles du programme : 2,5 Gio plus loin, on est
     * encore dans les adresses des programmes, ce que la pile, tout en
     * haut, ne garantit pas.) */
    struct iovec gros[2] = {{nom_a, 1UL << 30}, {nom_a, 3UL << 29}};
    verifier(writev(null, gros, 2) == 0x7ffff000, "writev de 2,5 Gio vers /dev/null : 2 Gio moins une page");
    struct iovec vers_noyau[2] = {{(void *)0xffff800000000000UL, 0}, {z, 2}};
    errno = 0;
    verifier(ERREUR(writev(null, vers_noyau, 2), EFAULT), "writev, un morceau vide vers le noyau : EFAULT");
    /* FIONREAD : les fichiers ordinaires seulement ; la valeur, en int,
     * peut être négative. */
    int dossier = open("/tmp", O_RDONLY | O_DIRECTORY), reste = 0;
    errno = 0;
    verifier(ERREUR(ioctl(dossier, FIONREAD, &reste), ENOTTY) && ERREUR(ioctl(null, FIONREAD, &reste), ENOTTY),
             "FIONREAD sur un dossier ou /dev/null : ENOTTY");
    close(fd);
    fd = open(nom_a, O_RDWR | O_TRUNC);
    verifier(write(fd, "abcdef", 6) == 6 && lseek(fd, 10, SEEK_SET) == 10 && ioctl(fd, FIONREAD, &reste) == 0 && reste == -4,
             "FIONREAD au-dela de la fin : -4");
    errno = 0;
    verifier(ERREUR(lseek(null, 5, 99), EINVAL), "lseek avec un whence inconnu : EINVAL, meme pour /dev/null");
    /* Les verrous : la demande est vérifiée, même si rien ne bloque. */
    int lecture = open(nom_a, O_RDONLY);
    struct flock v = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    errno = 0;
    verifier(ERREUR(fcntl(lecture, F_SETLK, NULL), EFAULT), "F_SETLK sans struct flock : EFAULT");
    errno = 0;
    verifier(ERREUR(fcntl(lecture, F_SETLK, &v), EBADF), "verrou d'ecriture sur un descripteur en lecture : EBADF");
    v.l_type = 77;
    errno = 0;
    verifier(ERREUR(fcntl(fd, F_SETLK, &v), EINVAL), "verrou d'un type inconnu : EINVAL");
    v.l_type = F_RDLCK;
    v.l_whence = SEEK_SET;
    v.l_start = -1;
    errno = 0;
    verifier(ERREUR(fcntl(fd, F_SETLK, &v), EINVAL), "verrou qui commence avant le debut : EINVAL");
    v.l_start = 0;
    verifier(fcntl(fd, F_SETLK, &v) == 0 && fcntl(fd, F_GETLK, &v) == 0 && v.l_type == F_UNLCK,
             "F_SETLK accorde, F_GETLK : rien ne bloque");
    close(lecture);
    /* O_PATH : F_GETFL ne rend que ses drapeaux, sans O_LARGEFILE. */
    int chemin = open(nom_a, O_PATH);
    verifier(fcntl(chemin, F_GETFL) == O_PATH, "F_GETFL d'un descripteur O_PATH : O_PATH seul");
    /* Linux 6.11 et plus : fstat par un chemin nul et AT_EMPTY_PATH. */
    verifier(syscall(SYS_newfstatat, fd, NULL, &st, AT_EMPTY_PATH) == 0 && st.st_size == 6,
             "newfstatat(fd, NULL, AT_EMPTY_PATH)");
    close(chemin);
    struct stat sn;
    verifier(fstat(null, &sn) == 0 && sn.st_blksize == 4096, "st_blksize de /dev/null : 4096");
    /* open : les drapeaux, puis le chemin, puis le numéro libre, puis la
     * résolution. */
    errno = 0;
    verifier(ERREUR(open("/tmp/fichiers-absent/x", O_CREAT | O_DIRECTORY, 0644), EINVAL),
             "O_CREAT | O_DIRECTORY sous un dossier absent : EINVAL d'abord");
    struct rlimit l, petite = {8, 4096};
    getrlimit(RLIMIT_NOFILE, &l);
    setrlimit(RLIMIT_NOFILE, &petite);
    int ouverts[8], n = 0, dernier;
    while (n < 8 && (dernier = open("/dev/null", O_RDONLY)) >= 0)
        ouverts[n++] = dernier;
    errno = 0;
    verifier(ERREUR(syscall(SYS_openat, AT_FDCWD, NULL, O_RDONLY), EFAULT), "table pleine, chemin nul : EFAULT");
    errno = 0;
    verifier(ERREUR(open("", O_RDONLY), ENOENT), "table pleine, chemin vide : ENOENT");
    errno = 0;
    verifier(ERREUR(open("/tmp/fichiers-absent/x", O_RDONLY), EMFILE), "table pleine, chemin absent : EMFILE");
    while (n > 0)
        close(ouverts[--n]);
    setrlimit(RLIMIT_NOFILE, &l);
    /* Les autres limites se baissent ; relever la dure demande d'être root. */
    struct rlimit core = {0, 0}, lu;
    verifier(setrlimit(RLIMIT_CORE, &core) == 0 && getrlimit(RLIMIT_CORE, &lu) == 0 && lu.rlim_max == 0,
             "RLIMIT_CORE baissee a 0");
    if (getuid() != 0) {
        core.rlim_max = 1;
        errno = 0;
        verifier(ERREUR(setrlimit(RLIMIT_CORE, &core), EPERM), "la relever, sans etre root : EPERM");
    }
    close(dossier);
    close(zero);
    close(null);
    close(fd);
    munmap(m, 4096);
}

static void peripheriques(void)
{
    char tampon[16];
    int null = open("/dev/null", O_RDWR);
    verifier(null >= 0 && read(null, tampon, sizeof tampon) == 0 && write(null, "abc", 3) == 3,
             "/dev/null : rien a lire, tout s'ecrit");
    close(null);
    int zero = open("/dev/zero", O_RDONLY);
    memset(tampon, 1, sizeof tampon);
    verifier(zero >= 0 && read(zero, tampon, sizeof tampon) == sizeof tampon && tampon[0] == 0 && tampon[15] == 0,
             "/dev/zero : des zeros");
    close(zero);
    int plein = open("/dev/full", O_WRONLY);
    errno = 0;
    verifier(plein >= 0 && ERREUR(write(plein, "x", 1), ENOSPC), "/dev/full : ENOSPC");
    close(plein);
    int alea = open("/dev/urandom", O_RDONLY);
    memset(tampon, 0, sizeof tampon);
    int non_nul = 0;
    verifier(alea >= 0 && read(alea, tampon, sizeof tampon) == sizeof tampon, "/dev/urandom : 16 octets");
    for (unsigned i = 0; i < sizeof tampon; i++)
        non_nul |= tampon[i];
    verifier(non_nul != 0, "/dev/urandom : pas tous nuls");
    close(alea);
}

static void notre_archive(void)
{
    struct stat a, b;
    if (stat("/etc/bonjour.txt", &a) != 0) {
        printf("[linux] fichiers : /etc/bonjour.txt absent (pas notre archive) : saute\n");
        return;
    }
    char texte[64] = {0};
    int fd = open("/etc/lien-bonjour", O_RDONLY);
    verifier(fd >= 0 && read(fd, texte, sizeof texte - 1) > 0 && strcmp(texte, "Bonjour depuis un fichier de /etc !\n") == 0,
             "/etc/bonjour.txt, lu par son lien symbolique");
    close(fd);
    verifier(stat("/etc/salut.txt", &b) == 0 && a.st_ino == b.st_ino && a.st_nlink == 2,
             "/etc/salut.txt : le meme fichier (deux liens physiques)");
    verifier(lstat("/etc/lien-bonjour", &b) == 0 && S_ISLNK(b.st_mode) && b.st_size == 11, "lstat d'un lien symbolique");
    verifier(a.st_uid == 0 && (a.st_mode & 0777) == 0644, "/etc/bonjour.txt : a root, 0644");
}

/* Les entrées d'un dossier, par getdents64 directement, avec un tampon
 * de `taille` octets : leurs noms, dans le tableau `noms`. */
struct entree64 {
    unsigned long long ino;
    long long suivante;
    unsigned short taille;
    unsigned char genre;
    char nom[];
};

static int compter(int fd, char noms[][16], int max, int taille)
{
    char tampon[1024];
    int n = 0;
    long lus;
    while ((lus = syscall(SYS_getdents64, fd, tampon, taille)) > 0) {
        for (long p = 0; p < lus;) {
            struct entree64 *e = (struct entree64 *)(tampon + p);
            if (n < max)
                snprintf(noms[n++], 16, "%.15s", e->nom);
            p += e->taille;
        }
    }
    return n;
}

static int contient(char noms[][16], int n, const char *nom)
{
    for (int i = 0; i < n; i++)
        if (strcmp(noms[i], nom) == 0)
            return 1;
    return 0;
}

static void arborescence(void)
{
    char d[64], c[96], e[96];
    nom(d, "d");
    verifier(mkdir(d, 0755) == 0, "mkdir");
    errno = 0;
    verifier(ERREUR(mkdir(d, 0755), EEXIST), "mkdir d'un dossier qui existe : EEXIST");
    snprintf(c, sizeof c, "%s/sous/", d);
    verifier(mkdir(c, 0755) == 0, "mkdir avec une barre finale");
    struct stat st;
    verifier(stat(d, &st) == 0 && S_ISDIR(st.st_mode) && st.st_nlink == 3, "un dossier et un sous-dossier : 3 liens");
    errno = 0;
    verifier(ERREUR(rmdir(d), ENOTEMPTY), "rmdir d'un dossier non vide : ENOTEMPTY");
    errno = 0;
    verifier(ERREUR(unlink(d), EISDIR), "unlink d'un dossier : EISDIR");
    snprintf(e, sizeof e, "%s/.", d);
    errno = 0;
    verifier(ERREUR(rmdir(e), EINVAL), "rmdir de d/. : EINVAL");
    snprintf(e, sizeof e, "%s/..", d);
    errno = 0;
    verifier(ERREUR(rmdir(e), ENOTEMPTY), "rmdir de d/.. : ENOTEMPTY");

    /* Des fichiers dans le dossier, listés par getdents64 avec un petit
     * tampon (deux entrées par appel), en effaçant pendant la lecture :
     * aucune autre entrée n'est sautée ni répétée (POSIX). */
    const char *noms_fichiers[] = {"f1", "f2", "f3", "f4", "f5"};
    for (int i = 0; i < 5; i++) {
        snprintf(e, sizeof e, "%s/%s", d, noms_fichiers[i]);
        close(open(e, O_CREAT | O_WRONLY, 0644));
    }
    int fd = open(d, O_RDONLY | O_DIRECTORY);
    char noms[16][16];
    int n = compter(fd, noms, 16, 1024);
    verifier(n == 8 && contient(noms, n, ".") && contient(noms, n, "..") && contient(noms, n, "sous")
             && contient(noms, n, "f1") && contient(noms, n, "f5"), "getdents64 : les 8 entrees");
    errno = 0;
    lseek(fd, 0, SEEK_SET);
    char petit[16];
    verifier(syscall(SYS_getdents64, fd, petit, sizeof petit) == -1 && errno == EINVAL,
             "getdents64, tampon trop petit : EINVAL");
    /* Une première lecture de 64 octets (deux ou trois petites entrées),
     * puis on efface un fichier pas encore vu, puis on lit le reste. */
    lseek(fd, 0, SEEK_SET);
    char tampon[64];
    char vus[16][16];
    int nvus = 0;
    long l = syscall(SYS_getdents64, fd, tampon, sizeof tampon);
    for (long p = 0; p < l && nvus < 16;) {
        struct entree64 *x = (struct entree64 *)(tampon + p);
        snprintf(vus[nvus++], 16, "%.15s", x->nom);
        p += x->taille;
    }
    const char *efface = NULL;
    for (int i = 0; i < 5 && !efface; i++)
        if (!contient(vus, nvus, noms_fichiers[i]))
            efface = noms_fichiers[i];
    if (efface) {
        snprintf(e, sizeof e, "%s/%s", d, efface);
        unlink(e);
    }
    char suite[16][16];
    int nsuite = compter(fd, suite, 16, 64), doubles = 0;
    for (int i = 0; i < nsuite; i++) {
        doubles += contient(vus, nvus, suite[i]);
        if (nvus < 16)
            snprintf(vus[nvus++], 16, "%.15s", suite[i]);
    }
    int tous = 1;
    for (int i = 0; i < 5; i++)
        if (noms_fichiers[i] != efface)
            tous &= contient(vus, nvus, noms_fichiers[i]);
    verifier(efface && doubles == 0 && tous, "effacer pendant la lecture : rien de saute ni de repete");
    close(fd);
    fd = open(nom_a, O_RDONLY);
    errno = 0;
    verifier(ERREUR(syscall(SYS_getdents64, fd, tampon, sizeof tampon), ENOTDIR), "getdents64 d'un fichier : ENOTDIR");
    close(fd);

    /* Renommer. */
    char f1[96], f2[96], g[96];
    snprintf(f1, sizeof f1, "%s/f1", d);
    snprintf(f2, sizeof f2, "%s/f2", d);
    snprintf(g, sizeof g, "%s/sous/g", d);
    /* Le fichier effacé pendant la lecture revient, s'il servait ensuite. */
    if (efface && strcmp(efface, "f1") == 0)
        close(open(f1, O_CREAT | O_WRONLY, 0644));
    if (efface && strcmp(efface, "f2") == 0)
        close(open(f2, O_CREAT | O_WRONLY, 0644));
    struct stat a1, a2;
    stat(f1, &a1);
    verifier(rename(f1, f2) == 0 && stat(f2, &a2) == 0 && a2.st_ino == a1.st_ino && stat(f1, &a2) == -1,
             "rename par-dessus un fichier : l'ancien disparait");
    snprintf(e, sizeof e, "%s/sous", d);
    errno = 0;
    verifier(ERREUR(rename(f2, e), EISDIR), "rename d'un fichier sur un dossier : EISDIR");
    errno = 0;
    verifier(ERREUR(rename(e, f2), ENOTDIR), "rename d'un dossier sur un fichier : ENOTDIR");
    snprintf(c, sizeof c, "%s/sous/x", d);
    errno = 0;
    verifier(ERREUR(rename(d, c), EINVAL), "rename d'un dossier dans lui-meme : EINVAL");
    errno = 0;
    verifier(ERREUR(rename(f2, "/tmp/fichiers-inexistant/"), ENOTDIR) || errno == ENOENT,
             "rename vers un nom avec une barre finale");
    close(open(g, O_CREAT | O_WRONLY, 0644));
    errno = 0;
    verifier(ERREUR(renameat2(AT_FDCWD, f2, AT_FDCWD, g, RENAME_NOREPLACE), EEXIST), "RENAME_NOREPLACE : EEXIST");
    struct stat s_f2, s_g;
    stat(f2, &s_f2);
    stat(g, &s_g);
    verifier(renameat2(AT_FDCWD, f2, AT_FDCWD, g, RENAME_EXCHANGE) == 0 && stat(f2, &a1) == 0 && stat(g, &a2) == 0
             && a1.st_ino == s_g.st_ino && a2.st_ino == s_f2.st_ino, "RENAME_EXCHANGE echange les deux");

    /* Les liens. */
    char lien[96], dur[96];
    snprintf(lien, sizeof lien, "%s/lien", d);
    snprintf(dur, sizeof dur, "%s/dur", d);
    verifier(link(f2, dur) == 0 && stat(dur, &a1) == 0 && stat(f2, &a2) == 0 && a1.st_ino == a2.st_ino && a1.st_nlink == 2,
             "link : un second nom, 2 liens");
    errno = 0;
    verifier(ERREUR(link(d, lien), EPERM), "link d'un dossier : EPERM");
    char cible[64] = {0};
    verifier(symlink("f2", lien) == 0 && readlink(lien, cible, sizeof cible) == 2 && memcmp(cible, "f2", 2) == 0,
             "symlink puis readlink");
    errno = 0;
    verifier(ERREUR(readlink(f2, cible, sizeof cible), EINVAL), "readlink de ce qui n'est pas un lien : EINVAL");
    char pendant[96], cree[96];
    snprintf(pendant, sizeof pendant, "%s/pendant", d);
    snprintf(cree, sizeof cree, "%s/cree", d);
    verifier(symlink("cree", pendant) == 0, "un lien pendant");
    errno = 0;
    verifier(ERREUR(open(pendant, O_CREAT | O_EXCL | O_WRONLY, 0644), EEXIST), "O_CREAT | O_EXCL sur un lien pendant : EEXIST");
    fd = open(pendant, O_CREAT | O_WRONLY, 0644);
    verifier(fd >= 0 && stat(cree, &a1) == 0, "O_CREAT sur un lien pendant cree sa cible");
    close(fd);
    errno = 0;
    verifier(ERREUR(open(lien, O_RDONLY | O_NOFOLLOW), ELOOP), "O_NOFOLLOW sur un lien : ELOOP");

    /* Le dossier courant. */
    char ici[128];
    verifier(chdir(d) == 0 && getcwd(ici, sizeof ici) && strcmp(ici, d) == 0, "chdir puis getcwd");
    verifier(access("f2", R_OK) == 0 && chdir("sous") == 0 && access("../f2", R_OK) == 0 && chdir("..") == 0,
             "des chemins relatifs au dossier courant");
    errno = 0;
    verifier(ERREUR(chdir("f2"), ENOTDIR), "chdir vers un fichier : ENOTDIR");
    errno = 0;
    verifier(getcwd(ici, 4) == NULL && errno == ERANGE, "getcwd, tampon trop petit : ERANGE");
    fd = open("/", O_RDONLY | O_DIRECTORY);
    verifier(fchdir(fd) == 0 && getcwd(ici, sizeof ici) && strcmp(ici, "/") == 0, "fchdir");
    close(fd);

    /* Tronquer : raccourcir puis rallonger relit des zéros. */
    fd = open(f2, O_RDWR | O_TRUNC);
    char lu[8];
    verifier(write(fd, "abcdefgh", 8) == 8 && ftruncate(fd, 3) == 0 && ftruncate(fd, 8) == 0
             && pread(fd, lu, 8, 0) == 8 && memcmp(lu, "abc\0\0\0\0\0", 8) == 0,
             "ftruncate qui raccourcit puis rallonge : des zeros");
    close(fd);
    fd = open(f2, O_RDONLY);
    errno = 0;
    verifier(ERREUR(ftruncate(fd, 0), EINVAL), "ftruncate en lecture seule : EINVAL");
    close(fd);
    errno = 0;
    verifier(ERREUR(truncate(f2, -1), EINVAL) && truncate(f2, 100) == 0 && stat(f2, &a1) == 0 && a1.st_size == 100,
             "truncate : -1 refuse, 100 accepte");
    errno = 0;
    verifier(ERREUR(truncate(d, 0), EISDIR), "truncate d'un dossier : EISDIR");
    fd = open(f2, O_RDONLY);
    verifier(fsync(fd) == 0 && fdatasync(fd) == 0, "fsync et fdatasync");
    close(fd);

    /* Les droits et les dates. */
    mode_t ancien = umask(077);
    snprintf(e, sizeof e, "%s/prive", d);
    fd = open(e, O_CREAT | O_WRONLY, 0666);
    verifier(fstat(fd, &a1) == 0 && (a1.st_mode & 0777) == 0600 && umask(ancien) == 077, "umask 077 : 0666 devient 0600");
    close(fd);
    verifier(chmod(e, 0640) == 0 && stat(e, &a1) == 0 && (a1.st_mode & 07777) == 0640, "chmod");
    verifier(chown(e, getuid(), getgid()) == 0, "chown vers soi-meme");
    struct timespec dates[2] = {{0, UTIME_OMIT}, {1000000000, 5}};
    verifier(utimensat(AT_FDCWD, e, dates, 0) == 0 && stat(e, &a1) == 0 && a1.st_mtim.tv_sec == 1000000000
             && a1.st_mtim.tv_nsec == 5, "utimensat pose la date de modification");
    if (getuid() != 0) {
        errno = 0;
        verifier(ERREUR(chown(e, 0, 0), EPERM), "chown vers root, sans l'etre : EPERM");
        chmod(e, 0);
        errno = 0;
        verifier(ERREUR(open(e, O_RDONLY), EACCES), "un fichier 0000 : EACCES");
    }

    /* Tout effacer. */
    const char *a_effacer[] = {"f2", "dur", "lien", "pendant", "cree", "prive", "sous/g", "f3", "f4", "f5"};
    int efface_ok = 1;
    for (unsigned i = 0; i < sizeof a_effacer / sizeof *a_effacer; i++) {
        snprintf(e, sizeof e, "%s/%s", d, a_effacer[i]);
        if (unlink(e) != 0 && errno != ENOENT)
            efface_ok = 0;
    }
    snprintf(e, sizeof e, "%s/sous", d);
    verifier(efface_ok && rmdir(e) == 0 && rmdir(d) == 0, "tout effacer");
}

/* L'arborescence : les cas où Linux vérifie dans un ordre précis, ou
 * répond autrement qu'on l'attendrait. */
static void arborescence_bornes(void)
{
    char d[64], e[96], f[96];
    nom(d, "bornes");
    mkdir(d, 0755);
    snprintf(f, sizeof f, "%s/f", d);
    int fd = open(f, O_CREAT | O_RDWR, 0644);
    /* utimensat : les deux dates à UTIME_OMIT, rien à faire, même sur un
     * chemin absent ; un chemin nul désigne le descripteur. */
    struct timespec omit[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    verifier(utimensat(AT_FDCWD, "/tmp/fichiers-absent/x", omit, 0) == 0, "utimensat(OMIT, OMIT) sur un chemin absent : 0");
    errno = 0;
    verifier(ERREUR(syscall(SYS_utimensat, fd, NULL, NULL, AT_SYMLINK_NOFOLLOW), EINVAL),
             "utimensat, chemin nul et un drapeau : EINVAL");
    errno = 0;
    verifier(ERREUR(syscall(SYS_utimensat, AT_FDCWD, NULL, NULL, 0), EFAULT), "utimensat(AT_FDCWD, NULL) : EFAULT");
    int chemin = open(f, O_PATH);
    errno = 0;
    verifier(ERREUR(syscall(SYS_utimensat, chemin, NULL, NULL, 0), EBADF), "utimensat sur un descripteur O_PATH : EBADF");
    struct timespec faux[2] = {{0, UTIME_OMIT}, {0, 2000000000}};
    errno = 0;
    verifier(ERREUR(utimensat(AT_FDCWD, "/tmp/fichiers-absent/x", faux, 0), ENOENT) && ERREUR(utimensat(AT_FDCWD, f, faux, 0), EINVAL),
             "utimensat, une date fausse : le chemin d'abord (ENOENT), puis EINVAL");
    /* readlinkat d'un chemin vide qui n'est pas un lien : ENOENT. */
    char lu[16];
    errno = 0;
    verifier(ERREUR(readlinkat(fd, "", lu, sizeof lu), ENOENT), "readlinkat(fichier, \"\") : ENOENT");
    /* linkat avec AT_EMPTY_PATH (Linux 6.10 et plus) : un nom pour le
     * fichier d'un descripteur, ouvert par nous. */
    snprintf(e, sizeof e, "%s/autre-nom", d);
    struct stat a, b;
    verifier(linkat(fd, "", AT_FDCWD, e, AT_EMPTY_PATH) == 0 && stat(e, &a) == 0 && fstat(fd, &b) == 0 && a.st_ino == b.st_ino,
             "linkat(fd, \"\", AT_EMPTY_PATH) : un nom de plus");
    unlink(e);
    errno = 0;
    verifier(ERREUR(syscall(SYS_renameat2, AT_FDCWD, NULL, AT_FDCWD, e, 0xff), EINVAL),
             "renameat2, drapeaux inconnus : EINVAL avant les chemins");
    errno = 0;
    verifier(ERREUR(symlink("", f), ENOENT), "symlink vers \"\" sur un nom qui existe : ENOENT");
    errno = 0;
    verifier(ERREUR(syscall(SYS_ftruncate, 999, -1L), EINVAL), "ftruncate(999, -1) : EINVAL d'abord");
    /* open avec O_CREAT : la barre finale, avant de suivre le lien. */
    snprintf(e, sizeof e, "%s/pendant", d);
    int lien = symlink("nulle/part", e);
    strcat(e, "/");
    errno = 0;
    verifier(lien == 0 && ERREUR(open(e, O_CREAT | O_WRONLY, 0644), EISDIR), "O_CREAT sur \"lien/\" qui ne mene a rien : EISDIR");
    errno = 0;
    verifier(ERREUR(open(d, O_CREAT | O_EXCL | O_WRONLY, 0644), EEXIST), "O_CREAT | O_EXCL sur un dossier : EEXIST");
    /* chown(-1, -1) retire le setuid, même à son propriétaire. */
    fchmod(fd, 04755);
    verifier(fchown(fd, -1, -1) == 0 && fstat(fd, &a) == 0 && (a.st_mode & 07777) == 0755, "chown(-1, -1) retire S_ISUID");
    /* Un dossier effacé, encore ouvert : rien à y lire (ENOENT). */
    snprintf(e, sizeof e, "%s/efface", d);
    mkdir(e, 0755);
    int mort = open(e, O_RDONLY | O_DIRECTORY);
    rmdir(e);
    errno = 0;
    verifier(ERREUR(syscall(SYS_getdents64, mort, lu, sizeof lu), ENOENT), "getdents64 d'un dossier efface : ENOENT");
    close(mort);
    /* getcwd au-delà de PATH_MAX : ENAMETOOLONG (la glibc se rabat alors
     * sur sa propre méthode). 21 dossiers de 200 caractères. */
    char long_nom[201];
    memset(long_nom, 'n', 200);
    long_nom[200] = 0;
    int ici = open(".", O_RDONLY | O_DIRECTORY), profondeur = 0, retour = chdir(d) == 0;
    while (profondeur < 21 && mkdir(long_nom, 0755) == 0 && chdir(long_nom) == 0)
        profondeur++;
    char *grand = malloc(8192);
    errno = 0;
    verifier(retour && profondeur == 21 && ERREUR(syscall(SYS_getcwd, grand, 8192), ENAMETOOLONG),
             "getcwd au-dela de 4096 octets : ENAMETOOLONG");
    free(grand);
    while (profondeur-- > 0)
        retour &= chdir("..") == 0 && rmdir(long_nom) == 0;
    verifier(retour && fchdir(ici) == 0, "remonter, effacer les dossiers longs");
    close(ici);
    close(chemin);
    close(fd);
    unlink(f);
    snprintf(e, sizeof e, "%s/pendant", d);
    unlink(e);
    verifier(rmdir(d) == 0, "tout effacer (bornes)");
}

/* Le sticky de /tmp : on n'y efface pas le fichier d'un autre. Il faut un
 * fichier d'un autre utilisateur : notre archive en met un (/tmp/a-root) ;
 * sur l'hôte, le cas est sauté. */
static void sticky(void)
{
    struct stat st;
    if (getuid() == 0 || stat("/tmp/a-root", &st) != 0 || st.st_uid == getuid()) {
        printf("[linux] fichiers : pas de fichier d'un autre dans /tmp : sticky saute\n");
        return;
    }
    errno = 0;
    verifier(ERREUR(unlink("/tmp/a-root"), EPERM), "/tmp sticky : effacer le fichier d'un autre : EPERM");
}

static void programme_en_cours(const char *moi)
{
    /* Le binaire de ce programme, en cours d'exécution : personne ne peut
     * l'écrire. (Chez nous, il appartient à l'utilisateur 1000, voir
     * archive.txt : sinon EACCES passerait avant.) */
    errno = 0;
    verifier(ERREUR(open(moi, O_WRONLY), ETXTBSY), "ouvrir en ecriture le programme en cours : ETXTBSY");
}

int main(int argc, char **argv)
{
    (void)argc;
    ecrire_lire();
    erreurs();
    descripteurs();
    bornes();
    peripheriques();
    notre_archive();
    programme_en_cours(argv[0]);
    arborescence();
    arborescence_bornes();
    sticky();
    struct stat st;
    verifier(unlink(nom_a) == 0 && stat(nom_a, &st) == -1 && errno == ENOENT, "effacer le fichier");
    printf("[linux] fichiers : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
