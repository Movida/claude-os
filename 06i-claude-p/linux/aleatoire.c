/*
 * Le générateur aléatoire (6h) : getrandom, /dev/random, /dev/urandom et
 * /proc/sys/kernel/random, comme Linux. Il tourne dans notre noyau et sur
 * l'hôte (make tests-hote) : chaque ligne doit dire « ok » des deux côtés.
 * Le générateur est prêt quand le test commence (un premier getrandom qui
 * attend s'en assure) : ce qui précède « prêt » se voit au démarrage du
 * noyau, pas ici. Rien ne compare de valeur tirée : seulement leur forme
 * et le fait qu'elles diffèrent.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] aleatoire : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* getrandom par l'appel brut : rend le résultat, ou -errno. */
static long brut(void *tampon, size_t n, unsigned options)
{
    long r = syscall(SYS_getrandom, tampon, n, options);
    return r < 0 ? -errno : r;
}

/* Lit un fichier de /proc en entier (au plus 255 octets) ; -1 en cas d'erreur. */
static int lire(const char *chemin, char *t, size_t place)
{
    int fd = open(chemin, O_RDONLY);
    if (fd < 0)
        return -1;
    int n = read(fd, t, place - 1);
    close(fd);
    if (n >= 0)
        t[n] = 0;
    return n;
}

/* Un UUID de version 4 au format de Linux : 8-4-4-4-12 chiffres
 * hexadécimaux minuscules, un saut de ligne ; la version 4, la variante
 * 10xx. */
static int est_uuid(const char *t)
{
    if (strlen(t) != 37 || t[36] != '\n')
        return 0;
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (t[i] != '-')
                return 0;
        } else if (!strchr("0123456789abcdef", t[i])) {
            return 0;
        }
    }
    return t[14] == '4' && strchr("89ab", t[19]) != NULL;
}

static int comparer(const void *a, const void *b)
{
    return memcmp(a, b, 64);
}

int main(void)
{
    unsigned char a[64], b[64];
    /* Prêt d'abord (attend s'il le faut, comme BoringSSL). */
    verifier(brut(a, 48, 0) == 48, "getrandom sans option : 48 octets (le generateur pret)");
    verifier(brut(a, 16, GRND_NONBLOCK) == 16 && brut(b, 16, GRND_NONBLOCK) == 16 && memcmp(a, b, 16) != 0,
             "GRND_NONBLOCK, une fois pret : deux tirages differents");
    verifier(brut(a, 16, GRND_INSECURE) == 16 && brut(a, 16, GRND_RANDOM) == 16, "GRND_INSECURE et GRND_RANDOM seuls : acceptes");

    verifier(brut(a, 16, 8) == -EINVAL, "une option inconnue : EINVAL");
    verifier(brut(a, 16, GRND_RANDOM | GRND_INSECURE) == -EINVAL, "GRND_RANDOM et GRND_INSECURE ensemble : EINVAL");
    verifier(brut(NULL, 0, 0) == 0, "zero octet : 0, sans lire le tampon");
    verifier(brut((void *)8, 16, 0) == -EFAULT, "une adresse non projetee : EFAULT");

    /* Un tampon dont la seconde page est retirée : ce qui tient dans la
     * première, rendu. */
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(p + page, page);
    verifier(brut(p + page - 10, 100, 0) == 10, "un tampon coupe par une page absente : les 10 premiers octets");
    verifier(brut(p + page - 100, 100, 0) == 100, "100 octets d'un coup : 100");
    munmap(p, page);

    /* 1 Mio : rendu en entier (sous MAX_RW_COUNT), aucun bloc de 64 octets
     * répété. */
    size_t n = 1 << 20;
    unsigned char *m = malloc(n);
    long r = brut(m, n, 0);
    verifier(r == (long)n, "1 Mio d'un coup : rendu en entier");
    qsort(m, n / 64, 64, comparer);
    int repetes = 0;
    for (size_t i = 64; i < n; i += 64)
        repetes += memcmp(m + i - 64, m + i, 64) == 0;
    verifier(repetes == 0, "1 Mio : aucun bloc de 64 octets repete");
    /* Chaque bit à 1 environ une fois sur deux (8 Mibits : l'écart type
     * est de 1448 bits ; 20 000, c'est une erreur, pas le hasard). */
    long uns = 0;
    for (size_t i = 0; i < n; i++)
        uns += __builtin_popcount(m[i]);
    verifier(labs(uns - 4 * (long)n) < 20000, "1 Mio : la moitie des bits a 1");
    free(m);

    /* /dev/random et /dev/urandom. */
    int fr = open("/dev/random", O_RDONLY), fu = open("/dev/urandom", O_RDWR);
    verifier(fr >= 0 && fu >= 0, "ouvrir /dev/random et /dev/urandom");
    verifier(read(fr, a, 64) == 64 && read(fu, b, 64) == 64 && memcmp(a, b, 64) != 0, "lire 64 octets de chacun, differents");
    verifier(write(fu, "graine", 6) == 6, "ecrire dans /dev/urandom : accepte (mele, sans credit)");
    struct pollfd pf = { fr, POLLIN | POLLOUT, 0 };
    verifier(poll(&pf, 1, 0) == 1 && pf.revents == (POLLIN), "poll de /dev/random pret : POLLIN");
    int compte = -1;
    verifier(ioctl(fr, RNDGETENTCNT, &compte) == 0 && compte == 256, "RNDGETENTCNT : 256 bits, une fois pret");
    verifier(ioctl(fr, RNDADDTOENTCNT, &compte) == -1 && errno == EPERM, "RNDADDTOENTCNT sans etre root : EPERM");
    close(fr);
    close(fu);

    /* /proc/sys/kernel/random. */
    char t1[256], t2[256];
    verifier(lire("/proc/sys/kernel/random/boot_id", t1, sizeof t1) == 37 && est_uuid(t1)
             && lire("/proc/sys/kernel/random/boot_id", t2, sizeof t2) == 37 && strcmp(t1, t2) == 0,
             "boot_id : un UUID de version 4, le meme a chaque lecture");
    verifier(lire("/proc/sys/kernel/random/uuid", t1, sizeof t1) == 37 && est_uuid(t1)
             && lire("/proc/sys/kernel/random/uuid", t2, sizeof t2) == 37 && est_uuid(t2) && strcmp(t1, t2) != 0,
             "uuid : un UUID de version 4, neuf a chaque lecture");
    verifier(lire("/proc/sys/kernel/random/poolsize", t1, sizeof t1) > 0 && strcmp(t1, "256\n") == 0, "poolsize : 256");
    verifier(lire("/proc/sys/kernel/random/write_wakeup_threshold", t1, sizeof t1) > 0 && strcmp(t1, "256\n") == 0
             && lire("/proc/sys/kernel/random/urandom_min_reseed_secs", t2, sizeof t2) > 0 && strcmp(t2, "60\n") == 0,
             "write_wakeup_threshold 256, urandom_min_reseed_secs 60 (sans effet, lus par tous)");
    verifier(lire("/proc/sys/kernel/random/entropy_avail", t1, sizeof t1) > 0 && strcmp(t1, "256\n") == 0,
             "entropy_avail : 256, une fois pret");

    printf("[linux] aleatoire : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
