/*
 * Des courses entre fils (6e) : ce qu'un fil trouve sous un verrou du
 * noyau et dont il se sert sous un autre, pendant qu'un autre fil le
 * change (le commit des descripteurs tenus). Pendant une fraction de
 * seconde :
 *   - un fil ouvre et ferme sans cesse les mêmes numéros : F, tantôt le
 *     fichier f (des « x », en lecture), tantôt le fichier g (des « y »,
 *     en écriture seule), et D, un dossier ;
 *   - un autre s'en sert : read, pread, fstat, lseek, mmap sur F, openat
 *     et getdents64 sur D ;
 *   - un troisième crée un dossier, y entre (chdir), lit son chemin
 *     (getcwd) et ouvre un fichier par un chemin relatif, en ressort, et
 *     l'efface (rmdir) ;
 *   - un quatrième lit le dossier courant (getcwd) et y ouvre un fichier
 *     pendant ce temps.
 * Chaque appel doit réussir avec ce qu'il faut (le contenu du fichier, le
 * bon chemin), ou échouer d'une façon que Linux permet (EBADF : le
 * descripteur venait d'être fermé ; ENOENT : le dossier venait d'être
 * effacé) : jamais un autre fichier, une autre erreur, ni un noyau
 * arrêté. Il tourne dans notre noyau et sur l'hôte.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define F 40
#define D 41
#define TAILLE (64 << 10)

/* Un dossier à soi (/tmp/courses-<pid>) : deux passages en même temps sur
 * l'hôte ne se gênent pas. */
static char racine[64];
static volatile int arreter;
static int ecarts;
static long tours[4];
static char ecart[256];

/* Un résultat que Linux ne permet pas : le premier est gardé, pour le dire. */
static void ecart_vu(const char *quoi, int e)
{
    if (__atomic_fetch_add(&ecarts, 1, __ATOMIC_RELAXED) == 0)
        snprintf(ecart, sizeof ecart, "%s : errno %d", quoi, e);
}

static long maintenant_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void *ouvrir_fermer(void *a)
{
    char chemin[128], autre[128];
    snprintf(chemin, sizeof chemin, "%s/f", racine);
    snprintf(autre, sizeof autre, "%s/g", racine);
    while (!arreter) {
        /* F change de fichier d'un coup (dup2 remplace l'ancien, qui est
         * fermé), et reste presque toujours ouvert : tantôt f, tantôt g.
         * g ne se lit pas : un read ou un mmap qui réussit ne doit voir que
         * f. Un noyau qui vérifierait les droits sur un fichier puis lirait
         * (ou projetterait) celui qui a pris son numéro entre-temps
         * montrerait des « y ». De temps en temps, F et D sont fermés. */
        int f = tours[0] % 2 ? open(autre, O_WRONLY) : open(chemin, O_RDONLY);
        int d = open(racine, O_RDONLY | O_DIRECTORY);
        if (f < 0 || d < 0)
            ecart_vu("open", errno);
        dup2(f, F);
        dup2(d, D);
        close(f);
        close(d);
        if (tours[0] % 8 == 7) {
            close(F);
            close(D);
        }
        tours[0]++;
    }
    return a;
}

static int tout_x(const char *t, long n)
{
    for (long i = 0; i < n; i++)
        if (t[i] != 'x')
            return 0;
    return 1;
}

static char t[TAILLE];

static void *se_servir(void *a)
{
    while (!arreter) {
        /* Un grand read : beaucoup de pages, et du temps entre le moment où
         * le noyau trouve le fichier et celui où il le lit. */
        long n = read(F, t, sizeof t);
        if (n < 0 ? errno != EBADF : !tout_x(t, n))
            ecart_vu("read", errno);
        n = pread(F, t, 512, 4096);
        if (n < 0 ? errno != EBADF : (n != 512 || !tout_x(t, n)))
            ecart_vu("pread", errno);
        struct stat s;
        if (fstat(F, &s) == 0 ? s.st_size != TAILLE : errno != EBADF)
            ecart_vu("fstat", errno);
        if (lseek(F, 0, SEEK_SET) < 0 && errno != EBADF)
            ecart_vu("lseek", errno);
        char *p = mmap(NULL, TAILLE, PROT_READ, MAP_PRIVATE, F, 0);
        if (p == MAP_FAILED) {
            if (errno != EBADF && errno != EACCES)
                ecart_vu("mmap", errno);
        } else {
            if (!tout_x(p, TAILLE))
                ecart_vu("mmap : contenu", 0);
            munmap(p, TAILLE);
        }
        int g = openat(D, "f", O_RDONLY);
        if (g >= 0)
            close(g);
        else if (errno != EBADF)
            ecart_vu("openat", errno);
        n = syscall(SYS_getdents64, D, t, 512);
        if (n < 0 && errno != EBADF)
            ecart_vu("getdents64", errno);
        tours[1]++;
    }
    return a;
}

static void *changer_de_dossier(void *a)
{
    char x[128], cwd[256];
    snprintf(x, sizeof x, "%s/d/x", racine);
    while (!arreter) {
        if (mkdir(x, 0755) < 0 && errno != EEXIST)
            ecart_vu("mkdir", errno);
        if (chdir(x) == 0) {
            if (getcwd(cwd, sizeof cwd) == NULL ? errno != ENOENT : strcmp(cwd, x) != 0 && strcmp(cwd, racine) != 0)
                ecart_vu("getcwd (dans x)", errno);
        } else if (errno != ENOENT) {
            ecart_vu("chdir", errno);
        }
        if (chdir(racine) < 0)
            ecart_vu("chdir (racine)", errno);
        if (rmdir(x) < 0 && errno != ENOENT)
            ecart_vu("rmdir", errno);
        tours[2]++;
    }
    return a;
}

static void *regarder_le_dossier(void *a)
{
    char cwd[256], x[128];
    snprintf(x, sizeof x, "%s/d/x", racine);
    while (!arreter) {
        /* Le dossier courant est la racine des courses, ou x (que l'autre
         * fil a pu effacer : ENOENT). */
        if (getcwd(cwd, sizeof cwd) == NULL ? errno != ENOENT : strcmp(cwd, racine) != 0 && strcmp(cwd, x) != 0)
            ecart_vu("getcwd", errno);
        int g = open("f", O_RDONLY);
        if (g >= 0)
            close(g);
        else if (errno != ENOENT)
            ecart_vu("open relatif", errno);
        tours[3]++;
    }
    return a;
}

/* Un fichier de TAILLE octets, tous `octet`. */
static int remplir(const char *nom, char octet)
{
    char chemin[128];
    snprintf(chemin, sizeof chemin, "%s/%s", racine, nom);
    int f = open(chemin, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    memset(t, octet, sizeof t);
    int ok = f >= 0 && write(f, t, sizeof t) == sizeof t;
    close(f);
    return ok;
}

int main(void)
{
    char chemin[128];
    snprintf(racine, sizeof racine, "/tmp/courses-%d", getpid());
    mkdir(racine, 0755);
    snprintf(chemin, sizeof chemin, "%s/d", racine);
    mkdir(chemin, 0755);
    if (!remplir("f", 'x') || !remplir("g", 'y'))
        return 2;
    if (chdir(racine) < 0)
        return 2;
    void *(*corps[4])(void *) = { ouvrir_fermer, se_servir, changer_de_dossier, regarder_le_dossier };
    pthread_t fils[4];
    for (int i = 0; i < 4; i++)
        pthread_create(&fils[i], NULL, corps[i], NULL);
    long debut = maintenant_ms();
    while (maintenant_ms() - debut < 500) {
        struct timespec dix = { 0, 10000000 };
        nanosleep(&dix, NULL);
    }
    arreter = 1;
    for (int i = 0; i < 4; i++)
        pthread_join(fils[i], NULL);
    /* Tout est effacé : un fichier gardé dans /tmp garderait ses pages
     * (le noyau dit « memoire rendue » à la fin de chaque programme). */
    if (chdir("/") < 0)
        ecart_vu("chdir /", errno);
    snprintf(chemin, sizeof chemin, "%s/d/x", racine);
    rmdir(chemin);
    snprintf(chemin, sizeof chemin, "%s/d", racine);
    rmdir(chemin);
    snprintf(chemin, sizeof chemin, "%s/f", racine);
    unlink(chemin);
    snprintf(chemin, sizeof chemin, "%s/g", racine);
    unlink(chemin);
    if (rmdir(racine) < 0)
        ecart_vu("rmdir de la racine des courses", errno);
    int tous = tours[0] > 0 && tours[1] > 0 && tours[2] > 0 && tours[3] > 0;
    printf("[linux] courses : tours de chaque fil : %ld, %ld, %ld, %ld\n", tours[0], tours[1], tours[2], tours[3]);
    if (ecarts)
        printf("[linux] courses : %d ecarts, le premier : %s\n", ecarts, ecart);
    printf("[linux] courses : quatre fils ont tourne : %s\n", tous ? "ok" : "ECHEC");
    printf("[linux] courses : %s\n", ecarts == 0 && tous ? "ok" : "ECHEC");
    return ecarts != 0 || !tous;
}
