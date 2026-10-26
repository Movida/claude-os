/*
 * Un programme dynamique comme `claude` : lié à ses cinq bibliothèques
 * (libc, libm, libpthread, libdl, librt), chargées par ld-linux, que le
 * noyau a chargé à côté de lui (PT_INTERP). Il vérifie ce que ld-linux et
 * la glibc partagée font avec ce que le noyau leur donne, puis charge à
 * l'exécution une bibliothèque à nous (dlopen de libessai.so, voir
 * linux/essai.c). Une ligne par vérification, « ok » ou « ECHEC ».
 *
 * Il tourne aussi sur l'hôte (make tests-hote, avec LD_LIBRARY_PATH pour
 * trouver libessai.so) : rien de ce qu'il vérifie ne dépend de la machine.
 *
 * Lié par -Wl,--no-as-needed -lm -l:libpthread.so.0 -l:libdl.so.2
 * -l:librt.so.1 (voir le Makefile) : depuis la glibc 2.34, -lpthread,
 * -ldl et -lrt ne trouvent que des archives vides, et ne donneraient aucun
 * NEEDED ; --no-as-needed garde ceux dont le programme n'appelle rien.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <math.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>

extern char _start[];

static int echecs = 0;

static void verifier(const char *quoi, int ok)
{
    printf("[linux] dynamique : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Le nom de base d'un chemin. */
static const char *base(const char *chemin)
{
    const char *b = strrchr(chemin, '/');
    return b ? b + 1 : chemin;
}

/* Les bibliothèques que ld-linux a chargées (dl_iterate_phdr) : chacune de
 * celles qu'on attend coche sa case. */
static const char *const attendues[] = {"libc.so.6", "libm.so.6", "libpthread.so.0", "libdl.so.2", "librt.so.1"};
static int trouvees[5];

static int noter(struct dl_phdr_info *info, size_t taille, void *donnees)
{
    (void)taille;
    (void)donnees;
    for (int i = 0; i < 5; i++)
        if (strcmp(base(info->dlpi_name), attendues[i]) == 0)
            trouvees[i] = 1;
    return 0;
}

int main(void)
{
    dl_iterate_phdr(noter, NULL);
    int toutes = 1;
    for (int i = 0; i < 5; i++)
        toutes &= trouvees[i];
    verifier("les cinq bibliotheques de claude chargees par ld-linux", toutes);

    verifier("AT_BASE non nul (ld-linux charge par le noyau)", getauxval(AT_BASE) != 0);
    verifier("AT_ENTRY = _start", getauxval(AT_ENTRY) == (unsigned long)_start);

    /* volatile : sinon gcc -O2 calcule cos(0) à la compilation, et la libm
     * n'est jamais appelée (mesuré). */
    volatile double zero = 0.0, deux = 2.0;
    verifier("cos(0) = 1 et sqrt(2) par la libm", cos(zero) == 1.0 && fabs(sqrt(deux) - 1.41421356) < 1e-8);

    void *essai = dlopen("libessai.so", RTLD_NOW);
    verifier("dlopen de libessai.so", essai != NULL);
    if (essai == NULL) {
        printf("[linux] dynamique : %s\n", dlerror());
        return 1;
    }
    int *construite = dlsym(essai, "essai_construite");
    int (*suivant)(void) = (int (*)(void))dlsym(essai, "essai_suivant");
    void (*signaler)(int *) = (void (*)(int *))dlsym(essai, "essai_signaler_la_fin");
    verifier("dlsym de ses fonctions et de sa variable", construite && suivant && signaler);
    if (!(construite && suivant && signaler))
        return 1;
    verifier("son constructeur appele par ld-linux", *construite == 1);
    int premier = suivant(), second = suivant();
    verifier("sa variable __thread (TLS dynamique) a sa valeur initiale, puis la suivante", premier == 42 && second == 43);

    Dl_info info;
    verifier("dladdr : la fonction est dans libessai.so",
             dladdr((void *)suivant, &info) && strcmp(base(info.dli_fname), "libessai.so") == 0);

    verifier("dlopen d'une bibliotheque absente : refuse, avec son nom",
             dlopen("libabsente.so", RTLD_NOW) == NULL && strstr(dlerror(), "libabsente.so") != NULL);

    int fin = 0;
    signaler(&fin);
    verifier("dlclose : son destructeur appele", dlclose(essai) == 0 && fin == 1);
    /* Projection rendue : on le demande au NOYAU, pas à ld-linux (dladdr ne
     * lit que sa liste, et ld-linux ne regarde pas ce que rend munmap).
     * madvise sur une page où rien n'est projeté rend ENOMEM. */
    void *page = (void *)((uintptr_t)suivant & ~(uintptr_t)4095);
    verifier("dlclose : la bibliotheque n'est plus projetee (madvise : ENOMEM)",
             madvise(page, 4096, MADV_NORMAL) == -1 && errno == ENOMEM);

    printf("[linux] dynamique : %s\n", echecs ? "des verifications ont ECHOUE" : "toutes les verifications : ok");
    return echecs != 0;
}
