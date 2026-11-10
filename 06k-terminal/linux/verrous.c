/* Les verrous de fichiers (les soldes d'avant 6k : jusque-là, fcntl et
 * flock vérifiaient leur demande et l'accordaient toujours). Sur l'hôte
 * comme chez nous, dans le dossier DOSSIER (un tmpfs : /dev/shm sur l'hôte,
 * /tmp chez nous).
 *
 *   verrous DOSSIER : dans un seul processus, ce qui s'y voit :
 *     - les verrous OFD (F_OFD_*), à la description ouverte : deux open du
 *       même fichier se gênent ; F_OFD_GETLK dit le verrou qui gêne (pid
 *       -1) ; un verrou rendu au milieu se coupe en deux, deux verrous du
 *       même genre qui se touchent se fondent, l'écriture rétrogradée en
 *       lecture laisse lire ; la dernière fermeture de la description les
 *       rend ; F_OFD_SETLKW attend qu'un autre fil rende le sien ;
 *     - un verrou POSIX gêne un OFD du même processus (deux propriétaires),
 *       et tombe dès que le processus ferme un AUTRE descripteur du fichier ;
 *     - flock : exclusif et partagé, LOCK_NB (EWOULDBLOCK), la conversion
 *       qui rend d'abord l'ancien verrou, l'indépendance d'avec fcntl, la
 *       description partagée par dup (le verrou reste jusqu'à la dernière
 *       fermeture), l'attente d'un autre fil.
 *   verrous DOSSIER a &  puis  verrous DOSSIER b : deux processus, qui se
 *     parlent par des fichiers témoins : a verrouille l'octet 0, b l'octet 1 ;
 *     b voit l'octet 0 pris (EAGAIN, F_GETLK donne le pid de a) ; a attend
 *     l'octet 1 (F_SETLKW) ; b demande l'octet 0 en attendant : EDEADLK (a
 *     attend b) ; b rend l'octet 1, a l'obtient ; a finit sans rien rendre,
 *     et b obtient les deux octets en attendant : la fin d'un processus rend
 *     ses verrous POSIX.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int echecs;
static const char *role = "";
static char chemin[256];

static void verifier(int ok, const char *quoi)
{
    printf("[linux] verrous%s%s : %s : %s\n", *role ? " " : "", role, quoi, ok ? "ok" : "ECHEC");
    fflush(stdout);
    echecs += !ok;
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void dormir_ms(int ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

/* Une demande de plage : le résultat de fcntl, et errno. */
static int plage(int fd, int commande, short genre, off_t debut, off_t longueur)
{
    struct flock l = { .l_type = genre, .l_whence = SEEK_SET, .l_start = debut, .l_len = longueur };
    return fcntl(fd, commande, &l) == 0 ? 0 : errno;
}

/* F_GETLK ou F_OFD_GETLK : la réponse. */
static struct flock tester(int fd, int commande, short genre, off_t debut, off_t longueur)
{
    struct flock l = { .l_type = genre, .l_whence = SEEK_SET, .l_start = debut, .l_len = longueur };
    if (fcntl(fd, commande, &l) != 0)
        l.l_type = -1;
    return l;
}

/* Une demande d'une plage donnée par l_whence (SEEK_CUR, SEEK_END). */
static int plage_depuis(int fd, int commande, short genre, short depuis, off_t debut, off_t longueur)
{
    struct flock l = { .l_type = genre, .l_whence = depuis, .l_start = debut, .l_len = longueur };
    return fcntl(fd, commande, &l) == 0 ? 0 : errno;
}

static int ouvrir(void)
{
    return open(chemin, O_RDWR | O_CREAT, 0644);
}

/* Le fil qui attend un verrou : F_OFD_SETLKW, ou flock. */
struct attente {
    int fd;
    int par_flock;
    double duree;
    int resultat;
};

static void *attendre(void *p)
{
    struct attente *a = p;
    double t = maintenant();
    if (a->par_flock)
        a->resultat = flock(a->fd, LOCK_EX) == 0 ? 0 : errno;
    else
        a->resultat = plage(a->fd, F_OFD_SETLKW, F_WRLCK, 0, 1);
    a->duree = maintenant() - t;
    return NULL;
}

/* Lance un fil qui attend sur `fd`, rend le verrou qui le gêne après
 * 100 ms (`rendre`), et vérifie qu'il l'a obtenu, après au moins 90 ms. */
static int attendu_apres_100_ms(int fd, int par_flock, void (*rendre)(void))
{
    struct attente a = { .fd = fd, .par_flock = par_flock };
    pthread_t f;
    pthread_create(&f, NULL, attendre, &a);
    dormir_ms(100);
    rendre();
    pthread_join(f, NULL);
    return a.resultat == 0 && a.duree >= 0.09 && a.duree < 5;
}

static int gene_ofd, gene_flock;
static void rendre_ofd(void)
{
    plage(gene_ofd, F_OFD_SETLK, F_UNLCK, 0, 0);
}
static void rendre_flock(void)
{
    flock(gene_flock, LOCK_UN);
}

static void rien(int s)
{
    (void)s;
}

/* Un fil attend un verrou que tient `tenu` ; un signal (sans SA_RESTART)
 * l'interrompt : EINTR. Avec SA_RESTART, l'appel est repris : le fil
 * attend encore, et obtient le verrou quand il est rendu. */
static int signal_pendant_l_attente(int tenu)
{
    plage(tenu, F_OFD_SETLK, F_WRLCK, 0, 1);
    int ok = 1;
    for (int k = 0; k < 2; k++) {
        struct sigaction sa = { .sa_handler = rien, .sa_flags = k ? SA_RESTART : 0 };
        sigaction(SIGUSR1, &sa, NULL);
        int fd = ouvrir();
        struct attente a = { .fd = fd };
        pthread_t f;
        pthread_create(&f, NULL, attendre, &a);
        dormir_ms(100);
        pthread_kill(f, SIGUSR1);
        dormir_ms(100);
        if (k == 1)
            plage(tenu, F_OFD_SETLK, F_UNLCK, 0, 1);
        pthread_join(f, NULL);
        ok &= k == 0 ? a.resultat == EINTR : a.resultat == 0 && a.duree >= 0.15;
        close(fd);
    }
    signal(SIGUSR1, SIG_DFL);
    return ok;
}

static void un_processus(void)
{
    int f1 = ouvrir(), f2 = ouvrir();
    static char cent[100];
    int ecrit = write(f1, cent, sizeof cent) == (ssize_t)sizeof cent;
    verifier(ecrit && plage(f1, F_OFD_SETLK, F_WRLCK, 0, 10) == 0 && plage(f2, F_OFD_SETLK, F_WRLCK, 5, 10) == EAGAIN,
             "OFD : deux descriptions du meme fichier, l'ecriture de [0, 9] gene [5, 14] : EAGAIN");
    struct flock l = tester(f2, F_OFD_GETLK, F_WRLCK, 5, 10);
    verifier(l.l_type == F_WRLCK && l.l_whence == SEEK_SET && l.l_start == 0 && l.l_len == 10 && l.l_pid == -1,
             "OFD : F_OFD_GETLK dit le verrou qui gene : ecriture, 0, 10 octets, pid -1");
    verifier(plage(f2, F_OFD_SETLK, F_RDLCK, 10, 10) == 0, "OFD : une lecture a cote, [10, 19] : accordee");
    /* F_OFD_GETLK de F_UNLCK (Linux 6.10) : le verrou de la MÊME
     * description ; F_GETLK de F_UNLCK : EINVAL. */
    l = tester(f1, F_OFD_GETLK, F_UNLCK, 0, 100);
    struct flock refus = tester(f1, F_GETLK, F_UNLCK, 0, 100);
    int e = errno;
    verifier(l.l_type == F_WRLCK && l.l_start == 0 && l.l_len == 10 && l.l_pid == -1 && refus.l_type == -1 && e == EINVAL,
             "F_OFD_GETLK de F_UNLCK dit le verrou de la meme description ; F_GETLK de F_UNLCK : EINVAL");
    verifier(plage(f1, F_SETLK, F_WRLCK, 0, 1) == EAGAIN && tester(f1, F_GETLK, F_WRLCK, 0, 1).l_pid == -1,
             "un verrou POSIX du meme processus est gene par un OFD (deux proprietaires), F_GETLK dit pid -1");
    plage(f1, F_OFD_SETLK, F_UNLCK, 3, 2);
    l = tester(f2, F_OFD_GETLK, F_WRLCK, 2, 2);
    verifier(tester(f2, F_OFD_GETLK, F_WRLCK, 3, 2).l_type == F_UNLCK && l.l_type == F_WRLCK && l.l_start == 0 && l.l_len == 3,
             "OFD : [3, 4] rendu au milieu de [0, 9] : [0, 2] et [5, 9] restent");
    plage(f1, F_OFD_SETLK, F_WRLCK, 3, 2);
    l = tester(f2, F_OFD_GETLK, F_WRLCK, 9, 1);
    verifier(l.l_type == F_WRLCK && l.l_start == 0 && l.l_len == 10, "OFD : [3, 4] repris : fondu en [0, 9]");
    plage(f1, F_OFD_SETLK, F_RDLCK, 0, 10);
    verifier(plage(f2, F_OFD_SETLK, F_RDLCK, 0, 1) == 0 && plage(f2, F_OFD_SETLK, F_WRLCK, 0, 1) == EAGAIN,
             "OFD : retrograde en lecture, l'autre lit, mais n'ecrit pas");
    close(f1);
    verifier(plage(f2, F_OFD_SETLK, F_WRLCK, 0, 10) == 0, "OFD : la derniere fermeture de la description rend ses verrous");
    plage(f2, F_OFD_SETLK, F_UNLCK, 0, 0);
    /* L'ordre de F_GETLK : un verrou fondu garde sa place (Linux le change
     * en place) : f1 lit [0, 9], puis g lit [0, 9], puis f1 étend à
     * [0, 19] ; le premier qui gêne une écriture est celui de f1. */
    {
        int a = ouvrir(), g = ouvrir();
        plage(a, F_OFD_SETLK, F_RDLCK, 0, 10);
        plage(g, F_OFD_SETLK, F_RDLCK, 0, 10);
        plage(a, F_OFD_SETLK, F_RDLCK, 0, 20);
        l = tester(f2, F_OFD_GETLK, F_WRLCK, 0, 5);
        verifier(l.l_type == F_RDLCK && l.l_start == 0 && l.l_len == 20, "F_GETLK : un verrou fondu garde sa place, le premier qui gene");
        close(a);
        close(g);
    }
    /* Les plages : une longueur nulle (jusqu'au bout, l_len 0 en retour),
     * négative (vers l'arrière), depuis la position (SEEK_CUR) et depuis la
     * fin (SEEK_END, le fichier a 100 octets). */
    {
        int a = ouvrir();
        plage(a, F_OFD_SETLK, F_WRLCK, 200, 0);
        struct flock bout = tester(f2, F_OFD_GETLK, F_WRLCK, 1000000, 1);
        plage(a, F_OFD_SETLK, F_UNLCK, 0, 0);
        lseek(a, 50, SEEK_SET);
        plage_depuis(a, F_OFD_SETLK, F_WRLCK, SEEK_CUR, 0, -10);
        struct flock arriere = tester(f2, F_OFD_GETLK, F_WRLCK, 45, 1);
        plage(a, F_OFD_SETLK, F_UNLCK, 0, 0);
        plage_depuis(a, F_OFD_SETLK, F_WRLCK, SEEK_END, -5, 5);
        struct flock fin = tester(f2, F_OFD_GETLK, F_WRLCK, 97, 1);
        verifier(bout.l_start == 200 && bout.l_len == 0 && arriere.l_start == 40 && arriere.l_len == 10 && fin.l_start == 95 && fin.l_len == 5,
                 "les plages : longueur nulle, negative, depuis SEEK_CUR et SEEK_END");
        close(a);
    }
    plage(f2, F_OFD_SETLK, F_WRLCK, 0, 10);
    int f3 = ouvrir();
    gene_ofd = f2;
    verifier(attendu_apres_100_ms(f3, 0, rendre_ofd), "F_OFD_SETLKW attend que l'autre description rende le sien");
    close(f3);
    verifier(signal_pendant_l_attente(f2), "un signal pendant F_OFD_SETLKW : EINTR sans SA_RESTART, repris avec");
    /* POSIX : tombe quand le processus ferme un AUTRE descripteur. */
    int f4 = ouvrir();
    plage(f4, F_SETLK, F_WRLCK, 50, 10);
    l = tester(f2, F_OFD_GETLK, F_WRLCK, 50, 1);
    int vu = l.l_type == F_WRLCK && l.l_start == 50 && l.l_len == 10 && l.l_pid == getpid();
    int f5 = ouvrir();
    close(f5);
    verifier(vu && tester(f2, F_OFD_GETLK, F_WRLCK, 50, 1).l_type == F_UNLCK,
             "POSIX : F_OFD_GETLK le voit, avec notre pid ; fermer un autre descripteur du fichier le rend");
    close(f4);
    close(f2);

    /* flock. */
    int a = ouvrir(), b = ouvrir();
    verifier(flock(a, LOCK_EX) == 0 && flock(b, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK
             && flock(b, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK,
             "flock : exclusif, l'autre description ne prend rien (EWOULDBLOCK)");
    verifier(flock(a, LOCK_SH) == 0 && flock(b, LOCK_SH | LOCK_NB) == 0, "flock : retrograde en partage, l'autre partage");
    verifier(flock(a, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK && flock(b, LOCK_EX | LOCK_NB) == 0,
             "flock : la conversion rend d'abord l'ancien verrou (refusee, il n'y en a plus)");
    verifier(plage(a, F_OFD_SETLK, F_WRLCK, 0, 0) == 0 && plage(a, F_OFD_SETLK, F_UNLCK, 0, 0) == 0,
             "flock et fcntl s'ignorent");
    int c = dup(b);
    close(b);
    int garde = flock(a, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK;
    close(c);
    verifier(garde && flock(a, LOCK_EX | LOCK_NB) == 0, "flock : dup partage la description, le verrou tient jusqu'a sa derniere fermeture");
    int d = ouvrir();
    gene_flock = a;
    verifier(attendu_apres_100_ms(d, 1, rendre_flock), "flock attend que l'autre description rende le sien");
    close(d);
    close(a);
    unlink(chemin);
}

/* Les fichiers témoins de a et b. */
static void temoin(const char *dossier, const char *nom, int valeur)
{
    char t[310], n[300];
    snprintf(n, sizeof n, "%s/verrous-%s", dossier, nom);
    snprintf(t, sizeof t, "%s.t", n);
    FILE *f = fopen(t, "w");
    fprintf(f, "%d\n", valeur);
    fclose(f);
    rename(t, n);
}

static int attendre_temoin(const char *dossier, const char *nom)
{
    char n[300];
    snprintf(n, sizeof n, "%s/verrous-%s", dossier, nom);
    for (int k = 0; k < 2000; k++) {
        FILE *f = fopen(n, "r");
        int v;
        if (f && fscanf(f, "%d", &v) == 1) {
            fclose(f);
            return v;
        }
        if (f)
            fclose(f);
        dormir_ms(5);
    }
    return -1;
}

static void processus_a(const char *dossier)
{
    int fd = ouvrir();
    verifier(plage(fd, F_SETLK, F_WRLCK, 0, 1) == 0, "l'octet 0 en ecriture");
    temoin(dossier, "a0", getpid());
    attendre_temoin(dossier, "b1");
    temoin(dossier, "a-attend", 1);
    double t = maintenant();
    int r = plage(fd, F_SETLKW, F_WRLCK, 1, 1);
    verifier(r == 0 && maintenant() - t >= 0.2, "F_SETLKW sur l'octet 1 : attend que b le rende, puis l'obtient");
    temoin(dossier, "a-fini", 1);
    /* Rien n'est rendu : la fin du processus s'en charge. */
    dormir_ms(200);
}

static void processus_b(const char *dossier)
{
    int pid_a = attendre_temoin(dossier, "a0");
    int fd = ouvrir();
    struct flock l = tester(fd, F_GETLK, F_WRLCK, 0, 1);
    verifier(plage(fd, F_SETLK, F_WRLCK, 0, 1) == EAGAIN && l.l_type == F_WRLCK && l.l_pid == pid_a && l.l_start == 0 && l.l_len == 1,
             "l'octet 0 pris par a : EAGAIN, et F_GETLK donne le pid de a");
    verifier(plage(fd, F_SETLK, F_WRLCK, 1, 1) == 0, "l'octet 1 en ecriture");
    temoin(dossier, "b1", getpid());
    attendre_temoin(dossier, "a-attend");
    /* Le temps que a dorme dans F_SETLKW. */
    dormir_ms(300);
    verifier(plage(fd, F_SETLKW, F_WRLCK, 0, 1) == EDEADLK, "F_SETLKW sur l'octet 0 alors que a attend l'octet 1 : EDEADLK");
    plage(fd, F_SETLK, F_UNLCK, 1, 1);
    attendre_temoin(dossier, "a-fini");
    double t = maintenant();
    int r = plage(fd, F_SETLKW, F_WRLCK, 0, 2);
    verifier(r == 0 && maintenant() - t >= 0.05, "a fini sans rien rendre : b obtient les deux octets, en attendant sa fin");
    close(fd);
    unlink(chemin);
    const char *noms[] = { "a0", "b1", "a-attend", "a-fini" };
    for (int k = 0; k < 4; k++) {
        char n[300];
        snprintf(n, sizeof n, "%s/verrous-%s", dossier, noms[k]);
        unlink(n);
    }
}

int main(int argc, char **argv)
{
    const char *dossier = argc > 1 ? argv[1] : "/tmp";
    if (argc > 2) {
        role = argv[2];
        snprintf(chemin, sizeof chemin, "%s/verrous-ab", dossier);
        if (!strcmp(role, "a"))
            processus_a(dossier);
        else
            processus_b(dossier);
    } else {
        snprintf(chemin, sizeof chemin, "%s/verrous", dossier);
        un_processus();
    }
    printf("[linux] verrous%s%s : %s\n", *role ? " " : "", role, echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
