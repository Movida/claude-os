/*
 * inotify (6i) : chaque événement de Linux 6.18, dans son ordre, et les
 * refus de ses appels. Les suites attendues ont été mesurées sur l'hôte
 * (deux sondes, au début du commit) : ce programme les vérifie sur l'hôte
 * (dans /dev/shm, un tmpfs) et dans notre noyau (dans /tmp).
 *
 *     surveillance [DOSSIER]
 *     surveillance --guetter DOSSIER NOM ATTENDUS [DOSSIER2 NOM2] &
 *     surveillance --dormir MS
 *
 * Les deux dernières formes vérifient, dans notre noyau, ce que voit
 * inotify de ce que fait un autre programme, lancé par la ligne suivante :
 * le guetteur, lancé par `&`, surveille DOSSIER et attend les événements
 * ATTENDUS (« OPEN ACCESS CLOSE_NOWRITE ») pour l'entrée NOM, en O_ASYNC :
 * il doit aussi recevoir SIGIO, même pour ce que pose le lanceur (qui ne
 * fait pas d'appel système : il envoie ce qu'il a différé après chaque
 * ligne) ; « --dormir » lui laisse le temps de poser sa surveillance. Avec
 * un second dossier et un second nom, il surveille les deux, et ATTENDUS
 * dit l'ordre de leurs événements (« nom:OPEN autre:OPEN ») : un programme
 * dynamique, puis son interpréteur, comme les ouvre `execve`. Un programme que lance le
 * lanceur (comme `execve` sous Linux, mesuré : IN_OPEN, IN_ACCESS, puis
 * IN_CLOSE_NOWRITE quand il finit), un fichier que lit un programme
 * WebAssembly (path_open, fd_read : les mêmes que pour Linux). Il
 * n'écrit qu'à la fin, une demi-seconde après : la console n'a qu'un
 * écrivain à la fois, sans quoi ses lignes et celles du lanceur
 * pourraient se mêler.
 *
 * Les événements lus s'écrivent « nom:MASQUE[:cN][:nom de l'entrée] »,
 * séparés d'une espace : le nom est celui qu'on a donné à la surveillance
 * (d : le dossier de l'essai, f : un fichier...), et cN numérote les cookies
 * dans l'ordre où ils apparaissent (deux événements d'un même déplacement
 * ont le même ; deux déplacements, deux différents).
 */
#define _GNU_SOURCE
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
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int ecarts;
static int in;
static char D[200];

static void verifier(int ok, const char *quoi)
{
    printf("[linux] surveillance : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    if (!ok)
        ecarts++;
}

/* Le résultat d'un appel : sa valeur, ou -errno. */
static long r(long v)
{
    return v < 0 ? -errno : v;
}

/* Un chemin dans le dossier de l'essai. */
static const char *p(const char *nom)
{
    static char t[8][300];
    static int i;
    i = (i + 1) % 8;
    snprintf(t[i], sizeof t[i], "%s/%s", D, nom);
    return t[i];
}

/* Les noms des surveillances : wd -> nom. */
static struct {
    int wd;
    const char *nom;
} noms[64];

static void nommer(int wd, const char *nom)
{
    for (int i = 0; i < 64; i++)
        if (noms[i].wd == wd || noms[i].nom == NULL) {
            noms[i].wd = wd;
            noms[i].nom = nom;
            return;
        }
}

static const char *nom_de(int wd)
{
    static char t[16];
    for (int i = 0; i < 64; i++)
        if (noms[i].nom && noms[i].wd == wd)
            return noms[i].nom;
    snprintf(t, sizeof t, "%d", wd);
    return t;
}

static void masque(unsigned m, char *t)
{
    static const char *n[] = {"ACCESS", "MODIFY", "ATTRIB", "CLOSE_WRITE", "CLOSE_NOWRITE", "OPEN", "MOVED_FROM",
                              "MOVED_TO", "CREATE", "DELETE", "DELETE_SELF", "MOVE_SELF", "b12", "UNMOUNT",
                              "Q_OVERFLOW", "IGNORED"};
    t[0] = 0;
    for (int i = 0; i < 16; i++)
        if (m & (1u << i)) {
            strcat(t, n[i]);
            strcat(t, "|");
        }
    if (m & IN_ISDIR)
        strcat(t, "ISDIR|");
    if (t[0])
        t[strlen(t) - 1] = 0;
}

/* Lit tous les événements de l'instance `i` (non bloquante) et les écrit
 * dans `sortie`. */
static void lire_de(int i, char *sortie, size_t taille)
{
    static char b[65536] __attribute__((aligned(8)));
    unsigned cookies[16];
    int ncookies = 0;
    sortie[0] = 0;
    ssize_t l = read(i, b, sizeof b);
    for (char *q = b; l > 0 && q < b + l;) {
        struct inotify_event *e = (void *)q;
        char m[200], c[16] = "", un[300];
        masque(e->mask, m);
        if (e->cookie) {
            int k = 0;
            while (k < ncookies && cookies[k] != e->cookie)
                k++;
            if (k == ncookies && ncookies < 16)
                cookies[ncookies++] = e->cookie;
            snprintf(c, sizeof c, ":c%d", k + 1);
        }
        snprintf(un, sizeof un, "%s%s:%s%s%s%s", sortie[0] ? " " : "", nom_de(e->wd), m, c, e->len ? ":" : "",
                 e->len ? e->name : "");
        strncat(sortie, un, taille - strlen(sortie) - 1);
        q += sizeof *e + e->len;
    }
}

/* Les événements en attente doivent être exactement `attendu`. */
static void attendre(const char *attendu, const char *quoi)
{
    char lu[4096];
    lire_de(in, lu, sizeof lu);
    int ok = strcmp(lu, attendu) == 0;
    if (!ok)
        printf("[linux] surveillance : %s : lu « %s », attendu « %s »\n", quoi, lu, attendu);
    verifier(ok, quoi);
}

static void ecrire_fichier(const char *chemin, const char *octets)
{
    int fd = open(chemin, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, octets, strlen(octets)) != (ssize_t)strlen(octets))
        verifier(0, "creer un fichier d'essai");
    close(fd);
}

static volatile int sigio;
static void sur_sigio(int s)
{
    (void)s;
    sigio++;
}

/* Un fil qui écrit dans le fichier `f` après 50 ms : réveille un read
 * bloquant. */
static void *ecrire_plus_tard(void *chemin)
{
    struct timespec t = {0, 50 * 1000 * 1000};
    nanosleep(&t, NULL);
    int fd = open(chemin, O_WRONLY);
    (void)!write(fd, "x", 1);
    close(fd);
    return NULL;
}

static void appels(void)
{
    /* inotify_init1 : ses drapeaux, son fichier. */
    verifier(r(inotify_init1(IN_NONBLOCK | 1)) == -EINVAL && r(inotify_init1(O_RDWR)) == -EINVAL,
             "inotify_init1, un drapeau inconnu : EINVAL");
    int a = r(syscall(SYS_inotify_init));
    verifier(a >= 0 && fcntl(a, F_GETFL) == O_RDONLY && fcntl(a, F_GETFD) == 0, "inotify_init : O_RDONLY, sans FD_CLOEXEC");
    close(a);
    char lien[64], t[64];
    snprintf(lien, sizeof lien, "/proc/self/fd/%d", in);
    ssize_t l = readlink(lien, t, sizeof t - 1);
    t[l > 0 ? l : 0] = 0;
    struct stat st;
    fstat(in, &st);
    verifier(fcntl(in, F_GETFL) == O_NONBLOCK && fcntl(in, F_GETFD) == FD_CLOEXEC && strcmp(t, "anon_inode:inotify") == 0
                 && st.st_mode == 0600 && st.st_uid == 0,
             "inotify_init1(IN_NONBLOCK | IN_CLOEXEC) : F_GETFL 0x800, FD_CLOEXEC, anon_inode:inotify, 0600 a root");
    char un;
    verifier(r(lseek(in, 0, SEEK_SET)) == 0 && r(write(in, "x", 1)) == -EBADF && r(pread(in, &un, 1, 0)) == -ESPIPE
                 && r(read(in, &un, 0)) == -EAGAIN,
             "lseek : 0 ; write : EBADF ; pread : ESPIPE ; read de 0 octet, vide : EAGAIN");

    /* inotify_add_watch : ses refus, dans l'ordre de Linux. */
    verifier(r(inotify_add_watch(in, D, 0)) == -EINVAL && r(inotify_add_watch(in, D, 0x1000)) == -EINVAL
                 && r(inotify_add_watch(999, D, 0x1000)) == -EINVAL,
             "inotify_add_watch, masque vide ou bit inconnu : EINVAL, avant le descripteur");
    verifier(r(inotify_add_watch(999, D, IN_CREATE)) == -EBADF
                 && r(inotify_add_watch(999, D, IN_CREATE | IN_MASK_ADD | IN_MASK_CREATE)) == -EBADF,
             "inotify_add_watch, descripteur ferme : EBADF, avant IN_MASK_ADD | IN_MASK_CREATE");
    verifier(r(inotify_add_watch(in, D, IN_CREATE | IN_MASK_ADD | IN_MASK_CREATE)) == -EINVAL
                 && r(inotify_add_watch(1, D, IN_CREATE)) == -EINVAL,
             "inotify_add_watch : IN_MASK_ADD | IN_MASK_CREATE, ou pas une instance : EINVAL");
    verifier(r(inotify_add_watch(in, "/nexiste/pas", IN_CREATE)) == -ENOENT && r(inotify_add_watch(in, "", IN_CREATE)) == -ENOENT
                 && r(inotify_add_watch(in, NULL, IN_CREATE)) == -EFAULT,
             "inotify_add_watch, chemin absent, vide, nul : ENOENT, ENOENT, EFAULT");
    ecrire_fichier(p("f"), "");
    verifier(r(inotify_add_watch(in, p("f"), IN_CREATE | IN_ONLYDIR)) == -ENOTDIR, "inotify_add_watch IN_ONLYDIR d'un fichier : ENOTDIR");
    chmod(p("f"), 0200);
    verifier(r(inotify_add_watch(in, p("f"), IN_MODIFY)) == -EACCES, "inotify_add_watch sans le droit de lire : EACCES");
    chmod(p("f"), 0600);
    verifier(r(inotify_add_watch(in, lien, IN_ALL_EVENTS)) == -EACCES, "inotify_add_watch de l'inode anonyme (0600 a root) : EACCES");
    (void)!symlink("f", p("s"));
    int ws = inotify_add_watch(in, p("s"), IN_ATTRIB | IN_DONT_FOLLOW);
    int wf = inotify_add_watch(in, p("f"), IN_ATTRIB);
    verifier(ws == 1 && wf == 2 && r(inotify_add_watch(in, p("s"), IN_ATTRIB)) == wf,
             "le lien (IN_DONT_FOLLOW), puis le fichier : 1 et 2 ; le lien suivi : le fichier, 2");
    verifier(r(inotify_add_watch(in, p("f"), IN_ATTRIB | IN_MASK_CREATE)) == -EEXIST, "IN_MASK_CREATE d'une surveillance qui existe : EEXIST");
    verifier(inotify_add_watch(in, D, IN_ONESHOT) == 3 && inotify_add_watch(in, D, IN_IGNORED) == 3,
             "IN_ONESHOT seul, IN_IGNORED seul : acceptes (aucun evenement demande)");
    nommer(1, "s");
    nommer(2, "f");
    nommer(3, "d");
    chmod(p("f"), 0644);
    attendre("f:ATTRIB", "chmod du fichier : IN_ATTRIB, pas au lien");

    /* inotify_rm_watch. */
    verifier(r(inotify_rm_watch(in, 1)) == 0 && r(inotify_rm_watch(in, 1)) == -EINVAL && r(inotify_rm_watch(in, 0)) == -EINVAL
                 && r(inotify_rm_watch(in, -1)) == -EINVAL && r(inotify_rm_watch(999, 2)) == -EBADF
                 && r(inotify_rm_watch(1, 2)) == -EINVAL,
             "inotify_rm_watch : 0, puis EINVAL ; 0, -1 : EINVAL ; EBADF ; pas une instance : EINVAL");
    int chemin_seul = open(D, O_PATH);
    verifier(r(inotify_add_watch(chemin_seul, D, IN_CREATE)) == -EBADF && r(inotify_rm_watch(chemin_seul, 2)) == -EBADF,
             "inotify_add_watch et inotify_rm_watch d'un descripteur O_PATH : EBADF");
    close(chemin_seul);
    inotify_rm_watch(in, 2);
    inotify_rm_watch(in, 3);
    attendre("s:IGNORED f:IGNORED d:IGNORED", "IN_IGNORED de chaque surveillance retiree");
    unlink(p("s"));
    verifier(inotify_add_watch(in, D, IN_ALL_EVENTS) == 4, "les numeros tournent : 4 apres 1, 2, 3 retires");
    inotify_rm_watch(in, 4);
    attendre("4:IGNORED", "(retiree)");
}

static int wd, wf;

static void donnees(void)
{
    char b[16];
    wd = inotify_add_watch(in, D, IN_ALL_EVENTS);
    nommer(wd, "d");
    int fd = open(p("f"), O_RDWR);
    attendre("d:OPEN:f", "open (le dossier seul surveille)");
    wf = inotify_add_watch(in, p("f"), IN_ALL_EVENTS);
    nommer(wf, "f");
    (void)!write(fd, "abc", 3);
    attendre("d:MODIFY:f f:MODIFY", "write : au dossier (avec le nom), puis au fichier");
    (void)!write(fd, "a", 1);
    (void)!write(fd, "b", 1);
    (void)!write(fd, "c", 1);
    attendre("d:MODIFY:f f:MODIFY d:MODIFY:f f:MODIFY d:MODIFY:f f:MODIFY",
             "trois write : six evenements, sans fusion (seulement avec le dernier)");
    (void)!write(fd, "", 0);
    lseek(fd, 0, SEEK_END);
    (void)!read(fd, b, 2);
    attendre("", "write de 0 octet, read en fin de fichier : rien");
    (void)!pread(fd, b, 2, 0);
    (void)!pwrite(fd, "z", 1, 0);
    attendre("d:ACCESS:f f:ACCESS d:MODIFY:f f:MODIFY", "pread, pwrite");
    struct iovec v[2] = {{b, 1}, {b + 1, 1}};
    lseek(fd, 0, SEEK_SET);
    (void)!readv(fd, v, 2);
    (void)!writev(fd, v, 2);
    attendre("d:ACCESS:f f:ACCESS d:MODIFY:f f:MODIFY", "readv, writev : un evenement chacun");
    lseek(fd, 0, SEEK_END);
    (void)!readv(fd, v, 2);
    struct iovec vide = {b, 0};
    (void)!readv(fd, &vide, 1);
    (void)!writev(fd, &vide, 1);
    attendre("d:ACCESS:f f:ACCESS d:ACCESS:f f:ACCESS",
             "readv en fin de fichier, readv d'un morceau vide : IN_ACCESS (vfs_readv) ; writev vide : rien");
    (void)!ftruncate(fd, 1);
    (void)!truncate(p("f"), 2);
    attendre("d:MODIFY:f f:MODIFY d:MODIFY:f f:MODIFY", "ftruncate, truncate : IN_MODIFY");
    fchmod(fd, 0600);
    (void)!fchown(fd, -1, -1);
    (void)!chown(p("f"), getuid(), -1);
    attendre("d:ATTRIB:f f:ATTRIB d:ATTRIB:f f:ATTRIB", "fchmod, fchown -1 -1 (rien), chown a soi-meme : IN_ATTRIB");
    struct stat st;
    fchmod(fd, 04755);
    (void)!fchown(fd, -1, -1);
    fstat(fd, &st);
    int apres_chown = st.st_mode & 07777;
    attendre("d:ATTRIB:f f:ATTRIB d:ATTRIB:f f:ATTRIB", "fchown -1 -1 d'un fichier setuid : le bit tombe, IN_ATTRIB");
    fchmod(fd, 04755);
    (void)!write(fd, "s", 1);
    fstat(fd, &st);
    int apres_write = st.st_mode & 07777;
    fchmod(fd, 04755);
    (void)!ftruncate(fd, 3);
    fstat(fd, &st);
    attendre("d:ATTRIB:f f:ATTRIB d:ATTRIB:f f:ATTRIB d:MODIFY:f f:MODIFY d:ATTRIB:f f:ATTRIB d:MODIFY|ATTRIB:f f:MODIFY|ATTRIB",
             "write, ftruncate d'un fichier setuid : le bit tombe (IN_ATTRIB, avec IN_MODIFY pour ftruncate)");
    verifier(apres_chown == 0755 && apres_write == 0755 && (st.st_mode & 07777) == 0755,
             "le mode apres fchown -1 -1, write, ftruncate : 0755");
    fchmod(fd, 0600);
    attendre("d:ATTRIB:f f:ATTRIB", "(fchmod 0600)");
    struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
    utimensat(AT_FDCWD, p("f"), NULL, 0);
    utimensat(AT_FDCWD, p("f"), ts, 0);
    ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_nsec = UTIME_NOW;
    utimensat(AT_FDCWD, p("f"), ts, 0);
    ts[1].tv_nsec = UTIME_OMIT;
    utimensat(AT_FDCWD, p("f"), ts, 0);
    fsync(fd);
    attendre("d:ATTRIB:f f:ATTRIB d:ACCESS:f f:ACCESS d:MODIFY:f f:MODIFY",
             "utimensat : les deux dates IN_ATTRIB, l'acces seul IN_ACCESS, la modification seule IN_MODIFY, aucune rien ; fsync rien");
    close(fd);
    attendre("d:CLOSE_WRITE:f f:CLOSE_WRITE", "close d'un fichier ouvert en ecriture");
    close(open(p("f"), O_RDONLY));
    attendre("d:OPEN:f f:OPEN d:CLOSE_NOWRITE:f f:CLOSE_NOWRITE", "open en lecture, close");
    close(open(p("f"), O_WRONLY | O_TRUNC));
    attendre("d:OPEN:f f:OPEN d:MODIFY:f f:MODIFY d:CLOSE_WRITE:f f:CLOSE_WRITE", "open O_TRUNC : IN_OPEN, puis IN_MODIFY");
    close(open(p("f"), O_PATH));
    attendre("", "open O_PATH, close : rien");
    close(open(p("g"), O_CREAT | O_WRONLY, 0600));
    attendre("d:CREATE:g d:OPEN:g d:CLOSE_WRITE:g", "creat : IN_CREATE, puis IN_OPEN");
    close(open(p("g"), O_CREAT | O_RDONLY, 0600));
    attendre("d:OPEN:g d:CLOSE_NOWRITE:g", "O_CREAT d'un fichier qui existe : pas d'IN_CREATE");
    ecrire_fichier(p("f"), "0123456789");
    attendre("d:OPEN:f f:OPEN d:MODIFY:f f:MODIFY d:MODIFY:f f:MODIFY d:CLOSE_WRITE:f f:CLOSE_WRITE",
             "O_TRUNC puis write : deux IN_MODIFY, separes (le dernier est celui du fichier)");
    int e = open(p("f"), O_RDONLY), s = open(p("g"), O_RDWR);
    sendfile(s, e, NULL, 4);
    loff_t pe = 0, ps = 0;
    syscall(SYS_copy_file_range, e, &pe, s, &ps, 4, 0);
    close(e);
    close(s);
    attendre("d:OPEN:f f:OPEN d:OPEN:g d:ACCESS:f f:ACCESS d:MODIFY:g d:ACCESS:f f:ACCESS d:MODIFY:g "
             "d:CLOSE_NOWRITE:f f:CLOSE_NOWRITE d:CLOSE_WRITE:g",
             "sendfile, copy_file_range : la lecture de l'entree, puis l'ecriture de la sortie");
    int dossier = open(D, O_RDONLY | O_DIRECTORY);
    char ents[4096];
    syscall(SYS_getdents64, dossier, ents, sizeof ents);
    syscall(SYS_getdents64, dossier, ents, sizeof ents);
    close(dossier);
    attendre("d:OPEN|ISDIR d:ACCESS|ISDIR d:CLOSE_NOWRITE|ISDIR", "getdents64 deux fois (fusionnes), close du dossier");
}

static void noms_et_liens(void)
{
    (void)!link(p("f"), p("h"));
    unlink(p("h"));
    attendre("f:ATTRIB d:CREATE:h f:ATTRIB d:DELETE:h", "link, unlink : le nombre de liens (au fichier), l'entree (au dossier)");
    mkdir(p("sd"), 0700);
    attendre("d:CREATE|ISDIR:sd", "mkdir");
    int wsd = inotify_add_watch(in, p("sd"), IN_ALL_EVENTS);
    nommer(wsd, "sd");
    chmod(p("sd"), 0755);
    close(open(p("sd"), O_RDONLY | O_DIRECTORY));
    attendre("d:ATTRIB|ISDIR:sd sd:ATTRIB|ISDIR d:OPEN|ISDIR:sd sd:OPEN|ISDIR d:CLOSE_NOWRITE|ISDIR:sd sd:CLOSE_NOWRITE|ISDIR",
             "chmod, open, close d'un sous-dossier surveille : IN_ISDIR");
    mkdir(p("sd"), 0700);
    rmdir(D);
    attendre("", "mkdir qui existe, rmdir non vide : rien");
    rename(p("sd"), p("l"));
    rename(p("l"), p("sd"));
    attendre("d:MOVED_FROM|ISDIR:c1:sd d:MOVED_TO|ISDIR:c1:l sd:MOVE_SELF d:MOVED_FROM|ISDIR:c2:l d:MOVED_TO|ISDIR:c2:sd sd:MOVE_SELF",
             "rename d'un dossier, aller et retour : deux cookies ; IN_MOVE_SELF sans IN_ISDIR");
    close(open(p("sd/x"), O_CREAT | O_WRONLY, 0600));
    unlink(p("sd/x"));
    attendre("sd:CREATE:x sd:OPEN:x sd:CLOSE_WRITE:x sd:DELETE:x", "creat, unlink dans le sous-dossier");
    (void)!symlink("f", p("s"));
    struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    utimensat(AT_FDCWD, p("s"), ts, AT_SYMLINK_NOFOLLOW);
    utimensat(AT_FDCWD, p("s"), ts, 0);
    unlink(p("s"));
    attendre("d:CREATE:s d:ATTRIB:s d:ATTRIB:f f:ATTRIB d:DELETE:s", "symlink, utimensat du lien puis suivi, unlink");
    char lien[64];
    int fd = open(p("f"), O_RDWR);
    snprintf(lien, sizeof lien, "/proc/self/fd/%d", fd);
    chmod(lien, 0600);
    (void)!truncate(lien, 3);
    close(open(lien, O_RDONLY));
    close(fd);
    attendre("d:OPEN:f f:OPEN d:ATTRIB:f f:ATTRIB d:MODIFY:f f:MODIFY d:OPEN:f f:OPEN d:CLOSE_NOWRITE:f f:CLOSE_NOWRITE "
             "d:CLOSE_WRITE:f f:CLOSE_WRITE",
             "par /proc/self/fd/N : chmod, truncate, open, au nom du fichier ouvert");
    (void)!link(p("f"), p("sd/h"));
    fd = open(p("sd/h"), O_RDONLY);
    (void)!read(fd, lien, 1);
    close(fd);
    unlink(p("sd/h"));
    attendre("f:ATTRIB sd:CREATE:h sd:OPEN:h f:OPEN sd:ACCESS:h f:ACCESS sd:CLOSE_NOWRITE:h f:CLOSE_NOWRITE f:ATTRIB sd:DELETE:h",
             "un lien physique ouvert par son autre nom : au dossier de ce nom");
}

static void renommer(void)
{
    rename(p("f"), p("n"));
    rename(p("n"), p("f"));
    attendre("d:MOVED_FROM:c1:f d:MOVED_TO:c1:n f:MOVE_SELF d:MOVED_FROM:c2:n d:MOVED_TO:c2:f f:MOVE_SELF",
             "rename, aller et retour : le meme cookie par deplacement");
    rename(p("f"), p("f"));
    attendre("", "rename vers lui-meme : rien");
    rename(p("g"), p("f"));
    attendre("d:MOVED_FROM:c1:g d:MOVED_TO:c1:f f:ATTRIB f:DELETE_SELF f:IGNORED", "rename sur un fichier surveille : il finit");
    close(open(p("g"), O_CREAT | O_WRONLY, 0600));
    attendre("d:CREATE:g d:OPEN:g d:CLOSE_WRITE:g", "(g)");
    wf = inotify_add_watch(in, p("f"), IN_ALL_EVENTS);
    int wg = inotify_add_watch(in, p("g"), IN_ALL_EVENTS);
    nommer(wf, "f");
    nommer(wg, "g");
    syscall(SYS_renameat2, AT_FDCWD, p("f"), AT_FDCWD, p("g"), RENAME_EXCHANGE);
    attendre("d:MOVED_FROM:c1:f d:MOVED_TO:c1:g f:MOVE_SELF d:MOVED_FROM:c2:g d:MOVED_TO:c2:f g:MOVE_SELF",
             "RENAME_EXCHANGE : deux deplacements, deux cookies");
    /* f est maintenant l'ancien g (wd g), g l'ancien f (wd f). */
    nommer(wf, "g");
    nommer(wg, "f");
    int fd = open(p("f"), O_RDWR);
    rename(p("f"), p("n"));
    (void)!write(fd, "x", 1);
    rename(p("n"), p("f"));
    close(fd);
    attendre("d:OPEN:f f:OPEN d:MOVED_FROM:c1:f d:MOVED_TO:c1:n f:MOVE_SELF d:MODIFY:n f:MODIFY "
             "d:MOVED_FROM:c2:n d:MOVED_TO:c2:f f:MOVE_SELF d:CLOSE_WRITE:f f:CLOSE_WRITE",
             "un fichier ouvert suit son nom");
    mkdir(p("autre"), 0700);
    attendre("d:CREATE|ISDIR:autre", "(autre)");
    int wa = inotify_add_watch(in, p("autre"), IN_ALL_EVENTS);
    nommer(wa, "autre");
    rename(p("f"), p("autre/f"));
    rename(p("autre/f"), p("f"));
    attendre("d:MOVED_FROM:c1:f autre:MOVED_TO:c1:f f:MOVE_SELF autre:MOVED_FROM:c2:f d:MOVED_TO:c2:f f:MOVE_SELF",
             "rename d'un dossier a l'autre, aller et retour");
    rmdir(p("autre"));
    attendre("autre:DELETE_SELF autre:IGNORED d:DELETE|ISDIR:autre", "rmdir d'un dossier surveille");
    unlink(p("g"));
    attendre("g:ATTRIB g:DELETE_SELF g:IGNORED d:DELETE:g", "unlink d'un fichier surveille, ferme : il finit aussitot");
    fd = open(p("f"), O_RDWR);
    unlink(p("f"));
    (void)!write(fd, "q", 1);
    attendre("d:OPEN:f f:OPEN f:ATTRIB d:DELETE:f d:MODIFY:f f:MODIFY",
             "unlink d'un fichier ouvert : il vit, et son dossier en entend encore parler");
    close(fd);
    attendre("d:CLOSE_WRITE:f f:CLOSE_WRITE f:DELETE_SELF f:IGNORED", "son dernier close : il finit");
    fd = open(p("sd/y"), O_CREAT | O_RDWR, 0600);
    unlink(p("sd/y"));
    rmdir(p("sd"));
    (void)!write(fd, "z", 1);
    attendre("sd:CREATE:y sd:OPEN:y sd:DELETE:y d:DELETE|ISDIR:sd sd:MODIFY:y",
             "rmdir d'un dossier dont un fichier est encore ouvert : il attend");
    close(fd);
    attendre("sd:CLOSE_WRITE:y sd:DELETE_SELF sd:IGNORED", "le close du fichier : le dossier finit");
}

/* Un fichier à deux noms (`dentry_unlink_inode`) : la fin vient quand
 * meurt une entrée que personne ne tient, l'inode n'ayant plus de nom. */
static void deux_noms(void)
{
    close(open(p("u"), O_CREAT | O_WRONLY, 0600));
    int wu = inotify_add_watch(in, p("u"), IN_ALL_EVENTS);
    nommer(wu, "u");
    int fd = open(p("u"), O_RDONLY);
    (void)!link(p("u"), p("h"));
    unlink(p("u"));
    unlink(p("h"));
    close(fd);
    attendre("d:CREATE:u d:OPEN:u d:CLOSE_WRITE:u d:OPEN:u u:OPEN u:ATTRIB d:CREATE:h u:ATTRIB d:DELETE:u "
             "u:ATTRIB u:DELETE_SELF u:IGNORED d:DELETE:h d:CLOSE_NOWRITE:u",
             "ouvert par u, lie en h, efface par u puis par h : la fin a l'effacement de h, rien au close");
    close(open(p("u"), O_CREAT | O_WRONLY, 0600));
    wu = inotify_add_watch(in, p("u"), IN_ALL_EVENTS);
    nommer(wu, "u");
    (void)!link(p("u"), p("h"));
    int f1 = open(p("u"), O_RDONLY), f2 = open(p("h"), O_RDONLY);
    unlink(p("u"));
    unlink(p("h"));
    close(f1);
    close(f2);
    attendre("d:CREATE:u d:OPEN:u d:CLOSE_WRITE:u u:ATTRIB d:CREATE:h d:OPEN:u u:OPEN d:OPEN:h u:OPEN u:ATTRIB d:DELETE:u "
             "u:ATTRIB d:DELETE:h d:CLOSE_NOWRITE:u u:CLOSE_NOWRITE u:DELETE_SELF u:IGNORED d:CLOSE_NOWRITE:h",
             "ouvert par u et par h, efface deux fois : la fin au premier close");
}

/* RENAME_EXCHANGE : les fichiers ouverts par l'une et l'autre entrée
 * suivent (le `d_exchange` de Linux). */
static void echange_ouvert(void)
{
    close(open(p("f"), O_CREAT | O_WRONLY, 0600));
    close(open(p("g"), O_CREAT | O_WRONLY, 0600));
    int ff = open(p("f"), O_WRONLY), fg = open(p("g"), O_WRONLY);
    syscall(SYS_renameat2, AT_FDCWD, p("f"), AT_FDCWD, p("g"), RENAME_EXCHANGE);
    (void)!write(ff, "x", 1);
    (void)!write(fg, "y", 1);
    close(ff);
    close(fg);
    unlink(p("f"));
    unlink(p("g"));
    attendre("d:CREATE:f d:OPEN:f d:CLOSE_WRITE:f d:CREATE:g d:OPEN:g d:CLOSE_WRITE:g d:OPEN:f d:OPEN:g "
             "d:MOVED_FROM:c1:f d:MOVED_TO:c1:g d:MOVED_FROM:c2:g d:MOVED_TO:c2:f d:MODIFY:g d:MODIFY:f "
             "d:CLOSE_WRITE:g d:CLOSE_WRITE:f d:DELETE:f d:DELETE:g",
             "RENAME_EXCHANGE de deux fichiers ouverts : chacun ecrit sous son nouveau nom");
}

/* « . » et « .. » : un dossier ouvert par eux s'annonce à son parent, sous
 * son nom. */
static void point(void)
{
    mkdir(p("sd"), 0700);
    char ici[300];
    if (!getcwd(ici, sizeof ici) || chdir(p("sd")) != 0)
        verifier(0, "chdir");
    close(open(".", O_RDONLY | O_DIRECTORY));
    chmod(".", 0700);
    close(open("..", O_RDONLY | O_DIRECTORY));
    if (chdir(ici) != 0)
        verifier(0, "chdir");
    rmdir(p("sd"));
    attendre("d:CREATE|ISDIR:sd d:OPEN|ISDIR:sd d:CLOSE_NOWRITE|ISDIR:sd d:ATTRIB|ISDIR:sd d:OPEN|ISDIR d:CLOSE_NOWRITE|ISDIR "
             "d:DELETE|ISDIR:sd", "open(.), chmod(.), open(..) : au parent, sous le nom du dossier");
}

/* /proc et /sys : un fichier lu s'annonce à lui-même et à son dossier,
 * sous son nom (mesuré sous Linux 6.18). Les événements, écrits
 * « dossier:MASQUE:nom » ou « fichier:MASQUE ». */
static void systemes_montes(void)
{
    struct {
        const char *dossier, *fichier;
    } c[] = {
        {"/proc/self", "/proc/self/comm"},
        {"/proc/sys/vm", "/proc/sys/vm/overcommit_memory"},
        {"/sys/devices/system/cpu", "/sys/devices/system/cpu/online"},
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        int k = inotify_init1(IN_NONBLOCK);
        int wd = inotify_add_watch(k, c[i].dossier, IN_ALL_EVENTS), wfi = inotify_add_watch(k, c[i].fichier, IN_ALL_EVENTS);
        char t[64];
        int fd = open(c[i].fichier, O_RDONLY);
        (void)!read(fd, t, sizeof t);
        close(fd);
        static char b[4096] __attribute__((aligned(8)));
        char vu[512] = "", attendu[512];
        ssize_t l = read(k, b, sizeof b);
        for (char *q = b; l > 0 && q < b + l;) {
            struct inotify_event *e = (void *)q;
            char m[64], un[160];
            masque(e->mask, m);
            snprintf(un, sizeof un, "%s%s:%s%s%s", vu[0] ? " " : "", e->wd == wd ? "dossier" : e->wd == wfi ? "fichier" : "?", m,
                     e->len ? ":" : "", e->len ? e->name : "");
            strncat(vu, un, sizeof vu - strlen(vu) - 1);
            q += sizeof *e + e->len;
        }
        const char *nom = strrchr(c[i].fichier, '/') + 1;
        snprintf(attendu, sizeof attendu,
                 "dossier:OPEN:%s fichier:OPEN dossier:ACCESS:%s fichier:ACCESS dossier:CLOSE_NOWRITE:%s fichier:CLOSE_NOWRITE", nom, nom,
                 nom);
        int ok = strcmp(vu, attendu) == 0;
        if (!ok)
            printf("[linux] surveillance : %s : lu « %s », attendu « %s »\n", c[i].fichier, vu, attendu);
        char quoi[200];
        snprintf(quoi, sizeof quoi, "lire %s : au fichier, et a %s sous son nom", c[i].fichier, c[i].dossier);
        verifier(ok, quoi);
        close(k);
    }
}

static void drapeaux(void)
{
    int fd = open(p("f"), O_CREAT | O_RDWR, 0600);
    attendre("d:CREATE:f d:OPEN:f", "(f)");
    inotify_rm_watch(in, wd);
    attendre("d:IGNORED", "(d retire)");
    wf = inotify_add_watch(in, p("f"), IN_MODIFY | IN_ONESHOT);
    nommer(wf, "f");
    (void)!write(fd, "1", 1);
    (void)!write(fd, "2", 1);
    attendre("f:MODIFY f:IGNORED", "IN_ONESHOT : un evenement, puis IN_IGNORED");
    wf = inotify_add_watch(in, p("f"), IN_MODIFY);
    nommer(wf, "f");
    verifier(inotify_add_watch(in, p("f"), IN_ATTRIB | IN_MASK_ADD) == wf, "IN_MASK_ADD : la meme surveillance");
    (void)!write(fd, "1", 1);
    fchmod(fd, 0600);
    attendre("f:MODIFY f:ATTRIB", "IN_MASK_ADD : les deux masques");
    inotify_add_watch(in, p("f"), IN_ATTRIB);
    (void)!write(fd, "1", 1);
    fchmod(fd, 0600);
    attendre("f:ATTRIB", "sans IN_MASK_ADD : le masque remplace");
    inotify_add_watch(in, p("f"), IN_MODIFY | IN_ATTRIB | IN_EXCL_UNLINK);
    wd = inotify_add_watch(in, D, IN_MODIFY | IN_DELETE | IN_EXCL_UNLINK);
    nommer(wd, "d");
    unlink(p("f"));
    (void)!write(fd, "1", 1);
    fchmod(fd, 0600);
    attendre("f:ATTRIB d:DELETE:f f:ATTRIB",
             "IN_EXCL_UNLINK : plus d'ecriture une fois le nom efface ; les attributs, si");
    close(fd);
    attendre("f:IGNORED", "close : la fin, sans IN_DELETE_SELF (pas demande)");
}

static void autres_fichiers(void)
{
    char c[64], b[8];
    int t[2];
    (void)!pipe(t);
    snprintf(c, sizeof c, "/proc/self/fd/%d", t[0]);
    int wt = inotify_add_watch(in, c, IN_ALL_EVENTS);
    nommer(wt, "tube");
    (void)!write(t[1], "x", 1);
    (void)!read(t[0], b, 1);
    close(t[1]);
    close(t[0]);
    attendre("tube:MODIFY tube:ACCESS tube:CLOSE_WRITE tube:CLOSE_NOWRITE", "un tube : ecriture, lecture, et ses deux bouts fermes");
    verifier(inotify_rm_watch(in, wt) == 0, "la surveillance d'un tube ferme demeure");
    attendre("tube:IGNORED", "inotify_rm_watch : IN_IGNORED");
    int sv[2];
    (void)!socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    snprintf(c, sizeof c, "/proc/self/fd/%d", sv[0]);
    int wso = inotify_add_watch(in, c, IN_ALL_EVENTS);
    nommer(wso, "socket");
    (void)!write(sv[1], "x", 1);
    (void)!read(sv[0], b, 1);
    (void)!write(sv[0], "y", 1);
    send(sv[0], "z", 1, 0);
    close(sv[0]);
    close(sv[1]);
    attendre("socket:ACCESS socket:MODIFY socket:CLOSE_WRITE", "une socket : read, write (pas send), close");
    inotify_rm_watch(in, wso);
    attendre("socket:IGNORED", "(retiree)");
    int wn = inotify_add_watch(in, "/dev/null", IN_ALL_EVENTS);
    nommer(wn, "null");
    int nf = open("/dev/null", O_WRONLY);
    (void)!write(nf, "x", 1);
    close(nf);
    inotify_rm_watch(in, wn);
    attendre("null:OPEN null:MODIFY null:CLOSE_WRITE null:IGNORED", "/dev/null : open, write, close");
    int so = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    snprintf(a.sun_path, sizeof a.sun_path, "%.100s/so", D);
    bind(so, (void *)&a, sizeof a);
    close(so);
    unlink(a.sun_path);
    attendre("d:CREATE:so d:DELETE:so", "bind d'une socket AF_UNIX : IN_CREATE");
}

static void lecture(void)
{
    close(open(p("un-nom-de-vingt-octets"), O_CREAT | O_WRONLY, 0600));
    int n = 0;
    ioctl(in, FIONREAD, &n);
    verifier(n == 3 * 48, "FIONREAD : trois evenements de 48 octets (le nom de 22 octets complete jusqu'a 32)");
    struct pollfd pf = {in, POLLIN | POLLOUT | POLLPRI | POLLRDNORM, 0};
    int k = poll(&pf, 1, 0);
    verifier(k == 1 && pf.revents == (POLLIN | POLLRDNORM), "poll : POLLIN | POLLRDNORM");
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLET}, sortie;
    epoll_ctl(ep, EPOLL_CTL_ADD, in, &ev);
    verifier(epoll_wait(ep, &sortie, 1, 0) == 1 && sortie.events == EPOLLIN, "epoll : EPOLLIN");
    close(ep);
    char petit[48], moyen[100];
    struct iovec v[2] = {{moyen, 20}, {moyen + 20, 80}};
    verifier(r(read(in, petit, 16)) == -EINVAL && r(read(in, petit, 47)) == -EINVAL && r(readv(in, v, 2)) == -EINVAL,
             "un tampon trop petit pour le premier evenement : EINVAL (readv : morceau par morceau)");
    memset(moyen, 0xff, sizeof moyen);
    verifier(read(in, moyen, 100) == 96, "read de 100 octets : deux evenements, 96");
    struct inotify_event *e = (void *)moyen;
    verifier(e->len == 32 && strcmp(e->name, "un-nom-de-vingt-octets") == 0 && e->name[22] == 0 && e->name[31] == 0,
             "le nom, et des zeros jusqu'a 32 octets");
    unlink(p("un-nom-de-vingt-octets"));
    attendre("d:CLOSE_WRITE:un-nom-de-vingt-octets d:DELETE:un-nom-de-vingt-octets", "le reste de la file");
    pf.revents = 0;
    verifier(r(read(in, petit, 48)) == -EAGAIN && poll(&pf, 1, 0) == 0, "vide : EAGAIN, poll 0");
    /* readv d'une instance et ses morceaux vides (`vfs_readv`, puis
     * `do_loop_readv_writev`) : des événements de 16 octets (une
     * surveillance du fichier, sans nom). */
    int iv = inotify_init1(IN_NONBLOCK), kb = inotify_init1(0);
    close(open(p("v"), O_CREAT | O_WRONLY, 0600));
    inotify_add_watch(iv, p("v"), IN_OPEN | IN_CLOSE);
    close(open(p("v"), O_RDONLY));
    char a1[16], a2[16], a3[16];
    struct iovec w3[3] = {{a1, 16}, {a2, 0}, {a3, 16}}, w2[2] = {{a2, 0}, {a3, 16}}, w1 = {a1, 0};
    long n3 = r(readv(iv, w3, 3));
    close(open(p("v"), O_RDONLY));
    long n2 = r(readv(iv, w2, 2));
    long n1 = r(readv(kb, &w1, 1));
    verifier(n3 == 32 && n2 == -EINVAL && n1 == 0,
             "readv d'une instance : {16, 0, 16} lit deux evenements ; {0, 16}, EINVAL ; {0}, 0 (meme bloquante et vide)");
    close(iv);
    close(kb);
    unlink(p("v"));
    attendre("d:CREATE:v d:OPEN:v d:CLOSE_WRITE:v d:OPEN:v d:CLOSE_NOWRITE:v d:OPEN:v d:CLOSE_NOWRITE:v d:DELETE:v", "(v)");
}

static void debordement(void)
{
    int fa = open(p("a"), O_CREAT | O_WRONLY, 0600), fb = open(p("b"), O_CREAT | O_WRONLY, 0600);
    char vu[200];
    lire_de(in, vu, sizeof vu);
    for (int i = 0; i < 16400; i++)
        (void)!write(i % 2 ? fb : fa, "x", 1);
    int n = 0;
    ioctl(in, FIONREAD, &n);
    verifier(n == 16384 * 32 + 16, "16400 ecritures alternees : 16384 evenements, puis IN_Q_OVERFLOW (FIONREAD)");
    static char gros[16384 * 32 + 64] __attribute__((aligned(8)));
    ssize_t l = read(in, gros, sizeof gros);
    struct inotify_event *dernier = NULL;
    int k = 0;
    for (char *q = gros; l > 0 && q < gros + l; k++) {
        dernier = (void *)q;
        q += sizeof *dernier + dernier->len;
    }
    verifier(k == 16385 && dernier && dernier->wd == -1 && dernier->mask == IN_Q_OVERFLOW && dernier->len == 0,
             "le dernier : IN_Q_OVERFLOW, numero -1, sans nom");
    (void)!write(fa, "x", 1);
    attendre("d:MODIFY:a", "vide : les evenements reviennent");
    /* Exactement pleine, puis le même événement que le dernier :
     * IN_Q_OVERFLOW, la place regardée avant la fusion
     * (`fsnotify_insert_event`). */
    for (int i = 0; i < 16384; i++)
        (void)!write(i % 2 ? fb : fa, "x", 1);
    int plein = 0, apres = 0;
    ioctl(in, FIONREAD, &plein);
    (void)!write(fb, "x", 1);
    ioctl(in, FIONREAD, &apres);
    verifier(plein == 16384 * 32 && apres == 16384 * 32 + 16,
             "file pleine, puis le meme evenement que le dernier : IN_Q_OVERFLOW (pas de fusion)");
    (void)!read(in, gros, sizeof gros);
    close(fa);
    close(fb);
    unlink(p("a"));
    unlink(p("b"));
    lire_de(in, vu, sizeof vu);
}

static void attentes(void)
{
    /* Un read bloquant, réveillé par un événement d'un autre fil. */
    int b = inotify_init1(0);
    close(open(p("r"), O_CREAT | O_WRONLY, 0600));
    inotify_add_watch(b, p("r"), IN_MODIFY);
    pthread_t fil;
    pthread_create(&fil, NULL, ecrire_plus_tard, (void *)p("r"));
    char t[64];
    ssize_t l = read(b, t, sizeof t);
    pthread_join(fil, NULL);
    verifier(l == 16 && ((struct inotify_event *)t)->mask == IN_MODIFY, "read bloquant, reveille par l'ecriture d'un autre fil");
    /* O_ASYNC : SIGIO à chaque événement. */
    struct sigaction sa = {.sa_handler = sur_sigio};
    sigaction(SIGIO, &sa, NULL);
    fcntl(b, F_SETOWN, getpid());
    fcntl(b, F_SETFL, O_ASYNC | O_NONBLOCK);
    int fd = open(p("r"), O_WRONLY);
    (void)!write(fd, "y", 1);
    close(fd);
    verifier(sigio == 1, "O_ASYNC : SIGIO");
    (void)!read(b, t, sizeof t);
    /* Une seconde instance a ses propres numéros ; les deux voient tout. */
    attendre("d:CREATE:r d:OPEN:r d:CLOSE_WRITE:r d:OPEN:r d:MODIFY:r d:CLOSE_WRITE:r d:OPEN:r d:MODIFY:r d:CLOSE_WRITE:r",
             "ce qu'en a vu la premiere instance");
    int c = inotify_init1(IN_NONBLOCK);
    int w1 = inotify_add_watch(c, p("r"), IN_ATTRIB), w2 = inotify_add_watch(in, p("r"), IN_ATTRIB);
    nommer(w2, "r");
    chmod(p("r"), 0644);
    int n = 0;
    ioctl(c, FIONREAD, &n);
    verifier(w1 == 1 && n == 16, "une seconde instance : son numero 1, et l'evenement");
    attendre("d:ATTRIB:r r:ATTRIB", "la premiere aussi");
    close(c);
    close(b);
    unlink(p("r"));
    attendre("r:ATTRIB r:IGNORED d:DELETE:r", "unlink : la fin, sans IN_DELETE_SELF (pas demande) ; les instances fermees, rien");
}

static void limites(void)
{
    long instances = 0, surveillances = 0, file = 0;
    FILE *f = fopen("/proc/sys/fs/inotify/max_user_instances", "r");
    if (f) {
        (void)!fscanf(f, "%ld", &instances);
        fclose(f);
    }
    f = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
    if (f) {
        (void)!fscanf(f, "%ld", &surveillances);
        fclose(f);
    }
    f = fopen("/proc/sys/fs/inotify/max_queued_events", "r");
    if (f) {
        (void)!fscanf(f, "%ld", &file);
        fclose(f);
    }
    verifier(instances >= 128 && surveillances >= 8192 && surveillances <= 1048576 && file == 16384,
             "/proc/sys/fs/inotify : des instances (128 au moins), des surveillances (8192 a 1048576), 16384 evenements");
    /* Au-delà des instances permises : EMFILE (là où la limite tient sous
     * celle des descripteurs : 128 dans notre noyau ; 8192 sur l'hôte, sauté). */
    if (instances <= 512) {
        int ouvertes[512], k = 0, e = 0;
        while (k < 512) {
            int i = inotify_init1(0);
            if (i < 0) {
                e = errno;
                break;
            }
            ouvertes[k++] = i;
        }
        /* Deux instances sont déjà ouvertes : `in`, et aucune autre. */
        verifier(k == instances - 1 && e == EMFILE, "au-dela de max_user_instances : EMFILE");
        while (k > 0)
            close(ouvertes[--k]);
    }
    int s = r(ioctl(in, _IOW('I', 0, int32_t), 0));
    int s2 = r(ioctl(in, _IOW('I', 0, int32_t), 100));
    verifier(s == -EINVAL && s2 == 0 && inotify_add_watch(in, "/", IN_ATTRIB) == 100,
             "INOTIFY_IOC_SETNEXTWD : 0 refuse, puis le prochain numero est 100");
}

/* Le guetteur : les événements de NOM dans DOSSIER, autant qu'il en attend
 * (10 s au plus). */
static int guetter(const char *dossier, const char *nom, const char *attendus, const char *dossier2, const char *nom2)
{
    int g = inotify_init1(0);
    inotify_add_watch(g, dossier, IN_ALL_EVENTS);
    if (dossier2)
        inotify_add_watch(g, dossier2, IN_ALL_EVENTS);
    struct sigaction sa = {.sa_handler = sur_sigio};
    sigaction(SIGIO, &sa, NULL);
    fcntl(g, F_SETOWN, getpid());
    fcntl(g, F_SETFL, O_ASYNC);
    int nombre = 1;
    for (const char *c = attendus; *c; c++)
        nombre += *c == ' ';
    char vu[512] = "";
    static char b[4096] __attribute__((aligned(8)));
    for (int vus = 0; vus < nombre;) {
        struct pollfd pf = {g, POLLIN, 0};
        int k = poll(&pf, 1, 10000);
        if (k < 0 && errno == EINTR)
            continue;
        if (k != 1)
            break;
        ssize_t l = read(g, b, sizeof b);
        for (char *q = b; l > 0 && q < b + l;) {
            struct inotify_event *e = (void *)q;
            q += sizeof *e + e->len;
            int premier = e->len && strcmp(e->name, nom) == 0, second = nom2 && e->len && strcmp(e->name, nom2) == 0;
            if (!premier && !second)
                continue;
            char m[64], un[160];
            masque(e->mask, m);
            if (nom2)
                snprintf(un, sizeof un, "%s:%s", e->name, m);
            else
                snprintf(un, sizeof un, "%s", m);
            if (strlen(vu) + strlen(un) + 2 < sizeof vu) {
                strcat(vu, vu[0] ? " " : "");
                strcat(vu, un);
            }
            vus++;
        }
    }
    /* Le lanceur dit d'abord la fin du programme : ne pas écrire en même
     * temps que lui sur la console. */
    struct timespec t = {0, 500 * 1000 * 1000};
    nanosleep(&t, NULL);
    int ok = strcmp(vu, attendus) == 0 && sigio > 0;
    if (!ok)
        printf("[linux] surveillance : %s : lu « %s », %d SIGIO\n", nom, vu, sigio);
    char quoi[300];
    snprintf(quoi, sizeof quoi, "guetter %s dans %s : %s, et SIGIO", nom, dossier, attendus);
    verifier(ok, quoi);
    return !ok;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 5 && strcmp(argv[1], "--guetter") == 0)
        return guetter(argv[2], argv[3], argv[4], NULL, NULL);
    if (argc == 7 && strcmp(argv[1], "--guetter") == 0)
        return guetter(argv[2], argv[3], argv[4], argv[5], argv[6]);
    if (argc == 3 && strcmp(argv[1], "--dormir") == 0) {
        struct timespec t = {0, atoi(argv[2]) * 1000000L};
        nanosleep(&t, NULL);
        return 0;
    }
    snprintf(D, sizeof D, "%s/surveillance", argc > 1 ? argv[1] : "/tmp");
    mkdir(D, 0700);
    in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    appels();
    donnees();
    noms_et_liens();
    renommer();
    deux_noms();
    echange_ouvert();
    point();
    systemes_montes();
    drapeaux();
    wd = inotify_add_watch(in, D, IN_ALL_EVENTS);
    nommer(wd, "d");
    autres_fichiers();
    lecture();
    debordement();
    attentes();
    limites();
    close(in);
    rmdir(D);
    if (ecarts == 0)
        printf("[linux] surveillance : toutes les verifications : ok\n");
    return ecarts != 0;
}
