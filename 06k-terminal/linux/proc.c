/*
 * /proc et /sys (6d) : ce qu'y lit Bun (maps, statm, /proc/sys/vm, le
 * nombre de processeurs, le réglage des grandes pages), et ce qu'en dit
 * Linux 6.18 (mesuré). Il tourne dans notre noyau et sur l'hôte (make
 * tests-hote) : chaque ligne doit dire « ok » des deux côtés. Ce qui dépend
 * de la machine (les valeurs des réglages, le nombre exact de pages
 * résidentes, ce que contient /proc en plus) n'est vérifié exactement que
 * chez nous ; sur l'hôte, aucune écriture n'est essayée sous /proc/sys
 * ni sous /sys (montés en lecture seule dans un conteneur).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/fs.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <unistd.h>

static int echecs;
static int chez_nous;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] proc : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static int erreur(long r)
{
    return r < 0 ? errno : 0;
}

/* Tout un fichier, lu par morceaux de `morceau` octets. */
static size_t lire_tout(const char *chemin, char *tampon, size_t taille, size_t morceau)
{
    int fd = open(chemin, O_RDONLY);
    size_t fait = 0;
    ssize_t n;
    while (fd >= 0 && fait < taille - 1 && (n = read(fd, tampon + fait, morceau < taille - 1 - fait ? morceau : taille - 1 - fait)) > 0)
        fait += n;
    tampon[fait] = 0;
    if (fd >= 0)
        close(fd);
    return fait;
}

static char cartes[65536], morceaux[65536];

/* Une ligne de maps, lue au format de Linux. */
struct ligne {
    unsigned long debut, fin, decalage, inode;
    char droits[5];
    unsigned majeur, mineur;
    const char *nom; /* NULL sans nom */
};

static int lire_ligne(const char *texte, struct ligne *l)
{
    int lu = 0;
    if (sscanf(texte, "%lx-%lx %4s %lx %x:%x %lu %n", &l->debut, &l->fin, l->droits, &l->decalage, &l->majeur, &l->mineur,
               &l->inode, &lu) < 7)
        return 0;
    const char *fin = strchr(texte, '\n');
    l->nom = NULL;
    if (texte + lu < fin)
        l->nom = texte + lu;
    /* Le nom commence à la colonne 73 (des espaces avant) quand la ligne
     * est assez courte. */
    if (l->nom && lu < 73 && l->nom != texte + 73)
        return 0;
    return 1;
}

/* La ligne de `cartes` qui contient l'adresse `a` ; 0 s'il n'y en a pas. */
static int trouver(unsigned long a, struct ligne *l, char *nom, size_t taille)
{
    for (const char *p = cartes; *p; p = strchr(p, '\n') + 1) {
        if (!lire_ligne(p, l))
            return 0;
        if (l->debut <= a && a < l->fin) {
            nom[0] = 0;
            if (l->nom) {
                size_t n = strchr(l->nom, '\n') - l->nom;
                if (n >= taille)
                    n = taille - 1;
                memcpy(nom, l->nom, n);
                nom[n] = 0;
            }
            return 1;
        }
    }
    return 0;
}

static void carte(void)
{
    char exe[4096] = { 0 }, nom[4096];
    struct ligne l;
    verifier(readlink("/proc/self/exe", exe, sizeof exe - 1) > 0 && exe[0] == '/', "/proc/self/exe : un chemin absolu");
    if (chez_nous)
        verifier(strcmp(exe, "/bin/proc") == 0, "/proc/self/exe, chez nous : /bin/proc");
    char moi[32], lien[32] = { 0 };
    snprintf(moi, sizeof moi, "%d", getpid());
    verifier(readlink("/proc/self", lien, sizeof lien - 1) > 0 && strcmp(lien, moi) == 0, "/proc/self : le numero du processus");

    size_t n = lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    int toutes = n > 0;
    for (const char *p = cartes; *p; p = strchr(p, '\n') + 1)
        toutes &= lire_ligne(p, &l);
    verifier(toutes, "chaque ligne de maps au format de Linux (nom a la colonne 73)");
    struct stat s;
    stat(exe, &s);
    verifier(trouver((unsigned long)&carte, &l, nom, sizeof nom) && strcmp(nom, exe) == 0 && l.droits[2] == 'x'
             && l.inode == s.st_ino && makedev(l.majeur, l.mineur) == s.st_dev,
             "la ligne de son code : r-x, son chemin canonique, son inode et son peripherique");
    int local;
    verifier(trouver((unsigned long)&local, &l, nom, sizeof nom) && strcmp(nom, "[stack]") == 0 && strcmp(l.droits, "rw-p") == 0,
             "[stack] contient une variable locale");
    char *tas = sbrk(0);
    sbrk(4 * 4096);
    tas[0] = 1;
    lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    verifier(trouver((unsigned long)tas, &l, nom, sizeof nom) && strcmp(nom, "[heap]") == 0, "[heap] apres un brk");

    /* Une page lisible et inscriptible entre deux pages PROT_NONE. */
    char *p = mmap(NULL, 3 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(p + 4096, 4096, PROT_READ | PROT_WRITE);
    lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    verifier(trouver((unsigned long)p + 4096, &l, nom, sizeof nom) && l.debut == (unsigned long)p + 4096
             && l.fin == (unsigned long)p + 8192 && strcmp(l.droits, "rw-p") == 0 && l.decalage == 0 && l.inode == 0
             && l.majeur == 0 && l.mineur == 0 && nom[0] == 0, "une zone coupee par mprotect : ses bornes, ses droits, sans nom");
    verifier(trouver((unsigned long)p, &l, nom, sizeof nom) && strcmp(l.droits, "---p") == 0, "les pages PROT_NONE autour : ---p");
    munmap(p + 4096, 4096);
    lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    verifier(!trouver((unsigned long)p + 4096, &l, nom, sizeof nom), "apres munmap, plus de ligne");
    munmap(p, 3 * 4096);

    /* Un fichier projeté par un lien : nommé par son chemin canonique, avec
     * son décalage ; « (deleted) » une fois effacé. */
    char fichier[64], vers[64];
    snprintf(fichier, sizeof fichier, "/tmp/proc.%d.f", getpid());
    snprintf(vers, sizeof vers, "/tmp/proc.%d.l", getpid());
    int fd = open(fichier, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (ftruncate(fd, 3 * 4096) < 0)
        verifier(0, "ftruncate");
    close(fd);
    if (symlink(fichier, vers) < 0)
        verifier(0, "symlink");
    fd = open(vers, O_RDONLY);
    char *f = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 4096);
    fstat(fd, &s);
    lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    verifier(trouver((unsigned long)f, &l, nom, sizeof nom) && strcmp(nom, fichier) == 0 && l.decalage == 4096
             && l.inode == s.st_ino && strcmp(l.droits, "r--p") == 0,
             "un fichier projete par un lien : sa cible, son decalage, son inode");
    unlink(fichier);
    unlink(vers);
    lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    char efface[80];
    snprintf(efface, sizeof efface, "%s (deleted)", fichier);
    verifier(trouver((unsigned long)f, &l, nom, sizeof nom) && strcmp(nom, efface) == 0, "efface : (deleted)");
    munmap(f, 4096);
    close(fd);

    /* La pile du fil principal, comme la cherche la glibc (et Bun). */
    pthread_attr_t a;
    void *pile;
    size_t taille;
    struct rlimit r;
    getrlimit(RLIMIT_STACK, &r);
    verifier(pthread_getattr_np(pthread_self(), &a) == 0 && pthread_attr_getstack(&a, &pile, &taille) == 0
             && (char *)pile <= (char *)&a && (char *)&a < (char *)pile + taille && taille <= r.rlim_cur,
             "pthread_getattr_np : la pile du fil principal contient une variable locale");
}

static void lectures(void)
{
    /* maps d'un seul trait, puis par morceaux de 1, 7 et 1024 octets : le
     * même texte (rien ne change la carte entre-temps). */
    size_t un = lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);
    int memes = un > 0;
    size_t tailles[] = { 1, 7, 1024 };
    for (int i = 0; i < 3; i++)
        memes &= lire_tout("/proc/self/maps", morceaux, sizeof morceaux, tailles[i]) == un && memcmp(cartes, morceaux, un) == 0;
    verifier(memes, "maps lu par morceaux de 1, 7, 1024 : le texte d'une seule lecture");
    /* De même statm, un seul enregistrement plus long que la lecture. */
    char st[256], st_morceaux[256];
    un = lire_tout("/proc/self/statm", st, sizeof st, sizeof st);
    memes = un > 0;
    for (int i = 0; i < 3; i++)
        memes &= lire_tout("/proc/self/statm", st_morceaux, sizeof st_morceaux, tailles[i]) == un && memcmp(st, st_morceaux, un) == 0;
    verifier(memes, "statm lu par morceaux de 1, 7, 1024 : le texte d'une seule lecture");

    /* Plus d'une page de lignes (200 zones : des pages aux droits
     * alternés) : comme le seq_file de Linux, une grande lecture rend au
     * plus une page de lignes ENTIERES ; à la suite, tout le texte. */
    char *z = mmap(NULL, 200 * 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 200; i += 2)
        mprotect(z + i * 4096, 4096, PROT_READ | PROT_WRITE);
    int fd = open("/proc/self/maps", O_RDONLY);
    size_t total = 0, lectures_ = 0;
    int entieres = 1;
    ssize_t r;
    while ((r = read(fd, cartes + total, sizeof cartes - 1 - total)) > 0) {
        entieres &= r < 4096 && cartes[total + r - 1] == '\n';
        total += r;
        lectures_++;
    }
    cartes[total] = 0;
    verifier(entieres && lectures_ >= 3 && total == lire_tout("/proc/self/maps", morceaux, sizeof morceaux, sizeof morceaux),
             "maps de 200 zones : des lectures de moins d'une page, de lignes entieres");
    close(fd);
    munmap(z, 200 * 4096);
    un = lire_tout("/proc/self/maps", cartes, sizeof cartes, sizeof cartes);

    fd = open("/proc/self/maps", O_RDONLY);
    char c[4];
    verifier(pread(fd, c, 1, 1) == 1 && c[0] == cartes[1], "pread a la position 1");
    int reste = 7;
    verifier(read(fd, c, 3) == 3 && ioctl(fd, FIONREAD, &reste) == 0 && reste == -3,
             "FIONREAD apres 3 octets : la taille (0) moins la position, -3");
    verifier(erreur(fsync(fd)) == EINVAL && erreur(fdatasync(fd)) == EINVAL && syncfs(fd) == 0,
             "fsync, fdatasync : EINVAL (pas d'operation fsync) ; syncfs : 0");
    verifier(erreur(lseek(fd, 0, SEEK_END)) == EINVAL && erreur(lseek(fd, 0, SEEK_DATA)) == EINVAL
             && lseek(fd, 3, SEEK_SET) == 3, "lseek : SEEK_SET seulement (SEEK_END, SEEK_DATA : EINVAL)");
    struct stat s;
    fstat(fd, &s);
    verifier(s.st_size == 0 && s.st_blksize == 1024 && (s.st_mode & 07777) == 0444 && s.st_uid == getuid() && S_ISREG(s.st_mode),
             "fstat de maps : taille 0, blocs de 1024, 0444, a l'utilisateur");
    verifier(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) == MAP_FAILED && errno == ENODEV, "mmap de maps : ENODEV");
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    verifier(erreur(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev)) == EPERM, "epoll de maps : EPERM");
    close(fd);

    /* Une valeur de /proc/sys : tout d'un coup, rien ensuite. */
    fd = open("/proc/sys/vm/overcommit_memory", O_RDONLY);
    char v[32] = { 0 };
    verifier(read(fd, v, 1) == 1 && v[0] >= '0' && v[0] <= '2' && read(fd, v + 1, 10) == 0, "overcommit_memory : 1 octet, puis rien");
    verifier(pread(fd, v + 1, 10, 1) == 0 && lseek(fd, 0, SEEK_END) == 0 && erreur(lseek(fd, 0, SEEK_DATA)) == ENXIO,
             "pread a 1 : rien ; SEEK_END : 0 ; SEEK_DATA : ENXIO");
    verifier(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) == 0, "epoll d'une valeur de /proc/sys : accepte");
    verifier(erreur(lseek(fd, -5, SEEK_DATA)) == EINVAL && lseek(fd, -5, SEEK_HOLE) == 0 && erreur(fsync(fd)) == EINVAL,
             "SEEK_DATA a -5 : EINVAL ; SEEK_HOLE a -5 : la fin, 0 ; fsync : EINVAL");
    close(fd);
    close(ep);
    memset(v, 0, sizeof v);
    lire_tout("/proc/sys/vm/overcommit_memory", v, sizeof v, sizeof v);
    if (chez_nous)
        verifier(strcmp(v, "0\n") == 0, "overcommit_memory, chez nous : 0 (OVERCOMMIT_GUESS)");
    memset(v, 0, sizeof v);
    lire_tout("/proc/sys/vm/mmap_min_addr", v, sizeof v, sizeof v);
    verifier(atol(v) > 0 && strchr(v, '\n'), "mmap_min_addr : un nombre");
    if (chez_nous)
        verifier(strcmp(v, "65536\n") == 0, "mmap_min_addr, chez nous : 65536");
}

static long statm(long champs[7])
{
    char t[256];
    lire_tout("/proc/self/statm", t, sizeof t, sizeof t);
    return sscanf(t, "%ld %ld %ld %ld %ld %ld %ld", &champs[0], &champs[1], &champs[2], &champs[3], &champs[4], &champs[5], &champs[6]);
}

static void memoire(void)
{
    long avant[7], apres[7];
    statm(avant); /* à blanc : les pages de la lecture elle-même */
    verifier(statm(avant) == 7 && avant[0] >= avant[1] && avant[1] >= avant[2] && avant[2] > 0 && avant[3] > 0 && avant[4] == 0
             && avant[6] == 0, "statm : sept nombres, taille >= resident >= partage > 0, du code");
    char *p = mmap(NULL, 64 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 64; i++)
        p[i * 4096] = 1;
    statm(apres);
    long anonymes = (apres[1] - apres[2]) - (avant[1] - avant[2]);
    /* La taille (total_vm) est exacte partout. Le résident, non : de
     * Linux 6.2 à 6.15 (celui de la CI), statm lit des compteurs par
     * processeur de façon approchée, par défaut (jusqu'à 2 fois le nombre
     * de processeurs, ou 32, pages par processeur non encore versées) ; il
     * est exact depuis 6.16. Sur l'hôte, seulement « il grandit » ; chez
     * nous, exactement. */
    verifier(anonymes > 0 && apres[0] - avant[0] == 64, "64 pages anonymes touchees : la taille grandit d'autant, le resident aussi");
    if (chez_nous)
        verifier(anonymes == 64, "chez nous, le resident exactement de 64");
    munmap(p, 64 * 4096);
}

static void arborescence(void)
{
    struct stat r, p, s;
    stat("/", &r);
    stat("/proc", &p);
    lstat("/proc/self", &s);
    verifier(p.st_dev != r.st_dev && p.st_ino == 1 && S_ISDIR(p.st_mode) && (p.st_mode & 07777) == 0555,
             "/proc : un autre systeme, l'inode 1, 0555");
    verifier(S_ISLNK(s.st_mode) && s.st_uid == 0, "/proc/self : un lien, a root");
    stat("/proc/self/", &s);
    verifier(S_ISDIR(s.st_mode) && s.st_uid == getuid() && (s.st_mode & 07777) == 0555, "/proc/<pid> : a l'utilisateur, 0555");
    lstat("/proc/self/exe", &s);
    verifier(S_ISLNK(s.st_mode) && s.st_size == 0 && lstat("/proc/self", &s) == 0 && s.st_size == 0,
             "les liens de /proc annoncent une taille nulle");
    stat("/proc/sys", &s);
    stat("/proc/sys/vm", &p);
    verifier(s.st_nlink == 1 && p.st_nlink == 1, "les dossiers de /proc/sys : un seul lien");
    int fd = open("/proc", O_RDONLY);
    verifier(erreur(fsync(fd)) == EINVAL && syncfs(fd) == 0, "fsync d'un dossier de /proc : EINVAL ; syncfs : 0");
    close(fd);
    DIR *d = opendir("/proc");
    struct dirent *e;
    char moi[32];
    snprintf(moi, sizeof moi, "%d", getpid());
    int vu_self = 0, vu_fil = 0, vu_moi = 0, vu_sys = 0, vu_net = 0, autres = 0, numeros = 0;
    while ((e = readdir(d))) {
        numeros += e->d_name[0] >= '1' && e->d_name[0] <= '9';
        if (!strcmp(e->d_name, "self"))
            vu_self = e->d_type == DT_LNK;
        else if (!strcmp(e->d_name, "thread-self"))
            vu_fil = e->d_type == DT_LNK;
        else if (!strcmp(e->d_name, moi))
            vu_moi = e->d_type == DT_DIR;
        else if (!strcmp(e->d_name, "sys"))
            vu_sys = e->d_type == DT_DIR;
        else if (!strcmp(e->d_name, "net"))
            /* Un lien vers self/net chez Linux, un dossier chez nous (6g). */
            vu_net = e->d_type == DT_DIR || e->d_type == DT_LNK;
        else if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            autres++;
    }
    closedir(d);
    verifier(vu_self && vu_fil && vu_moi && vu_sys && vu_net, "/proc contient self, thread-self, sys, net et le dossier du processus");
    /* Les liens de /proc : deux, un par sous-dossier fixe, et un par
     * processus (`proc_root_getattr`) ; sur l'hôte, bien plus de dossiers
     * fixes, et tous les processus de la machine. */
    stat("/proc", &p);
    verifier(p.st_nlink >= 3 + (nlink_t)numeros, "/proc : un lien de plus par processus");
    if (chez_nous)
        verifier(autres == 0, "chez nous, rien d'autre");
    char cwd[256];
    char attendu[64];
    snprintf(attendu, sizeof attendu, "/proc/%d", getpid());
    verifier(chdir("/proc/self") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, attendu) == 0, "cd /proc/self : getcwd /proc/<pid>");
    verifier(chdir("..") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/proc") == 0, "cd .. : /proc");
    verifier(chdir("..") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/") == 0, "cd .. : /");
    verifier(access("/proc/self/maps", W_OK) == -1 && errno == EACCES && access("/proc/self/exe", X_OK) == 0,
             "access : maps non inscriptible, exe executable");
}

static void modifications(void)
{
    char fichier[64];
    snprintf(fichier, sizeof fichier, "/tmp/proc.%d.m", getpid());
    close(open(fichier, O_RDWR | O_CREAT, 0644));
    const char *maps = "/proc/self/maps";
    verifier(erreur(open(maps, O_WRONLY)) == EACCES, "open en ecriture : EACCES");
    verifier(erreur(open(maps, O_RDONLY | O_TRUNC)) == EACCES, "open avec O_TRUNC : EACCES (il demande d'ecrire)");
    verifier(erreur(open(maps, O_CREAT | O_EXCL | O_RDONLY, 0644)) == EEXIST, "O_CREAT|O_EXCL : EEXIST");
    verifier(erreur(open("/proc", O_RDONLY | O_CREAT, 0644)) == EISDIR && erreur(open("/proc", O_RDONLY | O_TRUNC)) == EISDIR,
             "un dossier avec O_CREAT ou O_TRUNC : EISDIR");
    verifier(erreur(open("/proc/self/x/", O_RDONLY | O_CREAT, 0644)) == EISDIR, "O_CREAT et une barre finale : EISDIR");
    int fd = open("/proc/self/exe", O_PATH | O_NOFOLLOW);
    verifier(erreur(open("/proc/self/exe", O_RDONLY | O_NOFOLLOW)) == ELOOP && erreur(open("/proc/self", O_RDONLY | O_NOFOLLOW)) == ELOOP
             && fd >= 0, "un lien avec O_NOFOLLOW : ELOOP (avec O_PATH : ouvert)");
    close(fd);
    verifier(erreur(mkdir("/proc/x", 0755)) == ENOENT && erreur(symlink("a", "/proc/self/x")) == ENOENT,
             "mkdir, symlink dans /proc : ENOENT");
    verifier(erreur(mkdir("/proc/self", 0755)) == EEXIST, "mkdir d'un nom qui existe : EEXIST");
    verifier(erreur(rename(fichier, "/proc/x")) == EXDEV && erreur(rename(maps, "/tmp/x")) == EXDEV,
             "rename d'un systeme a l'autre : EXDEV");
    verifier(erreur(link(fichier, "/proc/x")) == ENOENT && erreur(link(maps, "/tmp/x")) == EXDEV,
             "link vers /proc : ENOENT ; depuis /proc : EXDEV");
    verifier(erreur(rename(maps, "/proc/self/x")) == ENOENT, "rename dans /proc : ENOENT");
    verifier(erreur(unlink(maps)) == EPERM && erreur(unlink("/proc/self/absent")) == ENOENT, "unlink : EPERM, ENOENT");
    verifier(erreur(unlink("/proc/self/maps/")) == ENOTDIR && erreur(unlink("/proc/sys/")) == EISDIR && erreur(unlink("/proc/")) == EISDIR,
             "unlink avec une barre finale : ENOTDIR (un fichier), EISDIR (un dossier, le point de montage)");
    verifier(erreur(rename("/proc/self/maps/", "/proc/self/statm")) == ENOTDIR && erreur(rename(fichier, "/proc/")) == ENOTDIR,
             "rename avec une barre finale : ENOTDIR");
    char absent[64];
    snprintf(absent, sizeof absent, "/tmp/proc.%d.absent", getpid());
    verifier(erreur(rename(absent, "/proc")) == ENOENT, "rename d'un absent sur le point de montage : ENOENT");
    int r2 = erreur(syscall(SYS_renameat2, AT_FDCWD, fichier, AT_FDCWD, "/proc", RENAME_NOREPLACE));
    int r3 = erreur(syscall(SYS_renameat2, AT_FDCWD, maps, AT_FDCWD, "/proc/self/statm", RENAME_NOREPLACE));
    int r4 = erreur(syscall(SYS_renameat2, AT_FDCWD, maps, AT_FDCWD, "/proc/.", RENAME_NOREPLACE));
    int r5 = erreur(syscall(SYS_renameat2, AT_FDCWD, "/proc", AT_FDCWD, absent, RENAME_EXCHANGE));
    verifier(r2 == EEXIST && r3 == EEXIST && r4 == EEXIST && r5 == ENOENT,
             "renameat2 : NOREPLACE sur ce qui existe, EEXIST ; EXCHANGE avec un absent, ENOENT");
    verifier(rename(maps, maps) == 0, "rename de maps sur lui-meme : 0");
    verifier(erreur(truncate("/proc/self", 0)) == EISDIR && erreur(truncate("/proc", 0)) == EISDIR, "truncate d'un dossier : EISDIR");
    verifier(erreur(rmdir("/proc/sys")) == EACCES, "rmdir de /proc/sys : EACCES");
    verifier(erreur(chmod(maps, 0400)) == EPERM, "chmod : EPERM");
    verifier(chown(maps, getuid(), getgid()) == 0 && chown(maps, -1, -1) == 0 && erreur(chown(maps, 0, 0)) == EPERM,
             "chown : sans changement 0, vers root EPERM");
    struct timeval tv[2] = { { 1, 0 }, { 1, 0 } };
    verifier(utimes(maps, NULL) == 0 && utimes(maps, tv) == 0, "utimes par le proprietaire : 0");
    /* Le dossier du processus est immuable (S_IMMUTABLE) : même vers son
     * propriétaire, chown rend EPERM, et ses dates ne changent pas. */
    verifier(erreur(chown("/proc/self/", getuid(), -1)) == EPERM && erreur(chown("/proc/self/", -1, getgid())) == EPERM
             && chown("/proc/self/", -1, -1) == 0, "chown de /proc/<pid> vers lui-meme : EPERM (immuable) ; -1, -1 : 0");
    verifier(erreur(utimes("/proc/self/", NULL)) == EPERM && erreur(utimes("/proc/self/", tv)) == EPERM,
             "utimes de /proc/<pid> : EPERM");
    verifier(erreur(truncate(maps, 0)) == EACCES, "truncate : EACCES");
    if (chez_nous)
        verifier(erreur(chmod("/proc/sys/vm/overcommit_memory", 0600)) == EPERM, "chmod d'un reglage, chez nous : EPERM");
    unlink(fichier);
}

/* Le nombre de processeurs d'une liste de Linux (« 0-3,5 »). */
static int compter(const char *liste)
{
    int n = 0, a, b;
    const char *p = liste;
    while (*p && *p != '\n') {
        int lu = 0;
        if (sscanf(p, "%d-%d%n", &a, &b, &lu) == 2)
            n += b - a + 1;
        else if (sscanf(p, "%d%n", &a, &lu) == 1)
            n += 1;
        else
            return -1;
        p += lu;
        if (*p == ',')
            p++;
    }
    return n;
}

static void sys(void)
{
    char online[64] = { 0 }, possible[64] = { 0 }, present[64] = { 0 }, thp[128] = { 0 };
    lire_tout("/sys/devices/system/cpu/online", online, sizeof online, sizeof online);
    lire_tout("/sys/devices/system/cpu/possible", possible, sizeof possible, sizeof possible);
    lire_tout("/sys/devices/system/cpu/present", present, sizeof present, sizeof present);
    cpu_set_t c;
    sched_getaffinity(0, sizeof c, &c);
    verifier(compter(online) >= CPU_COUNT(&c) && compter(online) == get_nprocs() && compter(possible) == get_nprocs_conf()
             && compter(present) >= 1, "cpu/online, possible, present : des listes de Linux, celles de get_nprocs et get_nprocs_conf");
    if (chez_nous)
        verifier(!strcmp(online, "0-3\n") && !strcmp(possible, "0-3\n") && !strcmp(present, "0-3\n") && get_nprocs() == 4
                 && get_nprocs_conf() == 4, "chez nous : quatre processeurs, 0-3");
    lire_tout("/sys/kernel/mm/transparent_hugepage/enabled", thp, sizeof thp, sizeof thp);
    const char *ouvre = strchr(thp, '['), *ferme = strchr(thp, ']');
    verifier(ouvre && ferme > ouvre && strchr(ouvre + 1, '[') == NULL, "transparent_hugepage/enabled : un choix entre crochets");
    if (chez_nous)
        verifier(!strcmp(thp, "always madvise [never]\n"), "chez nous : always madvise [never]");
    struct stat s, r, p;
    stat("/sys/devices/system/cpu/online", &s);
    verifier(s.st_size == 4096 && s.st_blksize == 4096 && (s.st_mode & 07777) == 0444 && s.st_uid == 0,
             "fstat de cpu/online : une page, blocs de 4096, 0444, a root");
    stat("/sys/kernel/mm/transparent_hugepage/enabled", &s);
    verifier((s.st_mode & 07777) == 0644, "transparent_hugepage/enabled : 0644");
    stat("/sys/devices/system/cpu", &s);
    stat("/", &r);
    stat("/proc", &p);
    verifier(S_ISDIR(s.st_mode) && (s.st_mode & 07777) == 0755 && s.st_dev != r.st_dev && s.st_dev != p.st_dev,
             "/sys/devices/system/cpu : 0755, un systeme a lui");
    /* Un attribut se lit comme un seq_file, et se déplace comme un fichier
     * d'une page. */
    char un[64] = { 0 }, morceaux_[64] = { 0 };
    lire_tout("/sys/devices/system/cpu/online", morceaux_, sizeof morceaux_, 1);
    lire_tout("/sys/devices/system/cpu/online", un, sizeof un, sizeof un);
    verifier(!strcmp(un, morceaux_), "lu octet par octet : la meme valeur");
    int fd = open("/sys/devices/system/cpu/online", O_RDONLY);
    char x;
    verifier(pread(fd, &x, 1, 1) == 1 && x == un[1], "pread a la position 1");
    verifier(lseek(fd, 0, SEEK_END) == 4096 && lseek(fd, 0, SEEK_DATA) == 0 && lseek(fd, 0, SEEK_HOLE) == 4096
             && erreur(lseek(fd, 5000, SEEK_DATA)) == ENXIO, "lseek : SEEK_END 4096, SEEK_DATA 0, SEEK_HOLE 4096, au-dela ENXIO");
    verifier(erreur(lseek(fd, -5, SEEK_DATA)) == ENXIO && erreur(lseek(fd, -5, SEEK_HOLE)) == ENXIO,
             "SEEK_DATA et SEEK_HOLE a -5 : ENXIO (compare sans signe)");
    int reste = 7;
    verifier(lseek(fd, 3, SEEK_SET) == 3 && ioctl(fd, FIONREAD, &reste) == 0 && reste == 4093 && fsync(fd) == 0,
             "FIONREAD a la position 3 : 4093 ; fsync : 0 (sysfs en a un)");
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    verifier(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev) == 0, "epoll d'un attribut : accepte");
    close(ep);
    close(fd);
    fd = open("/sys/devices", O_RDONLY);
    verifier(erreur(fsync(fd)) == EINVAL, "fsync d'un dossier de /sys : EINVAL");
    close(fd);
    verifier(erreur(symlink("x", "/sys/x/")) == ENOENT, "symlink vers un nom de /sys avec une barre finale : ENOENT");
    if (chez_nous)
        verifier(erreur(access("/sys/devices/system/node/node1", R_OK)) == ENOENT
                 && erreur(open("/sys/kernel/mm/transparent_hugepage/enabled", O_WRONLY)) == EACCES
                 && erreur(mkdir("/sys/x", 0755)) == EACCES, "chez nous : pas de NUMA, rien a ecrire (EACCES)");
}

/* Les fils dans /proc (6e), mesurés sous Linux 6.18 : comm (le nom, un
 * saut de ligne), task/<tid>/comm pour chaque fil, /proc/thread-self ;
 * écrire comm renomme le fil (15 octets au plus, tout compte comme écrit) ;
 * pthread_setname_np et pthread_getname_np pour un autre fil passent par
 * task/<tid>/comm. */
static pthread_mutex_t verrou = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static int fini;
static volatile pid_t tid_autre;

static void *fil_qui_attend(void *a)
{
    tid_autre = syscall(SYS_gettid);
    pthread_mutex_lock(&verrou);
    while (!fini)
        pthread_cond_wait(&condition, &verrou);
    pthread_mutex_unlock(&verrou);
    return a;
}

/* Le nombre d'entrées d'un dossier, sans « . » ni « .. ». */
static int entrees(const char *chemin)
{
    DIR *d = opendir(chemin);
    struct dirent *e;
    int n = 0;
    if (d == NULL)
        return -1;
    while ((e = readdir(d)) != NULL)
        n += strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
    closedir(d);
    return n;
}

static int dans_task(pid_t tid)
{
    char chemin[64];
    snprintf(chemin, sizeof chemin, "/proc/self/task/%d", tid);
    return access(chemin, F_OK) == 0;
}

static void fils(void)
{
    char t[256], chemin[64], attendu[64], nom[16];
    pid_t pid = getpid(), tid = syscall(SYS_gettid);
    lire_tout("/proc/self/comm", t, sizeof t, 1024);
    verifier(strcmp(t, "proc\n") == 0, "comm : le nom du programme, et un saut de ligne");
    snprintf(chemin, sizeof chemin, "/proc/self/task/%d/comm", tid);
    lire_tout(chemin, t, sizeof t, 1024);
    verifier(strcmp(t, "proc\n") == 0, "task/<tid>/comm du fil principal");
    ssize_t n = readlink("/proc/thread-self", t, sizeof t - 1);
    t[n < 0 ? 0 : n] = 0;
    snprintf(attendu, sizeof attendu, "%d/task/%d", pid, tid);
    verifier(strcmp(t, attendu) == 0, "/proc/thread-self : <pid>/task/<tid>");
    int fd = open("/proc/self/comm", O_WRONLY);
    verifier(fd >= 0 && write(fd, "nouveau", 7) == 7, "ecrire comm");
    verifier(prctl(PR_GET_NAME, nom) == 0 && strcmp(nom, "nouveau") == 0, "comm ecrit : le nom du fil (PR_GET_NAME)");
    verifier(write(fd, "0123456789abcdefghij", 20) == 20, "ecrire 20 octets dans comm : 20");
    lire_tout("/proc/self/comm", t, sizeof t, 1024);
    verifier(strcmp(t, "0123456789abcde\n") == 0, "comm : les 15 premiers seulement");
    verifier(write(fd, "proc", 4) == 4, "comm remis");
    close(fd);
    pthread_t f;
    verifier(pthread_create(&f, NULL, fil_qui_attend, NULL) == 0, "un fil (pthread_create)");
    while (tid_autre == 0)
        sched_yield();
    verifier(dans_task(tid_autre), "task/<tid> du nouveau fil");
    verifier(entrees("/proc/self/task") == 2, "task : deux fils");
    verifier(pthread_setname_np(f, "autre") == 0 && pthread_getname_np(f, nom, sizeof nom) == 0 && strcmp(nom, "autre") == 0,
             "nommer un autre fil (task/<tid>/comm)");
    verifier(prctl(PR_GET_NAME, nom) == 0 && strcmp(nom, "proc") == 0, "le nom du fil principal n'a pas change");
    /* /proc/<tid> d'un fil qui n'est pas le principal (6f) : résolu, sans
     * être listé dans /proc ; son comm est celui du fil. */
    struct stat st;
    snprintf(chemin, sizeof chemin, "/proc/%d", tid_autre);
    int resolu = stat(chemin, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == getuid();
    snprintf(chemin, sizeof chemin, "/proc/%d/comm", tid_autre);
    lire_tout(chemin, t, sizeof t, 1024);
    DIR *racine = opendir("/proc");
    struct dirent *e;
    int liste = 0;
    while (racine && (e = readdir(racine)) != NULL)
        liste |= atoi(e->d_name) == tid_autre;
    if (racine)
        closedir(racine);
    verifier(resolu && strcmp(t, "autre\n") == 0 && !liste, "/proc/<tid> d'un autre fil : resolu (son comm), sans etre liste");
    /* Le dossier d'un fil est immuable comme celui du processus
     * (`proc_task_instantiate`) ; task/ suit ses droits (0555). */
    snprintf(chemin, sizeof chemin, "/proc/self/task/%d", tid_autre);
    verifier(erreur(utimensat(AT_FDCWD, chemin, NULL, 0)) == EPERM && erreur(chown(chemin, getuid(), getgid())) == EPERM
                 && erreur(rmdir(chemin)) == EACCES,
             "task/<tid> : immuable (utimensat, chown : EPERM) ; rmdir : EACCES");
    pthread_mutex_lock(&verrou);
    fini = 1;
    pthread_cond_signal(&condition);
    pthread_mutex_unlock(&verrou);
    verifier(pthread_join(f, NULL) == 0, "pthread_join");
    /* Le fil efface son numéro (ce qu'attend pthread_join) un peu avant de
     * disparaître tout à fait. */
    int parti = 0;
    for (int i = 0; i < 1000 && !parti; i++) {
        parti = !dans_task(tid_autre);
        if (!parti)
            sched_yield();
    }
    verifier(parti && entrees("/proc/self/task") == 1, "task/<tid> retire a la fin du fil");
}

/* « proc cible » : écrit son numéro dans /tmp/proc-cible.pid, attend
 * 200 ms et se termine. « proc autre », lancé ensuite : ouvre maps et statm
 * de la cible tant qu'elle vit, les lit, puis attend qu'elle ait été
 * recueillie (kill(pid, 0) : ESRCH) ; ses fichiers, gardés ouverts, se
 * lisent alors ESRCH, comme sous Linux (mesuré). Dans notre noyau, lancés
 * ensemble par /etc/demarrage, init recueillant la cible dès sa fin. */
static int autre(void)
{
    struct timespec ms = { 0, 1000000 };
    int fd = -1;
    for (int i = 0; i < 10000 && (fd = open("/tmp/proc-cible.pid", O_RDONLY)) < 0; i++)
        nanosleep(&ms, NULL);
    char t[16] = { 0 }, chemin[64], tampon[256];
    if (read(fd, t, sizeof t - 1) <= 0)
        return 1;
    close(fd);
    unlink("/tmp/proc-cible.pid");
    int cible = atoi(t);
    snprintf(chemin, sizeof chemin, "/proc/%d/maps", cible);
    int maps = open(chemin, O_RDONLY);
    snprintf(chemin, sizeof chemin, "/proc/%d/statm", cible);
    int statm = open(chemin, O_RDONLY);
    snprintf(chemin, sizeof chemin, "/proc/%d", cible);
    int dossier = open(chemin, O_RDONLY | O_DIRECTORY);
    verifier(maps >= 0 && statm >= 0 && read(maps, tampon, sizeof tampon) > 0 && read(statm, tampon, sizeof tampon) > 0,
             "maps et statm d'un autre processus, vivant : lus");
    for (int i = 0; i < 10000 && kill(cible, 0) == 0; i++)
        nanosleep(&ms, NULL);
    lseek(maps, 0, SEEK_SET);
    lseek(statm, 0, SEEK_SET);
    verifier(kill(cible, 0) == -1 && erreur(read(maps, tampon, sizeof tampon)) == ESRCH && erreur(read(statm, tampon, sizeof tampon)) == ESRCH,
             "ses fichiers gardes ouverts, une fois recueilli : ESRCH");
    /* Son dossier, gardé ouvert : le même mode, à root (`pid_getattr`). */
    struct stat d;
    verifier(dossier >= 0 && fstat(dossier, &d) == 0 && d.st_mode == (S_IFDIR | 0555) && d.st_uid == 0,
             "son dossier garde ouvert, une fois recueilli : le meme mode, a root");
    printf("[linux] proc autre : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}

/* /proc/self/fd (6f), mesuré sous Linux 6.18 : le texte de chaque lien (le
 * chemin, « (deleted) », anon_inode:[...], pipe:[...]), ses droits (le mode
 * d'ouverture) et sa taille (64), le dossier (dr-x------, sa taille : le
 * nombre de descripteurs), et le LIEN MAGIQUE : stat et open vont droit au
 * fichier ouvert, même effacé ; un tube se rouvre du côté qu'on veut ; un
 * epoll non (EACCES : son inode anonyme est à root, 0600). */
static void lien_de(int fd, char *t, size_t n)
{
    char chemin[64];
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", fd);
    ssize_t r = readlink(chemin, t, n - 1);
    t[r < 0 ? 0 : r] = 0;
}

static mode_t droits_du_lien(int fd)
{
    char chemin[64];
    struct stat s;
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", fd);
    return lstat(chemin, &s) == 0 && S_ISLNK(s.st_mode) && s.st_size == 64 && s.st_uid == getuid() ? s.st_mode & 07777 : 07777;
}

static void descripteurs(void)
{
    char nom[64], t[256], attendu[256], chemin[64];
    snprintf(nom, sizeof nom, "/tmp/proc-fd-%d", getpid());
    int f = open(nom, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (write(f, "contenu", 7) != 7)
        verifier(0, "ecrire le fichier");
    int lu = open(nom, O_RDONLY), ecrit = open(nom, O_WRONLY), chemin_seul = open(nom, O_PATH);
    lien_de(f, t, sizeof t);
    verifier(strcmp(t, nom) == 0, "readlink /proc/self/fd/N : le chemin du fichier");
    verifier(droits_du_lien(lu) == 0500 && droits_du_lien(ecrit) == 0300 && droits_du_lien(f) == 0700 && droits_du_lien(chemin_seul) == 0,
             "lstat d'un lien : r-x en lecture, -wx en ecriture, rwx les deux, rien pour O_PATH ; taille 64, a l'utilisateur");
    struct stat a, b;
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", f);
    verifier(stat(chemin, &a) == 0 && stat(nom, &b) == 0 && a.st_ino == b.st_ino && S_ISREG(a.st_mode),
             "stat d'un lien : le fichier ouvert");
    /* Ce qu'on ouvre par un lien garde le chemin du fichier ouvert : un
     * fichier qui a son nom, la sortie standard (la console chez nous, un
     * tuyau sous make sur l'hôte), un dossier, l'exécutable. */
    int par_lien = open(chemin, O_RDONLY);
    char c[8] = { 0 }, t2[256];
    lien_de(par_lien, t2, sizeof t2);
    verifier(par_lien >= 0 && read(par_lien, c, 7) == 7 && strcmp(c, "contenu") == 0 && strcmp(t2, nom) == 0,
             "open d'un lien vers un fichier qui a son nom : ouvert, le meme chemin");
    close(par_lien);
    int sortie = open("/proc/self/fd/1", O_WRONLY);
    lien_de(1, t, sizeof t);
    lien_de(sortie, t2, sizeof t2);
    verifier(sortie >= 0 && t[0] != 0 && strcmp(t, t2) == 0, "open de /proc/self/fd/1 (/dev/stdout) : ouvert, le meme chemin");
    close(sortie);
    int tmp = open("/tmp", O_RDONLY | O_DIRECTORY);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", tmp);
    int dossier = open(chemin, O_RDONLY | O_DIRECTORY);
    lien_de(dossier, t2, sizeof t2);
    verifier(dossier >= 0 && strcmp(t2, "/tmp") == 0, "open d'un lien vers un dossier : ouvert, le meme chemin");
    close(dossier);
    close(tmp);
    char exe[256] = { 0 };
    struct stat e_lien, e_ouvert;
    int par_exe = open("/proc/self/exe", O_RDONLY);
    if (readlink("/proc/self/exe", exe, sizeof exe - 1) <= 0)
        exe[0] = 0;
    lien_de(par_exe, t2, sizeof t2);
    verifier(par_exe >= 0 && stat("/proc/self/exe", &e_lien) == 0 && fstat(par_exe, &e_ouvert) == 0 && e_lien.st_ino == e_ouvert.st_ino
                 && exe[0] == '/' && strcmp(t2, exe) == 0,
             "open de /proc/self/exe : l'executable, son chemin");
    close(par_exe);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", f);
    unlink(nom);
    lien_de(f, t, sizeof t);
    snprintf(attendu, sizeof attendu, "%s (deleted)", nom);
    verifier(strcmp(t, attendu) == 0, "le fichier efface : (deleted)");
    /* Le LIEN MAGIQUE : son texte ne mène plus nulle part, le suivre mène
     * encore au fichier. */
    verifier(stat(chemin, &a) == 0 && a.st_ino == b.st_ino && a.st_nlink == 0, "stat d'un lien vers un fichier efface : le fichier (un lien magique)");
    int rouvert = open(chemin, O_RDONLY);
    memset(c, 0, sizeof c);
    lien_de(rouvert, t2, sizeof t2);
    verifier(rouvert >= 0 && read(rouvert, c, 7) == 7 && strcmp(c, "contenu") == 0 && strcmp(t2, attendu) == 0,
             "open d'un lien vers un fichier efface : il se rouvre, avec son chemin et (deleted)");
    close(rouvert);

    int e = eventfd(0, 0), ep = epoll_create1(0), tube[2];
    if (pipe(tube) != 0)
        verifier(0, "pipe");
    int m = open("/proc/self/maps", O_RDONLY);
    char e_t[64], ep_t[64], tl[64], te[64], m_t[64];
    lien_de(e, e_t, sizeof e_t);
    lien_de(ep, ep_t, sizeof ep_t);
    lien_de(tube[0], tl, sizeof tl);
    lien_de(tube[1], te, sizeof te);
    lien_de(m, m_t, sizeof m_t);
    struct stat st;
    fstat(tube[0], &st);
    snprintf(attendu, sizeof attendu, "pipe:[%lu]", (unsigned long)st.st_ino);
    char maps[64];
    snprintf(maps, sizeof maps, "/proc/%d/maps", getpid());
    verifier(strcmp(e_t, "anon_inode:[eventfd]") == 0 && strcmp(ep_t, "anon_inode:[eventpoll]") == 0 && strcmp(tl, attendu) == 0
                 && strcmp(te, attendu) == 0 && strcmp(m_t, maps) == 0,
             "anon_inode:[eventfd], anon_inode:[eventpoll], pipe:[inode] pour les deux bouts, /proc/<pid>/maps");
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", tube[0]);
    int autre_bout = open(chemin, O_WRONLY);
    char x = 0;
    verifier(autre_bout >= 0 && write(autre_bout, "y", 1) == 1 && read(tube[0], &x, 1) == 1 && x == 'y',
             "open O_WRONLY du lien d'un bout de lecture : un bout d'ecriture du meme tube");
    close(autre_bout);
    int tube_chemin = open(chemin, O_PATH);
    lien_de(tube_chemin, t2, sizeof t2);
    verifier(tube_chemin >= 0 && strcmp(t2, attendu) == 0, "open O_PATH du lien d'un tube : pipe:[inode]");
    close(tube_chemin);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", ep);
    verifier(open(chemin, O_RDONLY) == -1 && errno == EACCES, "open du lien d'un epoll : EACCES");
    int ferme = dup(e);
    close(ferme);
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", ferme);
    verifier(readlink(chemin, t, sizeof t) == -1 && errno == ENOENT && open(chemin, O_RDONLY) == -1 && errno == ENOENT,
             "un numero ferme : ENOENT");

    struct stat d;
    DIR *dir = opendir("/proc/self/fd");
    int n = 0, dt = 1, croissants = 1, precedent = -1, points = 0;
    struct dirent *x_;
    while (dir && (x_ = readdir(dir)) != NULL) {
        if (strcmp(x_->d_name, ".") == 0 || strcmp(x_->d_name, "..") == 0) {
            points++;
            continue;
        }
        n++;
        dt &= x_->d_type == DT_LNK;
        croissants &= atoi(x_->d_name) > precedent;
        precedent = atoi(x_->d_name);
    }
    if (dir)
        closedir(dir);
    stat("/proc/self/fd", &d);
    verifier(S_ISDIR(d.st_mode) && (d.st_mode & 07777) == 0500 && d.st_nlink == 2 && d.st_uid == getuid(),
             "/proc/self/fd : dr-x------, deux liens, a l'utilisateur");
    /* Sa taille : le nombre de descripteurs ouverts (celui de opendir, fermé
     * depuis, n'y est plus ; la liste l'avait). */
    verifier((long)d.st_size == n - 1, "/proc/self/fd : sa taille est le nombre de descripteurs");
    verifier(points == 2 && dt && croissants, "getdents de /proc/self/fd : . et .., puis les numeros, croissants, en DT_LNK");
    close(f);
    close(lu);
    close(ecrit);
    close(chemin_seul);
    close(e);
    close(ep);
    close(tube[0]);
    close(tube[1]);
    close(m);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "cible") == 0) {
        char t[16];
        int k = snprintf(t, sizeof t, "%d", getpid());
        int fd = open("/tmp/proc-cible.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (write(fd, t, k) != k)
            return 1;
        close(fd);
        rename("/tmp/proc-cible.tmp", "/tmp/proc-cible.pid");
        struct timespec deux_cents = { 0, 200000000 };
        nanosleep(&deux_cents, NULL);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "autre") == 0)
        return autre();
    chez_nous = access("/etc/bonjour.txt", F_OK) == 0;
    printf("[linux] proc : debut\n"); /* le tampon de stdout, alloue avant de lire les cartes */
    carte();
    lectures();
    memoire();
    arborescence();
    modifications();
    sys();
    fils();
    descripteurs();
    printf("[linux] proc : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
