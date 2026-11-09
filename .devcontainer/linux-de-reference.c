/*
 * Le /init de la machine du Linux de référence (linux-de-reference.sh).
 *
 * La machine démarre le noyau de référence sur une petite archive (ce
 * programme et cinq modules) ; ce programme monte le système de fichiers de
 * l'hôte, partagé par QEMU (9p, sur virtio), s'y enferme (chroot), et y
 * lance la commande demandée, sous l'identité de qui l'a demandée, dans son
 * dossier, avec son environnement. Son code de sortie revient à l'hôte par
 * un fichier ; puis la machine s'éteint.
 *
 * Ce que la machine a en propre, et non l'hôte : /proc, /sys, /dev (ses
 * périphériques), /dev/shm, /dev/mqueue et /run (neufs : ceux de l'hôte
 * seraient vus à travers 9p), le réseau (la passerelle « utilisateur » de
 * QEMU, comme nos propres machines de test) et donc son /etc/resolv.conf ;
 * et les réglages qu'un Ubuntu 24.04 pose au démarrage (systemd et ses
 * fichiers de sysctl.d), que le noyau n'a pas d'emblée (pas /dev/hugepages :
 * rien ne s'en sert). Tout le reste est
 * celui de l'hôte : les programmes, les bibliothèques, le dépôt, HOME ; ce
 * qu'on écrit ailleurs que dans HOME et le dépôt (/tmp) reste dans la
 * machine (voir main).
 *
 * Écrit à la main, dans le prolongement du témoin de 6i (un /init statique
 * qui lançait quelques programmes de test sous le noyau de la CI) ; le
 * principe est celui de
 * virtme-ng (le système de l'hôte sous un autre noyau). Écarté : virtme-ng
 * lui-même (un paquet Python de plus dans la CI, pour cent lignes), une
 * image disque d'Ubuntu (tout l'outillage de la CI à y réinstaller, à chaque
 * version de l'image de GitHub), virtiofs (plus rapide que 9p, mais un démon
 * à côté de QEMU, virtiofsd, que ni la CI ni le conteneur n'ont).
 *
 * Statique (gcc -static) : il tourne avant que la glibc de l'hôte soit
 * visible.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* finit_module : le module est compressé (zstd, comme les paquets d'Ubuntu),
 * le noyau le décompresse lui-même (CONFIG_MODULE_DECOMPRESS). */
#ifndef MODULE_INIT_COMPRESSED_FILE
#define MODULE_INIT_COMPRESSED_FILE 4
#endif

static void dire(const char *format, ...)
{
    va_list a;
    va_start(a, format);
    fputs("[linux-de-reference] ", stderr);
    vfprintf(stderr, format, a);
    fputc('\n', stderr);
    va_end(a);
}

/* Une étape manquée : la machine s'éteint sans écrire de statut, et le
 * script de l'hôte le dit (code 125). */
static void arreter(const char *format, ...)
{
    va_list a;
    va_start(a, format);
    fputs("[linux-de-reference] ", stderr);
    vfprintf(stderr, format, a);
    fprintf(stderr, " : %s\n", strerror(errno));
    va_end(a);
    sync();
    reboot(RB_POWER_OFF);
    _exit(1);
}

/* Tout un fichier, terminé par un octet nul de plus. */
static char *lire(const char *chemin, size_t *taille)
{
    int fd = open(chemin, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    size_t place = 4096, n = 0;
    char *t = malloc(place);
    for (;;) {
        if (n + 1 >= place && !(t = realloc(t, place *= 2)))
            return NULL;
        ssize_t r = read(fd, t + n, place - n - 1);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        n += (size_t)r;
    }
    close(fd);
    t[n] = 0;
    if (taille)
        *taille = n;
    return t;
}

/* Des chaînes séparées par des octets nuls (`printf '%s\0'`, `env -0`), en
 * tableau terminé par NULL, pour execve. */
static char **morceaux(char *t, size_t n)
{
    size_t compte = 0;
    for (size_t i = 0; i < n; i++)
        compte += t[i] == 0;
    char **v = calloc(compte + 1, sizeof *v);
    size_t k = 0;
    for (size_t i = 0; i < n; i += strlen(t + i) + 1)
        v[k++] = t + i;
    v[k] = NULL;
    return v;
}

static void charger_module(const char *nom)
{
    char chemin[64];
    snprintf(chemin, sizeof chemin, "/modules/%s.ko.zst", nom);
    int fd = open(chemin, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || (syscall(SYS_finit_module, fd, "", MODULE_INIT_COMPRESSED_FILE) != 0 && errno != EEXIST))
        arreter("module %s", nom);
    close(fd);
}

static void monter(const char *source, const char *cible, const char *type, unsigned long drapeaux, const char *options)
{
    mkdir(cible, 0755);
    if (mount(source, cible, type, drapeaux, options) != 0)
        arreter("montage de %s sur %s", type, cible);
}

static void adresse(struct sockaddr *s, const char *texte)
{
    struct sockaddr_in *a = (struct sockaddr_in *)s;
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    inet_pton(AF_INET, texte, &a->sin_addr);
}

/* Une interface en service, avec son adresse si elle en a une. */
static void interface(int s, const char *nom, const char *ip, const char *masque)
{
    struct ifreq r;
    memset(&r, 0, sizeof r);
    strncpy(r.ifr_name, nom, IFNAMSIZ - 1);
    if (ip) {
        adresse(&r.ifr_addr, ip);
        if (ioctl(s, SIOCSIFADDR, &r) != 0)
            arreter("adresse de %s", nom);
        adresse(&r.ifr_netmask, masque);
        if (ioctl(s, SIOCSIFNETMASK, &r) != 0)
            arreter("masque de %s", nom);
    }
    if (ioctl(s, SIOCGIFFLAGS, &r) != 0)
        arreter("interface %s", nom);
    r.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &r) != 0)
        arreter("mise en service de %s", nom);
}

/* Le réseau « utilisateur » de QEMU (slirp) : 10.0.2.15, la passerelle
 * 10.0.2.2, son DNS 10.0.2.3 ; les adresses qu'il donnerait par DHCP, posées
 * sans client DHCP (il n'y a pas d'autre machine sur ce réseau). Nos étapes
 * en ont besoin : leurs propres machines de test demandent api.anthropic.com
 * au DNS de leur slirp, qui relaie celui de cette machine-ci. */
static void reseau(void)
{
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        arreter("socket");
    interface(s, "lo", NULL, NULL);
    interface(s, "eth0", "10.0.2.15", "255.255.255.0");
    struct rtentry route;
    memset(&route, 0, sizeof route);
    adresse(&route.rt_dst, "0.0.0.0");
    adresse(&route.rt_gateway, "10.0.2.2");
    adresse(&route.rt_genmask, "0.0.0.0");
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    if (ioctl(s, SIOCADDRT, &route) != 0)
        arreter("route par defaut");
    close(s);
}

/* Le /etc/resolv.conf de la machine : le DNS de slirp. Celui de l'hôte ne
 * vaut rien ici (sur la machine de GitHub, 127.0.0.53, le résolveur de
 * systemd, qui ne tourne pas dans la machine ; c'est même un lien vers
 * /run). Un fichier neuf à sa place, dans la couche du dessus : l'hôte n'en
 * voit rien. */
static void resolveur(void)
{
    static const char texte[] = "nameserver 10.0.2.3\n";
    unlink("/racine/etc/resolv.conf");
    int fd = open("/racine/etc/resolv.conf", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0 || write(fd, texte, sizeof texte - 1) != (ssize_t)(sizeof texte - 1))
        arreter("ecriture de resolv.conf");
    close(fd);
}

/* Les réglages qu'un Ubuntu 24.04 pose au démarrage (systemd :
 * 50-default.conf, 50-pid-max.conf ; Ubuntu : 10-kernel-hardening.conf,
 * 10-map-count.conf, 99-protect-links.conf), là où le noyau garde ses valeurs
 * par défaut : sans eux, les sockets de ping sont refusées à tous (« 1 0 »,
 * `ping_init_sock` : EACCES) et `linux/reseau` le verrait. Écrits ici, fixes,
 * plutôt que lus dans les fichiers de l'hôte : le conteneur n'a pas ceux de
 * systemd. */
static void reglages(void)
{
    static const char *const r[][2] = {
        { "net/ipv4/ping_group_range", "0 2147483647" },
        { "net/ipv4/conf/all/rp_filter", "2" },
        { "net/ipv4/conf/default/rp_filter", "2" },
        { "net/ipv4/conf/all/promote_secondaries", "1" },
        { "net/ipv4/conf/default/promote_secondaries", "1" },
        { "fs/protected_fifos", "1" },
        { "fs/protected_hardlinks", "1" },
        { "fs/protected_regular", "2" },
        { "fs/protected_symlinks", "1" },
        { "kernel/kptr_restrict", "1" },
        { "kernel/pid_max", "4194304" },
        { "vm/max_map_count", "1048576" },
    };
    for (size_t i = 0; i < sizeof r / sizeof *r; i++) {
        char chemin[128];
        snprintf(chemin, sizeof chemin, "/racine/proc/sys/%s", r[i][0]);
        int fd = open(chemin, O_WRONLY | O_CLOEXEC);
        if (fd < 0 || write(fd, r[i][1], strlen(r[i][1])) < 0)
            arreter("reglage %s", r[i][0]);
        close(fd);
    }
}

/* Un échec dans l'enfant, avant de lancer la commande : dit sur la console
 * (sa sortie est déjà le tube), et 126, que le premier processus écrira
 * comme statut. Jamais `arreter` : éteindre depuis l'enfant perdrait le
 * message. */
static int console_de_l_enfant = 2;

static void echouer(const char *quoi, const char *detail)
{
    dprintf(console_de_l_enfant, "[linux-de-reference] %s %s : %s\n", quoi, detail, strerror(errno));
    _exit(126);
}

/* Écrit le statut de la commande dans le dossier de ce lancement (un
 * partage de l'hôte), dès qu'elle est finie. */
static void ecrire_statut(const char *travail, int code)
{
    char chemin[PATH_MAX];
    snprintf(chemin, sizeof chemin, "%s/statut", travail);
    sync();
    FILE *f = fopen(chemin, "w");
    if (!f || fprintf(f, "%d\n", code) < 0 || fclose(f) != 0)
        arreter("ecriture du statut");
    sync();
}

int main(void)
{
    /* La console : le noyau ne l'a pas ouverte (l'archive n'a pas de
     * /dev/console). Sans traitement de la sortie : pas de \r ajouté avant
     * chaque \n, la sortie ressemble à celle d'un tube. */
    mkdir("/dev", 0755);
    mkdir("/hote", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    int c = open("/dev/console", O_RDWR);
    if (c >= 0) {
        dup2(c, 1);
        dup2(c, 2);
        if (c > 2)
            close(c);
    }
    int vide = open("/dev/null", O_RDONLY);
    if (vide >= 0 && vide != 0) {
        dup2(vide, 0);
        close(vide);
    }
    struct termios t;
    if (tcgetattr(1, &t) == 0) {
        t.c_oflag &= ~OPOST;
        tcsetattr(1, TCSANOW, &t);
    }

    const char *travail = getenv("travail");
    if (!travail)
        arreter("pas de travail= dans la ligne du noyau");

    /* 9p et overlayfs, en modules dans les paquets d'Ubuntu : netfs (le
     * cache des systèmes de fichiers en réseau), le protocole 9p, son
     * transport virtio, le système de fichiers ; overlayfs. Dans cet ordre,
     * celui de leurs dépendances. */
    charger_module("netfs");
    charger_module("9pnet");
    charger_module("9pnet_virtio");
    charger_module("9p");
    charger_module("overlay");

    /* Le système de l'hôte, en 9p, en lecture seule (QEMU le partage ainsi,
     * readonly=on). msize : la taille d'un message, 256 Kio (le défaut, 8 Kio,
     * coûte un aller-retour par 8 Kio lus) ; cache=loose : les pages et les
     * attributs gardés par la machine. Ce que l'hôte change pendant qu'elle
     * tourne (une autre session, dans le conteneur) peut ne pas s'y voir :
     * elle ne s'en sert que pour lire les programmes et les bibliothèques. */
    monter("racine", "/hote", "9p", MS_RDONLY, "trans=virtio,version=9p2000.L,msize=262144,cache=loose");
    /* La racine de la machine : celle de l'hôte, en lecture, sous une couche
     * en mémoire qui reçoit ce qu'on y écrit (overlayfs, comme un conteneur).
     * Pourquoi pas 9p directement : 9p ne rouvre pas un fichier effacé encore
     * ouvert (/proc/self/fd/N : `linux/proc` l'attend, comme ext4 et tmpfs le
     * font), et /tmp doit rester sur le même système que / (le même test
     * attend ENOTDIR, pas EXDEV, d'un rename de /tmp vers « /proc/ ») : /tmp
     * est dans la couche, sur le même montage que /. */
    monter("tmpfs", "/haut", "tmpfs", 0, "mode=755");
    mkdir("/haut/dessus", 0755);
    mkdir("/haut/travail", 0755);
    monter("overlay", "/racine", "overlay", 0, "lowerdir=/hote,upperdir=/haut/dessus,workdir=/haut/travail");
    /* Ce qui doit rester sur l'hôte, écrit à travers 9p : HOME et le dépôt
     * (les constructions, les téléchargements, le statut de ce lancement),
     * chacun son partage en écriture (« étiquette chemin » par ligne), monté
     * à sa place, nosuid et nodev. cache=mmap : les écritures vont tout de
     * suite à l'hôte (une machine arrêtée net ne laisse pas un objet de cargo
     * à moitié écrit derrière son empreinte), seules les projections passent
     * par le cache des pages (rustc en fait). */
    char chemin[PATH_MAX];
    snprintf(chemin, sizeof chemin, "/hote%s/partages", travail);
    char *partages = lire(chemin, NULL);
    if (!partages)
        arreter("lecture de %s", chemin);
    for (char *p = strtok(partages, "\n"); p; p = strtok(NULL, "\n")) {
        char *espace = strchr(p, ' ');
        if (!espace)
            arreter("partage mal ecrit : %s", p);
        *espace = 0;
        char cible[PATH_MAX];
        snprintf(cible, sizeof cible, "/racine%s", espace + 1);
        if (mount(p, cible, "9p", MS_NOSUID | MS_NODEV, "trans=virtio,version=9p2000.L,msize=262144,cache=mmap") != 0)
            arreter("partage de %s", espace + 1);
    }
    monter("proc", "/racine/proc", "proc", 0, NULL);
    monter("sysfs", "/racine/sys", "sysfs", 0, NULL);
    monter("cgroup2", "/racine/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    monter("devtmpfs", "/racine/dev", "devtmpfs", 0, NULL);
    /* Les liens que systemd pose dans /dev (devtmpfs ne les a pas) :
     * `tee /dev/stderr`, dans nos Makefile, en a besoin. */
    if (symlink("/proc/self/fd", "/racine/dev/fd") != 0 || symlink("/proc/self/fd/0", "/racine/dev/stdin") != 0
        || symlink("/proc/self/fd/1", "/racine/dev/stdout") != 0 || symlink("/proc/self/fd/2", "/racine/dev/stderr") != 0)
        arreter("liens de /dev");
    /* Comme systemd : les esclaves au groupe tty (5), /dev/pts/ptmx fermé
     * (on passe par /dev/ptmx). */
    monter("devpts", "/racine/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "gid=5,mode=620,ptmxmode=000");
    monter("tmpfs", "/racine/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");
    monter("mqueue", "/racine/dev/mqueue", "mqueue", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    monter("tmpfs", "/racine/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=755");
    reglages();
    reseau();
    resolveur();

    struct utsname u;
    uname(&u);
    dire("%s %s, %ld processeurs", u.sysname, u.release, sysconf(_SC_NPROCESSORS_ONLN));

    if (chroot("/racine") != 0 || chdir("/") != 0)
        arreter("chroot");

    size_t n;
    snprintf(chemin, sizeof chemin, "%s/commande", travail);
    char *commande = lire(chemin, &n);
    char **argv = commande ? morceaux(commande, n) : NULL;
    snprintf(chemin, sizeof chemin, "%s/environnement", travail);
    char *environnement = lire(chemin, &n);
    char **envp = environnement ? morceaux(environnement, n) : NULL;
    snprintf(chemin, sizeof chemin, "%s/dossier", travail);
    char *dossier = lire(chemin, NULL);
    snprintf(chemin, sizeof chemin, "%s/identite", travail);
    char *identite = lire(chemin, NULL);
    if (!argv || !argv[0] || !envp || !dossier || !identite)
        arreter("lecture de %s", travail);
    dossier[strcspn(dossier, "\n")] = 0;
    /* Le nom de l'hôte : celui que /etc/hosts connaît (sudo le cherche). */
    snprintf(chemin, sizeof chemin, "%s/nom", travail);
    char *nom = lire(chemin, NULL);
    if (!nom || sethostname(nom, strcspn(nom, "\n")) != 0)
        arreter("nom de la machine");

    /* « uid gid groupe... », comme l'écrit `id -u; id -G` (le premier des
     * groupes est le groupe principal). */
    unsigned uid, gid;
    gid_t groupes[64];
    int ngroupes = 0, lu = 0;
    if (sscanf(identite, "%u%n", &uid, &lu) != 1)
        arreter("identite");
    for (char *p = identite + lu; ngroupes < 64 && sscanf(p, "%u%n", &gid, &lu) == 1; p += lu)
        groupes[ngroupes++] = gid;
    if (ngroupes == 0)
        arreter("identite sans groupe");

    /* Les descripteurs comme une session de systemd (DefaultLimitNOFILE :
     * 1024, au plus 524288), pas ceux du premier processus du noyau
     * (1024, 4096). */
    struct rlimit fichiers = { 1024, 524288 };
    if (setrlimit(RLIMIT_NOFILE, &fichiers) != 0)
        arreter("RLIMIT_NOFILE");

    /* La sortie de la commande passe par un tube, que ce processus recopie
     * sur la console : comme dans la CI, où elle va dans un tube (`tee`).
     * La console appartient à root (0600) : un programme qui rouvre sa
     * sortie, `tee /dev/stderr` dans nos Makefile, ne le pourrait pas. */
    int tube[2];
    if (pipe2(tube, O_CLOEXEC) != 0)
        arreter("pipe");
    /* Rouvrir un tube par /proc/self/fd demande le droit sur son inode, qui
     * est à qui l'a créé (0600) : à l'utilisateur de la commande, comme s'il
     * l'avait créé lui-même. */
    if (fchown(tube[0], uid, groupes[0]) != 0)
        arreter("fchown du tube");
    pid_t enfant = fork();
    if (enfant == 0) {
        console_de_l_enfant = fcntl(1, F_DUPFD_CLOEXEC, 3);
        /* Sa propre session, et son groupe : le premier processus n'en a
         * pas (0), et `linux/proprietaire` attend des numéros, comme sous
         * n'importe quel service ou terminal. */
        if (setsid() < 0)
            echouer("setsid", "");
        /* dup2 retire O_CLOEXEC à la copie. */
        if (dup2(tube[1], 1) < 0 || dup2(tube[1], 2) < 0)
            echouer("dup2", "");
        if (chdir(dossier) != 0)
            echouer("dossier", dossier);
        if (setgroups(ngroupes, groupes) != 0 || setgid(groupes[0]) != 0 || setuid(uid) != 0)
            echouer("identite", identite);
        /* execvpe cherche la commande dans le PATH de l'appelant (le nôtre,
         * celui du noyau, vide), pas dans celui d'envp : on prend le sien. */
        for (char **e = envp; *e; e++)
            if (strncmp(*e, "PATH=", 5) == 0)
                setenv("PATH", *e + 5, 1);
        execvpe(argv[0], argv, envp);
        dire("%s : %s", argv[0], strerror(errno));
        _exit(127);
    }
    if (enfant < 0)
        arreter("fork");
    close(tube[1]);
    /* Recopier le tube sur la console, et recueillir les fins (le premier
     * processus recueille aussi les orphelins). Le statut est écrit dès que
     * la commande a fini ; puis la sortie de ce qu'elle a lancé en
     * arrière-plan est encore recopiée tant que quelqu'un tient le tube, dix
     * secondes au plus (`$(...)`, dans verifier.sh, attendrait aussi la fin du
     * tube : un orphelin qui le garde ferait sinon tourner la machine jusqu'à
     * DUREE_MAX, sans que l'hôte sache que la commande avait fini). */
    static char tampon[65536];
    int fini = 0, ouvert = 1;
    struct timespec limite = { 0, 0 }, maintenant;
    while (ouvert && (!fini || (clock_gettime(CLOCK_MONOTONIC, &maintenant), maintenant.tv_sec < limite.tv_sec))) {
        struct pollfd q = { tube[0], POLLIN, 0 };
        if (poll(&q, 1, 100) > 0) {
            ssize_t r = read(tube[0], tampon, sizeof tampon);
            if (r == 0 || (r < 0 && errno != EINTR))
                ouvert = 0;
            for (ssize_t fait = 0, e; r > 0 && fait < r; fait += e)
                if ((e = write(1, tampon + fait, (size_t)(r - fait))) <= 0)
                    break;
        }
        int statut;
        for (pid_t p; (p = waitpid(-1, &statut, WNOHANG)) > 0;) {
            if (p != enfant)
                continue;
            ecrire_statut(travail, WIFEXITED(statut) ? WEXITSTATUS(statut) : 128 + WTERMSIG(statut));
            fini = 1;
            clock_gettime(CLOCK_MONOTONIC, &limite);
            limite.tv_sec += 10;
        }
    }
    if (!fini) {
        /* Le tube fermé, la commande peut-être pas encore recueillie. */
        int statut;
        if (waitpid(enfant, &statut, 0) != enfant)
            arreter("waitpid");
        ecrire_statut(travail, WIFEXITED(statut) ? WEXITSTATUS(statut) : 128 + WTERMSIG(statut));
    }
    reboot(RB_POWER_OFF);
    return 0;
}
