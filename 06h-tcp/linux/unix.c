/*
 * Les sockets AF_UNIX (6h), contre ce qu'en fait Linux 6.18 (mesuré, sonde
 * unix.c du plan de 6h), dans un dossier à soi de /tmp, effacé à la fin :
 *   - les sortes (SOCK_RAW devient SOCK_DGRAM, SOCK_RDM refusée) ; une
 *     socket neuve (son nom vide, ses tampons, poll, send, recv, accept,
 *     listen sans nom) ;
 *   - bind d'un chemin (le fichier S_IFSOCK, 0777 moins l'umask ; le nom
 *     rendu ; deux fois ; un chemin pris ; open du fichier : ENXIO) ; les
 *     adresses refusées ; connect (sans écoute, absent, vers un fichier) ;
 *   - une connexion : établie avant accept, les noms des deux bouts,
 *     SO_PEERCRED ; la file d'écoute (backlog + 1) ; les données (FIONREAD,
 *     TIOCOUTQ, MSG_PEEK, la lecture à la suite) ; sans lecteur, EAGAIN ;
 *     shutdown ; les fermetures (POLLHUP, ECONNRESET des données non lues,
 *     une écoute fermée) ; le nom abstrait (comparé avec sa longueur) ;
 *   - DGRAM : sendto, FIONREAD du premier, MSG_TRUNC, la file de dix,
 *     EMSGSIZE, EPROTOTYPE ; socketpair des trois sortes ; SEQPACKET garde
 *     les limites ; unlink pendant la liaison ; /proc/net/unix (SCM_RIGHTS
 *     attend 6l : chez nous, EINVAL ; pas de ligne) ;
 *   - un serveur et trois clients, en fils.
 * La place que prend un message dans le noyau (sa taille vraie) change
 * d'un noyau à l'autre : les lignes qui en dépendent ne comparent que leur
 * forme (au moins un envoi, puis EAGAIN).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] unix : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static int masque(int s)
{
    struct pollfd p = { s, POLLIN | POLLOUT | POLLRDHUP, 0 };
    poll(&p, 1, 0);
    return p.revents & (POLLIN | POLLOUT | POLLRDHUP | POLLERR | POLLHUP);
}

static socklen_t adr(struct sockaddr_un *a, const char *chemin)
{
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    strcpy(a->sun_path, chemin);
    return offsetof(struct sockaddr_un, sun_path) + strlen(chemin) + 1;
}

static int option(int s, int nom)
{
    int v = -99;
    socklen_t l = sizeof v;
    if (getsockopt(s, SOL_SOCKET, nom, &v, &l) < 0)
        return -1000 - errno;
    return v;
}

/* wmem_default : la taille de départ des tampons d'AF_UNIX. */
static int tampon_defaut(void)
{
    int v = 212992;
    FILE *f = fopen("/proc/sys/net/core/wmem_default", "r");
    if (f) {
        if (fscanf(f, "%d", &v) != 1)
            v = 212992;
        fclose(f);
    }
    return v;
}

static void sortes(void)
{
    int s;
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(s >= 0 && option(s, SO_TYPE) == SOCK_STREAM && option(s, SO_DOMAIN) == AF_UNIX, "SOCK_STREAM");
    close(s);
    s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    verifier(s >= 0 && option(s, SO_TYPE) == SOCK_SEQPACKET, "SOCK_SEQPACKET");
    close(s);
    s = socket(AF_UNIX, SOCK_RAW, 0);
    verifier(s >= 0 && option(s, SO_TYPE) == SOCK_DGRAM, "SOCK_RAW devient SOCK_DGRAM");
    close(s);
    s = socket(AF_UNIX, SOCK_DGRAM, 1);
    verifier(s >= 0, "le protocole 1 (PF_UNIX)");
    close(s);
    verifier(erreur(socket(AF_UNIX, SOCK_RDM, 0)) == ESOCKTNOSUPPORT, "SOCK_RDM : ESOCKTNOSUPPORT");
    verifier(erreur(socket(AF_UNIX, SOCK_STREAM, 2)) == EPROTONOSUPPORT, "le protocole 2 : EPROTONOSUPPORT");
}

static void neuve(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un u;
    socklen_t l = sizeof u;
    char b[8];
    verifier(getsockname(s, (void *)&u, &l) == 0 && l == 2, "getsockname d'une socket neuve : longueur 2");
    int d = tampon_defaut();
    verifier(option(s, SO_RCVBUF) == d && option(s, SO_SNDBUF) == d, "SO_RCVBUF, SO_SNDBUF : wmem_default");
    verifier(masque(s) == (POLLOUT | POLLHUP), "poll : POLLOUT | POLLHUP");
    verifier(erreur(send(s, "x", 1, MSG_DONTWAIT)) == ENOTCONN, "send : ENOTCONN");
    verifier(erreur(recv(s, b, 1, MSG_DONTWAIT)) == EINVAL, "recv : EINVAL");
    verifier(erreur(accept(s, 0, 0)) == EINVAL, "accept : EINVAL");
    verifier(erreur(listen(s, 1)) == EINVAL, "listen sans nom : EINVAL");
    l = sizeof u;
    verifier(getsockname(s, (void *)&u, &l) == 0 && l == 2, "et toujours sans nom");
    close(s);
}

static void noms(void)
{
    struct sockaddr_un u;
    socklen_t l;
    struct stat st;
    int s = socket(AF_UNIX, SOCK_STREAM, 0), c;
    umask(022);
    verifier(bind(s, (void *)&u, adr(&u, "sock1")) == 0, "bind d'un chemin");
    verifier(stat("sock1", &st) == 0 && st.st_mode == (S_IFSOCK | 0755), "le fichier : S_IFSOCK, 0777 moins l'umask");
    l = sizeof u;
    verifier(getsockname(s, (void *)&u, &l) == 0 && l == 8 && strcmp(u.sun_path, "sock1") == 0, "getsockname : le chemin, longueur 8");
    verifier(erreur(bind(s, (void *)&u, adr(&u, "sock9"))) == EINVAL && stat("sock9", &st) < 0, "bind deux fois : EINVAL, sans fichier");
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(erreur(bind(c, (void *)&u, adr(&u, "sock1"))) == EADDRINUSE, "le chemin d'une autre : EADDRINUSE");
    verifier(erreur(open("sock1", O_RDONLY)) == ENXIO, "open du fichier : ENXIO");
    verifier(erreur(connect(c, (void *)&u, adr(&u, "sock1"))) == ECONNREFUSED, "connect sans ecoute : ECONNREFUSED");
    verifier(erreur(connect(c, (void *)&u, adr(&u, "absent"))) == ENOENT, "connect vers un chemin absent : ENOENT");
    close(open("fichier", O_CREAT | O_WRONLY, 0644));
    verifier(erreur(connect(c, (void *)&u, adr(&u, "fichier"))) == ECONNREFUSED, "connect vers un fichier : ECONNREFUSED");
    verifier(erreur(bind(c, (void *)&u, adr(&u, "fichier"))) == EADDRINUSE, "bind sur un fichier : EADDRINUSE");
    close(c);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    memset(u.sun_path, 'a', sizeof u.sun_path);
    verifier(bind(c, (void *)&u, sizeof u) == 0, "un chemin de 108 octets sans nul");
    char long_nom[109];
    memset(long_nom, 'a', 108);
    long_nom[108] = 0;
    unlink(long_nom);
    close(c);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(erreur(bind(c, (void *)&u, 111)) == EINVAL && erreur(bind(c, (void *)&u, 1)) == EINVAL, "longueur 111 ou 1 : EINVAL");
    u.sun_family = AF_INET;
    verifier(erreur(bind(c, (void *)&u, 10)) == EINVAL, "une autre famille : EINVAL");
    close(c);
    close(s);
    unlink("sock1");
    unlink("fichier");
}

static void connexion(void)
{
    struct sockaddr_un u;
    socklen_t l;
    char b[64];
    int s = socket(AF_UNIX, SOCK_STREAM, 0), c, a;
    bind(s, (void *)&u, adr(&u, "ecoute"));
    listen(s, 2);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(connect(c, (void *)&u, adr(&u, "ecoute")) == 0, "connect avant accept : 0");
    verifier(masque(s) == POLLIN && masque(c) == POLLOUT, "poll : l'ecoute POLLIN, le client POLLOUT");
    verifier(send(c, "abc", 3, 0) == 3, "send avant accept");
    l = sizeof u;
    a = accept(s, (void *)&u, &l);
    verifier(a >= 0 && l == 2, "accept : l'adresse du client, sans nom (2)");
    verifier(recv(a, b, 10, 0) == 3, "recv : ce qui avait ete envoye");
    l = sizeof u;
    verifier(getpeername(c, (void *)&u, &l) == 0 && l == 9 && strcmp(u.sun_path, "ecoute") == 0, "getpeername du client : le nom de l'ecoute");
    l = sizeof u;
    verifier(getsockname(a, (void *)&u, &l) == 0 && l == 9 && strcmp(u.sun_path, "ecoute") == 0, "getsockname de l'acceptee : le nom de l'ecoute");
    l = sizeof u;
    verifier(getpeername(a, (void *)&u, &l) == 0 && l == 2, "getpeername de l'acceptee : 2");
    struct ucred cr;
    l = sizeof cr;
    verifier(getsockopt(a, SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && l == sizeof cr && cr.pid == getpid() && cr.uid == getuid()
             && cr.gid == getgid(), "SO_PEERCRED : le processus du pair");
    l = sizeof cr;
    verifier(getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && cr.pid == getpid(), "SO_PEERCRED de l'ecoute : le sien");
    /* La file : backlog 2, trois connexions, la quatrième attendrait. */
    int cs[5], ok = 0, refus = 0;
    for (int i = 0; i < 5; i++) {
        cs[i] = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        long r = erreur(connect(cs[i], (void *)&u, adr(&u, "ecoute")));
        ok += r == 0;
        refus += r == EAGAIN;
    }
    verifier(ok == 3 && refus == 2, "listen(2) : trois connexions, puis EAGAIN");
    for (int i = 0; i < 5; i++)
        close(cs[i]);
    fcntl(s, F_SETFL, O_NONBLOCK);
    int acceptes = 0, zeros = 0, x;
    while ((x = accept(s, 0, 0)) >= 0) {
        acceptes++;
        zeros += recv(x, b, 1, MSG_DONTWAIT) == 0;
        close(x);
    }
    verifier(acceptes == 3 && zeros == 3, "clients fermes avant accept : acceptes quand meme, recv 0");
    /* Les données. */
    send(c, "12345", 5, 0);
    send(c, "678", 3, 0);
    int n = -1, q = -1;
    ioctl(a, FIONREAD, &n);
    ioctl(c, TIOCOUTQ, &q);
    verifier(n == 8 && q > 0, "FIONREAD : tout (8) ; TIOCOUTQ : ce que le pair n'a pas lu");
    long r1 = recv(a, b, 6, 0), r2 = recv(a, b, 10, 0);
    verifier(r1 == 6 && r2 == 2, "la lecture a la suite des messages (6 puis 2)");
    send(c, "ab", 2, 0);
    send(c, "cd", 2, 0);
    verifier(recv(a, b, 10, MSG_PEEK) == 4 && recv(a, b, 10, 0) == 4 && memcmp(b, "abcd", 4) == 0, "MSG_PEEK, puis tout");
    ioctl(c, TIOCOUTQ, &q);
    verifier(q == 0, "TIOCOUTQ : 0 une fois tout lu");
    /* Sans lecteur : des envois, puis EAGAIN ; poll sans POLLOUT. */
    fcntl(c, F_SETFL, O_NONBLOCK);
    static char gros[4096];
    long envois = 0, k;
    while ((k = send(c, gros, 1000, 0)) > 0)
        envois++;
    verifier(envois > 0 && errno == EAGAIN && erreur(send(c, gros, 1, 0)) == EAGAIN && (masque(c) & POLLOUT) == 0,
             "sans lecteur : des envois, puis EAGAIN, poll sans POLLOUT");
    while (recv(a, gros, sizeof gros, MSG_DONTWAIT) > 0)
        ;
    verifier(masque(c) & POLLOUT, "tout lu : POLLOUT revient");
    /* shutdown(SHUT_WR). */
    verifier(shutdown(c, SHUT_WR) == 0 && masque(a) == (POLLIN | POLLOUT | POLLRDHUP) && recv(a, b, 1, 0) == 0,
             "SHUT_WR : l'autre lit 0 (POLLIN | POLLRDHUP)");
    verifier(erreur(send(c, "x", 1, MSG_NOSIGNAL)) == EPIPE, "puis send : EPIPE");
    verifier(send(a, "yz", 2, 0) == 2, "l'autre ecrit encore");
    close(a);
    verifier(masque(c) == (POLLIN | POLLOUT | POLLRDHUP | POLLHUP), "l'autre ferme : POLLIN | POLLOUT | POLLHUP");
    verifier(recv(c, b, 10, 0) == 2 && recv(c, b, 10, 0) == 0, "ce qui reste se lit, puis 0");
    close(c);
    /* close avec des données non lues : ECONNRESET. */
    fcntl(s, F_SETFL, 0);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (void *)&u, adr(&u, "ecoute"));
    a = accept(s, 0, 0);
    send(c, "abc", 3, 0);
    close(a);
    verifier((masque(c) & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP) && erreur(recv(c, b, 10, MSG_DONTWAIT)) == ECONNRESET
             && erreur(send(c, "x", 1, MSG_DONTWAIT | MSG_NOSIGNAL)) == EPIPE, "ferme avec des donnees non lues : ECONNRESET, puis EPIPE");
    close(c);
    /* L'écoute fermée, un client en file : ECONNRESET. */
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (void *)&u, adr(&u, "ecoute"));
    close(s);
    verifier((masque(c) & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP) && erreur(recv(c, b, 10, MSG_DONTWAIT)) == ECONNRESET,
             "l'ecoute fermee, un client en file : ECONNRESET");
    close(c);
    struct stat st;
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(stat("ecoute", &st) == 0 && erreur(connect(c, (void *)&u, adr(&u, "ecoute"))) == ECONNREFUSED,
             "le fichier reste ; connect : ECONNREFUSED");
    close(c);
    unlink("ecoute");
}

/* Le plus petit numéro de descripteur libre. */
static int plus_petit_libre(void)
{
    int d = dup(0);
    close(d);
    return d;
}

/* accept sans descripteur libre : EMFILE, la connexion reste en file avec
 * ses données ; une adresse de retour qui faute : EFAULT, aucun descripteur,
 * et le client voit son pair fermé (POLLHUP). Comme Linux, qui réserve le
 * numéro avant de prendre la connexion, et copie l'adresse avant de
 * l'installer. */
static void accept_sans_place(void)
{
    struct sockaddr_un u;
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(s, (void *)&u, adr(&u, "pleine"));
    listen(s, 4);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (void *)&u, adr(&u, "pleine"));
    send(c, "abc", 3, 0);
    struct rlimit r, juste;
    getrlimit(RLIMIT_NOFILE, &r);
    juste = r;
    juste.rlim_cur = plus_petit_libre();
    setrlimit(RLIMIT_NOFILE, &juste);
    long e = erreur(accept(s, NULL, NULL));
    setrlimit(RLIMIT_NOFILE, &r);
    int a = accept4(s, NULL, NULL, SOCK_NONBLOCK);
    char b[8] = { 0 };
    long n = a >= 0 ? recv(a, b, sizeof b, 0) : -1;
    verifier(e == EMFILE && n == 3 && memcmp(b, "abc", 3) == 0, "accept sans descripteur libre : EMFILE, la connexion reste en file");
    close(a);
    close(c);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (void *)&u, adr(&u, "pleine"));
    int libre = plus_petit_libre();
    socklen_t l = sizeof u;
    e = erreur(accept(s, (struct sockaddr *)8, &l));
    verifier(e == EFAULT && plus_petit_libre() == libre && (masque(c) & POLLHUP), "accept dont l'adresse faute : EFAULT, sans descripteur, le client voit POLLHUP");
    close(c);
    close(s);
    unlink("pleine");
}

/* L'heure, en secondes. */
static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int paire_lecteurs[2];

static void *lecteur_bloque(void *x)
{
    (void)x;
    char b[4];
    recv(paire_lecteurs[0], b, sizeof b, 0);
    return NULL;
}

static void *debloquer_dans_une_seconde(void *x)
{
    (void)x;
    usleep(1000000);
    send(paire_lecteurs[1], "x", 1, 0);
    return NULL;
}

static void *ecrire_dans_300_ms(void *x)
{
    (void)x;
    usleep(300000);
    send(paire_lecteurs[1], "cd", 2, 0);
    return NULL;
}

/* Les lecteurs d'un flux : un lecteur bloqué n'empêche pas un autre de
 * voir EAGAIN tout de suite (le `iolock` rendu pendant l'attente) ;
 * SO_RCVLOWAT fait attendre le seuil. */
static void lecteurs(void)
{
    socketpair(AF_UNIX, SOCK_STREAM, 0, paire_lecteurs);
    pthread_t t, d;
    pthread_create(&t, NULL, lecteur_bloque, NULL);
    usleep(200000);
    pthread_create(&d, NULL, debloquer_dans_une_seconde, NULL);
    double t0 = maintenant();
    char b[8];
    long e = erreur(recv(paire_lecteurs[0], b, sizeof b, MSG_DONTWAIT));
    double duree = maintenant() - t0;
    pthread_join(t, NULL);
    pthread_join(d, NULL);
    verifier(e == EAGAIN && duree < 0.5, "recv MSG_DONTWAIT pendant le recv bloquant d'un autre fil : EAGAIN tout de suite");
    int quatre = 4;
    setsockopt(paire_lecteurs[0], SOL_SOCKET, SO_RCVLOWAT, &quatre, sizeof quatre);
    send(paire_lecteurs[1], "ab", 2, 0);
    pthread_create(&t, NULL, ecrire_dans_300_ms, NULL);
    long n = recv(paire_lecteurs[0], b, sizeof b, 0);
    pthread_join(t, NULL);
    verifier(n == 4, "SO_RCVLOWAT 4 : recv attend les 4 octets");
    close(paire_lecteurs[0]);
    close(paire_lecteurs[1]);
}

/* SEQPACKET : recv d'une socket qui n'est pas connectée (neuve, ou une
 * écoute, dont la file apporte ses filles) : ENOTCONN, la connexion
 * toujours là pour accept ; un pair fermé sans tout lire : ECONNRESET, une
 * fois, puis EPIPE ; recvfrom d'un flux et d'un SEQPACKET : le nom de
 * l'écoute (que porte la fille). */
static void seqpacket_et_adresses(void)
{
    struct sockaddr_un u;
    char b[8];
    int n = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    long e1 = erreur(recv(n, b, sizeof b, MSG_DONTWAIT));
    close(n);
    int s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    bind(s, (void *)&u, adr(&u, "sq"));
    listen(s, 1);
    int c = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    connect(c, (void *)&u, adr(&u, "sq"));
    long e2 = erreur(recv(s, b, sizeof b, MSG_DONTWAIT));
    fcntl(s, F_SETFL, O_NONBLOCK);
    int a = accept(s, NULL, NULL);
    verifier(e1 == ENOTCONN && e2 == ENOTCONN && a >= 0, "SEQPACKET : recv d'une neuve, d'une ecoute : ENOTCONN ; accept ensuite");
    close(a);
    close(c);
    close(s);
    unlink("sq");
    int v[2];
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, v);
    send(v[0], "abc", 3, 0);
    close(v[1]);
    long r1 = erreur(send(v[0], "x", 1, MSG_NOSIGNAL));
    long r2 = erreur(send(v[0], "x", 1, MSG_NOSIGNAL));
    verifier(r1 == ECONNRESET && r2 == EPIPE, "SEQPACKET, le pair ferme sans tout lire : send ECONNRESET, puis EPIPE");
    close(v[0]);
    int ok = 1;
    for (int sorte = SOCK_STREAM; sorte <= SOCK_SEQPACKET; sorte += SOCK_SEQPACKET - SOCK_STREAM) {
        s = socket(AF_UNIX, sorte, 0);
        bind(s, (void *)&u, adr(&u, "rf"));
        listen(s, 1);
        c = socket(AF_UNIX, sorte, 0);
        connect(c, (void *)&u, adr(&u, "rf"));
        a = accept(s, NULL, NULL);
        send(a, "x", 1, 0);
        struct sockaddr_un w;
        socklen_t l = sizeof w;
        memset(&w, 0, sizeof w);
        long r = recvfrom(c, b, sizeof b, 0, (void *)&w, &l);
        ok &= r == 1 && l == 5 && strcmp(w.sun_path, "rf") == 0;
        close(a);
        close(c);
        close(s);
        unlink("rf");
    }
    verifier(ok, "recvfrom d'un flux et d'un SEQPACKET : le nom de l'ecoute");
}

static int dest_poll;

static void *lire_dans_300_ms(void *x)
{
    (void)x;
    usleep(300000);
    char b[8];
    recv(dest_poll, b, sizeof b, 0);
    return NULL;
}

/* DGRAM : un connecté qui attend POLLOUT, la file de son pair pleine des
 * datagrammes d'un AUTRE, est réveillé quand le pair lit
 * (`unix_dgram_peer_wake_relay`) ; arrêté en lecture, recv non bloquant :
 * EAGAIN, bloquant : 0 ; MSG_PEEK laisse le datagramme ; un destinataire
 * fermé sans lire rend sa place à l'émetteur (TIOCOUTQ 0). */
static void datagrammes_suite(void)
{
    struct sockaddr_un u;
    int r = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(r, (void *)&u, adr(&u, "dp"));
    dest_poll = r;
    int autre = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    while (sendto(autre, "y", 1, 0, (void *)&u, adr(&u, "dp")) > 0)
        ;
    int s = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    connect(s, (void *)&u, adr(&u, "dp"));
    struct pollfd p = { s, POLLOUT, 0 };
    int avant = poll(&p, 1, 0);
    pthread_t t;
    pthread_create(&t, NULL, lire_dans_300_ms, NULL);
    double t0 = maintenant();
    int pret = poll(&p, 1, 3000);
    double duree = maintenant() - t0;
    pthread_join(t, NULL);
    verifier(avant == 0 && pret == 1 && duree < 2, "DGRAM connecte, la file du pair pleine d'un autre : poll(POLLOUT) reveille quand il lit");
    close(s);
    int q = -1;
    ioctl(autre, TIOCOUTQ, &q);
    int avant_fermeture = q;
    close(r);
    ioctl(autre, TIOCOUTQ, &q);
    verifier(avant_fermeture > 0 && q == 0, "un destinataire ferme sans lire : l'emetteur retrouve sa place (TIOCOUTQ 0)");
    close(autre);
    unlink("dp");
    int v[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, v);
    shutdown(v[0], SHUT_RD);
    char b[8];
    long e = erreur(recv(v[0], b, sizeof b, MSG_DONTWAIT));
    long z = recv(v[0], b, sizeof b, 0);
    send(v[1], "pk", 2, 0);
    long n1 = recv(v[0], b, sizeof b, MSG_PEEK | MSG_DONTWAIT);
    verifier(e == EAGAIN && z == 0 && n1 == -1, "DGRAM arrete en lecture : recv MSG_DONTWAIT EAGAIN, bloquant 0");
    close(v[0]);
    close(v[1]);
    socketpair(AF_UNIX, SOCK_DGRAM, 0, v);
    send(v[1], "pk", 2, 0);
    n1 = recv(v[0], b, sizeof b, MSG_PEEK);
    long n2 = recv(v[0], b, sizeof b, MSG_DONTWAIT);
    verifier(n1 == 2 && n2 == 2, "DGRAM : MSG_PEEK laisse le datagramme, la lecture suivante le prend");
    close(v[0]);
    close(v[1]);
}

/* Les noms : un chemin de 108 octets (longueur 111) ; un nom abstrait par
 * sorte (un flux ne trouve pas celui d'un DGRAM : ECONNREFUSED ; il peut
 * porter le même) ; le nom d'un pair fermé, d'un émetteur fermé, encore
 * là ; SO_PASSCRED de l'écoute, hérité par l'acceptée ; SO_PEERCRED du
 * client : l'écoute ; la taille vraie de Linux (TIOCOUTQ : 33 536 pour 32
 * Kio, 4352 pour 2000 ; sans lecteur, 215 488 octets envoyés). */
static void noms_et_tailles(void)
{
    struct sockaddr_un u, v;
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    memset(u.sun_path, 'b', sizeof u.sun_path);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    long r = bind(s, (void *)&u, sizeof u);
    struct sockaddr_storage w;
    socklen_t l = sizeof w;
    getsockname(s, (void *)&w, &l);
    verifier(r == 0 && l == 111, "un chemin de 108 octets : getsockname, longueur 111");
    char nom[109];
    memset(nom, 'b', 108);
    nom[108] = 0;
    unlink(nom);
    close(s);
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    memcpy(u.sun_path, "\0unix-sortes", 13);
    l = offsetof(struct sockaddr_un, sun_path) + 13;
    int d = socket(AF_UNIX, SOCK_DGRAM, 0), f = socket(AF_UNIX, SOCK_STREAM, 0), c = socket(AF_UNIX, SOCK_STREAM, 0);
    long r1 = bind(d, (void *)&u, l);
    long r2 = erreur(connect(c, (void *)&u, l));
    long r3 = bind(f, (void *)&u, l);
    verifier(r1 == 0 && r2 == ECONNREFUSED && r3 == 0, "un nom abstrait par sorte : un flux ne trouve pas celui d'un DGRAM, et peut le porter");
    close(c);
    close(f);
    close(d);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    int un = 1;
    setsockopt(s, SOL_SOCKET, SO_PASSCRED, &un, sizeof un);
    bind(s, (void *)&u, adr(&u, "nf"));
    listen(s, 1);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(c, (void *)&u, adr(&u, "nf"));
    struct ucred cr;
    socklen_t lc = sizeof cr;
    getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &lc);
    int a = accept(s, NULL, NULL);
    verifier(option(a, SO_PASSCRED) == 1 && cr.pid == getpid() && cr.uid == getuid(),
             "l'acceptee herite SO_PASSCRED ; SO_PEERCRED du client : le processus de l'ecoute");
    close(a);
    l = sizeof v;
    r = getpeername(c, (void *)&v, &l);
    int ok = r == 0 && l == 5;
    close(c);
    close(s);
    unlink("nf");
    d = socket(AF_UNIX, SOCK_DGRAM, 0);
    int e = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(d, (void *)&u, adr(&u, "nd"));
    bind(e, (void *)&u, adr(&u, "ne"));
    sendto(e, "x", 1, 0, (void *)&u, adr(&u, "nd"));
    close(e);
    char b[4];
    l = sizeof v;
    r = recvfrom(d, b, sizeof b, 0, (void *)&v, &l);
    ok &= r == 1 && l == 5;
    close(d);
    unlink("nd");
    unlink("ne");
    verifier(ok, "le nom d'un pair ferme (getpeername) et d'un emetteur ferme (recvfrom) : encore la");
    int p[2];
    static char gros[1 << 20];
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    send(p[0], gros, 32768, 0);
    int q32 = -1, qfin = -1;
    ioctl(p[0], TIOCOUTQ, &q32);
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    long total = 32768, k;
    while ((k = send(p[0], gros, sizeof gros, 0)) > 0)
        total += k;
    ioctl(p[0], TIOCOUTQ, &qfin);
    close(p[0]);
    close(p[1]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    send(p[0], gros, 2000, 0);
    int q2 = -1;
    ioctl(p[0], TIOCOUTQ, &q2);
    close(p[0]);
    close(p[1]);
    verifier(q32 == 33536 && q2 == 4352 && total == 215488 && qfin == 219136,
             "la taille vraie de Linux : 33536 pour 32 Kio, 4352 pour 2000 ; sans lecteur, 215488 octets envoyes");
}

static void abstrait(void)
{
    struct sockaddr_un u;
    socklen_t l;
    int s = socket(AF_UNIX, SOCK_STREAM, 0), c;
    memset(&u, 0, sizeof u);
    u.sun_family = AF_UNIX;
    memcpy(u.sun_path, "\0abc", 4);
    verifier(bind(s, (void *)&u, offsetof(struct sockaddr_un, sun_path) + 4) == 0, "un nom abstrait");
    l = sizeof u;
    verifier(getsockname(s, (void *)&u, &l) == 0 && l == 6, "son nom : longueur 6");
    listen(s, 1);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(connect(c, (void *)&u, offsetof(struct sockaddr_un, sun_path) + 4) == 0, "connect a la meme longueur");
    close(c);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(erreur(connect(c, (void *)&u, offsetof(struct sockaddr_un, sun_path) + 5)) == ECONNREFUSED, "un nul de plus : ECONNREFUSED");
    close(c);
    int d = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(erreur(bind(d, (void *)&u, offsetof(struct sockaddr_un, sun_path) + 4)) == EADDRINUSE, "le meme nom : EADDRINUSE");
    close(d);
    /* Le nom automatique : bind d'une adresse vide. */
    d = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un v = { .sun_family = AF_UNIX };
    l = sizeof v;
    verifier(bind(d, (void *)&v, offsetof(struct sockaddr_un, sun_path)) == 0 && getsockname(d, (void *)&v, &l) == 0 && l == 8
             && v.sun_path[0] == 0, "bind d'une adresse vide : un nom automatique (\\0 et 5 chiffres)");
    close(d);
    close(s);
}

static void datagrammes(void)
{
    struct sockaddr_un u;
    socklen_t l;
    static char b[300000];
    int s = socket(AF_UNIX, SOCK_DGRAM, 0), c;
    bind(s, (void *)&u, adr(&u, "dg1"));
    c = socket(AF_UNIX, SOCK_DGRAM, 0);
    verifier(sendto(c, "hello", 5, 0, (void *)&u, adr(&u, "dg1")) == 5, "sendto");
    sendto(c, "xy", 2, 0, (void *)&u, adr(&u, "dg1"));
    int n = -1;
    ioctl(s, FIONREAD, &n);
    verifier(n == 5, "FIONREAD : le premier datagramme");
    l = sizeof u;
    verifier(recvfrom(s, b, 2, 0, (void *)&u, &l) == 2 && l == 0, "recvfrom coupe, l'emetteur sans nom (longueur 0)");
    struct msghdr m = { 0 };
    struct iovec io = { b, 1 };
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    verifier(recvmsg(s, &m, 0) == 1 && (m.msg_flags & MSG_TRUNC), "recvmsg coupe : MSG_TRUNC");
    verifier(erreur(send(c, "x", 1, 0)) == ENOTCONN, "send sans destination : ENOTCONN");
    verifier(erreur(listen(c, 1)) == EOPNOTSUPP, "listen : EOPNOTSUPP");
    int t = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(erreur(connect(t, (void *)&u, adr(&u, "dg1"))) == EPROTOTYPE, "un flux vers un DGRAM : EPROTOTYPE");
    close(t);
    fcntl(c, F_SETFL, O_NONBLOCK);
    int k = 0;
    long r;
    while ((r = sendto(c, b, 100, 0, (void *)&u, adr(&u, "dg1"))) > 0)
        k++;
    verifier(k == 11 && errno == EAGAIN, "sans lecteur : onze datagrammes, puis EAGAIN");
    verifier(erreur(sendto(c, b, 300000, 0, (void *)&u, adr(&u, "dg1"))) == EMSGSIZE, "300 000 octets : EMSGSIZE");
    /* Connectée : l'adresse de l'émetteur nommé. */
    while (recv(s, b, sizeof b, MSG_DONTWAIT) > 0)
        ;
    int w = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(w, (void *)&u, adr(&u, "dg2"));
    connect(w, (void *)&u, adr(&u, "dg1"));
    send(w, "z", 1, 0);
    l = sizeof u;
    verifier(recvfrom(s, b, 10, 0, (void *)&u, &l) == 1 && l == 6 && strcmp(u.sun_path, "dg2") == 0,
             "connect, send ; recvfrom : l'emetteur nomme");
    close(w);
    close(s);
    verifier(erreur(sendto(c, "x", 1, 0, (void *)&u, adr(&u, "dg1"))) == ECONNREFUSED, "vers une socket fermee (le fichier reste) : ECONNREFUSED");
    close(c);
    unlink("dg1");
    unlink("dg2");
}

static void paires(void)
{
    int v[2];
    char b[16];
    struct sockaddr_un u;
    socklen_t l;
    verifier(socketpair(AF_UNIX, SOCK_STREAM, 0, v) == 0, "socketpair STREAM");
    l = sizeof u;
    int n1 = getsockname(v[0], (void *)&u, &l) == 0 && l == 2;
    l = sizeof u;
    verifier(n1 && getpeername(v[0], (void *)&u, &l) == 0 && l == 2, "ses noms : vides (2)");
    struct ucred cr;
    l = sizeof cr;
    verifier(getsockopt(v[0], SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && cr.pid == getpid(), "SO_PEERCRED : le processus");
    verifier(send(v[0], "ping", 4, 0) == 4 && recv(v[1], b, 16, 0) == 4 && send(v[1], "pong", 4, 0) == 4 && recv(v[0], b, 16, 0) == 4,
             "dans les deux sens");
    close(v[1]);
    verifier(masque(v[0]) == (POLLIN | POLLOUT | POLLRDHUP | POLLHUP) && erreur(send(v[0], "x", 1, MSG_NOSIGNAL)) == EPIPE,
             "le pair ferme : POLLHUP, puis EPIPE");
    close(v[0]);
    verifier(socketpair(AF_UNIX, SOCK_DGRAM, 0, v) == 0, "socketpair DGRAM");
    verifier(send(v[0], "d", 1, 0) == 1 && recv(v[1], b, 16, 0) == 1, "un datagramme de l'une a l'autre");
    close(v[0]);
    close(v[1]);
    verifier(erreur(socketpair(AF_INET, SOCK_STREAM, 0, v)) == EOPNOTSUPP, "socketpair AF_INET : EOPNOTSUPP");
    verifier(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, v) == 0, "socketpair SEQPACKET");
    send(v[0], "abcd", 4, 0);
    send(v[0], "ef", 2, 0);
    struct msghdr m = { 0 };
    struct iovec io = { b, 2 };
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    long r = recvmsg(v[1], &m, 0);
    verifier(r == 2 && (m.msg_flags & MSG_TRUNC) && recv(v[1], b, 10, 0) == 2, "SEQPACKET : les limites gardees (MSG_TRUNC)");
    close(v[0]);
    verifier(recv(v[1], b, 10, 0) == 0, "SEQPACKET, le pair ferme : recv 0");
    close(v[1]);
}

static void unlink_et_proc(void)
{
    struct sockaddr_un u;
    socklen_t l;
    int s = socket(AF_UNIX, SOCK_STREAM, 0), c;
    bind(s, (void *)&u, adr(&u, "sock2"));
    listen(s, 1);
    unlink("sock2");
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(erreur(connect(c, (void *)&u, adr(&u, "sock2"))) == ENOENT, "le chemin efface : connect ENOENT");
    close(c);
    l = sizeof u;
    verifier(getsockname(s, (void *)&u, &l) == 0 && l == 8 && strcmp(u.sun_path, "sock2") == 0, "la socket garde son nom");
    /* /proc/net/unix : l'en-tête, et notre écoute, son chemin entier. */
    bind(c = socket(AF_UNIX, SOCK_STREAM, 0), (void *)&u, adr(&u, "visible"));
    listen(c, 1);
    /* Le nom tel que donné à bind (relatif ici), pas un chemin absolu. */
    char ligne[512];
    const char *fin = " visible\n";
    FILE *f = fopen("/proc/net/unix", "r");
    int entete = 0, trouve = 0;
    if (f) {
        if (fgets(ligne, sizeof ligne, f))
            entete = strcmp(ligne, "Num       RefCount Protocol Flags    Type St Inode Path\n") == 0;
        while (fgets(ligne, sizeof ligne, f)) {
            size_t n = strlen(ligne), k = strlen(fin);
            /* Une écoute : __SO_ACCEPTCON, SOCK_STREAM, non connectée. */
            trouve |= n > k && strcmp(ligne + n - k, fin) == 0 && strstr(ligne, " 00010000 0001 01 ") != NULL;
        }
        fclose(f);
    }
    verifier(entete && trouve, "/proc/net/unix : l'en-tete, et l'ecoute (son nom)");
    close(c);
    close(s);
    unlink("visible");
}

/* Un serveur, trois clients en fils : chacun envoie une ligne, le serveur
 * la renvoie à l'envers. */
static int ecoute_fils;

static void *serveur(void *arg)
{
    (void)arg;
    for (int i = 0; i < 3; i++) {
        int a = accept(ecoute_fils, 0, 0);
        char b[64];
        long n = recv(a, b, sizeof b, 0);
        for (long k = 0; k < n / 2; k++) {
            char t = b[k];
            b[k] = b[n - 1 - k];
            b[n - 1 - k] = t;
        }
        send(a, b, n, 0);
        close(a);
    }
    return NULL;
}

static void *client(void *arg)
{
    struct sockaddr_un u;
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    long ok = 0;
    if (connect(c, (void *)&u, adr(&u, "serveur")) == 0) {
        char b[64], attendu[64];
        snprintf(b, sizeof b, "client %ld", (long)arg);
        size_t n = strlen(b);
        for (size_t k = 0; k < n; k++)
            attendu[k] = b[n - 1 - k];
        send(c, b, n, 0);
        long r = recv(c, b, sizeof b, MSG_WAITALL);
        ok = r == (long)n && memcmp(b, attendu, n) == 0;
    }
    close(c);
    return (void *)ok;
}

static void fils(void)
{
    struct sockaddr_un u;
    ecoute_fils = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(ecoute_fils, (void *)&u, adr(&u, "serveur"));
    listen(ecoute_fils, 5);
    pthread_t s, c[3];
    pthread_create(&s, NULL, serveur, NULL);
    for (long i = 0; i < 3; i++)
        pthread_create(&c[i], NULL, client, (void *)i);
    long bons = 0;
    for (int i = 0; i < 3; i++) {
        void *r;
        pthread_join(c[i], &r);
        bons += (long)r;
    }
    pthread_join(s, NULL);
    verifier(bons == 3, "un serveur et trois clients en fils");
    close(ecoute_fils);
    unlink("serveur");
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    char dossier[64];
    snprintf(dossier, sizeof dossier, "/tmp/unix-%d", getpid());
    mkdir(dossier, 0755);
    if (chdir(dossier) < 0) {
        printf("[linux] unix : pas de dossier a soi : ECHEC\n");
        return 1;
    }
    sortes();
    neuve();
    noms();
    connexion();
    accept_sans_place();
    lecteurs();
    seqpacket_et_adresses();
    datagrammes_suite();
    noms_et_tailles();
    abstrait();
    datagrammes();
    paires();
    unlink_et_proc();
    fils();
    if (chdir("/") < 0 || rmdir(dossier) < 0)
        verifier(0, "le dossier efface");
    printf("[linux] unix : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
