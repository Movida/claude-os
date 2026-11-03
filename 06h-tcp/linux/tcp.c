/*
 * Les sockets TCP (6h), contre ce qu'en fait Linux 6.18 (mesuré, sonde
 * tcp.c du plan de 6h), sur l'interface de boucle seulement (127.0.0.1,
 * des ports éphémères) :
 *   - socket et ses refus ; une socket neuve (getpeername, recv, send,
 *     accept, shutdown, poll) ; les options (leurs valeurs de départ, leurs
 *     bornes) ;
 *   - listen (sans bind : un port éphémère ; deux fois ; bind après :
 *     EINVAL), une écoute (connect : EISCONN, recv, send, poll) ;
 *   - connect vers un port fermé (ECONNREFUSED, bloquant et non bloquant,
 *     SO_ERROR), un connect non bloquant réussi (EINPROGRESS, puis 0, puis
 *     EISCONN), accept4 (SOCK_NONBLOCK, SOCK_CLOEXEC, une adresse coupée),
 *     le port éphémère d'un connect (pair) ;
 *   - les données : FIONREAD, SIOCOUTQ, MSG_PEEK, MSG_TRUNC qui jette,
 *     recvfrom (une adresse de longueur 0) ; shutdown(SHUT_WR) ; l'autre
 *     fermé (EPIPE après son RST) ; close avec des données non lues (RST,
 *     ECONNRESET) ; SO_LINGER 0 ; connect(AF_UNSPEC) ;
 *   - la file d'écoute (listen(0) : un client établi, listen(2) : trois) ;
 *   - un connect vers une écoute dont la file est pleine (un « trou noir »
 *     sur lo : chaque SYN y est jeté) : SO_SNDTIMEO de 300 ms, EINPROGRESS,
 *     puis EALREADY ; TCP_SYNCNT 1 : ETIMEDOUT vers 3 s (trois SYN, à 0, 1
 *     et 2 s : Linux 6.x ne double pas les premiers délais d'un SYN) ;
 *   - la socket vue comme fichier (fstat) ; UDP et TCP sur le même port ;
 *   - un connect non bloquant suivi par epoll en déclenchement par front,
 *     comme Bun ; deux fils qui s'échangent 1 Mio en aller-retour.
 * Rien ne compare de valeur qui dépend de la configuration de Linux (le
 * MSS sur lo, SO_SNDBUF agrandi, TCP_CONGESTION : « cubic » chez Linux,
 * « reno » chez nous). Sur l'hôte comme chez nous. Les délais sont des
 * multiples de 4 ms (le tic de l'hôte : HZ = 250).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <linux/sockios.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] tcp : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* L'errno d'un appel raté (0 s'il a réussi). */
static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static struct sockaddr_in lo(uint16_t port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    return a;
}

static int port_de(int s)
{
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    getsockname(s, (void *)&a, &l);
    return ntohs(a.sin_port);
}

static int option(int s, int niveau, int nom)
{
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(s, niveau, nom, &v, &l) < 0)
        return -1000 - errno;
    return v;
}

static int masque(int s)
{
    struct pollfd p = { s, POLLIN | POLLOUT | POLLRDHUP, 0 };
    poll(&p, 1, 0);
    return p.revents;
}

/* Une écoute liée à 127.0.0.1, sur un port éphémère. */
static int ecoute(int *port, int backlog)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = lo(0);
    bind(s, (void *)&a, sizeof a);
    listen(s, backlog);
    *port = port_de(s);
    return s;
}

/* Une connexion établie : le client et la socket acceptée. */
static void paire(int *c, int *a)
{
    int port, l = ecoute(&port, 1);
    *c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(*c, (void *)&x, sizeof x);
    *a = accept(l, NULL, NULL);
    close(l);
}

static void attendre_ms(int ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

/* Un port fermé : lié puis libéré (personne n'y écoute). */
static int port_ferme(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = lo(0);
    bind(s, (void *)&a, sizeof a);
    int p = port_de(s);
    close(s);
    return p;
}

static void neuve(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    verifier(s >= 0 && socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) >= 0, "socket(SOCK_STREAM), protocole 0 ou 6");
    verifier(erreur(socket(AF_INET, SOCK_STREAM, IPPROTO_UDP)) == EPROTONOSUPPORT, "SOCK_STREAM et IPPROTO_UDP : EPROTONOSUPPORT");
    char b[16];
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    verifier(erreur(getpeername(s, (void *)&a, &l)) == ENOTCONN, "socket neuve : getpeername ENOTCONN");
    verifier(erreur(recv(s, b, 1, MSG_DONTWAIT)) == ENOTCONN, "socket neuve : recv ENOTCONN");
    verifier(erreur(send(s, "x", 1, MSG_NOSIGNAL)) == EPIPE, "socket neuve : send EPIPE");
    verifier(erreur(accept(s, NULL, NULL)) == EINVAL, "socket neuve : accept EINVAL");
    verifier(masque(s) == (POLLOUT | POLLHUP), "socket neuve : poll POLLOUT | POLLHUP");
    verifier(erreur(shutdown(s, SHUT_RDWR)) == ENOTCONN && masque(s) == (POLLIN | POLLOUT | POLLHUP | POLLRDHUP),
             "socket neuve : shutdown ENOTCONN, mais les drapeaux poses");
    close(s);
    s = socket(AF_INET, SOCK_STREAM, 0);
    verifier(option(s, IPPROTO_TCP, TCP_MAXSEG) == 536 && option(s, IPPROTO_TCP, TCP_NODELAY) == 0
             && option(s, IPPROTO_TCP, TCP_CORK) == 0, "options neuves : TCP_MAXSEG 536, NODELAY et CORK 0");
    verifier(option(s, IPPROTO_TCP, TCP_KEEPIDLE) == 7200 && option(s, IPPROTO_TCP, TCP_KEEPINTVL) == 75
             && option(s, IPPROTO_TCP, TCP_KEEPCNT) == 9 && option(s, IPPROTO_TCP, TCP_SYNCNT) == 6,
             "options neuves : keepalive 7200, 75, 9 ; SYNCNT 6");
    int v = 0;
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &v, 4)) == EINVAL
             && erreur(setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &(int){32768}, 4)) == EINVAL
             && erreur(setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &(int){32767}, 4)) == 0,
             "TCP_KEEPIDLE : 0 et 32768 refuses, 32767 accepte");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &v, 4)) == EINVAL
             && erreur(setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &(int){128}, 4)) == EINVAL
             && erreur(setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &v, 4)) == EINVAL,
             "TCP_KEEPCNT 0 et 128, TCP_KEEPINTVL 0 : refuses");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &(int){1}, 4)) == EINVAL
             && erreur(setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &(int){88}, 4)) == 0
             && erreur(setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &(int){536}, 4)) == 0 && option(s, IPPROTO_TCP, TCP_MAXSEG) == 536,
             "TCP_MAXSEG : 1 refuse, 88 et 536 acceptes, relu 536");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &(int){1}, 1)) == EINVAL
             && erreur(setsockopt(s, IPPROTO_TCP, 999, &(int){1}, 4)) == ENOPROTOOPT
             && option(s, IPPROTO_TCP, 999) == -1000 - ENOPROTOOPT,
             "SOL_TCP : longueur 1 EINVAL, option inconnue ENOPROTOOPT");
    char nom[16] = {0};
    socklen_t ln = sizeof nom;
    verifier(getsockopt(s, IPPROTO_TCP, TCP_CONGESTION, nom, &ln) == 0 && nom[0] != 0, "TCP_CONGESTION : un nom");
    verifier(option(s, SOL_SOCKET, SO_RCVBUF) > 0 && option(s, SOL_SOCKET, SO_SNDBUF) > 0 && option(s, SOL_SOCKET, SO_TYPE) == SOCK_STREAM
             && option(s, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_TCP && option(s, SOL_SOCKET, SO_ACCEPTCONN) == 0,
             "SO_RCVBUF, SO_SNDBUF, SO_TYPE, SO_PROTOCOL, SO_ACCEPTCONN");
    struct stat st;
    verifier(fstat(s, &st) == 0 && st.st_mode == (S_IFSOCK | 0777) && st.st_size == 0, "fstat : 0140777, taille 0");
    close(s);
}

static void ecoutes(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    verifier(listen(s, 5) == 0 && port_de(s) != 0, "listen sans bind : un port ephemere");
    verifier(listen(s, 5) == 0, "listen deux fois : 0");
    verifier(option(s, SOL_SOCKET, SO_ACCEPTCONN) == 1, "SO_ACCEPTCONN d'une ecoute : 1");
    struct sockaddr_in a = lo(port_de(s));
    verifier(erreur(connect(s, (void *)&a, sizeof a)) == EISCONN, "connect d'une ecoute : EISCONN");
    char b[4];
    verifier(masque(s) == 0, "poll d'une ecoute vide : 0");
    verifier(erreur(recv(s, b, 1, MSG_DONTWAIT)) == ENOTCONN && erreur(send(s, "x", 1, MSG_NOSIGNAL)) == EPIPE,
             "une ecoute : recv ENOTCONN, send EPIPE");
    struct sockaddr_in z = lo(0);
    verifier(erreur(bind(s, (void *)&z, sizeof z)) == EINVAL, "bind apres listen : EINVAL");
    fcntl(s, F_SETFL, O_NONBLOCK);
    verifier(erreur(accept(s, NULL, NULL)) == EAGAIN, "accept non bloquant, rien : EAGAIN");
    /* Un client : POLLIN, puis accept4 avec ses drapeaux. */
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&a, sizeof a);
    attendre_ms(20);
    verifier(masque(s) == POLLIN, "poll d'une ecoute avec un client : POLLIN");
    struct sockaddr_in pa;
    socklen_t l = 3;
    int x = accept4(s, (void *)&pa, &l, SOCK_NONBLOCK | SOCK_CLOEXEC);
    verifier(x >= 0 && l == 16 && (fcntl(x, F_GETFL) & O_NONBLOCK) && (fcntl(x, F_GETFD) & FD_CLOEXEC),
             "accept4 : adresse coupee a 3, longueur 16 rendue ; SOCK_NONBLOCK, SOCK_CLOEXEC");
    struct sockaddr_in ca;
    socklen_t cl = sizeof ca;
    getsockname(c, (void *)&ca, &cl);
    verifier(ntohs(ca.sin_port) % 2 == 0, "le port ephemere d'un connect : pair");
    struct sockaddr_in xa;
    socklen_t xl = sizeof xa;
    getpeername(x, (void *)&xa, &xl);
    verifier(xa.sin_port == ca.sin_port && xa.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "getpeername de l'acceptee : le client");
    close(x);
    close(c);
    close(s);
}

static void refus(void)
{
    int p = port_ferme();
    struct sockaddr_in a = lo(p);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    verifier(erreur(connect(s, (void *)&a, sizeof a)) == ECONNREFUSED && option(s, SOL_SOCKET, SO_ERROR) == 0,
             "connect vers un port ferme : ECONNREFUSED, SO_ERROR 0 ensuite");
    verifier(masque(s) == (POLLOUT | POLLHUP), "apres le refus : poll POLLOUT | POLLHUP");
    close(s);
    s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    long r = erreur(connect(s, (void *)&a, sizeof a));
    attendre_ms(20);
    int m = masque(s);
    /* La connexion morte a ses deux sens arrêtés (`tcp_done`) : POLLIN et
     * POLLRDHUP aussi. */
    verifier(r == EINPROGRESS && m == (POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDHUP),
             "connect non bloquant vers un port ferme : EINPROGRESS, puis POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDHUP");
    verifier(option(s, SOL_SOCKET, SO_ERROR) == ECONNREFUSED && option(s, SOL_SOCKET, SO_ERROR) == 0,
             "SO_ERROR : ECONNREFUSED, puis 0");
    verifier(masque(s) == (POLLIN | POLLOUT | POLLHUP | POLLRDHUP), "l'erreur lue : plus de POLLERR");
    close(s);
    /* Refusée, la socket peut se reconnecter (une écoute ouverte
     * entre-temps) ou écouter : elle est redevenue neuve
     * (`tcp_disconnect`). */
    s = socket(AF_INET, SOCK_STREAM, 0);
    int ok1 = erreur(connect(s, (void *)&a, sizeof a)) == ECONNREFUSED;
    int e2 = socket(AF_INET, SOCK_STREAM, 0), un = 1;
    setsockopt(e2, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    bind(e2, (void *)&a, sizeof a);
    listen(e2, 1);
    verifier(ok1 && connect(s, (void *)&a, sizeof a) == 0, "le meme connect refait, une ecoute ouverte entre-temps : 0");
    close(s);
    close(e2);
    s = socket(AF_INET, SOCK_STREAM, 0);
    p = port_ferme();
    a = lo(p);
    ok1 = erreur(connect(s, (void *)&a, sizeof a)) == ECONNREFUSED;
    verifier(ok1 && listen(s, 1) == 0, "listen apres un connect refuse : 0");
    close(s);
    /* Un connect non bloquant réussi : EINPROGRESS, puis 0, puis EISCONN. */
    int port, l = ecoute(&port, 5);
    a = lo(port);
    s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    r = erreur(connect(s, (void *)&a, sizeof a));
    struct pollfd pf = { s, POLLOUT, 0 };
    poll(&pf, 1, 1000);
    long r2 = erreur(connect(s, (void *)&a, sizeof a));
    long r3 = erreur(connect(s, (void *)&a, sizeof a));
    verifier((r == EINPROGRESS || r == 0) && r2 == 0 && r3 == EISCONN && option(s, SOL_SOCKET, SO_ERROR) == 0,
             "connect non bloquant : EINPROGRESS, poll POLLOUT, puis 0, puis EISCONN");
    close(s);
    close(l);
}

static void donnees(void)
{
    int c, a, n;
    char b[100];
    paire(&c, &a);
    send(c, "12345", 5, 0);
    send(c, "678", 3, 0);
    attendre_ms(20);
    verifier(ioctl(a, FIONREAD, &n) == 0 && n == 8, "FIONREAD : tout ce qui est en file (8)");
    verifier(ioctl(c, SIOCOUTQ, &n) == 0 && n == 0, "SIOCOUTQ : 0 une fois acquitte");
    verifier(recv(a, b, 2, MSG_PEEK) == 2 && recv(a, b, 100, 0) == 8 && memcmp(b, "12345678", 8) == 0,
             "MSG_PEEK laisse les octets, puis recv les prend");
    send(c, "abcd", 4, 0);
    attendre_ms(20);
    verifier(recv(a, NULL, 2, MSG_TRUNC) == 2 && ioctl(a, FIONREAD, &n) == 0 && n == 2, "MSG_TRUNC jette (2), il en reste 2");
    struct sockaddr_in x;
    socklen_t l = sizeof x;
    verifier(recvfrom(a, b, 100, 0, (void *)&x, &l) == 2 && l == 0, "recvfrom : une adresse de longueur 0");
    verifier(erreur(recv(a, b, 1, MSG_DONTWAIT)) == EAGAIN, "recv non bloquant, rien : EAGAIN");
    /* shutdown(SHUT_WR) : l'autre lit 0, peut encore écrire. */
    verifier(shutdown(c, SHUT_WR) == 0, "shutdown(SHUT_WR) : 0");
    attendre_ms(20);
    verifier(recv(a, b, 1, 0) == 0 && (masque(a) & POLLIN), "l'autre lit 0 (fin), POLLIN");
    verifier(erreur(send(c, "x", 1, MSG_NOSIGNAL)) == EPIPE, "send apres SHUT_WR : EPIPE");
    verifier(send(a, "yz", 2, 0) == 2 && (attendre_ms(20), recv(c, b, 10, 0)) == 2, "l'autre ecrit encore, et on lit");
    close(a);
    attendre_ms(20);
    verifier(recv(c, b, 10, 0) == 0 && (masque(c) & POLLHUP), "l'autre ferme : recv 0, POLLHUP");
    close(c);
    /* L'autre fermé sans qu'on ait fermé : un send passe, son RST revient,
     * puis EPIPE. */
    paire(&c, &a);
    close(a);
    attendre_ms(20);
    long s1 = send(c, "x", 1, MSG_NOSIGNAL);
    attendre_ms(20);
    int m = masque(c);
    long s2 = erreur(send(c, "x", 1, MSG_NOSIGNAL));
    verifier(s1 == 1 && (m & (POLLERR | POLLHUP)) == (POLLERR | POLLHUP) && s2 == EPIPE,
             "l'autre ferme : un send passe, son RST revient (POLLERR | POLLHUP), puis EPIPE");
    close(c);
    /* close avec des données non lues : RST, l'autre lit ECONNRESET. */
    paire(&c, &a);
    send(c, "abc", 3, 0);
    attendre_ms(20);
    close(a);
    attendre_ms(20);
    verifier(erreur(recv(c, b, 10, MSG_DONTWAIT)) == ECONNRESET, "close avec des donnees non lues : RST, ECONNRESET");
    close(c);
    /* SO_LINGER 0 : RST aussitôt. */
    paire(&c, &a);
    struct linger lg = { 1, 0 };
    setsockopt(a, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(a);
    attendre_ms(20);
    verifier(erreur(recv(c, b, 10, MSG_DONTWAIT)) == ECONNRESET, "SO_LINGER 0 : RST, ECONNRESET");
    close(c);
    /* connect(AF_UNSPEC) d'une connexion établie : RST. */
    paire(&c, &a);
    struct sockaddr sa = { .sa_family = AF_UNSPEC };
    verifier(connect(c, &sa, sizeof sa) == 0, "connect(AF_UNSPEC) d'une connexion etablie : 0");
    attendre_ms(20);
    verifier(erreur(recv(a, b, 1, MSG_DONTWAIT)) == ECONNRESET, "l'autre lit ECONNRESET");
    close(c);
    close(a);
}

/* listen(backlog) : combien de clients sont établis avant accept. */
static int etablis(int backlog, int clients)
{
    int port, l = ecoute(&port, backlog), cs[8], ok = 0;
    for (int i = 0; i < clients; i++) {
        cs[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        struct sockaddr_in x = lo(port);
        connect(cs[i], (void *)&x, sizeof x);
    }
    attendre_ms(200);
    for (int i = 0; i < clients; i++)
        if ((masque(cs[i]) & POLLOUT) && option(cs[i], SOL_SOCKET, SO_ERROR) == 0)
            ok++;
    for (int i = 0; i < clients; i++)
        close(cs[i]);
    close(l);
    return ok;
}

static void file_d_ecoute(void)
{
    verifier(etablis(0, 4) == 1, "listen(0) : un client etabli");
    verifier(etablis(2, 6) == 3, "listen(2) : trois clients etablis");
    /* Le trou noir : une écoute à la file pleine jette chaque SYN. Un
     * connect bloquant avec SO_SNDTIMEO de 300 ms : EINPROGRESS. */
    int port, l = ecoute(&port, 0);
    int c1 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c1, (void *)&x, sizeof x);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = { 0, 300000 };
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long r = erreur(connect(c, (void *)&x, sizeof x));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(r == EINPROGRESS && ms >= 290 && ms < 2000, "connect vers une ecoute pleine, SO_SNDTIMEO 300 ms : EINPROGRESS");
    verifier(masque(c) == 0 && erreur(connect(c, (void *)&x, sizeof x)) == EALREADY, "poll 0, puis connect : EALREADY");
    close(c);
    /* Les SYN sans réponse, dans le même trou noir : avec TCP_SYNCNT 1,
     * trois SYN puis ETIMEDOUT, vers 3 s (Linux 6.18 : 3,06 s). */
    int d = socket(AF_INET, SOCK_STREAM, 0);
    int un = 1;
    setsockopt(d, IPPROTO_TCP, TCP_SYNCNT, &un, sizeof un);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    r = erreur(connect(d, (void *)&x, sizeof x));
    clock_gettime(CLOCK_MONOTONIC, &t1);
    ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(r == ETIMEDOUT && ms >= 2900 && ms < 4000, "TCP_SYNCNT 1, sans reponse : ETIMEDOUT vers 3 s");
    close(d);
    close(c1);
    close(l);
}

/* Le plus petit numéro de descripteur libre. */
static int plus_petit_libre(void)
{
    int d = dup(0);
    close(d);
    return d;
}

/* accept sans descripteur libre (RLIMIT_NOFILE au plus juste) : EMFILE, et
 * la connexion reste dans la file, avec ses données, pour l'accept suivant
 * (Linux réserve le numéro avant de prendre la connexion). Une adresse de
 * retour qui faute : EFAULT, aucun descripteur installé, et la connexion
 * fermée (le client voit la fin). */
static void accept_sans_place(void)
{
    int port, l = ecoute(&port, 4);
    struct sockaddr_in x = lo(port);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&x, sizeof x);
    send(c, "abc", 3, 0);
    struct rlimit r, juste;
    getrlimit(RLIMIT_NOFILE, &r);
    juste = r;
    juste.rlim_cur = plus_petit_libre();
    setrlimit(RLIMIT_NOFILE, &juste);
    long e = erreur(accept(l, NULL, NULL));
    setrlimit(RLIMIT_NOFILE, &r);
    int a = accept4(l, NULL, NULL, SOCK_NONBLOCK);
    char b[8] = { 0 };
    long n = a >= 0 ? recv(a, b, sizeof b, 0) : -1;
    verifier(e == EMFILE && n == 3 && memcmp(b, "abc", 3) == 0, "accept sans descripteur libre : EMFILE, la connexion reste en file");
    close(a);
    close(c);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&x, sizeof x);
    int libre = plus_petit_libre();
    socklen_t lg = sizeof x;
    e = erreur(accept(l, (struct sockaddr *)8, &lg));
    attendre_ms(8);
    char o;
    long fin = recv(c, &o, 1, MSG_DONTWAIT);
    verifier(e == EFAULT && plus_petit_libre() == libre && fin == 0, "accept dont l'adresse faute : EFAULT, sans descripteur, la connexion fermee");
    close(c);
    close(l);
}

/* Des filles que leur client a déjà fermées avant l'accept : en CLOSE_WAIT
 * (sa requête puis son FIN : HTTP/1.0, une sonde de santé), poll de
 * l'écoute dit POLLIN, et accept la rend, avec la requête puis la fin ;
 * remise à zéro (SO_LINGER 0), elle reste aussi dans la file : accept la
 * rend, et sa lecture dit ECONNRESET. */
static void filles_avant_accept(void)
{
    int port, l = ecoute(&port, 4);
    fcntl(l, F_SETFL, O_NONBLOCK);
    struct sockaddr_in x = lo(port);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&x, sizeof x);
    send(c, "GET", 3, 0);
    shutdown(c, SHUT_WR);
    attendre_ms(8);
    struct pollfd p = { l, POLLIN, 0 };
    int n = poll(&p, 1, 200);
    int a = accept4(l, NULL, NULL, SOCK_NONBLOCK);
    char b[8];
    long r1 = a >= 0 ? recv(a, b, sizeof b, 0) : -1;
    long r2 = a >= 0 ? recv(a, b, sizeof b, 0) : -1;
    verifier(n == 1 && p.revents == POLLIN && r1 == 3 && r2 == 0,
             "une fille en CLOSE_WAIT avant accept : POLLIN sur l'ecoute, accept la rend, sa requete puis la fin");
    close(a);
    close(c);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&x, sizeof x);
    struct linger z = { 1, 0 };
    setsockopt(c, SOL_SOCKET, SO_LINGER, &z, sizeof z);
    close(c);
    attendre_ms(8);
    a = accept4(l, NULL, NULL, SOCK_NONBLOCK);
    long e = a >= 0 ? erreur(recv(a, b, sizeof b, 0)) : -1;
    verifier(a >= 0 && e == ECONNRESET, "une fille remise a zero avant accept : accept la rend, sa lecture dit ECONNRESET");
    close(a);
    close(l);
}

static void meme_port(void)
{
    int port, l = ecoute(&port, 1);
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = lo(port);
    verifier(bind(u, (void *)&a, sizeof a) == 0, "UDP sur le port d'une ecoute TCP : permis");
    int t = socket(AF_INET, SOCK_STREAM, 0);
    verifier(erreur(bind(t, (void *)&a, sizeof a)) == EADDRINUSE, "TCP sur le port d'une ecoute : EADDRINUSE");
    int r = 1;
    setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &r, 4);
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &r, 4);
    verifier(erreur(bind(t, (void *)&a, sizeof a)) == EADDRINUSE, "meme avec SO_REUSEADDR des deux cotes : EADDRINUSE");
    close(t);
    close(u);
    close(l);
}

/* Le chemin de Bun : un connect non bloquant, epoll EPOLLOUT, SO_ERROR,
 * puis EPOLLIN | EPOLLET : un réveil à chaque arrivée. */
static void comme_bun(void)
{
    int port, l = ecoute(&port, 1);
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = lo(port);
    long r = erreur(connect(s, (void *)&a, sizeof a));
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event e = { .events = EPOLLOUT, .data.fd = s }, sortie[4];
    epoll_ctl(ep, EPOLL_CTL_ADD, s, &e);
    int n = epoll_wait(ep, sortie, 4, 1000);
    verifier((r == EINPROGRESS || r == 0) && n == 1 && (sortie[0].events & EPOLLOUT) && option(s, SOL_SOCKET, SO_ERROR) == 0,
             "connect non bloquant, epoll EPOLLOUT, SO_ERROR 0");
    int x = accept(l, NULL, NULL);
    e.events = EPOLLIN | EPOLLET;
    epoll_ctl(ep, EPOLL_CTL_MOD, s, &e);
    send(x, "a", 1, 0);
    int n1 = epoll_wait(ep, sortie, 4, 1000);
    send(x, "b", 1, 0);
    int n2 = epoll_wait(ep, sortie, 4, 1000);
    int n3 = epoll_wait(ep, sortie, 4, 50);
    char b[8];
    verifier(n1 == 1 && n2 == 1 && n3 == 0 && recv(s, b, 8, MSG_DONTWAIT) == 2,
             "EPOLLIN | EPOLLET : un reveil par arrivee, meme sans lecture entre les deux");
    close(ep);
    close(x);
    close(s);
    close(l);
}

/* Deux fils qui s'échangent 1 Mio, par morceaux de tailles variées. */
#define TOTAL (1 << 20)
static int echo_fd;

static void *echo(void *arg)
{
    (void)arg;
    static char b[65536];
    long n;
    while ((n = recv(echo_fd, b, sizeof b, 0)) > 0) {
        long fait = 0;
        while (fait < n) {
            long k = send(echo_fd, b + fait, n - fait, 0);
            if (k <= 0)
                return NULL;
            fait += k;
        }
    }
    shutdown(echo_fd, SHUT_WR);
    return NULL;
}

static void *ecrivain(void *arg)
{
    int s = *(int *)arg;
    static unsigned char b[TOTAL];
    for (int i = 0; i < TOTAL; i++)
        b[i] = (unsigned char)(i * 7 + (i >> 8));
    long fait = 0;
    int pas = 1;
    while (fait < TOTAL) {
        long n = TOTAL - fait < pas ? TOTAL - fait : pas;
        long k = send(s, b + fait, n, 0);
        if (k <= 0)
            break;
        fait += k;
        pas = pas * 3 % 50000 + 1;
    }
    shutdown(s, SHUT_WR);
    return NULL;
}

static void aller_retour(void)
{
    int c, a;
    paire(&c, &a);
    echo_fd = a;
    pthread_t f1, f2;
    pthread_create(&f1, NULL, echo, NULL);
    pthread_create(&f2, NULL, ecrivain, &c);
    static unsigned char r[TOTAL];
    long recu = 0, n;
    while ((n = recv(c, r + recu, TOTAL - recu < 30000 ? TOTAL - recu : 30000, 0)) > 0)
        recu += n;
    pthread_join(f1, NULL);
    pthread_join(f2, NULL);
    int bon = recu == TOTAL;
    for (int i = 0; bon && i < TOTAL; i++)
        bon = r[i] == (unsigned char)(i * 7 + (i >> 8));
    verifier(bon, "deux fils s'echangent 1 Mio en aller-retour, tout arrive dans l'ordre");
    close(c);
    close(a);
}

/* Les options de SOL_SOCKET et les tampons que l'écoute avait, sa fille
 * acceptée les a (`sk_clone_lock`). */
static void heritage(void)
{
    int port, l = ecoute(&port, 1);
    int v = 65536, un = 1;
    setsockopt(l, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    setsockopt(l, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    setsockopt(l, SOL_SOCKET, SO_KEEPALIVE, &un, sizeof un);
    setsockopt(l, SOL_SOCKET, SO_OOBINLINE, &un, sizeof un);
    struct linger li = { 1, 7 };
    setsockopt(l, SOL_SOCKET, SO_LINGER, &li, sizeof li);
    struct timeval tv = { 3, 0 };
    setsockopt(l, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    struct linger lf = { 0, 0 };
    struct timeval tf = { 0, 0 };
    socklen_t ll = sizeof lf, lt = sizeof tf;
    getsockopt(a, SOL_SOCKET, SO_LINGER, &lf, &ll);
    getsockopt(a, SOL_SOCKET, SO_RCVTIMEO, &tf, &lt);
    verifier(option(a, SOL_SOCKET, SO_SNDBUF) == 131072 && option(a, SOL_SOCKET, SO_RCVBUF) == 131072,
             "la fille acceptee : SO_SNDBUF et SO_RCVBUF de l'ecoute (65536, doubles)");
    verifier(option(a, SOL_SOCKET, SO_KEEPALIVE) == 1 && option(a, SOL_SOCKET, SO_OOBINLINE) == 1 && lf.l_onoff == 1
             && lf.l_linger == 7 && tf.tv_sec == 3, "la fille acceptee : SO_KEEPALIVE, SO_OOBINLINE, SO_LINGER, SO_RCVTIMEO de l'ecoute");
    close(a);
    close(c);
    close(l);
}

/* TCP_LINGER2 (0 se relit 60, borné à 120) et TCP_DEFER_ACCEPT (gardé en
 * retransmissions : 5 s se relisent 7). */
static void options_de_linux(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int v = 100;
    setsockopt(s, IPPROTO_TCP, TCP_LINGER2, &v, sizeof v);
    int l2 = option(s, IPPROTO_TCP, TCP_LINGER2);
    v = 0;
    setsockopt(s, IPPROTO_TCP, TCP_LINGER2, &v, sizeof v);
    int l0 = option(s, IPPROTO_TCP, TCP_LINGER2);
    v = 5;
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &v, sizeof v);
    verifier(l2 == 100 && l0 == 60 && option(s, IPPROTO_TCP, TCP_DEFER_ACCEPT) == 7,
             "TCP_LINGER2 100 puis 0 : 100, 60 ; TCP_DEFER_ACCEPT 5 : 7");
    close(s);
}

/* Fermée par le programme (close : plus personne ne lit), une connexion en
 * FIN_WAIT_1 (son FIN retenu derrière ce que l'autre ne lit pas) coupe
 * par RST ce que l'autre lui envoie encore (RFC 1122 4.2.2.13) : l'autre
 * finit par lire ECONNRESET. Et un send pendant la poignée de main attend
 * qu'elle aboutisse, en dormant. */
static void orpheline_et_poignee(void)
{
    int c, a;
    paire(&c, &a);
    int petit = 4096;
    setsockopt(c, SOL_SOCKET, SO_RCVBUF, &petit, sizeof petit);
    fcntl(a, F_SETFL, O_NONBLOCK);
    static char gros[65536];
    while (send(a, gros, sizeof gros, 0) > 0)
        ;
    close(a);
    attendre_ms(20);
    send(c, "y", 1, 0);
    attendre_ms(20);
    long e = 0;
    char b[65536];
    for (int i = 0; i < 1000; i++) {
        long n = recv(c, b, sizeof b, MSG_DONTWAIT);
        if (n < 0) {
            e = errno;
            if (e != EAGAIN)
                break;
            attendre_ms(4);
        } else if (n == 0) {
            break;
        }
    }
    verifier(e == ECONNRESET, "des donnees vers une connexion fermee en FIN_WAIT_1 : RST, l'autre lit ECONNRESET");
    close(c);
    /* Le trou noir de lo (une écoute pleine) : un connect non bloquant, puis
     * un send bloquant (SO_SNDTIMEO 300 ms) qui attend la fin de la poignée
     * de main : EAGAIN, sans brûler le processeur. */
    int port, l = ecoute(&port, 0);
    struct sockaddr_in x = lo(port);
    int c1 = socket(AF_INET, SOCK_STREAM, 0);
    connect(c1, (void *)&x, sizeof x);
    int d = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    connect(d, (void *)&x, sizeof x);
    fcntl(d, F_SETFL, 0);
    struct timeval tv = { 0, 300000 };
    setsockopt(d, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct timespec t0, t1;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t0);
    long r = erreur(send(d, "z", 1, 0));
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(r == EAGAIN && ms < 100, "send pendant la poignee de main : il attend en dormant, puis EAGAIN");
    close(d);
    close(c1);
    close(l);
}

static int suite_fd;

/* La suite, 100 ms plus tard. */
static void *envoyer_la_suite(void *arg)
{
    (void)arg;
    static char suite[100];
    attendre_ms(100);
    send(suite_fd, suite, sizeof suite, 0);
    return NULL;
}

/* Une copie qui faute après des octets déjà pris rend ceux-là, pas
 * EFAULT : un recv(MSG_WAITALL) de deux pages, dont la seconde n'existe
 * pas, reçoit une page, attend la suite, qui faute. (Arrivée avant le
 * recv, Linux l'aurait collée à la page dans un même paquet, et la copie
 * aurait fauté avant d'avoir rien pris : EFAULT.) */
static void faute(void)
{
    int c, a;
    paire(&c, &a);
    long page = sysconf(_SC_PAGESIZE);
    char *z = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(z + page, page);
    static char donnees[8192];
    send(c, donnees, page, 0);
    attendre_ms(20);
    suite_fd = c;
    pthread_t t;
    pthread_create(&t, NULL, envoyer_la_suite, NULL);
    long r = recv(a, z, 2 * page, MSG_WAITALL);
    pthread_join(t, NULL);
    verifier(r == page, "une copie qui faute apres une page deja prise : recv rend la page, pas EFAULT");
    munmap(z, page);
    close(c);
    close(a);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    neuve();
    ecoutes();
    refus();
    donnees();
    file_d_ecoute();
    accept_sans_place();
    filles_avant_accept();
    meme_port();
    comme_bun();
    aller_retour();
    heritage();
    options_de_linux();
    orpheline_et_poignee();
    faute();
    printf("[linux] tcp : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
