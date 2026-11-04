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
 *     comme Bun ; deux fils qui s'échangent 1 Mio en aller-retour ;
 *   - l'octet urgent (MSG_OOB : POLLPRI, lu à part, sauté dans le flux,
 *     SIOCATMARK) ; SO_SNDBUF agrandi à l'établissement, puis plein sans
 *     lecteur (EAGAIN, poll 0) ; SO_LINGER d'une seconde (close attend) ;
 *     le keepalive court sur une connexion vivante ; TCP_INFO ;
 *     /proc/net/tcp (l'écoute, comme la lisent ss et netstat) ; 64 Mio
 *     d'un fil à l'autre, la somme vérifiée (le débit affiché, sans être
 *     comparé) ;
 *   - les horodatages sur lo (advmss 65 483), TCP_MAXSEG dans le SYN, et
 *     un `connect` qui reprend le quadruplet d'un TIME_WAIT.
 *   - TCP_CONGESTION (cubic, reno, les refus, l'héritage par une fille) ;
 *     le débit calculé (`tcpi_pacing_rate`) ; SO_SNDBUF qui ne grandit que pour
 *     un programme qui attend de la place ;
 *   - la réception qui s'ajuste : les fenêtres du SYN et du SYN-ACK, SO_RCVBUF qui
 *     suit le débit, TCP_WINDOW_CLAMP, SO_RCVLOWAT ;
 *   - TCP_DEFER_ACCEPT, et /proc/sys/net.
 * Rien ne compare de valeur qui dépend de la configuration de Linux (le
 * MSS sur lo, SO_SNDBUF agrandi). Sur l'hôte comme chez nous. Les délais sont
 * des multiples de 4 ms (le tic de l'hôte : HZ = 250).
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

static void urgent(void)
{
    int c, a;
    char b[16];
    paire(&c, &a);
    verifier(erreur(recv(a, b, 1, MSG_OOB)) == EINVAL, "recv(MSG_OOB) sans donnee urgente : EINVAL");
    verifier(send(c, "abc", 3, MSG_OOB) == 3, "send(MSG_OOB) : 3");
    attendre_ms(20);
    struct pollfd p = { a, POLLPRI, 0 };
    verifier(poll(&p, 1, 0) == 1 && (p.revents & POLLPRI), "l'autre : POLLPRI");
    verifier(recv(a, b, 1, MSG_OOB) == 1 && b[0] == 'c', "recv(MSG_OOB) : l'octet urgent");
    int marque = -1;
    long n = recv(a, b, 16, 0);
    ioctl(a, SIOCATMARK, &marque);
    verifier(n == 2 && memcmp(b, "ab", 2) == 0 && marque == 1, "le flux s'arrete a la marque (ab), SIOCATMARK 1");
    send(c, "de", 2, 0);
    attendre_ms(20);
    n = recv(a, b, 16, 0);
    verifier(n == 2 && memcmp(b, "de", 2) == 0, "l'octet urgent n'est pas dans le flux");
    /* Seul l'octet urgent en file : rien à lire (EAGAIN), pas la fin du
     * flux ; avant comme après recv(MSG_OOB). */
    send(c, "x", 1, MSG_OOB);
    attendre_ms(20);
    long e1 = erreur(recv(a, b, 16, MSG_DONTWAIT));
    recv(a, b, 1, MSG_OOB);
    send(c, "y", 1, MSG_OOB);
    attendre_ms(20);
    recv(a, b, 1, MSG_OOB);
    long e2 = erreur(recv(a, b, 16, MSG_DONTWAIT));
    verifier(e1 == EAGAIN && e2 == EAGAIN, "seul l'octet urgent en file : recv rend EAGAIN, pas la fin");
    close(c);
    close(a);
    /* FIONREAD s'arrête à la marque (`tcp_inq`). */
    paire(&c, &a);
    send(c, "ab", 2, 0);
    send(c, "c", 1, MSG_OOB);
    attendre_ms(20);
    int avant = -1, apres = -1;
    ioctl(a, FIONREAD, &avant);
    recv(a, b, 16, 0);
    ioctl(a, FIONREAD, &apres);
    verifier(avant == 2 && apres == 0, "FIONREAD : les octets avant la marque (2), puis 0");
    close(c);
    close(a);
}

/* SO_SNDBUF grandit à l'établissement (Linux : 2 626 560 sur lo, une
 * valeur qui dépend du MSS : seule sa croissance est comparée) ; sans
 * lecteur, les envois finissent par EAGAIN, et poll ne dit plus POLLOUT. */
static void sans_lecteur(void)
{
    int c, a;
    paire(&c, &a);
    int sndbuf = option(c, SOL_SOCKET, SO_SNDBUF);
    verifier(sndbuf > 16384, "SO_SNDBUF agrandi a l'etablissement");
    static char b[65536];
    long envois = 0, r;
    while ((r = send(c, b, sizeof b, MSG_DONTWAIT)) > 0)
        envois++;
    verifier(envois > 0 && errno == EAGAIN && (masque(c) & POLLOUT) == 0, "sans lecteur : des envois, puis EAGAIN, poll sans POLLOUT");
    /* SO_LINGER d'une seconde : close attend que tout soit acquitté, en
     * vain (l'autre ne lit pas), une seconde. */
    struct linger lg = { 1, 1 };
    setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int f = close(c);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(f == 0 && ms >= 900 && ms < 3000, "SO_LINGER 1 s, rien d'acquitte : close attend 1 s");
    close(a);
}

/* Le keepalive sur une connexion vivante : sondée chaque seconde, elle
 * répond, et reste. TCP_INFO : l'état, le RTO, la fenêtre de
 * congestion. */
static void keepalive_et_info(void)
{
    int c, a, un = 1;
    paire(&c, &a);
    setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &un, sizeof un);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPIDLE, &un, sizeof un);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPINTVL, &un, sizeof un);
    setsockopt(c, IPPROTO_TCP, TCP_KEEPCNT, &un, sizeof un);
    attendre_ms(2500);
    char b[4];
    verifier(option(c, SOL_SOCKET, SO_ERROR) == 0 && send(c, "k", 1, 0) == 1 && recv(a, b, 4, 0) == 1,
             "keepalive d'une seconde, l'autre repond : la connexion reste");
    struct tcp_info i;
    socklen_t l = sizeof i;
    memset(&i, 0, sizeof i);
    verifier(getsockopt(c, IPPROTO_TCP, TCP_INFO, &i, &l) == 0 && i.tcpi_state == 1 && i.tcpi_rto >= 200000 && i.tcpi_snd_cwnd > 0 &&
             i.tcpi_snd_mss > 0, "TCP_INFO : etablie, RTO de 200 ms au moins, une fenetre de congestion");
    close(c);
    close(a);
}

/* /proc/net/tcp : la ligne de l'écoute (état 0A), le port en hexadécimal. */
static void proc_net_tcp(void)
{
    int port, l = ecoute(&port, 1);
    FILE *f = fopen("/proc/net/tcp", "r");
    char ligne[256], cherche[32];
    snprintf(cherche, sizeof cherche, ":%04X 00000000:0000 0A", port);
    int trouve = 0, entete = 0;
    if (f) {
        if (fgets(ligne, sizeof ligne, f))
            entete = strncmp(ligne, "  sl  local_address rem_address   st tx_queue rx_queue", 54) == 0;
        while (fgets(ligne, sizeof ligne, f))
            trouve |= strstr(ligne, cherche) != NULL;
        fclose(f);
    }
    verifier(entete && trouve, "/proc/net/tcp : l'en-tete, et l'ecoute (etat 0A)");
    close(l);
}

/* 64 Mio d'un fil à l'autre, par morceaux de tailles variées, la somme
 * vérifiée ; le débit est affiché (il change d'une machine à l'autre). */
#define GROS (64 << 20)
static int gros_fd;

static void *gros_ecrivain(void *arg)
{
    (void)arg;
    static unsigned char b[65536];
    long fait = 0;
    int pas = 1000;
    while (fait < GROS) {
        long n = GROS - fait < pas ? GROS - fait : pas;
        for (long k = 0; k < n; k++)
            b[k] = (unsigned char)((fait + k) * 13 + ((fait + k) >> 12));
        long r = send(gros_fd, b, n, 0);
        if (r <= 0)
            break;
        fait += r;
        pas = pas * 7 % 65536 + 1;
    }
    shutdown(gros_fd, SHUT_WR);
    return NULL;
}

static void debit(void)
{
    int c, a;
    paire(&c, &a);
    gros_fd = c;
    pthread_t f;
    pthread_create(&f, NULL, gros_ecrivain, NULL);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    static unsigned char b[131072];
    long recu = 0, n;
    int bon = 1;
    while ((n = recv(a, b, sizeof b, 0)) > 0) {
        for (long k = 0; bon && k < n; k++)
            bon = b[k] == (unsigned char)((recu + k) * 13 + ((recu + k) >> 12));
        recu += n;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    pthread_join(f, NULL);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    verifier(bon && recu == GROS, "64 Mio d'un fil a l'autre, chaque octet a sa place");
    printf("[linux] tcp : 64 Mio en %ld ms (%ld Mio/s)\n", ms, ms ? 64000 / ms : 0);
    close(c);
    close(a);
}

/* SO_RCVLOWAT (`sock_rcvlowat`, `tcp_epollin_ready`) : poll attend le
 * seuil, et recv aussi. */
static void seuil(void)
{
    int c, a;
    paire(&c, &a);
    int dix = 10;
    setsockopt(a, SOL_SOCKET, SO_RCVLOWAT, &dix, sizeof dix);
    send(c, "12345", 5, 0);
    attendre_ms(20);
    struct pollfd p = { a, POLLIN, 0 };
    int n0 = poll(&p, 1, 0);
    send(c, "67890", 5, 0);
    attendre_ms(20);
    int n1 = poll(&p, 1, 0);
    char b[64];
    long r = recv(a, b, sizeof b, 0);
    verifier(n0 == 0 && n1 == 1 && r == 10, "SO_RCVLOWAT 10 : poll 0 a 5 octets, 1 a 10, recv 10");
    close(c);
    close(a);
}

/* Une connexion fermée d'un côté puis de l'autre, en TIME_WAIT : TCP_INFO
 * dit TCP_CLOSE (7) pour la socket que le programme tient encore. */
static void info_en_time_wait(void)
{
    int c, a;
    paire(&c, &a);
    shutdown(c, SHUT_WR);
    attendre_ms(20);
    close(a);
    attendre_ms(20);
    struct tcp_info i;
    socklen_t li = sizeof i;
    getsockopt(c, IPPROTO_TCP, TCP_INFO, &i, &li);
    verifier(i.tcpi_state == 7, "une connexion en TIME_WAIT, vue de sa socket : TCP_INFO dit TCP_CLOSE (7)");
    close(c);
}

/* L'échelle de fenêtre proposée (`tcp_select_initial_window`) : avec
 * SO_RCVBUF fixé, celle de sa moitié, ilog2 - 15 ; sans, celle de
 * `tcp_rmem[2]`, qui dépend de la mémoire de la machine, et au moins celle
 * de SO_RCVBUF. Linux 6.18 : 5 avec 1 Mio demandé (rmem_max vaut 4 Mio), 10
 * sans sur l'hôte (12 Gio) ; nous, 5 aussi, et 8 sans (2 Gio). */
static void echelle(void)
{
    for (int fixe = 0; fixe <= 1; fixe++) {
        int port, l = ecoute(&port, 1);
        int c = socket(AF_INET, SOCK_STREAM, 0);
        int v = 1 << 20;
        if (fixe)
            setsockopt(c, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
        struct sockaddr_in x = lo(port);
        connect(c, (void *)&x, sizeof x);
        int a = accept(l, NULL, NULL);
        struct tcp_info i;
        socklen_t li = sizeof i;
        getsockopt(c, IPPROTO_TCP, TCP_INFO, &i, &li);
        int bits = 0;
        for (int place = option(c, SOL_SOCKET, SO_RCVBUF) / 2; place > 1; place >>= 1)
            bits++;
        int attendue = bits - 15 < 0 ? 0 : bits - 15 > 14 ? 14 : bits - 15;
        if (fixe)
            verifier((i.tcpi_options & TCPI_OPT_WSCALE) && i.tcpi_rcv_wscale == attendue,
                     "SO_RCVBUF fixe : l'echelle de sa moitie, ilog2 - 15");
        else
            verifier((i.tcpi_options & TCPI_OPT_WSCALE) && i.tcpi_rcv_wscale >= attendue && i.tcpi_rcv_wscale >= 7,
                     "sans SO_RCVBUF : l'echelle de la machine (tcp_rmem[2]), au moins 7");
        close(a);
        close(c);
        close(l);
    }
}

/* Les horodatages sur lo (mesuré sur l'hôte) : TCPI_OPT_TIMESTAMPS, et 12
 * octets de moins à ce qu'on dit pouvoir recevoir (advmss 65 483, sa MTU 65 535
 * reste) ; le MSS lu vaut au plus advmss. TCP_MAXSEG borne le MSS d'un côté
 * et de l'autre (`tcp_mss_clamp` : l'option du SYN). */
static void horodatages(void)
{
    int port, l = ecoute(&port, 1);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    struct tcp_info i, j;
    socklen_t li = sizeof i;
    getsockopt(c, IPPROTO_TCP, TCP_INFO, &i, &li);
    getsockopt(a, IPPROTO_TCP, TCP_INFO, &j, &li);
    verifier((i.tcpi_options & TCPI_OPT_TIMESTAMPS) && (j.tcpi_options & TCPI_OPT_TIMESTAMPS), "lo : les horodatages en service, des deux cotes");
    verifier(i.tcpi_advmss == 65483 && j.tcpi_advmss == 65483 && i.tcpi_pmtu == 65535, "lo : advmss 65 483 (12 octets pour l'option), MTU 65 535");
    verifier(option(c, IPPROTO_TCP, TCP_MAXSEG) <= 65483 && option(a, IPPROTO_TCP, TCP_MAXSEG) <= 65483, "lo : TCP_MAXSEG au plus 65 483");
    verifier((i.tcpi_options & TCPI_OPT_SACK) && (j.tcpi_options & TCPI_OPT_SACK), "lo : SACK en service, des deux cotes");
    verifier(i.tcpi_sacked == 0 && i.tcpi_lost == 0 && i.tcpi_retrans == 0 && i.tcpi_reordering == 3, "lo, sans perte : rien de SACKe, ni perdu, ni renvoye ; reordering 3");
    /* De quoi mesurer : un aller-retour, et son plus petit RTT. La suite de
     * `struct tcp_info` (Linux 6.18, 248 octets) n'est pas dans l'en-tête de
     * la glibc : lue à ses décalages. */
    char o;
    verifier(write(c, "x", 1) == 1 && read(a, &o, 1) == 1 && write(a, "y", 1) == 1 && read(c, &o, 1) == 1, "un aller-retour");
    attendre_ms(20);
    unsigned char b[248];
    socklen_t lb = sizeof b;
    getsockopt(c, IPPROTO_TCP, TCP_INFO, b, &lb);
    uint32_t min_rtt, delivered, snd_wnd;
    uint64_t bytes_acked;
    memcpy(&min_rtt, b + 148, 4);
    memcpy(&delivered, b + 192, 4);
    memcpy(&snd_wnd, b + 228, 4);
    memcpy(&bytes_acked, b + 120, 8);
    verifier(lb >= 232 && min_rtt > 0 && min_rtt != ~0u && bytes_acked >= 1 && delivered >= 1 && snd_wnd > 0,
             "TCP_INFO, la suite : min_rtt, bytes_acked, delivered, snd_wnd");
    close(a);
    close(c);
    int v = 1000;
    c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, IPPROTO_TCP, TCP_MAXSEG, &v, sizeof v);
    connect(c, (void *)&x, sizeof x);
    a = accept(l, NULL, NULL);
    verifier(option(c, IPPROTO_TCP, TCP_MAXSEG) == 988 && option(a, IPPROTO_TCP, TCP_MAXSEG) == 988,
             "TCP_MAXSEG 1000 avant connect : annonce dans le SYN ; 988 lu des deux cotes, sans l'option");
    close(a);
    close(c);
    close(l);
}

/* Reprendre le quadruplet d'un TIME_WAIT (`tcp_twsk_unique`) : un `connect`
 * d'une socket liée par `bind` au même port, avec SO_REUSEADDR ici et sur
 * l'ancienne, passe tout de suite (les horodatages protègent la neuve ; sans
 * délai, et sans `tcp_tw_reuse`, pour un port déjà lié) ; d'une socket sans
 * SO_REUSEADDR, `bind` refuse. */
static void reprise_time_wait(void)
{
    int port, l = ecoute(&port, 4), v = 1;
    struct sockaddr_in x = lo(port), moi = lo(0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
    bind(c, (void *)&moi, sizeof moi);
    socklen_t lm = sizeof moi;
    getsockname(c, (void *)&moi, &lm);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    /* Le client ferme le premier : TIME_WAIT de son côté. */
    close(c);
    attendre_ms(20);
    close(a);
    attendre_ms(20);
    c = socket(AF_INET, SOCK_STREAM, 0);
    verifier(erreur(bind(c, (void *)&moi, sizeof moi)) == EADDRINUSE, "le port d'un TIME_WAIT, sans SO_REUSEADDR : EADDRINUSE");
    close(c);
    c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, SOL_SOCKET, SO_REUSEADDR, &v, sizeof v);
    verifier(bind(c, (void *)&moi, sizeof moi) == 0, "le port d'un TIME_WAIT, avec SO_REUSEADDR : bind passe");
    verifier(connect(c, (void *)&x, sizeof x) == 0, "le meme quadruplet que le TIME_WAIT : connect le reprend, tout de suite");
    a = accept(l, NULL, NULL);
    verifier(a >= 0 && write(c, "x", 1) == 1, "et la connexion neuve marche");
    char o;
    verifier(read(a, &o, 1) == 1 && o == 'x', "et ce qu'elle envoie arrive");
    close(a);
    close(c);
    close(l);
}

/* TCP_CONGESTION (`tcp_set_congestion_control`, mesuré) : le nom sur 16 octets
 * complétés de zéros, ou coupé à la longueur demandée, sans zéro final ; à
 * l'écriture, 15 octets au plus, jusqu'au premier zéro ; un nom inconnu, ENOENT ;
 * sans longueur, EINVAL. Une fille prend le contrôle de son écoute, s'il a été
 * choisi par le programme. Sur l'hôte comme chez nous, cubic par défaut. */
static void lire_controle(int s, char *nom)
{
    socklen_t ln = 16;
    memset(nom, 0, 16);
    getsockopt(s, IPPROTO_TCP, TCP_CONGESTION, nom, &ln);
}

static void congestion(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    char nom[32];
    socklen_t ln = sizeof nom;
    memset(nom, 'x', sizeof nom);
    verifier(getsockopt(s, IPPROTO_TCP, TCP_CONGESTION, nom, &ln) == 0 && ln == 16 && strcmp(nom, "cubic") == 0 && nom[15] == 0 && nom[16] == 'x',
             "TCP_CONGESTION : cubic, sur 16 octets");
    ln = 4;
    memset(nom, 'x', sizeof nom);
    verifier(getsockopt(s, IPPROTO_TCP, TCP_CONGESTION, nom, &ln) == 0 && ln == 4 && memcmp(nom, "cubi", 4) == 0 && nom[4] == 'x',
             "TCP_CONGESTION lu sur 4 octets : cubi, sans zero final");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, "nimporte", 8)) == ENOENT, "TCP_CONGESTION : un nom inconnu, ENOENT");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, "", 1)) == ENOENT, "TCP_CONGESTION : un nom vide, ENOENT");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, "reno", 0)) == EINVAL, "TCP_CONGESTION : sans longueur, EINVAL");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, "cubic", 5)) == 0, "TCP_CONGESTION : le meme, 0");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, "renoXYZ", 4)) == 0, "TCP_CONGESTION : coupe a sa longueur, reno");
    lire_controle(s, nom);
    verifier(strcmp(nom, "reno") == 0, "TCP_CONGESTION relu : reno");
    verifier(erreur(setsockopt(s, IPPROTO_TCP, TCP_CONGESTION, "cubic\0zz", 8)) == 0, "TCP_CONGESTION : jusqu'au premier zero");
    lire_controle(s, nom);
    verifier(strcmp(nom, "cubic") == 0, "TCP_CONGESTION relu : cubic");
    /* Une écoute en reno : sa fille aussi, le client garde le sien. */
    int port, l = ecoute(&port, 2);
    setsockopt(l, IPPROTO_TCP, TCP_CONGESTION, "reno", 4);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    lire_controle(a, nom);
    verifier(strcmp(nom, "reno") == 0, "la fille d'une ecoute en reno : reno");
    lire_controle(c, nom);
    verifier(strcmp(nom, "cubic") == 0, "le client : cubic");
    /* Il change en route. */
    verifier(erreur(setsockopt(c, IPPROTO_TCP, TCP_CONGESTION, "reno", 4)) == 0, "TCP_CONGESTION sur une connexion etablie");
    lire_controle(c, nom);
    verifier(strcmp(nom, "reno") == 0, "relu : reno");
    close(a);
    close(c);
    close(l);
    close(s);
}

/* Le débit calculé (`tcp_update_pacing_rate`, `tcpi_pacing_rate`) : l'infini sur
 * une socket neuve ; dès le premier ACK : MSS × cwnd / SRTT, à 200 % ; et de même
 * pour la fille. Les décalages, comme plus haut. SRTT lu en µs, arrondi par Linux,
 * d'où la marge. */
static uint64_t debit_de(int s, uint32_t *srtt, uint32_t *cwnd, uint32_t *ssthresh, uint32_t *mss, uint64_t *max)
{
    unsigned char b[248];
    socklen_t lb = sizeof b;
    uint64_t r = 0;
    getsockopt(s, IPPROTO_TCP, TCP_INFO, b, &lb);
    memcpy(&r, b + 104, 8);
    memcpy(max, b + 112, 8);
    memcpy(srtt, b + 68, 4);
    memcpy(ssthresh, b + 76, 4);
    memcpy(cwnd, b + 80, 4);
    memcpy(mss, b + 16, 4);
    return r;
}

/* MSS × cwnd × 200 % / SRTT, à 15 % près : Linux divise par SRTT × 8, que TCP_INFO
 * arrondit. */
static int debit_attendu(uint64_t debit, uint32_t mss, uint32_t cwnd, uint32_t srtt)
{
    uint64_t attendu = (uint64_t)mss * 80000 * 200 * cwnd / (8ULL * srtt);
    return debit > attendu - attendu * 15 / 100 && debit < attendu + attendu * 15 / 100;
}

static void debit_calcule(void)
{
    uint32_t srtt, cwnd, ssthresh, mss;
    uint64_t max;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    uint64_t d = debit_de(s, &srtt, &cwnd, &ssthresh, &mss, &max);
    verifier(d == ~0ULL && max == ~0ULL, "tcpi_pacing_rate d'une socket neuve : ~0");
    /* TCP_INFO sans connexion : les valeurs de départ ; une écoute : presque rien,
     * les filles prêtes et sa file à la place de tcpi_unacked et tcpi_sacked. */
    struct tcp_info i;
    socklen_t li = sizeof i;
    getsockopt(s, IPPROTO_TCP, TCP_INFO, &i, &li);
    verifier(i.tcpi_state == 7 && i.tcpi_rto == 1000000 && i.tcpi_snd_mss == 536 && i.tcpi_rttvar == 250000 && i.tcpi_snd_ssthresh == 0x7fffffff
             && i.tcpi_snd_cwnd == 10 && i.tcpi_reordering == 3 && i.tcpi_rtt == 0, "TCP_INFO d'une socket neuve");
    close(s);
    int port, l = ecoute(&port, 2);
    d = debit_de(l, &srtt, &cwnd, &ssthresh, &mss, &max);
    getsockopt(l, IPPROTO_TCP, TCP_INFO, &i, &li);
    verifier(d == ~0ULL && i.tcpi_state == 10 && i.tcpi_rto == 0 && i.tcpi_unacked == 0 && i.tcpi_sacked == 2 && i.tcpi_snd_cwnd == 10 && i.tcpi_reordering == 3,
             "TCP_INFO d'une ecoute, sans fille : sa file dans tcpi_sacked");
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    /* (Le dernier ACK de la poignée de main arrive par lo avant que connect rende,
     * chez Linux comme chez nous.) */
    getsockopt(l, IPPROTO_TCP, TCP_INFO, &i, &li);
    verifier(i.tcpi_unacked == 1 && i.tcpi_sacked == 2, "une fille prete : tcpi_unacked 1");
    int a = accept(l, NULL, NULL);
    d = debit_de(c, &srtt, &cwnd, &ssthresh, &mss, &max);
    verifier(srtt > 0 && cwnd == 10 && max == ~0ULL && debit_attendu(d, mss, cwnd, srtt), "tcpi_pacing_rate apres connect : MSS x cwnd / SRTT, a 200 %");
    d = debit_de(a, &srtt, &cwnd, &ssthresh, &mss, &max);
    verifier(srtt > 0 && cwnd == 10 && debit_attendu(d, mss, cwnd, srtt), "tcpi_pacing_rate de la fille : de meme");
    char o;
    verifier(write(c, "x", 1) == 1 && read(a, &o, 1) == 1 && write(a, "y", 1) == 1 && read(c, &o, 1) == 1, "un aller-retour");
    d = debit_de(c, &srtt, &cwnd, &ssthresh, &mss, &max);
    verifier(srtt > 0 && debit_attendu(d, mss, cwnd, srtt), "tcpi_pacing_rate apres un ACK de donnees : de meme");
    close(a);
    close(c);
    close(l);
}

/* SO_SNDBUF ne grandit que pour un programme qui attend de la place
 * (`tcp_check_space`, SOCK_NOSPACE) : des envois qui tiennent ne le changent
 * pas, même lus et acquittés ; remplir le tampon, puis tout lire, oui. Avec un
 * petit MSS, pour que le tampon ait de la marge sous `tcp_wmem[2]`. */
static void sndbuf_seulement_si_plein(void)
{
    int port, l = ecoute(&port, 1), v = 1000;
    int c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, IPPROTO_TCP, TCP_MAXSEG, &v, sizeof v);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    close(l);
    int depart = option(c, SOL_SOCKET, SO_SNDBUF);
    static char b[1 << 20];
    int ok = 1;
    for (int i = 0; i < 64; i++)
        ok &= write(c, b, 100) == 100 && read(a, b, 100) == 100;
    attendre_ms(20);
    verifier(ok && option(c, SOL_SOCKET, SO_SNDBUF) == depart, "SO_SNDBUF inchange par des envois qui tiennent");
    long total = 0, r;
    while ((r = send(c, b, sizeof b, MSG_DONTWAIT)) > 0)
        total += r;
    verifier(total > 0 && errno == EAGAIN, "le tampon plein : EAGAIN");
    while (total > 0 && (r = read(a, b, sizeof b)) > 0)
        total -= r;
    attendre_ms(20);
    int apres = option(c, SOL_SOCKET, SO_SNDBUF);
    printf("[linux] tcp : SO_SNDBUF %d, puis %d une fois plein\n", depart, apres);
    verifier(total == 0 && apres > depart, "le programme a attendu de la place : SO_SNDBUF grandit");
    close(a);
    close(c);
}

/* La réception qui s'ajuste : la fenêtre du SYN (`tcp_select_initial_window`), vue
 * de l'autre côté : 65 495 (65 536 arrondis au MSS annoncé), 65 483 pour la fille ;
 * SO_RCVBUF qui suit le débit d'un programme qui lit, `tcpi_rcv_ssthresh` et
 * `tcpi_rcv_space` qui grandissent ; pas avec SO_RCVBUF fixé. */
static uint32_t champ(int s, int decalage)
{
    unsigned char b[248];
    socklen_t lb = sizeof b;
    uint32_t v = 0;
    getsockopt(s, IPPROTO_TCP, TCP_INFO, b, &lb);
    memcpy(&v, b + decalage, 4);
    return v;
}

#define TCPI_RCV_SSTHRESH 64
#define TCPI_RCV_SPACE 96
#define TCPI_SND_WND 228
#define TCPI_RCV_WND 232

static void *lire_tout(void *p)
{
    int a = *(int *)p;
    static char b[1 << 20];
    while (read(a, b, sizeof b) > 0)
        ;
    return NULL;
}

static void reception_qui_s_ajuste(void)
{
    int port, l = ecoute(&port, 2);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    verifier(champ(c, TCPI_SND_WND) == 65483, "lo : le SYN-ACK annonce 65 483");
    verifier(champ(a, TCPI_SND_WND) == 65536, "lo : le premier ACK du client annonce 65 536");
    verifier(champ(c, TCPI_RCV_SSTHRESH) == 65495 && champ(a, TCPI_RCV_SSTHRESH) == 65483, "lo : tcpi_rcv_ssthresh 65 495, et 65 483 pour la fille");
    verifier(champ(c, TCPI_RCV_SPACE) == 65495 && champ(a, TCPI_RCV_SPACE) == 65483, "lo : tcpi_rcv_space de meme");
    int rcvbuf = option(a, SOL_SOCKET, SO_RCVBUF), ss = champ(a, TCPI_RCV_SSTHRESH), esp = champ(a, TCPI_RCV_SPACE);
    pthread_t t;
    pthread_create(&t, NULL, lire_tout, &a);
    static char b[1 << 20];
    int ok = 1;
    for (int i = 0; i < 64; i++)
        ok &= write(c, b, sizeof b) == sizeof b;
    shutdown(c, SHUT_WR);
    pthread_join(t, NULL);
    verifier(ok && option(a, SOL_SOCKET, SO_RCVBUF) > rcvbuf, "64 Mio lus : SO_RCVBUF a grandi");
    verifier((int)champ(a, TCPI_RCV_SSTHRESH) > ss && (int)champ(a, TCPI_RCV_SPACE) > esp, "tcpi_rcv_ssthresh et tcpi_rcv_space ont grandi");
    close(a);
    close(c);
    /* SO_RCVBUF fixé (sur l'écoute, avant l'accept) : il ne bouge pas. */
    int v = 65536;
    setsockopt(l, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&x, sizeof x);
    a = accept(l, NULL, NULL);
    rcvbuf = option(a, SOL_SOCKET, SO_RCVBUF);
    pthread_create(&t, NULL, lire_tout, &a);
    for (int i = 0; i < 16; i++)
        ok &= write(c, b, sizeof b) == sizeof b;
    shutdown(c, SHUT_WR);
    pthread_join(t, NULL);
    verifier(ok && rcvbuf == 131072 && option(a, SOL_SOCKET, SO_RCVBUF) == rcvbuf, "SO_RCVBUF fixe : il ne bouge pas");
    close(a);
    close(c);
    close(l);
}

/* TCP_WINDOW_CLAMP (`tcp_set_window_clamp`, mesuré) : 0 sur une socket neuve, écrit
 * tel quel, au moins 1152 ; 0 refusé hors de TCP_CLOSE ; hérité par une fille, et la
 * fenêtre de son SYN-ACK le suit. */
static void window_clamp(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    verifier(option(s, IPPROTO_TCP, TCP_WINDOW_CLAMP) == 0, "TCP_WINDOW_CLAMP d'une socket neuve : 0");
    int v = 100;
    verifier(setsockopt(s, IPPROTO_TCP, TCP_WINDOW_CLAMP, &v, sizeof v) == 0 && option(s, IPPROTO_TCP, TCP_WINDOW_CLAMP) == 1152, "TCP_WINDOW_CLAMP 100 : 1152");
    v = -5;
    verifier(setsockopt(s, IPPROTO_TCP, TCP_WINDOW_CLAMP, &v, sizeof v) == 0 && option(s, IPPROTO_TCP, TCP_WINDOW_CLAMP) == 1152, "TCP_WINDOW_CLAMP negatif : 1152");
    v = 0;
    verifier(setsockopt(s, IPPROTO_TCP, TCP_WINDOW_CLAMP, &v, sizeof v) == 0 && option(s, IPPROTO_TCP, TCP_WINDOW_CLAMP) == 0, "TCP_WINDOW_CLAMP 0 d'une socket fermee : 0");
    close(s);
    int port, l = ecoute(&port, 2);
    v = 0;
    verifier(erreur(setsockopt(l, IPPROTO_TCP, TCP_WINDOW_CLAMP, &v, sizeof v)) == EINVAL, "TCP_WINDOW_CLAMP 0 d'une ecoute : EINVAL");
    v = 20000;
    setsockopt(l, IPPROTO_TCP, TCP_WINDOW_CLAMP, &v, sizeof v);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = lo(port);
    connect(c, (void *)&x, sizeof x);
    int a = accept(l, NULL, NULL);
    verifier(option(a, IPPROTO_TCP, TCP_WINDOW_CLAMP) == 20000, "la fille de l'ecoute : TCP_WINDOW_CLAMP 20 000");
    verifier(champ(c, TCPI_SND_WND) == 20000, "son SYN-ACK annonce 20 000");
    v = 0;
    verifier(erreur(setsockopt(a, IPPROTO_TCP, TCP_WINDOW_CLAMP, &v, sizeof v)) == EINVAL, "TCP_WINDOW_CLAMP 0 d'une connexion : EINVAL");
    close(a);
    close(c);
    close(l);
}

/* SO_RCVLOWAT de TCP (`tcp_set_rcvlowat`) : au plus la moitié de `tcp_rmem[2]`, et
 * SO_RCVBUF grandit pour le tenir ; 0 vaut 1 ; négatif : le plafond. */
static void rcvlowat(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int v = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &v, sizeof v);
    verifier(option(s, SOL_SOCKET, SO_RCVLOWAT) == 1, "SO_RCVLOWAT 0 : 1");
    int rcvbuf = option(s, SOL_SOCKET, SO_RCVBUF);
    v = 200000;
    setsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &v, sizeof v);
    verifier(option(s, SOL_SOCKET, SO_RCVLOWAT) == 200000 && option(s, SOL_SOCKET, SO_RCVBUF) >= 400000 && rcvbuf < 400000, "SO_RCVLOWAT 200 000 : SO_RCVBUF grandit pour le tenir");
    v = -1;
    setsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &v, sizeof v);
    verifier(option(s, SOL_SOCKET, SO_RCVLOWAT) > 200000, "SO_RCVLOWAT negatif : la moitie de tcp_rmem[2]");
    close(s);
}

/* TCP_DEFER_ACCEPT (`tcp_check_req`, `syn_ack_recalc`, mesuré) : relu arrondi à ses
 * périodes de SYN-ACK ; un client qui se connecte sans rien envoyer n'est pas accepté
 * avant ses données ; muet, à la fin de la période : 1 s pour 1, avec un SYN-ACK renvoyé ; 3 s
 * pour 2, avec un SYN-ACK renvoyé, à 3 s. */
static void defer_accept(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    const int demande[][2] = { {0, 0}, {1, 1}, {2, 3}, {3, 3}, {5, 7}, {10, 15}, {100, 127}, {1000, 1087} };
    int ok = 1;
    for (size_t i = 0; i < sizeof demande / sizeof demande[0]; i++) {
        setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &demande[i][0], sizeof(int));
        ok &= option(s, IPPROTO_TCP, TCP_DEFER_ACCEPT) == demande[i][1];
    }
    verifier(ok, "TCP_DEFER_ACCEPT relu : 1, 3, 3, 7, 15, 127, 1087");
    close(s);
    /* Les premières données le font accepter. */
    int port, l = ecoute(&port, 2);
    int v = 1;
    setsockopt(l, IPPROTO_TCP, TCP_DEFER_ACCEPT, &v, sizeof v);
    struct sockaddr_in x = lo(port);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&x, sizeof x);
    attendre_ms(100);
    struct pollfd p = { l, POLLIN, 0 };
    int r0 = poll(&p, 1, 0);
    verifier(write(c, "a", 1) == 1, "TCP_DEFER_ACCEPT 1 : le client ecrit");
    int r1 = poll(&p, 1, 500);
    int a = accept(l, NULL, NULL);
    char o;
    verifier(r0 == 0 && r1 == 1 && read(a, &o, 1) == 1 && o == 'a', "TCP_DEFER_ACCEPT 1 : pas pret sans donnees, pret des qu'elles arrivent");
    close(a);
    close(c);
    /* Un client muet : à la fin de la période, et le temps qu'elle dure. */
    for (int defer = 1; defer <= 2; defer++) {
        setsockopt(l, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof defer);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        c = socket(AF_INET, SOCK_STREAM, 0);
        connect(c, (void *)&x, sizeof x);
        int pret = poll(&p, 1, 6000);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        a = accept(l, NULL, NULL);
        struct tcp_info i;
        socklen_t li = sizeof i;
        getsockopt(a, IPPROTO_TCP, TCP_INFO, &i, &li);
        long attendu = defer == 1 ? 1000 : 3000;
        verifier(pret == 1 && ms >= attendu - 100 && ms < attendu + 500 && i.tcpi_total_retrans == 1, defer == 1 ? "TCP_DEFER_ACCEPT 1, client muet : pret a 1 s, un SYN-ACK renvoye" : "TCP_DEFER_ACCEPT 2, client muet : pret a 3 s, un SYN-ACK renvoye");
        close(a);
        close(c);
    }
    close(l);
}

/* /proc/sys/net : les réglages que suit notre TCP, lisibles par tous, avec les valeurs d'un
 * Linux 6.18 ; ceux qui dépendent de la mémoire, en forme. Écrire demande root : EACCES.
 * (tcp_mem n'existe que dans l'espace réseau initial : absent d'un conteneur.) */
static int reglage(const char *nom, char *o, size_t n)
{
    char c[128];
    snprintf(c, sizeof c, "/proc/sys/net/%s", nom);
    int f = open(c, O_RDONLY);
    if (f < 0)
        return -1;
    long r = read(f, o, n - 1);
    close(f);
    o[r < 0 ? 0 : r] = 0;
    return r;
}

static void reglages(void)
{
    static const struct { const char *nom, *valeur; } connus[] = {
        {"ipv4/tcp_timestamps", "1\n"}, {"ipv4/tcp_sack", "1\n"}, {"ipv4/tcp_dsack", "1\n"}, {"ipv4/tcp_window_scaling", "1\n"},
        {"ipv4/tcp_congestion_control", "cubic\n"}, {"ipv4/tcp_available_congestion_control", "reno cubic\n"},
        {"ipv4/tcp_allowed_congestion_control", "reno cubic\n"}, {"ipv4/tcp_fin_timeout", "60\n"}, {"ipv4/tcp_keepalive_time", "7200\n"},
        {"ipv4/tcp_keepalive_intvl", "75\n"}, {"ipv4/tcp_keepalive_probes", "9\n"}, {"ipv4/tcp_syn_retries", "6\n"}, {"ipv4/tcp_synack_retries", "5\n"},
        {"ipv4/tcp_retries2", "15\n"}, {"ipv4/tcp_orphan_retries", "0\n"}, {"ipv4/tcp_tw_reuse", "2\n"}, {"ipv4/tcp_recovery", "1\n"},
        {"ipv4/tcp_early_retrans", "3\n"}, {"ipv4/tcp_frto", "2\n"}, {"ipv4/tcp_moderate_rcvbuf", "1\n"}, {"ipv4/tcp_autocorking", "1\n"},
        {"ipv4/tcp_comp_sack_nr", "44\n"}, {"ipv4/tcp_comp_sack_delay_ns", "1000000\n"}, {"ipv4/tcp_comp_sack_slack_ns", "100000\n"},
        {"ipv4/tcp_min_rtt_wlen", "300\n"}, {"ipv4/tcp_reordering", "3\n"}, {"ipv4/tcp_max_reordering", "300\n"},
        {"ipv4/tcp_limit_output_bytes", "4194304\n"}, {"ipv4/tcp_app_win", "31\n"}, {"ipv4/tcp_pingpong_thresh", "1\n"}, {"ipv4/tcp_mtu_probing", "0\n"},
        {"ipv4/tcp_slow_start_after_idle", "1\n"}, {"ipv4/tcp_pacing_ss_ratio", "200\n"}, {"ipv4/tcp_pacing_ca_ratio", "120\n"},
        {"ipv4/ip_no_pmtu_disc", "0\n"}, {"ipv4/ip_local_port_range", "32768\t60999\n"}, {"ipv4/ip_default_ttl", "64\n"},
        {"ipv4/ipfrag_high_thresh", "4194304\n"}, {"ipv4/ipfrag_time", "30\n"}, {"ipv4/ipfrag_max_dist", "64\n"},
        {"ipv4/route/mtu_expires", "600\n"}, {"ipv4/route/min_pmtu", "552\n"},
        {"core/somaxconn", "4096\n"}, {"core/rmem_max", "4194304\n"}, {"core/wmem_max", "4194304\n"}, {"core/rmem_default", "212992\n"}, {"core/wmem_default", "212992\n"},
    };
    char o[128];
    int ok = 1;
    for (size_t i = 0; i < sizeof connus / sizeof connus[0]; i++) {
        if (reglage(connus[i].nom, o, sizeof o) < 0 || strcmp(o, connus[i].valeur) != 0) {
            printf("[linux] tcp : %s : %s", connus[i].nom, o);
            ok = 0;
        }
    }
    verifier(ok, "/proc/sys/net : les valeurs d'un Linux 6.18");
    long a, b, c;
    verifier(reglage("ipv4/tcp_rmem", o, sizeof o) > 0 && sscanf(o, "%ld\t%ld\t%ld", &a, &b, &c) == 3 && a == 4096 && b == 131072 && c >= 131072,
             "/proc/sys/net/ipv4/tcp_rmem : 4096, 131072, et d'apres la memoire");
    verifier(reglage("ipv4/tcp_wmem", o, sizeof o) > 0 && sscanf(o, "%ld\t%ld\t%ld", &a, &b, &c) == 3 && a == 4096 && b == 16384 && c >= 65536,
             "/proc/sys/net/ipv4/tcp_wmem : 4096, 16384, et d'apres la memoire");
    verifier(reglage("ipv4/tcp_mem", o, sizeof o) < 0 || (sscanf(o, "%ld\t%ld\t%ld", &a, &b, &c) == 3 && a < b && b < c),
             "/proc/sys/net/ipv4/tcp_mem : trois seuils croissants, en pages");
    verifier(open("/proc/sys/net/ipv4/tcp_sack", O_WRONLY) < 0 && errno == EACCES, "/proc/sys/net : ecrire demande root : EACCES");
    struct stat st;
    verifier(stat("/proc/sys/net/ipv4/tcp_sack", &st) == 0 && st.st_mode == (S_IFREG | 0644) && stat("/proc/sys/net/ipv4/tcp_available_congestion_control", &st) == 0
             && st.st_mode == (S_IFREG | 0444), "/proc/sys/net : les droits, 0644, et 0444");
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
    urgent();
    sans_lecteur();
    keepalive_et_info();
    proc_net_tcp();
    debit();
    seuil();
    info_en_time_wait();
    echelle();
    horodatages();
    reprise_time_wait();
    congestion();
    debit_calcule();
    sndbuf_seulement_si_plein();
    reception_qui_s_ajuste();
    window_clamp();
    rcvlowat();
    defer_accept();
    reglages();
    printf("[linux] tcp : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
