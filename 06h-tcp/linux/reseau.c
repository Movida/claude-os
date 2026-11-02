/*
 * Les sockets UDP (6g), contre ce qu'en fait Linux 6.18 (mesuré, sondes
 * du plan de 6g), sur l'interface de boucle seulement (127.0.0.1, des ports
 * éphémères : rien qui dépende du réseau de la machine) :
 *   - socket et socketpair, et leurs refus ; bind, connect, getsockname,
 *     getpeername, et leurs refus ; le port éphémère ;
 *   - envoyer et recevoir : sendto, recvfrom, send sans destination,
 *     sendmsg et recvmsg (IP_PKTINFO), sendmmsg et recvmmsg, MSG_PEEK,
 *     MSG_TRUNC, MSG_DONTWAIT, un datagramme vide, 65 507 octets (le plus
 *     grand) et 65 508 (EMSGSIZE), FIONREAD (le premier datagramme, pas le
 *     total), une socket connectée qui ne reçoit que de son pair ;
 *   - shutdown (ENOTCONN, mais les drapeaux posés), connect(AF_UNSPEC),
 *     un close qui ne réveille pas un autre fil ;
 *   - les options (SO_RCVBUF et SO_SNDBUF doublés, SO_RCVTIMEO arrondi,
 *     IP_TTL, IP_TOS et SO_PRIORITY, les niveaux inconnus) ;
 *   - la socket vue comme fichier (fstat, /proc/self/fd, read de 0 octet,
 *     pread et lseek, ftruncate, fsync, fchmod, un ioctl de terminal) ;
 *   - attendre : un recv réveillé par un datagramme d'un autre fil, par
 *     un shutdown, interrompu par un signal (EINTR, ou repris avec
 *     SA_RESTART, sauf avec un délai), SO_RCVTIMEO (100 ms) ; poll et
 *     epoll ;
 *   - SO_RCVBUF minimal : une file vide accepte 65 507 octets, un deuxième
 *     datagramme est jeté, rien n'est mélangé ;
 *   - deux fils qui s'échangent 10 000 datagrammes en aller-retour ;
 *   - ce que lo livre tout de suite (avant que sendto ne revienne), les
 *     routes (une source de la boucle ne sort pas, 0.0.0.0, la diffusion
 *     de lo, SO_DONTROUTE, l'interface d'IP_PKTINFO), les messages de
 *     contrôle (optmem_max, une place fautive, MSG_CMSG_CLOEXEC), l'ordre
 *     des erreurs d'accept4 et de connect ;
 *   - ICMP : une socket connectée à un port fermé (ECONNREFUSED une fois,
 *     au recv comme au send, et dès le send suivant : lo livre l'erreur
 *     avant qu'il ne revienne ; SO_ERROR, recvmmsg), IP_RECVERR et la file
 *     d'erreurs (MSG_ERRQUEUE, sock_extended_err, IP_PKTINFO d'une erreur,
 *     l'erreur locale d'EMSGSIZE), les sockets de ping (l'écho de
 *     127.0.0.1, l'identifiant remplacé, les refus, MSG_OOB), SOCK_RAW
 *     (EPERM ; EPROTONOSUPPORT pour le protocole 0).
 * Sur l'hôte comme chez nous. Les délais sont des multiples de 4 ms (le
 * tic de l'hôte : HZ = 250).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] reseau : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static struct sockaddr_in adresse(uint32_t ip, uint16_t port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(ip) };
    return a;
}

#define LO 0x7f000001

/* Une socket UDP, ou l'arrêt du test. */
static int udp(int drapeaux)
{
    int s = socket(AF_INET, SOCK_DGRAM | drapeaux, 0);
    if (s < 0) {
        printf("[linux] reseau : socket : ECHEC (%s)\n", strerror(errno));
        exit(1);
    }
    return s;
}

/* Une socket UDP liée à 127.0.0.1, sur un port éphémère, et ce port. */
static int liee(uint16_t *port)
{
    int s = udp(0);
    struct sockaddr_in a = adresse(LO, 0);
    socklen_t l = sizeof a;
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(s, (struct sockaddr *)&a, &l) != 0) {
        printf("[linux] reseau : bind : ECHEC (%s)\n", strerror(errno));
        exit(1);
    }
    *port = ntohs(a.sin_port);
    return s;
}

static ssize_t envoyer(int s, const void *o, size_t n, uint16_t port)
{
    struct sockaddr_in a = adresse(LO, port);
    return sendto(s, o, n, 0, (struct sockaddr *)&a, sizeof a);
}

/* Attend que tout ce qui a été envoyé par lo avant soit arrivé : lo livre
 * dans l'ordre, un datagramme envoyé à une socket témoin puis reçu passe
 * derrière les autres. */
static void attendre_lo(void)
{
    uint16_t p;
    int t = liee(&p);
    char c = 0;
    envoyer(t, &c, 1, p);
    recv(t, &c, 1, 0);
    close(t);
}

static double maintenant(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

/* La plage des ports éphémères : celle de l'hôte, ou celle de Linux par
 * défaut (notre /proc n'a pas encore /proc/sys/net). */
static void plage(int *bas, int *haut)
{
    *bas = 32768;
    *haut = 60999;
    FILE *f = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
    if (f) {
        if (fscanf(f, "%d %d", bas, haut) != 2) {
            *bas = 32768;
            *haut = 60999;
        }
        fclose(f);
    }
}

static void creation(void)
{
    verifier(erreur(socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP)) == EPROTONOSUPPORT, "socket(SOCK_DGRAM, IPPROTO_TCP) : EPROTONOSUPPORT");
    verifier(erreur(socket(AF_INET, SOCK_SEQPACKET, 0)) == ESOCKTNOSUPPORT, "socket(SOCK_SEQPACKET) : ESOCKTNOSUPPORT");
    verifier(erreur(socket(AF_INET, 77, 0)) == EINVAL, "socket de sorte 77 : EINVAL");
    verifier(erreur(socket(AF_INET, SOCK_DGRAM, 300)) == EINVAL && erreur(socket(AF_INET, SOCK_DGRAM, -1)) == EINVAL,
             "socket de protocole 300 ou -1 : EINVAL");
    verifier(erreur(socket(AF_INET, SOCK_DGRAM, 256)) == EPROTONOSUPPORT, "socket de protocole 256 : EPROTONOSUPPORT");
    /* Une famille hors de 0..NPROTO (46, -1) : EAFNOSUPPORT chez Linux,
     * mais EPERM dans un conteneur Docker (son filtre seccomp ne laisse
     * passer que les familles connues) : pas comparée ici. */
    int t[2];
    verifier(erreur(socketpair(AF_INET, SOCK_DGRAM, 0, t)) == EOPNOTSUPP, "socketpair(AF_INET) : EOPNOTSUPP");
    int s = udp(SOCK_NONBLOCK | SOCK_CLOEXEC);
    verifier(fcntl(s, F_GETFL) == (O_RDWR | O_NONBLOCK) && fcntl(s, F_GETFD) == FD_CLOEXEC,
             "socket(SOCK_NONBLOCK | SOCK_CLOEXEC) : F_GETFL O_RDWR | O_NONBLOCK, FD_CLOEXEC");
    int v;
    socklen_t l = sizeof v;
    verifier(getsockopt(s, SOL_SOCKET, SO_TYPE, &v, &l) == 0 && v == SOCK_DGRAM && l == 4
                 && getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &v, &l) == 0 && v == IPPROTO_UDP
                 && getsockopt(s, SOL_SOCKET, SO_DOMAIN, &v, &l) == 0 && v == AF_INET
                 && getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &l) == 0 && v == 0,
             "SO_TYPE, SO_PROTOCOL, SO_DOMAIN, SO_ERROR");
    verifier(erreur(listen(s, 1)) == EOPNOTSUPP && erreur(accept(s, NULL, NULL)) == EOPNOTSUPP, "listen et accept : EOPNOTSUPP");
    close(s);
}

static void lier(void)
{
    int s = udp(0);
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    verifier(getsockname(s, (struct sockaddr *)&a, &l) == 0 && l == 16 && a.sin_addr.s_addr == 0 && a.sin_port == 0,
             "getsockname avant bind : 0.0.0.0:0, 16 octets");
    a = adresse(LO, 0);
    verifier(erreur(bind(s, (struct sockaddr *)&a, 15)) == EINVAL, "bind de 15 octets : EINVAL");
    a.sin_family = AF_UNIX;
    verifier(erreur(bind(s, (struct sockaddr *)&a, sizeof a)) == EAFNOSUPPORT, "bind d'une famille AF_UNIX : EAFNOSUPPORT");
    a.sin_family = 99;
    verifier(erreur(bind(s, (struct sockaddr *)&a, sizeof a)) == EAFNOSUPPORT, "bind d'une famille 99 : EAFNOSUPPORT");
    a.sin_family = AF_UNSPEC;
    verifier(erreur(bind(s, (struct sockaddr *)&a, sizeof a)) == EAFNOSUPPORT, "bind AF_UNSPEC de 127.0.0.1 : EAFNOSUPPORT");
    /* 192.0.2.1 : une adresse de documentation (RFC 5737), jamais à une
     * machine. */
    a = adresse(0xc0000201, 0);
    verifier(erreur(bind(s, (struct sockaddr *)&a, sizeof a)) == EADDRNOTAVAIL, "bind d'une adresse qui n'est pas a nous : EADDRNOTAVAIL");
    a = adresse(0, 0);
    a.sin_family = AF_UNSPEC;
    verifier(bind(s, (struct sockaddr *)&a, sizeof a) == 0, "bind AF_UNSPEC de 0.0.0.0 : permis (compatibilite)");
    a = adresse(LO, 0);
    verifier(erreur(bind(s, (struct sockaddr *)&a, sizeof a)) == EINVAL, "bind deux fois : EINVAL");
    l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    int bas, haut;
    plage(&bas, &haut);
    int p = ntohs(a.sin_port);
    verifier(a.sin_addr.s_addr == 0 && p >= bas && p <= haut, "le port ephemere de bind(0) : dans ip_local_port_range");
    int t = udp(0);
    a = adresse(LO, p);
    verifier(erreur(bind(t, (struct sockaddr *)&a, sizeof a)) == EADDRINUSE, "bind d'un port pris (0.0.0.0 recouvre 127.0.0.1) : EADDRINUSE");
    int un = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    /* SO_REUSEADDR posé après le bind de s : Linux regarde l'option de
     * chacune au moment du conflit. */
    verifier(bind(t, (struct sockaddr *)&a, sizeof a) == 0, "SO_REUSEADDR des deux cotes : le port partage");
    close(s);
    close(t);

    /* Envoyer sans port : un port éphémère, l'adresse laissée à 0.0.0.0. */
    uint16_t pr;
    int r = liee(&pr);
    s = udp(0);
    verifier(envoyer(s, "x", 1, pr) == 1, "sendto d'une socket sans port");
    l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    p = ntohs(a.sin_port);
    verifier(a.sin_addr.s_addr == 0 && p >= bas && p <= haut, "puis getsockname : 0.0.0.0, un port ephemere");
    char c;
    l = sizeof a;
    verifier(recvfrom(r, &c, 1, 0, (struct sockaddr *)&a, &l) == 1 && c == 'x' && l == 16 && a.sin_family == AF_INET
                 && a.sin_addr.s_addr == htonl(LO) && ntohs(a.sin_port) == p,
             "recvfrom : l'emetteur, 127.0.0.1 et son port");
    close(s);

    /* send sans destination : EDESTADDRREQ, mais le port est déjà pris
     * (inet_sendmsg lie la socket avant d'appeler UDP). */
    s = udp(0);
    verifier(erreur(send(s, "x", 1, 0)) == EDESTADDRREQ, "send sans destination : EDESTADDRREQ");
    l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    verifier(a.sin_port != 0, "et la socket a deja son port ephemere");
    verifier(erreur(write(s, "", 0)) == EDESTADDRREQ, "write de 0 octet, sans destination : EDESTADDRREQ");
    l = sizeof a;
    verifier(erreur(getpeername(s, (struct sockaddr *)&a, &l)) == ENOTCONN, "getpeername sans connexion : ENOTCONN");
    a = adresse(LO, 0);
    verifier(erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a)) == EINVAL, "sendto vers le port 0 : EINVAL");
    a = adresse(LO, pr);
    verifier(erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&a, 8)) == EINVAL, "sendto d'une adresse de 8 octets : EINVAL");
    a = adresse(0xffffffff, 9);
    verifier(erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a)) == EACCES, "sendto(255.255.255.255) sans SO_BROADCAST : EACCES");
    close(s);

    /* connect, puis connect(AF_UNSPEC) : le port éphémère rendu. */
    s = udp(0);
    a = adresse(LO, pr);
    verifier(connect(s, (struct sockaddr *)&a, sizeof a) == 0, "connect");
    l = sizeof a;
    verifier(getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_addr.s_addr == htonl(LO) && a.sin_port != 0,
             "getsockname d'une socket connectee : 127.0.0.1, un port");
    l = sizeof a;
    verifier(getpeername(s, (struct sockaddr *)&a, &l) == 0 && a.sin_addr.s_addr == htonl(LO) && ntohs(a.sin_port) == pr,
             "getpeername : le pair");
    verifier(send(s, "y", 1, 0) == 1 && recv(r, &c, 1, 0) == 1 && c == 'y', "send d'une socket connectee");
    struct sockaddr un_spec = { .sa_family = AF_UNSPEC };
    verifier(connect(s, &un_spec, sizeof un_spec) == 0, "connect(AF_UNSPEC)");
    l = sizeof a;
    verifier(getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_addr.s_addr == 0 && a.sin_port == 0,
             "puis getsockname : 0.0.0.0:0, le port ephemere rendu");
    close(s);
    close(r);
}

/* Une socket connectée ne reçoit que de son pair. */
static void filtre(void)
{
    uint16_t pa, pb, pc;
    int a = liee(&pa), b = liee(&pb), c = liee(&pc);
    struct sockaddr_in d = adresse(LO, pb);
    connect(a, (struct sockaddr *)&d, sizeof d);
    envoyer(c, "c", 1, pa);
    envoyer(b, "b", 1, pa);
    attendre_lo();
    char o[4];
    verifier(recv(a, o, sizeof o, MSG_DONTWAIT) == 1 && o[0] == 'b' && erreur(recv(a, o, sizeof o, MSG_DONTWAIT)) == EAGAIN,
             "une socket connectee ne recoit que de son pair");
    close(a);
    close(b);
    close(c);
}

static void datagrammes(void)
{
    uint16_t pr;
    int r = liee(&pr);
    int s = udp(0);
    static char gros[65508];
    for (size_t i = 0; i < sizeof gros; i++)
        gros[i] = i * 7;
    char o[64];
    verifier(erreur(recv(r, o, sizeof o, MSG_DONTWAIT)) == EAGAIN, "MSG_DONTWAIT sans datagramme : EAGAIN");
    verifier(envoyer(s, "", 0, pr) == 0 && recv(r, o, sizeof o, 0) == 0, "un datagramme vide : recv rend 0");
    envoyer(s, "0123456789", 10, pr);
    envoyer(s, "abcdefghijklmnopqrst", 20, pr);
    attendre_lo();
    int n = -1;
    verifier(ioctl(r, FIONREAD, &n) == 0 && n == 10, "FIONREAD : la taille du premier datagramme, pas le total");
    verifier(recv(r, o, 4, MSG_PEEK) == 4 && memcmp(o, "0123", 4) == 0 && recv(r, o, sizeof o, 0) == 10
                 && memcmp(o, "0123456789", 10) == 0,
             "MSG_PEEK : le datagramme reste en file");
    verifier(recv(r, NULL, 0, MSG_TRUNC) == 20 && erreur(recv(r, o, sizeof o, MSG_DONTWAIT)) == EAGAIN,
             "recv(0, MSG_TRUNC) : la vraie longueur, le datagramme pris");
    envoyer(s, "abcdefghijklmnopqrst", 20, pr);
    struct iovec v = { o, 5 };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1 };
    verifier(recvmsg(r, &m, 0) == 5 && m.msg_flags == MSG_TRUNC, "recvmsg coupe : MSG_TRUNC dans msg_flags, le reste perdu");
    verifier(erreur(envoyer(s, gros, 65508, pr)) == EMSGSIZE, "65 508 octets : EMSGSIZE");
    verifier(envoyer(s, gros, 65507, pr) == 65507, "65 507 octets : envoyes (la MTU de lo est 65 536)");
    static char lu[65507];
    verifier(recv(r, lu, sizeof lu, 0) == 65507 && memcmp(lu, gros, 65507) == 0, "et recus, octet pour octet");

    /* IP_PKTINFO : l'interface d'arrivée (lo : 1), l'adresse locale et la
     * destination. */
    int un = 1;
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    envoyer(s, "p", 1, pr);
    char controle[64];
    struct sockaddr_in de;
    v = (struct iovec){ o, sizeof o };
    m = (struct msghdr){ .msg_name = &de, .msg_namelen = sizeof de, .msg_iov = &v, .msg_iovlen = 1,
                         .msg_control = controle, .msg_controllen = sizeof controle };
    int ok = recvmsg(r, &m, 0) == 1 && m.msg_namelen == 16 && de.sin_addr.s_addr == htonl(LO);
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    ok = ok && c && c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO && c->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo))
         && m.msg_controllen == CMSG_SPACE(sizeof(struct in_pktinfo));
    if (ok) {
        struct in_pktinfo *i = (struct in_pktinfo *)CMSG_DATA(c);
        ok = i->ipi_ifindex == 1 && i->ipi_addr.s_addr == htonl(LO) && i->ipi_spec_dst.s_addr == htonl(LO);
    }
    verifier(ok, "recvmsg et IP_PKTINFO : lo (1), 127.0.0.1");
    /* Trop peu de place pour le message de contrôle : MSG_CTRUNC. */
    envoyer(s, "p", 1, pr);
    m.msg_controllen = 8;
    verifier(recvmsg(r, &m, 0) == 1 && (m.msg_flags & MSG_CTRUNC) && m.msg_controllen == 0, "IP_PKTINFO sans la place : MSG_CTRUNC");

    /* sendmmsg, de deux messages (ce que fait la glibc pour ses deux
     * questions au DNS), puis recvmmsg. */
    struct sockaddr_in d = adresse(LO, pr);
    struct iovec v2[2] = { { "un", 2 }, { "deux", 4 } };
    struct mmsghdr mm[3] = {
        { .msg_hdr = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v2[0], .msg_iovlen = 1 } },
        { .msg_hdr = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v2[1], .msg_iovlen = 1 } },
    };
    verifier(sendmmsg(s, mm, 2, 0) == 2 && mm[0].msg_len == 2 && mm[1].msg_len == 4, "sendmmsg de deux messages : 2, et leurs longueurs");
    attendre_lo();
    char t[3][8];
    struct iovec vr[3] = { { t[0], 8 }, { t[1], 8 }, { t[2], 8 } };
    memset(mm, 0, sizeof mm);
    for (int k = 0; k < 3; k++)
        mm[k].msg_hdr = (struct msghdr){ .msg_iov = &vr[k], .msg_iovlen = 1 };
    verifier(recvmmsg(r, mm, 3, MSG_DONTWAIT, NULL) == 2 && mm[0].msg_len == 2 && mm[1].msg_len == 4 && memcmp(t[1], "deux", 4) == 0,
             "recvmmsg de 3, sans attendre : les deux");
    close(s);
    close(r);
}

static void options(void)
{
    int s = udp(0), v;
    socklen_t l = sizeof v;
    v = 1;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &l);
    int ok = v == 2304;
    v = 1;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    getsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, &l);
    ok = ok && v == 4608;
    v = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &l);
    verifier(ok && v == 8000, "SO_RCVBUF et SO_SNDBUF : doubles, au moins 2304 et 4608");
    struct timeval tv = { 0, 8000 }, lu;
    l = sizeof lu;
    verifier(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0 && getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &lu, &l) == 0
                 && l == sizeof lu && lu.tv_sec == 0 && lu.tv_usec == 8000,
             "SO_RCVTIMEO de 8 ms, relu");
    tv.tv_usec = 1000000;
    verifier(erreur(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv)) == EDOM, "SO_RCVTIMEO de 1 000 000 us : EDOM");
    verifier(erreur(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, 8)) == EINVAL, "SO_RCVTIMEO de 8 octets : EINVAL");
    v = 0;
    verifier(erreur(setsockopt(s, IPPROTO_IP, IP_TTL, &v, sizeof v)) == EINVAL, "IP_TTL 0 : EINVAL");
    v = 256;
    verifier(erreur(setsockopt(s, IPPROTO_IP, IP_TTL, &v, sizeof v)) == EINVAL, "IP_TTL 256 : EINVAL");
    v = 9;
    setsockopt(s, IPPROTO_IP, IP_TTL, &v, sizeof v);
    l = sizeof v;
    ok = getsockopt(s, IPPROTO_IP, IP_TTL, &v, &l) == 0 && v == 9;
    v = -1;
    setsockopt(s, IPPROTO_IP, IP_TTL, &v, sizeof v);
    getsockopt(s, IPPROTO_IP, IP_TTL, &v, &l);
    verifier(ok && v == 64, "IP_TTL 9, puis -1 : le defaut, 64");
    unsigned char octet = 0;
    l = 1;
    verifier(getsockopt(s, IPPROTO_IP, IP_TTL, &octet, &l) == 0 && l == 1 && octet == 64, "getsockopt(IP_TTL) dans un octet");
    v = 0x10;
    setsockopt(s, IPPROTO_IP, IP_TOS, &v, sizeof v);
    l = sizeof v;
    verifier(getsockopt(s, SOL_SOCKET, SO_PRIORITY, &v, &l) == 0 && v == 6, "IP_TOS 0x10 (faible delai) : SO_PRIORITY 6");
    if (getuid() != 0) {
        v = 7;
        verifier(erreur(setsockopt(s, SOL_SOCKET, SO_PRIORITY, &v, sizeof v)) == EPERM, "SO_PRIORITY 7 : EPERM");
    }
    v = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &v, sizeof v);
    l = sizeof v;
    verifier(getsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &v, &l) == 0 && v == 1, "SO_RCVLOWAT 0 : se relit 1");
    short court = -1;
    l = sizeof court;
    verifier(getsockopt(s, SOL_SOCKET, SO_TYPE, &court, &l) == 0 && l == 2 && court == SOCK_DGRAM, "getsockopt dans 2 octets : coupe");
    l = sizeof v;
    verifier(erreur(getsockopt(s, 99, 1, &v, &l)) == EOPNOTSUPP, "getsockopt d'un niveau inconnu : EOPNOTSUPP");
    verifier(erreur(setsockopt(s, 99, 1, &v, sizeof v)) == ENOPROTOOPT, "setsockopt d'un niveau inconnu : ENOPROTOOPT");
    verifier(erreur(setsockopt(s, SOL_SOCKET, 9999, &v, sizeof v)) == ENOPROTOOPT, "une option inconnue : ENOPROTOOPT");
    verifier(erreur(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, -1)) == EINVAL, "une longueur negative : EINVAL");
    close(s);
}

static void fichier(void)
{
    int s = udp(0);
    struct stat a;
    verifier(fstat(s, &a) == 0 && a.st_mode == (S_IFSOCK | 0777) && a.st_size == 0 && a.st_blksize == 4096 && a.st_nlink == 1
                 && a.st_uid == getuid(),
             "fstat : S_IFSOCK | 0777, taille 0, blocs de 4096, nlink 1");
    char chemin[64], lien[64], attendu[64];
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", s);
    snprintf(attendu, sizeof attendu, "socket:[%lu]", (unsigned long)a.st_ino);
    ssize_t n = readlink(chemin, lien, sizeof lien);
    verifier(n == (ssize_t)strlen(attendu) && memcmp(lien, attendu, n) == 0, "readlink de /proc/self/fd/N : socket:[inode]");
    verifier(erreur(open(chemin, O_RDWR)) == ENXIO, "open de /proc/self/fd/N : ENXIO");
    int p = open(chemin, O_PATH);
    verifier(p >= 0, "open de /proc/self/fd/N en O_PATH : permis");
    close(p);
    char o[4];
    verifier(read(s, o, 0) == 0, "read de 0 octet : 0, sans attendre");
    verifier(erreur(pread(s, o, 1, 0)) == ESPIPE && erreur(lseek(s, 0, SEEK_SET)) == ESPIPE, "pread et lseek : ESPIPE");
    verifier(erreur(ftruncate(s, 0)) == EINVAL && erreur(fsync(s)) == EINVAL, "ftruncate et fsync : EINVAL");
    verifier(fchmod(s, 0600) == 0 && fstat(s, &a) == 0 && a.st_mode == (S_IFSOCK | 0600), "fchmod : permis");
    struct termios t;
    verifier(erreur(ioctl(s, TCGETS, &t)) == ENOTTY, "ioctl(TCGETS) : ENOTTY");
    int f = open("/dev/null", O_RDONLY);
    struct sockaddr_in d = adresse(LO, 9);
    verifier(erreur(bind(f, (struct sockaddr *)&d, sizeof d)) == ENOTSOCK && erreur(bind(1000, (struct sockaddr *)&d, sizeof d)) == EBADF,
             "bind d'un autre fichier : ENOTSOCK ; d'un descripteur ferme : EBADF");
    close(f);
    close(s);
}

/* --- Les attentes, d'un fil à l'autre --- */

struct attente {
    int s;
    volatile int fini;
    long r;
    int e;
    char o[16];
};

static void *recevoir(void *arg)
{
    struct attente *a = arg;
    a->r = recv(a->s, a->o, sizeof a->o, 0);
    a->e = errno;
    a->fini = 1;
    return NULL;
}

static volatile int signaux;

static void compter(int n)
{
    (void)n;
    signaux++;
}

static void dormir_ms(int ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

/* Lance `recevoir` sur s dans un fil, et attend qu'il dorme (20 ms). */
static pthread_t lancer(struct attente *a, int s)
{
    pthread_t f;
    memset(a, 0, sizeof *a);
    a->s = s;
    pthread_create(&f, NULL, recevoir, a);
    dormir_ms(20);
    return f;
}

static void attentes(void)
{
    uint16_t pr;
    struct attente a;
    int r = liee(&pr), s = udp(0);

    pthread_t f = lancer(&a, r);
    verifier(!a.fini, "recv sans datagramme : il attend");
    envoyer(s, "reveil", 6, pr);
    pthread_join(f, NULL);
    verifier(a.r == 6 && memcmp(a.o, "reveil", 6) == 0, "un datagramme d'un autre fil le reveille");

    f = lancer(&a, r);
    verifier(erreur(shutdown(r, SHUT_RD)) == ENOTCONN, "shutdown(SHUT_RD) d'une socket non connectee : ENOTCONN");
    pthread_join(f, NULL);
    verifier(a.r == 0, "mais le drapeau est pose : le recv qui attendait rend 0");
    struct pollfd p = { r, POLLIN | POLLOUT | POLLRDHUP, 0 };
    verifier(poll(&p, 1, 0) == 1 && p.revents == (POLLIN | POLLOUT | POLLRDHUP), "poll apres SHUT_RD : POLLIN | POLLOUT | POLLRDHUP");
    verifier(recv(r, a.o, 1, 0) == 0 && erreur(recv(r, a.o, 1, MSG_DONTWAIT)) == EAGAIN,
             "recv apres SHUT_RD : 0 ; MSG_DONTWAIT : EAGAIN (l'arret n'est vu qu'en attendant)");
    close(r);

    r = liee(&pr);
    struct sigaction sa = { .sa_handler = compter };
    sigaction(SIGPIPE, &sa, NULL);
    verifier(erreur(shutdown(r, SHUT_WR)) == ENOTCONN && erreur(envoyer(r, "x", 1, pr)) == EPIPE && signaux == 0,
             "SHUT_WR : sendto rend EPIPE, sans SIGPIPE");
    verifier(erreur(shutdown(r, 7)) == EINVAL, "shutdown(7) : EINVAL");
    close(r);

    /* Un signal : EINTR sans SA_RESTART ; repris avec. */
    r = liee(&pr);
    sigaction(SIGUSR1, &sa, NULL);
    f = lancer(&a, r);
    for (int k = 0; k < 100 && !a.fini; k++) {
        pthread_kill(f, SIGUSR1);
        dormir_ms(20);
    }
    pthread_join(f, NULL);
    verifier(a.r == -1 && a.e == EINTR, "un signal sans SA_RESTART : EINTR");
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    signaux = 0;
    f = lancer(&a, r);
    for (int k = 0; k < 3; k++) {
        pthread_kill(f, SIGUSR1);
        dormir_ms(20);
    }
    int attend = !a.fini;
    envoyer(s, "repris", 6, pr);
    pthread_join(f, NULL);
    verifier(attend && signaux == 3 && a.r == 6, "avec SA_RESTART : le recv reprend, puis recoit");
    /* Avec un délai, un signal rend EINTR, même avec SA_RESTART
     * (sock_intr_errno). */
    struct timeval tv = { 10, 0 };
    setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    f = lancer(&a, r);
    for (int k = 0; k < 100 && !a.fini; k++) {
        pthread_kill(f, SIGUSR1);
        dormir_ms(20);
    }
    pthread_join(f, NULL);
    verifier(a.r == -1 && a.e == EINTR, "avec SO_RCVTIMEO et SA_RESTART : EINTR");
    tv = (struct timeval){ 0, 100000 };
    setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    double debut = maintenant();
    long n = recv(r, a.o, 1, 0);
    double duree = maintenant() - debut;
    verifier(n == -1 && errno == EAGAIN && duree >= 0.1 && duree < 5, "SO_RCVTIMEO de 100 ms : EAGAIN, apres 100 ms");
    close(r);

    /* Un close d'un autre fil ne réveille pas le recv : la socket vit tant
     * qu'il la tient, et reçoit encore. */
    r = liee(&pr);
    f = lancer(&a, r);
    close(r);
    dormir_ms(20);
    attend = !a.fini;
    envoyer(s, "apres", 5, pr);
    pthread_join(f, NULL);
    verifier(attend && a.r == 5, "close pendant un recv d'un autre fil : il attend encore, puis recoit");

    /* poll et epoll. */
    r = liee(&pr);
    p = (struct pollfd){ r, POLLIN | POLLOUT, 0 };
    verifier(poll(&p, 1, 0) == 1 && p.revents == POLLOUT, "poll d'une socket vide : POLLOUT");
    int e = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u32 = 7 };
    verifier(epoll_ctl(e, EPOLL_CTL_ADD, r, &ev) == 0 && epoll_wait(e, &ev, 1, 0) == 0, "epoll : une socket vide n'est pas prete");
    envoyer(s, "e", 1, pr);
    verifier(epoll_wait(e, &ev, 1, 5000) == 1 && ev.events == EPOLLIN && ev.data.u32 == 7, "epoll : un datagramme arrive, EPOLLIN");
    close(e);
    close(r);
    close(s);
}

/* SO_RCVBUF minimal : la file vide accepte le plus grand datagramme ; le
 * suivant, non. */
static void file_pleine(void)
{
    uint16_t pr;
    int r = liee(&pr), s = udp(0);
    int v = 1;
    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    static char gros[65507], lu[65507];
    for (size_t i = 0; i < sizeof gros; i++)
        gros[i] = i * 13;
    envoyer(s, gros, sizeof gros, pr);
    envoyer(s, "petit", 5, pr);
    attendre_lo();
    verifier(recv(r, lu, sizeof lu, MSG_DONTWAIT) == 65507 && memcmp(lu, gros, sizeof gros) == 0
                 && erreur(recv(r, lu, sizeof lu, MSG_DONTWAIT)) == EAGAIN,
             "SO_RCVBUF 2304 : 65 507 octets acceptes, le datagramme suivant jete");
    close(r);
    close(s);
}

/* Deux fils qui s'échangent un compteur, 10 000 fois. */
static int ping, pong;
static uint16_t port_ping, port_pong;

static void *renvoyer(void *arg)
{
    (void)arg;
    uint32_t n;
    for (int k = 0; k < 10000; k++) {
        if (recv(pong, &n, sizeof n, 0) != sizeof n)
            return (void *)1;
        n++;
        envoyer(pong, &n, sizeof n, port_ping);
    }
    return NULL;
}

static void aller_retour(void)
{
    ping = liee(&port_ping);
    pong = liee(&port_pong);
    pthread_t f;
    pthread_create(&f, NULL, renvoyer, NULL);
    uint32_t n = 0;
    int ok = 1;
    for (int k = 0; k < 10000 && ok; k++) {
        uint32_t attendu = n + 1;
        envoyer(ping, &n, sizeof n, port_pong);
        ok = recv(ping, &n, sizeof n, 0) == sizeof n && n == attendu;
    }
    void *r;
    pthread_join(f, &r);
    verifier(ok && r == NULL && n == 10000, "deux fils, 10 000 allers-retours");
    close(ping);
    close(pong);
}

/* 192.0.2.1 : une adresse de documentation (RFC 5737), jamais à une
 * machine, joignable par la route par défaut ; rien n'y part (chaque envoi
 * est refusé avant). */
#define DOC 0xc0000201

static void routes_et_messages(void)
{
    uint16_t pr;
    int r = liee(&pr), s = udp(0);
    /* lo livre avant que sendto ne revienne. */
    char o[64];
    int absents = 0;
    for (int k = 0; k < 200; k++) {
        envoyer(s, "x", 1, pr);
        absents += recv(r, o, sizeof o, MSG_DONTWAIT) != 1;
    }
    verifier(absents == 0, "lo : 200 datagrammes, chacun deja la quand sendto revient");

    /* Une source de la boucle ne sort pas par une carte. */
    int b = udp(0);
    struct sockaddr_in a = adresse(LO, 0), d = adresse(DOC, 9);
    bind(b, (struct sockaddr *)&a, sizeof a);
    verifier(erreur(sendto(b, "x", 1, 0, (struct sockaddr *)&d, sizeof d)) == EINVAL
                 && erreur(connect(b, (struct sockaddr *)&d, sizeof d)) == EINVAL,
             "liee a 127.0.0.1, vers le dehors : EINVAL (sendto et connect)");
    close(b);
    char c[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct iovec v = { "x", 1 };
    struct msghdr m = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c };
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = IPPROTO_IP;
    h->cmsg_type = IP_PKTINFO;
    h->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(h);
    memset(pi, 0, sizeof *pi);
    pi->ipi_spec_dst.s_addr = htonl(LO);
    verifier(erreur(sendmsg(s, &m, 0)) == EINVAL, "IP_PKTINFO de source 127.0.0.1, vers le dehors : EINVAL");
    pi->ipi_spec_dst.s_addr = 0;
    pi->ipi_ifindex = 99;
    verifier(erreur(sendmsg(s, &m, 0)) == ENODEV, "IP_PKTINFO d'une interface qui n'existe pas : ENODEV");

    /* 0.0.0.0 : la source liée, sinon 127.0.0.1. */
    uint16_t p2;
    int r2 = udp(0);
    a = adresse(0x7f000002, 0);
    socklen_t l = sizeof a;
    bind(r2, (struct sockaddr *)&a, sizeof a);
    getsockname(r2, (struct sockaddr *)&a, &l);
    p2 = ntohs(a.sin_port);
    b = udp(0);
    a = adresse(0x7f000002, 0);
    bind(b, (struct sockaddr *)&a, sizeof a);
    d = adresse(0, p2);
    verifier(sendto(b, "z", 1, 0, (struct sockaddr *)&d, sizeof d) == 1 && recv(r2, o, sizeof o, MSG_DONTWAIT) == 1,
             "vers 0.0.0.0 d'une socket liee a 127.0.0.2 : vers 127.0.0.2");
    close(b);
    close(r2);
    d = adresse(0x7fffffff, pr);
    verifier(erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&d, sizeof d)) == EACCES, "127.255.255.255, la diffusion de lo : EACCES sans SO_BROADCAST");

    /* SO_DONTROUTE : seulement un réseau directement branché ; relus. */
    int un = 1, val;
    l = sizeof val;
    setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &un, sizeof un);
    d = adresse(DOC, 9);
    int ok = erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&d, sizeof d)) == ENETUNREACH;
    ok = ok && getsockopt(s, SOL_SOCKET, SO_DONTROUTE, &val, &l) == 0 && val == 1;
    setsockopt(s, SOL_SOCKET, SO_OOBINLINE, &un, sizeof un);
    setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &un, sizeof un);
    ok = ok && getsockopt(s, SOL_SOCKET, SO_OOBINLINE, &val, &l) == 0 && val == 1 && getsockopt(s, SOL_SOCKET, SO_NO_CHECK, &val, &l) == 0 && val == 1;
    verifier(ok, "SO_DONTROUTE vers le dehors : ENETUNREACH ; SO_DONTROUTE, SO_OOBINLINE, SO_NO_CHECK relus");
    un = 0;
    setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &un, sizeof un);
    /* IP_TOS inchangé ne touche pas SO_PRIORITY. */
    val = 3;
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &val, sizeof val);
    val = 0;
    setsockopt(s, IPPROTO_IP, IP_TOS, &val, sizeof val);
    verifier(getsockopt(s, SOL_SOCKET, SO_PRIORITY, &val, &l) == 0 && val == 3, "IP_TOS sans changement : SO_PRIORITY garde 3");

    /* Les messages de contrôle : au-delà d'optmem_max, ENOBUFS ; une place
     * fautive en réception est ignorée ; MSG_CMSG_CLOEXEC rendu. */
    d = adresse(LO, pr);
    m = (struct msghdr){ .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = 200000 };
    verifier(erreur(sendmsg(s, &m, 0)) == ENOBUFS, "sendmsg, 200 000 octets de controle : ENOBUFS");
    un = 1;
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    envoyer(s, "c", 1, pr);
    struct iovec vr = { o, sizeof o };
    m = (struct msghdr){ .msg_iov = &vr, .msg_iovlen = 1, .msg_control = (void *)8, .msg_controllen = 64 };
    verifier(recvmsg(r, &m, 0) == 1 && m.msg_controllen == 0 && m.msg_flags == 0, "recvmsg, une place de controle fautive : ignoree");
    envoyer(s, "c", 1, pr);
    m = (struct msghdr){ .msg_iov = &vr, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c };
    verifier(recvmsg(r, &m, MSG_CMSG_CLOEXEC) == 1 && (m.msg_flags & MSG_CMSG_CLOEXEC), "MSG_CMSG_CLOEXEC rendu dans msg_flags");
    close(r);
    close(s);

    /* L'ordre des erreurs : accept4 rend EBADF avant de regarder ses
     * drapeaux ; connect copie l'adresse avant ENOTSOCK. */
    int f = open("/dev/null", O_RDONLY);
    verifier(erreur(accept4(-1, NULL, NULL, 0x1234)) == EBADF && erreur(accept4(f, NULL, NULL, 0x1234)) == EINVAL
                 && erreur(accept4(f, NULL, NULL, 0)) == ENOTSOCK,
             "accept4 : EBADF, puis EINVAL des drapeaux, puis ENOTSOCK");
    verifier(erreur(connect(f, NULL, 16)) == EFAULT && erreur(connect(f, (struct sockaddr *)&d, 200)) == EINVAL
                 && erreur(connect(f, (struct sockaddr *)&d, 16)) == ENOTSOCK,
             "connect d'un autre fichier : l'adresse d'abord (EFAULT, EINVAL), puis ENOTSOCK");
    close(f);
}

/* Un port fermé de 127.0.0.1 : celui d'une socket qu'on vient de fermer. */
static uint16_t port_ferme(void)
{
    uint16_t p;
    close(liee(&p));
    return p;
}

/* Attend POLLERR sur s, 5 s au plus. */
static int attendre_erreur(int s)
{
    struct pollfd p = { s, 0, 0 };
    return poll(&p, 1, 5000) == 1 && (p.revents & POLLERR);
}

/* Prend la première erreur de la file de s : ce qu'elle porte dans o (n
 * octets au plus), qui l'a dite et son adresse, et son IP_PKTINFO (nul
 * s'il n'y en a pas). Rend la longueur, ou -1. */
static long erreur_en_file(int s, char *o, size_t n, struct sock_extended_err *ee, struct sockaddr_in *offender,
                           struct sockaddr_in *nom, int *drapeaux, struct in_pktinfo *pi)
{
    char c[256];
    struct iovec v = { o, n };
    struct msghdr m = { .msg_name = nom, .msg_namelen = sizeof *nom, .msg_iov = &v, .msg_iovlen = 1,
                        .msg_control = c, .msg_controllen = sizeof c };
    long r = recvmsg(s, &m, MSG_ERRQUEUE);
    if (r < 0)
        return r;
    *drapeaux = m.msg_flags;
    memset(ee, 0, sizeof *ee);
    memset(pi, 0, sizeof *pi);
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h)) {
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_RECVERR) {
            memcpy(ee, CMSG_DATA(h), sizeof *ee);
            memcpy(offender, SO_EE_OFFENDER((struct sock_extended_err *)CMSG_DATA(h)), sizeof *offender);
        }
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO)
            memcpy(pi, CMSG_DATA(h), sizeof *pi);
    }
    return r;
}

static void icmp(void)
{
    /* Connectée à un port fermé : le send réussit, l'ICMP « port
     * injoignable » revient (de lo : sans limite), POLLERR ; le recv
     * suivant rend ECONNREFUSED une fois, puis EAGAIN. */
    int s = udp(0);
    struct sockaddr_in d = adresse(LO, port_ferme());
    connect(s, (struct sockaddr *)&d, sizeof d);
    char o[64];
    verifier(send(s, "x", 1, 0) == 1, "connectee a un port ferme : send reussit");
    struct pollfd p = { s, POLLIN | POLLOUT, 0 };
    verifier(attendre_erreur(s) && poll(&p, 1, 0) == 1 && p.revents == (POLLOUT | POLLERR), "l'ICMP revient : POLLOUT | POLLERR");
    verifier(erreur(recv(s, o, sizeof o, MSG_DONTWAIT)) == ECONNREFUSED && erreur(recv(s, o, sizeof o, MSG_DONTWAIT)) == EAGAIN,
             "recv : ECONNREFUSED une fois, puis EAGAIN");
    /* Au send aussi : celui qui suit l'erreur la rend. Par lo, elle est là
     * avant que le send qui l'a provoquée ne revienne : le suivant la rend
     * tout de suite. */
    send(s, "x", 1, 0);
    verifier(erreur(send(s, "x", 1, 0)) == ECONNREFUSED, "send juste apres : ECONNREFUSED (lo livre l'erreur avant le retour)");
    send(s, "x", 1, 0);
    attendre_erreur(s);
    int v;
    socklen_t l = sizeof v;
    int ok = getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &l) == 0 && v == ECONNREFUSED;
    verifier(ok && getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &l) == 0 && v == 0, "SO_ERROR : 111, puis effacee");
    send(s, "x", 1, 0);
    attendre_erreur(s);
    struct iovec iv = { o, sizeof o };
    struct mmsghdr mm = { .msg_hdr = { .msg_iov = &iv, .msg_iovlen = 1 } };
    verifier(erreur(recvmmsg(s, &mm, 1, MSG_DONTWAIT, NULL)) == ECONNREFUSED, "recvmmsg : l'erreur en attente d'abord");
    close(s);

    /* Non connectée : rien ; avec IP_RECVERR, la file d'erreurs. */
    s = udp(0);
    uint16_t ferme = port_ferme();
    envoyer(s, "rien", 4, ferme);
    attendre_lo();
    verifier(erreur(recv(s, o, sizeof o, MSG_DONTWAIT)) == EAGAIN, "non connectee, port ferme : aucune erreur");
    int un = 1;
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    setsockopt(s, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    envoyer(s, "origine", 7, ferme);
    struct sock_extended_err ee;
    struct sockaddr_in offender, nom;
    struct in_pktinfo pi;
    int drapeaux = 0;
    verifier(attendre_erreur(s), "avec IP_RECVERR : POLLERR");
    long n = erreur_en_file(s, o, sizeof o, &ee, &offender, &nom, &drapeaux, &pi);
    verifier(n == 7 && memcmp(o, "origine", 7) == 0 && (drapeaux & MSG_ERRQUEUE), "MSG_ERRQUEUE : le datagramme d'origine, MSG_ERRQUEUE");
    verifier(ee.ee_errno == ECONNREFUSED && ee.ee_origin == SO_EE_ORIGIN_ICMP && ee.ee_type == ICMP_DEST_UNREACH
                 && ee.ee_code == ICMP_PORT_UNREACH && offender.sin_family == AF_INET && offender.sin_addr.s_addr == htonl(LO)
                 && nom.sin_addr.s_addr == htonl(LO) && ntohs(nom.sin_port) == ferme,
             "sock_extended_err : 111, ICMP 3/3, de 127.0.0.1 ; le nom : la destination");
    /* L'IP_PKTINFO d'une erreur : celui du message ICMP, que rien n'a
     * préparé (l'adresse locale est nulle). */
    verifier(pi.ipi_ifindex == 1 && pi.ipi_spec_dst.s_addr == 0 && pi.ipi_addr.s_addr == htonl(LO),
             "IP_PKTINFO de l'erreur : lo (1), 0.0.0.0, 127.0.0.1");
    verifier(erreur(recv(s, o, sizeof o, MSG_DONTWAIT)) == EAGAIN && erreur(recvmsg(s, &(struct msghdr){ 0 }, MSG_ERRQUEUE)) == EAGAIN,
             "puis plus rien : recv et MSG_ERRQUEUE rendent EAGAIN");
    /* L'erreur locale d'EMSGSIZE : la destination, le port de la connexion
     * (0 : pas connectée), la MTU de lo bornée à 65 535. */
    static char gros[65508];
    verifier(erreur(envoyer(s, gros, sizeof gros, ferme)) == EMSGSIZE, "65 508 octets avec IP_RECVERR : EMSGSIZE");
    n = erreur_en_file(s, o, sizeof o, &ee, &offender, &nom, &drapeaux, &pi);
    verifier(n == 0 && ee.ee_errno == EMSGSIZE && ee.ee_origin == SO_EE_ORIGIN_LOCAL && ee.ee_info == 65535
                 && offender.sin_family == 0 && nom.sin_addr.s_addr == htonl(LO) && nom.sin_port == 0 && pi.ipi_ifindex == 0,
             "et l'erreur locale en file : 90, origine 1, ee_info 65 535, sans IP_PKTINFO");
    close(s);

    /* Une socket de ping, si l'hôte la permet (ping_group_range). */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (q >= 0) {
        struct icmphdr e = { .type = ICMP_ECHO, .un.echo = { .id = htons(0x1234), .sequence = htons(7) } };
        char m[sizeof e + 4];
        memcpy(m, &e, sizeof e);
        memcpy(m + sizeof e, "ping", 4);
        d = adresse(LO, 0);
        verifier(sendto(q, m, sizeof m, 0, (struct sockaddr *)&d, sizeof d) == sizeof m, "ping de 127.0.0.1 : l'echo part");
        struct sockaddr_in a;
        l = sizeof a;
        getsockname(q, (struct sockaddr *)&a, &l);
        char r[64];
        l = sizeof d;
        n = recvfrom(q, r, sizeof r, 0, (struct sockaddr *)&d, &l);
        struct icmphdr *h = (struct icmphdr *)r;
        verifier(n == (long)sizeof m && h->type == ICMP_ECHOREPLY && h->code == 0 && h->un.echo.id == a.sin_port
                     && ntohs(h->un.echo.sequence) == 7 && memcmp(r + sizeof e, "ping", 4) == 0
                     && d.sin_addr.s_addr == htonl(LO) && d.sin_port == 0,
                 "la reponse, sans en-tete IP, de 127.0.0.1:0 ; l'identifiant est le port de la socket");
        e.type = ICMP_TIMESTAMP;
        verifier(erreur(sendto(q, &e, sizeof e, 0, (struct sockaddr *)&d, sizeof d)) == EINVAL
                     && erreur(sendto(q, m, 4, 0, (struct sockaddr *)&d, sizeof d)) == EINVAL,
                 "ping : un autre genre que l'echo, ou moins de 8 octets : EINVAL");
        int f;
        verifier(ioctl(q, FIONREAD, &f) == -1 && errno == ENOTTY, "ping : FIONREAD : ENOTTY");
        /* MSG_OOB : refusé avant tout par ping, ignoré par UDP. */
        int u = udp(0);
        verifier(erreur(recv(q, r, sizeof r, MSG_OOB | MSG_DONTWAIT)) == EOPNOTSUPP
                     && erreur(recv(q, r, sizeof r, MSG_OOB | MSG_ERRQUEUE)) == EOPNOTSUPP
                     && erreur(recv(u, r, sizeof r, MSG_OOB | MSG_DONTWAIT)) == EAGAIN,
                 "ping : recv avec MSG_OOB : EOPNOTSUPP, meme avec MSG_ERRQUEUE (UDP : EAGAIN)");
        close(u);
        close(q);
        /* Ni diffusion ni multidiffusion pour une socket de ping, que UDP
         * accepte. */
        ok = 1;
        for (int k = 0; k < 3; k++) {
            uint32_t ad[] = { 0xffffffff, 0x7fffffff, 0xe0000001 };
            struct sockaddr_in b = adresse(ad[k], 0);
            q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
            u = udp(0);
            ok = ok && erreur(bind(q, (struct sockaddr *)&b, sizeof b)) == EADDRNOTAVAIL
                    && bind(u, (struct sockaddr *)&b, sizeof b) == 0;
            close(q);
            close(u);
        }
        verifier(ok, "ping : bind a 255.255.255.255, 127.255.255.255, 224.0.0.1 : EADDRNOTAVAIL (UDP : accepte)");
    }
    verifier(erreur(socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == EPERM && erreur(socket(AF_INET, SOCK_RAW, 0)) == EPROTONOSUPPORT,
             "SOCK_RAW sans CAP_NET_RAW : EPERM ; de protocole 0 : EPROTONOSUPPORT");
}

int main(void)
{
    creation();
    lier();
    filtre();
    datagrammes();
    options();
    fichier();
    attentes();
    file_pleine();
    aller_retour();
    routes_et_messages();
    icmp();
    printf("[linux] reseau : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
