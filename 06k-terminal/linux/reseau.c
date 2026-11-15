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
 *     (EPERM ; EPROTONOSUPPORT pour le protocole 0) ;
 *   - deux choses sortent de lo (les soldes d'avant 6k ; sautées sur une
 *     machine sans carte, le réseau de la carte lu dans /proc/net/route) :
 *     une diffusion envoyée par la carte revient une fois, entière, aux
 *     sockets de la machine, comme arrivée par la carte ; et SO_SNDBUF fait
 *     attendre les envois vers une machine muette du réseau, dont les
 *     datagrammes restent dans la file du voisin (EAGAIN, POLLOUT,
 *     SO_SNDTIMEO) ;
 *   - le bouchon d'UDP (MSG_MORE, UDP_CORK ; les soldes d'avant 6k) : les
 *     envois s'assemblent en un datagramme, vers la destination du premier
 *     (celles des suivants, et leurs messages de contrôle, ne comptent
 *     pas), SIOCOUTQ le voit grandir, plus de 65 507 octets en tout le
 *     vident (EMSGSIZE, l'erreur locale), un shutdown ne l'arrête pas, une
 *     déconnexion lui laisse le port d'alors (0 sans nouvel envoi), close
 *     le perd, sendfile bouche ses rondes et pousse à la fin du fichier ;
 *   - les options de SOL_IP (les soldes d'avant 6k), une à une, pour UDP et
 *     ping, puis IP_FREEBIND (et la source qui n'est pas à nous :
 *     ENETUNREACH), IP_BIND_ADDRESS_NO_PORT, IP_LOCAL_PORT_RANGE ;
 *   - les messages de contrôle de la réception IP (les soldes d'avant 6k),
 *     dans l'ordre de Linux, d'un datagramme, d'une réponse de ping et
 *     d'une erreur en file ; `reseau carte`, que lance make tests-qemu
 *     (test-carte) : ceux de datagrammes envoyés par l'hôte, venus par la
 *     carte (la somme d'UDP, la taille des morceaux) ; puis l'écoute TCP à
 *     qui le scénario envoie des segments (le Makefile vérifie les
 *     réponses), et deux erreurs ICMP qui portent des extensions (RFC 4884 :
 *     IP_RECVERR_RFC4884, le `ee_data` de l'erreur en file).
 * Sur l'hôte comme chez nous. Les délais sont des multiples de 4 ms (le
 * tic du noyau : HZ = 250 sous WSL, 1000 sous le Linux de référence).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
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

/* MSG_PROBE : chercher la route sans rien envoyer (Linux, 0x10 ; la glibc
 * ne le nomme que pour _GNU_SOURCE). */
#ifndef MSG_PROBE
#define MSG_PROBE 0x10
#endif

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

static ssize_t envoyer_drapeaux(int s, const void *o, size_t n, int drapeaux, uint16_t port)
{
    struct sockaddr_in a = adresse(LO, port);
    return sendto(s, o, n, drapeaux, (struct sockaddr *)&a, sizeof a);
}

static ssize_t envoyer(int s, const void *o, size_t n, uint16_t port)
{
    return envoyer_drapeaux(s, o, n, 0, port);
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

/* La plage des ports éphémères : celle de la machine, ou celle de Linux par
 * défaut, si elle ne le dit pas. */
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
    /* Le plafond d'une demande : `rmem_max`, 4 Mio dans Linux 6.18. C'est un
     * réglage : l'hôte le dit dans /proc, s'il l'a changé (ou un noyau plus
     * ancien, 212 992) ; sans ce fichier, la valeur de la source. */
    int rmem_max = 4 << 20;
    FILE *f = fopen("/proc/sys/net/core/rmem_max", "r");
    if (f) {
        if (fscanf(f, "%d", &rmem_max) != 1)
            rmem_max = -1;
        fclose(f);
    }
    v = rmem_max + 4096;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &l);
    verifier(v == 2 * rmem_max, "SO_RCVBUF borne par rmem_max, puis double");
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
    /* IP_TOS de 256 : l'octet reste 0, mais l'entier diffère de l'ancien
     * octet (`__ip_sock_set_tos` les compare) : SO_PRIORITY suit, 0. */
    val = 256;
    setsockopt(s, IPPROTO_IP, IP_TOS, &val, sizeof val);
    verifier(getsockopt(s, SOL_SOCKET, SO_PRIORITY, &val, &l) == 0 && val == 0, "IP_TOS de 256 : SO_PRIORITY 0 (l'entier compare)");

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

    /* Une socket de ping : permise par un Ubuntu (ping_group_range, que systemd ouvre à tous),
     * par Docker, par le Linux de référence et par nous ; pas par le noyau seul (« 1 0 »). */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    verifier(q >= 0, "une socket de ping, permise (ping_group_range)");
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
        /* SOL_UDP : sauté par ping (`ip_cmsg_send` ne lit que SOL_IP et
         * SOL_SOCKET), un genre inconnu compris ; l'écho part. */
        char oc[CMSG_SPACE(sizeof(int))] = { 0 };
        struct iovec iv = { m, sizeof m };
        struct msghdr mh = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &iv, .msg_iovlen = 1, .msg_control = oc,
                             .msg_controllen = sizeof oc };
        struct cmsghdr *ch = CMSG_FIRSTHDR(&mh);
        ch->cmsg_level = IPPROTO_UDP;
        ch->cmsg_type = 103;
        ch->cmsg_len = CMSG_LEN(sizeof(int));
        long km = sendmsg(q, &mh, 0);
        long nm = recv(q, r, sizeof r, 0);
        verifier(km == (long)sizeof m && nm == (long)sizeof m, "ping : un message de controle de SOL_UDP est saute, l'echo part");
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

/* SO_PEEK_OFF (`udp_set_peek_off`) : le décalage passe d'un datagramme à l'autre. */
static int peek_lu(int s)
{
    int v = -99;
    socklen_t n = sizeof v;
    if (getsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &v, &n) < 0)
        return -1000 - errno;
    return v;
}

static void decalage_de_peek(void)
{
    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0), v;
    struct sockaddr_in x = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t n = sizeof x;
    char o[16];
    long r;
    bind(b, (void *)&x, sizeof x);
    getsockname(b, (void *)&x, &n);
    connect(a, (void *)&x, sizeof x);
    verifier(peek_lu(b) == -1, "SO_PEEK_OFF : -1 au depart");
    send(a, "abcd", 4, 0);
    send(a, "efgh", 4, 0);
    v = 1;
    setsockopt(b, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v);
    verifier(peek_lu(b) == 1, "SO_PEEK_OFF : relu");
    r = recv(b, o, 2, MSG_PEEK);
    verifier(r == 2 && !memcmp(o, "bc", 2) && peek_lu(b) == 3, "SO_PEEK_OFF 1 : bc, il avance");
    r = recv(b, o, 10, MSG_PEEK);
    verifier(r == 1 && o[0] == 'd' && peek_lu(b) == 4, "SO_PEEK_OFF 3 : le reste du premier");
    r = recv(b, o, 10, MSG_PEEK);
    verifier(r == 4 && !memcmp(o, "efgh", 4) && peek_lu(b) == 8, "SO_PEEK_OFF 4 : le second");
    r = recv(b, o, 10, MSG_PEEK | MSG_DONTWAIT);
    verifier(r < 0 && errno == EAGAIN && peek_lu(b) == 8, "SO_PEEK_OFF au bout : EAGAIN");
    /* Coupé, ou pas : la place de ce qui reste, et celle du datagramme. */
    struct msghdr m = { 0 };
    struct iovec iv = { o, 3 };
    m.msg_iov = &iv;
    m.msg_iovlen = 1;
    v = 1;
    setsockopt(b, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v);
    r = recvmsg(b, &m, MSG_PEEK);
    verifier(r == 3 && (m.msg_flags & MSG_TRUNC), "juste la place de ce qui reste : MSG_TRUNC (`udp_recvmsg`)");
    v = 1;
    setsockopt(b, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v);
    iv.iov_len = 4;
    m.msg_flags = 0;
    r = recvmsg(b, &m, MSG_PEEK);
    verifier(r == 3 && !(m.msg_flags & MSG_TRUNC), "plus de place que ce qui reste : pas MSG_TRUNC");
    /* MSG_TRUNC : la vraie longueur, et il avance d'autant. */
    v = 1;
    setsockopt(b, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v);
    r = recv(b, o, 2, MSG_PEEK | MSG_TRUNC);
    verifier(r == 4 && peek_lu(b) == 5, "MSG_PEEK | MSG_TRUNC : la vraie longueur, il avance d'autant");
    v = 8;
    setsockopt(b, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v);
    r = recv(b, o, 10, MSG_DONTWAIT);
    verifier(r == 4 && !memcmp(o, "abcd", 4) && peek_lu(b) == 4, "une lecture part de la tete, et le fait reculer");
    r = recv(b, o, 10, MSG_PEEK | MSG_DONTWAIT);
    verifier(r < 0 && errno == EAGAIN && peek_lu(b) == 4, "SO_PEEK_OFF toujours au bout : EAGAIN");
    r = recv(b, o, 10, MSG_DONTWAIT);
    verifier(r == 4 && !memcmp(o, "efgh", 4) && peek_lu(b) == 0, "encore une lecture : 0");
    /* Un datagramme vide se voit une fois. */
    send(a, "", 0, 0);
    send(a, "z", 1, 0);
    r = recv(b, o, 10, MSG_PEEK);
    verifier(r == 0, "SO_PEEK_OFF 0 : le datagramme vide, une fois");
    r = recv(b, o, 10, MSG_PEEK);
    verifier(r == 1 && o[0] == 'z', "SO_PEEK_OFF 0 : puis le suivant");
    /* Négatif : relu tel quel, à la tête. */
    v = -3;
    setsockopt(b, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v);
    verifier(peek_lu(b) == -3, "SO_PEEK_OFF negatif : relu tel quel");
    r = recv(b, o, 10, MSG_PEEK);
    verifier(r == 0 && peek_lu(b) == -3, "SO_PEEK_OFF negatif : la tete, sans y toucher");
    close(a);
    close(b);
    /* Ping n'en a pas. */
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    verifier(p >= 0, "une seconde socket de ping, permise");
    if (p >= 0) {
        v = 1;
        verifier(setsockopt(p, SOL_SOCKET, SO_PEEK_OFF, &v, sizeof v) < 0 && errno == EOPNOTSUPP, "ping : SO_PEEK_OFF, EOPNOTSUPP");
        verifier(peek_lu(p) == -1000 - EOPNOTSUPP, "ping : relu, EOPNOTSUPP");
        close(p);
    }
}

/* Le datagramme reçu par `r` dans la seconde : sa taille (-1 : rien), qui l'a
 * envoyé, et son IP_PKTINFO. */
static ssize_t recu_avec_pktinfo(int r, struct sockaddr_in *de, struct in_pktinfo *pi, int ms)
{
    struct pollfd f = { .fd = r, .events = POLLIN };
    if (poll(&f, 1, ms) != 1)
        return -1;
    static char o[4096];
    char c[CMSG_SPACE(sizeof(struct in_pktinfo))];
    struct iovec v = { o, sizeof o };
    struct msghdr m = { .msg_name = de, .msg_namelen = sizeof *de, .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c };
    ssize_t n = recvmsg(r, &m, MSG_DONTWAIT);
    memset(pi, 0, sizeof *pi);
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h))
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO)
            memcpy(pi, CMSG_DATA(h), sizeof *pi);
    return n;
}

/* L'adresse de diffusion du réseau de la carte (dans l'ordre du réseau) :
 * la première route sans passerelle de /proc/net/route qui ne soit pas lo.
 * Faux : pas de carte. */
static int diffusion_du_reseau(uint32_t *diffusion)
{
    FILE *f = fopen("/proc/net/route", "r");
    char ligne[256], nom[32];
    unsigned destination, passerelle, masque;
    int trouve = 0;
    while (!trouve && f && fgets(ligne, sizeof ligne, f))
        if (sscanf(ligne, "%31s %x %x %*x %*d %*d %*d %x", nom, &destination, &passerelle, &masque) == 4 && strcmp(nom, "lo")
            && passerelle == 0 && masque != 0 && masque != 0xffffffff) {
            *diffusion = destination | ~masque;
            trouve = 1;
        }
    if (f)
        fclose(f);
    return trouve;
}

/* Une diffusion envoyée par la carte revient aux sockets de la machine
 * (`ip_mc_output` : une copie par la boucle, avant tout découpage) : une
 * fois, entière (2000 octets, plus que la MTU), de notre adresse, comme
 * arrivée par la carte (IP_PKTINFO : son interface, pas lo ; la diffusion
 * pour destination ; notre adresse pour répondre) ; de même pour
 * 255.255.255.255. */
static void diffusion_de_la_carte(void)
{
    uint32_t d;
    if (!diffusion_du_reseau(&d)) {
        verifier(1, "pas de carte : la diffusion de la carte, sautee");
        return;
    }
    int un = 1;
    for (int k = 0; k < 2; k++) {
        uint32_t vers = k == 0 ? d : htonl(0xffffffff);
        int r = udp(0), s = udp(0), c = udp(0);
        struct sockaddr_in a = adresse(0, 0), moi, de;
        socklen_t l = sizeof a;
        bind(r, (struct sockaddr *)&a, sizeof a);
        getsockname(r, (struct sockaddr *)&a, &l);
        setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
        setsockopt(s, SOL_SOCKET, SO_BROADCAST, &un, sizeof un);
        setsockopt(c, SOL_SOCKET, SO_BROADCAST, &un, sizeof un);
        a.sin_addr.s_addr = vers;
        /* Notre adresse : celle que prend une socket connectée à la diffusion. */
        l = sizeof moi;
        int pret = connect(c, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(c, (struct sockaddr *)&moi, &l) == 0;
        static char gros[2000];
        pret = pret && sendto(s, gros, sizeof gros, 0, (struct sockaddr *)&a, sizeof a) == (ssize_t)sizeof gros;
        struct in_pktinfo pi;
        ssize_t n = recu_avec_pktinfo(r, &de, &pi, 1000);
        int ok = pret && n == (ssize_t)sizeof gros && de.sin_addr.s_addr == moi.sin_addr.s_addr && pi.ipi_ifindex > 1
                 && pi.ipi_addr.s_addr == vers && pi.ipi_spec_dst.s_addr == moi.sin_addr.s_addr;
        ok = ok && recu_avec_pktinfo(r, &de, &pi, 200) == -1;
        verifier(ok, k == 0 ? "la diffusion de la carte revient une fois, entiere, comme arrivee par la carte"
                            : "255.255.255.255 revient une fois, entiere, comme arrivee par la carte");
        close(r);
        close(s);
        close(c);
    }
}

/* SO_SNDBUF fait attendre un envoi (les soldes d'avant 6k) : un datagramme
 * compte dans SO_SNDBUF de sa socket (le `sk_wmem_alloc` de Linux) jusqu'à
 * ce que la carte l'ait fini, ou qu'il soit jeté. Vers une machine muette
 * du réseau de la carte (l'avant-dernière adresse, que personne ne prend :
 * ni QEMU ni Docker n'y répondent), il reste dans la file du voisin jusqu'à
 * l'échec de la résolution (trois requêtes ARP, une par seconde). Avec
 * SO_SNDBUF au minimum : quelques envois MSG_DONTWAIT, puis EAGAIN ; poll ne
 * dit plus POLLOUT ; un envoi bloquant attend SO_SNDTIMEO (200 ms), puis
 * rend EAGAIN ; sans délai, un envoi (vers lo : il ne laisse rien dans la
 * file du voisin) attend, dans un autre fil, pendant que poll attend
 * POLLOUT : les deux reviennent à l'échec de la résolution. Le nombre
 * d'envois avant EAGAIN n'est pas comparé : il dépend de la taille vraie des
 * paquets, qui n'est pas la même chez nous. */
struct envoi_bloquant {
    int s;
    struct sockaddr_in vers;
    ssize_t n;
    double duree;
};

static void *envoyer_en_attendant(void *p)
{
    struct envoi_bloquant *e = p;
    static char c[100];
    double t = maintenant();
    e->n = sendto(e->s, c, sizeof c, 0, (struct sockaddr *)&e->vers, sizeof e->vers);
    e->duree = maintenant() - t;
    return NULL;
}

static void sndbuf_attend(void)
{
    uint32_t d;
    if (!diffusion_du_reseau(&d)) {
        verifier(1, "pas de carte : SO_SNDBUF vers une machine muette, saute");
        return;
    }
    struct sockaddr_in a = adresse(ntohl(d) - 2, 9);
    int s = udp(0), un = 1;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &un, sizeof un);
    static char c[1000];
    int n = 0, e = 0;
    while (n < 20 && sendto(s, c, sizeof c, MSG_DONTWAIT, (struct sockaddr *)&a, sizeof a) == (ssize_t)sizeof c)
        n++;
    e = errno;
    verifier(n >= 1 && n <= 10 && e == EAGAIN, "SO_SNDBUF au minimum, vers une machine muette : quelques envois, puis EAGAIN");
    struct pollfd p = { .fd = s, .events = POLLOUT };
    verifier(poll(&p, 1, 0) == 0, "la place manque : plus de POLLOUT");
    struct timeval tv = { .tv_usec = 200000 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    double t = maintenant();
    ssize_t k = sendto(s, c, sizeof c, 0, (struct sockaddr *)&a, sizeof a);
    e = errno;
    double duree = maintenant() - t;
    verifier(k < 0 && e == EAGAIN && duree >= 0.19 && duree < 1, "un envoi bloquant attend SO_SNDTIMEO (200 ms), puis EAGAIN");
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    int r = udp(0);
    struct sockaddr_in moi = adresse(INADDR_LOOPBACK, 0);
    socklen_t l = sizeof moi;
    bind(r, (struct sockaddr *)&moi, sizeof moi);
    getsockname(r, (struct sockaddr *)&moi, &l);
    struct envoi_bloquant b = { .s = s, .vers = moi };
    pthread_t f;
    pthread_create(&f, NULL, envoyer_en_attendant, &b);
    t = maintenant();
    int pr = poll(&p, 1, 10000);
    duree = maintenant() - t;
    pthread_join(f, NULL);
    verifier(pr == 1 && (p.revents & POLLOUT) && duree >= 0.5 && duree <= 8,
             "POLLOUT revient a l'echec de la resolution (de 0,5 a 8 s)");
    verifier(b.n == 100 && b.duree >= 0.5 && b.duree <= 8, "sans delai, un envoi attend l'echec de la resolution, puis part");
    close(r);
    close(s);
}

/* Le datagramme qui attend sur r (sans attendre), dans o ; son port
 * source dans *port. Rend sa longueur, ou -1. */
static ssize_t datagramme_de(int r, char *o, size_t n, uint16_t *port)
{
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    ssize_t k = recvfrom(r, o, n, MSG_DONTWAIT, (struct sockaddr *)&a, &l);
    if (port)
        *port = ntohs(a.sin_port);
    return k;
}

static int bouchee(int s, int oui)
{
    return setsockopt(s, SOL_UDP, UDP_CORK, &oui, sizeof oui);
}

static int connectee_a(uint16_t port)
{
    int s = udp(0);
    struct sockaddr_in a = adresse(LO, port);
    connect(s, (struct sockaddr *)&a, sizeof a);
    return s;
}

static void bouchon(void)
{
    static char o[70000];
    uint16_t pa, pb, de;
    int ra = liee(&pa), rb = liee(&pb);
    int s = udp(0);

    /* MSG_MORE, puis un envoi sans : un seul datagramme. */
    ssize_t k1 = envoyer_drapeaux(s, "ab", 2, MSG_MORE, pa);
    int vide = datagramme_de(ra, o, sizeof o, NULL) < 0 && errno == EAGAIN;
    ssize_t k2 = envoyer(s, "cd", 2, pa);
    ssize_t n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(k1 == 2 && vide && k2 == 2 && n == 4 && memcmp(o, "abcd", 4) == 0 && datagramme_de(ra, o, sizeof o, NULL) < 0,
             "MSG_MORE : rien ne part, puis un seul datagramme (abcd)");

    /* UDP_CORK : l'option, SIOCOUTQ, POLLOUT, et le départ en la retirant. */
    int v = -1;
    socklen_t l = sizeof v;
    getsockopt(s, SOL_UDP, UDP_CORK, &v, &l);
    int deux = 2, r1 = setsockopt(s, SOL_UDP, UDP_CORK, &deux, sizeof deux), v2 = -1;
    l = sizeof v2;
    getsockopt(s, SOL_UDP, UDP_CORK, &v2, &l);
    char c1 = 1;
    int court = erreur(setsockopt(s, SOL_UDP, UDP_CORK, &c1, 1));
    char un_octet = -1;
    socklen_t l1 = 1;
    getsockopt(s, SOL_UDP, UDP_CORK, &un_octet, &l1);
    verifier(v == 0 && r1 == 0 && v2 == 1 && l == 4 && court == EINVAL && un_octet == 1 && l1 == 1,
             "UDP_CORK : 0, puis 1 (pour 2) ; 1 octet : EINVAL a l'ecriture, 1 octet a la lecture");
    int q0 = -1, q1 = -1, q2 = -1, q3 = -1;
    ioctl(s, SIOCOUTQ, &q0);
    envoyer(s, o, 100, pa);
    ioctl(s, SIOCOUTQ, &q1);
    envoyer(s, o, 1000, pa);
    ioctl(s, SIOCOUTQ, &q2);
    struct pollfd p = { .fd = s, .events = POLLOUT };
    int pr = poll(&p, 1, 0);
    vide = datagramme_de(ra, o, sizeof o, NULL) < 0;
    bouchee(s, 0);
    n = datagramme_de(ra, o, sizeof o, NULL);
    ioctl(s, SIOCOUTQ, &q3);
    verifier(q0 == 0 && q1 > 100 && q2 - q1 == 1000 && pr == 1 && vide && n == 1100 && q3 == 0,
             "UDP_CORK : SIOCOUTQ grandit de chaque ajout, POLLOUT reste ; retire, un datagramme de 1100, SIOCOUTQ 0");

    /* La destination et les messages de contrôle des envois suivants ne
     * comptent pas (une adresse de port 0, un IP_TTL de 300) ; write ajoute
     * aussi, sans destination. */
    envoyer_drapeaux(s, "ab", 2, MSG_MORE, pa);
    ssize_t k0 = envoyer_drapeaux(s, "cd", 2, MSG_MORE, 0);
    char c[CMSG_SPACE(sizeof(int))] = { 0 };
    struct iovec iv = { "ef", 2 };
    struct sockaddr_in b = adresse(LO, pb);
    struct msghdr m = { .msg_name = &b, .msg_namelen = sizeof b, .msg_iov = &iv, .msg_iovlen = 1,
                        .msg_control = c, .msg_controllen = sizeof c };
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = IPPROTO_IP;
    h->cmsg_type = IP_TTL;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(h) = 300;
    ssize_t kt = sendmsg(s, &m, MSG_MORE);
    ssize_t kw = write(s, "gh", 2);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(k0 == 2 && kt == 2 && kw == 2 && n == 8 && memcmp(o, "abcdefgh", 8) == 0 && datagramme_de(rb, o, sizeof o, NULL) < 0,
             "bouchee : le port 0, un IP_TTL de 300 et write passent ; tout va a la premiere destination");
    verifier(erreur(sendmsg(s, &m, 0)) == EINVAL && datagramme_de(rb, o, sizeof o, NULL) < 0, "sans bouchon, l'IP_TTL de 300 : EINVAL");

    /* Plus de 65 535 octets, MSG_OOB : refusés avant le bouchon, qui reste. */
    envoyer_drapeaux(s, "ab", 2, MSG_MORE, pa);
    int e70000 = erreur(envoyer(s, o, 70000, pa));
    int eoob = erreur(envoyer_drapeaux(s, "cd", 2, MSG_OOB, pa));
    envoyer(s, "ef", 2, pa);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(e70000 == EMSGSIZE && eoob == EOPNOTSUPP && n == 4 && memcmp(o, "abef", 4) == 0,
             "bouchee : 70 000 octets (EMSGSIZE) et MSG_OOB (EOPNOTSUPP) laissent le bouchon");

    /* Trop en tout : EMSGSIZE, l'erreur locale, et le bouchon vidé. */
    int un = 1;
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    ssize_t k60 = envoyer_drapeaux(s, o, 60000, MSG_MORE, pa);
    int etrop = erreur(envoyer_drapeaux(s, o, 5508, MSG_MORE, pa));
    struct sock_extended_err ee;
    struct sockaddr_in offender, nom;
    struct in_pktinfo pi;
    int drapeaux;
    long nl = erreur_en_file(s, o, sizeof o, &ee, &offender, &nom, &drapeaux, &pi);
    ssize_t k5507 = envoyer(s, o, 5507, pa);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(k60 == 60000 && etrop == EMSGSIZE && nl == 0 && ee.ee_errno == EMSGSIZE && ee.ee_origin == SO_EE_ORIGIN_LOCAL
             && ee.ee_info == 65535 && k5507 == 5507 && n == 5507,
             "60 000 octets bouches, puis 5 508 : EMSGSIZE, l'erreur locale (ee_info 65 535), et le bouchon vide");
    int e65508 = erreur(envoyer_drapeaux(s, o, 65508, MSG_MORE, pa));
    envoyer(s, "y", 1, pa);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(e65508 == EMSGSIZE && n == 1, "65 508 octets avec MSG_MORE : EMSGSIZE, rien ne reste");
    un = 0;
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);

    /* Un envoi vide avec MSG_MORE bouche aussi ; close perd le bouchon. */
    envoyer_drapeaux(s, "", 0, MSG_MORE, pa);
    envoyer(s, "ab", 2, pa);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(n == 2 && datagramme_de(ra, o, sizeof o, NULL) < 0, "un envoi vide avec MSG_MORE, puis 2 octets : un datagramme de 2");
    envoyer_drapeaux(s, "ab", 2, MSG_MORE, pa);
    close(s);
    attendre_lo();
    verifier(datagramme_de(ra, o, sizeof o, NULL) < 0, "close perd le bouchon");

    /* Un shutdown n'arrête ni l'ajout, ni le départ ; avant le premier
     * envoi, EPIPE. */
    s = connectee_a(pa);
    envoyer_drapeaux(s, "ab", 2, MSG_MORE, pa);
    shutdown(s, SHUT_WR);
    ssize_t ks1 = send(s, "cd", 2, MSG_MORE), ks2 = send(s, "ef", 2, 0);
    n = datagramme_de(ra, o, sizeof o, NULL);
    int epipe = erreur(send(s, "gh", 2, MSG_MORE));
    verifier(ks1 == 2 && ks2 == 2 && n == 6 && memcmp(o, "abcdef", 6) == 0 && epipe == EPIPE,
             "shutdown pendant le bouchon : l'ajout et le depart passent ; puis EPIPE");
    close(s);

    /* La déconnexion rend le port éphémère : le datagramme part avec le
     * port d'alors (un nouveau, pris par l'envoi qui pousse ; 0 si c'est
     * UDP_CORK retiré). */
    s = connectee_a(pa);
    struct sockaddr_in moi;
    l = sizeof moi;
    getsockname(s, (struct sockaddr *)&moi, &l);
    send(s, "ab", 2, MSG_MORE);
    struct sockaddr_in rien = { .sin_family = AF_UNSPEC };
    connect(s, (struct sockaddr *)&rien, sizeof rien);
    ssize_t kd = send(s, "cd", 2, 0);
    n = datagramme_de(ra, o, sizeof o, &de);
    verifier(kd == 2 && n == 4 && de != 0 && de != ntohs(moi.sin_port),
             "bouchee, deconnectee : send ajoute, et le datagramme part d'un nouveau port");
    close(s);
    s = connectee_a(pa);
    bouchee(s, 1);
    send(s, "ab", 2, 0);
    connect(s, (struct sockaddr *)&rien, sizeof rien);
    bouchee(s, 0);
    n = datagramme_de(ra, o, sizeof o, &de);
    verifier(n == 2 && de == 0, "UDP_CORK, deconnectee, puis retire : le datagramme part du port 0");
    close(s);

    /* sendfile : ses rondes bouchent ; la fin du fichier pousse, sauf
     * UDP_CORK ; plus de 65 507 octets : EMSGSIZE. */
    char chemin[] = "/tmp/reseau-XXXXXX";
    int f = mkstemp(chemin);
    unlink(chemin);
    memset(o, 'q', 3000);
    int ecrit = write(f, o, 3000) == 3000;
    s = connectee_a(pa);
    off_t pos = 0;
    ssize_t kf = sendfile(s, f, &pos, 100000);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(ecrit && kf == 3000 && n == 3000 && datagramme_de(ra, o, sizeof o, NULL) < 0,
             "sendfile de 100 000 octets d'un fichier de 3 000 : un datagramme de 3 000");
    bouchee(s, 1);
    pos = 0;
    kf = sendfile(s, f, &pos, 100000);
    vide = datagramme_de(ra, o, sizeof o, NULL) < 0;
    bouchee(s, 0);
    n = datagramme_de(ra, o, sizeof o, NULL);
    verifier(kf == 3000 && vide && n == 3000, "avec UDP_CORK, sendfile attend qu'on le retire");
    memset(o, 1, sizeof o);
    ecrit = ftruncate(f, 0) == 0 && pwrite(f, o, 65536, 0) == 65536 && pwrite(f, o, 34464, 65536) == 34464;
    pos = 0;
    int egros = erreur(sendfile(s, f, &pos, 100000));
    verifier(ecrit && egros == EMSGSIZE && datagramme_de(ra, o, sizeof o, NULL) < 0, "sendfile d'un fichier de 100 000 octets : EMSGSIZE");
    close(s);
    close(f);

    /* MSG_PROBE (tracepath) : la route seulement, rien ne part, sans
     * regarder la taille (65 508 octets passent) ; bouchée, sans MSG_MORE,
     * il pousse le bouchon sans ses octets ; avec MSG_MORE, il ne bouche
     * pas ; une diffusion sans SO_BROADCAST : EACCES (la route le dit). */
    s = udp(0);
    ssize_t kp = envoyer_drapeaux(s, "abcd", 4, MSG_PROBE, pa);
    attendre_lo();
    int rien_parti = datagramme_de(ra, o, sizeof o, NULL) < 0;
    ssize_t kg = envoyer_drapeaux(s, o, 65508, MSG_PROBE, pa);
    envoyer_drapeaux(s, "ab", 2, MSG_MORE, pa);
    ssize_t kc = envoyer_drapeaux(s, "cd", 2, MSG_PROBE, pa);
    int ab = datagramme_de(ra, o, sizeof o, NULL) == 2 && memcmp(o, "ab", 2) == 0;
    envoyer_drapeaux(s, "xy", 2, MSG_PROBE | MSG_MORE, pa);
    envoyer(s, "zz", 2, pa);
    int zz = datagramme_de(ra, o, sizeof o, NULL) == 2 && memcmp(o, "zz", 2) == 0;
    struct sockaddr_in tous = { .sin_family = AF_INET, .sin_port = htons(pa), .sin_addr.s_addr = htonl(INADDR_BROADCAST) };
    int eacces = erreur(sendto(s, "a", 1, MSG_PROBE, (struct sockaddr *)&tous, sizeof tous));
    verifier(kp == 4 && rien_parti && kg == 65508 && kc == 2 && ab && zz && eacces == EACCES,
             "MSG_PROBE : rien ne part (65 508 octets compris), il pousse le bouchon sans ses octets, n'en pose pas ; EACCES");
    close(s);

    int t = socket(AF_INET, SOCK_STREAM, 0);
    verifier(erreur(setsockopt(t, SOL_UDP, UDP_CORK, &deux, sizeof deux)) == ENOPROTOOPT, "UDP_CORK d'une socket TCP : ENOPROTOOPT");
    close(t);
    close(ra);
    close(rb);
}

/* Une option de SOL_IP lue dans un entier : sa valeur, ou -1000 - errno. */
static int lire_ip(int s, int option)
{
    int v = -7777;
    socklen_t l = sizeof v;
    if (getsockopt(s, IPPROTO_IP, option, &v, &l) != 0)
        return -1000 - errno;
    return v;
}

static int poser_ip(int s, int option, int v, socklen_t l)
{
    return erreur(setsockopt(s, IPPROTO_IP, option, &v, l));
}

/* Un envoi vers 127.0.0.1:`port` depuis la source `source` d'IP_PKTINFO. */
static int envoyer_depuis_au_port(int s, uint32_t source, uint16_t port)
{
    struct sockaddr_in d = adresse(LO, port);
    char c[CMSG_SPACE(sizeof(struct in_pktinfo))] = { 0 };
    struct iovec v = { "x", 1 };
    struct msghdr m = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c };
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = IPPROTO_IP;
    h->cmsg_type = IP_PKTINFO;
    h->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    ((struct in_pktinfo *)CMSG_DATA(h))->ipi_spec_dst.s_addr = htonl(source);
    return erreur(sendmsg(s, &m, 0));
}

static int envoyer_depuis(int s, uint32_t source)
{
    return envoyer_depuis_au_port(s, source, 9);
}

static uint16_t port_local(int s, uint32_t *ip)
{
    struct sockaddr_in a = { 0 };
    socklen_t l = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &l);
    if (ip)
        *ip = ntohl(a.sin_addr.s_addr);
    return ntohs(a.sin_port);
}

/* Les options de SOL_IP (les soldes d'avant 6k : `do_ip_setsockopt` et
 * `do_ip_getsockopt` de Linux 6.18, mesurés option par option, UDP et ping
 * ensemble ; TCP dans linux/tcp.c), puis leurs effets : IP_FREEBIND et la
 * source qui n'est pas à nous, IP_BIND_ADDRESS_NO_PORT, IP_LOCAL_PORT_RANGE,
 * IP_PROTOCOL. */
static void sol_ip(void)
{
    int racine = getuid() == 0;
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    for (int k = 0; k < 2; k++) {
        int s = k ? q : udp(0);
        const char *qui = k ? "ping" : "UDP";
        char quoi[160];
        if (s < 0)
            continue;
        /* Les drapeaux : 0, puis 1 en entier, en octet ; une longueur nulle vaut 0. */
        static const int drapeaux[] = { IP_RECVOPTS, IP_RETOPTS, IP_RECVTTL, IP_RECVTOS, IP_PASSSEC, IP_RECVORIGDSTADDR,
                                        IP_CHECKSUM, IP_BIND_ADDRESS_NO_PORT, IP_RECVFRAGSIZE, IP_RECVERR_RFC4884, IP_FREEBIND };
        int ok = 1;
        for (unsigned i = 0; i < sizeof drapeaux / sizeof *drapeaux; i++) {
            int o = drapeaux[i];
            unsigned char un = 1;
            ok = ok && lire_ip(s, o) == 0 && poser_ip(s, o, 1, 4) == 0 && lire_ip(s, o) == 1 && poser_ip(s, o, 0, 4) == 0
                 && setsockopt(s, IPPROTO_IP, o, &un, 1) == 0 && lire_ip(s, o) == 1;
            /* Longueur nulle : 0, sauf IP_FREEBIND (EINVAL, sans rien changer). */
            int z = setsockopt(s, IPPROTO_IP, o, &un, 0) == 0 ? 0 : errno;
            ok = ok && (o == IP_FREEBIND ? z == EINVAL && lire_ip(s, o) == 1 : z == 0 && lire_ip(s, o) == 0);
            if (o == IP_FREEBIND)
                poser_ip(s, o, 0, 4);
            if (!ok) {
                printf("[linux] reseau : %s, option %d\n", qui, o);
                break;
            }
        }
        snprintf(quoi, sizeof quoi, "%s : les drapeaux de SOL_IP, 0, poses en entier et en octet, une longueur nulle", qui);
        verifier(ok, quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_HDRINCL et IP_NODEFRAG : ENOPROTOOPT (pas une socket brute), relus 0", qui);
        verifier(poser_ip(s, IP_HDRINCL, 1, 4) == ENOPROTOOPT && poser_ip(s, IP_NODEFRAG, 1, 0) == ENOPROTOOPT && lire_ip(s, IP_HDRINCL) == 0
                     && lire_ip(s, IP_NODEFRAG) == 0, quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_ROUTER_ALERT : EINVAL, meme de longueur nulle ; EFAULT avant ; relu 0", qui);
        verifier(poser_ip(s, IP_ROUTER_ALERT, 1, 4) == EINVAL && poser_ip(s, IP_ROUTER_ALERT, 0, 0) == EINVAL
                     && erreur(setsockopt(s, IPPROTO_IP, IP_ROUTER_ALERT, (void *)8, 4)) == EFAULT && lire_ip(s, IP_ROUTER_ALERT) == 0,
                 quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_PKTOPTIONS : ENOPROTOOPT (TCP seul)", qui);
        verifier(poser_ip(s, IP_PKTOPTIONS, 1, 4) == ENOPROTOOPT && lire_ip(s, IP_PKTOPTIONS) == -1000 - ENOPROTOOPT, quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_IPSEC_POLICY et IP_XFRM_POLICY : %s ; relues : ENOPROTOOPT", qui, racine ? "ENOPROTOOPT" : "EPERM");
        int attendu = racine ? ENOPROTOOPT : EPERM;
        verifier(poser_ip(s, IP_IPSEC_POLICY, 0, 0) == attendu && poser_ip(s, IP_XFRM_POLICY, 1, 4) == attendu
                     && lire_ip(s, IP_IPSEC_POLICY) == -1000 - ENOPROTOOPT && lire_ip(s, IP_XFRM_POLICY) == -1000 - ENOPROTOOPT,
                 quoi);
        if (!racine) {
            snprintf(quoi, sizeof quoi, "%s : IP_TRANSPARENT 1 : EPERM (avant la longueur) ; 0 : permis ; longueur nulle : EINVAL", qui);
            verifier(poser_ip(s, IP_TRANSPARENT, 1, 4) == EPERM && poser_ip(s, IP_TRANSPARENT, 1, 0) == EINVAL
                         && poser_ip(s, IP_TRANSPARENT, 0, 4) == 0 && lire_ip(s, IP_TRANSPARENT) == 0,
                     quoi);
        }
        snprintf(quoi, sizeof quoi, "%s : IP_MINTTL : 0 a 255, longueur nulle : EINVAL", qui);
        verifier(poser_ip(s, IP_MINTTL, 256, 4) == EINVAL && poser_ip(s, IP_MINTTL, -1, 4) == EINVAL && poser_ip(s, IP_MINTTL, 9, 0) == EINVAL
                     && poser_ip(s, IP_MINTTL, 255, 4) == 0 && lire_ip(s, IP_MINTTL) == 255,
                 quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_RECVERR_RFC4884 2 : EINVAL", qui);
        verifier(poser_ip(s, IP_RECVERR_RFC4884, 2, 4) == EINVAL, quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_MULTICAST_TTL : 1, -1 le defaut, 256 et une longueur nulle : EINVAL", qui);
        verifier(lire_ip(s, IP_MULTICAST_TTL) == 1 && poser_ip(s, IP_MULTICAST_TTL, 7, 4) == 0 && lire_ip(s, IP_MULTICAST_TTL) == 7
                     && poser_ip(s, IP_MULTICAST_TTL, -1, 4) == 0 && lire_ip(s, IP_MULTICAST_TTL) == 1
                     && poser_ip(s, IP_MULTICAST_TTL, 256, 4) == EINVAL && poser_ip(s, IP_MULTICAST_TTL, 3, 0) == EINVAL,
                 quoi);
        snprintf(quoi, sizeof quoi, "%s : IP_LOCAL_PORT_RANGE : 4 octets, bas <= haut ; relue telle quelle", qui);
        verifier(poser_ip(s, IP_LOCAL_PORT_RANGE, 0, 1) == EINVAL && poser_ip(s, IP_LOCAL_PORT_RANGE, 0, 8) == EINVAL
                     && poser_ip(s, IP_LOCAL_PORT_RANGE, 50000 | 40000 << 16, 4) == EINVAL
                     && poser_ip(s, IP_LOCAL_PORT_RANGE, (int)(32770u << 16), 4) == 0 && lire_ip(s, IP_LOCAL_PORT_RANGE) == (int)0x80020000,
                 quoi);
        /* Le routage de la multidiffusion (MRT_INIT, 200) : EOPNOTSUPP, sans lire la longueur ni la valeur. */
        int v;
        snprintf(quoi, sizeof quoi, "%s : MRT_INIT : EOPNOTSUPP, avant la longueur et la valeur", qui);
        verifier(erreur(getsockopt(s, IPPROTO_IP, 200, &v, NULL)) == EOPNOTSUPP && erreur(setsockopt(s, IPPROTO_IP, 212, NULL, 4)) == EOPNOTSUPP
                     && lire_ip(s, 213) == -1000 - ENOPROTOOPT,
                 quoi);
        snprintf(quoi, sizeof quoi, "%s : une valeur fautive : EFAULT ; IP_PROTOCOL ne se pose pas", qui);
        verifier(erreur(setsockopt(s, IPPROTO_IP, IP_RECVTTL, (void *)8, 4)) == EFAULT && poser_ip(s, IP_PROTOCOL, 17, 4) == ENOPROTOOPT, quoi);
        if (k == 0)
            close(s);
    }

    /* IP_FREEBIND : bind d'une adresse qui n'est pas à nous ; envoyer ou se
     * connecter depuis elle : ENETUNREACH (sa route). */
    int s = udp(0);
    struct sockaddr_in a = adresse(DOC, 0), d = adresse(LO, 9);
    int r = erreur(bind(s, (struct sockaddr *)&a, sizeof a));
    poser_ip(s, IP_FREEBIND, 1, 4);
    uint32_t ip;
    verifier(r == EADDRNOTAVAIL && bind(s, (struct sockaddr *)&a, sizeof a) == 0 && port_local(s, &ip) != 0 && ip == DOC,
             "IP_FREEBIND : bind de 192.0.2.1 (EADDRNOTAVAIL sans lui)");
    verifier(erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&d, sizeof d)) == ENETUNREACH
                 && erreur(connect(s, (struct sockaddr *)&d, sizeof d)) == ENETUNREACH,
             "IP_FREEBIND : sendto et connect depuis 192.0.2.1 : ENETUNREACH");
    close(s);
    s = udp(0);
    verifier(envoyer_depuis(s, DOC) == ENETUNREACH && envoyer_depuis(s, 0x00010203) == ENETUNREACH && envoyer_depuis(s, 0xe0000001) == EINVAL
                 && envoyer_depuis(s, 0xffffffff) == EINVAL && envoyer_depuis(s, LO + 1) == 0,
             "IP_PKTINFO d'une source : pas a nous, ENETUNREACH ; multidiffusion ou diffusion, EINVAL ; 127.0.0.2, permise");
    close(s);
    /* IP_PKTINFO remplace l'adresse liée, même par 0.0.0.0 (`ip_cmsg_send` :
     * `ipc->addr`) : la route choisit alors la source, comme sans bind (vers
     * 127.0.0.1 : elle-même). Sans IP_PKTINFO, l'adresse liée. */
    {
        uint16_t port;
        int t = liee(&port);
        struct sockaddr_in b = adresse(LO + 1, 0), de;
        struct in_pktinfo pi;
        s = udp(0);
        int ok = bind(s, (struct sockaddr *)&b, sizeof b) == 0;
        ok = ok && envoyer_depuis_au_port(s, 0, port) == 0 && recu_avec_pktinfo(t, &de, &pi, 1000) == 1 && de.sin_addr.s_addr == htonl(LO);
        b = adresse(LO, port);
        ok = ok && sendto(s, "x", 1, 0, (struct sockaddr *)&b, sizeof b) == 1 && recu_avec_pktinfo(t, &de, &pi, 1000) == 1
             && de.sin_addr.s_addr == htonl(LO + 1);
        verifier(ok, "IP_PKTINFO d'une source 0.0.0.0, liee a 127.0.0.2 : celle de la route (127.0.0.1)");
        close(s);
        close(t);
    }
    if (q >= 0) {
        int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        struct sockaddr_in m = adresse(0xe0000001, 0);
        poser_ip(p, IP_FREEBIND, 1, 4);
        verifier(bind(p, (struct sockaddr *)&m, sizeof m) < 0 && errno == EADDRNOTAVAIL && bind(p, (struct sockaddr *)&a, sizeof a) == 0,
                 "ping et IP_FREEBIND : 192.0.2.1 permise, une multidiffusion non");
        close(p);
        close(q);
    }

    /* IP_BIND_ADDRESS_NO_PORT : bind sans port ; un second bind est permis ;
     * le port vient au connect, la déconnexion le rend et garde l'adresse. */
    s = udp(0);
    poser_ip(s, IP_BIND_ADDRESS_NO_PORT, 1, 4);
    a = adresse(LO, 0);
    int ok = bind(s, (struct sockaddr *)&a, sizeof a) == 0 && port_local(s, &ip) == 0 && ip == LO && lire_ip(s, IP_PROTOCOL) == 0
             && bind(s, (struct sockaddr *)&a, sizeof a) == 0;
    uint16_t pc = connect(s, (struct sockaddr *)&d, sizeof d) == 0 ? port_local(s, &ip) : 0;
    ok = ok && pc != 0 && ip == LO && lire_ip(s, IP_PROTOCOL) == pc;
    struct sockaddr u = { .sa_family = AF_UNSPEC };
    verifier(ok && connect(s, &u, sizeof u) == 0 && port_local(s, &ip) == 0 && ip == LO,
             "IP_BIND_ADDRESS_NO_PORT : bind sans port (deux fois), le port au connect, rendu a la deconnexion");
    close(s);

    /* IP_LOCAL_PORT_RANGE : le port éphémère dans la plage de la socket ;
     * une plage hors de celle du système est ignorée. */
    int t[3];
    for (int i = 0; i < 3; i++) {
        t[i] = udp(0);
        poser_ip(t[i], IP_LOCAL_PORT_RANGE, 40000 | 40001 << 16, 4);
    }
    a = adresse(0, 0);
    r = erreur(bind(t[0], (struct sockaddr *)&a, sizeof a)) + erreur(bind(t[1], (struct sockaddr *)&a, sizeof a));
    uint16_t p0 = port_local(t[0], NULL), p1 = port_local(t[1], NULL);
    verifier(r == 0 && p0 + p1 == 80001 && erreur(bind(t[2], (struct sockaddr *)&a, sizeof a)) == EADDRINUSE
                 && lire_ip(t[0], IP_PROTOCOL) == p0,
             "IP_LOCAL_PORT_RANGE 40000-40001 : deux ports, puis EADDRINUSE ; IP_PROTOCOL, le port");
    for (int i = 0; i < 3; i++)
        close(t[i]);
    s = udp(0);
    poser_ip(s, IP_LOCAL_PORT_RANGE, 1000 | 2000 << 16, 4);
    uint16_t p2 = connect(s, (struct sockaddr *)&d, sizeof d) == 0 ? port_local(s, NULL) : 0;
    verifier(p2 >= 32768 && p2 <= 60999, "IP_LOCAL_PORT_RANGE 1000-2000 : ignoree, le port dans 32768-60999");
    close(s);
}

/* Les messages de contrôle d'une réception, à la suite, en texte : pour
 * chacun « type:longueur:octets » (le niveau, toujours IPPROTO_IP, n'est
 * pas écrit), séparés d'une espace. */
static void controles_en_texte(struct msghdr *m, char *t, size_t n)
{
    size_t k = 0;
    t[0] = 0;
    for (struct cmsghdr *h = CMSG_FIRSTHDR(m); h && k + 8 < n; h = CMSG_NXTHDR(m, h)) {
        size_t l = h->cmsg_len - CMSG_LEN(0);
        k += snprintf(t + k, n - k, "%s%d:%zu:", k ? " " : "", h->cmsg_type, l);
        for (size_t i = 0; i < l && k + 3 < n; i++)
            k += snprintf(t + k, n - k, "%02x", CMSG_DATA(h)[i]);
    }
}

/* Des octets en hexadécimal, à la suite de t. */
static void en_hexa(char *t, const void *o, size_t n)
{
    t += strlen(t);
    for (size_t i = 0; i < n; i++)
        t += sprintf(t, "%02x", ((const unsigned char *)o)[i]);
}

/* La somme de Linux (`csum_partial` d'x86-64), que rend IP_CHECKSUM : les
 * mots de 32 bits petit-boutistes, la fin complétée de zéros, ajoutés en
 * complément à un. */
static uint32_t somme_linux(const unsigned char *o, size_t n)
{
    uint64_t s = 0;
    for (size_t i = 0; i < n; i += 4) {
        uint32_t m = 0;
        memcpy(&m, o + i, n - i < 4 ? n - i : 4);
        s += m;
    }
    while (s >> 32)
        s = (s & 0xffffffff) + (s >> 32);
    return s;
}

/* `csum_sub` : a moins b. */
static uint32_t somme_moins(uint32_t a, uint32_t b)
{
    uint32_t s = a + ~b;
    return s + (s < ~b);
}

/* Tous les drapeaux de réception de SOL_IP. */
static void tous_les_controles(int s)
{
    int drapeaux[] = { IP_PKTINFO, IP_RECVTTL, IP_RECVTOS, IP_RECVOPTS, IP_RETOPTS, IP_PASSSEC, IP_RECVORIGDSTADDR,
                       IP_CHECKSUM, IP_RECVFRAGSIZE };
    for (unsigned i = 0; i < sizeof drapeaux / sizeof *drapeaux; i++)
        poser_ip(s, drapeaux[i], 1, 4);
}

/* Reçoit (drapeaux de recvmsg : `drapeaux`, place des messages de contrôle :
 * `place`) dans o, et écrit les messages de contrôle en texte dans t. Rend
 * la longueur, `msg_flags` dans *f et `msg_controllen` dans *l. */
static ssize_t recevoir_controles(int s, void *o, size_t n, int drapeaux, size_t place, char *t, size_t tn, int *f, size_t *l)
{
    char c[512];
    struct iovec v = { o, n };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = place };
    struct pollfd p = { s, drapeaux & MSG_ERRQUEUE ? 0 : POLLIN, 0 };
    poll(&p, 1, 2000);
    ssize_t r = recvmsg(s, &m, drapeaux | MSG_DONTWAIT);
    *f = m.msg_flags;
    *l = m.msg_controllen;
    if (r >= 0)
        controles_en_texte(&m, t, tn);
    else
        t[0] = 0;
    return r;
}

/* Les messages de contrôle de la réception IP (les soldes d'avant 6k), dans
 * l'ordre de Linux (`ip_cmsg_recv_offset`) : IP_PKTINFO, IP_TTL (un int),
 * IP_TOS (un octet), IP_RECVOPTS et IP_RETOPTS (rien sans options),
 * IP_PASSSEC (rien sans module de sécurité), IP_ORIGDSTADDR (la
 * destination, et les octets 2 et 3 de l'en-tête de transport), IP_CHECKSUM
 * (la somme complète : jamais pour UDP par lo, toujours pour ICMP),
 * IP_RECVFRAGSIZE (rien : pas de fragments). Pour un datagramme, une
 * réponse de ping, et une erreur de la file (ceux du message ICMP : son TTL,
 * son TOS 0xc0 | celui d'origine, sa somme, qui se plie en 0xffff ;
 * IP_ORIGDSTADDR seulement si la charge a 4 octets, les « ports » pris
 * dedans ; mesuré sous Linux 6.18). */
static void controles(void)
{
    uint16_t pr;
    int r = liee(&pr), s = udp(0);
    tous_les_controles(r);
    poser_ip(s, IP_TTL, 33, 4);
    poser_ip(s, IP_TOS, 0x28, 4);
    char o[64], t[512], attendu[512];
    int f;
    size_t l;
    envoyer(s, "abcd", 4, pr);
    ssize_t n = recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l);
    struct sockaddr_in a = adresse(LO, pr);
    strcpy(attendu, "8:12:010000007f0000017f000001 2:4:21000000 1:1:28 20:16:");
    en_hexa(attendu, &a, sizeof a);
    verifier(n == 4 && f == 0 && l == 112 && strcmp(t, attendu) == 0, "UDP par lo : PKTINFO, TTL 33, TOS 0x28, ORIGDSTADDR ; ni somme ni options");
    if (strcmp(t, attendu) != 0)
        printf("[linux] reseau :   %s\n[linux] reseau :   attendu %s\n", t, attendu);
    /* La place qui manque au quatrième : MSG_CTRUNC, la place prise toute. */
    envoyer(s, "abcd", 4, pr);
    n = recevoir_controles(r, o, sizeof o, 0, 74, t, sizeof t, &f, &l);
    verifier(n == 4 && f == MSG_CTRUNC && l == 74 && strcmp(t, "8:12:010000007f0000017f000001 2:4:21000000 1:1:28") == 0,
             "UDP par lo, 74 octets de place : trois messages, MSG_CTRUNC");
    close(r);

    /* Une réponse de ping : un IP_PKTINFO que rien n'a préparé (`ping_rcv`,
     * comme pour une erreur : l'interface d'arrivée, 0.0.0.0), TTL 64, le TOS
     * de la demande, ses « ports » (sa somme), et sa somme complète. */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (q >= 0) {
        tous_les_controles(q);
        poser_ip(q, IP_TOS, 0x28, 4);
        unsigned char echo[12] = { 8, 0, 0, 0, 0, 0, 0, 7, 'p', 'i', 'n', 'g' };
        struct sockaddr_in d = adresse(LO, 0);
        sendto(q, echo, sizeof echo, 0, (struct sockaddr *)&d, sizeof d);
        unsigned char rep[64];
        n = recevoir_controles(q, rep, sizeof rep, 0, 512, t, sizeof t, &f, &l);
        struct sockaddr_in de = adresse(LO, 0);
        memcpy(&de.sin_port, rep + 2, 2);
        uint32_t somme = n > 0 ? somme_linux(rep, n) : 0;
        strcpy(attendu, "8:12:01000000000000007f000001 2:4:40000000 1:1:28 20:16:");
        en_hexa(attendu, &de, sizeof de);
        strcat(attendu, " 23:4:");
        en_hexa(attendu, &somme, 4);
        verifier(n == 12 && f == 0 && strcmp(t, attendu) == 0, "ping par lo : PKTINFO (sans adresse locale), TTL 64, TOS 0x28, ORIGDSTADDR (sa somme), CHECKSUM");
        if (strcmp(t, attendu) != 0)
            printf("[linux] reseau :   %s\n[linux] reseau :   attendu %s\n", t, attendu);
        close(q);
    }

    /* Une erreur de la file : un port fermé, la charge de 3 octets, puis
     * de 4. */
    poser_ip(s, IP_RECVERR, 1, 4);
    tous_les_controles(s);
    for (int k = 3; k <= 4; k++) {
        struct sockaddr_in d = adresse(LO, port_ferme());
        sendto(s, "abcd", k, 0, (struct sockaddr *)&d, sizeof d);
        attendre_erreur(s);
        n = recevoir_controles(s, o, sizeof o, MSG_ERRQUEUE, 512, t, sizeof t, &f, &l);
        strcpy(attendu, "8:12:01000000000000007f000001 2:4:40000000 1:1:c8");
        if (k == 4) {
            struct sockaddr_in de = adresse(LO, 0x6364);
            strcat(attendu, " 20:16:");
            en_hexa(attendu, &de, sizeof de);
        }
        /* La somme, que le programme ne peut pas refaire (l'identifiant
         * de l'en-tête cité) : celle d'un message juste, qui se plie en
         * 0xffff ; puis IP_RECVERR, pas comparé ici. */
        char *c = strstr(t, " 23:4:"), *e = strstr(t, " 11:32:");
        uint32_t v = 0;
        if (c && sscanf(c + 6, "%8x", &v) == 1)
            v = __builtin_bswap32(v);
        uint32_t plie = (v & 0xffff) + (v >> 16);
        plie = (plie & 0xffff) + (plie >> 16);
        int ok = n == k && f == MSG_ERRQUEUE && c && e && e == c + 14 && plie == 0xffff;
        if (c)
            *c = 0;
        ok = ok && strcmp(t, attendu) == 0;
        verifier(ok, k == 3 ? "erreur en file, 3 octets : PKTINFO, TTL 64, TOS 0xc8, CHECKSUM (pliee : 0xffff), RECVERR"
                            : "erreur en file, 4 octets : de plus ORIGDSTADDR, ses ports dans la charge");
        if (!ok)
            printf("[linux] reseau :   %s (somme %08x)\n[linux] reseau :   attendu %s\n", t, v, attendu);
    }
    close(s);
}

/* Des octets donnés en hexadécimal ; rend leur nombre. */
static int de_hexa(const char *h, unsigned char *o)
{
    int n = 0;
    for (; h[0] && h[1]; h += 2)
        sscanf(h, "%2hhx", &o[n++]);
    return n;
}

/* Pose IP_OPTIONS (en hexadécimal) ; rend 0 ou l'errno. */
static int poser_options(int s, const char *h)
{
    unsigned char o[64];
    int n = de_hexa(h, o);
    return erreur(setsockopt(s, IPPROTO_IP, IP_OPTIONS, o, n));
}

/* Relit IP_OPTIONS, en hexadécimal dans t, avec `place` octets de place. */
static void relire_options(int s, socklen_t place, char *t)
{
    unsigned char o[64];
    socklen_t l = place;
    t[0] = 0;
    if (getsockopt(s, IPPROTO_IP, IP_OPTIONS, o, &l) != 0)
        strcpy(t, "erreur");
    else
        en_hexa(t, o, l);
}

/* Remplace par des points les 8 chiffres (4 octets : l'heure d'un
 * horodatage) qui suivent de `decalage` le texte `apres` dans t. */
static void masquer_l_heure(char *t, const char *apres, int decalage)
{
    char *c = strstr(t, apres);
    if (c && strlen(c) >= strlen(apres) + decalage + 8)
        memset(c + strlen(apres) + decalage, '.', 8);
}

/* IP_OPTIONS et l'écho des options reçues (les soldes d'avant 6k ; mesuré
 * sous Linux 6.18, soldes/sondes-sol-ip/cmsg.txt) :
 *   - posées, puis relues défaites (`ip_options_undo` : une route source
 *     retrouve sa première étape, les places réservées sont rendues),
 *     autant qu'il y a de place ; refusées (EINVAL), les précédentes
 *     restent : deux horodatages, une route source mal faite, plus de 40
 *     octets, la sécurité sans CAP_NET_RAW ; aucun octet : aucune ;
 *   - ce qui en arrive par lo (IP_RECVOPTS : l'émetteur, puis le receveur
 *     ont noté 127.0.0.1, ou l'heure ; un horodatage sans place compte son
 *     débordement) et leur écho défait (IP_RETOPTS) ;
 *   - une route source part, vers sa première étape (sendto réussit ; vers
 *     0.0.0.0 : EINVAL), mais n'arrive pas : jetée à l'arrivée ;
 *   - le message de contrôle IP_RETOPTS d'un envoi (vide : sans les
 *     options de la socket), IP_PROTOCOL (1 à 255, sans effet) ;
 *   - leur place : le plus grand datagramme UDP la perd ;
 *   - l'écho d'un ping (la réponse revient avec la route notée), et d'une
 *     erreur ICMP (un port fermé) en file. */
static void options_d_ip(void)
{
    int racine = getuid() == 0;
    uint16_t pr;
    int r = liee(&pr), s = udp(0);
    char t[512], attendu[512];
    int ok = poser_options(s, "070b040000000000000000") == 0;
    relire_options(s, 64, t);
    ok = ok && strcmp(t, "070b04000000000000000000") == 0;
    relire_options(s, 5, t);
    verifier(ok && strcmp(t, "070b040000") == 0, "IP_OPTIONS : la route notee, relue (12 octets ; 5 de place : 5)");
    static const char *const poses[][2] = {
        { "440c0501000000000000000001", "440c0501000000000000000001000000" },
        { "440c05037f00000100000000", "440c05037f00000100000000" },
        { "830b047f0000017f000002", "830b047f0000017f00000200" },
        { "44040502", "44040502" },
        { "94040000", "94040000" },
        { "07070800000000", "0707080000000000" },
        { "01010101010101010101010101010101010101010101010101010101010101010101010101010101",
          "01010101010101010101010101010101010101010101010101010101010101010101010101010101" },
        { "8307047f000001", "8307047f00000100" },
    };
    ok = 1;
    for (unsigned i = 0; i < sizeof poses / sizeof *poses; i++) {
        int e = poser_options(s, poses[i][0]);
        relire_options(s, 64, t);
        if (e != 0 || strcmp(t, poses[i][1]) != 0) {
            printf("[linux] reseau :   %s : %d, relu %s\n", poses[i][0], e, t);
            ok = 0;
        }
    }
    static const char *const refuses[] = {
        "440c0501000000000000000044080501", "8308040102030405", "83070801020304", "830304",
        "0101010101010101010101010101010101010101010101010101010101010101010101010101010101",
    };
    for (unsigned i = 0; i < sizeof refuses / sizeof *refuses; i++) {
        int e = poser_options(s, refuses[i]);
        relire_options(s, 64, t);
        if (e != EINVAL || strcmp(t, "8307047f00000100") != 0) {
            printf("[linux] reseau :   %s : %d, relu %s\n", refuses[i], e, t);
            ok = 0;
        }
    }
    int sec = poser_options(s, "82040000");
    relire_options(s, 64, t);
    ok = ok && (racine ? sec == 0 && strcmp(t, "82040000") == 0 : sec == EINVAL && strcmp(t, "8307047f00000100") == 0);
    ok = ok && poser_options(s, "") == 0;
    relire_options(s, 64, t);
    verifier(ok && t[0] == 0, "IP_OPTIONS : relues defaites ; refusees, les precedentes restent ; la securite (root seul) ; vides : aucune");

    /* Ce qui arrive par lo, et l'écho. */
    tous_les_controles(r);
    struct sockaddr_in a = adresse(LO, pr);
    char nom[40] = "";
    en_hexa(nom, &a, sizeof a);
    static const char *const recus[][2] = {
        { "070b040000000000000000", "6:12:070b0c7f0000017f00000100 7:12:070b0c7f0000017f00000100" },
        { "440c0501000000000000000001", "6:16:440c0d117f000001........01000000 7:12:440c0d117f000001........" },
        { "440c05037f00000100000000", "6:12:440c0d037f000001........ 7:12:440c0d037f000001........" },
    };
    char o[64];
    int f;
    size_t l;
    ok = 1;
    for (unsigned i = 0; i < sizeof recus / sizeof *recus; i++) {
        poser_options(s, recus[i][0]);
        envoyer(s, "abcd", 4, pr);
        ssize_t n = recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l);
        if (i > 0) {
            masquer_l_heure(t, " 6:", 19);
            masquer_l_heure(t, " 7:", 19);
        }
        snprintf(attendu, sizeof attendu, "8:12:010000007f0000017f000001 2:4:40000000 1:1:00 %s 20:16:%s", recus[i][1], nom);
        if (n != 4 || strcmp(t, attendu) != 0) {
            printf("[linux] reseau :   %s\n[linux] reseau :   attendu %s\n", t, attendu);
            ok = 0;
        }
    }
    verifier(ok, "IP_OPTIONS par lo : la route notee, l'horodatage (adresses, deborde ; donnees d'avance) ; RECVOPTS, RETOPTS");
    poser_options(s, "830b047f0000017f000002");
    struct sockaddr_in rien = adresse(0, pr);
    ok = envoyer(s, "abcd", 4, pr) == 4 && sendto(s, "abcd", 4, 0, (struct sockaddr *)&rien, sizeof rien) == -1 && errno == EINVAL;
    struct pollfd p = { r, POLLIN, 0 };
    verifier(ok && poll(&p, 1, 300) == 0, "IP_OPTIONS : une route source part (vers 0.0.0.0 : EINVAL), et n'arrive pas");

    /* Les messages de contrôle d'un envoi. */
    unsigned char cb[CMSG_SPACE(40)] = { 0 };
    struct iovec v = { "xyz", 3 };
    struct msghdr m = { .msg_name = &a, .msg_namelen = sizeof a, .msg_iov = &v, .msg_iovlen = 1, .msg_control = cb,
                        .msg_controllen = sizeof cb };
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_IP;
    h->cmsg_type = IP_RETOPTS;
    h->cmsg_len = CMSG_LEN(11);
    m.msg_controllen = CMSG_SPACE(11);
    de_hexa("070b040000000000000000", CMSG_DATA(h));
    poser_options(s, "");
    ok = sendmsg(s, &m, 0) == 3 && recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l) == 3
         && strstr(t, " 6:12:070b0c7f0000017f00000100 7:12:") != NULL;
    poser_options(s, "070b040000000000000000");
    h->cmsg_len = CMSG_LEN(0);
    m.msg_controllen = CMSG_SPACE(0);
    ok = ok && sendmsg(s, &m, 0) == 3 && recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l) == 3
         && strstr(t, " 6:") == NULL;
    int proto = 17;
    h->cmsg_type = IP_PROTOCOL;
    h->cmsg_len = CMSG_LEN(4);
    m.msg_controllen = CMSG_SPACE(4);
    memcpy(CMSG_DATA(h), &proto, 4);
    ok = ok && sendmsg(s, &m, 0) == 3 && recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l) == 3;
    proto = 0;
    memcpy(CMSG_DATA(h), &proto, 4);
    ok = ok && sendmsg(s, &m, 0) == -1 && errno == EINVAL;
    verifier(ok, "IP_RETOPTS a l'envoi (vide : sans celles de la socket) ; IP_PROTOCOL 17 : sans effet ; 0 : EINVAL");

    /* La place des options : 65 535 - 20 - 12 - 8 octets au plus. */
    static char gros[65496];
    ok = sendto(s, gros, 65496, 0, (struct sockaddr *)&a, sizeof a) == -1 && errno == EMSGSIZE
         && sendto(s, gros, 65495, 0, (struct sockaddr *)&a, sizeof a) == 65495
         && recevoir_controles(r, gros, sizeof gros, 0, 512, t, sizeof t, &f, &l) == 65495;
    verifier(ok, "IP_OPTIONS de 12 octets : un datagramme UDP de 65 495 octets au plus");
    close(r);

    /* L'écho d'un ping, puis d'une erreur ICMP. */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (q >= 0) {
        tous_les_controles(q);
        poser_options(q, "070b040000000000000000");
        unsigned char echo[12] = { 8, 0, 0, 0, 0, 0, 0, 7, 'p', 'i', 'n', 'g' };
        struct sockaddr_in d = adresse(LO, 0);
        sendto(q, echo, sizeof echo, 0, (struct sockaddr *)&d, sizeof d);
        unsigned char rep[64];
        ssize_t n = recevoir_controles(q, rep, sizeof rep, 0, 512, t, sizeof t, &f, &l);
        verifier(n == 12 && strstr(t, " 6:12:070b0c7f0000017f00000100 7:12:070b0c7f0000017f00000100 ") != NULL,
                 "ping avec la route notee : la reponse en fait l'echo (RECVOPTS, RETOPTS)");
        close(q);
    }
    poser_ip(s, IP_RECVERR, 1, 4);
    tous_les_controles(s);
    struct sockaddr_in d = adresse(LO, port_ferme());
    sendto(s, "abcd", 4, 0, (struct sockaddr *)&d, sizeof d);
    attendre_erreur(s);
    ssize_t n = recevoir_controles(s, o, sizeof o, MSG_ERRQUEUE, 512, t, sizeof t, &f, &l);
    verifier(n == 4 && strstr(t, " 6:12:070b0c7f0000017f00000100 7:12:070b0c7f0000017f00000100 ") != NULL,
             "erreur en file pour un envoi avec la route notee : l'erreur ICMP en fait l'echo");
    close(s);
}

/* La passerelle de la route par défaut (dans l'ordre du réseau), lue dans
 * /proc/net/route. Faux : pas de route par défaut. */
static int passerelle_par_defaut(uint32_t *passerelle)
{
    FILE *f = fopen("/proc/net/route", "r");
    char ligne[256], nom[32];
    unsigned destination, p, masque;
    int trouve = 0;
    while (!trouve && f && fgets(ligne, sizeof ligne, f))
        if (sscanf(ligne, "%31s %x %x %*x %*d %*d %*d %x", nom, &destination, &p, &masque) == 4 && destination == 0
            && masque == 0 && p != 0) {
            *passerelle = p;
            trouve = 1;
        }
    if (f)
        fclose(f);
    return trouve;
}

/* Envoie les n octets o de s vers vers:port (dans l'ordre du réseau), avec
 * un IP_PKTINFO d'interface `interface` (0 : sans message de contrôle).
 * Rend 0, ou errno. */
static int envoyer_par(int s, const void *o, size_t n, uint32_t vers, uint16_t port, int interface)
{
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = port, .sin_addr.s_addr = vers };
    char c[CMSG_SPACE(sizeof(struct in_pktinfo))] = { 0 };
    struct iovec v = { (void *)o, n };
    struct msghdr m = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v, .msg_iovlen = 1 };
    if (interface) {
        m.msg_control = c;
        m.msg_controllen = sizeof c;
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = IPPROTO_IP;
        h->cmsg_type = IP_PKTINFO;
        h->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        ((struct in_pktinfo *)CMSG_DATA(h))->ipi_ifindex = interface;
    }
    return erreur(sendmsg(s, &m, 0));
}

/* L'interface de sortie (les soldes d'avant 6k) : l'`ipi_ifindex`
 * d'IP_PKTINFO, sinon IP_UNICAST_IF (sauf vers une multidiffusion :
 * `udp_sendmsg`), choisit l'interface d'un envoi, et la route est cherchée
 * pour elle (`ip_route_output_key_hash_rcu`) : par lo, tout est livré ici,
 * même pour une adresse d'ailleurs, la source étant alors choisie sur une
 * autre interface (celles de lo sont de portée « hôte ») ; l'interface vue
 * à l'arrivée est celle de la route (`inet_iif`) ; IP_PKTINFO est préparé à
 * l'arrivée, pour une socket qui l'avait (`ipv4_pktinfo_prepare`) ; une
 * réponse d'ICMP ne part que d'une adresse à nous ; une socket UDP
 * connectée garde la route de son connect (`sk_dst_cache`). Le « hack de
 * vic/vat » : sans interface, une source liée et une diffusion limitée
 * partent par l'interface de la source. */
static void interface_de_sortie(void)
{
    const uint32_t ailleurs = htonl(0xc0000201); /* 192.0.2.1, TEST-NET-1 */
    uint32_t passerelle, diffusion;
    int un = 1;
    if (!passerelle_par_defaut(&passerelle) || !diffusion_du_reseau(&diffusion)) {
        verifier(1, "pas de carte : l'interface de sortie, sautee");
        return;
    }
    /* Notre adresse : la source d'une socket connectée ailleurs. */
    int s = udp(0), r = udp(0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = ailleurs }, moi, de;
    socklen_t l = sizeof moi;
    connect(s, (struct sockaddr *)&a, sizeof a);
    getsockname(s, (struct sockaddr *)&moi, &l);
    close(s);
    /* r écoute sur 0.0.0.0, avec IP_PKTINFO. */
    a = adresse(0, 0);
    l = sizeof a;
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &l);
    uint16_t port = a.sin_port;
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    struct in_pktinfo pi = { 0 };
    s = udp(0);
    /* Vers notre adresse sans interface : arrivé par la carte (la route
     * locale de notre adresse est la sienne). */
    int ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    int carte = pi.ipi_ifindex;
    verifier(ok && carte > 1 && pi.ipi_spec_dst.s_addr == moi.sin_addr.s_addr && pi.ipi_addr.s_addr == moi.sin_addr.s_addr,
             "vers notre adresse : arrive par la carte");
    ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, carte) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == carte, "IP_PKTINFO carte vers notre adresse : arrive par la carte");
    ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, 1) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_spec_dst.s_addr == moi.sin_addr.s_addr,
             "IP_PKTINFO lo vers notre adresse : arrive par lo");
    /* Par lo, une adresse d'ailleurs : livrée ici, de notre adresse. */
    ok = envoyer_par(s, "x", 1, ailleurs, port, 1) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && de.sin_addr.s_addr == moi.sin_addr.s_addr && pi.ipi_spec_dst.s_addr == ailleurs
                 && pi.ipi_addr.s_addr == ailleurs,
             "IP_PKTINFO lo vers 192.0.2.1 : livre ici par lo, de notre adresse");
    ok = envoyer_par(s, "x", 1, passerelle, port, 1) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_addr.s_addr == passerelle, "IP_PKTINFO lo vers la passerelle : livre ici");
    /* La diffusion du réseau par lo : un unicast, sans SO_BROADCAST. */
    verifier(envoyer_par(s, "x", 1, diffusion, port, 0) == EACCES, "vers la diffusion du reseau sans SO_BROADCAST : EACCES");
    ok = envoyer_par(s, "x", 1, diffusion, port, 1) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_spec_dst.s_addr == diffusion,
             "IP_PKTINFO lo vers la diffusion du reseau : un unicast, sans SO_BROADCAST");
    verifier(envoyer_par(s, "x", 1, ailleurs, port, 9999) == ENODEV, "IP_PKTINFO 9999 : ENODEV");
    verifier(recu_avec_pktinfo(r, &de, &pi, 0) == -1, "et rien de plus");
    close(s);

    /* Le « port injoignable » ne part que d'une adresse à nous : par lo,
     * vers un port fermé de 192.0.2.1, rien ; de 127.0.0.1, ECONNREFUSED. */
    s = udp(0);
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    uint16_t ferme = htons(port_ferme());
    struct pollfd pe = { s, 0, 0 };
    ok = envoyer_par(s, "x", 1, ailleurs, ferme, 1) == 0 && poll(&pe, 1, 300) == 0;
    verifier(ok, "IP_PKTINFO lo vers un port ferme de 192.0.2.1 : pas d'erreur ICMP (sa source n'est pas a nous)");
    ok = envoyer_par(s, "x", 1, htonl(LO), ferme, 0) == 0 && attendre_erreur(s);
    verifier(ok && getsockopt(s, SOL_SOCKET, SO_ERROR, &un, &(socklen_t){ sizeof un }) == 0 && un == ECONNREFUSED,
             "vers un port ferme de 127.0.0.1 : l'erreur ICMP");
    un = 1;
    close(s);

    /* L'écho de même : une socket de ping, par lo vers 192.0.2.1, sans réponse. */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (q >= 0) {
        struct icmphdr e = { .type = ICMP_ECHO, .un.echo = { .id = htons(0x4321), .sequence = htons(1) } };
        struct pollfd pq = { q, POLLIN, 0 };
        ok = envoyer_par(q, &e, sizeof e, ailleurs, 0, 1) == 0 && poll(&pq, 1, 300) == 0;
        verifier(ok, "ping, IP_PKTINFO lo vers 192.0.2.1 : pas de reponse (sa source n'est pas a nous)");
        ok = envoyer_par(q, &e, sizeof e, htonl(LO), 0, 1) == 0 && poll(&pq, 1, 1000) == 1;
        verifier(ok, "ping, IP_PKTINFO lo vers 127.0.0.1 : la reponse");
        close(q);
    }

    /* IP_PKTINFO posé après l'arrivée : rien de préparé, l'interface 0 et
     * l'adresse locale 0.0.0.0 (la destination reste). */
    uint16_t pv;
    int v = liee(&pv);
    s = udp(0);
    envoyer(s, "x", 1, pv);
    setsockopt(v, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    ok = recu_avec_pktinfo(v, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 0 && pi.ipi_spec_dst.s_addr == 0 && pi.ipi_addr.s_addr == htonl(LO),
             "IP_PKTINFO pose apres l'arrivee : interface 0, adresse locale 0.0.0.0");
    close(v);
    close(s);

    /* IP_UNICAST_IF : l'interface d'un envoi sans IP_PKTINFO. */
    s = udp(0);
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(1), 4) == 0 && lire_ip(s, IP_UNICAST_IF) == (int)htonl(1),
             "IP_UNICAST_IF lo, dans l'ordre du reseau, relu");
    ok = envoyer_par(s, "x", 1, ailleurs, port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_addr.s_addr == ailleurs, "IP_UNICAST_IF lo vers 192.0.2.1 : livre ici par lo");
    ok = envoyer_par(s, "x", 1, ailleurs, port, carte) == 0 && recu_avec_pktinfo(r, &de, &pi, 300) == -1;
    verifier(ok, "IP_UNICAST_IF lo, IP_PKTINFO carte vers 192.0.2.1 : par la carte (IP_PKTINFO l'emporte)");
    /* connect le suit : la source de notre adresse, et les envois par lo. */
    a.sin_addr.s_addr = passerelle;
    a.sin_port = port;
    struct sockaddr_in nom;
    l = sizeof nom;
    ok = connect(s, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(s, (struct sockaddr *)&nom, &l) == 0;
    verifier(ok && nom.sin_addr.s_addr == moi.sin_addr.s_addr, "IP_UNICAST_IF lo, connect vers la passerelle : de notre adresse");
    ok = send(s, "x", 1, 0) == 1 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_addr.s_addr == passerelle, "et send : livre ici par lo");
    close(s);
    /* Une socket connectée garde la route de son connect : IP_UNICAST_IF posé
     * après ne change rien pour send, mais sendto cherche une route. */
    s = udp(0);
    a.sin_addr.s_addr = ailleurs;
    connect(s, (struct sockaddr *)&a, sizeof a);
    poser_ip(s, IP_UNICAST_IF, htonl(1), 4);
    ok = send(s, "x", 1, 0) == 1 && recu_avec_pktinfo(r, &de, &pi, 300) == -1;
    verifier(ok, "connectee a 192.0.2.1, puis IP_UNICAST_IF lo : send garde la route du connect");
    ok = envoyer_par(s, "x", 1, ailleurs, port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1, "et sendto vers la meme adresse : une route neuve, par lo");
    close(s);
    /* Les valeurs : une longueur de 4 seulement, un index qui existe ; 0
     * l'efface ; lu dans un octet, le premier de l'entier. */
    s = udp(0);
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(1), 0) == EINVAL && poser_ip(s, IP_UNICAST_IF, htonl(1), 2) == EINVAL,
             "IP_UNICAST_IF de longueur 0 ou 2 : EINVAL");
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(9999), 4) == EADDRNOTAVAIL && poser_ip(s, IP_UNICAST_IF, 1, 4) == EADDRNOTAVAIL,
             "IP_UNICAST_IF 9999, ou 1 dans l'ordre de la machine : EADDRNOTAVAIL");
    poser_ip(s, IP_UNICAST_IF, htonl(1), 4);
    unsigned char octet = 0x55;
    socklen_t lo = 1;
    int lu = getsockopt(s, IPPROTO_IP, IP_UNICAST_IF, &octet, &lo);
    verifier(lu == 0 && lo == 1 && octet == 0, "IP_UNICAST_IF lu dans un octet : le premier de l'entier");
    long long grand = 0;
    lo = sizeof grand;
    lu = getsockopt(s, IPPROTO_IP, IP_UNICAST_IF, &grand, &lo);
    verifier(lu == 0 && lo == 4 && grand == htonl(1), "IP_UNICAST_IF lu dans 8 octets : 4");
    verifier(poser_ip(s, IP_UNICAST_IF, 0, 4) == 0 && lire_ip(s, IP_UNICAST_IF) == 0, "IP_UNICAST_IF 0 : efface");
    close(s);
    s = socket(AF_INET, SOCK_STREAM, 0);
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(1), 4) == 0 && lire_ip(s, IP_UNICAST_IF) == (int)htonl(1),
             "IP_UNICAST_IF d'une socket TCP : pose et relu");
    close(s);

    /* Le hack de vic/vat : liée à 127.0.0.1, vers 255.255.255.255, par lo. */
    s = udp(0);
    a = adresse(LO, 0);
    bind(s, (struct sockaddr *)&a, sizeof a);
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &un, sizeof un);
    ok = envoyer_par(s, "x", 1, htonl(0xffffffff), port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && de.sin_addr.s_addr == htonl(LO) && pi.ipi_spec_dst.s_addr == htonl(LO),
             "liee a 127.0.0.1, vers 255.255.255.255 : par lo (le hack de vic/vat)");
    verifier(recu_avec_pktinfo(r, &de, &pi, 200) == -1, "une fois");
    close(s);
    close(r);

    /* SO_DONTROUTE et MSG_DONTROUTE : la route est de portée « lien »
     * (`ip_sendmsg_scope`), celle par défaut ne compte plus (elle passe par
     * une passerelle) : sans interface, ni une machine d'ailleurs ni la
     * diffusion limitée n'ont de route ; par la carte demandée, une machine
     * d'ailleurs est sur son lien, et le datagramme part (mesuré sous Linux
     * 6.18.33). */
    s = udp(0);
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &un, sizeof un);
    setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &un, sizeof un);
    a = adresse(0xffffffff, 9);
    ok = erreur(sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a)) == ENETUNREACH;
    int k = htonl(carte);
    setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, &k, sizeof k);
    a.sin_addr.s_addr = ailleurs;
    ok = ok && sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a) == 1;
    close(s);
    s = udp(0);
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &un, sizeof un);
    a = adresse(0xffffffff, 9);
    ok = ok && erreur(sendto(s, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&a, sizeof a)) == ENETUNREACH;
    setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, &k, sizeof k);
    a.sin_addr.s_addr = ailleurs;
    ok = ok && sendto(s, "x", 1, MSG_DONTROUTE, (struct sockaddr *)&a, sizeof a) == 1;
    close(s);
    verifier(ok, "SO_DONTROUTE, MSG_DONTROUTE : pas de diffusion limitee sans interface ; par la carte, une machine d'ailleurs est sur son lien");
}

/* Les sockets liées à une interface (SO_BINDTODEVICE, SO_BINDTOIFINDEX ;
 * les soldes d'avant 6k, mesurés sous Linux 6.18) : les options, toute
 * socket (AF_UNIX comprise) ; la route gardée d'une socket connectée,
 * oubliée par la liaison ; l'interface des envois (IP_PKTINFO, puis la
 * liaison, puis IP_UNICAST_IF) ; la réception (une socket liée ne voit que
 * ce qui arrive par son interface, celle de la route du paquet : notre
 * adresse arrive par la carte, même par lo) ; les conflits de `bind` (deux
 * liaisons différentes ne se gênent pas). Changer une liaison déjà faite
 * demande CAP_NET_RAW : les tests tournent en utilisateur sur l'hôte, en
 * root dans le noyau. */
static int poser_nom(int s, const char *nom, socklen_t l)
{
    return erreur(setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, nom, l));
}

static int poser_index(int s, int k)
{
    return erreur(setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX, &k, sizeof k));
}

/* Le nom lu (SO_BINDTODEVICE) dans une place de `place` octets : rend errno,
 * ou 0, le nom dans `nom` et sa longueur dans `l`. */
static int lire_nom(int s, char *nom, socklen_t place, socklen_t *l)
{
    memset(nom, 'x', 16);
    *l = place;
    return erreur(getsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, nom, l));
}

static int lire_index(int s)
{
    int k = -7;
    socklen_t l = sizeof k;
    if (getsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX, &k, &l) != 0)
        return -1000 - errno;
    return k;
}

static int mtu_de(int s)
{
    int v = 0;
    socklen_t l = sizeof v;
    if (getsockopt(s, IPPROTO_IP, IP_MTU, &v, &l) != 0)
        return -errno;
    return v;
}

static void liees(void)
{
    int racine = getuid() == 0, un = 1;
    char nom[16], quoi[200];
    socklen_t l;
    /* Les options. */
    int s = udp(0);
    verifier(lire_nom(s, nom, 64, &l) == 0 && l == 0 && lire_nom(s, nom, 0, &l) == 0 && l == 0 && lire_index(s) == 0,
             "SO_BINDTODEVICE non liee : longueur 0, quelle que soit la place ; SO_BINDTOIFINDEX 0");
    verifier(poser_nom(s, "lo\0zzz", 6) == 0 && lire_nom(s, nom, 16, &l) == 0 && l == 3 && strcmp(nom, "lo") == 0 && lire_index(s) == 1,
             "SO_BINDTODEVICE \"lo\\0zzz\" : lo, relu avec son nul (3 octets), index 1");
    verifier(lire_nom(s, nom, 15, &l) == EINVAL, "SO_BINDTODEVICE lu dans 15 octets : EINVAL");
    snprintf(quoi, sizeof quoi, "SO_BINDTODEVICE de nouveau (lo, \"\", index 1) : %s", racine ? "permis (root)" : "EPERM (CAP_NET_RAW)");
    int attendu = racine ? 0 : EPERM;
    verifier(poser_nom(s, "lo", 3) == attendu && poser_nom(s, "", 1) == attendu && poser_index(s, 1) == attendu, quoi);
    close(s);
    s = udp(0);
    char long_nom[22] = "lo";
    memset(long_nom + 2, 'x', 20);
    verifier(poser_nom(s, long_nom, 22) == ENODEV && poser_nom(s, "zz0", 4) == ENODEV && lire_index(s) == 0,
             "SO_BINDTODEVICE lo et 20 x (coupe a 15 octets), zz0 : ENODEV");
    verifier(poser_nom(s, "", 1) == 0 && poser_nom(s, NULL, 0) == 0 && lire_index(s) == 0,
             "SO_BINDTODEVICE \"\" ou de longueur 0 : delie, permis non liee");
    verifier(erreur(setsockopt(s, SOL_SOCKET, SO_BINDTOIFINDEX, &un, 2)) == EINVAL && poser_index(s, -1) == EINVAL,
             "SO_BINDTOIFINDEX de 2 octets, ou -1 : EINVAL");
    verifier(poser_index(s, 9999) == 0 && lire_index(s) == 9999 && lire_nom(s, nom, 16, &l) == ENODEV,
             "SO_BINDTOIFINDEX 9999 : accepte sans verifier, relu ; son nom : ENODEV");
    close(s);
    s = udp(0);
    poser_nom(s, "lo", 3);
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(9999), 4) == EADDRNOTAVAIL && poser_ip(s, IP_UNICAST_IF, htonl(1), 4) == EINVAL
                 && poser_ip(s, IP_UNICAST_IF, 0, 4) == 0,
             "liee : IP_UNICAST_IF 9999 EADDRNOTAVAIL, lo EINVAL (meme la sienne), 0 permis");
    close(s);
    s = udp(0);
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(1), 4) == 0 && poser_nom(s, "lo", 3) == 0 && lire_ip(s, IP_UNICAST_IF) == (int)htonl(1),
             "IP_UNICAST_IF puis SO_BINDTODEVICE : permis, les deux gardes");
    close(s);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(poser_nom(s, "lo", 3) == 0 && lire_nom(s, nom, 16, &l) == 0 && strcmp(nom, "lo") == 0,
             "AF_UNIX : SO_BINDTODEVICE pose et relu");
    close(s);

    /* La route gardée d'une socket connectée : oubliée par la liaison (même
     * délier une socket non liée), retrouvée par send, pas par un sendto qui
     * nomme la destination ; IP_UNICAST_IF ne l'oublie pas. */
    uint16_t pr;
    int r = liee(&pr);
    struct sockaddr_in a = adresse(LO, pr);
    for (int k = 0; k < 3; k++) {
        static const char *comment[] = { "SO_BINDTODEVICE lo", "SO_BINDTOIFINDEX 1", "SO_BINDTODEVICE \"\"" };
        s = udp(0);
        connect(s, (struct sockaddr *)&a, sizeof a);
        int avant = mtu_de(s);
        int pose = k == 0 ? poser_nom(s, "lo", 3) : k == 1 ? poser_index(s, 1) : poser_nom(s, "", 1);
        int apres = mtu_de(s);
        int envoye = sendto(s, "x", 1, 0, (struct sockaddr *)&a, sizeof a) == 1;
        int apres_sendto = mtu_de(s);
        int envoye2 = send(s, "x", 1, 0) == 1;
        snprintf(quoi, sizeof quoi, "connectee a 127.0.0.1, puis %s : IP_MTU ENOTCONN, encore apres sendto, 65535 apres send", comment[k]);
        verifier(avant == 65535 && pose == 0 && apres == -ENOTCONN && envoye && apres_sendto == -ENOTCONN && envoye2 && mtu_de(s) == 65535, quoi);
        close(s);
    }
    s = udp(0);
    connect(s, (struct sockaddr *)&a, sizeof a);
    verifier(poser_ip(s, IP_UNICAST_IF, htonl(1), 4) == 0 && mtu_de(s) == 65535, "connectee, puis IP_UNICAST_IF : la route gardee");
    close(s);
    /* Un IP_TOS qui change l'oublie aussi (`__ip_sock_set_tos` : `sk_dst_reset`),
     * pas un qui ne change rien. */
    s = udp(0);
    connect(s, (struct sockaddr *)&a, sizeof a);
    int tos_meme = poser_ip(s, IP_TOS, 0, 4) == 0 ? mtu_de(s) : -1;
    int tos_change = poser_ip(s, IP_TOS, 0x10, 4) == 0 ? mtu_de(s) : -1;
    int tos_envoye = send(s, "x", 1, 0) == 1;
    verifier(tos_meme == 65535 && tos_change == -ENOTCONN && tos_envoye && mtu_de(s) == 65535,
             "connectee, puis IP_TOS : le meme garde la route, un autre l'oublie jusqu'au send");
    close(s);
    /* SO_DONTROUTE l'oublie, posé ou retiré (`sk_setsockopt` : `sk_dst_reset`) ;
     * tant qu'il est posé, la connexion n'en garde pas (son envoi est de portée
     * « lien », `connected` à 0). */
    s = udp(0);
    connect(s, (struct sockaddr *)&a, sizeof a);
    int zero = 0;
    setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &un, sizeof un);
    int dr_pose = mtu_de(s);
    int dr_envoye = send(s, "x", 1, 0) == 1;
    int dr_apres = mtu_de(s);
    setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &zero, sizeof zero);
    int dr_retire = mtu_de(s);
    int dr_reenvoye = send(s, "x", 1, 0) == 1;
    verifier(dr_pose == -ENOTCONN && dr_envoye && dr_apres == -ENOTCONN && dr_retire == -ENOTCONN && dr_reenvoye && mtu_de(s) == 65535,
             "connectee, puis SO_DONTROUTE : IP_MTU ENOTCONN, encore apres send ; retire, ENOTCONN jusqu'au send");
    close(s);
    while (recv(r, nom, sizeof nom, MSG_DONTWAIT) > 0) {
    }
    close(r);

    /* Le reste demande la carte : notre adresse, son index (celui d'un
     * datagramme envoyé à notre adresse, qui arrive par elle). */
    const uint32_t ailleurs = htonl(0xc0000201); /* 192.0.2.1 */
    uint32_t passerelle;
    if (!passerelle_par_defaut(&passerelle)) {
        verifier(1, "pas de carte : les sockets liees a une interface, sautees");
        return;
    }
    struct sockaddr_in moi, de;
    struct in_pktinfo pi;
    s = udp(0);
    a = adresse(0, 9);
    a.sin_addr.s_addr = ailleurs;
    l = sizeof moi;
    connect(s, (struct sockaddr *)&a, sizeof a);
    getsockname(s, (struct sockaddr *)&moi, &l);
    close(s);
    r = udp(0);
    a = adresse(0, 0);
    l = sizeof a;
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &l);
    uint16_t port = a.sin_port;
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    s = udp(0);
    int carte = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1 ? pi.ipi_ifindex : 0;
    close(s);
    char nom_carte[16] = "";
    s = udp(0);
    verifier(carte > 1 && poser_index(s, carte) == 0 && lire_nom(s, nom_carte, 16, &l) == 0 && l == strlen(nom_carte) + 1,
             "la carte : son index, et son nom par SO_BINDTOIFINDEX puis SO_BINDTODEVICE");
    close(s);

    /* L'interface des envois : la liaison, après IP_PKTINFO, avant
     * IP_UNICAST_IF ; par lo, une adresse d'ailleurs est livrée ici. */
    s = udp(0);
    poser_nom(s, "lo", 3);
    int ok = envoyer_par(s, "x", 1, ailleurs, port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_addr.s_addr == ailleurs && de.sin_addr.s_addr == moi.sin_addr.s_addr,
             "liee lo, vers 192.0.2.1 : livre ici par lo, de notre adresse");
    ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, carte) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == carte, "liee lo, IP_PKTINFO carte vers notre adresse : par la carte (IP_PKTINFO l'emporte)");
    close(s);
    s = udp(0);
    poser_ip(s, IP_UNICAST_IF, htonl(1), 4);
    poser_nom(s, nom_carte, strlen(nom_carte) + 1);
    ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, 0) == 0 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == carte, "IP_UNICAST_IF lo, liee a la carte, vers notre adresse : par la carte (la liaison l'emporte)");
    close(s);
    /* Liée après connect : l'envoi suivant part par la nouvelle. */
    s = udp(0);
    a = adresse(0, 0);
    a.sin_addr.s_addr = passerelle;
    a.sin_port = port;
    connect(s, (struct sockaddr *)&a, sizeof a);
    int mtu_carte = mtu_de(s);
    poser_nom(s, "lo", 3);
    ok = send(s, "x", 1, 0) == 1 && recu_avec_pktinfo(r, &de, &pi, 1000) == 1;
    verifier(ok && pi.ipi_ifindex == 1 && pi.ipi_addr.s_addr == passerelle && mtu_carte < 65535 && mtu_de(s) == 65535,
             "connectee a la passerelle, puis liee lo : send livre ici par lo, IP_MTU celle de lo");
    close(s);
    close(r);

    /* La réception : liée, une socket ne voit que son interface. */
    int rl = udp(0), rc = udp(0), rn = udp(0);
    poser_nom(rl, "lo", 3);
    poser_nom(rc, nom_carte, strlen(nom_carte) + 1);
    setsockopt(rl, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    setsockopt(rc, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    a = adresse(0, 0);
    l = sizeof a;
    bind(rl, (struct sockaddr *)&a, sizeof a);
    getsockname(rl, (struct sockaddr *)&a, &l);
    port = a.sin_port;
    ok = bind(rc, (struct sockaddr *)&a, sizeof a) == 0 && erreur(bind(rn, (struct sockaddr *)&a, sizeof a)) == EADDRINUSE;
    verifier(ok, "un port, liees lo et a la carte : permis ; non liee : EADDRINUSE");
    s = udp(0);
    ok = envoyer_par(s, "x", 1, htonl(LO), port, 0) == 0 && recu_avec_pktinfo(rl, &de, &pi, 1000) == 1 && recu_avec_pktinfo(rc, &de, &pi, 200) == -1;
    verifier(ok, "vers 127.0.0.1 : la liee lo, pas celle de la carte");
    ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, 0) == 0 && recu_avec_pktinfo(rc, &de, &pi, 1000) == 1
         && recu_avec_pktinfo(rl, &de, &pi, 200) == -1;
    verifier(ok && pi.ipi_ifindex == carte, "vers notre adresse : la liee a la carte (la route de notre adresse), pas lo");
    ok = envoyer_par(s, "x", 1, moi.sin_addr.s_addr, port, 1) == 0 && recu_avec_pktinfo(rl, &de, &pi, 1000) == 1
         && recu_avec_pktinfo(rc, &de, &pi, 200) == -1;
    verifier(ok && pi.ipi_ifindex == 1, "IP_PKTINFO lo vers notre adresse : la liee lo");
    close(s);
    close(rl);
    close(rc);
    /* La liaison posée après le bind compte au conflit suivant ; et une liée
     * l'emporte sur une non liée (SO_REUSEADDR des deux). */
    rn = udp(0);
    a = adresse(0, 0);
    l = sizeof a;
    setsockopt(rn, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    bind(rn, (struct sockaddr *)&a, sizeof a);
    getsockname(rn, (struct sockaddr *)&a, &l);
    rl = udp(0);
    ok = erreur(bind(rl, (struct sockaddr *)&a, sizeof a)) == EADDRINUSE;
    poser_nom(rn, "lo", 3);
    rc = udp(0);
    poser_nom(rc, nom_carte, strlen(nom_carte) + 1);
    ok = ok && bind(rc, (struct sockaddr *)&a, sizeof a) == 0;
    verifier(ok, "liee a lo apres son bind : une liee a la carte prend le meme port");
    close(rc);
    rc = udp(0);
    setsockopt(rc, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    bind(rc, (struct sockaddr *)&a, sizeof a);
    s = udp(0);
    char o[4];
    ok = envoyer_par(s, "y", 1, htonl(LO), a.sin_port, 0) == 0 && recu_avec_pktinfo(rn, &de, &pi, 1000) == 1
         && recv(rc, o, sizeof o, MSG_DONTWAIT) == -1;
    verifier(ok, "liee lo et non liee, SO_REUSEADDR : vers 127.0.0.1, la liee");
    ok = envoyer_par(s, "y", 1, moi.sin_addr.s_addr, a.sin_port, 0) == 0 && recu_avec_pktinfo(rc, &de, &pi, 1000) == 1
         && recv(rn, o, sizeof o, MSG_DONTWAIT) == -1;
    verifier(ok, "et vers notre adresse : la non liee");
    close(s);
    close(rn);
    close(rl);
    close(rc);

    /* Ping : la réponse revient par la route de sa source ; liée ailleurs, la
     * socket ne la voit pas. */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (q >= 0) {
        struct icmphdr e = { .type = ICMP_ECHO, .un.echo = { .id = htons(0x4322), .sequence = htons(1) } };
        struct pollfd pq = { q, POLLIN, 0 };
        poser_nom(q, "lo", 3);
        ok = envoyer_par(q, &e, sizeof e, htonl(LO), 0, 0) == 0 && poll(&pq, 1, 1000) == 1 && recv(q, o, sizeof o, 0) > 0;
        verifier(ok, "ping liee lo, vers 127.0.0.1 : la reponse");
        ok = envoyer_par(q, &e, sizeof e, moi.sin_addr.s_addr, 0, 0) == 0 && poll(&pq, 1, 300) == 0;
        verifier(ok, "ping liee lo, vers notre adresse : pas de reponse (elle arrive par la carte)");
        close(q);
        q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
        pq.fd = q;
        poser_nom(q, nom_carte, strlen(nom_carte) + 1);
        ok = envoyer_par(q, &e, sizeof e, moi.sin_addr.s_addr, 0, 0) == 0 && poll(&pq, 1, 1000) == 1;
        verifier(ok, "ping liee a la carte, vers notre adresse : la reponse");
        close(q);
    }
}

/* La multidiffusion (les soldes d'avant 6k ; mesurée sous Linux 6.18.33,
 * une sonde) : les options, une à une, dans l'ordre de leurs refus ; les
 * adhésions d'une socket (20 au plus), leurs filtres de sources (10 au
 * plus), lus par IP_MSFILTER et MCAST_MSFILTER (qui écrivent au-delà de la
 * place donnée) ; ce qu'en montrent /proc/net/igmp et /proc/net/mcfilter ;
 * la fermeture, qui rend tout. Il faut une carte (la route vers les
 * groupes) : sinon, sautée. */
static int mc_poser(int s, int option, const void *o, socklen_t l)
{
    return erreur(setsockopt(s, IPPROTO_IP, option, o, l));
}

static int mc_mreq(int s, int option, const char *groupe, uint32_t adresse, int index, socklen_t l)
{
    struct ip_mreqn m = { .imr_address.s_addr = adresse, .imr_ifindex = index };
    inet_pton(AF_INET, groupe, &m.imr_multiaddr);
    return mc_poser(s, option, &m, l);
}

static int mc_source(int s, int option, const char *groupe, uint32_t interface, const char *source, socklen_t l)
{
    struct ip_mreq_source m = { .imr_interface.s_addr = interface };
    inet_pton(AF_INET, groupe, &m.imr_multiaddr);
    inet_pton(AF_INET, source, &m.imr_sourceaddr);
    return mc_poser(s, option, &m, l);
}

static int mc_groupe(int s, int option, int index, const char *groupe, int famille, socklen_t l)
{
    static char o[256];
    memset(o, 0, sizeof o);
    struct group_req *g = (void *)o;
    struct sockaddr_in *a = (void *)&g->gr_group;
    g->gr_interface = index;
    a->sin_family = famille;
    inet_pton(AF_INET, groupe, &a->sin_addr);
    return mc_poser(s, option, o, l);
}

static int mc_groupe_source(int s, int option, int index, const char *groupe, const char *source, int famille, socklen_t l)
{
    static char o[300];
    memset(o, 0, sizeof o);
    struct group_source_req *g = (void *)o;
    struct sockaddr_in *a = (void *)&g->gsr_group, *b = (void *)&g->gsr_source;
    g->gsr_interface = index;
    a->sin_family = AF_INET;
    b->sin_family = famille;
    inet_pton(AF_INET, groupe, &a->sin_addr);
    inet_pton(AF_INET, source, &b->sin_addr);
    return mc_poser(s, option, o, l);
}

/* Une adresse de 10.x.y.z, dans l'ordre du réseau. */
static uint32_t dix(int x, int y, int z)
{
    return htonl(0x0a000000 | x << 16 | y << 8 | z);
}

/* IP_MSFILTER posé : `n` sources de `sources`, dans `l` octets. */
static int mc_msfilter(int s, const char *groupe, uint32_t interface, uint32_t mode, uint32_t n, const uint32_t *sources, socklen_t l)
{
    static uint32_t o[32];
    memset(o, 0, sizeof o);
    struct ip_msfilter *f = (void *)o;
    inet_pton(AF_INET, groupe, &f->imsf_multiaddr);
    f->imsf_interface.s_addr = interface;
    f->imsf_fmode = mode;
    f->imsf_numsrc = n;
    memcpy(o + 4, sources, 4 * (n < 12 ? n : 12));
    return mc_poser(s, IP_MSFILTER, o, l);
}

/* MCAST_MSFILTER posé : `n` sources de `sources` (en sockaddr_in), dans `l`
 * octets. */
static int mc_gsf(int s, int index, const char *groupe, uint32_t mode, uint32_t n, const uint32_t *sources, socklen_t l)
{
    static char o[2000];
    memset(o, 0, sizeof o);
    struct group_filter *f = (void *)o;
    struct sockaddr_in *a = (void *)&f->gf_group;
    f->gf_interface = index;
    a->sin_family = AF_INET;
    inet_pton(AF_INET, groupe, &a->sin_addr);
    f->gf_fmode = mode;
    f->gf_numsrc = n;
    for (uint32_t k = 0; k < n && k < 12; k++) {
        struct sockaddr_in *x = (void *)(o + 144 + 128 * k);
        x->sin_family = AF_INET;
        x->sin_addr.s_addr = sources[k];
    }
    return mc_poser(s, MCAST_MSFILTER, o, l);
}

/* IP_MSFILTER lu, `n` sources demandées, dans une place de `l` octets d'un
 * tampon de 64 octets rempli de 0xaa : rend errno, la longueur rendue dans
 * *rendue, le tampon dans `o`. */
static int mc_msfget(int s, const char *groupe, uint32_t interface, uint32_t n, socklen_t l, uint32_t *o, socklen_t *rendue)
{
    memset(o, 0xaa, 64);
    struct ip_msfilter *f = (void *)o;
    inet_pton(AF_INET, groupe, &f->imsf_multiaddr);
    f->imsf_interface.s_addr = interface;
    f->imsf_numsrc = n;
    *rendue = l;
    return erreur(getsockopt(s, IPPROTO_IP, IP_MSFILTER, o, rendue));
}

/* Le contenu du fichier `chemin` dans `o` (au plus n - 1 octets), sans rien
 * d'autre. */
static void contenu(const char *chemin, char *o, size_t n)
{
    FILE *f = fopen(chemin, "r");
    size_t lu = f ? fread(o, 1, n - 1, f) : 0;
    o[lu] = 0;
    if (f)
        fclose(f);
}

/* /proc/net/igmp attendu : lo (1) puis la carte, chacune avec ses groupes
 * (le plus récent d'abord) : « groupe/membres », séparés d'espaces. Un
 * groupe s'y écrit comme l'entier de l'ordre du réseau, lu par une machine
 * petit-boutiste (224.0.0.1 : 010000E0). */
static void igmp_attendu(char *o, size_t n, const char *lo, int carte, const char *nom, const char *groupes)
{
    const char *x[2] = { lo, groupes };
    int idx[2] = { 1, carte };
    const char *noms[2] = { "lo", nom };
    size_t p = snprintf(o, n, "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n");
    for (int i = 0; i < 2; i++) {
        int compte = 0;
        for (const char *c = x[i]; *c; c++)
            compte += *c == '/';
        p += snprintf(o + p, n - p, "%d\t%-10s: %5d %7s\n", idx[i], noms[i], compte, "V3");
        char g[16];
        unsigned u;
        int lus;
        for (const char *c = x[i]; sscanf(c, " %15[0-9.]/%u%n", g, &u, &lus) == 2; c += lus) {
            struct in_addr a;
            inet_pton(AF_INET, g, &a);
            p += snprintf(o + p, n - p, "\t\t\t\t%08X %5u %d:%08X\t\t%d\n", a.s_addr, u, 0, 0, 0);
        }
    }
}

static void multidiffusion(void)
{
    uint32_t passerelle, diffusion;
    if (!passerelle_par_defaut(&passerelle) || !diffusion_du_reseau(&diffusion)) {
        verifier(1, "pas de carte : la multidiffusion, sautee");
        return;
    }
    /* Notre adresse (celle d'une socket connectée ailleurs), l'index et le
     * nom de la carte (l'arrivée d'un datagramme à notre adresse : IP_PKTINFO ;
     * /proc/net/route). */
    int s = udp(0), r = udp(0), un = 1;
    struct sockaddr_in a = adresse(0xc0000201, 9), nous, de;
    socklen_t l = sizeof nous;
    connect(s, (struct sockaddr *)&a, sizeof a);
    getsockname(s, (struct sockaddr *)&nous, &l);
    close(s);
    a = adresse(0, 0);
    l = sizeof a;
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &l);
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    struct in_pktinfo pi = { 0 };
    s = udp(0);
    envoyer_par(s, "x", 1, nous.sin_addr.s_addr, a.sin_port, 0);
    recu_avec_pktinfo(r, &de, &pi, 1000);
    close(s);
    close(r);
    const int eth = pi.ipi_ifindex;
    const uint32_t moi = nous.sin_addr.s_addr, ailleurs = htonl(0x01020304), boucle = htonl(LO);
    char nom[32] = "", ligne[256];
    FILE *f = fopen("/proc/net/route", "r");
    while (f && fgets(ligne, sizeof ligne, f))
        if (sscanf(ligne, "%31s", nom) == 1 && strcmp(nom, "Iface") && strcmp(nom, "lo"))
            break;
    if (f)
        fclose(f);
    static char lu[4096], attendu[4096];
    uint32_t o[16];
    int t = socket(AF_INET, SOCK_STREAM, 0), v;
    int ok;

    /* Les valeurs de départ : IP_MULTICAST_IF lu en in_addr (au plus 4
     * octets), TTL 1, LOOP 1, ALL 1 ; de même pour TCP. */
    s = udp(0);
    memset(o, 0xaa, sizeof o);
    l = 8;
    ok = getsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, o, &l) == 0 && l == 4 && o[0] == 0 && o[1] == 0xaaaaaaaa;
    l = 2;
    ok = ok && getsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, o, &l) == 0 && l == 2;
    ok = ok && lire_ip(s, IP_MULTICAST_TTL) == 1 && lire_ip(s, IP_MULTICAST_LOOP) == 1 && lire_ip(s, IP_MULTICAST_ALL) == 1;
    ok = ok && lire_ip(t, IP_MULTICAST_LOOP) == 1 && lire_ip(t, IP_MULTICAST_ALL) == 1;
    verifier(ok, "multidiffusion : IF 0.0.0.0 (au plus 4 octets), TTL 1, LOOP 1, ALL 1 au depart");

    /* IP_MULTICAST_IF : TCP, moins de 4 octets : EINVAL ; une adresse, une
     * ip_mreq (le second champ), une ip_mreqn ; une adresse d'ailleurs sans
     * index : EADDRNOTAVAIL (rien ne change), avec un index : gardée ; 0
     * partout : tout à zéro. */
#define LIRE_IF(s) (l = 4, getsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, o, &l) == 0 && l == 4 ? o[0] : 0xdeadbeef)
    ok = mc_poser(t, IP_MULTICAST_IF, &moi, 4) == EINVAL && mc_poser(s, IP_MULTICAST_IF, &moi, 3) == EINVAL;
    ok = ok && mc_poser(s, IP_MULTICAST_IF, &moi, 4) == 0 && LIRE_IF(s) == moi;
    ok = ok && mc_poser(s, IP_MULTICAST_IF, &ailleurs, 4) == EADDRNOTAVAIL && LIRE_IF(s) == moi;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", 0, eth, 12) == 0 && LIRE_IF(s) == 0;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", ailleurs, 1, 12) == 0 && LIRE_IF(s) == ailleurs;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", 0, 9999, 12) == EADDRNOTAVAIL;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "239.1.1.1", moi, 0, 8) == 0 && LIRE_IF(s) == moi;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "239.1.1.1", boucle, 7, 10) == 0 && LIRE_IF(s) == boucle;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", 0, 0, 12) == 0 && LIRE_IF(s) == 0;
    verifier(ok, "IP_MULTICAST_IF : in_addr, ip_mreq, ip_mreqn ; TCP, 3 octets : EINVAL ; inconnue : EADDRNOTAVAIL");
    /* Liée à lo (SO_BINDTODEVICE, la première liaison est libre) : une
     * autre interface : EINVAL. */
    r = udp(0);
    ok = setsockopt(r, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) == 0 && mc_mreq(r, IP_MULTICAST_IF, "0.0.0.0", 0, eth, 12) == EINVAL;
    ok = ok && mc_mreq(r, IP_MULTICAST_IF, "0.0.0.0", 0, 1, 12) == 0 && mc_poser(r, IP_MULTICAST_IF, &moi, 4) == EINVAL;
    v = 0;
    ok = ok && mc_poser(r, IP_MULTICAST_IF, &v, 4) == 0;
    close(r);
    verifier(ok, "IP_MULTICAST_IF d'une socket liee a lo : la carte, EINVAL ; lo, permis");

    /* IP_MULTICAST_LOOP : non nul vaut 1, un octet lu sur 1 ; TCP permis.
     * IP_MULTICAST_ALL : 0 ou 1. */
    v = 5;
    ok = mc_poser(s, IP_MULTICAST_LOOP, &v, 0) == EINVAL && mc_poser(s, IP_MULTICAST_LOOP, &v, 4) == 0 && lire_ip(s, IP_MULTICAST_LOOP) == 1;
    v = 256;
    ok = ok && mc_poser(s, IP_MULTICAST_LOOP, &v, 1) == 0 && lire_ip(s, IP_MULTICAST_LOOP) == 0;
    v = -1;
    ok = ok && mc_poser(s, IP_MULTICAST_LOOP, &v, 4) == 0 && lire_ip(s, IP_MULTICAST_LOOP) == 1;
    v = 0;
    ok = ok && mc_poser(t, IP_MULTICAST_LOOP, &v, 4) == 0 && lire_ip(t, IP_MULTICAST_LOOP) == 0;
    v = 2;
    ok = ok && mc_poser(s, IP_MULTICAST_ALL, &v, 4) == EINVAL;
    v = 0;
    ok = ok && mc_poser(s, IP_MULTICAST_ALL, &v, 0) == EINVAL && mc_poser(s, IP_MULTICAST_ALL, &v, 4) == 0 && lire_ip(s, IP_MULTICAST_ALL) == 0;
    v = 257;
    ok = ok && mc_poser(s, IP_MULTICAST_ALL, &v, 1) == 0 && lire_ip(s, IP_MULTICAST_ALL) == 1;
    v = 0;
    ok = ok && mc_poser(t, IP_MULTICAST_ALL, &v, 4) == 0 && lire_ip(t, IP_MULTICAST_ALL) == 0;
    verifier(ok, "IP_MULTICAST_LOOP (non nul : 1) et IP_MULTICAST_ALL (0 ou 1), TCP compris");

    /* IP_ADD_MEMBERSHIP : TCP : EPROTO ; moins de 8 octets, pas un groupe :
     * EINVAL ; l'interface : l'index, sinon celle de l'adresse, sinon la
     * route (la carte) ; déjà membre par elle : EADDRINUSE ; pas
     * d'interface : ENODEV. */
    ok = mc_mreq(t, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == EPROTO && mc_mreq(t, IP_DROP_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == EPROTO;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, 0, 7) == EINVAL && mc_mreq(s, IP_ADD_MEMBERSHIP, "10.0.0.1", 0, 0, 8) == EINVAL;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "255.255.255.255", 0, 0, 8) == EINVAL;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "224.0.0.1", 0, 0, 8) == 0 && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == 0;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == EADDRINUSE && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, eth, 12) == EADDRINUSE;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", moi, 0, 8) == EADDRINUSE && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, 1, 12) == 0;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", boucle, 0, 8) == EADDRINUSE
         && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", htonl(0x7f000002), 0, 8) == EADDRINUSE;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.4", 0, 9999, 12) == ENODEV && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.4", ailleurs, 0, 8) == ENODEV;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.4", ailleurs, 1, 12) == 0 && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.5", 0, 0, 9) == 0;
    verifier(ok, "IP_ADD_MEMBERSHIP : EPROTO, EINVAL, EADDRINUSE, ENODEV, dans l'ordre de Linux");
    contenu("/proc/net/igmp", lu, sizeof lu);
    igmp_attendu(attendu, sizeof attendu, "239.1.2.4/1 239.1.2.3/1 224.0.0.1/1", eth, nom, "239.1.2.5/1 239.1.2.3/1 224.0.0.1/2");
    verifier(strcmp(lu, attendu) == 0, "/proc/net/igmp : les groupes de lo et de la carte, le plus recent d'abord");
    /* 20 adhésions par socket : 15 de plus, puis ENOBUFS. */
    char g[20];
    int n;
    for (n = 0; n < 16; n++) {
        snprintf(g, sizeof g, "239.2.0.%d", n);
        if (mc_mreq(s, IP_ADD_MEMBERSHIP, g, 0, 0, 8) != 0)
            break;
    }
    verifier(n == 15 && mc_mreq(s, IP_ADD_MEMBERSHIP, g, 0, 0, 8) == ENOBUFS, "20 adhesions, puis ENOBUFS");
    /* IP_DROP_MEMBERSHIP : par la route, l'index, l'adresse ; pas de
     * contrôle du groupe. */
    ok = mc_mreq(s, IP_DROP_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == 0 && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == EADDRNOTAVAIL;
    ok = ok && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.1.2.3", 0, 9999, 12) == EADDRNOTAVAIL
         && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.1.2.3", ailleurs, 0, 8) == EADDRNOTAVAIL;
    ok = ok && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.1.2.3", boucle, 0, 8) == 0 && mc_mreq(s, IP_DROP_MEMBERSHIP, "10.0.0.1", 0, 0, 8) == EADDRNOTAVAIL;
    ok = ok && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.1.2.3", 0, 0, 7) == EINVAL && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, 0, 8) == 0;
    verifier(ok, "IP_DROP_MEMBERSHIP : par la route, l'index, l'adresse ; EADDRNOTAVAIL, EINVAL");
    /* La fermeture rend tout. */
    close(s);
    contenu("/proc/net/igmp", lu, sizeof lu);
    igmp_attendu(attendu, sizeof attendu, "224.0.0.1/1", eth, nom, "224.0.0.1/1");
    verifier(strcmp(lu, attendu) == 0, "close : chaque interface n'a plus que 224.0.0.1");

    /* MCAST_JOIN_GROUP, MCAST_LEAVE_GROUP : une group_req (136 octets au
     * moins), AF_INET ; l'index (0 : la route) ; TCP peut adhérer. */
    s = udp(0);
    ok = mc_groupe(s, MCAST_JOIN_GROUP, eth, "239.1.2.6", AF_INET, 135) == EINVAL && mc_groupe(s, MCAST_JOIN_GROUP, eth, "239.1.2.6", AF_INET6, 136) == EINVAL;
    ok = ok && mc_groupe(s, MCAST_JOIN_GROUP, eth, "10.0.0.1", AF_INET, 136) == EINVAL && mc_groupe(s, MCAST_JOIN_GROUP, eth, "239.1.2.6", AF_INET, 136) == 0;
    ok = ok && mc_groupe(s, MCAST_JOIN_GROUP, eth, "239.1.2.6", AF_INET, 200) == EADDRINUSE && mc_groupe(s, MCAST_JOIN_GROUP, 0, "239.1.2.8", AF_INET, 136) == 0;
    ok = ok && mc_groupe(s, MCAST_JOIN_GROUP, 9999, "239.1.2.8", AF_INET, 136) == ENODEV && mc_groupe(s, MCAST_LEAVE_GROUP, 0, "239.1.2.8", AF_INET, 136) == 0;
    ok = ok && mc_groupe(s, MCAST_LEAVE_GROUP, 0, "239.1.2.8", AF_INET, 136) == EADDRNOTAVAIL && mc_groupe(s, MCAST_LEAVE_GROUP, 0, "239.1.2.8", AF_INET6, 136) == EINVAL;
    ok = ok && mc_groupe(t, MCAST_JOIN_GROUP, eth, "239.1.2.7", AF_INET, 136) == 0;
    contenu("/proc/net/igmp", lu, sizeof lu);
    igmp_attendu(attendu, sizeof attendu, "224.0.0.1/1", eth, nom, "239.1.2.7/1 239.1.2.6/1 224.0.0.1/1");
    verifier(ok && strcmp(lu, attendu) == 0, "MCAST_JOIN_GROUP et MCAST_LEAVE_GROUP : EINVAL, EADDRINUSE, ENODEV ; TCP adhere");
    ok = mc_groupe(t, MCAST_LEAVE_GROUP, eth, "239.1.2.7", AF_INET, 136) == 0;
    close(s);
    close(t);

    /* Les sources (ip_mreq_source, 12 octets exactement) : EXCLUDE par
     * IP_BLOCK_SOURCE ; pas d'adhésion, pas un groupe : EINVAL ; une liste
     * dans l'autre mode : EINVAL ; une source absente, ou déjà là :
     * EADDRNOTAVAIL ; 10 au plus (ENOBUFS), ajoutées en fin de liste. */
    s = udp(0);
    ok = ok && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 12) == EINVAL && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 11) == EINVAL;
    ok = ok && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 13) == EINVAL && mc_source(s, IP_BLOCK_SOURCE, "10.0.0.9", 0, "10.0.0.1", 12) == EINVAL;
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.3.3.3", 0, 0, 8) == 0 && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", ailleurs, "10.0.0.1", 12) == ENODEV;
    ok = ok && mc_source(s, IP_UNBLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 12) == EADDRNOTAVAIL && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 12) == 0;
    ok = ok && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 12) == EADDRNOTAVAIL && mc_source(s, IP_UNBLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.2", 12) == EADDRNOTAVAIL;
    ok = ok && mc_source(s, IP_ADD_SOURCE_MEMBERSHIP, "239.3.3.3", 0, "10.0.0.3", 12) == EINVAL && mc_source(s, IP_DROP_SOURCE_MEMBERSHIP, "239.3.3.3", 0, "10.0.0.1", 12) == EINVAL;
    for (n = 18; n >= 10; n--) {
        snprintf(g, sizeof g, "10.0.0.%d", n);
        ok = ok && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, g, 12) == 0;
    }
    ok = ok && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.9", 12) == ENOBUFS && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 12) == ENOBUFS;
    verifier(ok, "IP_BLOCK_SOURCE et les autres : EINVAL, ENODEV, EADDRNOTAVAIL, 10 sources puis ENOBUFS");
    /* IP_MSFILTER lu : 16 octets au moins ; le mode, le vrai nombre de
     * sources, et autant de sources que demandé, même au-delà de la place
     * donnée (24 octets : 56 rendus, 40 écrits). */
    ok = mc_msfget(s, "239.3.3.3", 0, 12, 64, o, &l) == 0 && l == 56 && o[2] == 0 && o[3] == 10 && o[4] == dix(0, 0, 1) && o[5] == dix(0, 0, 18)
         && o[13] == dix(0, 0, 10) && o[14] == 0xaaaaaaaa;
    ok = ok && mc_msfget(s, "239.3.3.3", 0, 2, 64, o, &l) == 0 && l == 24 && o[3] == 10 && o[6] == 0xaaaaaaaa;
    ok = ok && mc_msfget(s, "239.3.3.3", 0, 12, 24, o, &l) == 0 && l == 56 && o[13] == dix(0, 0, 10) && o[14] == 0xaaaaaaaa;
    ok = ok && mc_msfget(s, "239.3.3.3", 0, 12, 15, o, &l) == EINVAL && mc_msfget(s, "239.3.3.4", 0, 12, 64, o, &l) == EADDRNOTAVAIL;
    ok = ok && mc_msfget(s, "10.0.0.1", 0, 12, 64, o, &l) == EINVAL && mc_msfget(s, "239.3.3.3", ailleurs, 12, 64, o, &l) == ENODEV;
    verifier(ok, "IP_MSFILTER lu : le mode, 10 sources, ecrites au-dela de la place ; EINVAL, EADDRNOTAVAIL, ENODEV");
    /* MCAST_MSFILTER lu : par l'index seul (0 : aucune adhésion), des
     * sockaddr_storage (144 + 128 par source). */
    static char gf[2000];
    struct group_filter *gfl = (void *)gf;
    struct sockaddr_in *ga = (void *)&gfl->gf_group;
    memset(gf, 0xaa, sizeof gf);
    gfl->gf_interface = eth;
    ga->sin_family = AF_INET;
    inet_pton(AF_INET, "239.3.3.3", &ga->sin_addr);
    gfl->gf_numsrc = 3;
    l = 144;
    struct sockaddr_in *s0 = (void *)(gf + 144), *s2 = (void *)(gf + 144 + 256);
    ok = getsockopt(s, IPPROTO_IP, MCAST_MSFILTER, gf, &l) == 0 && l == 528 && gfl->gf_fmode == 0 && gfl->gf_numsrc == 10
         && s0->sin_family == AF_INET && s0->sin_port == 0 && s0->sin_addr.s_addr == dix(0, 0, 1) && s2->sin_addr.s_addr == dix(0, 0, 17)
         && (unsigned char)gf[144 + 384] == 0xaa;
    gfl->gf_interface = 0;
    l = 1680;
    ok = ok && erreur(getsockopt(s, IPPROTO_IP, MCAST_MSFILTER, gf, &l)) == EADDRNOTAVAIL;
    l = 143;
    ok = ok && erreur(getsockopt(s, IPPROTO_IP, MCAST_MSFILTER, gf, &l)) == EINVAL;
    verifier(ok, "MCAST_MSFILTER lu : par l'index (0 : EADDRNOTAVAIL), des sockaddr_storage ; 143 octets : EINVAL");
    /* /proc/net/mcfilter : chaque source, exclue par une socket. */
    contenu("/proc/net/mcfilter", lu, sizeof lu);
    n = snprintf(attendu, sizeof attendu, "Idx Device        MCA        SRC    INC    EXC\n");
    for (int k = 0; k < 10; k++)
        n += snprintf(attendu + n, sizeof attendu - n, "%3d %6.6s 0x%08x 0x%08x %6lu %6lu\n", eth, nom, 0xef030303,
                      k == 0 ? 0x0a000001 : 0x0a000013 - k, 0ul, 1ul);
    verifier(strcmp(lu, attendu) == 0, "/proc/net/mcfilter : les 10 sources, dans l'ordre, exclues");
    ok = mc_source(s, IP_UNBLOCK_SOURCE, "239.3.3.3", 0, "10.0.0.1", 12) == 0 && mc_msfget(s, "239.3.3.3", 0, 12, 64, o, &l) == 0 && l == 52
         && o[3] == 9 && o[4] == dix(0, 0, 18);
    ok = ok && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.3.3.3", 0, 0, 8) == 0;
    /* INCLUDE : IP_ADD_SOURCE_MEMBERSHIP adhère d'abord ; la dernière source
     * retirée, le groupe est quitté. */
    ok = ok && mc_source(s, IP_ADD_SOURCE_MEMBERSHIP, "239.3.3.5", 0, "10.0.0.1", 12) == 0 && mc_source(s, IP_ADD_SOURCE_MEMBERSHIP, "239.3.3.5", 0, "10.0.0.2", 12) == 0;
    ok = ok && mc_source(s, IP_ADD_SOURCE_MEMBERSHIP, "239.3.3.5", 0, "10.0.0.2", 12) == EADDRNOTAVAIL && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.3.3.5", 0, 0, 8) == EADDRINUSE;
    ok = ok && mc_source(s, IP_BLOCK_SOURCE, "239.3.3.5", 0, "10.0.0.3", 12) == EINVAL;
    ok = ok && mc_msfget(s, "239.3.3.5", 0, 12, 64, o, &l) == 0 && l == 24 && o[2] == 1 && o[3] == 2 && o[5] == dix(0, 0, 2);
    contenu("/proc/net/mcfilter", lu, sizeof lu);
    n = snprintf(attendu, sizeof attendu, "Idx Device        MCA        SRC    INC    EXC\n");
    for (int k = 1; k <= 2; k++)
        n += snprintf(attendu + n, sizeof attendu - n, "%3d %6.6s 0x%08x 0x%08x %6lu %6lu\n", eth, nom, 0xef030305, 0x0a000000 + k, 1ul, 0ul);
    ok = ok && strcmp(lu, attendu) == 0;
    ok = ok && mc_source(s, IP_DROP_SOURCE_MEMBERSHIP, "239.3.3.5", 0, "10.0.0.1", 12) == 0 && mc_source(s, IP_DROP_SOURCE_MEMBERSHIP, "239.3.3.5", 0, "10.0.0.2", 12) == 0;
    ok = ok && mc_msfget(s, "239.3.3.5", 0, 12, 64, o, &l) == EADDRNOTAVAIL && mc_mreq(s, IP_DROP_MEMBERSHIP, "239.3.3.5", 0, 0, 8) == EADDRNOTAVAIL;
    /* Une adhésion simple, sans liste, change de mode à sa première source. */
    ok = ok && mc_mreq(s, IP_ADD_MEMBERSHIP, "239.3.3.6", 0, 0, 8) == 0 && mc_source(s, IP_ADD_SOURCE_MEMBERSHIP, "239.3.3.6", 0, "10.0.0.1", 12) == 0;
    ok = ok && mc_msfget(s, "239.3.3.6", 0, 12, 64, o, &l) == 0 && l == 20 && o[2] == 1 && o[3] == 1;
    verifier(ok, "INCLUDE : IP_ADD_SOURCE_MEMBERSHIP adhere ; la derniere source retiree, le groupe quitte ; /proc/net/mcfilter");

    /* IP_MSFILTER posé : 16 octets au moins ; pas un groupe, un mode
     * inconnu, pas d'adhésion : EINVAL ; INCLUDE {} sans adhésion :
     * EADDRNOTAVAIL ; plus de 10 sources : ENOBUFS ; pas la place : EINVAL ;
     * pas d'interface : ENODEV ; puis la liste et le mode remplacés. */
    uint32_t sources[12];
    for (int k = 0; k < 12; k++)
        sources[k] = dix(1, 1, k + 1);
    ok = mc_msfilter(s, "239.3.3.6", 0, 0, 0, sources, 15) == EINVAL && mc_msfilter(s, "10.0.0.1", 0, 0, 0, sources, 16) == EINVAL;
    ok = ok && mc_msfilter(s, "239.3.3.6", 0, 2, 0, sources, 16) == EINVAL && mc_msfilter(s, "239.3.3.7", 0, 0, 0, sources, 16) == EINVAL;
    ok = ok && mc_msfilter(s, "239.3.3.7", 0, 1, 0, sources, 16) == EADDRNOTAVAIL && mc_msfilter(s, "239.3.3.6", 0, 0, 11, sources, 60) == ENOBUFS;
    ok = ok && mc_msfilter(s, "239.3.3.6", 0, 0, 2, sources, 20) == EINVAL && mc_msfilter(s, "239.3.3.6", ailleurs, 0, 0, sources, 16) == ENODEV;
    ok = ok && mc_msfilter(s, "239.3.3.6", 0, 0, 3, sources, 28) == 0 && mc_msfget(s, "239.3.3.6", 0, 12, 64, o, &l) == 0 && l == 28 && o[2] == 0
         && o[3] == 3 && o[6] == sources[2];
    ok = ok && mc_msfilter(s, "239.3.3.6", 0, 1, 2, sources, 40) == 0 && mc_msfget(s, "239.3.3.6", 0, 12, 64, o, &l) == 0 && l == 24 && o[2] == 1;
    contenu("/proc/net/mcfilter", lu, sizeof lu);
    n = snprintf(attendu, sizeof attendu, "Idx Device        MCA        SRC    INC    EXC\n");
    for (int k = 0; k < 2; k++)
        n += snprintf(attendu + n, sizeof attendu - n, "%3d %6.6s 0x%08x 0x%08x %6lu %6lu\n", eth, nom, 0xef030306, ntohl(sources[k]), 1ul, 0ul);
    ok = ok && strcmp(lu, attendu) == 0;
    ok = ok && mc_msfilter(s, "239.3.3.6", 0, 1, 0, sources, 16) == 0 && mc_msfget(s, "239.3.3.6", 0, 12, 64, o, &l) == EADDRNOTAVAIL;
    verifier(ok, "IP_MSFILTER pose : EINVAL, EADDRNOTAVAIL, ENOBUFS, ENODEV ; la liste et le mode remplaces ; INCLUDE {} : le depart");
    /* MCAST_MSFILTER posé : 144 octets au moins, 128 par source ; l'index
     * (0 : la route). */
    uint32_t deux[2] = { dix(2, 2, 1), dix(2, 2, 2) };
    ok = mc_groupe(s, MCAST_JOIN_GROUP, eth, "239.3.3.8", AF_INET, 136) == 0 && mc_gsf(s, eth, "239.3.3.8", 1, 0, deux, 143) == EINVAL;
    ok = ok && mc_gsf(s, eth, "239.3.3.8", 1, 11, deux, 1552) == ENOBUFS && mc_gsf(s, eth, "239.3.3.8", 1, 2, deux, 144) == EINVAL;
    ok = ok && mc_gsf(s, eth, "239.3.3.8", 1, 2, deux, 400) == 0 && mc_gsf(s, 0, "239.3.3.8", 0, 1, deux, 272) == 0;
    gfl->gf_interface = eth;
    inet_pton(AF_INET, "239.3.3.8", &ga->sin_addr);
    l = 1680;
    ok = ok && getsockopt(s, IPPROTO_IP, MCAST_MSFILTER, gf, &l) == 0 && l == 272 && gfl->gf_fmode == 0 && gfl->gf_numsrc == 1
         && s0->sin_addr.s_addr == deux[0];
    verifier(ok, "MCAST_MSFILTER pose : EINVAL, ENOBUFS ; par l'index, puis par la route");
    /* MCAST_*_SOURCE (une group_source_req, 264 octets exactement) : une
     * autre famille : EADDRNOTAVAIL ; MCAST_JOIN_SOURCE_GROUP adhère par
     * l'index (0 : la route). */
    ok = mc_groupe_source(s, MCAST_JOIN_SOURCE_GROUP, eth, "239.3.3.9", "10.0.0.1", AF_INET, 263) == EINVAL;
    ok = ok && mc_groupe_source(s, MCAST_JOIN_SOURCE_GROUP, eth, "239.3.3.9", "10.0.0.1", AF_INET6, 264) == EADDRNOTAVAIL;
    ok = ok && mc_groupe_source(s, MCAST_JOIN_SOURCE_GROUP, eth, "239.3.3.9", "10.0.0.1", AF_INET, 264) == 0;
    ok = ok && mc_groupe_source(s, MCAST_JOIN_SOURCE_GROUP, 0, "239.3.3.9", "10.0.0.2", AF_INET, 264) == 0;
    ok = ok && mc_groupe_source(s, MCAST_BLOCK_SOURCE, eth, "239.3.3.9", "10.0.0.3", AF_INET, 264) == EINVAL;
    ok = ok && mc_groupe_source(s, MCAST_LEAVE_SOURCE_GROUP, eth, "239.3.3.9", "10.0.0.1", AF_INET, 264) == 0;
    contenu("/proc/net/igmp", lu, sizeof lu);
    igmp_attendu(attendu, sizeof attendu, "224.0.0.1/1", eth, nom, "239.3.3.9/1 239.3.3.8/1 224.0.0.1/1");
    ok = ok && strcmp(lu, attendu) == 0;
    contenu("/proc/net/mcfilter", lu, sizeof lu);
    snprintf(attendu, sizeof attendu, "Idx Device        MCA        SRC    INC    EXC\n%3d %6.6s 0x%08x 0x%08x %6lu %6lu\n%3d %6.6s 0x%08x 0x%08x %6lu %6lu\n",
             eth, nom, 0xef030309, 0x0a000002, 1ul, 0ul, eth, nom, 0xef030308, 0x0a020201, 0ul, 1ul);
    verifier(ok && strcmp(lu, attendu) == 0, "MCAST_JOIN_SOURCE_GROUP, MCAST_LEAVE_SOURCE_GROUP ; /proc/net/igmp et mcfilter");
    close(s);
}

/* La multidiffusion, le trafic (les soldes d'avant 6k ; mesuré sous Linux
 * 6.18.33, une sonde) : un envoi vers un groupe part par l'interface
 * d'IP_MULTICAST_IF, sinon par celle de la route (la route par défaut, mais
 * jamais vers sa passerelle) ; si cette interface a le groupe, et que son
 * filtre laisse passer la source (RTCF_LOCAL), une copie revient aux
 * sockets de la machine, comme arrivée par la carte, sauf avec
 * IP_MULTICAST_LOOP 0 ; un TTL 0 ne sort pas, mais la copie revient. Par lo,
 * il n'est livré que si lo a le groupe (224.0.0.1). Le TTL : celui d'IP_TTL
 * en message de contrôle, sinon IP_MULTICAST_TTL (IP_TTL de la socket ne
 * compte pas). La source : l'adresse donnée à IP_MULTICAST_IF, sinon celle
 * de la route ; une socket liée à 127.0.0.1, sans interface, envoie par lo
 * (le « hack de vic/vat »). À l'arrivée, une socket liée au port reçoit
 * chaque groupe qu'a l'interface (IP_MULTICAST_ALL 1), ou seulement ceux
 * de ses adhésions (0), selon les filtres de sources : le sien, et celui de
 * l'interface (qui n'entre pas n'arrive à personne). SO_DONTROUTE : pas de
 * route par défaut, ENETUNREACH sans interface. TCP : connect vers un
 * groupe ou une diffusion, ENETUNREACH. Il faut une carte : sinon, sautée. */
static ssize_t recu_mc(int r, struct sockaddr_in *de, struct in_pktinfo *pi, int *ttl, int ms)
{
    struct pollfd f = { .fd = r, .events = POLLIN };
    memset(pi, 0, sizeof *pi);
    *ttl = -1;
    if (poll(&f, 1, ms) != 1)
        return -1;
    static char o[2048];
    char c[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(int))];
    struct iovec v = { o, sizeof o };
    struct msghdr m = { .msg_name = de, .msg_namelen = sizeof *de, .msg_iov = &v, .msg_iovlen = 1, .msg_control = c,
                        .msg_controllen = sizeof c };
    ssize_t n = recvmsg(r, &m, MSG_DONTWAIT);
    for (struct cmsghdr *h = n < 0 ? NULL : CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h)) {
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO)
            memcpy(pi, CMSG_DATA(h), sizeof *pi);
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_TTL)
            memcpy(ttl, CMSG_DATA(h), sizeof *ttl);
    }
    return n;
}

/* `r` reçoit-il un datagramme d'un octet de `de`, arrivé par l'interface
 * `k`, pour `groupe`, notre adresse pour répondre étant `spec`, avec le TTL
 * `ttl` (-1 : quelconque) ? */
static int mc_recoit(int r, uint32_t de, int k, uint32_t spec, uint32_t groupe, int ttl)
{
    struct sockaddr_in a = { 0 };
    struct in_pktinfo pi;
    int t;
    return recu_mc(r, &a, &pi, &t, 1000) == 1 && a.sin_addr.s_addr == de && pi.ipi_ifindex == k
           && pi.ipi_spec_dst.s_addr == spec && pi.ipi_addr.s_addr == groupe && (ttl < 0 || t == ttl);
}

/* `r` ne reçoit-il rien en 200 ms ? */
static int mc_rien(int r)
{
    struct sockaddr_in a;
    struct in_pktinfo pi;
    int t;
    return recu_mc(r, &a, &pi, &t, 200) < 0;
}

/* Un octet vers `vers`:`port`, avec IP_TTL `ttl` en message de contrôle. */
static int envoyer_avec_ttl(int s, uint32_t vers, uint16_t port, int ttl)
{
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = port, .sin_addr.s_addr = vers };
    char c[CMSG_SPACE(sizeof(int))] = { 0 };
    struct iovec v = { (void *)"x", 1 };
    struct msghdr m = { .msg_name = &d, .msg_namelen = sizeof d, .msg_iov = &v, .msg_iovlen = 1, .msg_control = c,
                        .msg_controllen = sizeof c };
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = IPPROTO_IP;
    h->cmsg_type = IP_TTL;
    h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &ttl, sizeof ttl);
    return erreur(sendmsg(s, &m, 0));
}

/* connect TCP vers `vers` (port 80), d'une socket liée à `source` (0 :
 * non liée) et à l'interface d'index `interface` (0 : aucune) : son errno
 * (0 : accepté ; -1 : bind ou SO_BINDTOIFINDEX refusé). */
static int tcp_depuis(uint32_t source, int interface, uint32_t vers)
{
    int t = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in s = { .sin_family = AF_INET, .sin_addr.s_addr = source };
    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = htons(80), .sin_addr.s_addr = vers };
    int e = -1;
    if ((interface == 0 || setsockopt(t, SOL_SOCKET, SO_BINDTOIFINDEX, &interface, sizeof interface) == 0)
        && (source == 0 || bind(t, (struct sockaddr *)&s, sizeof s) == 0))
        e = erreur(connect(t, (struct sockaddr *)&d, sizeof d));
    close(t);
    return e;
}

/* La même, non liée. */
static int tcp_vers(uint32_t vers)
{
    return tcp_depuis(0, 0, vers);
}

static void multidiffusion_trafic(void)
{
    uint32_t passerelle, diffusion;
    if (!passerelle_par_defaut(&passerelle) || !diffusion_du_reseau(&diffusion)) {
        verifier(1, "pas de carte : le trafic de la multidiffusion, saute");
        return;
    }
    const uint32_t g = inet_addr("239.1.2.3"), tous = inet_addr("224.0.0.1"), personne = inet_addr("239.9.8.7");
    const uint32_t boucle = htonl(LO), un_deux = inet_addr("1.2.3.4");
    int un = 1, zero = 0, v;
    /* Notre adresse (celle d'une socket connectée ailleurs), et l'index de
     * la carte (l'arrivée d'un datagramme à nous : IP_PKTINFO). */
    int s = udp(0), r = udp(0), c;
    struct sockaddr_in a = adresse(0xc0000201, 9), nous, de;
    socklen_t l = sizeof nous;
    connect(s, (struct sockaddr *)&a, sizeof a);
    getsockname(s, (struct sockaddr *)&nous, &l);
    close(s);
    a = adresse(0, 0);
    l = sizeof a;
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &l);
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    struct in_pktinfo pi = { 0 };
    s = udp(0);
    envoyer_par(s, "x", 1, nous.sin_addr.s_addr, a.sin_port, 0);
    recu_avec_pktinfo(r, &de, &pi, 1000);
    close(s);
    close(r);
    const int eth = pi.ipi_ifindex;
    const uint32_t moi = nous.sin_addr.s_addr;

    /* r et c, liées au même port (SO_REUSEADDR) ; r adhère au groupe par la
     * carte, pas c. s envoie. */
    r = udp(0);
    c = udp(0);
    s = udp(0);
    a = adresse(0, 0);
    l = sizeof a;
    setsockopt(r, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    setsockopt(c, SOL_SOCKET, SO_REUSEADDR, &un, sizeof un);
    bind(r, (struct sockaddr *)&a, sizeof a);
    getsockname(r, (struct sockaddr *)&a, &l);
    bind(c, (struct sockaddr *)&a, sizeof a);
    const uint16_t port = a.sin_port;
    for (int k = 0; k < 2; k++) {
        setsockopt(k ? c : r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
        setsockopt(k ? c : r, IPPROTO_IP, IP_RECVTTL, &un, sizeof un);
    }
    int ok = mc_mreq(r, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, eth, sizeof(struct ip_mreqn)) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0;
    ok = ok && mc_recoit(r, moi, eth, moi, g, 1) && mc_recoit(c, moi, eth, moi, g, 1);
    l = sizeof a;
    ok = ok && getsockname(s, (struct sockaddr *)&a, &l) == 0 && a.sin_addr.s_addr == 0 && a.sin_port != 0;
    verifier(ok, "vers un groupe de la carte : la copie revient, de nous, comme arrivee par la carte, TTL 1 ; la source reste 0.0.0.0");

    /* IP_MULTICAST_LOOP 0 : pas de copie. */
    ok = setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &zero, sizeof zero) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_rien(r) && mc_rien(c);
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &un, sizeof un);
    verifier(ok, "IP_MULTICAST_LOOP 0 : pas de copie");

    /* IP_MULTICAST_ALL 0 : seulement les groupes de ses adhésions. c n'en a
     * aucune ; r n'a pas 224.0.0.1 (que la carte a). */
    ok = setsockopt(c, IPPROTO_IP, IP_MULTICAST_ALL, &zero, sizeof zero) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 1) && mc_rien(c);
    setsockopt(c, IPPROTO_IP, IP_MULTICAST_ALL, &un, sizeof un);
    ok = ok && setsockopt(r, IPPROTO_IP, IP_MULTICAST_ALL, &zero, sizeof zero) == 0;
    ok = ok && envoyer_par(s, "x", 1, tous, port, 0) == 0 && mc_recoit(c, moi, eth, moi, tous, 1) && mc_rien(r);
    setsockopt(r, IPPROTO_IP, IP_MULTICAST_ALL, &un, sizeof un);
    /* Un groupe que personne n'a : rien. */
    ok = ok && envoyer_par(s, "x", 1, personne, port, 0) == 0 && mc_rien(r) && mc_rien(c);
    verifier(ok, "IP_MULTICAST_ALL 0 : seulement ses adhesions ; 224.0.0.1 ; un groupe que personne n'a");

    /* Le TTL : IP_TTL de la socket ne compte pas ; IP_MULTICAST_TTL ; IP_TTL
     * en message de contrôle ; un TTL 0 : la copie revient. */
    v = 50;
    ok = setsockopt(s, IPPROTO_IP, IP_TTL, &v, sizeof v) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 1) && mc_recoit(c, moi, eth, moi, g, 1);
    v = 7;
    ok = ok && setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &v, sizeof v) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 7) && mc_recoit(c, moi, eth, moi, g, 7);
    ok = ok && envoyer_avec_ttl(s, g, port, 9) == 0 && mc_recoit(r, moi, eth, moi, g, 9) && mc_recoit(c, moi, eth, moi, g, 9);
    v = 0;
    ok = ok && setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &v, sizeof v) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 0) && mc_recoit(c, moi, eth, moi, g, 0);
    v = 1;
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &v, sizeof v);
    verifier(ok, "le TTL : IP_MULTICAST_TTL, IP_TTL en message de controle, pas IP_TTL de la socket ; TTL 0, la copie revient");

    /* IP_MULTICAST_IF lo : vers le groupe, personne (lo ne l'a pas) ; vers
     * 224.0.0.1, livré par lo, de notre adresse (celles de lo sont de portée
     * « hôte »). */
    ok = mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", 0, 1, sizeof(struct ip_mreqn)) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_rien(r) && mc_rien(c);
    ok = ok && envoyer_par(s, "x", 1, tous, port, 0) == 0 && mc_recoit(r, moi, 1, moi, tous, 1) && mc_recoit(c, moi, 1, moi, tous, 1);
    /* IP_MULTICAST_IF 127.0.0.1 : par lo, de 127.0.0.1 ; notre adresse : la
     * carte, de la nôtre. */
    ok = ok && mc_poser(s, IP_MULTICAST_IF, &boucle, 4) == 0;
    ok = ok && envoyer_par(s, "x", 1, tous, port, 0) == 0 && mc_recoit(r, boucle, 1, boucle, tous, 1) && mc_recoit(c, boucle, 1, boucle, tous, 1);
    ok = ok && mc_poser(s, IP_MULTICAST_IF, &moi, 4) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 1) && mc_recoit(c, moi, eth, moi, g, 1);
    ok = ok && mc_poser(s, IP_MULTICAST_IF, &zero, 4) == 0;
    verifier(ok, "IP_MULTICAST_IF : lo (livre si lo a le groupe), 127.0.0.1 (la source), notre adresse");

    /* Liée à 127.0.0.1, sans interface : par lo (vic et vat). */
    int q = udp(0);
    struct sockaddr_in b = adresse(LO, 0);
    ok = bind(q, (struct sockaddr *)&b, sizeof b) == 0;
    ok = ok && envoyer_par(q, "x", 1, tous, port, 0) == 0 && mc_recoit(r, boucle, 1, boucle, tous, 1) && mc_recoit(c, boucle, 1, boucle, tous, 1);
    ok = ok && envoyer_par(q, "x", 1, g, port, 0) == 0 && mc_rien(r) && mc_rien(c);
    close(q);
    verifier(ok, "liee a 127.0.0.1 : par lo, vers 224.0.0.1 seulement");

    /* SO_DONTROUTE : pas de route (la route par défaut ne compte plus) ;
     * avec une interface, si. */
    ok = setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &un, sizeof un) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == ENETUNREACH;
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", 0, eth, sizeof(struct ip_mreqn)) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 1) && mc_recoit(c, moi, eth, moi, g, 1);
    ok = ok && mc_mreq(s, IP_MULTICAST_IF, "0.0.0.0", 0, 0, sizeof(struct ip_mreqn)) == 0;
    setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &zero, sizeof zero);
    verifier(ok, "SO_DONTROUTE vers un groupe : ENETUNREACH sans interface, envoye avec IP_MULTICAST_IF");

    /* Les filtres de sources. Celui de l'interface est l'union de ceux des
     * adhésions : qui n'y entre pas n'arrive à personne (pas de copie), ni
     * à r, ni à c (liée au port). INCLUDE {1.2.3.4} : r est seule membre,
     * l'interface ne laisse entrer que 1.2.3.4 (personne) ; EXCLUDE
     * {1.2.3.4} (les deux) ; EXCLUDE {nous} (personne) ; c adhère aussi
     * (EXCLUDE {}) : l'interface laisse tout entrer, le filtre de r
     * l'arrête encore. */
    ok = mc_msfilter(r, "239.1.2.3", moi, MCAST_INCLUDE, 1, &un_deux, 20) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_rien(r) && mc_rien(c);
    ok = ok && mc_msfilter(r, "239.1.2.3", moi, MCAST_EXCLUDE, 1, &un_deux, 20) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_recoit(r, moi, eth, moi, g, 1) && mc_recoit(c, moi, eth, moi, g, 1);
    ok = ok && mc_msfilter(r, "239.1.2.3", moi, MCAST_EXCLUDE, 1, &moi, 20) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_rien(r) && mc_rien(c);
    ok = ok && mc_mreq(c, IP_ADD_MEMBERSHIP, "239.1.2.3", 0, eth, sizeof(struct ip_mreqn)) == 0;
    ok = ok && envoyer_par(s, "x", 1, g, port, 0) == 0 && mc_rien(r) && mc_recoit(c, moi, eth, moi, g, 1);
    verifier(ok, "les filtres de sources : celui de la socket, puis celui de l'interface");
    close(r);
    close(c);
    close(s);

    /* TCP : ni vers un groupe, ni vers une diffusion (de la carte, ou de
     * lo). */
    ok = tcp_vers(g) == ENETUNREACH && tcp_vers(diffusion) == ENETUNREACH && tcp_vers(inet_addr("127.255.255.255")) == ENETUNREACH;
    verifier(ok, "TCP : connect vers un groupe, une diffusion : ENETUNREACH");

    /* Liée à 127.0.0.1 ou 127.0.0.2, sans interface : le hack de vic et vat
     * vaut pour TCP aussi (`ip_route_connect`), la route passe par lo, et
     * c'est le groupe ou la diffusion qui est refusé : ENETUNREACH (pas la
     * source de la boucle hors de lo, EINVAL, par la route par défaut).
     * Liée aussi à la carte : pas de hack, EINVAL ; à lo : ENETUNREACH. */
    const uint32_t lo2 = htonl(LO + 1), limitee = htonl(INADDR_BROADCAST);
    ok = tcp_depuis(boucle, 0, g) == ENETUNREACH && tcp_depuis(boucle, 0, tous) == ENETUNREACH;
    ok = ok && tcp_depuis(boucle, 0, limitee) == ENETUNREACH && tcp_depuis(lo2, 0, g) == ENETUNREACH;
    ok = ok && tcp_depuis(lo2, 0, limitee) == ENETUNREACH && tcp_depuis(moi, 0, g) == ENETUNREACH;
    ok = ok && tcp_depuis(boucle, eth, g) == EINVAL && tcp_depuis(boucle, eth, limitee) == EINVAL;
    ok = ok && tcp_depuis(boucle, 1, g) == ENETUNREACH;
    verifier(ok, "TCP lie a 127.0.0.1 vers un groupe ou 255.255.255.255 : par lo, ENETUNREACH ; lie aussi a la carte : EINVAL");
}

/* Le compteur `nom` du groupe `groupe` de /proc/net/snmp (« Udp: »,
 * « Icmp: » : deux lignes, les noms puis les valeurs) ; -1 : pas trouvé. */
static long compteur_snmp(const char *groupe, const char *nom)
{
    char noms[1024], valeurs[1024];
    size_t g = strlen(groupe);
    long r = -1;
    FILE *f = fopen("/proc/net/snmp", "r");
    while (f && fgets(noms, sizeof noms, f))
        if (strncmp(noms, groupe, g) == 0 && fgets(valeurs, sizeof valeurs, f)) {
            char *pn, *pv, *n = strtok_r(noms + g, " \n", &pn), *v = strtok_r(valeurs + g, " \n", &pv);
            for (; n && v; n = strtok_r(NULL, " \n", &pn), v = strtok_r(NULL, " \n", &pv))
                if (strcmp(n, nom) == 0)
                    r = atol(v);
            break;
        }
    if (f)
        fclose(f);
    return r;
}

/* Ce que l'hôte envoie à la machine, par la carte (make tests-qemu,
 * test-carte : `hostfwd` de slirp vers le port 4000) : la somme d'UDP
 * (IP_CHECKSUM) d'un datagramme venu par une carte, et IP_RECVFRAGSIZE
 * d'un datagramme en morceaux. slirp coupe ce qui dépasse sa MTU de 1 500
 * octets : chaque morceau, sauf le dernier, en fait 1 500, en-tête compris.
 * Dans l'ordre :
 *   - « petit » (28 octets ; 36 avec son en-tête, pas plus de 76) : sa
 *     somme est faite à l'arrivée sur tout le segment, puis celle de
 *     l'en-tête en est ôtée ;
 *   - 3 000 octets lus en entier : ni somme (elle attend une lecture qui
 *     coupe ou regarde), mais RECVFRAGSIZE 1 500 ;
 *   - 3 000 octets regardés (MSG_PEEK), puis regardés 100 octets plus loin
 *     (SO_PEEK_OFF), puis lus : la somme des données, celle des 100
 *     premiers octets ôtée pour le deuxième, et gardée pour la lecture ;
 *   - 3 000 octets lus dans 10 octets : coupé, la somme.
 * Pas de vérification sur l'hôte : sa carte vérifie les sommes elle-même.
 * Puis une écoute TCP sur le port 4001 (IP_TTL 33, IP_TOS 0x20) reste
 * ouverte une minute, sans rien accepter : le scénario lui envoie des
 * segments par la carte, et regarde ce qui en sort (le TOS et le TTL des
 * réponses, Makefile) ; elle est là dès le début, prête quand il le
 * sera. */
static int carte(void)
{
    int r = udp(0);
    struct sockaddr_in a = adresse(0, 4000);
    if (bind(r, (struct sockaddr *)&a, sizeof a) != 0)
        return printf("[linux] reseau carte : bind : ECHEC (%s)\n", strerror(errno)), 1;
    tous_les_controles(r);
    int e = socket(AF_INET, SOCK_STREAM, 0), ttl = 33, tos = 0x20;
    struct sockaddr_in ea = adresse(0, 4001);
    if (setsockopt(e, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl) != 0 || setsockopt(e, IPPROTO_IP, IP_TOS, &tos, sizeof tos) != 0
        || bind(e, (struct sockaddr *)&ea, sizeof ea) != 0 || listen(e, 4) != 0)
        return printf("[linux] reseau carte : l'ecoute TCP : ECHEC (%s)\n", strerror(errno)), 1;
    /* La socket qui recevra les erreurs ICMP de 10.0.2.77 (port 4002 vers
     * son port 9) : sa file d'erreurs, et les extensions (RFC 4884). Rien
     * n'est envoyé : une erreur ICMP trouve la socket par ses adresses et
     * ses ports, sans qu'on vérifie qu'elle a parlé (comme sous Linux). */
    int x = udp(0), un = 1;
    struct sockaddr_in xa = adresse(0, 4002), xd = adresse(0x0a00024d, 9);
    if (bind(x, (struct sockaddr *)&xa, sizeof xa) != 0 || connect(x, (struct sockaddr *)&xd, sizeof xd) != 0
        || setsockopt(x, IPPROTO_IP, IP_RECVERR, &un, sizeof un) != 0
        || setsockopt(x, IPPROTO_IP, IP_RECVERR_RFC4884, &un, sizeof un) != 0)
        return printf("[linux] reseau carte : la socket des erreurs : ECHEC (%s)\n", strerror(errno)), 1;
    /* Une adhésion à 239.1.2.3 (port 4003), par la carte (la route vers les
     * groupes, que le DHCP a donnée avant le lancement) : la machine
     * l'annonce aux routeurs, deux rapports IGMPv3 TO_EX {} (le Makefile les
     * lit dans l'enregistrement de la carte, outils/igmp.awk). */
    int m = udp(0);
    struct sockaddr_in ma = adresse(0, 4003);
    struct ip_mreqn mr = { .imr_multiaddr.s_addr = inet_addr("239.1.2.3") };
    if (bind(m, (struct sockaddr *)&ma, sizeof ma) != 0 || setsockopt(m, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr) != 0)
        return printf("[linux] reseau carte : l'adhesion : ECHEC (%s)\n", strerror(errno)), 1;
    printf("[linux] reseau carte : en attente\n");
    fflush(stdout);
    static unsigned char o[4000];
    char t[512];
    int f;
    size_t l;
    struct sockaddr_in de;
    socklen_t dl = sizeof de;
    struct pollfd p = { r, POLLIN, 0 };
    if (poll(&p, 1, 60000) != 1)
        return printf("[linux] reseau carte : rien recu : ECHEC\n"), 1;
    recvfrom(r, o, sizeof o, MSG_PEEK, (struct sockaddr *)&de, &dl);
    /* Le petit : sa somme UDP, que slirp a calculée (de 10.0.2.2 vers
     * 10.0.2.15), refaite ici pour son en-tête. */
    ssize_t n = recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l);
    unsigned char seg[8 + 64] = { 0 };
    memcpy(seg, &de.sin_port, 2);
    seg[2] = 4000 >> 8, seg[3] = 4000 & 0xff;
    seg[4] = 0, seg[5] = 8 + n;
    memcpy(seg + 8, o, n > 0 && n <= 64 ? n : 0);
    unsigned char pseudo[12] = { 10, 0, 2, 2, 10, 0, 2, 15, 0, 17, 0, 8 + n };
    uint32_t c = (somme_linux(pseudo, 12) + (uint64_t)somme_linux(seg, 8 + n)) % 0xffffffff;
    c = (c & 0xffff) + (c >> 16);
    uint16_t c16 = ~(uint16_t)((c & 0xffff) + (c >> 16));
    memcpy(seg + 6, &c16, 2);
    if (c16 == 0)
        seg[6] = seg[7] = 0xff;
    uint32_t attendue = n > 0 ? somme_moins(somme_linux(seg, 8 + n), somme_linux(seg, 8)) : 0;
    char attendu[512] = "23:4:";
    en_hexa(attendu, &attendue, 4);
    int ok = n == 28 && memcmp(o, "petit datagramme de la carte", 28) == 0 && strstr(t, attendu) && !strstr(t, "25:4:");
    verifier(ok, "carte, 28 octets : la somme faite a l'arrivee, l'en-tete ote");
    if (!ok)
        printf("[linux] reseau :   %zd %s\n[linux] reseau :   attendu %s\n", n, t, attendu);
    /* 3 000 octets lus en entier. */
    n = recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l);
    verifier(n == 3000 && !strstr(t, "23:4:") && strstr(t, "25:4:dc050000"), "carte, 3 000 octets lus : pas de somme, RECVFRAGSIZE 1 500");
    /* Regardés, regardés plus loin, lus. */
    n = recevoir_controles(r, o, sizeof o, MSG_PEEK, 512, t, sizeof t, &f, &l);
    uint32_t s = n == 3000 ? somme_linux(o, 3000) : 0;
    strcpy(attendu, "23:4:");
    en_hexa(attendu, &s, 4);
    ok = n == 3000 && strstr(t, attendu);
    int cent = 100;
    setsockopt(r, SOL_SOCKET, SO_PEEK_OFF, &cent, sizeof cent);
    n = recevoir_controles(r, o + 100, 64, MSG_PEEK, 512, t, sizeof t, &f, &l);
    uint32_t s100 = somme_moins(s, somme_linux(o, 100));
    strcpy(attendu, "23:4:");
    en_hexa(attendu, &s100, 4);
    ok = ok && n == 64 && strstr(t, attendu);
    int moins = -1;
    setsockopt(r, SOL_SOCKET, SO_PEEK_OFF, &moins, sizeof moins);
    n = recevoir_controles(r, o, sizeof o, 0, 512, t, sizeof t, &f, &l);
    strcpy(attendu, "23:4:");
    en_hexa(attendu, &s, 4);
    verifier(ok && n == 3000 && strstr(t, attendu), "carte, 3 000 octets regardes (et 100 plus loin), puis lus : la somme, gardee");
    /* Coupé. */
    n = recevoir_controles(r, o, 10, 0, 512, t, sizeof t, &f, &l);
    verifier(n == 10 && f == MSG_TRUNC && strstr(t, "23:4:"), "carte, 3 000 octets lus dans 10 : coupe, la somme");
    close(r);
    /* Le scénario débranche slirp et joue 10.0.2.77 (outils/envoyer-segments) :
     * des segments TCP vers l'écoute (le Makefile vérifie les réponses), puis
     * deux erreurs ICMP « port injoignable » pour x, d'une copie de 128
     * octets (la longueur que dit l'octet 5 : 32 mots), suivie d'extensions
     * (un objet de 8 octets) : de somme juste, puis fausse. Ce que lit le
     * programme commence après les en-têtes IPv4 et UDP de la copie : 100
     * octets, puis les 12 des extensions. */
    long icmp_fautes = compteur_snmp("Icmp: ", "InErrors");
    long ignorees = compteur_snmp("Udp: ", "IgnoredMulti"), sommes = compteur_snmp("Udp: ", "InCsumErrors"), fautes = compteur_snmp("Udp: ", "InErrors");
    printf("[linux] reseau carte : en attente des segments\n");
    fflush(stdout);
    struct sock_extended_err ee[2] = { 0 };
    struct sockaddr_in qui, nom;
    struct in_pktinfo pi;
    long lu[2] = { -1, -1 };
    int ok_ext = 1;
    static const unsigned char objet[8] = { 0, 8, 1, 1, 0xde, 0xad, 0xbe, 0xef };
    for (int i = 0; i < 2; i++) {
        struct pollfd px = { x, 0, 0 };
        if (poll(&px, 1, 60000) != 1 || !(px.revents & POLLERR))
            break;
        lu[i] = erreur_en_file(x, (char *)o, sizeof o, &ee[i], &qui, &nom, &f, &pi);
        ok_ext = ok_ext && lu[i] == 112 && o[0] == 'x' && o[99] == 'x' && o[100] == 0x20 && o[101] == 0
                 && memcmp(o + 104, objet, 8) == 0 && ee[i].ee_errno == ECONNREFUSED
                 && ee[i].ee_origin == SO_EE_ORIGIN_ICMP && ee[i].ee_type == 3 && ee[i].ee_code == 3;
    }
    verifier(ok_ext && ee[0].ee_data == 0x64 && ee[1].ee_data == 0x10064,
             "carte, RFC 4884 : deux erreurs ICMP, les extensions a 100 octets (ee_data 0x64), puis de somme fausse (0x10064)");
    if (lu[0] != 112 || lu[1] != 112 || ee[0].ee_data != 0x64 || ee[1].ee_data != 0x10064)
        printf("[linux] reseau :   lu %ld et %ld, ee_data %#x et %#x\n", lu[0], lu[1], ee[0].ee_data, ee[1].ee_data);
    close(x);
    /* Avant ces erreurs, le scénario a envoyé de la multidiffusion et des
     * requêtes d'IGMP : un datagramme de 10.0.2.77 pour 239.1.2.3 (m le
     * reçoit), un pour 239.1.2.4 (la machine n'en est pas membre : rien) ;
     * une requête v3 générale, puis une requête v2 (délai 0,1 s chacune) :
     * le routeur de la carte est noté v2, et notre rapport v2 sur 239.1.2.3
     * fait de nous le rapporteur (/proc/net/igmp ; les rapports eux-mêmes,
     * le Makefile les lit dans l'enregistrement). */
    char mc[16];
    ssize_t k = recv(m, mc, sizeof mc, MSG_DONTWAIT);
    int ok_mc = k == 6 && memcmp(mc, "xxxxxx", 6) == 0;
    ok_mc = ok_mc && recv(m, mc, sizeof mc, MSG_DONTWAIT) < 0 && errno == EAGAIN;
    verifier(ok_mc, "carte, multidiffusion : le datagramme pour notre groupe recu, pas celui d'un autre");
    /* Deux diffusions de somme fausse, que personne n'écoute : celle de 38
     * octets vérifiée à l'arrivée, celle de 208 jamais (IgnoredMulti). */
    ignorees = compteur_snmp("Udp: ", "IgnoredMulti") - ignorees;
    sommes = compteur_snmp("Udp: ", "InCsumErrors") - sommes;
    fautes = compteur_snmp("Udp: ", "InErrors") - fautes;
    verifier(ignorees == 1 && sommes == 1 && fautes == 1,
             "carte, diffusions de somme fausse : 38 octets, InCsumErrors et InErrors ; 208 octets, IgnoredMulti");
    if (ignorees != 1 || sommes != 1 || fautes != 1)
        printf("[linux] reseau :   IgnoredMulti %ld, InCsumErrors %ld, InErrors %ld\n", ignorees, sommes, fautes);
    /* Deux redirections qui citent un en-tête de 4 mots : UDP, qui n'y
     * trouve pas de socket, la compte (Icmp InErrors) ; ping, non. */
    icmp_fautes = compteur_snmp("Icmp: ", "InErrors") - icmp_fautes;
    verifier(icmp_fautes == 1, "carte, redirections d'un en-tete de 4 mots : UDP compte InErrors, ping non");
    if (icmp_fautes != 1)
        printf("[linux] reseau :   Icmp InErrors %ld\n", icmp_fautes);
    char proc_igmp[1024];
    contenu("/proc/net/igmp", proc_igmp, sizeof proc_igmp);
    ok_mc = strstr(proc_igmp, "eth0      :     2      V2\n\t\t\t\t030201EF     1 0:00000000\t\t1\n") != NULL;
    verifier(ok_mc, "carte, IGMP : le routeur v2 entendu, notre rapport v2 fait (/proc/net/igmp)");
    if (!ok_mc)
        printf("[linux] reseau :   %s", proc_igmp);
    /* Le départ : en v2, et rapporteur, la machine l'annonce tout de suite
     * (vers 224.0.0.2 : le dernier message que lit le Makefile). */
    close(m);
    printf("[linux] reseau carte : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    fflush(stdout);
    /* L'écoute reste ouverte jusqu'à l'arrêt de la machine : sa fille
     * (le SYN du scénario) ne doit rien envoyer de plus à l'enregistrement
     * qu'il lit. */
    struct pollfd pe = { e, POLLIN, 0 };
    poll(&pe, 1, 60000);
    close(e);
    return echecs != 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "carte") == 0)
        return carte();
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
    decalage_de_peek();
    diffusion_de_la_carte();
    sndbuf_attend();
    bouchon();
    sol_ip();
    controles();
    options_d_ip();
    interface_de_sortie();
    liees();
    multidiffusion();
    multidiffusion_trafic();
    printf("[linux] reseau : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
