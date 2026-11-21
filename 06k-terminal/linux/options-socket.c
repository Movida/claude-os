/*
 * Les options de SOL_SOCKET (les soldes d'avant 6k, le lot 6) : ce que chaque option
 * garde, refuse et fait, pour UDP, TCP, ping et AF_UNIX, comme sous Linux 6.18. Ce que
 * d'autres programmes vérifient déjà (SO_RCVTIMEO dans reseau et copies, SO_PEEK_OFF
 * dans unix, SO_SNDBUF qui grandit dans tcp...) n'est pas refait ici.
 *   - SO_PEERCRED : sans pair (toute socket d'Internet ; AF_UNIX neuve, liée, ou en
 *     datagrammes même connectée), pas de pid, et -1 pour l'utilisateur et le groupe ;
 *     une écoute AF_UNIX a les siens, une paire et une connexion ceux de l'autre bout ;
 *   - SO_REUSEPORT : refusé à AF_UNIX (EOPNOTSUPP), le retirer reste permis ;
 *   - ping : SO_REUSEADDR posé dès la création ; deux pings le partagent, une
 *     troisième qui l'a retiré trouve l'identifiant pris ;
 *   - SO_LINGER : le délai se relit, même retiré ; négatif, il ne finit pas, et se relit
 *     LONG_MAX / HZ coupé à 32 bits (HZ : 1000 chez nous et sous le Linux de référence,
 *     250 sous WSL) ;
 *   - SO_BUF_LOCK : les verrous que posent SO_SNDBUF et SO_RCVBUF, relus, posés et
 *     retirés ; un SO_SNDBUF de TCP verrouillé ne grandit pas, déverrouillé, si ;
 *   - les options qui se gardent : SO_SNDBUFFORCE et SO_RCVBUFFORCE (EPERM sans
 *     CAP_NET_ADMIN), l'attente active (SO_BUSY_POLL, SO_PREFER_BUSY_POLL,
 *     SO_BUSY_POLL_BUDGET, SO_INCOMING_NAPI_ID), SO_WIFI_STATUS, SO_NOFCS, SO_PASSSEC
 *     (AF_UNIX), SO_COOKIE et SO_NETNS_COOKIE (leurs longueurs), SO_TXTIME et
 *     SCM_TXTIME, SO_DEVMEM_DONTNEED (TCP), SO_CNX_ADVICE (une route sans MTU apprise
 *     reste : pmtu, sous root, voit l'autre cas) ;
 *   - SO_TXREHASH (TCP) : un SYN sans réponse change le hachage du flux à chaque RTO
 *     (TCP_INFO, `tcpi_rehash`), plus avec SO_TXREHASH 0 ;
 *   - SO_PEERNAME : l'adresse du pair, coupée à la place mais jamais plus longue
 *     qu'elle (EINVAL) ; celle que TCP garde même fermée (un RST, un SYN refusé), là
 *     où getpeername dit ENOTCONN ; connectée au port 0 (UDP, ping) : pas de pair ;
 *     un pair AF_UNIX parti reste jusqu'à l'envoi qui le découvre ;
 *   - SO_PEERGROUPS : les groupes du pair AF_UNIX, ceux de getgroups (aucun chez nous,
 *     ceux de l'utilisateur sur l'hôte) ; ENODATA sans droits gardés, ERANGE et la
 *     longueur qu'il faut pour une place trop petite ;
 *   - SO_MEMINFO : neuf compteurs, coupés à la place ; ce que garde la réception (UDP,
 *     TCP), ce qu'un envoi AF_UNIX tient chez qui l'envoie jusqu'à sa lecture, la file
 *     d'envoi de TCP, la mémoire des adhésions et de leurs listes de sources (les tailles
 *     de Linux), les pertes (une file pleine d'UDP et de ping, une écoute pleine) ;
 *   - SO_RESERVE_MEM : sans groupe de contrôle de la mémoire (chez nous, et sous Linux
 *     dans le groupe racine) EOPNOTSUPP ; dans un groupe (un conteneur), des pages
 *     réservées pour UDP et TCP ; EINVAL pour une valeur négative.
 * Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/net_tstamp.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Les options que la glibc 2.39 ne nomme pas encore. */
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif
#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif
#ifndef SO_BUF_LOCK
#define SO_BUF_LOCK 72
#endif
#ifndef SO_TXREHASH
#define SO_TXREHASH 74
#endif
#ifndef SO_DEVMEM_DONTNEED
#define SO_DEVMEM_DONTNEED 80
#endif
#ifndef SO_RESERVE_MEM
#define SO_RESERVE_MEM 73
#endif

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] options-socket : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* L'erreur d'un appel : 0 s'il a réussi, sinon errno. */
static int erreur(int r)
{
    return r < 0 ? errno : 0;
}

static int lire(int s, int option)
{
    int v = -99;
    socklen_t l = sizeof v;
    if (getsockopt(s, SOL_SOCKET, option, &v, &l) < 0)
        return -1000 - errno;
    return v;
}

static int poser(int s, int option, int v)
{
    return erreur(setsockopt(s, SOL_SOCKET, option, &v, sizeof v));
}

static void attendre_ms(int ms)
{
    struct timespec t = {ms / 1000, ms % 1000 * 1000000L};
    nanosleep(&t, NULL);
}

/* Les sortes de sockets : celles d'Internet, puis celles d'AF_UNIX. */
static const struct sorte {
    const char *nom;
    int famille, type, protocole;
} sortes[] = {
    {"udp", AF_INET, SOCK_DGRAM, 0},
    {"tcp", AF_INET, SOCK_STREAM, 0},
    {"ping", AF_INET, SOCK_DGRAM, IPPROTO_ICMP},
    {"unix flux", AF_UNIX, SOCK_STREAM, 0},
    {"unix datagrammes", AF_UNIX, SOCK_DGRAM, 0},
    {"unix paquets", AF_UNIX, SOCK_SEQPACKET, 0},
};
#define SORTES (int)(sizeof sortes / sizeof sortes[0])

static int ouvrir(const struct sorte *s)
{
    return socket(s->famille, s->type, s->protocole);
}

static char texte[160];

static const char *dire(const char *format, const char *nom)
{
    snprintf(texte, sizeof texte, format, nom);
    return texte;
}

/* SO_PEERCRED : 1 si ce sont les droits de ce processus, 0 s'il n'y en a pas
 * (pid 0, uid et gid -1), -1 pour toute autre réponse. */
static int droits(int s)
{
    struct ucred u;
    memset(&u, 0x55, sizeof u);
    socklen_t l = sizeof u;
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &u, &l) < 0 || l != sizeof u)
        return -1;
    if (u.pid == getpid() && u.uid == getuid() && u.gid == getgid())
        return 1;
    if (u.pid == 0 && u.uid == (uid_t)-1 && u.gid == (gid_t)-1)
        return 0;
    return -1;
}

/* Un nom abstrait d'AF_UNIX (sans fichier), propre à ce processus. */
static socklen_t nom_abstrait(struct sockaddr_un *n, const char *quoi)
{
    memset(n, 0, sizeof *n);
    n->sun_family = AF_UNIX;
    int l = snprintf(n->sun_path + 1, sizeof n->sun_path - 1, "options-socket-%d-%s", getpid(), quoi);
    return sizeof(sa_family_t) + 1 + l;
}

static void peercred(void)
{
    for (int i = 0; i < 3; i++) {
        int s = ouvrir(&sortes[i]);
        verifier(droits(s) == 0, dire("SO_PEERCRED %s : sans pair, pid 0, uid et gid -1", sortes[i].nom));
        close(s);
    }
    /* Une connexion TCP : toujours rien (seul AF_UNIX garde les droits du pair). */
    int e = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    bind(e, (void *)&a, sizeof a);
    listen(e, 1);
    getsockname(e, (void *)&a, &al);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&a, sizeof a);
    int f = accept(e, NULL, NULL);
    verifier(droits(e) == 0 && droits(c) == 0 && droits(f) == 0, "SO_PEERCRED tcp : ni l'ecoute, ni le client, ni l'acceptee");
    close(e), close(c), close(f);

    struct sockaddr_un n;
    socklen_t nl = nom_abstrait(&n, "flux");
    int u = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(droits(u) == 0, "SO_PEERCRED unix flux neuve : rien");
    bind(u, (void *)&n, nl);
    verifier(droits(u) == 0, "SO_PEERCRED unix flux liee : rien");
    listen(u, 1);
    verifier(droits(u) == 1, "SO_PEERCRED unix flux en ecoute : les siens");
    int uc = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(uc, (void *)&n, nl);
    int ua = accept(u, NULL, NULL);
    verifier(droits(uc) == 1 && droits(ua) == 1, "SO_PEERCRED unix flux connectee et acceptee : ceux du pair");
    close(u), close(uc), close(ua);

    nl = nom_abstrait(&n, "datagrammes");
    int d1 = socket(AF_UNIX, SOCK_DGRAM, 0), d2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(d1, (void *)&n, nl);
    verifier(connect(d2, (void *)&n, nl) == 0 && droits(d2) == 0 && droits(d1) == 0,
             "SO_PEERCRED unix datagrammes connectee : rien (connect ne les donne pas)");
    close(d1), close(d2);

    int types[3] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET}, ok = 1;
    for (int i = 0; i < 3; i++) {
        int p[2];
        ok &= socketpair(AF_UNIX, types[i], 0, p) == 0 && droits(p[0]) == 1 && droits(p[1]) == 1;
        close(p[0]), close(p[1]);
    }
    verifier(ok, "SO_PEERCRED d'une paire (flux, datagrammes, paquets) : ceux de l'autre bout");

    /* Une place plus petite : la structure coupée, la longueur dite. */
    int p[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    struct ucred cr;
    memset(&cr, 0x55, sizeof cr);
    socklen_t l = 4;
    verifier(getsockopt(p[0], SOL_SOCKET, SO_PEERCRED, &cr, &l) == 0 && l == 4 && cr.pid == getpid() && cr.uid == 0x55555555,
             "SO_PEERCRED dans 4 octets : le pid seul");
    close(p[0]), close(p[1]);
}

static void reuseport(void)
{
    for (int i = 3; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]);
        verifier(poser(s, SO_REUSEPORT, 1) == EOPNOTSUPP && lire(s, SO_REUSEPORT) == 0 && poser(s, SO_REUSEPORT, 0) == 0,
                 dire("SO_REUSEPORT %s : EOPNOTSUPP, le retirer est permis", sortes[i].nom));
        close(s);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    verifier(poser(s, SO_REUSEPORT, 1) == 0 && lire(s, SO_REUSEPORT) == 1, "SO_REUSEPORT udp : pose et relu");
    close(s);
}

/* ping : SO_REUSEADDR dès la naissance (INET_PROTOSW_REUSE) ; l'identifiant
 * partagé seulement si les deux sockets l'ont. */
static void ping_reuseaddr(void)
{
    int a = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), b = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    int c = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), u = socket(AF_INET, SOCK_DGRAM, 0);
    verifier(lire(a, SO_REUSEADDR) == 1 && lire(u, SO_REUSEADDR) == 0, "ping : SO_REUSEADDR des sa creation (pas udp)");
    close(u);
    struct sockaddr_in x = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t xl = sizeof x;
    int r = bind(a, (void *)&x, sizeof x);
    getsockname(a, (void *)&x, &xl);
    verifier(r == 0 && x.sin_port != 0 && bind(b, (void *)&x, sizeof x) == 0, "ping : deux sockets au meme identifiant");
    poser(c, SO_REUSEADDR, 0);
    verifier(erreur(bind(c, (void *)&x, sizeof x)) == EADDRINUSE, "ping : sans SO_REUSEADDR, l'identifiant est pris");
    close(a), close(b), close(c);
}

static void linger(void)
{
    /* LONG_MAX / HZ coupé à 32 bits, pour les HZ de Linux. */
    int hz[4] = {100, 250, 300, 1000}, infinis[4];
    for (int i = 0; i < 4; i++)
        infinis[i] = (int)(unsigned int)(LONG_MAX / hz[i]);
    struct {
        int onoff, delai, attendu;
    } cas[] = {{1, 5, 5}, {1, 0x7fffffff, 0x7fffffff}, {1, 0, 0}, {1, -1, 1}, {1, INT_MIN, 1}};
    const char *noms[] = {"5 s", "INT_MAX", "0", "-1 : infini", "INT_MIN : infini"};
    for (int i = 0; i < 5; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct linger l = {cas[i].onoff, cas[i].delai}, r = {-9, -9};
        socklen_t rl = sizeof r;
        int ok = setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0 && getsockopt(s, SOL_SOCKET, SO_LINGER, &r, &rl) == 0
                 && rl == sizeof r && r.l_onoff == 1;
        if (cas[i].delai < 0) {
            int trouve = 0;
            for (int h = 0; h < 4; h++)
                trouve |= r.l_linger == infinis[h];
            if (!trouve)
                printf("[linux] options-socket : SO_LINGER %d relu %d\n", cas[i].delai, r.l_linger);
            ok &= trouve;
        } else {
            ok &= r.l_linger == cas[i].attendu;
        }
        verifier(ok, dire("SO_LINGER %s : relu", noms[i]));
        close(s);
    }
    /* Retiré : le délai d'avant reste, et se relit ; un retrait ne lit pas son délai. */
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct linger l = {1, 7}, r;
    socklen_t rl = sizeof r;
    setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l);
    l.l_onoff = 0, l.l_linger = 99;
    setsockopt(s, SOL_SOCKET, SO_LINGER, &l, sizeof l);
    verifier(getsockopt(s, SOL_SOCKET, SO_LINGER, &r, &rl) == 0 && r.l_onoff == 0 && r.l_linger == 7,
             "SO_LINGER retire : l'ancien delai reste");
    verifier(erreur(setsockopt(s, SOL_SOCKET, SO_LINGER, &l, 4)) == EINVAL, "SO_LINGER en 4 octets : EINVAL");
    close(s);
}

/* SO_BUF_LOCK : les deux bits de `sk_userlocks`. */
static void buf_lock(void)
{
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]);
        int ok = lire(s, SO_BUF_LOCK) == 0;
        poser(s, SO_SNDBUF, 10000);
        ok &= lire(s, SO_BUF_LOCK) == 1;
        poser(s, SO_RCVBUF, 10000);
        ok &= lire(s, SO_BUF_LOCK) == 3;
        verifier(ok, dire("SO_BUF_LOCK %s : 0, puis pose par SO_SNDBUF (1) et SO_RCVBUF (2)", sortes[i].nom));
        int sndbuf = lire(s, SO_SNDBUF);
        ok = poser(s, SO_BUF_LOCK, 0) == 0 && lire(s, SO_BUF_LOCK) == 0 && lire(s, SO_SNDBUF) == sndbuf;
        ok &= poser(s, SO_BUF_LOCK, 2) == 0 && lire(s, SO_BUF_LOCK) == 2;
        ok &= poser(s, SO_BUF_LOCK, 1) == 0 && lire(s, SO_BUF_LOCK) == 1;
        verifier(ok, dire("SO_BUF_LOCK %s : pose et retire, sans toucher aux tailles", sortes[i].nom));
        ok = poser(s, SO_BUF_LOCK, 4) == EINVAL && poser(s, SO_BUF_LOCK, -1) == EINVAL && poser(s, SO_BUF_LOCK, 7) == EINVAL;
        verifier(ok && lire(s, SO_BUF_LOCK) == 1, dire("SO_BUF_LOCK %s : un autre bit, EINVAL", sortes[i].nom));
        close(s);
    }
}

/* Remplit le tampon d'envoi de c (EAGAIN), puis lit tout de a : TCP fait grandir un
 * SO_SNDBUF qui n'est pas verrouillé quand le programme a manqué de place
 * (`tcp_check_space`). Rend SO_SNDBUF après. */
static int remplir_et_vider(int c, int a)
{
    static char b[1 << 20];
    long total = 0, r;
    while ((r = send(c, b, sizeof b, MSG_DONTWAIT)) > 0)
        total += r;
    while (total > 0 && (r = read(a, b, sizeof b)) > 0)
        total -= r;
    attendre_ms(20);
    return lire(c, SO_SNDBUF);
}

static void buf_lock_tcp(void)
{
    int e = socket(AF_INET, SOCK_STREAM, 0), v = 1000;
    struct sockaddr_in x = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t xl = sizeof x;
    bind(e, (void *)&x, sizeof x);
    listen(e, 1);
    getsockname(e, (void *)&x, &xl);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, IPPROTO_TCP, TCP_MAXSEG, &v, sizeof v);
    connect(c, (void *)&x, sizeof x);
    int a = accept(e, NULL, NULL);
    close(e);
    poser(c, SO_SNDBUF, 16384);
    int fixe = lire(c, SO_SNDBUF);
    verifier(remplir_et_vider(c, a) == fixe, "tcp : SO_SNDBUF verrouille ne grandit pas");
    poser(c, SO_BUF_LOCK, 0);
    int apres = remplir_et_vider(c, a);
    printf("[linux] options-socket : SO_SNDBUF %d, puis %d deverrouille\n", fixe, apres);
    verifier(apres > fixe, "tcp : SO_BUF_LOCK 0, SO_SNDBUF grandit de nouveau");
    close(a), close(c);
}

/* Les options qui se gardent et se relisent, sans effet visible ici. */
static void gardees(void)
{
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]), ok = 1;
        if (geteuid() != 0)
            ok = poser(s, SO_SNDBUFFORCE, 4096) == EPERM && poser(s, SO_RCVBUFFORCE, 4096) == EPERM
                 && lire(s, SO_SNDBUFFORCE) == -1000 - ENOPROTOOPT && lire(s, SO_BUF_LOCK) == 0;
        verifier(ok, dire("SO_SNDBUFFORCE, SO_RCVBUFFORCE %s : EPERM sans CAP_NET_ADMIN, et sans get", sortes[i].nom));
        ok = lire(s, SO_BUSY_POLL) == 0 && poser(s, SO_BUSY_POLL, 50) == 0 && lire(s, SO_BUSY_POLL) == 50
             && poser(s, SO_BUSY_POLL, -1) == EINVAL && lire(s, SO_BUSY_POLL) == 50;
        ok &= poser(s, SO_PREFER_BUSY_POLL, 0) == 0 && lire(s, SO_PREFER_BUSY_POLL) == 0;
        if (geteuid() != 0)
            ok &= poser(s, SO_PREFER_BUSY_POLL, 1) == EPERM && poser(s, SO_BUSY_POLL_BUDGET, 1) == EPERM;
        ok &= poser(s, SO_BUSY_POLL_BUDGET, 0) == 0 && poser(s, SO_BUSY_POLL_BUDGET, -1) == EINVAL
              && lire(s, SO_BUSY_POLL_BUDGET) == -1000 - ENOPROTOOPT;
        ok &= lire(s, SO_INCOMING_NAPI_ID) == 0 && poser(s, SO_INCOMING_NAPI_ID, 1) == ENOPROTOOPT;
        verifier(ok, dire("l'attente active %s : gardee, relue, ses refus", sortes[i].nom));
        ok = poser(s, SO_WIFI_STATUS, 3) == 0 && lire(s, SO_WIFI_STATUS) == 1 && poser(s, SO_NOFCS, 7) == 0 && lire(s, SO_NOFCS) == 1;
        ok &= poser(s, SO_WIFI_STATUS, 0) == 0 && lire(s, SO_WIFI_STATUS) == 0 && poser(s, SO_NOFCS, 0) == 0 && lire(s, SO_NOFCS) == 0;
        verifier(ok, dire("SO_WIFI_STATUS, SO_NOFCS %s : relus 1, puis 0", sortes[i].nom));
        if (sortes[i].famille == AF_UNIX)
            ok = lire(s, SO_PASSSEC) == 0 && poser(s, SO_PASSSEC, 9) == 0 && lire(s, SO_PASSSEC) == 1;
        else
            ok = poser(s, SO_PASSSEC, 1) == EOPNOTSUPP && lire(s, SO_PASSSEC) == -1000 - EOPNOTSUPP;
        verifier(ok, dire("SO_PASSSEC %s : AF_UNIX seule", sortes[i].nom));
        if (sortes[i].famille == AF_UNIX && sortes[i].type != SOCK_DGRAM) {
            /* L'acceptée le prend de l'écoute, comme SO_PASSCRED
             * (`unix_stream_connect` recopie `sk_scm_recv_flags`) ; le
             * client garde le sien. */
            struct sockaddr_un n;
            socklen_t nl = nom_abstrait(&n, "passsec");
            int e = ouvrir(&sortes[i]), c = ouvrir(&sortes[i]);
            ok = poser(e, SO_PASSSEC, 1) == 0 && bind(e, (void *)&n, nl) == 0 && listen(e, 1) == 0
                 && connect(c, (void *)&n, nl) == 0;
            int a = accept(e, NULL, NULL);
            verifier(ok && lire(a, SO_PASSSEC) == 1 && lire(c, SO_PASSSEC) == 0,
                     dire("SO_PASSSEC %s : l'acceptee le prend de l'ecoute", sortes[i].nom));
            close(e), close(c), close(a);
        }
        ok = poser(s, SO_CNX_ADVICE, 1) == 0 && poser(s, SO_CNX_ADVICE, 7) == 0 && lire(s, SO_CNX_ADVICE) == -1000 - ENOPROTOOPT;
        verifier(ok, dire("SO_CNX_ADVICE %s : accepte, sans get", sortes[i].nom));
        ok = (sortes[i].type == SOCK_STREAM && sortes[i].famille == AF_INET)
                 ? lire(s, SO_TXREHASH) == 1 && poser(s, SO_TXREHASH, 0) == 0 && lire(s, SO_TXREHASH) == 0
                       && poser(s, SO_TXREHASH, -1) == 0 && lire(s, SO_TXREHASH) == 1 && poser(s, SO_TXREHASH, 2) == EINVAL
                       && poser(s, SO_TXREHASH, -2) == EINVAL
                 : poser(s, SO_TXREHASH, 1) == EOPNOTSUPP && lire(s, SO_TXREHASH) == -1000 - EOPNOTSUPP;
        verifier(ok, dire("SO_TXREHASH %s : TCP seule ; -1, celui du systeme (1)", sortes[i].nom));
        close(s);
    }
}

static uint64_t cookie(int s, int option, socklen_t place, int *e)
{
    uint64_t v[2] = {0, 0};
    *e = getsockopt(s, SOL_SOCKET, option, v, &place) < 0 ? errno : place == 8 ? 0 : -1;
    return v[0];
}

static void cookies(void)
{
    int u = socket(AF_INET, SOCK_DGRAM, 0), t = socket(AF_INET, SOCK_STREAM, 0), x = socket(AF_UNIX, SOCK_STREAM, 0);
    int e1, e2, e3, e4;
    uint64_t a = cookie(u, SO_COOKIE, 8, &e1), b = cookie(u, SO_COOKIE, 16, &e2), c = cookie(t, SO_COOKIE, 8, &e3);
    uint64_t d = cookie(x, SO_COOKIE, 8, &e4);
    verifier(!e1 && !e2 && !e3 && !e4 && a != 0 && a == b && c != 0 && c != a && d != 0 && d != a && d != c,
             "SO_COOKIE : 8 octets, jamais 0, le meme pour la socket, un autre pour une autre");
    cookie(u, SO_COOKIE, 4, &e1);
    cookie(u, SO_COOKIE, 0, &e2);
    verifier(e1 == EINVAL && e2 == EINVAL, "SO_COOKIE dans moins de 8 octets : EINVAL");
    a = cookie(u, SO_NETNS_COOKIE, 8, &e1), d = cookie(x, SO_NETNS_COOKIE, 8, &e2);
    cookie(u, SO_NETNS_COOKIE, 4, &e3), cookie(u, SO_NETNS_COOKIE, 16, &e4);
    verifier(!e1 && !e2 && a != 0 && a == d && e3 == EINVAL && e4 == EINVAL,
             "SO_NETNS_COOKIE : celui de l'espace reseau, en 8 octets exactement");
    close(u), close(t), close(x);
}

static void txtime(void)
{
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sock_txtime tx = {CLOCK_MONOTONIC, SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS}, r;
    socklen_t rl = sizeof r;
    memset(&r, 0x55, sizeof r);
    verifier(getsockopt(u, SOL_SOCKET, SO_TXTIME, &r, &rl) == 0 && rl == 8 && r.clockid == 0 && r.flags == 0,
             "SO_TXTIME : 0 et 0 au depart, 8 octets");
    rl = sizeof r;
    verifier(setsockopt(u, SOL_SOCKET, SO_TXTIME, &tx, sizeof tx) == 0 && getsockopt(u, SOL_SOCKET, SO_TXTIME, &r, &rl) == 0
                 && r.clockid == CLOCK_MONOTONIC && r.flags == 3,
             "SO_TXTIME : CLOCK_MONOTONIC et ses deux drapeaux, relus");
    tx.flags = 4;
    int e1 = erreur(setsockopt(u, SOL_SOCKET, SO_TXTIME, &tx, sizeof tx));
    tx.flags = 0;
    int e2 = erreur(setsockopt(u, SOL_SOCKET, SO_TXTIME, &tx, 4)), e3 = erreur(setsockopt(u, SOL_SOCKET, SO_TXTIME, &tx, 16));
    verifier(e1 == EINVAL && e2 == EINVAL && e3 == EINVAL, "SO_TXTIME : un autre drapeau, une autre longueur : EINVAL");
    if (geteuid() != 0) {
        tx.clockid = CLOCK_REALTIME;
        e1 = erreur(setsockopt(u, SOL_SOCKET, SO_TXTIME, &tx, sizeof tx));
        tx.clockid = 99;
        e2 = erreur(setsockopt(u, SOL_SOCKET, SO_TXTIME, &tx, sizeof tx));
        verifier(e1 == EPERM && e2 == EPERM, "SO_TXTIME : une autre horloge que CLOCK_MONOTONIC demande CAP_NET_ADMIN");
    }
    /* SCM_TXTIME : seulement avec SO_TXTIME ; un u64. */
    int v = socket(AF_INET, SOCK_DGRAM, 0), rec = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    bind(rec, (void *)&a, sizeof a);
    getsockname(rec, (void *)&a, &al);
    union {
        char b[CMSG_SPACE(8)];
        struct cmsghdr c;
    } cb;
    memset(&cb, 0, sizeof cb);
    struct iovec io = {"x", 1};
    struct msghdr m = {.msg_name = &a, .msg_namelen = sizeof a, .msg_iov = &io, .msg_iovlen = 1, .msg_control = cb.b,
                       .msg_controllen = sizeof cb.b};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET, c->cmsg_type = SCM_TXTIME, c->cmsg_len = CMSG_LEN(8);
    e1 = erreur(sendmsg(v, &m, 0));
    tx.clockid = CLOCK_MONOTONIC, tx.flags = 0;
    setsockopt(v, SOL_SOCKET, SO_TXTIME, &tx, sizeof tx);
    int n = sendmsg(v, &m, 0);
    char b[4];
    int lu = recv(rec, b, sizeof b, MSG_DONTWAIT);
    c->cmsg_len = CMSG_LEN(4);
    e2 = erreur(sendmsg(v, &m, 0));
    verifier(e1 == EINVAL && n == 1 && lu == 1 && e2 == EINVAL, "SCM_TXTIME : EINVAL sans SO_TXTIME ; avec, il part ; un u64 seulement");
    int p[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, p);
    setsockopt(p[0], SOL_SOCKET, SO_TXTIME, &tx, sizeof tx);
    c->cmsg_len = CMSG_LEN(8);
    m.msg_name = NULL, m.msg_namelen = 0;
    verifier(erreur(sendmsg(p[0], &m, 0)) == EINVAL, "SCM_TXTIME sur AF_UNIX : EINVAL meme avec SO_TXTIME");
    close(p[0]), close(p[1]), close(u), close(v), close(rec);
}

static void devmem(void)
{
    uint32_t jetons[300] = {1, 1, 5, 0};
    int t = socket(AF_INET, SOCK_STREAM, 0), u = socket(AF_INET, SOCK_DGRAM, 0), x = socket(AF_UNIX, SOCK_STREAM, 0);
    int ok = setsockopt(t, SOL_SOCKET, SO_DEVMEM_DONTNEED, jetons, 8) == 0 && setsockopt(t, SOL_SOCKET, SO_DEVMEM_DONTNEED, jetons, 1024) == 0;
    verifier(ok, "SO_DEVMEM_DONTNEED tcp : aucun jeton ne designe une page, 0");
    ok = erreur(setsockopt(t, SOL_SOCKET, SO_DEVMEM_DONTNEED, jetons, 12)) == EINVAL
         && erreur(setsockopt(t, SOL_SOCKET, SO_DEVMEM_DONTNEED, jetons, 1032)) == EINVAL
         && erreur(setsockopt(t, SOL_SOCKET, SO_DEVMEM_DONTNEED, (void *)8, 8)) == EFAULT;
    verifier(ok, "SO_DEVMEM_DONTNEED tcp : des jetons de 8 octets, 128 au plus, lus");
    ok = erreur(setsockopt(u, SOL_SOCKET, SO_DEVMEM_DONTNEED, jetons, 8)) == EBADF
         && erreur(setsockopt(x, SOL_SOCKET, SO_DEVMEM_DONTNEED, jetons, 8)) == EBADF && lire(t, SO_DEVMEM_DONTNEED) == -1000 - ENOPROTOOPT;
    verifier(ok, "SO_DEVMEM_DONTNEED : EBADF hors de TCP, et sans get");
    close(t), close(u), close(x);
}

/* SO_CNX_ADVICE sur une connexion dont la route n'a pas de MTU apprise : rien
 * (`ipv4_negative_advice` garde une route sûre). */
static void cnx_advice(void)
{
    int r = socket(AF_INET, SOCK_DGRAM, 0), s = socket(AF_INET, SOCK_DGRAM, 0), un = 1, m = -1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a, ml = sizeof m;
    bind(r, (void *)&a, sizeof a);
    getsockname(r, (void *)&a, &al);
    connect(s, (void *)&a, sizeof a);
    setsockopt(s, SOL_SOCKET, SO_CNX_ADVICE, &un, sizeof un);
    verifier(getsockopt(s, IPPROTO_IP, IP_MTU, &m, &ml) == 0 && m == 65535, "SO_CNX_ADVICE udp : la route de lo reste (IP_MTU)");
    close(r), close(s);
}

/* La valeur u32 de `struct tcp_info` à `decalage`. */
static uint32_t info(int s, int decalage)
{
    unsigned char b[256] = {0};
    socklen_t l = sizeof b;
    uint32_t v = 0;
    getsockopt(s, IPPROTO_TCP, TCP_INFO, b, &l);
    memcpy(&v, b + decalage, 4);
    return v;
}

/* Un SYN sans réponse (l'écoute, sa file pleine, l'ignore) : chaque RTO change le
 * hachage du flux (`tcpi_rehash`, à 236), sauf SO_TXREHASH 0 ; les RTO se comptent
 * (`tcpi_total_rto`, 16 bits à 240). */
static void txrehash(void)
{
    int e = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in x = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t xl = sizeof x;
    bind(e, (void *)&x, sizeof x);
    listen(e, 0);
    getsockname(e, (void *)&x, &xl);
    int plein = socket(AF_INET, SOCK_STREAM, 0);
    connect(plein, (void *)&x, sizeof x);
    int a = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0), b = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    poser(b, SO_TXREHASH, 0);
    connect(a, (void *)&x, sizeof x);
    connect(b, (void *)&x, sizeof x);
    attendre_ms(1300);
    uint32_t ra = info(a, 236), rb = info(b, 236), ta = info(a, 240) & 0xffff, tb = info(b, 240) & 0xffff;
    printf("[linux] options-socket : SYN sans reponse : rehash %u et %u, RTO %u et %u\n", ra, rb, ta, tb);
    verifier(ra >= 1 && ra == ta && rb == 0 && tb >= 1, "SO_TXREHASH 0 : les RTO du SYN ne changent plus le hachage");
    close(a), close(b), close(plein), close(e);
}

/* SO_PEERNAME dans une place de `place` octets : l'erreur (0 si l'appel réussit), la
 * longueur rendue dans *l, les octets dans b (0x55 au-delà). */
static int peername(int s, socklen_t place, unsigned char *b, socklen_t *l)
{
    memset(b, 0x55, 128);
    *l = place;
    return erreur(getsockopt(s, SOL_SOCKET, SO_PEERNAME, b, l));
}

/* SO_PEERNAME, dans toute la place de l'adresse, rend ce que rend getpeername ; une place
 * plus petite la coupe ; une plus grande : EINVAL. */
static int comme_getpeername(int s)
{
    struct sockaddr_storage a;
    socklen_t al = sizeof a, l;
    unsigned char b[128];
    if (getpeername(s, (void *)&a, &al) < 0)
        return 0;
    return peername(s, al, b, &l) == 0 && l == al && memcmp(b, &a, al) == 0 && b[al] == 0x55
        && peername(s, al - 1, b, &l) == 0 && l == al - 1 && memcmp(b, &a, al - 1) == 0 && b[al - 1] == 0x55
        && peername(s, 0, b, &l) == 0 && l == 0 && b[0] == 0x55
        && peername(s, al + 1, b, &l) == EINVAL && peername(s, 128, b, &l) == EINVAL;
}

/* SO_PEERNAME rend l'adresse de `a`, quand getpeername dit ENOTCONN. */
static int garde_sans_getpeername(int s, const struct sockaddr_in *a)
{
    struct sockaddr_in p;
    socklen_t pl = sizeof p, l;
    unsigned char b[128];
    return getpeername(s, (void *)&p, &pl) < 0 && errno == ENOTCONN && peername(s, sizeof p, b, &l) == 0
        && l == sizeof p && memcmp(b, a, sizeof *a) == 0;
}

static void pair(void)
{
    unsigned char b[128];
    socklen_t l;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in a0 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in rien = {.sin_family = AF_UNSPEC};
    for (int i = 0; i < 3; i++) {
        int s = ouvrir(&sortes[i]);
        verifier(peername(s, sizeof a, b, &l) == ENOTCONN, dire("SO_PEERNAME %s neuve : ENOTCONN", sortes[i].nom));
        close(s);
    }
    for (int i = 0; i < 3; i += 2) {
        int s = ouvrir(&sortes[i]);
        connect(s, (void *)&a, sizeof a);
        verifier(comme_getpeername(s), dire("SO_PEERNAME %s connectee : l'adresse, coupee a la place, EINVAL au-dela", sortes[i].nom));
        connect(s, (void *)&rien, sizeof rien);
        verifier(peername(s, sizeof a, b, &l) == ENOTCONN, dire("SO_PEERNAME %s deconnectee : ENOTCONN", sortes[i].nom));
        connect(s, (void *)&a0, sizeof a0);
        struct sockaddr_in p;
        socklen_t pl = sizeof p;
        int e = erreur(getpeername(s, (void *)&p, &pl));
        verifier(e == ENOTCONN && peername(s, sizeof a, b, &l) == ENOTCONN,
                 dire("SO_PEERNAME et getpeername %s connectee au port 0 : ENOTCONN", sortes[i].nom));
        close(s);
    }

    /* TCP : une écoute, une connexion des deux côtés, puis coupée par un RST. */
    int ec = socket(AF_INET, SOCK_STREAM, 0), e;
    socklen_t al = sizeof a0;
    bind(ec, (void *)&a0, sizeof a0);
    listen(ec, 2);
    getsockname(ec, (void *)&a0, &al);
    verifier(peername(ec, sizeof a0, b, &l) == ENOTCONN, "SO_PEERNAME tcp en ecoute : ENOTCONN");
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&a0, sizeof a0);
    int f = accept(ec, NULL, NULL);
    verifier(comme_getpeername(c) && comme_getpeername(f), "SO_PEERNAME tcp connectee et acceptee : comme getpeername");
    struct linger lg = {1, 0};
    setsockopt(f, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(f);
    char x;
    int r = read(c, &x, 1);
    e = errno;
    verifier(r < 0 && e == ECONNRESET && garde_sans_getpeername(c, &a0),
             "SO_PEERNAME tcp coupee par un RST : l'adresse gardee, getpeername ENOTCONN");
    close(c);
    close(ec);
    /* L'écoute fermée, le port refuse : un `connect` non bloquant garde l'adresse, même
     * l'erreur lue ; un bloquant la défait. */
    c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    r = connect(c, (void *)&a0, sizeof a0);
    struct pollfd pf = {c, POLLOUT, 0};
    poll(&pf, 1, 2000);
    int so = 0;
    socklen_t sol = sizeof so;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &so, &sol);
    verifier(so == ECONNREFUSED && garde_sans_getpeername(c, &a0),
             "SO_PEERNAME tcp refusee, connect non bloquant : l'adresse gardee, getpeername ENOTCONN");
    close(c);
    c = socket(AF_INET, SOCK_STREAM, 0);
    r = connect(c, (void *)&a0, sizeof a0);
    e = errno;
    verifier(r < 0 && e == ECONNREFUSED && peername(c, sizeof a0, b, &l) == ENOTCONN,
             "SO_PEERNAME tcp refusee, connect bloquant : ENOTCONN (la socket est defaite)");
    close(c);

    /* AF_UNIX : une paire n'a pas de nom (la famille seule, 2 octets) ; un nom de
     * chemin, un nom abstrait. */
    int p[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    verifier(peername(p[0], 2, b, &l) == 0 && l == 2 && b[0] == AF_UNIX && b[1] == 0 && peername(p[0], 1, b, &l) == 0 && l == 1
                 && peername(p[0], 3, b, &l) == EINVAL,
             "SO_PEERNAME unix paire : la famille seule, EINVAL pour 3 octets");
    close(p[0]), close(p[1]);
    struct sockaddr_un n = {.sun_family = AF_UNIX};
    snprintf(n.sun_path, sizeof n.sun_path, "/tmp/options-socket-%d", getpid());
    unlink(n.sun_path);
    int ue = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(ue, (void *)&n, sizeof n);
    listen(ue, 1);
    verifier(peername(ue, 2, b, &l) == ENOTCONN, "SO_PEERNAME unix en ecoute : ENOTCONN");
    int uc = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(uc, (void *)&n, sizeof n);
    int ua = accept(ue, NULL, NULL);
    verifier(comme_getpeername(uc) && peername(uc, 128, b, &l) == EINVAL && comme_getpeername(ua),
             "SO_PEERNAME unix connectee (un chemin) et acceptee : comme getpeername");
    close(uc), close(ua), close(ue);
    unlink(n.sun_path);
    socklen_t nl = nom_abstrait(&n, "pair");
    int d1 = socket(AF_UNIX, SOCK_DGRAM, 0), d2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    bind(d1, (void *)&n, nl);
    connect(d2, (void *)&n, nl);
    verifier(comme_getpeername(d2), "SO_PEERNAME unix datagrammes connectee (un nom abstrait) : comme getpeername");
    close(d1);
    verifier(peername(d2, nl, b, &l) == 0 && l == nl && memcmp(b, &n, nl) == 0, "SO_PEERNAME unix datagrammes, le pair ferme : son nom reste");
    r = send(d2, "x", 1, 0);
    e = errno;
    verifier(r < 0 && e == ECONNREFUSED && peername(d2, nl, b, &l) == ENOTCONN,
             "SO_PEERNAME unix datagrammes : l'envoi qui trouve le pair parti l'oublie (ENOTCONN)");
    close(d2);
}

/* SO_PEERGROUPS dans une place de `place` octets : l'erreur, la longueur dans *l. */
static int peergroups(int s, socklen_t place, gid_t *g, socklen_t *l)
{
    *l = place;
    return erreur(getsockopt(s, SOL_SOCKET, SO_PEERGROUPS, g, l));
}

/* Les groupes de SO_PEERGROUPS sont ceux de ce processus (getgroups). */
static int mes_groupes(int s)
{
    gid_t moi[64], g[64];
    int n = getgroups(64, moi);
    socklen_t l;
    if (n < 0 || peergroups(s, sizeof g, g, &l) != 0 || l != n * sizeof(gid_t))
        return 0;
    return memcmp(g, moi, l) == 0;
}

static void groupes(void)
{
    gid_t g[64];
    socklen_t l;
    int n = getgroups(0, NULL);
    printf("[linux] options-socket : %d groupes supplementaires\n", n);
    /* Une taille négative : par l'appel lui-même (la glibc fortifiée la refuse avant).
     * Une taille trop petite n'existe qu'à partir de deux groupes : 0 demande leur
     * nombre (root sous sudo n'en a qu'un, le groupe 0). */
    verifier(n >= 0 && syscall(SYS_getgroups, -1, g) < 0 && errno == EINVAL && (n <= 1 || (getgroups(n - 1, g) < 0 && errno == EINVAL))
                 && getgroups(64, g) == n,
             "getgroups : leur nombre, EINVAL pour une taille negative ou trop petite");
    for (int i = 0; i < 3; i++) {
        int s = ouvrir(&sortes[i]);
        verifier(peergroups(s, sizeof g, g, &l) == ENODATA && l == sizeof g, dire("SO_PEERGROUPS %s : ENODATA, la longueur intacte", sortes[i].nom));
        close(s);
    }
    int u = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(peergroups(u, sizeof g, g, &l) == ENODATA, "SO_PEERGROUPS unix flux neuve : ENODATA");
    struct sockaddr_un n_ = {.sun_family = AF_UNIX};
    socklen_t nl = nom_abstrait(&n_, "groupes");
    bind(u, (void *)&n_, nl);
    listen(u, 1);
    verifier(mes_groupes(u), "SO_PEERGROUPS unix flux en ecoute : les siens");
    int uc = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(uc, (void *)&n_, nl);
    int ua = accept(u, NULL, NULL);
    verifier(mes_groupes(uc) && mes_groupes(ua), "SO_PEERGROUPS unix flux connectee et acceptee : ceux du pair");
    close(u), close(uc), close(ua);
    int d1 = socket(AF_UNIX, SOCK_DGRAM, 0), d2 = socket(AF_UNIX, SOCK_DGRAM, 0);
    nl = nom_abstrait(&n_, "groupes-dgram");
    bind(d1, (void *)&n_, nl);
    connect(d2, (void *)&n_, nl);
    verifier(peergroups(d2, sizeof g, g, &l) == ENODATA, "SO_PEERGROUPS unix datagrammes connectee : ENODATA");
    close(d1), close(d2);
    int types[3] = {SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET}, ok = 1;
    for (int i = 0; i < 3; i++) {
        int p[2];
        socketpair(AF_UNIX, types[i], 0, p);
        ok &= mes_groupes(p[0]) && mes_groupes(p[1]);
        close(p[1]);
        ok &= mes_groupes(p[0]);
        close(p[0]);
    }
    verifier(ok, "SO_PEERGROUPS d'une paire (flux, datagrammes, paquets) : ceux de l'autre bout, gardes apres son depart");
    /* La place : trop petite, ERANGE et la longueur qu'il faut (aucun groupe : rien
     * n'est trop petit). */
    int p[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, p);
    int r = peergroups(p[0], 0, g, &l);
    verifier(n == 0 ? r == 0 && l == 0 : r == ERANGE && l == n * sizeof(gid_t), "SO_PEERGROUPS dans 0 octet : ERANGE et la longueur voulue (sans groupe : 0)");
    if (n > 0) {
        r = peergroups(p[0], n * sizeof(gid_t) - 1, g, &l);
        verifier(r == ERANGE && l == n * sizeof(gid_t), "SO_PEERGROUPS dans un octet de moins : ERANGE et la longueur voulue");
    }
    close(p[0]), close(p[1]);
}

/* SO_MEMINFO dans `place` octets : la longueur rendue (-1 : l'appel a échoué) ; m reçoit
 * les compteurs (0x55555555 au-delà). Leurs indices : */
enum { RMEM, RCVBUF, WMEM, SNDBUF, FWD, QUEUED, OPTMEM, BACKLOG, DROPS };
static int meminfo(int s, socklen_t place, unsigned *m)
{
    memset(m, 0x55, 12 * sizeof *m);
    socklen_t l = place;
    return getsockopt(s, SOL_SOCKET, SO_MEMINFO, m, &l) < 0 ? -1 : (int)l;
}

static unsigned compteur(int s, int i)
{
    unsigned m[12];
    meminfo(s, 36, m);
    return m[i];
}

/* Lit sans attendre tout ce qui est en file : le nombre de messages. */
static int vider(int s)
{
    char b[2048];
    int n = 0;
    while (recv(s, b, sizeof b, MSG_DONTWAIT) >= 0)
        n++;
    return n;
}

static void memoire(void)
{
    unsigned m[12];
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]);
        int l = meminfo(s, 36, m);
        verifier(l == 36 && m[RCVBUF] == (unsigned)lire(s, SO_RCVBUF) && m[SNDBUF] == (unsigned)lire(s, SO_SNDBUF) && m[RMEM] == 0 && m[WMEM] == 0
                     && m[QUEUED] == 0 && m[OPTMEM] == 0 && m[BACKLOG] == 0 && m[DROPS] == 0 && m[9] == 0x55555555,
                 dire("SO_MEMINFO %s neuve : SO_RCVBUF et SO_SNDBUF, rien de garde, 36 octets", sortes[i].nom));
        close(s);
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int l4 = meminfo(s, 4, m);
    unsigned m1 = m[1];
    int l0 = meminfo(s, 0, m);
    unsigned z = m[0];
    verifier(l4 == 4 && m1 == 0x55555555 && l0 == 0 && z == 0x55555555 && meminfo(s, 100, m) == 36, "SO_MEMINFO : coupe a la place, 36 octets au plus");
    close(s);

    /* UDP : ce que garde la réception, rendu à la lecture ; une file pleine perd. */
    int r = socket(AF_INET, SOCK_DGRAM, 0), e = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    bind(r, (void *)&a, sizeof a);
    getsockname(r, (void *)&a, &al);
    connect(e, (void *)&a, sizeof a);
    char b[1000] = {0};
    send(e, b, 100, 0);
    attendre_ms(20);
    unsigned avant = compteur(r, RMEM);
    vider(r);
    verifier(avant > 100 && compteur(r, RMEM) == 0, "SO_MEMINFO udp : un datagramme garde (plus que ses octets), rendu a la lecture");
    poser(r, SO_RCVBUF, 1);
    for (int i = 0; i < 20; i++)
        send(e, b, sizeof b, 0);
    attendre_ms(20);
    unsigned pertes = compteur(r, DROPS);
    int lus = vider(r);
    printf("[linux] options-socket : udp, SO_RCVBUF minimal, 20 datagrammes : %d lus, %u perdus\n", lus, pertes);
    verifier(pertes >= 1 && lus + pertes == 20, "SO_MEMINFO udp : la file pleine, chaque datagramme jete est une perte");
    close(r), close(e);

    /* ping : de même, les réponses que la file ne prend pas. */
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    poser(p, SO_RCVBUF, 1);
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    unsigned char echo[64] = {8, 0};
    for (int i = 0; i < 10; i++)
        sendto(p, echo, sizeof echo, 0, (void *)&lo, sizeof lo);
    attendre_ms(50);
    pertes = compteur(p, DROPS);
    lus = vider(p);
    verifier(pertes >= 1 && lus + pertes == 10, "SO_MEMINFO ping : la file pleine, chaque reponse jetee est une perte");
    close(p);

    /* AF_UNIX : l'envoi est à qui l'envoie, jusqu'à sa lecture. */
    int pr[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, pr);
    send(pr[0], b, 100, 0);
    unsigned w = compteur(pr[0], WMEM), rm = compteur(pr[1], RMEM);
    vider(pr[1]);
    verifier(w > 100 && rm == 0 && compteur(pr[0], WMEM) == 0, "SO_MEMINFO unix : l'envoi tenu par l'emetteur jusqu'a la lecture, rien chez le recepteur");
    close(pr[0]), close(pr[1]);

    /* TCP : un récepteur qui ne lit pas ; l'émetteur remplit sa file d'envoi. */
    int ec = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in t = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t tl = sizeof t;
    bind(ec, (void *)&t, sizeof t);
    listen(ec, 1);
    getsockname(ec, (void *)&t, &tl);
    int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    connect(c, (void *)&t, sizeof t);
    attendre_ms(20);
    int f = accept(ec, NULL, NULL);
    static char gros[65536];
    while (send(c, gros, sizeof gros, 0) > 0)
        ;
    attendre_ms(50);
    verifier(compteur(c, QUEUED) > 0 && compteur(f, RMEM) > 0, "SO_MEMINFO tcp : la file d'envoi pleine, la reception gardee");
    close(c), close(f), close(ec);
    /* Une écoute pleine perd les SYN qu'elle ne prend pas. */
    ec = socket(AF_INET, SOCK_STREAM, 0);
    t.sin_port = 0;
    bind(ec, (void *)&t, sizeof t);
    listen(ec, 0);
    getsockname(ec, (void *)&t, &tl);
    int cs[4];
    for (int i = 0; i < 4; i++) {
        cs[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        connect(cs[i], (void *)&t, sizeof t);
    }
    attendre_ms(100);
    verifier(compteur(ec, DROPS) >= 3, "SO_MEMINFO tcp : une ecoute pleine, chaque SYN jete est une perte");
    for (int i = 0; i < 4; i++)
        close(cs[i]);
    close(ec);

    /* La mémoire des options : une adhésion, 48 octets ; une liste de sources, 24 et 4 par
     * place (10 au départ, 10 de plus quand elle est pleine, autant que de sources pour
     * IP_MSFILTER). */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ip_mreqn mr = {.imr_multiaddr.s_addr = htonl(0xe0010203), .imr_ifindex = 1};
    setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof mr);
    unsigned o1 = compteur(s, OPTMEM);
    struct ip_mreq_source ms = {.imr_multiaddr.s_addr = htonl(0xe0010205), .imr_interface.s_addr = htonl(INADDR_LOOPBACK),
                                .imr_sourceaddr.s_addr = htonl(0x01020304)};
    setsockopt(s, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &ms, sizeof ms);
    unsigned o2 = compteur(s, OPTMEM);
    char tf[sizeof(struct ip_msfilter) + 3 * 4];
    struct ip_msfilter *msf = (void *)tf;
    msf->imsf_multiaddr = ms.imr_multiaddr, msf->imsf_interface = ms.imr_interface;
    msf->imsf_fmode = MCAST_INCLUDE, msf->imsf_numsrc = 3;
    for (int i = 0; i < 3; i++)
        msf->imsf_slist[i].s_addr = htonl(0x05060700 + i);
    setsockopt(s, IPPROTO_IP, IP_MSFILTER, msf, sizeof tf);
    unsigned o3 = compteur(s, OPTMEM);
    ms.imr_sourceaddr.s_addr = htonl(0x05060709);
    setsockopt(s, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &ms, sizeof ms);
    unsigned o4 = compteur(s, OPTMEM);
    /* INCLUDE sans source : l'adhésion s'en va (`ip_mc_msfilter`). */
    msf->imsf_numsrc = 0;
    setsockopt(s, IPPROTO_IP, IP_MSFILTER, msf, sizeof *msf);
    unsigned o5 = compteur(s, OPTMEM);
    setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof mr);
    unsigned o6 = compteur(s, OPTMEM);
    printf("[linux] options-socket : SO_MEMINFO, memoire des options : %u %u %u %u %u %u\n", o1, o2, o3, o4, o5, o6);
    verifier(o1 == 48 && o2 == 48 + 112 && o3 == 48 + 84 && o4 == 48 + 124 && o5 == 48 && o6 == 0,
             "SO_MEMINFO udp : la memoire des adhesions et de leurs listes de sources");
    close(s);
}

/* SO_RESERVE_MEM : l'erreur de la pose, et la valeur relue dans *v. */
static int reserver(int s, int octets, int *v)
{
    int e = poser(s, SO_RESERVE_MEM, octets);
    *v = lire(s, SO_RESERVE_MEM);
    return e;
}

static void reserve(void)
{
    int v, x = socket(AF_INET, SOCK_DGRAM, 0);
    /* Un groupe de contrôle de la mémoire pour la socket : UDP accepte 0. */
    int groupe = reserver(x, 0, &v) == 0;
    close(x);
    printf("[linux] options-socket : SO_RESERVE_MEM : %s\n", groupe ? "un groupe de controle de la memoire" : "sans groupe de controle de la memoire");
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]), ok;
        int compte = groupe && i < 2;
        if (compte)
            ok = reserver(s, 1, &v) == 0 && v == 4096 && reserver(s, 4097, &v) == 0 && v == 8192 && reserver(s, 0, &v) == 0 && v == 0;
        else
            ok = reserver(s, 0, &v) == EOPNOTSUPP && v == 0 && reserver(s, 4096, &v) == EOPNOTSUPP && v == 0;
        ok &= reserver(s, -1, &v) == EINVAL;
        verifier(ok, dire(compte ? "SO_RESERVE_MEM %s : des pages, rendues par 0 ; EINVAL pour -1" : "SO_RESERVE_MEM %s : EOPNOTSUPP, rien de reserve ; EINVAL pour -1",
                          sortes[i].nom));
        close(s);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    peercred();
    reuseport();
    ping_reuseaddr();
    linger();
    buf_lock();
    buf_lock_tcp();
    gardees();
    cookies();
    txtime();
    devmem();
    cnx_advice();
    txrehash();
    pair();
    groupes();
    memoire();
    reserve();
    printf("[linux] options-socket : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
