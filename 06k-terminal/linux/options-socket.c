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
 *     de Linux), les pertes (une file pleine d'UDP et de ping, une écoute pleine, et
 *     en CLOSE_WAIT l'ACK de ce qu'on envoie encore : Linux ne le prend pas) ;
 *   - SO_RESERVE_MEM : sans groupe de contrôle de la mémoire (chez nous, et sous Linux
 *     dans le groupe racine) EOPNOTSUPP ; dans un groupe (un conteneur), des pages
 *     réservées pour UDP et TCP ; EINVAL pour une valeur négative ;
 *   - la réception : SO_TIMESTAMP et SO_TIMESTAMPNS, _OLD et _NEW (qui se relisent
 *     chacune seulement posée ; l'heure de l'arrivée, pas de la lecture), SO_RXQ_OVFL
 *     (les pertes d'avant le datagramme), SO_RCVMARK et SO_RCVPRIORITY (la marque et la
 *     priorité de l'envoi, par lo ; celles d'un message de contrôle de l'envoi, IP_TOS
 *     compris ; SO_MARK demande CAP_NET_RAW), dans l'ordre de Linux et seulement pour
 *     qui les dit : UDP tout, ping, la file d'erreurs et TCP l'heure, AF_UNIX l'heure
 *     d'un datagramme ou d'un paquet (celle de l'envoi, ou de la lecture si l'option
 *     est venue après) ; SIOCGSTAMP ; SO_INCOMING_CPU (-1, le processeur de la
 *     réception d'une connexion, et la socket de ce processeur l'emporte à égalité) ;
 *     SO_INQ d'AF_UNIX en flux (SCM_INQ : ce qui reste à lire). Une course de Linux
 *     n'est pas exigée : un datagramme arrivé juste après la première SO_TIMESTAMP de
 *     la machine n'a pas d'heure (la clé `netstamp_needed_key` s'allume en différé, de
 *     5 à 33 ms mesurés selon la charge) : chaque cas qui veut l'heure de l'arrivée
 *     attend que la clé soit allumée (`cle_allumee`), jamais un temps fixe.
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
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
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
#ifndef SO_RCVMARK
#define SO_RCVMARK 75
#endif
#ifndef SO_RCVPRIORITY
#define SO_RCVPRIORITY 82
#endif
#ifndef SO_INQ
#define SO_INQ 84
#define SCM_INQ SO_INQ
#endif
/* Les quatre formes de l'horodatage, par leur numéro (la glibc ne nomme SO_TIMESTAMP
 * que selon la taille de time_t). */
#define TS_OLD 29
#define TSNS_OLD 35
#define TS_NEW 63
#define TSNS_NEW 64
#define SIOCGSTAMP_OLD_ 0x8906
#define SIOCGSTAMPNS_OLD_ 0x8907

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
    /* Après le FIN de l'autre (CLOSE_WAIT), ce qui n'est pas en arrière n'est pas pris
     * (`tcp_rcv_state_process`) : une perte, l'ACK de ce qu'on envoie encore aussi. En
     * ESTABLISHED, un ACK n'en est pas une, ni le FIN qui y arrive. */
    ec = socket(AF_INET, SOCK_STREAM, 0);
    t.sin_port = 0;
    bind(ec, (void *)&t, sizeof t);
    listen(ec, 1);
    getsockname(ec, (void *)&t, &tl);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&t, sizeof t);
    f = accept(ec, NULL, NULL);
    send(f, "a", 1, 0);
    attendre_ms(200);
    unsigned etablie = compteur(f, DROPS);
    shutdown(c, SHUT_WR);
    attendre_ms(200);
    unsigned close_wait = compteur(f, DROPS);
    send(f, "b", 1, 0);
    attendre_ms(200);
    printf("[linux] options-socket : SO_MEMINFO tcp, pertes : etablie %u, FIN %u, ACK en CLOSE_WAIT %u\n", etablie, close_wait, compteur(f, DROPS));
    verifier(etablie == 0 && close_wait == 0 && compteur(f, DROPS) == 1,
             "SO_MEMINFO tcp : en CLOSE_WAIT, l'ACK de ce qu'on envoie est une perte");
    close(c), close(f), close(ec);

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


/* --- La réception. --- */

/* Un message de contrôle reçu : son niveau, sa sorte, la longueur de ses données, et
 * ses deux premiers mots de 8 octets (ou son entier, dans `a`). */
struct vu {
    int niveau, sorte, longueur;
    long long a, b;
};

/* recvmsg de `s` avec `drapeaux`, une place de contrôle `place` : rend ce que rend
 * recvmsg, et remplit `v` (au plus 8), `*n` et `*flags`. */
static ssize_t controles(int s, int drapeaux, size_t place, struct vu *v, int *n, int *flags)
{
    static char ctl[512];
    char b[2048];
    struct iovec io = {b, sizeof b};
    struct msghdr m = {0, 0, &io, 1, ctl, place, 0};
    memset(ctl, 0, sizeof ctl);
    ssize_t r = recvmsg(s, &m, drapeaux);
    *n = 0;
    *flags = m.msg_flags;
    if (r < 0)
        return r;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c && *n < 8; c = CMSG_NXTHDR(&m, c)) {
        struct vu *x = &v[(*n)++];
        x->niveau = c->cmsg_level, x->sorte = c->cmsg_type, x->longueur = c->cmsg_len - CMSG_LEN(0);
        x->a = x->b = 0;
        if (x->longueur == 4) {
            int e;
            memcpy(&e, CMSG_DATA(c), 4);
            x->a = e;
        } else if (x->longueur >= 16) {
            memcpy(&x->a, CMSG_DATA(c), 8);
            memcpy(&x->b, CMSG_DATA(c) + 8, 8);
        }
    }
    return r;
}

static long long maintenant_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* L'horloge monotone : pour une durée. */
static long long monotone_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* Les sauts de l'horloge murale. Les heures du noyau sont murales (CLOCK_REALTIME),
 * et leur âge se mesure contre elle ; mais elle peut sauter : WSL la recule toutes
 * les 30 s pour la remettre à l'heure de Windows (mesuré le 23/11/2026 : 113 puis
 * 138 ms en une minute ; 1,5 s le 7/11), et un démon de l'heure peut en faire autant
 * ailleurs. Un âge mesuré à travers un saut est faux d'autant (200 ms d'attente, un
 * recul de 138 ms : 62 ms, et le cas échoue). Le saut se voit à l'écart entre la
 * murale et la monotone, qui ne change qu'à lui (un ajustement progressif de NTP
 * touche les deux) : `age_dans` relève l'écart à chaque âge, et, un saut vu, ne juge
 * plus aucun âge pendant les 5 s qui le suivent (plus le saut lui-même), en le disant
 * une fois : une heure prise avant lui, lue après, est fausse d'autant, et plusieurs
 * peuvent l'être (deux heures prises avant un recul de 106 ms, lues l'une après
 * l'autre : la seconde, jugée seule, avait 214 ms au lieu de 300, vu sur WSL). Passé
 * ce temps, une heure d'avant le saut aurait plus de 5 s, au-delà de tout âge que juge
 * ce test : elle serait fausse pour de bon. Le saut suivant est 30 s plus loin. L'écart
 * se lit entre deux lectures de la monotone proches (100 µs) : une tâche interrompue
 * entre ses deux lectures y verrait un faux saut. Écartés : corriger l'âge du saut (il
 * faudrait savoir si l'heure a été prise avant ou après lui, et les heures d'émission
 * et d'acquittement viennent pendant nos attentes) ; la monotone pour les âges (les
 * heures du noyau sont murales) ; une marge plus large, qu'un plus grand saut
 * franchirait encore ; ne pas juger le seul premier âge d'après le saut (les autres
 * heures prises avant lui restaient jugées). */
static long long ecart_vu;
/* Le dernier saut vu : quand (à la monotone ; -1 : aucun), et de combien (en ns). */
static long long saut_vu_a = -1, saut_vu;

static long long ecart_ns(void)
{
    long long m1, r, m2;
    for (int i = 0; i < 100; i++) {
        m1 = monotone_ns(), r = maintenant_ns(), m2 = monotone_ns();
        if (m2 - m1 < 100000)
            break;
    }
    return r - (m1 + m2) / 2;
}

__attribute__((constructor)) static void ecart_initial(void)
{
    ecart_vu = ecart_ns();
}

/* L'âge `age` (en ns) entre `min` et `max` millisecondes ; vrai, sans le juger, si
 * l'horloge murale a sauté (de 2 ms ou plus : le dit) depuis moins de 5 s, plus le
 * saut (voir plus haut). */
static int age_dans(long long age, int min, int max)
{
    long long e = ecart_ns(), saut = e - ecart_vu, ici = monotone_ns();
    ecart_vu = e;
    if (saut <= -2000000 || saut >= 2000000) {
        printf("[linux] options-socket : l'horloge murale a saute de %+lld ms : les ages des 5 s qui suivent ne sont pas juges\n",
               saut / 1000000);
        saut_vu_a = ici, saut_vu = saut;
    }
    if (saut_vu_a >= 0 && ici - saut_vu_a < 5000000000LL + (saut_vu < 0 ? -saut_vu : saut_vu))
        return 1;
    return age >= min * 1000000LL && age <= max * 1000000LL;
}

/* L'heure d'un horodatage de la sorte `sorte`, son âge entre `min` et `max`
 * millisecondes, et sa fraction dans ses bornes. */
static int heure_ok(const struct vu *v, int sorte, int min, int max)
{
    int ns = sorte == TSNS_OLD || sorte == TSNS_NEW;
    if (v->niveau != SOL_SOCKET || v->sorte != sorte || v->longueur != 16 || v->b < 0 || v->b >= (ns ? 1000000000 : 1000000))
        return 0;
    return age_dans(maintenant_ns() - (v->a * 1000000000LL + v->b * (ns ? 1 : 1000)), min, max);
}

static int entier_vu(const struct vu *v, int niveau, int sorte, long long valeur)
{
    return v->niveau == niveau && v->sorte == sorte && v->longueur == 4 && v->a == valeur;
}

/* SIOCGSTAMP : 0 et l'âge de l'heure rendue (en ms), ou l'errno. */
static int siocgstamp(int s, long long *age)
{
    struct timeval t;
    if (ioctl(s, SIOCGSTAMP_OLD_, &t) < 0)
        return errno;
    *age = (maintenant_ns() - (t.tv_sec * 1000000000LL + t.tv_usec * 1000LL)) / 1000000;
    return 0;
}

static int udp_lie(struct sockaddr_in *a)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    *a = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t l = sizeof *a;
    bind(s, (void *)a, sizeof *a);
    getsockname(s, (void *)a, &l);
    return s;
}

/* Attendre que la clé des horodatages de la machine (`netstamp_needed_key`) soit
 * allumée : 2 s au moins avant d'abandonner (les vérifications qui suivent le
 * diront), puis 200 ms pour le confirmer. Linux ne prend l'heure d'arrivée d'un
 * paquet que si une socket de la machine la demande, et la première demande allume
 * la clé EN DIFFÉRÉ : `net_enable_timestamp` confie `static_branch_enable` à un
 * travail (`netstamp_work`), qui réécrit le code et synchronise les processeurs.
 * Mesuré (sonde des soldes, c12-cle) : 4 à 5 ms au repos, jusqu'à 33 ms quand tous
 * les cœurs de l'hôte sont occupés. Un paquet arrivé avant n'a pas d'heure, et
 * SO_TIMESTAMP lui donne celle de sa lecture. Un temps fixe ne tient donc pas sous
 * la charge (50 ms : un échec sur quatre, les cœurs occupés) : on attend
 * l'événement lui-même.
 *
 * Le témoin : une socket à part, avec SO_TIMESTAMPNS, s'envoie un datagramme, le
 * laisse 20 ms en file, et le lit. Une heure prise à l'arrivée précède le début de
 * la lecture d'au moins 20 ms ; une heure prise par la lecture le suit : l'écart
 * (10 ms de marge, à la nanoseconde de SO_TIMESTAMPNS) ne dépend ni de la charge, ni
 * de la finesse de l'horloge. Le témoin compte lui aussi dans la clé, mais on ne
 * l'appelle que quand une socket du cas la tient déjà : sa fermeture ne fait alors
 * que décompter (`net_disable_timestamp`, au-dessus de 1), sans rien éteindre.
 *
 * Allumée, elle doit le rester 200 ms (dix rondes d'affilée). La clé qu'un cas
 * précédent a rendue en fermant sa dernière socket s'éteint, elle aussi, en
 * différé : un témoin qui la voit encore allumée à ce moment-là la verrait
 * s'éteindre juste après (vu sur WSL, juste après `reception_options`), avant que
 * le travail suivant ne compte la part du cas et ne la rallume pour de bon. 200 ms :
 * plus de quatre fois l'extinction la plus lente mesurée (44 ms, les cœurs
 * occupés). Une fois confirmée, elle reste allumée tant que le cas la tient : on ne
 * l'attend qu'après la demande qui l'allume (la première du cas), pas après les
 * suivantes. Chez nous, l'heure de l'arrivée ne se fait pas attendre : les dix
 * premières rondes suffisent. Écarté : un temps fixe plus long, qui recule la limite
 * sans l'ôter, et ralentit chaque cas. */
static void cle_allumee(void)
{
    struct sockaddr_in a;
    struct vu v[8];
    int w = udp_lie(&a), suite = 0, n, f;
    poser(w, TSNS_OLD, 1);
    for (int i = 0; i < 110 && suite < 10; i++) {
        sendto(w, "t", 1, 0, (void *)&a, sizeof a);
        struct pollfd p = {w, POLLIN, 0};
        poll(&p, 1, 1000);
        attendre_ms(20);
        long long lecture = maintenant_ns();
        int allumee = controles(w, MSG_DONTWAIT, 512, v, &n, &f) == 1 && n == 1 && v[0].sorte == TSNS_OLD
                      && v[0].a * 1000000000LL + v[0].b < lecture - 10000000LL;
        suite = allumee ? suite + 1 : 0;
    }
    close(w);
}

/* Un datagramme d'un octet vers `a`, avec un message de contrôle (niveau, sorte, entier)
 * si `niveau` n'est pas -1 : l'errno de sendmsg, 0 s'il est parti. */
static int envoyer_avec(int s, const struct sockaddr_in *a, int niveau, int sorte, int v)
{
    char ctl[CMSG_SPACE(sizeof(int))];
    memset(ctl, 0, sizeof ctl);
    struct iovec io = {"x", 1};
    struct msghdr m = {(void *)a, sizeof *a, &io, 1, niveau < 0 ? NULL : ctl, niveau < 0 ? 0 : sizeof ctl, 0};
    if (niveau >= 0) {
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = niveau, c->cmsg_type = sorte, c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &v, sizeof v);
    }
    return erreur(sendmsg(s, &m, 0));
}

static int ts4(int s, int a, int b, int c, int d)
{
    return lire(s, TS_OLD) == a && lire(s, TSNS_OLD) == b && lire(s, TS_NEW) == c && lire(s, TSNS_NEW) == d;
}

/* Les options de la réception, sur chaque sorte. */
static void reception_options(void)
{
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]), ok, v = 1;
        ok = ts4(s, 0, 0, 0, 0) && poser(s, TSNS_OLD, 1) == 0 && ts4(s, 0, 1, 0, 0) && poser(s, TS_NEW, 1) == 0
             && ts4(s, 0, 0, 1, 0) && poser(s, TS_OLD, 0) == 0 && ts4(s, 0, 0, 0, 0) && poser(s, TSNS_NEW, 5) == 0
             && ts4(s, 0, 0, 1, 1) && poser(s, TS_OLD, 1) == 0 && ts4(s, 1, 0, 0, 0) && poser(s, TSNS_NEW, 0) == 0
             && ts4(s, 0, 0, 0, 0);
        verifier(ok, dire("SO_TIMESTAMP(NS) _OLD et _NEW %s : chacune relue seulement posee", sortes[i].nom));
        ok = lire(s, SO_RXQ_OVFL) == 0 && lire(s, SO_RCVMARK) == 0 && lire(s, SO_RCVPRIORITY) == 0
             && poser(s, SO_RXQ_OVFL, 3) == 0 && poser(s, SO_RCVMARK, 3) == 0 && poser(s, SO_RCVPRIORITY, 3) == 0
             && lire(s, SO_RXQ_OVFL) == 1 && lire(s, SO_RCVMARK) == 1 && lire(s, SO_RCVPRIORITY) == 1;
        verifier(ok, dire("SO_RXQ_OVFL, SO_RCVMARK, SO_RCVPRIORITY %s : relues 1", sortes[i].nom));
        ok = lire(s, SO_MARK) == 0 && (geteuid() == 0 ? poser(s, SO_MARK, 5) == 0 && lire(s, SO_MARK) == 5 && poser(s, SO_MARK, 0) == 0
                                                      : poser(s, SO_MARK, 0) == EPERM && lire(s, SO_MARK) == 0);
        verifier(ok, dire("SO_MARK %s : CAP_NET_RAW, meme pour 0", sortes[i].nom));
        ok = lire(s, SO_INCOMING_CPU) == -1 && poser(s, SO_INCOMING_CPU, -5) == 0 && lire(s, SO_INCOMING_CPU) == -5
             && poser(s, SO_INCOMING_CPU, 100000) == 0 && lire(s, SO_INCOMING_CPU) == 100000
             && erreur(setsockopt(s, SOL_SOCKET, SO_INCOMING_CPU, &v, 2)) == EINVAL;
        verifier(ok, dire("SO_INCOMING_CPU %s : -1, puis toute valeur", sortes[i].nom));
        if (sortes[i].famille == AF_UNIX && sortes[i].type == SOCK_STREAM)
            ok = poser(s, SO_INQ, 1) == 0 && poser(s, SO_INQ, 2) == EINVAL && poser(s, SO_INQ, 0) == 0
                 && erreur(setsockopt(s, SOL_SOCKET, SO_INQ, &v, 8)) == EINVAL;
        else
            ok = poser(s, SO_INQ, 1) == ENOPROTOOPT && erreur(setsockopt(s, SOL_SOCKET, SO_INQ, &v, 2)) == EINVAL;
        ok &= lire(s, SO_INQ) == -1000 - ENOPROTOOPT;
        verifier(ok, dire("SO_INQ %s : AF_UNIX en flux seule, jamais relue", sortes[i].nom));
        long long age;
        verifier(siocgstamp(s, &age) == (sortes[i].famille == AF_UNIX ? ENOTTY : ENOENT),
                 dire("SIOCGSTAMP %s : rien de lu (AF_UNIX : ENOTTY)", sortes[i].nom));
        close(s);
    }
}

/* UDP par lo : l'heure, la marque, la priorité, dans l'ordre de Linux. */
static void reception_udp(void)
{
    struct sockaddr_in a;
    int r = udp_lie(&a), s = socket(AF_INET, SOCK_DGRAM, 0), un = 1, p = 5, n, f;
    struct vu v[8];
    long long age;
    sendto(s, "a", 1, 0, (void *)&a, sizeof a);
    controles(r, 0, 0, v, &n, &f);
    verifier(siocgstamp(r, &age) == 0 && age_dans(age * 1000000LL, 0, 149), "SIOCGSTAMP udp : apres une lecture sans heure, la sienne");
    setsockopt(s, SOL_SOCKET, SO_PRIORITY, &p, sizeof p);
    poser(r, SO_RXQ_OVFL, 1), poser(r, SO_RCVMARK, 1), poser(r, SO_RCVPRIORITY, 1);
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    int formes[] = {TS_OLD, TSNS_OLD, TS_NEW, TSNS_NEW};
    for (int i = 0; i < 4; i++) {
        poser(r, formes[i], 1);
        if (i == 0)
            cle_allumee(); /* la première forme l'allume ; r la garde ensuite */
        sendto(s, "b", 1, 0, (void *)&a, sizeof a);
        attendre_ms(200);
        struct vu w[8];
        int m;
        controles(r, MSG_PEEK, 512, w, &m, &f);
        controles(r, 0, 512, v, &n, &f);
        int ok = n == 4 && m == 4 && heure_ok(&v[0], formes[i], 150, 5000) && w[0].a == v[0].a && w[0].b == v[0].b
                 && entier_vu(&v[1], SOL_SOCKET, SO_MARK, 0) && entier_vu(&v[2], SOL_SOCKET, SO_PRIORITY, 5)
                 && v[3].niveau == IPPROTO_IP && v[3].sorte == IP_PKTINFO;
        char q[96];
        snprintf(q, sizeof q, "udp : l'heure %d (de l'arrivee, la meme par MSG_PEEK), SO_MARK, SO_PRIORITY, IP_PKTINFO", formes[i]);
        verifier(ok, q);
    }
    verifier(siocgstamp(r, &age) == 0 && age_dans(age * 1000000LL, 0, 4999), "SIOCGSTAMP udp : l'heure gardee de la premiere lecture");
    poser(r, TSNS_NEW, 0);
    sendto(s, "c", 1, 0, (void *)&a, sizeof a);
    controles(r, 0, 512, v, &n, &f);
    verifier(n == 3 && entier_vu(&v[0], SOL_SOCKET, SO_MARK, 0), "udp : l'heure retiree, plus de SO_TIMESTAMP");
    poser(r, TS_OLD, 1);
    verifier(envoyer_avec(s, &a, SOL_SOCKET, SO_PRIORITY, 3) == 0 && controles(r, 0, 512, v, &n, &f) == 1 && n == 4
             && entier_vu(&v[2], SOL_SOCKET, SO_PRIORITY, 3), "udp : SO_PRIORITY d'un envoi, a la place de celle de la socket");
    verifier(envoyer_avec(s, &a, IPPROTO_IP, IP_TOS, 0x10) == 0 && controles(r, 0, 512, v, &n, &f) == 1 && n == 4
             && entier_vu(&v[2], SOL_SOCKET, SO_PRIORITY, 6), "udp : IP_TOS 0x10 d'un envoi, la priorite 6");
    if (geteuid() == 0) {
        int marque = 7;
        setsockopt(s, SOL_SOCKET, SO_MARK, &marque, sizeof marque);
        verifier(envoyer_avec(s, &a, -1, 0, 0) == 0 && controles(r, 0, 512, v, &n, &f) == 1 && entier_vu(&v[1], SOL_SOCKET, SO_MARK, 7)
                 && envoyer_avec(s, &a, SOL_SOCKET, SO_MARK, 9) == 0 && controles(r, 0, 512, v, &n, &f) == 1
                 && entier_vu(&v[1], SOL_SOCKET, SO_MARK, 9), "udp : SO_MARK de la socket, puis d'un envoi, par lo");
    } else {
        verifier(envoyer_avec(s, &a, SOL_SOCKET, SO_MARK, 9) == EPERM && envoyer_avec(s, &a, SOL_SOCKET, SO_PRIORITY, 7) == EPERM,
                 "udp : SO_MARK d'un envoi, et SO_PRIORITY 7, sans CAP_NET_RAW : EPERM");
    }
    sendto(s, "d", 1, 0, (void *)&a, sizeof a);
    verifier(controles(r, 0, CMSG_SPACE(16) - 1, v, &n, &f) == 1 && n == 1 && v[0].sorte == TS_OLD && v[0].longueur == 15
             && (f & MSG_CTRUNC), "udp : une place de 31 octets, l'heure coupee, MSG_CTRUNC");
    verifier(lire(r, SO_INCOMING_CPU) == -1, "SO_INCOMING_CPU udp : pas connectee, pas notee");
    struct sockaddr_in b;
    socklen_t bl = sizeof b;
    getsockname(s, (void *)&b, &bl);
    connect(r, (void *)&b, sizeof b);
    sendto(s, "e", 1, 0, (void *)&a, sizeof a);
    controles(r, 0, 512, v, &n, &f);
    int cpu = lire(r, SO_INCOMING_CPU);
    verifier(cpu >= 0 && cpu < sysconf(_SC_NPROCESSORS_CONF), "SO_INCOMING_CPU udp : connectee, le processeur de la reception");
    close(r), close(s);
}

/* SO_RXQ_OVFL : les pertes d'avant chaque datagramme, dites quand il y en a. */
static void reception_pertes(void)
{
    struct sockaddr_in a;
    int r = udp_lie(&a), s = socket(AF_INET, SOCK_DGRAM, 0), petit = 1, lus = 0, sans = 1, n, f;
    struct vu v[8];
    char gros[1000];
    memset(gros, 'x', sizeof gros);
    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &petit, sizeof petit);
    poser(r, SO_RXQ_OVFL, 1);
    for (int i = 0; i < 6; i++)
        sendto(s, gros, sizeof gros, 0, (void *)&a, sizeof a);
    while (controles(r, MSG_DONTWAIT, 512, v, &n, &f) >= 0)
        lus++, sans &= n == 0;
    sendto(s, gros, sizeof gros, 0, (void *)&a, sizeof a);
    controles(r, 0, 512, v, &n, &f);
    verifier(lus >= 1 && lus < 6 && sans && n == 1 && entier_vu(&v[0], SOL_SOCKET, SO_RXQ_OVFL, 6 - lus),
             "SO_RXQ_OVFL udp : rien avant la premiere perte, puis les pertes d'avant le datagramme");
    poser(r, SO_RXQ_OVFL, 0);
    sendto(s, gros, sizeof gros, 0, (void *)&a, sizeof a);
    verifier(controles(r, 0, 512, v, &n, &f) == 1000 && n == 0, "SO_RXQ_OVFL udp : retiree, plus rien");
    close(r), close(s);
}

/* Ping, la file d'erreurs : l'heure seule, avant les messages d'IP. */
static void reception_ping_erreurs(void)
{
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), un = 1, n, f;
    struct vu v[8];
    long long age;
    poser(p, TS_OLD, 1), poser(p, SO_RXQ_OVFL, 1), poser(p, SO_RCVMARK, 1), poser(p, SO_RCVPRIORITY, 1);
    setsockopt(p, IPPROTO_IP, IP_RECVTTL, &un, sizeof un);
    cle_allumee();
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    unsigned char echo[8] = {8, 0, 0, 0, 0, 0, 0, 1};
    sendto(p, echo, sizeof echo, 0, (void *)&a, sizeof a);
    attendre_ms(200);
    verifier(controles(p, 0, 512, v, &n, &f) == 8 && n == 2 && heure_ok(&v[0], TS_OLD, 150, 5000)
             && v[1].niveau == IPPROTO_IP && v[1].sorte == IP_TTL, "ping : l'heure seule (ni pertes, ni marque, ni priorite), puis IP_TTL");
    verifier(siocgstamp(p, &age) == ENOENT, "SIOCGSTAMP ping : lu avec SO_TIMESTAMP, rien de garde");
    close(p);
    int f2 = udp_lie(&a);
    close(f2);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    poser(s, TSNS_OLD, 1), poser(s, SO_RXQ_OVFL, 1), poser(s, SO_RCVPRIORITY, 1);
    cle_allumee();
    connect(s, (void *)&a, sizeof a);
    send(s, "h", 1, 0);
    attendre_ms(200);
    verifier(controles(s, MSG_ERRQUEUE, 512, v, &n, &f) == 1 && n == 2 && heure_ok(&v[0], TSNS_OLD, 150, 5000)
             && v[1].niveau == IPPROTO_IP && v[1].sorte == IP_RECVERR, "file d'erreurs : l'heure du message ICMP, puis IP_RECVERR");
    close(s);
}

/* AF_UNIX : l'heure d'un datagramme ou d'un paquet ; SO_INQ d'un flux. */
static void reception_unix(void)
{
    int d[2], un = 1, n, f;
    struct vu v[8];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, d);
    poser(d[1], TS_OLD, 1), poser(d[1], SO_PASSCRED, 1), poser(d[1], SO_RXQ_OVFL, 1), poser(d[1], SO_RCVPRIORITY, 1);
    send(d[0], "i", 1, 0);
    attendre_ms(200);
    verifier(controles(d[1], 0, 512, v, &n, &f) == 1 && n == 2 && heure_ok(&v[0], TS_OLD, 150, 5000) && v[1].sorte == SCM_CREDENTIALS,
             "unix datagrammes : l'heure de l'envoi, puis les droits");
    poser(d[1], TS_OLD, 0);
    send(d[0], "j", 1, 0);
    attendre_ms(200);
    poser(d[1], TSNS_OLD, 1);
    verifier(controles(d[1], 0, 512, v, &n, &f) == 1 && n == 2 && heure_ok(&v[0], TSNS_OLD, 0, 149),
             "unix datagrammes : envoye avant l'option, l'heure de la lecture");
    close(d[0]), close(d[1]);
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, d);
    poser(d[1], TS_NEW, 1);
    send(d[0], "k", 1, 0);
    attendre_ms(200);
    verifier(controles(d[1], 0, 512, v, &n, &f) == 1 && n == 1 && heure_ok(&v[0], TS_NEW, 150, 5000), "unix paquets : SO_TIMESTAMP_NEW");
    close(d[0]), close(d[1]);
    socketpair(AF_UNIX, SOCK_STREAM, 0, d);
    poser(d[1], TS_OLD, 1), poser(d[1], SO_INQ, 1);
    send(d[0], "abcdef", 6, 0);
    send(d[0], "gh", 2, 0);
    int ok = controles(d[1], MSG_PEEK, 512, v, &n, &f) == 8 && n == 1 && entier_vu(&v[0], SOL_SOCKET, SCM_INQ, 8);
    struct iovec io;
    char b[8];
    struct msghdr m = {0, 0, &io, 1, 0, 0, 0};
    io = (struct iovec){b, 6};
    ok &= recvmsg(d[1], &m, 0) == 6;
    ok &= controles(d[1], 0, 512, v, &n, &f) == 2 && n == 1 && entier_vu(&v[0], SOL_SOCKET, SCM_INQ, 0);
    verifier(ok, "unix flux : SCM_INQ, ce qui reste a lire (MSG_PEEK compris) ; jamais d'heure");
    /* Un message lu en partie : Linux le compte jusqu'à sa fin (l'écart d'unix.rs). */
    send(d[0], "lm", 2, 0);
    io = (struct iovec){b, 1};
    char ctl[64];
    m = (struct msghdr){0, 0, &io, 1, ctl, sizeof ctl, 0};
    ok = recvmsg(d[1], &m, 0) == 1 && CMSG_FIRSTHDR(&m) && CMSG_FIRSTHDR(&m)->cmsg_type == SCM_INQ;
    int reste = ok ? *(int *)CMSG_DATA(CMSG_FIRSTHDR(&m)) : -1;
    verifier(ok && (reste == 1 || reste == 2), "unix flux : SCM_INQ apres une lecture partielle (Linux : 2, nous : 1)");
    controles(d[1], 0, 512, v, &n, &f);
    ok = controles(d[1], MSG_DONTWAIT, 512, v, &n, &f) < 0 && errno == EAGAIN;
    poser(d[1], SO_PASSCRED, 1);
    shutdown(d[0], SHUT_WR);
    ok &= controles(d[1], 0, 512, v, &n, &f) == 0 && n == 2 && v[0].sorte == SCM_CREDENTIALS && entier_vu(&v[1], SOL_SOCKET, SCM_INQ, 0);
    verifier(ok, "unix flux : rien sans lecture (EAGAIN) ; a la fin, les droits puis SCM_INQ 0");
    close(d[0]), close(d[1]);
    (void)un;
}

/* TCP : l'heure seule ; le processeur d'une connexion et de ses filles. */
static void reception_tcp(void)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    int l = socket(AF_INET, SOCK_STREAM, 0), n, f, cpus = sysconf(_SC_NPROCESSORS_CONF), z = 0;
    struct vu v[8];
    long long age;
    bind(l, (void *)&a, sizeof a);
    getsockname(l, (void *)&a, &al);
    listen(l, 4);
    poser(l, SO_RCVPRIORITY, 1);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&a, sizeof a);
    int t = accept(l, 0, 0);
    int ce = lire(c, SO_INCOMING_CPU), ct = lire(t, SO_INCOMING_CPU);
    verifier(lire(l, SO_INCOMING_CPU) == -1 && ce >= 0 && ce < cpus && ct >= 0 && ct < cpus,
             "SO_INCOMING_CPU tcp : l'ecoute -1, le client et la fille, un processeur");
    verifier(lire(t, SO_RCVPRIORITY) == 1, "tcp : la fille prend les drapeaux de son ecoute (SO_RCVPRIORITY)");
    poser(t, TS_OLD, 1), poser(t, SO_RXQ_OVFL, 1), poser(t, SO_RCVMARK, 1);
    cle_allumee();
    send(c, "xy", 2, 0);
    attendre_ms(200);
    verifier(controles(t, MSG_PEEK, 512, v, &n, &f) == 2 && n == 1 && heure_ok(&v[0], TS_OLD, 150, 5000)
             && controles(t, 0, 512, v, &n, &f) == 2 && n == 1 && heure_ok(&v[0], TS_OLD, 150, 5000),
             "tcp : l'heure de l'arrivee seule (ni pertes, ni marque, ni priorite)");
    poser(t, TSNS_NEW, 1);
    send(c, "u", 1, MSG_OOB);
    attendre_ms(50);
    verifier(controles(t, MSG_OOB, 512, v, &n, &f) == 1 && n == 0, "tcp : l'octet urgent, sans heure");
    poser(t, TSNS_NEW, 0);
    send(c, "w", 1, 0);
    verifier(controles(t, 0, 512, v, &n, &f) == 1 && n == 0, "tcp : l'heure retiree, plus rien");
    verifier(siocgstamp(t, &age) == ENOENT, "SIOCGSTAMP tcp : jamais d'heure gardee");
    close(c), close(t), close(l);
    (void)z;
}

/* SO_INCOMING_CPU dans la recherche : épinglé sur le processeur 0, une socket qui le
 * dit l'emporte à égalité, sans groupe comme dans un groupe SO_REUSEPORT. Trois sockets
 * au même port, la cible au milieu : ni la plus ancienne (notre choix à égalité), ni la
 * plus récente (celui de Linux sans groupe : `udp_lib_get_port` la met en tête) ; et un
 * émetteur neuf à chaque envoi (un autre port source), pour que le hachage d'un groupe
 * ne tombe pas sur elle par hasard. */
static void reception_processeur(void)
{
    cpu_set_t avant, zero;
    sched_getaffinity(0, sizeof avant, &avant);
    CPU_ZERO(&zero);
    CPU_SET(0, &zero);
    if (sched_setaffinity(0, sizeof zero, &zero) < 0) {
        verifier(0, "SO_INCOMING_CPU : epingle sur le processeur 0");
        return;
    }
    for (int groupe = 0; groupe < 2; groupe++) {
        int option = groupe ? SO_REUSEPORT : SO_REUSEADDR, n, f;
        struct sockaddr_in a;
        int x = socket(AF_INET, SOCK_DGRAM, 0), y = socket(AF_INET, SOCK_DGRAM, 0), z = socket(AF_INET, SOCK_DGRAM, 0);
        struct vu v[8];
        poser(x, option, 1), poser(y, option, 1), poser(z, option, 1);
        a = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        socklen_t al = sizeof a;
        bind(x, (void *)&a, sizeof a);
        getsockname(x, (void *)&a, &al);
        bind(y, (void *)&a, sizeof a);
        bind(z, (void *)&a, sizeof a);
        poser(y, SO_INCOMING_CPU, 0);
        int ok = 1;
        for (int i = 0; i < 4; i++) {
            int s = socket(AF_INET, SOCK_DGRAM, 0);
            sendto(s, "p", 1, 0, (void *)&a, sizeof a);
            ok &= controles(y, MSG_DONTWAIT, 512, v, &n, &f) == 1 && controles(x, MSG_DONTWAIT, 512, v, &n, &f) < 0
                  && controles(z, MSG_DONTWAIT, 512, v, &n, &f) < 0;
            close(s);
        }
        verifier(ok, groupe ? "SO_INCOMING_CPU : dans un groupe SO_REUSEPORT, celle du processeur"
                            : "SO_INCOMING_CPU : a egalite (SO_REUSEADDR), celle du processeur");
        close(x), close(y), close(z);
    }
    sched_setaffinity(0, sizeof avant, &avant);
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
    reception_options();
    reception_udp();
    reception_pertes();
    reception_ping_erreurs();
    reception_unix();
    reception_tcp();
    reception_processeur();
    printf("[linux] options-socket : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
