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
 *     attend que la clé soit allumée (`cle_allumee`), jamais un temps fixe ;
 *   - SO_SELECT_ERR_QUEUE : poll rend POLLPRI avec POLLERR (une erreur ICMP en file,
 *     ou l'erreur en attente seule) pour UDP et AF_UNIX en datagrammes et en
 *     paquets, pas pour TCP ni un flux AF_UNIX ; et qui une erreur venue pendant
 *     l'attente réveille : poll et epoll qui n'attendent que POLLPRI, select qui
 *     attend aussi la lecture, mais pas un select qui n'attend que les exceptions (le
 *     réveil ne dit que POLLERR) : il ne la voit qu'à son échéance ;
 *   - SO_TIMESTAMPING, à la réception : ce qu'elle refuse (un drapeau inconnu, OPT_ID_TCP
 *     sans OPT_ID, OPT_ID d'une socket TCP neuve ou qui écoute, OPT_STATS sans
 *     OPT_TSONLY, BIND_PHC sans horloge), ce qu'elle relit (sa forme _NEW seulement
 *     posée par une _NEW) ; SCM_TIMESTAMPING pour UDP, TCP, ping, la file d'erreurs, et
 *     AF_UNIX seulement avec SO_TIMESTAMP ; SOFTWARE sans RX_SOFTWARE dit l'heure
 *     qu'une autre socket a fait prendre (SO_TIMESTAMP, même retirée, ou RX_SOFTWARE ;
 *     pas une socket AF_UNIX), sauf avec OPT_RX_FILTER (la file d'erreurs, si) ; un
 *     datagramme arrivé quand personne ne voulait d'heure n'en a pas : SO_TIMESTAMP le
 *     dit à l'heure de sa lecture, et SCM_TIMESTAMPING avec elle ; la fille d'une
 *     écoute TCP en hérite, et compte dans la clé (toutes fermées, plus d'heure) ;
 *   - SO_TIMESTAMPING, à l'émission d'UDP et de ping : une entrée par point demandé
 *     (SCHED puis SND), dans la file d'erreurs dès le retour de l'envoi par lo (POLLERR
 *     seul), avec la trame entière (en-tête Ethernet nul de lo, puis IP), sans
 *     adresse, l'heure avec SOFTWARE ; OPT_ID (une clé par envoi qui demande un point,
 *     TX_HARDWARE et TX_COMPLETION compris, pas TX_ACK ; remise à zéro quand OPT_ID se
 *     pose), OPT_TSONLY (sans octets), OPT_CMSG (IP_PKTINFO, IP_TTL, IP_TOS,
 *     IP_ORIGDSTADDR du paquet, et sa source comme SO_EE_OFFENDER) ; le bouchon garde
 *     les drapeaux de son premier envoi ; les messages de contrôle SO_TIMESTAMPING et
 *     SCM_TS_OPT_ID (et leurs refus) ; MSG_TRUNC ; SO_RCVBUF borne la file.
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
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
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
#define TSG_OLD 37
#define TSG_NEW 65
/* Les drapeaux de SO_TIMESTAMPING de Linux 6.18 que les en-têtes de la glibc 2.39
 * n'ont pas tous. */
#define TSF_RX_SOFTWARE (1 << 3)
#define TSF_SOFTWARE (1 << 4)
#define TSF_MATERIEL 0x65 /* TX_HARDWARE, RX_HARDWARE, SYS_HARDWARE, RAW_HARDWARE */
#define TSF_OPT_ID (1 << 7)
#define TSF_OPT_TSONLY (1 << 11)
#define TSF_OPT_STATS (1 << 12)
#define TSF_BIND_PHC (1 << 15)
#define TSF_OPT_ID_TCP (1 << 16)
#define TSF_OPT_RX_FILTER (1 << 17)
#define TSF_TX_COMPLETION (1 << 18)
#define TSF_TX_HARDWARE (1 << 0)
#define TSF_TX_SOFTWARE (1 << 1)
#define TSF_TX_SCHED (1 << 8)
#define TSF_TX_ACK (1 << 9)
#define TSF_OPT_CMSG (1 << 10)
#define SCM_TS_OPT_ID_ 81
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
    int reste; /* SCM_TIMESTAMPING : ses deux autres heures ne sont pas nulles */
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
        x->a = x->b = x->reste = 0;
        for (int i = 16; i < x->longueur && i < 48; i++)
            x->reste |= CMSG_DATA(c)[i];
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

/* SCM_TIMESTAMPING de la forme `sorte` : l'heure logicielle, d'âge entre `min` et
 * `max` millisecondes, les deux autres nulles. */
static int heures_ok(const struct vu *v, int sorte, int min, int max)
{
    if (v->niveau != SOL_SOCKET || v->sorte != sorte || v->longueur != 48 || v->reste || v->b < 0 || v->b >= 1000000000)
        return 0;
    return age_dans(maintenant_ns() - (v->a * 1000000000LL + v->b), min, max);
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

/* Lie la socket TCP `s` à lo, au port que le noyau choisit (0), et le rend dans `a`.
 * Pas un port pris par `udp_lie` puis rendu : libre pour UDP, il peut être celui
 * d'une connexion TCP en TIME_WAIT (les cas précédents en laissent des centaines,
 * pour 60 s), et l'écoute qui s'y lie échoue (EADDRINUSE) ; listen la lie alors
 * ailleurs, et l'accept qui suit attend pour toujours (vu une fois sur douze
 * passages, sur l'hôte comme sous le Linux de référence). Le port 0 de TCP n'en
 * choisit pas un que tient une connexion (`inet_csk_find_open_port`). */
static int lier_tcp(int s, struct sockaddr_in *a)
{
    *a = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t l = sizeof *a;
    int r = bind(s, (void *)a, sizeof *a);
    getsockname(s, (void *)a, &l);
    return r;
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

/* SO_TIMESTAMPING relue sous la forme `forme` : 0 si ce sont `drapeaux` et un
 * `bind_phc` nul, sur 8 octets. */
static int tsg(int s, int forme, int drapeaux)
{
    int t[2] = {-7, -7};
    socklen_t l = sizeof t;
    return getsockopt(s, SOL_SOCKET, forme, t, &l) == 0 && l == 8 && t[0] == drapeaux && t[1] == 0;
}

static void horodatages_option(void)
{
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]), tcp = sortes[i].type == SOCK_STREAM && sortes[i].famille == AF_INET;
        int ok = tsg(s, TSG_OLD, 0) && tsg(s, TSG_NEW, 0) && poser(s, TSG_OLD, 1 << 19) == EINVAL
                 && poser(s, TSG_OLD, -1) == EINVAL && poser(s, TSG_OLD, TSF_OPT_ID_TCP) == EINVAL
                 && poser(s, TSG_OLD, TSF_OPT_STATS) == EINVAL && tsg(s, TSG_OLD, 0)
                 && poser(s, TSG_OLD, TSF_OPT_STATS | TSF_OPT_TSONLY) == 0 && tsg(s, TSG_OLD, TSF_OPT_STATS | TSF_OPT_TSONLY)
                 && poser(s, TSG_OLD, TSF_MATERIEL | TSF_TX_COMPLETION) == 0 && tsg(s, TSG_OLD, TSF_MATERIEL | TSF_TX_COMPLETION)
                 && poser(s, TSG_OLD, TSF_OPT_ID) == (tcp ? EINVAL : 0) && poser(s, TSG_OLD, TSF_BIND_PHC) == EOPNOTSUPP;
        verifier(ok, dire("SO_TIMESTAMPING %s : les drapeaux refuses (OPT_ID : TCP neuve), les autres relus", sortes[i].nom));
        struct {
            int drapeaux, bind_phc;
        } st = {TSF_SOFTWARE, 5};
        short court = 1;
        int quatre = -7;
        socklen_t l = 4;
        ok = erreur(setsockopt(s, SOL_SOCKET, TSG_NEW, &st, sizeof st)) == 0 && tsg(s, TSG_OLD, TSF_SOFTWARE)
             && tsg(s, TSG_NEW, TSF_SOFTWARE) && poser(s, TSG_OLD, TSF_SOFTWARE) == 0 && tsg(s, TSG_NEW, 0)
             && tsg(s, TSG_OLD, TSF_SOFTWARE) && getsockopt(s, SOL_SOCKET, TSG_OLD, &quatre, &l) == 0 && l == 4
             && quatre == TSF_SOFTWARE && erreur(setsockopt(s, SOL_SOCKET, TSG_OLD, &court, 2)) == EINVAL;
        verifier(ok, dire("SO_TIMESTAMPING %s : la so_timestamping, la forme _NEW relue seulement posee par elle", sortes[i].nom));
        close(s);
    }
    struct sockaddr_in a;
    int s = udp_lie(&a), l = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
    bind(l, (void *)&a, sizeof a);
    close(s);
    listen(l, 1);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
    verifier(poser(s, TSG_OLD, TSF_BIND_PHC) == EINVAL && poser(l, TSG_OLD, TSF_OPT_ID) == EINVAL,
             "SO_TIMESTAMPING : BIND_PHC liee a lo (sans horloge PTP) EINVAL ; OPT_ID d'une ecoute EINVAL");
    close(s), close(l);
}

/* Le premier message de contrôle d'une lecture de `s` (sans attendre), et leur nombre. */
static int lire_controles(int s, int drapeaux, struct vu *v)
{
    int n, f;
    memset(v, 0, 3 * sizeof *v);
    return controles(s, drapeaux | MSG_DONTWAIT, 512, v, &n, &f) < 0 ? -1 : n;
}

/* La clé des horodatages (`netstamp_needed_key`) est celle de TOUTE la machine : un
 * autre programme qui demande l'heure d'arrivée des paquets (SO_TIMESTAMP,
 * RX_SOFTWARE : un démon de l'heure, un autre test) l'allume pour tous. Les
 * vérifications qui la veulent éteinte l'attendent donc (`cle_eteinte` : un
 * datagramme toutes les 70 ms, lu par une socket qui n'a que SOFTWARE, jusqu'à un
 * sans heure). La voir éteinte une fois suffit : pendant l'attente, ce programme
 * n'ouvre ni ne ferme rien de ce qui compte, et la part d'une socket qu'il garde ne
 * s'en va pas toute seule ; un seul datagramme sans heure prouve qu'aucune n'en tient,
 * et que celles qu'il a fermées ont rendu la leur. Celle d'un autre programme, elle,
 * finit par partir : il suffit de l'attendre. Sur WSL, un programme hors du
 * conteneur (invisible d'ici ; toutes les 30 s, à l'instant où l'horloge murale
 * saute : la synchronisation de l'heure) la tient d'ordinaire 20 à 100 ms, et
 * parfois 15 s (guetté le 23/11/2026 : 15,09 s). L'attente va jusqu'à 30 s : le
 * double de cette plus longue, et sous les 60 s que `make tests-hote` laisse à tout
 * le programme (22 s d'ordinaire) même quand deux d'entre elles tombent dans un
 * passage. Elle ne coûte qu'à une clé tenue : éteinte, la première ronde rend. Une
 * part jamais rendue échoue toujours, et l'attente échue se dit. Tenue par un autre
 * dès le départ (mesuré au début, avant que ce programme n'y touche :
 * `cle_tenue_ailleurs`), elles sont sautées, en le disant. Linux l'éteint en
 * différé, comme il l'allume (`cle_allumee`) : 31 ms mesurés à côté d'un QEMU,
 * 44 ms les cœurs de l'hôte occupés ; une socket UDP liée ne rend même sa part
 * qu'après un délai de grâce de RCU (`SOCK_RCU_FREE` : 30 à 56 ms de plus, mesuré).
 * Le témoin d'ici n'a que SOFTWARE : il ne compte pas dans la clé, et ne la retient
 * donc pas ; celui de `cle_allumee` la demande (SO_TIMESTAMPNS), là où une socket du
 * cas la tient déjà, et sa part s'en va avec lui, après le délai de RCU, que
 * `cle_eteinte` attend comme les autres. Écartés : rejouer la vérification échouée
 * (la même attente, et le code de chaque cas en double) ; la sauter sur une machine
 * partagée (WSL, où se font les vérifications de David, ne la jugerait plus). */
static int cle_tenue_ailleurs;

static int cle_eteinte(void)
{
    struct sockaddr_in a, b;
    struct vu v[8];
    int r = udp_lie(&a), e = udp_lie(&b), eteinte = 0;
    poser(r, TSG_OLD, TSF_SOFTWARE);
    for (int i = 0; i < 430 && !eteinte; i++) {
        attendre_ms(50);
        sendto(e, "abc", 3, 0, (void *)&a, sizeof a);
        attendre_ms(20);
        eteinte = lire_controles(r, 0, v) == 0;
    }
    close(r), close(e);
    if (!eteinte)
        printf("[linux] options-socket : la cle des horodatages encore allumee apres 30 s\n");
    return eteinte;
}

/* Une vérification qui veut la clé éteinte : vraie si elle l'est (dans les 30 s), ou
 * si un autre programme la tenait dès le départ (sautée). */
static int sans_cle(void)
{
    return cle_tenue_ailleurs || cle_eteinte();
}

static void horodatages_reception(void)
{
    struct sockaddr_in a, b;
    struct vu v[8];
    int r = udp_lie(&a), e = udp_lie(&b), n;
    /* La socket qui allume la clé (celle qui lit, ou une autre) l'attend allumée
     * (`cle_allumee`), une fois, juste après sa demande. */
#define ENVOYER_LIRE(rr) (sendto(e, "abc", 3, 0, (void *)&a, sizeof a), attendre_ms(20), lire_controles(rr, 0, v))
    poser(r, TSG_OLD, TSF_RX_SOFTWARE | TSF_SOFTWARE);
    cle_allumee();
    n = ENVOYER_LIRE(r);
    int ok = n == 1 && heures_ok(&v[0], TSG_OLD, 0, 5000);
    poser(r, TSG_NEW, TSF_RX_SOFTWARE | TSF_SOFTWARE);
    n = ENVOYER_LIRE(r);
    ok &= n == 1 && heures_ok(&v[0], TSG_NEW, 0, 5000);
    poser(r, TSNS_OLD, 1);
    n = ENVOYER_LIRE(r);
    ok &= n == 2 && v[0].sorte == TSNS_OLD && heures_ok(&v[1], TSG_OLD, 0, 5000);
    poser(r, TSNS_OLD, 0);
    poser(r, TSG_OLD, TSF_RX_SOFTWARE);
    ok &= ENVOYER_LIRE(r) == 0;
    verifier(ok, "SCM_TIMESTAMPING UDP : RX_SOFTWARE et SOFTWARE, _OLD ou _NEW (la derniere forme posee, SO_TIMESTAMPNS compris), apres SO_TIMESTAMP ; RX_SOFTWARE seul, rien");
    /* Une socket neuve : celle-là garde SOCK_TIMESTAMP, et la clé, jusqu'à sa fermeture. */
    close(r);
    r = udp_lie(&a);
    poser(r, TSG_OLD, TSF_SOFTWARE);
    ok = sans_cle();
    int autre = socket(AF_INET, SOCK_DGRAM, 0);
    poser(autre, TSG_OLD, TSF_RX_SOFTWARE);
    cle_allumee();
    n = ENVOYER_LIRE(r);
    ok &= n == 1 && heures_ok(&v[0], TSG_OLD, 0, 5000);
    poser(r, TSG_OLD, TSF_SOFTWARE | TSF_OPT_RX_FILTER);
    ok &= ENVOYER_LIRE(r) == 0;
    close(autre);
    poser(r, TSG_OLD, TSF_SOFTWARE);
    ok &= sans_cle();
    autre = socket(AF_INET, SOCK_DGRAM, 0);
    poser(autre, TS_OLD, 1), poser(autre, TS_OLD, 0);
    cle_allumee();
    n = ENVOYER_LIRE(r);
    ok &= n == 1 && heures_ok(&v[0], TSG_OLD, 0, 5000);
    close(autre);
    int u[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, u);
    poser(u[0], TS_OLD, 1);
    ok &= sans_cle();
    close(u[0]), close(u[1]);
    verifier(ok, "SCM_TIMESTAMPING UDP, SOFTWARE seul : l'heure qu'une autre socket fait prendre (RX_SOFTWARE, SO_TIMESTAMP meme retiree ; pas AF_UNIX), sauf OPT_RX_FILTER");
    /* Une lecture qui ne dit pas l'heure (SO_RXQ_OVFL seul, ping) la laisse
     * quand même à SIOCGSTAMP, sans SOCK_TIMESTAMP (`sock_recv_timestamp`) :
     * celle du paquet quand une autre socket a allumé la clé. */
    close(r);
    r = udp_lie(&a);
    poser(r, SO_RXQ_OVFL, 1);
    int ping = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    autre = socket(AF_INET, SOCK_DGRAM, 0);
    poser(autre, TSG_OLD, TSF_RX_SOFTWARE);
    cle_allumee();
    ok = ENVOYER_LIRE(r) == 0;
    unsigned char demande[8] = {8, 0, 0, 0, 0, 0, 0, 2};
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    sendto(ping, demande, sizeof demande, 0, (void *)&lo, sizeof lo);
    attendre_ms(20);
    ok &= lire_controles(ping, 0, v) == 0;
    close(autre);
    attendre_ms(300);
    long long age_udp = -1, age_ping = -1;
    ok &= siocgstamp(r, &age_udp) == 0 && age_dans(age_udp * 1000000LL, 250, 4999);
    ok &= siocgstamp(ping, &age_ping) == 0 && age_dans(age_ping * 1000000LL, 250, 4999);
    char q[160];
    snprintf(q, sizeof q, "SIOCGSTAMP apres une lecture qui ne dit pas l'heure (SO_RXQ_OVFL seul, ping), la cle allumee par une autre : celle du paquet (%lld et %lld ms)", age_udp, age_ping);
    verifier(ok, q);
    close(ping);
    /* Un datagramme arrivé sans clé : SO_TIMESTAMP le dit à l'heure de la lecture,
     * SCM_TIMESTAMPING avec elle ; sans SO_TIMESTAMP, rien. La clé qu'un autre
     * programme allumerait pendant l'envoi : cinq essais (voir `cle_eteinte`). */
    close(r);
    ok = cle_tenue_ailleurs;
    for (int essai = 0; essai < 5 && !ok; essai++) {
        r = udp_lie(&a);
        cle_eteinte();
        sendto(e, "abc", 3, 0, (void *)&a, sizeof a);
        sendto(e, "abc", 3, 0, (void *)&a, sizeof a);
        attendre_ms(300);
        poser(r, TSG_OLD, TSF_RX_SOFTWARE | TSF_SOFTWARE);
        ok = lire_controles(r, 0, v) == 0;
        poser(r, TS_OLD, 1);
        n = lire_controles(r, 0, v);
        ok &= n == 2 && heure_ok(&v[0], TS_OLD, 0, 200) && heures_ok(&v[1], TSG_OLD, 0, 200);
        close(r);
    }
    verifier(ok, "un datagramme arrive sans cle : SO_TIMESTAMP a l'heure de la lecture, SCM_TIMESTAMPING avec elle ; sans SO_TIMESTAMP, rien");
    /* La file d'erreurs : SOFTWARE et OPT_RX_FILTER n'y filtrent rien. */
    int s = socket(AF_INET, SOCK_DGRAM, 0), un = 1;
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    poser(s, TSG_OLD, TSF_SOFTWARE | TSF_OPT_RX_FILTER);
    autre = socket(AF_INET, SOCK_DGRAM, 0);
    poser(autre, TSG_OLD, TSF_RX_SOFTWARE);
    cle_allumee();
    connect(s, (void *)&a, sizeof a);
    send(s, "h", 1, 0);
    attendre_ms(50);
    n = lire_controles(s, MSG_ERRQUEUE, v);
    verifier(n == 2 && heures_ok(&v[0], TSG_OLD, 0, 5000) && v[1].niveau == IPPROTO_IP && v[1].sorte == IP_RECVERR,
             "SCM_TIMESTAMPING de la file d'erreurs : SOFTWARE et OPT_RX_FILTER, puis IP_RECVERR");
    close(s), close(autre), close(e);
    /* TCP, ping, AF_UNIX. */
    s = socket(AF_INET, SOCK_STREAM, 0);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(s, &a);
    listen(s, 1);
    connect(c, (void *)&a, sizeof a);
    int d = accept(s, NULL, NULL);
    poser(d, TSG_OLD, TSF_RX_SOFTWARE | TSF_SOFTWARE);
    cle_allumee();
    send(c, "rx", 2, 0);
    attendre_ms(20);
    n = lire_controles(d, 0, v);
    verifier(n == 1 && heures_ok(&v[0], TSG_OLD, 0, 5000), "SCM_TIMESTAMPING TCP");
    close(c), close(d), close(s);
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    poser(p, TSG_NEW, TSF_RX_SOFTWARE | TSF_SOFTWARE);
    cle_allumee();
    unsigned char echo[8] = {8, 0, 0, 0, 0, 0, 0, 1};
    a.sin_port = 0;
    sendto(p, echo, sizeof echo, 0, (void *)&a, sizeof a);
    attendre_ms(50);
    n = lire_controles(p, 0, v);
    verifier(n == 1 && heures_ok(&v[0], TSG_NEW, 0, 5000), "SCM_TIMESTAMPING ping");
    close(p);
    socketpair(AF_UNIX, SOCK_DGRAM, 0, u);
    poser(u[1], TSG_OLD, TSF_RX_SOFTWARE | TSF_SOFTWARE);
    send(u[0], "a", 1, 0);
    ok = lire_controles(u[1], 0, v) == 0;
    poser(u[1], TS_OLD, 1);
    send(u[0], "b", 1, 0);
    n = lire_controles(u[1], 0, v);
    verifier(ok && n == 2 && heure_ok(&v[0], TS_OLD, 0, 5000) && heures_ok(&v[1], TSG_OLD, 0, 5000),
             "SCM_TIMESTAMPING AF_UNIX : seulement avec SO_TIMESTAMP, apres lui");
    close(u[0]), close(u[1]);
#undef ENVOYER_LIRE
}

/* La fille d'une écoute TCP hérite de SO_TIMESTAMPING (`sk_clone_lock`), et compte à
 * son tour dans la clé des horodatages : toutes fermées, la clé s'éteint, et une
 * socket qui n'a que SOFTWARE ne voit plus d'heure. */
static void horodatages_fille(void)
{
    struct sockaddr_in t;
    struct vu v[8];
    int l = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(l, &t);
    poser(l, TSG_OLD, TSF_RX_SOFTWARE | TSF_SOFTWARE);
    listen(l, 1);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&t, sizeof t);
    int d = accept(l, NULL, NULL);
    int ok = lire(d, TSG_OLD) == (TSF_RX_SOFTWARE | TSF_SOFTWARE);
    cle_allumee();
    send(c, "ab", 2, 0);
    attendre_ms(20);
    ok &= lire_controles(d, 0, v) == 1 && heures_ok(&v[0], TSG_OLD, 0, 5000);
    close(c), close(d), close(l);
    ok &= sans_cle();
    verifier(ok, "SO_TIMESTAMPING d'une ecoute TCP : sa fille l'herite, et compte dans la cle (toutes fermees, plus d'heure)");
}

/* --- L'émission horodatée. --- */

/* Une entrée de la file d'erreurs : ce que rend recvmsg (ou -errno), msg_flags,
 * msg_namelen, ses messages de contrôle dans l'ordre (niveau * 1000 + sorte), et ce
 * qu'ils disent : l'heure (SCM_TIMESTAMPING récent), IP_PKTINFO, un entier IP (TTL),
 * un octet (TOS), le port d'IP_ORIGDSTADDR, la sock_extended_err et SO_EE_OFFENDER. */
struct entree {
    int r, flags, nom, n, sortes[8], heure, ttl, tos, port;
    struct in_pktinfo pkt;
    unsigned ee_errno, ee_origin, ee_info, ee_data, famille, offender;
    unsigned char o[128];
};

static int lire_entree(int s, struct entree *e, size_t place)
{
    char ctl[512];
    struct sockaddr_in a;
    memset(e, 0, sizeof *e);
    struct iovec io = {e->o, place};
    struct msghdr m = {&a, sizeof a, &io, 1, ctl, sizeof ctl, 0};
    e->r = recvmsg(s, &m, MSG_ERRQUEUE | MSG_DONTWAIT);
    if (e->r < 0)
        return e->r = -errno;
    e->flags = m.msg_flags, e->nom = m.msg_namelen;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c && e->n < 8; c = CMSG_NXTHDR(&m, c)) {
        unsigned char *d = CMSG_DATA(c);
        int l = c->cmsg_len - CMSG_LEN(0);
        e->sortes[e->n++] = c->cmsg_level * 1000 + c->cmsg_type;
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == TSG_OLD) {
            struct vu v = {SOL_SOCKET, TSG_OLD, l, 0, 0, 0};
            memcpy(&v.a, d, 8), memcpy(&v.b, d + 8, 8);
            for (int i = 16; i < l && i < 48; i++)
                v.reste |= d[i];
            e->heure = heures_ok(&v, TSG_OLD, 0, 5000);
        } else if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_PKTINFO) {
            memcpy(&e->pkt, d, sizeof e->pkt);
        } else if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_TTL) {
            memcpy(&e->ttl, d, 4);
        } else if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_TOS) {
            e->tos = d[0];
        } else if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_ORIGDSTADDR) {
            e->port = ntohs(((struct sockaddr_in *)d)->sin_port);
        } else if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR) {
            uint32_t w[4];
            memcpy(w, d, 16);
            e->ee_errno = w[0], e->ee_origin = d[4], e->ee_info = w[2], e->ee_data = w[3];
            struct sockaddr_in f;
            memcpy(&f, d + 16, sizeof f);
            e->famille = f.sin_family, e->offender = f.sin_addr.s_addr;
        }
    }
    return e->r;
}

/* Les messages de contrôle de `e` sont-ils, dans l'ordre, les `n` de `sortes` ? */
static int sortes_ok(const struct entree *e, int n, const int *sortes)
{
    if (e->n != n)
        return 0;
    for (int i = 0; i < n; i++)
        if (e->sortes[i] != sortes[i])
            return 0;
    return 1;
}

#define S_TS (SOL_SOCKET * 1000 + TSG_OLD)
#define S_PKT IP_PKTINFO
#define S_ERR IP_RECVERR

/* Une entrée d'horodatage : sa longueur `r`, sans adresse, MSG_ERRQUEUE, ENOMSG
 * d'origine SO_EE_ORIGIN_TIMESTAMPING, son point `info`, sa clé `data`. */
static int horodatage_ok(const struct entree *e, int r, unsigned info, unsigned data)
{
    return e->r == r && e->nom == 0 && e->flags == MSG_ERRQUEUE && e->ee_errno == ENOMSG && e->ee_origin == 4
        && e->ee_info == info && e->ee_data == data;
}

/* La trame de lo d'un datagramme UDP de données `d` (n octets) : 12 octets nuls, le
 * type IPv4, l'en-tête IP, les données à la fin. */
static int trame_ok(const struct entree *e, const char *d, int n)
{
    static const unsigned char nul[12];
    return e->r == 14 + 20 + 8 + n && !memcmp(e->o, nul, 12) && e->o[12] == 8 && e->o[13] == 0 && e->o[14] == 0x45
        && e->o[23] == IPPROTO_UDP && !memcmp(e->o + e->r - n, d, n);
}

/* Un envoi « abc » puis « defg » vers `a` par une socket UDP neuve aux drapeaux `f`
 * (et `options` IP à 1, une liste finie par 0) ; ce que poll dit de POLLIN|POLLPRI. */
static int udp_horodatee(const struct sockaddr_in *a, int f, const int *options, short *poll_vu)
{
    struct sockaddr_in b;
    int s = udp_lie(&b), un = 1;
    for (; options && *options; options++)
        setsockopt(s, IPPROTO_IP, *options, &un, sizeof un);
    poser(s, TSG_OLD, f);
    sendto(s, "abc", 3, 0, (void *)a, sizeof *a);
    sendto(s, "defg", 4, 0, (void *)a, sizeof *a);
    struct pollfd p = {s, POLLIN | POLLPRI, 0};
    poll(&p, 1, 0);
    *poll_vu = p.revents;
    return s;
}

static void horodatages_emission_udp(void)
{
    struct sockaddr_in a;
    struct entree e[4];
    short p;
    int r = udp_lie(&a);
    /* SND, avec et sans SOFTWARE : là dès le retour de sendto. */
    int s = udp_horodatee(&a, TSF_TX_SOFTWARE | TSF_SOFTWARE, NULL, &p);
    int ok = p == POLLERR;
    for (int i = 0; i < 3; i++)
        lire_entree(s, &e[i], 128);
    ok &= horodatage_ok(&e[0], 45, 0, 0) && trame_ok(&e[0], "abc", 3) && e[0].heure && sortes_ok(&e[0], 2, (int[]){S_TS, S_ERR})
        && e[0].famille == 0 && horodatage_ok(&e[1], 46, 0, 0) && trame_ok(&e[1], "defg", 4) && e[2].r == -EAGAIN;
    close(s);
    s = udp_horodatee(&a, TSF_TX_SOFTWARE, NULL, &p);
    lire_entree(s, &e[0], 128);
    ok &= p == POLLERR && horodatage_ok(&e[0], 45, 0, 0) && sortes_ok(&e[0], 1, (int[]){S_ERR});
    close(s);
    verifier(ok, "SO_TIMESTAMPING TX_SOFTWARE UDP : SND des le retour de sendto (POLLERR), la trame de lo, sans adresse, l'heure avec SOFTWARE");
    /* SCHED puis SND, OPT_ID ; OPT_TSONLY. */
    s = udp_horodatee(&a, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_SOFTWARE | TSF_OPT_ID, NULL, &p);
    for (int i = 0; i < 4; i++)
        lire_entree(s, &e[i], 128);
    ok = horodatage_ok(&e[0], 45, 1, 0) && horodatage_ok(&e[1], 45, 0, 0) && !memcmp(e[0].o, e[1].o, 45)
        && horodatage_ok(&e[2], 46, 1, 1) && horodatage_ok(&e[3], 46, 0, 1) && lire_entree(s, &e[0], 128) == -EAGAIN;
    close(s);
    s = udp_horodatee(&a, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_ID | TSF_OPT_TSONLY, NULL, &p);
    lire_entree(s, &e[0], 128), lire_entree(s, &e[1], 128);
    ok &= horodatage_ok(&e[0], 0, 0, 0) && e[0].heure && horodatage_ok(&e[1], 0, 0, 1);
    close(s);
    verifier(ok, "SO_TIMESTAMPING UDP : SCHED puis SND, la meme trame ; OPT_ID, une cle par envoi ; OPT_TSONLY, sans octets");
    /* OPT_CMSG : les messages IP du paquet, sa source comme SO_EE_OFFENDER ; rien avec OPT_TSONLY. */
    int tous[] = {IP_PKTINFO, IP_RECVTTL, IP_RECVTOS, IP_RECVORIGDSTADDR, IP_CHECKSUM, IP_RECVOPTS, IP_RETOPTS, IP_RECVFRAGSIZE, 0};
    struct sockaddr_in b;
    s = udp_lie(&b);
    int tos = 0x10, un = 1;
    setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof tos);
    for (int *o = tous; *o; o++)
        setsockopt(s, IPPROTO_IP, *o, &un, sizeof un);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_CMSG);
    sendto(s, "abc", 3, 0, (void *)&a, sizeof a);
    lire_entree(s, &e[0], 128);
    ok = horodatage_ok(&e[0], 45, 0, 0) && sortes_ok(&e[0], 6, (int[]){S_TS, S_PKT, IP_TTL, IP_TOS, IP_ORIGDSTADDR, S_ERR})
        && e[0].pkt.ipi_ifindex == 1 && e[0].pkt.ipi_spec_dst.s_addr == htonl(INADDR_LOOPBACK)
        && e[0].pkt.ipi_addr.s_addr == htonl(INADDR_LOOPBACK) && e[0].ttl == 64 && e[0].tos == 0x10
        && e[0].port == ntohs(a.sin_port) && e[0].famille == AF_INET && e[0].offender == htonl(INADDR_LOOPBACK);
    close(s);
    s = udp_horodatee(&a, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_CMSG, NULL, &p);
    lire_entree(s, &e[0], 128);
    ok &= sortes_ok(&e[0], 2, (int[]){S_TS, S_ERR}) && e[0].famille == AF_INET;
    close(s);
    s = udp_horodatee(&a, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_CMSG | TSF_OPT_TSONLY, (int[]){IP_PKTINFO, 0}, &p);
    lire_entree(s, &e[0], 128);
    ok &= horodatage_ok(&e[0], 0, 0, 0) && sortes_ok(&e[0], 2, (int[]){S_TS, S_ERR}) && e[0].famille == 0;
    close(s);
    verifier(ok, "SO_TIMESTAMPING OPT_CMSG UDP : IP_PKTINFO, IP_TTL, IP_TOS, IP_ORIGDSTADDR du paquet, sa source en SO_EE_OFFENDER ; rien avec OPT_TSONLY");
    /* TX_ACK ne vaut pas pour UDP ; les clés : TX_HARDWARE et TX_COMPLETION en prennent,
     * pas TX_ACK ni SOFTWARE seul ; OPT_ID qui se pose les remet à zéro. */
    s = udp_horodatee(&a, TSF_TX_ACK | TSF_SOFTWARE, NULL, &p);
    ok = p == 0 && lire_entree(s, &e[0], 128) == -EAGAIN;
    close(s);
    s = udp_lie(&b);
    int suite[] = {TSF_TX_HARDWARE, TSF_TX_HARDWARE, TSF_TX_COMPLETION, TSF_TX_ACK, TSF_SOFTWARE, TSF_TX_SOFTWARE | TSF_OPT_TSONLY};
    for (int i = 0; i < 6; i++) {
        poser(s, TSG_OLD, suite[i] | TSF_OPT_ID);
        sendto(s, "a", 1, 0, (void *)&a, sizeof a);
    }
    lire_entree(s, &e[0], 128);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_OPT_TSONLY);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_OPT_TSONLY | TSF_OPT_ID);
    sendto(s, "a", 1, 0, (void *)&a, sizeof a);
    lire_entree(s, &e[1], 128);
    ok &= horodatage_ok(&e[0], 0, 0, 3) && horodatage_ok(&e[1], 0, 0, 0) && lire_entree(s, &e[2], 128) == -EAGAIN;
    close(s);
    verifier(ok, "SO_TIMESTAMPING UDP : TX_ACK sans effet ; les cles d'OPT_ID (TX_HARDWARE, TX_COMPLETION en prennent), remises a zero");
    /* Le bouchon : les drapeaux de son premier envoi, ses octets ensemble ; MSG_TRUNC. */
    s = udp_lie(&b);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_ID);
    sendto(s, "abc", 3, MSG_MORE, (void *)&a, sizeof a);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_SOFTWARE | TSF_OPT_ID);
    sendto(s, "de", 2, 0, (void *)&a, sizeof a);
    sendto(s, "f", 1, 0, (void *)&a, sizeof a);
    for (int i = 0; i < 4; i++)
        lire_entree(s, &e[i], i == 0 ? 128 : 10);
    ok = horodatage_ok(&e[0], 47, 0, 0) && trame_ok(&e[0], "abcde", 5) && e[1].r == 10 && e[1].flags == (MSG_ERRQUEUE | MSG_TRUNC)
        && e[1].ee_info == 1 && e[1].ee_data == 1 && e[2].r == 10 && e[2].ee_info == 0 && e[3].r == -EAGAIN;
    close(s);
    verifier(ok, "SO_TIMESTAMPING UDP : le bouchon garde les drapeaux de son premier envoi ; MSG_TRUNC");
    /* SO_RCVBUF borne la file (sock_queue_err_skb) : de douze entrées, quelques-unes. */
    s = udp_lie(&b);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &un, sizeof un);
    for (int i = 0; i < 6; i++)
        sendto(s, "abc", 3, 0, (void *)&a, sizeof a);
    int n = 0;
    while (lire_entree(s, &e[0], 128) > 0)
        n++;
    close(s);
    char quoi[96];
    snprintf(quoi, sizeof quoi, "SO_TIMESTAMPING UDP : SO_RCVBUF borne la file, %d entrees de 12", n);
    verifier(n >= 1 && n <= 3, quoi);
    /* Une entrée sans octets (OPT_TSONLY) : la même mémoire pour chacune (la tête vide
     * d'un paquet), rendue à la lecture ; SO_RCVBUF en garde ce qui y tient. */
    s = udp_lie(&b);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_TSONLY);
    sendto(s, "abc", 3, 0, (void *)&a, sizeof a);
    unsigned une = compteur(s, RMEM);
    sendto(s, "abc", 3, 0, (void *)&a, sizeof a);
    sendto(s, "abc", 3, 0, (void *)&a, sizeof a);
    unsigned trois = compteur(s, RMEM);
    n = 0;
    while (lire_entree(s, &e[0], 128) == 0)
        n++;
    ok = une > 0 && trois == 3 * une && n == 3 && compteur(s, RMEM) == 0;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &un, sizeof un);
    int rcvbuf = compteur(s, RCVBUF), tenues = 0;
    for (int i = 0; i < 12; i++)
        sendto(s, "abc", 3, 0, (void *)&a, sizeof a);
    while (lire_entree(s, &e[0], 128) == 0)
        tenues++;
    close(s);
    printf("[linux] options-socket : SO_TIMESTAMPING UDP, OPT_TSONLY : %u octets par entree, %d gardees sous SO_RCVBUF %d\n", une, tenues, rcvbuf);
    verifier(ok && tenues == (rcvbuf - 1) / (int)une,
             "SO_TIMESTAMPING UDP : une entree OPT_TSONLY compte la tete vide d'un paquet, rendue a la lecture, sous SO_RCVBUF");
    /* Les messages de contrôle : SO_TIMESTAMPING (_OLD ou _NEW, les drapeaux d'émission
     * seulement, 4 octets) et SCM_TS_OPT_ID (4 octets, OPT_ID posé, pas TCP). */
    s = udp_lie(&b);
    poser(s, TSG_OLD, TSF_SOFTWARE | TSF_OPT_ID | TSF_OPT_TSONLY);
    int deux[2] = {TSF_TX_SOFTWARE, 0};
    char ctl[2 * CMSG_SPACE(4)];
    memset(ctl, 0, sizeof ctl);
    struct iovec io = {"x", 1};
    struct msghdr m = {&a, sizeof a, &io, 1, ctl, sizeof ctl, 0};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET, c->cmsg_type = TSG_NEW, c->cmsg_len = CMSG_LEN(4);
    memcpy(CMSG_DATA(c), &deux[0], 4);
    c = CMSG_NXTHDR(&m, c);
    c->cmsg_level = SOL_SOCKET, c->cmsg_type = SCM_TS_OPT_ID_, c->cmsg_len = CMSG_LEN(4);
    memcpy(CMSG_DATA(c), &(int){1234}, 4);
    ok = sendmsg(s, &m, 0) == 1;
    ok &= envoyer_avec(s, &a, SOL_SOCKET, TSG_OLD, TSF_TX_SOFTWARE) == 0;
    ok &= envoyer_avec(s, &a, SOL_SOCKET, TSG_OLD, TSF_TX_ACK | TSF_TX_COMPLETION | TSF_TX_HARDWARE) == 0;
    ok &= envoyer_avec(s, &a, SOL_SOCKET, TSG_OLD, TSF_SOFTWARE) == EINVAL;
    ok &= envoyer_avec(s, &a, -1, 0, 0) == 0;
    lire_entree(s, &e[0], 128), lire_entree(s, &e[1], 128);
    ok &= horodatage_ok(&e[0], 0, 0, 1234) && horodatage_ok(&e[1], 0, 0, 0) && lire_entree(s, &e[2], 128) == -EAGAIN;
    poser(s, TSG_OLD, TSF_SOFTWARE);
    ok &= envoyer_avec(s, &a, SOL_SOCKET, SCM_TS_OPT_ID_, 5) == EINVAL;
    close(s);
    int l = socket(AF_INET, SOCK_STREAM, 0), t = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la;
    lier_tcp(l, &la), listen(l, 1), connect(t, (void *)&la, sizeof la);
    poser(t, TSG_OLD, TSF_SOFTWARE | TSF_OPT_ID);
    ok &= envoyer_avec(t, NULL, SOL_SOCKET, SCM_TS_OPT_ID_, 5) == EINVAL;
    close(t), close(l);
    verifier(ok, "SO_TIMESTAMPING a l'envoi : son message de controle (les drapeaux d'emission seuls) et SCM_TS_OPT_ID (OPT_ID pose, pas TCP)");
    while (recv(r, (char[64]){0}, 64, MSG_DONTWAIT) > 0)
        ;
    close(r);
}

/* Ping : SND, la trame de l'écho. */
static void horodatages_emission_ping(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP), un = 1;
    struct entree e[2];
    setsockopt(s, IPPROTO_IP, IP_RECVORIGDSTADDR, &un, sizeof un);
    setsockopt(s, IPPROTO_IP, IP_RECVTTL, &un, sizeof un);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_ID | TSF_OPT_CMSG);
    unsigned char echo[8] = {8, 0, 0, 0, 0, 0, 0, 1};
    struct sockaddr_in l = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    sendto(s, echo, 8, 0, (void *)&l, sizeof l);
    lire_entree(s, &e[0], 128);
    int ok = horodatage_ok(&e[0], 42, 0, 0) && e[0].o[23] == IPPROTO_ICMP && e[0].o[34] == 8
        && sortes_ok(&e[0], 4, (int[]){S_TS, IP_TTL, IP_ORIGDSTADDR, S_ERR}) && e[0].port == (e[0].o[36] << 8 | e[0].o[37])
        && lire_entree(s, &e[1], 128) == -EAGAIN;
    close(s);
    verifier(ok, "SO_TIMESTAMPING ping : SND, la trame de l'echo, OPT_ID, OPT_CMSG (IP_ORIGDSTADDR : la somme de l'ICMP)");
}

/* Ce que poll dit prêt, sans attendre. */
static int pret(int s)
{
    struct pollfd p = {s, POLLIN | POLLPRI | POLLOUT, 0};
    return poll(&p, 1, 0) < 0 ? -1 : p.revents;
}

/* Une socket UDP connectée au port 9 de lo, où personne n'écoute (chaque envoi
 * revient en erreur ICMP), avec IP_RECVERR si `recverr`, et SO_SELECT_ERR_QUEUE. */
static int udp_refusee(int recverr, int select_err_queue)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &recverr, sizeof recverr);
    poser(s, SO_SELECT_ERR_QUEUE, select_err_queue);
    connect(s, (void *)&a, sizeof a);
    return s;
}

/* IP_RECVERR remis à 0 vide la file d'erreurs, sauf les horodatages
 * (`skb_errqueue_purge`) : l'erreur ICMP part, l'entrée SND reste, et l'erreur en
 * attente aussi. */
static void horodatages_purge(void)
{
    int s = udp_refusee(1, 0), zero = 0, err = 0;
    socklen_t l = sizeof err;
    struct entree e[2];
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_TSONLY);
    int ok = send(s, "b", 1, 0) == 1;
    usleep(20000);
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &zero, sizeof zero);
    lire_entree(s, &e[0], 64);
    ok &= horodatage_ok(&e[0], 0, 0, 0) && lire_entree(s, &e[1], 64) == -EAGAIN;
    ok &= getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &l) == 0 && err == ECONNREFUSED;
    close(s);
    verifier(ok, "IP_RECVERR remis a 0 : l'erreur ICMP partie, l'horodatage SND garde, SO_ERROR encore ECONNREFUSED");
}

/* Le fil qui envoie 200 ms plus tard, pendant l'attente de l'autre : l'erreur arrive
 * alors qu'il dort. */
static void *envoyer_plus_tard(void *p)
{
    attendre_ms(200);
    send(*(int *)p, "x", 1, 0);
    return NULL;
}

static void select_err_queue(void)
{
    const int erreurs = POLLERR | POLLPRI;
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]), v = 1;
        verifier(lire(s, SO_SELECT_ERR_QUEUE) == 0 && poser(s, SO_SELECT_ERR_QUEUE, 7) == 0
                     && lire(s, SO_SELECT_ERR_QUEUE) == 1 && poser(s, SO_SELECT_ERR_QUEUE, 0) == 0
                     && lire(s, SO_SELECT_ERR_QUEUE) == 0
                     && erreur(setsockopt(s, SOL_SOCKET, SO_SELECT_ERR_QUEUE, &v, 2)) == EINVAL,
                 dire("SO_SELECT_ERR_QUEUE %s : 0, puis relue 1", sortes[i].nom));
        close(s);
    }
    char o[64], c[256];
    for (int avec = 0; avec < 2; avec++) {
        int s = udp_refusee(1, avec);
        int vide = pret(s);
        send(s, "x", 1, 0);
        attendre_ms(50);
        int en_file = pret(s);
        struct msghdr m = {.msg_iov = &(struct iovec){o, sizeof o}, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c};
        recvmsg(s, &m, MSG_ERRQUEUE | MSG_DONTWAIT);
        int lue = pret(s);
        verifier((vide & erreurs) == 0 && (en_file & erreurs) == (avec ? erreurs : POLLERR) && (lue & erreurs) == 0,
                 avec ? "SO_SELECT_ERR_QUEUE UDP : une erreur en file, POLLPRI avec POLLERR, jusqu'a sa lecture"
                      : "UDP sans SO_SELECT_ERR_QUEUE : une erreur en file, POLLERR seul");
        close(s);
    }
    int s = udp_refusee(0, 1);
    send(s, "x", 1, 0);
    attendre_ms(50);
    int avant = pret(s), e = lire(s, SO_ERROR), apres = pret(s);
    verifier((avant & erreurs) == erreurs && e == ECONNREFUSED && (apres & erreurs) == 0,
             "SO_SELECT_ERR_QUEUE UDP sans IP_RECVERR : l'erreur en attente seule, POLLPRI jusqu'a SO_ERROR");
    close(s);
    s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    poser(s, SO_SELECT_ERR_QUEUE, 1);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    connect(s, (void *)&a, sizeof a);
    attendre_ms(50);
    verifier((pret(s) & erreurs) == POLLERR, "SO_SELECT_ERR_QUEUE TCP : une connexion refusee, POLLERR seul");
    close(s);
    /* AF_UNIX : le pair parti sans avoir lu ce qu'on lui envoyait (ECONNRESET). */
    for (int i = 3; i < SORTES; i++) {
        if (sortes[i].type == SOCK_DGRAM)
            continue;
        int p[2];
        socketpair(AF_UNIX, sortes[i].type, 0, p);
        poser(p[0], SO_SELECT_ERR_QUEUE, 1);
        send(p[0], "ab", 2, 0);
        close(p[1]);
        int r = pret(p[0]);
        verifier(lire(p[0], SO_ERROR) == ECONNRESET && (r & erreurs) == (sortes[i].type == SOCK_STREAM ? POLLERR : erreurs),
                 dire("SO_SELECT_ERR_QUEUE %s : le pair parti sans lire, POLLPRI pour les paquets seulement", sortes[i].nom));
        close(p[0]);
    }
    /* AF_UNIX en datagrammes : le pair se déconnecte en laissant un message non lu
     * (`unix_dgram_disconnected` : ECONNRESET pour l'autre bout). */
    int d[2];
    struct sockaddr_un rien = {.sun_family = AF_UNSPEC};
    socketpair(AF_UNIX, SOCK_DGRAM, 0, d);
    poser(d[1], SO_SELECT_ERR_QUEUE, 1);
    send(d[1], "z", 1, 0);
    connect(d[0], (void *)&rien, sizeof(sa_family_t));
    int r = pret(d[1]);
    verifier((r & erreurs) == erreurs && lire(d[1], SO_ERROR) == ECONNRESET && (pret(d[1]) & erreurs) == 0,
             "SO_SELECT_ERR_QUEUE unix datagrammes : le pair deconnecte, POLLPRI avec POLLERR jusqu'a SO_ERROR");
    close(d[0]), close(d[1]);
    /* Les réveils : l'erreur arrive 200 ms après le début de l'attente. */
    for (int k = 0; k < 4; k++) {
        s = udp_refusee(1, 1);
        pthread_t f;
        pthread_create(&f, NULL, envoyer_plus_tard, &s);
        int ok = 0;
        if (k == 0) {
            struct pollfd q = {s, POLLPRI, 0};
            struct timespec d = {3, 0};
            ok = ppoll(&q, 1, &d, NULL) == 1 && q.revents == erreurs && (d.tv_sec || d.tv_nsec);
        } else if (k == 1) {
            int ep = epoll_create1(0);
            struct epoll_event ev = {.events = EPOLLPRI};
            epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);
            ok = epoll_wait(ep, &ev, 1, 3000) == 1 && ev.events == (EPOLLPRI | EPOLLERR);
            close(ep);
        } else {
            /* Avec la lecture, réveillé ; sans elle, rien ne le réveille : l'échéance
             * (une seconde), où son dernier tour voit l'erreur. */
            fd_set lu, ex;
            FD_ZERO(&lu);
            FD_ZERO(&ex);
            FD_SET(s, &lu);
            FD_SET(s, &ex);
            struct timeval d = {k == 2 ? 3 : 1, 0};
            int r = select(s + 1, k == 2 ? &lu : NULL, NULL, &ex, &d);
            ok = k == 2 ? r == 2 && FD_ISSET(s, &lu) && FD_ISSET(s, &ex) && (d.tv_sec || d.tv_usec)
                        : r == 1 && FD_ISSET(s, &ex) && d.tv_sec == 0 && d.tv_usec == 0;
        }
        pthread_join(f, NULL);
        const char *quoi[] = {"poll qui n'attend que POLLPRI : reveille, POLLPRI et POLLERR",
                              "epoll qui n'attend que EPOLLPRI : reveille, EPOLLPRI et EPOLLERR",
                              "select en lecture et en exceptions : reveille, les deux",
                              "select en exceptions seules : pas reveille, l'erreur vue a l'echeance"};
        verifier(ok, dire("SO_SELECT_ERR_QUEUE, une erreur pendant l'attente : %s", quoi[k]));
        close(s);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    cle_tenue_ailleurs = !cle_eteinte();
    if (cle_tenue_ailleurs)
        printf("[linux] options-socket : la cle des horodatages de la machine est tenue par un autre programme : "
               "les verifications qui la veulent eteinte sont sautees\n");
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
    select_err_queue();
    horodatages_option();
    horodatages_reception();
    horodatages_fille();
    horodatages_emission_udp();
    horodatages_emission_ping();
    horodatages_purge();
    printf("[linux] options-socket : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
