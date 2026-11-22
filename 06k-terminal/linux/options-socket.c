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
 *     SCM_TS_OPT_ID (et leurs refus) ; MSG_TRUNC ; SO_RCVBUF borne la file ;
 *   - SO_TIMESTAMPING, à l'émission de TCP : SCHED et SND du segment qui porte le
 *     dernier octet d'un envoi (sa trame de lo), puis ACK quand il est acquitté (ses
 *     données seules, sans interface) ; OPT_ID, la clé de ce dernier octet depuis
 *     SND.UNA, ou depuis tout ce qui est écrit avec OPT_ID_TCP ; deux envois dans le
 *     même segment (TCP_CORK) n'en font qu'un, le dernier, aux drapeaux des deux ;
 *     OPT_TSONLY ; OPT_CMSG (IP_PKTINFO pour SND, rien pour ACK) ; POLLERR seul, même
 *     avec SO_SELECT_ERR_QUEUE, et le réveil de qui attend dans poll ;
 *   - OPT_STATS (TCP, avec OPT_TSONLY) : à la place des octets, les attributs de
 *     netlink de la connexion (248 octets, 256 avec le TTL de l'ACK), redits en
 *     SCM_TIMESTAMPING_OPT_STATS avec l'heure seulement ; au passage du segment, ce
 *     qui est compté de lui et ce qui n'est pas encore parti ; à l'ACK, ce qui est
 *     livré, et le débit d'avant lui ; rien pour UDP.
 *   - SO_ZEROCOPY (TCP et UDP, 0 ou 1 ; EOPNOTSUPP ailleurs, même 0 ; la fille de TCP
 *     l'hérite) et MSG_ZEROCOPY : un numéro par envoi, l'avis de ses pages rendues dans
 *     la file d'erreurs (COPIED : sur lo, Linux copie aussi), les numéros consécutifs
 *     fondus en un ; ce qui ne prend pas de numéro (rien d'envoyé, une erreur) ; le
 *     bouchon d'UDP ; l'avis après SND (UDP) ou après ACK (TCP), avant l'erreur ICMP ;
 *     sa mémoire dans celle des options (SO_MEMINFO), la limite (ENOBUFS), et
 *     RLIMIT_MEMLOCK ; la taille du contrôle de sendmsg face à cette mémoire.
 *   - SO_MAX_PACING_RATE : pour toutes les sortes, un entier (-1 : l'infini) ou 8 octets,
 *     relu sur 8 octets s'il y a leur place, sinon sur 4 (au plus ~0U) ; TCP_INFO (le
 *     débit borné aussitôt, le plafond) ; la fille d'une écoute a celui de sa naissance ;
 *     et le rythme interne de TCP sur lo : 2 Mo à 2 Mo/s, les dix premiers segments
 *     sans attendre, contre bien moins sans plafond, ou à 0.
 *   - les filtres (SO_ATTACH_FILTER : le BPF classique) : ce que refusent la pose (la
 *     longueur, le programme, le verrou, la mémoire des options : le nouveau compté avant
 *     que l'ancien ne parte, et les adhésions derrière lui), SO_GET_FILTER (la place
 *     comptée en instructions), SO_DETACH_FILTER, SO_LOCK_FILTER, SO_ATTACH_BPF sans
 *     programme eBPF, SO_BPF_EXTENSIONS ; puis ce que voit un filtre et ce qu'il fait du
 *     paquet : les coupes (jamais sous l'en-tête d'UDP ni de TCP, ni sous un octet) et
 *     ce que compte un paquet jeté, pour UDP, ping, TCP (l'écoute, la connexion, la
 *     fille qui hérite du filtre de son écoute) et AF_UNIX (pas en flux) ; les octets
 *     des en-têtes (SKF_NET_OFF, SKF_LL_OFF) et les extensions (le protocole, le genre
 *     de la trame, la carte, la charge, le processeur, le hachage du flux : celui d'une
 *     socket UDP connectée, gardé après la déconnexion, neuf à chaque connexion, et
 *     après SO_CNX_ADVICE 1, d'UDP comme de TCP, sauf SO_TXREHASH 0).
 *   - les groupes SO_REUSEPORT et leur programme (SO_ATTACH_REUSEPORT_CBPF et _EBPF,
 *     SO_DETACH_REUSEPORT_BPF) : les refus (une socket sans SO_REUSEPORT, une liée sans
 *     groupe, une écoute ou une connexion TCP sans groupe, AF_UNIX ; le verrou des
 *     filtres) ; l'ordre des membres (celui des `bind` ou des `listen` ; une qui part,
 *     remplacée par la dernière), que choisit le programme par son index (trop grand :
 *     le hachage, qui répartit les flux et garde chacun à sa socket), ce qu'il voit
 *     (les données après l'en-tête de transport, les en-têtes, la charge à la fin, le
 *     processeur), SO_INCOMING_CPU dans un groupe ; ce qui fait quitter un groupe d'UDP
 *     (`connect`, AF_UNSPEC qui oublie l'adresse, SO_BINDTODEVICE, le port rendu) et
 *     pas une écoute TCP (SO_BINDTODEVICE) ; la recherche (la plus récente à égalité ;
 *     un groupe en tête rend sa membre sans voir une socket mieux notée, sauf une membre
 *     connectée un jour) ; former un groupe (pas avec un groupe à soi, sauf par
 *     SO_REUSEADDR, qui perd son programme ; SO_REUSEPORT posé après `bind`).
 * Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/net_tstamp.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
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
#define SCM_TIMESTAMPING_OPT_STATS_ 54
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
 * un octet (TOS), le port d'IP_ORIGDSTADDR, la sock_extended_err et SO_EE_OFFENDER,
 * SCM_TIMESTAMPING_OPT_STATS (sa longueur, ses octets). */
struct entree {
    int r, flags, nom, n, sortes[8], heure, ttl, tos, port, stats;
    struct in_pktinfo pkt;
    unsigned ee_errno, ee_origin, ee_type, ee_code, ee_info, ee_data, famille, offender, ctl;
    unsigned char o[256], st[256];
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
    e->flags = m.msg_flags, e->nom = m.msg_namelen, e->ctl = m.msg_controllen;
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
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPING_OPT_STATS_) {
            e->stats = l;
            memcpy(e->st, d, l < 256 ? l : 256);
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
            e->ee_errno = w[0], e->ee_origin = d[4], e->ee_type = d[5], e->ee_code = d[6], e->ee_info = w[2], e->ee_data = w[3];
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

/* Une connexion TCP par lo : le client `*c`, la fille acceptée `*d`. */
static void tcp_connectee(int *c, int *d)
{
    struct sockaddr_in t;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(l, &t), listen(l, 1);
    *c = socket(AF_INET, SOCK_STREAM, 0);
    connect(*c, (void *)&t, sizeof t);
    *d = accept(l, NULL, NULL);
    close(l);
}

/* La trame de lo d'un segment TCP de données `d` (n octets) : l'en-tête Ethernet nul,
 * IP, TCP avec l'option des horodatages (32 octets), les données à la fin. */
static int segment_ok(const struct entree *e, const char *d, int n)
{
    static const unsigned char nul[12];
    return e->r == 14 + 20 + 32 + n && !memcmp(e->o, nul, 12) && e->o[12] == 8 && e->o[14] == 0x45
        && e->o[23] == IPPROTO_TCP && e->o[46] == 0x80 && !memcmp(e->o + e->r - n, d, n);
}

/* Lit `n` entrées de la file d'erreurs de `s` dans `e` (256 octets au plus chacune) ;
 * la suivante doit manquer (EAGAIN). */
static int entrees(int s, struct entree *e, int n)
{
    for (int i = 0; i < n; i++)
        lire_entree(s, &e[i], sizeof e[i].o);
    struct entree fin;
    return lire_entree(s, &fin, sizeof fin.o) == -EAGAIN;
}

/* La mémoire d'une entrée OPT_TSONLY d'UDP : la tête vide d'un paquet. */
static unsigned entree_vide(void)
{
    struct sockaddr_in a, b;
    int r = udp_lie(&a), s = udp_lie(&b);
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_OPT_TSONLY);
    sendto(s, "a", 1, 0, (void *)&a, sizeof a);
    unsigned m = compteur(s, RMEM);
    close(s), close(r);
    return m;
}

/* Lit toute la file d'erreurs de `s` : combien d'entrées. */
static int vider_entrees(int s)
{
    struct entree e;
    int n = 0;
    while (lire_entree(s, &e, sizeof e.o) >= 0)
        n++;
    return n;
}

/* Combien de `k` (8 au plus) ont `avant + k * une < rcvbuf` : les entrées que garde
 * SO_RCVBUF (sock_queue_err_skb). */
static int admises(unsigned avant, unsigned une, unsigned rcvbuf)
{
    int k = 0;
    while (k < 8 && avant + (k + 1) * une < rcvbuf)
        k++;
    return k;
}

/* La mémoire des entrées de TCP : la tête vide (comme une entrée OPT_TSONLY d'UDP), plus
 * les octets de données du segment pour une copie (SCHED, SND, ACK) ; comptées dans
 * SO_MEMINFO avec ce que la connexion a reçu, sous son SO_RCVBUF. */
static void horodatages_memoire_tcp(void)
{
    unsigned vide = entree_vide();
    int c, d, un = 1;
    tcp_connectee(&c, &d);
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &un, sizeof un);
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_TX_ACK | TSF_OPT_TSONLY);
    send(c, "abc", 3, 0);
    attendre_ms(50);
    unsigned m1 = compteur(c, RMEM);
    int ok = m1 == 3 * vide && vider_entrees(c) == 3 && compteur(c, RMEM) == 0;
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_TX_ACK);
    send(c, "abc", 3, 0);
    attendre_ms(50);
    unsigned m2 = compteur(c, RMEM);
    ok &= m2 == 3 * (vide + 3) && vider_entrees(c) == 3;
    char z[3000];
    memset(z, 'z', sizeof z);
    send(c, z, sizeof z, 0);
    attendre_ms(50);
    unsigned m3 = compteur(c, RMEM);
    ok &= m3 == 3 * (vide + 3000) && vider_entrees(c) == 3 && compteur(c, RMEM) == 0;
    close(c), close(d);
    printf("[linux] options-socket : SO_TIMESTAMPING TCP, memoire : %u par entree vide ; SCHED, SND, ACK : %u, de 3 octets %u, de 3000 %u\n",
           vide, m1, m2, m3);
    verifier(ok, "SO_TIMESTAMPING TCP : une entree compte la tete vide d'un paquet (comme OPT_TSONLY d'UDP), plus les octets de donnees du segment");
    /* SO_RCVBUF petit (posé avant connect : il ne grandit pas) ; ce que la connexion a
     * reçu et pas lu compte avec la file d'erreurs. */
    struct sockaddr_in t;
    int petit = 2048;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(l, &t), listen(l, 1);
    c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, SOL_SOCKET, SO_RCVBUF, &petit, sizeof petit);
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &un, sizeof un);
    connect(c, (void *)&t, sizeof t);
    d = accept(l, NULL, NULL);
    close(l);
    unsigned rcvbuf = compteur(c, RCVBUF);
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_OPT_TSONLY);
    for (int i = 0; i < 8; i++)
        send(c, "a", 1, 0), attendre_ms(5);
    unsigned plein = compteur(c, RMEM);
    int n0 = vider_entrees(c);
    send(d, "0123456789", 10, 0);
    attendre_ms(20);
    unsigned recu = compteur(c, RMEM);
    for (int i = 0; i < 8; i++)
        send(c, "a", 1, 0), attendre_ms(5);
    unsigned apres = compteur(c, RMEM);
    int n1 = vider_entrees(c);
    ok = n0 == admises(0, vide, rcvbuf) && plein == n0 * vide && recu > 10 && n1 == admises(recu, vide, rcvbuf) && n1 < n0
        && apres == recu + n1 * vide && recv(c, z, sizeof z, MSG_DONTWAIT) == 10 && compteur(c, RMEM) == 0;
    close(c), close(d);
    printf("[linux] options-socket : SO_TIMESTAMPING TCP, SO_RCVBUF %u : %d entrees de 8 ; %u octets recus : %d\n", rcvbuf, n0, recu, n1);
    verifier(ok, "SO_TIMESTAMPING TCP : la file d'erreurs compte avec ce que la connexion a recu, sous son SO_RCVBUF (SO_MEMINFO : les deux)");
}

static void horodatages_emission_tcp(void)
{
    struct entree e[6];
    int c, d, un = 1, zero = 0;
    tcp_connectee(&c, &d);
    /* SCHED, SND, ACK, OPT_ID : un envoi de 10 octets, puis un de 5. */
    int ok = poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_TX_ACK | TSF_SOFTWARE | TSF_OPT_ID) == 0;
    send(c, "0123456789", 10, 0);
    send(c, "abcde", 5, 0);
    attendre_ms(50);
    ok &= entrees(c, e, 6) && horodatage_ok(&e[0], 76, 1, 9) && segment_ok(&e[0], "0123456789", 10) && e[0].heure
        && sortes_ok(&e[0], 2, (int[]){S_TS, S_ERR}) && e[0].famille == 0 && horodatage_ok(&e[1], 76, 0, 9) && !memcmp(e[0].o, e[1].o, 76)
        && horodatage_ok(&e[2], 10, 2, 9) && !memcmp(e[2].o, "0123456789", 10) && e[2].heure && sortes_ok(&e[2], 2, (int[]){S_TS, S_ERR})
        && horodatage_ok(&e[3], 71, 1, 14) && segment_ok(&e[3], "abcde", 5) && horodatage_ok(&e[4], 71, 0, 14)
        && horodatage_ok(&e[5], 5, 2, 14) && !memcmp(e[5].o, "abcde", 5);
    verifier(ok, "SO_TIMESTAMPING TCP : SCHED et SND du segment (sa trame), puis ACK (ses donnees seules) ; OPT_ID, la cle de son dernier octet depuis SND.UNA");
    /* TCP_CORK : deux envois dans le même segment, une demande, la dernière, aux
     * drapeaux des deux (ceux du message de contrôle, OPT_ID reposé garde la clé). */
    poser(c, TSG_OLD, TSF_SOFTWARE | TSF_OPT_ID);
    setsockopt(c, IPPROTO_TCP, TCP_CORK, &un, sizeof un);
    ok = envoyer_avec(c, NULL, SOL_SOCKET, TSG_OLD, TSF_TX_SCHED | TSF_TX_ACK) == 0 && envoyer_avec(c, NULL, SOL_SOCKET, TSG_OLD, TSF_TX_SOFTWARE) == 0;
    setsockopt(c, IPPROTO_TCP, TCP_CORK, &zero, sizeof zero);
    attendre_ms(50);
    ok &= entrees(c, e, 3) && horodatage_ok(&e[0], 68, 1, 16) && segment_ok(&e[0], "xx", 2) && horodatage_ok(&e[1], 68, 0, 16)
        && horodatage_ok(&e[2], 2, 2, 16) && !memcmp(e[2].o, "xx", 2);
    verifier(ok, "SO_TIMESTAMPING TCP : deux envois dans un segment (TCP_CORK), une demande, la derniere, aux drapeaux des deux");
    /* OPT_TSONLY ; OPT_ID_TCP (la clé depuis tout ce qui est écrit) ; OPT_ID reposé
     * après un retrait (depuis SND.UNA). */
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_ACK | TSF_SOFTWARE | TSF_OPT_ID | TSF_OPT_TSONLY);
    send(c, "xyz", 3, 0);
    attendre_ms(50);
    ok = entrees(c, e, 2) && horodatage_ok(&e[0], 0, 0, 19) && e[0].heure && horodatage_ok(&e[1], 0, 2, 19) && e[1].heure;
    poser(c, TSG_OLD, 0);
    ok &= poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_ID | TSF_OPT_ID_TCP | TSF_OPT_TSONLY) == 0;
    send(c, "12", 2, 0);
    attendre_ms(50);
    ok &= entrees(c, e, 1) && horodatage_ok(&e[0], 0, 0, 1);
    poser(c, TSG_OLD, 0);
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_OPT_ID | TSF_OPT_TSONLY);
    send(c, "3", 1, 0);
    attendre_ms(50);
    ok &= entrees(c, e, 1) && horodatage_ok(&e[0], 0, 0, 0);
    verifier(ok, "SO_TIMESTAMPING TCP : OPT_TSONLY ; OPT_ID_TCP, la cle depuis tout ce qui est ecrit ; OPT_ID repose, depuis SND.UNA");
    /* OPT_CMSG : IP_PKTINFO et SO_EE_OFFENDER pour SND (lo), rien pour ACK. */
    setsockopt(c, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_ACK | TSF_SOFTWARE | TSF_OPT_CMSG);
    send(c, "q", 1, 0);
    attendre_ms(50);
    ok = entrees(c, e, 2) && horodatage_ok(&e[0], 67, 0, 0) && sortes_ok(&e[0], 3, (int[]){S_TS, S_PKT, S_ERR})
        && e[0].pkt.ipi_ifindex == 1 && e[0].pkt.ipi_spec_dst.s_addr == htonl(INADDR_LOOPBACK) && e[0].famille == AF_INET
        && e[0].offender == htonl(INADDR_LOOPBACK) && horodatage_ok(&e[1], 1, 2, 0) && sortes_ok(&e[1], 2, (int[]){S_TS, S_ERR})
        && e[1].famille == 0;
    verifier(ok, "SO_TIMESTAMPING TCP : OPT_CMSG, IP_PKTINFO et SO_EE_OFFENDER pour SND, rien pour ACK (aucune interface)");
    /* poll : POLLERR seul, même avec SO_SELECT_ERR_QUEUE ; plus rien une fois lue ; qui
     * attend dans poll est réveillé par l'entrée. */
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE);
    poser(c, SO_SELECT_ERR_QUEUE, 1);
    send(c, "p", 1, 0);
    attendre_ms(20);
    ok = pret(c) == (POLLOUT | POLLERR) && entrees(c, e, 1) && pret(c) == POLLOUT;
    pthread_t f;
    pthread_create(&f, NULL, envoyer_plus_tard, &c);
    struct pollfd p = {c, POLLIN, 0};
    long long t0 = monotone_ns();
    ok &= poll(&p, 1, 3000) == 1 && p.revents == POLLERR && monotone_ns() - t0 >= 150000000LL;
    pthread_join(f, NULL);
    ok &= entrees(c, e, 1) && horodatage_ok(&e[0], 67, 0, 0);
    verifier(ok, "SO_TIMESTAMPING TCP : POLLERR seul, meme avec SO_SELECT_ERR_QUEUE, et le reveil de qui attend dans poll");
    close(c);
    char z[64];
    while (recv(d, z, sizeof z, MSG_DONTWAIT) > 0)
        ;
    close(d);
    /* Un envoi sans demande d'émission qui s'ajoute au segment d'une demande
     * (TCP_CORK) : l'entrée ACK copie tout le segment (`__skb_tstamp_tx` clone
     * le `sk_buff`), au-delà du dernier octet de la demande, dont elle garde la clé. */
    tcp_connectee(&c, &d);
    poser(c, TSG_OLD, TSF_SOFTWARE | TSF_OPT_ID);
    setsockopt(c, IPPROTO_TCP, TCP_CORK, &un, sizeof un);
    ok = envoyer_avec(c, NULL, SOL_SOCKET, TSG_OLD, TSF_TX_ACK) == 0 && send(c, "yy", 2, 0) == 2;
    setsockopt(c, IPPROTO_TCP, TCP_CORK, &zero, sizeof zero);
    attendre_ms(50);
    ok &= entrees(c, e, 1) && horodatage_ok(&e[0], 3, 2, 0) && !memcmp(e[0].o, "xyy", 3);
    verifier(ok, "SO_TIMESTAMPING TCP : un envoi sans demande ajoute au segment d'une demande (TCP_CORK), l'entree ACK copie tout le segment");
    close(c);
    while (recv(d, z, sizeof z, MSG_DONTWAIT) > 0)
        ;
    close(d);
    horodatages_memoire_tcp();
}

/* OPT_STATS : les attributs de `a` (n octets) sont-ils ceux de Linux 6.18, dans son
 * ordre et de leurs longueurs (le TTL seulement pour ACK) ? */
static int attributs_ok(const unsigned char *a, int n, int ack)
{
    static const int ordre[][2] = {{1, 12}, {2, 12}, {3, 12}, {4, 12}, {5, 12}, {6, 12}, {7, 12}, {8, 8}, {9, 8}, {10, 8},
                                   {11, 5}, {12, 5}, {15, 8}, {16, 8}, {17, 8}, {13, 8}, {14, 5}, {18, 12}, {19, 12},
                                   {20, 8}, {21, 8}, {22, 8}, {23, 6}, {24, 8}, {25, 12}, {26, 5}, {27, 8}};
    int i = 0;
    for (unsigned k = 0; k < sizeof ordre / sizeof ordre[0]; k++) {
        if (ordre[k][0] == 26 && !ack)
            continue;
        uint16_t l, t;
        if (i + 4 > n)
            return 0;
        memcpy(&l, a + i, 2), memcpy(&t, a + i + 2, 2);
        if (t != ordre[k][0] || l != ordre[k][1])
            return 0;
        i += (l + 3) & ~3;
    }
    return i == n;
}

/* La valeur de l'attribut `sorte` d'OPT_STATS dans `a` (n octets) ; -1 s'il n'y est pas. */
static long long attribut(const unsigned char *a, int n, int sorte)
{
    for (int i = 0; i + 4 <= n;) {
        uint16_t l, t;
        memcpy(&l, a + i, 2), memcpy(&t, a + i + 2, 2);
        if (t == sorte) {
            unsigned long long v = 0;
            memcpy(&v, a + i + 4, l - 4 > 8 ? 8 : l - 4);
            return v;
        }
        i += (l + 3) & ~3;
    }
    return -1;
}

/* Les compteurs que dit OPT_STATS de l'entrée `e` : DATA_SEGS_OUT, BYTES_SENT,
 * SNDQ_SIZE, BYTES_NOTSENT, DELIVERED, et les constantes d'une connexion neuve sans
 * perte (CWND 10, REORDERING 3, SSTHRESH infini, rien de renvoyé, CA_STATE Open) ;
 * l'heure de départ (EDT, temps monotone) de moins de 5 s. */
static int stats_ok(const struct entree *e, int segs, int envoyes, int en_file, int pas_partis, int livres)
{
    const unsigned char *a = e->o;
    long long edt = attribut(a, e->r, 25);
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    long long age = t.tv_sec * 1000000000LL + t.tv_nsec - edt;
    return attribut(a, e->r, 4) == segs && attribut(a, e->r, 18) == envoyes && attribut(a, e->r, 13) == en_file
        && attribut(a, e->r, 24) == pas_partis && attribut(a, e->r, 16) == livres && attribut(a, e->r, 8) == 10
        && attribut(a, e->r, 9) == 3 && attribut(a, e->r, 15) == 0x7fffffff && attribut(a, e->r, 5) == 0
        && attribut(a, e->r, 19) == 0 && attribut(a, e->r, 11) == 0 && attribut(a, e->r, 14) == 0
        && attribut(a, e->r, 17) == 0 && attribut(a, e->r, 27) == 0 && age >= 0 && age < 5000000000LL;
}

static void horodatages_stats_tcp(void)
{
    struct entree e[3];
    int c, d;
    tcp_connectee(&c, &d);
    /* SCHED, SND, ACK : les attributs, en octets et en message de contrôle, après
     * l'heure ; ce qui est compté du segment, ce qui n'est pas parti (pas encore lui),
     * ce qui est livré (le SYN compte) ; le débit d'avant l'ACK (0 au premier) ; le TTL. */
    int ok = poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_TX_ACK | TSF_SOFTWARE | TSF_OPT_ID | TSF_OPT_TSONLY | TSF_OPT_STATS) == 0;
    send(c, "abc", 3, 0);
    attendre_ms(50);
    /* Leurs attributs tiennent dans la tête vide d'un paquet : chacune compte comme une
     * entrée OPT_TSONLY. */
    unsigned vide = entree_vide(), trois = compteur(c, RMEM);
    printf("[linux] options-socket : OPT_STATS TCP, memoire : %u pour SCHED, SND, ACK (%u par entree vide)\n", trois, vide);
    ok &= trois == 3 * vide && entrees(c, e, 3);
    for (int i = 0; i < 3; i++)
        ok &= horodatage_ok(&e[i], i < 2 ? 248 : 256, i < 2 ? 1 - i : 2, 2) && e[i].heure
            && sortes_ok(&e[i], 3, (int[]){S_TS, SOL_SOCKET * 1000 + SCM_TIMESTAMPING_OPT_STATS_, S_ERR}) && e[i].stats == e[i].r
            && !memcmp(e[i].st, e[i].o, e[i].r) && attributs_ok(e[i].o, e[i].r, i == 2);
    ok &= stats_ok(&e[0], 1, 3, 3, 3, 1) && stats_ok(&e[1], 1, 3, 3, 3, 1) && stats_ok(&e[2], 1, 3, 0, 0, 2)
        && attribut(e[2].o, 256, 7) == 0 && attribut(e[2].o, 256, 26) == 64;
    verifier(ok, "OPT_STATS TCP : les attributs de SCHED, SND et ACK (248 et 256 octets), au passage du segment et au milieu de l'ACK ; chacune compte comme une entree vide");
    /* Un deuxième envoi ; sans SOFTWARE, les attributs sans message de contrôle. */
    send(c, "defgh", 5, 0);
    attendre_ms(50);
    ok = entrees(c, e, 3) && stats_ok(&e[1], 2, 8, 5, 5, 2) && stats_ok(&e[2], 2, 8, 0, 0, 3) && attribut(e[2].o, 256, 7) > 0;
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_ACK | TSF_OPT_TSONLY | TSF_OPT_STATS);
    send(c, "i", 1, 0);
    attendre_ms(50);
    ok &= entrees(c, e, 2) && e[0].r == 248 && sortes_ok(&e[0], 1, (int[]){S_ERR}) && attributs_ok(e[0].o, 248, 0)
        && e[1].r == 256 && sortes_ok(&e[1], 1, (int[]){S_ERR}) && attributs_ok(e[1].o, 256, 1);
    verifier(ok, "OPT_STATS TCP : un deuxieme envoi, le debit du premier ACK ; sans SOFTWARE, les attributs sans message de controle");
    close(c);
    char z[64];
    while (recv(d, z, sizeof z, MSG_DONTWAIT) > 0)
        ;
    close(d);
    /* Un envoi qui rend moins que voulu (non bloquant, SO_SNDBUF plein), dont tout ce
     * qu'il a écrit est déjà parti : sa demande va au dernier segment en vol
     * (`skb_rb_last`), et l'entrée ACK dit l'heure de son départ (EDT). */
    tcp_connectee(&c, &d);
    int petit = 4096;
    setsockopt(c, SOL_SOCKET, SO_SNDBUF, &petit, sizeof petit);
    poser(c, TSG_OLD, TSF_TX_ACK | TSF_OPT_TSONLY | TSF_OPT_STATS);
    static char gros[1 << 20];
    long envoye = send(c, gros, sizeof gros, MSG_DONTWAIT);
    attendre_ms(50);
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    long long edt = entrees(c, e, 1) ? attribut(e[0].o, e[0].r, 25) : -1, age = t.tv_sec * 1000000000LL + t.tv_nsec - edt;
    char q[160];
    snprintf(q, sizeof q, "OPT_STATS TCP : un envoi qui rend moins que voulu (%ld octets), tout parti : l'heure de depart (EDT) du dernier segment en vol", envoye);
    verifier(envoye > 0 && envoye < (long)sizeof gros && edt > 0 && age >= 0 && age < 5000000000LL, q);
    close(c);
    while (recv(d, gros, sizeof gros, MSG_DONTWAIT) > 0)
        ;
    close(d);
    /* UDP : rien (OPT_STATS ne vaut que pour TCP). */
    struct sockaddr_in a;
    int r = udp_lie(&a), u = socket(AF_INET, SOCK_DGRAM, 0);
    poser(u, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_TSONLY | TSF_OPT_STATS);
    sendto(u, "u", 1, 0, (void *)&a, sizeof a);
    ok = entrees(u, e, 1) && horodatage_ok(&e[0], 0, 0, 0) && sortes_ok(&e[0], 2, (int[]){S_TS, S_ERR});
    verifier(ok, "OPT_STATS UDP : une entree vide, sans attributs");
    close(u), close(r);
}

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif
/* `optmem_max` (net.core.optmem_max), sa valeur de départ chez Linux comme chez nous. */
#define OPTMEM_MAX 131072

/* Dans notre noyau (son /etc/bonjour.txt), pas sur l'hôte. */
static int chez_nous;

/* L'avis de MSG_ZEROCOPY des envois `premier` à `dernier` : rien à lire, sans adresse,
 * IP_RECVERR seul (48 octets), d'origine SO_EE_ORIGIN_ZEROCOPY, COPIED (sur lo, Linux
 * copie aussi), sans erreur ni émetteur. */
static int avis_ok(const struct entree *e, unsigned premier, unsigned dernier)
{
    return e->r == 0 && e->nom == 0 && e->flags == MSG_ERRQUEUE && e->ctl == 48 && sortes_ok(e, 1, (int[]){S_ERR})
        && e->ee_errno == 0 && e->ee_origin == 5 && e->ee_type == 0 && e->ee_code == 1 && e->ee_info == premier
        && e->ee_data == dernier && e->famille == 0;
}

/* Le processus a-t-il CAP_IPC_LOCK (le bit 14 de CapEff, /proc/self/status) ? Pas
 * root : sous docker, root ne l'a pas. */
static int verrouille_ses_pages(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char ligne[256];
    unsigned long long cap = 0;
    while (f && fgets(ligne, sizeof ligne, f))
        if (sscanf(ligne, "CapEff: %llx", &cap) == 1)
            break;
    if (f)
        fclose(f);
    return cap >> 14 & 1;
}

/* sendmsg d'un octet avec `n` octets de contrôle nuls : ce qu'il rend (errno, 0). */
static int controle(int s, size_t n)
{
    static char tampon[OPTMEM_MAX + 1];
    struct iovec io = {"x", 1};
    struct msghdr m = {0, 0, &io, 1, tampon, n, 0};
    return erreur(sendmsg(s, &m, 0));
}

static void zerocopie_option(void)
{
    static const struct { const char *nom; int dom, sorte, proto, prend; } sortes[] = {
        {"tcp", AF_INET, SOCK_STREAM, 0, 1}, {"udp", AF_INET, SOCK_DGRAM, 0, 1}, {"ping", AF_INET, SOCK_DGRAM, IPPROTO_ICMP, 0},
        {"unix flux", AF_UNIX, SOCK_STREAM, 0, 0}, {"unix datagrammes", AF_UNIX, SOCK_DGRAM, 0, 0},
        {"unix paquets", AF_UNIX, SOCK_SEQPACKET, 0, 0}};
    int ok = 1;
    for (unsigned i = 0; i < sizeof sortes / sizeof sortes[0]; i++) {
        int s = socket(sortes[i].dom, sortes[i].sorte, sortes[i].proto);
        short court = 1;
        int c = erreur(setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &court, sizeof court));
        if (sortes[i].prend)
            ok &= lire(s, SO_ZEROCOPY) == 0 && poser(s, SO_ZEROCOPY, 1) == 0 && lire(s, SO_ZEROCOPY) == 1 && poser(s, SO_ZEROCOPY, 2) == EINVAL
                && poser(s, SO_ZEROCOPY, -1) == EINVAL && lire(s, SO_ZEROCOPY) == 1 && poser(s, SO_ZEROCOPY, 0) == 0 && lire(s, SO_ZEROCOPY) == 0;
        else
            ok &= lire(s, SO_ZEROCOPY) == 0 && poser(s, SO_ZEROCOPY, 1) == EOPNOTSUPP && poser(s, SO_ZEROCOPY, 0) == EOPNOTSUPP
                && poser(s, SO_ZEROCOPY, -1) == EOPNOTSUPP && lire(s, SO_ZEROCOPY) == 0;
        ok &= s >= 0 && c == EINVAL;
        close(s);
    }
    verifier(ok, "SO_ZEROCOPY : TCP et UDP, 0 ou 1 (EINVAL sinon, ou trop court) ; EOPNOTSUPP pour ping et AF_UNIX, meme 0");
}

static void zerocopie_udp(void)
{
    struct sockaddr_in a, b;
    struct entree e[4];
    int r = udp_lie(&a), grand = 1 << 20, un = 1;
    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &grand, sizeof grand);
    unsigned vide = entree_vide();
    /* Sans l'option, MSG_ZEROCOPY ne fait rien. */
    int s = udp_lie(&b);
    connect(s, (void *)&a, sizeof a);
    int ok = send(s, "abc", 3, MSG_ZEROCOPY) == 3 && lire_entree(s, &e[0], 64) == -EAGAIN;
    close(s);
    s = udp_lie(&b);
    poser(s, SO_ZEROCOPY, 1);
    connect(s, (void *)&a, sizeof a);
    struct pollfd p = {s, POLLIN | POLLOUT | POLLPRI, 0};
    ok &= send(s, "abc", 3, 0) == 3 && lire_entree(s, &e[0], 64) == -EAGAIN && compteur(s, OPTMEM) == 0;
    ok &= send(s, "abc", 3, MSG_ZEROCOPY) == 3 && poll(&p, 1, 0) == 1 && p.revents == (POLLOUT | POLLERR)
        && compteur(s, OPTMEM) == vide && compteur(s, RMEM) == 0;
    ok &= send(s, "defg", 4, MSG_ZEROCOPY) == 4 && send(s, "h", 1, MSG_ZEROCOPY) == 1 && compteur(s, OPTMEM) == vide;
    ok &= entrees(s, e, 1) && avis_ok(&e[0], 0, 2) && compteur(s, OPTMEM) == 0 && poll(&p, 1, 0) == 1 && p.revents == POLLOUT;
    verifier(ok, "MSG_ZEROCOPY UDP : rien sans SO_ZEROCOPY ; un avis par envoi, les numeros consecutifs fondus, POLLERR ; "
                 "dans la memoire des options, celle d'une entree vide, jusqu'a sa lecture");
    /* 0 octet prend un numéro, EMSGSIZE et EFAULT non ; le bouchon : l'avis quand le
     * datagramme part, de tous les numéros de ses envois. */
    static char gros[70000];
    ok = send(s, "", 0, MSG_ZEROCOPY) == 0 && erreur(send(s, gros, sizeof gros, MSG_ZEROCOPY)) == EMSGSIZE
        && erreur(send(s, (void *)8, 10, MSG_ZEROCOPY)) == EFAULT && send(s, "i", 1, MSG_ZEROCOPY) == 1 && entrees(s, e, 1)
        && avis_ok(&e[0], 3, 4);
    ok &= send(s, "j", 1, MSG_ZEROCOPY | MSG_MORE) == 1 && lire_entree(s, &e[0], 64) == -EAGAIN
        && send(s, "k", 1, MSG_ZEROCOPY | MSG_MORE) == 1 && send(s, "l", 1, MSG_ZEROCOPY) == 1 && entrees(s, e, 1) && avis_ok(&e[0], 5, 7)
        && send(s, "m", 1, MSG_MORE) == 1 && send(s, "n", 1, MSG_ZEROCOPY) == 1 && entrees(s, e, 1) && avis_ok(&e[0], 8, 8)
        && send(s, "o", 1, MSG_ZEROCOPY | MSG_MORE) == 1 && send(s, "p", 1, 0) == 1 && entrees(s, e, 1) && avis_ok(&e[0], 9, 9);
    verifier(ok, "MSG_ZEROCOPY UDP : un envoi de 0 octet prend un numero, EMSGSIZE et EFAULT non ; le bouchon, l'avis au depart du datagramme");
    /* SO_TIMESTAMP : l'heure de la lecture, devant ; vers un port fermé, avec
     * IP_RECVERR : l'avis, puis l'erreur ICMP. */
    poser(s, SO_TIMESTAMP, 1);
    ok = send(s, "q", 1, MSG_ZEROCOPY) == 1 && entrees(s, e, 1) && e[0].r == 0 && e[0].ctl == 80
        && sortes_ok(&e[0], 2, (int[]){SOL_SOCKET * 1000 + SO_TIMESTAMP, S_ERR}) && e[0].ee_origin == 5 && e[0].ee_info == 10;
    poser(s, SO_TIMESTAMP, 0);
    close(r);
    setsockopt(s, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    send(s, "r", 1, MSG_ZEROCOPY);
    attendre_ms(20);
    ok &= entrees(s, e, 2) && avis_ok(&e[0], 11, 11) && e[1].ee_origin == 2 && e[1].ee_errno == ECONNREFUSED;
    close(s);
    verifier(ok, "MSG_ZEROCOPY UDP : SO_TIMESTAMP devant l'avis ; vers un port ferme, l'avis puis l'erreur ICMP");
    /* Horodaté (OPT_TSONLY) : SND puis l'avis, à chaque envoi (pas de fusion) ; la
     * mémoire des options pleine (ENOBUFS), puis rendue à la lecture ; le contrôle de
     * sendmsg (sock_kmalloc) doit tenir dans ce qu'il en reste, strictement. */
    r = udp_lie(&a);
    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &grand, sizeof grand);
    s = udp_lie(&b);
    poser(s, SO_ZEROCOPY, 1);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &grand, sizeof grand);
    connect(s, (void *)&a, sizeof a);
    ok = controle(s, 36) == EINVAL && controle(s, OPTMEM_MAX - 1) == EINVAL && controle(s, OPTMEM_MAX) == ENOBUFS;
    poser(s, TSG_OLD, TSF_TX_SOFTWARE | TSF_SOFTWARE | TSF_OPT_TSONLY);
    send(s, "a", 1, MSG_ZEROCOPY);
    send(s, "b", 1, MSG_ZEROCOPY);
    ok &= entrees(s, e, 4) && horodatage_ok(&e[0], 0, 0, 0) && avis_ok(&e[1], 0, 0) && horodatage_ok(&e[2], 0, 0, 0) && avis_ok(&e[3], 1, 1);
    int n = 0;
    unsigned avant = 0;
    for (; n < 1000; n++) {
        avant = compteur(s, OPTMEM);
        if (send(s, "c", 1, MSG_ZEROCOPY) < 0)
            break;
    }
    int refus = errno;
    unsigned rm = compteur(s, RMEM);
    ok &= controle(s, 36) == EINVAL && controle(s, 37) == EINVAL && controle(s, OPTMEM_MAX - avant - 1) == EINVAL
        && controle(s, OPTMEM_MAX - avant) == ENOBUFS;
    int lues = vider_entrees(s);
    ok &= refus == ENOBUFS && n > 100 && avant == n * vide && rm == n * vide && lues == 2 * n && compteur(s, OPTMEM) == 0;
    printf("[linux] options-socket : MSG_ZEROCOPY UDP, la memoire des options pleine apres %d avis (%u octets)\n", n, avant);
    verifier(ok, "MSG_ZEROCOPY UDP : SND puis l'avis ; la memoire des options pleine, ENOBUFS, rendue a la lecture ; le controle de sendmsg y tient, strictement");
    /* RLIMIT_MEMLOCK : à 0, ENOBUFS (sauf avec CAP_IPC_LOCK) ; rétablie, l'envoi passe. */
    poser(s, TSG_OLD, 0);
    struct rlimit avant_rl, rl;
    getrlimit(RLIMIT_MEMLOCK, &avant_rl);
    rl = avant_rl, rl.rlim_cur = 0;
    setrlimit(RLIMIT_MEMLOCK, &rl);
    int nul = erreur(send(s, "a", 1, MSG_ZEROCOPY)), sans = send(s, "a", 1, 0) == 1;
    setrlimit(RLIMIT_MEMLOCK, &avant_rl);
    ok = (verrouille_ses_pages() ? nul == 0 : nul == ENOBUFS) && sans && send(s, "a", 1, MSG_ZEROCOPY) == 1 && vider_entrees(s) == 1;
    close(s), close(r);
    verifier(ok, "MSG_ZEROCOPY : RLIMIT_MEMLOCK a 0, ENOBUFS (sauf avec CAP_IPC_LOCK), retablie, l'envoi passe");
}

static void zerocopie_tcp(void)
{
    struct entree e[4];
    unsigned vide = entree_vide();
    struct sockaddr_in t;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(l, &t), listen(l, 1);
    poser(l, SO_ZEROCOPY, 1);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    poser(c, SO_ZEROCOPY, 1);
    int ok = erreur(send(c, "x", 1, MSG_ZEROCOPY | MSG_NOSIGNAL)) == EPIPE && lire_entree(c, &e[0], 64) == -EAGAIN;
    connect(c, (void *)&t, sizeof t);
    int f = accept(l, NULL, NULL);
    close(l);
    ok &= lire(f, SO_ZEROCOPY) == 1 && poser(f, SO_ZEROCOPY, 0) == 0 && send(f, "abc", 3, MSG_ZEROCOPY) == 3;
    ok &= send(c, "", 0, MSG_ZEROCOPY) == 0 && send(c, "abc", 3, MSG_ZEROCOPY) == 3 && compteur(c, OPTMEM) == vide
        && send(c, "defg", 4, MSG_ZEROCOPY) == 4 && send(c, "h", 1, MSG_ZEROCOPY) == 1;
    attendre_ms(20);
    char trois[8];
    ok &= lire_entree(f, &e[0], 64) == -EAGAIN && recv(c, trois, sizeof trois, MSG_DONTWAIT) == 3 && compteur(c, OPTMEM) == vide
        && entrees(c, e, 1) && avis_ok(&e[0], 0, 2) && compteur(c, OPTMEM) == 0 && compteur(c, RMEM) == 0;
    verifier(ok, "MSG_ZEROCOPY TCP : EPIPE sans connexion, sans numero ; la fille herite SO_ZEROCOPY ; 0 octet, rien ; l'avis a l'ACK, les numeros fondus");
    /* Horodaté : SCHED, SND, ACK, puis l'avis ; un gros envoi, un numéro ; RLIMIT_MEMLOCK ;
     * après shutdown, EPIPE sans numéro. */
    poser(c, TSG_OLD, TSF_TX_SOFTWARE | TSF_TX_SCHED | TSF_TX_ACK | TSF_SOFTWARE | TSF_OPT_TSONLY);
    send(c, "ij", 2, MSG_ZEROCOPY);
    attendre_ms(20);
    ok = entrees(c, e, 4) && horodatage_ok(&e[0], 0, 1, 0) && horodatage_ok(&e[1], 0, 0, 0) && horodatage_ok(&e[2], 0, 2, 0)
        && avis_ok(&e[3], 3, 3);
    poser(c, TSG_OLD, 0);
    static char gros[200000], z[4096];
    ssize_t g = send(c, gros, sizeof gros, MSG_ZEROCOPY | MSG_DONTWAIT), recu = 0, k;
    for (int i = 0; i < 200 && recu < 10 + g; i++) {
        while ((k = recv(f, z, sizeof z, MSG_DONTWAIT)) > 0)
            recu += k;
        attendre_ms(10);
    }
    attendre_ms(20);
    ok &= g > 0 && recu == 10 + g && entrees(c, e, 1) && avis_ok(&e[0], 4, 4);
    struct rlimit avant_rl, rl;
    getrlimit(RLIMIT_MEMLOCK, &avant_rl);
    rl = avant_rl, rl.rlim_cur = 0;
    setrlimit(RLIMIT_MEMLOCK, &rl);
    int nul = erreur(send(c, "a", 1, MSG_ZEROCOPY));
    setrlimit(RLIMIT_MEMLOCK, &avant_rl);
    attendre_ms(20);
    ok &= (verrouille_ses_pages() ? nul == 0 && entrees(c, e, 1) : nul == ENOBUFS && entrees(c, e, 0));
    shutdown(c, SHUT_WR);
    ok &= erreur(send(c, "x", 1, MSG_ZEROCOPY | MSG_NOSIGNAL)) == EPIPE && lire_entree(c, &e[0], 64) == -EAGAIN;
    close(c), close(f);
    verifier(ok, "MSG_ZEROCOPY TCP : l'avis apres SCHED, SND et ACK ; un gros envoi, un numero ; RLIMIT_MEMLOCK ; EPIPE apres shutdown, sans numero");
    /* connect(AF_UNSPEC) jette les files de la connexion (`tcp_disconnect`) : les
     * avis qui attendaient leur ACK viennent tous, celui des envois dont rien n'est
     * parti d'abord (la file d'émission jetée avant celle de retransmission), puis
     * celui des 64 premiers (8 Kio chacun : un avis s'allonge jusqu'à 512 Kio), une
     * part en vol. Le premier n'est pas COPIED chez Linux (rien n'a été copié de
     * pages jamais parties) ; il l'est chez nous, qui copions à l'envoi (zerocopie.rs).
     * Puis, mise à l'écoute, sa fille repart de 0 (`sk_clone_lock` : `sk_zckey`). */
    int r = socket(AF_INET, SOCK_STREAM, 0), petit = 4096;
    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &petit, sizeof petit);
    lier_tcp(r, &t), listen(r, 1);
    c = socket(AF_INET, SOCK_STREAM, 0);
    poser(c, SO_ZEROCOPY, 1);
    connect(c, (void *)&t, sizeof t);
    f = accept(r, NULL, NULL);
    close(r);
    static char bloc[8192];
    unsigned envois = 0;
    while (envois < 1000 && send(c, bloc, sizeof bloc, MSG_ZEROCOPY | MSG_DONTWAIT) > 0)
        envois++;
    attendre_ms(20);
    struct sockaddr un_spec = {.sa_family = AF_UNSPEC};
    ok = envois > 1 && connect(c, &un_spec, sizeof un_spec) == 0;
    attendre_ms(20);
    ok &= envois > 64 && entrees(c, e, 2) && avis_ok(&e[1], 0, 63) && e[0].ee_code == (unsigned)chez_nous;
    e[0].ee_code = 1;
    ok &= avis_ok(&e[0], 64, envois - 1);
    close(f);
    struct sockaddr_in b;
    socklen_t lb = sizeof b;
    ok &= listen(c, 1) == 0 && getsockname(c, (void *)&b, &lb) == 0;
    int c2 = socket(AF_INET, SOCK_STREAM, 0);
    connect(c2, (void *)&b, sizeof b);
    int f2 = accept(c, NULL, NULL);
    ok &= send(f2, "z", 1, MSG_ZEROCOPY) == 1;
    attendre_ms(20);
    ok &= entrees(f2, e, 1) && avis_ok(&e[0], 0, 0);
    close(f2), close(c2), close(c);
    char q[160];
    snprintf(q, sizeof q, "MSG_ZEROCOPY TCP : connect(AF_UNSPEC), les avis des %u envois en attente viennent ; la fille de l'ecoute qu'elle devient repart de 0", envois);
    verifier(ok, q);
    /* Un envoi qui s'ajoute au `sk_buff` en queue, pas encore parti, allonge son avis
     * (`msg_zerocopy_realloc`) : rien tant que tout n'est pas acquitté, pas même pour
     * le premier envoi, puis un seul avis. */
    r = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(r, SOL_SOCKET, SO_RCVBUF, &petit, sizeof petit);
    lier_tcp(r, &t), listen(r, 1);
    c = socket(AF_INET, SOCK_STREAM, 0);
    int grand = 65536;
    setsockopt(c, SOL_SOCKET, SO_SNDBUF, &grand, sizeof grand);
    poser(c, SO_ZEROCOPY, 1);
    connect(c, (void *)&t, sizeof t);
    f = accept(r, NULL, NULL);
    close(r);
    ok = 1;
    for (int i = 0; i < 3; i++)
        ok &= send(c, bloc, sizeof bloc, MSG_ZEROCOPY | MSG_DONTWAIT) == (ssize_t)sizeof bloc;
    /* Le premier envoi arrivé tout entier (lu : acquitté) ; le persist de Linux
     * peut prendre une seconde. */
    size_t lus = 0;
    for (int i = 0; i < 1000 && lus < sizeof bloc; i++) {
        ssize_t k = recv(f, z, sizeof bloc - lus < sizeof z ? sizeof bloc - lus : sizeof z, MSG_DONTWAIT);
        if (k > 0)
            lus += k;
        else
            attendre_ms(5);
    }
    attendre_ms(20);
    ok &= lus == sizeof bloc && lire_entree(c, &e[0], 64) == -EAGAIN;
    for (int i = 0; i < 1000 && lus < 3 * sizeof bloc; i++) {
        ssize_t k = recv(f, z, sizeof z, MSG_DONTWAIT);
        if (k > 0)
            lus += k;
        else
            attendre_ms(5);
    }
    attendre_ms(20);
    ok &= lus == 3 * sizeof bloc && entrees(c, e, 1) && avis_ok(&e[0], 0, 2);
    close(c), close(f);
    verifier(ok, "MSG_ZEROCOPY TCP : un envoi qui s'ajoute au segment pas encore parti allonge son avis, qui vient quand tout est acquitte");
    /* AF_UNIX et ping : MSG_ZEROCOPY ignoré. */
    int u[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, u);
    ok = send(u[0], "a", 1, MSG_ZEROCOPY) == 1;
    close(u[0]), close(u[1]);
    socketpair(AF_UNIX, SOCK_DGRAM, 0, u);
    ok &= send(u[0], "a", 1, MSG_ZEROCOPY) == 1;
    close(u[0]), close(u[1]);
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    char echo[8] = {8, 0, 0, 0, 0, 0, 0, 1};
    ok &= sendto(p, echo, sizeof echo, MSG_ZEROCOPY, (void *)&lo, sizeof lo) == 8;
    attendre_ms(20);
    ok &= lire_entree(p, &e[0], 64) == -EAGAIN;
    close(p);
    verifier(ok, "MSG_ZEROCOPY : ignore par AF_UNIX et ping");
}

/* SO_MAX_PACING_RATE dans une place de `place` octets (0xaa au-delà de ce qui est écrit) :
 * la valeur lue, la longueur rendue dans *l. */
static uint64_t rythme_lu(int s, socklen_t place, socklen_t *l)
{
    unsigned char b[16];
    memset(b, 0xaa, sizeof b);
    *l = place;
    if (getsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, b, l) < 0)
        return 0x1000 + errno;
    uint64_t v = 0;
    memcpy(&v, b, 8);
    return v;
}

static int rythme_pose(int s, uint64_t v, socklen_t longueur)
{
    return erreur(setsockopt(s, SOL_SOCKET, SO_MAX_PACING_RATE, &v, longueur));
}

static uint64_t rythme(int s)
{
    socklen_t l;
    return rythme_lu(s, 8, &l);
}

/* Le débit et le plafond de TCP_INFO (`tcpi_pacing_rate`, `tcpi_max_pacing_rate`). */
static uint64_t info64(int s, int decalage)
{
    unsigned char b[256] = {0};
    socklen_t l = sizeof b;
    uint64_t v = 0;
    getsockopt(s, IPPROTO_TCP, TCP_INFO, b, &l);
    memcpy(&v, b + decalage, 8);
    return v;
}

struct lecteur {
    int f;
    long total, lu;
};

/* Lit `total` octets de la fille (combien : `lu`), puis répond un octet. */
static void *lire_tout(void *p)
{
    static char z[1 << 16];
    struct lecteur *l = p;
    ssize_t n;
    while (l->lu < l->total && (n = read(l->f, z, sizeof z)) > 0)
        l->lu += n;
    if (write(l->f, "f", 1) != 1)
        l->lu = -1;
    return NULL;
}

/* `total` octets par une connexion sur lo au plafond `max` (-1 : sans), lus par un fil : la
 * durée jusqu'à la fin de la lecture, en secondes (un milliard si tout n'est pas passé), et
 * le MSS de l'envoi dans *mss. */
static double transfert(long max, long total, unsigned *mss)
{
    static char d[1 << 16];
    int c, f;
    tcp_connectee(&c, &f);
    if (max >= 0)
        rythme_pose(c, max, 8);
    struct lecteur l = {f, total, 0};
    pthread_t t;
    pthread_create(&t, NULL, lire_tout, &l);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long ecrit = 0;
    ssize_t k;
    while (ecrit < total && (k = write(c, d, total - ecrit < (long)sizeof d ? total - ecrit : (long)sizeof d)) > 0)
        ecrit += k;
    char x;
    int fin = read(c, &x, 1) == 1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    *mss = info(c, 16);
    pthread_join(t, NULL);
    close(c), close(f);
    if (!fin || ecrit != total || l.lu != total)
        return 1e9;
    return (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
}

static void rythme_max(void)
{
    const uint64_t INFINI = ~0ull;
    for (int i = 0; i < SORTES; i++) {
        int s = ouvrir(&sortes[i]);
        socklen_t l16, l7, l2, l0;
        int ok = rythme_lu(s, 16, &l16) == INFINI && l16 == 8 && rythme_lu(s, 7, &l7) == 0xaaaaaaaaffffffffull && l7 == 4
            && rythme_lu(s, 2, &l2) == 0xaaaaaaaaaaaaffffull && l2 == 2 && rythme_lu(s, 0, &l0) == 0xaaaaaaaaaaaaaaaaull && l0 == 0;
        ok &= rythme_pose(s, 1000, 3) == EINVAL && rythme(s) == INFINI && rythme_pose(s, 1000, 4) == 0 && rythme(s) == 1000;
        ok &= rythme_pose(s, 1ull << 32, 8) == 0 && rythme(s) == 1ull << 32 && rythme_lu(s, 4, &l7) == 0xaaaaaaaaffffffffull;
        ok &= rythme_pose(s, 0xffffffff, 4) == 0 && rythme(s) == INFINI;
        ok &= rythme_pose(s, 0x80000000, 4) == 0 && rythme(s) == 0x80000000;
        ok &= rythme_pose(s, 0x100000005ull, 6) == 0 && rythme(s) == 5;
        ok &= rythme_pose(s, 0xffffffff, 8) == 0 && rythme(s) == 0xffffffff;
        ok &= rythme_pose(s, 0, 4) == 0 && rythme(s) == 0;
        close(s);
        verifier(ok, dire("SO_MAX_PACING_RATE (%s) : un entier (-1 l'infini) ou 8 octets, relu sur 8 ou sur 4 (au plus ~0U)", sortes[i].nom));
    }
    /* TCP_INFO : le débit borné tout de suite ; le plafond levé, il reste borné jusqu'à
     * l'ACK suivant. */
    int n = socket(AF_INET, SOCK_STREAM, 0);
    int ok = info64(n, 104) == INFINI && info64(n, 112) == INFINI;
    rythme_pose(n, 5000, 8);
    ok &= info64(n, 104) == 5000 && info64(n, 112) == 5000;
    rythme_pose(n, INFINI, 8);
    ok &= info64(n, 104) == 5000 && info64(n, 112) == INFINI;
    close(n);
    int c, f;
    char b[4];
    tcp_connectee(&c, &f);
    rythme_pose(c, 123456, 8);
    ok &= info64(c, 104) == 123456 && info64(c, 112) == 123456;
    ok &= write(c, "abc", 3) == 3 && read(f, b, 3) == 3 && write(f, "d", 1) == 1 && read(c, b, 1) == 1;
    attendre_ms(50);
    ok &= info64(c, 104) == 123456;
    rythme_pose(c, INFINI, 8);
    ok &= info64(c, 104) == 123456 && info64(c, 112) == INFINI;
    ok &= write(c, "abc", 3) == 3 && read(f, b, 3) == 3;
    attendre_ms(50);
    ok &= info64(c, 104) > 123456 && info64(c, 104) != INFINI;
    close(c), close(f);
    verifier(ok, "SO_MAX_PACING_RATE : TCP_INFO, le debit borne aussitot ; le plafond leve, borne jusqu'a l'ACK suivant");
    /* L'héritage : le plafond de l'écoute à la naissance de la fille. */
    struct sockaddr_in t;
    int e = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(e, &t), listen(e, 2);
    rythme_pose(e, 12345, 8);
    ok = info64(e, 104) == 12345 && info64(e, 112) == 12345;
    int c1 = socket(AF_INET, SOCK_STREAM, 0);
    connect(c1, (void *)&t, sizeof t);
    attendre_ms(50);
    rythme_pose(e, 777, 8);
    int f1 = accept(e, NULL, NULL);
    ok &= rythme(f1) == 12345 && info64(f1, 104) == 12345 && info64(f1, 112) == 12345;
    int c2 = socket(AF_INET, SOCK_STREAM, 0);
    connect(c2, (void *)&t, sizeof t);
    int f2 = accept(e, NULL, NULL);
    ok &= rythme(f2) == 777 && info64(f2, 104) == 777;
    close(c1), close(c2), close(f1), close(f2), close(e);
    verifier(ok, "SO_MAX_PACING_RATE : la fille a le plafond de l'ecoute a sa naissance, pas a l'accept");
    /* Le rythme interne : 2 Mo à 2 Mo/s. Les dix premiers segments partent sans attendre,
     * chacun des autres attend sa durée au débit, moins le retard pris (au plus la moitié) :
     * au moins (2 Mo - 10 MSS) / 4 Mo/s. Sans plafond, ou à 0 : bien plus vite. */
    unsigned mss, mss_sans, mss_nul;
    double avec = transfert(2000000, 2000000, &mss), sans = transfert(-1, 2000000, &mss_sans), nul = transfert(0, 2000000, &mss_nul);
    printf("[linux] options-socket : 2 Mo a 2 Mo/s en %.3f s (MSS %u), sans plafond %.3f s, a 0 %.3f s\n", avec, mss, sans, nul);
    verifier(avec >= (2000000.0 - 10 * mss) / 4000000 && avec <= 3 && sans < avec / 2 && nul < avec / 2,
             "SO_MAX_PACING_RATE : le rythme interne de TCP, dix segments sans attendre puis au debit ; sans plafond, ou a 0, rien n'attend");
}

/* --- Les filtres --- */

#define F(c, k) ((struct sock_filter){(unsigned short)(c), 0, 0, (unsigned)(k)})
#define RET_A F(BPF_RET | BPF_A, 0)
#define RET_K(k) F(BPF_RET | BPF_K, k)

static int filtre(int s, struct sock_filter *f, unsigned short n)
{
    struct sock_fprog p = {n, f};
    return erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof p));
}

static int filtre_k(int s, unsigned k)
{
    struct sock_filter f[1] = {RET_K(k)};
    return filtre(s, f, 1);
}

/* Un compteur de /proc/net/snmp (`proto` : Udp, Tcp...), -1 s'il manque. */
static long snmp(const char *proto, const char *champ)
{
    FILE *f = fopen("/proc/net/snmp", "r");
    char a[1024], b[1024];
    long v = -1;
    while (f && fgets(a, sizeof a, f) && fgets(b, sizeof b, f)) {
        if (strncmp(a, proto, strlen(proto)) || a[strlen(proto)] != ':')
            continue;
        char *sa, *sb, *ta = strtok_r(a, " \n", &sa), *tb = strtok_r(b, " \n", &sb);
        while ((ta = strtok_r(NULL, " \n", &sa)) && (tb = strtok_r(NULL, " \n", &sb)))
            if (!strcmp(ta, champ))
                v = atol(tb);
    }
    if (f)
        fclose(f);
    return v;
}

static void filtres_options(void)
{
    struct sock_filter trois[3] = {F(BPF_LD | BPF_W | BPF_ABS, 0), F(BPF_ALU | BPF_ADD | BPF_K, 1), RET_A};
    for (int i = 0; i < SORTES; i++) {
        const struct sorte *so = &sortes[i];
        int s = ouvrir(so), v = 1;
        socklen_t l = 0;
        struct sock_fprog p = {1, trois};
        /* La pose : au moins un entier, puis une `sock_fprog` exactement ; une adresse,
         * de 1 à 4096 instructions, un programme juste ; lisibles. */
        verifier(erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &p, 2)) == EINVAL
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &p, 8)) == EINVAL
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, NULL, sizeof p)) == EFAULT,
                 dire("%s : SO_ATTACH_FILTER, une sock_fprog de 16 octets (EINVAL, EFAULT)", so->nom));
        struct sock_fprog nul = {1, NULL}, vide = {0, trois}, trop = {4097, trois}, loin = {1, (void *)8};
        struct sock_filter sans_ret[1] = {F(BPF_LD | BPF_W | BPF_ABS, 0)}, div0[2] = {F(BPF_ALU | BPF_DIV | BPF_K, 0), RET_A};
        verifier(erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &nul, sizeof nul)) == EINVAL
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &vide, sizeof vide)) == EINVAL
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &trop, sizeof trop)) == EINVAL
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &loin, sizeof loin)) == EFAULT
                 && filtre(s, sans_ret, 1) == EINVAL && filtre(s, div0, 2) == EINVAL,
                 dire("%s : SO_ATTACH_FILTER refuse un programme absent, vide, trop long, illisible ou faux", so->nom));
        /* Relu : sans filtre, 0 ; la place comptée en instructions ; tout écrit. */
        verifier(getsockopt(s, SOL_SOCKET, SO_GET_FILTER, NULL, &l) == 0 && l == 0,
                 dire("%s : SO_GET_FILTER sans filtre : 0", so->nom));
        struct sock_filter relu[4];
        memset(relu, 0x77, sizeof relu);
        verifier(filtre(s, trois, 3) == 0 && getsockopt(s, SOL_SOCKET, SO_GET_FILTER, NULL, &l) == 0 && l == 3
                 && (l = 2, erreur(getsockopt(s, SOL_SOCKET, SO_GET_FILTER, relu, &l))) == EINVAL
                 && (l = 3, getsockopt(s, SOL_SOCKET, SO_GET_FILTER, relu, &l)) == 0 && l == 3
                 && !memcmp(relu, trois, sizeof trois) && relu[3].code == 0x7777,
                 dire("%s : SO_GET_FILTER : la longueur, EINVAL sous elle, le programme", so->nom));
        /* Enlevé, puis plus rien à enlever. */
        verifier(erreur(setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &v, sizeof v)) == 0
                 && erreur(setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &v, sizeof v)) == ENOENT
                 && getsockopt(s, SOL_SOCKET, SO_GET_FILTER, NULL, &l) == 0 && l == 0,
                 dire("%s : SO_DETACH_FILTER, puis ENOENT", so->nom));
        /* Un descripteur qui n'est pas un programme d'eBPF. */
        int fd = -1;
        verifier(erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &fd, 8)) == EINVAL
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &fd, 4)) == EBADF
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &s, 4)) == EINVAL,
                 dire("%s : SO_ATTACH_BPF : EINVAL, EBADF, EINVAL", so->nom));
        verifier(lire(s, SO_BPF_EXTENSIONS) == 64 && poser(s, SO_BPF_EXTENSIONS, 1) == ENOPROTOOPT,
                 dire("%s : SO_BPF_EXTENSIONS : 64, en lecture seule", so->nom));
        /* Le verrou : posé, il ne s'ouvre plus ; le filtre ne change plus. */
        verifier(filtre(s, trois, 3) == 0 && lire(s, SO_LOCK_FILTER) == 0 && poser(s, SO_LOCK_FILTER, 2) == 0
                 && lire(s, SO_LOCK_FILTER) == 1 && poser(s, SO_LOCK_FILTER, 0) == EPERM && poser(s, SO_LOCK_FILTER, 1) == 0
                 && filtre(s, trois, 3) == EPERM && filtre(s, sans_ret, 1) == EPERM
                 && erreur(setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &v, sizeof v)) == EPERM
                 && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_BPF, &fd, 4)) == EPERM
                 && getsockopt(s, SOL_SOCKET, SO_GET_FILTER, NULL, &l) == 0 && l == 3,
                 dire("%s : SO_LOCK_FILTER : EPERM pour l'ouvrir, changer ou enlever le filtre", so->nom));
        close(s);
    }
}

/* Un programme de `n` instructions, des lectures longues (ld [40000] : 16 instructions
 * d'eBPF, 128 octets), puis ret a. */
static int longues(int s, int n)
{
    static struct sock_filter f[4096];
    for (int i = 0; i < n - 1; i++)
        f[i] = F(BPF_LD | BPF_W | BPF_ABS, 40000);
    f[n - 1] = RET_A;
    return filtre(s, f, n);
}

static void filtres_memoire(void)
{
    /* Ce qu'un filtre compte dans la mémoire des options : celle de sa traduction. */
    int s = socket(AF_INET, SOCK_DGRAM, 0), v = 1;
    struct sock_filter un[1] = {RET_A}, deux[2] = {F(BPF_LD | BPF_W | BPF_ABS, 0), RET_A};
    verifier(filtre(s, un, 1) == 0 && compteur(s, OPTMEM) == 128 && filtre(s, deux, 2) == 0 && compteur(s, OPTMEM) == 264
             && setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &v, sizeof v) == 0 && compteur(s, OPTMEM) == 0,
             "un filtre dans SO_MEMINFO : 128 octets (ret a), 264 (ld [0] ; ret a), 0 enleve");
    /* La limite : le nouveau compté avant que l'ancien ne parte (ENOMEM). */
    verifier(longues(s, 1023) == 0 && compteur(s, OPTMEM) == 130976 && longues(s, 1024) == ENOMEM
             && filtre(s, deux, 2) == ENOMEM && compteur(s, OPTMEM) == 130976
             && setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &v, sizeof v) == 0 && filtre(s, deux, 2) == 0,
             "un filtre trop grand pour la memoire des options : ENOMEM, l'ancien encore compte");
    /* Derrière lui, les adhésions : un groupe tient (48 octets), pas deux (ENOBUFS) ;
     * derrière 130848, un groupe et sa liste de sources (64). */
    struct ip_mreq m = {{htonl(0xef010001)}, {htonl(INADDR_LOOPBACK)}};
    struct ip_mreq_source ms = {{htonl(0xef010003)}, {htonl(INADDR_LOOPBACK)}, {htonl(0x0a000001)}};
    verifier(setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &v, sizeof v) == 0 && longues(s, 1023) == 0
             && erreur(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof m)) == 0 && compteur(s, OPTMEM) == 131024
             && (m.imr_multiaddr.s_addr = htonl(0xef010002), erreur(setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof m))) == ENOBUFS
             && compteur(s, OPTMEM) == 131024,
             "derriere un filtre, les adhesions tiennent dans la memoire des options (ENOBUFS)");
    close(s);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    verifier(longues(s, 1022) == 0 && compteur(s, OPTMEM) == 130848
             && erreur(setsockopt(s, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &ms, sizeof ms)) == 0 && compteur(s, OPTMEM) == 130960,
             "derriere un filtre, un groupe et sa liste de sources");
    close(s);
}

/* Envoie `n` octets (le motif a, b, c...) de `tx` à `a` (NULL : connectée), puis la
 * longueur reçue par `rx` (-1 : rien en 200 ms). */
static int un_envoi(int tx, int rx, struct sockaddr_in *a, int n)
{
    char m[700];
    for (int i = 0; i < n; i++)
        m[i] = 'a' + i % 26;
    if (a)
        sendto(tx, m, n, 0, (void *)a, sizeof *a);
    else
        send(tx, m, n, 0);
    struct pollfd p = {rx, POLLIN, 0};
    if (poll(&p, 1, 200) <= 0)
        return -1;
    return recv(rx, texte, sizeof texte, MSG_DONTWAIT | MSG_TRUNC);
}

/* Ce que vaut A au bout de `f` (n instructions) pour un datagramme UDP de 600 octets
 * de `tx` (vers `a`, NULL : connectée), lu par la longueur reçue : le filtre finit par
 * « add #8 ; ret a », et garde l'en-tête et A octets de charge. Pour A sous 600 ; -1 :
 * jeté, -1000 : refusé. */
static int vu(int tx, int rx, struct sockaddr_in *a, struct sock_filter *f, int n)
{
    struct sock_filter g[8];
    memcpy(g, f, n * sizeof *f);
    g[n] = F(BPF_ALU | BPF_ADD | BPF_K, 8);
    g[n + 1] = RET_A;
    if (filtre(rx, g, n + 2))
        return -1000;
    return un_envoi(tx, rx, a, 600);
}

/* Le hachage du flux des datagrammes de `tx` (vers `a`, NULL : connectée), lu par le filtre de
 * `rx` (SKF_AD_RXHASH : lo garde celui de l'émetteur) en quatre octets, un datagramme chacun. */
static unsigned hachage_udp(int tx, int rx, struct sockaddr_in *a)
{
    unsigned h = 0;
    for (int o = 0; o < 4; o++) {
        struct sock_filter g[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_RXHASH), F(BPF_ALU | BPF_RSH | BPF_K, 8 * o),
                                   F(BPF_ALU | BPF_AND | BPF_K, 0xff)};
        h |= (unsigned)vu(tx, rx, a, g, 3) << (8 * o);
    }
    return h;
}

static void filtres_udp(void)
{
    cpu_set_t avant, zero;
    sched_getaffinity(0, sizeof avant, &avant);
    CPU_ZERO(&zero);
    CPU_SET(0, &zero);
    sched_setaffinity(0, sizeof zero, &zero);
    struct sockaddr_in a;
    int rx = udp_lie(&a), tx = socket(AF_INET, SOCK_DGRAM, 0);
    /* Les coupes : jamais sous l'en-tête (8) ; 0 jette, une perte et une erreur d'UDP. */
    long e = snmp("Udp", "InErrors");
    unsigned p = compteur(rx, DROPS);
    verifier(filtre_k(rx, 0) == 0 && un_envoi(tx, rx, &a, 100) == -1 && compteur(rx, DROPS) == p + 1
             && snmp("Udp", "InErrors") == e + 1,
             "udp : un filtre qui rend 0 jette le datagramme (une perte, InErrors)");
    unsigned ks[] = {1, 8, 9, 30, 100000}, attendus[] = {0, 0, 1, 22, 100};
    int ok = 1;
    for (int i = 0; i < 5; i++)
        ok &= filtre_k(rx, ks[i]) == 0 && un_envoi(tx, rx, &a, 100) == (int)attendus[i];
    verifier(ok && compteur(rx, DROPS) == p + 1, "udp : coupe, jamais sous l'en-tete (0, 0, 1, 22, 100 octets)");
    /* Ce qu'il voit : les données à l'en-tête UDP, les en-têtes IP et Ethernet (nul par lo)
     * derrière, et les extensions. Une valeur V se lit en recevant V octets de charge. */
    struct sock_filter longueur[2] = {F(BPF_LD | BPF_W | BPF_LEN, 0), F(BPF_ALU | BPF_SUB | BPF_K, 600)},
        net0[1] = {F(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF)},
        net9[1] = {F(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF + 9)},
        ll0[1] = {F(BPF_LD | BPF_B | BPF_ABS, SKF_LL_OFF)},
        ll12[2] = {F(BPF_LD | BPF_H | BPF_ABS, SKF_LL_OFF + 12), F(BPF_ALU | BPF_SUB | BPF_K, 0x800)},
        msh[2] = {F(BPF_LDX | BPF_B | BPF_MSH, SKF_NET_OFF), F(BPF_MISC | BPF_TXA, 0)};
    verifier(vu(tx, rx, &a, longueur, 2) == 8 && vu(tx, rx, &a, net0, 1) == 0x45 && vu(tx, rx, &a, net9, 1) == IPPROTO_UDP
             && vu(tx, rx, &a, ll0, 1) == 0 && vu(tx, rx, &a, ll12, 2) == 0 && vu(tx, rx, &a, msh, 2) == 20,
             "udp : la longueur (en-tete compris), l'en-tete IP (SKF_NET_OFF), l'en-tete Ethernet nul de lo (SKF_LL_OFF)");
    /* Chaque extension, moins ce qu'elle doit valoir : 0 octet de charge (au-delà de
     * 600, une valeur se verrait mal). */
    static const unsigned attendu[16] = {
        [SKF_AD_PROTOCOL / 4] = 0x800, [SKF_AD_IFINDEX / 4] = 1, [SKF_AD_HATYPE / 4] = 772, [SKF_AD_PAY_OFFSET / 4] = 8,
    };
    struct sock_filter ext[2];
    int ok_ext = 1;
    for (int k = 0; k < 16; k++) {
        ext[0] = F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + 4 * k);
        ext[1] = F(BPF_ALU | BPF_SUB | BPF_K, attendu[k]);
        if (k != SKF_AD_RANDOM / 4 && k != SKF_AD_NLATTR / 4 && k != SKF_AD_NLATTR_NEST / 4 && k != SKF_AD_ALU_XOR_X / 4)
            ok_ext &= vu(tx, rx, &a, ext, 2) == 0;
    }
    verifier(ok_ext,
             "udp : les extensions par lo (protocole, genre, carte 1 de type 772, charge a 8, processeur 0)");
    /* Lire hors du paquet, ou diviser par X nul : jeté. Sous SKF_AD_OFF : refusé. */
    struct sock_filter hors[1] = {F(BPF_LD | BPF_B | BPF_ABS, 620)}, div[3] = {F(BPF_LDX | BPF_IMM, 0), F(BPF_ALU | BPF_DIV | BPF_X, 0), RET_A},
        moins8[2] = {F(BPF_LD | BPF_B | BPF_ABS, -8), RET_A};
    verifier(vu(tx, rx, &a, hors, 1) == -1 && filtre(rx, div, 3) == 0 && un_envoi(tx, rx, &a, 10) == -1
             && filtre(rx, moins8, 2) == EINVAL,
             "udp : une lecture hors du paquet, une division par zero : jete ; un decalage sous SKF_AD_OFF refuse");
    /* Le hachage du flux : 0 pour une socket jamais connectée ; celui d'une connectée, le
     * même d'un datagramme à l'autre, gardé après la déconnexion, neuf à la connexion. */
    struct sock_filter h[1] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_RXHASH)};
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in u = {.sin_family = AF_UNSPEC};
    connect(c, (void *)&a, sizeof a);
    unsigned hc[3];
    for (int fois = 0; fois < 3; fois++) {
        if (fois == 1)
            connect(c, (void *)&u, sizeof u);
        if (fois == 2)
            connect(c, (void *)&a, sizeof a);
        hc[fois] = hachage_udp(c, rx, fois == 1 ? &a : NULL);
    }
    struct sock_filter bas[2] = {h[0], F(BPF_ALU | BPF_AND | BPF_K, 0xff)};
    verifier(vu(tx, rx, &a, bas, 2) == 0 && hc[0] != 0 && hc[1] == hc[0] && hc[2] != hc[0] && hc[2] != 0,
             "udp : le hachage du flux d'une socket connectee, garde apres la deconnexion, neuf a la connexion");
    /* SO_CNX_ADVICE 1 : un autre (`dst_negative_advice` : `sk_rethink_txhash`) ; 0 n'y touche
     * pas ; une socket jamais connectée garde 0 (mesuré : sonde cnx du lot 6 des soldes). */
    int non = 0, oui = 1;
    setsockopt(c, SOL_SOCKET, SO_CNX_ADVICE, &oui, sizeof oui);
    unsigned conseil = hachage_udp(c, rx, NULL);
    setsockopt(c, SOL_SOCKET, SO_CNX_ADVICE, &non, sizeof non);
    unsigned sans = hachage_udp(c, rx, NULL);
    setsockopt(tx, SOL_SOCKET, SO_CNX_ADVICE, &oui, sizeof oui);
    verifier(conseil != hc[2] && conseil != 0 && sans == conseil && vu(tx, rx, &a, bas, 2) == 0,
             "udp : SO_CNX_ADVICE 1 change le hachage du flux, 0 non ; jamais connectee, il reste 0");
    close(c);
    /* La diffusion par lo (127.255.255.255) : une copie, à nous (PACKET_HOST). La socket
     * qui la reçoit est liée à toute adresse (une liée à 127.0.0.1 ne la recevrait pas),
     * au port que le noyau choisit : un port deviné (celui de rx plus un) peut être tenu
     * par une autre socket, et son bind échouerait sans rien dire. */
    int d = socket(AF_INET, SOCK_DGRAM, 0), un = 1;
    setsockopt(tx, SOL_SOCKET, SO_BROADCAST, &un, sizeof un);
    struct sockaddr_in b = {.sin_family = AF_INET};
    socklen_t bl = sizeof b;
    bind(d, (void *)&b, sizeof b);
    getsockname(d, (void *)&b, &bl);
    b.sin_addr.s_addr = htonl(0x7fffffff);
    struct sock_filter genre[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE), F(BPF_ALU | BPF_ADD | BPF_K, 8 + 5), RET_A};
    filtre(d, genre, 3);
    sendto(tx, "0123456789", 10, 0, (void *)&b, sizeof b);
    attendre_ms(100);
    int n = recv(d, texte, sizeof texte, MSG_DONTWAIT), encore = recv(d, texte, sizeof texte, MSG_DONTWAIT);
    verifier(n == 5 && encore < 0, "udp : la diffusion par lo, une copie, PACKET_HOST");
    close(d), close(rx), close(tx);
    sched_setaffinity(0, sizeof avant, &avant);
}

static void filtres_ping_unix(void)
{
    /* ping : le message ICMP entier, au moins un octet, la charge à 8 ; jeté sans rien
     * compter. */
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    struct sockaddr_in lo = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    char echo[100] = {8};
    unsigned pertes = compteur(p, DROPS);
    long e = snmp("Icmp", "InErrors");
    int r[4], i = 0;
    unsigned ks[] = {0, 1, 5, 100000};
    for (int k = 0; k < 4; k++) {
        filtre_k(p, ks[k]);
        sendto(p, echo, sizeof echo, 0, (void *)&lo, sizeof lo);
        struct pollfd q = {p, POLLIN, 0};
        r[i++] = poll(&q, 1, 200) > 0 ? recv(p, texte, sizeof texte, MSG_DONTWAIT | MSG_TRUNC) : -1;
    }
    struct sock_filter charge[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PAY_OFFSET), F(BPF_ALU | BPF_ADD | BPF_K, 3), RET_A},
        ldb0[3] = {F(BPF_LD | BPF_B | BPF_ABS, 0), F(BPF_ALU | BPF_ADD | BPF_K, 1), RET_A};
    filtre(p, charge, 3);
    sendto(p, echo, sizeof echo, 0, (void *)&lo, sizeof lo);
    struct pollfd q = {p, POLLIN, 0};
    int c = poll(&q, 1, 200) > 0 ? recv(p, texte, sizeof texte, MSG_DONTWAIT | MSG_TRUNC) : -1;
    filtre(p, ldb0, 3);
    sendto(p, echo, sizeof echo, 0, (void *)&lo, sizeof lo);
    int z = poll(&q, 1, 200) > 0 ? recv(p, texte, sizeof texte, MSG_DONTWAIT | MSG_TRUNC) : -1;
    verifier(r[0] == -1 && r[1] == 1 && r[2] == 5 && r[3] == 100 && c == 11 && z == 1 && compteur(p, DROPS) == pertes
             && snmp("Icmp", "InErrors") == e,
             "ping : coupe a un octet au moins, la charge a 8, la reponse (type 0) ; jete sans rien compter");
    close(p);
    /* AF_UNIX : le message, au moins un octet ; jeté, l'envoi réussit ; pas de carte
     * (l'extension rend A tel quel, et le programme s'arrête) ; un flux n'a pas de filtre. */
    for (int sorte = 0; sorte < 3; sorte++) {
        int v[2];
        socketpair(AF_UNIX, sorte == 0 ? SOCK_DGRAM : sorte == 1 ? SOCK_SEQPACKET : SOCK_STREAM, 0, v);
        filtre_k(v[0], 0);
        int envoye = send(v[1], "abcdefghij", 10, 0);
        struct pollfd w = {v[0], POLLIN, 0};
        int recu = poll(&w, 1, 100) > 0 ? recv(v[0], texte, sizeof texte, MSG_DONTWAIT) : -1;
        struct sock_filter sans_carte[4] = {F(BPF_LD | BPF_IMM, 4), F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_IFINDEX),
                                            F(BPF_LD | BPF_IMM, 0), RET_A};
        filtre(v[0], sans_carte, 4);
        send(v[1], "abcdefghij", 10, 0);
        int quatre = poll(&w, 1, 100) > 0 ? recv(v[0], texte, sizeof texte, MSG_DONTWAIT) : -1;
        struct sock_filter net[2] = {F(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF + 2), RET_A};
        filtre(v[0], net, 2);
        send(v[1], "ab\007defghij", 10, 0);
        int sept = poll(&w, 1, 100) > 0 ? recv(v[0], texte, sizeof texte, MSG_DONTWAIT) : -1;
        if (sorte < 2)
            verifier(envoye == 10 && recu == -1 && quatre == 4 && sept == 7,
                     sorte == 0 ? "unix datagrammes : jete sans erreur d'envoi, A rendu sans carte, SKF_NET_OFF au message"
                                : "unix paquets : jete sans erreur d'envoi, A rendu sans carte, SKF_NET_OFF au message");
        else
            verifier(envoye == 10 && recu == 10, "unix flux : pas de filtre");
        close(v[0]), close(v[1]);
    }
}

static void filtres_tcp(void)
{
    /* Une écoute qui jette tout : le SYN, une perte pour elle ; puis la fille hérite du
     * filtre de son écoute (relu, compté) et de son verrou. */
    struct sockaddr_in t;
    int un = 1;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    lier_tcp(l, &t), listen(l, 4);
    filtre_k(l, 0);
    int c = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    connect(c, (void *)&t, sizeof t);
    struct pollfd p = {c, POLLOUT, 0};
    verifier(poll(&p, 1, 300) == 0 && compteur(l, DROPS) == 1, "tcp : une ecoute filtree jette le SYN (une perte)");
    close(c);
    filtre_k(l, 0xffffffff);
    setsockopt(l, SOL_SOCKET, SO_LOCK_FILTER, &un, sizeof un);
    c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&t, sizeof t);
    int f = accept(l, NULL, NULL);
    socklen_t n = 0;
    verifier(getsockopt(f, SOL_SOCKET, SO_GET_FILTER, NULL, &n) == 0 && n == 1 && lire(f, SO_LOCK_FILTER) == 1
             && compteur(f, OPTMEM) == 136,
             "tcp : la fille herite du filtre de son ecoute, compte, et de son verrou");
    close(f), close(c), close(l);
    /* Une connexion : jeté, une perte ; coupé à trois octets de charge, le reste revient par
     * les retransmissions, coupées à leur tour. */
    int d;
    tcp_connectee(&c, &d);
    filtre_k(d, 0);
    send(c, "abcdefghij", 10, 0);
    attendre_ms(100);
    int jete = recv(d, texte, sizeof texte, MSG_DONTWAIT) == -1 && errno == EAGAIN && compteur(d, DROPS) >= 1;
    struct sock_filter trois[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PAY_OFFSET), F(BPF_ALU | BPF_ADD | BPF_K, 3), RET_A};
    filtre(d, trois, 3);
    char recu[16] = {0};
    int tout = 0;
    for (int essai = 0; essai < 60 && tout < 10; essai++) {
        struct pollfd q = {d, POLLIN, 0};
        if (poll(&q, 1, 100) > 0) {
            int r = recv(d, recu + tout, sizeof recu - 1 - tout, MSG_DONTWAIT);
            tout += r > 0 ? r : 0;
        }
    }
    verifier(jete && tout == 10 && !strcmp(recu, "abcdefghij"),
             "tcp : une connexion filtree jette (une perte), ou coupe a trois octets : tout arrive, dans l'ordre");
    close(c), close(d);
}

/* Garde, d'un segment TCP, l'octet `o` du hachage de son flux plus un octets de charge
 * (SKF_AD_RXHASH : lo garde celui de l'émetteur ; SKF_AD_PAY_OFFSET : le début de la charge). */
static void filtre_octet_du_hachage(int d, int o)
{
    struct sock_filter f[8] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_RXHASH), F(BPF_ALU | BPF_RSH | BPF_K, 8 * o),
                               F(BPF_ALU | BPF_AND | BPF_K, 0xff), F(BPF_ALU | BPF_ADD | BPF_K, 1), F(BPF_MISC | BPF_TAX, 0),
                               F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PAY_OFFSET), F(BPF_ALU | BPF_ADD | BPF_X, 0), RET_A};
    filtre(d, f, 8);
}

/* Le hachage du flux des segments de `c`, lu par le filtre de `d` (connectées) : un envoi de
 * 1100 octets (plus que quatre octets du hachage plus un) ; chaque octet coupe le segment, puis
 * chacune de ses retransmissions, à sa valeur plus un ; le filtre enlevé, le reste arrive. Un
 * peu plus de quatre RTO (200 ms sur lo) : sous SO_TXREHASH 0 seulement, sans quoi chacun
 * change le hachage (`tcp_write_timeout`). 0 si quelque chose manque (un hachage ne l'est
 * jamais). */
static unsigned hachage_tcp(int c, int d)
{
    static char b[1100];
    unsigned h = 0;
    int lu = 0, ok = 1;
    for (int o = 0; o < 4 && ok; o++) {
        filtre_octet_du_hachage(d, o);
        if (o == 0)
            ok = send(c, b, sizeof b, 0) == (long)sizeof b;
        struct pollfd q = {d, POLLIN, 0};
        int r = poll(&q, 1, 3000) == 1 ? recv(d, b, sizeof b, MSG_DONTWAIT) : -1;
        ok &= r >= 1 && r <= 256;
        h |= (unsigned)(r - 1) << (8 * o);
        lu += r > 0 ? r : 0;
    }
    int rien = 0;
    setsockopt(d, SOL_SOCKET, SO_DETACH_FILTER, &rien, sizeof rien);
    while (ok && lu < (int)sizeof b) {
        struct pollfd q = {d, POLLIN, 0};
        int r = poll(&q, 1, 3000) == 1 ? recv(d, b, sizeof b, MSG_DONTWAIT) : -1;
        ok = r > 0;
        lu += r > 0 ? r : 0;
    }
    return ok && lu == (int)sizeof b ? h : 0;
}

/* Un envoi de `c` passe-t-il le filtre de `d` qui ne garde que les segments dont le hachage
 * vaut `h` (`egal`), ou ceux dont il ne le vaut pas ? Jeté, la retransmission passe une fois
 * le filtre enlevé. */
static int passe_si(int c, int d, unsigned h, int egal)
{
    struct sock_filter f[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_RXHASH),
                               {BPF_JMP | BPF_JEQ | BPF_K, egal ? 0 : 1, egal ? 1 : 0, h}, F(BPF_RET | BPF_K, 0xffff)};
    struct sock_filter g[4] = {f[0], f[1], f[2], F(BPF_RET | BPF_K, 0)};
    filtre(d, g, 4);
    send(c, "0123456789", 10, 0);
    struct pollfd q = {d, POLLIN, 0};
    int passe = poll(&q, 1, 300) == 1 && recv(d, texte, sizeof texte, MSG_DONTWAIT) == 10;
    int rien = 0;
    setsockopt(d, SOL_SOCKET, SO_DETACH_FILTER, &rien, sizeof rien);
    if (!passe) {
        struct pollfd r = {d, POLLIN, 0};
        if (poll(&r, 1, 3000) == 1)
            recv(d, texte, sizeof texte, MSG_DONTWAIT);
    }
    return passe;
}

/* SO_CNX_ADVICE 1 d'une connexion TCP : un autre hachage du flux (`sk_rethink_txhash`), sauf
 * SO_TXREHASH 0 (mesuré : sonde cnx du lot 6 des soldes). Le hachage lu sous SO_TXREHASH 0 ;
 * tout acquitté ensuite, plus de RTO : l'envoi qui suit chaque conseil part avec le hachage
 * que le conseil a laissé. */
static void conseil_tcp(void)
{
    int c, d, oui = 1;
    tcp_connectee(&c, &d);
    poser(c, SO_TXREHASH, 0);
    unsigned h = hachage_tcp(c, d);
    setsockopt(c, SOL_SOCKET, SO_CNX_ADVICE, &oui, sizeof oui);
    int garde = passe_si(c, d, h, 1);
    poser(c, SO_TXREHASH, 1);
    setsockopt(c, SOL_SOCKET, SO_CNX_ADVICE, &oui, sizeof oui);
    int change = passe_si(c, d, h, 0);
    verifier(h != 0 && garde && change, "tcp : SO_CNX_ADVICE 1 change le hachage du flux, sauf SO_TXREHASH 0");
    close(c), close(d);
}

/* Les groupes SO_REUSEPORT (mesurés : sonde c10f du lot 6 des soldes). */
#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif
#ifndef SO_DETACH_REUSEPORT_BPF
#define SO_DETACH_REUSEPORT_BPF 68
#endif
#define LOCALE 0x7f000001u

static int rp_attacher(int s, struct sock_filter *f, unsigned short n)
{
    struct sock_fprog p = {n, f};
    return erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &p, sizeof p));
}

/* Le programme « ret k » : l'index k. */
static int rp_index(int s, unsigned k)
{
    struct sock_filter f[1] = {F(BPF_RET | BPF_K, k)};
    return rp_attacher(s, f, 1);
}

static int rp_detacher(int s)
{
    int v = 0;
    return erreur(setsockopt(s, SOL_SOCKET, SO_DETACH_REUSEPORT_BPF, &v, sizeof v));
}

static int rp_lier(int s, unsigned a, int port)
{
    struct sockaddr_in x = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(a)};
    return erreur(bind(s, (struct sockaddr *)&x, sizeof x));
}

static int rp_port(int s)
{
    struct sockaddr_in x;
    socklen_t l = sizeof x;
    getsockname(s, (struct sockaddr *)&x, &l);
    return ntohs(x.sin_port);
}

/* Une socket UDP (SO_REUSEPORT, et SO_REUSEADDR si `ra`) liée à a:port ; -1 si refusé. */
static int rp_udp(unsigned a, int port, int rp, int ra)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    poser(s, SO_REUSEPORT, rp);
    poser(s, SO_REUSEADDR, ra);
    if (rp_lier(s, a, port)) {
        close(s);
        return -1;
    }
    return s;
}

/* Un port libre de 127.0.0.1 (choisi ensuite : un port éphémère se rend). */
static int rp_libre(void)
{
    int s = rp_udp(LOCALE, 0, 0, 0), p = rp_port(s);
    close(s);
    return p;
}

/* Un port libre de 127.0.0.1 pour TCP, choisi par TCP lui-même (le port 0 d'une socket
 * TCP, qui le rend à sa fermeture : ni écoute, ni connexion, pas de TIME_WAIT). Pas
 * celui de `rp_libre` : libre pour UDP, il peut être celui d'une connexion TCP en
 * TIME_WAIT (les cas précédents en laissent des centaines, pour 60 s), et une écoute
 * qui s'y lie échoue (EADDRINUSE) ; mesuré, 500 TIME_WAIT sur lo : 35 ports d'UDP sur
 * 2000 refusés, aucun de TCP (`inet_csk_find_open_port` n'en choisit pas un que tient
 * une connexion). Écarté : la première écoute liée au port 0, et les autres au sien
 * (sans `SOCK_BINDPORT_LOCK`, l'écoute arrêtée par shutdown rend son port, et
 * `listen` l'en lierait à un autre). */
static int rp_libre_tcp(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0), p = rp_lier(s, LOCALE, 0) ? -1 : rp_port(s);
    close(s);
    return p;
}

/* Un datagramme d'une socket neuve (un flux neuf) vers a:port : l'index de celle de
 * `s` qui l'a, livré par lo quand sendto revient (-1 : aucune). */
static int rp_qui(int *s, int n, unsigned a, int port)
{
    char m[20] = {3}, b[sizeof m];
    struct sockaddr_in x = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(a)};
    int tx = socket(AF_INET, SOCK_DGRAM, 0), r = -1;
    sendto(tx, m, sizeof m, 0, (struct sockaddr *)&x, sizeof x);
    close(tx);
    for (int i = 0; i < n; i++)
        if (s[i] >= 0 && recv(s[i], b, sizeof b, MSG_DONTWAIT) >= 0 && r < 0)
            r = i;
    return r;
}

/* `fois` flux neufs : chacune de `s` en a-t-elle eu au moins un ? Sinon, -1 ; la seule qui
 * en a eu (si une seule), son index. */
static int rp_repartis(int *s, int n, unsigned a, int port, int fois)
{
    int vus[8] = {0}, nombre = 0, seule = -1;
    for (int i = 0; i < fois; i++) {
        int r = rp_qui(s, n, a, port);
        if (r >= 0)
            vus[r]++;
    }
    for (int i = 0; i < n; i++)
        if (vus[i]) {
            nombre++;
            seule = i;
        }
    return nombre == n ? n : nombre == 1 ? seule : -1;
}

static void rp_processeur(int c)
{
    cpu_set_t e;
    CPU_ZERO(&e);
    CPU_SET(c, &e);
    sched_setaffinity(0, sizeof e, &e);
}

static void reuseport_options(void)
{
    struct sock_fprog p = {1, NULL};
    int s = socket(AF_INET, SOCK_DGRAM, 0), v = 0;
    verifier(rp_index(s, 0) == EINVAL && rp_detacher(s) == EINVAL, "SO_REUSEPORT : sans lui, EINVAL pour poser et retirer un programme");
    poser(s, SO_REUSEPORT, 1);
    verifier(rp_detacher(s) == ENOENT && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &p, 8)) == EINVAL
             && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &p, sizeof p)) == EINVAL
             && erreur(setsockopt(s, SOL_SOCKET, SO_DETACH_REUSEPORT_BPF, &v, 2)) == EINVAL,
             "SO_REUSEPORT : sans groupe ENOENT ; une sock_fprog de 16 octets, un programme, un entier");
    verifier(rp_index(s, 0) == 0 && rp_index(s, 1) == 0 && rp_detacher(s) == 0 && rp_detacher(s) == ENOENT && rp_index(s, 2) == 0,
             "SO_REUSEPORT : non liee, un groupe a elle ; poser, remplacer, retirer, ENOENT");
    verifier(rp_lier(s, LOCALE, 0) == 0 && rp_index(s, 0) == 0 && rp_detacher(s) == 0,
             "SO_REUSEPORT : son groupe garde par bind");
    close(s);
    s = rp_udp(LOCALE, 0, 0, 0);
    poser(s, SO_REUSEPORT, 1);
    verifier(rp_index(s, 0) == EINVAL && rp_detacher(s) == ENOENT, "SO_REUSEPORT : liee sans groupe (pose apres bind), EINVAL");
    verifier(poser(s, SO_LOCK_FILTER, 1) == 0 && rp_index(s, 0) == EPERM && rp_detacher(s) == ENOENT,
             "SO_REUSEPORT : SO_LOCK_FILTER, EPERM pour poser (pas pour retirer)");
    close(s);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    int fd = 999;
    verifier(erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &p, 8)) == EINVAL
             && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &fd, 4)) == EBADF
             && erreur(setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &s, 4)) == EINVAL,
             "SO_ATTACH_REUSEPORT_EBPF : EINVAL, EBADF, EINVAL");
    socklen_t l = sizeof v;
    verifier(erreur(getsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &v, &l)) == ENOPROTOOPT
             && erreur(getsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &v, &l)) == ENOPROTOOPT
             && erreur(getsockopt(s, SOL_SOCKET, SO_DETACH_REUSEPORT_BPF, &v, &l)) == ENOPROTOOPT,
             "SO_ATTACH_REUSEPORT : rien a relire (ENOPROTOOPT)");
    close(s);
    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    verifier(rp_index(s, 0) == EINVAL && rp_detacher(s) == EINVAL, "SO_REUSEPORT : AF_UNIX, EINVAL");
    close(s);
    /* TCP : liée (pas encore dans la table), un groupe ; une écoute ou une connexion sans
     * groupe, EINVAL ; celui d'avant `connect` reste. */
    int t = socket(AF_INET, SOCK_STREAM, 0);
    poser(t, SO_REUSEPORT, 1);
    verifier(rp_index(t, 0) == 0 && rp_lier(t, LOCALE, 0) == 0 && rp_index(t, 1) == 0 && listen(t, 4) == 0
             && rp_index(t, 2) == 0 && rp_detacher(t) == 0 && rp_detacher(t) == ENOENT,
             "SO_REUSEPORT tcp : neuve, liee, puis ecoute : son groupe");
    int e = socket(AF_INET, SOCK_STREAM, 0);
    rp_lier(e, LOCALE, 0);
    listen(e, 4);
    poser(e, SO_REUSEPORT, 1);
    verifier(rp_index(e, 0) == EINVAL && rp_detacher(e) == ENOENT, "SO_REUSEPORT tcp : une ecoute sans groupe, EINVAL");
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(rp_port(e)), .sin_addr.s_addr = htonl(LOCALE)};
    int c = socket(AF_INET, SOCK_STREAM, 0), d = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, sizeof a);
    poser(c, SO_REUSEPORT, 1);
    poser(d, SO_REUSEPORT, 1);
    rp_index(d, 0);
    connect(d, (struct sockaddr *)&a, sizeof a);
    verifier(rp_index(c, 0) == EINVAL && rp_detacher(c) == ENOENT && rp_detacher(d) == 0 && rp_detacher(d) == ENOENT
             && rp_index(d, 0) == 0,
             "SO_REUSEPORT tcp : une connexion sans groupe, EINVAL ; avec celui d'avant connect, garde");
    /* Un programme posé avant `shutdown` : ENOENT ne vient alors que d'une écoute sortie de
     * son groupe (restée, elle le retirerait : 0). Sans lui, ENOENT dans les deux cas. */
    verifier(rp_index(t, 3) == 0 && shutdown(t, SHUT_RDWR) == 0 && rp_detacher(t) == ENOENT,
             "SO_REUSEPORT tcp : une ecoute arretee quitte son groupe");
    close(t);
    close(e);
    close(c);
    close(d);
}

/* Deux sockets UDP liées au même port (SO_REUSEADDR), connectées au même émetteur : la plus
 * récemment connectée reçoit (`udp4_lib_lookup4`), dans les deux ordres ; une connectée
 * ailleurs d'abord, reconnectée ensuite, non : son premier quadruplet reste le sien (mesuré :
 * sondes r4a et r4b de la relecture du lot 6 des soldes). */
static void recherche_des_connectees(void)
{
    /* Les deux `connect` vers l'émetteur, dans l'ordre, et celle qui reçoit : la seconde liée
     * puis la première ; l'inverse ; la seconde connectée ailleurs avant tout. */
    static const int ordre[3][2] = {{1, 0}, {0, 1}, {0, 1}}, recoit[3] = {0, 1, 0};
    int ok = 1;
    for (int cas = 0; cas < 3; cas++) {
        int s[2], e = rp_udp(LOCALE, 0, 0, 0), ailleurs = rp_udp(LOCALE, 0, 0, 0);
        s[0] = rp_udp(LOCALE, 0, 0, 1);
        s[1] = rp_udp(LOCALE, rp_port(s[0]), 0, 1);
        struct sockaddr_in q = {.sin_family = AF_INET, .sin_port = htons(rp_port(e)), .sin_addr.s_addr = htonl(LOCALE)},
                           q2 = {.sin_family = AF_INET, .sin_port = htons(rp_port(ailleurs)), .sin_addr.s_addr = htonl(LOCALE)},
                           p = {.sin_family = AF_INET, .sin_port = htons(rp_port(s[0])), .sin_addr.s_addr = htonl(LOCALE)};
        if (cas == 2)
            connect(s[1], (void *)&q2, sizeof q2);
        connect(s[ordre[cas][0]], (void *)&q, sizeof q);
        connect(s[ordre[cas][1]], (void *)&q, sizeof q);
        sendto(e, "x", 1, 0, (void *)&p, sizeof p);
        attendre_ms(20);
        char o[4];
        int r[2] = {recv(s[0], o, sizeof o, MSG_DONTWAIT), recv(s[1], o, sizeof o, MSG_DONTWAIT)};
        ok &= r[recoit[cas]] == 1 && r[1 - recoit[cas]] < 0;
        close(s[0]), close(s[1]), close(e), close(ailleurs);
    }
    verifier(ok, "udp : deux connectees au meme emetteur, la plus recemment connectee recoit ; une reconnectee, non");
}

/* Le compte des membres qui disent un processeur (`incoming_cpu`) d'un groupe UDP : s2, liée
 * et connectée, entre dans le groupe que fait s1 en se liant après elle (sans processeur, pas
 * comptée) ; elle reçoit, connectée, ce qui lui donne le processeur 1 hors du compte ; puis
 * AF_UNSPEC l'y laisse (adresse et port de `bind`). Le compte nul, le hachage répartit les
 * envois de 64 ports entre les deux, même cherchés depuis le processeur 1 (mesuré : sonde r4c
 * de la relecture du lot 6 des soldes). */
static void groupe_processeur_non_compte(void)
{
    cpu_set_t avant, un;
    sched_getaffinity(0, sizeof avant, &avant);
    CPU_ZERO(&un);
    CPU_SET(1, &un);
    sched_setaffinity(0, sizeof un, &un);
    /* Un port nommé (SOCK_BINDPORT_LOCK) : AF_UNSPEC rendrait un port éphémère, et le groupe. */
    int s2 = rp_udp(LOCALE, rp_libre(), 1, 0), c = rp_udp(LOCALE, 0, 0, 0);
    struct sockaddr_in q = {.sin_family = AF_INET, .sin_port = htons(rp_port(c)), .sin_addr.s_addr = htonl(LOCALE)},
                       p = {.sin_family = AF_INET, .sin_port = htons(rp_port(s2)), .sin_addr.s_addr = htonl(LOCALE)};
    connect(s2, (void *)&q, sizeof q);
    int s1 = rp_udp(LOCALE, rp_port(s2), 1, 0);
    sendto(c, "x", 1, 0, (void *)&p, sizeof p);
    attendre_ms(20);
    char o[4];
    int recu = recv(s2, o, sizeof o, MSG_DONTWAIT), cpu2 = lire(s2, SO_INCOMING_CPU), cpu1 = lire(s1, SO_INCOMING_CPU);
    struct sockaddr u = {.sa_family = AF_UNSPEC};
    connect(s2, &u, sizeof u);
    int n1 = 0, n2 = 0;
    for (int k = 0; k < 64; k++) {
        int e = rp_udp(LOCALE, 0, 0, 0);
        sendto(e, "y", 1, 0, (void *)&p, sizeof p);
        close(e);
    }
    attendre_ms(50);
    while (recv(s1, o, sizeof o, MSG_DONTWAIT) == 1)
        n1++;
    while (recv(s2, o, sizeof o, MSG_DONTWAIT) == 1)
        n2++;
    verifier(recu == 1 && cpu2 == 1 && cpu1 == -1 && n1 > 0 && n2 > 0 && n1 + n2 == 64,
             "SO_REUSEPORT udp : un processeur que la reception donne ne compte pas dans le groupe (le hachage)");
    close(s1), close(s2), close(c);
    sched_setaffinity(0, sizeof avant, &avant);
}

static void reuseport_udp(void)
{
    /* L'ordre des `bind` ; le programme posé avant `bind` par la première, ou par
     * n'importe laquelle ensuite ; trop grand, le hachage. */
    int s[4], ok = 1;
    s[0] = socket(AF_INET, SOCK_DGRAM, 0);
    poser(s[0], SO_REUSEPORT, 1);
    rp_index(s[0], 1);
    rp_lier(s[0], LOCALE, 0);
    int port = rp_port(s[0]);
    for (int i = 1; i < 4; i++)
        s[i] = rp_udp(LOCALE, port, 1, 0);
    ok &= rp_qui(s, 4, LOCALE, port) == 1;
    for (int k = 0; k < 4; k++)
        ok &= rp_index(s[3], k) == 0 && rp_qui(s, 4, LOCALE, port) == k;
    verifier(ok, "SO_REUSEPORT udp : l'index du programme, dans l'ordre des bind");
    rp_index(s[0], 7);
    verifier(rp_repartis(s, 4, LOCALE, port, 64) == 4, "SO_REUSEPORT udp : un index trop grand, le hachage");
    rp_detacher(s[0]);
    char m[20] = {3}, b[sizeof m];
    struct sockaddr_in x = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(LOCALE)};
    int tx = socket(AF_INET, SOCK_DGRAM, 0), premiere = -1;
    ok = 1;
    for (int i = 0; i < 8; i++) {
        sendto(tx, m, sizeof m, 0, (struct sockaddr *)&x, sizeof x);
        for (int k = 0; k < 4; k++)
            if (recv(s[k], b, sizeof b, MSG_DONTWAIT) >= 0) {
                ok &= premiere < 0 || premiere == k;
                premiere = k;
            }
    }
    close(tx);
    verifier(ok && rp_repartis(s, 4, LOCALE, port, 64) == 4, "SO_REUSEPORT udp : sans programme, les flux repartis, chacun a sa socket");
    /* Ce que voit le programme : la charge après l'en-tête d'UDP, l'en-tête IP et celui
     * de lo, la longueur, la charge à la fin plus 8, le processeur. */
    struct sock_filter premier[2] = {F(BPF_LD | BPF_B | BPF_ABS, 0), RET_A},
                       reseau[3] = {F(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF + 9), F(BPF_ALU | BPF_SUB | BPF_K, 15), RET_A},
                       liaison[3] = {F(BPF_LD | BPF_H | BPF_ABS, SKF_LL_OFF + 12), F(BPF_ALU | BPF_SUB | BPF_K, 0x7fe), RET_A},
                       longueur[3] = {F(BPF_LD | BPF_W | BPF_LEN, 0), F(BPF_ALU | BPF_SUB | BPF_K, 17), RET_A},
                       charge[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PAY_OFFSET), F(BPF_ALU | BPF_SUB | BPF_K, 26), RET_A},
                       cpu[2] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_CPU), RET_A};
    verifier(rp_attacher(s[0], premier, 2) == 0 && rp_qui(s, 4, LOCALE, port) == 3 && rp_attacher(s[0], reseau, 3) == 0
             && rp_qui(s, 4, LOCALE, port) == 2 && rp_attacher(s[0], liaison, 3) == 0 && rp_qui(s, 4, LOCALE, port) == 2
             && rp_attacher(s[0], longueur, 3) == 0 && rp_qui(s, 4, LOCALE, port) == 3
             && rp_attacher(s[0], charge, 3) == 0 && rp_qui(s, 4, LOCALE, port) == 2,
             "SO_REUSEPORT udp : le programme voit la charge, les en-tetes, la longueur, SKF_AD_PAY_OFFSET");
    ok = rp_attacher(s[0], cpu, 2) == 0;
    for (int c = 0; c < 4; c++) {
        rp_processeur(c);
        ok &= rp_qui(s, 4, LOCALE, port) == c;
    }
    rp_processeur(0);
    verifier(ok, "SO_REUSEPORT udp : le programme voit le processeur");
    /* SO_INCOMING_CPU : la membre du processeur qui cherche ; aucune, le hachage. */
    rp_detacher(s[0]);
    poser(s[2], SO_INCOMING_CPU, 1);
    rp_processeur(1);
    int depuis_1 = rp_repartis(s, 4, LOCALE, port, 16);
    rp_processeur(3);
    int depuis_3 = rp_repartis(s, 4, LOCALE, port, 64);
    rp_processeur(0);
    poser(s[2], SO_INCOMING_CPU, -1);
    verifier(depuis_1 == 2 && depuis_3 == 4, "SO_REUSEPORT udp : SO_INCOMING_CPU, la membre de ce processeur");
    /* La 1 part : la dernière prend sa place. Puis la 0 (liée à 127.0.0.1) se connecte :
     * elle quitte le groupe. */
    close(s[1]);
    s[1] = -1;
    verifier(rp_index(s[2], 1) == 0 && rp_qui(s, 4, LOCALE, port) == 3 && rp_index(s[2], 2) == 0 && rp_qui(s, 4, LOCALE, port) == 2,
             "SO_REUSEPORT udp : une membre partie, la derniere prend sa place");
    struct sockaddr_in ailleurs = {.sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(LOCALE)};
    connect(s[0], (struct sockaddr *)&ailleurs, sizeof ailleurs);
    verifier(rp_index(s[2], 0) == 0 && rp_qui(s, 4, LOCALE, port) == 2 && rp_index(s[0], 0) == EINVAL,
             "SO_REUSEPORT udp : une membre qui se connecte quitte le groupe");
    for (int i = 0; i < 4; i++)
        if (s[i] >= 0)
            close(s[i]);
    /* AF_UNSPEC d'une membre jamais connectée : port choisi, liée à 0.0.0.0, elle quitte
     * le groupe et garde son port ; liée à 127.0.0.1, elle reste ; port éphémère, elle le
     * rend. Et SO_BINDTODEVICE, qui la ré-hache : elle quitte. Liée à lo avant `bind`,
     * AF_UNSPEC oublie l'interface sans la ré-hacher (`__udp_disconnect`) : elle reste. */
    struct sockaddr_in rien = {.sin_family = AF_UNSPEC};
    const char *cas[] = {"AF_UNSPEC, 0.0.0.0, port choisi : quitte, garde son port", "AF_UNSPEC, 127.0.0.1, port choisi : reste",
                         "AF_UNSPEC, port ephemere : rend son port", "SO_BINDTODEVICE : quitte",
                         "AF_UNSPEC, 127.0.0.1, port choisi, liee a lo : reste, sans interface"};
    for (int k = 0; k < 5; k++) {
        int d[3], adresse = k == 0 ? 0 : LOCALE, reste = k == 1 || k == 4;
        for (int i = 0; i < 3; i++) {
            d[i] = socket(AF_INET, SOCK_DGRAM, 0);
            poser(d[i], SO_REUSEPORT, 1);
            if (k == 4)
                setsockopt(d[i], SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
            rp_lier(d[i], adresse, i > 0 ? port : k == 2 ? 0 : rp_libre());
            port = rp_port(d[0]);
        }
        rp_index(d[1], 0);
        if (k == 3)
            setsockopt(d[0], SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
        else
            connect(d[0], (struct sockaddr *)&rien, sizeof rien);
        int garde = rp_port(d[0]) == port, qui = rp_qui(d, 3, LOCALE, port);
        char nom[16];
        socklen_t n = sizeof nom;
        getsockopt(d[0], SOL_SOCKET, SO_BINDTODEVICE, nom, &n);
        verifier(qui == (reste ? 0 : 2) && garde == (k != 2) && rp_detacher(d[0]) == (reste ? 0 : ENOENT)
                 && n == (k == 3 ? 3 : 0),
                 dire("SO_REUSEPORT udp : %s", cas[k]));
        for (int i = 0; i < 3; i++)
            close(d[i]);
    }
    /* La recherche : une socket liée à lo, plus ancienne que le groupe, ne reçoit rien ;
     * une membre connectée un jour (has_conns), et elle reçoit tout. */
    int r[3];
    r[0] = socket(AF_INET, SOCK_DGRAM, 0);
    poser(r[0], SO_REUSEPORT, 1);
    setsockopt(r[0], SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
    rp_lier(r[0], LOCALE, 0);
    port = rp_port(r[0]);
    r[1] = rp_udp(LOCALE, port, 1, 0);
    r[2] = rp_udp(LOCALE, port, 1, 0);
    int avant = rp_repartis(r, 3, LOCALE, port, 32);
    connect(r[1], (struct sockaddr *)&ailleurs, sizeof ailleurs);
    int apres = rp_repartis(r, 3, LOCALE, port, 16);
    verifier(avant == -1 && apres == 0, "SO_REUSEPORT udp : un groupe en tete l'emporte sur une liee a lo, sauf has_conns");
    for (int i = 0; i < 3; i++)
        close(r[i]);
    /* SO_REUSEADDR seul : la plus récente. */
    int e[2];
    e[0] = rp_udp(LOCALE, 0, 0, 1);
    port = rp_port(e[0]);
    e[1] = rp_udp(LOCALE, port, 0, 1);
    verifier(rp_qui(e, 2, LOCALE, port) == 1, "SO_REUSEADDR udp : la plus recemment liee recoit");
    close(e[0]);
    close(e[1]);
    /* Former un groupe : avec un groupe à elle, pas par SO_REUSEPORT (EADDRINUSE) ; par
     * SO_REUSEADDR, si, et son programme est perdu ; SO_REUSEPORT posé après `bind`. */
    int f[2];
    f[0] = rp_udp(LOCALE, 0, 1, 0);
    port = rp_port(f[0]);
    f[1] = socket(AF_INET, SOCK_DGRAM, 0);
    poser(f[1], SO_REUSEPORT, 1);
    rp_index(f[1], 0);
    verifier(rp_lier(f[1], LOCALE, port) == EADDRINUSE && rp_lier(f[1], LOCALE, 0) == 0,
             "SO_REUSEPORT udp : un groupe a elle, pas le port d'un autre groupe");
    close(f[0]);
    close(f[1]);
    f[0] = rp_udp(LOCALE, 0, 1, 1);
    port = rp_port(f[0]);
    rp_index(f[0], 0);
    f[1] = socket(AF_INET, SOCK_DGRAM, 0);
    poser(f[1], SO_REUSEPORT, 1);
    poser(f[1], SO_REUSEADDR, 1);
    rp_index(f[1], 1);
    verifier(rp_lier(f[1], LOCALE, port) == 0 && rp_qui(f, 2, LOCALE, port) == 0 && rp_detacher(f[1]) == 0 && rp_detacher(f[0]) == ENOENT,
             "SO_REUSEPORT udp : SO_REUSEADDR, le groupe de l'autre et son programme");
    close(f[0]);
    close(f[1]);
    f[0] = rp_udp(LOCALE, 0, 0, 0);
    port = rp_port(f[0]);
    poser(f[0], SO_REUSEPORT, 1);
    f[1] = rp_udp(LOCALE, port, 1, 0);
    verifier(f[1] >= 0 && rp_index(f[0], 1) == 0 && rp_qui(f, 2, LOCALE, port) == 1,
             "SO_REUSEPORT udp : pose apres bind, un groupe fait quand une autre arrive");
    close(f[0]);
    close(f[1]);
}

/* Une écoute TCP de 127.0.0.1:port avec SO_REUSEPORT, sans attendre à accept. */
static int rp_ecoute(int port, const char *interface)
{
    int l = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    poser(l, SO_REUSEPORT, 1);
    if (interface)
        setsockopt(l, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1);
    if (rp_lier(l, LOCALE, port) || listen(l, 64)) {
        close(l);
        return -1;
    }
    return l;
}

/* Une connexion à 127.0.0.1:port : l'index de l'écoute de `l` qui l'accepte. */
static int rp_accepte(int *l, int n, int port)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(LOCALE)};
    int c = socket(AF_INET, SOCK_STREAM, 0), r = -1;
    connect(c, (struct sockaddr *)&a, sizeof a);
    for (int i = 0; i < n; i++) {
        int f = l[i] < 0 ? -1 : accept(l[i], NULL, NULL);
        if (f >= 0) {
            close(f);
            if (r < 0)
                r = i;
        }
    }
    close(c);
    return r;
}

static void reuseport_tcp(void)
{
    int l[3], ok = 1, port = rp_libre_tcp();
    for (int i = 0; i < 3; i++)
        l[i] = rp_ecoute(port, NULL);
    for (int k = 0; k < 3; k++)
        ok &= rp_index(l[1], k) == 0 && rp_accepte(l, 3, port) == k;
    verifier(ok, "SO_REUSEPORT tcp : l'index du programme, dans l'ordre des listen");
    struct sock_filter charge[3] = {F(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_PAY_OFFSET), F(BPF_ALU | BPF_ADD | BPF_K, 1), RET_A},
                       longueur[3] = {F(BPF_LD | BPF_W | BPF_LEN, 0), F(BPF_ALU | BPF_ADD | BPF_K, 2), RET_A};
    verifier(rp_attacher(l[0], charge, 3) == 0 && rp_accepte(l, 3, port) == 1 && rp_attacher(l[0], longueur, 3) == 0
             && rp_accepte(l, 3, port) == 2,
             "SO_REUSEPORT tcp : un SYN, sans charge, vu par le programme");
    rp_detacher(l[0]);
    int vus[3] = {0};
    for (int i = 0; i < 48; i++) {
        int r = rp_accepte(l, 3, port);
        if (r >= 0)
            vus[r]++;
    }
    verifier(vus[0] && vus[1] && vus[2], "SO_REUSEPORT tcp : sans programme, les connexions reparties");
    rp_index(l[0], 1);
    close(l[0]);
    l[0] = -1;
    verifier(rp_accepte(l, 3, port) == 1 && rp_index(l[1], 0) == 0 && rp_accepte(l, 3, port) == 2,
             "SO_REUSEPORT tcp : une ecoute fermee, la derniere prend sa place");
    int m = socket(AF_INET, SOCK_STREAM, 0);
    poser(m, SO_REUSEPORT, 1);
    verifier(rp_lier(m, LOCALE, port) == 0 && rp_index(m, 0) == 0 && erreur(listen(m, 4)) == EADDRINUSE,
             "SO_REUSEPORT tcp : un groupe a elle, pas d'ecoute sur le port d'un autre groupe");
    close(m);
    m = socket(AF_INET, SOCK_STREAM, 0);
    poser(m, SO_REUSEPORT, 1);
    rp_index(m, 0);
    verifier(rp_lier(m, LOCALE, port) == EADDRINUSE, "SO_REUSEPORT tcp : un groupe avant bind, pas le port d'un autre groupe");
    close(m);
    /* Le groupe est [l2, l1]. L'index 1 : seule une l2 restée dans le groupe rend l1 ;
     * sortie, l2 l'emporterait seule (la plus récente, et liée à lo : mieux notée). */
    rp_index(l[1], 1);
    setsockopt(l[2], SOL_SOCKET, SO_BINDTODEVICE, "lo", 3);
    verifier(rp_accepte(l, 3, port) == 1, "SO_REUSEPORT tcp : SO_BINDTODEVICE ne fait pas quitter le groupe");
    /* L'index 0 : une l2 restée dans le groupe serait choisie sans écouter. */
    rp_index(l[1], 0);
    shutdown(l[2], SHUT_RD);
    verifier(rp_accepte(l, 3, port) == 1, "SO_REUSEPORT tcp : une ecoute arretee par shutdown quitte le groupe");
    close(l[1]);
    close(l[2]);
    /* Deux groupes (une écoute liée à lo) : la plus récente en tête avec son groupe
     * l'emporte, même moins bien notée. */
    port = rp_libre_tcp();
    l[0] = rp_ecoute(port, NULL);
    l[1] = rp_ecoute(port, "lo");
    int avant = rp_accepte(l, 2, port);
    shutdown(l[0], SHUT_RD);
    listen(l[0], 8);
    verifier(avant == 1 && rp_accepte(l, 2, port) == 0, "SO_REUSEPORT tcp : la plus recente ecoute en tete, avec son groupe");
    close(l[0]);
    close(l[1]);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    chez_nous = access("/etc/bonjour.txt", F_OK) == 0;
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
    horodatages_emission_tcp();
    horodatages_stats_tcp();
    zerocopie_option();
    zerocopie_udp();
    zerocopie_tcp();
    rythme_max();
    filtres_options();
    filtres_memoire();
    filtres_udp();
    filtres_ping_unix();
    filtres_tcp();
    conseil_tcp();
    reuseport_options();
    recherche_des_connectees();
    groupe_processeur_non_compte();
    reuseport_udp();
    reuseport_tcp();
    printf("[linux] options-socket : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
