/*
 * Le réseau tel que l'a configuré le noyau au démarrage (6g), sur le réseau
 * utilisateur de QEMU (slirp) : il ne tourne que dans notre noyau, car il
 * connaît les adresses de slirp (nous 10.0.2.15/24, la passerelle
 * 10.0.2.2, le DNS 10.0.2.3). Ce que montrerait Linux configuré par
 * ipconfig (ip=dhcp) sur la même machine, octet pour octet :
 *   - /proc/net/route : la table principale, lignes de 127 colonnes ;
 *   - /etc/resolv.conf, un lien vers /proc/net/pnp : le résultat du DHCP ;
 *   - /proc/net/dev : son en-tête, et les lignes de lo et d'eth0 ; un
 *     datagramme UDP envoyé à 10.0.2.2:9 (le port « discard ») part par
 *     eth0, et ses compteurs le comptent ;
 *   - /proc/net/arp : son en-tête, et les voisins résolus au démarrage (la
 *     passerelle et le DNS de slirp, dont l'adresse matérielle est 52:55
 *     suivi de leur adresse IPv4) ;
 *   - un ping de la passerelle, attendu par un recv sans délai : aucune
 *     minuterie armée, le détecteur d'interblocage doit le laisser
 *     attendre (une réponse peut venir du réseau) ;
 *   - une socket connectée à 10.0.2.2:9 : slirp répond par un ICMP « port
 *     injoignable » venu de 127.0.0.1 (ce que lui dit l'hôte), un martien
 *     que Linux jette : aucune erreur ;
 *   - le DNS, par getaddrinfo comme claude : api.anthropic.com trouvé (par
 *     le DNS de slirp, qui relaie celui de l'hôte : il y faut Internet ;
 *     l'adresse n'est pas affichée, elle change), localhost par /etc/hosts,
 *     nexistepas-claude-os.anthropic.com inconnu (EAI_NONAME ; pas un nom
 *     réservé de la RFC 6761, qu'un résolveur peut traiter à part).
 * `passerelle sans-reseau`, sur une machine sans carte : la glibc, sans
 * serveur DNS dans /etc/resolv.conf (/proc/net/pnp dit « #MANUAL »),
 * demande à 127.0.0.1, dont le port 53 est fermé : l'ICMP « port
 * injoignable » revient par lo, et getaddrinfo rend EAI_AGAIN tout de suite,
 * sans attendre ses 5 s de délai.
 * `passerelle muet`, dans le noyau des tests : 10.0.2.99, une adresse du
 * réseau où personne ne répond. Le voisin échoue (3 s), et chaque paquet
 * qui l'attendait revient en ICMP « hôte injoignable », de nous à nous :
 * une socket connectée sans IP_RECVERR n'en voit rien (l'erreur n'est pas
 * fatale), une socket UDP et une socket de ping avec IP_RECVERR l'ont
 * dans leur file d'erreurs (EHOSTUNREACH, ICMP 3/1, dite par 10.0.2.15) ;
 * un connect TCP en cours échoue aussitôt (6h : EHOSTUNREACH).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] passerelle : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Tout un fichier, lu par morceaux de `morceau` octets (une lecture de
 * /proc rend au plus une page à la fois). */
static size_t lire_tout(const char *chemin, char *tampon, size_t taille, size_t morceau)
{
    int fd = open(chemin, O_RDONLY);
    size_t fait = 0;
    ssize_t n;
    while (fd >= 0 && fait < taille - 1 && (n = read(fd, tampon + fait, morceau < taille - 1 - fait ? morceau : taille - 1 - fait)) > 0)
        fait += n;
    tampon[fait] = 0;
    if (fd >= 0)
        close(fd);
    return fait;
}

/* Une ligne de /proc/net/route : le texte, complété d'espaces jusqu'à 127
 * colonnes, et le saut de ligne. */
static void ligne_de_route(char *o, const char *texte)
{
    size_t n = strlen(texte);
    memcpy(o, texte, n);
    memset(o + n, ' ', 127 - n);
    o[127] = '\n';
    o[128] = 0;
}

static struct sockaddr_in adresse(uint32_t ip, uint16_t port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(ip) };
    return a;
}

/* Un écho de 12 octets : l'en-tête ICMP, puis « ping ». */
static void echo(char m[12])
{
    struct icmphdr e = { .type = ICMP_ECHO, .un.echo = { .id = htons(1), .sequence = htons(1) } };
    memcpy(m, &e, sizeof e);
    memcpy(m + 8, "ping", 4);
}

/* La première erreur de la file de s, avec son errno, son genre, son code
 * et qui l'a dite ; 0 si elle est ICMP 3/1 de 10.0.2.15, EHOSTUNREACH. */
static int hote_injoignable(int s)
{
    char o[64], c[256];
    struct iovec v = { o, sizeof o };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c };
    if (recvmsg(s, &m, MSG_ERRQUEUE) < 0)
        return -1;
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h)) {
        struct sock_extended_err *ee = (struct sock_extended_err *)CMSG_DATA(h);
        struct sockaddr_in *de = (struct sockaddr_in *)SO_EE_OFFENDER(ee);
        if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_RECVERR)
            return !(ee->ee_errno == EHOSTUNREACH && ee->ee_origin == SO_EE_ORIGIN_ICMP && ee->ee_type == ICMP_DEST_UNREACH
                     && ee->ee_code == ICMP_HOST_UNREACH && de->sin_addr.s_addr == htonl(0x0a00020f));
    }
    return -1;
}

static int muet(void)
{
    struct sockaddr_in a = adresse(0x0a000263, 9);
    int un = 1;
    int connectee = socket(AF_INET, SOCK_DGRAM, 0), libre = socket(AF_INET, SOCK_DGRAM, 0);
    int ping = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    setsockopt(libre, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    setsockopt(ping, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    connect(connectee, (struct sockaddr *)&a, sizeof a);
    char m[12];
    echo(m);
    int partis = send(connectee, "muet", 4, 0) == 4 && sendto(libre, "muet", 4, 0, (struct sockaddr *)&a, sizeof a) == 4
                 && sendto(ping, m, sizeof m, 0, (struct sockaddr *)&a, sizeof a) == sizeof m;
    verifier(partis, "10.0.2.99 : trois paquets partent (le voisin se cherche)");
    /* Et un connect TCP non bloquant : son SYN attend le voisin aussi. */
    struct sockaddr_in at = adresse(0x0a000263, 80);
    int t = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int rt = connect(t, (struct sockaddr *)&at, sizeof at) < 0 ? errno : 0;
    /* Les deux erreurs, 10 s au plus chacune (le voisin échoue en 3 s). */
    struct pollfd p = { libre, 0, 0 }, q = { ping, 0, 0 };
    poll(&p, 1, 10000);
    poll(&q, 1, 10000);
    verifier(hote_injoignable(libre) == 0, "UDP avec IP_RECVERR : EHOSTUNREACH, ICMP 3/1 de 10.0.2.15");
    verifier(hote_injoignable(ping) == 0, "ping avec IP_RECVERR : EHOSTUNREACH, ICMP 3/1 de 10.0.2.15");
    /* TCP : avant la fin de la poignée de main, toute erreur ICMP ferme la
     * connexion (`tcp_v4_err`) : EHOSTUNREACH, sans attendre l'abandon. */
    struct pollfd tp = { t, POLLOUT, 0 };
    poll(&tp, 1, 10000);
    int so = -1;
    socklen_t lso = sizeof so;
    getsockopt(t, SOL_SOCKET, SO_ERROR, &so, &lso);
    verifier(rt == EINPROGRESS && (tp.revents & POLLERR) && so == EHOSTUNREACH,
             "TCP vers 10.0.2.99 : EHOSTUNREACH apres l'echec du voisin (connect non bloquant)");
    close(t);
    struct pollfd c = { connectee, POLLIN, 0 };
    char o[8];
    verifier(poll(&c, 1, 0) == 0 && recv(connectee, o, sizeof o, MSG_DONTWAIT) == -1 && errno == EAGAIN,
             "connectee sans IP_RECVERR : rien (l'hote injoignable n'est pas fatal)");
    printf("[linux] passerelle : %s\n", echecs ? "ECHEC" : "toutes les verifications (muet) : ok");
    return echecs != 0;
}

/* getaddrinfo(nom), comme le fait claude (AF_UNSPEC, le port 443) ; rend
 * son code, et la première adresse IPv4 dans `a`. */
static int chercher(const char *nom, struct sockaddr_in *a)
{
    struct addrinfo h = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *r;
    int e = getaddrinfo(nom, "443", &h, &r);
    if (e != 0)
        return e;
    memset(a, 0, sizeof *a);
    for (struct addrinfo *p = r; p; p = p->ai_next)
        if (p->ai_family == AF_INET && a->sin_family == 0)
            memcpy(a, p->ai_addr, sizeof *a);
    freeaddrinfo(r);
    return 0;
}

static int sans_reseau(void)
{
    struct sockaddr_in a;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int e = chercher("api.anthropic.com", &a);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double duree = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    verifier(e == EAI_AGAIN && duree < 2, "sans carte : EAI_AGAIN, en moins de 2 s (le 127.0.0.1 de la glibc, l'ICMP de lo)");
    printf("[linux] passerelle : %s\n", echecs ? "ECHEC" : "toutes les verifications (sans reseau) : ok");
    return echecs != 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "muet") == 0)
        return muet();
    if (argc > 1 && strcmp(argv[1], "sans-reseau") == 0)
        return sans_reseau();
    char t[8192], attendu[3 * 128 + 1];
    /* La table de routage : la route par défaut (RTF_UP | RTF_GATEWAY, par
     * 10.0.2.2), puis celle du réseau (RTF_UP) ; les adresses comme Linux
     * les imprime (10.0.2.2 : 0202000A). Lue d'un coup, puis par morceaux
     * de 7 octets (la reprise d'une séquence au milieu d'une ligne). */
    ligne_de_route(attendu, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT");
    ligne_de_route(attendu + 128, "eth0\t00000000\t0202000A\t0003\t0\t0\t0\t00000000\t0\t0\t0");
    ligne_de_route(attendu + 256, "eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0");
    lire_tout("/proc/net/route", t, sizeof t, sizeof t);
    verifier(strcmp(t, attendu) == 0, "/proc/net/route comme Linux");
    lire_tout("/proc/net/route", t, sizeof t, 7);
    verifier(strcmp(t, attendu) == 0, "/proc/net/route lu par morceaux");

    /* /etc/resolv.conf : un lien vers /proc/net/pnp, au format d'ipconfig
     * (pnp_seq_show) : ce que slirp a donné par DHCP. */
    char lien[64] = {0};
    ssize_t n = readlink("/etc/resolv.conf", lien, sizeof lien - 1);
    verifier(n == 13 && strcmp(lien, "/proc/net/pnp") == 0, "/etc/resolv.conf -> /proc/net/pnp");
    lire_tout("/etc/resolv.conf", t, sizeof t, sizeof t);
    verifier(strcmp(t, "#PROTO: DHCP\nnameserver 10.0.2.3\nbootserver 10.0.2.2\n") == 0, "/etc/resolv.conf : le DNS de slirp");

    /* /proc/net/dev : l'en-tête de Linux, puis lo et eth0, dans l'ordre de
     * leur numéro (le nom aligné à droite sur 6 colonnes). Les compteurs ne
     * sont pas comparés : ils dépendent de ce qui est passé. */
    lire_tout("/proc/net/dev", t, sizeof t, sizeof t);
    const char *entete = "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";
    char *eth0 = strstr(t, "\n  eth0: ");
    verifier(strncmp(t, entete, strlen(entete)) == 0 && strncmp(t + strlen(entete), "    lo: ", 8) == 0 && eth0,
             "/proc/net/dev : en-tete, lo puis eth0");

    /* Un datagramme vers le port « discard » de la passerelle : il part par
     * eth0 (slirp le fait suivre à l'hôte, qui n'écoute pas : son ICMP
     * revient de 127.0.0.1, un martien, jeté). */
    unsigned long avant = 0, apres = 0, octets;
    if (eth0)
        sscanf(eth0 + 9, "%lu %*u %*u %*u %*u %*u %*u %*u %lu %lu", &octets, &octets, &avant);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(9), .sin_addr.s_addr = htonl(0x0a000202) };
    int parti = sendto(s, "bonjour", 7, 0, (struct sockaddr *)&a, sizeof a) == 7;
    close(s);
    lire_tout("/proc/net/dev", t, sizeof t, sizeof t);
    eth0 = strstr(t, "\n  eth0: ");
    if (eth0)
        sscanf(eth0 + 9, "%lu %*u %*u %*u %*u %*u %*u %*u %lu %lu", &octets, &octets, &apres);
    verifier(parti && apres > avant, "un datagramme vers 10.0.2.2:9 part par eth0");

    /* À notre adresse d'eth0, un datagramme passe par lo ; IP_PKTINFO dit
     * pourtant eth0 (2), l'interface qui porte l'adresse, comme Linux. */
    int r = socket(AF_INET, SOCK_DGRAM, 0), un = 1;
    struct sockaddr_in ici = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x0a00020f) };
    socklen_t l = sizeof ici;
    bind(r, (struct sockaddr *)&ici, sizeof ici);
    getsockname(r, (struct sockaddr *)&ici, &l);
    setsockopt(r, IPPROTO_IP, IP_PKTINFO, &un, sizeof un);
    s = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(s, "i", 1, 0, (struct sockaddr *)&ici, sizeof ici);
    char o[8], c[64];
    struct iovec v = { o, sizeof o };
    struct msghdr m = { .msg_iov = &v, .msg_iovlen = 1, .msg_control = c, .msg_controllen = sizeof c };
    struct cmsghdr *h = recvmsg(r, &m, MSG_DONTWAIT) == 1 ? CMSG_FIRSTHDR(&m) : NULL;
    verifier(h && h->cmsg_type == IP_PKTINFO && ((struct in_pktinfo *)CMSG_DATA(h))->ipi_ifindex == 2,
             "a 10.0.2.15 par lo : IP_PKTINFO dit eth0 (2)");
    close(s);
    close(r);

    /* /proc/net/arp : l'en-tête d'arp_seq_show, puis une ligne par voisin
     * (dans l'ordre de la table : Linux suit celui de ses seaux, on ne
     * compare que les lignes). */
    lire_tout("/proc/net/arp", t, sizeof t, 13);
    verifier(strncmp(t, "IP address       HW type     Flags       HW address            Mask     Device\n", 79) == 0
             && strstr(t, "\n10.0.2.2         0x1         0x2         52:55:0a:00:02:02     *        eth0\n")
             && strstr(t, "\n10.0.2.3         0x1         0x2         52:55:0a:00:02:03     *        eth0\n"),
             "/proc/net/arp : la passerelle et le DNS, comme Linux");

    /* Le ping de la passerelle, attendu sans délai. */
    int q = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    a = adresse(0x0a000202, 0);
    char e[12], rep[64];
    echo(e);
    parti = sendto(q, e, sizeof e, 0, (struct sockaddr *)&a, sizeof a) == sizeof e;
    l = sizeof a;
    n = recvfrom(q, rep, sizeof rep, 0, (struct sockaddr *)&a, &l);
    verifier(parti && n == sizeof e && rep[0] == ICMP_ECHOREPLY && memcmp(rep + 8, "ping", 4) == 0 && a.sin_addr.s_addr == htonl(0x0a000202),
             "ping de 10.0.2.2 : la reponse, attendue sans delai");
    close(q);

    /* 10.0.2.2:9, connectée : l'ICMP de slirp, de 127.0.0.1, est jeté. */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    a = adresse(0x0a000202, 9);
    connect(s, (struct sockaddr *)&a, sizeof a);
    send(s, "x", 1, 0);
    struct pollfd p = { s, POLLIN, 0 };
    verifier(poll(&p, 1, 500) == 0 && recv(s, rep, sizeof rep, MSG_DONTWAIT) == -1 && errno == EAGAIN,
             "10.0.2.2:9 connectee : l'ICMP de 127.0.0.1 est un martien, aucune erreur");
    close(s);

    /* Le DNS, par la glibc. */
    verifier(chercher("api.anthropic.com", &a) == 0 && a.sin_family == AF_INET && ntohs(a.sin_port) == 443,
             "api.anthropic.com : adresse trouvee");
    verifier(chercher("localhost", &a) == 0 && a.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "localhost : 127.0.0.1, par /etc/hosts");
    verifier(chercher("nexistepas-claude-os.anthropic.com", &a) == EAI_NONAME, "nexistepas-claude-os.anthropic.com : EAI_NONAME");

    printf("[linux] passerelle : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
