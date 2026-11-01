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
 *     suivi de leur adresse IPv4).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

int main(void)
{
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

    printf("[linux] passerelle : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
