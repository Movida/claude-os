/*
 * La MTU du chemin (6h), sur l'hôte seulement, sous `sudo` (make tests-hote-root) : ce
 * que fait Linux d'un ICMP « fragmentation nécessaire ». Il faut root pour forger cet ICMP
 * (une socket brute vers lo, qui cite un paquet vers une adresse 127.x.y.z tirée au
 * hasard : ce qu'il pose sur la route expire en 10 min, et ne touche pas 127.0.0.1). Notre
 * noyau n'a pas de socket brute : son auto-test (noyau/src/reseau/autotest.rs) rejoue ce
 * scénario, avec les mêmes valeurs :
 *   - TCP : un numéro hors du vol ne change rien ; dans le vol : TCP_MAXSEG 948 (1000 - 40 -
 *     12), IP_MTU et tcpi_pmtu 1000, ni SO_ERROR ni MSG_ERRQUEUE, même avec IP_RECVERR ;
 *     une connexion neuve annonce d'après la MTU apprise ;
 *   - UDP : connectée : EMSGSIZE, sans IP_RECVERR ; une autre socket voit la MTU ; WANT : un
 *     datagramme de 1400 octets vers une route à 1200 part quand même, et arrive entier ;
 *     IP_PMTUDISC_DO : EMSGSIZE. Sous le plancher (FRAG 400) : 552, verrouillée.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] pmtu : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    if (!ok)
        echecs++;
}

static uint16_t somme(const void *d, int n)
{
    const uint8_t *p = d;
    uint32_t s = 0;
    for (int i = 0; i + 1 < n; i += 2)
        s += p[i] << 8 | p[i + 1];
    if (n & 1)
        s += p[n - 1] << 8;
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return ~s;
}

/* Un ICMP 3/4 reçu de lo, qui cite un paquet de src à dst, au numéro seq. */
static void frag_necessaire(uint32_t src, uint32_t dst, int proto, uint16_t sport, uint16_t dport, uint32_t seq, int mtu)
{
    int r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    uint8_t b[8 + 20 + 8] = {0};
    b[0] = 3;
    b[1] = 4;
    b[6] = mtu >> 8;
    b[7] = mtu;
    struct iphdr *ih = (void *)(b + 8);
    ih->version = 4;
    ih->ihl = 5;
    ih->tot_len = htons(mtu + 100);
    ih->ttl = 64;
    ih->protocol = proto;
    ih->saddr = src;
    ih->daddr = dst;
    ih->frag_off = htons(IP_DF);
    ih->check = htons(somme(ih, 20));
    uint8_t *l4 = b + 28;
    l4[0] = sport >> 8;
    l4[1] = sport;
    l4[2] = dport >> 8;
    l4[3] = dport;
    l4[4] = seq >> 24;
    l4[5] = seq >> 16;
    l4[6] = seq >> 8;
    l4[7] = seq;
    uint16_t c = somme(b, sizeof b);
    b[2] = c >> 8;
    b[3] = c;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (r < 0 || sendto(r, b, sizeof b, 0, (void *)&a, sizeof a) < 0)
        perror("icmp");
    close(r);
    struct timespec t = { 0, 40000000 };
    nanosleep(&t, NULL);
}

static int ip_mtu(int s)
{
    int m = -1;
    socklen_t l = sizeof m;
    return getsockopt(s, IPPROTO_IP, IP_MTU, &m, &l) ? -errno : m;
}

static int entier(int s, int niveau, int nom)
{
    int m = -1;
    socklen_t l = sizeof m;
    getsockopt(s, niveau, nom, &m, &l);
    return m;
}

static uint32_t tcpi(int s, int decalage)
{
    unsigned char b[256];
    socklen_t l = sizeof b;
    uint32_t v = 0;
    getsockopt(s, IPPROTO_TCP, TCP_INFO, b, &l);
    memcpy(&v, b + decalage, 4);
    return v;
}

#define TCPI_PMTU 60
#define TCPI_ADVMSS 84

/* 127.a.b.c, tiré au hasard : deux lancers dans les 10 min ne se gênent pas. */
static uint32_t adresse_neuve(void)
{
    uint8_t o[4] = { 127 };
    if (getrandom(o + 1, 3, 0) != 3)
        memset(o + 1, 9, 3);
    o[1] = (o[1] & 0x7f) + 1;
    uint32_t a;
    memcpy(&a, o, 4);
    return a;
}

/* Le plus loin qu'ait envoyé le port `port`, d'après ce qu'a vu la capture `pk`. */
static uint32_t prochain_numero(int pk, uint16_t port)
{
    static uint8_t b[70000];
    uint32_t fin = 0;
    long k;
    while ((k = recv(pk, b, sizeof b, MSG_DONTWAIT)) > 0) {
        struct iphdr *ih = (void *)b;
        if (ih->protocol != IPPROTO_TCP)
            continue;
        uint8_t *t = b + ih->ihl * 4;
        if ((t[0] << 8 | t[1]) != port)
            continue;
        uint32_t seq = (uint32_t)t[4] << 24 | t[5] << 16 | t[6] << 8 | t[7];
        uint32_t e = seq + ntohs(ih->tot_len) - ih->ihl * 4 - (t[12] >> 4) * 4 + ((t[13] & 2) ? 1 : 0);
        if (fin == 0 || (int32_t)(e - fin) > 0)
            fin = e;
    }
    return fin;
}

static void tcp(void)
{
    uint32_t d = adresse_neuve();
    int un = 1;
    int pk = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    struct sockaddr_ll sll = { .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP), .sll_ifindex = if_nametoindex("lo") };
    bind(pk, (void *)&sll, sizeof sll);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = d };
    bind(l, (void *)&a, sizeof a);
    listen(l, 4);
    socklen_t al = sizeof a;
    getsockname(l, (void *)&a, &al);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(c, IPPROTO_IP, IP_RECVERR, &un, sizeof un);
    connect(c, (void *)&a, sizeof a);
    int s = accept(l, NULL, NULL);
    struct sockaddr_in moi;
    socklen_t ml = sizeof moi;
    getsockname(c, (void *)&moi, &ml);
    /* Un numéro loin hors du vol : rien, pas même la route. */
    frag_necessaire(moi.sin_addr.s_addr, d, IPPROTO_TCP, ntohs(moi.sin_port), ntohs(a.sin_port), 1, 1000);
    verifier(ip_mtu(c) == 65535, "TCP : FRAG hors du vol : rien, pas meme la route");
    /* Le numéro de SND.NXT, dans le vol : lu dans ce qui est passé sur lo (root n'a pas
     * forcément CAP_NET_ADMIN pour TCP_REPAIR ; il a CAP_NET_RAW). */
    int mss_avant = entier(c, IPPROTO_TCP, TCP_MAXSEG);
    uint32_t nxt = prochain_numero(pk, ntohs(moi.sin_port));
    frag_necessaire(moi.sin_addr.s_addr, d, IPPROTO_TCP, ntohs(moi.sin_port), ntohs(a.sin_port), nxt, 1000);
    verifier(mss_avant > 948 && entier(c, IPPROTO_TCP, TCP_MAXSEG) == 948, "TCP : FRAG 1000 : TCP_MAXSEG 948");
    verifier(ip_mtu(c) == 1000 && tcpi(c, TCPI_PMTU) == 1000, "TCP : IP_MTU et tcpi_pmtu 1000");
    verifier(entier(c, SOL_SOCKET, SO_ERROR) == 0, "TCP : pas d'erreur, meme avec IP_RECVERR");
    char o[16];
    verifier(recv(c, o, sizeof o, MSG_ERRQUEUE | MSG_DONTWAIT) < 0 && errno == EAGAIN, "TCP : la file d'erreurs vide");
    /* Une connexion neuve : d'après la MTU apprise. */
    int c2 = socket(AF_INET, SOCK_STREAM, 0);
    connect(c2, (void *)&a, sizeof a);
    int s2 = accept(l, NULL, NULL);
    verifier(tcpi(c2, TCPI_ADVMSS) == 948 && tcpi(c2, TCPI_PMTU) == 1000, "TCP : une connexion neuve : advmss 948");
    close(s2);
    close(c2);
    close(s);
    close(c);
    close(l);
    close(pk);
}

static void udp(void)
{
    uint32_t d = adresse_neuve();
    int r = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = d };
    bind(r, (void *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(r, (void *)&a, &al);
    int s = socket(AF_INET, SOCK_DGRAM, 0), autre = socket(AF_INET, SOCK_DGRAM, 0);
    connect(s, (void *)&a, sizeof a);
    connect(autre, (void *)&a, sizeof a);
    struct sockaddr_in moi;
    socklen_t ml = sizeof moi;
    getsockname(s, (void *)&moi, &ml);
    verifier(ip_mtu(s) == 65535, "UDP : la MTU de lo au depart");
    frag_necessaire(moi.sin_addr.s_addr, d, IPPROTO_UDP, ntohs(moi.sin_port), ntohs(a.sin_port), 0, 1200);
    verifier(entier(s, SOL_SOCKET, SO_ERROR) == EMSGSIZE, "UDP : FRAG 1200 : EMSGSIZE, sans IP_RECVERR");
    /* (Chez Linux, l'autre socket la voit après son prochain envoi : sa route en cache
     * est périmée, `ipv4_dst_check`. Chez nous, tout de suite.) */
    send(autre, "a", 1, 0);
    char t[8];
    recv(r, t, sizeof t, 0);
    verifier(ip_mtu(s) == 1200 && ip_mtu(autre) == 1200, "UDP : la MTU de la route, pour toutes les sockets");
    /* WANT (le défaut) : découpé, et recollé à l'arrivée. */
    static char b[1400], c[2000];
    memset(b, 'x', sizeof b);
    verifier(send(s, b, sizeof b, 0) == sizeof b, "UDP : 1400 octets vers une route a 1200 : envoyes");
    verifier(recv(r, c, sizeof c, 0) == sizeof b && memcmp(b, c, sizeof b) == 0, "UDP : et recus entiers");
    int v = IP_PMTUDISC_DO;
    setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof v);
    verifier(send(s, b, sizeof b, 0) < 0 && errno == EMSGSIZE, "UDP : IP_PMTUDISC_DO : EMSGSIZE");
    v = IP_PMTUDISC_WANT;
    setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER, &v, sizeof v);
    frag_necessaire(moi.sin_addr.s_addr, d, IPPROTO_UDP, ntohs(moi.sin_port), ntohs(a.sin_port), 0, 400);
    entier(s, SOL_SOCKET, SO_ERROR);
    verifier(ip_mtu(s) == 552, "UDP : FRAG 400 : 552");
    frag_necessaire(moi.sin_addr.s_addr, d, IPPROTO_UDP, ntohs(moi.sin_port), ntohs(a.sin_port), 0, 1000);
    entier(s, SOL_SOCKET, SO_ERROR);
    verifier(ip_mtu(s) == 552, "UDP : verrouillee a 552");
    close(s);
    close(autre);
    close(r);
}

int main(void)
{
    tcp();
    udp();
    printf("[linux] pmtu : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
