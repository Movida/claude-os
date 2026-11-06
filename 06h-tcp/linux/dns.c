/*
 * Le DNS de la glibc (6g), par le même chemin que claude : un programme
 * dynamique (la glibc partagée), getaddrinfo, ses deux questions (A et
 * AAAA) envoyées d'un coup par sendmmsg sur une socket connectée, poll,
 * FIONREAD et recvfrom. Sans Internet : le serveur DNS est ici, un fil du
 * programme sur 127.0.0.1 (un port éphémère), et la glibc y est envoyée
 * par `_res` (sa configuration lue de /etc/resolv.conf, puis changée).
 * Le serveur répond d'abord de travers, comme un réseau qui ment ou qui
 * abîme : à chaque question, une réponse au mauvais identifiant (la glibc
 * doit l'ignorer : un attaquant qui devine mal ne doit rien faire croire),
 * puis, la première fois, une réponse plus courte qu'un en-tête DNS (la
 * glibc abandonne cet essai, et recommence avec une autre socket : mesuré
 * sur l'hôte), puis la vraie. Vérifié :
 *   - essai.exemple : 192.0.2.7 (une adresse de documentation), le port
 *     443 demandé, l'IPv6 sans réponse ; deux essais de deux questions (A
 *     et AAAA), chacun d'un seul port ;
 *   - nexistepas.exemple : NXDOMAIN, EAI_NONAME ;
 *   - localhost : 127.0.0.1, par /etc/hosts, sans question au serveur.
 * Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] dns : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

static int serveur;
/* Ce que le serveur a vu : le nombre de questions, et leurs ports. */
static volatile int questions;
static unsigned short ports[8];

/* Répond à chaque question : un mauvais identifiant ; pour les deux
 * premières, 5 octets ; puis la réponse (192.0.2.7 pour A d'essai.exemple ;
 * rien pour AAAA ; NXDOMAIN pour tout autre nom). */
static void *repondre(void *arg)
{
    (void)arg;
    for (;;) {
        unsigned char q[512], r[600];
        struct sockaddr_in de;
        socklen_t l = sizeof de;
        int n = recvfrom(serveur, q, sizeof q, 0, (struct sockaddr *)&de, &l);
        if (n < 12 + 5)
            continue;
        if (questions < 8)
            ports[questions] = ntohs(de.sin_port);
        questions++;
        /* La question : son nom, son genre et sa classe. Ce qui suit ne se recopie pas : le OPT d'EDNS0,
         * si /etc/resolv.conf demande « options edns0 » (celui de la CI, avec systemd-resolved) ; une
         * réponse doit avoir ses enregistrements dans l'ordre de l'en-tête. */
        int fin = 12;
        while (fin < n && q[fin] != 0)
            fin += q[fin] + 1;
        fin += 5;
        if (fin > n)
            continue;
        int genre = q[fin - 4] << 8 | q[fin - 3];
        int essai = memmem(q + 12, fin - 12, "\005essai\007exemple", 15) != NULL;
        memcpy(r, q, fin);
        r[2] = 0x81; /* une réponse, récursion demandée */
        r[3] = essai ? 0x80 : 0x83; /* récursion possible ; NOERROR, ou NXDOMAIN */
        r[6] = 0;
        r[7] = essai && genre == 1;
        r[10] = r[11] = 0; /* pas d'enregistrement additionnel */
        int m = fin;
        if (r[7]) {
            unsigned char rr[] = { 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7 };
            memcpy(r + m, rr, sizeof rr);
            m += sizeof rr;
        }
        r[0] ^= 0xff;
        sendto(serveur, r, m, 0, (struct sockaddr *)&de, l);
        if (questions <= 2) {
            sendto(serveur, r, 5, 0, (struct sockaddr *)&de, l);
            continue;
        }
        r[0] ^= 0xff;
        sendto(serveur, r, m, 0, (struct sockaddr *)&de, l);
    }
    return NULL;
}

int main(void)
{
    serveur = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t l = sizeof a;
    if (bind(serveur, (struct sockaddr *)&a, sizeof a) != 0 || getsockname(serveur, (struct sockaddr *)&a, &l) != 0) {
        printf("[linux] dns : le serveur : ECHEC\n");
        return 1;
    }
    pthread_t f;
    pthread_create(&f, NULL, repondre, NULL);
    res_init();
    _res.nscount = 1;
    _res.nsaddr_list[0] = a;
    _res.options &= ~(RES_DNSRCH | RES_DEFNAMES);

    struct addrinfo h = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *r;
    int e = getaddrinfo("essai.exemple", "443", &h, &r);
    int ok = e == 0 && r->ai_family == AF_INET && r->ai_next == NULL;
    if (ok) {
        struct sockaddr_in *s = (struct sockaddr_in *)r->ai_addr;
        ok = s->sin_addr.s_addr == htonl(0xc0000207) && ntohs(s->sin_port) == 443;
        freeaddrinfo(r);
    }
    verifier(ok, "essai.exemple : 192.0.2.7:443, malgre les mauvais identifiants et la reponse tronquee");
    verifier(questions == 4 && ports[0] == ports[1] && ports[2] == ports[3], "deux essais de deux questions (A et AAAA), chacun d'un port");
    e = getaddrinfo("nexistepas.exemple", "443", &h, &r);
    verifier(e == EAI_NONAME, "nexistepas.exemple : NXDOMAIN, EAI_NONAME");
    int avant = questions;
    h.ai_family = AF_INET;
    e = getaddrinfo("localhost", NULL, &h, &r);
    ok = e == 0 && ((struct sockaddr_in *)r->ai_addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    if (e == 0)
        freeaddrinfo(r);
    verifier(ok && questions == avant, "localhost : 127.0.0.1, par /etc/hosts, sans question au DNS");
    printf("[linux] dns : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
