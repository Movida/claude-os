/*
 * Le jalon de 6h : un programme C télécharge une page HTTP de 4 Mio, par
 * TCP, à travers la carte réseau et le réseau « utilisateur » de QEMU
 * (slirp). La page vient de 10.0.2.100:80, que QEMU sert lui-même :
 * chaque connexion y lance outils/serveur-http sur l'hôte (guestfwd), sans
 * Internet ni port ouvert sur l'hôte. Il ne tourne que dans notre noyau.
 *   - getaddrinfo("10.0.2.100", "80") (une adresse en chiffres : sans DNS),
 *     connect, GET /page en HTTP/1.1 ;
 *   - l'en-tête : « 200 », et Content-Length ;
 *   - la page, octet par octet : des lignes de 16 octets qui disent
 *     chacune leur position (15 chiffres hexadécimaux, une fin de ligne) ;
 *     la première différence est dite (sa position, ce qui était attendu,
 *     ce qui est venu) ; puis la fin de la connexion (Connection: close) ;
 *   - une seconde connexion, GET /absente : 404, sans corps ; sa requête écrite
 *     par petits morceaux, sans Nagle (l'autocork, et le rappel de fin d'émission de
 *     la carte : sans lui, les derniers morceaux attendraient).
 * La durée et le débit sont affichés à part, hors des lignes comparées
 * (ils changent d'une fois à l'autre). SO_RCVTIMEO borne chaque attente
 * (60 s) : un serveur muet fait échouer le test au lieu de le bloquer.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define TAILLE 4194304

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] telecharger : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* L'octet attendu à la position `o` de la page : la ligne o / 16 dit sa
   position (o arrondi à 16) en 15 chiffres hexadécimaux, puis '\n'. */
static char attendu(unsigned long o)
{
    unsigned long debut = o & ~15UL;
    int i = o & 15;
    if (i == 15)
        return '\n';
    return "0123456789abcdef"[(debut >> (4 * (14 - i))) & 15];
}

/* Une connexion à 10.0.2.100:80 (getaddrinfo, socket, connect), la
   requête `chemin` envoyée ; -1 si quelque chose échoue (dit). */
static int demander(const char *chemin, int morceaux)
{
    struct addrinfo indices = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *r;
    int e = getaddrinfo("10.0.2.100", "80", &indices, &r);
    if (e != 0) {
        printf("[linux] telecharger : getaddrinfo : %s : ECHEC\n", gai_strerror(e));
        echecs++;
        return -1;
    }
    int s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
    struct timeval delai = { .tv_sec = 60 };
    int ok = s >= 0 && setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &delai, sizeof delai) == 0
             && connect(s, r->ai_addr, r->ai_addrlen) == 0;
    freeaddrinfo(r);
    char requete[256];
    int n = snprintf(requete, sizeof requete, "GET %s HTTP/1.1\r\nHost: 10.0.2.100\r\nConnection: close\r\n\r\n", chemin);
    if (ok && morceaux > 0) {
        int oui = 1;
        ok = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &oui, sizeof oui) == 0;
        for (int i = 0; ok && i < n; i += morceaux) {
            int m = n - i < morceaux ? n - i : morceaux;
            ok = send(s, requete + i, m, 0) == m;
        }
    } else if (ok)
        ok = send(s, requete, n, 0) == n;
    if (!ok) {
        printf("[linux] telecharger : connexion a 10.0.2.100:80 (%s) : ECHEC\n", strerror(errno));
        echecs++;
        if (s >= 0)
            close(s);
        return -1;
    }
    return s;
}

/* Lit l'en-tête de la réponse, jusqu'à la ligne vide : son code (200, 404)
   et Content-Length (-1 sans lui) ; ce qui a été lu après l'en-tête (le
   début du corps) est rangé dans `reste`, sa longueur dans `*n_reste`. */
static int en_tete(int s, long *longueur, char *reste, size_t *n_reste)
{
    static char t[4096];
    size_t n = 0;
    char *fin = NULL;
    while (!fin && n < sizeof t - 1) {
        ssize_t k = recv(s, t + n, sizeof t - 1 - n, 0);
        if (k <= 0)
            return -1;
        n += k;
        t[n] = 0;
        fin = strstr(t, "\r\n\r\n");
    }
    if (!fin)
        return -1;
    int code = -1;
    sscanf(t, "HTTP/1.1 %d", &code);
    char *cl = strcasestr(t, "\r\nContent-Length:");
    *longueur = cl && cl < fin ? strtol(cl + 17, NULL, 10) : -1;
    *n_reste = n - (fin + 4 - t);
    memcpy(reste, fin + 4, *n_reste);
    return code;
}

int main(void)
{
    struct timespec debut, fin;
    clock_gettime(CLOCK_MONOTONIC, &debut);
    int s = demander("/page", 0);
    if (s >= 0) {
        static char tampon[65536];
        long longueur;
        size_t n;
        int code = en_tete(s, &longueur, tampon, &n);
        verifier(code == 200 && longueur == TAILLE, "GET /page : 200, Content-Length 4194304");
        /* Le corps, vérifié au fil de l'eau ; la première différence est
           gardée. */
        unsigned long recu = 0, premiere = (unsigned long)-1;
        char vu = 0;
        ssize_t k = n;
        do {
            for (ssize_t i = 0; i < k; i++, recu++)
                if (premiere == (unsigned long)-1 && (recu >= TAILLE || tampon[i] != attendu(recu))) {
                    premiere = recu;
                    vu = tampon[i];
                }
        } while ((k = recv(s, tampon, sizeof tampon, 0)) > 0);
        int erreur = k < 0 ? errno : 0;
        clock_gettime(CLOCK_MONOTONIC, &fin);
        close(s);
        if (premiere != (unsigned long)-1 && premiere < TAILLE)
            printf("[linux] telecharger : octet %lu : attendu 0x%02x, recu 0x%02x\n", premiere, attendu(premiere), (unsigned char)vu);
        char quoi[96];
        snprintf(quoi, sizeof quoi, "page de %lu octets, chacun a sa place, puis la fin de la connexion", recu);
        verifier(recu == TAILLE && premiere == (unsigned long)-1 && erreur == 0, quoi);
        double secondes = (fin.tv_sec - debut.tv_sec) + (fin.tv_nsec - debut.tv_nsec) / 1e9;
        printf("[linux] telecharger : %.2f s, %.0f Kio/s\n", secondes, recu / 1024.0 / secondes);
    }
    s = demander("/absente", 4);
    if (s >= 0) {
        char reste[4096];
        long longueur;
        size_t n;
        int code = en_tete(s, &longueur, reste, &n);
        char octet;
        verifier(code == 404 && longueur == 0 && n == 0 && recv(s, &octet, 1, 0) == 0, "GET /absente : 404, sans corps");
        close(s);
    }
    verifier(echecs == 0, "toutes les verifications");
    return echecs != 0;
}
