/*
 * Les options IP d'un paquet reçu (les soldes d'avant 6k), sur l'hôte seulement, sous
 * `sudo` (make tests-hote-root) : ce que fait Linux de chaque cas de
 * formats/tests/reseau/options-ip.txt, que relit aussi le test de `compiler_options`
 * (formats/tests/reseau.rs). Le fichier dit donc ce que fait Linux, vérifié ici, et ce
 * que fait notre lecture, vérifiée là ; notre noyau n'a pas de socket brute pour le
 * rejouer en entier (son auto-test, noyau/src/reseau/autotest.rs, en rejoue deux cas).
 *
 * Il faut root pour écrire soi-même un en-tête IP (une socket brute, IP_HDRINCL). Dans
 * un espace réseau à lui quand il le peut (unshare : rien de la machine ne s'en mêle),
 * le programme envoie à 127.0.0.1, vers un port UDP fermé, un
 * datagramme qui porte les options du cas ; puis il écoute l'ICMP qui revient par lo :
 *   - « parametre N » : un problème de paramètre (ICMP 12) qui désigne l'octet N ;
 *   - « livre HEX » : le paquet est passé, et le port fermé répond (ICMP 3/3) en citant
 *     l'en-tête reçu, dont les options sont alors HEX (« .. » : un octet de l'heure) ;
 *   - « jete » : rien en 300 ms (une route source, jetée sans un mot) ;
 *   - « cipso N » : un problème de paramètre (octet N) part, mais ne revient jamais :
 *     Linux renvoie dans l'en-tête de l'erreur les options du paquet fautif
 *     (`ip_options_echo`), CIPSO compris, et lo jette l'erreur à son arrivée pour la
 *     même raison. Les compteurs de /proc/net/snmp le montrent : un OutParmProbs de
 *     plus, aucun InParmProbs, deux InHdrErrors (le paquet, puis son erreur). Notre
 *     noyau ne renvoie pas encore les options (avec IP_OPTIONS) : son erreur revient ;
 *   - « muet HEX » : le paquet passe (options HEX), mais le port fermé ne répond pas :
 *     Linux ne saurait pas renvoyer ces options (`ip_options_echo` refuse une route
 *     notée dont la dernière place déborde), et se tait plutôt (aucun OutDestUnreachs).
 *     Notre noyau répond : il ne renvoie pas d'options (avec IP_OPTIONS).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *nom, const char *quoi)
{
    printf("[linux] options-ip : %s : %s : %s\n", nom, quoi, ok ? "ok" : "ECHEC");
    if (!ok)
        echecs++;
}

/* Un octet en hexadécimal (deux caractères), -1 pour « .. », -2 si faux. */
static int octet(const char *h)
{
    if (h[0] == '.' && h[1] == '.')
        return -1;
    char t[3] = {h[0], h[1], 0};
    char *fin;
    long v = strtol(t, &fin, 16);
    return *fin || fin == t ? -2 : (int)v;
}

/* Le compteur `nom` de la ligne `table` de /proc/net/snmp (-1 : introuvable). */
static long compteur(const char *table, const char *nom)
{
    FILE *f = fopen("/proc/net/snmp", "r");
    char noms[2048], valeurs[2048];
    long v = -1;
    size_t n = strlen(table);
    while (f && fgets(noms, sizeof noms, f) && fgets(valeurs, sizeof valeurs, f)) {
        if (strncmp(noms, table, n) || noms[n] != ':')
            continue;
        char *pn, *pv, *a = strtok_r(noms + n + 1, " \n", &pn), *b = strtok_r(valeurs + n + 1, " \n", &pv);
        for (; a && b; a = strtok_r(NULL, " \n", &pn), b = strtok_r(NULL, " \n", &pv))
            if (!strcmp(a, nom))
                v = atol(b);
    }
    if (f)
        fclose(f);
    return v;
}

/* lo, levée : un espace réseau neuf la laisse éteinte. */
static int lever_lo(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strcpy(ifr.ifr_name, "lo");
    if (s < 0 || ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
        return -1;
    ifr.ifr_flags |= IFF_UP;
    int r = ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
    return r;
}

/* Un port UDP fermé de 127.0.0.1 : pris puis rendu. */
static uint16_t port_ferme(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t n = sizeof a;
    if (s < 0 || bind(s, (void *)&a, sizeof a) < 0 || getsockname(s, (void *)&a, &n) < 0)
        return 0;
    close(s);
    return ntohs(a.sin_port);
}

/*
 * Envoie le cas `nom` (ses options : `opt`, `n` octets) depuis le port `sport`, puis
 * attend l'ICMP qui cite ce port ; rend son genre (-1 : rien en 300 ms), et dans
 * `pointeur` et `cite` (`*ncite` octets) le pointeur d'un problème de paramètre et les
 * options citées.
 */
static int essayer(int brute, int icmp, const uint8_t *opt, int n, uint16_t sport, uint16_t dport,
                   int *pointeur, uint8_t *cite, int *ncite)
{
    uint8_t p[60 + 9] = {0};
    struct iphdr *h = (void *)p;
    int ihl = 20 + n;
    h->version = 4;
    h->ihl = ihl / 4;
    h->ttl = 64;
    h->protocol = IPPROTO_UDP;
    h->saddr = htonl(INADDR_LOOPBACK);
    h->daddr = htonl(INADDR_LOOPBACK);
    memcpy(p + 20, opt, n);
    uint8_t *u = p + ihl;
    u[0] = sport >> 8;
    u[1] = sport;
    u[2] = dport >> 8;
    u[3] = dport;
    u[5] = 9; /* longueur UDP : 8 + 1 ; somme 0 (aucune, permis en IPv4) */
    u[8] = 'x';
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    /* Linux remplit lui-même la longueur totale et la somme (`raw_send_hdrinc`). */
    if (sendto(brute, p, ihl + 9, 0, (void *)&a, sizeof a) != ihl + 9)
        return -2;
    for (;;) {
        struct pollfd f = {.fd = icmp, .events = POLLIN};
        if (poll(&f, 1, 300) <= 0)
            return -1;
        uint8_t r[1500];
        ssize_t l = recv(icmp, r, sizeof r, 0);
        if (l < 20)
            continue;
        int ext = (r[0] & 15) * 4;
        const uint8_t *m = r + ext;
        if (l < ext + 8 + 20)
            continue;
        const uint8_t *in = m + 8;
        int iihl = (in[0] & 15) * 4;
        if (l < ext + 8 + iihl + 4 || in[9] != IPPROTO_UDP)
            continue;
        const uint8_t *iu = in + iihl;
        if ((iu[0] << 8 | iu[1]) != sport)
            continue;
        *pointeur = m[4];
        *ncite = iihl - 20;
        memcpy(cite, in + 20, iihl - 20);
        return m[0] << 8 | m[1];
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage : %s formats/tests/reseau/options-ip.txt\n", argv[0]);
        return 2;
    }
    FILE *cas = fopen(argv[1], "r");
    if (!cas) {
        perror(argv[1]);
        return 2;
    }
    /* Un espace réseau à lui si la machine le permet (pas un conteneur sans
       CAP_SYS_ADMIN, comme le devcontainer) ; sinon celui de la machine, où lo est
       déjà levée : les ICMP d'autres programmes y passent aussi, triés par le port
       cité. */
    if (unshare(CLONE_NEWNET) == 0 && lever_lo() < 0) {
        perror("lo");
        return 2;
    }
    int brute = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    uint16_t dport = port_ferme();
    if (brute < 0 || icmp < 0 || !dport) {
        perror("les sockets brutes");
        return 2;
    }
    char ligne[512];
    int k = 0, vus = 0;
    while (fgets(ligne, sizeof ligne, cas)) {
        char nom[64], hex[256], issue[32], apres[256] = "";
        if (ligne[0] == '#' || ligne[0] == '\n')
            continue;
        if (sscanf(ligne, "%63s %255s %31s %255s", nom, hex, issue, apres) < 3) {
            verifier(0, ligne, "ligne illisible");
            continue;
        }
        uint8_t opt[40], cite[40];
        int n = strlen(hex) / 2, pointeur = -1, ncite = 0, bon = n <= 40 && n % 4 == 0;
        for (int i = 0; bon && i < n; i++) {
            int o = octet(hex + 2 * i);
            bon = o >= 0;
            opt[i] = o;
        }
        if (!bon) {
            verifier(0, nom, "options illisibles");
            continue;
        }
        vus++;
        long sortis = compteur("Icmp", "OutParmProbs"), entres = compteur("Icmp", "InParmProbs");
        long fautes = compteur("Ip", "InHdrErrors"), injoignables = compteur("Icmp", "OutDestUnreachs");
        int genre = essayer(brute, icmp, opt, n, 20000 + k++, dport, &pointeur, cite, &ncite);
        if (!strcmp(issue, "parametre")) {
            int attendu = atoi(apres);
            char quoi[64];
            snprintf(quoi, sizeof quoi, "probleme de parametre, octet %d (vu : genre %#x, octet %d)", attendu, genre, pointeur);
            verifier(genre == 12 << 8 && pointeur == attendu, nom, quoi);
        } else if (!strcmp(issue, "cipso")) {
            long s = compteur("Icmp", "OutParmProbs") - sortis, e = compteur("Icmp", "InParmProbs") - entres;
            long h = compteur("Ip", "InHdrErrors") - fautes;
            char quoi[160];
            snprintf(quoi, sizeof quoi, "l'erreur part et ne revient pas (vu : genre %#x ; %ld parti, %ld revenu, %ld en-tetes faux)",
                     genre, s, e, h);
            verifier(genre == -1 && s == 1 && e == 0 && h == 2, nom, quoi);
        } else if (!strcmp(issue, "muet")) {
            long u = compteur("Icmp", "OutDestUnreachs") - injoignables;
            char quoi[120];
            snprintf(quoi, sizeof quoi, "livre, sans reponse du port ferme (vu : genre %#x ; %ld envoyee)", genre, u);
            verifier(genre == -1 && u == 0, nom, quoi);
        } else if (!strcmp(issue, "jete")) {
            verifier(genre == -1, nom, "jete sans un mot");
        } else if (!strcmp(issue, "livre")) {
            int m = strlen(apres) / 2, egal = genre == (3 << 8 | 3) && m == ncite;
            for (int i = 0; egal && i < m; i++) {
                int o = octet(apres + 2 * i);
                egal = o == -1 || o == cite[i];
            }
            char quoi[200] = "livre, le port ferme cite ";
            for (int i = 0; i < ncite && strlen(quoi) < sizeof quoi - 3; i++)
                sprintf(quoi + strlen(quoi), "%02x", cite[i]);
            verifier(egal, nom, quoi);
        } else {
            verifier(0, nom, "issue inconnue");
        }
    }
    verifier(vus >= 30, "le fichier", "au moins 30 cas");
    printf("[linux] options-ip : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
