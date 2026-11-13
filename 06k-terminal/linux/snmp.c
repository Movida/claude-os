/*
 * /proc/net/snmp (les soldes d'avant 6k) : ses compteurs avancent comme
 * sous Linux 6.18, sur l'interface de boucle (127.0.0.1) :
 *   - le texte : les groupes et leurs noms, au caractère près ; Forwarding
 *     (1 : la machine route, 2 : non), DefaultTTL 64, les quatre valeurs
 *     fixes de TCP ;
 *   - un datagramme UDP vers soi : OutDatagrams à l'envoi, InDatagrams à la
 *     lecture seulement (pas en MSG_PEEK) ; et pour IP, un paquet de chaque
 *     sens : OutRequests, OutTransmits, InReceives, InDelivers ;
 *   - un datagramme vers un port fermé : NoPorts, et l'erreur ICMP « port
 *     injoignable » (OutMsgs, OutDestUnreachs, IcmpMsg OutType3, puis
 *     InMsgs, InDestUnreachs, InType3), deux paquets de chaque sens ;
 *   - un écho d'une socket de ping vers 127.0.0.1 : Echos et EchoReps,
 *     envoyés et reçus, et IcmpMsg pour les genres 0 et 8 ;
 *   - un connect TCP vers un port fermé : une ouverture active ratée
 *     (ActiveOpens, AttemptFails), le SYN et le RST qui lui répond (InSegs,
 *     OutSegs, OutRsts) ;
 *   - une connexion TCP acceptée (ActiveOpens, PassiveOpens, CurrEstab +2,
 *     trois segments), puis coupée par SO_LINGER à 0 : le RST, et deux
 *     connexions établies fermées d'un coup (EstabResets +2, CurrEstab -2).
 * Rien n'est renvoyé (RetransSegs), aucun segment n'est faux (InErrs) : sur
 * lo, InSegs et OutSegs avancent ensemble.
 * Chaque scénario lit /proc/net/snmp avant et après, et se rejoue (cinquante
 * fois au plus) tant que InReceives et OutRequests n'ont pas avancé
 * d'exactement ce qu'il a fait : le trafic des autres programmes de la
 * machine (WSL en a sans cesse) s'y voit. Sur un tour propre, chaque
 * compteur doit avoir avancé d'exactement l'attendu, et les autres de rien.
 * Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] snmp : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

#define LO 0x7f000001

static struct sockaddr_in adresse(uint32_t ip, uint16_t port)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(ip) };
    return a;
}

/* Le port d'une socket liée. */
static uint16_t port_de(int s)
{
    struct sockaddr_in a;
    socklen_t n = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &n);
    return ntohs(a.sin_port);
}

/* --- La lecture du fichier --- */

#define COMPTEURS_MAX 256

struct compteur {
    char groupe[16];
    char nom[40];
    long long valeur;
};

struct releve {
    int n;
    struct compteur c[COMPTEURS_MAX];
};

static char texte[16384];

/* Lit le fichier entier dans `texte` (une lecture suffit : Linux le rend
 * d'un coup, `single_open`) ; sa longueur, -1 en cas d'erreur. */
static int lire_fichier(void)
{
    int f = open("/proc/net/snmp", O_RDONLY);
    if (f < 0)
        return -1;
    int n = 0;
    for (;;) {
        ssize_t r = read(f, texte + n, sizeof texte - 1 - n);
        if (r <= 0)
            break;
        n += r;
    }
    close(f);
    texte[n] = 0;
    return n;
}

/* Les paires de lignes « Groupe: noms... » puis « Groupe: valeurs... ». */
static int relever(struct releve *r)
{
    r->n = 0;
    if (lire_fichier() < 0)
        return -1;
    char *noms = texte;
    while (*noms) {
        char *valeurs = strchr(noms, '\n');
        if (!valeurs)
            return -1;
        *valeurs++ = 0;
        char *suite = strchr(valeurs, '\n');
        if (!suite)
            return -1;
        *suite++ = 0;
        char *deux_points = strchr(noms, ':');
        if (!deux_points || strncmp(noms, valeurs, deux_points - noms + 1) != 0)
            return -1;
        char groupe[16];
        snprintf(groupe, sizeof groupe, "%.*s", (int)(deux_points - noms), noms);
        char *pn = deux_points + 1, *pv = valeurs + (deux_points - noms) + 1;
        for (;;) {
            while (*pn == ' ')
                pn++;
            if (!*pn)
                break;
            char *fin = strchr(pn, ' ');
            int l = fin ? fin - pn : (int)strlen(pn);
            if (r->n == COMPTEURS_MAX)
                return -1;
            struct compteur *c = &r->c[r->n++];
            snprintf(c->groupe, sizeof c->groupe, "%s", groupe);
            snprintf(c->nom, sizeof c->nom, "%.*s", l, pn);
            char *apres;
            c->valeur = strtoll(pv, &apres, 10);
            /* Un compteur au-delà de 2^63 (aucun, en pratique) : strtoll
             * le borne ; les écarts restent justes à moins de 2^63 près. */
            if (apres == pv)
                return -1;
            pv = apres;
            pn += l;
        }
        noms = suite;
    }
    return 0;
}

static const struct compteur *trouver(const struct releve *r, const char *groupe, const char *nom)
{
    for (int i = 0; i < r->n; i++)
        if (!strcmp(r->c[i].groupe, groupe) && !strcmp(r->c[i].nom, nom))
            return &r->c[i];
    return NULL;
}

static long long valeur(const struct releve *r, const char *groupe, const char *nom)
{
    const struct compteur *c = trouver(r, groupe, nom);
    return c ? c->valeur : 0; /* IcmpMsg ne montre que les compteurs non nuls. */
}

/* --- Les scénarios --- */

/* Ce qu'un scénario fait avancer : « Groupe Nom », et de combien. */
struct attendu {
    const char *groupe;
    const char *nom;
    long long ecart;
};

static long long attendu_de(const struct attendu *a, const char *groupe, const char *nom)
{
    for (; a->groupe; a++)
        if (!strcmp(a->groupe, groupe) && !strcmp(a->nom, nom))
            return a->ecart;
    return 0;
}

/* L'écart d'un compteur entre deux relevés, comparé à l'attendu ; dit s'il
 * est faux. Rend 1 s'il l'est. */
static int ecart_faux(const char *scenario, const struct releve *avant, const struct releve *apres, const char *g,
                      const char *n, long long voulu)
{
    long long e = valeur(apres, g, n) - valeur(avant, g, n);
    if (e == voulu)
        return 0;
    char quoi[160];
    snprintf(quoi, sizeof quoi, "%s : %s %s : %+lld, attendu %+lld", scenario, g, n, e, voulu);
    verifier(0, quoi);
    return 1;
}

/* Compare deux relevés à l'attendu, chaque compteur une fois : ceux de
 * l'après, ceux de l'avant qu'il n'a plus, les attendus qui ne sont dans
 * aucun (IcmpMsg ne montre que les compteurs non nuls). Rend le nombre
 * d'écarts faux. */
static int comparer(const char *scenario, const struct releve *avant, const struct releve *apres, const struct attendu *a)
{
    int faux = 0;
    for (int i = 0; i < apres->n; i++)
        faux += ecart_faux(scenario, avant, apres, apres->c[i].groupe, apres->c[i].nom,
                           attendu_de(a, apres->c[i].groupe, apres->c[i].nom));
    for (int i = 0; i < avant->n; i++)
        if (!trouver(apres, avant->c[i].groupe, avant->c[i].nom))
            faux += ecart_faux(scenario, avant, apres, avant->c[i].groupe, avant->c[i].nom,
                               attendu_de(a, avant->c[i].groupe, avant->c[i].nom));
    for (; a->groupe; a++)
        if (!trouver(apres, a->groupe, a->nom) && !trouver(avant, a->groupe, a->nom))
            faux += ecart_faux(scenario, avant, apres, a->groupe, a->nom, a->ecart);
    return faux;
}

#define ESSAIS 50

/* Joue `faire` jusqu'à un tour propre (InReceives et OutRequests ont avancé
 * de ce qu'attend `a`), puis compare tout. `faire` rend 0, ou -1 s'il a
 * échoué (dit par lui). Avec `b`, le scénario a deux temps : `faire`
 * relève lui-même le milieu ; l'avant et le milieu sont comparés à `a`, le
 * milieu et l'après à `b`. */
static struct releve avant, milieu, apres;

static void jouer(const char *scenario, int (*faire)(void), const struct attendu *a, const struct attendu *b)
{
    for (int essai = 0; essai < ESSAIS; essai++) {
        if (relever(&avant) < 0) {
            verifier(0, "lecture de /proc/net/snmp");
            return;
        }
        if (faire() < 0)
            return;
        if (relever(&apres) < 0) {
            verifier(0, "lecture de /proc/net/snmp");
            return;
        }
        const struct releve *fin_a = b ? &milieu : &apres;
        int propre = 1;
        for (int t = 0; t < (b ? 2 : 1); t++) {
            const struct releve *x = t ? &milieu : &avant, *y = t ? &apres : fin_a;
            const struct attendu *z = t ? b : a;
            propre &= valeur(y, "Ip", "InReceives") - valeur(x, "Ip", "InReceives") == attendu_de(z, "Ip", "InReceives")
                      && valeur(y, "Ip", "OutRequests") - valeur(x, "Ip", "OutRequests") == attendu_de(z, "Ip", "OutRequests");
        }
        if (!propre)
            continue;
        int faux = comparer(scenario, &avant, fin_a, a);
        if (b)
            faux += comparer(scenario, &milieu, &apres, b);
        if (!faux)
            verifier(1, scenario);
        return;
    }
    char quoi[160];
    snprintf(quoi, sizeof quoi, "%s : aucun tour sans autre trafic en %d essais", scenario, ESSAIS);
    verifier(0, quoi);
}

/* Le texte : les noms de Linux 6.18, et les valeurs qui ne sont pas des
 * compteurs. */
static void le_texte(void)
{
    static const char *const noms[] = {
        "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers "
        "OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates "
        "OutTransmits\n",
        "\nIcmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos "
        "InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutRateLimitGlobal "
        "OutRateLimitHost OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps "
        "OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps\n",
        "\nTcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs "
        "OutSegs RetransSegs InErrs OutRsts InCsumErrors\nTcp: 1 200 120000 -1 ",
        "\nUdp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti "
        "MemErrors\n",
        "\nUdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti "
        "MemErrors\nUdpLite: 0 0 0 0 0 0 0 0 0\n",
    };
    int n = lire_fichier();
    verifier(n > 0 && !strncmp(texte, noms[0], strlen(noms[0])), "la ligne des noms d'Ip");
    for (unsigned i = 1; i < sizeof noms / sizeof *noms; i++) {
        char quoi[64];
        snprintf(quoi, sizeof quoi, "le groupe %.*s", (int)strcspn(noms[i] + 1, ":"), noms[i] + 1);
        verifier(n > 0 && strstr(texte, noms[i]) != NULL, quoi);
    }
    verifier(n > 0 && texte[n - 1] == '\n' && (!strncmp(strchr(texte, '\n') + 1, "Ip: 1 64 ", 9)
                                               || !strncmp(strchr(texte, '\n') + 1, "Ip: 2 64 ", 9)),
             "Forwarding 1 ou 2, DefaultTTL 64, le saut de ligne final");
    struct releve r;
    verifier(relever(&r) == 0 && r.n >= 20 + 29 + 15 + 18, "les paires de lignes");
}

/* UDP vers soi : l'envoi, MSG_PEEK (rien), puis la lecture. */
static int udp_vers_soi(void)
{
    int a = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in lo = adresse(LO, 0);
    char o[8] = "bonjour", r[8];
    if (a < 0 || b < 0 || bind(a, (struct sockaddr *)&lo, sizeof lo) < 0) {
        verifier(0, "udp : socket et bind");
        return -1;
    }
    lo.sin_port = htons(port_de(a));
    int ok = sendto(b, o, sizeof o, 0, (struct sockaddr *)&lo, sizeof lo) == sizeof o
             && recv(a, r, sizeof r, MSG_PEEK) == sizeof o && relever(&milieu) == 0 && recv(a, r, sizeof r, 0) == sizeof o;
    close(a);
    close(b);
    if (!ok)
        verifier(0, "udp : sendto, recv");
    return ok ? 0 : -1;
}

/* UDP vers un port fermé : l'erreur ICMP revient, que la socket (pas
 * connectée) ne voit pas ; lo la livre avant que sendto ne revienne, chez
 * Linux comme chez nous (reseau.c le vérifie). */
static int udp_port_ferme(void)
{
    int f = socket(AF_INET, SOCK_DGRAM, 0), b = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in lo = adresse(LO, 0);
    if (f < 0 || b < 0 || bind(f, (struct sockaddr *)&lo, sizeof lo) < 0) {
        verifier(0, "port ferme : socket et bind");
        return -1;
    }
    lo.sin_port = htons(port_de(f));
    close(f);
    int ok = sendto(b, "x", 1, 0, (struct sockaddr *)&lo, sizeof lo) == 1;
    close(b);
    if (!ok)
        verifier(0, "port ferme : sendto");
    return ok ? 0 : -1;
}

/* Un écho d'une socket de ping (IPPROTO_ICMP), et sa réponse. */
static int echo(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    struct sockaddr_in lo = adresse(LO, 0);
    struct icmphdr h = { .type = ICMP_ECHO };
    char r[64];
    if (s < 0) {
        verifier(0, "echo : socket de ping");
        return -1;
    }
    int ok = sendto(s, &h, sizeof h, 0, (struct sockaddr *)&lo, sizeof lo) == sizeof h && recv(s, r, sizeof r, 0) == sizeof h;
    close(s);
    if (!ok)
        verifier(0, "echo : sendto, recv");
    return ok ? 0 : -1;
}

/* Un connect TCP vers un port fermé : ECONNREFUSED, par le RST qui répond
 * au SYN (lo le livre avant que connect ne revienne). */
static int tcp_refuse(void)
{
    int f = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo = adresse(LO, 0);
    if (f < 0 || c < 0 || bind(f, (struct sockaddr *)&lo, sizeof lo) < 0) {
        verifier(0, "tcp refuse : socket et bind");
        return -1;
    }
    lo.sin_port = htons(port_de(f));
    close(f);
    int ok = connect(c, (struct sockaddr *)&lo, sizeof lo) < 0 && errno == ECONNREFUSED;
    close(c);
    if (!ok)
        verifier(0, "tcp refuse : connect");
    return ok ? 0 : -1;
}

/* Une connexion acceptée (le milieu, relevé après accept : la poignée de
 * main est finie), puis le client la coupe (SO_LINGER à 0) ; recv de la
 * fille attend son RST (ECONNRESET). */
static int tcp_coupee(void)
{
    int e = socket(AF_INET, SOCK_STREAM, 0), c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo = adresse(LO, 0);
    if (e < 0 || c < 0 || bind(e, (struct sockaddr *)&lo, sizeof lo) < 0 || listen(e, 1) < 0) {
        verifier(0, "tcp coupee : socket, bind, listen");
        return -1;
    }
    lo.sin_port = htons(port_de(e));
    int a = -1;
    struct linger l = { .l_onoff = 1, .l_linger = 0 };
    char o;
    int ok = connect(c, (struct sockaddr *)&lo, sizeof lo) == 0 && (a = accept(e, NULL, NULL)) >= 0
             && relever(&milieu) == 0 && setsockopt(c, SOL_SOCKET, SO_LINGER, &l, sizeof l) == 0 && close(c) == 0
             && recv(a, &o, 1, 0) < 0 && errno == ECONNRESET;
    if (a < 0 || !ok)
        close(c);
    if (a >= 0)
        close(a);
    close(e);
    if (!ok)
        verifier(0, "tcp coupee : connect, accept, close, recv");
    return ok ? 0 : -1;
}

int main(void)
{
    le_texte();
    static const struct attendu udp_envoi[] = {
        { "Ip", "InReceives", 1 }, { "Ip", "InDelivers", 1 }, { "Ip", "OutRequests", 1 }, { "Ip", "OutTransmits", 1 },
        { "Udp", "OutDatagrams", 1 }, { 0 },
    };
    static const struct attendu udp_lecture[] = { { "Udp", "InDatagrams", 1 }, { 0 } };
    jouer("un datagramme UDP vers soi, compte a la lecture", udp_vers_soi, udp_envoi, udp_lecture);
    static const struct attendu ferme[] = {
        { "Ip", "InReceives", 2 }, { "Ip", "InDelivers", 2 }, { "Ip", "OutRequests", 2 }, { "Ip", "OutTransmits", 2 },
        { "Udp", "OutDatagrams", 1 }, { "Udp", "NoPorts", 1 },
        { "Icmp", "OutMsgs", 1 }, { "Icmp", "OutDestUnreachs", 1 }, { "Icmp", "InMsgs", 1 }, { "Icmp", "InDestUnreachs", 1 },
        { "IcmpMsg", "OutType3", 1 }, { "IcmpMsg", "InType3", 1 }, { 0 },
    };
    jouer("un port ferme : NoPorts et l'ICMP port injoignable", udp_port_ferme, ferme, NULL);
    static const struct attendu ping[] = {
        { "Ip", "InReceives", 2 }, { "Ip", "InDelivers", 2 }, { "Ip", "OutRequests", 2 }, { "Ip", "OutTransmits", 2 },
        { "Icmp", "OutMsgs", 2 }, { "Icmp", "OutEchos", 1 }, { "Icmp", "OutEchoReps", 1 },
        { "Icmp", "InMsgs", 2 }, { "Icmp", "InEchos", 1 }, { "Icmp", "InEchoReps", 1 },
        { "IcmpMsg", "OutType0", 1 }, { "IcmpMsg", "OutType8", 1 }, { "IcmpMsg", "InType0", 1 }, { "IcmpMsg", "InType8", 1 },
        { 0 },
    };
    jouer("un echo de ping vers 127.0.0.1", echo, ping, NULL);
    static const struct attendu refuse[] = {
        { "Ip", "InReceives", 2 }, { "Ip", "InDelivers", 2 }, { "Ip", "OutRequests", 2 }, { "Ip", "OutTransmits", 2 },
        { "Tcp", "ActiveOpens", 1 }, { "Tcp", "AttemptFails", 1 }, { "Tcp", "InSegs", 2 }, { "Tcp", "OutSegs", 2 },
        { "Tcp", "OutRsts", 1 }, { 0 },
    };
    jouer("un connect TCP vers un port ferme", tcp_refuse, refuse, NULL);
    static const struct attendu etablie[] = {
        { "Ip", "InReceives", 3 }, { "Ip", "InDelivers", 3 }, { "Ip", "OutRequests", 3 }, { "Ip", "OutTransmits", 3 },
        { "Tcp", "ActiveOpens", 1 }, { "Tcp", "PassiveOpens", 1 }, { "Tcp", "CurrEstab", 2 }, { "Tcp", "InSegs", 3 },
        { "Tcp", "OutSegs", 3 }, { 0 },
    };
    static const struct attendu coupee[] = {
        { "Ip", "InReceives", 1 }, { "Ip", "InDelivers", 1 }, { "Ip", "OutRequests", 1 }, { "Ip", "OutTransmits", 1 },
        { "Tcp", "EstabResets", 2 }, { "Tcp", "CurrEstab", -2 }, { "Tcp", "InSegs", 1 }, { "Tcp", "OutSegs", 1 },
        { "Tcp", "OutRsts", 1 }, { 0 },
    };
    jouer("une connexion TCP acceptee, puis coupee par SO_LINGER", tcp_coupee, etablie, coupee);
    printf("[linux] snmp : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
