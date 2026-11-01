/*
 * Le réseau tel que l'a configuré le noyau au démarrage (6g), sur le réseau
 * utilisateur de QEMU (slirp) : il ne tourne que dans notre noyau, car il
 * connaît les adresses de slirp (nous 10.0.2.15/24, la passerelle
 * 10.0.2.2, le DNS 10.0.2.3). Ce que montrerait Linux configuré par
 * ipconfig (ip=dhcp) sur la même machine, octet pour octet :
 *   - /proc/net/route : la table principale, lignes de 127 colonnes ;
 *   - /etc/resolv.conf, un lien vers /proc/net/pnp : le résultat du DHCP ;
 *   - /proc/net/dev : son en-tête, et la ligne d'eth0.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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

    /* /proc/net/dev : l'en-tête de Linux, puis eth0 (le nom aligné à droite
     * sur 6 colonnes). Les compteurs ne sont pas comparés : ils dépendent de
     * ce qui est passé. */
    lire_tout("/proc/net/dev", t, sizeof t, sizeof t);
    const char *entete = "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";
    verifier(strncmp(t, entete, strlen(entete)) == 0 && strncmp(t + strlen(entete), "  eth0: ", 8) == 0, "/proc/net/dev : en-tete et eth0");

    printf("[linux] passerelle : %s\n", echecs ? "ECHEC" : "toutes les verifications : ok");
    return echecs != 0;
}
