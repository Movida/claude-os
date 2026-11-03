/*
 * Le client Linux du serveur WebAssembly bonjour-tcp.wasm (6h) : un
 * programme Linux et un programme WebAssembly qui se parlent par TCP, sur
 * lo. Le serveur est lancé sur la ligne précédente de /etc/demarrage, en
 * arrière-plan, avec son écoute pré-ouverte (--tcplisten=127.0.0.1:PORT) :
 * le lanceur l'a créée avant de passer à notre ligne, elle est déjà là.
 * Deux connexions, l'une après l'autre : chacune envoie une ligne, et doit
 * recevoir la même à l'envers, puis la fin du flux. Le serveur répond à la
 * première par sock_send et sock_shutdown (seule son écriture s'arrête :
 * le client lui envoie alors un dernier mot, « merci », qu'il doit lire),
 * à la seconde par fd_write : de ce côté-ci, rien d'autre ne doit se voir.
 * SO_RCVTIMEO borne chaque attente (30 s : l'interpréteur WebAssembly est
 * lent sous QEMU sans accélération, mais pas à ce point) : un serveur muet
 * fait échouer le test au lieu de le bloquer.
 *   client-tcp PORT
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Une connexion : envoie `ligne` et sa fin de ligne, puis lit jusqu'à la
   fin du flux ; vrai si c'est `attendu` et sa fin de ligne. */
static int echange(int port, int numero, const char *ligne, const char *attendu, int merci)
{
    char recu[128] = { 0 };
    size_t n = 0;
    int ok = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval delai = { .tv_sec = 30 };
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s >= 0 && setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &delai, sizeof delai) == 0
        && connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
        char envoi[128];
        int longueur = snprintf(envoi, sizeof envoi, "%s\n", ligne);
        if (send(s, envoi, longueur, 0) == longueur) {
            ssize_t k = -1;
            while (n < sizeof recu - 1 && (k = recv(s, recu + n, sizeof recu - 1 - n, 0)) > 0)
                n += k;
            char voulu[128];
            snprintf(voulu, sizeof voulu, "%s\n", attendu);
            ok = k == 0 && strcmp(recu, voulu) == 0;
            if (merci)
                ok &= send(s, "merci\n", 6, 0) == 6;
        }
    }
    if (s >= 0)
        close(s);
    if (n > 0 && recu[n - 1] == '\n')
        recu[n - 1] = 0;
    printf("[linux] client-tcp : echange %d avec bonjour-tcp.wasm : envoye '%s', recu '%s' : %s\n", numero, ligne, recu,
           ok ? "ok" : "ECHEC");
    return ok;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    int ok = echange(port, 1, "bonjour", "ruojnob", 1);
    ok &= echange(port, 2, "Claude Code", "edoC edualC", 0);
    printf("[linux] client-tcp : les deux echanges : %s\n", ok ? "ok" : "ECHEC");
    return !ok;
}
