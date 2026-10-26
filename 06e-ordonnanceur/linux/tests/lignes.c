/*
 * Deux programmes qui écrivent sur la console en même temps ne doivent pas
 * mêler leurs lignes (6e) : « lignes <nom> <n> », lancé deux fois par `&`,
 * écrit n lignes longues d'un seul write chacune ; make tests-qemu compte
 * les lignes entières de chacun dans le journal.
 *
 * Sous QEMU sans accélération, ce test ne prouve pas le verrou des
 * écritures (console.rs) : mesuré, il passe encore sans lui. La console
 * écrit par paquets de 8 octets, interruptions coupées, et TCG ne livre
 * l'horloge qu'entre deux blocs traduits : la fenêtre entre deux paquets
 * ne laisse presque jamais passer la préemption, et les lignes ne se
 * coupent pas. Il vérifie que rien ne se perd ni ne se coupe ; sur un vrai
 * processeur, il pourrait mordre.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    char nom = argv[1][0], l[256];
    int n = atoi(argv[2]);
    for (int i = 0; i < n; i++) {
        int k = snprintf(l, sizeof l, "[linux] lignes %c %04d ", nom, i);
        memset(l + k, nom, 160);
        l[k + 160] = '\n';
        if (write(1, l, k + 161) != k + 161)
            return 1;
    }
    return 0;
}
