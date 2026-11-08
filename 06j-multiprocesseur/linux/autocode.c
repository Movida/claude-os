/*
 * Du code qui se modifie lui-même (6h), comme le compilateur à la volée de `claude` patche ses appels
 * directs (`DirectCallLinkInfo::setCallTarget` de JavaScriptCore : le déplacement du `call`, puis le
 * CodeBlock écrit en dur dans un `movabs`) : une page écrite et exécutée à la fois, réécrite alors que
 * ses instructions ont déjà tourné. L'exécution qui suit doit voir la nouvelle valeur : le processeur
 * l'assure de lui-même (manuel d'Intel, vol. 3A, 11.6), et le noyau n'y est pour rien, sauf à garder
 * W+X tel que le programme l'a demandé. Les instructions vont dans une seule page, puis à cheval sur
 * deux : opérande sur la page suivante, opérande coupée en deux, `call` coupé après son premier octet.
 *
 * Ce programme juge donc aussi la machine, et c'est pour elle qu'il existe. QEMU 8.2.2, celui d'Ubuntu
 * 24.04, a une erreur de frappe : `tb_record` et `tb_remove` (accel/tcg/tb-maint.c) calculent
 * `pindex1` d'après `paddr0`, si bien que la deuxième page d'un bloc traduit à cheval sur deux pages
 * n'est jamais enregistrée, et qu'écrire dans cette page n'invalide pas le bloc (corrigé en amont
 * dès la 8.2.3). Le code de `claude` y plantait une fois sur quarante environ, sous notre noyau comme
 * sous le vrai Linux dans le même QEMU (HISTORIQUE.md, 6h) : ce test le dit à chaque démarrage, au lieu
 * d'un plantage rare et sans rapport apparent.
 *
 * Sur l'hôte comme chez nous.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE 4096
#define TOURS 1000

typedef uint64_t (*fonction)(void);

static int echecs;

static void dire(const char *quoi, int perimes)
{
    printf("[linux] autocode : %s : %d lectures perimees sur %d : %s\n", quoi, perimes, TOURS, perimes ? "ECHEC" : "ok");
    echecs += perimes != 0;
}

/* `movabs rax, imm64 ; ret` à l'adresse `p`, puis l'opérande réécrite et relue à chaque tour. */
static int movabs(uint8_t *p)
{
    uint64_t v = 0;
    p[0] = 0x48;
    p[1] = 0xb8;
    memcpy(p + 2, &v, sizeof v);
    p[10] = 0xc3;
    fonction f = (fonction)p;
    int perimes = f() != 0;
    for (uint64_t i = 1; i <= TOURS; i++) {
        memcpy(p + 2, &i, sizeof i);
        perimes += f() != i;
    }
    return perimes;
}

/* `mov eax, imm32 ; ret`, la fonction que vise `call_vers`. */
static void cible(uint8_t *p, uint32_t valeur)
{
    p[0] = 0xb8;
    memcpy(p + 1, &valeur, sizeof valeur);
    p[5] = 0xc3;
}

/* `call rel32 ; ret` à l'adresse `p`, qui vise tour à tour deux cibles. */
static int call_vers(uint8_t *p, uint8_t *a, uint8_t *b)
{
    cible(a, 1);
    cible(b, 2);
    p[0] = 0xe8;
    p[5] = 0xc3;
    fonction f = (fonction)p;
    int perimes = 0;
    for (int i = 0; i <= TOURS; i++) {
        uint8_t *vers = i % 2 ? b : a;
        int32_t depl = (int32_t)(vers - (p + 5));
        memcpy(p + 1, &depl, sizeof depl);
        perimes += f() != (i % 2 ? 2u : 1u);
    }
    return perimes;
}

int main(void)
{
    uint8_t *z = mmap(NULL, 6 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (z == MAP_FAILED) {
        perror("[linux] autocode : mmap");
        return 2;
    }
    dire("une seule page", movabs(z + 100));
    int cheval = 0;
    int n = movabs(z + 2 * PAGE - 2);
    dire("l'operande sur la page suivante", n);
    cheval += n;
    n = movabs(z + 3 * PAGE - 6);
    dire("l'operande coupee en deux", n);
    cheval += n;
    n = call_vers(z + 4 * PAGE - 1, z + 200, z + 300);
    dire("le call coupe apres son premier octet", n);
    cheval += n;
    if (cheval) {
        printf("[linux] autocode : du code ecrit sur la 2e page d'un bloc n'invalide pas le bloc : QEMU avant 8.2.3 ? (HISTORIQUE.md, 6h)\n");
    }
    printf("[linux] autocode : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
