/*
 * Deux programmes qui gardent leurs registres vectoriels pendant qu'ils se
 * préemptent l'un l'autre (6e) : « avx <moi> <autre> », lancé deux fois par
 * `&`, après un rendez-vous, remplit XMM0 à XMM15 (et leurs moitiés hautes
 * YMM, si le processeur a AVX et que le noyau l'a mis en service), MXCSR
 * (l'arrondi vers le haut) et le mot de contrôle x87 (l'arrondi vers zéro)
 * de motifs à lui, puis, sans relire ses registres, cède 300 fois le
 * processeur (sched_yield) en calculant entre deux fois (le tic de
 * l'horloge le préempte aussi), et vérifie tout. Si la bascule ne sauvait
 * pas l'état de chaque tâche (FXSAVE, ou XSAVE pour AVX), les motifs de
 * l'autre programme apparaîtraient.
 */
#include <cpuid.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int avx(void)
{
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_AVX) || !(c & bit_OSXSAVE))
        return 0;
    unsigned bas, haut;
    __asm__ volatile("xgetbv" : "=a"(bas), "=d"(haut) : "c"(0));
    return (bas & 6) == 6;
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    char moi[64], autre[64];
    snprintf(moi, sizeof moi, "/tmp/avx-%s", argv[1]);
    snprintf(autre, sizeof autre, "/tmp/avx-%s", argv[2]);
    close(open(moi, O_CREAT | O_WRONLY, 0644));
    struct timespec ms = { 0, 1000000 };
    for (int i = 0; i < 10000 && access(autre, F_OK) != 0; i++)
        nanosleep(&ms, NULL);
    static uint8_t avant[16][32] __attribute__((aligned(32))), apres[16][32] __attribute__((aligned(32)));
    for (int r = 0; r < 16; r++)
        for (int o = 0; o < 32; o++)
            avant[r][o] = (uint8_t)(argv[1][0] * 7 + r * 13 + o);
    int a = avx();
    uint32_t mxcsr_avant = 0x5f80, mxcsr_apres = 0;
    uint16_t fcw_avant = 0x0f7f, fcw_apres = 0;
    __asm__ volatile(
        "ldmxcsr %[mxa]\n"
        "fldcw %[fca]\n"
        "test %[avx], %[avx]\n"
        "jz 3f\n"
        "vmovdqa 0(%[av]), %%ymm0\n vmovdqa 32(%[av]), %%ymm1\n vmovdqa 64(%[av]), %%ymm2\n vmovdqa 96(%[av]), %%ymm3\n"
        "vmovdqa 128(%[av]), %%ymm4\n vmovdqa 160(%[av]), %%ymm5\n vmovdqa 192(%[av]), %%ymm6\n vmovdqa 224(%[av]), %%ymm7\n"
        "vmovdqa 256(%[av]), %%ymm8\n vmovdqa 288(%[av]), %%ymm9\n vmovdqa 320(%[av]), %%ymm10\n vmovdqa 352(%[av]), %%ymm11\n"
        "vmovdqa 384(%[av]), %%ymm12\n vmovdqa 416(%[av]), %%ymm13\n vmovdqa 448(%[av]), %%ymm14\n vmovdqa 480(%[av]), %%ymm15\n"
        "jmp 4f\n"
        "3:\n"
        "movdqa 0(%[av]), %%xmm0\n movdqa 32(%[av]), %%xmm1\n movdqa 64(%[av]), %%xmm2\n movdqa 96(%[av]), %%xmm3\n"
        "movdqa 128(%[av]), %%xmm4\n movdqa 160(%[av]), %%xmm5\n movdqa 192(%[av]), %%xmm6\n movdqa 224(%[av]), %%xmm7\n"
        "movdqa 256(%[av]), %%xmm8\n movdqa 288(%[av]), %%xmm9\n movdqa 320(%[av]), %%xmm10\n movdqa 352(%[av]), %%xmm11\n"
        "movdqa 384(%[av]), %%xmm12\n movdqa 416(%[av]), %%xmm13\n movdqa 448(%[av]), %%xmm14\n movdqa 480(%[av]), %%xmm15\n"
        "4:\n"
        "mov $300, %%r12d\n"
        "1: mov $24, %%eax\n syscall\n"
        "mov $20000, %%r13d\n"
        "2: dec %%r13d\n jnz 2b\n"
        "dec %%r12d\n jnz 1b\n"
        "test %[avx], %[avx]\n"
        "jz 5f\n"
        "vmovdqa %%ymm0, 0(%[ap])\n vmovdqa %%ymm1, 32(%[ap])\n vmovdqa %%ymm2, 64(%[ap])\n vmovdqa %%ymm3, 96(%[ap])\n"
        "vmovdqa %%ymm4, 128(%[ap])\n vmovdqa %%ymm5, 160(%[ap])\n vmovdqa %%ymm6, 192(%[ap])\n vmovdqa %%ymm7, 224(%[ap])\n"
        "vmovdqa %%ymm8, 256(%[ap])\n vmovdqa %%ymm9, 288(%[ap])\n vmovdqa %%ymm10, 320(%[ap])\n vmovdqa %%ymm11, 352(%[ap])\n"
        "vmovdqa %%ymm12, 384(%[ap])\n vmovdqa %%ymm13, 416(%[ap])\n vmovdqa %%ymm14, 448(%[ap])\n vmovdqa %%ymm15, 480(%[ap])\n"
        "vzeroupper\n"
        "jmp 6f\n"
        "5:\n"
        "movdqa %%xmm0, 0(%[ap])\n movdqa %%xmm1, 32(%[ap])\n movdqa %%xmm2, 64(%[ap])\n movdqa %%xmm3, 96(%[ap])\n"
        "movdqa %%xmm4, 128(%[ap])\n movdqa %%xmm5, 160(%[ap])\n movdqa %%xmm6, 192(%[ap])\n movdqa %%xmm7, 224(%[ap])\n"
        "movdqa %%xmm8, 256(%[ap])\n movdqa %%xmm9, 288(%[ap])\n movdqa %%xmm10, 320(%[ap])\n movdqa %%xmm11, 352(%[ap])\n"
        "movdqa %%xmm12, 384(%[ap])\n movdqa %%xmm13, 416(%[ap])\n movdqa %%xmm14, 448(%[ap])\n movdqa %%xmm15, 480(%[ap])\n"
        "6:\n"
        "stmxcsr %[mxp]\n"
        "fnstcw %[fcp]\n"
        : [mxp] "=m"(mxcsr_apres), [fcp] "=m"(fcw_apres)
        : [mxa] "m"(mxcsr_avant), [fca] "m"(fcw_avant), [av] "r"(avant), [ap] "r"(apres), [avx] "r"(a)
        : "rax", "rcx", "r11", "r12", "r13", "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6",
          "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
    int largeur = a ? 32 : 16, ok = mxcsr_apres == mxcsr_avant && fcw_apres == fcw_avant;
    for (int r = 0; r < 16; r++)
        ok &= memcmp(avant[r], apres[r], largeur) == 0;
    unlink(moi);
    printf("[linux] avx %s : %s, MXCSR et x87 intacts apres 300 sched_yield : %s\n", argv[1],
           a ? "YMM0-YMM15" : "XMM0-XMM15", ok ? "ok" : "ECHEC");
    return 0;
}
