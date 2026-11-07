; Calculer une seconde et demie, puis sortir avec 0 : sans limite posée,
; le temps de calcul d'un programme est infini (RLIMIT_CPU par défaut,
; comme Linux), et le noyau ne doit pas l'arrêter. Le temps se lit à son
; horloge de calcul (CLOCK_PROCESS_CPUTIME_ID) : c'est celle que compare
; le noyau à la limite, et le temps réel, sous QEMU, peut être plus long.
%include "commun.inc"
SYS_CLOCK_GETTIME equ 228
CLOCK_PROCESS_CPUTIME_ID equ 2
_start:
    ECRIRE debut
    sub rsp, 16
.boucle:
    mov eax, SYS_CLOCK_GETTIME
    mov edi, CLOCK_PROCESS_CPUTIME_ID
    mov rsi, rsp
    syscall
    ; 1,5 s : 1 s et 500 000 000 ns, ou plus.
    mov rax, [rsp]
    cmp rax, 1
    jb .boucle
    ja .fini
    cmp qword [rsp + 8], 500000000
    jb .boucle
.fini:
    ECRIRE fin
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : calculer 1,5 s sans limite de temps de calcul."
TEXTE fin, "[linux] calcul-long : 1,5 s de calcul, pas arrete : ok"
