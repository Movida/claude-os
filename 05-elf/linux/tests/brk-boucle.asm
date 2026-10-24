; Faire grandir puis reculer son tas, sans fin : chaque appel met à zéro
; 32 Mio. Le programme doit être arrêté par son budget de temps (1 s,
; SIGXCPU), comme une boucle sans appel système : le temps passé dans le
; noyau pour lui compte aussi, et l'horloge ne doit pas perdre ses tics
; pendant que le noyau met des pages à zéro. (Sous QEMU sans accélération,
; qui ne délivre les interruptions qu'entre deux blocs d'instructions
; traduits, des tics se perdent encore dans les milliers de courtes
; sections critiques de brk : le programme est arrêté après quelques
; secondes réelles au lieu d'une. Un budget mesuré au compteur de cycles,
; avec l'horloge fine de l'étape 6, n'aura plus ce biais.)
%include "commun.inc"
SYS_BRK equ 12
_start:
    ECRIRE debut
    mov eax, SYS_BRK
    xor edi, edi
    syscall
    mov r12, rax
.boucle:
    lea rdi, [r12 + 32 * 1024 * 1024]
    mov eax, SYS_BRK
    syscall
    mov rdi, r12
    mov eax, SYS_BRK
    syscall
    jmp .boucle
section .rodata
TEXTE debut, "[linux] Test : brk qui grandit et recule sans fin."
