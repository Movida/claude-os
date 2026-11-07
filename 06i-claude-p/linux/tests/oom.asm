; Le tueur OOM : un programme écrit dans 256 Mio de tas, un octet par
; page. brk les promet sans rien compter (le surengagement), demandés en
; quatre fois 64 Mio : une seule demande plus grande que toute la mémoire
; serait refusée d'emblée. Dans QEMU
; (128 Mio), la mémoire manque avant la fin, à une faute de page : le
; noyau tue le programme (SIGKILL, code de sortie 137), rend toute sa
; mémoire, et le programme suivant tourne. Sur l'hôte, il va au bout.
%include "commun.inc"
SYS_BRK equ 12
_start:
    ECRIRE debut
    mov eax, SYS_BRK
    xor edi, edi
    syscall
    mov r12, rax
    mov rbx, r12
    mov ecx, 4
.brk:
    add rbx, 64 * 1024 * 1024
    mov rdi, rbx
    push rcx
    mov eax, SYS_BRK
    syscall
    pop rcx
    cmp rax, rbx
    jne echec
    dec ecx
    jnz .brk
.page:
    mov byte [r12], 1
    add r12, 4096
    cmp r12, rbx
    jb .page
    ECRIRE fini
    SORTIR 0
echec:
    ECRIRE rate
    SORTIR 1
section .rodata
TEXTE debut, "[linux] Test : 256 Mio de tas ecrits page par page."
TEXTE fini, "[linux] oom : 256 Mio ecrits."
TEXTE rate, "[linux] ECHEC : brk de 256 Mio refuse."
