; La page de zéros et la copie à l'écriture. Une page jamais écrite se lit
; à zéro : le noyau la projette sur la page de zéros, partagée, en lecture
; seule. Puis getrandom y écrit : c'est le NOYAU qui écrit, dans sa copie
; protégée (copie_utilisateur.rs) ; sa faute d'écriture sur la page de
; zéros doit être servie (une page neuve à la place), et la copie reprendre
; là où elle en était. Un writev dont le tableau de morceaux n'a jamais
; été écrit doit lire des zéros (le noyau lit la page de zéros : des
; morceaux vides), et rendre 0, pas EFAULT. Enfin, la page
; de zéros elle-même ne doit pas avoir changé : une autre page jamais
; écrite se lit toujours à zéro. Sous Linux, sur l'hôte, mêmes lignes.
%include "commun.inc"
SYS_WRITEV equ 20
SYS_GETRANDOM equ 318
_start:
    lea rbx, [rel zone]
    mov rax, [rbx]
    or rax, [rbx + 4096 - 8]
    jnz echec
    ECRIRE lue
    mov rdi, rbx
    mov esi, 16
    xor edx, edx
    mov eax, SYS_GETRANDOM
    syscall
    cmp rax, 16
    jne echec
    ; 16 octets aléatoires tous nuls : une chance sur 2^128.
    mov rax, [rbx]
    or rax, [rbx + 8]
    jz echec
    ; Le reste de la page : toujours nul.
    mov rax, [rbx + 16]
    or rax, [rbx + 4096 - 8]
    jnz echec
    ECRIRE ecrite
    mov eax, SYS_WRITEV
    mov edi, 1
    lea rsi, [rbx + 4096]
    mov edx, 4
    syscall
    test rax, rax
    jnz echec
    ECRIRE envoye
    mov rax, [rbx + 2 * 4096]
    or rax, [rbx + 3 * 4096 - 8]
    jnz echec
    ECRIRE intacte
    SORTIR 0
echec:
    ECRIRE rate
    SORTIR 1
section .rodata
TEXTE lue, "[linux] zero : une page jamais ecrite se lit a zero."
TEXTE ecrite, "[linux] zero : getrandom y a ecrit (copie a l'ecriture faite par le noyau) : ok."
TEXTE envoye, "[linux] zero : writev d'un tableau jamais ecrit : des morceaux vides, 0 octet."
TEXTE intacte, "[linux] zero : la page de zeros est restee nulle : ok."
TEXTE rate, "[linux] ECHEC : zero."
section .bss
alignb 4096
zone: resb 3 * 4096
