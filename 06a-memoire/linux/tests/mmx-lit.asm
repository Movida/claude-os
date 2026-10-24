; Lancé après mmx-ecrit : un programme doit démarrer avec tous les
; registres x87, MMX et SSE à zéro, le mot de contrôle x87 à 0x037F et
; MXCSR à 0x1F80, comme sous Linux. Rien de ce qu'a laissé le programme
; précédent.
%include "commun.inc"
_start:
    movq rax, mm0
    movq rbx, mm7
    or rax, rbx
    movq rbx, xmm0
    or rax, rbx
    jnz fuite
    fnstcw [rsp - 8]
    cmp word [rsp - 8], 0x037F
    jne fuite
    stmxcsr [rsp - 16]
    cmp dword [rsp - 16], 0x1F80
    jne fuite
    ECRIRE propre
    SORTIR 0
fuite:
    ECRIRE sale
    SORTIR 1
section .rodata
TEXTE propre, "[linux] mmx-lit : registres x87, MMX et SSE a l'etat initial : ok."
TEXTE sale, "[linux] ECHEC : mmx-lit trouve l'etat du programme precedent."
