; Une pile exécutable, parce que le programme la demande : il est lié avec
; `ld -z execstack`, qui écrit un en-tête PT_GNU_STACK avec PF_X. Linux
; rend alors la pile exécutable ; le noyau aussi. Le programme pose sur sa
; pile « mov eax, 42 ; ret », l'appelle, et doit recevoir 42. (Sans cette
; demande, la même chose est arrêtée : voir executer-pile.)
%include "commun.inc"
_start:
    sub rsp, 64
    mov dword [rsp], 0x00002AB8     ; B8 2A 00 00 : mov eax, 42...
    mov word [rsp + 4], 0xC300      ; ... 00 C3 : la fin, et ret.
    call rsp
    cmp eax, 42
    jne echec
    ECRIRE execute
    SORTIR 0
echec:
    ECRIRE rate
    SORTIR 1
section .rodata
TEXTE execute, "[linux] Pile executable (PT_GNU_STACK) : code pose sur la pile puis execute : ok."
TEXTE rate, "[linux] ECHEC : pile executable."
