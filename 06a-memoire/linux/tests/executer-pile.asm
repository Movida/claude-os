; Exécuter des octets posés sur la pile : la pile n'est pas exécutable
; (bit NX). Faute de page, code d'erreur 0x15 (page présente, anneau 3,
; lecture d'instruction) : SIGSEGV.
%include "commun.inc"
_start:
    ECRIRE debut
    sub rsp, 64
    mov byte [rsp], 0xC3        ; ret
    jmp rsp
section .rodata
TEXTE debut, "[linux] Test : executer la pile."
