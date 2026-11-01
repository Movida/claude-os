; Écrire dans son propre code : la page est en lecture et exécution
; seulement (W^X). Faute de page, code d'erreur 7 (page présente, écriture,
; anneau 3) : SIGSEGV.
%include "commun.inc"
_start:
    ECRIRE debut
    lea rax, [rel _start]
    mov byte [rax], 0x90
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : ecrire dans son propre code."
