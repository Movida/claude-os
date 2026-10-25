; Lire une adresse du noyau : la page est présente, mais sans le bit
; UTILISATEUR. Faute de page, code d'erreur 5 (présente, anneau 3) : SIGSEGV.
%include "commun.inc"
_start:
    ECRIRE debut
    mov rax, 0xffffffff80100000
    mov rax, [rax]
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : lire la memoire du noyau."
