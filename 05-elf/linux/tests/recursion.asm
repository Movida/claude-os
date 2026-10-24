; Une récursion sans fin : la pile (128 Kio projetés) déborde sur la page
; en dessous, absente. Faute de page, code d'erreur 6 (absente, écriture,
; anneau 3) : SIGSEGV.
%include "commun.inc"
_start:
    ECRIRE debut
    call recurser
    SORTIR 0
recurser:
    sub rsp, 512
    call recurser
    ret
section .rodata
TEXTE debut, "[linux] Test : recursion sans fin."
