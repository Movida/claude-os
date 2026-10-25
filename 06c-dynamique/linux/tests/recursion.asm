; Une récursion sans fin : la pile grandit à la faute jusqu'à 8 Mio
; (RLIMIT_STACK), puis la faute suivante n'est plus servie. Faute de page,
; code d'erreur 6 (absente, écriture, anneau 3), pas de zone : SIGSEGV.
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
