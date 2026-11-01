; Arrêter le processeur : hlt est réservé à l'anneau 0. Faute de
; protection générale : SIGSEGV.
%include "commun.inc"
_start:
    ECRIRE debut
    hlt
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : hlt."
