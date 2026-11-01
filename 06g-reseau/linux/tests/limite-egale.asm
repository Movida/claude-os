; Une boucle sans fin, sous une limite de temps de calcul courante ÉGALE à
; la limite dure (une seconde) : Linux vérifie la dure d'abord, et tue le
; programme par SIGKILL (code 137), sans SIGXCPU (mesuré).
%include "commun.inc"
_start:
    ECRIRE debut
    LIMITER_CALCUL 1, 1
.boucle:
    jmp .boucle
section .rodata
TEXTE debut, "[linux] Test : boucle sans fin sous RLIMIT_CPU (1 s, 1 s)."
