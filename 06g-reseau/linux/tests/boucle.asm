; Une boucle sans fin, sans appel système : seule l'horloge peut l'arrêter,
; quand le programme atteint la limite de temps de calcul qu'il s'est
; donnée (RLIMIT_CPU d'une seconde, sans limite dure) : SIGXCPU. Avec une
; limite dure d'une seconde aussi, ce serait SIGKILL (limite-egale).
%include "commun.inc"
_start:
    ECRIRE debut
    LIMITER_CALCUL 1, INFINI
.boucle:
    jmp .boucle
section .rodata
TEXTE debut, "[linux] Test : boucle sans fin."
