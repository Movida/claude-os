; Une boucle sans fin, sans appel système : seule l'horloge peut l'arrêter,
; quand le programme a épuisé son temps (1 s) : SIGXCPU.
%include "commun.inc"
_start:
    ECRIRE debut
.boucle:
    jmp .boucle
section .rodata
TEXTE debut, "[linux] Test : boucle sans fin."
