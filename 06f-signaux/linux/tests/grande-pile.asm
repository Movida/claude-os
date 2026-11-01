; La pile grandit à la demande : une faute de page sous elle l'étend,
; jusqu'à 8 Mio (RLIMIT_STACK). Une récursion de 7 Mio passe ; une de
; 9 Mio est arrêtée à 8 Mio par une faute de page qui n'est plus servie
; (code 6 : absente, écriture, anneau 3 ; pas de zone) : SIGSEGV. Sous
; Linux, sur l'hôte (ulimit -s 8192, la valeur par défaut), de même.
%include "commun.inc"
_start:
    ECRIRE debut
    mov ecx, 7 * 256
    call descendre
    ECRIRE sept
    mov ecx, 9 * 256
    call descendre
    ECRIRE rate
    SORTIR 1
; ecx cadres de 4 Kio chacun (l'adresse de retour, puis le reste), en
; écrivant un octet dans chacun : la pile descend page par page.
descendre:
    sub rsp, 4096 - 8
    mov byte [rsp], 0
    dec ecx
    jz .fond
    call descendre
.fond:
    add rsp, 4096 - 8
    ret
section .rodata
TEXTE debut, "[linux] Test : pile de 7 Mio, puis de 9 Mio."
TEXTE sept, "[linux] Pile de 7 Mio : ok."
TEXTE rate, "[linux] ECHEC : pile de 9 Mio acceptee."
