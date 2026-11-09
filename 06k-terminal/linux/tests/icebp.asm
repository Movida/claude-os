; icebp (ou int1, l'octet 0xF1) : une exception de débogage (#DB) que tout
; programme peut lever, quel que soit le privilège de l'IDT. Elle passe par
; une pile IST du noyau : SIGTRAP. QEMU, lui, sans accélération (TCG), en
; fait une instruction invalide : SIGILL. Dans les deux cas, le programme
; doit être arrêté, et le noyau continuer. (pas-a-pas.asm lève un vrai #DB
; venu de l'anneau 3, sous QEMU aussi.)
%include "commun.inc"
_start:
    ECRIRE debut
    db 0xF1
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : icebp."
