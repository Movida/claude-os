; sgdt : lire l'adresse de la GDT du noyau. Avec UMIP (CR4 bit 11), c'est
; interdit en anneau 3 : faute de protection générale, SIGSEGV. Sans UMIP
; (le processeur qemu64), l'instruction réussit : le programme le dit, et
; se termine normalement. (Linux, avec UMIP, imite l'instruction pour les
; vieux programmes qui s'en servent, en donnant une fausse adresse.)
%include "commun.inc"
_start:
    ECRIRE debut
    sub rsp, 16
    sgdt [rsp]
    ECRIRE permis
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : sgdt."
TEXTE permis, "[linux] sgdt permis : le processeur n'a pas UMIP."
