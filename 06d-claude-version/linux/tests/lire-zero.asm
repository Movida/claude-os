; Lire l'adresse 0 (un pointeur nul) : rien n'est projeté sous 64 Kio.
; Faute de page, code d'erreur 4 (absente, lecture, anneau 3) : SIGSEGV.
%include "commun.inc"
_start:
    ECRIRE debut
    xor eax, eax
    mov rax, [rax]
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : lire l'adresse 0."
