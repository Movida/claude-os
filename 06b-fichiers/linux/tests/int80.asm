; L'ABI 32 bits de Linux : int 0x80, avec exit(0) dans eax = 1. L'entrée
; 0x80 de l'IDT est interdite aux programmes : faute de protection générale,
; code d'erreur 0x402 (entrée 0x80 de l'IDT) : SIGSEGV, comme sous un Linux
; compilé sans émulation 32 bits (CONFIG_IA32_EMULATION). Sous un Linux qui
; l'a, le cas courant (la machine hôte), l'appel réussit : exit(0).
%include "commun.inc"
_start:
    ECRIRE debut
    mov eax, 1
    xor ebx, ebx
    int 0x80
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : int 0x80."
