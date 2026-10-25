; =============================================================================
;  Un interpréteur à la table des en-têtes de programme bien remplie
;  (make tests-qemu)
; =============================================================================
;
;  Un ET_DYN qui sert d'interpréteur (PT_INTERP) au programme interp-gros :
;  48 en-têtes (2688 octets), un segment, puis 47 PT_NOTE vides. Le noyau
;  copie cette table dans un bloc du tas pour la vérifier : il doit le
;  rendre avant de compter la mémoire du programme, sinon « memoire
;  rendue » dirait ECHEC à tort (un bloc de plus de 2 Kio vient de
;  l'allocateur de pages, pas d'une classe du tas). Il ne charge rien : il
;  écrit une ligne, et termine le programme.
; -----------------------------------------------------------------------------

bits 64
org 0
ENTETES equ 48

ehdr:
    db 0x7f, "ELF", 2, 1, 1, 0
    times 8 db 0
    dw 3, 62                            ; ET_DYN, x86_64
    dd 1
    dq _start
    dq phdr - ehdr
    dq 0
    dd 0
    dw 64, 56, ENTETES, 0, 0, 0

phdr:
    ; PT_LOAD (1), lecture et exécution (5) : tout le fichier, à l'adresse 0.
    dd 1, 5
    dq 0, 0, 0
    dq fin - ehdr, fin - ehdr
    dq 0x1000
%rep ENTETES - 1
    dd 4, 4                             ; PT_NOTE vide
    dq 0, 0, 0, 0, 0, 4
%endrep

_start:
    mov eax, 1                          ; write(1, message, longueur)
    mov edi, 1
    lea rsi, [rel message]
    mov edx, longueur
    syscall
    mov eax, 60                         ; exit(0)
    xor edi, edi
    syscall

message: db "[linux] interp-gros : un interpreteur de 48 en-tetes de programme a tourne.", 10
longueur equ $ - message
fin:
