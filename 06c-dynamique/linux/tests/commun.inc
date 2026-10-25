; =============================================================================
;  Ce que partagent les programmes de test (make tests-qemu) : écrire une
;  ligne, sortir. Chaque programme est un vrai exécutable Linux, sans
;  bibliothèque C : sous Linux, sur la machine hôte, il fait la même faute,
;  et Linux l'arrête par le même signal.
; =============================================================================

SYS_WRITE equ 1
SYS_EXIT  equ 60

; ECRIRE message : write(1, message, longueur), où la longueur est le
; symbole message_longueur (défini par TEXTE).
%macro ECRIRE 1
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel %1]
    mov edx, %1_longueur
    syscall
%endmacro

; SORTIR code : exit(code).
%macro SORTIR 1
    mov eax, SYS_EXIT
    mov edi, %1
    syscall
%endmacro

; TEXTE nom, "chaîne" : la chaîne suivie d'un saut de ligne, et sa longueur.
%macro TEXTE 2
%1: db %2, 10
%1_longueur equ $ - %1
%endmacro

section .text
global _start
