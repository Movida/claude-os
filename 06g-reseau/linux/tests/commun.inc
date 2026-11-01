; =============================================================================
;  Ce que partagent les programmes de test (make tests-qemu) : écrire une
;  ligne, sortir. Chaque programme est un vrai exécutable Linux, sans
;  bibliothèque C : sous Linux, sur la machine hôte, il fait la même faute,
;  et Linux l'arrête par le même signal.
; =============================================================================

SYS_WRITE    equ 1
SYS_EXIT     equ 60
SYS_PRLIMIT64 equ 302
RLIMIT_CPU   equ 0
INFINI       equ -1                ; RLIM_INFINITY, une fois sur 64 bits

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

; LIMITER_CALCUL courante, dure : prlimit64(0, RLIMIT_CPU, {courante,
; dure}, NULL), en secondes. Un programme qui veut que le noyau l'arrête
; s'il calcule trop longtemps pose lui-même sa limite, comme sous Linux
; (elle est infinie par défaut). La structure est posée sur la pile, le
; temps de l'appel.
%macro LIMITER_CALCUL 2
    sub rsp, 16
    mov qword [rsp], %1
    mov qword [rsp + 8], %2
    mov eax, SYS_PRLIMIT64
    xor edi, edi
    mov esi, RLIMIT_CPU
    mov rdx, rsp
    xor r10d, r10d
    syscall
    add rsp, 16
%endmacro
