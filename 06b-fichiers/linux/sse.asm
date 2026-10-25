; =============================================================================
;  Un calcul en SSE2, sans bibliothèque C
; =============================================================================
;
;  La racine carrée de 2, en double précision (sqrtsd), multipliée par un
;  million, convertie en entier (cvttsd2si) ; puis une addition de quatre
;  entiers à la fois (paddd), dans un registre XMM de 128 bits. Sans
;  CR4.OSFXSR, la première instruction SSE ferait une exception
;  « instruction invalide », et le programme serait arrêté (SIGILL).
; -----------------------------------------------------------------------------

SYS_WRITE equ 1
SYS_EXIT  equ 60

section .text
global _start
_start:
    ; 1 414 213 = racine de 2 x 1 000 000, tronquée.
    movsd xmm0, [rel deux]
    sqrtsd xmm0, xmm0
    mulsd xmm0, [rel million]
    cvttsd2si rax, xmm0
    cmp rax, 1414213
    jne echec
    ; (1, 2, 3, 4) + (10, 20, 30, 40) = (11, 22, 33, 44)
    movdqu xmm1, [rel quatre_a]
    movdqu xmm2, [rel quatre_b]
    paddd xmm1, xmm2
    movdqu xmm3, [rel quatre_somme]
    pcmpeqd xmm1, xmm3
    pmovmskb eax, xmm1          ; 16 bits à 1 si les quatre sont égaux.
    cmp eax, 0xFFFF
    jne echec
    lea rsi, [rel reussi]
    mov edx, reussi_longueur
    mov eax, SYS_WRITE
    mov edi, 1
    syscall
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
echec:
    lea rsi, [rel rate]
    mov edx, rate_longueur
    mov eax, SYS_WRITE
    mov edi, 1
    syscall
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

section .rodata
align 16
deux:         dq 2.0
million:      dq 1000000.0
quatre_a:     dd 1, 2, 3, 4
quatre_b:     dd 10, 20, 30, 40
quatre_somme: dd 11, 22, 33, 44
reussi: db "[linux] SSE2 : racine de 2 x 1000000 = 1414213, (1,2,3,4) + (10,20,30,40) = (11,22,33,44) : ok.", 10
reussi_longueur equ $ - reussi
rate:   db "[linux] ECHEC : calcul SSE2 faux.", 10
rate_longueur equ $ - rate
