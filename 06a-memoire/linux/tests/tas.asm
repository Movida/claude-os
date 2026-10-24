; Le tas, par brk : l'agrandir de 3 pages et écrire tout au bout, le
; réduire à 1 page, puis toucher une page retirée. Elle doit avoir
; disparu, même du cache des traductions du processeur (TLB) : faute de
; page, SIGSEGV. Entre-temps, un tas plus grand que le budget de mémoire
; du programme (256 Mio) doit être refusé par notre noyau (brk rend
; l'ancienne fin). Linux, sans budget par défaut, l'accepte : le programme
; dit alors ce qu'il a reçu, et continue.
%include "commun.inc"
SYS_BRK equ 12
_start:
    mov eax, SYS_BRK
    xor edi, edi
    syscall
    mov r12, rax                ; r12 : le début du tas.
    ; 3 pages et 10 octets.
    lea rdi, [r12 + 3 * 4096 + 10]
    mov eax, SYS_BRK
    syscall
    lea rbx, [r12 + 3 * 4096 + 10]
    cmp rax, rbx
    jne echec
    mov byte [r12 + 3 * 4096 + 9], 1     ; Le dernier octet du tas.
    mov byte [r12 + 2 * 4096], 1         ; La 3e page, utilisée : en cache.
    ; 300 Mio : au-delà du budget.
    lea rdi, [r12 + 300 * 1024 * 1024]
    mov eax, SYS_BRK
    syscall
    cmp rax, rbx
    jne .accepte
    ECRIRE budget
    jmp .reduire
.accepte:
    ECRIRE accepte
.reduire:
    ; Réduit à 1 page.
    lea rdi, [r12 + 4096]
    mov eax, SYS_BRK
    syscall
    ECRIRE reduit
    mov al, [r12 + 2 * 4096]             ; Retirée : faute.
    SORTIR 0
echec:
    ECRIRE rate
    SORTIR 1
section .rodata
TEXTE budget, "[linux] brk : tas agrandi de 3 pages ; 300 Mio refuses (budget)."
TEXTE accepte, "[linux] brk : tas agrandi de 3 pages ; 300 Mio acceptes (pas de budget)."
TEXTE reduit, "[linux] brk : tas reduit a 1 page, on touche une page retiree."
TEXTE rate, "[linux] ECHEC : brk inattendu."
