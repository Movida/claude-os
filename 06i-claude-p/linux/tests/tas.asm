; Le tas, par brk : l'agrandir de 3 pages et écrire tout au bout, le
; réduire à 1 page, puis toucher une page retirée. Elle doit avoir
; disparu, même du cache des traductions du processeur (TLB) : faute de
; page, SIGSEGV. Entre-temps, deux fois 100 Mio de plus : 200 Mio en
; tout, plus que la mémoire de la machine dans QEMU (128 Mio), doivent
; être ACCEPTÉS (le surengagement de Linux : ils ne coûtent rien tant
; qu'on n'y touche pas, et seule une demande plus grande à elle seule que
; toute la mémoire est refusée) ; puis 1 Tio de plus, justement plus
; grand que toute la mémoire, doit être refusé (brk rend l'ancienne fin).
; Sous Linux, avec le réglage par défaut (vm.overcommit_memory = 0),
; de même ; avec vm.overcommit_memory = 1 (« toujours »), le Tio passe.
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
    ; Deux fois 100 Mio : promis.
    lea rbx, [r12 + 100 * 1024 * 1024]
    mov rdi, rbx
    mov eax, SYS_BRK
    syscall
    cmp rax, rbx
    jne echec
    lea rbx, [r12 + 200 * 1024 * 1024]
    mov rdi, rbx
    mov eax, SYS_BRK
    syscall
    cmp rax, rbx
    jne echec
    ECRIRE accepte
    ; 1 Tio de plus : refusé, la fin ne bouge pas.
    mov rdi, 1 << 40
    add rdi, r12
    mov eax, SYS_BRK
    syscall
    cmp rax, rbx
    jne echec
    ECRIRE refuse
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
TEXTE accepte, "[linux] brk : tas agrandi de 3 pages, puis 2 x 100 Mio, plus que la machine : acceptes."
TEXTE refuse, "[linux] brk : 1 Tio de plus, plus que toute la memoire : refuse."
TEXTE reduit, "[linux] brk : tas reduit a 1 page, on touche une page retiree."
TEXTE rate, "[linux] ECHEC : brk inattendu."
