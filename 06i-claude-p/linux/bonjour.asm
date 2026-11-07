; =============================================================================
;  Le premier programme Linux de l'OS, en assembleur, sans bibliothèque C
; =============================================================================
;
;  Un vrai exécutable Linux : assemblé par nasm (format objet ELF 64 bits),
;  lié par ld en un ELF statique, il tourne tel quel sous Linux
;  (`./linux/construits/bonjour-asm ; echo $?`), et dans notre noyau.
;
;  Sans bibliothèque C, un programme parle au noyau par l'instruction
;  `syscall`, avec la convention de Linux sur x86_64 :
;    rax = numéro de l'appel (1 = write, 60 = exit...) ;
;    rdi, rsi, rdx, r10, r8, r9 = les arguments, dans cet ordre ;
;    au retour, rax = le résultat (négatif : -errno) ; rcx et r11 sont
;    écrasés (le processeur y range RIP et RFLAGS).
;  Les numéros sont ceux de arch/x86/entry/syscalls/syscall_64.tbl.
; -----------------------------------------------------------------------------

SYS_WRITE equ 1
SYS_EXIT  equ 60
SORTIE    equ 1             ; Le descripteur de la sortie standard.

section .text
global _start
_start:
    ; write(1, message, longueur)
    mov eax, SYS_WRITE
    mov edi, SORTIE
    lea rsi, [rel message]
    mov edx, longueur
    syscall

    ; exit(42) : un code de sortie reconnaissable.
    mov eax, SYS_EXIT
    mov edi, 42
    syscall

section .rodata
message:  db "[linux] Bonjour depuis l'anneau 3", 10
longueur  equ $ - message
