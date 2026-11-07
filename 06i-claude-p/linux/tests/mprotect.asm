; mprotect, comme le compilateur à la volée (JIT) d'un moteur JavaScript :
; une page de données rendue inscriptible ET exécutable, du code écrit
; dedans puis exécuté (permis, comme sous Linux) ; mprotect sur une page
; absente : -ENOMEM ; puis la page rendue inaccessible (PROT_NONE), et lue :
; faute de page, SIGSEGV.
%include "commun.inc"
SYS_MPROTECT equ 10
PROT_READ  equ 1
PROT_WRITE equ 2
PROT_EXEC  equ 4
_start:
    lea rdi, [rel page]
    mov esi, 4096
    mov edx, PROT_READ | PROT_WRITE | PROT_EXEC
    mov eax, SYS_MPROTECT
    syscall
    test rax, rax
    jnz echec
    ; mov eax, 42 ; ret
    lea rbx, [rel page]
    mov dword [rbx], 0x00002AB8
    mov word [rbx + 4], 0xC300
    call rbx
    cmp eax, 42
    jne echec
    ECRIRE jit
    mov edi, 0x10000000
    mov esi, 4096
    mov edx, PROT_READ
    mov eax, SYS_MPROTECT
    syscall
    cmp rax, -12
    jne echec
    ECRIRE absente
    lea rdi, [rel page]
    mov esi, 4096
    xor edx, edx                ; PROT_NONE
    mov eax, SYS_MPROTECT
    syscall
    test rax, rax
    jnz echec
    ECRIRE aucun
    mov al, [rel page]          ; Inaccessible : faute.
    SORTIR 0
echec:
    ECRIRE rate
    SORTIR 1
section .rodata
TEXTE jit, "[linux] mprotect W+X : code ecrit puis execute (JIT) : ok."
TEXTE absente, "[linux] mprotect d'une page absente : -ENOMEM."
TEXTE aucun, "[linux] mprotect PROT_NONE, puis lecture de la page."
TEXTE rate, "[linux] ECHEC : mprotect inattendu."
section .bss
alignb 4096
page: resb 4096
