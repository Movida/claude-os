; Projeter son propre fichier à 1 Gio au-delà de sa fin (mmap le permet),
; puis lire la page : elle n'existe pas dans le fichier. Faute de page dans
; une zone de fichier, au-delà de la fin : SIGBUS (code de sortie 135),
; comme sous Linux. Le chemin du fichier est argv[0] : le même programme
; fait la même chose sur l'hôte.
%include "commun.inc"

SYS_OPEN equ 2
SYS_MMAP equ 9
PROT_READ equ 1
MAP_PRIVATE equ 2

_start:
    ECRIRE debut
    ; open(argv[0], O_RDONLY) : argv[0] est juste au-dessus d'argc.
    mov rdi, [rsp + 8]
    xor esi, esi
    mov eax, SYS_OPEN
    syscall
    test rax, rax
    js .rate
    ; mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 1 Gio)
    mov r8, rax
    xor edi, edi
    mov esi, 4096
    mov edx, PROT_READ
    mov r10d, MAP_PRIVATE
    mov r9, 1 << 30
    mov eax, SYS_MMAP
    syscall
    cmp rax, -4096
    ja .rate
    ; La lecture : SIGBUS.
    mov al, [rax]
    SORTIR 0
.rate:
    ECRIRE rate
    SORTIR 1

section .rodata
TEXTE debut, "[linux] Test : lire une projection au-dela de la fin du fichier."
TEXTE rate, "[linux] bus-fichier : open ou mmap a echoue."
