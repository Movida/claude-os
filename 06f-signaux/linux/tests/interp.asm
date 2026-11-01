; =============================================================================
;  Un exécutable ELF écrit octet par octet, pour les PT_INTERP que gcc et ld
;  ne savent pas produire (make tests-qemu)
; =============================================================================
;
;  nasm -f bin, avec une de ces variantes (-D) :
;    MILIEU       : « /lib64/ld-linux-x86-64.so.2\0XXX\0 » : Linux ne lit que
;                   ce qui précède le premier zéro, et lance ld-linux. Le
;                   programme doit donc tourner, et le dire, s'il trouve
;                   AT_BASE non nul (ld-linux chargé par le noyau) dans son
;                   vecteur auxiliaire : sinon, un noyau qui ignorerait le
;                   PT_INTERP passerait le test ;
;    SANS_ZERO    : le chemin sans zéro final : refusé (ENOEXEC) ;
;    HORS_FICHIER : le PT_INTERP dit que le chemin va au-delà de la fin du
;                   fichier : refusé (EIO chez Linux, une lecture courte).
;
;  Un ET_EXEC à 0x400000, un seul segment (tout le fichier, R+X), et une
;  section dynamique minimale (PT_DYNAMIC : DT_STRTAB, DT_SYMTAB, DT_STRSZ,
;  DT_SYMENT, DT_NULL) : mesuré, ld-linux 2.39 fait SIGSEGV sur un programme
;  qui n'en a pas, ou qui n'a que DT_NULL. Aucune bibliothèque (pas de
;  DT_NEEDED) : le programme fait ses appels système lui-même.
; -----------------------------------------------------------------------------

bits 64
org 0x400000

ehdr:
    db 0x7f, "ELF", 2, 1, 1, 0          ; 64 bits, petit-boutiste, version 1
    times 8 db 0
    dw 2, 62                            ; ET_EXEC, x86_64
    dd 1
    dq _start                           ; e_entry
    dq phdr - ehdr                      ; e_phoff
    dq 0                                ; e_shoff : pas de sections
    dd 0
    dw 64, 56, 3, 0, 0, 0               ; tailles, 3 en-têtes de programme

phdr:
    ; PT_INTERP (3), en lecture (4).
    dd 3, 4
    dq interp - ehdr, interp, interp
%ifdef HORS_FICHIER
    dq 4096, 4096                       ; bien au-delà de la fin du fichier
%else
    dq interp_fin - interp, interp_fin - interp
%endif
    dq 1
    ; PT_LOAD (1), lecture et exécution (5) : tout le fichier.
    dd 1, 5
    dq 0, 0x400000, 0x400000
    dq fin - ehdr, fin - ehdr
    dq 0x1000
    ; PT_DYNAMIC (2).
    dd 2, 4
    dq dyn - ehdr, dyn, dyn
    dq dyn_fin - dyn, dyn_fin - dyn
    dq 8

dyn:
    dq 5, strtab                        ; DT_STRTAB
    dq 6, symtab                        ; DT_SYMTAB
    dq 10, 1                            ; DT_STRSZ
    dq 11, 24                           ; DT_SYMENT
    dq 0, 0                             ; DT_NULL
dyn_fin:
strtab: db 0
align 8
symtab: times 24 db 0                   ; le symbole nul, seul

interp:
%ifdef MILIEU
    db "/lib64/ld-linux-x86-64.so.2", 0, "XXX", 0
%else
    db "/lib64/ld-linux-x86-64.so.2"    ; SANS_ZERO, HORS_FICHIER
%ifndef SANS_ZERO
    db 0
%endif
%endif
interp_fin:

_start:
    ; ld-linux rend la main avec RSP sur argc, comme le noyau : sauter argv
    ; et envp (chacun terminé par un zéro), puis chercher AT_BASE (7) dans
    ; le vecteur auxiliaire.
    mov rax, [rsp]
    lea rbx, [rsp + 8 + rax * 8 + 8]   ; envp[0]
.envp:
    cmp qword [rbx], 0
    lea rbx, [rbx + 8]
    jne .envp
    xor r12, r12                        ; AT_BASE, 0 s'il manque.
.auxv:
    mov rax, [rbx]
    test rax, rax
    jz .fin_auxv
    cmp rax, 7
    cmove r12, [rbx + 8]
    add rbx, 16
    jmp .auxv
.fin_auxv:
    lea rsi, [rel message]
    mov edx, longueur
    xor edi, edi                        ; Le code de sortie : 0...
    test r12, r12
    jnz .ecrire
    lea rsi, [rel echec]
    mov edx, longueur_echec
    mov edi, 1                          ; ... ou 1 sans ld-linux.
.ecrire:
    mov r13d, edi
    mov eax, 1                          ; write(1, message, longueur)
    mov edi, 1
    syscall
    mov eax, 60                         ; exit(code)
    mov edi, r13d
    syscall

message: db "[linux] interp-milieu : un zero au milieu du PT_INTERP, ld-linux lance quand meme (AT_BASE non nul) : ok.", 10
longueur equ $ - message
echec: db "[linux] interp-milieu : ECHEC, AT_BASE nul : pas de ld-linux.", 10
longueur_echec equ $ - echec
fin:
