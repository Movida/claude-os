; =============================================================================
;  Ce qu'un programme Linux trouve sur sa pile en démarrant
; =============================================================================
;
;  Au point d'entrée, RSP désigne argc ; au-dessus : argv[0..argc], un
;  zéro, l'environnement, un zéro, puis le vecteur auxiliaire, des paires
;  (type, valeur) terminées par le type 0 (voir noyau/src/pile.rs). Ce
;  programme, sans bibliothèque C, affiche argc et argv[0], vérifie que RSP
;  est aligné sur 16, puis cherche dans le vecteur auxiliaire la taille des
;  pages (AT_PAGESZ) et son propre point d'entrée (AT_ENTRY). Il tourne
;  aussi sous Linux, sur la machine hôte.
; -----------------------------------------------------------------------------

SYS_WRITE equ 1
SYS_EXIT  equ 60
AT_PAGESZ equ 6
AT_ENTRY  equ 9

section .text
global _start
_start:
    mov r12, rsp                ; r12 : le début des tables.

    ; « argc = N »
    lea rsi, [rel texte_argc]
    mov edx, texte_argc_longueur
    call ecrire
    mov rax, [r12]
    call ecrire_nombre

    ; « , argv[0] = nom »
    lea rsi, [rel texte_argv0]
    mov edx, texte_argv0_longueur
    call ecrire
    mov rsi, [r12 + 8]
    call longueur
    call ecrire
    call fin_de_ligne

    ; RSP aligné sur 16 au départ ?
    test r12, 15
    jnz echec

    ; Sauter argv et envp : argc + 1 mots, puis jusqu'au zéro.
    mov rax, [r12]
    lea rbx, [r12 + 8 + rax * 8 + 8]
.envp:
    cmp qword [rbx], 0
    lea rbx, [rbx + 8]
    jne .envp
    ; rbx : le vecteur auxiliaire. On y cherche AT_PAGESZ et AT_ENTRY.
    xor r13, r13                ; La taille des pages.
    xor r14, r14                ; Le point d'entrée.
.auxv:
    mov rax, [rbx]
    test rax, rax
    jz .fin_auxv
    cmp rax, AT_PAGESZ
    cmove r13, [rbx + 8]
    cmp rax, AT_ENTRY
    cmove r14, [rbx + 8]
    add rbx, 16
    jmp .auxv
.fin_auxv:
    lea rsi, [rel texte_pagesz]
    mov edx, texte_pagesz_longueur
    call ecrire
    mov rax, r13
    call ecrire_nombre
    ; AT_ENTRY doit être l'adresse de _start.
    lea rax, [rel _start]
    cmp r14, rax
    jne echec
    lea rsi, [rel texte_entree]
    mov edx, texte_entree_longueur
    call ecrire
    mov eax, SYS_EXIT
    xor edi, edi
    syscall

echec:
    lea rsi, [rel texte_echec]
    mov edx, texte_echec_longueur
    call ecrire
    mov eax, SYS_EXIT
    mov edi, 1
    syscall

; ecrire : write(1, rsi, rdx).
ecrire:
    mov eax, SYS_WRITE
    mov edi, 1
    syscall
    ret

fin_de_ligne:
    lea rsi, [rel texte_ligne]
    mov edx, 1
    jmp ecrire

; longueur : rdx = longueur de la chaîne terminée par un zéro en rsi.
longueur:
    xor edx, edx
.suivant:
    cmp byte [rsi + rdx], 0
    je .fin
    inc rdx
    jmp .suivant
.fin:
    ret

; ecrire_nombre : écrit rax en décimal. Les chiffres sont produits de
; droite à gauche (restes des divisions par 10), dans un tampon sur la pile.
ecrire_nombre:
    sub rsp, 32
    lea rsi, [rsp + 32]
    mov ecx, 10
.chiffre:
    xor edx, edx
    div rcx
    add dl, '0'
    dec rsi
    mov [rsi], dl
    test rax, rax
    jnz .chiffre
    lea rdx, [rsp + 32]
    sub rdx, rsi
    call ecrire
    add rsp, 32
    ret

section .rodata
texte_argc:   db "[linux] argc = "
texte_argc_longueur equ $ - texte_argc
texte_argv0:  db ", argv[0] = "
texte_argv0_longueur equ $ - texte_argv0
texte_pagesz: db "[linux] Pile alignee sur 16, AT_PAGESZ = "
texte_pagesz_longueur equ $ - texte_pagesz
texte_entree: db ", AT_ENTRY = _start : ok.", 10
texte_entree_longueur equ $ - texte_entree
texte_echec:  db "[linux] ECHEC : pile initiale inattendue.", 10
texte_echec_longueur equ $ - texte_echec
texte_ligne:  db 10
