; Le pas-à-pas (le drapeau TF de RFLAGS) armé juste avant un appel système.
; Après chaque instruction exécutée avec TF, le processeur lève une
; exception de débogage (#DB). `syscall` efface TF en entrant dans le noyau
; (le masque FMASK) : le noyau ne doit pas être pas-à-pas. Au retour, le
; noyau voit TF dans le RFLAGS du programme et revient par iretq plutôt que
; sysretq (appel_systeme.rs) ; TF revient, et la première instruction du
; programme après l'appel lève #DB, dans l'anneau 3 : SIGTRAP. C'est ce que
; vérifie aussi Linux (tools/testing/selftests/x86/single_step_syscall.c).
%include "commun.inc"
_start:
    ; write(1, debut, longueur), TF armé juste avant syscall : popfq rend TF
    ; actif à partir de l'instruction qui le suit, le syscall.
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel debut]
    mov edx, debut_longueur
    pushfq
    or qword [rsp], 1 << 8      ; TF
    popfq
    syscall
    nop                         ; #DB après celle-ci.
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : pas-a-pas (TF) a travers un appel systeme."
