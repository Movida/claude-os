; Faire grandir puis reculer son tas, sans fin, en écrivant un octet dans
; chacune de ses 8192 pages à chaque tour : sans ces écritures, brk ne
; coûterait plus rien (les pages ne viennent qu'à la faute), et le test
; ne vérifierait plus rien. Chaque tour fait donc 8192 fautes de page
; (une page neuve, mise à zéro, chacune), puis les rend. Le programme
; doit être arrêté par sa limite de temps de calcul (RLIMIT_CPU d'une
; seconde, qu'il pose lui-même : SIGXCPU), comme une boucle sans appel
; système : le temps passé dans le noyau pour lui (les fautes, brk) compte
; aussi, et l'horloge ne doit pas perdre ses tics pendant que le noyau met
; des pages à zéro. (Sous QEMU sans accélération, qui ne délivre les
; interruptions qu'entre deux blocs d'instructions traduits, des tics se
; perdent encore dans les milliers de courtes sections critiques : le
; programme peut être arrêté après plus d'une seconde réelle. Un temps de
; calcul mesuré au compteur de cycles, avec l'horloge fine de 6e, n'aura
; plus ce biais.)
%include "commun.inc"
SYS_BRK equ 12
_start:
    ECRIRE debut
    LIMITER_CALCUL 1, INFINI
    mov eax, SYS_BRK
    xor edi, edi
    syscall
    mov r12, rax
.boucle:
    lea rdi, [r12 + 32 * 1024 * 1024]
    mov eax, SYS_BRK
    syscall
    mov rbx, r12
.page:
    mov byte [rbx], 1
    add rbx, 4096
    cmp rbx, rax
    jb .page
    mov rdi, r12
    mov eax, SYS_BRK
    syscall
    jmp .boucle
section .rodata
TEXTE debut, "[linux] Test : brk qui grandit et recule sans fin."
