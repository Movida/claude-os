; La forme de la faille CVE-2018-8897, avec un pas-à-pas : `mov ss` retarde
; toute exception de débogage jusqu'après l'instruction suivante, ici le
; `syscall`. Avec un point d'arrêt matériel sur la donnée lue par `mov ss`,
; le #DB tombe sur la première instruction du noyau, encore sur la pile du
; programme (d'où la pile IST de #DB, voir noyau/src/gdt.rs). Avec TF, un
; vrai processeur sert l'appel et lève le #DB au retour dans le programme
; (vérifié sur la machine hôte) ; QEMU, sans accélération, le lève juste
; avant le `syscall`. Dans les deux cas : SIGTRAP en anneau 3, et le noyau
; continue.
%include "commun.inc"
_start:
    ECRIRE debut
    mov eax, SYS_WRITE
    mov edi, 1
    lea rsi, [rel servi]
    mov edx, servi_longueur
    mov ecx, ss
    pushfq
    or qword [rsp], 1 << 8      ; TF
    popfq
    mov ss, ecx
    syscall
    nop
    SORTIR 0
section .rodata
TEXTE debut, "[linux] Test : mov ss, puis syscall, avec TF."
TEXTE servi, "[linux] mov-ss : appel systeme servi."
