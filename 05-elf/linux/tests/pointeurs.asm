; Des appels système avec de mauvais arguments : le noyau doit répondre par
; une erreur, et le programme continuer.
;   - write depuis une adresse du noyau, une adresse non projetée, une
;     plage qui franchit la fin des adresses permises : -EFAULT (-14) ;
;   - un appel inconnu (numéro 9999) : -ENOSYS (-38).
%include "commun.inc"

; ESSAYER numéro, adresse, longueur, attendu, message : l'appel système
; doit rendre `attendu`, sinon on écrit ECHEC.
%macro ESSAYER 5
    mov eax, %1
    mov edi, 1
    mov rsi, %2
    mov edx, %3
    syscall
    cmp rax, %4
    jne echec
    ECRIRE %5
%endmacro

_start:
    ESSAYER SYS_WRITE, 0xffffffff80100000, 16, -14, noyau
    ESSAYER SYS_WRITE, 0x10000000, 16, -14, absente
    ; Les 8 derniers octets de la pile, et 8 de plus, dans la dernière page
    ; de la moitié basse, interdite.
    ESSAYER SYS_WRITE, 0x7fffffffeff8, 16, -14, franchit
    ESSAYER 9999, 0, 0, -38, inconnu
    SORTIR 0
echec:
    ECRIRE rate
    SORTIR 1
section .rodata
TEXTE noyau, "[linux] write(adresse du noyau) : -EFAULT, on continue."
TEXTE absente, "[linux] write(adresse non projetee) : -EFAULT, on continue."
TEXTE franchit, "[linux] write(plage qui franchit la limite) : -EFAULT, on continue."
TEXTE inconnu, "[linux] appel 9999 : -ENOSYS, on continue."
TEXTE rate, "[linux] ECHEC : resultat inattendu."
