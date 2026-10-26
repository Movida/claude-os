; Laisse des valeurs dans les registres x87/MMX (mm0, mm7) et SSE (xmm0),
; et un mot de contrôle x87 changé, pour le programme suivant (mmx-lit).
%include "commun.inc"
_start:
    mov rax, 0x2153454352455453     ; « STERCES! »
    movq mm0, rax
    movq mm7, rax
    movq xmm0, rax
    fnstcw [rsp - 8]
    or word [rsp - 8], 0x0C00       ; Arrondi vers zéro.
    fldcw [rsp - 8]
    ECRIRE texte
    SORTIR 0
section .rodata
TEXTE texte, "[linux] mmx-ecrit : mm0, mm7 et xmm0 remplis, arrondi x87 change."
