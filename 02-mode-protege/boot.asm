; =============================================================================
;  Étape 2a : passer du mode réel 16 bits au mode protégé 32 bits
; =============================================================================
;
;  Pourquoi quitter le mode réel ?
;    - Le mode réel n'adresse que 1 Mio (segment * 16 + offset, sur 20 bits).
;    - Aucune protection : n'importe quel code peut écraser n'importe quoi.
;    - Le mode long 64 bits (indispensable pour Claude Code, binaire x86_64)
;      ne s'atteint QUE depuis le mode protégé : c'est un passage obligé.
;
;  Le chemin, dans l'ordre :
;    1. Mettre la machine dans un état connu (segments, pile, CS).
;    2. Initialiser le port série nous-mêmes (on va perdre le BIOS).
;    3. Activer la ligne A20 (sinon les adresses « rebouclent » à 1 Mio).
;    4. Décrire la mémoire au processeur : la table GDT.
;    5. Couper les interruptions, charger la GDT (lgdt), mettre CR0.PE à 1.
;    6. Saut lointain : recharge CS avec un sélecteur de la GDT.
;    7. En 32 bits : recharger les autres segments, une pile, et parler au
;       matériel directement (mémoire vidéo 0xB8000, UART 0x3F8).
;
;  Après l'étape 5, le BIOS est INUTILISABLE : ses routines sont du code
;  16 bits mode réel. Plus de « int 0x10 » : on écrit nous-mêmes dans la
;  mémoire de la carte vidéo et dans les registres du port série.
;
;  Assemblage : nasm -f bin boot.asm -o boot.bin
; -----------------------------------------------------------------------------

[org 0x7C00]
[bits 16]

COM1 equ 0x3F8          ; Registres de l'UART 16550 : 0x3F8 à 0x3FF.

start:
    ; --- 1. État connu ----------------------------------------------------------
    cli
    ; Certains BIOS sautent à 07C0:0000 au lieu de 0000:7C00 (même adresse
    ; physique, mais CS différent). Un saut lointain fixe CS = 0 pour que
    ; nos adresses [org 0x7C00] soient justes quoi qu'il arrive.
    jmp 0x0000:.cs_ok
.cs_ok:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov ax, 0x0003      ; Mode texte 80x25 (efface l'écran).
    int 0x10

    ; --- 2. Port série ----------------------------------------------------------
    call serial_init

    mov si, msg_reel
    call print16

    ; --- 3. Ligne A20 -----------------------------------------------------------
    ; Héritage du 8086 : son bus d'adresses n'avait que 20 fils (A0..A19), donc
    ; FFFF:0010 = 0x100000 « rebouclait » sur 0x00000. Des logiciels comptaient
    ; là-dessus ; IBM a donc ajouté une porte logique qui force le fil A20 à 0.
    ; Tant qu'elle est fermée, tous les Mio impairs sont des miroirs des pairs !
    ;
    ; Méthode « Fast A20 » : bit 1 du port 0x92 (System Control Port A).
    ; Le bit 0 de ce port provoque un RESET de la machine : on le laisse à 0.
    in al, 0x92
    test al, 0x02
    jnz .a20_deja
    or al, 0x02
    and al, 0xFE
    out 0x92, al
.a20_deja:
    call a20_check      ; On ne fait pas confiance : on vérifie.
    jnz .a20_ok
    mov si, msg_a20_ko
    call print16
    jmp halt16
.a20_ok:

    ; --- 5. Bascule en mode protégé ----------------------------------------------
    ; cli AVANT tout : une interruption maintenant ferait chercher au CPU une
    ; table d'interruptions 32 bits (IDT) qui n'existe pas -> triple faute.
    cli
    lgdt [gdt_descriptor]   ; Donne au CPU l'adresse et la taille de la GDT.

    mov eax, cr0
    or eax, 1               ; Bit 0 de CR0 = PE (Protection Enable).
    mov cr0, eax

    ; --- 6. Saut lointain ---------------------------------------------------------
    ; On est techniquement en mode protégé, mais CS contient encore une valeur
    ; « mode réel » et le CPU a peut-être déjà pré-décodé des instructions en
    ; 16 bits. Un saut lointain vide la file d'instructions et charge CS avec
    ; un SÉLECTEUR : l'offset de notre descripteur de code dans la GDT.
    jmp CODE_SEL:pm_entry


; -----------------------------------------------------------------------------
;  Routines 16 bits
; -----------------------------------------------------------------------------

; serial_init : programme l'UART 16550 à 115200 bauds, 8 bits, sans parité,
; 1 bit de stop (« 8N1 »). QEMU accepte n'importe quoi, un vrai PC non.
serial_init:
    mov dx, COM1 + 1
    xor al, al
    out dx, al          ; IER = 0 : aucune interruption venant de l'UART.
    mov dx, COM1 + 3
    mov al, 0x80
    out dx, al          ; LCR bit 7 (DLAB) : 0x3F8/0x3F9 deviennent le diviseur.
    mov dx, COM1
    mov al, 1
    out dx, al          ; Diviseur = 1 -> 115200 / 1 = 115200 bauds (octet bas).
    inc dx
    xor al, al
    out dx, al          ; Octet haut du diviseur.
    mov dx, COM1 + 3
    mov al, 0x03
    out dx, al          ; LCR = 8N1, DLAB remis à 0.
    mov dx, COM1 + 2
    mov al, 0xC7
    out dx, al          ; FCR : FIFO activée et vidée.
    mov dx, COM1 + 4
    mov al, 0x03
    out dx, al          ; MCR : DTR + RTS (« je suis prêt »).
    ret

; print16 : chaîne pointée par si -> écran (BIOS) + port série.
print16:
    lodsb
    test al, al
    jz .fin
    mov ah, 0x0E
    mov bx, 0x0007
    int 0x10
    call serial_putc16
    jmp print16
.fin:
    ret

; a20_check : ZF = 0 si A20 est active, ZF = 1 sinon.
; Si A20 est fermée, 0000:0500 et FFFF:0510 désignent le même octet physique.
; On écrit deux valeurs différentes et on regarde si l'une a écrasé l'autre.
a20_check:
    push ds
    push es
    xor ax, ax
    mov ds, ax          ; ds:0x0500 = 0x000500
    not ax
    mov es, ax          ; es:0x0510 = 0xFFFF0 + 0x510 = 0x100500
    mov byte [ds:0x0500], 0x00
    mov byte [es:0x0510], 0xFF
    cmp byte [ds:0x0500], 0xFF  ; Écrasé ? Alors c'est le même octet : A20 off.
    pop es
    pop ds
    ret                 ; (cmp a positionné ZF ; pop et ret n'y touchent pas)

; serial_putc16 : envoie al sur COM1, en attendant que l'UART soit prête.
; Bit 5 du registre LSR (0x3FD) = « registre d'émission vide ». Sans cette
; attente, sur du vrai matériel, des caractères seraient perdus.
serial_putc16:
    push dx
    push ax
    mov dx, COM1 + 5
.attente:
    in al, dx
    test al, 0x20
    jz .attente
    pop ax
    mov dx, COM1
    out dx, al
    pop dx
    ret

halt16:
    cli
    hlt
    jmp halt16


; -----------------------------------------------------------------------------
;  Code 32 bits
; -----------------------------------------------------------------------------
[bits 32]
pm_entry:
    ; --- 7. Recharger les segments de données -----------------------------------
    ; En mode protégé, un registre de segment ne contient plus une adresse / 16
    ; mais un sélecteur. Le CPU lit alors le descripteur et garde base, limite
    ; et droits dans un cache caché. Les anciennes valeurs « mode réel » de
    ; ds/es/ss n'ont plus de sens : on les remplace toutes.
    mov ax, DATA_SEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x90000    ; Pile 32 bits dans une zone libre sous 640 Kio.

    mov esi, msg_protege
    mov edi, 0xB8000 + 2 * 80 * 2   ; Ligne 2 de l'écran (voir print32).
    call print32

halt32:
    cli
    hlt
    jmp halt32

; print32 : chaîne pointée par esi -> mémoire vidéo à edi + port série.
; Le mode texte VGA est une simple zone de mémoire à 0xB8000 : 2 octets par
; case (le caractère, puis l'attribut couleur), 80 cases par ligne. Écrire
; dedans, c'est écrire directement dans la RAM de la carte vidéo.
print32:
    lodsb
    test al, al
    jz .fin
    cmp al, ' '         ; Caractères de contrôle (13, 10) : pas de sens en VGA,
                        ; ils ne partent que sur le port série.
    jb .serie
    mov ah, 0x0A        ; Vert clair sur fond noir.
    mov [edi], ax       ; Little-endian : al (caractère) puis ah (couleur).
    add edi, 2
.serie:
    call serial_putc
    jmp print32
.fin:
    ret


; -----------------------------------------------------------------------------
;  serial_putc : la même chose que serial_putc16, mais assemblée en 32 bits.
;  Pourquoi deux copies ? Le même octet ne se décode pas pareil selon le mode :
;  « mov dx, 0x3FD » en [bits 32] porte un préfixe 0x66 qui, exécuté en 16
;  bits, voudrait dire « mov edx, imm32 » et avalerait 2 octets de trop.
;  Le CPU ne sait pas ce que NASM avait en tête : il décode selon CS.
; -----------------------------------------------------------------------------
serial_putc:
    push edx
    push eax
    mov dx, COM1 + 5
.attente:
    in al, dx
    test al, 0x20
    jz .attente
    pop eax
    mov dx, COM1
    out dx, al
    pop edx
    ret


; -----------------------------------------------------------------------------
;  4. La GDT (Global Descriptor Table)
; -----------------------------------------------------------------------------
;  Une table de descripteurs de 8 octets. Chaque descripteur dit au CPU :
;  « ce segment commence à BASE, mesure LIMITE, et voici ses droits ».
;  Un sélecteur (ce qu'on met dans cs, ds...) = offset du descripteur dans la
;  table : 0x00 pour le premier, 0x08 pour le deuxième, 0x10 pour le troisième.
;
;  Format d'un descripteur (octets dans l'ordre en mémoire) :
;
;    octets 0-1 : limite, bits 0-15
;    octets 2-3 : base, bits 0-15
;    octet  4   : base, bits 16-23
;    octet  5   : octet d'ACCÈS   P DPL(2) S | E DC RW A
;                   P   = présent (1, sinon faute)
;                   DPL = niveau de privilège, 0 = noyau ... 3 = utilisateur
;                   S   = 1 pour un segment de code ou de données
;                   E   = 1 code (exécutable), 0 données
;                   DC  = code : « conforming » / données : sens de croissance
;                   RW  = code : lisible / données : inscriptible
;                   A   = « accédé », positionné par le CPU
;    octet  6   : FLAGS (4 bits hauts) G DB L 0  |  limite, bits 16-19 (bas)
;                   G   = granularité : 0 -> limite en octets, 1 -> en 4 Kio
;                   DB  = 1 : segment 32 bits (0 : 16 bits)
;                   L   = 1 : code 64 bits (pour plus tard, 0 ici)
;    octet  7   : base, bits 24-31
;
;  L'ordre éclaté base/limite est un héritage du 80286 (descripteurs 16 bits
;  étendus à la va-vite par le 386).
; -----------------------------------------------------------------------------

gdt_start:

gdt_null:
    ; Le premier descripteur DOIT être nul : le sélecteur 0 sert de « pointeur
    ; nul » (on peut le charger dans ds, mais tout accès provoque une faute).
    dq 0

gdt_code:
    ; Segment de CODE noyau (sélecteur 0x08) : décrit au commit suivant.
    ; Tant qu'il vaut 0, le CPU le voit « absent » et le saut lointain
    ; provoque une faute, puis un redémarrage.
    dq 0

gdt_data:
    ; Segment de DONNÉES noyau (sélecteur 0x10) : décrit au commit suivant.
    dq 0

gdt_end:

; Ce que lit l'instruction lgdt : taille - 1 (16 bits), puis adresse (32 bits).
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEL equ gdt_code - gdt_start   ; = 0x08
DATA_SEL equ gdt_data - gdt_start   ; = 0x10


; -----------------------------------------------------------------------------
;  Messages
; -----------------------------------------------------------------------------
msg_reel:    db "[16 bits] Mode reel, A20 en cours d'activation...", 13, 10, 0
msg_a20_ko:  db "[16 bits] ERREUR : la ligne A20 refuse de s'activer.", 13, 10, 0
msg_protege: db "[32 bits] Mode protege actif ! Plus de BIOS : ecriture directe en 0xB8000.", 13, 10, 0

times 510 - ($ - $$) db 0
dw 0xAA55
