; =============================================================================
;  Étape 2b : du mode réel 16 bits au mode long 64 bits
; =============================================================================
;
;  Le passage en 64 bits ne tient plus dans les 512 octets que le BIOS
;  charge : il faut vérifier le CPU, construire des tables de pages, ajouter
;  un descripteur 64 bits... On fait donc comme tous les vrais chargeurs
;  (GRUB, le chargeur de Windows, celui de FreeBSD) : un démarrage en DEUX
;  TEMPS.
;
;    1er étage (secteur 0, chargé par le BIOS en 0x7C00) : remet la machine
;       dans un état connu, puis demande au BIOS de lire les secteurs
;       suivants du disque, juste derrière lui en mémoire (0x7E00).
;    2e étage (secteurs 1 et suivants) : tout le reste, sans limite de taille.
;
;  Un seul fichier source pour les deux étages : le 2e est chargé pile à
;  l'adresse qui suit le 1er, donc [org 0x7C00] reste juste pour tout le
;  fichier et les étiquettes du 2e étage ont directement les bonnes adresses.
;
;  Assemblage : nasm -f bin boot.asm -o boot.bin  (image de plusieurs secteurs)
; -----------------------------------------------------------------------------

[org 0x7C00]
[bits 16]

COM1 equ 0x3F8          ; Registres de l'UART 16550 : 0x3F8 à 0x3FF.

; Nombre de secteurs du 2e étage, calculé par NASM à partir de la taille du
; code : on n'a jamais à le tenir à jour à la main.
NB_SECTEURS equ (fin_image - etage2 + 511) / 512


; =============================================================================
;  1er ÉTAGE : 512 octets, signature comprise
; =============================================================================
start:
    ; --- État connu -------------------------------------------------------------
    cli
    jmp 0x0000:.cs_ok   ; Certains BIOS arrivent en 07C0:0000 : on fixe CS = 0.
.cs_ok:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    ; Le BIOS met dans dl le numéro du disque dont il vient de démarrer
    ; (0x80 = premier disque dur, 0x00 = disquette...). C'est le seul moyen
    ; de savoir où lire la suite : on le garde précieusement, avant que le
    ; moindre appel au BIOS ne l'écrase.
    mov [disque], dl

    mov ax, 0x0003      ; Mode texte 80x25 (efface l'écran).
    int 0x10

    call serial_init
    mov si, msg_charge
    call print16

    ; --- Lire le 2e étage ---------------------------------------------------------
    ; Deux façons de parler au disque via le BIOS :
    ;   - ah=0x02, adressage CHS (cylindre, tête, secteur) : l'API de 1981,
    ;     limitée à ~8 Gio et qui oblige à connaître la géométrie du disque ;
    ;   - ah=0x42, adressage LBA (« secteur numéro N ») : les « extensions
    ;     disque » des BIOS depuis 1998, ce que GRUB utilise. On prend LBA.
    ; On vérifie d'abord que le BIOS connaît ces extensions (ah=0x41) : il
    ; répond en inversant la valeur magique 0x55AA dans bx.
    mov ah, 0x41
    mov bx, 0x55AA
    mov dl, [disque]
    int 0x13
    jc erreur_disque
    cmp bx, 0xAA55
    jne erreur_disque

    mov ah, 0x42
    mov dl, [disque]
    mov si, dap         ; ds:si -> le paquet qui décrit la lecture.
    int 0x13
    jc erreur_disque    ; CF = 1 : le BIOS signale une erreur de lecture.

    jmp etage2

erreur_disque:
    mov si, msg_disque_ko
    call print16
    ; (on tombe dans halt16)

halt16:
    cli
    hlt
    jmp halt16

; Le « Disk Address Packet » que lit l'appel ah=0x42 (format fixé par la
; spécification des extensions disque du BIOS).
dap:
    db 0x10             ; Taille du paquet : 16 octets.
    db 0                ; Réservé.
    dw NB_SECTEURS      ; Combien de secteurs lire.
    dw etage2           ; Où les ranger : offset...
    dw 0                ; ... et segment (0000:7E00).
    dq 1                ; Premier secteur à lire (LBA 1 : juste après nous).

disque: db 0


; -----------------------------------------------------------------------------
;  Routines 16 bits (dans le 1er étage : le 2e s'en sert aussi)
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

; serial_putc16 : envoie al sur COM1, en attendant que l'UART soit prête.
serial_putc16:
    push dx
    push ax
    mov dx, COM1 + 5
.attente:
    in al, dx
    test al, 0x20       ; LSR bit 5 : registre d'émission vide.
    jz .attente
    pop ax
    mov dx, COM1
    out dx, al
    pop dx
    ret

msg_charge:    db "[16 bits] 1er etage : lecture de la suite sur le disque...", 13, 10, 0
msg_disque_ko: db "[16 bits] ERREUR : lecture du disque impossible.", 13, 10, 0

times 510 - ($ - $$) db 0
dw 0xAA55


; =============================================================================
;  2e ÉTAGE : chargé en 0x7E00 par le 1er étage
; =============================================================================
etage2:
    mov si, msg_etage2
    call print16
    jmp halt16

msg_etage2: db "[16 bits] 2e etage charge depuis le disque.", 13, 10, 0

fin_image:
; On complète jusqu'à un nombre entier de secteurs : un disque ne se lit
; que par secteurs entiers de 512 octets.
times (512 - ($ - $$) % 512) % 512 db 0
