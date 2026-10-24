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

    ; --- Ligne A20 -----------------------------------------------------------
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

    ; --- Bascule en mode protégé ----------------------------------------------
    ; cli AVANT tout : une interruption maintenant ferait chercher au CPU une
    ; table d'interruptions 32 bits (IDT) qui n'existe pas -> triple faute.
    cli
    lgdt [gdt_descriptor]   ; Donne au CPU l'adresse et la taille de la GDT.

    mov eax, cr0
    or eax, 1               ; Bit 0 de CR0 = PE (Protection Enable).
    mov cr0, eax

    ; --- Saut lointain ---------------------------------------------------------
    ; On est techniquement en mode protégé, mais CS contient encore une valeur
    ; « mode réel » et le CPU a peut-être déjà pré-décodé des instructions en
    ; 16 bits. Un saut lointain vide la file d'instructions et charge CS avec
    ; un SÉLECTEUR : l'offset de notre descripteur de code dans la GDT.
    jmp CODE_SEL:pm_entry


; Routine 16 bits propre au 2e étage.
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

; -----------------------------------------------------------------------------
;  Code 32 bits
; -----------------------------------------------------------------------------
[bits 32]
pm_entry:
    ; --- Recharger les segments de données -----------------------------------
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

    ; --- Le CPU sait-il faire du 64 bits ? -----------------------------------
    ; L'instruction cpuid répond à des questions numérotées (eax en entrée).
    ; Le bit « LM » (Long Mode, bit 29 de edx pour la question 0x80000001)
    ; dit si le processeur a un mode 64 bits. Mais avant de poser la question
    ; 0x80000001, il faut demander (0x80000000) jusqu'où vont les questions
    ; « étendues » que ce CPU comprend : un vieux CPU répondrait n'importe quoi.
    ;
    ; On ne teste pas si cpuid existe (bit ID de eflags) : tous les CPU
    ; depuis le Pentium l'ont, et un CPU 64 bits l'a forcément.
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .pas_de_64
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .pas_de_64

    mov esi, msg_cpu64
    mov edi, 0xB8000 + 3 * 80 * 2
    call print32
    jmp halt32

.pas_de_64:
    ; Message clair plutôt qu'une triple faute (redémarrage en boucle)
    ; plus loin : sur un vieux PC, l'utilisateur saura pourquoi.
    mov esi, msg_pas_64
    mov edi, 0xB8000 + 3 * 80 * 2
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
;  La GDT (Global Descriptor Table), reprise de l'étape 2a
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
    ; Segment de CODE noyau (sélecteur 0x08), modèle « plat » :
    ; base 0, limite maximale, donc il couvre les 4 Gio.
    ;
    ; Pourquoi le modèle plat ? C'est le choix de Linux, de Windows et de
    ; tous les noyaux modernes :
    ;   - la protection mémoire viendra de la PAGINATION (étape 3), plus fine
    ;     (pages de 4 Kio) et la seule qui existe encore en 64 bits ;
    ;   - en mode long, le CPU ignore base et limite des segments de code et
    ;     de données : investir dans la segmentation serait du travail perdu ;
    ;   - un compilateur C suppose qu'un pointeur est une simple adresse,
    ;     identique quel que soit le segment : c'est vrai seulement si tous
    ;     les segments commencent à 0.
    dw 0xFFFF           ; Limite, bits 0-15.
    dw 0x0000           ; Base, bits 0-15.
    db 0x00             ; Base, bits 16-23.
    db 10011011b        ; Accès : P=1 (présent), DPL=00 (noyau), S=1,
                        ;   E=1 (code), DC=0 (non « conforming » : un code
                        ;   moins privilégié ne peut pas sauter ici),
                        ;   RW=1 (lisible : permet de lire des constantes
                        ;   rangées au milieu du code), A=1.
                        ; A=1 d'avance, comme le fait Linux : sinon le CPU
                        ; écrit lui-même ce bit dans la table au premier
                        ; chargement, ce qui échoue si la GDT est en mémoire
                        ; protégée en lecture seule.
    db 11001111b        ; Flags G=1 (limite en blocs de 4 Kio), DB=1
                        ;   (32 bits), L=0, puis limite bits 16-19 = 0xF.
                        ; Limite 0xFFFFF x 4 Kio = 4 Gio : tout l'espace 32 bits.
    db 0x00             ; Base, bits 24-31.

gdt_data:
    ; Segment de DONNÉES noyau (sélecteur 0x10) : le jumeau du code, même
    ; base, même limite, mêmes flags. Seul l'octet d'accès change.
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 10010011b        ; Accès : P=1, DPL=00, S=1, E=0 (données),
                        ;   DC=0 (croît vers le haut, le cas normal),
                        ;   RW=1 (inscriptible : indispensable pour la pile
                        ;   et les variables), A=1.
    db 11001111b        ; Pour des données, DB=1 veut dire que la pile
                        ;   utilise esp (32 bits) et non sp.
    db 0x00

; Pas encore de segments utilisateur (DPL=3) ni de TSS : ils arriveront avec
; les processus. Le mode 64 bits demandera un descripteur de code avec L=1.

gdt_end:

; Ce que lit l'instruction lgdt : taille - 1 (16 bits), puis adresse (32 bits).
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEL equ gdt_code - gdt_start   ; = 0x08
DATA_SEL equ gdt_data - gdt_start   ; = 0x10


; -----------------------------------------------------------------------------
;  Messages du 2e étage
; -----------------------------------------------------------------------------
msg_etage2:  db "[16 bits] 2e etage charge depuis le disque.", 13, 10, 0
msg_a20_ko:  db "[16 bits] ERREUR : la ligne A20 refuse de s'activer.", 13, 10, 0
msg_protege: db "[32 bits] Mode protege actif.", 13, 10, 0
msg_cpu64:   db "[32 bits] Le processeur sait passer en 64 bits (cpuid, bit LM).", 13, 10, 0
msg_pas_64:  db "[32 bits] ERREUR : ce processeur n'a pas de mode 64 bits.", 13, 10, 0

fin_image:
; On complète jusqu'à un nombre entier de secteurs : un disque ne se lit
; que par secteurs entiers de 512 octets.
times (512 - ($ - $$) % 512) % 512 db 0
