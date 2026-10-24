; =============================================================================
;  Étape 3 : le chargeur de l'étape 2b, qui charge maintenant un noyau Rust
; =============================================================================
;
;  Même chargeur en deux temps qu'à l'étape 2b (lire ce fichier-là pour le
;  détail du mode protégé, de la pagination et du mode long). Ce qui change :
;
;    - le 2e étage lit aussi le NOYAU sur le disque, toujours via le BIOS
;      (donc en mode réel, avant de quitter le 16 bits), dans une zone
;      tampon en mémoire basse (0x10000) ;
;    - une fois en 64 bits, il le recopie à 1 Mio (0x100000), l'adresse pour
;      laquelle le noyau a été lié, et saute dessus.
;
;  Pourquoi ce détour par un tampon ? En mode réel, le BIOS ne sait écrire
;  que sous 1 Mio (segment:offset). Or 1 Mio est l'adresse classique d'un
;  noyau (Linux y est chargé lui aussi) : en dessous, la mémoire est mitée
;  par le BIOS, la mémoire vidéo et nos propres tables. On lit donc en bas,
;  puis on recopie en haut une fois que le processeur voit toute la mémoire.
;
;  Le noyau est une image « plate » (objcopy -O binary) : son point
;  d'entrée est son premier octet. Lire un vrai fichier ELF (en-têtes,
;  segments) viendra avec le chargeur ELF de l'étape 5.
;
;  Plan de la mémoire basse :
;    0x01000-0x03FFF  tables de pages
;    0x04000-0x07BFF  pile du chargeur (15 Kio), dans tous les modes
;    0x07C00-...      1er puis 2e étage
;    0x10000-...      tampon du noyau, jusqu'au début de l'EBDA au plus
;
;  Assemblage : par le Makefile, qui passe NOYAU_SECTEURS à NASM.
; -----------------------------------------------------------------------------

[org 0x7C00]
[bits 16]

COM1 equ 0x3F8          ; Registres de l'UART 16550 : 0x3F8 à 0x3FF.

; Nombre de secteurs du 2e étage, calculé par NASM à partir de la taille du
; code : on n'a jamais à le tenir à jour à la main.
NB_SECTEURS equ (fin_image - etage2 + 511) / 512

; Taille du noyau en secteurs : connue seulement après sa compilation, donc
; fournie par le Makefile (nasm -D NOYAU_SECTEURS=...).
%ifndef NOYAU_SECTEURS
  %error "NOYAU_SECTEURS manquant : construire avec make"
%endif

NOYAU_TAMPON   equ 0x10000      ; Où le BIOS dépose le noyau (sous 1 Mio).
NOYAU_ADRESSE  equ 0x100000     ; Où il doit s'exécuter (1 Mio).
; Taille du noyau en Kio, arrondie au Kio supérieur (2 secteurs = 1 Kio).
NOYAU_KIO      equ (NOYAU_SECTEURS + 1) / 2

; Limite absolue : la mémoire conventionnelle s'arrête à 640 Kio (0xA0000),
; où commence la mémoire vidéo. La vraie limite, plus basse, n'est connue
; qu'au démarrage (voir « Place pour le noyau » dans le 2e étage).
%if NOYAU_TAMPON / 1024 + NOYAU_KIO > 640
  %error "noyau trop gros pour la memoire basse (640 Kio)"
%endif

; La pile du chargeur, sous le 1er étage : de 0x7C00 vers le bas, jusqu'aux
; tables de pages (0x4000), soit 15 Kio. Le chargeur n'en utilise
; que quelques dizaines d'octets. Elle sert dans les trois modes : on
; n'a pas à se demander si une autre zone est libre. (À l'étape 2b, en
; 32 et 64 bits, elle partait de 0x90000 : ici, elle descendrait dans le
; tampon du noyau, et un gros noyau verrait ses derniers octets écrasés
; avant même d'être recopié.)
PILE_CHARGEUR  equ 0x7C00


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
    mov sp, PILE_CHARGEUR
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
; Le 2e étage le réutilise pour lire le noyau, en changeant les champs.
dap:
    db 0x10             ; Taille du paquet : 16 octets.
    db 0                ; Réservé.
dap_nombre:
    dw NB_SECTEURS      ; Combien de secteurs lire.
dap_offset:
    dw etage2           ; Où les ranger : offset...
dap_segment:
    dw 0                ; ... et segment (0000:7E00).
dap_lba:
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

    ; --- Place pour le noyau --------------------------------------------------------
    ; La mémoire basse libre ne va pas toujours jusqu'à 640 Kio : le BIOS
    ; en garde le haut pour lui, l'EBDA (Extended BIOS Data Area : données
    ; du BIOS, de l'ACPI, de la souris PS/2...). Sur QEMU elle fait 1 Kio
    ; (0x9FC00), mais sur du vrai matériel elle peut être bien plus grande :
    ; Linux n'exclut pas qu'elle commence dès 0x20000. Écrire le noyau
    ; dedans écraserait les données du BIOS, qu'on utilise encore (disque).
    ; int 0x12 donne, en Kio dans ax, la taille de la mémoire basse libre,
    ; c'est-à-dire le début de l'EBDA. (Linux lit la même valeur dans la
    ; zone de données du BIOS, le mot à l'adresse 0x413.)
    int 0x12
    cmp ax, NOYAU_TAMPON / 1024 + NOYAU_KIO
    jae .place_ok
    mov si, msg_trop_gros
    call print16
    jmp halt16
.place_ok:

    ; --- Lire le noyau ------------------------------------------------------------
    ; Il suit le 2e étage sur le disque. On le lit par morceaux de 64
    ; secteurs (32 Kio) : certains BIOS refusent plus de 127 secteurs par
    ; appel, et un morceau de 32 Kio aligné ne franchit jamais une frontière
    ; de 64 Kio, une autre limite de vieux contrôleurs DMA.
    mov word [dap_segment], NOYAU_TAMPON >> 4  ; 0x1000:0000 = 0x10000.
    mov word [dap_offset], 0
    mov dword [dap_lba], 1 + NB_SECTEURS
    mov cx, NOYAU_SECTEURS          ; Secteurs restant à lire.
.lire_noyau:
    mov ax, cx
    cmp ax, 64
    jbe .taille_ok
    mov ax, 64
.taille_ok:
    mov [dap_nombre], ax
    push cx                         ; Le BIOS ne promet pas de garder cx.
    mov ah, 0x42
    mov dl, [disque]
    mov si, dap
    int 0x13
    pop cx
    jc erreur_disque
    mov ax, [dap_nombre]
    add [dap_lba], ax               ; Secteurs suivants sur le disque...
    shl ax, 5                       ; ... et en mémoire : n x 512 / 16
    add [dap_segment], ax           ;     paragraphes de plus pour le segment.
    sub cx, [dap_nombre]
    jnz .lire_noyau

    mov si, msg_noyau_lu
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
    mov esp, PILE_CHARGEUR  ; La même pile, en 32 bits.

    mov esi, msg_protege
    mov edi, 0xB8000 + 3 * 80 * 2   ; Ligne 3 de l'écran (voir print32).
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
    mov edi, 0xB8000 + 4 * 80 * 2
    call print32

    ; --- Les tables de pages ------------------------------------------------------
    ; En mode long, la pagination est OBLIGATOIRE : chaque adresse que manipule
    ; le code (adresse « virtuelle ») est traduite par le CPU en adresse
    ; physique, en descendant un arbre de tables. Chaque table fait 4 Kio et
    ; contient 512 entrées de 8 octets ; chaque niveau consomme 9 bits de
    ; l'adresse virtuelle :
    ;
    ;   bits 47-39 -> entrée de la PML4  -> adresse d'une PDPT
    ;   bits 38-30 -> entrée de la PDPT  -> adresse d'une PD
    ;   bits 29-21 -> entrée de la PD    -> une page de 2 Mio (bit PS = 1)
    ;   bits 20-0  -> position dans cette page de 2 Mio
    ;
    ; Nos choix :
    ;   - correspondance IDENTITÉ (adresse virtuelle = adresse physique) : le
    ;     code qui active la pagination continue de s'exécuter à la même
    ;     adresse, sans quoi l'instruction suivante serait introuvable. Le
    ;     noyau mettra plus tard sa propre organisation (noyau dans la moitié
    ;     haute de l'espace d'adresses, comme Linux) ;
    ;   - pages de 2 Mio : un seul niveau de moins à remplir. Des pages de
    ;     4 Kio couvriraient 1 Gio avec 512 tables de plus (2 Mio de tables) ;
    ;     des pages de 1 Gio n'existent pas sur tous les CPU (cpuid pdpe1gb),
    ;     et QEMU ne les propose pas par défaut. Linux fait comme nous au
    ;     démarrage ;
    ;   - 1 Gio couvert : une seule PD suffit (512 x 2 Mio), et c'est
    ;     largement assez pour le chargeur, la mémoire vidéo et un noyau.
    ;
    ; Où les ranger ? Dans la mémoire basse libre (0x1000-0x3FFF), comme tout
    ; ce que notre chargeur utilise. Chaque table doit être alignée sur 4 Kio :
    ; une entrée ne stocke que les bits hauts de l'adresse de la table suivante.
    ; (Les mettre dans l'image disque coûterait 12 Kio de zéros à lire.)
    mov edi, PML4
    xor eax, eax
    mov ecx, 3 * 4096 / 4
    rep stosd               ; Trois tables à zéro : entrée nulle = « absente ».

    ; Bits bas d'une entrée : bit 0 = P (présente), bit 1 = RW (inscriptible).
    ; Bit 2 = U/S reste à 0 : réservé au noyau, inaccessible en mode utilisateur.
    mov dword [PML4], PDPT | 0x03   ; PML4[0] -> PDPT : couvre 0 à 512 Gio.
    mov dword [PDPT], PD   | 0x03   ; PDPT[0] -> PD   : couvre 0 à 1 Gio.

    ; PD[i] = page de 2 Mio commençant à i x 2 Mio. 0x83 = P + RW + PS (bit 7,
    ; « page de grande taille » : l'entrée désigne la page elle-même, pas une
    ; table de niveau inférieur).
    mov edi, PD
    mov eax, 0x83
    mov ecx, 512
.remplir_pd:
    mov [edi], eax          ; Les 4 octets hauts de l'entrée restent à 0 :
    add eax, 0x200000       ; nos adresses physiques tiennent sous 4 Gio.
    add edi, 8
    loop .remplir_pd

    ; --- Activer le mode long -----------------------------------------------------
    ; Trois interrupteurs, dans un ordre imposé par le manuel d'Intel :
    ; 1. CR4.PAE (bit 5) : entrées de pages de 8 octets (au lieu de 4 en
    ;    32 bits classique). Le mode long n'existe qu'avec ce format.
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; 2. CR3 = adresse physique de la racine de l'arbre (la PML4).
    mov eax, PML4
    mov cr3, eax

    ; 3. EFER.LME (bit 8) : « je veux le mode long ». EFER n'est pas un
    ;    registre ordinaire mais un MSR (Model Specific Register), qu'on lit
    ;    et écrit avec rdmsr/wrmsr ; son numéro va dans ecx, sa valeur dans
    ;    edx:eax.
    mov ecx, EFER
    rdmsr
    or eax, 1 << 8
    wrmsr

    ; 4. CR0.PG (bit 31) : la pagination démarre, et avec LME le CPU entre
    ;    en mode long. Le bit EFER.LMA (« Long Mode Active ») passe à 1 tout
    ;    seul. Comme CS désigne encore un segment 32 bits (L=0), le CPU est
    ;    dans le sous-mode « compatibilité » : celui qui permettra aussi de
    ;    faire tourner des programmes 32 bits sous un noyau 64 bits.
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    ; On ne se fie pas à l'absence de plantage : on relit EFER.LMA (bit 10).
    mov ecx, EFER
    rdmsr
    test eax, 1 << 10
    jz halt32
    mov esi, msg_compat
    mov edi, 0xB8000 + 5 * 80 * 2
    call print32

    ; --- Dernier saut lointain : vers le vrai 64 bits ------------------------------
    ; Comme pour l'entrée en mode protégé, c'est le descripteur chargé dans
    ; CS qui décide comment le CPU décode les instructions : on saute vers
    ; un segment dont le bit L vaut 1. Le jeu d'instructions change : pour
    ; NASM, c'est [bits 64] à partir de lm_entry.
    jmp CODE64_SEL:lm_entry

.pas_de_64:
    ; Message clair plutôt qu'une triple faute (redémarrage en boucle)
    ; plus loin : sur un vieux PC, l'utilisateur saura pourquoi.
    mov esi, msg_pas_64
    mov edi, 0xB8000 + 4 * 80 * 2
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
;  Code 64 bits
; -----------------------------------------------------------------------------
[bits 64]
lm_entry:
    ; En mode 64 bits, le CPU ignore la base et la limite de ds, es et ss
    ; (fs et gs gardent une base, qui servira aux données propres à chaque
    ; processeur et à chaque thread). On y met quand même notre segment de
    ; données plutôt que des valeurs restées du mode 32 bits : c'est ce que
    ; fait Linux, et une interruption qui reviendrait ici trouverait des
    ; sélecteurs valides.
    mov ax, DATA_SEL
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov rsp, PILE_CHARGEUR  ; Et en 64 bits.

    mov rsi, msg_long
    mov rdi, 0xB8000 + 6 * 80 * 2
    call print64

    ; --- Recopier le noyau à 1 Mio et lui passer la main --------------------------
    ; rep movsq copie rcx mots de 8 octets de [rsi] vers [rdi]. cld : dans
    ; le sens des adresses croissantes (le BIOS ne garantit pas ce drapeau).
    cld
    mov rsi, NOYAU_TAMPON
    mov rdi, NOYAU_ADRESSE
    mov rcx, NOYAU_SECTEURS * 512 / 8
    rep movsq

    ; Les interruptions restent coupées : c'est le noyau qui les rétablira,
    ; une fois sa propre table d'interruptions en place. On saute par un
    ; registre : un saut relatif ne peut pas encoder une adresse aussi
    ; éloignée de façon lisible, et c'est ainsi que les chargeurs le font.
    mov rax, NOYAU_ADRESSE
    jmp rax

halt64:
    cli
    hlt
    jmp halt64

; print64 et serial_putc64 : les mêmes que print32 et serial_putc, en 64 bits.
; Encore une copie : les registres s'appellent rsi, rdi... et l'encodage des
; instructions change (préfixes REX). Dans le noyau Rust, il
; n'y aura plus qu'une seule version de chaque fonction.
print64:
    lodsb
    test al, al
    jz .fin
    cmp al, ' '
    jb .serie
    mov ah, 0x0A
    mov [rdi], ax
    add rdi, 2
.serie:
    call serial_putc64
    jmp print64
.fin:
    ret

serial_putc64:
    push rdx
    push rax
    mov dx, COM1 + 5
.attente:
    in al, dx
    test al, 0x20
    jz .attente
    pop rax
    mov dx, COM1
    out dx, al
    pop rdx
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
;                   L   = 1 : code 64 bits (alors DB doit valoir 0)
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
    ;   - la protection mémoire viendra de la PAGINATION (plus bas dans ce fichier), plus fine
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

gdt_code64:
    ; Segment de CODE noyau 64 bits (sélecteur 0x18). En mode 64 bits, le
    ; CPU ignore base et limite : seuls comptent l'octet d'accès et les bits
    ; L et DB. On garde quand même base 0 et limite maximale, comme Linux,
    ; pour qu'un outil qui lit la table voie un segment « plat » cohérent.
    ; On ajoute ce descripteur au lieu de modifier gdt_code : le saut en
    ; mode protégé a besoin d'un segment 32 bits, et le sous-mode
    ; compatibilité en aura besoin pour des programmes 32 bits.
    dw 0xFFFF
    dw 0x0000
    db 0x00
    db 10011011b        ; Accès : identique au code 32 bits (noyau, lisible).
    db 10101111b        ; Flags G=1, DB=0, L=1 : code 64 bits ; limite 0xF.
                        ; DB=1 avec L=1 est interdit (réservé par Intel).
    db 0x00

; Le segment de données 0x10 sert aussi en 64 bits : seul y compte le bit P.
; Pas encore de segments utilisateur (DPL=3) ni de TSS : ils arriveront avec
; les processus.

gdt_end:

; Ce que lit l'instruction lgdt : taille - 1 (16 bits), puis adresse (32 bits).
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

CODE_SEL equ gdt_code - gdt_start   ; = 0x08
DATA_SEL equ gdt_data - gdt_start   ; = 0x10
CODE64_SEL equ gdt_code64 - gdt_start ; = 0x18

; Les trois tables de pages, en mémoire basse libre, alignées sur 4 Kio.
PML4 equ 0x1000
PDPT equ 0x2000
PD   equ 0x3000

EFER equ 0xC0000080     ; Numéro du MSR « Extended Feature Enable Register ».


; -----------------------------------------------------------------------------
;  Messages du 2e étage
; -----------------------------------------------------------------------------
msg_etage2:  db "[16 bits] 2e etage charge depuis le disque.", 13, 10, 0
msg_a20_ko:  db "[16 bits] ERREUR : la ligne A20 refuse de s'activer.", 13, 10, 0
msg_protege: db "[32 bits] Mode protege actif.", 13, 10, 0
msg_cpu64:   db "[32 bits] Le processeur sait passer en 64 bits (cpuid, bit LM).", 13, 10, 0
msg_compat:  db "[32 bits] Pagination active, mode long actif (sous-mode compatibilite).", 13, 10, 0
msg_noyau_lu: db "[16 bits] Noyau lu sur le disque.", 13, 10, 0
msg_trop_gros: db "[16 bits] ERREUR : le noyau ne tient pas sous la zone du BIOS (EBDA).", 13, 10, 0
msg_long:    db "[64 bits] Mode long actif ! Le processeur execute du code 64 bits.", 13, 10, 0
msg_pas_64:  db "[32 bits] ERREUR : ce processeur n'a pas de mode 64 bits.", 13, 10, 0

fin_image:
; On complète jusqu'à un nombre entier de secteurs : un disque ne se lit
; que par secteurs entiers de 512 octets.
times (512 - ($ - $$) % 512) % 512 db 0
