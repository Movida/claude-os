; =============================================================================
;  Étape 5 : le chargeur lit le noyau par morceaux, en mode « irréel »
; =============================================================================
;
;  Même chargeur en deux temps qu'aux étapes 2b à 4 (lire 02-mode-long/boot.asm
;  pour le détail du mode protégé, de la pagination et du mode long). Ce qui
;  change : la façon d'amener le noyau à 1 Mio.
;
;  Jusqu'à l'étape 4, le BIOS déposait tout le noyau dans un tampon en
;  mémoire basse (de 0x10000 jusqu'à l'EBDA, 576 Kio au plus), et le code
;  64 bits le recopiait à 1 Mio. Le noyau pesait 157 Kio ; un programme C
;  compilé avec la glibc statique en pèse 767 à lui seul, et `claude` près
;  de 290 Mo : le tampon ne suffit plus. D'où le chargement par morceaux :
;
;    1. le BIOS lit 64 secteurs (32 Kio) dans un petit tampon en mémoire
;       basse : en mode réel, il ne sait écrire que sous 1 Mio ;
;    2. le chargeur recopie aussitôt ce morceau à sa place définitive,
;       au-dessus de 1 Mio, grâce au mode « irréel » (voir mode_irreel) ;
;    3. et ainsi de suite, jusqu'au dernier secteur.
;
;  La taille du noyau n'est plus limitée que par la mémoire libre au-dessus
;  de 1 Mio (vérifiée avec la carte E820) et par les 4 Gio qu'adresse le
;  mode irréel. C'est ainsi que GRUB et SYSLINUX chargent un noyau Linux et
;  son initramfs depuis le BIOS, avant le moindre pilote de disque.
;
;  Le noyau est une image « plate » (objcopy -O binary) : son point
;  d'entrée est son premier octet.
;
;  Derrière le noyau, sur le disque, vient l'ARCHIVE DE PROGRAMMES : une
;  archive cpio, comme l'initramfs de Linux (voir formats/src/cpio.rs). Le
;  chargeur la dépose en mémoire juste après la place qu'occupe le noyau
;  une fois lancé (son fichier, puis sa .bss et ses piles, que le Makefile
;  mesure, comme le champ init_size du protocole de démarrage de Linux), et
;  dit au noyau où elle est dans les INFORMATIONS DE DÉMARRAGE (voir INFOS).
;
;  Plan de la mémoire basse :
;    0x01000-0x03FFF  tables de pages
;    0x04000-0x04C1F  informations de démarrage, transmises au noyau
;    0x04C20-0x07BFF  pile du chargeur (près de 12 Kio), dans tous les modes
;    0x07C00-...      1er puis 2e étage (au plus jusqu'au tampon)
;    0x10000-0x17FFF  tampon de lecture : un morceau de 32 Kio
;  Puis, au-dessus de 1 Mio :
;    0x100000-...     le noyau, recopié morceau par morceau, puis sa .bss
;                     et ses piles (que le noyau met lui-même à zéro)
;    page suivante    l'archive de programmes
;
;  Assemblage : par le Makefile, qui passe à NASM la taille du noyau
;  (NOYAU_SECTEURS sur le disque, NOYAU_MEMOIRE en mémoire) et celle de
;  l'archive (ARCHIVE_OCTETS).
; -----------------------------------------------------------------------------

[org 0x7C00]
[bits 16]

COM1 equ 0x3F8          ; Registres de l'UART 16550 : 0x3F8 à 0x3FF.

; Nombre de secteurs du 2e étage, calculé par NASM à partir de la taille du
; code : on n'a jamais à le tenir à jour à la main.
NB_SECTEURS equ (fin_image - etage2 + 511) / 512

; Tailles du noyau et de l'archive : connues seulement après leur
; construction, donc fournies par le Makefile (nasm -D NOM=valeur) :
;   NOYAU_SECTEURS  le fichier du noyau, en secteurs ;
;   NOYAU_MEMOIRE   la place qu'il occupe en mémoire une fois lancé, en
;                   octets : son fichier, puis sa .bss et ses piles ;
;   ARCHIVE_OCTETS  l'archive de programmes, en octets (0 : pas d'archive).
%ifndef NOYAU_SECTEURS
  %error "NOYAU_SECTEURS manquant : construire avec make"
%endif
%ifndef NOYAU_MEMOIRE
  %error "NOYAU_MEMOIRE manquant : construire avec make"
%endif
%ifndef ARCHIVE_OCTETS
  %error "ARCHIVE_OCTETS manquant : construire avec make"
%endif
%if NOYAU_MEMOIRE < NOYAU_SECTEURS * 512
  %error "NOYAU_MEMOIRE plus petit que le fichier du noyau"
%endif
; Une borne de bon sens : le noyau, sa .bss et ses piles tiennent en
; quelques Mio. Une valeur énorme vient d'un calcul raté dans le Makefile.
%if NOYAU_MEMOIRE > 256 * 1024 * 1024
  %error "NOYAU_MEMOIRE invraisemblable (plus de 256 Mio)"
%endif

NOYAU_ADRESSE  equ 0x100000     ; Où le noyau s'exécute (1 Mio).
; L'archive : à la page qui suit la place du noyau. Le noyau la lit par sa
; projection directe, page par page : rien ne l'oblige à être alignée,
; mais la réserver ou la rendre se fait par pages entières.
ARCHIVE_ADRESSE  equ (NOYAU_ADRESSE + NOYAU_MEMOIRE + 0xFFF) & ~0xFFF
ARCHIVE_SECTEURS equ (ARCHIVE_OCTETS + 511) / 512

; Le tampon où le BIOS dépose chaque morceau, et la taille d'un morceau.
; 64 secteurs : certains BIOS refusent plus de 127 secteurs par appel, et
; un morceau de 32 Kio aligné sur 32 Kio ne franchit jamais une frontière
; de 64 Kio, une autre limite de vieux contrôleurs DMA.
TAMPON         equ 0x10000
MORCEAU        equ 64
TAMPON_FIN     equ TAMPON + MORCEAU * 512

; La pile du chargeur, sous le 1er étage : de 0x7C00 vers le bas, jusqu'aux
; informations de démarrage (0x4C20), soit près de 12 Kio. Le chargeur n'en utilise
; que quelques dizaines d'octets. Elle sert dans les trois modes : on
; n'a pas à se demander si une autre zone est libre.
PILE_CHARGEUR  equ 0x7C00

; Les informations de démarrage, que le chargeur transmet au noyau : ce
; que seul le chargeur sait (la carte de la mémoire, qu'on ne peut
; demander au BIOS qu'en mode réel ; où il a mis l'archive). C'est le rôle
; des « boot_params » de Linux (la « zero page »). Leur format est un
; contrat entre le chargeur et le noyau (voir noyau/src/demarrage.rs) :
;   +0x00  dword  signature INFOS_SIGNATURE, preuve que c'est bien nous
;   +0x04  dword  taille de la structure, en octets
;   +0x08  qword  adresse physique de l'archive de programmes
;   +0x10  qword  taille de l'archive, en octets (0 : pas d'archive)
;   +0x18  dword  nombre de zones de la carte de la mémoire
;   +0x1C  dword  inutilisé
;   +0x20  zones de 24 octets : base (qword), taille (qword), type (dword),
;          4 octets inutilisés
; La taille sert de numéro de version, comme le champ « version » du
; protocole de Linux : un chargeur plus récent ajoutera ses champs à la
; fin (ligne de commande, tables ACPI, informations d'UEFI...), et un
; noyau saura, à la taille, s'ils sont là.
INFOS          equ 0x4000
INFOS_SIGNATURE equ 'INFO'      ; NASM range les 4 caractères dans l'ordre.
INFOS_ARCHIVE  equ INFOS + 0x08
INFOS_ARCHIVE_TAILLE equ INFOS + 0x10
CARTE_NOMBRE   equ INFOS + 0x18
CARTE_ZONES    equ INFOS + 0x20
CARTE_MAX      equ 128          ; Comme Linux (E820_MAX_ENTRIES_ZEROPAGE).
INFOS_TAILLE   equ 0x20 + CARTE_MAX * 24
SMAP           equ 0x534D4150   ; « SMAP », mot de passe de l'appel E820.
E820_LIBRE     equ 1            ; Type d'une zone de mémoire vive libre.


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

    ; --- Ligne A20 -----------------------------------------------------------
    ; Héritage du 8086 : son bus d'adresses n'avait que 20 fils (A0..A19), donc
    ; FFFF:0010 = 0x100000 « rebouclait » sur 0x00000. Des logiciels comptaient
    ; là-dessus ; IBM a donc ajouté une porte logique qui force le fil A20 à 0.
    ; Tant qu'elle est fermée, tous les Mio impairs sont des miroirs des pairs !
    ;
    ; Il faut l'ouvrir AVANT de charger le noyau : sa place, 1 Mio, est
    ; justement le premier octet qu'une ligne A20 fermée renverrait à 0.
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

    ; --- Carte de la mémoire (E820) ------------------------------------------------
    ; Le chargeur s'en sert lui-même, pour vérifier qu'il a le droit
    ; d'écrire le noyau là où il va (voir zone_libre), puis la passe au
    ; noyau. Il faut savoir où est la mémoire vive : elle n'est pas d'un
    ; seul tenant. Il y a des trous (la mémoire vidéo à 0xA0000, le BIOS vers
    ; 0xF0000, les périphériques PCI sous 4 Gio...) et des zones que le
    ; firmware garde pour lui (tables ACPI). Seul le firmware le sait, et
    ; on ne peut le lui demander qu'en mode réel : c'est maintenant ou
    ; jamais.
    ;
    ; L'appel « E820 » (int 0x15, eax = 0xE820), disponible depuis 1996 et
    ; utilisé par Linux, rend une zone par appel : base, taille, type
    ; (1 = mémoire libre, 2 = réservée, 3 et 4 = ACPI, 5 = défectueuse).
    ; ebx sert de marque-page : 0 au premier appel, puis la valeur rendue
    ; par le BIOS, jusqu'à ce qu'il rende 0 (c'était la dernière zone).
    ;
    ; Options écartées : les appels plus anciens, int 0x15 ax=0xE801 et
    ; ah=0x88, qui ne donnent qu'une taille totale, sans les trous (Linux
    ; ne s'en sert qu'en secours, pour des machines d'avant 2000).
    ;
    ; Deux précautions de Linux (arch/x86/boot/memory.c), contre des BIOS
    ; réels :
    ;   - le BIOS écrit chaque zone dans un même petit tampon (e820_zone),
    ;     qu'on recopie ensuite dans la carte : au moins un BIOS suppose
    ;     qu'on lui redonne le même tampon à chaque appel, et n'y réécrit
    ;     que les champs qui changent ;
    ;   - un BIOS qui cesse de répondre « SMAP » au milieu de la liste
    ;     donne une carte peut-être partielle, peut-être fausse : on la
    ;     jette toute, plutôt que de s'y fier.
    mov dword [CARTE_NOMBRE], 0
    mov di, CARTE_ZONES             ; Où recopier la prochaine zone.
    xor ebx, ebx
.e820_suivante:
    ; ecx = 20 : on demande le format d'origine, sans le 5e champ
    ; « attributs étendus » de l'ACPI 3.0. Comme Linux : des BIOS le
    ; remplissent mal, et l'ACPI 4.0 l'a rendu inutile. On garde des cases
    ; de 24 octets pour que le noyau lise des champs de 8 octets alignés.
    push di
    mov di, e820_zone               ; es:di -> où le BIOS écrit la zone.
    mov eax, 0xE820
    mov edx, SMAP
    mov ecx, 20
    int 0x15
    pop di
    jc .e820_fin                    ; CF = 1 : plus de zone (ou pas d'E820).
    cmp eax, SMAP                   ; Le BIOS répond « SMAP » s'il a compris.
    jne .e820_perdue
    ; La zone : ses 20 octets, puis 4 octets nuls (la case fait 24 octets).
    mov si, e820_zone
    mov cx, 20
    cld
    rep movsb
    xor eax, eax
    stosd
    inc dword [CARTE_NOMBRE]
    cmp dword [CARTE_NOMBRE], CARTE_MAX
    jae .e820_fin
    test ebx, ebx
    jnz .e820_suivante
    jmp .e820_fin
.e820_perdue:
    mov dword [CARTE_NOMBRE], 0
.e820_fin:
    cmp dword [CARTE_NOMBRE], 0
    jne .e820_ok
    mov si, msg_e820_ko
    call print16
    jmp halt16
.e820_ok:

    ; --- Place pour le tampon ----------------------------------------------------
    ; La mémoire basse libre ne va pas toujours jusqu'à 640 Kio : le BIOS
    ; en garde le haut pour lui, l'EBDA (Extended BIOS Data Area : données
    ; du BIOS, de l'ACPI, de la souris PS/2...). Sur QEMU elle fait 1 Kio
    ; (0x9FC00), mais sur du vrai matériel elle peut être bien plus grande :
    ; Linux tient pour impossible qu'elle commence sous 128 Kio
    ; (BIOS_START_MIN, arch/x86/kernel/ebda.c). Notre tampon s'arrête à
    ; 96 Kio, mais on ne fait pas confiance : int 0x12 donne, en Kio dans
    ; ax, la taille de la mémoire basse libre, c'est-à-dire le début de
    ; l'EBDA. (Linux lit la même valeur dans la zone de données du BIOS,
    ; le mot à l'adresse 0x413.)
    int 0x12
    cmp ax, TAMPON_FIN / 1024
    jae .place_ok
    mov si, msg_ebda
    call print16
    jmp halt16
.place_ok:

    ; --- Lire le noyau ------------------------------------------------------------
    ; Il suit le 2e étage sur le disque, et va à 1 Mio, l'adresse pour
    ; laquelle il a été lié. Toute la place qu'il occupera une fois lancé
    ; doit être libre, pas seulement celle de son fichier : sa .bss et ses
    ; piles suivent.
    mov eax, NOYAU_ADRESSE
    mov edx, NOYAU_ADRESSE + NOYAU_MEMOIRE
    call zone_libre
    jc charger.pas_de_place
    mov dword [charge_lba], 1 + NB_SECTEURS
    mov dword [charge_secteurs], NOYAU_SECTEURS
    mov dword [charge_destination], NOYAU_ADRESSE
    call charger
    mov si, msg_noyau_lu
    call print16

    ; --- Lire l'archive de programmes -----------------------------------------
    ; Elle suit le noyau sur le disque, et va à la page qui suit sa place
    ; en mémoire.
    mov dword [charge_lba], 1 + NB_SECTEURS + NOYAU_SECTEURS
    mov dword [charge_secteurs], ARCHIVE_SECTEURS
    mov dword [charge_destination], ARCHIVE_ADRESSE
    call charger
    mov si, msg_archive_lue
    call print16

    ; --- Les informations de démarrage --------------------------------------------
    ; La carte de la mémoire y est déjà (écrite par l'appel E820) : on
    ; complète l'en-tête.
    mov dword [INFOS], INFOS_SIGNATURE
    mov dword [INFOS + 4], INFOS_TAILLE
    mov dword [INFOS_ARCHIVE], ARCHIVE_ADRESSE
    mov dword [INFOS_ARCHIVE + 4], 0
    mov dword [INFOS_ARCHIVE_TAILLE], ARCHIVE_OCTETS
    mov dword [INFOS_ARCHIVE_TAILLE + 4], 0

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


; -----------------------------------------------------------------------------
;  Routines 16 bits propres au 2e étage
; -----------------------------------------------------------------------------

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

; mode_irreel : donne à DS et ES une limite de 4 Gio, en restant en mode réel.
;
; En mode réel, une adresse vaut segment x 16 + offset, avec un offset sur
; 16 bits : on ne dépasse pas 1 Mio (et 64 Kio de plus). Mais le processeur
; ne recalcule pas tout à chaque accès : pour chaque registre de segment, il
; garde dans un cache invisible la base, la LIMITE et les droits, chargés
; quand on écrit le registre. En mode réel, écrire un registre de segment
; ne change que la base (sélecteur x 16) : la limite reste celle du cache.
; L'astuce, vieille comme le 386 (on l'appelle « mode irréel », ou « big
; real mode ») :
;   1. passer un instant en mode protégé, et y charger DS et ES avec notre
;      segment de données « plat » de 4 Gio : le cache reçoit la limite de
;      4 Gio ;
;   2. revenir aussitôt en mode réel (PE = 0) et remettre DS = ES = 0 : la
;      base revient à 0, la limite de 4 Gio reste.
; Rend la main INTERRUPTIONS COUPÉES (voir pourquoi plus bas) ; écrase EAX
; et BX.
; On est alors en mode réel : les appels au BIOS marchent comme avant ; et
; avec un préfixe de taille d'adresse (a32), une instruction peut utiliser
; un offset de 32 bits, donc écrire n'importe où sous 4 Gio.
;
; Pourquoi la refaire avant chaque copie : un BIOS qui passe lui-même en
; mode protégé (certains le font pour lire un disque USB) recharge ses
; segments, et peut nous rendre la main avec une limite de 64 Kio. Une
; copie hors limite ferait alors une faute de protection générale, en
; mode réel, sans gestionnaire : la machine se figerait. Le passage ne
; coûte que quelques instructions.
;
; CS n'est pas rechargé : pendant ce bref passage en mode protégé, le
; processeur continue d'exécuter du code 16 bits avec son ancien cache de
; CS, ce qui est permis tant qu'on ne touche pas à CS. Interruptions
; coupées pendant ce temps : l'IDTR désigne encore la table du mode réel,
; qu'une interruption lirait comme une IDT de mode protégé. Et elles le
; RESTENT jusqu'à la fin de la copie qui suit : le gestionnaire BIOS d'une
; interruption (l'horloge, un contrôleur USB) pourrait lui aussi passer en
; mode protégé et nous rendre DS et ES limités à 64 Kio, ou abîmer les
; 16 bits hauts d'ECX, ESI ou EDI au milieu de `rep movsd`. L'appelant les
; rétablit (sti) une fois la copie faite : quelques dizaines de
; microsecondes d'attente pour l'horloge, sans conséquence.
; (Le NMI, lui, ne se masque pas par cli ; Linux le masque par le port
; 0x70 pour son passage définitif en mode protégé. Notre passage dure
; quelques instructions : on accepte ce risque infime.)
mode_irreel:
    cli
    push ds
    push es
    lgdt [gdt_descriptor]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    jmp $ + 2           ; Vide la file d'instructions (exigé sur 386 et 486).
    mov bx, DATA_SEL
    mov ds, bx
    mov es, bx
    and al, 0xFE
    mov cr0, eax
    pop es              ; Retour aux valeurs du mode réel (0) :
    pop ds              ; seule la base change, la limite de 4 Gio reste.
    ret

; charger : lit [charge_secteurs] secteurs depuis le secteur [charge_lba]
; du disque, et les range à l'adresse physique [charge_destination], qui
; peut être au-dessus de 1 Mio. Par morceaux : le BIOS lit 32 Kio dans le
; tampon, puis on les recopie à leur place.
;
; Des comptes de secteurs sur 32 bits : `claude` en fera près de 600 000.
; Avant la première lecture, on vérifie avec la carte E820 que la
; destination est tout entière de la mémoire libre : écrire dans une zone
; réservée (tables ACPI, registres de périphériques) serait silencieux
; ici, et désastreux plus tard.
;
; Options écartées :
;   - int 0x15, ah=0x87 : le BIOS fait la copie lui-même. C'était la voie
;     de Linux avant 2.6 ; mais l'appel est limité à 64 Kio, et certains
;     BIOS le ratent (copie de travers au-delà de 16 Mio, interruptions
;     laissées coupées) ;
;   - un aller-retour complet en mode protégé 32 bits pour chaque
;     morceau, comme GRUB : plus propre sur le papier (aucun état caché),
;     mais deux fois plus de code, et un retour en mode réel qui doit
;     recharger aussi CS et SS ;
;   - faire écrire le BIOS directement au-dessus de 1 Mio, avec l'adresse
;     64 bits du paquet EDD 3.0 (le champ qui suit notre DAP) : peu de BIOS
;     la reconnaissent.
;
; Une lecture qui échoue est refaite, deux fois au plus, après avoir
; réinitialisé le disque (int 0x13, ah = 0), comme GRUB et les anciens
; secteurs de démarrage de Linux : sur une clé USB émulée par le BIOS, une
; erreur passagère n'est pas rare, et `claude` demandera près de 9000
; lectures.
charger:
    ; Rien à lire (une archive vide) : rien à vérifier non plus. Une plage
    ; vide n'a pas à être dans la mémoire libre.
    cmp dword [charge_secteurs], 0
    je .fin
    ; La destination est-elle de la mémoire libre ? On borne d'abord le
    ; calcul : au-delà de 4 Gio, le mode irréel ne peut pas écrire.
    mov eax, [charge_destination]
    mov edx, [charge_secteurs]
    cmp edx, 0xFFFFFFFF >> 9
    ja .pas_de_place
    shl edx, 9                      ; Secteurs x 512 = octets.
    add edx, eax                    ; edx = fin de la destination.
    jc .pas_de_place
    call zone_libre
    jc .pas_de_place
.morceau:
    mov ecx, [charge_secteurs]
    test ecx, ecx
    jz .fin
    cmp ecx, MORCEAU
    jbe .taille_ok
    mov ecx, MORCEAU
.taille_ok:
    mov [charge_morceau], ecx
    mov byte [charge_essais], 3
.lire:
    ; Le paquet de lecture : ce morceau, vers le tampon. Rempli à chaque
    ; essai : après une erreur, le BIOS y a mis le nombre de secteurs qu'il
    ; a vraiment lus.
    mov ecx, [charge_morceau]
    mov [dap_nombre], cx
    mov word [dap_offset], TAMPON & 0xF
    mov word [dap_segment], TAMPON >> 4
    mov eax, [charge_lba]
    mov [dap_lba], eax
    mov dword [dap_lba + 4], 0
    mov ah, 0x42
    mov dl, [disque]
    mov si, dap
    int 0x13
    jnc .lu
    dec byte [charge_essais]
    jz erreur_disque
    xor ah, ah                      ; Réinitialiser le disque, puis réessayer.
    mov dl, [disque]
    int 0x13
    jmp .lire
.lu:
    ; La copie : ecx mots de 4 octets, de ds:esi vers es:edi, en adresses
    ; de 32 bits (préfixe a32). cld : dans le sens des adresses croissantes
    ; (le BIOS ne garantit pas ce drapeau). On recharge tout après l'appel
    ; au BIOS : il ne promet pas de garder les 16 bits hauts des registres.
    call mode_irreel
    mov ecx, [charge_morceau]
    shl ecx, 9 - 2                  ; Secteurs x 512 / 4.
    mov esi, TAMPON
    mov edi, [charge_destination]
    cld
    a32 rep movsd
    sti                             ; Voir mode_irreel.
    ; Au morceau suivant.
    mov ecx, [charge_morceau]
    add [charge_lba], ecx
    sub [charge_secteurs], ecx
    shl ecx, 9
    add [charge_destination], ecx
    jmp .morceau
.fin:
    ret
.pas_de_place:
    mov si, msg_pas_de_place
    call print16
    jmp halt16

; zone_libre : la plage d'adresses physiques [eax, edx[ (sous 4 Gio)
; est-elle de la mémoire libre d'après la carte E820 ? CF = 0 si elle est
; tout entière dans une zone libre, et ne touche aucune zone non libre ;
; CF = 1 sinon. Le BIOS ne promet pas des zones disjointes : comme le
; noyau (cadres.rs), une zone réservée qui en chevauche une libre
; l'emporte. Deux zones libres qui se touchent ne sont pas réunies : une
; plage à cheval sur les deux est refusée (rien de tel sur QEMU, ni sur
; les machines courantes, où la mémoire au-dessus de 1 Mio est d'un seul
; tenant).
;
; Les champs de la carte sont sur 64 bits ; on travaille sur 32, en
; comparant à part les 32 bits hauts : une zone qui commence au-delà de
; 4 Gio ne peut ni contenir ni chevaucher la plage.
zone_libre:
    pushad
    mov [zone_debut], eax
    mov [zone_fin], edx
    xor bp, bp                      ; bp = 1 : une zone libre la contient.
    mov cx, [CARTE_NOMBRE]
    mov si, CARTE_ZONES
.zone:
    jcxz .bilan
    ; Taille nulle : certains BIOS en rendent, on les ignore.
    mov eax, [si + 8]
    or eax, [si + 12]
    jz .suivante
    cmp dword [si + 4], 0           ; Commence au-delà de 4 Gio ?
    jne .suivante
    ; ebx:edi = fin de la zone (base + taille), sur 64 bits ; au-delà de
    ; 2^64 (une zone mal décrite), on la ramène à 2^64 - 1.
    mov edi, [si]
    mov ebx, [si + 4]
    add edi, [si + 8]
    adc ebx, [si + 12]
    jnc .fin_calculee
    mov edi, 0xFFFFFFFF
    mov ebx, edi
.fin_calculee:
    mov eax, [si]                   ; eax = base de la zone (sous 4 Gio).
    cmp dword [si + 16], E820_LIBRE
    jne .non_libre
    ; Zone libre : la contient-elle (base <= début et fin >= fin) ?
    cmp eax, [zone_debut]
    ja .suivante
    test ebx, ebx
    jnz .contenue
    cmp edi, [zone_fin]
    jb .suivante
.contenue:
    mov bp, 1
    jmp .suivante
.non_libre:
    ; Zone non libre : la chevauche-t-elle (base < fin et fin > début) ?
    cmp eax, [zone_fin]
    jae .suivante
    test ebx, ebx
    jnz .refus
    cmp edi, [zone_debut]
    ja .refus
.suivante:
    add si, 24
    dec cx
    jmp .zone
.bilan:
    cmp bp, 1                       ; CF = 1 si bp = 0 (aucune ne la contient).
    popad                           ; (popad ne touche pas aux drapeaux)
    ret
.refus:
    stc
    popad
    ret

; Les paramètres de charger, et ses variables.
charge_lba:         dd 0
charge_secteurs:    dd 0
charge_destination: dd 0
charge_morceau:     dd 0
charge_essais:      db 0
; Le tampon où le BIOS écrit chaque zone de la carte E820 (20 octets).
e820_zone:          times 20 db 0
zone_debut:         dd 0
zone_fin:           dd 0

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

    ; --- Passer la main au noyau ------------------------------------------------
    ; Le noyau est déjà à sa place, à 1 Mio : chaque morceau y a été
    ; recopié en mode irréel. (Jusqu'à l'étape 4, c'est ici qu'on le
    ; recopiait depuis le tampon en mémoire basse.)
    ;
    ; Les interruptions restent coupées : c'est le noyau qui les rétablira,
    ; une fois sa propre table d'interruptions en place. On saute par un
    ; registre : un saut relatif ne peut pas encoder une adresse aussi
    ; éloignée de façon lisible, et c'est ainsi que les chargeurs le font.
    ; L'adresse des informations de démarrage va dans rdi : c'est là que
    ; la convention d'appel des systèmes Unix 64 bits (System V) met le 1er
    ; argument d'une fonction. Le noyau la reçoit comme un paramètre.
    ; (Linux reçoit de même ses « boot_params » dans rsi.)
    mov rdi, INFOS
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
msg_noyau_lu: db "[16 bits] Noyau lu sur le disque, recopie a 1 Mio en mode irreel.", 13, 10, 0
msg_ebda:    db "[16 bits] ERREUR : le tampon de lecture deborde sur la zone du BIOS (EBDA).", 13, 10, 0
msg_pas_de_place: db "[16 bits] ERREUR : pas assez de memoire libre pour le noyau et l'archive (E820).", 13, 10, 0
msg_archive_lue: db "[16 bits] Archive de programmes lue, placee apres le noyau.", 13, 10, 0
msg_e820_ko: db "[16 bits] ERREUR : le BIOS ne donne pas de carte memoire (E820).", 13, 10, 0
msg_long:    db "[64 bits] Mode long actif ! Le processeur execute du code 64 bits.", 13, 10, 0
msg_pas_64:  db "[32 bits] ERREUR : ce processeur n'a pas de mode 64 bits.", 13, 10, 0

fin_image:
; On complète jusqu'à un nombre entier de secteurs : un disque ne se lit
; que par secteurs entiers de 512 octets.
times (512 - ($ - $$) % 512) % 512 db 0

; Le 2e étage ne doit pas déborder sur le tampon de lecture (il écraserait
; son propre code au premier morceau lu). NASM n'a pas d'assertion : une
; répétition d'un nombre négatif de fois arrête l'assemblage.
times -(0x7C00 + (etage2 - $$) + NB_SECTEURS * 512 > TAMPON) db 0
