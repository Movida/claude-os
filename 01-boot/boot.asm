; =============================================================================
;  Étape 1 : un secteur de démarrage (boot sector) de 512 octets
; =============================================================================
;
;  Ce qui se passe à l'allumage d'un PC (mode BIOS « legacy ») :
;    1. Le processeur démarre en MODE RÉEL 16 bits, comme un 8086 de 1978.
;    2. Le BIOS teste le matériel, puis lit le PREMIER SECTEUR (512 octets)
;       du disque de démarrage.
;    3. Il vérifie que ses deux derniers octets valent 0x55 0xAA (la signature).
;    4. Il copie ce secteur à l'adresse mémoire 0x7C00 et saute dessus.
;
;  À partir de là, c'est NOTRE code qui a la main. Plus de système, plus de
;  bibliothèque : seulement le processeur, la mémoire, et les services du BIOS.
;
;  Assemblage : nasm -f bin boot.asm -o boot.bin
; -----------------------------------------------------------------------------

[org 0x7C00]        ; « Ce code sera chargé à 0x7C00 » : NASM calcule les
                    ; adresses des étiquettes (comme `message`) en conséquence.
[bits 16]           ; Le processeur est en mode réel : instructions 16 bits.

COM1 equ 0x3F8      ; Port d'entrée/sortie du premier port série.

start:
    ; --- 1. Mettre la machine dans un état connu ---------------------------
    ; Le BIOS ne garantit rien sur les registres de segment. En mode réel, une
    ; adresse = segment * 16 + offset. On met tous les segments à 0 pour que
    ; « adresse = offset », ce qui correspond à notre [org 0x7C00].
    cli                 ; Coupe les interruptions pendant qu'on touche la pile.
    xor ax, ax          ; ax = 0 (plus court que « mov ax, 0 »).
    mov ds, ax          ; Segment de données.
    mov es, ax          ; Segment supplémentaire.
    mov ss, ax          ; Segment de pile.
    mov sp, 0x7C00      ; La pile grandit vers le BAS, juste sous notre code.
    sti                 ; Réactive les interruptions (le BIOS en a besoin).

    ; --- 2. Effacer l'écran ----------------------------------------------------
    ; « int 0x10 » appelle le service vidéo du BIOS. ah = 0x00 : changer de
    ; mode ; al = 0x03 : texte 80 colonnes x 25 lignes, 16 couleurs.
    mov ax, 0x0003
    int 0x10

    ; --- 3. Afficher notre message --------------------------------------------
    mov si, message     ; si pointe sur le premier caractère.
    call print

    ; --- 4. Plus rien à faire : on endort le processeur ---------------------
.halt:
    cli
    hlt                 ; Arrête le CPU jusqu'à la prochaine interruption...
    jmp .halt           ; ...et s'il se réveille quand même, on y retourne.


; -----------------------------------------------------------------------------
;  print : affiche la chaîne pointée par si, terminée par un octet nul.
;  Chaque caractère part à deux endroits :
;    - l'écran, via le BIOS (int 0x10, fonction 0x0E « téléscripteur ») ;
;    - le port série COM1, en écrivant directement dans le matériel avec
;      l'instruction « out ». C'est ce qui nous servira à déboguer plus tard.
; -----------------------------------------------------------------------------
print:
    lodsb               ; al = [si], puis si = si + 1.
    test al, al         ; Octet nul ?
    jz .done            ; Oui : fin de chaîne.

    mov ah, 0x0E        ; Fonction BIOS : afficher le caractère contenu dans al.
    mov bx, 0x0007      ; bh = page 0, bl = couleur (gris clair).
    int 0x10

    mov dx, COM1
    out dx, al          ; Envoie l'octet directement au port série.

    jmp print
.done:
    ret


message:
    db "Bonjour depuis mon propre secteur de demarrage !", 13, 10
    db "Le CPU est en mode reel 16 bits, a l'adresse 0x7C00.", 13, 10, 0
    ; 13, 10 = retour chariot + saut de ligne. Pas d'accents : la police du
    ; BIOS utilise la page de code 437, pas l'UTF-8.


; -----------------------------------------------------------------------------
;  Remplissage et signature
; -----------------------------------------------------------------------------
;  $  = adresse courante, $$ = début de la section. On remplit de zéros
;  jusqu'à l'octet 510, puis on écrit la signature magique 0x55 0xAA.
;  Si le code dépasse 510 octets, NASM refusera d'assembler : c'est voulu.
times 510 - ($ - $$) db 0
dw 0xAA55           ; Stocké en little-endian : 0x55 puis 0xAA.
