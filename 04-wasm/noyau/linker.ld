/*
 * Script d'édition de liens : dit où ranger chaque morceau du noyau en mémoire.
 *
 * Le chargeur recopie l'image à 1 Mio et saute sur son PREMIER octet : la
 * section .text.debut (le point d'entrée _start) doit donc venir en tête.
 *
 * Deux adresses pour chaque section, comme pour Linux (vmlinux.lds.S) :
 *   - son adresse VIRTUELLE, où le code s'exécute : dans la moitié haute,
 *     à BASE_NOYAU + 1 Mio (voir src/espace.rs) ;
 *   - son adresse de CHARGEMENT (AT), où elle est en mémoire physique :
 *     1 Mio, là où le chargeur la recopie. objcopy range les octets de
 *     l'image selon ces adresses-là.
 * _start commence à son adresse physique, construit des tables de pages
 * qui projettent l'une sur l'autre, puis saute en haut (voir src/main.rs).
 */
ENTRY(_start)

BASE_NOYAU = 0xffffffff80000000;

SECTIONS
{
    . = BASE_NOYAU + 0x100000;

    .text : AT(ADDR(.text) - BASE_NOYAU) {
        KEEP(*(.text.debut))
        *(.text .text.*)
    }

    /* Chaque sorte de données commence sur une page de 4 Kio : plus tard,
       la pagination pourra interdire l'écriture dans le code et l'exécution
       des données, page par page (comme Linux). */
    .rodata : AT(ADDR(.rodata) - BASE_NOYAU) ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .data : AT(ADDR(.data) - BASE_NOYAU) ALIGN(4096) {
        *(.data .data.*)
        /* La GOT (Global Offset Table) : une table d'adresses par laquelle
           passe le code « indépendant de la position », que produit la
           cible x86_64-unknown-none. Comme le noyau est lié à une adresse
           fixe, l'éditeur de liens y écrit directement les bonnes adresses :
           rien à corriger au chargement. Sans cette ligne, il la plaçait
           seul, entre .rodata et .data, hors de toute règle de ce script. */
        *(.got .got.*)
    }

    /* .bss : les variables initialisées à zéro. Elle n'occupe aucune place
       dans l'image (objcopy n'écrit pas ces zéros) : c'est _start qui la
       met à zéro au démarrage, entre __bss_debut et __bss_fin. La pile du
       noyau y est aussi, pour ne dépendre d'aucune adresse du chargeur. */
    .bss : AT(ADDR(.bss) - BASE_NOYAU) ALIGN(4096) {
        __bss_debut = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __pile_bas = .;
        . += 64K;
        __pile_haut = .;
        __bss_fin = .;
    }

    /* Tables de déroulement de pile et commentaires du compilateur : inutiles
       avec panic = "abort". */
    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment)
    }
}
