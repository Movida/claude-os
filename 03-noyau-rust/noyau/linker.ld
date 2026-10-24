/*
 * Script d'édition de liens : dit où ranger chaque morceau du noyau en mémoire.
 *
 * Le chargeur recopie l'image à 1 Mio et saute sur son PREMIER octet : la
 * section .text.debut (le point d'entrée _start) doit donc venir en tête.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    .text : {
        KEEP(*(.text.debut))
        *(.text .text.*)
    }

    /* Chaque sorte de données commence sur une page de 4 Kio : plus tard,
       la pagination pourra interdire l'écriture dans le code et l'exécution
       des données, page par page (comme Linux). */
    .rodata : ALIGN(4096) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096) {
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
    .bss : ALIGN(4096) {
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
