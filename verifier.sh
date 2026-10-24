#!/bin/sh
# Construit chaque étape avec son Makefile, la démarre dans QEMU sans écran
# et compare serial.log avec attendu.txt (une ligne attendue par ligne,
# recherchée telle quelle). Une étape peut aussi avoir des tests qui
# tournent sur la machine hôte (la bibliothèque WebAssembly de l'étape 4) :
# la cible `tests-hote` de son Makefile, qu'on lance aussi.
# Code de sortie non nul si une étape ne produit pas ce qu'on attend.
echec=0
for etape in [0-9][0-9]-*/; do
    etape=${etape%/}
    [ -f "$etape/attendu.txt" ] || continue
    # make plutôt que nasm directement : depuis l'étape 3, l'image contient
    # aussi un noyau Rust. On n'affiche la sortie de make qu'en cas d'échec.
    if ! sortie=$(make -C "$etape" boot.bin 2>&1); then
        echo "$sortie"
        echo "ECHEC  $etape : construction"
        echec=1
        continue
    fi
    rm -f "$etape/serial.log"
    timeout 2 qemu-system-x86_64 -drive format=raw,file="$etape/boot.bin" \
        -display none -no-reboot -serial file:"$etape/serial.log" 2>/dev/null
    while IFS= read -r ligne; do
        if grep -qF -- "$ligne" "$etape/serial.log"; then
            echo "OK     $etape : $ligne"
        else
            echo "ECHEC  $etape : $ligne"
            echec=1
        fi
    done < "$etape/attendu.txt"
done
for etape in [0-9][0-9]-*/; do
    etape=${etape%/}
    grep -q '^tests-hote:' "$etape/Makefile" 2>/dev/null || continue
    if sortie=$(make -C "$etape" tests-hote 2>&1); then
        echo "OK     $etape : make tests-hote"
    else
        echo "$sortie"
        echo "ECHEC  $etape : make tests-hote"
        echec=1
    fi
done
exit $echec
