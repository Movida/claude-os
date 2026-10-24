#!/bin/sh
# Construit chaque étape avec son Makefile, la démarre dans QEMU sans écran
# et compare serial.log avec attendu.txt (une ligne attendue par ligne,
# recherchée telle quelle). Une étape peut aussi avoir, dans son Makefile :
#   - `tests-hote` : des tests qui tournent sur la machine hôte (la
#     bibliothèque WebAssembly de l'étape 4) ;
#   - `tests-qemu` : des scénarios de panne, dans QEMU (le noyau provoque
#     exprès une erreur, et doit l'arrêter avec un message clair).
# On les lance aussi.
# Code de sortie non nul si une étape ne produit pas ce qu'on attend.
#
# Les dossiers d'étape : deux chiffres, puis un nom (`05-elf/`), ou une
# lettre de sous-étape avant le nom (`06a-memoire/`) ; d'où le motif
# [0-9][0-9]*-*/. L'ordre alphabétique est celui des étapes.
echec=0
for etape in [0-9][0-9]*-*/; do
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
for etape in [0-9][0-9]*-*/; do
    etape=${etape%/}
    for cible in tests-hote tests-qemu; do
        grep -q "^$cible:" "$etape/Makefile" 2>/dev/null || continue
        if sortie=$(make -C "$etape" "$cible" 2>&1); then
            echo "OK     $etape : make $cible"
        else
            echo "$sortie"
            echo "ECHEC  $etape : make $cible"
            echec=1
        fi
    done
done
exit $echec
