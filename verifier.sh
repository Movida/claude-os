#!/bin/sh
# Démarre chaque étape dans QEMU sans écran et compare serial.log avec
# attendu.txt (une ligne attendue par ligne, recherchée telle quelle).
# Code de sortie non nul si une étape ne produit pas ce qu'on attend.
echec=0
for etape in [0-9][0-9]-*/; do
    etape=${etape%/}
    [ -f "$etape/attendu.txt" ] || continue
    nasm -f bin "$etape/boot.asm" -o "$etape/boot.bin" || { echec=1; continue; }
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
exit $echec
