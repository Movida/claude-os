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
    # Le temps laissé au démarrage : 2 s, ou ce que dit l'étape (`make
    # duree`), quand elle a plus à faire (l'archive de l'étape 6, que le
    # BIOS lit secteur par secteur, grossit à chaque sous-étape).
    duree=$(make -s -C "$etape" duree 2>/dev/null) || duree=2
    # Le disque et la machine : ceux de l'étape, quand elle en demande
    # d'autres que ceux de QEMU par défaut (un disque IDE, 128 Mio, le
    # processeur qemu64). Depuis 6d, `make qemu-disque` rend l'interface du
    # disque (virtio : le BIOS de QEMU lit un disque IDE mot par mot, 74 s
    # pour les 307 Mo de l'archive de claude, contre 3,8 s en virtio), et
    # `make qemu-options` les autres options (le processeur, la mémoire).
    # Sans chemin : QEMU est lancé d'ici, pas du dossier de l'étape.
    disque=$(make -s -C "$etape" qemu-disque 2>/dev/null) && disque=",if=$disque" || disque=
    options=$(make -s -C "$etape" qemu-options 2>/dev/null) || options=
    # $options sans guillemets : plusieurs mots, un argument chacun.
    timeout "$duree" qemu-system-x86_64 -drive format=raw,file="$etape/boot.bin$disque" $options \
        -display none -no-reboot -serial file:"$etape/serial.log" 2>/dev/null
    # Chaque ligne attendue, cherchée telle quelle n'importe où dans le
    # journal ; ou, depuis 6k, quand attendu.txt commence par « # Dans
    # l'ordre », chacune après la précédente (voir verifier-ordre.awk : les
    # commentaires, les lignes qui peuvent venir n'importe où, les parties
    # qui changent d'un démarrage à l'autre). Les étapes d'avant gardent
    # leur fichier, et la première façon.
    if head -n 1 "$etape/attendu.txt" | grep -q "^# Dans l'ordre"; then
        LC_ALL=C awk -v etape="$etape" -f verifier-ordre.awk "$etape/serial.log" "$etape/attendu.txt" || echec=1
    else
        while IFS= read -r ligne; do
            if grep -qF -- "$ligne" "$etape/serial.log"; then
                echo "OK     $etape : $ligne"
            else
                echo "ECHEC  $etape : $ligne"
                echec=1
            fi
        done < "$etape/attendu.txt"
    fi
    # Et aucun échec : le noyau dit « ok » ou « ECHEC » pour chacune de ses
    # vérifications, et « PANIQUE » s'il s'arrête. Une ligne attendue
    # trouvée n'importe où ne prouve pas qu'aucune autre n'a échoué
    # (depuis 6h ; make tests-qemu le faisait déjà pour son journal).
    if grep -nE 'ECHEC|PANIQUE' "$etape/serial.log"; then
        echo "ECHEC  $etape : un ECHEC ou une PANIQUE dans le journal du demarrage"
        echec=1
    fi
done
# Les tests sur l'hôte (`tests-hote`) dépendent du noyau de la machine : ils
# tournent sous le Linux de référence (6.18.33, CLAUDE.md), dans sa machine
# virtuelle quand la machine en a un autre (la CI de GitHub), sur elle sinon
# (WSL, sous le conteneur). Les démarrages et `tests-qemu` ne dépendent que de
# QEMU : sur la machine même. Pendant un jour (10 novembre 2026), toute la CI
# tournait dans la machine virtuelle : QEMU sans KVM y émulait deux fois plus
# lentement (64 min au lieu de 29), et des tests de temps des anciennes étapes
# y échouaient (le démarrage coupé par sa durée, une limite de temps de
# calcul atteinte).
case "$(uname -r)" in
    6.18.33*) reference= ;;
    *) reference=.devcontainer/linux-de-reference.sh ;;
esac
for etape in [0-9][0-9]*-*/; do
    etape=${etape%/}
    for cible in tests-hote tests-qemu; do
        grep -q "^$cible:" "$etape/Makefile" 2>/dev/null || continue
        lanceur=
        [ "$cible" = tests-hote ] && lanceur=$reference
        if sortie=$($lanceur make -C "$etape" "$cible" 2>&1); then
            echo "OK     $etape : make $cible"
        else
            echo "$sortie"
            echo "ECHEC  $etape : make $cible"
            echec=1
        fi
    done
done
exit $echec
