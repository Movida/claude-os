#!/bin/sh
# Fabrique l'archive que le chargeur dépose à côté du noyau : une archive
# cpio au format « newc », celui de l'initramfs de Linux (voir
# formats/src/cpio.rs pour le format, et pourquoi lui). Le noyau la
# déballe dans son système de fichiers en mémoire (6b), puis exécute les
# programmes de /bin, dans l'ordre de l'archive.
#
#   sh archive.sh SORTIE DESCRIPTION
#
# DESCRIPTION (un fichier, ou « - » pour l'entrée standard) dit ce que
# contient l'archive, une ligne par entrée, dans le format de
# gen_init_cpio, l'outil de Linux (usr/gen_init_cpio.c) :
#   dir   NOM MODE UID GID                     un dossier
#   file  NOM SOURCE MODE UID GID [LIEN...]    un fichier, copie de SOURCE,
#                                              avec d'autres noms (des liens
#                                              physiques) si on en donne
#   slink NOM CIBLE MODE UID GID               un lien symbolique
# NOM est un chemin absolu (« /bin/bonjour-c »), MODE les droits en octal
# (755). Les lignes vides et celles qui commencent par « # » sont
# ignorées. Un dossier doit venir avant ce qu'il contient.
#
# Pourquoi notre propre script plutôt que la commande cpio : Linux fait de
# même (gen_init_cpio, un petit programme C qui écrit les en-têtes avec
# printf), pour maîtriser chaque champ. Ici : la date est nulle, et les
# inodes numérotés dans l'ordre. L'archive ne dépend donc que de sa
# description et du contenu des fichiers : deux constructions donnent les
# mêmes octets, sur la VM de David comme dans la CI.
#
# Les liens physiques, comme gen_init_cpio et GNU cpio : une entrée par
# nom, toutes avec le même numéro d'inode et le nombre de liens, et le
# contenu seulement dans la dernière.
set -eu

sortie=${1:?usage : archive.sh SORTIE DESCRIPTION}
description=${2:?usage : archive.sh SORTIE DESCRIPTION}

# Écrit N zéros (N de 0 à 3 : le remplissage jusqu'au multiple de 4).
zeros() {
    head -c "$1" /dev/zero
}

# Une entrée : en-tête de 110 octets (la marque, puis 13 champs de 8
# chiffres hexadécimaux), le nom et son zéro final, des zéros jusqu'au
# multiple de 4, le contenu, des zéros jusqu'au multiple de 4.
# Arguments : numéro d'inode, mode (un nombre, type compris), uid, gid,
# nombre de liens, nom (sans « / » au début, comme gen_init_cpio), puis
# d'où vient le contenu : « fichier CHEMIN », « texte CHAINE », ou rien.
# $position compte les octets déjà écrits.
# (Le shell n'a pas de variables locales : les siennes commencent par e_,
# pour ne pas écraser celles de l'appelant.)
entree() {
    e_ino=$1 e_mode=$2 e_uid=$3 e_gid=$4 e_liens=$5 e_nom=$6
    shift 6
    taille=0
    case ${1:-} in
        fichier) taille=$(stat -c %s "$2") ;;
        texte) taille=$(printf '%s' "$2" | wc -c) ;;
    esac
    taille_nom=$(( $(printf '%s' "$e_nom" | wc -c) + 1 ))
    printf '070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X' \
        "$e_ino" "$e_mode" "$e_uid" "$e_gid" "$e_liens" 0 "$taille" 0 0 0 0 "$taille_nom" 0
    printf '%s\0' "$e_nom"
    position=$(( position + 110 + taille_nom ))
    zeros $(( (4 - position % 4) % 4 ))
    position=$(( (position + 3) / 4 * 4 ))
    case ${1:-} in
        fichier) cat "$2" ;;
        texte) printf '%s' "$2" ;;
    esac
    position=$(( position + taille ))
    zeros $(( (4 - position % 4) % 4 ))
    position=$(( (position + 3) / 4 * 4 ))
}

# Le nom dans l'archive : sans les « / » du début.
sans_racine() {
    printf '%s' "$1" | sed 's|^/*||'
}

position=0
ino=1
{
    # Lit la description depuis le fichier (ou l'entrée standard), en
    # découpant chaque ligne en mots.
    if [ "$description" = - ]; then cat; else cat "$description"; fi | while read -r genre nom reste; do
        case $genre in
            '' | '#'*) continue ;;
        esac
        # shellcheck disable=SC2086 # le découpage en mots est voulu
        set -- $reste
        case $genre in
            dir)
                entree "$ino" $(( 0040000 | 0$1 )) "$2" "$3" 2 "$(sans_racine "$nom")"
                ;;
            file)
                source=$1 mode=$2 uid=$3 gid=$4
                shift 4
                liens=$(( $# + 1 ))
                # Les autres noms d'abord, sans contenu ; le contenu avec le
                # dernier.
                noms="$nom $*"
                n=0
                for un_nom in $noms; do
                    n=$(( n + 1 ))
                    if [ "$n" -eq "$liens" ]; then
                        entree "$ino" $(( 0100000 | 0$mode )) "$uid" "$gid" "$liens" "$(sans_racine "$un_nom")" fichier "$source"
                    else
                        entree "$ino" $(( 0100000 | 0$mode )) "$uid" "$gid" "$liens" "$(sans_racine "$un_nom")"
                    fi
                done
                ;;
            slink)
                entree "$ino" $(( 0120000 | 0$2 )) "$3" "$4" 1 "$(sans_racine "$nom")" texte "$1"
                ;;
            *)
                echo "archive.sh : genre d'entree inconnu : $genre" >&2
                exit 1
                ;;
        esac
        ino=$(( ino + 1 ))
    done
    # La boucle tourne dans un sous-shell (le tube) : sa position est
    # perdue. Elle n'importe pas : chaque entrée finit sur un multiple de
    # 4, seul le reste de la division compte pour le remplissage.
    position=0
    entree 0 0 0 0 1 "TRAILER!!!"
} > "$sortie"
