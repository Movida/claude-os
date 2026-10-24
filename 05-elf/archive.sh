#!/bin/sh
# Fabrique l'archive de programmes que le chargeur dépose à côté du noyau :
# une archive cpio au format « newc », celui de l'initramfs de Linux (voir
# formats/src/cpio.rs pour le format, et pourquoi lui).
#
#   sh archive.sh SORTIE FICHIER...
#
# Chaque fichier est rangé sous son nom de base (sans dossier), dans
# l'ordre donné : c'est l'ordre dans lequel le noyau les exécutera.
#
# Pourquoi notre propre script plutôt que la commande cpio : Linux fait de
# même (usr/gen_init_cpio.c, un petit programme C qui écrit les en-têtes
# avec printf), pour maîtriser chaque champ. Ici : la date et les numéros
# d'utilisateur sont nuls, et les inodes numérotés dans l'ordre. L'archive
# ne dépend donc que du contenu des fichiers : deux constructions donnent
# les mêmes octets, sur la VM de David comme dans la CI.
set -eu

sortie=${1:?usage : archive.sh SORTIE FICHIER...}
shift

# Écrit N zéros (N de 0 à 3 : le remplissage jusqu'au multiple de 4).
zeros() {
    head -c "$1" /dev/zero
}

# Une entrée : en-tête de 110 octets (la marque, puis 13 champs de 8
# chiffres hexadécimaux), le nom et son zéro final, des zéros jusqu'au
# multiple de 4, le contenu, des zéros jusqu'au multiple de 4.
# Arguments : numéro d'inode, mode (en octal), nom, fichier du contenu
# (vide : pas de contenu). $position compte les octets déjà écrits.
entree() {
    ino=$1 mode=$2 nom=$3 fichier=$4
    taille=0
    [ -n "$fichier" ] && taille=$(stat -c %s "$fichier")
    taille_nom=$(( ${#nom} + 1 ))
    printf '070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X' \
        "$ino" "$((0$mode))" 0 0 1 0 "$taille" 0 0 0 0 "$taille_nom" 0
    printf '%s\0' "$nom"
    position=$(( position + 110 + taille_nom ))
    zeros $(( (4 - position % 4) % 4 ))
    position=$(( (position + 3) / 4 * 4 ))
    [ -n "$fichier" ] && cat "$fichier"
    position=$(( position + taille ))
    zeros $(( (4 - position % 4) % 4 ))
    position=$(( (position + 3) / 4 * 4 ))
}

position=0
ino=1
{
    for fichier in "$@"; do
        # Exécutable par tous, lisible par tous : 0100755 (fichier ordinaire).
        entree "$ino" 100755 "$(basename "$fichier")" "$fichier"
        ino=$(( ino + 1 ))
    done
    entree 0 0 "TRAILER!!!" ""
} > "$sortie"
