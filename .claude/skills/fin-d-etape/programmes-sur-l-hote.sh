#!/bin/bash
# programmes-sur-l-hote.sh ETAPE : la partie « programmes » de `make
# tests-hote` de l'étape (sans les tests de cargo, qui ne dépendent pas du
# noyau et prennent des heures sous TCG), chaque commande par sh -c comme
# make, pour la passer sous le Linux de référence avant un push :
#
#   .devcontainer/linux-de-reference.sh bash .claude/skills/fin-d-etape/programmes-sur-l-hote.sh 06k-terminal
#
# L'étape doit être construite (`make tests-hote` une fois sur l'hôte) : les
# lignes de `make -n` qui referaient quelque chose seraient lancées aussi.
cd "$1" || exit 2
echec=0
while IFS= read -r -d '' commande; do
    if sh -c "$commande"; then :; else
        echo "ECHEC (code $?) : $commande"
        echec=1
    fi
done < <(make -n tests-hote 2>/dev/null | grep -v -E "^(cd |make|if sudo)" \
         | awk '{ c = c $0 "\n" } !/\\$/ { printf "%s%c", c, 0; c = "" }')
echo "programmes de $1 : $([ $echec = 0 ] && echo ok || echo ECHEC)"
exit $echec
