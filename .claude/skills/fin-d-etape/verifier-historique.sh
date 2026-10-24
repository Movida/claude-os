#!/bin/sh
# Vérifie un historique commit par commit : chaque commit de BASE..HEAD doit
# se construire sans avertissement et passer verifier.sh. Avec SAUVEGARDE,
# vérifie en plus que l'arbre de HEAD est identique à celui de SAUVEGARDE
# (après une réécriture, rien ne doit avoir changé d'autre que l'historique).
#
#   sh .claude/skills/fin-d-etape/verifier-historique.sh BASE [SAUVEGARDE]
#
# BASE : le dernier commit déjà vérifié (en général origin/main), ou
# « racine » pour tout l'historique.
#
# Le travail se fait dans un « git worktree » temporaire : le dossier de
# travail n'est pas touché, et on peut continuer à y travailler pendant ce
# temps. Code de sortie non nul si un commit échoue ou si les arbres diffèrent.

BASE=${1:?usage : verifier-historique.sh BASE [SAUVEGARDE]}
SAUVEGARDE=${2:-}

# Commits dont l'échec est voulu : ils posent la plomberie d'une étape, qui
# ne fonctionne qu'au commit suivant. On les signale sans les compter.
ECHECS_CONNUS="Etape 02a : passage en mode protege, plomberie"

DEPOT=$(git rev-parse --show-toplevel) || exit 1
cd "$DEPOT" || exit 1

# HEAD figé au départ : on peut continuer à commiter pendant la
# vérification sans fausser la comparaison finale.
SOMMET=$(git rev-parse HEAD) || exit 1
if [ "$BASE" = racine ]; then
    COMMITS=$(git rev-list --reverse "$SOMMET")
else
    COMMITS=$(git rev-list --reverse "$BASE..$SOMMET") || exit 1
fi
[ -n "$COMMITS" ] || { echo "Aucun commit entre $BASE et HEAD."; exit 0; }

ARBRE=$(mktemp -d)
RAPPORT=$(mktemp)
# Nettoyage, même en cas d'erreur ou d'interruption (Ctrl+C).
nettoyer() {
    git worktree remove --force "$ARBRE/copie" 2>/dev/null
    rm -rf "$ARBRE" "$RAPPORT"
}
trap nettoyer EXIT INT TERM

# Un seul worktree, déplacé de commit en commit : cargo y garde ses fichiers
# compilés, et ne recompile que ce qui change d'un commit à l'autre.
git worktree add -q --detach "$ARBRE/copie" "$(echo "$COMMITS" | head -n1)" || exit 1

echec=0
for commit in $COMMITS; do
    git -C "$ARBRE/copie" checkout -q --detach "$commit" || exit 1
    sujet=$(git log -1 --format=%s "$commit")
    raison=""
    # verifier.sh n'affiche la sortie de make qu'en cas d'échec : pour voir
    # les avertissements, on construit d'abord chaque étape nous-mêmes.
    # (Pas de RUSTFLAGS="-D warnings" : cette variable remplacerait les
    # rustflags de .cargo/config.toml, dont relocation-model=static.)
    for makefile in "$ARBRE"/copie/[0-9][0-9]-*/Makefile; do
        [ -f "$makefile" ] || continue
        etape=$(dirname "$makefile")
        # Une étape sans attendu.txt n'a pas d'image à construire. Ses
        # tests sur la machine hôte (`make tests-hote`), verifier.sh les
        # lance, et ils refusent eux-mêmes les avertissements.
        [ -f "$etape/attendu.txt" ] || continue
        if ! sortie=$(make -C "$etape" boot.bin 2>&1); then
            raison="$raison construction de $(basename "$etape") ;"
        elif echo "$sortie" | grep -q '^warning'; then
            raison="$raison avertissements dans $(basename "$etape") ;"
        fi
    done
    # Les tout premiers commits n'ont pas encore de verifier.sh.
    if [ ! -f "$ARBRE/copie/verifier.sh" ]; then
        printf '%s  -               %s (pas de verifier.sh)\n' "$(git rev-parse --short "$commit")" "$sujet" >>"$RAPPORT"
        continue
    fi
    if ! (cd "$ARBRE/copie" && sh verifier.sh) >"$ARBRE/verif.log" 2>&1; then
        raison="$raison verifier.sh :$(grep '^ECHEC' "$ARBRE/verif.log" | head -n3 | sed 's/^ECHEC */ /' | tr '\n' ';')"
    fi
    court=$(git rev-parse --short "$commit")
    if [ -z "$raison" ]; then
        printf '%s  OK              %s\n' "$court" "$sujet" >>"$RAPPORT"
    elif [ "$sujet" = "$ECHECS_CONNUS" ]; then
        printf '%s  ECHEC (attendu) %s\n' "$court" "$sujet" >>"$RAPPORT"
    else
        printf '%s  ECHEC           %s\n        ->%s\n' "$court" "$sujet" "$raison" >>"$RAPPORT"
        echec=1
    fi
done

cat "$RAPPORT"

if [ -n "$SAUVEGARDE" ]; then
    echo
    if git diff --quiet "$SAUVEGARDE" "$SOMMET" >/dev/null 2>&1; then
        echo "Arbre de $(git rev-parse --short "$SOMMET") identique a celui de $SAUVEGARDE."
    else
        echo "Arbre de $(git rev-parse --short "$SOMMET") different de celui de $SAUVEGARDE :"
        git diff --stat "$SAUVEGARDE" "$SOMMET"
        echec=1
    fi
fi
exit $echec
