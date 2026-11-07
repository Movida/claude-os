#!/usr/bin/env bash
# Démarre le conteneur de ce dépôt sans VS Code, depuis WSL : la tâche planifiée
# de Windows le lance à l'ouverture de session (README.md). Le superviseur de
# Remote Control part avec le conteneur, et rien d'autre n'est à faire.
#
# Pourquoi pas `--restart=always` ou `unless-stopped`, qui le feraient sans tâche :
# Docker Desktop démarre alors le conteneur en même temps que lui, et les montages
# des dossiers de WSL peuvent manquer à ce moment-là, ou rester vides. Un `docker
# start` lancé depuis WSL passe par le même chemin que VS Code, celui qui marche.
set -u

depot=$(cd "$(dirname "$0")/.." && pwd)
# Les variables AC_* ne servent qu'aux tests (test-remote-control.sh).
DOCKER="${AC_DOCKER:-docker}"
ATTENTE="${AC_ATTENTE:-5}"
. "$(dirname "$0")/conteneur-du-depot.sh"

# Docker Desktop met un moment à démarrer après l'ouverture de session.
essai=0
until "$DOCKER" info >/dev/null 2>&1; do
    essai=$((essai + 1))
    if [ "$essai" -ge 60 ]; then
        echo "demarrer-conteneur : Docker ne repond pas apres 5 minutes" >&2
        exit 1
    fi
    sleep "$ATTENTE"
done

conteneurs=$(conteneurs_du_depot "$depot" -a)
if [ -z "$conteneurs" ]; then
    echo "demarrer-conteneur : aucun conteneur pour $depot ; ouvrir le dossier une fois dans VS Code" >&2
    exit 1
fi
# Un identifiant par ligne : le découpage en mots est voulu.
exec "$DOCKER" start $conteneurs
