#!/usr/bin/env bash
# Démarre le conteneur de ce dépôt sans VS Code, depuis WSL : le service
# claude-os-conteneur de WSL (claude-os-conteneur.service, à côté) le lance à chaque
# démarrage de WSL, donc à l'ouverture de session de Windows (README.md). Le
# superviseur de Remote Control part avec le conteneur, et rien d'autre n'est à faire.
# Ce qu'il fait est noté dans ~/.local/state/claude-os/conteneur.log.
#
# Pourquoi pas `--restart=always` ou `unless-stopped`, qui le feraient sans service :
# Docker Desktop démarre alors le conteneur en même temps que lui, avant que les
# dossiers de WSL soient montés. Le 8 novembre au matin, il l'a fait de lui-même,
# --restart=on-failure ayant pris l'arrêt brutal de la veille pour un échec : « failed
# to fulfil mount request: open /run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/
# Ubuntu/...: no such file or directory », une seconde avant que ce montage existe. Un
# `docker start` lancé depuis WSL passe, comme VS Code, par le relais que Docker
# Desktop fait tourner dans la distribution, celui qui fait ces montages.
#
# D'où deux attentes, notées au journal quand elles servent :
# - que Docker réponde : 40 s après l'ouverture de session ce matin-là, plus pendant
#   une mise à jour de Docker Desktop, d'où 15 minutes au plus ;
# - qu'un `docker start` réussisse : juste après le démarrage de Docker, son relais
#   peut ne pas avoir fait les montages ; une minute au plus.
# Si Docker a pu démarrer le conteneur lui-même, mais avant le montage, le dossier du
# dépôt y est vide, et le superviseur attend (« montage absent ? (docker restart) ») :
# le script l'arrête et le redémarre, les montages en place cette fois.
set -u

depot=$(cd "$(dirname "$0")/.." && pwd)
# Les variables AC_* ne servent qu'aux tests (test-remote-control.sh).
DOCKER="${AC_DOCKER:-docker}"
ATTENTE="${AC_ATTENTE:-5}"
. "$(dirname "$0")/conteneur-du-depot.sh"
# Le dossier du dépôt dans le conteneur : celui que la CLI devcontainer donne par
# défaut (devcontainer.json ne règle pas workspaceFolder), et que le superviseur reçoit.
DOSSIER_CONTENEUR="/workspaces/$(basename "$depot")"

# 180 nouveaux essais à 5 s d'écart : 15 minutes au plus.
if ! reessayer 181 "$DOCKER" info; then
    noter "Docker ne repond pas : conteneur non demarre"
    exit 1
fi

conteneurs=$(conteneurs_du_depot "$depot" -a)
if [ -z "$conteneurs" ]; then
    noter "aucun conteneur pour $depot ; ouvrir le dossier une fois dans VS Code"
    exit 1
fi

resultat=0
# Un identifiant par ligne : le découpage en mots est voulu.
for conteneur in $conteneurs; do
    if [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$conteneur")" = true ]; then
        # Le même test que le superviseur (pret, dans remote-control.sh).
        if "$DOCKER" exec "$conteneur" test -e "$DOSSIER_CONTENEUR/.git"; then
            noter "conteneur $conteneur deja en marche"
            continue
        fi
        noter "conteneur $conteneur en marche, mais sans le depot dans $DOSSIER_CONTENEUR (demarre par Docker avant le montage ?) : arret, puis demarrage"
        "$DOCKER" stop "$conteneur" >/dev/null
    fi
    # 12 nouveaux essais : une minute au plus.
    if reessayer 13 "$DOCKER" start "$conteneur"; then
        noter "conteneur $conteneur demarre"
    else
        noter "conteneur $conteneur non demarre"
        resultat=1
    fi
done
exit "$resultat"
