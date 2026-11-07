#!/usr/bin/env bash
# Arrête proprement le conteneur de ce dépôt, depuis WSL, puis éteint ou redémarre
# Windows si on le demande : le raccourci « Eteindre claude-os » du bureau le lance
# (README.md). À utiliser à la place du menu Démarrer pour éteindre le PC.
#
#   arreter-conteneur.sh               arrête le conteneur, sans plus
#   arreter-conteneur.sh --eteindre    puis éteint Windows
#   arreter-conteneur.sh --redemarrer  puis redémarre Windows
#
# Pourquoi : éteindre Windows arrête la machine WSL sans attendre le conteneur. Le 6
# novembre au soir, le journal du superviseur n'a gardé aucune ligne d'arrêt : soit le
# conteneur n'a pas reçu SIGTERM, soit ce qu'il a écrit en partant est resté en mémoire
# et s'est perdu avec la machine. Dans les deux cas, le serveur Remote Control n'avait
# pas noté ses sessions de fils, qu'il réveille sinon au démarrage suivant. `docker
# stop` lui envoie SIGTERM et attend la fin, 45 s au plus (--stop-timeout).
#
# Puis `sync` : toutes les distributions WSL et Docker Desktop partagent la même
# machine virtuelle et le même noyau, donc ce sync écrit aussi sur le disque le volume
# ~/.claude du conteneur. Sans lui, ce que le serveur vient d'écrire en partant (ses
# sessions, dans bridge-pointer.json, et le journal) peut rester en mémoire, et se
# perdre quand Windows tue la machine quelques secondes plus tard.
#
# Pourquoi pas un arrêt automatique, accroché à l'extinction de Windows :
# - une tâche planifiée sur l'événement d'arrêt (1074) : Windows ne l'attend pas, et
#   Docker Desktop se ferme en même temps ; une course, gagnée ou perdue selon le jour ;
# - un script de fermeture de session (stratégie de groupe) : il demande Windows
#   Pro, et rien ne garantit que Docker Desktop tourne encore quand il s'exécute ;
# - un programme qui retient l'extinction (ShutdownBlockReasonCreate) : le plus
#   automatique, mais une erreur y bloquerait l'extinction, et il ne peut pas
#   s'essayer depuis le conteneur.
# Ce qui reste sans raccourci (une mise à jour qui redémarre le PC) : le superviseur
# garde l'environnement (garder_environnement), et un message dans un fil le réveille.
#
# Après un arrêt propre, le conteneur ne repart pas seul (--restart=on-failure ne
# relance que les échecs) : la tâche planifiée de l'ouverture de session le relance
# (demarrer-conteneur.sh, README.md).
#
# Les variables AC_* ne servent qu'aux tests (test-remote-control.sh).
set -u

depot=$(cd "$(dirname "$0")/.." && pwd)
DOCKER="${AC_DOCKER:-docker}"
SHUTDOWN="${AC_SHUTDOWN:-shutdown.exe}"
SYNC="${AC_SYNC:-sync}"

case "${1:-}" in
    '') ensuite= ;;
    --eteindre) ensuite=/s ;;
    --redemarrer) ensuite=/r ;;
    *)
        echo "usage : $0 [--eteindre | --redemarrer]" >&2
        exit 2
        ;;
esac

# Quoi qu'il arrive au conteneur, Windows s'éteint ensuite si on l'a demandé : un
# échec est affiché, et la fenêtre attend Entrée pour qu'on ait le temps de le lire.
finir() {
    local code=$1
    "$SYNC"
    if [ -n "$ensuite" ]; then
        if [ "$code" -ne 0 ] && [ -t 0 ]; then
            read -r -p "Entree pour continuer quand meme... "
        fi
        exec "$SHUTDOWN" "$ensuite" /t 0
    fi
    exit "$code"
}

if ! "$DOCKER" info >/dev/null 2>&1; then
    echo "arreter-conteneur : Docker ne repond pas, aucun conteneur a arreter" >&2
    finir 1
fi

conteneur=$("$DOCKER" ps -q --filter "label=devcontainer.local_folder=$depot")
if [ -z "$conteneur" ]; then
    echo "arreter-conteneur : le conteneur de $depot ne tourne pas"
    finir 0
fi

echo "arreter-conteneur : arret du conteneur $conteneur (45 s au plus)..."
"$DOCKER" stop "$conteneur" >/dev/null
# Le superviseur sort avec 0 quand le serveur a fini proprement ; 137, c'est que
# Docker a dû le tuer au bout des 45 s.
code=$("$DOCKER" inspect -f '{{.State.ExitCode}}' "$conteneur")
if [ "$code" = 0 ]; then
    echo "arreter-conteneur : conteneur arrete proprement"
    finir 0
fi
echo "arreter-conteneur : le conteneur s'est arrete avec le code $code (journal : ~/.claude/remote-control.log)" >&2
finir 1
