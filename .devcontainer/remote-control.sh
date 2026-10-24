#!/usr/bin/env bash
# Lance `claude remote-control` en arrière-plan à chaque démarrage du
# conteneur, pour piloter Claude Code dans ce dépôt depuis claude.ai/code ou
# l'application mobile, sans ouvrir de terminal.
#
# Appelé par postStartCommand (devcontainer.json) : postCreateCommand ne
# tourne qu'à la création du conteneur, alors qu'un redémarrage tue aussi le
# serveur ; il faut donc le relancer à chaque démarrage.
set -u

DOSSIER="${1:-$(pwd)}"
JOURNAL="$HOME/.claude/remote-control.log"

# Un seul serveur à la fois : si postStartCommand est rejoué sans que le
# conteneur ait redémarré, on ne lance pas de doublon.
# Le motif est ancré (^) : sans cela, pgrep reconnaît aussi tout shell dont la
# ligne de commande contient ces mots, y compris celui qui lance ce script.
if pgrep -u "$(id -u)" -f "^claude remote-control" >/dev/null; then
    echo "remote-control tourne deja"
    exit 0
fi

# Sans terminal, Claude Code ne peut ni demander la connexion au compte ni
# demander si l'on fait confiance au dossier. La connexion survit aux
# reconstructions (~/.claude est un volume), mais la confiance est notée dans
# ~/.claude.json, hors du volume : après une reconstruction, il faut lancer
# `claude` une fois à la main dans le dossier, puis relancer ce script.
if [ ! -f "$HOME/.claude/.credentials.json" ]; then
    echo "remote-control non lance : se connecter d'abord avec 'claude'" | tee "$JOURNAL"
    exit 0
fi

# setsid + nohup : le processus quitte le groupe de la commande de démarrage,
# sinon l'outil devcontainer le tue en même temps que le shell qui l'a lancé.
# Les journaux vont dans ~/.claude, conservé d'une reconstruction à l'autre.
#
# Si le script est relancé à la main depuis une session Claude Code, il en
# hérite des variables CLAUDECODE et CLAUDE_CODE_* : les sessions lancées par
# le serveur se croiraient alors imbriquées dans la nôtre et échoueraient.
# On les retire ; au démarrage du conteneur, elles n'existent pas.
for variable in $(compgen -e | grep -E '^(CLAUDECODE|CLAUDE_CODE_|CLAUDE_PID)'); do
    unset "$variable"
done
cd "$DOSSIER"
CLAUDE_REMOTE_CONTROL_SESSION_NAME_PREFIX=claude-os \
    setsid nohup claude remote-control </dev/null >"$JOURNAL" 2>&1 &
echo "remote-control lance (journal : $JOURNAL)"
