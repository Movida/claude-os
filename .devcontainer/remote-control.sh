#!/usr/bin/env bash
# Lance `claude remote-control` en arrière-plan à chaque démarrage du
# conteneur, pour piloter Claude Code dans ce dépôt depuis claude.ai/code ou
# l'application mobile, sans ouvrir de terminal.
#
# Appelé par postStartCommand (devcontainer.json) : postCreateCommand ne
# tourne qu'à la création du conteneur, alors qu'un redémarrage tue aussi le
# serveur ; il faut donc le relancer à chaque démarrage.
#
# Sans terminal, Claude Code ne peut rien demander (connexion au compte,
# confiance dans le dossier, accord pour Remote Control) : une question
# sans réponse, et le serveur s'arrête sans rien dire. Ce script vérifie
# donc d'avance ce que Claude Code demanderait, et écrit dans le journal ce
# qui manque et comment y remédier, plutôt que de lancer un serveur qui
# s'arrêtera. Tout ce qu'il fait est daté dans le journal.
set -u

DOSSIER="${1:-$(pwd)}"
# Le dossier de configuration de Claude Code : ~/.claude, un volume qui
# survit aux reconstructions. Avec CLAUDE_CONFIG_DIR (devcontainer.json),
# Claude Code y range aussi .claude.json (la connexion au compte, la
# confiance dans chaque dossier, l'accord pour Remote Control), qu'il met
# sinon dans ~/.claude.json, hors du volume : perdu à chaque reconstruction.
CONFIG="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
JOURNAL="$CONFIG/remote-control.log"

noter() {
    echo "$(date '+%F %T') remote-control.sh : $*" | tee -a "$JOURNAL"
}

# Un seul serveur à la fois : si postStartCommand est rejoué sans que le
# conteneur ait redémarré, ou si le serveur a été lancé à la main dans un
# terminal (sa sortie va alors dans ce terminal, pas dans le journal), on ne
# lance pas de doublon. Le motif est ancré (^) : sans cela, pgrep reconnaît
# aussi tout shell dont la ligne de commande contient ces mots, y compris
# celui qui lance ce script. (Depuis une session Claude Code dont le bac à
# sable cache les processus, `ps` ne montre pas le serveur : c'est pgrep,
# ici, qui dit vrai.)
if serveurs=$(pgrep -u "$(id -u)" -f "^claude remote-control"); then
    noter "remote-control tourne deja (pid $(echo $serveurs)) ;" \
        "pour le relancer : pkill -f '^claude remote-control', puis ce script"
    exit 0
fi

# .claude.json, s'il manque : celui de ~ (le passage à CLAUDE_CONFIG_DIR,
# une fois), sinon la sauvegarde la plus récente que Claude Code tient dans
# ~/.claude/backups (après une reconstruction, sans CLAUDE_CONFIG_DIR).
if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
    CONFIGURATION="$CONFIG/.claude.json"
else
    CONFIGURATION="$HOME/.claude.json"
fi
if [ ! -f "$CONFIGURATION" ]; then
    sauvegarde=$(ls -t "$CONFIG"/backups/.claude.json.backup.* 2>/dev/null | head -n 1)
    if [ "$CONFIGURATION" != "$HOME/.claude.json" ] && [ -f "$HOME/.claude.json" ]; then
        cp -p "$HOME/.claude.json" "$CONFIGURATION"
        noter "configuration reprise de ~/.claude.json"
    elif [ -n "$sauvegarde" ]; then
        cp -p "$sauvegarde" "$CONFIGURATION"
        noter "configuration restauree depuis $sauvegarde"
    fi
fi

# Ce que Claude Code demanderait.
if [ ! -f "$CONFIG/.credentials.json" ]; then
    noter "non lance : pas de connexion au compte ; lancer 'claude' dans un" \
        "terminal, se connecter, puis relancer ce script"
    exit 0
fi
confiance=$(jq -r --arg d "$DOSSIER" '.projects[$d].hasTrustDialogAccepted // false' "$CONFIGURATION" 2>/dev/null)
if [ "$confiance" != true ]; then
    noter "non lance : $DOSSIER n'est pas marque de confiance ; lancer 'claude'" \
        "une fois dans ce dossier, accepter, puis relancer ce script"
    exit 0
fi

# setsid + nohup : le processus quitte le groupe de la commande de démarrage,
# sinon l'outil devcontainer le tue en même temps que le shell qui l'a lancé.
#
# Si le script est relancé à la main depuis une session Claude Code, il en
# hérite des variables CLAUDECODE et CLAUDE_CODE_* : les sessions lancées par
# le serveur se croiraient alors imbriquées dans la nôtre et échoueraient.
# On les retire ; au démarrage du conteneur, elles n'existent pas.
for variable in $(compgen -e | grep -E '^(CLAUDECODE|CLAUDE_CODE_|CLAUDE_PID)'); do
    unset "$variable"
done
cd "$DOSSIER" || { noter "non lance : dossier $DOSSIER introuvable"; exit 0; }
CLAUDE_REMOTE_CONTROL_SESSION_NAME_PREFIX=claude-os \
    setsid nohup claude remote-control </dev/null >>"$JOURNAL" 2>&1 &
serveur=$!

# Une question restée sans réponse, ou une erreur, l'arrête dans les
# premières secondes : on le dit, plutôt que de laisser croire qu'il tourne.
sleep 5
if kill -0 "$serveur" 2>/dev/null; then
    noter "remote-control lance (pid $serveur, journal : $JOURNAL)"
else
    noter "remote-control s'est arrete aussitot : voir les lignes au-dessus" \
        "dans $JOURNAL, ou lancer 'claude remote-control' dans un terminal"
fi
