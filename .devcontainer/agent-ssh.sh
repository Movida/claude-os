#!/usr/bin/env bash
# Lance ssh ou ssh-keygen avec un agent SSH joignable : celui de Windows
# (1Password), que VS Code transmet au conteneur.
#
# Git s'en sert pour pousser et pour signer les commits, dans le conteneur
# seulement : WSL lit le même .git sous un autre chemin, où ce script
# n'existe pas (le push et la signature y échouaient). Les deux réglages
# sont donc dans .git/conteneur.config, que .git/config n'inclut que sous
# /workspaces :
#   git config 'includeIf.gitdir:/workspaces/claude-os/.path' conteneur.config
# avec, dans .git/conteneur.config :
#   [core]
#       sshCommand = /workspaces/claude-os/.devcontainer/agent-ssh.sh ssh
#   [gpg "ssh"]
#       program = /workspaces/claude-os/.devcontainer/agent-ssh.sh
# Appelé sans commande (cas de gpg.ssh.program), il lance ssh-keygen.
#
# VS Code ouvre une prise /tmp/vscode-ssh-auth-*.sock à chaque connexion de
# la fenêtre, et n'en donne le chemin (SSH_AUTH_SOCK) qu'aux processus qu'il
# lance ensuite. Remote Control, lancé au démarrage du conteneur avant toute
# fenêtre (remote-control.sh), n'a donc jamais d'agent, ni les sessions qu'il
# ouvre ; et un terminal ouvert avant un « Reload Window » garde une prise
# morte. On cherche donc la prise vivante au moment où git en a besoin.
set -u

# ssh-add -l rend 2 quand il ne joint pas l'agent (0 : des clés, 1 : aucune).
joignable() {
    SSH_AUTH_SOCK="$1" ssh-add -l >/dev/null 2>&1
    [ $? -ne 2 ]
}

if [ -z "${SSH_AUTH_SOCK:-}" ] || ! joignable "$SSH_AUTH_SOCK"; then
    unset SSH_AUTH_SOCK
    # La plus récente d'abord : les prises des fenêtres fermées restent dans /tmp.
    for prise in $(ls -t /tmp/vscode-ssh-auth-*.sock 2>/dev/null); do
        if joignable "$prise"; then
            export SSH_AUTH_SOCK="$prise"
            break
        fi
    done
fi
if [ -z "${SSH_AUTH_SOCK:-}" ]; then
    echo "agent-ssh : aucun agent SSH joignable. Ouvrir 1Password sous Windows," >&2
    echo "puis lancer « Developer: Reload Window » dans VS Code." >&2
fi

case "${1:-}" in
    ssh | ssh-keygen) exec "$@" ;;
    *) exec ssh-keygen "$@" ;;
esac
