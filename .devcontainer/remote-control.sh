#!/usr/bin/env bash
# Le superviseur de `claude remote-control` : le processus principal du
# conteneur (le CMD du Dockerfile, copié dans l'image). Il garde le serveur en
# vie pour piloter Claude Code dans ce dépôt depuis claude.ai/code ou
# l'application mobile, sans terminal ni fenêtre VS Code.
#
# Pourquoi le processus principal, et pas postStartCommand comme avant :
# - postStartCommand, c'est VS Code qui l'exécute en s'attachant au conteneur :
#   un conteneur démarré sans fenêtre VS Code n'avait pas de serveur ;
# - le serveur reçoit enfin SIGTERM à l'arrêt du conteneur. Avant, le PID 1 de
#   VS Code (`trap "exit 0" 15`) sortait aussitôt et le noyau tuait tout le
#   reste par SIGKILL. Or c'est à l'arrêt propre que le serveur écrit dans
#   bridge-pointer.json la liste des sessions de fils, actives et « parquées »
#   (inactives, leur processus fini), qu'il réveille au démarrage suivant :
#   chaque redémarrage du conteneur les oubliait.
# - un serveur mort se relance tout seul. Le serveur abandonne de lui-même
#   après 10 minutes d'erreurs de réseau, et s'arrête s'il ne peut pas
#   s'enregistrer au démarrage (Wi-Fi pas encore là) : personne ne le relançait.
#
# Pourquoi pas les autres façons de faire :
# - tmux : il n'apporterait qu'une fenêtre à regarder, le journal le fait, et
#   il ajouterait un serveur de plus à faire vivre ;
# - supervisord, s6... : une dépendance de plus pour une seule boucle ;
# - une surveillance de la santé du serveur (le tuer s'il ne dit plus rien) :
#   un serveur inactif n'écrit rien et ne donne aucun signal fiable. Une erreur
#   tuerait des sessions qui marchent, et le journal le montre se reconnecter
#   seul en quelques secondes. On relance donc ce qui meurt, pas ce qui se tait.
#
# Pas de `set -e` ni de `set -u` : si ce script meurt, le conteneur s'arrête
# avec lui, VS Code et les sessions compris. Une variable vide ou une commande
# en échec doivent être notées, jamais fatales.
#
# Sans terminal, Claude Code ne peut rien demander (connexion au compte,
# confiance dans le dossier, accord pour Remote Control) : une question sans
# réponse, et le serveur s'arrête sans rien dire. Le script vérifie donc d'avance
# ce que Claude Code demanderait, écrit dans le journal ce qui manque et comment
# y remédier, puis attend : le serveur démarre dès que c'est réglé.
#
# Mode d'emploi et réglages côté Windows : README.md, à côté de ce script.
# Tests (avec un faux serveur, sans toucher au vrai) : test-remote-control.sh.

DOSSIER="${1:-/workspaces/claude-os}"
# Le dossier de configuration de Claude Code : ~/.claude, un volume qui
# survit aux reconstructions. Avec CLAUDE_CONFIG_DIR (devcontainer.json),
# Claude Code y range aussi .claude.json (la connexion au compte, la
# confiance dans chaque dossier, l'accord pour Remote Control), qu'il met
# sinon dans ~/.claude.json, hors du volume : perdu à chaque reconstruction.
CONFIG="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
JOURNAL="$CONFIG/remote-control.log"
# Tant que ce fichier existe, le serveur reste arrêté (pour le lancer à la main
# dans un terminal, par exemple) ; le retirer le relance.
PAUSE="$CONFIG/remote-control.pause"

# Les variables RC_* ne servent qu'aux tests.
COMMANDE="${RC_CLAUDE:-claude}"
# Le rythme de la boucle, en secondes. La relance double à chaque échec, de
# PERIODE à ATTENTE_MAX ; une fois DUREE_STABLE tenue, elle repart de PERIODE.
PERIODE="${RC_PERIODE:-5}"
ATTENTE_MAX=$((PERIODE * 60))
DUREE_STABLE="${RC_DUREE_STABLE:-600}"
# Une attente qui dure 4 périodes de trop : le conteneur a été figé.
SEUIL_GEL=$((PERIODE * 4))
EVENEMENTS_MEMOIRE="${RC_EVENEMENTS_MEMOIRE:-/sys/fs/cgroup/memory.events}"
# Le filtre ne garde que l'essentiel : quelques dizaines de lignes par jour. Ce
# plafond ne joue donc que si une erreur se répète en boucle.
TAILLE_MAX="${RC_TAILLE_MAX:-$((10 * 1024 * 1024))}"

arret=
serveur=
filtre=

noter() {
    # Dans le journal, et sur la sortie du conteneur (docker logs). Le tube garde
    # le superviseur d'un SIGPIPE : seul le sous-shell du printf en mourrait.
    printf '%(%F %T)T remote-control.sh : %s\n' -1 "$*" | tee -a "$JOURNAL"
}

# Une attente que SIGTERM interrompt aussitôt : `wait` rend la main dès qu'un
# signal a un trap, alors qu'un `sleep` au premier plan le ferait patienter.
#
# Elle sert aussi à voir les gels : quand Windows se met en veille, la machine
# virtuelle s'arrête, `sleep` avec elle, mais l'horloge rattrape son retard au
# réveil. Une attente bien plus longue que demandé, c'est un conteneur figé.
dormir() {
    local debut=$EPOCHSECONDS
    sleep "$1" &
    local minuteur=$!
    wait "$minuteur"
    kill "$minuteur" 2>/dev/null
    local retard=$((EPOCHSECONDS - debut - $1))
    if [ "$retard" -gt "$SEUIL_GEL" ]; then
        noter "conteneur fige pendant ${retard}s (veille de Windows ou memoire saturee)"
    fi
}

# Docker envoie SIGTERM à l'arrêt du conteneur (par docker-init, "init": true) ;
# --stop-timeout laisse au serveur le temps de finir (30 s au plus pour ses
# sessions, puis la mise hors ligne de l'environnement).
arreter() {
    arret=1
    [ -n "$serveur" ] && kill -TERM "$serveur" 2>/dev/null
}
trap arreter TERM INT HUP

# Le serveur redessine son état sur la sortie, en moyenne cinq lignes par seconde
# dès qu'une session tourne, même vers un fichier : 106 Mo en dix jours, où les
# événements utiles étaient noyés. On ne garde que ce qui change. Le test porte
# sur ce qu'il faut jeter : une ligne inconnue passe, on ne perd pas une erreur.
filtrer_serveur() {
    sed -u -E \
        -e 's/\x1b\]8;;[^\x07\x1b]*(session_[A-Za-z0-9]+)[^\x07\x1b]*(\x07|\x1b\\)/\1 /g' \
        -e 's/\x1b\][^\x07\x1b]*(\x07|\x1b\\)//g' \
        -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' \
        -e 's/^·[^ ]*· //' \
        -e 's/^ +//; s/ +$//' |
    {
        local -A vues=()
        local ligne etat= capacite=
        while IFS= read -r ligne; do
            case $ligne in
                '') continue ;;
                # Un événement daté par le serveur : toujours.
                '['[0-9][0-9]:*) ;;
                # Son état, quand il change. Pendant une reconnexion, le délai
                # change à chaque ligne : seul le début compte.
                Reconnecting*)
                    [ "$etat" = Reconnecting ] && continue
                    etat=Reconnecting
                    ;;
                Connecting*|Connected*|Ready*)
                    [ "$etat" = "$ligne" ] && continue
                    etat=$ligne
                    ;;
                Capacity:*)
                    [ "$capacite" = "$ligne" ] && continue
                    capacite=$ligne
                    ;;
                # Le reste (titres de sessions, adresses) : une fois par serveur.
                *)
                    [ -n "${vues[$ligne]}" ] && continue
                    vues[$ligne]=1
                    ;;
            esac
            # Le fichier est rouvert à chaque ligne : la rotation peut le déplacer.
            printf '%(%F %T)T serveur : %s\n' -1 "$ligne" >>"$JOURNAL"
        done
    }
}

# .claude.json, s'il manque : celui de ~ (le passage à CLAUDE_CONFIG_DIR,
# une fois), sinon la sauvegarde la plus récente que Claude Code tient dans
# ~/.claude/backups (après une reconstruction, sans CLAUDE_CONFIG_DIR).
restaurer_configuration() {
    if [ -n "${CLAUDE_CONFIG_DIR:-}" ]; then
        CONFIGURATION="$CONFIG/.claude.json"
    else
        CONFIGURATION="$HOME/.claude.json"
    fi
    [ -f "$CONFIGURATION" ] && return
    local sauvegarde
    sauvegarde=$(ls -t "$CONFIG"/backups/.claude.json.backup.* 2>/dev/null | head -n 1)
    if [ "$CONFIGURATION" != "$HOME/.claude.json" ] && [ -f "$HOME/.claude.json" ]; then
        cp -p "$HOME/.claude.json" "$CONFIGURATION"
        noter "configuration reprise de ~/.claude.json"
    elif [ -n "$sauvegarde" ]; then
        cp -p "$sauvegarde" "$CONFIGURATION"
        noter "configuration restauree depuis $sauvegarde"
    fi
}

# Peut-on lancer le serveur ? Sinon, `raison` dit ce qui manque.
pret() {
    raison=
    if [ -e "$PAUSE" ]; then
        raison="en pause : retirer $PAUSE pour relancer le serveur"
        return 1
    fi
    # Docker Desktop peut démarrer un conteneur avant que le dossier de WSL soit
    # monté : un dossier vide ne donnerait qu'un serveur sans dépôt.
    if [ ! -e "$DOSSIER/.git" ]; then
        raison="$DOSSIER n'est pas un depot git : montage absent ? (docker restart)"
        return 1
    fi
    restaurer_configuration
    if [ ! -f "$CONFIG/.credentials.json" ]; then
        raison="pas de connexion au compte : lancer 'claude' dans un terminal et se connecter"
        return 1
    fi
    local confiance
    confiance=$(jq -r --arg d "$DOSSIER" '.projects[$d].hasTrustDialogAccepted // false' "$CONFIGURATION" 2>/dev/null)
    if [ "$confiance" != true ]; then
        raison="$DOSSIER n'est pas marque de confiance : lancer 'claude' une fois dans ce dossier et accepter"
        return 1
    fi
    # Un serveur lancé à la main dans un terminal : pas de doublon, le serveur
    # refuserait de toute façon de partager son dossier. On prend la suite quand
    # il s'arrête. Le motif est ancré (^) : sans cela, pgrep reconnaîtrait aussi
    # tout shell dont la ligne de commande contient ces mots.
    local autres
    if autres=$(pgrep -u "$(id -u)" -f "^$COMMANDE remote-control"); then
        raison="un serveur tourne hors supervision (pid $(echo $autres)) : relais a son arret"
        return 1
    fi
    return 0
}

# Attend que le serveur puisse partir, en notant chaque nouvelle raison une fois.
attendre_conditions() {
    local derniere=
    while [ -z "$arret" ] && ! pret; do
        if [ "$raison" != "$derniere" ]; then
            noter "en attente : $raison"
            derniere=$raison
        fi
        dormir "$PERIODE"
        surveiller
    done
}

# Ce qui ne se voyait pas : avec les gels notés par dormir, on saura si une session
# perdue vient de la veille ou de la mémoire, au lieu de le deviner.
oom_vus=
surveiller() {
    local cle valeur oom=0
    if [ -r "$EVENEMENTS_MEMOIRE" ]; then
        while read -r cle valeur; do
            [ "$cle" = oom_kill ] && oom=$valeur
        done <"$EVENEMENTS_MEMOIRE"
    fi
    if [ -n "$oom_vus" ] && [ "$oom" -gt "$oom_vus" ]; then
        noter "plafond de memoire atteint : $((oom - oom_vus)) processus tue(s) par le noyau"
    fi
    oom_vus=$oom

    local taille
    taille=$(stat -c %s "$JOURNAL" 2>/dev/null)
    if [ "${taille:-0}" -gt "$TAILLE_MAX" ]; then
        mv -f "$JOURNAL" "$JOURNAL.1"
        noter "journal deplace dans $JOURNAL.1 (il faisait $taille octets)"
    fi
}

# Le filtre a son propre descripteur, ouvert avant le serveur et fermé ensuite :
# `$!` donne ainsi le pid du serveur, ce que `claude | filtre &` ne donnerait pas.
lancer_serveur() {
    cd "$DOSSIER" || return
    exec 3> >(filtrer_serveur 9>&-)
    filtre=$!
    CLAUDE_REMOTE_CONTROL_SESSION_NAME_PREFIX=claude-os \
        "$COMMANDE" remote-control </dev/null >&3 2>&3 3>&- 9>&- &
    serveur=$!
    exec 3>&-
}

# Le filtre finit quand plus personne n'écrit dans le tube. Le serveur ne passe
# pas sa sortie aux sessions (elles ont leurs propres tubes), mais une borne
# garde la boucle de rester bloquée si cela changeait.
attendre_filtre() {
    local essai
    for essai in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$filtre" 2>/dev/null || return
        sleep 0.2
    done
    kill "$filtre" 2>/dev/null
}

mkdir -p "$CONFIG"

# Un seul superviseur : s'il est relancé à la main alors que le conteneur a déjà
# le sien, celui-ci s'en va. Le noyau rend le verrou quand le processus meurt,
# alors qu'un fichier de pid survivrait à un arrêt brutal. Le descripteur n'est
# pas transmis au serveur (9>&-) : le verrou suit le superviseur, pas lui.
if exec 9>>"$CONFIG/remote-control.verrou"; then
    if ! flock -n 9; then
        noter "un superviseur tourne deja : rien a faire (journal : $JOURNAL)"
        exit 0
    fi
else
    noter "verrou impossible dans $CONFIG : on continue sans lui"
fi

# Les réglages git propres au conteneur (l'agent SSH, voir agent-ssh.sh). Ils
# sont réécrits à chaque démarrage, avant tout le reste, car une reconstruction
# efface ~/.config : ils ne doivent dépendre ni du serveur ni de la connexion.
#
# Pourquoi ~/.config/git/config, git le lit en plus de ~/.gitconfig :
# - pas ~/.gitconfig : VS Code le recopie depuis WSL à chaque démarrage ;
# - pas .git/config, même sous un includeIf : ce fichier est partagé avec WSL,
#   et Claude Code refuse de créer un worktree dès que la configuration du
#   dépôt contient un includeIf (il ne peut plus savoir quels filtres git
#   chargerait). Chaque session Remote Control mourait alors à son démarrage.
AGENT_SSH=/workspaces/claude-os/.devcontainer/agent-ssh.sh
CONFIG_GIT="${XDG_CONFIG_HOME:-$HOME/.config}/git/config"
mkdir -p "$(dirname "$CONFIG_GIT")"
git config --file "$CONFIG_GIT" core.sshCommand "$AGENT_SSH ssh"
git config --file "$CONFIG_GIT" gpg.ssh.program "$AGENT_SSH"

# L'environnement que VS Code donnait au serveur et que Docker ne donne pas : le
# serveur le passe aux sessions, donc à cargo, make et git. Une locale UTF-8 pour
# les noms de fichiers et les messages accentués. On ne reprend pas le reste
# (BROWSER, GIT_ASKPASS, SSH_AUTH_SOCK...) : ces chemins meurent avec la fenêtre
# de VS Code, et agent-ssh.sh cherche déjà l'agent vivant quand git en a besoin.
export LANG="${LANG:-en_US.UTF-8}"
export SHELL="${SHELL:-/bin/bash}"
export USER="${USER:-$(id -un)}"
export PATH="$PATH:$HOME/.local/bin"

# Si le script est relancé à la main depuis une session Claude Code, il en
# hérite des variables CLAUDECODE et CLAUDE_CODE_* : les sessions lancées par
# le serveur se croiraient alors imbriquées dans la nôtre et échoueraient.
# On les retire ; au démarrage du conteneur, elles n'existent pas.
for variable in $(compgen -e | grep -E '^(CLAUDECODE|CLAUDE_CODE_|CLAUDE_PID)'); do
    unset "$variable"
done

noter "superviseur lance (pid $$, dossier $DOSSIER)"
surveiller

attente=$PERIODE
while [ -z "$arret" ]; do
    attendre_conditions
    [ -n "$arret" ] && break

    debut=$EPOCHSECONDS
    lancer_serveur
    if [ -z "$serveur" ]; then
        noter "lancement impossible depuis $DOSSIER"
        dormir "$PERIODE"
        continue
    fi
    noter "serveur lance (pid $serveur, journal : $JOURNAL)"

    while [ -z "$arret" ] && [ ! -e "$PAUSE" ] && kill -0 "$serveur" 2>/dev/null; do
        dormir "$PERIODE"
        surveiller
    done

    # Arrêt demandé : SIGTERM à nouveau, car le signal a pu arriver juste avant
    # que `serveur` soit connu. Le serveur s'en moque s'il s'arrête déjà. Le
    # second `wait` couvre un signal qui interrompt le premier.
    if [ -n "$arret" ] || [ -e "$PAUSE" ]; then
        kill -TERM "$serveur" 2>/dev/null
    fi
    wait "$serveur"
    code=$?
    while kill -0 "$serveur" 2>/dev/null; do
        wait "$serveur"
        code=$?
    done
    attendre_filtre
    duree=$((EPOCHSECONDS - debut))
    serveur=

    [ -n "$arret" ] && break
    if [ "$duree" -ge "$DUREE_STABLE" ]; then
        attente=$PERIODE
    fi
    if [ -e "$PAUSE" ]; then
        noter "serveur arrete pour la pause (code $code)"
        continue
    fi
    noter "serveur arrete (code $code) apres ${duree}s ; relance dans ${attente}s au plus tot"
    dormir "$attente"
    attente=$((attente * 2))
    if [ "$attente" -gt "$ATTENTE_MAX" ]; then
        attente=$ATTENTE_MAX
    fi
done

noter "superviseur arrete"
exit 0
