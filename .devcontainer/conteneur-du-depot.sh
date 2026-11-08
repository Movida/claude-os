# Sourcé par demarrer-conteneur.sh et arreter-conteneur.sh, qui tournent dans WSL : ce
# qu'ils ont en commun. Trouver les conteneurs de ce dépôt, noter ce qu'ils font, et
# réessayer une commande de docker qui échoue.
#
# Les variables lues ici : DOCKER (la commande docker, un faux dans les tests), ATTENTE
# (l'écart entre deux essais, en secondes) et AC_JOURNAL (le journal, pour les tests).

# Trouver les conteneurs du dépôt.
#
# L'extension Dev Containers les marque de deux labels, et pas sous la même forme. Le 7
# novembre : devcontainer.config_file valait le chemin de WSL
# (/home/morva/claude-os/.devcontainer/devcontainer.json), et devcontainer.local_folder
# le chemin vu de Windows (\\wsl.localhost\Ubuntu\home\morva\claude-os). Le filtre de
# Docker, qui compare un label à l'octet près, ne trouvait donc rien avec le chemin de
# WSL : arreter-conteneur.sh disait le conteneur arrêté alors qu'il tournait, et la
# relance au démarrage n'aurait jamais pu le trouver.
#
# On compare donc les deux labels, ramenés au chemin de WSL. Pourquoi pas l'un des deux
# seulement : rien ne dit qu'une autre version de l'extension, ou un dossier ouvert
# autrement (depuis une fenêtre WSL de VS Code plutôt que depuis Windows), garde ces
# formes-là.

# chemin_wsl CHEMIN : \\wsl.localhost\<distribution>\a\b, ou \\wsl$\<distribution>\a\b,
# devient /a/b ; un chemin de WSL reste tel quel.
chemin_wsl() {
    local chemin=$1 prefixe
    for prefixe in '\\wsl.localhost\' '\\wsl$\'; do
        if [ "${chemin#"$prefixe"}" != "$chemin" ]; then
            chemin=${chemin#"$prefixe"}
            # Le nom de la distribution, jusqu'à la barre suivante.
            chemin=${chemin#*\\}
            chemin="/${chemin//\\//}"
            break
        fi
    done
    printf '%s\n' "$chemin"
}

# conteneurs_du_depot DEPOT [OPTION...] : les identifiants des conteneurs du dépôt, un
# par ligne ; les options vont à `docker ps` (-a : arrêtés compris).
conteneurs_du_depot() {
    local depot=$1 id dossier config
    shift
    "${DOCKER:-docker}" ps -q "$@" --filter label=devcontainer.local_folder |
        while read -r id; do
            dossier=$("${DOCKER:-docker}" inspect -f '{{index .Config.Labels "devcontainer.local_folder"}}' "$id")
            config=$("${DOCKER:-docker}" inspect -f '{{index .Config.Labels "devcontainer.config_file"}}' "$id")
            if [ "$(chemin_wsl "$dossier")" = "$depot" ] ||
                [ "$(chemin_wsl "$config")" = "$depot/.devcontainer/devcontainer.json" ]; then
                printf '%s\n' "$id"
            fi
        done
}

# Noter ce que font les scripts : une ligne datée par étape, à l'écran (ou dans le
# journal de systemd, pour le service de WSL) et dans
# ~/.local/state/claude-os/conteneur.log, comme le superviseur dans
# ~/.claude/remote-control.log.
#
# Pourquoi : la fenêtre du raccourci disparaît avec Windows, et le service qui relance le
# conteneur au démarrage de WSL n'en a pas. Le 7 novembre au soir, le raccourci a bien
# lancé l'extinction, sans un seul appel à Docker (son journal le montre), et rien n'a
# gardé ce que le script avait vu.
#
# Pourquoi un fichier plutôt que le seul journal de systemd (journalctl) : le raccourci
# ne tourne pas sous systemd, et un même fichier montre l'arrêt et la relance dans
# l'ordre, lisible depuis WSL comme depuis Windows. L'heure est celle de WSL, avec son
# fuseau : le journal du superviseur, lui, est en UTC, comme le conteneur.
JOURNAL_WSL="${AC_JOURNAL:-${XDG_STATE_HOME:-$HOME/.local/state}/claude-os/conteneur.log}"
mkdir -p "$(dirname "$JOURNAL_WSL")" 2>/dev/null

# noter MESSAGE
noter() {
    printf '%(%F %T %Z)T %s : %s\n' -1 "${0##*/}" "$*" | tee -a "$JOURNAL_WSL"
}

# derniere_ligne TEXTE : la dernière ligne non vide, pour noter une erreur sur une ligne.
derniere_ligne() {
    printf '%s\n' "$1" | grep . | tail -n 1
}

# reessayer ESSAIS COMMANDE... : relance COMMANDE (sa sortie est jetée) jusqu'à ce
# qu'elle réussisse, ESSAIS fois au plus, à ATTENTE secondes d'écart. Note la première
# erreur, puis la réussite qui suit ou l'abandon, avec la dernière erreur : de quoi savoir
# après coup ce que Docker répondait, sans une ligne par essai.
reessayer() {
    local essais=$1 essai=1 erreur attente=${ATTENTE:-5} quoi
    shift
    # La commande, sans le chemin de docker.
    quoi="${1##*/} ${*:2}"
    until erreur=$("$@" 2>&1 >/dev/null); do
        if [ "$essai" -ge "$essais" ]; then
            noter "$quoi : toujours en echec apres $(((essai - 1) * attente)) s : $(derniere_ligne "$erreur")"
            return 1
        fi
        if [ "$essai" -eq 1 ]; then
            noter "$quoi : $(derniere_ligne "$erreur") ; nouvel essai toutes les $attente s, $((essais - 1)) fois au plus"
        fi
        essai=$((essai + 1))
        sleep "$attente"
    done
    if [ "$essai" -gt 1 ]; then
        noter "$quoi : reussi au bout de $(((essai - 1) * attente)) s"
    fi
}
