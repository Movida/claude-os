# Sourcé par demarrer-conteneur.sh et arreter-conteneur.sh, qui tournent dans WSL :
# trouver les conteneurs de ce dépôt.
#
# L'extension Dev Containers les marque de deux labels, et pas sous la même forme. Le 7
# novembre : devcontainer.config_file valait le chemin de WSL
# (/home/morva/claude-os/.devcontainer/devcontainer.json), et devcontainer.local_folder
# le chemin vu de Windows (\\wsl.localhost\Ubuntu\home\morva\claude-os). Le filtre de
# Docker, qui compare un label à l'octet près, ne trouvait donc rien avec le chemin de
# WSL : arreter-conteneur.sh disait le conteneur arrêté alors qu'il tournait, et la tâche
# de l'ouverture de session n'aurait jamais pu le relancer.
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
# par ligne ; les options vont à `docker ps` (-a : arrêtés compris). $DOCKER : la
# commande docker (un faux dans les tests).
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
