#!/usr/bin/env bash
# Teste le superviseur (remote-control.sh) avec un faux serveur, dans un dossier
# temporaire : ni le vrai serveur, ni le vrai journal, ni la configuration git ne
# sont touchés, et il peut tourner à côté d'un serveur en service. Les processus
# sont arrêtés par leur pid, jamais par leur nom (un pkill tuerait le vrai).
#
# Ce qu'il ne peut pas tester, faute de Docker dans le conteneur : devcontainer.json
# et le Dockerfile eux-mêmes. Le scénario de l'arrêt passe tout de même par la
# commande exacte que VS Code donne à Docker (DEMARRAGE_DOCKER).
set -u

ICI=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$ICI/remote-control.sh"
T=$(mktemp -d)
FAUX="$T/bin/faux-claude"
DEPOT="$T/depot"
HOME_TEST="$T/home"
CONFIG="$T/config"
JOURNAL="$CONFIG/remote-control.log"
OOM="$T/memory.events"
echecs=0
superviseurs=()
autres=()

# Copie de la commande de la CLI devcontainer (`overrideCommand: false`).
DEMARRAGE_DOCKER='echo Container started
trap "exit 0" 15

exec "$@"
while sleep 1 & wait $!; do :; done'

nettoyer() {
    local p
    # Le groupe aussi, pour ceux qui en mènent un : leurs enfants partent avec eux.
    for p in "${superviseurs[@]}" "${autres[@]}"; do
        kill -TERM -- "-$p" "$p" 2>/dev/null
    done
    sleep 0.5
    [ -f "$T/pids" ] && while read -r p _; do kill -9 "$p" 2>/dev/null; done <"$T/pids"
    rm -rf "$T"
}
trap nettoyer EXIT

ok() { echo "ok     - $1"; }
echec() {
    echo "ECHEC  - $1"
    echecs=$((echecs + 1))
}
verifier() {
    local nom=$1
    shift
    if "$@"; then ok "$nom"; else echec "$nom"; fi
}
# Attend qu'une commande réussisse (15 s au plus), sans dormir plus que nécessaire.
attendre() {
    local nom=$1 essai
    shift
    for essai in $(seq 150); do
        if "$@"; then ok "$nom"; return 0; fi
        sleep 0.1
    done
    echec "$nom (delai depasse)"
    echo "--- journal :"; cat "$JOURNAL" 2>/dev/null; echo "---"
    return 1
}
au_journal() { grep -q -- "$1" "$JOURNAL" 2>/dev/null; }
pas_au_journal() { ! grep -q -- "$1" "$JOURNAL" 2>/dev/null; }
compte_au_journal() { [ "$(grep -c -- "$1" "$JOURNAL" 2>/dev/null)" = "$2" ]; }
lignes() { { wc -l <"$1"; } 2>/dev/null || echo 0; }
appels_au_moins() { [ "$(lignes "$T/pids")" -ge "$1" ]; }
appels_exactement() { [ "$(lignes "$T/pids")" -eq "$1" ]; }
fins_au_moins() { [ "$(lignes "$T/fins")" -ge "$1" ]; }
mort() { ! kill -0 "$1" 2>/dev/null; }
pid_faux() { tail -n 1 "$T/pids" | cut -d' ' -f1; }

mkdir -p "$T/bin" "$DEPOT/.git" "$HOME_TEST" "$CONFIG"
# Le faux serveur : il note son pid et son environnement, puis suit le scénario
# (lu à chaque lancement). Comme le vrai, il redessine son état et met du temps à
# s'arrêter sur SIGTERM.
cat >"$FAUX" <<'FIN'
#!/usr/bin/env bash
# Le scénario est lu avant que le pid soit noté : le test, qui attend ce pid pour changer
# de scénario, ne peut pas le changer sous le nez de ce lancement-ci.
scenario=$(cat "$FAUX_DIR/scenario")
echo "$$ $*" >>"$FAUX_DIR/pids"
env >"$FAUX_DIR/env"
readlink /proc/$$/fd/0 >"$FAUX_DIR/entree"
[ -e /proc/$$/fd/9 ] && echo oui >"$FAUX_DIR/fd9"
if [ "$scenario" = panne ]; then
    echo "[12:00:00] Error: panne simulee"
    exit 3
fi
trap 'echo "[12:00:09] Shutting down 1 active session(s)…"; sleep 1
      echo "[12:00:10] Environment preserved."; echo fin >>"$FAUX_DIR/fins"
      kill "$minuteur" 2>/dev/null; exit 0' TERM
cat "$FAUX_DIR/affichage"
sleep 1000 &
minuteur=$!
wait "$minuteur"
FIN
chmod +x "$FAUX"

# Ce qu'écrit le vrai serveur (voir le journal de novembre), en deux redessins
# puis une reconnexion, avec ses couleurs, ses liens et sa toupie.
printf '%b' \
    'Spawn mode: same-dir (saved for this folder)\n' \
    '\e[9A\e[J\e[32m·✔︎·\e[0m \e[32mConnected\e[0m \e[2m·\e[0m \e[2mclaude-os\e[0m\n' \
    '    \e[2mCapacity: 1/32 · New sessions will be created in the current directory\e[0m\n' \
    '    \e]8;;https://claude.ai/code/session_01ABC?from=cli\aFinir etape 6h\e]8;;\a\n' \
    '\n' \
    'Continue coding in the Claude mobile app or https://claude.ai/code?environment=env_01X\n' \
    '\e[9A\e[J\e[32m·✔︎·\e[0m \e[32mConnected\e[0m \e[2m·\e[0m \e[2mclaude-os\e[0m\n' \
    '    \e[2mCapacity: 1/32 · New sessions will be created in the current directory\e[0m\n' \
    '    \e]8;;https://claude.ai/code/session_01ABC?from=cli\aFinir etape 6h\e]8;;\a\n' \
    '\n' \
    'Continue coding in the Claude mobile app or https://claude.ai/code?environment=env_01X\n' \
    '\e[33m·|·\e[0m \e[33mReconnecting\e[0m · retrying in 2.4s · disconnected 0s\n' \
    '\e[33m·/·\e[0m \e[33mReconnecting\e[0m · retrying in 378ms · disconnected 0s\n' \
    '\e[9A\e[J\e[2m[21:41:30]\e[0m \e[32mReconnected\e[0m after 3s\n' \
    '\e[32m·✔︎·\e[0m \e[32mReady\e[0m \e[2m·\e[0m \e[2mclaude-os\e[0m\n' \
    '    Capacity: 0/32 · New sessions will be created in the current directory\n' \
    'une ligne inconnue\n' \
    'une ligne inconnue\n' \
    >"$T/affichage"

echo normal >"$T/scenario"
echo "oom_kill 0" >"$OOM"
echo '{"projects":{"'"$DEPOT"'":{"hasTrustDialogAccepted":true}}}' >"$T/confiance.json"
echo '{"projects":{}}' >"$T/sans-confiance.json"

# Lance un superviseur sans rien de la session d'où part le test.
superviser() {
    env -i PATH="$PATH" HOME="$HOME_TEST" CLAUDE_CONFIG_DIR="$CONFIG" \
        XDG_CONFIG_HOME="$T/xdg" FAUX_DIR="$T" CLAUDECODE=1 CLAUDE_CODE_ENTRYPOINT=test \
        RC_CLAUDE="$FAUX" RC_PERIODE=1 RC_DUREE_STABLE=2 RC_TAILLE_MAX=20000 \
        RC_EVENEMENTS_MEMOIRE="$OOM" RC_PREFIXE_CONNEXION="$T/connexion-" "$@" >>"$T/sortie" 2>&1 &
    dernier=$!
    superviseurs+=("$dernier")
}
pret_a_partir() {
    touch "$CONFIG/.credentials.json"
    cp "$T/confiance.json" "$CONFIG/.claude.json"
}

echo "== attente de ce qui manque, sans sortir"
superviser sh -c "$DEMARRAGE_DOCKER" - bash "$SCRIPT" "$T/absent"
s=$dernier
attendre "un dossier sans depot : il attend" au_journal "n'est pas un depot git"
verifier "le superviseur reste vivant" kill -0 "$s"
kill -TERM "$s"
attendre "SIGTERM pendant l'attente : il sort aussitot" mort "$s"

superviser bash "$SCRIPT" "$DEPOT"
s=$dernier
attendre "pas de connexion au compte : il attend" au_journal "pas de connexion au compte"
touch "$CONFIG/.credentials.json"
cp "$T/sans-confiance.json" "$CONFIG/.claude.json"
attendre "connexion faite, pas de confiance : il le dit" au_journal "marque de confiance"
verifier "aucun serveur lance avant que tout soit pret" pas_au_journal "serveur lance"
cp "$T/confiance.json" "$CONFIG/.claude.json"
attendre "tout est pret : le serveur part, sans relancer le script" appels_au_moins 1

echo "== ce que recoit le serveur"
attendre "le journal note le lancement" au_journal "serveur lance (pid"
env_ok() { grep -q "^$1" "$T/env"; }
env_absent() { ! grep -q "^$1" "$T/env"; }
verifier "son entree est /dev/null" grep -q '^/dev/null$' "$T/entree"
verifier "le verrou ne lui est pas transmis" test ! -e "$T/fd9"
verifier "prefixe des sessions" env_ok "CLAUDE_REMOTE_CONTROL_SESSION_NAME_PREFIX=claude-os$"
verifier "locale UTF-8" env_ok "LANG=en_US.UTF-8$"
verifier "shell" env_ok "SHELL=/bin/bash$"
verifier "~/.local/bin dans le PATH" env_ok "PATH=.*$HOME_TEST/.local/bin"
verifier "CLAUDECODE retire" env_absent "CLAUDECODE="
verifier "CLAUDE_CODE_* retire" env_absent "CLAUDE_CODE_"
verifier "reglage git : sshCommand" grep -q 'agent-ssh.sh ssh' "$T/xdg/git/config"
verifier "reglage git : gpg" grep -q 'program = .*agent-ssh.sh' "$T/xdg/git/config"

echo "== le filtre du journal"
attendre "la fin de l'affichage est arrivee" au_journal "une ligne inconnue"
verifier "un seul Connected pour deux redessins" compte_au_journal "serveur : Connected" 1
verifier "pas de code de terminal" pas_au_journal $'\e'
verifier "pas de toupie" pas_au_journal "✔"
verifier "le lien garde l'identifiant et le titre" au_journal "session_01ABC Finir etape 6h"
verifier "titre une seule fois" compte_au_journal "Finir etape 6h" 1
verifier "un seul Reconnecting pour deux delais" compte_au_journal "Reconnecting" 1
verifier "evenement date garde" au_journal "\[21:41:30\] Reconnected after 3s"
verifier "changement d'etat garde" au_journal "serveur : Ready"
verifier "changement de capacite garde" au_journal "Capacity: 0/32"
verifier "ligne inconnue gardee une fois" compte_au_journal "une ligne inconnue" 1

echo "== un seul superviseur"
env -i PATH="$PATH" HOME="$HOME_TEST" CLAUDE_CONFIG_DIR="$CONFIG" XDG_CONFIG_HOME="$T/xdg" \
    RC_CLAUDE="$FAUX" FAUX_DIR="$T" RC_PERIODE=1 bash "$SCRIPT" "$DEPOT" >/dev/null
verifier "le second sort avec le code 0" test $? -eq 0
verifier "il le dit" au_journal "un superviseur tourne deja"
verifier "le premier continue" kill -0 "$s"
verifier "pas de second serveur" appels_exactement 1

echo "== ce qui ne se voyait pas"
echo "oom_kill 2" >"$OOM"
attendre "les processus tues par le plafond de memoire" au_journal "2 processus tue(s)"
# Le gel ne se mesure que dans dormir. Arrêté juste après la ligne ci-dessus, le
# superviseur était souvent encore dans surveiller, et le gel passait inaperçu. On l'arrête
# donc, puis on regarde s'il a un enfant sleep, vivant ou mort mais pas encore attendu : il
# est alors entre le lancement de son minuteur et la mesure. Sinon, on le relâche et on
# recommence.
#
# Le gel dure 10 s, quand 5 suffiraient : dormir le mesure à l'horloge murale, et celle de
# la machine WSL recule de 1,5 s toutes les 30 s (son horloge monotone avance 5 % trop vite,
# et la synchronisation avec Windows la rattrape ; mesuré le 7 novembre). Avec 6 s, un recul
# pendant le gel le faisait passer sous le seuil (4 s), une fois sur sept.
figer_pendant_le_sommeil() {
    local essai
    for essai in $(seq 50); do
        kill -STOP "$1"
        pgrep -P "$1" -x sleep >/dev/null && return 0
        kill -CONT "$1"
        sleep 0.1
    done
    return 1
}
verifier "le superviseur est arrete pendant qu'il dort" figer_pendant_le_sommeil "$s"
sleep 10
kill -CONT "$s"
attendre "le conteneur fige (veille simulee)" au_journal "conteneur fige pendant"
head -c 30000 /dev/zero | tr '\0' x >>"$JOURNAL"
attendre "le journal trop gros est deplace" test -s "$JOURNAL.1"
attendre "le journal repart" au_journal "journal deplace dans"
verifier "un seul fichier garde, plus petit que le plafond" test "$(stat -c %s "$JOURNAL")" -lt 20000

echo "== les serveurs de connexion de VS Code"
# Un faux serveur de connexion, comme le vrai : `<chemin>/node <prise>.js` et rien
# d'autre sur la ligne de commande, sous un sh qui mène son groupe. `cat` sur un tube
# nommé, sous le nom de node, attend sans fin. La prise est dans le dossier du test
# (RC_PREFIXE_CONNEXION) : le superviseur de ce test ne voit pas ceux de VS Code.
ln -s "$(command -v cat)" "$T/bin/node"
lancer_connexion() {
    [ -p "$T/connexion-$1.js" ] || mkfifo "$T/connexion-$1.js"
    setsid sh -c '"$0" "$1"; sleep 1000' "$T/bin/node" "$T/connexion-$1.js" &
    connexion=$!
    autres+=("$connexion")
    sleep 0.1
}
vivant() { kill -0 "$1" 2>/dev/null; }
lancer_connexion seule
c_seule=$connexion
lancer_connexion double
c_ancienne=$connexion
lancer_connexion double
c_moyenne=$connexion
lancer_connexion double
c_recente=$connexion
# Une commande qui cite le chemin, comme un grep d'une session, sans en être un. Elle
# mène son groupe : arrêter bash seul laisserait son sleep, et la sortie du test ouverte.
setsid bash -c "sleep 1000; echo $T/bin/node $T/connexion-double.js" &
c_citee=$!
autres+=("$c_citee")
attendre "l'ancien serveur d'une fenetre est arrete, avec son sh" mort "$c_ancienne"
attendre "le suivant aussi" mort "$c_moyenne"
verifier "le plus recent reste" vivant "$c_recente"
verifier "le serveur seul d'une autre fenetre reste" vivant "$c_seule"
verifier "une commande qui cite le chemin reste" vivant "$c_citee"
attendre "le journal le dit" au_journal "fenetre VS Code double : serveurs de connexion en trop"
verifier "le superviseur est toujours la" vivant "$s"
lancer_connexion double
c_suivant=$connexion
attendre "un essai de plus : le precedent part a son tour" mort "$c_recente"
verifier "le dernier reste" vivant "$c_suivant"
verifier "la fenetre n'est notee qu'une fois" compte_au_journal "fenetre VS Code double" 1
kill -TERM -- "-$c_seule" "-$c_suivant" "-$c_citee" 2>/dev/null

echo "== la pause"
touch "$CONFIG/remote-control.pause"
attendre "pause : le serveur s'arrete proprement" fins_au_moins 1
attendre "pause : il le dit" au_journal "en attente : en pause"
sleep 1.5
verifier "pause : aucun serveur relance" appels_exactement 1
verifier "pause : pas de relance annoncee" pas_au_journal "relance dans"
rm -f "$CONFIG/remote-control.pause"
attendre "pause retiree : il repart" appels_au_moins 2

echo "== les pannes"
kill -TERM "$(pid_faux)"
attendre "un serveur arrete a la main repart seul" appels_au_moins 3
# Une durée stable d'abord, sans quoi l'attente de départ dépend de l'arrondi des
# secondes : 1 ou 2 s, et les trois relances dépassaient parfois le délai du test. 4 s
# plutôt que les 2 de RC_DUREE_STABLE : l'horloge murale peut reculer de 1,5 s entre-temps
# (voir le gel simulé).
sleep 4
echo panne >"$T/scenario"
kill -TERM "$(pid_faux)"
attendre "pannes en serie : 3 relances" appels_au_moins 6
attendre "l'attente double entre les pannes" au_journal "serveur arrete (code 3).*relance dans 2s"
attendre "... puis double encore" au_journal "serveur arrete (code 3).*relance dans 4s"
verifier "l'erreur du serveur est au journal" au_journal "Error: panne simulee"
echo normal >"$T/scenario"
n=$(wc -l <"$T/pids")
attendre "la panne finie, il repart" appels_au_moins $((n + 1))
sleep 4
kill -TERM "$(pid_faux)"
attendre "apres une duree stable, l'attente repart de zero" au_journal "serveur arrete (code 0).*relance dans 1s"
attendre "il repart" appels_au_moins $((n + 2))
verifier "les longues attentes de relance ne passent pas pour des gels" pas_au_journal "conteneur fige"

echo "== l'arret du conteneur"
kill -TERM "$s"
attendre "le superviseur attend la fin du serveur" fins_au_moins 2
attendre "le superviseur sort" mort "$s"
wait "$s"
verifier "code 0 : le conteneur ne repart pas (--restart=on-failure)" test $? -eq 0
verifier "le serveur a fini proprement" au_journal "Environment preserved"
verifier "dans l'ordre : le serveur, puis le superviseur" sh -c \
    "grep -n 'Environment preserved\|superviseur arrete' '$JOURNAL' | tail -n 1 | grep -q 'superviseur arrete'"

echo "== un serveur lance a la main"
: >"$T/pids"
bash -c 'exec -a "$0 remote-control" sleep 30' "$FAUX" &
main=$!
autres+=("$main")
sleep 0.2
superviser sh -c "$DEMARRAGE_DOCKER" - bash "$SCRIPT" "$DEPOT"
s=$dernier
attendre "pas de doublon : il attend" au_journal "tourne hors supervision (pid $main)"
verifier "aucun serveur lance" test ! -s "$T/pids"
kill "$main"
attendre "il prend la suite quand l'autre s'arrete" appels_au_moins 1
verifier "la sortie du conteneur a le journal du superviseur (docker logs)" grep -q "superviseur lance" "$T/sortie"
kill -TERM "$s"
attendre "arret par la commande de Docker : le superviseur sort" mort "$s"

if [ "$echecs" -eq 0 ]; then
    echo "tout est bon"
else
    echo "$echecs ECHEC(S)"
    exit 1
fi
