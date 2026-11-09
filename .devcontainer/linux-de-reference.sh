#!/bin/sh
# linux-de-reference.sh COMMANDE [ARGUMENT...] : lance la commande sous le
# Linux de référence du projet (6.18.33), dans une machine virtuelle qui voit
# le système de fichiers de cette machine-ci : les mêmes programmes, le même
# dépôt, le même HOME ; seul le noyau change. Rend le code de sortie de la
# commande ; 125 si la machine n'a pas pu la lancer ou la mener au bout (le
# message dit pourquoi). Ctrl+C l'arrête, QEMU avec, et efface ce lancement.
#
#   .devcontainer/linux-de-reference.sh ./verifier.sh          (la CI)
#   .devcontainer/linux-de-reference.sh make -C 06k-terminal tests-hote
#
# Pourquoi : nos tests sur l'hôte (`make tests-hote`) comparent notre noyau
# au vrai Linux, celui dont nous lisons les sources : 6.18. Ils tournaient
# sous le noyau de la machine qui les lance, et celui de la CI change sans
# prévenir (Linux 7.0 depuis novembre 2026, et des processeurs à cinq
# niveaux de tables) : deux fois la CI est passée au rouge pour un
# changement du noyau de GitHub (6h, 6i), et cinq programmes de test avaient
# pris des tolérances pour « un autre noyau ». Sous un noyau figé, chaque
# test est strict, partout, et le reste.
#
# Le noyau : le paquet « mainline » d'Ubuntu de la 6.18 (la série à long
# terme de 2025), à une version figée, vérifiée par son SHA-256, comme
# claude, wabt et QEMU. Laquelle : 6.18.33, la version du noyau de WSL sur
# lequel tous nos tests ont été écrits et mesurés. Une série à long terme
# change encore de comportement : la 6.18.51 annonce le MSS d'une connexion
# neuve d'après la MTU de l'interface, plus d'après celle que le chemin a
# apprise (2640e641959, « the wrong direction entirely ») ; sous 6.18.62,
# `linux/pmtu` le voit. Passer à une version plus récente se décide donc
# exprès, avec ce qu'elle change dans notre noyau et nos tests. La même
# version, pas le même noyau : sa configuration est celle d'Ubuntu
# (CONFIG_HZ=1000 contre 250 sous WSL, PREEMPT_VOLUNTARY contre
# PREEMPT_NONE, TMPFS_INODE64, LRU_GEN...), et la machine ne charge que les
# cinq modules de son archive (9p et overlayfs) : ce qu'Ubuntu charge à la
# demande (sctp, tls, tcp_bbr, inet_diag, vsock...) y manque. Aucun de nos
# tests n'en dépend ; un test qui en dépendrait le dirait.
#
# Le processeur de la machine n'a pas LA57 : quatre niveaux de tables, comme
# le nôtre et celui du PC de David. KVM quand la machine l'offre (les
# machines de GitHub, pour un dépôt public), sinon TCG, bien plus lent (le
# conteneur, sous WSL).
#
# Le /init de la machine : linux-de-reference.c, à côté (ce qu'il monte,
# les réglages d'un Ubuntu qu'il pose, pourquoi 9p, ce qui a été écarté).
#
# Réglages : MEMOIRE (la mémoire de la machine, 2G par défaut : le conteneur
# est plafonné à 8 Go et compte la machine parmi ses deux QEMU au plus ; la
# CI en donne 10G), PROCESSEURS (4 au plus par défaut), DUREE_MAX (en
# secondes, 7200).
set -eu
VERSION=6.18.33
PAQUET=$VERSION-061833
CONSTRUCTION=202605231243
ADRESSE=https://kernel.ubuntu.com/mainline/v$VERSION/amd64
SHA256_IMAGE=5a16395caf8ee72838ad4051b3b96b524bd86c524809ec70823be6ee3a11c0a6
SHA256_MODULES=b1146d2030b13521b768623149e0c63277388abb52f6801fa617ef8990d6bbbd
MODULES="fs/netfs/netfs net/9p/9pnet net/9p/9pnet_virtio fs/9p/9p fs/overlayfs/overlay"

dire() { echo "linux-de-reference : $*" >&2; }
[ $# -gt 0 ] || { echo "usage : linux-de-reference.sh COMMANDE [ARGUMENT...]" >&2; exit 2; }
ici=$(cd "$(dirname "$0")" && pwd -P)
depot=$(dirname "$ici")
maison=$(cd "$HOME" && pwd -P)
# Dans HOME, comme le Makefile (pas XDG_CACHE_HOME) : le dossier de ce
# lancement doit être dans un partage que la machine écrit (voir plus bas).
cache=$maison/.cache/claude-os/linux-$VERSION

# Le noyau et ses cinq modules, une fois : téléchargés, vérifiés, extraits
# dans un dossier à part, puis mis en place d'un coup (deux lancements à la
# fois ne voient jamais un noyau à moitié écrit ; un téléchargement
# interrompu ne laisse rien). Leurs empreintes, gardées à côté, sont
# revérifiées à chaque lancement, comme celle de claude.
if [ ! -f "$cache/empreintes" ]; then
    mkdir -p "$(dirname "$cache")"
    neuf=$(mktemp -d "$cache.XXXXXX")
    trap 'rm -rf "$neuf"' EXIT
    (
        cd "$neuf"
        curl -sSfL -o image.deb "$ADRESSE/linux-image-unsigned-$PAQUET-generic_$PAQUET.${CONSTRUCTION}_amd64.deb"
        curl -sSfL -o modules.deb "$ADRESSE/linux-modules-$PAQUET-generic_$PAQUET.${CONSTRUCTION}_amd64.deb"
        printf '%s  image.deb\n%s  modules.deb\n' "$SHA256_IMAGE" "$SHA256_MODULES" | sha256sum -c --quiet -
        dpkg-deb -x image.deb paquet
        dpkg-deb -x modules.deb paquet
        mkdir modules
        cp "paquet/boot/vmlinuz-$PAQUET-generic" vmlinuz
        for m in $MODULES; do
            cp "paquet/usr/lib/modules/$PAQUET-generic/kernel/$m.ko.zst" modules/
        done
        rm -rf paquet image.deb modules.deb
        sha256sum vmlinuz modules/* > empreintes
    )
    mv -T "$neuf" "$cache" 2>/dev/null || rm -rf "$neuf"
    trap - EXIT
fi
(cd "$cache" && sha256sum -c --quiet empreintes) || { dire "$cache ne correspond plus a ses empreintes : l'effacer"; exit 125; }

# Ce lancement : le /init, l'archive de démarrage, et ce que le /init lira
# (la commande, l'environnement, le dossier, le nom de la machine,
# l'identité, les partages) puis écrira (le statut). Effacé à la fin, même
# sur Ctrl+C : il a une copie de tout l'environnement (0700).
travail=$(mktemp -d "$cache/travail.XXXXXX")
qemu_pid=
finir() {
    [ -z "$qemu_pid" ] || kill "$qemu_pid" 2>/dev/null || true
    rm -rf "$travail"
}
trap finir EXIT
trap 'finir; trap - EXIT; exit 130' INT TERM HUP
gcc -static -O2 -Wall -Werror -o "$travail/init" "$ici/linux-de-reference.c"
{
    printf 'dir /dev 755 0 0\ndir /hote 755 0 0\ndir /haut 755 0 0\ndir /racine 755 0 0\ndir /modules 755 0 0\n'
    printf 'file /init %s/init 755 0 0\n' "$travail"
    for m in $MODULES; do
        printf 'file /modules/%s.ko.zst %s/modules/%s.ko.zst 644 0 0\n' "${m##*/}" "$cache" "${m##*/}"
    done
} > "$travail/archive.txt"
# L'archive.sh de la dernière étape : celui de nos images (le format newc).
archive=$(ls -d "$depot"/[0-9][0-9]*-*/archive.sh | tail -n 1)
sh "$archive" "$travail/initramfs.cpio" "$travail/archive.txt"
printf '%s\0' "$@" > "$travail/commande"
env -0 > "$travail/environnement"
pwd -P > "$travail/dossier"
uname -n > "$travail/nom"
echo "$(id -u) $(id -G)" > "$travail/identite"

# Les partages. La racine de cette machine-ci, en lecture seule
# (readonly=on : QEMU refuse toute écriture, même d'un root de la machine,
# où sudo marche) : le dessous de la racine de la machine. Puis, en
# écriture, les dossiers où la commande écrit pour de bon : HOME (où est ce
# lancement) et le dépôt, s'il n'est pas dans HOME ; montés nosuid,nodev
# dans la machine. Le reste de ses écritures (/tmp) y reste.
partages="-virtfs local,path=/,mount_tag=racine,security_model=passthrough,multidevs=remap,readonly=on"
: > "$travail/partages"
n=0
for d in "$maison" "$depot"; do
    case "$d/" in
        "$maison/"?*) [ "$d" = "$maison" ] || continue ;;
    esac
    partages="$partages -virtfs local,path=$d,mount_tag=partage$n,security_model=passthrough,multidevs=remap"
    printf 'partage%s %s\n' "$n" "$d" >> "$travail/partages"
    n=$((n + 1))
done

# QEMU sous root (sudo, sans mot de passe : la CI et le conteneur l'ont) :
# le partage « passthrough » montre à la machine les fichiers de l'hôte
# tels qu'ils sont, ceux de root compris (sudo y lit /etc/sudoers, pour
# `make tests-hote-root`), et donne à ce qu'elle crée le propriétaire qui
# l'a créé. Écarté : QEMU sous l'utilisateur (« security_model=none ») :
# il ne lit pas ce qui n'est qu'à root, et sudo échoue dans la machine. Un
# root de la machine écrit donc en root dans HOME et dans le dépôt : pas plus
# que le sudo sans mot de passe que ce script demande déjà.
if [ "$(id -u)" = 0 ]; then root=; else root="sudo -n"; fi
if [ -n "$root" ] && ! sudo -n true 2>/dev/null; then
    dire "il faut sudo sans mot de passe (QEMU sous root)"
    exit 125
fi
qemu=$(command -v qemu-system-x86_64)
if $root test -w /dev/kvm 2>/dev/null; then
    machine="-accel kvm -cpu host,-la57"
else
    machine="-accel tcg -cpu max,-la57"
fi
processeurs=${PROCESSEURS:-$(nproc)}
[ -n "${PROCESSEURS:-}" ] || [ "$processeurs" -le 4 ] || processeurs=4
# $root, $machine et $partages sans guillemets : plusieurs mots, un argument
# chacun. L'entrée standard fermée : QEMU mettrait sinon un terminal en mode
# brut. `timeout --foreground` : il reste dans le groupe de premier plan, et
# QEMU, en arrière-plan de ce script, est arrêté par son trap sur Ctrl+C
# (sans quoi timeout, dans son propre groupe, ne le voit pas, et la machine
# tourne jusqu'à DUREE_MAX). loglevel=4 : les messages d'erreur du noyau de
# la machine (le tueur OOM) se voient.
timeout --foreground "${DUREE_MAX:-7200}" $root "$qemu" $machine \
    -smp "$processeurs" -m "${MEMOIRE:-2G}" \
    -kernel "$cache/vmlinuz" -initrd "$travail/initramfs.cpio" \
    -append "console=ttyS0 quiet loglevel=4 panic=-1 travail=$travail" \
    $partages \
    -netdev user,id=reseau -device virtio-net-pci,netdev=reseau \
    -nodefaults -display none -no-reboot -serial stdio </dev/null &
qemu_pid=$!
code=0
wait "$qemu_pid" || code=$?
qemu_pid=
if [ ! -f "$travail/statut" ]; then
    if [ "$code" = 124 ]; then
        dire "DUREE_MAX (${DUREE_MAX:-7200} s) atteinte : machine arretee"
    else
        dire "la machine s'est arretee sans finir la commande (QEMU : code $code)"
    fi
    exit 125
fi
exit "$(cat "$travail/statut")"
