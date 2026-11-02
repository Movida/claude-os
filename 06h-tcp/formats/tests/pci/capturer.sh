#!/bin/sh
# Capture les espaces de configuration PCI des fonctions de QEMU, pour les
# tests de formats::pci (tests/pci.rs) : les 256 octets de chaque fonction
# tels que le BIOS de QEMU (SeaBIOS) les laisse, lus par le moniteur en
# passant par les ports du mécanisme n° 1 (`o /w 0xcf8 <adresse>` puis
# `i /w 0xcfc`, mot de 32 bits par mot de 32 bits), sans démarrer aucun
# système : le disque est un secteur de démarrage qui ne fait que boucler
# (le BIOS ne démarre donc pas la ROM réseau, qui changerait l'espace de
# la carte). Lancé une fois, à la main ; ses fichiers sont gardés dans le
# dépôt (256 octets chacun), nommés bus-periph-fonction.dat (en .dat comme
# les tables ACPI : les .bin sont les images construites, que git ignore).
#
# La machine : celle de l'étape (la VGA de QEMU, virtio-net, le disque en
# virtio-blk), plus un pont PCI (pci-bridge) et une seconde carte virtio-net
# derrière lui, sur le bus 1. Mesuré avec QEMU 8.2.2.
set -e
ici=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Un secteur de démarrage : « jmp $ » (EB FE), puis la signature 55 AA,
# sur un disque d'un Mio (mesuré : un disque d'un seul secteur n'est pas
# démarré, et le BIOS passe à la ROM réseau, qui allume la maîtrise du bus
# de la carte).
printf '\353\376' > $tmp/disque
dd if=/dev/zero bs=1 count=508 status=none >> $tmp/disque
printf '\125\252' >> $tmp/disque
truncate -s 1M $tmp/disque
qemu-system-x86_64 -cpu Nehalem -m 2G -display none -drive format=raw,file=$tmp/disque,if=virtio \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    -device pci-bridge,id=pont,chassis_nr=1 -netdev user,id=n1 -device virtio-net-pci,netdev=n1,bus=pont,addr=1 \
    -monitor unix:$tmp/mon.sock,server,nowait & q=$!
# Le BIOS attribue les BAR et les bus en quelques dizaines de
# millisecondes, puis démarre le disque.
sleep 3
for f in 00-00-0 00-01-0 00-01-1 00-01-3 00-02-0 00-03-0 00-04-0 00-05-0 01-01-0; do
    bus=$((0x${f%%-*})); reste=${f#*-}; periph=$((0x${reste%-*})); fonction=${reste#*-}
    # Les 64 mots : l'adresse de chacun, puis sa lecture.
    for mot in $(seq 0 63); do
        printf 'o /w 0xcf8 0x%x\ni /w 0xcfc\n' $((0x80000000 | bus << 16 | periph << 11 | fonction << 8 | mot * 4))
    done | nc -U -q1 $tmp/mon.sock | tr -d '\r' | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' \
        | grep -oE 'portl\[0x0cfc\] = 0x[0-9a-f]{8}' | sed 's/.*= 0x//' > $tmp/mots
    test "$(wc -l < $tmp/mots)" -eq 64 || { echo "$f : $(wc -l < $tmp/mots) mots lus sur 64"; kill $q; exit 1; }
    # Chaque mot en petit-boutiste, comme la mémoire (xxd, du paquet de vim).
    sed -E 's/(..)(..)(..)(..)/\4\3\2\1/' $tmp/mots | xxd -r -p > "$ici/$f.dat"
done
kill $q
wait $q 2>/dev/null || true
ls -l "$ici"
