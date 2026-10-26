#!/bin/sh
# Capture les tables ACPI de QEMU, pour les tests de formats::acpi
# (tests/acpi.rs) : les octets que le BIOS de QEMU (SeaBIOS) laisse en
# mémoire, lus par le moniteur (pmemsave), sans démarrer aucun système.
# Lancé une fois, à la main ; ses fichiers sont gardés dans le dépôt
# (quelques Kio fabriqués par QEMU). Pour chaque machine (pc, celle des
# étapes, et q35) :
#   - <machine>-rsdp-<adresse>.dat : la page de 4 Kio où est la RSDP ;
#   - <machine>-tables-<adresse>.dat : 12 Kio autour de la RSDT (la page
#     d'avant, la sienne, celle d'après), où QEMU met aussi la MADT, la
#     FADT, HPET et WAET. Le test vérifie que chaque table listée y est.
# L'adresse (en hexadécimal, dans le nom) est celle du premier octet.
# Mesuré avec QEMU 8.2.2 : la même disposition à 128 Mio et à 2 Gio, à
# l'adresse près.
set -e
ici=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for machine in pc q35; do
    qemu-system-x86_64 -machine $machine -cpu Nehalem -m 2G -nodefaults -display none \
        -monitor unix:$tmp/mon.sock,server,nowait & q=$!
    # Le BIOS construit ses tables en quelques dizaines de millisecondes,
    # puis cherche un disque qu'il ne trouve pas : il n'y touche plus.
    sleep 3
    printf 'pmemsave 0xe0000 0x20000 "%s/fseg"\n' "$tmp" | nc -U -q2 $tmp/mon.sock >/dev/null
    sleep 1
    # La RSDP : « RSD PTR » à une position multiple de 16.
    pos=$(grep -obUa "RSD PTR " $tmp/fseg | cut -d: -f1 | while read p; do [ $((p % 16)) -eq 0 ] && echo $p && break; done)
    rsdp=$((0xe0000 + pos))
    page=$((rsdp / 4096 * 4096))
    dd if=$tmp/fseg of="$ici/$machine-rsdp-$(printf %x $page).dat" bs=4096 skip=$(((page - 0xe0000) / 4096)) count=1 status=none
    rsdt=$(od -An -tu4 -j $((pos + 16)) -N4 $tmp/fseg | tr -d ' ')
    debut=$((rsdt / 4096 * 4096 - 4096))
    printf 'pmemsave %d 12288 "%s/tables"\n' $debut "$tmp" | nc -U -q2 $tmp/mon.sock >/dev/null
    sleep 1
    cp $tmp/tables "$ici/$machine-tables-$(printf %x $debut).dat"
    kill $q
    wait $q 2>/dev/null || true
    rm -f $tmp/mon.sock
done
ls -l "$ici"
