#!/bin/sh
# Capture des trames échangées avec le réseau utilisateur de QEMU (slirp),
# pour les tests de formats::reseau (tests/reseau.rs) et d'inet : le noyau
# de l'étape démarre sur l'archive vide (make vide.bin), envoie ses deux
# sondes ARP puis fait son DHCP, et QEMU garde chaque trame de la carte
# (-object filter-dump, au format pcap). Lancé une fois, à la main, depuis
# le dossier de l'étape ; les trames sont gardées dans le dépôt (en .dat :
# git ignore les .bin) :
#   arp-reponse.dat  la réponse de 10.0.2.2 à une sonde de 0.0.0.0 ;
#   dhcp-discover.dat, dhcp-offer.dat, dhcp-request.dat, dhcp-ack.dat :
#                    l'échange DHCP, nos deux messages et ceux de slirp.
# Mesuré avec QEMU 8.2.2 (libslirp 4.7.0).
set -e
ici=$(cd "$(dirname "$0")" && pwd)
etape=$(cd "$ici/../../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$etape/vide.bin" $tmp/disque
timeout 15 qemu-system-x86_64 -cpu Nehalem -m 2G -display none -no-reboot -drive format=raw,file=$tmp/disque \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 -object filter-dump,id=f0,netdev=n0,file=$tmp/trames.pcap \
    -serial file:$tmp/serie.log || true
grep -q "DHCP de 10.0.2.2" $tmp/serie.log || { echo "le DHCP n'a pas abouti"; exit 1; }
# Le format pcap : un en-tête de 24 octets, puis pour chaque trame 16 octets
# (dont sa longueur aux octets 8 à 11, petit-boutiste) et la trame. Les
# trames voulues, dans l'ordre où elles passent.
python3 -I - $tmp/trames.pcap "$ici" <<'FIN'
import struct, sys
d = open(sys.argv[1], 'rb').read()
noms = {1: 'arp-reponse', 4: 'dhcp-discover', 5: 'dhcp-offer', 6: 'dhcp-request', 7: 'dhcp-ack'}
i, n = 24, 0
while i < len(d):
    longueur = struct.unpack('<I', d[i + 8:i + 12])[0]
    if n in noms:
        open(f'{sys.argv[2]}/{noms[n]}.dat', 'wb').write(d[i + 16:i + 16 + longueur])
    i += 16 + longueur
    n += 1
FIN
ls -l "$ici"
