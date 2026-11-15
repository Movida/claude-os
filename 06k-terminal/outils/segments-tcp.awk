# Les segments TCP que la machine a envoyés à 10.0.2.77 (la machine que joue
# l'hôte, outils/trame.awk), de son réseau (10.0.2.0/24 : de 10.0.2.15, et
# d'une diffusion, s'il en partait), dans un enregistrement de
# QEMU (`-object filter-dump` : un fichier pcap, le format est dit dans
# erreurs-icmp.awk), lu octet par octet :
#   od -An -v -tu1 FICHIER | awk -f segments-tcp.awk
# Une ligne par segment : le port source, le port de destination, les
# drapeaux TCP, le TOS (les deux en hexadécimal), le TTL et la longueur de
# l'en-tête IPv4 (en octets : plus de 20, des options).
{ for (i = 1; i <= NF; i++) o[n++] = $i + 0 }
END {
    k = 24
    while (k + 16 <= n) {
        l = o[k + 8] + o[k + 9] * 256 + o[k + 10] * 65536 + o[k + 11] * 16777216
        f = k + 16
        if (l >= 34 && f + l <= n && o[f + 12] == 8 && o[f + 13] == 0) {
            ip = f + 14
            h = (o[ip] % 16) * 4
            t = ip + h
            if (o[ip + 9] == 6 && o[ip + 12] == 10 && o[ip + 13] == 0 && o[ip + 14] == 2 \
                && o[ip + 16] == 10 && o[ip + 17] == 0 && o[ip + 18] == 2 && o[ip + 19] == 77 && 14 + h + 20 <= l)
                printf "%d %d %02x %02x %d %d\n", o[t] * 256 + o[t + 1], o[t + 2] * 256 + o[t + 3], o[t + 13], o[ip + 1], o[ip + 8], h
        }
        k = f + l
    }
}
