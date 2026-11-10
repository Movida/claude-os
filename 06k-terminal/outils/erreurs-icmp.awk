# Compte les erreurs ICMP « destination injoignable » (genre 3) que la
# machine (10.0.2.15) a envoyées, dans un enregistrement de QEMU
# (`-object filter-dump` : un fichier pcap), lu octet par octet :
#   od -An -v -tu1 FICHIER | awk -f erreurs-icmp.awk
# Le format pcap : un en-tête de 24 octets, puis pour chaque trame 16
# octets (la date en secondes et microsecondes, la longueur gardée et la
# longueur vraie, en petit-boutiste), puis la trame Ethernet elle-même.
# awk plutôt qu'un outil de plus (tcpdump, python) : la CI n'a que sh, awk
# et od pour ses scénarios.
{ for (i = 1; i <= NF; i++) o[n++] = $i + 0 }
END {
    k = 24; e = 0
    while (k + 16 <= n) {
        l = o[k + 8] + o[k + 9] * 256 + o[k + 10] * 65536 + o[k + 11] * 16777216
        f = k + 16
        # IPv4 (le type 0x0800 après les deux adresses Ethernet).
        if (l >= 34 && f + l <= n && o[f + 12] == 8 && o[f + 13] == 0) {
            ip = f + 14
            h = (o[ip] % 16) * 4
            if (o[ip + 9] == 1 && o[ip + 12] == 10 && o[ip + 13] == 0 && o[ip + 14] == 2 && o[ip + 15] == 15 \
                && 14 + h < l && o[ip + h] == 3)
                e++
        }
        k = f + l
    }
    print e
}
