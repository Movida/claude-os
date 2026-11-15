# Les messages d'IGMP que la machine (son adresse Ethernet 52:54:00:12:34:56)
# a envoyés, dans un enregistrement de QEMU (`-object filter-dump` : un
# fichier pcap, le format est dit dans erreurs-icmp.awk), lu octet par
# octet, pour test-carte (make tests-qemu) :
#   od -An -v -tu1 FICHIER | awk -f igmp.awk
# Une ligne par message : l'adresse Ethernet de destination, les adresses
# IPv4, le TOS, le TTL, DF, l'identifiant, la longueur de l'en-tête IPv4
# (24 : l'alerte aux routeurs), ses options, puis le message : un rapport
# v3 et ses enregistrements ({genre groupe sources...}), ou le genre et le
# groupe d'un message v1 ou v2 ; et si sa somme est juste.
{ for (i = 1; i <= NF; i++) o[n++] = $i + 0 }
function adresse(k) { return o[k] "." o[k + 1] "." o[k + 2] "." o[k + 3] }
# La somme d'Internet des octets o[debut..fin[ : 0 si elle est juste.
function somme(debut, fin, s, i) {
    s = 0
    for (i = debut; i < fin; i += 2)
        s += o[i] * 256 + (i + 1 < fin ? o[i + 1] : 0)
    while (s >= 65536)
        s = s % 65536 + int(s / 65536)
    return 65535 - s
}
END {
    k = 24
    while (k + 16 <= n) {
        l = o[k + 8] + o[k + 9] * 256 + o[k + 10] * 65536 + o[k + 11] * 16777216
        f = k + 16
        if (l >= 34 && f + l <= n && o[f + 12] == 8 && o[f + 13] == 0 && o[f + 6] == 82 && o[f + 7] == 84 \
            && o[f + 8] == 0 && o[f + 9] == 18 && o[f + 10] == 52 && o[f + 11] == 86 && o[f + 14 + 9] == 2) {
            ip = f + 14
            h = (o[ip] % 16) * 4
            t = ip + h
            fin = ip + o[ip + 2] * 256 + o[ip + 3]
            ligne = sprintf("%02x:%02x:%02x:%02x:%02x:%02x %s>%s tos %02x ttl %d df %d id %d ihl %d opt",
                            o[f], o[f + 1], o[f + 2], o[f + 3], o[f + 4], o[f + 5], adresse(ip + 12), adresse(ip + 16),
                            o[ip + 1], o[ip + 8], int(o[ip + 6] / 64) % 2, o[ip + 4] * 256 + o[ip + 5], h)
            for (i = ip + 20; i < t; i++)
                ligne = ligne sprintf(" %02x", o[i])
            if (o[t] == 34) {
                ligne = ligne " v3"
                e = t + 8
                for (r = 0; r < o[t + 6] * 256 + o[t + 7]; r++) {
                    ligne = ligne " {" o[e] " " adresse(e + 4)
                    for (s = 0; s < o[e + 2] * 256 + o[e + 3]; s++)
                        ligne = ligne " " adresse(e + 8 + 4 * s)
                    ligne = ligne "}"
                    e += 8 + 4 * (o[e + 2] * 256 + o[e + 3]) + 4 * o[e + 1]
                }
            } else
                ligne = ligne sprintf(" type %02x groupe %s", o[t], adresse(t + 4))
            print ligne (somme(t, fin) == 0 ? " somme juste" : " somme fausse")
        }
        k = f + l
    }
}
