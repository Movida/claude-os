# Les datagrammes UDP que la machine (son adresse Ethernet
# 52:54:00:12:34:56) a envoyés vers l'adresse `vers`, dans un
# enregistrement de QEMU (`-object filter-dump` : un fichier pcap, le
# format est dit dans erreurs-icmp.awk), lu octet par octet, pour
# test-carte (make tests-qemu) :
#   od -An -v -tu1 FICHIER | awk -v vers=10.0.2.77 -f udp.awk
# Une ligne par datagramme : ses adresses et ses ports, sa longueur, puis
# sa somme : nulle (0 : pas de somme, SO_NO_CHECK), juste ou fausse (sur
# le pseudo-en-tête et tout le datagramme, RFC 768).
{ for (i = 1; i <= NF; i++) o[n++] = $i + 0 }
function adresse(k) { return o[k] "." o[k + 1] "." o[k + 2] "." o[k + 3] }
function mot(k) { return o[k] * 256 + o[k + 1] }
END {
    k = 24
    while (k + 16 <= n) {
        l = o[k + 8] + o[k + 9] * 256 + o[k + 10] * 65536 + o[k + 11] * 16777216
        f = k + 16
        if (l >= 42 && f + l <= n && o[f + 12] == 8 && o[f + 13] == 0 && o[f + 6] == 82 && o[f + 7] == 84 \
            && o[f + 8] == 0 && o[f + 9] == 18 && o[f + 10] == 52 && o[f + 11] == 86 && o[f + 14 + 9] == 17 \
            && adresse(f + 14 + 16) == vers) {
            ip = f + 14
            u = ip + (o[ip] % 16) * 4
            longueur = mot(u + 4)
            # Le pseudo-en-tête (les deux adresses, le protocole, la
            # longueur), puis le datagramme, mot par mot ; plié en 16 bits.
            s = mot(ip + 12) + mot(ip + 14) + mot(ip + 16) + mot(ip + 18) + 17 + longueur
            for (i = u; i < u + longueur; i += 2)
                s += o[i] * 256 + (i + 1 < u + longueur ? o[i + 1] : 0)
            while (s >= 65536)
                s = s % 65536 + int(s / 65536)
            printf "%s:%d>%s:%d longueur %d somme %s\n", adresse(ip + 12), mot(u), adresse(ip + 16), mot(u + 2), longueur,
                   mot(u + 6) == 0 ? "nulle" : s == 65535 ? "juste" : "fausse"
        }
        k = f + l
    }
}
