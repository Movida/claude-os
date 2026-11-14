# Fabrique une trame Ethernet à envoyer à la machine par la socket UDP de
# QEMU (`-netdev dgram`, make tests-qemu, test-carte), d'une machine du
# réseau de slirp que slirp n'a pas : 10.0.2.77, d'adresse Ethernet
# 52:54:00:00:00:4d, vers la machine (10.0.2.15, 52:54:00:12:34:56).
# Écrit ses octets en \xHH, que le printf de bash rend tels quels :
#   printf "$(awk -v genre=tcp -v seq=1000 ... -f trame.awk)" >&3
# awk plutôt qu'un outil de plus (python, scapy) : la CI n'a que sh, awk
# et od pour ses scénarios (comme erreurs-icmp.awk) ; et pas d'octets
# bruts sortis d'awk : mawk et gawk ne les écrivent pas de la même façon
# (gawk, en UTF-8, ferait deux octets d'un seul au-delà de 127).
#
# Les variables (-v) :
#   genre    « arp » : une requête ARP de 10.0.2.77 pour 10.0.2.15, qui lui
#            apprend où est 10.0.2.77 (`neigh_event_ns` : une requête pour
#            nous crée l'entrée de qui la pose), sans qu'il ait à le
#            demander ; « tcp » : un segment TCP ;
#   tos, ttl le TOS et le TTL de l'en-tête IPv4 ;
#   options  les options IPv4, en hexadécimal (une longueur multiple de 4
#            octets, bourrage compris) ;
#   source, destination, seq, ack, drapeaux, donnees : les ports, les
#            numéros, les drapeaux du segment TCP (en décimal : 2 SYN, 16
#            ACK...), et le nombre d'octets de données (des « x »).
function octet(v) { o[n++] = v % 256 }
function mot(v) { octet(int(v / 256)); octet(v) }
function long(v) { mot(int(v / 65536)); mot(v % 65536) }
function adresse(a, i, p) { split(a, p, "."); for (i = 1; i <= 4; i++) octet(p[i] + 0) }
# La somme d'Internet (RFC 1071) des octets o[debut..fin[, plus `depart`,
# repliée et complémentée.
function somme(debut, fin, depart, s, i) {
    s = depart
    for (i = debut; i < fin; i += 2)
        s += o[i] * 256 + (i + 1 < fin ? o[i + 1] : 0)
    while (s >= 65536)
        s = s % 65536 + int(s / 65536)
    return 65535 - s
}
function hexa(c) { return index("0123456789abcdef", tolower(c)) - 1 }
BEGIN {
    n = 0
    # Ethernet : la destination, la source, le type.
    split("52 54 00 12 34 56 52 54 00 00 00 4d", m, " ")
    for (i = 1; i <= 12; i++) octet(hexa(substr(m[i], 1, 1)) * 16 + hexa(substr(m[i], 2, 1)))
    if (genre == "arp") {
        # ARP (RFC 826) : Ethernet (1), IPv4 (0x0800), 6 et 4 octets, une
        # requête (1) ; qui la pose, puis qui est cherché (adresse Ethernet
        # inconnue : des zéros).
        mot(2054); mot(1); mot(2048); octet(6); octet(4); mot(1)
        for (i = 7; i <= 12; i++) octet(hexa(substr(m[i], 1, 1)) * 16 + hexa(substr(m[i], 2, 1)))
        adresse("10.0.2.77")
        for (i = 0; i < 6; i++) octet(0)
        adresse("10.0.2.15")
    } else {
        mot(2048)
        lo = length(options) / 2
        lt = 20 + donnees
        # IPv4 : version 4 et la longueur de l'en-tête en mots, le TOS, la
        # longueur totale, l'identifiant, ni fragment ni DF, le TTL, TCP
        # (6), la somme (plus bas), les adresses, les options.
        ip = n
        octet(64 + 5 + lo / 4); octet(tos + 0); mot(20 + lo + lt); mot(1); mot(0); octet(ttl + 0); octet(6); mot(0)
        adresse("10.0.2.77"); adresse("10.0.2.15")
        for (i = 0; i < lo; i++) octet(hexa(substr(options, 2 * i + 1, 1)) * 16 + hexa(substr(options, 2 * i + 2, 1)))
        s = somme(ip, n, 0)
        o[ip + 10] = int(s / 256); o[ip + 11] = s % 256
        # TCP : les ports, les numéros, la longueur de l'en-tête (5 mots), les
        # drapeaux, la fenêtre, la somme (plus bas), le pointeur d'urgence.
        t = n
        mot(source + 0); mot(destination + 0); long(seq + 0); long(ack + 0); octet(80); octet(drapeaux + 0); mot(8192); mot(0); mot(0)
        for (i = 0; i < donnees; i++) octet(120)
        # La somme TCP prend le pseudo-en-tête : les adresses, le protocole,
        # la longueur du segment.
        s = somme(t, n, 10 * 256 + 0 + 2 * 256 + 77 + 10 * 256 + 0 + 2 * 256 + 15 + 6 + lt)
        o[t + 16] = int(s / 256); o[t + 17] = s % 256
    }
    # Une trame Ethernet a au moins 60 octets (sans sa somme) : des zéros.
    while (n < 60) octet(0)
    for (i = 0; i < n; i++) printf "\\x%02x", o[i]
}
