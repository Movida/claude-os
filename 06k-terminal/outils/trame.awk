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
#            demander ; « tcp » : un segment TCP ; « icmp » : une erreur
#            ICMP pour un datagramme UDP de la machine vers 10.0.2.77 ;
#   tos, ttl le TOS et le TTL de l'en-tête IPv4 ;
#   options  les options IPv4, en hexadécimal (une longueur multiple de 4
#            octets, bourrage compris) ;
#   source, destination, seq, ack, drapeaux, donnees : les ports, les
#            numéros, les drapeaux du segment TCP (en décimal : 2 SYN, 16
#            ACK...), et le nombre d'octets de données (des « x ») ; pour
#            icmp, les ports et la taille des données du datagramme cité ;
#   type, code, longueur : pour icmp, le genre et le code du message, et
#            son octet 5 (RFC 4884 : la longueur de la copie d'origine, en
#            mots de 32 bits ; la copie est complétée de zéros jusque-là) ;
#   extension : pour icmp, ce qui suit la copie, en hexadécimal ; « xxxx »
#            à la place des octets 2 et 3 : la somme des extensions,
#            calculée, fausse (la juste plus un) si faussee=1 ;
#   ihl, cite : pour icmp, la longueur de l'en-tête cité, en mots (5 sans
#            elle), et son protocole (17, UDP, sans lui).
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
        # IPv4 : version 4 et la longueur de l'en-tête en mots, le TOS, la
        # longueur totale (plus bas), l'identifiant, ni fragment ni DF, le
        # TTL, ICMP (1) ou TCP (6), la somme (plus bas), les adresses, les
        # options.
        ip = n
        octet(64 + 5 + lo / 4); octet(tos + 0); mot(0); mot(1); mot(0); octet(ttl + 0); octet(genre == "icmp" ? 1 : 6); mot(0)
        adresse("10.0.2.77"); adresse("10.0.2.15")
        for (i = 0; i < lo; i++) octet(hexa(substr(options, 2 * i + 1, 1)) * 16 + hexa(substr(options, 2 * i + 2, 1)))
        if (genre == "icmp")
            icmp()
        else
            tcp()
        # La longueur totale, puis la somme de l'en-tête.
        o[ip + 2] = int((n - ip) / 256); o[ip + 3] = (n - ip) % 256
        s = somme(ip, ip + 20 + lo, 0)
        o[ip + 10] = int(s / 256); o[ip + 11] = s % 256
    }
    # Une trame Ethernet a au moins 60 octets (sans sa somme) : des zéros.
    while (n < 60) octet(0)
    for (i = 0; i < n; i++) printf "\\x%02x", o[i]
}
# Un segment TCP, de 10.0.2.77 vers la machine.
function tcp(t, s, i, lt) {
        lt = 20 + donnees
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
# Une erreur ICMP de 10.0.2.77, qui cite un datagramme UDP de la machine
# vers lui.
function icmp(t, c, x, s, i, h) {
        # ICMP : le genre, le code, la somme (plus bas), un octet nul, la
        # longueur de la copie (RFC 4884), deux octets nuls.
        t = n
        octet(type + 0); octet(code + 0); mot(0); octet(0); octet(longueur + 0); mot(0)
        # La copie : l'en-tête IPv4 du datagramme (de 10.0.2.15 vers
        # 10.0.2.77, UDP, 17), son en-tête UDP (sans somme), ses données ;
        # complétée de zéros jusqu'à la longueur dite.
        c = n
        octet(64 + (ihl == "" ? 5 : ihl)); octet(0); mot(28 + donnees); mot(1); mot(0); octet(64); octet(cite == "" ? 17 : cite); mot(0)
        adresse("10.0.2.15"); adresse("10.0.2.77")
        s = somme(c, n, 0)
        o[c + 10] = int(s / 256); o[c + 11] = s % 256
        mot(source + 0); mot(destination + 0); mot(8 + donnees); mot(0)
        for (i = 0; i < donnees; i++) octet(120)
        while (n - c < longueur * 4) octet(0)
        # Les extensions, et leur somme. La juste plus un n'est jamais 0 (« pas
        # de somme ») : la juste vaut au plus 0xFFFE dès qu'un octet n'est pas
        # nul, et la version 2 en est un.
        x = n
        for (i = 0; i < length(extension) / 2; i++) {
            h = substr(extension, 2 * i + 1, 2)
            octet(h == "xx" ? 0 : hexa(substr(h, 1, 1)) * 16 + hexa(substr(h, 2, 1)))
        }
        if (substr(extension, 5, 4) == "xxxx") {
            s = (somme(x, n, 0) + (faussee ? 1 : 0)) % 65536
            o[x + 2] = int(s / 256); o[x + 3] = s % 256
        }
        # La somme du message entier.
        s = somme(t, n, 0)
        o[t + 2] = int(s / 256); o[t + 3] = s % 256
}
