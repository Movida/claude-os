//! Les compteurs de /proc/net/snmp (les soldes d'avant 6k) : un bloc pour la
//! machine (inet::snmp dit pourquoi un seul, et pas un par processeur),
//! que chaque étage incrémente là où Linux le fait : IP à l'entrée, à la
//! livraison, au réassemblage et à la sortie (ipv4.rs, inet::fragments),
//! ICMP (icmp.rs, ping.rs), UDP (udp.rs, datagramme.rs, et la lecture :
//! socket.rs), TCP. proc.rs en fait le texte.

use inet::snmp::Mib;

pub static MIB: Mib = Mib::new();
