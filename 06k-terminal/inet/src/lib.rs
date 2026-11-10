//! La pile d'IPv4 sans le matériel (6g) : ce qui se décide d'après des
//! tables et des délais, écrit pour qu'on le vérifie sur l'hôte. Son nom
//! est celui de la famille d'IPv4 dans Linux (« inet », net/ipv4).
//!
//! Le noyau garde ce qui touche le matériel (les cartes, leurs files), les
//! verrous, les attentes des programmes et les copies vers eux. Ici, les
//! RÈGLES : quelle route prend un paquet (routes.rs), ce que fait le client
//! DHCP du démarrage à chaque message et à chaque échéance (dhcp.rs), ce
//! qu'on sait de chaque voisin du réseau local et quand le redemander
//! (voisins.rs), à quelle socket UDP va un datagramme et quels ports une
//! socket peut prendre (ports.rs), et de même pour les sockets de ping et
//! leurs identifiants (idents.rs) ; et quand la tâche du réseau doit
//! se réveiller, et pour qui (echeances.rs, 6h), comment recoller un paquet en
//! fragments (fragments.rs), combien d'erreurs ICMP envoyer à chaque
//! machine (pairs.rs). Rien
//! ici ne lit l'horloge ni ne tire au hasard : l'heure (en nanosecondes) et
//! le hasard sont des arguments, si bien qu'un test peut faire passer 45
//! secondes en une ligne, et rejouer exactement un cas.
//!
//! Comme `formats`, sans `unsafe` (`forbid`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod dhcp;
pub mod echeances;
pub mod en_vol;
pub mod fragments;
pub mod idents;
pub mod pairs;
pub mod pmtu;
pub mod ports;
pub mod ports_tcp;
pub mod routes;
pub mod tcp;
pub mod voisins;
