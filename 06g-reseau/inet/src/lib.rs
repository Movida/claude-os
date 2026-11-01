//! La pile d'IPv4 sans le matériel (6g) : ce qui se décide d'après des
//! tables et des délais, écrit pour qu'on le vérifie sur l'hôte. Son nom
//! est celui de la famille d'IPv4 dans Linux (« inet », net/ipv4).
//!
//! Le noyau garde ce qui touche le matériel (les cartes, leurs files), les
//! verrous, les attentes des programmes et les copies vers eux. Ici, les
//! RÈGLES : quelle route prend un paquet (routes.rs), ce que fait le client
//! DHCP du démarrage à chaque message et à chaque échéance (dhcp.rs). Rien
//! ici ne lit l'horloge ni ne tire au hasard : l'heure (en nanosecondes) et
//! le hasard sont des arguments, si bien qu'un test peut faire passer 45
//! secondes en une ligne, et rejouer exactement un cas.
//!
//! Comme `formats`, sans `unsafe` (`forbid`).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod dhcp;
pub mod routes;
