//! La MTU du chemin (RFC 1191 ; `__ip_rt_update_pmtu`, `update_or_create_fnhe`,
//! net/ipv4/route.c de Linux).
//!
//! La MTU de notre carte ne dit rien du plus petit lien sur le chemin. Un routeur qui
//! reçoit un paquet DF trop grand pour la suite le jette, et répond ICMP « fragmentation
//! nécessaire », avec sa MTU. On la retient pour cette DESTINATION, dans une table à
//! part des routes (`fib_nh_exception` : une route couvre tout un réseau, pas un
//! chemin), 10 min : le chemin peut avoir changé, et c'est le seul moyen de le découvrir
//! à nouveau (`ip_rt_mtu_expires`). Toutes les sockets vers cette destination en profitent.
//!
//! Le PLANCHER : un ICMP forgé disant une MTU de 68 ferait envoyer des paquets minuscules,
//! à grands frais (CVE-2004-1060 et la suite). Sous 552 octets (`ip_rt_min_pmtu`), on
//! retient 552, et la MTU est VERROUILLÉE : plus rien ne la change, et les paquets
//! partent alors sans DF : qu'un vrai petit lien les fragmente.
//!
//! Écarté : la découverte par sondes (PLPMTUD, `tcp_mtu_probing` vaut 0 par défaut) ;
//! l'arbre des exceptions de Linux, par route : une petite table suffit, et la plus
//! proche de son expiration cède sa place (`fnhe_oldest`).

/// `ip_rt_min_pmtu`.
pub const MTU_MIN: u32 = 552;
/// `ip_rt_mtu_expires` : 10 min.
pub const EXPIRATION: u64 = 600_000_000_000;
/// Les destinations à la fois.
pub const ENTREES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Exception {
    destination: [u8; 4],
    mtu: u32,
    verrouillee: bool,
    expire: u64,
}

pub struct Exceptions {
    t: [Option<Exception>; ENTREES],
}

impl Exceptions {
    pub const fn new() -> Exceptions {
        Exceptions { t: [None; ENTREES] }
    }

    fn chercher(&self, destination: [u8; 4], maintenant: u64) -> Option<&Exception> {
        self.t.iter().flatten().find(|e| e.destination == destination && maintenant < e.expire)
    }

    /// La MTU vers `destination` (`ipv4_mtu`) : celle retenue, sinon `route`, celle de
    /// la carte.
    pub fn mtu(&self, destination: [u8; 4], route: u32, maintenant: u64) -> u32 {
        self.chercher(destination, maintenant).map_or(route, |e| e.mtu)
    }

    /// `ip_mtu_locked` : retenue sous le plancher ?
    pub fn verrouillee(&self, destination: [u8; 4], maintenant: u64) -> bool {
        self.chercher(destination, maintenant).is_some_and(|e| e.verrouillee)
    }

    /// `__ip_rt_update_pmtu` : le réseau dit `mtu` vers `destination`. Rien si elle est
    /// verrouillée, ou si `mtu` dépasse ce qu'on croyait (un paquet qui passait ne dit
    /// rien de plus) ; sous le plancher : le plancher, verrouillée. La même redite ne
    /// repousse l'expiration que passé la moitié du délai : un flot d'ICMP ne la
    /// rendrait pas éternelle pour un chemin qui aurait changé.
    pub fn apprendre(&mut self, destination: [u8; 4], mtu: u32, route: u32, maintenant: u64) {
        if self.verrouillee(destination, maintenant) {
            return;
        }
        let ancienne = self.mtu(destination, route, maintenant);
        if ancienne < mtu {
            return;
        }
        let verrouillee = mtu < MTU_MIN;
        let mtu = if verrouillee { ancienne.min(MTU_MIN) } else { mtu };
        let existante = self.t.iter().position(|e| e.is_some_and(|e| e.destination == destination));
        if !verrouillee
            && let Some(i) = existante
            && let Some(e) = &self.t[i]
            && e.mtu == mtu
            && maintenant < e.expire
            && maintenant < e.expire.saturating_sub(EXPIRATION / 2)
        {
            return;
        }
        // Sa place, une libre (ou expirée), sinon celle qui expire le plus tôt.
        let i = existante.or_else(|| self.t.iter().position(|e| e.is_none_or(|e| maintenant >= e.expire))).unwrap_or_else(|| {
            let mut k = 0;
            for (j, e) in self.t.iter().enumerate() {
                if e.is_some_and(|e| self.t[k].is_some_and(|x| e.expire < x.expire)) {
                    k = j;
                }
            }
            k
        });
        self.t[i] = Some(Exception { destination, mtu, verrouillee, expire: maintenant + EXPIRATION });
    }

    /// Oublie ce qu'on sait de cette destination.
    pub fn oublier(&mut self, destination: [u8; 4]) {
        for e in self.t.iter_mut() {
            if e.is_some_and(|x| x.destination == destination) {
                *e = None;
            }
        }
    }
}
