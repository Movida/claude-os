//! Le temps d'aller-retour (RTT) d'une connexion, le délai de
//! retransmission (RTO) qu'on en tire, et le temps au bout duquel on
//! abandonne : l'estimateur de Jacobson (SIGCOMM 1988) tel que l'écrit
//! Linux (`tcp_rtt_estimator`, `tcp_set_rto`, net/ipv4/tcp_input.c), et
//! le « temps modélisé » des abandons de Linux 6.18 (`tcp_model_timeout`,
//! net/ipv4/tcp_timer.c).
//!
//! L'IDÉE. Un émetteur qui n'a pas reçu l'ACK d'un segment au bout d'un
//! certain temps le croit perdu, et le renvoie. Trop tôt, il encombre le
//! réseau de copies inutiles ; trop tard, la connexion reste muette. Ce
//! délai se règle sur le RTT mesuré : une moyenne lissée (SRTT, chaque
//! mesure compte pour 1/8) et l'écart moyen autour d'elle (MDEV, 1/4).
//! RTO = SRTT + RTTVAR, où RTTVAR est le plus grand écart vu pendant le
//! dernier aller-retour (`mdev_max`), et jamais moins de 200 ms.
//!
//! Par rapport à la RFC 6298 (RTO = SRTT + max(G, 4 × RTTVAR), au moins
//! 1 s), deux différences, celles de Linux : le plancher de 200 ms
//! (TCP_RTO_MIN) porte sur l'écart, pas sur le RTO entier, et la seconde
//! minimale de la RFC n'est appliquée par personne ; un écart qui DIMINUE
//! pèse huit fois moins qu'un écart qui grandit (le RTO ne s'effondre pas
//! quand le RTT baisse d'un coup : ce que Linux appelle sa variante
//! d'« Eifel »). Écarté : la RFC à la lettre, dont le RTO d'au moins 1 s
//! rendrait chaque perte sur `lo` cinq fois plus lente que chez Linux.
//!
//! Les unités : des nanosecondes (l'horloge du noyau), là où Linux compte
//! en microsecondes ; les décalages (×8 pour SRTT, ×4 pour MDEV) sont les
//! siens, pour qu'on puisse lire les deux côte à côte.

/// Le RTO de départ, avant toute mesure (TCP_TIMEOUT_INIT, RFC 6298 2.1).
pub const RTO_INITIAL: u64 = 1_000_000_000;
/// Le RTO quand la poignée de main n'a pas donné de mesure (son SYN a été
/// retransmis) : 3 s (TCP_TIMEOUT_FALLBACK, RFC 6298 5.7).
pub const RTO_REPLI: u64 = 3_000_000_000;
/// Les bornes du RTO (TCP_RTO_MIN, TCP_RTO_MAX).
pub const RTO_MIN: u64 = 200_000_000;
pub const RTO_MAX: u64 = 120_000_000_000;

/// L'estimateur (les champs `srtt_us`, `mdev_us`, `mdev_max_us`,
/// `rttvar_us` et `rtt_seq` du `tcp_sock` de Linux).
#[derive(Debug, Clone, Copy)]
pub struct Rtt {
    /// SRTT × 8 ; 0 : aucune mesure encore.
    srtt8: u64,
    /// MDEV × 4.
    mdev4: u64,
    /// Le plus grand MDEV × 4 depuis le début de l'aller-retour en cours.
    mdev_max: u64,
    /// L'écart que le RTO ajoute à SRTT (au moins RTO_MIN).
    rttvar: u64,
    /// La fin de l'aller-retour en cours : quand SND.UNA la dépasse,
    /// RTTVAR se rapproche de `mdev_max`, qui repart du plancher.
    rtt_seq: u32,
}

impl Rtt {
    pub const fn new() -> Rtt {
        Rtt { srtt8: 0, mdev4: 0, mdev_max: 0, rttvar: 0, rtt_seq: 0 }
    }

    /// Une mesure a-t-elle déjà été faite ?
    pub fn mesure(&self) -> bool {
        self.srtt8 != 0
    }

    /// SRTT (la borne des ACK retardés, TCP_INFO) et l'écart moyen MDEV
    /// (le `tcpi_rttvar` de TCP_INFO).
    pub fn srtt(&self) -> u64 {
        self.srtt8 >> 3
    }

    /// SRTT × 8, en µs (le `srtt_us` de Linux) : 0 sans mesure.
    pub fn srtt8_us(&self) -> u64 {
        self.srtt8 / 1000
    }

    pub fn ecart(&self) -> u64 {
        self.mdev4 >> 2
    }

    /// Le RTO que donne l'estimateur, sans recul (`__tcp_set_rto`, borné
    /// par `tcp_bound_rto`).
    pub fn rto(&self) -> u64 {
        ((self.srtt8 >> 3) + self.rttvar).min(RTO_MAX)
    }

    /// Une mesure `m` (en ns) ; `snd_una` et `snd_nxt` disent où en est
    /// l'aller-retour (`tcp_rtt_estimator`, ligne à ligne).
    pub fn echantillon(&mut self, m: u64, snd_una: u32, snd_nxt: u32) {
        let m = m.max(1) as i64;
        if self.srtt8 != 0 {
            // L'erreur de la moyenne, puis la moyenne : 7/8 de l'ancienne,
            // 1/8 de la mesure.
            let mut m = m - (self.srtt8 >> 3) as i64;
            let srtt8 = (self.srtt8 as i64 + m) as u64;
            if m < 0 {
                // Le RTT a baissé : l'écart ne compte que pour 1/32 (le
                // gain de 1/4, encore divisé par 8).
                m = -m - (self.mdev4 >> 2) as i64;
                if m > 0 {
                    m >>= 3;
                }
            } else {
                m -= (self.mdev4 >> 2) as i64;
            }
            // L'écart : 3/4 de l'ancien, 1/4 du nouveau.
            self.mdev4 = (self.mdev4 as i64 + m) as u64;
            if self.mdev4 > self.mdev_max {
                self.mdev_max = self.mdev4;
                if self.mdev_max > self.rttvar {
                    self.rttvar = self.mdev_max;
                }
            }
            // Un aller-retour de plus : RTTVAR redescend d'un quart vers le
            // plus grand écart de celui qui s'achève.
            if super::apres(snd_una, self.rtt_seq) {
                if self.mdev_max < self.rttvar {
                    self.rttvar -= (self.rttvar - self.mdev_max) >> 2;
                }
                self.rtt_seq = snd_nxt;
                self.mdev_max = RTO_MIN;
            }
            self.srtt8 = srtt8.max(1);
        } else {
            // La première mesure : SRTT = m, MDEV = m / 2 (le RTO vaut
            // alors 3 m, au moins m + 200 ms).
            self.srtt8 = (m as u64) << 3;
            self.mdev4 = (m as u64) << 1;
            self.rttvar = self.mdev4.max(RTO_MIN);
            self.mdev_max = self.rttvar;
            self.rtt_seq = snd_nxt;
        }
    }

    /// La poignée de main s'achève sans mesure (son SYN, ou SYN-ACK, a été
    /// retransmis : Karn interdit de mesurer) : l'écart de 3 s de la RFC
    /// 6298 (5.7), comme `tcp_init_metrics`. Le RTO vaut alors 3 s.
    pub fn repli(&mut self) {
        self.rttvar = RTO_REPLI;
        self.mdev4 = RTO_REPLI;
        self.mdev_max = RTO_REPLI;
    }
}

/// Le temps qu'auraient pris `limite` retransmissions, la première après
/// `base` et chacune doublant la précédente jusqu'à RTO_MAX
/// (`tcp_model_timeout` de Linux). Linux juge un abandon à ce temps, et
/// non au seul nombre de retransmissions : un RTO qui a été remis à zéro
/// en route (une mesure) ne prolonge pas la connexion. `tcp_retries2` = 15
/// avec une base de 200 ms : 924,6 s.
pub fn temps_modele(limite: u32, base: u64) -> u64 {
    let seuil = (RTO_MAX / base).ilog2();
    if limite <= seuil {
        ((2u64 << limite) - 1) * base
    } else {
        ((2u64 << seuil) - 1) * base + (limite - seuil) as u64 * RTO_MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    /// L'estimateur de Linux, sur deux mesures : 100 ms, puis 10 ms (le RTT
    /// baisse). SRTT : 7/8 × 100 + 1/8 × 10 = 88,75 ms. MDEV : la première
    /// mesure le pose à 50 ms ; la baisse (90 ms d'erreur, moins 50) ne
    /// compte que pour 1/8 de 1/4 : 50 + 40/32 = 51,25 ms (sans ce 1/8 :
    /// 60 ms). RTTVAR (4 × MDEV au plus haut, jamais sous 200 ms) passe à
    /// 205 ms : RTO = 88,75 + 205.
    #[test]
    fn estimateur_de_linux() {
        let mut r = Rtt::new();
        r.echantillon(100 * MS, 0, 10);
        assert_eq!((r.srtt(), r.ecart(), r.rto()), (100 * MS, 50 * MS, 300 * MS));
        r.echantillon(10 * MS, 0, 10);
        assert_eq!((r.srtt(), r.ecart()), (88_750_000, 51_250_000));
        assert_eq!(r.rto(), 88_750_000 + 205 * MS);
        // Le RTT monte : l'erreur compte pour 1/4. 88,75 + (200 - 88,75) / 8.
        r.echantillon(200 * MS, 0, 10);
        assert_eq!(r.srtt(), 102_656_250);
    }
}
