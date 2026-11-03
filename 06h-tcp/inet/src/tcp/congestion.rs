//! Le contrôle de congestion d'une connexion : Reno (RFC 5681), sa reprise
//! rapide NewReno (RFC 6582) et la réduction proportionnelle de la fenêtre
//! pendant la reprise (PRR, RFC 6937), ce que fait Linux quand l'autre ne
//! parle pas SACK (`tcp_reno_cong_avoid`, net/ipv4/tcp_cong.c ;
//! `tcp_fastretrans_alert`, `tcp_cwnd_reduction`, net/ipv4/tcp_input.c).
//!
//! L'IDÉE. La fenêtre de l'autre dit combien IL peut recevoir ; la fenêtre
//! de congestion (cwnd) dit combien le RÉSEAU semble pouvoir porter. On
//! n'a jamais en vol plus que la plus petite des deux. La cwnd part de 10
//! segments (RFC 6928, comme Linux) et double à chaque aller-retour (le
//! « démarrage lent », qui n'a de lent que le nom) jusqu'au seuil
//! (ssthresh) ; au-delà, elle ne grandit plus que d'un segment par
//! aller-retour (« l'évitement de congestion »). Une perte est prise pour
//! un signe d'encombrement : le seuil tombe à la moitié de la cwnd.
//!   - Une perte vue par trois ACK DUPLIQUÉS (l'autre redit trois fois
//!     qu'il attend le même octet : les segments suivants arrivent, un
//!     seul manque) : la RETRANSMISSION RAPIDE du segment manquant, sans
//!     attendre le RTO, puis la REPRISE RAPIDE jusqu'à ce que tout ce qui
//!     était en vol au moment de la perte soit acquitté (le point de
//!     reprise). NewReno : un ACK « partiel » pendant la reprise (qui
//!     avance sans tout couvrir) montre la perte suivante, retransmise
//!     aussitôt. PRR règle combien de segments neufs partent pendant ce
//!     temps : en proportion de ce que l'autre reçoit, pour arriver en fin
//!     de reprise à une fenêtre égale au seuil, sans à-coup.
//!   - Une perte vue par le RTO (plus rien ne revient) : la cwnd retombe à
//!     ce qui est en vol plus un segment, et tout ce qui était en vol est
//!     renvoyé depuis le premier octet non acquitté, au rythme du démarrage
//!     lent.
//!
//! LES UNITÉS : des segments, comme Linux (`snd_cwnd`) ; la RFC compte en
//! octets. Les états, ce qui est perdu et renvoyé, et PRR sont dans retrans.rs ;
//! ici, la fenêtre et son seuil.
//!
//! Écarté : CUBIC, le contrôle par défaut de Linux (une fenêtre qui suit
//! une fonction cubique du temps depuis la dernière perte, et HyStart pour
//! quitter le démarrage lent) : derrière slirp ou sur `lo`, rien ne se
//! perd, et la cwnd ne limite jamais rien ; Linux garde Reno comme
//! référence. TCP_CONGESTION rend « reno ». Pas non plus d'« annulation »
//! (Linux revient sur une réduction quand il découvre qu'une
//! retransmission était inutile : il lui faut les horodatages ou les
//! D-SACK, que nous n'avons pas), ni de F-RTO (RFC 5682).

use super::avant;

/// Le seuil de départ : l'infini (TCP_INFINITE_SSTHRESH).
pub const SSTHRESH_INFINI: u32 = 0x7fff_ffff;
/// La fenêtre de départ (TCP_INIT_CWND, RFC 6928).
pub const CWND_INITIALE: u32 = 10;
/// Le degré de réordonnancement de départ (`tcp_reordering`) : sans SACK, le
/// nombre d'ACK dupliqués qui déclenche la retransmission rapide.
pub const TCP_REORDERING: u32 = 3;

/// Où en est la connexion (le `icsk_ca_state` de Linux, dans son ordre : ses
/// comparaisons en dépendent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Rien d'anormal.
    Ouverte,
    /// Des ACK dupliqués, pas encore trois.
    Desordre,
    /// La cwnd réduit sans reprise (TCP_CA_CWR).
    Reduction,
    /// La reprise rapide, après trois ACK dupliqués.
    Reprise,
    /// Après un RTO.
    Perte,
}

#[derive(Debug, Clone, Copy)]
pub struct Congestion {
    pub phase: Phase,
    /// La fenêtre de congestion et le seuil, en segments.
    pub cwnd: u32,
    pub ssthresh: u32,
    /// Les segments acquittés pendant l'évitement de congestion, vers le
    /// prochain segment de cwnd (`snd_cwnd_cnt`).
    compte: u32,
    /// La cwnd a-t-elle limité l'émission pendant l'aller-retour en cours
    /// (`is_cwnd_limited`), et le plus de segments en vol (`max_packets_out`),
    /// jusqu'à `fin_usage` (`cwnd_usage_seq`).
    limitee: bool,
    max_sortis: u32,
    fin_usage: u32,
}

impl Congestion {
    pub const fn new() -> Congestion {
        Congestion {
            phase: Phase::Ouverte,
            cwnd: CWND_INITIALE,
            ssthresh: SSTHRESH_INFINI,
            compte: 0,
            limitee: false,
            max_sortis: 0,
            fin_usage: 0,
        }
    }

    /// Le démarrage lent ?
    pub fn demarrage_lent(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// CWR ou la reprise rapide (`tcp_in_cwnd_reduction`).
    pub fn en_reduction(&self) -> bool {
        matches!(self.phase, Phase::Reduction | Phase::Reprise)
    }

    /// Le seuil après une perte : pour Reno, la moitié de la cwnd, au moins 2
    /// (`tcp_reno_ssthresh`).
    pub fn seuil(&self) -> u32 {
        (self.cwnd >> 1).max(2)
    }

    /// Le compte vers le prochain segment repart de zéro.
    pub fn remettre_compte(&mut self) {
        self.compte = 0;
    }

    /// La cwnd a-t-elle servi pendant l'aller-retour en cours
    /// (`tcp_is_cwnd_limited`) ? Sinon, la faire grandir n'aurait pas de
    /// sens : elle ne mesurerait rien (RFC 7661). Au démarrage lent, on la
    /// laisse aller jusqu'au double de ce qui a été en vol.
    fn a_servi(&self) -> bool {
        self.limitee || (self.demarrage_lent() && self.cwnd < 2 * self.max_sortis)
    }

    /// Après une émission : la cwnd l'a-t-elle arrêtée, et combien de
    /// segments sont en vol (`tcp_cwnd_validate`) ? Retenu pour
    /// l'aller-retour en cours, jusqu'à ce que SND.UNA passe `snd_nxt`.
    pub fn valider(&mut self, limitee: bool, sortis: u32, snd_una: u32, snd_nxt: u32) {
        if !avant(snd_una, self.fin_usage) || limitee || (!self.limitee && sortis > self.max_sortis) {
            self.limitee = limitee;
            self.max_sortis = sortis;
            self.fin_usage = snd_nxt;
        }
    }

    /// `acquittes` segments de plus acquittés hors de toute reprise : la
    /// cwnd grandit (`tcp_reno_cong_avoid`) ; au démarrage lent, d'autant
    /// de segments (le double par aller-retour), jusqu'au seuil ; au-delà,
    /// d'un segment chaque fois qu'une cwnd entière a été acquittée.
    pub fn croitre(&mut self, acquittes: u32) {
        if !self.a_servi() {
            return;
        }
        let mut acquittes = acquittes;
        if self.demarrage_lent() {
            let c = self.cwnd.saturating_add(acquittes).min(self.ssthresh);
            acquittes -= c - self.cwnd;
            self.cwnd = c;
            if acquittes == 0 {
                return;
            }
        }
        // `tcp_cong_avoid_ai(tp, w = cwnd, acked)`.
        let w = self.cwnd;
        if self.compte >= w {
            self.compte = 0;
            self.cwnd += 1;
        }
        self.compte += acquittes;
        if self.compte >= w {
            let d = self.compte / w;
            self.compte -= d * w;
            self.cwnd += d;
        }
    }

    /// Après un long silence (plus d'un RTO sans rien envoyer), la cwnd ne
    /// dit plus rien du réseau : elle est divisée par deux par RTO écoulé,
    /// jusqu'à la fenêtre de départ (`tcp_cwnd_restart`, RFC 2861 ; le
    /// `tcp_slow_start_after_idle` de Linux, vrai par défaut). Le seuil
    /// garde la trace de ce qu'elle était.
    pub fn redemarrer(&mut self, silence: u64, rto: u64) {
        let depart = CWND_INITIALE.min(self.cwnd);
        self.ssthresh = self.ssthresh_courant();
        let mut cwnd = self.cwnd;
        let mut reste = silence as i64;
        loop {
            reste -= rto as i64;
            if reste <= 0 || cwnd <= depart {
                break;
            }
            cwnd >>= 1;
        }
        self.cwnd = cwnd.max(depart);
    }

    /// Le seuil « courant » (`tcp_current_ssthresh`) : hors réduction, au
    /// moins les trois quarts de la cwnd.
    pub fn ssthresh_courant(&self) -> u32 {
        if self.en_reduction() {
            self.ssthresh
        } else {
            self.ssthresh.max((self.cwnd >> 1) + (self.cwnd >> 2))
        }
    }
}
