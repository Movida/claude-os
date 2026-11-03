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
//!     un segment, et tout ce qui était en vol est renvoyé depuis le
//!     premier octet non acquitté, au rythme du démarrage lent.
//!
//! LES UNITÉS : des segments, comme Linux (`snd_cwnd`) ; la RFC compte en
//! octets. Nos tampons sont des octets, sans liste des segments envoyés :
//! le nombre de segments en vol est estimé par les octets en vol divisés
//! par le MSS (tcp.rs, `paquets_en_vol`), exact pour des segments pleins.
//!
//! Écarté : CUBIC, le contrôle par défaut de Linux (une fenêtre qui suit
//! une fonction cubique du temps depuis la dernière perte, et HyStart pour
//! quitter le démarrage lent) : derrière slirp ou sur `lo`, rien ne se
//! perd, et la cwnd ne limite jamais rien ; Linux garde Reno comme
//! référence. TCP_CONGESTION rend « reno ». Pas non plus d'« annulation »
//! (Linux revient sur une réduction quand il découvre qu'une
//! retransmission était inutile : il lui faut les horodatages ou les
//! D-SACK, que nous n'avons pas), ni de F-RTO (RFC 5682).

use super::{apres, avant};

/// Le seuil de départ : l'infini (TCP_INFINITE_SSTHRESH).
pub const SSTHRESH_INFINI: u32 = 0x7fff_ffff;
/// La fenêtre de départ (TCP_INIT_CWND, RFC 6928).
pub const CWND_INITIALE: u32 = 10;
/// Le nombre d'ACK dupliqués qui déclenche la retransmission rapide
/// (`tcp_reordering`).
pub const REORDONNANCEMENT: u32 = 3;

/// Où en est la connexion (le `icsk_ca_state` de Linux, sans CWR qui
/// suit les marques ECN, que nous n'avons pas).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Rien d'anormal.
    Ouverte,
    /// Des ACK dupliqués, pas encore trois.
    Desordre,
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
    /// Les ACK dupliqués de l'épisode : sans SACK, chacun dit qu'un segment
    /// de plus a quitté le réseau (le `sacked_out` que Linux simule pour
    /// Reno).
    pub dupacks: u32,
    /// Le point de reprise (`high_seq`) : le plus loin qu'on avait envoyé
    /// au début de la reprise ou de la perte. None : pas encore d'épisode.
    pub point: Option<u32>,
    /// La cwnd au début de la reprise, ce que PRR a reçu et envoyé depuis
    /// (`prior_cwnd`, `prr_delivered`, `prr_out`).
    cwnd_avant: u32,
    prr_livres: u32,
    pub prr_sortis: u32,
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
            dupacks: 0,
            point: None,
            cwnd_avant: 0,
            prr_livres: 0,
            prr_sortis: 0,
            limitee: false,
            max_sortis: 0,
            fin_usage: 0,
        }
    }

    /// Le démarrage lent ?
    pub fn demarrage_lent(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Le seuil de Reno après une perte : la moitié de la cwnd, au moins 2
    /// (`tcp_reno_ssthresh`).
    fn seuil_reno(&self) -> u32 {
        (self.cwnd >> 1).max(2)
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

    /// Le troisième ACK dupliqué : la reprise rapide commence
    /// (`tcp_enter_recovery`), sauf si l'épisode précédent n'est pas fini
    /// (RFC 6582, 3.2 : des ACK dupliqués qui ne couvrent pas le point de
    /// reprise précédent viennent de nos propres retransmissions, et non
    /// d'une perte nouvelle). Rend vrai si elle commence.
    pub fn entrer_reprise(&mut self, snd_una: u32, snd_max: u32) -> bool {
        if self.point.is_some_and(|p| !apres(snd_una, p)) {
            return false;
        }
        self.cwnd_avant = self.cwnd;
        self.ssthresh = self.seuil_reno();
        self.prr_livres = 0;
        self.prr_sortis = 0;
        self.point = Some(snd_max);
        self.phase = Phase::Reprise;
        true
    }

    /// Un RTO (`tcp_enter_loss`) : le seuil tombe, une seule fois par
    /// fenêtre (pas si l'on était déjà en reprise ou en perte pour les
    /// mêmes données, sauf à la première retransmission de la perte) ; la
    /// cwnd à un segment ; tout ce qui est en vol est réputé perdu.
    pub fn entrer_perte(&mut self, snd_una: u32, snd_max: u32, retransmissions: u32) {
        let reduire = matches!(self.phase, Phase::Ouverte | Phase::Desordre)
            || self.point.is_none_or(|p| !apres(p, snd_una))
            || (self.phase == Phase::Perte && retransmissions == 0);
        if reduire {
            self.cwnd_avant = self.cwnd;
            self.ssthresh = self.seuil_reno();
        }
        self.cwnd = 1;
        self.compte = 0;
        self.dupacks = 0;
        self.point = Some(snd_max);
        self.phase = Phase::Perte;
    }

    /// La reprise est finie (un ACK couvre le point de reprise) : la cwnd
    /// au seuil (`tcp_end_cwnd_reduction`).
    pub fn finir_reprise(&mut self) {
        if self.ssthresh < SSTHRESH_INFINI {
            self.cwnd = self.ssthresh;
        }
        self.dupacks = 0;
        self.phase = Phase::Ouverte;
    }

    /// PRR (`tcp_cwnd_reduction`, RFC 6937) : `livres` segments de plus ont
    /// quitté le réseau ; la cwnd devient ce qui est en vol plus ce qu'on a
    /// le droit d'envoyer. Tant qu'il y a plus en vol que le seuil, on
    /// envoie en proportion de ce qui arrive (seuil / cwnd d'avant : à peu
    /// près un segment pour deux reçus) ; en dessous, on remonte vers le
    /// seuil, sans dépasser ce qui arrive plus un (la variante « SSRB »
    /// de la RFC, celle de Linux). Toujours au moins un segment au début
    /// de la reprise : la retransmission rapide elle-même.
    pub fn prr(&mut self, livres: u32, perdus: u32, una_avance: bool, en_vol: u32) {
        if livres == 0 || self.cwnd_avant == 0 {
            return;
        }
        self.prr_livres += livres;
        let delta = self.ssthresh as i64 - en_vol as i64;
        let mut envoyer = if delta < 0 {
            let dividende = self.ssthresh as u64 * self.prr_livres as u64 + self.cwnd_avant as u64 - 1;
            (dividende / self.cwnd_avant as u64) as i64 - self.prr_sortis as i64
        } else {
            let mut s = (self.prr_livres as i64 - self.prr_sortis as i64).max(livres as i64);
            if una_avance && perdus == 0 {
                s += 1;
            }
            s.min(delta)
        };
        envoyer = envoyer.max(if self.prr_sortis > 0 { 0 } else { 1 });
        self.cwnd = (en_vol as i64 + envoyer).max(1) as u32;
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
        self.compte = 0;
    }

    /// Le seuil « courant » (`tcp_current_ssthresh`) : hors réduction, au
    /// moins les trois quarts de la cwnd.
    fn ssthresh_courant(&self) -> u32 {
        if self.phase == Phase::Reprise {
            self.ssthresh
        } else {
            self.ssthresh.max((self.cwnd >> 1) + (self.cwnd >> 2))
        }
    }
}
