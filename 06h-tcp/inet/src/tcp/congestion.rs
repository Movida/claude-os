//! Le contrôle de congestion d'une connexion (les `tcp_congestion_ops` de Linux,
//! net/ipv4/tcp_cong.c) : Reno (RFC 5681), et CUBIC (cubic.rs), celui par défaut.
//! Ce qui est commun aux deux vit ici et dans retrans.rs : la reprise rapide
//! NewReno (RFC 6582) et la réduction proportionnelle de la fenêtre pendant la
//! reprise (PRR, RFC 6937).
//!
//! L'IDÉE. La fenêtre de l'autre dit combien IL peut recevoir ; la fenêtre
//! de congestion (cwnd) dit combien le RÉSEAU semble pouvoir porter. On
//! n'a jamais en vol plus que la plus petite des deux. La cwnd part de 10
//! segments (RFC 6928, comme Linux) et double à chaque aller-retour (le
//! « démarrage lent », qui n'a de lent que le nom) jusqu'au seuil
//! (ssthresh) ; au-delà (« l'évitement de congestion »), elle grandit selon
//! le contrôle : d'un segment par aller-retour pour Reno, le long d'une courbe
//! du temps pour CUBIC. Une perte est prise pour un signe d'encombrement : le
//! seuil tombe (à la moitié pour Reno, à 70 % pour CUBIC).
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
//! LES CROCHETS. Linux a une table de pointeurs de fonctions (`tcp_congestion_ops`)
//! par contrôle, et une place dans la socket pour ses variables (`icsk_ca_priv`).
//! Les sept que Reno et CUBIC utilisent : `init` (`initialiser`), `ssthresh`
//! (`seuil`), `cong_avoid` (`croitre`), `set_state` (`changer_phase`), `undo_cwnd`
//! (`annuler`), `cwnd_event` (`depart`) et `pkts_acked` (`segments_acquittes`). Ici
//! une énumération : elle tient l'état de chacun dans la connexion, sans
//! allocation ni transtypage, et Rust y vérifie que chaque crochet traite chaque
//! contrôle. Écarté : un trait et un `dyn` (une allocation par connexion, ou une
//! place réservée à la main, pour une liste de contrôles qui ne change qu'en
//! écrivant du noyau) ; BBR et les modules chargeables, qui demanderaient le débit
//! mesuré (`tcp_rate.c`) et le pacing réel : Linux ne les prend pas par défaut.
//!
//! LE PACING (`sk_pacing_rate`) : un débit calculé à chaque ACK (`maj_pacing`), lu
//! par TCP_INFO et par HyStart. Rien ne s'envoie à ce rythme (par défaut, Linux non
//! plus : seuls `fq` et BBR l'appliquent).

use super::avant;
use super::cubic::{Acquittement, Cubic};

/// Le seuil de départ : l'infini (TCP_INFINITE_SSTHRESH).
pub const SSTHRESH_INFINI: u32 = 0x7fff_ffff;
/// La fenêtre de départ (TCP_INIT_CWND, RFC 6928).
pub const CWND_INITIALE: u32 = 10;
/// Le degré de réordonnancement de départ (`tcp_reordering`) : sans SACK, le
/// nombre d'ACK dupliqués qui déclenche la retransmission rapide.
pub const TCP_REORDERING: u32 = 3;

/// Le débit de `sk_pacing_rate` d'avant toute mesure (`~0UL`, et aussi
/// `tcpi_max_pacing_rate`, sans SO_MAX_PACING_RATE).
pub const PACING_MAX: u64 = u64::MAX;
/// `tcp_pacing_ss_ratio` et `tcp_pacing_ca_ratio`, en %.
const PACING_SS: u64 = 200;
const PACING_CA: u64 = 120;

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

/// Un contrôle de congestion, par son nom (TCP_CONGESTION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Controle {
    Reno,
    Cubic,
}

impl Controle {
    /// Celui d'une socket neuve (`tcp_congestion_control`).
    pub const DEFAUT: Controle = Controle::Cubic;

    /// Son nom (`tcp_congestion_ops.name`).
    pub fn nom(self) -> &'static [u8] {
        match self {
            Controle::Reno => b"reno",
            Controle::Cubic => b"cubic",
        }
    }

    /// Le contrôle qui porte ce nom (`tcp_ca_find`).
    pub fn par_nom(nom: &[u8]) -> Option<Controle> {
        [Controle::Reno, Controle::Cubic].into_iter().find(|c| c.nom() == nom)
    }
}

/// L'état du contrôle en service (`icsk_ca_ops`, et `icsk_ca_priv`). Reno n'en a
/// pas, sauf `compte`, que Linux garde dans la connexion pour tous.
#[derive(Debug, Clone, Copy)]
enum Algo {
    Reno,
    Cubic(Cubic),
}

#[derive(Debug, Clone, Copy)]
pub struct Congestion {
    pub phase: Phase,
    /// La fenêtre de congestion et le seuil, en segments.
    pub cwnd: u32,
    pub ssthresh: u32,
    algo: Algo,
    /// `icsk_ca_initialized` : `initialiser` n'est fait qu'une fois, à
    /// l'établissement, ou par TCP_CONGESTION sur une socket déjà en route.
    initialise: bool,
    /// Les segments acquittés pendant l'évitement de congestion, vers le
    /// prochain segment de cwnd (`snd_cwnd_cnt`).
    compte: u32,
    /// La cwnd a-t-elle limité l'émission pendant l'aller-retour en cours
    /// (`is_cwnd_limited`), et le plus de segments en vol (`max_packets_out`),
    /// jusqu'à `fin_usage` (`cwnd_usage_seq`).
    limitee: bool,
    max_sortis: u32,
    fin_usage: u32,
    /// Le plus de segments en vol pendant que le programme n'avait pas de quoi
    /// remplir la cwnd (`snd_cwnd_used`), et l'heure où elle a servi ou changé
    /// pour la dernière fois (`snd_cwnd_stamp`).
    utilisee: u32,
    instant: u64,
    /// Le débit calculé, en octets par seconde (`sk_pacing_rate`) ; l'infini
    /// tant qu'aucune mesure ne l'a calculé (`sock_init_data`).
    pub pacing: u64,
}

impl Congestion {
    pub const fn new() -> Congestion {
        Congestion {
            phase: Phase::Ouverte,
            cwnd: CWND_INITIALE,
            ssthresh: SSTHRESH_INFINI,
            algo: Algo::Cubic(Cubic::new()),
            initialise: false,
            compte: 0,
            limitee: false,
            max_sortis: 0,
            fin_usage: 0,
            utilisee: 0,
            instant: 0,
            pacing: PACING_MAX,
        }
    }

    /// Le contrôle en service.
    pub fn controle(&self) -> Controle {
        match self.algo {
            Algo::Reno => Controle::Reno,
            Algo::Cubic(_) => Controle::Cubic,
        }
    }

    /// Change de contrôle (`tcp_reinit_congestion_control`) ; l'état du précédent
    /// est perdu ; une connexion déjà ouverte initialise le nouveau tout de suite.
    pub fn choisir(&mut self, c: Controle, ouverte: bool, snd_nxt: u32, maintenant: u64) {
        if c == self.controle() {
            return;
        }
        self.algo = match c {
            Controle::Reno => Algo::Reno,
            Controle::Cubic => Algo::Cubic(Cubic::new()),
        };
        self.initialise = false;
        if ouverte {
            self.initialiser(snd_nxt, maintenant);
        }
    }

    /// `tcp_init_congestion_control`.
    pub fn initialiser(&mut self, snd_nxt: u32, maintenant: u64) {
        if let Algo::Cubic(c) = &mut self.algo {
            c.initialiser(snd_nxt, maintenant);
        }
        self.initialise = true;
    }

    /// L'établissement : initialisé, si TCP_CONGESTION ne l'a pas déjà fait
    /// (`tcp_init_transfer`).
    pub fn etablir(&mut self, snd_nxt: u32, maintenant: u64) {
        if !self.initialise {
            self.initialiser(snd_nxt, maintenant);
        }
        self.instant = maintenant;
    }

    /// L'état de la reprise change (`tcp_set_ca_state`).
    pub fn changer_phase(&mut self, phase: Phase, snd_nxt: u32, maintenant: u64) {
        if phase == Phase::Perte && let Algo::Cubic(c) = &mut self.algo {
            c.perte(snd_nxt, maintenant);
        }
        self.phase = phase;
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
    /// (`tcp_reno_ssthresh`) ; CUBIC, β × cwnd, et il retient la perte.
    pub fn seuil(&mut self) -> u32 {
        match &mut self.algo {
            Algo::Reno => (self.cwnd >> 1).max(2),
            Algo::Cubic(c) => c.seuil(self.cwnd),
        }
    }

    /// La cwnd d'une réduction défaite (`tcp_reno_undo_cwnd`, pour les deux).
    pub fn annuler(&mut self, avant: u32, maintenant: u64) -> u32 {
        self.instant = maintenant;
        self.cwnd.max(avant)
    }

    /// Le premier segment de données après un silence (`CA_EVENT_TX_START`,
    /// rien n'étant en vol) ; `dernier_envoi`, l'heure du précédent.
    pub fn depart(&mut self, dernier_envoi: u64, maintenant: u64) {
        if let Algo::Cubic(c) = &mut self.algo {
            c.depart(dernier_envoi, maintenant);
        }
    }

    /// `pkts_acked`, à chaque ACK qui retire quelque chose de la file ; `rtt`, en
    /// ns, celle du dernier segment acquitté (`rate_sample.rtt_us`). HyStart peut y
    /// décider de quitter le démarrage lent : le seuil devient la cwnd.
    pub fn segments_acquittes(&mut self, rtt: Option<u64>, snd_una: u32, snd_nxt: u32, maintenant: u64) {
        let (Algo::Cubic(c), Some(rtt)) = (&mut self.algo, rtt) else { return };
        let a = Acquittement { cwnd: self.cwnd, ssthresh: self.ssthresh, snd_una, snd_nxt, pacing: self.pacing, maintenant };
        if c.acquitte((rtt / 1000) as u32, &a) {
            self.ssthresh = self.cwnd;
        }
    }

    /// Le débit calculé (`tcp_update_pacing_rate`) : cwnd × MSS / SRTT, à 200 % en
    /// démarrage lent (la cwnd double à chaque aller-retour : `tcp_pacing_ss_ratio`),
    /// à 120 % ensuite (`tcp_pacing_ca_ratio`). `srtt8_us`, SRTT × 8 en µs, le
    /// `srtt_us` de Linux ; sans mesure, le calcul reste sans division, comme le sien.
    pub fn maj_pacing(&mut self, mss: u32, sortis: u32, srtt8_us: u64) {
        let ratio = if self.cwnd < self.ssthresh / 2 { PACING_SS } else { PACING_CA };
        let mut debit = mss as u64 * ((1_000_000 / 100) << 3) * ratio * self.cwnd.max(sortis) as u64;
        if srtt8_us != 0 {
            debit /= srtt8_us;
        }
        self.pacing = debit;
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

    /// Après une émission (`tcp_cwnd_validate`) : la cwnd l'a-t-elle arrêtée, et
    /// combien de segments sont en vol ? Retenu pour l'aller-retour en cours,
    /// jusqu'à ce que SND.UNA passe `snd_nxt`. Puis, si elle ne sert pas depuis
    /// plus d'un RTO (RFC 2861, le programme n'a pas de quoi la remplir), elle
    /// redescend vers ce qui a servi : `relachable`, si rien n'est à reprendre
    /// et que le programme n'est pas bloqué sur son tampon d'envoi.
    pub fn valider(&mut self, limitee: bool, sortis: u32, snd_una: u32, snd_nxt: u32, rto: u64, relachable: bool, maintenant: u64) {
        if !avant(snd_una, self.fin_usage) || limitee || (!self.limitee && sortis > self.max_sortis) {
            self.limitee = limitee;
            self.max_sortis = sortis;
            self.fin_usage = snd_nxt;
        }
        if self.a_servi() {
            self.utilisee = 0;
            self.instant = maintenant;
        } else {
            self.utilisee = self.utilisee.max(sortis);
            if maintenant.saturating_sub(self.instant) >= rto {
                self.limitee_par_le_programme(relachable, maintenant);
            }
        }
    }

    /// `tcp_cwnd_application_limited` : la moitié de l'écart entre la cwnd et ce
    /// qui a servi, jamais moins que la fenêtre de départ ; le seuil en garde la
    /// trace, pour y remonter vite.
    fn limitee_par_le_programme(&mut self, relachable: bool, maintenant: u64) {
        if relachable {
            let utilisee = self.utilisee.max(CWND_INITIALE);
            if utilisee < self.cwnd {
                self.ssthresh = self.ssthresh_courant();
                self.cwnd = (self.cwnd + utilisee) >> 1;
            }
            self.utilisee = 0;
        }
        self.instant = maintenant;
    }

    /// `acquittes` segments de plus acquittés hors de toute reprise : la
    /// cwnd grandit (`tcp_cong_avoid`, `cong_avoid` de chaque contrôle) ; au
    /// démarrage lent, d'autant de segments (le double par aller-retour),
    /// jusqu'au seuil ; au-delà, d'un segment tous les `w` acquittés : `w` = la
    /// cwnd pour Reno, le pas de la courbe pour CUBIC.
    pub fn croitre(&mut self, acquittes: u32, maintenant: u64) {
        self.instant = maintenant;
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
        let w = match &mut self.algo {
            Algo::Reno => self.cwnd,
            Algo::Cubic(c) => c.pas(self.cwnd, acquittes, maintenant),
        };
        // `tcp_cong_avoid_ai`.
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

    /// La cwnd a été posée de l'extérieur, ou a servi (`snd_cwnd_stamp`).
    pub fn poser_instant(&mut self, maintenant: u64) {
        self.instant = maintenant;
    }

    /// Après un long silence (plus d'un RTO sans rien envoyer), la cwnd ne
    /// dit plus rien du réseau : elle est divisée par deux par RTO écoulé,
    /// jusqu'à la fenêtre de départ (`tcp_cwnd_restart`, RFC 2861 ; le
    /// `tcp_slow_start_after_idle` de Linux, vrai par défaut). Le seuil
    /// garde la trace de ce qu'elle était.
    pub fn redemarrer(&mut self, silence: u64, rto: u64, maintenant: u64) {
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
        self.instant = maintenant;
        self.utilisee = 0;
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
