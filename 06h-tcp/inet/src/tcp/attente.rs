//! Une entrée de TIME_WAIT (le `tcp_timewait_sock` de Linux,
//! `tcp_timewait_state_process`, net/ipv4/tcp_minisocks.c) : ce qui reste
//! d'une connexion finie, le temps que ses derniers segments disparaissent du
//! réseau, sans la mémoire de ses tampons. Aussi l'orpheline en FIN_WAIT_2
//! (son sous-état), qui attend le FIN de l'autre sans programme pour le lire.
//!
//! Ici, les règles, testées sur l'hôte ; le noyau (noyau/src/reseau/tcp.rs)
//! garde la table et l'échéance, et fait ce que dit `Issue`.

use super::{apres, avant, dans_la_fenetre, paws_rejet, Horodatages, LIMITE_ACK_INVALIDE};
use formats::reseau::tcp::{self, Tcp};

/// Ce que le noyau doit faire d'un segment reçu par l'entrée.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Issue {
    /// Répondre par l'ACK de l'entrée (`entete_ack`).
    pub ack: bool,
    /// Répondre par un RST (`tcp_v4_send_reset`).
    pub rst: bool,
    /// L'entrée disparaît.
    pub effacer: bool,
    /// Elle repart pour 60 s (`inet_twsk_reschedule`).
    pub prolonger: bool,
    /// Un SYN reprend le quadruplet (`TCP_TW_SYN`) : s'il y a une écoute,
    /// l'entrée disparaît et la fille prend ce numéro initial, plus loin que
    /// tout ce que l'ancienne connexion a envoyé (RFC 1122 4.2.2.13) ; sinon,
    /// un ACK.
    pub reprendre: Option<u32>,
}

/// Le délai avant qu'un `connect` reprenne une entrée (`tcp_tw_reuse_delay`).
const REUTILISATION: u64 = 1_000_000_000;

#[derive(Debug, Clone, Copy)]
pub struct Attente {
    pub port_local: u16,
    pub port_distant: u16,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    /// La fenêtre annoncée (`tw_rcv_wnd`) et notre échelle (`tw_rcv_wscale`),
    /// pour les ACK de l'entrée et la fenêtre d'une orpheline en FIN_WAIT_2.
    pub rcv_wnd: u32,
    pub echelle: u8,
    /// Le sous-état FIN_WAIT_2, ou TIME_WAIT.
    pub fin_attente2: bool,
    /// L'heure de son dernier ACK hors fenêtre (`tw_last_oow_ack_time`).
    dernier_ack: Option<u64>,
    /// Les horodatages de la connexion, s'ils étaient en service
    /// (`tw_ts_recent`, `tw_ts_recent_stamp`, `tw_ts_offset`).
    pub ts: Option<Horodatages>,
    /// Son entrée dans ce sous-état (`tw_entry_stamp`) : un `connect` ne la
    /// reprend pas moins d'une seconde après (`tcp_tw_reuse_delay`).
    pub entree: u64,
}

impl Attente {
    pub fn new(port_local: u16, port_distant: u16, snd_nxt: u32, rcv_nxt: u32, rcv_wnd: u32, echelle: u8, fin_attente2: bool, ts: Option<Horodatages>,
               entree: u64) -> Attente {
        Attente { port_local, port_distant, snd_nxt, rcv_nxt, rcv_wnd, echelle, fin_attente2, dernier_ack: None, ts, entree }
    }

    /// Un `connect` peut-il reprendre ce quadruplet (`tcp_twsk_unique`) ? Il
    /// faut qu'elle ait vu des horodatages : PAWS protège alors la connexion
    /// neuve des vieux segments de l'ancienne. Un port déjà lié par `bind` : cela
    /// suffit (`twp` nul). Un port choisi par `connect` : seulement par la boucle
    /// (`tcp_tw_reuse` = 2), plus d'une seconde après son entrée, et pas
    /// d'une orpheline qui attend en FIN_WAIT_2. Rend le numéro initial de
    /// la neuve, et ses horodatages.
    pub fn reprise(&self, port_lie: bool, boucle: bool, maintenant: u64) -> Option<(u32, Horodatages)> {
        let ts = self.ts?;
        if !port_lie && (self.fin_attente2 || !boucle || maintenant.saturating_sub(self.entree) <= REUTILISATION) {
            return None;
        }
        let isn = self.snd_nxt.wrapping_add(65_535 + 2);
        Some((if isn == 0 { 1 } else { isn }, ts))
    }

    /// Un ACK hors fenêtre, au plus un toutes les 500 ms, sauf pour un
    /// segment de données sans SYN (`tcp_timewait_check_oow_rate_limit`).
    fn ack_hors_fenetre(&mut self, donnees_sans_syn: bool, maintenant: u64) -> bool {
        if donnees_sans_syn {
            return true;
        }
        if self.dernier_ack.is_some_and(|d| maintenant.saturating_sub(d) < LIMITE_ACK_INVALIDE) {
            return false;
        }
        self.dernier_ack = Some(maintenant);
        true
    }

    /// Un segment pour l'entrée, dans l'ordre de
    /// `tcp_timewait_state_process`. PAWS d'abord : un segment plus vieux que le
    /// dernier horodatage vu est « rejeté ». En FIN_WAIT_2 : rejeté, ou hors de
    /// la fenêtre, un ACK ; un RST l'efface ; un SYN, ou des données après une
    /// fermeture d'un côté, RST et l'entrée disparaît ; le FIN de l'autre en
    /// fait un vrai TIME_WAIT, de 60 s. En TIME_WAIT : non rejeté, au bord
    /// gauche, un RST l'efface (`tcp_rfc1337` à 0) et un ACK nu la prolonge, sans
    /// réponse ; un SYN non rejeté, plus loin que ce qu'elle a reçu ou d'un
    /// horodatage plus récent, reprend le quadruplet ; tout le reste (un FIN
    /// retransmis...) est réacquitté, et un ACK ou un rejet la prolonge ; un RST
    /// ailleurs, rien.
    pub fn recevoir(&mut self, h: &Tcp, longueur_charge: u32, maintenant: u64) -> Issue {
        let rst = h.drapeaux & tcp::RST != 0;
        let syn = h.drapeaux & tcp::SYN != 0;
        let ack = h.drapeaux & tcp::ACK != 0;
        let fin = h.drapeaux & tcp::FIN != 0;
        let fin_seq = h.seq.wrapping_add(longueur_charge + u32::from(syn) + u32::from(fin));
        let donnees_sans_syn = fin_seq != h.seq && !syn;
        let mut r = Issue::default();
        // Un segment horodaté, l'entrée ayant vu des horodatages.
        let vu = self.ts.and(h.options.horodatage);
        let rejet = match (self.ts, vu) {
            (Some(ts), Some((val, _))) => paws_rejet(&ts, val, rst, maintenant),
            _ => false,
        };
        if self.fin_attente2 {
            if rejet || !dans_la_fenetre(h.seq, fin_seq, self.rcv_nxt, self.rcv_nxt.wrapping_add(self.rcv_wnd)) {
                r.ack = self.ack_hors_fenetre(donnees_sans_syn, maintenant);
                return r;
            }
            if rst {
                r.effacer = true;
                return r;
            }
            if syn && !avant(h.seq, self.rcv_nxt) {
                r.effacer = true;
                r.rst = true;
                return r;
            }
            if !ack || !apres(fin_seq, self.rcv_nxt) || fin_seq == h.seq {
                // Un ACK seul, un vieux segment : rien.
                return r;
            }
            if !fin || fin_seq != self.rcv_nxt.wrapping_add(1) {
                // Des données après une fermeture d'un côté (`TCP_TW_RST`).
                r.effacer = true;
                r.rst = true;
                return r;
            }
            // Le FIN de l'autre : un vrai TIME_WAIT.
            self.fin_attente2 = false;
            self.rcv_nxt = fin_seq;
            if let (Some(ts), Some((val, _))) = (self.ts.as_mut(), vu) {
                self.entree = maintenant;
                ts.retenir(val, maintenant);
            }
            r.prolonger = true;
            r.ack = true;
            return r;
        }
        if !rejet && h.seq == self.rcv_nxt && (h.seq == fin_seq || rst) {
            if rst {
                r.effacer = true;
            } else {
                r.prolonger = true;
            }
            if let (Some(ts), Some((val, _))) = (self.ts.as_mut(), vu) {
                ts.retenir(val, maintenant);
            }
            return r;
        }
        let plus_recent = matches!((self.ts, vu), (Some(ts), Some((val, _))) if (ts.recent.wrapping_sub(val) as i32) < 0);
        if syn && !rst && !ack && !rejet && (apres(h.seq, self.rcv_nxt) || plus_recent) {
            let isn = self.snd_nxt.wrapping_add(65_535 + 2);
            r.reprendre = Some(if isn == 0 { 1 } else { isn });
            return r;
        }
        if !rst {
            r.prolonger = rejet || ack;
            r.ack = self.ack_hors_fenetre(donnees_sans_syn, maintenant);
        }
        r
    }

    /// L'ACK de l'entrée (`tcp_v4_timewait_ack`) : ses numéros, la fenêtre
    /// annoncée, à notre échelle, et les horodatages s'il y a de quoi répondre
    /// (`tcp_v4_send_ack` : seulement si TSecr n'est pas nul).
    pub fn entete_ack(&self, maintenant: u64) -> Tcp {
        let horodatage = self.ts.filter(|t| t.recent != 0).map(|t| (t.valeur(maintenant), t.recent));
        Tcp {
            source: self.port_local,
            destination: self.port_distant,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            drapeaux: tcp::ACK,
            fenetre: (self.rcv_wnd >> self.echelle).min(super::FENETRE_MAX) as u16,
            urgent: 0,
            options: tcp::Options { horodatage, ..tcp::Options::default() },
        }
    }
}
