//! La file de retransmission et la reprise après une perte : le modèle de
//! Linux (`tcp_rtx_queue`, `tcp_clean_rtx_queue`, `tcp_fastretrans_alert`,
//! `tcp_enter_loss`, `tcp_xmit_retransmit_queue`, net/ipv4/tcp_input.c et
//! tcp_output.c), fonction par fonction, pour qu'on puisse lire les deux côte
//! à côte.
//!
//! LA FILE. Chaque segment envoyé et pas encore acquitté y a son entrée : ses
//! numéros, l'heure de son dernier envoi, et ce qu'on sait de lui. Les octets
//! restent dans le tampon d'émission : une entrée ne fait que les désigner.
//! SND.NXT ne recule jamais : un segment se renvoie depuis sa place dans la
//! file, marqué perdu, sans que rien d'autre ne bouge. (Le modèle de BSD
//! recule SND.NXT après un RTO et ré-émet tout de là : pas besoin de liste,
//! mais il renverrait ce que l'autre a déjà dit avoir reçu, et il ne pourrait
//! pas envoyer du neuf après un RTO, ce que demandent SACK et F-RTO.)
//!
//! CE QUI EST EN VOL. `tcp_packets_in_flight` :
//!     packets_out - (sacked_out + lost_out) + retrans_out
//! c'est-à-dire tout ce qui a été envoyé, moins ce qui a quitté le réseau
//! (arrivé hors d'ordre, ou réputé perdu), plus ce qui a été renvoyé. Sans
//! SACK, `sacked_out` compte les ACK dupliqués : chacun dit qu'un segment de
//! plus est arrivé, sans dire lequel (`tcp_add_reno_sack`).
//!
//! LES ÉTATS (`icsk_ca_state`, congestion.rs : `Phase`) ne changent pas ce qui
//! est envoyé par eux-mêmes : un ACK fait son chemin dans `traiter_ack` (le
//! `tcp_ack` de Linux, dans tcp.rs), qui appelle `alerte` s'il a quelque chose
//! d'anormal ; `alerte` marque ce qui est perdu et change d'état ;
//! `controler_congestion` règle ensuite la cwnd ; `emettre` renvoie enfin ce
//! qui est marqué, dans la limite de la cwnd.
//!
//! La mesure du RTT est faite à chaque ACK, par l'heure d'envoi du segment
//! acquitté le plus ancien et jamais renvoyé (Karn : si un segment renvoyé est
//! dans ce que couvre l'ACK, pas de mesure).

use super::congestion::{Phase, TCP_REORDERING};
use super::rtt::RTO_MAX;
use super::sack::{JIFFY, MIN_RTT_FENETRE, en_jiffies, parti_apres};
use super::{Charge, Effets, Etat, Sortant, Tcb, apres, avant, reculer};
use formats::reseau::tcp;

// Les drapeaux d'un ACK (les FLAG_ de net/ipv4/tcp_input.c).
pub(super) const FLAG_DATA: u32 = 0x01;
pub(super) const FLAG_WIN_UPDATE: u32 = 0x02;
pub(super) const FLAG_DATA_ACKED: u32 = 0x04;
pub(super) const FLAG_RETRANS_DATA_ACKED: u32 = 0x08;
pub(super) const FLAG_SYN_ACKED: u32 = 0x10;
pub(super) const FLAG_DATA_SACKED: u32 = 0x20;
pub(super) const FLAG_LOST_RETRANS: u32 = 0x80;
pub(super) const FLAG_ORIG_SACK_ACKED: u32 = 0x200;
pub(super) const FLAG_SND_UNA_ADVANCED: u32 = 0x400;
pub(super) const FLAG_DSACKING_ACK: u32 = 0x800;
pub(super) const FLAG_SET_XMIT_TIMER: u32 = 0x1000;
pub(super) const FLAG_SACK_RENEGING: u32 = 0x2000;
pub(super) const FLAG_NO_CHALLENGE_ACK: u32 = 0x8000;
pub(super) const FLAG_ACK_MAYBE_DELAYED: u32 = 0x10000;
pub(super) const FLAG_DSACK_TLP: u32 = 0x20000;
pub(super) const FLAG_ACKED: u32 = FLAG_DATA_ACKED | FLAG_SYN_ACKED;
pub(super) const FLAG_NOT_DUP: u32 = FLAG_DATA | FLAG_WIN_UPDATE | FLAG_ACKED;
pub(super) const FLAG_CA_ALERT: u32 = FLAG_DATA_SACKED | FLAG_DSACKING_ACK;
pub(super) const FLAG_FORWARD_PROGRESS: u32 = FLAG_ACKED | FLAG_DATA_SACKED;

// Ce qu'on sait d'un segment envoyé (les TCPCB_ de include/net/tcp.h).
/// Réputé perdu (TCPCB_LOST).
pub(super) const PERDU: u8 = 1;
/// Renvoyé, et ce renvoi est encore en vol (TCPCB_SACKED_RETRANS).
pub(super) const EN_RENVOI: u8 = 2;
/// Renvoyé au moins une fois (TCPCB_EVER_RETRANS).
pub(super) const DEJA_RENVOYE: u8 = 4;
/// Arrivé hors d'ordre, dit par SACK (TCPCB_SACKED_ACKED).
pub(super) const SACKE: u8 = 8;
/// Déjà compté dans la mesure du débit (`tx.delivered_mstamp` remis à 0).
const COMPTE: u8 = 16;

/// Un segment envoyé (le `sk_buff` de la `tcp_rtx_queue`, et son `tcp_skb_cb`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Envoye {
    /// Son premier numéro, et celui qui le suit (son FIN compris).
    pub(super) seq: u32,
    pub(super) fin_seq: u32,
    /// L'heure de son dernier envoi (`skb_mstamp_ns`).
    pub(super) envoi: u64,
    pub(super) marques: u8,
    /// Ses drapeaux d'origine : un renvoi les redit (PSH, FIN).
    drapeaux: u8,
    /// Les segments livrés à son dernier envoi (`tx.delivered`).
    livres_tx: u32,
}

/// Ce que les blocs d'un ACK ont appris (`tcp_sacktag_state`), et ce que la
/// mesure du débit en retient (`rate_sample`, seulement `prior_delivered`).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct EtatSack {
    /// Les heures d'envoi du premier et du dernier segment SACKé jamais renvoyé.
    pub premier: Option<u64>,
    pub dernier: Option<u64>,
    /// Le numéro le plus bas arrivé après un plus haut (`reord`).
    pub reord: u32,
    /// Les segments livrés par ces blocs (`sack_delivered`).
    pub livres: u32,
    pub flag: u32,
    /// Les segments livrés à l'envoi du segment acquitté parti le plus récemment.
    pub prior_livres: Option<u32>,
    pub derniere_fin: u32,
}

/// Ce que `emettre` doit renvoyer après un ACK (les REXMIT_ de Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rexmit {
    Rien,
    /// Les segments marqués perdus.
    Perdus,
    /// Des segments neufs, à la façon de F-RTO, sinon les perdus.
    Neuf,
}

/// Ce qu'a donné l'ACK d'un segment (ce que rend `tcp_ack`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResultatAck {
    /// Un ACK normal.
    Traite,
    /// Un vieil ACK (en deçà de SND.UNA) : la suite du segment vaut encore.
    Vieux,
    /// Il acquitte ce qui n'a jamais été envoyé, ou il est bien trop vieux :
    /// le segment s'arrête là.
    Rejete,
}

impl Envoye {
    pub(super) fn neuf(seq: u32, fin_seq: u32, envoi: u64, drapeaux: u8, livres_tx: u32) -> Envoye {
        Envoye { seq, fin_seq, envoi, marques: 0, drapeaux, livres_tx }
    }

    /// Ses octets de données, sans le FIN.
    fn longueur(&self) -> u32 {
        self.fin_seq.wrapping_sub(self.seq) - u32::from(self.drapeaux & tcp::FIN != 0)
    }
}

impl<P: Charge> Tcb<P> {
    /// Les segments encore dans le réseau (`tcp_packets_in_flight`).
    pub(super) fn paquets_en_vol(&self) -> u32 {
        (self.file.len() as u32).saturating_sub(self.sacked_out + self.lost_out) + self.retrans_out
    }

    /// CWR ou la reprise rapide : la cwnd est en train de réduire
    /// (`tcp_in_cwnd_reduction`).
    pub(super) fn en_reduction(&self) -> bool {
        self.cc.en_reduction()
    }

    // --- L'ACK et la file ---

    /// Retire de la file ce que SND.UNA couvre (`tcp_clean_rtx_queue`), mesure
    /// le RTT, et compte ce qui est arrivé. Un segment acquitté en partie
    /// reste : sa tête sera retirée s'il faut le renvoyer (`tcp_trim_head`).
    pub(super) fn nettoyer_file(&mut self, fack_avant: u32, una_avant: u32, etat: &mut EtatSack, maintenant: u64) -> u32 {
        let mut flag = 0;
        let mut premier = None;
        let mut dernier = None;
        let mut acquittes = 0;
        let sacked_avant = self.sacked_out;
        let mut reord = self.snd_nxt;
        while let Some(e) = self.file.front().copied() {
            if apres(e.fin_seq, self.snd_una) {
                break;
            }
            if e.marques & (EN_RENVOI | DEJA_RENVOYE) != 0 {
                if e.marques & EN_RENVOI != 0 {
                    self.retrans_out -= 1;
                }
                flag |= FLAG_RETRANS_DATA_ACKED;
            } else if e.marques & SACKE == 0 {
                dernier = Some(e.envoi);
                premier.get_or_insert(e.envoi);
                if avant(e.seq, reord) {
                    reord = e.seq;
                }
                if !apres(e.fin_seq, self.high_seq) {
                    flag |= FLAG_ORIG_SACK_ACKED;
                }
            }
            if e.marques & SACKE != 0 {
                self.sacked_out -= 1;
            } else if self.sack_ok {
                self.livres += 1;
                if !self.renvoi_inutile(&e) {
                    self.rack_avancer(e.marques, e.fin_seq, e.envoi, maintenant);
                }
            }
            if e.marques & PERDU != 0 {
                self.lost_out -= 1;
            }
            acquittes += 1;
            self.taux_segment_livre(0, etat);
            flag |= FLAG_DATA_ACKED;
            self.file.pop_front();
            if self.indice_renvoi == Some(e.seq) {
                self.indice_renvoi = None;
            }
        }
        if self.file.front().is_some_and(|e| e.marques & SACKE != 0) {
            flag |= FLAG_SACK_RENEGING;
        }
        // Karn : un segment renvoyé dans ce qui est acquitté, pas de mesure.
        let mut seq_rtt = None;
        let mut ca_rtt = None;
        if flag & FLAG_RETRANS_DATA_ACKED == 0 && let Some(p) = premier {
            seq_rtt = Some(maintenant.saturating_sub(p));
            ca_rtt = dernier.map(|d: u64| maintenant.saturating_sub(d));
            // Sans doute un ACK retardé : un petit segment seul, sans rien
            // d'anormal. Il ne dit rien du chemin.
            if acquittes == 1
                && sacked_avant == 0
                && self.snd_una.wrapping_sub(una_avant) < self.mss as u32
                && etat.prior_livres.is_some_and(|p| p.wrapping_add(1) == self.livres)
                && (flag | etat.flag) & (FLAG_CA_ALERT | FLAG_SYN_ACKED) == 0
            {
                flag |= FLAG_ACK_MAYBE_DELAYED;
            }
        }
        let sack_rtt = etat.premier.map(|p| maintenant.saturating_sub(p));
        if let Some(d) = etat.dernier {
            ca_rtt = Some(maintenant.saturating_sub(d));
        }
        let (mesure, rtt_dernier) = self.mettre_a_jour_rtt(flag, seq_rtt, sack_rtt, ca_rtt, maintenant);
        if flag & FLAG_ACKED != 0 {
            flag |= FLAG_SET_XMIT_TIMER;
            if self.sack_ok {
                // Un trou comblé par un segment jamais renvoyé : du réordonnancement.
                if avant(reord, fack_avant) {
                    self.verifier_reordonnancement(reord);
                }
            } else {
                self.retirer_reno_sacks(acquittes);
                // Sans SACK, un ACK cumulatif qui couvre un segment renvoyé ne dit
                // pas si l'original y est pour quelque chose.
                if flag & FLAG_RETRANS_DATA_ACKED != 0 {
                    flag &= !FLAG_ORIG_SACK_ACKED;
                }
            }
        } else if let (Some(tete), true, Some(s)) = (self.file.front(), mesure, sack_rtt)
            && s > maintenant.saturating_sub(tete.envoi)
        {
            // Pas de réarmement si la mesure vient de données parties après le
            // dernier envoi de la tête : le RTO reculerait sans fin pendant la reprise.
            flag |= FLAG_SET_XMIT_TIMER;
        }
        self.cc.segments_acquittes(rtt_dernier, self.snd_una, self.snd_nxt, maintenant);
        flag
    }

    /// `tcp_skb_spurious_retrans` : TSecr dit que l'ACK répond à un envoi antérieur
    /// à ce renvoi.
    fn renvoi_inutile(&self, e: &Envoye) -> bool {
        e.marques & (EN_RENVOI | DEJA_RENVOYE) != 0
            && self.ts_recu.is_some_and(|(_, ecr)| ecr != 0 && avant(ecr, super::horloge_ts(e.envoi)))
    }

    /// `tcp_rate_skb_delivered`, réduit à ce que lisent RACK et la détection des
    /// ACK retardés : les segments livrés à l'envoi du segment parti le plus
    /// récemment parmi ceux que cet ACK couvre.
    pub(super) fn taux_segment_livre(&mut self, i: usize, etat: &mut EtatSack) {
        let e = self.file[i];
        if e.marques & COMPTE != 0 {
            return;
        }
        if etat.prior_livres.is_none() || parti_apres(e.envoi, self.tx_acquitte, e.fin_seq, etat.derniere_fin) {
            etat.prior_livres = Some(e.livres_tx);
            etat.derniere_fin = e.fin_seq;
            self.tx_acquitte = e.envoi;
        }
        self.file[i].marques |= COMPTE;
    }

    /// Une mesure du RTT (`tcp_ack_update_rtt`) : par l'heure d'envoi, par SACK,
    /// ou à défaut par TSecr si l'ACK acquitte quelque chose ; pas avant : une
    /// mesure en ms ferait monter à 1 ms le SRTT d'une boucle de 30 µs. Le RTO
    /// repart de l'estimateur, sans recul (RFC 6298 5.7 : seulement sur une vraie
    /// mesure) ; `min_rtt` suit la mesure du dernier segment (`tcp_update_rtt_min`).
    /// Rend si l'estimateur a eu une mesure, et le RTT du dernier segment
    /// (`rs->rtt_us`), que lit le contrôle de congestion.
    pub(super) fn mettre_a_jour_rtt(&mut self, flag: u32, seq: Option<u64>, sack: Option<u64>, ca: Option<u64>, maintenant: u64) -> (bool, Option<u64>) {
        let mut seq = seq.or(sack);
        let mut ca = ca;
        if seq.is_none() && flag & FLAG_ACKED != 0 && let Some(m) = self.rtt_par_tsecr(maintenant, 1) {
            seq = Some(m);
            ca = Some(m);
        }
        let Some(m) = seq else { return (false, ca) };
        let c = ca.unwrap_or(m);
        if !(flag & FLAG_ACK_MAYBE_DELAYED != 0 && c > self.min_rtt.valeur()) {
            // Une mesure de moins d'une µs compte pour un jiffy (`rtt_us ?:
            // jiffies_to_usecs(1)`).
            self.min_rtt.mesure(MIN_RTT_FENETRE, maintenant, if c < 1000 { JIFFY } else { c });
        }
        self.rtt.echantillon(m, self.snd_una, self.snd_nxt);
        self.rto = self.rtt.rto();
        self.recul = 0;
        (true, Some(c))
    }

    // --- Les ACK dupliqués, faute de SACK ---

    /// `sacked_out` + un trou au moins ne dépassent pas ce qui est en file
    /// (`tcp_limit_reno_sacked`) ; rend vrai s'il a fallu le réduire.
    pub(super) fn limiter_reno_sacked(&mut self) -> bool {
        let packets_out = self.file.len() as u32;
        let trous = self.lost_out.max(1).min(packets_out);
        if self.sacked_out + trous > packets_out {
            self.sacked_out = packets_out - trous;
            return true;
        }
        false
    }

    /// Plus d'ACK dupliqués que de segments en vol : c'est du désordre, pas une
    /// perte (`tcp_check_reno_reordering`).
    fn verifier_reordonnancement_reno(&mut self, en_plus: u32) {
        if !self.limiter_reno_sacked() {
            return;
        }
        self.reordering = (self.file.len() as u32 + en_plus).min(super::TCP_MAX_REORDERING);
        self.reord_seen += 1;
    }

    /// Un ACK dupliqué de plus (`tcp_add_reno_sack`).
    fn ajouter_reno_sack(&mut self, num_dupack: u32) {
        if num_dupack > 0 {
            let avant = self.sacked_out;
            self.sacked_out += num_dupack;
            self.verifier_reordonnancement_reno(0);
            self.livres += self.sacked_out.saturating_sub(avant);
        }
    }

    /// Un ACK cumulatif : un segment comble le trou, les autres consomment des
    /// ACK dupliqués (`tcp_remove_reno_sacks`).
    fn retirer_reno_sacks(&mut self, acquittes: u32) {
        if acquittes > 0 {
            self.livres += acquittes.saturating_sub(self.sacked_out).max(1);
            if acquittes - 1 >= self.sacked_out {
                self.sacked_out = 0;
            } else {
                self.sacked_out -= acquittes - 1;
            }
        }
        self.verifier_reordonnancement_reno(acquittes);
    }

    // --- La perte ---

    /// Un segment est réputé perdu (`tcp_mark_skb_lost`), sauf s'il est dit
    /// arrivé ; déjà marqué et renvoyé : c'est son renvoi qui est perdu.
    pub(super) fn marquer_perdu(&mut self, i: usize) {
        if self.file[i].marques & SACKE != 0 {
            return;
        }
        let seq = self.file[i].seq;
        // Le prochain à renvoyer ne peut pas être plus loin que lui
        // (`tcp_verify_retransmit_hint`).
        let plus_tot = self.indice_renvoi.is_some_and(|h| avant(seq, h));
        if (self.indice_renvoi.is_none() && self.retrans_out >= self.lost_out) || plus_tot {
            self.indice_renvoi = Some(seq);
        }
        let m = self.file[i].marques;
        if m & PERDU != 0 {
            if m & EN_RENVOI != 0 {
                self.file[i].marques &= !EN_RENVOI;
                self.retrans_out -= 1;
                self.perdus += 1;
            }
        } else {
            self.lost_out += 1;
            self.file[i].marques |= PERDU;
            self.perdus += 1;
        }
    }

    /// NewReno (`tcp_newreno_mark_lost`) : au troisième ACK dupliqué, la tête ;
    /// pendant la reprise, à chaque ACK partiel, la nouvelle tête.
    fn marquer_tete_perdue(&mut self, una_avance: bool) {
        let declenche = (self.cc.phase < Phase::Reprise && self.sacked_out >= self.reordering) || (self.cc.phase == Phase::Reprise && una_avance);
        if declenche && let Some(e) = self.file.front() && e.marques & PERDU == 0 {
            self.marquer_perdu(0);
        }
    }

    /// `tcp_identify_packet_loss` : NewReno sans SACK, RACK avec.
    fn identifier_pertes(&mut self, flag: &mut u32, maintenant: u64) {
        if self.file.is_empty() {
            return;
        }
        if !self.sack_ok {
            self.marquer_tete_perdue(*flag & FLAG_SND_UNA_ADVANCED != 0);
        } else {
            let renvois = self.retrans_out;
            if self.rack_marquer(maintenant) {
                *flag &= !FLAG_SET_XMIT_TIMER;
            }
            if renvois > self.retrans_out {
                *flag |= FLAG_LOST_RETRANS;
            }
        }
    }

    /// `tcp_init_undo` : d'où partira l'annulation.
    fn poser_annulation(&mut self) {
        self.undo_marker = Some(self.snd_una);
        self.undo_retrans = self.retrans_out as i32;
        if self.tlp_high_seq.is_some() && self.tlp_renvoi {
            self.undo_retrans += 1;
        }
        if self.undo_retrans == 0 {
            self.undo_retrans = -1;
        }
    }

    /// Un RTO : tout ce qui est en vol est réputé perdu (`tcp_enter_loss`,
    /// `tcp_timeout_mark_lost`). Le seuil tombe, une seule fois par fenêtre (pas
    /// si l'on était déjà en reprise ou en perte pour les mêmes données, sauf à
    /// la première retransmission de la perte).
    pub(super) fn entrer_perte(&mut self, maintenant: u64) {
        let nouvelle_reprise = self.cc.phase < Phase::Reprise;
        // `tcp_timeout_mark_lost` : la tête marquée SACKée veut dire que l'autre a
        // oublié ce qu'il avait dit recevoir (« reneging ») : tout est oublié.
        // Sinon, les SACK restent, et ce qui vient de partir (moins d'un RTT de
        // RACK) n'est pas encore perdu.
        let renie = self.file.front().is_some_and(|e| e.marques & SACKE != 0);
        if renie {
            self.sacked_out = 0;
            self.sack_renie = true;
        } else if !self.sack_ok {
            self.sacked_out = 0;
        }
        for i in 0..self.file.len() {
            if renie {
                self.file[i].marques &= !SACKE;
            } else if i != 0 && self.rack_restant(self.file[i].envoi, 0, maintenant) > 0 {
                continue;
            }
            self.marquer_perdu(i);
        }
        self.indice_renvoi = None;
        let phase = self.cc.phase;
        if phase <= Phase::Desordre || !apres(self.high_seq, self.snd_una) || (phase == Phase::Perte && self.retransmissions == 0) {
            self.prior_ssthresh = self.cc.ssthresh_courant();
            self.prior_cwnd = self.cc.cwnd;
            self.cc.ssthresh = self.cc.seuil();
            self.poser_annulation();
        }
        self.cc.cwnd = self.paquets_en_vol() + 1;
        self.cc.remettre_compte();
        self.cc.poser_instant(maintenant);
        // Un RTO en désordre après beaucoup d'ACK dupliqués : le degré de
        // réordonnancement estimé était trop grand.
        if phase <= Phase::Desordre && self.sacked_out >= TCP_REORDERING {
            self.reordering = self.reordering.min(TCP_REORDERING);
        }
        self.changer_phase(Phase::Perte);
        self.high_seq = self.snd_nxt;
        self.tlp_high_seq = None;
        // F-RTO (RFC 5682, 3.1, étape 1) : seulement hors d'une autre reprise,
        // ou pour des RTO répétés du même SND.UNA (3.2). (`tcp_frto` vaut 2 sur
        // l'hôte ; toute valeur non nulle dit la même chose dans 6.18.)
        self.frto = nouvelle_reprise || self.retransmissions > 0;
    }

    /// Une réduction de la cwnd commence (`tcp_init_cwnd_reduction`).
    pub(super) fn commencer_reduction(&mut self) {
        self.high_seq = self.snd_nxt;
        self.tlp_high_seq = None;
        self.cc.remettre_compte();
        self.prior_cwnd = self.cc.cwnd;
        self.prr_livres = 0;
        self.prr_sortis = 0;
        self.cc.ssthresh = self.cc.seuil();
    }

    /// La réduction est finie : la cwnd au seuil (`tcp_end_cwnd_reduction`),
    /// sauf si elle a été annulée.
    pub(super) fn finir_reduction(&mut self) {
        if self.cc.ssthresh < super::congestion::SSTHRESH_INFINI && (self.cc.phase == Phase::Reduction || self.undo_marker.is_some()) {
            self.cc.cwnd = self.cc.ssthresh;
            self.cc.poser_instant(self.heure);
        }
    }

    /// La reprise rapide commence (`tcp_enter_recovery`).
    pub(super) fn entrer_reprise(&mut self) {
        self.nettoyer_retrans_stamp();
        self.prior_ssthresh = 0;
        self.poser_annulation();
        if !self.en_reduction() {
            self.prior_ssthresh = self.cc.ssthresh_courant();
            self.commencer_reduction();
        }
        self.changer_phase(Phase::Reprise);
    }

    /// Reste-t-il un renvoi dans la fenêtre (`tcp_any_retrans_done`) ?
    fn renvoi_fait(&self) -> bool {
        self.retrans_out > 0 || self.file.front().is_some_and(|e| e.marques & DEJA_RENVOYE != 0)
    }

    /// `tcp_retrans_stamp_cleanup` : la reprise est finie, plus rien de renvoyé
    /// en vol : le prochain épisode compte son temps à partir de lui.
    fn nettoyer_retrans_stamp(&mut self) {
        if !self.renvoi_fait() {
            self.retrans_stamp = 0;
        }
    }

    /// Sans SACK, l'état reste jusqu'à ce qu'un ACK passe `high_seq`
    /// (`tcp_is_non_sack_preventing_reopen`, RFC 2582 : sinon, les ACK
    /// dupliqués de nos propres renvois déclencheraient une fausse
    /// retransmission rapide).
    fn reno_empeche_de_rouvrir(&mut self) -> bool {
        if self.snd_una == self.high_seq && !self.sack_ok {
            self.nettoyer_retrans_stamp();
            return true;
        }
        false
    }

    // --- L'annulation ---

    /// TSecr répond-il à un envoi antérieur à `quand` (`tcp_tsopt_ecr_before`) ?
    fn tsecr_avant(&self, quand: u64) -> bool {
        self.ts_recu.is_some_and(|(_, ecr)| ecr != 0 && avant(ecr, super::horloge_ts(quand)))
    }

    /// Rien n'a été renvoyé, ou l'écho dit que ce qui arrive précède le premier
    /// renvoi : le paquet n'était que retardé (`tcp_packet_delayed`).
    fn paquet_retarde(&self) -> bool {
        if self.retrans_stamp != 0 {
            return self.tsecr_avant(self.retrans_stamp);
        }
        // `retrans_stamp` nul, ce qui veut dire d'ordinaire : rien de renvoyé ;
        // sauf deux cas où il a été effacé après un renvoi.
        if !self.sack_ok && !avant(self.snd_una, self.high_seq) {
            return false;
        }
        self.etat != Etat::SynEnvoye
    }

    /// `tcp_may_undo` : il y a un épisode à annuler, et tous ses renvois sont
    /// démentis par des D-SACK, ou c'était un retard.
    fn annulation_possible(&self) -> bool {
        self.undo_marker.is_some() && (self.undo_retrans == 0 || self.paquet_retarde())
    }

    /// La réduction est défaite (`tcp_undo_cwnd_reduction`) : la cwnd et le seuil
    /// d'avant ; `sans_pertes` : ce qui était marqué perdu ne l'est plus. Le recul
    /// du RTO, lui, reste jusqu'à la prochaine vraie mesure.
    fn annuler_reduction(&mut self, sans_pertes: bool) {
        if sans_pertes {
            for e in self.file.iter_mut() {
                e.marques &= !PERDU;
            }
            self.lost_out = 0;
            self.indice_renvoi = None;
        }
        if self.prior_ssthresh != 0 {
            self.cc.cwnd = self.cc.annuler(self.prior_cwnd, self.heure);
            if self.prior_ssthresh > self.cc.ssthresh {
                self.cc.ssthresh = self.prior_ssthresh;
            }
        }
        self.cc.poser_instant(self.heure);
        self.undo_marker = None;
        self.rack.avance = true;
    }

    /// La fin d'une reprise (`tcp_try_undo_recovery`) : défaite, si elle l'a été
    /// pour rien. Rend vrai si l'état doit rester.
    fn fin_de_reprise(&mut self) -> bool {
        if self.annulation_possible() {
            self.annuler_reduction(false);
        } else {
            self.rack.persiste = self.rack.persiste.saturating_sub(1);
        }
        if self.reno_empeche_de_rouvrir() {
            return true;
        }
        self.changer_phase(Phase::Ouverte);
        self.sack_renie = false;
        false
    }

    /// Les D-SACK ont démenti tous les renvois (`tcp_try_undo_dsack`).
    fn annuler_par_dsack(&mut self) -> bool {
        if self.undo_marker.is_some() && self.undo_retrans == 0 {
            self.rack.persiste = (self.rack.persiste + 1).min(super::sack::RACK_PERSISTE);
            self.annuler_reduction(false);
            return true;
        }
        false
    }

    /// Pendant une perte, après un ACK partiel ou par F-RTO (`tcp_try_undo_loss`).
    fn annuler_la_perte(&mut self, par_frto: bool) -> bool {
        if par_frto || self.annulation_possible() {
            self.annuler_reduction(true);
            self.retransmissions = 0;
            if self.reno_empeche_de_rouvrir() {
                return true;
            }
            if par_frto || self.sack_ok {
                self.changer_phase(Phase::Ouverte);
                self.sack_renie = false;
            }
            return true;
        }
        false
    }

    /// Pendant une reprise rapide, après un ACK partiel (`tcp_try_undo_partial`) :
    /// le trou a été comblé par le paquet retardé, pas par son renvoi : c'est du
    /// réordonnancement, et il est plus grand qu'on ne le croyait. Rend vrai s'il
    /// reste des renvois en vol : on continue d'envoyer, sans rien marquer de plus.
    fn annuler_partiel(&mut self, una_avant: u32) -> bool {
        if self.undo_marker.is_some() && self.paquet_retarde() {
            self.verifier_reordonnancement(una_avant);
            if self.retrans_out > 0 {
                return true;
            }
            self.nettoyer_retrans_stamp();
            self.annuler_reduction(true);
            self.rester_ouverte();
        }
        false
    }

    /// `tcp_try_undo_spurious_syn` : le SYN (ou le SYN-ACK) a été renvoyé, mais
    /// l'écho est celui du premier : le renvoi était inutile.
    pub(super) fn syn_renvoye_pour_rien(&mut self) {
        if self.undo_marker.is_some()
            && self.retrans_stamp != 0
            && self.ts_recu.is_some_and(|(_, ecr)| ecr == super::horloge_ts(self.retrans_stamp))
        {
            self.undo_marker = None;
        }
    }

    /// `tcp_try_keep_open`.
    pub(super) fn rester_ouverte(&mut self) {
        let etat = if self.sacked_out + self.lost_out > 0 || self.renvoi_fait() { Phase::Desordre } else { Phase::Ouverte };
        if self.cc.phase != etat {
            self.changer_phase(etat);
            self.high_seq = self.snd_nxt;
        }
    }

    /// `tcp_try_to_open`.
    fn essayer_d_ouvrir(&mut self) {
        self.nettoyer_retrans_stamp();
        if self.cc.phase != Phase::Reduction {
            self.rester_ouverte();
        }
    }

    /// Un ACK dans l'état de perte (`tcp_process_loss`) : la perte était fausse, ou
    /// est réparée, ou on continue. F-RTO (RFC 5682, la variante SACK, qui vaut
    /// aussi sans) : après le renvoi de la tête, si l'ACK avance sans tout couvrir,
    /// DEUX SEGMENTS NEUFS plutôt que de tout renvoyer (étape 2.b) ; si ce qui revient
    /// ensuite acquitte des segments jamais renvoyés, le RTO s'est déclenché pour
    /// rien : tout est annulé (3.b) ; un ACK dupliqué ou un SACK : la perte était
    /// vraie (3.a). Le RTO pour rien vient d'un chemin dont le délai a sauté ; sans
    /// F-RTO, tout serait renvoyé, et tous ces doublons feraient croire à une perte.
    fn traiter_perte(&mut self, flag: u32, num_dupack: u32) {
        let repare = !avant(self.snd_una, self.high_seq);
        if flag & FLAG_SND_UNA_ADVANCED != 0 && self.annuler_la_perte(false) {
            return;
        }
        if self.frto {
            if flag & FLAG_ORIG_SACK_ACKED != 0 && self.annuler_la_perte(true) {
                return;
            }
            if apres(self.snd_nxt, self.high_seq) {
                if flag & FLAG_DATA_SACKED != 0 || num_dupack > 0 {
                    self.frto = false;
                }
            } else if flag & FLAG_SND_UNA_ADVANCED != 0 && !repare {
                self.high_seq = self.snd_nxt;
                if self.prochain_segment().is_some() && apres(self.snd_una.wrapping_add(self.snd_wnd), self.snd_nxt) {
                    self.rexmit = Rexmit::Neuf;
                    return;
                }
                self.frto = false;
            }
        }
        if repare {
            self.fin_de_reprise();
            return;
        }
        if !self.sack_ok {
            // Un ACK dupliqué : les segments neufs de F-RTO sont arrivés ; moins
            // en vol, de quoi renvoyer.
            if apres(self.snd_nxt, self.high_seq) && num_dupack > 0 {
                self.ajouter_reno_sack(num_dupack);
            } else if flag & FLAG_SND_UNA_ADVANCED != 0 {
                self.sacked_out = 0;
            }
        }
        self.rexmit = Rexmit::Perdus;
    }

    /// Un ACK anormal, ou n'importe quel ACK hors de l'état ouvert : ce qui
    /// est perdu, et ce que devient l'état (`tcp_fastretrans_alert`).
    pub(super) fn alerte(&mut self, una_avant: u32, num_dupack: u32, flag: &mut u32, maintenant: u64) {
        if self.file.is_empty() && self.sacked_out > 0 {
            self.sacked_out = 0;
        }
        // Le bord gauche tombe sur du SACKé : l'autre a peut-être oublié. Un peu
        // de temps (la moitié du RTT, au moins 10 ms) pour qu'un autre ACK le
        // démente (`tcp_check_sack_reneging`) ; au RTO, tout sera oublié.
        if *flag & FLAG_SACK_RENEGING != 0 && *flag & FLAG_SND_UNA_ADVANCED != 0 {
            let d = en_jiffies(self.rtt.srtt() / 2).max(en_jiffies(10_000_000));
            self.armer_xmit(super::Minuteur::Retransmission, d, maintenant);
            *flag &= !FLAG_SET_XMIT_TIMER;
            return;
        }
        // Les conditions de sortie : `high_seq` est acquitté.
        if self.cc.phase == Phase::Ouverte {
            self.retrans_stamp = 0;
        } else if !avant(self.snd_una, self.high_seq) {
            match self.cc.phase {
                Phase::Reduction => {
                    if self.snd_una != self.high_seq {
                        self.finir_reduction();
                        self.changer_phase(Phase::Ouverte);
                    }
                }
                Phase::Reprise => {
                    if !self.sack_ok {
                        self.sacked_out = 0;
                    }
                    if self.fin_de_reprise() {
                        return;
                    }
                    self.finir_reduction();
                }
                _ => {}
            }
        }
        match self.cc.phase {
            Phase::Reprise => {
                if *flag & FLAG_SND_UNA_ADVANCED == 0 {
                    if !self.sack_ok {
                        self.ajouter_reno_sack(num_dupack);
                    }
                } else if self.annuler_partiel(una_avant) {
                    return;
                }
                if self.annuler_par_dsack() {
                    self.essayer_d_ouvrir();
                }
                self.identifier_pertes(flag, maintenant);
                // L'annulation a défait la reprise ; si une perte est là malgré
                // tout (du désordre, puis une vraie), une nouvelle reprise.
                if self.cc.phase != Phase::Reprise {
                    if self.lost_out == 0 {
                        return;
                    }
                    self.entrer_reprise();
                }
            }
            Phase::Perte => {
                self.traiter_perte(*flag, num_dupack);
                self.identifier_pertes(flag, maintenant);
                if !(self.cc.phase == Phase::Ouverte || *flag & FLAG_LOST_RETRANS != 0) {
                    return;
                }
                self.alerte_ouverte(num_dupack, flag, maintenant);
                return;
            }
            _ => {
                self.alerte_ouverte(num_dupack, flag, maintenant);
                return;
            }
        }
        self.rexmit = Rexmit::Perdus;
    }

    /// Le cas général de `tcp_fastretrans_alert`.
    fn alerte_ouverte(&mut self, num_dupack: u32, flag: &mut u32, maintenant: u64) {
        if !self.sack_ok {
            if *flag & FLAG_SND_UNA_ADVANCED != 0 {
                self.sacked_out = 0;
            }
            self.ajouter_reno_sack(num_dupack);
        }
        if self.cc.phase <= Phase::Desordre {
            self.annuler_par_dsack();
        }
        self.identifier_pertes(flag, maintenant);
        if self.lost_out == 0 {
            self.essayer_d_ouvrir();
            return;
        }
        self.entrer_reprise();
        self.rexmit = Rexmit::Perdus;
    }

    /// L'état de la reprise change (`tcp_set_ca_state`).
    pub(super) fn changer_phase(&mut self, phase: Phase) {
        self.cc.changer_phase(phase, self.snd_nxt, self.heure);
    }

    /// Le débit calculé, à chaque ACK (`tcp_update_pacing_rate`).
    pub(super) fn maj_pacing(&mut self, mss: u32) {
        self.cc.maj_pacing(mss, self.file.len() as u32, self.rtt.srtt8_us());
    }

    /// La cwnd après un ACK (`tcp_cong_control`) : elle réduit si l'état le
    /// veut, grandit sinon, si l'ACK a acquitté des données ; puis le débit calculé.
    pub(super) fn controler_congestion(&mut self, livres: u32, perdus: u32, flag: u32, maintenant: u64) {
        if self.en_reduction() {
            self.reduire_cwnd(livres, perdus, flag);
        } else {
            // `tcp_may_raise_cwnd` : si l'ACK couvre des données ; un fort
            // réordonnancement estimé rend moins prudent.
            let peut = if self.reordering > TCP_REORDERING { flag & FLAG_FORWARD_PROGRESS != 0 } else { flag & FLAG_DATA_ACKED != 0 };
            if peut {
                self.cc.croitre(livres, maintenant);
            }
        }
        self.maj_pacing(self.mss_borne());
    }

    /// PRR (`tcp_cwnd_reduction`, RFC 6937) : `livres` segments de plus ont
    /// quitté le réseau ; la cwnd devient ce qui est en vol plus ce qu'on a le
    /// droit d'envoyer. Tant qu'il y a plus en vol que le seuil, on envoie en
    /// proportion de ce qui arrive (seuil / cwnd d'avant : à peu près un segment
    /// pour deux reçus) ; en dessous, on remonte vers le seuil, sans dépasser ce
    /// qui arrive plus un (la variante « SSRB » de la RFC, celle de Linux).
    /// Toujours au moins un segment au début de la reprise : la retransmission
    /// rapide elle-même.
    pub(super) fn reduire_cwnd(&mut self, livres: u32, perdus: u32, flag: u32) {
        if livres == 0 || self.prior_cwnd == 0 {
            return;
        }
        let en_vol = self.paquets_en_vol();
        let delta = self.cc.ssthresh as i64 - en_vol as i64;
        self.prr_livres += livres;
        let mut envoyer = if delta < 0 {
            let dividende = self.cc.ssthresh as u64 * self.prr_livres as u64 + self.prior_cwnd as u64 - 1;
            (dividende / self.prior_cwnd as u64) as i64 - self.prr_sortis as i64
        } else {
            let mut s = (self.prr_livres as i64 - self.prr_sortis as i64).max(livres as i64);
            if flag & FLAG_SND_UNA_ADVANCED != 0 && perdus == 0 {
                s += 1;
            }
            s.min(delta)
        };
        envoyer = envoyer.max(if self.prr_sortis > 0 { 0 } else { 1 });
        self.cc.cwnd = (en_vol as i64 + envoyer).max(1) as u32;
    }

    // --- Le renvoi ---

    /// La place de `seq` dans la file : elle est triée par numéro.
    pub(super) fn indice_de(&self, seq: u32) -> usize {
        self.file.partition_point(|e| avant(e.seq, seq))
    }

    /// La place de l'entrée qui contient `seq`, ou de la suivante
    /// (`tcp_sacktag_bsearch`).
    pub(super) fn indice_avant(&self, seq: u32) -> usize {
        self.file.partition_point(|e| !apres(e.fin_seq, seq))
    }

    /// Coupe l'entrée `i` après `n` octets (`tcp_fragment`) : la seconde moitié
    /// prend ses marques et ses drapeaux d'origine, la première perd PSH et FIN.
    /// Faux si la mémoire manque.
    fn couper(&mut self, i: usize, n: u32) -> bool {
        if self.file.try_reserve(1).is_err() {
            return false;
        }
        let e = self.file[i];
        let suite = Envoye { seq: e.seq.wrapping_add(n), ..e };
        self.file[i].fin_seq = suite.seq;
        self.file[i].drapeaux &= !(tcp::FIN | tcp::PSH);
        if e.marques & EN_RENVOI != 0 {
            self.retrans_out += 1;
        }
        if e.marques & PERDU != 0 {
            self.lost_out += 1;
        }
        self.file.insert(i + 1, suite);
        // Sa place dans l'ordre d'envoi : juste après l'autre moitié.
        if let Some(k) = self.tri.iter().position(|&x| x == (e.seq, e.envoi))
            && self.tri.try_reserve(1).is_ok()
        {
            self.tri.insert(k + 1, (suite.seq, suite.envoi));
        }
        true
    }

    /// Accole à l'entrée `i` les suivantes, tant qu'elles tiennent dans `place`
    /// octets (`tcp_retrans_try_collapse`) : renvoyer une série de petits
    /// segments en un seul coûte moins au réseau.
    fn accoler(&mut self, i: usize, mut place: i64) {
        place -= self.file[i].longueur() as i64;
        while let Some(s) = self.file.get(i + 1).copied() {
            place -= s.longueur() as i64;
            if place < 0 || apres(s.fin_seq, self.snd_una.wrapping_add(self.snd_wnd)) || self.file[i].drapeaux & tcp::FIN != 0 || s.marques & SACKE != 0 {
                break;
            }
            if self.indice_renvoi == Some(s.seq) {
                self.indice_renvoi = Some(self.file[i].seq);
            }
            let e = &mut self.file[i];
            e.fin_seq = s.fin_seq;
            e.drapeaux |= s.drapeaux;
            e.marques |= s.marques & DEJA_RENVOYE;
            if s.marques & EN_RENVOI != 0 {
                self.retrans_out -= 1;
            }
            if s.marques & PERDU != 0 {
                self.lost_out -= 1;
            }
            // Sans SACK, `sacked_out` compte des segments arrivés : un de moins dans la file, un
            // de moins là (`tcp_adjust_pcount` : « Reno case is special »).
            if !self.sack_ok {
                self.sacked_out = self.sacked_out.saturating_sub(1);
            }
            self.file.remove(i + 1);
        }
    }

    /// Renvoie l'entrée `i` (`__tcp_retransmit_skb`). Coupée à ce que laisse la
    /// fenêtre de l'autre ; une fenêtre fermée n'arrête que ce qui n'est pas la
    /// tête : la tête part entière, et sert de sonde (sinon une fenêtre réduite à
    /// rien sur des données en vol bloquerait tout). Rend faux si rien n'a pu
    /// partir.
    pub(super) fn envoyer_entree(&mut self, i: usize, maintenant: u64, sortir: &mut impl FnMut(Sortant)) -> bool {
        // Sa tête a pu être acquittée depuis (`tcp_trim_head`).
        if avant(self.file[i].seq, self.snd_una) {
            self.file[i].seq = self.snd_una;
        }
        let e = self.file[i];
        let mss = self.mss_courant() as i64;
        let mut place = self.snd_una.wrapping_add(self.snd_wnd).wrapping_sub(e.seq) as i32 as i64;
        if place <= 0 {
            if e.seq != self.snd_una {
                return false;
            }
            place = mss;
        }
        let mut n = mss;
        if n > place {
            n = place - place % mss;
            if n == 0 {
                n = place;
            }
        }
        if e.longueur() as i64 > n {
            if !self.couper(i, n as u32) {
                return false;
            }
        } else if (e.longueur() as i64) < place.min(mss) {
            self.accoler(i, place.min(mss));
        }
        let e = self.file[i];
        self.total_retrans += 1;
        let debut = e.seq.wrapping_sub(self.seq_envoi) as usize;
        let h = self.entete(e.seq, e.drapeaux);
        sortir(Sortant { entete: h, debut, longueur: e.longueur() as usize });
        self.file[i].envoi = maintenant;
        self.file[i].marques = (self.file[i].marques | DEJA_RENVOYE) & !COMPTE;
        self.file[i].livres_tx = self.livres;
        self.tri_ajouter(e.seq, maintenant);
        // L'ACK d'abord : sortir du mode rapide remet `ato` au plus bas, ce que lit le test du
        // ping-pong (`__tcp_transmit_skb`).
        self.ack_envoye();
        if e.longueur() > 0 {
            self.segment_de_donnees_parti(maintenant);
        }
        true
    }

    /// `tcp_retransmit_skb` : l'entrée `i` part, marquée renvoyée ; le temps
    /// du premier renvoi est retenu (`retrans_stamp` : les abandons le lisent).
    fn renvoyer(&mut self, i: usize, maintenant: u64, sortir: &mut impl FnMut(Sortant)) -> bool {
        let ok = self.envoyer_entree(i, maintenant, sortir);
        if ok {
            // Déjà marqué : une annulation a pu retirer sa perte en lui laissant son
            // renvoi, et le RTO le renvoie encore. Linux le compte alors deux fois
            // (« retrans_out leaked », dit son journal de débogage) ; pas nous.
            if self.file[i].marques & EN_RENVOI == 0 {
                self.retrans_out += 1;
            }
            self.file[i].marques |= EN_RENVOI;
        }
        if self.retrans_stamp == 0 {
            self.retrans_stamp = self.file[i].envoi;
        }
        if self.undo_retrans < 0 {
            self.undo_retrans = 0;
        }
        self.undo_retrans += 1;
        ok
    }

    /// La tête, après un RTO (`tcp_retransmit_skb(sk, head, 1)`).
    pub(super) fn renvoyer_tete(&mut self, maintenant: u64, sortir: &mut impl FnMut(Sortant)) {
        if !self.file.is_empty() {
            self.renvoyer(0, maintenant, sortir);
        }
    }

    /// Les segments marqués perdus, dans la limite de la cwnd
    /// (`tcp_xmit_retransmit_queue`) ; la tête renvoyée fait repartir le RTO.
    pub(super) fn renvoyer_perdus(&mut self, maintenant: u64, sortir: &mut impl FnMut(Sortant)) {
        if self.file.is_empty() {
            return;
        }
        let mut i = self.indice_renvoi.map_or(0, |h| self.indice_de(h));
        let mut trou = false;
        let mut rearmer = false;
        while i < self.file.len() {
            if !trou {
                self.indice_renvoi = Some(self.file[i].seq);
            }
            if self.cc.cwnd as i64 - self.paquets_en_vol() as i64 <= 0 {
                break;
            }
            let m = self.file[i].marques;
            if self.retrans_out >= self.lost_out {
                break;
            }
            if m & PERDU == 0 {
                if !trou && m & (EN_RENVOI | SACKE) == 0 {
                    trou = true;
                }
                i += 1;
                continue;
            }
            if m & (EN_RENVOI | SACKE) != 0 {
                i += 1;
                continue;
            }
            if !self.renvoyer(i, maintenant, sortir) {
                break;
            }
            if self.en_reduction() {
                self.prr_sortis += 1;
            }
            if i == 0 && !(self.t_xmit.is_some() && self.t_sorte == super::Minuteur::Reordonnancement) {
                rearmer = true;
            }
            i += 1;
        }
        if rearmer {
            self.armer_rto(maintenant);
        }
    }

    // --- Les minuteurs ---

    /// Arme le minuteur de retransmission à `maintenant` + RTO
    /// (`tcp_reset_xmit_timer`, ICSK_TIME_RETRANS).
    pub(super) fn armer_rto(&mut self, maintenant: u64) {
        self.armer_xmit(super::Minuteur::Retransmission, self.rto, maintenant);
    }

    /// Le minuteur de la connexion, pour `sorte`, dans `delai` au plus RTO_MAX
    /// (`inet_csk_reset_xmit_timer`). Un seul à la fois : chez Linux, retransmission
    /// et sonde partagent `icsk_retransmit_timer`, et `icsk_pending` dit laquelle.
    pub(super) fn armer_xmit(&mut self, sorte: super::Minuteur, delai: u64, maintenant: u64) {
        self.t_xmit = Some(maintenant + delai.min(RTO_MAX));
        self.t_sorte = sorte;
    }

    /// `tcp_rearm_rto` : après un progrès, le RTO repart de maintenant ; plus
    /// rien en file : il s'arrête.
    pub(super) fn rearmer_rto(&mut self, maintenant: u64) {
        let Some(tete) = self.file.front().copied() else {
            self.t_xmit = None;
            return;
        };
        // Le temps déjà passé compte, si l'échéance en cours n'était pas un RTO
        // (`tcp_rto_delta_us`).
        if matches!(self.t_sorte, super::Minuteur::Reordonnancement | super::Minuteur::SondeDePerte) {
            let d = (tete.envoi + self.rto).saturating_sub(maintenant).max(1);
            self.armer_xmit(super::Minuteur::Retransmission, d, maintenant);
        } else {
            self.armer_rto(maintenant);
        }
    }

    /// `tcp_ld_RTO_revert` (RFC 6069) : un cran de recul de moins, et
    /// l'échéance recalculée depuis le dernier envoi de la tête ; déjà passée :
    /// la retransmission tout de suite.
    pub(super) fn defaire_recul(&mut self, seq: u32, maintenant: u64, e: &mut Effets) {
        if seq != self.snd_una || self.retransmissions == 0 || self.recul == 0 {
            return;
        }
        let Some(tete) = self.file.front().copied() else { return };
        self.recul -= 1;
        let base = if self.rtt.mesure() { self.rtt.rto() } else { super::RTO_INITIAL };
        self.rto = reculer(base, self.recul);
        let ecoule = maintenant.saturating_sub(tete.envoi);
        if self.rto > ecoule {
            self.armer_xmit(super::Minuteur::Retransmission, self.rto - ecoule, maintenant);
        } else {
            self.minuteur_retrans(maintenant, e);
        }
    }

    /// Le RTO est échu (`tcp_retransmit_timer`) : abandonner (`tcp_write_timeout`),
    /// ou renvoyer la tête (le SYN, le SYN-ACK, ou le premier segment de la file),
    /// et doubler le RTO (sauf pour les quatre premières retransmissions d'un SYN).
    pub(super) fn minuteur_retrans(&mut self, maintenant: u64, e: &mut Effets) {
        let syn = matches!(self.etat, Etat::SynEnvoye | Etat::SynRecu);
        if self.etat == Etat::Fermee || (!syn && self.file.is_empty()) {
            return;
        }
        if !syn && self.snd_wnd == 0 && !self.reglages.orpheline {
            // L'autre a refermé sa fenêtre sur des données déjà en vol :
            // nos retransmissions deviennent des sondes, qui n'abandonnent
            // pas tant qu'il répond (Linux : « Receiver dastardly shrinks
            // window »). Une orpheline, elle, abandonne comme d'habitude.
            let depuis = if self.retrans_stamp != 0 { self.retrans_stamp } else { self.file.front().map_or(maintenant, |t| t.envoi) };
            if self.fenetre_nulle_echue(maintenant, maintenant.saturating_sub(depuis)) {
                self.abandonner(e);
                return;
            }
            self.entrer_perte(maintenant);
        } else {
            if self.temps_ecoule(maintenant) {
                self.abandonner(e);
                return;
            }
            self.entrer_perte(maintenant);
            self.retransmissions += 1;
            self.total_rto += 1;
        }
        if syn {
            self.syn_du = true;
            self.total_retrans += 1;
            self.syn_envoi = None;
        } else {
            self.rto_du = true;
            if self.retrans_stamp == 0 {
                self.retrans_stamp = maintenant;
            }
        }
        if !(self.etat == Etat::SynEnvoye && self.total_rto <= super::SYN_LINEAIRES) {
            self.recul += 1;
            self.rto = (self.rto * 2).min(RTO_MAX);
        }
        let d = self.borne_utilisateur(maintenant, self.rto);
        self.armer_xmit(super::Minuteur::Retransmission, d, maintenant);
        e.a_emettre = true;
    }
}
