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
use super::debit::{Chrono, TxDebit};
use super::rtt::RTO_MAX;
use super::sack::{JIFFY, MIN_RTT_FENETRE, en_jiffies};
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
pub(super) const COMPTE: u8 = 16;

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
    /// Ce qu'il retient de son dernier envoi, pour la mesure du débit (debit.rs).
    pub(super) tx: TxDebit,
    /// Le numéro de son dernier envoi (carte.rs).
    pub(super) numero: u64,
}

/// Ce que les blocs d'un ACK ont appris (`tcp_sacktag_state`), et l'échantillon de
/// débit qui se prépare (`rate_sample`, debit.rs).
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
    /// À quelle heure, ce qu'il avait de limité par le programme, et le temps d'envoi
    /// de sa fenêtre (`prior_mstamp`, `is_app_limited`, `interval_us`).
    pub prior_livre_a: u64,
    pub app_limite: bool,
    pub intervalle: u64,
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
    pub(super) fn neuf(seq: u32, fin_seq: u32, envoi: u64, drapeaux: u8, tx: TxDebit, numero: u64) -> Envoye {
        Envoye { seq, fin_seq, envoi, marques: 0, drapeaux, tx, numero }
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
        if self.file.is_empty() {
            self.chrono_arreter(Chrono::Occupee, maintenant);
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

    /// `tcp_simple_retransmit` : ce qui est en vol et plus long que le nouveau MSS ne
    /// passera pas : perdu. Pas de réduction de la cwnd : rien ne dit que le réseau
    /// est encombré ; c'est seulement l'unité qui a changé
    /// (`tcp_non_congestion_loss_retransmit`).
    pub(super) fn renvoyer_trop_longs(&mut self) {
        let mss = self.mss_courant();
        for i in 0..self.file.len() {
            if self.file[i].longueur() > mss {
                self.marquer_perdu(i);
            }
        }
        if self.lost_out == 0 {
            return;
        }
        if !self.sack_ok {
            self.limiter_reno_sacked();
        }
        if self.cc.phase != Phase::Perte {
            self.high_seq = self.snd_nxt;
            self.cc.ssthresh = self.cc.ssthresh_courant();
            self.prior_ssthresh = 0;
            self.undo_marker = None;
            self.changer_phase(Phase::Perte);
        }
        self.rexmit = Rexmit::Perdus;
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
                if self.cc.phase != Phase::Perte {
                    self.rto_fini(maintenant);
                }
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
        // Toujours dans la carte (`skb_still_in_host_queue`) : il n'est pas perdu.
        if self.encore_dans_la_carte(i) {
            return false;
        }
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
        self.mesures.octets_renvoyes += e.longueur() as u64;
        let debut = e.seq.wrapping_sub(self.seq_envoi) as usize;
        let h = self.entete(e.seq, e.drapeaux);
        let numero = self.compter_envoi(e.longueur() as usize);
        self.compter_sortie(e.longueur() as usize);
        sortir(Sortant { entete: h, debut, longueur: e.longueur() as usize, numero });
        self.file[i].numero = numero;
        self.file[i].envoi = maintenant;
        self.file[i].marques = (self.file[i].marques | DEJA_RENVOYE) & !COMPTE;
        self.file[i].tx = self.debit_parti(maintenant);
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

    /// La tête, après un RTO (`tcp_retransmit_skb(sk, head, 1)`). Qu'elle n'ait pas pu partir
    /// (encore dans la carte, ou plus de mémoire) ne change rien : le recul vaut quand même :
    /// -EBUSY et -ENOMEM ne sont pas la « congestion locale » de `tcp_retransmit_timer`, qui
    /// réessaie plus vite : un NET_XMIT_DROP de la couche du dessous, qu'aucun chemin ne nous dit.
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
            if m & PERDU != 0 && m & (EN_RENVOI | SACKE) == 0 && self.carte_trop_pleine(self.file[i].longueur() as usize, 1) {
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
        if self.etat == Etat::SynRecu && self.fille {
            return self.minuteur_fille(maintenant, e);
        }
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
            self.rto_compter(maintenant);
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

#[cfg(test)]
mod tests {
    use super::super::essais::*;
    use super::super::{Minuteur, RTO_INITIAL};
    use super::*;
    use alloc::vec::Vec;

    /// Une connexion avec `n` entrées d'un MSS en file, partie à HEURE.
    fn avec(sack: bool, n: usize) -> C {
        let mut c = etablie(sack);
        en_vol(&mut c, n);
        c
    }

    fn sortir_rien() -> impl FnMut(Sortant) {
        |_| ()
    }

    /// ACK du segment `i` compris : SND.UNA avance, comme avant `tcp_clean_rtx_queue`.
    fn nettoyer(c: &mut C, i: u32, etat: &mut EtatSack, quand: u64) -> u32 {
        let una = c.snd_una;
        c.snd_una = fin(i);
        let fack = c.plus_haut_sack();
        c.nettoyer_file(fack, una, etat, quand)
    }

    /// Un petit segment seul, sans rien d'anormal : sans doute un ACK retardé.
    #[test]
    fn un_ack_peut_etre_retarde() {
        let cas = |preparer: &dyn Fn(&mut C, &mut EtatSack)| {
            let mut c = etablie(true);
            c.reglages.nodelay = true;
            c.ecrire::<()>(100, |d| {
                d.fill(1);
                Ok(())
            })
            .unwrap();
            c.emettre(HEURE, |_| {});
            let mut e = EtatSack::default();
            preparer(&mut c, &mut e);
            let una = c.snd_una;
            c.snd_una = c.snd_nxt;
            c.nettoyer_file(c.snd_una, una, &mut e, HEURE + 10 * MS)
        };
        assert_ne!(cas(&|_, _| ()) & FLAG_ACK_MAYBE_DELAYED, 0);
        // D'autres livraisons depuis son envoi.
        assert_eq!(cas(&|c, _| c.livres += 1) & FLAG_ACK_MAYBE_DELAYED, 0);
        // Déjà du SACK.
        assert_eq!(cas(&|c, _| c.sacked_out = 1) & FLAG_ACK_MAYBE_DELAYED, 0);
        // Un ACK anormal.
        for f in [FLAG_DATA_SACKED, FLAG_DSACKING_ACK, FLAG_SYN_ACKED] {
            assert_eq!(cas(&|_, e| e.flag = f) & FLAG_ACK_MAYBE_DELAYED, 0);
        }
        // Un MSS entier, ou un de moins.
        assert_eq!(cas(&|c, _| c.mss = 100) & FLAG_ACK_MAYBE_DELAYED, 0);
        assert_ne!(cas(&|c, _| c.mss = 101) & FLAG_ACK_MAYBE_DELAYED, 0);
        // Deux segments.
        let mut c = avec(true, 2);
        c.mss = 10_000;
        let mut e = EtatSack::default();
        assert_eq!(nettoyer(&mut c, 1, &mut e, HEURE + MS) & FLAG_ACK_MAYBE_DELAYED, 0);
    }

    #[test]
    fn nettoyer_compte_ce_qui_part() {
        let mut c = avec(true, 5);
        c.file[0].marques = EN_RENVOI | DEJA_RENVOYE;
        c.retrans_out = 1;
        c.file[1].marques = DEJA_RENVOYE;
        c.file[2].marques = SACKE;
        c.sacked_out = 1;
        c.file[3].marques = PERDU;
        c.lost_out = 1;
        let avant_ = c.livres;
        c.high_seq = fin(4);
        c.indice_renvoi = Some(debut(4));
        let mut e = EtatSack::default();
        let f = nettoyer(&mut c, 3, &mut e, HEURE + MS);
        assert_eq!((c.retrans_out, c.sacked_out, c.lost_out), (0, 0, 0));
        // Le SACKé était déjà compté : les trois autres.
        assert_eq!(c.livres - avant_, 3);
        assert_ne!(f & FLAG_RETRANS_DATA_ACKED, 0);
        assert_ne!(f & FLAG_DATA_ACKED, 0);
        assert_ne!(f & FLAG_SET_XMIT_TIMER, 0);
        assert_eq!(c.indice_renvoi, Some(debut(4)), "toujours là");
        assert_eq!(c.file.len(), 1);
        // Karn : un renvoi acquitté : pas de mesure.
        assert!(!c.rtt.mesure());
        // Le prochain à renvoyer s'en va avec son segment.
        c.indice_renvoi = Some(debut(4));
        let mut e = EtatSack::default();
        let f = nettoyer(&mut c, 4, &mut e, HEURE + MS);
        assert_eq!(c.indice_renvoi, None);
        assert_eq!(f & FLAG_RETRANS_DATA_ACKED, 0);
        assert_ne!(f & FLAG_ORIG_SACK_ACKED, 0, "jamais renvoyé, sous high_seq");
        assert!(c.rtt.mesure());
    }

    #[test]
    fn nettoyer_orig_sack_acked_sous_high_seq() {
        let mut c = avec(true, 2);
        c.high_seq = fin(0) - 1;
        let mut e = EtatSack::default();
        assert_eq!(nettoyer(&mut c, 0, &mut e, HEURE + MS) & FLAG_ORIG_SACK_ACKED, 0);
        c.high_seq = fin(1);
        let mut e = EtatSack::default();
        assert_ne!(nettoyer(&mut c, 1, &mut e, HEURE + MS) & FLAG_ORIG_SACK_ACKED, 0);
    }

    /// La tête est SACKée après l'ACK : l'autre a peut-être oublié.
    #[test]
    fn nettoyer_reneging() {
        let mut c = avec(true, 3);
        c.file[1].marques = SACKE;
        c.sacked_out = 1;
        let mut e = EtatSack::default();
        assert_ne!(nettoyer(&mut c, 0, &mut e, HEURE + MS) & FLAG_SACK_RENEGING, 0);
        let mut c = avec(true, 3);
        c.file[2].marques = SACKE;
        c.sacked_out = 1;
        let mut e = EtatSack::default();
        assert_eq!(nettoyer(&mut c, 0, &mut e, HEURE + MS) & FLAG_SACK_RENEGING, 0);
    }

    /// Pas d'ACK de la tête, une mesure par SACK : le minuteur ne repart que si la mesure vient de
    /// données parties avant le dernier envoi de la tête.
    #[test]
    fn nettoyer_le_minuteur_sur_un_sack() {
        for (premier, tete, oui) in [(HEURE - MS, HEURE, true), (HEURE, HEURE, false), (HEURE + MS, HEURE, false)] {
            let mut c = avec(true, 2);
            c.file[0].envoi = tete;
            let mut e = EtatSack { premier: Some(premier), ..EtatSack::default() };
            let una = c.snd_una;
            let f = c.nettoyer_file(una, una, &mut e, HEURE + 5 * MS);
            assert_eq!(f & FLAG_SET_XMIT_TIMER != 0, oui, "{premier}");
            assert_eq!(f & FLAG_ACKED, 0);
        }
    }

    /// Un trou comblé par un segment jamais renvoyé : du réordonnancement (SACK).
    #[test]
    fn nettoyer_voit_le_reordonnancement() {
        let mut c = avec(true, 5);
        c.file[4].marques = SACKE;
        c.sacked_out = 1;
        c.fack = fin(4);
        let mut e = EtatSack::default();
        let una = c.snd_una;
        c.snd_una = fin(0);
        c.nettoyer_file(fin(4), una, &mut e, HEURE + MS);
        assert_eq!(c.reord_seen, 1);
        assert_eq!(c.reordering, 5, "5 MSS de distance");
        // Ce qui est tout en haut, non.
        let mut c = avec(true, 2);
        let mut e = EtatSack::default();
        let una = c.snd_una;
        c.snd_una = fin(0);
        c.nettoyer_file(debut(0), una, &mut e, HEURE + MS);
        assert_eq!(c.reord_seen, 0);
    }

    /// Sans SACK : `tcp_remove_reno_sacks`, et l'ACK d'un renvoi ne prouve pas l'original.
    #[test]
    fn nettoyer_sans_sack() {
        let mut c = avec(false, 5);
        c.file[0].marques = EN_RENVOI | DEJA_RENVOYE;
        c.retrans_out = 1;
        c.high_seq = fin(4);
        c.sacked_out = 2;
        let l = c.livres;
        let mut e = EtatSack::default();
        let f = nettoyer(&mut c, 1, &mut e, HEURE + MS);
        assert_eq!(f & FLAG_ORIG_SACK_ACKED, 0);
        assert_eq!(c.sacked_out, 1);
        assert_eq!(c.livres - l, 1);
    }

    #[test]
    fn un_renvoi_inutile() {
        let mut c = avec(true, 1);
        let mut e = c.file[0];
        let ts = crate::tcp::horloge_ts(e.envoi);
        c.ts_recu = Some((0, ts.wrapping_sub(1)));
        assert!(!c.renvoi_inutile(&e), "pas renvoyé");
        e.marques = EN_RENVOI;
        assert!(c.renvoi_inutile(&e));
        e.marques = DEJA_RENVOYE;
        assert!(c.renvoi_inutile(&e));
        c.ts_recu = Some((0, 0));
        assert!(!c.renvoi_inutile(&e), "pas d'écho");
        c.ts_recu = Some((0, ts));
        assert!(!c.renvoi_inutile(&e), "l'écho de ce renvoi");
        c.ts_recu = None;
        assert!(!c.renvoi_inutile(&e));
    }

    #[test]
    fn une_mesure_du_rtt() {
        let mut c = avec(true, 1);
        c.recul = 3;
        // Rien à mesurer.
        assert_eq!(c.mettre_a_jour_rtt(0, None, None, Some(7), HEURE), (false, Some(7)));
        assert_eq!(c.recul, 3);
        // Par l'heure d'envoi, ou le SACK : le RTO repart de l'estimateur.
        assert_eq!(c.mettre_a_jour_rtt(0, None, Some(20 * MS), None, HEURE), (true, Some(20 * MS)));
        assert_eq!(c.recul, 0);
        assert_eq!(c.rto, c.rtt.rto());
        assert_eq!(c.min_rtt.valeur(), 20 * MS);
        // `ca` dit le dernier segment, la mesure le premier.
        assert_eq!(c.mettre_a_jour_rtt(0, Some(30 * MS), None, Some(10 * MS), HEURE), (true, Some(10 * MS)));
        assert_eq!(c.min_rtt.valeur(), 10 * MS);
        // Un ACK sans doute retardé ne fait pas monter le minimum ; plus petit, si.
        let mut d = avec(true, 1);
        d.min_rtt.mesure(MIN_RTT_FENETRE, HEURE, 10 * MS);
        d.mettre_a_jour_rtt(FLAG_ACK_MAYBE_DELAYED, Some(20 * MS), None, None, HEURE + 400 * 1000 * MS);
        assert_eq!(d.min_rtt.valeur(), 10 * MS, "ni lui, ni l'expiration");
        d.mettre_a_jour_rtt(FLAG_ACK_MAYBE_DELAYED, Some(5 * MS), None, None, HEURE);
        assert_eq!(d.min_rtt.valeur(), 5 * MS);
        // Moins d'une µs : un jiffy.
        let mut d = avec(true, 1);
        d.mettre_a_jour_rtt(0, Some(999), None, None, HEURE);
        assert_eq!(d.min_rtt.valeur(), JIFFY);
        let mut d = avec(true, 1);
        d.mettre_a_jour_rtt(0, Some(1000), None, None, HEURE);
        assert_eq!(d.min_rtt.valeur(), 1000);
        // Par TSecr, seulement si l'ACK acquitte quelque chose.
        let mut d = avec(true, 1);
        d.ts_recu = Some((0, crate::tcp::horloge_ts(HEURE)));
        d.ts = Some(crate::tcp::Horodatages { recent: 0, instant: 0, decalage: 0 });
        assert_eq!(d.mettre_a_jour_rtt(0, None, None, None, HEURE + 50 * MS).0, false);
        let (oui, m) = d.mettre_a_jour_rtt(FLAG_DATA_ACKED, None, None, None, HEURE + 50 * MS);
        assert!(oui);
        assert!(m.is_some_and(|x| x >= 49 * MS && x <= 51 * MS), "{m:?}");
    }

    #[test]
    fn les_ack_dupliques_sans_sack() {
        let mut c = avec(false, 5);
        c.sacked_out = 4;
        assert!(!c.limiter_reno_sacked());
        c.sacked_out = 5;
        assert!(c.limiter_reno_sacked());
        assert_eq!(c.sacked_out, 4);
        c.lost_out = 2;
        c.sacked_out = 4;
        assert!(c.limiter_reno_sacked());
        assert_eq!(c.sacked_out, 3);
        c.lost_out = 9;
        assert!(c.limiter_reno_sacked());
        assert_eq!(c.sacked_out, 0);
        c.lost_out = 0;
        // Plus d'ACK dupliqués que de segments : du désordre.
        c.sacked_out = 5;
        let vu = c.reord_seen;
        c.verifier_reordonnancement_reno(2);
        assert_eq!(c.reordering, 7);
        assert_eq!(c.reord_seen, vu + 1);
        c.sacked_out = 1;
        c.verifier_reordonnancement_reno(2);
        assert_eq!(c.reord_seen, vu + 1, "rien d'anormal");
        // Un ACK dupliqué de plus.
        let l = c.livres;
        c.sacked_out = 1;
        c.ajouter_reno_sack(0);
        assert_eq!((c.sacked_out, c.livres), (1, l));
        c.ajouter_reno_sack(2);
        assert_eq!((c.sacked_out, c.livres), (3, l + 2));
        c.sacked_out = 4;
        let l = c.livres;
        c.ajouter_reno_sack(3);
        assert_eq!((c.sacked_out, c.livres), (4, l), "borné : rien de plus de livré");
        // Un ACK cumulatif.
        let l = c.livres;
        c.sacked_out = 4;
        c.retirer_reno_sacks(3);
        assert_eq!((c.sacked_out, c.livres), (2, l + 1));
        let l = c.livres;
        c.sacked_out = 2;
        c.retirer_reno_sacks(3);
        assert_eq!((c.sacked_out, c.livres), (0, l + 1));
        let l = c.livres;
        c.sacked_out = 0;
        c.retirer_reno_sacks(3);
        assert_eq!((c.sacked_out, c.livres), (0, l + 3));
        let l = c.livres;
        c.sacked_out = 2;
        c.retirer_reno_sacks(0);
        assert_eq!((c.sacked_out, c.livres), (2, l));
        c.sacked_out = 5;
        c.retirer_reno_sacks(0);
        assert_eq!(c.sacked_out, 4, "le contrôle se fait même sans rien d'acquitté");
    }

    #[test]
    fn marquer_perdu_() {
        let mut c = avec(true, 3);
        // SACKé : non.
        c.file[1].marques = SACKE;
        c.marquer_perdu(1);
        assert_eq!((c.lost_out, c.file[1].marques), (0, SACKE));
        assert_eq!(c.indice_renvoi, None);
        // Le premier : le prochain à renvoyer.
        c.marquer_perdu(2);
        assert_eq!((c.lost_out, c.perdus, c.indice_renvoi), (1, 1, Some(debut(2))));
        assert_ne!(c.file[2].marques & PERDU, 0);
        // Plus tôt : il prend sa place.
        c.marquer_perdu(0);
        assert_eq!((c.lost_out, c.perdus, c.indice_renvoi), (2, 2, Some(debut(0))));
        // Marqué et pas renvoyé : rien de plus.
        c.marquer_perdu(0);
        assert_eq!((c.lost_out, c.perdus), (2, 2));
        // Marqué et renvoyé : c'est son renvoi qui est perdu.
        c.file[0].marques |= EN_RENVOI;
        c.retrans_out = 1;
        c.marquer_perdu(0);
        assert_eq!((c.lost_out, c.perdus, c.retrans_out), (2, 3, 0));
        assert_eq!(c.file[0].marques & EN_RENVOI, 0);
        // Sans indice : seulement s'il n'y a pas plus de perdus que de renvoyés.
        let mut c = avec(true, 3);
        c.lost_out = 1;
        c.retrans_out = 0;
        c.marquer_perdu(1);
        assert_eq!(c.indice_renvoi, None, "des perdus restent à renvoyer plus bas");
        let mut c = avec(true, 3);
        c.lost_out = 1;
        c.retrans_out = 1;
        c.marquer_perdu(1);
        assert_eq!(c.indice_renvoi, Some(debut(1)));
    }

    #[test]
    fn poser_l_annulation() {
        let mut c = avec(true, 1);
        c.retrans_out = 2;
        c.poser_annulation();
        assert_eq!((c.undo_marker, c.undo_retrans), (Some(c.snd_una), 2));
        c.tlp_high_seq = Some(1);
        c.tlp_renvoi = true;
        c.poser_annulation();
        assert_eq!(c.undo_retrans, 3);
        c.tlp_renvoi = false;
        c.poser_annulation();
        assert_eq!(c.undo_retrans, 2);
        c.tlp_high_seq = None;
        c.tlp_renvoi = true;
        c.poser_annulation();
        assert_eq!(c.undo_retrans, 2);
        c.retrans_out = 0;
        c.poser_annulation();
        assert_eq!(c.undo_retrans, -1);
    }

    /// `tcp_enter_loss` : le seuil tombe une seule fois par fenêtre.
    #[test]
    fn entrer_perte_une_fois_par_fenetre() {
        // (phase, high_seq au-delà de SND.UNA, retransmissions, le seuil est-il retenu ?)
        for (phase, loin, retrans, oui) in [
            (Phase::Ouverte, true, 1, true), (Phase::Desordre, true, 1, true), (Phase::Reprise, true, 1, false),
            (Phase::Reprise, false, 1, true), (Phase::Perte, true, 1, false), (Phase::Perte, true, 0, true),
            (Phase::Reprise, true, 0, false), (Phase::Perte, false, 1, true),
        ] {
            let mut c = avec(true, 3);
            c.cc.phase = phase;
            c.high_seq = if loin { c.snd_nxt } else { c.snd_una };
            c.retransmissions = retrans;
            c.prior_ssthresh = 77;
            c.entrer_perte(HEURE);
            assert_eq!(c.prior_ssthresh != 77, oui, "{phase:?} {loin} {retrans}");
            assert_eq!(c.cc.phase, Phase::Perte);
            assert_eq!(c.high_seq, c.snd_nxt);
            assert_eq!(c.tlp_high_seq, None);
            assert_eq!(c.cc.cwnd, c.paquets_en_vol() + 1);
        }
    }

    /// F-RTO : hors d'une autre reprise, ou des RTO répétés.
    #[test]
    fn entrer_perte_et_frto() {
        for (phase, retrans, frto) in [
            (Phase::Ouverte, 0, true), (Phase::Reduction, 0, true), (Phase::Reprise, 0, false), (Phase::Perte, 0, false),
            (Phase::Reprise, 1, true), (Phase::Perte, 1, true),
        ] {
            let mut c = avec(true, 2);
            c.cc.phase = phase;
            c.retransmissions = retrans;
            c.entrer_perte(HEURE);
            assert_eq!(c.frto, frto, "{phase:?} {retrans}");
        }
    }

    /// `tcp_timeout_mark_lost` : la tête toujours, le reste s'il n'est plus récent ; une tête
    /// SACKée : tout est oublié.
    #[test]
    fn entrer_perte_ce_qui_est_perdu() {
        let mut c = avec(true, 3);
        c.rack.rtt = 100 * MS;
        c.file[1].envoi = HEURE - 50 * MS;
        c.file[2].envoi = HEURE - 100 * MS;
        c.file[0].envoi = HEURE;
        c.entrer_perte(HEURE);
        assert_ne!(c.file[0].marques & PERDU, 0, "la tête, même récente");
        assert_eq!(c.file[1].marques & PERDU, 0, "récent");
        assert_ne!(c.file[2].marques & PERDU, 0, "un RTT tout juste");
        assert_eq!(c.indice_renvoi, None);
        assert!(!c.sack_renie);
        // Une tête SACKée.
        let mut c = avec(true, 3);
        c.file[0].marques = SACKE;
        c.file[2].marques = SACKE;
        c.sacked_out = 2;
        c.rack.rtt = 100 * MS;
        c.entrer_perte(HEURE);
        assert!(c.sack_renie);
        assert_eq!(c.sacked_out, 0);
        assert!(c.file.iter().all(|e| e.marques & SACKE == 0 && e.marques & PERDU != 0));
        // Un SACK plus loin reste.
        let mut c = avec(true, 3);
        c.file[1].marques = SACKE;
        c.sacked_out = 1;
        c.entrer_perte(HEURE + 10_000 * MS);
        assert_eq!(c.sacked_out, 1);
        assert_ne!(c.file[1].marques & SACKE, 0);
        // Sans SACK, les ACK dupliqués sont oubliés.
        let mut c = avec(false, 3);
        c.sacked_out = 2;
        c.entrer_perte(HEURE);
        assert_eq!(c.sacked_out, 0);
    }

    /// Un RTO en désordre après beaucoup d'ACK dupliqués.
    #[test]
    fn entrer_perte_et_le_reordonnancement() {
        for (phase, sacked, attendu) in [(Phase::Desordre, 3, 3), (Phase::Ouverte, 3, 3), (Phase::Desordre, 2, 10), (Phase::Reprise, 3, 10)] {
            let mut c = avec(true, 6);
            for i in 1..=sacked {
                c.file[i].marques = SACKE;
            }
            c.sacked_out = sacked as u32;
            c.reordering = 10;
            c.cc.phase = phase;
            c.entrer_perte(HEURE);
            assert_eq!(c.reordering, attendu, "{phase:?} {sacked}");
        }
    }

    /// `tcp_process_loss`.
    #[test]
    fn traiter_perte_frto() {
        // Prêt à recevoir un ACK : un RTO, la tête renvoyée, du neuf encore à envoyer.
        let perte = |sack: bool| {
            let mut c = avec(sack, 4);
            c.entrer_perte(HEURE);
            c.ts_recu = None;
            c.undo_marker = Some(c.snd_una);
            c.undo_retrans = 1;
            c.retrans_stamp = HEURE;
            c
        };
        // Un ACK partiel de ce qui n'a pas été renvoyé : la perte est fausse (3.b).
        let mut c = perte(true);
        c.traiter_perte(FLAG_ORIG_SACK_ACKED, 0);
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert_eq!(c.undo_marker, None);
        // Sans F-RTO, ce n'est pas une preuve.
        let mut c = perte(true);
        c.frto = false;
        c.traiter_perte(FLAG_ORIG_SACK_ACKED, 0);
        assert_eq!(c.cc.phase, Phase::Perte);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        // Du neuf parti depuis (après 2.b) : un SACK ou un ACK dupliqué : la perte est vraie (3.a).
        for (flag, dup, frto) in [(FLAG_DATA_SACKED, 0, false), (0, 1, false), (0, 0, true)] {
            let mut c = perte(true);
            c.snd_nxt = c.high_seq.wrapping_add(10);
            c.traiter_perte(flag, dup);
            assert_eq!(c.frto, frto, "{flag:#x} {dup}");
            assert_eq!(c.rexmit, Rexmit::Perdus);
        }
        // 2.b : l'ACK avance : deux segments neufs, s'il y en a, et si la fenêtre le permet.
        let mut c = perte(true);
        c.snd_una = fin(0);
        c.undo_marker = None;
        c.octets_envoi += 1000;
        c.rexmit = Rexmit::Rien;
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.rexmit, Rexmit::Neuf);
        assert!(c.frto);
        assert_eq!(c.high_seq, c.snd_nxt);
        // Rien de neuf à envoyer : le retour au cas ordinaire.
        let mut c = perte(true);
        c.snd_una = fin(0);
        c.undo_marker = None;
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        assert!(!c.frto);
        // La fenêtre fermée de même.
        let mut c = perte(true);
        c.snd_una = fin(0);
        c.undo_marker = None;
        c.octets_envoi += 1000;
        c.snd_wnd = c.snd_nxt.wrapping_sub(c.snd_una);
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        assert!(!c.frto);
        // L'ACK n'avance pas : rien de neuf, F-RTO reste.
        let mut c = perte(true);
        c.undo_marker = None;
        c.octets_envoi += 1000;
        let h = c.high_seq;
        c.traiter_perte(0, 0);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        assert!(c.frto);
        assert_eq!(c.high_seq, h);
        // Tout est acquitté : la fin de la reprise, sans rien de plus.
        let mut c = perte(true);
        c.undo_marker = None;
        c.snd_una = c.high_seq;
        c.rexmit = Rexmit::Rien;
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.rexmit, Rexmit::Rien);
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert!(c.frto, "(`repare` : pas de 2.b)");
    }

    #[test]
    fn traiter_perte_une_annulation() {
        // L'ACK avance et rien n'a été renvoyé pour rien : `tcp_try_undo_loss`.
        let mut c = avec(true, 3);
        c.entrer_perte(HEURE);
        c.frto = false;
        c.undo_marker = Some(c.snd_una);
        c.undo_retrans = 0;
        c.snd_una = fin(0);
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert_eq!(c.lost_out, 0);
        // Sans avancée de l'ACK : pas d'annulation.
        let mut c = avec(true, 3);
        c.entrer_perte(HEURE);
        c.frto = false;
        c.undo_marker = Some(c.snd_una);
        c.undo_retrans = 0;
        c.traiter_perte(0, 0);
        assert_eq!(c.cc.phase, Phase::Perte);
    }

    #[test]
    fn traiter_perte_sans_sack() {
        let perte = || {
            let mut c = avec(false, 4);
            c.entrer_perte(HEURE);
            c.undo_marker = None;
            c.frto = false;
            // (Un seul perdu : `tcp_limit_reno_sacked` ne réduit rien.)
            c.lost_out = 1;
            c
        };
        // Un ACK dupliqué après du neuf : moins en vol.
        let mut c = perte();
        c.snd_nxt = c.high_seq.wrapping_add(10);
        c.traiter_perte(0, 1);
        assert_eq!(c.sacked_out, 1);
        // Sans neuf : non.
        let mut c = perte();
        c.traiter_perte(0, 1);
        assert_eq!(c.sacked_out, 0);
        // Sans ACK dupliqué : non.
        let mut c = perte();
        c.sacked_out = 2;
        c.snd_nxt = c.high_seq.wrapping_add(10);
        c.traiter_perte(0, 0);
        assert_eq!(c.sacked_out, 2);
        // Un ACK qui avance : ils sont oubliés.
        let mut c = perte();
        c.sacked_out = 2;
        c.snd_una = fin(0);
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.sacked_out, 0);
        // Avec SACK : on n'y touche pas.
        let mut c = avec(true, 4);
        c.entrer_perte(HEURE);
        c.undo_marker = None;
        c.frto = false;
        c.sacked_out = 2;
        c.snd_una = fin(0);
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.sacked_out, 2);
        c.snd_nxt = c.high_seq.wrapping_add(10);
        c.traiter_perte(0, 1);
        assert_eq!(c.sacked_out, 2);
    }

    /// PRR : les valeurs viennent de `tcp_cwnd_reduction`, à la main.
    #[test]
    fn reduire_la_cwnd() {
        // 10 en vol, seuil, prior_cwnd 10.
        let cas = |ssthresh: u32, livres: u32, perdus: u32, flag: u32, prr_livres: u32, prr_sortis: u32| {
            let mut c = avec(true, 10);
            c.cc.ssthresh = ssthresh;
            c.prior_cwnd = 10;
            c.prr_livres = prr_livres;
            c.prr_sortis = prr_sortis;
            c.cc.cwnd = 999;
            c.reduire_cwnd(livres, perdus, flag);
            assert_eq!(c.prr_livres, if livres == 0 { prr_livres } else { prr_livres + livres });
            c.cc.cwnd
        };
        // Plus en vol que le seuil : en proportion. (5 * 2 + 9) / 10 = 1.
        assert_eq!(cas(5, 2, 0, 0, 0, 0), 11);
        assert_eq!(cas(5, 2, 0, 0, 0, 1), 10, "1 - 1");
        assert_eq!(cas(5, 2, 0, 0, 0, 3), 10, "jamais moins de 0");
        // (5 * 20 + 9) / 10 = 10, moins 4 sortis.
        assert_eq!(cas(5, 2, 0, 0, 18, 4), 16);
        // Toujours un au début.
        assert_eq!(cas(1, 1, 0, 0, 0, 0), 11);
        // Le seuil atteint : delta 0 : rien, sauf le premier.
        assert_eq!(cas(10, 2, 0, 0, 0, 1), 10);
        assert_eq!(cas(10, 2, 0, 0, 0, 0), 11);
        // Sous le seuil : max(livrés - sortis, livres), + 1 si l'ACK avance sans perte, au plus delta.
        assert_eq!(cas(20, 2, 0, 0, 0, 1), 12);
        assert_eq!(cas(20, 2, 0, FLAG_SND_UNA_ADVANCED, 0, 1), 13);
        assert_eq!(cas(20, 2, 1, FLAG_SND_UNA_ADVANCED, 0, 1), 12);
        assert_eq!(cas(20, 2, 0, FLAG_DATA_ACKED, 0, 1), 12);
        assert_eq!(cas(30, 2, 0, 0, 6, 1), 17);
        assert_eq!(cas(11, 2, 0, 0, 0, 1), 11, "au plus delta");
        // Rien de livré, ou pas de cwnd d'avant : rien.
        assert_eq!(cas(5, 0, 0, 0, 0, 0), 999);
        let mut c = avec(true, 10);
        c.prior_cwnd = 0;
        c.cc.cwnd = 999;
        c.reduire_cwnd(2, 0, 0);
        assert_eq!(c.cc.cwnd, 999);
    }

    fn entree(seq: u32, n: u32, marques: u8, drapeaux: u8) -> Envoye {
        let tx = etablie(true).debit_parti(HEURE);
        Envoye { seq, fin_seq: seq + n, envoi: HEURE, marques, drapeaux, tx, numero: 0 }
    }

    /// `tcp_retrans_try_collapse`.
    #[test]
    fn accoler_() {
        let trois = |sack: bool| {
            let mut c = etablie(sack);
            let b = c.snd_una;
            c.file.clear();
            c.file.push_back(entree(b, 100, 0, 0));
            c.file.push_back(entree(b + 100, 100, 0, 0));
            c.file.push_back(entree(b + 200, 100, 0, 0));
            c.snd_nxt = b + 300;
            c.snd_wnd = 1 << 20;
            c
        };
        // Tant que ça tient dans la place, jusqu'à la dernière exacte.
        let mut c = trois(true);
        c.accoler(0, 250);
        assert_eq!(c.file.len(), 2);
        assert_eq!(c.file[0].longueur(), 200);
        let mut c = trois(true);
        c.accoler(0, 300);
        assert_eq!(c.file.len(), 1);
        assert_eq!(c.file[0].longueur(), 300);
        let mut c = trois(true);
        c.accoler(0, 199);
        assert_eq!(c.file.len(), 3);
        // La fenêtre : tout juste, oui ; un de plus, non.
        let mut c = trois(true);
        c.snd_wnd = 200;
        c.accoler(0, 1000);
        assert_eq!(c.file.len(), 2);
        let mut c = trois(true);
        c.snd_wnd = 199;
        c.accoler(0, 1000);
        assert_eq!(c.file.len(), 3);
        // Un FIN devant, un SACK derrière : non.
        let mut c = trois(true);
        c.file[0].drapeaux = tcp::FIN;
        c.file[0].fin_seq += 1;
        c.file[1].seq += 1;
        c.accoler(0, 1000);
        assert_eq!(c.file.len(), 3);
        let mut c = trois(true);
        c.file[1].marques = SACKE;
        c.accoler(0, 1000);
        assert_eq!(c.file.len(), 3);
        // Ce qui est accolé apporte ses drapeaux, son DEJA_RENVOYE, et quitte ses comptes.
        let mut c = trois(true);
        let b = c.snd_una;
        c.file[1].drapeaux = tcp::PSH;
        c.file[1].marques = EN_RENVOI | DEJA_RENVOYE | PERDU;
        c.retrans_out = 3;
        c.lost_out = 3;
        c.indice_renvoi = Some(b + 100);
        c.accoler(0, 200);
        assert_eq!(c.file[0].fin_seq, b + 200);
        assert_eq!(c.file[0].drapeaux, tcp::PSH);
        assert_eq!(c.file[0].marques, DEJA_RENVOYE);
        assert_eq!((c.retrans_out, c.lost_out), (2, 2));
        assert_eq!(c.indice_renvoi, Some(b));
        // Un indice ailleurs reste.
        let mut c = trois(true);
        c.indice_renvoi = Some(b + 200);
        c.accoler(0, 200);
        assert_eq!(c.indice_renvoi, Some(b + 200));
        // Sans SACK, un ACK dupliqué de moins ; avec, non.
        let mut c = trois(false);
        c.sacked_out = 2;
        c.accoler(0, 200);
        assert_eq!(c.sacked_out, 1);
        let mut c = trois(false);
        c.accoler(0, 200);
        assert_eq!(c.sacked_out, 0);
        let mut c = trois(true);
        c.sacked_out = 2;
        c.accoler(0, 200);
        assert_eq!(c.sacked_out, 2);
    }

    /// `tcp_fragment`.
    #[test]
    fn couper_() {
        let mut c = etablie(true);
        let b = c.snd_una;
        c.file.clear();
        let mut e = entree(b, 100, EN_RENVOI | PERDU | DEJA_RENVOYE, tcp::PSH | tcp::FIN);
        e.fin_seq += 1;
        c.file.push_back(e);
        c.tri.push_back((b, HEURE));
        c.retrans_out = 1;
        c.lost_out = 1;
        assert!(c.couper(0, 40));
        assert_eq!((c.file[0].seq, c.file[0].fin_seq, c.file[0].drapeaux), (b, b + 40, 0));
        assert_eq!((c.file[1].seq, c.file[1].fin_seq, c.file[1].drapeaux), (b + 40, b + 101, tcp::PSH | tcp::FIN));
        assert_eq!(c.file[1].marques, e.marques);
        assert_eq!((c.retrans_out, c.lost_out), (2, 2));
        let t: Vec<(u32, u64)> = c.tri.iter().copied().collect();
        assert_eq!(t, alloc::vec![(b, HEURE), (b + 40, HEURE)]);
        // Rien à compter pour une entrée sans marque, et pas de place dans le tri : rien.
        let mut c = etablie(true);
        c.file.clear();
        c.file.push_back(entree(b, 100, 0, tcp::PSH));
        assert!(c.couper(0, 40));
        assert_eq!((c.retrans_out, c.lost_out), (0, 0));
        assert!(c.tri.is_empty());
    }

    /// `tcp_xmit_retransmit_queue`.
    #[test]
    fn renvoyer_les_perdus() {
        let perdus = |n: usize| {
            let mut c = avec(true, n);
            for i in 0..n {
                c.marquer_perdu(i);
            }
            c.indice_renvoi = None;
            c
        };
        let mut sorties = Vec::new();
        // Autant que la cwnd laisse : ici, tous.
        let mut c = perdus(3);
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(0), debut(1), debut(2)]);
        assert_eq!(c.retrans_out, 3);
        assert_eq!(c.indice_renvoi, Some(debut(2)));
        assert!(c.file.iter().all(|e| e.marques & EN_RENVOI != 0));
        assert_eq!(c.t_xmit, Some(HEURE + MS + c.rto), "la tête renvoyée : le RTO repart");
        // La cwnd : `paquets_en_vol` compte les renvois.
        sorties.clear();
        let mut c = perdus(3);
        c.cc.cwnd = c.paquets_en_vol() + 1;
        c.t_xmit = None;
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(0)]);
        assert_eq!(c.indice_renvoi, Some(debut(1)));
        // Puis on repart de l'indice.
        c.cc.cwnd = c.paquets_en_vol() + 1;
        sorties.clear();
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(1)]);
        // Rien de plus que les perdus.
        let mut c = perdus(2);
        c.retrans_out = 2;
        sorties.clear();
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert!(sorties.is_empty());
        // Ce qui n'est pas perdu est sauté, et le premier trou fige l'indice.
        let mut c = avec(true, 4);
        c.marquer_perdu(1);
        c.marquer_perdu(3);
        c.file[2].marques |= SACKE;
        c.indice_renvoi = None;
        sorties.clear();
        c.t_xmit = None;
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(1), debut(3)]);
        assert_eq!(c.indice_renvoi, Some(debut(0)), "le trou");
        assert_eq!(c.t_xmit, None, "pas la tête");
        // Un renvoi déjà en vol, ou SACKé et perdu : sauté, l'indice le passe.
        let mut c = avec(true, 3);
        c.marquer_perdu(0);
        c.marquer_perdu(1);
        c.marquer_perdu(2);
        c.file[0].marques |= EN_RENVOI;
        c.retrans_out = 1;
        c.file[1].marques |= SACKE;
        c.indice_renvoi = None;
        sorties.clear();
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(2)]);
        assert_eq!(c.indice_renvoi, Some(debut(2)));
        // En réduction, PRR compte ce qui sort.
        let mut c = perdus(2);
        c.cc.phase = Phase::Reprise;
        c.renvoyer_perdus(HEURE + MS, &mut sortir_rien());
        assert_eq!(c.prr_sortis, 2);
        let mut c = perdus(2);
        c.renvoyer_perdus(HEURE + MS, &mut sortir_rien());
        assert_eq!(c.prr_sortis, 0);
        // Le minuteur de réordonnancement armé n'est pas touché.
        let mut c = perdus(1);
        c.t_xmit = Some(5);
        c.t_sorte = Minuteur::Reordonnancement;
        c.renvoyer_perdus(HEURE + MS, &mut sortir_rien());
        assert_eq!(c.t_xmit, Some(5));
        let mut c = perdus(1);
        c.t_xmit = None;
        c.t_sorte = Minuteur::Reordonnancement;
        c.renvoyer_perdus(HEURE + MS, &mut sortir_rien());
        assert!(c.t_xmit.is_some());
        let mut c = perdus(1);
        c.t_xmit = Some(5);
        c.t_sorte = Minuteur::Retransmission;
        c.renvoyer_perdus(HEURE + MS, &mut sortir_rien());
        assert_eq!(c.t_xmit, Some(HEURE + MS + c.rto));
        // La carte pleine arrête tout ; rien en file : rien.
        let mut c = perdus(2);
        c.sans_file = false;
        c.en_file = 1 << 30;
        sorties.clear();
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert!(sorties.is_empty());
        assert!(c.etrangle);
        let mut c = etablie(true);
        c.indice_renvoi = None;
        c.renvoyer_perdus(HEURE, &mut sortir_rien());
        assert_eq!(c.indice_renvoi, None);
    }

    /// `__tcp_retransmit_skb`.
    #[test]
    fn envoyer_une_entree() {
        let mut c = avec(true, 2);
        c.mss = 400;
        c.snd_wnd = 1 << 20;
        let mut parti = None;
        // Plus long que le MSS : coupé.
        assert!(c.envoyer_entree(0, HEURE + MS, &mut |s: Sortant| parti = Some((s.entete.seq, s.longueur))));
        assert_eq!(parti, Some((debut(0), 400)));
        assert_eq!(c.file.len(), 3);
        assert_eq!(c.file[0].fin_seq, debut(0) + 400);
        assert_eq!(c.file[0].envoi, HEURE + MS);
        assert_ne!(c.file[0].marques & DEJA_RENVOYE, 0);
        assert_eq!(c.total_retrans, 1);
        assert_eq!(c.mesures.octets_renvoyes, 400);
        // Sa tête acquittée depuis : retirée.
        let mut c = avec(true, 1);
        c.snd_una = debut(0) + 100;
        c.envoyer_entree(0, HEURE + MS, &mut |s: Sortant| parti = Some((s.entete.seq, s.longueur)));
        assert_eq!(parti, Some((debut(0) + 100, 900)));
        // Une fenêtre fermée : seule la tête part, entière (jusqu'au MSS).
        let mut c = avec(true, 2);
        c.snd_wnd = 0;
        assert!(c.envoyer_entree(0, HEURE + MS, &mut |s: Sortant| parti = Some((s.entete.seq, s.longueur))));
        assert_eq!(parti, Some((debut(0), 1000)));
        assert!(!c.envoyer_entree(1, HEURE + MS, &mut sortir_rien()));
        // Une petite fenêtre : coupé à des multiples du MSS, ou à ce qu'elle laisse.
        let mut c = avec(true, 1);
        c.snd_wnd = 700;
        assert!(c.envoyer_entree(0, HEURE + MS, &mut |s: Sortant| parti = Some((s.entete.seq, s.longueur))));
        assert_eq!(parti, Some((debut(0), 700)));
        // Exactement le MSS : ni coupé ni accolé.
        let mut c = avec(true, 2);
        assert!(c.envoyer_entree(0, HEURE + MS, &mut sortir_rien()));
        assert_eq!(c.file.len(), 2);
        // Plus court : accolé à ce qui suit, dans la place du MSS.
        let mut c = etablie(true);
        let b = c.snd_una;
        c.file.clear();
        c.file.push_back(entree(b, 100, 0, 0));
        c.file.push_back(entree(b + 100, 100, 0, 0));
        c.snd_nxt = b + 200;
        c.octets_envoi = 200;
        assert!(c.envoyer_entree(0, HEURE + MS, &mut |s: Sortant| parti = Some((s.entete.seq, s.longueur))));
        assert_eq!(parti, Some((b, 200)));
        assert_eq!(c.file.len(), 1);
        // Encore dans la carte : rien.
        let mut c = avec(true, 1);
        c.sans_file = false;
        c.file[0].numero = 10;
        c.rendu = 9;
        assert!(!c.envoyer_entree(0, HEURE + MS, &mut sortir_rien()));
        assert_eq!(c.total_retrans, 0);
    }

    /// `tcp_retransmit_skb` : les comptes.
    #[test]
    fn renvoyer_compte() {
        let mut c = avec(true, 1);
        c.undo_retrans = -1;
        assert!(c.renvoyer(0, HEURE + MS, &mut sortir_rien()));
        assert_eq!((c.retrans_out, c.undo_retrans, c.retrans_stamp), (1, 1, HEURE + MS));
        assert!(c.renvoyer(0, HEURE + 2 * MS, &mut sortir_rien()));
        assert_eq!(c.retrans_out, 1, "déjà compté");
        assert_eq!(c.undo_retrans, 2);
        assert_eq!(c.retrans_stamp, HEURE + MS, "le premier reste");
    }

    /// `tcp_ld_RTO_revert`.
    #[test]
    fn defaire_le_recul() {
        let prete = || {
            let mut c = avec(true, 1);
            c.retransmissions = 2;
            c.recul = 2;
            c.rto = 800 * MS;
            c
        };
        let u = debut(0);
        // Pas pour la tête, sans renvoi, sans recul : rien.
        for (seq, ret, rec) in [(u + 1, 2, 2), (u, 0, 2), (u, 2, 0)] {
            let mut c = prete();
            c.retransmissions = ret;
            c.recul = rec;
            let mut e = Effets::default();
            c.defaire_recul(seq, HEURE, &mut e);
            assert_eq!(c.rto, 800 * MS, "{seq} {ret} {rec}");
        }
        // Un cran de moins, l'échéance depuis le dernier envoi.
        let mut c = prete();
        let mut e = Effets::default();
        c.defaire_recul(u, HEURE + 100 * MS, &mut e);
        assert_eq!(c.recul, 1);
        assert_eq!(c.rto, 2 * RTO_INITIAL);
        assert_eq!(c.t_xmit, Some(HEURE + 2 * RTO_INITIAL));
        assert_eq!(c.t_sorte, Minuteur::Retransmission);
        // Avec une mesure, l'estimateur ; l'échéance passée : le renvoi tout de suite.
        let mut c = prete();
        c.rtt.echantillon(10 * MS, 0, 10);
        c.recul = 1;
        let mut e = Effets::default();
        c.defaire_recul(u, HEURE + 10_000 * MS, &mut e);
        assert_eq!(c.recul, 1, "le renvoi l'a fait remonter");
        assert_eq!(c.etat, Etat::Etablie);
    }

    #[test]
    fn la_fin_d_une_reduction() {
        let mut c = avec(true, 1);
        c.cc.cwnd = 50;
        c.cc.ssthresh = 10;
        c.cc.phase = Phase::Reduction;
        c.finir_reduction();
        assert_eq!(c.cc.cwnd, 10);
        c.cc.cwnd = 50;
        c.cc.phase = Phase::Reprise;
        c.undo_marker = None;
        c.finir_reduction();
        assert_eq!(c.cc.cwnd, 50, "annulée");
        c.undo_marker = Some(1);
        c.finir_reduction();
        assert_eq!(c.cc.cwnd, 10);
        c.cc.cwnd = 50;
        c.cc.ssthresh = crate::tcp::congestion::SSTHRESH_INFINI;
        c.finir_reduction();
        assert_eq!(c.cc.cwnd, 50);
    }

    #[test]
    fn un_paquet_retarde() {
        let mut c = avec(true, 1);
        c.retrans_stamp = HEURE;
        c.ts_recu = Some((0, crate::tcp::horloge_ts(HEURE).wrapping_sub(1)));
        assert!(c.paquet_retarde());
        c.ts_recu = Some((0, crate::tcp::horloge_ts(HEURE)));
        assert!(!c.paquet_retarde());
        // `retrans_stamp` effacé : rien de renvoyé, sauf deux cas.
        c.retrans_stamp = 0;
        c.snd_una = 10;
        c.high_seq = 20;
        assert!(c.paquet_retarde());
        c.etat = Etat::SynEnvoye;
        assert!(!c.paquet_retarde());
        c.etat = Etat::Etablie;
        c.sack_ok = false;
        assert!(c.paquet_retarde());
        c.snd_una = 20;
        assert!(!c.paquet_retarde());
        c.sack_ok = true;
        assert!(c.paquet_retarde());
    }

    #[test]
    fn annuler_par_un_dsack() {
        let mut c = avec(true, 1);
        c.undo_marker = Some(1);
        c.undo_retrans = 1;
        assert!(!c.annuler_par_dsack());
        c.undo_retrans = 0;
        c.rack.persiste = 0;
        assert!(c.annuler_par_dsack());
        assert_eq!(c.rack.persiste, 1);
        assert_eq!(c.undo_marker, None);
        assert!(!c.annuler_par_dsack());
    }

    /// `tcp_try_undo_partial`.
    #[test]
    fn annuler_en_partie() {
        let prete = |renvois: u32| {
            let mut c = avec(true, 3);
            c.retrans_stamp = HEURE;
            c.ts_recu = Some((0, crate::tcp::horloge_ts(HEURE).wrapping_sub(1)));
            c.undo_marker = Some(c.snd_una);
            c.cc.phase = Phase::Reprise;
            c.retrans_out = renvois;
            c.marquer_perdu(0);
            c.file[1].marques |= SACKE;
            c.sacked_out = 1;
            c.fack = fin(1);
            c
        };
        // Des renvois encore en vol : on continue d'envoyer, sans annuler.
        let mut c = prete(1);
        assert!(c.annuler_partiel(debut(0)));
        assert_eq!(c.reord_seen, 1);
        assert!(c.undo_marker.is_some());
        // Plus de renvois : tout est défait.
        let mut c = prete(0);
        assert!(!c.annuler_partiel(debut(0)));
        assert_eq!(c.undo_marker, None);
        assert_eq!(c.lost_out, 0);
        assert_eq!(c.cc.phase, Phase::Desordre);
        // Pas un retard : rien.
        let mut c = prete(0);
        c.ts_recu = None;
        assert!(!c.annuler_partiel(debut(0)));
        assert!(c.undo_marker.is_some());
    }

    #[test]
    fn rester_ouverte_() {
        let mut c = avec(true, 2);
        c.cc.phase = Phase::Desordre;
        c.high_seq = 1;
        c.rester_ouverte();
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert_eq!(c.high_seq, c.snd_nxt);
        c.high_seq = 1;
        c.rester_ouverte();
        assert_eq!(c.high_seq, 1, "pas de changement : pas de high_seq");
        for (s, l, m, r) in [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, DEJA_RENVOYE, 0), (0, 0, 0, 1)] {
            let mut c = avec(true, 2);
            c.sacked_out = s;
            c.lost_out = l;
            c.file[0].marques = m;
            c.retrans_out = r;
            c.rester_ouverte();
            assert_eq!(c.cc.phase, Phase::Desordre, "{s} {l} {m} {r}");
        }
    }

    /// `tcp_fastretrans_alert`.
    #[test]
    fn alerte_le_bord_gauche_sur_du_sack() {
        let mut c = avec(true, 2);
        c.rtt.echantillon(100 * MS, 0, 10);
        let mut f = FLAG_SACK_RENEGING | FLAG_SND_UNA_ADVANCED | FLAG_SET_XMIT_TIMER;
        c.alerte(debut(0), 0, &mut f, HEURE);
        assert_eq!(c.t_xmit, Some(HEURE + 52 * MS), "la moitié du RTT, arrondie au tic");
        assert_eq!(f & FLAG_SET_XMIT_TIMER, 0);
        assert_eq!(c.t_sorte, Minuteur::Retransmission);
        // Au moins 10 ms.
        let mut c = avec(true, 2);
        c.rtt.echantillon(4 * MS, 0, 10);
        let mut f = FLAG_SACK_RENEGING | FLAG_SND_UNA_ADVANCED;
        c.alerte(debut(0), 0, &mut f, HEURE);
        assert_eq!(c.t_xmit, Some(HEURE + 12 * MS), "10 ms, arrondis au tic");
        // L'un sans l'autre : le cas ordinaire.
        for f0 in [FLAG_SACK_RENEGING, FLAG_SND_UNA_ADVANCED] {
            let mut c = avec(true, 2);
            let t = c.t_xmit;
            let mut f = f0 | FLAG_SET_XMIT_TIMER;
            c.alerte(debut(0), 0, &mut f, HEURE);
            assert_eq!(c.t_xmit, t);
            assert_ne!(f & FLAG_SET_XMIT_TIMER, 0);
        }
    }

    #[test]
    fn alerte_les_sorties() {
        // Une file vide oublie ce qui est SACKé.
        let mut c = etablie(true);
        c.sacked_out = 3;
        let mut f = 0;
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.sacked_out, 0);
        // Ouverte : `retrans_stamp` s'efface.
        let mut c = avec(true, 1);
        c.retrans_stamp = 5;
        let mut f = 0;
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.retrans_stamp, 0);
        // CWR : au-delà de high_seq seulement, la cwnd au seuil.
        let mut c = avec(true, 1);
        c.cc.phase = Phase::Reduction;
        c.cc.cwnd = 50;
        c.cc.ssthresh = 10;
        c.high_seq = c.snd_una;
        let mut f = 0;
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.cc.phase, Phase::Reduction);
        c.high_seq = c.snd_una.wrapping_sub(1);
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert_eq!(c.cc.cwnd, 10);
        // La reprise finie.
        let mut c = avec(true, 2);
        c.cc.phase = Phase::Reprise;
        c.cc.cwnd = 50;
        c.cc.ssthresh = 10;
        c.high_seq = c.snd_una;
        c.undo_marker = Some(c.snd_una);
        c.undo_retrans = 1;
        c.retrans_stamp = HEURE;
        let mut f = 0;
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert_eq!(c.cc.cwnd, 10);
        // Sans SACK, elle reste jusqu'à ce qu'un ACK passe `high_seq`.
        let mut c = avec(false, 2);
        c.cc.phase = Phase::Reprise;
        c.cc.ssthresh = 10;
        c.high_seq = c.snd_una;
        c.sacked_out = 1;
        let mut f = 0;
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.cc.phase, Phase::Reprise);
        assert_eq!(c.sacked_out, 0);
    }

    #[test]
    fn alerte_ouverte_entre_en_reprise() {
        // Reno : le troisième ACK dupliqué.
        let mut c = avec(false, 5);
        let mut f = 0;
        c.alerte(c.snd_una, 2, &mut f, HEURE);
        assert_eq!(c.cc.phase, Phase::Desordre);
        assert_eq!(c.sacked_out, 2);
        assert_eq!(c.rexmit, Rexmit::Rien);
        let mut f = 0;
        c.alerte(c.snd_una, 1, &mut f, HEURE);
        assert_eq!(c.cc.phase, Phase::Reprise);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        assert_ne!(c.file[0].marques & PERDU, 0);
        // Pendant la reprise, un ACK partiel marque la nouvelle tête.
        let mut f = FLAG_SND_UNA_ADVANCED;
        let una = c.snd_una;
        c.snd_una = fin(0);
        c.file.pop_front();
        c.lost_out = 0;
        c.rexmit = Rexmit::Rien;
        c.alerte(una, 0, &mut f, HEURE);
        assert_ne!(c.file[0].marques & PERDU, 0);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        // Une avance d'ACK fait oublier les ACK dupliqués, hors reprise.
        let mut c = avec(false, 5);
        c.cc.phase = Phase::Desordre;
        c.sacked_out = 2;
        let mut f = FLAG_SND_UNA_ADVANCED;
        c.alerte(c.snd_una, 0, &mut f, HEURE);
        assert_eq!(c.sacked_out, 0);
    }

    /// Un renvoi démenti par l'écho ne fait pas avancer RACK ; un segment jamais renvoyé, si.
    #[test]
    fn nettoyer_et_rack() {
        let mut c = avec(true, 2);
        let mut e = EtatSack::default();
        nettoyer(&mut c, 0, &mut e, HEURE + MS);
        assert!(c.rack.avance);
        assert_eq!(c.rack.fin_seq, fin(0));
        let mut c = avec(true, 2);
        c.file[0].marques = DEJA_RENVOYE;
        c.ts_recu = Some((0, crate::tcp::horloge_ts(c.file[0].envoi).wrapping_sub(1)));
        let mut e = EtatSack::default();
        nettoyer(&mut c, 0, &mut e, HEURE + MS);
        assert!(!c.rack.avance);
    }

    /// `min_rtt` : seul un ACK sans doute retardé, plus grand que le minimum, ne compte pas.
    #[test]
    fn min_rtt_et_l_ack_retarde() {
        // Un ACK normal, plus grand : compté. Il prend la place du minimum quand celui-ci expire.
        // `tcp_min_rtt_wlen` : 300 s.
        let mut c = avec(true, 1);
        c.min_rtt.mesure(MIN_RTT_FENETRE, HEURE, 10 * MS);
        c.mettre_a_jour_rtt(0, Some(20 * MS), None, None, HEURE + 300_000 * MS - 1);
        assert_eq!(c.min_rtt.valeur(), 10 * MS);
        c.mettre_a_jour_rtt(0, Some(20 * MS), None, None, HEURE + 300_000 * MS + 1);
        assert_eq!(c.min_rtt.valeur(), 20 * MS);
        // Retardé, mais égal au minimum : compté, et le minimum repart de cet instant.
        let mut c = avec(true, 1);
        c.min_rtt.mesure(MIN_RTT_FENETRE, HEURE, 10 * MS);
        c.mettre_a_jour_rtt(FLAG_ACK_MAYBE_DELAYED, Some(10 * MS), None, None, HEURE + MIN_RTT_FENETRE - 1);
        c.mettre_a_jour_rtt(0, Some(20 * MS), None, None, HEURE + MIN_RTT_FENETRE + 1);
        assert_eq!(c.min_rtt.valeur(), 10 * MS);
    }

    /// Sans ACK dupliqué, `tcp_add_reno_sack` ne vérifie rien.
    #[test]
    fn aucun_ack_duplique() {
        let mut c = avec(false, 2);
        c.sacked_out = 2;
        c.ajouter_reno_sack(0);
        assert_eq!((c.sacked_out, c.reord_seen, c.reordering), (2, 0, TCP_REORDERING));
        c.ajouter_reno_sack(1);
        assert_eq!(c.reord_seen, 1, "trop d'ACK dupliqués : du désordre");
    }

    /// NewReno : au seuil hors de la reprise ; en reprise, seulement si SND.UNA avance.
    #[test]
    fn marquer_la_tete() {
        let prete = |phase| {
            let mut c = avec(false, 5);
            c.cc.phase = phase;
            c.sacked_out = TCP_REORDERING;
            c
        };
        let mut c = prete(Phase::Desordre);
        c.marquer_tete_perdue(false);
        assert_eq!(c.lost_out, 1, "le seuil atteint");
        let mut c = prete(Phase::Reprise);
        c.marquer_tete_perdue(false);
        assert_eq!(c.lost_out, 0, "en reprise, le seuil ne compte pas");
        let mut c = prete(Phase::Perte);
        c.marquer_tete_perdue(true);
        assert_eq!(c.lost_out, 0, "ni en perte");
        let mut c = prete(Phase::Reprise);
        c.marquer_tete_perdue(true);
        assert_eq!(c.lost_out, 1);
        // Par `identifier_pertes` : c'est le drapeau qui dit si SND.UNA avance.
        for (f, attendu) in [(0, 0), (FLAG_DATA_ACKED, 0), (FLAG_SND_UNA_ADVANCED, 1)] {
            let mut c = prete(Phase::Reprise);
            let mut flag = f;
            c.identifier_pertes(&mut flag, HEURE + MS);
            assert_eq!(c.lost_out, attendu, "{f:#x}");
            assert_eq!(flag, f);
        }
    }

    /// RACK (`tcp_identify_packet_loss`) : un segment attend encore : pas de RTO ré-armé ; un
    /// renvoi réputé perdu : le drapeau.
    #[test]
    fn identifier_les_pertes_par_rack() {
        let prete = || {
            let mut c = avec(true, 2);
            c.rack.rtt = 10 * MS;
            c.rack.mstamp = HEURE;
            c.rack.fin_seq = fin(1);
            c.rack.avance = true;
            c.cc.phase = Phase::Reprise;
            c.rto = 1000 * MS;
            c
        };
        // Un segment attend encore.
        let mut c = prete();
        let mut f = FLAG_SET_XMIT_TIMER | FLAG_DATA_ACKED;
        c.identifier_pertes(&mut f, HEURE + 4 * MS);
        assert_eq!(f, FLAG_DATA_ACKED);
        // Rien à marquer : rien ne change.
        let mut c = prete();
        c.rack.avance = false;
        let mut f = FLAG_SET_XMIT_TIMER | FLAG_DATA_ACKED;
        c.identifier_pertes(&mut f, HEURE + 4 * MS);
        assert_eq!(f, FLAG_SET_XMIT_TIMER | FLAG_DATA_ACKED);
        // Le renvoi de la tête est perdu à son tour.
        let mut c = prete();
        c.file[0].marques = PERDU | EN_RENVOI | DEJA_RENVOYE;
        c.lost_out = 1;
        c.retrans_out = 1;
        let mut f = 0;
        c.identifier_pertes(&mut f, HEURE + 100 * MS);
        assert_eq!(c.retrans_out, 0);
        assert_eq!(f, FLAG_LOST_RETRANS);
        // Des renvois encore en vol, pas perdus : pas de drapeau.
        let mut c = prete();
        c.rack.mstamp = HEURE - 100 * MS;
        c.file[0].marques = PERDU | EN_RENVOI | DEJA_RENVOYE;
        c.lost_out = 1;
        c.retrans_out = 1;
        let mut f = 0;
        c.identifier_pertes(&mut f, HEURE + 100 * MS);
        assert_eq!(c.retrans_out, 1);
        assert_eq!(f, 0);
    }

    /// `tcp_simple_retransmit` : plus long que le MSS, pas tout juste ; le compte de Reno borné.
    #[test]
    fn renvoyer_les_trop_longs() {
        let mut c = avec(true, 3);
        c.renvoyer_trop_longs();
        assert_eq!(c.lost_out, 0, "tout juste le MSS");
        assert_eq!(c.cc.phase, Phase::Ouverte);
        c.file[1].fin_seq += 1;
        c.renvoyer_trop_longs();
        assert_eq!(c.lost_out, 1);
        assert_eq!(c.file[1].marques & PERDU, PERDU);
        assert_eq!(c.cc.phase, Phase::Perte);
        assert_eq!(c.high_seq, c.snd_nxt);
        assert_eq!(c.rexmit, Rexmit::Perdus);
        // Le compte des ACK dupliqués, sans SACK seulement.
        for (sack, reste) in [(true, 3), (false, 2)] {
            let mut c = avec(sack, 3);
            c.sacked_out = 3;
            c.file[1].fin_seq += 1;
            c.renvoyer_trop_longs();
            assert_eq!(c.sacked_out, reste, "{sack}");
        }
    }

    /// La reprise commence : l'heure du premier renvoi s'efface, s'il n'y a plus rien de renvoyé.
    #[test]
    fn nettoyer_l_heure_du_renvoi() {
        let mut c = avec(true, 2);
        c.retrans_stamp = 5;
        c.entrer_reprise();
        assert_eq!(c.retrans_stamp, 0);
        let mut c = avec(true, 2);
        c.retrans_stamp = 5;
        c.retrans_out = 1;
        c.file[0].marques = EN_RENVOI;
        c.entrer_reprise();
        assert_eq!(c.retrans_stamp, 5);
        let mut c = avec(true, 2);
        c.retrans_stamp = 5;
        c.file[0].marques = DEJA_RENVOYE;
        c.entrer_reprise();
        assert_eq!(c.retrans_stamp, 5);
    }

    /// Sans SACK, en perte, au-delà de `high_seq` : sans ACK dupliqué, SND.UNA qui avance oublie
    /// le compte (`tcp_process_loss`).
    #[test]
    fn traiter_perte_le_compte_sans_sack() {
        let prete = || {
            let mut c = avec(false, 4);
            c.cc.phase = Phase::Perte;
            c.high_seq = debut(1);
            c.snd_una = debut(0);
            c.sacked_out = 2;
            c
        };
        let mut c = prete();
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 0);
        assert_eq!(c.sacked_out, 0);
        let mut c = prete();
        c.traiter_perte(0, 0);
        assert_eq!(c.sacked_out, 2);
        let mut c = prete();
        c.traiter_perte(FLAG_SND_UNA_ADVANCED, 1);
        assert_eq!(c.sacked_out, 3, "un ACK dupliqué passe avant");
    }

    /// En reprise : un ACK qui n'avance pas compte comme dupliqué, sans SACK ; la reprise qui
    /// continue laisse les perdus à renvoyer.
    #[test]
    fn alerte_en_reprise() {
        let prete = |sack| {
            let mut c = avec(sack, 5);
            c.cc.phase = Phase::Reprise;
            c.cc.ssthresh = 10;
            c.high_seq = c.snd_nxt;
            c.undo_marker = Some(c.snd_una);
            c.undo_retrans = 1;
            c.retrans_stamp = HEURE;
            c
        };
        let mut c = prete(false);
        let mut f = FLAG_DATA;
        c.alerte(c.snd_una, 1, &mut f, HEURE + MS);
        assert_eq!(c.sacked_out, 1);
        assert_eq!(c.cc.phase, Phase::Reprise);
        assert_eq!(c.rexmit, Rexmit::Perdus, "rien de perdu pour l'instant, mais la reprise continue");
        assert_eq!(c.reord_seen, 0);
        assert_eq!(c.prior_ssthresh, 0, "pas une nouvelle reprise");
        // SND.UNA avance : un ACK partiel, pas un dupliqué.
        let mut c = prete(false);
        c.snd_una = fin(0);
        let mut f = FLAG_SND_UNA_ADVANCED;
        c.alerte(debut(0), 1, &mut f, HEURE + MS);
        assert_eq!(c.sacked_out, 0);
        assert_eq!(c.lost_out, 1, "NewReno : la nouvelle tête");
    }

    /// En perte : seuls l'état ouvert, ou un renvoi perdu, vont plus loin que `tcp_process_loss`.
    #[test]
    fn alerte_en_perte() {
        let prete = || {
            let mut c = avec(true, 5);
            c.cc.phase = Phase::Perte;
            c.cc.ssthresh = 10;
            c.high_seq = c.snd_nxt;
            c.marquer_perdu(1);
            c
        };
        let mut c = prete();
        let mut f = 0;
        c.alerte(c.snd_una, 0, &mut f, HEURE + MS);
        assert_eq!(c.cc.phase, Phase::Perte);
        // Un renvoi perdu : la reprise, tout de suite.
        let mut c = prete();
        let mut f = FLAG_LOST_RETRANS;
        c.alerte(c.snd_una, 0, &mut f, HEURE + MS);
        assert_eq!(c.cc.phase, Phase::Reprise);
    }

    /// `tcp_try_undo_dsack`, en dessous de CWR seulement.
    #[test]
    fn alerte_ouverte_et_le_dsack() {
        let prete = |phase| {
            let mut c = avec(true, 2);
            c.cc.phase = phase;
            c.undo_marker = Some(c.snd_una);
            c.undo_retrans = 0;
            c.prior_ssthresh = 77;
            c
        };
        let mut c = prete(Phase::Desordre);
        let mut f = 0;
        c.alerte_ouverte(0, &mut f, HEURE + MS);
        assert_eq!(c.undo_marker, None);
        let mut c = prete(Phase::Reduction);
        let mut f = 0;
        c.alerte_ouverte(0, &mut f, HEURE + MS);
        assert_eq!(c.undo_marker, Some(c.snd_una));
    }

    /// `tcp_may_raise_cwnd` : un fort réordonnancement estimé rend moins prudent.
    #[test]
    fn la_cwnd_peut_grandir() {
        for (reord, flag, oui) in [
            (TCP_REORDERING, FLAG_DATA_ACKED, true),
            (TCP_REORDERING, FLAG_DATA_SACKED, false),
            (TCP_REORDERING, FLAG_SYN_ACKED, false),
            (TCP_REORDERING, FLAG_WIN_UPDATE, false),
            (TCP_REORDERING + 1, FLAG_DATA_SACKED, true),
            (TCP_REORDERING + 1, FLAG_DATA_ACKED, true),
            (TCP_REORDERING + 1, FLAG_SYN_ACKED, true),
            (TCP_REORDERING + 1, FLAG_WIN_UPDATE, false),
        ] {
            let mut c = avec(true, 2);
            c.reordering = reord;
            c.cc.cwnd = 5;
            c.cc.ssthresh = 100;
            c.cc.valider(true, 5, c.snd_una, c.snd_nxt, c.rto, false, HEURE);
            c.controler_congestion(1, 0, flag, HEURE + MS);
            assert_eq!(c.cc.cwnd > 5, oui, "{reord} {flag:#x}");
        }
    }

    /// `tcp_sacktag_bsearch` : l'entrée qui contient `seq`, ou la suivante.
    #[test]
    fn la_place_d_une_sequence() {
        let c = avec(true, 3);
        assert_eq!(c.indice_avant(debut(0)), 0);
        assert_eq!(c.indice_avant(debut(0) + 1), 0);
        assert_eq!(c.indice_avant(debut(1)), 1);
        assert_eq!(c.indice_avant(fin(2) - 1), 2);
        assert_eq!(c.indice_avant(fin(2)), 3);
    }

    /// Un deuxième renvoi garde la marque du premier ; un renvoi qui porte des données compte
    /// comme un envoi.
    #[test]
    fn renvoyer_deux_fois() {
        let mut c = avec(true, 1);
        c.dernier_envoi = HEURE;
        assert!(c.envoyer_entree(0, HEURE + MS, &mut sortir_rien()));
        assert_eq!(c.file[0].marques & DEJA_RENVOYE, DEJA_RENVOYE);
        assert_eq!(c.dernier_envoi, HEURE + MS);
        assert!(c.envoyer_entree(0, HEURE + 2 * MS, &mut sortir_rien()));
        assert_eq!(c.file[0].marques & DEJA_RENVOYE, DEJA_RENVOYE);
        assert_eq!(c.dernier_envoi, HEURE + 2 * MS);
    }

    /// Tout juste un MSS : `tcp_retrans_try_collapse` n'est même pas essayé, le FIN qui suit reste seul.
    #[test]
    fn renvoyer_un_mss_garde_le_fin_a_part() {
        let mut c = avec(true, 1);
        c.fermer_envoi();
        c.emettre(HEURE, |_| {});
        assert_eq!(c.file.len(), 2);
        assert!(c.envoyer_entree(0, HEURE + MS, &mut sortir_rien()));
        assert_eq!(c.file.len(), 2);
    }

    /// Le renvoi d'un FIN seul ne porte pas de données : pas un envoi (`__tcp_transmit_skb`).
    #[test]
    fn renvoyer_le_fin_seul() {
        let mut c = etablie(true);
        c.fermer_envoi();
        c.emettre(HEURE, |_| {});
        assert_eq!(c.file.len(), 1);
        assert_eq!(c.file[0].longueur(), 0);
        c.dernier_envoi = 5;
        assert!(c.envoyer_entree(0, HEURE + MS, &mut sortir_rien()));
        assert_eq!(c.dernier_envoi, 5);
    }

    /// Ce qui ferme la boucle de `tcp_xmit_retransmit_queue` : la carte pleine, seulement pour ce
    /// qui part vraiment ; l'indice s'arrête au premier trou.
    #[test]
    fn renvoyer_les_perdus_et_la_carte() {
        // Ni perdu, ni à renvoyer : la carte pleine n'arrête pas le parcours.
        let prete = |marques: [u8; 3]| {
            let mut c = avec(true, 3);
            for (i, m) in marques.iter().enumerate() {
                c.file[i].marques = *m;
                if m & PERDU != 0 {
                    c.lost_out += 1;
                }
                if m & EN_RENVOI != 0 {
                    c.retrans_out += 1;
                }
                if m & SACKE != 0 {
                    c.sacked_out += 1;
                }
            }
            c.cc.cwnd = 100;
            c.indice_renvoi = None;
            c
        };
        let mut sorties = Vec::new();
        // Le trou (ni perdu, ni SACKé) fixe l'indice : la suite sera reprise de lui.
        let mut c = prete([0, PERDU, 0]);
        let t = c.t_xmit;
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(1)]);
        assert_eq!(c.indice_renvoi, Some(debut(0)));
        assert_eq!(c.t_xmit, t, "pas la tête : le RTO ne repart pas");
        // La carte pleine n'arrête que ce qui partirait pour de bon : un renvoi en vol, on passe.
        sorties.clear();
        let mut c = prete([PERDU | EN_RENVOI, PERDU, 0]);
        c.sans_file = false;
        c.en_file = 1 << 30;
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert!(sorties.is_empty());
        assert!(c.etrangle);
        assert_eq!(c.indice_renvoi, Some(debut(1)));
        // Un petit segment pas perdu n'arrête pas un grand qui l'est, dont la carte a plus de place.
        sorties.clear();
        let mut c = prete([0, PERDU, 0]);
        c.file[0].fin_seq = debut(0) + 100;
        c.cc.pacing = 0;
        c.sans_file = false;
        c.en_file = 4 * (100 + super::super::carte::COUT_SEGMENT) + 1;
        c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
        assert_eq!(sorties, alloc::vec![debut(1)]);
        // Rien de perdu : la carte n'est même pas regardée.
        let mut c = prete([0, 0, 0]);
        c.sans_file = false;
        c.en_file = 1 << 30;
        c.renvoyer_perdus(HEURE + MS, &mut sortir_rien());
        assert!(!c.etrangle);
        // SACKé, ou déjà renvoyé : ce n'est pas un trou, l'indice passe.
        for m in [SACKE, PERDU | EN_RENVOI] {
            sorties.clear();
            let mut c = prete([m, PERDU, 0]);
            c.renvoyer_perdus(HEURE + MS, &mut |s: Sortant| sorties.push(s.entete.seq));
            assert_eq!(sorties, alloc::vec![debut(1)], "{m}");
            assert_eq!(c.indice_renvoi, Some(debut(2)), "{m}");
        }
    }

    /// Le recul défait tombe tout juste à échéance : le renvoi, tout de suite.
    #[test]
    fn defaire_le_recul_a_l_echeance() {
        let mut c = avec(true, 1);
        c.retransmissions = 2;
        c.recul = 2;
        let d = 2 * RTO_INITIAL;
        let mut e = Effets::default();
        c.defaire_recul(debut(0), HEURE + d, &mut e);
        assert!(e.a_emettre, "à l'échéance");
        let mut c = avec(true, 1);
        c.retransmissions = 2;
        c.recul = 2;
        let mut e = Effets::default();
        c.defaire_recul(debut(0), HEURE + d - 1, &mut e);
        assert!(!e.a_emettre);
        assert_eq!(c.t_xmit, Some(HEURE + d));
    }

    /// Le RTO : rien pour une connexion fermée, ni pour une file vide.
    #[test]
    fn le_rto_sans_rien_a_faire() {
        let mut c = etablie(true);
        let r = c.rto;
        let mut e = Effets::default();
        c.minuteur_retrans(HEURE + 10_000 * MS, &mut e);
        assert_eq!((c.rto, c.recul, e.a_emettre), (r, 0, false), "file vide");
        let mut c = avec(true, 1);
        c.etat = Etat::Fermee;
        let r = c.rto;
        let mut e = Effets::default();
        c.minuteur_retrans(HEURE + 10_000 * MS, &mut e);
        assert_eq!((c.rto, c.recul, e.a_emettre), (r, 0, false), "fermée");
    }

    /// La fenêtre refermée : le temps de l'abandon se compte du premier renvoi, à défaut de
    /// l'envoi de la tête.
    #[test]
    fn le_rto_et_la_fenetre_nulle_compte_depuis() {
        let d = 60_000 * MS;
        let prete = || {
            let mut c = avec(true, 1);
            c.snd_wnd = 0;
            c.reglages.delai_utilisateur = d;
            c.dernier_recu = HEURE + 2 * d;
            c
        };
        // Sans renvoi : depuis l'envoi de la tête, HEURE.
        let mut c = prete();
        let mut e = Effets::default();
        c.minuteur_retrans(HEURE + d + 1, &mut e);
        assert_eq!(c.etat, Etat::Fermee, "plus longtemps que le délai");
        // Le premier renvoi est plus récent : pas encore.
        let mut c = prete();
        c.retrans_stamp = HEURE + 10 * MS;
        let mut e = Effets::default();
        c.minuteur_retrans(HEURE + d + 1, &mut e);
        assert_eq!(c.etat, Etat::Etablie);
    }
}
