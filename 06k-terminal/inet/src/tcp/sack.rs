//! SACK (RFC 2018), D-SACK (RFC 2883) et RACK (RFC 8985), tels que Linux 6.18
//! les fait marcher ensemble : avec SACK, détecter les pertes, c'est RACK, et
//! rien d'autre (`tcp_identify_packet_loss`, `tcp_time_to_recover`).
//!
//! L'IDÉE DE SACK. L'ACK cumulatif ne dit que le début du premier trou. Les blocs
//! SACK disent aussi ce qui est arrivé au-delà : l'émetteur ne renvoie plus que
//! ce qui manque, plusieurs pertes par aller-retour se réparent sans RTO.
//! D-SACK : le premier bloc dit un DOUBLON reçu (un renvoi inutile, ou un
//! paquet dupliqué par le réseau).
//!
//! L'IDÉE DE RACK. Un segment est perdu si un segment envoyé APRÈS lui est
//! arrivé, et que plus d'un RTT plus une petite fenêtre de réordonnancement a
//! passé depuis son envoi. Le temps plutôt que le compte de trois ACK dupliqués :
//! ça vaut aussi pour un segment renvoyé, et une dernière salve sans ACK
//! dupliqués. Tant qu'aucun réordonnancement n'a été vu, la fenêtre est nulle
//! pendant une reprise, ou dès trois segments arrivés hors d'ordre : les trois
//! ACK dupliqués survivent ainsi.
//!
//! TLP (RFC 8985, la sonde de fin de rafale) : le dernier segment d'une rafale
//! perdu n'a personne après lui pour le dire. Si rien ne revient après 2 × SRTT,
//! un segment repart (un neuf, sinon le dernier) ; son ACK déclenche la reprise par
//! les blocs, sans attendre le RTO. Sans SACK : pas de TLP.
//!
//! Écarté : `recv_sack_cache` et `tcp_shift_skb_data`, deux économies de Linux :
//! ne pas reparcourir ce qu'un bloc redit, et fondre les segments SACKés. Nos
//! files sont petites, et chaque ACK ne coûte qu'un parcours de ce que ses blocs
//! couvrent. La file triée par heure d'envoi (`tsorted_sent_queue`) est ici une
//! `VecDeque` de (numéro, heure) nettoyée à la lecture : une entrée dont le
//! segment a disparu, ou a été renvoyé, ne vaut plus.

use super::congestion::Phase;
use super::hors_ordre::etendre_bloc;
use super::retrans::{DEJA_RENVOYE, EN_RENVOI, EtatSack, FLAG_DATA_SACKED, FLAG_DSACK_TLP, FLAG_DSACKING_ACK, FLAG_NOT_DUP, FLAG_ORIG_SACK_ACKED, FLAG_SND_UNA_ADVANCED, PERDU, SACKE};
use super::rtt::{RTO_INITIAL, RTO_MIN};
use super::{Charge, Sortant, Tcb, Tcp, apres, avant};
use formats::reseau::tcp::BLOCS_MAX;
use faillible::FileFaillible;

/// Les blocs qu'un segment attend de trouver sans ACK à part (TCP_SACK_BLOCKS_EXPECTED).
const BLOCS_ATTENDUS: usize = 2;
/// Un jiffy de Linux, là où il compte en jiffies : HZ = 250, celui de l'hôte, la
/// valeur par défaut de Kconfig ; les sondes se comparent ainsi à l'arrondi près.
pub(super) const JIFFY: u64 = 4_000_000;
/// Le plus petit délai de RACK (TCP_TIMEOUT_MIN_US).
pub(super) const TIMEOUT_MIN: u64 = 2_000_000;
/// La fenêtre de `min_rtt` (`tcp_min_rtt_wlen`, 300 s).
pub(super) const MIN_RTT_FENETRE: u64 = 300 * 1_000_000_000;
/// Les reprises pendant lesquelles une fenêtre de RACK agrandie reste
/// (TCP_RACK_RECOVERY_THRESH).
pub(super) const RACK_PERSISTE: u32 = 16;

/// Le prochain jiffy (`usecs_to_jiffies`).
pub(super) fn en_jiffies(ns: u64) -> u64 {
    ns.div_ceil(JIFFY) * JIFFY
}

/// `t1`, `seq1` est-il parti après `t2`, `seq2` (`tcp_skb_sent_after`) ?
pub(super) fn parti_apres(t1: u64, t2: u64, seq1: u32, seq2: u32) -> bool {
    t1 > t2 || (t1 == t2 && apres(seq1, seq2))
}

/// L'état de RACK (`tp->rack`).
#[derive(Debug, Clone, Copy)]
pub(super) struct Rack {
    /// L'heure d'envoi et la fin du segment parti le plus récemment parmi ceux
    /// qui sont arrivés.
    pub mstamp: u64,
    pub fin_seq: u32,
    /// Le RTT de ce segment.
    pub rtt: u64,
    /// Les segments livrés à la dernière hausse de la fenêtre.
    pub dernier_livre: u32,
    /// La fenêtre de réordonnancement, en quarts de `min_rtt`.
    pub pas: u32,
    /// Les reprises qui restent avant de revenir à un pas.
    pub persiste: u32,
    pub dsack_vu: bool,
    /// Une arrivée neuve : il y a de quoi regarder.
    pub avance: bool,
}

impl Rack {
    pub const fn new() -> Rack {
        Rack { mstamp: 0, fin_seq: 0, rtt: 0, dernier_livre: 0, pas: 1, persiste: 0, dsack_vu: false, avance: false }
    }
}

impl<P: Charge> Tcb<P> {
    /// Propose SACK dans le SYN de `connect` (`tcp_sack`, `tcp_dsack`). Sans cet
    /// appel, la connexion n'en propose pas.
    pub fn proposer_sack(&mut self) {
        self.sack_ok = true;
    }

    // --- Le récepteur : les blocs ---

    /// Les blocs d'un segment (`tcp_established_options`) : le D-SACK d'abord,
    /// puis les autres, le plus récent en tête ; autant qu'il en tient (4, 3 avec
    /// les horodatages).
    pub(super) fn blocs_a_envoyer(&self) -> ([(u32, u32); BLOCS_MAX], u8) {
        let mut o = [(0, 0); BLOCS_MAX];
        let place = if self.ts.is_some() { 3 } else { 4 };
        let mut n = 0;
        if let Some(d) = self.dsack {
            o[0] = d;
            n = 1;
        }
        for b in &self.blocs[..self.nb_blocs as usize] {
            if n == place {
                break;
            }
            o[n] = *b;
            n += 1;
        }
        (o, n as u8)
    }

    /// Ce que les blocs prennent à un segment (`tcp_current_mss`).
    pub(super) fn place_des_blocs(&self) -> u32 {
        let n = self.blocs_a_envoyer().1 as u32;
        if n > 0 { 4 + 8 * n } else { 0 }
    }

    /// Un doublon, à dire par D-SACK (`tcp_dsack_set`).
    pub(super) fn poser_doublon(&mut self, debut: u32, fin: u32) {
        if self.sack_ok {
            self.dsack = Some((debut, fin));
        }
    }

    /// Le premier bloc d'une file hors d'ordre vide, ou un de plus
    /// (`tcp_sack_new_ofo_skb`) : un bloc touché remonte en tête et fusionne ;
    /// un neuf prend la tête, le plus vieux tombe s'il n'y a plus de place.
    pub(super) fn nouveau_bloc(&mut self, debut: u32, fin: u32) {
        let n = self.nb_blocs as usize;
        for i in 0..n {
            if etendre_bloc(&mut self.blocs[i], debut, fin) {
                if i >= BLOCS_ATTENDUS {
                    self.ack_compresse_maintenant();
                }
                self.blocs[..=i].rotate_right(1);
                self.fusionner_blocs();
                return;
            }
        }
        if n >= BLOCS_ATTENDUS {
            self.ack_compresse_maintenant();
        }
        let garde = n.min(BLOCS_MAX - 1);
        self.blocs.copy_within(..garde, 1);
        self.blocs[0] = (debut, fin);
        self.nb_blocs = (garde + 1) as u8;
    }

    /// Le premier bloc a grandi : il mange peut-être les autres
    /// (`tcp_sack_maybe_coalesce`).
    fn fusionner_blocs(&mut self) {
        let mut i = 1;
        while i < self.nb_blocs as usize {
            let b = self.blocs[i];
            if etendre_bloc(&mut self.blocs[0], b.0, b.1) {
                self.nb_blocs -= 1;
                self.blocs.copy_within(i + 1.., i);
            } else {
                i += 1;
            }
        }
    }

    /// Les blocs que RCV.NXT a dépassés (`tcp_sack_remove`).
    pub(super) fn retirer_blocs(&mut self) {
        if self.hors_ordre.vide() {
            self.nb_blocs = 0;
            return;
        }
        let mut i = 0;
        while i < self.nb_blocs as usize {
            if !avant(self.rcv_nxt, self.blocs[i].0) {
                self.nb_blocs -= 1;
                self.blocs.copy_within(i + 1.., i);
            } else {
                i += 1;
            }
        }
    }

    /// Un ACK comprimé attendait : il part (`tcp_sack_compress_send_ack`).
    pub(super) fn ack_compresse_maintenant(&mut self) {
        if self.ack_comprimes > 0 {
            self.ack_comprimes = 0;
            self.t_comprime = None;
            self.ack_maintenant = true;
        }
    }

    // --- L'émetteur : le tableau ---

    /// Le numéro qui suit le plus haut segment SACKé (`tcp_highest_sack_seq`).
    pub(super) fn plus_haut_sack(&self) -> u32 {
        // Sans SACK, `sacked_out` ne compte que des ACK dupliqués : rien de plus haut que la tête.
        if self.sacked_out == 0 || !self.sack_ok { self.snd_una } else { self.fack }
    }

    /// Un D-SACK vu (`tcp_dsack_seen`) : rend le nombre de segments doublons, ou
    /// 0 s'il est douteux (plus grand que la fenêtre, ou plus de doublons que de
    /// renvois) : un récepteur malveillant ne fera pas annuler nos réductions.
    fn doublon_vu(&mut self, debut: u32, fin: u32, etat: &mut EtatSack) -> u32 {
        if !avant(debut, fin) {
            return 0;
        }
        let n = fin.wrapping_sub(debut);
        if n > self.max_fenetre {
            return 0;
        }
        let segments = if n > self.mss as u32 { n.div_ceil(self.mss as u32) } else { 1 };
        // Le doublon de notre sonde (un segment renvoyé par TLP, arrivé en plus de
        // l'original) n'est pas dû au réordonnancement.
        let de_la_sonde = n <= self.mss as u32 && self.tlp_high_seq == Some(fin);
        if de_la_sonde {
            etat.flag |= FLAG_DSACK_TLP;
        }
        self.dsack_doublons += segments;
        if self.dsack_doublons > self.total_retrans {
            return 0;
        }
        if self.reord_seen > 0 && !de_la_sonde {
            self.rack.dsack_vu = true;
        }
        etat.flag |= FLAG_DSACKING_ACK;
        etat.livres += segments;
        segments
    }

    /// Le premier bloc est-il un D-SACK (`tcp_check_dsack`) : sous l'ACK, ou dans
    /// le deuxième bloc (RFC 2883) ?
    fn verifier_doublon(&mut self, t: &Tcp, una_avant: u32, etat: &mut EtatSack) -> bool {
        let b = t.options.blocs[0];
        if !avant(b.0, t.ack) {
            if t.options.nb_blocs < 2 {
                return false;
            }
            let b1 = t.options.blocs[1];
            if apres(b.1, b1.1) || avant(b.0, b1.0) {
                return false;
            }
        }
        let segments = self.doublon_vu(b.0, b.1, etat);
        if segments == 0 {
            return false;
        }
        // Un doublon de ce qui est déjà oublié : on compte seulement.
        if let Some(u) = self.undo_marker
            && self.undo_retrans > 0
            && !apres(b.1, una_avant)
            && apres(b.1, u)
        {
            self.undo_retrans = (self.undo_retrans - segments as i32).max(0);
        }
        true
    }

    /// Un bloc a-t-il un sens (`tcp_is_sackblock_valid`) ? Au-delà de SND.NXT, à
    /// l'envers, ou sous SND.UNA : non. Un D-SACK peut être sous SND.UNA, entier,
    /// jusqu'à `undo_marker`, ou le recouper de moins d'une fenêtre.
    fn bloc_valide(&self, doublon: bool, debut: u32, fin: u32) -> bool {
        if apres(fin, self.snd_nxt) || !avant(debut, fin) || !avant(debut, self.snd_nxt) {
            return false;
        }
        if apres(debut, self.snd_una) {
            return true;
        }
        let Some(u) = self.undo_marker.filter(|_| doublon) else { return false };
        if apres(fin, self.snd_una) {
            return false;
        }
        if !avant(debut, u) {
            return true;
        }
        if !apres(fin, u) {
            return false;
        }
        !avant(debut, fin.wrapping_sub(self.max_fenetre))
    }

    /// Les blocs d'un ACK marquent la file (`tcp_sacktag_write_queue`).
    pub(super) fn marquer_blocs(&mut self, t: &Tcp, una_avant: u32, etat: &mut EtatSack, maintenant: u64) -> u32 {
        etat.flag = 0;
        etat.reord = self.snd_nxt;
        if self.sacked_out == 0 {
            self.fack = self.snd_una;
        }
        let doublon = self.verifier_doublon(t, una_avant, etat);
        // Trop vieux pour être cru ; plus frais, ses blocs valent encore.
        if avant(t.ack, una_avant.wrapping_sub(self.max_fenetre)) {
            return 0;
        }
        if !self.file.is_empty() {
            // Dans l'ordre de la file, pas dans celui de l'autre, qui met le plus récent en tête
            // (`tcp_sacktag_write_queue`) : sinon, deux blocs neufs du même ACK feraient croire que
            // le plus bas est arrivé après le plus haut : un réordonnancement qui n'a pas eu lieu.
            let mut blocs = [(0u32, 0u32, false); BLOCS_MAX];
            let mut n = 0;
            for k in 0..t.options.nb_blocs as usize {
                let (debut, fin) = t.options.blocs[k];
                let dup = k == 0 && doublon;
                if !self.bloc_valide(dup, debut, fin) || !apres(fin, una_avant) {
                    continue;
                }
                let mut j = n;
                while j > 0 && apres(blocs[j - 1].0, debut) {
                    blocs[j] = blocs[j - 1];
                    j -= 1;
                }
                blocs[j] = (debut, fin, dup);
                n += 1;
            }
            // Une seule passe sur la file, sans jamais revenir en arrière (`tcp_sacktag_skip`) : ce
            // qu'un bloc a vu, le suivant ne le revoit pas.
            let mut i = 0;
            for k in 0..n {
                let (debut, fin, dup) = blocs[k];
                // Le D-SACK qui suit, dans ce bloc (RFC 2883) : ses segments sont des doublons
                // (`next_dup`).
                let doublon_suivant = blocs[..n].get(k + 1).filter(|b| b.2);
                i = i.max(self.indice_avant(debut));
                while i < self.file.len() {
                    let e = self.file[i];
                    if !avant(e.seq, fin) {
                        break;
                    }
                    // Les segments entiers dans ce bloc (`tcp_match_skb_to_sack`) : un
                    // segment coupé ne compte pas à moitié.
                    let entier = |d: u32, f: u32| !apres(d, e.seq) && !avant(f, e.fin_seq);
                    let dans_le_doublon = doublon_suivant.is_some_and(|b| entier(b.0, b.1));
                    if dans_le_doublon || entier(debut, fin) {
                        self.marquer_segment(i, dup || dans_le_doublon, etat, maintenant);
                    }
                    i += 1;
                }
            }
            if self.cc.phase != Phase::Perte || self.undo_marker.is_some() {
                self.verifier_reordonnancement(etat.reord);
            }
        }
        etat.flag
    }

    /// Un segment arrivé hors d'ordre (`tcp_sacktag_one`, et ce que fait
    /// `tcp_sacktag_walk` autour).
    fn marquer_segment(&mut self, i: usize, dup: bool, etat: &mut EtatSack, maintenant: u64) {
        let e = self.file[i];
        let mut m = e.marques;
        // Un doublon d'un segment renvoyé : ce renvoi était inutile.
        if dup && m & (EN_RENVOI | DEJA_RENVOYE) != 0 {
            if let Some(u) = self.undo_marker
                && self.undo_retrans > 0
                && apres(e.fin_seq, u)
            {
                self.undo_retrans = (self.undo_retrans - 1).max(0);
            }
            if m & SACKE != 0 && avant(e.seq, etat.reord) {
                etat.reord = e.seq;
            }
        }
        if !apres(e.fin_seq, self.snd_una) {
            return;
        }
        let neuf = m & SACKE == 0;
        if neuf {
            self.rack_avancer(m, e.fin_seq, e.envoi, maintenant);
            if m & EN_RENVOI != 0 {
                // Réputé perdu et renvoyé : c'est fini pour les deux comptes. Pas
                // perdu : le renvoi reste en vol.
                if m & PERDU != 0 {
                    m &= !(PERDU | EN_RENVOI);
                    self.lost_out -= 1;
                    self.retrans_out -= 1;
                }
            } else {
                if m & DEJA_RENVOYE == 0 {
                    // Un trou comblé par un segment jamais renvoyé : c'est du
                    // réordonnancement.
                    if avant(e.seq, self.plus_haut_sack()) && avant(e.seq, etat.reord) {
                        etat.reord = e.seq;
                    }
                    if !apres(e.fin_seq, self.high_seq) {
                        etat.flag |= FLAG_ORIG_SACK_ACKED;
                    }
                    etat.premier.get_or_insert(e.envoi);
                    etat.dernier = Some(e.envoi);
                }
                if m & PERDU != 0 {
                    m &= !PERDU;
                    self.lost_out -= 1;
                }
            }
            m |= SACKE;
            etat.flag |= FLAG_DATA_SACKED;
            self.sacked_out += 1;
            etat.livres += 1;
            // `tcp_advance_highest_sack`.
            if !avant(e.seq, self.plus_haut_sack()) || self.sacked_out == 1 {
                self.fack = e.fin_seq;
            }
        }
        if dup && m & EN_RENVOI != 0 {
            m &= !EN_RENVOI;
            self.retrans_out -= 1;
        }
        self.file[i].marques = m;
        if neuf {
            self.taux_segment_livre(i, etat);
        }
    }

    /// Un segment jamais renvoyé arrive après un plus loin que lui : le degré de
    /// réordonnancement grandit (`tcp_check_sack_reordering`), en segments, et
    /// l'événement compte : il rouvre la fenêtre de RACK.
    pub(super) fn verifier_reordonnancement(&mut self, bas: u32) {
        let fack = self.plus_haut_sack();
        if !avant(bas, fack) {
            return;
        }
        let distance = fack.wrapping_sub(bas);
        let mss = self.mss as u32;
        if mss > 0 && distance > self.reordering * mss {
            self.reordering = distance.div_ceil(mss).min(super::TCP_MAX_REORDERING);
        }
        self.reord_seen += 1;
    }

    // --- RACK ---

    /// `tcp_rack_reo_wnd`.
    fn rack_fenetre(&self) -> u64 {
        if self.reord_seen == 0 && (self.cc.phase >= Phase::Reprise || self.sacked_out >= self.reordering) {
            return 0;
        }
        (self.min_rtt.valeur() >> 2).saturating_mul(self.rack.pas as u64).min(self.rtt.srtt())
    }

    /// `tcp_rack_skb_timeout` : ce qu'il reste à attendre pour ce segment.
    pub(super) fn rack_restant(&self, envoi: u64, fenetre: u64, maintenant: u64) -> i64 {
        (self.rack.rtt + fenetre) as i64 - maintenant.saturating_sub(envoi) as i64
    }

    /// `tcp_rack_detect_loss` : rend le plus long à attendre encore.
    fn rack_detecter(&mut self, maintenant: u64) -> u64 {
        let fenetre = self.rack_fenetre();
        let mut attente = 0;
        let mut k = 0;
        while let Some(&(seq, envoi)) = self.tri.get(k) {
            let i = self.indice_de(seq);
            let e = self.file.get(i).copied();
            let Some(e) = e.filter(|e| e.seq == seq && e.envoi == envoi && e.marques & SACKE == 0) else {
                // Acquitté, SACKé, renvoyé depuis, ou fondu dans un autre.
                self.tri.remove(k);
                continue;
            };
            if e.marques & PERDU != 0 && e.marques & EN_RENVOI == 0 {
                k += 1;
                continue;
            }
            if !parti_apres(self.rack.mstamp, e.envoi, self.rack.fin_seq, e.fin_seq) {
                break;
            }
            let reste = self.rack_restant(e.envoi, fenetre, maintenant);
            if reste <= 0 {
                self.marquer_perdu(i);
                self.tri.remove(k);
            } else {
                attente = attente.max(reste as u64);
                k += 1;
            }
        }
        attente
    }

    /// `tcp_rack_mark_lost` : rend vrai si un segment attend encore, et que le
    /// minuteur de réordonnancement est armé.
    pub(super) fn rack_marquer(&mut self, maintenant: u64) -> bool {
        if !self.rack.avance {
            return false;
        }
        self.rack.avance = false;
        let attente = self.rack_detecter(maintenant);
        if attente > 0 {
            let d = en_jiffies(attente + TIMEOUT_MIN).min(self.rto);
            self.armer_xmit(super::Minuteur::Reordonnancement, d, maintenant);
        }
        attente > 0
    }

    /// `tcp_rack_advance`.
    pub(super) fn rack_avancer(&mut self, marques: u8, fin_seq: u32, envoi: u64, maintenant: u64) {
        let rtt = maintenant.saturating_sub(envoi);
        // Un segment renvoyé revenu trop vite : c'est l'original, pas le renvoi.
        if rtt < self.min_rtt.valeur() && marques & (EN_RENVOI | DEJA_RENVOYE) != 0 {
            return;
        }
        self.rack.avance = true;
        self.rack.rtt = rtt;
        if parti_apres(envoi, self.rack.mstamp, fin_seq, self.rack.fin_seq) {
            self.rack.mstamp = envoi;
            self.rack.fin_seq = fin_seq;
        }
    }

    /// `tcp_rack_update_reo_wnd` : un pas de plus par D-SACK dû au
    /// réordonnancement, au plus un par aller-retour ; gardé RACK_PERSISTE
    /// reprises, puis retour à un pas.
    pub(super) fn rack_maj_fenetre(&mut self, prior_livres: Option<u32>) {
        let Some(prior) = prior_livres else { return };
        if avant(prior, self.rack.dernier_livre) {
            self.rack.dsack_vu = false;
        }
        if self.rack.dsack_vu {
            self.rack.pas = (self.rack.pas + 1).min(0xFF);
            self.rack.dsack_vu = false;
            self.rack.dernier_livre = self.livres;
            self.rack.persiste = RACK_PERSISTE;
        } else if self.rack.persiste == 0 {
            self.rack.pas = 1;
        }
    }

    /// Le minuteur de réordonnancement est échu (`tcp_rack_reo_timeout`).
    pub(super) fn minuteur_reordonnancement(&mut self, maintenant: u64, e: &mut super::Effets) {
        let en_vol = self.paquets_en_vol();
        let perdus = self.perdus;
        self.rack_detecter(maintenant);
        if en_vol != self.paquets_en_vol() {
            if self.cc.phase != Phase::Reprise {
                self.entrer_reprise();
                self.reduire_cwnd(1, self.perdus.wrapping_sub(perdus), 0);
            }
            self.rexmit = super::Rexmit::Perdus;
            e.a_emettre = true;
        }
        self.rearmer_rto(maintenant);
    }

    // --- TLP ---

    /// Arme la sonde de fin de rafale (`tcp_schedule_loss_probe`) : avec SACK,
    /// hors de toute reprise, 2 × SRTT plus de quoi laisser partir un ACK retardé
    /// s'il n'y a qu'un segment en vol (200 ms), sinon 2 ms ; sans mesure, 1 s ; pas
    /// après le RTO. Rend vrai si elle est armée.
    pub(super) fn programmer_sonde_de_perte(&mut self, rto_repart: bool, maintenant: u64) -> bool {
        if !self.sack_ok || !matches!(self.cc.phase, Phase::Ouverte | Phase::Reduction) {
            return false;
        }
        let Some(tete) = self.file.front().copied() else { return false };
        let mut d = if self.rtt.mesure() {
            en_jiffies(2 * self.rtt.srtt() + if self.file.len() == 1 { RTO_MIN } else { TIMEOUT_MIN })
        } else {
            RTO_INITIAL
        };
        let rto = if rto_repart { self.rto as i64 } else { (tete.envoi + self.rto) as i64 - maintenant as i64 };
        if rto > 0 {
            d = d.min(en_jiffies(rto as u64));
        }
        self.armer_xmit(super::Minuteur::SondeDePerte, d, maintenant);
        true
    }

    /// La sonde part (`tcp_send_loss_probe`) : une seule à la fois ; un segment
    /// neuf, si la fenêtre de l'autre le laisse (la cwnd, non : c'est toute
    /// l'idée) ; sinon le dernier, renvoyé. Puis le RTO repart.
    pub(super) fn envoyer_sonde_de_perte(&mut self, maintenant: u64, sortir: &mut impl FnMut(Sortant)) {
        if self.tlp_high_seq.is_none() {
            self.tlp_renvoi = false;
            let mut partie = false;
            let bord = self.snd_una.wrapping_add(self.snd_wnd);
            if let Some(l) = self.prochain_segment()
                && !apres(self.snd_nxt.wrapping_add(l), bord)
            {
                let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
                let reste = self.octets_envoi.saturating_sub(debut);
                let n = reste.min(self.mss_courant() as usize);
                let avec_fin = self.fin_seq().is_some_and(|f| !apres(self.snd_nxt, f)) && n == reste;
                // `tcp_write_xmit` (`push_one` à 2) : TSQ a son mot à dire, et ce qui part compte.
                partie = !self.carte_trop_pleine(n, 0) && self.envoyer_donnees(n, avec_fin, maintenant, false, sortir);
                if partie {
                    self.apres_xmit(1, maintenant);
                }
            } else if !self.file.is_empty() && self.envoyer_entree(self.file.len() - 1, maintenant, sortir) {
                self.tlp_renvoi = true;
                partie = true;
            }
            if partie {
                self.tlp_high_seq = Some(self.snd_nxt);
                self.t_sorte = super::Minuteur::Retransmission;
            }
        }
        self.rearmer_rto(maintenant);
    }

    /// L'ACK pendant une sonde (`tcp_process_tlp_ack`) : l'original et la sonde sont
    /// arrivés (un D-SACK d'elle, ou un ACK dupliqué pur) : rien de perdu ; un ACK
    /// qui passe la sonde renvoyée : il y avait bien une perte, la cwnd réduit, en
    /// CWR : le renvoi l'a réparée, sans reprise.
    pub(super) fn traiter_ack_de_sonde(&mut self, ack: u32, flag: u32) {
        let Some(haut) = self.tlp_high_seq else { return };
        if avant(ack, haut) {
            return;
        }
        if !self.tlp_renvoi || flag & FLAG_DSACK_TLP != 0 {
            self.tlp_high_seq = None;
        } else if apres(ack, haut) {
            self.commencer_reduction();
            self.changer_phase(Phase::Reduction);
            self.finir_reduction();
            self.rester_ouverte();
        } else if flag & (FLAG_SND_UNA_ADVANCED | FLAG_NOT_DUP | FLAG_DATA_SACKED) == 0 {
            self.tlp_high_seq = None;
        }
    }

    /// Retient l'envoi d'un segment, pour RACK (`tsorted_sent_queue`) ; nettoie la
    /// file quand elle s'allonge pour rien.
    pub(super) fn tri_ajouter(&mut self, seq: u32, envoi: u64) {
        if !self.sack_ok {
            return;
        }
        if self.tri.len() > 2 * self.file.len() + 16 {
            let file = &self.file;
            self.tri.retain(|&(s, t)| {
                let i = file.partition_point(|e| avant(e.seq, s));
                file.get(i).is_some_and(|e| e.seq == s && e.envoi == t)
            });
        }
        let _ = self.tri.ajouter_derriere((seq, envoi));
    }
}

#[cfg(test)]
mod tests {
    use super::super::essais::*;
    use super::super::retrans::{DEJA_RENVOYE, EN_RENVOI, FLAG_DATA, FLAG_DATA_ACKED, FLAG_RETRANS_DATA_ACKED, FLAG_SYN_ACKED, FLAG_WIN_UPDATE, PERDU, SACKE};
    use super::*;
    use formats::reseau::tcp;

    fn avec(sack: bool, n: usize) -> C {
        let mut c = etablie(sack);
        en_vol(&mut c, n);
        c
    }

    /// `tcp_dsack_seen`.
    #[test]
    fn un_doublon_vu() {
        let mut c = avec(true, 3);
        c.mss = 1000;
        c.max_fenetre = 10_000;
        c.total_retrans = 100;
        let mut e = EtatSack::default();
        // Vide, ou à l'envers.
        assert_eq!(c.doublon_vu(50, 50, &mut e), 0);
        assert_eq!(c.doublon_vu(50, 49, &mut e), 0);
        assert_eq!((c.dsack_doublons, e.flag), (0, 0));
        // Plus grand que la fenêtre.
        assert_eq!(c.doublon_vu(0, 10_001, &mut e), 0);
        assert_eq!(c.dsack_doublons, 0);
        // Exactement la fenêtre.
        assert_eq!(c.doublon_vu(0, 10_000, &mut e), 10);
        assert_eq!((c.dsack_doublons, e.livres), (10, 10));
        assert_ne!(e.flag & FLAG_DSACKING_ACK, 0);
        // Des segments : arrondi au-dessus, au moins un.
        assert_eq!(c.doublon_vu(0, 1001, &mut e), 2);
        assert_eq!(c.doublon_vu(0, 1000, &mut e), 1);
        assert_eq!(c.doublon_vu(0, 1, &mut e), 1);
        assert_eq!(e.flag & FLAG_DSACK_TLP, 0);
        assert!(!c.rack.dsack_vu, "aucun désordre vu");
        // Du désordre vu : RACK élargit sa fenêtre.
        c.reord_seen = 1;
        c.doublon_vu(0, 1, &mut e);
        assert!(c.rack.dsack_vu);
        // Plus de doublons que de renvois : pas cru. Tout juste autant : oui.
        let mut c = avec(true, 1);
        c.max_fenetre = 10_000;
        c.total_retrans = 2;
        let mut e = EtatSack::default();
        assert_eq!(c.doublon_vu(0, 2000, &mut e), 2);
        assert_ne!(e.flag & FLAG_DSACKING_ACK, 0);
        let mut e = EtatSack::default();
        assert_eq!(c.doublon_vu(0, 1, &mut e), 0);
        assert_eq!((e.flag, e.livres, c.dsack_doublons), (0, 0, 3));
    }

    /// Le doublon de notre sonde.
    #[test]
    fn le_doublon_de_la_sonde() {
        let mut c = avec(true, 1);
        c.max_fenetre = 10_000;
        c.total_retrans = 10;
        c.reord_seen = 1;
        c.tlp_high_seq = Some(1000);
        let mut e = EtatSack::default();
        c.doublon_vu(0, 1000, &mut e);
        assert_ne!(e.flag & FLAG_DSACK_TLP, 0);
        assert!(!c.rack.dsack_vu, "pas du désordre");
        // Une autre fin, ou plus d'un MSS : non.
        let mut e = EtatSack::default();
        c.doublon_vu(0, 999, &mut e);
        assert_eq!(e.flag & FLAG_DSACK_TLP, 0);
        c.tlp_high_seq = Some(1001);
        let mut e = EtatSack::default();
        c.doublon_vu(0, 1001, &mut e);
        assert_eq!(e.flag & FLAG_DSACK_TLP, 0);
    }

    fn segment(ack: u32, blocs: &[(u32, u32)]) -> Tcp {
        let mut t = Tcp { ack, ..Tcp::default() };
        for (k, b) in blocs.iter().enumerate() {
            t.options.blocs[k] = *b;
        }
        t.options.nb_blocs = blocs.len() as u8;
        t
    }

    /// `tcp_check_dsack`.
    #[test]
    fn verifier_un_doublon() {
        let prete = || {
            let mut c = avec(true, 1);
            c.max_fenetre = 100_000;
            c.total_retrans = 100;
            c
        };
        let ack = 10_000;
        // Le premier bloc sous l'ACK : un doublon.
        let mut c = prete();
        let mut e = EtatSack::default();
        assert!(c.verifier_doublon(&segment(ack, &[(ack - 100, ack)]), ack, &mut e));
        // Au-dessus, seul : non.
        let mut c = prete();
        assert!(!c.verifier_doublon(&segment(ack, &[(ack, ack + 100)]), ack, &mut e));
        assert_eq!(c.dsack_doublons, 0);
        // Au-dessus, dans le second : oui, bords compris.
        let mut c = prete();
        assert!(c.verifier_doublon(&segment(ack, &[(ack + 100, ack + 200), (ack + 100, ack + 200)]), ack, &mut e));
        // Il dépasse du second, d'un côté ou de l'autre : non.
        let mut c = prete();
        assert!(!c.verifier_doublon(&segment(ack, &[(ack + 100, ack + 201), (ack + 100, ack + 200)]), ack, &mut e));
        assert!(!c.verifier_doublon(&segment(ack, &[(ack + 99, ack + 200), (ack + 100, ack + 200)]), ack, &mut e));
        assert_eq!(c.dsack_doublons, 0);
        // Pas cru : faux.
        let mut c = prete();
        c.total_retrans = 0;
        assert!(!c.verifier_doublon(&segment(ack, &[(ack - 100, ack)]), ack, &mut e));
    }

    /// Un doublon de ce qui est déjà acquitté : l'annulation avance.
    #[test]
    fn un_doublon_compte_pour_l_annulation() {
        let prete = || {
            let mut c = avec(true, 1);
            c.max_fenetre = 100_000;
            c.total_retrans = 100;
            c.mss = 1000;
            c.undo_marker = Some(5000);
            c.undo_retrans = 3;
            c
        };
        let ack = 10_000;
        let mut e = EtatSack::default();
        let mut c = prete();
        c.verifier_doublon(&segment(ack, &[(6000, 8000)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 1, "deux segments");
        c.verifier_doublon(&segment(ack, &[(6000, 8000)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 0);
        c.verifier_doublon(&segment(ack, &[(6000, 8000)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 0, "pas sous zéro");
        // Au-dessus de l'ancien SND.UNA : `marquer_segment` s'en occupe.
        let mut c = prete();
        c.verifier_doublon(&segment(ack, &[(6000, 8001)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 3);
        // Sous le début de l'épisode.
        let mut c = prete();
        c.verifier_doublon(&segment(ack, &[(4000, 5000)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 3);
        let mut c = prete();
        c.verifier_doublon(&segment(ack, &[(4000, 5001)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 1, "deux segments, dont un bout dans l'épisode");
        // Pas d'épisode, ou rien à annuler.
        let mut c = prete();
        c.undo_marker = None;
        c.verifier_doublon(&segment(ack, &[(6000, 8000)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 3);
        let mut c = prete();
        c.undo_retrans = 0;
        c.verifier_doublon(&segment(ack, &[(6000, 8000)]), 8000, &mut e);
        assert_eq!(c.undo_retrans, 0);
    }

    /// `tcp_sacktag_one`.
    #[test]
    fn marquer_un_segment_neuf() {
        let mut c = avec(true, 3);
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.high_seq = fin(2);
        c.marquer_segment(2, false, &mut e, HEURE + MS);
        assert_ne!(c.file[2].marques & SACKE, 0);
        assert_eq!((c.sacked_out, e.livres), (1, 1));
        assert_ne!(e.flag & FLAG_DATA_SACKED, 0);
        assert_ne!(e.flag & FLAG_ORIG_SACK_ACKED, 0);
        assert_eq!((e.premier, e.dernier), (Some(HEURE), Some(HEURE)));
        assert_eq!(c.fack, fin(2));
        assert!(c.rack.avance);
        assert_eq!(e.reord, c.snd_nxt, "le plus haut : pas de désordre");
        // Un trou comblé plus bas : du désordre ; le plus haut ne recule pas.
        c.high_seq = fin(0) - 1;
        c.file[0].envoi = HEURE + 1;
        c.marquer_segment(0, false, &mut e, HEURE + MS);
        assert_eq!(e.reord, debut(0));
        assert_eq!(c.fack, fin(2));
        assert_eq!(e.dernier, Some(HEURE + 1));
        assert_eq!(e.premier, Some(HEURE));
        // Déjà SACKé : rien de plus.
        let f = e.flag;
        c.marquer_segment(2, false, &mut e, HEURE + MS);
        assert_eq!((c.sacked_out, e.livres, e.flag), (2, 2, f));
    }

    #[test]
    fn marquer_un_segment_perdu_ou_renvoye() {
        // Perdu, jamais renvoyé : plus perdu.
        let mut c = avec(true, 3);
        c.file[0].marques = PERDU;
        c.lost_out = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(0, false, &mut e, HEURE + MS);
        assert_eq!(c.lost_out, 0);
        assert_eq!(c.file[0].marques & PERDU, 0);
        // Perdu et renvoyé : fini pour les deux comptes.
        let mut c = avec(true, 3);
        c.file[0].marques = PERDU | EN_RENVOI | DEJA_RENVOYE;
        c.lost_out = 1;
        c.retrans_out = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(0, false, &mut e, HEURE + MS);
        assert_eq!((c.lost_out, c.retrans_out), (0, 0));
        assert_eq!(c.file[0].marques & (PERDU | EN_RENVOI), 0);
        assert_eq!(e.premier, None, "renvoyé : pas de mesure");
        // En renvoi, pas perdu : le renvoi reste en vol.
        let mut c = avec(true, 3);
        c.file[0].marques = EN_RENVOI | DEJA_RENVOYE;
        c.retrans_out = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(0, false, &mut e, HEURE + MS);
        assert_eq!(c.retrans_out, 1);
        assert_ne!(c.file[0].marques & EN_RENVOI, 0);
        // Déjà renvoyé, plus en vol, et perdu : le perdu tombe, sans mesure ni désordre.
        let mut c = avec(true, 3);
        c.file[0].marques = PERDU | DEJA_RENVOYE;
        c.lost_out = 1;
        c.fack = fin(2);
        c.sacked_out = 1;
        c.high_seq = fin(2);
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(0, false, &mut e, HEURE + MS);
        assert_eq!(c.lost_out, 0);
        assert_eq!((e.premier, e.reord), (None, c.snd_nxt));
        assert_eq!(e.flag & FLAG_ORIG_SACK_ACKED, 0);
    }

    #[test]
    fn marquer_un_doublon() {
        // Le doublon d'un renvoi : ce renvoi était inutile.
        let mut c = avec(true, 3);
        c.file[1].marques = EN_RENVOI | DEJA_RENVOYE;
        c.retrans_out = 1;
        c.undo_marker = Some(debut(0));
        c.undo_retrans = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(1, true, &mut e, HEURE + MS);
        assert_eq!(c.undo_retrans, 0);
        assert_eq!(c.retrans_out, 0);
        assert_eq!(c.file[1].marques & EN_RENVOI, 0);
        // Rien à annuler : pas sous 0 ; pas d'épisode ; sous l'épisode.
        for (marque, retrans, attendu) in [(Some(debut(0)), 0, 0), (None, 1, 1), (Some(fin(1)), 1, 1)] {
            let mut c = avec(true, 3);
            c.file[1].marques = DEJA_RENVOYE;
            c.undo_marker = marque;
            c.undo_retrans = retrans;
            let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
            c.marquer_segment(1, true, &mut e, HEURE + MS);
            assert_eq!(c.undo_retrans, attendu, "{marque:?} {retrans}");
        }
        // Jamais renvoyé : un doublon n'y change rien.
        let mut c = avec(true, 3);
        c.undo_marker = Some(debut(0));
        c.undo_retrans = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(1, true, &mut e, HEURE + MS);
        assert_eq!(c.undo_retrans, 1);
        // Pas un doublon : le renvoi reste.
        let mut c = avec(true, 3);
        c.file[1].marques = EN_RENVOI | DEJA_RENVOYE;
        c.retrans_out = 1;
        c.undo_marker = Some(debut(0));
        c.undo_retrans = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(1, false, &mut e, HEURE + MS);
        assert_eq!((c.undo_retrans, c.retrans_out), (1, 1));
        // Déjà SACKé et renvoyé, le doublon dit où commence le désordre.
        let mut c = avec(true, 3);
        c.file[1].marques = SACKE | DEJA_RENVOYE;
        c.sacked_out = 1;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(1, true, &mut e, HEURE + MS);
        assert_eq!(e.reord, debut(1));
        let mut e = EtatSack { reord: debut(0), ..EtatSack::default() };
        c.marquer_segment(1, true, &mut e, HEURE + MS);
        assert_eq!(e.reord, debut(0));
        let mut c = avec(true, 3);
        c.file[1].marques = DEJA_RENVOYE;
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.fack = fin(1);
        c.marquer_segment(1, true, &mut e, HEURE + MS);
        assert_eq!(e.reord, c.snd_nxt, "pas SACKé");
        // Sous SND.UNA : compté pour l'annulation, sans plus.
        let mut c = avec(true, 3);
        c.file[0].marques = DEJA_RENVOYE;
        c.undo_marker = Some(debut(0));
        c.undo_retrans = 1;
        c.snd_una = fin(0);
        let mut e = EtatSack { reord: c.snd_nxt, ..EtatSack::default() };
        c.marquer_segment(0, true, &mut e, HEURE + MS);
        assert_eq!(c.undo_retrans, 0);
        assert_eq!((c.sacked_out, e.livres), (0, 0));
    }

    /// `tcp_check_sack_reordering`.
    #[test]
    fn verifier_le_reordonnancement() {
        let mut c = avec(true, 1);
        c.mss = 100;
        c.sacked_out = 1;
        c.fack = 10_000;
        c.reordering = 3;
        c.verifier_reordonnancement(10_000);
        assert_eq!(c.reord_seen, 0, "pas sous le plus haut");
        c.verifier_reordonnancement(9700);
        assert_eq!((c.reord_seen, c.reordering), (1, 3), "tout juste trois");
        c.verifier_reordonnancement(9699);
        assert_eq!((c.reord_seen, c.reordering), (2, 4), "arrondi au-dessus");
        c.verifier_reordonnancement(9000);
        assert_eq!(c.reordering, 10);
        c.reordering = 3;
        c.fack = 1 << 20;
        c.verifier_reordonnancement(0);
        assert_eq!(c.reordering, crate::tcp::TCP_MAX_REORDERING);
    }

    /// `tcp_rack_advance`.
    #[test]
    fn rack_avancer_() {
        let mut c = avec(true, 1);
        c.min_rtt.mesure(1 << 40, HEURE, 10 * MS);
        // Un renvoi revenu trop vite : c'est l'original.
        for m in [EN_RENVOI, DEJA_RENVOYE] {
            c.rack.avance = false;
            c.rack_avancer(m, 100, HEURE, HEURE + 10 * MS - 1);
            assert!(!c.rack.avance, "{m}");
        }
        // Pas si vite, ou jamais renvoyé : il compte.
        c.rack_avancer(EN_RENVOI, 100, HEURE, HEURE + 10 * MS);
        assert!(c.rack.avance);
        assert_eq!((c.rack.rtt, c.rack.mstamp, c.rack.fin_seq), (10 * MS, HEURE, 100));
        c.rack_avancer(0, 200, HEURE, HEURE + MS);
        assert_eq!((c.rack.rtt, c.rack.mstamp, c.rack.fin_seq), (MS, HEURE, 200), "même heure, plus loin");
        // Parti avant : le RTT suit, le reste non.
        c.rack_avancer(0, 300, HEURE - MS, HEURE + MS);
        assert_eq!((c.rack.rtt, c.rack.mstamp, c.rack.fin_seq), (2 * MS, HEURE, 200));
        c.rack_avancer(0, 100, HEURE, HEURE + MS);
        assert_eq!(c.rack.fin_seq, 200, "même heure, plus près");
    }

    /// `tcp_rack_detect_loss`.
    #[test]
    fn rack_detecter_() {
        let prete = || {
            let mut c = avec(true, 3);
            c.rack.rtt = 10 * MS;
            c.rack.mstamp = HEURE;
            c.rack.fin_seq = fin(2);
            c.reord_seen = 0;
            c.cc.phase = Phase::Reprise;
            c
        };
        // Fenêtre nulle en reprise, sans désordre vu ; assez de temps : tout est perdu, sauf ce qui
        // part après ce qui est arrivé.
        let mut c = prete();
        c.rack.fin_seq = fin(1);
        assert_eq!(c.rack_detecter(HEURE + 10 * MS), 0);
        assert_eq!((c.file[0].marques & PERDU, c.file[1].marques & PERDU, c.file[2].marques & PERDU), (PERDU, 0, 0));
        assert_eq!(c.tri.len(), 2, "le perdu quitte le tri");
        // Encore à attendre : la plus longue attente.
        let mut c = prete();
        c.file[0].envoi = HEURE - 3 * MS;
        c.tri.clear();
        c.tri.push_back((debut(0), HEURE - 3 * MS));
        c.tri.push_back((debut(1), HEURE));
        c.rack.fin_seq = fin(2);
        assert_eq!(c.rack_detecter(HEURE + 4 * MS), 6 * MS);
        assert_eq!(c.lost_out, 0);
        assert_eq!(c.tri.len(), 2);
        // Un renvoi déjà marqué, en vol : son renvoi peut être perdu. Marqué et pas renvoyé : sauté.
        let mut c = prete();
        c.file[0].marques = PERDU;
        c.lost_out = 1;
        c.file[1].marques = PERDU | EN_RENVOI;
        c.lost_out = 2;
        c.retrans_out = 1;
        assert_eq!(c.rack_detecter(HEURE + 100 * MS), 0);
        assert_eq!(c.retrans_out, 0);
        assert_eq!(c.tri.len(), 2, "le premier reste, marqué, pas renvoyé ; le dernier n'est pas parti avant");
        // SACKé, ou renvoyé depuis : l'entrée du tri est vieille, elle s'en va.
        let mut c = prete();
        c.file[0].marques = SACKE;
        c.file[1].envoi = HEURE + 1;
        c.rack.fin_seq = fin(2);
        c.rack.mstamp = HEURE + 1;
        c.rack_detecter(HEURE + 100 * MS);
        assert!(c.tri.len() <= 1);
        assert_eq!(c.file[0].marques & PERDU, 0);
    }

    #[test]
    fn rack_marquer_() {
        let mut c = avec(true, 2);
        c.rack.rtt = 10 * MS;
        c.rack.mstamp = HEURE;
        c.rack.fin_seq = fin(1);
        c.cc.phase = Phase::Reprise;
        // Rien de neuf : rien.
        c.rack.avance = false;
        assert!(!c.rack_marquer(HEURE + 100 * MS));
        assert_eq!(c.lost_out, 0);
        // Il y a à attendre : le minuteur, borné par le RTO, en tics.
        c.rack.avance = true;
        c.rto = 1000 * MS;
        assert!(c.rack_marquer(HEURE + 4 * MS));
        assert!(!c.rack.avance);
        assert_eq!(c.t_sorte, crate::tcp::Minuteur::Reordonnancement);
        assert_eq!(c.t_xmit, Some(HEURE + 4 * MS + en_jiffies(6 * MS + TIMEOUT_MIN)));
        c.rack.avance = true;
        c.rto = MS;
        assert!(c.rack_marquer(HEURE + 4 * MS));
        assert_eq!(c.t_xmit, Some(HEURE + 4 * MS + MS));
        // Plus rien à attendre : tout marqué.
        c.rack.avance = true;
        assert!(!c.rack_marquer(HEURE + 100 * MS));
        assert_eq!(c.lost_out, 1, "le dernier arrivé lui-même n'est pas parti avant");
    }

    /// `tcp_current_mss` : quatre octets, et huit par bloc.
    #[test]
    fn la_place_des_blocs() {
        let mut c = etablie(true);
        assert_eq!(c.place_des_blocs(), 0);
        for (n, place) in [(1, 12), (2, 20), (3, 28)] {
            c.nb_blocs = n;
            for i in 0..n as usize {
                c.blocs[i] = (1000 * (i as u32 + 1), 1000 * (i as u32 + 1) + 500);
            }
            assert_eq!(c.place_des_blocs(), place, "{n}");
        }
    }

    /// Un ACK comprimé part quand un bloc qui n'est pas des tout premiers est touché, ou qu'il
    /// y en aurait trop.
    #[test]
    fn un_nouveau_bloc_et_l_ack_comprime() {
        let prete = |n: usize| {
            let mut c = etablie(true);
            for i in 0..n {
                c.blocs[i] = (10_000 * (i as u32 + 1), 10_000 * (i as u32 + 1) + 500);
            }
            c.nb_blocs = n as u8;
            c.ack_comprimes = 2;
            c
        };
        // Le premier bloc touché : l'ACK attend encore.
        let mut c = prete(3);
        c.nouveau_bloc(10_500, 10_600);
        assert_eq!(c.ack_comprimes, 2);
        // Le deuxième, non plus.
        let mut c = prete(3);
        c.nouveau_bloc(20_500, 20_600);
        assert_eq!(c.ack_comprimes, 2);
        // Le troisième : il part.
        let mut c = prete(3);
        c.nouveau_bloc(30_500, 30_600);
        assert_eq!(c.ack_comprimes, 0);
        assert_eq!(c.blocs[0], (30_000, 30_600));
    }

    /// Le premier bloc mange ceux qu'il touche, les autres remontent d'une place.
    #[test]
    fn fusionner_les_blocs() {
        let mut c = etablie(true);
        c.blocs[0] = (1000, 2000);
        c.blocs[1] = (2000, 3000);
        c.blocs[2] = (5000, 6000);
        c.blocs[3] = (7000, 8000);
        c.nb_blocs = 4;
        c.fusionner_blocs();
        assert_eq!(c.nb_blocs, 3);
        assert_eq!(&c.blocs[..3], &[(1000, 3000), (5000, 6000), (7000, 8000)]);
    }

    /// Les blocs que RCV.NXT a dépassés partent, l'ordre des autres reste.
    #[test]
    fn retirer_les_blocs() {
        let mut c = etablie(true);
        let base = c.rcv_nxt;
        c.hors_ordre.ranger(base + 1000, octets(100, 200)).unwrap();
        c.blocs[0] = (base + 1000, base + 1100);
        c.blocs[1] = (base.wrapping_sub(500), base);
        c.blocs[2] = (base + 3000, base + 3100);
        c.blocs[3] = (base.wrapping_sub(900), base.wrapping_sub(800));
        c.nb_blocs = 4;
        c.retirer_blocs();
        assert_eq!(c.nb_blocs, 2);
        assert_eq!(&c.blocs[..2], &[(base + 1000, base + 1100), (base + 3000, base + 3100)]);
        // Tout juste RCV.NXT au début du bloc : dépassé.
        c.blocs[0] = (base, base + 100);
        c.nb_blocs = 1;
        c.retirer_blocs();
        assert_eq!(c.nb_blocs, 0);
    }

    /// Un D-SACK dans le deuxième bloc, quel que soit le nombre de blocs, et ce qu'il défait.
    #[test]
    fn verifier_un_doublon_dans_le_deuxieme_bloc() {
        let prete = || {
            let mut c = avec(true, 4);
            c.max_fenetre = 100_000;
            c.total_retrans = 100;
            c
        };
        let segment = |blocs: &[(u32, u32)]| {
            let mut o = tcp::Options::default();
            for (i, b) in blocs.iter().enumerate() {
                o.blocs[i] = *b;
            }
            o.nb_blocs = blocs.len() as u8;
            Tcp { ack: debut(0), drapeaux: tcp::ACK, options: o, ..Tcp::default() }
        };
        let dedans = (debut(1), fin(1));
        let large = (debut(1), fin(2));
        for blocs in [&[dedans, large][..], &[dedans, large, (debut(3), fin(3))][..]] {
            let mut c = prete();
            let mut e = EtatSack::default();
            assert!(c.verifier_doublon(&segment(blocs), debut(0), &mut e), "{}", blocs.len());
        }
        // Seul, au-dessus de l'ACK : pas un doublon.
        let mut c = prete();
        let mut e = EtatSack::default();
        assert!(!c.verifier_doublon(&segment(&[dedans]), debut(0), &mut e));
        // Sous l'ACK : un de moins à démentir, pas une division.
        let mut c = prete();
        c.undo_marker = Some(debut(0).wrapping_sub(5000));
        c.undo_retrans = 3;
        let mut s = segment(&[(debut(0).wrapping_sub(2000), debut(0).wrapping_sub(1000))]);
        s.ack = debut(0);
        let mut e = EtatSack::default();
        assert!(c.verifier_doublon(&s, debut(0), &mut e));
        assert_eq!(c.undo_retrans, 2);
    }

    /// `tcp_is_sackblock_valid` : à l'envers, jamais.
    #[test]
    fn un_bloc_a_l_envers() {
        let c = avec(true, 3);
        assert!(c.bloc_valide(false, debut(1), fin(1)));
        assert!(!c.bloc_valide(false, fin(1), debut(1)));
        assert!(!c.bloc_valide(false, debut(1), debut(1)));
    }

    /// `tcp_is_sackblock_valid`, pour un D-SACK sous SND.UNA : jusqu'à `undo_marker`, ou le recoupant
    /// de moins d'une fenêtre.
    #[test]
    fn un_doublon_valide() {
        let mut c = avec(true, 3);
        c.snd_una = debut(1);
        c.undo_marker = Some(debut(0));
        c.max_fenetre = 3000;
        // Entier, depuis `undo_marker` ou au-dessus.
        assert!(c.bloc_valide(true, debut(0), fin(0)));
        assert!(!c.bloc_valide(false, debut(0), fin(0)), "pas un D-SACK");
        // Entier sous `undo_marker` : trop vieux.
        assert!(!c.bloc_valide(true, debut(0) - 500, debut(0)));
        // À cheval sur `undo_marker`, de moins d'une fenêtre ; tout juste une ; plus.
        assert!(c.bloc_valide(true, debut(0) - 500, debut(0) + 500));
        assert!(c.bloc_valide(true, fin(0) - 3000, fin(0)));
        assert!(!c.bloc_valide(true, fin(0) - 3001, fin(0)));
    }

    fn segment_avec(blocs: &[(u32, u32)]) -> Tcp {
        let mut o = tcp::Options::default();
        for (i, b) in blocs.iter().enumerate() {
            o.blocs[i] = *b;
        }
        o.nb_blocs = blocs.len() as u8;
        Tcp { ack: debut(0), drapeaux: tcp::ACK, options: o, ..Tcp::default() }
    }

    /// Seul le premier bloc d'un ACK peut être un D-SACK, et seulement si `verifier_doublon` l'a dit ;
    /// un D-SACK suivi de plus large : ses segments restent des doublons.
    #[test]
    fn marquer_les_blocs_et_les_doublons() {
        let prete = || {
            let mut c = avec(true, 4);
            c.max_fenetre = 100_000;
            c.total_retrans = 100;
            c.undo_marker = Some(debut(0));
            c.undo_retrans = 2;
            for i in 1..4 {
                c.file[i].marques = DEJA_RENVOYE;
            }
            c
        };
        // Un SACK ordinaire d'un segment renvoyé : l'annulation n'y croit pas.
        let mut c = prete();
        c.marquer_blocs(&segment_avec(&[(debut(1), fin(1))]), debut(0), &mut EtatSack::default(), HEURE + MS);
        assert_eq!(c.undo_retrans, 2);
        // Le D-SACK de la RFC 2883 dans le bloc plus large qui suit : le segment est un doublon.
        let mut c = prete();
        c.marquer_blocs(&segment_avec(&[(debut(2), fin(2)), (debut(1), fin(3))]), debut(0), &mut EtatSack::default(), HEURE + MS);
        assert_eq!(c.undo_retrans, 1, "un seul : celui du doublon");
        assert_eq!(c.sacked_out, 3);
    }

    /// Un seuil en segments, pas autre chose : deux MSS de distance, sous trois de `reordering`.
    #[test]
    fn verifier_le_reordonnancement_sous_le_seuil() {
        let mut c = avec(true, 1);
        c.mss = 100;
        c.sacked_out = 1;
        c.fack = 10_000;
        c.reordering = 3;
        c.verifier_reordonnancement(9800);
        assert_eq!((c.reord_seen, c.reordering), (1, 3));
        // Pas de MSS : pas de division, le désordre est compté quand même.
        c.mss = 0;
        c.verifier_reordonnancement(9000);
        assert_eq!((c.reord_seen, c.reordering), (2, 3));
    }

    /// `tcp_rack_reo_wnd` : le quart de `min_rtt`, par pas, au plus SRTT.
    #[test]
    fn la_fenetre_de_rack() {
        let mut c = avec(true, 1);
        c.reord_seen = 1;
        c.min_rtt.mesure(MIN_RTT_FENETRE, HEURE, 8 * MS);
        c.rtt.echantillon(100 * MS, 0, 10);
        assert_eq!(c.rack_fenetre(), 2 * MS);
        c.rack.pas = 3;
        assert_eq!(c.rack_fenetre(), 6 * MS);
        c.rack.pas = 255;
        assert_eq!(c.rack_fenetre(), c.rtt.srtt());
    }

    /// Ce qui reste dans le tri : un segment SACKé, ou renvoyé depuis, n'y est plus jugé.
    #[test]
    fn rack_oublie_ce_qui_a_change() {
        let prete = || {
            let mut c = avec(true, 3);
            c.rack.rtt = 10 * MS;
            c.rack.mstamp = HEURE + MS;
            c.rack.fin_seq = fin(2);
            c.cc.phase = Phase::Reprise;
            c
        };
        // SACKé : il n'est pas perdu.
        let mut c = prete();
        c.file[0].marques = SACKE;
        c.sacked_out = 1;
        c.rack_detecter(HEURE + 100 * MS);
        assert_eq!(c.file[0].marques & PERDU, 0);
        assert_eq!(c.lost_out, 2);
        // Renvoyé depuis : l'entrée du tri n'est plus la sienne, elle part sans être jugée.
        let mut c = prete();
        c.file[0].envoi = HEURE + 50 * MS;
        let n = c.tri.len();
        c.rack_detecter(HEURE + 100 * MS);
        assert_eq!(c.file[0].marques & PERDU, 0);
        assert_eq!(c.tri.len(), n - 3, "la sienne et les deux perdus");
        // Le numéro a disparu : de même.
        let mut c = prete();
        c.file[0].seq = debut(0) + 1;
        c.rack_detecter(HEURE + 100 * MS);
        assert_eq!(c.file[0].marques & PERDU, 0);
    }

    /// `tcp_rack_update_reo_wnd`.
    #[test]
    fn la_fenetre_de_rack_grandit() {
        let mut c = etablie(true);
        c.livres = 100;
        c.rack.pas = 1;
        c.rack.dernier_livre = 50;
        c.rack.dsack_vu = true;
        // Pas d'échantillon : rien du tout.
        c.rack_maj_fenetre(None);
        assert_eq!((c.rack.pas, c.rack.dsack_vu), (1, true));
        // Un D-SACK d'avant la dernière hausse ne compte pas.
        c.rack_maj_fenetre(Some(49));
        assert_eq!((c.rack.pas, c.rack.dsack_vu), (1, false));
        // Une hausse par aller-retour : un pas de plus, gardé RACK_PERSISTE reprises.
        c.rack.dsack_vu = true;
        c.rack_maj_fenetre(Some(50));
        assert_eq!((c.rack.pas, c.rack.dsack_vu, c.rack.dernier_livre, c.rack.persiste), (2, false, 100, RACK_PERSISTE));
        c.rack.dsack_vu = true;
        c.rack_maj_fenetre(Some(100));
        assert_eq!(c.rack.pas, 3);
        // Sans D-SACK, tant qu'il persiste : le pas reste ; ensuite, il retombe.
        c.rack_maj_fenetre(Some(100));
        assert_eq!(c.rack.pas, 3);
        c.rack.persiste = 0;
        c.rack_maj_fenetre(Some(100));
        assert_eq!(c.rack.pas, 1);
        // Au plus 255.
        c.rack.pas = 255;
        c.rack.dsack_vu = true;
        c.rack_maj_fenetre(Some(100));
        assert_eq!(c.rack.pas, 255);
    }

    /// `tcp_rack_reo_timeout` : ce qui devient perdu ouvre la reprise, si elle ne l'est pas déjà.
    #[test]
    fn le_minuteur_de_reordonnancement() {
        let prete = |phase| {
            let mut c = avec(true, 2);
            c.rack.rtt = 10 * MS;
            c.rack.mstamp = HEURE;
            c.rack.fin_seq = fin(1);
            c.cc.phase = phase;
            c.cc.ssthresh = 100;
            c.cc.cwnd = 10;
            c
        };
        let mut e = crate::tcp::Effets::default();
        let mut c = prete(Phase::Ouverte);
        c.minuteur_reordonnancement(HEURE + 100 * MS, &mut e);
        assert_eq!(c.lost_out, 1);
        assert_eq!(c.cc.phase, Phase::Reprise);
        assert_ne!(c.undo_marker, None, "une reprise qui commence");
        assert_eq!(c.rexmit, crate::tcp::Rexmit::Perdus);
        assert!(e.a_emettre);
        // Déjà en reprise : pas une deuxième.
        let mut e = crate::tcp::Effets::default();
        let mut c = prete(Phase::Reprise);
        c.minuteur_reordonnancement(HEURE + 100 * MS, &mut e);
        assert_eq!(c.lost_out, 1);
        assert_eq!(c.undo_marker, None);
        assert!(e.a_emettre);
        // Rien de perdu : rien à faire.
        let mut e = crate::tcp::Effets::default();
        let mut c = prete(Phase::Ouverte);
        c.minuteur_reordonnancement(HEURE + MS, &mut e);
        assert_eq!(c.lost_out, 0);
        assert_eq!(c.cc.phase, Phase::Ouverte);
        assert!(!e.a_emettre);
    }

    /// `tcp_schedule_loss_probe` : jamais après le RTO qui reste, s'il en reste.
    #[test]
    fn la_sonde_avant_le_rto() {
        let prete = || {
            let mut c = avec(true, 2);
            c.rtt.echantillon(100 * MS, 0, 10);
            c.rto = 50 * MS;
            c
        };
        let d = en_jiffies(2 * 100 * MS + TIMEOUT_MIN);
        // Il reste 40 ms.
        let mut c = prete();
        assert!(c.programmer_sonde_de_perte(false, HEURE + 10 * MS));
        assert_eq!(c.t_xmit, Some(HEURE + 10 * MS + en_jiffies(40 * MS)));
        // Tout juste échu, ou dépassé : la borne ne s'applique plus.
        for t in [HEURE + 50 * MS, HEURE + 60 * MS] {
            let mut c = prete();
            assert!(c.programmer_sonde_de_perte(false, t));
            assert_eq!(c.t_xmit, Some(t + d), "{t}");
        }
        // Le RTO va repartir : tout le RTO.
        let mut c = prete();
        assert!(c.programmer_sonde_de_perte(true, HEURE + 60 * MS));
        assert_eq!(c.t_xmit, Some(HEURE + 60 * MS + en_jiffies(50 * MS)));
    }

    /// La sonde peut emporter le FIN, s'il suit ce qu'elle envoie.
    #[test]
    fn la_sonde_et_le_fin() {
        let prete = |fin_voulue: bool| {
            let mut c = avec(true, 1);
            c.reglages.nodelay = false;
            c.ecrire::<()>(500, |d| {
                d.fill(1);
                Ok(())
            })
            .unwrap();
            c.fin_voulue = fin_voulue;
            c
        };
        for (voulue, attendu) in [(true, tcp::FIN), (false, 0)] {
            let mut c = prete(voulue);
            let mut vus = alloc::vec::Vec::new();
            c.envoyer_sonde_de_perte(HEURE + MS, &mut |s: Sortant| vus.push(s.entete.drapeaux));
            assert_eq!(vus.len(), 1);
            assert_eq!(vus[0] & tcp::FIN, attendu, "{voulue}");
        }
    }

    /// `tcp_process_tlp_ack` : l'ACK tout juste à la sonde renvoyée : un ACK pur, c'est que l'original
    /// et elle sont arrivés ; autre chose (il avance, il dit du neuf) : on ne sait pas encore.
    #[test]
    fn l_ack_de_la_sonde() {
        for (f, fini) in [
            (0, true),
            (FLAG_RETRANS_DATA_ACKED, true),
            (FLAG_SND_UNA_ADVANCED, false),
            (FLAG_DATA, false),
            (FLAG_WIN_UPDATE, false),
            (FLAG_DATA_ACKED, false),
            (FLAG_SYN_ACKED, false),
            (FLAG_DATA_SACKED, false),
        ] {
            let mut c = avec(true, 1);
            c.tlp_high_seq = Some(fin(0));
            c.tlp_renvoi = true;
            c.traiter_ack_de_sonde(fin(0), f);
            assert_eq!(c.tlp_high_seq.is_none(), fini, "{f:#x}");
        }
    }

    /// Le tri se nettoie à plus de deux fois la file, plus 16 : de ce qui n'y est plus.
    #[test]
    fn le_tri_se_nettoie() {
        let prete = |n: usize| {
            let mut c = avec(true, 3);
            let (s0, t0) = c.tri[0];
            c.tri.clear();
            // Le bon, puis des périmés : d'autres heures, d'autres numéros.
            c.tri.push_back((s0, t0));
            for k in 1..n {
                let k = k as u64;
                c.tri.push_back(if k % 2 == 0 { (s0, t0 + k) } else { (s0 + 1, t0) });
            }
            c
        };
        // Tout juste à la limite : pas encore.
        let mut c = prete(2 * 3 + 16);
        c.tri_ajouter(fin(2), HEURE);
        assert_eq!(c.tri.len(), 2 * 3 + 16 + 1);
        // Au-delà : il ne reste que le bon, et le nouveau.
        let mut c = prete(2 * 3 + 16 + 1);
        let bon = c.tri[0];
        c.tri_ajouter(fin(2), HEURE);
        assert_eq!(c.tri.len(), 2);
        assert_eq!(c.tri[0], bon);
        assert_eq!(c.tri[1], (fin(2), HEURE));
    }
}
