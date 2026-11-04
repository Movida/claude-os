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
        if self.sacked_out == 0 { self.snd_una } else { self.fack }
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
                partie = self.envoyer_donnees(n, avec_fin, maintenant, sortir);
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
        if self.tri.try_reserve(1).is_ok() {
            self.tri.push_back((seq, envoi));
        }
    }
}
