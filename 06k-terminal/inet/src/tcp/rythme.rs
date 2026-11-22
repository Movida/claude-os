//! Le rythme interne de TCP, que SO_MAX_PACING_RATE demande (`tcp_pacing_check`,
//! `tcp_update_skb_after_send`, `tcp_pace_kick`, net/ipv4/tcp_output.c ;
//! `tcp_pacing_delay`, include/net/tcp.h).
//!
//! L'IDÉE. Une connexion envoie d'ordinaire d'un coup ce que permet la cwnd, en rafale :
//! les files de la carte et des routeurs absorbent. Le programme qui pose
//! SO_MAX_PACING_RATE demande au contraire un débit au plus (un serveur de vidéo qui ne
//! veut pas noyer le lien d'un client, un transfert de fond qui laisse la place aux
//! autres) : les segments partent alors espacés, chacun à son heure, l'écart venant du
//! débit (`sk_pacing_rate`, borné par le plafond : congestion.rs). Linux le fait de deux
//! façons : la file `fq` de la carte, qui retient chaque paquet jusqu'à l'heure de départ
//! que TCP y a écrite (le modèle EDT, « earliest departure time ») ; et, sans `fq` (le
//! cas par défaut, et le nôtre : aucune file de paquets ordonnancée chez nous), le rythme
//! interne de TCP (Eric Dumazet, Linux 4.13) : TCP s'arrête lui-même d'envoyer tant que
//! l'heure du prochain départ n'est pas venue, et un minuteur fin (un hrtimer,
//! `pacing_timer`) le réveille à cette heure.
//!
//! LE CALCUL. `depart` (`tcp_wstamp_ns`) est l'heure au plus tôt du prochain segment.
//! Chaque segment part à max(`depart`, maintenant) ; s'il porte des données, `depart`
//! avance de leur durée au débit (longueur / débit), moins le retard que le segment avait
//! déjà pris sur son heure, au plus la moitié de sa durée : la gigue du système ne doit
//! pas coûter de débit, sans qu'un long retard se rattrape d'un coup, en rafale. Les dix
//! premiers segments de données de la connexion partent sans attendre, comme sous `fq`
//! (« Original sch_fq does not pace first 10 MSS »). Un débit nul ou infini ne rythme
//! rien (mesuré : SO_MAX_PACING_RATE à 0, 4 Mo en 1 ms sur lo, comme sans plafond).
//!
//! OÙ IL RETIENT. Avant chaque segment neuf (`tcp_write_xmit`, la sonde de fin de rafale
//! comprise) et chaque renvoi de la reprise (`tcp_xmit_retransmit_queue`) ; pas le renvoi
//! de la tête au RTO, ni la sonde de fenêtre, ni un ACK, ni le SYN. Et les minuteurs de
//! retransmission (réarmés après un progrès), de sonde et de sonde de fin de rafale
//! reculent d'autant (`tcp_pacing_delay`, en jiffies entiers) : un RTO qui tomberait avant
//! que le segment n'ait pu partir n'aurait pas de sens.
//!
//! Mesuré sous Linux (6.18, lo, SO_MAX_PACING_RATE à 2 Mo/s) : 2 Mo en 0,78 s, 4 Mo en
//! 1,82 s (les dix premiers segments, 55 Kio chacun, partent tout de suite) ; sans plafond,
//! 4 Mo en 2 ms.
//!
//! Choix de conception : le minuteur du rythme est une échéance fine de la connexion
//! (`echeance_fine`, comme la compression des SACK), que le noyau sert par le minuteur
//! précis de la tâche du réseau ; à son heure, la connexion fait ce que fait une fin
//! d'émission (`tcp_pace_kick` appelle `tcp_tsq_handler`, comme TSQ) : la reprise si la
//! cwnd le permet, puis le neuf. Écarté : une file de paquets datés à la carte (`fq`),
//! qui demanderait un ordonnanceur de paquets pour ce seul usage ; et un minuteur de la
//! roue, au tic (4 ms) : à 2 Mo/s, un segment de 1460 octets dure 0,7 ms, et le débit
//! voulu ne serait pas tenu.

use super::congestion::PACING_MAX;
use super::sack::JIFFY;
use super::{Charge, Effets, Minuteur, Tcb};

/// Les premiers segments de données de la connexion, qui partent sans attendre.
const SANS_RYTHME: u32 = 10;

impl<P: Charge> Tcb<P> {
    /// SO_MAX_PACING_RATE : `max`, le plafond ; `interne`, la socket a déjà posé un
    /// plafond fini (le rythme interne reste alors, même revenu à l'infini). Une connexion
    /// le reçoit de sa socket, une fille de son écoute (`sk_clone_lock`), et le prochain
    /// segment en tient compte.
    pub fn poser_rythme(&mut self, max: u64, interne: bool) {
        self.cc.plafonner(max);
        self.cc.rythme_interne |= interne;
    }

    /// Le plafond et le rythme interne de la connexion : une fille les donne à la socket
    /// que l'accept lui fait (ce qu'elle a reçu de son écoute à sa naissance).
    pub fn rythme(&self) -> (u64, bool) {
        (self.cc.pacing_max, self.cc.rythme_interne)
    }

    /// Un segment part (`__tcp_transmit_skb`) : à son heure, ou maintenant si elle est
    /// passée. Rend l'heure prévue d'avant, que `avancer_le_depart` compare.
    pub(super) fn partir_a_l_heure(&mut self) -> u64 {
        let avant = self.depart;
        self.depart = self.depart.max(self.heure);
        avant
    }

    /// Un segment de `n` octets de données est parti (`tcp_update_skb_after_send`), prévu
    /// à `avant` : l'heure du suivant recule de sa durée au débit, moins le retard qu'il
    /// avait pris (au plus la moitié de sa durée).
    pub(super) fn avancer_le_depart(&mut self, n: usize, avant: u64) {
        let debit = self.cc.pacing;
        if !self.cc.rythme_interne || debit == PACING_MAX || debit == 0 || self.mesures.data_segs_out < SANS_RYTHME {
            return;
        }
        let duree = n as u64 * 1_000_000_000 / debit;
        let retard = self.depart - avant;
        self.depart += duree - (duree / 2).min(retard);
    }

    /// `tcp_pacing_check` : l'heure du prochain départ n'est pas venue ; le minuteur du
    /// rythme l'attend (armé s'il ne l'est pas déjà).
    pub(super) fn retenu_par_le_rythme(&mut self) -> bool {
        if !self.cc.rythme_interne || self.depart <= self.heure {
            return false;
        }
        if self.t_rythme.is_none() {
            self.t_rythme = Some(self.depart);
        }
        true
    }

    /// `tcp_pacing_delay` : ce qui reste avant le prochain départ, en jiffies entiers
    /// (`nsecs_to_jiffies` tronque).
    fn delai_du_rythme(&self, maintenant: u64) -> u64 {
        self.depart.saturating_sub(maintenant) / JIFFY * JIFFY
    }

    /// `tcp_reset_xmit_timer` avec `pace_delay` : le minuteur de la connexion pour
    /// `sorte`, dans `delai` plus ce qui reste avant le prochain départ.
    pub(super) fn armer_xmit_au_rythme(&mut self, sorte: Minuteur, delai: u64, maintenant: u64) {
        self.armer_xmit(sorte, delai.saturating_add(self.delai_du_rythme(maintenant)), maintenant);
    }

    /// Le minuteur du rythme est échu (`tcp_pace_kick`, puis `tcp_tsq_handler`) : ce que
    /// fait une fin d'émission (la reprise, si la cwnd le permet), puis le neuf.
    pub(super) fn minuteur_rythme(&mut self, e: &mut Effets) {
        self.fin_d_emission();
        e.a_emettre = true;
    }
}

#[cfg(test)]
mod tests {
    use super::super::essais::*;
    use super::*;
    use alloc::vec::Vec;

    /// Une connexion établie, son RTT de 10 ms mesuré, au plafond de `debit`.
    fn au_rythme(debit: u64) -> C {
        let mut c = etablie(true);
        c.rtt.echantillon(10 * MS, c.snd_una, c.snd_nxt);
        c.rto = c.rtt.rto();
        c.reglages.nodelay = true;
        c.poser_rythme(debit, false);
        c
    }

    /// Écrit `n` octets, et rend les longueurs des segments partis à `t`.
    fn ecrire_et_emettre(c: &mut C, n: usize, t: u64) -> Vec<usize> {
        if n > 0 {
            assert_eq!(c.ecrire::<()>(n, |d| { d.fill(1); Ok(()) }), Ok(n));
        }
        let mut partis = Vec::new();
        c.emettre(t, |s| partis.push(s.longueur));
        partis
    }

    /// Dix segments sans attendre, le dixième comptant déjà (`data_segs_out` le compte
    /// avant `tcp_update_skb_after_send`) ; puis un par durée au débit, le minuteur du
    /// rythme armé à l'heure du suivant, une échéance fine ; à son heure, le suivant part.
    #[test]
    fn dix_segments_puis_au_rythme() {
        // 1000 octets à 100 000 octets/s : 10 ms par segment.
        let mut c = au_rythme(100_000);
        let partis = ecrire_et_emettre(&mut c, 20 * MSS as usize, HEURE);
        assert_eq!(partis.len(), 10);
        // Le dixième est parti à HEURE ; le suivant, 10 ms plus tard.
        assert_eq!(c.depart, HEURE + 10 * MS);
        assert_eq!(c.t_rythme, Some(HEURE + 10 * MS));
        assert_eq!(c.echeance_fine(), Some(HEURE + 10 * MS));
        assert!(c.echeance().is_some_and(|e| e <= HEURE + 10 * MS));
        // Rien de plus avant l'heure.
        assert!(ecrire_et_emettre(&mut c, 0, HEURE + 10 * MS - 1).is_empty());
        let e = c.minuteur(HEURE + 10 * MS);
        assert!(e.a_emettre);
        assert_eq!(c.t_rythme, None);
        assert_eq!(ecrire_et_emettre(&mut c, 0, HEURE + 10 * MS), [MSS as usize]);
        assert_eq!(c.depart, HEURE + 20 * MS);
    }

    /// Le retard pris sur l'heure prévue se rattrape, au plus la moitié de la durée.
    #[test]
    fn le_retard_se_rattrape_a_moitie() {
        let mut c = au_rythme(100_000);
        ecrire_et_emettre(&mut c, 20 * MSS as usize, HEURE);
        // 3 ms de retard : le suivant est prévu 7 ms après son départ.
        c.minuteur(HEURE + 13 * MS);
        ecrire_et_emettre(&mut c, 0, HEURE + 13 * MS);
        assert_eq!(c.depart, HEURE + 20 * MS);
        // 8 ms de retard : la moitié seulement, 5 ms.
        c.minuteur(HEURE + 28 * MS);
        ecrire_et_emettre(&mut c, 0, HEURE + 28 * MS);
        assert_eq!(c.depart, HEURE + 33 * MS);
    }

    /// Sans plafond jamais posé, à un débit nul, ou infini (rien de mesuré encore) :
    /// rien n'attend.
    #[test]
    fn sans_rythme() {
        // Un débit calculé, sans plafond posé : pas de rythme interne (seul `fq` le suivrait).
        let mut c = au_rythme(PACING_MAX);
        c.cc.pacing = 100_000;
        assert_eq!(ecrire_et_emettre(&mut c, 30 * MSS as usize, HEURE).len(), 30);
        assert_eq!(c.t_rythme, None);
        // Un plafond nul.
        let mut c = au_rythme(0);
        assert_eq!(ecrire_et_emettre(&mut c, 30 * MSS as usize, HEURE).len(), 30);
        // Le rythme interne, à un débit infini.
        let mut c = au_rythme(100_000);
        c.poser_rythme(PACING_MAX, true);
        c.cc.pacing = PACING_MAX;
        assert_eq!(ecrire_et_emettre(&mut c, 30 * MSS as usize, HEURE).len(), 30);
        assert_eq!(c.depart, HEURE);
        // Le plafond levé, le rythme interne reste, au débit déjà borné.
        let mut c = au_rythme(100_000);
        c.poser_rythme(PACING_MAX, true);
        assert_eq!(ecrire_et_emettre(&mut c, 30 * MSS as usize, HEURE).len(), 10);
    }

    /// La reprise attend son heure aussi ; le RTO réarmé, la sonde de fin de rafale
    /// reculent de ce qui reste, en jiffies entiers.
    #[test]
    fn la_reprise_et_les_minuteurs_attendent() {
        let mut c = au_rythme(100_000);
        ecrire_et_emettre(&mut c, 10 * MSS as usize, HEURE);
        assert_eq!(c.depart, HEURE + 10 * MS);
        // Le RTO réarmé après un progrès : 10 ms de plus, 2 jiffies entiers (8 ms).
        c.rearmer_rto(HEURE);
        assert_eq!(c.t_xmit, Some(HEURE + c.rto + 8 * MS));
        // La sonde de fin de rafale : de même.
        assert!(c.programmer_sonde_de_perte(true, HEURE));
        let d = c.t_xmit.unwrap() - HEURE;
        c.depart = HEURE;
        assert!(c.programmer_sonde_de_perte(true, HEURE));
        assert_eq!(c.t_xmit, Some(HEURE + d - 8 * MS));
        // Un segment perdu attend l'heure du rythme pour être renvoyé.
        c.depart = HEURE + 10 * MS;
        c.file[0].marques |= super::super::retrans::PERDU;
        c.lost_out = 1;
        c.rexmit = super::super::Rexmit::Perdus;
        assert!(ecrire_et_emettre(&mut c, 0, HEURE + MS).is_empty());
        assert_eq!(c.t_rythme, Some(HEURE + 10 * MS));
        c.minuteur(HEURE + 10 * MS);
        assert_eq!(ecrire_et_emettre(&mut c, 0, HEURE + 10 * MS), [MSS as usize]);
        assert_eq!(c.retrans_out, 1);
    }

    /// Une fermeture arrête le minuteur du rythme (`tcp_clear_xmit_timers`).
    #[test]
    fn la_fermeture_l_arrete() {
        let mut c = au_rythme(100_000);
        ecrire_et_emettre(&mut c, 20 * MSS as usize, HEURE);
        assert!(c.t_rythme.is_some());
        c.avorter();
        assert_eq!(c.t_rythme, None);
        assert_eq!(c.echeance_fine(), None);
    }
}
