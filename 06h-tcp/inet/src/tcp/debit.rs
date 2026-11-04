//! Ce que seul lit TCP_INFO (`tcp_get_info`) : le débit livré (net/ipv4/tcp_rate.c), les
//! chronomètres (`tcp_chrono_*`, tcp_output.c) et les compteurs.
//!
//! LE DÉBIT LIVRÉ. À chaque ACK, un échantillon : combien de segments le réseau a livrés,
//! et en combien de temps, de l'envoi d'un segment à son acquittement. Chaque segment
//! retient donc à son envoi ce qui était déjà livré, et quand (`TxDebit`) ; l'ACK garde,
//! parmi ceux qu'il couvre, le segment parti le plus récemment (`taux_segment_livre`). Le
//! temps est le plus long de deux : celui de l'envoi de ces segments, et celui de leurs
//! ACK : des ACK groupés feraient croire à un débit que le réseau ne peut pas tenir.
//!
//! Un échantillon pris alors que le programme n'avait rien à envoyer dit ce que le
//! programme demandait, pas ce que le réseau peut donner : il est « limité par le
//! programme » (`app_limited`). Il ne remplace le débit retenu que s'il est plus haut.
//! Rien ne le lit ici, sinon TCP_INFO : chez Linux, c'est le moteur de BBR ; écarté : le
//! laisser à 0 jusqu'à BBR : un programme qui surveille ses connexions le lit, et les
//! compteurs de `tcp_rate.c` s'écrivent avec la file, pas après.
//!
//! LES CHRONOMÈTRES. Le temps passé à avoir de quoi envoyer, en trois causes dont la plus
//! intéressante l'emporte : rien de spécial, la fenêtre de l'autre, le tampon du
//! programme. En jiffies (notre HZ imité : cubic.rs), comme Linux : ce ne sont pas des
//! mesures fines.

use super::cubic::{HZ, en_jiffies32};
use super::retrans::{COMPTE, EtatSack};
use super::sack::parti_apres;
use super::{Charge, Etat, Tcb, apres};

/// Ce qui occupe la connexion (`tcp_chrono`), dans l'ordre de leur priorité.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Chrono {
    Aucun,
    Occupee,
    FenetreDeLAutre,
    TamponPlein,
}

/// Ce que retient un segment à son envoi (le `tx` de `tcp_skb_cb`).
#[derive(Debug, Clone, Copy)]
pub(super) struct TxDebit {
    /// L'envoi du segment acquitté le plus récent, à cet instant (`first_tx_mstamp`).
    premier: u64,
    /// La dernière livraison, à cet instant (`delivered_mstamp`).
    livre_a: u64,
    /// Les segments livrés (`delivered`).
    livres: u32,
    app_limite: bool,
}

/// Les compteurs, le débit et les chronomètres d'une connexion.
#[derive(Debug, Clone, Copy)]
pub(super) struct Mesures {
    pub(super) segs_in: u32,
    pub(super) data_segs_in: u32,
    pub(super) segs_out: u32,
    pub(super) data_segs_out: u32,
    pub(super) octets_envoyes: u64,
    pub(super) octets_renvoyes: u64,
    pub(super) octets_recus: u64,
    /// Les segments rangés hors d'ordre (`rcv_ooopack`).
    pub(super) hors_ordre: u32,
    /// Les épisodes de RTO (`total_rto_recoveries`), le début de celui en cours
    /// (`rto_stamp`), et le temps de ceux qui sont finis (`total_rto_time`), en ms.
    pub(super) rto_reprises: u32,
    rto_debut: Option<u64>,
    pub(super) rto_temps: u32,
    premier_tx: u64,
    livre_a: u64,
    /// Le numéro de livraison où la bulle laissée par le programme aura disparu
    /// (`app_limited`, 0 : aucune).
    app_limite: u32,
    /// Le débit retenu (`rate_delivered`, `rate_interval_us`, `rate_app_limited`).
    rate_livres: u32,
    rate_intervalle: u32,
    pub(super) rate_app_limite: bool,
    chrono: Chrono,
    chrono_debut: u32,
    chrono_stat: [u32; 3],
}

impl Mesures {
    pub(super) const fn new() -> Mesures {
        Mesures {
            segs_in: 0,
            data_segs_in: 0,
            segs_out: 0,
            data_segs_out: 0,
            octets_envoyes: 0,
            octets_renvoyes: 0,
            octets_recus: 0,
            hors_ordre: 0,
            rto_reprises: 0,
            rto_debut: None,
            rto_temps: 0,
            premier_tx: 0,
            livre_a: 0,
            // `tcp_init_sock` : rien de mesuré encore, et rien ne dira le contraire
            // avant le premier échantillon.
            app_limite: u32::MAX,
            rate_livres: 0,
            rate_intervalle: 0,
            rate_app_limite: true,
            chrono: Chrono::Aucun,
            chrono_debut: 0,
            chrono_stat: [0; 3],
        }
    }

    /// `tcp_compute_delivery_rate`, en octets par seconde.
    pub(super) fn debit(&self, mss: u32) -> u64 {
        if self.rate_livres == 0 || self.rate_intervalle == 0 {
            return 0;
        }
        self.rate_livres as u64 * mss as u64 * 1_000_000 / self.rate_intervalle as u64
    }

    /// `tcp_get_info_chrono_stats`, en µs : le temps occupé, ce qu'en prend la fenêtre de
    /// l'autre, et le tampon.
    pub(super) fn chronos(&self, maintenant: u64) -> (u64, u64, u64) {
        let mut stat = self.chrono_stat.map(u64::from);
        if self.chrono != Chrono::Aucun {
            stat[self.chrono as usize - 1] += en_jiffies32(maintenant).wrapping_sub(self.chrono_debut) as u64;
        }
        let us = 1_000_000 / HZ as u64;
        ((stat[0] + stat[1] + stat[2]) * us, stat[1] * us, stat[2] * us)
    }

    /// Le temps des épisodes de RTO, celui qui court compris, en ms.
    pub(super) fn temps_de_rto(&self, maintenant: u64) -> u32 {
        self.rto_temps + self.rto_debut.map_or(0, |d| ms(maintenant).wrapping_sub(ms(d)))
    }

    /// Un segment de `n` octets arrive (`tcp_segs_in`).
    pub(super) fn segment_recu(&mut self, n: u32) {
        self.segs_in += 1;
        if n > 0 {
            self.data_segs_in += 1;
        }
    }
}

/// L'horloge des horodatages de TCP (`tcp_time_stamp_ms`).
fn ms(maintenant: u64) -> u32 {
    (maintenant / 1_000_000) as u32
}

impl<P: Charge> Tcb<P> {
    /// Un segment de `n` octets part (`__tcp_transmit_skb`). Le SYN-ACK et les ACK d'une
    /// fille ne comptent pas : chez Linux, ils partent d'une simple demande, qui n'a pas de
    /// compteurs.
    pub(super) fn compter_sortie(&mut self, n: usize) {
        if self.fille && self.etat == Etat::SynRecu {
            return;
        }
        self.mesures.segs_out += 1;
        if n > 0 {
            self.mesures.data_segs_out += 1;
            self.mesures.octets_envoyes += n as u64;
        }
    }

    /// Un segment part (`tcp_rate_skb_sent`) : ce qu'il doit retenir. Sans rien en vol, une
    /// mesure ne peut commencer que maintenant : le temps d'avant ne dit rien du réseau.
    pub(super) fn debit_parti(&mut self, envoi: u64) -> TxDebit {
        let m = &mut self.mesures;
        if self.file.is_empty() {
            m.premier_tx = envoi;
            m.livre_a = envoi;
        }
        TxDebit { premier: m.premier_tx, livre_a: m.livre_a, livres: self.livres, app_limite: m.app_limite != 0 }
    }

    /// Le segment `i` est acquitté ou SACKé (`tcp_rate_skb_delivered`) : l'ACK retient
    /// celui parti le plus récemment. Une seule fois : acquitté après un SACK, il ne
    /// recompte pas.
    pub(super) fn taux_segment_livre(&mut self, i: usize, etat: &mut EtatSack) {
        let e = self.file[i];
        if e.marques & COMPTE != 0 {
            return;
        }
        if etat.prior_livres.is_none() || parti_apres(e.envoi, self.mesures.premier_tx, e.fin_seq, etat.derniere_fin) {
            etat.prior_livres = Some(e.tx.livres);
            etat.prior_livre_a = e.tx.livre_a;
            etat.app_limite = e.tx.app_limite;
            etat.derniere_fin = e.fin_seq;
            self.mesures.premier_tx = e.envoi;
            // Le temps d'envoi de cette fenêtre.
            etat.intervalle = e.envoi.saturating_sub(e.tx.premier);
        }
        self.file[i].marques |= COMPTE;
    }

    /// L'échantillon de cet ACK (`tcp_rate_gen`) : `livres` segments de plus livrés ; `renie` :
    /// l'autre avait oublié des SACK, ce qu'il en a dit gonflerait le débit.
    pub(super) fn generer_debit(&mut self, livres: u32, renie: bool, etat: &EtatSack, maintenant: u64) {
        let m = &mut self.mesures;
        // La bulle est passée.
        if m.app_limite != 0 && apres(self.livres, m.app_limite) {
            m.app_limite = 0;
        }
        if livres != 0 {
            m.livre_a = maintenant;
        }
        let Some(prior) = etat.prior_livres else { return };
        if renie {
            return;
        }
        let livres = self.livres.wrapping_sub(prior);
        // Le plus long du temps d'envoi et de celui des ACK.
        let intervalle = etat.intervalle.max(maintenant.saturating_sub(etat.prior_livre_a)) / 1000;
        // Plus court qu'un aller-retour : une illusion (un renvoi inutile, souvent) ; et sans
        // mesure du RTT (`min_rtt` : sa valeur de départ, très grande), pas d'échantillon.
        if intervalle < self.min_rtt.valeur() / 1000 {
            return;
        }
        // Le dernier s'il n'est pas limité par le programme, sinon le plus haut.
        if !etat.app_limite || livres as u64 * m.rate_intervalle as u64 >= m.rate_livres as u64 * intervalle {
            m.rate_livres = livres;
            m.rate_intervalle = intervalle as u32;
            m.rate_app_limite = etat.app_limite;
        }
    }

    /// L'ACK du SYN, qui n'a pas d'entrée dans notre file. Il ne fait pas d'échantillon : chez
    /// Linux, le SYN compte déjà dans `packets_out` à son envoi, et n'a donc pas reçu de
    /// `delivered_mstamp` (mesuré : pas de débit après `connect`). Reste ce que fait tout ACK.
    pub(super) fn debit_du_syn(&mut self, maintenant: u64) {
        self.generer_debit(1, false, &EtatSack::default(), maintenant);
    }

    /// Un `send` commence (`tcp_rate_check_app_limited`, sans `en_file` : ce que garde la
    /// carte) : si rien n'est prêt à partir, ni dans la carte, et que ni la fenêtre de
    /// congestion ni les pertes ne retiennent, c'est que le programme s'est fait attendre.
    pub fn verifier_app_limite(&mut self, en_file: usize) {
        if self.non_envoyes() < self.mss as usize
            && en_file == 0
            && self.paquets_en_vol() < self.cc.cwnd
            && self.lost_out <= self.retrans_out
        {
            let bulle = self.livres.wrapping_add(self.paquets_en_vol());
            self.mesures.app_limite = if bulle == 0 { 1 } else { bulle };
        }
    }

    /// `tcp_chrono_set`.
    fn chrono_poser(&mut self, neuf: Chrono, maintenant: u64) {
        let m = &mut self.mesures;
        let now = en_jiffies32(maintenant);
        if m.chrono != Chrono::Aucun {
            let i = m.chrono as usize - 1;
            m.chrono_stat[i] = m.chrono_stat[i].wrapping_add(now.wrapping_sub(m.chrono_debut));
        }
        m.chrono_debut = now;
        m.chrono = neuf;
    }

    /// `tcp_chrono_start` : la cause la plus intéressante l'emporte.
    pub(super) fn chrono_commencer(&mut self, c: Chrono, maintenant: u64) {
        if c > self.mesures.chrono {
            self.chrono_poser(c, maintenant);
        }
    }

    /// `tcp_chrono_stop` : plus rien en file, plus de chrono ; sinon la cause courante cesse,
    /// reste que la connexion est occupée.
    pub(super) fn chrono_arreter(&mut self, c: Chrono, maintenant: u64) {
        if self.file.is_empty() && self.non_envoyes() == 0 {
            self.chrono_poser(Chrono::Aucun, maintenant);
        } else if c == self.mesures.chrono {
            self.chrono_poser(Chrono::Occupee, maintenant);
        }
    }

    /// Un RTO commence un épisode s'il est le premier de suite (`tcp_update_rto_stats`).
    pub(super) fn rto_compter(&mut self, maintenant: u64) {
        if self.retransmissions == 0 {
            self.mesures.rto_reprises += 1;
            self.mesures.rto_debut = Some(maintenant);
        }
    }

    /// L'épisode est fini (`tcp_update_rto_time`).
    pub(super) fn rto_fini(&mut self, maintenant: u64) {
        if let Some(d) = self.mesures.rto_debut.take() {
            self.mesures.rto_temps += ms(maintenant).wrapping_sub(ms(d));
        }
    }

    /// Une fille naît (`tcp_create_openreq_child`) : son SYN et ce dernier segment, de `n`
    /// octets ; et le temps que ses SYN-ACK ont mis à servir.
    pub(super) fn compter_naissance(&mut self, n: u32, maintenant: u64) {
        self.mesures.segs_in = 1;
        self.mesures.segment_recu(n);
        if self.total_rto > 0 {
            self.mesures.rto_reprises = 1;
            self.mesures.rto_temps = ms(maintenant).wrapping_sub(ms(self.retrans_stamp));
        }
    }
}
