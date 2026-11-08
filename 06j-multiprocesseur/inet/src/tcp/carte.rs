//! Ce que la carte réseau a encore d'une connexion : TSQ et l'autocork
//! (`tcp_small_queue_check`, `tcp_should_autocork`, `skb_still_in_host_queue`,
//! net/ipv4/tcp_output.c et tcp.c).
//!
//! L'IDÉE. Un segment envoyé n'est pas parti : il attend son tour dans la file de
//! la carte. Linux compte ces octets par socket (`sk_wmem_alloc` : le paquet tient sa
//! socket tant que la carte ne l'a pas rendu, `tcp_wfree`). Il s'en sert trois fois :
//!   - TSQ (TCP Small Queues, Eric Dumazet, 2012) : pas plus d'une milliseconde de débit
//!     (`sk_pacing_rate` >> 10) dans les files d'en bas, ni plus de 4 Mio ; le reste
//!     attend la fin d'émission. Ces files plus courtes, c'est une latence plus
//!     courte pour tout le monde (le « bufferbloat ») ;
//!   - l'AUTOCORK (`tcp_autocorking`) : un petit `send` alors que la carte a encore
//!     de quoi s'occuper est retenu jusqu'à la fin d'émission : les petits envois
//!     suivants se réunissent en un seul segment, sans que le programme n'ait rien à
//!     demander (ni TCP_CORK, ni MSG_MORE) ;
//!   - la sonde de fin de rafale et le RTO ne renvoient pas un segment qui n'est pas
//!     encore parti (`skb_still_in_host_queue`).
//!
//! `inet` ne voit pas la carte : le noyau pose ce qu'elle garde avant d'émettre
//! (`poser_en_file`), et lit `prendre_etrangle` après : il attend alors la fin
//! d'émission, qui rappellera la connexion (noyau/src/reseau/paquet.rs, `Retenue`). Sur
//! `lo`, rien n'attend (`loopback_xmit` : `skb_orphan`) : `sans_file`.

use super::{Charge, FENETRE_MAX, Tcb, Rexmit};

/// Ce que coûte un segment de plus que ses données, en taille vraie : ses en-têtes et
/// ses structures, à peu près (la marge de `Paquet`, et son `SURCOUT`).
pub(super) const COUT_SEGMENT: usize = 96 + 32 + 576;
/// `tcp_limit_output_bytes`.
const TSQ_MAX: usize = 4 << 20;
/// `sk_pacing_shift` : une milliseconde de débit, à peu près.
const PACING_DECALAGE: u32 = 10;
/// `sk_gso_max_size`, pour la taille des blocs d'écriture (`tcp_xmit_size_goal`).
const GSO_MAX: u32 = 65_536 - 321;

impl<P: Charge> Tcb<P> {
    /// Ce que la carte garde de cette connexion, en taille vraie, et jusqu'à quel envoi
    /// elle a fini ; à poser avant `emettre`.
    pub fn poser_en_file(&mut self, octets: usize, rendu: u64) {
        self.en_file = octets;
        self.rendu = rendu;
    }

    /// Faut-il être rappelé à la fin d'émission (TSQ_THROTTLED) ?
    pub fn prendre_etrangle(&mut self) -> bool {
        core::mem::take(&mut self.etrangle)
    }

    /// Un segment part : son numéro, et il compte dans ce que garde la carte.
    pub(super) fn compter_envoi(&mut self, n: usize) -> u64 {
        self.envois += 1;
        if !self.sans_file {
            self.en_file += n + COUT_SEGMENT;
        }
        self.envois
    }

    /// `tcp_small_queue_check`, pour un segment de `n` octets : la carte en a déjà assez.
    /// `facteur`, 1 pour un renvoi : il a droit au double. Toujours un segment s'il n'y
    /// a rien d'autre en vol : la fin d'émission peut tarder, autant ne pas l'attendre.
    pub(super) fn carte_trop_pleine(&mut self, n: usize, facteur: u32) -> bool {
        if self.sans_file {
            return false;
        }
        let v = n + COUT_SEGMENT;
        let debit = (self.cc.pacing >> PACING_DECALAGE).min(TSQ_MAX as u64) as usize;
        let limite = (2 * v).max(debit).min(TSQ_MAX) << facteur;
        if self.en_file > limite && self.file.len() > 1 {
            self.etrangle = true;
            return true;
        }
        false
    }

    /// `skb_still_in_host_queue` : le dernier envoi de l'entrée `i` attend-il encore dans
    /// la carte ? Il n'a pas été perdu : inutile de le renvoyer.
    pub(super) fn encore_dans_la_carte(&mut self, i: usize) -> bool {
        if !self.sans_file && self.file[i].numero > self.rendu {
            self.etrangle = true;
            return true;
        }
        false
    }

    /// `tcp_xmit_size_goal` : la taille d'un bloc d'écriture, autant de MSS que la
    /// segmentation par la carte en porterait, bornée par la moitié de la plus grande
    /// fenêtre de l'autre. Nous n'avons pas de TSO ; c'est la mesure de l'autocork.
    fn but_d_ecriture(&self) -> usize {
        let mss = self.mss_courant();
        let coupure = if self.max_fenetre > 536 { self.max_fenetre / 2 } else { self.max_fenetre };
        let plafond = if coupure > 0 { GSO_MAX.min(coupure) } else { GSO_MAX };
        ((plafond / mss).max(1).min(FENETRE_MAX) * mss) as usize
    }

    /// `tcp_should_autocork`, à la fin d'un `send` (`tcp_push`) : ce qu'il faut retenir
    /// du dernier bloc, s'il n'est pas plein, s'il reste du vol et que la carte a de quoi
    /// s'occuper. Les blocs pleins partent toujours (`tcp_sendmsg_locked`). Pas de numéro
    /// de bloc ici : le dernier est ce qui dépasse un multiple de la mesure.
    pub(super) fn autocork(&mut self) -> usize {
        if !core::mem::take(&mut self.ecrit) || self.sans_file || self.file.is_empty() {
            return 0;
        }
        let debut = self.snd_nxt.wrapping_sub(self.seq_envoi) as usize;
        let reste = self.octets_envoi.saturating_sub(debut);
        let queue = reste % self.but_d_ecriture();
        if queue > 0 && self.en_file > queue + COUT_SEGMENT {
            self.etrangle = true;
            return queue;
        }
        0
    }

    /// La fin d'émission est là (`tcp_tsq_write`) : ce qui est perdu, si la cwnd le permet,
    /// avant le neuf que fera partir le prochain `emettre`.
    pub fn fin_d_emission(&mut self) {
        if self.lost_out > self.retrans_out && self.cc.cwnd > self.paquets_en_vol() && self.etat.synchronise() {
            self.rexmit = Rexmit::Perdus;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::essais::*;
    use super::super::Etat;
    use super::*;

    #[test]
    fn la_carte_trop_pleine_aux_bornes() {
        let mut c = etablie(true);
        en_vol(&mut c, 2);
        c.sans_file = false;
        c.cc.pacing = 0;
        let n = 1000;
        let v = n + 96 + 32 + 576;
        // `tcp_small_queue_check` : max(2 * truesize, débit >> 10), au plus 4 Mio, << facteur.
        for (en_file, facteur, oui) in [(2 * v, 0, false), (2 * v + 1, 0, true), (4 * v, 1, false), (4 * v + 1, 1, true)] {
            c.en_file = en_file;
            c.etrangle = false;
            assert_eq!(c.carte_trop_pleine(n, facteur), oui, "{en_file} {facteur}");
            assert_eq!(c.etrangle, oui);
        }
        c.cc.pacing = 10_000 << 10;
        c.en_file = 10_000;
        assert!(!c.carte_trop_pleine(n, 0));
        c.en_file = 10_001;
        assert!(c.carte_trop_pleine(n, 0));
        c.cc.pacing = u64::MAX >> 1;
        c.en_file = 4 << 20;
        assert!(!c.carte_trop_pleine(n, 0));
        c.en_file = (4 << 20) + 1;
        assert!(c.carte_trop_pleine(n, 0));
        // Un très gros segment ne fait pas monter le plafond.
        c.cc.pacing = 0;
        assert!(c.carte_trop_pleine(5 << 20, 0));
        // Seul en vol : il part toujours. Sans file : jamais de limite.
        c.file.truncate(1);
        c.en_file = 1 << 30;
        c.etrangle = false;
        assert!(!c.carte_trop_pleine(n, 0));
        assert!(!c.etrangle);
        let mut d = etablie(true);
        en_vol(&mut d, 2);
        d.sans_file = true;
        d.en_file = 1 << 30;
        assert!(!d.carte_trop_pleine(n, 0));
    }

    #[test]
    fn compter_un_envoi() {
        let mut c = etablie(true);
        let a = c.compter_envoi(100);
        assert_eq!(c.compter_envoi(100), a + 1, "des numéros qui se suivent");
        assert_eq!(c.en_file, 0, "sans file, rien de compté");
        c.sans_file = false;
        c.compter_envoi(100);
        assert_eq!(c.en_file, 100 + 96 + 32 + 576);
    }

    #[test]
    fn le_but_d_ecriture() {
        let mut c = etablie(true);
        c.mss = 100;
        // `tcp_bound_to_half_wnd` : au-delà de 536, la moitié de la plus grande fenêtre.
        for (fenetre, but) in [(536, 500), (537, 200), (0, 65_200), (10_000, 5_000), (130_430, 65_200), (130_600, 65_200), (50, 50)] {
            c.max_fenetre = fenetre;
            assert_eq!(c.but_d_ecriture(), but, "fenetre {fenetre}");
        }
        c.mss = 1;
        c.max_fenetre = 0;
        assert_eq!(c.but_d_ecriture(), 65_215);
        // Au plus 65 535 segments, si petit soit le segment : sans objet ici, GSO_MAX les borne.
        assert!(c.but_d_ecriture() <= 65_535);
    }

    #[test]
    fn l_autocork() {
        let mut c = etablie(true);
        en_vol(&mut c, 1);
        c.sans_file = false;
        c.max_fenetre = 1 << 20;
        // Ce qui reste de l'écriture, après ce qui est parti.
        c.octets_envoi = c.snd_nxt.wrapping_sub(c.seq_envoi) as usize + 300;
        let seuil = 300 + 96 + 32 + 576;
        c.en_file = seuil;
        c.ecrit = true;
        assert_eq!(c.autocork(), 0);
        assert!(!c.etrangle);
        assert!(!c.ecrit, "une seule fois par écriture");
        c.en_file = seuil + 1;
        c.ecrit = true;
        assert_eq!(c.autocork(), 300);
        assert!(c.etrangle);
        assert_eq!(c.autocork(), 0, "déjà pris");
        // Un multiple exact du but : tout part, même si la carte est bien occupée.
        let but = c.but_d_ecriture();
        c.octets_envoi = c.snd_nxt.wrapping_sub(c.seq_envoi) as usize + but;
        c.en_file = 1 << 20;
        c.etrangle = false;
        c.ecrit = true;
        assert_eq!(c.autocork(), 0);
        assert!(!c.etrangle);
        // Plus d'un but : seul ce qui dépasse attend.
        c.octets_envoi = c.snd_nxt.wrapping_sub(c.seq_envoi) as usize + but + 10;
        c.en_file = 10_000;
        c.ecrit = true;
        assert_eq!(c.autocork(), 10);
        // Rien en vol, ou pas de file : rien à attendre.
        c.ecrit = true;
        c.sans_file = true;
        assert_eq!(c.autocork(), 0);
        c.sans_file = false;
        c.ecrit = true;
        c.file.clear();
        assert_eq!(c.autocork(), 0);
    }

    /// `skb_still_in_host_queue` : son dernier envoi n'est pas encore rendu.
    #[test]
    fn encore_dans_la_carte_() {
        let mut c = etablie(true);
        en_vol(&mut c, 1);
        c.sans_file = false;
        c.file[0].numero = 10;
        c.poser_en_file(5000, 9);
        assert_eq!(c.en_file, 5000);
        assert!(c.encore_dans_la_carte(0));
        assert!(c.prendre_etrangle());
        assert!(!c.prendre_etrangle(), "lu une fois");
        c.poser_en_file(0, 10);
        assert!(!c.encore_dans_la_carte(0));
        assert!(!c.prendre_etrangle());
        c.poser_en_file(0, 11);
        assert!(!c.encore_dans_la_carte(0));
        c.sans_file = true;
        c.poser_en_file(0, 9);
        assert!(!c.encore_dans_la_carte(0));
    }

    #[test]
    fn la_fin_d_emission() {
        let mut c = etablie(true);
        en_vol(&mut c, 3);
        c.lost_out = 1;
        c.retrans_out = 0;
        c.cc.cwnd = c.paquets_en_vol() + 1;
        c.rexmit = Rexmit::Rien;
        c.fin_d_emission();
        assert_eq!(c.rexmit, Rexmit::Perdus);
        // Tout ce qui est perdu est déjà renvoyé.
        c.rexmit = Rexmit::Rien;
        c.retrans_out = 1;
        c.cc.cwnd = c.paquets_en_vol() + 1;
        c.fin_d_emission();
        assert_eq!(c.rexmit, Rexmit::Rien);
        // La cwnd pleine.
        c.retrans_out = 0;
        c.cc.cwnd = c.paquets_en_vol();
        c.fin_d_emission();
        assert_eq!(c.rexmit, Rexmit::Rien);
        // La connexion est finie.
        c.cc.cwnd = c.paquets_en_vol() + 1;
        c.etat = Etat::Fermee;
        c.fin_d_emission();
        assert_eq!(c.rexmit, Rexmit::Rien);
    }
}
