//! La réception qui s'ajuste : la fenêtre annoncée, SO_RCVBUF qui suit le débit
//! du programme, et la mémoire d'une connexion qui reçoit (net/ipv4/tcp_input.c et
//! tcp_output.c de Linux : `__tcp_select_window`, `tcp_grow_window`,
//! `tcp_rcv_space_adjust`, `tcp_prune_queue`).
//!
//! DEUX UNITÉS. SO_RCVBUF et ce que garde la file de réception comptent de la
//! MÉMOIRE (le `truesize` d'un paquet, ses octets et leur tampon, et ses
//! structures) ; la fenêtre annoncée compte des OCTETS DE DONNÉES. Pour passer de
//! l'une à l'autre, Linux mesure un rapport, `scaling_ratio` : les octets de
//! données sur la taille vraie du dernier grand segment reçu (`tcp_measure_rcv_mss`),
//! sur 256, 50 % au départ. Ainsi une carte qui gâche beaucoup de place fait
//! annoncer moins. Nos tailles vraies sont celles de nos paquets : nous n'annonçons
//! pas exactement ce qu'annonce Linux pour un même débit, mais nous suivons sa règle.
//!
//! TROIS LIMITES de la fenêtre, de la plus souple à la plus dure :
//!   - `rcv_ssthresh` : ce qu'on a vu passer jusqu'ici. Il part de la fenêtre du
//!     SYN et grandit à chaque segment de bon rendement (`tcp_grow_window`) : une
//!     fenêtre qui s'ouvre d'un coup à un émetteur qu'on ne connaît pas inviterait
//!     une rafale que la mémoire ne pourrait peut-être pas garder ;
//!   - `window_clamp` : le plus grand qu'on annoncera jamais, d'après SO_RCVBUF ;
//!   - la place libre, à l'instant, dans SO_RCVBUF.
//!
//! LA FENÊTRE NE RECULE PAS (RFC 9293 3.8.6.2.2, `tcp_select_window`) : ce qu'on a
//! promis l'a été. La fenêtre se calcule à chaque segment qui part ; moins de place
//! qu'annoncé : le bord droit reste où il est.
//!
//! SO_RCVBUF QUI GRANDIT (Dynamic Right Sizing, Fisk et Feng, 2001 ;
//! `tcp_rcv_space_adjust`, `tcp_rcvbuf_grow` de 6.18). Pour que le débit ne soit
//! pas limité par le récepteur, la fenêtre doit couvrir au moins ce que le programme
//! lit en un aller-retour, et de quoi laisser l'émetteur doubler (il est en démarrage
//! lent). À chaque RTT du récepteur, on regarde ce que le programme a lu ; s'il en a
//! lu plus que jamais, SO_RCVBUF grandit, jusqu'à `tcp_rmem[2]`. Rien si le programme
//! a fixé SO_RCVBUF. Un programme lent, lui, ne fait rien grandir.
//!
//! LA MÉMOIRE (`tcp_try_rmem_schedule`). Un segment dans la fenêtre doit tenir dans
//! SO_RCVBUF. Sinon, dans l'ordre : la limite ajustée à ce que la file garde
//! (`tcp_clamp_window`) ; la file recopiée en petits paquets denses (`tcp_collapse`) ;
//! la file hors d'ordre jetée par la fin ; en dernier recours, le segment est jeté
//! et un ACK annonce une fenêtre nulle (ICSK_ACK_NOMEM), que l'émetteur respecte, et
//! une lecture rouvrira.

use super::{ACK_POUSSE, ACK_POUSSE2, Charge, ECHELLE_MAX, FENETRE_MAX, MSS_DEFAUT, MSS_MIN, Memoire, TS_ALIGNE, Tcb, Tcp, apres};
use formats::reseau::tcp;

/// Le rapport de départ (TCP_DEFAULT_SCALING_RATIO), sur 256 (TCP_RMEM_TO_WIN_SCALE).
pub(super) const RATIO_DEFAUT: u8 = 128;
const RATIO_DECALAGE: u32 = 8;
/// `SOCK_MIN_RCVBUF` / 2 : le plus petit `window_clamp` (`tcp_set_window_clamp`).
const FENETRE_MAX_MIN: u32 = 1152;
/// La taille d'un paquet recopié (`SKB_MAX_ORDER(0, 0)`, une page moins ses
/// structures) par `tcp_collapse`.
const TAILLE_FONTE: usize = 3776;
/// La mémoire garantie à une socket au-delà de sa juste part (`tcp_rmem[0]`).
const RMEM0: usize = 4096;

/// L'espace de `tcp_rcv_space_adjust` (`rcvq_space`).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct EspaceLu {
    /// Le plus que le programme ait lu en un RTT (`space`).
    pub(super) octets: u32,
    /// Où en était la lecture (`copied_seq`), et quand, au début de la mesure.
    pub(super) seq: u32,
    pub(super) temps: u64,
}

impl<P: Charge> Tcb<P> {
    /// `tcp_win_from_space` : ce que `espace` octets de mémoire donnent en octets
    /// de données (négatif : la mémoire est déjà dépassée).
    pub(super) fn fenetre_de(&self, espace: i64) -> i64 {
        (espace * self.ratio as i64) >> RATIO_DECALAGE
    }

    /// `tcp_space_from_win`.
    fn espace_de(&self, fenetre: u32) -> u64 {
        ((fenetre as u64) << RATIO_DECALAGE) / self.ratio as u64
    }

    /// `tcp_space` : la place libre, en octets de données. (Sans `sk_backlog.len` :
    /// ce qui attend dans la file de la possession est traité par le possesseur
    /// avant qu'il n'émette.)
    fn espace_libre(&self) -> i64 {
        self.fenetre_de(self.rcvbuf as i64 - self.memoire_reception() as i64)
    }

    /// `tcp_full_space`.
    pub(super) fn espace_plein(&self) -> i64 {
        self.fenetre_de(self.rcvbuf as i64)
    }

    /// `tcp_receive_window` : ce qui reste de la dernière fenêtre annoncée.
    pub(super) fn fenetre_restante(&self) -> u32 {
        let reste = self.rcv_wup.wrapping_add(self.rcv_wnd).wrapping_sub(self.rcv_nxt) as i32;
        reste.max(0) as u32
    }

    /// La mémoire est-elle accordée, pour recevoir (`sk_rmem_schedule`,
    /// `__sk_mem_raise_allocated`) ? À la limite, non ; au-delà de la juste part, plus
    /// que le minimum (`tcp_rmem[0]`).
    pub(super) fn memoire_accordee(&self) -> bool {
        match self.memoire {
            Memoire::Limite => false,
            Memoire::Excedent => self.memoire_reception() < RMEM0,
            _ => true,
        }
    }

    /// `tcp_adjust_rcv_ssthresh` : sous pression, plus que quatre segments.
    fn seuil_reduit(&mut self) {
        self.rcv_ssthresh = self.rcv_ssthresh.min(4 * self.mss_local as u32);
    }

    /// `tcp_select_initial_window` (par `tcp_connect_init` ou
    /// `tcp_openreq_init_rwin`, pour le premier SYN), une fois TCP_MAXSEG, SO_RCVBUF
    /// et TCP_WINDOW_CLAMP connus : `mss`, la charge que nous annonçons, moins les
    /// options de chaque segment. La fenêtre, le plein de SO_RCVBUF arrondi à un
    /// multiple du MSS ; son plafond tient compte de l'échelle.
    pub(super) fn fenetre_initiale(&mut self, mss: u32) {
        let plein = self.espace_plein().max(0) as u32;
        if self.rcvbuf_fixe && (self.window_clamp > plein || self.window_clamp == 0) {
            self.window_clamp = plein;
        }
        let plafond = if self.window_clamp == 0 { FENETRE_MAX << ECHELLE_MAX } else { self.window_clamp };
        let mut espace = plein.min(plafond);
        if espace > mss && mss > 0 {
            espace -= espace % mss;
        }
        self.rcv_wnd = espace;
        self.window_clamp = plafond.min(FENETRE_MAX << self.echelle_reception);
        self.rcv_ssthresh = self.rcv_wnd;
    }

    /// `tcp_init_buffer_space`, à l'établissement. Le plafond réserve un segment
    /// de la place pleine (« Force reservation of one segment ») : `tcp_app_win`
    /// vaut 31 : le reste n'est pas réservé au programme.
    pub(super) fn espace_initial(&mut self, maintenant: u64) {
        self.espace.temps = maintenant;
        self.espace.seq = self.rcv_lu;
        let plein = self.espace_plein().max(0) as u32;
        let advmss = self.mss_local as u32;
        if self.window_clamp >= plein {
            self.window_clamp = plein;
        }
        if self.window_clamp > 2 * advmss && self.window_clamp + advmss > plein {
            self.window_clamp = (2 * advmss).max(plein.saturating_sub(advmss));
        }
        self.rcv_ssthresh = self.rcv_ssthresh.min(self.window_clamp);
        self.espace.octets = self.rcv_ssthresh.min(self.rcv_wnd).min(super::congestion::CWND_INITIALE * advmss);
    }

    /// `__tcp_select_window` : la fenêtre qu'on annoncerait maintenant, sans le
    /// réduire ni l'arrondi d'une fenêtre sans échelle. Une place libre sous la moitié
    /// de la pleine : le mode « quickack » cesse (ce récepteur ne suit pas), et si elle
    /// tombe sous le seizième de la pleine, ou sous un segment, on annonce 0, à temps.
    pub(super) fn choisir_fenetre(&mut self) -> u32 {
        let mut mss = self.ack.rcv_mss as i64;
        let mut libre = self.espace_libre();
        let permis = self.espace_plein();
        let plein = (self.window_clamp as i64).min(permis);
        if mss > plein {
            mss = plein;
            if mss <= 0 {
                return 0;
            }
        }
        let e = self.echelle_reception as u32;
        if libre < plein >> 1 {
            self.ack.rapides = 0;
            if self.memoire >= Memoire::Pression {
                self.seuil_reduit();
            }
            // Elle pourrait devenir la fenêtre : que l'échelle ne l'augmente pas.
            libre &= !((1i64 << e) - 1);
            if libre < permis >> 4 || libre < mss {
                return 0;
            }
        }
        if libre > self.rcv_ssthresh as i64 {
            libre = self.rcv_ssthresh as i64;
        }
        if e != 0 {
            // Avec une échelle, un multiple du MSS ne voudrait rien dire ; et une
            // place assez grande pour ne pas disparaître dans l'échelle.
            return ((libre + (1i64 << e) - 1) & !((1i64 << e) - 1)) as u32;
        }
        // Sans échelle, un multiple du MSS, le plus grand ; à moins d'un MSS de
        // l'annonce précédente, on la garde : la division n'est pas gratuite, et
        // l'émetteur voit une fenêtre stable.
        let mut fenetre = self.rcv_wnd as i64;
        if fenetre <= libre - mss || fenetre > libre {
            fenetre = if mss > 0 { libre - libre % mss } else { libre };
        } else if mss == plein && libre > fenetre + (plein >> 1) {
            fenetre = libre;
        }
        fenetre.max(0) as u32
    }

    /// `tcp_select_window`, pour tout segment qui part (hors SYN) : la fenêtre
    /// choisie, jamais moins que ce qui a déjà été promis ; ou 0 si un segment vient
    /// d'être jeté, faute de mémoire. Rend le champ de l'en-tête, décalé de l'échelle.
    pub(super) fn fenetre_a_annoncer(&mut self) -> u16 {
        if self.ack.sans_memoire {
            self.rcv_wnd = 0;
            self.rcv_wup = self.rcv_nxt;
            return 0;
        }
        let promis = self.fenetre_restante();
        let mut neuve = self.choisir_fenetre();
        let e = self.echelle_reception as u32;
        if neuve < promis {
            neuve = promis.div_ceil(1 << e) << e;
        }
        self.rcv_wnd = neuve;
        self.rcv_wup = self.rcv_nxt;
        (neuve.min(FENETRE_MAX << e) >> e) as u16
    }

    /// `tcp_measure_rcv_mss`, pour un segment de `longueur` octets, de taille vraie
    /// `vraie` : la taille des segments de l'autre, et le rapport, qui change avec
    /// elle. Un plus petit segment ne dit rien, sauf répété deux fois (il est plein
    /// pour l'autre : un MSS plus petit, ou des options) ; et il dit, s'il y en a deux,
    /// que l'autre n'envoie pas de quoi faire partir un ACK (ICSK_ACK_PUSHED).
    pub(super) fn mesurer_rcv_mss(&mut self, longueur: u32, vraie: usize, t: &Tcp) {
        let precedent = core::mem::take(&mut self.ack.dernier_segment);
        if longueur >= self.ack.rcv_mss {
            if longueur != self.ack.rcv_mss {
                let val = ((longueur as u64) << RATIO_DECALAGE) / vraie.max(1) as u64;
                let ancien = self.ratio;
                self.ratio = val.clamp(1, 255) as u8;
                if ancien != self.ratio {
                    let f = self.espace_plein().max(0) as u32;
                    self.poser_fenetre_max(f);
                    self.espace.octets = self.espace.octets.min(self.window_clamp);
                }
            }
            self.ack.rcv_mss = longueur.min(self.mss_local as u32);
            // Exactement un MSS, avec PSH : sans doute la fin d'une écriture ;
            // qu'une lecture qui vide tout fasse partir un ACK.
            if t.drapeaux & tcp::PSH != 0 {
                self.ack.pousse |= ACK_POUSSE;
            }
            return;
        }
        // La longueur en comptant l'en-tête, qui ne change pas avec les blocs SACK.
        let avec_entete = longueur + tcp::longueur_entete(&t.options) as u32;
        const ENTETE: u32 = tcp::ENTETE as u32;
        let reste = t.drapeaux & (tcp::FIN | tcp::URG | tcp::SYN | tcp::PSH) != 0;
        if avec_entete >= MSS_DEFAUT as u32 + ENTETE || (avec_entete >= MSS_MIN as u32 + ENTETE && !reste) {
            let l = avec_entete - ENTETE - if self.ts.is_some() { TS_ALIGNE as u32 } else { 0 };
            self.ack.dernier_segment = l;
            if l == precedent {
                self.ack.rcv_mss = l;
                return;
            }
        }
        if self.ack.pousse & ACK_POUSSE != 0 {
            self.ack.pousse |= ACK_POUSSE2;
        }
        self.ack.pousse |= ACK_POUSSE;
    }

    /// `tcp_set_window_clamp` (TCP_WINDOW_CLAMP, et le rapport qui change). 0 : rien
    /// (d'une socket fermée, il se règle sans connexion ; sinon, EINVAL).
    pub fn poser_fenetre_max(&mut self, val: u32) {
        if val == 0 {
            return;
        }
        let ancien = self.window_clamp;
        let neuf = val.max(FENETRE_MAX_MIN);
        if neuf == ancien {
            return;
        }
        self.window_clamp = neuf;
        if neuf < ancien {
            self.rcv_ssthresh = self.rcv_ssthresh.min(neuf);
        } else {
            self.rcv_ssthresh = self.rcv_ssthresh.max(self.rcv_wnd.min(neuf));
        }
    }

    /// `tcp_set_rcvlowat`, sur une connexion : le seuil vaut au plus la moitié de
    /// SO_RCVBUF s'il est fixé, sinon de `tcp_rmem[2]`, et SO_RCVBUF grandit assez pour
    /// le tenir. Rend le seuil retenu.
    pub fn poser_rcvlowat(&mut self, val: u32) -> u32 {
        let plafond = if self.rcvbuf_fixe { self.rcvbuf >> 1 } else { self.rcvbuf_max >> 1 };
        let val = val.min(plafond as u32);
        self.rcvlowat = val.max(1);
        if !self.rcvbuf_fixe {
            let espace = self.espace_de(val) as usize;
            if espace > self.rcvbuf {
                self.rcvbuf = espace;
                if self.window_clamp != 0 && self.window_clamp < val {
                    self.window_clamp = val;
                }
            }
        }
        self.rcvlowat
    }

    /// `tcp_grow_window`, pour un segment de `longueur` octets, de taille vraie
    /// `vraie`. Hors pression : s'il est de bon rendement (ou le deviendra sous une
    /// fenêtre plus petite), `rcv_ssthresh` grandit, d'au moins deux fois sa
    /// longueur, et l'ACK part vite pour le dire.
    pub(super) fn agrandir_fenetre(&mut self, longueur: u32, vraie: usize) {
        let place = (self.window_clamp as i64).min(self.espace_libre()) - self.rcv_ssthresh as i64;
        if place <= 0 {
            return;
        }
        if self.memoire >= Memoire::Pression {
            self.seuil_reduit();
            return;
        }
        let f = self.fenetre_de(vraie as i64);
        let increment = if f <= longueur as i64 { 2 * self.mss_local as i64 } else { self.agrandir_lentement(longueur as i64, vraie) };
        if increment > 0 {
            self.rcv_ssthresh += place.min(increment.max(2 * longueur as i64)) as u32;
            self.ack.rapides |= 1;
        }
    }

    /// `__tcp_grow_window` : un segment de mauvais rendement ne fait grandir qu'une
    /// petite fenêtre : plus il est mauvais, plus elle doit être petite.
    fn agrandir_lentement(&self, longueur: i64, vraie: usize) -> i64 {
        let mut v = self.fenetre_de(vraie as i64) >> 1;
        let mut fenetre = self.fenetre_de(self.rcvbuf_max as i64) >> 1;
        while self.rcv_ssthresh as i64 <= fenetre {
            if v <= longueur {
                return 2 * self.ack.rcv_mss as i64;
            }
            v >>= 1;
            fenetre >>= 1;
        }
        0
    }

    /// `tcp_rcvbuf_grow` : le programme a lu `lu` octets en un RTT. DRS a toujours un
    /// RTT de retard : le double ; l'émetteur peut doubler en démarrage lent : d'autant
    /// plus que cela grandit vite ; et ce qui attend hors d'ordre. Au plus `tcp_rmem[2]`.
    pub(super) fn rcvbuf_suit(&mut self, lu: u32) {
        let ancien = self.espace.octets;
        self.espace.octets = lu;
        if self.rcvbuf_fixe {
            return;
        }
        let mut fenetre = (lu as u64) << 1;
        let croissance = fenetre * lu.wrapping_sub(ancien) as u64 / ancien.max(1) as u64;
        fenetre = fenetre.wrapping_add(croissance << 1);
        if let Some(fin) = self.hors_ordre.derniere_fin() {
            fenetre = fenetre.wrapping_add(fin.wrapping_sub(self.rcv_nxt) as u64);
        }
        let espace = (self.espace_de(fenetre.min(u32::MAX as u64) as u32) as usize).min(self.rcvbuf_max);
        if espace > self.rcvbuf {
            self.rcvbuf = espace;
            self.window_clamp = self.fenetre_de(espace as i64) as u32;
        }
    }

    /// `tcp_rcv_space_adjust`, à chaque lecture : pas plus d'une mesure par RTT du
    /// récepteur ; ce que le programme a lu de nouveau (moins ce qui reste en file :
    /// il pourrait n'être que peu en retard) fait grandir SO_RCVBUF, s'il dépasse le
    /// plus grand vu.
    pub(super) fn ajuster_espace(&mut self, maintenant: u64) {
        let rtt = self.rcv_rtt8 >> 3;
        let ecoule = maintenant.saturating_sub(self.espace.temps);
        if ecoule < rtt || self.rcv_rtt8 == 0 {
            return;
        }
        let lu = self.rcv_lu.wrapping_sub(self.espace.seq) as i32;
        let en_file = self.rcv_nxt.wrapping_sub(self.rcv_lu) as i32;
        let lu = lu.wrapping_sub(en_file);
        if lu > self.espace.octets as i32 {
            self.rcvbuf_suit(lu as u32);
        }
        self.espace.seq = self.rcv_lu;
        self.espace.temps = maintenant;
    }

    /// `tcp_can_ingest` : `longueur` octets de plus tiennent-ils ? (Linux compte
    /// ici la longueur, pas la taille vraie : un petit paquet dans un gros tampon ne
    /// doit pas faire jeter ce que la fenêtre a promis.)
    fn peut_recevoir(&self, longueur: usize) -> bool {
        self.memoire_reception() + longueur <= self.rcvbuf
    }

    /// `tcp_clamp_window` : la limite de SO_RCVBUF atteinte. Il grandit jusqu'à ce que
    /// garde la file, si rien ne l'interdit ; sinon `rcv_ssthresh` tombe à deux segments.
    fn resserrer(&mut self) {
        self.ack.rapides = 0;
        if self.rcvbuf < self.rcvbuf_max && !self.rcvbuf_fixe && self.memoire == Memoire::Libre {
            self.rcvbuf = self.memoire_reception().min(self.rcvbuf_max);
        }
        if self.memoire_reception() > self.rcvbuf {
            self.rcv_ssthresh = self.window_clamp.min(2 * self.mss_local as u32);
        }
    }

    /// `tcp_prune_queue` : faire de la place pour un segment de `longueur` octets (au
    /// numéro `seq`). Faux : il faudra le jeter.
    fn elaguer(&mut self, seq: u32, longueur: usize) -> bool {
        if self.memoire_reception() == 0 {
            return false;
        }
        if !self.peut_recevoir(longueur) {
            self.resserrer();
        } else if self.memoire >= Memoire::Pression {
            self.seuil_reduit();
        }
        if self.peut_recevoir(longueur) {
            return true;
        }
        self.fondre_hors_ordre();
        self.fondre_reception();
        if self.peut_recevoir(longueur) {
            return true;
        }
        self.elaguer_hors_ordre(seq, longueur);
        self.peut_recevoir(longueur)
    }

    /// `tcp_prune_ofo_queue` : jeter ce qui attend hors d'ordre, par la fin, un
    /// huitième de SO_RCVBUF à la fois, jusqu'à ce que le segment au numéro `seq` tienne,
    /// mais jamais ce qui le précède : il arrive pour le combler, ou le suit. Les blocs
    /// SACK sont oubliés (comme à un RTO : l'émetteur le supporte, RFC 2018).
    fn elaguer_hors_ordre(&mut self, seq: u32, longueur: usize) -> bool {
        let mut but = (self.rcvbuf >> 3) as i64;
        let mut elague = false;
        while let Some(d) = self.hors_ordre.derniere_seq() {
            if apres(seq, d) {
                break;
            }
            let v = self.hors_ordre.jeter_la_derniere();
            elague = true;
            but -= v as i64;
            if self.hors_ordre.vide() || but <= 0 {
                if self.peut_recevoir(longueur) && self.memoire < Memoire::Pression {
                    break;
                }
                but = (self.rcvbuf >> 3) as i64;
            }
        }
        if elague {
            self.nb_blocs = 0;
        }
        elague
    }

    /// `tcp_try_rmem_schedule` : la place et la mémoire pour un segment. Faux : pas
    /// de place, malgré tout.
    pub(super) fn reserver_reception(&mut self, seq: u32, longueur: usize) -> bool {
        if !self.peut_recevoir(longueur) || !self.memoire_accordee() {
            if !self.elaguer(seq, longueur) {
                return false;
            }
            while !self.memoire_accordee() {
                if !self.elaguer_hors_ordre(seq, longueur) {
                    return false;
                }
            }
        }
        true
    }

    /// `tcp_collapse`, sur la file de lecture : à partir du premier paquet de
    /// mauvais rendement, tout est recopié en paquets denses d'une page (de petits
    /// segments gardent chacun un tampon et ses structures ; Linux les fond d'ailleurs
    /// dès l'arrivée quand il le peut, ce que nos tampons exacts ne permettent pas). La
    /// mémoire manque : on s'arrête là.
    fn fondre_reception(&mut self) {
        let Some(premier) = self.reception.iter().position(|p| self.fenetre_de(p.taille_vraie() as i64) > p.octets().len() as i64) else { return };
        let mut reste: usize = self.reception.iter().skip(premier).map(|p| p.octets().len()).sum();
        let mut neuves: alloc::vec::Vec<P> = alloc::vec::Vec::new();
        let (mut i, mut decalage) = (premier, 0);
        while reste > 0 {
            let n = reste.min(TAILLE_FONTE);
            let Some(mut neuve) = P::neuve(n) else { break };
            let mut fait = 0;
            while fait < n {
                let o = &self.reception[i].octets()[decalage..];
                let m = o.len().min(n - fait);
                neuve.completer(&o[..m]);
                fait += m;
                decalage += m;
                if decalage == self.reception[i].octets().len() {
                    i += 1;
                    decalage = 0;
                }
            }
            if neuves.try_reserve(1).is_err() {
                // Ce paquet-là n'est pas pris : ce qu'il a recopié reste à sa place.
                let (j, d) = revenir(&self.reception, i, decalage, fait);
                (i, decalage) = (j, d);
                break;
            }
            neuves.push(neuve);
            reste -= n;
        }
        if neuves.is_empty() || self.reception.try_reserve(neuves.len()).is_err() {
            return;
        }
        // Les paquets entièrement recopiés sont rendus ; le dernier, s'il ne l'a été
        // qu'en partie (la mémoire a manqué), perd ce qui a été recopié, et reste.
        for p in self.reception.drain(premier..i) {
            self.taille_vraie_reception = self.taille_vraie_reception.saturating_sub(p.taille_vraie());
        }
        if decalage > 0 && let Some(p) = self.reception.get_mut(premier) {
            p.avancer(decalage);
        }
        for (k, p) in neuves.into_iter().enumerate() {
            self.taille_vraie_reception += p.taille_vraie();
            self.reception.insert(premier + k, p);
        }
    }

    /// `tcp_collapse_ofo_queue` : de même pour chaque suite sans trou de la file hors
    /// d'ordre, sauf les toutes petites.
    fn fondre_hors_ordre(&mut self) {
        self.hors_ordre.fondre(TAILLE_FONTE, self.rcvbuf >> 3, self.ratio);
    }

    /// `tcp_rmem_pressure` : sous pression, ou 7/8 de SO_RCVBUF pris : plus question
    /// d'attendre SO_RCVLOWAT.
    pub(super) fn reception_pressee(&self) -> bool {
        self.memoire >= Memoire::Pression || self.memoire_reception() > self.rcvbuf - (self.rcvbuf >> 3)
    }
}

/// Revient de `n` octets en arrière depuis la place (`i`, `decalage`) d'une file.
fn revenir<P: Charge>(file: &alloc::collections::VecDeque<P>, mut i: usize, mut decalage: usize, mut n: usize) -> (usize, usize) {
    while n > decalage {
        n -= decalage;
        i -= 1;
        decalage = file[i].octets().len();
    }
    (i, decalage - n)
}
