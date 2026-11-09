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

#[cfg(test)]
mod tests {
    use super::super::essais::*;
    use super::*;
    use alloc::{vec, vec::Vec};

    /// Un ratio d'une moitié, 100 000 octets de tampon, rien de reçu : la pleine vaut 50 000.
    fn cas() -> C {
        let mut c = etablie(true);
        c.ratio = 128;
        c.rcvbuf = 100_000;
        c.window_clamp = 1 << 24;
        c.rcv_ssthresh = 1 << 24;
        c.ack.rcv_mss = 1000;
        c.echelle_reception = 0;
        c.rcv_wnd = 0;
        c.ack.rapides = 3;
        c
    }

    /// `__tcp_select_window`, sans échelle : un multiple du MSS, à moins d'un MSS de l'annonce
    /// précédente, celle-ci.
    #[test]
    fn la_fenetre_sans_echelle() {
        let mut c = cas();
        c.rcv_ssthresh = 30_500;
        // (annonce précédente, résultat)
        for (avant, apres_) in [(0, 30_000), (29_500, 30_000), (29_501, 29_501), (29_700, 29_700), (30_000, 30_000), (30_500, 30_500), (30_501, 30_000)] {
            c.rcv_wnd = avant;
            assert_eq!(c.choisir_fenetre(), apres_, "avant {avant}");
        }
    }

    /// Le MSS vaut la pleine : on ne garde pas une annonce trop petite.
    #[test]
    fn la_fenetre_quand_le_mss_est_la_pleine() {
        let mut c = cas();
        c.window_clamp = 2000;
        c.ack.rcv_mss = 2000;
        c.rcv_ssthresh = 5000;
        c.rcv_wnd = 3500;
        assert_eq!(c.choisir_fenetre(), 5000);
        c.rcv_wnd = 4000;
        assert_eq!(c.choisir_fenetre(), 4000, "pas plus d'une demi-pleine d'écart : on la garde");
        // Le MSS plus grand que la pleine : borné par elle.
        c.ack.rcv_mss = 3000;
        c.rcv_wnd = 3500;
        assert_eq!(c.choisir_fenetre(), 5000);
        // Pas de pleine du tout : 0.
        c.window_clamp = 0;
        assert_eq!(c.choisir_fenetre(), 0);
        c.window_clamp = 1 << 24;
        c.rcvbuf = 0;
        assert_eq!(c.choisir_fenetre(), 0);
    }

    /// Le tampon se remplit : le mode rapide cesse sous la moitié, 0 sous le seizième ou un MSS.
    #[test]
    fn la_fenetre_quand_le_tampon_se_remplit() {
        let mut c = cas();
        // Libre : la moitié de ce qui reste. Exactement la moitié de la pleine : rien ne change.
        c.taille_vraie_reception = 50_000;
        assert_eq!(c.choisir_fenetre(), 25_000);
        assert_eq!(c.ack.rapides, 3);
        c.taille_vraie_reception = 50_002;
        assert_eq!(c.choisir_fenetre(), 24_000);
        assert_eq!(c.ack.rapides, 0);
        assert_eq!(c.rcv_ssthresh, 1 << 24, "pas de pression, pas de seuil réduit");
        // Le seizième : 3125 ; juste au-dessus et au-dessous.
        c.taille_vraie_reception = 93_750;
        assert_eq!(c.choisir_fenetre(), 3000);
        c.taille_vraie_reception = 93_752;
        assert_eq!(c.choisir_fenetre(), 0);
        // Un MSS plus grand : c'est lui qui compte.
        c.ack.rcv_mss = 4000;
        c.taille_vraie_reception = 92_000;
        assert_eq!(c.choisir_fenetre(), 4000);
        c.taille_vraie_reception = 92_002;
        assert_eq!(c.choisir_fenetre(), 0);
        // Sous pression : `tcp_adjust_rcv_ssthresh`, quatre segments.
        c.ack.rcv_mss = 1000;
        c.memoire = Memoire::Pression;
        c.taille_vraie_reception = 60_000;
        assert_eq!(c.choisir_fenetre(), 4 * c.mss_local as u32);
        assert_eq!(c.rcv_ssthresh, 4 * c.mss_local as u32);
        // Plus de mémoire qu'il n'en faut : négatif, 0.
        c.memoire = Memoire::Libre;
        c.rcv_ssthresh = 1 << 24;
        c.taille_vraie_reception = 200_000;
        assert_eq!(c.choisir_fenetre(), 0);
    }

    /// Avec une échelle : `ALIGN` vers le haut, mais une petite place s'arrondit d'abord vers le
    /// bas : l'échelle ne doit pas l'augmenter.
    #[test]
    fn la_fenetre_avec_une_echelle() {
        let mut c = cas();
        c.echelle_reception = 4;
        c.rcv_ssthresh = 30_500;
        assert_eq!(c.choisir_fenetre(), 30_512);
        c.rcv_ssthresh = 30_496;
        assert_eq!(c.choisir_fenetre(), 30_496);
        c.rcv_ssthresh = 1 << 24;
        c.taille_vraie_reception = 89_990;
        assert_eq!(c.choisir_fenetre(), 4992);
    }

    fn entete(drapeaux: u8) -> Tcp {
        Tcp { drapeaux, ..Tcp::default() }
    }

    /// `tcp_measure_rcv_mss` : un segment au moins aussi grand que l'estimation.
    #[test]
    fn le_mss_mesure_sur_un_grand_segment() {
        let mut c = cas();
        c.mss_local = 1460;
        c.ack.rcv_mss = 500;
        c.ack.pousse = 0;
        // Le rendement change : (1000 << 8) / 4000 = 64 ; le plafond suit.
        c.mesurer_rcv_mss(1000, 4000, &entete(tcp::ACK));
        assert_eq!(c.ack.rcv_mss, 1000);
        assert_eq!(c.ratio, 64);
        assert_eq!(c.window_clamp, 25_000);
        assert_eq!(c.ack.pousse, 0, "sans PSH");
        // Rien ne change à longueur égale, même de rendement différent.
        c.mesurer_rcv_mss(1000, 8000, &entete(tcp::ACK));
        assert_eq!(c.ratio, 64);
        // Avec PSH : la fin d'une écriture.
        c.mesurer_rcv_mss(1000, 8000, &entete(tcp::ACK | tcp::PSH));
        assert_eq!(c.ack.pousse, ACK_POUSSE);
        // Borné par ce qu'on a annoncé.
        c.mesurer_rcv_mss(2000, 8000, &entete(tcp::ACK));
        assert_eq!(c.ack.rcv_mss, 1460);
        // Un rendement hors de 1..255.
        c.ack.rcv_mss = 1000;
        c.mesurer_rcv_mss(1100, 1 << 30, &entete(tcp::ACK));
        assert_eq!(c.ratio, 1);
        c.mesurer_rcv_mss(1200, 1, &entete(tcp::ACK));
        assert_eq!(c.ratio, 255);
        // Le même rendement : `espace` ne change pas.
        c.ratio = 64;
        c.espace.octets = 1 << 30;
        c.window_clamp = 1 << 24;
        c.ack.rcv_mss = 1000;
        c.mesurer_rcv_mss(1100, 4400, &entete(tcp::ACK));
        assert_eq!(c.window_clamp, 1 << 24);
        assert_eq!(c.espace.octets, 1 << 30);
        // Un autre rendement : `espace` est borné par le nouveau plafond.
        c.ack.rcv_mss = 1000;
        c.mesurer_rcv_mss(1100, 2200, &entete(tcp::ACK));
        assert_eq!(c.ratio, 128);
        assert_eq!(c.espace.octets, c.window_clamp);
    }

    /// Un segment plus petit que l'estimation : deux de même taille la font baisser ; sinon, seuls
    /// les « poussés » s'en souviennent.
    #[test]
    fn le_mss_mesure_sur_de_petits_segments() {
        let mut c = cas();
        c.ack.rcv_mss = 1000;
        c.ack.pousse = 0;
        // 536 + 20 d'en-tête tout juste : il compte, même avec PSH.
        c.mesurer_rcv_mss(536, 2000, &entete(tcp::ACK | tcp::PSH));
        assert_eq!(c.ack.rcv_mss, 1000);
        assert_eq!(c.ack.dernier_segment, 536);
        assert_eq!(c.ack.pousse, ACK_POUSSE);
        c.mesurer_rcv_mss(536, 2000, &entete(tcp::ACK));
        assert_eq!(c.ack.rcv_mss, 536, "deux de suite");
        assert_eq!(c.ack.pousse, ACK_POUSSE, "il revient avant d'avoir compté");
        // En dessous de 536, avec un des drapeaux : il n'est pas mesuré.
        for d in [tcp::FIN, tcp::URG, tcp::SYN, tcp::PSH] {
            c.ack.rcv_mss = 1000;
            c.ack.dernier_segment = 300;
            c.mesurer_rcv_mss(300, 2000, &entete(tcp::ACK | d));
            assert_eq!(c.ack.rcv_mss, 1000, "{d:#x}");
            assert_eq!(c.ack.dernier_segment, 0, "{d:#x}");
        }
        // Sans drapeau : à partir de 88 + 20.
        c.ack.dernier_segment = 88;
        c.mesurer_rcv_mss(88, 2000, &entete(tcp::ACK));
        assert_eq!(c.ack.rcv_mss, 88);
        c.ack.rcv_mss = 1000;
        c.ack.dernier_segment = 87;
        c.mesurer_rcv_mss(87, 2000, &entete(tcp::ACK));
        assert_eq!(c.ack.rcv_mss, 1000);
        assert_eq!(c.ack.dernier_segment, 0);
        // Pas la même taille : retenue pour la prochaine fois.
        c.ack.dernier_segment = 200;
        c.mesurer_rcv_mss(300, 2000, &entete(tcp::ACK));
        assert_eq!(c.ack.rcv_mss, 1000);
        assert_eq!(c.ack.dernier_segment, 300);
        // Les « poussés » : un, puis deux.
        c.ack.pousse = 0;
        c.ack.dernier_segment = 0;
        c.mesurer_rcv_mss(50, 2000, &entete(tcp::ACK));
        assert_eq!(c.ack.pousse, ACK_POUSSE);
        c.mesurer_rcv_mss(50, 2000, &entete(tcp::ACK));
        assert_eq!(c.ack.pousse, ACK_POUSSE | ACK_POUSSE2);
        // Les horodatages ne comptent pas dans la taille retenue, les autres options comptent dans
        // le seuil.
        c.ts = Some(crate::tcp::Horodatages { recent: 0, instant: 0, decalage: 0 });
        c.ack.rcv_mss = 1000;
        c.ack.dernier_segment = 0;
        let mut t = entete(tcp::ACK);
        t.options.horodatage = Some((1, 2));
        c.mesurer_rcv_mss(100, 2000, &t);
        assert_eq!(c.ack.dernier_segment, 100, "(100 + 32 - 20 - 12)");
    }

    #[test]
    fn la_memoire_accordee() {
        let mut c = cas();
        for m in [Memoire::Libre, Memoire::Souple, Memoire::Pression] {
            c.memoire = m;
            assert!(c.memoire_accordee());
        }
        c.memoire = Memoire::Limite;
        assert!(!c.memoire_accordee());
        c.memoire = Memoire::Excedent;
        c.taille_vraie_reception = RMEM0 - 1;
        assert!(c.memoire_accordee());
        c.taille_vraie_reception = RMEM0;
        assert!(!c.memoire_accordee());
    }

    /// `tcp_select_initial_window`.
    #[test]
    fn la_fenetre_initiale() {
        let mut c = cas();
        c.rcvbuf_fixe = false;
        c.window_clamp = 0;
        c.echelle_reception = 2;
        c.fenetre_initiale(1000);
        assert_eq!(c.rcv_wnd, 50_000);
        assert_eq!(c.rcv_ssthresh, 50_000);
        assert_eq!(c.window_clamp, 65_535 << 2);
        // Un arrondi au MSS, sauf si le MSS est plus grand, ou nul.
        c.rcvbuf = 2500;
        c.window_clamp = 0;
        c.fenetre_initiale(1000);
        assert_eq!(c.rcv_wnd, 1000);
        c.window_clamp = 0;
        c.fenetre_initiale(1250);
        assert_eq!(c.rcv_wnd, 1250);
        c.window_clamp = 0;
        c.fenetre_initiale(5000);
        assert_eq!(c.rcv_wnd, 1250);
        c.window_clamp = 0;
        c.fenetre_initiale(0);
        assert_eq!(c.rcv_wnd, 1250);
        // TCP_WINDOW_CLAMP.
        c.rcvbuf = 100_000;
        c.window_clamp = 7000;
        c.fenetre_initiale(1000);
        assert_eq!(c.rcv_wnd, 7000);
        assert_eq!(c.window_clamp, 7000);
        // SO_RCVBUF fixé : le plafond ne le dépasse pas.
        c.rcvbuf_fixe = true;
        c.window_clamp = 70_000;
        c.fenetre_initiale(1000);
        assert_eq!(c.window_clamp, 50_000);
        c.window_clamp = 50_000;
        c.fenetre_initiale(1000);
        assert_eq!(c.window_clamp, 50_000);
        c.window_clamp = 0;
        c.fenetre_initiale(1000);
        assert_eq!(c.window_clamp, 50_000);
        c.window_clamp = 7000;
        c.fenetre_initiale(1000);
        assert_eq!(c.window_clamp, 7000);
    }

    /// `tcp_init_buffer_space`.
    #[test]
    fn l_espace_initial() {
        let mut c = cas();
        c.mss_local = 1000;
        c.rcv_lu = 1234;
        // Un plafond plus grand que la pleine : la pleine, moins un segment réservé.
        c.window_clamp = 70_000;
        c.rcv_ssthresh = 90_000;
        c.rcv_wnd = 90_000;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 49_000);
        assert_eq!(c.rcv_ssthresh, 49_000);
        assert_eq!(c.espace.octets, 10_000, "au plus la cwnd initiale");
        assert_eq!((c.espace.temps, c.espace.seq), (HEURE, 1234));
        // À un segment de la pleine exactement : la réserve s'applique ; plus loin, non.
        c.window_clamp = 49_000;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 49_000);
        c.window_clamp = 49_001;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 49_000);
        c.window_clamp = 40_000;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 40_000);
        // Au plus deux segments : on n'y touche pas. Une petite pleine : au moins deux segments.
        c.rcvbuf = 4000;
        c.window_clamp = 2000;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 2000);
        c.window_clamp = 2000 + 1;
        c.rcvbuf = 4004;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 2000);
        // Le plus petit de la fenêtre et du seuil.
        let mut d = cas();
        d.mss_local = 1000;
        d.window_clamp = 40_000;
        d.rcv_ssthresh = 3000;
        d.rcv_wnd = 2000;
        d.espace_initial(HEURE);
        assert_eq!(d.espace.octets, 2000);
        d.rcv_ssthresh = 2000;
        d.rcv_wnd = 3000;
        d.espace_initial(HEURE);
        assert_eq!(d.espace.octets, 2000);
    }

    /// `tcp_set_rcvlowat`.
    #[test]
    fn so_rcvlowat() {
        let mut c = cas();
        c.rcvbuf_max = 1 << 20;
        c.rcvbuf_fixe = false;
        assert_eq!(c.poser_rcvlowat(0), 1);
        assert_eq!(c.rcvbuf, 100_000);
        // De quoi le loger : SO_RCVBUF grandit, et le plafond s'il est trop bas.
        c.window_clamp = 60_000;
        assert_eq!(c.poser_rcvlowat(100_000), 100_000);
        assert_eq!(c.rcvbuf, 200_000);
        assert_eq!(c.window_clamp, 100_000);
        // Déjà assez grand : rien.
        c.window_clamp = 120_000;
        assert_eq!(c.poser_rcvlowat(100_000), 100_000);
        assert_eq!(c.rcvbuf, 200_000);
        assert_eq!(c.window_clamp, 120_000);
        c.rcvbuf = 100_000;
        c.window_clamp = 120_000;
        c.poser_rcvlowat(100_000);
        assert_eq!(c.window_clamp, 120_000);
        // Un plafond nul reste nul.
        c.rcvbuf = 100_000;
        c.window_clamp = 0;
        c.poser_rcvlowat(100_000);
        assert_eq!(c.window_clamp, 0);
        // Borné par la moitié du maximum, ou de SO_RCVBUF fixé (qui ne bouge pas).
        assert_eq!(c.poser_rcvlowat(1 << 30), 1 << 19);
        c.rcvbuf_fixe = true;
        c.rcvbuf = 100_000;
        assert_eq!(c.poser_rcvlowat(1 << 30), 50_000);
        assert_eq!(c.rcvbuf, 100_000);
    }

    /// `tcp_grow_window`.
    #[test]
    fn agrandir_la_fenetre() {
        let mut c = cas();
        c.mss_local = 1000;
        c.rcvbuf_max = 1 << 20;
        c.window_clamp = 40_000;
        c.rcv_ssthresh = 10_000;
        c.ack.rapides = 0;
        // Un bon rendement (fenetre_de(2000) = 1000 <= 1000) : au moins deux MSS, ou deux segments.
        c.agrandir_fenetre(1000, 2000);
        assert_eq!(c.rcv_ssthresh, 12_000);
        assert_eq!(c.ack.rapides, 1);
        c.agrandir_fenetre(1500, 3000);
        assert_eq!(c.rcv_ssthresh, 15_000);
        // Borné par ce qui reste de place.
        c.rcv_ssthresh = 39_000;
        c.agrandir_fenetre(1000, 2000);
        assert_eq!(c.rcv_ssthresh, 40_000);
        // Plus de place : rien. Et de même si la place libre est plus petite que le plafond.
        c.ack.rapides = 0;
        c.agrandir_fenetre(1000, 2000);
        assert_eq!(c.rcv_ssthresh, 40_000);
        assert_eq!(c.ack.rapides, 0);
        c.rcv_ssthresh = 10_000;
        c.taille_vraie_reception = 80_000;
        c.agrandir_fenetre(1000, 2000);
        assert_eq!(c.rcv_ssthresh, 10_000);
        c.taille_vraie_reception = 79_000;
        c.agrandir_fenetre(1000, 2000);
        assert_eq!(c.rcv_ssthresh, 10_500);
        // Sous pression : réduit, plus d'agrandissement.
        c.taille_vraie_reception = 0;
        c.memoire = Memoire::Pression;
        c.rcv_ssthresh = 10_000;
        c.agrandir_fenetre(1000, 2000);
        assert_eq!(c.rcv_ssthresh, 4000);
        c.memoire = Memoire::Souple;
        // Un mauvais rendement (fenetre_de(32 000) = 16 000) : `__tcp_grow_window`.
        c.ack.rcv_mss = 700;
        c.window_clamp = 60_000;
        c.rcv_ssthresh = 40_000;
        assert_eq!(c.agrandir_lentement(1000, 32_000), 0, "(trop grande pour ce rendement)");
        c.agrandir_fenetre(1000, 32_000);
        assert_eq!(c.rcv_ssthresh, 40_000);
        // Une fenêtre plus petite : elle grandit, de deux rcv_mss (ou deux segments).
        c.rcv_ssthresh = 3000;
        assert_eq!(c.agrandir_lentement(1000, 32_000), 1400);
        c.agrandir_fenetre(1000, 32_000);
        assert_eq!(c.rcv_ssthresh, 5000);
    }

    /// `__tcp_grow_window`, pas à pas : v et la fenêtre sont divisés par deux ensemble.
    #[test]
    fn agrandir_lentement_aux_bornes() {
        let mut c = cas();
        c.rcvbuf_max = 1 << 20;
        c.ack.rcv_mss = 700;
        // fenetre_de(2^20) >> 1 = 2^18, v = 8000 ; il faut 3 pas pour v <= 1000 : la fenêtre 2^15.
        for (seuil, attendu) in [(1 << 15, 1400), ((1 << 15) + 1, 0), ((1 << 18) + 1, 0)] {
            c.rcv_ssthresh = seuil;
            assert_eq!(c.agrandir_lentement(1000, 32_000), attendu, "seuil {seuil}");
        }
        // Une longueur exacte : v <= longueur.
        c.rcv_ssthresh = 1 << 18;
        assert_eq!(c.agrandir_lentement(8000, 32_000), 1400);
        assert_eq!(c.agrandir_lentement(7999, 32_000), 0);
    }

    /// `tcp_clamp_window`.
    #[test]
    fn resserrer() {
        let mut c = cas();
        c.mss_local = 1000;
        c.rcvbuf_max = 200_000;
        c.window_clamp = 50_000;
        c.rcv_ssthresh = 30_000;
        c.rcvbuf_fixe = false;
        c.memoire = Memoire::Libre;
        // SO_RCVBUF prend ce que garde la file ; le seuil ne bouge pas.
        c.taille_vraie_reception = 150_000;
        c.resserrer();
        assert_eq!(c.ack.rapides, 0);
        assert_eq!(c.rcvbuf, 150_000);
        assert_eq!(c.rcv_ssthresh, 30_000);
        // Borné par le maximum : il dépasse encore, le seuil tombe à deux segments.
        c.rcvbuf = 100_000;
        c.taille_vraie_reception = 300_000;
        c.resserrer();
        assert_eq!(c.rcvbuf, 200_000);
        assert_eq!(c.rcv_ssthresh, 2000);
        // ... ou au plafond, s'il est plus petit.
        c.window_clamp = 1500;
        c.rcv_ssthresh = 30_000;
        c.resserrer();
        assert_eq!(c.rcv_ssthresh, 1500);
        // SO_RCVBUF fixé, au maximum, ou la mémoire tendue : il ne grandit pas.
        for (fixe, buf, mem) in [(true, 100_000, Memoire::Libre), (false, 100_000, Memoire::Souple), (false, 200_000, Memoire::Libre)] {
            c.rcvbuf_fixe = fixe;
            c.rcvbuf = buf;
            c.memoire = mem;
            c.resserrer();
            assert_eq!(c.rcvbuf, buf, "{fixe} {buf}");
        }
        // Une file égale à SO_RCVBUF ne dépasse pas.
        c.rcvbuf_fixe = true;
        c.rcvbuf = 100_000;
        c.memoire = Memoire::Libre;
        c.taille_vraie_reception = 100_000;
        c.window_clamp = 50_000;
        c.rcv_ssthresh = 30_000;
        c.resserrer();
        assert_eq!(c.rcv_ssthresh, 30_000);
    }

    #[test]
    fn la_reception_pressee() {
        let mut c = cas();
        c.taille_vraie_reception = 87_500;
        assert!(!c.reception_pressee(), "7/8 tout juste");
        c.taille_vraie_reception = 87_501;
        assert!(c.reception_pressee());
        c.taille_vraie_reception = 0;
        assert!(!c.reception_pressee());
        c.memoire = Memoire::Souple;
        assert!(!c.reception_pressee());
        c.memoire = Memoire::Pression;
        assert!(c.reception_pressee());
    }

    /// `tcp_prune_ofo_queue` : par la fin, jamais ce qui précède le segment, un huitième à la fois.
    #[test]
    fn elaguer_le_hors_ordre() {
        let mut c = cas();
        c.rcvbuf = 8000;
        let base = c.rcv_nxt;
        let places = [1000u32, 2000, 3000, 4000, 5000];
        for p in places {
            c.hors_ordre.ranger(base + p, octets(500, 1000)).unwrap();
        }
        c.nb_blocs = 2;
        // Le segment arrive après tout : rien à jeter.
        assert!(!c.elaguer_hors_ordre(base + 6000, 100));
        assert_eq!(c.nb_blocs, 2);
        assert_eq!(c.hors_ordre.taille_vraie, 5000);
        // Pour 4000 octets, une place : 1000 à la fois (rcvbuf >> 3), jusqu'à ce qu'il tienne.
        assert!(c.elaguer_hors_ordre(base + 500, 4000));
        assert_eq!(c.nb_blocs, 0, "les blocs sont oubliés");
        assert_eq!(c.hors_ordre.taille_vraie, 4000);
        // Jamais ce qui le précède.
        assert!(c.elaguer_hors_ordre(base + 3500, 100_000));
        assert_eq!(c.hors_ordre.derniere_seq(), Some(base + 3000));
        // Sous pression, on va jusqu'au bout, même s'il tient déjà.
        c.memoire = Memoire::Pression;
        assert!(c.elaguer_hors_ordre(base, 0));
        assert!(c.hors_ordre.vide());
    }

    /// `tcp_collapse`.
    #[test]
    fn fondre_la_reception() {
        let mut c = cas();
        c.ratio = 128;
        // Le premier de bon rendement reste ; ensuite, recopiés en paquets denses.
        c.reception.push_back(octets(1000, 2000));
        c.reception.push_back(octets(100, 2000));
        c.reception.push_back(octets(3700, 8000));
        c.taille_vraie_reception = 12_000;
        c.fondre_reception();
        let tailles: Vec<usize> = c.reception.iter().map(|p| p.octets().len()).collect();
        assert_eq!(tailles, vec![1000, TAILLE_FONTE, 24]);
        // Le tout, moins ce qui a été rendu, plus ce qui a été fait.
        let vraie: usize = c.reception.iter().map(|p| p.taille_vraie()).sum();
        assert_eq!(c.taille_vraie_reception, vraie);
        assert_eq!(c.reception[0].taille_vraie(), 2000);
        // Rien de mauvais rendement : rien.
        let mut d = cas();
        d.reception.push_back(octets(1000, 2000));
        d.taille_vraie_reception = 2000;
        d.fondre_reception();
        assert_eq!(d.reception[0].taille_vraie(), 2000);
        assert_eq!(d.reception.len(), 1);
    }

    #[test]
    fn revenir_en_arriere() {
        let mut f = alloc::collections::VecDeque::new();
        f.push_back(octets(10, 0));
        f.push_back(octets(20, 0));
        f.push_back(octets(30, 0));
        assert_eq!(revenir(&f, 2, 5, 3), (2, 2));
        assert_eq!(revenir(&f, 2, 5, 5), (2, 0));
        assert_eq!(revenir(&f, 2, 5, 6), (1, 19));
        assert_eq!(revenir(&f, 2, 5, 26), (0, 9));
    }

    /// `tcp_rcvbuf_grow` : 2 × lu ; plus ce qui a crû depuis la dernière fois, proportionnellement
    /// et deux fois ; plus ce qui attend hors d'ordre ; ramené de fenêtre en mémoire.
    #[test]
    fn rcvbuf_suit_le_debit() {
        let mut c = cas();
        c.rcvbuf_fixe = true;
        c.espace.octets = 1000;
        c.rcvbuf_suit(5000);
        assert_eq!(c.espace.octets, 5000);
        assert_eq!(c.rcvbuf, 100_000, "SO_RCVBUF fixé");
        c.rcvbuf_fixe = false;
        c.rcvbuf_max = 1 << 30;
        c.rcvbuf = 1000;
        c.espace.octets = 40_000;
        // 2 × 50 000 = 100 000 ; croissance 100 000 × 10 000 / 40 000 = 25 000, deux fois.
        c.rcvbuf_suit(50_000);
        assert_eq!(c.espace.octets, 50_000);
        assert_eq!(c.rcvbuf, 2 * 150_000);
        assert_eq!(c.window_clamp, 150_000);
        // Rien de plus lu : le double seulement. Et plus petit : on n'y touche pas.
        let mut d = cas();
        d.rcvbuf_max = 1 << 30;
        d.rcvbuf = 2 * 100_000 - 1;
        d.espace.octets = 50_000;
        d.rcvbuf_suit(50_000);
        assert_eq!(d.rcvbuf, 2 * 100_000);
        assert_eq!(d.window_clamp, 100_000);
        d.window_clamp = 77;
        d.rcvbuf_suit(50_000);
        assert_eq!((d.rcvbuf, d.window_clamp), (2 * 100_000, 77), "le même");
        // Borné par tcp_rmem[2].
        d.rcvbuf_max = 300_000;
        d.espace.octets = 50_000;
        d.rcvbuf_suit(200_000);
        assert_eq!(d.rcvbuf, 300_000);
        // Ce qui attend hors d'ordre.
        let mut e = cas();
        e.rcvbuf_max = 1 << 30;
        e.rcvbuf = 1000;
        e.espace.octets = 50_000;
        e.hors_ordre.ranger(e.rcv_nxt + 1000, octets(500, 1000)).unwrap();
        e.rcvbuf_suit(50_000);
        assert_eq!(e.rcvbuf, 2 * (100_000 + 1500));
    }

    /// `tcp_rcv_space_adjust`.
    #[test]
    fn ajuster_l_espace() {
        let mut c = cas();
        c.rcvbuf_max = 1 << 30;
        c.rcvbuf = 1000;
        c.espace.temps = HEURE;
        c.espace.seq = c.rcv_lu;
        c.espace.octets = 1000;
        // Pas de RTT du récepteur : rien.
        c.rcv_rtt8 = 0;
        c.rcv_lu = c.rcv_lu.wrapping_add(5000);
        c.rcv_nxt = c.rcv_lu;
        c.ajuster_espace(HEURE + 100 * MS);
        assert_eq!(c.espace.octets, 1000);
        // Pas encore un RTT : rien. Tout juste un RTT : oui.
        c.rcv_rtt8 = 8 * 10 * MS;
        c.ajuster_espace(HEURE + 10 * MS - 1);
        assert_eq!(c.espace.octets, 1000);
        c.ajuster_espace(HEURE + 10 * MS);
        assert_eq!(c.espace.octets, 5000);
        assert_eq!(c.espace.temps, HEURE + 10 * MS);
        assert_eq!(c.espace.seq, c.rcv_lu);
        assert!(c.rcvbuf > 1000);
        // Ce qui reste en file ne compte pas : 4000 lus, 1000 en file : 3000 ; pas le plus grand.
        let t = c.espace.temps;
        c.rcv_lu = c.rcv_lu.wrapping_add(4000);
        c.rcv_nxt = c.rcv_lu.wrapping_add(1000);
        c.ajuster_espace(t + 10 * MS);
        assert_eq!(c.espace.octets, 5000);
        assert_eq!(c.espace.temps, t + 10 * MS, "la mesure repart quand même");
        // Égal au plus grand : rien ; au-dessus : oui.
        let t = c.espace.temps;
        c.rcv_nxt = c.rcv_lu;
        c.rcv_lu = c.rcv_lu.wrapping_add(5000);
        c.rcv_nxt = c.rcv_lu;
        c.ajuster_espace(t + 10 * MS);
        assert_eq!(c.espace.octets, 5000);
        let t = c.espace.temps;
        c.rcv_lu = c.rcv_lu.wrapping_add(5001);
        c.rcv_nxt = c.rcv_lu;
        c.ajuster_espace(t + 10 * MS);
        assert_eq!(c.espace.octets, 5001);
    }

    /// `tcp_set_window_clamp` : plus bas, `rcv_ssthresh` suit.
    #[test]
    fn la_fenetre_maximale() {
        let mut c = cas();
        c.window_clamp = 20_000;
        c.rcv_ssthresh = 15_000;
        c.poser_fenetre_max(0);
        assert_eq!(c.window_clamp, 20_000);
        c.poser_fenetre_max(10_000);
        assert_eq!(c.window_clamp, 10_000);
        assert_eq!(c.rcv_ssthresh, 10_000);
        // Plus haut : le seuil suit ce qu'on a déjà annoncé, au plus le plafond.
        c.rcv_wnd = 25_000;
        c.rcv_ssthresh = 5000;
        c.poser_fenetre_max(30_000);
        assert_eq!(c.window_clamp, 30_000);
        assert_eq!(c.rcv_ssthresh, 25_000);
        c.rcv_wnd = 60_000;
        c.rcv_ssthresh = 5000;
        c.poser_fenetre_max(40_000);
        assert_eq!(c.rcv_ssthresh, 40_000);
        // Le même plafond : rien ne bouge. Et jamais sous la moitié du tampon minimal.
        c.rcv_ssthresh = 5000;
        c.poser_fenetre_max(40_000);
        assert_eq!(c.rcv_ssthresh, 5000);
        c.poser_fenetre_max(1);
        assert_eq!(c.window_clamp, FENETRE_MAX_MIN);
    }

    /// `tcp_prune_queue` et `tcp_try_rmem_schedule`.
    #[test]
    fn faire_de_la_place() {
        let mut c = cas();
        c.rcvbuf = 10_000;
        c.rcvbuf_fixe = true;
        let base = c.rcv_nxt;
        // De la place : rien à faire, et la mémoire est accordée.
        assert!(c.peut_recevoir(10_000));
        assert!(!c.peut_recevoir(10_001));
        assert!(c.reserver_reception(base, 10_000));
        // Rien en mémoire : `elaguer` ne peut rien.
        assert!(!c.elaguer(base, 20_000));
        assert!(!c.reserver_reception(base, 20_000));
        // Du hors d'ordre à jeter après `seq` : il tiendra.
        for k in 1..=4u32 {
            c.hors_ordre.ranger(base + k * 1000, octets(100, 2000)).unwrap();
        }
        assert_eq!(c.memoire_reception(), 8000);
        assert!(c.reserver_reception(base, 4000));
        assert!(c.memoire_reception() <= 6000);
        // Le hors d'ordre qui précède reste : pas de place, faux.
        assert!(!c.reserver_reception(base + 500_000, 9000));
        // Sous pression, avec de la place : `rcv_ssthresh` réduit.
        c.memoire = Memoire::Pression;
        c.rcv_ssthresh = 100_000;
        assert!(c.elaguer(base, 100));
        assert_eq!(c.rcv_ssthresh, 4 * c.mss_local as u32);
        // Sans pression, sans toucher au seuil.
        c.memoire = Memoire::Souple;
        c.rcv_ssthresh = 100_000;
        assert!(c.elaguer(base, 100));
        assert_eq!(c.rcv_ssthresh, 100_000);
        // La mémoire refusée : on jette jusqu'à ce qu'elle passe, ou faux.
        let mut d = cas();
        d.rcvbuf = 100_000;
        let b = d.rcv_nxt;
        d.hors_ordre.ranger(b + 1000, octets(100, 3000)).unwrap();
        d.hors_ordre.ranger(b + 2000, octets(100, 3000)).unwrap();
        d.memoire = Memoire::Excedent;
        assert!(d.reserver_reception(b, 100));
        assert!(d.hors_ordre.vide(), "sous pression, on va jusqu'au bout");
        d.memoire = Memoire::Limite;
        assert!(!d.reserver_reception(b, 100));
    }

    /// Le rendement qui ne dépasse pas la limite d'une page, et la fin de la file.
    #[test]
    fn fondre_garde_la_memoire_bonne() {
        let mut c = cas();
        c.reception.push_back(octets(100, 2000));
        c.taille_vraie_reception = 2000;
        // Rendement mauvais : (2000 * 128 >> 8) = 1000 > 100 : recopié.
        c.fondre_reception();
        assert_eq!(c.reception[0].octets().len(), 100);
        assert_eq!(c.reception.len(), 1);
        assert_eq!(c.taille_vraie_reception, 96 + 100 + 576);
    }

    /// Ni MSS du récepteur, ni plafond : `mss > plein` est faux, on continue (seul un MSS plus
    /// grand que la pleine rend 0, quand la pleine est nulle).
    #[test]
    fn la_fenetre_sans_mss_ni_plafond() {
        let mut c = cas();
        c.window_clamp = 0;
        c.ack.rcv_mss = 0;
        c.rcv_ssthresh = 5000;
        c.rcv_wnd = 3000;
        assert_eq!(c.choisir_fenetre(), 5000);
    }

    /// Tout juste une demi-pleine d'écart : on garde encore l'annonce précédente.
    #[test]
    fn la_fenetre_a_une_demi_pleine_d_ecart() {
        let mut c = cas();
        c.window_clamp = 2000;
        c.ack.rcv_mss = 2000;
        c.rcv_ssthresh = 5000;
        c.rcv_wnd = 4000;
        assert_eq!(c.choisir_fenetre(), 4000);
        // Une de moins : l'écart dépasse.
        c.rcv_wnd = 3999;
        assert_eq!(c.choisir_fenetre(), 5000);
    }

    /// La réserve d'un segment ne touche pas un plafond d'au plus deux segments.
    #[test]
    fn l_espace_initial_un_petit_plafond() {
        let mut c = cas();
        c.mss_local = 1000;
        c.rcvbuf = 4000;
        let plein = c.espace_plein().max(0) as u32;
        assert_eq!(plein, 2000);
        c.window_clamp = 1500;
        c.rcv_ssthresh = 90_000;
        c.rcv_wnd = 90_000;
        c.espace_initial(HEURE);
        assert_eq!(c.window_clamp, 1500);
    }

    /// Juste sous le MSS par défaut, avec PSH : pas mesuré (`tcp_measure_rcv_mss`).
    #[test]
    fn le_mss_pas_mesure_juste_sous_le_defaut() {
        let mut c = cas();
        let entete = Tcp { drapeaux: tcp::ACK | tcp::PSH, options: tcp::Options::default(), ..Tcp::default() };
        c.ack.rcv_mss = 1000;
        c.ack.dernier_segment = 535;
        c.mesurer_rcv_mss(535, 2000, &entete);
        assert_eq!(c.ack.rcv_mss, 1000);
        assert_eq!(c.ack.dernier_segment, 0);
        c.ack.dernier_segment = 536;
        c.mesurer_rcv_mss(536, 2000, &entete);
        assert_eq!(c.ack.rcv_mss, 536);
    }

    /// SO_RCVBUF tient déjà tout juste le seuil : ni lui, ni le plafond ne bougent.
    #[test]
    fn so_rcvlowat_tout_juste() {
        let mut c = cas();
        c.rcvbuf_max = 1 << 20;
        c.rcvbuf_fixe = false;
        c.rcvbuf = c.espace_de(100_000) as usize;
        let r = c.rcvbuf;
        c.window_clamp = 60_000;
        assert_eq!(c.poser_rcvlowat(100_000), 100_000);
        assert_eq!((c.rcvbuf, c.window_clamp), (r, 60_000));
    }

    /// Deux fois la longueur du segment, quand elle dépasse deux MSS ; sinon, deux MSS.
    #[test]
    fn agrandir_de_deux_segments() {
        let mut c = cas();
        c.mss_local = 1000;
        c.rcvbuf_max = 1 << 20;
        c.window_clamp = 40_000;
        c.rcv_ssthresh = 10_000;
        c.agrandir_fenetre(1500, 3000);
        assert_eq!(c.rcv_ssthresh, 13_000);
        c.rcv_ssthresh = 10_000;
        c.agrandir_fenetre(500, 1000);
        assert_eq!(c.rcv_ssthresh, 12_000);
    }

    /// Tout juste autant lu que la mesure précédente : SO_RCVBUF ne suit pas.
    #[test]
    fn ajuster_l_espace_tout_juste() {
        let mut c = cas();
        c.rcvbuf_max = 1 << 30;
        c.rcvbuf = 1000;
        c.espace.temps = HEURE;
        c.espace.seq = c.rcv_lu;
        c.espace.octets = 1000;
        c.rcv_rtt8 = 8 * 10 * MS;
        c.rcv_lu = c.rcv_lu.wrapping_add(1000);
        c.rcv_nxt = c.rcv_lu;
        c.ajuster_espace(HEURE + 100 * MS);
        assert_eq!((c.rcvbuf, c.espace.octets), (1000, 1000));
        assert_eq!(c.espace.temps, HEURE + 100 * MS, "la mesure repart quand même");
    }

    /// SO_RCVBUF déjà au maximum ne redescend pas vers ce que garde la file.
    #[test]
    fn resserrer_au_maximum() {
        let mut c = cas();
        c.mss_local = 1000;
        c.rcvbuf_max = 200_000;
        c.rcvbuf = 200_000;
        c.rcvbuf_fixe = false;
        c.memoire = Memoire::Libre;
        c.taille_vraie_reception = 1000;
        c.resserrer();
        assert_eq!(c.rcvbuf, 200_000);
    }

    /// Le segment ne tient toujours pas : le but repart d'un huitième de SO_RCVBUF, et pas de
    /// huit fois : une entrée de plus suffit à regarder de nouveau.
    #[test]
    fn elaguer_un_huitieme_a_la_fois() {
        let mut c = cas();
        c.rcvbuf = 8000;
        let base = c.rcv_nxt;
        for p in [1000u32, 2000, 3000, 4000, 5000] {
            c.hors_ordre.ranger(base + p, octets(500, 1000)).unwrap();
        }
        // Au départ tout tient (la taille vraie du hors d'ordre : 5000) ; il reste à jeter.
        c.taille_vraie_reception = 0;
        assert!(c.elaguer_hors_ordre(base + 500, 4000));
        assert_eq!(c.hors_ordre.taille_vraie, 4000, "1000 suffisent");
        // 6000 ne tiendraient qu'une fois descendu à 2000 : deux passes de 1000.
        assert!(c.elaguer_hors_ordre(base + 500, 6000));
        assert_eq!(c.hors_ordre.taille_vraie, 2000);
    }

    /// La mémoire manque au milieu d'un paquet : ce qui a été recopié n'y reste pas, et le flux
    /// ne perd ni ne double rien.
    #[test]
    fn fondre_quand_la_memoire_manque() {
        let mut c = cas();
        // TAILLE_FONTE octets recopiés, puis le reste n'a pas de quoi être créé.
        c.reception.push_back(octets(TAILLE_FONTE + REFUSEE, 2 * TAILLE_FONTE + 8000));
        c.taille_vraie_reception = 2 * TAILLE_FONTE + 8000;
        c.fondre_reception();
        let tailles: Vec<usize> = c.reception.iter().map(|p| p.octets().len()).collect();
        assert_eq!(tailles, vec![TAILLE_FONTE, REFUSEE]);
    }

    /// `tcp_collapse_ofo_queue` : au plus un huitième de SO_RCVBUF de petits en suivant.
    #[test]
    fn fondre_le_hors_ordre_un_huitieme() {
        let prete = |rcvbuf: usize| {
            let mut c = cas();
            c.rcvbuf = rcvbuf;
            let base = c.rcv_nxt;
            // Trois petits isolés, de 1000 en taille vraie, puis une suite de deux à fondre.
            for p in [1000u32, 3000, 5000] {
                c.hors_ordre.ranger(base + p, octets(100, 1000)).unwrap();
            }
            c.hors_ordre.ranger(base + 7000, octets(100, 2000)).unwrap();
            c.hors_ordre.ranger(base + 7100, octets(100, 2000)).unwrap();
            c
        };
        let mut c = prete(8000);
        c.fondre_hors_ordre();
        assert_eq!(c.hors_ordre.taille_vraie, 7000, "2000 de petits dépassent le huitième : on s'arrête avant la suite");
        let mut c = prete(32_000);
        c.fondre_hors_ordre();
        assert_eq!(c.hors_ordre.taille_vraie, 3000 + 96 + 200 + 576, "3000 de petits n'atteignent pas le huitième");
    }
}
