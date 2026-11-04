//! La file hors d'ordre d'une connexion (le rbtree `out_of_order_queue`
//! de Linux, `tcp_data_queue_ofo` et `tcp_ofo_queue`, net/ipv4/tcp_input.c).
//!
//! Quand un segment se perd, ceux qui le suivent arrivent avant lui :
//! les jeter (ce que faisait le commit 5) forcerait l'émetteur à tout
//! renvoyer depuis le trou. On les garde ici, rangés par numéro de
//! séquence, sans recouvrement : ce qui est déjà là est retiré du début de
//! la charge qui arrive, ou du début des suivantes qu'elle recouvre (les
//! octets sont les mêmes : c'est le même flux). Quand le trou se comble,
//! la connexion reprend les charges qui se suivent, une à une.
//!
//! Une liste triée plutôt que l'arbre de Linux : elle ne dépasse guère une
//! fenêtre de segments (sa mémoire compte contre SO_RCVBUF), et l'arrivée
//! la plus fréquente (le segment qui suit le dernier rangé) se range à la
//! fin. Linux prend un arbre parce qu'une fenêtre de plusieurs Mio, avec
//! SACK, peut y mettre des milliers de segments.

use super::{Charge, apres, avant};
use alloc::collections::VecDeque;

pub struct HorsOrdre<P> {
    /// (numéro du premier octet, charge), triées, sans recouvrement.
    file: VecDeque<(u32, P)>,
    /// La taille vraie de ce qui est rangé (compte contre SO_RCVBUF).
    pub taille_vraie: usize,
}

fn fin<P: Charge>(e: &(u32, P)) -> u32 {
    e.0.wrapping_add(e.1.octets().len() as u32)
}

/// `tcp_dsack_extend` : le premier doublon, ou le bloc déjà dit, s'il le touche.
pub(super) fn etendre_doublon(d: &mut Option<(u32, u32)>, debut: u32, fin: u32) {
    match d {
        None => *d = Some((debut, fin)),
        Some(b) => {
            etendre_bloc(b, debut, fin);
        }
    }
}

/// `tcp_sack_extend` : `debut`..`fin` touche-t-il le bloc ? Alors il l'agrandit.
pub(super) fn etendre_bloc(b: &mut (u32, u32), debut: u32, fin: u32) -> bool {
    if !apres(debut, b.1) && !apres(b.0, fin) {
        if avant(debut, b.0) {
            b.0 = debut;
        }
        if apres(fin, b.1) {
            b.1 = fin;
        }
        return true;
    }
    false
}

impl<P: Charge> HorsOrdre<P> {
    pub const fn new() -> HorsOrdre<P> {
        HorsOrdre { file: VecDeque::new(), taille_vraie: 0 }
    }

    pub fn vide(&self) -> bool {
        self.file.is_empty()
    }

    /// Range `charge`, dont le premier octet porte le numéro `seq` ; rend le
    /// doublon qu'elle contenait, à dire par D-SACK (`tcp_data_queue_ofo`).
    /// Si la mémoire manque, la charge est jetée : l'émetteur la renverra.
    pub fn ranger(&mut self, mut seq: u32, mut charge: P) -> Option<(u32, u32)> {
        let debut = seq;
        let fin_charge = seq.wrapping_add(charge.octets().len() as u32);
        let mut doublon = None;
        if charge.octets().is_empty() || self.file.try_reserve(1).is_err() {
            return None;
        }
        // La première charge rangée qui finit après le début de la nôtre.
        let mut i = self.file.iter().position(|e| apres(fin(e), seq)).unwrap_or(self.file.len());
        if let Some(e) = self.file.get(i)
            && !apres(e.0, seq)
        {
            // Elle couvre notre début : retiré ; et si elle nous couvre en
            // entier, rien de neuf.
            let f = fin(e);
            if !apres(fin_charge, f) {
                return Some((debut, fin_charge));
            }
            doublon = Some((debut, f));
            charge.avancer(f.wrapping_sub(seq) as usize);
            seq = f;
            i += 1;
        }
        // Celles que nous couvrons en entier disparaissent ; celle que
        // nous couvrons en partie perd son début.
        while let Some(e) = self.file.get(i) {
            if !apres(fin(e), fin_charge) {
                let (d, f) = (e.0, fin(e));
                etendre_doublon(&mut doublon, d, f);
                if let Some((_, p)) = self.file.remove(i) {
                    self.taille_vraie = self.taille_vraie.saturating_sub(p.taille_vraie());
                }
                continue;
            }
            if avant(e.0, fin_charge)
                && let Some(e) = self.file.get_mut(i)
            {
                etendre_doublon(&mut doublon, e.0, fin_charge);
                e.1.avancer(fin_charge.wrapping_sub(e.0) as usize);
                e.0 = fin_charge;
            }
            break;
        }
        self.taille_vraie += charge.taille_vraie();
        // La place est prise plus haut.
        self.file.insert(i, (seq, charge));
        doublon
    }

    /// La prochaine charge qui commence au plus tard à `rcv_nxt` (le trou
    /// est comblé), sans ce qui précède `rcv_nxt` ; None : il reste un
    /// trou, ou la file est vide. Ce qu'elle a de commun avec ce qui était déjà
    /// reçu, avant `dsack_haut`, va dans `doublon` (`tcp_ofo_queue`).
    pub fn suivante(&mut self, rcv_nxt: u32, dsack_haut: u32, doublon: &mut Option<(u32, u32)>) -> Option<P> {
        loop {
            let e = self.file.front()?;
            if apres(e.0, rcv_nxt) {
                return None;
            }
            if avant(e.0, dsack_haut) {
                let f = if avant(fin(e), dsack_haut) { fin(e) } else { dsack_haut };
                etendre_doublon(doublon, e.0, f);
            }
            let (s, mut p) = self.file.pop_front()?;
            self.taille_vraie = self.taille_vraie.saturating_sub(p.taille_vraie());
            let deja = rcv_nxt.wrapping_sub(s) as usize;
            if deja >= p.octets().len() {
                // Déjà reçue tout entière (par une retransmission plus
                // grande) : jetée.
                continue;
            }
            p.avancer(deja);
            return Some(p);
        }
    }

    /// Jette la charge la plus lointaine, pour faire de la place à ce qui
    /// arrive dans l'ordre (`tcp_prune_ofo_queue`) ; faux : il n'y avait
    /// rien.
    pub fn jeter_la_derniere(&mut self) -> bool {
        match self.file.pop_back() {
            Some((_, p)) => {
                self.taille_vraie = self.taille_vraie.saturating_sub(p.taille_vraie());
                true
            }
            None => false,
        }
    }

    /// Jette tout (la connexion se ferme).
    pub fn vider(&mut self) {
        self.file.clear();
        self.taille_vraie = 0;
    }
}
