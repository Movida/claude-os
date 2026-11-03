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

impl<P: Charge> HorsOrdre<P> {
    pub const fn new() -> HorsOrdre<P> {
        HorsOrdre { file: VecDeque::new(), taille_vraie: 0 }
    }

    pub fn vide(&self) -> bool {
        self.file.is_empty()
    }

    /// Range `charge`, dont le premier octet porte le numéro `seq` ; faux
    /// si la mémoire manque (la charge est jetée : l'émetteur la renverra).
    pub fn ranger(&mut self, mut seq: u32, mut charge: P) -> bool {
        let fin_charge = seq.wrapping_add(charge.octets().len() as u32);
        if charge.octets().is_empty() {
            return true;
        }
        if self.file.try_reserve(1).is_err() {
            return false;
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
                return true;
            }
            charge.avancer(f.wrapping_sub(seq) as usize);
            seq = f;
            i += 1;
        }
        // Celles que nous couvrons en entier disparaissent ; celle que
        // nous couvrons en partie perd son début.
        while let Some(e) = self.file.get(i) {
            if !apres(fin(e), fin_charge) {
                if let Some((_, p)) = self.file.remove(i) {
                    self.taille_vraie = self.taille_vraie.saturating_sub(p.taille_vraie());
                }
                continue;
            }
            if avant(e.0, fin_charge)
                && let Some(e) = self.file.get_mut(i)
            {
                e.1.avancer(fin_charge.wrapping_sub(e.0) as usize);
                e.0 = fin_charge;
            }
            break;
        }
        self.taille_vraie += charge.taille_vraie();
        // La place est prise plus haut.
        self.file.insert(i, (seq, charge));
        true
    }

    /// La prochaine charge qui commence au plus tard à `rcv_nxt` (le trou
    /// est comblé), sans ce qui précède `rcv_nxt` ; None : il reste un
    /// trou, ou la file est vide.
    pub fn suivante(&mut self, rcv_nxt: u32) -> Option<P> {
        loop {
            let e = self.file.front()?;
            if apres(e.0, rcv_nxt) {
                return None;
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
